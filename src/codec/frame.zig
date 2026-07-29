//! Framing decoders: turning a byte stream into discrete frames.
//!
//! These are the workhorses of any custom binary or line protocol, and the
//! direct counterparts of Netty's `LineBasedFrameDecoder`,
//! `LengthFieldBasedFrameDecoder` and `LengthFieldPrepender`.
//!
//! Every decoder here is bounded: a frame that exceeds its configured maximum
//! is reported and skipped rather than accumulated, so a hostile or broken peer
//! cannot turn a framing bug into unbounded memory use.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../buffer.zig").Buffer;
const codec = @import("codec.zig");
const pipeline_mod = @import("../pipeline.zig");

const ByteToMessageDecoder = codec.ByteToMessageDecoder;
const Error = codec.Error;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Splits a stream on line endings, accepting both `\n` and `\r\n`.
///
/// A line longer than `max_length` is not a frame this decoder can deliver, so
/// it reports `error.FrameTooLong` and then discards bytes until the next line
/// ending, which resynchronizes the stream instead of stalling it.
pub const LineBasedFrameDecoder = struct {
    decoder: ByteToMessageDecoder(LineBasedFrameDecoder),
    options: Options,
    /// Set while skipping the remainder of an oversized line.
    discarding: bool = false,
    /// Bytes skipped so far in the current discard, for diagnostics.
    discarded: usize = 0,

    pub const handler_name = "line-frame-decoder";

    pub const Options = struct {
        /// Longest line that will be delivered, excluding the line ending.
        max_length: usize = 8 * 1024,
        /// Whether the line ending is removed from the delivered frame.
        strip_delimiter: bool = true,
        /// Report the failure as soon as the line is known to be too long,
        /// rather than waiting for its end. Fast failure is almost always what
        /// a server wants; waiting only helps when the peer must be told
        /// exactly how long the offending line was.
        fail_fast: bool = true,
    };

    pub fn init(options: Options) LineBasedFrameDecoder {
        assert(options.max_length > 0);
        return .{
            .decoder = .{
                .options = .{
                    // One line must fit in the accumulation buffer, plus its
                    // two-byte ending.
                    .max_cumulation = options.max_length + 2,
                },
            },
            .options = options,
        };
    }

    /// Allocates a decoder and installs it at the end of `pipeline`.
    pub fn addTo(pipeline: *Pipeline, options: Options) !*LineBasedFrameDecoder {
        const decoder = try pipeline.gpa.create(LineBasedFrameDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *LineBasedFrameDecoder, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn onRead(
        self: *LineBasedFrameDecoder,
        ctx: *HandlerContext,
        msg: Message,
    ) Error!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *LineBasedFrameDecoder, ctx: *HandlerContext) Error!void {
        return self.decoder.onInactive(self, ctx);
    }

    /// Called by the accumulating decoder; see the contract in `codec.zig`.
    ///
    /// An over-long line is *reported* rather than returned. Returning it would
    /// abort the accumulating decoder's drain loop, and the bytes behind the
    /// offending line — which may hold perfectly good frames that arrived in
    /// the same read — would go undecoded, then be dropped at end of stream.
    /// Since this decoder can resynchronize on the next line ending, the
    /// failure is an event about one frame, not the end of the stream. Netty
    /// makes the same distinction by firing the exception from inside its
    /// decode loop.
    pub fn decode(
        self: *LineBasedFrameDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) Error!?Message {
        if (self.discarding) return self.discard(cumulation);

        const readable = cumulation.readableSlice();
        const newline = std.mem.indexOfScalar(u8, readable, '\n') orelse {
            // No line ending yet. Only the length can rule the line out.
            if (readable.len > self.options.max_length and self.options.fail_fast) {
                self.beginDiscard(cumulation);
                ctx.fireError(error.FrameTooLong);
            }
            return null;
        };

        const line_len = newline; // Bytes before the '\n'.
        if (line_len > self.options.max_length) {
            // Skip the whole offending line, ending included, then carry on.
            try cumulation.skip(newline + 1);
            ctx.fireError(error.FrameTooLong);
            return null;
        }

        const delimiter_len: usize = if (line_len > 0 and readable[line_len - 1] == '\r') 2 else 1;
        const payload_len = if (self.options.strip_delimiter)
            line_len + 1 - delimiter_len
        else
            newline + 1;

        const frame = try Message.initBytes(ctx.gpa(), readable[0..payload_len]);
        // Always consume the ending, whether or not it was delivered.
        cumulation.skip(newline + 1) catch unreachable;
        return frame;
    }

    fn beginDiscard(self: *LineBasedFrameDecoder, cumulation: *Buffer) void {
        assert(!self.discarding);
        self.discarding = true;
        self.discarded = cumulation.readableLen();
        cumulation.clear();
    }

    /// Skips bytes until the line ending that terminates the oversized line.
    fn discard(self: *LineBasedFrameDecoder, cumulation: *Buffer) Error!?Message {
        assert(self.discarding);
        const readable = cumulation.readableSlice();
        if (std.mem.indexOfScalar(u8, readable, '\n')) |newline| {
            self.discarding = false;
            self.discarded += newline + 1;
            try cumulation.skip(newline + 1);
            return null;
        }
        self.discarded += readable.len;
        cumulation.clear();
        return null;
    }
};

// -- Fixed-length framing --------------------------------------------------

/// Splits a stream into frames of exactly `frame_length` bytes.
///
/// Netty's `FixedLengthFrameDecoder`. The simplest possible framing, and the
/// only one that cannot fail: every byte belongs to a frame, so there is no
/// malformed input and nothing to resynchronize.
pub const FixedLengthFrameDecoder = struct {
    decoder: ByteToMessageDecoder(FixedLengthFrameDecoder),
    frame_length: usize,

    pub const handler_name = "fixed-length-frame-decoder";

    pub const Options = struct {
        /// Size of every delivered frame. Must be greater than zero.
        frame_length: usize,
    };

    pub fn init(options: Options) FixedLengthFrameDecoder {
        assert(options.frame_length > 0);
        return .{
            // A residue is always shorter than one frame, so one frame's worth
            // of accumulation is all this decoder can ever hold undecoded.
            .decoder = .{ .options = .{ .max_cumulation = options.frame_length } },
            .frame_length = options.frame_length,
        };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*FixedLengthFrameDecoder {
        const decoder = try pipeline.gpa.create(FixedLengthFrameDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *FixedLengthFrameDecoder, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn onRead(
        self: *FixedLengthFrameDecoder,
        ctx: *HandlerContext,
        msg: Message,
    ) Error!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *FixedLengthFrameDecoder, ctx: *HandlerContext) Error!void {
        return self.decoder.onInactive(self, ctx);
    }

    pub fn onRemoved(self: *FixedLengthFrameDecoder, ctx: *HandlerContext) void {
        self.decoder.onRemoved(ctx);
    }

    pub fn decode(
        self: *FixedLengthFrameDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) Error!?Message {
        if (cumulation.readableLen() < self.frame_length) return null;
        const payload = cumulation.readableSlice()[0..self.frame_length];
        const frame = try Message.initBytes(ctx.gpa(), payload);
        cumulation.skip(self.frame_length) catch unreachable;
        return frame;
    }
};

// -- Delimiter framing -----------------------------------------------------

/// Ready-made delimiter sets, matching Netty's `Delimiters`.
pub const Delimiters = struct {
    /// `\r\n` then `\n`, in that order: the longer one must be tried first or a
    /// CRLF stream would deliver frames with a trailing CR.
    pub const line: []const []const u8 = &.{ "\r\n", "\n" };
    /// A single NUL byte, as used by Flash XML sockets and STOMP.
    pub const nul: []const []const u8 = &.{"\x00"};
};

/// Splits a stream on any of several byte sequences.
///
/// Netty's `DelimiterBasedFrameDecoder`. Where several delimiters could match,
/// the one producing the **shortest** frame wins, and among equal-position
/// matches the longest delimiter wins — so `\r\n` beats `\n` at the same offset
/// and a frame never keeps a stray `\r`.
///
/// Over-long frames are handled exactly as in `LineBasedFrameDecoder`: reported
/// through `ctx.fireError` and skipped, because the stream can be
/// resynchronized at the next delimiter and the bytes behind the offending
/// frame may be perfectly good.
pub const DelimiterBasedFrameDecoder = struct {
    decoder: ByteToMessageDecoder(DelimiterBasedFrameDecoder),
    options: Options,
    /// Longest configured delimiter, so a discard can keep enough tail to
    /// recognize one that straddles a read boundary.
    longest_delimiter: usize,
    discarding: bool = false,
    discarded: usize = 0,

    pub const handler_name = "delimiter-frame-decoder";

    pub const Options = struct {
        /// Sequences that end a frame. Borrowed: they must outlive the decoder,
        /// which is why the built-in sets are comptime constants.
        delimiters: []const []const u8 = Delimiters.line,
        /// Longest frame that will be delivered, excluding the delimiter.
        max_length: usize = 8 * 1024,
        /// Whether the delimiter is removed from the delivered frame.
        strip_delimiter: bool = true,
        /// Report an over-long frame as soon as it is known to be too long,
        /// rather than waiting for its delimiter.
        fail_fast: bool = true,
    };

    pub fn init(options: Options) DelimiterBasedFrameDecoder {
        assert(options.max_length > 0);
        assert(options.delimiters.len > 0);
        var longest: usize = 0;
        for (options.delimiters) |delimiter| {
            assert(delimiter.len > 0);
            longest = @max(longest, delimiter.len);
        }
        return .{
            .decoder = .{
                .options = .{ .max_cumulation = options.max_length + longest },
            },
            .options = options,
            .longest_delimiter = longest,
        };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*DelimiterBasedFrameDecoder {
        const decoder = try pipeline.gpa.create(DelimiterBasedFrameDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *DelimiterBasedFrameDecoder, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn onRead(
        self: *DelimiterBasedFrameDecoder,
        ctx: *HandlerContext,
        msg: Message,
    ) Error!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *DelimiterBasedFrameDecoder, ctx: *HandlerContext) Error!void {
        return self.decoder.onInactive(self, ctx);
    }

    pub fn onRemoved(self: *DelimiterBasedFrameDecoder, ctx: *HandlerContext) void {
        self.decoder.onRemoved(ctx);
    }

    /// Earliest delimiter match, preferring the longest one at that position.
    const Match = struct { offset: usize, length: usize };

    fn findDelimiter(self: *const DelimiterBasedFrameDecoder, readable: []const u8) ?Match {
        var best: ?Match = null;
        for (self.options.delimiters) |delimiter| {
            const offset = std.mem.indexOf(u8, readable, delimiter) orelse continue;
            const candidate: Match = .{ .offset = offset, .length = delimiter.len };
            const current = best orelse {
                best = candidate;
                continue;
            };
            if (candidate.offset < current.offset or
                (candidate.offset == current.offset and candidate.length > current.length))
            {
                best = candidate;
            }
        }
        return best;
    }

    pub fn decode(
        self: *DelimiterBasedFrameDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) Error!?Message {
        if (self.discarding) return self.discard(cumulation);

        const readable = cumulation.readableSlice();
        const match = self.findDelimiter(readable) orelse {
            if (readable.len > self.options.max_length and self.options.fail_fast) {
                self.beginDiscard(cumulation);
                ctx.fireError(error.FrameTooLong);
            }
            return null;
        };

        const total = match.offset + match.length;
        if (match.offset > self.options.max_length) {
            try cumulation.skip(total);
            ctx.fireError(error.FrameTooLong);
            return null;
        }

        const payload_len = if (self.options.strip_delimiter) match.offset else total;
        const frame = try Message.initBytes(ctx.gpa(), readable[0..payload_len]);
        cumulation.skip(total) catch unreachable;
        return frame;
    }

    fn beginDiscard(self: *DelimiterBasedFrameDecoder, cumulation: *Buffer) void {
        assert(!self.discarding);
        self.discarding = true;
        self.discarded += self.dropAllButDelimiterTail(cumulation);
    }

    fn discard(self: *DelimiterBasedFrameDecoder, cumulation: *Buffer) Error!?Message {
        assert(self.discarding);
        const readable = cumulation.readableSlice();
        if (self.findDelimiter(readable)) |match| {
            const total = match.offset + match.length;
            self.discarding = false;
            self.discarded += total;
            try cumulation.skip(total);
            return null;
        }
        self.discarded += self.dropAllButDelimiterTail(cumulation);
        return null;
    }

    /// Drops the buffer while keeping enough of its tail that a delimiter
    /// straddling the read boundary can still be recognized.
    ///
    /// Without this, a two-byte delimiter split across two reads would be
    /// missed and the discard would run on to the *next* delimiter, swallowing
    /// one good frame. The single-byte case cannot straddle, which is why
    /// `LineBasedFrameDecoder` gets away with clearing outright.
    fn dropAllButDelimiterTail(
        self: *const DelimiterBasedFrameDecoder,
        cumulation: *Buffer,
    ) usize {
        const keep = @min(self.longest_delimiter - 1, cumulation.readableLen());
        const drop = cumulation.readableLen() - keep;
        cumulation.skip(drop) catch unreachable;
        return drop;
    }
};

// -- Length-field framing --------------------------------------------------

/// Widths a length field may have, in bytes.
pub const LengthFieldWidth = enum(u8) {
    one = 1,
    two = 2,
    three = 3,
    four = 4,
    eight = 8,

    pub fn byteCount(width: LengthFieldWidth) usize {
        return @intFromEnum(width);
    }

    /// Reads a length field of this width from the front of `bytes`.
    pub fn read(width: LengthFieldWidth, bytes: []const u8, endian: std.builtin.Endian) u64 {
        assert(bytes.len >= width.byteCount());
        return switch (width) {
            .one => bytes[0],
            .two => std.mem.readInt(u16, bytes[0..2], endian),
            .three => std.mem.readInt(u24, bytes[0..3], endian),
            .four => std.mem.readInt(u32, bytes[0..4], endian),
            .eight => std.mem.readInt(u64, bytes[0..8], endian),
        };
    }

    /// Largest value this width can represent.
    pub fn maxValue(width: LengthFieldWidth) u64 {
        return switch (width) {
            .one => std.math.maxInt(u8),
            .two => std.math.maxInt(u16),
            .three => std.math.maxInt(u24),
            .four => std.math.maxInt(u32),
            .eight => std.math.maxInt(u64),
        };
    }

    /// Appends `value` to `out` in this width.
    pub fn write(
        width: LengthFieldWidth,
        out: *Buffer,
        gpa: Allocator,
        value: u64,
        endian: std.builtin.Endian,
    ) !void {
        switch (width) {
            .one => try out.writeInt(gpa, u8, @intCast(value), endian),
            .two => try out.writeInt(gpa, u16, @intCast(value), endian),
            .three => try out.writeInt(gpa, u24, @intCast(value), endian),
            .four => try out.writeInt(gpa, u32, @intCast(value), endian),
            .eight => try out.writeInt(gpa, u64, value, endian),
        }
    }
};

/// Splits a stream using a length field embedded in each frame's header.
///
/// The parameters match Netty's `LengthFieldBasedFrameDecoder`, which between
/// them cover essentially every length-prefixed protocol in the wild:
///
/// ```
///                 <------------ frame_length ------------>
/// +--------------+---------------+-----------------------+
/// | before       | length field  | body                  |
/// +--------------+---------------+-----------------------+
///  ^offset        ^field_width
/// ```
///
/// `frame_length = length_value + length_adjustment + offset + field_width`,
/// that is, the length field is interpreted relative to the end of the header,
/// and `length_adjustment` reconciles protocols whose length counts something
/// other than "the bytes that follow".
pub const LengthFieldBasedFrameDecoder = struct {
    decoder: ByteToMessageDecoder(LengthFieldBasedFrameDecoder),
    options: Options,
    /// Bytes still to be skipped from an oversized frame.
    discarding_remaining: usize = 0,
    /// Set once a corrupt length field has been reported. A length-prefixed
    /// stream offers no way to find the next frame boundary after that, so the
    /// rest of it is discarded rather than guessed at.
    failed: bool = false,

    pub const handler_name = "length-frame-decoder";

    pub const Options = struct {
        /// Bytes before the length field.
        length_field_offset: usize = 0,
        /// Width of the length field.
        length_field_width: LengthFieldWidth = .four,
        /// Added to the decoded length. Use this when the length counts the
        /// header too (a negative adjustment) or excludes a trailer.
        length_adjustment: i64 = 0,
        /// Bytes removed from the front of the delivered frame, normally the
        /// header, so handlers see only the body.
        initial_bytes_to_strip: usize = 0,
        /// Byte order of the length field. Network order is the default because
        /// it is what protocols specify.
        endian: std.builtin.Endian = .big,
        /// Longest frame that will be delivered. A larger one is reported as
        /// `error.FrameTooLong` and skipped.
        max_frame_length: usize = 8 * 1024 * 1024,
    };

    pub fn init(options: Options) LengthFieldBasedFrameDecoder {
        const header_end = options.length_field_offset + options.length_field_width.byteCount();
        assert(options.max_frame_length >= header_end);
        assert(options.initial_bytes_to_strip <= options.max_frame_length);
        return .{
            .decoder = .{ .options = .{ .max_cumulation = options.max_frame_length } },
            .options = options,
        };
    }

    /// Allocates a decoder and installs it at the end of `pipeline`.
    pub fn addTo(pipeline: *Pipeline, options: Options) !*LengthFieldBasedFrameDecoder {
        const decoder = try pipeline.gpa.create(LengthFieldBasedFrameDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *LengthFieldBasedFrameDecoder, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn onRead(
        self: *LengthFieldBasedFrameDecoder,
        ctx: *HandlerContext,
        msg: Message,
    ) Error!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *LengthFieldBasedFrameDecoder, ctx: *HandlerContext) Error!void {
        return self.decoder.onInactive(self, ctx);
    }

    /// Called by the accumulating decoder; see the contract in `codec.zig`.
    ///
    /// The two failure modes are treated differently on purpose. An over-long
    /// frame is recoverable: its length is known, so the decoder can skip
    /// exactly that many bytes and pick the stream back up. It is therefore
    /// reported through `ctx.fireError` and decoding continues, which keeps
    /// frames that shared the read from being dropped. A corrupt length field
    /// is not recoverable — nothing in the stream says where the next frame
    /// starts — so it is latched: reported once, and everything after it is
    /// discarded.
    pub fn decode(
        self: *LengthFieldBasedFrameDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) Error!?Message {
        if (self.failed) {
            cumulation.clear();
            return null;
        }
        if (self.discarding_remaining > 0) return self.discard(cumulation);

        const options = self.options;
        const header_end = options.length_field_offset + options.length_field_width.byteCount();
        const readable = cumulation.readableSlice();
        if (readable.len < header_end) return null;

        const raw = options.length_field_width.read(
            readable[options.length_field_offset..],
            options.endian,
        );
        const frame_length = resolveFrameLength(raw, options.length_adjustment, header_end) catch |err| {
            self.fail(cumulation);
            return err;
        };

        if (frame_length > options.max_frame_length) {
            // Skip the whole frame. Only what has arrived can be skipped now;
            // the rest is skipped as it arrives.
            const available = @min(frame_length, readable.len);
            self.discarding_remaining = frame_length - available;
            try cumulation.skip(available);
            ctx.fireError(error.FrameTooLong);
            return null;
        }
        if (readable.len < frame_length) return null;
        if (frame_length < options.initial_bytes_to_strip) {
            self.fail(cumulation);
            return error.CorruptFrame;
        }

        const body = readable[options.initial_bytes_to_strip..frame_length];
        const message = try Message.initBytes(ctx.gpa(), body);
        cumulation.skip(frame_length) catch unreachable;
        return message;
    }

    /// Gives up on the stream: the failure is reported once by the caller, and
    /// everything that arrives afterwards is discarded.
    fn fail(self: *LengthFieldBasedFrameDecoder, cumulation: *Buffer) void {
        self.failed = true;
        self.discarding_remaining = 0;
        cumulation.clear();
    }

    /// Total frame size implied by a length field, or an error when the header
    /// describes something impossible.
    fn resolveFrameLength(raw: u64, adjustment: i64, header_end: usize) Error!usize {
        const adjusted = std.math.add(i128, @as(i128, raw), @as(i128, adjustment)) catch
            return error.CorruptFrame;
        const total = adjusted + @as(i128, @intCast(header_end));
        if (total < @as(i128, @intCast(header_end))) return error.CorruptFrame;
        // A length that does not fit in memory cannot be skipped either, so it
        // is a desynchronized stream rather than a merely over-long frame.
        if (total > std.math.maxInt(usize)) return error.CorruptFrame;
        return @intCast(total);
    }

    fn discard(
        self: *LengthFieldBasedFrameDecoder,
        cumulation: *Buffer,
    ) Error!?Message {
        assert(self.discarding_remaining > 0);
        const available = @min(self.discarding_remaining, cumulation.readableLen());
        if (available == 0) return null;
        try cumulation.skip(available);
        self.discarding_remaining -= available;
        return null;
    }
};

/// Prepends a length field to every outbound byte message, so a peer running
/// `LengthFieldBasedFrameDecoder` can frame the stream.
pub const LengthFieldPrepender = struct {
    options: Options,

    pub const handler_name = "length-field-prepender";

    pub const Options = struct {
        length_field_width: LengthFieldWidth = .four,
        /// Whether the written length counts the length field itself.
        length_includes_length_field: bool = false,
        /// Added to the written length, mirroring the decoder's adjustment.
        length_adjustment: i64 = 0,
        endian: std.builtin.Endian = .big,
    };

    pub fn init(options: Options) LengthFieldPrepender {
        return .{ .options = options };
    }

    /// Allocates a prepender and installs it at the end of `pipeline`.
    pub fn addTo(pipeline: *Pipeline, options: Options) !*LengthFieldPrepender {
        const prepender = try pipeline.gpa.create(LengthFieldPrepender);
        prepender.* = .init(options);
        errdefer pipeline.gpa.destroy(prepender);
        _ = try pipeline.addLast(handler_name, .initOwned(prepender));
        return prepender;
    }

    pub fn onWrite(
        self: *LengthFieldPrepender,
        ctx: *HandlerContext,
        msg: Message,
    ) Error!void {
        var owned = msg;
        if (owned.bytes() == null) {
            // Not bytes; leave it for a codec further along the chain.
            return ctx.write(owned.move());
        }
        defer owned.deinit(ctx.gpa());

        const body = owned.bytes().?;
        const width = self.options.length_field_width;
        const declared = try self.declaredLength(body.len);

        var framed = try Buffer.init(ctx.gpa(), .{
            .capacity = width.byteCount() + body.len,
            .max_capacity = width.byteCount() + body.len,
        });
        errdefer framed.deinit(ctx.gpa());

        try width.write(&framed, ctx.gpa(), declared, self.options.endian);
        try framed.writeBytes(ctx.gpa(), body);
        return ctx.write(.initBuffer(&framed));
    }

    /// The value to put in the length field for a body of `body_len` bytes.
    fn declaredLength(self: *const LengthFieldPrepender, body_len: usize) Error!u64 {
        const width = self.options.length_field_width;
        var value: i128 = @intCast(body_len);
        if (self.options.length_includes_length_field) {
            value += @intCast(width.byteCount());
        }
        value += self.options.length_adjustment;
        if (value < 0) return error.CorruptFrame;
        if (value > width.maxValue()) return error.FrameTooLong;
        return @intCast(value);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const test_support = @import("test_support.zig");

fn addLineDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try LineBasedFrameDecoder.addTo(pipeline, .{ .max_length = 16 });
}

test "LineBasedFrameDecoder: splits on both line endings" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try fixture.addCodec(addLineDecoder);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "first\nsecond\r\nthird\n"));

    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    try testing.expectEqualStrings("first", collector.messages.items[0]);
    try testing.expectEqualStrings("second", collector.messages.items[1]);
    try testing.expectEqualStrings("third", collector.messages.items[2]);
}

test "LineBasedFrameDecoder: an empty line is a frame of length zero" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try fixture.addCodec(addLineDecoder);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "\n\r\nx\n"));

    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    try testing.expectEqualStrings("", collector.messages.items[0]);
    try testing.expectEqualStrings("", collector.messages.items[1]);
    try testing.expectEqualStrings("x", collector.messages.items[2]);
}

test "LineBasedFrameDecoder: a line arriving in fragments is reassembled" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try fixture.addCodec(addLineDecoder);
    const collector = try fixture.addCollector();

    for ("hello\r") |byte| {
        fixture.pipeline.fireRead(try Message.initBytes(gpa, &.{byte}));
        try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    }
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "\n"));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("hello", collector.messages.items[0]);
}

test "LineBasedFrameDecoder: keeps the delimiter when asked to" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LineBasedFrameDecoder.addTo(fixture.pipeline, .{
        .max_length = 16,
        .strip_delimiter = false,
    });
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "a\nb\r\n"));

    try testing.expectEqualStrings("a\n", collector.messages.items[0]);
    try testing.expectEqualStrings("b\r\n", collector.messages.items[1]);
}

test "LineBasedFrameDecoder: an oversized line fails and the stream recovers" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try fixture.addCodec(addLineDecoder);
    const collector = try fixture.addCollector();

    // 20 bytes with no ending exceeds the 16-byte limit, so it fails fast.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "x" ** 20));
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.FrameTooLong), collector.errors.items[0]);
    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);

    // The rest of the bad line is skipped, and the next line decodes normally.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "yyy\ngood\n"));
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("good", collector.messages.items[0]);
}

test "LineBasedFrameDecoder: an oversized line does not hide the frames behind it" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LineBasedFrameDecoder.addTo(fixture.pipeline, .{
        .max_length = 8,
        .fail_fast = false,
    });
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "0123456789\nshort\n"));

    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.FrameTooLong), collector.errors.items[0]);
    // The good line shared a read with the bad one. Reporting the failure must
    // not cost it: it is delivered in the same read, not held back to the next
    // one and lost if the peer never sends another.
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("short", collector.messages.items[0]);

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "next\n"));
    try testing.expectEqual(@as(usize, 2), collector.messages.items.len);
    try testing.expectEqualStrings("next", collector.messages.items[1]);
}

test "LineBasedFrameDecoder: an oversized line is reported once, not once per read" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LineBasedFrameDecoder.addTo(fixture.pipeline, .{ .max_length = 4 });
    const collector = try fixture.addCollector();

    // A peer that exceeds the limit and then dribbles bytes must not be able to
    // make the decoder raise an error per read.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "aaaaaaaaaa"));
    for (0..8) |_| {
        fixture.pipeline.fireRead(try Message.initBytes(gpa, "b"));
    }
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);

    // Recovery still works: the next line ending resynchronizes the stream.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "\nok\n"));
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("ok", collector.messages.items[0]);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
}

test "LineBasedFrameDecoder: a trailing partial line at end of stream is reported" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try fixture.addCodec(addLineDecoder);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "done\nhalf"));
    fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.IncompleteMessage), collector.errors.items[0]);
}

test "LineBasedFrameDecoder: randomly split input decodes identically" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x11e5);
    const random = prng.random();

    for (0..32) |_| {
        var fixture = try test_support.Fixture.init(gpa);
        defer fixture.deinit();
        try fixture.addCodec(addLineDecoder);
        const collector = try fixture.addCollector();

        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        var expected_lines: usize = 0;

        const line_count = random.intRangeAtMost(usize, 1, 8);
        for (0..line_count) |_| {
            const line_len = random.intRangeAtMost(usize, 0, 12);
            for (0..line_len) |_| {
                try wire.append(gpa, random.intRangeAtMost(u8, 'a', 'z'));
            }
            if (random.boolean()) try wire.append(gpa, '\r');
            try wire.append(gpa, '\n');
            expected_lines += 1;
        }

        var offset: usize = 0;
        while (offset < wire.items.len) {
            const chunk_len = random.intRangeAtMost(usize, 1, wire.items.len - offset);
            fixture.pipeline.fireRead(
                try Message.initBytes(gpa, wire.items[offset..][0..chunk_len]),
            );
            offset += chunk_len;
        }

        try testing.expectEqual(expected_lines, collector.messages.items.len);
        try testing.expectEqual(@as(usize, 0), collector.errors.items.len);
    }
}

// -- Length-field tests ----------------------------------------------------

/// Writes a `<u16 big-endian length><payload>` frame.
fn appendU16Frame(out: *std.ArrayList(u8), gpa: Allocator, payload: []const u8) !void {
    var header: [2]u8 = undefined;
    std.mem.writeInt(u16, &header, @intCast(payload.len), .big);
    try out.appendSlice(gpa, &header);
    try out.appendSlice(gpa, payload);
}

fn addU16Decoder(pipeline: *Pipeline) anyerror!void {
    _ = try LengthFieldBasedFrameDecoder.addTo(pipeline, .{
        .length_field_width = .two,
        .initial_bytes_to_strip = 2,
        .max_frame_length = 1024,
    });
}

test "LengthFieldBasedFrameDecoder: strips the header and delivers the body" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try fixture.addCodec(addU16Decoder);
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try appendU16Frame(&wire, gpa, "alpha");
    try appendU16Frame(&wire, gpa, "");
    try appendU16Frame(&wire, gpa, "omega");

    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));

    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    try testing.expectEqualStrings("alpha", collector.messages.items[0]);
    try testing.expectEqualStrings("", collector.messages.items[1]);
    try testing.expectEqualStrings("omega", collector.messages.items[2]);
}

test "LengthFieldBasedFrameDecoder: keeps the header when nothing is stripped" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LengthFieldBasedFrameDecoder.addTo(fixture.pipeline, .{
        .length_field_width = .two,
        .max_frame_length = 1024,
    });
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try appendU16Frame(&wire, gpa, "hi");

    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));
    try testing.expectEqualSlices(u8, &.{ 0, 2, 'h', 'i' }, collector.messages.items[0]);
}

test "LengthFieldBasedFrameDecoder: honours offset, adjustment and strip together" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    // Layout: 2 magic bytes, a u16 length that counts itself plus the body,
    // then the body. Delivered frames start at the body.
    _ = try LengthFieldBasedFrameDecoder.addTo(fixture.pipeline, .{
        .length_field_offset = 2,
        .length_field_width = .two,
        .length_adjustment = -2,
        .initial_bytes_to_strip = 4,
        .max_frame_length = 1024,
    });
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try wire.appendSlice(gpa, &.{ 0xAB, 0xCD });
    var header: [2]u8 = undefined;
    std.mem.writeInt(u16, &header, 2 + 7, .big); // length field + body
    try wire.appendSlice(gpa, &header);
    try wire.appendSlice(gpa, "payload");

    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("payload", collector.messages.items[0]);
}

test "LengthFieldBasedFrameDecoder: every field width round trips" {
    const gpa = testing.allocator;
    const widths = [_]LengthFieldWidth{ .one, .two, .three, .four, .eight };
    for (widths) |width| {
        for ([_]std.builtin.Endian{ .big, .little }) |endian| {
            var fixture = try test_support.Fixture.init(gpa);
            defer fixture.deinit();
            _ = try LengthFieldBasedFrameDecoder.addTo(fixture.pipeline, .{
                .length_field_width = width,
                .initial_bytes_to_strip = width.byteCount(),
                .endian = endian,
                .max_frame_length = 1024,
            });
            const collector = try fixture.addCollector();

            var wire = try Buffer.init(gpa, .{ .capacity = 32 });
            defer wire.deinit(gpa);
            try width.write(&wire, gpa, "framed".len, endian);
            try wire.writeBytes(gpa, "framed");

            fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.readableSlice()));
            try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
            try testing.expectEqualStrings("framed", collector.messages.items[0]);
        }
    }
}

test "LengthFieldBasedFrameDecoder: a truncated frame waits for the rest" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try fixture.addCodec(addU16Decoder);
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try appendU16Frame(&wire, gpa, "split across reads");

    for (wire.items, 0..) |byte, index| {
        fixture.pipeline.fireRead(try Message.initBytes(gpa, &.{byte}));
        const expected: usize = if (index + 1 == wire.items.len) 1 else 0;
        try testing.expectEqual(expected, collector.messages.items.len);
    }
    try testing.expectEqualStrings("split across reads", collector.messages.items[0]);
}

test "LengthFieldBasedFrameDecoder: an oversized frame is skipped, then framing resumes" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LengthFieldBasedFrameDecoder.addTo(fixture.pipeline, .{
        .length_field_width = .two,
        .initial_bytes_to_strip = 2,
        .max_frame_length = 16,
    });
    const collector = try fixture.addCollector();

    // Header claims 100 bytes; only 10 of them have arrived.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    var header: [2]u8 = undefined;
    std.mem.writeInt(u16, &header, 100, .big);
    try wire.appendSlice(gpa, &header);
    try wire.appendSlice(gpa, "0123456789");

    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));
    try testing.expectEqual(@as(anyerror, error.FrameTooLong), collector.errors.items[0]);

    // The remaining 90 bytes of the bad frame are swallowed as they arrive.
    const filler = try gpa.alloc(u8, 90);
    defer gpa.free(filler);
    @memset(filler, 'x');
    fixture.pipeline.fireRead(try Message.initBytes(gpa, filler));
    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);

    var good: std.ArrayList(u8) = .empty;
    defer good.deinit(gpa);
    try appendU16Frame(&good, gpa, "back");
    fixture.pipeline.fireRead(try Message.initBytes(gpa, good.items));
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("back", collector.messages.items[0]);
}

test "LengthFieldBasedFrameDecoder: an impossible header is rejected" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    // A length that counts the header, adjusted so a zero length would imply a
    // frame shorter than its own header.
    _ = try LengthFieldBasedFrameDecoder.addTo(fixture.pipeline, .{
        .length_field_width = .two,
        .length_adjustment = -8,
        .max_frame_length = 1024,
    });
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(gpa, &.{ 0, 0, 'x', 'y' }));
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.CorruptFrame), collector.errors.items[0]);
}

test "LengthFieldPrepender: writes a header in front of the body" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LengthFieldPrepender.addTo(fixture.pipeline, .{ .length_field_width = .two });

    try fixture.pipeline.write(try Message.initBytes(gpa, "abc"));
    try testing.expectEqualSlices(u8, &.{ 0, 3, 'a', 'b', 'c' }, fixture.written());
}

test "LengthFieldPrepender: the length can include the field itself" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LengthFieldPrepender.addTo(fixture.pipeline, .{
        .length_field_width = .two,
        .length_includes_length_field = true,
    });

    try fixture.pipeline.write(try Message.initBytes(gpa, "abc"));
    try testing.expectEqualSlices(u8, &.{ 0, 5, 'a', 'b', 'c' }, fixture.written());
}

test "LengthFieldPrepender: a body too large for the field is rejected" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LengthFieldPrepender.addTo(fixture.pipeline, .{ .length_field_width = .one });

    const body = try gpa.alloc(u8, 300);
    defer gpa.free(body);
    @memset(body, 'z');

    try testing.expectError(
        error.FrameTooLong,
        fixture.pipeline.write(try Message.initBytes(gpa, body)),
    );
}

test "LengthFieldPrepender and decoder are inverses" {
    const gpa = testing.allocator;

    // Encode with the prepender, then feed the bytes to the decoder and check
    // the payloads come back unchanged.
    var encoder_fixture = try test_support.Fixture.init(gpa);
    defer encoder_fixture.deinit();
    _ = try LengthFieldPrepender.addTo(encoder_fixture.pipeline, .{
        .length_field_width = .four,
    });

    const payloads = [_][]const u8{ "", "a", "hello world", "x" ** 200 };
    for (payloads) |payload| {
        try encoder_fixture.pipeline.write(try Message.initBytes(gpa, payload));
    }

    var decoder_fixture = try test_support.Fixture.init(gpa);
    defer decoder_fixture.deinit();
    _ = try LengthFieldBasedFrameDecoder.addTo(decoder_fixture.pipeline, .{
        .length_field_width = .four,
        .initial_bytes_to_strip = 4,
        .max_frame_length = 4096,
    });
    const collector = try decoder_fixture.addCollector();

    decoder_fixture.pipeline.fireRead(
        try Message.initBytes(gpa, encoder_fixture.written()),
    );

    try testing.expectEqual(payloads.len, collector.messages.items.len);
    for (payloads, collector.messages.items) |wanted, got| {
        try testing.expectEqualSlices(u8, wanted, got);
    }
}

test "LengthFieldBasedFrameDecoder: a corrupt length is reported once and ends the stream" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LengthFieldBasedFrameDecoder.addTo(fixture.pipeline, .{
        .length_field_width = .four,
        // A negative adjustment large enough that some lengths describe a frame
        // shorter than its own header.
        .length_adjustment = -8,
        .max_frame_length = 64,
    });
    const collector = try fixture.addCollector();

    // Length 0 with a -8 adjustment implies a frame smaller than its header,
    // which says the stream is not where the decoder thinks it is.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "\x00\x00\x00\x00"));
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.CorruptFrame), collector.errors.items[0]);

    // Nothing after a desynchronized length is trusted, and no further errors
    // are raised however much the peer sends.
    for (0..16) |_| {
        fixture.pipeline.fireRead(try Message.initBytes(gpa, "\x00\x00\x00\x0chello world!"));
    }
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
}

test "LengthFieldBasedFrameDecoder: an oversized frame does not hide the frame behind it" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try LengthFieldBasedFrameDecoder.addTo(fixture.pipeline, .{
        .length_field_width = .two,
        .initial_bytes_to_strip = 2,
        .max_frame_length = 16,
    });
    const collector = try fixture.addCollector();

    // An over-long frame followed, in the same read, by a good one. The length
    // field says exactly how much to skip, so the good frame must survive.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try wire.appendSlice(gpa, "\x00\x20");
    try wire.appendSlice(gpa, "x" ** 32);
    try wire.appendSlice(gpa, "\x00\x02ok");

    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));

    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.FrameTooLong), collector.errors.items[0]);
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("ok", collector.messages.items[0]);
}

// -- FixedLengthFrameDecoder -----------------------------------------------

fn addFixed(pipeline: *Pipeline) anyerror!void {
    _ = try FixedLengthFrameDecoder.addTo(pipeline, .{ .frame_length = 3 });
}

test "FixedLengthFrameDecoder: splits a stream into equal frames" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addFixed);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "abcdefghi"));

    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    try testing.expectEqualStrings("abc", collector.messages.items[0]);
    try testing.expectEqualStrings("def", collector.messages.items[1]);
    try testing.expectEqualStrings("ghi", collector.messages.items[2]);
}

test "FixedLengthFrameDecoder: a partial frame waits for the rest" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addFixed);
    const collector = try fixture.addCollector();

    // One byte at a time: nothing until the third.
    for ("ab") |byte| {
        fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, &.{byte}));
        try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    }
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "c"));
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("abc", collector.messages.items[0]);
}

test "FixedLengthFrameDecoder: a truncated tail fails at end of stream" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addFixed);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "abcd"));
    fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.IncompleteMessage), collector.errors.items[0]);
}

// -- DelimiterBasedFrameDecoder --------------------------------------------

fn addDelimiter(pipeline: *Pipeline) anyerror!void {
    _ = try DelimiterBasedFrameDecoder.addTo(pipeline, .{ .max_length = 16 });
}

test "DelimiterBasedFrameDecoder: CRLF wins over LF at the same position" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDelimiter);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "one\r\ntwo\nthree\r\n"));

    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    // No stray carriage return: the two-byte delimiter matched first.
    try testing.expectEqualStrings("one", collector.messages.items[0]);
    try testing.expectEqualStrings("two", collector.messages.items[1]);
    try testing.expectEqualStrings("three", collector.messages.items[2]);
}

test "DelimiterBasedFrameDecoder: a custom delimiter set" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    const build = struct {
        fn add(pipeline: *Pipeline) anyerror!void {
            _ = try DelimiterBasedFrameDecoder.addTo(pipeline, .{
                .delimiters = Delimiters.nul,
                .max_length = 16,
            });
        }
    }.add;
    try fixture.addCodec(build);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "a\x00bb\x00"));

    try testing.expectEqual(@as(usize, 2), collector.messages.items.len);
    try testing.expectEqualStrings("a", collector.messages.items[0]);
    try testing.expectEqualStrings("bb", collector.messages.items[1]);
}

test "DelimiterBasedFrameDecoder: keeping the delimiter is optional" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    const build = struct {
        fn add(pipeline: *Pipeline) anyerror!void {
            _ = try DelimiterBasedFrameDecoder.addTo(pipeline, .{
                .max_length = 16,
                .strip_delimiter = false,
            });
        }
    }.add;
    try fixture.addCodec(build);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "one\r\n"));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("one\r\n", collector.messages.items[0]);
}

test "DelimiterBasedFrameDecoder: an oversized frame does not hide the frame behind it" {
    // The same property the line decoder has: a failure about one frame must
    // not abort the drain and strand the good frames in the same read.
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    const build = struct {
        fn add(pipeline: *Pipeline) anyerror!void {
            _ = try DelimiterBasedFrameDecoder.addTo(pipeline, .{
                .max_length = 4,
                .fail_fast = false,
            });
        }
    }.add;
    try fixture.addCodec(build);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(
        testing.allocator,
        "wayyytoolong\r\nfine\r\n",
    ));

    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.FrameTooLong), collector.errors.items[0]);
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("fine", collector.messages.items[0]);
}

test "DelimiterBasedFrameDecoder: resynchronizes on a delimiter split across reads" {
    // The case that a single-byte delimiter cannot produce: the discard ends on
    // a `\r` whose `\n` has not arrived yet. Dropping the whole buffer would
    // miss that boundary and swallow the next good frame too.
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    const build = struct {
        fn add(pipeline: *Pipeline) anyerror!void {
            _ = try DelimiterBasedFrameDecoder.addTo(pipeline, .{
                .delimiters = &.{"\r\n"},
                .max_length = 4,
            });
        }
    }.add;
    try fixture.addCodec(build);
    const collector = try fixture.addCollector();

    // Over-long, and the read stops right between the CR and the LF.
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "toolongforthis\r"));
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.FrameTooLong), collector.errors.items[0]);

    // The rest of the delimiter, then a good frame.
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "\ngood\r\n"));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("good", collector.messages.items[0]);
}
