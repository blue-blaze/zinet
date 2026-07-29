//! The foundation every protocol codec is built on.
//!
//! TCP gives a byte stream, not messages. A read can deliver half a frame, or
//! three frames and a fragment. Every protocol implementation therefore needs
//! the same two pieces of machinery, and getting them wrong is the classic
//! source of protocol bugs:
//!
//! * `ByteToMessageDecoder` accumulates inbound bytes and repeatedly asks a
//!   protocol-specific `decode` for as many messages as the buffer holds.
//! * `MessageToByteEncoder` turns an outbound message of some type back into
//!   bytes.
//!
//! Both are mixins in the Zig sense: a generic struct that a codec embeds and
//! drives, rather than a base class it inherits from.
//!
//! # The decode contract
//!
//! `decode(self, ctx, cumulation) !?Message` is called with the accumulated
//! bytes and must do one of:
//!
//! * consume a whole message from `cumulation` and return it,
//! * consume nothing and return `null`, meaning "not enough bytes yet", or
//! * consume bytes and return `null`, which is how a decoder skips over a
//!   corrupt or oversized frame to resynchronize.
//!
//! Returning a message without consuming anything is a bug and is asserted
//! against: it would turn the decode loop into an infinite one.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../buffer.zig").Buffer;
const pipeline_mod = @import("../pipeline.zig");

const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;

pub const Error = pipeline_mod.Error;

/// Accumulation strategy and limits shared by every byte-to-message decoder.
pub const DecoderOptions = struct {
    /// Hard ceiling on accumulated bytes that decoding could not turn into a
    /// message. A peer that sends an endless stream without ever completing a
    /// message must not be able to exhaust memory; when the residue exceeds
    /// this after a read, decoding fails with `error.MessageTooLarge`.
    max_cumulation: usize = 64 * 1024,
    /// Once this many leading bytes have been consumed, the accumulation buffer
    /// is compacted. Bounds the copying done per read while keeping the buffer
    /// from creeping forward forever.
    compact_threshold: usize = 4 * 1024,
};

/// Turns a stream of inbound byte chunks into a stream of protocol messages.
///
/// `Codec` must provide:
///
/// ```
/// fn decode(self: *Codec, ctx: *HandlerContext, cumulation: *Buffer) Error!?Message
/// ```
///
/// and may additionally provide:
///
/// ```
/// /// Last chance to emit a message when the peer has stopped sending.
/// fn decodeLast(self: *Codec, ctx: *HandlerContext, cumulation: *Buffer) Error!?Message
/// ```
///
/// Embed it as a field and forward the handler callbacks to it:
///
/// ```
/// const MyCodec = struct {
///     decoder: ByteToMessageDecoder(MyCodec) = .{},
///
///     pub fn onRead(self: *MyCodec, ctx: *HandlerContext, msg: Message) Error!void {
///         return self.decoder.onRead(self, ctx, msg);
///     }
///     pub fn onInactive(self: *MyCodec, ctx: *HandlerContext) Error!void {
///         return self.decoder.onInactive(self, ctx);
///     }
///     fn decode(self: *MyCodec, ctx: *HandlerContext, cumulation: *Buffer) Error!?Message {
///         ...
///     }
/// };
/// ```
pub fn ByteToMessageDecoder(comptime Codec: type) type {
    return struct {
        const Self = @This();

        /// Bytes seen but not yet turned into messages. Empty until the first
        /// partial message arrives, so a stream of whole messages never
        /// allocates here.
        cumulation: Buffer = .empty,
        options: DecoderOptions = .{},
        /// Set once the peer stops sending, so late arrivals are rejected
        /// rather than silently decoded.
        finished: bool = false,

        /// Releases the accumulation buffer. Call from the codec's `deinit`.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.cumulation.deinit(gpa);
        }

        /// Bytes accumulated but not yet decoded.
        pub fn pendingLen(self: *const Self) usize {
            return self.cumulation.readableLen();
        }

        /// Handler entry point: accumulate `msg`, then drain as many messages
        /// as the accumulated bytes allow.
        ///
        /// Takes ownership of `msg`.
        pub fn onRead(
            self: *Self,
            codec: *Codec,
            ctx: *HandlerContext,
            msg: Message,
        ) Error!void {
            var owned = msg;
            if (owned.bytes() == null) {
                // Not bytes; a decoder has no opinion on it, so pass ownership
                // straight along. Note this returns before the release below
                // is armed: forwarding and releasing are exclusive.
                ctx.fireRead(owned.move());
                return;
            }

            defer owned.deinit(ctx.gpa());
            if (self.finished) return error.StreamAlreadyFinished;

            try self.append(ctx.gpa(), owned.bytes().?);
            try self.drain(codec, ctx, false);
            return self.enforceResidueLimit();
        }

        /// Handler entry point for the end of the stream: give the codec a last
        /// chance to emit, then fail if bytes remain undecodable.
        pub fn onInactive(self: *Self, codec: *Codec, ctx: *HandlerContext) Error!void {
            defer ctx.fireInactive();
            if (self.finished) return;
            self.finished = true;

            try self.drainLast(codec, ctx);

            const leftover = self.cumulation.readableLen();
            self.cumulation.clear();
            if (leftover != 0) return error.IncompleteMessage;
        }

        /// Like `drain`, but makes at least one call even with nothing buffered.
        ///
        /// A decoder may be holding a message that only the end of the stream
        /// completes — an HTTP response whose body runs until the connection
        /// closes is the canonical case, and it can be *empty*, so waiting for
        /// leftover bytes before asking would lose it. Netty likewise calls
        /// `decodeLast` with an empty buffer.
        ///
        /// Consuming bytes is the only thing that earns another round, so a
        /// codec that emits a held message without consuming anything is called
        /// once and not looped over.
        fn drainLast(self: *Self, codec: *Codec, ctx: *HandlerContext) Error!void {
            var again = true;
            while (again) {
                const before = self.cumulation.readableLen();
                const decoded = try self.callDecode(codec, ctx, true);
                const after = self.cumulation.readableLen();
                if (decoded) |message| {
                    var owned = message;
                    ctx.fireRead(owned.move());
                }
                again = after < before;
            }
            self.compactIfNeeded();
        }

        /// Hands undecoded bytes to the next inbound handler when this decoder
        /// is removed from the pipeline.
        ///
        /// This is what makes a protocol upgrade lossless. A client may send its
        /// first post-upgrade bytes in the same read as the upgrade request; they
        /// are sitting in this decoder's accumulation buffer when the handshake
        /// replaces it, and without this they would be freed along with it.
        ///
        /// Forward from the codec's `onRemoved` to enable it.
        pub fn onRemoved(self: *Self, ctx: *HandlerContext) void {
            // After end of stream there is nothing legitimate to forward, and
            // firing a read during teardown would be surprising.
            if (self.finished) return;
            if (self.cumulation.readableLen() == 0) return;
            ctx.fireRead(.initBuffer(&self.cumulation));
        }

        /// Copies `incoming` into the accumulation buffer.
        ///
        /// The limit is not applied here: one read may legitimately carry many
        /// messages, and their total can exceed what any single message is
        /// allowed to be. What must stay bounded is the *undecoded* residue,
        /// which `enforceResidueLimit` checks once decoding has had its turn.
        fn append(self: *Self, gpa: Allocator, incoming: []const u8) Error!void {
            const needed = self.cumulation.readableLen() + incoming.len;
            if (self.cumulation.max_capacity < needed) {
                self.cumulation.max_capacity = needed;
            }
            try self.cumulation.writeBytes(gpa, incoming);
        }

        /// Fails when bytes that no message could be made of are piling up.
        ///
        /// Peak memory is therefore bounded by `max_cumulation` plus one read,
        /// and the read size is itself a channel-level setting.
        fn enforceResidueLimit(self: *Self) Error!void {
            if (self.cumulation.readableLen() <= self.options.max_cumulation) return;
            self.cumulation.clear();
            return error.MessageTooLarge;
        }

        /// Calls `decode` until it stops making progress.
        ///
        /// Every iteration either emits a message, consumes bytes without
        /// emitting one (a decoder resynchronizing after a corrupt frame), or
        /// makes no progress at all — and only the last of those ends the loop.
        /// Since the first two strictly shrink the buffer, the loop terminates.
        fn drain(self: *Self, codec: *Codec, ctx: *HandlerContext, last: bool) Error!void {
            while (self.cumulation.readableLen() > 0) {
                const before = self.cumulation.readableLen();
                const decoded = try self.callDecode(codec, ctx, last);
                const after = self.cumulation.readableLen();

                if (decoded) |message| {
                    // A message must correspond to consumed bytes, otherwise
                    // this loop would never end.
                    assert(after < before);
                    ctx.fireRead(message);
                    continue;
                }
                // No message: either bytes were skipped, in which case there may
                // be a message behind them, or more input is needed.
                if (after == before) break;
            }
            self.compactIfNeeded();
        }

        fn callDecode(
            self: *Self,
            codec: *Codec,
            ctx: *HandlerContext,
            last: bool,
        ) Error!?Message {
            if (last and @hasDecl(Codec, "decodeLast")) {
                return codec.decodeLast(ctx, &self.cumulation);
            }
            return codec.decode(ctx, &self.cumulation);
        }

        fn compactIfNeeded(self: *Self) void {
            if (self.cumulation.readableLen() == 0) {
                self.cumulation.clear();
                return;
            }
            if (self.cumulation.reader_index >= self.options.compact_threshold) {
                self.cumulation.discardReadBytes();
            }
        }
    };
}

/// Turns outbound messages of one type back into bytes.
///
/// `Codec` must provide:
///
/// ```
/// fn encode(self: *Codec, ctx: *HandlerContext, value: *const Payload, out: *Buffer) Error!void
/// ```
///
/// where `Payload` is the type given to `MessageToByteEncoder`. Messages that
/// do not carry a `Payload` are passed through untouched, which is what lets an
/// encoder sit in a pipeline that also writes raw bytes.
pub fn MessageToByteEncoder(comptime Codec: type, comptime Payload: type) type {
    return struct {
        const Self = @This();

        /// Bytes reserved for the encoded form of the first message. Grows as
        /// needed; sized to avoid a reallocation for typical messages.
        initial_capacity: usize = 512,
        /// Ceiling on one encoded message.
        max_capacity: usize = Buffer.default_max_capacity,

        /// Handler entry point. Takes ownership of `msg`.
        pub fn onWrite(
            self: *Self,
            codec: *Codec,
            ctx: *HandlerContext,
            msg: Message,
        ) Error!void {
            var owned = msg;
            const payload = owned.get(Payload) orelse {
                // Not ours: forward without touching it.
                return ctx.write(owned.move());
            };
            defer owned.deinit(ctx.gpa());

            var out = try Buffer.init(ctx.gpa(), .{
                .capacity = self.initial_capacity,
                .max_capacity = self.max_capacity,
            });
            errdefer out.deinit(ctx.gpa());

            try codec.encode(ctx, payload, &out);
            if (out.readableLen() == 0) {
                // Nothing to send; drop the empty buffer rather than issuing a
                // zero-length write.
                out.deinit(ctx.gpa());
                return;
            }
            return ctx.write(.initBuffer(&out));
        }
    };
}

/// Whether `In` means "any message carrying bytes" rather than a specific
/// payload struct.
///
/// Netty spells this distinction with the type parameter —
/// `MessageToMessageDecoder<ByteBuf>` versus `MessageToMessageDecoder<MyType>`
/// — and so does Zinet, except that here it is one `comptime` branch instead of
/// two class hierarchies.
fn matchesBytes(comptime In: type) bool {
    return In == []const u8;
}

/// The value a codec is handed for input type `In`.
fn Matched(comptime In: type) type {
    return if (matchesBytes(In)) []const u8 else *const In;
}

/// Extracts `In` from a message, or null if the message is not ours.
fn matchMessage(comptime In: type, msg: *const Message) ?Matched(In) {
    if (comptime matchesBytes(In)) return msg.bytes();
    return msg.get(In);
}

/// Transforms inbound messages of one type into messages of another.
///
/// This is the base class for every decoder whose input is already framed —
/// sitting behind a `LengthFieldBasedFrameDecoder`, say — as opposed to
/// `ByteToMessageDecoder`, which exists to do the framing. Netty draws the same
/// line, and for the same reason: accumulation is the expensive, easy-to-get-
/// wrong part, and a decoder that does not need it should not pay for it.
///
/// `Codec` must provide:
///
/// ```
/// fn decode(self: *Codec, ctx: *HandlerContext, value: Matched(In)) Error!?Message
/// ```
///
/// Return null to drop the input. To emit more than one message, fire the
/// extras through `ctx.fireRead` and return the last (or null); the ordering is
/// the order of the calls.
///
/// Ownership: the input message is released once `decode` returns, including on
/// failure, so `value` must not be retained. Messages that do not carry an `In`
/// are forwarded untouched, which is what lets a decoder share a pipeline with
/// traffic it does not understand.
pub fn MessageToMessageDecoder(comptime Codec: type, comptime In: type) type {
    return struct {
        /// Handler entry point. Takes ownership of `msg`.
        pub fn onRead(codec: *Codec, ctx: *HandlerContext, msg: Message) Error!void {
            var owned = msg;
            const value = matchMessage(In, &owned) orelse {
                // Not ours: forward without touching it.
                ctx.fireRead(owned.move());
                return;
            };
            // Released even when `decode` fails: the contract is that a
            // callback which returns an error has already disposed of its
            // message.
            defer owned.deinit(ctx.gpa());

            var out = try codec.decode(ctx, value) orelse return;
            ctx.fireRead(out.move());
        }
    };
}

/// Transforms outbound messages of one type into messages of another.
///
/// The mirror of `MessageToMessageDecoder`, and the counterpart to
/// `MessageToByteEncoder` for encoders whose output is another message rather
/// than raw bytes — a frame that a length prepender will then serialize, for
/// instance.
///
/// `Codec` must provide:
///
/// ```
/// fn encode(self: *Codec, ctx: *HandlerContext, value: Matched(Out)) Error!?Message
/// ```
///
/// Ownership matches the decoder's: the input message is released when `encode`
/// returns, and foreign messages pass through. Returning null drops the
/// message, which is a legitimate way to swallow one — but note that `Sink`
/// guarantees a write always consumes its message, so dropping is invisible to
/// the caller.
pub fn MessageToMessageEncoder(comptime Codec: type, comptime Out: type) type {
    return struct {
        /// Handler entry point. Takes ownership of `msg`.
        pub fn onWrite(codec: *Codec, ctx: *HandlerContext, msg: Message) Error!void {
            var owned = msg;
            const value = matchMessage(Out, &owned) orelse {
                return ctx.write(owned.move());
            };
            defer owned.deinit(ctx.gpa());

            var out = try codec.encode(ctx, value) orelse return;
            return ctx.write(out.move());
        }
    };
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const test_support = @import("test_support.zig");

/// Decodes `<u16 big-endian length><payload>` frames into `[]u8` messages.
///
/// Deliberately simple: the point of these tests is the accumulation
/// machinery, not the protocol.
const LengthPrefixedCodec = struct {
    decoder: ByteToMessageDecoder(LengthPrefixedCodec) = .{},
    decode_calls: usize = 0,

    pub const handler_name = "length-prefixed";

    pub fn onRead(
        self: *LengthPrefixedCodec,
        ctx: *HandlerContext,
        msg: Message,
    ) Error!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *LengthPrefixedCodec, ctx: *HandlerContext) Error!void {
        return self.decoder.onInactive(self, ctx);
    }

    pub fn deinit(self: *LengthPrefixedCodec, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    fn decode(
        self: *LengthPrefixedCodec,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) Error!?Message {
        self.decode_calls += 1;
        const header_len = @sizeOf(u16);
        if (cumulation.readableLen() < header_len) return null;

        const frame_len = try cumulation.peekInt(u16, .big);
        if (cumulation.readableLen() < header_len + frame_len) return null;

        try cumulation.skip(header_len);
        const payload = try cumulation.readBytes(frame_len);
        return try Message.initBytes(ctx.gpa(), payload);
    }
};

fn buildLengthPrefixed(pipeline: *pipeline_mod.Pipeline) anyerror!void {
    const codec = try pipeline.gpa.create(LengthPrefixedCodec);
    codec.* = .{};
    errdefer pipeline.gpa.destroy(codec);
    _ = try pipeline.addLast("codec", .initOwned(codec));
}

fn frame(out: *std.ArrayList(u8), gpa: Allocator, payload: []const u8) !void {
    var header: [2]u8 = undefined;
    std.mem.writeInt(u16, &header, @intCast(payload.len), .big);
    try out.appendSlice(gpa, &header);
    try out.appendSlice(gpa, payload);
}

test "ByteToMessageDecoder: a whole frame in one read decodes immediately" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    try fixture.addCodec(buildLengthPrefixed);
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try frame(&wire, gpa, "hello");

    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("hello", collector.messages.items[0]);
}

test "ByteToMessageDecoder: several frames in one read all decode" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    try fixture.addCodec(buildLengthPrefixed);
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try frame(&wire, gpa, "one");
    try frame(&wire, gpa, "two");
    try frame(&wire, gpa, "three");

    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));

    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    try testing.expectEqualStrings("one", collector.messages.items[0]);
    try testing.expectEqualStrings("two", collector.messages.items[1]);
    try testing.expectEqualStrings("three", collector.messages.items[2]);
}

test "ByteToMessageDecoder: a frame split byte by byte is reassembled" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    try fixture.addCodec(buildLengthPrefixed);
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try frame(&wire, gpa, "fragmented payload");

    for (wire.items, 0..) |byte, index| {
        fixture.pipeline.fireRead(try Message.initBytes(gpa, &.{byte}));
        // Nothing may be emitted before the very last byte arrives.
        const expected: usize = if (index + 1 == wire.items.len) 1 else 0;
        try testing.expectEqual(expected, collector.messages.items.len);
    }
    try testing.expectEqualStrings("fragmented payload", collector.messages.items[0]);
}

test "ByteToMessageDecoder: randomly split streams decode identically" {
    const gpa = testing.allocator;

    var prng: std.Random.DefaultPrng = .init(0xC0DEC);
    const random = prng.random();

    for (0..64) |_| {
        var fixture = try test_support.Fixture.init(gpa);
        defer fixture.deinit();
        try fixture.addCodec(buildLengthPrefixed);
        const collector = try fixture.addCollector();

        // Build a stream of frames, then chop it at arbitrary boundaries.
        var expected: std.ArrayList([]const u8) = .empty;
        defer {
            for (expected.items) |item| gpa.free(item);
            expected.deinit(gpa);
        }
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);

        const frame_count = random.intRangeAtMost(usize, 1, 8);
        for (0..frame_count) |_| {
            const payload_len = random.intRangeAtMost(usize, 0, 64);
            const payload = try gpa.alloc(u8, payload_len);
            random.bytes(payload);
            try expected.append(gpa, payload);
            try frame(&wire, gpa, payload);
        }

        var offset: usize = 0;
        while (offset < wire.items.len) {
            const remaining = wire.items.len - offset;
            const chunk_len = random.intRangeAtMost(usize, 1, remaining);
            fixture.pipeline.fireRead(
                try Message.initBytes(gpa, wire.items[offset..][0..chunk_len]),
            );
            offset += chunk_len;
        }

        try testing.expectEqual(expected.items.len, collector.messages.items.len);
        for (expected.items, collector.messages.items) |wanted, got| {
            try testing.expectEqualSlices(u8, wanted, got);
        }
    }
}

test "ByteToMessageDecoder: accumulation is bounded" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    // A codec that never completes a message, so everything accumulates.
    const Hoarder = struct {
        decoder: ByteToMessageDecoder(@This()) = .{},

        pub fn onRead(self: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            return self.decoder.onRead(self, ctx, msg);
        }
        pub fn deinit(self: *@This(), gpa_: Allocator) void {
            self.decoder.deinit(gpa_);
        }
        fn decode(_: *@This(), _: *HandlerContext, _: *Buffer) Error!?Message {
            return null;
        }
    };
    const Failures = struct {
        seen: ?anyerror = null,
        pub fn onError(self: *@This(), _: *HandlerContext, err: anyerror) void {
            self.seen = err;
        }
    };

    const hoarder = try gpa.create(Hoarder);
    hoarder.* = .{};
    hoarder.decoder.options.max_cumulation = 16;
    _ = try fixture.pipeline.addLast("hoarder", .initOwned(hoarder));

    var failures: Failures = .{};
    _ = try fixture.pipeline.addLast("failures", .init(&failures));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "0123456789"));
    try testing.expectEqual(@as(usize, 10), hoarder.decoder.pendingLen());
    try testing.expect(failures.seen == null);

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "0123456789"));
    try testing.expectEqual(@as(?anyerror, error.MessageTooLarge), failures.seen);
}

test "ByteToMessageDecoder: leftover bytes at end of stream are reported" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    try fixture.addCodec(buildLengthPrefixed);
    const Failures = struct {
        seen: ?anyerror = null,
        inactive: usize = 0,
        pub fn onError(self: *@This(), _: *HandlerContext, err: anyerror) void {
            self.seen = err;
        }
        pub fn onInactive(self: *@This(), ctx: *HandlerContext) Error!void {
            self.inactive += 1;
            ctx.fireInactive();
        }
    };
    var failures: Failures = .{};
    _ = try fixture.pipeline.addLast("failures", .init(&failures));

    // Header promises five bytes but only two arrive before the peer leaves.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, &.{ 0, 5, 'a', 'b' }));
    try testing.expect(failures.seen == null);

    fixture.pipeline.fireInactive();
    try testing.expectEqual(@as(?anyerror, error.IncompleteMessage), failures.seen);
    try testing.expectEqual(@as(usize, 1), failures.inactive);
}

test "ByteToMessageDecoder: a clean end of stream reports nothing" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    try fixture.addCodec(buildLengthPrefixed);
    const collector = try fixture.addCollector();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try frame(&wire, gpa, "complete");
    fixture.pipeline.fireRead(try Message.initBytes(gpa, wire.items));
    fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 0), fixture.pipeline.stats.unhandled_errors);
}

test "ByteToMessageDecoder: non-byte messages pass through untouched" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    try fixture.addCodec(buildLengthPrefixed);

    const Ticket = struct { id: u32 };
    const Watcher = struct {
        seen: ?u32 = null,
        pub fn onRead(self: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            if (owned.get(Ticket)) |ticket| self.seen = ticket.id;
        }
    };
    var watcher: Watcher = .{};
    _ = try fixture.pipeline.addLast("watcher", .init(&watcher));

    fixture.pipeline.fireRead(try Message.initAny(gpa, Ticket, .{ .id = 7 }));
    try testing.expectEqual(@as(?u32, 7), watcher.seen);
}

/// Encodes a `Greeting` into `hello <name>!`.
const GreetingCodec = struct {
    encoder: MessageToByteEncoder(GreetingCodec, Greeting) = .{},

    pub const Greeting = struct { name: []const u8 };

    pub fn onWrite(self: *GreetingCodec, ctx: *HandlerContext, msg: Message) Error!void {
        return self.encoder.onWrite(self, ctx, msg);
    }

    fn encode(
        _: *GreetingCodec,
        ctx: *HandlerContext,
        value: *const Greeting,
        out: *Buffer,
    ) Error!void {
        try out.writeBytes(ctx.gpa(), "hello ");
        try out.writeBytes(ctx.gpa(), value.name);
        try out.writeByte(ctx.gpa(), '!');
    }
};

test "MessageToByteEncoder: encodes its payload type into bytes" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    var codec: GreetingCodec = .{};
    _ = try fixture.pipeline.addLast("greeting", .init(&codec));

    try fixture.pipeline.write(
        try Message.initAny(gpa, GreetingCodec.Greeting, .{ .name = "zinet" }),
    );
    try testing.expectEqualStrings("hello zinet!", fixture.written());
}

test "MessageToByteEncoder: other payloads are forwarded unchanged" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    var codec: GreetingCodec = .{};
    _ = try fixture.pipeline.addLast("greeting", .init(&codec));

    try fixture.pipeline.write(try Message.initBytes(gpa, "raw bytes"));
    try testing.expectEqualStrings("raw bytes", fixture.written());
}

test "MessageToByteEncoder: an empty encoding writes nothing" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();

    const Silent = struct {
        encoder: MessageToByteEncoder(@This(), Payload) = .{},
        pub const Payload = struct { drop: bool };

        pub fn onWrite(self: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            return self.encoder.onWrite(self, ctx, msg);
        }
        fn encode(_: *@This(), _: *HandlerContext, _: *const Payload, _: *Buffer) Error!void {}
    };
    var silent: Silent = .{};
    _ = try fixture.pipeline.addLast("silent", .init(&silent));

    try fixture.pipeline.write(try Message.initAny(gpa, Silent.Payload, .{ .drop = true }));
    try testing.expectEqualStrings("", fixture.written());
}

// -- MessageToMessage base classes -----------------------------------------

/// Upper-cases byte messages, and demonstrates the `[]const u8` input form.
const ShoutCodec = struct {
    const Base = MessageToMessageDecoder(ShoutCodec, []const u8);

    /// Set to have `decode` fail, so the test can check the input is still
    /// released.
    fail: bool = false,
    /// Set to have `decode` drop its input.
    drop: bool = false,
    /// Emit this many extra messages before the returned one.
    extras: usize = 0,

    pub const handler_name = "shout";

    pub fn onRead(self: *ShoutCodec, ctx: *HandlerContext, msg: Message) Error!void {
        return Base.onRead(self, ctx, msg);
    }

    pub fn decode(self: *ShoutCodec, ctx: *HandlerContext, value: []const u8) Error!?Message {
        if (self.fail) return error.MalformedMessage;
        if (self.drop) return null;

        var i: usize = 0;
        while (i < self.extras) : (i += 1) {
            var extra = try Message.initBytes(ctx.gpa(), "extra");
            ctx.fireRead(extra.move());
        }

        var out = try Buffer.init(ctx.gpa(), .{ .capacity = value.len });
        errdefer out.deinit(ctx.gpa());
        for (value) |byte| try out.writeByte(ctx.gpa(), std.ascii.toUpper(byte));
        return .initBuffer(&out);
    }
};

/// Renders a struct payload into bytes on the way out, demonstrating the
/// specific-type input form.
const TicketCodec = struct {
    const Base = MessageToMessageEncoder(TicketCodec, Ticket);

    pub const Ticket = struct { id: u32 };
    pub const handler_name = "ticket";

    pub fn onWrite(self: *TicketCodec, ctx: *HandlerContext, msg: Message) Error!void {
        return Base.onWrite(self, ctx, msg);
    }

    pub fn encode(_: *TicketCodec, ctx: *HandlerContext, value: *const Ticket) Error!?Message {
        var out = try Buffer.init(ctx.gpa(), .{ .capacity = 16 });
        errdefer out.deinit(ctx.gpa());
        try out.writeInt(ctx.gpa(), u32, value.id, .big);
        return .initBuffer(&out);
    }
};

test "MessageToMessageDecoder: transforms bytes and forwards the result" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();

    var shout: ShoutCodec = .{};
    _ = try fixture.pipeline.addLast("shout", .init(&shout));
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "hello"));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("HELLO", collector.messages.items[0]);
}

test "MessageToMessageDecoder: a message it does not recognize passes through" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();

    // A decoder whose input is bytes must not swallow an `any` message.
    var shout: ShoutCodec = .{};
    _ = try fixture.pipeline.addLast("shout", .init(&shout));
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initAny(
        testing.allocator,
        TicketCodec.Ticket,
        .{ .id = 7 },
    ));

    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.others.items.len);
}

test "MessageToMessageDecoder: returning null drops the input without leaking" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();

    var shout: ShoutCodec = .{ .drop = true };
    _ = try fixture.pipeline.addLast("shout", .init(&shout));
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "hello"));

    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 0), collector.errors.items.len);
}

test "MessageToMessageDecoder: a failing decode still releases its input" {
    // The leak checker is the real assertion here: `decode` returning an error
    // must not leave the caller holding the message.
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();

    var shout: ShoutCodec = .{ .fail = true };
    _ = try fixture.pipeline.addLast("shout", .init(&shout));
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "hello"));

    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.MalformedMessage), collector.errors.items[0]);
}

test "MessageToMessageDecoder: one input can fan out to several messages" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();

    var shout: ShoutCodec = .{ .extras = 2 };
    _ = try fixture.pipeline.addLast("shout", .init(&shout));
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "hi"));

    // Extras first, in call order, then the returned message.
    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    try testing.expectEqualStrings("extra", collector.messages.items[0]);
    try testing.expectEqualStrings("extra", collector.messages.items[1]);
    try testing.expectEqualStrings("HI", collector.messages.items[2]);
}

test "MessageToMessageEncoder: encodes its payload and passes others through" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();

    var ticket: TicketCodec = .{};
    _ = try fixture.pipeline.addLast("ticket", .init(&ticket));

    try fixture.pipeline.write(try Message.initAny(
        testing.allocator,
        TicketCodec.Ticket,
        .{ .id = 0x01020304 },
    ));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, fixture.written());

    // Raw bytes are not a Ticket, so they must reach the sink untouched.
    fixture.clearWritten();
    try fixture.pipeline.write(try Message.initBytes(testing.allocator, "raw"));
    try testing.expectEqualStrings("raw", fixture.written());
}
