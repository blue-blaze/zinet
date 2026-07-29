//! Redis serialization protocol (RESP), versions 2 and 3.
//!
//! RESP is the first protocol here whose values *nest*, which changes what a
//! decoder has to do. `ByteToMessageDecoder` demands that an incomplete message
//! consume no bytes, and a recursive parser that allocates as it descends cannot
//! honour that without unwinding whatever it built. So decoding is two passes
//! over the same bytes:
//!
//! 1. `Scanner` walks the value without allocating, to find out whether it is
//!    complete and how long it is. This is also where every limit is enforced,
//!    so a malformed or oversized value is rejected before a byte is committed.
//! 2. `Parser` then builds the value into an arena, knowing it cannot run out of
//!    input.
//!
//! Two passes cost one extra walk over bytes that are already in cache, and buy
//! a decoder with no rollback path — which is the part that would otherwise be
//! easy to get wrong.
//!
//! ## Direction
//!
//! `Value` is just a tree; who owns its strings depends on which way it is
//! travelling, per the rule the rest of the codecs follow. `Incoming` owns an
//! arena, because nothing else is around to keep a decoded value alive. Outbound
//! `Value` and `Command` borrow, because the caller already has the strings.
//!
//! That symmetry is what makes this usable from both ends: a Redis *client*
//! writes `Command` and reads `Incoming`; a Redis *server* reads `Incoming` (a
//! command arrives as an array of bulk strings) and writes `Value`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../buffer.zig").Buffer;
const codec_mod = @import("codec.zig");
const pipeline_mod = @import("../pipeline.zig");

const ByteToMessageDecoder = codec_mod.ByteToMessageDecoder;
const CodecError = codec_mod.Error;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Type markers, as they appear as the first byte of a value.
pub const Marker = enum(u8) {
    simple = '+',
    err = '-',
    integer = ':',
    bulk = '$',
    array = '*',
    // RESP3 additions.
    null = '_',
    boolean = '#',
    double = ',',
    big_number = '(',
    blob_error = '!',
    verbatim = '=',
    map = '%',
    set = '~',
    push = '>',

    pub fn parse(byte: u8) ?Marker {
        return switch (byte) {
            '+', '-', ':', '$', '*', '_', '#', ',', '(', '!', '=', '%', '~', '>' => @enumFromInt(byte),
            else => null,
        };
    }
};

/// A RESP value.
///
/// Aggregates hold slices of further values; `map` holds them flattened as
/// key, value, key, value, because a Zig slice of pairs would need a second type
/// for no gain and RESP itself sends them that way.
pub const Value = union(enum) {
    /// `+OK`
    simple: []const u8,
    /// `-ERR unknown command`
    err: []const u8,
    /// `:42`
    integer: i64,
    /// `$5\r\nhello`, or null for `$-1`, which RESP2 uses for "no such key".
    bulk: ?[]const u8,
    /// `*2\r\n...`, or null for `*-1`.
    array: ?[]const Value,
    /// RESP3 `_`, the replacement for both null forms above.
    null,
    /// RESP3 `#t` / `#f`.
    boolean: bool,
    /// RESP3 `,3.14`. `inf`, `-inf` and `nan` are all legal on the wire.
    double: f64,
    /// RESP3 `(`. Kept as text: the value can exceed any fixed-width integer,
    /// and inventing a bignum here would be a worse answer than handing over the
    /// digits.
    big_number: []const u8,
    /// RESP3 `!`, an error with a length prefix rather than a line.
    blob_error: []const u8,
    /// RESP3 `=`, a bulk string whose first three bytes name a format.
    verbatim: []const u8,
    /// RESP3 `%`, flattened as key, value, key, value.
    map: []const Value,
    /// RESP3 `~`.
    set: []const Value,
    /// RESP3 `>`, an out-of-band message rather than a reply to a command.
    push: []const Value,

    /// Whether this value is either RESP error form.
    pub fn isError(value: Value) bool {
        return switch (value) {
            .err, .blob_error => true,
            else => false,
        };
    }

    /// The text of an error, whichever form it took.
    pub fn errorText(value: Value) ?[]const u8 {
        return switch (value) {
            .err => |message| message,
            .blob_error => |message| message,
            else => null,
        };
    }

    /// Bytes of a string-ish value, for the common case of reading a reply.
    pub fn text(value: Value) ?[]const u8 {
        return switch (value) {
            .simple => |bytes| bytes,
            .bulk => |bytes| bytes,
            .verbatim => |bytes| bytes,
            .big_number => |bytes| bytes,
            else => null,
        };
    }

    /// Elements of any aggregate.
    pub fn elements(value: Value) ?[]const Value {
        return switch (value) {
            .array => |items| items,
            .map => |items| items,
            .set => |items| items,
            .push => |items| items,
            else => null,
        };
    }
};

/// A decoded value. Owns the arena its strings and element slices live in.
pub const Incoming = struct {
    arena: std.heap.ArenaAllocator,
    value: Value,

    pub fn init(gpa: Allocator) Incoming {
        return .{ .arena = .init(gpa), .value = .null };
    }

    /// Takes an allocator it does not use so `Message`'s type-erased destructor
    /// can call it uniformly.
    pub fn deinit(incoming: *Incoming, _: Allocator) void {
        incoming.arena.deinit();
    }

    pub fn allocator(incoming: *Incoming) Allocator {
        return incoming.arena.allocator();
    }
};

/// A command to send, as the array of bulk strings a real client sends.
///
/// RESP also allows "inline commands" — a bare line, for typing at a socket by
/// hand — but no client uses them for real traffic and they cannot carry
/// arbitrary bytes, so only the array form is written.
pub const Command = struct {
    args: []const []const u8,
};

/// Caps on what a peer can make the decoder do.
pub const Limits = struct {
    /// Longest line for the line-terminated types, which bounds a simple string
    /// or an error message.
    max_line: usize = 64 * 1024,
    /// Longest bulk string, blob error or verbatim string.
    max_bulk: usize = 64 * 1024 * 1024,
    /// Most elements in one aggregate.
    max_elements: usize = 1024 * 1024,
    /// Deepest nesting accepted.
    ///
    /// This is not a comfort limit: `*1\r\n` repeated is a nesting bomb, and both
    /// passes below recurse, so without a bound a peer could exhaust the stack
    /// with a few dozen bytes.
    max_depth: usize = 32,
};

/// Walks a value without allocating, to decide whether it is complete.
///
/// Every limit is checked here rather than during parsing, so that nothing is
/// committed for a value that will be rejected.
const Scanner = struct {
    bytes: []const u8,
    at: usize = 0,
    limits: Limits,

    const Error = error{
        /// Not all of the value has arrived. The only non-fatal outcome.
        Incomplete,
        UnknownMarker,
        LineTooLong,
        MalformedInteger,
        MalformedLength,
        MalformedDouble,
        MalformedBoolean,
        BulkTooLarge,
        TooManyElements,
        NestingTooDeep,
        MissingTerminator,
    };

    /// Content of the next CRLF-terminated line, advancing past the ending.
    fn line(self: *Scanner) Error![]const u8 {
        const rest = self.bytes[self.at..];
        const end = std.mem.indexOf(u8, rest, "\r\n") orelse {
            // A line longer than the limit will never become valid, so it is a
            // failure rather than a request for more bytes.
            if (rest.len > self.limits.max_line) return error.LineTooLong;
            return error.Incomplete;
        };
        if (end > self.limits.max_line) return error.LineTooLong;
        self.at += end + 2;
        return rest[0..end];
    }

    fn integer(self: *Scanner) Error!i64 {
        const text = try self.line();
        return std.fmt.parseInt(i64, text, 10) catch error.MalformedInteger;
    }

    /// Consumes `len` bytes of payload plus the CRLF that must follow them.
    fn payload(self: *Scanner, len: usize) Error!void {
        if (self.bytes.len - self.at < len + 2) return error.Incomplete;
        const terminator = self.bytes[self.at + len ..][0..2];
        // The length said where the payload ends; if a CRLF is not there, the
        // stream and this parser disagree about framing and there is no way back.
        if (!std.mem.eql(u8, terminator, "\r\n")) return error.MissingTerminator;
        self.at += len + 2;
    }

    fn count(self: *Scanner) Error!?usize {
        const raw = try self.integer();
        if (raw < 0) {
            // Only -1 is the null form; other negatives are malformed.
            if (raw != -1) return error.MalformedLength;
            return null;
        }
        const wanted: usize = @intCast(raw);
        if (wanted > self.limits.max_elements) return error.TooManyElements;
        return wanted;
    }

    fn bulkLength(self: *Scanner) Error!?usize {
        const raw = try self.integer();
        if (raw < 0) {
            if (raw != -1) return error.MalformedLength;
            return null;
        }
        const wanted: usize = @intCast(raw);
        if (wanted > self.limits.max_bulk) return error.BulkTooLarge;
        return wanted;
    }

    fn value(self: *Scanner, depth: usize) Error!void {
        if (depth > self.limits.max_depth) return error.NestingTooDeep;
        if (self.at >= self.bytes.len) return error.Incomplete;

        const marker = Marker.parse(self.bytes[self.at]) orelse return error.UnknownMarker;
        self.at += 1;

        switch (marker) {
            .simple, .err, .big_number => _ = try self.line(),
            .integer => _ = try self.integer(),
            .null => {
                const rest = try self.line();
                if (rest.len != 0) return error.MissingTerminator;
            },
            .boolean => {
                const text = try self.line();
                if (text.len != 1 or (text[0] != 't' and text[0] != 'f')) {
                    return error.MalformedBoolean;
                }
            },
            .double => {
                const text = try self.line();
                _ = parseDouble(text) catch return error.MalformedDouble;
            },
            .bulk, .blob_error, .verbatim => {
                const len = try self.bulkLength();
                if (len) |actual| try self.payload(actual);
            },
            .array, .set, .push => {
                const len = try self.count();
                if (len) |actual| {
                    for (0..actual) |_| try self.value(depth + 1);
                }
            },
            .map => {
                const pairs = try self.count() orelse return error.MalformedLength;
                if (pairs > self.limits.max_elements / 2) return error.TooManyElements;
                for (0..pairs * 2) |_| try self.value(depth + 1);
            },
        }
    }
};

/// RESP writes `inf`, `-inf` and `nan` in a form `parseFloat` does not accept.
fn parseDouble(text: []const u8) !f64 {
    if (std.mem.eql(u8, text, "inf")) return std.math.inf(f64);
    if (std.mem.eql(u8, text, "-inf")) return -std.math.inf(f64);
    if (std.mem.eql(u8, text, "nan")) return std.math.nan(f64);
    return std.fmt.parseFloat(f64, text);
}

/// Builds a value that `Scanner` has already proved complete and within limits.
///
/// Only allocation can fail here, which is what makes the two-pass split worth
/// having: none of the protocol checks are repeated, so they cannot disagree
/// between the passes.
const Parser = struct {
    bytes: []const u8,
    at: usize = 0,
    arena: Allocator,

    fn line(self: *Parser) []const u8 {
        const rest = self.bytes[self.at..];
        const end = std.mem.indexOf(u8, rest, "\r\n").?;
        self.at += end + 2;
        return rest[0..end];
    }

    fn value(self: *Parser) Allocator.Error!Value {
        const marker = Marker.parse(self.bytes[self.at]).?;
        self.at += 1;

        switch (marker) {
            .simple => return .{ .simple = try self.arena.dupe(u8, self.line()) },
            .err => return .{ .err = try self.arena.dupe(u8, self.line()) },
            .big_number => return .{ .big_number = try self.arena.dupe(u8, self.line()) },
            .integer => return .{ .integer = std.fmt.parseInt(i64, self.line(), 10) catch unreachable },
            .null => {
                _ = self.line();
                return .null;
            },
            .boolean => return .{ .boolean = self.line()[0] == 't' },
            .double => return .{ .double = parseDouble(self.line()) catch unreachable },
            .bulk, .blob_error, .verbatim => {
                const raw = std.fmt.parseInt(i64, self.line(), 10) catch unreachable;
                if (raw < 0) return switch (marker) {
                    .bulk => .{ .bulk = null },
                    // Only bulk strings have a null form; the scanner rejected
                    // the others, so this cannot be reached.
                    else => unreachable,
                };
                const len: usize = @intCast(raw);
                const payload = try self.arena.dupe(u8, self.bytes[self.at..][0..len]);
                self.at += len + 2;
                return switch (marker) {
                    .bulk => .{ .bulk = payload },
                    .blob_error => .{ .blob_error = payload },
                    .verbatim => .{ .verbatim = payload },
                    else => unreachable,
                };
            },
            .array, .set, .push => {
                const raw = std.fmt.parseInt(i64, self.line(), 10) catch unreachable;
                if (raw < 0) return switch (marker) {
                    .array => .{ .array = null },
                    else => unreachable,
                };
                const items = try self.elements(@intCast(raw));
                return switch (marker) {
                    .array => .{ .array = items },
                    .set => .{ .set = items },
                    .push => .{ .push = items },
                    else => unreachable,
                };
            },
            .map => {
                const pairs = std.fmt.parseInt(usize, self.line(), 10) catch unreachable;
                return .{ .map = try self.elements(pairs * 2) };
            },
        }
    }

    fn elements(self: *Parser, len: usize) Allocator.Error![]const Value {
        const items = try self.arena.alloc(Value, len);
        for (items) |*slot| slot.* = try self.value();
        return items;
    }
};

/// Turns a stream of RESP bytes into `Incoming` messages.
pub const Decoder = struct {
    decoder: ByteToMessageDecoder(Decoder),
    limits: Limits,
    /// Set once a protocol failure has been reported.
    ///
    /// RESP is framed by lengths and line endings, so a bad marker or a bad
    /// length leaves no way to find where the next value starts. Continuing to
    /// parse would be guesswork, and leaving the bytes accumulated would let a
    /// peer replay one bad byte into an error per read. Same discipline as the
    /// HTTP decoders.
    failed: bool = false,

    pub const handler_name = "redis-decoder";

    pub const Options = struct {
        limits: Limits = .{},
    };

    pub fn init(options: Options) Decoder {
        return .{
            .decoder = .{
                .options = .{
                    // One whole value must fit while it accumulates. The bulk
                    // limit dominates, plus room for the markers around it.
                    .max_cumulation = @max(options.limits.max_bulk, options.limits.max_line) + 32,
                },
            },
            .limits = options.limits,
        };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*Decoder {
        const decoder = try pipeline.gpa.create(Decoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *Decoder, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn onRead(self: *Decoder, ctx: *HandlerContext, msg: Message) CodecError!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *Decoder, ctx: *HandlerContext) CodecError!void {
        return self.decoder.onInactive(self, ctx);
    }

    pub fn onRemoved(self: *Decoder, ctx: *HandlerContext) void {
        self.decoder.onRemoved(ctx);
    }

    pub fn decode(
        self: *Decoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        if (self.failed) {
            cumulation.clear();
            return null;
        }

        const readable = cumulation.readableSlice();
        if (readable.len == 0) return null;

        var scanner: Scanner = .{ .bytes = readable, .limits = self.limits };
        scanner.value(0) catch |err| switch (err) {
            error.Incomplete => return null,
            else => {
                self.failed = true;
                cumulation.clear();
                return err;
            },
        };
        const total = scanner.at;
        assert(total > 0);

        var incoming: Incoming = .init(ctx.gpa());
        errdefer incoming.deinit(ctx.gpa());

        var parser: Parser = .{ .bytes = readable[0..total], .arena = incoming.allocator() };
        incoming.value = try parser.value();
        assert(parser.at == total); // The passes must agree on the length.

        cumulation.skip(total) catch unreachable;
        return try Message.initAny(ctx.gpa(), Incoming, incoming);
    }
};

/// Serializes `Command` and `Value` messages into bytes.
///
/// Both, so that the same handler serves a client sending commands and a server
/// sending replies.
pub const Encoder = struct {
    options: Options = .{},

    pub const handler_name = "redis-encoder";

    pub const Options = struct {
        /// Bytes reserved before growing.
        initial_capacity: usize = 256,
        /// Deepest value this encoder will write, mirroring the decoder's bound
        /// so a cycle in a caller-built tree cannot recurse forever.
        max_depth: usize = 32,
    };

    pub fn init(options: Options) Encoder {
        return .{ .options = options };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*Encoder {
        const encoder = try pipeline.gpa.create(Encoder);
        encoder.* = .init(options);
        errdefer pipeline.gpa.destroy(encoder);
        _ = try pipeline.addLast(handler_name, .initOwned(encoder));
        return encoder;
    }

    pub fn onWrite(self: *Encoder, ctx: *HandlerContext, msg: Message) CodecError!void {
        var owned = msg;
        if (owned.get(Command)) |command| {
            defer owned.deinit(ctx.gpa());
            return self.writeCommand(ctx, command);
        }
        if (owned.get(Value)) |value| {
            defer owned.deinit(ctx.gpa());
            return self.writeValue(ctx, value);
        }
        return ctx.write(owned.move());
    }

    fn writeCommand(
        self: *Encoder,
        ctx: *HandlerContext,
        command: *const Command,
    ) CodecError!void {
        if (command.args.len == 0) return error.EmptyCommand;

        const gpa = ctx.gpa();
        var out = try Buffer.init(gpa, .{ .capacity = self.options.initial_capacity });
        errdefer out.deinit(gpa);

        var scratch: [64]u8 = undefined;
        var adapter = out.writerAdapter(gpa, &scratch);
        const writer = &adapter.interface;

        try writer.print("*{d}\r\n", .{command.args.len});
        for (command.args) |arg| {
            try writer.print("${d}\r\n", .{arg.len});
            try writer.writeAll(arg);
            try writer.writeAll("\r\n");
        }
        try writer.flush();
        if (adapter.err) |err| return err;

        return ctx.write(.initBuffer(&out));
    }

    fn writeValue(self: *Encoder, ctx: *HandlerContext, value: *const Value) CodecError!void {
        const gpa = ctx.gpa();
        var out = try Buffer.init(gpa, .{ .capacity = self.options.initial_capacity });
        errdefer out.deinit(gpa);

        var scratch: [64]u8 = undefined;
        var adapter = out.writerAdapter(gpa, &scratch);
        const writer = &adapter.interface;

        try encodeInto(writer, value.*, 0, self.options.max_depth);
        try writer.flush();
        if (adapter.err) |err| return err;

        return ctx.write(.initBuffer(&out));
    }
};

/// Writes one value, recursing into aggregates.
pub fn encodeInto(
    writer: *std.Io.Writer,
    value: Value,
    depth: usize,
    max_depth: usize,
) CodecError!void {
    if (depth > max_depth) return error.NestingTooDeep;

    switch (value) {
        .simple => |text| try writer.print("+{s}\r\n", .{text}),
        .err => |text| try writer.print("-{s}\r\n", .{text}),
        .integer => |number| try writer.print(":{d}\r\n", .{number}),
        .big_number => |text| try writer.print("({s}\r\n", .{text}),
        .null => try writer.writeAll("_\r\n"),
        .boolean => |flag| try writer.print("#{s}\r\n", .{if (flag) "t" else "f"}),
        .double => |number| try writeDouble(writer, number),
        .bulk => |maybe| {
            const payload = maybe orelse {
                try writer.writeAll("$-1\r\n");
                return;
            };
            try writer.print("${d}\r\n", .{payload.len});
            try writer.writeAll(payload);
            try writer.writeAll("\r\n");
        },
        .blob_error => |payload| {
            try writer.print("!{d}\r\n", .{payload.len});
            try writer.writeAll(payload);
            try writer.writeAll("\r\n");
        },
        .verbatim => |payload| {
            try writer.print("={d}\r\n", .{payload.len});
            try writer.writeAll(payload);
            try writer.writeAll("\r\n");
        },
        .array => |maybe| {
            const items = maybe orelse {
                try writer.writeAll("*-1\r\n");
                return;
            };
            try writer.print("*{d}\r\n", .{items.len});
            for (items) |item| try encodeInto(writer, item, depth + 1, max_depth);
        },
        .set => |items| {
            try writer.print("~{d}\r\n", .{items.len});
            for (items) |item| try encodeInto(writer, item, depth + 1, max_depth);
        },
        .push => |items| {
            try writer.print(">{d}\r\n", .{items.len});
            for (items) |item| try encodeInto(writer, item, depth + 1, max_depth);
        },
        .map => |items| {
            // Flattened on the wire as well, so the count is pairs.
            if (items.len % 2 != 0) return error.MalformedMap;
            try writer.print("%{d}\r\n", .{items.len / 2});
            for (items) |item| try encodeInto(writer, item, depth + 1, max_depth);
        },
    }
}

/// RESP spells the non-finite doubles as bare words.
fn writeDouble(writer: *std.Io.Writer, number: f64) CodecError!void {
    if (std.math.isNan(number)) return writer.writeAll(",nan\r\n");
    if (std.math.isPositiveInf(number)) return writer.writeAll(",inf\r\n");
    if (std.math.isNegativeInf(number)) return writer.writeAll(",-inf\r\n");
    return writer.print(",{d}\r\n", .{number});
}

/// Installs the RESP codec: decoder then encoder.
pub fn addCodec(pipeline: *Pipeline, options: struct {
    decoder: Decoder.Options = .{},
    encoder: Encoder.Options = .{},
}) !void {
    _ = try Decoder.addTo(pipeline, options.decoder);
    _ = try Encoder.addTo(pipeline, options.encoder);
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const test_support = @import("test_support.zig");

/// Collects decoded values so tests can assert on them.
const Collector = struct {
    gpa: Allocator,
    items: std.ArrayList(Incoming) = .empty,
    errors: std.ArrayList(anyerror) = .empty,

    pub const handler_name = "redis-collector";

    pub fn onRead(self: *Collector, ctx: *HandlerContext, msg: Message) CodecError!void {
        var owned = msg;
        if (owned.take(ctx.gpa(), Incoming)) |incoming| {
            try self.items.append(self.gpa, incoming);
            return;
        }
        owned.deinit(ctx.gpa());
    }

    pub fn onError(self: *Collector, _: *HandlerContext, err: anyerror) void {
        self.errors.append(self.gpa, err) catch {};
    }

    pub fn deinit(self: *Collector, gpa: Allocator) void {
        for (self.items.items) |*item| item.deinit(gpa);
        self.items.deinit(gpa);
        self.errors.deinit(gpa);
    }
};

const Fixture = struct {
    fixture: test_support.Fixture,
    collected: *Collector,

    fn init(gpa: Allocator, options: Decoder.Options) !Fixture {
        var fixture = try test_support.Fixture.init(gpa);
        errdefer fixture.deinit();

        try addCodec(fixture.pipeline, .{ .decoder = options });

        const collected = try gpa.create(Collector);
        collected.* = .{ .gpa = gpa };
        errdefer gpa.destroy(collected);
        _ = try fixture.pipeline.addLast(Collector.handler_name, .init(collected));

        return .{ .fixture = fixture, .collected = collected };
    }

    fn deinit(self: *Fixture) void {
        const gpa = self.fixture.gpa;
        self.fixture.deinit();
        self.collected.deinit(gpa);
        gpa.destroy(self.collected);
    }

    fn feed(self: *Fixture, bytes: []const u8) !void {
        self.fixture.pipeline.fireRead(try Message.initBytes(self.fixture.gpa, bytes));
    }

    fn values(self: *const Fixture) []const Incoming {
        return self.collected.items.items;
    }

    fn errors(self: *const Fixture) []const anyerror {
        return self.collected.errors.items;
    }
};

test "Decoder: the RESP2 scalar types" {
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    try rig.feed("+OK\r\n-ERR bad\r\n:42\r\n:-7\r\n$5\r\nhello\r\n$0\r\n\r\n$-1\r\n");

    try testing.expectEqual(@as(usize, 0), rig.errors().len);
    try testing.expectEqual(@as(usize, 7), rig.values().len);
    try testing.expectEqualStrings("OK", rig.values()[0].value.simple);
    try testing.expectEqualStrings("ERR bad", rig.values()[1].value.err);
    try testing.expect(rig.values()[1].value.isError());
    try testing.expectEqual(@as(i64, 42), rig.values()[2].value.integer);
    try testing.expectEqual(@as(i64, -7), rig.values()[3].value.integer);
    try testing.expectEqualStrings("hello", rig.values()[4].value.bulk.?);
    // An empty bulk string and a null one are different values.
    try testing.expectEqualStrings("", rig.values()[5].value.bulk.?);
    try testing.expect(rig.values()[6].value.bulk == null);
}

test "Decoder: a bulk string may contain CRLF and NUL" {
    // The length prefix is authoritative, so the payload is opaque bytes.
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    try rig.feed("$7\r\na\r\nb\x00c!\r\n");

    try testing.expectEqual(@as(usize, 1), rig.values().len);
    try testing.expectEqualStrings("a\r\nb\x00c!", rig.values()[0].value.bulk.?);
}

test "Decoder: nested arrays" {
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    try rig.feed("*3\r\n:1\r\n*2\r\n+a\r\n$1\r\nb\r\n*-1\r\n");

    try testing.expectEqual(@as(usize, 1), rig.values().len);
    const outer = rig.values()[0].value.array.?;
    try testing.expectEqual(@as(usize, 3), outer.len);
    try testing.expectEqual(@as(i64, 1), outer[0].integer);
    const inner = outer[1].array.?;
    try testing.expectEqualStrings("a", inner[0].simple);
    try testing.expectEqualStrings("b", inner[1].bulk.?);
    try testing.expect(outer[2].array == null);
}

test "Decoder: the RESP3 types" {
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    try rig.feed("_\r\n#t\r\n#f\r\n,3.5\r\n,inf\r\n,-inf\r\n(12345678901234567890\r\n" ++
        "!5\r\nboom!\r\n=7\r\ntxt:abc\r\n%1\r\n+k\r\n:9\r\n~2\r\n+a\r\n+b\r\n>2\r\n+msg\r\n+x\r\n");

    try testing.expectEqual(@as(usize, 0), rig.errors().len);
    const items = rig.values();
    try testing.expectEqual(@as(usize, 12), items.len);
    try testing.expect(items[0].value == .null);
    try testing.expectEqual(true, items[1].value.boolean);
    try testing.expectEqual(false, items[2].value.boolean);
    try testing.expectEqual(@as(f64, 3.5), items[3].value.double);
    try testing.expect(std.math.isPositiveInf(items[4].value.double));
    try testing.expect(std.math.isNegativeInf(items[5].value.double));
    try testing.expectEqualStrings("12345678901234567890", items[6].value.big_number);
    try testing.expectEqualStrings("boom!", items[7].value.blob_error);
    try testing.expect(items[7].value.isError());
    try testing.expectEqualStrings("txt:abc", items[8].value.verbatim);
    // A map arrives flattened: key, value.
    try testing.expectEqual(@as(usize, 2), items[9].value.map.len);
    try testing.expectEqualStrings("k", items[9].value.map[0].simple);
    try testing.expectEqual(@as(i64, 9), items[9].value.map[1].integer);
    try testing.expectEqual(@as(usize, 2), items[10].value.set.len);
    try testing.expectEqual(@as(usize, 2), items[11].value.push.len);
}

test "Decoder: an incomplete value consumes nothing and waits" {
    // The contract the two-pass design exists to satisfy.
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    const partials = [_][]const u8{ "*2\r\n", "$5\r\nhel", "lo\r\n", "+wor" };
    for (partials) |part| {
        try rig.feed(part);
        try testing.expectEqual(@as(usize, 0), rig.values().len);
        try testing.expectEqual(@as(usize, 0), rig.errors().len);
    }
    try rig.feed("ld\r\n");

    try testing.expectEqual(@as(usize, 1), rig.values().len);
    const items = rig.values()[0].value.array.?;
    try testing.expectEqualStrings("hello", items[0].bulk.?);
    try testing.expectEqualStrings("world", items[1].simple);
}

test "Decoder: byte-at-a-time delivery gives the same result" {
    const stream = "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nvalue\r\n:7\r\n%1\r\n+a\r\n#f\r\n";

    var whole = try Fixture.init(testing.allocator, .{});
    defer whole.deinit();
    try whole.feed(stream);

    var split = try Fixture.init(testing.allocator, .{});
    defer split.deinit();
    for (stream) |byte| try split.feed(&.{byte});

    try testing.expectEqual(whole.values().len, split.values().len);
    try testing.expectEqual(@as(usize, 3), whole.values().len);
    try testing.expectEqualStrings(
        "SET",
        split.values()[0].value.array.?[0].bulk.?,
    );
    try testing.expectEqual(@as(i64, 7), split.values()[1].value.integer);
    try testing.expectEqual(false, split.values()[2].value.map[1].boolean);
}

test "Decoder: a malformed value is reported once, not once per read" {
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    // `?` is not a type marker, and RESP gives no way to resynchronize.
    try rig.feed("?nonsense\r\n");
    try testing.expectEqual(@as(usize, 1), rig.errors().len);
    try testing.expectEqual(@as(anyerror, error.UnknownMarker), rig.errors()[0]);

    for (0..5) |_| try rig.feed("+more\r\n");
    try testing.expectEqual(@as(usize, 1), rig.errors().len);
    try testing.expectEqual(@as(usize, 0), rig.values().len);
}

test "Decoder: rejects the malformed shapes" {
    const Case = struct { input: []const u8, expected: anyerror };
    const cases = [_]Case{
        .{ .input = ":notanumber\r\n", .expected = error.MalformedInteger },
        .{ .input = "$abc\r\n", .expected = error.MalformedInteger },
        // A negative length other than -1 has no meaning.
        .{ .input = "$-2\r\n", .expected = error.MalformedLength },
        .{ .input = "*-3\r\n", .expected = error.MalformedLength },
        // The length said the payload ends here; nothing else may.
        .{ .input = "$2\r\nabc\r\n", .expected = error.MissingTerminator },
        .{ .input = "#maybe\r\n", .expected = error.MalformedBoolean },
        .{ .input = ",notafloat\r\n", .expected = error.MalformedDouble },
        // A map must have a length; there is no null map.
        .{ .input = "%-1\r\n", .expected = error.MalformedLength },
    };

    for (cases) |case| {
        var rig = try Fixture.init(testing.allocator, .{});
        defer rig.deinit();
        try rig.feed(case.input);

        try testing.expectEqual(@as(usize, 0), rig.values().len);
        try testing.expectEqual(@as(usize, 1), rig.errors().len);
        try testing.expectEqual(case.expected, rig.errors()[0]);
    }
}

test "Decoder: a nesting bomb is refused rather than recursed into" {
    // Sixty bytes of `*1` would otherwise be sixty stack frames, and a peer can
    // send far more than sixty.
    var rig = try Fixture.init(testing.allocator, .{ .limits = .{ .max_depth = 4 } });
    defer rig.deinit();

    var bomb: std.ArrayList(u8) = .empty;
    defer bomb.deinit(testing.allocator);
    for (0..64) |_| try bomb.appendSlice(testing.allocator, "*1\r\n");
    try bomb.appendSlice(testing.allocator, "+deep\r\n");

    try rig.feed(bomb.items);

    try testing.expectEqual(@as(usize, 0), rig.values().len);
    try testing.expectEqual(@as(usize, 1), rig.errors().len);
    try testing.expectEqual(@as(anyerror, error.NestingTooDeep), rig.errors()[0]);
}

test "Decoder: the size limits are enforced" {
    {
        var rig = try Fixture.init(testing.allocator, .{ .limits = .{ .max_bulk = 4 } });
        defer rig.deinit();
        try rig.feed("$10\r\n");
        try testing.expectEqual(@as(anyerror, error.BulkTooLarge), rig.errors()[0]);
    }
    {
        var rig = try Fixture.init(testing.allocator, .{ .limits = .{ .max_elements = 3 } });
        defer rig.deinit();
        try rig.feed("*9\r\n");
        try testing.expectEqual(@as(anyerror, error.TooManyElements), rig.errors()[0]);
    }
    {
        // An over-long line is a failure before it is even complete, so a peer
        // cannot hold memory by never sending the ending.
        var rig = try Fixture.init(testing.allocator, .{ .limits = .{ .max_line = 8 } });
        defer rig.deinit();
        try rig.feed("+aaaaaaaaaaaaaaaaaaaa");
        try testing.expectEqual(@as(anyerror, error.LineTooLong), rig.errors()[0]);
    }
}

test "Encoder: writes a command as an array of bulk strings" {
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    try rig.fixture.pipeline.write(try Message.initAny(
        testing.allocator,
        Command,
        .{ .args = &.{ "SET", "key", "a\r\nb" } },
    ));

    try testing.expectEqualStrings(
        "*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$4\r\na\r\nb\r\n",
        rig.fixture.written(),
    );
}

test "Encoder: an empty command is refused" {
    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();

    try testing.expectError(error.EmptyCommand, rig.fixture.pipeline.write(
        try Message.initAny(testing.allocator, Command, .{ .args = &.{} }),
    ));
    try testing.expectEqualStrings("", rig.fixture.written());
}

test "Encoder: every value type round trips through the decoder" {
    const gpa = testing.allocator;
    const nested = [_]Value{ .{ .integer = 1 }, .{ .bulk = "two" } };
    const pairs = [_]Value{ .{ .simple = "k" }, .{ .boolean = true } };
    const cases = [_]Value{
        .{ .simple = "OK" },
        .{ .err = "ERR nope" },
        .{ .integer = -12345 },
        .{ .bulk = "payload" },
        .{ .bulk = "" },
        .{ .bulk = null },
        .{ .array = &nested },
        .{ .array = null },
        .null,
        .{ .boolean = false },
        .{ .double = 2.5 },
        .{ .double = std.math.inf(f64) },
        .{ .big_number = "99999999999999999999" },
        .{ .blob_error = "boom" },
        .{ .verbatim = "txt:hi" },
        .{ .map = &pairs },
        .{ .set = &nested },
        .{ .push = &nested },
    };

    for (cases) |value| {
        var encode = try Fixture.init(gpa, .{});
        defer encode.deinit();
        try encode.fixture.pipeline.write(try Message.initAny(gpa, Value, value));

        var decode = try Fixture.init(gpa, .{});
        defer decode.deinit();
        try decode.feed(encode.fixture.written());

        try testing.expectEqual(@as(usize, 0), decode.errors().len);
        try testing.expectEqual(@as(usize, 1), decode.values().len);
        try expectValueEqual(value, decode.values()[0].value);
    }
}

fn expectValueEqual(expected: Value, actual: Value) anyerror!void {
    try testing.expectEqual(std.meta.activeTag(expected), std.meta.activeTag(actual));
    switch (expected) {
        .simple, .err, .big_number, .blob_error, .verbatim => {
            try testing.expectEqualStrings(expected.text() orelse
                expected.errorText().?, actual.text() orelse actual.errorText().?);
        },
        .integer => |number| try testing.expectEqual(number, actual.integer),
        .boolean => |flag| try testing.expectEqual(flag, actual.boolean),
        .null => {},
        .double => |number| {
            if (std.math.isInf(number)) {
                try testing.expect(std.math.isInf(actual.double));
            } else {
                try testing.expectEqual(number, actual.double);
            }
        },
        .bulk => |maybe| {
            if (maybe) |payload| {
                try testing.expectEqualStrings(payload, actual.bulk.?);
            } else {
                try testing.expect(actual.bulk == null);
            }
        },
        .array => |maybe| {
            if (maybe) |items| {
                try expectElementsEqual(items, actual.array.?);
            } else {
                try testing.expect(actual.array == null);
            }
        },
        .map => |items| try expectElementsEqual(items, actual.map),
        .set => |items| try expectElementsEqual(items, actual.set),
        .push => |items| try expectElementsEqual(items, actual.push),
    }
}

fn expectElementsEqual(expected: []const Value, actual: []const Value) anyerror!void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try expectValueEqual(want, got);
}

test "Encoder: a value nested past the limit is refused" {
    var deep: Value = .{ .integer = 0 };
    var level: usize = 0;
    // Built on the stack, so keep it shallow enough to be safe while still
    // exceeding a small configured bound.
    var storage: [8][1]Value = undefined;
    while (level < 8) : (level += 1) {
        storage[level] = .{deep};
        deep = .{ .array = &storage[level] };
    }

    var rig = try Fixture.init(testing.allocator, .{});
    defer rig.deinit();
    // Tighten the bound in place, which is simpler than a second fixture.
    const handler: *Encoder = @ptrCast(@alignCast(
        rig.fixture.pipeline.find(Encoder.handler_name).?.handler.context,
    ));
    handler.options.max_depth = 3;

    try testing.expectError(error.NestingTooDeep, rig.fixture.pipeline.write(
        try Message.initAny(testing.allocator, Value, deep),
    ));
}
