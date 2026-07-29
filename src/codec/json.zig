//! Framing a stream of JSON values, the counterpart of Netty's
//! `JsonObjectDecoder`.
//!
//! This finds boundaries; it does not parse. A framed value is delivered as
//! bytes for `std.json` to take apart, the same division of labour as the rest of
//! `codec/`: `Message` already hands out `[]const u8`, so a decoder that also
//! parsed would be choosing an allocation strategy on the application's behalf.
//!
//! One thing separates it from the framers in `frame.zig`, and it is worth being
//! explicit about because it inverts their central rule. A line or delimiter
//! decoder that meets an over-long frame reports it and then skips to the next
//! delimiter, resynchronizing the stream: the delimiter is unambiguous, so the
//! decoder knows where the next frame begins. **JSON has no such marker.** A `{`
//! may open a value or sit inside a string, and nothing in the grammar says "a
//! value starts here". So there is nowhere to resynchronize to, and every error
//! here is terminal: the decoder latches and keeps failing rather than pretending
//! it has found its footing again.

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

/// Splits a stream into whole JSON values.
///
/// By default a value is an object or an array, which is what a stream of JSON
/// looks like in practice and what the name says. With `stream_array_elements`
/// the top-level array is unwrapped instead and each of its elements is delivered
/// on its own, so a large response can be handled without holding all of it.
pub const JsonObjectDecoder = struct {
    decoder: ByteToMessageDecoder(JsonObjectDecoder),
    options: Options,

    /// How many leading readable bytes have already been examined.
    ///
    /// Without this, a value arriving in N reads would be rescanned from its
    /// first byte on each one, which is quadratic in the size of the value — and
    /// the size of a value is the peer's choice.
    scanned: usize = 0,
    /// Where the value being scanned begins, relative to the readable bytes.
    start: usize = 0,
    /// Nesting depth within the value being scanned.
    depth: usize = 0,
    state: State = .between,
    kind: Kind = .structure,
    in_string: bool = false,
    escaped: bool = false,
    /// Whether the top-level array has been entered, in `stream_array_elements`
    /// mode. Also how an unterminated array is noticed at end of stream.
    entered_array: bool = false,
    /// Set once the stream is known to be unusable, after which every later byte
    /// is discarded; see the module comment for why, and `http`'s `bad_message`
    /// for the same reasoning about HTTP/1 framing.
    bad_message: bool = false,

    pub const handler_name = "json-object-decoder";

    const State = enum { between, value };

    /// What the first byte of a value said it was. The three need different
    /// termination rules, which is the only reason the distinction exists.
    const Kind = enum {
        /// An object or an array: ends when nesting returns to zero.
        structure,
        /// A string: ends at its closing quote.
        string,
        /// A number, `true`, `false` or `null`: ends at whatever follows it, so
        /// only ever appears as an array element, where the enclosing array
        /// guarantees something follows.
        scalar,
    };

    pub const Options = struct {
        /// Longest value that will be delivered. Exceeding it is terminal.
        max_length: usize = 64 * 1024,
        /// Deliver each element of a top-level array rather than the array.
        stream_array_elements: bool = false,
    };

    pub fn init(options: Options) JsonObjectDecoder {
        assert(options.max_length > 0);
        return .{
            // One byte of slack over `max_length` so this decoder's own limit is
            // what reports an over-long value, with the mixin's residue ceiling
            // left as the backstop it is meant to be.
            .decoder = .{ .options = .{ .max_cumulation = options.max_length + 1 } },
            .options = options,
        };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*JsonObjectDecoder {
        const decoder = try pipeline.gpa.create(JsonObjectDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *JsonObjectDecoder, gpa: Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn onRead(self: *JsonObjectDecoder, ctx: *HandlerContext, msg: Message) Error!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *JsonObjectDecoder, ctx: *HandlerContext) Error!void {
        return self.decoder.onInactive(self, ctx);
    }

    pub fn onRemoved(self: *JsonObjectDecoder, ctx: *HandlerContext) void {
        self.decoder.onRemoved(ctx);
    }

    pub fn decode(
        self: *JsonObjectDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) Error!?Message {
        if (self.bad_message) {
            // Reported once, at the point of failure; everything after it is
            // dropped. Raising the error again on each later read would turn one
            // bad byte followed by a slow dribble into an error storm, and would
            // make the transcript depend on how the peer chunked its writes.
            cumulation.skip(cumulation.readableLen()) catch unreachable;
            self.scanned = 0;
            return null;
        }

        const readable = cumulation.readableSlice();
        var i = self.scanned;
        while (i < readable.len) : (i += 1) {
            const c = readable[i];

            if (self.state == .between) {
                if (isWhitespace(c)) continue;
                if (self.options.stream_array_elements and self.punctuation(c)) continue;
                self.kind = kindOf(c) orelse return self.fail(error.MalformedJson);
                // A bare scalar has no terminator of its own, so outside an array
                // there is nothing to say where it ends.
                if (self.kind == .scalar and !self.entered_array) {
                    return self.fail(error.MalformedJson);
                }
                self.state = .value;
                self.start = i;
                self.depth = 0;
                self.in_string = false;
                self.escaped = false;
                // Deliberately no `continue`: this byte opens the value and has
                // to be handled below as part of it.
            }

            switch (self.kind) {
                .structure => if (try self.consumeStructureByte(c)) {
                    return self.emit(ctx, cumulation, readable, i + 1);
                },
                .string => {
                    // `start` holds the opening quote, which closes nothing.
                    if (i != self.start and self.consumeStringByte(c)) {
                        return self.emit(ctx, cumulation, readable, i + 1);
                    }
                },
                // The terminator belongs to the enclosing array rather than to
                // the element, so it is left for the next trip round the loop.
                .scalar => if (isScalarEnd(c)) return self.emit(ctx, cumulation, readable, i),
            }

            if (i + 1 - self.start > self.options.max_length) {
                return self.fail(error.FrameTooLong);
            }
        }

        if (self.state == .between and i > 0) {
            // Leading whitespace and array punctuation are only consumed when a
            // value completes, so a peer sending nothing but spaces would grow
            // the accumulation without bound. Drop what has been examined.
            assert(i == readable.len);
            cumulation.skip(i) catch unreachable;
            self.scanned = 0;
            return null;
        }

        self.scanned = i;
        return null;
    }

    /// Reports an unterminated top-level array, which `decode` cannot: it has
    /// consumed every byte, so the mixin sees no residue to complain about.
    pub fn decodeLast(
        self: *JsonObjectDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) Error!?Message {
        if (try self.decode(ctx, cumulation)) |msg| return msg;
        // A stream already reported as bad says nothing more about truncation.
        if (self.bad_message) return null;
        if (self.entered_array) return error.IncompleteMessage;
        return null;
    }

    /// Handles one byte of an object or array. Returns true when nesting has
    /// returned to zero, i.e. the value ends at this byte.
    fn consumeStructureByte(self: *JsonObjectDecoder, c: u8) Error!bool {
        if (self.in_string) {
            if (self.escaped) {
                self.escaped = false;
                return false;
            }
            switch (c) {
                '\\' => self.escaped = true,
                '"' => self.in_string = false,
                else => {},
            }
            return false;
        }
        switch (c) {
            '"' => self.in_string = true,
            '{', '[' => self.depth += 1,
            '}', ']' => {
                // A close with nothing open cannot be resynchronized from.
                if (self.depth == 0) {
                    self.bad_message = true;
                    return error.MalformedJson;
                }
                self.depth -= 1;
                if (self.depth == 0) return true;
            },
            else => {},
        }
        return false;
    }

    /// Handles one byte of a string value. Returns true at its closing quote.
    fn consumeStringByte(self: *JsonObjectDecoder, c: u8) bool {
        if (self.escaped) {
            self.escaped = false;
            return false;
        }
        switch (c) {
            '\\' => self.escaped = true,
            '"' => return true,
            else => {},
        }
        return false;
    }

    /// Consumes the brackets and commas that hold a streamed array together.
    /// Returns whether `c` was one of them.
    fn punctuation(self: *JsonObjectDecoder, c: u8) bool {
        if (!self.entered_array) {
            if (c != '[') return false;
            self.entered_array = true;
            return true;
        }
        if (c == ',') return true;
        if (c == ']') {
            self.entered_array = false;
            return true;
        }
        return false;
    }

    fn emit(
        self: *JsonObjectDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
        readable: []const u8,
        end: usize,
    ) Error!?Message {
        assert(end > self.start);
        const value = try Message.initBytes(ctx.gpa(), readable[self.start..end]);
        // Everything before `start` was whitespace or array punctuation, so it
        // goes with the value rather than being left to be rescanned.
        cumulation.skip(end) catch unreachable;
        self.state = .between;
        self.scanned = 0;
        self.start = 0;
        self.depth = 0;
        self.in_string = false;
        self.escaped = false;
        return value;
    }

    fn fail(self: *JsonObjectDecoder, err: anyerror) Error!?Message {
        self.bad_message = true;
        return err;
    }

    fn kindOf(c: u8) ?Kind {
        return switch (c) {
            '{', '[' => .structure,
            '"' => .string,
            '-', '0'...'9', 't', 'f', 'n' => .scalar,
            else => null,
        };
    }

    fn isWhitespace(c: u8) bool {
        return c == ' ' or c == '\t' or c == '\n' or c == '\r';
    }

    fn isScalarEnd(c: u8) bool {
        return isWhitespace(c) or c == ',' or c == ']' or c == '}';
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const test_support = @import("test_support.zig");

fn addDefault(pipeline: *Pipeline) anyerror!void {
    _ = try JsonObjectDecoder.addTo(pipeline, .{ .max_length = 256 });
}

fn addStreaming(pipeline: *Pipeline) anyerror!void {
    _ = try JsonObjectDecoder.addTo(pipeline, .{
        .max_length = 256,
        .stream_array_elements = true,
    });
}

test "JsonObjectDecoder: one object" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "{\"a\":1}"));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("{\"a\":1}", collector.messages.items[0]);
}

test "JsonObjectDecoder: values back to back, with whitespace between" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    // Newline-delimited JSON is the common shape, but nothing here depends on
    // the newline: the values are self-delimiting.
    fixture.pipeline.fireRead(try Message.initBytes(
        testing.allocator,
        "{\"a\":1}\n  {\"b\":2}{\"c\":3}\r\n",
    ));

    try testing.expectEqual(@as(usize, 3), collector.messages.items.len);
    try testing.expectEqualStrings("{\"a\":1}", collector.messages.items[0]);
    try testing.expectEqualStrings("{\"b\":2}", collector.messages.items[1]);
    try testing.expectEqualStrings("{\"c\":3}", collector.messages.items[2]);
    try testing.expectEqual(@as(usize, 0), collector.errors.items.len);
}

test "JsonObjectDecoder: nesting is tracked, and a top-level array is one value" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    const nested = "{\"a\":{\"b\":[1,{\"c\":[]}]}}";
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, nested ++ "[1,2,3]"));

    try testing.expectEqual(@as(usize, 2), collector.messages.items.len);
    try testing.expectEqualStrings(nested, collector.messages.items[0]);
    try testing.expectEqualStrings("[1,2,3]", collector.messages.items[1]);
}

test "JsonObjectDecoder: braces inside strings do not count" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    // Every structural character appears inside the string, plus an escaped
    // quote and a backslash immediately before the closing quote — the case
    // where a naive escape check ends the string one byte early.
    const tricky = "{\"s\":\"}{][ \\\" \\\\\"}";
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, tricky));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings(tricky, collector.messages.items[0]);
}

test "JsonObjectDecoder: one byte at a time gives the same frames" {
    const gpa = testing.allocator;
    const input = "{\"a\":\"}{\"}  [1,[2]]\n{\"b\":2}";

    var whole = try test_support.Fixture.init(gpa);
    defer whole.deinit();
    try whole.addCodec(addDefault);
    const whole_collector = try whole.addCollector();
    whole.pipeline.fireRead(try Message.initBytes(gpa, input));

    var split = try test_support.Fixture.init(gpa);
    defer split.deinit();
    try split.addCodec(addDefault);
    const split_collector = try split.addCollector();
    for (input) |byte| {
        split.pipeline.fireRead(try Message.initBytes(gpa, &[_]u8{byte}));
    }

    try testing.expectEqual(@as(usize, 3), whole_collector.messages.items.len);
    try testing.expectEqual(whole_collector.messages.items.len, split_collector.messages.items.len);
    for (whole_collector.messages.items, split_collector.messages.items) |a, b| {
        try testing.expectEqualStrings(a, b);
    }
}

test "JsonObjectDecoder: streaming a top-level array delivers its elements" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addStreaming);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(
        testing.allocator,
        "[ {\"a\":1} , {\"b\":[2]} ]",
    ));

    try testing.expectEqual(@as(usize, 2), collector.messages.items.len);
    try testing.expectEqualStrings("{\"a\":1}", collector.messages.items[0]);
    try testing.expectEqualStrings("{\"b\":[2]}", collector.messages.items[1]);
    try testing.expectEqual(@as(usize, 0), collector.errors.items.len);
}

test "JsonObjectDecoder: streamed elements may be scalars or strings" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addStreaming);
    const collector = try fixture.addCollector();

    // A scalar has no terminator of its own; what ends it belongs to the array,
    // so it must be left behind rather than swallowed.
    fixture.pipeline.fireRead(try Message.initBytes(
        testing.allocator,
        "[1,-2.5e3,true,null,\"x,y\",[7]]",
    ));

    const expected = [_][]const u8{ "1", "-2.5e3", "true", "null", "\"x,y\"", "[7]" };
    try testing.expectEqual(expected.len, collector.messages.items.len);
    for (expected, collector.messages.items) |want, got| {
        try testing.expectEqualStrings(want, got);
    }
}

test "JsonObjectDecoder: a bare scalar outside an array has no end" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "42"));

    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.MalformedJson), collector.errors.items[0]);
}

test "JsonObjectDecoder: a close with nothing open is terminal" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    // The valid object behind the damage must not be delivered: there is no
    // marker in JSON that says where a value begins, so claiming to have
    // resynchronized would be a guess.
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "{\"a\":1}}{\"b\":2}"));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("{\"a\":1}", collector.messages.items[0]);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.MalformedJson), collector.errors.items[0]);

    // Latched, and reported once: later bytes are dropped rather than decoded,
    // and do not raise the error again.
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "{\"c\":3}"));
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
}

test "JsonObjectDecoder: an over-long value is terminal, not skipped" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    const build = struct {
        fn add(pipeline: *Pipeline) anyerror!void {
            _ = try JsonObjectDecoder.addTo(pipeline, .{ .max_length = 8 });
        }
    }.add;
    try fixture.addCodec(build);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "{\"aaaaaaaaaa\":1}"));

    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.FrameTooLong), collector.errors.items[0]);
}

test "JsonObjectDecoder: trailing whitespace is not an incomplete message" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "{\"a\":1}\n \t"));
    fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 0), collector.errors.items.len);
}

test "JsonObjectDecoder: a half-received value at end of stream is reported" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addDefault);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "{\"a\":1}{\"b\":"));
    fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.IncompleteMessage), collector.errors.items[0]);
}

test "JsonObjectDecoder: an unterminated streamed array is reported" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    try fixture.addCodec(addStreaming);
    const collector = try fixture.addCollector();

    // Every byte has been consumed, so the accumulation is empty and the mixin
    // has nothing to complain about; only the decoder knows the array is open.
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "[{\"a\":1},"));
    fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.IncompleteMessage), collector.errors.items[0]);
}

test "JsonObjectDecoder: whitespace alone does not accumulate" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    const decoder = try JsonObjectDecoder.addTo(fixture.pipeline, .{ .max_length = 16 });
    const collector = try fixture.addCollector();

    // A peer that sends nothing but whitespace must not be able to grow the
    // accumulation: whitespace is consumed even though no value completes.
    for (0..64) |_| {
        fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "   \n"));
    }

    try testing.expectEqual(@as(usize, 0), decoder.decoder.pendingLen());
    try testing.expectEqual(@as(usize, 0), collector.errors.items.len);
}
