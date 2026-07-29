//! Text transforms that sit on already-framed messages.
//!
//! ## Why there is no `StringDecoder`
//!
//! Netty ships `StringDecoder` and `StringEncoder` because a `ByteBuf` is not a
//! `String`: something has to do the conversion, and a charset has to be chosen.
//! Zinet's `Message` already hands out `[]const u8`, so the equivalent handler
//! would forward its input unchanged — a name with no behaviour behind it. What
//! is genuinely missing from "these bytes are text" is *validation*, so that is
//! what `Utf8Validator` provides.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../buffer.zig").Buffer;
const codec = @import("codec.zig");
const pipeline_mod = @import("../pipeline.zig");

const Error = codec.Error;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const MessageToMessageDecoder = codec.MessageToMessageDecoder;
const MessageToMessageEncoder = codec.MessageToMessageEncoder;
const Pipeline = pipeline_mod.Pipeline;

/// Which alphabet and padding a Base64 handler uses.
pub const Base64Variant = enum {
    /// RFC 4648 §4 with padding, the default everywhere.
    standard,
    /// RFC 4648 §4 without padding.
    standard_no_pad,
    /// RFC 4648 §5, `-` and `_` instead of `+` and `/`, with padding.
    url_safe,
    /// RFC 4648 §5 without padding, as used by JWT.
    url_safe_no_pad,

    fn codecs(variant: Base64Variant) std.base64.Codecs {
        return switch (variant) {
            .standard => std.base64.standard,
            .standard_no_pad => std.base64.standard_no_pad,
            .url_safe => std.base64.url_safe,
            .url_safe_no_pad => std.base64.url_safe_no_pad,
        };
    }
};

/// Encodes each inbound-or-outbound message's bytes as Base64.
///
/// Netty's `Base64Encoder`. Operates on whole messages, so it belongs *after* a
/// framing decoder or *before* a length prepender — never on a raw stream, where
/// message boundaries would be arbitrary and the output would not decode.
pub const Base64Encoder = struct {
    const Base = MessageToMessageEncoder(Base64Encoder, []const u8);

    variant: Base64Variant = .standard,
    /// Ceiling on one encoded message.
    max_capacity: usize = Buffer.default_max_capacity,

    pub const handler_name = "base64-encoder";

    pub fn addTo(pipeline: *Pipeline, variant: Base64Variant) !*Base64Encoder {
        const handler = try pipeline.gpa.create(Base64Encoder);
        handler.* = .{ .variant = variant };
        errdefer pipeline.gpa.destroy(handler);
        _ = try pipeline.addLast(handler_name, .initOwned(handler));
        return handler;
    }

    pub fn onWrite(self: *Base64Encoder, ctx: *HandlerContext, msg: Message) Error!void {
        return Base.onWrite(self, ctx, msg);
    }

    pub fn encode(
        self: *Base64Encoder,
        ctx: *HandlerContext,
        value: []const u8,
    ) Error!?Message {
        const encoder = self.variant.codecs().Encoder;
        const size = encoder.calcSize(value.len);

        var out = try Buffer.init(ctx.gpa(), .{
            .capacity = size,
            .max_capacity = self.max_capacity,
        });
        errdefer out.deinit(ctx.gpa());

        const destination = try out.reserve(ctx.gpa(), size);
        const written = encoder.encode(destination, value);
        assert(written.len == size);
        return .initBuffer(&out);
    }
};

/// Decodes each message's bytes from Base64.
///
/// Netty's `Base64Decoder`. Invalid input fails the message with
/// `error.MalformedMessage`: unlike a stream decoder there is nothing to
/// resynchronize on, because the caller has already decided where this message
/// begins and ends.
pub const Base64Decoder = struct {
    const Base = MessageToMessageDecoder(Base64Decoder, []const u8);

    variant: Base64Variant = .standard,
    max_capacity: usize = Buffer.default_max_capacity,

    pub const handler_name = "base64-decoder";

    pub fn addTo(pipeline: *Pipeline, variant: Base64Variant) !*Base64Decoder {
        const handler = try pipeline.gpa.create(Base64Decoder);
        handler.* = .{ .variant = variant };
        errdefer pipeline.gpa.destroy(handler);
        _ = try pipeline.addLast(handler_name, .initOwned(handler));
        return handler;
    }

    pub fn onRead(self: *Base64Decoder, ctx: *HandlerContext, msg: Message) Error!void {
        return Base.onRead(self, ctx, msg);
    }

    pub fn decode(
        self: *Base64Decoder,
        ctx: *HandlerContext,
        value: []const u8,
    ) Error!?Message {
        const decoder = self.variant.codecs().Decoder;
        const size = decoder.calcSizeForSlice(value) catch return error.MalformedMessage;

        var out = try Buffer.init(ctx.gpa(), .{
            .capacity = @max(size, 1),
            .max_capacity = self.max_capacity,
        });
        errdefer out.deinit(ctx.gpa());

        const destination = try out.reserve(ctx.gpa(), size);
        decoder.decode(destination[0..size], value) catch return error.MalformedMessage;
        return .initBuffer(&out);
    }
};

/// Rejects inbound messages that are not valid UTF-8.
///
/// The part of Netty's `StringDecoder` that actually does something. Place it
/// after framing, where a message is a whole unit of text; validating a raw
/// stream would reject any multi-byte character split across two reads.
pub const Utf8Validator = struct {
    const Base = MessageToMessageDecoder(Utf8Validator, []const u8);

    pub const handler_name = "utf8-validator";

    pub fn addTo(pipeline: *Pipeline) !*Utf8Validator {
        const handler = try pipeline.gpa.create(Utf8Validator);
        handler.* = .{};
        errdefer pipeline.gpa.destroy(handler);
        _ = try pipeline.addLast(handler_name, .initOwned(handler));
        return handler;
    }

    pub fn onRead(self: *Utf8Validator, ctx: *HandlerContext, msg: Message) Error!void {
        return Base.onRead(self, ctx, msg);
    }

    pub fn decode(
        _: *Utf8Validator,
        ctx: *HandlerContext,
        value: []const u8,
    ) Error!?Message {
        if (!std.unicode.utf8ValidateSlice(value)) return error.MalformedMessage;
        // Valid: hand the same bytes on. A copy is needed because the input
        // message is released when this returns.
        return try Message.initBytes(ctx.gpa(), value);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const test_support = @import("test_support.zig");

test "Base64Encoder: encodes an outbound message" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    _ = try Base64Encoder.addTo(fixture.pipeline, .standard);

    try fixture.pipeline.write(try Message.initBytes(testing.allocator, "hello"));
    try testing.expectEqualStrings("aGVsbG8=", fixture.written());
}

test "Base64Decoder: decodes an inbound message" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    _ = try Base64Decoder.addTo(fixture.pipeline, .standard);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "aGVsbG8="));

    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("hello", collector.messages.items[0]);
}

test "Base64: encoding then decoding is the identity, for every variant" {
    const payloads = [_][]const u8{ "", "a", "ab", "abc", "abcd", "\x00\xff\xfe binary" };
    for (std.enums.values(Base64Variant)) |variant| {
        for (payloads) |payload| {
            var fixture = try test_support.Fixture.init(testing.allocator);
            defer fixture.deinit();
            _ = try Base64Decoder.addTo(fixture.pipeline, variant);
            const collector = try fixture.addCollector();

            // Encode out of band, then feed the result back in.
            var encoder: Base64Encoder = .{ .variant = variant };
            var scratch = try Buffer.init(testing.allocator, .{ .capacity = 64 });
            defer scratch.deinit(testing.allocator);
            const codecs = encoder.variant.codecs();
            const size = codecs.Encoder.calcSize(payload.len);
            const destination = try scratch.reserve(testing.allocator, size);
            _ = codecs.Encoder.encode(destination, payload);

            fixture.pipeline.fireRead(try Message.initBytes(
                testing.allocator,
                scratch.readableSlice(),
            ));

            try testing.expectEqual(@as(usize, 0), collector.errors.items.len);
            try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
            try testing.expectEqualStrings(payload, collector.messages.items[0]);
        }
    }
}

test "Base64Decoder: invalid input fails the message" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    _ = try Base64Decoder.addTo(fixture.pipeline, .standard);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "not!base64!!"));

    try testing.expectEqual(@as(usize, 0), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.MalformedMessage), collector.errors.items[0]);
}

test "Utf8Validator: passes valid text and rejects invalid bytes" {
    var fixture = try test_support.Fixture.init(testing.allocator);
    defer fixture.deinit();
    _ = try Utf8Validator.addTo(fixture.pipeline);
    const collector = try fixture.addCollector();

    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "héllo ✓"));
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqualStrings("héllo ✓", collector.messages.items[0]);

    // A lone continuation byte is not valid UTF-8.
    fixture.pipeline.fireRead(try Message.initBytes(testing.allocator, "\x80"));
    try testing.expectEqual(@as(usize, 1), collector.messages.items.len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.MalformedMessage), collector.errors.items[0]);
}
