//! The `permessage-deflate` WebSocket extension, RFC 7692.
//!
//! Compresses the payload of each data message with raw DEFLATE and marks the
//! first frame of the message with RSV1. What makes it an extension rather than
//! a codec is the handshake: both ends must agree, in
//! `Sec-WebSocket-Extensions`, on parameters that bound each side's memory.
//!
//! ## What is negotiated, and why it is not everything
//!
//! RFC 7692 defines four parameters. Zinet's answer to each is decided by what
//! `std.compress.flate` can do, not by preference:
//!
//! * **`server_no_context_takeover` / `client_no_context_takeover` are always
//!   required.** Context takeover means keeping the LZ77 window across messages,
//!   which needs a *sync flush* — ending a message without ending the DEFLATE
//!   stream. `std.compress.flate.Compress` has no such operation: its `flush`
//!   only byte-aligns, and `finish` closes the stream for good. So each message
//!   is compressed from an empty window, and both parameters are negotiated so
//!   the peer knows it and resets too. Refusing to compress at all would be
//!   worse; silently deviating would be much worse.
//! * **`server_max_window_bits` / `client_max_window_bits` are not supported.**
//!   `Compress` asserts a full 32 KiB window, so a smaller one cannot be
//!   promised. An offer that *requires* a smaller server window is declined
//!   rather than accepted and ignored, and no response ever carries
//!   `client_max_window_bits`, which RFC 7692 §7.1.2.2 forbids unless the offer
//!   asked for it.
//!
//! ## Framing without a sync flush
//!
//! §7.2.1 wants a message to end with an empty uncompressed DEFLATE block whose
//! trailing `00 00 FF FF` is then stripped. Without a sync flush that is not
//! reachable — but §7.2.3.4 anticipates exactly this platform and blesses the
//! alternative: finish the stream with `BFINAL` set to 1 and append one `0x00`
//! octet, the header of an empty uncompressed block with `BFINAL` clear. A
//! receiver appending `00 00 FF FF` then decodes it identically. So that is what
//! `Compressor` emits, and it is conformant rather than a shortcut.
//!
//! Decompression handles both forms, because the peer is free to use either.

const std = @import("std");
const test_support = @import("test_support.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;
const Io = std.Io;

/// The registered extension name.
pub const extension_name = "permessage-deflate";

/// Bytes a receiver appends before inflating, per RFC 7692 §7.2.2.
const sync_tail = [_]u8{ 0x00, 0x00, 0xff, 0xff };

/// The offer a Zinet client sends.
///
/// Both `no_context_takeover` parameters are requested because neither side can
/// carry a window across messages here. `client_max_window_bits` is deliberately
/// absent: including it would invite a response constraining our window, which
/// we could not honour.
pub const client_offer = extension_name ++
    "; client_no_context_takeover; server_no_context_takeover";

/// The response a Zinet server sends when it accepts.
pub const server_response = extension_name ++
    "; client_no_context_takeover; server_no_context_takeover";

pub const Error = error{
    /// A parameter appeared that is not defined for this direction, or twice, or
    /// with a bad value. RFC 7692 §7 requires declining or failing.
    MalformedExtensionParameters,
    /// The server's response asks for something this implementation cannot do.
    UnsupportedExtensionParameters,
    /// The peer accepted an extension that was never offered.
    UnexpectedExtension,
};

/// One element of a `Sec-WebSocket-Extensions` header value.
pub const Offer = struct {
    name: []const u8,
    server_no_context_takeover: bool = false,
    client_no_context_takeover: bool = false,
    /// Present, with a value.
    server_max_window_bits: ?u8 = null,
    /// Present; the value is optional in an offer.
    client_max_window_bits: bool = false,
    client_max_window_bits_value: ?u8 = null,

    /// Whether this offer is one a Zinet server can accept as-is.
    ///
    /// A `server_max_window_bits` request has to be declined: it constrains the
    /// window we compress with, and we cannot make that promise. Clients that
    /// care usually offer a fallback element without it, which is why declining
    /// one element is not the same as declining the extension.
    pub fn isAcceptable(offer: Offer) bool {
        return offer.server_max_window_bits == null;
    }
};

/// Splits a header value on commas and parses each element.
///
/// Elements are returned in order, because order is the client's preference.
pub const OfferIterator = struct {
    rest: []const u8,

    pub fn init(header_value: []const u8) OfferIterator {
        return .{ .rest = header_value };
    }

    pub fn next(iterator: *OfferIterator) Error!?Offer {
        while (true) {
            const text = iterator.take() orelse return null;
            const trimmed = std.mem.trim(u8, text, " \t");
            if (trimmed.len == 0) continue;
            return try parseOffer(trimmed);
        }
    }

    fn take(iterator: *OfferIterator) ?[]const u8 {
        if (iterator.rest.len == 0) return null;
        const comma = std.mem.indexOfScalar(u8, iterator.rest, ',') orelse {
            const all = iterator.rest;
            iterator.rest = "";
            return all;
        };
        const head = iterator.rest[0..comma];
        iterator.rest = iterator.rest[comma + 1 ..];
        return head;
    }
};

/// Parses one element: a name followed by `; key` or `; key=value` parameters.
pub fn parseOffer(text: []const u8) Error!Offer {
    var parts = std.mem.splitScalar(u8, text, ';');
    const name = std.mem.trim(u8, parts.first(), " \t");
    var offer: Offer = .{ .name = name };

    while (parts.next()) |raw| {
        const part = std.mem.trim(u8, raw, " \t");
        if (part.len == 0) return error.MalformedExtensionParameters;

        var key = part;
        var value: ?[]const u8 = null;
        if (std.mem.indexOfScalar(u8, part, '=')) |equals| {
            key = std.mem.trim(u8, part[0..equals], " \t");
            // Values may be quoted, per RFC 6455 §9.1.
            value = std.mem.trim(u8, std.mem.trim(
                u8,
                part[equals + 1 ..],
                " \t",
            ), "\"");
        }

        if (std.mem.eql(u8, key, "server_no_context_takeover")) {
            if (value != null) return error.MalformedExtensionParameters;
            if (offer.server_no_context_takeover) return error.MalformedExtensionParameters;
            offer.server_no_context_takeover = true;
        } else if (std.mem.eql(u8, key, "client_no_context_takeover")) {
            if (value != null) return error.MalformedExtensionParameters;
            if (offer.client_no_context_takeover) return error.MalformedExtensionParameters;
            offer.client_no_context_takeover = true;
        } else if (std.mem.eql(u8, key, "server_max_window_bits")) {
            if (offer.server_max_window_bits != null) return error.MalformedExtensionParameters;
            // Required to have a value in an offer, per §7.1.2.1.
            offer.server_max_window_bits = try parseWindowBits(value orelse
                return error.MalformedExtensionParameters);
        } else if (std.mem.eql(u8, key, "client_max_window_bits")) {
            if (offer.client_max_window_bits) return error.MalformedExtensionParameters;
            offer.client_max_window_bits = true;
            if (value) |text_value| {
                offer.client_max_window_bits_value = try parseWindowBits(text_value);
            }
        } else {
            // An unknown parameter is not something to ignore: §7 says an offer
            // carrying one must be declined.
            return error.MalformedExtensionParameters;
        }
    }
    return offer;
}

fn parseWindowBits(text: []const u8) Error!u8 {
    if (text.len == 0 or text[0] == '0') return error.MalformedExtensionParameters;
    const bits = std.fmt.parseInt(u8, text, 10) catch
        return error.MalformedExtensionParameters;
    if (bits < 8 or bits > 15) return error.MalformedExtensionParameters;
    return bits;
}

/// Picks an offer a server can accept, in the client's order of preference.
///
/// Returns null when every element must be declined, which means proceeding
/// without compression rather than failing — the extension is optional.
pub fn selectOffer(header_value: []const u8) ?Offer {
    var iterator: OfferIterator = .init(header_value);
    while (iterator.next() catch return null) |offer| {
        if (!std.mem.eql(u8, offer.name, extension_name)) continue;
        if (offer.isAcceptable()) return offer;
    }
    return null;
}

/// Checks a server's response against what a Zinet client offered.
///
/// Returns whether compression is in use. A response that accepts the extension
/// on terms we cannot meet is an error: RFC 7692 says the client must fail the
/// connection rather than proceed and produce garbage.
pub fn acceptResponse(header_value: ?[]const u8) Error!bool {
    const value = header_value orelse return false;

    var iterator: OfferIterator = .init(value);
    var found = false;
    while (try iterator.next()) |response| {
        if (!std.mem.eql(u8, response.name, extension_name)) {
            // Some other extension we never offered.
            return error.UnexpectedExtension;
        }
        // Only one element may be accepted.
        if (found) return error.MalformedExtensionParameters;
        found = true;

        // Without this, the server may carry its window across messages and our
        // decompressor — which starts empty every time — would produce garbage.
        if (!response.server_no_context_takeover) return error.UnsupportedExtensionParameters;
        // A window we cannot promise.
        if (response.server_max_window_bits != null) return error.UnsupportedExtensionParameters;
        // §7.1.2.2: forbidden unless the offer asked for it, and ours does not.
        if (response.client_max_window_bits) return error.UnsupportedExtensionParameters;
    }
    return found;
}

/// Per-connection compression state.
///
/// Windows are allocated on first use in each direction, so a connection that
/// only ever receives compressed messages does not pay for a compressor. Each
/// one is 64 KiB, which is what a 32 KiB LZ77 window costs in this
/// implementation; that is the price of the extension and worth knowing before
/// enabling it on many connections.
pub const Deflate = struct {
    options: Options,
    compress_window: []u8 = &.{},
    decompress_window: []u8 = &.{},

    pub const Options = struct {
        /// Payloads shorter than this are sent uncompressed, with RSV1 clear.
        ///
        /// DEFLATE has per-message overhead, so compressing a few bytes usually
        /// makes them longer. The extension allows a message to be sent
        /// uncompressed at any time, which is what makes this legal.
        min_compress_size: usize = 64,
        /// Hard ceiling on what one message may decompress to.
        ///
        /// This is a security limit, not a tuning knob. DEFLATE reaches ratios
        /// of roughly 1000:1, so without it a peer could turn a 1 MiB frame into
        /// a gigabyte of allocation — and the frame-level `max_message_length`
        /// bounds the *compressed* size, which says nothing about the output.
        max_decompressed_size: usize = 1 << 20,
    };

    pub fn init(options: Options) Deflate {
        return .{ .options = options };
    }

    pub fn deinit(self: *Deflate, gpa: Allocator) void {
        if (self.compress_window.len != 0) gpa.free(self.compress_window);
        if (self.decompress_window.len != 0) gpa.free(self.decompress_window);
        self.* = undefined;
    }

    /// Whether `payload` is worth compressing.
    pub fn shouldCompress(self: *const Deflate, payload: []const u8) bool {
        return payload.len >= self.options.min_compress_size;
    }

    /// Compresses `payload` for a frame with RSV1 set. The result is owned by
    /// the caller, matching `Frame.payload`.
    pub fn compress(self: *Deflate, gpa: Allocator, payload: []const u8) ![]u8 {
        if (self.compress_window.len == 0) {
            self.compress_window = try gpa.alloc(u8, flate.max_window_len);
        }

        var out: Io.Writer.Allocating = try .initCapacity(gpa, payload.len / 2 + 32);
        errdefer out.deinit();

        var compressor = try flate.Compress.init(
            &out.writer,
            self.compress_window,
            .raw,
            .default,
        );
        try compressor.writer.writeAll(payload);
        try compressor.finish();

        // RFC 7692 §7.2.3.4: the header of an empty uncompressed block with
        // BFINAL clear, which is what remains of `00 00 00 FF FF` after §7.2.1
        // strips the last four octets. Without it a peer that appends the sync
        // tail sees a malformed stream.
        try out.writer.writeByte(0x00);
        return out.toOwnedSlice();
    }

    /// Decompresses a message payload that arrived with RSV1 set. The result is
    /// owned by the caller.
    pub fn decompress(self: *Deflate, gpa: Allocator, payload: []const u8) ![]u8 {
        if (self.decompress_window.len == 0) {
            self.decompress_window = try gpa.alloc(u8, flate.max_window_len);
        }

        // §7.2.2: restore the tail the sender stripped. Copied rather than
        // streamed in two pieces because the inflater wants one reader.
        const framed = try gpa.alloc(u8, payload.len + sync_tail.len);
        defer gpa.free(framed);
        @memcpy(framed[0..payload.len], payload);
        @memcpy(framed[payload.len..], &sync_tail);

        var input: Io.Reader = .fixed(framed);
        var decompressor = flate.Decompress.init(&input, .raw, self.decompress_window);

        var plain: std.ArrayList(u8) = .empty;
        errdefer plain.deinit(gpa);

        // The limit is the zip-bomb guard, and it is enforced while inflating
        // rather than after, so the oversized output is never fully held.
        decompressor.reader.appendRemaining(
            gpa,
            &plain,
            .limited(self.options.max_decompressed_size),
        ) catch |err| switch (err) {
            error.StreamTooLong => return error.DecompressedMessageTooLarge,
            error.OutOfMemory => return error.OutOfMemory,
            error.ReadFailed => {
                // Running out of input without a final block is not a failure
                // here: a message flushed the usual way — with an empty
                // non-final block, which is what zlib's `Z_SYNC_FLUSH` writes —
                // ends exactly like that, and the inflater cannot know the
                // message is over. Anything else is a real decoding failure.
                //
                // The cost of accepting it is that a deliberately truncated
                // stream yields a short message rather than an error. WebSocket
                // framing already guarantees the payload is complete, so there
                // is nothing else this layer could conclude.
                const cause = decompressor.err orelse return error.MalformedCompressedMessage;
                if (cause != error.EndOfStream) return error.MalformedCompressedMessage;
            },
        };
        return plain.toOwnedSlice(gpa);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "parseOffer: the shapes RFC 7692 §7.1.3 shows" {
    {
        const offer = try parseOffer("permessage-deflate");
        try testing.expectEqualStrings("permessage-deflate", offer.name);
        try testing.expect(!offer.server_no_context_takeover);
        try testing.expect(offer.server_max_window_bits == null);
        try testing.expect(offer.isAcceptable());
    }
    {
        const offer = try parseOffer(
            "permessage-deflate; client_max_window_bits; server_max_window_bits=10",
        );
        try testing.expect(offer.client_max_window_bits);
        try testing.expectEqual(@as(?u8, 10), offer.server_max_window_bits);
        // A window we cannot promise, so this element must be declined.
        try testing.expect(!offer.isAcceptable());
    }
    {
        // Quoted values are legal.
        const offer = try parseOffer("permessage-deflate; server_max_window_bits=\"12\"");
        try testing.expectEqual(@as(?u8, 12), offer.server_max_window_bits);
    }
    {
        const offer = try parseOffer(
            "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
        );
        try testing.expect(offer.client_no_context_takeover);
        try testing.expect(offer.server_no_context_takeover);
        try testing.expect(offer.isAcceptable());
    }
}

test "parseOffer: rejects the malformed shapes" {
    const cases = [_][]const u8{
        // A valueless parameter given a value, and the reverse.
        "permessage-deflate; server_no_context_takeover=1",
        "permessage-deflate; server_max_window_bits",
        // Out of the 8..15 range, and with a leading zero.
        "permessage-deflate; server_max_window_bits=7",
        "permessage-deflate; server_max_window_bits=16",
        "permessage-deflate; client_max_window_bits=08",
        // Repeated parameters.
        "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
        // Unknown parameters must be declined, not ignored.
        "permessage-deflate; unknown_parameter",
        "permessage-deflate; ;",
    };
    for (cases) |case| {
        try testing.expectError(error.MalformedExtensionParameters, parseOffer(case));
    }
}

test "selectOffer: takes the first element it can accept" {
    // The fallback pattern from §7.1.3: a constrained offer first, then a plain
    // one. The constrained element is declined and the fallback taken.
    const header = "permessage-deflate; client_max_window_bits; server_max_window_bits=10, " ++
        "permessage-deflate; client_max_window_bits";
    const chosen = selectOffer(header).?;
    try testing.expect(chosen.server_max_window_bits == null);
    try testing.expect(chosen.client_max_window_bits);

    // Nothing acceptable means no compression, not a failure.
    try testing.expect(selectOffer("permessage-deflate; server_max_window_bits=9") == null);
    try testing.expect(selectOffer("permessage-bar") == null);
    try testing.expect(selectOffer("") == null);
}

test "acceptResponse: only a response we can honour enables compression" {
    try testing.expectEqual(false, try acceptResponse(null));

    try testing.expectEqual(true, try acceptResponse(
        "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
    ));

    // Without server_no_context_takeover the server may carry its window over,
    // and our decompressor starts empty every message, so this cannot proceed.
    try testing.expectError(
        error.UnsupportedExtensionParameters,
        acceptResponse("permessage-deflate; client_no_context_takeover"),
    );
    // A window size we cannot promise.
    try testing.expectError(
        error.UnsupportedExtensionParameters,
        acceptResponse("permessage-deflate; server_no_context_takeover; " ++
            "server_max_window_bits=10"),
    );
    // §7.1.2.2 forbids this unless the offer asked, and ours does not.
    try testing.expectError(
        error.UnsupportedExtensionParameters,
        acceptResponse("permessage-deflate; server_no_context_takeover; " ++
            "client_max_window_bits=10"),
    );
    // An extension that was never offered.
    try testing.expectError(error.UnexpectedExtension, acceptResponse("permessage-bar"));
}

test "Deflate: round trips a payload" {
    const gpa = testing.allocator;
    var deflate: Deflate = .init(.{});
    defer deflate.deinit(gpa);

    const payload = "the quick brown fox jumps over the lazy dog, " ++
        "the quick brown fox jumps over the lazy dog";

    const compressed = try deflate.compress(gpa, payload);
    defer gpa.free(compressed);
    // Repetitive text must actually get smaller, or the extension is pointless.
    try testing.expect(compressed.len < payload.len);

    const plain = try deflate.decompress(gpa, compressed);
    defer gpa.free(plain);
    try testing.expectEqualStrings(payload, plain);
}

test "Deflate: round trips the awkward sizes" {
    const gpa = testing.allocator;
    var deflate: Deflate = .init(.{});
    defer deflate.deinit(gpa);

    var big: [70000]u8 = undefined;
    for (&big, 0..) |*slot, index| slot.* = @truncate(index * 31);

    const cases = [_][]const u8{ "", "a", "ab", &big };
    for (cases) |payload| {
        const compressed = try deflate.compress(gpa, payload);
        defer gpa.free(compressed);
        const plain = try deflate.decompress(gpa, compressed);
        defer gpa.free(plain);
        try testing.expectEqualSlices(u8, payload, plain);
    }
}

test "Deflate: each message compresses from an empty window" {
    // The observable consequence of no context takeover: the same input gives
    // the same output every time. If a window were carried over, the second
    // would be shorter — and a peer told we do not use takeover would then be
    // unable to decode it.
    const gpa = testing.allocator;
    var deflate: Deflate = .init(.{});
    defer deflate.deinit(gpa);

    const payload = test_support.repeat("Hello", 20);

    const first = try deflate.compress(gpa, payload);
    defer gpa.free(first);
    const second = try deflate.compress(gpa, payload);
    defer gpa.free(second);

    try testing.expectEqualSlices(u8, first, second);
}

test "Deflate: decodes a payload flushed with a sync flush" {
    // The other legal form, which is what zlib's Z_SYNC_FLUSH produces and
    // therefore what most peers send. The bytes are the example from RFC 7692
    // §7.2.3.1: "Hello", with `00 00 FF FF` already stripped.
    const gpa = testing.allocator;
    var deflate: Deflate = .init(.{});
    defer deflate.deinit(gpa);

    const wire = [_]u8{ 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00 };
    const plain = try deflate.decompress(gpa, &wire);
    defer gpa.free(plain);
    try testing.expectEqualStrings("Hello", plain);
}

test "Deflate: decodes the BFINAL form from RFC 7692 §7.2.3.4" {
    const gpa = testing.allocator;
    var deflate: Deflate = .init(.{});
    defer deflate.deinit(gpa);

    const wire = [_]u8{ 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x00 };
    const plain = try deflate.decompress(gpa, &wire);
    defer gpa.free(plain);
    try testing.expectEqualStrings("Hello", plain);
}

test "Deflate: a decompression bomb is refused" {
    // The security property. A small frame must not be able to make the
    // receiver allocate without bound, and the frame-level length limit says
    // nothing about the decompressed size.
    const gpa = testing.allocator;

    var sender: Deflate = .init(.{});
    defer sender.deinit(gpa);

    const zeros = try gpa.alloc(u8, 512 * 1024);
    defer gpa.free(zeros);
    @memset(zeros, 0);

    const bomb = try sender.compress(gpa, zeros);
    defer gpa.free(bomb);
    // Half a megabyte of zeros compresses to a tiny frame.
    try testing.expect(bomb.len < 2048);

    var receiver: Deflate = .init(.{ .max_decompressed_size = 4096 });
    defer receiver.deinit(gpa);
    try testing.expectError(
        error.DecompressedMessageTooLarge,
        receiver.decompress(gpa, bomb),
    );
}

test "Deflate: garbage is reported rather than trusted" {
    const gpa = testing.allocator;
    var deflate: Deflate = .init(.{});
    defer deflate.deinit(gpa);

    const garbage = [_]u8{ 0xff, 0xfe, 0xfd, 0xfc, 0x01, 0x02, 0x03 };
    try testing.expectError(
        error.MalformedCompressedMessage,
        deflate.decompress(gpa, &garbage),
    );
}
