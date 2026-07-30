//! QUIC variable-length integers, RFC 9000 §16.
//!
//! Two bits of the first byte give the length, so the value range and the
//! encoded length are tied together:
//!
//! | prefix | bytes | value range |
//! |---|---|---|
//! | `00` | 1 | 0 .. 63 |
//! | `01` | 2 | 0 .. 16383 |
//! | `10` | 4 | 0 .. 1073741823 |
//! | `11` | 8 | 0 .. 4611686018427387903 |
//!
//! The rule that catches implementations out is in §16: "the encoding is not
//! required to use the minimum number of bytes". A decoder that rejects
//! non-minimal encodings is not merely strict, it is wrong — and it will
//! interoperate for years before meeting a peer that greases a frame type into
//! eight bytes. So `decode` accepts every encoding of a value and `isMinimal`
//! exists separately, for the two places §16 does require minimal form.

const std = @import("std");
const assert = std.debug.assert;

/// The largest value a QUIC varint can carry: 2^62 - 1 (§16).
pub const max_value: u64 = (1 << 62) - 1;

/// Every legal encoded length. Indexed by the two-bit prefix.
const lengths = [4]u4{ 1, 2, 4, 8 };

pub const Error = error{
    /// Fewer bytes are present than the prefix promises. On a datagram this is
    /// fatal for the packet; there is no "wait for more" in QUIC, because a
    /// datagram boundary is a message boundary.
    VarintTruncated,
    /// The value exceeds 2^62 - 1, which no encoding can represent, so this can
    /// only come from an out-of-range value handed to an encoder.
    VarintTooLarge,
};

pub const Decoded = struct {
    value: u64,
    /// How many bytes were consumed: 1, 2, 4 or 8. Not derivable from `value`,
    /// because the encoding need not be minimal.
    len: u4,
};

/// The encoded length promised by a first byte, without needing the rest.
/// Useful when deciding whether a buffer holds a whole varint yet.
pub fn peekLen(first: u8) u4 {
    return lengths[first >> 6];
}

/// The shortest number of bytes that can carry `value`.
pub fn encodedLen(value: u64) u4 {
    assert(value <= max_value);
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
}

/// Whether `value` is encoded minimally in `len` bytes. §16 lets a sender pick
/// any sufficient length, but a few fields elsewhere in the specification are
/// required to be minimal, and those callers ask this rather than re-deriving it.
pub fn isMinimal(value: u64, len: u4) bool {
    return encodedLen(value) == len;
}

/// Encode `value` minimally into `dest`, returning the bytes written.
/// Asserts `dest` is large enough: the caller knows the length from
/// `encodedLen`, so a short buffer is a local bug rather than a peer's doing.
pub fn encode(dest: []u8, value: u64) u4 {
    const len = encodedLen(value);
    return encodeIn(dest, value, len);
}

/// Encode `value` in exactly `len` bytes, which must be a legal length able to
/// hold it. This is the non-minimal path, and it exists for greasing: RFC 9114
/// §7.2.8 reserves values whose point is to be unfamiliar, and padding one out
/// to eight bytes exercises a peer's decoder the way §16 says it must cope with.
pub fn encodeIn(dest: []u8, value: u64, len: u4) u4 {
    assert(value <= max_value);
    assert(len == 1 or len == 2 or len == 4 or len == 8);
    assert(encodedLen(value) <= len);
    assert(dest.len >= len);

    switch (len) {
        1 => dest[0] = @intCast(value),
        2 => {
            std.mem.writeInt(u16, dest[0..2], @intCast(value), .big);
            dest[0] |= 0x40;
        },
        4 => {
            std.mem.writeInt(u32, dest[0..4], @intCast(value), .big);
            dest[0] |= 0x80;
        },
        8 => {
            std.mem.writeInt(u64, dest[0..8], value, .big);
            dest[0] |= 0xc0;
        },
        else => unreachable,
    }
    return len;
}

/// Decode a varint from the front of `src`.
pub fn decode(src: []const u8) Error!Decoded {
    if (src.len == 0) return error.VarintTruncated;
    const len = peekLen(src[0]);
    if (src.len < len) return error.VarintTruncated;

    // The two prefix bits are not part of the value.
    const first: u64 = src[0] & 0x3f;
    const value: u64 = switch (len) {
        1 => first,
        2 => (first << 8) | src[1],
        4 => (first << 24) | (@as(u64, src[1]) << 16) |
            (@as(u64, src[2]) << 8) | src[3],
        8 => (first << 56) | (@as(u64, src[1]) << 48) |
            (@as(u64, src[2]) << 40) | (@as(u64, src[3]) << 32) |
            (@as(u64, src[4]) << 24) | (@as(u64, src[5]) << 16) |
            (@as(u64, src[6]) << 8) | src[7],
        else => unreachable,
    };

    // Six bits are masked off the first byte and at most 56 follow, so the
    // result cannot exceed 2^62 - 1. Stated as an assertion because callers
    // downstream rely on it to skip their own range checks.
    assert(value <= max_value);
    return .{ .value = value, .len = len };
}

/// Decode and advance `src` past the varint, the shape most parsers want.
pub fn take(src: *[]const u8) Error!u64 {
    const decoded = try decode(src.*);
    src.* = src.*[decoded.len..];
    return decoded.value;
}

/// Take a varint and then that many bytes, the length-prefixed pattern that
/// appears throughout QUIC and HTTP/3.
pub fn takeBytes(src: *[]const u8) Error![]const u8 {
    const len = try take(src);
    if (len > src.len) return error.VarintTruncated;
    const bytes = src.*[0..@intCast(len)];
    src.* = src.*[@intCast(len)..];
    return bytes;
}

const testing = std.testing;

test "varint: the RFC 9000 appendix A.1 examples" {
    // §A.1 gives these four encodings by name.
    const cases = [_]struct { hex: []const u8, value: u64, len: u4 }{
        .{ .hex = "c2197c5eff14e88c", .value = 151288809941952652, .len = 8 },
        .{ .hex = "9d7f3e7d", .value = 494878333, .len = 4 },
        .{ .hex = "7bbd", .value = 15293, .len = 2 },
        .{ .hex = "25", .value = 37, .len = 1 },
    };
    for (cases) |case| {
        var bytes: [8]u8 = undefined;
        const src = try std.fmt.hexToBytes(&bytes, case.hex);

        const decoded = try decode(src);
        try testing.expectEqual(case.value, decoded.value);
        try testing.expectEqual(case.len, decoded.len);

        // And back, since these examples are all minimal.
        var out: [8]u8 = undefined;
        const written = encode(&out, case.value);
        try testing.expectEqual(case.len, written);
        try testing.expectEqualSlices(u8, src, out[0..written]);
    }
}

test "varint: a two-byte encoding of a one-byte value decodes to the same value" {
    // §16: "the encoding is not required to use the minimum number of bytes".
    // 37 fits in one byte; §A.1 also spells it as 0x4025. A decoder that
    // rejects this is wrong, and this is the test that says so.
    var bytes: [2]u8 = undefined;
    const src = try std.fmt.hexToBytes(&bytes, "4025");
    const decoded = try decode(src);
    try testing.expectEqual(@as(u64, 37), decoded.value);
    try testing.expectEqual(@as(u4, 2), decoded.len);

    // It is still not minimal, and callers who care can tell.
    try testing.expect(!isMinimal(decoded.value, decoded.len));
    try testing.expect(isMinimal(37, 1));
}

test "varint: every length can carry zero, and all four decode alike" {
    for ([_]u4{ 1, 2, 4, 8 }) |len| {
        var out: [8]u8 = undefined;
        _ = encodeIn(&out, 0, len);
        const decoded = try decode(out[0..len]);
        try testing.expectEqual(@as(u64, 0), decoded.value);
        try testing.expectEqual(len, decoded.len);
    }
}

test "varint: the boundary of each length, either side" {
    const boundaries = [_]struct { value: u64, len: u4 }{
        .{ .value = 0, .len = 1 },
        .{ .value = 63, .len = 1 },
        .{ .value = 64, .len = 2 },
        .{ .value = 16383, .len = 2 },
        .{ .value = 16384, .len = 4 },
        .{ .value = 1073741823, .len = 4 },
        .{ .value = 1073741824, .len = 8 },
        .{ .value = max_value, .len = 8 },
    };
    for (boundaries) |b| {
        try testing.expectEqual(b.len, encodedLen(b.value));
        var out: [8]u8 = undefined;
        const written = encode(&out, b.value);
        try testing.expectEqual(b.len, written);
        const decoded = try decode(out[0..written]);
        try testing.expectEqual(b.value, decoded.value);
    }
}

test "varint: a truncated encoding is reported rather than guessed" {
    // The prefix promises eight bytes; only three are here. Guessing would
    // fabricate a value, and on a datagram there is no more to wait for.
    var bytes: [3]u8 = undefined;
    const src = try std.fmt.hexToBytes(&bytes, "c21900");
    try testing.expectError(error.VarintTruncated, decode(src));
    try testing.expectError(error.VarintTruncated, decode(&.{}));
}

test "varint: peekLen answers from the first byte alone" {
    try testing.expectEqual(@as(u4, 1), peekLen(0x25));
    try testing.expectEqual(@as(u4, 2), peekLen(0x7b));
    try testing.expectEqual(@as(u4, 4), peekLen(0x9d));
    try testing.expectEqual(@as(u4, 8), peekLen(0xc2));
}

test "varint: take advances, takeBytes carries a length prefix" {
    var buf: [16]u8 = undefined;
    var i: usize = 0;
    i += encode(buf[i..], 37);
    i += encode(buf[i..], 3);
    @memcpy(buf[i..][0..3], "abc");
    i += 3;

    var src: []const u8 = buf[0..i];
    try testing.expectEqual(@as(u64, 37), try take(&src));
    try testing.expectEqualStrings("abc", try takeBytes(&src));
    try testing.expectEqual(@as(usize, 0), src.len);
}

test "varint: a length prefix longer than what follows is refused" {
    // Claiming ten bytes with three present must not hand out a slice past the
    // end. This is the shape that becomes a read overrun when it is not checked.
    var buf: [8]u8 = undefined;
    var i: usize = 0;
    i += encode(&buf, 10);
    @memcpy(buf[i..][0..3], "abc");
    i += 3;

    var src: []const u8 = buf[0..i];
    try testing.expectError(error.VarintTruncated, takeBytes(&src));
}

test "varint: round trip over every length boundary and many values" {
    var prng = std.Random.DefaultPrng.init(0x9000);
    const random = prng.random();
    for (0..4096) |_| {
        const value = random.uintAtMost(u64, max_value);
        var out: [8]u8 = undefined;
        const written = encode(&out, value);
        const decoded = try decode(out[0..written]);
        try testing.expectEqual(value, decoded.value);
        try testing.expectEqual(written, decoded.len);

        // Any longer legal length must decode to the same value.
        var len: u4 = written;
        while (len < 8) {
            len = if (len == 1) 2 else if (len == 2) 4 else 8;
            var padded: [8]u8 = undefined;
            _ = encodeIn(&padded, value, len);
            const wide = try decode(padded[0..len]);
            try testing.expectEqual(value, wide.value);
        }
    }
}
