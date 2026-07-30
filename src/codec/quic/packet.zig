//! QUIC packet headers, RFC 9000 §17.
//!
//! Three things about this layer shape its interface, and each one is a place
//! implementations go wrong.
//!
//! **The packet number is encrypted.** Header protection (RFC 9001 §5.4) covers
//! the packet number field and the low bits of the first byte — including the
//! length of the packet number itself. So parsing cannot be one pass: this
//! module locates the packet number *offset* and leaves the field alone.
//! `crypto.zig` removes protection, and only then can `decodePacketNumber` run.
//! An interface that returned a packet number here would be lying about what is
//! knowable.
//!
//! **A short header does not carry its destination connection ID length.**
//! §17.3 leaves it out because both ends already know it: the length is chosen
//! by whoever issued the connection ID. That makes it local knowledge rather
//! than wire data, so `parse` takes it as a parameter. Long headers do carry it,
//! which is what lets a server parse a first packet from a peer it has never
//! seen.
//!
//! **A datagram may hold several packets.** §12.2 permits coalescing, and a
//! handshake normally does it — Initial and Handshake in one datagram. So
//! parsing reports where the packet ends, and the caller loops. A short header
//! has no length field, so it is always last.

const std = @import("std");
const assert = std.debug.assert;

const varint = @import("varint.zig");

/// §17.2: connection IDs are 0 to 20 bytes in QUIC version 1.
pub const max_cid_len = 20;

/// §5.1.1: an endpoint that issues zero-length connection IDs cannot migrate,
/// but it is legal, so zero is a valid length rather than a missing value.
pub const ConnectionId = struct {
    bytes: [max_cid_len]u8 = @splat(0),
    len: u8 = 0,

    pub const empty: ConnectionId = .{};

    /// Named to avoid shadowing this module's `Error`, which a reference from
    /// inside this struct would otherwise find ambiguous.
    pub const InitError = error{ConnectionIdTooLong};

    pub fn init(source: []const u8) InitError!ConnectionId {
        if (source.len > max_cid_len) return error.ConnectionIdTooLong;
        var cid: ConnectionId = .{ .len = @intCast(source.len) };
        @memcpy(cid.bytes[0..source.len], source);
        return cid;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(a: *const ConnectionId, b: *const ConnectionId) bool {
        return std.mem.eql(u8, a.slice(), b.slice());
    }

    /// For hashing connection IDs in a demultiplexing table.
    pub fn hash(self: *const ConnectionId) u64 {
        return std.hash.Wyhash.hash(0, self.slice());
    }

    pub fn format(self: ConnectionId, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        for (self.slice()) |byte| try writer.print("{x:0>2}", .{byte});
    }
};

/// §15: version 1 is 0x00000001. Version 0 is reserved for Version
/// Negotiation, which is why it is named rather than left to the caller.
/// Non-exhaustive because §6 requires answering an unknown version rather than
/// failing to represent it.
pub const Version = enum(u32) {
    negotiation = 0x00000000,
    v1 = 0x00000001,
    /// §15 reserves 0x?a?a?a?a to exercise version negotiation. Any such value
    /// is deliberately unknown; this one is the conventional example.
    grease = 0x0a0a0a0a,
    _,

    pub fn isSupported(self: Version) bool {
        return self == .v1;
    }
};

/// §17.2, bits 5 and 4 of the first byte of a long header.
pub const LongType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

/// Which of the four packet number spaces a packet belongs to (§12.3).
/// Not a property of the header alone: 0-RTT and 1-RTT share the application
/// data space, which is why this is derived rather than parsed.
pub const NumberSpace = enum {
    initial,
    handshake,
    application,
};

pub const header_form_bit: u8 = 0x80;
/// §17.2: "Fixed Bit". Zero means "not a QUIC v1 packet as far as this endpoint
/// is concerned", except in a Version Negotiation packet where it is unused.
pub const fixed_bit: u8 = 0x40;
pub const spin_bit: u8 = 0x20;
pub const key_phase_bit: u8 = 0x04;

/// §17.1: the packet number is one to four bytes on the wire.
pub const max_pn_len = 4;
/// §17.2.5.1 and §21: 16 bytes of AEAD tag, so a protected packet cannot be
/// shorter than this plus its header.
pub const retry_integrity_tag_len = 16;

pub const Error = error{
    /// Fewer bytes than the header requires.
    PacketTruncated,
    /// §17.2: the Fixed Bit is zero on a packet that must have it set.
    PacketFixedBitClear,
    /// §17.2: a connection ID longer than 20 bytes in version 1.
    ConnectionIdTooLong,
    /// A length field that runs past the end of the datagram.
    PacketLengthInvalid,
    /// §17.2: a long header whose type reserves bits that must be zero, or a
    /// packet too short to hold what its form requires.
    PacketMalformed,
} || varint.Error;

/// A Retry packet (§17.2.5) carries no packet number and is not protected; its
/// integrity comes from a tag over the whole thing.
pub const Retry = struct {
    version: Version,
    destination: ConnectionId,
    source: ConnectionId,
    token: []const u8,
    integrity_tag: *const [retry_integrity_tag_len]u8,
};

/// A Version Negotiation packet (§17.2.1) is identified by version 0 and is not
/// protected either. Its version list is raw bytes because it may contain
/// values this implementation has no name for, which is the point of it.
pub const VersionNegotiation = struct {
    destination: ConnectionId,
    source: ConnectionId,
    versions: []const u8,

    pub fn count(self: VersionNegotiation) usize {
        return self.versions.len / 4;
    }

    pub fn get(self: VersionNegotiation, index: usize) Version {
        assert(index < self.count());
        return @fromBackingInt(@intCast(std.mem.readInt(u32, self.versions[index * 4 ..][0..4], .big)));
    }

    pub fn offers(self: VersionNegotiation, wanted: Version) bool {
        for (0..self.count()) |i| if (self.get(i) == wanted) return true;
        return false;
    }
};

/// A packet whose payload is protected, so its packet number is not readable
/// yet. Covers Initial, 0-RTT, Handshake and 1-RTT.
pub const Protected = struct {
    /// Null for a 1-RTT packet, which has no type field: a short header is
    /// always 1-RTT in version 1.
    long_type: ?LongType,
    version: Version,
    destination: ConnectionId,
    /// Empty for a short header, which carries no source connection ID.
    source: ConnectionId,
    /// Only an Initial packet has one (§17.2.2). Empty is normal and means the
    /// client has not been given a token.
    token: []const u8,
    /// Offset within the datagram of the packet number field, which is where
    /// header protection starts and, four bytes later, where its sample comes
    /// from (RFC 9001 §5.4.2).
    pn_offset: usize,
    /// Packet number plus payload: exactly what the Length field covers for a
    /// long header, and the rest of the datagram for a short one.
    remainder_len: usize,

    pub fn space(self: Protected) NumberSpace {
        const long = self.long_type orelse return .application;
        return switch (long) {
            .initial => .initial,
            .handshake => .handshake,
            // §12.3: 0-RTT and 1-RTT share a number space.
            .zero_rtt => .application,
            .retry => unreachable, // Retry is not a Protected packet.
        };
    }
};

pub const Packet = union(enum) {
    protected: Protected,
    retry: Retry,
    version_negotiation: VersionNegotiation,
};

pub const Parsed = struct {
    packet: Packet,
    /// One past the last byte of this packet within the datagram. §12.2 allows
    /// coalescing, so the caller continues from here.
    end: usize,
};

/// Parse one packet from the front of `datagram`.
///
/// `local_cid_len` is how long the connection IDs this endpoint issues are. It
/// is needed only for short headers, which do not carry it, and it must be the
/// same value used when the connection ID was chosen — see the module comment.
pub fn parse(datagram: []const u8, local_cid_len: u8) Error!Parsed {
    assert(local_cid_len <= max_cid_len);
    if (datagram.len < 1) return error.PacketTruncated;

    const first = datagram[0];
    if (first & header_form_bit != 0) return parseLong(datagram);
    return parseShort(datagram, local_cid_len);
}

fn parseLong(datagram: []const u8) Error!Parsed {
    // §17.2: first byte, then a four-byte version, then two length-prefixed
    // connection IDs. The version comes before the connection IDs precisely so
    // that a packet of an unknown version can still be answered: §5.2.1 says an
    // endpoint uses those IDs without understanding anything else.
    if (datagram.len < 1 + 4 + 1) return error.PacketTruncated;

    const first = datagram[0];
    const version: Version = @fromBackingInt(@intCast(std.mem.readInt(u32, datagram[1..5], .big)));

    var pos: usize = 5;
    const destination = try takeCid(datagram, &pos);
    const source = try takeCid(datagram, &pos);

    // §17.2.1: version 0 means Version Negotiation, and its Fixed Bit is
    // unused — so this test must come before the Fixed Bit check, not after.
    if (version == .negotiation) {
        const versions = datagram[pos..];
        // §17.2.1 requires at least one version, and a partial one is malformed.
        if (versions.len == 0 or versions.len % 4 != 0) return error.PacketMalformed;
        return .{
            .packet = .{ .version_negotiation = .{
                .destination = destination,
                .source = source,
                .versions = versions,
            } },
            // A Version Negotiation packet is never coalesced with anything.
            .end = datagram.len,
        };
    }

    if (first & fixed_bit == 0) return error.PacketFixedBitClear;

    const long_type: LongType = @fromBackingInt(@intCast(@as(u2, @truncate(first >> 4))));
    if (long_type == .retry) {
        // §17.2.5: everything after the connection IDs is token, except a
        // trailing 16-byte integrity tag.
        if (datagram.len < pos + retry_integrity_tag_len) return error.PacketTruncated;
        const tag_start = datagram.len - retry_integrity_tag_len;
        return .{
            .packet = .{ .retry = .{
                .version = version,
                .destination = destination,
                .source = source,
                .token = datagram[pos..tag_start],
                .integrity_tag = datagram[tag_start..][0..retry_integrity_tag_len],
            } },
            .end = datagram.len,
        };
    }

    var token: []const u8 = &.{};
    if (long_type == .initial) {
        // §17.2.2: only Initial packets carry a token, and only a client's is
        // ever non-empty in practice — a server's Initial has a zero length.
        var rest = datagram[pos..];
        token = try varint.takeBytes(&rest);
        pos = datagram.len - rest.len;
    }

    // §17.2: the Length field covers the packet number and the payload, and
    // nothing else. That is what makes coalescing possible.
    var rest = datagram[pos..];
    const length = try varint.take(&rest);
    pos = datagram.len - rest.len;
    if (length > rest.len) return error.PacketLengthInvalid;

    // The packet number is at least one byte, and RFC 9001 §5.4.2 needs four
    // bytes of sample starting after a notional four-byte packet number, so a
    // protected packet shorter than 4 + 16 cannot be unprotected at all.
    if (length < max_pn_len + retry_integrity_tag_len) return error.PacketMalformed;

    return .{
        .packet = .{ .protected = .{
            .long_type = long_type,
            .version = version,
            .destination = destination,
            .source = source,
            .token = token,
            .pn_offset = pos,
            .remainder_len = @intCast(length),
        } },
        .end = pos + @as(usize, @intCast(length)),
    };
}

fn parseShort(datagram: []const u8, local_cid_len: u8) Error!Parsed {
    // §17.3: first byte, destination connection ID of locally known length,
    // then the packet number and payload with no length field — so a short
    // header packet runs to the end of the datagram and is always last.
    const pn_offset = 1 + @as(usize, local_cid_len);
    if (datagram.len < pn_offset) return error.PacketTruncated;
    if (datagram[0] & fixed_bit == 0) return error.PacketFixedBitClear;

    const remainder_len = datagram.len - pn_offset;
    if (remainder_len < max_pn_len + retry_integrity_tag_len) return error.PacketMalformed;

    return .{
        .packet = .{ .protected = .{
            .long_type = null,
            .version = .v1,
            .destination = try ConnectionId.init(datagram[1..pn_offset]),
            .source = .empty,
            .token = &.{},
            .pn_offset = pn_offset,
            .remainder_len = remainder_len,
        } },
        .end = datagram.len,
    };
}

fn takeCid(datagram: []const u8, pos: *usize) Error!ConnectionId {
    if (pos.* >= datagram.len) return error.PacketTruncated;
    const len = datagram[pos.*];
    pos.* += 1;
    if (len > max_cid_len) return error.ConnectionIdTooLong;
    if (pos.* + len > datagram.len) return error.PacketTruncated;
    const cid = try ConnectionId.init(datagram[pos.*..][0..len]);
    pos.* += len;
    return cid;
}

/// The number of bytes needed to encode `pn` given that everything up to
/// `largest_acked` has been acknowledged (§17.1 and §A.2).
///
/// The rule is not "as few as fit": it is that the range of unacknowledged
/// packet numbers must fit in *half* the space the encoded length can express,
/// because the decoder resolves ambiguity by picking the nearest candidate. Two
/// times the outstanding range is the requirement.
pub fn packetNumberLen(pn: u64, largest_acked: ?u64) u4 {
    const range = if (largest_acked) |acked| blk: {
        assert(pn > acked);
        break :blk (pn - acked) * 2;
    } else pn + 1;

    if (range < (1 << 8)) return 1;
    if (range < (1 << 16)) return 2;
    if (range < (1 << 24)) return 3;
    return 4;
}

/// Write the low `len` bytes of `pn`, big endian (§17.1).
pub fn encodePacketNumber(dest: []u8, pn: u64, len: u4) void {
    assert(len >= 1 and len <= max_pn_len);
    assert(dest.len >= len);
    // The shift is computed in usize, not u4: `(len - 1 - i) * 8` reaches 24 for
    // a four-byte packet number, which overflows the u4 the loop counter would
    // otherwise impose. In Debug that panics; in ReleaseFast it wraps silently and
    // writes the wrong packet number, so the peer builds the wrong AEAD nonce, the
    // packet fails to authenticate and is discarded — indistinguishable from
    // ordinary loss, which is the same failure mode `decodePacketNumber` is
    // written so carefully to avoid.
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const shift: u6 = @intCast((@as(usize, len) - 1 - i) * 8);
        dest[i] = @truncate(pn >> shift);
    }
}

/// Reconstruct a full packet number from its truncated form (§A.3).
///
/// This is the algorithm from Appendix A.3, transcribed rather than invented,
/// because getting it wrong is close to undetectable: a mis-reconstructed
/// packet number produces the wrong AEAD nonce, the packet fails to
/// authenticate, and it is discarded — which looks exactly like packet loss.
/// A connection would work, slowly and inexplicably, on a lossy path.
///
/// `largest_acked` is the largest packet number *successfully processed* in
/// this number space, or null if none has been.
pub fn decodePacketNumber(largest: ?u64, truncated: u64, len: u4) u64 {
    assert(len >= 1 and len <= max_pn_len);
    const bits: u6 = @intCast(@as(u8, len) * 8);

    // The RFC's pseudocode assumes unbounded integers, and two of its
    // comparisons underflow at the start of a connection where expected is
    // small and the half window is large. Signed arithmetic wide enough for
    // both is the transcription that keeps its meaning.
    const expected: i128 = @as(i128, if (largest) |l| l + 1 else 0);
    const win: i128 = @as(i128, 1) << bits;
    const hwin = @divExact(win, 2);
    const mask = win - 1;

    const candidate: i128 = (expected & ~mask) | @as(i128, @intCast(truncated));

    if (candidate <= expected - hwin and candidate < (@as(i128, 1) << 62) - win) {
        return @intCast(candidate + win);
    }
    if (candidate > expected + hwin and candidate >= win) {
        return @intCast(candidate - win);
    }
    return @intCast(candidate);
}

const testing = std.testing;

test "packet: connection ids of every legal length, including zero" {
    const zero = try ConnectionId.init(&.{});
    try testing.expectEqual(@as(usize, 0), zero.slice().len);
    try testing.expect(zero.eql(&ConnectionId.empty));

    var longest: [max_cid_len]u8 = undefined;
    for (&longest, 0..) |*b, i| b.* = @intCast(i);
    const cid = try ConnectionId.init(&longest);
    try testing.expectEqualSlices(u8, &longest, cid.slice());

    var too_long: [max_cid_len + 1]u8 = @splat(0);
    try testing.expectError(error.ConnectionIdTooLong, ConnectionId.init(&too_long));
}

test "packet: appendix A.3 packet number decoding" {
    // The worked example from §A.3.
    try testing.expectEqual(
        @as(u64, 0xa82f9b32),
        decodePacketNumber(0xa82f30ea, 0x9b32, 2),
    );
}

test "packet: a truncated number resolves to the nearest candidate either way" {
    // Forward across a byte boundary: largest 0xff, truncated 0x00 must mean
    // 0x100 rather than 0x00, because 0x100 is nearer to the expected 0x100.
    try testing.expectEqual(@as(u64, 0x100), decodePacketNumber(0xff, 0x00, 1));

    // Backward: a reordered packet from before the window's start. Expected is
    // 0x101, and 0xff is nearer than 0x1ff.
    try testing.expectEqual(@as(u64, 0xff), decodePacketNumber(0x100, 0xff, 1));

    // At the very start of a connection nothing has been processed, so the
    // expected number is zero. This is the case whose intermediate value
    // underflows if the arithmetic is unsigned.
    try testing.expectEqual(@as(u64, 0), decodePacketNumber(null, 0, 1));
    try testing.expectEqual(@as(u64, 7), decodePacketNumber(null, 7, 1));
}

test "packet: encode then decode every packet number across a wide range" {
    var largest: ?u64 = null;
    var pn: u64 = 0;
    while (pn < 70000) : (pn += 1) {
        const len = packetNumberLen(pn, largest);
        var buf: [max_pn_len]u8 = undefined;
        encodePacketNumber(&buf, pn, len);

        var truncated: u64 = 0;
        for (buf[0..len]) |byte| truncated = (truncated << 8) | byte;

        try testing.expectEqual(pn, decodePacketNumber(largest, truncated, len));
        largest = pn;
    }
}

test "packet: the length chosen covers twice the unacknowledged range" {
    // §A.2: with everything up to 0xabe8b3 acknowledged, sending 0xac5c02
    // needs two bytes, because twice the gap still fits in sixteen bits.
    try testing.expectEqual(@as(u4, 2), packetNumberLen(0xac5c02, 0xabe8b3));
    // And with a wider gap, three.
    try testing.expectEqual(@as(u4, 3), packetNumberLen(0xace8fe, 0xabe8b3));
}

test "packet: a long header Initial, parsed field by field" {
    // Built by hand rather than round-tripped, so that a mistake in the writer
    // cannot hide a matching mistake in the parser.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const gpa = testing.allocator;

    try buf.append(gpa, header_form_bit | fixed_bit | (0 << 4) | 0x03); // Initial, pn_len bits set
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 }); // version 1
    try buf.append(gpa, 4); // dcid len
    try buf.appendSlice(gpa, &.{ 0xde, 0xad, 0xbe, 0xef });
    try buf.append(gpa, 2); // scid len
    try buf.appendSlice(gpa, &.{ 0xca, 0xfe });
    try buf.append(gpa, 0x03); // token length 3, one-byte varint
    try buf.appendSlice(gpa, &.{ 0x11, 0x22, 0x33 });

    const payload_len = 24; // at least max_pn_len + tag
    var len_buf: [8]u8 = undefined;
    const len_written = varint.encode(&len_buf, payload_len);
    try buf.appendSlice(gpa, len_buf[0..len_written]);
    const pn_offset = buf.items.len;
    try buf.appendNTimes(gpa, 0xaa, payload_len);

    const parsed = try parse(buf.items, 4);
    try testing.expectEqual(buf.items.len, parsed.end);

    const p = parsed.packet.protected;
    try testing.expectEqual(LongType.initial, p.long_type.?);
    try testing.expectEqual(Version.v1, p.version);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, p.destination.slice());
    try testing.expectEqualSlices(u8, &.{ 0xca, 0xfe }, p.source.slice());
    try testing.expectEqualSlices(u8, &.{ 0x11, 0x22, 0x33 }, p.token);
    try testing.expectEqual(pn_offset, p.pn_offset);
    try testing.expectEqual(@as(usize, payload_len), p.remainder_len);
    try testing.expectEqual(NumberSpace.initial, p.space());
}

test "packet: a short header takes its connection id length from local knowledge" {
    // The same bytes parse into different packets depending on the length this
    // endpoint issues, which is exactly why it is a parameter. Nothing on the
    // wire distinguishes them.
    var datagram: [40]u8 = @splat(0x55);
    datagram[0] = fixed_bit;

    const with_four = try parse(&datagram, 4);
    try testing.expectEqual(@as(usize, 5), with_four.packet.protected.pn_offset);
    try testing.expectEqualSlices(u8, datagram[1..5], with_four.packet.protected.destination.slice());

    const with_eight = try parse(&datagram, 8);
    try testing.expectEqual(@as(usize, 9), with_eight.packet.protected.pn_offset);
    try testing.expectEqual(@as(usize, 8), with_eight.packet.protected.destination.len);

    // A short header is 1-RTT and shares the application number space.
    try testing.expectEqual(NumberSpace.application, with_four.packet.protected.space());
    try testing.expect(with_four.packet.protected.long_type == null);
}

test "packet: two packets coalesced in one datagram" {
    // §12.2. A handshake normally does this, and a parser that assumes one
    // packet per datagram drops the second silently.
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    // An Initial with a 20-byte remainder.
    try buf.append(gpa, header_form_bit | fixed_bit | (0 << 4));
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 });
    try buf.append(gpa, 0); // empty dcid
    try buf.append(gpa, 0); // empty scid
    try buf.append(gpa, 0); // empty token
    try buf.append(gpa, 20); // length, one-byte varint
    try buf.appendNTimes(gpa, 0xbb, 20);
    const first_end = buf.items.len;

    // A Handshake packet after it.
    try buf.append(gpa, header_form_bit | fixed_bit | (2 << 4));
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 });
    try buf.append(gpa, 0);
    try buf.append(gpa, 0);
    try buf.append(gpa, 22);
    try buf.appendNTimes(gpa, 0xcc, 22);

    const first = try parse(buf.items, 0);
    try testing.expectEqual(first_end, first.end);
    try testing.expectEqual(LongType.initial, first.packet.protected.long_type.?);

    const second = try parse(buf.items[first.end..], 0);
    try testing.expectEqual(buf.items.len - first_end, second.end);
    try testing.expectEqual(LongType.handshake, second.packet.protected.long_type.?);
    try testing.expectEqual(NumberSpace.handshake, second.packet.protected.space());
}

test "packet: a Version Negotiation packet is recognised despite a clear fixed bit" {
    // §17.2.1: the Fixed Bit is unused here. Checking it before looking at the
    // version would reject the one packet that tells us our version is wrong —
    // and the failure mode is a connection that cannot even learn why.
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    try buf.append(gpa, header_form_bit); // no fixed bit
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x00 }); // version 0
    try buf.append(gpa, 2);
    try buf.appendSlice(gpa, &.{ 0xaa, 0xbb });
    try buf.append(gpa, 0);
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 }); // offers v1
    try buf.appendSlice(gpa, &.{ 0x0a, 0x0a, 0x0a, 0x0a }); // and a grease value

    const parsed = try parse(buf.items, 0);
    const vn = parsed.packet.version_negotiation;
    try testing.expectEqual(@as(usize, 2), vn.count());
    try testing.expect(vn.offers(.v1));
    try testing.expect(vn.offers(.grease));
    try testing.expect(!vn.offers(@fromBackingInt(@intCast(0xdeadbeef))));
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, vn.destination.slice());
}

test "packet: a Retry packet ends in its integrity tag and has no packet number" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    try buf.append(gpa, header_form_bit | fixed_bit | (3 << 4));
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 });
    try buf.append(gpa, 0);
    try buf.append(gpa, 3);
    try buf.appendSlice(gpa, &.{ 0x01, 0x02, 0x03 });
    try buf.appendSlice(gpa, "opaque token");
    try buf.appendNTimes(gpa, 0x77, retry_integrity_tag_len);

    const parsed = try parse(buf.items, 0);
    const retry = parsed.packet.retry;
    try testing.expectEqualStrings("opaque token", retry.token);
    const expected_tag: [retry_integrity_tag_len]u8 = @splat(0x77);
    try testing.expectEqualSlices(u8, &expected_tag, retry.integrity_tag);
}

test "packet: a clear fixed bit is refused on a version 1 packet" {
    var datagram: [40]u8 = @splat(0);
    datagram[0] = header_form_bit; // long header, no fixed bit
    std.mem.writeInt(u32, datagram[1..5], 1, .big); // version 1, so not negotiation
    try testing.expectError(error.PacketFixedBitClear, parse(&datagram, 0));

    var short: [40]u8 = @splat(0x55);
    short[0] = 0; // short header, no fixed bit
    try testing.expectError(error.PacketFixedBitClear, parse(&short, 4));
}

test "packet: a length field past the end of the datagram is refused" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    try buf.append(gpa, header_form_bit | fixed_bit | (2 << 4));
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 });
    try buf.append(gpa, 0);
    try buf.append(gpa, 0);
    try buf.append(gpa, 100); // claims 100 bytes
    try buf.appendNTimes(gpa, 0xdd, 10); // provides 10

    try testing.expectError(error.PacketLengthInvalid, parse(buf.items, 0));
}

test "packet: a truncated header is refused rather than read past" {
    // Every prefix of a valid packet must fail cleanly. This is the cheap
    // version of what the fuzzer will do later, and it runs on every build.
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    try buf.append(gpa, header_form_bit | fixed_bit);
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 });
    try buf.append(gpa, 8);
    try buf.appendSlice(gpa, &.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try buf.append(gpa, 0);
    try buf.append(gpa, 0);
    try buf.append(gpa, 30);
    try buf.appendNTimes(gpa, 0xee, 30);

    _ = try parse(buf.items, 0); // the whole thing is valid

    for (0..buf.items.len) |cut| {
        _ = parse(buf.items[0..cut], 0) catch continue;
        // Some prefixes are legitimately parseable, because the length field
        // describes a shorter packet than we built; the requirement is only
        // that none of them crash or read past the slice.
    }
}

test "packet: a protected packet too short to unprotect is refused" {
    // RFC 9001 §5.4.2 samples four bytes starting after a notional four-byte
    // packet number, so fewer than 20 bytes of remainder cannot be unprotected.
    // Accepting it here would push the failure into a slice out of bounds later.
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    try buf.append(gpa, header_form_bit | fixed_bit | (2 << 4));
    try buf.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x01 });
    try buf.append(gpa, 0);
    try buf.append(gpa, 0);
    try buf.append(gpa, 19); // one short of the minimum
    try buf.appendNTimes(gpa, 0xff, 19);

    try testing.expectError(error.PacketMalformed, parse(buf.items, 0));
}

test "packet: a packet number round trips at every encoded length" {
    // This test exists because its absence hid a real defect: `encodePacketNumber`
    // computed its shift in u4, which overflows at 24 — so any three- or four-byte
    // packet number was written wrong. Nothing caught it, because the Appendix A.3
    // vectors exercise the *decode* path and the encode path had only ever been
    // asked for one- and two-byte numbers.
    //
    // The symptom would have been silent: a wrong packet number means a wrong AEAD
    // nonce, so the peer discards the packet exactly as though the network had
    // dropped it.
    const cases = [_]u64{
        0,          1,        0x7f,      0xff,
        0x100,      0x1234,   0xffff,    0x10000,
        0xabcdef,   0xffffff, 0x1000000, 0xdeadbeef,
        0xffffffff,
        0xac5c02, // Appendix A.3's packet number
        654360564, // Appendix A.5's
    };

    for (cases) |pn| {
        var len: u4 = 1;
        while (len <= max_pn_len) : (len += 1) {
            var buf: [max_pn_len]u8 = @splat(0);
            encodePacketNumber(buf[0..len], pn, len);

            // The encoded bytes are the low `len` bytes of the number, big endian.
            var expected: u64 = 0;
            for (buf[0..len]) |byte| expected = (expected << 8) | byte;
            const mask: u64 = if (len == 8) std.math.maxInt(u64) else (@as(u64, 1) << (@as(u6, len) * 8)) - 1;
            try std.testing.expectEqual(pn & mask, expected);

            // And a receiver expecting a number near this one reconstructs it.
            // §17.1's whole point: the truncated form is unambiguous within its
            // window, so a decoder primed with the previous number gets it back.
            const largest: ?u64 = if (pn == 0) null else pn - 1;
            try std.testing.expectEqual(pn, decodePacketNumber(largest, expected, len));
        }
    }
}
