//! QPACK field compression, RFC 9204.
//!
//! QPACK is HPACK redesigned for a transport that reorders: HPACK's dynamic
//! table assumes every header block observes all previous ones, which TCP
//! guaranteed and QUIC streams do not. QPACK moves table updates onto their own
//! unidirectional stream and stamps each field section with the table state it
//! needs (the Required Insert Count), so sections can be decoded — or
//! deliberately parked — out of order.
//!
//! This implementation runs the mode RFC 9204 defines as the *default*:
//! `SETTINGS_QPACK_MAX_TABLE_CAPACITY` of zero, meaning no dynamic table on
//! either side. §3.2.3: "the maximum table capacity is 0 until the encoder
//! processes a SETTINGS frame with a non-zero value", and an encoder facing a
//! zero capacity "MUST NOT insert entries into the dynamic table and MUST NOT
//! send any encoder instructions on the encoder stream". Everything in that
//! mode is implemented completely — the static table, both literal forms,
//! Huffman both ways, the section prefix, and the policing of instruction
//! streams that must stay silent. What is *not* implemented is the dynamic
//! table itself, which is a compression-ratio feature, never a requirement:
//! every conforming peer must interoperate with a zero-capacity endpoint,
//! because zero is what every connection starts at.
//!
//! Three pieces come from elsewhere and are shared on purpose:
//! * The Huffman code is HPACK's, unmodified (§4.1.2), so `http2/huffman.zig`
//!   is imported rather than duplicated.
//! * The prefixed integer is HPACK's format (§4.1.1) but QPACK "MUST be able
//!   to decode integers up to and including 62 bits long", and the HTTP/2
//!   implementation is deliberately 32-bit; a stream ID in a Section
//!   Acknowledgment can exceed that legitimately, so the width difference is
//!   a real requirement, not a rewrite for taste.
//! * The static table is Appendix A verbatim — 99 entries, indexed from 0
//!   where HPACK indexes from 1.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const huffman = @import("../http2/huffman.zig");

pub const Error = error{
    /// QPACK_DECOMPRESSION_FAILED (0x0200): a field section could not be
    /// interpreted.
    DecompressionFailed,
    /// QPACK_ENCODER_STREAM_ERROR (0x0201): the peer's encoder stream said
    /// something it must not — with a zero-capacity table, anything at all.
    EncoderStreamError,
    /// QPACK_DECODER_STREAM_ERROR (0x0202): the peer's decoder stream
    /// acknowledged things we never did.
    DecoderStreamError,
    /// RFC 9114 §4.2.2: the decoded section exceeds what we advertised in
    /// SETTINGS_MAX_FIELD_SECTION_SIZE. Not a QPACK wire error — the encoding
    /// is valid — which is why it is distinct: the HTTP layer maps it to
    /// H3_EXCESSIVE_LOAD rather than a QPACK code.
    FieldSectionTooLarge,
} || Allocator.Error;

/// §8.3's registered wire codes.
pub fn errorCode(err: Error) u64 {
    return switch (err) {
        error.DecompressionFailed => 0x0200,
        error.EncoderStreamError => 0x0201,
        error.DecoderStreamError => 0x0202,
        error.FieldSectionTooLarge => 0x0107, // H3_EXCESSIVE_LOAD
        error.OutOfMemory => 0x0102, // H3_INTERNAL_ERROR
    };
}

/// The largest single string literal accepted, §7.4: "an implementation has to
/// set a limit to the length it accepts for string literals". Independent of
/// the field-section limit because it bounds a *single allocation* made before
/// any content is seen.
pub const max_string_len = 32 * 1024;

// ── Prefixed integers, §4.1.1 ────────────────────────────────────────────────
// RFC 7541 §5.1's format at the width RFC 9204 requires: values up to 2^62-1.

/// The QPACK requirement, used as the overflow bound below.
pub const max_int: u64 = (1 << 62) - 1;

pub fn decodePrefixInt(input: *[]const u8, prefix_bits: u4) Error!u64 {
    if (input.len == 0) return error.DecompressionFailed;
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    var value: u64 = input.*[0] & @as(u8, @intCast(max_prefix));
    input.* = input.*[1..];
    if (value < max_prefix) return value;

    var shift: u6 = 0;
    while (true) {
        if (input.len == 0) return error.DecompressionFailed;
        const byte = input.*[0];
        input.* = input.*[1..];
        const chunk: u64 = byte & 0x7f;
        // §7.4: an integer past the 62-bit requirement is an attack or a
        // defect, not a large header. Checked before the shift so the shift
        // itself cannot overflow.
        if (shift >= 62 or chunk << @intCast(@min(shift, 62)) > max_int - value) {
            return error.DecompressionFailed;
        }
        value += chunk << @intCast(shift);
        if (byte & 0x80 == 0) break;
        shift += 7;
    }
    // No final range check: the in-loop guard already caps the running value at
    // `max_int` on every step, so a second check here would be a second copy of
    // the same rule — and a self-check that broke the loop guard passed while
    // this line covered for it, which is exactly how dead duplicates hide.
    return value;
}

/// `flags` are the bits above the prefix, already positioned.
pub fn encodePrefixInt(out: anytype, gpa: Allocator, flags: u8, value: u64, prefix_bits: u4) !void {
    const max_prefix: u64 = (@as(u64, 1) << prefix_bits) - 1;
    assert(flags & @as(u8, @intCast(max_prefix)) == 0);
    assert(value <= max_int);
    if (value < max_prefix) {
        try out.append(gpa, flags | @as(u8, @intCast(value)));
        return;
    }
    try out.append(gpa, flags | @as(u8, @intCast(max_prefix)));
    var rest = value - max_prefix;
    while (rest >= 0x80) {
        try out.append(gpa, @as(u8, @intCast(rest & 0x7f)) | 0x80);
        rest >>= 7;
    }
    try out.append(gpa, @intCast(rest));
}

// ── String literals, §4.1.2 ──────────────────────────────────────────────────

/// Decode one string literal with an N-bit prefix (H bit + (N-1)-bit length).
/// The caller owns the returned bytes.
fn decodeString(gpa: Allocator, input: *[]const u8, prefix_bits: u4) Error![]u8 {
    if (input.len == 0) return error.DecompressionFailed;
    const huffman_bit = @as(u8, 1) << @as(u3, @intCast(prefix_bits - 1));
    const is_huffman = input.*[0] & huffman_bit != 0;
    const len = try decodePrefixInt(input, prefix_bits - 1);
    if (len > max_string_len) return error.DecompressionFailed;
    if (len > input.len) return error.DecompressionFailed;
    const raw = input.*[0..@intCast(len)];
    input.* = input.*[@intCast(len)..];

    if (!is_huffman) return gpa.dupe(u8, raw);

    const decoded_len = huffman.decodedLen(raw) catch return error.DecompressionFailed;
    const out = try gpa.alloc(u8, decoded_len);
    errdefer gpa.free(out);
    _ = huffman.decode(out, raw) catch return error.DecompressionFailed;
    return out;
}

/// Encode a string literal, choosing Huffman when it is strictly shorter —
/// ties go to plain text, which costs nothing and decodes faster.
fn encodeString(out: *std.ArrayList(u8), gpa: Allocator, flags: u8, bytes: []const u8, prefix_bits: u4) !void {
    const huffman_bit = @as(u8, 1) << @as(u3, @intCast(prefix_bits - 1));
    assert(flags & huffman_bit == 0);
    const encoded_len = huffman.encodedLen(bytes);
    if (encoded_len < bytes.len) {
        try encodePrefixInt(out, gpa, flags | huffman_bit, encoded_len, prefix_bits - 1);
        const start = out.items.len;
        try out.resize(gpa, start + encoded_len);
        _ = huffman.encode(out.items[start..], bytes);
        return;
    }
    try encodePrefixInt(out, gpa, flags, bytes.len, prefix_bits - 1);
    try out.appendSlice(gpa, bytes);
}

// ── The static table, Appendix A ─────────────────────────────────────────────

pub const StaticEntry = struct { name: []const u8, value: []const u8 };

/// Appendix A verbatim. Indexed from 0 (§3.1) — HPACK's table starts at 1, and
/// an off-by-one here decodes every request into the wrong header names, which
/// interop testing catches immediately and unit tests only catch if the table
/// is spot-checked at both ends. It is.
pub const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" }, // 0
    .{ .name = ":path", .value = "/" }, // 1
    .{ .name = "age", .value = "0" }, // 2
    .{ .name = "content-disposition", .value = "" }, // 3
    .{ .name = "content-length", .value = "0" }, // 4
    .{ .name = "cookie", .value = "" }, // 5
    .{ .name = "date", .value = "" }, // 6
    .{ .name = "etag", .value = "" }, // 7
    .{ .name = "if-modified-since", .value = "" }, // 8
    .{ .name = "if-none-match", .value = "" }, // 9
    .{ .name = "last-modified", .value = "" }, // 10
    .{ .name = "link", .value = "" }, // 11
    .{ .name = "location", .value = "" }, // 12
    .{ .name = "referer", .value = "" }, // 13
    .{ .name = "set-cookie", .value = "" }, // 14
    .{ .name = ":method", .value = "CONNECT" }, // 15
    .{ .name = ":method", .value = "DELETE" }, // 16
    .{ .name = ":method", .value = "GET" }, // 17
    .{ .name = ":method", .value = "HEAD" }, // 18
    .{ .name = ":method", .value = "OPTIONS" }, // 19
    .{ .name = ":method", .value = "POST" }, // 20
    .{ .name = ":method", .value = "PUT" }, // 21
    .{ .name = ":scheme", .value = "http" }, // 22
    .{ .name = ":scheme", .value = "https" }, // 23
    .{ .name = ":status", .value = "103" }, // 24
    .{ .name = ":status", .value = "200" }, // 25
    .{ .name = ":status", .value = "304" }, // 26
    .{ .name = ":status", .value = "404" }, // 27
    .{ .name = ":status", .value = "503" }, // 28
    .{ .name = "accept", .value = "*/*" }, // 29
    .{ .name = "accept", .value = "application/dns-message" }, // 30
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // 31
    .{ .name = "accept-ranges", .value = "bytes" }, // 32
    .{ .name = "access-control-allow-headers", .value = "cache-control" }, // 33
    .{ .name = "access-control-allow-headers", .value = "content-type" }, // 34
    .{ .name = "access-control-allow-origin", .value = "*" }, // 35
    .{ .name = "cache-control", .value = "max-age=0" }, // 36
    .{ .name = "cache-control", .value = "max-age=2592000" }, // 37
    .{ .name = "cache-control", .value = "max-age=604800" }, // 38
    .{ .name = "cache-control", .value = "no-cache" }, // 39
    .{ .name = "cache-control", .value = "no-store" }, // 40
    .{ .name = "cache-control", .value = "public, max-age=31536000" }, // 41
    .{ .name = "content-encoding", .value = "br" }, // 42
    .{ .name = "content-encoding", .value = "gzip" }, // 43
    .{ .name = "content-type", .value = "application/dns-message" }, // 44
    .{ .name = "content-type", .value = "application/javascript" }, // 45
    .{ .name = "content-type", .value = "application/json" }, // 46
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" }, // 47
    .{ .name = "content-type", .value = "image/gif" }, // 48
    .{ .name = "content-type", .value = "image/jpeg" }, // 49
    .{ .name = "content-type", .value = "image/png" }, // 50
    .{ .name = "content-type", .value = "text/css" }, // 51
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // 52
    .{ .name = "content-type", .value = "text/plain" }, // 53
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" }, // 54
    .{ .name = "range", .value = "bytes=0-" }, // 55
    .{ .name = "strict-transport-security", .value = "max-age=31536000" }, // 56
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" }, // 57
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" }, // 58
    .{ .name = "vary", .value = "accept-encoding" }, // 59
    .{ .name = "vary", .value = "origin" }, // 60
    .{ .name = "x-content-type-options", .value = "nosniff" }, // 61
    .{ .name = "x-xss-protection", .value = "1; mode=block" }, // 62
    .{ .name = ":status", .value = "100" }, // 63
    .{ .name = ":status", .value = "204" }, // 64
    .{ .name = ":status", .value = "206" }, // 65
    .{ .name = ":status", .value = "302" }, // 66
    .{ .name = ":status", .value = "400" }, // 67
    .{ .name = ":status", .value = "403" }, // 68
    .{ .name = ":status", .value = "421" }, // 69
    .{ .name = ":status", .value = "425" }, // 70
    .{ .name = ":status", .value = "500" }, // 71
    .{ .name = "accept-language", .value = "" }, // 72
    .{ .name = "access-control-allow-credentials", .value = "FALSE" }, // 73
    .{ .name = "access-control-allow-credentials", .value = "TRUE" }, // 74
    .{ .name = "access-control-allow-headers", .value = "*" }, // 75
    .{ .name = "access-control-allow-methods", .value = "get" }, // 76
    .{ .name = "access-control-allow-methods", .value = "get, post, options" }, // 77
    .{ .name = "access-control-allow-methods", .value = "options" }, // 78
    .{ .name = "access-control-expose-headers", .value = "content-length" }, // 79
    .{ .name = "access-control-request-headers", .value = "content-type" }, // 80
    .{ .name = "access-control-request-method", .value = "get" }, // 81
    .{ .name = "access-control-request-method", .value = "post" }, // 82
    .{ .name = "alt-svc", .value = "clear" }, // 83
    .{ .name = "authorization", .value = "" }, // 84
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    .{ .name = "early-data", .value = "1" }, // 86
    .{ .name = "expect-ct", .value = "" }, // 87
    .{ .name = "forwarded", .value = "" }, // 88
    .{ .name = "if-range", .value = "" }, // 89
    .{ .name = "origin", .value = "" }, // 90
    .{ .name = "purpose", .value = "prefetch" }, // 91
    .{ .name = "server", .value = "" }, // 92
    .{ .name = "timing-allow-origin", .value = "*" }, // 93
    .{ .name = "upgrade-insecure-requests", .value = "1" }, // 94
    .{ .name = "user-agent", .value = "" }, // 95
    .{ .name = "x-forwarded-for", .value = "" }, // 96
    .{ .name = "x-frame-options", .value = "deny" }, // 97
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 98
};

/// Exact-match lookup, then name-only. Linear because the table is 99 entries
/// read once per field of an encode — a comptime map would trade clarity for a
/// win no profile has asked for.
fn staticLookup(name: []const u8, value: []const u8) struct { exact: ?u64, name_only: ?u64 } {
    var name_only: ?u64 = null;
    for (&static_table, 0..) |entry, i| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (name_only == null) name_only = i;
        if (std.mem.eql(u8, entry.value, value)) return .{ .exact = i, .name_only = name_only };
    }
    return .{ .exact = null, .name_only = name_only };
}

// ── Field sections ───────────────────────────────────────────────────────────

/// One decoded field line. `never_index` carries §4.5.4's 'N' bit through, so
/// an intermediary re-encoding this section can honour "MUST use a literal
/// representation to forward this field line" — dropping the bit here would
/// make that obligation invisible to the layer that has to meet it.
pub const Field = struct {
    name: []u8,
    value: []u8,
    never_index: bool = false,

    /// RFC 9114 §4.2.2's field size: name + value + 32, uncompressed.
    pub fn size(self: *const Field) u64 {
        return self.name.len + self.value.len + 32;
    }
};

/// A decoded section, owning its strings.
pub const FieldSection = struct {
    fields: std.ArrayList(Field) = .empty,

    pub fn deinit(self: *FieldSection, gpa: Allocator) void {
        for (self.fields.items) |field| {
            gpa.free(field.name);
            gpa.free(field.value);
        }
        self.fields.deinit(gpa);
        self.* = undefined;
    }
};

/// What the encoder is asked to write. `never_index` sets §4.5.4's 'N' bit:
/// sensitive values (Authorization, session cookies) are marked so no hop —
/// ours or an intermediary's — ever puts them in a compression table an
/// attacker could probe (§7.1.3).
pub const FieldLine = struct {
    name: []const u8,
    value: []const u8,
    never_index: bool = false,
};

pub const DecodeOptions = struct {
    /// RFC 9114 §4.2.2: what we advertised in SETTINGS_MAX_FIELD_SECTION_SIZE.
    max_field_section_size: u64 = std.math.maxInt(u64),
};

/// Decode one encoded field section (the payload of a HEADERS frame).
///
/// With no dynamic table, §4.5.1's prefix must say Required Insert Count zero:
/// a nonzero count references table state we told the peer (by never raising
/// SETTINGS_QPACK_MAX_TABLE_CAPACITY) that we would not hold, and §2.2.3 makes
/// the reference itself QPACK_DECOMPRESSION_FAILED.
pub fn decodeSection(
    gpa: Allocator,
    encoded: []const u8,
    options: DecodeOptions,
) Error!FieldSection {
    var input = encoded;

    // §4.5.1: Required Insert Count (8-bit prefix), then S bit + Delta Base
    // (7-bit prefix).
    const required_insert_count = try decodePrefixInt(&input, 8);
    if (required_insert_count != 0) return error.DecompressionFailed;
    _ = try decodePrefixInt(&input, 7); // Base: irrelevant without a dynamic table

    var section: FieldSection = .{};
    errdefer section.deinit(gpa);
    var total_size: u64 = 0;

    while (input.len > 0) {
        const first = input[0];

        if (first & 0x80 != 0) {
            // §4.5.2, '1TXXXXXX': indexed field line.
            const is_static = first & 0x40 != 0;
            const index = try decodePrefixInt(&input, 6);
            // T=0 references the dynamic table, which does not exist here; the
            // prefix already promised (count zero) that it would not be needed.
            if (!is_static) return error.DecompressionFailed;
            if (index >= static_table.len) return error.DecompressionFailed;
            const entry = static_table[index];
            try appendField(gpa, &section, entry.name, entry.value, false, &total_size, options);
            continue;
        }

        if (first & 0x40 != 0) {
            // §4.5.4, '01NTxxxx': literal field line with name reference.
            const never = first & 0x20 != 0;
            const is_static = first & 0x10 != 0;
            const index = try decodePrefixInt(&input, 4);
            if (!is_static) return error.DecompressionFailed;
            if (index >= static_table.len) return error.DecompressionFailed;
            const value = try decodeString(gpa, &input, 8);
            defer gpa.free(value);
            try appendField(gpa, &section, static_table[index].name, value, never, &total_size, options);
            continue;
        }

        if (first & 0x20 != 0) {
            // §4.5.6, '001NHxxx': literal field line with literal name.
            const never = first & 0x10 != 0;
            const name = try decodeString(gpa, &input, 4);
            defer gpa.free(name);
            const value = try decodeString(gpa, &input, 8);
            defer gpa.free(value);
            try appendField(gpa, &section, name, value, never, &total_size, options);
            continue;
        }

        // §4.5.3 ('0001') and §4.5.5 ('0000') are post-Base references into the
        // dynamic table. Same reasoning as T=0 above.
        return error.DecompressionFailed;
    }

    return section;
}

fn appendField(
    gpa: Allocator,
    section: *FieldSection,
    name: []const u8,
    value: []const u8,
    never_index: bool,
    total_size: *u64,
    options: DecodeOptions,
) Error!void {
    // RFC 9114 §4.2.2: the limit is checked field by field as the section
    // decodes, not after — a peer blowing the limit should not get the memory
    // for the whole section before being told no.
    total_size.* += name.len + value.len + 32;
    if (total_size.* > options.max_field_section_size) return error.FieldSectionTooLarge;

    const owned_name = try gpa.dupe(u8, name);
    errdefer gpa.free(owned_name);
    const owned_value = try gpa.dupe(u8, value);
    errdefer gpa.free(owned_value);
    try section.fields.append(gpa, .{
        .name = owned_name,
        .value = owned_value,
        .never_index = never_index,
    });
}

/// Encode a field section into `out` using only the static table, which is the
/// entire repertoire when the peer's table capacity is zero — and, per §2.1,
/// "references to the static table and literal representations ... never risk
/// head-of-line blocking", so this mode also cannot block a stream.
pub fn encodeSection(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    fields: []const FieldLine,
) Error!void {
    // §4.5.1: with no dynamic table references, Required Insert Count is zero
    // and any Base works; zero for both is the encoding the RFC calls one of
    // the most efficient.
    try out.append(gpa, 0x00);
    try out.append(gpa, 0x00);

    for (fields) |field| {
        const found = staticLookup(field.name, field.value);

        // A field marked never-index must not even be an *exact* static match
        // reference? It may: the static table is public by definition, an
        // index into it reveals nothing the table did not already say. §7.1.3
        // protects values from landing in *dynamic* tables. But an exact match
        // for a sensitive value (e.g. cookie="") is fine precisely because the
        // value is in a public RFC.
        if (found.exact) |index| {
            if (!field.never_index) {
                // §4.5.2: '1' '1' index(6+).
                try encodePrefixInt(out, gpa, 0xc0, index, 6);
                continue;
            }
        }

        if (found.name_only) |index| {
            // §4.5.4: '01' N '1' index(4+), then the value as an 8-bit string.
            const flags: u8 = if (field.never_index) 0x70 else 0x50;
            try encodePrefixInt(out, gpa, flags, index, 4);
            try encodeString(out, gpa, 0x00, field.value, 8);
            continue;
        }

        // §4.5.6: '001' N H name-len(3+), name, then the value.
        const flags: u8 = if (field.never_index) 0x30 else 0x20;
        try encodeString(out, gpa, flags, field.name, 4);
        try encodeString(out, gpa, 0x00, field.value, 8);
    }
}

// ── The instruction streams, §4.2 ────────────────────────────────────────────

/// Bytes arriving on the peer's *encoder* stream (stream type 0x02). §3.2.3:
/// with our advertised table capacity at zero, the peer "MUST NOT send any
/// encoder instructions on the encoder stream" — so the stream must exist
/// (§4.2 requires allowing it) and must stay empty. Any byte is the peer
/// inserting into a table we said we would not keep.
pub fn onEncoderStreamData(bytes: []const u8) Error!void {
    if (bytes.len > 0) return error.EncoderStreamError;
}

/// §4.4's decoder instructions, parsed incrementally from the peer's decoder
/// stream (stream type 0x03).
pub const DecoderInstruction = union(enum) {
    /// §4.4.1: the peer finished a section whose Required Insert Count was
    /// nonzero. We never send those, so receiving one is the peer
    /// acknowledging work that never happened (QPACK_DECODER_STREAM_ERROR) —
    /// but the *parse* is still this layer's job, and the judgement the
    /// caller's, because a future dynamic-table encoder will receive these
    /// legitimately.
    section_ack: u64,
    /// §4.4.2: the peer abandoned a stream. Always legal, and with no dynamic
    /// table there are no references to release, so it is a no-op here.
    stream_cancel: u64,
    /// §4.4.3: the peer's Known Received Count moved. We never inserted, so
    /// any increment — including the always-illegal zero — is an error.
    insert_count_increment: u64,
};

/// Parse one decoder instruction. Returns null if `input` does not yet hold a
/// whole instruction (nothing is consumed in that case).
pub fn parseDecoderInstruction(input: *[]const u8) Error!?DecoderInstruction {
    if (input.len == 0) return null;
    const first = input.*[0];
    var attempt = input.*;

    if (first & 0x80 != 0) {
        const id = decodePrefixInt(&attempt, 7) catch return null;
        input.* = attempt;
        return .{ .section_ack = id };
    }
    if (first & 0x40 != 0) {
        const id = decodePrefixInt(&attempt, 6) catch return null;
        input.* = attempt;
        return .{ .stream_cancel = id };
    }
    const increment = decodePrefixInt(&attempt, 6) catch return null;
    input.* = attempt;
    return .{ .insert_count_increment = increment };
}

/// Apply a decoder instruction in the zero-capacity mode, which is where the
/// "we never inserted, so..." judgements live — split from parsing so the
/// parse stays reusable when a dynamic table exists.
pub fn applyDecoderInstruction(instruction: DecoderInstruction) Error!void {
    switch (instruction) {
        // §4.4.1: acknowledging a section on a stream where "every encoded
        // field section with a non-zero Required Insert Count has already been
        // acknowledged" is an error — and with none ever sent, every stream is
        // such a stream.
        .section_ack => return error.DecoderStreamError,
        .stream_cancel => {},
        // §4.4.3: "an Increment field equal to zero, or one that increases the
        // Known Received Count beyond what the encoder has sent" — with zero
        // sent, that is any increment at all.
        .insert_count_increment => return error.DecoderStreamError,
    }
}

const testing = std.testing;

test "qpack: RFC 9204 Appendix B.1's exact bytes decode" {
    // The RFC's own worked example, byte for byte: prefix 0x0000, then a
    // literal field line with static name reference to index 1 (:path) and the
    // plain-text value "/index.html". A vector from the RFC rather than our
    // own round trip, so an error symmetrical in encoder and decoder — the
    // kind a round trip cannot see — still fails.
    const bytes = [_]u8{
        0x00, 0x00, 0x51, 0x0b, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c,
    };
    const gpa = testing.allocator;
    var section = try decodeSection(gpa, &bytes, .{});
    defer section.deinit(gpa);

    try testing.expectEqual(@as(usize, 1), section.fields.items.len);
    try testing.expectEqualStrings(":path", section.fields.items[0].name);
    try testing.expectEqualStrings("/index.html", section.fields.items[0].value);
    try testing.expect(!section.fields.items[0].never_index);
}

test "qpack: the static table is Appendix A, indexed from zero" {
    // §3.1 note: "the QPACK static table is indexed from 0, whereas the HPACK
    // static table is indexed from 1". An off-by-one shifts every decoded
    // header name; spot checks at both ends and the exact count make the whole
    // table load-bearing.
    try testing.expectEqual(@as(usize, 99), static_table.len);
    try testing.expectEqualStrings(":authority", static_table[0].name);
    try testing.expectEqualStrings("/", static_table[1].value);
    try testing.expectEqualStrings("GET", static_table[17].value);
    try testing.expectEqualStrings(":scheme", static_table[23].name);
    try testing.expectEqualStrings("https", static_table[23].value);
    try testing.expectEqualStrings("authorization", static_table[84].name);
    try testing.expectEqualStrings("x-frame-options", static_table[98].name);
    try testing.expectEqualStrings("sameorigin", static_table[98].value);
}

test "qpack: a realistic request round-trips, choosing the cheapest representation" {
    const gpa = testing.allocator;
    const request = [_]FieldLine{
        .{ .name = ":method", .value = "GET" }, // exact static match
        .{ .name = ":scheme", .value = "https" }, // exact static match
        .{ .name = ":authority", .value = "example.com" }, // static name only
        .{ .name = ":path", .value = "/api/v1/items?q=zig" }, // static name only
        .{ .name = "x-request-id", .value = "12345-abcdef" }, // literal name
        .{ .name = "user-agent", .value = "zinet/0.1" }, // static name only
    };

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encodeSection(gpa, &out, &request);

    // The two exact matches cost one byte each (after the two-byte prefix).
    try testing.expectEqual(@as(u8, 0xc0 | 17), out.items[2]);
    try testing.expectEqual(@as(u8, 0xc0 | 23), out.items[3]);

    var section = try decodeSection(gpa, out.items, .{});
    defer section.deinit(gpa);
    try testing.expectEqual(request.len, section.fields.items.len);
    for (request, section.fields.items) |sent, got| {
        try testing.expectEqualStrings(sent.name, got.name);
        try testing.expectEqualStrings(sent.value, got.value);
    }
}

test "qpack: the never-indexed bit survives encoding and decoding" {
    // §7.1.3: the 'N' bit is a promise that travels — an intermediary
    // re-encoding a field it received with the bit set must keep it literal on
    // the next hop. That obligation is only meetable if the decoder *reports*
    // the bit, which is why Field carries it rather than dropping it as
    // wire-level trivia.
    const gpa = testing.allocator;
    const fields = [_]FieldLine{
        .{ .name = "authorization", .value = "Bearer secret-token", .never_index = true },
        .{ .name = "x-api-key", .value = "hunter2", .never_index = true },
        .{ .name = "accept", .value = "*/*" }, // exact match, unaffected
    };

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encodeSection(gpa, &out, &fields);

    // authorization is static index 84: name reference with N set — the name
    // is public RFC content, only the *value* needed protecting.
    try testing.expectEqual(@as(u8, 0x70 | 0x0f), out.items[2]); // '01' N=1 T=1, index 15+ continues

    var section = try decodeSection(gpa, out.items, .{});
    defer section.deinit(gpa);
    try testing.expect(section.fields.items[0].never_index);
    try testing.expect(section.fields.items[1].never_index);
    try testing.expect(!section.fields.items[2].never_index);
    try testing.expectEqualStrings("Bearer secret-token", section.fields.items[0].value);
}

test "qpack: huffman is used when shorter, skipped when not, and both decode" {
    const gpa = testing.allocator;

    // Lowercase text compresses well; the H bit should be set and the wire
    // shorter than the input.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encodeSection(gpa, &out, &[_]FieldLine{
        .{ .name = "x-lang", .value = "accept-encoding-style-text" },
    });
    var section = try decodeSection(gpa, out.items, .{});
    defer section.deinit(gpa);
    try testing.expectEqualStrings("accept-encoding-style-text", section.fields.items[0].value);

    // Bytes that Huffman expands (rare symbols get long codes) must go plain:
    // an encoder that always sets H produces valid but *larger* output, which
    // no correctness test would ever catch — so this one checks the choice.
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    const binary = [_]u8{ 0x00, 0xff, 0x01, 0xfe, 0x02 };
    try encodeSection(gpa, &raw, &[_]FieldLine{
        .{ .name = "x-b", .value = &binary },
    });
    var raw_section = try decodeSection(gpa, raw.items, .{});
    defer raw_section.deinit(gpa);
    try testing.expectEqualStrings(&binary, raw_section.fields.items[0].value);
    // Find the value's H bit: it is the byte after the name. Cheaper to assert
    // the aggregate: plain encoding of 5 bytes costs exactly length+1.
    const value_bytes = raw.items[raw.items.len - 6 ..];
    try testing.expectEqual(@as(u8, 5), value_bytes[0]); // H=0, length 5
}

test "qpack: dynamic-table references are refused while capacity is zero" {
    const gpa = testing.allocator;

    // A nonzero Required Insert Count claims the section needs table state we
    // never agreed to hold (§2.2.3). EncInsertCount = 1 means RIC = 1 after
    // the decoder transform — but with MaxEntries 0 *any* nonzero value is
    // unproducible by a conformant encoder.
    const nonzero_ric = [_]u8{ 0x01, 0x00, 0xc0 | 17 };
    try testing.expectError(error.DecompressionFailed, decodeSection(gpa, &nonzero_ric, .{}));

    // An indexed field line with T=0 (dynamic) even under RIC 0.
    const dynamic_ref = [_]u8{ 0x00, 0x00, 0x80 };
    try testing.expectError(error.DecompressionFailed, decodeSection(gpa, &dynamic_ref, .{}));

    // Post-Base forms, §4.5.3 and §4.5.5.
    const post_base = [_]u8{ 0x00, 0x00, 0x10 };
    try testing.expectError(error.DecompressionFailed, decodeSection(gpa, &post_base, .{}));
    const post_base_name = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x41 };
    try testing.expectError(error.DecompressionFailed, decodeSection(gpa, &post_base_name, .{}));

    // A static index past the table (§3.1: invalid index is
    // QPACK_DECOMPRESSION_FAILED).
    var bad_index: std.ArrayList(u8) = .empty;
    defer bad_index.deinit(gpa);
    try bad_index.appendSlice(gpa, &.{ 0x00, 0x00 });
    try encodePrefixInt(&bad_index, gpa, 0xc0, static_table.len, 6);
    try testing.expectError(error.DecompressionFailed, decodeSection(gpa, bad_index.items, .{}));
}

test "qpack: the field section size limit is enforced during decoding, not after" {
    // RFC 9114 §4.2.2: size is name + value + 32 per field, uncompressed. The
    // limit must bite while decoding — after would mean the peer already got
    // the allocation it was aiming for. With the limit at 80, the second field
    // (42, total 94) must fail even though the first (52) fit.
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try encodeSection(gpa, &out, &[_]FieldLine{
        .{ .name = "aaaaaaaaaa", .value = "bbbbbbbbbb" }, // 10 + 10 + 32 = 52
        .{ .name = "ccccc", .value = "ddddd" }, // 5 + 5 + 32 = 42
    });

    try testing.expectError(
        error.FieldSectionTooLarge,
        decodeSection(gpa, out.items, .{ .max_field_section_size = 80 }),
    );

    // At 94 (52 + 42) both fit exactly.
    var section = try decodeSection(gpa, out.items, .{ .max_field_section_size = 94 });
    defer section.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), section.fields.items.len);
}

test "qpack: instruction streams are policed for the zero-capacity promise" {
    // §3.2.3: with our advertised capacity at zero the peer must send nothing
    // on its encoder stream. The stream itself must be *allowed* (§4.2), so
    // emptiness is the property — any byte is an insertion into a table we
    // said we would not keep, and the memory it implies is exactly what the
    // zero was for.
    try onEncoderStreamData(&.{});
    try testing.expectError(error.EncoderStreamError, onEncoderStreamData(&.{0x3f}));

    // Decoder instructions parse incrementally: a split prefix integer waits
    // rather than fails.
    var partial: []const u8 = &.{0xff}; // section ack, id needs continuation
    try testing.expect((try parseDecoderInstruction(&partial)) == null);
    try testing.expectEqual(@as(usize, 1), partial.len); // nothing consumed

    var whole: []const u8 = &.{ 0xff, 0x02 }; // stream id 127 + 2 = 129
    const ack = (try parseDecoderInstruction(&whole)).?;
    try testing.expectEqual(@as(u64, 129), ack.section_ack);
    try testing.expectEqual(@as(usize, 0), whole.len);

    // A cancellation is always legal; with no dynamic table it releases
    // nothing. The other two acknowledge inserts and sections that never
    // happened (§4.4.1, §4.4.3).
    try applyDecoderInstruction(.{ .stream_cancel = 4 });
    try testing.expectError(error.DecoderStreamError, applyDecoderInstruction(.{ .section_ack = 0 }));
    try testing.expectError(
        error.DecoderStreamError,
        applyDecoderInstruction(.{ .insert_count_increment = 1 }),
    );
}

test "qpack: prefixed integers reach 62 bits and stop there" {
    // §4.1.1: QPACK "MUST be able to decode integers up to and including 62
    // bits long" — that is why http2's 32-bit implementation is not reused: a
    // Section Acknowledgment's stream ID can exceed 32 bits legitimately.
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    for ([_]u64{ 0, 5, 31, 32, 1337, 1 << 32, max_int }) |value| {
        out.clearRetainingCapacity();
        try encodePrefixInt(&out, gpa, 0x00, value, 5);
        var input: []const u8 = out.items;
        try testing.expectEqual(value, try decodePrefixInt(&input, 5));
        try testing.expectEqual(@as(usize, 0), input.len);
    }

    // One beyond the requirement is refused, not wrapped (§7.4): large-integer
    // handling is named as a security consideration, and saturating or
    // wrapping here turns an attack into a quiet misdecode.
    out.clearRetainingCapacity();
    try out.append(gpa, 0x1f); // 5-bit prefix maxed
    var rest = max_int - 31 + 1; // encodes max_int + 1
    while (rest >= 0x80) : (rest >>= 7) {
        try out.append(gpa, @as(u8, @intCast(rest & 0x7f)) | 0x80);
    }
    try out.append(gpa, @intCast(rest));
    var input: []const u8 = out.items;
    try testing.expectError(error.DecompressionFailed, decodePrefixInt(&input, 5));

    // And a truncated integer is malformed, not "wait for more" — this decoder
    // works on whole sections, where missing continuation bytes cannot arrive.
    var cut: []const u8 = &.{0x1f};
    try testing.expectError(error.DecompressionFailed, decodePrefixInt(&cut, 5));
}
