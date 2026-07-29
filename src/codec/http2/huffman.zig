//! The canonical Huffman code of RFC 7541 Appendix B.
//!
//! The table is not a tuning choice: HPACK fixes one code, derived from header
//! frequencies in a corpus of real traffic, so both peers can build it in.
//!
//! Decoding walks a flattened DFA rather than a pointer tree. Each state is
//! sixteen entries wide — four bits of input per step — so a symbol costs at most
//! eight table lookups instead of thirty bits of branching, and the whole
//! structure is `comptime`-built read-only data with no allocation and no
//! pointers to chase.

const std = @import("std");
const assert = std.debug.assert;

/// Code and bit length for each of the 256 octets plus the end-of-string symbol,
/// which is index 256. RFC 7541 Appendix B, transcribed as `{ code, bits }`.
const raw_codes = [257][2]u32{
    .{ 0x1ff8, 13 },     .{ 0x7fffd8, 23 },   .{ 0xfffffe2, 28 },  .{ 0xfffffe3, 28 },
    .{ 0xfffffe4, 28 },  .{ 0xfffffe5, 28 },  .{ 0xfffffe6, 28 },  .{ 0xfffffe7, 28 },
    .{ 0xfffffe8, 28 },  .{ 0xffffea, 24 },   .{ 0x3ffffffc, 30 }, .{ 0xfffffe9, 28 },
    .{ 0xfffffea, 28 },  .{ 0x3ffffffd, 30 }, .{ 0xfffffeb, 28 },  .{ 0xfffffec, 28 },
    .{ 0xfffffed, 28 },  .{ 0xfffffee, 28 },  .{ 0xfffffef, 28 },  .{ 0xffffff0, 28 },
    .{ 0xffffff1, 28 },  .{ 0xffffff2, 28 },  .{ 0x3ffffffe, 30 }, .{ 0xffffff3, 28 },
    .{ 0xffffff4, 28 },  .{ 0xffffff5, 28 },  .{ 0xffffff6, 28 },  .{ 0xffffff7, 28 },
    .{ 0xffffff8, 28 },  .{ 0xffffff9, 28 },  .{ 0xffffffa, 28 },  .{ 0xffffffb, 28 },
    .{ 0x14, 6 },        .{ 0x3f8, 10 },      .{ 0x3f9, 10 },      .{ 0xffa, 12 },
    .{ 0x1ff9, 13 },     .{ 0x15, 6 },        .{ 0xf8, 8 },        .{ 0x7fa, 11 },
    .{ 0x3fa, 10 },      .{ 0x3fb, 10 },      .{ 0xf9, 8 },        .{ 0x7fb, 11 },
    .{ 0xfa, 8 },        .{ 0x16, 6 },        .{ 0x17, 6 },        .{ 0x18, 6 },
    .{ 0x0, 5 },         .{ 0x1, 5 },         .{ 0x2, 5 },         .{ 0x19, 6 },
    .{ 0x1a, 6 },        .{ 0x1b, 6 },        .{ 0x1c, 6 },        .{ 0x1d, 6 },
    .{ 0x1e, 6 },        .{ 0x1f, 6 },        .{ 0x5c, 7 },        .{ 0xfb, 8 },
    .{ 0x7ffc, 15 },     .{ 0x20, 6 },        .{ 0xffb, 12 },      .{ 0x3fc, 10 },
    .{ 0x1ffa, 13 },     .{ 0x21, 6 },        .{ 0x5d, 7 },        .{ 0x5e, 7 },
    .{ 0x5f, 7 },        .{ 0x60, 7 },        .{ 0x61, 7 },        .{ 0x62, 7 },
    .{ 0x63, 7 },        .{ 0x64, 7 },        .{ 0x65, 7 },        .{ 0x66, 7 },
    .{ 0x67, 7 },        .{ 0x68, 7 },        .{ 0x69, 7 },        .{ 0x6a, 7 },
    .{ 0x6b, 7 },        .{ 0x6c, 7 },        .{ 0x6d, 7 },        .{ 0x6e, 7 },
    .{ 0x6f, 7 },        .{ 0x70, 7 },        .{ 0x71, 7 },        .{ 0x72, 7 },
    .{ 0xfc, 8 },        .{ 0x73, 7 },        .{ 0xfd, 8 },        .{ 0x1ffb, 13 },
    .{ 0x7fff0, 19 },    .{ 0x1ffc, 13 },     .{ 0x3ffc, 14 },     .{ 0x22, 6 },
    .{ 0x7ffd, 15 },     .{ 0x3, 5 },         .{ 0x23, 6 },        .{ 0x4, 5 },
    .{ 0x24, 6 },        .{ 0x5, 5 },         .{ 0x25, 6 },        .{ 0x26, 6 },
    .{ 0x27, 6 },        .{ 0x6, 5 },         .{ 0x74, 7 },        .{ 0x75, 7 },
    .{ 0x28, 6 },        .{ 0x29, 6 },        .{ 0x2a, 6 },        .{ 0x7, 5 },
    .{ 0x2b, 6 },        .{ 0x76, 7 },        .{ 0x2c, 6 },        .{ 0x8, 5 },
    .{ 0x9, 5 },         .{ 0x2d, 6 },        .{ 0x77, 7 },        .{ 0x78, 7 },
    .{ 0x79, 7 },        .{ 0x7a, 7 },        .{ 0x7b, 7 },        .{ 0x7ffe, 15 },
    .{ 0x7fc, 11 },      .{ 0x3ffd, 14 },     .{ 0x1ffd, 13 },     .{ 0xffffffc, 28 },
    .{ 0xfffe6, 20 },    .{ 0x3fffd2, 22 },   .{ 0xfffe7, 20 },    .{ 0xfffe8, 20 },
    .{ 0x3fffd3, 22 },   .{ 0x3fffd4, 22 },   .{ 0x3fffd5, 22 },   .{ 0x7fffd9, 23 },
    .{ 0x3fffd6, 22 },   .{ 0x7fffda, 23 },   .{ 0x7fffdb, 23 },   .{ 0x7fffdc, 23 },
    .{ 0x7fffdd, 23 },   .{ 0x7fffde, 23 },   .{ 0xffffeb, 24 },   .{ 0x7fffdf, 23 },
    .{ 0xffffec, 24 },   .{ 0xffffed, 24 },   .{ 0x3fffd7, 22 },   .{ 0x7fffe0, 23 },
    .{ 0xffffee, 24 },   .{ 0x7fffe1, 23 },   .{ 0x7fffe2, 23 },   .{ 0x7fffe3, 23 },
    .{ 0x7fffe4, 23 },   .{ 0x1fffdc, 21 },   .{ 0x3fffd8, 22 },   .{ 0x7fffe5, 23 },
    .{ 0x3fffd9, 22 },   .{ 0x7fffe6, 23 },   .{ 0x7fffe7, 23 },   .{ 0xffffef, 24 },
    .{ 0x3fffda, 22 },   .{ 0x1fffdd, 21 },   .{ 0xfffe9, 20 },    .{ 0x3fffdb, 22 },
    .{ 0x3fffdc, 22 },   .{ 0x7fffe8, 23 },   .{ 0x7fffe9, 23 },   .{ 0x1fffde, 21 },
    .{ 0x7fffea, 23 },   .{ 0x3fffdd, 22 },   .{ 0x3fffde, 22 },   .{ 0xfffff0, 24 },
    .{ 0x1fffdf, 21 },   .{ 0x3fffdf, 22 },   .{ 0x7fffeb, 23 },   .{ 0x7fffec, 23 },
    .{ 0x1fffe0, 21 },   .{ 0x1fffe1, 21 },   .{ 0x3fffe0, 22 },   .{ 0x1fffe2, 21 },
    .{ 0x7fffed, 23 },   .{ 0x3fffe1, 22 },   .{ 0x7fffee, 23 },   .{ 0x7fffef, 23 },
    .{ 0xfffea, 20 },    .{ 0x3fffe2, 22 },   .{ 0x3fffe3, 22 },   .{ 0x3fffe4, 22 },
    .{ 0x7ffff0, 23 },   .{ 0x3fffe5, 22 },   .{ 0x3fffe6, 22 },   .{ 0x7ffff1, 23 },
    .{ 0x3ffffe0, 26 },  .{ 0x3ffffe1, 26 },  .{ 0xfffeb, 20 },    .{ 0x7fff1, 19 },
    .{ 0x3fffe7, 22 },   .{ 0x7ffff2, 23 },   .{ 0x3fffe8, 22 },   .{ 0x1ffffec, 25 },
    .{ 0x3ffffe2, 26 },  .{ 0x3ffffe3, 26 },  .{ 0x3ffffe4, 26 },  .{ 0x7ffffde, 27 },
    .{ 0x7ffffdf, 27 },  .{ 0x3ffffe5, 26 },  .{ 0xfffff1, 24 },   .{ 0x1ffffed, 25 },
    .{ 0x7fff2, 19 },    .{ 0x1fffe3, 21 },   .{ 0x3ffffe6, 26 },  .{ 0x7ffffe0, 27 },
    .{ 0x7ffffe1, 27 },  .{ 0x3ffffe7, 26 },  .{ 0x7ffffe2, 27 },  .{ 0xfffff2, 24 },
    .{ 0x1fffe4, 21 },   .{ 0x1fffe5, 21 },   .{ 0x3ffffe8, 26 },  .{ 0x3ffffe9, 26 },
    .{ 0xffffffd, 28 },  .{ 0x7ffffe3, 27 },  .{ 0x7ffffe4, 27 },  .{ 0x7ffffe5, 27 },
    .{ 0xfffec, 20 },    .{ 0xfffff3, 24 },   .{ 0xfffed, 20 },    .{ 0x1fffe6, 21 },
    .{ 0x3fffe9, 22 },   .{ 0x1fffe7, 21 },   .{ 0x1fffe8, 21 },   .{ 0x7ffff3, 23 },
    .{ 0x3fffea, 22 },   .{ 0x3fffeb, 22 },   .{ 0x1ffffee, 25 },  .{ 0x1ffffef, 25 },
    .{ 0xfffff4, 24 },   .{ 0xfffff5, 24 },   .{ 0x3ffffea, 26 },  .{ 0x7ffff4, 23 },
    .{ 0x3ffffeb, 26 },  .{ 0x7ffffe6, 27 },  .{ 0x3ffffec, 26 },  .{ 0x3ffffed, 26 },
    .{ 0x7ffffe7, 27 },  .{ 0x7ffffe8, 27 },  .{ 0x7ffffe9, 27 },  .{ 0x7ffffea, 27 },
    .{ 0x7ffffeb, 27 },  .{ 0xffffffe, 28 },  .{ 0x7ffffec, 27 },  .{ 0x7ffffed, 27 },
    .{ 0x7ffffee, 27 },  .{ 0x7ffffef, 27 },  .{ 0x7fffff0, 27 },  .{ 0x3ffffee, 26 },
    .{ 0x3fffffff, 30 },
};

pub const Code = struct {
    bits: u32,
    len: u5,
};

pub const codes = blk: {
    var out: [257]Code = undefined;
    for (raw_codes, 0..) |entry, index| {
        out[index] = .{ .bits = entry[0], .len = @intCast(entry[1]) };
    }
    break :blk out;
};

/// The end-of-string symbol. It never appears in a decoded string: RFC 7541 §5.2
/// pads with the *prefix* of it, and an actual complete EOS is a decoding error.
pub const eos_symbol = 256;

pub const Error = error{
    /// The padding was not a prefix of the EOS code, was longer than seven bits,
    /// or a complete EOS symbol appeared. RFC 7541 §5.2 makes each of these a
    /// `COMPRESSION_ERROR`.
    InvalidHuffman,
};

/// The exact encoded length in bytes, so the caller can size a buffer once
/// instead of growing it.
pub fn encodedLen(source: []const u8) usize {
    var bits: usize = 0;
    for (source) |byte| bits += codes[byte].len;
    return (bits + 7) / 8;
}

/// Encodes into `out`, which must be at least `encodedLen(source)` bytes.
/// Returns the bytes written.
pub fn encode(out: []u8, source: []const u8) []u8 {
    const needed = encodedLen(source);
    assert(out.len >= needed);

    var accumulator: u64 = 0;
    var pending: u6 = 0;
    var written: usize = 0;

    for (source) |byte| {
        const code = codes[byte];
        accumulator = (accumulator << code.len) | code.bits;
        pending += code.len;
        while (pending >= 8) {
            pending -= 8;
            out[written] = @truncate(accumulator >> pending);
            written += 1;
        }
    }

    if (pending > 0) {
        // §5.2: pad with the most significant bits of the EOS code, which are
        // all ones. Any other padding is a decoding error at the far end.
        const pad: u6 = 8 - pending;
        const ones: u64 = (@as(u64, 1) << pad) - 1;
        out[written] = @truncate((accumulator << pad) | ones);
        written += 1;
    }

    assert(written == needed);
    return out[0..written];
}

// -- Decoding --------------------------------------------------------------

/// One transition of the flattened DFA: four bits in, at most one octet out.
const Transition = struct {
    /// Where to go next.
    next: u9 = 0,
    /// Whether `symbol` was completed by this transition.
    emits: bool = false,
    /// Whether stopping here would be a valid end of string, i.e. whether every
    /// bit consumed so far in this state is part of the EOS prefix.
    accepting: bool = false,
    /// Set when this nibble cannot continue any code, which happens only for the
    /// EOS symbol and for over-long padding.
    fail: bool = false,
    symbol: u8 = 0,
};

/// A node of the code tree, built at comptime purely to derive the table below.
const Node = struct {
    children: [2]?usize = .{ null, null },
    symbol: ?u16 = null,
};

/// Builds the code tree, then flattens it into nibble-indexed states.
const table = blk: {
    // A canonical Huffman code over 257 symbols has at most 2*257 internal nodes.
    @setEvalBranchQuota(2_000_000);
    var nodes: [600]Node = @splat(.{});
    var node_count: usize = 1;

    for (codes, 0..) |code, symbol| {
        var current: usize = 0;
        var shift: u5 = code.len;
        while (shift > 0) {
            shift -= 1;
            const bit: usize = (code.bits >> shift) & 1;
            if (nodes[current].children[bit] == null) {
                nodes[current].children[bit] = node_count;
                node_count += 1;
            }
            current = nodes[current].children[bit].?;
        }
        // Two symbols at one node would mean the transcribed table is not
        // prefix-free, which no canonical Huffman code is.
        assert(nodes[current].symbol == null);
        assert(nodes[current].children[0] == null and nodes[current].children[1] == null);
        nodes[current].symbol = symbol;
    }

    // Each tree node that is not a leaf becomes a state. Walking four bits at a
    // time from it gives sixteen transitions, each landing on another state.
    var state_of: [600]?u9 = @splat(null);
    var state_count: u9 = 0;
    for (0..node_count) |index| {
        if (nodes[index].symbol == null) {
            state_of[index] = state_count;
            state_count += 1;
        }
    }

    var flat: [512][16]Transition = @splat(@splat(.{}));
    for (0..node_count) |index| {
        const state = state_of[index] orelse continue;
        for (0..16) |nibble| {
            var current: usize = index;
            var emits = false;
            var symbol: u8 = 0;
            var failed = false;

            var bit_index: u5 = 4;
            while (bit_index > 0) {
                bit_index -= 1;
                const bit: usize = (nibble >> bit_index) & 1;
                const child = nodes[current].children[bit] orelse {
                    failed = true;
                    break;
                };
                current = child;
                if (nodes[current].symbol) |found| {
                    if (found == eos_symbol) {
                        // §5.2: a complete EOS in the stream is an error.
                        failed = true;
                        break;
                    }
                    // Two symbols cannot complete within one nibble: the shortest
                    // code is five bits.
                    assert(!emits);
                    emits = true;
                    symbol = found;
                    current = 0;
                }
            }

            flat[state][nibble] = if (failed) .{
                .next = 0,
                .emits = false,
                .accepting = false,
                .fail = true,
            } else .{
                .next = state_of[current].?,
                .emits = emits,
                .accepting = isEosPrefix(&nodes, current),
                .fail = false,
                .symbol = symbol,
            };
        }
    }

    break :blk flat[0..state_count].*;
};

/// Whether every bit consumed to reach `index` is a prefix of the EOS code,
/// which is the only padding §5.2 permits.
fn isEosPrefix(nodes: []const Node, index: usize) bool {
    // The EOS code is thirty one-bits, so its prefixes are exactly the nodes
    // reached by following the 1 branch from the root.
    var current: usize = 0;
    var depth: usize = 0;
    while (depth <= 7) : (depth += 1) {
        if (current == index) return true;
        current = nodes[current].children[1] orelse return false;
    }
    return false;
}

/// The state a decode starts and must end in.
const initial_state: u9 = 0;

/// Decodes into `out`, returning the bytes written, or `error.NoSpaceLeft` if the
/// output does not fit. The caller sizes the output, which is how the header-list
/// limit is enforced *while* decoding rather than after: a Huffman string can
/// expand by a factor of eight and a half.
pub fn decode(out: []u8, source: []const u8) (Error || error{NoSpaceLeft})![]u8 {
    var state: u9 = initial_state;
    var accepting = true;
    var written: usize = 0;

    for (source) |byte| {
        inline for ([_]u3{ 4, 0 }) |shift| {
            const nibble: u4 = @truncate(byte >> shift);
            const transition = table[state][nibble];
            if (transition.fail) return error.InvalidHuffman;
            if (transition.emits) {
                if (written == out.len) return error.NoSpaceLeft;
                out[written] = transition.symbol;
                written += 1;
            }
            state = transition.next;
            accepting = transition.accepting;
        }
    }

    // §5.2: the padding must be a prefix of EOS and shorter than eight bits. The
    // state being accepting covers the first; being back at the root after a
    // symbol covers a string that ended on a byte boundary.
    if (!accepting) return error.InvalidHuffman;
    return out[0..written];
}

/// The decoded length, without writing anything. Used to size an allocation
/// exactly once rather than growing, and to check a limit before committing.
pub fn decodedLen(source: []const u8) Error!usize {
    var state: u9 = initial_state;
    var accepting = true;
    var count: usize = 0;
    for (source) |byte| {
        inline for ([_]u3{ 4, 0 }) |shift| {
            const nibble: u4 = @truncate(byte >> shift);
            const transition = table[state][nibble];
            if (transition.fail) return error.InvalidHuffman;
            if (transition.emits) count += 1;
            state = transition.next;
            accepting = transition.accepting;
        }
    }
    if (!accepting) return error.InvalidHuffman;
    return count;
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "huffman: the RFC 7541 Appendix C vectors" {
    // These are the encodings the RFC prints, so they check the table itself
    // rather than only checking that encode and decode agree with each other.
    const cases = [_]struct { plain: []const u8, encoded: []const u8 }{
        .{ .plain = "www.example.com", .encoded = "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff" },
        .{ .plain = "no-cache", .encoded = "\xa8\xeb\x10\x64\x9c\xbf" },
        .{ .plain = "custom-key", .encoded = "\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f" },
        .{ .plain = "custom-value", .encoded = "\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf" },
        .{ .plain = "302", .encoded = "\x64\x02" },
        .{ .plain = "private", .encoded = "\xae\xc3\x77\x1a\x4b" },
        .{ .plain = "Mon, 21 Oct 2013 20:13:21 GMT", .encoded = "\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff" },
        .{ .plain = "https://www.example.com", .encoded = "\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3" },
        .{ .plain = "gzip", .encoded = "\x9b\xd9\xab" },
    };

    for (cases) |case| {
        var encoded_buf: [64]u8 = undefined;
        try testing.expectEqual(case.encoded.len, encodedLen(case.plain));
        try testing.expectEqualSlices(u8, case.encoded, encode(&encoded_buf, case.plain));

        var decoded_buf: [64]u8 = undefined;
        try testing.expectEqual(case.plain.len, try decodedLen(case.encoded));
        try testing.expectEqualStrings(case.plain, try decode(&decoded_buf, case.encoded));
    }
}

test "huffman: every octet round trips, alone and in sequence" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*slot, index| slot.* = @intCast(index);

    var encoded_buf: [1024]u8 = undefined;
    var decoded_buf: [512]u8 = undefined;

    const encoded = encode(&encoded_buf, &all);
    try testing.expectEqualStrings(&all, try decode(&decoded_buf, encoded));

    // Alone, so that every code length hits the padding path on its own.
    for (all) |byte| {
        const one = [_]u8{byte};
        const bytes = encode(&encoded_buf, &one);
        try testing.expectEqual(bytes.len, encodedLen(&one));
        try testing.expectEqualSlices(u8, &one, try decode(&decoded_buf, bytes));
    }
}

test "huffman: the empty string" {
    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), encodedLen(""));
    try testing.expectEqualStrings("", encode(&buf, ""));
    try testing.expectEqualStrings("", try decode(&buf, ""));
}

test "huffman: §5.2 rejects bad padding and a complete EOS" {
    var buf: [64]u8 = undefined;

    // Padding that is not all ones: 'a' is 00011 (5 bits), so three pad bits of
    // zero rather than one.
    try testing.expectError(error.InvalidHuffman, decode(&buf, "\x18"));

    // A whole byte of padding. 'a' plus 'a' plus 'a' is fifteen bits, so one pad
    // bit; appending 0xff adds eight more, which is more than §5.2 allows.
    try testing.expectError(error.InvalidHuffman, decode(&buf, "\x18\xc7\xff"));

    // A complete EOS symbol is thirty one-bits, which no valid stream contains.
    try testing.expectError(error.InvalidHuffman, decode(&buf, "\xff\xff\xff\xff"));
}

test "huffman: decoding into too small an output is reported, not truncated" {
    var buf: [3]u8 = undefined;
    const encoded = "\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"; // www.example.com
    try testing.expectError(error.NoSpaceLeft, decode(&buf, encoded));
    // The length is still available without a buffer, which is what lets a
    // header-list limit be checked before anything is committed.
    try testing.expectEqual(@as(usize, 15), try decodedLen(encoded));
}

test "huffman: the transcribed table is a complete prefix-free code" {
    // The Appendix C vectors only exercise the octets those strings contain, and
    // a round trip only proves encode and decode agree with each other — so a
    // typo in an unused entry would pass both. Kraft's equality checks all 257 at
    // once: a prefix-free code is complete exactly when the sum of 2^-len over
    // every symbol is one, and any single wrong length breaks it.
    //
    // Prefix-freeness itself is asserted while the decoding tree is built, where
    // two symbols landing on one node, or a symbol landing on an interior node,
    // fails the comptime build.
    const scale = 30; // the longest code
    var sum: u64 = 0;
    var longest: u5 = 0;
    for (codes) |code| {
        try testing.expect(code.len >= 5 and code.len <= scale);
        sum += @as(u64, 1) << (scale - code.len);
        longest = @max(longest, code.len);
    }
    try testing.expectEqual(@as(u64, 1) << scale, sum);
    try testing.expectEqual(@as(u5, scale), longest);

    // Every code must also fit in the bits its length claims.
    for (codes) |code| {
        if (code.len < 32) try testing.expect(code.bits < (@as(u64, 1) << code.len));
    }

    // Distinctness follows from prefix-freeness, but check it directly since it
    // is cheap and catches a duplicated line in the transcription.
    for (codes, 0..) |a, i| {
        for (codes[i + 1 ..]) |b| {
            try testing.expect(a.bits != b.bits or a.len != b.len);
        }
    }
}
