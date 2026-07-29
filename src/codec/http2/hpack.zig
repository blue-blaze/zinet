//! HPACK: header compression for HTTP/2 (RFC 7541).
//!
//! ## Why decoded fields are always copied
//!
//! An indexed field names an entry in the static or the dynamic table, so the
//! cheap implementation hands back a slice pointing into that table. The dynamic
//! table evicts, and it evicts *while a later field in the same block is being
//! decoded* — a size update or an insertion can drop the entry a previous field
//! pointed at. So every decoded name and value is duplicated into the caller's
//! arena. It costs a copy per field and it makes the lifetime of a decoded header
//! the lifetime of the request, which is the rule the rest of the codebase already
//! states: inbound messages own an arena.
//!
//! ## Why the limits are enforced during the decode rather than after
//!
//! A header list decompresses. Huffman alone reaches roughly 8.5:1, and an
//! indexed field is one byte on the wire for an entry of any size, so a small
//! block can name a very large list — the same shape as the zip bomb the
//! WebSocket compression path had to bound. Checking the total afterwards means
//! having already allocated it, so `max_header_list_size` is charged per field as
//! the block is decoded and the decode stops at the first field that exceeds it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const huffman = @import("huffman.zig");

pub const Error = error{
    /// The block is malformed: a truncated integer, an index that names nothing,
    /// invalid Huffman, a size update above what was negotiated. RFC 7541 §4.2
    /// and RFC 9113 §4.3 make every one of these a connection error carrying
    /// `COMPRESSION_ERROR`.
    CompressionError,
    /// A limit this implementation imposes was exceeded, answered with
    /// `ENHANCE_YOUR_CALM` rather than blaming the peer's syntax.
    LimitExceeded,
};

/// One header field. `name` and `value` are owned by whoever allocated them; a
/// decoded field's strings live in the arena passed to `decode`.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
    /// RFC 7541 §6.2.3: the peer asked that this field never be put into an
    /// index, by any intermediary, ever. Preserved so a proxy can honour it.
    never_indexed: bool = false,

    /// RFC 7541 §4.1: the size an entry accounts for, the 32 covering per-entry
    /// overhead so that a table of many tiny entries cannot be unbounded.
    pub fn size(field: Field) u32 {
        return @intCast(field.name.len + field.value.len + entry_overhead);
    }
};

pub const entry_overhead = 32;

/// Bounds on one header block. Every one of these is a published denial-of-service
/// class rather than a tuning knob; see the module comment.
pub const Limits = struct {
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`, charged per field while decoding.
    max_header_list_size: u32 = 32 * 1024,
    /// Longest single name or value, checked before the string is materialized.
    max_string_len: u32 = 8 * 1024,
    /// Most fields one block may carry.
    max_fields: u32 = 128,
};

// -- Primitives ------------------------------------------------------------

/// A cursor over a header block. Every read is bounds-checked, and running out of
/// bytes mid-instruction is a compression error rather than a partial decode: a
/// header block is delivered whole, after `CONTINUATION` reassembly, so a short
/// read means the peer lied about a length.
pub const Cursor = struct {
    bytes: []const u8,
    index: usize = 0,

    pub fn remaining(cursor: Cursor) usize {
        return cursor.bytes.len - cursor.index;
    }

    pub fn isEmpty(cursor: Cursor) bool {
        return cursor.index >= cursor.bytes.len;
    }

    fn byte(cursor: *Cursor) Error!u8 {
        if (cursor.index >= cursor.bytes.len) return error.CompressionError;
        defer cursor.index += 1;
        return cursor.bytes[cursor.index];
    }

    fn take(cursor: *Cursor, n: usize) Error![]const u8 {
        if (cursor.remaining() < n) return error.CompressionError;
        defer cursor.index += n;
        return cursor.bytes[cursor.index..][0..n];
    }
};

/// RFC 7541 §5.1. `prefix_bits` is how many low bits of the first byte carry the
/// value; the first byte has already been read and is passed as `first`.
pub fn decodeInteger(cursor: *Cursor, first: u8, prefix_bits: u4) Error!u32 {
    const max_prefix: u32 = (@as(u32, 1) << prefix_bits) - 1;
    var value: u32 = first & @as(u8, @intCast(max_prefix));
    if (value < max_prefix) return value;

    // Continuation octets, seven bits each. Five of them would already exceed
    // 32 bits, so the shift is bounded before it can overflow — an unbounded
    // loop here is how an integer-overflow bug becomes a remote crash.
    var shift: u5 = 0;
    while (true) {
        const octet = try cursor.byte();
        const chunk: u32 = octet & 0x7f;
        if (shift >= 32) return error.CompressionError;
        const shifted = @shlWithOverflow(chunk, shift);
        if (shifted[1] != 0) return error.CompressionError;
        value = std.math.add(u32, value, shifted[0]) catch return error.CompressionError;
        if (octet & 0x80 == 0) break;
        shift += 7;
    }
    return value;
}

/// The number of bytes `encodeInteger` will write for `value`.
pub fn encodedIntegerLen(value: u32, prefix_bits: u4) usize {
    const max_prefix: u32 = (@as(u32, 1) << prefix_bits) - 1;
    if (value < max_prefix) return 1;
    var rest = value - max_prefix;
    var len: usize = 1;
    while (rest >= 0x80) : (rest >>= 7) len += 1;
    return len + 1;
}

/// RFC 7541 §5.1. `flags` are the bits above the prefix, already positioned.
pub fn encodeInteger(out: []u8, flags: u8, value: u32, prefix_bits: u4) []u8 {
    const max_prefix: u32 = (@as(u32, 1) << prefix_bits) - 1;
    assert(flags & @as(u8, @intCast(max_prefix)) == 0);

    if (value < max_prefix) {
        out[0] = flags | @as(u8, @intCast(value));
        return out[0..1];
    }
    out[0] = flags | @as(u8, @intCast(max_prefix));
    var rest = value - max_prefix;
    var written: usize = 1;
    while (rest >= 0x80) : (rest >>= 7) {
        out[written] = @as(u8, @truncate(rest)) | 0x80;
        written += 1;
    }
    out[written] = @truncate(rest);
    return out[0 .. written + 1];
}

/// RFC 7541 §5.2. Returns a slice owned by `arena`, or borrowed from the block
/// when it was not Huffman-coded and `borrow_plain` is set.
fn decodeString(
    cursor: *Cursor,
    arena: Allocator,
    limits: Limits,
    borrow_plain: bool,
) (Error || Allocator.Error)![]const u8 {
    const first = try cursor.byte();
    const is_huffman = first & 0x80 != 0;
    const len = try decodeInteger(cursor, first, 7);
    if (len > limits.max_string_len) return error.LimitExceeded;

    const raw = try cursor.take(len);
    if (!is_huffman) {
        return if (borrow_plain) raw else try arena.dupe(u8, raw);
    }

    // The decoded length is computed first so the allocation is exact and the
    // limit is checked before any of it is written. Huffman reaches about 8.5:1,
    // so the encoded length says nothing useful about the decoded one.
    const decoded_len = huffman.decodedLen(raw) catch return error.CompressionError;
    if (decoded_len > limits.max_string_len) return error.LimitExceeded;
    const out = try arena.alloc(u8, decoded_len);
    const written = huffman.decode(out, raw) catch return error.CompressionError;
    assert(written.len == decoded_len);
    return written;
}

// -- The static table ------------------------------------------------------

/// RFC 7541 Appendix A. Index 0 is unused, so entry *n* sits at `static[n - 1]`.
pub const static = [_]Field{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

pub const static_count: u32 = static.len;

/// Finds `name`/`value` in the static table. Returns an exact match if there is
/// one, otherwise the first entry with a matching name, which is what lets a
/// literal reuse an index for its name alone.
fn findStatic(name: []const u8, value: []const u8) struct { index: u32, exact: bool } {
    var name_only: u32 = 0;
    for (static, 1..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (std.mem.eql(u8, entry.value, value)) return .{ .index = @intCast(index), .exact = true };
        if (name_only == 0) name_only = @intCast(index);
    }
    return .{ .index = name_only, .exact = false };
}

// -- The dynamic table -----------------------------------------------------

/// RFC 7541 §2.3.2: a FIFO of the entries most recently inserted, addressed from
/// the newest, bounded by a byte size the peer controls through
/// `SETTINGS_HEADER_TABLE_SIZE` and the encoder through a size update.
pub const DynamicTable = struct {
    /// Newest first, so entry index 0 is HPACK index `static_count + 1`.
    entries: std.ArrayList(Owned) = .empty,
    /// Sum of `Field.size` over `entries`.
    size: u32 = 0,
    /// The current agreed capacity, which a size update may change.
    capacity: u32 = 0,
    /// The ceiling on `capacity`, from the settings the decoder announced. An
    /// update above this is a compression error, not a clamp: RFC 7541 §6.3 is
    /// explicit that the encoder must not exceed what it was told.
    max_capacity: u32 = 0,

    const Owned = struct {
        name: []u8,
        value: []u8,

        fn field(owned: Owned) Field {
            return .{ .name = owned.name, .value = owned.value };
        }
    };

    pub fn deinit(table: *DynamicTable, gpa: Allocator) void {
        for (table.entries.items) |entry| {
            gpa.free(entry.name);
            gpa.free(entry.value);
        }
        table.entries.deinit(gpa);
        table.* = .{};
    }

    pub fn count(table: *const DynamicTable) u32 {
        return @intCast(table.entries.items.len);
    }

    /// `index` counts from the newest entry, zero-based.
    pub fn at(table: *const DynamicTable, index: u32) ?Field {
        if (index >= table.entries.items.len) return null;
        return table.entries.items[index].field();
    }

    /// RFC 7541 §4.3. Evicting to fit is the caller's obligation, so this both
    /// evicts and inserts.
    pub fn insert(table: *DynamicTable, gpa: Allocator, field: Field) Allocator.Error!void {
        const needed = field.size();

        // §4.4: an entry larger than the whole capacity is not an error — the
        // table is emptied and the entry simply is not added.
        if (needed > table.capacity) {
            table.evictAll(gpa);
            return;
        }
        while (table.size + needed > table.capacity) table.evictOldest(gpa);

        const name = try gpa.dupe(u8, field.name);
        errdefer gpa.free(name);
        const value = try gpa.dupe(u8, field.value);
        errdefer gpa.free(value);
        try table.entries.insert(gpa, 0, .{ .name = name, .value = value });
        table.size += needed;
    }

    fn evictOldest(table: *DynamicTable, gpa: Allocator) void {
        assert(table.entries.items.len > 0);
        const evicted = table.entries.pop().?;
        table.size -= @intCast(evicted.name.len + evicted.value.len + entry_overhead);
        gpa.free(evicted.name);
        gpa.free(evicted.value);
    }

    fn evictAll(table: *DynamicTable, gpa: Allocator) void {
        while (table.entries.items.len > 0) table.evictOldest(gpa);
        assert(table.size == 0);
    }

    /// RFC 7541 §6.3, a dynamic table size update.
    pub fn setCapacity(table: *DynamicTable, gpa: Allocator, new_capacity: u32) Error!void {
        if (new_capacity > table.max_capacity) return error.CompressionError;
        table.capacity = new_capacity;
        while (table.size > table.capacity) table.evictOldest(gpa);
    }

    /// Raises the ceiling, as the peer's new settings allow. The current capacity
    /// is left alone: it changes only when the encoder says so.
    pub fn setMaxCapacity(table: *DynamicTable, gpa: Allocator, new_max: u32) void {
        table.max_capacity = new_max;
        if (table.capacity > new_max) {
            table.capacity = new_max;
            while (table.size > table.capacity) table.evictOldest(gpa);
        }
    }

    fn find(table: *const DynamicTable, name: []const u8, value: []const u8) struct {
        index: u32,
        exact: bool,
    } {
        var name_only: u32 = 0;
        for (table.entries.items, 0..) |entry, index| {
            if (!std.mem.eql(u8, entry.name, name)) continue;
            const hpack_index: u32 = static_count + 1 + @as(u32, @intCast(index));
            if (std.mem.eql(u8, entry.value, value)) return .{ .index = hpack_index, .exact = true };
            if (name_only == 0) name_only = hpack_index;
        }
        return .{ .index = name_only, .exact = false };
    }
};

// -- Decoding --------------------------------------------------------------

/// Decodes header blocks, carrying the dynamic table between them.
///
/// One decoder belongs to one direction of one connection and must see every
/// block in order: HPACK is stateful, so a block skipped or decoded twice
/// desynchronizes the table and every later block decodes to nonsense. RFC 9113
/// §4.3 is why that has to be a connection error rather than a stream one.
pub const Decoder = struct {
    table: DynamicTable = .{},

    /// `max_capacity` is what this side announced as
    /// `SETTINGS_HEADER_TABLE_SIZE`; the peer may size its table anywhere up to it.
    pub fn init(max_capacity: u32) Decoder {
        return .{ .table = .{ .capacity = max_capacity, .max_capacity = max_capacity } };
    }

    pub fn deinit(decoder: *Decoder, gpa: Allocator) void {
        decoder.table.deinit(gpa);
    }

    /// Announces a new `SETTINGS_HEADER_TABLE_SIZE`. Lowering it takes effect
    /// immediately; the peer will acknowledge with a size update of its own.
    pub fn setMaxCapacity(decoder: *Decoder, gpa: Allocator, new_max: u32) void {
        decoder.table.setMaxCapacity(gpa, new_max);
    }

    /// Decodes a whole reassembled header block, appending to `out`. Names and
    /// values are allocated from `arena` except where they name a static entry,
    /// whose strings are program constants and so can be borrowed safely.
    pub fn decode(
        decoder: *Decoder,
        gpa: Allocator,
        arena: Allocator,
        block: []const u8,
        out: *std.ArrayList(Field),
        limits: Limits,
    ) (Error || Allocator.Error)!void {
        var cursor: Cursor = .{ .bytes = block };
        var list_size: u32 = 0;
        // §4.2: a size update is only legal at the very start of a block.
        var updates_allowed = true;

        while (!cursor.isEmpty()) {
            const first = try cursor.byte();

            if (first & 0x80 != 0) {
                // §6.1: indexed header field.
                const index = try decodeInteger(&cursor, first, 7);
                const field = try decoder.resolve(index);
                try decoder.emit(arena, out, field, &list_size, limits);
                updates_allowed = false;
                continue;
            }

            if (first & 0x40 != 0) {
                // §6.2.1: literal with incremental indexing.
                const field = try decoder.literal(&cursor, arena, first, 6, limits);
                try decoder.table.insert(gpa, field);
                try decoder.emit(arena, out, field, &list_size, limits);
                updates_allowed = false;
                continue;
            }

            if (first & 0x20 != 0) {
                // §6.3: dynamic table size update. Legal only before any field,
                // because the encoder has to make its change before it starts
                // referring to entries the change may have evicted.
                if (!updates_allowed) return error.CompressionError;
                const new_capacity = try decodeInteger(&cursor, first, 5);
                try decoder.table.setCapacity(gpa, new_capacity);
                continue;
            }

            // §6.2.2 and §6.2.3: literal without indexing, and never indexed.
            // They differ only in what an intermediary is allowed to do later, so
            // the flag is carried on the field rather than acted on here.
            const never_indexed = first & 0x10 != 0;
            var field = try decoder.literal(&cursor, arena, first, 4, limits);
            field.never_indexed = never_indexed;
            try decoder.emit(arena, out, field, &list_size, limits);
            updates_allowed = false;
        }
    }

    /// RFC 7541 §2.3.3: one index space, static first, then the dynamic table
    /// newest-first.
    fn resolve(decoder: *const Decoder, index: u32) Error!Field {
        // §6.1: index zero is not a valid entry.
        if (index == 0) return error.CompressionError;
        if (index <= static_count) return static[index - 1];
        return decoder.table.at(index - static_count - 1) orelse error.CompressionError;
    }

    fn literal(
        decoder: *const Decoder,
        cursor: *Cursor,
        arena: Allocator,
        first: u8,
        prefix_bits: u4,
        limits: Limits,
    ) (Error || Allocator.Error)!Field {
        const name_index = try decodeInteger(cursor, first, prefix_bits);
        const name = if (name_index == 0)
            try decodeString(cursor, arena, limits, false)
        else
            (try decoder.resolve(name_index)).name;
        const value = try decodeString(cursor, arena, limits, false);
        return .{ .name = name, .value = value };
    }

    fn emit(
        _: *const Decoder,
        arena: Allocator,
        out: *std.ArrayList(Field),
        field: Field,
        list_size: *u32,
        limits: Limits,
    ) (Error || Allocator.Error)!void {
        if (out.items.len >= limits.max_fields) return error.LimitExceeded;
        list_size.* = std.math.add(u32, list_size.*, field.size()) catch
            return error.LimitExceeded;
        if (list_size.* > limits.max_header_list_size) return error.LimitExceeded;

        // The dynamic table can evict this entry while a later field in the same
        // block is decoded, so what leaves here must not point into it. Static
        // entries are program constants and need no copy; a literal was already
        // put in the arena by `decodeString`.
        try out.append(arena, .{
            .name = try dupeUnlessStatic(arena, field.name),
            .value = try dupeUnlessStatic(arena, field.value),
            .never_indexed = field.never_indexed,
        });
    }
};

/// Copies unless the slice is one of the static table's own strings, which live
/// for the life of the program.
fn dupeUnlessStatic(arena: Allocator, slice: []const u8) Allocator.Error![]const u8 {
    for (static) |entry| {
        if (slice.ptr == entry.name.ptr and slice.len == entry.name.len) return slice;
        if (slice.ptr == entry.value.ptr and slice.len == entry.value.len) return slice;
    }
    return arena.dupe(u8, slice);
}

// -- Encoding --------------------------------------------------------------

const Buffer = @import("../../buffer.zig").Buffer;

/// Encodes header blocks, carrying the dynamic table between them.
///
/// The strategy is Netty's default and is deliberately simple: index what is
/// already indexed, otherwise emit a literal and index it, and Huffman-code a
/// string only when that makes it shorter. A cleverer encoder buys bytes, not
/// correctness, and every choice here is one the decoder cannot tell apart.
pub const Encoder = struct {
    table: DynamicTable = .{},
    /// Set when a size update has to be emitted before the next block.
    pending_capacity: ?u32 = null,

    pub fn init(capacity: u32) Encoder {
        return .{ .table = .{ .capacity = capacity, .max_capacity = capacity } };
    }

    pub fn deinit(encoder: *Encoder, gpa: Allocator) void {
        encoder.table.deinit(gpa);
    }

    /// Adopts the capacity the peer announced in its `SETTINGS_HEADER_TABLE_SIZE`.
    /// The change is announced on the wire before the next block, because the
    /// decoder has to apply it at the same point in the stream.
    pub fn setPeerCapacity(encoder: *Encoder, gpa: Allocator, new_capacity: u32) void {
        encoder.table.max_capacity = new_capacity;
        const target = @min(new_capacity, encoder.table.capacity);
        encoder.table.capacity = target;
        while (encoder.table.size > encoder.table.capacity) encoder.table.evictOldest(gpa);
        encoder.pending_capacity = target;
    }

    /// Appends one header block. Fields whose `never_indexed` is set are emitted
    /// so that no intermediary may index them either (§6.2.3), which is what makes
    /// the flag worth carrying through a decode.
    pub fn encode(
        encoder: *Encoder,
        out: *Buffer,
        gpa: Allocator,
        fields: []const Field,
    ) !void {
        var scratch: [8]u8 = undefined;

        if (encoder.pending_capacity) |capacity| {
            // §6.3: 001 prefix, five bits of value.
            try out.writeBytes(gpa, encodeInteger(&scratch, 0x20, capacity, 5));
            encoder.pending_capacity = null;
        }

        for (fields) |field| {
            const in_static = findStatic(field.name, field.value);
            const in_dynamic = encoder.table.find(field.name, field.value);

            if (field.never_indexed) {
                // §6.2.3: 0001 prefix. A name index may still be used; it is the
                // value that must not be indexed.
                const name_index = if (in_static.index != 0) in_static.index else in_dynamic.index;
                try out.writeBytes(gpa, encodeInteger(&scratch, 0x10, name_index, 4));
                if (name_index == 0) try writeString(out, gpa, field.name);
                try writeString(out, gpa, field.value);
                continue;
            }

            if (in_static.exact) {
                // §6.1: 1 prefix, seven bits of index.
                try out.writeBytes(gpa, encodeInteger(&scratch, 0x80, in_static.index, 7));
                continue;
            }
            if (in_dynamic.exact) {
                try out.writeBytes(gpa, encodeInteger(&scratch, 0x80, in_dynamic.index, 7));
                continue;
            }

            // §6.2.1: 01 prefix, six bits of name index.
            const name_index = if (in_static.index != 0) in_static.index else in_dynamic.index;
            try out.writeBytes(gpa, encodeInteger(&scratch, 0x40, name_index, 6));
            if (name_index == 0) try writeString(out, gpa, field.name);
            try writeString(out, gpa, field.value);
            try encoder.table.insert(gpa, field);
        }
    }
};

fn writeString(out: *Buffer, gpa: Allocator, source: []const u8) !void {
    var scratch: [8]u8 = undefined;
    const packed_len = huffman.encodedLen(source);
    if (packed_len < source.len) {
        try out.writeBytes(gpa, encodeInteger(&scratch, 0x80, @intCast(packed_len), 7));
        const dest = try out.reserve(gpa, packed_len);
        const written = huffman.encode(dest, source);
        assert(written.len == packed_len);
    } else {
        try out.writeBytes(gpa, encodeInteger(&scratch, 0x00, @intCast(source.len), 7));
        try out.writeBytes(gpa, source);
    }
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "hpack: the Appendix C.1 integer examples" {
    var out: [8]u8 = undefined;

    // C.1.1: ten in a five-bit prefix fits in the prefix.
    try testing.expectEqualSlices(u8, &.{0x0a}, encodeInteger(&out, 0x00, 10, 5));
    // C.1.2: 1337 in a five-bit prefix needs two continuation octets.
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, encodeInteger(&out, 0x00, 1337, 5));
    // C.1.3: 42 with the whole octet available.
    try testing.expectEqualSlices(u8, &.{0x2a}, encodeInteger(&out, 0x00, 42, 8));

    // And back, which is what the decoder actually does.
    for ([_]struct { bytes: []const u8, prefix: u4, value: u32 }{
        .{ .bytes = &.{0x0a}, .prefix = 5, .value = 10 },
        .{ .bytes = &.{ 0x1f, 0x9a, 0x0a }, .prefix = 5, .value = 1337 },
        .{ .bytes = &.{0x2a}, .prefix = 8, .value = 42 },
    }) |case| {
        var cursor: Cursor = .{ .bytes = case.bytes, .index = 1 };
        try testing.expectEqual(case.value, try decodeInteger(&cursor, case.bytes[0], case.prefix));
        try testing.expect(cursor.isEmpty());
        try testing.expectEqual(case.bytes.len, encodedIntegerLen(case.value, case.prefix));
    }
}

test "hpack: integers round trip across the prefix boundary" {
    var out: [8]u8 = undefined;
    for ([_]u4{ 4, 5, 6, 7, 8 }) |prefix| {
        const max_prefix = (@as(u32, 1) << prefix) - 1;
        for ([_]u32{ 0, 1, max_prefix - 1, max_prefix, max_prefix + 1, 127, 128, 255, 16_383, 16_384, std.math.maxInt(u32) }) |value| {
            const bytes = encodeInteger(&out, 0x00, value, prefix);
            try testing.expectEqual(bytes.len, encodedIntegerLen(value, prefix));
            var cursor: Cursor = .{ .bytes = bytes, .index = 1 };
            try testing.expectEqual(value, try decodeInteger(&cursor, bytes[0], prefix));
            try testing.expect(cursor.isEmpty());
        }
    }
}

test "hpack: a truncated or overlong integer is a compression error" {
    // The continuation bit set with nothing behind it.
    var truncated: Cursor = .{ .bytes = &.{ 0x1f, 0x80 }, .index = 1 };
    try testing.expectError(error.CompressionError, decodeInteger(&truncated, 0x1f, 5));

    // Enough continuation octets to overflow 32 bits. An unbounded shift here is
    // how a malformed length becomes a crash.
    const bomb = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
    var overflow: Cursor = .{ .bytes = &bomb, .index = 1 };
    try testing.expectError(error.CompressionError, decodeInteger(&overflow, bomb[0], 5));
}

test "hpack: the static table matches Appendix A" {
    try testing.expectEqual(@as(u32, 61), static_count);
    try testing.expectEqualStrings(":authority", static[0].name);
    try testing.expectEqualStrings("GET", static[1].value);
    try testing.expectEqualStrings("POST", static[2].value);
    try testing.expectEqualStrings("/index.html", static[4].value);
    try testing.expectEqualStrings("gzip, deflate", static[15].value);
    try testing.expectEqualStrings("www-authenticate", static[60].name);

    // The pseudo-header entries a request always uses, at the indices the wire
    // format depends on.
    try testing.expectEqual(@as(u32, 2), findStatic(":method", "GET").index);
    try testing.expect(findStatic(":method", "GET").exact);
    try testing.expectEqual(@as(u32, 6), findStatic(":scheme", "http").index);
    try testing.expectEqual(@as(u32, 4), findStatic(":path", "/").index);
    try testing.expectEqual(@as(u32, 8), findStatic(":status", "200").index);

    // A name-only hit, which is what lets a literal borrow an index.
    const authority = findStatic(":authority", "www.example.com");
    try testing.expectEqual(@as(u32, 1), authority.index);
    try testing.expect(!authority.exact);
}

fn expectDecoded(
    decoder: *Decoder,
    gpa: Allocator,
    block: []const u8,
    expected: []const Field,
) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fields: std.ArrayList(Field) = .empty;
    try decoder.decode(gpa, arena, block, &fields, .{});

    try testing.expectEqual(expected.len, fields.items.len);
    for (expected, fields.items) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
        try testing.expectEqual(want.never_indexed, got.never_indexed);
    }
}

test "hpack: the Appendix C.2 literal examples" {
    const gpa = testing.allocator;

    // C.2.1: literal with incremental indexing, a new name.
    {
        var decoder: Decoder = .init(4096);
        defer decoder.deinit(gpa);
        try expectDecoded(&decoder, gpa, "\x40\x0acustom-key\x0dcustom-header", &.{
            .{ .name = "custom-key", .value = "custom-header" },
        });
        try testing.expectEqual(@as(u32, 1), decoder.table.count());
        try testing.expectEqual(@as(u32, 55), decoder.table.size);
    }

    // C.2.2: literal without indexing, name from the static table.
    {
        var decoder: Decoder = .init(4096);
        defer decoder.deinit(gpa);
        try expectDecoded(&decoder, gpa, "\x04\x0c/sample/path", &.{
            .{ .name = ":path", .value = "/sample/path" },
        });
        // Not indexed, so the table stays empty.
        try testing.expectEqual(@as(u32, 0), decoder.table.count());
    }

    // C.2.3: literal never indexed, which must survive as a flag.
    {
        var decoder: Decoder = .init(4096);
        defer decoder.deinit(gpa);
        try expectDecoded(&decoder, gpa, "\x10\x08password\x06secret", &.{
            .{ .name = "password", .value = "secret", .never_indexed = true },
        });
        try testing.expectEqual(@as(u32, 0), decoder.table.count());
    }

    // C.2.4: indexed header field.
    {
        var decoder: Decoder = .init(4096);
        defer decoder.deinit(gpa);
        try expectDecoded(&decoder, gpa, "\x82", &.{.{ .name = ":method", .value = "GET" }});
    }
}

test "hpack: the Appendix C.3 request sequence, and the table after each step" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(4096);
    defer decoder.deinit(gpa);

    // C.3.1
    try expectDecoded(&decoder, gpa, "\x82\x86\x84\x41\x0fwww.example.com", &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    });
    try testing.expectEqual(@as(u32, 57), decoder.table.size);
    try testing.expectEqualStrings(":authority", decoder.table.at(0).?.name);

    // C.3.2: 0xbe is index 62, the entry just added.
    try expectDecoded(&decoder, gpa, "\x82\x86\x84\xbe\x58\x08no-cache", &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    });
    try testing.expectEqual(@as(u32, 110), decoder.table.size);
    try testing.expectEqualStrings("cache-control", decoder.table.at(0).?.name);
    try testing.expectEqualStrings(":authority", decoder.table.at(1).?.name);

    // C.3.3
    try expectDecoded(
        &decoder,
        gpa,
        "\x82\x87\x85\xbf\x40\x0acustom-key\x0ccustom-value",
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "custom-key", .value = "custom-value" },
        },
    );
    try testing.expectEqual(@as(u32, 164), decoder.table.size);
    try testing.expectEqual(@as(u32, 3), decoder.table.count());
    try testing.expectEqualStrings("custom-key", decoder.table.at(0).?.name);
}

test "hpack: the Appendix C.4 sequence, the same requests Huffman-coded" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(4096);
    defer decoder.deinit(gpa);

    try expectDecoded(
        &decoder,
        gpa,
        "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "www.example.com" },
        },
    );
    try testing.expectEqual(@as(u32, 57), decoder.table.size);

    try expectDecoded(&decoder, gpa, "\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf", &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    });
    try testing.expectEqual(@as(u32, 110), decoder.table.size);

    try expectDecoded(
        &decoder,
        gpa,
        "\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf",
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = ":authority", .value = "www.example.com" },
            .{ .name = "custom-key", .value = "custom-value" },
        },
    );
    try testing.expectEqual(@as(u32, 164), decoder.table.size);
}

test "hpack: the Appendix C.5 response sequence exercises eviction" {
    const gpa = testing.allocator;
    // The example negotiates a 256-byte table, which is what forces the evictions
    // the third response depends on.
    var decoder: Decoder = .init(256);
    defer decoder.deinit(gpa);

    try expectDecoded(
        &decoder,
        gpa,
        "\x48\x03302\x58\x07private\x61\x1dMon, 21 Oct 2013 20:13:21 GMT" ++
            "\x6e\x17https://www.example.com",
        &.{
            .{ .name = ":status", .value = "302" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
        },
    );
    try testing.expectEqual(@as(u32, 222), decoder.table.size);
    try testing.expectEqual(@as(u32, 4), decoder.table.count());

    // The second response replaces :status, and adding it evicts the oldest.
    try expectDecoded(&decoder, gpa, "\x48\x03307\xc1\xc0\xbf", &.{
        .{ .name = ":status", .value = "307" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    });
    try testing.expectEqual(@as(u32, 222), decoder.table.size);
    try testing.expectEqualStrings("307", decoder.table.at(0).?.value);

    // The third adds two entries and evicts three, leaving the table holding only
    // what the RFC says it should.
    try expectDecoded(
        &decoder,
        gpa,
        "\x88\xc1\x61\x1dMon, 21 Oct 2013 20:13:22 GMT\xc0" ++
            "\x5a\x04gzip" ++
            "\x77\x38foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "cache-control", .value = "private" },
            .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
            .{ .name = "location", .value = "https://www.example.com" },
            .{ .name = "content-encoding", .value = "gzip" },
            .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
        },
    );
    try testing.expectEqual(@as(u32, 215), decoder.table.size);
    try testing.expectEqual(@as(u32, 3), decoder.table.count());
    try testing.expectEqualStrings("set-cookie", decoder.table.at(0).?.name);
    try testing.expectEqualStrings("content-encoding", decoder.table.at(1).?.name);
    try testing.expectEqualStrings("date", decoder.table.at(2).?.name);
}

test "hpack: the encoder produces the Appendix C.4 bytes" {
    const gpa = testing.allocator;
    var encoder: Encoder = .init(4096);
    defer encoder.deinit(gpa);
    var out: Buffer = .empty;
    defer out.deinit(gpa);

    // C.4 rather than C.3: Huffman is used whenever it is shorter, and for
    // "www.example.com" it saves three bytes.
    try encoder.encode(&out, gpa, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    });
    try testing.expectEqualSlices(
        u8,
        "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
        out.readableSlice(),
    );
    try testing.expectEqual(@as(u32, 57), encoder.table.size);

    // C.4.2: the authority is now in the dynamic table, so it costs one byte.
    out.clear();
    try encoder.encode(&out, gpa, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "cache-control", .value = "no-cache" },
    });
    try testing.expectEqualSlices(
        u8,
        "\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf",
        out.readableSlice(),
    );
    try testing.expectEqual(@as(u32, 110), encoder.table.size);
}

test "hpack: encoder and decoder agree, dynamic table and all" {
    const gpa = testing.allocator;
    var encoder: Encoder = .init(4096);
    defer encoder.deinit(gpa);
    var decoder: Decoder = .init(4096);
    defer decoder.deinit(gpa);

    // Several blocks in sequence, because the tables only diverge over time: a
    // single block would pass even if insertion were broken on one side.
    const blocks = [_][]const Field{
        &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/upload" },
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "authorization", .value = "Bearer abc.def", .never_indexed = true },
        },
        &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/upload" },
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "x-trace", .value = "0123456789abcdef" },
        },
        &.{
            .{ .name = "x-trace", .value = "0123456789abcdef" },
            .{ .name = ":status", .value = "200" },
            .{ .name = "\xc3\xa9-utf8", .value = "\xff\xfe binary \x00" },
        },
    };

    for (blocks) |fields| {
        var out: Buffer = .empty;
        defer out.deinit(gpa);
        try encoder.encode(&out, gpa, fields);
        try expectDecoded(&decoder, gpa, out.readableSlice(), fields);
        // The two tables must stay byte-for-byte in step, which is the property
        // that makes HPACK usable at all.
        try testing.expectEqual(encoder.table.size, decoder.table.size);
        try testing.expectEqual(encoder.table.count(), decoder.table.count());
    }
}

test "hpack: a size update is honoured, and only at the start of a block" {
    const gpa = testing.allocator;

    {
        var decoder: Decoder = .init(4096);
        defer decoder.deinit(gpa);
        // 0x3f 0xe1 0x1f is a size update to 4096; 0x20 is one to zero, which
        // §4.3 uses to clear the table.
        try expectDecoded(&decoder, gpa, "\x40\x0acustom-key\x0ccustom-value", &.{
            .{ .name = "custom-key", .value = "custom-value" },
        });
        try testing.expectEqual(@as(u32, 1), decoder.table.count());

        try expectDecoded(&decoder, gpa, "\x20", &.{});
        try testing.expectEqual(@as(u32, 0), decoder.table.count());
        try testing.expectEqual(@as(u32, 0), decoder.table.capacity);
    }

    // §6.3: above what was announced is a compression error, not a clamp.
    {
        var decoder: Decoder = .init(256);
        defer decoder.deinit(gpa);
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        var fields: std.ArrayList(Field) = .empty;
        // A size update to 4096 when only 256 was announced.
        try testing.expectError(error.CompressionError, decoder.decode(
            gpa,
            arena_state.allocator(),
            "\x3f\xe1\x1f",
            &fields,
            .{},
        ));
    }

    // §4.2: a size update after a field has been emitted is a compression error.
    {
        var decoder: Decoder = .init(4096);
        defer decoder.deinit(gpa);
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        var fields: std.ArrayList(Field) = .empty;
        try testing.expectError(error.CompressionError, decoder.decode(
            gpa,
            arena_state.allocator(),
            "\x82\x20",
            &fields,
            .{},
        ));
    }
}

test "hpack: an entry larger than the table empties it rather than failing" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(64);
    defer decoder.deinit(gpa);

    try expectDecoded(&decoder, gpa, "\x40\x02aa\x02bb", &.{.{ .name = "aa", .value = "bb" }});
    try testing.expectEqual(@as(u32, 1), decoder.table.count());

    // §4.4: an entry that cannot fit is not an error; the table is emptied and
    // the entry is simply not added, and the field is still delivered.
    const long_value: [40]u8 = @splat('x');
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(gpa);
    try block.appendSlice(gpa, "\x40\x02cc\x28");
    try block.appendSlice(gpa, &long_value);
    try expectDecoded(&decoder, gpa, block.items, &.{
        .{ .name = "cc", .value = &long_value },
    });
    try testing.expectEqual(@as(u32, 0), decoder.table.count());
    try testing.expectEqual(@as(u32, 0), decoder.table.size);
}

test "hpack: an index that names nothing is a compression error" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(4096);
    defer decoder.deinit(gpa);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    for ([_][]const u8{
        // §6.1: index zero.
        "\x80",
        // Past the end of the static table with an empty dynamic table.
        "\xbe",
        // A name index that names nothing, in a literal.
        "\x7f\x00\x02aa",
        // Truncated: a string length with nothing behind it.
        "\x40\x0acustom",
        // Truncated: an instruction with no value at all.
        "\x40",
    }) |block| {
        var fields: std.ArrayList(Field) = .empty;
        try testing.expectError(
            error.CompressionError,
            decoder.decode(gpa, arena, block, &fields, .{}),
        );
    }
}

test "hpack: the header-list limit is charged while decoding" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(4096);
    defer decoder.deinit(gpa);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `:method GET` is one byte on the wire and 42 bytes of header list — 7 for
    // the name, 3 for the value, 32 of per-entry overhead — so a four-byte block
    // names 168 bytes of list. Charging per field is what makes the limit
    // meaningful; checking the total afterwards would mean having already built it.
    var fields: std.ArrayList(Field) = .empty;
    try testing.expectError(error.LimitExceeded, decoder.decode(
        gpa,
        arena,
        "\x82\x82\x82\x82",
        &fields,
        .{ .max_header_list_size = 2 * 42 },
    ));
    // Exactly two fitted, and the third stopped the decode where it stood.
    try testing.expectEqual(@as(usize, 2), fields.items.len);

    // The field count is bounded separately, because many tiny fields cost little
    // header-list size but still cost a slot each.
    var many: std.ArrayList(Field) = .empty;
    try testing.expectError(error.LimitExceeded, decoder.decode(
        gpa,
        arena,
        "\x82\x82\x82",
        &many,
        .{ .max_fields = 2 },
    ));
    try testing.expectEqual(@as(usize, 2), many.items.len);
}

test "hpack: a long string is refused before it is materialized" {
    const gpa = testing.allocator;
    var decoder: Decoder = .init(4096);
    defer decoder.deinit(gpa);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A plain literal whose declared length exceeds the limit. The bytes are not
    // even present, which is the point: the length is checked first, so a peer
    // cannot make us reserve for a string it never sends.
    var fields: std.ArrayList(Field) = .empty;
    try testing.expectError(error.LimitExceeded, decoder.decode(
        gpa,
        arena,
        "\x40\x7f\x81\x00",
        &fields,
        .{ .max_string_len = 16 },
    ));
}
