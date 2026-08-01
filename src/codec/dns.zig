//! DNS, RFC 1035, on the wire.
//!
//! `std.Io` has no resolver, so every client in this repository asks the caller
//! for an address. That is honest but inconvenient, and this is the missing
//! piece: a codec here, a resolver on a datagram endpoint in `dns/resolver.zig`.
//!
//! Netty has `codec-dns` and `resolver-dns`, and the split is the same one — the
//! wire format knows nothing about sockets or timeouts.
//!
//! **Name compression is where this format is dangerous.** §4.1.4 lets a name end
//! in a pointer to an earlier offset, which means a name can be arbitrarily
//! indirected, can point forward, and can point at itself. A parser that follows
//! pointers without a budget can be sent into an infinite loop by two bytes, and
//! one that allows forward pointers can be made to loop between two names that
//! each point at the other. Both are refused here, and the bound is explicit:
//! `max_pointer_hops`.
//!
//! Everything else about the format is small: a twelve-byte header, four sections
//! of counted records, and names as length-prefixed labels.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const resolver = @import("dns/resolver.zig");

pub const Error = error{
    /// Ran out of bytes mid-record.
    Truncated,
    /// A label longer than §2.3.4's 63 octets, or a name longer than 255.
    NameTooLong,
    /// A compression pointer that goes forward, points at itself, or exceeds
    /// `max_pointer_hops`.
    BadCompression,
    /// A record whose RDATA length disagrees with its type (an A record that is
    /// not four bytes, for instance).
    BadRecord,
    /// More records than `max_records`.
    TooManyRecords,
    /// The output buffer is too small.
    BufferTooSmall,
};

/// §2.3.4: a label is at most 63 octets and a name at most 255, both on the wire.
pub const max_label_len = 63;
pub const max_name_len = 255;
/// How many compression pointers one name may follow. §4.1.4 sets no limit, so
/// this is one: a legitimate name needs one or two, and a hostile one needs no
/// bound at all to hang a parser.
pub const max_pointer_hops = 16;
/// The largest number of records this parses from one message. A bound rather
/// than a guess: the counts in the header are attacker-controlled, and a parser
/// that allocated from them would allocate whatever it was told to.
pub const max_records = 64;
/// §4.2.1: the classic limit on a UDP DNS message without EDNS(0).
pub const max_udp_message = 512;
/// With EDNS(0) (RFC 6891) a larger one may be advertised; this is what we ask
/// for, chosen to stay under the usual path MTU so that a reply does not
/// fragment.
pub const edns_udp_size = 1232;

pub const Opcode = enum(u4) {
    query = 0,
    inverse_query = 1,
    status = 2,
    _,
};

/// §4.1.1's RCODE. The names are the RFC's; `refused` and `name_error` are the
/// two a caller actually branches on.
pub const ResponseCode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    /// NXDOMAIN: the name does not exist. Distinct from "exists but has no
    /// record of this type", which is `no_error` with an empty answer section —
    /// a distinction that matters, because only the first is cacheable as
    /// "absent".
    name_error = 3,
    not_implemented = 4,
    refused = 5,
    _,
};

pub const Type = enum(u16) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    ptr = 12,
    mx = 15,
    txt = 16,
    aaaa = 28,
    srv = 33,
    opt = 41,
    any = 255,
    _,
};

pub const Class = enum(u16) {
    in = 1,
    any = 255,
    _,
};

/// §4.1.1's header, as fields rather than as bit arithmetic.
pub const Header = struct {
    id: u16,
    /// Whether this is a response.
    response: bool = false,
    opcode: Opcode = .query,
    /// Set by a server that is authoritative for the name.
    authoritative: bool = false,
    /// §4.1.1's TC bit: the reply did not fit. What makes TCP fallback
    /// necessary, and the reason a resolver cannot treat UDP as sufficient.
    truncated: bool = false,
    recursion_desired: bool = true,
    recursion_available: bool = false,
    response_code: ResponseCode = .no_error,
    question_count: u16 = 0,
    answer_count: u16 = 0,
    authority_count: u16 = 0,
    additional_count: u16 = 0,

    pub const wire_len = 12;

    pub fn encode(header: Header, dest: *[wire_len]u8) void {
        std.mem.writeInt(u16, dest[0..2], header.id, .big);
        var flags: u16 = 0;
        if (header.response) flags |= 0x8000;
        flags |= @as(u16, @backingInt(header.opcode)) << 11;
        if (header.authoritative) flags |= 0x0400;
        if (header.truncated) flags |= 0x0200;
        if (header.recursion_desired) flags |= 0x0100;
        if (header.recursion_available) flags |= 0x0080;
        flags |= @backingInt(header.response_code);
        std.mem.writeInt(u16, dest[2..4], flags, .big);
        std.mem.writeInt(u16, dest[4..6], header.question_count, .big);
        std.mem.writeInt(u16, dest[6..8], header.answer_count, .big);
        std.mem.writeInt(u16, dest[8..10], header.authority_count, .big);
        std.mem.writeInt(u16, dest[10..12], header.additional_count, .big);
    }

    pub fn decode(bytes: *const [wire_len]u8) Header {
        const flags = std.mem.readInt(u16, bytes[2..4], .big);
        return .{
            .id = std.mem.readInt(u16, bytes[0..2], .big),
            .response = flags & 0x8000 != 0,
            .opcode = @fromBackingInt(@intCast(@as(u4, @truncate(flags >> 11)))),
            .authoritative = flags & 0x0400 != 0,
            .truncated = flags & 0x0200 != 0,
            .recursion_desired = flags & 0x0100 != 0,
            .recursion_available = flags & 0x0080 != 0,
            .response_code = @fromBackingInt(@intCast(@as(u4, @truncate(flags)))),
            .question_count = std.mem.readInt(u16, bytes[4..6], .big),
            .answer_count = std.mem.readInt(u16, bytes[6..8], .big),
            .authority_count = std.mem.readInt(u16, bytes[8..10], .big),
            .additional_count = std.mem.readInt(u16, bytes[10..12], .big),
        };
    }
};

/// A domain name in presentation form ("www.example.com"), owned by whoever
/// parsed it.
///
/// Stored decompressed on purpose: a name that is a pointer into the message it
/// came from is a name that stops being valid when the message buffer is reused,
/// which is the borrowed-buffer defect this repository has hit four times.
pub const Name = struct {
    /// Room for the longest name plus the dots. A fixed array rather than an
    /// allocation: a name is bounded by the format itself, so the bound belongs
    /// in the type.
    bytes: [max_name_len]u8 = undefined,
    len: usize = 0,

    pub fn init(text: []const u8) Error!Name {
        if (text.len > max_name_len) return error.NameTooLong;
        var name: Name = .{ .len = text.len };
        @memcpy(name.bytes[0..text.len], text);
        return name;
    }

    pub fn slice(name: *const Name) []const u8 {
        return name.bytes[0..name.len];
    }

    /// Case-insensitive, because §2.3.3 says comparisons are.
    pub fn eqlText(name: *const Name, text: []const u8) bool {
        if (name.len != text.len) return false;
        for (name.slice(), text) |a, b| {
            if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
        }
        return true;
    }
};

pub const Question = struct {
    name: Name,
    type: Type,
    class: Class = .in,
};

/// One resource record. The payload is a tagged union rather than raw RDATA for
/// the types worth understanding, and raw for the rest — a resolver that had to
/// re-parse RDATA at every call site would parse it inconsistently.
pub const Record = struct {
    name: Name,
    type: Type,
    class: Class,
    ttl: u32,
    data: Data,

    pub const Data = union(enum) {
        a: [4]u8,
        aaaa: [16]u8,
        /// CNAME, NS and PTR are all a single name.
        name: Name,
        /// MX, with its preference.
        mx: struct { preference: u16, exchange: Name },
        /// Everything else, borrowed from the message being parsed. Valid only
        /// until that buffer is reused — which is why the types above are not
        /// left in here.
        raw: []const u8,
    };
};

/// A parsed message. Bounded arrays rather than allocations: every count comes
/// from the peer, and the whole point of a bound is that the peer cannot choose
/// it.
pub const Message = struct {
    header: Header,
    questions: [max_records]Question = undefined,
    question_len: usize = 0,
    answers: [max_records]Record = undefined,
    answer_len: usize = 0,
    authorities: [max_records]Record = undefined,
    authority_len: usize = 0,
    additionals: [max_records]Record = undefined,
    additional_len: usize = 0,

    pub fn questionSlice(self: *const Message) []const Question {
        return self.questions[0..self.question_len];
    }

    pub fn answerSlice(self: *const Message) []const Record {
        return self.answers[0..self.answer_len];
    }
};

/// Write a name as length-prefixed labels (§3.1), returning the bytes written.
///
/// Never compressed. A query has one name, so compression would save nothing, and
/// a resolver that emitted pointers into its own message would be inventing
/// complexity for a saving of zero bytes.
pub fn encodeName(dest: []u8, text: []const u8) Error!usize {
    var cursor: usize = 0;
    var rest = text;
    // A trailing dot is the root and is already implied by the terminator.
    if (rest.len > 0 and rest[rest.len - 1] == '.') rest = rest[0 .. rest.len - 1];

    while (rest.len > 0) {
        const dot = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
        const label = rest[0..dot];
        if (label.len == 0) return error.BadRecord; // an empty label mid-name
        if (label.len > max_label_len) return error.NameTooLong;
        if (cursor + 1 + label.len + 1 > dest.len) return error.BufferTooSmall;
        dest[cursor] = @intCast(label.len);
        cursor += 1;
        @memcpy(dest[cursor..][0..label.len], label);
        cursor += label.len;
        rest = if (dot == rest.len) rest[dot..] else rest[dot + 1 ..];
    }

    if (cursor + 1 > dest.len) return error.BufferTooSmall;
    dest[cursor] = 0; // the root label
    cursor += 1;
    if (cursor > max_name_len + 1) return error.NameTooLong;
    return cursor;
}

/// A cursor over a message, which is what name decompression needs: a pointer is
/// an offset into the whole message, not into the remaining bytes.
const Cursor = struct {
    message: []const u8,
    at: usize,

    fn need(self: *Cursor, n: usize) Error![]const u8 {
        if (self.at + n > self.message.len) return error.Truncated;
        const out = self.message[self.at..][0..n];
        self.at += n;
        return out;
    }

    fn u16be(self: *Cursor) Error!u16 {
        const bytes = try self.need(2);
        return std.mem.readInt(u16, bytes[0..2], .big);
    }

    fn u32be(self: *Cursor) Error!u32 {
        const bytes = try self.need(4);
        return std.mem.readInt(u32, bytes[0..4], .big);
    }
};

/// Read a name, following compression pointers (§4.1.4).
///
/// Two rules make this safe, and both are needed:
///
/// * **A pointer must go backwards.** A forward pointer allows two names to point
///   at each other, which is a loop no hop budget catches quickly and which no
///   legitimate encoder produces — compression exists to refer to something
///   already written.
/// * **A bounded number of hops.** Even going strictly backwards, a chain can be
///   as long as the message, and a message can be full of them.
fn decodeName(cursor: *Cursor) Error!Name {
    var name: Name = .{};
    var hops: usize = 0;
    var at = cursor.at;
    // Where the caller resumes: past the *first* pointer, since everything after
    // it belongs to whatever the pointer referenced.
    var resume_at: ?usize = null;

    while (true) {
        if (at >= cursor.message.len) return error.Truncated;
        const length = cursor.message[at];

        if (length & 0xc0 == 0xc0) {
            // A pointer: two bytes, fourteen bits of offset.
            if (at + 2 > cursor.message.len) return error.Truncated;
            const target = (@as(u16, length & 0x3f) << 8) | cursor.message[at + 1];
            if (resume_at == null) resume_at = at + 2;
            if (target >= at) return error.BadCompression; // must go backwards
            hops += 1;
            if (hops > max_pointer_hops) return error.BadCompression;
            at = target;
            continue;
        }
        if (length & 0xc0 != 0) return error.BadCompression; // reserved label type
        if (length > max_label_len) return error.NameTooLong;

        at += 1;
        if (length == 0) break; // the root label ends the name

        if (at + length > cursor.message.len) return error.Truncated;
        // The separating dot, except before the first label.
        const need = length + @as(usize, if (name.len == 0) 0 else 1);
        if (name.len + need > max_name_len) return error.NameTooLong;
        if (name.len != 0) {
            name.bytes[name.len] = '.';
            name.len += 1;
        }
        @memcpy(name.bytes[name.len..][0..length], cursor.message[at..][0..length]);
        name.len += length;
        at += length;
    }

    cursor.at = resume_at orelse at;
    return name;
}

/// Parse a whole message.
pub fn decode(bytes: []const u8) Error!Message {
    if (bytes.len < Header.wire_len) return error.Truncated;
    const header = Header.decode(bytes[0..Header.wire_len]);
    var message: Message = .{ .header = header };

    var cursor: Cursor = .{ .message = bytes, .at = Header.wire_len };

    if (header.question_count > max_records) return error.TooManyRecords;
    for (0..header.question_count) |_| {
        const name = try decodeName(&cursor);
        const kind = try cursor.u16be();
        const class = try cursor.u16be();
        message.questions[message.question_len] = .{
            .name = name,
            .type = @fromBackingInt(@intCast(kind)),
            .class = @fromBackingInt(@intCast(class)),
        };
        message.question_len += 1;
    }

    // The three record sections, filled in order. Reading all three matters even
    // when only answers are wanted: a CNAME chain can put the useful record in
    // the answer section while the authority section explains a negative reply.
    const sections = [_]struct { count: u16, target: *[max_records]Record, len: *usize }{
        .{ .count = header.answer_count, .target = &message.answers, .len = &message.answer_len },
        .{ .count = header.authority_count, .target = &message.authorities, .len = &message.authority_len },
        .{ .count = header.additional_count, .target = &message.additionals, .len = &message.additional_len },
    };
    for (sections) |section| {
        if (section.count > max_records) return error.TooManyRecords;
        for (0..section.count) |_| {
            section.target[section.len.*] = try decodeRecord(&cursor);
            section.len.* += 1;
        }
    }

    return message;
}

fn decodeRecord(cursor: *Cursor) Error!Record {
    const name = try decodeName(cursor);
    const kind: Type = @fromBackingInt(@intCast(try cursor.u16be()));
    const class: Class = @fromBackingInt(@intCast(try cursor.u16be()));
    const ttl = try cursor.u32be();
    const rdlength = try cursor.u16be();

    const rdata_start = cursor.at;
    const rdata = try cursor.need(rdlength);

    const data: Record.Data = switch (kind) {
        .a => blk: {
            // A record that is not four bytes is not an A record, whatever it
            // says. Guessing here would mean handing an address made of
            // whatever was next in the buffer to a caller about to connect to it.
            if (rdata.len != 4) return error.BadRecord;
            break :blk .{ .a = rdata[0..4].* };
        },
        .aaaa => blk: {
            if (rdata.len != 16) return error.BadRecord;
            break :blk .{ .aaaa = rdata[0..16].* };
        },
        .cname, .ns, .ptr => blk: {
            // Parsed from a cursor of its own, positioned at the RDATA: names
            // inside RDATA may themselves be compressed, and pointers are
            // relative to the message rather than to the record.
            var inner: Cursor = .{ .message = cursor.message, .at = rdata_start };
            break :blk .{ .name = try decodeName(&inner) };
        },
        .mx => blk: {
            if (rdata.len < 3) return error.BadRecord;
            var inner: Cursor = .{ .message = cursor.message, .at = rdata_start };
            const preference = try inner.u16be();
            break :blk .{ .mx = .{ .preference = preference, .exchange = try decodeName(&inner) } };
        },
        else => .{ .raw = rdata },
    };

    return .{ .name = name, .type = kind, .class = class, .ttl = ttl, .data = data };
}

pub const QueryOptions = struct {
    id: u16,
    type: Type,
    class: Class = .in,
    recursion_desired: bool = true,
    /// Whether to append an EDNS(0) OPT record advertising a larger UDP payload
    /// (RFC 6891). Worth doing: without it the answer is capped at 512 bytes and
    /// anything larger comes back truncated, forcing a TCP retry.
    edns: bool = true,
};

/// Write a query for one name.
pub fn encodeQuery(dest: []u8, name: []const u8, options: QueryOptions) Error!usize {
    if (dest.len < Header.wire_len) return error.BufferTooSmall;
    var header: Header = .{
        .id = options.id,
        .recursion_desired = options.recursion_desired,
        .question_count = 1,
        .additional_count = if (options.edns) 1 else 0,
    };
    header.encode(dest[0..Header.wire_len]);
    var cursor: usize = Header.wire_len;

    cursor += try encodeName(dest[cursor..], name);
    if (cursor + 4 > dest.len) return error.BufferTooSmall;
    std.mem.writeInt(u16, dest[cursor..][0..2], @backingInt(options.type), .big);
    cursor += 2;
    std.mem.writeInt(u16, dest[cursor..][0..2], @backingInt(options.class), .big);
    cursor += 2;

    if (options.edns) {
        // RFC 6891 §6.1.2: an OPT pseudo-record. Its name is root, its CLASS
        // field carries the UDP payload size we can accept, and its TTL carries
        // flags we set to zero.
        if (cursor + 11 > dest.len) return error.BufferTooSmall;
        dest[cursor] = 0; // root name
        cursor += 1;
        std.mem.writeInt(u16, dest[cursor..][0..2], @backingInt(Type.opt), .big);
        cursor += 2;
        std.mem.writeInt(u16, dest[cursor..][0..2], edns_udp_size, .big);
        cursor += 2;
        std.mem.writeInt(u32, dest[cursor..][0..4], 0, .big); // extended rcode + version + flags
        cursor += 4;
        std.mem.writeInt(u16, dest[cursor..][0..2], 0, .big); // no options
        cursor += 2;
    }

    return cursor;
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test {
    // Without this the resolver's own tests never run. They did not, for a
    // while: a mutation that removed the resolver's canonical-name check left
    // the suite green, and the reason turned out to be that five tests were
    // silently absent rather than that they were weak.
    _ = resolver;
}

test "dns: a query round-trips through its own decoder" {
    var buf: [512]u8 = undefined;
    const len = try encodeQuery(&buf, "www.example.com", .{ .id = 0x1234, .type = .a });
    const message = try decode(buf[0..len]);

    try testing.expectEqual(@as(u16, 0x1234), message.header.id);
    try testing.expect(!message.header.response);
    try testing.expect(message.header.recursion_desired);
    try testing.expectEqual(@as(usize, 1), message.question_len);
    try testing.expect(message.questions[0].name.eqlText("www.example.com"));
    try testing.expectEqual(Type.a, message.questions[0].type);
    // The EDNS(0) OPT record went in the additional section.
    try testing.expectEqual(@as(usize, 1), message.additional_len);
    try testing.expectEqual(Type.opt, message.additionals[0].type);
}

test "dns: a trailing dot and mixed case survive the round trip" {
    var buf: [512]u8 = undefined;
    const len = try encodeQuery(&buf, "Example.COM.", .{ .id = 1, .type = .aaaa, .edns = false });
    const message = try decode(buf[0..len]);
    // §2.3.3: comparison is case-insensitive, and the case that was sent is what
    // comes back — servers echo the question verbatim.
    try testing.expect(message.questions[0].name.eqlText("example.com"));
    try testing.expect(message.questions[0].name.eqlText("EXAMPLE.COM"));
    try testing.expectEqual(@as(usize, 0), message.additional_len);
}

test "dns: an oversized label and an empty one are refused" {
    var buf: [512]u8 = undefined;
    const long: [64]u8 = @splat('a');
    var long_name: [68]u8 = undefined;
    @memcpy(long_name[0..64], &long);
    @memcpy(long_name[64..68], ".com");
    try testing.expectError(error.NameTooLong, encodeName(&buf, &long_name));
    // An empty label mid-name is not the root and cannot be encoded.
    try testing.expectError(error.BadRecord, encodeName(&buf, "www..com"));
}

test "dns: a response with A records decodes, compression and all" {
    // Built by hand so the compression pointer is real: the answer's name points
    // back at the question's, which is what every server actually does.
    var buf: [512]u8 = undefined;
    var header: Header = .{
        .id = 0xabcd,
        .response = true,
        .recursion_available = true,
        .question_count = 1,
        .answer_count = 2,
    };
    header.encode(buf[0..Header.wire_len]);
    var cursor: usize = Header.wire_len;
    const name_offset = cursor;
    cursor += try encodeName(buf[cursor..], "example.com");
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Type.a), .big);
    cursor += 2;
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Class.in), .big);
    cursor += 2;

    for ([_][4]u8{ .{ 93, 184, 216, 34 }, .{ 93, 184, 216, 35 } }) |address| {
        // The pointer: 0xc0 plus the offset of the question's name.
        buf[cursor] = 0xc0 | @as(u8, @intCast(name_offset >> 8));
        buf[cursor + 1] = @intCast(name_offset & 0xff);
        cursor += 2;
        std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Type.a), .big);
        cursor += 2;
        std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Class.in), .big);
        cursor += 2;
        std.mem.writeInt(u32, buf[cursor..][0..4], 300, .big);
        cursor += 4;
        std.mem.writeInt(u16, buf[cursor..][0..2], 4, .big);
        cursor += 2;
        @memcpy(buf[cursor..][0..4], &address);
        cursor += 4;
    }

    const message = try decode(buf[0..cursor]);
    try testing.expectEqual(@as(usize, 2), message.answer_len);
    // Decompressed, so the name is usable after the buffer is gone.
    try testing.expect(message.answers[0].name.eqlText("example.com"));
    try testing.expectEqual([4]u8{ 93, 184, 216, 34 }, message.answers[0].data.a);
    try testing.expectEqual([4]u8{ 93, 184, 216, 35 }, message.answers[1].data.a);
    try testing.expectEqual(@as(u32, 300), message.answers[0].ttl);
}

test "dns: a compression pointer that loops is refused rather than followed" {
    // Two bytes are enough to hang a parser that follows pointers without rules.
    // A pointer to itself:
    var buf: [64]u8 = undefined;
    var header: Header = .{ .id = 1, .response = true, .question_count = 1 };
    header.encode(buf[0..Header.wire_len]);
    buf[12] = 0xc0;
    buf[13] = 12; // points at itself
    try testing.expectError(error.BadCompression, decode(buf[0..14]));

    // A pointer forward. The buffer is zeroed first, and that is the point of the
    // test: the target is then a valid root label, so the name would parse
    // perfectly well and the hop budget would never be reached. Only the "must go
    // backwards" rule rejects this — and it must, because a forward pointer is how
    // two names come to point at each other.
    //
    // Written the weak way first, with an uninitialised buffer, this test passed
    // even with the rule removed: the forward target happened to hold bytes that
    // looked like another pointer, and the hop budget caught it instead.
    @memset(&buf, 0);
    var zeroed: Header = .{ .id = 1, .response = true, .question_count = 1 };
    zeroed.encode(buf[0..Header.wire_len]);
    buf[12] = 0xc0;
    buf[13] = 20;
    buf[20] = 0; // a root label: a perfectly valid name to point at
    // The question needs its type and class after the name for the parse to get
    // that far, so the failure is about the pointer and nothing else.
    buf[22] = 0;
    buf[23] = 1;
    buf[24] = 0;
    buf[25] = 1;
    try testing.expectError(error.BadCompression, decode(buf[0..26]));

    // And a reserved label type (0x80) is not a length either.
    @memset(&buf, 0);
    zeroed.encode(buf[0..Header.wire_len]);
    buf[12] = 0x80;
    try testing.expectError(error.BadCompression, decode(buf[0..14]));
}

test "dns: a long backwards chain is refused by the hop budget" {
    // Strictly backwards, so the "must go backwards" rule allows every hop; only
    // the budget stops it. Built as a ladder of pointers each aimed at the one
    // before, which is legal at every individual step.
    var buf: [256]u8 = undefined;
    @memset(&buf, 0);
    var header: Header = .{ .id = 1, .response = true, .question_count = 1 };
    header.encode(buf[0..Header.wire_len]);

    // A real name at the very end, and a chain of pointers back to front.
    const chain_start = Header.wire_len;
    const hops = max_pointer_hops + 4;
    var i: usize = 0;
    while (i < hops) : (i += 1) {
        const at = chain_start + i * 2;
        const target = if (i == 0) chain_start + hops * 2 else chain_start + (i - 1) * 2;
        _ = target;
        // Each points at the previous slot, so following from the last one walks
        // the whole ladder.
        const previous = if (i == 0) chain_start else chain_start + (i - 1) * 2;
        buf[at] = 0xc0 | @as(u8, @intCast(previous >> 8));
        buf[at + 1] = @intCast(previous & 0xff);
    }
    // Parsing starts at the last link, so it walks back through all of them.
    var last_header: Header = .{ .id = 1, .response = true, .question_count = 1 };
    last_header.encode(buf[0..Header.wire_len]);
    const err = decode(buf[0 .. chain_start + hops * 2]);
    try testing.expectError(error.BadCompression, err);
}

test "dns: an A record whose RDATA is the wrong length is refused" {
    // The alternative is handing four bytes of whatever came next to a caller
    // about to connect to them.
    var buf: [128]u8 = undefined;
    var header: Header = .{ .id = 2, .response = true, .answer_count = 1 };
    header.encode(buf[0..Header.wire_len]);
    var cursor: usize = Header.wire_len;
    cursor += try encodeName(buf[cursor..], "h.test");
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Type.a), .big);
    cursor += 2;
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Class.in), .big);
    cursor += 2;
    std.mem.writeInt(u32, buf[cursor..][0..4], 60, .big);
    cursor += 4;
    const rdlength_at = cursor;
    std.mem.writeInt(u16, buf[cursor..][0..2], 3, .big); // three bytes, not four
    cursor += 2;
    @memcpy(buf[cursor..][0..3], "abc");
    cursor += 3;
    try testing.expectError(error.BadRecord, decode(buf[0..cursor]));

    // And too *many* bytes, which is the direction a length check written as
    // "at least four" would let through — taking the first four and ignoring the
    // rest, which is to say inventing an address the server did not send.
    std.mem.writeInt(u16, buf[rdlength_at..][0..2], 6, .big);
    @memcpy(buf[rdlength_at + 2 ..][0..6], "abcdef");
    try testing.expectError(error.BadRecord, decode(buf[0 .. rdlength_at + 8]));
}

test "dns: a truncated message is reported rather than half-parsed" {
    var buf: [512]u8 = undefined;
    const len = try encodeQuery(&buf, "www.example.com", .{ .id = 3, .type = .a });
    // Every prefix short of the whole thing must fail, and none may loop.
    var cut: usize = 0;
    while (cut < len) : (cut += 1) {
        const result = decode(buf[0..cut]);
        try testing.expect(std.meta.isError(result));
    }
    _ = try decode(buf[0..len]);
}

test "dns: header flags survive encoding, including TC" {
    // The truncation bit is the one a resolver must not lose: it is what says
    // "this answer is incomplete, ask over TCP".
    const original: Header = .{
        .id = 0x7f7f,
        .response = true,
        .authoritative = true,
        .truncated = true,
        .recursion_desired = true,
        .recursion_available = true,
        .response_code = .name_error,
        .question_count = 1,
        .answer_count = 2,
        .authority_count = 3,
        .additional_count = 4,
    };
    var bytes: [Header.wire_len]u8 = undefined;
    original.encode(&bytes);
    const decoded = Header.decode(&bytes);
    try testing.expectEqual(original, decoded);
    try testing.expect(decoded.truncated);
    try testing.expectEqual(ResponseCode.name_error, decoded.response_code);
}

test "dns: a CNAME chain and its target both decode" {
    var buf: [512]u8 = undefined;
    var header: Header = .{ .id = 5, .response = true, .question_count = 1, .answer_count = 2 };
    header.encode(buf[0..Header.wire_len]);
    var cursor: usize = Header.wire_len;
    const question_at = cursor;
    cursor += try encodeName(buf[cursor..], "alias.test");
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Type.a), .big);
    cursor += 2;
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Class.in), .big);
    cursor += 2;

    // CNAME alias.test -> real.test
    buf[cursor] = 0xc0 | @as(u8, @intCast(question_at >> 8));
    buf[cursor + 1] = @intCast(question_at & 0xff);
    cursor += 2;
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Type.cname), .big);
    cursor += 2;
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Class.in), .big);
    cursor += 2;
    std.mem.writeInt(u32, buf[cursor..][0..4], 60, .big);
    cursor += 4;
    var target_buf: [64]u8 = undefined;
    const target_len = try encodeName(&target_buf, "real.test");
    std.mem.writeInt(u16, buf[cursor..][0..2], @intCast(target_len), .big);
    cursor += 2;
    const target_at = cursor;
    @memcpy(buf[cursor..][0..target_len], target_buf[0..target_len]);
    cursor += target_len;

    // A real.test -> 10.0.0.1, its name a pointer into the CNAME's RDATA. This is
    // the case that makes RDATA names need their own cursor: the pointer is
    // relative to the message, not to the record.
    buf[cursor] = 0xc0 | @as(u8, @intCast(target_at >> 8));
    buf[cursor + 1] = @intCast(target_at & 0xff);
    cursor += 2;
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Type.a), .big);
    cursor += 2;
    std.mem.writeInt(u16, buf[cursor..][0..2], @backingInt(Class.in), .big);
    cursor += 2;
    std.mem.writeInt(u32, buf[cursor..][0..4], 60, .big);
    cursor += 4;
    std.mem.writeInt(u16, buf[cursor..][0..2], 4, .big);
    cursor += 2;
    @memcpy(buf[cursor..][0..4], &[4]u8{ 10, 0, 0, 1 });
    cursor += 4;

    const message = try decode(buf[0..cursor]);
    try testing.expectEqual(@as(usize, 2), message.answer_len);
    try testing.expectEqual(Type.cname, message.answers[0].type);
    try testing.expect(message.answers[0].data.name.eqlText("real.test"));
    try testing.expect(message.answers[1].name.eqlText("real.test"));
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, message.answers[1].data.a);
}

test "dns: record counts beyond the bound are refused rather than trusted" {
    // The counts are the peer's to state, so they are checked before anything is
    // read from them.
    var buf: [Header.wire_len]u8 = undefined;
    var header: Header = .{ .id = 6, .response = true, .answer_count = max_records + 1 };
    header.encode(&buf);
    try testing.expectError(error.TooManyRecords, decode(&buf));
}
