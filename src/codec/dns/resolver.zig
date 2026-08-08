//! A DNS resolver on a datagram endpoint.
//!
//! `std.Io` has no resolver, so every client in this repository takes an address
//! rather than a host name. This is what closes that gap — and it is deliberately
//! a small resolver rather than a caching one: it asks a server, waits, retries,
//! and returns addresses.
//!
//! Three things it does that a naive one does not, each because leaving it out is
//! a real defect rather than a missing feature:
//!
//! * **The transaction ID is random and checked**, along with the question. An
//!   off-path attacker who can guess the ID can answer before the real server
//!   does, and that is the whole of cache poisoning. The ID comes from the
//!   injected `Io`, like every other source of randomness here.
//! * **A reply from the wrong address is ignored.** One socket receives from
//!   anybody; a resolver that trusted whatever arrived would accept an answer
//!   from anyone who guessed the port.
//! * **Truncation is reported rather than silently accepted.** §4.1.1's TC bit
//!   means the answer is incomplete. EDNS(0) makes it rare, and TCP fallback —
//!   which this does not do — is the general answer; returning a partial answer as
//!   though it were whole is the one thing that must not happen.
//!
//! Retries are bounded and the whole operation has a deadline, because a resolver
//! that can block forever is a client that can hang on a name.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const dns = @import("../dns.zig");

pub const Error = error{
    /// No server answered within the deadline.
    Timeout,
    /// The name does not exist (NXDOMAIN).
    NameNotFound,
    /// The name exists but has no record of the requested type. Distinct from
    /// `NameNotFound` because only the latter means "try something else
    /// entirely" — this one means the host has no address of this family.
    NoAddress,
    /// The server refused, failed, or answered something unusable.
    ServerFailure,
    /// The reply did not fit in a datagram and TCP fallback is not implemented.
    Truncated,
} || dns.Error;

/// How many addresses one lookup returns. Bounded like everything else: a name
/// can legitimately have dozens, and a hostile server can claim more.
pub const max_addresses = 16;

pub const Options = struct {
    gpa: Allocator,
    io: Io,
    /// The servers to ask, in order. No default: a resolver that guessed
    /// 8.8.8.8 would send every name a program looks up to a third party without
    /// the application having chosen that.
    servers: []const Io.net.IpAddress,
    /// How long to wait for one server before moving to the next.
    per_query_timeout: Io.Duration = .fromMilliseconds(2000),
    /// How many times to ask each server. §4.2.1 leaves retransmission to the
    /// resolver; a datagram can be lost, and one retry catches nearly all of it.
    attempts: usize = 2,
    /// Which address families to ask for, in order of preference.
    families: []const Family = &.{ .ip4, .ip6 },
    /// Whether a truncated datagram reply is retried over TCP.
    ///
    /// §4.2.1 caps a UDP message and sets TC when the answer did not fit; §4.2.2 defines the
    /// stream form that has no such cap. Without the retry a name with more records than fit
    /// simply fails, which makes the resolver unusable for exactly the names that need it —
    /// and the failure looks like a broken server rather than an unimplemented transport.
    tcp_fallback: bool = true,
    /// The largest stream reply this resolver will read. §4.2.2's length prefix is sixteen
    /// bits, so a server may announce up to 64 KiB; this is the ceiling on what will be
    /// allocated to hold one, because "the peer said so" is not a bound.
    max_tcp_reply: usize = 16 * 1024,
};

pub const Family = enum {
    ip4,
    ip6,

    fn recordType(self: Family) dns.Type {
        return switch (self) {
            .ip4 => .a,
            .ip6 => .aaaa,
        };
    }
};

pub const Answer = struct {
    addresses: [max_addresses]Io.net.IpAddress = undefined,
    len: usize = 0,
    /// The smallest TTL among the records, which is how long the whole answer is
    /// good for. The minimum rather than the maximum: an answer is only as fresh
    /// as its stalest part.
    ttl: u32 = 0,
    /// The name the addresses actually belong to, after any CNAME. Worth
    /// reporting: a caller doing TLS needs the name it asked for, not this one,
    /// and having both makes that choice visible.
    canonical: dns.Name = .{},

    pub fn slice(self: *const Answer) []const Io.net.IpAddress {
        return self.addresses[0..self.len];
    }
};

pub const Resolver = struct {
    gpa: Allocator,
    io: Io,
    options: Options,

    pub fn init(options: Options) Resolver {
        assert(options.servers.len > 0);
        assert(options.attempts > 0);
        return .{ .gpa = options.gpa, .io = options.io, .options = options };
    }

    /// Resolve `host` to addresses, trying each family in the configured order.
    ///
    /// A literal address is returned as itself without a query, which is what
    /// makes this safe to call unconditionally: an application should not have to
    /// decide whether its configuration holds a name or an address.
    pub fn resolve(self: *Resolver, host: []const u8, port: u16) Error!Answer {
        if (parseLiteral(host, port)) |literal| {
            var answer: Answer = .{ .len = 1, .ttl = 0 };
            answer.addresses[0] = literal;
            answer.canonical = dns.Name.init(host) catch return error.NameTooLong;
            return answer;
        }

        var last_error: Error = error.Timeout;
        for (self.options.families) |family| {
            const result = self.query(host, port, family) catch |err| {
                switch (err) {
                    // A name that does not exist will not exist for the other
                    // family either, so there is nothing to try.
                    error.NameNotFound => return err,
                    // No record of *this* type is an ordinary answer; try the next
                    // family before giving up.
                    error.NoAddress => {
                        last_error = err;
                        continue;
                    },
                    else => {
                        last_error = err;
                        continue;
                    },
                }
            };
            if (result.len > 0) return result;
            last_error = error.NoAddress;
        }
        return last_error;
    }

    /// One question, asked of each server in turn until one answers.
    pub fn query(self: *Resolver, host: []const u8, port: u16, family: Family) Error!Answer {
        var attempt: usize = 0;
        while (attempt < self.options.attempts) : (attempt += 1) {
            for (self.options.servers) |server| {
                const outcome = self.ask(server, host, port, family) catch |err| switch (err) {
                    // A lost datagram or a slow server: try the next one, then
                    // come round again.
                    error.Timeout => continue,
                    // These are answers, not failures to get one. Returning
                    // immediately matters: asking another server the same question
                    // and believing a different answer is how a resolver ends up
                    // choosing whichever server lies fastest.
                    error.NameNotFound, error.NoAddress => return err,
                    // Truncation belongs with those rather than with a lost datagram: it is
                    // a fact about the answer, and asking the same server again gets the same
                    // TC bit. It reaches here only when `tcp_fallback` is off, since
                    // otherwise §4.2.2's transport has already been tried.
                    //
                    // It used to fall into the branch below, which means `error.Truncated`
                    // was documented in this file's error set and unreachable through its
                    // public API: every truncated answer was reported as `error.Timeout`. So
                    // the old behaviour was not "fail with Truncated" but "fail with the
                    // wrong error", which is worth knowing when judging what the retry is
                    // worth.
                    error.Truncated => return err,
                    else => continue,
                };
                return outcome;
            }
        }
        return error.Timeout;
    }

    fn ask(
        self: *Resolver,
        server: Io.net.IpAddress,
        host: []const u8,
        port: u16,
        family: Family,
    ) Error!Answer {
        // A fresh transaction ID per attempt, from the injected CSPRNG. Reusing
        // one across retries would let an attacker who saw the first attempt
        // answer the second.
        var id_bytes: [2]u8 = undefined;
        self.io.randomSecure(&id_bytes) catch return error.ServerFailure;
        const id = std.mem.readInt(u16, &id_bytes, .big);

        var out: [dns.max_udp_message]u8 = undefined;
        const query_len = try dns.encodeQuery(&out, host, .{
            .id = id,
            .type = family.recordType(),
        });

        // A socket per query. Wasteful in principle and correct in practice: the
        // source port is then unpredictable too, which is the other half of the
        // defence the transaction ID provides (RFC 5452).
        var bind: Io.net.IpAddress = switch (server) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        var socket = bind.bind(self.io, .{ .mode = .dgram }) catch return error.ServerFailure;
        defer socket.close(self.io);

        var destination = server;
        socket.send(self.io, &destination, out[0..query_len]) catch return error.ServerFailure;

        const deadline = Io.Timestamp.now(self.io, .awake)
            .addDuration(self.options.per_query_timeout);

        // Loop rather than take the first datagram: an unsolicited or spoofed
        // reply must not consume the attempt, or an attacker able to send one
        // packet could make every lookup fail.
        while (true) {
            if (Io.Timestamp.now(self.io, .awake).nanoseconds >= deadline.nanoseconds) {
                return error.Timeout;
            }

            var scratch: [dns.edns_udp_size]u8 = undefined;
            var incoming: Io.net.IncomingMessage = .init;
            const result = self.io.operateTimeout(.{ .net_receive = .{
                .socket_handle = socket.handle,
                .message_buffer = (&incoming)[0..1],
                .data_buffer = &scratch,
                .flags = .{},
            } }, .{ .deadline = deadline.withClock(.awake) }) catch return error.Timeout;
            const maybe_err, _ = result.net_receive;
            if (maybe_err != null) return error.Timeout;
            if (incoming.data.len == 0) continue;

            // From the server we asked, or not at all. One socket receives from
            // anybody, so without this check an answer from whoever guessed the
            // port would be believed — and the port is the only thing an
            // off-path attacker has to guess once the ID is in hand.
            if (!sameAddress(incoming.from, server)) continue;

            const message = dns.decode(incoming.data) catch continue;
            if (!answersOurQuestion(&message, id, host, family)) continue;

            // Only now is the reply ours to believe.
            if (message.header.truncated) {
                // §4.2.1: the answer did not fit in a datagram. §4.2.2's stream transport is
                // where it does fit, and asking again there is the whole remedy — the query
                // is identical, including its transaction ID, because this is the same
                // question to the same server by another road.
                if (!self.options.tcp_fallback) return error.Truncated;
                return self.askOverStream(server, out[0..query_len], id, host, port, family);
            }
            switch (message.header.response_code) {
                .no_error => {},
                .name_error => return error.NameNotFound,
                else => return error.ServerFailure,
            }

            return collect(&message, host, port, family);
        }
    }

    /// Asks `server` the same question over TCP, which is where an answer too large for a
    /// datagram fits (§4.2.2).
    ///
    /// The reply is framed by a two-byte big-endian length that excludes itself, so the read is
    /// two reads: the prefix, then exactly that many bytes. Bounded by `max_tcp_reply`, because
    /// the prefix is a claim by the peer and sixteen bits of it.
    ///
    /// Everything after decoding is the datagram path's logic, deliberately: this is a different
    /// transport for the same question, not a different question. A second copy of "is this our
    /// reply" is how the two would come to disagree.
    /// Fills `dest` from `stream`, giving up at `deadline` rather than trusting the peer to
    /// send what it announced.
    ///
    /// `net_receive` is the one operation `std.Io` offers that takes a deadline, which is why
    /// this reads through it rather than through a `Reader`: on this path a bounded read is
    /// worth more than a buffered one, and the messages are small.
    fn readStreamBytes(
        self: *Resolver,
        stream: *Io.net.Stream,
        dest: []u8,
        deadline: Io.Timestamp,
    ) Error!void {
        const io = self.options.io;
        var filled: usize = 0;
        while (filled < dest.len) {
            if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) {
                return error.Timeout;
            }
            var incoming: Io.net.IncomingMessage = .init;
            const result = io.operateTimeout(.{ .net_receive = .{
                .socket_handle = stream.socket.handle,
                .message_buffer = (&incoming)[0..1],
                .data_buffer = dest[filled..],
                .flags = .{},
            } }, .{ .deadline = deadline.withClock(.awake) }) catch return error.Timeout;
            const maybe_err, _ = result.net_receive;
            if (maybe_err != null) return error.ServerFailure;
            // Zero bytes on a stream is the orderly close: the server ended the connection
            // without sending what it said it would.
            if (incoming.data.len == 0) return error.ServerFailure;
            filled += incoming.data.len;
        }
    }

    fn askOverStream(
        self: *Resolver,
        server: Io.net.IpAddress,
        question_bytes: []const u8,
        id: u16,
        host: []const u8,
        port: u16,
        family: Family,
    ) Error!Answer {
        const io = self.options.io;
        const gpa = self.options.gpa;

        var address = server;
        var stream = address.connect(io, .{ .mode = .stream }) catch return error.ServerFailure;
        defer stream.close(io);

        const deadline = Io.Timestamp.now(io, .awake).addDuration(self.options.per_query_timeout);

        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(question_bytes.len), .big);

        var write_buffer: [dns.max_udp_message + 2]u8 = undefined;
        var writer = stream.writer(io, &write_buffer);
        writer.interface.writeAll(&length_prefix) catch return error.ServerFailure;
        writer.interface.writeAll(question_bytes) catch return error.ServerFailure;
        writer.interface.flush() catch return error.ServerFailure;

        // Every read is bounded by the one deadline computed above. Checking the clock *after*
        // reading — which is how this was written first — is not a bound at all: a server that
        // announces sixty thousand bytes and sends a hundred leaves the resolver blocked
        // forever, and the check it never reaches is the one that would have caught it. The
        // fault was found by mutating the length ceiling and watching the suite wedge rather
        // than fail.
        var prefix_bytes: [2]u8 = undefined;
        try self.readStreamBytes(&stream, &prefix_bytes, deadline);
        const announced = std.mem.readInt(u16, &prefix_bytes, .big);
        if (announced == 0) return error.ServerFailure;
        if (announced > self.options.max_tcp_reply) return error.Truncated;

        const reply = gpa.alloc(u8, announced) catch return error.ServerFailure;
        defer gpa.free(reply);
        try self.readStreamBytes(&stream, reply, deadline);

        const message = dns.decode(reply) catch return error.ServerFailure;
        if (!answersOurQuestion(&message, id, host, family)) return error.ServerFailure;
        // TC on a stream reply means the server could not fit the answer in 64 KiB either, which
        // is not something another transport fixes.
        if (message.header.truncated) return error.Truncated;
        switch (message.header.response_code) {
            .no_error => {},
            .name_error => return error.NameNotFound,
            else => return error.ServerFailure,
        }
        return collect(&message, host, port, family);
    }
};

/// Whether a decoded reply is an answer to the question this query asked.
///
/// One predicate rather than a run of `continue`s in the receive loop, because every one
/// of these conditions is the same rule — "this is our reply" — and a rule with one
/// implementation can be tested without a socket.
///
/// Two of them were missing. The opcode was never looked at, so a STATUS or NOTIFY
/// message that happened to carry our transaction ID was read as an answer to a QUERY.
/// The question's class was never looked at either, so a reply asking about
/// `example.com A` in class CH — a different namespace that shares the name space's
/// spelling — satisfied every check we did make. Neither is a likely accident, which is
/// precisely why they are worth refusing: an off-path attacker chooses the fields nobody
/// compares.
fn answersOurQuestion(
    message: *const dns.Message,
    id: u16,
    host: []const u8,
    family: Family,
) bool {
    if (!message.header.response) return false;
    if (message.header.id != id) return false;
    // A reply to a QUERY is a QUERY (§4.1.1: the opcode is copied into the response).
    if (message.header.opcode != .query) return false;
    // The question must be the one we asked. A server that answers a different question
    // is either confused or not the server.
    if (message.question_len != 1) return false;
    if (!message.questions[0].name.eqlText(host)) return false;
    if (message.questions[0].type != family.recordType()) return false;
    if (message.questions[0].class != .in) return false;
    return true;
}

/// Pull addresses out of an answer, following the CNAME chain by name rather than
/// by position.
///
/// Following by name matters: a server may put the records in any order, and the
/// chain may be several links long. Taking every A record regardless of name would
/// accept records for names nobody asked about — which is exactly how a
/// cache-poisoning answer smuggles an address in beside a legitimate one.
fn collect(
    message: *const dns.Message,
    host: []const u8,
    port: u16,
    family: Family,
) Error!Answer {
    var answer: Answer = .{};
    answer.canonical = dns.Name.init(host) catch return error.NameTooLong;

    // Walk the CNAME chain, bounded by the number of records — a chain longer
    // than that would have to revisit a name.
    var hops: usize = 0;
    while (hops <= message.answer_len) : (hops += 1) {
        var advanced = false;
        for (message.answerSlice()) |record| {
            if (record.class != .in) continue;
            if (record.type != .cname) continue;
            if (!record.name.eqlText(answer.canonical.slice())) continue;
            answer.canonical = record.data.name;
            advanced = true;
            break;
        }
        if (!advanced) break;
    }

    var min_ttl: u32 = std.math.maxInt(u32);
    for (message.answerSlice()) |record| {
        // Class as well as type and name. We only ever ask in class IN, and a record in
        // another class is an answer about a different namespace that happens to spell its
        // names the same way — an `A` record in class CH is not an internet address, so
        // handing its four bytes to a caller about to connect is handing it a guess.
        if (record.class != .in) continue;
        if (record.type != family.recordType()) continue;
        if (!record.name.eqlText(answer.canonical.slice())) continue;
        if (answer.len == max_addresses) break;
        answer.addresses[answer.len] = switch (record.data) {
            .a => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = port } },
            .aaaa => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = port } },
            else => continue,
        };
        answer.len += 1;
        min_ttl = @min(min_ttl, record.ttl);
    }

    if (answer.len == 0) return error.NoAddress;
    answer.ttl = min_ttl;
    return answer;
}

/// An address written out, or null if `text` is a name.
fn parseLiteral(text: []const u8, port: u16) ?Io.net.IpAddress {
    if (Io.net.Ip4Address.parse(text, port)) |v4| {
        return .{ .ip4 = v4 };
    } else |_| {}
    if (Io.net.Ip6Address.parse(text, port)) |v6| {
        return .{ .ip6 = v6 };
    } else |_| {}
    return null;
}

/// Whether two addresses are the same host and port.
fn sameAddress(a: Io.net.IpAddress, b: Io.net.IpAddress) bool {
    return switch (a) {
        .ip4 => |x| switch (b) {
            .ip4 => |y| std.mem.eql(u8, &x.bytes, &y.bytes) and x.port == y.port,
            .ip6 => false,
        },
        .ip6 => |x| switch (b) {
            .ip6 => |y| std.mem.eql(u8, &x.bytes, &y.bytes) and x.port == y.port,
            .ip4 => false,
        },
    };
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const backend = @import("backend");

test "resolver: a literal address needs no query" {
    // Which is what makes it safe to call `resolve` unconditionally: an
    // application should not have to know whether its configuration holds a name.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    var r: Resolver = .init(.{
        .gpa = gpa,
        .io = threaded.io(),
        // Deliberately unreachable: if a query happened, this test would hang
        // rather than pass.
        .servers = &.{.{ .ip4 = .{ .bytes = .{ 203, 0, 113, 1 }, .port = 53 } }},
    });

    const answer = try r.resolve("127.0.0.1", 8080);
    try testing.expectEqual(@as(usize, 1), answer.len);
    try testing.expectEqual(@as(u16, 8080), answer.addresses[0].ip4.port);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, answer.addresses[0].ip4.bytes);

    const v6 = try r.resolve("::1", 443);
    try testing.expectEqual(@as(usize, 1), v6.len);
    try testing.expectEqual(@as(u16, 443), v6.addresses[0].ip6.port);
}

test "resolver: only records for the canonical name are taken" {
    // The rule that keeps a smuggled record out. Built as a reply carrying a
    // legitimate CNAME chain plus an A record for a name nobody asked about.
    const gpa = testing.allocator;
    _ = gpa;

    var message: dns.Message = .{ .header = .{ .id = 1, .response = true } };
    message.answers[0] = .{
        .name = try dns.Name.init("asked.test"),
        .type = .cname,
        .class = .in,
        .ttl = 60,
        .data = .{ .name = try dns.Name.init("real.test") },
    };
    message.answers[1] = .{
        .name = try dns.Name.init("real.test"),
        .type = .a,
        .class = .in,
        .ttl = 30,
        .data = .{ .a = .{ 10, 0, 0, 1 } },
    };
    // The interloper: a perfectly well-formed A record for something else.
    message.answers[2] = .{
        .name = try dns.Name.init("evil.test"),
        .type = .a,
        .class = .in,
        .ttl = 99999,
        .data = .{ .a = .{ 203, 0, 113, 66 } },
    };
    message.answer_len = 3;

    const answer = try collect(&message, "asked.test", 80, .ip4);
    try testing.expectEqual(@as(usize, 1), answer.len);
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, answer.addresses[0].ip4.bytes);
    try testing.expect(answer.canonical.eqlText("real.test"));
    // The TTL is the minimum among the records used, not among all of them.
    try testing.expectEqual(@as(u32, 30), answer.ttl);
}

test "resolver: a name that exists with no record of the family is not NXDOMAIN" {
    // The distinction matters: NXDOMAIN means stop, an empty answer means try the
    // other family.
    var message: dns.Message = .{ .header = .{ .id = 2, .response = true } };
    message.answers[0] = .{
        .name = try dns.Name.init("v6only.test"),
        .type = .aaaa,
        .class = .in,
        .ttl = 60,
        .data = .{ .aaaa = @splat(0) },
    };
    message.answer_len = 1;

    try testing.expectError(error.NoAddress, collect(&message, "v6only.test", 80, .ip4));
    const v6 = try collect(&message, "v6only.test", 80, .ip6);
    try testing.expectEqual(@as(usize, 1), v6.len);
}

test "resolver: a CNAME loop terminates rather than spinning" {
    // Two CNAMEs pointing at each other. A resolver that followed the chain
    // without a bound would not return.
    var message: dns.Message = .{ .header = .{ .id = 3, .response = true } };
    message.answers[0] = .{
        .name = try dns.Name.init("a.test"),
        .type = .cname,
        .class = .in,
        .ttl = 60,
        .data = .{ .name = try dns.Name.init("b.test") },
    };
    message.answers[1] = .{
        .name = try dns.Name.init("b.test"),
        .type = .cname,
        .class = .in,
        .ttl = 60,
        .data = .{ .name = try dns.Name.init("a.test") },
    };
    message.answer_len = 2;

    // No addresses, and it returns — which is the whole assertion.
    try testing.expectError(error.NoAddress, collect(&message, "a.test", 80, .ip4));
}

test "resolver: addresses beyond the bound are dropped rather than overflowing" {
    var message: dns.Message = .{ .header = .{ .id = 4, .response = true } };
    var i: usize = 0;
    while (i < max_addresses + 8) : (i += 1) {
        message.answers[i] = .{
            .name = try dns.Name.init("many.test"),
            .type = .a,
            .class = .in,
            .ttl = 10,
            .data = .{ .a = .{ 10, 0, 0, @intCast(i) } },
        };
    }
    message.answer_len = max_addresses + 8;
    const answer = try collect(&message, "many.test", 80, .ip4);
    try testing.expectEqual(@as(usize, max_addresses), answer.len);
}

/// A fake DNS server for the tests below: reads one query, answers it from
/// whichever socket it is told to.
const FakeServer = struct {
    io: Io,
    /// The socket the resolver will address.
    listener: Io.net.Socket,
    address: Io.net.IpAddress,
    /// A second socket, so a reply can arrive from the wrong place.
    other: Io.net.Socket,
    /// Whether to answer from `other` rather than from `listener`.
    answer_from_other: bool,
    answered: std.atomic.Value(bool) = .init(false),

    fn init(io: Io, answer_from_other: bool) !FakeServer {
        var bind: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const listener = try bind.bind(io, .{ .mode = .dgram });
        var other_bind: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const other = try other_bind.bind(io, .{ .mode = .dgram });
        return .{
            .io = io,
            .listener = listener,
            .address = listener.address,
            .other = other,
            .answer_from_other = answer_from_other,
        };
    }

    fn deinit(self: *FakeServer) void {
        self.listener.close(self.io);
        self.other.close(self.io);
    }

    /// Read the query and answer it with one A record. Runs on its own task.
    fn serve(self: *FakeServer) void {
        var scratch: [dns.edns_udp_size]u8 = undefined;
        var incoming: Io.net.IncomingMessage = .init;
        const deadline = Io.Timestamp.now(self.io, .awake).addDuration(.fromSeconds(5));
        const result = self.io.operateTimeout(.{ .net_receive = .{
            .socket_handle = self.listener.handle,
            .message_buffer = (&incoming)[0..1],
            .data_buffer = &scratch,
            .flags = .{},
        } }, .{ .deadline = deadline.withClock(.awake) }) catch return;
        const maybe_err, _ = result.net_receive;
        if (maybe_err != null) return;

        const query = dns.decode(incoming.data) catch return;
        if (query.question_len != 1) return;

        // Echo the question and add one answer, with the *right* transaction ID —
        // so the only thing wrong about the reply from `other` is where it came
        // from. That is exactly the position an off-path attacker who guessed the
        // ID is in.
        var out: [dns.max_udp_message]u8 = undefined;
        var header: dns.Header = .{
            .id = query.header.id,
            .response = true,
            .recursion_available = true,
            .question_count = 1,
            .answer_count = 1,
        };
        header.encode(out[0..dns.Header.wire_len]);
        var cursor: usize = dns.Header.wire_len;
        const name_at = cursor;
        cursor += dns.encodeName(out[cursor..], query.questions[0].name.slice()) catch return;
        std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(query.questions[0].type), .big);
        cursor += 2;
        std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(dns.Class.in), .big);
        cursor += 2;

        out[cursor] = 0xc0 | @as(u8, @intCast(name_at >> 8));
        out[cursor + 1] = @intCast(name_at & 0xff);
        cursor += 2;
        std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(dns.Type.a), .big);
        cursor += 2;
        std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(dns.Class.in), .big);
        cursor += 2;
        std.mem.writeInt(u32, out[cursor..][0..4], 42, .big);
        cursor += 4;
        std.mem.writeInt(u16, out[cursor..][0..2], 4, .big);
        cursor += 2;
        @memcpy(out[cursor..][0..4], &[4]u8{ 192, 0, 2, 7 });
        cursor += 4;

        var back = incoming.from;
        const socket = if (self.answer_from_other) self.other else self.listener;
        socket.send(self.io, &back, out[0..cursor]) catch return;
        self.answered.store(true, .release);
    }
};

test "resolver: a reply from the right server is accepted" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var server = try FakeServer.init(io, false);
    defer server.deinit();

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, FakeServer.serve, .{&server});

    var r: Resolver = .init(.{
        .gpa = gpa,
        .io = io,
        .servers = &.{server.address},
        .per_query_timeout = .fromMilliseconds(3000),
        .attempts = 1,
        .families = &.{.ip4},
    });

    const answer = try r.resolve("checked.test", 80);
    try testing.expectEqual(@as(usize, 1), answer.len);
    try testing.expectEqual([4]u8{ 192, 0, 2, 7 }, answer.addresses[0].ip4.bytes);
    try testing.expectEqual(@as(u32, 42), answer.ttl);
}

test "resolver: a reply with the right transaction ID from the wrong address is ignored" {
    // The other half of RFC 5452's defence, and the half a transaction-ID check
    // alone does not provide. This reply is perfect in every respect except its
    // source address — which is the position an off-path attacker who has guessed
    // or observed the ID occupies. Accepting it is cache poisoning.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var server = try FakeServer.init(io, true);
    defer server.deinit();

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, FakeServer.serve, .{&server});

    var r: Resolver = .init(.{
        .gpa = gpa,
        .io = io,
        .servers = &.{server.address},
        // Short, because the expected outcome is a timeout.
        .per_query_timeout = .fromMilliseconds(600),
        .attempts = 1,
        .families = &.{.ip4},
    });

    try testing.expectError(error.Timeout, r.resolve("spoofed.test", 80));
    // The forged reply really was sent, so the test would have passed for the
    // wrong reason if it had not been.
    try testing.expect(server.answered.load(.acquire));
}

test "resolver: a reply is only ours if every field we asked with comes back" {
    // Each case is a reply that is perfect except for one field, which is the position an
    // off-path attacker occupies once the transaction ID is in hand: they cannot see the
    // query, so they choose the fields they hope nobody compares.
    const asked = "checked.test";
    const Case = struct { name: []const u8, message: dns.Message, want: bool };
    const cases = [_]Case{
        .{
            .name = "the reply we asked for",
            .message = .{ .header = .{ .id = 7, .response = true }, .question_len = 1, .questions = blk: {
                var q: [dns.max_records]dns.Question = undefined;
                q[0] = .{ .name = dns.Name.init(asked) catch unreachable, .type = .a, .class = .in };
                break :blk q;
            } },
            .want = true,
        },
        .{
            .name = "a QUERY answered with a STATUS",
            .message = .{ .header = .{ .id = 7, .response = true, .opcode = .status }, .question_len = 1, .questions = blk: {
                var q: [dns.max_records]dns.Question = undefined;
                q[0] = .{ .name = dns.Name.init(asked) catch unreachable, .type = .a, .class = .in };
                break :blk q;
            } },
            .want = false,
        },
        .{
            .name = "the right name and type in the wrong class",
            .message = .{ .header = .{ .id = 7, .response = true }, .question_len = 1, .questions = blk: {
                var q: [dns.max_records]dns.Question = undefined;
                q[0] = .{ .name = dns.Name.init(asked) catch unreachable, .type = .a, .class = @fromBackingInt(@intCast(3)) };
                break :blk q;
            } },
            .want = false,
        },
        .{
            .name = "a different transaction",
            .message = .{ .header = .{ .id = 8, .response = true }, .question_len = 1, .questions = blk: {
                var q: [dns.max_records]dns.Question = undefined;
                q[0] = .{ .name = dns.Name.init(asked) catch unreachable, .type = .a, .class = .in };
                break :blk q;
            } },
            .want = false,
        },
        .{
            .name = "a question about something else",
            .message = .{ .header = .{ .id = 7, .response = true }, .question_len = 1, .questions = blk: {
                var q: [dns.max_records]dns.Question = undefined;
                q[0] = .{ .name = dns.Name.init("other.test") catch unreachable, .type = .a, .class = .in };
                break :blk q;
            } },
            .want = false,
        },
        .{
            .name = "a query rather than a response",
            .message = .{ .header = .{ .id = 7, .response = false }, .question_len = 1, .questions = blk: {
                var q: [dns.max_records]dns.Question = undefined;
                q[0] = .{ .name = dns.Name.init(asked) catch unreachable, .type = .a, .class = .in };
                break :blk q;
            } },
            .want = false,
        },
    };

    for (cases) |case| {
        const got = answersOurQuestion(&case.message, 7, asked, .ip4);
        testing.expectEqual(case.want, got) catch |err| {
            std.debug.print("case: {s}\n", .{case.name});
            return err;
        };
    }
}

test "resolver: a record in another class is not an address" {
    // Type and name match, class does not. Class CH is a separate namespace that spells
    // its names the same way, so four bytes from it are not an internet address.
    var message: dns.Message = .{ .header = .{ .id = 1, .response = true } };
    message.answers[0] = .{
        .name = try dns.Name.init("asked.test"),
        .type = .a,
        .class = @fromBackingInt(@intCast(3)), // CH
        .ttl = 60,
        .data = .{ .a = .{ 203, 0, 113, 9 } },
    };
    message.answer_len = 1;
    try testing.expectError(error.NoAddress, collect(&message, "asked.test", 80, .ip4));

    // And a CNAME in another class does not redirect the chain either.
    message.answers[0] = .{
        .name = try dns.Name.init("asked.test"),
        .type = .cname,
        .class = @fromBackingInt(@intCast(3)),
        .ttl = 60,
        .data = .{ .name = try dns.Name.init("evil.test") },
    };
    message.answers[1] = .{
        .name = try dns.Name.init("evil.test"),
        .type = .a,
        .class = .in,
        .ttl = 60,
        .data = .{ .a = .{ 203, 0, 113, 66 } },
    };
    message.answer_len = 2;
    try testing.expectError(error.NoAddress, collect(&message, "asked.test", 80, .ip4));
}

/// A server that answers the datagram query with TC set and nothing else, and answers the
/// stream query in full. Both transports on the same port, which is what §4.2 requires of a
/// name server and therefore what the retry depends on.
const TruncatingServer = struct {
    io: Io,
    datagram: Io.net.Socket,
    stream_listener: Io.net.Server,
    address: Io.net.IpAddress,
    /// How many addresses the stream answer carries. More than one, so that the test is
    /// asserting the *whole* answer arrived rather than that something arrived.
    answers: usize = 3,
    /// What the stream reply looks like, so that each check on that path has an input that
    /// exercises it.
    mode: Mode = .full,
    served_stream: std.atomic.Value(bool) = .init(false),

    const Mode = enum {
        /// A complete, correct answer.
        full,
        /// A length prefix claiming more than `max_tcp_reply`. The prefix is the peer's
        /// claim, and this is what makes the ceiling on it load-bearing.
        oversized_prefix,
        /// A well-formed answer to a different transaction, which is what an off-path
        /// attacker who reached the stream first would send.
        wrong_id,
    };

    fn init(io: Io) !TruncatingServer {
        // The datagram socket picks the port, and the stream listener is bound to the same
        // one — a resolver retries the same server, not a different one.
        var bind: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const datagram = try bind.bind(io, .{ .mode = .dgram });
        var stream_bind = datagram.address;
        const listener = try stream_bind.listen(io, .{ .reuse_address = true });
        return .{
            .io = io,
            .datagram = datagram,
            .stream_listener = listener,
            .address = datagram.address,
        };
    }

    fn deinit(self: *TruncatingServer) void {
        self.datagram.close(self.io);
        self.stream_listener.deinit(self.io);
    }

    /// One datagram query answered with TC, then one stream query answered in full.
    fn serve(self: *TruncatingServer) void {
        var scratch: [dns.edns_udp_size]u8 = undefined;
        var incoming: Io.net.IncomingMessage = .init;
        const deadline = Io.Timestamp.now(self.io, .awake).addDuration(.fromSeconds(5));
        const result = self.io.operateTimeout(.{ .net_receive = .{
            .socket_handle = self.datagram.handle,
            .message_buffer = (&incoming)[0..1],
            .data_buffer = &scratch,
            .flags = .{},
        } }, .{ .deadline = deadline.withClock(.awake) }) catch return;
        const maybe_err, _ = result.net_receive;
        if (maybe_err != null) return;

        const query = dns.decode(incoming.data) catch return;
        if (query.question_len != 1) return;

        // §4.2.1's truncated reply: the header says so, and the answer section is empty
        // because that is what "it did not fit" looks like.
        var out: [dns.max_udp_message]u8 = undefined;
        const truncated_len = writeReply(&out, &query, 0, true) catch return;
        var back = incoming.from;
        self.datagram.send(self.io, &back, out[0..truncated_len]) catch return;

        // And the same question over the stream, answered in full.
        const connection = self.stream_listener.accept(self.io) catch return;
        defer connection.close(self.io);

        var read_buffer: [dns.edns_udp_size]u8 = undefined;
        var reader = connection.reader(self.io, &read_buffer);
        const announced = reader.interface.takeInt(u16, .big) catch return;
        const request = reader.interface.take(announced) catch return;
        const stream_query = dns.decode(request) catch return;

        var reply_query = stream_query;
        if (self.mode == .wrong_id) reply_query.header.id = stream_query.header.id ^ 0xffff;

        var full: [dns.max_udp_message]u8 = undefined;
        const full_len = writeReply(&full, &reply_query, self.answers, false) catch return;

        var write_buffer: [dns.max_udp_message + 2]u8 = undefined;
        var writer = connection.writer(self.io, &write_buffer);
        var prefix: [2]u8 = undefined;
        // An announced length the reply does not actually carry: the resolver must refuse on
        // the claim alone, before allocating for it.
        const announced_len: u16 = if (self.mode == .oversized_prefix) 60000 else @intCast(full_len);
        std.mem.writeInt(u16, &prefix, announced_len, .big);
        writer.interface.writeAll(&prefix) catch return;
        writer.interface.writeAll(full[0..full_len]) catch return;
        writer.interface.flush() catch return;
        self.served_stream.store(true, .release);

        // A server that announces more than it sends and then stalls, rather than closing.
        // Closing would end the resolver's read promptly and hide what the length ceiling is
        // for; holding the connection open is both the harder case and the realistic one,
        // since a peer trying to spend someone else's memory has no reason to hang up.
        if (self.mode == .oversized_prefix) {
            var waited: usize = 0;
            while (waited < 60) : (waited += 1) {
                self.io.sleep(.fromMilliseconds(50), .awake) catch return;
            }
        }
    }

    /// Echoes the question and appends `answers` A records, all for the queried name.
    fn writeReply(out: []u8, query: *const dns.Message, answers: usize, truncated: bool) !usize {
        var header: dns.Header = .{
            .id = query.header.id,
            .response = true,
            .recursion_available = true,
            .truncated = truncated,
            .question_count = 1,
            .answer_count = @intCast(answers),
        };
        header.encode(out[0..dns.Header.wire_len]);
        var cursor: usize = dns.Header.wire_len;
        const name_at = cursor;
        cursor += try dns.encodeName(out[cursor..], query.questions[0].name.slice());
        std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(query.questions[0].type), .big);
        cursor += 2;
        std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(dns.Class.in), .big);
        cursor += 2;

        for (0..answers) |index| {
            out[cursor] = 0xc0 | @as(u8, @intCast(name_at >> 8));
            out[cursor + 1] = @intCast(name_at & 0xff);
            cursor += 2;
            std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(dns.Type.a), .big);
            cursor += 2;
            std.mem.writeInt(u16, out[cursor..][0..2], @backingInt(dns.Class.in), .big);
            cursor += 2;
            std.mem.writeInt(u32, out[cursor..][0..4], 42, .big);
            cursor += 4;
            std.mem.writeInt(u16, out[cursor..][0..2], 4, .big);
            cursor += 2;
            @memcpy(out[cursor..][0..4], &[4]u8{ 192, 0, 2, @intCast(10 + index) });
            cursor += 4;
        }
        return cursor;
    }
};

test "resolver: a truncated datagram answer is asked again over TCP" {
    // §4.2.1 caps a datagram reply and sets TC when the answer did not fit; §4.2.2 is the
    // transport where it does. Before this the resolver returned `error.Truncated` and
    // stopped, which fails exactly the names that have enough records to need the retry — and
    // fails them in a way that looks like a broken server rather than a missing transport.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var server = try TruncatingServer.init(io);

    // Declared before `server.deinit` so that it runs *after* it: `Io.net.Server.accept`
    // takes no deadline, so the only thing that reliably ends a task waiting in it is the
    // listener closing. Cancelling first and closing second would leave the suite hung
    // whenever the resolver decides not to connect — which is exactly what happens when the
    // retry regresses, so the wrong order turns a failing test into a wedged one.
    var group: Io.Group = .init;
    defer group.cancel(io);
    defer server.deinit();
    try group.concurrent(io, TruncatingServer.serve, .{&server});

    var r: Resolver = .init(.{
        .gpa = gpa,
        .io = io,
        .servers = &.{server.address},
        .per_query_timeout = .fromMilliseconds(3000),
        .attempts = 1,
        .families = &.{.ip4},
    });

    const answer = try r.resolve("truncated.test", 80);
    // All three records, which is the point: a retry that returned one address would look
    // like success while having lost most of the answer.
    try testing.expectEqual(@as(usize, 3), answer.len);
    try testing.expectEqual([4]u8{ 192, 0, 2, 10 }, answer.addresses[0].ip4.bytes);
    try testing.expectEqual([4]u8{ 192, 0, 2, 12 }, answer.addresses[2].ip4.bytes);
    try testing.expect(server.served_stream.load(.acquire));
}

test "resolver: the TCP retry can be declined, and then truncation is the answer" {
    // The retry is an option because a deployment may not want its resolver opening streams —
    // a firewall that permits port 53 over UDP and not over TCP is common enough that the
    // failure is worth being able to choose. Declining it restores the old behaviour, which
    // is now a decision rather than a limitation.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var server = try TruncatingServer.init(io);

    var group: Io.Group = .init;
    defer group.cancel(io);
    defer server.deinit();
    try group.concurrent(io, TruncatingServer.serve, .{&server});

    var r: Resolver = .init(.{
        .gpa = gpa,
        .io = io,
        .servers = &.{server.address},
        .per_query_timeout = .fromMilliseconds(1000),
        .attempts = 1,
        .families = &.{.ip4},
        .tcp_fallback = false,
    });

    try testing.expectError(error.Truncated, r.resolve("truncated.test", 80));
    try testing.expect(!server.served_stream.load(.acquire));
}

/// Runs one `resolve` so a test can wait for it with a bound of its own.
const Probe = struct {
    resolver: *Resolver,
    accepted: bool = false,
    done: std.atomic.Value(bool) = .init(false),

    fn run(self: *Probe) void {
        if (self.resolver.resolve("truncated.test", 80)) |_| {
            self.accepted = true;
        } else |_| {}
        self.done.store(true, .release);
    }
};

test "resolver: a stream reply is bounded by what it claims, and checked like any other" {
    // Two conditions on the TCP path that the successful case cannot exercise. Both are about
    // trusting the peer exactly as far as a datagram peer is trusted: §4.2.2's length prefix
    // is sixteen bits of *the server's claim*, and a stream reply is no more inherently ours
    // than a datagram one.
    // What is asserted is that the lookup does not *succeed*, rather than which error name
    // comes out. That is the property with teeth: the wrong-transaction reply is otherwise a
    // perfectly well-formed answer carrying A records, so a resolver missing the check returns
    // addresses — and an assertion on an error name would be an assertion about how `query`
    // classifies a bad server, which is a different subject.
    const gpa = testing.allocator;
    const modes = [_]TruncatingServer.Mode{ .oversized_prefix, .wrong_id };

    for (modes) |mode| {
        var threaded = try backend.Runtime.init(gpa);
        defer threaded.deinit();
        const io = threaded.io();

        var server = try TruncatingServer.init(io);
        server.mode = mode;

        var group: Io.Group = .init;
        defer group.cancel(io);
        defer server.deinit();
        try group.concurrent(io, TruncatingServer.serve, .{&server});

        var r: Resolver = .init(.{
            .gpa = gpa,
            .io = io,
            .servers = &.{server.address},
            .per_query_timeout = .fromMilliseconds(600),
            .attempts = 1,
            .families = &.{.ip4},
        });

        // On its own task, with a bound, so that anything which merely makes `resolve` slow
        // is reported as a failure rather than as a hung suite.
        //
        // One regression is not caught this way and it is worth naming: deleting the deadline
        // from the stream reads themselves. The probe then blocks in an unbounded receive, and
        // a task in that state cannot be cancelled from outside — which is precisely why the
        // deadline has to be on the receive rather than checked around it. That mutation
        // wedges instead of failing, and the harness timeout is what catches it.
        var probe: Probe = .{ .resolver = &r };
        var probe_group: Io.Group = .init;
        defer probe_group.cancel(io);
        try probe_group.concurrent(io, Probe.run, .{&probe});

        const started = Io.Timestamp.now(io, .awake);
        const give_up = started.addDuration(.fromSeconds(3));
        while (!probe.done.load(.acquire)) {
            if (Io.Timestamp.now(io, .awake).nanoseconds >= give_up.nanoseconds) {
                std.debug.print("mode {t}: resolve never returned\n", .{mode});
                return error.ResolveDidNotReturn;
            }
            try io.sleep(.fromMilliseconds(5), .awake);
        }
        const elapsed = Io.Timestamp.now(io, .awake).nanoseconds - started.nanoseconds;

        if (probe.accepted) {
            std.debug.print("mode {t}: accepted an answer it should have refused\n", .{mode});
            return error.AcceptedAnUnacceptableReply;
        }

        // Refused on what the reply *claimed*, not by waiting out the clock. Without the
        // ceiling the resolver would sit for the whole per-query timeout waiting for sixty
        // thousand bytes that are not coming — the same failure to the caller, arrived at by
        // spending the budget and a 60 KB allocation. This is what makes the ceiling
        // observable rather than merely present.
        try testing.expect(elapsed < 400 * std.time.ns_per_ms);
    }
}
