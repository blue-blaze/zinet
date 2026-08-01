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
            if (!message.header.response) continue;
            if (message.header.id != id) continue;
            // The question must be the one we asked. A server that answers a
            // different question is either confused or not the server.
            if (message.question_len != 1) continue;
            if (!message.questions[0].name.eqlText(host)) continue;
            if (message.questions[0].type != family.recordType()) continue;

            // Only now is the reply ours to believe.
            if (message.header.truncated) return error.Truncated;
            switch (message.header.response_code) {
                .no_error => {},
                .name_error => return error.NameNotFound,
                else => return error.ServerFailure,
            }

            return collect(&message, host, port, family);
        }
    }
};

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
