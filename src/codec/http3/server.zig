//! An HTTP/3 server: one UDP socket, many QUIC connections, one `Pipeline` per
//! request stream.
//!
//! The shape differs from every other server in this repository, and the reason is
//! worth stating because it drove the design: a TCP server gets a *new socket* per
//! connection and can therefore give each one its own task blocked in a read.
//! A QUIC server gets one socket for everybody. Connections are told apart by the
//! Destination Connection ID in each packet header, which means demultiplexing is
//! this layer's job rather than the kernel's, and it means every connection is
//! driven from the endpoint's single reader task.
//!
//! That turns out to fit the framework rather than fight it. The threading model's
//! guarantee is "one task per connection, so handler state needs no locks"; here
//! it becomes "one task for the endpoint, so no connection's state is touched
//! concurrently" — the same guarantee with a wider scope. Nothing in a stream
//! handler can tell the difference.
//!
//! Three things are deliberately absent:
//!
//! * **No connection migration.** §9 allows a client to change address, and
//!   handling it means path validation with PATH_CHALLENGE. A connection is found
//!   by connection ID and its address is *updated* rather than checked, which is
//!   what §9.3 requires anyway before an address is validated — but the probing
//!   that would confirm the new path is not done, so a NAT rebinding survives and
//!   a deliberate migration is not verified.
//! * **No stateless reset.** §10.3 wants an endpoint that has lost state to
//!   answer with something the peer can recognise; that needs a key that survives
//!   restarts, which is an operational input this layer does not yet take.
//! * **No 0-RTT.** §4.6.1 of RFC 9001 needs a session ticket store and the replay
//!   protection that goes with it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const datagram = @import("../../datagram.zig");
const pipeline_mod = @import("../../pipeline.zig");
const Pipeline = pipeline_mod.Pipeline;
const Message = @import("../../message.zig").Message;
const Initializer = @import("../../channel.zig").Initializer;

const quic = @import("../quic.zig");
const connection_mod = @import("connection.zig");
const Connection = connection_mod.Connection;
const multiplex = @import("multiplex.zig");
const identity_mod = @import("../tls13/identity.zig");

const ConnectionId = quic.packet.ConnectionId;

pub const Options = struct {
    gpa: Allocator,
    io: Io,
    address: Io.net.IpAddress,
    /// The certificate chain and the key that signs every `CertificateVerify`.
    identity: *const identity_mod.Identity,
    /// Builds each request stream's pipeline. The application's only required hook.
    streams: Initializer,
    /// Signs address validation tokens. Injected because a fleet must share it —
    /// see `quic/acceptor.zig`.
    token_key: quic.acceptor.TokenKey,
    /// Whether to demand address validation from every new client, costing one
    /// round trip. §8.1 leaves it to the server; a server under load turns it on.
    require_address_validation: bool = false,
    /// How many connections may exist at once. A hard ceiling rather than a
    /// tuning knob: without it, a peer able to send packets from many addresses
    /// can make the server allocate without bound, which is the same reasoning
    /// every other limit in this repository follows.
    max_connections: usize = 1024,
    /// How often the reader wakes to run QUIC's timers when nothing is arriving.
    /// Loss detection is time-driven, so a silent connection still needs the
    /// clock — this is what makes a retransmission happen at all.
    tick_interval: Io.Duration = .fromMilliseconds(10),
    /// The connection IDs this server issues are this long. One value for the
    /// whole endpoint, because a short header carries no length and the only way
    /// to find the ID in one is to know it in advance (§5.1).
    connection_id_len: u8 = 8,
    max_field_section_size: u64 = 64 * 1024,
    /// Randomness. Injected like everything else here, so a test can make a whole
    /// server reproducible; `null` asks the `Io` for it.
    seed: ?[32]u8 = null,
};

/// One accepted connection: the HTTP/3 connection, its stream multiplexer, and
/// where its packets go.
const Entry = struct {
    conn: Connection,
    mux: multiplex.Multiplexer,
    address: Io.net.IpAddress,
    /// Our connection ID from the handshake. Also `cid_keys[0]`, the key this
    /// entry is owned by.
    local_cid: ConnectionId,
    /// Every key in the routing table that reaches this entry: the handshake ID
    /// first, then each spare issued under §5.1.1. A short-header packet carries
    /// only a connection ID, so a spare the client starts using has to be a key
    /// here or its packets go nowhere.
    ///
    /// The first is the *owning* key. Deletion walks this list rather than the
    /// table, which is what keeps one entry from being freed once per key it
    /// answers to.
    cid_keys: [quic.cid.max_stored]u64 = undefined,
    cid_key_count: usize = 0,
    /// How many spares have been issued, so the endpoint stops at what the peer
    /// said it would hold.
    spares_issued: usize = 0,
    /// The last address whose path validation succeeded, or the handshake's.
    ///
    /// §9.3.2 requires reverting to it when validating a new address fails, which is
    /// what keeps an on-path attacker's spurious migration from killing the
    /// connection instead of merely being ignored.
    validated_address: Io.net.IpAddress,
    /// Whether a NEW_TOKEN has been minted for this connection. One is enough:
    /// §8.1.3 lets a server send several, but each is a credential and the client
    /// only needs one to skip validation next time.
    token_offered: bool = false,
    /// Set when the connection has failed or drained and the entry is awaiting
    /// removal. Kept a moment longer than it is useful so that `receive` can
    /// answer §10.2.1's re-sends of CONNECTION_CLOSE.
    finished: bool = false,

    fn deinit(self: *Entry, gpa: Allocator) void {
        self.mux.deinit();
        self.conn.deinit(gpa);
    }
};

/// How many spare connection IDs to give each client (§5.1.1).
///
/// Two, not as many as the peer will hold: one lets a client move to a new path
/// with an ID an observer cannot link to the old one, and the second covers the
/// first being retired while a third is still being announced. Filling the peer's
/// limit costs a routing-table slot each and buys nothing this endpoint needs,
/// since it never asks the client to retire anything.
const spare_connection_ids = 2;

/// The endpoint handler: every datagram, every timer, every connection.
pub const Handler = struct {
    gpa: Allocator,
    io: Io,
    options: Options,
    /// Connections by the ID we issued. A short-header packet carries nothing
    /// else to go on.
    connections: std.AutoHashMapUnmanaged(u64, *Entry) = .empty,
    /// Where the next connection ID comes from. A counter mixed with the seed
    /// rather than a plain counter: §5.1 wants IDs an observer cannot predict,
    /// since a predictable one lets an off-path attacker address a connection it
    /// never saw.
    cid_counter: u64 = 0,
    seed: [32]u8,
    accepted: usize = 0,
    /// How many times a connection's address has been rewritten because its peer
    /// migrated (§9.3).
    ///
    /// Observable because the interesting assertion is that it stays at zero: an
    /// endpoint that takes the address from every datagram lets anyone able to spoof
    /// a source address redirect a connection's whole output at a victim, and the
    /// symptom of that defect is this number rising during ordinary traffic.
    address_moves: usize = 0,
    /// Spare connection IDs issued across all connections. Observable for the same
    /// reason `accepted` is: it is how a test can tell the announcements happened
    /// without reaching into a connection that another task owns.
    spares_total: usize = 0,

    pub const handler_name = "http3-server";

    pub fn deinit(self: *Handler, gpa: Allocator) void {
        assert(gpa.ptr == self.gpa.ptr);
        var it = self.entries();
        while (it.next()) |entry| {
            entry.deinit(gpa);
            gpa.destroy(entry);
        }
        self.connections.deinit(gpa);
    }

    pub fn onActive(_: *Handler, ctx: *pipeline_mod.HandlerContext) !void {
        ctx.fireActive();
    }

    /// The endpoint's pipeline is this handler and nothing else.
    ///
    /// The handler is its own initializer on purpose: the pipeline is built by the
    /// endpoint's reader task *after* `listen` returns, so an initializer living
    /// in `listen`'s frame would be dangling by then. That is the same defect
    /// class as the transport parameters slice in `quic/connection.zig`, and it
    /// showed up the same way — a segfault the first time a real socket was
    /// involved, with every sans-io test passing.
    pub fn initPipeline(self: *Handler, pipeline: *Pipeline) anyerror!void {
        // Borrowed, not owned: the server owns the handler and outlives the
        // pipeline.
        _ = try pipeline.addLast(handler_name, .init(self));
    }

    pub fn onRead(self: *Handler, ctx: *pipeline_mod.HandlerContext, msg: Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const incoming = owned.get(datagram.Datagram) orelse return;
        try self.onDatagram(ctx, incoming.address, incoming.bytes());
    }

    pub fn onEvent(
        self: *Handler,
        ctx: *pipeline_mod.HandlerContext,
        event: pipeline_mod.Event,
    ) !void {
        if (event.get(datagram.DatagramChannel.Tick) == null) return ctx.fireEvent(event);

        // A tick is only a wakeup: whether a timer is due is each connection's
        // decision against its own injected clock.
        const moment = self.now();
        var it = self.connections.valueIterator();
        while (it.next()) |slot| {
            const entry = slot.*;
            if (entry.finished) continue;
            entry.conn.setTime(moment);
            if (entry.conn.nextTimeout()) |deadline| {
                if (moment >= deadline) {
                    entry.conn.onTimeout(self.gpa, moment) catch {
                        entry.finished = true;
                    };
                }
            }
            self.pump(ctx, entry) catch {};
        }
        self.sweep();
    }

    fn onDatagram(
        self: *Handler,
        ctx: *pipeline_mod.HandlerContext,
        from: Io.net.IpAddress,
        bytes: []const u8,
    ) !void {
        const parsed = quic.packet.parse(bytes, self.options.connection_id_len) catch return;
        const destination = switch (parsed.packet) {
            .protected => |p| p.destination,
            // A Retry or Version Negotiation reaching a server is a client that
            // has confused the roles; §17.2.5 and §17.2.1 make both server-to-
            // client only.
            .retry, .version_negotiation => return,
        };

        if (self.lookup(destination)) |entry| {
            // §9.3: the address moves only when the connection says the peer has
            // migrated — a non-probing packet from a new path, carrying the highest
            // packet number seen. Taking the address from every datagram, as this
            // did before, means anyone able to spoof a source address can redirect
            // the connection's whole output at a victim (§9.3.1).
            const migrations_before = entry.conn.transport.migrations;
            entry.conn.setTime(self.now());
            entry.conn.receiveOn(self.gpa, bytes, pathKey(from)) catch {
                entry.finished = true;
            };
            if (entry.conn.transport.migrations != migrations_before) {
                // §9.3.2: keep the address that was working, to revert to if
                // validating the new one fails.
                entry.validated_address = entry.address;
                entry.address = from;
                self.address_moves += 1;
            }
            try self.dispatchEvents(entry);
            self.offerToken(entry, from);
            self.offerSpareCids(entry);
            try self.pump(ctx, entry);
            self.sweep();
            return;
        }

        // No connection claims it, so this is either a new one or noise.
        try self.maybeAccept(ctx, from, bytes, parsed);
        self.sweep();
    }

    fn maybeAccept(
        self: *Handler,
        ctx: *pipeline_mod.HandlerContext,
        from: Io.net.IpAddress,
        bytes: []const u8,
        parsed: quic.packet.Parsed,
    ) !void {
        const header = switch (parsed.packet) {
            .protected => |p| p,
            else => return,
        };

        var address_buf: [quic.acceptor.max_address_len]u8 = undefined;
        const address = encodeAddress(&address_buf, from);

        const policy: quic.acceptor.Policy = .{
            .key = self.options.token_key,
            .require_validation = self.options.require_address_validation,
        };
        const decision = quic.acceptor.classify(policy, header, address, self.nowMillis());

        switch (decision) {
            .drop => return,
            .negotiate_version => |v| {
                var out: [256]u8 = undefined;
                const len = quic.acceptor.writeVersionNegotiation(
                    &out,
                    v.client_source,
                    v.destination,
                    policy.versions,
                ) catch return;
                try self.sendRaw(ctx, from, out[0..len]);
            },
            .retry => |r| {
                var token_buf: [quic.acceptor.max_token_len]u8 = undefined;
                const token = quic.acceptor.mintToken(
                    &token_buf,
                    policy.key,
                    .retry,
                    self.nowMillis(),
                    address,
                    r.original_destination,
                ) catch return;
                const new_cid = self.nextConnectionId();
                var out: [512]u8 = undefined;
                const len = quic.acceptor.writeRetry(
                    &out,
                    r.client_source,
                    new_cid,
                    r.original_destination,
                    token,
                ) catch return;
                try self.sendRaw(ctx, from, out[0..len]);
            },
            .accept => |a| {
                // The ceiling. Dropping is the only honest answer: a
                // CONNECTION_CLOSE would need state we are declining to create.
                if (self.connections.count() >= self.options.max_connections) return;

                const local_cid = if (a.after_retry) a.destination else self.nextConnectionId();
                const entry = try self.gpa.create(Entry);
                errdefer self.gpa.destroy(entry);

                var seed: [64]u8 = undefined;
                @memcpy(seed[0..32], &self.seed);
                std.mem.writeInt(u64, seed[32..40], self.cid_counter, .little);
                @memcpy(seed[40..64], self.seed[0..24]);

                entry.* = .{
                    .conn = try Connection.initServer(.{
                        .identity = self.options.identity,
                        .local_cid = local_cid,
                        .destination = a.destination,
                        .original_destination = a.original_destination,
                        .peer_cid = a.client_source,
                        .after_retry = a.after_retry,
                        .max_field_section_size = self.options.max_field_section_size,
                    }, seed),
                    .mux = undefined,
                    .address = from,
                    .validated_address = from,
                    .local_cid = local_cid,
                };
                errdefer entry.conn.deinit(self.gpa);
                entry.mux = .init(self.gpa, self.io, &entry.conn, self.options.streams);

                entry.cid_keys[0] = cidKey(local_cid);
                entry.cid_key_count = 1;
                try self.connections.put(self.gpa, entry.cid_keys[0], entry);
                self.accepted += 1;

                entry.conn.setTime(self.now());
                entry.conn.receive(self.gpa, bytes) catch {
                    entry.finished = true;
                };
                try self.dispatchEvents(entry);
                try self.pump(ctx, entry);
            },
        }
    }

    /// Route a connection's events: stream events to child pipelines, the rest to
    /// the endpoint's own bookkeeping.
    fn dispatchEvents(self: *Handler, entry: *Entry) !void {
        while (entry.conn.nextEvent()) |event| {
            const handled = entry.mux.dispatch(event) catch |err| switch (err) {
                // A child pipeline that cannot be built is this connection's
                // problem, not the endpoint's.
                else => {
                    entry.finished = true;
                    continue;
                },
            };
            if (handled) continue;
            switch (event) {
                .peer_closed, .idle_timeout => entry.finished = true,
                .established, .goaway => {},
                else => {},
            }
        }
        _ = self;
    }

    /// §8.1.3: once the handshake is confirmed, give the client a token it can
    /// replay on a future connection to skip address validation.
    ///
    /// Minted here rather than in the connection because it must encode the
    /// client's address (§8.1.4), and the address is something only this layer
    /// knows — the connection is handed datagrams, not peers. The same division
    /// that puts `acceptor.zig` outside the connection.
    fn offerToken(self: *Handler, entry: *Entry, from: Io.net.IpAddress) void {
        if (entry.token_offered) return;
        if (!entry.conn.transport.handshake_confirmed) return;

        var address_buf: [quic.acceptor.max_address_len]u8 = undefined;
        const address = encodeAddress(&address_buf, from);
        var token_buf: [quic.acceptor.max_token_len]u8 = undefined;
        const token = quic.acceptor.mintToken(
            &token_buf,
            self.options.token_key,
            .new_token,
            self.nowMillis(),
            address,
            // §8.1.4: a NEW_TOKEN token must carry nothing an observer could use to
            // link it to the connection that issued it. No connection ID goes in,
            // which is exactly what distinguishes this from a Retry token.
            null,
        ) catch return;
        entry.conn.transport.queueNewToken(token) catch return;
        entry.token_offered = true;
    }

    /// §5.1.1: give the client spare connection IDs, and route them here.
    ///
    /// Order matters: the route is registered *before* the ID is announced. The
    /// reverse would leave a window in which the client uses an ID this endpoint
    /// cannot resolve, and a short-header packet carries nothing else to route by,
    /// so those packets would be dropped as unknown.
    fn offerSpareCids(self: *Handler, entry: *Entry) void {
        // §8.1.3's condition applies here too: before the handshake is confirmed the
        // client cannot use a spare, and the frame would only compete with the
        // handshake for space.
        if (!entry.conn.transport.handshake_confirmed) return;

        while (entry.spares_issued < spare_connection_ids) {
            if (!entry.conn.transport.canIssueConnectionId()) return;
            if (entry.cid_key_count == entry.cid_keys.len) return;

            const spare = self.nextConnectionId();
            const key = cidKey(spare);
            // A collision would make one entry unreachable, which is worse than not
            // issuing: the IDs are derived from a counter mixed with a secret, so
            // this is vanishingly unlikely rather than impossible.
            if (self.connections.contains(key)) return;

            // The stateless reset token must be unguessable and tied to nothing an
            // observer can see, since §10.3 makes possession of it sufficient to
            // end the connection.
            var token: [quic.cid.stateless_reset_token_len]u8 = undefined;
            var mac: std.crypto.auth.hmac.sha2.HmacSha256 = .init(&self.seed);
            mac.update("zinet stateless reset");
            mac.update(spare.slice());
            var digest: [32]u8 = undefined;
            mac.final(&digest);
            @memcpy(&token, digest[0..token.len]);

            self.connections.put(self.gpa, key, entry) catch return;
            _ = entry.conn.transport.issueConnectionId(spare, token) catch {
                // Announcing failed, so the route must not survive it — an ID the
                // client was never told about is not one it can use, and leaving the
                // key behind would keep the entry alive past its last real ID.
                _ = self.connections.remove(key);
                return;
            };
            entry.cid_keys[entry.cid_key_count] = key;
            entry.cid_key_count += 1;
            entry.spares_issued += 1;
            self.spares_total += 1;
        }
    }

    /// Everything the connection wants on the wire.
    fn pump(self: *Handler, ctx: *pipeline_mod.HandlerContext, entry: *Entry) !void {
        entry.mux.needs_flush = false;
        var buf: [quic.connection.max_datagram]u8 = undefined;
        while (true) {
            const len = entry.conn.send(self.gpa, &buf) catch {
                entry.finished = true;
                return;
            };
            if (len == 0) break;
            try self.sendRaw(ctx, entry.address, buf[0..len]);
        }
        // Only now, after this side's FIN is on the wire: a child swept earlier
        // would have its response discarded.
        entry.mux.sweepAll();
    }

    fn sendRaw(
        self: *Handler,
        ctx: *pipeline_mod.HandlerContext,
        to: Io.net.IpAddress,
        bytes: []const u8,
    ) !void {
        _ = self;
        try ctx.write(try Message.initAny(
            ctx.gpa(),
            datagram.Datagram,
            try datagram.Datagram.init(ctx.gpa(), to, bytes),
        ));
    }

    /// Remove connections that have finished. Separate from marking them so that
    /// a `finished` connection can still answer packets during the same call —
    /// §10.2.1 requires answering with CONNECTION_CLOSE again.
    /// Walk the entries once each, rather than once per key they answer to.
    ///
    /// A connection with spare IDs appears in the table several times, and every
    /// caller that wants entries rather than routes needs the same filter. Written
    /// once because the two callers that need it — sweeping and teardown — both
    /// free what they find, and a missing filter there is a double free rather than
    /// a miscount.
    const EntryIterator = struct {
        inner: std.AutoHashMapUnmanaged(u64, *Entry).Iterator,

        fn next(self: *EntryIterator) ?*Entry {
            while (self.inner.next()) |kv| {
                const entry = kv.value_ptr.*;
                assert(entry.cid_key_count > 0);
                if (kv.key_ptr.* != entry.cid_keys[0]) continue;
                return entry;
            }
            return null;
        }
    };

    fn entries(self: *Handler) EntryIterator {
        return .{ .inner = self.connections.iterator() };
    }

    /// Remove an entry from the routing table under every key it answers to, then
    /// free it.
    ///
    /// The only place an entry is freed. An entry reachable by several connection
    /// IDs would otherwise be freed once per key, and the second free is a
    /// use-after-free — so the loop over keys and the single `destroy` belong in
    /// one routine rather than repeated at each call site.
    fn removeEntry(self: *Handler, entry: *Entry) void {
        assert(entry.cid_key_count > 0);
        for (entry.cid_keys[0..entry.cid_key_count]) |key| {
            _ = self.connections.remove(key);
        }
        entry.deinit(self.gpa);
        self.gpa.destroy(entry);
    }

    fn sweep(self: *Handler) void {
        var done: [32]*Entry = undefined;
        var found: usize = 0;
        var it = self.entries();
        while (it.next()) |entry| {
            if (!entry.finished) continue;
            if (entry.conn.transport.lifecycle() != .drained) continue;
            if (found == done.len) break;
            done[found] = entry;
            found += 1;
        }
        for (done[0..found]) |entry| self.removeEntry(entry);
    }

    fn lookup(self: *Handler, destination: ConnectionId) ?*Entry {
        return self.connections.get(cidKey(destination));
    }

    /// A connection ID an observer cannot guess: the endpoint's seed keyed
    /// against a counter, so IDs are unpredictable without being random state
    /// this layer has to keep.
    fn nextConnectionId(self: *Handler) ConnectionId {
        self.cid_counter += 1;
        var mac: [32]u8 = undefined;
        var input: [8]u8 = undefined;
        std.mem.writeInt(u64, &input, self.cid_counter, .big);
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, &input, &self.seed);
        const len = @min(self.options.connection_id_len, quic.packet.max_cid_len);
        return ConnectionId.init(mac[0..len]) catch unreachable;
    }

    fn now(self: *const Handler) u64 {
        const stamp = Io.Timestamp.now(self.io, .awake);
        return @intCast(@max(0, stamp.nanoseconds));
    }

    fn nowMillis(self: *const Handler) u64 {
        return self.now() / std.time.ns_per_ms;
    }
};

/// Connection IDs as a hash key.
///
/// Eight bytes of the ID plus its length, rather than the ID itself: a
/// `ConnectionId` is a fixed array with a length, so hashing it directly would
/// hash undefined padding. This is only safe because the endpoint issues IDs of
/// one length — which it must anyway, since a short header does not carry the
/// length (§5.1).
/// A path, as this endpoint counts them: the peer's address and port together.
///
/// §9.3 needs only to tell one path from another, so a hash is enough and the
/// connection layer never sees an address. The port is included because a NAT
/// rebinding that changes only the port is still a path change (§9.4 treats it
/// specially when resetting congestion state, but it is a change).
fn pathKey(address: Io.net.IpAddress) u64 {
    var buf: [quic.acceptor.max_address_len]u8 = undefined;
    const encoded = encodeAddress(&buf, address);
    var key: u64 = 0xcbf2_9ce4_8422_2325;
    for (encoded) |byte| key = (key ^ byte) *% 0x100_0000_01b3;
    return key;
}

fn cidKey(cid: ConnectionId) u64 {
    var key: u64 = cid.len;
    for (cid.slice()) |byte| key = key *% 31 +% byte;
    // Fold the raw bytes in too, so two IDs differing only in a later byte do
    // not collide through the multiply.
    var extra: [8]u8 = @splat(0);
    const take = @min(cid.len, 8);
    @memcpy(extra[0..take], cid.slice()[0..take]);
    return key ^ std.mem.readInt(u64, &extra, .little);
}

/// A client address as authenticated token content: the bytes, then the port.
/// Both matter — two clients behind one NAT differ only in the port, and a token
/// that ignored it would be transferable between them.
fn encodeAddress(dest: []u8, address: Io.net.IpAddress) []const u8 {
    switch (address) {
        .ip4 => |v4| {
            @memcpy(dest[0..4], &v4.bytes);
            std.mem.writeInt(u16, dest[4..6], v4.port, .big);
            return dest[0..6];
        },
        .ip6 => |v6| {
            @memcpy(dest[0..16], &v6.bytes);
            std.mem.writeInt(u16, dest[16..18], v6.port, .big);
            return dest[0..18];
        },
    }
}

/// An HTTP/3 server on one UDP socket.
pub const Server = struct {
    endpoint: datagram.Endpoint,
    handler: *Handler,
    gpa: Allocator,

    pub fn listen(options: Options) !Server {
        const gpa = options.gpa;
        const handler = try gpa.create(Handler);
        errdefer gpa.destroy(handler);

        var seed: [32]u8 = undefined;
        if (options.seed) |given| {
            seed = given;
        } else {
            try options.io.randomSecure(&seed);
        }

        handler.* = .{
            .gpa = gpa,
            .io = options.io,
            .options = options,
            .seed = seed,
        };
        errdefer handler.deinit(gpa);

        const endpoint = try datagram.Endpoint.open(.{
            .gpa = gpa,
            .io = options.io,
            .address = options.address,
            .initializer = .init(handler),
            .tick_interval = options.tick_interval,
        });

        return .{ .endpoint = endpoint, .handler = handler, .gpa = gpa };
    }

    pub fn deinit(self: *Server) void {
        self.endpoint.deinit();
        self.handler.deinit(self.gpa);
        self.gpa.destroy(self.handler);
    }

    pub fn localAddress(self: *const Server) Io.net.IpAddress {
        return self.endpoint.localAddress();
    }

    pub fn port(self: *const Server) u16 {
        return switch (self.localAddress()) {
            .ip4 => |v4| v4.port,
            .ip6 => |v6| v6.port,
        };
    }

    /// How many connections have been accepted since the server started. For
    /// tests and for anything that wants to know the endpoint is being used.
    pub fn acceptedCount(self: *const Server) usize {
        return self.handler.accepted;
    }

    /// How many spare connection IDs have been issued and routed (§5.1.1).
    pub fn spareIdsIssued(self: *const Server) usize {
        return self.handler.spares_total;
    }

    /// How many times a peer's address has been acted on as a migration (§9.3).
    pub fn addressMoves(self: *const Server) usize {
        return self.handler.address_moves;
    }

    /// How many keys the routing table holds. More than one per connection once
    /// spares are issued, which is the point: a short-header packet carries only a
    /// connection ID, so every ID a client may use has to be a key here.
    pub fn routeCount(self: *const Server) usize {
        return self.handler.connections.count();
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "http3 server: every declaration compiles" {
    testing.refAllDecls(Handler);
    testing.refAllDecls(Server);
}

test "http3 server: connection ID keys distinguish ids that differ late" {
    // The hash key folds the raw bytes in for exactly this case: two IDs
    // agreeing on everything but a trailing byte must not collide, or two
    // connections would share an entry and each would receive the other's
    // packets.
    const a = ConnectionId.init(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }) catch unreachable;
    const b = ConnectionId.init(&.{ 1, 2, 3, 4, 5, 6, 7, 9 }) catch unreachable;
    const c = ConnectionId.init(&.{ 9, 2, 3, 4, 5, 6, 7, 8 }) catch unreachable;
    try testing.expect(cidKey(a) != cidKey(b));
    try testing.expect(cidKey(a) != cidKey(c));
    // And a shorter ID with the same prefix is a different key.
    const short = ConnectionId.init(&.{ 1, 2, 3, 4 }) catch unreachable;
    try testing.expect(cidKey(a) != cidKey(short));
}

test "http3 server: an address encodes its port, so two clients behind one NAT differ" {
    var a: [quic.acceptor.max_address_len]u8 = undefined;
    var b: [quic.acceptor.max_address_len]u8 = undefined;
    const one = encodeAddress(&a, .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 1000 } });
    const two = encodeAddress(&b, .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 1001 } });
    try testing.expect(!std.mem.eql(u8, one, two));
}

const backend = @import("backend");

/// A stream handler for the integration test: answers every request.
const TestResponder = struct {
    log: *TestLog,

    pub fn onRead(self: *TestResponder, ctx: *pipeline_mod.HandlerContext, msg: Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const headers = owned.get(multiplex.Headers) orelse return;
        if (headers.trailers) return;

        self.log.requests += 1;
        if (headers.get(":path")) |path| {
            self.log.last_path_len = @min(path.len, self.log.last_path.len);
            @memcpy(self.log.last_path[0..self.log.last_path_len], path[0..self.log.last_path_len]);
        }

        var fields = [_]@import("qpack.zig").FieldLine{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain" },
        };
        try ctx.write(try Message.initAny(ctx.gpa(), multiplex.OutgoingHeaders, .{ .fields = &fields }));
        try ctx.write(try Message.initBytes(ctx.gpa(), "served over h3"));
        try ctx.flush();
        try ctx.close();
    }
};

const TestLog = struct {
    requests: usize = 0,
    last_path: [64]u8 = undefined,
    last_path_len: usize = 0,
};

const TestBuilder = struct {
    log: *TestLog,

    pub fn initPipeline(self: *TestBuilder, pipeline: *Pipeline) anyerror!void {
        const responder = try pipeline.gpa.create(TestResponder);
        responder.* = .{ .log = self.log };
        errdefer pipeline.gpa.destroy(responder);
        _ = try pipeline.addLast("respond", .initOwned(responder));
    }
};

/// What the test client records.
///
/// The flags cross tasks — the endpoint's reader task writes them, the test's task
/// polls — so they are atomic and everything else is read only after one flips.
/// The request is sent from inside the callback, which runs on the reader task:
/// the flush that follows `deliver` puts the datagrams on the wire with no extra
/// wakeup, and it is the same discipline the client's own test uses.
const ClientRecorder = struct {
    established: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    status: [8]u8 = undefined,
    status_len: usize = 0,
    body: [64]u8 = undefined,
    body_len: usize = 0,
    gpa: Allocator,

    fn onEvent(self: *ClientRecorder, conn: *Connection, event: connection_mod.Event) void {
        switch (event) {
            .established => {
                var field_buf: [8]@import("qpack.zig").FieldLine = undefined;
                const fields = connection_mod.requestFields(
                    "GET",
                    "https",
                    "example.test",
                    "/served",
                    &.{},
                    &field_buf,
                );
                _ = conn.request(self.gpa, fields, true) catch return;
                self.established.store(true, .release);
            },
            .headers => |h| {
                var section = conn.takeSection(h.stream) orelse return;
                defer section.deinit(self.gpa);
                for (section.fields.items) |field| {
                    if (std.mem.eql(u8, field.name, ":status")) {
                        self.status_len = @min(field.value.len, self.status.len);
                        @memcpy(self.status[0..self.status_len], field.value[0..self.status_len]);
                    }
                }
                if (h.fin) self.done.store(true, .release);
            },
            .body => |b| {
                const bytes = conn.readBody(b.stream);
                const take = @min(bytes.len, self.body.len - self.body_len);
                @memcpy(self.body[self.body_len..][0..take], bytes[0..take]);
                self.body_len += take;
                conn.consumeBody(b.stream, bytes.len);
                if (b.fin) self.done.store(true, .release);
            },
            else => {},
        }
    }
};

test "http3 server: our own client fetches from it over a real UDP socket" {
    // The whole stack over a socket: QUIC handshake with the self-written TLS 1.3
    // engine on both ends, connection IDs demultiplexed by this endpoint, a
    // request stream given its own pipeline, and the response coming back.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var log: TestLog = .{};
    var builder: TestBuilder = .{ .log = &log };
    const identity = quic.server.testIdentity();

    var server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .identity = &identity,
        .streams = .init(&builder),
        .token_key = .init(@splat(0x91)),
        .seed = @splat(0x92),
    });
    defer server.deinit();

    var recorder: ClientRecorder = .{ .gpa = gpa };

    const client_mod = @import("client.zig");
    var client = try client_mod.Client.connect(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(server.port()) },
        .host = "example.test",
        .verification = null, // the test certificate is a placeholder, not a chain
        .delegate = .init(&recorder, ClientRecorder.onEvent),
        .seed = @splat(0x93),
    });
    defer client.deinit();

    // Bounded: a handshake that does not finish is a defect, and waiting forever
    // would hang the suite instead of reporting it.
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(10));
    while (!recorder.done.load(.acquire)) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) {
            return error.RequestTimedOut;
        }
        try io.sleep(.fromMilliseconds(5), .awake);
    }

    try testing.expect(recorder.established.load(.acquire));
    try testing.expectEqual(@as(usize, 1), server.acceptedCount());
    try testing.expectEqualStrings("200", recorder.status[0..recorder.status_len]);
    try testing.expectEqualStrings("served over h3", recorder.body[0..recorder.body_len]);
    try testing.expectEqual(@as(usize, 1), log.requests);
    try testing.expectEqualStrings("/served", log.last_path[0..log.last_path_len]);

    // §5.1.1: the spares were issued and routed. Safe to read here without racing
    // the server's task: a complete response cannot have arrived before the
    // handshake was confirmed, and confirming it is what triggers the issuing.
    try testing.expectEqual(@as(usize, spare_connection_ids), server.spareIdsIssued());
    // One connection, three ways to address it. If a spare were announced without
    // being routed, the client's first packet using it would be dropped as unknown.
    try testing.expectEqual(@as(usize, 1 + spare_connection_ids), server.routeCount());

    // §9.3: the client never moved, so its address was never rewritten. Zero rather
    // than "the right value", because the defect this guards against is rewriting the
    // address from whatever a datagram claims — which an attacker chooses.
    try testing.expectEqual(@as(usize, 0), server.addressMoves());
}
