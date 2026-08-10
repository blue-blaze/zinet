//! The HTTP/3 client over UDP: `codec/http3/connection` attached to a
//! `datagram.Endpoint`.
//!
//! Everything below this file is sans-io — bytes in, bytes out, injected time —
//! and this is the one place the HTTP/3 stack touches a socket. The shape
//! follows the rest of the framework: the connection lives in a pipeline
//! handler on the endpoint's reader task, so every callback the application
//! receives runs on that one task and handler state needs no locks. What
//! `tls.Connection` is to the TCP side — the protocol engine sitting on the
//! transport, under the application — this is to the UDP side.
//!
//! Time is the part worth reading twice. A QUIC connection has timers — loss
//! detection, probe timeouts, the idle clock — and a datagram socket blocked
//! in a receive runs none of them. The peer going quiet is exactly when those
//! timers matter most: a lost packet produces no datagram to wake us. So the
//! endpoint's `tick_interval` (added for this) puts a deadline on the read,
//! and the handler feeds every wakeup — datagram or tick — into the
//! connection's injected clock, calling `onTimeout` when a deadline has
//! actually passed. The connection never reads a clock itself; this file is
//! where wall-clock time enters.
//!
//! Scope, stated plainly: one socket, one connection, client-side. Dispatching
//! datagrams by connection ID across many connections, and connection
//! migration, are server-side and multi-path concerns; the transport already
//! rejects PATH_CHALLENGE (answering a challenge on an unvalidated path being
//! worse than not answering), and a client that never changes address never
//! needs to prove one.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const datagram = @import("../../datagram.zig");
const pipeline_mod = @import("../../pipeline.zig");
const Message = @import("../../message.zig").Message;

const quic = @import("../quic.zig");

const log = std.log.scoped(.zinet);
const connection = @import("connection.zig");
const qpack = @import("qpack.zig");

pub const Event = connection.Event;
pub const Connection = connection.Connection;

/// The application's view: called on the endpoint's reader task for every
/// HTTP/3 event, with the connection available for `takeSection`, `readBody`,
/// follow-up requests, and the rest. The same contract as a pipeline handler,
/// because it runs in one.
pub const Delegate = struct {
    context: *anyopaque,
    on_event: *const fn (context: *anyopaque, conn: *Connection, event: Event) void,

    pub fn init(
        context: anytype,
        comptime on_event: fn (@TypeOf(context), *Connection, Event) void,
    ) Delegate {
        const Context = @TypeOf(context);
        const wrap = struct {
            fn call(erased: *anyopaque, conn: *Connection, event: Event) void {
                on_event(@ptrCast(@alignCast(erased)), conn, event);
            }
        };
        _ = @as(Context, context);
        return .{ .context = @ptrCast(context), .on_event = wrap.call };
    }
};

pub const Options = struct {
    gpa: Allocator,
    io: Io,
    /// The server. `std.Io` has no resolver, so bring the address — the same
    /// stance as `TlsClient.connect`.
    address: Io.net.IpAddress,
    /// Sent as SNI and checked against the certificate.
    host: []const u8,
    verification: ?quic.verify.Options = null,
    parameters: quic.transport.Parameters = .client_defaults,
    max_field_section_size: u64 = 64 * 1024,
    delegate: Delegate,
    /// Handshake and connection-ID entropy, injected like every other source
    /// of randomness in this repository. `null` draws from the OS CSPRNG,
    /// which is what production callers want; tests pass a seed and get
    /// reproducible connections.
    seed: ?[64]u8 = null,
    /// The local connection ID. Null derives one from the seed.
    local_cid: ?quic.packet.ConnectionId = null,
    /// How often the reader wakes to run the connection's timers when no
    /// datagrams arrive. The QUIC timers themselves are exact — this bounds
    /// only how late they can fire, the same contract as `Channel.Tick`.
    tick_interval: Io.Duration = .fromMilliseconds(25),
};

/// The pipeline handler that owns the connection. Public so an application
/// composing its own endpoint (extra handlers, its own pool) can mount it
/// directly; `Client.connect` is the assembled convenience.
pub const Handler = struct {
    gpa: Allocator,
    io: Io,
    conn: Connection,
    server: Io.net.IpAddress,
    delegate: Delegate,
    /// Set when the connection has failed or drained; the handler stops
    /// pumping and the endpoint is idle until closed.
    finished: bool = false,
    /// Whether the handshake has been begun.
    ///
    /// Exists because §9.2 lets this handler outlive the socket it was mounted on:
    /// migrating to a new local address means opening another endpoint and mounting
    /// the same handler, so `onActive` runs more than once per connection. A second
    /// `start` would produce a second ClientHello, which is not a migration but a
    /// different connection.
    started: bool = false,

    pub const handler_name = "http3";

    pub fn deinit(self: *Handler, gpa: Allocator) void {
        self.conn.deinit(gpa);
    }

    pub fn onActive(self: *Handler, ctx: *pipeline_mod.HandlerContext) !void {
        self.conn.setTime(self.now());
        if (!self.started) {
            self.started = true;
            try self.conn.start(ctx.gpa());
        }
        // Flushed either way, and that is the point on a second mount: whatever the
        // connection owes — a PATH_CHALLENGE for the path just moved to (§8.2), the
        // RETIRE_CONNECTION_ID the move owes (§5.1.2) — goes out from the new socket.
        try self.flush(ctx);
        ctx.fireActive();
    }

    pub fn onRead(self: *Handler, ctx: *pipeline_mod.HandlerContext, msg: Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const incoming = owned.get(datagram.Datagram) orelse return;
        if (self.finished) return;

        self.conn.setTime(self.now());
        self.conn.receive(ctx.gpa(), incoming.bytes()) catch |err| {
            // The connection has already recorded the failure and queued the
            // CONNECTION_CLOSE if one is owed; what remains is to send it.
            // Nothing here is recoverable — QUIC's answer to a protocol
            // violation is to stop being a connection.
            //
            // Logged because this comment used to claim it also told the
            // application, and it did not: every datagram after this point is
            // dropped at the top of this function, so a connection that failed
            // here looked exactly like a peer that had gone quiet. That cost a
            // long diagnosis — a server sending a perfectly legal
            // NewSessionTicket killed the connection and the benchmark reported
            // "connections up: 1, requests: 0" with no error anywhere. The
            // application still has no *event* for this, which is a real gap
            // rather than a decision: `Event` has `peer_closed` and
            // `idle_timeout` but nothing for "we failed the connection
            // ourselves", and adding one is an API change rather than a line.
            log.warn("connection failed while receiving: {t}", .{err});
            self.finished = true;
        };
        try self.deliver();
        try self.flush(ctx);
    }

    pub fn onEvent(self: *Handler, ctx: *pipeline_mod.HandlerContext, event: pipeline_mod.Event) !void {
        if (event.get(datagram.DatagramChannel.Tick) == null) return ctx.fireEvent(event);
        if (self.finished) return;

        // A tick is only a wakeup. Whether a timer fired is the connection's
        // decision against its own injected clock — `onTimeout` at a moment
        // when nothing is due does nothing, by design.
        const moment = self.now();
        self.conn.setTime(moment);
        if (self.conn.nextTimeout()) |deadline| {
            if (moment >= deadline) {
                self.conn.onTimeout(ctx.gpa(), moment) catch {
                    self.finished = true;
                };
            }
        }
        try self.deliver();
        try self.flush(ctx);
    }

    fn now(self: *const Handler) u64 {
        const stamp = Io.Timestamp.now(self.io, .awake);
        return @intCast(@max(0, stamp.nanoseconds));
    }

    /// Surface the connection's events to the application.
    fn deliver(self: *Handler) !void {
        while (self.conn.nextEvent()) |event| {
            switch (event) {
                .peer_closed, .idle_timeout => self.finished = true,
                else => {},
            }
            self.delegate.on_event(self.delegate.context, &self.conn, event);
        }
    }

    /// Drain everything the connection wants on the wire. Also the application
    /// half of writing: a delegate that queued a request during `deliver` gets
    /// its datagrams sent by the flush that follows, on the same task, with no
    /// wakeup needed.
    fn flush(self: *Handler, ctx: *pipeline_mod.HandlerContext) !void {
        var buf: [quic.connection.max_datagram]u8 = undefined;
        while (true) {
            const len = self.conn.send(ctx.gpa(), &buf) catch {
                self.finished = true;
                return;
            };
            if (len == 0) return;
            try ctx.write(try Message.initAny(
                ctx.gpa(),
                datagram.Datagram,
                try datagram.Datagram.init(ctx.gpa(), self.server, buf[0..len]),
            ));
        }
    }
};

/// One HTTP/3 client connection on its own UDP socket.
pub const Client = struct {
    endpoint: datagram.Endpoint,
    handler: *Handler,
    gpa: Allocator,
    io: Io,
    /// What to bind each socket to, kept because `migrate` opens another one.
    bind_to: Io.net.IpAddress,
    tick_interval: Io.Duration,
    /// How many times `migrate` has been called, which doubles as the opaque path
    /// identifier the connection wants (§9.2) — the connection never sees addresses,
    /// so any value that distinguishes one local address from the next will do.
    migrations: u64 = 0,

    pub fn connect(options: Options) !Client {
        const gpa = options.gpa;

        var seed: [64]u8 = undefined;
        if (options.seed) |provided| {
            seed = provided;
        } else {
            // Randomness comes from the injected `Io`, like time and memory —
            // 0.17 moved the CSPRNG onto it, which suits this repository's
            // no-globals rule exactly.
            try options.io.randomSecure(&seed);
        }
        const local_cid = options.local_cid orelse
            quic.packet.ConnectionId.init(seed[48..56]) catch unreachable;
        const initial_dcid = quic.packet.ConnectionId.init(seed[56..64]) catch unreachable;

        const handler = try gpa.create(Handler);
        errdefer gpa.destroy(handler);
        handler.* = .{
            .gpa = gpa,
            .io = options.io,
            .server = options.address,
            .delegate = options.delegate,
            .conn = try Connection.init(.{
                .host = options.host,
                .parameters = options.parameters,
                .verification = options.verification,
                .local_cid = local_cid,
                .initial_destination = initial_dcid,
                .max_field_section_size = options.max_field_section_size,
            }, seed),
        };
        errdefer handler.conn.deinit(gpa);

        var client: Client = .{
            .endpoint = undefined,
            .handler = handler,
            .gpa = gpa,
            .io = options.io,
            .bind_to = switch (options.address) {
                .ip4 => .{ .ip4 = .unspecified(0) },
                .ip6 => .{ .ip6 = .unspecified(0) },
            },
            .tick_interval = options.tick_interval,
        };
        client.endpoint = try datagram.Endpoint.open(client.endpointOptions());
        return client;
    }

    /// One description of the socket, used by `connect` and again by `migrate`.
    /// Separate so the two cannot drift: a migration that opened a socket with
    /// different options would be a different connection in a way nothing would
    /// report.
    fn endpointOptions(self: *const Client) datagram.Endpoint.Options {
        const Bind = struct {
            fn build(pipeline: *pipeline_mod.Pipeline) anyerror!void {
                const mounted: *Handler = @ptrCast(@alignCast(pipeline.owner.?));
                _ = try pipeline.addLast(Handler.handler_name, .init(mounted));
            }
        };
        return .{
            .gpa = self.gpa,
            .io = self.io,
            // Port zero: the kernel picks, which is what makes each `migrate` a
            // genuinely different local address rather than the same one reopened.
            .address = self.bind_to,
            .initializer = .initFunction(Bind.build),
            .owner = self.handler,
            // QUIC never sends larger, and an inbound datagram above this is
            // not QUIC v1 (§14 of RFC 9000 caps at the path MTU; our peer
            // cannot know a higher one).
            .max_datagram_size = 2048,
            .tick_interval = self.tick_interval,
        };
    }

    /// §9.2: move this connection to a new local address.
    ///
    /// The socket is replaced rather than rebound, because `std.Io` offers no
    /// rebinding and a new socket is what a new address means. The order below is
    /// the whole subtlety and is not an implementation detail:
    ///
    ///   1. the old endpoint is stopped, which cancels its reader task;
    ///   2. the connection is migrated, which mutates state that reader touches;
    ///   3. a new endpoint is opened, whose reader task takes over.
    ///
    /// Doing 2 before 1 would race the reader for the connection's state, and the
    /// framework's one-reader-task rule is exactly what makes handler state need no
    /// locks — so migration has to respect it rather than be an exception to it.
    /// Between 1 and 3 nothing is read, which costs a few microseconds of a
    /// connection that is in any case changing address.
    ///
    /// `port_only` is passed through to §9.4's congestion decision; see
    /// `quic.connection.Connection.MigrateOptions`.
    ///
    /// On failure the connection is left usable but *unmounted*: the caller can
    /// retry, or give up and `deinit`. That is stated because the alternative —
    /// reopening on the old address to pretend nothing happened — would hide from
    /// the caller that its address did change.
    pub fn migrate(self: *Client, port_only: bool) !void {
        self.endpoint.deinit();
        self.migrations += 1;
        // Through `transport`, as every other QUIC-level operation here is reached:
        // migration is a transport concern and HTTP/3 has no opinion about it.
        try self.handler.conn.transport.migrate(.{
            .path = self.migrations,
            .port_only = port_only,
        });
        self.endpoint = try datagram.Endpoint.open(self.endpointOptions());
    }

    /// Stops the endpoint (cancelling its reader) and frees the connection.
    pub fn deinit(self: *Client) void {
        self.endpoint.deinit();
        self.handler.conn.deinit(self.gpa);
        self.gpa.destroy(self.handler);
        self.* = undefined;
    }

    pub fn localAddress(self: *const Client) Io.net.IpAddress {
        return self.endpoint.localAddress();
    }
};

const testing = std.testing;
const backend = @import("backend");
const quic_conn = quic.connection;
const frame = @import("frame.zig");

/// What the test's delegate accumulates. Shared between the endpoint's reader
/// task (which writes) and the test's task (which polls `done`), so the flag
/// crossing tasks is atomic and everything else is read only after it flips.
const Outcome = struct {
    established: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    status: [3]u8 = undefined,
    body: [64]u8 = undefined,
    body_len: usize = 0,

    fn on(self: *Outcome, conn: *Connection, event: Event) void {
        switch (event) {
            .established => {
                // Send the request from inside the callback: it runs on the
                // reader task, and the flush that follows `deliver` puts the
                // datagrams on the wire without any extra wakeup.
                var field_buf: [8]qpack.FieldLine = undefined;
                const fields = connection.requestFields(
                    "GET",
                    "https",
                    "test.local",
                    "/hello",
                    &.{},
                    &field_buf,
                );
                _ = conn.request(testing.allocator, fields, true) catch return;
                self.established.store(true, .release);
            },
            .headers => |e| {
                var section = conn.takeSection(e.stream) orelse return;
                defer section.deinit(testing.allocator);
                for (section.fields.items) |field| {
                    if (std.mem.eql(u8, field.name, ":status") and field.value.len == 3) {
                        @memcpy(&self.status, field.value);
                    }
                }
            },
            .body => |e| {
                const bytes = conn.readBody(e.stream);
                const take = @min(bytes.len, self.body.len - self.body_len);
                @memcpy(self.body[self.body_len..][0..take], bytes[0..take]);
                self.body_len += take;
                conn.consumeBody(e.stream, bytes.len);
                if (e.fin) self.done.store(true, .release);
            },
            else => {},
        }
    }
};

test "http3 client: a request crosses real UDP sockets and the response comes back" {
    // The whole stack, sockets included: the client handshakes, opens its
    // control streams, sends a GET, and reads the response — against a fixture
    // server on a plain UDP socket that derives its own keys. This is the file
    // where sans-io meets a socket, so this is the test where nothing is
    // simulated.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    // The server's socket, opened before the client so the Initial has
    // somewhere to land.
    var server_address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const server_socket = try server_address.bind(io, .{ .mode = .dgram });
    defer server_socket.close(io);

    const seed: [64]u8 = @splat(0x5a);
    const client_cid = quic.packet.ConnectionId.init(seed[48..56]) catch unreachable;
    const initial_dcid = quic.packet.ConnectionId.init(seed[56..64]) catch unreachable;
    const server_cid = quic.packet.ConnectionId.init(&.{ 0x77, 0x66 }) catch unreachable;

    var outcome: Outcome = .{};
    var client = try Client.connect(.{
        .gpa = gpa,
        .io = io,
        .address = server_socket.address,
        .host = "test.local",
        .verification = null, // the fixture cannot sign; see quic/connection.zig
        .delegate = .init(&outcome, Outcome.on),
        .seed = seed,
        .tick_interval = .fromMilliseconds(10),
    });
    defer client.deinit();

    var server: quic_conn.PacketServer = .init(0xb3, initial_dcid, server_cid);
    defer server.deinit(gpa);
    // `Established` here is a pair of 1-RTT keys plus a read-only snapshot of
    // the server; the outer `server` owns all heap state, so no deinit.
    var established: ?quic_conn.Established = null;

    var client_address: ?Io.net.IpAddress = null;
    var responded = false;
    var dropped_first = false;
    var scratch: [2048]u8 = undefined;

    // Serve until the delegate reports the response, or give up. Each pass
    // waits briefly so a quiet moment does not hang the test.
    var passes: usize = 0;
    while (passes < 400 and !outcome.done.load(.acquire)) : (passes += 1) {
        const deadline = Io.Timestamp.now(io, .awake)
            .addDuration(.fromMilliseconds(25))
            .withClock(.awake);
        const incoming = server_socket.receiveTimeout(io, &scratch, .{
            .deadline = deadline,
        }) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        client_address = incoming.from;
        const bytes = incoming.data;
        if (bytes.len == 0) continue;

        // Drop the very first datagram — the ClientHello — on the floor. This
        // is what makes the test cover the timer path and not only the happy
        // one: the client's tick must fire the PTO, and the probe must carry
        // the CRYPTO bytes again (§6.2.4), because no ACK-driven loss
        // declaration can ever happen for a hello the server never saw.
        if (!dropped_first) {
            dropped_first = true;
            continue;
        }

        if (bytes[0] & 0x80 != 0) {
            // Long header: handshake traffic for the fixture's TLS engine.
            server.receive(gpa, bytes) catch {};
            if (established == null) {
                // Answer with the server's flight. Building it is also what
                // advances the fixture's key schedule: the application secrets
                // exist only *after* `reply`, not after merely receiving the
                // ClientHello — checking for them first waits forever.
                var params: quic.transport.Parameters = .{
                    .initial_source_connection_id = server_cid,
                    .original_destination_connection_id = initial_dcid,
                    .initial_max_data = 1 << 20,
                    .initial_max_stream_data_bidi_remote = 256 * 1024,
                    .initial_max_stream_data_uni = 64 * 1024,
                    .initial_max_streams_bidi = 16,
                    .initial_max_streams_uni = 8,
                };
                var params_buf: [256]u8 = undefined;
                const params_len = quic.transport.encode(&params_buf, &params, .server);
                var reply: [quic_conn.max_datagram]u8 = undefined;
                const reply_len = try server.reply(&reply, client_cid, "h3", params_buf[0..params_len]);
                var to = incoming.from;
                try server_socket.send(io, &to, reply[0..reply_len]);

                const suite = server.inner.schedule.?.suite;
                const app = server.inner.application_secrets.?;
                established = .{
                    // A by-value snapshot: `open` reads `server.local_cid` to
                    // parse short headers (the DCID length is the receiver's
                    // own knowledge, not wire data). Never deinited — the
                    // outer `server` owns the heap state.
                    .server = server,
                    .send = .fromSecret(suite, app.server.slice()),
                    .recv = .fromSecret(suite, app.client.slice()),
                    .client_cid = client_cid,
                };
            }
            // Do not skip the 1-RTT scan below: the client coalesces. Its
            // Finished flight is a long-header datagram with a 1-RTT packet
            // riding behind it, and that packet carries the control streams
            // and the request. A server that files the datagram under
            // "handshake" and moves on waits forever for a request that
            // already arrived — `Established.open` walks coalesced packets
            // and picks out the 1-RTT one, so it handles both shapes.
        }

        // 1-RTT application data, whether the datagram was purely short-header
        // or had it coalesced behind handshake packets.
        const peer = &(established orelse continue);
        var plain: [quic_conn.max_datagram]u8 = undefined;
        var rest = peer.open(&plain, bytes) catch continue;
        var saw_request = false;
        while (rest.len > 0) {
            const f = quic.frame.parse(&rest) catch break;
            switch (f) {
                .stream => |sf| if (sf.id == 0 and sf.fin) {
                    saw_request = true;
                },
                else => {},
            }
        }

        if (saw_request and !responded) {
            responded = true;
            // The response: our control stream (type + empty SETTINGS), then
            // HEADERS(:status 200) + DATA("hello h3") with FIN on stream 0.
            var control: [64]u8 = undefined;
            var control_len: usize = quic.varint.encode(&control, 0x00);
            control_len += frame.writeSettings(control[control_len..], &.{});
            var frames: [512]u8 = undefined;
            var frames_len: usize = quic.frame.encode(&frames, .{
                .stream = .{
                    .id = 3, // the server's first unidirectional stream
                    .offset = 0,
                    .data = control[0..control_len],
                    .fin = false,
                    .had_length = true,
                },
            });

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(gpa);
            try qpack.encodeSection(gpa, &encoded, &.{
                .{ .name = ":status", .value = "200" },
            });
            var payload: std.ArrayList(u8) = .empty;
            defer payload.deinit(gpa);
            var header: [16]u8 = undefined;
            var header_len = frame.writeFrameHeader(&header, 0x01, encoded.items.len);
            try payload.appendSlice(gpa, header[0..header_len]);
            try payload.appendSlice(gpa, encoded.items);
            header_len = frame.writeFrameHeader(&header, 0x00, 8);
            try payload.appendSlice(gpa, header[0..header_len]);
            try payload.appendSlice(gpa, "hello h3");

            frames_len += quic.frame.encode(frames[frames_len..], .{ .stream = .{
                .id = 0,
                .offset = 0,
                .data = payload.items,
                .fin = true,
                .had_length = true,
            } });

            var packet_buf: [quic_conn.max_datagram]u8 = undefined;
            const packet_len = try peer.seal(&packet_buf, client_cid, frames[0..frames_len]);
            var to = client_address.?;
            try server_socket.send(io, &to, packet_buf[0..packet_len]);
        }
    }

    try testing.expect(outcome.established.load(.acquire));
    try testing.expect(outcome.done.load(.acquire));
    try testing.expectEqualStrings("200", &outcome.status);
    try testing.expectEqualStrings("hello h3", outcome.body[0..outcome.body_len]);
}
