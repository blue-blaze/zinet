//! TLS 1.3 server connections: accept, handshake, then the same `Pipeline` and
//! the same handlers as any other connection.
//!
//! This is the half `src/tls.zig` says cannot be built, and the note there is
//! now out of date rather than wrong: it says accepting a TLS connection needs
//! certificate loading and `CertificateVerify` signing, neither of which the
//! standard library provides. Both are here — `tls13/identity.zig` and
//! `quic/server.zig` — because QUIC needed the engine and the record layer made
//! it reach TCP. What remains upstream is narrower and unchanged: std cannot
//! *produce* RSA signatures, so a server here holds an ECDSA P-256 or Ed25519
//! certificate.
//!
//! The read loop, the outbound queue and the flush rules come from
//! `driver.zig`, shared with the client. What is server-specific is the accept
//! loop and the handshake, which needs no first message: a server has nothing
//! to say until it has heard a ClientHello.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const log = std.log.scoped(.zinet);

const buffer_mod = @import("../../buffer.zig");
const Buffer = buffer_mod.Buffer;
const channel_mod = @import("../../channel.zig");
const message_mod = @import("../../message.zig");
const Message = message_mod.Message;
const pipeline_mod = @import("../../pipeline.zig");
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;
const pool_mod = @import("../../pool.zig");
const BufferPool = pool_mod.BufferPool;

const driver = @import("driver.zig");
const session_mod = @import("session.zig");
const identity_mod = @import("identity.zig");
pub const ServerSession = session_mod.ServerSession;
pub const Identity = identity_mod.Identity;

pub const Error = driver.Error;

/// Per-connection settings, mirroring `bootstrap.ChildConfig` for the plain
/// TCP server.
pub const ChildConfig = struct {
    initializer: ?channel_mod.Initializer = null,
    read_chunk: usize = 16 * 1024,
    max_inbound_capacity: usize = Buffer.default_max_capacity,
    outbound_capacity: usize = 64,
    /// Longest a queued write waits while the connection is blocked reading.
    write_poll: Io.Duration = .fromMilliseconds(10),
    pool: ?*BufferPool = null,
};

/// One accepted connection: a socket, a `ServerSession`, a pipeline, one task.
pub const Connection = struct {
    gpa: Allocator,
    io: Io,
    options: ChildConfig,

    stream: Io.net.Stream,
    stream_writer: Io.net.Stream.Writer,
    socket_write_buffer: []u8,
    session: ServerSession,

    pipeline: Pipeline,

    outbound: Io.Queue(driver.Outbound),
    outbound_storage: []driver.Outbound,
    pending: std.atomic.Value(u32),

    farewell: bool,
    closing: std.atomic.Value(bool),
    finished: std.atomic.Value(bool),
    refs: std.atomic.Value(u32),

    pub const Outbound = driver.Outbound;

    /// Wraps an accepted stream. The handshake has *not* happened yet: it runs
    /// on the connection's own task in `serve`, because a client that connects
    /// and then says nothing must not hold up the acceptor.
    pub fn create(
        gpa: Allocator,
        io: Io,
        stream: Io.net.Stream,
        identity: *const Identity,
        alpn: []const []const u8,
        require_alpn: bool,
        config: ChildConfig,
        seed: [64]u8,
        owner: ?*anyopaque,
    ) !*Connection {
        assert(config.read_chunk > 0);
        assert(config.outbound_capacity > 0);

        const connection = try gpa.create(Connection);
        errdefer gpa.destroy(connection);

        const outbound_storage = try gpa.alloc(driver.Outbound, config.outbound_capacity);
        errdefer gpa.free(outbound_storage);
        const socket_write_buffer = try gpa.alloc(u8, 32 * 1024);
        errdefer gpa.free(socket_write_buffer);

        var session: ServerSession = try .init(.{
            .identity = identity,
            .alpn = alpn,
            .require_alpn = require_alpn,
        }, seed);
        errdefer session.deinit(gpa);

        connection.* = .{
            .gpa = gpa,
            .io = io,
            .options = config,
            .stream = stream,
            .stream_writer = undefined,
            .socket_write_buffer = socket_write_buffer,
            .session = session,
            .pipeline = undefined,
            .outbound_storage = outbound_storage,
            .outbound = .init(outbound_storage),
            .pending = .init(0),
            .farewell = false,
            .closing = .init(false),
            .finished = .init(false),
            .refs = .init(1),
        };
        connection.stream_writer = connection.stream.writer(io, socket_write_buffer);

        try connection.pipeline.init(.{
            .gpa = gpa,
            .io = io,
            .sink = connection.sink(),
            .owner = owner orelse connection,
        });
        return connection;
    }

    /// Releases a connection that was created but never served.
    pub fn destroy(connection: *Connection) void {
        connection.pipeline.deinit();
        connection.session.deinit(connection.gpa);
        connection.release();
    }

    pub fn retain(connection: *Connection) void {
        const previous = connection.refs.fetchAdd(1, .acq_rel);
        assert(previous > 0);
    }

    pub fn release(connection: *Connection) void {
        const previous = connection.refs.fetchSub(1, .acq_rel);
        assert(previous > 0);
        if (previous != 1) return;
        const gpa = connection.gpa;
        gpa.free(connection.outbound_storage);
        gpa.free(connection.socket_write_buffer);
        gpa.destroy(connection);
    }

    pub fn isOpen(connection: *const Connection) bool {
        return !connection.closing.load(.acquire);
    }

    /// What was negotiated, valid once the pipeline is active. Empty means no
    /// ALPN, which is the ordinary case for a plain HTTPS client.
    pub fn negotiatedAlpn(connection: *const Connection) []const u8 {
        return connection.session.negotiatedAlpn();
    }

    /// The SNI the client sent.
    pub fn serverName(connection: *const Connection) []const u8 {
        return connection.session.serverName();
    }

    pub fn requestClose(connection: *Connection) void {
        connection.closing.store(true, .release);
        connection.stream.shutdown(connection.io, .both) catch {};
    }

    pub fn write(connection: *Connection, msg: Message) Error!void {
        return driver.enqueue(connection, msg, .data);
    }

    pub fn submitWrite(connection: *Connection, msg: Message) Error!void {
        return driver.enqueue(connection, msg, .submit);
    }

    pub fn writeBytes(connection: *Connection, bytes: []const u8) Error!void {
        return connection.write(try Message.initBytes(connection.gpa, bytes));
    }

    pub fn submitClose(connection: *Connection) Error!void {
        connection.outbound.putOne(connection.io, .close) catch
            return error.ConnectionClosed;
        _ = connection.pending.fetchAdd(1, .monotonic);
    }

    // -- Sink ---------------------------------------------------------------

    fn sink(connection: *Connection) Sink {
        return .{ .context = connection, .vtable = &sink_vtable };
    }

    const sink_vtable: Sink.VTable = .{
        .write = sinkWrite,
        .flush = sinkFlush,
        .close = sinkClose,
    };

    fn sinkWrite(context: *anyopaque, msg: Message) pipeline_mod.Error!void {
        const connection: *Connection = @ptrCast(@alignCast(context));
        var owned = msg;
        defer owned.deinit(connection.gpa);
        const bytes = owned.bytes() orelse return;
        connection.session.write(connection.gpa, bytes) catch return error.ChannelClosed;
    }

    fn sinkFlush(context: *anyopaque) pipeline_mod.Error!void {
        const connection: *Connection = @ptrCast(@alignCast(context));
        driver.flushOutput(connection) catch return error.ChannelClosed;
    }

    fn sinkClose(context: *anyopaque) pipeline_mod.Error!void {
        const connection: *Connection = @ptrCast(@alignCast(context));
        connection.farewell = true;
        connection.closing.store(true, .release);
    }

    // -- The task -----------------------------------------------------------

    /// Handshakes, builds the pipeline, then runs the connection. Consumes one
    /// reference.
    pub fn serve(connection: *Connection) void {
        defer connection.release();
        defer driver.drainOutbound(connection);
        defer connection.teardown();

        // The handshake first, and on this task: a failed handshake is not a
        // connection the application should ever see, so no `onActive` is
        // fired for one.
        connection.handshake() catch |err| {
            log.debug("TLS handshake failed: {s}", .{@errorName(err)});
            return;
        };

        if (connection.options.initializer) |initializer| {
            initializer.apply(&connection.pipeline) catch |err| {
                connection.pipeline.fireError(err);
                return;
            };
        }

        connection.pipeline.fireActive();
        driver.readLoop(connection);

        if (connection.farewell) {
            connection.session.close(connection.gpa) catch {};
            driver.flushOutput(connection) catch {};
        }

        connection.pipeline.fireInactive();
    }

    /// Reads until the client's Finished has been verified. A server sends
    /// nothing first, so this is a plain receive loop.
    fn handshake(connection: *Connection) !void {
        var scratch: [16 * 1024]u8 = undefined;
        while (!connection.session.isEstablished()) {
            const n = try driver.readSocket(connection, &scratch, null);
            try connection.session.receive(connection.gpa, scratch[0..n]);
            try driver.flushOutput(connection);
        }
    }

    fn teardown(connection: *Connection) void {
        connection.closing.store(true, .release);
        connection.finished.store(true, .release);
        connection.outbound.close(connection.io);
        connection.stream.close(connection.io);
        connection.session.deinit(connection.gpa);
        connection.pipeline.deinit();
    }
};

pub const ServerOptions = struct {
    gpa: Allocator,
    io: Io,
    /// Address to bind. Port 0 lets the kernel choose; read it back from
    /// `boundAddress`.
    address: Io.net.IpAddress,
    /// Certificate chain and key. Borrowed and shared by every connection, so
    /// it must outlive the server.
    identity: *const Identity,
    /// Protocols offered, most preferred first. "h2" here is what makes
    /// HTTP/2 over TLS reachable (RFC 9113 §3.1).
    alpn: []const []const u8 = &.{},
    /// Whether a client with nothing in common is refused rather than served
    /// without ALPN. False matches what browsers expect of an HTTPS server.
    require_alpn: bool = false,
    child: ChildConfig = .{},
    listen: Io.net.IpAddress.ListenOptions = .{ .reuse_address = true },
    /// Handshake seed. Null draws from the Io's CSPRNG per connection;
    /// supplying one makes a test reproducible.
    seed: ?[64]u8 = null,
};

/// A listening socket, its acceptor task, and the connections it has admitted.
///
/// Connections run on their own tasks rather than through `EventLoopGroup`,
/// which registers `*Channel` specifically. The shape otherwise follows
/// `bootstrap.Server`.
pub const Server = struct {
    gpa: Allocator,
    io: Io,
    listener: Io.net.Server,
    address: Io.net.IpAddress,
    options: ServerOptions,
    acceptor: Io.Group,
    connections: Io.Group,
    accepting: std.atomic.Value(bool),
    accepted: std.atomic.Value(u64),
    rejected: std.atomic.Value(u64),

    pub fn listen(options: ServerOptions) !*Server {
        const gpa = options.gpa;
        const server = try gpa.create(Server);
        errdefer gpa.destroy(server);

        var address = options.address;
        var listener = try address.listen(options.io, options.listen);
        errdefer listener.deinit(options.io);

        server.* = .{
            .gpa = gpa,
            .io = options.io,
            .listener = listener,
            .address = listener.socket.address,
            .options = options,
            .acceptor = .init,
            .connections = .init,
            .accepting = .init(false),
            .accepted = .init(0),
            .rejected = .init(0),
        };
        return server;
    }

    /// Starts accepting on a background task and returns.
    pub fn serve(server: *Server) !void {
        server.accepting.store(true, .release);
        server.acceptor.concurrent(server.io, acceptLoop, .{server}) catch |err| {
            server.accepting.store(false, .release);
            return err;
        };
    }

    /// Stops accepting, cancels the connections, frees the server.
    pub fn deinit(server: *Server) void {
        server.accepting.store(false, .release);
        server.listener.deinit(server.io);
        server.acceptor.cancel(server.io);
        server.connections.cancel(server.io);
        server.gpa.destroy(server);
    }

    pub fn boundAddress(server: *const Server) Io.net.IpAddress {
        return server.address;
    }

    pub fn port(server: *const Server) u16 {
        return server.address.getPort();
    }

    pub fn acceptedCount(server: *const Server) u64 {
        return server.accepted.load(.acquire);
    }

    fn acceptLoop(server: *Server) void {
        while (server.accepting.load(.acquire)) {
            const stream = server.listener.accept(server.io) catch |err| switch (err) {
                error.Canceled, error.SocketNotListening => return,
                error.ConnectionAborted, error.BlockedByFirewall, error.WouldBlock => continue,
                else => {
                    log.warn("TLS accept failed: {s}", .{@errorName(err)});
                    return;
                },
            };
            server.admit(stream);
        }
    }

    fn admit(server: *Server, stream: Io.net.Stream) void {
        var seed: [64]u8 = undefined;
        if (server.options.seed) |given| {
            seed = given;
        } else {
            server.io.randomSecure(&seed) catch server.io.random(&seed);
        }

        const connection = Connection.create(
            server.gpa,
            server.io,
            stream,
            server.options.identity,
            server.options.alpn,
            server.options.require_alpn,
            server.options.child,
            seed,
            null,
        ) catch |err| {
            log.warn("dropping TLS connection: {s}", .{@errorName(err)});
            stream.close(server.io);
            _ = server.rejected.fetchAdd(1, .monotonic);
            return;
        };

        server.connections.concurrent(server.io, Connection.serve, .{connection}) catch |err| {
            log.warn("no task for TLS connection: {s}", .{@errorName(err)});
            connection.destroy();
            stream.close(server.io);
            _ = server.rejected.fetchAdd(1, .monotonic);
            return;
        };
        _ = server.accepted.fetchAdd(1, .monotonic);
    }
};

// --- Tests --------------------------------------------------------------------

const testing = std.testing;
const backend = @import("backend");
const client_mod = @import("client.zig");
const http = @import("../http.zig");

fn testIdentity() Identity {
    // Key from a scalar in code; the certificate is a blob, because the client
    // in these tests runs with `verification = null` — what is under test is
    // the connection, not the chain. `identity.zig` covers loading, verified
    // against openssl.
    const scalar: [32]u8 = .{
        0x0d, 0x2c, 0x1f, 0x37, 0x4b, 0x59, 0x66, 0x71, 0x8a, 0x93, 0xa5, 0xb2, 0xc4, 0xd1, 0xe8, 0xf3,
        0x02, 0x15, 0x24, 0x38, 0x47, 0x51, 0x63, 0x7a, 0x85, 0x9c, 0xab, 0xb7, 0xcd, 0xd9, 0xe4, 0xfb,
    };
    const secret = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(scalar) catch unreachable;
    const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret) catch unreachable;
    return .{ .certificates = &test_certificates, .key = .{ .ecdsa_p256 = key_pair } };
}

const test_certificate = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
const test_certificates = [_][]const u8{&test_certificate};

/// Echoes what it reads, so the client can observe the round trip.
const EchoHandler = struct {
    pub fn onRead(_: *EchoHandler, ctx: *pipeline_mod.HandlerContext, msg: Message) !void {
        return ctx.writeAndFlush(msg);
    }
};

fn buildEcho(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(EchoHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("echo", .initOwned(handler));
}

const Collector = struct {
    seen: std.atomic.Value(usize) = .init(0),
    buf: [256]u8 = @splat(0),

    pub fn onRead(self: *Collector, ctx: *pipeline_mod.HandlerContext, msg: Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const bytes = owned.bytes() orelse return;
        const at = self.seen.load(.acquire);
        const len = @min(bytes.len, self.buf.len - at);
        @memcpy(self.buf[at..][0..len], bytes[0..len]);
        self.seen.store(at + len, .release);
    }
};

var test_collector: Collector = .{};

fn buildCollector(pipeline: *Pipeline) anyerror!void {
    _ = try pipeline.addLast("collect", .init(&test_collector));
}

test "tls13 server: our client handshakes against our server over a real socket" {
    // Both ends of the self-written engine, meeting over TCP with the record
    // layer between them. Nothing here is simulated: two sockets, two tasks,
    // one certificate that neither side pretends to trust.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const identity = testIdentity();
    var server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .identity = &identity,
        .alpn = &.{ "h2", "http/1.1" },
        .child = .{ .initializer = .initFunction(buildEcho) },
        .seed = @splat(0x33),
    });
    defer server.deinit();
    try server.serve();

    test_collector = .{};
    var client = try client_mod.Client.connect(.{
        .gpa = gpa,
        .io = io,
        .address = server.boundAddress(),
        .host = "example.test",
        .alpn = &.{ "http/1.1", "h2" },
        .verification = null,
        .initializer = .initFunction(buildCollector),
        .seed = @splat(0x34),
    });

    // The server picked from its own list, and the client agrees.
    try testing.expectEqualStrings("h2", client.negotiatedAlpn());

    try client.writeBytes("hello over TLS");

    // Wait for the echo, bounded: a hang here is a bug, not a slow machine.
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
    while (test_collector.seen.load(.acquire) < "hello over TLS".len) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    const seen = test_collector.seen.load(.acquire);
    try testing.expectEqualStrings("hello over TLS", test_collector.buf[0..seen]);

    client.shutdown();
}

test "tls13 server: a client offering no shared protocol is still served" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const identity = testIdentity();
    var server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .identity = &identity,
        .alpn = &.{"h3"}, // nothing an HTTP/1.1 client would ask for
        .child = .{ .initializer = .initFunction(buildEcho) },
        .seed = @splat(0x35),
    });
    defer server.deinit();
    try server.serve();

    test_collector = .{};
    var client = try client_mod.Client.connect(.{
        .gpa = gpa,
        .io = io,
        .address = server.boundAddress(),
        .host = "example.test",
        .alpn = &.{"http/1.1"},
        .verification = null,
        .initializer = .initFunction(buildCollector),
        .seed = @splat(0x36),
    });
    // No agreement, and the connection works anyway — which is what a browser
    // expects when it offers something the server has never heard of.
    try testing.expectEqual(@as(usize, 0), client.negotiatedAlpn().len);

    try client.writeBytes("no alpn");
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
    while (test_collector.seen.load(.acquire) < "no alpn".len) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    const seen = test_collector.seen.load(.acquire);
    try testing.expectEqualStrings("no alpn", test_collector.buf[0..seen]);
    client.shutdown();
}

test "tls13 server: a request coalesced with the client Finished is not lost" {
    // The regression test for a real defect, and the reason `driver.readLoop`
    // delivers before its first read: a request/response client writes its
    // Finished and its first request in one go, so the handshake loop consumes
    // both and the request is already decrypted by the time the pipeline
    // exists. curl does this; `openssl s_client` does not, which is why only
    // one of them found it.
    //
    // Driven with a sans-io `ClientSession` over a bare socket, because that is
    // the only way to control *when* the bytes leave.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const identity = testIdentity();
    var server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .identity = &identity,
        .child = .{ .initializer = .initFunction(buildEcho) },
        .seed = @splat(0x37),
    });
    defer server.deinit();
    try server.serve();

    var address = server.boundAddress();
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var session = try ServerSession.ClientPeer.init(.{
        .host = "example.test",
        .verification = null,
    }, @splat(0x38));
    defer session.deinit(gpa);

    var write_buf: [32 * 1024]u8 = undefined;
    var writer = stream.writer(io, &write_buf);

    try session.start(gpa);
    try writer.interface.writeAll(session.output());
    try writer.interface.flush();
    session.consumeOutput(session.output().len);

    var scratch: [16 * 1024]u8 = undefined;
    while (!session.isEstablished()) {
        var incoming: Io.net.IncomingMessage = .init;
        const result = try io.operateTimeout(.{ .net_receive = .{
            .socket_handle = stream.socket.handle,
            .message_buffer = (&incoming)[0..1],
            .data_buffer = &scratch,
            .flags = .{},
        } }, .{ .deadline = Io.Timestamp.now(io, .awake)
            .addDuration(.fromSeconds(5)).withClock(.awake) });
        const maybe_err, _ = result.net_receive;
        if (maybe_err != null) return error.SocketFailed;
        try session.receive(gpa, incoming.data);
    }

    // The Finished is in `output` and unsent. Append the request to it, so both
    // leave in one write — exactly what curl does.
    try session.write(gpa, "coalesced request");
    try writer.interface.writeAll(session.output());
    try writer.interface.flush();
    session.consumeOutput(session.output().len);

    // The echo must come back. Before the fix this read timed out: the server
    // was blocked on a socket read with the request already in hand.
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
    while (session.appData().len < "coalesced request".len) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;
        var incoming: Io.net.IncomingMessage = .init;
        const result = io.operateTimeout(.{ .net_receive = .{
            .socket_handle = stream.socket.handle,
            .message_buffer = (&incoming)[0..1],
            .data_buffer = &scratch,
            .flags = .{},
        } }, .{ .deadline = deadline.withClock(.awake) }) catch break;
        const maybe_err, _ = result.net_receive;
        if (maybe_err != null) break;
        if (incoming.data.len == 0) break;
        try session.receive(gpa, incoming.data);
    }
    try testing.expectEqualStrings("coalesced request", session.appData());
}
