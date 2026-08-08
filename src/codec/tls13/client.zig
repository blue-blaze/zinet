//! A TLS 1.3 client connection on the self-written engine, mounted under a
//! `Pipeline` — the same position `src/tls.zig` gives the standard library's
//! client, with two differences that both come from the engine being sans-io:
//!
//! 1. **ALPN works.** `std.crypto.tls.Client` cannot send it; this engine has
//!    sent it since it was written for QUIC. That is what makes `h2` over TLS
//!    negotiable at last.
//! 2. **Reads carry deadlines.** The standard client pulls its own bytes, so
//!    src/tls.zig needs a pump-reader contraption to bound a read. Here the
//!    socket read is a plain `net_receive` with a deadline — decryption is a
//!    separate step — so a queued write waits at most `write_poll` with no
//!    machinery beyond the deadline itself.
//!
//! Still one task, though. Not for the standard client's reason (its read path
//! mutates write state); the session here has the same property — a peer
//! KeyUpdate rotates the read keys and may queue a reply — and one task is
//! what makes that safe without a lock.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

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
const verify = @import("../quic/verify.zig");
pub const ClientSession = session_mod.ClientSession;

pub const Error = driver.Error;

/// One connection: a socket, a `ClientSession`, a pipeline and one task.
pub const Connection = struct {
    gpa: Allocator,
    io: Io,
    options: Options,

    stream: Io.net.Stream,
    stream_writer: Io.net.Stream.Writer,
    socket_write_buffer: []u8,
    session: ClientSession,

    pipeline: Pipeline,

    outbound: Io.Queue(Outbound),
    outbound_storage: []Outbound,
    pending: std.atomic.Value(u32),

    /// Set when the peer deserves a close_notify before the socket goes away.
    /// Only the connection's own task touches it.
    farewell: bool,

    closing: std.atomic.Value(bool),
    finished: std.atomic.Value(bool),
    refs: std.atomic.Value(u32),

    pub const Outbound = driver.Outbound;

    pub const Options = struct {
        gpa: Allocator,
        io: Io,
        /// Already resolved; `std.Io` has no name resolver.
        address: Io.net.IpAddress,
        /// Sent as SNI and checked against the certificate. Must outlive the
        /// connection.
        host: []const u8,
        /// ALPN protocols, most preferred first. Empty offers none. "h2" here
        /// is how HTTP/2 over TLS is announced (RFC 9113 §3.1).
        alpn: []const []const u8 = &.{},
        /// Null skips certificate validation — written down, not defaulted.
        verification: ?verify.Options,
        initializer: ?channel_mod.Initializer = null,
        owner: ?*anyopaque = null,
        /// Ciphertext bytes requested per socket read.
        read_chunk: usize = 16 * 1024,
        max_inbound_capacity: usize = Buffer.default_max_capacity,
        outbound_capacity: usize = 64,
        /// Longest a queued write waits while the task is blocked reading.
        /// This is the read deadline, nothing more.
        write_poll: Io.Duration = .fromMilliseconds(10),
        /// Handshake seed; null draws from the Io's CSPRNG. Injectable so a
        /// test can reproduce a connection.
        seed: ?[64]u8 = null,
        /// How long the server has to complete the handshake, from the moment `connect`
        /// sends the ClientHello. Null waits forever, which is what this used to do.
        ///
        /// The client's exposure is smaller than the server's — it chose to connect — but
        /// the failure is worse to diagnose: a server that accepts the TCP connection and
        /// then never answers leaves `connect` blocked with no error to report, so an
        /// application that opens connections on demand accumulates stuck tasks and looks
        /// like it is doing nothing.
        ///
        /// One deadline for the whole handshake rather than one per read, for the same
        /// reason as on the server: a per-read deadline can be reset forever by a byte.
        handshake_timeout: ?Io.Duration = .fromSeconds(10),
        pool: ?*BufferPool = null,
    };

    /// Connects, performs the handshake on the caller's task, and builds the
    /// pipeline. Returns with one reference held.
    pub fn connect(options: Options) !*Connection {
        assert(options.read_chunk > 0);
        assert(options.outbound_capacity > 0);

        const gpa = options.gpa;
        const io = options.io;

        const connection = try gpa.create(Connection);
        errdefer gpa.destroy(connection);

        const outbound_storage = try gpa.alloc(Outbound, options.outbound_capacity);
        errdefer gpa.free(outbound_storage);
        const socket_write_buffer = try gpa.alloc(u8, 32 * 1024);
        errdefer gpa.free(socket_write_buffer);

        var seed: [64]u8 = undefined;
        if (options.seed) |given| {
            seed = given;
        } else {
            io.randomSecure(&seed) catch io.random(&seed);
        }
        defer std.crypto.secureZero(u8, &seed);

        var address = options.address;
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        // The session is built in place rather than built locally and copied. The copy is
        // what made the previous shape wrong: `errdefer session.deinit(gpa)` on a local
        // that has since been assigned into `connection` tears down the state the session
        // *started* with, while everything the handshake below allocated lives in
        // `connection.session` and was simply leaked. Nothing exercised it, because no test
        // had ever made `connect` fail after this point — a handshake timeout is the first
        // way to do that.
        connection.* = .{
            .gpa = gpa,
            .io = io,
            .options = options,
            .stream = stream,
            .stream_writer = undefined,
            .socket_write_buffer = socket_write_buffer,
            .session = try .init(.{
                .host = options.host,
                .alpn = options.alpn,
                .verification = options.verification,
            }, seed),
            .pipeline = undefined,
            .outbound_storage = outbound_storage,
            .outbound = .init(outbound_storage),
            .pending = .init(0),
            .farewell = false,
            .closing = .init(false),
            .finished = .init(false),
            .refs = .init(1),
        };
        errdefer connection.session.deinit(gpa);
        connection.stream_writer = connection.stream.writer(io, socket_write_buffer);

        // The handshake, here and now: a failure to establish trust is a plain
        // error return rather than an event on a pipeline that never existed.
        try connection.handshake();

        try connection.pipeline.init(.{
            .gpa = gpa,
            .io = io,
            .sink = connection.sink(),
            .owner = options.owner orelse connection,
        });
        return connection;
    }

    fn handshake(connection: *Connection) !void {
        const gpa = connection.gpa;
        try connection.session.start(gpa);
        try connection.flushOutput();

        // Absolute, computed once: `readSocket` reports a timeout as zero bytes, and so
        // does a peer that closed, so the clock is what tells them apart.
        const deadline: ?Io.Timestamp = if (connection.options.handshake_timeout) |timeout|
            Io.Timestamp.now(connection.io, .awake).addDuration(timeout)
        else
            null;

        var scratch: [16 * 1024]u8 = undefined;
        while (!connection.session.isEstablished()) {
            const n = try connection.readSocket(&scratch, deadline);
            if (n == 0) {
                if (deadline) |d| {
                    if (Io.Timestamp.now(connection.io, .awake).nanoseconds >= d.nanoseconds) {
                        return error.HandshakeTimeout;
                    }
                }
                return error.ConnectionResetByPeer;
            }
            try connection.session.receive(gpa, scratch[0..n]);
            try connection.flushOutput();
        }
    }

    /// Releases a connection that was established but never served.
    pub fn destroy(connection: *Connection) void {
        assert(connection.refs.load(.acquire) == 1);
        connection.pipeline.deinit();
        connection.stream.close(connection.io);
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

    pub fn referenceCount(connection: *const Connection) u32 {
        return connection.refs.load(.acquire);
    }

    pub fn isOpen(connection: *const Connection) bool {
        return !connection.closing.load(.acquire);
    }

    pub fn pendingOutbound(connection: *const Connection) usize {
        return connection.pending.load(.acquire);
    }

    /// What the server agreed to speak. Empty when ALPN was not negotiated.
    pub fn negotiatedAlpn(connection: *const Connection) []const u8 {
        return connection.session.negotiatedAlpn();
    }

    /// Ends the connection now, without a closing handshake. Callable from any
    /// task; shutting the socket down unblocks the read.
    pub fn requestClose(connection: *Connection) void {
        connection.closing.store(true, .release);
        connection.stream.shutdown(connection.io, .both) catch {};
    }

    /// Queues raw bytes, skipping the pipeline. Callable from any task.
    pub fn write(connection: *Connection, msg: Message) Error!void {
        return connection.enqueue(msg, .data);
    }

    /// Queues a message to travel the pipeline on the connection's own task.
    pub fn submitWrite(connection: *Connection, msg: Message) Error!void {
        return connection.enqueue(msg, .submit);
    }

    pub fn writeBytes(connection: *Connection, bytes: []const u8) Error!void {
        return connection.write(try Message.initBytes(connection.gpa, bytes));
    }

    fn enqueue(
        connection: *Connection,
        msg: Message,
        comptime kind: std.meta.Tag(Outbound),
    ) Error!void {
        return driver.enqueue(connection, msg, kind);
    }

    /// Queues a graceful close: what is queued goes out, then close_notify.
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
        connection.flushOutput() catch return error.ChannelClosed;
    }

    fn sinkClose(context: *anyopaque) pipeline_mod.Error!void {
        const connection: *Connection = @ptrCast(@alignCast(context));
        connection.farewell = true;
        connection.closing.store(true, .release);
    }

    // -- The task -----------------------------------------------------------

    /// Runs the connection's whole lifecycle on this task. Consumes one
    /// reference.
    pub fn serve(connection: *Connection) void {
        defer connection.release();
        defer connection.drainOutbound();
        defer connection.teardown();

        if (connection.options.initializer) |initializer| {
            initializer.apply(&connection.pipeline) catch |err| {
                connection.pipeline.fireError(err);
                return;
            };
        }

        connection.pipeline.fireActive();
        connection.readLoop();

        if (connection.farewell) {
            connection.session.close(connection.gpa) catch {};
            connection.flushOutput() catch {};
        }

        connection.pipeline.fireInactive();
    }

    fn teardown(connection: *Connection) void {
        connection.closing.store(true, .release);
        connection.finished.store(true, .release);
        connection.outbound.close(connection.io);
        connection.stream.close(connection.io);
        connection.session.deinit(connection.gpa);
        connection.pipeline.deinit();
    }

    fn readLoop(connection: *Connection) void {
        return driver.readLoop(connection);
    }

    fn deliverPlaintext(connection: *Connection) void {
        return driver.deliverPlaintext(connection);
    }

    /// Sends everything queued, then flushes. Returns false to stop the loop.
    fn pumpOutbound(connection: *Connection) bool {
        return driver.pumpOutbound(connection);
    }

    fn drainOutbound(connection: *Connection) void {
        return driver.drainOutbound(connection);
    }

    fn finishRead(connection: *Connection, err: anyerror) void {
        return driver.finishRead(connection, err);
    }

    /// One socket read. With a deadline, expiry is a zero-byte result rather
    /// than an error; without one, blocks until data or end of stream.
    fn readSocket(connection: *Connection, dest: []u8, deadline: ?Io.Timestamp) !usize {
        return driver.readSocket(connection, dest, deadline);
    }

    fn flushOutput(connection: *Connection) !void {
        return driver.flushOutput(connection);
    }

    fn acquireInbound(connection: *Connection, wanted: usize) Buffer.Error!Buffer {
        return driver.acquireInbound(connection, wanted);
    }
};

/// The user-facing wrapper: connect, then serve on a spawned task — the same
/// split `tls.Client` (the std-based one) offers.
pub const Client = struct {
    connection: *Connection,
    future: Io.Future(void),

    pub fn connect(options: Connection.Options) !Client {
        const connection = try Connection.connect(options);
        // Retained before the task starts, so the handle stays valid even if
        // the task finishes immediately.
        connection.retain();
        errdefer {
            connection.release();
            connection.destroy();
        }
        const future = try options.io.concurrent(Connection.serve, .{connection});
        return .{ .connection = connection, .future = future };
    }

    /// Ends the connection, waits for its task, then drops this reference.
    pub fn deinit(client: *Client) void {
        const io = client.connection.io;
        client.connection.requestClose();
        client.future.await(io);
        client.connection.release();
        client.* = undefined;
    }

    /// Graceful close: the peer sees close_notify, not a vanishing socket.
    pub fn shutdown(client: *Client) void {
        const io = client.connection.io;
        client.connection.submitClose() catch {};
        client.future.await(io);
        client.connection.release();
        client.* = undefined;
    }

    pub fn submitWrite(client: *Client, msg: Message) Error!void {
        return client.connection.submitWrite(msg);
    }

    pub fn write(client: *Client, msg: Message) Error!void {
        return client.connection.write(msg);
    }

    pub fn writeBytes(client: *Client, bytes: []const u8) Error!void {
        return client.connection.writeBytes(bytes);
    }

    pub fn negotiatedAlpn(client: *const Client) []const u8 {
        return client.connection.negotiatedAlpn();
    }
};
