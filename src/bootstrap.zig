//! Assembly and lifecycle: bind a port, accept connections, shut down cleanly.
//!
//! Netty exposes this as a fluent builder (`ServerBootstrap().group(...)
//! .childHandler(...).bind(port)`) because Java has no designated
//! initializers. Zig does, so Zinet takes an options struct instead. The
//! moving parts map one to one:
//!
//! | Netty                          | Zinet                        |
//! |--------------------------------|------------------------------|
//! | `ServerBootstrap`              | `Server.listen(options)`     |
//! | boss `EventLoopGroup`          | `Server.acceptors`           |
//! | worker `EventLoopGroup`        | `ServerOptions.workers`      |
//! | `childHandler(initializer)`    | `ChildConfig.initializer`    |
//! | `Bootstrap` (client)           | `connect(options)`           |
//!
//! # Shutdown
//!
//! Shutdown happens in two stages, which is what makes it graceful:
//!
//! 1. `stopAccepting` cancels the acceptor tasks, so no new connections are
//!    admitted, while established ones keep running.
//! 2. `shutdownGracefully` then waits for those connections to end on their
//!    own, or `shutdown` cancels them immediately.
//!
//! Either way, every channel is destroyed before `deinit` returns, so a leak
//! check at the end of `main` is meaningful.

const std = @import("std");
const backend = @import("backend");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Buffer = @import("buffer.zig").Buffer;
const BufferPool = @import("pool.zig").BufferPool;
const channel_mod = @import("channel.zig");
const event_loop_mod = @import("event_loop.zig");

const Channel = channel_mod.Channel;
const EventLoopGroup = event_loop_mod.EventLoopGroup;
const Initializer = channel_mod.Initializer;

const log = std.log.scoped(.zinet);

/// Per-connection configuration, applied to every accepted channel.
pub const ChildConfig = struct {
    /// Builds each connection's pipeline. A server without one accepts
    /// connections whose pipelines are empty, which is only useful in tests.
    initializer: ?Initializer = null,
    read_chunk: usize = 16 * 1024,
    max_inbound_capacity: usize = Buffer.default_max_capacity,
    write_buffer_capacity: usize = 16 * 1024,
    outbound_capacity: usize = 64,
    /// Wake each connection this often to fire a `Channel.Tick`. Handlers that
    /// need time — `IdleStateHandler` — lower it themselves via
    /// `Channel.requestTick`, so this only needs setting to force a floor.
    tick_interval: ?Io.Duration = null,
    /// Submitted tasks each connection queues before `Channel.submit` refuses.
    /// Zero, the default, disables task hopping. See `Channel.Task`.
    task_capacity: usize = 0,
    /// Longest a connection stays blocked in a read before looking for submitted
    /// tasks. Only consulted when `task_capacity` is non-zero.
    task_wake_interval: Io.Duration = .fromMilliseconds(10),
    /// Optional recycler shared by every connection's inbound buffers.
    pool: ?*BufferPool = null,
};

pub const ServerOptions = struct {
    gpa: Allocator,
    io: Io,
    /// Address to bind. Use port 0 to let the kernel pick one and read it back
    /// from `Server.boundAddress`.
    address: Io.net.IpAddress,
    /// Loops that will serve accepted connections. When null, the server creates and owns
    /// a group of `worker_count` loops.
    ///
    /// Sharing a group across listeners is supported, with one consequence worth knowing
    /// before choosing it: **a server does not cancel a group it does not own.** `Io.Group`
    /// cancels all or nothing, so there is no way to end one server's connections without
    /// ending its siblings'. `shutdown` and `deinit` therefore stop accepting, close the
    /// listener and free the server, leaving established connections to be ended by
    /// whoever owns the group — normally by `EventLoopGroup.shutdown` at process exit.
    /// A server that must be able to cut its own connections should own its group, which
    /// is the default.
    workers: ?*EventLoopGroup = null,
    /// Loop count for the server-owned worker group. Null means one per CPU.
    worker_count: ?usize = null,
    /// The most connections this server will serve at once. Null accepts as many as the
    /// runtime will start tasks for.
    ///
    /// This is the bound that was missing while every other resource had one. `src/root.zig`
    /// states that "every buffer, queue and protocol limit has an explicit, caller-visible
    /// maximum" — and the one resource a peer can actually exhaust, the task budget, had
    /// none. Without it a server accepts until `Io.concurrent` refuses, which turns a
    /// capacity decision into whatever the runtime happens to do under pressure, at the
    /// moment it is already under pressure.
    ///
    /// Measured behaviour, for choosing a value: on `std.Io.Threaded` a connection costs two
    /// tasks and 2048 of them were served with no refusals, throughput declining from 39 k
    /// to 25 k req/s (bench/README.md). So the ceiling is a *policy* about the service you
    /// want, not a workaround for a cliff — at these sizes there is no cliff. Above it,
    /// connections are closed immediately and counted in `stats.refused_at_capacity`, which
    /// is how a load balancer learns to send traffic elsewhere.
    ///
    /// Counted against the connections this server's worker group is serving. With a shared
    /// group that is the group's total rather than this server's share, for the same reason
    /// `shutdown` cannot narrow to one server: `Io.Group` has no per-registrant view.
    max_connections: ?usize = null,
    child: ChildConfig = .{},
    listen: Io.net.IpAddress.ListenOptions = .{ .reuse_address = true },
    /// Concurrent acceptor tasks. More than one helps only when accept itself
    /// is the bottleneck.
    acceptor_count: usize = 1,
};

/// A bound listening socket and the tasks accepting on it.
///
/// Heap-allocated because the acceptor tasks hold a pointer to it.
pub const Server = struct {
    gpa: Allocator,
    io: Io,
    listener: Io.net.Server,
    address: Io.net.IpAddress,
    workers: *EventLoopGroup,
    owned_workers: ?EventLoopGroup,
    child: ChildConfig,
    acceptors: Io.Group,
    acceptor_count: usize,
    /// The ceiling from `ServerOptions.max_connections`, kept because `admit` runs on an
    /// acceptor task long after `listen` returned.
    max_connections: ?usize,
    state: std.atomic.Value(State),
    stats: Stats,

    pub const State = enum(u8) { idle, accepting, draining, closed };

    pub const Stats = struct {
        accepted: std.atomic.Value(u64) = .init(0),
        /// Connections dropped because something failed: no memory for a channel, or no
        /// loop able to start its tasks.
        rejected: std.atomic.Value(u64) = .init(0),
        /// Connections closed immediately because `max_connections` was reached. Separate
        /// from `rejected` on purpose: one is the server failing, the other is the server
        /// doing exactly what it was configured to do, and an operator reading a dashboard
        /// needs to tell those apart.
        refused_at_capacity: std.atomic.Value(u64) = .init(0),
        accept_failures: std.atomic.Value(u64) = .init(0),
    };

    pub const Error = error{
        /// Every acceptor task failed to start.
        ConcurrencyUnavailable,
        /// `serve` was called on a server that is already accepting.
        AlreadyServing,
    } || Allocator.Error || Io.net.IpAddress.ListenError;

    /// Binds the address and prepares the worker loops. Call `serve` to start
    /// accepting.
    pub fn listen(options: ServerOptions) Error!*Server {
        assert(options.acceptor_count > 0);
        assert(options.child.read_chunk > 0);

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
            .workers = undefined,
            .owned_workers = null,
            .child = options.child,
            .acceptors = .init,
            .acceptor_count = options.acceptor_count,
            .max_connections = options.max_connections,
            .state = .init(.idle),
            .stats = .{},
        };

        if (options.workers) |shared| {
            server.workers = shared;
        } else {
            server.owned_workers = try EventLoopGroup.init(gpa, options.io, .{
                .loop_count = options.worker_count,
            });
            server.workers = &server.owned_workers.?;
        }
        return server;
    }

    /// Stops accepting, cancels any surviving connection, and frees the
    /// server.
    pub fn deinit(server: *Server) void {
        server.shutdown();
        if (server.owned_workers) |*owned| owned.deinit();
        server.listener.deinit(server.io);
        const gpa = server.gpa;
        server.* = undefined;
        gpa.destroy(server);
    }

    /// Connections currently being served, which is what `max_connections` is compared
    /// against. Exposed because a ceiling nobody can see the distance to is a ceiling that
    /// gets discovered by hitting it.
    pub fn liveCount(server: *const Server) usize {
        return server.workers.activeCount();
    }

    /// The address actually bound, including the port the kernel chose when 0
    /// was requested.
    pub fn boundAddress(server: *const Server) Io.net.IpAddress {
        return server.address;
    }

    pub fn port(server: *const Server) u16 {
        return server.address.getPort();
    }

    pub fn currentState(server: *const Server) State {
        return server.state.load(.acquire);
    }

    /// Starts the acceptor tasks and returns immediately.
    pub fn serve(server: *Server) Error!void {
        // A compare-and-swap rather than an assertion: assertions compile away
        // in ReleaseFast, and a second `serve` there would quietly start a
        // second set of acceptors on the same socket.
        if (server.state.cmpxchgStrong(.idle, .accepting, .acq_rel, .acquire) != null) {
            return error.AlreadyServing;
        }

        var started: usize = 0;
        while (started < server.acceptor_count) : (started += 1) {
            server.acceptors.concurrent(server.io, acceptLoop, .{server}) catch break;
        }
        if (started == 0) {
            server.state.store(.idle, .release);
            return error.ConcurrencyUnavailable;
        }
    }

    /// Blocks until the acceptor tasks finish, which happens when the server is
    /// asked to stop accepting.
    pub fn wait(server: *Server) void {
        server.acceptors.await(server.io) catch {};
    }

    /// Cancels the acceptor tasks. Established connections keep running.
    /// Idempotent.
    pub fn stopAccepting(server: *Server) void {
        if (server.currentState() == .closed) return;
        server.state.store(.draining, .release);
        server.acceptors.cancel(server.io);
    }

    /// How long established connections are given to finish once the server
    /// has stopped accepting.
    pub const GraceOptions = struct {
        /// Null waits indefinitely, which is only safe when the protocol
        /// guarantees connections end by themselves. Anything long-lived — an
        /// idle keep-alive socket, a WebSocket — needs a bound here, otherwise
        /// one quiet peer keeps the process alive forever.
        timeout: ?Io.Duration = .fromSeconds(10),
        /// How often the remaining connections are checked.
        poll_interval: Io.Duration = .fromMilliseconds(25),
    };

    /// Stops accepting, then gives established connections up to
    /// `options.timeout` to finish before cancelling whatever is left.
    ///
    /// Returns true when every connection ended on its own, false when the
    /// deadline forced a cancelation. Idempotent.
    pub fn shutdownGracefully(server: *Server, options: GraceOptions) bool {
        server.stopAccepting();

        const drained = server.awaitQuiet(options);
        if (drained) {
            // No connections left — in a shared group, none belonging to anybody — so this
            // only reaps task bookkeeping and cannot wait on a sibling's traffic. Guarding
            // it on ownership was written first and no test could tell the difference,
            // because reaching here means the group is already quiet by construction.
            server.workers.drain();
        } else {
            log.warn("shutdown deadline reached with {d} connections still open", .{
                server.workers.activeCount(),
            });
            server.cancelOwnConnections();
        }

        server.state.store(.closed, .release);
        return drained;
    }

    /// Waits until no connection is being served, or the deadline passes.
    fn awaitQuiet(server: *Server, options: GraceOptions) bool {
        const timeout = options.timeout orelse {
            // Unbounded: wait for the tasks themselves. With a shared group this waits for
            // the whole group rather than this server's share of it, which is a limit of
            // the primitive rather than a choice — `Io.Group` has no per-registrant view.
            // A caller that needs its own bound should pass one, which the branch below
            // honours by polling instead.
            server.workers.drain();
            return true;
        };

        const deadline = Io.Timestamp.now(server.io, .awake).addDuration(timeout);
        while (server.workers.activeCount() > 0) {
            const now = Io.Timestamp.now(server.io, .awake);
            // Compared in nanoseconds: rounding to milliseconds turns any
            // sub-millisecond timeout into no timeout at all.
            if (now.nanoseconds >= deadline.nanoseconds) return false;
            server.io.sleep(options.poll_interval, .awake) catch return false;
        }
        return true;
    }

    /// Stops accepting and cancels established connections. Idempotent.
    ///
    /// "Established connections" means *this server's*, and that is only achievable when
    /// the worker group belongs to this server. `Io.Group` cancels all or nothing, so a
    /// group shared with other listeners cannot be narrowed to one server's connections —
    /// and cancelling it anyway would drop a sibling's live traffic, which is what this
    /// used to do from `shutdown` and therefore from `deinit`. With a shared group the
    /// group's owner is responsible for its connections; see `Options.workers`.
    pub fn shutdown(server: *Server) void {
        server.stopAccepting();
        server.cancelOwnConnections();
        server.state.store(.closed, .release);
    }

    /// Cancels the connections this server is entitled to cancel, which is all of them
    /// when it owns its worker group and none of them when the group is shared.
    fn cancelOwnConnections(server: *Server) void {
        if (server.owned_workers) |*owned| {
            owned.shutdown();
            return;
        }
        if (server.workers.activeCount() > 0) {
            log.info(
                "leaving {d} connection(s) in the shared worker group to its owner",
                .{server.workers.activeCount()},
            );
        }
    }

    fn acceptLoop(server: *Server) void {
        while (server.currentState() == .accepting) {
            const stream = server.listener.accept(server.io) catch |err| {
                if (server.handleAcceptError(err)) continue;
                return;
            };
            server.admit(stream);
        }
    }

    /// Turns an accepted stream into a running channel, or closes it.
    fn admit(server: *Server, stream: Io.net.Stream) void {
        // Checked before a channel exists: refusing after allocating one would spend the
        // memory of a connection that is not going to be served.
        if (server.max_connections) |limit| {
            if (server.liveCount() >= limit) {
                stream.close(server.io);
                _ = server.stats.refused_at_capacity.fetchAdd(1, .monotonic);
                return;
            }
        }

        const channel = Channel.create(.{
            .gpa = server.gpa,
            .io = server.io,
            .stream = stream,
            .initializer = server.child.initializer,
            .read_chunk = server.child.read_chunk,
            .max_inbound_capacity = server.child.max_inbound_capacity,
            .write_buffer_capacity = server.child.write_buffer_capacity,
            .outbound_capacity = server.child.outbound_capacity,
            .tick_interval = server.child.tick_interval,
            .task_capacity = server.child.task_capacity,
            .task_wake_interval = server.child.task_wake_interval,
            .pool = server.child.pool,
        }) catch |err| {
            log.warn("dropping connection: {s}", .{@errorName(err)});
            stream.close(server.io);
            _ = server.stats.rejected.fetchAdd(1, .monotonic);
            return;
        };

        server.workers.register(channel) catch |err| {
            log.warn("no loop accepted the connection: {s}", .{@errorName(err)});
            channel.destroy();
            stream.close(server.io);
            _ = server.stats.rejected.fetchAdd(1, .monotonic);
            return;
        };
        _ = server.stats.accepted.fetchAdd(1, .monotonic);
    }

    /// Returns true when the accept loop should keep going.
    ///
    /// Resource exhaustion is transient: the right response is to stop piling
    /// on, not to stop serving. Anything that means the socket is gone ends the
    /// loop.
    fn handleAcceptError(server: *Server, err: Io.net.Server.AcceptError) bool {
        _ = server.stats.accept_failures.fetchAdd(1, .monotonic);
        switch (err) {
            error.Canceled, error.SocketNotListening => return false,
            error.ConnectionAborted, error.BlockedByFirewall, error.WouldBlock => return true,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.SystemResources,
            => {
                log.warn("accept throttled: {s}", .{@errorName(err)});
                server.io.sleep(.fromMilliseconds(50), .awake) catch return false;
                return true;
            },
            error.NetworkDown, error.ProtocolFailure, error.Unexpected => {
                log.err("accept failed fatally: {s}", .{@errorName(err)});
                return false;
            },
        }
    }
};

pub const ClientOptions = struct {
    gpa: Allocator,
    io: Io,
    address: Io.net.IpAddress,
    /// Loop that will serve the connection.
    loops: *EventLoopGroup,
    /// Same knobs as a server's child connections.
    config: ChildConfig = .{},
    connect: Io.net.IpAddress.ConnectOptions = .{ .mode = .stream },
};

pub const ConnectError = error{
    ConcurrencyUnavailable,
} || Allocator.Error || Io.net.IpAddress.ConnectError;

/// Connects, builds the pipeline, hands the connection to a loop, and returns a
/// reference to it.
///
/// The returned channel is **retained**: the caller owns one reference and must
/// `release` it. That is what makes a client usable from the task that opened
/// the connection — writing a request and waiting for the reply — rather than
/// only from inside its handlers.
///
/// Netty returns a `ChannelFuture` here and expects `sync()`. Zinet's connect is
/// already synchronous, so there is nothing to await; what was missing was
/// something safe to hold, which reference counting now provides. Releasing the
/// reference does not close the connection: use `requestClose` for that, then
/// release.
pub fn connect(options: ClientOptions) ConnectError!*Channel {
    var address = options.address;
    const stream = try address.connect(options.io, options.connect);

    const channel = Channel.create(.{
        .gpa = options.gpa,
        .io = options.io,
        .stream = stream,
        .initializer = options.config.initializer,
        .read_chunk = options.config.read_chunk,
        .max_inbound_capacity = options.config.max_inbound_capacity,
        .write_buffer_capacity = options.config.write_buffer_capacity,
        .outbound_capacity = options.config.outbound_capacity,
        .tick_interval = options.config.tick_interval,
        .task_capacity = options.config.task_capacity,
        .task_wake_interval = options.config.task_wake_interval,
        .pool = options.config.pool,
    }) catch |err| {
        stream.close(options.io);
        return err;
    };

    // Claimed before registering, so the caller's reference exists before the
    // channel's own task can possibly end and drop its one.
    channel.retain();

    options.loops.register(channel) catch |err| {
        // `register` failed, so no task will ever call `serve`: both references
        // are ours to drop, and the stream is still ours to close.
        channel.release();
        channel.destroy();
        stream.close(options.io);
        return err;
    };
    return channel;
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const pipeline_mod = @import("pipeline.zig");
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Echoes bytes straight back, upper-cased so the test can tell the server's
/// output apart from its own input.
const ShoutHandler = struct {
    pub fn onRead(_: *ShoutHandler, ctx: *HandlerContext, msg: Message) pipeline_mod.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());

        const bytes = owned.bytes() orelse return;
        var loud = try Buffer.initFrom(ctx.gpa(), bytes, .{});
        errdefer loud.deinit(ctx.gpa());
        for (loud.readableSliceMut()) |*byte| byte.* = std.ascii.toUpper(byte.*);

        return ctx.writeAndFlush(.initBuffer(&loud));
    }
};

fn buildShoutPipeline(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(ShoutHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("shout", .initOwned(handler));
}

test "Server: binds an ephemeral port and reports it" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = threaded.io(),
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
    });
    defer server.deinit();

    try testing.expect(server.port() != 0);
    try testing.expectEqual(Server.State.idle, server.currentState());
    try testing.expectEqual(@as(usize, 1), server.workers.loopCount());
}

test "Server: serves a client through the child pipeline" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 2,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer server.deinit();
    try server.serve();
    try testing.expectEqual(Server.State.accepting, server.currentState());

    var address = server.boundAddress();
    var client = try address.connect(io, .{ .mode = .stream });
    defer client.close(io);

    var write_buffer: [64]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    try client_writer.interface.writeAll("hello");
    try client_writer.interface.flush();

    var read_buffer: [64]u8 = undefined;
    var client_reader = client.reader(io, &read_buffer);
    try testing.expectEqualStrings("HELLO", try client_reader.interface.take(5));
    try testing.expectEqual(@as(u64, 1), server.stats.accepted.load(.acquire));
}

test "Server: a bounded concurrency budget refuses connections instead of wedging" {
    // Zinet needs two units of concurrency per connection plus one per acceptor,
    // so an `Io` with a small budget will run out. What matters is *how* it runs
    // out: `Io.concurrent` reports `ConcurrencyUnavailable` rather than waiting
    // for a slot, so the shortage has to surface as a refused connection and a
    // server that is still answering — not as a stall.
    //
    // This is the deployment-shaped version of the question, and the closest
    // check available for whether Zinet assumes unbounded concurrency. The real
    // test would be an evented backend, where every task is a fiber; that is
    // blocked on Zig (see the note on `Io.Evented` in README).
    const gpa = testing.allocator;
    // Pinned to the threaded backend on purpose: the property under test is
    // `Io.Threaded`'s own budget semantics, not something every backend has.
    var threaded: Io.Threaded = .init(gpa, .{ .concurrent_limit = .limited(3) });
    defer threaded.deinit();
    const io = threaded.io();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer server.deinit();
    try server.serve();

    var address = server.boundAddress();

    // One connection fits: the acceptor holds a slot, the channel's reader and
    // writer tasks take the other two.
    var first = try address.connect(io, .{ .mode = .stream });
    defer first.close(io);
    var write_buffer: [32]u8 = undefined;
    var read_buffer: [32]u8 = undefined;
    var first_writer = first.writer(io, &write_buffer);
    try first_writer.interface.writeAll("one");
    try first_writer.interface.flush();
    var first_reader = first.reader(io, &read_buffer);
    try testing.expectEqualStrings("ONE", try first_reader.interface.take(3));

    // Further connections cannot be served. The TCP handshake still completes,
    // because the kernel accepts into the backlog before Zinet sees it, so what
    // the client observes is a connection that closes without answering. The
    // point of the assertion is that this happens promptly rather than hanging.
    var extra = try address.connect(io, .{ .mode = .stream });
    defer extra.close(io);
    var extra_write: [32]u8 = undefined;
    var extra_writer = extra.writer(io, &extra_write);
    // A write may succeed into the socket buffer even though nobody will read it.
    extra_writer.interface.writeAll("two") catch {};
    extra_writer.interface.flush() catch {};
    var extra_read: [32]u8 = undefined;
    var extra_reader = extra.reader(io, &extra_read);
    // Which error arrives is not the property under test: an orderly close gives
    // `EndOfStream`, while a close with unread bytes still in flight gives an RST
    // and so `ReadFailed`. Either is fine. What must not happen is a read that
    // blocks forever.
    if (extra_reader.interface.take(3)) |_| {
        return error.RefusedConnectionAnswered;
    } else |_| {}

    // The server is still alive and the first connection still works, which is
    // the part that would fail if a shortage wedged the acceptor.
    try first_writer.interface.writeAll("still");
    try first_writer.interface.flush();
    try testing.expectEqualStrings("STILL", try first_reader.interface.take(5));
}

test "Server: stopAccepting refuses new work but keeps live connections" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer server.deinit();
    try server.serve();

    var address = server.boundAddress();
    var client = try address.connect(io, .{ .mode = .stream });
    defer client.close(io);

    var write_buffer: [32]u8 = undefined;
    var read_buffer: [32]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    var client_reader = client.reader(io, &read_buffer);
    try client_writer.interface.writeAll("before");
    try client_writer.interface.flush();
    try testing.expectEqualStrings("BEFORE", try client_reader.interface.take(6));

    server.stopAccepting();
    server.wait();
    try testing.expectEqual(Server.State.draining, server.currentState());

    // The established connection still works after accepting stopped.
    try client_writer.interface.writeAll("after");
    try client_writer.interface.flush();
    try testing.expectEqualStrings("AFTER", try client_reader.interface.take(5));
}

test "Server: shutdownGracefully waits for connections to end" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer server.deinit();
    try server.serve();

    var address = server.boundAddress();
    var client = try address.connect(io, .{ .mode = .stream });

    var write_buffer: [32]u8 = undefined;
    var read_buffer: [32]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    var client_reader = client.reader(io, &read_buffer);
    try client_writer.interface.writeAll("bye");
    try client_writer.interface.flush();
    try testing.expectEqualStrings("BYE", try client_reader.interface.take(3));

    client.close(io); // Lets the server's connection finish by itself.
    try testing.expect(server.shutdownGracefully(.{}));

    try testing.expectEqual(Server.State.closed, server.currentState());
    try testing.expectEqual(@as(usize, 0), server.workers.activeCount());
}

test "Server: an idle connection cannot outlast the shutdown deadline" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer server.deinit();
    try server.serve();

    var address = server.boundAddress();
    var client = try address.connect(io, .{ .mode = .stream });
    defer client.close(io);

    var write_buffer: [32]u8 = undefined;
    var read_buffer: [32]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    var client_reader = client.reader(io, &read_buffer);
    try client_writer.interface.writeAll("idle");
    try client_writer.interface.flush();
    try testing.expectEqualStrings("IDLE", try client_reader.interface.take(4));

    // The client stays connected and silent, so the deadline is what ends the
    // connection rather than the peer.
    const drained = server.shutdownGracefully(.{ .timeout = .fromMilliseconds(100) });
    try testing.expect(!drained);
    try testing.expectEqual(@as(usize, 0), server.workers.activeCount());
}

test "connect: a client channel runs its pipeline on a loop" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer server.deinit();
    try server.serve();

    // The client handler greets the server on connect and reports what comes
    // back through a queue, which is how application code observes a channel
    // from outside its task.
    const Reply = struct {
        var storage: [1][8]u8 = undefined;
        var queue: Io.Queue([8]u8) = .init(&storage);
    };
    const Greeter = struct {
        pub fn onActive(_: *@This(), ctx: *HandlerContext) pipeline_mod.Error!void {
            var greeting = try Buffer.initFrom(ctx.gpa(), "zinet", .{});
            errdefer greeting.deinit(ctx.gpa());
            return ctx.writeAndFlush(.initBuffer(&greeting));
        }

        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            var slot: [8]u8 = @splat(0);
            const bytes = owned.bytes() orelse return;
            @memcpy(slot[0..@min(bytes.len, slot.len)], bytes[0..@min(bytes.len, slot.len)]);
            try Reply.queue.putOne(ctx.io(), slot);
        }
    };
    const build = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Greeter);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("greeter", .initOwned(handler));
        }
    }.pipelineOf;

    var clients = try EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer clients.deinit();

    const client = try connect(.{
        .gpa = gpa,
        .io = io,
        .address = server.boundAddress(),
        .loops = &clients,
        .config = .{ .initializer = .initFunction(build) },
    });
    defer client.release();

    const reply = try Reply.queue.getOne(io);
    try testing.expectEqualStrings("ZINET", reply[0..5]);
}

test "connect: the returned channel can be written to from the calling task" {
    // This is the point of returning it: a client sends its request from
    // wherever it happens to be, not only from inside a handler.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const Echoed = struct {
        var queue: Io.Queue([16]u8) = undefined;
        var storage: [4][16]u8 = undefined;

        pub fn onRead(
            _: *@This(),
            ctx: *HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const bytes = owned.bytes() orelse return;
            var slot: [16]u8 = @splat(0);
            @memcpy(slot[0..@min(bytes.len, slot.len)], bytes[0..@min(bytes.len, slot.len)]);
            try queue.putOne(ctx.io(), slot);
        }
    };
    Echoed.queue = .init(&Echoed.storage);

    // A server that echoes whatever it is sent.
    const EchoBack = struct {
        pub fn onRead(
            _: *@This(),
            ctx: *HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            return ctx.writeAndFlush(msg);
        }
    };
    const buildServer = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(EchoBack);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("echo", .initOwned(handler));
        }
    }.pipelineOf;
    const buildClient = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Echoed);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("collect", .initOwned(handler));
        }
    }.pipelineOf;

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .child = .{ .initializer = .initFunction(buildServer) },
    });
    defer server.deinit();
    try server.serve();

    var clients = try EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer clients.deinit();

    const client = try connect(.{
        .gpa = gpa,
        .io = io,
        .address = server.boundAddress(),
        .loops = &clients,
        .config = .{ .initializer = .initFunction(buildClient) },
    });
    defer client.release();

    try client.write(try Message.initBytes(gpa, "ping"));
    try client.flush();

    const reply = try Echoed.queue.getOne(io);
    try testing.expectEqualStrings("ping", reply[0..4]);

    client.requestClose();
}

test "connect: a submitted write reaches the encoder the client installed" {
    // Needs task hopping, hence a bounded read; see `channel.zig`.
    try channel_mod.skipIfReadDeadlinesAreBroken();
    // The gap task hopping closes. `Channel.write` bypasses the pipeline, so a
    // client sending from its own task used to have to pre-encode its bytes or
    // hand them to a handler through a queue. Now the work travels instead.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const Collected = struct {
        var queue: Io.Queue([16]u8) = undefined;
        var storage: [4][16]u8 = undefined;

        pub fn onRead(
            _: *@This(),
            ctx: *HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const bytes = owned.bytes() orelse return;
            var slot: [16]u8 = @splat(0);
            @memcpy(slot[0..@min(bytes.len, slot.len)], bytes[0..@min(bytes.len, slot.len)]);
            try queue.putOne(ctx.io(), slot);
        }

        /// Stands in for a protocol encoder: frames the payload.
        pub fn onWrite(
            _: *@This(),
            ctx: *HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const bytes = owned.bytes() orelse return;

            var framed = try Buffer.init(ctx.gpa(), .{ .capacity = bytes.len + 2 });
            errdefer framed.deinit(ctx.gpa());
            const destination = try framed.reserve(ctx.gpa(), bytes.len + 2);
            destination[0] = '<';
            @memcpy(destination[1 .. bytes.len + 1], bytes);
            destination[bytes.len + 1] = '>';

            return ctx.write(.initBuffer(&framed));
        }
    };
    Collected.queue = .init(&Collected.storage);

    const EchoBack = struct {
        pub fn onRead(
            _: *@This(),
            ctx: *HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            return ctx.writeAndFlush(msg);
        }
    };
    const buildServer = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(EchoBack);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("echo", .initOwned(handler));
        }
    }.pipelineOf;
    const buildClient = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Collected);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("codec", .initOwned(handler));
        }
    }.pipelineOf;

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .child = .{ .initializer = .initFunction(buildServer) },
    });
    defer server.deinit();
    try server.serve();

    var clients = try EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer clients.deinit();

    const client = try connect(.{
        .gpa = gpa,
        .io = io,
        .address = server.boundAddress(),
        .loops = &clients,
        .config = .{
            .initializer = .initFunction(buildClient),
            .task_capacity = 4,
            .task_wake_interval = .fromMilliseconds(1),
        },
    });
    defer client.release();

    try client.submitWrite(try Message.initBytes(gpa, "ping"));

    // The server echoed what it received, so the framing proves the encoder ran.
    const reply = try Collected.queue.getOne(io);
    try testing.expectEqualStrings("<ping>", reply[0..6]);

    client.requestClose();
}

test "connect: a refused connection leaks nothing" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    // Bind and immediately release a port to get one that is very likely free.
    var probe: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try probe.listen(io, .{ .reuse_address = true });
    const dead_address = listener.socket.address;
    listener.deinit(io);

    var loops = try EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer loops.deinit();

    const result = connect(.{
        .gpa = gpa,
        .io = io,
        .address = dead_address,
        .loops = &loops,
        .config = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    try testing.expectError(error.ConnectionRefused, result);
}

test "Server: shutting down one server does not cut another's connections" {
    // `options.workers` lets several listeners share one `EventLoopGroup`. Every server
    // then called `workers.shutdown()` from its own `shutdown` — and from `deinit`, which
    // calls it — so tearing down one server cancelled the *group*, taking with it every
    // connection the other servers had admitted. A "shut down my server" call that drops a
    // sibling's live connections is the kind of thing that only shows up in production,
    // under whichever traffic happened to be in flight.
    //
    // Nothing in this repository used the option, which is why the suite was green: it was
    // an API whose only observable behaviour was the defect.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var shared = try EventLoopGroup.init(gpa, io, .{ .loop_count = 2 });
    defer shared.deinit();

    const keeper = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .workers = &shared,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer keeper.deinit();
    try keeper.serve();

    const departing = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .workers = &shared,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    try departing.serve();

    // A live connection on the server that is staying.
    var address = keeper.boundAddress();
    var client = try address.connect(io, .{ .mode = .stream });
    defer client.close(io);

    var write_buffer: [64]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    var read_buffer: [64]u8 = undefined;
    var client_reader = client.reader(io, &read_buffer);

    try client_writer.interface.writeAll("before");
    try client_writer.interface.flush();
    try testing.expectEqualStrings("BEFORE", try client_reader.interface.take(6));

    // And one on the server that is leaving, which is the other half of the new contract:
    // its connections outlive it, so nothing they hold may point back at it. A `Channel`
    // copies what it needs out of the child config at creation, and the acceptor tasks that
    // touch `server.stats` are cancelled — and waited for — by `stopAccepting`, so the
    // connection below is not reading freed memory. Asserted rather than asserted-in-prose:
    // this exchange happens after `departing` has been destroyed, under a leak- and
    // use-after-free-checking allocator.
    var departing_address = departing.boundAddress();
    var orphan = try departing_address.connect(io, .{ .mode = .stream });
    defer orphan.close(io);

    var orphan_write_buffer: [64]u8 = undefined;
    var orphan_writer = orphan.writer(io, &orphan_write_buffer);
    var orphan_read_buffer: [64]u8 = undefined;
    var orphan_reader = orphan.reader(io, &orphan_read_buffer);

    try orphan_writer.interface.writeAll("mine");
    try orphan_writer.interface.flush();
    try testing.expectEqualStrings("MINE", try orphan_reader.interface.take(4));

    // The graceful path has the same obligation, and reaches it differently: it waits, sees
    // the group is not quiet — the count is group-wide, which with a shared group is the
    // only view `Io.Group` offers — and must still not cancel on the way out.
    try testing.expect(!departing.shutdownGracefully(.{ .timeout = .fromMilliseconds(50) }));

    try client_writer.interface.writeAll("during");
    try client_writer.interface.flush();
    try testing.expectEqualStrings("DURING", try client_reader.interface.take(6));

    // The other server goes away entirely.
    departing.deinit();

    // The connection that has nothing to do with it is still being served.
    try client_writer.interface.writeAll("after");
    try client_writer.interface.flush();
    try testing.expectEqualStrings("AFTER", try client_reader.interface.take(5));

    // As is the one it admitted itself.
    try orphan_writer.interface.writeAll("orphan");
    try orphan_writer.interface.flush();
    try testing.expectEqualStrings("ORPHAN", try orphan_reader.interface.take(6));
}

test "Server: a connection ceiling refuses rather than accepting without limit" {
    // The bound that every other resource in this framework had and this one did not. Without
    // it a server accepts until `Io.concurrent` refuses to start a task, which means the
    // capacity decision is made by the runtime, under pressure, at the worst possible moment
    // — and the operator has no way to state a policy or to see how close to it they are.
    //
    // Refusal is a *close*, immediately, before a channel is allocated: spending memory on a
    // connection that will not be served is the opposite of what a ceiling is for. And it is
    // counted separately from `rejected`, because "the server is at the capacity you gave it"
    // and "the server failed to serve a connection" are different facts about a deployment.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const server = try Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
        .max_connections = 2,
        .child = .{ .initializer = .initFunction(buildShoutPipeline) },
    });
    defer server.deinit();
    try server.serve();

    var address = server.boundAddress();

    // Two connections, both served.
    var first = try address.connect(io, .{ .mode = .stream });
    // Closed explicitly further down, to free a slot; the flag is what keeps that from being
    // a second close of the same descriptor.
    var first_closed = false;
    defer if (!first_closed) first.close(io);
    var second = try address.connect(io, .{ .mode = .stream });
    defer second.close(io);

    var first_write: [64]u8 = undefined;
    var first_writer = first.writer(io, &first_write);
    var first_read: [64]u8 = undefined;
    var first_reader = first.reader(io, &first_read);
    try first_writer.interface.writeAll("one");
    try first_writer.interface.flush();
    try testing.expectEqualStrings("ONE", try first_reader.interface.take(3));

    var second_write: [64]u8 = undefined;
    var second_writer = second.writer(io, &second_write);
    var second_read: [64]u8 = undefined;
    var second_reader = second.reader(io, &second_read);
    try second_writer.interface.writeAll("two");
    try second_writer.interface.flush();
    try testing.expectEqualStrings("TWO", try second_reader.interface.take(3));

    try testing.expectEqual(@as(usize, 2), server.liveCount());

    // The third is refused. TCP completes — the kernel's backlog does that without asking the
    // application — so what the client observes is a connection that closes without answering,
    // which is exactly what a server at capacity should look like.
    {
        var third = try address.connect(io, .{ .mode = .stream });
        defer third.close(io);

        // The counter first, with a bound, and only then the read. Asserting through the read
        // alone would mean that a server *without* a ceiling — which serves this connection
        // and waits for it to say something — leaves the test blocked forever instead of
        // failing it. A test that wedges when the behaviour regresses is worse than no test:
        // it teaches people to kill the suite rather than read it.
        const refused_by = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
        while (server.stats.refused_at_capacity.load(.acquire) == 0) {
            if (Io.Timestamp.now(io, .awake).nanoseconds >= refused_by.nanoseconds) break;
            try io.sleep(.fromMilliseconds(2), .awake);
        }
        try testing.expectEqual(@as(u64, 1), server.stats.refused_at_capacity.load(.acquire));

        // Nothing is written on it, so the refusal is observed as end of stream: a plain FIN.
        // Writing first would make the server's close produce a reset instead, and then this
        // would be an assertion about which error name the platform picks.
        var third_read: [64]u8 = undefined;
        var third_reader = third.reader(io, &third_read);
        try testing.expectError(error.EndOfStream, third_reader.interface.take(1));
    }

    try testing.expectEqual(@as(u64, 1), server.stats.refused_at_capacity.load(.acquire));
    // Refused at capacity is not a failure, and the two counters do not bleed into each other.
    try testing.expectEqual(@as(u64, 0), server.stats.rejected.load(.acquire));
    try testing.expectEqual(@as(u64, 2), server.stats.accepted.load(.acquire));

    // And the ceiling is a ceiling on *live* connections, not a lifetime quota: when one ends,
    // the next one in is served.
    first.close(io);
    first_closed = true;
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
    while (server.liveCount() > 1) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    try testing.expectEqual(@as(usize, 1), server.liveCount());

    var fourth = try address.connect(io, .{ .mode = .stream });
    defer fourth.close(io);
    var fourth_write: [64]u8 = undefined;
    var fourth_writer = fourth.writer(io, &fourth_write);
    var fourth_read: [64]u8 = undefined;
    var fourth_reader = fourth.reader(io, &fourth_read);
    try fourth_writer.interface.writeAll("four");
    try fourth_writer.interface.flush();
    try testing.expectEqualStrings("FOUR", try fourth_reader.interface.take(4));
    try testing.expectEqual(@as(u64, 1), server.stats.refused_at_capacity.load(.acquire));
}
