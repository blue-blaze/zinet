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
    /// Loops that will serve accepted connections. When null, the server
    /// creates and owns a group of `worker_count` loops.
    workers: ?*EventLoopGroup = null,
    /// Loop count for the server-owned worker group. Null means one per CPU.
    worker_count: ?usize = null,
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
    state: std.atomic.Value(State),
    stats: Stats,

    pub const State = enum(u8) { idle, accepting, draining, closed };

    pub const Stats = struct {
        accepted: std.atomic.Value(u64) = .init(0),
        rejected: std.atomic.Value(u64) = .init(0),
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
            // No connections left, so this only reaps task bookkeeping.
            server.workers.drain();
        } else {
            log.warn("shutdown deadline reached with {d} connections still open", .{
                server.workers.activeCount(),
            });
            server.workers.shutdown();
        }

        server.state.store(.closed, .release);
        return drained;
    }

    /// Waits until no connection is being served, or the deadline passes.
    fn awaitQuiet(server: *Server, options: GraceOptions) bool {
        const timeout = options.timeout orelse {
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
    pub fn shutdown(server: *Server) void {
        server.stopAccepting();
        server.workers.shutdown();
        server.state.store(.closed, .release);
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
