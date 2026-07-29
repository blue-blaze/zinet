//! Where channels run.
//!
//! Netty's `EventLoop` is a thread plus a selector; channels are assigned to
//! one at registration and never migrate, which is what makes handler state
//! lock free. Zinet keeps the concept but not the mechanism: an `EventLoop`
//! here is an `Io.Group` of channel tasks. The scheduling is the `Io`
//! implementation's business, and the lock-free property comes from each
//! channel having exactly one reader task.
//!
//! Keeping the abstraction is deliberate. It is the seam at which a future
//! backend — a dedicated poller thread per loop, io_uring, kqueue — can be
//! substituted without touching a single handler.
//!
//! A group of loops is used the way Netty uses one: a small "boss" group whose
//! job is accepting, and a larger "worker" group that serves the accepted
//! connections.

const std = @import("std");
const backend = @import("backend");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Channel = @import("channel.zig").Channel;

/// A set of channel tasks that are started, cancelled and awaited together.
///
/// Self-referential through the tasks it spawns, so it must not be moved after
/// the first `register`.
pub const EventLoop = struct {
    io: Io,
    group: Io.Group,
    /// Channels registered over this loop's lifetime.
    registered: std.atomic.Value(u64),
    /// Channels currently being served.
    active: std.atomic.Value(i64),

    pub const Error = Io.ConcurrentError;

    pub fn init(io: Io) EventLoop {
        return .{
            .io = io,
            .group = .init,
            .registered = .init(0),
            .active = .init(0),
        };
    }

    /// Hands `channel` to this loop, which serves and eventually destroys it.
    ///
    /// Ownership of the channel transfers on success. On failure the caller
    /// still owns it and must destroy it.
    pub fn register(loop: *EventLoop, channel: *Channel) Error!void {
        _ = loop.registered.fetchAdd(1, .monotonic);
        _ = loop.active.fetchAdd(1, .monotonic);
        loop.group.concurrent(loop.io, run, .{ loop, channel }) catch |err| {
            _ = loop.active.fetchSub(1, .monotonic);
            _ = loop.registered.fetchSub(1, .monotonic);
            return err;
        };
    }

    fn run(loop: *EventLoop, channel: *Channel) void {
        defer _ = loop.active.fetchSub(1, .monotonic);
        channel.serve();
    }

    /// Requests cancelation of every channel task and waits for them to finish.
    ///
    /// Idempotent.
    pub fn shutdown(loop: *EventLoop) void {
        loop.group.cancel(loop.io);
        assert(loop.activeCount() == 0);
    }

    /// Waits for every channel task to finish on its own.
    pub fn drain(loop: *EventLoop) void {
        loop.group.await(loop.io) catch {};
    }

    pub fn activeCount(loop: *const EventLoop) usize {
        const value = loop.active.load(.acquire);
        assert(value >= 0);
        return @intCast(value);
    }

    pub fn registeredCount(loop: *const EventLoop) u64 {
        return loop.registered.load(.acquire);
    }
};

/// A fixed set of event loops with round-robin assignment.
pub const EventLoopGroup = struct {
    gpa: Allocator,
    io: Io,
    loops: []EventLoop,
    next_index: std.atomic.Value(usize),

    pub const Options = struct {
        /// Number of loops. `null` means one per logical CPU, which is the
        /// sensible default for a worker group.
        loop_count: ?usize = null,
        /// Upper bound applied to the CPU-derived default.
        max_loop_count: usize = 64,
    };

    /// Allocates the loops. The group must stay at a stable address, because
    /// the tasks it spawns refer back to it.
    pub fn init(gpa: Allocator, io: Io, options: Options) Allocator.Error!EventLoopGroup {
        const count = resolveLoopCount(options);
        assert(count > 0);

        const loops = try gpa.alloc(EventLoop, count);
        for (loops) |*loop| loop.* = .init(io);

        return .{
            .gpa = gpa,
            .io = io,
            .loops = loops,
            .next_index = .init(0),
        };
    }

    fn resolveLoopCount(options: Options) usize {
        if (options.loop_count) |requested| return @max(1, requested);
        const cpus = std.Thread.getCpuCount() catch 1;
        return std.math.clamp(cpus, 1, options.max_loop_count);
    }

    /// Cancels every loop, then frees the group. Safe to call after
    /// `shutdown`.
    pub fn deinit(group: *EventLoopGroup) void {
        group.shutdown();
        group.gpa.free(group.loops);
        group.* = undefined;
    }

    /// The next loop in round-robin order.
    pub fn next(group: *EventLoopGroup) *EventLoop {
        const index = group.next_index.fetchAdd(1, .monotonic);
        return &group.loops[index % group.loops.len];
    }

    /// Registers `channel` with the next loop, retrying the remaining loops if
    /// one cannot take it.
    ///
    /// Ownership of the channel transfers on success.
    pub fn register(group: *EventLoopGroup, channel: *Channel) EventLoop.Error!void {
        var attempts: usize = 0;
        while (attempts < group.loops.len) : (attempts += 1) {
            group.next().register(channel) catch continue;
            return;
        }
        return error.ConcurrencyUnavailable;
    }

    /// Cancels and joins every channel task in every loop. Idempotent.
    pub fn shutdown(group: *EventLoopGroup) void {
        for (group.loops) |*loop| loop.shutdown();
    }

    /// Waits for every channel task to finish on its own.
    pub fn drain(group: *EventLoopGroup) void {
        for (group.loops) |*loop| loop.drain();
    }

    pub fn loopCount(group: *const EventLoopGroup) usize {
        return group.loops.len;
    }

    pub fn activeCount(group: *const EventLoopGroup) usize {
        var total: usize = 0;
        for (group.loops) |*loop| total += loop.activeCount();
        return total;
    }

    pub fn registeredCount(group: *const EventLoopGroup) u64 {
        var total: u64 = 0;
        for (group.loops) |*loop| total += loop.registeredCount();
        return total;
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "EventLoopGroup: loop count defaults to the CPU count and is clamped" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var defaulted = try EventLoopGroup.init(gpa, io, .{});
    defer defaulted.deinit();
    try testing.expect(defaulted.loopCount() >= 1);

    var clamped = try EventLoopGroup.init(gpa, io, .{ .max_loop_count = 2 });
    defer clamped.deinit();
    try testing.expect(clamped.loopCount() <= 2);

    var explicit = try EventLoopGroup.init(gpa, io, .{ .loop_count = 3 });
    defer explicit.deinit();
    try testing.expectEqual(@as(usize, 3), explicit.loopCount());
}

test "EventLoopGroup: next cycles through the loops" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    var group = try EventLoopGroup.init(gpa, threaded.io(), .{ .loop_count = 3 });
    defer group.deinit();

    const first = group.next();
    const second = group.next();
    const third = group.next();
    const fourth = group.next();

    try testing.expect(first != second);
    try testing.expect(second != third);
    try testing.expectEqual(first, fourth);
    try testing.expectEqual(@as(usize, 0), group.activeCount());
}

// -- Integration tests -----------------------------------------------------
//
// These drive real loopback sockets: listen, accept onto a worker loop, run
// bytes through a pipeline, and tear everything down. `testing.allocator`
// checks for leaks on every path, including the cancelation path.

const channel_mod = @import("channel.zig");
const pipeline_mod = @import("pipeline.zig");
const Initializer = channel_mod.Initializer;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Shared, thread-safe tally of what the server's handlers observed.
const Observed = struct {
    bytes: std.atomic.Value(usize) = .init(0),
    reads: std.atomic.Value(usize) = .init(0),
    active: std.atomic.Value(usize) = .init(0),
    inactive: std.atomic.Value(usize) = .init(0),
    errors: std.atomic.Value(usize) = .init(0),
};

/// Echoes every chunk it receives and reports lifecycle transitions.
const EchoHandler = struct {
    observed: *Observed,
    /// When set, the connection is closed after the first echo.
    close_after_echo: bool = false,

    pub fn onActive(self: *EchoHandler, _: *HandlerContext) pipeline_mod.Error!void {
        _ = self.observed.active.fetchAdd(1, .monotonic);
    }

    pub fn onInactive(self: *EchoHandler, _: *HandlerContext) pipeline_mod.Error!void {
        _ = self.observed.inactive.fetchAdd(1, .monotonic);
    }

    pub fn onRead(
        self: *EchoHandler,
        ctx: *HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        _ = self.observed.bytes.fetchAdd(msg.len(), .monotonic);
        _ = self.observed.reads.fetchAdd(1, .monotonic);
        // The sink consumes the message even when the write fails, so there is
        // nothing to release here on either path.
        try ctx.writeAndFlush(msg);
        if (self.close_after_echo) try ctx.close();
    }

    pub fn onError(self: *EchoHandler, _: *HandlerContext, _: pipeline_mod.Error) void {
        _ = self.observed.errors.fetchAdd(1, .monotonic);
    }
};

const EchoInitializer = struct {
    observed: *Observed,
    close_after_echo: bool = false,

    pub fn initPipeline(self: *EchoInitializer, pipeline: *Pipeline) anyerror!void {
        const handler = try pipeline.gpa.create(EchoHandler);
        handler.* = .{
            .observed = self.observed,
            .close_after_echo = self.close_after_echo,
        };
        errdefer pipeline.gpa.destroy(handler);
        _ = try pipeline.addLast("echo", .initOwned(handler));
    }
};

/// Accepts exactly `count` connections and registers each with `group`.
fn acceptOnto(
    io: Io,
    gpa: Allocator,
    server: *Io.net.Server,
    group: *EventLoopGroup,
    initializer: Initializer,
    count: usize,
) void {
    var accepted: usize = 0;
    while (accepted < count) : (accepted += 1) {
        const stream = server.accept(io) catch return;
        const channel = channel_mod.Channel.create(.{
            .gpa = gpa,
            .io = io,
            .stream = stream,
            .initializer = initializer,
            .read_chunk = 4096,
            .outbound_capacity = 8,
        }) catch {
            stream.close(io);
            return;
        };
        group.register(channel) catch {
            channel.destroy();
            stream.close(io);
            return;
        };
    }
}

/// A listening socket bound to an ephemeral loopback port.
const Listener = struct {
    server: Io.net.Server,
    address: Io.net.IpAddress,

    fn open(io: Io) !Listener {
        var wanted: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        const server = try wanted.listen(io, .{ .reuse_address = true });
        return .{ .server = server, .address = server.socket.address };
    }

    fn close(listener: *Listener, io: Io) void {
        listener.server.deinit(io);
    }
};

test "integration: bytes make a round trip through a channel pipeline" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.open(io);
    defer listener.close(io);

    var group = try EventLoopGroup.init(gpa, io, .{ .loop_count = 2 });
    defer group.deinit();

    var observed: Observed = .{};
    var echo_initializer: EchoInitializer = .{ .observed = &observed };
    var acceptor = try io.concurrent(acceptOnto, .{
        io,                                  gpa,           &listener.server, &group,
        Initializer.init(&echo_initializer), @as(usize, 1),
    });
    defer acceptor.cancel(io);

    var client = try listener.address.connect(io, .{ .mode = .stream });
    var write_buffer: [64]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    try client_writer.interface.writeAll("hello zinet");
    try client_writer.interface.flush();

    var read_buffer: [64]u8 = undefined;
    var client_reader = client.reader(io, &read_buffer);
    const echoed = try client_reader.interface.take("hello zinet".len);
    try testing.expectEqualStrings("hello zinet", echoed);

    client.close(io); // Ends the server's read loop.
    group.drain();

    try testing.expectEqual(@as(usize, 1), observed.active.load(.acquire));
    try testing.expectEqual(@as(usize, 1), observed.inactive.load(.acquire));
    try testing.expectEqual(@as(usize, 11), observed.bytes.load(.acquire));
    try testing.expectEqual(@as(usize, 0), observed.errors.load(.acquire));
    try testing.expectEqual(@as(u64, 1), group.registeredCount());
    try testing.expectEqual(@as(usize, 0), group.activeCount());
}

test "integration: a handler can close the connection from the read path" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.open(io);
    defer listener.close(io);

    var group = try EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer group.deinit();

    var observed: Observed = .{};
    var echo_initializer: EchoInitializer = .{
        .observed = &observed,
        .close_after_echo = true,
    };
    var acceptor = try io.concurrent(acceptOnto, .{
        io,                                  gpa,           &listener.server, &group,
        Initializer.init(&echo_initializer), @as(usize, 1),
    });
    defer acceptor.cancel(io);

    var client = try listener.address.connect(io, .{ .mode = .stream });
    defer client.close(io);

    var write_buffer: [32]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    try client_writer.interface.writeAll("bye");
    try client_writer.interface.flush();

    var read_buffer: [32]u8 = undefined;
    var client_reader = client.reader(io, &read_buffer);
    try testing.expectEqualStrings("bye", try client_reader.interface.take(3));

    // The server shut the socket down, so the next read reports end of stream.
    try testing.expectError(error.EndOfStream, client_reader.interface.peek(1));

    group.drain();
    try testing.expectEqual(@as(usize, 1), observed.inactive.load(.acquire));
}

test "integration: shutdown cancels a live connection without leaking" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.open(io);
    defer listener.close(io);

    var group = try EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    var observed: Observed = .{};
    var echo_initializer: EchoInitializer = .{ .observed = &observed };
    var acceptor = try io.concurrent(acceptOnto, .{
        io,                                  gpa,           &listener.server, &group,
        Initializer.init(&echo_initializer), @as(usize, 1),
    });
    defer acceptor.cancel(io);

    var client = try listener.address.connect(io, .{ .mode = .stream });
    defer client.close(io);

    // Wait until the server side is serving, then pull the rug out while the
    // reader task is parked in a blocking read.
    var write_buffer: [32]u8 = undefined;
    var client_writer = client.writer(io, &write_buffer);
    try client_writer.interface.writeAll("still here");
    try client_writer.interface.flush();
    var read_buffer: [32]u8 = undefined;
    var client_reader = client.reader(io, &read_buffer);
    _ = try client_reader.interface.take("still here".len);

    group.deinit(); // Cancels the channel task mid-read.
    try testing.expectEqual(@as(usize, 1), observed.active.load(.acquire));
}

test "integration: several connections are served across the loops" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try Listener.open(io);
    defer listener.close(io);

    var group = try EventLoopGroup.init(gpa, io, .{ .loop_count = 2 });
    defer group.deinit();

    const connection_count = 4;
    var observed: Observed = .{};
    var echo_initializer: EchoInitializer = .{ .observed = &observed };
    var acceptor = try io.concurrent(acceptOnto, .{
        io,                                  gpa,
        &listener.server,                    &group,
        Initializer.init(&echo_initializer), @as(usize, connection_count),
    });
    defer acceptor.cancel(io);

    var clients: [connection_count]Io.net.Stream = undefined;
    var opened: usize = 0;
    defer for (clients[0..opened]) |client| client.close(io);

    while (opened < connection_count) : (opened += 1) {
        clients[opened] = try listener.address.connect(io, .{ .mode = .stream });
    }

    for (clients, 0..) |client, index| {
        var write_buffer: [32]u8 = undefined;
        var client_writer = client.writer(io, &write_buffer);
        try client_writer.interface.print("ping{d}", .{index});
        try client_writer.interface.flush();
    }

    for (clients, 0..) |client, index| {
        var read_buffer: [32]u8 = undefined;
        var client_reader = client.reader(io, &read_buffer);
        var expected: [8]u8 = undefined;
        const wanted = try std.fmt.bufPrint(&expected, "ping{d}", .{index});
        try testing.expectEqualStrings(wanted, try client_reader.interface.take(wanted.len));
    }

    try testing.expectEqual(@as(u64, connection_count), group.registeredCount());
    try testing.expectEqual(@as(usize, connection_count), observed.active.load(.acquire));
}
