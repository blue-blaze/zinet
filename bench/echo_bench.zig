//! Echo throughput benchmark.
//!
//! Runs a Zinet echo server and a load generator in the same process, so the
//! numbers are reproducible without any external tool. Both sides use raw
//! sockets for the client to keep the framework out of the measurement path on
//! the generating side.
//!
//! ```
//! zig build bench-echo_bench                       # defaults
//! zig build bench-echo_bench -- 64 4096 5          # connections, payload, seconds
//! ```
//!
//! Reported:
//!
//! * round trips per second, and bytes per second in each direction,
//! * mean and worst-case round-trip latency,
//! * buffer pool hit rate, which shows whether recycling is working,
//! * bytes still allocated at the end, which must be zero.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;

const log = std.log.scoped(.bench);

/// The same three roles as `http_bench`, for the same reason: a load generator sharing a
/// process and a runtime with the server under test measures both together, and at high
/// connection counts mostly measures itself.
const Role = enum { both, server, client };

const Config = struct {
    role: Role = .both,
    connections: usize = 32,
    payload_len: usize = 1024,
    duration_seconds: u64 = 3,
    worker_count: usize = 4,
    port: u16 = 0,
    /// This executable, as invoked, so `both` can spawn the server role from it.
    exe: []const u8 = &.{},
};

const server_prefix = "server:  ";

/// Echoes bytes straight back; the smallest possible server-side pipeline.
const EchoHandler = struct {
    pub fn onRead(
        _: *EchoHandler,
        ctx: *HandlerContext,
        msg: Message,
    ) zinet.pipeline.Error!void {
        return ctx.writeAndFlush(msg);
    }
};

fn buildPipeline(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(EchoHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("echo", .initOwned(handler));
}

/// Per-connection results, summed by the reporter.
const Result = struct {
    round_trips: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    latency_sum_ns: u64 = 0,
    latency_max_ns: u64 = 0,
    failures: u64 = 0,
};

/// Drives one connection: send a payload, read it back, repeat until the
/// deadline. Latency is measured per round trip.
fn loadConnection(
    io: std.Io,
    gpa: std.mem.Allocator,
    address: std.Io.net.IpAddress,
    payload_len: usize,
    deadline: std.Io.Timestamp,
    result: *Result,
) void {
    var target = address;
    var stream = target.connect(io, .{ .mode = .stream }) catch {
        result.failures += 1;
        return;
    };
    defer stream.close(io);

    const payload = gpa.alloc(u8, payload_len) catch {
        result.failures += 1;
        return;
    };
    defer gpa.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);

    const read_buffer = gpa.alloc(u8, payload_len * 2) catch {
        result.failures += 1;
        return;
    };
    defer gpa.free(read_buffer);
    const write_buffer = gpa.alloc(u8, payload_len) catch {
        result.failures += 1;
        return;
    };
    defer gpa.free(write_buffer);

    var writer = stream.writer(io, write_buffer);
    var reader = stream.reader(io, read_buffer);

    while (true) {
        const now = std.Io.Timestamp.now(io, .awake);
        if (now.nanoseconds >= deadline.nanoseconds) break;

        const started = std.Io.Timestamp.now(io, .awake);
        writer.interface.writeAll(payload) catch break;
        writer.interface.flush() catch break;
        const echoed = reader.interface.take(payload_len) catch break;
        const finished = std.Io.Timestamp.now(io, .awake);

        if (echoed.len != payload_len) {
            result.failures += 1;
            break;
        }
        const elapsed_ns: u64 = @intCast(@max(
            0,
            started.durationTo(finished).nanoseconds,
        ));
        result.round_trips += 1;
        result.bytes_sent += payload_len;
        result.bytes_received += payload_len;
        result.latency_sum_ns += elapsed_ns;
        result.latency_max_ns = @max(result.latency_max_ns, elapsed_ns);
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) {
        log.err("benchmark leaked memory", .{});
        std.process.exit(1);
    };
    const gpa = debug_allocator.allocator();

    const config = try parseConfig(gpa, init.args);
    defer gpa.free(config.exe);
    switch (config.role) {
        .server => return runServer(gpa, config),
        .client => return runClient(gpa, config, null),
        .both => return runBoth(gpa, config),
    }
}

/// Spawns the server role from this same binary — same `Io` backend, since that is chosen at
/// build time — and loads it. See `http_bench.runBoth` for why the two are separate processes
/// and why the coordination is a pre-chosen port rather than a pipe.
fn runBoth(gpa: std.mem.Allocator, config: Config) !void {
    var harness: std.Io.Threaded = .init(gpa, .{});
    defer harness.deinit();
    const harness_io = harness.io();

    const port = try freePort(harness_io);
    const port_text = try std.fmt.allocPrint(gpa, "{d}", .{port});
    defer gpa.free(port_text);
    const seconds_text = try std.fmt.allocPrint(gpa, "{d}", .{config.duration_seconds + 3});
    defer gpa.free(seconds_text);
    const workers_text = try std.fmt.allocPrint(gpa, "{d}", .{config.worker_count});
    defer gpa.free(workers_text);
    const payload_text = try std.fmt.allocPrint(gpa, "{d}", .{config.payload_len});
    defer gpa.free(payload_text);

    var child = try std.process.spawn(harness_io, .{
        .argv = &.{ config.exe, "server", port_text, seconds_text, workers_text, payload_text },
    });
    var reaped = false;
    defer if (!reaped) child.kill(harness_io);

    try awaitListening(harness_io, port);

    var client_config = config;
    client_config.port = port;
    var load_runtime = try backend.Runtime.init(gpa);
    defer load_runtime.deinit();
    try runClient(gpa, client_config, load_runtime.io());

    _ = child.wait(harness_io) catch {};
    reaped = true;
}

fn freePort(io: std.Io) !u16 {
    var probe: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try probe.listen(io, .{ .reuse_address = true });
    const chosen = listener.socket.address.getPort();
    listener.deinit(io);
    return chosen;
}

fn awaitListening(io: std.Io, port: u16) !void {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        if (address.connect(io, .{ .mode = .stream })) |stream| {
            stream.close(io);
            return;
        } else |_| {
            try io.sleep(.fromMilliseconds(25), .awake);
        }
    }
    return error.ServerDidNotStart;
}

/// Serves echoes for a fixed duration, then reports what only the serving process can see.
fn runServer(gpa: std.mem.Allocator, config: Config) !void {
    var runtime = try backend.Runtime.init(gpa);
    defer runtime.deinit();
    const io = runtime.io();

    var pool = try zinet.BufferPool.init(gpa, .{});
    defer pool.deinit();

    const server = try zinet.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(config.port) },
        .worker_count = config.worker_count,
        .child = .{
            .initializer = .initFunction(buildPipeline),
            .pool = &pool,
            .read_chunk = @max(4096, config.payload_len * 2),
        },
    });
    defer server.deinit();
    try server.serve();

    log.info("{s}listening on port {d}", .{ server_prefix, server.port() });

    try io.sleep(.fromSeconds(@intCast(config.duration_seconds)), .awake);
    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(5) });

    const stats = pool.snapshotStats();
    const requests = stats.hits + stats.misses;
    const hit_rate = if (requests == 0) 0.0 else @as(f64, @floatFromInt(stats.hits)) * 100.0 /
        @as(f64, @floatFromInt(requests));
    log.info("{s}{d} accepted, {d} rejected, pool hit rate {d:.1}% ({d} hits, {d} misses)", .{
        server_prefix,
        server.stats.accepted.load(.acquire),
        server.stats.rejected.load(.acquire),
        hit_rate,
        stats.hits,
        stats.misses,
    });
}

/// The load generator: raw sockets, so the framework is measured only on the serving side.
fn runClient(gpa: std.mem.Allocator, config: Config, provided_io: ?std.Io) !void {
    var runtime: ?backend.Runtime = if (provided_io == null) try backend.Runtime.init(gpa) else null;
    defer if (runtime) |*owned| owned.deinit();
    const io = provided_io orelse runtime.?.io();

    log.info(
        "echo bench: {d} connections, {d} byte payload, {d}s, port {d}",
        .{ config.connections, config.payload_len, config.duration_seconds, config.port },
    );

    const results = try gpa.alloc(Result, config.connections);
    defer gpa.free(results);
    @memset(results, .{});

    const deadline = std.Io.Timestamp.now(io, .awake)
        .addDuration(.fromSeconds(@intCast(config.duration_seconds)));

    // Every connection runs concurrently; the group keeps them together.
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(config.port) };
    for (results) |*result| {
        try group.concurrent(io, loadConnection, .{
            io, gpa, address, config.payload_len, deadline, result,
        });
    }
    const started = std.Io.Timestamp.now(io, .awake);
    group.await(io) catch {};
    const finished = std.Io.Timestamp.now(io, .awake);

    report(results, started, finished);
}

fn report(
    results: []const Result,
    started: std.Io.Timestamp,
    finished: std.Io.Timestamp,
) void {
    var total: Result = .{};
    for (results) |result| {
        total.round_trips += result.round_trips;
        total.bytes_sent += result.bytes_sent;
        total.bytes_received += result.bytes_received;
        total.latency_sum_ns += result.latency_sum_ns;
        total.latency_max_ns = @max(total.latency_max_ns, result.latency_max_ns);
        total.failures += result.failures;
    }

    const elapsed_ns: u64 = @intCast(@max(1, started.durationTo(finished).nanoseconds));
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);
    const round_trips_per_second = @as(f64, @floatFromInt(total.round_trips)) / elapsed_s;
    const throughput_mib = @as(f64, @floatFromInt(total.bytes_sent)) /
        elapsed_s / (1024.0 * 1024.0);
    const mean_latency_us = if (total.round_trips == 0) 0.0 else @as(f64, @floatFromInt(total.latency_sum_ns)) /
        @as(f64, @floatFromInt(total.round_trips)) / 1000.0;

    log.info("elapsed:          {d:.2} s", .{elapsed_s});
    log.info("round trips:      {d} ({d:.0}/s)", .{ total.round_trips, round_trips_per_second });
    log.info("throughput:       {d:.1} MiB/s each way", .{throughput_mib});
    log.info("latency mean:     {d:.0} us", .{mean_latency_us});
    log.info("latency max:      {d:.0} us", .{
        @as(f64, @floatFromInt(total.latency_max_ns)) / 1000.0,
    });
    log.info("failures:         {d}", .{total.failures});
}

fn parseConfig(gpa: std.mem.Allocator, args: std.process.Args) !Config {
    var iterator = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iterator.deinit();

    var config: Config = .{};
    config.exe = try gpa.dupe(u8, iterator.next() orelse return error.NoExecutablePath);
    const first = iterator.next() orelse return config;

    // A role word, or the positional arguments this benchmark has always taken — kept so the
    // numbers in bench/README.md remain reproducible with the spelling that produced them.
    if (std.mem.eql(u8, first, "server")) {
        config.role = .server;
        if (iterator.next()) |text| config.port = try std.fmt.parseInt(u16, text, 10);
        if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
        if (iterator.next()) |text| config.worker_count = try std.fmt.parseInt(usize, text, 10);
        if (iterator.next()) |text| config.payload_len = try std.fmt.parseInt(usize, text, 10);
        if (config.payload_len == 0) return error.InvalidPayloadLength;
        return config;
    }
    if (std.mem.eql(u8, first, "client")) {
        config.role = .client;
        if (iterator.next()) |text| config.port = try std.fmt.parseInt(u16, text, 10);
        if (iterator.next()) |text| config.connections = try std.fmt.parseInt(usize, text, 10);
        if (iterator.next()) |text| config.payload_len = try std.fmt.parseInt(usize, text, 10);
        if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
        if (config.port == 0) return error.PortRequired;
        if (config.connections == 0) return error.InvalidConnectionCount;
        if (config.payload_len == 0) return error.InvalidPayloadLength;
        return config;
    }

    config.connections = try std.fmt.parseInt(usize, first, 10);
    if (iterator.next()) |text| config.payload_len = try std.fmt.parseInt(usize, text, 10);
    if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
    if (iterator.next()) |text| config.worker_count = try std.fmt.parseInt(usize, text, 10);

    if (config.connections == 0) return error.InvalidConnectionCount;
    if (config.payload_len == 0) return error.InvalidPayloadLength;
    return config;
}
