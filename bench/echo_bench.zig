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

const Config = struct {
    connections: usize = 32,
    payload_len: usize = 1024,
    duration_seconds: u64 = 3,
    worker_count: usize = 4,
};

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

    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const config = try parseConfig(gpa, init.args);

    var pool = try zinet.BufferPool.init(gpa, .{});
    defer pool.deinit();

    const server = try zinet.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = config.worker_count,
        .child = .{
            .initializer = .initFunction(buildPipeline),
            .pool = &pool,
            .read_chunk = @max(4096, config.payload_len * 2),
        },
    });
    defer server.deinit();
    try server.serve();

    log.info(
        "echo bench: {d} connections, {d} byte payload, {d}s, {d} worker loops",
        .{ config.connections, config.payload_len, config.duration_seconds, config.worker_count },
    );

    const results = try gpa.alloc(Result, config.connections);
    defer gpa.free(results);
    @memset(results, .{});

    const deadline = std.Io.Timestamp.now(io, .awake)
        .addDuration(.fromSeconds(@intCast(config.duration_seconds)));

    // Every connection runs concurrently; the group keeps them together.
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    const address = server.boundAddress();
    for (results) |*result| {
        try group.concurrent(io, loadConnection, .{
            io, gpa, address, config.payload_len, deadline, result,
        });
    }
    const started = std.Io.Timestamp.now(io, .awake);
    group.await(io) catch {};
    const finished = std.Io.Timestamp.now(io, .awake);

    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(5) });
    report(config, results, started, finished, &pool, server);
}

fn report(
    config: Config,
    results: []const Result,
    started: std.Io.Timestamp,
    finished: std.Io.Timestamp,
    pool: *zinet.BufferPool,
    server: *zinet.Server,
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

    const stats = pool.snapshotStats();
    const requests = stats.hits + stats.misses;
    const hit_rate = if (requests == 0) 0.0 else @as(f64, @floatFromInt(stats.hits)) * 100.0 / @as(f64, @floatFromInt(requests));

    log.info("elapsed:          {d:.2} s", .{elapsed_s});
    log.info("round trips:      {d} ({d:.0}/s)", .{ total.round_trips, round_trips_per_second });
    log.info("throughput:       {d:.1} MiB/s each way", .{throughput_mib});
    log.info("latency mean:     {d:.0} us", .{mean_latency_us});
    log.info("latency max:      {d:.0} us", .{
        @as(f64, @floatFromInt(total.latency_max_ns)) / 1000.0,
    });
    log.info("pool hit rate:    {d:.1}% ({d} hits, {d} misses)", .{
        hit_rate, stats.hits, stats.misses,
    });
    log.info("connections:      {d} accepted, {d} failures", .{
        server.stats.accepted.load(.acquire),
        total.failures,
    });
    _ = config;
}

fn parseConfig(gpa: std.mem.Allocator, args: std.process.Args) !Config {
    var iterator = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();

    var config: Config = .{};
    if (iterator.next()) |text| config.connections = try std.fmt.parseInt(usize, text, 10);
    if (iterator.next()) |text| config.payload_len = try std.fmt.parseInt(usize, text, 10);
    if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
    if (iterator.next()) |text| config.worker_count = try std.fmt.parseInt(usize, text, 10);

    if (config.connections == 0) return error.InvalidConnectionCount;
    if (config.payload_len == 0) return error.InvalidPayloadLength;
    return config;
}
