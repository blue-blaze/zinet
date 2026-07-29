//! HTTP request throughput benchmark.
//!
//! Runs a Zinet HTTP server and a keep-alive load generator in one process.
//! The generator speaks HTTP/1.1 over a raw socket, so the framework is only
//! measured on the serving side.
//!
//! ```
//! zig build bench-http_bench                    # defaults
//! zig build bench-http_bench -- 64 5 8          # connections, seconds, worker loops
//! ```
//!
//! Reported: requests per second, mean and worst-case latency, pool hit rate,
//! and whether any request failed. A leak makes the process exit non-zero.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const http = zinet.http;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;

const log = std.log.scoped(.bench);

const Config = struct {
    connections: usize = 32,
    duration_seconds: u64 = 3,
    worker_count: usize = 4,
};

const response_body = "Hello from Zinet\n";

const response_headers = [_]http.Header{
    .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
};

/// Answers every request with the same small body, which is the standard shape
/// of an HTTP benchmark: it measures the framework, not the application.
const StaticHandler = struct {
    pub fn onRead(
        _: *StaticHandler,
        ctx: *HandlerContext,
        msg: Message,
    ) zinet.pipeline.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());

        const request = owned.get(http.Request) orelse return;
        const response: http.Response = .{
            .status = .ok,
            .body = response_body,
            .headers = &response_headers,
            .keep_alive = request.keep_alive,
        };
        return ctx.writeAndFlush(try Message.initAny(ctx.gpa(), http.Response, response));
    }
};

fn buildPipeline(pipeline: *Pipeline) anyerror!void {
    try http.addServerCodec(pipeline, .{}, .{});

    const handler = try pipeline.gpa.create(StaticHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("static", .initOwned(handler));
}

const Result = struct {
    requests: u64 = 0,
    latency_sum_ns: u64 = 0,
    latency_max_ns: u64 = 0,
    failures: u64 = 0,
};

/// Issues requests on one keep-alive connection until the deadline.
fn loadConnection(
    io: std.Io,
    gpa: std.mem.Allocator,
    address: std.Io.net.IpAddress,
    port: u16,
    deadline: std.Io.Timestamp,
    result: *Result,
) void {
    var target = address;
    var stream = target.connect(io, .{ .mode = .stream }) catch {
        result.failures += 1;
        return;
    };
    defer stream.close(io);

    const request_text = std.fmt.allocPrint(
        gpa,
        "GET /bench HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n",
        .{port},
    ) catch {
        result.failures += 1;
        return;
    };
    defer gpa.free(request_text);

    const read_buffer = gpa.alloc(u8, 4096) catch {
        result.failures += 1;
        return;
    };
    defer gpa.free(read_buffer);
    const write_buffer = gpa.alloc(u8, 1024) catch {
        result.failures += 1;
        return;
    };
    defer gpa.free(write_buffer);

    var writer = stream.writer(io, write_buffer);
    var reader = stream.reader(io, read_buffer);

    while (true) {
        if (std.Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;

        const started = std.Io.Timestamp.now(io, .awake);
        writer.interface.writeAll(request_text) catch break;
        writer.interface.flush() catch break;

        // Read the head, then exactly the advertised body.
        const head = readHead(&reader.interface) catch break;
        const content_length = parseContentLength(head) orelse {
            result.failures += 1;
            break;
        };
        reader.interface.toss(head.len);
        _ = reader.interface.take(content_length) catch break;
        const finished = std.Io.Timestamp.now(io, .awake);

        const elapsed_ns: u64 = @intCast(@max(0, started.durationTo(finished).nanoseconds));
        result.requests += 1;
        result.latency_sum_ns += elapsed_ns;
        result.latency_max_ns = @max(result.latency_max_ns, elapsed_ns);
    }
}

/// Peeks at the response head, up to and including the blank line.
fn readHead(reader: *std.Io.Reader) ![]const u8 {
    var wanted: usize = 16;
    while (true) {
        const buffered = try reader.peekGreedy(wanted);
        if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |end| {
            return buffered[0 .. end + 4];
        }
        wanted = buffered.len + 1;
    }
}

fn parseContentLength(head: []const u8) ?usize {
    const marker = "Content-Length: ";
    const start = std.mem.indexOf(u8, head, marker) orelse return null;
    const rest = head[start + marker.len ..];
    const end = std.mem.indexOfScalar(u8, rest, '\r') orelse return null;
    return std.fmt.parseInt(usize, rest[0..end], 10) catch null;
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
        },
    });
    defer server.deinit();
    try server.serve();

    log.info("http bench: {d} connections, {d}s, {d} worker loops", .{
        config.connections,
        config.duration_seconds,
        config.worker_count,
    });

    const results = try gpa.alloc(Result, config.connections);
    defer gpa.free(results);
    @memset(results, .{});

    const deadline = std.Io.Timestamp.now(io, .awake)
        .addDuration(.fromSeconds(@intCast(config.duration_seconds)));

    var group: std.Io.Group = .init;
    defer group.cancel(io);
    const address = server.boundAddress();
    for (results) |*result| {
        try group.concurrent(io, loadConnection, .{
            io, gpa, address, server.port(), deadline, result,
        });
    }
    const started = std.Io.Timestamp.now(io, .awake);
    group.await(io) catch {};
    const finished = std.Io.Timestamp.now(io, .awake);

    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(5) });

    var total: Result = .{};
    for (results) |result| {
        total.requests += result.requests;
        total.latency_sum_ns += result.latency_sum_ns;
        total.latency_max_ns = @max(total.latency_max_ns, result.latency_max_ns);
        total.failures += result.failures;
    }

    const elapsed_ns: u64 = @intCast(@max(1, started.durationTo(finished).nanoseconds));
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);
    const qps = @as(f64, @floatFromInt(total.requests)) / elapsed_s;
    const mean_latency_us = if (total.requests == 0) 0.0 else @as(f64, @floatFromInt(total.latency_sum_ns)) /
        @as(f64, @floatFromInt(total.requests)) / 1000.0;

    const stats = pool.snapshotStats();
    const pool_requests = stats.hits + stats.misses;
    const hit_rate = if (pool_requests == 0) 0.0 else @as(f64, @floatFromInt(stats.hits)) * 100.0 /
        @as(f64, @floatFromInt(pool_requests));

    log.info("elapsed:          {d:.2} s", .{elapsed_s});
    log.info("requests:         {d} ({d:.0} req/s)", .{ total.requests, qps });
    log.info("latency mean:     {d:.0} us", .{mean_latency_us});
    log.info("latency max:      {d:.0} us", .{
        @as(f64, @floatFromInt(total.latency_max_ns)) / 1000.0,
    });
    log.info("pool hit rate:    {d:.1}%", .{hit_rate});
    log.info("connections:      {d} accepted, {d} failures", .{
        server.stats.accepted.load(.acquire),
        total.failures,
    });
}

fn parseConfig(gpa: std.mem.Allocator, args: std.process.Args) !Config {
    var iterator = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();

    var config: Config = .{};
    if (iterator.next()) |text| config.connections = try std.fmt.parseInt(usize, text, 10);
    if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
    if (iterator.next()) |text| config.worker_count = try std.fmt.parseInt(usize, text, 10);
    if (config.connections == 0) return error.InvalidConnectionCount;
    return config;
}
