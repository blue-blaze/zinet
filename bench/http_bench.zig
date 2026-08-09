//! HTTP request throughput benchmark.
//!
//! The server under test runs in **its own process, on its own `Io`**, and the load
//! generator runs in another. That separation is the point of this file's shape, and it was
//! not always so: generator and server used to share one process and one runtime, and at
//! high connection counts the numbers that came out were as much the generator's scheduling
//! delay as the server's cost. The symptom was unmistakable once both backends were
//! measured — the fiber runtime, where every connection is cheap, reported *worse*
//! throughput than the thread-per-connection one, which is the opposite of what the design
//! predicts. A harness that cannot tell the two apart cannot answer the question it exists
//! to answer.
//!
//! Three roles, one binary:
//!
//! ```
//! zig build bench-http_bench                       # spawns the server, then loads it
//! zig build bench-http_bench -- 64 5 8             # connections, seconds, worker loops
//! ./zig-out/bin/http_bench server 0 20 8           # serve only: port, seconds, workers
//! ./zig-out/bin/http_bench client 8080 64 5        # load only: port, connections, seconds
//! ```
//!
//! The separate roles are what CI and cross-machine runs use, because a client and a server
//! on one box still share cores however many processes they occupy. The default mode is for
//! a quick local answer.
//!
//! Reported: requests per second, mean and worst-case latency, pool hit rate,
//! and whether any request failed. A leak makes the process exit non-zero.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");
const bench_allocator = @import("allocator.zig");

const http = zinet.http;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;

const log = std.log.scoped(.bench);

const Role = enum {
    /// Spawn a server process, load it, report. The convenient default.
    both,
    /// Serve until the duration expires, then print the server-side statistics that only
    /// this process can see.
    server,
    /// Load a server that is already listening.
    client,
};

const Config = struct {
    role: Role = .both,
    connections: usize = 32,
    duration_seconds: u64 = 3,
    worker_count: usize = 4,
    /// Which port to serve on (`server`) or connect to (`client`). Zero lets the kernel
    /// choose, which is what `server` does when driven by `both`.
    port: u16 = 0,
    /// This executable, as it was invoked, so that `both` can spawn the server role from the
    /// same binary — and therefore the same `Io` backend, since that is a build-time choice.
    /// Owned by the caller of `parseConfig`.
    exe: []const u8 = &.{},
};

/// Prefix for what the serving process reports about itself, so that lines from the two
/// processes are attributable at a glance.
const server_prefix = "server:  ";

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
    // `smp_allocator` by default, `DebugAllocator` when asked: see bench/allocator.zig. The
    // leak-checking one unmaps pages as it frees, which on a per-request allocation costs more
    // than the network does, so measuring through it measures the harness.
    var allocators: bench_allocator.Choice = .init(init.args);
    defer allocators.deinit();
    const gpa = allocators.allocator();

    const config = try parseConfig(gpa, init.args);
    defer gpa.free(config.exe);
    switch (config.role) {
        .server => return runServer(gpa, config),
        .client => return runClient(gpa, config, null),
        .both => return runBoth(gpa, config, allocators.leak_check),
    }
}

/// Spawns the server as a child process and loads it.
///
/// The child gets the same executable and therefore the same `Io` backend, selected by
/// `-Dio=` at build time — so "which runtime is being measured" is decided once, for both
/// processes, and cannot drift between them.
///
/// Coordination is deliberately minimal: the parent picks a free port by binding one and
/// letting it go, the child is told to use it, and the parent waits for the port to answer
/// before loading it. The child inherits stdout, so its own report — the pool and accept
/// counters, which only the serving process can see — lands in the same output a person is
/// already reading.
///
/// A readiness-and-statistics protocol over a pipe was tried first and is not here. The
/// parent read the child's first line and then never observed the second, which the child had
/// demonstrably written and logged. Rather than guess at why, the coordination was removed:
/// an unexplained dependency is a worse thing to have in a measurement harness than a spare
/// bind call.
fn runBoth(gpa: std.mem.Allocator, config: Config, leak_check: bool) !void {
    var harness: std.Io.Threaded = .init(gpa, .{});
    defer harness.deinit();
    const harness_io = harness.io();

    const port = try freePort(harness_io);
    const port_text = try std.fmt.allocPrint(gpa, "{d}", .{port});
    defer gpa.free(port_text);

    // The server outlives the load, so that neither a slow start nor a slow shutdown can be
    // mistaken for a slow server.
    const seconds_text = try std.fmt.allocPrint(gpa, "{d}", .{config.duration_seconds + 3});
    defer gpa.free(seconds_text);
    const workers_text = try std.fmt.allocPrint(gpa, "{d}", .{config.worker_count});
    defer gpa.free(workers_text);

    var child = try std.process.spawn(harness_io, .{
        .argv = if (leak_check)
            &.{ config.exe, "server", port_text, seconds_text, workers_text, bench_allocator.leak_check_flag }
        else
            &.{ config.exe, "server", port_text, seconds_text, workers_text },
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

/// A port nothing is listening on, obtained the way `bootstrap`'s own tests obtain one: bind
/// to zero, read back what the kernel chose, and release it. Racy in principle and reliable
/// in practice, which is the right trade for a benchmark and the wrong one for a server.
fn freePort(io: std.Io) !u16 {
    var probe: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try probe.listen(io, .{ .reuse_address = true });
    const chosen = listener.socket.address.getPort();
    listener.deinit(io);
    return chosen;
}

/// Waits for the child to be answering on `port`, by trying to connect to it.
///
/// A connect attempt is the only readiness signal that means what it says: a server is ready
/// exactly when it accepts. Bounded, so a child that fails to start is reported rather than
/// waited on forever.
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

/// Serves for a fixed duration, then prints the counters the load side cannot observe.
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
        },
    });
    defer server.deinit();
    try server.serve();

    // Both processes write through the same logger, on stderr, so that lines from the two of
    // them cannot interleave mid-line the way a stdout writer and a logger did.
    log.info("{s}listening on port {d}", .{ server_prefix, server.port() });

    try io.sleep(.fromSeconds(@intCast(config.duration_seconds)), .awake);
    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(5) });

    const stats = pool.snapshotStats();
    const pool_requests = stats.hits + stats.misses;
    const hit_rate = if (pool_requests == 0) 0.0 else @as(f64, @floatFromInt(stats.hits)) * 100.0 /
        @as(f64, @floatFromInt(pool_requests));
    log.info("{s}{d} accepted, {d} rejected, pool hit rate {d:.1}%", .{
        server_prefix,
        server.stats.accepted.load(.acquire),
        server.stats.rejected.load(.acquire),
        hit_rate,
    });
}

/// The load generator. Speaks HTTP/1.1 over raw sockets, so nothing of the framework is in
/// the measurement path on this side.
fn runClient(gpa: std.mem.Allocator, config: Config, provided_io: ?std.Io) !void {
    var runtime: ?backend.Runtime = if (provided_io == null) try backend.Runtime.init(gpa) else null;
    defer if (runtime) |*owned| owned.deinit();
    const io = provided_io orelse runtime.?.io();

    log.info("http bench: {d} connections, {d}s, port {d}", .{
        config.connections,
        config.duration_seconds,
        config.port,
    });

    const results = try gpa.alloc(Result, config.connections);
    defer gpa.free(results);
    @memset(results, .{});

    const deadline = std.Io.Timestamp.now(io, .awake)
        .addDuration(.fromSeconds(@intCast(config.duration_seconds)));

    var group: std.Io.Group = .init;
    defer group.cancel(io);
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(config.port) };
    for (results) |*result| {
        try group.concurrent(io, loadConnection, .{
            io, gpa, address, config.port, deadline, result,
        });
    }
    const started = std.Io.Timestamp.now(io, .awake);
    group.await(io) catch {};
    const finished = std.Io.Timestamp.now(io, .awake);

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

    log.info("elapsed:          {d:.2} s", .{elapsed_s});
    log.info("requests:         {d} ({d:.0} req/s)", .{ total.requests, qps });
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

    // A leading role word, or the positional arguments the benchmark has always taken. Kept
    // compatible on purpose: the numbers published in bench/README.md were produced by the
    // old spelling and a reader should be able to reproduce them with it.
    if (std.mem.eql(u8, first, "server")) {
        config.role = .server;
        if (iterator.next()) |text| config.port = try std.fmt.parseInt(u16, text, 10);
        if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
        if (iterator.next()) |text| config.worker_count = try std.fmt.parseInt(usize, text, 10);
        return config;
    }
    if (std.mem.eql(u8, first, "client")) {
        config.role = .client;
        if (iterator.next()) |text| config.port = try std.fmt.parseInt(u16, text, 10);
        if (iterator.next()) |text| config.connections = try std.fmt.parseInt(usize, text, 10);
        if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
        if (config.port == 0) return error.PortRequired;
        if (config.connections == 0) return error.InvalidConnectionCount;
        return config;
    }

    config.connections = try std.fmt.parseInt(usize, first, 10);
    if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
    if (iterator.next()) |text| config.worker_count = try std.fmt.parseInt(usize, text, 10);
    if (config.connections == 0) return error.InvalidConnectionCount;
    return config;
}
