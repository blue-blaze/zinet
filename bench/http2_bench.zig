//! HTTP/2 request throughput benchmark.
//!
//! Same three-role shape as `http_bench`, and for the same reason: the server under test runs in
//! its own process on its own `Io`, because a load generator sharing a runtime with the server
//! measures the two together.
//!
//! ```
//! zig build bench-http2_bench                      # 8 connections, 16 streams each
//! zig build bench-http2_bench -- 8 16 5 4          # connections, streams, seconds, loops
//! ./zig-out/bin/http2_bench server 0 20 4          # serve only: port, seconds, workers
//! ./zig-out/bin/http2_bench client 8080 8 16 5     # load only: port, connections, streams, secs
//! ```
//!
//! **Two axes, because HTTP/2 has two.** A connection multiplexes many streams, and a Zinet
//! connection is served by exactly one reader task — so "requests in flight on one connection"
//! and "connections" are different questions with different answers, and a benchmark that only
//! varied one of them would miss the interesting boundary. `connections × streams` is the total
//! concurrency; the split between them is the experiment.
//!
//! **The load generator speaks HTTP/2 over a raw socket**, like `http_bench` speaks HTTP/1.1
//! over one: no part of this framework is in the measurement path on the generating side. That
//! costs about a hundred lines of frame handling and buys the ability to attribute a cost to the
//! server. Two shortcuts make it affordable, and both are stated rather than hidden:
//!
//! * **The request's HPACK block is a constant.** Every request is identical, so it is encoded
//!   once, by hand, using static-table indices and literals *without* indexing — which means the
//!   generator keeps no dynamic table and no encoder.
//! * **Responses are not decoded.** The generator reads frame headers and counts `END_STREAM`;
//!   it never decodes HPACK. Nothing about a benchmark's answer depends on reading the header it
//!   already knows.
//!
//! The generator does honour the server's `SETTINGS_MAX_CONCURRENT_STREAMS` and reports when it
//! had to clamp, because a silently clamped concurrency would make the interesting axis lie.
//!
//! Reported: requests per second, mean and worst-case latency, whether any stream was reset, and
//! the server-side pool and accept counters that only the serving process can see.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");
const bench_allocator = @import("allocator.zig");

const Io = std.Io;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;
const http2 = zinet.http2;

const log = std.log.scoped(.bench);

const Role = enum { both, server, client };

const Config = struct {
    role: Role = .both,
    connections: usize = 8,
    /// Requests in flight per connection. The HTTP/2-specific axis.
    streams: usize = 16,
    duration_seconds: u64 = 3,
    worker_count: usize = 4,
    port: u16 = 0,
    exe: []const u8 = &.{},
};

const server_prefix = "server:  ";

const response_body = "Hello from Zinet\n";

/// Answers one stream with a fixed body. A fresh instance per request.
const Responder = struct {
    pub const handler_name = "responder";

    pub fn onRead(_: *Responder, ctx: *HandlerContext, msg: Message) zinet.pipeline.Error!void {
        const gpa = ctx.gpa();
        var owned = msg;
        defer owned.deinit(gpa);

        // Only the header section warrants a reply; a body chunk on a GET does not.
        if (owned.take(gpa, http2.Headers)) |taken| {
            var headers = taken;
            defer headers.deinit(gpa);
        } else {
            return;
        }

        var fields = [_]http2.hpack.Field{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
            .{ .name = "content-length", .value = std.fmt.comptimePrint("{d}", .{response_body.len}) },
        };
        try ctx.write(try Message.initAny(gpa, http2.OutgoingHeaders, .{ .fields = &fields }));
        try ctx.write(try Message.initBytes(gpa, response_body));
        try ctx.flush();
        // Ends the stream, not the connection.
        try ctx.close();
    }
};

fn buildStream(pipeline: *Pipeline) anyerror!void {
    const responder = try pipeline.gpa.create(Responder);
    responder.* = .{};
    errdefer pipeline.gpa.destroy(responder);
    _ = try pipeline.addLast(Responder.handler_name, .initOwned(responder));
}

fn buildConnection(pipeline: *Pipeline) anyerror!void {
    _ = try http2.addServerCodec(pipeline, .{ .streams = .initFunction(buildStream) });
}

// ---------------------------------------------------------------------------
// The load generator's HTTP/2, written out rather than imported.
// ---------------------------------------------------------------------------

const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FrameType = enum(u8) {
    data = 0,
    headers = 1,
    rst_stream = 3,
    settings = 4,
    ping = 6,
    goaway = 7,
    window_update = 8,
    _,
};

const flag_end_stream: u8 = 0x1;
const flag_ack: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

/// A 9-octet frame header (§4.1), written into `dest`.
fn frameHeader(dest: *[9]u8, length: u24, kind: FrameType, flags: u8, stream: u31) void {
    std.mem.writeInt(u24, dest[0..3], length, .big);
    dest[3] = @backingInt(kind);
    dest[4] = flags;
    std.mem.writeInt(u32, dest[5..9], stream, .big);
}

const Result = struct {
    requests: u64 = 0,
    latency_sum_ns: u64 = 0,
    latency_max_ns: u64 = 0,
    failures: u64 = 0,
    resets: u64 = 0,
    /// The concurrency actually used, after the server's SETTINGS were applied.
    streams_used: usize = 0,
};

/// One stream in flight: which id, and when its request went out.
const InFlight = struct {
    id: u31 = 0,
    started: Io.Timestamp = undefined,
};

/// Drives one connection until the deadline, keeping `wanted_streams` requests in flight.
fn loadConnection(
    io: Io,
    gpa: std.mem.Allocator,
    port: u16,
    wanted_streams: usize,
    deadline: Io.Timestamp,
    result: *Result,
) void {
    runConnection(io, gpa, port, wanted_streams, deadline, result) catch {
        result.failures += 1;
    };
}

fn runConnection(
    io: Io,
    gpa: std.mem.Allocator,
    port: u16,
    wanted_streams: usize,
    deadline: Io.Timestamp,
    result: *Result,
) !void {
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    const read_buffer = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(read_buffer);
    const write_buffer = try gpa.alloc(u8, 64 * 1024);
    defer gpa.free(write_buffer);
    var writer = stream.writer(io, write_buffer);
    var reader = stream.reader(io, read_buffer);

    const request_block = try requestBlock(gpa, port);
    defer gpa.free(request_block);

    // Preface, then our SETTINGS. Empty: the defaults are what a client here wants, and
    // announcing values it does not need would put them in the measurement.
    try writer.interface.writeAll(preface);
    var header: [9]u8 = undefined;
    frameHeader(&header, 0, .settings, 0, 0);
    try writer.interface.writeAll(&header);
    try writer.interface.flush();

    const in_flight = try gpa.alloc(InFlight, wanted_streams);
    defer gpa.free(in_flight);
    @memset(in_flight, .{});

    // Until the server's SETTINGS arrive, one stream is always safe: §6.5.2's default for
    // MAX_CONCURRENT_STREAMS is unlimited, but a server that means to allow fewer says so in
    // the SETTINGS it sends immediately, and starting conservatively costs one round trip.
    var allowed: usize = 1;
    var next_id: u31 = 1;
    var consumed_since_update: u32 = 0;
    var settings_seen = false;

    while (true) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;

        // Top up the streams in flight.
        var launched = false;
        for (in_flight[0..@min(allowed, wanted_streams)]) |*slot| {
            if (slot.id != 0) continue;
            slot.id = next_id;
            slot.started = Io.Timestamp.now(io, .awake);
            next_id += 2;
            frameHeader(
                &header,
                @intCast(request_block.len),
                .headers,
                flag_end_stream | flag_end_headers,
                slot.id,
            );
            try writer.interface.writeAll(&header);
            try writer.interface.writeAll(request_block);
            launched = true;
        }
        if (launched) try writer.interface.flush();

        // One frame, then back to the top: a request is launched as soon as a slot frees, which
        // is what keeps the concurrency at the number the run claims.
        const raw = reader.interface.takeArray(9) catch break;
        const length = std.mem.readInt(u24, raw[0..3], .big);
        const kind: FrameType = @fromBackingInt(@intCast(raw[3]));
        const flags = raw[4];
        const stream_id: u31 = @truncate(std.mem.readInt(u32, raw[5..9], .big) & 0x7fff_ffff);

        switch (kind) {
            .settings => {
                if (flags & flag_ack != 0) {
                    reader.interface.discardAll(length) catch break;
                } else {
                    const payload = reader.interface.take(length) catch break;
                    if (!settings_seen) {
                        settings_seen = true;
                        allowed = wanted_streams;
                        if (maxConcurrentStreams(payload)) |limit| {
                            allowed = @min(wanted_streams, limit);
                        }
                    }
                    frameHeader(&header, 0, .settings, flag_ack, 0);
                    try writer.interface.writeAll(&header);
                    try writer.interface.flush();
                }
            },
            .ping => {
                if (flags & flag_ack != 0) {
                    reader.interface.discardAll(length) catch break;
                } else {
                    const payload = reader.interface.take(length) catch break;
                    frameHeader(&header, @intCast(payload.len), .ping, flag_ack, 0);
                    try writer.interface.writeAll(&header);
                    try writer.interface.writeAll(payload);
                    try writer.interface.flush();
                }
            },
            .goaway => break,
            .rst_stream => {
                reader.interface.discardAll(length) catch break;
                if (findSlot(in_flight, stream_id)) |slot| {
                    slot.id = 0;
                    result.resets += 1;
                }
            },
            .data, .headers => {
                reader.interface.discardAll(length) catch break;
                if (kind == .data) consumed_since_update += length;
                if (flags & flag_end_stream != 0) {
                    if (findSlot(in_flight, stream_id)) |slot| {
                        const finished = Io.Timestamp.now(io, .awake);
                        const elapsed: u64 = @intCast(@max(0, slot.started.durationTo(finished).nanoseconds));
                        result.requests += 1;
                        result.latency_sum_ns += elapsed;
                        result.latency_max_ns = @max(result.latency_max_ns, elapsed);
                        slot.id = 0;
                    }
                }
                // The connection window is the one a short-lived-stream workload actually
                // exhausts: each stream gets a fresh window, the connection does not.
                if (consumed_since_update >= 32 * 1024) {
                    frameHeader(&header, 4, .window_update, 0, 0);
                    var increment: [4]u8 = undefined;
                    std.mem.writeInt(u32, &increment, consumed_since_update, .big);
                    try writer.interface.writeAll(&header);
                    try writer.interface.writeAll(&increment);
                    try writer.interface.flush();
                    consumed_since_update = 0;
                }
            },
            else => reader.interface.discardAll(length) catch break,
        }
    }

    result.streams_used = @min(allowed, wanted_streams);
}

fn findSlot(slots: []InFlight, id: u31) ?*InFlight {
    for (slots) |*slot| {
        if (slot.id == id) return slot;
    }
    return null;
}

/// §6.5.2's MAX_CONCURRENT_STREAMS, if the SETTINGS payload carries it.
fn maxConcurrentStreams(payload: []const u8) ?usize {
    var offset: usize = 0;
    while (offset + 6 <= payload.len) : (offset += 6) {
        const id = std.mem.readInt(u16, payload[offset..][0..2], .big);
        const value = std.mem.readInt(u32, payload[offset + 2 ..][0..4], .big);
        if (id == 0x3) return value;
    }
    return null;
}

/// The request's HPACK block, encoded once.
///
/// `:method` and `:scheme` are static-table indices (§2.3.1); `:path` and `:authority` are
/// literals whose *names* come from the static table and which are **not** added to the dynamic
/// table (§6.2.2). That is what lets this generator have no HPACK encoder and no table at all.
fn requestBlock(gpa: std.mem.Allocator, port: u16) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    try out.append(gpa, 0x82); // :method: GET, static index 2
    try out.append(gpa, 0x86); // :scheme: http, static index 6

    const path = "/bench";
    try out.append(gpa, 0x04); // literal without indexing, name = static index 4 (:path)
    try out.append(gpa, @intCast(path.len));
    try out.appendSlice(gpa, path);

    var authority_buffer: [32]u8 = undefined;
    const authority = try std.fmt.bufPrint(&authority_buffer, "127.0.0.1:{d}", .{port});
    try out.append(gpa, 0x01); // literal without indexing, name = static index 1 (:authority)
    try out.append(gpa, @intCast(authority.len));
    try out.appendSlice(gpa, authority);

    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

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

fn runBoth(gpa: std.mem.Allocator, config: Config, leak_check: bool) !void {
    var harness: Io.Threaded = .init(gpa, .{});
    defer harness.deinit();
    const harness_io = harness.io();

    const port = try freePort(harness_io);
    const port_text = try std.fmt.allocPrint(gpa, "{d}", .{port});
    defer gpa.free(port_text);
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

fn freePort(io: Io) !u16 {
    var probe: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try probe.listen(io, .{ .reuse_address = true });
    const chosen = listener.socket.address.getPort();
    listener.deinit(io);
    return chosen;
}

fn awaitListening(io: Io, port: u16) !void {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        if (address.connect(io, .{ .mode = .stream })) |stream| {
            stream.close(io);
            return;
        } else |_| {
            try io.sleep(.fromMilliseconds(25), .awake);
        }
    }
    return error.ServerDidNotStart;
}

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
            .initializer = .initFunction(buildConnection),
            .pool = &pool,
        },
    });
    defer server.deinit();
    try server.serve();

    log.info("{s}build: {t}", .{ server_prefix, @import("builtin").mode });
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

fn runClient(gpa: std.mem.Allocator, config: Config, provided_io: ?Io) !void {
    var runtime: ?backend.Runtime = if (provided_io == null) try backend.Runtime.init(gpa) else null;
    defer if (runtime) |*owned| owned.deinit();
    const io = provided_io orelse runtime.?.io();

    log.info("http/2 bench: {d} connections x {d} streams, {d}s, port {d}", .{
        config.connections,
        config.streams,
        config.duration_seconds,
        config.port,
    });

    const results = try gpa.alloc(Result, config.connections);
    defer gpa.free(results);
    @memset(results, .{});

    const deadline = Io.Timestamp.now(io, .awake)
        .addDuration(.fromSeconds(@intCast(config.duration_seconds)));

    var group: Io.Group = .init;
    defer group.cancel(io);
    for (results) |*result| {
        try group.concurrent(io, loadConnection, .{
            io, gpa, config.port, config.streams, deadline, result,
        });
    }
    const started = Io.Timestamp.now(io, .awake);
    group.await(io) catch {};
    const finished = Io.Timestamp.now(io, .awake);

    var total: Result = .{};
    var streams_used: usize = 0;
    for (results) |result| {
        total.requests += result.requests;
        total.latency_sum_ns += result.latency_sum_ns;
        total.latency_max_ns = @max(total.latency_max_ns, result.latency_max_ns);
        total.failures += result.failures;
        total.resets += result.resets;
        streams_used = @max(streams_used, result.streams_used);
    }

    const elapsed_ns: u64 = @intCast(@max(1, started.durationTo(finished).nanoseconds));
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);
    const qps = @as(f64, @floatFromInt(total.requests)) / elapsed_s;
    const mean_us = if (total.requests == 0) 0.0 else @as(f64, @floatFromInt(total.latency_sum_ns)) /
        @as(f64, @floatFromInt(total.requests)) / 1000.0;

    log.info("elapsed:          {d:.2} s", .{elapsed_s});
    log.info("requests:         {d} ({d:.0} req/s)", .{ total.requests, qps });
    log.info("latency mean:     {d:.0} us", .{mean_us});
    log.info("latency max:      {d:.0} us", .{
        @as(f64, @floatFromInt(total.latency_max_ns)) / 1000.0,
    });
    log.info("failures:         {d} ({d} stream resets)", .{ total.failures, total.resets });
    if (streams_used != config.streams) {
        log.info("streams clamped:  {d} of {d} requested (server's SETTINGS)", .{
            streams_used,
            config.streams,
        });
    }
}

fn parseConfig(gpa: std.mem.Allocator, args: std.process.Args) !Config {
    var iterator = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iterator.deinit();

    var config: Config = .{};
    config.exe = try gpa.dupe(u8, iterator.next() orelse return error.NoExecutablePath);
    const first = iterator.next() orelse return config;

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
        if (iterator.next()) |text| config.streams = try std.fmt.parseInt(usize, text, 10);
        if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
        if (config.port == 0) return error.PortRequired;
        if (config.connections == 0 or config.streams == 0) return error.InvalidConcurrency;
        return config;
    }

    config.connections = try std.fmt.parseInt(usize, first, 10);
    if (iterator.next()) |text| config.streams = try std.fmt.parseInt(usize, text, 10);
    if (iterator.next()) |text| config.duration_seconds = try std.fmt.parseInt(u64, text, 10);
    if (iterator.next()) |text| config.worker_count = try std.fmt.parseInt(usize, text, 10);
    if (config.connections == 0 or config.streams == 0) return error.InvalidConcurrency;
    return config;
}
