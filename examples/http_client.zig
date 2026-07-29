//! An HTTP/1.1 client: fetches a URL and prints the response.
//!
//! ```
//! zig build run-http-client -- localhost 8080 /echo
//! ```
//!
//! The shape worth copying is where the request is sent. `addClientCodec`
//! requires it to happen on the connection's own task, so the request goes out
//! from `onActive` and the response comes back through an `Io.Queue` that `main`
//! waits on. That is the pattern for driving any client protocol in Zinet: the
//! pipeline stays single-tasked, and the queue is the seam between it and the
//! rest of the program.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Io = std.Io;

/// What the handler hands back to `main`. A fixed-size copy rather than a
/// pointer, so nothing in the response's arena has to outlive the callback.
const Outcome = union(enum) {
    response: struct {
        status: u16,
        body_len: usize,
        body: [4096]u8,
    },
    failed: [64]u8,
};

var outcomes: Io.Queue(Outcome) = undefined;
var outcome_storage: [2]Outcome = undefined;
var tracker: zinet.HttpMethodTracker = .{};

/// Sends one request when the connection comes up, and reports what comes back.
const Fetch = struct {
    host: []const u8,
    target: []const u8,

    pub fn onActive(self: *Fetch, ctx: *zinet.HandlerContext) !void {
        try ctx.writeAndFlush(try zinet.Message.initAny(
            ctx.gpa(),
            zinet.HttpOutgoingRequest,
            .{
                .method = .get,
                .target = self.target,
                .host = self.host,
                // One request, then done: no reason to keep the connection.
                .keep_alive = false,
            },
        ));
        ctx.fireActive();
    }

    pub fn onRead(_: *Fetch, ctx: *zinet.HandlerContext, msg: zinet.Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const response = owned.get(zinet.HttpIncomingResponse) orelse return;

        var outcome: Outcome = .{ .response = .{
            .status = response.status.code(),
            .body_len = @min(response.body.len, 4096),
            .body = undefined,
        } };
        @memcpy(
            outcome.response.body[0..outcome.response.body_len],
            response.body[0..outcome.response.body_len],
        );
        try outcomes.putOne(ctx.io(), outcome);
    }

    pub fn onError(_: *Fetch, ctx: *zinet.HandlerContext, err: anyerror) void {
        var text: [64]u8 = @splat(0);
        const name = @errorName(err);
        @memcpy(text[0..@min(name.len, 64)], name[0..@min(name.len, 64)]);
        outcomes.putOne(ctx.io(), .{ .failed = text }) catch {};
        ctx.close() catch {};
    }
};

var fetch_config: Fetch = .{ .host = "", .target = "/" };

fn buildPipeline(pipeline: *zinet.Pipeline) anyerror!void {
    try zinet.http.addClientCodec(pipeline, &tracker, .{});

    const handler = try pipeline.gpa.create(Fetch);
    handler.* = fetch_config;
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("fetch", .initOwned(handler));
}

pub fn main(init: std.process.Init.Minimal) !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug.deinit() == .leak) std.process.exit(1);
    const gpa = debug.allocator();

    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var iterator = try std.process.Args.Iterator.initAllocator(init.args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();
    // The strings must outlive the iterator, because the handler holds them for
    // the life of the connection.
    const host = try gpa.dupe(u8, iterator.next() orelse "localhost");
    defer gpa.free(host);
    const port_text = try gpa.dupe(u8, iterator.next() orelse "8080");
    defer gpa.free(port_text);
    const target = try gpa.dupe(u8, iterator.next() orelse "/");
    defer gpa.free(target);
    const port = try std.fmt.parseInt(u16, port_text, 10);

    fetch_config = .{ .host = host, .target = target };
    outcomes = .init(&outcome_storage);

    var loops = try zinet.EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer loops.deinit();

    // Resolve to a loopback or literal address; this example does not do DNS.
    const address: Io.net.IpAddress = blk: {
        if (std.mem.eql(u8, host, "localhost")) break :blk .{ .ip4 = .loopback(port) };
        break :blk Io.net.IpAddress.parse(host, port) catch {
            std.debug.print("cannot parse '{s}' as an IP address\n", .{host});
            return error.InvalidAddress;
        };
    };

    const channel = try zinet.connect(.{
        .gpa = gpa,
        .io = io,
        .address = address,
        .loops = &loops,
        .config = .{ .initializer = .initFunction(buildPipeline) },
    });
    defer channel.release();

    switch (try outcomes.getOne(io)) {
        .response => |response| {
            std.debug.print("HTTP {d}\n{s}\n", .{
                response.status,
                response.body[0..response.body_len],
            });
        },
        .failed => |text| {
            std.debug.print("failed: {s}\n", .{std.mem.sliceTo(&text, 0)});
        },
    }

    channel.requestClose();
    loops.shutdown();
    loops.drain();
}
