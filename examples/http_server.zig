//! An HTTP/1.1 server.
//!
//! ```
//! zig build run-http-server -- 8080
//! curl -v http://localhost:8080/
//! curl -v http://localhost:8080/echo -d 'hello'
//! curl -v http://localhost:8080/stream
//! ```
//!
//! Routes:
//!
//! * `/`       — a plain text greeting
//! * `/echo`   — replies with the request body and a summary of the request
//! * `/stream` — a chunked response produced in several pieces
//! * anything else — 404
//!
//! Pipeline layout:
//!
//! ```
//! socket -> RequestDecoder -> ResponseEncoder -> Router -> socket
//! ```
//!
//! The encoder sits between the decoder and the router so that inbound requests
//! pass through it untouched on their way in, while outbound responses meet it
//! on their way out.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const http = zinet.http;
const Chunk = http.Chunk;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;
const Request = http.Request;
const Response = http.Response;

const default_port = 8080;
const log = std.log.scoped(.http_server);

var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// Shared header set for the plain-text routes. A response only borrows its
/// headers, so one static array serves every request.
const text_plain = [_]http.Header{
    .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
};

/// Answers requests. One instance per connection, so no synchronization.
const Router = struct {
    requests_served: u64 = 0,

    pub const handler_name = "router";

    pub fn onRead(
        self: *Router,
        ctx: *HandlerContext,
        msg: Message,
    ) zinet.pipeline.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());

        const request = owned.get(Request) orelse return;
        self.requests_served += 1;
        log.info("{s} {s}", .{ request.method.name(), request.target });

        const path = request.path();
        if (std.mem.eql(u8, path, "/")) return self.serveRoot(ctx, request);
        if (std.mem.eql(u8, path, "/echo")) return self.serveEcho(ctx, request);
        if (std.mem.eql(u8, path, "/stream")) return self.serveStream(ctx, request);
        return self.serveNotFound(ctx, request);
    }

    fn serveRoot(
        self: *Router,
        ctx: *HandlerContext,
        request: *Request,
    ) zinet.pipeline.Error!void {
        // The body lives in the request's arena, which outlives the write
        // because the response is written before the request is released.
        const arena = request.allocator();
        const body = try std.fmt.allocPrint(
            arena,
            "Hello from Zinet\nrequests on this connection: {d}\n",
            .{self.requests_served},
        );

        const response: Response = .{
            .status = .ok,
            .body = body,
            .headers = &text_plain,
            .keep_alive = request.keep_alive,
        };
        return send(ctx, response, request.keep_alive);
    }

    fn serveEcho(
        _: *Router,
        ctx: *HandlerContext,
        request: *Request,
    ) zinet.pipeline.Error!void {
        const arena = request.allocator();
        const body = try std.fmt.allocPrint(
            arena,
            "method: {s}\ntarget: {s}\nheaders: {d}\nbody ({d} bytes):\n{s}",
            .{
                request.method.name(),
                request.target,
                request.headers.len(),
                request.body.len,
                request.body,
            },
        );

        const response: Response = .{
            .status = .ok,
            .body = body,
            .headers = &text_plain,
            .keep_alive = request.keep_alive,
        };
        return send(ctx, response, request.keep_alive);
    }

    /// Demonstrates a streamed body: the head goes out first, then chunks.
    fn serveStream(
        _: *Router,
        ctx: *HandlerContext,
        request: *Request,
    ) zinet.pipeline.Error!void {
        const arena = request.allocator();
        const response: Response = .{
            .status = .ok,
            .chunked = true,
            .headers = &text_plain,
            .keep_alive = request.keep_alive,
        };
        try ctx.write(try Message.initAny(ctx.gpa(), Response, response));

        for (1..4) |index| {
            const piece = try std.fmt.allocPrint(arena, "piece {d}\n", .{index});
            try ctx.write(try Message.initAny(ctx.gpa(), Chunk, .{ .data = piece }));
        }
        try ctx.write(try Message.initAny(ctx.gpa(), Chunk, .{ .last = true }));
        try ctx.flush();
        if (!request.keep_alive) try ctx.close();
    }

    fn serveNotFound(
        _: *Router,
        ctx: *HandlerContext,
        request: *Request,
    ) zinet.pipeline.Error!void {
        const response: Response = .{
            .status = .not_found,
            .body = "not found\n",
            .headers = &text_plain,
            .keep_alive = request.keep_alive,
        };
        return send(ctx, response, request.keep_alive);
    }

    fn send(
        ctx: *HandlerContext,
        response: Response,
        keep_alive: bool,
    ) zinet.pipeline.Error!void {
        try ctx.writeAndFlush(try Message.initAny(ctx.gpa(), Response, response));
        if (!keep_alive) try ctx.close();
    }

    /// A framing or parsing failure gets a best-effort error response, then the
    /// connection is closed: after a framing error the stream cannot be trusted.
    pub fn onError(_: *Router, ctx: *HandlerContext, err: anyerror) void {
        log.warn("request failed: {s}", .{@errorName(err)});
        const status: http.Status = switch (err) {
            error.HeaderTooLong, error.TooManyHeaders => .request_header_fields_too_large,
            error.BodyTooLarge => .payload_too_large,
            error.UnsupportedHttpVersion => .http_version_not_supported,
            else => .bad_request,
        };
        const response: Response = .{ .status = status, .keep_alive = false };
        const message = Message.initAny(ctx.gpa(), Response, response) catch {
            ctx.close() catch {};
            return;
        };
        ctx.writeAndFlush(message) catch {};
        ctx.close() catch {};
    }
};

fn buildPipeline(pipeline: *Pipeline) anyerror!void {
    try http.addServerCodec(pipeline, .{}, .{});

    const router = try pipeline.gpa.create(Router);
    router.* = .{};
    errdefer pipeline.gpa.destroy(router);
    _ = try pipeline.addLast(Router.handler_name, .initOwned(router));
}

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) std.process.exit(1);
    const gpa = debug_allocator.allocator();

    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const port = try parsePort(gpa, init.args);

    var pool = try zinet.BufferPool.init(gpa, .{});
    defer pool.deinit();

    const server = try zinet.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .unspecified(port) },
        .child = .{
            .initializer = .initFunction(buildPipeline),
            .pool = &pool,
        },
    });
    defer server.deinit();

    installSignalHandlers();
    try server.serve();
    log.info("http server listening on http://localhost:{d}/", .{server.port()});
    log.info("try: curl -v http://localhost:{d}/echo -d hello", .{server.port()});

    while (!shutdown_requested.load(.acquire)) {
        io.sleep(.fromMilliseconds(100), .awake) catch break;
    }

    log.info("shutting down", .{});
    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(5) });
    log.info("served {d} connections", .{server.stats.accepted.load(.acquire)});
}

fn parsePort(gpa: std.mem.Allocator, args: std.process.Args) !u16 {
    var iterator = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();
    const argument = iterator.next() orelse return default_port;
    return std.fmt.parseInt(u16, argument, 10);
}

fn installSignalHandlers() void {
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
}

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}
