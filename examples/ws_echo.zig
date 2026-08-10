//! A WebSocket echo server, demonstrating a protocol upgrade at run time.
//!
//! ```
//! zig build run-ws-echo -- 8090
//! websocat ws://localhost:8090/
//! ```
//!
//! The pipeline starts out speaking HTTP:
//!
//! ```
//! socket -> RequestDecoder -> ResponseEncoder -> Handshaker -> EchoHandler
//! ```
//!
//! and once the handshake succeeds the handshaker rewrites it in place:
//!
//! ```
//! socket -> FrameCodec -> EchoHandler
//! ```
//!
//! An HTTP GET to any path other than the upgrade still gets a plain HTTP
//! response, so the same port serves both.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const http = zinet.http;
const ws = zinet.websocket;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;

const default_port = 8090;
const log = std.log.scoped(.ws_echo);

var shutdown_requested: std.atomic.Value(bool) = .init(false);

const text_html = [_]http.Header{
    .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
};

/// Echoes WebSocket messages, and answers plain HTTP requests with a hint.
///
/// The same handler sees both because it sits after the handshaker: before the
/// upgrade it receives `http.Request` messages, after it `ws.Frame` messages.
const EchoHandler = struct {
    messages_echoed: u64 = 0,
    upgraded: bool = false,

    pub const handler_name = "ws-echo";

    pub fn onRead(
        self: *EchoHandler,
        ctx: *HandlerContext,
        msg: Message,
    ) zinet.pipeline.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());

        if (owned.get(ws.Frame)) |frame| return self.onFrame(ctx, frame);
        if (owned.get(http.Request)) |request| return self.onHttpRequest(ctx, request);
    }

    fn onFrame(
        self: *EchoHandler,
        ctx: *HandlerContext,
        frame: *const ws.Frame,
    ) zinet.pipeline.Error!void {
        switch (frame.opcode) {
            .text, .binary => {
                self.messages_echoed += 1;
                log.info("echoing {d} bytes ({s})", .{
                    frame.payload.len,
                    @tagName(frame.opcode),
                });
                // The frame codec serializes during the write, so borrowing the
                // inbound payload is safe here.
                const reply: ws.OutboundFrame = .{
                    .opcode = frame.opcode,
                    .payload = frame.payload,
                };
                return ctx.writeAndFlush(try Message.initAny(ctx.gpa(), ws.OutboundFrame, reply));
            },
            .close => {
                log.info("peer closed: {?}", .{frame.close_code});
                // The codec already echoed the close frame; finish the teardown.
                return ctx.close();
            },
            .pong => return,
            else => return,
        }
    }

    /// Anything that is not an upgrade gets a normal HTTP response.
    fn onHttpRequest(
        _: *EchoHandler,
        ctx: *HandlerContext,
        request: *http.Request,
    ) zinet.pipeline.Error!void {
        const response: http.Response = .{
            .status = .upgrade_required,
            .body = "this endpoint speaks WebSocket; try websocat ws://host:port/\n",
            .headers = &text_html,
            .keep_alive = request.keep_alive,
        };
        try ctx.writeAndFlush(try Message.initAny(ctx.gpa(), http.Response, response));
        if (!request.keep_alive) try ctx.close();
    }

    pub fn onEvent(
        self: *EchoHandler,
        ctx: *HandlerContext,
        event: zinet.Event,
    ) zinet.pipeline.Error!void {
        if (event.get(ws.HandshakeComplete)) |complete| {
            self.upgraded = true;
            log.info("upgraded to websocket (protocol: {?s})", .{complete.protocol});
        }
        ctx.fireEvent(event);
    }

    pub fn onInactive(self: *EchoHandler, ctx: *HandlerContext) zinet.pipeline.Error!void {
        log.info("connection closed after {d} messages", .{self.messages_echoed});
        ctx.fireInactive();
    }

    pub fn onError(_: *EchoHandler, ctx: *HandlerContext, err: anyerror) void {
        log.warn("connection failed: {s}", .{@errorName(err)});
        ctx.close() catch {};
    }
};

fn buildPipeline(pipeline: *Pipeline) anyerror!void {
    try ws.addServerUpgrade(pipeline, .{
        // Accepted when the client offers it; a compressed echo is visible proof
        // the extension works end to end.
        .permessage_deflate = .{},
        .codec = .{ .max_frame_payload = 256 * 1024 },
    });

    const handler = try pipeline.gpa.create(EchoHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast(EchoHandler.handler_name, .initOwned(handler));
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
    // Announced because a benchmark run against a Debug build of this example once produced a
    // handshake cost four times the real one, and nothing in its output said which build it was.
    // Warn rather than inform when this is a Debug build: the mode was already
    // logged at `info` and a measurement was still taken against a Debug binary
    // and briefly believed — sixteen times slower than the same example in
    // ReleaseFast. A guard that has to be noticed is not a guard, so the level
    // does the noticing.
    switch (@import("builtin").mode) {
        .Debug => log.warn("build: debug — unoptimized, not a performance measurement", .{}),
        else => log.info("build: {t}", .{@import("builtin").mode}),
    }
    log.info("websocket echo server listening on ws://localhost:{d}/", .{server.port()});
    log.info("try: websocat ws://localhost:{d}/", .{server.port()});

    while (!shutdown_requested.load(.acquire)) {
        io.sleep(.fromMilliseconds(100), .awake) catch break;
    }

    log.info("shutting down", .{});
    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(5) });
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
