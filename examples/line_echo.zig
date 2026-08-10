//! A line-oriented echo server, showing a framing decoder in a pipeline.
//!
//! ```
//! zig build run-line-echo -- 8008
//! nc localhost 8008
//! ```
//!
//! Type a line and it comes back numbered and upper-cased. Unlike the raw echo
//! example, handlers here never see partial lines: the decoder in front of them
//! guarantees one message per line, however the bytes happened to arrive.
//!
//! Pipeline layout:
//!
//! ```
//! socket -> LineBasedFrameDecoder -> LineHandler -> socket
//! ```

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Buffer = zinet.Buffer;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;

const default_port = 8008;
const max_line_length = 1024;
const log = std.log.scoped(.line_echo);

var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// Answers each decoded line. Per-connection state, so no synchronization.
const LineHandler = struct {
    lines_seen: u32 = 0,

    pub const handler_name = "line-handler";

    pub fn onRead(
        self: *LineHandler,
        ctx: *HandlerContext,
        msg: Message,
    ) zinet.pipeline.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());

        const line = owned.bytes() orelse return;
        self.lines_seen += 1;

        if (std.mem.eql(u8, line, "quit")) {
            try reply(ctx, self.lines_seen, "bye");
            return ctx.close();
        }

        var upper: [max_line_length]u8 = undefined;
        const copied = @min(line.len, upper.len);
        for (line[0..copied], upper[0..copied]) |source, *target| {
            target.* = std.ascii.toUpper(source);
        }
        return reply(ctx, self.lines_seen, upper[0..copied]);
    }

    fn reply(
        ctx: *HandlerContext,
        number: u32,
        text: []const u8,
    ) zinet.pipeline.Error!void {
        var out: Buffer = .empty;
        errdefer out.deinit(ctx.gpa());

        var scratch: [32]u8 = undefined;
        var adapter = out.writerAdapter(ctx.gpa(), &scratch);
        try adapter.interface.print("{d}: ", .{number});
        try adapter.interface.writeAll(text);
        try adapter.interface.writeByte('\n');
        try adapter.interface.flush();

        return ctx.writeAndFlush(.initBuffer(&out));
    }

    pub fn onError(_: *LineHandler, ctx: *HandlerContext, err: anyerror) void {
        log.warn("connection failed: {s}", .{@errorName(err)});
        ctx.close() catch {};
    }
};

fn buildPipeline(pipeline: *Pipeline) anyerror!void {
    _ = try zinet.LineBasedFrameDecoder.addTo(pipeline, .{
        .max_length = max_line_length,
    });

    const handler = try pipeline.gpa.create(LineHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast(LineHandler.handler_name, .initOwned(handler));
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
    log.info("line echo server listening on port {d}", .{server.port()});
    log.info("try: nc localhost {d}   (send \"quit\" to disconnect)", .{server.port()});

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
