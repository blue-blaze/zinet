//! An echo server, the "hello world" of network frameworks.
//!
//! ```
//! zig build run-echo -- 8007
//! nc localhost 8007
//! ```
//!
//! Press Ctrl-C to shut down: the server stops accepting, lets established
//! connections finish, and exits. The allocator's leak check runs last, so a
//! clean exit is also proof that nothing was leaked.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Buffer = zinet.Buffer;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;

const default_port = 8007;
const log = std.log.scoped(.echo);

/// Set from the signal handler; polled by `main`. Only async-signal-safe
/// operations are permitted in a handler, so all it does is store a flag.
var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// Sends every chunk it receives straight back to its peer.
///
/// This handler runs in its connection's own task, so its state needs no
/// synchronization at all.
const EchoHandler = struct {
    bytes_echoed: u64 = 0,

    pub const handler_name = "echo";

    pub fn onActive(_: *EchoHandler, ctx: *HandlerContext) zinet.pipeline.Error!void {
        log.info("connection open", .{});
        ctx.fireActive();
    }

    pub fn onRead(
        self: *EchoHandler,
        ctx: *HandlerContext,
        msg: Message,
    ) zinet.pipeline.Error!void {
        self.bytes_echoed += msg.len();
        // `write` consumes the message on every path, including failure, so
        // there is nothing left to release here.
        return ctx.writeAndFlush(msg);
    }

    pub fn onInactive(self: *EchoHandler, ctx: *HandlerContext) zinet.pipeline.Error!void {
        log.info("connection closed after {d} bytes", .{self.bytes_echoed});
        ctx.fireInactive();
    }

    pub fn onError(_: *EchoHandler, ctx: *HandlerContext, err: anyerror) void {
        log.warn("connection failed: {s}", .{@errorName(err)});
        ctx.close() catch {};
    }
};

/// Builds the pipeline for each accepted connection.
///
/// The handler is heap-allocated per connection and handed to the pipeline,
/// which destroys it when the connection ends.
fn buildPipeline(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(EchoHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("echo", .initOwned(handler));
}

/// Zig 0.16 passes process state to `main` rather than exposing it globally.
/// `Init.Minimal` provides the command line while leaving the allocator and the
/// `Io` implementation to us, which is what this example wants: both are
/// created here so their leak checks are visible.
pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) std.process.exit(1);
    const gpa = debug_allocator.allocator();

    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const port = try parsePort(gpa, init.args);

    // One recycler shared by every connection's inbound buffers.
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
    log.info("echo server listening on port {d} across {d} loops", .{
        server.port(),
        server.workers.loopCount(),
    });
    log.info("connect with: nc localhost {d}", .{server.port()});

    // Wait for Ctrl-C. Polling keeps the signal handler trivial, which is what
    // makes it correct.
    while (!shutdown_requested.load(.acquire)) {
        io.sleep(.fromMilliseconds(100), .awake) catch break;
    }

    log.info("shutting down: no new connections, draining existing ones", .{});
    const drained = server.shutdownGracefully(.{ .timeout = .fromSeconds(5) });
    if (!drained) log.warn("deadline reached; remaining connections were cut", .{});
    log.info("accepted {d} connections in total", .{
        server.stats.accepted.load(.acquire),
    });
}

fn parsePort(gpa: std.mem.Allocator, args: std.process.Args) !u16 {
    var iterator = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer iterator.deinit();
    _ = iterator.skip(); // Executable name.
    const argument = iterator.next() orelse return default_port;
    return std.fmt.parseInt(u16, argument, 10);
}

fn installSignalHandlers() void {
    if (!@hasDecl(std.posix.system, "Sigaction")) return;
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        // Restart interrupted syscalls: the signal is a request to shut down,
        // not a reason for in-flight I/O to fail.
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
}

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}
