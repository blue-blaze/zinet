//! Compile check for the snippets in the top-level README.
//!
//! Documentation that does not compile is worse than no documentation, so the
//! handler and codec examples from the README live here as real code. This file
//! is built by `zig build examples`; if the README drifts, the build fails.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Buffer = zinet.Buffer;
const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;

/// From "Writing a handler".
const CountingHandler = struct {
    reads: u64 = 0,

    pub const handler_name = "counter";

    pub fn onActive(_: *@This(), ctx: *HandlerContext) !void {
        ctx.fireActive();
    }

    pub fn onRead(self: *@This(), ctx: *HandlerContext, msg: Message) !void {
        self.reads += 1;
        ctx.fireRead(msg);
    }

    pub fn onError(_: *@This(), ctx: *HandlerContext, err: anyerror) void {
        std.log.warn("counter saw {s}", .{@errorName(err)});
        ctx.close() catch {};
    }
};

/// From "Writing a codec": four-byte fixed-size frames.
const MyCodec = struct {
    decoder: zinet.codec.ByteToMessageDecoder(MyCodec) = .{},

    pub fn onRead(self: *MyCodec, ctx: *HandlerContext, msg: Message) !void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn deinit(self: *MyCodec, gpa: std.mem.Allocator) void {
        self.decoder.deinit(gpa);
    }

    pub fn decode(
        _: *MyCodec,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) !?Message {
        if (cumulation.readableLen() < 4) return null;
        const payload = try cumulation.readBytes(4);
        return try Message.initBytes(ctx.gpa(), payload);
    }
};

/// From the opening example.
const EchoHandler = struct {
    pub fn onRead(_: *EchoHandler, ctx: *HandlerContext, msg: Message) !void {
        return ctx.writeAndFlush(msg);
    }
};

fn buildPipeline(pipeline: *Pipeline) anyerror!void {
    const codec = try pipeline.gpa.create(MyCodec);
    codec.* = .{};
    errdefer pipeline.gpa.destroy(codec);
    _ = try pipeline.addLast("frames", .initOwned(codec));

    const counter = try pipeline.gpa.create(CountingHandler);
    counter.* = .{};
    errdefer pipeline.gpa.destroy(counter);
    _ = try pipeline.addLast("counter", .initOwned(counter));

    const echo = try pipeline.gpa.create(EchoHandler);
    echo.* = .{};
    errdefer pipeline.gpa.destroy(echo);
    _ = try pipeline.addLast("echo", .initOwned(echo));
}

/// Assembles the whole thing and shuts it down again, proving the API in the
/// README is the API that exists.
pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) std.process.exit(1);
    const gpa = debug_allocator.allocator();

    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const server = try zinet.Server.listen(.{
        .gpa = gpa,
        .io = threaded.io(),
        // Port 0 keeps this runnable in a test environment.
        .address = .{ .ip4 = .loopback(0) },
        .worker_count = 1,
        .child = .{ .initializer = .initFunction(buildPipeline) },
    });
    defer server.deinit();

    try server.serve();
    // Announced because a benchmark run against a Debug build of this example once produced a
    // handshake cost four times the real one, and nothing in its output said which build it was.
    std.log.info("build: {t}", .{@import("builtin").mode});
    std.log.info("readme example listening on port {d}", .{server.port()});
    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(1) });
}
