//! A UDP echo endpoint, showing the datagram side of the framework.
//!
//! ```
//! zig build run-udp-echo -- 9000
//! echo hello | nc -u localhost 9000
//! ```
//!
//! Note what is *not* here: no framing codec, because a datagram is already a
//! message, and no per-peer state, because one socket serves everybody. The
//! sender's address arrives with each datagram, which is what makes replying
//! possible without a connection.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Io = std.Io;

const default_port = 9000;

/// Echoes each datagram back, upper-cased so the round trip is visible.
const Echoer = struct {
    seen: u64 = 0,

    pub fn onRead(self: *Echoer, ctx: *zinet.HandlerContext, msg: zinet.Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const datagram = owned.get(zinet.Datagram) orelse return;

        self.seen += 1;
        const payload = datagram.bytes();
        std.debug.print("{f} sent {d} bytes\n", .{ datagram.address, payload.len });

        var reply = try zinet.Buffer.init(ctx.gpa(), .{ .capacity = payload.len });
        errdefer reply.deinit(ctx.gpa());
        const destination = try reply.reserve(ctx.gpa(), payload.len);
        for (payload, destination) |source, *slot| slot.* = std.ascii.toUpper(source);

        return ctx.write(try zinet.Message.initAny(
            ctx.gpa(),
            zinet.Datagram,
            .initBuffer(datagram.address, &reply),
        ));
    }

    pub fn onError(_: *Echoer, _: *zinet.HandlerContext, err: anyerror) void {
        // A truncated datagram lands here rather than being half delivered.
        std.debug.print("error: {s}\n", .{@errorName(err)});
    }
};

fn buildPipeline(pipeline: *zinet.Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(Echoer);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("echo", .initOwned(handler));
}

var shutdown_requested: std.atomic.Value(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
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
    const port = if (iterator.next()) |text|
        try std.fmt.parseInt(u16, text, 10)
    else
        default_port;

    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);

    var endpoint = try zinet.DatagramEndpoint.open(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .unspecified(port) },
        .initializer = .initFunction(buildPipeline),
        // Bounds how long shutdown takes, since a blocked receive is what the
        // reader would otherwise sit in.
    });
    defer endpoint.deinit();

    std.debug.print("listening on {d}\n", .{endpoint.port()});

    while (!shutdown_requested.load(.acquire)) {
        const duration: Io.Clock.Duration = .{
            .raw = .fromMilliseconds(50),
            .clock = .awake,
        };
        duration.sleep(io) catch break;
    }

    std.debug.print("shutting down\n", .{});
}
