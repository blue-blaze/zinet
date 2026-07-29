//! A WebSocket client: opens a connection, sends a message, prints the echo.
//!
//! ```
//! zig build run-ws-client -- 127.0.0.1 8090 /
//! ```
//!
//! Same shape as the HTTP client example. `ClientHandshaker` sends the upgrade
//! from `onActive` and rewrites the pipeline when the answer checks out; from
//! then on the connection speaks frames, and the handler below sends one as soon
//! as it sees `HandshakeComplete`.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Io = std.Io;

const Outcome = union(enum) {
    /// The handshake finished, so the pipeline now speaks WebSocket.
    ready,
    echo: struct { len: usize, bytes: [1024]u8 },
    failed: [64]u8,
};

var outcomes: Io.Queue(Outcome) = undefined;
var outcome_storage: [2]Outcome = undefined;
var tracker: zinet.HttpMethodTracker = .{};
var message: []const u8 = "hello from zinet";

/// Reports when the connection is ready, and what came back.
///
/// Nothing here decides what to send: `main` does, through
/// `Channel.submitWrite`. That is the shape a real client has — the application
/// knows what it wants, and the connection is somewhere else — and it is what
/// task hopping exists for. Before it, this handler had to own the request.
const Talker = struct {
    pub fn onEvent(_: *Talker, ctx: *zinet.HandlerContext, event: zinet.Event) !void {
        if (event.is(zinet.WebSocketHandshakeComplete)) {
            outcomes.putOne(ctx.io(), .ready) catch {};
        }
        ctx.fireEvent(event);
    }

    pub fn onRead(_: *Talker, ctx: *zinet.HandlerContext, msg: zinet.Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const frame = owned.get(zinet.WebSocketFrame) orelse return;
        if (frame.opcode != .text and frame.opcode != .binary) return;

        var outcome: Outcome = .{ .echo = .{
            .len = @min(frame.payload.len, 1024),
            .bytes = undefined,
        } };
        @memcpy(outcome.echo.bytes[0..outcome.echo.len], frame.payload[0..outcome.echo.len]);
        try outcomes.putOne(ctx.io(), outcome);
    }

    pub fn onError(_: *Talker, ctx: *zinet.HandlerContext, err: anyerror) void {
        var text: [64]u8 = @splat(0);
        const name = @errorName(err);
        @memcpy(text[0..@min(name.len, 64)], name[0..@min(name.len, 64)]);
        outcomes.putOne(ctx.io(), .{ .failed = text }) catch {};
        ctx.close() catch {};
    }
};

var handshake_options: zinet.WebSocketClientHandshaker.Options = .{};

fn buildPipeline(pipeline: *zinet.Pipeline) anyerror!void {
    try zinet.websocket.addClientUpgrade(pipeline, &tracker, handshake_options);

    const handler = try pipeline.gpa.create(Talker);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("talker", .initOwned(handler));
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
    // Duped because the handler holds them for the life of the connection.
    const host = try gpa.dupe(u8, iterator.next() orelse "127.0.0.1");
    defer gpa.free(host);
    const port_text = try gpa.dupe(u8, iterator.next() orelse "8090");
    defer gpa.free(port_text);
    const target = try gpa.dupe(u8, iterator.next() orelse "/");
    defer gpa.free(target);
    const port = try std.fmt.parseInt(u16, port_text, 10);

    const host_header = try std.fmt.allocPrint(gpa, "{s}:{d}", .{ host, port });
    defer gpa.free(host_header);

    handshake_options = .{
        .host = host_header,
        .target = target,
        .permessage_deflate = .{},
    };
    outcomes = .init(&outcome_storage);

    var loops = try zinet.EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer loops.deinit();

    const address = Io.net.IpAddress.parse(host, port) catch {
        std.debug.print("cannot parse '{s}' as an IP address\n", .{host});
        return error.InvalidAddress;
    };

    const channel = try zinet.connect(.{
        .gpa = gpa,
        .io = io,
        .address = address,
        .loops = &loops,
        .config = .{
            .initializer = .initFunction(buildPipeline),
            // Without this, `submitWrite` below would be refused. It is opt-in
            // because a server whose handlers send everything themselves should
            // not pay for a queue it never uses.
            .task_capacity = 4,
            .task_wake_interval = .fromMilliseconds(5),
        },
    });
    defer channel.release();

    // Wait for the upgrade, because a text frame written before it would be
    // encoded by an HTTP encoder that is about to be removed.
    switch (try outcomes.getOne(io)) {
        .ready => {},
        .failed => |text| {
            std.debug.print("failed: {s}\n", .{std.mem.sliceTo(&text, 0)});
            loops.shutdown();
            loops.drain();
            return;
        },
        .echo => unreachable,
    }

    // Sent from this task, and still framed and masked by the codec on the
    // connection's task.
    try channel.submitWrite(try zinet.Message.initAny(
        gpa,
        zinet.WebSocketOutboundFrame,
        .textFrame(message),
    ));

    switch (try outcomes.getOne(io)) {
        .echo => |echo| std.debug.print("echo: {s}\n", .{echo.bytes[0..echo.len]}),
        .failed => |text| std.debug.print("failed: {s}\n", .{std.mem.sliceTo(&text, 0)}),
        .ready => unreachable,
    }

    // Through the pipeline, so the codec sends a close frame first.
    // `requestClose` would drop the connection without one, which the peer
    // cannot tell apart from a network failure.
    channel.submitClose() catch channel.requestClose();

    // A submitted close is *queued*, so it has not happened yet. Cancelling the
    // loops here would abort the reader task before it ran the close through the
    // pipeline, and the peer would see a dropped connection rather than a closing
    // handshake — which is exactly the failure `submitClose` exists to avoid.
    // So wait for the connection to end on its own, with a bound in case the
    // peer never answers.
    const close_deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
    while (channel.isOpen()) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= close_deadline.nanoseconds) {
            std.debug.print("peer did not complete the closing handshake\n", .{});
            break;
        }
        io.sleep(.fromMilliseconds(2), .awake) catch break;
    }

    loops.shutdown();
    loops.drain();
}
