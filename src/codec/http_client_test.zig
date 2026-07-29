//! End-to-end check of the HTTP client codec against Zinet's own server.
//!
//! Kept out of `http.zig` on purpose. Importing `bootstrap` from a codec file
//! drags the whole socket layer, and its integration tests, into everything that
//! imports the codec — including the fuzz module, which is deliberately built
//! without them so it stays fast and free of real I/O.

const std = @import("std");
const backend = @import("backend");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const bootstrap = @import("../bootstrap.zig");
const event_loop = @import("../event_loop.zig");
const http = @import("http.zig");
const pipeline_mod = @import("../pipeline.zig");

const CodecError = pipeline_mod.Error;
const Header = http.Header;
const HandlerContext = pipeline_mod.HandlerContext;
const IncomingResponse = http.IncomingResponse;
const Message = pipeline_mod.Message;
const MethodTracker = http.MethodTracker;
const OutgoingRequest = http.OutgoingRequest;
const Pipeline = pipeline_mod.Pipeline;
const Request = http.Request;
const Response = http.Response;
const addClientCodec = http.addClientCodec;
const addServerCodec = http.addServerCodec;
const testing = std.testing;

test "the client codec talks to Zinet's own server over a real socket" {
    // Both sides of the implementation checked against each other end to end,
    // over a real connection, including keep-alive reuse. Unit tests feed the
    // decoder bytes the test itself wrote; this feeds it bytes the encoder on
    // the other side produced.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    // -- Server: echoes the request body back with a header of its own.
    const Echo = struct {
        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) CodecError!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const request = owned.get(Request) orelse return;

            var headers = [_]Header{.{ .name = "X-Served-By", .value = "zinet" }};
            const response: Response = .{
                .status = .ok,
                .headers = &headers,
                .body = request.body,
                .keep_alive = request.keep_alive,
            };
            return ctx.writeAndFlush(
                try Message.initAny(ctx.gpa(), Response, response),
            );
        }
    };
    const buildServer = struct {
        fn build(pipeline: *Pipeline) anyerror!void {
            try addServerCodec(pipeline, .{}, .{});
            const handler = try pipeline.gpa.create(Echo);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("echo", .initOwned(handler));
        }
    }.build;

    const server = try bootstrap.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .child = .{ .initializer = .initFunction(buildServer) },
    });
    defer server.deinit();
    try server.serve();

    // -- Client: sends two requests from `onActive` and reports what came back.
    const Client = struct {
        var replies: Io.Queue(Reply) = undefined;
        var storage: [4]Reply = undefined;
        /// Shared by the encoder and decoder on this connection; see
        /// `MethodTracker`. Static because the test's pipeline builder is a
        /// plain function with nowhere to put per-connection state.
        var tracker: MethodTracker = .{};

        const Reply = struct {
            status: u16,
            body: [32]u8,
            body_len: usize,
            served_by: [16]u8,
            served_by_len: usize,
        };

        pub fn onActive(_: *@This(), ctx: *HandlerContext) CodecError!void {
            // Sending from the connection's own task, which is the rule
            // `addClientCodec` documents.
            try ctx.write(try Message.initAny(ctx.gpa(), OutgoingRequest, .{
                .method = .post,
                .target = "/first",
                .host = "localhost",
                .body = "alpha",
            }));
            try ctx.write(try Message.initAny(ctx.gpa(), OutgoingRequest, .{
                .method = .post,
                .target = "/second",
                .host = "localhost",
                .body = "beta",
            }));
            try ctx.flush();
            ctx.fireActive();
        }

        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) CodecError!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const response = owned.get(IncomingResponse) orelse return;

            var reply: Reply = .{
                .status = response.status.code(),
                .body = @splat(0),
                .body_len = @min(response.body.len, 32),
                .served_by = @splat(0),
                .served_by_len = 0,
            };
            @memcpy(reply.body[0..reply.body_len], response.body[0..reply.body_len]);
            if (response.headers.get("x-served-by")) |value| {
                reply.served_by_len = @min(value.len, 16);
                @memcpy(reply.served_by[0..reply.served_by_len], value[0..reply.served_by_len]);
            }
            try replies.putOne(ctx.io(), reply);
        }
    };
    Client.replies = .init(&Client.storage);
    Client.tracker = .{};

    const buildClient = struct {
        fn build(pipeline: *Pipeline) anyerror!void {
            try addClientCodec(pipeline, &Client.tracker, .{});
            const handler = try pipeline.gpa.create(Client);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("client", .initOwned(handler));
        }
    }.build;

    var loops = try event_loop.EventLoopGroup.init(gpa, io, .{ .loop_count = 1 });
    defer loops.deinit();

    const channel = try bootstrap.connect(.{
        .gpa = gpa,
        .io = io,
        .address = server.boundAddress(),
        .loops = &loops,
        .config = .{ .initializer = .initFunction(buildClient) },
    });
    defer channel.release();

    const first = try Client.replies.getOne(io);
    try testing.expectEqual(@as(u16, 200), first.status);
    try testing.expectEqualStrings("alpha", first.body[0..first.body_len]);
    try testing.expectEqualStrings("zinet", first.served_by[0..first.served_by_len]);

    // The second response proves the connection was reused rather than the
    // decoder mistaking one response's tail for the next one's head.
    const second = try Client.replies.getOne(io);
    try testing.expectEqual(@as(u16, 200), second.status);
    try testing.expectEqualStrings("beta", second.body[0..second.body_len]);

    channel.requestClose();
}
