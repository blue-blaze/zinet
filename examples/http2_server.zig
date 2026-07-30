//! A cleartext HTTP/2 server, spoken with prior knowledge.
//!
//! ```
//! zig build run-http2-server -- 8081
//! curl -v --http2-prior-knowledge http://localhost:8081/
//! curl -sS --http2-prior-knowledge http://localhost:8081/echo -d 'hello'
//! # several requests on one connection, which is the point of the protocol
//! curl -sS --http2-prior-knowledge http://localhost:8081/a http://localhost:8081/b
//! ```
//!
//! `--http2-prior-knowledge` is not a workaround. RFC 9113 §3 lists three ways to
//! reach HTTP/2: the `Upgrade:` dance, which §3.2 removed from the specification;
//! `h2` over TLS, identified by ALPN, which `std.crypto.tls.Client` cannot send; and
//! prior knowledge, which is this. It is what gRPC between services and a reverse
//! proxy talking to a backend both use.
//!
//! Routes:
//!
//! * `/`      — a plain text greeting
//! * `/echo`  — replies with the request body
//! * `/slow`  — a body in several `DATA` frames, so interleaving is visible
//! * anything else — 404
//!
//! Pipeline layout:
//!
//! ```
//! socket -> http2 codec -> (one child pipeline per stream) -> Responder
//! ```
//!
//! The parent pipeline carries bytes and connection-level events. Every request
//! lands in a pipeline of its own, built by `buildStream`, and all of them run on
//! the connection's single reader task — so `Responder` needs no synchronization
//! even though several requests are in flight at once.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const HandlerContext = zinet.HandlerContext;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;
const http2 = zinet.http2;
const Field = http2.hpack.Field;

const default_port = 8081;
const log = std.log.scoped(.http2_server);

var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// Answers one stream. A fresh instance per request, which is what makes the
/// per-stream state below safe to keep in a plain field.
const Responder = struct {
    body: std.ArrayList(u8) = .empty,
    path: []const u8 = "/",
    method: []const u8 = "GET",
    responded: bool = false,
    /// The reply still to go out, and how much of it has. Held rather than written
    /// in one call because HTTP/2 reports backpressure instead of applying it: a
    /// stream that has queued as much as its water mark allows says so, and the
    /// rest has to wait for `WritabilityChanged`.
    outgoing: []const u8 = "",
    sent: usize = 0,
    writable: bool = true,
    /// Owns `outgoing` when the body was built rather than borrowed.
    owned_body: ?[]u8 = null,

    pub const handler_name = "responder";

    pub fn deinit(self: *Responder, gpa: std.mem.Allocator) void {
        self.body.deinit(gpa);
        if (self.owned_body) |owned| gpa.free(owned);
        if (self.path.len > 0) gpa.free(self.path);
        if (self.method.len > 0) gpa.free(self.method);
    }

    pub fn onRead(
        self: *Responder,
        ctx: *HandlerContext,
        msg: Message,
    ) zinet.pipeline.Error!void {
        const gpa = ctx.gpa();
        var owned = msg;
        defer owned.deinit(gpa);

        if (owned.take(gpa, http2.Headers)) |taken| {
            var headers = taken;
            defer headers.deinit(gpa);
            // The header list lives in the message's own arena, so anything kept
            // past this callback has to be copied.
            self.path = try gpa.dupe(u8, headers.get(":path") orelse "/");
            self.method = try gpa.dupe(u8, headers.get(":method") orelse "GET");
            return;
        }

        if (owned.bytes()) |chunk| {
            try self.body.appendSlice(gpa, chunk);
            return;
        }
    }

    pub fn onInactive(_: *Responder, ctx: *HandlerContext) zinet.pipeline.Error!void {
        ctx.fireInactive();
    }

    pub fn onEvent(
        self: *Responder,
        ctx: *HandlerContext,
        event: zinet.Event,
    ) zinet.pipeline.Error!void {
        // The request is complete. The stream is still open the other way, which is
        // exactly why this is an event and not `onInactive`.
        if (event.is(http2.InboundComplete)) {
            try self.respond(ctx);
            return;
        }
        if (event.get(http2.WritabilityChanged)) |changed| {
            self.writable = changed.writable;
            if (changed.writable) try self.pumpBody(ctx);
            return;
        }
        if (event.get(http2.StreamReset)) |reset| {
            // Distinguishable from an ordinary end, which is the reason the event
            // exists: there is no point writing a response nobody will read.
            log.info("{s} {s}: reset by peer ({s})", .{
                self.method, self.path, reset.code.name(),
            });
            self.responded = true;
        }
        ctx.fireEvent(event);
    }

    fn respond(self: *Responder, ctx: *HandlerContext) zinet.pipeline.Error!void {
        if (self.responded) return;
        self.responded = true;
        const gpa = ctx.gpa();

        if (std.mem.eql(u8, self.path, "/echo")) {
            // The echo body can be any size the peer chose, so it is queued and
            // metered rather than handed over in one call.
            self.owned_body = try gpa.dupe(u8, self.body.items);
            try self.sendHeaders(ctx, "200", self.owned_body.?.len);
            self.outgoing = self.owned_body.?;
            try self.pumpBody(ctx);
            return;
        }
        if (std.mem.eql(u8, self.path, "/slow")) {
            // Several DATA frames, so a client asking for two things at once can see
            // them interleave rather than queue. No content-length, because the
            // length is not known until the last piece.
            var fields = [_]Field{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
            };
            try ctx.write(try Message.initAny(gpa, http2.OutgoingHeaders, .{ .fields = &fields }));
            var built: std.ArrayList(u8) = .empty;
            errdefer built.deinit(gpa);
            for (0..5) |index| {
                var line: [32]u8 = undefined;
                try built.appendSlice(gpa, try std.fmt.bufPrint(&line, "piece {d}\n", .{index}));
            }
            self.owned_body = try built.toOwnedSlice(gpa);
            self.outgoing = self.owned_body.?;
            try self.pumpBody(ctx);
            return;
        }
        if (std.mem.eql(u8, self.path, "/")) {
            try self.sendHeaders(ctx, "200", greeting.len);
            self.outgoing = greeting;
            try self.pumpBody(ctx);
            return;
        }
        try self.sendHeaders(ctx, "404", not_found.len);
        self.outgoing = not_found;
        try self.pumpBody(ctx);
    }

    const greeting = "hello over HTTP/2\n";
    const not_found = "not found\n";

    /// Writes as much of the reply as the stream will take, then stops. A
    /// `WritabilityChanged` event brings it back for the rest.
    ///
    /// This is the shape HTTP/2 forces and the rest of the framework avoids: a
    /// blocking write is safe when one exchange owns the connection and deadlocks
    /// when many share a credit pool, so here the handler is *told* to stop.
    fn pumpBody(self: *Responder, ctx: *HandlerContext) zinet.pipeline.Error!void {
        const gpa = ctx.gpa();
        const chunk = 16 * 1024;
        while (self.sent < self.outgoing.len) {
            if (!self.writable) {
                // Nothing is lost by stopping: the queue drains, the event fires,
                // and this resumes where it left off.
                try ctx.flush();
                return;
            }
            const take = @min(chunk, self.outgoing.len - self.sent);
            try ctx.write(try Message.initBytes(gpa, self.outgoing[self.sent..][0..take]));
            self.sent += take;
        }
        try ctx.flush();
        // Ends the stream, not the connection: the connection is shared with every
        // other request in flight.
        try ctx.close();
    }

    fn sendHeaders(
        self: *Responder,
        ctx: *HandlerContext,
        status: []const u8,
        length: usize,
    ) zinet.pipeline.Error!void {
        _ = self;
        var length_text: [20]u8 = undefined;
        var fields = [_]Field{
            .{ .name = ":status", .value = status },
            .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
            .{ .name = "content-length", .value = try std.fmt.bufPrint(
                &length_text,
                "{d}",
                .{length},
            ) },
        };
        // Outgoing headers borrow: the encoder serializes before `write` returns, so
        // a stack array is enough. Same rule as `http.Response`.
        try ctx.write(try Message.initAny(ctx.gpa(), http2.OutgoingHeaders, .{
            .fields = &fields,
        }));
    }
};

/// Builds one request's pipeline. Called by the multiplexer for every new stream.
fn buildStream(pipeline: *Pipeline) anyerror!void {
    const responder = try pipeline.gpa.create(Responder);
    responder.* = .{};
    errdefer pipeline.gpa.destroy(responder);
    _ = try pipeline.addLast(Responder.handler_name, .initOwned(responder));
}

fn buildConnection(pipeline: *Pipeline) anyerror!void {
    _ = try http2.addServerCodec(pipeline, .{
        .streams = .initFunction(buildStream),
    });
}

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) std.process.exit(1);
    const gpa = debug_allocator.allocator();

    var runtime = try backend.Runtime.init(gpa);
    defer runtime.deinit();
    const io = runtime.io();

    const port = try parsePort(gpa, init.args);

    const server = try zinet.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .unspecified(port) },
        .child = .{ .initializer = .initFunction(buildConnection) },
    });
    defer server.deinit();

    installSignalHandlers();
    try server.serve();
    log.info("http/2 server listening on port {d}", .{server.port()});
    log.info(
        "try: curl -v --http2-prior-knowledge http://localhost:{d}/",
        .{server.port()},
    );

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
