//! An HTTPS client: TLS to a server, one request through the HTTP codec, print
//! the response.
//!
//! ```
//! zig build run-https-client -- 127.0.0.1 8443 localhost /        # insecure
//! zig build run-https-client -- 93.184.216.34 443 example.com / verify
//! ```
//!
//! The point of the example is that the pipeline is the *same* pipeline: the
//! HTTP client codec does not know it is talking over TLS, because the session
//! sits under the pipeline rather than in it. See `src/tls.zig` for why that is
//! forced rather than chosen.
//!
//! The address is passed separately from the host name because `std.Io` has no
//! name resolver — the host name is what gets verified against the certificate.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Io = std.Io;
const http = zinet.http;

const Outcome = union(enum) {
    response: struct { status: u16, len: usize, body: [2048]u8 },
    failed: [64]u8,
};

var outcomes: Io.Queue(Outcome) = undefined;
var outcome_storage: [2]Outcome = undefined;
var tracker: zinet.HttpMethodTracker = .{};

/// Collects the response and hands it to `main`.
const Collector = struct {
    pub fn onRead(_: *Collector, ctx: *zinet.HandlerContext, msg: zinet.Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());

        if (owned.get(http.IncomingResponse)) |response| {
            var outcome: Outcome = .{ .response = .{
                .status = @backingInt(response.status),
                .len = 0,
                .body = undefined,
            } };
            const body = response.body;
            const len = @min(body.len, outcome.response.body.len);
            @memcpy(outcome.response.body[0..len], body[0..len]);
            outcome.response.len = len;
            outcomes.putOne(ctx.io(), outcome) catch {};
        }
    }

    pub fn onError(_: *Collector, ctx: *zinet.HandlerContext, err: anyerror) void {
        var outcome: Outcome = .{ .failed = @splat(0) };
        const name = @errorName(err);
        const len = @min(name.len, outcome.failed.len - 1);
        @memcpy(outcome.failed[0..len], name[0..len]);
        outcomes.putOne(ctx.io(), outcome) catch {};
        ctx.close() catch {};
    }
};

fn buildPipeline(pipeline: *zinet.Pipeline) anyerror!void {
    try http.addClientCodec(pipeline, &tracker, .{});

    const collector = try pipeline.gpa.create(Collector);
    collector.* = .{};
    errdefer pipeline.gpa.destroy(collector);
    _ = try pipeline.addLast("collect", .initOwned(collector));
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
    const ip_text = try gpa.dupe(u8, iterator.next() orelse "127.0.0.1");
    defer gpa.free(ip_text);
    const port_text = try gpa.dupe(u8, iterator.next() orelse "8443");
    defer gpa.free(port_text);
    const host = try gpa.dupe(u8, iterator.next() orelse "localhost");
    defer gpa.free(host);
    const target = try gpa.dupe(u8, iterator.next() orelse "/");
    defer gpa.free(target);
    const mode = try gpa.dupe(u8, iterator.next() orelse "insecure");
    defer gpa.free(mode);

    const port = try std.fmt.parseInt(u16, port_text, 10);
    const address = Io.net.IpAddress.parse(ip_text, port) catch {
        std.debug.print("cannot parse '{s}' as an IP address\n", .{ip_text});
        return error.InvalidAddress;
    };

    // Loaded once and shared, because reading the system trust store is not
    // something to do per connection.
    var ca: ?zinet.CaBundle = null;
    defer if (ca) |*bundle| bundle.deinit(gpa);
    const verification: zinet.tls.Verification = if (std.mem.eql(u8, mode, "verify")) blk: {
        ca = try zinet.CaBundle.loadSystem(gpa, io);
        break :blk .{ .bundle = &ca.? };
    } else if (std.mem.eql(u8, mode, "self-signed"))
        .self_signed
    else
        .insecure;

    outcomes = .init(&outcome_storage);

    var client = zinet.TlsClient.connect(.{
        .gpa = gpa,
        .io = io,
        .address = address,
        .host = host,
        .verification = verification,
        .initializer = .initFunction(buildPipeline),
    }) catch |err| {
        std.debug.print("TLS handshake failed: {s}\n", .{@errorName(err)});
        return err;
    };
    // Asserted rather than only printed. `protocolVersion` documents itself as always
    // 1.3, because the standard library has no 1.2 client — so anything else means
    // that claim has stopped being true, and a claim nothing checks is the kind this
    // repository has already had to correct once.
    const version = client.connection.protocolVersion();
    std.debug.print("connected: TLS {s}\n", .{@tagName(version)});
    if (version != .tls_1_3) {
        std.debug.print("expected TLS 1.3, got {s}\n", .{@tagName(version)});
        return error.UnexpectedTlsVersion;
    }

    // The request goes through the pipeline, so the HTTP encoder serializes it —
    // the TLS session only ever sees the bytes it produced.
    var headers = [_]http.Header{
        .{ .name = "Host", .value = host },
        .{ .name = "Connection", .value = "close" },
        .{ .name = "Accept", .value = "*/*" },
    };
    try client.submitWrite(try zinet.Message.initAny(gpa, http.OutgoingRequest, .{
        .method = .get,
        .target = target,
        .headers = &headers,
    }));

    const outcome = outcomes.getOne(io) catch {
        client.deinit();
        return error.NoResponse;
    };
    switch (outcome) {
        .response => |response| std.debug.print(
            "status {d}, {d} bytes of body\n{s}\n",
            .{ response.status, response.len, response.body[0..response.len] },
        ),
        .failed => |name| {
            std.debug.print("failed: {s}\n", .{std.mem.sliceTo(&name, 0)});
            client.deinit();
            return error.RequestFailed;
        },
    }

    // Graceful: the peer sees `close_notify` rather than a socket that vanished.
    client.shutdown();
}
