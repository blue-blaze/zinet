//! An HTTPS client on the *self-written* TLS 1.3 engine — the one that can
//! send ALPN, which `std.crypto.tls.Client` cannot.
//!
//! ```
//! zig build run-tls13-client -- 127.0.0.1 8443 localhost / http/1.1,h2
//! ```
//!
//! Against OpenSSL:
//!
//! ```
//! openssl s_server -accept 8443 -cert cert.pem -key key.pem -alpn h2,http/1.1 -www
//! ```
//!
//! The pipeline is the same pipeline as every other example; what changed is
//! only the session underneath it. The negotiated ALPN is printed, because the
//! ability to negotiate one is the entire reason this client exists — it is
//! what makes `h2` over TLS announceable (RFC 9113 §3.1).

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
    const alpn_text = try gpa.dupe(u8, iterator.next() orelse "http/1.1");
    defer gpa.free(alpn_text);

    const port = try std.fmt.parseInt(u16, port_text, 10);
    const address = Io.net.IpAddress.parse(ip_text, port) catch {
        std.debug.print("cannot parse '{s}' as an IP address\n", .{ip_text});
        return error.InvalidAddress;
    };

    // Comma-separated ALPN list, most preferred first; "none" offers nothing.
    var alpn_buf: [8][]const u8 = undefined;
    var alpn_count: usize = 0;
    if (!std.mem.eql(u8, alpn_text, "none")) {
        var it = std.mem.splitScalar(u8, alpn_text, ',');
        while (it.next()) |protocol| {
            if (protocol.len == 0) continue;
            if (alpn_count == alpn_buf.len) break;
            alpn_buf[alpn_count] = protocol;
            alpn_count += 1;
        }
    }

    outcomes = .init(&outcome_storage);

    var client = zinet.tls13.client.Client.connect(.{
        .gpa = gpa,
        .io = io,
        .address = address,
        .host = host,
        .alpn = alpn_buf[0..alpn_count],
        // The self-signed test certificate is the expected peer here; chain
        // verification against a bundle is exercised by verify.zig's tests
        // over RFC 8448's genuine signature.
        .verification = null,
        .initializer = .initFunction(buildPipeline),
    }) catch |err| {
        std.debug.print("TLS handshake failed: {s}\n", .{@errorName(err)});
        return err;
    };
    const negotiated = client.negotiatedAlpn();
    std.debug.print("connected: TLS 1.3, alpn={s}\n", .{
        if (negotiated.len > 0) negotiated else "(none)",
    });

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

    client.shutdown();
}
