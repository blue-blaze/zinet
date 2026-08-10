//! An HTTPS server on the self-written TLS 1.3 engine.
//!
//! ```
//! zig build run-tls13-server -- 8443 cert.pem key.pem h2,http/1.1
//! curl -k --noproxy '*' https://localhost:8443/
//! curl -k --noproxy '*' --http2 https://localhost:8443/     # via ALPN
//! openssl s_client -connect localhost:8443 -alpn h2
//! ```
//!
//! Generate a certificate the standard library can sign with — ECDSA P-256 or
//! Ed25519, because `std.crypto.Certificate.rsa` can verify but not sign:
//!
//! ```
//! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
//!     -keyout key.pem -out cert.pem -days 30 -nodes -subj "/CN=localhost"
//! ```
//!
//! When ALPN settles on "h2", the pipeline gets HTTP/2's server codec and the
//! multiplexer; otherwise HTTP/1.1. That switch is the whole point: it is the
//! negotiation RFC 9113 §3.1 requires and the one `std.crypto.tls.Client` could
//! never perform.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Io = std.Io;
const http = zinet.http;
const http2 = zinet.http2;

/// Answers any request with a short body.
const Responder = struct {
    pub fn onRead(_: *Responder, ctx: *zinet.HandlerContext, msg: zinet.Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());

        if (owned.get(http.Request)) |request| {
            var headers = [_]http.Header{
                .{ .name = "Content-Type", .value = "text/plain" },
            };
            _ = request;
            const body = "hello from zinet over TLS\n";
            try ctx.writeAndFlush(try zinet.Message.initAny(ctx.gpa(), http.Response, .{
                .status = .ok,
                .headers = &headers,
                .body = body,
            }));
        }
    }

    pub fn onError(_: *Responder, ctx: *zinet.HandlerContext, err: anyerror) void {
        std.debug.print("connection failed: {s}\n", .{@errorName(err)});
        ctx.close() catch {};
    }
};

fn buildHttp1(pipeline: *zinet.Pipeline) anyerror!void {
    try http.addServerCodec(pipeline, .{}, .{});
    const responder = try pipeline.gpa.create(Responder);
    responder.* = .{};
    errdefer pipeline.gpa.destroy(responder);
    _ = try pipeline.addLast("respond", .initOwned(responder));
}

fn buildHttp2(pipeline: *zinet.Pipeline) anyerror!void {
    // One `Pipeline` per stream, built by the codec's multiplexer.
    _ = try http2.addServerCodec(pipeline, .{
        .streams = .initFunction(buildStream),
    });
}

/// One request's pipeline. HTTP/2 answers with headers and DATA rather than an
/// `http.Response`, because a stream is not a connection.
const Http2Responder = struct {
    pub fn onRead(_: *Http2Responder, ctx: *zinet.HandlerContext, msg: zinet.Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        if (owned.get(http2.Headers) == null) return;

        const body = "hello from zinet over h2\n";
        var length_text: [20]u8 = undefined;
        var fields = [_]http2.hpack.Field{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain" },
            .{ .name = "content-length", .value = try std.fmt.bufPrint(
                &length_text,
                "{d}",
                .{body.len},
            ) },
        };
        try ctx.write(try zinet.Message.initAny(ctx.gpa(), http2.OutgoingHeaders, .{
            .fields = &fields,
        }));
        try ctx.write(try zinet.Message.initBytes(ctx.gpa(), body));
        try ctx.flush();
        // Ends the stream, not the connection.
        try ctx.close();
    }
};

fn buildStream(pipeline: *zinet.Pipeline) anyerror!void {
    const responder = try pipeline.gpa.create(Http2Responder);
    responder.* = .{};
    errdefer pipeline.gpa.destroy(responder);
    _ = try pipeline.addLast("respond", .initOwned(responder));
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
    const port_text = try gpa.dupe(u8, iterator.next() orelse "8443");
    defer gpa.free(port_text);
    const cert_path = try gpa.dupe(u8, iterator.next() orelse "cert.pem");
    defer gpa.free(cert_path);
    const key_path = try gpa.dupe(u8, iterator.next() orelse "key.pem");
    defer gpa.free(key_path);
    const alpn_text = try gpa.dupe(u8, iterator.next() orelse "http/1.1");
    defer gpa.free(alpn_text);

    const port = try std.fmt.parseInt(u16, port_text, 10);

    const cert_pem = try readFile(gpa, io, cert_path);
    defer gpa.free(cert_pem);
    const key_pem = try readFile(gpa, io, key_path);
    defer gpa.free(key_pem);

    var identity = zinet.tls13.identity.Identity.fromPem(gpa, cert_pem, key_pem) catch |err| {
        if (err == error.UnsupportedKeyType) {
            std.debug.print(
                "that key is one std cannot sign with: use ECDSA P-256 or Ed25519\n",
                .{},
            );
        }
        return err;
    };
    defer identity.deinit(gpa);

    var alpn_buf: [8][]const u8 = undefined;
    var alpn_count: usize = 0;
    if (!std.mem.eql(u8, alpn_text, "none")) {
        var it = std.mem.splitScalar(u8, alpn_text, ',');
        while (it.next()) |protocol| {
            if (protocol.len == 0 or alpn_count == alpn_buf.len) continue;
            alpn_buf[alpn_count] = protocol;
            alpn_count += 1;
        }
    }

    // One initializer per protocol would need to be chosen per connection,
    // which needs the negotiated ALPN — available only after the handshake.
    // The example keeps it simple: whichever protocol is listed first decides
    // the pipeline, and h2 is announced only when it can be served.
    const prefer_h2 = alpn_count > 0 and std.mem.eql(u8, alpn_buf[0], "h2");

    var server = try zinet.tls13.server.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .unspecified(port) },
        .identity = &identity,
        .alpn = alpn_buf[0..alpn_count],
        .child = .{
            .initializer = if (prefer_h2)
                zinet.ChannelInitializer.initFunction(buildHttp2)
            else
                zinet.ChannelInitializer.initFunction(buildHttp1),
        },
    });
    defer server.deinit();
    try server.serve();

    // Announced because a benchmark run against a Debug build of this example once produced a
    // handshake cost four times the real one, and nothing in its output said which build it was.
    // Debug builds say so loudly: the mode was logged quietly once already and a
    // measurement was still taken against one and briefly believed.
    switch (@import("builtin").mode) {
        .Debug => std.debug.print("build: debug — unoptimized, not a performance measurement\n", .{}),
        else => std.debug.print("build: {t}\n", .{@import("builtin").mode}),
    }
    std.debug.print("listening on https://localhost:{d} (alpn: {s})\n", .{ port, alpn_text });

    // Runs until interrupted; the example is meant to be driven by curl.
    while (true) try io.sleep(.fromMilliseconds(200), .awake);
}

fn readFile(gpa: std.mem.Allocator, io: Io, path: []const u8) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1 << 20));
}
