//! An HTTP/3 server: `zig build run-http3-server -- <port> <cert.pem> <key.pem>`
//!
//! One UDP socket serving many QUIC connections, each request stream getting its
//! own pipeline. The certificate must be ECDSA P-256 or Ed25519: the standard
//! library can verify RSA signatures but not produce them, and a TLS 1.3 server
//! signs a `CertificateVerify` on every handshake.
//!
//! Check it against a client that shares none of this code:
//!
//!     python3 -m venv venv && venv/bin/pip install aioquic
//!     venv/bin/python -c "..."   # see .github/workflows/ci.yml

const std = @import("std");
const zinet = @import("zinet");
const backend = @import("backend");
const Io = std.Io;

const http3 = zinet.http3;
const tls13 = zinet.tls13;
const Message = zinet.Message;
const Pipeline = zinet.Pipeline;
const HandlerContext = zinet.HandlerContext;

const log = std.log.scoped(.example);

var shutdown_requested: std.atomic.Value(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
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

/// One request's pipeline. HTTP/3 answers with a field section and DATA rather
/// than an `http.Response`, because a stream is not a connection.
const Responder = struct {
    pub fn onRead(_: *Responder, ctx: *HandlerContext, msg: Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const headers = owned.get(http3.Headers) orelse return;
        // Trailers need no answer; the request already got one.
        if (headers.trailers) return;

        const path = headers.get(":path") orelse "/";
        log.info("h3 request for {s}", .{path});

        const body = "hello from zinet over HTTP/3\n";
        var length_text: [20]u8 = undefined;
        var fields = [_]http3.qpack.FieldLine{
            .{ .name = ":status", .value = "200" },
            .{ .name = "content-type", .value = "text/plain; charset=utf-8" },
            .{ .name = "content-length", .value = try std.fmt.bufPrint(
                &length_text,
                "{d}",
                .{body.len},
            ) },
        };
        try ctx.write(try Message.initAny(ctx.gpa(), http3.OutgoingHeaders, .{ .fields = &fields }));
        try ctx.write(try Message.initBytes(ctx.gpa(), body));
        try ctx.flush();
        // Ends the stream, not the connection: the connection is shared with
        // every other request in flight.
        try ctx.close();
    }
};

const Builder = struct {
    pub fn initPipeline(_: *Builder, pipeline: *Pipeline) anyerror!void {
        const responder = try pipeline.gpa.create(Responder);
        responder.* = .{};
        errdefer pipeline.gpa.destroy(responder);
        _ = try pipeline.addLast("respond", .initOwned(responder));
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) std.process.exit(1);
    const gpa = debug_allocator.allocator();

    var runtime = try backend.Runtime.init(gpa);
    defer runtime.deinit();
    const io = runtime.io();

    var iterator = try std.process.Args.Iterator.initAllocator(init.args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();
    // Copied: the iterator's strings do not outlive it, and the identity below
    // is built after it is gone.
    const port_text = try gpa.dupe(u8, iterator.next() orelse "4433");
    defer gpa.free(port_text);
    const cert_path = try gpa.dupe(u8, iterator.next() orelse "cert.pem");
    defer gpa.free(cert_path);
    const key_path = try gpa.dupe(u8, iterator.next() orelse "key.pem");
    defer gpa.free(key_path);
    const port = try std.fmt.parseInt(u16, port_text, 10);

    const cert_pem = try Io.Dir.cwd().readFileAlloc(io, cert_path, gpa, .limited(1 << 20));
    defer gpa.free(cert_pem);
    const key_pem = try Io.Dir.cwd().readFileAlloc(io, key_path, gpa, .limited(1 << 20));
    defer gpa.free(key_pem);

    var identity = tls13.identity.Identity.fromPem(gpa, cert_pem, key_pem) catch |err| {
        if (err == error.UnsupportedKeyType) {
            log.err("that key is RSA; std can verify RSA but not sign with it", .{});
            log.err("generate an ECDSA one: openssl req -x509 -newkey ec " ++
                "-pkeyopt ec_paramgen_curve:P-256 -nodes ...", .{});
        }
        return err;
    };
    defer identity.deinit(gpa);

    // The token key signs address validation tokens. Injected, because every
    // server in a fleet has to accept every other one's tokens.
    var token_bytes: [32]u8 = undefined;
    try io.randomSecure(&token_bytes);

    var builder: Builder = .{};
    var server = try http3.server.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .unspecified(port) },
        .identity = &identity,
        .streams = .init(&builder),
        .token_key = .init(token_bytes),
    });
    defer server.deinit();

    installSignalHandlers();
    log.info("listening on https://127.0.0.1:{d} (HTTP/3 over QUIC)", .{server.port()});

    while (!shutdown_requested.load(.acquire)) {
        io.sleep(.fromMilliseconds(100), .awake) catch break;
    }
    log.info("shutting down after {d} connection(s)", .{server.acceptedCount()});
}
