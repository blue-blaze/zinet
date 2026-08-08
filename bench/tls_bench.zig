//! What a TLS 1.3 handshake costs, measured in this repository rather than by pointing an
//! external tool at an example binary.
//!
//! It exists because doing it the other way produced a wrong answer that stood for a while. The
//! handshake rate was measured with `openssl s_time` against `zig-out/bin/tls13_server`, and
//! `zig build examples` builds with `-Doptimize` — which defaults to **Debug**. So an
//! unoptimized server was compared against OpenSSL's optimized one, and the 4.3 ms per handshake
//! that comparison produced was mostly Debug-mode field arithmetic. TLS.md drew three
//! conclusions from it, two of which were wrong, and pointed at a 2.8 ms remainder to go and
//! find. There is no such remainder: in ReleaseFast the same server does a full handshake in
//! about 0.8 ms, slightly faster than `openssl s_server` on the same loopback, of which roughly
//! 175 us is this code's own computation and three quarters of that is one signature.
//!
//! A benchmark registered in `build.zig` cannot make that mistake, because benchmarks there are
//! built `.fast` whatever `-Doptimize` says. That is the reason this file is a benchmark and not
//! a hand-run command, and it is the same reason the mutation catalogue became a build step.
//!
//! ```
//! zig build bench-tls_bench                # defaults
//! zig build bench-tls_bench -- 2000        # handshakes
//! ```
//!
//! Reported, all per handshake:
//!
//! * **server CPU** and **client CPU** separately, which is the split that matters: a server
//!   operator pays the first and the peer pays the second. They are timed apart rather than
//!   summed because in-process both run on this thread.
//! * the **signature's** share of the server's cost, measured directly through
//!   `PrivateKey.sign`, for both schemes a server here can present, so "how much would a cheaper
//!   signature scheme save" is an answer rather than an inference.
//! A leak fails the run, as in the other benchmarks.
//!
//! Deliberately absent: sockets. This measures the engine — key schedule, record layer,
//! certificate parsing, signing and verification — because everything a socket adds is already
//! measured by `openssl s_time` against a real server, and the gap between the two is what
//! attributes the cost. On this machine the engine is most of it.

const std = @import("std");
const zinet = @import("zinet");

const Io = std.Io;
const session = zinet.tls13.session;
const identity_mod = zinet.tls13.identity;

const log = std.log.scoped(.bench);

const Config = struct {
    handshakes: usize = 2000,
};

fn parseConfig(args: *std.process.Args.Iterator) Config {
    var config: Config = .{};
    _ = args.skip();
    if (args.next()) |raw| config.handshakes = std.fmt.parseInt(usize, raw, 10) catch config.handshakes;
    return config;
}

pub fn main(init: std.process.Init.Minimal) !void {
    // Same shape as the other benchmarks: a leak fails the run rather than being reported as a
    // number nobody reads.
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) {
        log.err("benchmark leaked memory", .{});
        std.process.exit(1);
    };
    const gpa = debug_allocator.allocator();

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var iterator = try std.process.Args.Iterator.initAllocator(init.args, gpa);
    defer iterator.deinit();
    const config = parseConfig(&iterator);

    // A real certificate with a real key, from the test corpus: a client has to parse the chain
    // and check CertificateVerify against it, so a placeholder would measure a different thing.
    const identity = identity_mod.testRealIdentity();

    var server_nanos: u64 = 0;
    var client_nanos: u64 = 0;
    var completed: usize = 0;

    var seed: u64 = 0;
    while (completed < config.handshakes) : (completed += 1) {
        seed +%= 1;
        var seed_bytes: [64]u8 = @splat(0);
        std.mem.writeInt(u64, seed_bytes[0..8], seed, .little);
        // Distinct per side: the same seed on both would make the two key shares equal, which
        // is not a handshake anybody performs.
        var client_seed = seed_bytes;
        client_seed[63] = 1;

        var client: session.ClientSession = try .init(.{
            .host = identity_mod.test_real_host,
            .verification = null,
        }, client_seed);
        defer client.deinit(gpa);

        var server: session.ServerSession = try .init(.{ .identity = &identity }, seed_bytes);
        defer server.deinit(gpa);

        try client.start(gpa);
        try pump(gpa, io, &client, &server, &client_nanos, &server_nanos);

        if (!client.isEstablished() or !server.isEstablished()) return error.HandshakeFailed;
    }

    const signature_nanos = try measureSignature(io, &identity.key);
    // The other scheme this server can present, measured even though the handshakes above ran on
    // ECDSA. It is what makes "would a cheaper signature help" answerable here, and it
    // cross-checks the socket-level measurement: `openssl s_time` against a real server sees
    // Ed25519 beat ECDSA by about 80 us per handshake, which should be this difference.
    const ed25519_seed: [32]u8 = @splat(7);
    const ed25519: identity_mod.PrivateKey = .{
        .ed25519 = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(ed25519_seed),
    };
    const ed25519_nanos = try measureSignature(io, &ed25519);

    report(config, server_nanos, client_nanos, signature_nanos, ed25519_nanos);
}

/// Drives the handshake, charging each side's `receive` to that side.
///
/// The copy out of `output()` is charged to neither: it is this harness moving bytes a socket
/// would have moved, and attributing it to either side would overstate that side.
fn pump(
    gpa: std.mem.Allocator,
    io: Io,
    client: *session.ClientSession,
    server: *session.ServerSession,
    client_nanos: *u64,
    server_nanos: *u64,
) !void {
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        var moved = false;
        if (client.output().len > 0) {
            const bytes = try gpa.dupe(u8, client.output());
            defer gpa.free(bytes);
            client.consumeOutput(bytes.len);
            const started = Io.Timestamp.now(io, .awake);
            try server.receive(gpa, bytes);
            server_nanos.* += elapsed(started, Io.Timestamp.now(io, .awake));
            moved = true;
        }
        if (server.output().len > 0) {
            const bytes = try gpa.dupe(u8, server.output());
            defer gpa.free(bytes);
            server.consumeOutput(bytes.len);
            const started = Io.Timestamp.now(io, .awake);
            try client.receive(gpa, bytes);
            client_nanos.* += elapsed(started, Io.Timestamp.now(io, .awake));
            moved = true;
        }
        if (!moved) return;
    }
    return error.PumpDidNotSettle;
}

/// One CertificateVerify signature, averaged over enough repetitions to be visible.
///
/// The content length is what §4.4.3 produces: 64 spaces, the context string, a zero byte and a
/// 32-byte transcript hash. The exact bytes do not matter to the cost; the length does not
/// either for ECDSA, which hashes first, but using the real shape keeps the number honest.
fn measureSignature(io: Io, key: *const identity_mod.PrivateKey) !u64 {
    const repetitions = 200;
    var content: [130]u8 = @splat(0x20);
    var buffer: [identity_mod.PrivateKey.max_signature_len]u8 = undefined;

    const started = Io.Timestamp.now(io, .awake);
    var index: usize = 0;
    while (index < repetitions) : (index += 1) {
        content[129] = @truncate(index);
        _ = try key.sign(&content, &buffer);
    }
    return elapsed(started, Io.Timestamp.now(io, .awake)) / repetitions;
}

fn elapsed(from: Io.Timestamp, to: Io.Timestamp) u64 {
    if (to.nanoseconds <= from.nanoseconds) return 0;
    return @intCast(to.nanoseconds - from.nanoseconds);
}

fn report(
    config: Config,
    server_nanos: u64,
    client_nanos: u64,
    signature_nanos: u64,
    ed25519_nanos: u64,
) void {
    const count = config.handshakes;
    const server_each = server_nanos / count;
    const client_each = client_nanos / count;

    std.debug.print(
        \\tls handshake: {d} handshakes, sans-io
        \\  server CPU        {d:.0} us each  ({d:.0} handshakes/s if nothing else ran)
        \\  client CPU        {d:.0} us each
        \\  ecdsa p256 sign   {d:.0} us       ({d:.0}% of the server's cost)
        \\  ed25519 sign      {d:.0} us       (what the other scheme would cost instead)
        \\
    , .{
        count,
        @as(f64, @floatFromInt(server_each)) / 1000.0,
        if (server_each == 0) 0.0 else 1_000_000_000.0 / @as(f64, @floatFromInt(server_each)),
        @as(f64, @floatFromInt(client_each)) / 1000.0,
        @as(f64, @floatFromInt(signature_nanos)) / 1000.0,
        if (server_each == 0) 0.0 else 100.0 * @as(f64, @floatFromInt(signature_nanos)) /
            @as(f64, @floatFromInt(server_each)),
        @as(f64, @floatFromInt(ed25519_nanos)) / 1000.0,
    });
}
