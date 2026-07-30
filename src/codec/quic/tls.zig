//! The TLS 1.3 key schedule and handshake framing, in the shape QUIC needs.
//!
//! This exists because `std.crypto.tls.Client` is the wrong shape rather than
//! because it is missing pieces. It has nine public declarations, and `init` is a
//! blocking function that carries its own record layer and runs an entire
//! handshake to completion. QUIC needs the opposite: give me handshake message
//! bytes with no record header so I can put them in CRYPTO frames, and tell me
//! the secrets as they become available (RFC 9001 §4.1.4).
//!
//! What is reused rather than rewritten: `tls.hkdfExpandLabel`, which is public
//! and generic over the HKDF type, plus the hashes, HMACs and AEADs themselves.
//! The key schedule in `Client.zig` is inlined into its state machine at lines
//! 518-564 with no reusable function, so it is reassembled here — from the same
//! primitives, against RFC 8448's published intermediate values.
//!
//! Three QUIC-specific differences from TLS over TCP, all from RFC 9001 §8:
//!
//! * **There is no record layer.** Handshake messages go directly into CRYPTO
//!   frames, so this module frames messages by their own four-byte header and
//!   nothing else.
//! * **ALPN is mandatory** (§8.1), not optional as it is for TLS over TCP. Which
//!   is why `h3` can be negotiated at all — the very thing `h2` over TLS cannot
//!   do here, because `tls.Client` has no way to send ALPN.
//! * **The transcript excludes nothing.** No ChangeCipherSpec (§8.4 prohibits
//!   middlebox compatibility mode) and no EndOfEarlyData (§8.3 removes it), so
//!   the transcript is exactly the handshake messages in order.

const std = @import("std");
const assert = std.debug.assert;
const tls = std.crypto.tls;

const quic_crypto = @import("crypto.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

/// The longest digest any supported suite produces (SHA-384).
pub const max_digest_len = 48;

pub const Error = error{
    /// A handshake message header promises more than has arrived. Not fatal:
    /// CRYPTO frames deliver a stream, so the caller waits for more.
    HandshakeIncomplete,
    /// A message longer than any legitimate handshake message. §4.3 notes a
    /// ClientHello can span packets, so the bound is generous, but unbounded
    /// buffering of an unauthenticated peer's data is exactly what §4.3 warns
    /// against.
    HandshakeMessageTooLarge,
    /// A verify_data that did not match. §4.1.1: the handshake is complete only
    /// once the peer's Finished is verified, so this is fatal.
    FinishedMismatch,
};

/// RFC 8446 §4: every handshake message is a one-byte type and a 24-bit length.
pub const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    _,
};

pub const message_header_len = 4;

/// §4.3 permits a ClientHello to span multiple packets, so a peer may legally
/// send a large one — but not an unbounded one. 64 KiB is far above any real
/// certificate chain and still bounded, which is the requirement.
pub const max_message_len = 64 * 1024;

/// One handshake message, borrowed from the caller's CRYPTO stream buffer.
pub const Message = struct {
    type: MessageType,
    /// The body, without the four-byte header.
    body: []const u8,
    /// Header and body together, which is what goes into the transcript — the
    /// transcript covers whole messages including their headers (§4.4.1).
    raw: []const u8,
};

/// Cuts whole handshake messages out of a contiguous CRYPTO stream.
///
/// QUIC delivers CRYPTO frames that may split a message anywhere, so this is the
/// same "is there a whole message yet" question `ByteToMessageDecoder` answers
/// for a socket — except the accumulation is the CRYPTO stream's reassembly
/// buffer, which the stream layer already owns.
pub fn nextMessage(stream: []const u8) Error!?Message {
    if (stream.len < message_header_len) return null;
    const length = (@as(u32, stream[1]) << 16) | (@as(u32, stream[2]) << 8) | stream[3];
    if (length > max_message_len) return error.HandshakeMessageTooLarge;
    const total = message_header_len + @as(usize, length);
    if (stream.len < total) return null;
    return .{
        .type = @fromBackingInt(@intCast(stream[0])),
        .body = stream[message_header_len..total],
        .raw = stream[0..total],
    };
}

/// Write a handshake message header. The body follows.
pub fn writeMessageHeader(dest: []u8, message_type: MessageType, body_len: usize) void {
    assert(dest.len >= message_header_len);
    assert(body_len <= max_message_len);
    dest[0] = @backingInt(message_type);
    dest[1] = @intCast((body_len >> 16) & 0xff);
    dest[2] = @intCast((body_len >> 8) & 0xff);
    dest[3] = @intCast(body_len & 0xff);
}

/// The running hash of every handshake message, in order (§4.4.1).
///
/// A union rather than a generic parameter because the suite is not known until
/// the ServerHello is parsed, and by then the ClientHello is already in the
/// transcript. So the hash has to be chosen at run time and both branches kept.
pub const Transcript = union(enum) {
    sha256: Sha256,
    sha384: Sha384,

    pub fn init(suite: quic_crypto.Suite) Transcript {
        return switch (suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .{ .sha256 = .init(.{}) },
            .aes_256_gcm_sha384 => .{ .sha384 = .init(.{}) },
        };
    }

    pub fn update(self: *Transcript, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*hash| hash.update(bytes),
        }
    }

    pub fn digestLen(self: Transcript) usize {
        return switch (self) {
            .sha256 => Sha256.digest_length,
            .sha384 => Sha384.digest_length,
        };
    }

    /// The hash so far, without ending the transcript — every secret is derived
    /// from a prefix of the handshake, so this is peeked repeatedly.
    pub fn peek(self: Transcript) [max_digest_len]u8 {
        var out: [max_digest_len]u8 = @splat(0);
        switch (self) {
            inline else => |hash| {
                var copy = hash;
                var digest: [@TypeOf(hash).digest_length]u8 = undefined;
                copy.final(&digest);
                @memcpy(out[0..digest.len], &digest);
            },
        }
        return out;
    }
};

/// A traffic secret plus the length that is meaningful in it. Fixed-size so that
/// secrets can be returned by value without allocating.
pub const Secret = struct {
    bytes: [max_digest_len]u8 = @splat(0),
    len: u8 = 0,

    pub fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }

    fn from(bytes: []const u8) Secret {
        assert(bytes.len <= max_digest_len);
        var secret: Secret = .{ .len = @intCast(bytes.len) };
        @memcpy(secret.bytes[0..bytes.len], bytes);
        return secret;
    }
};

pub const Pair = struct {
    client: Secret,
    server: Secret,
};

/// RFC 8446 §7.1's key schedule, driven step by step as the handshake proceeds.
///
/// The steps have to be separable because QUIC installs keys at three different
/// moments (§4.1.4), and each one depends on a different prefix of the
/// transcript. A function that ran the whole schedule at once — which is what
/// `tls.Client` effectively does — cannot serve that.
pub const Schedule = struct {
    suite: quic_crypto.Suite,
    transcript: Transcript,
    early_secret: [max_digest_len]u8 = @splat(0),
    handshake_secret: [max_digest_len]u8 = @splat(0),
    master_secret: [max_digest_len]u8 = @splat(0),

    pub fn init(suite: quic_crypto.Suite) Schedule {
        var schedule: Schedule = .{ .suite = suite, .transcript = .init(suite) };
        // §7.1: Early-Secret = HKDF-Extract(0, PSK), and with no PSK the input
        // keying material is a string of zeros the length of the digest.
        const zeros: [max_digest_len]u8 = @splat(0);
        const len = schedule.digestLen();
        switch (suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                const salt: [1]u8 = .{0};
                schedule.early_secret[0..32].* = HkdfSha256.extract(&salt, zeros[0..len]);
            },
            .aes_256_gcm_sha384 => {
                const salt: [1]u8 = .{0};
                schedule.early_secret[0..48].* = HkdfSha384.extract(&salt, zeros[0..len]);
            },
        }
        return schedule;
    }

    pub fn digestLen(self: *const Schedule) usize {
        return switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => 32,
            .aes_256_gcm_sha384 => 48,
        };
    }

    /// Add a whole handshake message, header included, to the transcript.
    pub fn addMessage(self: *Schedule, raw: []const u8) void {
        self.transcript.update(raw);
    }

    /// §7.1's Derive-Secret, which is HKDF-Expand-Label over a transcript hash.
    fn deriveSecret(self: *const Schedule, secret: []const u8, label: []const u8, context: []const u8) Secret {
        return switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => blk: {
                const prk: [32]u8 = secret[0..32].*;
                const out = tls.hkdfExpandLabel(HkdfSha256, prk, label, context, 32);
                break :blk .from(&out);
            },
            .aes_256_gcm_sha384 => blk: {
                const prk: [48]u8 = secret[0..48].*;
                const out = tls.hkdfExpandLabel(HkdfSha384, prk, label, context, 48);
                break :blk .from(&out);
            },
        };
    }

    /// Install the handshake secrets, given the ECDHE shared secret.
    ///
    /// Must be called with the transcript holding exactly ClientHello and
    /// ServerHello (§7.1): the handshake traffic secrets are bound to that
    /// prefix, and including one message more or fewer produces keys the peer
    /// cannot match — a failure that looks like every packet being corrupt.
    pub fn setSharedSecret(self: *Schedule, shared: []const u8) Pair {
        const len = self.digestLen();

        // §7.1: derive-secret with an *empty* transcript, not the running one.
        const derived = self.deriveSecretOfEmpty(self.early_secret[0..len], "derived");
        switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                self.handshake_secret[0..32].* = HkdfSha256.extract(derived.slice(), shared);
            },
            .aes_256_gcm_sha384 => {
                self.handshake_secret[0..48].* = HkdfSha384.extract(derived.slice(), shared);
            },
        }

        const hello_hash = self.transcript.peek();
        const client = self.deriveSecret(self.handshake_secret[0..len], "c hs traffic", hello_hash[0..len]);
        const server = self.deriveSecret(self.handshake_secret[0..len], "s hs traffic", hello_hash[0..len]);

        // §7.1: the master secret comes from the handshake secret immediately,
        // even though the application secrets it feeds are not derived until the
        // server's Finished is in the transcript.
        const master_derived = self.deriveSecretOfEmpty(self.handshake_secret[0..len], "derived");
        const zeros: [max_digest_len]u8 = @splat(0);
        switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                self.master_secret[0..32].* = HkdfSha256.extract(master_derived.slice(), zeros[0..len]);
            },
            .aes_256_gcm_sha384 => {
                self.master_secret[0..48].* = HkdfSha384.extract(master_derived.slice(), zeros[0..len]);
            },
        }

        return .{ .client = client, .server = server };
    }

    /// Derive-Secret with the hash of an empty message sequence, which §7.1 uses
    /// for the two "derived" steps. Distinct from `deriveSecret` over the running
    /// transcript, and mixing them up is a classic way to produce keys that are
    /// self-consistent but wrong.
    fn deriveSecretOfEmpty(self: *const Schedule, secret: []const u8, label: []const u8) Secret {
        const empty_hash: [max_digest_len]u8 = switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => blk: {
                var out: [max_digest_len]u8 = @splat(0);
                out[0..32].* = tls.emptyHash(Sha256);
                break :blk out;
            },
            .aes_256_gcm_sha384 => blk: {
                var out: [max_digest_len]u8 = @splat(0);
                out[0..48].* = tls.emptyHash(Sha384);
                break :blk out;
            },
        };
        return self.deriveSecret(secret, label, empty_hash[0..self.digestLen()]);
    }

    /// Install the application (1-RTT) secrets.
    ///
    /// Must be called with the transcript holding everything up to and including
    /// the *server's* Finished (§7.1), which is before the client's Finished is
    /// sent. That asymmetry is the part implementations get wrong.
    pub fn applicationSecrets(self: *const Schedule) Pair {
        const len = self.digestLen();
        const hash = self.transcript.peek();
        return .{
            .client = self.deriveSecret(self.master_secret[0..len], "c ap traffic", hash[0..len]),
            .server = self.deriveSecret(self.master_secret[0..len], "s ap traffic", hash[0..len]),
        };
    }

    /// §7.5's exporter master secret, which application protocols use to derive
    /// their own keys.
    pub fn exporterSecret(self: *const Schedule) Secret {
        const len = self.digestLen();
        const hash = self.transcript.peek();
        return self.deriveSecret(self.master_secret[0..len], "exp master", hash[0..len]);
    }

    /// §4.4.4's verify_data: HMAC over the current transcript with a key derived
    /// from the sender's handshake traffic secret.
    ///
    /// The transcript must be everything before the Finished being computed —
    /// the message does not include itself.
    pub fn finishedVerifyData(self: *const Schedule, traffic_secret: []const u8) Secret {
        const hash = self.transcript.peek();
        const len = self.digestLen();
        return switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => blk: {
                const prk: [32]u8 = traffic_secret[0..32].*;
                const finished_key = tls.hkdfExpandLabel(HkdfSha256, prk, "finished", "", 32);
                var out: [HmacSha256.mac_length]u8 = undefined;
                HmacSha256.create(&out, hash[0..len], &finished_key);
                break :blk .from(&out);
            },
            .aes_256_gcm_sha384 => blk: {
                const prk: [48]u8 = traffic_secret[0..48].*;
                const finished_key = tls.hkdfExpandLabel(HkdfSha384, prk, "finished", "", 48);
                var out: [HmacSha384.mac_length]u8 = undefined;
                HmacSha384.create(&out, hash[0..len], &finished_key);
                break :blk .from(&out);
            },
        };
    }

    /// Check a peer's Finished. Constant time, because a timing oracle here would
    /// let an attacker forge one byte at a time.
    pub fn verifyFinished(self: *const Schedule, traffic_secret: []const u8, received: []const u8) Error!void {
        const expected = self.finishedVerifyData(traffic_secret);
        if (received.len != expected.len) return error.FinishedMismatch;
        const equal = switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => std.crypto.timing_safe.eql(
                [32]u8,
                expected.bytes[0..32].*,
                received[0..32].*,
            ),
            .aes_256_gcm_sha384 => std.crypto.timing_safe.eql(
                [48]u8,
                expected.bytes[0..48].*,
                received[0..48].*,
            ),
        };
        if (!equal) return error.FinishedMismatch;
    }
};

const testing = std.testing;
const vectors = @import("rfc8448.zig");

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "tls: RFC 8448 message framing over a split stream" {
    try testing.expectEqual(@as(usize, 196), vectors.client_hello.len);
    try testing.expectEqual(@as(usize, 90), vectors.server_hello.len);

    // A CRYPTO stream may split a message anywhere, so every prefix must report
    // "not yet" rather than guessing.
    for (0..vectors.client_hello.len) |cut| {
        try testing.expect(try nextMessage(vectors.client_hello[0..cut]) == null);
    }

    const message = (try nextMessage(&vectors.client_hello)).?;
    try testing.expectEqual(MessageType.client_hello, message.type);
    try testing.expectEqual(@as(usize, 192), message.body.len);
    try testing.expectEqualSlices(u8, &vectors.client_hello, message.raw);

    // Two messages back to back, which is how a server's flight arrives.
    var both: [196 + 90]u8 = undefined;
    @memcpy(both[0..196], &vectors.client_hello);
    @memcpy(both[196..], &vectors.server_hello);
    const first = (try nextMessage(&both)).?;
    try testing.expectEqual(@as(usize, 196), first.raw.len);
    const second = (try nextMessage(both[first.raw.len..])).?;
    try testing.expectEqual(MessageType.server_hello, second.type);
    try testing.expectEqual(@as(usize, 90), second.raw.len);

    // A length field beyond any legitimate message is refused rather than
    // buffered, since the peer is unauthenticated at this point (§4.3).
    const absurd = [_]u8{ 1, 0xff, 0xff, 0xff };
    try testing.expectError(error.HandshakeMessageTooLarge, nextMessage(&absurd));
}

test "tls: RFC 8448 §3 transcript hash over ClientHello and ServerHello" {
    // The value every handshake secret is bound to. Asserted on its own because
    // a wrong transcript produces keys that are internally consistent and
    // useless — the peer simply cannot decrypt anything.
    var transcript: Transcript = .init(.aes_128_gcm_sha256);
    transcript.update(&vectors.client_hello);
    transcript.update(&vectors.server_hello);
    const hash = transcript.peek();
    try testing.expectEqualSlices(
        u8,
        &vectors.hello_hash,
        hash[0..32],
    );
}

test "tls: RFC 8448 §3 key schedule, every published intermediate value" {
    var schedule: Schedule = .init(.aes_128_gcm_sha256);

    // §7.1's early secret, with no PSK.
    try testing.expectEqualSlices(
        u8,
        &vectors.early_secret,
        schedule.early_secret[0..32],
    );

    schedule.addMessage(&vectors.client_hello);
    schedule.addMessage(&vectors.server_hello);

    // The ECDHE output §3 publishes for its x25519 pair.
    const shared = vectors.shared_secret;
    const handshake = schedule.setSharedSecret(&shared);

    try testing.expectEqualSlices(
        u8,
        &vectors.handshake_secret,
        schedule.handshake_secret[0..32],
    );
    try testing.expectEqualSlices(
        u8,
        &vectors.client_handshake_secret,
        handshake.client.slice(),
    );
    try testing.expectEqualSlices(
        u8,
        &vectors.server_handshake_secret,
        handshake.server.slice(),
    );
    try testing.expectEqualSlices(
        u8,
        &vectors.master_secret,
        schedule.master_secret[0..32],
    );

    // Those handshake secrets feed QUIC's own key derivation, so the two layers
    // meet here: this is the same function packet protection uses, with QUIC's
    // labels rather than TLS's.
    const keys: quic_crypto.Keys = .fromSecret(.aes_128_gcm_sha256, handshake.server.slice());
    try testing.expectEqual(@as(usize, 12), keys.iv.len);
}

test "tls: RFC 8448 §3 Finished, both directions" {
    // §3's whole server flight, as one blob rather than message by message. That
    // is deliberate: the messages are cut back out with `nextMessage`, so this
    // tests the framing and the key schedule together, and a hand-split
    // transcription cannot introduce a boundary error the RFC does not have.
    const flight = vectors.server_flight;
    try testing.expectEqual(@as(usize, 657), flight.len);

    var schedule: Schedule = .init(.aes_128_gcm_sha256);
    schedule.addMessage(&vectors.client_hello);
    schedule.addMessage(&vectors.server_hello);
    const shared = vectors.shared_secret;
    const handshake = schedule.setSharedSecret(&shared);

    // Walk the flight. The server's Finished covers everything before it, so the
    // first three messages go into the transcript and the fourth is what we
    // check against.
    var rest: []const u8 = &flight;
    var seen: [4]MessageType = undefined;
    var count: usize = 0;
    var server_finished_body: []const u8 = &.{};
    while (try nextMessage(rest)) |message| {
        seen[count] = message.type;
        count += 1;
        if (message.type == .finished) {
            server_finished_body = message.body;
            break;
        }
        schedule.addMessage(message.raw);
        rest = rest[message.raw.len..];
    }
    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqual(MessageType.encrypted_extensions, seen[0]);
    try testing.expectEqual(MessageType.certificate, seen[1]);
    try testing.expectEqual(MessageType.certificate_verify, seen[2]);
    try testing.expectEqual(MessageType.finished, seen[3]);

    // §3's server verify_data, and it must equal what the server actually sent.
    const server_finished = schedule.finishedVerifyData(handshake.server.slice());
    try testing.expectEqualSlices(
        u8,
        &vectors.server_verify_data,
        server_finished.slice(),
    );
    try testing.expectEqualSlices(u8, server_finished_body, server_finished.slice());
    try schedule.verifyFinished(handshake.server.slice(), server_finished_body);

    // A single flipped bit must not verify. Stated as a test because a
    // comparison that always succeeds is the classic way this goes wrong.
    var tampered: [32]u8 = server_finished.bytes[0..32].*;
    tampered[31] ^= 1;
    try testing.expectError(
        error.FinishedMismatch,
        schedule.verifyFinished(handshake.server.slice(), &tampered),
    );

    // The application secrets are derived at this exact point — after the
    // server's Finished, before the client's. §3 publishes both.
    schedule.addMessage(rest[0 .. message_header_len + server_finished_body.len]);
    const application = schedule.applicationSecrets();
    try testing.expectEqualSlices(
        u8,
        &vectors.client_application_secret,
        application.client.slice(),
    );
    try testing.expectEqualSlices(
        u8,
        &vectors.server_application_secret,
        application.server.slice(),
    );
    try testing.expectEqualSlices(
        u8,
        &vectors.exporter_secret,
        schedule.exporterSecret().slice(),
    );

    // The client's Finished is computed over a transcript that *includes* the
    // server's. That asymmetry with the application secrets above is the part
    // worth having a test for.
    const client_finished = schedule.finishedVerifyData(handshake.client.slice());
    try testing.expectEqualSlices(
        u8,
        &vectors.client_verify_data,
        client_finished.slice(),
    );
}

test "tls: the two derive-secret forms are not interchangeable" {
    // §7.1 uses Derive-Secret with the *empty* transcript for its two "derived"
    // steps and with the running transcript everywhere else. Confusing them
    // produces a schedule that is self-consistent and cannot talk to anything,
    // so this asserts they differ.
    var schedule: Schedule = .init(.aes_128_gcm_sha256);
    schedule.addMessage(&vectors.client_hello);

    const len = schedule.digestLen();
    const over_empty = schedule.deriveSecretOfEmpty(schedule.early_secret[0..len], "derived");
    const over_running = schedule.deriveSecret(schedule.early_secret[0..len], "derived", schedule.transcript.peek()[0..len]);
    try testing.expect(!std.mem.eql(u8, over_empty.slice(), over_running.slice()));

    // And the empty-transcript one matches §3's published value, which is what
    // says which of the two is correct there.
    try testing.expectEqualSlices(
        u8,
        &vectors.derived_for_handshake,
        over_empty.slice(),
    );
}

test "tls: SHA-384 suites run the same schedule at a different width" {
    // Every step has a SHA-384 branch, and a copy-paste error there would only
    // show up against a peer that negotiated AES-256. There is no published
    // vector for it, so the property checked is self-consistency at the right
    // width plus a difference from the SHA-256 result.
    var wide: Schedule = .init(.aes_256_gcm_sha384);
    try testing.expectEqual(@as(usize, 48), wide.digestLen());
    try testing.expectEqual(@as(usize, 48), wide.transcript.digestLen());

    wide.addMessage(&vectors.client_hello);
    wide.addMessage(&vectors.server_hello);
    const shared = vectors.shared_secret;
    const handshake = wide.setSharedSecret(&shared);
    try testing.expectEqual(@as(u8, 48), handshake.client.len);
    try testing.expectEqual(@as(u8, 48), handshake.server.len);

    const verify = wide.finishedVerifyData(handshake.server.slice());
    try testing.expectEqual(@as(u8, 48), verify.len);
    try wide.verifyFinished(handshake.server.slice(), verify.slice());

    // The same inputs under SHA-256 must give something different, or one of the
    // branches is not being taken.
    var narrow: Schedule = .init(.aes_128_gcm_sha256);
    narrow.addMessage(&vectors.client_hello);
    narrow.addMessage(&vectors.server_hello);
    const narrow_handshake = narrow.setSharedSecret(&shared);
    try testing.expect(!std.mem.eql(
        u8,
        handshake.client.slice()[0..32],
        narrow_handshake.client.slice()[0..32],
    ));
}
