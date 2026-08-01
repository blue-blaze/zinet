//! The server half of the TLS 1.3 handshake: sans-io, level-addressed, and
//! shared between TCP (via `codec/tls13/`) and QUIC (RFC 9001 §4).
//!
//! It sits beside `client.zig` because they are the same engine seen from the
//! two ends — same key schedule, same message builders, same `provide`/`output`
//! shape — and because a QUIC server needs exactly this with the record layer
//! swapped for CRYPTO frames. What differs between the two transports is
//! carried in `Options`: whether the `quic_transport_parameters` extension is
//! produced, and whether ALPN must be agreed.
//!
//! Two things a client-only engine never had to do, and both are load bearing:
//!
//! - **`legacy_session_id` is echoed** (§4.1.3). A QUIC client sends an empty
//!   one because RFC 9001 §8.4 forbids middlebox compatibility mode, but a TCP
//!   client sends 32 random bytes and *checks* that they come back. Not echoing
//!   it fails against every real client while passing every test written
//!   against our own.
//! - **CertificateVerify is signed rather than verified**, which is why this
//!   file needs `identity.zig` and why the standard library's inability to
//!   produce RSA signatures decides what certificates a server can hold.
//!
//! HelloRetryRequest is never sent. A client offering no x25519 share is
//! refused with `error.NoSupportedGroup` instead, for the same reason the
//! client refuses to *receive* one: §4.4.1's transcript replacement is a
//! separate mechanism, and half of it would fail only against the peers that
//! exercise it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const tls = @import("tls.zig");
const handshake = @import("handshake.zig");
const quic_crypto = @import("crypto.zig");
const client_mod = @import("client.zig");
const identity_mod = @import("../tls13/identity.zig");

pub const Level = client_mod.Level;
pub const Identity = identity_mod.Identity;

pub const Error = error{
    /// A message arrived at an encryption level that cannot carry it (§4.1.3).
    UnexpectedEncryptionLevel,
    UnexpectedMessage,
    HandshakeBufferOverflow,
    /// The client offered no TLS 1.3 in supported_versions.
    UnsupportedVersion,
    /// No cipher suite in common.
    NoSupportedCipherSuite,
    /// No x25519 key share. A HelloRetryRequest would be the other answer;
    /// see the module comment for why this one is preferred.
    NoSupportedGroup,
    /// The client's signature_algorithms does not include what our key can
    /// produce — with an ECDSA or Ed25519 key this means a client that only
    /// accepts RSA.
    NoSupportedSignatureScheme,
    /// The client offered no protocol we speak, and this transport requires
    /// one (QUIC does; RFC 9001 §8.1).
    NoApplicationProtocol,
    /// A client offering a session ID longer than §4.1.2 permits.
    HandshakeMalformed,
    /// The client's Finished did not verify: it does not hold the keys.
    FinishedMismatch,
    /// Latched, so one failure does not become a storm.
    HandshakeFailed,
} || identity_mod.Error || Allocator.Error;

const max_buffered = tls.max_message_len + tls.message_header_len;
/// §4.1.2: opaque legacy_session_id<0..32>.
const max_session_id = 32;

const max_local_parameters = client_mod.max_local_parameters;

pub const Options = struct {
    /// The certificate chain and signing key. Borrowed; must outlive the
    /// handshake.
    identity: *const Identity,
    /// Protocols we speak, most preferred first. The intersection with the
    /// client's list is resolved in our order, which is what RFC 7301 §3.2
    /// intends by letting the server choose.
    alpn: []const []const u8 = &.{},
    /// RFC 9000 §18's encoded transport parameters. Null (TCP) omits the
    /// extension; its presence is what makes this a QUIC handshake.
    transport_parameters: ?[]const u8 = null,
    /// Whether a failure to agree on ALPN is fatal. QUIC says yes (§8.1); TCP
    /// leaves it to policy, and declining is the ordinary outcome.
    require_alpn: bool = false,
};

pub const State = enum {
    wait_client_hello,
    wait_finished,
    complete,
    failed,
};

pub const Server = struct {
    state: State = .wait_client_hello,
    options: Options,

    private_key: [handshake.X25519.secret_length]u8,
    public_key: [handshake.X25519.public_length]u8,
    random: [handshake.random_len]u8,

    schedule: ?tls.Schedule = null,
    handshake_secrets: ?tls.Pair = null,
    application_secrets: ?tls.Pair = null,
    negotiated_suite: ?quic_crypto.Suite = null,

    /// Echoed into the ServerHello (§4.1.3).
    session_id: [max_session_id]u8 = @splat(0),
    session_id_len: u8 = 0,

    /// What we chose, copied out of the ClientHello because that buffer is the
    /// caller's and is gone by the time anyone asks.
    negotiated_alpn_buf: [255]u8 = @splat(0),
    negotiated_alpn_len: u8 = 0,
    /// SNI, copied for the same reason. Kept so a caller can log it or, later,
    /// choose a certificate by it.
    server_name_buf: [253]u8 = @splat(0),
    server_name_len: u8 = 0,
    /// Our own transport parameters, copied rather than borrowed.
    ///
    /// `Options` carries a slice, and the caller that encodes those parameters
    /// usually does so into a local buffer and then returns the connection by
    /// value — at which point the slice points into a dead stack frame. That
    /// defect existed here and survived every test plus the aioquic
    /// cross-check, because the bytes happened to still be intact when they
    /// were read. An inline array moves with the struct and cannot dangle.
    local_parameters: [max_local_parameters]u8 = undefined,
    local_parameters_len: usize = 0,
    peer_transport_parameters: std.ArrayList(u8) = .empty,

    inbox: [Level.count]std.ArrayList(u8) = .{ .empty, .empty, .empty },
    outbox: [Level.count]std.ArrayList(u8) = .{ .empty, .empty, .empty },

    /// `seed` supplies the ephemeral key and the ServerHello random; injected
    /// rather than drawn, so a handshake is reproducible in a test.
    pub fn init(options: Options, seed: [64]u8) !Server {
        const key_pair = try handshake.X25519.KeyPair.generateDeterministic(seed[0..32].*);
        var self: @This() = .{
            .options = options,
            .private_key = key_pair.secret_key,
            .public_key = key_pair.public_key,
            .random = seed[32..64].*,
        };
        if (options.transport_parameters) |parameters| {
            if (parameters.len > max_local_parameters) return error.BufferTooSmall;
            @memcpy(self.local_parameters[0..parameters.len], parameters);
            self.local_parameters_len = parameters.len;
        }
        return self;
    }

    /// Our transport parameters, or null when this handshake carries none —
    /// which is what tells the peer this is TLS over TCP rather than QUIC.
    fn localParameters(self: *const @This()) ?[]const u8 {
        if (self.options.transport_parameters == null) return null;
        return self.local_parameters[0..self.local_parameters_len];
    }

    pub fn deinit(self: *Server, gpa: Allocator) void {
        self.peer_transport_parameters.deinit(gpa);
        for (&self.inbox) |*list| list.deinit(gpa);
        for (&self.outbox) |*list| list.deinit(gpa);
        self.* = undefined;
    }

    /// Feed handshake bytes for one encryption level, in order.
    pub fn provide(self: *Server, gpa: Allocator, level: Level, bytes: []const u8) !void {
        if (self.state == .failed) return error.HandshakeFailed;

        const inbox = &self.inbox[@backingInt(level)];
        if (inbox.items.len + bytes.len > max_buffered) {
            self.state = .failed;
            return error.HandshakeBufferOverflow;
        }
        try inbox.appendSlice(gpa, bytes);

        while (true) {
            const message = tls.nextMessage(inbox.items) catch |err| {
                self.state = .failed;
                return err;
            };
            const found = message orelse break;
            const consumed = found.raw.len;

            self.handleMessage(gpa, level, found) catch |err| {
                self.state = .failed;
                return err;
            };
            inbox.replaceRangeAssumeCapacity(0, consumed, &.{});
        }
    }

    fn handleMessage(self: *Server, gpa: Allocator, level: Level, message: tls.Message) !void {
        switch (self.state) {
            .wait_client_hello => {
                // §4.1.3: the ClientHello arrives before any key exists.
                if (level != .initial) return error.UnexpectedEncryptionLevel;
                if (message.type != .client_hello) return error.UnexpectedMessage;
                try self.handleClientHello(gpa, message);
            },
            .wait_finished => {
                if (level != .handshake) return error.UnexpectedEncryptionLevel;
                if (message.type != .finished) return error.UnexpectedMessage;
                // §4.4.4 against the *client's* handshake traffic secret: this
                // is the step that proves the peer holds the keys.
                self.schedule.?.verifyFinished(
                    self.handshake_secrets.?.client.slice(),
                    message.body,
                ) catch return error.FinishedMismatch;
                self.state = .complete;
            },
            .complete => {
                // Post-handshake messages are the transport's business (session
                // tickets, KeyUpdate); the engine is done.
                return error.UnexpectedMessage;
            },
            .failed => return error.HandshakeFailed,
        }
    }

    fn handleClientHello(self: *Server, gpa: Allocator, message: tls.Message) !void {
        const hello = try parseClientHello(message.body);

        // Version first: §4.2.1 makes a client without TLS 1.3 in
        // supported_versions unservable, and every later choice assumes 1.3.
        if (!hello.offers_tls13) return error.UnsupportedVersion;

        const chosen_suite = try self.chooseSuite(hello.cipher_suites);
        const share = hello.x25519_share orelse return error.NoSupportedGroup;
        try self.checkSignatureScheme(hello.signature_algorithms);
        const chosen_alpn = try self.chooseAlpn(hello.alpn);

        // Nothing above this line has changed any state, which is the same rule
        // the QUIC connection layer follows for unauthenticated packets: a
        // rejected ClientHello leaves a server able to serve the next one.
        if (hello.session_id.len > max_session_id) return error.HandshakeMalformed;
        @memcpy(self.session_id[0..hello.session_id.len], hello.session_id);
        self.session_id_len = @intCast(hello.session_id.len);

        if (chosen_alpn.len > self.negotiated_alpn_buf.len) return error.HandshakeMalformed;
        @memcpy(self.negotiated_alpn_buf[0..chosen_alpn.len], chosen_alpn);
        self.negotiated_alpn_len = @intCast(chosen_alpn.len);

        const name_len = @min(hello.server_name.len, self.server_name_buf.len);
        @memcpy(self.server_name_buf[0..name_len], hello.server_name[0..name_len]);
        self.server_name_len = @intCast(name_len);

        self.peer_transport_parameters.clearRetainingCapacity();
        try self.peer_transport_parameters.appendSlice(gpa, hello.transport_parameters);

        self.negotiated_suite = chosen_suite;
        self.schedule = .init(chosen_suite);
        self.schedule.?.addMessage(message.raw);

        // ServerHello, at the level the ClientHello came in on: it is what the
        // handshake keys are derived *from*, so it cannot be protected by them.
        var hello_buf: [128 + max_session_id]u8 = undefined;
        const server_hello = self.writeServerHello(&hello_buf, chosen_suite);
        self.schedule.?.addMessage(server_hello);
        try self.outbox[@backingInt(Level.initial)].appendSlice(gpa, server_hello);

        const shared = try handshake.X25519.scalarmult(self.private_key, share);
        self.handshake_secrets = self.schedule.?.setSharedSecret(&shared);

        try self.writeFlight(gpa);
        self.state = .wait_finished;
    }

    fn writeServerHello(self: *Server, dest: []u8, chosen: quic_crypto.Suite) []const u8 {
        var builder: handshake.Builder = .init(dest);
        builder.byte(@backingInt(tls.MessageType.server_hello));
        const message = builder.begin24();

        builder.int16(handshake.tls_1_2_legacy);
        builder.bytes(&self.random);

        // §4.1.3: echo the client's legacy_session_id verbatim. A TCP client in
        // compatibility mode rejects a handshake that does not.
        const session_id = builder.beginByte();
        builder.bytes(self.session_id[0..self.session_id_len]);
        builder.end(session_id);

        builder.int16(@backingInt(suiteToCipherSuite(chosen)));
        builder.byte(0); // legacy_compression_method

        {
            const extensions = builder.begin16();
            {
                const ext = builder.beginExtension(.supported_versions);
                builder.int16(handshake.tls_1_3);
                builder.end(ext);
            }
            {
                const ext = builder.beginExtension(.key_share);
                builder.int16(@backingInt(handshake.NamedGroup.x25519));
                const share = builder.begin16();
                builder.bytes(&self.public_key);
                builder.end(share);
                builder.end(ext);
            }
            builder.end(extensions);
        }
        builder.end(message);
        return builder.written();
    }

    /// EncryptedExtensions, Certificate, CertificateVerify, Finished — one
    /// flight at the handshake level, in the order §4.4 fixes.
    fn writeFlight(self: *Server, gpa: Allocator) !void {
        const outbox = &self.outbox[@backingInt(Level.handshake)];
        var scratch: [4096]u8 = undefined;

        // EncryptedExtensions.
        {
            var builder: handshake.Builder = .init(&scratch);
            builder.byte(@backingInt(tls.MessageType.encrypted_extensions));
            const message = builder.begin24();
            const extensions = builder.begin16();
            if (self.negotiated_alpn_len > 0) {
                const ext = builder.beginExtension(.alpn);
                const list = builder.begin16();
                const entry = builder.beginByte();
                builder.bytes(self.negotiated_alpn_buf[0..self.negotiated_alpn_len]);
                builder.end(entry);
                builder.end(list);
                builder.end(ext);
            }
            if (self.localParameters()) |parameters| {
                const ext = builder.beginExtension(.quic_transport_parameters);
                builder.bytes(parameters);
                builder.end(ext);
            }
            builder.end(extensions);
            builder.end(message);
            const written = builder.written();
            self.schedule.?.addMessage(written);
            try outbox.appendSlice(gpa, written);
        }

        // Certificate (§4.4.2). Built into the outbox directly, because a chain
        // can be several kilobytes and a stack scratch big enough for one is
        // a stack scratch big enough for a peer to care about.
        {
            const start = outbox.items.len;
            var total: usize = 4 + 1 + 3; // header, context, list length
            for (self.options.identity.certificates) |certificate| {
                total += 3 + certificate.len + 2; // length, DER, extensions
            }
            const dest = try outbox.addManyAsSlice(gpa, total);
            var builder: handshake.Builder = .init(dest);
            builder.byte(@backingInt(tls.MessageType.certificate));
            const message = builder.begin24();
            builder.byte(0); // certificate_request_context: empty for a server
            // §4.4.2: certificate_list carries a three-byte length, unlike
            // most TLS vectors — which is exactly the boundary the RFC 8448
            // transcription got wrong once already.
            const list = builder.begin24();
            for (self.options.identity.certificates) |certificate| {
                const entry = builder.begin24();
                builder.bytes(certificate);
                builder.end(entry);
                const extensions = builder.begin16();
                builder.end(extensions);
            }
            builder.end(list);
            builder.end(message);
            assert(builder.len == total);
            self.schedule.?.addMessage(outbox.items[start..]);
        }

        // CertificateVerify (§4.4.3): a signature over the transcript so far,
        // which is what binds the certificate to *this* handshake.
        {
            const transcript_hash = self.schedule.?.transcript.peek();
            const digest_len = self.schedule.?.digestLen();
            var content_buf: [64 + handshake.server_signature_context.len + 1 + tls.max_digest_len]u8 = undefined;
            const content = handshake.signatureContent(
                &content_buf,
                handshake.server_signature_context,
                transcript_hash[0..digest_len],
            );

            var signature_buf: [identity_mod.PrivateKey.max_signature_len]u8 = undefined;
            const signature = try self.options.identity.key.sign(content, &signature_buf);

            var builder: handshake.Builder = .init(&scratch);
            builder.byte(@backingInt(tls.MessageType.certificate_verify));
            const message = builder.begin24();
            builder.int16(@backingInt(self.options.identity.key.scheme()));
            const body = builder.begin16();
            builder.bytes(signature);
            builder.end(body);
            builder.end(message);
            const written = builder.written();
            self.schedule.?.addMessage(written);
            try outbox.appendSlice(gpa, written);
        }

        // Finished (§4.4.4), then the application secrets — in that order,
        // because §7.1 derives them from a transcript that includes this
        // message but not the client's.
        {
            const verify_data = self.schedule.?.finishedVerifyData(
                self.handshake_secrets.?.server.slice(),
            );
            var builder: handshake.Builder = .init(&scratch);
            builder.byte(@backingInt(tls.MessageType.finished));
            const message = builder.begin24();
            builder.bytes(verify_data.slice());
            builder.end(message);
            const written = builder.written();
            self.schedule.?.addMessage(written);
            try outbox.appendSlice(gpa, written);
        }
        self.application_secrets = self.schedule.?.applicationSecrets();
    }

    fn chooseSuite(self: *const Server, offered: []const u8) Error!quic_crypto.Suite {
        _ = self;
        // Our preference order, not the client's: the server chooses (§4.1.1).
        const preference = [_]handshake.CipherSuite{
            .aes_128_gcm_sha256,
            .aes_256_gcm_sha384,
            .chacha20_poly1305_sha256,
        };
        for (preference) |candidate| {
            var index: usize = 0;
            while (index + 1 < offered.len) : (index += 2) {
                const value = std.mem.readInt(u16, offered[index..][0..2], .big);
                if (value == @backingInt(candidate)) return candidate.toSuite().?;
            }
        }
        return error.NoSupportedCipherSuite;
    }

    fn checkSignatureScheme(self: *const Server, offered: []const u8) Error!void {
        const ours = @backingInt(self.options.identity.key.scheme());
        var index: usize = 0;
        while (index + 1 < offered.len) : (index += 2) {
            if (std.mem.readInt(u16, offered[index..][0..2], .big) == ours) return;
        }
        // An empty signature_algorithms is not "anything goes": §4.2.3 makes
        // the extension mandatory for a certificate-authenticated handshake.
        return error.NoSupportedSignatureScheme;
    }

    /// Resolve the intersection in *our* preference order. Returns an empty
    /// slice when nothing matches and the transport tolerates that.
    fn chooseAlpn(self: *const Server, offered: []const u8) Error![]const u8 {
        if (self.options.alpn.len == 0 or offered.len == 0) {
            if (self.options.require_alpn) return error.NoApplicationProtocol;
            return &.{};
        }
        for (self.options.alpn) |candidate| {
            var reader: handshake.Reader = .init(offered);
            while (!reader.empty()) {
                const protocol = reader.blockByte() catch return error.HandshakeMalformed;
                if (std.mem.eql(u8, protocol, candidate)) return candidate;
            }
        }
        if (self.options.require_alpn) return error.NoApplicationProtocol;
        return &.{};
    }

    pub fn output(self: *const Server, level: Level) []const u8 {
        return self.outbox[@backingInt(level)].items;
    }

    pub fn consumeOutput(self: *Server, gpa: Allocator, level: Level, n: usize) void {
        _ = gpa;
        const outbox = &self.outbox[@backingInt(level)];
        assert(n <= outbox.items.len);
        outbox.replaceRangeAssumeCapacity(0, n, &.{});
    }

    pub fn secrets(self: *const Server, level: Level) ?tls.Pair {
        return switch (level) {
            .initial => null,
            .handshake => self.handshake_secrets,
            .one_rtt => self.application_secrets,
        };
    }

    pub fn suite(self: *const Server) ?quic_crypto.Suite {
        return self.negotiated_suite;
    }

    /// True once the client's Finished has been verified. Note the asymmetry
    /// with the client: a server's application keys exist *before* this, since
    /// it may send data as soon as its own Finished is out.
    pub fn isComplete(self: *const Server) bool {
        return self.state == .complete;
    }

    pub fn alpn(self: *const Server) []const u8 {
        return self.negotiated_alpn_buf[0..self.negotiated_alpn_len];
    }

    pub fn serverName(self: *const Server) []const u8 {
        return self.server_name_buf[0..self.server_name_len];
    }

    pub fn transportParameters(self: *const Server) []const u8 {
        return self.peer_transport_parameters.items;
    }
};

fn suiteToCipherSuite(suite: quic_crypto.Suite) handshake.CipherSuite {
    return switch (suite) {
        .aes_128_gcm_sha256 => .aes_128_gcm_sha256,
        .aes_256_gcm_sha384 => .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256 => .chacha20_poly1305_sha256,
    };
}

/// What a ClientHello offers. Everything borrows the message.
pub const ClientHello = struct {
    session_id: []const u8,
    /// Raw two-byte-per-entry list, as it appears on the wire.
    cipher_suites: []const u8,
    signature_algorithms: []const u8,
    /// The ALPN ProtocolNameList body (one-byte-prefixed names).
    alpn: []const u8,
    server_name: []const u8,
    transport_parameters: []const u8,
    x25519_share: ?[handshake.X25519.public_length]u8,
    offers_tls13: bool,
};

pub fn parseClientHello(body: []const u8) handshake.Error!ClientHello {
    var reader: handshake.Reader = .init(body);
    _ = try reader.int16(); // legacy_version
    _ = try reader.take(handshake.random_len);
    const session_id = try reader.blockByte();
    const cipher_suites = try reader.block16();
    _ = try reader.blockByte(); // legacy_compression_methods

    var result: ClientHello = .{
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .signature_algorithms = &.{},
        .alpn = &.{},
        .server_name = &.{},
        .transport_parameters = &.{},
        .x25519_share = null,
        .offers_tls13 = false,
    };

    // §4.1.2: a TLS 1.3 ClientHello always has extensions, and without them
    // there is no supported_versions, so the version check below rejects it.
    if (reader.empty()) return result;

    var iterator: handshake.ExtensionIterator = .{ .reader = .init(try reader.block16()) };
    while (try iterator.next()) |extension| switch (extension.type) {
        .supported_versions => {
            var inner: handshake.Reader = .init(extension.body);
            var list: handshake.Reader = .init(try inner.blockByte());
            while (!list.empty()) {
                if (try list.int16() == handshake.tls_1_3) result.offers_tls13 = true;
            }
        },
        .key_share => {
            var inner: handshake.Reader = .init(extension.body);
            var shares: handshake.Reader = .init(try inner.block16());
            while (!shares.empty()) {
                const group = try shares.int16();
                const share = try shares.block16();
                // Take the first x25519 share and ignore the rest: a client
                // may offer several groups, and this server speaks one.
                if (group == @backingInt(handshake.NamedGroup.x25519) and
                    share.len == handshake.X25519.public_length and
                    result.x25519_share == null)
                {
                    result.x25519_share = share[0..handshake.X25519.public_length].*;
                }
            }
        },
        .signature_algorithms => {
            var inner: handshake.Reader = .init(extension.body);
            result.signature_algorithms = try inner.block16();
        },
        .alpn => {
            var inner: handshake.Reader = .init(extension.body);
            result.alpn = try inner.block16();
        },
        .server_name => {
            var inner: handshake.Reader = .init(extension.body);
            var list: handshake.Reader = .init(try inner.block16());
            while (!list.empty()) {
                const name_type = try list.byte();
                const name = try list.block16();
                if (name_type == 0) {
                    result.server_name = name;
                    break;
                }
            }
        },
        .quic_transport_parameters => result.transport_parameters = extension.body,
        else => {},
    };
    return result;
}

// -- Tests --------------------------------------------------------------------

const testing = std.testing;

/// An identity for the tests. The key is derived from a scalar in code rather
/// than loaded from a pasted PEM: the parser has its own tests in
/// `identity.zig`, and what matters here is the handshake. The certificate is
/// an opaque blob, which is all it can be — the client under test runs with
/// `verification = null` precisely so the *handshake* is what is measured.
pub fn testIdentity() Identity {
    const scalar: [32]u8 = .{
        0x0d, 0x2c, 0x1f, 0x37, 0x4b, 0x59, 0x66, 0x71, 0x8a, 0x93, 0xa5, 0xb2, 0xc4, 0xd1, 0xe8, 0xf3,
        0x02, 0x15, 0x24, 0x38, 0x47, 0x51, 0x63, 0x7a, 0x85, 0x9c, 0xab, 0xb7, 0xcd, 0xd9, 0xe4, 0xfb,
    };
    const secret = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(scalar) catch unreachable;
    const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret) catch unreachable;
    return .{
        .certificates = &test_certificates,
        .key = .{ .ecdsa_p256 = key_pair },
    };
}

fn testEd25519Identity() Identity {
    const seed: [32]u8 = @splat(0x2c);
    const key_pair = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
    return .{
        .certificates = &test_certificates,
        .key = .{ .ed25519 = key_pair },
    };
}

const test_certificate = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
const test_certificates = [_][]const u8{&test_certificate};

/// Builds a ClientHello for tests. Public because the TCP session layer needs
/// one with a non-empty `legacy_session_id`, and our own client never sends
/// that — RFC 9001 §8.4 forbids it on QUIC. Same reason `TestServer` is public.
pub fn testClientHello(dest: []u8, alpn: []const []const u8, session_id_len: usize) []const u8 {
    const seed: [64]u8 = @splat(0x11);
    const key_pair = handshake.X25519.KeyPair.generateDeterministic(seed[0..32].*) catch unreachable;
    var builder: handshake.Builder = .init(dest);
    builder.byte(@backingInt(tls.MessageType.client_hello));
    const message = builder.begin24();
    builder.int16(handshake.tls_1_2_legacy);
    builder.bytes(seed[32..64]);
    const session_id = builder.beginByte();
    for (0..session_id_len) |index| builder.byte(@intCast(index));
    builder.end(session_id);
    {
        const suites = builder.begin16();
        builder.int16(@backingInt(handshake.CipherSuite.aes_128_gcm_sha256));
        builder.end(suites);
    }
    builder.byte(1);
    builder.byte(0);
    {
        const extensions = builder.begin16();
        {
            const ext = builder.beginExtension(.supported_versions);
            const list = builder.beginByte();
            builder.int16(handshake.tls_1_3);
            builder.end(list);
            builder.end(ext);
        }
        {
            const ext = builder.beginExtension(.key_share);
            const shares = builder.begin16();
            builder.int16(@backingInt(handshake.NamedGroup.x25519));
            const share = builder.begin16();
            builder.bytes(&key_pair.public_key);
            builder.end(share);
            builder.end(shares);
            builder.end(ext);
        }
        {
            const ext = builder.beginExtension(.signature_algorithms);
            const list = builder.begin16();
            builder.int16(@backingInt(handshake.SignatureScheme.ecdsa_secp256r1_sha256));
            builder.end(list);
            builder.end(ext);
        }
        if (alpn.len > 0) {
            const ext = builder.beginExtension(.alpn);
            const list = builder.begin16();
            for (alpn) |protocol| {
                const entry = builder.beginByte();
                builder.bytes(protocol);
                builder.end(entry);
            }
            builder.end(list);
            builder.end(ext);
        }
        {
            const ext = builder.beginExtension(.server_name);
            const list = builder.begin16();
            builder.byte(0);
            const name = builder.begin16();
            builder.bytes("example.test");
            builder.end(name);
            builder.end(list);
            builder.end(ext);
        }
        builder.end(extensions);
    }
    builder.end(message);
    return builder.written();
}

test "server: a ClientHello yields a full flight, and the signature verifies" {
    const gpa = testing.allocator;
    const identity = testIdentity();

    const seed: [64]u8 = @splat(0x77);
    var server: Server = try .init(.{
        .identity = &identity,
        .alpn = &.{ "h2", "http/1.1" },
    }, seed);
    defer server.deinit(gpa);

    var hello_buf: [1024]u8 = undefined;
    const hello = testClientHello(&hello_buf, &.{ "http/1.1", "h2" }, 32);
    try server.provide(gpa, .initial, hello);

    // The ServerHello is unprotected; the rest is at the handshake level.
    try testing.expect(server.output(.initial).len > 0);
    try testing.expect(server.output(.handshake).len > 0);
    try testing.expect(server.secrets(.handshake) != null);
    try testing.expect(server.secrets(.one_rtt) != null);
    // Not complete: the client's Finished has not arrived.
    try testing.expect(!server.isComplete());

    // The server chose from *its* preference order, not the client's.
    try testing.expectEqualStrings("h2", server.alpn());
    try testing.expectEqualStrings("example.test", server.serverName());

    // §4.1.3: the 32-byte session id came back verbatim.
    const server_hello = (try tls.nextMessage(server.output(.initial))).?;
    var reader: handshake.Reader = .init(server_hello.body);
    _ = try reader.int16();
    _ = try reader.take(handshake.random_len);
    const echoed = try reader.blockByte();
    try testing.expectEqual(@as(usize, 32), echoed.len);
    for (echoed, 0..) |byte, index| try testing.expectEqual(@as(u8, @intCast(index)), byte);
}

test "server: the whole handshake against the client engine, both directions" {
    // The real check: our client and our server, each written from the RFC
    // without reference to the other's internals, agreeing on secrets.
    const gpa = testing.allocator;
    const identity = testIdentity();

    const server_seed: [64]u8 = @splat(0x31);
    var server: Server = try .init(.{
        .identity = &identity,
        .alpn = &.{"h2"},
        .transport_parameters = &.{ 0x01, 0x00 },
        .require_alpn = true,
    }, server_seed);
    defer server.deinit(gpa);

    const client_seed: [64]u8 = @splat(0x32);
    var client: client_mod.Client = try .init(.{
        .host = "example.test",
        .alpn = &.{"h2"},
        .transport_parameters = &.{ 0x02, 0x00 },
        .verification = null,
    }, client_seed);
    defer client.deinit(gpa);

    try client.start(gpa);
    try server.provide(gpa, .initial, client.output(.initial));
    client.consumeOutput(gpa, .initial, client.output(.initial).len);

    // ServerHello first, then the protected flight: the client must derive
    // handshake keys from the former to read the latter.
    try client.provide(gpa, .initial, server.output(.initial));
    server.consumeOutput(gpa, .initial, server.output(.initial).len);
    try client.provide(gpa, .handshake, server.output(.handshake));
    server.consumeOutput(gpa, .handshake, server.output(.handshake).len);

    try testing.expect(client.isComplete());
    try testing.expectEqualStrings("h2", client.alpn());
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, client.transportParameters());

    // The client's Finished completes the server.
    try server.provide(gpa, .handshake, client.output(.handshake));
    client.consumeOutput(gpa, .handshake, client.output(.handshake).len);
    try testing.expect(server.isComplete());
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x00 }, server.transportParameters());

    // Both sides derived the same secrets, in both directions and at both
    // levels — which is the only statement that matters.
    const client_hs = client.secrets(.handshake).?;
    const server_hs = server.secrets(.handshake).?;
    try testing.expectEqualSlices(u8, client_hs.client.slice(), server_hs.client.slice());
    try testing.expectEqualSlices(u8, client_hs.server.slice(), server_hs.server.slice());
    const client_ap = client.secrets(.one_rtt).?;
    const server_ap = server.secrets(.one_rtt).?;
    try testing.expectEqualSlices(u8, client_ap.client.slice(), server_ap.client.slice());
    try testing.expectEqualSlices(u8, client_ap.server.slice(), server_ap.server.slice());
    // And the two directions are not the same key.
    try testing.expect(!std.mem.eql(u8, client_ap.client.slice(), client_ap.server.slice()));
}

test "server: a forged client Finished is refused" {
    const gpa = testing.allocator;
    const identity = testIdentity();

    const seed: [64]u8 = @splat(0x41);
    var server: Server = try .init(.{ .identity = &identity }, seed);
    defer server.deinit(gpa);

    var hello_buf: [1024]u8 = undefined;
    try server.provide(gpa, .initial, testClientHello(&hello_buf, &.{}, 0));

    // A Finished of the right shape and the wrong contents.
    var forged: [4 + 32]u8 = @splat(0);
    forged[0] = @backingInt(tls.MessageType.finished);
    forged[3] = 32;
    try testing.expectError(error.FinishedMismatch, server.provide(gpa, .handshake, &forged));
    try testing.expectEqual(State.failed, server.state);
}

test "server: every refusal is its own error, and none of them changes state" {
    const gpa = testing.allocator;
    const identity = testIdentity();

    const seed: [64]u8 = @splat(0x51);
    var scratch: [1024]u8 = undefined;

    // No TLS 1.3 in supported_versions.
    {
        var server: Server = try .init(.{ .identity = &identity }, seed);
        defer server.deinit(gpa);
        const hello = testClientHello(&scratch, &.{}, 0);
        // Rewrite the version inside supported_versions to 1.2.
        var mutable: [1024]u8 = undefined;
        @memcpy(mutable[0..hello.len], hello);
        const at = std.mem.indexOf(u8, mutable[0..hello.len], &[_]u8{ 0x03, 0x04 }).?;
        mutable[at + 1] = 0x03;
        try testing.expectError(
            error.UnsupportedVersion,
            server.provide(gpa, .initial, mutable[0..hello.len]),
        );
    }

    // A client offering only a suite we do not have.
    {
        var server: Server = try .init(.{ .identity = &identity }, seed);
        defer server.deinit(gpa);
        const hello = testClientHello(&scratch, &.{}, 0);
        var mutable: [1024]u8 = undefined;
        @memcpy(mutable[0..hello.len], hello);
        const at = std.mem.indexOf(u8, mutable[0..hello.len], &[_]u8{ 0x13, 0x01 }).?;
        mutable[at + 1] = 0x04; // TLS_AES_128_CCM_SHA256, which we refuse
        try testing.expectError(
            error.NoSupportedCipherSuite,
            server.provide(gpa, .initial, mutable[0..hello.len]),
        );
    }

    // A client whose signature_algorithms cannot accept our key: with an
    // ECDSA identity, an RSA-only client.
    {
        var server: Server = try .init(.{ .identity = &identity }, seed);
        defer server.deinit(gpa);
        const hello = testClientHello(&scratch, &.{}, 0);
        var mutable: [1024]u8 = undefined;
        @memcpy(mutable[0..hello.len], hello);
        const at = std.mem.indexOf(u8, mutable[0..hello.len], &[_]u8{ 0x04, 0x03 }).?;
        mutable[at] = 0x08;
        mutable[at + 1] = 0x04; // rsa_pss_rsae_sha256
        try testing.expectError(
            error.NoSupportedSignatureScheme,
            server.provide(gpa, .initial, mutable[0..hello.len]),
        );
    }

    // ALPN with nothing in common: fatal when required, tolerated when not.
    {
        var strict: Server = try .init(.{
            .identity = &identity,
            .alpn = &.{"h3"},
            .require_alpn = true,
        }, seed);
        defer strict.deinit(gpa);
        const hello = testClientHello(&scratch, &.{"h2"}, 0);
        try testing.expectError(
            error.NoApplicationProtocol,
            strict.provide(gpa, .initial, hello),
        );

        var lenient: Server = try .init(.{
            .identity = &identity,
            .alpn = &.{"h3"},
        }, seed);
        defer lenient.deinit(gpa);
        var buf: [1024]u8 = undefined;
        try lenient.provide(gpa, .initial, testClientHello(&buf, &.{"h2"}, 0));
        try testing.expectEqual(@as(usize, 0), lenient.alpn().len);
        try testing.expect(lenient.output(.handshake).len > 0);
    }
}

test "server: no x25519 share is refused rather than answered with a retry" {
    const gpa = testing.allocator;
    const identity = testIdentity();

    const seed: [64]u8 = @splat(0x61);
    var server: Server = try .init(.{ .identity = &identity }, seed);
    defer server.deinit(gpa);

    var scratch: [1024]u8 = undefined;
    const hello = testClientHello(&scratch, &.{}, 0);
    var mutable: [1024]u8 = undefined;
    @memcpy(mutable[0..hello.len], hello);
    // Relabel the key share's group as secp256r1, which we do not implement.
    const at = std.mem.indexOf(u8, mutable[0..hello.len], &[_]u8{ 0x00, 0x1d, 0x00, 0x20 }).?;
    mutable[at + 1] = 0x17;
    try testing.expectError(
        error.NoSupportedGroup,
        server.provide(gpa, .initial, mutable[0..hello.len]),
    );
    // And nothing was emitted: a refused ClientHello leaves no half-built
    // handshake behind.
    try testing.expectEqual(@as(usize, 0), server.output(.initial).len);
    try testing.expectEqual(@as(usize, 0), server.output(.handshake).len);
}

test "server: an Ed25519 identity negotiates its own scheme" {
    const gpa = testing.allocator;
    const identity = testEd25519Identity();
    try testing.expectEqual(handshake.SignatureScheme.ed25519, identity.key.scheme());

    const seed: [64]u8 = @splat(0x71);
    var server: Server = try .init(.{ .identity = &identity }, seed);
    defer server.deinit(gpa);

    // The stock test ClientHello offers only ECDSA, so it must be refused...
    var scratch: [1024]u8 = undefined;
    const ecdsa_only = testClientHello(&scratch, &.{}, 0);
    try testing.expectError(
        error.NoSupportedSignatureScheme,
        server.provide(gpa, .initial, ecdsa_only),
    );

    // ...and the same hello with ed25519 offered is served.
    var server2: Server = try .init(.{ .identity = &identity }, seed);
    defer server2.deinit(gpa);
    var mutable: [1024]u8 = undefined;
    @memcpy(mutable[0..ecdsa_only.len], ecdsa_only);
    const at = std.mem.indexOf(u8, mutable[0..ecdsa_only.len], &[_]u8{ 0x04, 0x03 }).?;
    mutable[at] = 0x08;
    mutable[at + 1] = 0x07;
    try server2.provide(gpa, .initial, mutable[0..ecdsa_only.len]);
    try testing.expect(server2.output(.handshake).len > 0);
}
