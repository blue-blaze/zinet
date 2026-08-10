//! The client side of the QUIC handshake, RFC 9001 §4.
//!
//! This is the engine `std.crypto.tls.Client` is not: bytes in, keys and events
//! out, no sockets and no record layer. The interface is the one §4.1.3
//! describes — a CRYPTO byte stream per encryption level in each direction — so
//! the caller's job is to move `output` into CRYPTO frames and to feed whatever
//! arrives in them back through `provide`.
//!
//! **Keys arrive at three separate moments** (§4.1.4), and each depends on a
//! different prefix of the transcript, which is why the schedule is driven step
//! by step rather than run to completion:
//!
//! | after | installs |
//! |---|---|
//! | ServerHello | handshake keys, both directions |
//! | the server's Finished | 1-RTT keys, both directions |
//! | the client's Finished | nothing; the handshake is complete |
//!
//! The awkward part of that table is the middle row: the 1-RTT secrets are
//! derived from a transcript that includes the server's Finished but *not* the
//! client's, while the client's Finished is computed over one that includes the
//! server's. Two adjacent operations, two different transcripts.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const quic_crypto = @import("crypto.zig");
const handshake = @import("handshake.zig");
const tls = @import("tls.zig");
const verify = @import("verify.zig");

pub const Level = enum {
    initial,
    handshake,
    one_rtt,

    /// §4.1.3: CRYPTO frames appear at three levels; 0-RTT carries application
    /// data only, never handshake bytes.
    pub const count = 3;
};

pub const Error = error{
    /// A handshake message arrived at an encryption level that cannot carry it
    /// (§4.1.3). A ServerHello in a Handshake packet, for instance, means the
    /// peer has skipped a step — or that somebody is injecting packets.
    UnexpectedEncryptionLevel,
    /// A message arrived out of order. §4.1.3 delivers CRYPTO data in order, so
    /// this is the peer being wrong rather than the network reordering.
    UnexpectedMessage,
    /// More buffered handshake data than a single message can legitimately need.
    HandshakeBufferOverflow,
    /// §4.7: the server asked for a HelloRetryRequest. Refused rather than
    /// mishandled; see the comment at `handleServerHello`.
    HelloRetryRequestUnsupported,
    /// The handshake already failed. Latched, so that one error does not become
    /// a storm as more CRYPTO data arrives.
    HandshakeFailed,
};

/// One message at a time is buffered, so the bound is one message plus its
/// header. §4.3 permits a large ClientHello and by symmetry a large flight, but
/// each *message* is bounded, and that is what has to be held at once.
const max_buffered = tls.max_message_len + tls.message_header_len;

/// Room for our own encoded transport parameters. RFC 9000 §18 has no total
/// limit, so this is a stated one: everything defined there fits several times
/// over, and an unbounded copy would be an unbounded allocation driven by a
/// caller's struct.
pub const max_local_parameters = 512;

pub const Options = struct {
    /// Sent as SNI and matched against the certificate. Empty omits SNI, which
    /// also means there is no name to verify.
    host: []const u8,
    /// RFC 9001 §8.1: mandatory, most preferred first. For HTTP/3 this is "h3".
    alpn: []const []const u8,
    /// RFC 9000 §18's encoded transport parameters. Opaque here; the transport
    /// layer builds and interprets them. Null (TLS over TCP) omits the
    /// extension from the ClientHello.
    transport_parameters: ?[]const u8,
    /// Which EncryptedExtensions contents to insist on. QUIC connections use
    /// the default; the TCP record layer passes `.tcp`, where a declined ALPN
    /// and absent transport parameters are both ordinary.
    requirements: handshake.EncryptedExtensionsRequirements = .quic,
    /// How to authenticate the server.
    ///
    /// Null skips certificate validation entirely and has to be written down
    /// rather than defaulted into, because a client that does not check the
    /// certificate is talking to whoever answered. Tests use null deliberately;
    /// the real validation path is covered against RFC 8448's genuine signature
    /// in `verify.zig`.
    verification: ?verify.Options,
};

pub const State = enum {
    /// Before `start`.
    idle,
    wait_server_hello,
    wait_encrypted_extensions,
    /// A certificate, or a Finished if the server authenticated some other way.
    wait_certificate,
    wait_certificate_verify,
    wait_finished,
    complete,
    failed,
};

pub const Client = struct {
    state: State = .idle,
    options: Options,

    private_key: [handshake.X25519.secret_length]u8,
    public_key: [handshake.X25519.public_length]u8,
    random: [handshake.random_len]u8,

    /// Null until the ServerHello names a cipher suite, because the transcript
    /// hash depends on it — and the ClientHello is already in the transcript by
    /// then. So the transcript is buffered until the suite is known.
    schedule: ?tls.Schedule = null,
    /// The ClientHello, kept because the transcript cannot start without a suite.
    client_hello: std.ArrayList(u8) = .empty,

    handshake_secrets: ?tls.Pair = null,
    application_secrets: ?tls.Pair = null,

    /// The peer's public key, copied out of its certificate. A copy rather than a
    /// borrow because Certificate and CertificateVerify are two messages and the
    /// buffer holding the first is consumed before the second arrives.
    peer_public_key: [verify.max_public_key_len]u8 = @splat(0),
    peer_public_key_len: u16 = 0,
    peer_algorithm: std.crypto.Certificate.AlgorithmCategory = .rsaEncryption,

    /// What the server chose. Copied rather than borrowed: the flight it arrived
    /// in is consumed as soon as the message is handled, and a borrow into that
    /// buffer reads whatever the next message happens to put there. This is the
    /// same rule the HTTP/2 code follows for inbound header values, and it was
    /// found the same way — by a test asserting the value survived.
    negotiated_alpn_buf: [255]u8 = @splat(0),
    negotiated_alpn_len: u8 = 0,
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

    /// Incoming CRYPTO bytes per level, awaiting a whole message.
    inbox: [Level.count]std.ArrayList(u8) = .{ .empty, .empty, .empty },
    /// Outgoing handshake bytes per level, for the caller to frame.
    outbox: [Level.count]std.ArrayList(u8) = .{ .empty, .empty, .empty },

    pub fn init(options: Options, seed: [64]u8) !Client {
        // Both the random and the key come from one seed so that a test can make
        // the whole handshake reproducible, and so that nothing here reaches for
        // a global source of randomness.
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

    pub fn deinit(self: *Client, gpa: Allocator) void {
        self.client_hello.deinit(gpa);
        self.peer_transport_parameters.deinit(gpa);
        for (&self.inbox) |*list| list.deinit(gpa);
        for (&self.outbox) |*list| list.deinit(gpa);
        self.* = undefined;
    }

    /// Produce the ClientHello. §4.1.3: a client starts by asking TLS for
    /// handshake bytes before it has sent anything.
    pub fn start(self: *Client, gpa: Allocator) !void {
        assert(self.state == .idle);

        var buf: [handshake.client_hello_overhead + 512]u8 = undefined;
        const hello = handshake.writeClientHello(&buf, .{
            .random = self.random,
            .key_share = self.public_key,
            .server_name = self.options.host,
            .alpn = self.options.alpn,
            .transport_parameters = self.localParameters(),
        });

        try self.client_hello.appendSlice(gpa, hello);
        try self.outbox[@backingInt(Level.initial)].appendSlice(gpa, hello);
        self.state = .wait_server_hello;
    }

    /// Feed CRYPTO stream bytes for one encryption level.
    ///
    /// The bytes must be in order and gap-free: RFC 9001 §4.1.3 makes reassembly
    /// the transport's job, so a gap here would be a bug in the caller rather
    /// than something to tolerate.
    pub fn provide(self: *Client, gpa: Allocator, level: Level, bytes: []const u8) !void {
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

            // Only now discard, so a handler can borrow from the buffer.
            inbox.replaceRange(gpa, 0, consumed, &.{}) catch unreachable;
            if (self.state == .complete) break;
        }
    }

    fn handleMessage(self: *Client, gpa: Allocator, level: Level, message: tls.Message) !void {
        switch (self.state) {
            .wait_server_hello => {
                // §4.1.3: a ServerHello is at the Initial level, because the
                // handshake keys it produces do not exist yet.
                if (level != .initial) return error.UnexpectedEncryptionLevel;
                if (message.type != .server_hello) return error.UnexpectedMessage;
                try self.handleServerHello(message);
            },
            .wait_encrypted_extensions => {
                if (level != .handshake) return error.UnexpectedEncryptionLevel;
                if (message.type != .encrypted_extensions) return error.UnexpectedMessage;
                const extensions = try handshake.parseEncryptedExtensions(
                    message.body,
                    self.options.alpn,
                    self.options.requirements,
                );
                if (extensions.alpn.len > self.negotiated_alpn_buf.len) {
                    return error.UnexpectedMessage;
                }
                @memcpy(self.negotiated_alpn_buf[0..extensions.alpn.len], extensions.alpn);
                self.negotiated_alpn_len = @intCast(extensions.alpn.len);
                self.peer_transport_parameters.clearRetainingCapacity();
                try self.peer_transport_parameters.appendSlice(gpa, extensions.transport_parameters);
                self.schedule.?.addMessage(message.raw);
                self.state = .wait_certificate;
            },
            .wait_certificate => {
                if (level != .handshake) return error.UnexpectedEncryptionLevel;
                switch (message.type) {
                    .certificate => {
                        if (self.options.verification) |options| {
                            const peer = try verify.verifyChain(message.body, options);
                            const key = peer.publicKey();
                            if (key.len > self.peer_public_key.len) return error.UnexpectedMessage;
                            @memcpy(self.peer_public_key[0..key.len], key);
                            self.peer_public_key_len = @intCast(key.len);
                            self.peer_algorithm = peer.algorithm();
                        }
                        self.schedule.?.addMessage(message.raw);
                        self.state = .wait_certificate_verify;
                    },
                    .finished => {
                        // §4.4.2: a server authenticated by something other than
                        // a certificate sends none. With verification configured
                        // this is fatal — a server that skips its certificate is
                        // a server that has not proved anything. With
                        // verification explicitly off, requiring a certificate
                        // nobody will check is ceremony rather than safety, so
                        // `verification` is the one switch that decides.
                        if (self.options.verification != null) return error.UnexpectedMessage;
                        try self.handleFinished(gpa, message);
                    },
                    else => return error.UnexpectedMessage,
                }
            },
            .wait_certificate_verify => {
                if (level != .handshake) return error.UnexpectedEncryptionLevel;
                if (message.type != .certificate_verify) return error.UnexpectedMessage;
                if (self.options.verification != null) {
                    const parsed = try handshake.parseCertificateVerify(message.body);
                    // §4.4.3: the signature covers the transcript up to and
                    // including the Certificate message, which is exactly what
                    // the transcript holds right now — this message has not been
                    // added yet, and adding it first would be the classic error.
                    const transcript_hash = self.schedule.?.transcript.peek();
                    const digest_len = self.schedule.?.digestLen();

                    var content_buf: [64 + handshake.server_signature_context.len + 1 + tls.max_digest_len]u8 = undefined;
                    const content = handshake.signatureContent(
                        &content_buf,
                        handshake.server_signature_context,
                        transcript_hash[0..digest_len],
                    );
                    try verify.verifySignatureWithKey(
                        self.peer_algorithm,
                        self.peer_public_key[0..self.peer_public_key_len],
                        parsed.scheme,
                        parsed.signature,
                        content,
                    );
                }
                self.schedule.?.addMessage(message.raw);
                self.state = .wait_finished;
            },
            .wait_finished => {
                if (level != .handshake) return error.UnexpectedEncryptionLevel;
                if (message.type != .finished) return error.UnexpectedMessage;
                try self.handleFinished(gpa, message);
            },
            // §4.6: post-handshake messages are legal at any time after the
            // handshake, and treating them as violations killed every connection
            // to a server built on OpenSSL — which sends a NewSessionTicket by
            // default. The handshake completed, the connection reported itself
            // established, and then the first 1-RTT packet carrying the ticket
            // failed the whole connection with no error reaching the application.
            // Ignoring the ticket is right, because resumption is not implemented
            // (see the row in HTTP3.md); *failing* on it was not.
            //
            // KeyUpdate stays fatal, and that is not an oversight: §6 of RFC 9001
            // gives QUIC its own key update and says an endpoint MUST treat a TLS
            // KeyUpdate as a connection error. So the two directions of this rule
            // differ on purpose from `tls13.session`, which rotates keys on one
            // because over TCP that is exactly what it means.
            .complete => switch (message.type) {
                .new_session_ticket => {},
                else => return error.UnexpectedMessage,
            },
            .idle, .failed => return error.UnexpectedMessage,
        }
    }

    fn handleServerHello(self: *Client, message: tls.Message) !void {
        const hello = try handshake.parseServerHello(message.body);

        // §4.7 recommends QUIC use its own Retry rather than a
        // HelloRetryRequest, and supporting one properly means replacing the
        // first ClientHello in the transcript with a message_hash (§4.4.1). That
        // is a real feature rather than a line of code, and getting it subtly
        // wrong would produce a handshake that fails only against servers that
        // send it. Refused explicitly, with the reason, rather than mishandled.
        if (hello.is_retry) return error.HelloRetryRequestUnsupported;

        const share = hello.key_share orelse return error.UnexpectedMessage;
        const shared = handshake.X25519.scalarmult(self.private_key, share) catch
            return error.UnexpectedMessage;

        // Only now is the hash function known, so the transcript starts here
        // with the ClientHello that was buffered for exactly this reason.
        self.schedule = .init(hello.suite);
        self.schedule.?.addMessage(self.client_hello.items);
        self.schedule.?.addMessage(message.raw);

        self.handshake_secrets = self.schedule.?.setSharedSecret(&shared);
        self.state = .wait_encrypted_extensions;
    }

    fn handleFinished(self: *Client, gpa: Allocator, message: tls.Message) !void {
        const pair = self.handshake_secrets.?;

        // §4.4.4: verified over the transcript *before* this message.
        try self.schedule.?.verifyFinished(pair.server.slice(), message.body);

        // §7.1: the 1-RTT secrets come from a transcript that includes the
        // server's Finished, so it goes in before they are derived.
        self.schedule.?.addMessage(message.raw);
        self.application_secrets = self.schedule.?.applicationSecrets();

        // And the client's Finished is computed over that same transcript — the
        // one including the server's but not its own.
        const verify_data = self.schedule.?.finishedVerifyData(pair.client.slice());

        var buf: [tls.message_header_len + tls.max_digest_len]u8 = undefined;
        tls.writeMessageHeader(&buf, .finished, verify_data.len);
        @memcpy(buf[tls.message_header_len..][0..verify_data.len], verify_data.slice());
        const finished = buf[0 .. tls.message_header_len + verify_data.len];

        try self.outbox[@backingInt(Level.handshake)].appendSlice(gpa, finished);
        self.schedule.?.addMessage(finished);
        self.state = .complete;
    }

    /// Handshake bytes waiting to be put in CRYPTO frames at this level.
    pub fn output(self: *const Client, level: Level) []const u8 {
        return self.outbox[@backingInt(level)].items;
    }

    /// Discard bytes the caller has framed. Separate from `output` because a
    /// CRYPTO frame may carry only part of what is pending, and the rest has to
    /// stay put until it is acknowledged.
    pub fn consumeOutput(self: *Client, gpa: Allocator, level: Level, n: usize) void {
        const list = &self.outbox[@backingInt(level)];
        assert(n <= list.items.len);
        list.replaceRange(gpa, 0, n, &.{}) catch unreachable;
    }

    /// The secrets for a level, or null before they exist.
    pub fn secrets(self: *const Client, level: Level) ?tls.Pair {
        return switch (level) {
            .initial => null, // §5.2: derived from the connection ID, not here.
            .handshake => self.handshake_secrets,
            .one_rtt => self.application_secrets,
        };
    }

    pub fn suite(self: *const Client) ?quic_crypto.Suite {
        const schedule = self.schedule orelse return null;
        return schedule.suite;
    }

    pub fn isComplete(self: *const Client) bool {
        return self.state == .complete;
    }

    pub fn alpn(self: *const Client) []const u8 {
        return self.negotiated_alpn_buf[0..self.negotiated_alpn_len];
    }

    pub fn transportParameters(self: *const Client) []const u8 {
        return self.peer_transport_parameters.items;
    }
};

/// §4.8: a TLS alert becomes a QUIC CRYPTO_ERROR whose code is 0x0100 plus the
/// alert. Mapping errors to alerts here keeps the connection layer from having
/// to know TLS's numbering.
pub fn cryptoError(err: anyerror) u64 {
    const alert: u8 = switch (err) {
        error.UnsupportedVersion => 70, // protocol_version
        error.UnsupportedCipherSuite, error.UnsupportedGroup => 71, // insufficient_security
        error.NoApplicationProtocol => 120, // no_application_protocol
        error.FinishedMismatch => 51, // decrypt_error
        error.CertificateVerifyFailed => 51,
        error.CertificateExpired => 45, // certificate_expired
        error.CertificateHostMismatch => 42, // bad_certificate
        error.IllegalParameter, error.MissingExtension => 47, // illegal_parameter
        error.UnexpectedMessage, error.UnexpectedEncryptionLevel => 10, // unexpected_message
        else => 80, // internal_error
    };
    return 0x0100 + @as(u64, alert);
}

const testing = std.testing;

test "client: a ClientHello is produced at the Initial level and nowhere else" {
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "example.com",
        .alpn = &.{"h3"},
        .transport_parameters = &.{ 0x01, 0x02 },
        .verification = null,
    }, @splat(0x42));
    defer client.deinit(gpa);

    try testing.expectEqual(State.idle, client.state);
    try testing.expectEqual(@as(usize, 0), client.output(.initial).len);

    try client.start(gpa);
    try testing.expectEqual(State.wait_server_hello, client.state);

    const hello = client.output(.initial);
    try testing.expect(hello.len > 100);
    // §4.1.3: nothing at the other levels yet, because their keys do not exist.
    try testing.expectEqual(@as(usize, 0), client.output(.handshake).len);
    try testing.expectEqual(@as(usize, 0), client.output(.one_rtt).len);

    // It is a whole, well-formed ClientHello.
    const message = (try tls.nextMessage(hello)).?;
    try testing.expectEqual(tls.MessageType.client_hello, message.type);
    try testing.expectEqual(hello.len, message.raw.len);

    // No secrets before the ServerHello, and never any for Initial — those come
    // from the connection ID (§5.2), not from TLS.
    try testing.expect(client.secrets(.initial) == null);
    try testing.expect(client.secrets(.handshake) == null);
    try testing.expect(client.secrets(.one_rtt) == null);
    try testing.expect(client.suite() == null);
}

test "client: a ServerHello at the wrong encryption level is refused" {
    // §4.1.3. A ServerHello can only be at the Initial level, since it is what
    // produces the Handshake keys. Accepting one at the Handshake level would
    // mean accepting a message encrypted with keys derived from itself.
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "",
        .alpn = &.{"h3"},
        .transport_parameters = &.{0},
        .verification = null,
    }, @splat(1));
    defer client.deinit(gpa);
    try client.start(gpa);

    var server = TestServer.init(0x77);
    const server_hello = server.writeServerHello(client.output(.initial));

    try testing.expectError(
        error.UnexpectedEncryptionLevel,
        client.provide(gpa, .handshake, server_hello),
    );
    // And the failure latches, so more data does not produce a storm of errors.
    try testing.expectEqual(State.failed, client.state);
    try testing.expectError(error.HandshakeFailed, client.provide(gpa, .initial, server_hello));
}

test "client: a full handshake against a server built from the same schedule" {
    // Two sides wired to each other, which is the shape that caught a direction
    // confusion in this repository's HTTP/2 code. The server here is a test
    // fixture rather than a peer implementation: it drives the same `Schedule`
    // from the other side, so anything that depends on *which* direction a
    // secret belongs to has to be right for this to pass.
    //
    // It sends no Certificate, and the client is configured with
    // `verification = null` to match. That boundary is deliberate: certificate
    // and CertificateVerify validation is tested against RFC 8448's genuine RSA
    // signature in verify.zig, and cannot be tested here because the standard
    // library can verify RSA signatures but not produce them — so a fixture
    // cannot sign a CertificateVerify over this handshake's transcript.
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "example.com",
        .alpn = &.{ "h3", "h3-29" },
        .transport_parameters = &.{ 0xaa, 0xbb },
        .verification = null,
    }, @splat(0x11));
    defer client.deinit(gpa);

    try client.start(gpa);
    var server = TestServer.init(0x22);

    // Initial: ServerHello.
    const server_hello = server.writeServerHello(client.output(.initial));
    try client.provide(gpa, .initial, server_hello);
    try testing.expectEqual(State.wait_encrypted_extensions, client.state);

    // Both sides now hold the same handshake secrets, and the client can name
    // the suite.
    try testing.expectEqual(quic_crypto.Suite.aes_128_gcm_sha256, client.suite().?);
    const client_handshake = client.secrets(.handshake).?;
    try testing.expectEqualSlices(
        u8,
        server.handshake_secrets.?.client.slice(),
        client_handshake.client.slice(),
    );
    try testing.expectEqualSlices(
        u8,
        server.handshake_secrets.?.server.slice(),
        client_handshake.server.slice(),
    );
    // The two directions must differ, or a mix-up would go unnoticed.
    try testing.expect(!std.mem.eql(
        u8,
        client_handshake.client.slice(),
        client_handshake.server.slice(),
    ));
    try testing.expect(client.secrets(.one_rtt) == null);

    // Handshake: EncryptedExtensions, then Finished.
    var flight_buf: [512]u8 = undefined;
    const flight = server.writeFlight(&flight_buf, "h3", &.{ 0xcc, 0xdd });
    try client.provide(gpa, .handshake, flight);

    try testing.expect(client.isComplete());
    try testing.expectEqualStrings("h3", client.alpn());
    try testing.expectEqualSlices(u8, &.{ 0xcc, 0xdd }, client.transportParameters());

    // 1-RTT secrets on both sides, matching.
    const application = client.secrets(.one_rtt).?;
    try testing.expectEqualSlices(
        u8,
        server.application_secrets.?.client.slice(),
        application.client.slice(),
    );
    try testing.expectEqualSlices(
        u8,
        server.application_secrets.?.server.slice(),
        application.server.slice(),
    );

    // The client's Finished went out at the Handshake level, and the server
    // accepts it — which is what proves the transcripts stayed in step through
    // the asymmetry around the application secrets.
    const client_finished = client.output(.handshake);
    const finished_message = (try tls.nextMessage(client_finished)).?;
    try testing.expectEqual(tls.MessageType.finished, finished_message.type);
    try server.verifyClientFinished(finished_message.body);

    // Those secrets feed QUIC's packet protection, so the layers meet: keys
    // derived here protect packets with crypto.zig's labels.
    var keys: quic_crypto.Keys = .fromSecret(client.suite().?, application.client.slice());
    var sealed: [64]u8 = undefined;
    const len = try keys.seal(&sealed, 0, "header", "payload");
    var opened: [64]u8 = undefined;
    var peer_keys: quic_crypto.Keys = .fromSecret(
        client.suite().?,
        server.application_secrets.?.client.slice(),
    );
    const opened_len = try peer_keys.open(&opened, 0, "header", sealed[0..len]);
    try testing.expectEqualStrings("payload", opened[0..opened_len]);
}

test "client: a NewSessionTicket after the handshake is ignored rather than fatal" {
    // The defect this covers was found by pointing this client at a server built
    // on OpenSSL QUIC, which sends a ticket by default: the handshake completed,
    // the connection reported itself established, and the first 1-RTT packet
    // carrying the ticket failed the connection — with no error reaching the
    // application, because the HTTP/3 client marks itself finished and drops
    // every datagram after that. Zero requests, no reset, no error.
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "example.com",
        .alpn = &.{"h3"},
        .transport_parameters = &.{ 0xaa, 0xbb },
        .verification = null,
    }, @splat(0x11));
    defer client.deinit(gpa);

    try client.start(gpa);
    var server = TestServer.init(0x22);
    try client.provide(gpa, .initial, server.writeServerHello(client.output(.initial)));
    var flight_buf: [512]u8 = undefined;
    try client.provide(gpa, .handshake, server.writeFlight(&flight_buf, "h3", &.{ 0xcc, 0xdd }));
    try testing.expect(client.isComplete());

    // §4.6.1: ticket_lifetime, ticket_age_add, an empty nonce, a one-byte ticket
    // and no extensions. The body is not read — resumption is not implemented —
    // but a well-formed one is what a server actually sends.
    const ticket = [_]u8{
        @backingInt(tls.MessageType.new_session_ticket), 0, 0, 14,
        0, 0, 0x1c, 0x20, // ticket_lifetime: 7200
        0x11, 0x22, 0x33, 0x44, // ticket_age_add
        0, // nonce: empty
        0, 1, 0xab, // ticket: one byte
        0, 0, // extensions: none
    };
    try client.provide(gpa, .one_rtt, &ticket);
    try testing.expect(client.isComplete());
    try testing.expectEqual(State.complete, client.state);

    // A second one, because OpenSSL sends two by default and a rule that only
    // survives the first would fail in exactly the same place.
    try client.provide(gpa, .one_rtt, &ticket);
    try testing.expect(client.isComplete());
}

test "client: a TLS KeyUpdate is fatal, because QUIC has its own key update" {
    // The other half of the rule above, and the reason this file cannot simply
    // copy `tls13.session`, which rotates keys on a KeyUpdate because over TCP
    // that is what it means. §6 of RFC 9001 gives QUIC its own key update and
    // requires an endpoint to treat a TLS KeyUpdate as a connection error.
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "example.com",
        .alpn = &.{"h3"},
        .transport_parameters = &.{ 0xaa, 0xbb },
        .verification = null,
    }, @splat(0x11));
    defer client.deinit(gpa);

    try client.start(gpa);
    var server = TestServer.init(0x22);
    try client.provide(gpa, .initial, server.writeServerHello(client.output(.initial)));
    var flight_buf: [512]u8 = undefined;
    try client.provide(gpa, .handshake, server.writeFlight(&flight_buf, "h3", &.{ 0xcc, 0xdd }));
    try testing.expect(client.isComplete());

    const key_update = [_]u8{ @backingInt(tls.MessageType.key_update), 0, 0, 1, 0 };
    try testing.expectError(
        error.UnexpectedMessage,
        client.provide(gpa, .one_rtt, &key_update),
    );
}

test "client: an ALPN the client never offered fails the handshake" {
    // RFC 9001 §8.1: fatal, not advisory. A server picking something else has
    // not agreed on an application protocol, and there is nothing to speak.
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "",
        .alpn = &.{"h3"},
        .transport_parameters = &.{0},
        .verification = null,
    }, @splat(3));
    defer client.deinit(gpa);
    try client.start(gpa);

    var server = TestServer.init(0x44);
    try client.provide(gpa, .initial, server.writeServerHello(client.output(.initial)));

    var flight_buf: [512]u8 = undefined;
    const flight = server.writeFlight(&flight_buf, "h2", &.{0x01});
    try testing.expectError(error.NoApplicationProtocol, client.provide(gpa, .handshake, flight));
    try testing.expectEqual(State.failed, client.state);
}

test "client: a tampered server Finished fails the handshake" {
    // §4.1.1: the handshake is complete only when the peer's Finished verifies.
    // Without this check the whole transcript is unauthenticated and an
    // in-path attacker could have altered any of it.
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "",
        .alpn = &.{"h3"},
        .transport_parameters = &.{0},
        .verification = null,
    }, @splat(5));
    defer client.deinit(gpa);
    try client.start(gpa);

    var server = TestServer.init(0x66);
    try client.provide(gpa, .initial, server.writeServerHello(client.output(.initial)));

    var flight_buf: [512]u8 = undefined;
    const flight = server.writeFlight(&flight_buf, "h3", &.{0x01});
    // Flip a bit in the last byte, which is inside the Finished's verify_data.
    var tampered: [512]u8 = undefined;
    @memcpy(tampered[0..flight.len], flight);
    tampered[flight.len - 1] ^= 1;

    try testing.expectError(
        error.FinishedMismatch,
        client.provide(gpa, .handshake, tampered[0..flight.len]),
    );
    try testing.expect(!client.isComplete());
}

test "client: a HelloRetryRequest is refused rather than mishandled" {
    // §4.7 recommends QUIC use Retry instead, and handling one correctly needs
    // §4.4.1's message_hash substitution in the transcript. Refusing explicitly
    // is honest; half-handling it would fail only against the servers that send
    // one, which is the worst kind of bug to have.
    const gpa = testing.allocator;
    var client = try Client.init(.{
        .host = "",
        .alpn = &.{"h3"},
        .transport_parameters = &.{0},
        .verification = null,
    }, @splat(7));
    defer client.deinit(gpa);
    try client.start(gpa);

    var buf: [128]u8 = undefined;
    var builder: handshake.Builder = .init(&buf);
    builder.byte(@backingInt(tls.MessageType.server_hello));
    const message = builder.begin24();
    builder.int16(handshake.tls_1_2_legacy);
    builder.bytes(&handshake.hello_retry_request_random);
    builder.byte(0);
    builder.int16(@backingInt(handshake.CipherSuite.aes_128_gcm_sha256));
    builder.byte(0);
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
            builder.end(ext);
        }
        builder.end(extensions);
    }
    builder.end(message);

    try testing.expectError(
        error.HelloRetryRequestUnsupported,
        client.provide(gpa, .initial, builder.written()),
    );
}

test "client: a message split across CRYPTO frames is reassembled" {
    // The transport delivers CRYPTO data in order but in arbitrary pieces, so
    // every split must produce the same handshake. This is the same
    // chunk-independence property the rest of this repository fuzzes for, at the
    // one layer where it still applies inside QUIC.
    const gpa = testing.allocator;
    for ([_]usize{ 1, 3, 17, 64 }) |chunk| {
        var client = try Client.init(.{
            .host = "",
            .alpn = &.{"h3"},
            .transport_parameters = &.{0},
            .verification = null,
        }, @splat(9));
        defer client.deinit(gpa);
        try client.start(gpa);

        var server = TestServer.init(0x88);
        const server_hello = server.writeServerHello(client.output(.initial));

        var offset: usize = 0;
        while (offset < server_hello.len) {
            const end = @min(offset + chunk, server_hello.len);
            try client.provide(gpa, .initial, server_hello[offset..end]);
            offset = end;
        }
        try testing.expectEqual(State.wait_encrypted_extensions, client.state);

        var flight_buf: [512]u8 = undefined;
        const flight = server.writeFlight(&flight_buf, "h3", &.{0x01});
        offset = 0;
        while (offset < flight.len) {
            const end = @min(offset + chunk, flight.len);
            try client.provide(gpa, .handshake, flight[offset..end]);
            offset = end;
        }
        try testing.expect(client.isComplete());
    }
}

test "client: alerts map onto CRYPTO_ERROR codes" {
    // §4.8: 0x0100 plus the alert. The connection layer sends these without
    // needing to know TLS's numbering.
    try testing.expectEqual(@as(u64, 0x0100 + 120), cryptoError(error.NoApplicationProtocol));
    try testing.expectEqual(@as(u64, 0x0100 + 51), cryptoError(error.FinishedMismatch));
    try testing.expectEqual(@as(u64, 0x0100 + 70), cryptoError(error.UnsupportedVersion));
    try testing.expectEqual(@as(u64, 0x0100 + 10), cryptoError(error.UnexpectedMessage));
    // Anything unrecognised still produces a legal code rather than a panic.
    try testing.expectEqual(@as(u64, 0x0100 + 80), cryptoError(error.OutOfMemory));
}

/// A server side sufficient to exercise the client, driving the same `Schedule`
/// from the other direction.
///
/// Not a QUIC server: it has no packets, no flow control and no certificate. Its
/// only job is to be a second implementation of the *transcript*, so that a
/// direction mix-up or an ordering error cannot pass unnoticed.
/// The other side of the handshake, for tests.
///
/// Not a QUIC server: it speaks no packets and owns no sockets. It is a *second
/// implementation of the transcript*, driving the same `tls.Schedule` from the
/// opposite side, which is what makes "both ends agree" a real assertion rather
/// than a tautology about one code path. `connection.zig` reuses it to complete a
/// handshake over genuine datagrams.
pub const TestServer = struct {
    private_key: [handshake.X25519.secret_length]u8,
    public_key: [handshake.X25519.public_length]u8,
    schedule: ?tls.Schedule = null,
    handshake_secrets: ?tls.Pair = null,
    application_secrets: ?tls.Pair = null,

    /// The peer's public key, copied out of its certificate. A copy rather than a
    /// borrow because Certificate and CertificateVerify are two messages and the
    /// buffer holding the first is consumed before the second arrives.
    peer_public_key: [verify.max_public_key_len]u8 = @splat(0),
    peer_public_key_len: u16 = 0,
    peer_algorithm: std.crypto.Certificate.AlgorithmCategory = .rsaEncryption,
    hello_buf: [256]u8 = undefined,

    pub fn init(seed_byte: u8) TestServer {
        const seed: [32]u8 = @splat(seed_byte);
        const pair = handshake.X25519.KeyPair.generateDeterministic(seed) catch unreachable;
        return .{ .private_key = pair.secret_key, .public_key = pair.public_key };
    }

    pub fn writeServerHello(self: *TestServer, client_hello: []const u8) []const u8 {
        var builder: handshake.Builder = .init(&self.hello_buf);
        builder.byte(@backingInt(tls.MessageType.server_hello));
        const message = builder.begin24();
        builder.int16(handshake.tls_1_2_legacy);
        const random: [handshake.random_len]u8 = @splat(0x5a);
        builder.bytes(&random);
        builder.byte(0); // §8.4: empty session id
        builder.int16(@backingInt(handshake.CipherSuite.aes_128_gcm_sha256));
        builder.byte(0);
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
        const hello = builder.written();

        // The client's public key is in its ClientHello; pull it out the same way
        // a server would, so the fixture cannot cheat by being handed it.
        const client_message = (tls.nextMessage(client_hello) catch unreachable).?;
        const client_share = extractClientShare(client_message.body) catch unreachable;
        const shared = handshake.X25519.scalarmult(self.private_key, client_share) catch unreachable;

        self.schedule = .init(.aes_128_gcm_sha256);
        self.schedule.?.addMessage(client_hello);
        self.schedule.?.addMessage(hello);
        self.handshake_secrets = self.schedule.?.setSharedSecret(&shared);
        return hello;
    }

    fn extractClientShare(body: []const u8) !([handshake.X25519.public_length]u8) {
        var reader: handshake.Reader = .init(body);
        _ = try reader.int16();
        _ = try reader.take(handshake.random_len);
        _ = try reader.blockByte();
        _ = try reader.block16();
        _ = try reader.take(2);
        var iterator: handshake.ExtensionIterator = .{ .reader = .init(try reader.block16()) };
        while (try iterator.next()) |extension| {
            if (extension.type != .key_share) continue;
            var inner: handshake.Reader = .init(extension.body);
            var shares: handshake.Reader = .init(try inner.block16());
            _ = try shares.int16();
            const share = try shares.block16();
            return share[0..handshake.X25519.public_length].*;
        }
        return error.MissingExtension;
    }

    /// EncryptedExtensions and Finished, in one flight.
    pub fn writeFlight(
        self: *TestServer,
        dest: []u8,
        alpn: []const u8,
        transport_parameters: []const u8,
    ) []const u8 {
        var builder: handshake.Builder = .init(dest);

        builder.byte(@backingInt(tls.MessageType.encrypted_extensions));
        const ee = builder.begin24();
        {
            const extensions = builder.begin16();
            {
                const ext = builder.beginExtension(.alpn);
                const list = builder.begin16();
                const entry = builder.beginByte();
                builder.bytes(alpn);
                builder.end(entry);
                builder.end(list);
                builder.end(ext);
            }
            {
                const ext = builder.beginExtension(.quic_transport_parameters);
                builder.bytes(transport_parameters);
                builder.end(ext);
            }
            builder.end(extensions);
        }
        builder.end(ee);
        const ee_end = builder.len;
        self.schedule.?.addMessage(dest[0..ee_end]);

        const verify_data = self.schedule.?.finishedVerifyData(
            self.handshake_secrets.?.server.slice(),
        );
        builder.byte(@backingInt(tls.MessageType.finished));
        const fin = builder.begin24();
        builder.bytes(verify_data.slice());
        builder.end(fin);
        const finished = dest[ee_end..builder.len];

        // Same ordering the client must follow: the Finished joins the
        // transcript, then the application secrets come from it.
        self.schedule.?.addMessage(finished);
        self.application_secrets = self.schedule.?.applicationSecrets();
        return builder.written();
    }

    pub fn verifyClientFinished(self: *TestServer, verify_data: []const u8) !void {
        try self.schedule.?.verifyFinished(
            self.handshake_secrets.?.client.slice(),
            verify_data,
        );
    }
};

test "client: with verification configured, a server that sends no certificate fails" {
    // The other half of the switch above. A server skipping its certificate has
    // proved nothing, so a client that asked for verification must refuse — even
    // though the transcript and the Finished would otherwise line up perfectly.
    const gpa = testing.allocator;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);

    var client = try Client.init(.{
        .host = "example.com",
        .alpn = &.{"h3"},
        .transport_parameters = &.{0},
        .verification = .{ .bundle = &bundle, .host = "example.com", .now_sec = 1_700_000_000 },
    }, @splat(0x1f));
    defer client.deinit(gpa);
    try client.start(gpa);

    var server = TestServer.init(0x2f);
    try client.provide(gpa, .initial, server.writeServerHello(client.output(.initial)));

    var flight_buf: [512]u8 = undefined;
    const flight = server.writeFlight(&flight_buf, "h3", &.{0x01});
    try testing.expectError(error.UnexpectedMessage, client.provide(gpa, .handshake, flight));
    try testing.expect(!client.isComplete());
    try testing.expectEqual(State.failed, client.state);
}
