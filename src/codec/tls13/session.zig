//! A TLS 1.3 client session over TCP: the QUIC handshake engine plus the
//! record layer, sans-io.
//!
//! Bytes from the socket go into `receive`; bytes for the socket come out of
//! `output`/`consumeOutput`; decrypted application data waits in
//! `appData`/`consumeAppData`. Nothing here reads a socket or a clock, which
//! is what makes the whole handshake testable against a second implementation
//! in-process — and against OpenSSL once a socket is bolted on.
//!
//! The level mapping is the part worth writing down. The engine speaks QUIC's
//! three encryption levels; on TCP those correspond to how each record is
//! protected:
//!
//! - `initial`   = plaintext handshake records (ClientHello, ServerHello)
//! - `handshake` = records under the handshake traffic keys (EE..Finished)
//! - `one_rtt`   = records under the application traffic keys
//!
//! Which keys decrypt an inbound record is never guessed: TLS over TCP is
//! strictly sequential, so the reader holds handshake keys until the server's
//! Finished has been consumed and application keys after, and a record
//! protected with the wrong generation simply fails to open — which §5.2 makes
//! fatal anyway.
//!
//! Post-handshake messages are handled here rather than in the engine, because
//! they are where TCP and QUIC genuinely differ: NewSessionTicket is ignored
//! (no session resumption), and KeyUpdate — which RFC 9001 §6 *forbids* on
//! QUIC — is answered as §4.6.3 requires.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const record = @import("record.zig");
const engine = @import("../quic/client.zig");
const tls = @import("../quic/tls.zig");
const handshake = @import("../quic/handshake.zig");
const verify = @import("../quic/verify.zig");
const server_engine = @import("../quic/server.zig");
const identity_mod = @import("identity.zig");
const quic_crypto = @import("../quic/crypto.zig");

pub const Error = error{
    /// The peer sent a fatal alert; `close_alert` holds it.
    AlertReceived,
    /// The session is not in a state where the operation makes sense.
    SessionClosed,
    HandshakeIncomplete,
    /// More decrypted application data than `max_buffered_plaintext` waiting
    /// for the caller. Consume before receiving more.
    PlaintextBufferFull,
    /// A post-handshake handshake message violated the protocol.
    UnexpectedMessage,
    /// §5: a record arrived in the clear that §4.4.4 requires to be protected, or a
    /// change_cipher_spec that is not the single byte 0x01, or one outside the window
    /// §5 permits it in. The peer gets an unexpected_message alert.
    UnexpectedRecord,
} || record.Error || Allocator.Error;

pub const Options = struct {
    /// Sent as SNI and checked against the certificate.
    host: []const u8,
    /// ALPN protocols, most preferred first. Empty offers none, which plain
    /// HTTPS clients routinely do; "h2" is how HTTP/2 over TLS is reached.
    alpn: []const []const u8 = &.{},
    /// Null skips certificate validation — a decision, not a default.
    verification: ?verify.Options,
    /// Decrypted application data the caller has not consumed yet. Receiving
    /// past it is an error, which makes the bound the caller's read pace.
    max_buffered_plaintext: usize = 64 * 1024,
};

pub const State = enum {
    handshaking,
    established,
    /// close_notify received; no more application data will arrive.
    peer_closed,
    /// close_notify sent; `output` still holds it until drained.
    closed,
    failed,
};

/// §6.1: a close_notify ends the peer's data but is not a failure; anything
/// else fatal is. One implementation for both roles, because getting it wrong
/// in one direction means a clean shutdown looks like an error to exactly half
/// the connections.
/// §5's rules for a plaintext record, which are the same for both roles and therefore
/// live in one place.
///
/// `keyed` is whether read keys have been installed, and `complete` whether the peer's
/// Finished has been processed. Both matter:
///
///   * A plaintext **alert** is legitimate only while no read key exists. Before that it
///     is how a peer refuses a Hello; after it, §4.4.4 requires every record to be
///     protected, and an unprotected one is unauthenticated — acting on it lets anyone who
///     can inject a segment terminate the connection, or truncate it with a forged
///     close_notify, which is what §6.1's close handshake exists to prevent.
///   * A plaintext **change_cipher_spec** is compatibility theatre (§D.4), but §5 still
///     bounds it: it must consist of "the single byte value 0x01", and it may appear only
///     "after the first ClientHello message has been sent or received and before the peer's
///     Finished message has been received". Any other value, and any CCS outside that
///     window, "MUST be treated as an unexpected record type". Skipping the record without
///     reading it accepts arbitrary bytes under a content type nobody parses.
const PlaintextVerdict = enum { accept, drop, refuse };

fn plaintextVerdict(
    content_type: record.ContentType,
    body: []const u8,
    keyed: bool,
    complete: bool,
) PlaintextVerdict {
    return switch (content_type) {
        .change_cipher_spec => blk: {
            if (complete) break :blk .refuse;
            if (body.len != 1 or body[0] != 0x01) break :blk .refuse;
            break :blk .drop;
        },
        .alert => if (keyed) .refuse else .accept,
        .handshake => .accept,
        // A protected record: this function judges what may appear *in the clear*, and the
        // caller's own branch decides what to do with the ciphertext.
        .application_data => .accept,
        // The framer already rejects unknown outer content types, so this is unreachable
        // in practice — but a pure function that answers for every input is testable, and
        // `unreachable` here would be a promise about a different file's behaviour.
        _ => .refuse,
    };
}

fn handleAlertInto(state: *State, close_alert: *?record.Alert, alert: record.Alert) Error!void {
    close_alert.* = alert;
    if (alert.description == record.Alert.close_notify) {
        state.* = .peer_closed;
        return;
    }
    state.* = .failed;
    return error.AlertReceived;
}

/// Fragment `content` into protected records and append them to `out`.
///
/// One implementation for both directions on purpose: the loop's exit
/// condition is the subtle part. It sits at the bottom so that zero-length
/// application data still produces exactly one record — an earlier
/// `while (offset <= content.len)` emitted a trailing empty record for every
/// non-empty payload, which consumed a sequence number and made every
/// subsequent record fail to decrypt.
fn sealRecords(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    keys: *record.Keys,
    content_type: record.ContentType,
    content: []const u8,
) Error!void {
    var offset: usize = 0;
    while (true) {
        const chunk = @min(content.len - offset, record.max_plaintext_len);
        const record_len = record.header_len + chunk + 1 + record.tag_len;
        const dest = try out.addManyAsSlice(gpa, record_len);
        const n = try keys.seal(dest, content_type, content[offset..][0..chunk], 0);
        assert(n == record_len);
        offset += chunk;
        if (offset >= content.len) break;
    }
}

pub const ClientSession = struct {
    client: engine.Client,
    options: Options,
    state: State = .handshaking,

    parser: record.Parser = .{},
    /// Read direction: null until the ServerHello yields handshake secrets.
    read_keys: ?record.Keys = null,
    write_keys: ?record.Keys = null,
    /// True once the server Finished has been consumed: the *next* inbound
    /// protected record is under the application keys.
    read_at_application: bool = false,

    /// Records ready for the socket.
    to_send: std.ArrayList(u8) = .empty,
    /// Decrypted application data ready for the caller. Bounded by
    /// `options.max_buffered_plaintext`.
    plaintext: std.ArrayList(u8) = .empty,
    /// Post-handshake handshake messages can span records; reassembled here,
    /// bounded by the same limit the engine uses per message.
    post_handshake: std.ArrayList(u8) = .empty,

    /// The alert that ended the session, if one did.
    close_alert: ?record.Alert = null,

    scratch: [record.max_ciphertext_len]u8 = undefined,

    pub fn init(options: Options, seed: [64]u8) !ClientSession {
        const client: engine.Client = try .init(.{
            .host = options.host,
            .alpn = options.alpn,
            .transport_parameters = null,
            .requirements = .tcp,
            .verification = options.verification,
        }, seed);
        return .{ .client = client, .options = options };
    }

    pub fn deinit(self: *ClientSession, gpa: Allocator) void {
        self.client.deinit(gpa);
        self.to_send.deinit(gpa);
        self.plaintext.deinit(gpa);
        self.post_handshake.deinit(gpa);
        self.* = undefined;
    }

    /// Build the ClientHello. Its record is in `output` afterwards.
    pub fn start(self: *ClientSession, gpa: Allocator) !void {
        try self.client.start(gpa);
        try self.flushEngineOutput(gpa);
    }

    /// Feed bytes from the socket. Records are framed, decrypted and handled;
    /// handshake progress lands in `output`, application data in `appData`.
    pub fn receive(self: *ClientSession, gpa: Allocator, bytes: []const u8) !void {
        if (self.state == .failed) return error.SessionClosed;
        var remaining = bytes;
        while (remaining.len > 0) {
            const result = self.parser.next(remaining) catch |err| {
                self.state = .failed;
                return err;
            };
            const framed = result orelse return;
            remaining = remaining[framed.consumed..];
            self.handleRecord(gpa, &framed.record) catch |err| {
                if (self.state != .peer_closed) self.state = .failed;
                return err;
            };
        }
    }

    fn handleRecord(self: *ClientSession, gpa: Allocator, rec: *const record.Record) !void {
        switch (plaintextVerdict(
            rec.content_type,
            rec.body(),
            self.read_keys != null,
            self.client.isComplete(),
        )) {
            .drop => return,
            .refuse => return error.UnexpectedRecord,
            .accept => {},
        }
        switch (rec.content_type) {
            .change_cipher_spec => unreachable, // dropped or refused above
            .alert => return self.handleAlert(try record.Alert.decode(rec.body())),
            .handshake => {
                // Plaintext handshake: only legitimate before handshake keys
                // exist (ServerHello, HelloRetryRequest).
                try self.client.provide(gpa, .initial, rec.body());
                try self.afterEngineProgress(gpa);
            },
            .application_data => {
                const keys = if (self.read_keys) |*keys| keys else {
                    // Protected bytes before any key exists cannot be real.
                    return error.BadRecord;
                };
                const opened = try keys.open(&self.scratch, rec.bytes);
                const content = self.scratch[0..opened.len];
                switch (opened.content_type) {
                    .alert => return self.handleAlert(try record.Alert.decode(content)),
                    .handshake => {
                        if (self.client.isComplete()) {
                            try self.handlePostHandshake(gpa, content);
                        } else {
                            try self.client.provide(gpa, .handshake, content);
                            try self.afterEngineProgress(gpa);
                        }
                    },
                    .application_data => {
                        if (!self.client.isComplete()) return error.BadRecord;
                        if (self.plaintext.items.len + content.len > self.options.max_buffered_plaintext) {
                            return error.PlaintextBufferFull;
                        }
                        try self.plaintext.appendSlice(gpa, content);
                    },
                    .change_cipher_spec => return error.BadRecord,
                    _ => return error.BadRecord,
                }
            },
            _ => unreachable, // The framer rejected it already.
        }
    }

    /// After the engine consumed messages: pick up any new secrets, then any
    /// new outbound flight, in that order — the client Finished must leave
    /// under the handshake keys that the same progress step produced.
    fn afterEngineProgress(self: *ClientSession, gpa: Allocator) !void {
        if (self.read_keys == null) {
            if (self.client.secrets(.handshake)) |secrets| {
                const suite = self.client.suite().?;
                self.read_keys = .fromTrafficSecret(suite, secrets.server.slice());
                self.write_keys = .fromTrafficSecret(suite, secrets.client.slice());
            }
        }
        try self.flushEngineOutput(gpa);
        if (self.client.isComplete() and !self.read_at_application) {
            // The engine has consumed the server Finished and emitted ours;
            // both directions switch generations. §5.3: sequences restart.
            const suite = self.client.suite().?;
            const secrets = self.client.secrets(.one_rtt).?;
            self.read_keys = .fromTrafficSecret(suite, secrets.server.slice());
            self.write_keys = .fromTrafficSecret(suite, secrets.client.slice());
            self.read_at_application = true;
            self.state = .established;
        }
    }

    fn flushEngineOutput(self: *ClientSession, gpa: Allocator) !void {
        // Initial-level output is plaintext records.
        const initial = self.client.output(.initial);
        if (initial.len > 0) {
            var offset: usize = 0;
            while (offset < initial.len) {
                const chunk = @min(initial.len - offset, record.max_plaintext_len);
                const dest = try self.to_send.addManyAsSlice(gpa, record.header_len + chunk);
                _ = try record.writePlaintextRecord(dest, .handshake, initial[offset..][0..chunk]);
                offset += chunk;
            }
            self.client.consumeOutput(gpa, .initial, initial.len);
        }
        // Handshake-level output (the client Finished) is protected.
        const hs = self.client.output(.handshake);
        if (hs.len > 0) {
            try self.sealInto(gpa, .handshake, hs);
            self.client.consumeOutput(gpa, .handshake, hs.len);
        }
    }

    fn sealInto(
        self: *ClientSession,
        gpa: Allocator,
        content_type: record.ContentType,
        content: []const u8,
    ) Error!void {
        return sealRecords(gpa, &self.to_send, &self.write_keys.?, content_type, content);
    }

    fn handleAlert(self: *ClientSession, alert: record.Alert) Error!void {
        return handleAlertInto(&self.state, &self.close_alert, alert);
    }

    /// §4.6: NewSessionTicket is ignored (no resumption here); KeyUpdate
    /// rotates the read keys and, when the peer requests it, answers with our
    /// own update before rotating the write keys.
    fn handlePostHandshake(self: *ClientSession, gpa: Allocator, content: []const u8) Error!void {
        if (self.post_handshake.items.len + content.len >
            tls.max_message_len + tls.message_header_len)
        {
            return error.UnexpectedMessage;
        }
        try self.post_handshake.appendSlice(gpa, content);
        while (true) {
            const message = tls.nextMessage(self.post_handshake.items) catch {
                return error.UnexpectedMessage;
            } orelse return;
            const consumed = message.raw.len;
            switch (message.type) {
                .new_session_ticket => {},
                .key_update => {
                    if (message.body.len != 1) return error.UnexpectedMessage;
                    const request = message.body[0];
                    if (request > 1) return error.UnexpectedMessage;
                    // §4.6.3: the sender's next records use its next keys, so
                    // our read direction rotates now.
                    self.read_keys = self.read_keys.?.update();
                    if (request == 1) {
                        // update_requested: answer under the *current* write
                        // keys, then rotate. The other order encrypts the
                        // announcement with keys the peer was never told about.
                        const reply = [_]u8{ @backingInt(tls.MessageType.key_update), 0, 0, 1, 0 };
                        try self.sealInto(gpa, .handshake, &reply);
                        self.write_keys = self.write_keys.?.update();
                    }
                },
                else => return error.UnexpectedMessage,
            }
            self.post_handshake.replaceRangeAssumeCapacity(0, consumed, &.{});
        }
    }

    /// Encrypt application data toward the peer. Records land in `output`.
    pub fn write(self: *ClientSession, gpa: Allocator, bytes: []const u8) Error!void {
        if (self.state != .established and self.state != .peer_closed) {
            return if (self.state == .handshaking) error.HandshakeIncomplete else error.SessionClosed;
        }
        try self.sealInto(gpa, .application_data, bytes);
    }

    /// Send close_notify. The record still has to be drained from `output`.
    pub fn close(self: *ClientSession, gpa: Allocator) Error!void {
        if (self.state == .closed or self.state == .failed) return;
        const was_established = self.state == .established or self.state == .peer_closed;
        if (was_established) {
            const alert: record.Alert = .{
                .level = record.Alert.warning,
                .description = record.Alert.close_notify,
            };
            try self.sealInto(gpa, .alert, &alert.encode());
        }
        self.state = .closed;
    }

    /// Bytes waiting for the socket.
    pub fn output(self: *const ClientSession) []const u8 {
        return self.to_send.items;
    }

    pub fn consumeOutput(self: *ClientSession, n: usize) void {
        assert(n <= self.to_send.items.len);
        self.to_send.replaceRangeAssumeCapacity(0, n, &.{});
    }

    /// Decrypted application data waiting for the caller.
    pub fn appData(self: *const ClientSession) []const u8 {
        return self.plaintext.items;
    }

    pub fn consumeAppData(self: *ClientSession, n: usize) void {
        assert(n <= self.plaintext.items.len);
        self.plaintext.replaceRangeAssumeCapacity(0, n, &.{});
    }

    pub fn isEstablished(self: *const ClientSession) bool {
        return self.state == .established or self.state == .peer_closed;
    }

    pub fn negotiatedAlpn(self: *const ClientSession) []const u8 {
        return self.client.alpn();
    }
};

pub const ServerOptions = struct {
    /// Certificate chain and signing key. Borrowed; must outlive the session.
    identity: *const identity_mod.Identity,
    /// Protocols we speak, most preferred first. The choice is made in this
    /// order (RFC 7301 §3.2).
    alpn: []const []const u8 = &.{},
    /// Whether failing to agree on ALPN ends the handshake. False is the
    /// ordinary HTTPS server: a client that offers nothing we know still gets
    /// served.
    require_alpn: bool = false,
    max_buffered_plaintext: usize = 64 * 1024,
};

/// The server side of a TLS 1.3 connection, sans-io.
///
/// The asymmetry with `ClientSession` is the part to be careful about, and it
/// is not symmetric by accident: **the server's write keys advance one step
/// ahead of its read keys.** After its own Finished the server may encrypt
/// application data (§4.4.4 permits it, and 0.5-RTT data is exactly that),
/// while its read keys stay at the handshake generation until the client's
/// Finished arrives. Keeping one `read_at_application` flag per direction is
/// what stops the read path from switching early and failing to decrypt the
/// one message that completes the handshake.
pub const ServerSession = struct {
    /// The other end, for tests that need to drive a handshake by hand.
    pub const ClientPeer = ClientSession;

    server: server_engine.Server,
    options: ServerOptions,
    state: State = .handshaking,

    parser: record.Parser = .{},
    read_keys: ?record.Keys = null,
    write_keys: ?record.Keys = null,
    /// True once the client's Finished has been consumed and the read
    /// direction has moved to the application keys.
    read_at_application: bool = false,

    to_send: std.ArrayList(u8) = .empty,
    plaintext: std.ArrayList(u8) = .empty,
    post_handshake: std.ArrayList(u8) = .empty,

    close_alert: ?record.Alert = null,
    scratch: [record.max_ciphertext_len]u8 = undefined,

    pub fn init(options: ServerOptions, seed: [64]u8) !ServerSession {
        const built: server_engine.Server = try .init(.{
            .identity = options.identity,
            .alpn = options.alpn,
            .transport_parameters = null,
            .require_alpn = options.require_alpn,
        }, seed);
        return .{ .server = built, .options = options };
    }

    pub fn deinit(self: *ServerSession, gpa: Allocator) void {
        self.server.deinit(gpa);
        self.to_send.deinit(gpa);
        self.plaintext.deinit(gpa);
        self.post_handshake.deinit(gpa);
        self.* = undefined;
    }

    /// Feed bytes from the socket. A server has nothing to send until it has
    /// heard a ClientHello, so there is no `start`.
    pub fn receive(self: *ServerSession, gpa: Allocator, bytes: []const u8) !void {
        if (self.state == .failed) return error.SessionClosed;
        var remaining = bytes;
        while (remaining.len > 0) {
            const result = self.parser.next(remaining) catch |err| {
                self.state = .failed;
                return err;
            };
            const framed = result orelse return;
            remaining = remaining[framed.consumed..];
            self.handleRecord(gpa, &framed.record) catch |err| {
                if (self.state != .peer_closed) self.state = .failed;
                return err;
            };
        }
    }

    fn handleRecord(self: *ServerSession, gpa: Allocator, rec: *const record.Record) !void {
        switch (plaintextVerdict(
            rec.content_type,
            rec.body(),
            self.read_keys != null,
            self.server.isComplete(),
        )) {
            .drop => return,
            .refuse => return error.UnexpectedRecord,
            .accept => {},
        }
        switch (rec.content_type) {
            .change_cipher_spec => unreachable, // dropped or refused above
            .alert => return handleAlertInto(&self.state, &self.close_alert, try record.Alert.decode(rec.body())),
            .handshake => {
                // Plaintext handshake: the ClientHello, and nothing else.
                try self.server.provide(gpa, .initial, rec.body());
                try self.afterEngineProgress(gpa);
            },
            .application_data => {
                const keys = if (self.read_keys) |*keys| keys else return error.BadRecord;
                const opened = try keys.open(&self.scratch, rec.bytes);
                const content = self.scratch[0..opened.len];
                switch (opened.content_type) {
                    .alert => return handleAlertInto(&self.state, &self.close_alert, try record.Alert.decode(content)),
                    .handshake => {
                        if (self.server.isComplete()) {
                            try self.handlePostHandshake(gpa, content);
                        } else {
                            try self.server.provide(gpa, .handshake, content);
                            try self.afterEngineProgress(gpa);
                        }
                    },
                    .application_data => {
                        if (!self.server.isComplete()) return error.BadRecord;
                        if (self.plaintext.items.len + content.len > self.options.max_buffered_plaintext) {
                            return error.PlaintextBufferFull;
                        }
                        try self.plaintext.appendSlice(gpa, content);
                    },
                    .change_cipher_spec => return error.BadRecord,
                    _ => return error.BadRecord,
                }
            },
            _ => unreachable, // The framer rejected it already.
        }
    }

    fn afterEngineProgress(self: *ServerSession, gpa: Allocator) !void {
        const first_flight = self.write_keys == null and self.server.secrets(.handshake) != null;
        if (first_flight) {
            const suite = self.server.suite().?;
            const secrets = self.server.secrets(.handshake).?;
            // Reversed from the client: we write with the server secret and
            // read with the client's.
            self.write_keys = .fromTrafficSecret(suite, secrets.server.slice());
            self.read_keys = .fromTrafficSecret(suite, secrets.client.slice());
        }

        // ServerHello goes out in the clear; it is what the handshake keys are
        // derived from.
        const initial = self.server.output(.initial);
        if (initial.len > 0) {
            var offset: usize = 0;
            while (offset < initial.len) {
                const chunk = @min(initial.len - offset, record.max_plaintext_len);
                const dest = try self.to_send.addManyAsSlice(gpa, record.header_len + chunk);
                _ = try record.writePlaintextRecord(dest, .handshake, initial[offset..][0..chunk]);
                offset += chunk;
            }
            self.server.consumeOutput(gpa, .initial, initial.len);
            // §D.4: a client that sent a non-empty legacy_session_id is in
            // compatibility mode and expects this record between the
            // ServerHello and the encrypted flight. Harmless to any other
            // client, since §5 makes it ignorable.
            if (self.server.session_id_len > 0) {
                try self.to_send.appendSlice(gpa, &record.change_cipher_spec_record);
            }
        }

        // The flight (EE, Certificate, CertificateVerify, Finished) under the
        // handshake write keys.
        const hs = self.server.output(.handshake);
        if (hs.len > 0) {
            try sealRecords(gpa, &self.to_send, &self.write_keys.?, .handshake, hs);
            self.server.consumeOutput(gpa, .handshake, hs.len);
            // Our Finished is out, so our *write* direction moves to the
            // application keys now — before the client's Finished has been
            // seen. The read direction deliberately does not.
            const suite = self.server.suite().?;
            const secrets = self.server.secrets(.one_rtt).?;
            self.write_keys = .fromTrafficSecret(suite, secrets.server.slice());
        }

        if (self.server.isComplete() and !self.read_at_application) {
            const suite = self.server.suite().?;
            const secrets = self.server.secrets(.one_rtt).?;
            self.read_keys = .fromTrafficSecret(suite, secrets.client.slice());
            self.read_at_application = true;
            self.state = .established;
        }
    }

    /// §4.6.3: a client KeyUpdate rotates our read keys, and an
    /// update_requested is answered under the *current* write keys before
    /// rotating them.
    fn handlePostHandshake(self: *ServerSession, gpa: Allocator, content: []const u8) !void {
        if (self.post_handshake.items.len + content.len >
            tls.max_message_len + tls.message_header_len)
        {
            return error.UnexpectedMessage;
        }
        try self.post_handshake.appendSlice(gpa, content);
        while (true) {
            const message = tls.nextMessage(self.post_handshake.items) catch {
                return error.UnexpectedMessage;
            } orelse return;
            const consumed = message.raw.len;
            switch (message.type) {
                .key_update => {
                    if (message.body.len != 1) return error.UnexpectedMessage;
                    const request = message.body[0];
                    if (request > 1) return error.UnexpectedMessage;
                    self.read_keys = self.read_keys.?.update();
                    if (request == 1) {
                        const reply = [_]u8{ @backingInt(tls.MessageType.key_update), 0, 0, 1, 0 };
                        try sealRecords(gpa, &self.to_send, &self.write_keys.?, .handshake, &reply);
                        self.write_keys = self.write_keys.?.update();
                    }
                },
                // A server never asked for client authentication, so a
                // Certificate here is a client inventing a conversation.
                else => return error.UnexpectedMessage,
            }
            self.post_handshake.replaceRangeAssumeCapacity(0, consumed, &.{});
        }
    }

    pub fn write(self: *ServerSession, gpa: Allocator, bytes: []const u8) Error!void {
        if (self.state != .established and self.state != .peer_closed) {
            return if (self.state == .handshaking) error.HandshakeIncomplete else error.SessionClosed;
        }
        return sealRecords(gpa, &self.to_send, &self.write_keys.?, .application_data, bytes);
    }

    pub fn close(self: *ServerSession, gpa: Allocator) Error!void {
        if (self.state == .closed or self.state == .failed) return;
        if (self.state == .established or self.state == .peer_closed) {
            const alert: record.Alert = .{
                .level = record.Alert.warning,
                .description = record.Alert.close_notify,
            };
            try sealRecords(gpa, &self.to_send, &self.write_keys.?, .alert, &alert.encode());
        }
        self.state = .closed;
    }

    pub fn output(self: *const ServerSession) []const u8 {
        return self.to_send.items;
    }

    pub fn consumeOutput(self: *ServerSession, n: usize) void {
        assert(n <= self.to_send.items.len);
        self.to_send.replaceRangeAssumeCapacity(0, n, &.{});
    }

    pub fn appData(self: *const ServerSession) []const u8 {
        return self.plaintext.items;
    }

    pub fn consumeAppData(self: *ServerSession, n: usize) void {
        assert(n <= self.plaintext.items.len);
        self.plaintext.replaceRangeAssumeCapacity(0, n, &.{});
    }

    pub fn isEstablished(self: *const ServerSession) bool {
        return self.state == .established or self.state == .peer_closed;
    }

    pub fn negotiatedAlpn(self: *const ServerSession) []const u8 {
        return self.server.alpn();
    }

    /// The SNI the client sent, for logging or certificate selection.
    pub fn serverName(self: *const ServerSession) []const u8 {
        return self.server.serverName();
    }
};

// --- Tests ----------------------------------------------------------------

const testing = std.testing;

/// The QUIC TestServer speaking TCP: the same second implementation of the
/// handshake, wrapped in records instead of CRYPTO frames.
const RecordServer = struct {
    inner: engine.TestServer,
    read_keys: ?record.Keys = null,
    write_keys: ?record.Keys = null,
    app_read: ?record.Keys = null,
    app_write: ?record.Keys = null,
    scratch: [record.max_ciphertext_len]u8 = undefined,

    fn init(seed_byte: u8) RecordServer {
        return .{ .inner = .init(seed_byte) };
    }

    /// Consume the ClientHello record, reply with ServerHello (plaintext) and
    /// the flight (protected), returning the bytes to feed the client.
    fn respond(self: *RecordServer, dest: []u8, client_output: []const u8, alpn: []const u8) ![]const u8 {
        var parser: record.Parser = .{};
        const framed = (try parser.next(client_output)).?;
        try testing.expectEqual(record.ContentType.handshake, framed.record.content_type);

        const server_hello = self.inner.writeServerHello(framed.record.body());
        var written = try record.writePlaintextRecord(dest, .handshake, server_hello);

        const secrets = self.inner.handshake_secrets.?;
        self.write_keys = .fromTrafficSecret(.aes_128_gcm_sha256, secrets.server.slice());
        self.read_keys = .fromTrafficSecret(.aes_128_gcm_sha256, secrets.client.slice());

        var flight_buf: [4096]u8 = undefined;
        const flight = self.inner.writeFlight(&flight_buf, alpn, &.{ 0x01, 0x00 });
        const app = self.inner.application_secrets.?;
        self.app_write = .fromTrafficSecret(.aes_128_gcm_sha256, app.server.slice());
        self.app_read = .fromTrafficSecret(.aes_128_gcm_sha256, app.client.slice());
        written += try self.write_keys.?.seal(dest[written..], .handshake, flight, 0);
        return dest[0..written];
    }

    /// Verify the client Finished record and step the server to app keys.
    fn finish(self: *RecordServer, client_output: []const u8) !usize {
        var parser: record.Parser = .{};
        const framed = (try parser.next(client_output)).?;
        const opened = try self.read_keys.?.open(&self.scratch, framed.record.bytes);
        try testing.expectEqual(record.ContentType.handshake, opened.content_type);
        const message = (try tls.nextMessage(self.scratch[0..opened.len])).?;
        try testing.expectEqual(tls.MessageType.finished, message.type);
        try self.inner.verifyClientFinished(message.body);
        return framed.consumed;
    }

    fn sealApp(self: *RecordServer, dest: []u8, bytes: []const u8) !usize {
        return self.app_write.?.seal(dest, .application_data, bytes, 0);
    }

    fn openApp(self: *RecordServer, client_output: []const u8) ![]const u8 {
        var parser: record.Parser = .{};
        const framed = (try parser.next(client_output)).?;
        const opened = try self.app_read.?.open(&self.scratch, framed.record.bytes);
        try testing.expectEqual(record.ContentType.application_data, opened.content_type);
        return self.scratch[0..opened.len];
    }
};

fn testSession(alpn: []const []const u8) !ClientSession {
    const seed: [64]u8 = @splat(0x42);
    return ClientSession.init(.{
        .host = "example.test",
        .alpn = alpn,
        .verification = null,
    }, seed);
}

test "session: full handshake against the record-wrapped second implementation" {
    const gpa = testing.allocator;
    var session = try testSession(&.{"h2"});
    defer session.deinit(gpa);
    var server: RecordServer = .init(7);

    try session.start(gpa);
    try testing.expect(!session.isEstablished());

    var reply_buf: [8192]u8 = undefined;
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);

    try session.receive(gpa, reply);
    try testing.expect(session.isEstablished());
    try testing.expectEqualStrings("h2", session.negotiatedAlpn());

    // The client Finished is waiting and verifies against the server's own
    // transcript — the same cross-check the QUIC handshake test makes, here
    // crossing the record layer both ways.
    const consumed = try server.finish(session.output());
    session.consumeOutput(consumed);

    // Application data both directions.
    try session.write(gpa, "GET / HTTP/1.1\r\n\r\n");
    const request = try server.openApp(session.output());
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", request);
    session.consumeOutput(session.output().len);

    var app_buf: [256]u8 = undefined;
    const n = try server.sealApp(&app_buf, "HTTP/1.1 200 OK\r\n\r\n");
    try session.receive(gpa, app_buf[0..n]);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\n", session.appData());
    session.consumeAppData(session.appData().len);
}

test "session: byte-at-a-time delivery reaches the same establishment" {
    const gpa = testing.allocator;
    var session = try testSession(&.{"h2"});
    defer session.deinit(gpa);
    var server: RecordServer = .init(9);

    try session.start(gpa);
    var reply_buf: [8192]u8 = undefined;
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);

    for (reply) |byte| try session.receive(gpa, &.{byte});
    try testing.expect(session.isEstablished());
    _ = try server.finish(session.output());
}

test "session: server key update rotates read keys, requested update answers" {
    const gpa = testing.allocator;
    var session = try testSession(&.{"h2"});
    defer session.deinit(gpa);
    var server: RecordServer = .init(11);

    try session.start(gpa);
    var reply_buf: [8192]u8 = undefined;
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);
    try session.receive(gpa, reply);
    const consumed = try server.finish(session.output());
    session.consumeOutput(consumed);

    // update_requested from the server.
    const key_update = [_]u8{ @backingInt(tls.MessageType.key_update), 0, 0, 1, 1 };
    var rec_buf: [256]u8 = undefined;
    var n = try server.app_write.?.seal(&rec_buf, .handshake, &key_update, 0);
    try session.receive(gpa, rec_buf[0..n]);

    // The client answered with its own KeyUpdate — a *handshake* record —
    // under its *old* keys...
    var answer_parser: record.Parser = .{};
    const answer_framed = (try answer_parser.next(session.output())).?;
    var answer_scratch: [128]u8 = undefined;
    const answer = try server.app_read.?.open(&answer_scratch, answer_framed.record.bytes);
    try testing.expectEqual(record.ContentType.handshake, answer.content_type);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ @backingInt(tls.MessageType.key_update), 0, 0, 1, 0 },
        answer_scratch[0..answer.len],
    );
    session.consumeOutput(session.output().len);

    // ...and both directions now run the next generation.
    server.app_write = server.app_write.?.update();
    server.app_read = server.app_read.?.update();
    n = try server.sealApp(&rec_buf, "next generation");
    try session.receive(gpa, rec_buf[0..n]);
    try testing.expectEqualStrings("next generation", session.appData());
    session.consumeAppData(session.appData().len);
    try session.write(gpa, "still here");
    try testing.expectEqualStrings("still here", try server.openApp(session.output()));
    session.consumeOutput(session.output().len);
}

test "session: new session ticket is ignored and data continues" {
    const gpa = testing.allocator;
    var session = try testSession(&.{"h2"});
    defer session.deinit(gpa);
    var server: RecordServer = .init(13);

    try session.start(gpa);
    var reply_buf: [8192]u8 = undefined;
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);
    try session.receive(gpa, reply);
    const consumed = try server.finish(session.output());
    session.consumeOutput(consumed);

    // A ticket split across two records, then data — order must survive.
    const ticket = [_]u8{ @backingInt(tls.MessageType.new_session_ticket), 0, 0, 6, 0, 0, 0, 30, 0, 0 };
    var rec_buf: [256]u8 = undefined;
    var n = try server.app_write.?.seal(&rec_buf, .handshake, ticket[0..4], 0);
    try session.receive(gpa, rec_buf[0..n]);
    n = try server.app_write.?.seal(&rec_buf, .handshake, ticket[4..], 0);
    try session.receive(gpa, rec_buf[0..n]);
    n = try server.sealApp(&rec_buf, "after ticket");
    try session.receive(gpa, rec_buf[0..n]);
    try testing.expectEqualStrings("after ticket", session.appData());
}

test "session: close_notify both ways, and fatal alerts fail the session" {
    const gpa = testing.allocator;
    var session = try testSession(&.{"h2"});
    defer session.deinit(gpa);
    var server: RecordServer = .init(17);

    try session.start(gpa);
    var reply_buf: [8192]u8 = undefined;
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);
    try session.receive(gpa, reply);
    const consumed = try server.finish(session.output());
    session.consumeOutput(consumed);

    // Peer closes cleanly.
    var rec_buf: [128]u8 = undefined;
    const close_notify: record.Alert = .{ .level = record.Alert.warning, .description = 0 };
    const n = try server.app_write.?.seal(&rec_buf, .alert, &close_notify.encode(), 0);
    try session.receive(gpa, rec_buf[0..n]);
    try testing.expectEqual(State.peer_closed, session.state);

    // Our close goes out as a record the server can read.
    try session.close(gpa);
    var parser: record.Parser = .{};
    const framed = (try parser.next(session.output())).?;
    var scratch: [128]u8 = undefined;
    const opened = try server.app_read.?.open(&scratch, framed.record.bytes);
    try testing.expectEqual(record.ContentType.alert, opened.content_type);
    const alert = try record.Alert.decode(scratch[0..opened.len]);
    try testing.expectEqual(record.Alert.close_notify, alert.description);

    // A fatal alert on a second session is an error, not a close.
    var session2 = try testSession(&.{"h2"});
    defer session2.deinit(gpa);
    var server2: RecordServer = .init(19);
    try session2.start(gpa);
    const reply2 = try server2.respond(&reply_buf, session2.output(), "h2");
    session2.consumeOutput(session2.output().len);
    try session2.receive(gpa, reply2);
    const consumed2 = try server2.finish(session2.output());
    session2.consumeOutput(consumed2);
    const fatal: record.Alert = .{ .level = record.Alert.fatal, .description = 40 };
    const n2 = try server2.app_write.?.seal(&rec_buf, .alert, &fatal.encode(), 0);
    try testing.expectError(error.AlertReceived, session2.receive(gpa, rec_buf[0..n2]));
    try testing.expectEqual(State.failed, session2.state);
    try testing.expectEqual(@as(u8, 40), session2.close_alert.?.description);
}

test "session: no ALPN offered, none required, and writes before completion fail" {
    const gpa = testing.allocator;
    var session = try testSession(&.{});
    defer session.deinit(gpa);
    var server: RecordServer = .init(23);

    try testing.expectError(error.HandshakeIncomplete, session.write(gpa, "early"));

    try session.start(gpa);
    var reply_buf: [8192]u8 = undefined;
    // The TestServer always answers ALPN; answering one the client never
    // offered must fail the handshake rather than be believed.
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);
    try testing.expectError(error.NoApplicationProtocol, session.receive(gpa, reply));
}

test "session: change_cipher_spec is tolerated mid-handshake" {
    const gpa = testing.allocator;
    var session = try testSession(&.{"h2"});
    defer session.deinit(gpa);
    var server: RecordServer = .init(29);

    try session.start(gpa);
    var reply_buf: [8192]u8 = undefined;
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);

    // Splice a CCS between ServerHello and the flight, as a compat-mode
    // server would send it.
    var parser: record.Parser = .{};
    const hello = (try parser.next(reply)).?;
    try session.receive(gpa, reply[0..hello.consumed]);
    try session.receive(gpa, &record.change_cipher_spec_record);
    try session.receive(gpa, reply[hello.consumed..]);
    try testing.expect(session.isEstablished());
}

test "session: plaintext cap refuses data the caller has not consumed" {
    const gpa = testing.allocator;
    const seed: [64]u8 = @splat(0x21);
    var session = try ClientSession.init(.{
        .host = "example.test",
        .alpn = &.{"h2"},
        .verification = null,
        .max_buffered_plaintext = 16,
    }, seed);
    defer session.deinit(gpa);
    var server: RecordServer = .init(31);

    try session.start(gpa);
    var reply_buf: [8192]u8 = undefined;
    const reply = try server.respond(&reply_buf, session.output(), "h2");
    session.consumeOutput(session.output().len);
    try session.receive(gpa, reply);
    _ = try server.finish(session.output());
    session.consumeOutput(session.output().len);

    var rec_buf: [256]u8 = undefined;
    const n = try server.sealApp(&rec_buf, "0123456789abcdef!");
    try testing.expectError(error.PlaintextBufferFull, session.receive(gpa, rec_buf[0..n]));
}

// --- Server tests -----------------------------------------------------------

fn testServerIdentity() identity_mod.Identity {
    // Key from a scalar in code, certificate an opaque blob: the client under
    // test runs with `verification = null`, so the handshake is what is being
    // measured. `identity.zig` covers the loading.
    const scalar: [32]u8 = .{
        0x0d, 0x2c, 0x1f, 0x37, 0x4b, 0x59, 0x66, 0x71, 0x8a, 0x93, 0xa5, 0xb2, 0xc4, 0xd1, 0xe8, 0xf3,
        0x02, 0x15, 0x24, 0x38, 0x47, 0x51, 0x63, 0x7a, 0x85, 0x9c, 0xab, 0xb7, 0xcd, 0xd9, 0xe4, 0xfb,
    };
    const secret = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(scalar) catch unreachable;
    const key_pair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret) catch unreachable;
    return .{ .certificates = &server_test_certificates, .key = .{ .ecdsa_p256 = key_pair } };
}

const server_test_certificate = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
const server_test_certificates = [_][]const u8{&server_test_certificate};

/// Runs both sessions against each other until neither has anything to say.
fn pump(gpa: Allocator, client: *ClientSession, server: *ServerSession) !void {
    var rounds: usize = 0;
    while (rounds < 8) : (rounds += 1) {
        var moved = false;
        if (client.output().len > 0) {
            const bytes = try gpa.dupe(u8, client.output());
            defer gpa.free(bytes);
            client.consumeOutput(bytes.len);
            try server.receive(gpa, bytes);
            moved = true;
        }
        if (server.output().len > 0) {
            const bytes = try gpa.dupe(u8, server.output());
            defer gpa.free(bytes);
            server.consumeOutput(bytes.len);
            try client.receive(gpa, bytes);
            moved = true;
        }
        if (!moved) return;
    }
    return error.PumpDidNotSettle;
}

test "session: our client and our server complete a handshake over records" {
    const gpa = testing.allocator;
    const identity = testServerIdentity();

    var server = try ServerSession.init(.{
        .identity = &identity,
        .alpn = &.{ "h2", "http/1.1" },
    }, @splat(0x13));
    defer server.deinit(gpa);

    var client = try ClientSession.init(.{
        .host = "example.test",
        .alpn = &.{ "http/1.1", "h2" },
        .verification = null,
    }, @splat(0x14));
    defer client.deinit(gpa);

    try client.start(gpa);
    try pump(gpa, &client, &server);

    try testing.expect(client.isEstablished());
    try testing.expect(server.isEstablished());
    // The server chose in its own order, and both agree on the result.
    try testing.expectEqualStrings("h2", client.negotiatedAlpn());
    try testing.expectEqualStrings("h2", server.negotiatedAlpn());
    try testing.expectEqualStrings("example.test", server.serverName());

    // Application data in both directions.
    try client.write(gpa, "ping");
    try pump(gpa, &client, &server);
    try testing.expectEqualStrings("ping", server.appData());
    server.consumeAppData(server.appData().len);

    try server.write(gpa, "pong");
    try pump(gpa, &client, &server);
    try testing.expectEqualStrings("pong", client.appData());
    client.consumeAppData(client.appData().len);
}

test "session: the server may write before the client's Finished arrives" {
    // §4.4.4's asymmetry: the server's write keys advance at its own Finished,
    // its read keys only at the client's. This is the 0.5-RTT case, and it is
    // the one place where treating the two directions alike would break.
    const gpa = testing.allocator;
    const identity = testServerIdentity();

    var server = try ServerSession.init(.{ .identity = &identity }, @splat(0x15));
    defer server.deinit(gpa);
    var client = try ClientSession.init(.{
        .host = "example.test",
        .verification = null,
    }, @splat(0x16));
    defer client.deinit(gpa);

    try client.start(gpa);
    const hello = try gpa.dupe(u8, client.output());
    defer gpa.free(hello);
    client.consumeOutput(hello.len);
    try server.receive(gpa, hello);

    // The server has sent its flight and is not yet established...
    try testing.expect(!server.isEstablished());
    // ...but it already holds application write keys, which is what makes
    // early data possible. Sending through `write` is refused (the session
    // reports what the state machine says), while the keys themselves exist.
    try testing.expectError(error.HandshakeIncomplete, server.write(gpa, "early"));
    try testing.expect(server.write_keys != null);
    try testing.expect(!server.read_at_application);

    try pump(gpa, &client, &server);
    try testing.expect(server.isEstablished());
    try testing.expect(server.read_at_application);
}

test "session: a compatibility-mode client gets its change_cipher_spec" {
    // A TCP client that sends a 32-byte legacy_session_id is in compatibility
    // mode (§D.4) and expects a CCS record after the ServerHello. Our own
    // client never sends one — RFC 9001 §8.4 forbids it on QUIC — so the
    // hello comes from the engine's builder.
    const gpa = testing.allocator;
    const identity = testServerIdentity();

    // Compatibility mode: ServerHello, then CCS, then the protected flight.
    {
        var server = try ServerSession.init(.{ .identity = &identity }, @splat(0x17));
        defer server.deinit(gpa);
        var hello_buf: [1024]u8 = undefined;
        const hello = server_engine.testClientHello(&hello_buf, &.{}, 32);
        var framed_buf: [1200]u8 = undefined;
        const record_bytes = try record.writePlaintextRecord(&framed_buf, .handshake, hello);
        try server.receive(gpa, framed_buf[0..record_bytes]);

        var parser: record.Parser = .{};
        var offset: usize = 0;
        const first = (try parser.next(server.output())).?;
        try testing.expectEqual(record.ContentType.handshake, first.record.content_type);
        offset += first.consumed;
        const second = (try parser.next(server.output()[offset..])).?;
        try testing.expectEqual(record.ContentType.change_cipher_spec, second.record.content_type);
        offset += second.consumed;
        const third = (try parser.next(server.output()[offset..])).?;
        try testing.expectEqual(record.ContentType.application_data, third.record.content_type);
    }

    // An empty session id means no CCS: the flight follows the ServerHello
    // directly. Emitting one anyway would be legal but would make the record
    // stream differ from what the client's own tests expect.
    {
        var server = try ServerSession.init(.{ .identity = &identity }, @splat(0x18));
        defer server.deinit(gpa);
        var hello_buf: [1024]u8 = undefined;
        const hello = server_engine.testClientHello(&hello_buf, &.{}, 0);
        var framed_buf: [1200]u8 = undefined;
        const record_bytes = try record.writePlaintextRecord(&framed_buf, .handshake, hello);
        try server.receive(gpa, framed_buf[0..record_bytes]);

        var parser: record.Parser = .{};
        const first = (try parser.next(server.output())).?;
        try testing.expectEqual(record.ContentType.handshake, first.record.content_type);
        const second = (try parser.next(server.output()[first.consumed..])).?;
        try testing.expectEqual(record.ContentType.application_data, second.record.content_type);
    }
}

test "session: a client key update is answered and both directions rotate" {
    const gpa = testing.allocator;
    const identity = testServerIdentity();
    var server = try ServerSession.init(.{ .identity = &identity }, @splat(0x1a));
    defer server.deinit(gpa);
    var client = try ClientSession.init(.{
        .host = "example.test",
        .verification = null,
    }, @splat(0x1b));
    defer client.deinit(gpa);

    try client.start(gpa);
    try pump(gpa, &client, &server);
    try testing.expect(server.isEstablished());

    // The client asks the server to update too.
    const key_update = [_]u8{ @backingInt(tls.MessageType.key_update), 0, 0, 1, 1 };
    try sealRecords(gpa, &client.to_send, &client.write_keys.?, .handshake, &key_update);
    client.write_keys = client.write_keys.?.update();
    try pump(gpa, &client, &server);
    // The server's reply is a KeyUpdate of its own, and the client rotated its
    // read keys while handling it — nothing for the test to do by hand, which
    // is the point: both sides moved a generation through their own code.

    // Data still flows both ways under the new generation.
    try server.write(gpa, "after update");
    try pump(gpa, &client, &server);
    try testing.expectEqualStrings("after update", client.appData());
    client.consumeAppData(client.appData().len);
    try client.write(gpa, "and back");
    try pump(gpa, &client, &server);
    try testing.expectEqualStrings("and back", server.appData());
}

test "session: a client offering no shared protocol is served or refused by policy" {
    const gpa = testing.allocator;
    const identity = testServerIdentity();

    // Lenient (the HTTPS default): no agreement, connection proceeds.
    {
        var server = try ServerSession.init(.{
            .identity = &identity,
            .alpn = &.{"h3"},
        }, @splat(0x1c));
        defer server.deinit(gpa);
        var client = try ClientSession.init(.{
            .host = "example.test",
            .alpn = &.{"h2"},
            .verification = null,
        }, @splat(0x1d));
        defer client.deinit(gpa);
        try client.start(gpa);
        try pump(gpa, &client, &server);
        try testing.expect(server.isEstablished());
        try testing.expectEqual(@as(usize, 0), server.negotiatedAlpn().len);
    }

    // Strict: the handshake ends.
    {
        var server = try ServerSession.init(.{
            .identity = &identity,
            .alpn = &.{"h3"},
            .require_alpn = true,
        }, @splat(0x1e));
        defer server.deinit(gpa);
        var client = try ClientSession.init(.{
            .host = "example.test",
            .alpn = &.{"h2"},
            .verification = null,
        }, @splat(0x1f));
        defer client.deinit(gpa);
        try client.start(gpa);
        try testing.expectError(error.NoApplicationProtocol, server.receive(gpa, client.output()));
        try testing.expectEqual(State.failed, server.state);
    }
}

test "session: close_notify from the client is a clean end, not a failure" {
    const gpa = testing.allocator;
    const identity = testServerIdentity();
    var server = try ServerSession.init(.{ .identity = &identity }, @splat(0x20));
    defer server.deinit(gpa);
    var client = try ClientSession.init(.{
        .host = "example.test",
        .verification = null,
    }, @splat(0x21));
    defer client.deinit(gpa);

    try client.start(gpa);
    try pump(gpa, &client, &server);
    try client.close(gpa);
    try pump(gpa, &client, &server);
    try testing.expectEqual(State.peer_closed, server.state);
    try testing.expectEqual(record.Alert.close_notify, server.close_alert.?.description);

    // And the server can still answer in kind.
    try server.close(gpa);
    try testing.expect(server.output().len > 0);
}

test "session: an unauthenticated record is refused once keys exist" {
    // §4.4.4: "Any records following a Finished message MUST be encrypted under the
    // appropriate application traffic key." A plaintext alert arriving after the read keys
    // are installed carries no authentication at all, so acting on it lets anyone who can
    // inject a segment into the TCP stream end the connection — or, with close_notify,
    // truncate it, which is the attack §6.1 exists to prevent. Before any key exists a
    // plaintext alert is the only way a server can refuse a ClientHello, so the window is
    // exactly "no read keys yet".
    const gpa = testing.allocator;

    // The alert this test injects, byte for byte: fatal handshake_failure.
    const fatal_alert = [_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };

    // Before keys: accepted, and it fails the session — which is the point of it.
    {
        var session = try testSession(&.{"h2"});
        defer session.deinit(gpa);
        try session.start(gpa);
        try testing.expectError(error.AlertReceived, session.receive(gpa, &fatal_alert));
    }

    // After the ServerHello has installed handshake read keys: refused as a record that
    // has no business being in the clear.
    {
        var session = try testSession(&.{"h2"});
        defer session.deinit(gpa);
        var server: RecordServer = .init(31);
        try session.start(gpa);
        var reply_buf: [8192]u8 = undefined;
        const reply = try server.respond(&reply_buf, session.output(), "h2");
        session.consumeOutput(session.output().len);

        var parser: record.Parser = .{};
        const hello = (try parser.next(reply)).?;
        try session.receive(gpa, reply[0..hello.consumed]);
        try testing.expect(session.read_keys != null);

        try testing.expectError(error.UnexpectedRecord, session.receive(gpa, &fatal_alert));
    }
}

test "session: change_cipher_spec is checked, not merely skipped" {
    // §5: an implementation "may receive an unencrypted record of type change_cipher_spec
    // consisting of the single byte value 0x01" within a window, and "which receives any
    // other change_cipher_spec value ... MUST abort the handshake with an
    // unexpected_message alert". Dropping the record without reading it accepts a
    // arbitrary-length payload under a content type nobody parses, which is a hole a
    // middlebox or an attacker can push bytes through unexamined.
    const gpa = testing.allocator;

    const Case = struct { name: []const u8, record: []const u8, want: anyerror };
    const bad = [_]Case{
        // The right length, the wrong value.
        .{
            .name = "value 0x00",
            .record = &[_]u8{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x00 },
            .want = error.UnexpectedRecord,
        },
        // Two bytes, the first of them correct — which is what a check on only the first
        // byte would accept.
        .{
            .name = "0x01 plus a passenger",
            .record = &[_]u8{ 0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0xff },
            .want = error.UnexpectedRecord,
        },
        // Empty: refused by the framer before this rule is reached, under §5.1's ban on
        // zero-length fragments. A different rule with the same consequence here, so the
        // expectation records the error that actually arrives rather than pretending this
        // check is what caught it.
        .{
            .name = "empty",
            .record = &[_]u8{ 0x14, 0x03, 0x03, 0x00, 0x00 },
            .want = error.BadRecord,
        },
    };

    for (bad) |case| {
        var session = try testSession(&.{"h2"});
        defer session.deinit(gpa);
        try session.start(gpa);
        session.consumeOutput(session.output().len);
        testing.expectError(case.want, session.receive(gpa, case.record)) catch |err| {
            std.debug.print("case: {s}\n", .{case.name});
            return err;
        };
    }

    // And after the handshake completes the window has closed: §5 says a CCS "received
    // ... after the peer's Finished message ... MUST be treated as an unexpected record
    // type", so compatibility theatre stops being tolerated once there is nothing left to
    // be compatible about.
    {
        var session = try testSession(&.{"h2"});
        defer session.deinit(gpa);
        var server: RecordServer = .init(32);
        try session.start(gpa);
        var reply_buf: [8192]u8 = undefined;
        const reply = try server.respond(&reply_buf, session.output(), "h2");
        session.consumeOutput(session.output().len);
        try session.receive(gpa, reply);
        try testing.expect(session.isEstablished());
        try testing.expectError(
            error.UnexpectedRecord,
            session.receive(gpa, &record.change_cipher_spec_record),
        );
    }
}
