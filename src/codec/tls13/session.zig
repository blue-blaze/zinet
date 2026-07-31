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
        switch (rec.content_type) {
            // §D.4: a change_cipher_spec during the handshake is compatibility
            // theatre and is dropped without so much as a length check beyond
            // the framer's.
            .change_cipher_spec => return,
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
        const keys = &self.write_keys.?;
        var offset: usize = 0;
        while (true) {
            const chunk = @min(content.len - offset, record.max_plaintext_len);
            const record_len = record.header_len + chunk + 1 + record.tag_len;
            const dest = try self.to_send.addManyAsSlice(gpa, record_len);
            const n = try keys.seal(dest, content_type, content[offset..][0..chunk], 0);
            assert(n == record_len);
            offset += chunk;
            // The check sits at the bottom so zero-length application data
            // still produces its one record — and nothing produces two.
            if (offset >= content.len) break;
        }
    }

    fn handleAlert(self: *ClientSession, alert: record.Alert) Error!void {
        self.close_alert = alert;
        if (alert.description == record.Alert.close_notify) {
            // §6.1: the peer will send no more data. Ours may still flow, but
            // in practice everyone closes; the caller decides.
            self.state = .peer_closed;
            return;
        }
        self.state = .failed;
        return error.AlertReceived;
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
