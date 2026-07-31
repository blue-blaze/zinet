//! TLS 1.3 record layer (RFC 8446 §5), for TLS over TCP.
//!
//! This is the one piece the QUIC work did not need: QUIC replaces the record
//! layer with its own packet protection (RFC 9001 §4.1), which is why
//! `codec/quic/` contains a complete TLS 1.3 handshake engine and no record
//! framing. Putting this file on top of that engine is what carries the
//! handshake onto TCP.
//!
//! Shape mirrors the rest of the repository: sans-io, bytes in and bytes out,
//! with the AEAD suite and HKDF shared with `codec/quic/crypto.zig` — the key
//! derivation here differs from QUIC's only in the labels ("key"/"iv" rather
//! than "quic key"/"quic iv") and in what replaces the packet number (a plain
//! 64-bit sequence, §5.3).
//!
//! Two rules that are easy to get wrong, both enforced here rather than in the
//! caller:
//!
//! - §5.2: the *real* content type of a protected record is the last nonzero
//!   byte of the decrypted plaintext, and everything after the content is zero
//!   padding. The outer type is always application_data and means nothing.
//! - §5.3: sequence numbers are per direction and reset to zero at every key
//!   change. They are never transmitted; a desynchronized sequence looks
//!   exactly like corruption, which is why `Keys` owns the counter instead of
//!   trusting the caller to pass one.

const std = @import("std");
const assert = std.debug.assert;
const hkdfExpandLabel = std.crypto.tls.hkdfExpandLabel;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const quic_crypto = @import("../quic/crypto.zig");
pub const Suite = quic_crypto.Suite;

pub const Error = error{
    /// §5.1/§5.2: a record longer than the protocol allows. The peer gets a
    /// record_overflow alert.
    RecordOverflow,
    /// A record that cannot be parsed at all: unknown outer content type, or a
    /// protected record too short to contain a tag.
    BadRecord,
    /// §5.2: AEAD failure. The connection must be torn down with a
    /// bad_record_mac alert — unlike QUIC, TLS over TCP cannot discard and
    /// continue, because the stream position is now unknowable.
    DecryptionFailed,
    /// §5.4: the decrypted plaintext was all padding, or a zero-length
    /// handshake fragment (§5.1 forbids sending those).
    BadInnerPlaintext,
    /// The AEAD has protected as many records as its keys safely allow; the
    /// caller must send a KeyUpdate or close. Mirrors §6.6 of RFC 9001, which
    /// is where TLS 1.3's own §5.5 sends the reader for the analysis.
    ConfidentialityLimitReached,
    IntegrityLimitReached,
    /// Destination buffer too small; caller error, not peer error.
    BufferTooSmall,
};

/// §5.1. Non-exhaustive because an unknown type must be rejected as data, not
/// as a failed enum cast.
pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const header_len = 5;
/// §5.1: TLSPlaintext.fragment is at most 2^14 bytes.
pub const max_plaintext_len = 1 << 14;
/// §5.2: TLSCiphertext.encrypted_record is at most 2^14 + 256 (content type
/// byte plus up to 255 bytes of padding plus the tag).
pub const max_ciphertext_len = max_plaintext_len + 256;
pub const max_record_len = header_len + max_ciphertext_len;
pub const tag_len = quic_crypto.tag_len;
pub const iv_len = quic_crypto.iv_len;

/// §6. Only the fields, not the registry: alerts are forwarded or logged, and
/// the two-byte encoding is all the record layer needs to know.
pub const Alert = struct {
    pub const warning: u8 = 1;
    pub const fatal: u8 = 2;
    pub const close_notify: u8 = 0;

    level: u8,
    description: u8,

    pub fn encode(self: Alert) [2]u8 {
        return .{ self.level, self.description };
    }

    pub fn decode(bytes: []const u8) Error!Alert {
        if (bytes.len != 2) return error.BadRecord;
        return .{ .level = bytes[0], .description = bytes[1] };
    }
};

/// Write a record header. `len` is the length of what follows the header.
pub fn writeHeader(dest: *[header_len]u8, content_type: ContentType, len: usize) void {
    assert(len <= max_ciphertext_len);
    dest[0] = @backingInt(content_type);
    // §5.1: legacy_record_version, 0x0303 everywhere except a first ClientHello
    // where 0x0301 is also allowed; receivers must not enforce it, so senders
    // gain nothing from the exception.
    dest[1] = 0x03;
    dest[2] = 0x03;
    std.mem.writeInt(u16, dest[3..5], @intCast(len), .big);
}

/// Write a whole plaintext record (handshake before keys exist, alerts, CCS).
/// Returns bytes written.
pub fn writePlaintextRecord(
    dest: []u8,
    content_type: ContentType,
    payload: []const u8,
) Error!usize {
    if (payload.len > max_plaintext_len) return error.RecordOverflow;
    if (dest.len < header_len + payload.len) return error.BufferTooSmall;
    writeHeader(dest[0..header_len], content_type, payload.len);
    @memcpy(dest[header_len..][0..payload.len], payload);
    return header_len + payload.len;
}

/// §D.4: the middlebox-compatibility change_cipher_spec record, byte for byte.
pub const change_cipher_spec_record = [_]u8{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };

/// One direction's record protection: key, IV and the sequence number that
/// §5.3 attaches to them. Owning the counter here is what makes "sequence
/// resets on key change" impossible to forget — a new `Keys` is the reset.
pub const Keys = struct {
    suite: Suite,
    secret: [quic_crypto.max_secret_len]u8,
    key: [quic_crypto.max_key_len]u8,
    iv: [iv_len]u8,
    sequence: u64 = 0,
    records_protected: u64 = 0,
    decryption_failures: u64 = 0,

    /// §7.3: key = HKDF-Expand-Label(secret, "key", "", key_length) and the
    /// same for "iv". The labels are the only difference from QUIC's §5.1.
    pub fn fromTrafficSecret(suite: Suite, secret: []const u8) Keys {
        assert(secret.len == suite.secretLen());
        var keys: Keys = .{
            .suite = suite,
            .secret = @splat(0),
            .key = @splat(0),
            .iv = @splat(0),
        };
        @memcpy(keys.secret[0..secret.len], secret);
        const key_len = suite.keyLen();
        switch (suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                const prk: [32]u8 = secret[0..32].*;
                if (key_len == 16) {
                    keys.key[0..16].* = hkdfExpandLabel(HkdfSha256, prk, "key", "", 16);
                } else {
                    keys.key[0..32].* = hkdfExpandLabel(HkdfSha256, prk, "key", "", 32);
                }
                keys.iv = hkdfExpandLabel(HkdfSha256, prk, "iv", "", iv_len);
            },
            .aes_256_gcm_sha384 => {
                const prk: [48]u8 = secret[0..48].*;
                keys.key[0..32].* = hkdfExpandLabel(HkdfSha384, prk, "key", "", 32);
                keys.iv = hkdfExpandLabel(HkdfSha384, prk, "iv", "", iv_len);
            },
        }
        return keys;
    }

    /// §7.2: the next generation's traffic secret, for KeyUpdate. Unlike
    /// QUIC's "quic ku" there is no header-protection key to carry over; the
    /// new `Keys` starts clean, sequence at zero (§5.3).
    pub fn update(self: *const Keys) Keys {
        const secret_len = self.suite.secretLen();
        var next_secret: [quic_crypto.max_secret_len]u8 = @splat(0);
        switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                const prk: [32]u8 = self.secret[0..32].*;
                next_secret[0..32].* = hkdfExpandLabel(HkdfSha256, prk, "traffic upd", "", 32);
            },
            .aes_256_gcm_sha384 => {
                const prk: [48]u8 = self.secret[0..48].*;
                next_secret[0..48].* = hkdfExpandLabel(HkdfSha384, prk, "traffic upd", "", 48);
            },
        }
        return fromTrafficSecret(self.suite, next_secret[0..secret_len]);
    }

    /// §5.3: nonce = IV XOR sequence, right-aligned. Same arithmetic as QUIC
    /// with the sequence standing in for the packet number.
    fn nonce(self: *const Keys, seq: u64) [iv_len]u8 {
        var out = self.iv;
        var seq_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &seq_bytes, seq, .big);
        for (0..8) |i| out[iv_len - 8 + i] ^= seq_bytes[i];
        return out;
    }

    /// Encrypt one record into `dest`: header, ciphertext of
    /// `content || content_type || pad zeros`, tag. Returns bytes written and
    /// advances the sequence. `pad_len` is §5.4's optional padding; zero is
    /// what everyone sends.
    pub fn seal(
        self: *Keys,
        dest: []u8,
        content_type: ContentType,
        plaintext: []const u8,
        pad_len: usize,
    ) Error!usize {
        if (plaintext.len > max_plaintext_len) return error.RecordOverflow;
        const inner_len = plaintext.len + 1 + pad_len;
        if (inner_len + tag_len > max_ciphertext_len) return error.RecordOverflow;
        const record_len = header_len + inner_len + tag_len;
        if (dest.len < record_len) return error.BufferTooSmall;
        if (self.records_protected >= self.suite.confidentialityLimit()) {
            return error.ConfidentialityLimitReached;
        }

        // §5.2: the header is the associated data, with the outer type always
        // application_data and the length covering ciphertext plus tag.
        writeHeader(dest[0..header_len], .application_data, inner_len + tag_len);

        // Assemble TLSInnerPlaintext in place: content, real type, padding.
        var inner = dest[header_len..][0..inner_len];
        @memcpy(inner[0..plaintext.len], plaintext);
        inner[plaintext.len] = @backingInt(content_type);
        @memset(inner[plaintext.len + 1 ..], 0);

        const npub = self.nonce(self.sequence);
        const tag = dest[header_len + inner_len ..][0..tag_len];
        switch (self.suite) {
            .aes_128_gcm_sha256 => Aes128Gcm.encrypt(
                inner,
                tag,
                inner,
                dest[0..header_len],
                npub,
                self.key[0..16].*,
            ),
            .aes_256_gcm_sha384 => Aes256Gcm.encrypt(
                inner,
                tag,
                inner,
                dest[0..header_len],
                npub,
                self.key[0..32].*,
            ),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.encrypt(
                inner,
                tag,
                inner,
                dest[0..header_len],
                npub,
                self.key[0..32].*,
            ),
        }
        self.sequence += 1;
        self.records_protected += 1;
        return record_len;
    }

    pub const Opened = struct {
        content_type: ContentType,
        len: usize,
    };

    /// Decrypt one protected record (header included) into `dest` and locate
    /// the real content type behind §5.4's padding. Advances the sequence on
    /// success — and only on success, because a failure here is fatal to the
    /// connection anyway (§5.2), unlike QUIC where a bad packet is discarded.
    pub fn open(self: *Keys, dest: []u8, record: []const u8) Error!Opened {
        if (record.len < header_len + 1 + tag_len) return error.BadRecord;
        const ciphertext = record[header_len..];
        if (ciphertext.len > max_ciphertext_len) return error.RecordOverflow;
        const inner_len = ciphertext.len - tag_len;
        if (dest.len < inner_len) return error.BufferTooSmall;

        const npub = self.nonce(self.sequence);
        const body = ciphertext[0..inner_len];
        const tag: [tag_len]u8 = ciphertext[inner_len..][0..tag_len].*;
        const out = dest[0..inner_len];

        const result = switch (self.suite) {
            .aes_128_gcm_sha256 => Aes128Gcm.decrypt(
                out,
                body,
                tag,
                record[0..header_len],
                npub,
                self.key[0..16].*,
            ),
            .aes_256_gcm_sha384 => Aes256Gcm.decrypt(
                out,
                body,
                tag,
                record[0..header_len],
                npub,
                self.key[0..32].*,
            ),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.decrypt(
                out,
                body,
                tag,
                record[0..header_len],
                npub,
                self.key[0..32].*,
            ),
        };
        result catch {
            self.decryption_failures += 1;
            if (self.decryption_failures > self.suite.integrityLimit()) {
                return error.IntegrityLimitReached;
            }
            return error.DecryptionFailed;
        };
        self.sequence += 1;

        // §5.4: scan back over the zero padding; the last nonzero byte is the
        // content type. All zeros means no content type at all, which §5.4
        // makes an unexpected_message-grade failure rather than an empty
        // record.
        var end = inner_len;
        while (end > 0 and out[end - 1] == 0) end -= 1;
        if (end == 0) return error.BadInnerPlaintext;
        const content_type: ContentType = @fromBackingInt(@intCast(out[end - 1]));
        const content_len = end - 1;
        // §5.1: zero-length handshake and alert fragments must not be sent.
        // Empty application data is legal (it is how some stacks probe).
        if (content_len == 0 and content_type != .application_data) {
            return error.BadInnerPlaintext;
        }
        return .{ .content_type = content_type, .len = content_len };
    }
};

/// One record as framed off the wire, before any decryption. `body` borrows
/// the parser's internal buffer and is valid until the next call — same
/// borrowed-payload rule as the HTTP/3 frame parser, and the same reason:
/// copying every record would double the memory for nothing, since the very
/// next step (decrypt or handle) consumes it.
pub const Record = struct {
    content_type: ContentType,
    /// The whole record including its 5-byte header, which `Keys.open` needs
    /// because the header is the AEAD's associated data.
    bytes: []const u8,

    pub fn body(self: *const Record) []const u8 {
        return self.bytes[header_len..];
    }
};

/// Incremental record framer. TCP refragments, so a record may arrive in any
/// number of pieces and a read may contain any number of records; `next` is
/// fed whatever arrived and yields at most one record per call, telling the
/// caller how much input it consumed.
///
/// The buffer is fixed at the protocol's own maximum (§5.2), so a peer cannot
/// make it grow; a record claiming more than that is rejected before any of
/// it is buffered.
pub const Parser = struct {
    buf: [max_record_len]u8 = undefined,
    len: usize = 0,

    pub const Result = struct {
        record: Record,
        consumed: usize,
    };

    /// Returns null if `input` completes no record (everything given was
    /// consumed and buffered). On success, `consumed` says how much of
    /// `input` was used; the rest belongs to the next record and must be fed
    /// again.
    pub fn next(self: *Parser, input: []const u8) Error!?Result {
        var consumed: usize = 0;

        // Fill the header first: five bytes, possibly one at a time.
        while (self.len < header_len and consumed < input.len) {
            self.buf[self.len] = input[consumed];
            self.len += 1;
            consumed += 1;
        }
        if (self.len < header_len) return null;

        const content_type: ContentType = @fromBackingInt(@intCast(self.buf[0]));
        switch (content_type) {
            .change_cipher_spec, .alert, .handshake, .application_data => {},
            // §5: an unknown content type is fatal. Checked before the length
            // so garbage cannot ask us to buffer 16 KiB of itself.
            _ => return error.BadRecord,
        }
        const body_len: usize = std.mem.readInt(u16, self.buf[3..5], .big);
        // §5.2's limit is on protected records; plaintext records (§5.1) are
        // capped smaller, but the framer cannot know which keys apply, so it
        // enforces the outer bound and `Keys.open`/the engine enforce the rest.
        if (body_len > max_ciphertext_len) return error.RecordOverflow;
        if (body_len == 0 and content_type != .application_data) {
            // A zero-length plaintext handshake or alert record can only be
            // an attempt to wedge the parser (§5.1 forbids sending them).
            return error.BadRecord;
        }

        const record_len = header_len + body_len;
        const want = record_len - self.len;
        const take = @min(want, input.len - consumed);
        @memcpy(self.buf[self.len..][0..take], input[consumed..][0..take]);
        self.len += take;
        consumed += take;

        if (self.len < record_len) return null;
        self.len = 0; // Ready for the next record; the returned slice stays valid until the next call.
        return .{
            .record = .{
                .content_type = content_type,
                .bytes = self.buf[0..record_len],
            },
            .consumed = consumed,
        };
    }
};

// --- Tests --------------------------------------------------------------

const rfc8448 = @import("../quic/rfc8448.zig");

// §4.4.4: Finished is its verify_data behind a four-byte handshake header.
const client_finished_message = [_]u8{ 0x14, 0x00, 0x00, 0x20 } ++ rfc8448.client_verify_data;
const testing = std.testing;

test "record: traffic keys match RFC 8448 §3 for all four directions and levels" {
    // The labels differ from QUIC's ("key"/"iv" against "quic key"/"quic iv"),
    // so QUIC's Appendix A coverage says nothing about these two lines.
    const cases = [_]struct { secret: []const u8, key: []const u8, iv: []const u8 }{
        .{ .secret = &rfc8448.server_handshake_secret, .key = &rfc8448.server_handshake_key, .iv = &rfc8448.server_handshake_iv },
        .{ .secret = &rfc8448.client_handshake_secret, .key = &rfc8448.client_handshake_key, .iv = &rfc8448.client_handshake_iv },
        .{ .secret = &rfc8448.server_application_secret, .key = &rfc8448.server_application_key, .iv = &rfc8448.server_application_iv },
        .{ .secret = &rfc8448.client_application_secret, .key = &rfc8448.client_application_key, .iv = &rfc8448.client_application_iv },
    };
    for (cases) |case| {
        const keys: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, case.secret);
        try testing.expectEqualSlices(u8, case.key, keys.key[0..16]);
        try testing.expectEqualSlices(u8, case.iv, &keys.iv);
    }
}

test "record: seal reproduces RFC 8448 §3's protected records byte for byte" {
    // The server flight: 657 bytes of handshake under the handshake keys,
    // sequence 0. Byte equality here pins the AAD, the nonce, the inner
    // content type and the header all at once.
    var server_hs: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.server_handshake_secret);
    var buf: [1024]u8 = undefined;
    var n = try server_hs.seal(&buf, .handshake, &rfc8448.server_flight, 0);
    try testing.expectEqualSlices(u8, &rfc8448.record_server_flight, buf[0..n]);

    // The client Finished under the client handshake keys.
    var client_hs: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_handshake_secret);
    n = try client_hs.seal(&buf, .handshake, &client_finished_message, 0);
    try testing.expectEqualSlices(u8, &rfc8448.record_client_finished, buf[0..n]);

    // Application data, client direction, sequence 0.
    var client_ap: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    n = try client_ap.seal(&buf, .application_data, &rfc8448.app_payload, 0);
    try testing.expectEqualSlices(u8, &rfc8448.record_client_data, buf[0..n]);

    // The server's application direction shows the sequence advancing: the
    // NewSessionTicket is its record 0, the echoed data record 1.
    var server_ap: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.server_application_secret);
    n = try server_ap.seal(&buf, .handshake, &rfc8448.ticket_payload, 0);
    try testing.expectEqualSlices(u8, &rfc8448.record_ticket, buf[0..n]);
    n = try server_ap.seal(&buf, .application_data, &rfc8448.app_payload, 0);
    try testing.expectEqualSlices(u8, &rfc8448.record_server_data, buf[0..n]);
}

test "record: open recovers content and real type, and the alert closes the trace" {
    var server_hs: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.server_handshake_secret);
    var buf: [1024]u8 = undefined;
    var opened = try server_hs.open(&buf, &rfc8448.record_server_flight);
    try testing.expectEqual(ContentType.handshake, opened.content_type);
    try testing.expectEqualSlices(u8, &rfc8448.server_flight, buf[0..opened.len]);

    // Client direction: data is record 0, close_notify record 1. Getting the
    // alert to decrypt at all proves the sequence advanced.
    var client_ap: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    opened = try client_ap.open(&buf, &rfc8448.record_client_data);
    try testing.expectEqual(ContentType.application_data, opened.content_type);
    opened = try client_ap.open(&buf, &rfc8448.record_client_alert);
    try testing.expectEqual(ContentType.alert, opened.content_type);
    const alert = try Alert.decode(buf[0..opened.len]);
    try testing.expectEqual(Alert.warning, alert.level);
    try testing.expectEqual(Alert.close_notify, alert.description);
}

test "record: a wrong sequence number is indistinguishable from corruption" {
    // §5.3's design consequence, asserted so nobody "fixes" the counter reset.
    var client_ap: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    client_ap.sequence = 1; // As if one record had already been read.
    var buf: [1024]u8 = undefined;
    try testing.expectError(error.DecryptionFailed, client_ap.open(&buf, &rfc8448.record_client_data));

    // And a failure must not advance the sequence. No manual reset here: feed
    // a corrupted record to fresh keys, then the genuine record 0 — if the
    // failure moved the counter, the genuine record now fails too and the
    // connection desynchronizes on the first bit flip instead of reporting it.
    var fresh: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    var corrupted = rfc8448.record_client_data;
    corrupted[corrupted.len - 1] ^= 0x01;
    try testing.expectError(error.DecryptionFailed, fresh.open(&buf, &corrupted));
    _ = try fresh.open(&buf, &rfc8448.record_client_data);
}

test "record: padding hides behind the content type and empty records are rejected" {
    var a: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    var b: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    var rec: [256]u8 = undefined;
    var out: [256]u8 = undefined;

    // Padded record round-trips to the same content.
    const n = try a.seal(&rec, .application_data, "hello", 100);
    try testing.expectEqual(@as(usize, header_len + 5 + 1 + 100 + tag_len), n);
    const opened = try b.open(&out, rec[0..n]);
    try testing.expectEqual(ContentType.application_data, opened.content_type);
    try testing.expectEqualSlices(u8, "hello", out[0..opened.len]);

    // All-padding plaintext: no content type anywhere, must be rejected
    // (§5.4). `seal` cannot produce such a record — it always writes a type
    // byte — so encrypt raw zeros directly with the same keys and nonce.
    var c: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    var zeros_rec: [64]u8 = undefined;
    const inner: [8]u8 = @splat(0);
    writeHeader(zeros_rec[0..header_len], .application_data, inner.len + tag_len);
    var ct: [8]u8 = undefined;
    var tag: [tag_len]u8 = undefined;
    Aes128Gcm.encrypt(&ct, &tag, &inner, zeros_rec[0..header_len], c.nonce(0), c.key[0..16].*);
    @memcpy(zeros_rec[header_len..][0..8], &ct);
    @memcpy(zeros_rec[header_len + 8 ..][0..tag_len], &tag);
    try testing.expectError(
        error.BadInnerPlaintext,
        c.open(&out, zeros_rec[0 .. header_len + 8 + tag_len]),
    );

    // A zero-length handshake fragment is likewise rejected (§5.1).
    var d: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.server_application_secret);
    var e: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.server_application_secret);
    const hn = try d.seal(&rec, .handshake, "", 0);
    try testing.expectError(error.BadInnerPlaintext, e.open(&out, rec[0..hn]));
    // But zero-length application data is legal.
    var f: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.server_application_secret);
    var g: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.server_application_secret);
    const an = try f.seal(&rec, .application_data, "", 0);
    const aopened = try g.open(&out, rec[0..an]);
    try testing.expectEqual(@as(usize, 0), aopened.len);
}

test "record: key update derives a new generation and resets the sequence" {
    var gen0: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    var buf: [128]u8 = undefined;
    _ = try gen0.seal(&buf, .application_data, "x", 0);
    try testing.expectEqual(@as(u64, 1), gen0.sequence);

    var gen1 = gen0.update();
    try testing.expectEqual(@as(u64, 0), gen1.sequence);
    try testing.expect(!std.mem.eql(u8, gen0.key[0..16], gen1.key[0..16]));
    try testing.expect(!std.mem.eql(u8, &gen0.iv, &gen1.iv));

    // The new generation is self-consistent, and the old keys cannot read it.
    var gen1_reader = gen0.update();
    const n = try gen1.seal(&buf, .application_data, "after update", 0);
    var out: [128]u8 = undefined;
    const opened = try gen1_reader.open(&out, buf[0..n]);
    try testing.expectEqualSlices(u8, "after update", out[0..opened.len]);
    var old_reader: Keys = .fromTrafficSecret(.aes_128_gcm_sha256, &rfc8448.client_application_secret);
    try testing.expectError(error.DecryptionFailed, old_reader.open(&out, buf[0..n]));
}

test "record: parser frames the whole RFC 8448 server stream chunk-independently" {
    // Everything the server sends in §3, concatenated as it would cross TCP.
    const stream = rfc8448.record_server_hello ++ rfc8448.record_server_flight ++
        rfc8448.record_ticket ++ rfc8448.record_server_data ++ rfc8448.record_server_alert;
    const expected_types = [_]ContentType{ .handshake, .application_data, .application_data, .application_data, .application_data };
    const expected_lens = [_]usize{
        rfc8448.record_server_hello.len,
        rfc8448.record_server_flight.len,
        rfc8448.record_ticket.len,
        rfc8448.record_server_data.len,
        rfc8448.record_server_alert.len,
    };

    // One shot.
    {
        var parser: Parser = .{};
        var offset: usize = 0;
        var count: usize = 0;
        while (offset < stream.len) {
            const result = (try parser.next(stream[offset..])) orelse break;
            try testing.expectEqual(expected_types[count], result.record.content_type);
            try testing.expectEqual(expected_lens[count], result.record.bytes.len);
            count += 1;
            offset += result.consumed;
        }
        try testing.expectEqual(@as(usize, 5), count);
    }

    // One byte at a time must produce the identical framing.
    {
        var parser: Parser = .{};
        var count: usize = 0;
        for (stream, 0..) |_, i| {
            if (try parser.next(stream[i .. i + 1])) |result| {
                try testing.expectEqual(@as(usize, 1), result.consumed);
                try testing.expectEqual(expected_types[count], result.record.content_type);
                try testing.expectEqual(expected_lens[count], result.record.bytes.len);
                count += 1;
            }
        }
        try testing.expectEqual(@as(usize, 5), count);
    }
}

test "record: parser consumes partially and returns the remainder to the caller" {
    // Two records fed as one buffer: the first call must consume exactly the
    // first record and leave the second for the next call.
    const stream = rfc8448.record_server_data ++ rfc8448.record_server_alert;
    var parser: Parser = .{};
    const first = (try parser.next(&stream)).?;
    try testing.expectEqual(rfc8448.record_server_data.len, first.consumed);
    const second = (try parser.next(stream[first.consumed..])).?;
    try testing.expectEqual(rfc8448.record_server_alert.len, second.consumed);
}

test "record: parser rejects garbage before buffering and tolerates CCS" {
    var parser: Parser = .{};
    // Unknown content type: rejected at the header, nothing buffered.
    try testing.expectError(error.BadRecord, parser.next(&[_]u8{ 0x99, 0x03, 0x03, 0x40, 0x00 }));

    // Length over §5.2's bound: rejected before any body arrives.
    var parser2: Parser = .{};
    var oversized = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x00 };
    std.mem.writeInt(u16, oversized[3..5], max_ciphertext_len + 1, .big);
    try testing.expectError(error.RecordOverflow, parser2.next(&oversized));

    // §D.4's change_cipher_spec frames as an ordinary record for the engine
    // to ignore.
    var parser3: Parser = .{};
    const result = (try parser3.next(&change_cipher_spec_record)).?;
    try testing.expectEqual(ContentType.change_cipher_spec, result.record.content_type);
    try testing.expectEqualSlices(u8, &[_]u8{0x01}, result.record.body());
}

test "record: plaintext records reproduce the RFC trace" {
    var buf: [512]u8 = undefined;
    const n = try writePlaintextRecord(&buf, .handshake, &rfc8448.client_hello);
    try testing.expectEqualSlices(u8, rfc8448.record_client_hello[5..], buf[5..n]);
    // The trace uses legacy version 0x0301 on the first record, the one place
    // it may differ; everything after the version must match.
    try testing.expectEqual(rfc8448.record_client_hello.len, n);
    try testing.expectEqual(rfc8448.record_client_hello[0], buf[0]);
    try testing.expectEqualSlices(u8, rfc8448.record_client_hello[3..5], buf[3..5]);
}
