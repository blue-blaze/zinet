//! QUIC packet protection, RFC 9001 §5.
//!
//! Everything here is built from `std.crypto` parts. That is worth stating
//! because it was not obvious in advance: `std.crypto.tls.hkdfExpandLabel` is
//! public and generic over the HKDF type, which is exactly what §5.1 needs, and
//! raw AES blocks and ChaCha20 are available for header protection. So this
//! layer needs nothing that does not exist, and the whole of Appendix A can be
//! reproduced byte for byte.
//!
//! Two orderings matter, and reversing either produces a connection that fails
//! to authenticate every packet:
//!
//! **Sending: AEAD first, then header protection.** The header protection sample
//! is taken from the *ciphertext*, so the payload must be encrypted before the
//! header can be protected. Receiving is the mirror image: remove header
//! protection to learn the packet number, then use it to build the nonce.
//!
//! **The sample offset assumes a four-byte packet number** regardless of the
//! actual length (§5.4.2). It has to: the length is itself encrypted, so the
//! receiver cannot know it before sampling. This is why `packet.zig` refuses a
//! protected packet with fewer than 4 + 16 bytes of remainder.

const std = @import("std");
const assert = std.debug.assert;
const tls = std.crypto.tls;

const packet = @import("packet.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
/// Not predefined in `std.crypto.kdf.hkdf`, unlike the SHA-256 one, so it is
/// instantiated here from the same generic the standard library's own TLS code
/// uses (`std/crypto/tls.zig`, `ApplicationCipherT`).
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

/// §5.2: the version 1 salt. A different QUIC version uses a different salt,
/// which is deliberate — it makes Initial packets of one version undecryptable
/// as another, so a version-confused endpoint fails closed.
pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

pub const tag_len = 16;
pub const iv_len = 12;
pub const sample_len = 16;
pub const mask_len = 5;
/// The longest key and secret any supported suite uses, so that one value type
/// can hold every case without allocating.
pub const max_key_len = 32;
pub const max_secret_len = 48;

pub const Error = error{
    /// The AEAD tag did not verify. §5.3 requires the packet be discarded
    /// without any other effect, which is why this is the only failure the
    /// caller can distinguish.
    DecryptionFailed,
    /// §6.6: this key has protected as many packets as the AEAD allows. The
    /// connection must update keys or close; continuing would weaken the AEAD's
    /// guarantees, so it is refused rather than logged.
    ConfidentialityLimitReached,
    /// §6.6: too many forged packets have been rejected under this key. This is
    /// an attack in progress, and §6.6 requires closing the connection.
    IntegrityLimitReached,
    /// A buffer smaller than the operation needs.
    BufferTooSmall,
};

/// §5.1 and RFC 8446: the cipher suites TLS 1.3 may negotiate for QUIC.
/// AEGIS suites exist in `std.crypto.tls` but no QUIC registry entry does, so
/// they are deliberately absent rather than forgotten.
pub const Suite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,

    pub fn keyLen(self: Suite) usize {
        return switch (self) {
            .aes_128_gcm_sha256 => 16,
            .aes_256_gcm_sha384, .chacha20_poly1305_sha256 => 32,
        };
    }

    pub fn secretLen(self: Suite) usize {
        return switch (self) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => 32,
            .aes_256_gcm_sha384 => 48,
        };
    }

    /// §6.6, table 2. The number of packets that may be protected with one key.
    /// AES-GCM's limit is low enough to be reached by a fast bulk transfer, so
    /// this is a live constraint rather than a theoretical one: 2^23 packets is
    /// about 12 GB at 1500 bytes.
    pub fn confidentialityLimit(self: Suite) u64 {
        return switch (self) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => 1 << 23,
            .chacha20_poly1305_sha256 => std.math.maxInt(u64),
        };
    }

    /// §6.6, table 2. How many failed decryptions may be tolerated before the
    /// connection must close. Forged packets are how an attacker probes the
    /// AEAD, so this bound is a security property.
    pub fn integrityLimit(self: Suite) u64 {
        return switch (self) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => 1 << 52,
            .chacha20_poly1305_sha256 => 1 << 36,
        };
    }
};

/// Header protection key material. Separate from `Keys` because the algorithm
/// differs by suite in a way the AEAD does not: AES uses a raw block cipher
/// (§5.4.3) and ChaCha20 uses its stream with the sample split into a counter
/// and a nonce (§5.4.4).
pub const HeaderKey = struct {
    suite: Suite,
    bytes: [max_key_len]u8,

    pub fn mask(self: *const HeaderKey, sample: *const [sample_len]u8) [mask_len]u8 {
        var out: [mask_len]u8 = undefined;
        switch (self.suite) {
            .aes_128_gcm_sha256 => {
                // §5.4.3: encrypt the sample as a single AES block and take the
                // first five bytes. ECB is correct here precisely because it is
                // one block of unpredictable input, never a message.
                const aes = std.crypto.core.aes.Aes128.initEnc(self.bytes[0..16].*);
                var block: [16]u8 = undefined;
                aes.encrypt(&block, sample);
                @memcpy(&out, block[0..mask_len]);
            },
            .aes_256_gcm_sha384 => {
                const aes = std.crypto.core.aes.Aes256.initEnc(self.bytes[0..32].*);
                var block: [16]u8 = undefined;
                aes.encrypt(&block, sample);
                @memcpy(&out, block[0..mask_len]);
            },
            .chacha20_poly1305_sha256 => {
                // §5.4.4: the first four bytes of the sample are the block
                // counter, little endian, and the remaining twelve are the
                // nonce. The mask is the keystream, so five zero bytes.
                const counter = std.mem.readInt(u32, sample[0..4], .little);
                const nonce = sample[4..16].*;
                const zeros: [mask_len]u8 = @splat(0);
                std.crypto.stream.chacha.ChaCha20IETF.xor(
                    &out,
                    &zeros,
                    counter,
                    self.bytes[0..32].*,
                    nonce,
                );
            },
        }
        return out;
    }
};

/// Keys for one direction at one encryption level.
///
/// Stateful on purpose: §6.6's limits belong to the key rather than to the
/// connection, so counting here makes them impossible to bypass by using the
/// key through some other path.
pub const Keys = struct {
    suite: Suite,
    /// The traffic secret, kept because a key update (§6.1) derives the next
    /// one from it.
    secret: [max_secret_len]u8,
    key: [max_key_len]u8,
    iv: [iv_len]u8,
    header: HeaderKey,

    packets_protected: u64 = 0,
    decryption_failures: u64 = 0,

    /// §5.1: derive key, iv and hp from a traffic secret.
    pub fn fromSecret(suite: Suite, secret: []const u8) Keys {
        assert(secret.len == suite.secretLen());
        var keys: Keys = .{
            .suite = suite,
            .secret = @splat(0),
            .key = @splat(0),
            .iv = @splat(0),
            .header = .{ .suite = suite, .bytes = @splat(0) },
        };
        @memcpy(keys.secret[0..secret.len], secret);

        const key_len = suite.keyLen();
        switch (suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                const prk: [32]u8 = secret[0..32].*;
                if (key_len == 16) {
                    keys.key[0..16].* = tls.hkdfExpandLabel(HkdfSha256, prk, "quic key", "", 16);
                    keys.header.bytes[0..16].* = tls.hkdfExpandLabel(HkdfSha256, prk, "quic hp", "", 16);
                } else {
                    keys.key[0..32].* = tls.hkdfExpandLabel(HkdfSha256, prk, "quic key", "", 32);
                    keys.header.bytes[0..32].* = tls.hkdfExpandLabel(HkdfSha256, prk, "quic hp", "", 32);
                }
                keys.iv = tls.hkdfExpandLabel(HkdfSha256, prk, "quic iv", "", iv_len);
            },
            .aes_256_gcm_sha384 => {
                const prk: [48]u8 = secret[0..48].*;
                keys.key[0..32].* = tls.hkdfExpandLabel(HkdfSha384, prk, "quic key", "", 32);
                keys.header.bytes[0..32].* = tls.hkdfExpandLabel(HkdfSha384, prk, "quic hp", "", 32);
                keys.iv = tls.hkdfExpandLabel(HkdfSha384, prk, "quic iv", "", iv_len);
            },
        }
        return keys;
    }

    /// §6.1: derive the next generation's keys. The header protection key is
    /// *not* updated — §6 keeps it for the life of the connection, because
    /// rotating it would make the key phase bit itself undecipherable.
    pub fn update(self: *const Keys) Keys {
        const secret_len = self.suite.secretLen();
        var next_secret: [max_secret_len]u8 = @splat(0);
        switch (self.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => {
                const prk: [32]u8 = self.secret[0..32].*;
                next_secret[0..32].* = tls.hkdfExpandLabel(HkdfSha256, prk, "quic ku", "", 32);
            },
            .aes_256_gcm_sha384 => {
                const prk: [48]u8 = self.secret[0..48].*;
                next_secret[0..48].* = tls.hkdfExpandLabel(HkdfSha384, prk, "quic ku", "", 48);
            },
        }
        var next = fromSecret(self.suite, next_secret[0..secret_len]);
        // Header protection survives the update, so carry it across rather than
        // letting `fromSecret` derive a new one from the new secret.
        next.header = self.header;
        return next;
    }

    /// §5.3: nonce is the IV exclusive-ored with the packet number, right
    /// aligned. The full packet number, not the truncated one on the wire —
    /// which is the whole reason packet number recovery has to be right.
    fn nonce(self: *const Keys, pn: u64) [iv_len]u8 {
        var out = self.iv;
        var pn_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &pn_bytes, pn, .big);
        for (0..8) |i| out[iv_len - 8 + i] ^= pn_bytes[i];
        return out;
    }

    /// Encrypt `payload` into `dest`, authenticating `header`. Returns the
    /// bytes written, which is `payload.len + tag_len`.
    ///
    /// `header` must be the *unprotected* header including the packet number, as
    /// §5.3 makes it the associated data. Header protection is applied
    /// afterwards, by `protectHeader`.
    pub fn seal(
        self: *Keys,
        dest: []u8,
        pn: u64,
        header: []const u8,
        payload: []const u8,
    ) Error!usize {
        if (self.packets_protected >= self.suite.confidentialityLimit()) {
            return error.ConfidentialityLimitReached;
        }
        if (dest.len < payload.len + tag_len) return error.BufferTooSmall;

        const npub = self.nonce(pn);
        const ciphertext = dest[0..payload.len];
        const tag = dest[payload.len..][0..tag_len];

        switch (self.suite) {
            .aes_128_gcm_sha256 => Aes128Gcm.encrypt(
                ciphertext,
                tag,
                payload,
                header,
                npub,
                self.key[0..16].*,
            ),
            .aes_256_gcm_sha384 => Aes256Gcm.encrypt(
                ciphertext,
                tag,
                payload,
                header,
                npub,
                self.key[0..32].*,
            ),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.encrypt(
                ciphertext,
                tag,
                payload,
                header,
                npub,
                self.key[0..32].*,
            ),
        }

        self.packets_protected += 1;
        return payload.len + tag_len;
    }

    /// Decrypt `ciphertext` (which includes the tag) into `dest`.
    ///
    /// A failure here is counted against §6.6's integrity limit, because the
    /// count is what distinguishes a corrupt path from an attacker probing the
    /// AEAD. The packet must be discarded with no other effect (§5.3): a failed
    /// decryption cannot be a connection error, or an off-path attacker could
    /// kill any connection by sending one bad packet.
    pub fn open(
        self: *Keys,
        dest: []u8,
        pn: u64,
        header: []const u8,
        ciphertext: []const u8,
    ) Error!usize {
        if (ciphertext.len < tag_len) return error.DecryptionFailed;
        const body_len = ciphertext.len - tag_len;
        if (dest.len < body_len) return error.BufferTooSmall;

        const npub = self.nonce(pn);
        const body = ciphertext[0..body_len];
        const tag: [tag_len]u8 = ciphertext[body_len..][0..tag_len].*;

        const result = switch (self.suite) {
            .aes_128_gcm_sha256 => Aes128Gcm.decrypt(
                dest[0..body_len],
                body,
                tag,
                header,
                npub,
                self.key[0..16].*,
            ),
            .aes_256_gcm_sha384 => Aes256Gcm.decrypt(
                dest[0..body_len],
                body,
                tag,
                header,
                npub,
                self.key[0..32].*,
            ),
            .chacha20_poly1305_sha256 => ChaCha20Poly1305.decrypt(
                dest[0..body_len],
                body,
                tag,
                header,
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
        return body_len;
    }
};

/// Both directions' Initial keys, derived from the client's first destination
/// connection ID (§5.2).
pub const InitialKeys = struct {
    client: Keys,
    server: Keys,

    /// The `dcid` is the connection ID the *client* chose for its first Initial
    /// packet, and both endpoints derive from that same value even after the
    /// server picks its own. A server that used its own connection ID here
    /// would produce keys the client cannot match.
    pub fn derive(dcid: []const u8) InitialKeys {
        const initial_secret = HkdfSha256.extract(&initial_salt_v1, dcid);
        const client_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, "client in", "", 32);
        const server_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, "server in", "", 32);
        return .{
            // §5.2: Initial packets always use AEAD_AES_128_GCM, whatever the
            // handshake later negotiates.
            .client = .fromSecret(.aes_128_gcm_sha256, &client_secret),
            .server = .fromSecret(.aes_128_gcm_sha256, &server_secret),
        };
    }
};

/// Apply header protection in place (§5.4.1).
///
/// `pn_offset` is where the packet number field starts and `pn_len` how long it
/// is. The sample is taken four bytes past `pn_offset` regardless of `pn_len`,
/// because a receiver cannot know the length before it has the mask.
pub fn protectHeader(datagram: []u8, pn_offset: usize, pn_len: u4, key: *const HeaderKey) void {
    assert(pn_len >= 1 and pn_len <= packet.max_pn_len);
    const sample = sampleFor(datagram, pn_offset);
    const mask = key.mask(sample);
    applyMask(datagram, pn_offset, pn_len, mask);
}

/// Remove header protection in place, returning the packet number length that
/// was hidden in the first byte.
pub fn unprotectHeader(datagram: []u8, pn_offset: usize, key: *const HeaderKey) u4 {
    const sample = sampleFor(datagram, pn_offset);
    const mask = key.mask(sample);

    // §5.4.1: which bits of the first byte are protected depends on the header
    // form, because a long header's low four bits are reserved plus packet
    // number length while a short header also has the key phase and spin bits.
    const is_long = datagram[0] & packet.header_form_bit != 0;
    datagram[0] ^= mask[0] & (if (is_long) @as(u8, 0x0f) else 0x1f);

    // Only now is the length readable. Everything before this point had to work
    // without knowing it.
    const pn_len: u4 = @as(u4, @truncate(datagram[0] & 0x03)) + 1;
    for (0..pn_len) |i| datagram[pn_offset + i] ^= mask[1 + i];
    return pn_len;
}

fn sampleFor(datagram: []const u8, pn_offset: usize) *const [sample_len]u8 {
    // §5.4.2. The offset is fixed at four rather than the real packet number
    // length, so that both endpoints sample the same bytes.
    const start = pn_offset + packet.max_pn_len;
    assert(datagram.len >= start + sample_len);
    return datagram[start..][0..sample_len];
}

fn applyMask(datagram: []u8, pn_offset: usize, pn_len: u4, mask: [mask_len]u8) void {
    const is_long = datagram[0] & packet.header_form_bit != 0;
    datagram[0] ^= mask[0] & (if (is_long) @as(u8, 0x0f) else 0x1f);
    for (0..pn_len) |i| datagram[pn_offset + i] ^= mask[1 + i];
}

/// §5.8: the key and nonce for a Retry packet's integrity tag are constants,
/// version specific. They authenticate the Retry without any shared secret,
/// which is the point — a Retry happens before either side has one.
const retry_key_v1 = [16]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
const retry_nonce_v1 = [12]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

/// Compute a Retry packet's integrity tag (§5.8).
///
/// `retry_without_tag` is the whole Retry packet up to but excluding the tag.
/// `original_dcid` is the connection ID the client used in the Initial that
/// prompted this Retry — including it is what stops an attacker replaying a
/// captured Retry at a different connection.
pub fn retryIntegrityTag(
    original_dcid: []const u8,
    retry_without_tag: []const u8,
) [tag_len]u8 {
    assert(original_dcid.len <= packet.max_cid_len);
    // §5.8: the pseudo-packet is the original destination connection ID,
    // length-prefixed, followed by the Retry packet without its tag.
    var pseudo: [1 + packet.max_cid_len + 512]u8 = undefined;
    assert(retry_without_tag.len <= pseudo.len - 1 - original_dcid.len);

    pseudo[0] = @intCast(original_dcid.len);
    @memcpy(pseudo[1..][0..original_dcid.len], original_dcid);
    const body_start = 1 + original_dcid.len;
    @memcpy(pseudo[body_start..][0..retry_without_tag.len], retry_without_tag);
    const pseudo_len = body_start + retry_without_tag.len;

    var tag: [tag_len]u8 = undefined;
    // The pseudo-packet is entirely associated data: a Retry has no
    // confidential content, only integrity.
    Aes128Gcm.encrypt(&.{}, &tag, &.{}, pseudo[0..pseudo_len], retry_nonce_v1, retry_key_v1);
    return tag;
}

/// Whether a Retry packet's tag is the one it should be.
pub fn verifyRetry(
    original_dcid: []const u8,
    retry_without_tag: []const u8,
    tag: *const [tag_len]u8,
) bool {
    const expected = retryIntegrityTag(original_dcid, retry_without_tag);
    // Constant time, because a timing oracle on this tag would let an attacker
    // forge a Retry and redirect a connection.
    return std.crypto.timing_safe.eql([tag_len]u8, expected, tag.*);
}

const testing = std.testing;

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "crypto: RFC 9001 appendix A.1 initial secrets and keys" {
    const dcid = hexBytes("8394c8f03e515708");

    // The intermediate PRK is published too, so it is checked separately: if
    // only the final keys were compared, an error in the salt and a
    // compensating error in a label would cancel out.
    const initial_secret = HkdfSha256.extract(&initial_salt_v1, &dcid);
    try testing.expectEqualSlices(
        u8,
        &hexBytes("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"),
        &initial_secret,
    );

    const keys = InitialKeys.derive(&dcid);

    try testing.expectEqualSlices(
        u8,
        &hexBytes("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"),
        keys.client.secret[0..32],
    );
    try testing.expectEqualSlices(u8, &hexBytes("1f369613dd76d5467730efcbe3b1a22d"), keys.client.key[0..16]);
    try testing.expectEqualSlices(u8, &hexBytes("fa044b2f42a3fd3b46fb255c"), &keys.client.iv);
    try testing.expectEqualSlices(u8, &hexBytes("9f50449e04a0e810283a1e9933adedd2"), keys.client.header.bytes[0..16]);

    try testing.expectEqualSlices(
        u8,
        &hexBytes("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"),
        keys.server.secret[0..32],
    );
    try testing.expectEqualSlices(u8, &hexBytes("cf3a5331653c364c88f0f379b6067e37"), keys.server.key[0..16]);
    try testing.expectEqualSlices(u8, &hexBytes("0ac1493ca1905853b0bba03e"), &keys.server.iv);
    try testing.expectEqualSlices(u8, &hexBytes("c206b8d9b9f0f37644430b490eeaa314"), keys.server.header.bytes[0..16]);
}

test "crypto: RFC 9001 appendix A.5 ChaCha20-Poly1305 short header packet" {
    // The only appendix vector for a complete 1-RTT packet, and the only one
    // that exercises ChaCha20 header protection — whose sample split into a
    // counter and a nonce is nothing like the AES path.
    const secret = hexBytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    var keys: Keys = .fromSecret(.chacha20_poly1305_sha256, &secret);

    try testing.expectEqualSlices(
        u8,
        &hexBytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"),
        keys.key[0..32],
    );
    try testing.expectEqualSlices(u8, &hexBytes("e0459b3474bdd0e44a41c144"), &keys.iv);
    try testing.expectEqualSlices(
        u8,
        &hexBytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"),
        keys.header.bytes[0..32],
    );

    // A key update derives the secret the appendix also gives, which checks
    // that "quic ku" is applied to the secret rather than to the key.
    const updated = keys.update();
    try testing.expectEqualSlices(
        u8,
        &hexBytes("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"),
        updated.secret[0..32],
    );
    // And header protection survives it (§6).
    try testing.expectEqualSlices(u8, keys.header.bytes[0..32], updated.header.bytes[0..32]);

    // Build the packet the appendix describes: header 4200bff4, a PING frame,
    // packet number 654360564 encoded in three bytes as 49140. The full number
    // goes into the nonce and the truncated one onto the wire, which is exactly
    // the distinction §5.3 draws.
    const header = hexBytes("4200bff4");
    const pn: u64 = 654360564;
    var datagram: [4 + 1 + tag_len]u8 = undefined;
    @memcpy(datagram[0..4], &header);
    const written = try keys.seal(datagram[4..], pn, &header, &hexBytes("01"));
    try testing.expectEqual(@as(usize, 1 + tag_len), written);

    // §A.5 gives the whole protected packet: the smallest one QUIC allows.
    protectHeader(&datagram, 1, 3, &keys.header);
    try testing.expectEqualSlices(
        u8,
        &hexBytes("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"),
        &datagram,
    );

    // And the receiver's path recovers it: unprotect the header, learn the
    // length, rebuild the number, decrypt.
    const pn_len = unprotectHeader(&datagram, 1, &keys.header);
    try testing.expectEqual(@as(u4, 3), pn_len);
    try testing.expectEqualSlices(u8, &header, datagram[0..4]);

    var truncated: u64 = 0;
    for (datagram[1..4]) |byte| truncated = (truncated << 8) | byte;
    try testing.expectEqual(@as(u64, 49140), truncated); // what §A.5 says is encoded
    const recovered = packet.decodePacketNumber(pn - 1, truncated, pn_len);
    try testing.expectEqual(pn, recovered);

    var plaintext: [8]u8 = undefined;
    const len = try keys.open(&plaintext, recovered, datagram[0..4], datagram[4..]);
    try testing.expectEqualSlices(u8, &hexBytes("01"), plaintext[0..len]);
}

test "crypto: RFC 9001 appendix A.4 Retry integrity tag" {
    // §5.8. A Retry is authenticated with constants because it happens before
    // either endpoint has a secret; the original connection ID in the pseudo
    // packet is what stops a captured Retry being replayed at a new connection.
    const retry_without_tag = hexBytes("ff000000010008f067a5502a4262b574" ++ "6f6b656e");
    const original_dcid = hexBytes("8394c8f03e515708");

    const tag = retryIntegrityTag(&original_dcid, &retry_without_tag);
    try testing.expectEqualSlices(u8, &hexBytes("04a265ba2eff4d829058fb3f0f2496ba"), &tag);
    try testing.expect(verifyRetry(&original_dcid, &retry_without_tag, &tag));

    // A different original connection ID must not verify, which is the replay
    // protection the pseudo packet exists for.
    const other_dcid = hexBytes("8394c8f03e515709");
    try testing.expect(!verifyRetry(&other_dcid, &retry_without_tag, &tag));
}

test "crypto: header protection is its own inverse over every packet number length" {
    const secret: [32]u8 = @splat(0x2a);
    const keys: Keys = .fromSecret(.aes_128_gcm_sha256, &secret);

    for ([_]u4{ 1, 2, 3, 4 }) |pn_len| {
        for ([_]bool{ true, false }) |long| {
            var datagram: [64]u8 = undefined;
            for (&datagram, 0..) |*b, i| b.* = @truncate(i * 7);
            // The first byte's low two bits encode pn_len - 1 (§17.1).
            datagram[0] = (if (long) packet.header_form_bit | packet.fixed_bit else packet.fixed_bit) |
                (pn_len - 1);
            const original = datagram;

            protectHeader(&datagram, 5, pn_len, &keys.header);
            // Something must actually have changed, or this test would pass
            // against a no-op implementation.
            try testing.expect(!std.mem.eql(u8, &original, &datagram));

            const recovered_len = unprotectHeader(&datagram, 5, &keys.header);
            try testing.expectEqual(pn_len, recovered_len);
            try testing.expectEqualSlices(u8, &original, &datagram);
        }
    }
}

test "crypto: a short header protects five bits of the first byte and a long header four" {
    // §5.4.1. Getting this mask wrong corrupts the key phase bit on 1-RTT
    // packets, which makes a key update undetectable and every packet after it
    // fail to decrypt.
    const secret: [32]u8 = @splat(0x5c);
    const keys: Keys = .fromSecret(.aes_128_gcm_sha256, &secret);

    var short: [64]u8 = @splat(0x11);
    short[0] = packet.fixed_bit;
    var long: [64]u8 = @splat(0x11);
    long[0] = packet.header_form_bit | packet.fixed_bit;

    const short_before = short[0];
    const long_before = long[0];
    protectHeader(&short, 5, 1, &keys.header);
    protectHeader(&long, 5, 1, &keys.header);

    // The same sample, so the same mask; the difference is only which bits it
    // is allowed to touch.
    try testing.expectEqual(@as(u8, 0), (short[0] ^ short_before) & 0xe0);
    try testing.expectEqual(@as(u8, 0), (long[0] ^ long_before) & 0xf0);
}

test "crypto: a tampered packet fails to decrypt and is counted" {
    const dcid = hexBytes("8394c8f03e515708");
    var keys = InitialKeys.derive(&dcid).client;

    const header = hexBytes("c00000000108" ++ "8394c8f03e515708" ++ "0000449e00000002");
    var sealed: [64]u8 = undefined;
    const len = try keys.seal(&sealed, 2, &header, "some payload");

    // Unmodified, it opens.
    var out: [64]u8 = undefined;
    const opened = try keys.open(&out, 2, &header, sealed[0..len]);
    try testing.expectEqualStrings("some payload", out[0..opened]);
    try testing.expectEqual(@as(u64, 0), keys.decryption_failures);

    // One flipped bit in the ciphertext.
    sealed[0] ^= 1;
    try testing.expectError(error.DecryptionFailed, keys.open(&out, 2, &header, sealed[0..len]));
    sealed[0] ^= 1;

    // The wrong packet number gives the wrong nonce, which is why packet number
    // recovery has to be exact: this failure is indistinguishable from loss.
    try testing.expectError(error.DecryptionFailed, keys.open(&out, 3, &header, sealed[0..len]));

    // A modified header, which is associated data rather than ciphertext.
    var bad_header = header;
    bad_header[0] ^= 0x01;
    try testing.expectError(error.DecryptionFailed, keys.open(&out, 2, &bad_header, sealed[0..len]));

    try testing.expectEqual(@as(u64, 3), keys.decryption_failures);
}

test "crypto: the AEAD limits of §6.6 are enforced rather than documented" {
    const secret: [32]u8 = @splat(0x77);
    var keys: Keys = .fromSecret(.aes_128_gcm_sha256, &secret);

    // Wind the counter to the limit rather than encrypting 2^23 packets.
    keys.packets_protected = keys.suite.confidentialityLimit();
    var out: [64]u8 = undefined;
    try testing.expectError(
        error.ConfidentialityLimitReached,
        keys.seal(&out, 1, "header", "payload"),
    );

    // The integrity limit closes the connection rather than merely discarding,
    // because that many forgeries is an attack rather than a bad path.
    var other: Keys = .fromSecret(.chacha20_poly1305_sha256, &secret);
    other.decryption_failures = other.suite.integrityLimit();
    var sealed: [64]u8 = undefined;
    const len = try other.seal(&sealed, 1, "header", "payload");
    sealed[0] ^= 1;
    try testing.expectError(
        error.IntegrityLimitReached,
        other.open(&out, 1, "header", sealed[0..len]),
    );

    // ChaCha20's integrity limit is far lower than AES-GCM's, and its
    // confidentiality limit far higher. Asserting both stops a copy-paste error
    // silently applying one suite's bounds to another.
    try testing.expect(
        Suite.chacha20_poly1305_sha256.integrityLimit() <
            Suite.aes_128_gcm_sha256.integrityLimit(),
    );
    try testing.expect(
        Suite.chacha20_poly1305_sha256.confidentialityLimit() >
            Suite.aes_128_gcm_sha256.confidentialityLimit(),
    );
}

test "crypto: every suite round trips, and a key update changes the ciphertext" {
    for ([_]Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        var secret: [max_secret_len]u8 = @splat(0);
        for (&secret, 0..) |*b, i| b.* = @truncate(i * 3 + 1);
        var keys: Keys = .fromSecret(suite, secret[0..suite.secretLen()]);

        var sealed: [128]u8 = undefined;
        const len = try keys.seal(&sealed, 42, "the header", "the payload");

        var out: [128]u8 = undefined;
        const opened = try keys.open(&out, 42, "the header", sealed[0..len]);
        try testing.expectEqualStrings("the payload", out[0..opened]);

        // After an update the same input must produce different ciphertext, and
        // the old keys must no longer open it — that is what makes the update
        // worth doing.
        var next = keys.update();
        var resealed: [128]u8 = undefined;
        const relen = try next.seal(&resealed, 42, "the header", "the payload");
        try testing.expect(!std.mem.eql(u8, sealed[0..len], resealed[0..relen]));
        try testing.expectError(
            error.DecryptionFailed,
            keys.open(&out, 42, "the header", resealed[0..relen]),
        );
    }
}

test "crypto: both endpoints derive the same Initial keys from the client's first id" {
    // §5.2. A server that derived from its own chosen connection ID would
    // produce keys the client cannot match, and the handshake would fail with
    // nothing but decryption errors to explain it.
    const dcid = hexBytes("0001020304050607");
    var from_client = InitialKeys.derive(&dcid);
    var from_server = InitialKeys.derive(&dcid);

    var sealed: [64]u8 = undefined;
    const len = try from_client.client.seal(&sealed, 0, "hdr", "client speaks");

    var out: [64]u8 = undefined;
    const opened = try from_server.client.open(&out, 0, "hdr", sealed[0..len]);
    try testing.expectEqualStrings("client speaks", out[0..opened]);

    // And the directions are not interchangeable: the server's keys cannot open
    // what the client's sealed.
    try testing.expectError(
        error.DecryptionFailed,
        from_server.server.open(&out, 0, "hdr", sealed[0..len]),
    );
}

test "crypto: RFC 9001 appendix A.3 server Initial, whole packet" {
    // The end-to-end vector: a real header, a real payload of ACK and CRYPTO
    // frames, and the exact bytes that must go on the wire. Every layer has to
    // be right for this to match — key derivation, nonce construction,
    // associated data, the AEAD itself, the sample offset and the mask.
    //
    // A.3 is used rather than A.2 because its payload is 99 bytes rather than
    // 1162, so it fits in a test without burying what is being asserted. It
    // exercises the same code path; the packet number length A.2 would add
    // (four bytes rather than two) is covered by its own test.
    const dcid = hexBytes("8394c8f03e515708");
    var keys = InitialKeys.derive(&dcid).server;

    const payload = hexBytes(
        "02000000000600405a020000560303ee" ++
            "fce7f7b37ba1d1632e96677825ddf739" ++
            "88cfc79825df566dc5430b9a045a1200" ++
            "130100002e00330024001d00209d3c94" ++
            "0d89690b84d08a60993c144eca684d10" ++
            "81287c834d5311bcf32bb9da1a002b00" ++
            "020304",
    );
    try testing.expectEqual(@as(usize, 99), payload.len);

    // The unprotected header §A.3 gives, ending in a two-byte packet number.
    const header = hexBytes("c1000000010008f067a5502a4262b50040750001");
    try testing.expectEqual(@as(usize, 20), header.len);
    const pn_offset = 18;
    const pn: u64 = 1;

    // The Length field says 117, which covers the packet number *and* the
    // payload and tag; the packet number is already inside `header`, so what
    // follows it is 99 + 16.
    var datagram: [20 + 99 + tag_len]u8 = undefined;
    @memcpy(datagram[0..header.len], &header);
    const written = try keys.seal(datagram[header.len..], pn, &header, &payload);
    try testing.expectEqual(@as(usize, 99 + tag_len), written);

    protectHeader(&datagram, pn_offset, 2, &keys.header);
    try testing.expectEqualSlices(
        u8,
        &hexBytes(
            "cf000000010008f067a5502a4262b500" ++
                "4075c0d95a482cd0991cd25b0aac406a" ++
                "5816b6394100f37a1c69797554780bb3" ++
                "8cc5a99f5ede4cf73c3ec2493a1839b3" ++
                "dbcba3f6ea46c5b7684df3548e7ddeb9" ++
                "c3bf9c73cc3f3bded74b562bfb19fb84" ++
                "022f8ef4cdd93795d77d06edbb7aaf2f" ++
                "58891850abbdca3d20398c276456cbc4" ++
                "2158407dd074ee",
        ),
        &datagram,
    );

    // The protected header §A.3 spells out separately, which pins the mask
    // rather than only the packet as a whole.
    try testing.expectEqualSlices(
        u8,
        &hexBytes("cf000000010008f067a5502a4262b5004075c0d9"),
        datagram[0..20],
    );

    // And the receive path recovers the payload from those exact bytes.
    const recovered_len = unprotectHeader(&datagram, pn_offset, &keys.header);
    try testing.expectEqual(@as(u4, 2), recovered_len);
    try testing.expectEqualSlices(u8, &header, datagram[0..20]);

    var out: [128]u8 = undefined;
    const opened = try keys.open(&out, pn, datagram[0..20], datagram[20..]);
    try testing.expectEqualSlices(u8, &payload, out[0..opened]);

    // The payload really is the frames §A.3 describes, which is what makes this
    // a test of the stack rather than of a hex string.
    const frame = @import("frame.zig");
    var rest: []const u8 = out[0..opened];
    const ack = try frame.parse(&rest);
    try testing.expectEqual(@as(u64, 0), ack.ack.largest);
    const crypto_frame = try frame.parse(&rest);
    try testing.expectEqual(@as(u64, 0), crypto_frame.crypto.offset);
    try testing.expectEqual(@as(usize, 90), crypto_frame.crypto.data.len);
    try testing.expectEqual(@as(usize, 0), rest.len);
}
