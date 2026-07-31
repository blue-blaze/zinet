//! A server's identity: its certificate chain and the private key that signs
//! CertificateVerify.
//!
//! This file exists because the standard library can *verify* every common
//! signature but can only *produce* ECDSA and Ed25519 ones —
//! `std.crypto.Certificate.rsa` has no signing half — and because nothing in
//! std parses a private key file at all. So the ASN.1 here is the minimum that
//! covers what `openssl req -newkey ec`/`-newkey ed25519` actually emit:
//! PKCS#8 (`PRIVATE KEY`) and SEC1 (`EC PRIVATE KEY`), plus a PEM walk for the
//! certificate chain. RSA keys are rejected with their own error, so the
//! upstream constraint is a diagnosis rather than a mystery.
//!
//! The DER element parser is std's own (`std.crypto.Certificate.der.Element`),
//! the same one certificate verification already trusts.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

const handshake = @import("../quic/handshake.zig");

pub const Error = error{
    /// No `-----BEGIN ...-----` block of the wanted label.
    PemBlockNotFound,
    PemMalformed,
    KeyMalformed,
    /// The key parsed but is a kind std cannot sign with. RSA lands here, and
    /// the error is deliberately specific: "use an ECDSA P-256 or Ed25519
    /// certificate" is actionable where "malformed" is not.
    UnsupportedKeyType,
    CertificateChainEmpty,
    SigningFailed,
} || Allocator.Error;

/// A private key std can sign with.
pub const PrivateKey = union(enum) {
    ecdsa_p256: EcdsaP256Sha256.KeyPair,
    ed25519: Ed25519.KeyPair,

    /// The TLS signature scheme this key produces (RFC 8446 §4.2.3).
    pub fn scheme(self: *const PrivateKey) handshake.SignatureScheme {
        return switch (self.*) {
            .ecdsa_p256 => .ecdsa_secp256r1_sha256,
            .ed25519 => .ed25519,
        };
    }

    pub const max_signature_len = EcdsaP256Sha256.Signature.der_encoded_length_max;

    /// Sign CertificateVerify content (`handshake.signatureContent`'s output).
    /// ECDSA goes to the wire DER-encoded, Ed25519 as its raw 64 bytes —
    /// each is what RFC 8446 §4.2.3 defines for the scheme.
    pub fn sign(self: *const PrivateKey, content: []const u8, dest: []u8) Error![]const u8 {
        switch (self.*) {
            .ecdsa_p256 => |key_pair| {
                const signature = key_pair.sign(content, null) catch return error.SigningFailed;
                var buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
                const encoded = signature.toDer(&buf);
                if (dest.len < encoded.len) return error.SigningFailed;
                @memcpy(dest[0..encoded.len], encoded);
                return dest[0..encoded.len];
            },
            .ed25519 => |key_pair| {
                const signature = key_pair.sign(content, null) catch return error.SigningFailed;
                const bytes = signature.toBytes();
                if (dest.len < bytes.len) return error.SigningFailed;
                @memcpy(dest[0..bytes.len], &bytes);
                return dest[0..bytes.len];
            },
        }
    }
};

/// Certificates in wire order (leaf first) plus the leaf's key.
pub const Identity = struct {
    /// DER blobs, each individually allocated; `deinit` frees them.
    certificates: []const []const u8,
    key: PrivateKey,

    /// Load from PEM text: every CERTIFICATE block in `certificate_pem` (leaf
    /// first, as every tool emits them) and the first private-key block in
    /// `key_pem`. The two arguments may be the same buffer — combined files
    /// are common.
    pub fn fromPem(
        gpa: Allocator,
        certificate_pem: []const u8,
        key_pem: []const u8,
    ) Error!Identity {
        var chain: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (chain.items) |item| gpa.free(item);
            chain.deinit(gpa);
        }

        var offset: usize = 0;
        while (nextPemBlock(certificate_pem[offset..], "CERTIFICATE")) |block| {
            offset += block.end;
            const decoded = try decodePemBody(gpa, block.body);
            errdefer gpa.free(decoded);
            try chain.append(gpa, decoded);
        }
        if (chain.items.len == 0) return error.CertificateChainEmpty;

        const key = try privateKeyFromPem(gpa, key_pem);

        return .{
            .certificates = try chain.toOwnedSlice(gpa),
            .key = key,
        };
    }

    pub fn deinit(self: *Identity, gpa: Allocator) void {
        for (self.certificates) |certificate| gpa.free(certificate);
        gpa.free(self.certificates);
        self.* = undefined;
    }
};

/// Parse whichever private-key PEM block appears first: PKCS#8 ("PRIVATE
/// KEY") or SEC1 ("EC PRIVATE KEY").
pub fn privateKeyFromPem(gpa: Allocator, pem: []const u8) Error!PrivateKey {
    if (nextPemBlock(pem, "PRIVATE KEY")) |block| {
        const decoded = try decodePemBody(gpa, block.body);
        defer gpa.free(decoded);
        return privateKeyFromPkcs8(decoded);
    }
    if (nextPemBlock(pem, "EC PRIVATE KEY")) |block| {
        const decoded = try decodePemBody(gpa, block.body);
        defer gpa.free(decoded);
        return privateKeyFromSec1(decoded);
    }
    return error.PemBlockNotFound;
}

// -- ASN.1 ------------------------------------------------------------------

// Object identifiers, as raw DER contents.
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
const oid_ed25519 = [_]u8{ 0x2b, 0x65, 0x70 }; // 1.3.101.112
const oid_rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 }; // 1.2.840.113549.1.1.1

fn slice(bytes: []const u8, element: der.Element) []const u8 {
    return bytes[element.slice.start..element.slice.end];
}

/// RFC 5958 OneAsymmetricKey (what "BEGIN PRIVATE KEY" contains):
/// SEQUENCE { version, SEQUENCE { algorithm OID, parameters? }, OCTET STRING }
fn privateKeyFromPkcs8(bytes: []const u8) Error!PrivateKey {
    const outer = der.Element.parse(bytes, 0) catch return error.KeyMalformed;
    const version = der.Element.parse(bytes, outer.slice.start) catch return error.KeyMalformed;
    const algorithm_seq = der.Element.parse(bytes, version.slice.end) catch return error.KeyMalformed;
    const algorithm = der.Element.parse(bytes, algorithm_seq.slice.start) catch return error.KeyMalformed;
    const algorithm_oid = slice(bytes, algorithm);
    const key_octets = der.Element.parse(bytes, algorithm_seq.slice.end) catch return error.KeyMalformed;
    const key_bytes = slice(bytes, key_octets);

    if (std.mem.eql(u8, algorithm_oid, &oid_ec_public_key)) {
        // Parameters name the curve; insist on P-256, the one we can sign.
        const parameters = der.Element.parse(bytes, algorithm.slice.end) catch return error.KeyMalformed;
        if (!std.mem.eql(u8, slice(bytes, parameters), &oid_prime256v1)) {
            return error.UnsupportedKeyType;
        }
        return privateKeyFromSec1(key_bytes);
    }
    if (std.mem.eql(u8, algorithm_oid, &oid_ed25519)) {
        // RFC 8410 §7: the key is an OCTET STRING inside the OCTET STRING.
        const inner = der.Element.parse(key_bytes, 0) catch return error.KeyMalformed;
        const seed = slice(key_bytes, inner);
        if (seed.len != Ed25519.KeyPair.seed_length) return error.KeyMalformed;
        const key_pair = Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch {
            return error.KeyMalformed;
        };
        return .{ .ed25519 = key_pair };
    }
    if (std.mem.eql(u8, algorithm_oid, &oid_rsa_encryption)) {
        // The named upstream constraint: std verifies RSA but cannot sign it.
        return error.UnsupportedKeyType;
    }
    return error.UnsupportedKeyType;
}

/// RFC 5915 ECPrivateKey (what "BEGIN EC PRIVATE KEY" contains, and what
/// PKCS#8 wraps for EC keys):
/// SEQUENCE { version 1, OCTET STRING key, [0] curve?, [1] public? }
fn privateKeyFromSec1(bytes: []const u8) Error!PrivateKey {
    const outer = der.Element.parse(bytes, 0) catch return error.KeyMalformed;
    const version = der.Element.parse(bytes, outer.slice.start) catch return error.KeyMalformed;
    const key_octets = der.Element.parse(bytes, version.slice.end) catch return error.KeyMalformed;
    const key_bytes = slice(bytes, key_octets);
    if (key_bytes.len != EcdsaP256Sha256.SecretKey.encoded_length) {
        return error.UnsupportedKeyType;
    }
    // A bare SEC1 file names its curve in [0]; when absent (PKCS#8 wrapping),
    // the outer algorithm already named it. When present, check it.
    var cursor = key_octets.slice.end;
    while (cursor < outer.slice.end) {
        const element = der.Element.parse(bytes, cursor) catch return error.KeyMalformed;
        if (element.identifier.class == .context_specific and
            @backingInt(element.identifier.tag) == 0)
        {
            if (!std.mem.eql(u8, slice(bytes, element), &oid_prime256v1)) {
                const inner = der.Element.parse(bytes, element.slice.start) catch
                    return error.KeyMalformed;
                if (!std.mem.eql(u8, slice(bytes, inner), &oid_prime256v1)) {
                    return error.UnsupportedKeyType;
                }
            }
        }
        cursor = element.slice.end;
    }

    const secret_key = EcdsaP256Sha256.SecretKey.fromBytes(key_bytes[0..32].*) catch {
        return error.KeyMalformed;
    };
    const key_pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key) catch {
        return error.KeyMalformed;
    };
    return .{ .ecdsa_p256 = key_pair };
}

// -- PEM ---------------------------------------------------------------------

const PemBlock = struct {
    /// Base64 text between the BEGIN and END lines, whitespace included.
    body: []const u8,
    /// Offset just past the END line, relative to the searched slice.
    end: usize,
};

fn nextPemBlock(text: []const u8, comptime label: []const u8) ?PemBlock {
    const begin_marker = "-----BEGIN " ++ label ++ "-----";
    const end_marker = "-----END " ++ label ++ "-----";
    const begin = std.mem.indexOf(u8, text, begin_marker) orelse return null;
    const body_start = begin + begin_marker.len;
    const end = std.mem.indexOfPos(u8, text, body_start, end_marker) orelse return null;
    return .{
        .body = text[body_start..end],
        .end = end + end_marker.len,
    };
}

fn decodePemBody(gpa: Allocator, body: []const u8) Error![]const u8 {
    var compact = try std.ArrayList(u8).initCapacity(gpa, body.len);
    defer compact.deinit(gpa);
    for (body) |char| {
        if (char == '\n' or char == '\r' or char == ' ' or char == '\t') continue;
        compact.appendAssumeCapacity(char);
    }
    const decoder = std.base64.standard.Decoder;
    const len = decoder.calcSizeForSlice(compact.items) catch return error.PemMalformed;
    const decoded = try gpa.alloc(u8, len);
    errdefer gpa.free(decoded);
    decoder.decode(decoded, compact.items) catch return error.PemMalformed;
    return decoded;
}

// -- Tests --------------------------------------------------------------------

const testing = std.testing;
const verify = @import("../quic/verify.zig");

// Test key material is *assembled* here from a raw scalar rather than pasted
// in as base64. Three reasons: what the parser is being fed is visible, no file
// in the repository has the shape of a deployed credential, and a home-made
// encoding could otherwise be a shape only this parser accepts. That last risk
// was checked rather than assumed — the three encodings below were written out
// and read back by `openssl pkey`/`openssl ec`, which reports exactly
// `test_scalar` as the private key and derives one public key from both EC
// forms.

const test_scalar: [32]u8 = .{
    0x0d, 0x2c, 0x1f, 0x37, 0x4b, 0x59, 0x66, 0x71, 0x8a, 0x93, 0xa5, 0xb2, 0xc4, 0xd1, 0xe8, 0xf3,
    0x02, 0x15, 0x24, 0x38, 0x47, 0x51, 0x63, 0x7a, 0x85, 0x9c, 0xab, 0xb7, 0xcd, 0xd9, 0xe4, 0xfb,
};

/// DER assembly for the tests, bottom-up: each element is written into its
/// own buffer and handed to the enclosing one. Deliberately *not* a
/// back-filling writer — the first attempt was, and shrinking a length prefix
/// to DER's short form moved the bytes an outer element had already recorded
/// an offset into. Composing upward has no offsets to invalidate.
fn derElement(dest: []u8, tag: u8, body: []const u8) []const u8 {
    std.debug.assert(body.len < 128); // Everything here is small; long form unused.
    dest[0] = tag;
    dest[1] = @intCast(body.len);
    @memcpy(dest[2..][0..body.len], body);
    return dest[0 .. 2 + body.len];
}

/// Same, for the one element that exceeds 127 bytes (the PKCS#8 wrapper).
fn derElementLong(dest: []u8, tag: u8, body: []const u8) []const u8 {
    if (body.len < 128) return derElement(dest, tag, body);
    std.debug.assert(body.len <= 255);
    dest[0] = tag;
    dest[1] = 0x81;
    dest[2] = @intCast(body.len);
    @memcpy(dest[3..][0..body.len], body);
    return dest[0 .. 3 + body.len];
}

fn concat(dest: []u8, parts: []const []const u8) []const u8 {
    var len: usize = 0;
    for (parts) |part| {
        @memcpy(dest[len..][0..part.len], part);
        len += part.len;
    }
    return dest[0..len];
}

fn testEcdsaKeyPair() EcdsaP256Sha256.KeyPair {
    const secret = EcdsaP256Sha256.SecretKey.fromBytes(test_scalar) catch unreachable;
    return EcdsaP256Sha256.KeyPair.fromSecretKey(secret) catch unreachable;
}

/// RFC 5915 ECPrivateKey. `with_parameters` adds the [0] curve OID that a bare
/// SEC1 file carries and a PKCS#8-wrapped one omits.
fn writeEcPrivateKey(dest: []u8, with_parameters: bool) []const u8 {
    var scratch: [256]u8 = undefined;
    var parts_buf: [4][]const u8 = undefined;
    var count: usize = 0;

    var version_buf: [8]u8 = undefined;
    parts_buf[count] = derElement(&version_buf, 0x02, &[_]u8{1});
    count += 1;

    var key_buf: [64]u8 = undefined;
    parts_buf[count] = derElement(&key_buf, 0x04, &test_scalar);
    count += 1;

    var params_buf: [32]u8 = undefined;
    if (with_parameters) {
        var oid_buf: [16]u8 = undefined;
        const oid = derElement(&oid_buf, 0x06, &oid_prime256v1);
        parts_buf[count] = derElement(&params_buf, 0xa0, oid);
        count += 1;
    }

    var public_buf: [96]u8 = undefined;
    var bitstring_buf: [80]u8 = undefined;
    {
        const sec1 = testEcdsaKeyPair().public_key.toUncompressedSec1();
        var padded: [66]u8 = undefined;
        padded[0] = 0; // BIT STRING's unused-bits count
        @memcpy(padded[1..][0..sec1.len], &sec1);
        const bitstring = derElement(&bitstring_buf, 0x03, padded[0 .. 1 + sec1.len]);
        parts_buf[count] = derElement(&public_buf, 0xa1, bitstring);
        count += 1;
    }

    const body = concat(&scratch, parts_buf[0..count]);
    return derElementLong(dest, 0x30, body);
}

/// RFC 5958 OneAsymmetricKey around the EC key above.
fn writePkcs8Ecdsa(dest: []u8) []const u8 {
    var version_buf: [8]u8 = undefined;
    const version = derElement(&version_buf, 0x02, &[_]u8{0});

    var algorithm_buf: [48]u8 = undefined;
    var oid1_buf: [16]u8 = undefined;
    var oid2_buf: [16]u8 = undefined;
    var alg_body_buf: [32]u8 = undefined;
    const algorithm = derElement(&algorithm_buf, 0x30, concat(&alg_body_buf, &.{
        derElement(&oid1_buf, 0x06, &oid_ec_public_key),
        derElement(&oid2_buf, 0x06, &oid_prime256v1),
    }));

    var ec_buf: [192]u8 = undefined;
    const ec = writeEcPrivateKey(&ec_buf, false);
    var octets_buf: [208]u8 = undefined;
    const octets = derElement(&octets_buf, 0x04, ec);

    var body_buf: [256]u8 = undefined;
    return derElementLong(dest, 0x30, concat(&body_buf, &.{ version, algorithm, octets }));
}

fn writeSec1Ecdsa(dest: []u8) []const u8 {
    return writeEcPrivateKey(dest, true);
}

/// RFC 8410 §7: the seed is an OCTET STRING inside the OCTET STRING.
fn writePkcs8Ed25519(dest: []u8, seed: [32]u8) []const u8 {
    var version_buf: [8]u8 = undefined;
    const version = derElement(&version_buf, 0x02, &[_]u8{0});

    var oid_buf: [16]u8 = undefined;
    var algorithm_buf: [24]u8 = undefined;
    const algorithm = derElement(&algorithm_buf, 0x30, derElement(&oid_buf, 0x06, &oid_ed25519));

    var inner_buf: [48]u8 = undefined;
    const inner = derElement(&inner_buf, 0x04, &seed);
    var octets_buf: [56]u8 = undefined;
    const octets = derElement(&octets_buf, 0x04, inner);

    var body_buf: [96]u8 = undefined;
    return derElement(dest, 0x30, concat(&body_buf, &.{ version, algorithm, octets }));
}

/// Wrap DER as PEM at run time, so the PEM path is covered without a
/// credential-shaped literal in the source.
fn toPem(gpa: Allocator, comptime label: []const u8, der_bytes: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const body_len = encoder.calcSize(der_bytes.len);
    const header = "-----BEGIN " ++ label ++ "-----\n";
    const footer = "\n-----END " ++ label ++ "-----\n";
    const out = try gpa.alloc(u8, header.len + body_len + footer.len);
    @memcpy(out[0..header.len], header);
    _ = encoder.encode(out[header.len..][0..body_len], der_bytes);
    @memcpy(out[header.len + body_len ..], footer);
    return out;
}

test "identity: PKCS#8 P-256 key loads and produces verifiable signatures" {
    const gpa = testing.allocator;
    var der_buf: [256]u8 = undefined;
    const pem = try toPem(gpa, "PRIVATE KEY", writePkcs8Ecdsa(&der_buf));
    defer gpa.free(pem);
    const key = try privateKeyFromPem(gpa, pem);
    try testing.expectEqual(handshake.SignatureScheme.ecdsa_secp256r1_sha256, key.scheme());

    // Sign, then verify with the public half through the same code path the
    // client uses for a real server (SEC1 uncompressed point).
    const content = "certificate verify content";
    var sig_buf: [PrivateKey.max_signature_len]u8 = undefined;
    const signature = try key.sign(content, &sig_buf);

    const public = key.ecdsa_p256.public_key;
    const public_sec1 = public.toUncompressedSec1();
    try verify.verifySignatureWithKey(
        .X9_62_id_ecPublicKey,
        &public_sec1,
        .ecdsa_secp256r1_sha256,
        signature,
        content,
    );
    // And a flipped byte fails.
    var bad: [PrivateKey.max_signature_len]u8 = undefined;
    @memcpy(bad[0..signature.len], signature);
    bad[signature.len - 1] ^= 1;
    try testing.expectError(error.CertificateVerifyFailed, verify.verifySignatureWithKey(
        .X9_62_id_ecPublicKey,
        &public_sec1,
        .ecdsa_secp256r1_sha256,
        bad[0..signature.len],
        content,
    ));
}

test "identity: Ed25519 PKCS#8 loads and signs" {
    const gpa = testing.allocator;
    var der_buf: [128]u8 = undefined;
    const pem = try toPem(gpa, "PRIVATE KEY", writePkcs8Ed25519(&der_buf, test_scalar));
    defer gpa.free(pem);
    const key = try privateKeyFromPem(gpa, pem);
    try testing.expectEqual(handshake.SignatureScheme.ed25519, key.scheme());

    const content = "certificate verify content";
    var sig_buf: [PrivateKey.max_signature_len]u8 = undefined;
    const signature = try key.sign(content, &sig_buf);
    try testing.expectEqual(@as(usize, 64), signature.len);

    const public = key.ed25519.public_key.toBytes();
    try verify.verifySignatureWithKey(
        .curveEd25519,
        &public,
        .ed25519,
        signature,
        content,
    );
}

test "identity: RSA keys are refused by name, not by confusion" {
    // A PKCS#8 header declaring rsaEncryption with a nonsense key body: the
    // algorithm OID alone must decide the error.
    var body: [64]u8 = undefined;
    var n: usize = 0;
    // SEQUENCE { INTEGER 0, SEQUENCE { OID rsaEncryption, NULL }, OCTET STRING {} }
    const inner_alg = [_]u8{ 0x06, 0x09 } ++ oid_rsa_encryption ++ [_]u8{ 0x05, 0x00 };
    const alg_seq = [_]u8{ 0x30, inner_alg.len } ++ inner_alg;
    const content = [_]u8{ 0x02, 0x01, 0x00 } ++ alg_seq ++ [_]u8{ 0x04, 0x00 };
    body[0] = 0x30;
    body[1] = content.len;
    @memcpy(body[2..][0..content.len], &content);
    n = 2 + content.len;

    try testing.expectError(error.UnsupportedKeyType, privateKeyFromPkcs8(body[0..n]));
}

test "identity: certificate chain loads leaf-first from concatenated PEM" {
    const gpa = testing.allocator;
    // Two tiny fake "certificates" — PEM structure is what is under test; the
    // DER inside is opaque to the loader.
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "AQID\n" ++
        "-----END CERTIFICATE-----\n" ++
        "junk between blocks is legal in PEM\n" ++
        "-----BEGIN CERTIFICATE-----\n" ++
        "BAUG\n" ++
        "-----END CERTIFICATE-----\n";
    var der_buf: [256]u8 = undefined;
    const key_pem = try toPem(gpa, "PRIVATE KEY", writePkcs8Ecdsa(&der_buf));
    defer gpa.free(key_pem);
    var identity = try Identity.fromPem(gpa, pem, key_pem);
    defer identity.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), identity.certificates.len);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, identity.certificates[0]);
    try testing.expectEqualSlices(u8, &.{ 4, 5, 6 }, identity.certificates[1]);
}

test "identity: SEC1 and PKCS#8 encodings of the same key agree" {
    const gpa = testing.allocator;
    var pkcs8_buf: [256]u8 = undefined;
    var sec1_buf: [256]u8 = undefined;
    const pkcs8_pem = try toPem(gpa, "PRIVATE KEY", writePkcs8Ecdsa(&pkcs8_buf));
    defer gpa.free(pkcs8_pem);
    const sec1_pem = try toPem(gpa, "EC PRIVATE KEY", writeSec1Ecdsa(&sec1_buf));
    defer gpa.free(sec1_pem);
    const from_pkcs8 = try privateKeyFromPem(gpa, pkcs8_pem);
    const from_sec1 = try privateKeyFromPem(gpa, sec1_pem);
    try testing.expectEqualSlices(
        u8,
        &from_pkcs8.ecdsa_p256.public_key.toUncompressedSec1(),
        &from_sec1.ecdsa_p256.public_key.toUncompressedSec1(),
    );
}

test "identity: missing blocks are their own error" {
    const gpa = testing.allocator;
    try testing.expectError(
        error.PemBlockNotFound,
        privateKeyFromPem(gpa, "no keys here"),
    );
    var der_buf: [256]u8 = undefined;
    const key_pem = try toPem(gpa, "PRIVATE KEY", writePkcs8Ecdsa(&der_buf));
    defer gpa.free(key_pem);
    try testing.expectError(
        error.CertificateChainEmpty,
        Identity.fromPem(gpa, "no certs", key_pem),
    );
}
