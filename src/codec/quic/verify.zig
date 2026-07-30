//! Certificate chain and CertificateVerify validation for the QUIC handshake.
//!
//! RFC 9001 §4.4 leaves authentication to TLS, and RFC 8446 §4.4.2 and §4.4.3
//! define what has to be checked. Both parts are here because they answer the
//! same question — is this the peer it claims to be — and skipping either one
//! makes the other pointless: a valid chain with an unverified
//! CertificateVerify authenticates whoever relayed the certificate rather than
//! whoever holds its key.
//!
//! `std.crypto.Certificate` does the heavy lifting: DER parsing, name matching,
//! chain signatures and the RSA and ECDSA primitives are all there. What it does
//! not do is dispatch a TLS 1.3 CertificateVerify, because that dispatch lives
//! inside `tls.Client`'s state machine rather than in a callable function.
//!
//! **Time is a parameter.** Every validity check takes `now_sec`, because a
//! verifier that reads the clock cannot be tested at both edges of a validity
//! window — and because the rest of this framework injects its clock too.

const std = @import("std");
const assert = std.debug.assert;
const Certificate = std.crypto.Certificate;

const handshake = @import("handshake.zig");

pub const Error = error{
    /// The chain was empty. §4.4.2 requires at least the end-entity certificate.
    CertificateChainEmpty,
    /// More certificates than any legitimate chain. Bounded because the peer is
    /// not yet authenticated and each entry costs a parse.
    CertificateChainTooLong,
    /// The signature over the transcript did not verify, so whoever sent this
    /// does not hold the certificate's private key. §4.4.3.
    CertificateVerifyFailed,
    /// The scheme in CertificateVerify does not match the certificate's key
    /// type, or is one this implementation does not accept.
    UnsupportedSignatureScheme,
    /// An RSA modulus of a size the standard library's dispatch does not cover.
    UnsupportedKeySize,
};

/// §4.4.2 sets no limit, but an unauthenticated peer should not be able to make
/// us parse an unbounded chain. Ten is far beyond any real deployment.
pub const max_chain_len = 10;

/// How much to trust, and against what.
pub const Options = struct {
    /// The trust anchors. Null skips chain verification entirely, which is only
    /// for tests and for peers authenticated some other way — it is spelled as an
    /// explicit null rather than defaulted, so that no caller gets it by accident.
    bundle: ?*const Certificate.Bundle,
    /// The name to match against the certificate. Empty skips name checking,
    /// which is separate from trust: a certificate can be perfectly valid and
    /// simply be for somebody else.
    host: []const u8,
    /// Seconds since the Unix epoch, injected.
    now_sec: i64,
};

/// The end-entity certificate, parsed, plus what is needed to verify a signature
/// with it.
pub const Peer = struct {
    parsed: Certificate.Parsed,

    pub fn commonName(self: *const Peer) []const u8 {
        return self.parsed.commonName();
    }

    pub fn publicKey(self: *const Peer) []const u8 {
        return self.parsed.pubKey();
    }

    pub fn algorithm(self: *const Peer) Certificate.AlgorithmCategory {
        return self.parsed.pub_key_algo;
    }
};

/// Verify a Certificate message body and return the end-entity certificate.
///
/// The chain is walked in order, each certificate verified as signed by the next
/// (§4.4.2 requires that order), and the last one checked against the trust
/// anchors. The end-entity certificate's name is matched separately, because a
/// name mismatch and an untrusted issuer are different failures and conflating
/// them makes the error useless.
pub fn verifyChain(certificate_message_body: []const u8, options: Options) !Peer {
    var iterator = try handshake.CertificateIterator.init(certificate_message_body);

    var chain: [max_chain_len]Certificate.Parsed = undefined;
    var count: usize = 0;
    while (try iterator.next()) |der| {
        if (count == max_chain_len) return error.CertificateChainTooLong;
        const certificate: Certificate = .{ .buffer = der, .index = 0 };
        chain[count] = try certificate.parse();
        count += 1;
    }
    if (count == 0) return error.CertificateChainEmpty;

    const end_entity = chain[0];

    if (options.host.len > 0) try end_entity.verifyHostName(options.host);

    if (options.bundle) |bundle| {
        // Each certificate is signed by the next one along, which also checks
        // each one's validity window against `now_sec`.
        var i: usize = 0;
        while (i + 1 < count) : (i += 1) {
            try chain[i].verify(chain[i + 1], options.now_sec);
        }
        // And the last one has to be signed by something we already trust.
        try bundle.verify(chain[count - 1], options.now_sec);
    } else {
        // Without anchors there is no chain to walk, but the end-entity
        // certificate's own validity window still means something.
        if (options.now_sec < @as(i64, @intCast(end_entity.validity.not_before))) {
            return error.CertificateNotYetValid;
        }
        if (options.now_sec > @as(i64, @intCast(end_entity.validity.not_after))) {
            return error.CertificateExpired;
        }
    }

    return .{ .parsed = end_entity };
}

/// Verify a CertificateVerify signature (§4.4.3).
///
/// `content` is what `handshake.signatureContent` produced: 64 spaces, the
/// context string, a zero byte and the transcript hash. Those spaces are why a
/// signature cannot be moved between contexts, so the caller building the wrong
/// content is a real failure mode rather than a theoretical one.
pub fn verifySignature(
    peer: *const Peer,
    scheme: handshake.SignatureScheme,
    signature: []const u8,
    content: []const u8,
) !void {
    // §4.4.3: the scheme has to match the key. A certificate with an ECDSA key
    // cannot produce an RSA signature, and accepting the mismatch would mean
    // verifying against a key type the certificate never committed to.
    const expected_algorithm: Certificate.AlgorithmCategory = switch (scheme) {
        .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => .X9_62_id_ecPublicKey,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        => .rsaEncryption,
        .ed25519 => .curveEd25519,
        _ => return error.UnsupportedSignatureScheme,
    };
    if (peer.algorithm() != expected_algorithm) return error.UnsupportedSignatureScheme;

    const public_key = peer.publicKey();

    switch (scheme) {
        inline .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => |comptime_scheme| {
            const Ecdsa = switch (comptime_scheme) {
                .ecdsa_secp256r1_sha256 => std.crypto.sign.ecdsa.EcdsaP256Sha256,
                .ecdsa_secp384r1_sha384 => std.crypto.sign.ecdsa.EcdsaP384Sha384,
                else => unreachable,
            };
            const sig = Ecdsa.Signature.fromDer(signature) catch return error.CertificateVerifyFailed;
            const key = Ecdsa.PublicKey.fromSec1(public_key) catch return error.CertificateVerifyFailed;
            var verifier = sig.verifier(key) catch return error.CertificateVerifyFailed;
            verifier.update(content);
            verifier.verify() catch return error.CertificateVerifyFailed;
        },
        inline .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        => |comptime_scheme| {
            const Signature = switch (comptime_scheme) {
                .rsa_pss_rsae_sha256,
                .rsa_pss_rsae_sha384,
                .rsa_pss_rsae_sha512,
                => Certificate.rsa.PSSSignature,
                else => Certificate.rsa.PKCS1v1_5Signature,
            };
            const Hash = switch (comptime_scheme) {
                .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => std.crypto.hash.sha2.Sha256,
                .rsa_pss_rsae_sha384, .rsa_pkcs1_sha384 => std.crypto.hash.sha2.Sha384,
                else => std.crypto.hash.sha2.Sha512,
            };
            const components = Certificate.rsa.PublicKey.parseDer(public_key) catch
                return error.CertificateVerifyFailed;
            switch (components.modulus.len) {
                inline 128, 256, 384, 512 => |modulus_len| {
                    if (signature.len != modulus_len) return error.CertificateVerifyFailed;
                    const key = Certificate.rsa.PublicKey.fromBytes(
                        components.exponent,
                        components.modulus,
                    ) catch return error.CertificateVerifyFailed;
                    const sig = Signature.fromBytes(modulus_len, signature);
                    Signature.verify(modulus_len, sig, content, key, Hash) catch
                        return error.CertificateVerifyFailed;
                },
                else => return error.UnsupportedKeySize,
            }
        },
        .ed25519 => {
            const Ed25519 = std.crypto.sign.Ed25519;
            if (signature.len != Ed25519.Signature.encoded_length) return error.CertificateVerifyFailed;
            if (public_key.len != Ed25519.PublicKey.encoded_length) return error.CertificateVerifyFailed;
            const sig: Ed25519.Signature = .fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            const key = Ed25519.PublicKey.fromBytes(
                public_key[0..Ed25519.PublicKey.encoded_length].*,
            ) catch return error.CertificateVerifyFailed;
            var verifier = sig.verifier(key) catch return error.CertificateVerifyFailed;
            verifier.update(content);
            verifier.verify() catch return error.CertificateVerifyFailed;
        },
        _ => return error.UnsupportedSignatureScheme,
    }
}

const testing = std.testing;
const vectors = @import("rfc8448.zig");
const tls = @import("tls.zig");

/// Pull one message of a given type out of RFC 8448's server flight.
fn flightMessage(want: tls.MessageType) !tls.Message {
    var rest: []const u8 = &vectors.server_flight;
    while (try tls.nextMessage(rest)) |message| {
        if (message.type == want) return message;
        rest = rest[message.raw.len..];
    }
    return error.CertificateChainEmpty;
}

test "verify: RFC 8448's certificate parses, and its name and window are checked" {
    const certificate_message = try flightMessage(.certificate);

    // No trust anchors: this certificate is self-signed and in nobody's store,
    // so what is being checked here is parsing, naming and validity.
    const inside_window = vectors.certificate_not_before + 1000;
    const peer = try verifyChain(certificate_message.body, .{
        .bundle = null,
        .host = vectors.certificate_common_name,
        .now_sec = inside_window,
    });
    try testing.expectEqualStrings(vectors.certificate_common_name, peer.commonName());
    try testing.expectEqual(Certificate.AlgorithmCategory.rsaEncryption, peer.algorithm());

    // The window the vectors claim must be the window the DER actually holds.
    // Without this the expiry cases below can pass by testing nothing, which is
    // exactly what happened when the constant was first written ten days out.
    try testing.expectEqual(vectors.certificate_not_before, @as(i64, @intCast(peer.parsed.validity.not_before)));
    try testing.expectEqual(vectors.certificate_not_after, @as(i64, @intCast(peer.parsed.validity.not_after)));

    // A different name must not match. This is a separate failure from an
    // untrusted issuer, and conflating them is what makes "certificate error"
    // useless to diagnose.
    try testing.expectError(error.CertificateHostMismatch, verifyChain(certificate_message.body, .{
        .bundle = null,
        .host = "example.com",
        .now_sec = inside_window,
    }));

    // Both edges of the validity window, which is only testable because the
    // clock is a parameter. This certificate's window has in fact now closed,
    // which is why a verifier reading the real clock would fail here for a
    // reason unrelated to what it is testing.
    try testing.expectError(error.CertificateNotYetValid, verifyChain(certificate_message.body, .{
        .bundle = null,
        .host = vectors.certificate_common_name,
        .now_sec = vectors.certificate_not_before - 1,
    }));
    try testing.expectError(error.CertificateExpired, verifyChain(certificate_message.body, .{
        .bundle = null,
        .host = vectors.certificate_common_name,
        .now_sec = vectors.certificate_not_after + 1,
    }));
}

test "verify: RFC 8448's real CertificateVerify signature" {
    // The end-to-end check for authentication: a genuine RSA-PSS signature over
    // a transcript this code computed itself. Every layer has to agree — the
    // transcript hash, §4.4.3's content prefix, the DER of the signature, and the
    // public key out of the certificate.
    var schedule: tls.Schedule = .init(.aes_128_gcm_sha256);
    schedule.addMessage(&vectors.client_hello);
    schedule.addMessage(&vectors.server_hello);

    const certificate_message = try flightMessage(.certificate);
    const verify_message = try flightMessage(.certificate_verify);

    // The transcript CertificateVerify signs is everything up to and including
    // the Certificate message.
    var rest: []const u8 = &vectors.server_flight;
    while (try tls.nextMessage(rest)) |message| {
        if (message.type == .certificate_verify) break;
        schedule.addMessage(message.raw);
        rest = rest[message.raw.len..];
    }
    const transcript_hash = schedule.transcript.peek();

    var content_buf: [256]u8 = undefined;
    const content = handshake.signatureContent(
        &content_buf,
        handshake.server_signature_context,
        transcript_hash[0..32],
    );

    const parsed = try handshake.parseCertificateVerify(verify_message.body);
    try testing.expectEqual(handshake.SignatureScheme.rsa_pss_rsae_sha256, parsed.scheme);
    try testing.expectEqual(@as(usize, 128), parsed.signature.len); // 1024-bit key

    const peer = try verifyChain(certificate_message.body, .{
        .bundle = null,
        .host = vectors.certificate_common_name,
        .now_sec = vectors.certificate_not_before + 1000,
    });

    try verifySignature(&peer, parsed.scheme, parsed.signature, content);

    // A single flipped bit anywhere must fail: in the signature, and in the
    // content. The second is the one that matters most, because it is what stops
    // a captured signature being replayed over a different handshake.
    var tampered_signature: [128]u8 = parsed.signature[0..128].*;
    tampered_signature[64] ^= 1;
    try testing.expectError(error.CertificateVerifyFailed, verifySignature(
        &peer,
        parsed.scheme,
        &tampered_signature,
        content,
    ));

    var tampered_content: [256]u8 = undefined;
    @memcpy(tampered_content[0..content.len], content);
    tampered_content[content.len - 1] ^= 1;
    try testing.expectError(error.CertificateVerifyFailed, verifySignature(
        &peer,
        parsed.scheme,
        parsed.signature,
        tampered_content[0..content.len],
    ));
}

test "verify: the signature scheme must match the certificate's key type" {
    // §4.4.3. Accepting a mismatch would mean verifying against a key type the
    // certificate never committed to, which is a signature forgery waiting to
    // happen rather than a compatibility nicety.
    const certificate_message = try flightMessage(.certificate);
    const peer = try verifyChain(certificate_message.body, .{
        .bundle = null,
        .host = vectors.certificate_common_name,
        .now_sec = vectors.certificate_not_before + 1000,
    });
    try testing.expectEqual(Certificate.AlgorithmCategory.rsaEncryption, peer.algorithm());

    const signature: [64]u8 = @splat(0);
    var content: [128]u8 = @splat(0);

    // The certificate holds an RSA key, so an ECDSA scheme is refused before any
    // signature maths happens.
    try testing.expectError(error.UnsupportedSignatureScheme, verifySignature(
        &peer,
        .ecdsa_secp256r1_sha256,
        &signature,
        &content,
    ));
    try testing.expectError(error.UnsupportedSignatureScheme, verifySignature(
        &peer,
        .ed25519,
        &signature,
        &content,
    ));
    // And a scheme with no name at all.
    try testing.expectError(error.UnsupportedSignatureScheme, verifySignature(
        &peer,
        @fromBackingInt(@intCast(0xfefe)),
        &signature,
        &content,
    ));
}

test "verify: the wrong signature context does not verify" {
    // §4.4.3's context string is what separates a server's signature from a
    // client's over the same transcript. Using the client's context to check a
    // server's signature must fail, or the two roles are interchangeable.
    var schedule: tls.Schedule = .init(.aes_128_gcm_sha256);
    schedule.addMessage(&vectors.client_hello);
    schedule.addMessage(&vectors.server_hello);
    var rest: []const u8 = &vectors.server_flight;
    while (try tls.nextMessage(rest)) |message| {
        if (message.type == .certificate_verify) break;
        schedule.addMessage(message.raw);
        rest = rest[message.raw.len..];
    }
    const transcript_hash = schedule.transcript.peek();

    var buf: [256]u8 = undefined;
    const wrong_content = handshake.signatureContent(
        &buf,
        handshake.client_signature_context,
        transcript_hash[0..32],
    );

    const certificate_message = try flightMessage(.certificate);
    const verify_message = try flightMessage(.certificate_verify);
    const parsed = try handshake.parseCertificateVerify(verify_message.body);
    const peer = try verifyChain(certificate_message.body, .{
        .bundle = null,
        .host = vectors.certificate_common_name,
        .now_sec = vectors.certificate_not_before + 1000,
    });

    try testing.expectError(error.CertificateVerifyFailed, verifySignature(
        &peer,
        parsed.scheme,
        parsed.signature,
        wrong_content,
    ));
}

test "verify: an empty chain is refused" {
    // §4.4.2 requires at least the end-entity certificate. An empty chain would
    // otherwise reach `chain[0]` on an uninitialised entry.
    var buf: [16]u8 = undefined;
    var builder: handshake.Builder = .init(&buf);
    builder.byte(0); // empty request context
    const list = builder.begin24();
    builder.end(list); // and an empty list

    try testing.expectError(error.CertificateChainEmpty, verifyChain(builder.written(), .{
        .bundle = null,
        .host = "",
        .now_sec = 0,
    }));
}
