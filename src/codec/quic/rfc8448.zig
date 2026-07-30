//! RFC 8448 §3's "Simple 1-RTT Handshake" trace, transcribed once.
//!
//! Test data only, and it lives in its own file for one reason: the first
//! attempt at the Finished test transcribed the server's flight message by
//! message and got a boundary wrong, which cost more time to find than the test
//! was worth. Every vector now has exactly one copy, and the flight is stored as
//! the RFC gives it — one blob — with the messages cut back out by the code under
//! test rather than by hand here.
//!
//! The trace predates QUIC, so it has no `quic_transport_parameters` and its ALPN
//! is absent. That does not weaken it for the parts it does cover: the key
//! schedule, the transcript, Finished, the message framing, and the certificate
//! path are identical between TLS over TCP and TLS over QUIC. What QUIC changes
//! is which extensions are required, and those are tested against locally built
//! messages instead.

const std = @import("std");

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    // The server flight is 657 bytes, which is more comptime work than the
    // default quota allows.
    @setEvalBranchQuota(20_000);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

/// §3's ClientHello, 196 bytes including its handshake header.
pub const client_hello = hexBytes(
    "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303130201" ++
        "0000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400" ++
        "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b00" ++
        "03020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c" ++
        "00024001",
);

/// §3's ServerHello, 90 bytes.
pub const server_hello = hexBytes(
    "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024" ++
        "001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
);

/// The server's whole encrypted flight, 657 bytes: EncryptedExtensions,
/// Certificate, CertificateVerify and Finished, back to back exactly as §3
/// prints them. Consumers cut the messages out themselves.
pub const server_flight = hexBytes(
    "080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b5" ++
        "0001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a0603550403130372" ++
        "7361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372" ++
        "736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c" ++
        "0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0cc" ++
        "b0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a" ++
        "8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0" ++
        "300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594" ++
        "365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1" ++
        "fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4" ++
        "2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc" ++
        "90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671" ++
        "459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000" ++
        "209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718",
);

/// The client's ephemeral private key, so the exchange can be reproduced.
pub const client_private_key = hexBytes(
    "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005",
);

/// The ECDHE output §3 publishes, which the two keys above must produce.
pub const shared_secret = hexBytes(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d",
);

/// Published intermediate values from §3's key schedule.
pub const early_secret = hexBytes(
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
);
pub const derived_for_handshake = hexBytes(
    "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
);
pub const handshake_secret = hexBytes(
    "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
);
pub const hello_hash = hexBytes(
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
);
pub const client_handshake_secret = hexBytes(
    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
);
pub const server_handshake_secret = hexBytes(
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
);
pub const master_secret = hexBytes(
    "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
);
pub const server_verify_data = hexBytes(
    "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718",
);
pub const client_verify_data = hexBytes(
    "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61",
);
pub const client_application_secret = hexBytes(
    "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
);
pub const server_application_secret = hexBytes(
    "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
);
pub const exporter_secret = hexBytes(
    "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50",
);

/// The certificate's own validity window, from its DER: 2016-07-30T01:23:59Z to
/// 2026-07-30T01:23:59Z. Useful because that window has now closed, which makes
/// it a ready-made expiry case — and awkward for any verifier that reads the real
/// clock instead of taking one.
///
/// These two are asserted against the parsed certificate in `verify.zig` rather
/// than trusted, because the first attempt at them was ten days out and the only
/// symptom was an expiry test that quietly passed.
pub const certificate_not_before: i64 = 1469841839;
pub const certificate_not_after: i64 = 1785374639;

/// The common name in that certificate. There is no subjectAltName, which is
/// itself worth knowing: a modern verifier requires one.
pub const certificate_common_name = "rsa";

test {
    // The lengths §3 states, asserted so a transcription error is caught here
    // rather than as a mysterious failure in whatever uses these.
    try std.testing.expectEqual(@as(usize, 196), client_hello.len);
    try std.testing.expectEqual(@as(usize, 90), server_hello.len);
    try std.testing.expectEqual(@as(usize, 657), server_flight.len);

    // And that the two keys really produce the published secret, which checks
    // the three of them against each other rather than one at a time.
    const produced = try std.crypto.dh.X25519.scalarmult(
        client_private_key,
        server_hello[90 - 38 ..][0..32].*,
    );
    try std.testing.expectEqualSlices(u8, &shared_secret, &produced);
}
