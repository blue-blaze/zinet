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
    @setEvalBranchQuota(40_000);
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

// --- Record layer vectors (RFC 8448 §3, extracted mechanically from the RFC text) ---

/// §3: the ClientHello as sent on the wire — a plaintext handshake record, 201 bytes.
pub const record_client_hello = hexBytes(
    "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece70000061301" ++
        "13031302010000910000000b0009000006736572766572ff01000100000a00140012001d001700180019010001010102" ++
        "0103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529a" ++
        "af2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00" ++
        "020101001c00024001",
);

/// §3: the ServerHello record, plaintext, 95 bytes.
pub const record_server_hello = hexBytes(
    "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e269280013010000" ++
        "2e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
);

/// §3: the server flight (EE..Finished) as one protected record under the server handshake keys, 679 bytes.
pub const record_server_flight = hexBytes(
    "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca" ++
        "07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b" ++
        "d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c" ++
        "7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092" ++
        "8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a8" ++
        "9441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f" ++
        "4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a3" ++
        "6ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e" ++
        "1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052c" ++
        "f93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe" ++
        "5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb" ++
        "5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038" ++
        "ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd50278" ++
        "4016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e" ++
        "750edc53370d2b",
);

/// §3: the client Finished as a protected record under the client handshake keys, 58 bytes.
pub const record_client_finished = hexBytes(
    "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1c" ++
        "aeacab6867d726c40546",
);

/// §3: the NewSessionTicket as a protected record under the server application keys, 227 bytes.
pub const record_ticket = hexBytes(
    "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c758db289a" ++
        "015940252f55713e061dc13e078891a38efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e0" ++
        "9c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406f16e3fc181a77ca475840025db2f0a77" ++
        "f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74" ++
        "bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf15985684f",
);

/// §3: the NewSessionTicket handshake message itself, 205 bytes.
pub const ticket_payload = hexBytes(
    "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf" ++
        "1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827" ++
        "db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228" ++
        "bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934a" ++
        "e4d3570008002a000400000400",
);

/// §3: 50 application bytes under the client application keys, 72 bytes.
pub const record_client_data = hexBytes(
    "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b" ++
        "62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4",
);

/// §3: the same 50 bytes echoed under the server application keys, 72 bytes.
pub const record_server_data = hexBytes(
    "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8" ++
        "fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d",
);

/// §3: the client close_notify alert record, 24 bytes.
pub const record_client_alert = hexBytes(
    "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3",
);

/// §3: the server close_notify alert record, 24 bytes.
pub const record_server_alert = hexBytes(
    "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9",
);

/// §3: the 50 application-data bytes both sides send (0x00..0x31).
pub const app_payload = hexBytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" ++
        "3031",
);

/// §3: the server handshake write key ('tls13 key' from s hs traffic).
pub const server_handshake_key = hexBytes(
    "3fce516009c21727d0f2e4e86ee403bc",
);

/// §3: the server handshake write IV.
pub const server_handshake_iv = hexBytes(
    "5d313eb2671276ee13000b30",
);

/// §3: the client handshake write key.
pub const client_handshake_key = hexBytes(
    "dbfaa693d1762c5b666af5d950258d01",
);

/// §3: the client handshake write IV.
pub const client_handshake_iv = hexBytes(
    "5bd3c71b836e0b76bb73265f",
);

/// §3: the server application write key.
pub const server_application_key = hexBytes(
    "9f02283b6c9c07efc26bb9f2ac92e356",
);

/// §3: the server application write IV.
pub const server_application_iv = hexBytes(
    "cf782b88dd83549aadf1e984",
);

/// §3: the client application write key.
pub const client_application_key = hexBytes(
    "17422dda596ed5d9acd890e3c63f5051",
);

/// §3: the client application write IV.
pub const client_application_iv = hexBytes(
    "5b78923dee08579033e523d9",
);
