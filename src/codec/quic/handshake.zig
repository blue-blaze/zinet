//! TLS 1.3 handshake messages and extensions, RFC 8446 §4, with the
//! QUIC-specific requirements of RFC 9001 §8.
//!
//! Separate from `tls.zig` because the key schedule is arithmetic over secrets
//! while this is wire format, and the two fail in different ways: a schedule
//! error produces keys that cannot decrypt, a format error produces a peer that
//! rejects the handshake with an alert.
//!
//! **Nested length prefixes get their own abstraction.** TLS nests
//! length-prefixed blocks four deep in places — a ClientHello's extensions
//! block contains a key_share extension containing a share list containing a
//! share — and writing those lengths by hand means computing each one before
//! knowing what goes in it. `Builder` reserves the space and fills it in on
//! close, so a length can never disagree with what follows it. That mismatch is
//! the single most common way a hand-written ClientHello fails, and it fails as
//! "the server hung up" rather than as anything diagnosable.

const std = @import("std");
const assert = std.debug.assert;
const std_tls = std.crypto.tls;

const quic_crypto = @import("crypto.zig");
const tls = @import("tls.zig");

pub const X25519 = std.crypto.dh.X25519;

pub const Error = error{
    /// A field ran past the end of the message.
    HandshakeTruncated,
    /// A field is present but cannot mean what it says: a length prefix that
    /// disagrees with its container, a list with a partial element.
    HandshakeMalformed,
    /// §4.1.3: the server chose a version other than TLS 1.3. Fatal, because
    /// RFC 9001 §4.2 requires terminating rather than falling back.
    UnsupportedVersion,
    /// §4.1.3: the server chose a cipher suite that was not offered, or one with
    /// no QUIC header protection scheme (RFC 9001 §5.4.1 excludes
    /// TLS_AES_128_CCM_8_SHA256).
    UnsupportedCipherSuite,
    /// The server's key_share names a group that was not offered.
    UnsupportedGroup,
    /// §8.1 of RFC 9001: an ALPN mismatch must close the connection with
    /// no_application_protocol. Unlike TLS over TCP, this is not optional.
    NoApplicationProtocol,
    /// A required extension was absent: key_share or supported_versions in a
    /// ServerHello, quic_transport_parameters in either direction (RFC 9001 §8.2).
    MissingExtension,
    /// §4.1.2: a ClientHello field QUIC forbids, such as a non-empty
    /// legacy_session_id (RFC 9001 §8.4).
    IllegalParameter,
};

/// §4.2, plus RFC 9001 §8.2's codepoint. Non-exhaustive because §4.2 requires
/// ignoring unknown extensions rather than failing on them — the opposite of
/// QUIC's own rule for frame types, and worth noticing when moving between the
/// two layers of this same connection.
pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    alpn = 16,
    supported_versions = 43,
    psk_key_exchange_modes = 45,
    key_share = 51,
    /// RFC 9001 §8.2, IANA codepoint 57. Carries RFC 9000 §18's transport
    /// parameters as opaque bytes: TLS transports them and does not interpret
    /// them, which is why this module treats them as a blob.
    quic_transport_parameters = 57,
    _,
};

/// §B.4. Only the three suites QUIC can use: RFC 9001 §5.4.1 defines no header
/// protection for TLS_AES_128_CCM_8_SHA256, and §5.3 forbids negotiating a suite
/// without one.
pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
    _,

    pub fn toSuite(self: CipherSuite) ?quic_crypto.Suite {
        return switch (self) {
            .aes_128_gcm_sha256 => .aes_128_gcm_sha256,
            .aes_256_gcm_sha384 => .aes_256_gcm_sha384,
            .chacha20_poly1305_sha256 => .chacha20_poly1305_sha256,
            _ => null,
        };
    }
};

pub const NamedGroup = enum(u16) {
    x25519 = 0x001d,
    secp256r1 = 0x0017,
    _,
};

pub const SignatureScheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    _,
};

pub const tls_1_2_legacy: u16 = 0x0303;
pub const tls_1_3: u16 = 0x0304;
pub const random_len = 32;

/// §4.1.4: a HelloRetryRequest is a ServerHello whose random is this exact
/// value. Not a separate message type, which is why a parser that switches on
/// the type alone silently treats a retry as a real ServerHello and then fails
/// to derive keys.
pub const hello_retry_request_random = std_tls.hello_retry_request_sequence;

/// Writes length-prefixed structures without computing lengths in advance.
///
/// Every `begin*` reserves the prefix and returns a marker; the matching `end`
/// backfills it. So a length is derived from what was actually written rather
/// than from a separate calculation that can drift out of step with it.
pub const Builder = struct {
    buf: []u8,
    len: usize = 0,

    pub const Marker = struct { at: usize, width: u2 };

    pub fn init(buf: []u8) Builder {
        return .{ .buf = buf };
    }

    pub fn written(self: *const Builder) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn byte(self: *Builder, value: u8) void {
        assert(self.len < self.buf.len);
        self.buf[self.len] = value;
        self.len += 1;
    }

    pub fn int16(self: *Builder, value: u16) void {
        assert(self.len + 2 <= self.buf.len);
        std.mem.writeInt(u16, self.buf[self.len..][0..2], value, .big);
        self.len += 2;
    }

    pub fn bytes(self: *Builder, value: []const u8) void {
        assert(self.len + value.len <= self.buf.len);
        @memcpy(self.buf[self.len..][0..value.len], value);
        self.len += value.len;
    }

    pub fn beginByte(self: *Builder) Marker {
        const marker: Marker = .{ .at = self.len, .width = 1 };
        self.byte(0);
        return marker;
    }

    pub fn begin16(self: *Builder) Marker {
        const marker: Marker = .{ .at = self.len, .width = 2 };
        self.int16(0);
        return marker;
    }

    pub fn begin24(self: *Builder) Marker {
        const marker: Marker = .{ .at = self.len, .width = 3 };
        self.byte(0);
        self.byte(0);
        self.byte(0);
        return marker;
    }

    pub fn end(self: *Builder, marker: Marker) void {
        const body_len = self.len - marker.at - marker.width;
        switch (marker.width) {
            1 => {
                assert(body_len <= std.math.maxInt(u8));
                self.buf[marker.at] = @intCast(body_len);
            },
            2 => {
                assert(body_len <= std.math.maxInt(u16));
                std.mem.writeInt(u16, self.buf[marker.at..][0..2], @intCast(body_len), .big);
            },
            3 => {
                assert(body_len <= std.math.maxInt(u24));
                self.buf[marker.at] = @intCast((body_len >> 16) & 0xff);
                self.buf[marker.at + 1] = @intCast((body_len >> 8) & 0xff);
                self.buf[marker.at + 2] = @intCast(body_len & 0xff);
            },
            else => unreachable,
        }
    }

    /// An extension is a type and a length-prefixed body, which is common enough
    /// to deserve its own pair.
    pub fn beginExtension(self: *Builder, extension: ExtensionType) Marker {
        self.int16(@backingInt(extension));
        return self.begin16();
    }
};

/// Reads length-prefixed structures, refusing anything that runs past its
/// container.
pub const Reader = struct {
    rest: []const u8,

    pub fn init(bytes: []const u8) Reader {
        return .{ .rest = bytes };
    }

    pub fn int24(self: *Reader) Error!usize {
        if (self.rest.len < 3) return error.HandshakeTruncated;
        const value = (@as(usize, self.rest[0]) << 16) |
            (@as(usize, self.rest[1]) << 8) | self.rest[2];
        self.rest = self.rest[3..];
        return value;
    }

    /// A block whose length is three bytes, which §4.4.2 uses for certificates.
    pub fn block24(self: *Reader) Error![]const u8 {
        return self.take(try self.int24());
    }

    pub fn byte(self: *Reader) Error!u8 {
        if (self.rest.len < 1) return error.HandshakeTruncated;
        const value = self.rest[0];
        self.rest = self.rest[1..];
        return value;
    }

    pub fn int16(self: *Reader) Error!u16 {
        if (self.rest.len < 2) return error.HandshakeTruncated;
        const value = std.mem.readInt(u16, self.rest[0..2], .big);
        self.rest = self.rest[2..];
        return value;
    }

    pub fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.rest.len < n) return error.HandshakeTruncated;
        const value = self.rest[0..n];
        self.rest = self.rest[n..];
        return value;
    }

    /// A block whose length is a single byte.
    pub fn blockByte(self: *Reader) Error![]const u8 {
        return self.take(try self.byte());
    }

    /// A block whose length is two bytes.
    pub fn block16(self: *Reader) Error![]const u8 {
        return self.take(try self.int16());
    }

    pub fn empty(self: *const Reader) bool {
        return self.rest.len == 0;
    }
};

/// One extension, borrowed from the message.
pub const Extension = struct {
    type: ExtensionType,
    body: []const u8,
};

/// Walks an extensions block. §4.2 requires unknown extensions be ignored, so
/// the caller matches on what it knows and skips the rest — which is what makes
/// greasing safe.
pub const ExtensionIterator = struct {
    reader: Reader,

    pub fn next(self: *ExtensionIterator) Error!?Extension {
        if (self.reader.empty()) return null;
        const extension_type = try self.reader.int16();
        const body = try self.reader.block16();
        return .{ .type = @fromBackingInt(@intCast(extension_type)), .body = body };
    }
};

/// What a client offers. The caller supplies randomness and the key share,
/// because neither is this module's to invent — and because injecting them is
/// what makes a ClientHello reproducible in a test.
pub const ClientHelloOptions = struct {
    random: [random_len]u8,
    /// The X25519 public key. One group is offered rather than several: a second
    /// share costs a round trip's worth of bytes in every handshake to avoid a
    /// HelloRetryRequest that x25519-capable servers never send.
    key_share: [X25519.public_length]u8,
    /// Sent as SNI, and later checked against the certificate. Empty omits the
    /// extension, which is legal but means no name can be verified.
    server_name: []const u8 = &.{},
    /// RFC 9001 §8.1 makes this mandatory *for QUIC*; over TCP it is ordinary
    /// ALPN and an empty list omits the extension. Most preferred first.
    alpn: []const []const u8,
    /// RFC 9000 §18's encoded transport parameters, opaque here. Null omits
    /// the extension, which is what a ClientHello over TCP must do — the
    /// extension's presence is what tells the peer it is speaking QUIC.
    transport_parameters: ?[]const u8,
};

/// Bytes a ClientHello needs, before its variable parts.
pub const client_hello_overhead = 512;

/// Write a ClientHello, header included, and return it.
pub fn writeClientHello(dest: []u8, options: ClientHelloOptions) []const u8 {
    var builder: Builder = .init(dest);

    builder.byte(@backingInt(tls.MessageType.client_hello));
    const message = builder.begin24();

    // §4.1.2: legacy_version is always 0x0303 in TLS 1.3; the real version is in
    // supported_versions.
    builder.int16(tls_1_2_legacy);
    builder.bytes(&options.random);

    // RFC 9001 §8.4: middlebox compatibility mode is prohibited, so the session
    // id is empty rather than the 32 random bytes TLS over TCP sends. A server
    // that sees a non-empty one here would also expect a ChangeCipherSpec.
    builder.byte(0);

    {
        const suites = builder.begin16();
        builder.int16(@backingInt(CipherSuite.aes_128_gcm_sha256));
        builder.int16(@backingInt(CipherSuite.aes_256_gcm_sha384));
        builder.int16(@backingInt(CipherSuite.chacha20_poly1305_sha256));
        builder.end(suites);
    }

    // §4.1.2: exactly one compression method, "null".
    builder.byte(1);
    builder.byte(0);

    {
        const extensions = builder.begin16();

        if (options.server_name.len > 0) {
            const ext = builder.beginExtension(.server_name);
            const list = builder.begin16();
            builder.byte(0); // name_type: host_name
            const name = builder.begin16();
            builder.bytes(options.server_name);
            builder.end(name);
            builder.end(list);
            builder.end(ext);
        }

        {
            const ext = builder.beginExtension(.supported_versions);
            const list = builder.beginByte();
            builder.int16(tls_1_3);
            builder.end(list);
            builder.end(ext);
        }

        {
            const ext = builder.beginExtension(.supported_groups);
            const list = builder.begin16();
            builder.int16(@backingInt(NamedGroup.x25519));
            builder.end(list);
            builder.end(ext);
        }

        {
            const ext = builder.beginExtension(.signature_algorithms);
            const list = builder.begin16();
            for ([_]SignatureScheme{
                .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384,
                .rsa_pss_rsae_sha256,
                .rsa_pss_rsae_sha384,
                .rsa_pss_rsae_sha512,
                .ed25519,
                .rsa_pkcs1_sha256,
                .rsa_pkcs1_sha384,
                .rsa_pkcs1_sha512,
            }) |scheme| builder.int16(@backingInt(scheme));
            builder.end(list);
            builder.end(ext);
        }

        {
            const ext = builder.beginExtension(.key_share);
            const shares = builder.begin16();
            builder.int16(@backingInt(NamedGroup.x25519));
            const share = builder.begin16();
            builder.bytes(&options.key_share);
            builder.end(share);
            builder.end(shares);
            builder.end(ext);
        }

        if (options.alpn.len > 0) {
            // RFC 9001 §8.1: QUIC requires ALPN, and its callers always pass
            // one; plain TLS callers may omit it, so an empty list writes no
            // extension rather than an illegally empty one.
            const ext = builder.beginExtension(.alpn);
            const list = builder.begin16();
            for (options.alpn) |protocol| {
                const name = builder.beginByte();
                builder.bytes(protocol);
                builder.end(name);
            }
            builder.end(list);
            builder.end(ext);
        }

        if (options.transport_parameters) |transport_parameters| {
            const ext = builder.beginExtension(.quic_transport_parameters);
            builder.bytes(transport_parameters);
            builder.end(ext);
        }

        builder.end(extensions);
    }

    builder.end(message);
    return builder.written();
}

/// What a client learns from a ServerHello.
pub const ServerHello = struct {
    /// True when this is really a HelloRetryRequest (§4.1.4).
    is_retry: bool,
    suite: quic_crypto.Suite,
    /// The server's X25519 public key, or null in a HelloRetryRequest that only
    /// names a group.
    key_share: ?[X25519.public_length]u8,
    selected_group: NamedGroup,
};

/// Parse a ServerHello body — everything after the four-byte message header.
pub fn parseServerHello(body: []const u8) Error!ServerHello {
    var reader: Reader = .init(body);

    const legacy_version = try reader.int16();
    if (legacy_version != tls_1_2_legacy) return error.UnsupportedVersion;

    const random = try reader.take(random_len);
    const is_retry = std.mem.eql(u8, random, &hello_retry_request_random);

    // RFC 9001 §8.4: the client sent an empty session id, so the echo must be
    // empty too. A server echoing something means it thinks it is in middlebox
    // compatibility mode, and a ChangeCipherSpec would follow.
    const session_id = try reader.blockByte();
    if (session_id.len != 0) return error.IllegalParameter;

    const suite_value = try reader.int16();
    const suite = (@as(CipherSuite, @fromBackingInt(@intCast(suite_value)))).toSuite() orelse
        return error.UnsupportedCipherSuite;

    const compression = try reader.byte();
    if (compression != 0) return error.IllegalParameter;

    var found_version = false;
    var key_share: ?[X25519.public_length]u8 = null;
    var selected_group: ?NamedGroup = null;

    var iterator: ExtensionIterator = .{ .reader = .init(try reader.block16()) };
    while (try iterator.next()) |extension| switch (extension.type) {
        .supported_versions => {
            // §4.2.1: in a ServerHello this is a single version, not a list.
            var inner: Reader = .init(extension.body);
            const version = try inner.int16();
            if (version != tls_1_3) return error.UnsupportedVersion;
            found_version = true;
        },
        .key_share => {
            var inner: Reader = .init(extension.body);
            const group: NamedGroup = @fromBackingInt(@intCast(try inner.int16()));
            if (group != .x25519) return error.UnsupportedGroup;
            selected_group = group;
            if (!is_retry) {
                // §4.2.8: a ServerHello carries the share; a HelloRetryRequest
                // carries only the group it wants.
                const share = try inner.block16();
                if (share.len != X25519.public_length) return error.HandshakeMalformed;
                key_share = share[0..X25519.public_length].*;
            }
        },
        // §4.2: ignore what we do not know. This is what makes greasing safe,
        // and it is the opposite of QUIC's rule for unknown frame types.
        else => {},
    };

    if (!found_version) return error.UnsupportedVersion;
    if (selected_group == null) return error.MissingExtension;
    if (!is_retry and key_share == null) return error.MissingExtension;

    return .{
        .is_retry = is_retry,
        .suite = suite,
        .key_share = key_share,
        .selected_group = selected_group.?,
    };
}

/// What a client learns from EncryptedExtensions.
pub const EncryptedExtensions = struct {
    /// The protocol the server selected. Borrowed from the message.
    alpn: []const u8,
    /// RFC 9000 §18's transport parameters, still opaque. Borrowed.
    transport_parameters: []const u8,
};

/// Parse an EncryptedExtensions body.
///
/// `wanted` is the ALPN list the client offered; the server's choice must be one
/// of them. RFC 9001 §8.1 makes this fatal rather than advisory, unlike TLS over
/// TCP where an absent ALPN merely means no protocol was negotiated.
/// What the caller insists EncryptedExtensions must contain. QUIC requires
/// both (RFC 9001 §8.1/§8.2); TLS over TCP requires neither — a server that
/// ignores an offered ALPN has merely declined it (RFC 7301 leaves the client
/// to decide whether that is fatal).
pub const EncryptedExtensionsRequirements = struct {
    alpn: bool,
    transport_parameters: bool,

    pub const quic: EncryptedExtensionsRequirements = .{ .alpn = true, .transport_parameters = true };
    pub const tcp: EncryptedExtensionsRequirements = .{ .alpn = false, .transport_parameters = false };
};

pub fn parseEncryptedExtensions(
    body: []const u8,
    wanted: []const []const u8,
    require: EncryptedExtensionsRequirements,
) Error!EncryptedExtensions {
    var reader: Reader = .init(body);
    var result: EncryptedExtensions = .{ .alpn = &.{}, .transport_parameters = &.{} };

    var iterator: ExtensionIterator = .{ .reader = .init(try reader.block16()) };
    while (try iterator.next()) |extension| switch (extension.type) {
        .alpn => {
            var inner: Reader = .init(extension.body);
            var list: Reader = .init(try inner.block16());
            // §3.1 of RFC 7301: the server's list holds exactly one protocol.
            const protocol = try list.blockByte();
            if (!list.empty()) return error.HandshakeMalformed;
            var acceptable = false;
            for (wanted) |candidate| {
                if (std.mem.eql(u8, candidate, protocol)) acceptable = true;
            }
            if (!acceptable) return error.NoApplicationProtocol;
            result.alpn = protocol;
        },
        .quic_transport_parameters => result.transport_parameters = extension.body,
        else => {},
    };

    if (require.alpn and result.alpn.len == 0) return error.NoApplicationProtocol;
    // RFC 9001 §8.2: a server that omits transport parameters has not agreed to
    // any, and a QUIC connection cannot proceed without them.
    if (require.transport_parameters and result.transport_parameters.len == 0) {
        return error.MissingExtension;
    }
    return result;
}

/// Walks the certificate chain in a Certificate message (§4.4.2).
///
/// Each entry is DER, borrowed from the message, and carries its own extensions
/// block which TLS 1.3 added and which is almost always empty.
pub const CertificateIterator = struct {
    entries: Reader,

    pub fn init(body: []const u8) Error!CertificateIterator {
        var reader: Reader = .init(body);
        // §4.4.2: an opaque request context, empty for a server's certificate.
        // A non-empty one here would mean the server is answering a request the
        // client never made.
        const context = try reader.blockByte();
        if (context.len != 0) return error.IllegalParameter;
        return .{ .entries = .init(try reader.block24()) };
    }

    pub fn next(self: *CertificateIterator) Error!?[]const u8 {
        if (self.entries.empty()) return null;
        const der = try self.entries.block24();
        // §4.4.2: per-certificate extensions, which TLS 1.3 added and which are
        // almost always empty. Skipped rather than parsed, per §4.2.
        _ = try self.entries.block16();
        return der;
    }
};

/// A CertificateVerify body (§4.4.3): the scheme and the signature over a
/// context string plus the transcript hash.
pub const CertificateVerify = struct {
    scheme: SignatureScheme,
    signature: []const u8,
};

pub fn parseCertificateVerify(body: []const u8) Error!CertificateVerify {
    var reader: Reader = .init(body);
    const scheme = try reader.int16();
    const signature = try reader.block16();
    if (!reader.empty()) return error.HandshakeMalformed;
    return .{ .scheme = @fromBackingInt(@intCast(scheme)), .signature = signature };
}

/// §4.4.3's signed content: 64 spaces, a context string, a zero byte, then the
/// transcript hash. The spaces exist so that a signature cannot be confused with
/// one made in a different context, which is why the whole prefix matters.
pub const server_signature_context = "TLS 1.3, server CertificateVerify";
pub const client_signature_context = "TLS 1.3, client CertificateVerify";

pub fn signatureContent(
    dest: []u8,
    context: []const u8,
    transcript_hash: []const u8,
) []const u8 {
    assert(dest.len >= 64 + context.len + 1 + transcript_hash.len);
    var builder: Builder = .init(dest);
    const spaces: [64]u8 = @splat(' ');
    builder.bytes(&spaces);
    builder.bytes(context);
    builder.byte(0);
    builder.bytes(transcript_hash);
    return builder.written();
}

const testing = std.testing;

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "handshake: builder backfills nested lengths" {
    // Three levels deep, which is what a key_share extension actually is. The
    // point of the abstraction is that none of these lengths is computed twice.
    var buf: [64]u8 = undefined;
    var builder: Builder = .init(&buf);

    const outer = builder.begin16();
    const middle = builder.beginByte();
    const inner = builder.begin16();
    builder.bytes("abcd");
    builder.end(inner);
    builder.end(middle);
    builder.end(outer);

    // outer = 2 (inner prefix) + 4 (body) + 1 (middle prefix) = 7
    try testing.expectEqualSlices(u8, &.{ 0, 7, 6, 0, 4, 'a', 'b', 'c', 'd' }, builder.written());

    var reader: Reader = .init(builder.written());
    var level1: Reader = .init(try reader.block16());
    var level2: Reader = .init(try level1.blockByte());
    try testing.expectEqualStrings("abcd", try level2.block16());
    try testing.expect(level2.empty());
}

test "handshake: a client hello round trips through the message framer" {
    var buf: [2048]u8 = undefined;
    const random: [random_len]u8 = @splat(0x11);
    const share: [X25519.public_length]u8 = @splat(0x22);
    const written = writeClientHello(&buf, .{
        .random = random,
        .key_share = share,
        .server_name = "example.com",
        .alpn = &.{ "h3", "h3-29" },
        .transport_parameters = &.{ 0x01, 0x02, 0x03 },
    });

    // It is a well-formed handshake message, which the framer must agree with.
    const message = (try tls.nextMessage(written)).?;
    try testing.expectEqual(tls.MessageType.client_hello, message.type);
    try testing.expectEqual(written.len, message.raw.len);

    // And every field is where the specification says.
    var reader: Reader = .init(message.body);
    try testing.expectEqual(tls_1_2_legacy, try reader.int16());
    try testing.expectEqualSlices(u8, &random, try reader.take(random_len));
    // RFC 9001 §8.4: empty session id.
    try testing.expectEqual(@as(usize, 0), (try reader.blockByte()).len);
    const suites = try reader.block16();
    try testing.expectEqual(@as(usize, 6), suites.len);
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, try reader.take(2)); // null compression

    var found: struct {
        sni: bool = false,
        versions: bool = false,
        groups: bool = false,
        sig_algs: bool = false,
        key_share: bool = false,
        alpn: bool = false,
        transport: bool = false,
    } = .{};

    var iterator: ExtensionIterator = .{ .reader = .init(try reader.block16()) };
    while (try iterator.next()) |extension| switch (extension.type) {
        .server_name => {
            var inner: Reader = .init(extension.body);
            var list: Reader = .init(try inner.block16());
            try testing.expectEqual(@as(u8, 0), try list.byte());
            try testing.expectEqualStrings("example.com", try list.block16());
            found.sni = true;
        },
        .supported_versions => {
            var inner: Reader = .init(extension.body);
            var list: Reader = .init(try inner.blockByte());
            try testing.expectEqual(tls_1_3, try list.int16());
            try testing.expect(list.empty());
            found.versions = true;
        },
        .supported_groups => found.groups = true,
        .signature_algorithms => found.sig_algs = true,
        .key_share => {
            var inner: Reader = .init(extension.body);
            var shares: Reader = .init(try inner.block16());
            try testing.expectEqual(@backingInt(NamedGroup.x25519), try shares.int16());
            try testing.expectEqualSlices(u8, &share, try shares.block16());
            found.key_share = true;
        },
        .alpn => {
            var inner: Reader = .init(extension.body);
            var list: Reader = .init(try inner.block16());
            try testing.expectEqualStrings("h3", try list.blockByte());
            try testing.expectEqualStrings("h3-29", try list.blockByte());
            try testing.expect(list.empty());
            found.alpn = true;
        },
        .quic_transport_parameters => {
            try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, extension.body);
            found.transport = true;
        },
        else => {},
    };

    try testing.expect(found.sni and found.versions and found.groups);
    try testing.expect(found.sig_algs and found.key_share and found.alpn and found.transport);
}

test "handshake: ALPN is always sent, because QUIC requires it" {
    // RFC 9001 §8.1. A ClientHello without ALPN is legal TLS and illegal QUIC,
    // and it is the one extension this builder has no option to omit.
    var buf: [2048]u8 = undefined;
    const written = writeClientHello(&buf, .{
        .random = @splat(0),
        .key_share = @splat(0),
        // No SNI this time, to show ALPN is not tied to it.
        .alpn = &.{"h3"},
        .transport_parameters = &.{0x00},
    });

    const message = (try tls.nextMessage(written)).?;
    var reader: Reader = .init(message.body);
    _ = try reader.int16();
    _ = try reader.take(random_len);
    _ = try reader.blockByte();
    _ = try reader.block16();
    _ = try reader.take(2);

    var saw_alpn = false;
    var saw_sni = false;
    var iterator: ExtensionIterator = .{ .reader = .init(try reader.block16()) };
    while (try iterator.next()) |extension| switch (extension.type) {
        .alpn => saw_alpn = true,
        .server_name => saw_sni = true,
        else => {},
    };
    try testing.expect(saw_alpn);
    try testing.expect(!saw_sni);
}

test "handshake: RFC 8448 §3's real ServerHello parses" {
    // Somebody else's bytes, which is the only kind that proves the parser
    // handles the wire format rather than its own writer's habits. This one
    // predates QUIC, so it has no transport parameters — only the fields a
    // ServerHello must always have.
    const server_hello = hexBytes(
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800" ++
            "13010000" ++ "2e" ++ "00330024001d0020c98288761120" ++
            "95fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f" ++ "002b00020304",
    );
    const message = (try tls.nextMessage(&server_hello)).?;
    try testing.expectEqual(tls.MessageType.server_hello, message.type);

    const hello = try parseServerHello(message.body);
    try testing.expect(!hello.is_retry);
    try testing.expectEqual(quic_crypto.Suite.aes_128_gcm_sha256, hello.suite);
    try testing.expectEqual(NamedGroup.x25519, hello.selected_group);
    try testing.expectEqualSlices(
        u8,
        &hexBytes("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"),
        &hello.key_share.?,
    );

    // And that share completes the exchange: §3 publishes both private keys and
    // the shared secret, so this checks the parse feeds a working X25519.
    const client_private = hexBytes("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005");
    const shared = try X25519.scalarmult(client_private, hello.key_share.?);
    try testing.expectEqualSlices(
        u8,
        &hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"),
        &shared,
    );
}

test "handshake: a HelloRetryRequest is a ServerHello with a special random" {
    // §4.1.4. A parser switching on the message type alone treats this as a real
    // ServerHello, then derives keys from a share that is not there.
    var buf: [128]u8 = undefined;
    var builder: Builder = .init(&buf);
    builder.byte(@backingInt(tls.MessageType.server_hello));
    const message = builder.begin24();
    builder.int16(tls_1_2_legacy);
    builder.bytes(&hello_retry_request_random);
    builder.byte(0); // empty session id
    builder.int16(@backingInt(CipherSuite.aes_128_gcm_sha256));
    builder.byte(0); // null compression
    {
        const extensions = builder.begin16();
        {
            const ext = builder.beginExtension(.supported_versions);
            builder.int16(tls_1_3);
            builder.end(ext);
        }
        {
            // A retry names a group and sends no share.
            const ext = builder.beginExtension(.key_share);
            builder.int16(@backingInt(NamedGroup.x25519));
            builder.end(ext);
        }
        builder.end(extensions);
    }
    builder.end(message);

    const parsed = (try tls.nextMessage(builder.written())).?;
    const hello = try parseServerHello(parsed.body);
    try testing.expect(hello.is_retry);
    try testing.expect(hello.key_share == null);
    try testing.expectEqual(NamedGroup.x25519, hello.selected_group);
}

test "handshake: a ServerHello that breaks QUIC's rules is refused" {
    const base = struct {
        fn build(
            buf: []u8,
            mutate: enum { none, legacy_session, tls_1_2, bad_suite, no_key_share, no_versions },
        ) []const u8 {
            var builder: Builder = .init(buf);
            builder.byte(@backingInt(tls.MessageType.server_hello));
            const message = builder.begin24();
            builder.int16(tls_1_2_legacy);
            const random: [random_len]u8 = @splat(0x7a);
            builder.bytes(&random);
            if (mutate == .legacy_session) {
                const id = builder.beginByte();
                const echoed: [32]u8 = @splat(0xcc);
                builder.bytes(&echoed);
                builder.end(id);
            } else builder.byte(0);
            builder.int16(if (mutate == .bad_suite)
                0x1305 // TLS_AES_128_CCM_8_SHA256-ish: no QUIC header protection
            else
                @backingInt(CipherSuite.aes_128_gcm_sha256));
            builder.byte(0);
            {
                const extensions = builder.begin16();
                if (mutate != .no_versions) {
                    const ext = builder.beginExtension(.supported_versions);
                    builder.int16(if (mutate == .tls_1_2) tls_1_2_legacy else tls_1_3);
                    builder.end(ext);
                }
                if (mutate != .no_key_share) {
                    const ext = builder.beginExtension(.key_share);
                    builder.int16(@backingInt(NamedGroup.x25519));
                    const share = builder.begin16();
                    const public: [X25519.public_length]u8 = @splat(0x33);
                    builder.bytes(&public);
                    builder.end(share);
                    builder.end(ext);
                }
                builder.end(extensions);
            }
            builder.end(message);
            return builder.written();
        }
    };
    var scratch: [256]u8 = undefined;

    // The unmutated one parses, or the negative cases would prove nothing.
    {
        const bytes = base.build(&scratch, .none);
        const message = (try tls.nextMessage(bytes)).?;
        _ = try parseServerHello(message.body);
    }

    {
        // RFC 9001 §8.4: echoing a session id means middlebox compatibility mode.
        const bytes = base.build(&scratch, .legacy_session);
        const message = (try tls.nextMessage(bytes)).?;
        try testing.expectError(error.IllegalParameter, parseServerHello(message.body));
    }
    {
        // RFC 9001 §4.2: a version older than 1.3 must terminate, not fall back.
        const bytes = base.build(&scratch, .tls_1_2);
        const message = (try tls.nextMessage(bytes)).?;
        try testing.expectError(error.UnsupportedVersion, parseServerHello(message.body));
    }
    {
        // A suite with no QUIC header protection scheme (§5.4.1).
        const bytes = base.build(&scratch, .bad_suite);
        const message = (try tls.nextMessage(bytes)).?;
        try testing.expectError(error.UnsupportedCipherSuite, parseServerHello(message.body));
    }
    {
        const bytes = base.build(&scratch, .no_key_share);
        const message = (try tls.nextMessage(bytes)).?;
        try testing.expectError(error.MissingExtension, parseServerHello(message.body));
    }
    {
        // §4.2.1: without supported_versions this is not TLS 1.3 at all.
        const bytes = base.build(&scratch, .no_versions);
        const message = (try tls.nextMessage(bytes)).?;
        try testing.expectError(error.UnsupportedVersion, parseServerHello(message.body));
    }
}

test "handshake: an ALPN mismatch is fatal, and missing transport parameters too" {
    // RFC 9001 §8.1 and §8.2. Both are connection errors here where TLS over TCP
    // would merely proceed without a negotiated protocol.
    const build = struct {
        fn go(buf: []u8, protocol: ?[]const u8, transport: ?[]const u8) []const u8 {
            var builder: Builder = .init(buf);
            const extensions = builder.begin16();
            if (protocol) |name| {
                const ext = builder.beginExtension(.alpn);
                const list = builder.begin16();
                const entry = builder.beginByte();
                builder.bytes(name);
                builder.end(entry);
                builder.end(list);
                builder.end(ext);
            }
            if (transport) |params| {
                const ext = builder.beginExtension(.quic_transport_parameters);
                builder.bytes(params);
                builder.end(ext);
            }
            builder.end(extensions);
            return builder.written();
        }
    };

    var scratch: [128]u8 = undefined;
    const wanted: []const []const u8 = &.{"h3"};

    const good = try parseEncryptedExtensions(build.go(&scratch, "h3", &.{ 1, 2 }), wanted, .quic);
    try testing.expectEqualStrings("h3", good.alpn);
    try testing.expectEqualSlices(u8, &.{ 1, 2 }, good.transport_parameters);

    // A protocol that was never offered.
    try testing.expectError(
        error.NoApplicationProtocol,
        parseEncryptedExtensions(build.go(&scratch, "h2", &.{1}), wanted, .quic),
    );
    // No ALPN at all.
    try testing.expectError(
        error.NoApplicationProtocol,
        parseEncryptedExtensions(build.go(&scratch, null, &.{1}), wanted, .quic),
    );
    // No transport parameters.
    try testing.expectError(
        error.MissingExtension,
        parseEncryptedExtensions(build.go(&scratch, "h3", null), wanted, .quic),
    );
}

test "handshake: §4.4.3's signed content has its 64 spaces and separator" {
    // The spaces are what stop a signature made in one context being replayed in
    // another, so their presence is the property worth asserting.
    var buf: [256]u8 = undefined;
    const hash: [32]u8 = @splat(0xab);
    const content = signatureContent(&buf, server_signature_context, &hash);

    try testing.expectEqual(@as(usize, 64 + server_signature_context.len + 1 + 32), content.len);
    for (content[0..64]) |byte| try testing.expectEqual(@as(u8, ' '), byte);
    try testing.expectEqualStrings(server_signature_context, content[64..][0..server_signature_context.len]);
    try testing.expectEqual(@as(u8, 0), content[64 + server_signature_context.len]);
    try testing.expectEqualSlices(u8, &hash, content[64 + server_signature_context.len + 1 ..]);

    // And the client's context differs, so a client's signature cannot be taken
    // for a server's.
    var other: [256]u8 = undefined;
    const client_content = signatureContent(&other, client_signature_context, &hash);
    try testing.expect(!std.mem.eql(u8, content, client_content));
}
