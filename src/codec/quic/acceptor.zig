//! What a QUIC server does before a connection exists: decide whether the first
//! Initial packet deserves one.
//!
//! This is deliberately a separate layer from `connection.zig`, because none of
//! it has connection state to work with. A server receiving an Initial from an
//! address it has never heard from has three choices — answer, send a Retry, or
//! drop — and it must make them without allocating anything an attacker could
//! make it allocate. That is the whole shape of RFC 9000 §8.1: no state is
//! created until the address is validated, and the state that would have been
//! created is instead handed to the client to hold, as a token.
//!
//! **Tokens are authenticated by us and opaque to everyone else.** §8.1.1 leaves
//! the format entirely to the server, which means the only requirements are the
//! ones that follow from what it is used for: it must prove we issued it, prove
//! the address it was issued to, expire, and — for a Retry token — carry the
//! original Destination Connection ID, because §7.3 has the server report that
//! value in its transport parameters and after a Retry it has no other copy.
//!
//! The signing key is a parameter. A server that generated one internally could
//! not be a fleet: every member has to accept every other member's tokens, which
//! makes the key an operational input, not an implementation detail.
//!
//! Version Negotiation (§6.1) lives here for the same reason: the version being
//! unsupported is precisely the case where no connection can be made.

const std = @import("std");
const assert = std.debug.assert;

const cid_mod = @import("cid.zig");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const transport = @import("transport.zig");
const varint = @import("varint.zig");

const ConnectionId = packet.ConnectionId;

pub const Error = error{
    BufferTooSmall,
    TokenTooLong,
    AddressTooLong,
};

/// The key that signs address validation tokens. Injected, and shared across a
/// fleet: a token minted by one server must be accepted by whichever one the
/// client's next packet reaches, or a load balancer turns address validation
/// into a connection failure.
pub const TokenKey = struct {
    bytes: [32]u8,

    pub fn init(bytes: [32]u8) TokenKey {
        return .{ .bytes = bytes };
    }
};

/// §8.1.1 vs §8.1.3: the two kinds of token a server issues differ in what they
/// prove, so they are distinguished inside the authenticated bytes rather than by
/// where they arrived. A Retry token proves the client answered *this* Retry and
/// carries the connection ID that Retry replaced; a NEW_TOKEN token proves only
/// that the address completed a handshake once, possibly long ago.
///
/// Mixing them up is not cosmetic. Accepting a NEW_TOKEN token as a Retry token
/// would mean fabricating an `original_destination_connection_id`, and §7.3's
/// check on the client would fail for a reason that looks like an attack.
pub const TokenKind = enum(u8) {
    retry = 1,
    new_token = 2,
};

/// Longest client address this accepts. An IPv6 address and port is 18 bytes;
/// this leaves room for a caller that wants to include something else, and
/// states a bound rather than trusting the caller to be reasonable.
pub const max_address_len = 32;

const token_version = 1;
const mac_len = 32;
/// version, kind, issued_at, address length, cid length
const token_header_len = 1 + 1 + 8 + 1 + 1;

/// Largest token this produces: header, address, connection ID, MAC.
pub const max_token_len = token_header_len + max_address_len + packet.max_cid_len + mac_len;

/// Mint a token for `address`, valid from `now_ms`.
///
/// `original_destination` is the connection ID the client used before the Retry,
/// and must be present for a Retry token and absent for a NEW_TOKEN one — that
/// asymmetry is the whole reason the two kinds exist.
pub fn mintToken(
    dest: []u8,
    key: TokenKey,
    kind: TokenKind,
    now_ms: u64,
    address: []const u8,
    original_destination: ?ConnectionId,
) Error![]const u8 {
    if (address.len > max_address_len) return error.AddressTooLong;
    assert((kind == .retry) == (original_destination != null));

    const cid_len: usize = if (original_destination) |cid| cid.len else 0;
    const total = token_header_len + address.len + cid_len + mac_len;
    if (dest.len < total) return error.BufferTooSmall;

    dest[0] = token_version;
    dest[1] = @backingInt(kind);
    std.mem.writeInt(u64, dest[2..10], now_ms, .big);
    dest[10] = @intCast(address.len);
    dest[11] = @intCast(cid_len);
    var cursor: usize = token_header_len;
    @memcpy(dest[cursor..][0..address.len], address);
    cursor += address.len;
    if (original_destination) |cid| {
        @memcpy(dest[cursor..][0..cid_len], cid.slice());
        cursor += cid_len;
    }

    // The MAC covers everything before it, so nothing in the token — not the
    // address, not the expiry, not the connection ID — can be changed by the
    // client that holds it.
    var mac: [mac_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, dest[0..cursor], &key.bytes);
    @memcpy(dest[cursor..][0..mac_len], &mac);
    return dest[0 .. cursor + mac_len];
}

pub const ValidatedToken = struct {
    kind: TokenKind,
    /// The connection ID from before the Retry. Null for a NEW_TOKEN token,
    /// which is issued mid-connection and has none to carry.
    original_destination: ?ConnectionId,
    issued_at_ms: u64,
};

/// Whether `token` is one we issued to `address` and has not expired.
///
/// Returns null rather than an error for every failure, and deliberately: a
/// server cannot distinguish "forged" from "stale" from "issued to someone else"
/// in any way that should change its behaviour. All three mean the same thing —
/// the address is not validated — and §8.1.3 says to proceed as though no token
/// had been presented at all.
pub fn validateToken(
    key: TokenKey,
    token: []const u8,
    address: []const u8,
    now_ms: u64,
    max_age_ms: u64,
) ?ValidatedToken {
    if (token.len < token_header_len + mac_len) return null;
    if (token[0] != token_version) return null;
    const kind: TokenKind = switch (token[1]) {
        1 => .retry,
        2 => .new_token,
        else => return null,
    };
    const issued_at = std.mem.readInt(u64, token[2..10], .big);
    const address_len = token[10];
    const cid_len = token[11];
    if (address_len > max_address_len or cid_len > packet.max_cid_len) return null;

    const body_len = token_header_len + @as(usize, address_len) + @as(usize, cid_len);
    if (token.len != body_len + mac_len) return null;

    // Constant time, because a timing oracle here is a token forgery oracle.
    var expected: [mac_len]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&expected, token[0..body_len], &key.bytes);
    if (!std.crypto.timing_safe.eql([mac_len]u8, expected, token[body_len..][0..mac_len].*)) {
        return null;
    }

    // Only now is anything inside the token trustworthy. Checking the address or
    // the expiry before the MAC would be reading attacker-controlled bytes and
    // acting on them.
    if (!std.mem.eql(u8, token[token_header_len..][0..address_len], address)) return null;
    if (now_ms < issued_at) return null; // clock moved backwards; treat as invalid
    if (now_ms - issued_at > max_age_ms) return null;

    var original: ?ConnectionId = null;
    if (cid_len > 0) {
        const start = token_header_len + @as(usize, address_len);
        original = ConnectionId.init(token[start..][0..cid_len]) catch return null;
    }
    // A Retry token without a connection ID could not serve its purpose, and one
    // on a NEW_TOKEN token would be a value we never put there.
    if ((kind == .retry) != (original != null)) return null;

    return .{ .kind = kind, .original_destination = original, .issued_at_ms = issued_at };
}

/// Write a Retry packet (§17.2.5).
///
/// `client_source` is where the reply goes, and becomes the Retry's Destination
/// Connection ID. `new_source` is the connection ID we are asking the client to
/// use from now on, which is also what §7.3 has us report as
/// `retry_source_connection_id`. `original_destination` is what the client used
/// in the Initial being answered, and is what the integrity tag binds to — which
/// is what stops anyone who did not see that Initial from forging this.
pub fn writeRetry(
    dest: []u8,
    client_source: ConnectionId,
    new_source: ConnectionId,
    original_destination: ConnectionId,
    token: []const u8,
) Error!usize {
    if (token.len == 0) return error.TokenTooLong; // §17.2.5.1: never empty
    const total = 1 + 4 + 1 + client_source.len + 1 + new_source.len +
        token.len + packet.retry_integrity_tag_len;
    if (dest.len < total) return error.BufferTooSmall;

    var cursor: usize = 0;
    // §17.2.5: the four unused bits are arbitrary. Fixed rather than random:
    // nothing reads them, and a reproducible packet is worth more in a test than
    // entropy nobody consumes.
    dest[0] = packet.header_form_bit | packet.fixed_bit |
        (@as(u8, @backingInt(packet.LongType.retry)) << 4);
    cursor = 1;
    std.mem.writeInt(u32, dest[cursor..][0..4], @backingInt(packet.Version.v1), .big);
    cursor += 4;
    dest[cursor] = client_source.len;
    cursor += 1;
    @memcpy(dest[cursor..][0..client_source.len], client_source.slice());
    cursor += client_source.len;
    dest[cursor] = new_source.len;
    cursor += 1;
    @memcpy(dest[cursor..][0..new_source.len], new_source.slice());
    cursor += new_source.len;
    @memcpy(dest[cursor..][0..token.len], token);
    cursor += token.len;

    const tag = crypto.retryIntegrityTag(original_destination.slice(), dest[0..cursor]);
    @memcpy(dest[cursor..][0..packet.retry_integrity_tag_len], &tag);
    return cursor + packet.retry_integrity_tag_len;
}

/// Write a Version Negotiation packet (§17.2.1).
///
/// It is not a version 1 packet and is not protected: an endpoint that does not
/// understand the version cannot protect anything, which is also why this is the
/// one server response an attacker can forge freely. §6.1 accepts that, and the
/// client's defence is that a Version Negotiation cannot change a connection
/// already under way.
pub fn writeVersionNegotiation(
    dest: []u8,
    client_source: ConnectionId,
    server_source: ConnectionId,
    versions: []const u32,
) Error!usize {
    const total = 1 + 4 + 1 + client_source.len + 1 + server_source.len + versions.len * 4;
    if (dest.len < total) return error.BufferTooSmall;

    // The high bit marks a long header; the rest of the first byte is
    // unconstrained because the version field is what identifies this packet.
    dest[0] = packet.header_form_bit | packet.fixed_bit;
    var cursor: usize = 1;
    std.mem.writeInt(u32, dest[cursor..][0..4], 0, .big);
    cursor += 4;
    dest[cursor] = client_source.len;
    cursor += 1;
    @memcpy(dest[cursor..][0..client_source.len], client_source.slice());
    cursor += client_source.len;
    dest[cursor] = server_source.len;
    cursor += 1;
    @memcpy(dest[cursor..][0..server_source.len], server_source.slice());
    cursor += server_source.len;
    for (versions) |version| {
        std.mem.writeInt(u32, dest[cursor..][0..4], version, .big);
        cursor += 4;
    }
    return cursor;
}

/// The largest stateless reset this writes.
///
/// §10.3.3 wants resets small (a loop of them must shrink to nothing) and §10.3
/// wants them indistinguishable from 1-RTT packets, which argues for *not* being
/// identifiably short: "a Stateless Reset that is smaller than 41 bytes might be
/// identifiable as a Stateless Reset by an observer". This sits above that line
/// and is exactly the token plus one HMAC block of unpredictable bytes, which is
/// where the number comes from rather than taste.
pub const max_stateless_reset_len = stateless_reset_token_len + 32;

const stateless_reset_token_len = transport.stateless_reset_token_len;

/// §10.3: the size a reset may be, given the datagram that triggered it, or null
/// when none may be sent.
///
/// Three requirements meet here, which is why it is one function rather than
/// three checks at the call site:
///
///   * **Smaller than the trigger, always** (§10.3.3). The RFC permits equality
///     only for an endpoint that "maintains state sufficient to prevent looping",
///     and this layer holds no per-peer state by design — so a reset that met a
///     reset could ping-pong for ever. Shrinking makes the loop terminate
///     structurally instead of being watched for.
///   * **At least 21 bytes** (§10.3), because the two fixed bits plus 38
///     unpredictable bits plus a 16-byte token is the smallest thing a peer will
///     accept: "short header packets that are smaller than 21 bytes are never
///     valid", so a smaller reset would be discarded rather than acted on.
///   * **Never three times or more the trigger** (§10.3), which the first rule
///     already implies. Stated because it is the reason the first rule is a MUST
///     and not a preference.
///
/// The consequence of the first two together is that a trigger of 21 bytes or
/// fewer gets no answer at all — there is no size that is both valid and smaller.
/// §10.3.3 acknowledges this trade-off directly: "not sending a Stateless Reset
/// in response to a small packet might result in Stateless Resets not being
/// useful in detecting cases of broken connections where only very small packets
/// are sent".
pub fn statelessResetLen(trigger_len: usize) ?usize {
    if (trigger_len < min_stateless_reset_len + 1) return null;
    return @min(trigger_len - 1, max_stateless_reset_len);
}

const min_stateless_reset_len = 21;

/// Write a stateless reset for `destination` into `dest`, or report that the
/// trigger was too small to answer.
///
/// The unpredictable bits are derived rather than drawn from a generator, for the
/// same reason everything else here takes its randomness as a parameter: a server
/// built from a fixed seed is reproducible in a test. `nonce` makes successive
/// resets differ, which matters because §10.3 asks for bytes "indistinguishable
/// from random" and a constant padding would be a signature.
pub fn writeStatelessReset(
    dest: []u8,
    trigger_len: usize,
    key: *const [32]u8,
    destination: ConnectionId,
    nonce: u64,
) ?usize {
    const len = statelessResetLen(trigger_len) orelse return null;
    if (dest.len < len) return null;
    assert(len >= min_stateless_reset_len);
    assert(len < trigger_len);

    var mac: std.crypto.auth.hmac.sha2.HmacSha256 = .init(key);
    mac.update("zinet stateless reset padding");
    var nonce_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &nonce_bytes, nonce, .little);
    mac.update(&nonce_bytes);
    var noise: [32]u8 = undefined;
    mac.final(&noise);

    const padding = len - stateless_reset_token_len;
    assert(padding <= noise.len);
    @memcpy(dest[0..padding], noise[0..padding]);
    // §10.3's layout: header form 0 and the fixed bit 1, so this reads as a short
    // header to anyone who does not hold the token; the other six bits stay
    // random. Overwriting the first noise byte rather than reserving one keeps the
    // packet's *first* byte from being the only unpredictable thing about it.
    dest[0] = (dest[0] & ~(packet.header_form_bit | packet.fixed_bit)) | packet.fixed_bit;

    const token = cid_mod.statelessResetToken(key, destination);
    @memcpy(dest[padding..len], &token);
    return len;
}

/// What to do with a datagram that no existing connection claims.
pub const Decision = union(enum) {
    /// Not a valid new-connection attempt: drop it silently. §5.2.2 requires
    /// exactly this for anything that cannot be matched, and answering would
    /// make the server a reflector.
    drop,
    /// The version is one we do not speak; answer with the list we do.
    negotiate_version: struct { client_source: ConnectionId, destination: ConnectionId },
    /// Send a Retry to validate the address before creating any state.
    retry: struct { client_source: ConnectionId, original_destination: ConnectionId },
    /// §10.3: a short header addressed to a connection ID we do not know. The
    /// peer believes a 1-RTT connection exists and we have no state for it, which
    /// is the one situation a stateless reset is for — and the only way to tell
    /// that peer to stop, since answering with CONNECTION_CLOSE would need the
    /// keys we do not have. `destination` is what to derive the token from
    /// (§10.3.2): it came out of the packet, which is the whole point.
    stateless_reset: struct { destination: ConnectionId },
    /// Create a connection.
    accept: struct {
        client_source: ConnectionId,
        /// What the client addressed. Initial keys derive from it, so the
        /// connection needs it even when a Retry has since replaced it.
        destination: ConnectionId,
        /// What §7.3 has the server report as
        /// `original_destination_connection_id`: the value from *before* any
        /// Retry, recovered from the token when one happened.
        original_destination: ConnectionId,
        after_retry: bool,
    },
};

pub const Policy = struct {
    key: TokenKey,
    /// Whether to demand address validation from every new client. Costs one
    /// round trip and is what a server under load turns on; §8.1 leaves it to
    /// the server.
    require_validation: bool = false,
    /// How long a token stays usable. §8.1.3 has no number, so this is stated:
    /// long enough to survive a retransmission, short enough that a captured
    /// token is not a lasting credential.
    retry_token_lifetime_ms: u64 = 10_000,
    /// A NEW_TOKEN token spans connections, so it lives longer.
    new_token_lifetime_ms: u64 = 24 * 60 * 60 * 1000,
    /// Versions this server speaks, for Version Negotiation.
    versions: []const u32 = &.{@backingInt(packet.Version.v1)},
};

/// Classify the first packet of a would-be connection.
///
/// Takes the parsed header rather than the datagram, because deciding this does
/// not require removing packet protection — and must not, since the whole point
/// is to reach a decision before doing work an unvalidated address could
/// multiply.
pub fn classify(
    policy: Policy,
    header: packet.Protected,
    address: []const u8,
    now_ms: u64,
) Decision {
    // §17.3: no long type means a short header, so the peer is addressing a
    // 1-RTT connection. Nothing here can create one — 1-RTT keys come from a
    // handshake — so the only useful answers are silence and a stateless reset.
    if (header.long_type == null) return .{ .stateless_reset = .{
        .destination = header.destination,
    } };
    // §7.2: a client's first Destination Connection ID is at least 8 bytes. A
    // shorter one is not a client we can talk to, and it is also the cheap
    // signal that this is not a real connection attempt.
    if (header.long_type != packet.LongType.initial) return .drop;
    if (!header.version.isSupported()) {
        // §6.1: answer even an unsupported version, because the client cannot
        // learn what we speak any other way. Version 0 is a Version Negotiation
        // itself and is never answered.
        if (@backingInt(header.version) == 0) return .drop;
        return .{ .negotiate_version = .{
            .client_source = header.source,
            .destination = header.destination,
        } };
    }
    if (header.destination.len < 8) return .drop;

    if (header.token.len > 0) {
        if (validateToken(
            policy.key,
            header.token,
            address,
            now_ms,
            switch (tokenKindOf(header.token) orelse return retryOrAccept(policy, header)) {
                .retry => policy.retry_token_lifetime_ms,
                .new_token => policy.new_token_lifetime_ms,
            },
        )) |validated| {
            return .{
                .accept = .{
                    .client_source = header.source,
                    .destination = header.destination,
                    // After a Retry the connection ID the client is using is ours,
                    // not the one §7.3 asks about — that one is in the token, and
                    // this is the only place it can be recovered from.
                    .original_destination = validated.original_destination orelse header.destination,
                    .after_retry = validated.kind == .retry,
                },
            };
        }
        // An invalid token is treated as no token (§8.1.3), not as an attack:
        // the ordinary cause is a token that expired while the client sat idle.
        return retryOrAccept(policy, header);
    }

    return retryOrAccept(policy, header);
}

fn retryOrAccept(policy: Policy, header: packet.Protected) Decision {
    if (policy.require_validation) {
        return .{ .retry = .{
            .client_source = header.source,
            .original_destination = header.destination,
        } };
    }
    return .{ .accept = .{
        .client_source = header.source,
        .destination = header.destination,
        .original_destination = header.destination,
        .after_retry = false,
    } };
}

/// The kind claimed by a token, before it is known to be genuine. Used only to
/// choose which lifetime to check it against; nothing else may depend on it,
/// because at this point the byte is the client's word.
fn tokenKindOf(token: []const u8) ?TokenKind {
    if (token.len < 2 or token[0] != token_version) return null;
    return switch (token[1]) {
        1 => .retry,
        2 => .new_token,
        else => null,
    };
}

// --- Tests -------------------------------------------------------------------

const testing = std.testing;

fn testCid(bytes: []const u8) ConnectionId {
    return ConnectionId.init(bytes) catch unreachable;
}

test "acceptor: a minted token validates for its own address and not another" {
    const key: TokenKey = .init(@splat(0x5a));
    const odcid = testCid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    var buf: [max_token_len]u8 = undefined;

    const token = try mintToken(&buf, key, .retry, 1_000, "\x7f\x00\x00\x01\x1f\x90", odcid);
    const good = validateToken(key, token, "\x7f\x00\x00\x01\x1f\x90", 1_500, 10_000);
    try testing.expect(good != null);
    try testing.expectEqual(TokenKind.retry, good.?.kind);
    try testing.expect(good.?.original_destination.?.eql(&odcid));

    // A different address: the token was not issued to this peer, and accepting
    // it would let anyone who saw one packet claim validation for any address.
    try testing.expect(validateToken(key, token, "\x7f\x00\x00\x02\x1f\x90", 1_500, 10_000) == null);
    // A different port is a different address too.
    try testing.expect(validateToken(key, token, "\x7f\x00\x00\x01\x1f\x91", 1_500, 10_000) == null);
    // A different key: not ours.
    try testing.expect(validateToken(.init(@splat(0x5b)), token, "\x7f\x00\x00\x01\x1f\x90", 1_500, 10_000) == null);
}

test "acceptor: a token expires and cannot be extended by editing it" {
    const key: TokenKey = .init(@splat(0x11));
    var buf: [max_token_len]u8 = undefined;
    const token = try mintToken(&buf, key, .retry, 1_000, "addr", testCid(&.{ 9, 9, 9, 9, 9, 9, 9, 9 }));

    try testing.expect(validateToken(key, token, "addr", 10_999, 10_000) != null);
    try testing.expect(validateToken(key, token, "addr", 11_001, 10_000) == null);

    // Rewriting the timestamp breaks the MAC, which is the point of covering it.
    var forged: [max_token_len]u8 = undefined;
    @memcpy(forged[0..token.len], token);
    std.mem.writeInt(u64, forged[2..10], 10_000, .big);
    try testing.expect(validateToken(key, forged[0..token.len], "addr", 11_001, 10_000) == null);

    // So does flipping the kind, which is what stops a NEW_TOKEN token from
    // being presented as a Retry token and inventing an original connection ID.
    @memcpy(forged[0..token.len], token);
    forged[1] = @backingInt(TokenKind.new_token);
    try testing.expect(validateToken(key, forged[0..token.len], "addr", 1_500, 10_000) == null);
}

test "acceptor: a NEW_TOKEN token carries no connection ID" {
    const key: TokenKey = .init(@splat(0x22));
    var buf: [max_token_len]u8 = undefined;
    const token = try mintToken(&buf, key, .new_token, 500, "addr", null);
    const validated = validateToken(key, token, "addr", 600, 60_000).?;
    try testing.expectEqual(TokenKind.new_token, validated.kind);
    try testing.expect(validated.original_destination == null);
}

test "acceptor: a Retry carries a verifiable tag bound to the original id" {
    const client_scid = testCid(&.{ 0xc0, 0xc1, 0xc2, 0xc3 });
    const new_scid = testCid(&.{ 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 });
    const odcid = testCid(&.{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 });

    var dest: [256]u8 = undefined;
    const len = try writeRetry(&dest, client_scid, new_scid, odcid, "token-bytes");

    // It parses as a Retry, and the parse recovers what was written.
    const parsed = try packet.parse(dest[0..len], 8);
    const retry = parsed.packet.retry;
    try testing.expect(retry.destination.eql(&client_scid));
    try testing.expect(retry.source.eql(&new_scid));
    try testing.expectEqualStrings("token-bytes", retry.token);

    // §5.8: the tag authenticates the packet against the connection ID it
    // replaces, so a client that did not send that Initial cannot verify it —
    // which is exactly what makes an off-path Retry injection fail.
    const without_tag = dest[0 .. len - packet.retry_integrity_tag_len];
    try testing.expect(crypto.verifyRetry(odcid.slice(), without_tag, retry.integrity_tag));
    try testing.expect(!crypto.verifyRetry(
        testCid(&.{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd8 }).slice(),
        without_tag,
        retry.integrity_tag,
    ));
}

test "acceptor: an empty token is refused rather than written" {
    var dest: [256]u8 = undefined;
    // §17.2.5.1: a Retry token is never empty, and a client must discard a Retry
    // whose token is. Writing one would produce a packet guaranteed to be ignored.
    try testing.expectError(error.TokenTooLong, writeRetry(
        &dest,
        testCid(&.{ 1, 2, 3, 4 }),
        testCid(&.{ 5, 6, 7, 8 }),
        testCid(&.{ 9, 9, 9, 9, 9, 9, 9, 9 }),
        "",
    ));
}

test "acceptor: classify demands validation, then accepts the token it issued" {
    const policy: Policy = .{ .key = .init(@splat(0x77)), .require_validation = true };
    const odcid = testCid(&.{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 });
    const client_scid = testCid(&.{ 0xb0, 0xb1, 0xb2, 0xb3 });
    const address = "\x0a\x00\x00\x01\x30\x39";

    var header: packet.Protected = .{
        .version = .v1,
        .long_type = .initial,
        .destination = odcid,
        .source = client_scid,
        .token = &.{},
        .pn_offset = 0,
        .remainder_len = 0,
    };

    switch (classify(policy, header, address, 1_000)) {
        .retry => |r| {
            try testing.expect(r.original_destination.eql(&odcid));
            try testing.expect(r.client_source.eql(&client_scid));
        },
        else => return error.ExpectedRetry,
    }

    // The client comes back with the token, addressed to the connection ID the
    // Retry gave it. What §7.3 needs is the *original*, which only the token has.
    var token_buf: [max_token_len]u8 = undefined;
    const token = try mintToken(&token_buf, policy.key, .retry, 1_000, address, odcid);
    const retry_scid = testCid(&.{ 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 });
    header.destination = retry_scid;
    header.token = token;

    switch (classify(policy, header, address, 1_100)) {
        .accept => |a| {
            try testing.expect(a.after_retry);
            try testing.expect(a.destination.eql(&retry_scid));
            try testing.expect(a.original_destination.eql(&odcid));
        },
        else => return error.ExpectedAccept,
    }

    // The same token from a different address buys nothing: back to a Retry.
    try testing.expect(classify(policy, header, "\x0a\x00\x00\x02\x30\x39", 1_100) == .retry);
    // And an expired one is treated as absent rather than as an attack.
    try testing.expect(classify(policy, header, address, 100_000) == .retry);
}

test "acceptor: without validation a first Initial is accepted directly" {
    const policy: Policy = .{ .key = .init(@splat(0x33)) };
    const dcid = testCid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const header: packet.Protected = .{
        .version = .v1,
        .long_type = .initial,
        .destination = dcid,
        .source = testCid(&.{ 9, 8, 7, 6 }),
        .token = &.{},
        .pn_offset = 0,
        .remainder_len = 0,
    };
    switch (classify(policy, header, "addr", 0)) {
        .accept => |a| {
            try testing.expect(!a.after_retry);
            try testing.expect(a.original_destination.eql(&dcid));
        },
        else => return error.ExpectedAccept,
    }
}

test "acceptor: a short first connection id and a non-Initial are dropped" {
    const policy: Policy = .{ .key = .init(@splat(0x44)) };
    // §7.2: a client's first Destination Connection ID is at least 8 bytes, so a
    // shorter one cannot be the start of a connection.
    var header: packet.Protected = .{
        .version = .v1,
        .long_type = .initial,
        .destination = testCid(&.{ 1, 2, 3, 4 }),
        .source = testCid(&.{ 9, 8, 7, 6 }),
        .token = &.{},
        .pn_offset = 0,
        .remainder_len = 0,
    };
    try testing.expect(classify(policy, header, "addr", 0) == .drop);

    // A Handshake packet for a connection that does not exist is not a way to
    // start one: §5.2.2 has it discarded.
    header.destination = testCid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    header.long_type = .handshake;
    try testing.expect(classify(policy, header, "addr", 0) == .drop);
}

test "acceptor: an unsupported version is answered with the ones we speak" {
    const policy: Policy = .{ .key = .init(@splat(0x55)) };
    const header: packet.Protected = .{
        .version = @fromBackingInt(@intCast(0x1a2a3a4a)), // a reserved "force negotiation" version
        .long_type = .initial,
        .destination = testCid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }),
        .source = testCid(&.{ 9, 8, 7, 6 }),
        .token = &.{},
        .pn_offset = 0,
        .remainder_len = 0,
    };
    const decision = classify(policy, header, "addr", 0);
    switch (decision) {
        .negotiate_version => |v| {
            var dest: [256]u8 = undefined;
            const len = try writeVersionNegotiation(
                &dest,
                v.client_source,
                v.destination,
                policy.versions,
            );
            const parsed = try packet.parse(dest[0..len], 8);
            const list = parsed.packet.version_negotiation;
            try testing.expect(list.destination.eql(&testCid(&.{ 9, 8, 7, 6 })));
            try testing.expectEqual(@as(usize, 4), list.versions.len);
            try testing.expectEqual(
                @as(u32, @backingInt(packet.Version.v1)),
                std.mem.readInt(u32, list.versions[0..4], .big),
            );
        },
        else => return error.ExpectedVersionNegotiation,
    }
}

test "acceptor: a reset's size is bounded from both ends, so a loop of them dies out" {
    // §10.3.3's MUST and §10.3's minimum meet here, and the interesting case is
    // where they conflict: a trigger of 21 bytes has no valid answer, because
    // anything smaller than 21 bytes is not a packet a peer will accept.
    try testing.expectEqual(@as(?usize, null), statelessResetLen(0));
    try testing.expectEqual(@as(?usize, null), statelessResetLen(21));
    try testing.expectEqual(@as(?usize, 21), statelessResetLen(22));
    try testing.expectEqual(@as(?usize, 29), statelessResetLen(30));
    // §10.3: one byte shorter for triggers of 43 bytes or fewer, which this rule
    // gives for free by always shrinking by one until the cap bites.
    try testing.expectEqual(@as(?usize, 42), statelessResetLen(43));
    // A full-size packet does not produce a full-size reset: §10.3.3 prefers small,
    // and the cap keeps it above the 41 bytes that would make it identifiable.
    try testing.expectEqual(@as(?usize, max_stateless_reset_len), statelessResetLen(1200));
    try testing.expect(max_stateless_reset_len > 41);

    // Every answer is strictly smaller than what triggered it. Checked as a range
    // rather than at a few points, because this is the property that makes an
    // exchange of resets terminate.
    var trigger: usize = 22;
    while (trigger <= 200) : (trigger += 1) {
        const len = statelessResetLen(trigger).?;
        try testing.expect(len < trigger);
        try testing.expect(len >= 21);
        // §10.3: never three times or more the trigger. Implied by shrinking, and
        // asserted because that implication is the reason shrinking is a MUST.
        try testing.expect(len < 3 * trigger);
    }
}

test "acceptor: a stateless reset is a short header, random bits, and the token" {
    const key: [32]u8 = @splat(0x33);
    const destination = ConnectionId.init(&.{ 8, 7, 6, 5, 4, 3, 2, 1 }) catch unreachable;

    var out: [max_stateless_reset_len]u8 = undefined;
    const len = writeStatelessReset(&out, 1200, &key, destination, 0).?;
    try testing.expectEqual(max_stateless_reset_len, len);

    // §10.3's layout: header form clear, fixed bit set, token last.
    try testing.expectEqual(@as(u8, 0), out[0] & packet.header_form_bit);
    try testing.expect(out[0] & packet.fixed_bit != 0);
    const token = cid_mod.statelessResetToken(&key, destination);
    try testing.expectEqualSlices(u8, &token, out[len - token.len ..]);

    // The unpredictable bits differ between resets. A constant padding would be a
    // signature, which is the opposite of what §10.3 asks for.
    var second: [max_stateless_reset_len]u8 = undefined;
    const second_len = writeStatelessReset(&second, 1200, &key, destination, 1).?;
    try testing.expectEqual(len, second_len);
    try testing.expect(!std.mem.eql(u8, out[0 .. len - token.len], second[0 .. len - token.len]));
    // But the token does not, because it is derived from the connection ID alone.
    try testing.expectEqualSlices(u8, out[len - token.len ..], second[second_len - token.len ..]);

    // A trigger too small to answer, and a destination buffer too small to write
    // into, both report rather than truncate.
    try testing.expectEqual(@as(?usize, null), writeStatelessReset(&out, 21, &key, destination, 0));
    var tiny: [8]u8 = undefined;
    try testing.expectEqual(@as(?usize, null), writeStatelessReset(&tiny, 1200, &key, destination, 0));
}

test "acceptor: a short header for an unknown connection asks for a reset, not a drop" {
    const policy: Policy = .{ .key = .init(@splat(0x44)) };
    const destination = ConnectionId.init(&.{ 1, 1, 2, 2, 3, 3, 4, 4 }) catch unreachable;

    // §17.3: a short header has no long type. It cannot start a connection — 1-RTT
    // keys come from a handshake — so the only answers are silence and a reset.
    const short: packet.Protected = .{
        .long_type = null,
        .version = .v1,
        .destination = destination,
        .source = ConnectionId.init(&.{}) catch unreachable,
        .token = &.{},
        .pn_offset = 9,
        .remainder_len = 40,
    };
    switch (classify(policy, short, "addr", 0)) {
        .stateless_reset => |r| try testing.expectEqualSlices(
            u8,
            destination.slice(),
            r.destination.slice(),
        ),
        else => return error.ExpectedStatelessReset,
    }

    // A long header that is not an Initial still drops: §10.3 says a reset before
    // the peer holds the token achieves nothing, and long headers only appear
    // during the handshake in version 1.
    const handshake: packet.Protected = .{
        .long_type = .handshake,
        .version = .v1,
        .destination = destination,
        .source = destination,
        .token = &.{},
        .pn_offset = 20,
        .remainder_len = 40,
    };
    try testing.expect(classify(policy, handshake, "addr", 0) == .drop);
}
