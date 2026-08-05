//! QUIC transport parameters, RFC 9000 §18.
//!
//! These belong to the transport but travel as a TLS extension, which is why
//! `handshake.zig` carries them as opaque bytes and this file is where they mean
//! something. The split matters: TLS authenticates them (any tampering breaks the
//! handshake, §8.2 of RFC 9001) while QUIC decides what they permit.
//!
//! **The connection ID parameters are an authentication mechanism, not
//! bookkeeping.** §7.3 requires each endpoint to check the connection IDs it saw
//! in packet headers against the ones the peer reports here. Packet headers
//! during the handshake are unprotected, so an attacker can rewrite them; the
//! copies inside the transport parameters are covered by the handshake
//! signature, and comparing the two is what makes header rewriting detectable.
//! `checkConnectionIds` is that comparison, and skipping it leaves the
//! connection open to having its identity swapped underneath it.

const std = @import("std");
const assert = std.debug.assert;

const packet = @import("packet.zig");
const varint = @import("varint.zig");

const ConnectionId = packet.ConnectionId;

pub const Error = error{
    /// A parameter's value is malformed, out of range, or appears twice. §18
    /// makes all of these TRANSPORT_PARAMETER_ERROR.
    TransportParameterError,
    /// A parameter only one role may send arrived from the other. Separate from
    /// the above because it says something different: the peer is confused about
    /// which side of the connection it is on.
    TransportParameterForbidden,
    /// §7.3: a connection ID in the parameters disagrees with what was in the
    /// packet headers. Its own error because the cause is an attacker rewriting
    /// headers rather than a peer encoding something wrong.
    ConnectionIdMismatch,
} || varint.Error;

/// §18.2's identifiers. Non-exhaustive because §18.1 requires ignoring unknown
/// parameters — that is what makes extensions and greasing possible, and it is
/// the opposite of QUIC's rule for unknown *frame* types.
pub const Id = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    /// RFC 9221 §3: how large a DATAGRAM frame this endpoint will receive, or 0 for
    /// "not at all". An extension parameter rather than a core one, which is why the
    /// value is out past 0x10.
    max_datagram_frame_size = 0x20,
    _,

    /// §18.2: four parameters are the server's alone. A client sending one is
    /// not merely odd — `original_destination_connection_id` from a client would
    /// be claiming to have chosen what the client itself sent.
    pub fn serverOnly(self: Id) bool {
        return switch (self) {
            .original_destination_connection_id,
            .stateless_reset_token,
            .preferred_address,
            .retry_source_connection_id,
            => true,
            else => false,
        };
    }
};

pub const Role = enum { client, server };

/// §14.1: an endpoint must be able to receive a 1200-byte UDP payload, so
/// advertising less is refused.
pub const min_max_udp_payload_size = 1200;
/// §18.2's default and maximum for that parameter.
pub const default_max_udp_payload_size = 65527;
/// §18.2: the exponent cannot exceed 20, because a larger one would let a peer
/// describe an ACK delay longer than any clock cares about.
pub const max_ack_delay_exponent = 20;
/// §18.2: max_ack_delay is in milliseconds and must be under 2^14.
pub const max_max_ack_delay_ms = (1 << 14) - 1;
/// §18.2: at least two, because one is needed for the current connection ID and
/// one for the next — an endpoint with a limit of one could never rotate.
pub const min_active_connection_id_limit = 2;
pub const stateless_reset_token_len = 16;

/// §18.2's preferred_address. Kept as raw fields rather than a `std.net.Address`
/// because both families are always present on the wire, and a server may offer
/// one, the other, or both.
pub const PreferredAddress = struct {
    ip4: [4]u8,
    ip4_port: u16,
    ip6: [16]u8,
    ip6_port: u16,
    connection_id: ConnectionId,
    stateless_reset_token: [stateless_reset_token_len]u8,

    /// An all-zero address means "not offered" (§18.2).
    pub fn hasIp4(self: *const PreferredAddress) bool {
        return !std.mem.allEqual(u8, &self.ip4, 0);
    }

    pub fn hasIp6(self: *const PreferredAddress) bool {
        return !std.mem.allEqual(u8, &self.ip6, 0);
    }
};

/// One endpoint's transport parameters. Defaults are §18.2's, so a parameter the
/// peer omits already means the right thing and no caller has to remember which
/// absent value implies what.
pub const Parameters = struct {
    /// Milliseconds. Zero means no idle timeout, which §10.1 defines as the
    /// *absence* of a limit rather than an immediate one.
    max_idle_timeout_ms: u64 = 0,
    max_udp_payload_size: u64 = default_max_udp_payload_size,
    initial_max_data: u64 = 0,
    initial_max_stream_data_bidi_local: u64 = 0,
    initial_max_stream_data_bidi_remote: u64 = 0,
    initial_max_stream_data_uni: u64 = 0,
    initial_max_streams_bidi: u64 = 0,
    initial_max_streams_uni: u64 = 0,
    ack_delay_exponent: u64 = 3,
    max_ack_delay_ms: u64 = 25,
    disable_active_migration: bool = false,
    active_connection_id_limit: u64 = min_active_connection_id_limit,
    /// RFC 9221 §3: the largest DATAGRAM frame this endpoint will receive, *including*
    /// the frame type and length fields — not just the payload, which is the detail
    /// worth getting right because a sender that forgets the overhead sends a frame
    /// its peer must treat as a PROTOCOL_VIOLATION.
    ///
    /// Zero means unsupported, and is the default because §3 makes it one: "the
    /// default for this parameter is 0, which indicates that the endpoint does not
    /// support DATAGRAM frames". An application that wants them says so.
    max_datagram_frame_size: u64 = 0,

    /// §7.3: the connection ID this endpoint put in the Source Connection ID
    /// field of its first packet. Both roles send it, and both check it.
    initial_source_connection_id: ?ConnectionId = null,

    /// Server only. §7.3: the Destination Connection ID from the client's first
    /// Initial packet, which only the server that received it can know.
    original_destination_connection_id: ?ConnectionId = null,
    /// Server only, and present only if a Retry happened.
    retry_source_connection_id: ?ConnectionId = null,
    /// Server only. §10.3: lets the client recognise a stateless reset later.
    stateless_reset_token: ?[stateless_reset_token_len]u8 = null,
    /// Server only.
    preferred_address: ?PreferredAddress = null,

    /// A reasonable set for a client to offer. Not defaults on the struct,
    /// because §18.2's defaults describe what an *absent* parameter means and
    /// conflating the two would make an omitted parameter look deliberate.
    pub const client_defaults: Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_stream_data_uni = 256 * 1024,
        .initial_max_streams_bidi = 0, // a client accepts no server-opened bidi streams
        .initial_max_streams_uni = 16, // enough for HTTP/3's control streams
        .max_idle_timeout_ms = 30_000,
        .active_connection_id_limit = 4,
    };

    /// What a server advertises. It differs from a client's in exactly the place
    /// the asymmetry is real: a server accepts client-opened bidirectional
    /// streams — that is what a request is — while a client accepts none.
    pub const server_defaults: Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 256 * 1024,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_stream_data_uni = 256 * 1024,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 16,
        .max_idle_timeout_ms = 30_000,
        .active_connection_id_limit = 4,
    };
};

/// Bytes `encode` will write, so a caller can size its buffer.
pub fn encodedLen(params: *const Parameters, role: Role) usize {
    var counter: Counter = .{};
    write(&counter, params, role);
    return counter.len;
}

/// Encode into `dest`, returning the bytes written.
pub fn encode(dest: []u8, params: *const Parameters, role: Role) usize {
    var writer: Writer = .{ .buf = dest };
    write(&writer, params, role);
    return writer.len;
}

/// Counts without writing, so `encodedLen` and `encode` cannot disagree about
/// the size — the same shape as the length-prefix problem in `handshake.zig`,
/// solved the same way: one traversal, two sinks.
const Counter = struct {
    len: usize = 0,

    fn varint(self: *Counter, value: u64) void {
        self.len += @import("varint.zig").encodedLen(value);
    }

    fn bytes(self: *Counter, value: []const u8) void {
        self.len += value.len;
    }
};

const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn varint(self: *Writer, value: u64) void {
        self.len += @import("varint.zig").encode(self.buf[self.len..], value);
    }

    fn bytes(self: *Writer, value: []const u8) void {
        @memcpy(self.buf[self.len..][0..value.len], value);
        self.len += value.len;
    }
};

fn write(sink: anytype, params: *const Parameters, role: Role) void {
    // Every parameter is id, length, value — all varints except the values that
    // are byte strings.
    const Sink = @TypeOf(sink);

    const put = struct {
        fn integer(s: Sink, id: Id, value: u64) void {
            s.varint(@backingInt(id));
            s.varint(@import("varint.zig").encodedLen(value));
            s.varint(value);
        }
        fn blob(s: Sink, id: Id, value: []const u8) void {
            s.varint(@backingInt(id));
            s.varint(value.len);
            s.bytes(value);
        }
        fn empty(s: Sink, id: Id) void {
            s.varint(@backingInt(id));
            s.varint(0);
        }
    };

    // Only non-default values are sent. §18.1 lets a parameter be omitted when
    // it equals its default, and sending it anyway wastes bytes in the one packet
    // where space is tightest — the client's first Initial, which §14.1 requires
    // be padded to 1200 bytes anyway but which also has to fit the ClientHello.
    if (params.max_idle_timeout_ms != 0) {
        put.integer(sink, .max_idle_timeout, params.max_idle_timeout_ms);
    }
    if (params.max_udp_payload_size != default_max_udp_payload_size) {
        put.integer(sink, .max_udp_payload_size, params.max_udp_payload_size);
    }
    if (params.initial_max_data != 0) {
        put.integer(sink, .initial_max_data, params.initial_max_data);
    }
    if (params.initial_max_stream_data_bidi_local != 0) {
        put.integer(sink, .initial_max_stream_data_bidi_local, params.initial_max_stream_data_bidi_local);
    }
    if (params.initial_max_stream_data_bidi_remote != 0) {
        put.integer(sink, .initial_max_stream_data_bidi_remote, params.initial_max_stream_data_bidi_remote);
    }
    if (params.initial_max_stream_data_uni != 0) {
        put.integer(sink, .initial_max_stream_data_uni, params.initial_max_stream_data_uni);
    }
    if (params.initial_max_streams_bidi != 0) {
        put.integer(sink, .initial_max_streams_bidi, params.initial_max_streams_bidi);
    }
    if (params.initial_max_streams_uni != 0) {
        put.integer(sink, .initial_max_streams_uni, params.initial_max_streams_uni);
    }
    if (params.ack_delay_exponent != 3) {
        put.integer(sink, .ack_delay_exponent, params.ack_delay_exponent);
    }
    if (params.max_ack_delay_ms != 25) {
        put.integer(sink, .max_ack_delay, params.max_ack_delay_ms);
    }
    if (params.disable_active_migration) put.empty(sink, .disable_active_migration);
    if (params.active_connection_id_limit != min_active_connection_id_limit) {
        put.integer(sink, .active_connection_id_limit, params.active_connection_id_limit);
    }
    // RFC 9221 §3: omitted rather than sent as zero when unsupported, because absence
    // and zero mean the same thing and the shorter encoding is the one a peer that
    // never heard of the extension will ignore either way.
    if (params.max_datagram_frame_size != 0) {
        put.integer(sink, .max_datagram_frame_size, params.max_datagram_frame_size);
    }
    if (params.initial_source_connection_id) |cid| {
        put.blob(sink, .initial_source_connection_id, cid.slice());
    }

    if (role == .server) {
        if (params.original_destination_connection_id) |cid| {
            put.blob(sink, .original_destination_connection_id, cid.slice());
        }
        if (params.retry_source_connection_id) |cid| {
            put.blob(sink, .retry_source_connection_id, cid.slice());
        }
        if (params.stateless_reset_token) |token| {
            put.blob(sink, .stateless_reset_token, &token);
        }
        if (params.preferred_address) |address| {
            sink.varint(@backingInt(Id.preferred_address));
            const len = 4 + 2 + 16 + 2 + 1 + address.connection_id.len + stateless_reset_token_len;
            sink.varint(len);
            sink.bytes(&address.ip4);
            var port: [2]u8 = undefined;
            std.mem.writeInt(u16, &port, address.ip4_port, .big);
            sink.bytes(&port);
            sink.bytes(&address.ip6);
            std.mem.writeInt(u16, &port, address.ip6_port, .big);
            sink.bytes(&port);
            sink.bytes(&.{address.connection_id.len});
            sink.bytes(address.connection_id.slice());
            sink.bytes(&address.stateless_reset_token);
        }
    }
}

/// Decode parameters sent by a peer in the given role.
///
/// `sender` is the role of whoever sent these, so that §18.2's server-only
/// parameters can be refused when a client sends them.
pub fn decode(bytes: []const u8, sender: Role) Error!Parameters {
    var params: Parameters = .{};
    // A bitmask rather than an EnumSet: `Id` is non-exhaustive so its tag values
    // reach 2^62, and only the seventeen §18.2 defines can be duplicated in a way
    // that matters — unknown ones are ignored before they get here.
    // One bit per identifier, and 64 rather than 32 because RFC 9221's
    // `max_datagram_frame_size` is 0x20 — an extension identifier that a 32-bit word
    // cannot index. Widened with the assertion below rather than after a crash.
    var seen: u64 = 0;

    var rest = bytes;
    while (rest.len > 0) {
        const id_value = varint.take(&rest) catch return error.TransportParameterError;
        const value = varint.takeBytes(&rest) catch return error.TransportParameterError;
        const id: Id = @fromBackingInt(@intCast(id_value));

        // §18.1: unknown parameters must be ignored, which is what makes
        // greasing and extensions work. Checked before anything else, so that an
        // unknown id cannot trip the duplicate detector either.
        const known = switch (id) {
            _ => false,
            else => true,
        };
        if (!known) continue;

        // §18: a duplicate is a connection error. Without this a peer could send
        // a safe value and then an unsafe one and see which the receiver kept.
        //
        // The bitmap is indexed by identifier, so it has to cover every identifier
        // this decoder claims to know — which stopped being "0x00 through 0x10" when
        // RFC 9221's 0x20 arrived. The assertion caught exactly that, which is what it
        // was for; the fix is a wider word rather than a narrower claim.
        assert(id_value <= @backingInt(Id.max_datagram_frame_size));
        const bit = @as(u64, 1) << @intCast(id_value);
        if (seen & bit != 0) return error.TransportParameterError;
        seen |= bit;

        if (id.serverOnly() and sender == .client) return error.TransportParameterForbidden;

        switch (id) {
            .max_idle_timeout => params.max_idle_timeout_ms = try integer(value),
            .max_udp_payload_size => {
                const size = try integer(value);
                // §14.1: an endpoint must accept 1200 bytes, so claiming less is
                // claiming not to speak QUIC.
                if (size < min_max_udp_payload_size) return error.TransportParameterError;
                params.max_udp_payload_size = size;
            },
            .initial_max_data => params.initial_max_data = try integer(value),
            .initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local = try integer(value),
            .initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote = try integer(value),
            .initial_max_stream_data_uni => params.initial_max_stream_data_uni = try integer(value),
            .initial_max_streams_bidi => {
                const count = try integer(value);
                // §18.2: above 2^60 the resulting stream ID would not fit a
                // varint once shifted for its two type bits.
                if (count > (@as(u64, 1) << 60)) return error.TransportParameterError;
                params.initial_max_streams_bidi = count;
            },
            .initial_max_streams_uni => {
                const count = try integer(value);
                if (count > (@as(u64, 1) << 60)) return error.TransportParameterError;
                params.initial_max_streams_uni = count;
            },
            .ack_delay_exponent => {
                const exponent = try integer(value);
                if (exponent > max_ack_delay_exponent) return error.TransportParameterError;
                params.ack_delay_exponent = exponent;
            },
            .max_ack_delay => {
                const delay = try integer(value);
                if (delay > max_max_ack_delay_ms) return error.TransportParameterError;
                params.max_ack_delay_ms = delay;
            },
            .disable_active_migration => {
                // §18.2: zero length. A value here means the peer misunderstands
                // the parameter, so it is refused rather than ignored.
                if (value.len != 0) return error.TransportParameterError;
                params.disable_active_migration = true;
            },
            .active_connection_id_limit => {
                const limit = try integer(value);
                if (limit < min_active_connection_id_limit) return error.TransportParameterError;
                params.active_connection_id_limit = limit;
            },
            .max_datagram_frame_size => params.max_datagram_frame_size = try integer(value),
            .initial_source_connection_id => {
                params.initial_source_connection_id = ConnectionId.init(value) catch
                    return error.TransportParameterError;
            },
            .original_destination_connection_id => {
                params.original_destination_connection_id = ConnectionId.init(value) catch
                    return error.TransportParameterError;
            },
            .retry_source_connection_id => {
                params.retry_source_connection_id = ConnectionId.init(value) catch
                    return error.TransportParameterError;
            },
            .stateless_reset_token => {
                if (value.len != stateless_reset_token_len) return error.TransportParameterError;
                params.stateless_reset_token = value[0..stateless_reset_token_len].*;
            },
            .preferred_address => params.preferred_address = try decodePreferredAddress(value),
            _ => unreachable, // handled by the `known` check above
        }
    }

    return params;
}

fn integer(value: []const u8) Error!u64 {
    var rest = value;
    const result = varint.take(&rest) catch return error.TransportParameterError;
    // §18.1: the value is exactly one varint, so trailing bytes mean the peer
    // encoded something this parameter does not have room for.
    if (rest.len != 0) return error.TransportParameterError;
    return result;
}

fn decodePreferredAddress(value: []const u8) Error!PreferredAddress {
    if (value.len < 4 + 2 + 16 + 2 + 1) return error.TransportParameterError;
    var address: PreferredAddress = .{
        .ip4 = value[0..4].*,
        .ip4_port = std.mem.readInt(u16, value[4..6], .big),
        .ip6 = value[6..22].*,
        .ip6_port = std.mem.readInt(u16, value[22..24], .big),
        .connection_id = .empty,
        .stateless_reset_token = @splat(0),
    };
    const cid_len = value[24];
    if (cid_len > packet.max_cid_len) return error.TransportParameterError;
    const expected = 25 + @as(usize, cid_len) + stateless_reset_token_len;
    if (value.len != expected) return error.TransportParameterError;
    address.connection_id = ConnectionId.init(value[25..][0..cid_len]) catch
        return error.TransportParameterError;
    address.stateless_reset_token = value[25 + cid_len ..][0..stateless_reset_token_len].*;
    return address;
}

/// What was seen in packet headers, for §7.3's check.
pub const ObservedConnectionIds = struct {
    /// The Source Connection ID in the first packet received from the peer.
    peer_source: ConnectionId,
    /// The Destination Connection ID the client put in its first Initial. A
    /// client knows this because it chose it; a server knows it because it
    /// received it.
    original_destination: ?ConnectionId = null,
    /// The Source Connection ID from a Retry packet, if one arrived.
    retry_source: ?ConnectionId = null,
};

/// §7.3: check the peer's reported connection IDs against what the packet
/// headers actually carried.
///
/// This is the point of those parameters. Packet headers are unprotected during
/// the handshake, so an attacker can rewrite a connection ID in flight; the
/// copies here are covered by the handshake's signature. Comparing them turns an
/// invisible rewrite into a failed handshake, and omitting the comparison leaves
/// an attacker free to redirect a connection to itself.
pub fn checkConnectionIds(
    params: *const Parameters,
    sender: Role,
    observed: ObservedConnectionIds,
) Error!void {
    // Both roles must report the source connection ID they used, and it must be
    // the one we saw.
    const reported = params.initial_source_connection_id orelse
        return error.TransportParameterError;
    if (!reported.eql(&observed.peer_source)) return error.ConnectionIdMismatch;

    if (sender == .server) {
        // Only the server reports these, and only the server can know the first
        // one — which is precisely why it proves the server received what the
        // client actually sent.
        const original = params.original_destination_connection_id orelse
            return error.TransportParameterError;
        if (observed.original_destination) |expected| {
            if (!original.eql(&expected)) return error.ConnectionIdMismatch;
        }

        if (observed.retry_source) |expected| {
            // A Retry happened, so the server must say which connection ID it
            // used in it. Absence here would let an attacker inject a Retry.
            const retry = params.retry_source_connection_id orelse
                return error.TransportParameterError;
            if (!retry.eql(&expected)) return error.ConnectionIdMismatch;
        } else if (params.retry_source_connection_id != null) {
            // The reverse: claiming a Retry that never happened.
            return error.ConnectionIdMismatch;
        }
    }
}

const testing = std.testing;

test "transport: an absent parameter means its default, not zero" {
    // §18.2. Getting this wrong makes a peer that omits max_udp_payload_size look
    // as though it cannot receive anything, and one that omits
    // active_connection_id_limit look unable to rotate.
    const params = try decode(&.{}, .server);
    try testing.expectEqual(@as(u64, default_max_udp_payload_size), params.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 3), params.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 25), params.max_ack_delay_ms);
    try testing.expectEqual(@as(u64, min_active_connection_id_limit), params.active_connection_id_limit);
    try testing.expect(!params.disable_active_migration);
    // And zero really does mean "no idle timeout" rather than "expire at once".
    try testing.expectEqual(@as(u64, 0), params.max_idle_timeout_ms);
}

test "transport: a full round trip in both roles" {
    const cid = try ConnectionId.init(&.{ 1, 2, 3, 4 });
    const original = try ConnectionId.init(&.{ 9, 9, 9, 9, 9, 9, 9, 9 });
    const token: [stateless_reset_token_len]u8 = @splat(0xab);

    const server_params: Parameters = .{
        .max_idle_timeout_ms = 30_000,
        .max_udp_payload_size = 1350,
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_local = 65536,
        .initial_max_stream_data_bidi_remote = 65536,
        .initial_max_stream_data_uni = 32768,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 3,
        .ack_delay_exponent = 5,
        .max_ack_delay_ms = 50,
        .disable_active_migration = true,
        .active_connection_id_limit = 8,
        .initial_source_connection_id = cid,
        .original_destination_connection_id = original,
        .stateless_reset_token = token,
    };

    var buf: [256]u8 = undefined;
    const written = encode(&buf, &server_params, .server);
    try testing.expectEqual(encodedLen(&server_params, .server), written);

    const decoded = try decode(buf[0..written], .server);
    try testing.expectEqual(server_params.max_idle_timeout_ms, decoded.max_idle_timeout_ms);
    try testing.expectEqual(server_params.max_udp_payload_size, decoded.max_udp_payload_size);
    try testing.expectEqual(server_params.initial_max_data, decoded.initial_max_data);
    try testing.expectEqual(server_params.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expectEqual(server_params.ack_delay_exponent, decoded.ack_delay_exponent);
    try testing.expectEqual(server_params.max_ack_delay_ms, decoded.max_ack_delay_ms);
    try testing.expect(decoded.disable_active_migration);
    try testing.expectEqual(server_params.active_connection_id_limit, decoded.active_connection_id_limit);
    try testing.expect(decoded.initial_source_connection_id.?.eql(&cid));
    try testing.expect(decoded.original_destination_connection_id.?.eql(&original));
    try testing.expectEqualSlices(u8, &token, &decoded.stateless_reset_token.?);

    // A client's set survives the same trip, and the defaults are sane enough to
    // encode without any server-only parameter appearing.
    var client_params: Parameters = .client_defaults;
    client_params.initial_source_connection_id = cid;
    const client_written = encode(&buf, &client_params, .client);
    const client_decoded = try decode(buf[0..client_written], .client);
    try testing.expectEqual(client_params.initial_max_data, client_decoded.initial_max_data);
    try testing.expect(client_decoded.stateless_reset_token == null);
}

test "transport: a client may not send the server's parameters" {
    // §18.2. `original_destination_connection_id` from a client would be the
    // client telling us what the client itself sent, which proves nothing — the
    // whole value of that parameter is that only the server can know it.
    var buf: [64]u8 = undefined;
    var writer: Writer = .{ .buf = &buf };
    writer.varint(@backingInt(Id.original_destination_connection_id));
    writer.varint(4);
    writer.bytes(&.{ 1, 2, 3, 4 });

    try testing.expectError(
        error.TransportParameterForbidden,
        decode(buf[0..writer.len], .client),
    );
    // The same bytes from a server are fine.
    _ = try decode(buf[0..writer.len], .server);
}

test "transport: a duplicate parameter is a connection error" {
    // §18. Without this a peer could send a safe value followed by an unsafe one
    // and find out which the receiver kept — which is a way to probe for a
    // last-one-wins implementation and then exploit it.
    var buf: [64]u8 = undefined;
    var writer: Writer = .{ .buf = &buf };
    writer.varint(@backingInt(Id.initial_max_data));
    writer.varint(varint.encodedLen(1000));
    writer.varint(1000);
    writer.varint(@backingInt(Id.initial_max_data));
    writer.varint(varint.encodedLen(1 << 30));
    writer.varint(1 << 30);

    try testing.expectError(error.TransportParameterError, decode(buf[0..writer.len], .server));
}

test "transport: unknown parameters are ignored, which is what greasing needs" {
    // §18.1, and the opposite of §19's rule for unknown frame types. Worth a test
    // because the two rules live in the same specification and an implementation
    // that applies one to the other breaks against every greasing peer.
    var buf: [64]u8 = undefined;
    var writer: Writer = .{ .buf = &buf };
    // A reserved value of the form 31 * N + 27 (§18.1).
    writer.varint(31 * 1000 + 27);
    writer.varint(3);
    writer.bytes(&.{ 0xde, 0xad, 0xbe });
    writer.varint(@backingInt(Id.initial_max_data));
    writer.varint(varint.encodedLen(4242));
    writer.varint(4242);

    const params = try decode(buf[0..writer.len], .server);
    try testing.expectEqual(@as(u64, 4242), params.initial_max_data);

    // An unknown parameter twice is still fine, because it never enters the
    // duplicate set at all.
    var again: Writer = .{ .buf = &buf };
    again.varint(31 * 7 + 27);
    again.varint(0);
    again.varint(31 * 7 + 27);
    again.varint(0);
    _ = try decode(buf[0..again.len], .server);
}

test "transport: every range check in §18.2" {
    const cases = [_]struct { id: Id, value: u64 }{
        // §14.1: below the 1200 bytes every endpoint must accept.
        .{ .id = .max_udp_payload_size, .value = 1199 },
        // §18.2: the exponent cannot exceed 20.
        .{ .id = .ack_delay_exponent, .value = 21 },
        // §18.2: under 2^14 milliseconds.
        .{ .id = .max_ack_delay, .value = 1 << 14 },
        // §18.2: at least two, or the endpoint could never rotate its ID.
        .{ .id = .active_connection_id_limit, .value = 1 },
        // §18.2: a stream count whose ID would overflow a varint.
        .{ .id = .initial_max_streams_bidi, .value = (1 << 60) + 1 },
        .{ .id = .initial_max_streams_uni, .value = (1 << 60) + 1 },
    };

    for (cases) |case| {
        var buf: [32]u8 = undefined;
        var writer: Writer = .{ .buf = &buf };
        writer.varint(@backingInt(case.id));
        writer.varint(varint.encodedLen(case.value));
        writer.varint(case.value);
        try testing.expectError(
            error.TransportParameterError,
            decode(buf[0..writer.len], .server),
        );
    }

    // And the values just inside each limit are accepted, so the tests above are
    // checking a boundary rather than rejecting everything.
    const ok = [_]struct { id: Id, value: u64 }{
        .{ .id = .max_udp_payload_size, .value = 1200 },
        .{ .id = .ack_delay_exponent, .value = 20 },
        .{ .id = .max_ack_delay, .value = (1 << 14) - 1 },
        .{ .id = .active_connection_id_limit, .value = 2 },
        .{ .id = .initial_max_streams_bidi, .value = 1 << 60 },
    };
    for (ok) |case| {
        var buf: [32]u8 = undefined;
        var writer: Writer = .{ .buf = &buf };
        writer.varint(@backingInt(case.id));
        writer.varint(varint.encodedLen(case.value));
        writer.varint(case.value);
        _ = try decode(buf[0..writer.len], .server);
    }
}

test "transport: a value with trailing bytes is refused" {
    // §18.1: an integer parameter's value is exactly one varint. Trailing bytes
    // mean the peer put something there this parameter has no room for, and
    // ignoring them would be reading a prefix of an unknown structure.
    var buf: [32]u8 = undefined;
    var writer: Writer = .{ .buf = &buf };
    writer.varint(@backingInt(Id.initial_max_data));
    writer.varint(3);
    writer.bytes(&.{ 0x01, 0xff, 0xff });
    try testing.expectError(error.TransportParameterError, decode(buf[0..writer.len], .server));

    // And disable_active_migration must be exactly zero length.
    var other: Writer = .{ .buf = &buf };
    other.varint(@backingInt(Id.disable_active_migration));
    other.varint(1);
    other.bytes(&.{0});
    try testing.expectError(error.TransportParameterError, decode(buf[0..other.len], .server));
}

test "transport: §7.3 catches a rewritten connection id" {
    // The security property. Packet headers are unprotected during the
    // handshake, so an attacker can change a connection ID in flight; the copy
    // in the transport parameters is covered by the handshake signature. This
    // comparison is what turns an invisible rewrite into a failed handshake.
    const server_cid = try ConnectionId.init(&.{ 0xaa, 0xbb, 0xcc });
    const original_dcid = try ConnectionId.init(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });

    const good: Parameters = .{
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = original_dcid,
    };
    try checkConnectionIds(&good, .server, .{
        .peer_source = server_cid,
        .original_destination = original_dcid,
    });

    // An attacker rewrote the Source Connection ID in the header, so what we saw
    // is not what the server signed.
    const rewritten = try ConnectionId.init(&.{ 0xaa, 0xbb, 0xcd });
    try testing.expectError(error.ConnectionIdMismatch, checkConnectionIds(&good, .server, .{
        .peer_source = rewritten,
        .original_destination = original_dcid,
    }));

    // Or rewrote the client's first Destination Connection ID, which only the
    // server can attest to.
    const other_dcid = try ConnectionId.init(&.{ 8, 7, 6, 5, 4, 3, 2, 1 });
    try testing.expectError(error.ConnectionIdMismatch, checkConnectionIds(&good, .server, .{
        .peer_source = server_cid,
        .original_destination = other_dcid,
    }));

    // A peer that reports no source connection ID at all is refused: §7.3 makes
    // the parameter mandatory precisely so its absence cannot be a way out.
    const silent: Parameters = .{ .original_destination_connection_id = original_dcid };
    try testing.expectError(error.TransportParameterError, checkConnectionIds(&silent, .server, .{
        .peer_source = server_cid,
        .original_destination = original_dcid,
    }));

    // And a server that omits the original destination ID.
    const partial: Parameters = .{ .initial_source_connection_id = server_cid };
    try testing.expectError(error.TransportParameterError, checkConnectionIds(&partial, .server, .{
        .peer_source = server_cid,
        .original_destination = original_dcid,
    }));

    // A client's parameters carry only the one ID, so the same check passes with
    // less to compare.
    const client: Parameters = .{ .initial_source_connection_id = server_cid };
    try checkConnectionIds(&client, .client, .{ .peer_source = server_cid });
}

test "transport: a Retry must be reported by exactly the side that sent one" {
    const server_cid = try ConnectionId.init(&.{ 1, 1, 1 });
    const original_dcid = try ConnectionId.init(&.{ 2, 2, 2, 2 });
    const retry_cid = try ConnectionId.init(&.{ 3, 3, 3, 3, 3 });

    const with_retry: Parameters = .{
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = original_dcid,
        .retry_source_connection_id = retry_cid,
    };
    try checkConnectionIds(&with_retry, .server, .{
        .peer_source = server_cid,
        .original_destination = original_dcid,
        .retry_source = retry_cid,
    });

    // A Retry happened but the server does not say so: that is how an injected
    // Retry would look, since the real server never sent one to attest to.
    const silent_about_retry: Parameters = .{
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = original_dcid,
    };
    try testing.expectError(error.TransportParameterError, checkConnectionIds(
        &silent_about_retry,
        .server,
        .{
            .peer_source = server_cid,
            .original_destination = original_dcid,
            .retry_source = retry_cid,
        },
    ));

    // And the reverse: claiming a Retry that never happened.
    try testing.expectError(error.ConnectionIdMismatch, checkConnectionIds(&with_retry, .server, .{
        .peer_source = server_cid,
        .original_destination = original_dcid,
    }));
}

test "transport: a server's preferred address round trips" {
    const address: PreferredAddress = .{
        .ip4 = .{ 192, 0, 2, 1 },
        .ip4_port = 443,
        .ip6 = @splat(0),
        .ip6_port = 0,
        .connection_id = try ConnectionId.init(&.{ 7, 7, 7 }),
        .stateless_reset_token = @splat(0x5c),
    };
    const params: Parameters = .{
        .initial_source_connection_id = try ConnectionId.init(&.{1}),
        .original_destination_connection_id = try ConnectionId.init(&.{2}),
        .preferred_address = address,
    };

    var buf: [128]u8 = undefined;
    const written = encode(&buf, &params, .server);
    const decoded = try decode(buf[0..written], .server);
    const got = decoded.preferred_address.?;

    try testing.expectEqualSlices(u8, &address.ip4, &got.ip4);
    try testing.expectEqual(@as(u16, 443), got.ip4_port);
    try testing.expect(got.hasIp4());
    // An all-zero family means "not offered" rather than "the unspecified
    // address", which is why this is a method rather than a comparison at each
    // call site.
    try testing.expect(!got.hasIp6());
    try testing.expect(got.connection_id.eql(&address.connection_id));
    try testing.expectEqualSlices(u8, &address.stateless_reset_token, &got.stateless_reset_token);

    // A length that does not match its own connection id length is refused.
    var truncated: [128]u8 = undefined;
    @memcpy(truncated[0..written], buf[0..written]);
    try testing.expectError(
        error.TransportParameterError,
        decode(truncated[0 .. written - 1], .server),
    );
}

test "transport: encodedLen and encode cannot disagree" {
    // They share one traversal with two sinks, which is the same fix the
    // handshake builder uses for length prefixes: a size computed separately
    // from what is written is a size that can drift.
    var prng = std.Random.DefaultPrng.init(0x9001);
    const random = prng.random();

    for (0..256) |_| {
        var params: Parameters = .{};
        params.max_idle_timeout_ms = random.uintAtMost(u64, 1 << 30);
        params.initial_max_data = random.uintAtMost(u64, 1 << 40);
        params.initial_max_streams_bidi = random.uintAtMost(u64, 1000);
        params.ack_delay_exponent = random.uintAtMost(u64, 20);
        params.max_ack_delay_ms = random.uintAtMost(u64, max_max_ack_delay_ms);
        params.disable_active_migration = random.boolean();
        params.active_connection_id_limit = 2 + random.uintAtMost(u64, 6);
        var cid_bytes: [20]u8 = undefined;
        random.bytes(&cid_bytes);
        const cid_len = random.uintAtMost(usize, packet.max_cid_len);
        params.initial_source_connection_id = try ConnectionId.init(cid_bytes[0..cid_len]);

        var buf: [512]u8 = undefined;
        const expected = encodedLen(&params, .client);
        const written = encode(&buf, &params, .client);
        try testing.expectEqual(expected, written);

        // And it decodes back to the same thing.
        const decoded = try decode(buf[0..written], .client);
        try testing.expectEqual(params.max_idle_timeout_ms, decoded.max_idle_timeout_ms);
        try testing.expectEqual(params.initial_max_data, decoded.initial_max_data);
        try testing.expectEqual(params.ack_delay_exponent, decoded.ack_delay_exponent);
        try testing.expectEqual(params.active_connection_id_limit, decoded.active_connection_id_limit);
        try testing.expectEqual(params.disable_active_migration, decoded.disable_active_migration);
    }
}
