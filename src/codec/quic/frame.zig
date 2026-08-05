//! QUIC frames, RFC 9000 §19.
//!
//! Like `http2.frame`, this is parsing and serialization only: no handler, no
//! socket, no state. Unlike it, severity is not in question — QUIC has no notion
//! of a stream error at the frame level, so every malformed frame here is a
//! connection error and the only decision left to `connection.zig` is which
//! error code (§11).
//!
//! Three differences from HTTP/2 shape this interface, and each one is a place
//! an HTTP/2 habit produces a bug:
//!
//! **Variant bits live in the frame type.** A STREAM frame's OFF, LEN and FIN
//! bits are the low three bits of its type value, 0x08 through 0x0f. There is no
//! flags byte, so a type is not a single number to switch on but a number plus a
//! mask.
//!
//! **An unknown frame type is a connection error** (§19), where HTTP/2 §4.1
//! requires ignoring one. The reasoning is inverted because QUIC negotiates
//! extensions through transport parameters, so an unnegotiated frame type means
//! the peer is confused about what was agreed.
//!
//! **The last frame in a packet can omit its length.** With LEN clear, a STREAM
//! or CRYPTO frame runs to the end of the packet. So frames are parsed from a
//! slice that is exactly one packet's payload — which is natural here, because a
//! datagram is a message boundary and there is no stream to reframe.

const std = @import("std");
const assert = std.debug.assert;

const varint = @import("varint.zig");

/// §19. Frame types are varints, so a type is up to 2^62 - 1; these are the
/// ones version 1 defines. Non-exhaustive because an unknown type must be
/// *representable* in order to be reported as an error with its value.
pub const Type = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    // 0x08 .. 0x0f are STREAM with three variant bits; see `stream_base`.
    stream = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close_transport = 0x1c,
    connection_close_application = 0x1d,
    handshake_done = 0x1e,
    /// RFC 9221 §4. The low bit is the LEN flag, exactly as for STREAM frames.
    datagram = 0x30,
    datagram_len = 0x31,
    _,
};

/// §19.8: STREAM frame types occupy 0x08..0x0f, the low three bits being flags.
pub const stream_base: u64 = 0x08;
pub const stream_fin: u64 = 0x01;
pub const stream_len: u64 = 0x02;
pub const stream_off: u64 = 0x04;

/// §19.2 and §21.2: PATH_CHALLENGE and PATH_RESPONSE carry eight bytes of
/// unpredictable data. The length is fixed by the specification, not chosen.
pub const path_data_len = 8;

pub const Error = error{
    /// A frame ran past the end of the packet payload, or a field was shorter
    /// than its own encoding requires. §11.2 maps this to FRAME_ENCODING_ERROR.
    FrameTruncated,
    /// A frame type version 1 does not define and no extension negotiated.
    FrameTypeUnknown,
    /// A field is structurally present but cannot mean anything: an ACK range
    /// that descends below zero, a connection ID of illegal length, a stream ID
    /// whose final offset would exceed 2^62 - 1.
    FrameEncodingInvalid,
} || varint.Error;

pub const Ack = struct {
    largest: u64,
    /// §19.3: in microseconds scaled by the peer's ack_delay_exponent, so it is
    /// deliberately left unscaled here — the exponent is a transport parameter
    /// this layer does not see.
    delay: u64,
    /// §19.3.1: the count of contiguous packets below `largest` also being
    /// acknowledged, so the first range is `largest - first_range ..= largest`.
    first_range: u64,
    range_count: u64,
    /// The additional ranges, kept as raw bytes and walked by `iterator` rather
    /// than allocated. Already validated during parsing, so iteration cannot
    /// fail. **This excludes the range containing `largest`** — use `allRanges`
    /// unless the distinction is the point.
    ranges: []const u8,
    ecn: ?Ecn,

    pub const Ecn = struct { ect0: u64, ect1: u64, ce: u64 };

    /// One acknowledged run of packet numbers, inclusive at both ends.
    pub const Range = struct { largest: u64, smallest: u64 };

    pub fn first(self: Ack) Range {
        return .{ .largest = self.largest, .smallest = self.largest - self.first_range };
    }

    /// Every acknowledged range, first one included.
    ///
    /// This exists because `additionalRanges` is a trap: the first range's bounds
    /// live in explicit fields while the rest are raw bytes, so an iterator over
    /// the bytes alone silently omits the range containing `largest` — and a
    /// caller looking for the largest acknowledged packet number would find
    /// nothing at all in the common case of a single-range ACK. That defect was
    /// live in the connection layer until this method existed. The fix is the
    /// shape of the interface rather than a comment: the obvious call is now the
    /// correct one.
    pub fn allRanges(self: Ack) AllRanges {
        return .{ .ack = self, .rest = self.iterator(), .gave_first = false };
    }

    pub const AllRanges = struct {
        ack: Ack,
        rest: RangeIterator,
        gave_first: bool,

        pub fn next(self: *AllRanges) ?Range {
            if (!self.gave_first) {
                self.gave_first = true;
                return self.ack.first();
            }
            return self.rest.next();
        }
    };

    /// Does any acknowledged range contain `pn`?
    pub fn covers(self: Ack, pn: u64) bool {
        var it = self.allRanges();
        while (it.next()) |range| {
            if (pn <= range.largest and pn >= range.smallest) return true;
        }
        return false;
    }

    pub fn iterator(self: Ack) RangeIterator {
        return .{ .rest = self.ranges, .previous_smallest = self.first().smallest };
    }

    /// §19.3.1's gap arithmetic, in exactly one place.
    ///
    /// Both the validating pass in `parseAck` and `RangeIterator` come through
    /// here. That is deliberate: the first version of this file had the
    /// arithmetic written twice, and a self-check that corrupted one copy passed
    /// the whole suite, because the validator and the iterator disagreed without
    /// anything noticing. Two copies of a rule is two chances to get it wrong
    /// and no way to tell which one is authoritative.
    ///
    /// The two is not a fudge: `gap` counts unacknowledged packets below
    /// `previous_smallest - 1`, so the next acknowledged packet is one further
    /// down again. Returns null when the encoding would descend below zero,
    /// which is a connection error rather than a saturating value — a peer that
    /// acknowledges packet numbers which cannot exist would make the sender
    /// believe lost packets had arrived.
    pub fn descend(previous_smallest: u64, gap: u64, length: u64) ?Range {
        if (gap + 2 > previous_smallest) return null;
        const largest = previous_smallest - gap - 2;
        if (length > largest) return null;
        return .{ .largest = largest, .smallest = largest - length };
    }

    /// The inverse of `descend`, for the encoder. Named and placed next to it so
    /// that the pair is visible: these two are the only places the `2` appears,
    /// and a test round trips them against each other.
    pub fn gapTo(previous_smallest: u64, next_largest: u64) u64 {
        assert(previous_smallest > next_largest + 1); // ranges may not touch
        return previous_smallest - next_largest - 2;
    }

    /// Walks the ranges after the first. Infallible because `parseAck` already
    /// pushed every gap and length through `descend`, which is the point of
    /// validating there rather than here.
    pub const RangeIterator = struct {
        rest: []const u8,
        previous_smallest: u64,

        pub fn next(self: *RangeIterator) ?Range {
            if (self.rest.len == 0) return null;
            const gap = varint.take(&self.rest) catch unreachable;
            const length = varint.take(&self.rest) catch unreachable;
            const range = descend(self.previous_smallest, gap, length) orelse unreachable;
            self.previous_smallest = range.smallest;
            return range;
        }
    };
};

pub const Stream = struct {
    id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
    /// Whether the length was explicit. Kept because it changes what may follow
    /// this frame: with LEN clear the frame consumed the rest of the packet, so
    /// nothing can.
    had_length: bool,
};

pub const Crypto = struct {
    offset: u64,
    data: []const u8,
};

pub const ResetStream = struct {
    id: u64,
    error_code: u64,
    /// §19.4: the sender's final size for the stream, which the receiver needs
    /// in order to account for flow control it never saw the data for.
    final_size: u64,
};

pub const StopSending = struct {
    id: u64,
    error_code: u64,
};

pub const MaxStreamData = struct {
    id: u64,
    limit: u64,
};

pub const StreamDataBlocked = struct {
    id: u64,
    limit: u64,
};

pub const NewConnectionId = struct {
    sequence: u64,
    retire_prior_to: u64,
    /// Borrowed from the packet payload, 1..20 bytes (§19.15 forbids zero
    /// length here, unlike the handshake, because it is issuing an alternative).
    id: []const u8,
    reset_token: *const [16]u8,
};

pub const ConnectionClose = struct {
    error_code: u64,
    /// §19.19: present only in the transport variant. An application close does
    /// not know what frame type was at fault because it is not looking at frames.
    frame_type: ?u64,
    reason: []const u8,
    /// Which variant, since an application close in an Initial packet is
    /// forbidden by §12.4 and the connection layer must be able to tell.
    is_application: bool,
};

pub const Frame = union(enum) {
    /// §19.1: PADDING is one byte, and a packet is normally padded with many.
    /// Runs are coalesced into a count, because a 1200-byte Initial otherwise
    /// yields a thousand frames and every consumer has to know not to care.
    padding: u64,
    ping,
    ack: Ack,
    reset_stream: ResetStream,
    stop_sending: StopSending,
    crypto: Crypto,
    new_token: []const u8,
    stream: Stream,
    max_data: u64,
    max_stream_data: MaxStreamData,
    /// §19.11: a count of streams, not a stream ID.
    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,
    stream_data_blocked: StreamDataBlocked,
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    new_connection_id: NewConnectionId,
    retire_connection_id: u64,
    path_challenge: *const [path_data_len]u8,
    path_response: *const [path_data_len]u8,
    connection_close: ConnectionClose,
    handshake_done,
    /// RFC 9221: application data that will not be retransmitted. Borrowed from the
    /// packet being parsed on the way in, and from the caller on the way out — the
    /// same contract every other payload-carrying frame here has.
    datagram: []const u8,

    /// §13.2: whether receiving this frame obliges an acknowledgement. ACK,
    /// PADDING and CONNECTION_CLOSE do not, and that exclusion is what stops
    /// two idle peers acknowledging each other's acknowledgements for ever.
    pub fn isAckEliciting(self: Frame) bool {
        return switch (self) {
            .padding, .ack, .connection_close => false,
            else => true,
        };
    }

    /// §9.1: a probing frame can arrive from a new address without implying
    /// migration, so a packet containing only these does not move the path.
    /// Anything else makes the packet non-probing, which is the test §9.2 uses.
    pub fn isProbing(self: Frame) bool {
        return switch (self) {
            .padding, .path_challenge, .path_response, .new_connection_id => true,
            else => false,
        };
    }

    /// §12.4, table 3: which packet types may carry this frame. Enforced by the
    /// connection layer, but stated here because the table is a property of the
    /// frame. It is also a security boundary rather than bookkeeping: it is what
    /// stops application data riding in an unauthenticated Initial packet.
    pub fn allowedIn(self: Frame, space: Space) bool {
        return switch (self) {
            .padding, .ping => true,
            // §12.4: ACK and CRYPTO are forbidden in 0-RTT.
            .ack, .crypto => space != .zero_rtt,
            .new_token, .path_response, .handshake_done => space == .one_rtt,
            // RFC 9221 §5: "Like STREAM frames, DATAGRAM frames contain application
            // data and MUST be protected with either 0-RTT or 1-RTT keys."
            .datagram => space == .zero_rtt or space == .one_rtt,
            .connection_close => |close| if (close.is_application)
                // §12.4: an application close needs an application, which does
                // not exist before the handshake keys do.
                space == .zero_rtt or space == .one_rtt
            else
                true,
            else => space == .zero_rtt or space == .one_rtt,
        };
    }
};

/// Which packet type a frame was found in, for `allowedIn`. Distinct from
/// `packet.NumberSpace` because 0-RTT and 1-RTT share a number space but not
/// this table.
pub const Space = enum { initial, handshake, zero_rtt, one_rtt };

/// Parse one frame from the front of `src`, advancing it.
///
/// `src` must be exactly one packet's payload, because a STREAM or CRYPTO frame
/// with its LEN bit clear extends to the end of the packet — there is no other
/// way to know where it stops.
pub fn parse(src: *[]const u8) Error!Frame {
    if (src.len == 0) return error.FrameTruncated;

    const type_value = try varint.take(src);

    // §19.8 first, because it is a range rather than a value.
    if (type_value >= stream_base and type_value < stream_base + 8) {
        return parseStream(src, type_value);
    }

    return switch (@as(Type, @fromBackingInt(@intCast(type_value)))) {
        .padding => blk: {
            // Coalesce the run. The type byte just consumed is the first one.
            var count: u64 = 1;
            while (src.len > 0 and src.*[0] == 0x00) {
                src.* = src.*[1..];
                count += 1;
            }
            break :blk .{ .padding = count };
        },
        .ping => .ping,
        .ack, .ack_ecn => try parseAck(src, type_value == 0x03),
        .reset_stream => .{ .reset_stream = .{
            .id = try varint.take(src),
            .error_code = try varint.take(src),
            .final_size = try varint.take(src),
        } },
        .stop_sending => .{ .stop_sending = .{
            .id = try varint.take(src),
            .error_code = try varint.take(src),
        } },
        .crypto => blk: {
            const offset = try varint.take(src);
            const data = try varint.takeBytes(src);
            // §19.6: the largest offset plus length must stay below 2^62, since
            // that is the largest value a varint can later describe.
            if (offset + data.len > varint.max_value) return error.FrameEncodingInvalid;
            break :blk .{ .crypto = .{ .offset = offset, .data = data } };
        },
        .new_token => blk: {
            const token = try varint.takeBytes(src);
            // §19.7: a zero-length token is a connection error, because a token
            // that proves nothing is not a token.
            if (token.len == 0) return error.FrameEncodingInvalid;
            break :blk .{ .new_token = token };
        },
        .max_data => .{ .max_data = try varint.take(src) },
        .max_stream_data => .{ .max_stream_data = .{
            .id = try varint.take(src),
            .limit = try varint.take(src),
        } },
        .max_streams_bidi => .{ .max_streams_bidi = try takeStreamCount(src) },
        .max_streams_uni => .{ .max_streams_uni = try takeStreamCount(src) },
        .data_blocked => .{ .data_blocked = try varint.take(src) },
        .stream_data_blocked => .{ .stream_data_blocked = .{
            .id = try varint.take(src),
            .limit = try varint.take(src),
        } },
        .streams_blocked_bidi => .{ .streams_blocked_bidi = try takeStreamCount(src) },
        .streams_blocked_uni => .{ .streams_blocked_uni = try takeStreamCount(src) },
        .new_connection_id => try parseNewConnectionId(src),
        .retire_connection_id => .{ .retire_connection_id = try varint.take(src) },
        .path_challenge => .{ .path_challenge = try takePathData(src) },
        .path_response => .{ .path_response = try takePathData(src) },
        .connection_close_transport, .connection_close_application => blk: {
            const is_application = type_value == 0x1d;
            const error_code = try varint.take(src);
            const frame_type: ?u64 = if (is_application) null else try varint.take(src);
            const reason = try varint.takeBytes(src);
            break :blk .{ .connection_close = .{
                .error_code = error_code,
                .frame_type = frame_type,
                .reason = reason,
                .is_application = is_application,
            } };
        },
        .handshake_done => .handshake_done,
        // RFC 9221 §4: the LEN bit decides whether a length is present, and with it
        // clear "the Datagram Data field extends to the end of the packet". Empty
        // datagrams are explicitly allowed, so a zero length is not an error.
        .datagram, .datagram_len => blk: {
            const with_length = type_value == @backingInt(Type.datagram_len);
            const data = if (with_length) try varint.takeBytes(src) else rest: {
                const all = src.*;
                src.* = src.*[src.len..];
                break :rest all;
            };
            break :blk .{ .datagram = data };
        },
        // §19: unlike HTTP/2, an unknown frame type is fatal. Extensions are
        // agreed through transport parameters, so an unnegotiated type means the
        // peer has a different idea of what was agreed than we do.
        _ => error.FrameTypeUnknown,
        .stream => unreachable, // handled above as a range
    };
}

fn parseStream(src: *[]const u8, type_value: u64) Error!Frame {
    const flags = type_value - stream_base;
    const id = try varint.take(src);
    const offset = if (flags & stream_off != 0) try varint.take(src) else 0;
    const had_length = flags & stream_len != 0;
    const data = if (had_length) try varint.takeBytes(src) else blk: {
        // §19.8: with LEN clear the frame extends to the end of the packet.
        const rest = src.*;
        src.* = src.*[src.len..];
        break :blk rest;
    };

    // §4.5: the final size of a stream cannot exceed 2^62 - 1, so neither can
    // any offset within it. Checked here because an overflow later would wrap
    // into a small offset and silently corrupt the reassembly buffer.
    if (offset + data.len > varint.max_value) return error.FrameEncodingInvalid;

    return .{ .stream = .{
        .id = id,
        .offset = offset,
        .data = data,
        .fin = flags & stream_fin != 0,
        .had_length = had_length,
    } };
}

fn parseAck(src: *[]const u8, with_ecn: bool) Error!Frame {
    const largest = try varint.take(src);
    const delay = try varint.take(src);
    const range_count = try varint.take(src);
    const first_range = try varint.take(src);

    // §19.3.1: the first range descends from `largest`, so it cannot descend
    // past zero.
    if (first_range > largest) return error.FrameEncodingInvalid;
    var smallest = largest - first_range;

    // Walk the ranges now rather than lazily. Two reasons: the frame's end is
    // not known until they are all consumed, and validating here is what lets
    // the iterator be infallible. A dishonest range_count cannot loop for long,
    // because every iteration consumes at least two bytes.
    const ranges_start = src.*;
    var i: u64 = 0;
    while (i < range_count) : (i += 1) {
        const gap = try varint.take(src);
        const length = try varint.take(src);

        // The same function the iterator uses, so the two cannot drift apart.
        const range = Ack.descend(smallest, gap, length) orelse
            return error.FrameEncodingInvalid;
        smallest = range.smallest;
    }
    const ranges = ranges_start[0 .. ranges_start.len - src.len];

    const ecn: ?Ack.Ecn = if (with_ecn) .{
        .ect0 = try varint.take(src),
        .ect1 = try varint.take(src),
        .ce = try varint.take(src),
    } else null;

    return .{ .ack = .{
        .largest = largest,
        .delay = delay,
        .first_range = first_range,
        .range_count = range_count,
        .ranges = ranges,
        .ecn = ecn,
    } };
}

fn parseNewConnectionId(src: *[]const u8) Error!Frame {
    const sequence = try varint.take(src);
    const retire_prior_to = try varint.take(src);
    // §19.15: retire_prior_to greater than the sequence number being issued is
    // a connection error, because it would retire a connection ID that has not
    // been given out.
    if (retire_prior_to > sequence) return error.FrameEncodingInvalid;

    if (src.len == 0) return error.FrameTruncated;
    const len = src.*[0];
    src.* = src.*[1..];
    // §19.15: 1 to 20. Zero is legal for a handshake connection ID but not
    // here, because an endpoint using zero-length IDs has nothing to migrate to.
    if (len == 0 or len > 20) return error.FrameEncodingInvalid;
    if (src.len < @as(usize, len) + 16) return error.FrameTruncated;

    const id = src.*[0..len];
    src.* = src.*[len..];
    const token = src.*[0..16];
    src.* = src.*[16..];

    return .{ .new_connection_id = .{
        .sequence = sequence,
        .retire_prior_to = retire_prior_to,
        .id = id,
        .reset_token = token,
    } };
}

fn takeStreamCount(src: *[]const u8) Error!u64 {
    const count = try varint.take(src);
    // §19.11: a count above 2^60 is a connection error, because the resulting
    // stream ID would not fit in a varint once shifted for its two type bits.
    if (count > (@as(u64, 1) << 60)) return error.FrameEncodingInvalid;
    return count;
}

fn takePathData(src: *[]const u8) Error!*const [path_data_len]u8 {
    if (src.len < path_data_len) return error.FrameTruncated;
    const data = src.*[0..path_data_len];
    src.* = src.*[path_data_len..];
    return data;
}

/// Bytes `encode` will write for `frame`. Callers need this before writing,
/// because a packet's size is bounded by the congestion window and the path MTU
/// and a frame that does not fit must be deferred rather than truncated.
pub fn encodedLen(frame: Frame) usize {
    return switch (frame) {
        .padding => |count| @intCast(count),
        .ping, .handshake_done => 1,
        // Always encoded with an explicit length (type 0x31): the length-less form
        // only works as the last frame in a packet, and making that a property of the
        // caller's frame ordering would be a trap for one saved byte.
        .datagram => |data| 1 + varint.encodedLen(data.len) + data.len,
        .ack => |ack| blk: {
            var len: usize = 1 + varint.encodedLen(ack.largest) +
                varint.encodedLen(ack.delay) + varint.encodedLen(ack.range_count) +
                varint.encodedLen(ack.first_range) + ack.ranges.len;
            if (ack.ecn) |ecn| len += varint.encodedLen(ecn.ect0) +
                varint.encodedLen(ecn.ect1) + varint.encodedLen(ecn.ce);
            break :blk len;
        },
        .reset_stream => |f| 1 + varint.encodedLen(f.id) +
            varint.encodedLen(f.error_code) + varint.encodedLen(f.final_size),
        .stop_sending => |f| 1 + varint.encodedLen(f.id) + varint.encodedLen(f.error_code),
        .crypto => |f| 1 + varint.encodedLen(f.offset) +
            varint.encodedLen(f.data.len) + f.data.len,
        .new_token => |token| 1 + varint.encodedLen(token.len) + token.len,
        .stream => |f| blk: {
            var len: usize = 1 + varint.encodedLen(f.id);
            if (f.offset != 0) len += varint.encodedLen(f.offset);
            if (f.had_length) len += varint.encodedLen(f.data.len);
            break :blk len + f.data.len;
        },
        .max_data, .data_blocked, .retire_connection_id => |v| 1 + varint.encodedLen(v),
        .max_streams_bidi, .max_streams_uni => |v| 1 + varint.encodedLen(v),
        .streams_blocked_bidi, .streams_blocked_uni => |v| 1 + varint.encodedLen(v),
        .max_stream_data => |f| 1 + varint.encodedLen(f.id) + varint.encodedLen(f.limit),
        .stream_data_blocked => |f| 1 + varint.encodedLen(f.id) + varint.encodedLen(f.limit),
        .new_connection_id => |f| 1 + varint.encodedLen(f.sequence) +
            varint.encodedLen(f.retire_prior_to) + 1 + f.id.len + 16,
        .path_challenge, .path_response => 1 + path_data_len,
        .connection_close => |f| blk: {
            var len: usize = 1 + varint.encodedLen(f.error_code) +
                varint.encodedLen(f.reason.len) + f.reason.len;
            // §19.19: the transport form (0x1c) always carries the Frame Type field,
            // and "a value of 0 ... is used when the frame type is unknown". Only the
            // application form (0x1d) omits it. Making it conditional on the caller
            // having a value to put there produced a frame this file's own parser
            // could not read — it reads the field whenever the type is 0x1c — which
            // went unnoticed because every close ever encoded was either an
            // application close or a test that happened to name a frame type.
            if (!f.is_application) len += varint.encodedLen(f.frame_type orelse 0);
            break :blk len;
        },
    };
}

/// Serialize `frame` into `dest`, returning the bytes written. Asserts `dest` is
/// large enough: the caller knows the size from `encodedLen`, so a short buffer
/// is a local bug.
pub fn encode(dest: []u8, frame: Frame) usize {
    const needed = encodedLen(frame);
    assert(dest.len >= needed);
    var i: usize = 0;

    switch (frame) {
        .padding => |count| {
            @memset(dest[0..@intCast(count)], 0x00);
            i = @intCast(count);
        },
        .ping => {
            i += putType(dest[i..], .ping);
        },
        .datagram => |data| {
            i += putType(dest[i..], .datagram_len);
            i += varint.encode(dest[i..], data.len);
            @memcpy(dest[i..][0..data.len], data);
            i += data.len;
        },
        .handshake_done => {
            i += putType(dest[i..], .handshake_done);
        },
        .ack => |ack| {
            i += putType(dest[i..], if (ack.ecn == null) .ack else .ack_ecn);
            i += varint.encode(dest[i..], ack.largest);
            i += varint.encode(dest[i..], ack.delay);
            i += varint.encode(dest[i..], ack.range_count);
            i += varint.encode(dest[i..], ack.first_range);
            @memcpy(dest[i..][0..ack.ranges.len], ack.ranges);
            i += ack.ranges.len;
            if (ack.ecn) |ecn| {
                i += varint.encode(dest[i..], ecn.ect0);
                i += varint.encode(dest[i..], ecn.ect1);
                i += varint.encode(dest[i..], ecn.ce);
            }
        },
        .reset_stream => |f| {
            i += putType(dest[i..], .reset_stream);
            i += varint.encode(dest[i..], f.id);
            i += varint.encode(dest[i..], f.error_code);
            i += varint.encode(dest[i..], f.final_size);
        },
        .stop_sending => |f| {
            i += putType(dest[i..], .stop_sending);
            i += varint.encode(dest[i..], f.id);
            i += varint.encode(dest[i..], f.error_code);
        },
        .crypto => |f| {
            i += putType(dest[i..], .crypto);
            i += varint.encode(dest[i..], f.offset);
            i += varint.encode(dest[i..], f.data.len);
            @memcpy(dest[i..][0..f.data.len], f.data);
            i += f.data.len;
        },
        .new_token => |token| {
            i += putType(dest[i..], .new_token);
            i += varint.encode(dest[i..], token.len);
            @memcpy(dest[i..][0..token.len], token);
            i += token.len;
        },
        .stream => |f| {
            var type_value = stream_base;
            if (f.offset != 0) type_value |= stream_off;
            if (f.had_length) type_value |= stream_len;
            if (f.fin) type_value |= stream_fin;
            i += varint.encode(dest[i..], type_value);
            i += varint.encode(dest[i..], f.id);
            if (f.offset != 0) i += varint.encode(dest[i..], f.offset);
            if (f.had_length) i += varint.encode(dest[i..], f.data.len);
            @memcpy(dest[i..][0..f.data.len], f.data);
            i += f.data.len;
        },
        .max_data => |v| {
            i += putType(dest[i..], .max_data);
            i += varint.encode(dest[i..], v);
        },
        .max_stream_data => |f| {
            i += putType(dest[i..], .max_stream_data);
            i += varint.encode(dest[i..], f.id);
            i += varint.encode(dest[i..], f.limit);
        },
        .max_streams_bidi => |v| {
            i += putType(dest[i..], .max_streams_bidi);
            i += varint.encode(dest[i..], v);
        },
        .max_streams_uni => |v| {
            i += putType(dest[i..], .max_streams_uni);
            i += varint.encode(dest[i..], v);
        },
        .data_blocked => |v| {
            i += putType(dest[i..], .data_blocked);
            i += varint.encode(dest[i..], v);
        },
        .stream_data_blocked => |f| {
            i += putType(dest[i..], .stream_data_blocked);
            i += varint.encode(dest[i..], f.id);
            i += varint.encode(dest[i..], f.limit);
        },
        .streams_blocked_bidi => |v| {
            i += putType(dest[i..], .streams_blocked_bidi);
            i += varint.encode(dest[i..], v);
        },
        .streams_blocked_uni => |v| {
            i += putType(dest[i..], .streams_blocked_uni);
            i += varint.encode(dest[i..], v);
        },
        .new_connection_id => |f| {
            i += putType(dest[i..], .new_connection_id);
            i += varint.encode(dest[i..], f.sequence);
            i += varint.encode(dest[i..], f.retire_prior_to);
            dest[i] = @intCast(f.id.len);
            i += 1;
            @memcpy(dest[i..][0..f.id.len], f.id);
            i += f.id.len;
            @memcpy(dest[i..][0..16], f.reset_token);
            i += 16;
        },
        .retire_connection_id => |v| {
            i += putType(dest[i..], .retire_connection_id);
            i += varint.encode(dest[i..], v);
        },
        .path_challenge => |data| {
            i += putType(dest[i..], .path_challenge);
            @memcpy(dest[i..][0..path_data_len], data);
            i += path_data_len;
        },
        .path_response => |data| {
            i += putType(dest[i..], .path_response);
            @memcpy(dest[i..][0..path_data_len], data);
            i += path_data_len;
        },
        .connection_close => |f| {
            i += putType(dest[i..], if (f.is_application)
                .connection_close_application
            else
                .connection_close_transport);
            i += varint.encode(dest[i..], f.error_code);
            if (!f.is_application) i += varint.encode(dest[i..], f.frame_type orelse 0);
            i += varint.encode(dest[i..], f.reason.len);
            @memcpy(dest[i..][0..f.reason.len], f.reason);
            i += f.reason.len;
        },
    }

    assert(i == needed);
    return i;
}

fn putType(dest: []u8, frame_type: Type) usize {
    return varint.encode(dest, @backingInt(frame_type));
}

/// Write an ACK frame from a descending list of acknowledged ranges.
///
/// Kept separate from `encode` because building the ranges is the connection
/// layer's job: this takes them already in the form §19.3.1 describes and does
/// the gap arithmetic, which is the part worth having in one tested place.
pub fn writeAck(
    dest: []u8,
    ranges: []const Ack.Range,
    delay: u64,
    ecn: ?Ack.Ecn,
) usize {
    assert(ranges.len >= 1);
    var i: usize = 0;
    i += varint.encode(dest[i..], if (ecn == null) 0x02 else 0x03);
    i += varint.encode(dest[i..], ranges[0].largest);
    i += varint.encode(dest[i..], delay);
    i += varint.encode(dest[i..], ranges.len - 1);
    i += varint.encode(dest[i..], ranges[0].largest - ranges[0].smallest);

    for (ranges[1..], 0..) |range, index| {
        const previous = ranges[index]; // the one before, since we skipped the first
        i += varint.encode(dest[i..], Ack.gapTo(previous.smallest, range.largest));
        i += varint.encode(dest[i..], range.largest - range.smallest);
    }

    if (ecn) |counts| {
        i += varint.encode(dest[i..], counts.ect0);
        i += varint.encode(dest[i..], counts.ect1);
        i += varint.encode(dest[i..], counts.ce);
    }
    return i;
}

const testing = std.testing;

fn parseOne(bytes: []const u8) Error!Frame {
    var src: []const u8 = bytes;
    return parse(&src);
}

test "frame: a run of padding becomes one frame" {
    // §19.1. Otherwise a padded Initial packet produces a thousand frames and
    // every consumer needs to know to ignore them.
    var bytes: [1200]u8 = @splat(0x00);
    var src: []const u8 = &bytes;
    const frame = try parse(&src);
    try testing.expectEqual(@as(u64, 1200), frame.padding);
    try testing.expectEqual(@as(usize, 0), src.len);
    try testing.expect(!frame.isAckEliciting());
    try testing.expect(frame.isProbing());
}

test "frame: padding stops at the first non-padding byte" {
    const bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01 }; // three pads then PING
    var src: []const u8 = &bytes;
    const pad = try parse(&src);
    try testing.expectEqual(@as(u64, 3), pad.padding);
    const ping = try parse(&src);
    try testing.expect(ping == .ping);
    try testing.expectEqual(@as(usize, 0), src.len);
}

test "frame: all eight STREAM variants" {
    // §19.8. The three bits are in the type value, so each combination is a
    // different frame type and all eight need to work.
    const gpa = testing.allocator;
    for (0..8) |flags| {
        const has_off = flags & stream_off != 0;
        const has_len = flags & stream_len != 0;
        const has_fin = flags & stream_fin != 0;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        var scratch: [8]u8 = undefined;

        try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, stream_base + flags)]);
        try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 4)]); // stream id
        if (has_off) try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 100)]);
        if (has_len) try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 3)]);
        try buf.appendSlice(gpa, "abc");

        const frame = try parseOne(buf.items);
        try testing.expectEqual(@as(u64, 4), frame.stream.id);
        try testing.expectEqual(@as(u64, if (has_off) 100 else 0), frame.stream.offset);
        try testing.expectEqualStrings("abc", frame.stream.data);
        try testing.expectEqual(has_fin, frame.stream.fin);
        try testing.expectEqual(has_len, frame.stream.had_length);

        // And it round trips, including which bits were set.
        var out: [64]u8 = undefined;
        const written = encode(&out, frame);
        try testing.expectEqualSlices(u8, buf.items, out[0..written]);
    }
}

test "frame: a STREAM frame without a length runs to the end of the packet" {
    // §19.8. This is why frames are parsed from a packet payload rather than a
    // stream: nothing else says where the data stops.
    var scratch: [8]u8 = undefined;
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, stream_base)]); // no LEN
    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 8)]);
    try buf.appendSlice(gpa, "everything that follows");

    var src: []const u8 = buf.items;
    const frame = try parse(&src);
    try testing.expectEqualStrings("everything that follows", frame.stream.data);
    try testing.expectEqual(@as(usize, 0), src.len);
    try testing.expect(!frame.stream.had_length);
}

test "frame: ACK ranges and the two the specification subtracts" {
    // §19.3.1. Acknowledging 100..104, 90..95 and 80..80.
    const ranges = [_]Ack.Range{
        .{ .largest = 104, .smallest = 100 },
        .{ .largest = 95, .smallest = 90 },
        .{ .largest = 80, .smallest = 80 },
    };
    var out: [64]u8 = undefined;
    const written = writeAck(&out, &ranges, 42, null);

    const frame = try parseOne(out[0..written]);
    const ack = frame.ack;
    try testing.expectEqual(@as(u64, 104), ack.largest);
    try testing.expectEqual(@as(u64, 42), ack.delay);
    try testing.expectEqual(@as(u64, 2), ack.range_count);
    try testing.expectEqual(@as(u64, 104), ack.first().largest);
    try testing.expectEqual(@as(u64, 100), ack.first().smallest);

    var it = ack.iterator();
    const second = it.next().?;
    try testing.expectEqual(@as(u64, 95), second.largest);
    try testing.expectEqual(@as(u64, 90), second.smallest);
    const third = it.next().?;
    try testing.expectEqual(@as(u64, 80), third.largest);
    try testing.expectEqual(@as(u64, 80), third.smallest);
    try testing.expect(it.next() == null);

    // An ACK does not itself need acknowledging (§13.2), which is what stops
    // two idle peers acknowledging each other for ever.
    try testing.expect(!frame.isAckEliciting());
}

test "frame: an ACK range descending below zero is refused" {
    // Without this check a peer can acknowledge packet numbers that cannot
    // exist. The sender would then believe lost packets had arrived and never
    // retransmit them — data loss with no error anywhere.
    var out: [32]u8 = undefined;
    var i: usize = 0;
    i += varint.encode(out[i..], 0x02); // ACK
    i += varint.encode(out[i..], 10); // largest
    i += varint.encode(out[i..], 0); // delay
    i += varint.encode(out[i..], 1); // one extra range
    i += varint.encode(out[i..], 2); // first range: 8..10
    i += varint.encode(out[i..], 20); // gap of 20, far below zero
    i += varint.encode(out[i..], 0);

    try testing.expectError(error.FrameEncodingInvalid, parseOne(out[0..i]));

    // And a first range larger than the largest acknowledged.
    var j: usize = 0;
    j += varint.encode(out[j..], 0x02);
    j += varint.encode(out[j..], 5);
    j += varint.encode(out[j..], 0);
    j += varint.encode(out[j..], 0);
    j += varint.encode(out[j..], 9); // descends past zero
    try testing.expectError(error.FrameEncodingInvalid, parseOne(out[0..j]));
}

test "frame: an ACK with ECN counts" {
    const ranges = [_]Ack.Range{.{ .largest = 7, .smallest = 7 }};
    var out: [64]u8 = undefined;
    const written = writeAck(&out, &ranges, 1, .{ .ect0 = 3, .ect1 = 4, .ce = 5 });
    const frame = try parseOne(out[0..written]);
    try testing.expectEqual(@as(u64, 3), frame.ack.ecn.?.ect0);
    try testing.expectEqual(@as(u64, 5), frame.ack.ecn.?.ce);
    try testing.expectEqual(written, encodedLen(frame));
}

test "frame: an unknown frame type is a connection error, unlike HTTP/2" {
    // §19. HTTP/2 §4.1 requires ignoring unknown frames; QUIC requires failing.
    // Extensions here are agreed in transport parameters, so an unnegotiated
    // type means the peer disagrees about what was agreed.
    var out: [8]u8 = undefined;
    const written = varint.encode(&out, 0x42);
    try testing.expectError(error.FrameTypeUnknown, parseOne(out[0..written]));

    // Including a greased eight-byte type, which must be reported rather than
    // silently skipped.
    const wide = varint.encodeIn(&out, 0x1f, 8);
    try testing.expectError(error.FrameTypeUnknown, parseOne(out[0..wide]));
}

test "frame: §12.4 forbids application data in an Initial packet" {
    // The table is a security boundary, not bookkeeping: an Initial packet is
    // unauthenticated, so anything that reaches the application from one would
    // be attacker-controlled.
    const stream_frame: Frame = .{ .stream = .{
        .id = 0,
        .offset = 0,
        .data = "x",
        .fin = false,
        .had_length = true,
    } };
    try testing.expect(!stream_frame.allowedIn(.initial));
    try testing.expect(!stream_frame.allowedIn(.handshake));
    try testing.expect(stream_frame.allowedIn(.zero_rtt));
    try testing.expect(stream_frame.allowedIn(.one_rtt));

    // CRYPTO is the inverse: allowed in the handshake spaces, forbidden in
    // 0-RTT because the handshake cannot progress on unacknowledged data.
    const crypto_frame: Frame = .{ .crypto = .{ .offset = 0, .data = "x" } };
    try testing.expect(crypto_frame.allowedIn(.initial));
    try testing.expect(!crypto_frame.allowedIn(.zero_rtt));

    // An application close needs an application to exist.
    const app_close: Frame = .{ .connection_close = .{
        .error_code = 0,
        .frame_type = null,
        .reason = "",
        .is_application = true,
    } };
    try testing.expect(!app_close.allowedIn(.initial));
    try testing.expect(app_close.allowedIn(.one_rtt));

    const transport_close: Frame = .{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0x06,
        .reason = "",
        .is_application = false,
    } };
    try testing.expect(transport_close.allowedIn(.initial));
}

test "frame: NEW_CONNECTION_ID rejects what it must" {
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    var scratch: [8]u8 = undefined;

    // retire_prior_to above the sequence being issued would retire something
    // never given out (§19.15).
    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 0x18)]);
    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 2)]); // sequence
    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 5)]); // retire_prior_to
    try buf.append(gpa, 4);
    try buf.appendSlice(gpa, &.{ 1, 2, 3, 4 });
    try buf.appendNTimes(gpa, 0xaa, 16);
    try testing.expectError(error.FrameEncodingInvalid, parseOne(buf.items));

    // A zero-length connection ID here is invalid, though it is legal in a
    // handshake header: an endpoint issuing an alternative must issue one.
    buf.clearRetainingCapacity();
    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 0x18)]);
    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 1)]);
    try buf.appendSlice(gpa, scratch[0..varint.encode(&scratch, 0)]);
    try buf.append(gpa, 0); // zero length
    try buf.appendNTimes(gpa, 0xaa, 16);
    try testing.expectError(error.FrameEncodingInvalid, parseOne(buf.items));
}

test "frame: CONNECTION_CLOSE has a frame type only in its transport form" {
    // §19.19. An application close does not know the frame type because it is
    // not looking at frames.
    var out: [64]u8 = undefined;

    const transport: Frame = .{ .connection_close = .{
        .error_code = 0x0a,
        .frame_type = 0x06,
        .reason = "bad crypto",
        .is_application = false,
    } };
    var written = encode(&out, transport);
    var parsed = try parseOne(out[0..written]);
    try testing.expectEqual(@as(?u64, 0x06), parsed.connection_close.frame_type);
    try testing.expectEqualStrings("bad crypto", parsed.connection_close.reason);
    try testing.expect(!parsed.connection_close.is_application);

    const application: Frame = .{ .connection_close = .{
        .error_code = 0x100,
        .frame_type = null,
        .reason = "",
        .is_application = true,
    } };
    written = encode(&out, application);
    parsed = try parseOne(out[0..written]);
    try testing.expect(parsed.connection_close.frame_type == null);
    try testing.expect(parsed.connection_close.is_application);
    try testing.expectEqual(@as(usize, 0), parsed.connection_close.reason.len);
}

test "frame: every simple frame round trips and reports its own length" {
    const challenge: [path_data_len]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const token: [16]u8 = @splat(0xbb);
    const frames = [_]Frame{
        .ping,
        .handshake_done,
        .{ .reset_stream = .{ .id = 4, .error_code = 7, .final_size = 1000 } },
        .{ .stop_sending = .{ .id = 8, .error_code = 2 } },
        .{ .crypto = .{ .offset = 300, .data = "handshake bytes" } },
        .{ .new_token = "a token" },
        .{ .max_data = 1 << 30 },
        .{ .max_stream_data = .{ .id = 12, .limit = 65536 } },
        .{ .max_streams_bidi = 100 },
        .{ .max_streams_uni = 3 },
        .{ .data_blocked = 1 << 20 },
        .{ .stream_data_blocked = .{ .id = 16, .limit = 4096 } },
        .{ .streams_blocked_bidi = 50 },
        .{ .streams_blocked_uni = 0 },
        .{ .retire_connection_id = 3 },
        .{ .path_challenge = &challenge },
        .{ .path_response = &challenge },
        .{ .new_connection_id = .{
            .sequence = 4,
            .retire_prior_to = 2,
            .id = &.{ 9, 9, 9 },
            .reset_token = &token,
        } },
    };

    for (frames) |frame| {
        var out: [128]u8 = undefined;
        const written = encode(&out, frame);
        try testing.expectEqual(encodedLen(frame), written);

        var src: []const u8 = out[0..written];
        const parsed = try parse(&src);
        try testing.expectEqual(@as(usize, 0), src.len);
        try testing.expectEqual(std.meta.activeTag(frame), std.meta.activeTag(parsed));

        // Re-encoding the parsed frame must give back the same bytes.
        var again: [128]u8 = undefined;
        const rewritten = encode(&again, parsed);
        try testing.expectEqualSlices(u8, out[0..written], again[0..rewritten]);
    }
}

test "frame: every prefix of a valid frame sequence fails cleanly" {
    // A packet payload arrives whole or not at all, so truncation here means a
    // malicious or corrupt packet rather than a partial read. It must be
    // reported, never read past.
    const gpa = testing.allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);

    const token: [16]u8 = @splat(0xcc);
    const frames = [_]Frame{
        .{ .crypto = .{ .offset = 0, .data = "hello" } },
        .{ .ack = .{
            .largest = 9,
            .delay = 0,
            .first_range = 2,
            .range_count = 0,
            .ranges = &.{},
            .ecn = null,
        } },
        .{ .new_connection_id = .{
            .sequence = 1,
            .retire_prior_to = 0,
            .id = &.{ 7, 7 },
            .reset_token = &token,
        } },
        .ping,
    };
    for (frames) |frame| {
        var out: [128]u8 = undefined;
        const written = encode(&out, frame);
        try buf.appendSlice(gpa, out[0..written]);
    }

    // The whole thing parses into exactly four frames.
    var src: []const u8 = buf.items;
    var count: usize = 0;
    while (src.len > 0) : (count += 1) _ = try parse(&src);
    try testing.expectEqual(@as(usize, 4), count);

    // And no prefix crashes or reads past its end.
    for (0..buf.items.len) |cut| {
        var prefix: []const u8 = buf.items[0..cut];
        while (prefix.len > 0) {
            _ = parse(&prefix) catch break;
        }
    }
}

test "frame: a stream offset that would overflow the varint space is refused" {
    // §4.5: a stream's final size cannot exceed 2^62 - 1. Unchecked, the
    // addition wraps to a small offset and corrupts reassembly silently.
    var out: [32]u8 = undefined;
    var i: usize = 0;
    i += varint.encode(out[i..], stream_base | stream_off | stream_len);
    i += varint.encode(out[i..], 0); // stream 0
    i += varint.encode(out[i..], varint.max_value); // offset at the ceiling
    i += varint.encode(out[i..], 1); // one more byte
    out[i] = 0xff;
    i += 1;

    try testing.expectError(error.FrameEncodingInvalid, parseOne(out[0..i]));
}

test "frame: the gap arithmetic is its own inverse" {
    // `descend` and `gapTo` are the only two places §19.3.1's `2` appears, and
    // a mismatch between them would be invisible in a round trip through both.
    // So they are checked against each other directly, over the shapes that
    // matter: adjacent-but-one ranges, wide gaps, and single-packet ranges.
    const previous_smallest: u64 = 1000;
    for ([_]u64{ 2, 3, 10, 500 }) |distance| {
        for ([_]u64{ 0, 1, 7 }) |length| {
            if (distance < length + 2) continue;
            const next_largest = previous_smallest - distance;
            const gap = Ack.gapTo(previous_smallest, next_largest);
            const range = Ack.descend(previous_smallest, gap, length).?;
            try testing.expectEqual(next_largest, range.largest);
            try testing.expectEqual(next_largest - length, range.smallest);
        }
    }
}

test "frame: §19.19 the transport close always carries a frame type, the application one never" {
    // The field is mandatory in the 0x1c form and absent from 0x1d, and the parser in
    // this file has always read it that way. The encoder wrote it only when the caller
    // supplied one, so a transport close with no frame type to name — which is the
    // ordinary case for a protocol violation detected outside frame parsing — encoded
    // one varint short and desynchronised whatever read it. Nothing caught it because
    // the only closes ever encoded were application closes, which omit the field
    // correctly, and one test that happened to pass a frame type.
    var buf: [64]u8 = undefined;

    for ([_]?u64{ null, 0, 0x06 }) |frame_type| {
        const transport_close: Frame = .{ .connection_close = .{
            .error_code = 0x0a,
            .frame_type = frame_type,
            .reason = "why",
            .is_application = false,
        } };
        const len = encode(&buf, transport_close);
        try testing.expectEqual(encodedLen(transport_close), len);

        var rest: []const u8 = buf[0..len];
        const back = try parse(&rest);
        try testing.expectEqual(@as(usize, 0), rest.len);
        try testing.expect(!back.connection_close.is_application);
        try testing.expectEqual(@as(u64, 0x0a), back.connection_close.error_code);
        try testing.expectEqualStrings("why", back.connection_close.reason);
        // A missing type reads back as §19.19's "unknown", which is the value 0.
        try testing.expectEqual(@as(?u64, frame_type orelse 0), back.connection_close.frame_type);
    }

    const app_close: Frame = .{ .connection_close = .{
        .error_code = 0x0102,
        .frame_type = null,
        .reason = "",
        .is_application = true,
    } };
    const len = encode(&buf, app_close);
    try testing.expectEqual(encodedLen(app_close), len);
    var rest: []const u8 = buf[0..len];
    const back = try parse(&rest);
    try testing.expectEqual(@as(usize, 0), rest.len);
    try testing.expect(back.connection_close.is_application);
    try testing.expectEqual(@as(?u64, null), back.connection_close.frame_type);
}
