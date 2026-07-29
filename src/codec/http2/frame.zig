//! The HTTP/2 frame layer: RFC 9113 §4 and §6.
//!
//! This is deliberately not a pipeline handler. HTTP/2's frames are internal
//! machinery — what reaches an application pipeline is a stream's headers and
//! data, not a `WINDOW_UPDATE` — so framing lives here as pure functions over
//! bytes and the connection layer drives them. Netty draws the line in the same
//! place: `Http2ConnectionHandler` reads frames and calls listener methods rather
//! than passing frames down a pipeline. The practical benefit is that every rule
//! in §6 is testable without a socket or a pipeline.
//!
//! **Severity is not decided here.** RFC 9113 §5.4 splits failures into
//! connection errors, which end everything, and stream errors, which reset one
//! stream — and which applies often depends on context this module does not have
//! (whether the stream is known, whether a header block is open). So parsing
//! returns a plain Zig error that maps one-to-one onto an `ErrorCode` via
//! `errorCode`, and the connection layer decides severity with an RFC citation at
//! each site.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../../buffer.zig").Buffer;

/// Every frame begins with the same nine bytes: length (24), type (8),
/// flags (8), R bit plus stream identifier (1 + 31).
pub const header_len = 9;

/// The client connection preface (RFC 9113 §3.4). A server reads exactly this
/// before anything else; it is chosen to be invalid HTTP/1.1 so a server that
/// does not speak HTTP/2 rejects it rather than misinterpreting it.
pub const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// `SETTINGS_MAX_FRAME_SIZE` bounds (§6.5.2). The default is also the floor: a
/// peer may raise the ceiling but never lower it below 16 KiB.
pub const default_max_frame_size: u24 = 16_384;
pub const max_max_frame_size: u24 = 16_777_215;

/// `SETTINGS_INITIAL_WINDOW_SIZE` default and ceiling (§6.5.2, §6.9.1).
pub const default_initial_window_size: u31 = 65_535;
pub const max_window_size: u31 = 2_147_483_647;

/// `SETTINGS_HEADER_TABLE_SIZE` default (§6.5.2), i.e. HPACK's initial capacity.
pub const default_header_table_size: u32 = 4_096;

pub const Error = error{
    /// The frame's length is wrong for its type: `FRAME_SIZE_ERROR`.
    FrameSizeError,
    /// The frame is not allowed here, or a field is out of range:
    /// `PROTOCOL_ERROR`.
    ProtocolError,
    /// A window would exceed its maximum: `FLOW_CONTROL_ERROR`.
    FlowControlError,
    /// HPACK could not decode the header block: `COMPRESSION_ERROR`.
    CompressionError,
    /// A limit this implementation imposes was exceeded. Not an RFC code; the
    /// connection layer answers it with `ENHANCE_YOUR_CALM`.
    LimitExceeded,
};

/// RFC 9113 §7. Non-exhaustive: an unknown code must be treated as
/// `INTERNAL_ERROR` rather than rejected, so it has to be representable.
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,

    pub fn name(code: ErrorCode) []const u8 {
        return switch (code) {
            .no_error => "NO_ERROR",
            .protocol_error => "PROTOCOL_ERROR",
            .internal_error => "INTERNAL_ERROR",
            .flow_control_error => "FLOW_CONTROL_ERROR",
            .settings_timeout => "SETTINGS_TIMEOUT",
            .stream_closed => "STREAM_CLOSED",
            .frame_size_error => "FRAME_SIZE_ERROR",
            .refused_stream => "REFUSED_STREAM",
            .cancel => "CANCEL",
            .compression_error => "COMPRESSION_ERROR",
            .connect_error => "CONNECT_ERROR",
            .enhance_your_calm => "ENHANCE_YOUR_CALM",
            .inadequate_security => "INADEQUATE_SECURITY",
            .http_1_1_required => "HTTP_1_1_REQUIRED",
            _ => "UNKNOWN",
        };
    }
};

/// Maps a parse failure onto the code that goes on the wire.
pub fn errorCode(err: Error) ErrorCode {
    return switch (err) {
        error.FrameSizeError => .frame_size_error,
        error.ProtocolError => .protocol_error,
        error.FlowControlError => .flow_control_error,
        error.CompressionError => .compression_error,
        error.LimitExceeded => .enhance_your_calm,
    };
}

/// RFC 9113 §6. Non-exhaustive on purpose: §4.1 requires that a frame of an
/// unknown type be discarded rather than treated as an error, which is what makes
/// extensions possible, so unknown types must survive parsing.
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,

    pub fn name(frame_type: FrameType) []const u8 {
        return switch (frame_type) {
            .data => "DATA",
            .headers => "HEADERS",
            .priority => "PRIORITY",
            .rst_stream => "RST_STREAM",
            .settings => "SETTINGS",
            .push_promise => "PUSH_PROMISE",
            .ping => "PING",
            .goaway => "GOAWAY",
            .window_update => "WINDOW_UPDATE",
            .continuation => "CONTINUATION",
            _ => "UNKNOWN",
        };
    }

    /// Whether a header block continues past this frame, i.e. whether a
    /// `CONTINUATION` may follow it.
    pub fn carriesHeaderBlock(frame_type: FrameType) bool {
        return switch (frame_type) {
            .headers, .push_promise, .continuation => true,
            else => false,
        };
    }
};

/// The flags byte. One bit position means different things in different frames —
/// 0x1 is `END_STREAM` on `DATA` and `HEADERS` but `ACK` on `SETTINGS` and
/// `PING` — so these are accessors rather than a packed struct with one name per
/// bit, which would invite reading the wrong one.
pub const Flags = struct {
    bits: u8 = 0,

    pub const end_stream: u8 = 0x1;
    pub const ack: u8 = 0x1;
    pub const end_headers: u8 = 0x4;
    pub const padded: u8 = 0x8;
    pub const priority: u8 = 0x20;

    pub fn endStream(flags: Flags) bool {
        return flags.bits & end_stream != 0;
    }
    pub fn isAck(flags: Flags) bool {
        return flags.bits & ack != 0;
    }
    pub fn endHeaders(flags: Flags) bool {
        return flags.bits & end_headers != 0;
    }
    pub fn isPadded(flags: Flags) bool {
        return flags.bits & padded != 0;
    }
    pub fn hasPriority(flags: Flags) bool {
        return flags.bits & priority != 0;
    }

    pub fn with(flags: Flags, bit: u8) Flags {
        return .{ .bits = flags.bits | bit };
    }
};

pub const Header = struct {
    length: u24,
    frame_type: FrameType,
    flags: Flags = .{},
    stream_id: u31 = 0,

    /// Parses the nine header bytes. The reserved bit is ignored rather than
    /// validated, as §4.1 requires.
    pub fn parse(bytes: *const [header_len]u8) Header {
        return .{
            .length = std.mem.readInt(u24, bytes[0..3], .big),
            .frame_type = @fromBackingInt(@intCast(bytes[3])),
            .flags = .{ .bits = bytes[4] },
            .stream_id = @truncate(std.mem.readInt(u32, bytes[5..9], .big)),
        };
    }

    pub fn write(header: Header, out: *[header_len]u8) void {
        std.mem.writeInt(u24, out[0..3], header.length, .big);
        out[3] = @backingInt(header.frame_type);
        out[4] = header.flags.bits;
        // The reserved bit is left clear; a receiver ignores it either way.
        std.mem.writeInt(u32, out[5..9], header.stream_id, .big);
    }

    pub fn writeTo(header: Header, buffer: *Buffer, gpa: Allocator) !void {
        var bytes: [header_len]u8 = undefined;
        header.write(&bytes);
        try buffer.writeBytes(gpa, &bytes);
    }

    /// Checks the length and stream-id rules of §6 that depend on nothing but the
    /// header itself, so a frame with an impossible shape is rejected before its
    /// payload is looked at, let alone accumulated.
    pub fn validate(header: Header, max_frame_size: u24) Error!void {
        if (header.length > max_frame_size) return error.FrameSizeError;

        switch (header.frame_type) {
            // §6.1, §6.2, §6.3, §6.4, §6.6, §6.10: these are about a stream, so
            // stream 0 is a connection error.
            .data, .headers, .priority, .rst_stream, .push_promise, .continuation => {
                if (header.stream_id == 0) return error.ProtocolError;
            },
            // §6.5, §6.7, §6.8: these are about the connection, so a stream id is
            // a connection error.
            .settings, .ping, .goaway => {
                if (header.stream_id != 0) return error.ProtocolError;
            },
            // §6.9: WINDOW_UPDATE is the one frame that is valid either way.
            .window_update => {},
            // §4.1: unknown types are discarded, so nothing is checked.
            _ => return,
        }

        switch (header.frame_type) {
            .priority => if (header.length != 5) return error.FrameSizeError,
            .rst_stream => if (header.length != 4) return error.FrameSizeError,
            .window_update => if (header.length != 4) return error.FrameSizeError,
            // §6.7: an 8-byte opaque payload, exactly.
            .ping => if (header.length != 8) return error.FrameSizeError,
            // §6.5: a sequence of 6-byte settings, and an ACK carries none.
            .settings => {
                if (header.length % 6 != 0) return error.FrameSizeError;
                if (header.flags.isAck() and header.length != 0) return error.FrameSizeError;
            },
            // §6.8: last-stream-id and error code, then optional debug data.
            .goaway => if (header.length < 8) return error.FrameSizeError,
            else => {},
        }
    }
};

/// Strips the padding a `DATA`, `HEADERS` or `PUSH_PROMISE` frame may carry
/// (§6.1). Returns the payload without its pad length byte or its padding.
///
/// The check is `>=` rather than `>`: a pad length equal to what is left would
/// leave no room for the length byte itself, which §6.1 makes a connection error.
pub fn stripPadding(payload: []const u8, flags: Flags) Error![]const u8 {
    if (!flags.isPadded()) return payload;
    if (payload.len < 1) return error.ProtocolError;
    const pad_len = payload[0];
    const rest = payload[1..];
    if (pad_len > rest.len) return error.ProtocolError;
    return rest[0 .. rest.len - pad_len];
}

/// The priority fields carried by `PRIORITY`, and optionally by `HEADERS`
/// (§6.3). Retained and reported but not acted on: RFC 9113 §5.3.1 deprecates
/// this scheme, and §5.3 permits an implementation to ignore it.
pub const Priority = struct {
    exclusive: bool = false,
    dependency: u31 = 0,
    /// On the wire this is the weight minus one, so the range is 1..=256.
    weight: u9 = 16,

    pub const wire_len = 5;

    pub fn parse(bytes: *const [wire_len]u8) Priority {
        const word = std.mem.readInt(u32, bytes[0..4], .big);
        return .{
            .exclusive = word & 0x8000_0000 != 0,
            .dependency = @truncate(word),
            .weight = @as(u9, bytes[4]) + 1,
        };
    }

    pub fn write(priority: Priority, out: *[wire_len]u8) void {
        var word: u32 = priority.dependency;
        if (priority.exclusive) word |= 0x8000_0000;
        std.mem.writeInt(u32, out[0..4], word, .big);
        assert(priority.weight >= 1 and priority.weight <= 256);
        out[4] = @intCast(priority.weight - 1);
    }
};

/// The fields a `HEADERS` frame carries ahead of its header block fragment.
pub const HeadersPrologue = struct {
    priority: ?Priority = null,
    fragment: []const u8,
};

/// Splits a `HEADERS` payload into its optional priority fields and the header
/// block fragment (§6.2).
pub fn parseHeaders(payload: []const u8, flags: Flags) Error!HeadersPrologue {
    const unpadded = try stripPadding(payload, flags);
    if (!flags.hasPriority()) return .{ .fragment = unpadded };
    if (unpadded.len < Priority.wire_len) return error.FrameSizeError;
    return .{
        .priority = .parse(unpadded[0..Priority.wire_len]),
        .fragment = unpadded[Priority.wire_len..],
    };
}

/// Splits a `PUSH_PROMISE` payload into the promised stream id and the header
/// block fragment (§6.6).
pub fn parsePushPromise(payload: []const u8, flags: Flags) Error!struct {
    promised_stream_id: u31,
    fragment: []const u8,
} {
    const unpadded = try stripPadding(payload, flags);
    if (unpadded.len < 4) return error.FrameSizeError;
    return .{
        .promised_stream_id = @truncate(std.mem.readInt(u32, unpadded[0..4], .big)),
        .fragment = unpadded[4..],
    };
}

/// Parses a `RST_STREAM` payload (§6.4). The length was already checked.
pub fn parseRstStream(payload: []const u8) ErrorCode {
    assert(payload.len == 4);
    return @fromBackingInt(@intCast(std.mem.readInt(u32, payload[0..4], .big)));
}

/// Parses a `WINDOW_UPDATE` payload (§6.9). A zero increment is a protocol
/// error; the reserved bit is ignored.
pub fn parseWindowUpdate(payload: []const u8) Error!u31 {
    assert(payload.len == 4);
    const increment: u31 = @truncate(std.mem.readInt(u32, payload[0..4], .big));
    if (increment == 0) return error.ProtocolError;
    return increment;
}

pub const Goaway = struct {
    last_stream_id: u31,
    error_code: ErrorCode,
    /// Borrowed from the payload; §6.8 leaves its contents unspecified.
    debug_data: []const u8,
};

pub fn parseGoaway(payload: []const u8) Goaway {
    assert(payload.len >= 8);
    return .{
        .last_stream_id = @truncate(std.mem.readInt(u32, payload[0..4], .big)),
        .error_code = @fromBackingInt(@intCast(std.mem.readInt(u32, payload[4..8], .big))),
        .debug_data = payload[8..],
    };
}

/// RFC 9113 §6.5.2. Non-exhaustive: §6.5.2 requires that an unknown setting be
/// ignored, so it has to be representable.
pub const SettingId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

pub const Setting = struct {
    id: SettingId,
    value: u32,

    pub const wire_len = 6;
};

/// Walks the settings in a `SETTINGS` payload. The payload length was already
/// checked to be a multiple of six, which is what makes this infallible.
pub const SettingIterator = struct {
    payload: []const u8,
    index: usize = 0,

    pub fn next(iterator: *SettingIterator) ?Setting {
        if (iterator.index + Setting.wire_len > iterator.payload.len) return null;
        const entry = iterator.payload[iterator.index..][0..Setting.wire_len];
        iterator.index += Setting.wire_len;
        return .{
            .id = @fromBackingInt(@intCast(std.mem.readInt(u16, entry[0..2], .big))),
            .value = std.mem.readInt(u32, entry[2..6], .big),
        };
    }
};

pub fn settings(payload: []const u8) SettingIterator {
    assert(payload.len % Setting.wire_len == 0);
    return .{ .payload = payload };
}

/// The peer's settings, as understood after every `SETTINGS` frame received so
/// far. Defaults are the ones §6.5.2 specifies for a connection that has not
/// negotiated anything.
pub const Settings = struct {
    header_table_size: u32 = default_header_table_size,
    enable_push: bool = true,
    /// Absent means unlimited, which is what §6.5.2 says of a missing value. An
    /// implementation is still expected to impose its own ceiling; see
    /// `Connection.Options`.
    max_concurrent_streams: ?u32 = null,
    initial_window_size: u31 = default_initial_window_size,
    max_frame_size: u24 = default_max_frame_size,
    max_header_list_size: ?u32 = null,

    /// Applies one setting, rejecting the values §6.5.2 declares out of range.
    pub fn apply(self: *Settings, setting: Setting) Error!void {
        switch (setting.id) {
            .header_table_size => self.header_table_size = setting.value,
            .enable_push => switch (setting.value) {
                0 => self.enable_push = false,
                1 => self.enable_push = true,
                // §6.5.2: any other value is a connection error.
                else => return error.ProtocolError,
            },
            .max_concurrent_streams => self.max_concurrent_streams = setting.value,
            .initial_window_size => {
                // §6.5.2: above 2^31-1 is FLOW_CONTROL_ERROR, not PROTOCOL_ERROR.
                if (setting.value > max_window_size) return error.FlowControlError;
                self.initial_window_size = @intCast(setting.value);
            },
            .max_frame_size => {
                if (setting.value < default_max_frame_size or setting.value > max_max_frame_size) {
                    return error.ProtocolError;
                }
                self.max_frame_size = @intCast(setting.value);
            },
            .max_header_list_size => self.max_header_list_size = setting.value,
            // §6.5.2: an unknown setting must be ignored, which is what makes
            // extensions possible.
            _ => {},
        }
    }
};

// -- Serializing -----------------------------------------------------------

/// Appends a whole frame: header then payload.
pub fn writeFrame(
    buffer: *Buffer,
    gpa: Allocator,
    frame_type: FrameType,
    flags: Flags,
    stream_id: u31,
    payload: []const u8,
) !void {
    assert(payload.len <= max_max_frame_size);
    const header: Header = .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    };
    try header.writeTo(buffer, gpa);
    try buffer.writeBytes(gpa, payload);
}

pub fn writeData(
    buffer: *Buffer,
    gpa: Allocator,
    stream_id: u31,
    payload: []const u8,
    end_stream: bool,
) !void {
    assert(stream_id != 0);
    const flags: Flags = if (end_stream) .{ .bits = Flags.end_stream } else .{};
    try writeFrame(buffer, gpa, .data, flags, stream_id, payload);
}

pub fn writeRstStream(
    buffer: *Buffer,
    gpa: Allocator,
    stream_id: u31,
    code: ErrorCode,
) !void {
    assert(stream_id != 0);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, @backingInt(code), .big);
    try writeFrame(buffer, gpa, .rst_stream, .{}, stream_id, &payload);
}

pub fn writeSettings(buffer: *Buffer, gpa: Allocator, list: []const Setting) !void {
    var payload_buf: [16 * Setting.wire_len]u8 = undefined;
    assert(list.len * Setting.wire_len <= payload_buf.len);
    for (list, 0..) |setting, index| {
        const entry = payload_buf[index * Setting.wire_len ..][0..Setting.wire_len];
        std.mem.writeInt(u16, entry[0..2], @backingInt(setting.id), .big);
        std.mem.writeInt(u32, entry[2..6], setting.value, .big);
    }
    try writeFrame(buffer, gpa, .settings, .{}, 0, payload_buf[0 .. list.len * Setting.wire_len]);
}

pub fn writeSettingsAck(buffer: *Buffer, gpa: Allocator) !void {
    try writeFrame(buffer, gpa, .settings, .{ .bits = Flags.ack }, 0, "");
}

pub fn writePing(buffer: *Buffer, gpa: Allocator, opaque_data: [8]u8, is_ack: bool) !void {
    const flags: Flags = if (is_ack) .{ .bits = Flags.ack } else .{};
    try writeFrame(buffer, gpa, .ping, flags, 0, &opaque_data);
}

pub fn writeGoaway(
    buffer: *Buffer,
    gpa: Allocator,
    last_stream_id: u31,
    code: ErrorCode,
    debug_data: []const u8,
) !void {
    var head: [8]u8 = undefined;
    std.mem.writeInt(u32, head[0..4], last_stream_id, .big);
    std.mem.writeInt(u32, head[4..8], @backingInt(code), .big);
    const header: Header = .{
        .length = @intCast(head.len + debug_data.len),
        .frame_type = .goaway,
        .stream_id = 0,
    };
    try header.writeTo(buffer, gpa);
    try buffer.writeBytes(gpa, &head);
    try buffer.writeBytes(gpa, debug_data);
}

pub fn writeWindowUpdate(
    buffer: *Buffer,
    gpa: Allocator,
    stream_id: u31,
    increment: u31,
) !void {
    assert(increment > 0);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment, .big);
    try writeFrame(buffer, gpa, .window_update, .{}, stream_id, &payload);
}

pub fn writePriority(
    buffer: *Buffer,
    gpa: Allocator,
    stream_id: u31,
    priority: Priority,
) !void {
    assert(stream_id != 0);
    var payload: [Priority.wire_len]u8 = undefined;
    priority.write(&payload);
    try writeFrame(buffer, gpa, .priority, .{}, stream_id, &payload);
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "frame header: round trip, and the reserved bit is ignored" {
    var bytes: [header_len]u8 = undefined;
    const original: Header = .{
        .length = 0x0102_03,
        .frame_type = .headers,
        .flags = .{ .bits = Flags.end_headers | Flags.end_stream },
        .stream_id = 0x7fff_ffff,
    };
    original.write(&bytes);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x01, 0x05, 0x7f, 0xff, 0xff, 0xff }, &bytes);

    const parsed: Header = .parse(&bytes);
    try testing.expectEqual(original.length, parsed.length);
    try testing.expectEqual(original.frame_type, parsed.frame_type);
    try testing.expectEqual(original.flags.bits, parsed.flags.bits);
    try testing.expectEqual(original.stream_id, parsed.stream_id);

    // §4.1: the R bit is set here and must not disturb the stream id.
    bytes[5] |= 0x80;
    try testing.expectEqual(@as(u31, 0x7fff_ffff), Header.parse(&bytes).stream_id);
}

test "frame header: an unknown type parses and is not validated" {
    var bytes: [header_len]u8 = undefined;
    (Header{ .length = 7, .frame_type = @fromBackingInt(@intCast(0xef)), .stream_id = 0 }).write(&bytes);
    const parsed: Header = .parse(&bytes);
    try testing.expectEqual(@as(u8, 0xef), @backingInt(parsed.frame_type));
    try testing.expectEqualStrings("UNKNOWN", parsed.frame_type.name());
    // §4.1: an extension frame must be discarded, so no rule applies to it —
    // not even the stream-id rules that apply to every known type.
    try parsed.validate(default_max_frame_size);
}

test "frame header: length above max_frame_size is a size error" {
    const header: Header = .{ .length = default_max_frame_size + 1, .frame_type = .data, .stream_id = 1 };
    try testing.expectError(error.FrameSizeError, header.validate(default_max_frame_size));
    // The same frame is fine once the peer has raised the ceiling.
    try header.validate(default_max_frame_size + 1);
}

test "frame header: stream-id rules per frame type" {
    // §6.1-6.4, §6.6, §6.10: about a stream, so stream 0 is a protocol error.
    for ([_]FrameType{ .data, .headers, .priority, .rst_stream, .push_promise, .continuation }) |t| {
        const length: u24 = switch (t) {
            .priority => 5,
            .rst_stream => 4,
            else => 0,
        };
        try testing.expectError(
            error.ProtocolError,
            (Header{ .length = length, .frame_type = t, .stream_id = 0 }).validate(default_max_frame_size),
        );
        try (Header{ .length = length, .frame_type = t, .stream_id = 1 }).validate(default_max_frame_size);
    }

    // §6.5, §6.7, §6.8: about the connection, so a stream id is an error.
    for ([_]FrameType{ .settings, .ping, .goaway }) |t| {
        const length: u24 = switch (t) {
            .ping => 8,
            .goaway => 8,
            else => 0,
        };
        try testing.expectError(
            error.ProtocolError,
            (Header{ .length = length, .frame_type = t, .stream_id = 1 }).validate(default_max_frame_size),
        );
        try (Header{ .length = length, .frame_type = t, .stream_id = 0 }).validate(default_max_frame_size);
    }

    // §6.9: WINDOW_UPDATE is the one frame valid on either.
    try (Header{ .length = 4, .frame_type = .window_update, .stream_id = 0 }).validate(default_max_frame_size);
    try (Header{ .length = 4, .frame_type = .window_update, .stream_id = 3 }).validate(default_max_frame_size);
}

test "frame header: fixed-length frames reject any other length" {
    const cases = [_]struct { t: FrameType, ok: u24, stream: u31 }{
        .{ .t = .priority, .ok = 5, .stream = 1 },
        .{ .t = .rst_stream, .ok = 4, .stream = 1 },
        .{ .t = .window_update, .ok = 4, .stream = 1 },
        .{ .t = .ping, .ok = 8, .stream = 0 },
    };
    for (cases) |case| {
        try (Header{ .length = case.ok, .frame_type = case.t, .stream_id = case.stream })
            .validate(default_max_frame_size);
        for ([_]u24{ 0, 1, 3, 7, 9, 100 }) |bad| {
            if (bad == case.ok) continue;
            try testing.expectError(error.FrameSizeError, (Header{
                .length = bad,
                .frame_type = case.t,
                .stream_id = case.stream,
            }).validate(default_max_frame_size));
        }
    }
}

test "frame header: SETTINGS length must be a multiple of six, and an ACK empty" {
    for ([_]u24{ 0, 6, 12, 60 }) |ok| {
        try (Header{ .length = ok, .frame_type = .settings }).validate(default_max_frame_size);
    }
    for ([_]u24{ 1, 5, 7, 11 }) |bad| {
        try testing.expectError(
            error.FrameSizeError,
            (Header{ .length = bad, .frame_type = .settings }).validate(default_max_frame_size),
        );
    }
    // §6.5: an ACK carries no payload.
    try (Header{ .length = 0, .frame_type = .settings, .flags = .{ .bits = Flags.ack } })
        .validate(default_max_frame_size);
    try testing.expectError(error.FrameSizeError, (Header{
        .length = 6,
        .frame_type = .settings,
        .flags = .{ .bits = Flags.ack },
    }).validate(default_max_frame_size));
}

test "frame header: GOAWAY needs its two fixed fields" {
    for ([_]u24{ 0, 1, 7 }) |bad| {
        try testing.expectError(
            error.FrameSizeError,
            (Header{ .length = bad, .frame_type = .goaway }).validate(default_max_frame_size),
        );
    }
    try (Header{ .length = 8, .frame_type = .goaway }).validate(default_max_frame_size);
    // Debug data of any length is allowed on top.
    try (Header{ .length = 300, .frame_type = .goaway }).validate(default_max_frame_size);
}

test "padding: stripped, and a pad length that eats its own byte is rejected" {
    const padded: Flags = .{ .bits = Flags.padded };

    // Not padded: the payload is returned untouched.
    try testing.expectEqualStrings("abc", try stripPadding("abc", .{}));

    // One byte of pad length, three of data, two of padding.
    try testing.expectEqualStrings("abc", try stripPadding("\x02abc\x00\x00", padded));

    // §6.1: all padding and no data is legal.
    try testing.expectEqualStrings("", try stripPadding("\x02\x00\x00", padded));

    // §6.1: a pad length equal to the whole remainder leaves nothing, which is
    // still legal; one byte more is a connection error.
    try testing.expectEqualStrings("", try stripPadding("\x01\x00", padded));
    try testing.expectError(error.ProtocolError, stripPadding("\x02\x00", padded));

    // The PADDED flag with no room for the length byte itself.
    try testing.expectError(error.ProtocolError, stripPadding("", padded));
}

test "HEADERS: priority fields are optional and come before the fragment" {
    const plain = try parseHeaders("\x82\x84", .{});
    try testing.expect(plain.priority == null);
    try testing.expectEqualStrings("\x82\x84", plain.fragment);

    // Exclusive bit set, dependency 1, weight byte 15 meaning 16.
    const with_priority = try parseHeaders(
        "\x80\x00\x00\x01\x0f\x82",
        .{ .bits = Flags.priority },
    );
    try testing.expect(with_priority.priority.?.exclusive);
    try testing.expectEqual(@as(u31, 1), with_priority.priority.?.dependency);
    try testing.expectEqual(@as(u9, 16), with_priority.priority.?.weight);
    try testing.expectEqualStrings("\x82", with_priority.fragment);

    // Padding is removed before the priority fields are read, which is the order
    // §6.2 lays the payload out in.
    const both = try parseHeaders(
        "\x03\x00\x00\x00\x02\x10\x82\xff\xff\xff",
        .{ .bits = Flags.padded | Flags.priority },
    );
    try testing.expectEqual(@as(u31, 2), both.priority.?.dependency);
    try testing.expectEqual(@as(u9, 17), both.priority.?.weight);
    try testing.expectEqualStrings("\x82", both.fragment);

    // The PRIORITY flag with fewer than five bytes behind it.
    try testing.expectError(
        error.FrameSizeError,
        parseHeaders("\x00\x00\x00\x01", .{ .bits = Flags.priority }),
    );
}

test "PUSH_PROMISE: the promised id is 31 bits, reserved bit ignored" {
    const promise = try parsePushPromise("\x80\x00\x00\x04\x82", .{});
    try testing.expectEqual(@as(u31, 4), promise.promised_stream_id);
    try testing.expectEqualStrings("\x82", promise.fragment);

    try testing.expectError(error.FrameSizeError, parsePushPromise("\x00\x00\x00", .{}));
}

test "WINDOW_UPDATE: a zero increment is a protocol error" {
    try testing.expectEqual(@as(u31, 1), try parseWindowUpdate("\x00\x00\x00\x01"));
    // The reserved bit is ignored rather than making the value enormous.
    try testing.expectEqual(@as(u31, 1), try parseWindowUpdate("\x80\x00\x00\x01"));
    try testing.expectEqual(max_window_size, try parseWindowUpdate("\x7f\xff\xff\xff"));
    try testing.expectError(error.ProtocolError, parseWindowUpdate("\x00\x00\x00\x00"));
}

test "RST_STREAM and GOAWAY payloads" {
    try testing.expectEqual(ErrorCode.cancel, parseRstStream("\x00\x00\x00\x08"));
    // §7: an unknown code must be representable rather than rejected.
    try testing.expectEqual(@as(u32, 0xbeef), @backingInt(parseRstStream("\x00\x00\xbe\xef")));

    const bye = parseGoaway("\x00\x00\x00\x07\x00\x00\x00\x01too much");
    try testing.expectEqual(@as(u31, 7), bye.last_stream_id);
    try testing.expectEqual(ErrorCode.protocol_error, bye.error_code);
    try testing.expectEqualStrings("too much", bye.debug_data);

    const bare = parseGoaway("\x00\x00\x00\x00\x00\x00\x00\x00");
    try testing.expectEqualStrings("", bare.debug_data);
}

test "PRIORITY: weight is offset by one on the wire" {
    var bytes: [Priority.wire_len]u8 = undefined;

    (Priority{ .exclusive = true, .dependency = 3, .weight = 256 }).write(&bytes);
    try testing.expectEqualSlices(u8, &.{ 0x80, 0x00, 0x00, 0x03, 0xff }, &bytes);
    const round = Priority.parse(&bytes);
    try testing.expect(round.exclusive);
    try testing.expectEqual(@as(u31, 3), round.dependency);
    try testing.expectEqual(@as(u9, 256), round.weight);

    (Priority{ .weight = 1 }).write(&bytes);
    try testing.expectEqual(@as(u8, 0), bytes[4]);
    try testing.expectEqual(@as(u9, 1), Priority.parse(&bytes).weight);
}

test "SETTINGS: the values §6.5.2 declares out of range" {
    var s: Settings = .{};

    try s.apply(.{ .id = .header_table_size, .value = 0 });
    try testing.expectEqual(@as(u32, 0), s.header_table_size);

    try s.apply(.{ .id = .enable_push, .value = 0 });
    try testing.expect(!s.enable_push);
    try s.apply(.{ .id = .enable_push, .value = 1 });
    try testing.expect(s.enable_push);
    // Anything but 0 or 1 is a connection error, not a truthy value.
    try testing.expectError(error.ProtocolError, s.apply(.{ .id = .enable_push, .value = 2 }));

    // Above 2^31-1 this is FLOW_CONTROL_ERROR specifically, not PROTOCOL_ERROR.
    try s.apply(.{ .id = .initial_window_size, .value = max_window_size });
    try testing.expectEqual(max_window_size, s.initial_window_size);
    try testing.expectError(
        error.FlowControlError,
        s.apply(.{ .id = .initial_window_size, .value = @as(u32, max_window_size) + 1 }),
    );

    // The default is also the floor.
    try testing.expectError(
        error.ProtocolError,
        s.apply(.{ .id = .max_frame_size, .value = default_max_frame_size - 1 }),
    );
    try testing.expectError(
        error.ProtocolError,
        s.apply(.{ .id = .max_frame_size, .value = @as(u32, max_max_frame_size) + 1 }),
    );
    try s.apply(.{ .id = .max_frame_size, .value = max_max_frame_size });
    try testing.expectEqual(max_max_frame_size, s.max_frame_size);

    // Absent means unlimited; §6.5.2 says nothing else about it.
    try testing.expect(s.max_concurrent_streams == null);
    try s.apply(.{ .id = .max_concurrent_streams, .value = 100 });
    try testing.expectEqual(@as(?u32, 100), s.max_concurrent_streams);

    // §6.5.2: an unknown setting is ignored, which is what lets extensions ship.
    const before = s;
    try s.apply(.{ .id = @fromBackingInt(@intCast(0xbeef)), .value = 12345 });
    try testing.expectEqual(before.header_table_size, s.header_table_size);
    try testing.expectEqual(before.max_frame_size, s.max_frame_size);
}

test "SETTINGS: walking a payload" {
    var iterator = settings("\x00\x03\x00\x00\x00\x64\x00\x04\x00\x01\x00\x00");
    const first = iterator.next().?;
    try testing.expectEqual(SettingId.max_concurrent_streams, first.id);
    try testing.expectEqual(@as(u32, 100), first.value);
    const second = iterator.next().?;
    try testing.expectEqual(SettingId.initial_window_size, second.id);
    try testing.expectEqual(@as(u32, 65_536), second.value);
    try testing.expect(iterator.next() == null);

    var empty = settings("");
    try testing.expect(empty.next() == null);
}

test "serializing: every writer produces a frame that parses back" {
    const gpa = testing.allocator;
    var out: Buffer = .empty;
    defer out.deinit(gpa);

    try writeData(&out, gpa, 1, "hello", true);
    try writeRstStream(&out, gpa, 3, .cancel);
    try writeSettings(&out, gpa, &.{
        .{ .id = .max_concurrent_streams, .value = 100 },
        .{ .id = .initial_window_size, .value = 65_536 },
    });
    try writeSettingsAck(&out, gpa);
    try writePing(&out, gpa, .{ 1, 2, 3, 4, 5, 6, 7, 8 }, false);
    try writeGoaway(&out, gpa, 7, .no_error, "bye");
    try writeWindowUpdate(&out, gpa, 0, 1024);
    try writePriority(&out, gpa, 5, .{ .dependency = 1, .weight = 200 });

    // Walk the whole thing back, validating each header the way a receiver does.
    var reader = out;
    var seen: std.ArrayList(FrameType) = .empty;
    defer seen.deinit(gpa);
    while (reader.readableLen() >= header_len) {
        const head_bytes = try reader.readBytes(header_len);
        const header: Header = .parse(head_bytes[0..header_len]);
        try header.validate(default_max_frame_size);
        const payload = try reader.readBytes(header.length);
        try seen.append(gpa, header.frame_type);

        switch (header.frame_type) {
            .data => {
                try testing.expectEqualStrings("hello", try stripPadding(payload, header.flags));
                try testing.expect(header.flags.endStream());
            },
            .rst_stream => try testing.expectEqual(ErrorCode.cancel, parseRstStream(payload)),
            .settings => if (header.flags.isAck()) {
                try testing.expectEqual(@as(usize, 0), payload.len);
            } else {
                var applied: Settings = .{};
                var iterator = settings(payload);
                while (iterator.next()) |setting| try applied.apply(setting);
                try testing.expectEqual(@as(?u32, 100), applied.max_concurrent_streams);
                try testing.expectEqual(@as(u31, 65_536), applied.initial_window_size);
            },
            .ping => try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, payload),
            .goaway => {
                const bye = parseGoaway(payload);
                try testing.expectEqual(@as(u31, 7), bye.last_stream_id);
                try testing.expectEqualStrings("bye", bye.debug_data);
            },
            .window_update => try testing.expectEqual(@as(u31, 1024), try parseWindowUpdate(payload)),
            .priority => {
                const priority: Priority = .parse(payload[0..Priority.wire_len]);
                try testing.expectEqual(@as(u9, 200), priority.weight);
            },
            else => unreachable,
        }
    }
    try testing.expectEqual(@as(usize, 0), reader.readableLen());
    try testing.expectEqualSlices(FrameType, &.{
        .data, .rst_stream, .settings, .settings, .ping, .goaway, .window_update, .priority,
    }, seen.items);
}

test "error codes map onto the wire values" {
    try testing.expectEqual(ErrorCode.frame_size_error, errorCode(error.FrameSizeError));
    try testing.expectEqual(ErrorCode.protocol_error, errorCode(error.ProtocolError));
    try testing.expectEqual(ErrorCode.flow_control_error, errorCode(error.FlowControlError));
    try testing.expectEqual(ErrorCode.compression_error, errorCode(error.CompressionError));
    // A limit of our own choosing is answered with the code that says "slow down"
    // rather than one that blames the peer's syntax.
    try testing.expectEqual(ErrorCode.enhance_your_calm, errorCode(error.LimitExceeded));
}
