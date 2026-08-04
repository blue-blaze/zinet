//! HTTP/3 frames and stream types, RFC 9114 §6 and §7.
//!
//! HTTP/3's frame layer differs from QUIC's in the two ways that matter most to
//! an implementation, and both run *opposite* to a neighbouring layer of this
//! stack, which is why they are stated here rather than discovered later:
//!
//! * **Frames ride a stream, not a packet.** A QUIC frame is parsed from
//!   exactly one packet's payload; an HTTP/3 frame arrives in however many
//!   STREAM frames the sender's packetizer chose, so the reframing problem —
//!   which QUIC abolished — is back, and the parser here is incremental: feed
//!   it bytes, it hands back frames when they are whole.
//! * **Unknown frame types are ignored** (§9), where QUIC §19 makes them a
//!   connection error. HTTP/3 extensions are deployed by just sending new
//!   types, and greasing (§7.2.8) sends deliberately meaningless ones to keep
//!   that path working. The exception runs through §7.2.9 and §11.2.1: the
//!   type values HTTP/2 used for PRIORITY, PING, WINDOW_UPDATE and CONTINUATION
//!   are *reserved to catch confusion* — a peer sending one has mapped HTTP/2
//!   onto HTTP/3 frame for frame, and everything else it believes is suspect.
//!   Ignoring those would paper over a peer that needs correcting.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const varint = @import("../quic/varint.zig");

/// §7.2: the frame types this implementation knows. Non-exhaustive because §9
/// requires carrying unknown values around rather than failing on them.
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    _,

    /// §11.2.1: 0x1f * N + 0x21 for non-negative N is reserved for greasing.
    /// These carry no meaning by construction, and §7.2.8 requires ignoring
    /// them — an endpoint that errors on grease is exactly what greasing exists
    /// to flush out.
    pub fn isGrease(value: u64) bool {
        if (value < 0x21) return false;
        return (value - 0x21) % 0x1f == 0;
    }

    /// §7.2.9 and §11.2.1: the HTTP/2 frame types with no HTTP/3 equivalent.
    /// Their values are reserved so that a peer translating HTTP/2 frame for
    /// frame fails immediately and loudly rather than half-working: a peer that
    /// sends WINDOW_UPDATE believes it controls flow at a layer where QUIC does,
    /// and every other belief it holds is now suspect too.
    pub fn isForbidden(value: u64) bool {
        return switch (value) {
            0x02, // HTTP/2 PRIORITY
            0x06, // HTTP/2 PING
            0x08, // HTTP/2 WINDOW_UPDATE
            0x09, // HTTP/2 CONTINUATION
            => true,
            else => false,
        };
    }
};

/// §6.2: the type carried in the first varint of every unidirectional stream.
/// Non-exhaustive for the same §9 reason: unknown stream types are not an
/// error, the stream is simply not read (§6.2.4).
pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    /// RFC 9204 §4.2: the QPACK encoder and decoder streams.
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    _,

    pub fn isGrease(value: u64) bool {
        return FrameType.isGrease(value); // §11.2.4 uses the same formula
    }
};

/// §7 and §11.2.1's errors, named after the H3_* registry entries in §8.1.
pub const Error = error{
    /// H3_FRAME_ERROR: a frame violated its own layout.
    FrameError,
    /// H3_FRAME_UNEXPECTED: a legal frame in an illegal place.
    FrameUnexpected,
    /// H3_SETTINGS_ERROR: SETTINGS malformed, duplicated, or carrying an
    /// HTTP/2-reserved identifier.
    SettingsError,
    /// H3_MISSING_SETTINGS: the control stream's first frame was not SETTINGS.
    MissingSettings,
    /// H3_ID_ERROR: a pushed or GOAWAY'd identifier moved the wrong way.
    IdError,
    /// H3_EXCESSIVE_LOAD: a frame larger than this implementation will buffer.
    ExcessiveLoad,
} || Allocator.Error;

/// §8.1's wire codes, for the CONNECTION_CLOSE this layer's errors become.
pub fn errorCode(err: Error) u64 {
    return switch (err) {
        error.FrameError => 0x0106,
        error.FrameUnexpected => 0x0105,
        error.SettingsError => 0x0109,
        error.MissingSettings => 0x010a,
        error.IdError => 0x0108,
        error.ExcessiveLoad => 0x0107,
        error.OutOfMemory => 0x0102, // H3_INTERNAL_ERROR
    };
}

/// §7.2.4: one setting. Identifiers are open-ended (§9), so this is a pair
/// rather than an enum.
pub const Setting = struct {
    id: u64,
    value: u64,

    /// §7.2.4.1: the identifiers this implementation assigns meaning to.
    pub const qpack_max_table_capacity = 0x01;
    pub const max_field_section_size = 0x06;
    pub const qpack_blocked_streams = 0x07;
    /// RFC 9220 §3: SETTINGS_ENABLE_CONNECT_PROTOCOL, the same value as in
    /// HTTP/2, registered separately for HTTP/3 as Appendix A.3 requires.
    pub const enable_connect_protocol = 0x08;

    /// §11.2.2: grease for settings uses the same 0x1f * N + 0x21 formula.
    pub fn isGrease(id: u64) bool {
        return FrameType.isGrease(id);
    }

    /// §7.2.4.1: settings carried over from HTTP/2 whose identifiers are
    /// reserved precisely because their *absence* is meaningful — flow control
    /// and push concurrency belong to QUIC and MAX_PUSH_ID here. Receiving one
    /// is H3_SETTINGS_ERROR, the same "this peer is translating, not speaking"
    /// diagnosis as the forbidden frame types.
    pub fn isForbidden(id: u64) bool {
        return switch (id) {
            0x02, // HTTP/2 SETTINGS_ENABLE_PUSH
            0x03, // HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS
            0x04, // HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE
            0x05, // HTTP/2 SETTINGS_MAX_FRAME_SIZE
            => true,
            else => false,
        };
    }
};

/// The settings this implementation reads out of a peer's SETTINGS frame,
/// §7.2.4.2's defaults pre-applied: omitted is indistinguishable from default
/// by design, so the type says so.
pub const Settings = struct {
    /// RFC 9204 §5: zero means the peer's QPACK decoder accepts no dynamic
    /// table, which is the mode this stack starts every connection in.
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    /// §7.2.4.2 gives this an unlimited default.
    max_field_section_size: u64 = std.math.maxInt(u64),
    /// RFC 9220's registry entry gives this a default of 0, which is what makes
    /// the extension safe to negotiate with a setting at all: §9 requires that an
    /// omitted setting leave the extension disabled.
    enable_connect_protocol: bool = false,

    pub fn apply(self: *Settings, setting: Setting) void {
        switch (setting.id) {
            Setting.qpack_max_table_capacity => self.qpack_max_table_capacity = setting.value,
            Setting.qpack_blocked_streams => self.qpack_blocked_streams = setting.value,
            Setting.max_field_section_size => self.max_field_section_size = setting.value,
            // RFC 8441 §3: "The value of the parameter MUST be 0 or 1." A value
            // outside that never reaches here — `SettingsIterator.next` refuses it,
            // which is also where §7.2.4's other payload rules live.
            Setting.enable_connect_protocol => self.enable_connect_protocol = setting.value == 1,
            // §9: unknown settings must be ignored. This is where grease lands
            // too, and deliberately through the same path — grease works only
            // because it is indistinguishable from a real future extension.
            else => {},
        }
    }
};

/// A whole HTTP/3 frame, borrowed from the parser's buffer: valid until the
/// next call that feeds or consumes. Frames whose payload this layer does not
/// interpret (DATA, HEADERS, PUSH_PROMISE) carry raw bytes for the next layer
/// (QPACK for the field sections, the application for the body).
pub const Frame = union(enum) {
    data: []const u8,
    headers: []const u8,
    cancel_push: u64,
    /// The raw id/value pairs, decoded by `settingsIterator` — kept raw so the
    /// caller controls when validation errors surface.
    settings: []const u8,
    push_promise: struct { push_id: u64, field_section: []const u8 },
    goaway: u64,
    max_push_id: u64,
    /// §9: a type this implementation does not know, greased or genuinely new.
    /// Delivered rather than silently swallowed so a connection layer can count
    /// them — ignoring is a semantic decision, not a parsing one.
    unknown: struct { frame_type: u64, payload: []const u8 },
};

/// Iterate the id/value pairs of a SETTINGS payload, enforcing §7.2.4 as it
/// goes: identifiers must not repeat, and HTTP/2's reserved ones must not
/// appear at all.
pub const SettingsIterator = struct {
    rest: []const u8,
    /// Duplicate detection for the identifiers we interpret; unknown ones are
    /// the peer's business. Bit positions follow the Setting.* constants, so the
    /// width has to cover the largest one we read — 0x08 (RFC 9220) sat one bit
    /// outside a `u8` and would have slipped through unnoticed.
    seen: u16 = 0,

    pub fn init(payload: []const u8) SettingsIterator {
        return .{ .rest = payload };
    }

    pub fn next(self: *SettingsIterator) Error!?Setting {
        if (self.rest.len == 0) return null;
        const id = varint.take(&self.rest) catch return error.SettingsError;
        const value = varint.take(&self.rest) catch return error.SettingsError;

        // §7.2.4.1: HTTP/2's settings identifiers are reserved. See
        // Setting.isForbidden for why this is an error rather than ignorable.
        if (Setting.isForbidden(id)) return error.SettingsError;

        // RFC 8441 §3, carried into HTTP/3 by RFC 9220 §3: "The value of the
        // parameter MUST be 0 or 1." Enforced here rather than by the caller so the
        // rule has one home — and because a value a setting's own definition
        // forbids is precisely "an error in the payload of a SETTINGS frame"
        // (§8.1), which is the code this iterator's error already carries.
        if (id == Setting.enable_connect_protocol and value > 1) return error.SettingsError;

        // §7.2.4: "The same setting identifier MUST NOT occur more than once".
        // Only tracked for identifiers small enough to matter to us — a full
        // map for arbitrary u64 identifiers would let a peer size our memory.
        if (id < 16) {
            const bit = @as(u16, 1) << @intCast(id);
            if (self.seen & bit != 0) return error.SettingsError;
            self.seen |= bit;
        }
        return .{ .id = id, .value = value };
    }
};

/// How much of one frame this parser will hold while waiting for the rest.
/// This bounds control-plane frames (SETTINGS, and the field sections of
/// HEADERS); DATA is not buffered at all — see `Parser.next`. A peer declaring
/// a gigabyte HEADERS frame is asking us to allocate a gigabyte before a single
/// header can be rejected, which is §7's H3_EXCESSIVE_LOAD by name.
pub const max_buffered_frame = 64 * 1024;

/// The incremental frame parser for one stream's bytes.
///
/// Streaming DATA is the design constraint: a body can be arbitrarily long, so
/// DATA payloads are handed out in whatever pieces arrive, never accumulated.
/// Every other frame is delivered whole, because its meaning is not
/// incremental — half a SETTINGS frame says nothing.
pub const Parser = struct {
    state: State = .type,
    /// The current frame's type, valid from state .length onward.
    frame_type: u64 = 0,
    /// Remaining payload bytes of the current frame.
    remaining: u64 = 0,
    /// Accumulation for non-DATA frames that arrive in pieces.
    buffer: std.ArrayList(u8) = .empty,
    /// Partial varint accumulation for the type and length fields themselves —
    /// even the frame header can split across QUIC STREAM frames.
    header: [8]u8 = undefined,
    header_len: usize = 0,

    const State = enum { type, length, payload };

    pub fn deinit(self: *Parser, gpa: Allocator) void {
        self.buffer.deinit(gpa);
        self.* = undefined;
    }

    /// Whether the parser is part-way through a frame: a payload with bytes still
    /// outstanding, or a header varint split across deliveries.
    ///
    /// §7.1 needs this at the moment a stream ends cleanly, where "part-way" stops
    /// being "wait for more" and becomes H3_FRAME_ERROR — the peer promised bytes it
    /// will never send. Answered here rather than by the caller inspecting these
    /// fields, so the definition of "between frames" has one home.
    ///
    /// `buffer` is deliberately *not* consulted. It still holds the last completed
    /// frame's payload after that frame was returned — the item borrows it, so it is
    /// cleared only when the next frame's length is read. Treating a non-empty buffer
    /// as "part-way" would report H3_FRAME_ERROR for a peer whose frame merely arrived
    /// in two pieces before a clean end, which is a legal delivery and not an error.
    pub fn midFrame(self: *const Parser) bool {
        return self.state != .type or self.header_len != 0;
    }

    /// One parsed result: a whole frame, or a piece of a DATA payload.
    pub const Item = union(enum) {
        frame: Frame,
        /// A piece of the current DATA frame's payload. `last` marks the final
        /// piece; the pieces concatenated are the frame.
        body_chunk: struct { bytes: []const u8, last: bool },
    };

    /// Feed bytes; returns the next item and how many bytes of `input` were
    /// consumed, or null if more bytes are needed (all of `input` consumed).
    ///
    /// Slices in the returned item borrow either from `input` or from the
    /// internal buffer, and are valid until the next call.
    pub fn next(self: *Parser, gpa: Allocator, input: []const u8) Error!?struct {
        item: Item,
        consumed: usize,
    } {
        var rest = input;

        while (true) {
            switch (self.state) {
                .type => {
                    const value = self.takeVarint(&rest) orelse return null;
                    self.frame_type = value;
                    // §7.2.9: see FrameType.isForbidden. Checked at the earliest
                    // possible moment — before the length, because a peer this
                    // confused cannot be trusted to frame the rest correctly.
                    if (FrameType.isForbidden(value)) return error.FrameUnexpected;
                    self.state = .length;
                },
                .length => {
                    const len = self.takeVarint(&rest) orelse return null;
                    self.remaining = len;
                    self.state = .payload;
                    self.buffer.clearRetainingCapacity();

                    // Everything delivered whole must fit the buffer bound.
                    // DATA streams and never buffers, so bodies are unbounded
                    // the way bodies must be.
                    if (self.frame_type != @backingInt(FrameType.data) and
                        len > max_buffered_frame)
                    {
                        return error.ExcessiveLoad;
                    }

                    // Zero-length frames complete right here, with no payload
                    // bytes to wait for. Deferring them to the payload state
                    // would stall: a parser waiting for zero more bytes waits
                    // forever on a quiet stream.
                    if (self.remaining == 0) {
                        self.state = .type;
                        if (self.frame_type == @backingInt(FrameType.data)) {
                            return .{
                                .item = .{ .body_chunk = .{ .bytes = &.{}, .last = true } },
                                .consumed = input.len - rest.len,
                            };
                        }
                        return .{
                            .item = .{ .frame = try finishFrame(self.frame_type, &.{}) },
                            .consumed = input.len - rest.len,
                        };
                    }
                },
                .payload => {
                    if (self.frame_type == @backingInt(FrameType.data)) {
                        // DATA streams: no accumulation, no bound, no copy.
                        if (rest.len == 0) return null;
                        const take: usize = @intCast(@min(self.remaining, @as(u64, rest.len)));
                        const chunk = rest[0..take];
                        rest = rest[take..];
                        self.remaining -= take;
                        const last = self.remaining == 0;
                        if (last) self.state = .type;
                        return .{
                            .item = .{ .body_chunk = .{ .bytes = chunk, .last = last } },
                            .consumed = input.len - rest.len,
                        };
                    }

                    // Whole-frame delivery. The fast path — the entire payload
                    // in this input, nothing buffered — borrows from `input`
                    // and copies nothing.
                    if (self.buffer.items.len == 0 and rest.len >= self.remaining) {
                        const take: usize = @intCast(self.remaining);
                        const payload = rest[0..take];
                        rest = rest[take..];
                        self.remaining = 0;
                        self.state = .type;
                        return .{
                            .item = .{ .frame = try finishFrame(self.frame_type, payload) },
                            .consumed = input.len - rest.len,
                        };
                    }

                    // Slow path: hold what arrived, wait for the rest.
                    const take: usize = @intCast(@min(self.remaining, @as(u64, rest.len)));
                    try self.buffer.appendSlice(gpa, rest[0..take]);
                    rest = rest[take..];
                    self.remaining -= take;
                    if (self.remaining > 0) {
                        assert(rest.len == 0);
                        return null;
                    }
                    self.state = .type;
                    return .{
                        .item = .{ .frame = try finishFrame(self.frame_type, self.buffer.items) },
                        .consumed = input.len - rest.len,
                    };
                },
            }
        }
    }

    /// Take one varint that may itself be split across inputs. Returns null and
    /// consumes everything useful when more bytes are needed.
    fn takeVarint(self: *Parser, rest: *[]const u8) ?u64 {
        if (self.header_len == 0 and rest.len > 0) {
            // Fast path: whole varint present, no accumulation round trip.
            const need = varint.peekLen(rest.*[0]);
            if (rest.len >= need) {
                const value = varint.take(rest) catch unreachable;
                return value;
            }
        }
        // Accumulate byte by byte. At most eight, so the loop is bounded by
        // the encoding, not the peer.
        while (rest.len > 0) {
            self.header[self.header_len] = rest.*[0];
            self.header_len += 1;
            rest.* = rest.*[1..];
            const need = varint.peekLen(self.header[0]);
            if (self.header_len == need) {
                var slice: []const u8 = self.header[0..need];
                const value = varint.take(&slice) catch unreachable;
                self.header_len = 0;
                return value;
            }
        }
        return null;
    }
};

/// Interpret a whole payload as the frame its type says it is.
fn finishFrame(frame_type: u64, payload: []const u8) Error!Frame {
    return switch (frame_type) {
        0x00 => unreachable, // DATA is streamed, never delivered whole
        0x01 => .{ .headers = payload },
        0x03 => .{ .cancel_push = wholeVarint(payload) orelse return error.FrameError },
        0x04 => .{ .settings = payload },
        0x05 => blk: {
            // §7.2.5: a push ID, then the field section.
            var rest = payload;
            const push_id = varint.take(&rest) catch return error.FrameError;
            break :blk .{ .push_promise = .{ .push_id = push_id, .field_section = rest } };
        },
        0x07 => .{ .goaway = wholeVarint(payload) orelse return error.FrameError },
        0x0d => .{ .max_push_id = wholeVarint(payload) orelse return error.FrameError },
        else => .{ .unknown = .{ .frame_type = frame_type, .payload = payload } },
    };
}

/// §7.2.3, §7.2.6, §7.2.7: frames whose payload is exactly one varint. Trailing
/// bytes are H3_FRAME_ERROR — a longer payload means the peer meant something
/// this implementation would silently drop.
fn wholeVarint(payload: []const u8) ?u64 {
    var rest = payload;
    const value = varint.take(&rest) catch return null;
    if (rest.len != 0) return null;
    return value;
}

/// §7.2's table of where each frame may appear, as one function so the rule
/// reads the way the RFC's Section 7.2 table does. `push` covers push streams,
/// where only what the server promised may follow.
pub const Where = enum { control, request, push };

pub fn allowedOn(frame_type: u64, where: Where) bool {
    return switch (frame_type) {
        // DATA and HEADERS belong to requests and pushes, never control (§7.2.1,
        // §7.2.2): control carries the connection's own bookkeeping, and body
        // bytes there have no request to belong to.
        0x00, 0x01 => where != .control,
        // CANCEL_PUSH, SETTINGS, GOAWAY, MAX_PUSH_ID: control only. SETTINGS on
        // a request stream is the classic confusion of a peer speaking
        // HTTP/2-shaped HTTP/3 (§7.2.4: "MUST NOT be sent on any other stream").
        0x03, 0x04, 0x07, 0x0d => where == .control,
        // PUSH_PROMISE: request streams only (§7.2.5) — it is the *server's*
        // reference to a push from a request's context.
        0x05 => where == .request,
        // Unknown types are allowed anywhere; §9 requires ignoring them, and a
        // placement rule for a frame with no meaning would be unenforceable.
        else => true,
    };
}

/// Serialize one frame header; the caller appends the payload. Split this way
/// because DATA payloads should be written where they already are rather than
/// copied through an encoder.
pub fn writeFrameHeader(dest: []u8, frame_type: u64, len: u64) usize {
    var i: usize = 0;
    i += varint.encode(dest[i..], frame_type);
    i += varint.encode(dest[i..], len);
    return i;
}

/// Serialize a SETTINGS frame from the settings we advertise.
pub fn writeSettings(dest: []u8, settings: []const Setting) usize {
    var payload_len: u64 = 0;
    for (settings) |s| {
        payload_len += varint.encodedLen(s.id) + varint.encodedLen(s.value);
    }
    var i = writeFrameHeader(dest, @backingInt(FrameType.settings), payload_len);
    for (settings) |s| {
        i += varint.encode(dest[i..], s.id);
        i += varint.encode(dest[i..], s.value);
    }
    return i;
}

/// Serialize a GOAWAY frame (§7.2.6). Its payload is one varint whose meaning
/// depends on which end sent it: a stream ID from a server, a push ID from a
/// client.
pub fn writeGoaway(dest: []u8, id: u64) usize {
    var i = writeFrameHeader(dest, @backingInt(FrameType.goaway), varint.encodedLen(id));
    i += varint.encode(dest[i..], id);
    return i;
}

const testing = std.testing;

/// Feed the parser a buffer in one piece and collect frames.
fn parseAll(gpa: Allocator, parser: *Parser, bytes: []const u8, out: *std.ArrayList(Parser.Item)) !void {
    var rest = bytes;
    while (rest.len > 0) {
        const result = (try parser.next(gpa, rest)) orelse break;
        // Frames borrow from the input, so tests that need them after this loop
        // must copy — these tests only inspect scalars and lengths.
        try out.append(gpa, result.item);
        rest = rest[result.consumed..];
    }
}

test "http3: frames are recovered identically from whole and fragmented input" {
    // The chunk-independence property, the same one the repository's fuzzers
    // assert for every stream codec: a parser fed one byte at a time must see
    // exactly what a parser fed everything at once sees. This is the property
    // QUIC's frame layer did not need and this layer cannot do without —
    // stream bytes arrive in whatever pieces the peer's packetizer chose.
    const gpa = testing.allocator;

    var bytes: [128]u8 = undefined;
    var len: usize = 0;
    // SETTINGS with one entry.
    const entries = [_]Setting{.{ .id = Setting.qpack_max_table_capacity, .value = 4096 }};
    len += writeSettings(bytes[len..], &entries);
    // A GOAWAY.
    len += writeFrameHeader(bytes[len..], 0x07, 1);
    bytes[len] = 8;
    len += 1;
    // An unknown (grease) frame with a three-byte payload.
    len += writeFrameHeader(bytes[len..], 0x21, 3);
    @memcpy(bytes[len..][0..3], "abc");
    len += 3;

    // Whole.
    var whole: Parser = .{};
    defer whole.deinit(gpa);
    var whole_items: std.ArrayList(Parser.Item) = .empty;
    defer whole_items.deinit(gpa);
    try parseAll(gpa, &whole, bytes[0..len], &whole_items);

    try testing.expectEqual(@as(usize, 3), whole_items.items.len);
    try testing.expectEqual(@as(u64, 8), whole_items.items[1].frame.goaway);
    try testing.expectEqual(@as(u64, 0x21), whole_items.items[2].frame.unknown.frame_type);

    // One byte at a time. Frame payloads borrow, so record only shapes.
    var split: Parser = .{};
    defer split.deinit(gpa);
    var count: usize = 0;
    for (bytes[0..len]) |byte| {
        var rest: []const u8 = &.{byte};
        while (rest.len > 0) {
            const result = (try split.next(gpa, rest)) orelse break;
            rest = rest[result.consumed..];
            switch (result.item) {
                .frame => |f| {
                    switch (count) {
                        0 => {
                            var it = SettingsIterator.init(f.settings);
                            const s = (try it.next()).?;
                            try testing.expectEqual(@as(u64, 4096), s.value);
                            try testing.expect((try it.next()) == null);
                        },
                        1 => try testing.expectEqual(@as(u64, 8), f.goaway),
                        2 => try testing.expectEqualStrings("abc", f.unknown.payload),
                        else => return error.TestUnexpectedResult,
                    }
                    count += 1;
                },
                .body_chunk => return error.TestUnexpectedResult,
            }
        }
    }
    try testing.expectEqual(@as(usize, 3), count);
}

test "http3: DATA streams through without buffering, in as many pieces as it arrives" {
    // A body can be larger than any bound this layer could justify, so DATA is
    // the one frame never accumulated: each piece is handed out as it arrives
    // and the parser holds nothing. Buffering it would make every download
    // allocate its own size — §7's H3_EXCESSIVE_LOAD names the failure.
    const gpa = testing.allocator;
    var parser: Parser = .{};
    defer parser.deinit(gpa);

    var bytes: [64]u8 = undefined;
    var len = writeFrameHeader(&bytes, 0x00, 10);
    @memcpy(bytes[len..][0..10], "0123456789");
    len += 10;
    // And a HEADERS after it, to prove the boundary lands exactly.
    len += writeFrameHeader(bytes[len..], 0x01, 2);
    @memcpy(bytes[len..][0..2], "hh");
    len += 2;

    // Feed in three uneven pieces.
    var collected: std.ArrayList(u8) = .empty;
    defer collected.deinit(gpa);
    var saw_last = false;
    var saw_headers = false;
    const cuts = [_]usize{ 0, 5, 9, len };
    for (cuts[0 .. cuts.len - 1], cuts[1..]) |from, to| {
        var rest = bytes[from..to];
        while (rest.len > 0) {
            const result = (try parser.next(gpa, rest)) orelse break;
            rest = rest[result.consumed..];
            switch (result.item) {
                .body_chunk => |chunk| {
                    try testing.expect(!saw_last);
                    try collected.appendSlice(gpa, chunk.bytes);
                    if (chunk.last) saw_last = true;
                },
                .frame => |f| {
                    try testing.expect(saw_last);
                    try testing.expectEqualStrings("hh", f.headers);
                    saw_headers = true;
                },
            }
        }
    }
    try testing.expectEqualStrings("0123456789", collected.items);
    try testing.expect(saw_last);
    try testing.expect(saw_headers);
    // Nothing was ever held: the buffer was only ever used for HEADERS pieces,
    // and DATA left no residue.
    try testing.expectEqual(@as(usize, 0), parser.buffer.items.len);

    // A zero-length DATA frame still produces its (empty, last) chunk — a
    // parser that defers it waits forever for zero more bytes.
    var empty_bytes: [8]u8 = undefined;
    const empty_len = writeFrameHeader(&empty_bytes, 0x00, 0);
    const result = (try parser.next(gpa, empty_bytes[0..empty_len])).?;
    try testing.expect(result.item.body_chunk.last);
    try testing.expectEqual(@as(usize, 0), result.item.body_chunk.bytes.len);
}

test "http3: HTTP/2's frame types are rejected, unknown types are ignored" {
    // Two rules pointing in opposite directions, and both load-bearing. §9:
    // unknown types must be ignored, or no extension (and no grease) can ever
    // deploy. §7.2.9: the four types HTTP/2 used for stream state are reserved
    // as an error, because a peer sending WINDOW_UPDATE has mapped HTTP/2 onto
    // HTTP/3 frame for frame and *everything* it believes about the connection
    // is suspect. Treating those as ignorable-unknown would paper over exactly
    // the peer the reservation exists to catch.
    const gpa = testing.allocator;

    for ([_]u64{ 0x02, 0x06, 0x08, 0x09 }) |forbidden| {
        var parser: Parser = .{};
        defer parser.deinit(gpa);
        var bytes: [16]u8 = undefined;
        const len = writeFrameHeader(&bytes, forbidden, 4);
        try testing.expectError(error.FrameUnexpected, parser.next(gpa, bytes[0..len]));
        try testing.expect(FrameType.isForbidden(forbidden));
    }

    // Grease values from the reserved formula parse as unknown frames.
    var parser: Parser = .{};
    defer parser.deinit(gpa);
    for ([_]u64{ 0x21, 0x21 + 0x1f, 0x21 + 0x1f * 7 }) |grease| {
        try testing.expect(FrameType.isGrease(grease));
        var bytes: [16]u8 = undefined;
        var len = writeFrameHeader(&bytes, grease, 2);
        @memcpy(bytes[len..][0..2], "xx");
        len += 2;
        const result = (try parser.next(gpa, bytes[0..len])).?;
        try testing.expectEqual(grease, result.item.frame.unknown.frame_type);
    }
    // Near misses of the grease formula are not grease.
    try testing.expect(!FrameType.isGrease(0x22));
    try testing.expect(!FrameType.isGrease(0x20));
    // And the forbidden values are not grease either — the two sets must not
    // overlap or the rules above would contradict each other.
    for ([_]u64{ 0x02, 0x06, 0x08, 0x09 }) |forbidden| {
        try testing.expect(!FrameType.isGrease(forbidden));
    }
}

test "http3: SETTINGS enforcement — duplicates, HTTP/2 leftovers, and grease" {
    const gpa = testing.allocator;
    _ = gpa;

    // A well-formed SETTINGS with an interpreted, a grease and an unknown entry.
    var bytes: [64]u8 = undefined;
    var len: usize = 0;
    for ([_]Setting{
        .{ .id = Setting.qpack_max_table_capacity, .value = 4096 },
        .{ .id = 0x21, .value = 999 }, // grease
        .{ .id = 0x4242, .value = 7 }, // unknown
    }) |s| {
        len += varint.encode(bytes[len..], s.id);
        len += varint.encode(bytes[len..], s.value);
    }
    var settings: Settings = .{};
    var it = SettingsIterator.init(bytes[0..len]);
    while (try it.next()) |s| settings.apply(s);
    try testing.expectEqual(@as(u64, 4096), settings.qpack_max_table_capacity);
    // Defaults survive unknown and grease entries.
    try testing.expectEqual(@as(u64, 0), settings.qpack_blocked_streams);
    try testing.expectEqual(std.math.maxInt(u64), settings.max_field_section_size);

    // §7.2.4: a repeated identifier is H3_SETTINGS_ERROR. Loss recovery cannot
    // explain it — SETTINGS is sent once on a reliable stream — so a duplicate
    // means the encoder disagrees with itself about what it advertised.
    var dup: [32]u8 = undefined;
    var dup_len: usize = 0;
    for ([_]Setting{
        .{ .id = Setting.qpack_blocked_streams, .value = 1 },
        .{ .id = Setting.qpack_blocked_streams, .value = 2 },
    }) |s| {
        dup_len += varint.encode(dup[dup_len..], s.id);
        dup_len += varint.encode(dup[dup_len..], s.value);
    }
    var dup_it = SettingsIterator.init(dup[0..dup_len]);
    _ = try dup_it.next();
    try testing.expectError(error.SettingsError, dup_it.next());

    // §7.2.4.1: HTTP/2's settings identifiers are reserved errors, not
    // ignorable unknowns — same diagnosis as the forbidden frame types.
    for ([_]u64{ 0x02, 0x03, 0x04, 0x05 }) |leftover| {
        var bad: [16]u8 = undefined;
        var bad_len = varint.encode(&bad, leftover);
        bad_len += varint.encode(bad[bad_len..], 100);
        var bad_it = SettingsIterator.init(bad[0..bad_len]);
        try testing.expectError(error.SettingsError, bad_it.next());
    }

    // A truncated pair — an id with no value — is malformed, not "almost done".
    var cut: [8]u8 = undefined;
    const cut_len = varint.encode(&cut, Setting.max_field_section_size);
    var cut_it = SettingsIterator.init(cut[0..cut_len]);
    try testing.expectError(error.SettingsError, cut_it.next());
}

test "http3: §7.2's placement table, and single-varint frames reject trailing bytes" {
    const gpa = testing.allocator;

    // The placement table, spot-checked at the entries whose confusion is
    // documented: SETTINGS on a request stream is the HTTP/2 reflex (§7.2.4),
    // DATA on the control stream has no request to belong to, PUSH_PROMISE is
    // request-only. Unknown types pass everywhere because a placement rule for
    // a meaningless frame cannot be enforced.
    try testing.expect(allowedOn(0x00, .request));
    try testing.expect(!allowedOn(0x00, .control));
    try testing.expect(allowedOn(0x01, .push));
    try testing.expect(!allowedOn(0x04, .request));
    try testing.expect(allowedOn(0x04, .control));
    try testing.expect(!allowedOn(0x05, .control));
    try testing.expect(!allowedOn(0x05, .push));
    try testing.expect(allowedOn(0x05, .request));
    try testing.expect(allowedOn(0x21, .control));
    try testing.expect(allowedOn(0x21, .request));

    // GOAWAY's payload is exactly one varint; a trailing byte means the peer
    // said something we would otherwise silently drop (§7.2.6).
    var parser: Parser = .{};
    defer parser.deinit(gpa);
    var bytes: [16]u8 = undefined;
    var len = writeFrameHeader(&bytes, 0x07, 2);
    bytes[len] = 8;
    bytes[len + 1] = 9; // trailing
    len += 2;
    try testing.expectError(error.FrameError, parser.next(gpa, bytes[0..len]));

    // And a control-plane frame above the buffer bound is refused by its
    // declared length, before any of it is held: the attack is the declaration.
    var big: Parser = .{};
    defer big.deinit(gpa);
    var head: [16]u8 = undefined;
    const head_len = writeFrameHeader(&head, 0x01, max_buffered_frame + 1);
    try testing.expectError(error.ExcessiveLoad, big.next(gpa, head[0..head_len]));

    // DATA of the same size is fine — bodies are unbounded the way bodies
    // must be.
    var body: Parser = .{};
    defer body.deinit(gpa);
    var data_head: [16]u8 = undefined;
    const data_head_len = writeFrameHeader(&data_head, 0x00, max_buffered_frame + 1);
    try testing.expect((try body.next(gpa, data_head[0..data_head_len])) == null);
}

test "http3: stream types — control, QPACK, grease" {
    // §6.2: the first varint of a unidirectional stream is its type. Unknown
    // types are not an error (§6.2.4) — the stream is simply not read — which
    // is the same ignore-to-extend posture as unknown frames, and greased
    // stream types (§11.2.4) exercise it.
    try testing.expectEqual(StreamType.control, @as(StreamType, @fromBackingInt(@intCast(0x00))));
    try testing.expectEqual(StreamType.qpack_encoder, @as(StreamType, @fromBackingInt(@intCast(0x02))));
    try testing.expectEqual(StreamType.qpack_decoder, @as(StreamType, @fromBackingInt(@intCast(0x03))));
    try testing.expect(StreamType.isGrease(0x21 + 0x1f * 3));
    try testing.expect(!StreamType.isGrease(0x00));

    // Every H3 error this layer can produce has its registered wire code, so a
    // CONNECTION_CLOSE built from one is meaningful at any conforming peer.
    try testing.expectEqual(@as(u64, 0x0106), errorCode(error.FrameError));
    try testing.expectEqual(@as(u64, 0x0109), errorCode(error.SettingsError));
    try testing.expectEqual(@as(u64, 0x0105), errorCode(error.FrameUnexpected));
    try testing.expectEqual(@as(u64, 0x010a), errorCode(error.MissingSettings));
}
