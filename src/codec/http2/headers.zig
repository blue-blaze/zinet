//! Reassembling header blocks across `CONTINUATION` frames: RFC 9113 §6.10.
//!
//! A header block is one HPACK byte stream cut into fragments by frame
//! boundaries, and the cut points are not part of it: HPACK is decoded over the
//! concatenation, so nothing can be decoded until the block completes. That is
//! also why §6.10 forbids interleaving anything — a frame from *any* stream —
//! between a `HEADERS` and its `CONTINUATION`s. The header block is the one place
//! HTTP/2 stops being multiplexed.
//!
//! ## Why the two limits here are the point rather than a detail
//!
//! §6.10 says a block continues until a frame carries `END_HEADERS`, and says
//! nothing about how long that may take. In 2024 that turned out to be a
//! denial-of-service class of its own: a peer sends `HEADERS` without
//! `END_HEADERS` and then `CONTINUATION` frames forever, and an implementation
//! that accumulates until the block completes accumulates forever. Worse, the
//! frames are individually legal, so nothing in the parser objects.
//!
//! Two bounds close it, and both are needed. A cap on accumulated bytes alone
//! still lets a peer send an unbounded number of *empty* `CONTINUATION` frames,
//! which costs no memory but unbounded CPU and keeps the connection pinned. A cap
//! on frames alone lets sixteen frames of 16 KiB each through. So there is a
//! ceiling on the block's size and a ceiling on how many frames may build it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../../buffer.zig").Buffer;
const frame = @import("frame.zig");

pub const Error = error{
    /// §6.10 was violated: something was interleaved into a header block, a
    /// `CONTINUATION` arrived with no block open, or one arrived for the wrong
    /// stream. Always a connection error — the HPACK stream is now of unknown
    /// alignment, so no stream on the connection can be trusted.
    ProtocolError,
    /// One of the two bounds above was reached.
    LimitExceeded,
};

/// Which frame opened the block, since the two are completed the same way but
/// mean different things.
pub const Kind = enum { headers, push_promise };

/// A reassembled header block, ready for HPACK.
///
/// `block` is borrowed. When the whole block arrived in one frame — the ordinary
/// case — it points into that frame's payload; otherwise it points into the
/// assembler. Either way it is valid only until the next frame is fed, which is
/// enough because the caller decodes it immediately and everything runs on one
/// task.
pub const Complete = struct {
    stream_id: u31,
    kind: Kind,
    /// §6.2: `END_STREAM` on the `HEADERS` frame, which arrives before the block
    /// is complete and so has to be remembered across the `CONTINUATION`s.
    end_stream: bool,
    /// §6.3, retained and reported but not acted on; see `frame.Priority`.
    priority: ?frame.Priority = null,
    /// Only meaningful when `kind` is `push_promise`.
    promised_stream_id: u31 = 0,
    block: []const u8,
};

pub const Options = struct {
    /// Most bytes one header block may accumulate. Independent of
    /// `max_header_list_size`, which bounds the *decoded* list: this bounds the
    /// compressed form, before anything has been decoded.
    max_block_size: u32 = 16 * 1024,
    /// Most `CONTINUATION` frames one block may be built from. Bounds the empty
    /// frame flood, which costs no memory.
    max_continuation_frames: u32 = 16,
};

pub const Assembler = struct {
    options: Options = .{},
    /// Fragments concatenated so far. Only used when a block spans frames.
    accumulated: Buffer = .empty,
    open: ?Open = null,

    const Open = struct {
        stream_id: u31,
        kind: Kind,
        end_stream: bool,
        priority: ?frame.Priority,
        promised_stream_id: u31,
        continuation_frames: u32 = 0,
    };

    pub fn deinit(assembler: *Assembler, gpa: Allocator) void {
        assembler.accumulated.deinit(gpa);
        assembler.* = .{ .options = assembler.options };
    }

    pub fn isOpen(assembler: *const Assembler) bool {
        return assembler.open != null;
    }

    /// The stream whose header block is open, if one is.
    pub fn openStream(assembler: *const Assembler) ?u31 {
        return if (assembler.open) |open| open.stream_id else null;
    }

    /// §6.10: enforces what may appear next. Every frame the connection reads goes
    /// through this before it is routed, because the rule is about the frame
    /// *sequence* rather than about any one frame's contents.
    pub fn guard(assembler: *const Assembler, header: frame.Header) Error!void {
        const open = assembler.open orelse {
            // A CONTINUATION continues nothing.
            if (header.frame_type == .continuation) return error.ProtocolError;
            return;
        };
        // A block is open, so the only legal next frame is its continuation. Not
        // a PING, not a SETTINGS, not a DATA on another stream: §6.10 admits no
        // exception, because the HPACK stream would otherwise be ambiguous.
        if (header.frame_type != .continuation) return error.ProtocolError;
        if (header.stream_id != open.stream_id) return error.ProtocolError;
    }

    /// Feeds a `HEADERS` frame. Returns the block if `END_HEADERS` was set.
    pub fn pushHeaders(
        assembler: *Assembler,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
    ) (Error || frame.Error || Buffer.Error)!?Complete {
        assert(header.frame_type == .headers);
        assert(assembler.open == null);

        const prologue = try frame.parseHeaders(payload, header.flags);
        return assembler.begin(gpa, .{
            .stream_id = header.stream_id,
            .kind = .headers,
            .end_stream = header.flags.endStream(),
            .priority = prologue.priority,
            .promised_stream_id = 0,
        }, prologue.fragment, header.flags.endHeaders());
    }

    /// Feeds a `PUSH_PROMISE` frame. Returns the block if `END_HEADERS` was set.
    pub fn pushPromise(
        assembler: *Assembler,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
    ) (Error || frame.Error || Buffer.Error)!?Complete {
        assert(header.frame_type == .push_promise);
        assert(assembler.open == null);

        const parsed = try frame.parsePushPromise(payload, header.flags);
        return assembler.begin(gpa, .{
            .stream_id = header.stream_id,
            .kind = .push_promise,
            // §6.6: END_STREAM has no meaning on PUSH_PROMISE; the promised
            // stream's request is complete by definition.
            .end_stream = false,
            .priority = null,
            .promised_stream_id = parsed.promised_stream_id,
        }, parsed.fragment, header.flags.endHeaders());
    }

    /// Feeds a `CONTINUATION` frame. `guard` has already established that one is
    /// legal and that it belongs to the open block.
    pub fn pushContinuation(
        assembler: *Assembler,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
    ) (Error || Buffer.Error)!?Complete {
        assert(header.frame_type == .continuation);
        if (assembler.open == null) return error.ProtocolError;
        const open = &assembler.open.?;
        assert(header.stream_id == open.stream_id);

        open.continuation_frames += 1;
        if (open.continuation_frames > assembler.options.max_continuation_frames) {
            return error.LimitExceeded;
        }
        try assembler.append(gpa, payload);

        if (!header.flags.endHeaders()) return null;
        const finished = open.*;
        assembler.open = null;
        return .{
            .stream_id = finished.stream_id,
            .kind = finished.kind,
            .end_stream = finished.end_stream,
            .priority = finished.priority,
            .promised_stream_id = finished.promised_stream_id,
            .block = assembler.accumulated.readableSlice(),
        };
    }

    fn begin(
        assembler: *Assembler,
        gpa: Allocator,
        open: Open,
        fragment: []const u8,
        end_headers: bool,
    ) (Error || Buffer.Error)!?Complete {
        if (fragment.len > assembler.options.max_block_size) return error.LimitExceeded;

        if (end_headers) {
            // The ordinary case: one frame carries the whole block, so it is used
            // where it lies. Copying it would be a per-request cost paid for a
            // situation that is not happening.
            return .{
                .stream_id = open.stream_id,
                .kind = open.kind,
                .end_stream = open.end_stream,
                .priority = open.priority,
                .promised_stream_id = open.promised_stream_id,
                .block = fragment,
            };
        }

        assembler.accumulated.clear();
        try assembler.accumulated.writeBytes(gpa, fragment);
        assembler.open = open;
        return null;
    }

    fn append(assembler: *Assembler, gpa: Allocator, fragment: []const u8) (Error || Buffer.Error)!void {
        const total = assembler.accumulated.readableLen() + fragment.len;
        if (total > assembler.options.max_block_size) return error.LimitExceeded;
        try assembler.accumulated.writeBytes(gpa, fragment);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const hpack = @import("hpack.zig");

fn headerOf(frame_type: frame.FrameType, stream_id: u31, flag_bits: u8, length: u24) frame.Header {
    return .{
        .length = length,
        .frame_type = frame_type,
        .flags = .{ .bits = flag_bits },
        .stream_id = stream_id,
    };
}

test "assembler: one HEADERS frame with END_HEADERS completes at once" {
    const gpa = testing.allocator;
    var assembler: Assembler = .{};
    defer assembler.deinit(gpa);

    const payload = "\x82\x86\x84";
    const header = headerOf(.headers, 1, frame.Flags.end_headers | frame.Flags.end_stream, 3);
    try assembler.guard(header);
    const done = (try assembler.pushHeaders(gpa, header, payload)).?;

    try testing.expectEqual(@as(u31, 1), done.stream_id);
    try testing.expectEqual(Kind.headers, done.kind);
    try testing.expect(done.end_stream);
    try testing.expectEqualStrings(payload, done.block);
    // Nothing was copied: the block is the payload where it lies.
    try testing.expectEqual(payload.ptr, done.block.ptr);
    try testing.expect(!assembler.isOpen());
}

test "assembler: fragments are concatenated, and only the cut points differ" {
    const gpa = testing.allocator;

    // A real HPACK block, then the same block cut at every possible position. The
    // decoded fields must be identical each time, which is what "the frame
    // boundaries are not part of the header block" actually means.
    const block = "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    const expected = [_]hpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "www.example.com" },
    };

    for (0..block.len + 1) |cut| {
        var assembler: Assembler = .{};
        defer assembler.deinit(gpa);
        var decoder: hpack.Decoder = .init(4096);
        defer decoder.deinit(gpa);

        const first = block[0..cut];
        const rest = block[cut..];

        const open_header = headerOf(.headers, 1, 0, @intCast(first.len));
        try assembler.guard(open_header);
        try testing.expect(try assembler.pushHeaders(gpa, open_header, first) == null);
        try testing.expect(assembler.isOpen());
        try testing.expectEqual(@as(?u31, 1), assembler.openStream());

        const cont_header = headerOf(.continuation, 1, frame.Flags.end_headers, @intCast(rest.len));
        try assembler.guard(cont_header);
        const done = (try assembler.pushContinuation(gpa, cont_header, rest)).?;
        try testing.expectEqualStrings(block, done.block);
        try testing.expect(!assembler.isOpen());

        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        var fields: std.ArrayList(hpack.Field) = .empty;
        try decoder.decode(gpa, arena_state.allocator(), done.block, &fields, .{});
        try testing.expectEqual(expected.len, fields.items.len);
        for (expected, fields.items) |want, got| {
            try testing.expectEqualStrings(want.name, got.name);
            try testing.expectEqualStrings(want.value, got.value);
        }
    }
}

test "assembler: flags and priority set on HEADERS survive the continuations" {
    const gpa = testing.allocator;
    var assembler: Assembler = .{};
    defer assembler.deinit(gpa);

    // END_STREAM and the priority fields arrive on the opening frame, before the
    // block is complete, so they have to be remembered rather than re-read.
    const open_header = headerOf(
        .headers,
        7,
        frame.Flags.end_stream | frame.Flags.priority | frame.Flags.padded,
        0,
    );
    try testing.expect(try assembler.pushHeaders(
        gpa,
        open_header,
        "\x02\x80\x00\x00\x03\x0f\x82\xff\xff",
    ) == null);

    var done: ?Complete = null;
    for (0..3) |index| {
        const last = index == 2;
        const cont = headerOf(.continuation, 7, if (last) frame.Flags.end_headers else 0, 1);
        try assembler.guard(cont);
        done = try assembler.pushContinuation(gpa, cont, "\x86");
        try testing.expectEqual(last, done != null);
    }

    try testing.expect(done.?.end_stream);
    try testing.expect(done.?.priority.?.exclusive);
    try testing.expectEqual(@as(u31, 3), done.?.priority.?.dependency);
    try testing.expectEqual(@as(u9, 16), done.?.priority.?.weight);
    // The padding came off before anything was accumulated.
    try testing.expectEqualStrings("\x82\x86\x86\x86", done.?.block);
}

test "assembler: PUSH_PROMISE carries the promised id across continuations" {
    const gpa = testing.allocator;
    var assembler: Assembler = .{};
    defer assembler.deinit(gpa);

    const open_header = headerOf(.push_promise, 1, 0, 5);
    try testing.expect(try assembler.pushPromise(gpa, open_header, "\x00\x00\x00\x02\x82") == null);

    const cont = headerOf(.continuation, 1, frame.Flags.end_headers, 1);
    const done = (try assembler.pushContinuation(gpa, cont, "\x86")).?;
    try testing.expectEqual(Kind.push_promise, done.kind);
    try testing.expectEqual(@as(u31, 2), done.promised_stream_id);
    // §6.6: END_STREAM means nothing on PUSH_PROMISE.
    try testing.expect(!done.end_stream);
    try testing.expectEqualStrings("\x82\x86", done.block);
}

test "assembler: §6.10 admits nothing between HEADERS and its CONTINUATIONs" {
    const gpa = testing.allocator;
    var assembler: Assembler = .{};
    defer assembler.deinit(gpa);

    // A CONTINUATION continues nothing.
    try testing.expectError(
        error.ProtocolError,
        assembler.guard(headerOf(.continuation, 1, frame.Flags.end_headers, 0)),
    );

    _ = try assembler.pushHeaders(gpa, headerOf(.headers, 1, 0, 1), "\x82");
    try testing.expect(assembler.isOpen());

    // Not a PING, not a SETTINGS, not even a DATA on an unrelated stream. §6.10
    // has no exception, because the HPACK stream would otherwise be ambiguous.
    for ([_]frame.Header{
        headerOf(.data, 1, 0, 0),
        headerOf(.data, 3, 0, 0),
        headerOf(.ping, 0, 0, 8),
        headerOf(.settings, 0, 0, 0),
        headerOf(.window_update, 0, 0, 4),
        headerOf(.rst_stream, 1, 0, 4),
        headerOf(.headers, 3, frame.Flags.end_headers, 0),
        // An unknown frame type is normally discarded, but not here: §6.10 is
        // about the sequence, so an extension frame cannot slip in either.
        headerOf(@fromBackingInt(@intCast(0xef)), 0, 0, 0),
    }) |interloper| {
        try testing.expectError(error.ProtocolError, assembler.guard(interloper));
    }

    // A CONTINUATION for a different stream is equally not allowed.
    try testing.expectError(
        error.ProtocolError,
        assembler.guard(headerOf(.continuation, 3, frame.Flags.end_headers, 0)),
    );
    // The right one is.
    try assembler.guard(headerOf(.continuation, 1, frame.Flags.end_headers, 0));
}

test "assembler: the CONTINUATION flood is bounded by frames and by bytes" {
    const gpa = testing.allocator;

    // The 2024 flood: frames that are individually legal and never complete the
    // block. Empty ones cost no memory at all, which is why a byte ceiling alone
    // would not close it.
    {
        var assembler: Assembler = .{ .options = .{ .max_continuation_frames = 4 } };
        defer assembler.deinit(gpa);
        _ = try assembler.pushHeaders(gpa, headerOf(.headers, 1, 0, 1), "\x82");

        const empty = headerOf(.continuation, 1, 0, 0);
        for (0..4) |_| {
            try assembler.guard(empty);
            try testing.expect(try assembler.pushContinuation(gpa, empty, "") == null);
        }
        try assembler.guard(empty);
        try testing.expectError(
            error.LimitExceeded,
            assembler.pushContinuation(gpa, empty, ""),
        );
    }

    // And bytes, which a frame ceiling alone would not close: sixteen frames of
    // 16 KiB is a quarter of a megabyte per header block.
    {
        var assembler: Assembler = .{ .options = .{ .max_block_size = 64 } };
        defer assembler.deinit(gpa);
        const chunk: [32]u8 = @splat('a');
        _ = try assembler.pushHeaders(gpa, headerOf(.headers, 1, 0, 32), &chunk);

        const cont = headerOf(.continuation, 1, 0, 32);
        try testing.expect(try assembler.pushContinuation(gpa, cont, &chunk) == null);
        try testing.expectError(
            error.LimitExceeded,
            assembler.pushContinuation(gpa, cont, &chunk),
        );
    }

    // A single opening frame already over the ceiling is refused before anything
    // is accumulated.
    {
        var assembler: Assembler = .{ .options = .{ .max_block_size = 16 } };
        defer assembler.deinit(gpa);
        const chunk: [32]u8 = @splat('a');
        try testing.expectError(
            error.LimitExceeded,
            assembler.pushHeaders(gpa, headerOf(.headers, 1, 0, 32), &chunk),
        );
    }
}

test "assembler: a completed block is reusable for the next one" {
    const gpa = testing.allocator;
    var assembler: Assembler = .{};
    defer assembler.deinit(gpa);

    // Two blocks in a row, both spanning frames, so the accumulation buffer is
    // reused rather than concatenating one block onto the last.
    for ([_]u31{ 1, 3 }) |stream_id| {
        _ = try assembler.pushHeaders(gpa, headerOf(.headers, stream_id, 0, 1), "\x82");
        const cont = headerOf(.continuation, stream_id, frame.Flags.end_headers, 1);
        const done = (try assembler.pushContinuation(gpa, cont, "\x86")).?;
        try testing.expectEqual(stream_id, done.stream_id);
        try testing.expectEqualStrings("\x82\x86", done.block);
    }
}
