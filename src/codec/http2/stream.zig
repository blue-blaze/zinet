//! The stream state machine, stream identifiers, and the two rate limits that
//! keep a peer from making streams cost more than they are worth.
//! RFC 9113 §5.1, §5.1.1 and §5.1.2.
//!
//! ## Severity *is* decided here, unlike in the frame layer
//!
//! §5.4 splits failures in two: a connection error ends everything, a stream error
//! resets one stream and the connection carries on. The frame layer deliberately
//! leaves the choice to its caller because the same malformed frame can be either.
//! Here the RFC is explicit, and the distinctions are sharp enough to be worth
//! spelling out — the same event on a closed stream is a *stream* error if the
//! stream was reset and a *connection* error if it ended with `END_STREAM`:
//!
//! > An endpoint that receives any frame other than PRIORITY after receiving a
//! > RST_STREAM MUST treat that as a stream error of type STREAM_CLOSED.
//!
//! > An endpoint that receives any frames after receiving a frame with the
//! > END_STREAM flag set MUST treat that as a connection error of type
//! > STREAM_CLOSED.
//!
//! The reason is not arbitrary. A `RST_STREAM` and a frame already in flight cross
//! on the wire all the time, so punishing the whole connection for a race the peer
//! could not avoid would be wrong. `END_STREAM` is different: the peer said it was
//! finished, so anything after it means the two sides disagree about what the
//! stream even is.
//!
//! So how a stream closed is remembered rather than collapsed into one `closed`
//! state, and the error set names the severity.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../../buffer.zig").Buffer;
const flow = @import("flow.zig");
const frame = @import("frame.zig");
const limits = @import("limits.zig");

pub const Error = error{
    /// §5.4.2, `STREAM_CLOSED`: reset this stream and carry on.
    StreamClosed,
    /// §5.4.1, `STREAM_CLOSED`: the peer sent something after `END_STREAM`, so the
    /// two sides no longer agree about the stream and the connection must end.
    StreamClosedFatal,
    /// §5.4.1, `PROTOCOL_ERROR`.
    ProtocolError,
    /// §5.1.2, `REFUSED_STREAM`: a stream error, and specifically the one that
    /// tells the peer it may retry the request on a new connection.
    RefusedStream,
    /// A rate limit of our own, answered with `ENHANCE_YOUR_CALM`.
    EnhanceYourCalm,
};

pub const Severity = enum { connection, stream };

pub fn severity(err: Error) Severity {
    return switch (err) {
        error.StreamClosed, error.RefusedStream => .stream,
        error.StreamClosedFatal, error.ProtocolError, error.EnhanceYourCalm => .connection,
    };
}

pub fn errorCode(err: Error) frame.ErrorCode {
    return switch (err) {
        error.StreamClosed, error.StreamClosedFatal => .stream_closed,
        error.ProtocolError => .protocol_error,
        error.RefusedStream => .refused_stream,
        error.EnhanceYourCalm => .enhance_your_calm,
    };
}

/// Which side an event came from. "Local" is this endpoint sending, "remote" is
/// the peer sending; the state machine is deliberately symmetric, which is what
/// lets one implementation serve both a client and a server.
pub const Direction = enum { local, remote };

/// RFC 9113 §5.1. `closed` is split by cause because the two behave differently
/// on a late frame; see the module comment.
pub const State = enum {
    idle,
    reserved_local,
    reserved_remote,
    open,
    half_closed_local,
    half_closed_remote,
    /// Closed by `RST_STREAM`, from either side.
    closed_reset,
    /// Closed because both sides sent `END_STREAM`.
    closed_complete,

    pub fn isClosed(state: State) bool {
        return state == .closed_reset or state == .closed_complete;
    }

    /// Whether the stream counts against `SETTINGS_MAX_CONCURRENT_STREAMS`.
    /// §5.1.2 counts open and half-closed streams, and explicitly not the
    /// reserved ones or anything closed — which is precisely the gap Rapid Reset
    /// exploited, and why `ResetLimiter` exists.
    pub fn isConcurrent(state: State) bool {
        return switch (state) {
            .open, .half_closed_local, .half_closed_remote => true,
            .idle, .reserved_local, .reserved_remote, .closed_reset, .closed_complete => false,
        };
    }
};

pub const Stream = struct {
    id: u31,
    state: State = .idle,

    /// §5.2: the two windows are per stream as well as per connection, and they
    /// live here rather than in a table of their own because they are created and
    /// destroyed with the stream. Defaults are §6.5.2's, replaced by whatever was
    /// negotiated when the registry opens the stream.
    send_window: flow.Window = .init(frame.default_initial_window_size),
    recv_window: flow.Window = .init(frame.default_initial_window_size),
    /// Bytes the application has handed over that no credit has yet covered, and
    /// the water mark accounting that reports it. See `flow.SendQueue` for why
    /// HTTP/2 needs this where the rest of the framework blocks instead.
    sends: flow.SendQueue = .{},
    pending: Buffer = .empty,
    /// Set when `END_STREAM` should go out with the last of `pending`.
    pending_end_stream: bool = false,
    /// Whether a header block has been *received* on this stream, so that a second
    /// one is recognised as trailers (§8.1).
    ///
    /// Strictly the receive direction. Marking it when this side sends its own
    /// headers conflates the two, and then a client treats the response it asked
    /// for as trailers on its own request — which is exactly what happened before
    /// the two-sided test above existed to catch it.
    remote_headers_seen: bool = false,

    pub fn deinit(stream: *Stream, gpa: Allocator) void {
        stream.pending.deinit(gpa);
    }

    /// §6.2. `end_stream` is the flag on the frame, which is what actually drives
    /// the transition — a `HEADERS` with it set opens and half-closes at once.
    pub fn onHeaders(stream: *Stream, direction: Direction, end_stream: bool) Error!void {
        switch (stream.state) {
            .idle => stream.state = .open,
            // §5.1: sending HEADERS on a stream reserved locally is what turns a
            // push into a response, and the peer can never send on it.
            .reserved_local => {
                if (direction != .local) return error.ProtocolError;
                stream.state = .half_closed_remote;
            },
            .reserved_remote => {
                if (direction != .remote) return error.ProtocolError;
                stream.state = .half_closed_local;
            },
            // A second HEADERS is legal: trailers. §8.1 allows exactly one such
            // block and only with END_STREAM set, which is checked by the caller
            // that knows whether a block has already been delivered.
            .open, .half_closed_local => {},
            // §5.1: the peer already said it was done sending.
            .half_closed_remote => if (direction == .remote) return error.StreamClosed,
            .closed_reset => return error.StreamClosed,
            .closed_complete => return error.StreamClosedFatal,
        }
        if (end_stream) try stream.endStream(direction);
    }

    /// §6.1.
    pub fn onData(stream: *Stream, direction: Direction, end_stream: bool) Error!void {
        switch (stream.state) {
            // §6.1: DATA before HEADERS. There is no request yet, so the frame
            // belongs to nothing.
            .idle => return error.ProtocolError,
            .reserved_local, .reserved_remote => return error.ProtocolError,
            .open => {},
            .half_closed_local => if (direction == .local) return error.ProtocolError,
            .half_closed_remote => if (direction == .remote) return error.StreamClosed,
            .closed_reset => return error.StreamClosed,
            .closed_complete => return error.StreamClosedFatal,
        }
        if (end_stream) try stream.endStream(direction);
    }

    /// §6.6. Called on the *promised* stream, which must be idle.
    pub fn onPushPromise(stream: *Stream, direction: Direction) Error!void {
        if (stream.state != .idle) return error.ProtocolError;
        stream.state = switch (direction) {
            .local => .reserved_local,
            .remote => .reserved_remote,
        };
    }

    /// §6.4. Legal from any state but idle, and idempotent thereafter: a
    /// `RST_STREAM` crossing another on the wire is ordinary.
    pub fn onRstStream(stream: *Stream, _: Direction) Error!void {
        switch (stream.state) {
            // §6.4: a RST_STREAM for an idle stream refers to nothing.
            .idle => return error.ProtocolError,
            .closed_complete => {
                // §5.1 permits RST_STREAM shortly after END_STREAM; treating the
                // race as fatal would punish a peer for timing it could not
                // control. The stream is already gone, so nothing changes.
                return;
            },
            else => stream.state = .closed_reset,
        }
    }

    /// §6.9. Allowed in every state including closed, because credit granted for
    /// bytes already sent has to be accepted somewhere.
    pub fn onWindowUpdate(stream: *Stream, _: Direction) Error!void {
        switch (stream.state) {
            // §5.1: a WINDOW_UPDATE for a stream that has never existed is a
            // connection error — there is no window to credit.
            .idle => return error.ProtocolError,
            // §5.1 explicitly allows this "for a short period" after END_STREAM,
            // and permits but does not require treating a late one as an error.
            // Accepting it is the choice that cannot break a conforming peer.
            else => {},
        }
    }

    /// §6.3. Permitted in any state, including idle and closed: priority
    /// information is about a stream that may not exist yet or any more.
    pub fn onPriority(_: *Stream, _: Direction) Error!void {}

    fn endStream(stream: *Stream, direction: Direction) Error!void {
        switch (stream.state) {
            .open => stream.state = switch (direction) {
                .local => .half_closed_local,
                .remote => .half_closed_remote,
            },
            .half_closed_local => {
                assert(direction == .remote);
                stream.state = .closed_complete;
            },
            .half_closed_remote => {
                assert(direction == .local);
                stream.state = .closed_complete;
            },
            else => unreachable,
        }
    }
};

/// Bounds `RST_STREAM` frames per unit of time, which is the shape CVE-2023-44487
/// forced on every implementation.
///
/// The attack — Rapid Reset — is to open a stream, immediately reset it, and
/// repeat. Each request is dispatched and each stream is then abandoned, so the
/// server does the work and the client pays almost nothing. What makes it work is
/// that §5.1.2 counts only open and half-closed streams against
/// `SETTINGS_MAX_CONCURRENT_STREAMS`, so a reset stream frees its slot at once and
/// the concurrency limit — the obvious defence — never engages.
///
/// The mechanism is `limits.RateLimiter`, shared with the control-frame floods,
/// which have a different cause and the same answer.
pub const ResetLimiter = limits.RateLimiter;

/// The live streams of one connection, plus the identifier rules of §5.1.1.
///
/// Closed streams are removed rather than remembered, so `highest_remote` and
/// `highest_local` carry the part of history that still matters: §5.1.1 requires
/// identifiers to increase, which is what lets a receiver tell "a stream I have
/// forgotten because it closed" from "a stream that never existed".
pub const Registry = struct {
    /// Whether this endpoint is the server, which decides identifier parity.
    is_server: bool,
    streams: std.AutoHashMapUnmanaged(u31, Stream) = .empty,
    /// Highest identifier the peer has opened, and the highest we have.
    highest_remote: u31 = 0,
    highest_local: u31 = 0,
    resets: ResetLimiter = .{},
    /// §5.1.2, as the peer announced it. Absent means unlimited, so a ceiling of
    /// our own is applied regardless; see `Options`.
    peer_max_concurrent: ?u32 = null,
    /// The initial window sizes in force, which `SETTINGS` may change.
    initial_send_window: u31 = frame.default_initial_window_size,
    initial_recv_window: u31 = frame.default_initial_window_size,
    options: Options = .{},

    pub const Options = struct {
        /// What this endpoint announces as `SETTINGS_MAX_CONCURRENT_STREAMS`, and
        /// enforces on the peer. §6.5.2 lets this be absent, meaning unlimited;
        /// it is not optional here, because "unlimited" is not a thing this
        /// codebase offers.
        max_concurrent_streams: u32 = 128,
        resets: ResetLimiter = .{},
        sends: flow.SendQueue.Limits = .{},
    };

    pub fn init(is_server: bool, options: Options) Registry {
        return .{ .is_server = is_server, .options = options, .resets = options.resets };
    }

    pub fn deinit(registry: *Registry, gpa: Allocator) void {
        var iterator = registry.streams.valueIterator();
        while (iterator.next()) |stream| stream.deinit(gpa);
        registry.streams.deinit(gpa);
        registry.* = undefined;
    }

    pub fn get(registry: *Registry, id: u31) ?*Stream {
        return registry.streams.getPtr(id);
    }

    /// How many streams count towards the concurrency limit (§5.1.2).
    pub fn concurrentCount(registry: *const Registry) u32 {
        var total: u32 = 0;
        var iterator = registry.streams.valueIterator();
        while (iterator.next()) |stream| {
            if (stream.state.isConcurrent()) total += 1;
        }
        return total;
    }

    /// Whether `id` was opened by the peer, from its parity (§5.1.1): clients use
    /// odd identifiers, servers even.
    pub fn isRemoteInitiated(registry: *const Registry, id: u31) bool {
        const odd = id % 2 == 1;
        return if (registry.is_server) odd else !odd;
    }

    /// Registers a stream the peer is opening with `HEADERS`, applying §5.1.1 and
    /// the concurrency limit.
    pub fn openRemote(registry: *Registry, gpa: Allocator, id: u31) (Error || Allocator.Error)!*Stream {
        // §5.1.1: zero is the connection, not a stream.
        if (id == 0) return error.ProtocolError;
        // §5.1.1: parity is fixed by who opens the stream.
        if (!registry.isRemoteInitiated(id)) return error.ProtocolError;
        // §5.1.1: identifiers must increase. An identifier at or below the highest
        // seen is either a reuse or an attempt to revive a closed stream, and both
        // are connection errors — a receiver cannot distinguish them from a peer
        // that has lost track of the connection.
        if (id <= registry.highest_remote) return error.ProtocolError;

        // §5.1.2: over the limit is a stream error, and REFUSED_STREAM
        // specifically, because that is the code that tells the peer the request
        // was untouched and may be retried.
        if (registry.concurrentCount() >= registry.options.max_concurrent_streams) {
            // The identifier is still consumed: the stream existed long enough to
            // be refused, and letting it be reused would break monotonicity.
            registry.highest_remote = id;
            return error.RefusedStream;
        }

        registry.highest_remote = id;
        return registry.create(gpa, id);
    }

    /// Registers a stream this endpoint is opening.
    pub fn openLocal(registry: *Registry, gpa: Allocator, id: u31) (Error || Allocator.Error)!*Stream {
        assert(id != 0);
        assert(!registry.isRemoteInitiated(id));
        assert(id > registry.highest_local);
        if (registry.peer_max_concurrent) |limit| {
            if (registry.concurrentCount() >= limit) return error.RefusedStream;
        }
        registry.highest_local = id;
        return registry.create(gpa, id);
    }

    fn create(registry: *Registry, gpa: Allocator, id: u31) Allocator.Error!*Stream {
        const entry = try registry.streams.getOrPut(gpa, id);
        assert(!entry.found_existing);
        entry.value_ptr.* = .{
            .id = id,
            // The windows start at whatever each side announced, not at the
            // default: a peer that sent SETTINGS before this stream existed has
            // already changed the initial size for it.
            .send_window = .init(registry.initial_send_window),
            .recv_window = .init(registry.initial_recv_window),
            .sends = .init(registry.options.sends),
        };
        return entry.value_ptr;
    }

    /// The next identifier this endpoint may use.
    pub fn nextLocalId(registry: *const Registry) u31 {
        if (registry.highest_local == 0) return if (registry.is_server) 2 else 1;
        return registry.highest_local + 2;
    }

    /// Whether a frame naming `id` refers to a stream that has been closed and
    /// forgotten, as opposed to one that never existed. §5.1.1 makes the
    /// difference decidable purely from the identifier.
    pub fn wasClosed(registry: *const Registry, id: u31) bool {
        const highest = if (registry.isRemoteInitiated(id))
            registry.highest_remote
        else
            registry.highest_local;
        return id <= highest;
    }

    /// Drops a stream that has reached a closed state, releasing whatever it still
    /// had queued. A stream that is reset with bytes pending is the ordinary case.
    pub fn remove(registry: *Registry, gpa: Allocator, id: u31) void {
        if (registry.streams.getPtr(id)) |stream| stream.deinit(gpa);
        _ = registry.streams.remove(id);
    }

    /// §6.9.2: a new `SETTINGS_INITIAL_WINDOW_SIZE` from the peer shifts every
    /// existing stream's *send* window by the difference. Applying it to new
    /// streams alone would leave the two sides disagreeing about every stream
    /// already open.
    pub fn adjustSendWindows(registry: *Registry, old: u31, new: u31) flow.Error!void {
        const delta = @as(i64, new) - @as(i64, old);
        registry.initial_send_window = new;
        if (delta == 0) return;
        var iterator = registry.streams.valueIterator();
        while (iterator.next()) |stream| try stream.send_window.adjust(delta);
    }

    /// Records a reset for the rate limit. Returns `error.EnhanceYourCalm` when the
    /// peer is resetting faster than `ResetLimiter` allows.
    pub fn recordReset(registry: *Registry, now_ns: u64) Error!void {
        return registry.resets.record(now_ns);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "stream: the ordinary request and response walk of §5.1" {
    // A server's view of one exchange.
    var s: Stream = .{ .id = 1 };
    try testing.expectEqual(State.idle, s.state);

    // The request arrives, complete.
    try s.onHeaders(.remote, true);
    try testing.expectEqual(State.half_closed_remote, s.state);
    try testing.expect(s.state.isConcurrent());

    // The response goes out with a body.
    try s.onHeaders(.local, false);
    try testing.expectEqual(State.half_closed_remote, s.state);
    try s.onData(.local, false);
    try s.onData(.local, true);
    try testing.expectEqual(State.closed_complete, s.state);
    // §5.1.2 counts neither closed nor reserved streams, which is the gap Rapid
    // Reset exploited.
    try testing.expect(!s.state.isConcurrent());
}

test "stream: a request with a body half-closes in two steps" {
    var s: Stream = .{ .id = 1 };
    try s.onHeaders(.remote, false);
    try testing.expectEqual(State.open, s.state);
    try s.onData(.remote, false);
    try testing.expectEqual(State.open, s.state);
    try s.onData(.remote, true);
    try testing.expectEqual(State.half_closed_remote, s.state);
}

test "stream: server push reserves before it responds" {
    // The pushing side. §5.1: reserved_local, then sending HEADERS turns the
    // promise into a response, and the peer may never send on the stream at all.
    var pushed: Stream = .{ .id = 2 };
    try pushed.onPushPromise(.local);
    try testing.expectEqual(State.reserved_local, pushed.state);
    try testing.expect(!pushed.state.isConcurrent());
    // The peer cannot send HEADERS on a stream we reserved.
    try testing.expectError(error.ProtocolError, pushed.onHeaders(.remote, false));
    try pushed.onHeaders(.local, false);
    try testing.expectEqual(State.half_closed_remote, pushed.state);

    // The receiving side, mirrored.
    var promised: Stream = .{ .id = 2 };
    try promised.onPushPromise(.remote);
    try testing.expectEqual(State.reserved_remote, promised.state);
    try testing.expectError(error.ProtocolError, promised.onHeaders(.local, false));
    try promised.onHeaders(.remote, false);
    try testing.expectEqual(State.half_closed_local, promised.state);

    // §6.6: a PUSH_PROMISE only makes sense for a stream that does not exist yet.
    var busy: Stream = .{ .id = 4, .state = .open };
    try testing.expectError(error.ProtocolError, busy.onPushPromise(.remote));
}

test "stream: how a stream closed decides the severity of a late frame" {
    // This is the distinction the module comment argues for, and it is the whole
    // reason `closed` is two states rather than one.

    // Closed by RST_STREAM: a frame already in flight is an ordinary race, so it
    // is a *stream* error and the connection survives.
    {
        var s: Stream = .{ .id = 1, .state = .open };
        try s.onRstStream(.remote);
        try testing.expectEqual(State.closed_reset, s.state);
        try testing.expectError(error.StreamClosed, s.onData(.remote, false));
        try testing.expectError(error.StreamClosed, s.onHeaders(.remote, false));
        try testing.expectEqual(Severity.stream, severity(error.StreamClosed));
        try testing.expectEqual(frame.ErrorCode.stream_closed, errorCode(error.StreamClosed));
    }

    // Closed by END_STREAM from both sides: the peer said it was finished, so
    // anything after it means the two sides disagree, and that is fatal.
    {
        var s: Stream = .{ .id = 1, .state = .half_closed_local };
        try s.onData(.remote, true);
        try testing.expectEqual(State.closed_complete, s.state);
        try testing.expectError(error.StreamClosedFatal, s.onData(.remote, false));
        try testing.expectError(error.StreamClosedFatal, s.onHeaders(.remote, false));
        try testing.expectEqual(Severity.connection, severity(error.StreamClosedFatal));
        // The code on the wire is the same; only the blast radius differs.
        try testing.expectEqual(frame.ErrorCode.stream_closed, errorCode(error.StreamClosedFatal));
    }
}

test "stream: half-closed remote refuses the peer but not this side" {
    var s: Stream = .{ .id = 1, .state = .half_closed_remote };
    // §5.1: the peer has finished sending, so anything but WINDOW_UPDATE,
    // PRIORITY or RST_STREAM from it is a stream error.
    try testing.expectError(error.StreamClosed, s.onData(.remote, false));
    try testing.expectError(error.StreamClosed, s.onHeaders(.remote, false));
    try s.onWindowUpdate(.remote);
    try s.onPriority(.remote);
    // This side is still free to send.
    try s.onData(.local, false);
    try testing.expectEqual(State.half_closed_remote, s.state);
}

test "stream: half-closed local refuses this side but not the peer" {
    var s: Stream = .{ .id = 1, .state = .half_closed_local };
    try testing.expectError(error.ProtocolError, s.onData(.local, false));
    try s.onData(.remote, false);
    try testing.expectEqual(State.half_closed_local, s.state);
    // Trailers, then the end.
    try s.onHeaders(.remote, true);
    try testing.expectEqual(State.closed_complete, s.state);
}

test "stream: DATA before HEADERS belongs to nothing" {
    var s: Stream = .{ .id = 1 };
    try testing.expectError(error.ProtocolError, s.onData(.remote, false));
    try testing.expectEqual(Severity.connection, severity(error.ProtocolError));

    // Nor on a reserved stream, where no request has been sent either.
    var reserved: Stream = .{ .id = 2, .state = .reserved_remote };
    try testing.expectError(error.ProtocolError, reserved.onData(.remote, false));
}

test "stream: RST_STREAM is idempotent and tolerates the END_STREAM race" {
    // §6.4: for an idle stream it refers to nothing.
    var idle: Stream = .{ .id = 1 };
    try testing.expectError(error.ProtocolError, idle.onRstStream(.remote));

    // Two resets crossing on the wire is ordinary.
    var s: Stream = .{ .id = 1, .state = .open };
    try s.onRstStream(.local);
    try s.onRstStream(.remote);
    try testing.expectEqual(State.closed_reset, s.state);

    // §5.1 permits a RST_STREAM shortly after END_STREAM. Treating it as fatal
    // would punish the peer for timing it does not control.
    var finished: Stream = .{ .id = 1, .state = .closed_complete };
    try finished.onRstStream(.remote);
    try testing.expectEqual(State.closed_complete, finished.state);
}

test "stream: WINDOW_UPDATE is refused only on an idle stream" {
    var idle: Stream = .{ .id = 1 };
    // There is no window to credit.
    try testing.expectError(error.ProtocolError, idle.onWindowUpdate(.remote));

    // Everywhere else it is accepted, including after close: credit for bytes
    // already sent has to land somewhere, and §5.1 explicitly allows it.
    for ([_]State{
        .open,            .half_closed_local, .half_closed_remote,
        .reserved_local,  .reserved_remote,   .closed_reset,
        .closed_complete,
    }) |state| {
        var s: Stream = .{ .id = 1, .state = state };
        try s.onWindowUpdate(.remote);
        // PRIORITY is accepted from every state, idle included.
        try s.onPriority(.remote);
    }
    try idle.onPriority(.remote);
}

test "registry: §5.1.1 parity depends on which side we are" {
    const gpa = testing.allocator;

    var server: Registry = .init(true, .{});
    defer server.deinit(gpa);
    // A client opens odd streams, so odd is remote-initiated at a server.
    try testing.expect(server.isRemoteInitiated(1));
    try testing.expect(!server.isRemoteInitiated(2));
    _ = try server.openRemote(gpa, 1);
    try testing.expectError(error.ProtocolError, server.openRemote(gpa, 2));
    // A server's own streams — pushes — are even.
    try testing.expectEqual(@as(u31, 2), server.nextLocalId());

    var client: Registry = .init(false, .{});
    defer client.deinit(gpa);
    try testing.expect(client.isRemoteInitiated(2));
    try testing.expect(!client.isRemoteInitiated(1));
    try testing.expectEqual(@as(u31, 1), client.nextLocalId());
    _ = try client.openLocal(gpa, 1);
    try testing.expectEqual(@as(u31, 3), client.nextLocalId());

    // §5.1.1: zero is the connection, not a stream.
    try testing.expectError(error.ProtocolError, server.openRemote(gpa, 0));
}

test "registry: §5.1.1 identifiers must increase" {
    const gpa = testing.allocator;
    var registry: Registry = .init(true, .{});
    defer registry.deinit(gpa);

    _ = try registry.openRemote(gpa, 5);
    // Reuse, and going backwards. Neither is distinguishable from a peer that has
    // lost track of the connection, so both are connection errors.
    try testing.expectError(error.ProtocolError, registry.openRemote(gpa, 5));
    try testing.expectError(error.ProtocolError, registry.openRemote(gpa, 3));
    _ = try registry.openRemote(gpa, 7);

    // Which is what makes "closed and forgotten" decidable from the identifier
    // alone, without remembering every stream that ever existed.
    try testing.expect(registry.wasClosed(3));
    try testing.expect(registry.wasClosed(7));
    try testing.expect(!registry.wasClosed(9));
}

test "registry: §5.1.2 refuses rather than resets, and keeps the identifier" {
    const gpa = testing.allocator;
    var registry: Registry = .init(true, .{ .max_concurrent_streams = 2 });
    defer registry.deinit(gpa);

    const a = try registry.openRemote(gpa, 1);
    try a.onHeaders(.remote, false);
    const b = try registry.openRemote(gpa, 3);
    try b.onHeaders(.remote, false);
    try testing.expectEqual(@as(u32, 2), registry.concurrentCount());

    // REFUSED_STREAM specifically: it is the code that tells the peer the request
    // was not acted on and may be retried on another connection.
    try testing.expectError(error.RefusedStream, registry.openRemote(gpa, 5));
    try testing.expectEqual(Severity.stream, severity(error.RefusedStream));
    try testing.expectEqual(frame.ErrorCode.refused_stream, errorCode(error.RefusedStream));
    // The identifier is consumed even so, or monotonicity would break.
    try testing.expectError(error.ProtocolError, registry.openRemote(gpa, 5));

    // Finishing one frees a slot.
    try a.onRstStream(.remote);
    registry.remove(gpa, 1);
    try testing.expectEqual(@as(u32, 1), registry.concurrentCount());
    _ = try registry.openRemote(gpa, 7);
}

test "registry: a half-closed stream still counts against the limit" {
    const gpa = testing.allocator;
    var registry: Registry = .init(true, .{ .max_concurrent_streams = 1 });
    defer registry.deinit(gpa);

    // §5.1.2 counts open and both half-closed states — a request whose response
    // is still being written is very much occupying a slot.
    const s = try registry.openRemote(gpa, 1);
    try s.onHeaders(.remote, true);
    try testing.expectEqual(State.half_closed_remote, s.state);
    try testing.expectEqual(@as(u32, 1), registry.concurrentCount());
    try testing.expectError(error.RefusedStream, registry.openRemote(gpa, 3));
}

test "registry: Rapid Reset is bounded by rate, since the slot limit cannot see it" {
    const gpa = testing.allocator;
    var registry: Registry = .init(true, .{
        .max_concurrent_streams = 100,
        .resets = .{ .max_per_window = 3, .window_ns = 1_000_000_000 },
    });
    defer registry.deinit(gpa);

    // CVE-2023-44487: open, reset, repeat. Each stream frees its slot the moment
    // it is reset, so `max_concurrent_streams` never engages — which is exactly
    // why this needs a limit of a different shape.
    var id: u31 = 1;
    for (0..3) |_| {
        const s = try registry.openRemote(gpa, id);
        try s.onHeaders(.remote, false);
        try s.onRstStream(.remote);
        try registry.recordReset(0);
        registry.remove(gpa, id);
        id += 2;
    }
    try testing.expectEqual(@as(u32, 0), registry.concurrentCount());

    // The fourth reset inside the window is refused.
    try testing.expectError(error.EnhanceYourCalm, registry.recordReset(0));
    try testing.expectEqual(Severity.connection, severity(error.EnhanceYourCalm));
    try testing.expectEqual(frame.ErrorCode.enhance_your_calm, errorCode(error.EnhanceYourCalm));

    // The window moves on, and a peer that resets occasionally is unaffected.
    try registry.recordReset(1_000_000_000);
    try registry.recordReset(1_000_000_001);
}
