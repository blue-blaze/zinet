//! Flow control and the write scheduler: RFC 9113 §5.2, §6.9 and §6.9.2.
//!
//! ## Only `DATA` is flow-controlled, and all of it is
//!
//! §6.9 subjects `DATA` frames and nothing else to flow control. `HEADERS`,
//! `SETTINGS`, `RST_STREAM` and the rest are never blocked by a window, which is
//! deliberate: a connection whose windows are exhausted must still be able to open
//! streams, reset them and say goodbye, or the protocol would have no way to
//! recover from being blocked.
//!
//! And §6.1 charges the *whole* `DATA` payload, "including the Pad Length and
//! Padding fields if present". So the number charged here is larger than the
//! number the application sees. Getting that wrong is invisible until a peer pads
//! its frames, at which point the two sides' windows drift apart and the
//! connection stalls with neither side at fault.
//!
//! ## Why a window is signed
//!
//! §6.9.2: changing `SETTINGS_INITIAL_WINDOW_SIZE` shifts every existing stream's
//! window by the difference, and the RFC says outright that this "can cause the
//! available space in a flow-control window to become negative". A negative window
//! is not an error — it means the sender has already sent bytes it is no longer
//! entitled to and must wait for a `WINDOW_UPDATE` covering the shortfall.
//!
//! ## Why the writer must never wait on a window
//!
//! This is the constraint that decides the shape of everything above, and it is
//! the one HTTP2.md §3 argued out before any of this was written. Zinet's ordinary
//! backpressure blocks the producer on a bounded queue, which is safe when a
//! connection carries one exchange. HTTP/2 carries many that share a credit pool,
//! and there the same move deadlocks: a writer blocked because one stream's window
//! is exhausted is a writer that is not sending *anything* — including on streams
//! that still have credit, and including the frames the peer is waiting for before
//! it will send the `WINDOW_UPDATE` that would release the block. The thing that
//! unblocks the writer can only arrive if the writer is not blocked.
//!
//! So a stream with no credit is parked and the scheduler moves on. That is what
//! `Scheduler` is for, and it is why a stream's pending bytes have to be bounded
//! somewhere the application can see rather than by blocking it — the water mark
//! decision, which is the next piece.

const std = @import("std");
const assert = std.debug.assert;

const frame = @import("frame.zig");

pub const Error = error{
    /// §6.9.1: a window would exceed 2^31-1, or more `DATA` arrived than the
    /// receive window allowed.
    ///
    /// Severity is the caller's to decide and depends on which window overflowed:
    /// §6.9.1 makes it a *connection* error for the connection window and a
    /// *stream* error for a stream's, since one stream miscounting need not end
    /// everything.
    FlowControlError,
};

/// The largest a window may be, and the largest a `WINDOW_UPDATE` may make it
/// (§6.9.1).
pub const max_window: i64 = frame.max_window_size;

/// One direction of one window: either the connection's or a single stream's.
pub const Window = struct {
    /// Signed and wider than 31 bits, because §6.9.2 permits a negative value and
    /// the intermediate arithmetic has to be able to represent an overflow in
    /// order to reject it.
    available: i64,

    pub fn init(initial: u31) Window {
        return .{ .available = initial };
    }

    /// Whether anything may be sent at all right now.
    pub fn isBlocked(window: Window) bool {
        return window.available <= 0;
    }

    /// How much may be sent, capped by `limit`. Zero when the window is blocked,
    /// including when it is negative.
    pub fn allows(window: Window, limit: u32) u32 {
        if (window.available <= 0) return 0;
        return @intCast(@min(window.available, @as(i64, limit)));
    }

    /// Charges `n` bytes of outbound `DATA`. Asserted rather than fallible: this
    /// side chose to send, so exceeding its own window is a bug here, not a
    /// protocol violation by anyone.
    pub fn send(window: *Window, n: u32) void {
        assert(@as(i64, n) <= window.available);
        window.available -= n;
    }

    /// Charges `n` bytes of inbound `DATA`, which is the whole payload including
    /// padding. Fallible, because overrunning the window is exactly the peer's
    /// fault and §6.9.1 requires it be reported.
    pub fn receive(window: *Window, n: u32) Error!void {
        if (@as(i64, n) > window.available) return error.FlowControlError;
        window.available -= n;
        return;
    }

    /// §6.9: applies a `WINDOW_UPDATE`. The increment has already been checked to
    /// be non-zero by the frame layer; what is checked here is the ceiling.
    pub fn increase(window: *Window, increment: u31) Error!void {
        assert(increment > 0);
        const next = window.available + increment;
        if (next > max_window) return error.FlowControlError;
        window.available = next;
    }

    /// §6.9.2: a new `SETTINGS_INITIAL_WINDOW_SIZE` shifts this window by the
    /// difference from the old one. Only the upper bound is checked; a negative
    /// result is legal and means the sender is in arrears.
    pub fn adjust(window: *Window, delta: i64) Error!void {
        const next = window.available + delta;
        if (next > max_window) return error.FlowControlError;
        window.available = next;
    }
};

/// A stream with bytes waiting and a window that may or may not permit sending
/// them. `window` is borrowed so that `Scheduler.run` can charge it, which keeps
/// the two windows charged together or not at all.
pub const Candidate = struct {
    stream_id: u31,
    /// Bytes queued for this stream, already framed or not; the scheduler only
    /// needs to know how many there are.
    pending: u32,
    window: *Window,
};

/// One slice of the connection's write budget, granted to one stream.
pub const Allocation = struct {
    stream_id: u31,
    bytes: u32,
};

/// Decides which stream sends next, and how much.
///
/// The policy is round robin with a per-pass cap of one frame each. Both halves
/// matter. Round robin is what stops a stream that always has data from starving
/// one that occasionally does. The per-pass cap is what stops a large body from
/// sitting in front of another stream's data: a megabyte on one stream becomes
/// sixty-four frames interleaved with everyone else's, rather than sixty-four
/// frames back to back.
///
/// Netty reaches the same place with a pluggable `Http2RemoteFlowController` whose
/// default is weighted fair queueing over the priority tree. This is the same idea
/// with the priority tree left out, which RFC 9113 §5.3.1 deprecated anyway.
pub const Scheduler = struct {
    /// The stream served last, so the next pass begins after it. Held as an
    /// identifier rather than an index because the candidate list changes between
    /// passes as streams open and close.
    last_served: u31 = 0,

    /// Grants budget to as many candidates as `out` holds, in fair order.
    /// Returns the allocations written. Charges both the connection window and
    /// each stream's, so what it returns is already paid for.
    pub fn run(
        scheduler: *Scheduler,
        connection: *Window,
        candidates: []const Candidate,
        max_frame_size: u24,
        out: []Allocation,
    ) []Allocation {
        assert(max_frame_size > 0);
        var written: usize = 0;
        if (candidates.len == 0) return out[0..0];

        // Begin after the stream served last. Candidates are not required to be
        // sorted, so this is a scan rather than a search; the list is bounded by
        // the concurrency limit and this runs once per write pass.
        var start: usize = 0;
        for (candidates, 0..) |candidate, index| {
            if (candidate.stream_id > scheduler.last_served) {
                start = index;
                break;
            }
        }

        var offset: usize = 0;
        while (offset < candidates.len and written < out.len) : (offset += 1) {
            if (connection.isBlocked()) break;
            const candidate = candidates[(start + offset) % candidates.len];
            if (candidate.pending == 0) continue;

            // A stream with no credit is skipped, not waited on. This one line is
            // the deadlock argument: waiting here would stop the writes that
            // produce the WINDOW_UPDATE this stream needs.
            const by_stream = candidate.window.allows(candidate.pending);
            if (by_stream == 0) continue;

            const grant = connection.allows(@min(by_stream, max_frame_size));
            if (grant == 0) break;

            candidate.window.send(grant);
            connection.send(grant);
            out[written] = .{ .stream_id = candidate.stream_id, .bytes = grant };
            written += 1;
            scheduler.last_served = candidate.stream_id;
        }
        return out[0..written];
    }
};

// -- Backpressure ----------------------------------------------------------

/// Where writability turns off, and where it comes back.
///
/// The gap between the two is the point. A single threshold makes writability flap
/// on every write once the queue sits near it, so the application is told to stop
/// and start again thousands of times; Netty's `WriteBufferWaterMark` exists for
/// the same reason and defaults to the same 32/64 KiB shape.
pub const WaterMark = struct {
    /// At or above this many pending bytes, the stream reports unwritable.
    high: u32 = 64 * 1024,
    /// Writability returns when pending falls to this or below.
    low: u32 = 32 * 1024,

    pub fn validate(marks: WaterMark) void {
        assert(marks.low < marks.high);
    }
};

/// What changed about writability, so the caller can fire an event on the edges
/// rather than on every write.
pub const Transition = enum { unchanged, became_unwritable, became_writable };

/// The pending-byte accounting for one stream's send side, and the one place
/// HTTP/2 departs from how the rest of this framework applies backpressure.
///
/// ## Two models, and where the boundary is
///
/// Everywhere else, Zinet's outbound queue is bounded and **blocks the producer**;
/// write water marks are listed in the README under "deliberately absent" because
/// blocking is backpressure that cannot be ignored. That argument is sound and it
/// is specifically about a connection carrying one exchange.
///
/// It does not survive HTTP/2, and `Scheduler` above explains why: with many
/// exchanges sharing one credit pool, blocking a producer on an exhausted window
/// deadlocks the connection. So a stream that cannot send has to *return* to its
/// caller, which means its pending bytes accumulate, which means the application
/// has to be told to stop rather than stopped.
///
/// The boundary is therefore: **blocking where one exchange owns the connection,
/// water marks where many share it.** Not a preference — a consequence of whether
/// the thing that would unblock the producer can arrive while it is blocked.
///
/// ## Why there is a hard ceiling as well
///
/// Netty's write queue is unbounded, so its water marks are the only defence, and
/// an application that ignores them is simply misbehaving. Nothing in this
/// codebase is unbounded and HTTP/2 is not going to be the exception, so the water
/// marks are *advice* — an application that heeds them never sees the ceiling —
/// and `max_pending` is the *rule*. Exceeding it fails the write.
pub const SendQueue = struct {
    limits: Limits = .{},
    /// Bytes accepted from the application and not yet granted by the scheduler.
    pending: u32 = 0,
    writable: bool = true,

    pub const Limits = struct {
        marks: WaterMark = .{},
        /// The ceiling that is not negotiable. Reaching it fails the write rather
        /// than growing the queue.
        max_pending: u32 = 256 * 1024,
    };

    /// Named apart from this module's `Error`, which is about flow control. These
    /// are unrelated failures: one is the peer miscounting, this is us refusing.
    pub const WriteError = error{
        /// `max_pending` would be exceeded. Distinct from unwritability: this is
        /// what happens to an application that carried on regardless.
        StreamWriteQueueFull,
    };

    pub fn init(limits: Limits) SendQueue {
        limits.marks.validate();
        assert(limits.max_pending >= limits.marks.high);
        return .{ .limits = limits };
    }

    /// Accepts `n` more bytes for sending.
    pub fn add(queue: *SendQueue, n: u32) WriteError!Transition {
        const next = std.math.add(u32, queue.pending, n) catch
            return error.StreamWriteQueueFull;
        if (next > queue.limits.max_pending) return error.StreamWriteQueueFull;
        queue.pending = next;
        return queue.reassess();
    }

    /// Records bytes the scheduler has taken and handed to the connection.
    pub fn drained(queue: *SendQueue, n: u32) Transition {
        assert(n <= queue.pending);
        queue.pending -= n;
        return queue.reassess();
    }

    fn reassess(queue: *SendQueue) Transition {
        if (queue.writable and queue.pending >= queue.limits.marks.high) {
            queue.writable = false;
            return .became_unwritable;
        }
        if (!queue.writable and queue.pending <= queue.limits.marks.low) {
            queue.writable = true;
            return .became_writable;
        }
        return .unchanged;
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "window: the default is what §6.5.2 says, and sending draws it down" {
    var window: Window = .init(frame.default_initial_window_size);
    try testing.expectEqual(@as(i64, 65_535), window.available);
    try testing.expect(!window.isBlocked());

    window.send(1_000);
    try testing.expectEqual(@as(i64, 64_535), window.available);
    try testing.expectEqual(@as(u32, 64_535), window.allows(std.math.maxInt(u32)));
    // `allows` is what a caller uses to size a frame, so it caps rather than
    // reporting the whole window.
    try testing.expectEqual(@as(u32, 16_384), window.allows(16_384));
}

test "window: receiving more than the window allows is the peer's fault" {
    var window: Window = .init(100);
    try window.receive(60);
    try testing.expectEqual(@as(i64, 40), window.available);

    // §6.9.1: exceeding it is reported rather than clamped. The window is left
    // where it was, since the frame is not being accepted.
    try testing.expectError(error.FlowControlError, window.receive(41));
    try testing.expectEqual(@as(i64, 40), window.available);

    // Exactly the remainder is fine, and leaves the window shut.
    try window.receive(40);
    try testing.expect(window.isBlocked());
    try testing.expectEqual(@as(u32, 0), window.allows(1));
    // Zero-length DATA is always allowed, even with the window shut: it carries no
    // bytes, and it is how END_STREAM arrives when there is no body left.
    try window.receive(0);
}

test "window: WINDOW_UPDATE has a ceiling of 2^31-1" {
    var window: Window = .init(0);
    try window.increase(frame.max_window_size);
    try testing.expectEqual(max_window, window.available);

    // §6.9.1: taking it above 2^31-1 is a flow control error, which is how a peer
    // that has lost count is caught rather than silently wrapping.
    try testing.expectError(error.FlowControlError, window.increase(1));

    // From a negative window, an increment that only pays off the arrears is fine.
    var arrears: Window = .{ .available = -100 };
    try arrears.increase(60);
    try testing.expectEqual(@as(i64, -40), arrears.available);
    try testing.expect(arrears.isBlocked());
    try arrears.increase(40);
    try testing.expect(arrears.isBlocked());
    try arrears.increase(1);
    try testing.expect(!arrears.isBlocked());
}

test "window: §6.9.2 lets a settings change push a window negative" {
    // A peer that advertised 65535, saw us send 60000, then lowers the initial
    // window size to 1000. The delta is -64535, and the window goes negative: we
    // have already sent bytes we are no longer entitled to.
    var window: Window = .init(65_535);
    window.send(60_000);
    try testing.expectEqual(@as(i64, 5_535), window.available);

    try window.adjust(@as(i64, 1_000) - 65_535);
    try testing.expectEqual(@as(i64, -59_000), window.available);
    // Not an error — a legal state that means "wait for credit".
    try testing.expect(window.isBlocked());
    try testing.expectEqual(@as(u32, 0), window.allows(1));

    // Raising it again is bounded by the same ceiling.
    var high: Window = .init(frame.max_window_size);
    try testing.expectError(error.FlowControlError, high.adjust(1));
}

test "flow control charges padding, which the application never sees" {
    // §6.1: "The entire DATA frame payload is included in flow control, including
    // the Pad Length and Padding fields". So the number charged is the frame's
    // length, not the length of the data delivered upstream.
    const payload = "\x04hello\x00\x00\x00\x00"; // pad length 4, five bytes of data
    const flags: frame.Flags = .{ .bits = frame.Flags.padded };
    const delivered = try frame.stripPadding(payload, flags);
    try testing.expectEqualStrings("hello", delivered);

    // A window between the two lengths is what makes the difference visible.
    try testing.expectEqual(@as(usize, 10), payload.len);
    try testing.expectEqual(@as(usize, 5), delivered.len);

    var window: Window = .init(7);
    try testing.expectError(error.FlowControlError, window.receive(@intCast(payload.len)));

    // And the wrong number would have been accepted, leaving the two sides'
    // windows five bytes apart and a connection that stalls with neither side at
    // fault. That is the whole reason this is worth a test rather than a comment.
    var mistaken: Window = .init(7);
    try mistaken.receive(@intCast(delivered.len));
}

test "scheduler: a blocked stream is stepped over, not waited on" {
    // This is the deadlock argument as a test. Stream 1 has data and no credit;
    // stream 3 has both. If the writer waited on stream 1, stream 3 would never
    // send — and the WINDOW_UPDATE that would free stream 1 arrives only in
    // response to what stream 3 is trying to send.
    var connection: Window = .init(65_535);
    var blocked: Window = .init(0);
    var open: Window = .init(1_000);

    var scheduler: Scheduler = .{};
    var out: [4]Allocation = undefined;
    const granted = scheduler.run(&connection, &.{
        .{ .stream_id = 1, .pending = 5_000, .window = &blocked },
        .{ .stream_id = 3, .pending = 5_000, .window = &open },
    }, 16_384, &out);

    try testing.expectEqual(@as(usize, 1), granted.len);
    try testing.expectEqual(@as(u31, 3), granted[0].stream_id);
    try testing.expectEqual(@as(u32, 1_000), granted[0].bytes);
    // Stream 1's window is untouched: nothing was taken from a window that had
    // nothing to give.
    try testing.expectEqual(@as(i64, 0), blocked.available);
    try testing.expectEqual(@as(i64, 64_535), connection.available);
}

test "scheduler: one frame per stream per pass, so a large body interleaves" {
    // A megabyte on stream 1 must not sit in front of stream 3's bytes. Capping
    // each stream at one frame per pass is what turns it into sixty-four frames
    // interleaved with everyone else rather than sixty-four back to back.
    var connection: Window = .init(frame.max_window_size);
    var one: Window = .init(frame.max_window_size);
    var three: Window = .init(frame.max_window_size);

    var scheduler: Scheduler = .{};
    var out: [8]Allocation = undefined;
    const granted = scheduler.run(&connection, &.{
        .{ .stream_id = 1, .pending = 1_000_000, .window = &one },
        .{ .stream_id = 3, .pending = 1_000_000, .window = &three },
    }, 16_384, &out);

    try testing.expectEqual(@as(usize, 2), granted.len);
    try testing.expectEqual(@as(u31, 1), granted[0].stream_id);
    try testing.expectEqual(@as(u32, 16_384), granted[0].bytes);
    try testing.expectEqual(@as(u31, 3), granted[1].stream_id);
    try testing.expectEqual(@as(u32, 16_384), granted[1].bytes);
}

test "scheduler: round robin, so a chatty stream cannot starve a quiet one" {
    var connection: Window = .init(frame.max_window_size);
    var one: Window = .init(frame.max_window_size);
    var three: Window = .init(frame.max_window_size);
    var five: Window = .init(frame.max_window_size);

    const candidates = [_]Candidate{
        .{ .stream_id = 1, .pending = 1_000_000, .window = &one },
        .{ .stream_id = 3, .pending = 1_000_000, .window = &three },
        .{ .stream_id = 5, .pending = 1_000_000, .window = &five },
    };

    // One allocation per pass, which is the worst case for fairness: whoever the
    // pass starts with is the only one served.
    var scheduler: Scheduler = .{};
    var out: [1]Allocation = undefined;
    var served: [6]u31 = undefined;
    for (&served) |*slot| {
        const granted = scheduler.run(&connection, &candidates, 16_384, &out);
        try testing.expectEqual(@as(usize, 1), granted.len);
        slot.* = granted[0].stream_id;
    }
    // Each stream gets its turn, in order, twice round.
    try testing.expectEqualSlices(u31, &.{ 1, 3, 5, 1, 3, 5 }, &served);
}

test "scheduler: the connection window is the shared budget" {
    // Two streams with generous windows of their own, and a connection window that
    // only covers one and a half frames. The connection window is what gets
    // divided, and the pass stops when it runs out.
    var connection: Window = .init(24_000);
    var one: Window = .init(frame.max_window_size);
    var three: Window = .init(frame.max_window_size);

    var scheduler: Scheduler = .{};
    var out: [4]Allocation = undefined;
    const granted = scheduler.run(&connection, &.{
        .{ .stream_id = 1, .pending = 100_000, .window = &one },
        .{ .stream_id = 3, .pending = 100_000, .window = &three },
    }, 16_384, &out);

    try testing.expectEqual(@as(usize, 2), granted.len);
    try testing.expectEqual(@as(u32, 16_384), granted[0].bytes);
    // The second stream gets what is left rather than a full frame.
    try testing.expectEqual(@as(u32, 7_616), granted[1].bytes);
    try testing.expect(connection.isBlocked());

    // A further pass grants nothing at all, and touches no stream window.
    const again = scheduler.run(&connection, &.{
        .{ .stream_id = 1, .pending = 100_000, .window = &one },
        .{ .stream_id = 3, .pending = 100_000, .window = &three },
    }, 16_384, &out);
    try testing.expectEqual(@as(usize, 0), again.len);
}

test "scheduler: nothing pending, nothing granted" {
    var connection: Window = .init(65_535);
    var one: Window = .init(65_535);
    var scheduler: Scheduler = .{};
    var out: [4]Allocation = undefined;

    try testing.expectEqual(@as(usize, 0), scheduler.run(&connection, &.{}, 16_384, &out).len);
    try testing.expectEqual(@as(usize, 0), scheduler.run(&connection, &.{
        .{ .stream_id = 1, .pending = 0, .window = &one },
    }, 16_384, &out).len);
    try testing.expectEqual(@as(i64, 65_535), connection.available);
}

test "scheduler: a stream in arrears from a settings change waits its turn out" {
    // §6.9.2 can leave a window negative. `allows` returns zero for that, so the
    // stream is parked exactly like one at zero — and once credit covers the
    // arrears it resumes.
    var connection: Window = .init(65_535);
    var arrears: Window = .{ .available = -500 };

    var scheduler: Scheduler = .{};
    var out: [2]Allocation = undefined;
    const candidates = [_]Candidate{
        .{ .stream_id = 1, .pending = 1_000, .window = &arrears },
    };
    try testing.expectEqual(@as(usize, 0), scheduler.run(&connection, &candidates, 16_384, &out).len);

    try arrears.increase(500);
    try testing.expectEqual(@as(usize, 0), scheduler.run(&connection, &candidates, 16_384, &out).len);

    try arrears.increase(300);
    const granted = scheduler.run(&connection, &candidates, 16_384, &out);
    try testing.expectEqual(@as(usize, 1), granted.len);
    try testing.expectEqual(@as(u32, 300), granted[0].bytes);
}

test "backpressure: the water marks have a gap so writability cannot flap" {
    var queue: SendQueue = .init(.{ .marks = .{ .high = 100, .low = 40 } });
    try testing.expect(queue.writable);

    try testing.expectEqual(Transition.unchanged, try queue.add(99));
    try testing.expect(queue.writable);
    try testing.expectEqual(Transition.became_unwritable, try queue.add(1));
    try testing.expect(!queue.writable);

    // Draining back to just above the low mark does not restore writability. With
    // a single threshold this is where the application would be told to start,
    // and then told to stop again on its very next write — thousands of times over
    // for a queue that sits near the line.
    try testing.expectEqual(Transition.unchanged, queue.drained(59));
    try testing.expectEqual(@as(u32, 41), queue.pending);
    try testing.expect(!queue.writable);

    try testing.expectEqual(Transition.became_writable, queue.drained(1));
    try testing.expect(queue.writable);

    // And the edges are reported once each, not on every call.
    try testing.expectEqual(Transition.unchanged, try queue.add(59));
    try testing.expectEqual(Transition.became_unwritable, try queue.add(1));
    try testing.expectEqual(Transition.unchanged, try queue.add(1));
}

test "backpressure: the water marks are advice, the ceiling is the rule" {
    // An application that heeds the mark never reaches the ceiling. This one does
    // not, which is the case Netty's unbounded queue answers by growing and this
    // one answers by refusing.
    var queue: SendQueue = .init(.{
        .marks = .{ .high = 100, .low = 40 },
        .max_pending = 200,
    });

    try testing.expectEqual(Transition.became_unwritable, try queue.add(150));
    try testing.expect(!queue.writable);
    // Still accepted: unwritable is a request, not a refusal.
    try testing.expectEqual(Transition.unchanged, try queue.add(50));
    try testing.expectEqual(@as(u32, 200), queue.pending);

    // The ceiling is where it stops being a request.
    try testing.expectError(error.StreamWriteQueueFull, queue.add(1));
    try testing.expectEqual(@as(u32, 200), queue.pending);

    // Overflow of the counter itself is the same answer rather than a wrap.
    var wide: SendQueue = .init(.{ .max_pending = std.math.maxInt(u32) });
    _ = try wide.add(std.math.maxInt(u32) - 1);
    try testing.expectError(error.StreamWriteQueueFull, wide.add(2));
}

test "backpressure: a parked stream is what fills the queue, and draining frees it" {
    // The two halves joined up: a stream with no credit is skipped by the
    // scheduler, so its queue grows until the water mark reports it — and a
    // WINDOW_UPDATE is what eventually drains it.
    var connection: Window = .init(frame.max_window_size);
    var window: Window = .init(0);
    var queue: SendQueue = .init(.{ .marks = .{ .high = 4_000, .low = 1_000 } });

    try testing.expectEqual(Transition.unchanged, try queue.add(3_000));
    try testing.expectEqual(Transition.became_unwritable, try queue.add(2_000));

    var scheduler: Scheduler = .{};
    var out: [2]Allocation = undefined;
    // Nothing moves while the window is shut, and the application has been told.
    try testing.expectEqual(@as(usize, 0), scheduler.run(&connection, &.{
        .{ .stream_id = 1, .pending = queue.pending, .window = &window },
    }, 16_384, &out).len);
    try testing.expect(!queue.writable);

    try window.increase(5_000);
    const granted = scheduler.run(&connection, &.{
        .{ .stream_id = 1, .pending = queue.pending, .window = &window },
    }, 16_384, &out);
    try testing.expectEqual(@as(u32, 5_000), granted[0].bytes);
    try testing.expectEqual(Transition.became_writable, queue.drained(granted[0].bytes));
    try testing.expectEqual(@as(u32, 0), queue.pending);
}
