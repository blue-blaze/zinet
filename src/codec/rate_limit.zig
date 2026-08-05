//! A rate limit over a sliding window, shared by the protocols that need one.
//!
//! Every other limit in Zinet is a ceiling on a quantity: this buffer holds at
//! most N bytes, this queue at most N entries. Those work because the resource is
//! held. Some attacks hold nothing — an HTTP/2 `RST_STREAM` frees its stream's
//! slot immediately, a QUIC packet addressed to a connection ID nobody knows is
//! answered and forgotten — and what they consume is *work*, which is only
//! bounded per unit of time.
//!
//! This lives here rather than inside one protocol because two of them now want
//! it, and the alternative was a second copy of a sliding window. What does *not*
//! live here is what to do when the limit is reached: HTTP/2 answers
//! `ENHANCE_YOUR_CALM`, QUIC's stateless reset simply is not sent. Those are
//! protocol decisions and stay with their protocols.
//!
//! Time is injected rather than read, in keeping with the rest of the framework:
//! the caller has an `Io` and passes a timestamp in.

const std = @import("std");

pub const Window = struct {
    start_ns: u64 = 0,
    count: u32 = 0,
    started: bool = false,

    /// Record one event and report whether it is within the limit.
    ///
    /// The limit and the window are parameters rather than fields because each
    /// caller already keeps its configuration somewhere the caller can explain —
    /// HTTP/2 in its limiter's own tunables, the HTTP/3 server in its options —
    /// and copying them in here would make two places able to disagree.
    pub fn allow(window: *Window, now_ns: u64, max_per_window: u32, window_ns: u64) bool {
        // Saturating subtraction, so a clock that goes backwards cannot produce a
        // huge elapsed time and open the gate. A monotonic clock should not go
        // backwards; this does not depend on that being true.
        if (!window.started or now_ns -| window.start_ns >= window_ns) {
            window.started = true;
            window.start_ns = now_ns;
            window.count = 0;
        }
        window.count += 1;
        return window.count <= max_per_window;
    }
};

const testing = std.testing;

test "rate limit: the window refills rather than counting for ever" {
    var window: Window = .{};

    try testing.expect(window.allow(1_000, 2, 100));
    try testing.expect(window.allow(1_050, 2, 100));
    try testing.expect(!window.allow(1_099, 2, 100));
    // A new window starts at the first event past the end of the old one.
    try testing.expect(window.allow(1_100, 2, 100));
    try testing.expect(window.allow(1_150, 2, 100));
    try testing.expect(!window.allow(1_199, 2, 100));
}

test "rate limit: a clock that goes backwards does not open the gate" {
    var window: Window = .{};
    try testing.expect(window.allow(1_000, 1, 100));
    // Earlier than the window's start. Saturating arithmetic makes the elapsed
    // time zero rather than enormous, so the window does not reset.
    try testing.expect(!window.allow(500, 1, 100));
}
