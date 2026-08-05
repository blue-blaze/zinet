//! HTTP/2's rate limit, which is to say: what HTTP/2 does when a peer exceeds one.
//!
//! The sliding window itself is in `codec/rate_limit.zig`, because QUIC's
//! stateless reset needs the same mechanism (§10.3.3) and one window written twice
//! is one window that can drift. What stays here is the part that is HTTP/2: the
//! defaults, which came from Netty's `RST_STREAM` limits, and the error code —
//! `ENHANCE_YOUR_CALM` is the answer this protocol gives, where QUIC's answer is
//! to send nothing at all.
//!
//! Why a rate limit at all, when every other bound in Zinet is a ceiling on a
//! quantity: HTTP/2's cheapest attacks hold nothing. A `RST_STREAM` frees its
//! stream's slot immediately, a `PING` is answered and forgotten, an empty `DATA`
//! frame occupies no memory. What they consume is *work*, and work is only bounded
//! per unit of time.

const std = @import("std");

const rate_limit = @import("../rate_limit.zig");

pub const Error = error{
    /// The peer exceeded the rate. Answered with `ENHANCE_YOUR_CALM`, which is the
    /// code that says "you are within your rights and doing too much of it".
    EnhanceYourCalm,
};

pub const RateLimiter = struct {
    /// Netty's `RST_STREAM` defaults, which is where this shape came from and the
    /// closest thing to a community consensus. Other users override them.
    max_per_window: u32 = 200,
    window_ns: u64 = 30 * std.time.ns_per_s,

    window: rate_limit.Window = .{},

    pub fn record(limiter: *RateLimiter, now_ns: u64) Error!void {
        if (!limiter.window.allow(now_ns, limiter.max_per_window, limiter.window_ns)) {
            return error.EnhanceYourCalm;
        }
    }
};

const testing = std.testing;

test "rate limiter: the window refills rather than counting for ever" {
    var limiter: RateLimiter = .{ .max_per_window = 2, .window_ns = 100 };

    try limiter.record(1_000);
    try limiter.record(1_050);
    try testing.expectError(error.EnhanceYourCalm, limiter.record(1_099));
    // A new window starts at the first record past the end of the old one.
    try limiter.record(1_100);
    try limiter.record(1_150);
    try testing.expectError(error.EnhanceYourCalm, limiter.record(1_199));
}

test "rate limiter: a clock that goes backwards does not open the gate" {
    var limiter: RateLimiter = .{ .max_per_window = 1, .window_ns = 100 };
    try limiter.record(1_000);
    try testing.expectError(error.EnhanceYourCalm, limiter.record(0));
}

test "rate limiter: the first record starts the window rather than comparing to zero" {
    // Without the `started` flag, a first record at a large timestamp would
    // compare against a window that began at zero, find it long expired, and
    // silently allow one extra.
    var limiter: RateLimiter = .{ .max_per_window = 1, .window_ns = 100 };
    try limiter.record(1_000_000);
    try testing.expectError(error.EnhanceYourCalm, limiter.record(1_000_001));
}
