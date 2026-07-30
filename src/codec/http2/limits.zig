//! A rate limit over a sliding window, and the reason HTTP/2 needs a shape the
//! rest of this codebase does not have.
//!
//! Every other limit in Zinet is a ceiling on a quantity: this buffer holds at
//! most N bytes, this queue at most N entries. Those work because the resource is
//! held. HTTP/2's cheapest attacks hold nothing — a `RST_STREAM` frees its stream's
//! slot immediately, a `PING` is answered and forgotten, an empty `DATA` frame
//! occupies no memory at all. What they consume is *work*, and work is only bounded
//! per unit of time.
//!
//! Time is injected rather than read, in keeping with the rest of the framework:
//! the connection layer has an `Io` and passes a timestamp in.

const std = @import("std");

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

    window_start_ns: u64 = 0,
    count: u32 = 0,
    started: bool = false,

    pub fn record(limiter: *RateLimiter, now_ns: u64) Error!void {
        // Saturating subtraction, so a clock that goes backwards cannot produce a
        // huge elapsed time and open the gate. A monotonic clock should not go
        // backwards; this does not depend on that being true.
        if (!limiter.started or now_ns -| limiter.window_start_ns >= limiter.window_ns) {
            limiter.started = true;
            limiter.window_start_ns = now_ns;
            limiter.count = 0;
        }
        limiter.count += 1;
        if (limiter.count > limiter.max_per_window) return error.EnhanceYourCalm;
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
