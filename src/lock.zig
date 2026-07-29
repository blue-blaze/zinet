//! Small synchronization primitives that do not need an `Io` instance.
//!
//! Zig 0.16 offers `std.Io.Mutex`, which is the right tool for locks held
//! across suspension points, and `std.atomic.Mutex`, which only offers
//! `tryLock`. Zinet needs one more shape: a lock for critical sections that
//! are a handful of instructions long and never perform I/O, callable from any
//! thread without threading an `Io` through the API (the buffer pool, for
//! example). `Spinlock` fills that gap.

const std = @import("std");
const assert = std.debug.assert;

/// A mutual exclusion lock for very short, I/O-free critical sections.
///
/// Do not hold this across an `Io` call, an allocation that may block, or any
/// operation whose duration is not bounded by a few hundred instructions; use
/// `std.Io.Mutex` for those.
pub const Spinlock = struct {
    state: std.atomic.Mutex,

    /// Spins before descheduling. Chosen so that an uncontended handoff never
    /// reaches the syscall, while a contended one does not burn a whole time
    /// slice.
    const spin_attempts = 64;

    pub const init: Spinlock = .{ .state = .unlocked };

    pub fn tryLock(s: *Spinlock) bool {
        return s.state.tryLock();
    }

    pub fn lock(s: *Spinlock) void {
        var attempt: usize = 0;
        while (true) : (attempt += 1) {
            if (s.state.tryLock()) return;
            if (attempt < spin_attempts) {
                std.atomic.spinLoopHint();
            } else {
                attempt = 0;
                std.Thread.yield() catch std.atomic.spinLoopHint();
            }
        }
    }

    pub fn unlock(s: *Spinlock) void {
        s.state.unlock();
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "Spinlock: uncontended lock and unlock" {
    var lock: Spinlock = .init;
    try testing.expect(lock.tryLock());
    try testing.expect(!lock.tryLock());
    lock.unlock();
    lock.lock();
    lock.unlock();
}

test "Spinlock: serializes increments from several threads" {
    var lock: Spinlock = .init;
    var counter: usize = 0;

    const Worker = struct {
        fn run(l: *Spinlock, c: *usize) void {
            for (0..10_000) |_| {
                l.lock();
                defer l.unlock();
                c.* += 1; // Non-atomic on purpose: the lock is what protects it.
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &lock, &counter });
    }
    for (threads) |thread| thread.join();

    try testing.expectEqual(@as(usize, 40_000), counter);
}
