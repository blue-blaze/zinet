//! Buffer recycling and opt-in reference counted sharing.
//!
//! Two independent facilities live here:
//!
//! * `BufferPool` recycles `Buffer` allocations across connections. A pooled
//!   buffer is indistinguishable from an owned one; the only difference is
//!   that it is returned to the pool instead of to the allocator. The pool is
//!   bounded in both the number and the size of retained buffers, so a burst
//!   of traffic cannot leave memory pinned forever.
//!
//! * `SharedBuffer` is the escape hatch for the cases where single ownership
//!   is genuinely the wrong model: fan-out to several channels, or slicing one
//!   payload into several views without copying. It is reference counted with
//!   atomics, because views may cross event loop boundaries.
//!
//! Both are optional. The core framework never forces a caller into either.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const buffer_mod = @import("buffer.zig");
const Buffer = buffer_mod.Buffer;
const Recycler = buffer_mod.Recycler;
const Spinlock = @import("lock.zig").Spinlock;

/// A bounded, thread-safe free list of `Buffer` allocations grouped by size
/// class.
///
/// Size classes are powers of two between `min_buffer_capacity` and
/// `max_buffer_capacity`. A buffer whose capacity falls outside that range is
/// freed rather than retained, which keeps a single oversized request from
/// permanently inflating the pool.
///
/// Thread safety: `acquire` and `release` may be called from any thread. A
/// plain mutex is enough because the critical sections are a handful of
/// instructions; contention is avoided by the fact that each channel keeps its
/// own buffers for the duration of a read.
pub const BufferPool = struct {
    gpa: Allocator,
    mutex: Spinlock,
    /// Free lists, indexed by size class. `classes[i]` holds buffers whose
    /// capacity is exactly `min_buffer_capacity << i`.
    classes: []Class,
    options: Options,
    /// Diagnostic counters. Monotonic; read them for tests and metrics only.
    stats: Stats,

    pub const Options = struct {
        /// Smallest pooled size class. Requests below this are rounded up.
        min_buffer_capacity: usize = 512,
        /// Largest pooled size class. Buffers larger than this are not
        /// retained.
        max_buffer_capacity: usize = 64 * 1024,
        /// Most buffers retained per size class.
        max_buffers_per_class: usize = 64,
        /// `max_capacity` handed to buffers created by this pool.
        buffer_max_capacity: usize = Buffer.default_max_capacity,
    };

    pub const Stats = struct {
        /// Requests served from a free list.
        hits: usize = 0,
        /// Requests that required a fresh allocation.
        misses: usize = 0,
        /// Buffers accepted back into a free list.
        recycled: usize = 0,
        /// Buffers freed on release because no free list would take them.
        discarded: usize = 0,
    };

    const Class = struct {
        capacity: usize,
        free: std.ArrayList(Buffer),
    };

    pub const Error = Allocator.Error;

    /// Creates a pool. The caller owns the result and must release it with
    /// `deinit`, which must happen after every acquired buffer has been
    /// released back or independently freed.
    pub fn init(gpa: Allocator, options: Options) Error!BufferPool {
        assert(options.min_buffer_capacity > 0);
        assert(std.math.isPowerOfTwo(options.min_buffer_capacity));
        assert(options.max_buffer_capacity >= options.min_buffer_capacity);
        assert(std.math.isPowerOfTwo(options.max_buffer_capacity));
        assert(options.buffer_max_capacity >= options.max_buffer_capacity);

        const class_count = std.math.log2_int(usize, options.max_buffer_capacity) -
            std.math.log2_int(usize, options.min_buffer_capacity) + 1;

        const classes = try gpa.alloc(Class, class_count);
        errdefer gpa.free(classes);
        for (classes, 0..) |*class, i| {
            class.* = .{
                .capacity = options.min_buffer_capacity << @intCast(i),
                .free = .empty,
            };
        }

        return .{
            .gpa = gpa,
            .mutex = .init,
            .classes = classes,
            .options = options,
            .stats = .{},
        };
    }

    /// Frees every retained buffer and the pool bookkeeping itself.
    pub fn deinit(pool: *BufferPool) void {
        for (pool.classes) |*class| {
            for (class.free.items) |*pooled| pooled.deinit(pool.gpa);
            class.free.deinit(pool.gpa);
        }
        pool.gpa.free(pool.classes);
        pool.* = undefined;
    }

    /// Returns a cleared buffer with at least `capacity` writable bytes.
    ///
    /// The returned buffer carries a recycler, so releasing it anywhere — in a
    /// message, in a write queue, in a handler — returns it here rather than to
    /// the allocator. That is what lets recycling survive ownership transfers.
    pub fn acquire(pool: *BufferPool, capacity: usize) Error!Buffer {
        var buffer = try pool.allocate(capacity);
        buffer.recycler = pool.recycler();
        return buffer;
    }

    /// The recycler that returns buffers to this pool.
    pub fn recycler(pool: *BufferPool) Recycler {
        return .{ .context = pool, .releaseFn = recycleImpl };
    }

    fn recycleImpl(context: *anyopaque, buffer: *Buffer) void {
        const pool: *BufferPool = @ptrCast(@alignCast(context));
        pool.release(buffer);
    }

    fn allocate(pool: *BufferPool, capacity: usize) Error!Buffer {
        const class_index = pool.classIndexFor(capacity);

        if (class_index) |index| {
            pool.mutex.lock();
            const maybe_pooled = pool.classes[index].free.pop();
            if (maybe_pooled != null) pool.stats.hits += 1 else pool.stats.misses += 1;
            pool.mutex.unlock();

            if (maybe_pooled) |pooled| {
                var reused = pooled;
                reused.clear();
                assert(reused.capacity() >= capacity);
                return reused;
            }
            return Buffer.init(pool.gpa, .{
                .capacity = pool.classes[index].capacity,
                .max_capacity = pool.options.buffer_max_capacity,
            }) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.BufferFull => unreachable, // Class capacity is bounded by options.
            };
        }

        pool.mutex.lock();
        pool.stats.misses += 1;
        pool.mutex.unlock();
        return Buffer.init(pool.gpa, .{
            .capacity = capacity,
            .max_capacity = @max(capacity, pool.options.buffer_max_capacity),
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BufferFull => unreachable, // max_capacity is at least capacity.
        };
    }

    /// Takes ownership of `buffer` back, retaining it for reuse when it fits a
    /// size class with room left, and freeing it otherwise.
    ///
    /// After this call, `buffer` owns nothing.
    pub fn release(pool: *BufferPool, buffer: *Buffer) void {
        var owned = buffer.move();
        // Cleared first: a retained buffer gets its recycler back when it is
        // acquired again, and a discarded one must free normally rather than
        // recursing back into this function.
        owned.recycler = null;

        const class_index = pool.exactClassIndexFor(owned.capacity()) orelse {
            owned.deinit(pool.gpa);
            pool.mutex.lock();
            pool.stats.discarded += 1;
            pool.mutex.unlock();
            return;
        };

        owned.clear();

        pool.mutex.lock();
        const class = &pool.classes[class_index];
        if (class.free.items.len >= pool.options.max_buffers_per_class) {
            pool.stats.discarded += 1;
            pool.mutex.unlock();
            owned.deinit(pool.gpa);
            return;
        }
        // A pool that cannot grow its bookkeeping simply declines to retain.
        class.free.append(pool.gpa, owned) catch {
            pool.stats.discarded += 1;
            pool.mutex.unlock();
            owned.deinit(pool.gpa);
            return;
        };
        pool.stats.recycled += 1;
        pool.mutex.unlock();
    }

    /// Snapshot of the counters. Safe to call concurrently.
    pub fn snapshotStats(pool: *BufferPool) Stats {
        pool.mutex.lock();
        defer pool.mutex.unlock();
        return pool.stats;
    }

    /// Number of buffers currently retained across all size classes.
    pub fn pooledCount(pool: *BufferPool) usize {
        pool.mutex.lock();
        defer pool.mutex.unlock();
        var total: usize = 0;
        for (pool.classes) |class| total += class.free.items.len;
        return total;
    }

    /// Size class that can serve `capacity`, or `null` when `capacity` exceeds
    /// the largest class.
    fn classIndexFor(pool: *const BufferPool, capacity: usize) ?usize {
        if (capacity > pool.options.max_buffer_capacity) return null;
        const wanted = @max(capacity, pool.options.min_buffer_capacity);
        const rounded = std.math.ceilPowerOfTwoAssert(usize, wanted);
        return std.math.log2_int(usize, rounded) -
            std.math.log2_int(usize, pool.options.min_buffer_capacity);
    }

    /// Size class whose capacity is exactly `capacity`, or `null` when the
    /// capacity does not correspond to a class.
    fn exactClassIndexFor(pool: *const BufferPool, capacity: usize) ?usize {
        if (capacity < pool.options.min_buffer_capacity) return null;
        if (capacity > pool.options.max_buffer_capacity) return null;
        if (!std.math.isPowerOfTwo(capacity)) return null;
        return std.math.log2_int(usize, capacity) -
            std.math.log2_int(usize, pool.options.min_buffer_capacity);
    }
};

/// A reference counted `Buffer` that can be observed through several
/// independent, read-only `View`s.
///
/// Ownership rules:
///
/// * `create` returns a `SharedBuffer` with a reference count of one, held by
///   the caller.
/// * `retain` adds a reference; `release` drops one. The final `release`
///   destroys the buffer and the bookkeeping.
/// * A `View` holds one reference for as long as it lives; releasing the view
///   releases that reference.
///
/// In safe builds, an unbalanced reference count is caught at `destroy` time
/// by an assertion, and `leak_count` lets a test assert that every shared
/// buffer it created has been fully released.
pub const SharedBuffer = struct {
    gpa: Allocator,
    buffer: Buffer,
    references: std.atomic.Value(u32),
    /// Optional pool the backing buffer returns to on destruction.
    pool: ?*BufferPool,

    /// Number of `SharedBuffer`s currently alive process-wide. Debug aid only:
    /// tests assert it returns to its starting value. Disabled in release
    /// builds where the atomics would be pure overhead.
    var live_count: std.atomic.Value(usize) = .init(0);

    pub const track_leaks = builtin.mode == .Debug or builtin.mode == .ReleaseSafe;

    pub const Error = Allocator.Error;

    /// Wraps `owned` (ownership transferred) in a reference counted box.
    ///
    /// The caller holds the single initial reference and must eventually call
    /// `release`.
    pub fn create(gpa: Allocator, owned: *Buffer) Error!*SharedBuffer {
        const shared = try gpa.create(SharedBuffer);
        shared.* = .{
            .gpa = gpa,
            .buffer = owned.move(),
            .references = .init(1),
            .pool = null,
        };
        if (track_leaks) _ = live_count.fetchAdd(1, .monotonic);
        return shared;
    }

    /// Like `create`, but the backing buffer is returned to `pool` when the
    /// last reference goes away.
    pub fn createPooled(pool: *BufferPool, owned: *Buffer) Error!*SharedBuffer {
        const shared = try create(pool.gpa, owned);
        shared.pool = pool;
        return shared;
    }

    /// Copies `source` into a new reference counted buffer.
    pub fn createFrom(gpa: Allocator, source: []const u8) Buffer.Error!*SharedBuffer {
        var owned = try Buffer.initFrom(gpa, source, .{});
        errdefer owned.deinit(gpa);
        return create(gpa, &owned);
    }

    /// Adds a reference. Threadsafe.
    pub fn retain(shared: *SharedBuffer) *SharedBuffer {
        const previous = shared.references.fetchAdd(1, .monotonic);
        assert(previous > 0); // Retaining a dead buffer is use-after-free.
        return shared;
    }

    /// Drops a reference, destroying the buffer when it was the last one.
    /// Threadsafe.
    pub fn release(shared: *SharedBuffer) void {
        const previous = shared.references.fetchSub(1, .release);
        assert(previous > 0); // Over-release.
        if (previous != 1) return;
        // Acquire barrier so this thread observes every prior write before
        // tearing the buffer down.
        _ = shared.references.load(.acquire);
        shared.destroy();
    }

    fn destroy(shared: *SharedBuffer) void {
        assert(shared.references.load(.monotonic) == 0);
        const gpa = shared.gpa;
        if (shared.pool) |pool| {
            pool.release(&shared.buffer);
        } else {
            shared.buffer.deinit(gpa);
        }
        if (track_leaks) {
            const previous = live_count.fetchSub(1, .monotonic);
            assert(previous > 0);
        }
        gpa.destroy(shared);
    }

    pub fn referenceCount(shared: *const SharedBuffer) u32 {
        return shared.references.load(.monotonic);
    }

    /// Bytes currently readable in the shared buffer.
    pub fn readableSlice(shared: *const SharedBuffer) []const u8 {
        return shared.buffer.readableSlice();
    }

    /// Creates a read-only view over `[start, start + len)` of the readable
    /// region, holding its own reference.
    ///
    /// The caller owns the view and must call `View.release`.
    pub fn view(shared: *SharedBuffer, start: usize, len: usize) Buffer.ReadError!View {
        const readable = shared.buffer.readableSlice();
        if (start > readable.len) return error.EndOfBuffer;
        if (readable.len - start < len) return error.EndOfBuffer;
        return .{ .shared = shared.retain(), .start = start, .len = len };
    }

    /// A view over the whole readable region.
    pub fn viewAll(shared: *SharedBuffer) View {
        return .{
            .shared = shared.retain(),
            .start = 0,
            .len = shared.buffer.readableLen(),
        };
    }

    /// Number of `SharedBuffer`s alive process-wide, for leak assertions in
    /// tests. Always zero when `track_leaks` is false.
    pub fn liveCount() usize {
        if (!track_leaks) return 0;
        return live_count.load(.monotonic);
    }

    /// A read-only window into a `SharedBuffer`, holding one reference.
    ///
    /// Views are cheap to copy only via `clone`, which takes the additional
    /// reference; copying the struct by assignment would silently share a
    /// reference and is a bug.
    pub const View = struct {
        shared: *SharedBuffer,
        start: usize,
        len: usize,

        pub fn bytes(v: View) []const u8 {
            const readable = v.shared.buffer.readableSlice();
            assert(v.start + v.len <= readable.len);
            return readable[v.start..][0..v.len];
        }

        /// Adds a reference and returns an independent view.
        pub fn clone(v: View) View {
            return .{ .shared = v.shared.retain(), .start = v.start, .len = v.len };
        }

        /// A narrower view of this view, holding its own reference.
        pub fn slice(v: View, start: usize, len: usize) Buffer.ReadError!View {
            if (start > v.len) return error.EndOfBuffer;
            if (v.len - start < len) return error.EndOfBuffer;
            return .{
                .shared = v.shared.retain(),
                .start = v.start + start,
                .len = len,
            };
        }

        /// Drops this view's reference.
        pub fn release(v: *View) void {
            v.shared.release();
            v.* = undefined;
        }
    };
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "BufferPool: acquire rounds up to a size class and reuses on release" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{
        .min_buffer_capacity = 512,
        .max_buffer_capacity = 4096,
    });
    defer pool.deinit();

    var first = try pool.acquire(600);
    try testing.expectEqual(@as(usize, 1024), first.capacity());
    try first.writeBytes(gpa, "in use");

    const address = first.bytes.ptr;
    pool.release(&first);
    try testing.expectEqual(@as(usize, 1), pool.pooledCount());

    var second = try pool.acquire(1000);
    defer pool.release(&second);
    try testing.expectEqual(address, second.bytes.ptr); // Same allocation.
    try testing.expectEqual(@as(usize, 0), second.readableLen()); // Cleared.

    const stats = pool.snapshotStats();
    try testing.expectEqual(@as(usize, 1), stats.hits);
    try testing.expectEqual(@as(usize, 1), stats.misses);
    try testing.expectEqual(@as(usize, 1), stats.recycled);
}

test "BufferPool: oversized buffers are served but not retained" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{
        .min_buffer_capacity = 512,
        .max_buffer_capacity = 1024,
    });
    defer pool.deinit();

    var big = try pool.acquire(8192);
    try testing.expectEqual(@as(usize, 8192), big.capacity());
    pool.release(&big);

    try testing.expectEqual(@as(usize, 0), pool.pooledCount());
    try testing.expectEqual(@as(usize, 1), pool.snapshotStats().discarded);
}

test "BufferPool: retention is capped per size class" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{
        .min_buffer_capacity = 512,
        .max_buffer_capacity = 512,
        .max_buffers_per_class = 2,
    });
    defer pool.deinit();

    var buffers: [4]Buffer = undefined;
    for (&buffers) |*buffer| buffer.* = try pool.acquire(512);
    for (&buffers) |*buffer| pool.release(buffer);

    try testing.expectEqual(@as(usize, 2), pool.pooledCount());
    try testing.expectEqual(@as(usize, 2), pool.snapshotStats().discarded);
}

test "BufferPool: a pooled buffer returns home when it is deinitialized" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{ .min_buffer_capacity = 512 });
    defer pool.deinit();

    // This is the path that matters in production: a buffer is acquired here,
    // handed to a message, carried through a pipeline, and released by whoever
    // happens to own it last — with no knowledge of the pool.
    var acquired = try pool.acquire(512);
    try acquired.writeBytes(gpa, "in flight");
    const address = acquired.bytes.ptr;

    acquired.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), pool.pooledCount());
    try testing.expectEqual(@as(usize, 1), pool.snapshotStats().recycled);

    var reacquired = try pool.acquire(512);
    defer reacquired.deinit(gpa);
    try testing.expectEqual(address, reacquired.bytes.ptr);
    try testing.expectEqual(@as(usize, 0), reacquired.readableLen());
}

test "BufferPool: a buffer that outgrew its class is freed, not recycled" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{
        .min_buffer_capacity = 512,
        .max_buffer_capacity = 512,
    });
    defer pool.deinit();

    var grown = try pool.acquire(512);
    // Growing past the class size means the allocation no longer matches any
    // free list, so releasing it must free rather than corrupt the pool.
    try grown.writeByteNTimes(gpa, 'x', 2048);
    try testing.expect(grown.capacity() > 512);
    grown.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), pool.pooledCount());
    try testing.expectEqual(@as(usize, 1), pool.snapshotStats().discarded);
}

test "BufferPool: released buffers own nothing" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{});
    defer pool.deinit();

    var buffer = try pool.acquire(512);
    pool.release(&buffer);

    // Releasing hands ownership back; a stray deinit must not double free.
    buffer.deinit(gpa);
}

test "BufferPool: concurrent acquire and release stay consistent" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{
        .min_buffer_capacity = 512,
        .max_buffer_capacity = 2048,
        .max_buffers_per_class = 8,
    });
    defer pool.deinit();

    const Worker = struct {
        fn run(p: *BufferPool, seed: u64) void {
            var prng: std.Random.DefaultPrng = .init(seed);
            const random = prng.random();
            for (0..256) |_| {
                const size = random.intRangeAtMost(usize, 1, 4096);
                var buffer = p.acquire(size) catch return;
                assert(buffer.capacity() >= size);
                buffer.writeByte(p.gpa, 0xab) catch {};
                p.release(&buffer);
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*thread, i| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{ &pool, @as(u64, i) + 1 });
    }
    for (threads) |thread| thread.join();

    try testing.expect(pool.pooledCount() <= 8 * pool.classes.len);
}

test "SharedBuffer: last release destroys the buffer" {
    const gpa = testing.allocator;
    const live_before = SharedBuffer.liveCount();

    const shared = try SharedBuffer.createFrom(gpa, "shared payload");
    try testing.expectEqual(@as(u32, 1), shared.referenceCount());

    _ = shared.retain();
    try testing.expectEqual(@as(u32, 2), shared.referenceCount());
    shared.release();
    try testing.expectEqual(@as(u32, 1), shared.referenceCount());

    shared.release();
    try testing.expectEqual(live_before, SharedBuffer.liveCount());
}

test "SharedBuffer: two views observe the same bytes without copying" {
    const gpa = testing.allocator;
    const live_before = SharedBuffer.liveCount();

    const shared = try SharedBuffer.createFrom(gpa, "HEADERBODY");
    var head = try shared.view(0, 6);
    var body = try shared.view(6, 4);
    try testing.expectEqual(@as(u32, 3), shared.referenceCount());

    try testing.expectEqualStrings("HEADER", head.bytes());
    try testing.expectEqualStrings("BODY", body.bytes());
    // Views alias the one underlying allocation.
    try testing.expectEqual(shared.readableSlice().ptr, head.bytes().ptr);

    shared.release(); // Views keep it alive.
    try testing.expectEqual(@as(u32, 2), shared.referenceCount());
    try testing.expectEqualStrings("HEADER", head.bytes());

    head.release();
    body.release();
    try testing.expectEqual(live_before, SharedBuffer.liveCount());
}

test "SharedBuffer: views validate their bounds and can be narrowed" {
    const gpa = testing.allocator;
    const live_before = SharedBuffer.liveCount();

    const shared = try SharedBuffer.createFrom(gpa, "0123456789");
    defer shared.release();

    try testing.expectError(error.EndOfBuffer, shared.view(0, 11));
    try testing.expectError(error.EndOfBuffer, shared.view(11, 0));

    var window = try shared.view(2, 6);
    defer window.release();
    try testing.expectEqualStrings("234567", window.bytes());

    var inner = try window.slice(1, 3);
    defer inner.release();
    try testing.expectEqualStrings("345", inner.bytes());
    try testing.expectError(error.EndOfBuffer, window.slice(4, 3));

    var cloned = window.clone();
    defer cloned.release();
    try testing.expectEqualStrings("234567", cloned.bytes());

    if (SharedBuffer.track_leaks) {
        try testing.expect(SharedBuffer.liveCount() > live_before);
    }
}

test "SharedBuffer: pooled backing memory returns to the pool" {
    const gpa = testing.allocator;
    var pool = try BufferPool.init(gpa, .{ .min_buffer_capacity = 512 });
    defer pool.deinit();

    var owned = try pool.acquire(512);
    try owned.writeBytes(gpa, "pooled");

    const shared = try SharedBuffer.createPooled(&pool, &owned);
    var window = shared.viewAll();
    try testing.expectEqualStrings("pooled", window.bytes());

    shared.release();
    try testing.expectEqual(@as(usize, 0), pool.pooledCount());
    window.release();
    try testing.expectEqual(@as(usize, 1), pool.pooledCount());
}

test "SharedBuffer: reference counting survives concurrent retain and release" {
    const gpa = testing.allocator;
    const live_before = SharedBuffer.liveCount();

    const shared = try SharedBuffer.createFrom(gpa, "concurrent");

    const Worker = struct {
        fn run(s: *SharedBuffer) void {
            for (0..1024) |_| {
                var v = s.viewAll();
                assert(std.mem.eql(u8, v.bytes(), "concurrent"));
                v.release();
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{shared});
    }
    for (threads) |thread| thread.join();

    try testing.expectEqual(@as(u32, 1), shared.referenceCount());
    shared.release();
    try testing.expectEqual(live_before, SharedBuffer.liveCount());
}
