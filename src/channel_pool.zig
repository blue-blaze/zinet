//! A bounded pool of client connections, in the spirit of Netty's
//! `FixedChannelPool`.
//!
//! What a pool is for is not saving the `connect` syscall — it is bounding how
//! many connections a client opens. A service calling another service under load
//! without a pool opens as many connections as it has concurrent requests, which
//! is how one slow dependency turns into thousands of sockets and a file
//! descriptor limit.
//!
//! So the interesting parameter is `capacity`, and the interesting decision is
//! what happens when it is reached. Netty offers a queue with a timeout; this
//! blocks the caller, for the same reason `Channel`'s write queue blocks rather
//! than growing: backpressure that can be ignored is not backpressure. A caller
//! that would rather fail than wait passes a deadline.
//!
//! **The health check is unavoidable rather than optional.** A pooled connection
//! is idle by definition, and the peer may have closed it while it sat there — a
//! server with a keep-alive timeout does exactly that. So `acquire` checks and
//! reconnects rather than handing back a channel whose next write fails. That
//! check is why the pool cannot be a plain free list.
//!
//! **Reference counting is the sharp edge**, and this file exists partly to hide
//! it. A `Channel` is reference counted, and holding a bare `*Channel` without a
//! reference is the one thing the ownership rules forbid. The pool holds a
//! reference for every channel it stores, hands it to the borrower for the
//! duration, and takes it back on release. A caller therefore never calls
//! `retain` or `release` itself.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const channel_mod = @import("channel.zig");
const Channel = channel_mod.Channel;
const bootstrap = @import("bootstrap.zig");
const Spinlock = @import("lock.zig").Spinlock;
const EventLoopGroup = @import("event_loop.zig").EventLoopGroup;

pub const Error = error{
    /// The pool is full and no connection came back before the deadline.
    PoolTimeout,
    /// `deinit` has been called; the pool refuses rather than handing out a
    /// connection it is about to tear down.
    PoolClosed,
} || bootstrap.ConnectError;

pub const Options = struct {
    gpa: Allocator,
    io: Io,
    /// Where the connections go. One pool serves one endpoint, which is what
    /// makes "is this connection usable" answerable without asking the caller.
    address: Io.net.IpAddress,
    loops: *EventLoopGroup,
    /// How each connection's pipeline is built.
    config: bootstrap.ChildConfig = .{},
    /// The ceiling, and the whole point of the pool.
    capacity: usize = 8,
    /// How long an idle connection is kept before being closed. Zero keeps them
    /// indefinitely — which is reasonable for a service talking to a service, and
    /// wrong for a client with thousands of possible destinations.
    idle_timeout: Io.Duration = .fromSeconds(60),
    /// How long `acquire` waits for a connection to come free when the pool is at
    /// capacity. Null waits indefinitely.
    acquire_timeout: ?Io.Duration = .fromSeconds(10),
    /// How often a waiting `acquire` re-checks. Polling rather than a condition
    /// variable because `std.Io` gives a sleep and the wait is rare: a pool that
    /// is constantly at capacity is a pool that is too small, and that is the
    /// application's problem to notice rather than this file's to optimise.
    poll_interval: Io.Duration = .fromMilliseconds(2),
};

/// One pooled connection.
const Entry = struct {
    channel: *Channel,
    /// When it was last returned, for the idle timeout.
    idle_since: i96,
};

pub const Pool = struct {
    options: Options,
    /// Connections that are available. Held with a reference each.
    idle: std.ArrayList(Entry) = .empty,
    /// How many connections exist, borrowed or idle. This is what `capacity`
    /// bounds — counting only the idle ones would bound nothing.
    live: usize = 0,
    closed: bool = false,
    /// Guards everything above. A pool is the one thing here that is genuinely
    /// shared: it exists so that several tasks can use one set of connections,
    /// which is the opposite of the per-connection isolation the rest of the
    /// framework relies on.
    ///
    /// A `Spinlock` rather than a blocking mutex, and every critical section is
    /// kept to a few instructions to earn it: the connect happens *outside* the
    /// lock, which is why the slot is reserved before it and given back on
    /// failure. Holding a spinlock across a connect would be a bug of the kind
    /// this repository's own `lock.zig` warns about.
    lock: Spinlock = .init,

    // Counters, for tests and for anything that wants to see the pool working.
    acquired: usize = 0,
    created: usize = 0,
    discarded_unhealthy: usize = 0,
    reused: usize = 0,

    pub fn init(options: Options) Pool {
        assert(options.capacity > 0);
        return .{ .options = options };
    }

    /// Closes every connection and frees the pool.
    ///
    /// Borrowed connections are *not* waited for: a caller still holding one has
    /// a reference, so the channel stays alive and its own release finishes it.
    /// That is what reference counting is for, and the alternative — waiting —
    /// would let one stuck borrower prevent shutdown.
    pub fn deinit(pool: *Pool) void {
        pool.lock.lock();
        pool.closed = true;
        var entries = pool.idle;
        pool.idle = .empty;
        pool.lock.unlock();

        for (entries.items) |entry| {
            closeAndRelease(entry.channel);
        }
        entries.deinit(pool.options.gpa);
    }

    /// Take a connection, creating one if the pool is below capacity and waiting
    /// if it is not.
    ///
    /// The returned channel is borrowed: pass it back to `release` (or
    /// `discard`), and do not call `retain` or `release` on it directly — the
    /// pool holds the reference on the caller's behalf.
    pub fn acquire(pool: *Pool) Error!*Channel {
        const deadline: ?Io.Timestamp = if (pool.options.acquire_timeout) |timeout|
            Io.Timestamp.now(pool.options.io, .awake).addDuration(timeout)
        else
            null;

        while (true) {
            if (try pool.tryAcquire()) |channel| return channel;

            if (deadline) |limit| {
                if (Io.Timestamp.now(pool.options.io, .awake).nanoseconds >= limit.nanoseconds) {
                    return error.PoolTimeout;
                }
            }
            pool.options.io.sleep(pool.options.poll_interval, .awake) catch
                return error.PoolTimeout;
        }
    }

    /// One attempt: an idle connection, or a new one, or null meaning "full".
    fn tryAcquire(pool: *Pool) Error!?*Channel {
        pool.lock.lock();
        if (pool.closed) {
            pool.lock.unlock();
            return error.PoolClosed;
        }

        // Newest first. A recently used connection is the one most likely to
        // still be open, and taking the oldest would mean the whole pool ages at
        // the same rate — every connection expiring at once.
        while (pool.idle.items.len > 0) {
            const entry = pool.idle.pop().?;

            if (!entry.channel.isOpen()) {
                // The peer closed it while it sat here, which is what a keep-alive
                // timeout on the server looks like. Not an error: it is the
                // ordinary life of a pooled connection.
                pool.live -= 1;
                pool.discarded_unhealthy += 1;
                pool.lock.unlock();
                entry.channel.release();
                // Round again rather than recursing: there may be more stale ones.
                return pool.tryAcquire();
            }

            if (pool.expired(entry)) {
                pool.live -= 1;
                pool.lock.unlock();
                closeAndRelease(entry.channel);
                return pool.tryAcquire();
            }

            pool.acquired += 1;
            pool.reused += 1;
            pool.lock.unlock();
            return entry.channel;
        }

        if (pool.live >= pool.options.capacity) {
            pool.lock.unlock();
            return null; // full; the caller waits
        }

        // Reserve the slot before connecting, so two tasks cannot both decide
        // there is room for one more.
        pool.live += 1;
        pool.lock.unlock();

        const channel = bootstrap.connect(.{
            .gpa = pool.options.gpa,
            .io = pool.options.io,
            .address = pool.options.address,
            .loops = pool.options.loops,
            .config = pool.options.config,
        }) catch |err| {
            pool.lock.lock();
            pool.live -= 1;
            pool.lock.unlock();
            return err;
        };

        pool.lock.lock();
        pool.created += 1;
        pool.acquired += 1;
        pool.lock.unlock();
        return channel;
    }

    /// Give a connection back.
    ///
    /// A closed one is discarded rather than stored: putting it back would mean
    /// the next caller gets a connection that fails on first write, having paid
    /// the wait for it.
    pub fn release(pool: *Pool, channel: *Channel) void {
        pool.lock.lock();

        if (pool.closed or !channel.isOpen()) {
            pool.live -= 1;
            pool.lock.unlock();
            closeAndRelease(channel);
            return;
        }

        pool.idle.append(pool.options.gpa, .{
            .channel = channel,
            .idle_since = Io.Timestamp.now(pool.options.io, .awake).nanoseconds,
        }) catch {
            // Out of memory storing it: close it rather than leak the reference.
            pool.live -= 1;
            pool.lock.unlock();
            closeAndRelease(channel);
            return;
        };
        pool.lock.unlock();
    }

    /// Give a connection back and do not reuse it.
    ///
    /// For a caller that knows the connection is spent even though it is still
    /// open — a protocol error, a `Connection: close`, a response it could not
    /// parse. Without this, "still open" and "still usable" get conflated, and the
    /// pool hands out connections in a state only the borrower could know about.
    pub fn discard(pool: *Pool, channel: *Channel) void {
        pool.lock.lock();
        pool.live -= 1;
        pool.lock.unlock();
        closeAndRelease(channel);
    }

    /// Close idle connections that have sat longer than the timeout.
    ///
    /// Called by `acquire` on the connection it takes, and available to an
    /// application that wants to sweep the rest — the pool arms no timer of its
    /// own, because a timer would need a task and this framework's rule is that
    /// time arrives as an event on work already happening.
    pub fn sweepIdle(pool: *Pool) void {
        pool.lock.lock();
        var stale: [32]*Channel = undefined;
        var found: usize = 0;
        var index: usize = 0;
        while (index < pool.idle.items.len and found < stale.len) {
            const entry = pool.idle.items[index];
            if (!entry.channel.isOpen() or pool.expired(entry)) {
                stale[found] = entry.channel;
                found += 1;
                pool.live -= 1;
                _ = pool.idle.orderedRemove(index);
                continue;
            }
            index += 1;
        }
        pool.lock.unlock();
        for (stale[0..found]) |channel| closeAndRelease(channel);
    }

    /// How many connections exist, borrowed or idle.
    pub fn liveCount(pool: *Pool) usize {
        pool.lock.lock();
        defer pool.lock.unlock();
        return pool.live;
    }

    pub fn idleCount(pool: *Pool) usize {
        pool.lock.lock();
        defer pool.lock.unlock();
        return pool.idle.items.len;
    }

    fn expired(pool: *const Pool, entry: Entry) bool {
        const timeout = pool.options.idle_timeout.nanoseconds;
        if (timeout == 0) return false;
        const now = Io.Timestamp.now(pool.options.io, .awake).nanoseconds;
        return now - entry.idle_since >= timeout;
    }
};

/// End a connection and drop the pool's reference.
///
/// `requestClose` rather than `submitClose`: a submitted close travels the
/// pipeline, which is what a protocol with a closing handshake needs — but it is
/// also queued, so it has not happened when the call returns, and a pool tearing
/// down would drop its reference while the close was still pending. A pooled
/// connection is a plain client connection; when its protocol needs a graceful
/// close, the borrower performs it before releasing.
fn closeAndRelease(channel: *Channel) void {
    channel.requestClose();
    channel.release();
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const backend = @import("backend");
const pipeline_mod = @import("pipeline.zig");
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;
const Buffer = @import("buffer.zig").Buffer;

/// Echoes what it is given, so a test can tell a live connection from a dead one.
const EchoHandler = struct {
    pub fn onRead(_: *EchoHandler, ctx: *HandlerContext, msg: Message) pipeline_mod.Error!void {
        return ctx.writeAndFlush(msg);
    }
};

fn buildEcho(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(EchoHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("echo", .initOwned(handler));
}

/// A server, a loop group and a runtime for the tests below.
///
/// Initialised in place rather than returned by value: `EventLoopGroup` says in
/// as many words that it must stay at a stable address, because the tasks it
/// spawns refer back to it. Returning one by value moves it, and every test here
/// segfaulted until this was in place — a reminder that "returns a struct" is a
/// decision, not a default.
const Fixture = struct {
    runtime: backend.Runtime = undefined,
    server: *bootstrap.Server = undefined,
    loops: EventLoopGroup = undefined,
    gpa: Allocator = undefined,

    fn init(self: *Fixture, gpa: Allocator) !void {
        self.gpa = gpa;
        self.runtime = try backend.Runtime.init(gpa);
        errdefer self.runtime.deinit();
        const io = self.runtime.io();

        self.server = try bootstrap.Server.listen(.{
            .gpa = gpa,
            .io = io,
            .address = .{ .ip4 = .loopback(0) },
            .child = .{ .initializer = .initFunction(buildEcho) },
        });
        errdefer self.server.deinit();
        try self.server.serve();

        self.loops = try .init(gpa, io, .{ .loop_count = 1 });
    }

    fn deinit(self: *Fixture) void {
        self.loops.shutdown();
        self.loops.deinit();
        self.server.deinit();
        self.runtime.deinit();
    }

    fn ioOf(self: *Fixture) Io {
        return self.runtime.io();
    }

    fn address(self: *Fixture) Io.net.IpAddress {
        return self.server.boundAddress();
    }
};

test "pool: a released connection is the one handed out next" {
    // The whole point: the second acquire costs no connect.
    const gpa = testing.allocator;
    var fixture: Fixture = .{};
    try fixture.init(gpa);
    defer fixture.deinit();

    var pool: Pool = .init(.{
        .gpa = gpa,
        .io = fixture.ioOf(),
        .address = fixture.address(),
        .loops = &fixture.loops,
        .config = .{ .initializer = .initFunction(buildEcho) },
        .capacity = 4,
    });
    defer pool.deinit();

    const first = try pool.acquire();
    try testing.expectEqual(@as(usize, 1), pool.liveCount());
    try testing.expectEqual(@as(usize, 1), pool.created);
    pool.release(first);
    try testing.expectEqual(@as(usize, 1), pool.idleCount());

    const second = try pool.acquire();
    try testing.expectEqual(first, second);
    try testing.expectEqual(@as(usize, 1), pool.created); // no second connect
    try testing.expectEqual(@as(usize, 1), pool.reused);
    pool.release(second);
}

test "pool: capacity is a ceiling and a full pool refuses rather than growing" {
    const gpa = testing.allocator;
    var fixture: Fixture = .{};
    try fixture.init(gpa);
    defer fixture.deinit();

    var pool: Pool = .init(.{
        .gpa = gpa,
        .io = fixture.ioOf(),
        .address = fixture.address(),
        .loops = &fixture.loops,
        .config = .{ .initializer = .initFunction(buildEcho) },
        .capacity = 2,
        // Short, because the expected outcome is the timeout.
        .acquire_timeout = .fromMilliseconds(200),
    });
    defer pool.deinit();

    const a = try pool.acquire();
    const b = try pool.acquire();
    try testing.expectEqual(@as(usize, 2), pool.liveCount());

    // A third would exceed the ceiling. Waiting, then failing, is the contract:
    // the alternative is opening a connection the application did not budget for,
    // which is exactly the failure a pool exists to prevent.
    try testing.expectError(error.PoolTimeout, pool.acquire());

    pool.release(a);
    // Now there is room, and it is the same connection rather than a new one.
    const c = try pool.acquire();
    try testing.expectEqual(a, c);
    try testing.expectEqual(@as(usize, 2), pool.created);

    pool.release(b);
    pool.release(c);
}

test "pool: a connection the peer closed is replaced rather than handed back" {
    // The health check, which is what makes a pool different from a free list. A
    // pooled connection is idle by definition, and a server with a keep-alive
    // timeout closes it while it waits.
    const gpa = testing.allocator;
    var fixture: Fixture = .{};
    try fixture.init(gpa);
    defer fixture.deinit();

    var pool: Pool = .init(.{
        .gpa = gpa,
        .io = fixture.ioOf(),
        .address = fixture.address(),
        .loops = &fixture.loops,
        .config = .{ .initializer = .initFunction(buildEcho) },
        .capacity = 4,
    });
    defer pool.deinit();

    const first = try pool.acquire();
    pool.release(first);

    // Simulate the peer going away by closing it behind the pool's back, which is
    // observationally what a keep-alive timeout does.
    first.requestClose();
    const deadline = Io.Timestamp.now(fixture.ioOf(), .awake).addDuration(.fromSeconds(5));
    while (first.isOpen()) {
        if (Io.Timestamp.now(fixture.ioOf(), .awake).nanoseconds >= deadline.nanoseconds) break;
        try fixture.ioOf().sleep(.fromMilliseconds(2), .awake);
    }
    try testing.expect(!first.isOpen());

    // The pool notices, drops it, and connects again — rather than handing back a
    // channel whose next write fails.
    const second = try pool.acquire();
    try testing.expect(second != first);
    try testing.expectEqual(@as(usize, 1), pool.discarded_unhealthy);
    try testing.expectEqual(@as(usize, 2), pool.created);
    try testing.expectEqual(@as(usize, 1), pool.liveCount());
    pool.release(second);
}

test "pool: releasing a connection that died in use does not store it" {
    // The other end of the health check, and the one that costs a caller a wait
    // if it is missing: a connection that broke *during* the exchange must not go
    // back in the pool, or the next borrower pays the queue for a channel whose
    // first write fails.
    const gpa = testing.allocator;
    var fixture: Fixture = .{};
    try fixture.init(gpa);
    defer fixture.deinit();

    var pool: Pool = .init(.{
        .gpa = gpa,
        .io = fixture.ioOf(),
        .address = fixture.address(),
        .loops = &fixture.loops,
        .config = .{ .initializer = .initFunction(buildEcho) },
        .capacity = 4,
    });
    defer pool.deinit();

    const channel = try pool.acquire();
    // It dies while borrowed, which is what a peer resetting mid-exchange does.
    channel.requestClose();
    const deadline = Io.Timestamp.now(fixture.ioOf(), .awake).addDuration(.fromSeconds(5));
    while (channel.isOpen()) {
        if (Io.Timestamp.now(fixture.ioOf(), .awake).nanoseconds >= deadline.nanoseconds) break;
        try fixture.ioOf().sleep(.fromMilliseconds(2), .awake);
    }
    try testing.expect(!channel.isOpen());

    pool.release(channel);
    try testing.expectEqual(@as(usize, 0), pool.idleCount());
    try testing.expectEqual(@as(usize, 0), pool.liveCount());

    // And the slot really was given back, so the pool can still be used.
    const replacement = try pool.acquire();
    try testing.expect(replacement != channel);
    pool.release(replacement);
}

test "pool: a discarded connection is not reused even though it is open" {
    // "Open" and "usable" are different, and only the borrower knows which. A
    // protocol error mid-exchange leaves a connection whose state neither end
    // agrees on.
    const gpa = testing.allocator;
    var fixture: Fixture = .{};
    try fixture.init(gpa);
    defer fixture.deinit();

    var pool: Pool = .init(.{
        .gpa = gpa,
        .io = fixture.ioOf(),
        .address = fixture.address(),
        .loops = &fixture.loops,
        .config = .{ .initializer = .initFunction(buildEcho) },
        .capacity = 4,
    });
    defer pool.deinit();

    const first = try pool.acquire();
    try testing.expect(first.isOpen());
    pool.discard(first);
    try testing.expectEqual(@as(usize, 0), pool.liveCount());
    try testing.expectEqual(@as(usize, 0), pool.idleCount());

    const second = try pool.acquire();
    try testing.expect(second != first);
    pool.release(second);
}

test "pool: an idle connection past its timeout is closed" {
    const gpa = testing.allocator;
    var fixture: Fixture = .{};
    try fixture.init(gpa);
    defer fixture.deinit();

    var pool: Pool = .init(.{
        .gpa = gpa,
        .io = fixture.ioOf(),
        .address = fixture.address(),
        .loops = &fixture.loops,
        .config = .{ .initializer = .initFunction(buildEcho) },
        .capacity = 4,
        .idle_timeout = .fromMilliseconds(20),
    });
    defer pool.deinit();

    const first = try pool.acquire();
    pool.release(first);
    try testing.expectEqual(@as(usize, 1), pool.idleCount());

    try fixture.ioOf().sleep(.fromMilliseconds(60), .awake);
    pool.sweepIdle();
    try testing.expectEqual(@as(usize, 0), pool.idleCount());
    try testing.expectEqual(@as(usize, 0), pool.liveCount());

    // And the next acquire connects rather than reviving it.
    const second = try pool.acquire();
    try testing.expectEqual(@as(usize, 2), pool.created);
    pool.release(second);
}

test "pool: a pooled connection still works, which is the point" {
    // Everything above counts connections. This one uses them: a write through a
    // reused connection must reach the server and come back.
    const gpa = testing.allocator;
    var fixture: Fixture = .{};
    try fixture.init(gpa);
    defer fixture.deinit();

    const Collector = struct {
        got: std.atomic.Value(usize) = .init(0),
        buf: [64]u8 = undefined,
        len: usize = 0,

        pub fn onRead(self: *@This(), ctx: *HandlerContext, msg: Message) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const bytes = owned.bytes() orelse return;
            const take = @min(bytes.len, self.buf.len - self.len);
            @memcpy(self.buf[self.len..][0..take], bytes[0..take]);
            self.len += take;
            _ = self.got.fetchAdd(1, .release);
        }
    };

    var collector: Collector = .{};
    const Builder = struct {
        collector: *Collector,
        pub fn initPipeline(self: *@This(), pipeline: *Pipeline) anyerror!void {
            _ = try pipeline.addLast("collect", .init(self.collector));
        }
    };
    var builder: Builder = .{ .collector = &collector };

    var pool: Pool = .init(.{
        .gpa = gpa,
        .io = fixture.ioOf(),
        .address = fixture.address(),
        .loops = &fixture.loops,
        .config = .{ .initializer = .init(&builder) },
        .capacity = 2,
    });
    defer pool.deinit();

    // Two exchanges over one connection, the second on the reused channel.
    for ([_][]const u8{ "first", "second" }) |payload| {
        const channel = try pool.acquire();
        try channel.write(try Message.initBytes(gpa, payload));
        try channel.flush();

        const deadline = Io.Timestamp.now(fixture.ioOf(), .awake).addDuration(.fromSeconds(5));
        const before = collector.got.load(.acquire);
        while (collector.got.load(.acquire) == before) {
            if (Io.Timestamp.now(fixture.ioOf(), .awake).nanoseconds >= deadline.nanoseconds) {
                return error.EchoTimedOut;
            }
            try fixture.ioOf().sleep(.fromMilliseconds(2), .awake);
        }
        pool.release(channel);
    }

    try testing.expectEqual(@as(usize, 1), pool.created);
    try testing.expectEqual(@as(usize, 1), pool.reused);
    try testing.expectEqualStrings("firstsecond", collector.buf[0..collector.len]);
}
