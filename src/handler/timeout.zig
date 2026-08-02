//! Time-based handlers: idle detection and the timeouts built on it.
//!
//! Netty's `IdleStateHandler` schedules a task on the event loop and compares
//! timestamps when it runs. Zinet's version reacts to `Channel.Tick` instead,
//! for the reason spelled out on `Channel.Tick`: a connection blocked in a read
//! has no loop to hang a timer on, and delivering timer callbacks from a second
//! task would break the guarantee that all handler callbacks share one task.
//!
//! The consequence is that idleness is detected on the first tick *after* the
//! threshold passes, not at the instant it passes. `IdleStateHandler` therefore
//! asks the channel for ticks at half its shortest threshold, which bounds the
//! lateness at roughly half a threshold. Anything needing a hard deadline should
//! not be built on this.
//!
//! ## Writer idleness requires writes to go through the pipeline
//!
//! `last_write` is stamped in `onWrite`, so only writes issued through
//! `ctx.write` / `pipeline.write` count. `Channel.write` deliberately bypasses
//! the pipeline — that is what makes it callable from any task — so a
//! broadcaster using it will look idle to this handler. Use `ctx.write` from
//! inside the connection's own handlers if writer idleness matters.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const channel_mod = @import("../channel.zig");
const pipeline_mod = @import("../pipeline.zig");

const Channel = channel_mod.Channel;
const Error = pipeline_mod.Error;
const Event = pipeline_mod.Event;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Which kind of quiet was observed.
pub const IdleState = enum {
    /// Nothing has been read for `reader_idle`.
    reader_idle,
    /// Nothing has been written for `writer_idle`.
    writer_idle,
    /// Neither, for `all_idle`.
    all_idle,
};

/// Fired inbound as a pipeline event when a threshold is crossed.
///
/// The equivalent of Netty's `IdleStateEvent`. Handlers downstream decide what
/// it means: a WebSocket keepalive sends a ping, a server closes the
/// connection, a client reconnects.
pub const IdleStateEvent = struct {
    state: IdleState,
    /// 1 for the first firing since traffic last reset the timer, incrementing
    /// while the quiet continues. Lets a handler ping once and close on the
    /// second miss.
    count: u32,
};

pub const Options = struct {
    /// Fire `reader_idle` after this long with no inbound message.
    reader_idle: ?Io.Duration = null,
    /// Fire `writer_idle` after this long with no outbound message.
    writer_idle: ?Io.Duration = null,
    /// Fire `all_idle` after this long with neither.
    all_idle: ?Io.Duration = null,
};

/// Watches for quiet and reports it as an `IdleStateEvent`.
///
/// State is per connection and touched only from the connection's own task, so
/// nothing here is synchronized.
pub const IdleStateHandler = struct {
    options: Options,

    last_read: ?Io.Timestamp = null,
    last_write: ?Io.Timestamp = null,
    reader_count: u32 = 0,
    writer_count: u32 = 0,
    all_count: u32 = 0,

    pub const handler_name = "idle-state";

    /// Shortest tick this handler will ask a channel for, so a very small
    /// threshold cannot turn into a spin.
    pub const min_tick = Io.Duration.fromMilliseconds(1);

    pub fn init(options: Options) IdleStateHandler {
        assert(options.reader_idle != null or
            options.writer_idle != null or
            options.all_idle != null);
        return .{ .options = options };
    }

    /// Asks the channel to tick often enough to notice the shortest threshold.
    pub fn onAdded(self: *IdleStateHandler, ctx: *HandlerContext) Error!void {
        const owner = ctx.owner() orelse return;
        const channel: *Channel = @ptrCast(@alignCast(owner));

        var shortest: ?i96 = null;
        for ([_]?Io.Duration{
            self.options.reader_idle,
            self.options.writer_idle,
            self.options.all_idle,
        }) |maybe| {
            const nanoseconds = (maybe orelse continue).toNanoseconds();
            if (shortest == null or nanoseconds < shortest.?) shortest = nanoseconds;
        }
        const threshold = shortest orelse return;

        // Half the threshold, so a crossing is noticed within about half a
        // threshold rather than a whole one.
        const wanted = @max(@divTrunc(threshold, 2), min_tick.toNanoseconds());
        channel.requestTick(.fromNanoseconds(wanted));
    }

    pub fn onActive(self: *IdleStateHandler, ctx: *HandlerContext) Error!void {
        const now = Io.Timestamp.now(ctx.io(), .awake);
        self.last_read = now;
        self.last_write = now;
        ctx.fireActive();
    }

    pub fn onRead(self: *IdleStateHandler, ctx: *HandlerContext, msg: Message) Error!void {
        self.last_read = Io.Timestamp.now(ctx.io(), .awake);
        self.reader_count = 0;
        self.all_count = 0;
        ctx.fireRead(msg);
    }

    pub fn onWrite(self: *IdleStateHandler, ctx: *HandlerContext, msg: Message) Error!void {
        self.last_write = Io.Timestamp.now(ctx.io(), .awake);
        self.writer_count = 0;
        self.all_count = 0;
        return ctx.write(msg);
    }

    pub fn onEvent(self: *IdleStateHandler, ctx: *HandlerContext, event: Event) Error!void {
        const tick = event.get(Channel.Tick) orelse {
            ctx.fireEvent(event);
            return;
        };

        // Ticks are consumed rather than forwarded: they are transport
        // plumbing, and what downstream handlers want is the conclusion.
        self.evaluate(ctx, tick.at);
    }

    fn evaluate(self: *IdleStateHandler, ctx: *HandlerContext, now: Io.Timestamp) void {
        if (self.options.reader_idle) |threshold| {
            if (elapsed(self.last_read, now, threshold)) {
                self.last_read = now;
                self.reader_count += 1;
                fire(ctx, .{ .state = .reader_idle, .count = self.reader_count });
            }
        }
        if (self.options.writer_idle) |threshold| {
            if (elapsed(self.last_write, now, threshold)) {
                self.last_write = now;
                self.writer_count += 1;
                fire(ctx, .{ .state = .writer_idle, .count = self.writer_count });
            }
        }
        if (self.options.all_idle) |threshold| {
            const quietest = later(self.last_read, self.last_write);
            if (elapsed(quietest, now, threshold)) {
                self.last_read = now;
                self.last_write = now;
                self.all_count += 1;
                fire(ctx, .{ .state = .all_idle, .count = self.all_count });
            }
        }
    }

    fn fire(ctx: *HandlerContext, event: IdleStateEvent) void {
        var payload = event;
        ctx.fireEvent(.init(&payload));
    }

    /// Whether `threshold` has passed since `since`. An absent `since` means no
    /// traffic has been seen at all, which counts as idle.
    fn elapsed(since: ?Io.Timestamp, now: Io.Timestamp, threshold: Io.Duration) bool {
        const start = since orelse return true;
        return start.durationTo(now).toNanoseconds() >= threshold.toNanoseconds();
    }

    fn later(a: ?Io.Timestamp, b: ?Io.Timestamp) ?Io.Timestamp {
        const first = a orelse return b;
        const second = b orelse return first;
        return if (first.toNanoseconds() >= second.toNanoseconds()) first else second;
    }
};

/// Closes the connection when an `IdleStateEvent` of the configured kinds
/// arrives, reporting `error.ReadTimeout` or `error.WriteTimeout` first.
///
/// Netty packages this as `ReadTimeoutHandler` / `WriteTimeoutHandler`. Here it
/// is a separate handler placed *after* an `IdleStateHandler`, because that is
/// what the pipeline actually requires: the idle handler fires its event
/// downstream, so whatever reacts to it has to be downstream. Wrapping one
/// inside the other would look tidier and never fire.
pub const IdleCloser = struct {
    /// Which idle kinds end the connection.
    on: std.EnumSet(IdleState),
    /// How many consecutive events to tolerate before closing. 1 closes on the
    /// first; 2 leaves room for a keepalive handler to try a ping first.
    tolerate: u32 = 1,
    closed: bool = false,

    pub const handler_name = "idle-closer";

    pub fn init(on: []const IdleState) IdleCloser {
        return .{ .on = .initMany(on) };
    }

    pub fn onEvent(self: *IdleCloser, ctx: *HandlerContext, event: Event) Error!void {
        const idle = event.get(IdleStateEvent) orelse {
            ctx.fireEvent(event);
            return;
        };
        if (!self.on.contains(idle.state) or idle.count < self.tolerate or self.closed) {
            ctx.fireEvent(event);
            return;
        }

        self.closed = true;
        ctx.fireError(switch (idle.state) {
            .reader_idle => error.ReadTimeout,
            .writer_idle => error.WriteTimeout,
            .all_idle => error.IdleTimeout,
        });
        ctx.close() catch {};
    }
};

/// Installs idle detection that ends the connection after `timeout` with no
/// inbound traffic — Netty's `ReadTimeoutHandler`, assembled from its parts.
pub fn addReadTimeout(pipeline: *Pipeline, timeout: Io.Duration) !void {
    const gpa = pipeline.gpa;

    const idle = try gpa.create(IdleStateHandler);
    errdefer gpa.destroy(idle);
    idle.* = .init(.{ .reader_idle = timeout });
    _ = try pipeline.addLast("idle-state", .initOwned(idle));

    const closer = try gpa.create(IdleCloser);
    errdefer gpa.destroy(closer);
    closer.* = .init(&.{.reader_idle});
    _ = try pipeline.addLast("idle-closer", .initOwned(closer));
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

/// Records idle events so a test can assert on them.
const IdleRecorder = struct {
    events: std.ArrayList(IdleStateEvent) = .empty,
    gpa: std.mem.Allocator,

    pub const handler_name = "idle-recorder";

    pub fn onEvent(self: *IdleRecorder, ctx: *HandlerContext, event: Event) Error!void {
        if (event.get(IdleStateEvent)) |idle| {
            try self.events.append(self.gpa, idle.*);
        }
        ctx.fireEvent(event);
    }

    pub fn deinit(self: *IdleRecorder, gpa: std.mem.Allocator) void {
        self.events.deinit(gpa);
    }
};

test "IdleStateHandler: reports reader idleness once per threshold" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pipeline = try Pipeline.create(.{ .gpa = gpa, .io = io, .sink = nullSink() });
    defer pipeline.destroy();

    var idle: IdleStateHandler = .init(.{ .reader_idle = .fromMilliseconds(10) });
    _ = try pipeline.addLast("idle", .init(&idle));
    var recorder: IdleRecorder = .{ .gpa = gpa };
    defer recorder.deinit(gpa);
    _ = try pipeline.addLast("recorder", .init(&recorder));

    // Pretend the connection just became active, then that time passed.
    pipeline.fireActive();
    idle.last_read = Io.Timestamp.now(io, .awake).subDuration(.fromMilliseconds(50));

    var tick: Channel.Tick = .{ .at = Io.Timestamp.now(io, .awake) };
    pipeline.fireEvent(.init(&tick));

    try testing.expectEqual(@as(usize, 1), recorder.events.items.len);
    try testing.expectEqual(IdleState.reader_idle, recorder.events.items[0].state);
    try testing.expectEqual(@as(u32, 1), recorder.events.items[0].count);

    // A tick right after the last one is inside the threshold again, because
    // firing reset the clock. No second event.
    var again: Channel.Tick = .{ .at = Io.Timestamp.now(io, .awake) };
    pipeline.fireEvent(.init(&again));
    try testing.expectEqual(@as(usize, 1), recorder.events.items.len);
}

test "IdleStateHandler: the count grows while the quiet continues" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pipeline = try Pipeline.create(.{ .gpa = gpa, .io = io, .sink = nullSink() });
    defer pipeline.destroy();

    var idle: IdleStateHandler = .init(.{ .reader_idle = .fromMilliseconds(10) });
    _ = try pipeline.addLast("idle", .init(&idle));
    var recorder: IdleRecorder = .{ .gpa = gpa };
    defer recorder.deinit(gpa);
    _ = try pipeline.addLast("recorder", .init(&recorder));

    pipeline.fireActive();

    var round: usize = 0;
    while (round < 3) : (round += 1) {
        idle.last_read = Io.Timestamp.now(io, .awake).subDuration(.fromMilliseconds(50));
        var tick: Channel.Tick = .{ .at = Io.Timestamp.now(io, .awake) };
        pipeline.fireEvent(.init(&tick));
    }

    try testing.expectEqual(@as(usize, 3), recorder.events.items.len);
    try testing.expectEqual(@as(u32, 1), recorder.events.items[0].count);
    try testing.expectEqual(@as(u32, 2), recorder.events.items[1].count);
    try testing.expectEqual(@as(u32, 3), recorder.events.items[2].count);
}

test "IdleStateHandler: traffic resets the counter" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pipeline = try Pipeline.create(.{ .gpa = gpa, .io = io, .sink = nullSink() });
    defer pipeline.destroy();

    var idle: IdleStateHandler = .init(.{ .reader_idle = .fromMilliseconds(10) });
    _ = try pipeline.addLast("idle", .init(&idle));
    var recorder: IdleRecorder = .{ .gpa = gpa };
    defer recorder.deinit(gpa);
    _ = try pipeline.addLast("recorder", .init(&recorder));

    pipeline.fireActive();

    idle.last_read = Io.Timestamp.now(io, .awake).subDuration(.fromMilliseconds(50));
    var first: Channel.Tick = .{ .at = Io.Timestamp.now(io, .awake) };
    pipeline.fireEvent(.init(&first));
    try testing.expectEqual(@as(u32, 1), recorder.events.items[0].count);

    // A read arrives, so the next idle period starts from 1 again.
    pipeline.fireRead(try Message.initBytes(gpa, "data"));
    idle.last_read = Io.Timestamp.now(io, .awake).subDuration(.fromMilliseconds(50));
    var second: Channel.Tick = .{ .at = Io.Timestamp.now(io, .awake) };
    pipeline.fireEvent(.init(&second));

    try testing.expectEqual(@as(usize, 2), recorder.events.items.len);
    try testing.expectEqual(@as(u32, 1), recorder.events.items[1].count);
}

test "IdleStateHandler: a tick is consumed, not forwarded" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pipeline = try Pipeline.create(.{ .gpa = gpa, .io = io, .sink = nullSink() });
    defer pipeline.destroy();

    var idle: IdleStateHandler = .init(.{ .reader_idle = .fromSeconds(3600) });
    _ = try pipeline.addLast("idle", .init(&idle));

    var seen: TickCounter = .{};
    _ = try pipeline.addLast("counter", .init(&seen));

    pipeline.fireActive();
    var tick: Channel.Tick = .{ .at = Io.Timestamp.now(io, .awake) };
    pipeline.fireEvent(.init(&tick));

    try testing.expectEqual(@as(usize, 0), seen.ticks);
}

const TickCounter = struct {
    ticks: usize = 0,

    pub const handler_name = "tick-counter";

    pub fn onEvent(self: *TickCounter, ctx: *HandlerContext, event: Event) Error!void {
        if (event.is(Channel.Tick)) self.ticks += 1;
        ctx.fireEvent(event);
    }
};

/// A sink that records whether it was closed, for the composition test below.
const CloseWatch = struct {
    closed: bool = false,

    fn sink(self: *CloseWatch) pipeline_mod.Sink {
        return .{ .context = self, .vtable = &.{
            .write = nullWrite,
            .flush = watchFlush,
            .close = watchClose,
        } };
    }

    fn watchFlush(_: *anyopaque) Error!void {}

    fn watchClose(context: *anyopaque) Error!void {
        const self: *CloseWatch = @ptrCast(@alignCast(context));
        self.closed = true;
    }
};

test "addReadTimeout: a quiet reader ends the connection" {
    // The composition README promises as Netty's ReadTimeoutHandler. It was
    // written, documented, and never called or tested — so nothing established
    // that the two handlers it installs are in the right order, or that the
    // closer listens for the kind of idleness the state handler reports.
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var watch: CloseWatch = .{};
    var pipeline = try Pipeline.create(.{ .gpa = gpa, .io = io, .sink = watch.sink() });
    defer pipeline.destroy();

    try addReadTimeout(pipeline, .fromMilliseconds(10));
    pipeline.fireActive();

    // Real time rather than a reached-in `last_read`, because the point is to drive
    // the composition the way an application does — the handlers it installs are
    // owned by the pipeline and not reachable from here, which is itself the reason
    // this went untested.
    try io.sleep(.fromMilliseconds(25), .awake);
    var tick: Channel.Tick = .{ .at = Io.Timestamp.now(io, .awake) };
    pipeline.fireEvent(.init(&tick));

    try testing.expect(watch.closed);
}

fn nullSink() pipeline_mod.Sink {
    return .{ .context = undefined, .vtable = &.{
        .write = nullWrite,
        .flush = nullFlush,
        .close = nullFlush,
    } };
}

fn nullWrite(_: *anyopaque, msg: Message) Error!void {
    var owned = msg;
    owned.deinit(testing.allocator);
}

fn nullFlush(_: *anyopaque) Error!void {}
