//! A connection: a socket, its pipeline, and the two tasks that drive them.
//!
//! # Threading model
//!
//! Netty binds every channel to one event loop thread, which is what makes its
//! handlers lock free. Zinet gets the same guarantee from a different
//! mechanism: **one reader task per channel**. Every inbound event and every
//! handler callback runs in that task, so handler state needs no
//! synchronization at all.
//!
//! A second task owns the socket's write side and consumes an `Io.Queue`. That
//! costs one more task per connection and buys two things: writes from any
//! task (a chat server broadcasting to its peers), and natural backpressure —
//! when the queue is full, producers block instead of growing memory without
//! bound.
//!
//! Whether that second task is worth its cost has been measured rather than argued. A
//! variant that removed it — writing straight to the socket from whichever task called
//! `write`, with no queue and no writer task — was built, benchmarked and thrown away:
//!
//! * one connection, 64-byte echo: 17.9 k round trips/s and 56 µs against 16.8 k and 60 µs,
//!   so about 6 % and 4 µs;
//! * thirty-two connections: 44.5 k round trips/s against 45.4 k — no gain, marginally worse.
//!
//! The queue hop is not what limits this path; the syscalls are. And the price of keeping the
//! variant would have been two implementations of "how a write reaches the socket", which is
//! the shape this codebase has found drifting apart more often than any other, plus the
//! ordering guarantee that `close` travels the same queue as writes — the reason there is no
//! `ChannelPromise` here at all. Six percent at a concurrency of one does not buy that.
//!
//! ```
//!  reader task                        writer task
//!  -----------                        -----------
//!  read() -> Buffer                   getOne() <- outbound queue
//!    |                                  |
//!    v                                  v
//!  pipeline.fireRead  --(handlers)--> channel.write -> queue
//!                                     write()/flush() -> socket
//! ```
//!
//! # Lifetime
//!
//! A channel is reference counted. `serve` holds one reference for the whole
//! connection and, when its read loop ends, dismantles the pipeline and closes
//! the socket — but the memory is only released once the last reference goes.
//!
//! That split is what makes cross-task writes safe. A task that wants to keep
//! writing to a channel it does not own — a chat server holding its peers —
//! calls `retain` from inside a handler callback and `release` when done. Its
//! writes then either reach the socket or fail with `error.ChannelClosed`;
//! neither outcome touches freed memory.
//!
//! Holding a raw `*Channel` without a reference is the one thing that is not
//! allowed.

const std = @import("std");
const backend = @import("backend");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Buffer = @import("buffer.zig").Buffer;
const BufferPool = @import("pool.zig").BufferPool;
const pipeline_mod = @import("pipeline.zig");

const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;

/// Populates a fresh pipeline. Netty calls this a `ChannelInitializer`.
///
/// Invoked once per connection, from the channel's own task, before the
/// channel becomes active.
pub const Initializer = struct {
    context: *anyopaque,
    initFn: *const fn (context: *anyopaque, pipeline: *Pipeline) anyerror!void,

    /// Wraps a type with `fn initPipeline(self: *T, pipeline: *Pipeline) !void`.
    pub fn init(instance: anytype) Initializer {
        const Pointer = @TypeOf(instance);
        const info = @typeInfo(Pointer);
        comptime assert(info == .pointer and info.pointer.size == .one);
        const T = info.pointer.child;
        return .{
            .context = instance,
            .initFn = struct {
                fn call(context: *anyopaque, pipeline: *Pipeline) anyerror!void {
                    const self: *T = @ptrCast(@alignCast(context));
                    return self.initPipeline(pipeline);
                }
            }.call,
        };
    }

    /// Wraps a plain function, for initializers with no state of their own.
    pub fn initFunction(
        comptime function: fn (pipeline: *Pipeline) anyerror!void,
    ) Initializer {
        return .{
            .context = undefined,
            .initFn = struct {
                fn call(_: *anyopaque, pipeline: *Pipeline) anyerror!void {
                    return function(pipeline);
                }
            }.call,
        };
    }

    pub fn apply(initializer: Initializer, pipeline: *Pipeline) anyerror!void {
        return initializer.initFn(initializer.context, pipeline);
    }
};

/// One TCP connection.
pub const Channel = struct {
    gpa: Allocator,
    io: Io,
    stream: Io.net.Stream,
    /// Embedded, not a pointer: a channel always lives on the heap, so the
    /// pipeline's self-references stay valid, and one allocation is saved.
    pipeline: Pipeline,
    options: Options,

    /// Scratch space for the socket's buffered writer.
    write_buffer: []u8,
    /// Ring storage backing `outbound`.
    outbound_storage: []Outbound,
    outbound: Io.Queue(Outbound),

    state: std.atomic.Value(State),
    /// Outstanding references. `serve` holds one for the connection's whole
    /// life; anything that wants to keep the channel addressable past that must
    /// hold one too.
    ///
    /// This is what makes "write from any task" a real guarantee rather than a
    /// race. Without it, `serve` frees the channel the moment its peer
    /// disconnects, and a broadcaster still holding the pointer — the chat
    /// server case — reads freed memory. Netty reaches the same place by
    /// reference counting its channels.
    refs: std.atomic.Value(u32),
    stats: Stats,

    /// Effective tick interval. Starts at `options.tick_interval` and can only
    /// be lowered, by `requestTick`.
    ///
    /// A plain field rather than an atomic on purpose: it is read by the reader
    /// task and written only from handler callbacks, which run on that same
    /// task. Making it atomic would suggest a cross-task contract that does not
    /// exist.
    tick_interval: ?Io.Duration,

    /// Items queued for the writer task. Tracked here because `Io.Queue` does
    /// not publish its length, and reading its internals without its lock would
    /// be a race.
    pending: std.atomic.Value(u32),

    /// Ring storage backing `tasks`. Empty when task hopping is off.
    tasks_storage: []Task,
    /// Work handed to the reader task by other tasks. See `submit`.
    tasks: Io.Queue(Task),
    /// Counterpart of `pending`, for the task queue.
    pending_tasks: std.atomic.Value(u32),

    pub const State = enum(u8) {
        /// Reading and writing.
        open,
        /// A close has been requested; queued writes are still being drained.
        closing,
        /// Both tasks have finished.
        closed,
    };

    pub const Options = struct {
        gpa: Allocator,
        io: Io,
        stream: Io.net.Stream,
        /// Builds the pipeline for this connection.
        initializer: ?Initializer = null,
        /// Handle the pipeline hands to handlers as `ctx.owner()`. Defaults to
        /// the channel itself.
        owner: ?*anyopaque = null,
        /// Bytes requested per socket read. Also the size of each inbound
        /// `Buffer`.
        read_chunk: usize = 16 * 1024,
        /// Ceiling for an inbound buffer, which a decoder may grow while
        /// accumulating a frame.
        max_inbound_capacity: usize = Buffer.default_max_capacity,
        /// Scratch size for the socket's buffered writer.
        write_buffer_capacity: usize = 16 * 1024,
        /// Queued outbound items before producers block. This is the
        /// connection's write backpressure knob.
        outbound_capacity: usize = 64,
        /// How often the connection wakes itself to fire a `Tick`, even with no
        /// traffic. Null means never, which is also what costs nothing.
        ///
        /// This is Zinet's whole time dimension, and it is deliberately thin:
        /// handlers that care about time (`IdleStateHandler`) build on ticks
        /// rather than on a scheduler. See `Tick`.
        tick_interval: ?Io.Duration = null,
        /// Submitted tasks the queue holds before `submit` starts refusing.
        /// Zero, the default, disables task hopping entirely and costs nothing.
        ///
        /// See `submit` for why this queue refuses rather than blocks.
        task_capacity: usize = 0,
        /// Longest the reader may stay blocked in a read before it looks for
        /// submitted tasks. Only consulted when `task_capacity` is non-zero.
        ///
        /// This is the latency a submitted task can face on an idle connection,
        /// and it is a straight trade: a shorter interval wakes the reader more
        /// often for nothing. On a connection that is receiving data, tasks run
        /// as soon as the read in progress completes, so this bound only binds
        /// when the peer is silent.
        task_wake_interval: Io.Duration = .fromMilliseconds(10),
        /// Optional recycler for inbound buffers.
        pool: ?*BufferPool = null,
    };

    pub const Stats = struct {
        bytes_read: u64 = 0,
        bytes_written: u64 = 0,
        reads: u64 = 0,
        writes: u64 = 0,
        flushes: u64 = 0,
    };

    /// An item in the outbound queue. Ordering between data, flushes and the
    /// close is preserved because they all travel through the same queue.
    pub const Outbound = union(enum) {
        data: Message,
        flush: void,
        /// Flush what is queued, then shut the connection down.
        close: void,
    };

    /// Work for the reader task, submitted by some other task.
    ///
    /// This is Zinet's answer to Netty's `EventLoop.execute`, and it exists
    /// because `Pipeline` is single-task by construction: propagation walks the
    /// chain through plain fields, so entering it from two tasks at once would
    /// corrupt it. `Channel.write` sidesteps the pipeline — which is exactly
    /// what makes it callable from anywhere — but that also means it skips every
    /// encoder in the chain. For anything that needs the pipeline, the work has
    /// to travel to the reader task instead of the other way round.
    pub const Task = union(enum) {
        /// Send `msg` through the outbound half of the pipeline, then flush.
        write: Message,
        /// Close through the pipeline rather than under it.
        ///
        /// Worth having on its own: `requestClose` shuts the connection down
        /// without telling the handlers, so a protocol with a closing handshake
        /// — WebSocket's is the example — never gets to perform it. This close
        /// goes through `onClose`, so it does.
        close: void,
        /// Run an arbitrary callback on the reader task.
        run: Callback,

        pub const Callback = struct {
            function: *const fn (*Channel, ?*anyopaque) void,
            context: ?*anyopaque = null,
        };

        /// Releases whatever the task owns. A task that is never run has to be
        /// disposed of, and only the `.write` variant owns anything.
        pub fn deinit(task: *Task, gpa: Allocator) void {
            switch (task.*) {
                .write => |*msg| msg.deinit(gpa),
                .close, .run => {},
            }
            task.* = .close;
        }
    };

    /// Fired as a pipeline event when `tick_interval` elapses without the read
    /// loop having anything better to do.
    ///
    /// Netty gets its time dimension from `EventLoop.schedule`, because a Netty
    /// event loop is a thread that already multiplexes I/O and timers. Zinet's
    /// connections instead block in a read, so there is no loop to hang a timer
    /// on — and starting a *second* task to run timers would be worse than
    /// useless: it would deliver callbacks off the reader task and so destroy
    /// the property that makes handler state lock free.
    ///
    /// So the read itself carries the deadline, and the tick is delivered by the
    /// reader task between reads. Everything time-related is then an ordinary
    /// handler reacting to an ordinary event.
    ///
    /// Ticks are not a precise clock. One arrives no earlier than the interval
    /// and, because a tick cannot interrupt a handler, possibly much later.
    /// Anything comparing timestamps must read the clock rather than counting
    /// ticks.
    pub const Tick = struct {
        /// When the reader task noticed the deadline had passed.
        at: Io.Timestamp,
    };

    pub const Error = error{
        /// The channel is shutting down or already closed.
        ChannelClosed,
        /// `submit` was called on a channel created with `task_capacity` zero.
        TaskHoppingDisabled,
        /// The task queue is full. See `submit` for why this is reported rather
        /// than waited out.
        TaskQueueFull,
    } || Allocator.Error;

    /// Allocates a channel and its pipeline. Takes ownership of
    /// `options.stream`.
    ///
    /// On success, the caller must arrange for exactly one call to `serve`,
    /// which consumes the channel. On failure, the stream is left untouched for
    /// the caller to close.
    pub fn create(options: Options) Allocator.Error!*Channel {
        assert(options.read_chunk > 0);
        assert(options.outbound_capacity > 0);

        const gpa = options.gpa;
        const channel = try gpa.create(Channel);
        errdefer gpa.destroy(channel);

        const write_buffer = try gpa.alloc(u8, options.write_buffer_capacity);
        errdefer gpa.free(write_buffer);

        const outbound_storage = try gpa.alloc(Outbound, options.outbound_capacity);
        errdefer gpa.free(outbound_storage);

        // Zero-length when task hopping is off, which makes the queue's capacity
        // zero and every `submit` refuse — the same answer the explicit check in
        // `submit` gives, so the two cannot disagree.
        const tasks_storage = try gpa.alloc(Task, options.task_capacity);
        errdefer gpa.free(tasks_storage);

        channel.* = .{
            .gpa = gpa,
            .io = options.io,
            .stream = options.stream,
            .pipeline = undefined,
            .options = options,
            .write_buffer = write_buffer,
            .outbound_storage = outbound_storage,
            .outbound = .init(outbound_storage),
            .state = .init(.open),
            .refs = .init(1),
            .stats = .{},
            .tick_interval = options.tick_interval,
            .pending = .init(0),
            .tasks_storage = tasks_storage,
            .tasks = .init(tasks_storage),
            .pending_tasks = .init(0),
        };

        try channel.pipeline.init(.{
            .gpa = gpa,
            .io = options.io,
            .sink = channel.sink(),
            .owner = options.owner orelse channel,
        });
        return channel;
    }

    /// Releases a channel that was created but never served.
    ///
    /// Once `serve` has been scheduled it owns the channel; use `release`.
    pub fn destroy(channel: *Channel) void {
        assert(channel.refs.load(.acquire) == 1);
        channel.pipeline.deinit();
        channel.release();
    }

    /// Claims a reference, so the channel stays addressable even after its
    /// connection ends.
    ///
    /// Only legal while already holding one — from inside one of this channel's
    /// own handler callbacks, for instance, which by definition run while
    /// `serve` holds its reference. Every `retain` needs a matching `release`.
    ///
    /// A retained channel whose connection has ended is safe but inert: it
    /// reports `closed`, and `write` fails with `error.ChannelClosed` rather
    /// than touching a socket that is gone.
    pub fn retain(channel: *Channel) void {
        const previous = channel.refs.fetchAdd(1, .acq_rel);
        assert(previous > 0); // Retaining from nothing means the pointer is stale.
    }

    /// Drops a reference, freeing the channel with the last one.
    pub fn release(channel: *Channel) void {
        const previous = channel.refs.fetchSub(1, .acq_rel);
        assert(previous > 0);
        if (previous != 1) return;

        const gpa = channel.gpa;
        gpa.free(channel.write_buffer);
        gpa.free(channel.outbound_storage);
        gpa.free(channel.tasks_storage);
        gpa.destroy(channel);
    }

    pub fn referenceCount(channel: *const Channel) u32 {
        return channel.refs.load(.acquire);
    }

    /// Ends the connection: no more I/O, and the pipeline is dismantled.
    ///
    /// Deliberately separate from freeing the memory. Another task may still
    /// hold a reference and call `write`, which must find a coherent — if
    /// closed — channel rather than a freed one. The queue's storage in
    /// particular has to outlive this, because a producer may be blocked inside
    /// `putOne` when the connection ends.
    fn teardown(channel: *Channel) void {
        const io = channel.io;
        channel.state.store(.closed, .release);
        channel.outbound.close(io);
        channel.tasks.close(io);
        channel.stream.close(io);
        channel.pipeline.deinit();
    }

    fn sink(channel: *Channel) Sink {
        return .{ .context = channel, .vtable = &sink_vtable };
    }

    const sink_vtable: Sink.VTable = .{
        .write = sinkWrite,
        .flush = sinkFlush,
        .close = sinkClose,
    };

    fn sinkWrite(context: *anyopaque, msg: Message) pipeline_mod.Error!void {
        const channel: *Channel = @ptrCast(@alignCast(context));
        return channel.write(msg);
    }

    fn sinkFlush(context: *anyopaque) pipeline_mod.Error!void {
        const channel: *Channel = @ptrCast(@alignCast(context));
        return channel.flush();
    }

    fn sinkClose(context: *anyopaque) pipeline_mod.Error!void {
        const channel: *Channel = @ptrCast(@alignCast(context));
        channel.requestClose();
        return {};
    }

    // -- Public API --------------------------------------------------------

    pub fn isOpen(channel: *const Channel) bool {
        return channel.state.load(.acquire) == .open;
    }

    pub fn currentState(channel: *const Channel) State {
        return channel.state.load(.acquire);
    }

    /// Asks for ticks at least this often, lowering the interval if a handler
    /// has already asked for a coarser one.
    ///
    /// Only legal from this channel's own handler callbacks — including
    /// `onAdded` while the pipeline is being built, which is where handlers that
    /// need ticks should call it. Those all run on the reader task, which is the
    /// only reader of the field.
    pub fn requestTick(channel: *Channel, interval: Io.Duration) void {
        assert(interval.toNanoseconds() > 0);
        if (channel.tick_interval) |current| {
            if (current.toNanoseconds() <= interval.toNanoseconds()) return;
        }
        channel.tick_interval = interval;
    }

    /// Messages and flushes waiting for the writer task.
    ///
    /// The honest version of Netty's `isWritable`. Netty needs water marks
    /// because its write queue is unbounded, so the application has to be told
    /// when to stop; Zinet's queue is bounded and blocks the producer instead,
    /// which is backpressure that cannot be ignored. What is still worth
    /// exposing is how close to blocking a writer is.
    pub fn pendingOutbound(channel: *const Channel) usize {
        return channel.pending.load(.monotonic);
    }

    /// Whether a `write` can be expected not to block.
    ///
    /// Advisory only: another task may fill the queue between the check and the
    /// write. Treat it as a hint for shedding load, not as a lock.
    pub fn isWritable(channel: *const Channel) bool {
        return channel.isOpen() and
            channel.pendingOutbound() < channel.options.outbound_capacity;
    }

    /// Queues `msg` for transmission, taking ownership of it. Blocks while the
    /// queue is full. Safe to call from any task that holds a reference.
    ///
    /// The message is released whether or not this succeeds. Once the
    /// connection has ended this fails with `error.ChannelClosed` instead of
    /// touching the socket, so a broadcaster does not have to know which of its
    /// peers are still there.
    pub fn write(channel: *Channel, msg: Message) Error!void {
        var owned = msg;
        if (!channel.isOpen()) {
            owned.deinit(channel.gpa);
            return error.ChannelClosed;
        }
        channel.outbound.putOne(channel.io, .{ .data = owned }) catch |err| {
            owned.deinit(channel.gpa);
            return switch (err) {
                error.Closed, error.Canceled => error.ChannelClosed,
            };
        };
        _ = channel.pending.fetchAdd(1, .monotonic);
    }

    /// Asks the writer task to push queued bytes to the socket.
    pub fn flush(channel: *Channel) Error!void {
        return channel.enqueueSignal(.flush);
    }

    /// Queues a graceful shutdown: pending writes are flushed, then the socket
    /// is shut down in both directions, which ends the reader task too.
    ///
    /// Idempotent and safe to call from any task.
    pub fn requestClose(channel: *Channel) void {
        if (channel.state.cmpxchgStrong(.open, .closing, .acq_rel, .acquire) != null) return;
        channel.enqueueSignal(.close) catch {
            // The writer is already gone; shut the socket down directly so the
            // reader task cannot block forever.
            channel.stream.shutdown(channel.io, .both) catch {};
        };
    }

    fn enqueueSignal(channel: *Channel, item: Outbound) Error!void {
        assert(item != .data);
        channel.outbound.putOne(channel.io, item) catch |err| switch (err) {
            error.Closed, error.Canceled => return error.ChannelClosed,
        };
        _ = channel.pending.fetchAdd(1, .monotonic);
    }

    // -- Task hopping ------------------------------------------------------

    /// Hands `task` to the reader task. Safe to call from any task that holds a
    /// reference. See `Task`.
    ///
    /// **Does not block.** A full queue is `error.TaskQueueFull`, and that is a
    /// deliberate difference from `write`, which blocks. The two queues are
    /// drained by different tasks and that changes what waiting means:
    ///
    /// * The outbound queue is drained by a task that does nothing but write to
    ///   a socket, so blocking on it is real backpressure — the peer is slow.
    /// * This queue is drained by the reader task, which may legitimately sit
    ///   blocked in a read for as long as the peer chooses to stay silent.
    ///   Blocking here would tie the producer's progress to the peer's chatter,
    ///   and worse, a handler submitting from the reader task itself would
    ///   deadlock against a queue only it can drain.
    ///
    /// So the caller is told, and decides. Refusing needs no extra machinery
    /// either: `Io.Queue.put` with a minimum of zero is defined to enqueue what
    /// fits without waiting.
    ///
    /// Takes ownership of the task either way. A rejected `.write` has its
    /// message released here, matching `Sink.write` and `Channel.write`: a
    /// caller that has handed a message over never has to wonder whether it got
    /// it back.
    pub fn submit(channel: *Channel, task: Task) Error!void {
        var owned = task;
        errdefer owned.deinit(channel.gpa);

        if (channel.options.task_capacity == 0) return error.TaskHoppingDisabled;
        if (!channel.isOpen()) return error.ChannelClosed;

        const accepted = channel.tasks.put(channel.io, &.{owned}, 0) catch |err| switch (err) {
            error.Closed, error.Canceled => return error.ChannelClosed,
        };
        if (accepted == 0) return error.TaskQueueFull;
        assert(accepted == 1);
        // The queue holds the only copy from here on, so the local must not be
        // released: neutralize it rather than relying on the errdefer not firing.
        owned = .close;
        _ = channel.pending_tasks.fetchAdd(1, .monotonic);
    }

    /// Sends `msg` through the pipeline from another task, taking ownership.
    ///
    /// This is the point of the whole facility: unlike `write`, the message
    /// passes through every outbound handler, so a client can hand a request to
    /// its encoder from the task that built it.
    ///
    /// The message is released whether or not this succeeds, matching `write`.
    pub fn submitWrite(channel: *Channel, msg: Message) Error!void {
        return channel.submit(.{ .write = msg });
    }

    /// Closes through the pipeline from another task, so protocols with a
    /// closing handshake get to perform it. Contrast `requestClose`.
    pub fn submitClose(channel: *Channel) Error!void {
        return channel.submit(.close);
    }

    /// Submitted tasks not yet run.
    pub fn pendingTasks(channel: *const Channel) usize {
        return channel.pending_tasks.load(.acquire);
    }

    /// Runs everything queued, on the reader task.
    ///
    /// Called between reads, never from inside a handler callback, so the
    /// pipeline is always at depth zero here and a submitted write cannot
    /// interleave with an inbound propagation.
    fn runTasks(channel: *Channel) void {
        assert(channel.pipeline.depth == 0);
        while (true) {
            // Non-blocking: stop as soon as the queue is empty rather than
            // waiting for more work, because the reader task has a socket to get
            // back to.
            var one: [1]Task = undefined;
            const got = channel.tasks.get(channel.io, &one, 0) catch return;
            if (got == 0) return;
            _ = channel.pending_tasks.fetchSub(1, .monotonic);

            switch (one[0]) {
                .write => |msg| {
                    var owned = msg;
                    channel.pipeline.write(owned.move()) catch |err| {
                        channel.pipeline.fireError(err);
                        continue;
                    };
                    channel.pipeline.flush() catch |err| channel.pipeline.fireError(err);
                },
                .close => channel.pipeline.close() catch |err| channel.pipeline.fireError(err),
                .run => |callback| callback.function(channel, callback.context),
            }
        }
    }

    /// Frees whatever is left in the task queue. Must only run once the queue is
    /// closed, and after the reader task has stopped, so nothing is executed
    /// here — a task submitted to a connection that has ended is dropped.
    fn drainTasks(channel: *Channel) void {
        while (true) {
            var one: [1]Task = undefined;
            const got = channel.tasks.getUncancelable(channel.io, &one, 0) catch return;
            if (got == 0) return;
            _ = channel.pending_tasks.fetchSub(1, .monotonic);
            one[0].deinit(channel.gpa);
        }
    }

    // -- Task bodies -------------------------------------------------------

    /// Top-level body of a channel's task. Consumes the channel.
    ///
    /// Runs the pipeline's whole lifecycle: build it, announce the connection,
    /// pump reads until the peer or an error ends them, then tear everything
    /// down in the reverse order.
    pub fn serve(channel: *Channel) void {
        const io = channel.io;
        // Declared first so it runs last: the channel's memory outlives its
        // connection whenever another task still holds a reference.
        defer channel.release();
        // Ordered between the two on purpose: the queue has to be closed before
        // a drain can terminate, and its storage has to outlive the drain.
        defer channel.drainTasks();
        defer channel.teardown();

        if (channel.options.initializer) |initializer| {
            initializer.apply(&channel.pipeline) catch |err| {
                channel.pipeline.fireError(err);
                return;
            };
        }

        var writer_future = io.concurrent(writeLoop, .{channel}) catch |err| {
            // Without a second unit of concurrency there is no write side, so
            // the connection cannot be served.
            channel.pipeline.fireError(err);
            return;
        };

        channel.pipeline.fireActive();
        channel.readLoop();
        channel.pipeline.fireInactive();

        // Let the writer drain what is already queued, then stop it. `cancel`
        // rather than `await` bounds teardown: a peer that stopped reading must
        // not be able to hold the connection open forever.
        channel.outbound.close(io);
        writer_future.cancel(io);
        channel.state.store(.closed, .release);
    }

    /// Reads until end of stream, a failure, or cancelation, firing every
    /// chunk into the pipeline.
    fn readLoop(channel: *Channel) void {
        const io = channel.io;
        // An unbuffered reader lands socket bytes straight in the inbound buffer, so
        // there is no intermediate copy — and, less obviously, so that there is
        // nowhere for received bytes to hide.
        //
        // `Io.Reader.readVec` reports through the reader's own buffer whenever that
        // buffer has more room than the destination, returning zero while having
        // stored the bytes (`defaultReadVec`). A loop that reads the return value and
        // ignores the buffer would then hold a delivered reply until more arrived —
        // which is exactly the defect the TLS client had, where the reader is
        // `tls.Client`'s and buffering is not optional. Here it is optional, and the
        // choice is load-bearing rather than an optimisation, so it is asserted.
        var reader = channel.stream.reader(io, &.{});
        assert(reader.interface.buffer.len == 0);

        var chunk: ?Buffer = null;
        defer if (chunk) |*pending| channel.releaseInbound(pending);

        // Absolute rather than per-read, so ticks keep a steady cadence instead
        // of being pushed back by every arriving byte.
        var next_tick: ?Io.Timestamp = if (channel.tick_interval) |interval|
            Io.Timestamp.now(io, .awake).addDuration(interval)
        else
            null;

        // A second, independent deadline. Sharing one with ticks would tie two
        // unrelated cadences together: a connection wanting prompt task delivery
        // would start firing tick events at that rate, and one wanting a slow
        // idle check would delay its tasks by minutes.
        const wake_interval: ?Io.Duration = if (channel.options.task_capacity > 0)
            channel.options.task_wake_interval
        else
            null;
        var next_wake: ?Io.Timestamp = if (wake_interval) |interval|
            Io.Timestamp.now(io, .awake).addDuration(interval)
        else
            null;

        while (channel.isOpen()) {
            // Before blocking again, and after every completed read: on a busy
            // connection this is what makes submitted work prompt, leaving the
            // wake interval to cover only a silent peer.
            if (channel.options.task_capacity > 0) channel.runTasks();

            if (chunk == null) {
                chunk = channel.acquireInbound() catch |err| {
                    channel.pipeline.fireError(err);
                    return;
                };
            }

            var destination: [1][]u8 = .{chunk.?.writableSlice()};
            assert(destination[0].len > 0);

            var n: usize = undefined;
            if (earlier(next_tick, next_wake)) |deadline| {
                switch (channel.receiveBounded(destination[0], deadline)) {
                    .received => |count| n = count,
                    .timed_out => {
                        const now = Io.Timestamp.now(io, .awake);
                        // Either deadline may have been the one that fired, and
                        // both may be due at once.
                        if (due(next_wake, now)) {
                            next_wake = if (wake_interval) |interval|
                                now.addDuration(interval)
                            else
                                null;
                        }
                        if (due(next_tick, now)) {
                            // A handler may have asked for a different cadence
                            // since the last tick, so re-read the interval.
                            if (channel.tick_interval) |interval| {
                                next_tick = now.addDuration(interval);
                                var tick: Tick = .{ .at = now };
                                channel.pipeline.fireEvent(.init(&tick));
                            } else {
                                next_tick = null;
                            }
                        }
                        continue;
                    },
                    .ended => {
                        channel.finishRead(error.EndOfStream, null);
                        return;
                    },
                    .failed => |cause| {
                        channel.finishRead(error.ReadFailed, cause);
                        return;
                    },
                }
            } else {
                n = reader.interface.readVec(&destination) catch |err| {
                    channel.finishRead(err, reader.err);
                    return;
                };
            }

            // Neither path can report zero. `receiveBounded` turns a zero-length
            // receive into `.ended`, because on a stream socket that is the orderly
            // shutdown; and the unbuffered `readVec` above streams straight into the
            // destination, so it cannot return zero while holding bytes back.
            //
            // This used to tolerate a run of zeroes and then declare the stream
            // broken. That guarded a case neither path produces, and it would have
            // *hidden* the one case that can: give the reader a buffer and `readVec`
            // starts returning zero with the bytes stored, at which point sixty-four
            // silent retries and an `error.Unexpected` is a far worse report than an
            // assertion naming the invariant.
            assert(n > 0);

            var ready = chunk.?;
            chunk = null;
            ready.commit(n);
            channel.stats.bytes_read += n;
            channel.stats.reads += 1;
            channel.pipeline.fireRead(.initBuffer(&ready));
            channel.pipeline.fireReadComplete();
        }
    }

    /// Whichever deadline comes first, if either exists.
    fn earlier(a: ?Io.Timestamp, b: ?Io.Timestamp) ?Io.Timestamp {
        const first = a orelse return b;
        const second = b orelse return first;
        return if (first.nanoseconds < second.nanoseconds) first else second;
    }

    /// Whether `deadline` exists and has passed.
    fn due(deadline: ?Io.Timestamp, now: Io.Timestamp) bool {
        const at = deadline orelse return false;
        return now.nanoseconds >= at.nanoseconds;
    }

    /// What a deadline-bounded read produced.
    const BoundedRead = union(enum) {
        received: usize,
        /// The deadline passed with no data. Not an error.
        timed_out,
        /// The peer shut its side down.
        ended,
        failed: Io.net.Stream.Reader.Error,
    };

    /// One read, abandoned if `deadline` passes first.
    ///
    /// Goes under `Io.net.Stream.Reader` to `net_receive`, because the reader
    /// interface has no way to express a deadline. Only reached when ticks are
    /// enabled; without them the plain reader is used, so nothing pays for this.
    fn receiveBounded(
        channel: *Channel,
        destination: []u8,
        deadline: Io.Timestamp,
    ) BoundedRead {
        assert(destination.len > 0);
        var incoming: Io.net.IncomingMessage = .init;
        const result = channel.io.operateTimeout(.{ .net_receive = .{
            .socket_handle = channel.stream.socket.handle,
            .message_buffer = (&incoming)[0..1],
            .data_buffer = destination,
            .flags = .{},
        } }, .{ .deadline = deadline.withClock(.awake) }) catch |err| switch (err) {
            error.Timeout => return .timed_out,
            error.Canceled => return .{ .failed = error.Canceled },
            error.ConcurrencyUnavailable => return .{ .failed = error.SystemResources },
        };

        const maybe_err, const count = result.net_receive;
        if (maybe_err) |err| return .{
            .failed = switch (err) {
                error.ConnectionResetByPeer => error.ConnectionResetByPeer,
                error.SocketUnconnected => error.SocketUnconnected,
                error.NetworkDown => error.NetworkDown,
                error.SystemResources,
                error.ProcessFdQuotaExceeded,
                error.SystemFdQuotaExceeded,
                => error.SystemResources,
                error.Canceled => error.Canceled,
                // `MessageOversize` and `PortUnreachable` describe datagram
                // failures that a stream socket cannot produce.
                else => error.Unexpected,
            },
        };
        assert(count == 1);

        // On a stream socket a successful receive of zero bytes is the orderly
        // shutdown, which is exactly the signal `readVec` turns into
        // `error.EndOfStream`.
        if (incoming.data.len == 0) return .ended;
        return .{ .received = incoming.data.len };
    }

    /// Classifies why the read loop stopped and reports it once.
    fn finishRead(channel: *Channel, err: anyerror, stream_err: ?Io.net.Stream.Reader.Error) void {
        switch (err) {
            error.EndOfStream => {
                // Orderly shutdown by the peer.
                _ = channel.state.cmpxchgStrong(.open, .closing, .acq_rel, .acquire);
            },
            error.ReadFailed => {
                const cause = stream_err orelse error.Unexpected;
                _ = channel.state.cmpxchgStrong(.open, .closing, .acq_rel, .acquire);
                if (cause != error.Canceled) channel.pipeline.fireError(cause);
            },
            else => {
                _ = channel.state.cmpxchgStrong(.open, .closing, .acq_rel, .acquire);
                channel.pipeline.fireError(err);
            },
        }
    }

    /// Body of the writer task: drains the outbound queue into the socket.
    fn writeLoop(channel: *Channel) void {
        const io = channel.io;
        // Declared first so it runs last: by then the queue is closed, so the
        // drain is guaranteed to terminate and every queued message is freed.
        defer channel.drainOutbound();
        defer channel.outbound.close(io);

        var writer = channel.stream.writer(io, channel.write_buffer);
        while (true) {
            var item = channel.outbound.getOne(io) catch break;
            _ = channel.pending.fetchSub(1, .monotonic);
            switch (item) {
                .data => |*msg| {
                    defer msg.deinit(channel.gpa);
                    const bytes = msg.bytes() orelse continue;
                    writer.interface.writeAll(bytes) catch break;
                    channel.stats.bytes_written += bytes.len;
                    channel.stats.writes += 1;
                },
                .flush => {
                    writer.interface.flush() catch break;
                    channel.stats.flushes += 1;
                },
                .close => {
                    writer.interface.flush() catch {};
                    // Shutting down both directions also unblocks the reader.
                    channel.stream.shutdown(io, .both) catch {};
                    break;
                },
            }
        }
        writer.interface.flush() catch {};
    }

    /// Frees whatever is left in the outbound queue. Must only run once the
    /// queue is closed, otherwise it would block waiting for new items.
    fn drainOutbound(channel: *Channel) void {
        while (true) {
            var item = channel.outbound.getOneUncancelable(channel.io) catch return;
            _ = channel.pending.fetchSub(1, .monotonic);
            switch (item) {
                .data => |*msg| msg.deinit(channel.gpa),
                .flush, .close => {},
            }
        }
    }

    fn acquireInbound(channel: *Channel) Buffer.Error!Buffer {
        const wanted = channel.options.read_chunk;
        if (channel.options.pool) |pool| {
            var pooled = try pool.acquire(wanted);
            errdefer pool.release(&pooled);
            try pooled.ensureWritable(channel.gpa, wanted);
            // The channel's ceiling applies whether or not a pool is in play.
            // Leaving the pool's own limit in force here would give one server
            // two different inbound limits depending on how it was configured.
            pooled.max_capacity = @max(pooled.capacity(), channel.options.max_inbound_capacity);
            return pooled;
        }
        return Buffer.init(channel.gpa, .{
            .capacity = wanted,
            .max_capacity = channel.options.max_inbound_capacity,
        });
    }

    fn releaseInbound(channel: *Channel, chunk: *Buffer) void {
        if (channel.options.pool) |pool| {
            pool.release(chunk);
        } else {
            chunk.deinit(channel.gpa);
        }
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "Initializer: wraps both a stateful type and a plain function" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const Recorder = struct {
        calls: usize = 0,
        pub fn initPipeline(self: *@This(), _: *Pipeline) anyerror!void {
            self.calls += 1;
        }
    };
    const Free = struct {
        var calls: usize = 0;
        fn build(_: *Pipeline) anyerror!void {
            calls += 1;
        }
    };

    const Discarding = struct {
        fn sink() Sink {
            return .{ .context = undefined, .vtable = &.{ .write = writeImpl } };
        }
        fn writeImpl(_: *anyopaque, msg: Message) pipeline_mod.Error!void {
            var owned = msg;
            owned.deinit(testing.allocator);
        }
    };

    const pipeline = try Pipeline.create(.{
        .gpa = gpa,
        .io = threaded.io(),
        .sink = Discarding.sink(),
    });
    defer pipeline.destroy();

    var recorder: Recorder = .{};
    try Initializer.init(&recorder).apply(pipeline);
    try testing.expectEqual(@as(usize, 1), recorder.calls);

    Free.calls = 0;
    try Initializer.initFunction(Free.build).apply(pipeline);
    try testing.expectEqual(@as(usize, 1), Free.calls);
}

test "Channel: a retained channel outlives its connection and refuses writes" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    // A handler that retains its own channel, the way a chat server registers a
    // peer it will later broadcast to.
    const Registry = struct {
        var slot: Io.Queue(*Channel) = undefined;
        var storage: [1]*Channel = undefined;
    };
    Registry.slot = .init(&Registry.storage);

    const Joiner = struct {
        pub fn onActive(_: *@This(), ctx: *pipeline_mod.HandlerContext) pipeline_mod.Error!void {
            const channel: *Channel = @ptrCast(@alignCast(ctx.owner().?));
            // Legal here: this callback runs on the channel's own task, so
            // `serve`'s reference is definitely still held.
            channel.retain();
            try Registry.slot.putOne(ctx.io(), channel);
            ctx.fireActive();
        }
    };
    const build = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Joiner);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("joiner", .initOwned(handler));
        }
    }.pipelineOf;

    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var client = try listener.socket.address.connect(io, .{ .mode = .stream });
    const accepted = try listener.accept(io);

    const channel = try Channel.create(.{
        .gpa = gpa,
        .io = io,
        .stream = accepted,
        .initializer = .initFunction(build),
    });

    var loop: @import("event_loop.zig").EventLoop = .init(io);
    try loop.register(channel);

    // The handler hands us a reference; from here the channel is ours to hold.
    const retained = try Registry.slot.getOne(io);
    try testing.expect(retained.referenceCount() >= 2);

    // The peer goes away, which ends the read loop and tears the channel down.
    client.close(io);
    loop.drain();

    // Before reference counting this was a use-after-free: `serve` had already
    // freed the channel, queue storage included. Now it is merely closed.
    try testing.expectEqual(Channel.State.closed, retained.currentState());
    try testing.expectError(
        error.ChannelClosed,
        retained.write(try Message.initBytes(gpa, "broadcast")),
    );
    // Closing an already-dead channel is a no-op rather than a stale-fd
    // shutdown.
    retained.requestClose();

    try testing.expectEqual(@as(u32, 1), retained.referenceCount());
    retained.release();
}

/// Sleeps on the wall/awake clock, for tests that need real elapsed time.
fn sleepMs(io: Io, milliseconds: i64) void {
    const duration: Io.Clock.Duration = .{
        .raw = .fromMilliseconds(milliseconds),
        .clock = .awake,
    };
    duration.sleep(io) catch {};
}

/// Skips a test that needs a deadline-bounded socket read, on a backend whose
/// `net_receive` cannot provide one.
///
/// `Channel.receiveBounded` is the only way to put a deadline on a socket read —
/// `std.Io.Operation` offers no other primitive — and zio panics on it for a
/// *stream* socket: `recvmsg` leaves `msg_name` untouched on a connected socket,
/// and zio converts that untouched buffer unconditionally (`src/io.zig:2406`
/// reaching `else => unreachable` at `src/io.zig:1871`) where the standard
/// library defines the case away (`std/Io/Threaded.zig:14181`).
///
/// So this is an upstream defect, not a difference of design, and it is stated
/// here rather than silently skipped so the claim can be checked. Everything not
/// using ticks or task hopping runs on either backend.
pub fn skipIfReadDeadlinesAreBroken() error{SkipZigTest}!void {
    if (comptime std.mem.eql(u8, backend.Runtime.name, "zio")) return error.SkipZigTest;
}

test "Channel: a quiet connection ticks, and traffic still arrives" {
    try skipIfReadDeadlinesAreBroken();
    // Exercises the deadline-bounded read path, which is the only place
    // `net_receive` is used instead of the stream reader. Firing ticks by hand
    // in a unit test would not have covered it.
    // `net_receive` is used instead of the stream reader. Firing ticks by hand
    // in a unit test would not have covered it.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const Watcher = struct {
        var ticks: std.atomic.Value(u32) = .init(0);
        var bytes: std.atomic.Value(u32) = .init(0);

        pub fn onEvent(
            _: *@This(),
            ctx: *pipeline_mod.HandlerContext,
            event: pipeline_mod.Event,
        ) pipeline_mod.Error!void {
            if (event.is(Channel.Tick)) _ = ticks.fetchAdd(1, .monotonic);
            ctx.fireEvent(event);
        }

        pub fn onRead(
            _: *@This(),
            ctx: *pipeline_mod.HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            _ = bytes.fetchAdd(@intCast(owned.len()), .monotonic);
        }
    };
    Watcher.ticks.store(0, .monotonic);
    Watcher.bytes.store(0, .monotonic);

    const build = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Watcher);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("watcher", .initOwned(handler));
        }
    }.pipelineOf;

    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var client = try listener.socket.address.connect(io, .{ .mode = .stream });
    const accepted = try listener.accept(io);

    const channel = try Channel.create(.{
        .gpa = gpa,
        .io = io,
        .stream = accepted,
        .initializer = .initFunction(build),
        .tick_interval = .fromMilliseconds(5),
    });

    var loop: @import("event_loop.zig").EventLoop = .init(io);
    try loop.register(channel);

    // Stay silent long enough for several deadlines to pass.
    sleepMs(io, 80);
    const while_quiet = Watcher.ticks.load(.monotonic);
    try testing.expect(while_quiet >= 2);

    // A bounded read must still deliver data, not just deadlines.
    var writer = client.writer(io, &.{});
    try writer.interface.writeAll("hello");
    try writer.interface.flush();

    var waited: usize = 0;
    while (Watcher.bytes.load(.monotonic) == 0 and waited < 200) : (waited += 1) {
        sleepMs(io, 5);
    }
    try testing.expectEqual(@as(u32, 5), Watcher.bytes.load(.monotonic));

    client.close(io);
    loop.drain();
}

test "Channel: requestTick lowers the interval but never raises it" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const accepted = try listener.accept(io);

    const channel = try Channel.create(.{
        .gpa = gpa,
        .io = io,
        .stream = accepted,
        .tick_interval = .fromMilliseconds(100),
    });
    defer {
        channel.stream.close(io);
        channel.destroy();
    }

    channel.requestTick(.fromMilliseconds(10));
    try testing.expectEqual(@as(i96, 10_000_000), channel.tick_interval.?.toNanoseconds());

    // A coarser request is ignored: the shortest requirement wins.
    channel.requestTick(.fromMilliseconds(500));
    try testing.expectEqual(@as(i96, 10_000_000), channel.tick_interval.?.toNanoseconds());
}

test "Channel: pendingOutbound tracks the queue and isWritable follows it" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const accepted = try listener.accept(io);

    // No writer task is started here, so nothing drains: the queue depth is
    // fully under the test's control.
    const channel = try Channel.create(.{
        .gpa = gpa,
        .io = io,
        .stream = accepted,
        .outbound_capacity = 2,
    });
    defer {
        channel.stream.close(io);
        channel.destroy();
    }

    try testing.expectEqual(@as(usize, 0), channel.pendingOutbound());
    try testing.expect(channel.isWritable());

    try channel.write(try Message.initBytes(gpa, "one"));
    try testing.expectEqual(@as(usize, 1), channel.pendingOutbound());
    try testing.expect(channel.isWritable());

    try channel.write(try Message.initBytes(gpa, "two"));
    try testing.expectEqual(@as(usize, 2), channel.pendingOutbound());
    // Full: the next write would block until the writer task caught up.
    try testing.expect(!channel.isWritable());

    // Draining by hand, the way the writer task would, restores writability.
    channel.outbound.close(io);
    channel.drainOutbound();
    try testing.expectEqual(@as(usize, 0), channel.pendingOutbound());
}

// -- Task hopping ----------------------------------------------------------

/// A connected pair, for driving a channel from the other end.
const Pair = struct {
    listener: Io.net.Server,
    client: Io.net.Stream,
    accepted: Io.net.Stream,

    fn init(io: Io) !Pair {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var listener = try address.listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const client = try listener.socket.address.connect(io, .{ .mode = .stream });
        const accepted = try listener.accept(io);
        return .{ .listener = listener, .client = client, .accepted = accepted };
    }

    /// Closes the client side and the listener. The accepted side belongs to the
    /// channel it was given to.
    fn deinit(pair: *Pair, io: Io) void {
        pair.client.close(io);
        pair.listener.deinit(io);
    }
};

/// Uppercases outbound bytes, standing in for a protocol encoder.
const ShoutEncoder = struct {
    pub fn onWrite(_: *ShoutEncoder, ctx: *pipeline_mod.HandlerContext, msg: Message) pipeline_mod.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const bytes = owned.bytes() orelse return;

        var shouted = try Buffer.init(ctx.gpa(), .{ .capacity = bytes.len });
        errdefer shouted.deinit(ctx.gpa());
        const destination = try shouted.reserve(ctx.gpa(), bytes.len);
        for (bytes, destination) |source, *slot| slot.* = std.ascii.toUpper(source);

        return ctx.write(.initBuffer(&shouted));
    }
};

fn buildShoutingPipeline(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(ShoutEncoder);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("shout", .initOwned(handler));
}

/// Writes a farewell when closed, standing in for a closing handshake.
const Farewell = struct {
    pub fn onClose(_: *Farewell, ctx: *pipeline_mod.HandlerContext) pipeline_mod.Error!void {
        try ctx.writeAndFlush(try Message.initBytes(ctx.gpa(), "bye"));
        return ctx.close();
    }
};

fn buildFarewellPipeline(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(Farewell);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("farewell", .initOwned(handler));
}

/// Waits until `serve` has built the pipeline, which it does before reading.
fn waitForPipeline(io: Io, channel: *Channel, name: []const u8) !void {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        if (channel.pipeline.find(name) != null) return;
        if (channel.currentState() == .closed) return error.ChannelWentAway;
        sleepMs(io, 5);
    }
    return error.PipelineNeverBuilt;
}

test "Channel: submit is refused unless task hopping was configured" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try Pair.init(io);
    defer pair.deinit(io);

    const channel = try Channel.create(.{ .gpa = gpa, .io = io, .stream = pair.accepted });
    defer channel.destroy();

    // The default costs nothing and therefore offers nothing.
    try testing.expectEqual(@as(usize, 0), channel.options.task_capacity);
    try testing.expectError(
        error.TaskHoppingDisabled,
        channel.submitWrite(try Message.initBytes(gpa, "nope")),
    );
    try testing.expectError(error.TaskHoppingDisabled, channel.submitClose());
}

test "Channel: a submitted write travels through the pipeline's encoders" {
    // The reason the facility exists. `Channel.write` would put these bytes on
    // the socket unchanged; going through the pipeline runs the encoder the
    // protocol installed, which is what a client needs.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try Pair.init(io);
    defer pair.deinit(io);

    const channel = try Channel.create(.{
        .gpa = gpa,
        .io = io,
        .stream = pair.accepted,
        .initializer = .initFunction(buildShoutingPipeline),
        .task_capacity = 4,
        .task_wake_interval = .fromMilliseconds(1),
    });

    var loop: @import("event_loop.zig").EventLoop = .init(io);
    try loop.register(channel);
    defer loop.shutdown();

    try waitForPipeline(io, channel, "shout");
    // Submitted from this task, which is not the reader task.
    try channel.submitWrite(try Message.initBytes(gpa, "hello"));

    var buffer: [16]u8 = undefined;
    var reader = pair.client.reader(io, &buffer);
    try testing.expectEqualStrings("HELLO", try reader.interface.take(5));
}

test "Channel: a submitted close runs the pipeline's close handlers" {
    try skipIfReadDeadlinesAreBroken();
    // `requestClose` shuts the socket down without telling the handlers, which
    // is why a protocol with a closing handshake needs this instead.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try Pair.init(io);
    defer pair.deinit(io);

    const channel = try Channel.create(.{
        .gpa = gpa,
        .io = io,
        .stream = pair.accepted,
        .initializer = .initFunction(buildFarewellPipeline),
        .task_capacity = 4,
        .task_wake_interval = .fromMilliseconds(1),
    });

    var loop: @import("event_loop.zig").EventLoop = .init(io);
    try loop.register(channel);
    defer loop.shutdown();

    try waitForPipeline(io, channel, "farewell");
    try channel.submitClose();

    var buffer: [16]u8 = undefined;
    var reader = pair.client.reader(io, &buffer);
    // The handler got its chance to say goodbye before the socket went away.
    try testing.expectEqualStrings("bye", try reader.interface.take(3));
}

test "Channel: a full task queue is reported rather than waited out" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try Pair.init(io);
    defer pair.deinit(io);

    // Never served, so nothing ever drains the queue. A blocking submit would
    // hang here, which is exactly what `submit` promises not to do.
    const channel = try Channel.create(.{
        .gpa = gpa,
        .io = io,
        .stream = pair.accepted,
        .task_capacity = 2,
    });
    defer channel.destroy();

    try channel.submitWrite(try Message.initBytes(gpa, "one"));
    try channel.submitWrite(try Message.initBytes(gpa, "two"));
    try testing.expectEqual(@as(usize, 2), channel.pendingTasks());

    try testing.expectError(
        error.TaskQueueFull,
        channel.submitWrite(try Message.initBytes(gpa, "three")),
    );
    // The refused message was released rather than leaked, which the checking
    // allocator this test runs under would otherwise report.
    try testing.expectEqual(@as(usize, 2), channel.pendingTasks());

    // Whatever is still queued when the connection ends is freed, not run.
    channel.tasks.close(io);
    channel.drainTasks();
    try testing.expectEqual(@as(usize, 0), channel.pendingTasks());
}
