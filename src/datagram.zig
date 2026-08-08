//! Datagram (UDP) channels.
//!
//! A stream channel has one peer and a byte stream that needs framing. A
//! datagram channel has neither, and that changes three things about it:
//!
//! * **One socket serves every peer.** So there is one pipeline for the endpoint
//!   rather than one per peer, and each message has to carry an address. That is
//!   what `Datagram` is.
//! * **The framing codecs do not apply.** `ByteToMessageDecoder` exists to find
//!   message boundaries in a stream; a datagram *is* the boundary. Handlers on a
//!   datagram pipeline decode a whole message from the bytes they are handed, so
//!   `MessageToMessageDecoder` is the base class that fits.
//! * **There is no end of stream.** A UDP socket never reports that the peer
//!   went away, and `shutdown` does not apply to an unconnected socket, so
//!   nothing external ends the read loop. It is ended by cancelling its task,
//!   which is what `Endpoint.deinit` does; `close_poll` exists for the case where
//!   neither the reader nor the owner of that task is the one asking.
//!
//! One thing datagrams get for free that streams do not: the peer's address.
//! `recvmsg` reports it with every message, whereas `std.Io` 0.16 exposes no
//! `getpeername` for a connected socket. So `Datagram.address` is always there.
//!
//! ```zig
//! var endpoint = try zinet.datagram.Endpoint.open(.{
//!     .gpa = gpa,
//!     .io = io,
//!     .address = .{ .ip4 = .unspecified(9000) },
//!     .initializer = .initFunction(buildPipeline),
//! });
//! defer endpoint.deinit();
//! ```

const std = @import("std");
const backend = @import("backend");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const buffer_mod = @import("buffer.zig");
const pipeline_mod = @import("pipeline.zig");
const channel_mod = @import("channel.zig");
const pool_mod = @import("pool.zig");

const Buffer = buffer_mod.Buffer;
const BufferPool = pool_mod.BufferPool;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;

const log = std.log.scoped(.zinet);

/// Largest payload a UDP datagram can carry over IPv4.
pub const max_udp_payload = 65507;

/// One datagram, in either direction.
///
/// Unlike the stream codecs' outbound types, this owns its payload. Those can
/// borrow because an encoder serializes into a `Buffer` before `write` returns;
/// a datagram instead crosses a queue to the writer task, so the bytes have to
/// outlive the call that produced them.
pub const Datagram = struct {
    /// Where it came from, or where it is going.
    address: Io.net.IpAddress,
    payload: Buffer,

    /// Copies `bytes` into a new datagram addressed to `address`.
    pub fn init(
        gpa: Allocator,
        address: Io.net.IpAddress,
        payload: []const u8,
    ) Buffer.Error!Datagram {
        return .{
            .address = address,
            .payload = try Buffer.initFrom(gpa, payload, .{}),
        };
    }

    /// Takes ownership of `payload`.
    pub fn initBuffer(address: Io.net.IpAddress, payload: *Buffer) Datagram {
        return .{ .address = address, .payload = payload.move() };
    }

    pub fn deinit(datagram: *Datagram, gpa: Allocator) void {
        datagram.payload.deinit(gpa);
    }

    pub fn bytes(datagram: *const Datagram) []const u8 {
        return datagram.payload.readableSlice();
    }

    /// A datagram addressed back at the sender, carrying `reply`.
    ///
    /// The common shape for a server: answer whoever asked.
    pub fn replyWith(
        datagram: *const Datagram,
        gpa: Allocator,
        reply: []const u8,
    ) Buffer.Error!Datagram {
        return .init(gpa, datagram.address, reply);
    }
};

/// What to do with a datagram too big for the receive buffer.
pub const Truncation = enum {
    /// Report `error.DatagramTruncated` and drop it.
    ///
    /// The default, because a protocol handed the first half of a message may
    /// act on it, and acting on half a message is worse than losing one. UDP
    /// applications already have to tolerate loss; they do not have to tolerate
    /// corruption.
    drop,
    /// Deliver what arrived. Only sound for protocols where a prefix is
    /// meaningful on its own.
    deliver,
};

/// An endpoint bound to a local address, with a pipeline for its traffic.
pub const DatagramChannel = struct {
    gpa: Allocator,
    io: Io,
    socket: Io.net.Socket,
    pipeline: Pipeline,
    options: Options,

    outbound_storage: []Datagram,
    outbound: Io.Queue(Datagram),
    /// Queued datagrams, tracked because `Io.Queue` does not publish a length.
    pending: std.atomic.Value(u32),

    closing: std.atomic.Value(bool),
    refs: std.atomic.Value(u32),
    stats: Stats,

    pub const Error = error{
        /// The endpoint is shutting down or already closed.
        ChannelClosed,
    } || Buffer.Error;

    pub const Options = struct {
        gpa: Allocator,
        io: Io,
        /// Builds the pipeline for this endpoint.
        initializer: ?channel_mod.Initializer = null,
        /// Handle handlers see as `ctx.owner()`. Defaults to the channel.
        owner: ?*anyopaque = null,
        /// Receive buffer size, and therefore the largest datagram accepted
        /// whole. Defaults to the IPv4 maximum so that nothing is truncated by
        /// accident; lower it when the protocol has a smaller ceiling of its own.
        max_datagram_size: usize = max_udp_payload,
        /// How a datagram larger than `max_datagram_size` is handled.
        truncation: Truncation = .drop,
        /// Queued outbound datagrams before senders block.
        outbound_capacity: usize = 64,
        /// How long the reader may block in one receive.
        ///
        /// A datagram socket has no end of stream and `shutdown` does not apply
        /// to an unconnected one, so there is nothing to make a blocked receive
        /// return. The reader therefore receives with a deadline and rechecks
        /// whether it has been asked to stop, which makes this the worst-case
        /// delay of `requestClose`.
        /// How often the reader wakes to notice a `requestClose` that came from
        /// another task.
        ///
        /// Null, the default, means never: the reader blocks in a receive until a
        /// datagram arrives or its task is cancelled, so an idle endpoint costs
        /// nothing at all. `Endpoint.deinit` cancels, so the ordinary shutdown
        /// path needs no polling, and neither does a handler closing the endpoint
        /// from inside — that runs on the reader's own task, which then sees
        /// `closing` on its next trip round the loop.
        ///
        /// Set it only when something that is neither the reader nor the owner of
        /// the task has to stop the endpoint. A datagram socket has no end of
        /// stream and `shutdown` does not apply to an unconnected one, so in that
        /// case there is nothing to interrupt a blocked receive with and polling
        /// is the only answer. This is the one place Zinet polls, which is why it
        /// is opt-in.
        close_poll: ?Io.Duration = null,
        /// Fire a `Tick` pipeline event whenever a receive waits this long, the
        /// same contract as `Channel.Tick` and for the same reason: the reader
        /// blocks in a receive, so the read itself must carry the deadline. A
        /// QUIC connection is the motivating consumer — its loss-detection and
        /// idle timers have to fire on a connection the peer has gone quiet on,
        /// which is precisely when no datagram will arrive to run them.
        tick_interval: ?Io.Duration = null,
        /// Optional recycler for receive buffers.
        pool: ?*BufferPool = null,
    };

    /// Fired as a pipeline event when `tick_interval` elapses without a
    /// datagram arriving. See `Channel.Tick` for the design; the semantics are
    /// identical, including the imprecision: a tick arrives no earlier than the
    /// interval and possibly later, so handlers compare timestamps rather than
    /// counting ticks.
    pub const Tick = struct {
        at: Io.Timestamp,
    };

    pub const Stats = struct {
        datagrams_received: u64 = 0,
        datagrams_sent: u64 = 0,
        bytes_received: u64 = 0,
        bytes_sent: u64 = 0,
        /// Datagrams dropped because they did not fit. A non-zero count means
        /// `max_datagram_size` is too small for the traffic.
        truncated: u64 = 0,
    };

    /// Binds `address` and prepares the pipeline. Does not start any task; see
    /// `serve`, or use `Endpoint` which does both.
    pub fn open(address: Io.net.IpAddress, options: Options) !*DatagramChannel {
        assert(options.max_datagram_size > 0);
        assert(options.outbound_capacity > 0);

        const gpa = options.gpa;
        const channel = try gpa.create(DatagramChannel);
        errdefer gpa.destroy(channel);

        const outbound_storage = try gpa.alloc(Datagram, options.outbound_capacity);
        errdefer gpa.free(outbound_storage);

        var bound = address;
        const socket = try bound.bind(options.io, .{ .mode = .dgram });
        errdefer socket.close(options.io);

        channel.* = .{
            .gpa = gpa,
            .io = options.io,
            .socket = socket,
            .pipeline = undefined,
            .options = options,
            .outbound_storage = outbound_storage,
            .outbound = .init(outbound_storage),
            .pending = .init(0),
            .closing = .init(false),
            .refs = .init(1),
            .stats = .{},
        };

        try channel.pipeline.init(.{
            .gpa = gpa,
            .io = options.io,
            .sink = channel.sink(),
            .owner = options.owner orelse channel,
        });
        return channel;
    }

    /// Releases a channel that was opened but never served.
    pub fn destroy(channel: *DatagramChannel) void {
        assert(channel.refs.load(.acquire) == 1);
        channel.pipeline.deinit();
        channel.socket.close(channel.io);
        channel.release();
    }

    /// Claims a reference. Only legal while already holding one.
    pub fn retain(channel: *DatagramChannel) void {
        const previous = channel.refs.fetchAdd(1, .acq_rel);
        assert(previous > 0);
    }

    /// Drops a reference, freeing the channel with the last one.
    pub fn release(channel: *DatagramChannel) void {
        const previous = channel.refs.fetchSub(1, .acq_rel);
        assert(previous > 0);
        if (previous != 1) return;

        const gpa = channel.gpa;
        gpa.free(channel.outbound_storage);
        gpa.destroy(channel);
    }

    pub fn referenceCount(channel: *const DatagramChannel) u32 {
        return channel.refs.load(.acquire);
    }

    /// The address actually bound, with the ephemeral port resolved.
    pub fn localAddress(channel: *const DatagramChannel) Io.net.IpAddress {
        return channel.socket.address;
    }

    pub fn isOpen(channel: *const DatagramChannel) bool {
        return !channel.closing.load(.acquire);
    }

    /// Queued datagrams not yet sent.
    pub fn pendingOutbound(channel: *const DatagramChannel) usize {
        return channel.pending.load(.acquire);
    }

    /// Asks the endpoint to stop. Idempotent and safe from any task.
    ///
    /// Called from the reader's own task — a handler closing the endpoint — the
    /// reader notices on its next trip round the loop. Called from any other
    /// task, it only takes effect once a datagram arrives, or within
    /// `close_poll` if that is set, or when the reader's task is cancelled;
    /// `Endpoint.deinit` does the last of those.
    pub fn requestClose(channel: *DatagramChannel) void {
        channel.closing.store(true, .release);
    }

    /// Queues `datagram` for sending, taking ownership. Blocks while the queue
    /// is full. Safe to call from any task holding a reference.
    ///
    /// Goes under the pipeline, like `Channel.write`, which is what makes it
    /// callable from anywhere. Use `Pipeline.write` from a handler to pass
    /// through the outbound handlers.
    pub fn send(channel: *DatagramChannel, datagram: Datagram) Error!void {
        var owned = datagram;
        if (!channel.isOpen()) {
            owned.deinit(channel.gpa);
            return error.ChannelClosed;
        }
        channel.outbound.putOne(channel.io, owned) catch |err| {
            owned.deinit(channel.gpa);
            return switch (err) {
                error.Closed, error.Canceled => error.ChannelClosed,
            };
        };
        _ = channel.pending.fetchAdd(1, .monotonic);
    }

    /// Copies `bytes` and sends them to `address`.
    pub fn sendTo(
        channel: *DatagramChannel,
        address: Io.net.IpAddress,
        payload: []const u8,
    ) Error!void {
        return channel.send(try Datagram.init(channel.gpa, address, payload));
    }

    fn sink(channel: *DatagramChannel) Sink {
        return .{ .context = channel, .vtable = &sink_vtable };
    }

    const sink_vtable: Sink.VTable = .{
        .write = sinkWrite,
        .close = sinkClose,
    };

    /// Consumes the message unconditionally, as `Sink.write` requires.
    fn sinkWrite(context: *anyopaque, msg: Message) pipeline_mod.Error!void {
        const channel: *DatagramChannel = @ptrCast(@alignCast(context));
        var owned = msg;
        // Only addressed messages can reach a datagram socket. Anything else has
        // no destination, and guessing one would be worse than saying so.
        const datagram = owned.take(channel.gpa, Datagram) orelse {
            owned.deinit(channel.gpa);
            return error.UnaddressedDatagram;
        };
        return channel.send(datagram);
    }

    fn sinkClose(context: *anyopaque) pipeline_mod.Error!void {
        const channel: *DatagramChannel = @ptrCast(@alignCast(context));
        channel.requestClose();
    }

    // -- Task bodies -------------------------------------------------------

    /// Runs the endpoint's whole lifecycle. Consumes one reference.
    pub fn serve(channel: *DatagramChannel) void {
        const io = channel.io;
        // Declared first so it runs last: the memory outlives the socket
        // whenever another task still holds a reference.
        defer channel.release();
        defer channel.teardown();

        if (channel.options.initializer) |initializer| {
            initializer.apply(&channel.pipeline) catch |err| {
                channel.pipeline.fireError(err);
                return;
            };
        }

        var writer_future = io.concurrent(sendLoop, .{channel}) catch |err| {
            channel.pipeline.fireError(err);
            return;
        };

        channel.pipeline.fireActive();
        channel.receiveLoop();
        channel.pipeline.fireInactive();

        channel.outbound.close(io);
        writer_future.cancel(io);
    }

    fn teardown(channel: *DatagramChannel) void {
        channel.closing.store(true, .release);
        channel.outbound.close(channel.io);
        channel.socket.close(channel.io);
        channel.pipeline.deinit();
    }

    /// Receives datagrams until asked to stop, firing each into the pipeline.
    fn receiveLoop(channel: *DatagramChannel) void {
        const io = channel.io;
        var scratch: ?Buffer = null;
        defer if (scratch) |*pending| channel.releaseBuffer(pending);

        // Two independent absolute deadlines, following `Channel.readLoop`.
        //
        // They were one relative deadline — the nearer of the two intervals, recomputed
        // after every datagram — and both halves of that were wrong. A tick fired on *any*
        // expiry, so a 2 ms `close_poll` turned a one-second `tick_interval` into a 2 ms
        // one: hundreds of pipeline events a second the application never asked for. And
        // because the deadline restarted from "now" on every arrival, a peer sending
        // steadily postponed ticks indefinitely — an idle timer a busy peer can suppress is
        // the timer nobody wants.
        //
        // Absolute deadlines fix both: each cadence keeps its own next-due time, expiry is
        // attributed by comparing the clock against each, and a datagram arriving does not
        // move either one.
        var next_tick: ?Io.Timestamp = if (channel.options.tick_interval) |interval|
            Io.Timestamp.now(io, .awake).addDuration(interval)
        else
            null;
        var next_poll: ?Io.Timestamp = if (channel.options.close_poll) |interval|
            Io.Timestamp.now(io, .awake).addDuration(interval)
        else
            null;

        while (channel.isOpen()) {
            if (scratch == null) {
                scratch = channel.acquireBuffer() catch |err| {
                    channel.pipeline.fireError(err);
                    return;
                };
            }
            const destination = scratch.?.writableSlice();
            assert(destination.len > 0);

            const incoming = receive: {
                // The nearer of the two deadlines bounds the read; which one *fired* is
                // decided afterwards by the clock, because they mean different things —
                // nothing versus a pipeline event — and both can be due at once.
                if (earlier(next_tick, next_poll)) |deadline| {
                    break :receive channel.socket.receiveTimeout(io, destination, .{
                        .deadline = deadline.withClock(.awake),
                    }) catch |err| switch (err) {
                        error.Timeout => {
                            const now = Io.Timestamp.now(io, .awake);
                            if (due(next_poll, now)) {
                                // Nothing to deliver: waking up *is* the poll. The loop's
                                // own `isOpen()` check is what it woke up for.
                                next_poll = if (channel.options.close_poll) |interval|
                                    now.addDuration(interval)
                                else
                                    null;
                            }
                            if (due(next_tick, now)) {
                                // Re-read the interval: a handler may have changed it since
                                // the last tick.
                                if (channel.options.tick_interval) |interval| {
                                    next_tick = now.addDuration(interval);
                                    // Delivered on the reader task like every other
                                    // pipeline event, which is what keeps handler state
                                    // lock free.
                                    var tick: Tick = .{ .at = now };
                                    channel.pipeline.fireEvent(.init(&tick));
                                } else {
                                    next_tick = null;
                                }
                            }
                            continue;
                        },
                        error.Canceled => return,
                        else => {
                            channel.pipeline.fireError(err);
                            return;
                        },
                    };
                }
                // Unbounded, which is what makes an idle endpoint free. What ends
                // this is a datagram, a socket failure, or cancellation of this
                // task.
                break :receive channel.socket.receive(io, destination) catch |err| switch (err) {
                    error.Canceled => return,
                    else => {
                        channel.pipeline.fireError(err);
                        return;
                    },
                };
            };

            if (incoming.flags.trunc) {
                channel.stats.truncated += 1;
                if (channel.options.truncation == .drop) {
                    scratch.?.clear();
                    channel.pipeline.fireError(error.DatagramTruncated);
                    continue;
                }
            }

            var ready = scratch.?;
            scratch = null;
            ready.commit(incoming.data.len);
            channel.stats.datagrams_received += 1;
            channel.stats.bytes_received += incoming.data.len;

            var datagram: Datagram = .initBuffer(incoming.from, &ready);
            const msg = Message.initAny(channel.gpa, Datagram, datagram) catch |err| {
                datagram.deinit(channel.gpa);
                channel.pipeline.fireError(err);
                continue;
            };
            channel.pipeline.fireRead(msg);
            channel.pipeline.fireReadComplete();
        }
    }

    /// Body of the writer task: drains the outbound queue onto the socket.
    fn sendLoop(channel: *DatagramChannel) void {
        const io = channel.io;
        // Declared first so it runs last: by then the queue is closed, so the
        // drain terminates and every queued datagram is freed.
        defer channel.drainOutbound();
        defer channel.outbound.close(io);

        while (true) {
            var datagram = channel.outbound.getOne(io) catch break;
            _ = channel.pending.fetchSub(1, .monotonic);
            defer datagram.deinit(channel.gpa);

            const payload = datagram.bytes();
            channel.socket.send(io, &datagram.address, payload) catch |err| {
                // One undeliverable datagram is not a reason to stop serving the
                // rest: UDP has no delivery guarantee to break, and a single bad
                // destination must not take the endpoint down.
                log.warn("dropping datagram: {s}", .{@errorName(err)});
                continue;
            };
            channel.stats.datagrams_sent += 1;
            channel.stats.bytes_sent += payload.len;
        }
    }

    /// Frees whatever is left in the queue. Only valid once it is closed.
    fn drainOutbound(channel: *DatagramChannel) void {
        while (true) {
            var datagram = channel.outbound.getOneUncancelable(channel.io) catch return;
            _ = channel.pending.fetchSub(1, .monotonic);
            datagram.deinit(channel.gpa);
        }
    }

    fn acquireBuffer(channel: *DatagramChannel) Buffer.Error!Buffer {
        const wanted = channel.options.max_datagram_size;
        if (channel.options.pool) |pool| {
            var pooled = try pool.acquire(wanted);
            errdefer pool.release(&pooled);
            try pooled.ensureWritable(channel.gpa, wanted);
            return pooled;
        }
        return Buffer.init(channel.gpa, .{ .capacity = wanted });
    }

    fn releaseBuffer(channel: *DatagramChannel, target: *Buffer) void {
        target.deinit(channel.gpa);
    }
};

/// A bound endpoint with its tasks running.
///
/// The thin wrapper exists because a datagram endpoint is usually a single
/// The nearer of two optional deadlines, or whichever one exists.
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

/// long-lived socket rather than one of many connections, so there is no
/// acceptor and no event loop group to hand it to.
pub const Endpoint = struct {
    channel: *DatagramChannel,
    future: Io.Future(void),

    pub const Options = struct {
        gpa: Allocator,
        io: Io,
        address: Io.net.IpAddress,
        initializer: ?channel_mod.Initializer = null,
        owner: ?*anyopaque = null,
        max_datagram_size: usize = max_udp_payload,
        truncation: Truncation = .drop,
        outbound_capacity: usize = 64,
        /// How often the reader wakes to notice a `requestClose` that came from
        /// another task.
        ///
        /// Null, the default, means never: the reader blocks in a receive until a
        /// datagram arrives or its task is cancelled, so an idle endpoint costs
        /// nothing at all. `Endpoint.deinit` cancels, so the ordinary shutdown
        /// path needs no polling, and neither does a handler closing the endpoint
        /// from inside — that runs on the reader's own task, which then sees
        /// `closing` on its next trip round the loop.
        ///
        /// Set it only when something that is neither the reader nor the owner of
        /// the task has to stop the endpoint. A datagram socket has no end of
        /// stream and `shutdown` does not apply to an unconnected one, so in that
        /// case there is nothing to interrupt a blocked receive with and polling
        /// is the only answer. This is the one place Zinet polls, which is why it
        /// is opt-in.
        close_poll: ?Io.Duration = null,
        /// See `DatagramChannel.Options.tick_interval`.
        tick_interval: ?Io.Duration = null,
        pool: ?*BufferPool = null,
    };

    pub fn open(options: Options) !Endpoint {
        const channel = try DatagramChannel.open(options.address, .{
            .gpa = options.gpa,
            .io = options.io,
            .initializer = options.initializer,
            .owner = options.owner,
            .max_datagram_size = options.max_datagram_size,
            .truncation = options.truncation,
            .outbound_capacity = options.outbound_capacity,
            .close_poll = options.close_poll,
            .tick_interval = options.tick_interval,
            .pool = options.pool,
        });
        // Retained before the task starts, so the handle stays valid even if the
        // task finishes immediately.
        channel.retain();
        errdefer {
            channel.release();
            channel.destroy();
        }

        const future = try options.io.concurrent(DatagramChannel.serve, .{channel});
        return .{ .channel = channel, .future = future };
    }

    /// Stops the endpoint and waits for its tasks, then drops the handle's
    /// reference.
    ///
    /// Cancels rather than merely asking, because asking is not enough on its
    /// own: a datagram socket has no end of stream and `shutdown` does not apply
    /// to an unconnected one, so a reader blocked in a receive has nothing else
    /// to interrupt it. `cancel` awaits, so the tasks are finished when this
    /// returns.
    pub fn deinit(endpoint: *Endpoint) void {
        const io = endpoint.channel.io;
        // Set first, so anything still trying to send is refused rather than
        // queueing onto a socket that is about to close.
        endpoint.channel.requestClose();
        endpoint.future.cancel(io);
        endpoint.channel.release();
        endpoint.* = undefined;
    }

    pub fn localAddress(endpoint: *const Endpoint) Io.net.IpAddress {
        return endpoint.channel.localAddress();
    }

    pub fn port(endpoint: *const Endpoint) u16 {
        return endpoint.channel.localAddress().getPort();
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

/// Echoes every datagram back to its sender.
const Echoer = struct {
    pub fn onRead(
        _: *Echoer,
        ctx: *pipeline_mod.HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const datagram = owned.get(Datagram) orelse return;
        // Through the pipeline, so an outbound handler would see it.
        return ctx.write(try Message.initAny(
            ctx.gpa(),
            Datagram,
            try datagram.replyWith(ctx.gpa(), datagram.bytes()),
        ));
    }
};

fn buildEchoPipeline(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(Echoer);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("echo", .initOwned(handler));
}

/// A client socket for driving an endpoint under test.
const Peer = struct {
    socket: Io.net.Socket,

    fn init(io: Io) !Peer {
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        return .{ .socket = try address.bind(io, .{ .mode = .dgram }) };
    }

    fn deinit(peer: *Peer, io: Io) void {
        peer.socket.close(io);
    }

    fn sendTo(peer: *Peer, io: Io, target: Io.net.IpAddress, bytes: []const u8) !void {
        var destination = target;
        return peer.socket.send(io, &destination, bytes);
    }

    fn receive(peer: *Peer, io: Io, into: []u8, milliseconds: i64) !Io.net.IncomingMessage {
        const deadline = Io.Timestamp.now(io, .awake)
            .addDuration(.fromMilliseconds(milliseconds))
            .withClock(.awake);
        return peer.socket.receiveTimeout(io, into, .{ .deadline = deadline });
    }
};

test "DatagramChannel: binds an ephemeral port and reports it" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const channel = try DatagramChannel.open(.{ .ip4 = .loopback(0) }, .{
        .gpa = gpa,
        .io = io,
    });
    defer channel.destroy();

    try testing.expect(channel.localAddress().getPort() != 0);
    try testing.expect(channel.isOpen());
}

test "DatagramChannel: echoes a datagram back to its sender" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try Endpoint.open(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .initializer = .initFunction(buildEchoPipeline),
    });
    defer endpoint.deinit();

    var peer = try Peer.init(io);
    defer peer.deinit(io);

    try peer.sendTo(io, endpoint.localAddress(), "hello datagram");

    var scratch: [64]u8 = undefined;
    const reply = try peer.receive(io, &scratch, 2000);
    try testing.expectEqualStrings("hello datagram", reply.data);
    // The reply came from the endpoint, which is the address the peer sent to.
    try testing.expectEqual(endpoint.port(), reply.from.getPort());
}

test "DatagramChannel: every message carries the sender's address" {
    // What datagrams get for free and streams do not.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const Seen = struct {
        var queue: Io.Queue(u16) = undefined;
        var storage: [4]u16 = undefined;

        pub fn onRead(
            _: *@This(),
            ctx: *pipeline_mod.HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const datagram = owned.get(Datagram) orelse return;
            try queue.putOne(ctx.io(), datagram.address.getPort());
        }
    };
    Seen.queue = .init(&Seen.storage);

    const build = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Seen);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("seen", .initOwned(handler));
        }
    }.pipelineOf;

    var endpoint = try Endpoint.open(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .initializer = .initFunction(build),
    });
    defer endpoint.deinit();

    var first = try Peer.init(io);
    defer first.deinit(io);
    var second = try Peer.init(io);
    defer second.deinit(io);

    try first.sendTo(io, endpoint.localAddress(), "from first");
    const seen_first = try Seen.queue.getOne(io);
    try testing.expectEqual(first.socket.address.getPort(), seen_first);

    try second.sendTo(io, endpoint.localAddress(), "from second");
    const seen_second = try Seen.queue.getOne(io);
    try testing.expectEqual(second.socket.address.getPort(), seen_second);
    try testing.expect(seen_first != seen_second);
}

test "DatagramChannel: an oversized datagram is reported rather than half delivered" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const Watcher = struct {
        var errors: Io.Queue([32]u8) = undefined;
        var error_storage: [4][32]u8 = undefined;
        var delivered: std.atomic.Value(u32) = .init(0);

        pub fn onRead(
            _: *@This(),
            ctx: *pipeline_mod.HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            _ = delivered.fetchAdd(1, .monotonic);
        }

        pub fn onError(_: *@This(), ctx: *pipeline_mod.HandlerContext, err: anyerror) void {
            var name: [32]u8 = @splat(0);
            const text = @errorName(err);
            @memcpy(name[0..@min(text.len, 32)], text[0..@min(text.len, 32)]);
            errors.putOne(ctx.io(), name) catch {};
        }
    };
    Watcher.errors = .init(&Watcher.error_storage);
    Watcher.delivered.store(0, .release);

    const build = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Watcher);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("watch", .initOwned(handler));
        }
    }.pipelineOf;

    var endpoint = try Endpoint.open(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .initializer = .initFunction(build),
        // Small enough that the datagram below cannot fit.
        .max_datagram_size = 8,
    });
    defer endpoint.deinit();

    var peer = try Peer.init(io);
    defer peer.deinit(io);
    try peer.sendTo(io, endpoint.localAddress(), "far more than eight bytes");

    const reported = try Watcher.errors.getOne(io);
    try testing.expectEqualStrings("DatagramTruncated", std.mem.sliceTo(&reported, 0));
    // Dropped, not delivered as a prefix.
    try testing.expectEqual(@as(u32, 0), Watcher.delivered.load(.acquire));
    try testing.expectEqual(@as(u64, 1), endpoint.channel.stats.truncated);
}

test "DatagramChannel: a truncated datagram is delivered when asked for" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const Collector = struct {
        var queue: Io.Queue([8]u8) = undefined;
        var storage: [4][8]u8 = undefined;

        pub fn onRead(
            _: *@This(),
            ctx: *pipeline_mod.HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const datagram = owned.get(Datagram) orelse return;
            var slot: [8]u8 = @splat(0);
            const payload = datagram.bytes();
            @memcpy(slot[0..@min(payload.len, 8)], payload[0..@min(payload.len, 8)]);
            try queue.putOne(ctx.io(), slot);
        }
    };
    Collector.queue = .init(&Collector.storage);

    const build = struct {
        fn pipelineOf(pipeline: *Pipeline) anyerror!void {
            const handler = try pipeline.gpa.create(Collector);
            handler.* = .{};
            errdefer pipeline.gpa.destroy(handler);
            _ = try pipeline.addLast("collect", .initOwned(handler));
        }
    }.pipelineOf;

    var endpoint = try Endpoint.open(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
        .initializer = .initFunction(build),
        .max_datagram_size = 8,
        .truncation = .deliver,
    });
    defer endpoint.deinit();

    var peer = try Peer.init(io);
    defer peer.deinit(io);
    try peer.sendTo(io, endpoint.localAddress(), "truncate me please");

    const got = try Collector.queue.getOne(io);
    try testing.expectEqualStrings("truncate", &got);
}

test "DatagramChannel: send works from a task that is not the reader" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try Endpoint.open(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(0) },
    });
    defer endpoint.deinit();

    var peer = try Peer.init(io);
    defer peer.deinit(io);

    // Straight from the test's task, under the pipeline.
    try endpoint.channel.sendTo(io_target(&peer), "unsolicited");

    var scratch: [32]u8 = undefined;
    const got = try peer.receive(io, &scratch, 2000);
    try testing.expectEqualStrings("unsolicited", got.data);
}

fn io_target(peer: *const Peer) Io.net.IpAddress {
    return peer.socket.address;
}

test "DatagramChannel: an unaddressed message cannot reach the socket" {
    // A datagram needs a destination, and inventing one would be worse than
    // refusing.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const channel = try DatagramChannel.open(.{ .ip4 = .loopback(0) }, .{
        .gpa = gpa,
        .io = io,
    });
    defer channel.destroy();

    try testing.expectError(
        error.UnaddressedDatagram,
        channel.pipeline.write(try Message.initBytes(gpa, "no address")),
    );
}

test "DatagramChannel: closing frees queued datagrams" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const channel = try DatagramChannel.open(.{ .ip4 = .loopback(0) }, .{
        .gpa = gpa,
        .io = io,
        .outbound_capacity = 4,
    });
    defer channel.destroy();

    const target = channel.localAddress();
    try channel.sendTo(target, "one");
    try channel.sendTo(target, "two");
    try testing.expectEqual(@as(usize, 2), channel.pendingOutbound());

    // Nothing is serving, so the drain stands in for what the writer task's
    // teardown does. A leak here would fail the test.
    channel.outbound.close(io);
    channel.drainOutbound();
    try testing.expectEqual(@as(usize, 0), channel.pendingOutbound());
}

test "DatagramChannel: send after close is refused and releases the datagram" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    const channel = try DatagramChannel.open(.{ .ip4 = .loopback(0) }, .{
        .gpa = gpa,
        .io = io,
    });
    defer channel.destroy();

    const target = channel.localAddress();
    channel.requestClose();
    try testing.expectError(error.ChannelClosed, channel.sendTo(target, "too late"));
}

/// Reports when the reader has fired `onActive`, which is the last thing that
/// happens before it enters its first receive.
var reader_active: std.atomic.Value(bool) = .init(false);

const ActiveFlag = struct {
    pub fn onActive(_: *ActiveFlag, ctx: *pipeline_mod.HandlerContext) !void {
        reader_active.store(true, .release);
        ctx.fireActive();
    }
};

fn buildActiveFlag(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(ActiveFlag);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("active-flag", .initOwned(handler));
}

test "DatagramChannel: with close_poll set, another task can stop the reader" {
    // Every other test here shuts down through `Endpoint.deinit`, which cancels.
    // This one covers the opt-in poll, which exists for a caller holding neither
    // the reader's task nor its future.
    //
    // Written as bounded waits rather than an `await`, so a regression fails the
    // test instead of wedging the suite: without the poll the reader would sit in
    // an unbounded receive and `await` would never return.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    reader_active.store(false, .release);

    const poll: Io.Duration = .fromMilliseconds(5);
    const channel = try DatagramChannel.open(.{ .ip4 = .loopback(0) }, .{
        .gpa = gpa,
        .io = io,
        .initializer = .initFunction(buildActiveFlag),
        .close_poll = poll,
    });
    // One reference for the task, one for this test.
    channel.retain();
    defer channel.release();

    var future = try io.concurrent(DatagramChannel.serve, .{channel});

    // The close has to be observed by a reader that is *already blocked*,
    // otherwise the loop's opening `isOpen()` check would end it and the poll
    // would never be exercised.
    try waitFor(io, .fromSeconds(5), struct {
        fn ready() bool {
            return reader_active.load(.acquire);
        }
    }.ready);
    try testing.expect(reader_active.load(.acquire));
    try io.sleep(.fromMilliseconds(20), .awake);

    channel.requestClose();

    // `serve` consumes a reference on the way out, so the count falling back to
    // the one this test holds is the observable "the task finished".
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
    while (channel.referenceCount() != 1) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    // Cancelled rather than awaited when the wait failed, because a reader still
    // sitting in an unbounded receive would make `await` hang forever — turning a
    // failing test into a wedged suite.
    const stopped = channel.referenceCount() == 1;
    if (stopped) future.await(io) else future.cancel(io);
    try testing.expect(stopped);
}

/// Polls `ready` until it holds or `budget` runs out. Generous on purpose — this
/// is a liveness check, and a tight bound would only make it fail under load.
fn waitFor(io: Io, budget: Io.Duration, comptime ready: fn () bool) !void {
    const deadline = Io.Timestamp.now(io, .awake).addDuration(budget);
    while (!ready()) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) return;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
}

/// Counts `Tick` events for the test below.
var tick_count: std.atomic.Value(u32) = .init(0);

const TickCounter = struct {
    pub fn onEvent(_: *TickCounter, ctx: *pipeline_mod.HandlerContext, event: pipeline_mod.Event) !void {
        if (event.is(DatagramChannel.Tick)) _ = tick_count.fetchAdd(1, .monotonic);
        ctx.fireEvent(event);
    }
};

fn buildTickCounter(pipeline: *Pipeline) anyerror!void {
    const handler = try pipeline.gpa.create(TickCounter);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("tick-counter", .initOwned(handler));
}

test "DatagramChannel: close polling does not set the tick cadence" {
    // Two independent cadences sharing one deadline is the defect. `close_poll` exists so
    // a caller holding neither the reader's task nor its future can stop it, and wants to
    // be short; `tick_interval` is a protocol timer and may be minutes. The receive was
    // bounded by the nearer of the two and then fired a tick on *any* expiry, so setting a
    // 5 ms poll turned a 1-second tick into a 5 ms tick — two hundred pipeline events per
    // second the application never asked for, each of them a handler callback.
    //
    // The second half of the same defect: the deadline was recomputed relative to "now"
    // after every datagram, so a peer sending steadily could postpone ticks forever. An
    // idle timer that a busy peer can suppress is exactly the timer nobody wants.
    try channel_mod.skipIfReadDeadlinesAreBroken();
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    tick_count.store(0, .release);

    const channel = try DatagramChannel.open(.{ .ip4 = .loopback(0) }, .{
        .gpa = gpa,
        .io = io,
        .initializer = .initFunction(buildTickCounter),
        .close_poll = .fromMilliseconds(2),
        .tick_interval = .fromMilliseconds(200),
    });
    channel.retain();
    defer channel.release();

    var future = try io.concurrent(DatagramChannel.serve, .{channel});

    // Long enough for a hundred close polls and no more than one tick.
    try io.sleep(.fromMilliseconds(150), .awake);
    const during = tick_count.load(.acquire);

    // `serve` consumes a reference on its way out, so the count returning to the one this
    // test holds is the observable "the reader finished" — and waiting for it with a bound
    // rather than `await` means a reader that ignores the poll fails this test instead of
    // wedging the suite.
    channel.requestClose();
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(5));
    while (channel.refs.load(.acquire) > 1) {
        if (Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) break;
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    try testing.expectEqual(@as(u32, 1), channel.refs.load(.acquire));
    future.cancel(io);

    // One tick would be a scheduling accident near the boundary; seventy-five is the poll
    // interval having become the tick interval.
    try testing.expect(during <= 1);
}

test "DatagramChannel: a busy peer cannot postpone ticks" {
    // The other half of the same defect. The receive deadline used to be computed as
    // "now + interval" on every pass of the loop, so each arriving datagram pushed the next
    // tick out by a full interval — a peer sending faster than the tick rate suppressed
    // ticks entirely. Anything built on ticks is a timer, and a timer a busy peer can
    // switch off is worse than no timer: the idle detection, the read timeout and QUIC's
    // loss recovery all stop exactly when traffic is heaviest.
    //
    // With absolute deadlines, arrivals do not move the tick, so a steady flood still sees
    // one tick per interval.
    try channel_mod.skipIfReadDeadlinesAreBroken();
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    tick_count.store(0, .release);

    const channel = try DatagramChannel.open(.{ .ip4 = .loopback(0) }, .{
        .gpa = gpa,
        .io = io,
        .initializer = .initFunction(buildTickCounter),
        .tick_interval = .fromMilliseconds(40),
    });
    channel.retain();
    defer channel.release();

    var future = try io.concurrent(DatagramChannel.serve, .{channel});
    const target = channel.localAddress();

    var peer = try Peer.init(io);
    defer peer.deinit(io);

    // Faster than the tick interval, for several intervals' worth of time.
    const stop = Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(300));
    while (Io.Timestamp.now(io, .awake).nanoseconds < stop.nanoseconds) {
        try peer.sendTo(io, target, "keep busy");
        try io.sleep(.fromMilliseconds(5), .awake);
    }
    const during = tick_count.load(.acquire);

    channel.requestClose();
    // No `close_poll` here, so the reader is woken by cancellation rather than by noticing.
    future.cancel(io);

    // 300 ms of 40 ms ticks is seven in the ideal case; three is a generous floor that still
    // cannot be reached if arrivals reset the timer, which produced none at all.
    try testing.expect(during >= 3);
}
