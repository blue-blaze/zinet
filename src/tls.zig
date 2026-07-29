//! TLS 1.3 client connections, with the same `Pipeline` and the same handlers
//! as a plain `Channel`.
//!
//! ## Why a TLS connection is single-tasked
//!
//! A plain `Channel` runs two tasks: a reader and a writer. That split is what
//! lets any task write to a connection and what makes a full outbound queue
//! honest backpressure. A TLS connection cannot have it, and the reason is not a
//! preference — it is forced by two properties of `std.crypto.tls.Client`:
//!
//! 1. **The read path mutates the write direction.** `Client.readIndirect`
//!    handles a server `key_update` by rotating `client_key`, `client_iv` and
//!    resetting `write_seq` (`std/crypto/tls/Client.zig`, the `.key_update`
//!    branch). Handing the client's `reader` to one task and its `writer` to
//!    another is therefore a data race on the cipher state, and the failure mode
//!    is not a crash but a silently corrupted write stream. Key updates are
//!    rare, which makes this worse rather than better: it would be a bug that
//!    shows up in production and never in a test.
//!
//! 2. **A TLS read cannot carry a deadline.** `Channel` bounds its reads by
//!    going *under* `Io.net.Stream.Reader` straight to `net_receive`, which is
//!    impossible here — bytes have to pass through record decryption, and
//!    `Client.reader` is an ordinary blocking `Io.Reader` with no deadline and no
//!    non-blocking mode. So a timer cannot wake a task that is blocked in a TLS
//!    read.
//!
//! One task owning the whole session resolves (1). Working around (2) needs one
//! more step, and it is the piece that makes this practical rather than
//! deadlock-prone: the session's *input* is not the socket's reader but
//! `PumpReader`, a reader of Zinet's own whose fill routine receives with a
//! deadline and, whenever that deadline passes, sends whatever has been queued
//! before trying again.
//!
//! So the pump lives *inside* the read. Draining before the read is not enough:
//! a client that queues its request a moment after the task has already entered
//! a read would wait for a response to a request that was never sent, and the
//! peer would wait for the request — a deadlock reachable by losing a race, and
//! the first thing a request/response client does.
//!
//! What is left is a latency bound rather than a hazard: a write submitted while
//! the task is blocked leaves within `write_poll`, which is the same trade
//! `Channel.task_wake_interval` makes. `requestClose` is immediate either way,
//! since shutting the socket down ends the receive.
//!
//! ## Server-side TLS
//!
//! Not available, and not by choice: `std.crypto.tls` ships `Client` and nothing
//! else. Accepting a TLS connection needs a server handshake — certificate and
//! key loading, `CertificateVerify` signing, session tickets — none of which
//! exists in the standard library, and writing it here would mean hand-rolling
//! the security-critical half of TLS.

const std = @import("std");
const backend = @import("backend");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const tls = std.crypto.tls;
const Certificate = std.crypto.Certificate;

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

/// Smallest buffer `tls.Client` accepts, for both plaintext and ciphertext.
pub const min_buffer_len = tls.Client.min_buffer_len;

/// How the server's certificate is checked.
///
/// `.insecure` exists for testing against a server whose certificate is not
/// meant to be trusted. It is spelled that way on purpose: it makes the
/// connection confidential against a passive observer and worthless against an
/// active one.
pub const Verification = union(enum) {
    /// Verify the host name against the certificate and the certificate against
    /// a CA bundle.
    bundle: *CaBundle,
    /// Verify the host name, and accept any valid self-signed certificate.
    /// Authenticates nothing, since anyone can self-sign.
    self_signed,
    /// Verify nothing.
    insecure,
};

/// A CA bundle plus the lock `tls.Client` needs in order to share it.
///
/// Loading one reads the whole system trust store, so a program that opens many
/// connections should load one of these and hand it to all of them. That is why
/// it is a separate type rather than something `connect` does per connection.
pub const CaBundle = struct {
    bundle: Certificate.Bundle,
    lock: Io.RwLock,

    /// Reads the system trust store. Callers that need a specific set of roots
    /// can build `bundle` themselves and construct this directly.
    pub fn loadSystem(gpa: Allocator, io: Io) !CaBundle {
        var bundle: Certificate.Bundle = .empty;
        errdefer bundle.deinit(gpa);
        try bundle.rescan(gpa, io, .now(io, .real));
        return .{ .bundle = bundle, .lock = .init };
    }

    pub fn deinit(self: *CaBundle, gpa: Allocator) void {
        self.bundle.deinit(gpa);
        self.* = undefined;
    }
};

pub const Error = error{
    /// `submitWrite` or `send` was called on a connection that has closed.
    ConnectionClosed,
} || Buffer.Error;

/// One TLS connection: a socket, a TLS session, a pipeline and one task.
pub const Connection = struct {
    gpa: Allocator,
    io: Io,
    options: Options,

    stream: Io.net.Stream,
    /// Pinned, because `client` holds pointers into these.
    pump_reader: PumpReader,
    stream_writer: Io.net.Stream.Writer,
    client: tls.Client,

    /// True once the pipeline exists, so `PumpReader` knows whether it may send.
    /// Only the connection's own task reads it; only `serve` writes it, before
    /// the first read.
    serving: bool,

    /// Ciphertext staging for the socket, plus plaintext staging for the TLS
    /// session. All four are at least `min_buffer_len`, which is what the
    /// session asserts.
    socket_read_buffer: []u8,
    socket_write_buffer: []u8,
    tls_read_buffer: []u8,
    tls_write_buffer: []u8,

    pipeline: Pipeline,

    outbound: Io.Queue(Outbound),
    outbound_storage: []Outbound,
    pending: std.atomic.Value(u32),

    /// Set when plaintext has been handed to the session but not yet flushed.
    /// Only the connection's own task touches this, which is why it is a plain
    /// field rather than an atomic.
    dirty: bool,
    /// Set when the peer should be told goodbye before the socket goes away.
    /// Same ownership as `dirty`.
    farewell: bool,

    closing: std.atomic.Value(bool),
    /// True once the session has been torn down, so `send` can refuse instead of
    /// touching a dead `tls.Client`.
    finished: std.atomic.Value(bool),
    refs: std.atomic.Value(u32),
    stats: Stats,

    pub const Stats = struct {
        bytes_read: u64 = 0,
        bytes_written: u64 = 0,
        reads: u64 = 0,
        writes: u64 = 0,
        flushes: u64 = 0,
    };

    /// Same shape as `Channel.Outbound`, and for the same reason: data, flushes
    /// and the close travel one queue, so their order is the order they were
    /// asked for.
    pub const Outbound = union(enum) {
        /// Bytes to encrypt as they are, having already passed the pipeline or
        /// deliberately skipped it. The counterpart of `Channel.write`.
        data: Message,
        /// A message to send *through* the pipeline, so its encoders run on the
        /// connection's own task. The counterpart of `Channel.submitWrite`.
        submit: Message,
        flush: void,
        /// Write what is queued, send `close_notify`, then shut down.
        close: void,

        pub fn deinit(item: *Outbound, gpa: Allocator) void {
            switch (item.*) {
                .data, .submit => |*msg| msg.deinit(gpa),
                .flush, .close => {},
            }
        }
    };

    pub const Options = struct {
        gpa: Allocator,
        io: Io,
        /// Already resolved: `std.Io` has no name resolver, so the caller brings
        /// the address.
        address: Io.net.IpAddress,
        /// Sent as SNI and checked against the certificate. Must outlive the
        /// connection.
        host: []const u8,
        verification: Verification,
        initializer: ?channel_mod.Initializer = null,
        owner: ?*anyopaque = null,
        /// Plaintext bytes requested per read, and the size of each inbound
        /// `Buffer`.
        read_chunk: usize = 16 * 1024,
        max_inbound_capacity: usize = Buffer.default_max_capacity,
        /// Queued outbound items before producers block.
        outbound_capacity: usize = 64,
        /// Longest a queued write waits while the connection is blocked reading.
        ///
        /// A TLS read cannot carry a deadline, so this is the interval at which
        /// the receive underneath it gives up, sends what is queued, and tries
        /// again. Shorter costs more wakeups for nothing; longer delays writes on
        /// a quiet connection.
        write_poll: Io.Duration = .fromMilliseconds(10),
        /// Forwards end-of-stream to the application instead of failing with
        /// `TlsConnectionTruncated` when the peer vanishes without a
        /// `close_notify`.
        ///
        /// Leave this false unless the protocol above bounds its own message
        /// lengths; otherwise a truncation attack looks like a clean close.
        allow_truncation_attacks: bool = false,
        pool: ?*BufferPool = null,
    };

    /// Connects, performs the TLS handshake, and builds the pipeline. Returns
    /// with one reference held.
    ///
    /// The handshake happens here, on the caller's task, so a failure to
    /// establish trust is a plain error return rather than an event on a
    /// pipeline that never became active.
    pub fn connect(options: Options) !*Connection {
        assert(options.read_chunk > 0);
        assert(options.outbound_capacity > 0);
        assert(options.host.len > 0);

        const gpa = options.gpa;
        const io = options.io;

        const connection = try gpa.create(Connection);
        errdefer gpa.destroy(connection);

        const outbound_storage = try gpa.alloc(Outbound, options.outbound_capacity);
        errdefer gpa.free(outbound_storage);

        const socket_read_buffer = try gpa.alloc(u8, min_buffer_len);
        errdefer gpa.free(socket_read_buffer);
        const socket_write_buffer = try gpa.alloc(u8, min_buffer_len);
        errdefer gpa.free(socket_write_buffer);
        const tls_read_buffer = try gpa.alloc(u8, min_buffer_len);
        errdefer gpa.free(tls_read_buffer);
        const tls_write_buffer = try gpa.alloc(u8, min_buffer_len);
        errdefer gpa.free(tls_write_buffer);

        var address = options.address;
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        connection.* = .{
            .gpa = gpa,
            .io = io,
            .options = options,
            .stream = stream,
            .pump_reader = undefined,
            .stream_writer = undefined,
            .serving = false,
            .client = undefined,
            .socket_read_buffer = socket_read_buffer,
            .socket_write_buffer = socket_write_buffer,
            .tls_read_buffer = tls_read_buffer,
            .tls_write_buffer = tls_write_buffer,
            .pipeline = undefined,
            .outbound_storage = outbound_storage,
            .outbound = .init(outbound_storage),
            .pending = .init(0),
            .dirty = false,
            .farewell = false,
            .closing = .init(false),
            .finished = .init(false),
            .refs = .init(1),
            .stats = .{},
        };

        // Built in place, because the session below keeps pointers to them.
        connection.pump_reader = .init(connection, socket_read_buffer);
        connection.stream_writer = connection.stream.writer(io, socket_write_buffer);

        // From the same CSPRNG as the WebSocket masking keys. `tls.Client` only
        // reads it during `init`.
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        defer std.crypto.secureZero(u8, &entropy);

        connection.client = try tls.Client.init(
            &connection.pump_reader.interface,
            &connection.stream_writer.interface,
            .{
                .host = switch (options.verification) {
                    .insecure => .no_verification,
                    .self_signed, .bundle => .{ .explicit = options.host },
                },
                .ca = switch (options.verification) {
                    .insecure => .no_verification,
                    .self_signed => .self_signed,
                    .bundle => |ca| .{ .bundle = .{
                        .gpa = gpa,
                        .io = io,
                        .lock = &ca.lock,
                        .bundle = &ca.bundle,
                    } },
                },
                .read_buffer = tls_read_buffer,
                .write_buffer = tls_write_buffer,
                .entropy = &entropy,
                .realtime_now = .now(io, .real),
                .allow_truncation_attacks = options.allow_truncation_attacks,
            },
        );

        try connection.pipeline.init(.{
            .gpa = gpa,
            .io = io,
            .sink = connection.sink(),
            .owner = options.owner orelse connection,
        });
        return connection;
    }

    /// Releases a connection that was established but never served.
    pub fn destroy(connection: *Connection) void {
        assert(connection.refs.load(.acquire) == 1);
        connection.pipeline.deinit();
        connection.stream.close(connection.io);
        connection.release();
    }

    /// Claims a reference. Only legal while already holding one.
    pub fn retain(connection: *Connection) void {
        const previous = connection.refs.fetchAdd(1, .acq_rel);
        assert(previous > 0);
    }

    /// Drops a reference, freeing the connection with the last one.
    pub fn release(connection: *Connection) void {
        const previous = connection.refs.fetchSub(1, .acq_rel);
        assert(previous > 0);
        if (previous != 1) return;

        const gpa = connection.gpa;
        gpa.free(connection.outbound_storage);
        gpa.free(connection.socket_read_buffer);
        gpa.free(connection.socket_write_buffer);
        gpa.free(connection.tls_read_buffer);
        gpa.free(connection.tls_write_buffer);
        gpa.destroy(connection);
    }

    pub fn referenceCount(connection: *const Connection) u32 {
        return connection.refs.load(.acquire);
    }

    pub fn isOpen(connection: *const Connection) bool {
        return !connection.closing.load(.acquire);
    }

    pub fn pendingOutbound(connection: *const Connection) usize {
        return connection.pending.load(.acquire);
    }

    /// The TLS version that was negotiated. Always 1.3 with the current
    /// standard library, which offers no 1.2 client.
    pub fn protocolVersion(connection: *const Connection) tls.ProtocolVersion {
        return connection.client.tls_version;
    }

    /// Ends the connection now, without a closing handshake.
    ///
    /// Callable from any task. Shutting the socket down is what unblocks a read
    /// that has no deadline, which is why this does not need a poll interval the
    /// way a datagram endpoint does. For a graceful close — flush what is
    /// queued, then `close_notify` — use `submitClose`.
    pub fn requestClose(connection: *Connection) void {
        connection.closing.store(true, .release);
        connection.stream.shutdown(connection.io, .both) catch {};
    }

    /// Queues raw bytes, skipping the pipeline. Blocks while the queue is full,
    /// which is this connection's write backpressure.
    ///
    /// Callable from any task, and for the same reason `Channel.write` is: it
    /// goes *under* the pipeline, so it runs no encoders. Use `submitWrite` when
    /// the pipeline has to see the message.
    pub fn write(connection: *Connection, msg: Message) Error!void {
        return connection.enqueue(msg, .data);
    }

    /// Queues a message to travel the pipeline on the connection's own task, so
    /// every encoder in it runs.
    ///
    /// Callable from any task. This is the TLS counterpart of
    /// `Channel.submitWrite`, and it exists for exactly the same reason: a
    /// pipeline may only be driven by the task that owns it.
    pub fn submitWrite(connection: *Connection, msg: Message) Error!void {
        return connection.enqueue(msg, .submit);
    }

    /// Queues bytes, copied into a message, skipping the pipeline.
    pub fn writeBytes(connection: *Connection, bytes: []const u8) Error!void {
        return connection.write(try Message.initBytes(connection.gpa, bytes));
    }

    /// Takes ownership of `msg` on every path, as the rest of Zinet's write
    /// entry points do.
    fn enqueue(
        connection: *Connection,
        msg: Message,
        comptime kind: std.meta.Tag(Outbound),
    ) Error!void {
        var owned = msg;
        errdefer owned.deinit(connection.gpa);
        if (connection.finished.load(.acquire)) return error.ConnectionClosed;

        var item: Outbound = @unionInit(Outbound, @tagName(kind), owned.move());
        connection.outbound.putOne(connection.io, item) catch {
            item.deinit(connection.gpa);
            return error.ConnectionClosed;
        };
        _ = connection.pending.fetchAdd(1, .monotonic);
    }

    /// Queues a graceful close: everything already queued is written, then
    /// `close_notify` goes out and the socket shuts down.
    ///
    /// This is the counterpart of `Channel.submitClose`, and it matters for the
    /// same reason — a protocol with a closing handshake gets to perform it.
    pub fn submitClose(connection: *Connection) Error!void {
        connection.outbound.putOne(connection.io, .close) catch
            return error.ConnectionClosed;
        _ = connection.pending.fetchAdd(1, .monotonic);
    }

    // -- Sink --------------------------------------------------------------

    fn sink(connection: *Connection) Sink {
        return .{ .context = connection, .vtable = &sink_vtable };
    }

    const sink_vtable: Sink.VTable = .{
        .write = sinkWrite,
        .flush = sinkFlush,
        .close = sinkClose,
    };

    /// Encrypts the message here and now, and consumes it unconditionally as
    /// `Sink.write` requires.
    ///
    /// Writing straight into the session rather than queueing is safe — and is
    /// the only sane choice — because a `Sink` is reached by driving the
    /// pipeline, and Zinet already forbids driving a pipeline from any task but
    /// the one that owns it. Queueing here would mean the task handing work to
    /// itself through a bounded queue it is the sole consumer of, which is the
    /// shape of a deadlock.
    fn sinkWrite(context: *anyopaque, msg: Message) pipeline_mod.Error!void {
        const connection: *Connection = @ptrCast(@alignCast(context));
        var owned = msg;
        defer owned.deinit(connection.gpa);
        const bytes = owned.bytes() orelse return;
        connection.client.writer.writeAll(bytes) catch return error.ChannelClosed;
        connection.dirty = true;
        connection.stats.bytes_written += bytes.len;
        connection.stats.writes += 1;
    }

    fn sinkFlush(context: *anyopaque) pipeline_mod.Error!void {
        const connection: *Connection = @ptrCast(@alignCast(context));
        connection.flushSession() catch return error.ChannelClosed;
    }

    /// Pushes plaintext all the way to the socket.
    ///
    /// Two steps, because `tls.Client.flush` only encrypts the buffered
    /// plaintext into the *output writer* and advances it — it does not flush
    /// that writer. Stopping after the first step leaves a finished record
    /// sitting in the socket's buffer, which looks exactly like a peer that
    /// never answered.
    fn flushSession(connection: *Connection) !void {
        try connection.client.writer.flush();
        try connection.stream_writer.interface.flush();
        connection.dirty = false;
        connection.stats.flushes += 1;
    }

    fn sinkClose(context: *anyopaque) pipeline_mod.Error!void {
        const connection: *Connection = @ptrCast(@alignCast(context));
        connection.farewell = true;
        connection.closing.store(true, .release);
    }

    // -- The task ----------------------------------------------------------

    /// Runs the connection's whole lifecycle on this task. Consumes one
    /// reference.
    pub fn serve(connection: *Connection) void {
        // Declared first so it runs last: another task may still hold a
        // reference when the session is already gone.
        defer connection.release();
        defer connection.drainOutbound();
        defer connection.teardown();

        if (connection.options.initializer) |initializer| {
            initializer.apply(&connection.pipeline) catch |err| {
                connection.pipeline.fireError(err);
                return;
            };
        }

        // From here the pump reader may send, which it must not do before the
        // pipeline exists.
        connection.serving = true;

        connection.pipeline.fireActive();
        connection.readLoop();

        // `end` flushes and sends `close_notify`, which is the difference
        // between a graceful close and a truncation as far as the peer is
        // concerned. Only attempted when something asked for one.
        if (connection.farewell) {
            // `end` appends `close_notify` to the output writer; the socket still
            // has to be told about it.
            connection.client.end() catch {};
            connection.stream_writer.interface.flush() catch {};
        }

        connection.pipeline.fireInactive();
    }

    fn teardown(connection: *Connection) void {
        connection.closing.store(true, .release);
        connection.finished.store(true, .release);
        connection.outbound.close(connection.io);
        connection.stream.close(connection.io);
        connection.pipeline.deinit();
    }

    /// Alternates between writing what is queued and reading what arrives.
    ///
    /// The order is deliberate and is the whole reason a request/response
    /// protocol works on one task: everything queued is written *and flushed*
    /// before the read that would otherwise block until the peer replies.
    fn readLoop(connection: *Connection) void {
        var chunk: ?Buffer = null;
        defer if (chunk) |*pending| connection.releaseInbound(pending);
        var empty_reads: usize = 0;

        while (connection.isOpen()) {
            if (!connection.pumpOutbound()) return;

            if (chunk == null) {
                chunk = connection.acquireInbound() catch |err| {
                    connection.pipeline.fireError(err);
                    return;
                };
            }

            var destination: [1][]u8 = .{chunk.?.writableSlice()};
            assert(destination[0].len > 0);

            const n = connection.client.reader.readVec(&destination) catch |err| {
                connection.finishRead(err);
                return;
            };
            if (n == 0) {
                // A zero-length read does not mean the stream ended: a TLS
                // record may have carried only handshake bytes. Tolerating a
                // bounded run of them is what keeps this from spinning a core.
                empty_reads += 1;
                if (empty_reads >= max_empty_reads) {
                    connection.finishRead(error.EndOfStream);
                    return;
                }
                continue;
            }
            empty_reads = 0;

            chunk.?.commit(n);
            connection.stats.bytes_read += n;
            connection.stats.reads += 1;

            var ready = chunk.?;
            chunk = null;
            connection.pipeline.fireRead(.initBuffer(&ready));
            connection.pipeline.fireReadComplete();
        }
    }

    /// Consecutive zero-length reads tolerated before the session is treated as
    /// finished.
    const max_empty_reads = 64;

    /// Sends everything that has been queued, then flushes. Returns false when
    /// the loop should stop.
    ///
    /// Taking from the queue is non-blocking (`min = 0`): this task is also the
    /// one that has to get back to reading, so it must never wait here.
    /// Producers still block on a full queue, so backpressure is unchanged.
    fn pumpOutbound(connection: *Connection) bool {
        const io = connection.io;
        while (true) {
            var one: [1]Outbound = undefined;
            const count = connection.outbound.get(io, &one, 0) catch return false;
            if (count == 0) break;
            _ = connection.pending.fetchSub(1, .monotonic);

            switch (one[0]) {
                .data => |*msg| {
                    defer msg.deinit(connection.gpa);
                    const bytes = msg.bytes() orelse continue;
                    connection.client.writer.writeAll(bytes) catch return false;
                    connection.dirty = true;
                    connection.stats.bytes_written += bytes.len;
                    connection.stats.writes += 1;
                },
                .submit => |*msg| {
                    // Travels the pipeline, so its encoders run — which is the
                    // whole reason this variant exists. `Pipeline.write`
                    // consumes the message on every path.
                    const owned = msg.move();
                    connection.pipeline.write(owned) catch |err| {
                        connection.pipeline.fireError(err);
                    };
                },
                .flush => connection.flushSession() catch return false,
                .close => {
                    connection.farewell = true;
                    connection.closing.store(true, .release);
                    return false;
                },
            }
        }

        // The single most important line in this file: the next thing this task
        // does is block until the peer speaks, so plaintext still sitting in the
        // record buffer would be waiting for a reply to a request that was never
        // sent.
        if (connection.dirty) connection.flushSession() catch return false;
        return true;
    }

    /// Frees whatever is left in the queue. Only safe once the queue is closed,
    /// otherwise it would block waiting for new items.
    fn drainOutbound(connection: *Connection) void {
        while (true) {
            var item = connection.outbound.getOneUncancelable(connection.io) catch return;
            _ = connection.pending.fetchSub(1, .monotonic);
            item.deinit(connection.gpa);
        }
    }

    /// Reports why reading stopped, translating the ends that are not failures.
    fn finishRead(connection: *Connection, err: anyerror) void {
        connection.closing.store(true, .release);
        if (err == error.EndOfStream) return;

        // `Reader.Error` collapses everything into `ReadFailed`, so the useful
        // reason is whichever layer recorded one: the session for a protocol
        // failure, the pump reader for a socket failure.
        if (err == error.ReadFailed) {
            if (connection.client.read_err) |reason| {
                connection.pipeline.fireError(reason);
                return;
            }
            if (connection.pump_reader.err) |reason| {
                connection.pipeline.fireError(reason);
                return;
            }
        }
        connection.pipeline.fireError(err);
    }

    fn acquireInbound(connection: *Connection) Buffer.Error!Buffer {
        const wanted = connection.options.read_chunk;
        if (connection.options.pool) |pool| {
            var pooled = try pool.acquire(wanted);
            errdefer pool.release(&pooled);
            try pooled.ensureWritable(connection.gpa, wanted);
            pooled.max_capacity = @max(
                pooled.capacity(),
                connection.options.max_inbound_capacity,
            );
            return pooled;
        }
        return Buffer.init(connection.gpa, .{
            .capacity = wanted,
            .max_capacity = connection.options.max_inbound_capacity,
        });
    }

    fn releaseInbound(connection: *Connection, target: *Buffer) void {
        target.deinit(connection.gpa);
    }
};

/// The session's input: a reader that receives with a deadline and, each time
/// the deadline passes, sends whatever the application has queued.
///
/// This is where a single-tasked TLS connection stops being half duplex. The
/// alternative — pump only between reads — deadlocks the moment a caller queues
/// its first request after the task has entered a read, which for a client is
/// most of the time.
pub const PumpReader = struct {
    interface: Io.Reader,
    connection: *Connection,
    /// The socket failure behind an `error.ReadFailed`, since `Io.Reader.Error`
    /// cannot carry it.
    err: ?anyerror = null,

    /// `buffer` must be at least `min_buffer_len`, which `tls.Client` asserts of
    /// whatever it is given as input.
    pub fn init(connection: *Connection, buffer: []u8) PumpReader {
        assert(buffer.len >= min_buffer_len);
        return .{
            .interface = .{
                .vtable = &.{ .stream = streamImpl, .readVec = readVec },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .connection = connection,
        };
    }

    fn streamImpl(
        io_r: *Io.Reader,
        io_w: *Io.Writer,
        limit: Io.Limit,
    ) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(io_r, &data);
        io_w.advance(n);
        return n;
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const self: *PumpReader = @alignCast(@fieldParentPtr("interface", io_r));
        const connection = self.connection;
        const io = connection.io;

        var vectors: [8][]u8 = undefined;
        const dest_n, const data_size = try io_r.writableVector(&vectors, data);
        const dest = vectors[0..dest_n];
        assert(dest[0].len > 0);

        while (true) {
            // Only this task sends, so pumping here cannot race with anything.
            // It is also the only chance a queued write gets while the peer is
            // quiet.
            if (connection.serving and !connection.pumpOutbound()) return error.EndOfStream;
            if (!connection.isOpen()) return error.EndOfStream;

            const deadline = Io.Timestamp.now(io, .awake)
                .addDuration(connection.options.write_poll);

            var incoming: Io.net.IncomingMessage = .init;
            const result = io.operateTimeout(.{ .net_receive = .{
                .socket_handle = connection.stream.socket.handle,
                .message_buffer = (&incoming)[0..1],
                .data_buffer = dest[0],
                .flags = .{},
            } }, .{ .deadline = deadline.withClock(.awake) }) catch |err| switch (err) {
                // The whole point: nothing arrived, so go around and send.
                error.Timeout => continue,
                error.Canceled => {
                    self.err = error.Canceled;
                    return error.ReadFailed;
                },
                error.ConcurrencyUnavailable => {
                    self.err = error.SystemResources;
                    return error.ReadFailed;
                },
            };

            const maybe_err, const count = result.net_receive;
            if (maybe_err) |err| {
                self.err = err;
                return error.ReadFailed;
            }
            assert(count == 1);

            // On a stream socket a successful receive of zero bytes is the
            // orderly shutdown.
            const n = incoming.data.len;
            if (n == 0) return error.EndOfStream;

            // `writableVector` puts the caller's slices first and the reader's
            // own buffer last, so an empty request means `dest[0]` is that
            // buffer and the bytes are reported through `end` instead.
            if (data_size == 0) {
                io_r.end += n;
                return 0;
            }
            assert(n <= data_size);
            return n;
        }
    }
};

/// Owns a connection and the task running it, the way `datagram.Endpoint` owns
/// its socket. A TLS connection is usually a thing a program has one or a few
/// of, not one of thousands, so there is no loop group here.
pub const Client = struct {
    connection: *Connection,
    future: Io.Future(void),

    pub fn connect(options: Connection.Options) !Client {
        const connection = try Connection.connect(options);
        // Retained before the task starts, so the handle stays valid even if the
        // task finishes immediately.
        connection.retain();
        errdefer {
            connection.release();
            connection.destroy();
        }

        const future = try options.io.concurrent(Connection.serve, .{connection});
        return .{ .connection = connection, .future = future };
    }

    /// Ends the connection, waits for its task, then drops this handle's
    /// reference.
    pub fn deinit(client: *Client) void {
        const io = client.connection.io;
        client.connection.requestClose();
        client.future.await(io);
        client.connection.release();
        client.* = undefined;
    }

    /// Asks for a graceful close and waits for the task to finish.
    ///
    /// Prefer this over `deinit` when the peer should see a `close_notify`
    /// rather than a vanishing socket.
    pub fn shutdown(client: *Client) void {
        const io = client.connection.io;
        client.connection.submitClose() catch {};
        client.future.await(io);
        client.connection.release();
        client.* = undefined;
    }

    /// Sends through the pipeline, so its encoders run. This is what an
    /// application almost always wants.
    pub fn submitWrite(client: *Client, msg: Message) Error!void {
        return client.connection.submitWrite(msg);
    }

    /// Sends raw bytes, skipping the pipeline.
    pub fn write(client: *Client, msg: Message) Error!void {
        return client.connection.write(msg);
    }

    pub fn writeBytes(client: *Client, bytes: []const u8) Error!void {
        return client.connection.writeBytes(bytes);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "CaBundle: loading the system trust store yields certificates" {
    // Skipped rather than failed where there is no store to read: a container
    // without ca-certificates is a valid place to run these tests.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var bundle = CaBundle.loadSystem(gpa, io) catch |err| switch (err) {
        error.FileNotFound, error.AccessDenied => return error.SkipZigTest,
        else => return err,
    };
    defer bundle.deinit(gpa);

    try testing.expect(bundle.bundle.bytes.items.len > 0);
}

test "Connection: refuses to connect where nothing is listening" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    // Port 1 on loopback: reserved and not something a test machine serves.
    const result = Connection.connect(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .loopback(1) },
        .host = "localhost",
        .verification = .insecure,
    });
    try testing.expect(std.meta.isError(result));
}

test "Connection: a plain TCP peer is not mistaken for a TLS one" {
    // `PumpReader` bounds every TLS read, so this reaches the same broken
    // primitive as the tick tests; see `channel.zig`. Note the crash is
    // intermittent there: zio only converts the bogus address after a
    // *successful* receive, so whether it fires depends on whether the peer's
    // bytes beat the socket error.
    try channel_mod.skipIfReadDeadlinesAreBroken();
    // The handshake must fail rather than hand the application the server's
    // bytes: a peer that does not speak TLS is exactly what a downgrade looks
    // like.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.socket.close(io);

    const Peer = struct {
        fn run(listen: *Io.net.Server, inner_io: Io) void {
            const accepted = listen.accept(inner_io) catch return;
            defer accepted.close(inner_io);
            var scratch: [256]u8 = undefined;
            var writer = accepted.writer(inner_io, &scratch);
            // A plausible-looking line of a text protocol, not a TLS record.
            writer.interface.writeAll("220 not-tls ready\r\n") catch {};
            writer.interface.flush() catch {};
        }
    };
    var server = listener;
    var peer = try io.concurrent(Peer.run, .{ &server, io });
    defer peer.await(io);

    const result = Connection.connect(.{
        .gpa = gpa,
        .io = io,
        .address = listener.socket.address,
        .host = "localhost",
        .verification = .insecure,
    });
    try testing.expect(std.meta.isError(result));
}

test "Connection: verification choices map onto the session's options" {
    // A compile-time check that every `Verification` case is covered, so adding
    // one cannot silently fall through to the insecure branch.
    inline for (@typeInfo(Verification).@"union".field_names) |name| {
        comptime var seen = false;
        inline for (.{ "bundle", "self_signed", "insecure" }) |known| {
            if (comptime std.mem.eql(u8, name, known)) seen = true;
        }
        try testing.expect(seen);
    }
}
