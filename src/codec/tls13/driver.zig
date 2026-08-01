//! The parts of a TLS connection's task that do not depend on which end of the
//! handshake it is: the read loop, the outbound queue, the socket read with a
//! deadline, and the two flush rules.
//!
//! This exists because a client connection and a server connection differ in
//! exactly two places — how they are created and how the handshake starts —
//! and agree everywhere else. Writing the loop twice would put a second copy of
//! the rule that matters most (flush before blocking in a read) in the
//! repository, and this codebase has been bitten five times by a rule with two
//! implementations: break one copy and the suite stays green.
//!
//! The functions take `conn: anytype` and reach for named fields. That is duck
//! typing, checked at compile time: a connection type that is missing
//! `session`, `pipeline`, `outbound`, `closing` or `options.write_poll` fails
//! to build rather than misbehaving.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const buffer_mod = @import("../../buffer.zig");
const Buffer = buffer_mod.Buffer;
const message_mod = @import("../../message.zig");
const Message = message_mod.Message;

pub const Error = error{
    ConnectionClosed,
} || Buffer.Error;

/// Data, flushes and the close travel one queue, so their order is the order
/// they were asked for. Same shape as `Channel.Outbound` for the same reason.
pub const Outbound = union(enum) {
    /// Bytes to encrypt as they are, having skipped the pipeline.
    data: Message,
    /// A message to send *through* the pipeline, so its encoders run on the
    /// connection's own task.
    submit: Message,
    flush: void,
    /// Write what is queued, send close_notify, then shut down.
    close: void,

    pub fn deinit(item: *Outbound, gpa: Allocator) void {
        switch (item.*) {
            .data, .submit => |*msg| msg.deinit(gpa),
            .flush, .close => {},
        }
    }
};

/// Takes ownership of `msg` on every path, as every write entry point in Zinet
/// does.
pub fn enqueue(
    conn: anytype,
    msg: Message,
    comptime kind: std.meta.Tag(Outbound),
) Error!void {
    var owned = msg;
    errdefer owned.deinit(conn.gpa);
    if (conn.finished.load(.acquire)) return error.ConnectionClosed;

    var item: Outbound = @unionInit(Outbound, @tagName(kind), owned.move());
    conn.outbound.putOne(conn.io, item) catch {
        item.deinit(conn.gpa);
        return error.ConnectionClosed;
    };
    _ = conn.pending.fetchAdd(1, .monotonic);
}

/// Alternates between writing what is queued and reading what arrives.
pub fn readLoop(conn: anytype) void {
    // Application data may already be decrypted and waiting: peers coalesce
    // the end of the handshake with their first request into one TCP segment,
    // and the handshake loop consumed that whole segment. Blocking on the
    // socket before delivering it waits for a second request that a
    // request/response client will never send — the connection just hangs.
    // curl does exactly this; `openssl s_client` does not, which is why only
    // one of the two found it.
    deliverPlaintext(conn);

    var scratch: [16 * 1024]u8 = undefined;
    while (!conn.closing.load(.acquire)) {
        if (!pumpOutbound(conn)) return;

        const deadline: Io.Timestamp = Io.Timestamp.now(conn.io, .awake)
            .addDuration(conn.options.write_poll);
        const n = readSocket(conn, &scratch, deadline) catch |err| {
            finishRead(conn, err);
            return;
        };
        if (n == 0) continue; // The deadline passed; queued writes get a turn.

        conn.session.receive(conn.gpa, scratch[0..n]) catch |err| {
            // Deliver whatever was already decrypted before reporting: a
            // protocol above may have a complete message in hand.
            deliverPlaintext(conn);
            finishRead(conn, err);
            return;
        };
        // Handshake progress — a KeyUpdate answer — may want the wire.
        flushOutput(conn) catch |err| {
            finishRead(conn, err);
            return;
        };
        deliverPlaintext(conn);

        if (conn.session.state == .peer_closed) {
            // close_notify: a clean end of stream. Answer in kind.
            conn.farewell = true;
            conn.closing.store(true, .release);
            return;
        }
    }
}

pub fn deliverPlaintext(conn: anytype) void {
    const data = conn.session.appData();
    if (data.len == 0) return;
    var chunk = acquireInbound(conn, data.len) catch |err| {
        conn.pipeline.fireError(err);
        return;
    };
    chunk.writeBytes(conn.gpa, data) catch |err| {
        chunk.deinit(conn.gpa);
        conn.pipeline.fireError(err);
        return;
    };
    conn.session.consumeAppData(data.len);
    conn.pipeline.fireRead(.initBuffer(&chunk));
    conn.pipeline.fireReadComplete();
}

/// Sends everything queued, then flushes. Returns false to stop the loop.
///
/// Taking from the queue is non-blocking (`min = 0`): this task also has to get
/// back to reading, so it must never wait here. Producers still block on a full
/// queue, so backpressure is unchanged.
pub fn pumpOutbound(conn: anytype) bool {
    const io = conn.io;
    while (true) {
        var one: [1]Outbound = undefined;
        const count = conn.outbound.get(io, &one, 0) catch return false;
        if (count == 0) break;
        _ = conn.pending.fetchSub(1, .monotonic);

        switch (one[0]) {
            .data => |*msg| {
                defer msg.deinit(conn.gpa);
                const bytes = msg.bytes() orelse continue;
                conn.session.write(conn.gpa, bytes) catch return false;
            },
            .submit => |*msg| {
                // Travels the pipeline, so its encoders run — the whole reason
                // this variant exists. `Pipeline.write` consumes on every path.
                const owned = msg.move();
                conn.pipeline.write(owned) catch |err| {
                    conn.pipeline.fireError(err);
                };
            },
            .flush => flushOutput(conn) catch return false,
            .close => {
                conn.farewell = true;
                conn.closing.store(true, .release);
                return false;
            },
        }
    }

    // The single most important line here: the next thing this task does is
    // block until the peer speaks, so a record still sitting in the session's
    // output would be waiting for a reply to a request that was never sent.
    flushOutput(conn) catch return false;
    return true;
}

/// Frees whatever is left in the queue. Only safe once the queue is closed.
pub fn drainOutbound(conn: anytype) void {
    while (true) {
        var item = conn.outbound.getOneUncancelable(conn.io) catch return;
        _ = conn.pending.fetchSub(1, .monotonic);
        item.deinit(conn.gpa);
    }
}

pub fn finishRead(conn: anytype, err: anyerror) void {
    conn.closing.store(true, .release);
    if (err == error.EndOfStream) return;
    conn.pipeline.fireError(err);
}

/// One socket read. With a deadline, expiry is a zero-byte result rather than
/// an error; without one, blocks until data or end of stream.
pub fn readSocket(conn: anytype, dest: []u8, deadline: ?Io.Timestamp) !usize {
    var incoming: Io.net.IncomingMessage = .init;
    const result = conn.io.operateTimeout(.{ .net_receive = .{
        .socket_handle = conn.stream.socket.handle,
        .message_buffer = (&incoming)[0..1],
        .data_buffer = dest,
        .flags = .{},
    } }, if (deadline) |d|
        .{ .deadline = d.withClock(.awake) }
    else
        .none) catch |err| switch (err) {
        error.Timeout => return 0,
        error.Canceled => return error.Canceled,
        error.ConcurrencyUnavailable => return error.SystemResources,
    };
    const maybe_err, const count = result.net_receive;
    if (maybe_err) |err| return switch (err) {
        error.ConnectionResetByPeer => error.EndOfStream,
        error.Canceled => error.Canceled,
        else => error.Unexpected,
    };
    assert(count == 1);
    // On a stream socket a successful receive of zero bytes is the orderly
    // shutdown.
    if (incoming.data.len == 0) return error.EndOfStream;
    return incoming.data.len;
}

pub fn flushOutput(conn: anytype) !void {
    const out = conn.session.output();
    if (out.len == 0) return;
    try conn.stream_writer.interface.writeAll(out);
    try conn.stream_writer.interface.flush();
    conn.session.consumeOutput(out.len);
}

pub fn acquireInbound(conn: anytype, wanted: usize) Buffer.Error!Buffer {
    const size = @max(wanted, conn.options.read_chunk);
    if (conn.options.pool) |pool| {
        var pooled = try pool.acquire(size);
        errdefer pool.release(&pooled);
        try pooled.ensureWritable(conn.gpa, size);
        pooled.max_capacity = @max(pooled.capacity(), conn.options.max_inbound_capacity);
        return pooled;
    }
    return Buffer.init(conn.gpa, .{
        .capacity = size,
        .max_capacity = conn.options.max_inbound_capacity,
    });
}
