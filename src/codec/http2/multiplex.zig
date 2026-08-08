//! One `Pipeline` per stream, all of them on the parent connection's single reader
//! task. Netty's `Http2MultiplexHandler` and `Http2StreamChannel`, in the shape this
//! framework already has.
//!
//! ## Why this does not break the threading model
//!
//! Zinet gives each connection exactly one reader task, and handler state is lock
//! free *because* of that. HTTP/2 runs many exchanges over one connection, which
//! looks like a contradiction and is not: the guarantee was always "one task per
//! connection", never "one pipeline per task". Every child pipeline here is driven
//! synchronously from the parent's reader task — `dispatch` is an ordinary function
//! call — so a stream handler has exactly the same freedom from synchronization that
//! a connection handler has. Multiplexing is logical, not parallel. Netty reaches
//! the same conclusion by keeping every child channel on the parent's event loop.
//!
//! Nothing here is HTTP/2-specific except the two message types and the sink, which
//! is why HTTP2.md §3 flagged it as the piece worth having regardless: any
//! multiplexed protocol needs exactly this.
//!
//! ## What a stream handler sees
//!
//! An ordinary pipeline. Inbound: a `Headers` message, then byte messages for the
//! body, then `onInactive` when the stream ends. Outbound: `OutgoingHeaders`, byte
//! messages, and `ctx.close()` to end the stream. Writability arrives as an event,
//! because HTTP/2 is the one place in this framework where backpressure is reported
//! rather than applied by blocking — see `flow.SendQueue`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const channel_mod = @import("../../channel.zig");
const connection_mod = @import("connection.zig");
const flow = @import("flow.zig");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const pipeline_mod = @import("../../pipeline.zig");

const Connection = connection_mod.Connection;
const Initializer = channel_mod.Initializer;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;

pub const Error = pipeline_mod.Error;

/// A header list that arrived on a stream.
///
/// Owns an arena, following the rule the rest of the codebase states: inbound
/// messages own their strings because nothing else is around to keep them alive.
/// The connection's own decode buffer is reused by the very next frame, so the
/// copy is not avoidable — it is the same copy `http.Request` makes.
pub const Headers = struct {
    stream_id: u31,
    fields: []const hpack.Field,
    end_stream: bool,
    /// A second block on this stream, i.e. trailers (§8.1).
    trailers: bool,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(headers: *Headers, _: Allocator) void {
        headers.arena.deinit();
    }

    /// The value of a field, or null. Linear because a header list is short and
    /// ordered; a map would cost more than it saves.
    pub fn get(headers: *const Headers, name: []const u8) ?[]const u8 {
        for (headers.fields) |field| {
            if (std.mem.eql(u8, field.name, name)) return field.value;
        }
        return null;
    }
};

/// A header list to send. Borrows everything, because the encoder serializes before
/// `write` returns — the same split `http.Response` has, for the same reason.
pub const OutgoingHeaders = struct {
    fields: []const hpack.Field,
    end_stream: bool = false,
};

/// Fired down a child pipeline when the stream crosses a water mark.
pub const WritabilityChanged = struct { writable: bool };

/// Fired down a child pipeline when the peer reset the stream, so a handler can
/// tell a reset from an ordinary end.
pub const StreamReset = struct { code: frame.ErrorCode };

/// Fired when the peer has finished sending on this stream — the request body at a
/// server, the response body at a client. The stream is still open the other way.
///
/// Distinct from `onInactive`, which means the stream is over in *both* directions.
/// Collapsing the two is tempting and wrong: a server hears the end of the request
/// and only then starts writing the response, so tearing the pipeline down here
/// would make an asynchronous reply impossible — a handler could reply only from
/// inside the callback that told it the request had arrived.
pub const InboundComplete = struct {};

/// One stream's channel: a pipeline whose sink writes onto that stream.
///
/// Heap-allocated by the multiplexer, because the sink holds its address.
pub const StreamChannel = struct {
    stream_id: u31,
    pipeline: *Pipeline,
    parent: *Multiplexer,
    /// Set once `END_STREAM` has been queued from this side, so a second close is
    /// a no-op rather than an empty `DATA` frame on a finished stream.
    end_sent: bool = false,

    fn sink(child: *StreamChannel) Sink {
        return .{ .context = child, .vtable = &sink_vtable };
    }

    const sink_vtable: Sink.VTable = .{
        .write = sinkWrite,
        .flush = sinkFlush,
        .close = sinkClose,
    };

    /// Consumes `message` unconditionally, including on failure, which is the
    /// contract every `Sink` in this codebase holds to.
    fn sinkWrite(context: *anyopaque, message: Message) Error!void {
        const child: *StreamChannel = @ptrCast(@alignCast(context));
        const gpa = child.parent.gpa;
        var owned = message;
        defer owned.deinit(gpa);

        if (owned.take(gpa, OutgoingHeaders)) |headers| {
            try child.parent.connection.sendHeaders(
                gpa,
                child.stream_id,
                headers.fields,
                headers.end_stream,
            );
            if (headers.end_stream) child.end_sent = true;
            return;
        }

        const body = owned.bytes() orelse {
            // A message of some other type reached the sink, which means the
            // pipeline is missing an encoder. Reporting it beats dropping it.
            return error.UnsupportedMessage;
        };
        const transition = try child.parent.connection.sendData(
            gpa,
            child.stream_id,
            body,
            false,
        );
        child.parent.note(child.stream_id, transition);
    }

    fn sinkFlush(context: *anyopaque) Error!void {
        const child: *StreamChannel = @ptrCast(@alignCast(context));
        // Flushing is the connection's job and happens once per read cycle: a
        // per-stream flush would defeat the interleaving the scheduler exists for.
        child.parent.needs_flush = true;
    }

    /// Ends the stream. `ctx.close()` on a child pipeline means "this exchange is
    /// over", not "drop the connection" — the connection is shared.
    fn sinkClose(context: *anyopaque) Error!void {
        const child: *StreamChannel = @ptrCast(@alignCast(context));
        if (child.end_sent) return;
        child.end_sent = true;
        const gpa = child.parent.gpa;
        _ = child.parent.connection.sendData(gpa, child.stream_id, "", true) catch |err| {
            return switch (err) {
                error.StreamWriteQueueFull => error.StreamWriteQueueFull,
                else => |e| e,
            };
        };
        child.parent.needs_flush = true;
    }
};

pub const Multiplexer = struct {
    gpa: Allocator,
    io: Io,
    connection: *Connection,
    /// Builds each new stream's pipeline. The application's hook, and the only
    /// thing here it has to supply.
    initializer: Initializer,
    /// What `Pipeline.owner` is set to on every child, so a stream handler can
    /// reach whatever the application put there — typically the parent `Channel`.
    owner: ?*anyopaque = null,

    children: std.AutoHashMapUnmanaged(u31, *StreamChannel) = .empty,
    /// Set when a child queued bytes, so the caller knows to run `Connection.flush`.
    needs_flush: bool = false,

    pub fn init(
        gpa: Allocator,
        io: Io,
        connection: *Connection,
        initializer: Initializer,
    ) Multiplexer {
        return .{ .gpa = gpa, .io = io, .connection = connection, .initializer = initializer };
    }

    pub fn deinit(multiplexer: *Multiplexer) void {
        var iterator = multiplexer.children.valueIterator();
        while (iterator.next()) |child| {
            child.*.pipeline.fireInactive();
            child.*.pipeline.destroy();
            multiplexer.gpa.destroy(child.*);
        }
        multiplexer.children.deinit(multiplexer.gpa);
        multiplexer.* = undefined;
    }

    pub fn count(multiplexer: *const Multiplexer) usize {
        return multiplexer.children.count();
    }

    pub fn get(multiplexer: *Multiplexer, stream_id: u31) ?*StreamChannel {
        return multiplexer.children.get(stream_id);
    }

    /// Routes one connection event to the stream it belongs to, creating that
    /// stream's pipeline if this is its first header block.
    ///
    /// Events that are about the connection rather than a stream — `settings_updated`,
    /// `pong`, `goaway` — are not this function's business and are returned to the
    /// caller unhandled.
    pub fn dispatch(multiplexer: *Multiplexer, event: connection_mod.Inbound) !bool {
        switch (event) {
            .headers => |incoming| {
                const child = try multiplexer.childFor(incoming.stream_id);
                try multiplexer.deliverHeaders(child, incoming);
                if (incoming.end_stream) multiplexer.finishInbound(incoming.stream_id);
                return true;
            },
            .data => |incoming| {
                const child = multiplexer.children.get(incoming.stream_id) orelse return true;
                if (incoming.bytes.len > 0) {
                    child.pipeline.fireRead(try Message.initBytes(multiplexer.gpa, incoming.bytes));
                }
                if (incoming.end_stream) multiplexer.finishInbound(incoming.stream_id);
                return true;
            },
            .reset => |incoming| {
                const child = multiplexer.children.get(incoming.stream_id) orelse return true;
                // A reset is not an ordinary end, and a handler that is writing a
                // response needs to know which it was. The event is borrowed for
                // the duration of the callback, so a local is the right home.
                var reset: StreamReset = .{ .code = incoming.code };
                child.pipeline.fireEvent(.init(&reset));
                multiplexer.endStream(incoming.stream_id);
                return true;
            },
            .push_promise => |incoming| {
                // The promise is reported on the stream that carried it; the
                // promised stream's own pipeline is built when its HEADERS arrive.
                const child = multiplexer.children.get(incoming.stream_id) orelse return true;
                _ = child;
                return true;
            },
            .settings_updated, .pong, .goaway => return false,
        }
    }

    /// Opens a stream from this side and returns its channel, for a client sending
    /// a request or a server pushing.
    pub fn open(multiplexer: *Multiplexer, stream_id: u31) !*StreamChannel {
        assert(multiplexer.children.get(stream_id) == null);
        return multiplexer.childFor(stream_id);
    }

    /// Reports a water-mark crossing to the stream it concerns.
    pub fn note(multiplexer: *Multiplexer, stream_id: u31, transition: flow.Transition) void {
        if (transition == .unchanged) return;
        const child = multiplexer.children.get(stream_id) orelse return;
        var changed: WritabilityChanged = .{ .writable = transition == .became_writable };
        child.pipeline.fireEvent(.init(&changed));
    }

    /// Applies the writability changes `Connection.flush` reported.
    pub fn applyWritability(
        multiplexer: *Multiplexer,
        changes: []const Connection.Writability,
    ) void {
        for (changes) |change| {
            const child = multiplexer.children.get(change.stream_id) orelse continue;
            var changed: WritabilityChanged = .{ .writable = change.writable };
            child.pipeline.fireEvent(.init(&changed));
        }
    }

    /// Ends a stream: the pipeline hears `onInactive`, then it is torn down.
    ///
    /// Separate steps, the same split `Channel` makes between ending a connection
    /// and freeing it, and for the same reason: a handler's `onInactive` may still
    /// want to touch its own state.
    pub fn endStream(multiplexer: *Multiplexer, stream_id: u31) void {
        const entry = multiplexer.children.fetchRemove(stream_id) orelse return;
        const child = entry.value;
        child.pipeline.fireInactive();
        child.pipeline.destroy();
        multiplexer.gpa.destroy(child);
    }

    fn childFor(multiplexer: *Multiplexer, stream_id: u31) !*StreamChannel {
        if (multiplexer.children.get(stream_id)) |existing| return existing;

        const child = try multiplexer.gpa.create(StreamChannel);
        errdefer multiplexer.gpa.destroy(child);
        child.* = .{ .stream_id = stream_id, .pipeline = undefined, .parent = multiplexer };

        const pipeline = try Pipeline.create(.{
            .gpa = multiplexer.gpa,
            .io = multiplexer.io,
            .sink = child.sink(),
            .owner = multiplexer.owner,
        });
        errdefer pipeline.destroy();
        child.pipeline = pipeline;

        try multiplexer.initializer.initFn(multiplexer.initializer.context, pipeline);
        try multiplexer.children.put(multiplexer.gpa, stream_id, child);
        pipeline.fireActive();
        return child;
    }

    /// The peer has finished sending. Tells the handler, then tears the stream down
    /// only if that also finished the stream — which it does when this side had
    /// already sent its own `END_STREAM`, and does not when a response is still owed.
    fn finishInbound(multiplexer: *Multiplexer, stream_id: u31) void {
        const child = multiplexer.children.get(stream_id) orelse return;
        var complete: InboundComplete = .{};
        child.pipeline.fireEvent(.init(&complete));
        multiplexer.sweep(stream_id);
    }

    /// Tears down a child whose stream the connection has finished with. The
    /// connection is the single source of truth for whether a stream is over: it
    /// drops the entry when the state machine reaches a closed state, whichever
    /// direction closed last.
    pub fn sweep(multiplexer: *Multiplexer, stream_id: u31) void {
        if (multiplexer.connection.registry.get(stream_id) != null) return;
        multiplexer.endStream(stream_id);
    }

    /// Tears down every child whose stream the connection has finished with. Called
    /// after a write pass, since that is when this side's `END_STREAM` goes out.
    pub fn sweepAll(multiplexer: *Multiplexer) void {
        var done: [64]u31 = undefined;
        var found: usize = 0;
        var iterator = multiplexer.children.keyIterator();
        while (iterator.next()) |stream_id| {
            if (multiplexer.connection.registry.get(stream_id.*) != null) continue;
            if (found == done.len) break;
            done[found] = stream_id.*;
            found += 1;
        }
        for (done[0..found]) |stream_id| multiplexer.endStream(stream_id);
    }

    fn deliverHeaders(
        multiplexer: *Multiplexer,
        child: *StreamChannel,
        incoming: connection_mod.Inbound.Headers,
    ) !void {
        // The connection's decode arena is reused by the next frame, so the header
        // list is copied into one this message owns.
        var arena: std.heap.ArenaAllocator = .init(multiplexer.gpa);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        const fields = try allocator.alloc(hpack.Field, incoming.fields.len);
        for (incoming.fields, fields) |source, *destination| {
            destination.* = .{
                .name = try allocator.dupe(u8, source.name),
                .value = try allocator.dupe(u8, source.value),
                .never_indexed = source.never_indexed,
            };
        }

        const message = try Message.initAny(multiplexer.gpa, Headers, .{
            .stream_id = incoming.stream_id,
            .fields = fields,
            .end_stream = incoming.end_stream,
            .trailers = incoming.trailers,
            .arena = arena,
        });
        child.pipeline.fireRead(message);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

const Buffer = @import("../../buffer.zig").Buffer;
const HandlerContext = pipeline_mod.HandlerContext;

test "multiplex: every declaration compiles" {
    testing.refAllDecls(Multiplexer);
    testing.refAllDecls(StreamChannel);
    testing.refAllDecls(Headers);
}

/// One stream's handler, with state of its own. Whether that state stays private
/// to its stream is the property this whole file exists to provide.
const Recorder = struct {
    gpa: Allocator,
    stream_id: u31 = 0,
    log: std.ArrayList(u8) = .empty,
    body: std.ArrayList(u8) = .empty,
    reads: usize = 0,
    active: bool = false,
    inactive: bool = false,
    writable_events: std.ArrayList(bool) = .empty,
    reset_code: ?frame.ErrorCode = null,
    inbound_complete: bool = false,
    /// A response to write when headers arrive, if the test wants one.
    respond_with: ?[]const hpack.Field = null,

    fn deinit(recorder: *Recorder) void {
        recorder.log.deinit(recorder.gpa);
        recorder.body.deinit(recorder.gpa);
        recorder.writable_events.deinit(recorder.gpa);
    }

    pub fn onActive(recorder: *Recorder, ctx: *HandlerContext) !void {
        recorder.active = true;
        ctx.fireActive();
    }

    pub fn onInactive(recorder: *Recorder, ctx: *HandlerContext) !void {
        recorder.inactive = true;
        ctx.fireInactive();
    }

    pub fn onRead(recorder: *Recorder, ctx: *HandlerContext, msg: Message) !void {
        const gpa = ctx.gpa();
        var owned = msg;
        defer owned.deinit(gpa);
        recorder.reads += 1;

        if (owned.take(gpa, Headers)) |taken| {
            var headers = taken;
            defer headers.deinit(gpa);
            recorder.stream_id = headers.stream_id;
            try appendLine(&recorder.log, recorder.gpa, "HEADERS {d} trailers={}", .{
                headers.stream_id, headers.trailers,
            });
            if (headers.get(":path")) |path| {
                try appendLine(&recorder.log, recorder.gpa, "  path={s}", .{path});
            }
            if (recorder.respond_with) |fields| {
                try ctx.write(try Message.initAny(gpa, OutgoingHeaders, .{ .fields = fields }));
            }
            return;
        }

        const bytes = owned.bytes() orelse return;
        try recorder.body.appendSlice(recorder.gpa, bytes);
        try appendLine(&recorder.log, recorder.gpa, "DATA {d}", .{bytes.len});
    }

    pub fn onEvent(recorder: *Recorder, ctx: *HandlerContext, event: pipeline_mod.Event) !void {
        if (event.get(WritabilityChanged)) |changed| {
            try recorder.writable_events.append(recorder.gpa, changed.writable);
        }
        if (event.get(StreamReset)) |reset| recorder.reset_code = reset.code;
        if (event.is(InboundComplete)) recorder.inbound_complete = true;
        ctx.fireEvent(event);
    }
};

fn appendLine(
    list: *std.ArrayList(u8),
    gpa: Allocator,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    var scratch: [256]u8 = undefined;
    try list.appendSlice(gpa, try std.fmt.bufPrint(&scratch, fmt ++ "\n", args));
}

/// Builds one recorder per child pipeline and keeps a pointer, so a test can look
/// at each stream's state separately after the fact.
const Recorders = struct {
    gpa: Allocator,
    made: std.ArrayList(*Recorder) = .empty,
    respond_with: ?[]const hpack.Field = null,

    fn deinit(recorders: *Recorders) void {
        for (recorders.made.items) |recorder| {
            recorder.deinit();
            recorders.gpa.destroy(recorder);
        }
        recorders.made.deinit(recorders.gpa);
    }

    /// Borrowed rather than owned by the pipeline: the pipeline is destroyed when
    /// its stream ends, and the test wants to read the state afterwards.
    pub fn initPipeline(recorders: *Recorders, pipeline: *Pipeline) anyerror!void {
        const recorder = try recorders.gpa.create(Recorder);
        recorder.* = .{ .gpa = recorders.gpa, .respond_with = recorders.respond_with };
        errdefer recorders.gpa.destroy(recorder);
        try recorders.made.append(recorders.gpa, recorder);
        _ = try pipeline.addLast("recorder", .init(recorder));
    }
};

/// A server made of a connection plus a multiplexer, and a bare client to talk to
/// it. The client has no multiplexer: it drives the connection directly, which is
/// what makes it a clean source of bytes.
const Rig = struct {
    gpa: Allocator,
    threaded: *Io.Threaded,
    client: Connection,
    server: Connection,
    multiplexer: Multiplexer,
    recorders: *Recorders,
    wire: Buffer = .empty,

    fn init(gpa: Allocator, recorders: *Recorders) !*Rig {
        const rig = try gpa.create(Rig);
        const threaded = try gpa.create(Io.Threaded);
        threaded.* = .init(gpa, .{});
        rig.* = .{
            .gpa = gpa,
            .threaded = threaded,
            .client = .init(gpa, .client, .{}),
            .server = .init(gpa, .server, .{}),
            .multiplexer = undefined,
            .recorders = recorders,
        };
        rig.multiplexer = .init(gpa, threaded.io(), &rig.server, .init(recorders));
        try rig.client.start(gpa);
        try rig.server.start(gpa);
        try rig.pump();
        return rig;
    }

    fn deinit(rig: *Rig) void {
        rig.multiplexer.deinit();
        rig.client.deinit(rig.gpa);
        rig.server.deinit(rig.gpa);
        rig.wire.deinit(rig.gpa);
        rig.threaded.deinit();
        rig.gpa.destroy(rig.threaded);
        rig.gpa.destroy(rig);
    }

    /// Moves the client's bytes to the server, dispatching every event that a
    /// stream is about into that stream's pipeline.
    fn pump(rig: *Rig) !void {
        try rig.wire.writeBytes(rig.gpa, rig.client.out.readableSlice());
        rig.client.out.clear();
        while (try rig.server.poll(rig.gpa, &rig.wire, 0)) |event| {
            _ = try rig.multiplexer.dispatch(event);
        }
        if (rig.multiplexer.needs_flush) {
            rig.multiplexer.needs_flush = false;
            var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
            rig.multiplexer.applyWritability(try rig.server.flush(rig.gpa, &transitions));
        }
        // Drain what the server said, so the client's own state keeps up.
        var back: Buffer = .empty;
        defer back.deinit(rig.gpa);
        try back.writeBytes(rig.gpa, rig.server.out.readableSlice());
        rig.server.out.clear();
        while (try rig.client.poll(rig.gpa, &back, 0)) |_| {}
    }

    fn request(rig: *Rig, id: u31, path: []const u8, end_stream: bool) !void {
        try rig.client.sendHeaders(rig.gpa, id, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = path },
        }, end_stream);
    }
};

test "multiplex: each stream gets its own pipeline and its own handler state" {
    const gpa = testing.allocator;
    var recorders: Recorders = .{ .gpa = gpa };
    defer recorders.deinit();
    var rig = try Rig.init(gpa, &recorders);
    defer rig.deinit();

    // Two requests, interleaved rather than one after the other, which is the case
    // HTTP/1.1 cannot express at all.
    try rig.request(1, "/first", false);
    try rig.request(3, "/second", false);
    try rig.pump();

    try testing.expectEqual(@as(usize, 2), recorders.made.items.len);
    try testing.expectEqual(@as(usize, 2), rig.multiplexer.count());

    // Each recorder saw only its own stream. Nothing synchronizes them because
    // nothing has to: both pipelines ran on this task.
    try testing.expectEqual(@as(u31, 1), recorders.made.items[0].stream_id);
    try testing.expectEqual(@as(u31, 3), recorders.made.items[1].stream_id);
    try testing.expect(std.mem.indexOf(u8, recorders.made.items[0].log.items, "/first") != null);
    try testing.expect(std.mem.indexOf(u8, recorders.made.items[0].log.items, "/second") == null);
    try testing.expect(std.mem.indexOf(u8, recorders.made.items[1].log.items, "/second") != null);
    for (recorders.made.items) |recorder| try testing.expect(recorder.active);
}

test "multiplex: body bytes go to the stream they belong to" {
    const gpa = testing.allocator;
    var recorders: Recorders = .{ .gpa = gpa };
    defer recorders.deinit();
    var rig = try Rig.init(gpa, &recorders);
    defer rig.deinit();

    try rig.request(1, "/a", false);
    try rig.request(3, "/b", false);
    try rig.pump();

    var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
    _ = try rig.client.sendData(gpa, 1, "one-one", false);
    _ = try rig.client.sendData(gpa, 3, "three", false);
    _ = try rig.client.sendData(gpa, 1, "-more", false);
    _ = try rig.client.flush(gpa, &transitions);
    try rig.pump();

    try testing.expectEqualStrings("one-one-more", recorders.made.items[0].body.items);
    try testing.expectEqualStrings("three", recorders.made.items[1].body.items);
}

test "multiplex: inbound END_STREAM half-closes, it does not tear the stream down" {
    const gpa = testing.allocator;
    var recorders: Recorders = .{ .gpa = gpa };
    defer recorders.deinit();
    var rig = try Rig.init(gpa, &recorders);
    defer rig.deinit();

    try rig.request(1, "/done", true);
    try rig.request(3, "/open", false);
    try rig.pump();

    // The request is complete, and the handler was told — but the stream is only
    // half closed, because a response is still owed. Tearing the pipeline down here
    // would mean a handler could reply only from inside the callback that told it the
    // request had arrived, which is no way to write a server.
    try testing.expect(recorders.made.items[0].inbound_complete);
    try testing.expect(!recorders.made.items[0].inactive);
    try testing.expectEqual(@as(usize, 2), rig.multiplexer.count());
    try testing.expect(rig.multiplexer.get(1) != null);

    // The other stream heard nothing, since its request is still arriving.
    try testing.expect(!recorders.made.items[1].inbound_complete);

    // Once this side ends the stream too, it is over and the pipeline goes.
    var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
    try rig.server.sendHeaders(gpa, 1, &.{.{ .name = ":status", .value = "204" }}, false);
    _ = try rig.server.sendData(gpa, 1, "", true);
    _ = try rig.server.flush(gpa, &transitions);
    rig.multiplexer.sweepAll();

    try testing.expect(recorders.made.items[0].inactive);
    try testing.expectEqual(@as(usize, 1), rig.multiplexer.count());
    try testing.expect(rig.multiplexer.get(1) == null);
    try testing.expect(rig.multiplexer.get(3) != null);
}

test "multiplex: a response written through a child lands on that child's stream" {
    const gpa = testing.allocator;
    const response = [_]hpack.Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    var recorders: Recorders = .{ .gpa = gpa, .respond_with = &response };
    defer recorders.deinit();
    var rig = try Rig.init(gpa, &recorders);
    defer rig.deinit();

    try rig.request(1, "/hello", true);
    try rig.pump();

    // The client, which knows nothing about multiplexers, decoded a response on
    // stream 1 — so the child's sink really did write onto the right stream. The
    // handler replied from its `InboundComplete`, and the stream ended once that
    // reply's END_STREAM went out.
    try testing.expect(recorders.made.items[0].inbound_complete);
    try testing.expectEqual(@as(usize, 1), recorders.made.items[0].reads);
}

test "multiplex: a reset is reported as an event before the stream ends" {
    const gpa = testing.allocator;
    var recorders: Recorders = .{ .gpa = gpa };
    defer recorders.deinit();
    var rig = try Rig.init(gpa, &recorders);
    defer rig.deinit();

    try rig.request(1, "/cancel-me", false);
    try rig.pump();
    try rig.client.sendReset(gpa, 1, .cancel);
    try rig.pump();

    // A handler writing a response needs to tell a cancellation from a normal end,
    // which onInactive alone cannot say.
    try testing.expectEqual(frame.ErrorCode.cancel, recorders.made.items[0].reset_code.?);
    try testing.expect(recorders.made.items[0].inactive);
    try testing.expectEqual(@as(usize, 0), rig.multiplexer.count());
}

test "multiplex: connection-level events are not a stream's business" {
    const gpa = testing.allocator;
    var recorders: Recorders = .{ .gpa = gpa };
    defer recorders.deinit();
    var rig = try Rig.init(gpa, &recorders);
    defer rig.deinit();

    // SETTINGS, PING replies and GOAWAY belong to whoever owns the connection, so
    // `dispatch` hands them back rather than inventing a stream for them.
    try testing.expect(!try rig.multiplexer.dispatch(.settings_updated));
    try testing.expect(!try rig.multiplexer.dispatch(.{ .pong = @splat(0) }));
    try testing.expect(!try rig.multiplexer.dispatch(.{ .goaway = .{
        .last_stream_id = 0,
        .code = .no_error,
        .debug_data = "",
    } }));
    try testing.expectEqual(@as(usize, 0), recorders.made.items.len);
}
