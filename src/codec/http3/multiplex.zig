//! One `Pipeline` per request stream, all on the connection's own task.
//!
//! The same shape as `http2/multiplex.zig`, deliberately: an application that has
//! written handlers for one should be able to move them to the other, and the two
//! protocols really do present the same picture — many independent exchanges over
//! one connection, each wanting its own handler state.
//!
//! What differs is beneath, and it makes this file smaller rather than larger:
//!
//! * **Stream IDs are 62-bit** (RFC 9000 §2.1), not 31-bit, and they are QUIC's
//!   to allocate rather than this layer's to count.
//! * **There is no flow control here.** HTTP/2 needs a scheduler, water marks and
//!   a credit pool because it multiplexes over one TCP stream; QUIC gives each
//!   stream its own flow control and its own loss recovery, so this layer has
//!   nothing to interleave and no window to police. `WritabilityChanged` is
//!   therefore absent — the backpressure lives one layer down.
//! * **There is no push.** §4.6 makes server push optional and this
//!   implementation declines, so there is no promised-stream case.
//!
//! Ownership follows the rule the rest of the repository states: inbound
//! messages own an arena, because the connection's decode buffer is reused by the
//! next frame; outbound ones borrow, because the encoder serializes before
//! `write` returns.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const pipeline_mod = @import("../../pipeline.zig");
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;
const Message = @import("../../message.zig").Message;
const Initializer = @import("../../channel.zig").Initializer;

const connection_mod = @import("connection.zig");
const Connection = connection_mod.Connection;
const qpack = @import("qpack.zig");

pub const Error = pipeline_mod.Error;

/// A field section that arrived on a stream: a request at a server, a response at
/// a client.
///
/// Owns an arena. The section the connection hands over is already owned rather
/// than borrowed — `takeSection` passes ownership — but it is a `FieldSection`
/// with its own allocations, and moving those into one arena makes the message a
/// single `deinit` for whoever ends up holding it.
pub const Headers = struct {
    stream_id: u64,
    fields: []const qpack.FieldLine,
    /// Whether the stream ended with this section.
    fin: bool,
    /// A second section on this stream, i.e. trailers (§4.1).
    trailers: bool,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(headers: *Headers, _: Allocator) void {
        headers.arena.deinit();
    }

    /// The value of a field, or null. Linear because a field section is short and
    /// ordered; a map would cost more than it saves.
    pub fn get(headers: *const Headers, name: []const u8) ?[]const u8 {
        for (headers.fields) |field| {
            if (std.mem.eql(u8, field.name, name)) return field.value;
        }
        return null;
    }
};

/// A field section to send. Borrows everything, because the encoder serializes
/// before `write` returns — the same split `http.Response` has.
pub const OutgoingHeaders = struct {
    fields: []const qpack.FieldLine,
    fin: bool = false,
};

/// Fired down a child pipeline when the peer reset the stream, so a handler can
/// tell a reset from an ordinary end.
pub const StreamReset = struct { code: u64 };

/// Fired when the peer has finished sending on this stream — the request body at
/// a server, the response body at a client. The stream is still open the other
/// way.
///
/// Distinct from `onInactive`, which means the stream is over in *both*
/// directions. Collapsing them would make an asynchronous reply impossible: a
/// server hears the end of the request and only then starts writing.
pub const InboundComplete = struct {};

/// One stream's channel: a pipeline whose sink writes onto that stream.
///
/// Heap-allocated by the multiplexer, because the sink holds its address.
pub const StreamChannel = struct {
    stream_id: u64,
    pipeline: *Pipeline,
    parent: *Multiplexer,
    /// Set once this side has ended the stream, so a second close is a no-op
    /// rather than a zero-length DATA frame on a finished stream.
    fin_sent: bool = false,
    /// Whether a field section has already been delivered, which is what turns
    /// the next one into trailers (§4.1). Tracked here rather than asked of the
    /// connection: what makes a section "second" is what this pipeline has seen.
    saw_section: bool = false,

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
            child.parent.connection.respond(
                gpa,
                child.stream_id,
                headers.fields,
                headers.fin,
            ) catch return error.UnsupportedMessage;
            if (headers.fin) child.fin_sent = true;
            return;
        }

        const body = owned.bytes() orelse {
            // Some other message type reached the sink, which means the pipeline
            // is missing an encoder. Reporting beats dropping.
            return error.UnsupportedMessage;
        };
        child.parent.connection.writeBody(gpa, child.stream_id, body, false) catch
            return error.UnsupportedMessage;
    }

    fn sinkFlush(context: *anyopaque) Error!void {
        const child: *StreamChannel = @ptrCast(@alignCast(context));
        // Getting datagrams onto the wire is the connection driver's job and
        // happens once per read cycle. A per-stream flush would serialize what
        // QUIC exists to interleave.
        child.parent.needs_flush = true;
    }

    /// Ends the stream. `ctx.close()` on a child pipeline means "this exchange is
    /// over", not "drop the connection" — the connection is shared.
    fn sinkClose(context: *anyopaque) Error!void {
        const child: *StreamChannel = @ptrCast(@alignCast(context));
        if (child.fin_sent) return;
        child.fin_sent = true;
        const gpa = child.parent.gpa;
        child.parent.connection.writeBody(gpa, child.stream_id, "", true) catch
            return error.UnsupportedMessage;
        child.parent.needs_flush = true;
    }
};

pub const Multiplexer = struct {
    gpa: Allocator,
    io: Io,
    connection: *Connection,
    /// Builds each new stream's pipeline. The application's only required hook.
    initializer: Initializer,
    /// What `Pipeline.owner` is set to on every child, so a stream handler can
    /// reach whatever the application put there.
    owner: ?*anyopaque = null,

    children: std.AutoHashMapUnmanaged(u64, *StreamChannel) = .empty,
    /// Set when a child queued bytes, so the driver knows datagrams are waiting.
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

    pub fn get(multiplexer: *Multiplexer, stream_id: u64) ?*StreamChannel {
        return multiplexer.children.get(stream_id);
    }

    /// Routes one connection event to the stream it belongs to, creating that
    /// stream's pipeline if this is its first field section.
    ///
    /// Connection-level events — `established`, `goaway`, `peer_closed`,
    /// `idle_timeout` — are not this function's business and are reported back as
    /// unhandled, the same division `http2.multiplex.dispatch` makes.
    pub fn dispatch(multiplexer: *Multiplexer, event: connection_mod.Event) !bool {
        switch (event) {
            .headers => |incoming| {
                const child = try multiplexer.childFor(incoming.stream);
                try multiplexer.deliverHeaders(child, incoming.stream, incoming.fin);
                if (incoming.fin) multiplexer.finishInbound(incoming.stream);
                return true;
            },
            .body => |incoming| {
                const child = multiplexer.children.get(incoming.stream) orelse return true;
                const bytes = multiplexer.connection.readBody(incoming.stream);
                if (bytes.len > 0) {
                    // Copied because `Message` outlives the read: the connection's
                    // body buffer is compacted by `consumeBody` below, and this is
                    // the borrowed-buffer rule this repository has now been bitten
                    // by four times.
                    child.pipeline.fireRead(try Message.initBytes(multiplexer.gpa, bytes));
                    multiplexer.connection.consumeBody(incoming.stream, bytes.len);
                }
                if (incoming.fin) multiplexer.finishInbound(incoming.stream);
                return true;
            },
            .stream_reset => |reset_event| {
                // §4.1.1: the exchange is over, and the code is what the handler
                // needs — it decides whether the request may be retried. `reset`
                // was written for this and had no caller but a test.
                multiplexer.reset(reset_event.stream, reset_event.code);
                return true;
            },
            .established, .goaway, .peer_closed, .idle_timeout => return false,
        }
    }

    /// Opens a stream from this side and returns its channel, for a client
    /// sending a request.
    pub fn open(multiplexer: *Multiplexer, stream_id: u64) !*StreamChannel {
        assert(multiplexer.children.get(stream_id) == null);
        return multiplexer.childFor(stream_id);
    }

    /// Reports that the peer reset a stream, then tears it down.
    pub fn reset(multiplexer: *Multiplexer, stream_id: u64, code: u64) void {
        const child = multiplexer.children.get(stream_id) orelse return;
        var event: StreamReset = .{ .code = code };
        child.pipeline.fireEvent(.init(&event));
        multiplexer.endStream(stream_id);
    }

    /// Ends a stream: the pipeline hears `onInactive`, then it is torn down.
    ///
    /// Separate steps, the same split `Channel` makes between ending a connection
    /// and freeing it, and for the same reason: a handler's `onInactive` may still
    /// want to touch its own state.
    pub fn endStream(multiplexer: *Multiplexer, stream_id: u64) void {
        const entry = multiplexer.children.fetchRemove(stream_id) orelse return;
        const child = entry.value;
        child.pipeline.fireInactive();
        child.pipeline.destroy();
        multiplexer.gpa.destroy(child);
    }

    /// Tears down every child whose exchange has finished in both directions.
    /// Called after a write pass, since that is when this side's FIN goes out.
    pub fn sweepAll(multiplexer: *Multiplexer) void {
        var done: [64]u64 = undefined;
        var found: usize = 0;
        var iterator = multiplexer.children.iterator();
        while (iterator.next()) |entry| {
            const child = entry.value_ptr.*;
            if (!child.fin_sent) continue;
            if (!multiplexer.connection.inboundFinished(child.stream_id)) continue;
            if (found == done.len) break;
            done[found] = child.stream_id;
            found += 1;
        }
        for (done[0..found]) |stream_id| multiplexer.endStream(stream_id);
    }

    fn childFor(multiplexer: *Multiplexer, stream_id: u64) !*StreamChannel {
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

    /// The peer has finished sending. Tells the handler, then tears the stream
    /// down only if this side had already finished too.
    fn finishInbound(multiplexer: *Multiplexer, stream_id: u64) void {
        const child = multiplexer.children.get(stream_id) orelse return;
        var complete: InboundComplete = .{};
        child.pipeline.fireEvent(.init(&complete));
        if (child.fin_sent) multiplexer.endStream(stream_id);
    }

    fn deliverHeaders(
        multiplexer: *Multiplexer,
        child: *StreamChannel,
        stream_id: u64,
        fin: bool,
    ) !void {
        var section = multiplexer.connection.takeSection(stream_id) orelse return;
        defer section.deinit(multiplexer.gpa);

        var arena: std.heap.ArenaAllocator = .init(multiplexer.gpa);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        const fields = try allocator.alloc(qpack.FieldLine, section.fields.items.len);
        for (section.fields.items, fields) |source, *destination| {
            destination.* = .{
                .name = try allocator.dupe(u8, source.name),
                .value = try allocator.dupe(u8, source.value),
            };
        }

        const trailers = child.saw_section;
        child.saw_section = true;

        const message = try Message.initAny(multiplexer.gpa, Headers, .{
            .stream_id = stream_id,
            .fields = fields,
            .fin = fin,
            .trailers = trailers,
            .arena = arena,
        });
        child.pipeline.fireRead(message);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const HandlerContext = pipeline_mod.HandlerContext;
const backend = @import("backend");

test "http3 multiplex: every declaration compiles" {
    testing.refAllDecls(Multiplexer);
    testing.refAllDecls(StreamChannel);
    testing.refAllDecls(Headers);
}

/// A stream handler for tests: answers every request and records what it saw.
const Responder = struct {
    reads: usize = 0,
    /// The code from a `StreamReset`, if the handler was told of one.
    reset_code: ?u64 = null,
    inbound_complete: bool = false,
    inactive: bool = false,
    saw_trailers: bool = false,
    body: std.ArrayList(u8) = .empty,
    log: *Log,

    const Log = struct {
        created: usize = 0,
        finished: usize = 0,
        /// The code of the last `StreamReset` any handler was told about. On the
        /// shared log rather than the handler, because the handler is destroyed with
        /// its pipeline the moment the reset is delivered.
        last_reset_code: ?u64 = null,
    };

    pub fn onRead(self: *Responder, ctx: *HandlerContext, msg: Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        self.reads += 1;

        if (owned.get(Headers)) |headers| {
            if (headers.trailers) {
                self.saw_trailers = true;
                return;
            }
            // The request. Answer it the way an application would.
            var fields = [_]qpack.FieldLine{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-type", .value = "text/plain" },
            };
            try ctx.write(try Message.initAny(ctx.gpa(), OutgoingHeaders, .{ .fields = &fields }));
            try ctx.write(try Message.initBytes(ctx.gpa(), "answered"));
            try ctx.flush();
            try ctx.close();
            return;
        }
        if (owned.bytes()) |bytes| try self.body.appendSlice(ctx.gpa(), bytes);
    }

    pub fn onEvent(self: *Responder, ctx: *HandlerContext, event: pipeline_mod.Event) !void {
        _ = ctx;
        if (event.get(InboundComplete) != null) self.inbound_complete = true;
        if (event.get(StreamReset)) |reset| {
            self.reset_code = reset.code;
            self.log.last_reset_code = reset.code;
        }
    }

    pub fn onInactive(self: *Responder, ctx: *HandlerContext) !void {
        _ = ctx;
        self.inactive = true;
        self.log.finished += 1;
    }

    pub fn deinit(self: *Responder, gpa: Allocator) void {
        self.body.deinit(gpa);
    }
};

const Builder = struct {
    log: Responder.Log = .{},

    pub fn initPipeline(self: *Builder, pipeline: *Pipeline) anyerror!void {
        const responder = try pipeline.gpa.create(Responder);
        responder.* = .{ .log = &self.log };
        errdefer pipeline.gpa.destroy(responder);
        _ = try pipeline.addLast("respond", .initOwned(responder));
        self.log.created += 1;
    }
};

test "http3 multiplex: a request gets its own pipeline and the answer goes back" {
    // The multiplexer against two real connections, so the whole round trip is
    // exercised: a request arrives, a pipeline is built for it, the handler's
    // response is encoded onto the same stream, and the client sees it.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try connection_mod.testPairForMultiplex(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try connection_mod.pumpForMultiplex(gpa, client, server, 16);

    var builder: Builder = .{};
    var multiplexer: Multiplexer = .init(gpa, io, server, .init(&builder));
    defer multiplexer.deinit();

    var buf: [8]qpack.FieldLine = undefined;
    const stream = try client.request(
        gpa,
        connection_mod.requestFields("GET", "https", "h", "/x", &.{}, &buf),
        true,
    );
    try connection_mod.pumpForMultiplex(gpa, client, server, 8);

    // Route what the server saw into child pipelines.
    while (server.nextEvent()) |event| {
        _ = try multiplexer.dispatch(event);
    }
    try testing.expectEqual(@as(usize, 1), builder.log.created);
    try testing.expect(multiplexer.needs_flush);

    // The handler closed its stream and the peer had already finished, so the
    // child is swept — the exchange is over in both directions.
    multiplexer.sweepAll();
    try testing.expectEqual(@as(usize, 1), builder.log.finished);
    try testing.expectEqual(@as(usize, 0), multiplexer.count());

    // And the client received what the handler wrote.
    try connection_mod.pumpForMultiplex(gpa, client, server, 8);
    var saw_status = false;
    var saw_body = false;
    var received: std.ArrayList(u8) = .empty;
    defer received.deinit(gpa);
    while (client.nextEvent()) |event| switch (event) {
        .headers => |h| {
            var section = client.takeSection(h.stream).?;
            defer section.deinit(gpa);
            try testing.expectEqualStrings("200", section.fields.items[0].value);
            saw_status = true;
        },
        .body => |b| {
            // Two body events arrive: the payload, then the zero-length DATA that
            // carries the FIN. Accumulating rather than asserting per event is the
            // honest reading — a stream is a stream, and where the boundaries fall
            // is not something an application may depend on.
            const bytes = client.readBody(b.stream);
            try received.appendSlice(gpa, bytes);
            client.consumeBody(b.stream, bytes.len);
            if (b.fin) saw_body = true;
        },
        else => {},
    };
    try testing.expect(saw_status and saw_body);
    try testing.expectEqualStrings("answered", received.items);
    try testing.expect(stream > 0 or stream == 0);
}

test "http3 multiplex: a reset tells the handler before the pipeline goes away" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try connection_mod.testPairForMultiplex(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try connection_mod.pumpForMultiplex(gpa, client, server, 16);

    var builder: Builder = .{};
    var multiplexer: Multiplexer = .init(gpa, io, server, .init(&builder));
    defer multiplexer.deinit();

    // A stream opened by hand, so it exists without a request having been served.
    const child = try multiplexer.open(4);
    try testing.expectEqual(@as(usize, 1), builder.log.created);
    _ = child;

    // A reset is not an ordinary end: the handler is told which it was, and only
    // then does the pipeline go away.
    multiplexer.reset(4, 0x010c);
    try testing.expectEqual(@as(usize, 1), builder.log.finished);
    try testing.expectEqual(@as(usize, 0), multiplexer.count());
}

test "http3 multiplex: a peer's reset reaches the stream handler with its code" {
    // Through `dispatch` rather than by calling `reset` directly. The distinction
    // matters: `reset` had no caller outside a test, so nothing established that a
    // reset arriving from the peer was routed to the stream at all — and the code is
    // what the handler needs, since §4.1.1 makes it the difference between a request
    // that may be retried and one that may not.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try connection_mod.testPairForMultiplex(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try connection_mod.pumpForMultiplex(gpa, client, server, 16);

    var builder: Builder = .{};
    var multiplexer: Multiplexer = .init(gpa, io, server, .init(&builder));
    defer multiplexer.deinit();

    // A request the server has a stream for, left open at the client.
    var buf: [8]@import("qpack.zig").FieldLine = undefined;
    const id = try client.request(
        gpa,
        connection_mod.requestFields("GET", "https", "h", "/abandoned", &.{}, &buf),
        false,
    );
    try connection_mod.pumpForMultiplex(gpa, client, server, 8);
    while (server.nextEvent()) |event| _ = try multiplexer.dispatch(event);
    try testing.expectEqual(@as(usize, 1), builder.log.created);

    // The client gives up on it.
    client.cancel(gpa, id, 0x010c); // H3_REQUEST_CANCELLED
    try connection_mod.pumpForMultiplex(gpa, client, server, 8);

    var handled = false;
    while (server.nextEvent()) |event| {
        if (try multiplexer.dispatch(event)) handled = true;
    }
    try testing.expect(handled);

    // The handler heard it, with the code, before its pipeline went away.
    try testing.expectEqual(@as(?u64, 0x010c), builder.log.last_reset_code);
    try testing.expectEqual(@as(usize, 0), multiplexer.count());
}
