//! The pipeline entry points: `addServerCodec` and `addClientCodec`.
//!
//! One handler, sitting closest to the socket in the parent channel's pipeline. It
//! owns the connection and the multiplexer, turns inbound bytes into events on child
//! pipelines, and writes whatever the protocol owes the peer back out.
//!
//! ## This is cleartext HTTP/2 with prior knowledge, and that is not a limitation of
//! ## the code
//!
//! RFC 9113 §3 lists three ways to arrive at HTTP/2. The `Upgrade:` dance was removed
//! from the specification in §3.2. `h2` over TLS is identified by ALPN (§3.1), and
//! `std.crypto.tls.Client` has no way to send it — see the table in README under
//! "Blocked upstream". What is left is prior knowledge, which is what `Server.listen`
//! plus `addServerCodec` gives you: exactly the configuration gRPC between services
//! and a reverse proxy talking to a backend use.
//!
//! Nothing about the protocol implementation is conditional on that. When ALPN
//! appears, `h2` needs the negotiated protocol name checked and nothing else.
//!
//! ## Where the parent pipeline ends and a stream's begins
//!
//! The parent pipeline carries bytes and connection-level events: `SettingsUpdated`,
//! `Pong`, `GoawayReceived`. A stream's pipeline carries that stream's headers and
//! body. An application that wants per-request handlers puts them in the stream
//! initializer and needs nothing in the parent pipeline at all.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Buffer = @import("../../buffer.zig").Buffer;
const channel_mod = @import("../../channel.zig");
const connection_mod = @import("connection.zig");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const multiplex = @import("multiplex.zig");
const pipeline_mod = @import("../../pipeline.zig");
const semantics = @import("semantics.zig");

const Connection = connection_mod.Connection;
const Error = pipeline_mod.Error;
const HandlerContext = pipeline_mod.HandlerContext;
const Initializer = channel_mod.Initializer;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Fired up the parent pipeline when the peer's settings changed. Worth seeing
/// because it can change how much a stream may send.
pub const SettingsUpdated = struct {
    initial_window_size: u31,
    max_concurrent_streams: ?u32,
    max_frame_size: u24,
};

/// A `PING` this endpoint sent has come back.
pub const Pong = struct { data: [8]u8 };

/// The peer is going away. Streams at or below `last_stream_id` may still finish;
/// anything above it was never processed and may be retried on a new connection.
pub const GoawayReceived = struct {
    last_stream_id: u31,
    code: frame.ErrorCode,
};

pub const Options = struct {
    connection: connection_mod.Options = .{},
    /// Builds each stream's pipeline. The application's only required hook.
    streams: Initializer,
    /// Whether to hold inbound messages to RFC 9113 §8 before delivering them.
    ///
    /// On by default and not really optional: a gateway that forwards a message
    /// carrying `Transfer-Encoding` into HTTP/1.1 is a request smuggling vector.
    /// The switch exists so a test can feed deliberate nonsense at the layers below.
    validate_semantics: bool = true,
};

pub const Codec = struct {
    connection: Connection,
    multiplexer: multiplex.Multiplexer,
    options: Options,
    /// Bytes read but not yet a whole frame.
    input: Buffer = .empty,
    /// Latched once the connection has failed, so later reads are dropped rather
    /// than reparsed — the same discipline the HTTP/1 decoder's `bad_message` state
    /// applies, for the same reason.
    failed: bool = false,

    pub const handler_name = "http2";

    /// Installs the codec. `role` decides who sends the connection preface and which
    /// stream identifiers belong to whom.
    pub fn addTo(
        pipeline: *Pipeline,
        role: connection_mod.Role,
        options: Options,
    ) !*Codec {
        const codec = try pipeline.gpa.create(Codec);
        errdefer pipeline.gpa.destroy(codec);

        codec.* = .{
            .connection = .init(pipeline.gpa, role, options.connection),
            .multiplexer = undefined,
            .options = options,
        };
        // The multiplexer holds the connection's address, so it can only be built
        // once the codec's own address is settled.
        codec.multiplexer = .init(
            pipeline.gpa,
            pipeline.io,
            &codec.connection,
            options.streams,
        );
        codec.multiplexer.owner = pipeline.owner;

        _ = try pipeline.addLast(handler_name, .initOwned(codec));
        return codec;
    }

    pub fn deinit(codec: *Codec, gpa: Allocator) void {
        codec.multiplexer.deinit();
        codec.connection.deinit(gpa);
        codec.input.deinit(gpa);
    }

    pub fn onActive(codec: *Codec, ctx: *HandlerContext) Error!void {
        try codec.connection.start(ctx.gpa());
        try codec.drain(ctx);
        ctx.fireActive();
    }

    pub fn onRead(codec: *Codec, ctx: *HandlerContext, msg: Message) Error!void {
        const gpa = ctx.gpa();
        var owned = msg;
        defer owned.deinit(gpa);

        const bytes = owned.bytes() orelse {
            // Not bytes, so it belongs to something else in the pipeline.
            ctx.fireRead(owned.move());
            return;
        };
        // Once the connection has failed there is nothing useful to do with more
        // bytes, and reparsing them would let one bad frame become an error storm.
        if (codec.failed) return;

        try codec.input.writeBytes(gpa, bytes);
        // `poll` refuses a frame larger than the negotiated maximum before waiting
        // for it, so the accumulation cannot exceed one frame plus its header.
        const ceiling: usize = frame.header_len + codec.connection.local_settings.max_frame_size;
        if (codec.input.readableLen() > ceiling) {
            codec.failed = true;
            return error.Http2InputOverflow;
        }

        codec.pump(ctx) catch |err| {
            codec.failed = true;
            // GOAWAY is already queued and the peer needs it before the connection
            // goes: §6.8's error code is the only explanation it will ever get.
            codec.drain(ctx) catch {};
            return err;
        };
        try codec.drain(ctx);
    }

    pub fn onInactive(codec: *Codec, ctx: *HandlerContext) Error!void {
        // Every child pipeline hears `onInactive` before the connection's own
        // handlers do, since a stream cannot outlive the connection carrying it.
        var iterator = codec.multiplexer.children.valueIterator();
        while (iterator.next()) |child| child.*.pipeline.fireInactive();
        ctx.fireInactive();
    }

    /// Reads every frame the input holds, routing events where they belong.
    fn pump(codec: *Codec, ctx: *HandlerContext) !void {
        const gpa = ctx.gpa();
        const now = nowNs(ctx.io());

        while (try codec.connection.poll(gpa, &codec.input, now)) |event| {
            if (event == .headers and codec.options.validate_semantics) {
                codec.wellFormed(event.headers) catch {
                    // §8.1.1: a malformed message is a *stream* error. The
                    // connection is fine, and so is every other stream on it.
                    try codec.connection.sendReset(
                        gpa,
                        event.headers.stream_id,
                        .protocol_error,
                    );
                    continue;
                };
            }

            if (try codec.multiplexer.dispatch(event)) continue;
            codec.fireConnectionEvent(ctx, event);
        }

        if (codec.multiplexer.needs_flush) {
            codec.multiplexer.needs_flush = false;
            var transitions: [32]Connection.Writability = undefined;
            const changed = try codec.connection.flush(gpa, &transitions);
            codec.multiplexer.applyWritability(changed);
        }
    }

    fn wellFormed(codec: *const Codec, headers: connection_mod.Inbound.Headers) semantics.Error!void {
        if (headers.trailers) return semantics.validateTrailers(headers.fields);
        switch (codec.connection.role) {
            .server => _ = try semantics.validateRequest(headers.fields),
            .client => _ = try semantics.validateResponse(headers.fields),
        }
    }

    fn fireConnectionEvent(
        codec: *Codec,
        ctx: *HandlerContext,
        event: connection_mod.Inbound,
    ) void {
        switch (event) {
            .settings_updated => {
                var updated: SettingsUpdated = .{
                    .initial_window_size = codec.connection.remote_settings.initial_window_size,
                    .max_concurrent_streams = codec.connection.remote_settings.max_concurrent_streams,
                    .max_frame_size = codec.connection.remote_settings.max_frame_size,
                };
                ctx.fireEvent(.init(&updated));
            },
            .pong => |data| {
                var pong: Pong = .{ .data = data };
                ctx.fireEvent(.init(&pong));
            },
            .goaway => |bye| {
                var received: GoawayReceived = .{
                    .last_stream_id = bye.last_stream_id,
                    .code = bye.code,
                };
                ctx.fireEvent(.init(&received));
            },
            else => unreachable,
        }
    }

    /// Puts whatever the connection has queued on the wire.
    fn drain(codec: *Codec, ctx: *HandlerContext) Error!void {
        if (codec.connection.out.readableLen() == 0) return;
        const message = try Message.initBytes(ctx.gpa(), codec.connection.out.readableSlice());
        codec.connection.out.clear();
        try ctx.write(message);
        try ctx.flush();
    }

    // -- The application's handles ----------------------------------------

    /// Opens the next stream from this side and returns its channel, for a client
    /// sending a request or a server pushing.
    ///
    /// Must be called from the connection's reader task, like anything else that
    /// touches a pipeline.
    pub fn openStream(codec: *Codec) !*multiplex.StreamChannel {
        return codec.multiplexer.open(codec.connection.nextStreamId());
    }

    /// The stream channel for `stream_id`, if it is still open.
    pub fn stream(codec: *Codec, stream_id: u31) ?*multiplex.StreamChannel {
        return codec.multiplexer.get(stream_id);
    }

    /// Sends `PING`. The reply arrives as a `Pong` event on the parent pipeline.
    pub fn ping(codec: *Codec, ctx: *HandlerContext, data: [8]u8) Error!void {
        try codec.connection.sendPing(ctx.gpa(), data);
        try codec.drain(ctx);
    }

    /// Begins a graceful shutdown (§6.8). Open streams may still finish, so this
    /// does not close the channel.
    pub fn goAway(
        codec: *Codec,
        ctx: *HandlerContext,
        code: frame.ErrorCode,
        debug: []const u8,
    ) Error!void {
        try codec.connection.sendGoaway(ctx.gpa(), code, debug);
        try codec.drain(ctx);
    }
};

/// The clock, read once per read cycle and injected downwards, so the rate limits
/// are the only thing that needs it and nothing reaches for a global.
fn nowNs(io: Io) u64 {
    const timestamp = Io.Timestamp.now(io, .awake);
    const nanoseconds = @max(0, timestamp.nanoseconds);
    return std.math.cast(u64, nanoseconds) orelse std.math.maxInt(u64);
}

/// Installs a server-side HTTP/2 codec: cleartext, prior knowledge.
pub fn addServerCodec(pipeline: *Pipeline, options: Options) !*Codec {
    return Codec.addTo(pipeline, .server, options);
}

/// Installs a client-side HTTP/2 codec: cleartext, prior knowledge.
pub fn addClientCodec(pipeline: *Pipeline, options: Options) !*Codec {
    return Codec.addTo(pipeline, .client, options);
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

const test_support = @import("../test_support.zig");

test "codec: every declaration compiles" {
    testing.refAllDecls(Codec);
}

/// A stream handler that answers every request, so a test can watch a whole
/// exchange leave through the parent pipeline's sink.
const Responder = struct {
    gpa: Allocator,
    seen: std.ArrayList([]u8) = .empty,
    resets: usize = 0,

    const response = [_]hpack.Field{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };

    fn deinit(responder: *Responder) void {
        for (responder.seen.items) |item| responder.gpa.free(item);
        responder.seen.deinit(responder.gpa);
    }

    pub fn onRead(responder: *Responder, ctx: *HandlerContext, msg: Message) !void {
        const gpa = ctx.gpa();
        var owned = msg;
        defer owned.deinit(gpa);

        if (owned.take(gpa, multiplex.Headers)) |taken| {
            var headers = taken;
            defer headers.deinit(gpa);
            const path = headers.get(":path") orelse ":none";
            try responder.seen.append(responder.gpa, try responder.gpa.dupe(u8, path));

            try ctx.write(try Message.initAny(gpa, multiplex.OutgoingHeaders, .{
                .fields = &response,
            }));
            try ctx.write(try Message.initBytes(gpa, "pong"));
            try ctx.flush();
            try ctx.close();
            return;
        }
    }

    pub fn onEvent(responder: *Responder, ctx: *HandlerContext, event: pipeline_mod.Event) !void {
        if (event.is(multiplex.StreamReset)) responder.resets += 1;
        ctx.fireEvent(event);
    }
};

/// Builds one responder per stream and keeps the pointers, so a test can read the
/// state after a stream's pipeline has been torn down.
const Responders = struct {
    gpa: Allocator,
    made: std.ArrayList(*Responder) = .empty,

    fn deinit(responders: *Responders) void {
        for (responders.made.items) |responder| {
            responder.deinit();
            responders.gpa.destroy(responder);
        }
        responders.made.deinit(responders.gpa);
    }

    pub fn initPipeline(responders: *Responders, pipeline: *Pipeline) anyerror!void {
        const responder = try responders.gpa.create(Responder);
        responder.* = .{ .gpa = responders.gpa };
        errdefer responders.gpa.destroy(responder);
        try responders.made.append(responders.gpa, responder);
        _ = try pipeline.addLast("responder", .init(responder));
    }
};

/// The bytes a real client would send for `requests`, produced by the client half of
/// this same implementation rather than hand-assembled.
fn clientBytes(
    gpa: Allocator,
    requests: []const []const hpack.Field,
    end_stream: bool,
) !Buffer {
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit(gpa);
    try client.start(gpa);

    var id: u31 = 1;
    for (requests) |fields| {
        try client.sendHeaders(gpa, id, fields, end_stream);
        id += 2;
    }

    var out: Buffer = .empty;
    errdefer out.deinit(gpa);
    try out.writeBytes(gpa, client.out.readableSlice());
    return out;
}

/// Walks frames out of a byte stream, so a test can assert on what went to the wire.
fn countFrames(bytes: []const u8, kind: frame.FrameType) usize {
    var offset: usize = 0;
    var total: usize = 0;
    while (offset + frame.header_len <= bytes.len) {
        const header: frame.Header = .parse(bytes[offset..][0..frame.header_len]);
        offset += frame.header_len + header.length;
        if (offset > bytes.len) break;
        if (header.frame_type == kind) total += 1;
    }
    return total;
}

fn firstFrame(bytes: []const u8, kind: frame.FrameType) ?[]const u8 {
    var offset: usize = 0;
    while (offset + frame.header_len <= bytes.len) {
        const header: frame.Header = .parse(bytes[offset..][0..frame.header_len]);
        const payload_start = offset + frame.header_len;
        offset = payload_start + header.length;
        if (offset > bytes.len) break;
        if (header.frame_type == kind) return bytes[payload_start..offset];
    }
    return null;
}

test "codec: a server announces its settings as soon as the channel is active" {
    const gpa = testing.allocator;
    var responders: Responders = .{ .gpa = gpa };
    defer responders.deinit();

    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try addServerCodec(fixture.pipeline, .{ .streams = .init(&responders) });
    fixture.pipeline.fireActive();

    // A server sends no magic of its own, so the very first bytes are SETTINGS.
    const written = fixture.written();
    try testing.expect(written.len > frame.header_len);
    const header: frame.Header = .parse(written[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.settings, header.frame_type);
}

test "codec: a client sends the connection preface first" {
    const gpa = testing.allocator;
    var responders: Responders = .{ .gpa = gpa };
    defer responders.deinit();

    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try addClientCodec(fixture.pipeline, .{ .streams = .init(&responders) });
    fixture.pipeline.fireActive();

    try testing.expect(std.mem.startsWith(u8, fixture.written(), frame.client_preface));
}

test "codec: a request arrives at a stream handler and its response reaches the wire" {
    const gpa = testing.allocator;
    var responders: Responders = .{ .gpa = gpa };
    defer responders.deinit();

    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try addServerCodec(fixture.pipeline, .{ .streams = .init(&responders) });
    fixture.pipeline.fireActive();
    fixture.clearWritten();

    var bytes = try clientBytes(gpa, &.{
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/one" },
        },
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/two" },
        },
    }, true);
    defer bytes.deinit(gpa);
    fixture.pipeline.fireRead(try Message.initBytes(gpa, bytes.readableSlice()));

    // Two streams, two handlers, each with its own request.
    try testing.expectEqual(@as(usize, 2), responders.made.items.len);
    try testing.expectEqualStrings("/one", responders.made.items[0].seen.items[0]);
    try testing.expectEqualStrings("/two", responders.made.items[1].seen.items[0]);

    // And two responses on the wire, each with a body.
    const written = fixture.written();
    try testing.expectEqual(@as(usize, 2), countFrames(written, .headers));
    try testing.expect(countFrames(written, .data) >= 2);
    // The SETTINGS acknowledgement went out too, because the client's settings
    // arrived in the same read.
    try testing.expect(countFrames(written, .settings) >= 1);
}

test "codec: §8 is enforced at the boundary, as a stream error" {
    const gpa = testing.allocator;
    var responders: Responders = .{ .gpa = gpa };
    defer responders.deinit();

    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try addServerCodec(fixture.pipeline, .{ .streams = .init(&responders) });
    fixture.pipeline.fireActive();
    fixture.clearWritten();

    // An uppercase field name, which §8.2.1 makes malformed. The stream is reset and
    // the request never reaches a handler — but the connection carries on, which is
    // what §8.1.1 asks for.
    var bytes = try clientBytes(gpa, &.{&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = "Content-Length", .value = "0" },
    }}, true);
    defer bytes.deinit(gpa);
    fixture.pipeline.fireRead(try Message.initBytes(gpa, bytes.readableSlice()));

    const written = fixture.written();
    try testing.expectEqual(@as(usize, 1), countFrames(written, .rst_stream));
    try testing.expectEqual(@as(usize, 0), countFrames(written, .goaway));
    try testing.expectEqual(@as(usize, 0), responders.made.items.len);

    const payload = firstFrame(written, .rst_stream).?;
    try testing.expectEqual(frame.ErrorCode.protocol_error, frame.parseRstStream(payload[0..4]));
}

test "codec: a peer that is not speaking HTTP/2 is answered with GOAWAY" {
    const gpa = testing.allocator;
    var responders: Responders = .{ .gpa = gpa };
    defer responders.deinit();

    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try addServerCodec(fixture.pipeline, .{ .streams = .init(&responders) });
    const collector = try fixture.addCollector();
    fixture.pipeline.fireActive();
    fixture.clearWritten();

    // At least as long as the preface, or the codec is still waiting for bytes
    // rather than judging what it has — which is itself the right behaviour.
    const request = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    try testing.expect(request.len > frame.client_preface.len);
    fixture.pipeline.fireRead(try Message.initBytes(gpa, request));

    // GOAWAY went out before the error was reported, because it is the only
    // explanation the peer will ever get.
    try testing.expectEqual(@as(usize, 1), countFrames(fixture.written(), .goaway));
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
    try testing.expectEqual(@as(anyerror, error.ConnectionError), collector.errors.items[0]);

    // Latched: more bytes are dropped rather than reparsed into a second GOAWAY.
    fixture.clearWritten();
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "more nonsense"));
    try testing.expectEqual(@as(usize, 0), fixture.written().len);
    try testing.expectEqual(@as(usize, 1), collector.errors.items.len);
}

test "codec: bytes arriving one at a time produce the same exchange" {
    const gpa = testing.allocator;
    var responders: Responders = .{ .gpa = gpa };
    defer responders.deinit();

    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try addServerCodec(fixture.pipeline, .{ .streams = .init(&responders) });
    fixture.pipeline.fireActive();
    fixture.clearWritten();

    var bytes = try clientBytes(gpa, &.{&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/drip" },
    }}, true);
    defer bytes.deinit(gpa);

    // The socket is under no obligation to respect a frame boundary, let alone the
    // connection preface.
    for (bytes.readableSlice()) |byte| {
        fixture.pipeline.fireRead(try Message.initBytes(gpa, &[_]u8{byte}));
    }

    try testing.expectEqual(@as(usize, 1), responders.made.items.len);
    try testing.expectEqualStrings("/drip", responders.made.items[0].seen.items[0]);
    try testing.expectEqual(@as(usize, 1), countFrames(fixture.written(), .headers));
}
