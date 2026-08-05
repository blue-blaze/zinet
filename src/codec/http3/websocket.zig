//! RFC 9220: WebSocket over HTTP/3, which is the other half of extended CONNECT.
//!
//! The half already here is the transport rule: a CONNECT request carrying
//! `:protocol` opens a tunnel, and §4.4 of RFC 9114 restricts what may then be sent
//! on that stream. What was missing is the part that makes the tunnel useful —
//! putting the WebSocket protocol inside it — and that turns out to need almost no
//! new protocol code, because RFC 9220 delegates the semantics to RFC 8441, which in
//! turn says to run RFC 6455 "using the HTTP/2 stream from the CONNECT transaction as
//! if it were the TCP connection".
//!
//! So this module is a handshake check and a mount point. `websocket.FrameCodec` is
//! the same codec the HTTP/1.1 upgrade path uses; it was separated from
//! `websocket.Handshaker` for exactly this reuse, and this is what finally exercises
//! that separation.
//!
//! **Three things follow from the delegation and are easy to get wrong.** RFC 8441 §5
//! says the `Sec-WebSocket-Key` and `Sec-WebSocket-Accept` fields are *not* processed
//! — `:protocol` has superseded them, and computing an accept hash here would be
//! inventing a requirement. The `Connection` and `Upgrade` fields MUST NOT appear,
//! because they are HTTP/1.1 connection-level fields that HTTP/3 has no place for.
//! And masking is unchanged: RFC 8441 excludes only §10.8 of RFC 6455's security
//! considerations, so a client still masks and a server still refuses unmasked
//! frames, which is why `FrameCodec` takes a role.
//!
//! What is *not* here: HTTP Datagrams (RFC 9297) and therefore unreliable WebSocket
//! messages. That needs the QUIC DATAGRAM extension (RFC 9221) in the transport
//! underneath, which this repository does not implement; see HTTP3.md. RFC 9220
//! itself does not use datagrams — this binding is complete without them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const pipeline_mod = @import("../../pipeline.zig");
const Pipeline = pipeline_mod.Pipeline;
const Message = @import("../../message.zig").Message;
const websocket = @import("../websocket.zig");
const qpack = @import("qpack.zig");
const multiplex = @import("multiplex.zig");

pub const protocol_token = "websocket";

/// The version RFC 6455 defines, still carried in the CONNECT request because
/// RFC 8441 §5 keeps `Sec-WebSocket-Version` in use.
pub const version = "13";

pub const Options = struct {
    frame: websocket.FrameCodec.Options = .{},
    /// Subprotocols this server will accept, in order of preference. Empty means
    /// none is negotiated, and a client's `sec-websocket-protocol` is then answered
    /// with no such field — which RFC 6455 §4.2.2 makes the client's decision to
    /// accept or fail.
    subprotocols: []const []const u8 = &.{},
};

pub const Error = error{
    /// The request is not an extended CONNECT for the WebSocket protocol.
    NotWebSocket,
    /// RFC 8441 §4: `:scheme` and `:path` are required once `:protocol` is present,
    /// and `:authority` carries what RFC 6455 put in `Host`.
    MissingPseudoField,
    /// RFC 8441 §5: these are HTTP/1.1 connection-level fields and "MUST NOT be
    /// included in the CONNECT request defined here".
    ConnectionFieldPresent,
    /// A version this side does not speak.
    UnsupportedVersion,
};

/// Check a CONNECT request against RFC 8441 §5, as RFC 9220 requires.
///
/// Returns the negotiated subprotocol, if any. Separate from the handler so that a
/// server which routes requests itself can ask the question without mounting
/// anything — and so that the rules are testable without a connection.
pub fn checkRequest(headers: *const multiplex.Headers, options: Options) Error!?[]const u8 {
    const method = headers.get(":method") orelse return error.MissingPseudoField;
    if (!std.mem.eql(u8, method, "CONNECT")) return error.NotWebSocket;

    const protocol = headers.get(":protocol") orelse return error.NotWebSocket;
    if (!std.mem.eql(u8, protocol, protocol_token)) return error.NotWebSocket;

    // RFC 8441 §4: with `:protocol` present these stop being optional, because the
    // request is no longer "connect to this host" but "connect to this resource".
    _ = headers.get(":scheme") orelse return error.MissingPseudoField;
    _ = headers.get(":path") orelse return error.MissingPseudoField;
    _ = headers.get(":authority") orelse return error.MissingPseudoField;

    // RFC 8441 §5. Not merely unnecessary: RFC 9114 §4.2 already forbids them, so
    // their presence means the peer is speaking HTTP/1.1's handshake at us.
    if (headers.get("connection") != null) return error.ConnectionFieldPresent;
    if (headers.get("upgrade") != null) return error.ConnectionFieldPresent;

    if (headers.get("sec-websocket-version")) |v| {
        if (!std.mem.eql(u8, v, version)) return error.UnsupportedVersion;
    }

    if (headers.get("sec-websocket-protocol")) |offered| {
        // RFC 6455 §4.2.2: a comma-separated list, and the server picks one it
        // speaks. First match in *our* order, so preference is ours to state.
        for (options.subprotocols) |wanted| {
            var it = std.mem.tokenizeAny(u8, offered, ", ");
            while (it.next()) |candidate| {
                if (std.mem.eql(u8, candidate, wanted)) return wanted;
            }
        }
    }
    return null;
}

/// The field lines for a client's CONNECT request (RFC 8441 §5).
///
/// `buf` must hold at least six entries. Returned as a slice of the caller's buffer
/// because the field values are borrowed: the encoder serializes before `request`
/// returns, which is the same contract every outbound field section here has.
pub fn requestFields(
    authority: []const u8,
    path: []const u8,
    subprotocols: ?[]const u8,
    origin: ?[]const u8,
    buf: []qpack.FieldLine,
) []const qpack.FieldLine {
    assert(buf.len >= 6);
    var n: usize = 0;
    buf[n] = .{ .name = ":method", .value = "CONNECT" };
    n += 1;
    buf[n] = .{ .name = ":protocol", .value = protocol_token };
    n += 1;
    // RFC 8441 §5: "https" for wss-schemed WebSockets. HTTP/3 has no plaintext
    // form, so there is nothing for the "ws" scheme to map onto here.
    buf[n] = .{ .name = ":scheme", .value = "https" };
    n += 1;
    buf[n] = .{ .name = ":authority", .value = authority };
    n += 1;
    buf[n] = .{ .name = ":path", .value = path };
    n += 1;
    buf[n] = .{ .name = "sec-websocket-version", .value = version };
    n += 1;
    if (subprotocols) |value| {
        buf[n] = .{ .name = "sec-websocket-protocol", .value = value };
        n += 1;
    }
    if (origin) |value| {
        buf[n] = .{ .name = "origin", .value = value };
        n += 1;
    }
    return buf[0..n];
}

/// The server side of the handshake, as a stream handler.
///
/// Sits in front of `FrameCodec` rather than replacing it: the codec is mounted from
/// the start and this handler simply does not let a field section reach it. Adding
/// the codec on success would work too, and would mutate the pipeline from inside a
/// dispatch — legal here, but a shape worth not relying on when gating costs one
/// bool.
pub const Upgrader = struct {
    options: Options,
    /// Set once the 2xx response has gone out, which is the moment RFC 8441 §5 calls
    /// the WebSocket connection OPEN.
    open: bool = false,

    pub const handler_name = "http3-websocket-upgrade";

    pub fn onRead(self: *Upgrader, ctx: *pipeline_mod.HandlerContext, msg: Message) !void {
        var owned = msg;
        const headers = owned.get(multiplex.Headers) orelse {
            // Not a field section: tunnel bytes, which belong to the codec behind us
            // once the handshake is done. Before it, a peer sending data has not
            // waited for the response; dropping is the conservative reading of
            // "after successfully processing the opening handshake, the peers should
            // proceed with the WebSocket Protocol".
            if (!self.open) {
                owned.deinit(ctx.gpa());
                return;
            }
            return ctx.fireRead(owned);
        };
        defer owned.deinit(ctx.gpa());

        if (self.open) {
            // A second field section on a tunnel. RFC 9114 §4.4 makes frames other
            // than DATA a stream error on a connected stream, and the connection
            // layer already enforces it; reaching here would mean that check moved.
            return ctx.close();
        }

        const negotiated = checkRequest(headers, self.options) catch |err| {
            // RFC 9220 §3: an unknown `:protocol` "SHOULD" be answered with 501, and
            // a malformed extended CONNECT is an ordinary bad request. Answering at
            // all — rather than resetting — is what lets a client tell "this server
            // does not do WebSocket" from "the network ate my request".
            const status: []const u8 = switch (err) {
                error.NotWebSocket => "501",
                else => "400",
            };
            var fields: [1]qpack.FieldLine = .{.{ .name = ":status", .value = status }};
            try ctx.write(try Message.initAny(
                ctx.gpa(),
                multiplex.OutgoingHeaders,
                .{ .fields = &fields, .fin = true },
            ));
            return;
        };

        var fields: [2]qpack.FieldLine = undefined;
        var count: usize = 1;
        fields[0] = .{ .name = ":status", .value = "200" };
        if (negotiated) |chosen| {
            fields[1] = .{ .name = "sec-websocket-protocol", .value = chosen };
            count = 2;
        }
        try ctx.write(try Message.initAny(
            ctx.gpa(),
            multiplex.OutgoingHeaders,
            .{ .fields = fields[0..count], .fin = false },
        ));
        self.open = true;
        // The application's handlers are behind the codec, and RFC 8441 §5 puts the
        // connection in OPEN here — so an `onActive`-style signal is the pipeline's
        // existing "active" event rather than something invented for this module.
        ctx.fireActive();
    }
};

/// Mount the server side of RFC 9220 on a request stream's pipeline.
///
/// The application adds its own handlers after this call; they will see
/// `websocket.Frame` messages and write `websocket.OutboundFrame` ones, exactly as
/// they would behind the HTTP/1.1 upgrade path.
pub fn addServerBinding(pipeline: *Pipeline, options: Options) !void {
    const upgrader = try pipeline.gpa.create(Upgrader);
    errdefer pipeline.gpa.destroy(upgrader);
    upgrader.* = .{ .options = options };
    _ = try pipeline.addLast(Upgrader.handler_name, .initOwned(upgrader));

    const codec = try pipeline.gpa.create(websocket.FrameCodec);
    errdefer pipeline.gpa.destroy(codec);
    codec.* = .init(.server, options.frame);
    _ = try pipeline.addLast(websocket.FrameCodec.handler_name, .initOwned(codec));
}

const testing = std.testing;

test "http3 websocket: RFC 8441 §5's rules on the CONNECT request" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    const Case = struct {
        fields: []const qpack.FieldLine,
        expect: ?Error,
        subprotocol: ?[]const u8 = null,
    };
    const ok_fields = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/chat" },
    };
    const cases = [_]Case{
        .{ .fields = &ok_fields, .expect = null },
        // A plain CONNECT is a tunnel to a host, not a WebSocket.
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":authority", .value = "example.test:443" },
        }, .expect = error.NotWebSocket },
        // GET is what RFC 6455 used and RFC 8441 §5 replaced.
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.test" },
            .{ .name = ":path", .value = "/chat" },
        }, .expect = error.NotWebSocket },
        // §4: `:path` stops being optional once `:protocol` is there.
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.test" },
        }, .expect = error.MissingPseudoField },
        // §5: HTTP/1.1's connection-level fields must not be carried over.
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.test" },
            .{ .name = ":path", .value = "/chat" },
            .{ .name = "upgrade", .value = "websocket" },
        }, .expect = error.ConnectionFieldPresent },
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.test" },
            .{ .name = ":path", .value = "/chat" },
            .{ .name = "sec-websocket-version", .value = "8" },
        }, .expect = error.UnsupportedVersion },
        // A subprotocol we speak is chosen out of the offered list.
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "example.test" },
            .{ .name = ":path", .value = "/chat" },
            .{ .name = "sec-websocket-protocol", .value = "superchat, chat" },
        }, .expect = null, .subprotocol = "chat" },
    };

    for (cases) |case| {
        var headers: multiplex.Headers = .{
            .stream_id = 0,
            .fields = case.fields,
            .fin = false,
            .trailers = false,
            .arena = .init(gpa),
        };
        defer headers.deinit(gpa);

        const result = checkRequest(&headers, .{ .subprotocols = &.{ "chat", "kite" } });
        if (case.expect) |expected| {
            try testing.expectError(expected, result);
        } else {
            const chosen = try result;
            if (case.subprotocol) |want| {
                try testing.expectEqualStrings(want, chosen.?);
            } else {
                try testing.expect(chosen == null);
            }
        }
    }
}

test "http3 websocket: the CONNECT request carries what RFC 8441 §5 says and nothing else" {
    var buf: [8]qpack.FieldLine = undefined;
    const fields = requestFields("example.test", "/chat", "chat", "https://example.test", &buf);

    var seen_key = false;
    var seen_upgrade = false;
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, "sec-websocket-key")) seen_key = true;
        if (std.mem.eql(u8, field.name, "upgrade")) seen_upgrade = true;
        // §5 and RFC 9114 §4.2: field names are lowercase, pseudo-fields aside.
        for (field.name) |c| try testing.expect(!std.ascii.isUpper(c));
    }
    // §5: the key is not used, because `:protocol` superseded it. Sending one anyway
    // would invite a peer to compute an accept hash we would then have to check.
    try testing.expect(!seen_key);
    try testing.expect(!seen_upgrade);

    try testing.expectEqualStrings("CONNECT", fields[0].value);
    try testing.expectEqualStrings("websocket", fields[1].value);
    try testing.expectEqualStrings("https", fields[2].value);
    try testing.expectEqualStrings("13", fields[5].value);
    try testing.expectEqualStrings("sec-websocket-protocol", fields[6].name);
    try testing.expectEqualStrings("origin", fields[7].name);

    // Without the optional fields, the required six remain.
    const minimal = requestFields("example.test", "/", null, null, &buf);
    try testing.expectEqual(@as(usize, 6), minimal.len);
}

const connection_mod = @import("connection.zig");
const backend = @import("backend");
const embedded = @import("../../embedded.zig");

/// The application behind the binding: echoes every text frame back.
const EchoPeer = struct {
    frames: usize = 0,
    last: [64]u8 = undefined,
    last_len: usize = 0,

    pub const handler_name = "ws-echo";

    pub fn onRead(self: *EchoPeer, ctx: *pipeline_mod.HandlerContext, msg: Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const frame = owned.get(websocket.Frame) orelse return;
        const text = frame.text() orelse return;
        self.frames += 1;
        self.last_len = @min(text.len, self.last.len);
        @memcpy(self.last[0..self.last_len], text[0..self.last_len]);
        try ctx.write(try Message.initAny(
            ctx.gpa(),
            websocket.OutboundFrame,
            .{ .opcode = .text, .payload = self.last[0..self.last_len] },
        ));
    }
};

const TestBinder = struct {
    peer: *EchoPeer,

    pub fn initPipeline(self: *TestBinder, pipeline: *Pipeline) anyerror!void {
        try addServerBinding(pipeline, .{ .subprotocols = &.{"chat"} });
        _ = try pipeline.addLast(EchoPeer.handler_name, .init(self.peer));
    }
};

test "http3 websocket: a CONNECT tunnel carries real WebSocket frames both ways" {
    // RFC 9220 end to end over two real HTTP/3 connections: the extended CONNECT, the
    // 200 that opens the tunnel, and then RFC 6455 framing on the stream — masked
    // from the client, unmasked from the server, because RFC 8441 §5 keeps RFC 6455's
    // rules and excludes only its §10.8.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try connection_mod.testPairWith(gpa, .{ .connect_protocol = true });
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try connection_mod.pumpH3(gpa, client, server, 16);

    var peer: EchoPeer = .{};
    var binder: TestBinder = .{ .peer = &peer };
    var multiplexer: multiplex.Multiplexer = .init(gpa, io, server, .init(&binder));
    defer multiplexer.deinit();

    var buf: [8]qpack.FieldLine = undefined;
    const stream = try client.request(
        gpa,
        requestFields("example.test", "/chat", "chat", null, &buf),
        false, // the tunnel stays open: a FIN here would close it before it opened
    );
    try connection_mod.pumpH3(gpa, client, server, 8);
    while (server.nextEvent()) |event| _ = try multiplexer.dispatch(event);
    try connection_mod.pumpH3(gpa, client, server, 8);

    // The client sees 200 and the subprotocol it asked for.
    var negotiated: ?[]const u8 = null;
    var status: ?[]const u8 = null;
    var section_store: ?qpack.FieldSection = null;
    defer if (section_store) |*s| s.deinit(gpa);
    while (client.nextEvent()) |event| switch (event) {
        .headers => |h| {
            const section = client.takeSection(h.stream) orelse continue;
            for (section.fields.items) |field| {
                if (std.mem.eql(u8, field.name, ":status")) status = field.value;
                if (std.mem.eql(u8, field.name, "sec-websocket-protocol")) {
                    negotiated = field.value;
                }
            }
            section_store = section;
        },
        else => {},
    };
    try testing.expectEqualStrings("200", status.?);
    try testing.expectEqualStrings("chat", negotiated.?);

    // Now the stream *is* the TCP connection of RFC 6455, so the client's side of the
    // tunnel is an ordinary client-role `FrameCodec`. Driven through an
    // `EmbeddedChannel` rather than hand-built bytes: the point is that the same codec
    // the HTTP/1.1 path uses produces and accepts these frames, and a hand-rolled
    // frame in the test would prove only that the test can build one.
    var peer_channel: embedded.EmbeddedChannel = undefined;
    try peer_channel.init(gpa, io, .initFunction(mountClientCodec));
    defer peer_channel.deinit();

    try peer_channel.writeOutbound(try Message.initAny(
        gpa,
        websocket.OutboundFrame,
        .{ .opcode = .text, .payload = "over h3" },
    ));
    var wire = peer_channel.readOutbound() orelse return error.NoFrameEncoded;
    defer wire.deinit(gpa);
    const wire_bytes = wire.bytes() orelse return error.NotBytes;
    // RFC 6455 §5.1: a client masks. The tunnel changes none of that.
    try testing.expect(wire_bytes[1] & 0x80 != 0);

    try client.writeBody(gpa, stream, wire_bytes, false);
    try connection_mod.pumpH3(gpa, client, server, 8);
    while (server.nextEvent()) |event| _ = try multiplexer.dispatch(event);

    try testing.expectEqual(@as(usize, 1), peer.frames);
    try testing.expectEqualStrings("over h3", peer.last[0..peer.last_len]);

    // And the echo comes back through the tunnel, unmasked, as a server's frame.
    try connection_mod.pumpH3(gpa, client, server, 8);
    var inbound: std.ArrayList(u8) = .empty;
    defer inbound.deinit(gpa);
    while (client.nextEvent()) |event| switch (event) {
        .body => |b| {
            const bytes = client.readBody(b.stream);
            try inbound.appendSlice(gpa, bytes);
            client.consumeBody(b.stream, bytes.len);
        },
        else => {},
    };
    try testing.expect(inbound.items.len > 0);
    // Decoded by the client-role codec, which is also the check that the server did
    // not mask: RFC 6455 §5.1 makes a masked server frame a protocol error, so a
    // codec in the client role fails the connection rather than accepting it.
    peer_channel.writeInbound(try Message.initBytes(gpa, inbound.items));
    var echoed = peer_channel.readInbound() orelse return error.NoFrameDecoded;
    defer echoed.deinit(gpa);
    const frame = echoed.get(websocket.Frame) orelse return error.NotAFrame;
    try testing.expectEqualStrings("over h3", frame.text().?);
}

fn mountClientCodec(pipeline: *Pipeline) anyerror!void {
    const codec = try pipeline.gpa.create(websocket.FrameCodec);
    errdefer pipeline.gpa.destroy(codec);
    codec.* = .init(.client, .{});
    _ = try pipeline.addLast(websocket.FrameCodec.handler_name, .initOwned(codec));
}

test "http3 websocket: bytes that arrive before the handshake do not reach the codec" {
    // A peer that sends WebSocket data without waiting for the 200. RFC 8441 §5 puts
    // the connection in OPEN only "after successfully processing the opening
    // handshake", so those bytes have no meaning yet — and letting them through would
    // let a peer drive the frame state machine on a stream we are about to answer 501.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    // The wire bytes of a legitimate masked client frame, from the real encoder.
    var producer: embedded.EmbeddedChannel = undefined;
    try producer.init(gpa, io, .initFunction(mountClientCodec));
    defer producer.deinit();
    try producer.writeOutbound(try Message.initAny(
        gpa,
        websocket.OutboundFrame,
        .{ .opcode = .text, .payload = "early" },
    ));
    var wire = producer.readOutbound() orelse return error.NoFrameEncoded;
    defer wire.deinit(gpa);
    const frame_bytes = wire.bytes() orelse return error.NotBytes;

    var peer: EchoPeer = .{};
    var binder: TestBinder = .{ .peer = &peer };
    var channel: embedded.EmbeddedChannel = undefined;
    try channel.init(gpa, io, .init(&binder));
    defer channel.deinit();

    // Before any field section: dropped, and nothing is written back.
    channel.writeInbound(try Message.initBytes(gpa, frame_bytes));
    try testing.expectEqual(@as(usize, 0), peer.frames);
    try testing.expect(channel.readOutbound() == null);

    // The handshake, then the same bytes: now they are a frame.
    var fields = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/chat" },
    };
    channel.writeInbound(try Message.initAny(gpa, multiplex.Headers, .{
        .stream_id = 0,
        .fields = &fields,
        .fin = false,
        .trailers = false,
        .arena = .init(gpa),
    }));
    var response = channel.readOutbound() orelse return error.NoResponse;
    defer response.deinit(gpa);
    const out_headers = response.get(multiplex.OutgoingHeaders) orelse return error.NotHeaders;
    // Only `fin` is read, deliberately. An outbound field section *borrows* its
    // fields — the encoder serializes before `write` returns — and `EmbeddedChannel`
    // keeps the message instead of serializing it, so by the time it is read back here
    // the slice points at a stack frame that has gone. The status is checked in the
    // end-to-end test above, where a real encoder consumed it in time.
    try testing.expect(!out_headers.fin);

    channel.writeInbound(try Message.initBytes(gpa, frame_bytes));
    try testing.expectEqual(@as(usize, 1), peer.frames);
    try testing.expectEqualStrings("early", peer.last[0..peer.last_len]);
}
