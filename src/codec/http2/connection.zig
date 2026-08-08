//! The connection: the piece that drives every layer below it.
//!
//! Bytes go in through `poll`, which yields application events and accumulates any
//! protocol response — a `SETTINGS` acknowledgement, a `PING` reply, a
//! `WINDOW_UPDATE`, a `GOAWAY` — into `out` for the caller to flush. That seam is
//! what makes the whole protocol testable without a socket: a test feeds frames and
//! reads back the bytes that would have gone on the wire.
//!
//! ## What decides severity, and who acts on it
//!
//! §5.4 splits failures into connection errors, which end everything, and stream
//! errors, which reset one stream. The lower layers report; this one decides and
//! acts:
//!
//! * A **stream error** is handled here and never surfaces. `RST_STREAM` goes into
//!   `out`, the stream is dropped, and `poll` carries on with the next frame — the
//!   connection is unharmed and the peer's other streams never noticed.
//! * A **connection error** writes `GOAWAY` into `out` and returns
//!   `error.ConnectionError`. The caller must flush *before* closing, or the peer
//!   learns nothing about why.
//!
//! ## Why the frame floods each need a limit
//!
//! `SETTINGS` and `PING` oblige us to write a reply, so a peer that sends them in
//! a loop makes us do unbounded work for nothing; §6.5 and §6.7 require the reply
//! and say nothing about a rate. `WINDOW_UPDATE`, `PRIORITY` and empty `DATA`
//! frames oblige no reply but advance no exchange either, so they are free to send
//! and not free to receive. Both categories get a rate limit, because what they
//! consume is work rather than a resource — see `limits.RateLimiter`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../../buffer.zig").Buffer;
const flow = @import("flow.zig");
const frame = @import("frame.zig");
const headers_mod = @import("headers.zig");
const hpack = @import("hpack.zig");
const limits = @import("limits.zig");
const semantics = @import("semantics.zig");
const stream_mod = @import("stream.zig");

pub const Error = error{
    /// A connection error was detected. `GOAWAY` is already in `out`; flush it,
    /// then close. §5.4.1.
    ConnectionError,
} || Allocator.Error || Buffer.Error;

pub const Role = enum { server, client };

pub const Options = struct {
    /// What this endpoint announces in its initial `SETTINGS`.
    header_table_size: u32 = frame.default_header_table_size,
    max_concurrent_streams: u32 = 128,
    /// The per-stream receive window this endpoint wants.
    initial_window_size: u31 = frame.default_initial_window_size,
    max_frame_size: u24 = frame.default_max_frame_size,
    /// §6.5.2. A server that does not want pushes says so, and then a
    /// `PUSH_PROMISE` from the peer is a connection error.
    enable_push: bool = false,

    /// The connection-level receive window this endpoint wants. §6.9.2 is explicit
    /// that `SETTINGS_INITIAL_WINDOW_SIZE` does *not* apply to the connection
    /// window — it starts at 65535 for everyone and moves only by `WINDOW_UPDATE`
    /// — so wanting a larger one means sending one at startup.
    connection_window: u31 = 1024 * 1024,

    hpack: hpack.Limits = .{},
    headers: headers_mod.Options = .{},
    sends: flow.SendQueue.Limits = .{},

    /// `SETTINGS` and `PING`, which each oblige a reply.
    control_frames: limits.RateLimiter = .{ .max_per_window = 100, .window_ns = 10 * std.time.ns_per_s },
    /// `WINDOW_UPDATE`, `PRIORITY` and empty `DATA`: no reply owed, no progress
    /// made. A higher ceiling because legitimate traffic produces many of them.
    idle_frames: limits.RateLimiter = .{ .max_per_window = 10_000, .window_ns = 10 * std.time.ns_per_s },
    resets: stream_mod.ResetLimiter = .{},
};

/// What the application is told. Every slice is borrowed and valid only until the
/// next call to `poll`, which is the same contract the header assembler has and is
/// sufficient because a connection is driven from one task.
pub const Inbound = union(enum) {
    /// A request at a server, a response at a client, or trailers on either.
    headers: Headers,
    data: Data,
    /// The peer reset a stream. It has already been dropped.
    reset: Reset,
    /// The peer is going away. No new streams; those below `last_stream_id` may
    /// still complete.
    goaway: Goaway,
    /// The peer's settings changed. Reported because it can change writability.
    settings_updated,
    /// A `PING` we sent came back, so a round trip completed.
    pong: [8]u8,
    /// A push the peer promised, at a client that allows them.
    push_promise: PushPromise,

    pub const Headers = struct {
        stream_id: u31,
        fields: []const hpack.Field,
        end_stream: bool,
        /// A second header block on a stream is trailers (§8.1).
        trailers: bool,
        priority: ?frame.Priority,
    };

    pub const Data = struct {
        stream_id: u31,
        /// Padding already removed, so this is shorter than what flow control was
        /// charged for.
        bytes: []const u8,
        end_stream: bool,
    };

    pub const Reset = struct {
        stream_id: u31,
        code: frame.ErrorCode,
    };

    pub const Goaway = struct {
        last_stream_id: u31,
        code: frame.ErrorCode,
        debug_data: []const u8,
    };

    pub const PushPromise = struct {
        stream_id: u31,
        promised_stream_id: u31,
        fields: []const hpack.Field,
    };
};

pub const Connection = struct {
    role: Role,
    options: Options,

    /// What this endpoint announced, and what the peer did.
    local_settings: frame.Settings,
    remote_settings: frame.Settings = .{},

    registry: stream_mod.Registry,
    assembler: headers_mod.Assembler,
    decoder: hpack.Decoder,
    encoder: hpack.Encoder,
    scheduler: flow.Scheduler = .{},

    /// The connection-level windows (§6.9.1). Separate from every stream's, and
    /// changed only by `WINDOW_UPDATE`.
    recv_window: flow.Window = .init(frame.default_initial_window_size),
    send_window: flow.Window = .init(frame.default_initial_window_size),

    /// Bytes to put on the wire. The caller flushes and clears.
    out: Buffer = .empty,

    /// Scratch for one decoded header block. Reset per block, so a decoded field's
    /// strings live exactly as long as the event that carries them.
    arena: std.heap.ArenaAllocator,
    fields: std.ArrayList(hpack.Field) = .empty,

    state: State = .start,
    /// §3.4: the first frame from the peer must be `SETTINGS`.
    peer_settings_received: bool = false,
    /// How many of our `SETTINGS` are unacknowledged.
    settings_outstanding: u32 = 0,
    goaway_sent: bool = false,
    /// The highest peer-initiated stream this endpoint has acted on, which is what
    /// `GOAWAY` has to report so the peer knows what to retry (§6.8).
    last_remote_processed: u31 = 0,

    control_frames: limits.RateLimiter,
    idle_frames: limits.RateLimiter,

    pub const State = enum {
        /// Nothing sent or received yet.
        start,
        /// A server that has not yet seen the 24-byte preface.
        awaiting_preface,
        open,
        /// `GOAWAY` has been sent or received; existing streams may finish.
        closing,
        closed,
    };

    pub fn init(gpa: Allocator, role: Role, options: Options) Connection {
        return .{
            .role = role,
            .options = options,
            .local_settings = .{
                .header_table_size = options.header_table_size,
                .enable_push = options.enable_push,
                .max_concurrent_streams = options.max_concurrent_streams,
                .initial_window_size = options.initial_window_size,
                .max_frame_size = options.max_frame_size,
                .max_header_list_size = options.hpack.max_header_list_size,
            },
            .registry = brk: {
                var registry: stream_mod.Registry = .init(role == .server, .{
                    .max_concurrent_streams = options.max_concurrent_streams,
                    .resets = options.resets,
                    .sends = options.sends,
                });
                registry.initial_recv_window = options.initial_window_size;
                break :brk registry;
            },
            .assembler = .{ .options = options.headers },
            .decoder = .init(options.header_table_size),
            .encoder = .init(frame.default_header_table_size),
            .arena = .init(gpa),
            .control_frames = options.control_frames,
            .idle_frames = options.idle_frames,
        };
    }

    pub fn deinit(connection: *Connection, gpa: Allocator) void {
        connection.registry.deinit(gpa);
        connection.assembler.deinit(gpa);
        connection.decoder.deinit(gpa);
        connection.encoder.deinit(gpa);
        connection.out.deinit(gpa);
        connection.fields.deinit(connection.arena.allocator());
        connection.arena.deinit();
    }

    /// Writes this endpoint's preface: the magic octets if we are the client
    /// (§3.4), then our `SETTINGS`, then a connection `WINDOW_UPDATE` if we want a
    /// larger window than the 65535 everyone starts with.
    pub fn start(connection: *Connection, gpa: Allocator) Error!void {
        assert(connection.state == .start);
        if (connection.role == .client) {
            try connection.out.writeBytes(gpa, frame.client_preface);
            connection.state = .open;
        } else {
            connection.state = .awaiting_preface;
        }

        // One SETTINGS frame, one acknowledgement to wait for. Writing two frames
        // and counting one is how this first went wrong: the peer dutifully
        // acknowledged both and the second looked unsolicited.
        var announced: [6]frame.Setting = undefined;
        var count: usize = 0;
        for ([_]frame.Setting{
            .{ .id = .header_table_size, .value = connection.options.header_table_size },
            .{ .id = .max_concurrent_streams, .value = connection.options.max_concurrent_streams },
            .{ .id = .initial_window_size, .value = connection.options.initial_window_size },
            .{ .id = .max_frame_size, .value = connection.options.max_frame_size },
            .{ .id = .max_header_list_size, .value = connection.options.hpack.max_header_list_size },
        }) |setting| {
            announced[count] = setting;
            count += 1;
        }
        // §6.5.2: only a client has a say here. A server "MUST NOT explicitly set
        // this value to 1", and 0 is already the effect of never pushing, so a
        // server says nothing at all.
        if (connection.role == .client) {
            announced[count] = .{
                .id = .enable_push,
                .value = @intFromBool(connection.options.enable_push),
            };
            count += 1;
        }
        try frame.writeSettings(&connection.out, gpa, announced[0..count]);
        connection.settings_outstanding += 1;

        if (connection.options.connection_window > frame.default_initial_window_size) {
            const increment = connection.options.connection_window - frame.default_initial_window_size;
            try frame.writeWindowUpdate(&connection.out, gpa, 0, increment);
            // The target is a u31 and the window started below it, so this cannot
            // overflow; if it could, that would be a bug here rather than the
            // peer's doing.
            connection.recv_window.increase(increment) catch unreachable;
        }
    }

    /// Pulls the next application event out of `input`, consuming what it uses.
    /// Returns null when more bytes are needed; protocol responses land in `out`.
    ///
    /// `now_ns` feeds the rate limits. It is a parameter rather than a clock read
    /// so that the limits are testable and so nothing here reaches for a global.
    pub fn poll(
        connection: *Connection,
        gpa: Allocator,
        input: *Buffer,
        now_ns: u64,
    ) Error!?Inbound {
        while (true) {
            if (connection.state == .closed) return null;

            if (connection.state == .awaiting_preface) {
                if (input.readableLen() < frame.client_preface.len) return null;
                const seen = input.peekBytes(frame.client_preface.len) catch unreachable;
                if (!std.mem.eql(u8, seen, frame.client_preface)) {
                    // §3.4: the preface is deliberately invalid HTTP/1.1, so this
                    // is a peer speaking a different protocol rather than a
                    // corrupt HTTP/2 stream. There is nothing to say to it that it
                    // would understand, but GOAWAY costs nothing.
                    return connection.fatal(gpa, .protocol_error, "bad preface");
                }
                input.skip(frame.client_preface.len) catch unreachable;
                connection.state = .open;
            }

            if (input.readableLen() < frame.header_len) return null;
            const head_bytes = input.peekBytes(frame.header_len) catch unreachable;
            const header: frame.Header = .parse(head_bytes[0..frame.header_len]);
            header.validate(connection.local_settings.max_frame_size) catch |err| {
                return connection.fatal(gpa, frame.errorCode(err), "bad frame header");
            };

            // Wait for the whole frame. A frame is the unit everything below works
            // in, so nothing is dispatched on a fragment.
            if (input.readableLen() < frame.header_len + header.length) return null;
            input.skip(frame.header_len) catch unreachable;
            const payload = input.readBytes(header.length) catch unreachable;

            if (try connection.dispatch(gpa, header, payload, now_ns)) |event| return event;
        }
    }

    fn dispatch(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
        now_ns: u64,
    ) Error!?Inbound {
        // §6.10 comes first: the rule is about the frame *sequence*, so it applies
        // before anything cares what this frame is.
        connection.assembler.guard(header) catch {
            return connection.fatal(gpa, .protocol_error, "interleaved header block");
        };

        // §3.4: SETTINGS must be the peer's first frame. Checked after §6.10 only
        // because a CONTINUATION here would be caught by either.
        if (!connection.peer_settings_received and header.frame_type != .settings) {
            // An unknown frame type is still not permitted to precede it: §3.4
            // says the first frame, not the first frame we recognise.
            return connection.fatal(gpa, .protocol_error, "expected SETTINGS");
        }

        return switch (header.frame_type) {
            .settings => connection.onSettings(gpa, header, payload, now_ns),
            .ping => connection.onPing(gpa, header, payload, now_ns),
            .goaway => connection.onGoaway(payload),
            .window_update => connection.onWindowUpdate(gpa, header, payload, now_ns),
            .rst_stream => connection.onRstStream(gpa, header, payload, now_ns),
            .priority => connection.onPriority(gpa, header, now_ns),
            .headers => connection.onHeaders(gpa, header, payload),
            .continuation => connection.onContinuation(gpa, header, payload),
            .data => connection.onData(gpa, header, payload, now_ns),
            .push_promise => connection.onPushPromise(gpa, header, payload),
            // §4.1: a frame of an unknown type must be discarded, which is what
            // makes extensions possible. It still counts as work.
            _ => brk: {
                connection.idle_frames.record(now_ns) catch {
                    break :brk connection.fatal(gpa, .enhance_your_calm, "extension frame flood");
                };
                break :brk null;
            },
        };
    }

    // -- Connection-level frames ------------------------------------------

    fn onSettings(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
        now_ns: u64,
    ) Error!?Inbound {
        connection.control_frames.record(now_ns) catch {
            return connection.fatal(gpa, .enhance_your_calm, "SETTINGS flood");
        };

        if (header.flags.isAck()) {
            // §6.5: an ACK for something we never sent means the peer has lost
            // track of the exchange.
            if (connection.settings_outstanding == 0) {
                return connection.fatal(gpa, .protocol_error, "unsolicited SETTINGS ACK");
            }
            connection.settings_outstanding -= 1;
            return null;
        }

        const previous_window = connection.remote_settings.initial_window_size;
        var iterator = frame.settings(payload);
        while (iterator.next()) |setting| {
            // §6.5.2: SETTINGS_ENABLE_PUSH is a client's to send, because push travels
            // server to client — a client receiving it is being told something the
            // sender has no standing to say. Checked here rather than in
            // `frame.Settings.apply`, which owns the value ranges: the range belongs to
            // the setting, but who may send it belongs to the connection, and this is
            // the layer that knows which end it is.
            if (setting.id == .enable_push and connection.role == .client) {
                return connection.fatal(gpa, .protocol_error, "server sent ENABLE_PUSH");
            }
            connection.remote_settings.apply(setting) catch |err| {
                return connection.fatal(gpa, frame.errorCode(err), "bad setting");
            };
        }
        connection.peer_settings_received = true;

        // §6.9.2: the new initial window size applies to streams that already
        // exist, by shifting each of their send windows. Applying it only to new
        // streams would leave the two sides disagreeing about every open one.
        connection.registry.adjustSendWindows(
            previous_window,
            connection.remote_settings.initial_window_size,
        ) catch {
            return connection.fatal(gpa, .flow_control_error, "window overflow from settings");
        };
        connection.registry.peer_max_concurrent = connection.remote_settings.max_concurrent_streams;
        // §4.2: the peer's table size is a ceiling on what our encoder may use, and
        // the change has to be announced in the header block itself.
        connection.encoder.setPeerCapacity(gpa, connection.remote_settings.header_table_size);

        // §6.5.3: acknowledge, and in order — the peer applies settings when it
        // sees the ACK, so it must not arrive before anything we sent first.
        try frame.writeSettingsAck(&connection.out, gpa);
        return .settings_updated;
    }

    fn onPing(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
        now_ns: u64,
    ) Error!?Inbound {
        connection.control_frames.record(now_ns) catch {
            return connection.fatal(gpa, .enhance_your_calm, "PING flood");
        };
        var data: [8]u8 = undefined;
        @memcpy(&data, payload[0..8]);
        if (header.flags.isAck()) return .{ .pong = data };
        // §6.7: the reply carries the same opaque octets back.
        try frame.writePing(&connection.out, gpa, data, true);
        return null;
    }

    fn onGoaway(connection: *Connection, payload: []const u8) Error!?Inbound {
        const bye = frame.parseGoaway(payload);
        // §6.8: streams above `last_stream_id` were not processed and may be
        // retried elsewhere. Existing ones below it may still complete, so this is
        // `closing` rather than `closed`.
        connection.state = .closing;
        return .{ .goaway = .{
            .last_stream_id = bye.last_stream_id,
            .code = bye.error_code,
            .debug_data = bye.debug_data,
        } };
    }

    fn onWindowUpdate(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
        now_ns: u64,
    ) Error!?Inbound {
        connection.idle_frames.record(now_ns) catch {
            return connection.fatal(gpa, .enhance_your_calm, "WINDOW_UPDATE flood");
        };
        const increment = frame.parseWindowUpdate(payload) catch |err| {
            // §6.9: a zero increment on the connection is a connection error; on a
            // stream it is a stream error. Same malformed frame, different reach.
            if (header.stream_id == 0) {
                return connection.fatal(gpa, frame.errorCode(err), "zero window update");
            }
            try connection.resetStream(gpa, header.stream_id, .protocol_error);
            return null;
        };

        if (header.stream_id == 0) {
            connection.send_window.increase(increment) catch {
                return connection.fatal(gpa, .flow_control_error, "connection window overflow");
            };
            return null;
        }

        const stream = connection.registry.get(header.stream_id) orelse {
            // Credit for a stream we have already forgotten is ordinary; credit for
            // one that never existed is not.
            if (connection.registry.wasClosed(header.stream_id)) return null;
            return connection.fatal(gpa, .protocol_error, "window update for idle stream");
        };
        stream.onWindowUpdate(.remote) catch |err| {
            return connection.streamFailure(gpa, header.stream_id, err);
        };
        stream.send_window.increase(increment) catch {
            // §6.9.1: overflowing one stream's window need not end the connection.
            try connection.resetStream(gpa, header.stream_id, .flow_control_error);
        };
        return null;
    }

    fn onRstStream(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
        now_ns: u64,
    ) Error!?Inbound {
        // Rapid Reset: the rate limit is the only thing that sees this, because a
        // reset stream frees its concurrency slot immediately.
        connection.registry.recordReset(now_ns) catch {
            return connection.fatal(gpa, .enhance_your_calm, "RST_STREAM flood");
        };
        const code = frame.parseRstStream(payload);

        const stream = connection.registry.get(header.stream_id) orelse {
            if (connection.registry.wasClosed(header.stream_id)) return null;
            return connection.fatal(gpa, .protocol_error, "reset of idle stream");
        };
        stream.onRstStream(.remote) catch |err| {
            return connection.streamFailure(gpa, header.stream_id, err);
        };
        connection.registry.remove(gpa, header.stream_id);
        return .{ .reset = .{ .stream_id = header.stream_id, .code = code } };
    }

    fn onPriority(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        now_ns: u64,
    ) Error!?Inbound {
        connection.idle_frames.record(now_ns) catch {
            return connection.fatal(gpa, .enhance_your_calm, "PRIORITY flood");
        };
        // §5.3.1 deprecates the scheme and §5.3 permits ignoring it, so this is
        // accepted and dropped. It is still counted above, because a peer can send
        // them without limit and they are the cheapest frame there is.
        _ = header;
        return null;
    }

    // -- Stream frames ----------------------------------------------------

    fn onHeaders(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
    ) Error!?Inbound {
        const complete = connection.assembler.pushHeaders(gpa, header, payload) catch |err| {
            return connection.headerFailure(gpa, err);
        };
        return connection.finishHeaderBlock(gpa, complete);
    }

    fn onContinuation(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
    ) Error!?Inbound {
        const complete = connection.assembler.pushContinuation(gpa, header, payload) catch |err| {
            return connection.headerFailure(gpa, err);
        };
        return connection.finishHeaderBlock(gpa, complete);
    }

    fn onPushPromise(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
    ) Error!?Inbound {
        // §8.4: only a server may push. A client sending one is a protocol error,
        // and so is any push at all once we have said we do not want them.
        if (connection.role == .server) {
            return connection.fatal(gpa, .protocol_error, "client push");
        }
        if (!connection.local_settings.enable_push) {
            return connection.fatal(gpa, .protocol_error, "push while disabled");
        }
        const complete = connection.assembler.pushPromise(gpa, header, payload) catch |err| {
            return connection.headerFailure(gpa, err);
        };
        return connection.finishHeaderBlock(gpa, complete);
    }

    fn finishHeaderBlock(
        connection: *Connection,
        gpa: Allocator,
        maybe_complete: ?headers_mod.Complete,
    ) Error!?Inbound {
        const complete = maybe_complete orelse return null;

        // One block's strings live in this arena, so the event's slices are valid
        // exactly until the next one is decoded.
        _ = connection.arena.reset(.retain_capacity);
        connection.fields = .empty;
        const arena = connection.arena.allocator();

        connection.decoder.decode(
            gpa,
            arena,
            complete.block,
            &connection.fields,
            connection.options.hpack,
        ) catch |err| {
            // §4.3: HPACK is stateful and shared by every stream, so a block that
            // fails to decode leaves the table of unknown content. There is no
            // recovering one stream from that.
            const code: frame.ErrorCode = switch (err) {
                error.CompressionError => .compression_error,
                error.LimitExceeded => .enhance_your_calm,
                error.OutOfMemory => return error.OutOfMemory,
            };
            return connection.fatal(gpa, code, "hpack");
        };

        return switch (complete.kind) {
            .headers => connection.deliverHeaders(gpa, complete),
            .push_promise => connection.deliverPush(gpa, complete),
        };
    }

    fn deliverHeaders(
        connection: *Connection,
        gpa: Allocator,
        complete: headers_mod.Complete,
    ) Error!?Inbound {
        const id = complete.stream_id;
        const existing = connection.registry.get(id);

        const stream = existing orelse brk: {
            if (connection.registry.isRemoteInitiated(id)) {
                // §6.8: once GOAWAY is out, a new stream is refused rather than
                // served — that is what makes the last-stream-id in it meaningful.
                if (connection.goaway_sent) {
                    try frame.writeRstStream(&connection.out, gpa, id, .refused_stream);
                    return null;
                }
                break :brk connection.registry.openRemote(gpa, id) catch |err| {
                    return connection.streamFailure(gpa, id, err);
                };
            }
            // A header block for a locally-initiated stream we no longer have.
            if (connection.registry.wasClosed(id)) return null;
            return connection.fatal(gpa, .protocol_error, "headers for idle local stream");
        };

        if (connection.registry.isRemoteInitiated(id)) {
            connection.last_remote_processed = @max(connection.last_remote_processed, id);
        }

        const trailers = stream.remote_headers_seen;

        // §8.5: "Frame types other than DATA or stream management frames
        // (RST_STREAM, WINDOW_UPDATE, and PRIORITY) MUST NOT be sent on a connected
        // stream and MUST be treated as a stream error if received." A tunnel
        // therefore has no trailer section — and accepting one means a peer can put
        // field semantics into a byte stream a proxy relays verbatim.
        //
        // A stream error rather than a connection error, which is where HTTP/2 and
        // HTTP/3 differ on the same rule: §4.4 of RFC 9114 makes it a connection
        // error. §5.4 permits the generic code where the RFC names no type.
        if (stream.tunnel) {
            try connection.resetStream(gpa, id, .protocol_error);
            return null;
        }

        // §8.1: a stream carries at most one trailer block, and it must end the
        // stream. Anything else is a second request on the same stream.
        if (trailers and !complete.end_stream) {
            try connection.resetStream(gpa, id, .protocol_error);
            return null;
        }

        stream.onHeaders(.remote, complete.end_stream) catch |err| {
            return connection.streamFailure(gpa, id, err);
        };
        stream.remote_headers_seen = true;

        // §8.5's "connected stream", from each side's point of view.
        if (!trailers) switch (connection.role) {
            .server => if (semantics.isConnectRequest(connection.fields.items)) {
                stream.tunnel = true;
            },
            .client => if (stream.sent_connect and
                semantics.isSuccessResponse(connection.fields.items))
            {
                stream.tunnel = true;
            },
        };

        const event: Inbound = .{ .headers = .{
            .stream_id = id,
            .fields = connection.fields.items,
            .end_stream = complete.end_stream,
            .trailers = trailers,
            .priority = complete.priority,
        } };
        if (stream.state.isClosed()) connection.registry.remove(gpa, id);
        return event;
    }

    fn deliverPush(
        connection: *Connection,
        gpa: Allocator,
        complete: headers_mod.Complete,
    ) Error!?Inbound {
        // §8.5 permits only DATA, RST_STREAM, WINDOW_UPDATE and PRIORITY on a
        // connected stream. PUSH_PROMISE arrives on the *associated* stream, so a
        // tunnel is a place a peer could try to open one from.
        if (connection.registry.get(complete.stream_id)) |associated| {
            if (associated.tunnel) {
                try connection.resetStream(gpa, complete.stream_id, .protocol_error);
                return null;
            }
        }
        const promised = connection.registry.openRemote(gpa, complete.promised_stream_id) catch |err| {
            return connection.streamFailure(gpa, complete.promised_stream_id, err);
        };
        promised.onPushPromise(.remote) catch |err| {
            return connection.streamFailure(gpa, complete.promised_stream_id, err);
        };
        return .{ .push_promise = .{
            .stream_id = complete.stream_id,
            .promised_stream_id = complete.promised_stream_id,
            .fields = connection.fields.items,
        } };
    }

    fn onData(
        connection: *Connection,
        gpa: Allocator,
        header: frame.Header,
        payload: []const u8,
        now_ns: u64,
    ) Error!?Inbound {
        // §6.1: flow control is charged the whole payload, padding included. The
        // application sees less than this, and charging what it sees would leave
        // the two sides' windows drifting apart with neither at fault.
        const charged: u32 = header.length;

        if (charged == 0 and !header.flags.endStream()) {
            connection.idle_frames.record(now_ns) catch {
                return connection.fatal(gpa, .enhance_your_calm, "empty DATA flood");
            };
        }

        // The connection window is charged even for a stream we will refuse, because
        // the bytes arrived either way and the peer is counting them.
        connection.recv_window.receive(charged) catch {
            return connection.fatal(gpa, .flow_control_error, "connection window exceeded");
        };
        try connection.replenishConnection(gpa);

        const stream = connection.registry.get(header.stream_id) orelse {
            if (connection.registry.wasClosed(header.stream_id)) {
                // §5.1: data for a stream we have forgotten. It is already reset or
                // complete; the bytes are charged and dropped.
                return null;
            }
            return connection.fatal(gpa, .protocol_error, "data for idle stream");
        };

        stream.recv_window.receive(charged) catch {
            try connection.resetStream(gpa, header.stream_id, .flow_control_error);
            return null;
        };
        stream.onData(.remote, header.flags.endStream()) catch |err| {
            return connection.streamFailure(gpa, header.stream_id, err);
        };

        const bytes = frame.stripPadding(payload, header.flags) catch |err| {
            return connection.fatal(gpa, frame.errorCode(err), "bad padding");
        };
        try connection.replenishStream(gpa, stream);

        const event: Inbound = .{ .data = .{
            .stream_id = header.stream_id,
            .bytes = bytes,
            .end_stream = header.flags.endStream(),
        } };
        if (stream.state.isClosed()) connection.registry.remove(gpa, header.stream_id);
        return event;
    }

    // -- Replenishing receive windows -------------------------------------

    /// Returns credit once half the window has been spent. Doing it per frame would
    /// double the frame count on every download; doing it only when empty would
    /// stall the peer for a round trip each time.
    fn replenishConnection(connection: *Connection, gpa: Allocator) Error!void {
        const target: i64 = connection.options.connection_window;
        const spent = target - connection.recv_window.available;
        if (spent < @divTrunc(target, 2)) return;
        const increment: u31 = @intCast(spent);
        try frame.writeWindowUpdate(&connection.out, gpa, 0, increment);
        // Returning exactly what was spent cannot exceed the target it came from.
        connection.recv_window.increase(increment) catch unreachable;
    }

    fn replenishStream(
        connection: *Connection,
        gpa: Allocator,
        stream: *stream_mod.Stream,
    ) Error!void {
        // A stream that is finished receiving needs no credit; sending it would be
        // a frame the peer has no use for.
        if (stream.state.isClosed() or stream.state == .half_closed_remote) return;
        const target: i64 = connection.options.initial_window_size;
        const spent = target - stream.recv_window.available;
        if (spent < @divTrunc(target, 2)) return;
        const increment: u31 = @intCast(spent);
        try frame.writeWindowUpdate(&connection.out, gpa, stream.id, increment);
        stream.recv_window.increase(increment) catch unreachable;
    }

    // -- Failure handling -------------------------------------------------

    /// Writes `GOAWAY` and latches. The caller must flush `out` before closing, or
    /// the peer is left guessing.
    fn fatal(
        connection: *Connection,
        gpa: Allocator,
        code: frame.ErrorCode,
        debug: []const u8,
    ) Error {
        if (!connection.goaway_sent) {
            connection.goaway_sent = true;
            frame.writeGoaway(
                &connection.out,
                gpa,
                connection.last_remote_processed,
                code,
                debug,
            ) catch {};
        }
        connection.state = .closing;
        return error.ConnectionError;
    }

    /// Acts on a failure the stream layer reported, using the severity it named.
    fn streamFailure(
        connection: *Connection,
        gpa: Allocator,
        stream_id: u31,
        err: (stream_mod.Error || Allocator.Error),
    ) Error!?Inbound {
        const stream_err = switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| @as(stream_mod.Error, e),
        };
        switch (stream_mod.severity(stream_err)) {
            .connection => return connection.fatal(
                gpa,
                stream_mod.errorCode(stream_err),
                "stream state",
            ),
            .stream => {
                try connection.resetStream(gpa, stream_id, stream_mod.errorCode(stream_err));
                return null;
            },
        }
    }

    fn headerFailure(
        connection: *Connection,
        gpa: Allocator,
        err: (headers_mod.Error || frame.Error || Buffer.Error),
    ) Error {
        const code: frame.ErrorCode = switch (err) {
            error.OutOfMemory, error.BufferFull => return connection.fatal(
                gpa,
                .internal_error,
                "out of memory",
            ),
            error.LimitExceeded => .enhance_your_calm,
            error.ProtocolError => .protocol_error,
            error.FrameSizeError => .frame_size_error,
            error.FlowControlError => .flow_control_error,
            error.CompressionError => .compression_error,
        };
        // Every one of these is a connection error: a header block that cannot be
        // assembled leaves HPACK of unknown alignment for every stream.
        return connection.fatal(gpa, code, "header block");
    }

    fn resetStream(
        connection: *Connection,
        gpa: Allocator,
        stream_id: u31,
        code: frame.ErrorCode,
    ) Error!void {
        try frame.writeRstStream(&connection.out, gpa, stream_id, code);
        connection.registry.remove(gpa, stream_id);
    }

    // -- Sending ----------------------------------------------------------

    /// Sends a header block, opening the stream if it is new. Returns the stream id.
    ///
    /// `HEADERS` is not flow-controlled (§6.9), so this goes out immediately rather
    /// than through the scheduler — which is exactly why a large `DATA` for one
    /// stream must not be allowed to sit in front of it.
    pub fn sendHeaders(
        connection: *Connection,
        gpa: Allocator,
        stream_id: u31,
        fields: []const hpack.Field,
        end_stream: bool,
    ) (Error || stream_mod.Error)!void {
        // §5.1.2: the peer's limit is on us as well, and reaching it is the
        // application's problem rather than a protocol violation — REFUSED_STREAM
        // is precisely "try again elsewhere".
        const stream = connection.registry.get(stream_id) orelse
            try connection.registry.openLocal(gpa, stream_id);

        var block: Buffer = .empty;
        defer block.deinit(gpa);
        try connection.encoder.encode(&block, gpa, fields);

        var flags: frame.Flags = .{ .bits = frame.Flags.end_headers };
        if (end_stream) flags = flags.with(frame.Flags.end_stream);
        try connection.emitHeaderBlock(gpa, stream_id, block.readableSlice(), flags);

        // §8.5: remember an outgoing CONNECT so a 2xx answer can be recognised as
        // opening a tunnel. Only a client's requests matter here; a server's own
        // 2xx is what *makes* the tunnel, and it already marked the stream when the
        // request arrived.
        if (connection.role == .client and !stream.remote_headers_seen) {
            if (semantics.isConnectRequest(fields)) stream.sent_connect = true;
        }

        stream.onHeaders(.local, end_stream) catch {};
        if (stream.state.isClosed()) connection.registry.remove(gpa, stream_id);
    }

    /// Splits a header block across `HEADERS` and `CONTINUATION` when it exceeds
    /// what one frame may carry. §6.10 requires the pieces be adjacent, which is
    /// automatic here: they are written back to back into `out`.
    fn emitHeaderBlock(
        connection: *Connection,
        gpa: Allocator,
        stream_id: u31,
        block: []const u8,
        flags: frame.Flags,
    ) Error!void {
        const max: usize = connection.remote_settings.max_frame_size;
        if (block.len <= max) {
            try frame.writeFrame(&connection.out, gpa, .headers, flags, stream_id, block);
            return;
        }

        // The first frame carries every flag except END_HEADERS, which belongs on
        // the last piece.
        var first_flags: frame.Flags = .{ .bits = flags.bits & ~frame.Flags.end_headers };
        try frame.writeFrame(&connection.out, gpa, .headers, first_flags, stream_id, block[0..max]);
        first_flags = .{};

        var offset = max;
        while (offset < block.len) {
            const take = @min(max, block.len - offset);
            const last = offset + take == block.len;
            const cont_flags: frame.Flags =
                if (last) .{ .bits = frame.Flags.end_headers } else .{};
            try frame.writeFrame(
                &connection.out,
                gpa,
                .continuation,
                cont_flags,
                stream_id,
                block[offset..][0..take],
            );
            offset += take;
        }
    }

    /// Queues body bytes. They leave on the next `flush`, subject to both windows.
    ///
    /// Returns `error.StreamWriteQueueFull` when the application has ignored
    /// unwritability past the ceiling; see `flow.SendQueue`.
    pub fn sendData(
        connection: *Connection,
        gpa: Allocator,
        stream_id: u31,
        bytes: []const u8,
        end_stream: bool,
    ) (Error || flow.SendQueue.WriteError)!flow.Transition {
        const stream = connection.registry.get(stream_id) orelse return error.ConnectionError;
        const transition = try stream.sends.add(@intCast(bytes.len));
        try stream.pending.writeBytes(gpa, bytes);
        if (end_stream) stream.pending_end_stream = true;
        return transition;
    }

    /// Whether a stream is accepting more body bytes without exceeding its mark.
    pub fn isWritable(connection: *Connection, stream_id: u31) bool {
        const stream = connection.registry.get(stream_id) orelse return false;
        return stream.sends.writable;
    }

    /// Runs the scheduler once, moving as much queued body as the windows allow
    /// into `out`. Returns the streams whose writability changed, written into
    /// `transitions`.
    /// Runs write passes and reports every writability edge they produced.
    ///
    /// `transitions` is a pointer to an array of exactly `max_writability_transitions`
    /// rather than a slice, so a caller that supplies a smaller one does not compile.
    /// It used to be a slice and the report stopped at its length, which silently
    /// dropped edges past 32 while the streams' internal state had already changed —
    /// see `max_writability_transitions` for why a dropped edge never comes back.
    pub fn flush(
        connection: *Connection,
        gpa: Allocator,
        transitions: *[max_writability_transitions]Writability,
    ) Error![]Writability {
        var candidates: std.ArrayList(flow.Candidate) = .empty;
        defer candidates.deinit(gpa);
        // Streams whose only remaining business is END_STREAM. Collected rather
        // than sent inside the walk, because sending one can close the stream and
        // removing an entry while iterating the map is not allowed.
        var ends: std.ArrayList(u31) = .empty;
        defer ends.deinit(gpa);

        var iterator = connection.registry.streams.valueIterator();
        while (iterator.next()) |stream| {
            if (stream.pending.readableLen() == 0) {
                if (stream.pending_end_stream) try ends.append(gpa, stream.id);
                continue;
            }
            try candidates.append(gpa, .{
                .stream_id = stream.id,
                .pending = @intCast(stream.pending.readableLen()),
                .window = &stream.send_window,
            });
        }

        // An empty DATA frame carrying END_STREAM is not waiting for credit. §6.9
        // charges the payload, and this one has none — so it must not go through
        // the scheduler, which skips anything with nothing pending and would
        // therefore park the stream for ever. A response with an empty body ends
        // exactly this way, which is how the omission showed up: curl waited
        // through a 404 with no body and never saw the stream close.
        for (ends.items) |stream_id| {
            const stream = connection.registry.get(stream_id) orelse continue;
            stream.pending_end_stream = false;
            try frame.writeData(&connection.out, gpa, stream_id, "", true);
            stream.onData(.local, true) catch {};
            if (stream.state.isClosed()) connection.registry.remove(gpa, stream_id);
        }
        // A stable order, so round robin means something across passes.
        std.mem.sort(flow.Candidate, candidates.items, {}, lessByStreamId);

        // One place, so the caller's buffer and this array cannot disagree.
        var grants: [max_writability_transitions]flow.Allocation = undefined;
        const granted = connection.scheduler.run(
            &connection.send_window,
            candidates.items,
            connection.remote_settings.max_frame_size,
            &grants,
        );

        var changed: usize = 0;
        for (granted) |grant| {
            const stream = connection.registry.get(grant.stream_id).?;
            const chunk = stream.pending.readBytes(grant.bytes) catch unreachable;
            const drains_queue = stream.pending.readableLen() == 0;
            const end = drains_queue and stream.pending_end_stream;
            try frame.writeData(&connection.out, gpa, grant.stream_id, chunk, end);
            stream.pending.discardReadBytes();

            if (end) {
                stream.pending_end_stream = false;
                stream.onData(.local, true) catch {};
            }
            const transition = stream.sends.drained(grant.bytes);
            if (transition != .unchanged) {
                transitions[changed] = .{ .stream_id = grant.stream_id, .writable = stream.sends.writable };
                changed += 1;
            }
            if (stream.state.isClosed()) connection.registry.remove(gpa, grant.stream_id);
        }
        return transitions[0..changed];
    }

    pub const Writability = struct {
        stream_id: u31,
        writable: bool,
    };

    /// The most writability transitions one `flush` can produce, and therefore the
    /// smallest buffer `flush` accepts.
    ///
    /// A transition is an *edge*: `flush` makes a stream writable and the event is the
    /// only announcement it will ever get, because the crossing does not happen twice.
    /// So a report that silently stops at the caller's capacity does not postpone a
    /// notification — it loses it, and an application obeying the high-water mark then
    /// stops writing to that stream for good. Asserted rather than truncated for that
    /// reason, and the grant array below is sized from the same constant.
    pub const max_writability_transitions = 64;

    fn lessByStreamId(_: void, a: flow.Candidate, b: flow.Candidate) bool {
        return a.stream_id < b.stream_id;
    }

    /// Resets a stream from this side.
    pub fn sendReset(
        connection: *Connection,
        gpa: Allocator,
        stream_id: u31,
        code: frame.ErrorCode,
    ) Error!void {
        try connection.resetStream(gpa, stream_id, code);
    }

    /// Sends `PING`. The eight octets come back unchanged in the reply.
    pub fn sendPing(connection: *Connection, gpa: Allocator, data: [8]u8) Error!void {
        try frame.writePing(&connection.out, gpa, data, false);
    }

    /// Starts a graceful shutdown (§6.8). Streams at or below the reported
    /// identifier may still finish, which is why this does not close anything.
    pub fn sendGoaway(
        connection: *Connection,
        gpa: Allocator,
        code: frame.ErrorCode,
        debug: []const u8,
    ) Error!void {
        if (connection.goaway_sent) return;
        connection.goaway_sent = true;
        try frame.writeGoaway(
            &connection.out,
            gpa,
            connection.last_remote_processed,
            code,
            debug,
        );
        connection.state = .closing;
    }

    /// The next identifier this endpoint may open.
    pub fn nextStreamId(connection: *const Connection) u31 {
        return connection.registry.nextLocalId();
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "connection: every declaration compiles" {
    // Zig analyses function bodies lazily, so a module referenced but never called
    // is only syntax-checked. This forces the rest, and it found four real errors
    // the first time it was added.
    testing.refAllDecls(Connection);
}

/// Two connections wired to each other, which is the only way to check a protocol
/// against itself honestly: every byte one side writes is parsed by the other with
/// no test-only shortcut in between.
const Pair = struct {
    gpa: Allocator,
    client: Connection,
    server: Connection,
    /// Bytes in flight towards each side.
    to_client: Buffer = .empty,
    to_server: Buffer = .empty,
    now_ns: u64 = 0,

    fn init(gpa: Allocator, client_options: Options, server_options: Options) !Pair {
        var pair: Pair = .{
            .gpa = gpa,
            .client = .init(gpa, .client, client_options),
            .server = .init(gpa, .server, server_options),
        };
        try pair.client.start(gpa);
        try pair.server.start(gpa);
        return pair;
    }

    fn deinit(pair: *Pair) void {
        pair.client.deinit(pair.gpa);
        pair.server.deinit(pair.gpa);
        pair.to_client.deinit(pair.gpa);
        pair.to_server.deinit(pair.gpa);
    }

    /// Moves what each side has queued into the other's input.
    fn transfer(pair: *Pair) !void {
        try pair.to_server.writeBytes(pair.gpa, pair.client.out.readableSlice());
        pair.client.out.clear();
        try pair.to_client.writeBytes(pair.gpa, pair.server.out.readableSlice());
        pair.server.out.clear();
    }

    fn pollServer(pair: *Pair) !?Inbound {
        return pair.server.poll(pair.gpa, &pair.to_server, pair.now_ns);
    }

    fn pollClient(pair: *Pair) !?Inbound {
        return pair.client.poll(pair.gpa, &pair.to_client, pair.now_ns);
    }

    /// Drains both sides until neither has anything to say, transferring in
    /// between. Returns how many events each side produced, so a test can assert
    /// that a handshake is silent as far as the application is concerned.
    const Counts = struct { client: usize, server: usize };

    fn settle(pair: *Pair) !Counts {
        var counts: Counts = .{ .client = 0, .server = 0 };
        for (0..8) |_| {
            try pair.transfer();
            while (try pair.pollServer()) |_| counts.server += 1;
            while (try pair.pollClient()) |_| counts.client += 1;
            if (pair.client.out.readableLen() == 0 and pair.server.out.readableLen() == 0) break;
        }
        return counts;
    }
};

fn fieldsOf(event: Inbound) []const hpack.Field {
    return switch (event) {
        .headers => |h| h.fields,
        .push_promise => |p| p.fields,
        else => unreachable,
    };
}

fn expectField(fields: []const hpack.Field, name: []const u8, value: []const u8) !void {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) {
            try testing.expectEqualStrings(value, field.value);
            return;
        }
    }
    std.debug.print("no field named {s}\n", .{name});
    return error.FieldMissing;
}

test "connection: the client preface is the magic octets then SETTINGS" {
    const gpa = testing.allocator;
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit(gpa);
    try client.start(gpa);

    const bytes = client.out.readableSlice();
    try testing.expect(bytes.len > frame.client_preface.len);
    try testing.expectEqualStrings(frame.client_preface, bytes[0..frame.client_preface.len]);

    // §3.4: what follows the magic must be SETTINGS.
    const header: frame.Header = .parse(bytes[frame.client_preface.len..][0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.settings, header.frame_type);
    try testing.expectEqual(@as(u31, 0), header.stream_id);
    try testing.expect(!header.flags.isAck());
}

test "connection: a server sends SETTINGS with no magic of its own" {
    const gpa = testing.allocator;
    var server: Connection = .init(gpa, .server, .{});
    defer server.deinit(gpa);
    try server.start(gpa);

    const header: frame.Header = .parse(server.out.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.settings, header.frame_type);
    try testing.expectEqual(Connection.State.awaiting_preface, server.state);
}

test "connection: the handshake settles without telling the application anything" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();

    const counts = try pair.settle();
    // Each side hears that the other's settings arrived, and nothing else: no
    // stream events, no errors.
    try testing.expectEqual(@as(usize, 1), counts.client);
    try testing.expectEqual(@as(usize, 1), counts.server);
    try testing.expectEqual(Connection.State.open, pair.client.state);
    try testing.expectEqual(Connection.State.open, pair.server.state);
    // Both acknowledgements arrived, so neither side is still waiting.
    try testing.expectEqual(@as(u32, 0), pair.client.settings_outstanding);
    try testing.expectEqual(@as(u32, 0), pair.server.settings_outstanding);
}

test "connection: a peer that is not speaking HTTP/2 gets GOAWAY" {
    const gpa = testing.allocator;
    var server: Connection = .init(gpa, .server, .{});
    defer server.deinit(gpa);
    try server.start(gpa);
    server.out.clear();

    var input: Buffer = .empty;
    defer input.deinit(gpa);
    // §3.4 chose a preface that is invalid HTTP/1.1 precisely so this case is
    // unambiguous: a plain HTTP/1.1 request is not a corrupt HTTP/2 stream.
    try input.writeBytes(gpa, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try testing.expectError(error.ConnectionError, server.poll(gpa, &input, 0));

    const header: frame.Header = .parse(server.out.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.goaway, header.frame_type);
    const bye = frame.parseGoaway(server.out.readableSlice()[frame.header_len..]);
    try testing.expectEqual(frame.ErrorCode.protocol_error, bye.error_code);
}

test "connection: §3.4 requires SETTINGS first, whatever else arrives" {
    const gpa = testing.allocator;
    for ([_]frame.FrameType{ .ping, .headers, .window_update, @fromBackingInt(@intCast(0xef)) }) |first| {
        var server: Connection = .init(gpa, .server, .{});
        defer server.deinit(gpa);
        try server.start(gpa);
        server.out.clear();

        var input: Buffer = .empty;
        defer input.deinit(gpa);
        try input.writeBytes(gpa, frame.client_preface);
        const payload_len: usize = switch (first) {
            .ping => 8,
            .window_update => 4,
            else => 0,
        };
        var payload: [8]u8 = @splat(1);
        try frame.writeFrame(
            &input,
            gpa,
            first,
            .{ .bits = frame.Flags.end_headers },
            if (first == .headers) 1 else 0,
            payload[0..payload_len],
        );
        try testing.expectError(error.ConnectionError, server.poll(gpa, &input, 0));
        const header: frame.Header = .parse(server.out.readableSlice()[0..frame.header_len]);
        try testing.expectEqual(frame.FrameType.goaway, header.frame_type);
    }
}

test "connection: a request and a response cross the wire" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    const id = pair.client.nextStreamId();
    try testing.expectEqual(@as(u31, 1), id);
    try pair.client.sendHeaders(gpa, id, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/hello" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "authorization", .value = "Bearer x", .never_indexed = true },
    }, true);
    try pair.transfer();

    const request = (try pair.pollServer()).?;
    try expectField(fieldsOf(request), ":method", "GET");
    try expectField(fieldsOf(request), ":path", "/hello");
    try testing.expect(request.headers.end_stream);
    try testing.expect(!request.headers.trailers);
    // §6.2.3 survives a round trip, so a proxy downstream can still honour it.
    for (fieldsOf(request)) |field| {
        if (std.mem.eql(u8, field.name, "authorization")) try testing.expect(field.never_indexed);
    }
    try testing.expectEqual(@as(u31, 1), pair.server.last_remote_processed);

    var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
    try pair.server.sendHeaders(gpa, id, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    }, false);
    _ = try pair.server.sendData(gpa, id, "hello", true);
    _ = try pair.server.flush(gpa, &transitions);
    try pair.transfer();

    const response = (try pair.pollClient()).?;
    try expectField(fieldsOf(response), ":status", "200");
    try testing.expect(!response.headers.end_stream);

    const body = (try pair.pollClient()).?;
    try testing.expectEqualStrings("hello", body.data.bytes);
    try testing.expect(body.data.end_stream);

    // Both sides forgot the stream, since it completed.
    try testing.expect(pair.client.registry.get(id) == null);
    try testing.expect(pair.server.registry.get(id) == null);
}

test "connection: trailers are a second header block and must end the stream" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    const id = pair.client.nextStreamId();
    try pair.client.sendHeaders(gpa, id, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/upload" },
    }, false);
    var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
    _ = try pair.client.sendData(gpa, id, "body", false);
    _ = try pair.client.flush(gpa, &transitions);
    try pair.client.sendHeaders(gpa, id, &.{.{ .name = "x-checksum", .value = "abc" }}, true);
    try pair.transfer();

    const request = (try pair.pollServer()).?;
    try testing.expect(!request.headers.trailers);
    const chunk = (try pair.pollServer()).?;
    try testing.expectEqualStrings("body", chunk.data.bytes);
    const trailers = (try pair.pollServer()).?;
    // §8.1: recognised as trailers because a block already arrived on this stream.
    try testing.expect(trailers.headers.trailers);
    try testing.expect(trailers.headers.end_stream);
    try expectField(fieldsOf(trailers), "x-checksum", "abc");
}

test "connection: PING is answered with the same octets, and its reply surfaces" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    const payload: [8]u8 = .{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try pair.client.sendPing(gpa, payload);
    try pair.transfer();
    // The server answers without telling its application anything.
    try testing.expect(try pair.pollServer() == null);
    try pair.transfer();

    const pong = (try pair.pollClient()).?;
    try testing.expectEqualSlices(u8, &payload, &pong.pong);
}

test "connection: GOAWAY surfaces and stops new streams being served" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    try pair.server.sendGoaway(gpa, .no_error, "restarting");
    try pair.transfer();
    const bye = (try pair.pollClient()).?;
    try testing.expectEqual(frame.ErrorCode.no_error, bye.goaway.code);
    try testing.expectEqualStrings("restarting", bye.goaway.debug_data);
    // §6.8: existing streams may still finish, so this is not `closed`.
    try testing.expectEqual(Connection.State.closing, pair.client.state);
    try testing.expectEqual(Connection.State.closing, pair.server.state);

    // A request that arrives after GOAWAY is refused rather than served, which is
    // what makes the last-stream-id in it mean something.
    try pair.client.sendHeaders(gpa, 3, &.{.{ .name = ":path", .value = "/late" }}, true);
    try pair.transfer();
    try testing.expect(try pair.pollServer() == null);
    try pair.transfer();
    const header: frame.Header = .parse(pair.to_client.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.rst_stream, header.frame_type);
}

test "connection: RST_STREAM ends one stream and leaves the connection alone" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    try pair.client.sendHeaders(gpa, 1, &.{.{ .name = ":path", .value = "/a" }}, false);
    try pair.transfer();
    _ = (try pair.pollServer()).?;

    try pair.client.sendReset(gpa, 1, .cancel);
    try pair.transfer();
    const reset = (try pair.pollServer()).?;
    try testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try testing.expectEqual(frame.ErrorCode.cancel, reset.reset.code);
    try testing.expect(pair.server.registry.get(1) == null);

    // The connection is untouched: another stream works normally.
    try testing.expectEqual(Connection.State.open, pair.server.state);
    try pair.client.sendHeaders(gpa, 3, &.{.{ .name = ":path", .value = "/b" }}, true);
    try pair.transfer();
    const next = (try pair.pollServer()).?;
    try expectField(fieldsOf(next), ":path", "/b");
}

test "connection: flow control charges padding, and the application sees less" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{ .initial_window_size = 100 }, .{ .initial_window_size = 100 });
    defer pair.deinit();
    _ = try pair.settle();

    try pair.client.sendHeaders(gpa, 1, &.{.{ .name = ":path", .value = "/p" }}, false);
    try pair.transfer();
    _ = (try pair.pollServer()).?;

    // A padded DATA frame, written by hand because the sending path here does not
    // pad: §6.1 charges the whole payload, so what the peer's window loses is more
    // than what its application receives.
    const before = pair.server.registry.get(1).?.recv_window.available;
    try frame.writeFrame(
        &pair.to_server,
        gpa,
        .data,
        .{ .bits = frame.Flags.padded },
        1,
        "\x04hello\x00\x00\x00\x00",
    );
    const data = (try pair.pollServer()).?;
    try testing.expectEqualStrings("hello", data.data.bytes);

    const stream = pair.server.registry.get(1).?;
    const charged = before - stream.recv_window.available;
    // Ten charged, five delivered. Charging five would leave the two sides five
    // bytes apart with neither of them wrong.
    try testing.expectEqual(@as(i64, 10), charged);
    try testing.expectEqual(@as(usize, 5), data.data.bytes.len);
}

test "connection: a receive window is replenished at halfway, not per frame" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{
        .initial_window_size = 1_000,
        .connection_window = 10_000,
    });
    defer pair.deinit();
    _ = try pair.settle();

    try pair.client.sendHeaders(gpa, 1, &.{.{ .name = ":path", .value = "/p" }}, false);
    try pair.transfer();
    _ = (try pair.pollServer()).?;
    pair.server.out.clear();

    const chunk: [200]u8 = @splat('x');
    // Two frames of 200 leaves 600 of 1000: under halfway, so nothing is returned.
    for (0..2) |_| {
        try frame.writeFrame(&pair.to_server, gpa, .data, .{}, 1, &chunk);
        _ = (try pair.pollServer()).?;
    }
    try testing.expectEqual(@as(usize, 0), pair.server.out.readableLen());

    // The third crosses halfway and the credit comes back in one frame rather than
    // three: per-frame updates would double the frame count of every download.
    try frame.writeFrame(&pair.to_server, gpa, .data, .{}, 1, &chunk);
    _ = (try pair.pollServer()).?;
    const header: frame.Header = .parse(pair.server.out.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.window_update, header.frame_type);
    try testing.expectEqual(@as(u31, 1), header.stream_id);
    const increment = try frame.parseWindowUpdate(
        pair.server.out.readableSlice()[frame.header_len..][0..4],
    );
    try testing.expectEqual(@as(u31, 600), increment);
    try testing.expectEqual(@as(i64, 1_000), pair.server.registry.get(1).?.recv_window.available);
}

test "connection: Rapid Reset trips the rate limit and ends the connection" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{
        .max_concurrent_streams = 100,
        .resets = .{ .max_per_window = 4, .window_ns = std.time.ns_per_s },
    });
    defer pair.deinit();
    _ = try pair.settle();

    // Open, reset, repeat. The concurrency limit never engages, because §5.1.2
    // stops counting a stream the moment it is reset.
    var id: u31 = 1;
    for (0..4) |_| {
        try pair.client.sendHeaders(gpa, id, &.{.{ .name = ":path", .value = "/x" }}, false);
        try pair.client.sendReset(gpa, id, .cancel);
        try pair.transfer();
        _ = (try pair.pollServer()).?;
        _ = (try pair.pollServer()).?;
        id += 2;
    }
    try testing.expectEqual(@as(u32, 0), pair.server.registry.concurrentCount());

    try pair.client.sendHeaders(gpa, id, &.{.{ .name = ":path", .value = "/x" }}, false);
    try pair.client.sendReset(gpa, id, .cancel);
    try pair.transfer();
    _ = (try pair.pollServer()).?;
    try testing.expectError(error.ConnectionError, pair.pollServer());

    const bye = frame.parseGoaway(pair.server.out.readableSlice()[frame.header_len..]);
    try testing.expectEqual(frame.ErrorCode.enhance_your_calm, bye.error_code);
    // §6.8: the peer is told how far we got, so it knows what it may retry.
    try testing.expectEqual(id, bye.last_stream_id);
}

test "connection: PING and SETTINGS floods are bounded because each owes a reply" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{
        .control_frames = .{ .max_per_window = 6, .window_ns = std.time.ns_per_s },
    });
    defer pair.deinit();
    // The handshake itself spends one, which is the honest accounting.
    _ = try pair.settle();

    var sent: usize = 0;
    while (sent < 20) : (sent += 1) {
        try pair.client.sendPing(gpa, @splat(0));
    }
    try pair.transfer();

    // One `poll` chews through as many frames as it can, because a PING produces
    // no application event — so this is a single call that ends in an error, not a
    // sequence of calls. What is worth asserting is the shape: some pings were
    // answered, and then the flood was stopped rather than answered for ever.
    try testing.expectError(error.ConnectionError, pair.pollServer());

    var acks: usize = 0;
    var goaways: usize = 0;
    var goaway_code: frame.ErrorCode = .no_error;
    var reader = pair.server.out;
    while (reader.readableLen() >= frame.header_len) {
        const head = reader.readBytes(frame.header_len) catch unreachable;
        const header: frame.Header = .parse(head[0..frame.header_len]);
        const payload = reader.readBytes(header.length) catch unreachable;
        switch (header.frame_type) {
            .ping => if (header.flags.isAck()) {
                acks += 1;
            },
            .goaway => {
                goaways += 1;
                goaway_code = frame.parseGoaway(payload).error_code;
            },
            else => {},
        }
    }
    try testing.expect(acks > 0);
    try testing.expect(acks < 20);
    try testing.expectEqual(@as(usize, 1), goaways);
    try testing.expectEqual(frame.ErrorCode.enhance_your_calm, goaway_code);
}

test "connection: an empty DATA flood is bounded even though it costs no memory" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{
        .idle_frames = .{ .max_per_window = 3, .window_ns = std.time.ns_per_s },
    });
    defer pair.deinit();
    _ = try pair.settle();

    try pair.client.sendHeaders(gpa, 1, &.{.{ .name = ":path", .value = "/x" }}, false);
    try pair.transfer();
    _ = (try pair.pollServer()).?;

    // Zero-length DATA without END_STREAM advances nothing and allocates nothing,
    // so only a rate limit sees it.
    for (0..8) |_| {
        try frame.writeFrame(&pair.to_server, gpa, .data, .{}, 1, "");
    }
    var delivered: usize = 0;
    while (delivered < 8) : (delivered += 1) {
        if (pair.pollServer()) |_| {} else |err| {
            try testing.expectEqual(error.ConnectionError, err);
            break;
        }
    }
    try testing.expect(delivered < 8);
}

test "connection: §5.1.2 refuses an over-limit stream without harming the others" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{ .max_concurrent_streams = 2 });
    defer pair.deinit();
    _ = try pair.settle();

    for ([_]u31{ 1, 3 }) |id| {
        try pair.client.sendHeaders(gpa, id, &.{.{ .name = ":path", .value = "/x" }}, false);
        try pair.transfer();
        _ = (try pair.pollServer()).?;
    }

    // §5.1.2 binds the sender too, so a well-behaved client refuses before the
    // frame is even built. That is not the server's enforcement being tested — it
    // is the reason the server's enforcement needs a peer that ignores the limit.
    try testing.expectError(
        error.RefusedStream,
        pair.client.sendHeaders(gpa, 5, &.{.{ .name = ":path", .value = "/x" }}, false),
    );

    // So write the frame by hand, as a peer that does not care would.
    pair.server.out.clear();
    try frame.writeFrame(
        &pair.to_server,
        gpa,
        .headers,
        .{ .bits = frame.Flags.end_headers },
        5,
        "\x82",
    );
    try testing.expect(try pair.pollServer() == null);
    try testing.expectEqual(Connection.State.open, pair.server.state);

    const header: frame.Header = .parse(pair.server.out.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.rst_stream, header.frame_type);
    // REFUSED_STREAM specifically: the request was not acted on and may be retried.
    try testing.expectEqual(
        frame.ErrorCode.refused_stream,
        frame.parseRstStream(pair.server.out.readableSlice()[frame.header_len..][0..4]),
    );
}

test "connection: a header block too large for one frame becomes CONTINUATION" {
    const gpa = testing.allocator;
    const roomy: Options = .{
        .hpack = .{ .max_string_len = 64 * 1024, .max_header_list_size = 128 * 1024 },
        .headers = .{ .max_block_size = 64 * 1024 },
    };
    var pair: Pair = try .init(gpa, roomy, roomy);
    defer pair.deinit();
    _ = try pair.settle();

    // §6.5.2 puts the floor for max_frame_size at 16 KiB, so exceeding one frame
    // takes a header value larger than that even after Huffman.
    const long: [24 * 1024]u8 = @splat('x');
    try pair.client.sendHeaders(gpa, 1, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/big" },
        .{ .name = "x-long", .value = &long },
    }, true);

    // Count what went out: §6.10 requires the pieces be adjacent, which they are
    // because they were written back to back.
    var kinds: std.ArrayList(frame.FrameType) = .empty;
    defer kinds.deinit(gpa);
    var reader = pair.client.out;
    while (reader.readableLen() >= frame.header_len) {
        const head = reader.readBytes(frame.header_len) catch unreachable;
        const header: frame.Header = .parse(head[0..frame.header_len]);
        _ = reader.readBytes(header.length) catch unreachable;
        try kinds.append(gpa, header.frame_type);
    }
    try testing.expect(kinds.items.len >= 2);
    try testing.expectEqual(frame.FrameType.headers, kinds.items[0]);
    for (kinds.items[1..]) |kind| try testing.expectEqual(frame.FrameType.continuation, kind);

    // And it reassembles to the same header list on the far side.
    try pair.transfer();
    const request = (try pair.pollServer()).?;
    try expectField(fieldsOf(request), ":path", "/big");
    for (fieldsOf(request)) |field| {
        if (std.mem.eql(u8, field.name, "x-long")) {
            try testing.expectEqual(long.len, field.value.len);
            try testing.expectEqualStrings(&long, field.value);
        }
    }
}

/// Appends a formatted line. `std.ArrayList` grew no `writer` in 0.17, and the
/// lines here are short and known.
fn logPrint(
    log: *std.ArrayList(u8),
    gpa: Allocator,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    var scratch: [1024]u8 = undefined;
    try log.appendSlice(gpa, try std.fmt.bufPrint(&scratch, fmt, args));
}

/// Records what a server made of a byte stream, so two feedings can be compared.
fn transcribe(gpa: Allocator, bytes: []const u8, fragment: usize) !std.ArrayList(u8) {
    var log: std.ArrayList(u8) = .empty;
    errdefer log.deinit(gpa);

    var server: Connection = .init(gpa, .server, .{});
    defer server.deinit(gpa);
    try server.start(gpa);
    server.out.clear();

    var input: Buffer = .empty;
    defer input.deinit(gpa);

    var offset: usize = 0;
    while (offset < bytes.len) {
        const take = @min(fragment, bytes.len - offset);
        try input.writeBytes(gpa, bytes[offset..][0..take]);
        offset += take;

        while (true) {
            const event = server.poll(gpa, &input, 0) catch |err| {
                try logPrint(&log, gpa, "ERR {s}\n", .{@errorName(err)});
                return log;
            } orelse break;
            switch (event) {
                .headers => |h| {
                    try logPrint(&log, gpa, "HEADERS {d} end={} trailers={}\n", .{
                        h.stream_id, h.end_stream, h.trailers,
                    });
                    for (h.fields) |field| {
                        try logPrint(&log, gpa, "  {s}: {s}\n", .{ field.name, field.value });
                    }
                },
                .data => |d| try logPrint(&log, gpa, "DATA {d} {d} end={}\n", .{
                    d.stream_id, d.bytes.len, d.end_stream,
                }),
                .reset => |r| try logPrint(&log, gpa, "RESET {d} {s}\n", .{
                    r.stream_id, r.code.name(),
                }),
                .goaway => |g| try logPrint(&log, gpa, "GOAWAY {d} {s}\n", .{
                    g.last_stream_id, g.code.name(),
                }),
                .settings_updated => try log.appendSlice(gpa, "SETTINGS\n"),
                .pong => try log.appendSlice(gpa, "PONG\n"),
                .push_promise => try log.appendSlice(gpa, "PUSH\n"),
            }
        }
    }
    return log;
}

test "connection: the same bytes decode the same however they are fragmented" {
    const gpa = testing.allocator;

    // A whole client conversation, built by a real client so the bytes are ones a
    // peer would actually send.
    var bytes: Buffer = .empty;
    defer bytes.deinit(gpa);
    {
        var client: Connection = .init(gpa, .client, .{});
        defer client.deinit(gpa);
        try client.start(gpa);
        try client.sendHeaders(gpa, 1, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/submit" },
            .{ .name = ":authority", .value = "example.test" },
            .{ .name = "content-type", .value = "application/json" },
        }, false);
        var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
        _ = try client.sendData(gpa, 1, "{\"a\":1}", false);
        _ = try client.flush(gpa, &transitions);
        try client.sendHeaders(gpa, 1, &.{.{ .name = "x-sum", .value = "9" }}, true);
        try client.sendHeaders(gpa, 3, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/other" },
        }, true);
        try client.sendPing(gpa, .{ 1, 2, 3, 4, 5, 6, 7, 8 });
        try client.sendReset(gpa, 3, .cancel);
        try bytes.writeBytes(gpa, client.out.readableSlice());
    }

    // This is the invariant that has found more real defects in this codebase than
    // any other: a stream decoder must produce identical output whether its bytes
    // arrive in one read or in arbitrary fragments. HTTP/2 has three nested places
    // to get it wrong — the frame boundary, the header block, and the connection
    // preface — and a socket delivers no respect for any of them.
    var whole = try transcribe(gpa, bytes.readableSlice(), bytes.readableLen());
    defer whole.deinit(gpa);
    try testing.expect(whole.items.len > 0);

    for ([_]usize{ 1, 2, 3, 5, 7, 8, 9, 13, 16, 17, 64, 100 }) |fragment| {
        var split = try transcribe(gpa, bytes.readableSlice(), fragment);
        defer split.deinit(gpa);
        testing.expectEqualStrings(whole.items, split.items) catch |err| {
            std.debug.print("fragment size {d} diverged\n", .{fragment});
            return err;
        };
    }
}

test "connection: a response with no body still ends its stream" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    try pair.client.sendHeaders(gpa, 1, &.{.{ .name = ":path", .value = "/empty" }}, true);
    try pair.transfer();
    _ = (try pair.pollServer()).?;

    // Headers, then nothing but END_STREAM. An empty DATA frame is not waiting for
    // credit — §6.9 charges the payload and this one has none — so it must not go
    // through the scheduler, which skips anything with nothing pending.
    var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
    try pair.server.sendHeaders(gpa, 1, &.{.{ .name = ":status", .value = "204" }}, false);
    _ = try pair.server.sendData(gpa, 1, "", true);
    _ = try pair.server.flush(gpa, &transitions);
    try pair.transfer();

    const response = (try pair.pollClient()).?;
    try testing.expect(!response.headers.end_stream);
    const end = (try pair.pollClient()).?;
    try testing.expectEqual(@as(usize, 0), end.data.bytes.len);
    // Without this the peer waits for ever for a stream that will never close.
    try testing.expect(end.data.end_stream);
    try testing.expect(pair.server.registry.get(1) == null);
    try testing.expect(pair.client.registry.get(1) == null);
}

// ── CONNECT tunnels (§8.5) ────────────────────────────────────────────────────

test "connection: §8.5 a CONNECT tunnel carries DATA and nothing else" {
    // §8.5: "Frame types other than DATA or stream management frames (RST_STREAM,
    // WINDOW_UPDATE, and PRIORITY) MUST NOT be sent on a connected stream and MUST
    // be treated as a stream error if received." The shape of a CONNECT request was
    // already checked (semantics.zig); which frames may follow it was not, so a
    // tunnel accepted trailers like any other exchange — field semantics inserted
    // into a byte stream a proxy relays verbatim.
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    const id = pair.client.nextStreamId();
    // §8.5: authority and nothing else, and the stream stays open.
    try pair.client.sendHeaders(gpa, id, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    }, false);
    try pair.transfer();

    const request = (try pair.pollServer()).?;
    try expectField(fieldsOf(request), ":method", "CONNECT");
    try testing.expect(pair.server.registry.get(id).?.tunnel);

    // Tunnel bytes are what the stream is for.
    var transitions: [Connection.max_writability_transitions]Connection.Writability = undefined;
    _ = try pair.client.sendData(gpa, id, "tunnelled", false);
    _ = try pair.client.flush(gpa, &transitions);
    try pair.transfer();
    const body = (try pair.pollServer()).?;
    try testing.expect(body == .data);
    try testing.expect(pair.server.out.readableLen() == 0);

    // A HEADERS frame is not, even one that ends the stream — which is exactly the
    // shape §8.1 would otherwise accept as a trailer section.
    try pair.client.sendHeaders(gpa, id, &.{
        .{ .name = "x-late", .value = "1" },
    }, true);
    try pair.transfer();
    _ = try pair.pollServer();

    // The server answered with RST_STREAM(PROTOCOL_ERROR) rather than closing the
    // connection: §8.5 makes this a stream error, unlike RFC 9114 §4.4.
    const header: frame.Header = .parse(pair.server.out.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.rst_stream, header.frame_type);
    const code = std.mem.readInt(u32, pair.server.out.readableSlice()[frame.header_len..][0..4], .big);
    try testing.expectEqual(@backingInt(frame.ErrorCode.protocol_error), code);
}

test "connection: §8.5 a refused CONNECT is an ordinary exchange" {
    // The 2xx is what §8.5 makes the signal that a tunnel is open. A refusal is an
    // ordinary response, and treating it as a tunnel would reject the trailers any
    // response may carry.
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    const id = pair.client.nextStreamId();
    try pair.client.sendHeaders(gpa, id, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    }, false);
    try pair.transfer();
    _ = try pair.pollServer();
    try testing.expect(pair.client.registry.get(id).?.sent_connect);

    // The proxy declines.
    try pair.server.sendHeaders(gpa, id, &.{
        .{ .name = ":status", .value = "502" },
    }, false);
    try pair.transfer();
    _ = try pair.pollClient();
    try testing.expect(!pair.client.registry.get(id).?.tunnel);

    // So trailers on it are still legal, and the client does not reset the stream.
    try pair.server.sendHeaders(gpa, id, &.{
        .{ .name = "x-reason", .value = "refused" },
    }, true);
    try pair.transfer();
    const trailers = (try pair.pollClient()).?;
    try testing.expect(trailers.headers.trailers);
    try testing.expect(pair.client.out.readableLen() == 0);
}

test "connection: §8.5 a 2xx to CONNECT makes the client's stream a tunnel" {
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{}, .{});
    defer pair.deinit();
    _ = try pair.settle();

    const id = pair.client.nextStreamId();
    try pair.client.sendHeaders(gpa, id, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    }, false);
    try pair.transfer();
    _ = try pair.pollServer();

    try pair.server.sendHeaders(gpa, id, &.{
        .{ .name = ":status", .value = "200" },
    }, false);
    try pair.transfer();
    _ = try pair.pollClient();
    try testing.expect(pair.client.registry.get(id).?.tunnel);

    // Now a HEADERS frame from the proxy is a stream error.
    try pair.server.sendHeaders(gpa, id, &.{
        .{ .name = "x-late", .value = "1" },
    }, true);
    try pair.transfer();
    _ = try pair.pollClient();
    const header: frame.Header = .parse(pair.client.out.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.rst_stream, header.frame_type);
}

test "connection: §8.5 no PUSH_PROMISE on a connected stream" {
    // §8.5 lists what may be sent on a connected stream, and PUSH_PROMISE is not in
    // it. Reached only when pushes are enabled, since a client that refuses them
    // rejects the frame earlier (§8.4) — so this is the case where the tunnel rule is
    // the thing standing between a peer and a stream reserved off a tunnel.
    const gpa = testing.allocator;
    var pair: Pair = try .init(gpa, .{ .enable_push = true }, .{});
    defer pair.deinit();
    _ = try pair.settle();

    const id = pair.client.nextStreamId();
    try pair.client.sendHeaders(gpa, id, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    }, false);
    try pair.transfer();
    _ = try pair.pollServer();
    try pair.server.sendHeaders(gpa, id, &.{.{ .name = ":status", .value = "200" }}, false);
    try pair.transfer();
    _ = try pair.pollClient();
    try testing.expect(pair.client.registry.get(id).?.tunnel);
    pair.client.out.clear();

    // A push promised off the tunnel stream. Hand-built because nothing here sends
    // pushes — the decision not to is in HTTP2.md.
    var block: Buffer = .empty;
    defer block.deinit(gpa);
    try pair.server.encoder.encode(&block, gpa, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/pushed" },
        .{ .name = ":authority", .value = "example.test" },
    });
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);
    var promised: [4]u8 = undefined;
    std.mem.writeInt(u32, &promised, 2, .big); // a server-initiated identifier
    try payload.appendSlice(gpa, &promised);
    try payload.appendSlice(gpa, block.readableSlice());
    try frame.writeFrame(
        &pair.to_client,
        gpa,
        .push_promise,
        .{ .bits = frame.Flags.end_headers },
        id,
        payload.items,
    );

    const event = try pair.pollClient();
    try testing.expect(event == null); // not delivered to the application
    const header: frame.Header = .parse(pair.client.out.readableSlice()[0..frame.header_len]);
    try testing.expectEqual(frame.FrameType.rst_stream, header.frame_type);
}

test "connection: §6.5.2 a client refuses SETTINGS_ENABLE_PUSH from a server" {
    // Push travels server to client, so the setting that permits it is a *client's* to
    // send: "A client MUST treat receipt of a SETTINGS frame with SETTINGS_ENABLE_PUSH
    // set to a value other than 0 as a connection error", and §8.4 leaves a server no
    // reason to send 0 either — it would be describing a capability it does not have.
    const gpa = testing.allocator;
    var client: Connection = .init(gpa, .client, .{});
    defer client.deinit(gpa);
    try client.start(gpa);

    var input: Buffer = .empty;
    defer input.deinit(gpa);
    try frame.writeSettings(&input, gpa, &.{.{ .id = .enable_push, .value = 1 }});
    try testing.expectError(error.ConnectionError, client.poll(gpa, &input, 0));
    try testing.expect(client.goaway_sent);
}

test "connection: §6.5.2 a server still accepts SETTINGS_ENABLE_PUSH from a client" {
    // The other half, so this is a rule about direction rather than a blanket ban: a
    // client saying it will not accept pushes is ordinary, and this endpoint declines to
    // push anyway.
    const gpa = testing.allocator;
    var server: Connection = .init(gpa, .server, .{});
    defer server.deinit(gpa);
    try server.start(gpa);

    var input: Buffer = .empty;
    defer input.deinit(gpa);
    try input.writeBytes(gpa, frame.client_preface);
    try frame.writeSettings(&input, gpa, &.{.{ .id = .enable_push, .value = 0 }});
    _ = try server.poll(gpa, &input, 0);
    try testing.expect(!server.remote_settings.enable_push);
    try testing.expect(!server.goaway_sent);
}
