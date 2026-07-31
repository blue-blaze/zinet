//! The HTTP/3 connection: RFC 9114's semantics on top of `codec/quic`.
//!
//! Client-side, because the QUIC underneath is client-side (a QUIC server
//! needs a `CertificateVerify` signature, and the standard library can verify
//! RSA signatures but not produce them — the README's blocked-upstream list
//! has the details). The shape matches `quic.Connection`: datagrams in,
//! events out, no sockets, injected time and allocator. This layer owns what
//! HTTP adds to QUIC:
//!
//! * the three unidirectional streams each side must open (control, QPACK
//!   encoder, QPACK decoder), and the policing of the peer's three;
//! * SETTINGS: first frame on the control stream or H3_MISSING_SETTINGS;
//! * the request stream's frame grammar (§4.1): HEADERS, then DATA, then at
//!   most one trailing HEADERS;
//! * field validation (§4.3): pseudo-fields first, response's `:status`,
//!   and the connection-specific headers HTTP/3 banishes (§4.2);
//! * server push, refused by never inviting it: this client never sends
//!   MAX_PUSH_ID, so §4.6 makes every push ID the server could use an
//!   H3_ID_ERROR.
//!
//! Events carry stream IDs, never slices — borrowed-buffer events have caused
//! two real defects in this repository, and the rule holds here too. Decoded
//! sections are taken with `takeSection`, body bytes with `readBody`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const quic = @import("../quic.zig");
const frame = @import("frame.zig");
const qpack = @import("qpack.zig");

pub const Error = error{
    /// The peer broke an HTTP/3 rule; the wire code to close with is in
    /// `errorCode`. One error per registry entry would force every caller
    /// through a giant switch; the code is what the peer needs, and it is
    /// preserved in `close_code`.
    H3Error,
} || quic.connection.Error || frame.Error || qpack.Error;

/// What this connection reports upward. IDs only — see the module comment.
pub const Event = union(enum) {
    /// The QUIC and HTTP/3 layers are both up: SETTINGS sent, streams open.
    established,
    /// A field section arrived on `stream`; `takeSection` yields it.
    /// `fin` says the stream ended with it.
    headers: struct { stream: u64, fin: bool },
    /// Body bytes arrived on `stream`; `readBody`/`consumeBody` access them.
    body: struct { stream: u64, fin: bool },
    /// §5.2: the server is shutting down; requests on streams at or above
    /// `id` were not processed and are safe to retry elsewhere.
    goaway: struct { id: u64 },
    /// The peer closed the connection (either layer's mechanism).
    peer_closed: struct { code: u64, application: bool },
    /// The transport idled out (§10.1 of RFC 9000), silently.
    idle_timeout,
};

/// One request stream's receive state: §4.1's grammar as a state machine, so
/// what is accepted is visible in one place.
const RequestState = enum {
    /// Nothing yet; only HEADERS (or ignorable unknown frames) may come.
    awaiting_headers,
    /// The response header section arrived; DATA or trailers may follow.
    /// (Interim 1xx responses mean *another* HEADERS is also legal here.)
    headers_received,
    /// A second HEADERS after DATA: trailers. Nothing may follow (§4.1).
    trailers_received,
};

const Request = struct {
    parser: frame.Parser = .{},
    state: RequestState = .awaiting_headers,
    /// Whether any DATA frame has arrived, which is what turns the next
    /// HEADERS into trailers.
    saw_data: bool = false,
    /// Decoded sections in arrival order, waiting for `takeSection`.
    sections: std.ArrayList(qpack.FieldSection) = .empty,
    /// Body bytes waiting for the application.
    body: std.ArrayList(u8) = .empty,
    fin_seen: bool = false,

    fn deinit(self: *Request, gpa: Allocator) void {
        self.parser.deinit(gpa);
        for (self.sections.items) |*section| section.deinit(gpa);
        self.sections.deinit(gpa);
        self.body.deinit(gpa);
    }
};

/// A unidirectional stream from the peer whose type varint has not fully
/// arrived yet (it can split across packets like anything else).
const PendingUni = struct {
    id: u64,
};

pub const Options = struct {
    host: []const u8,
    /// QUIC transport parameters. The HTTP/3-level settings ride separately
    /// in the SETTINGS frame.
    parameters: quic.transport.Parameters = .client_defaults,
    verification: ?quic.verify.Options = null,
    local_cid: quic.packet.ConnectionId,
    initial_destination: quic.packet.ConnectionId,
    token: []const u8 = &.{},
    /// Our SETTINGS_MAX_FIELD_SECTION_SIZE: the largest decoded field section
    /// we will accept (RFC 9114 §4.2.2).
    max_field_section_size: u64 = 64 * 1024,
};

pub const Connection = struct {
    transport: quic.connection.Connection,
    max_field_section_size: u64,

    // Our three unidirectional streams, opened once QUIC is established.
    control_out: ?u64 = null,
    qpack_encoder_out: ?u64 = null,
    qpack_decoder_out: ?u64 = null,

    // The peer's three, learned from the type varint on each incoming
    // unidirectional stream. §6.2.1/RFC 9204 §4.2: at most one of each —
    // a second is H3_STREAM_CREATION_ERROR.
    control_in: ?u64 = null,
    qpack_encoder_in: ?u64 = null,
    qpack_decoder_in: ?u64 = null,

    control_parser: frame.Parser = .{},
    /// §6.2.1: the first frame on the control stream must be SETTINGS.
    peer_settings: ?frame.Settings = null,
    /// §5.2: GOAWAY IDs may only decrease; recorded to enforce it.
    goaway_id: ?u64 = null,

    /// Request streams by ID.
    requests: std.AutoHashMapUnmanaged(u64, Request) = .empty,
    /// Peer unidirectional streams whose type is not yet known, or which are
    /// being deliberately ignored (unknown/grease types, §6.2.4).
    ignored_uni: std.AutoHashMapUnmanaged(u64, void) = .empty,

    events: std.ArrayList(Event) = .empty,
    event_cursor: usize = 0,
    /// Set once the H3 layer is up (streams opened, SETTINGS queued).
    h3_ready: bool = false,
    /// The H3_* code this endpoint closed with, if it closed. What `Error.H3Error`
    /// points at.
    close_code: ?u64 = null,

    pub fn init(options: Options, seed: [64]u8) !Connection {
        return .{
            .transport = try quic.connection.Connection.initClient(.{
                .host = options.host,
                // §3.1: the ALPN token for HTTP/3 is "h3". Not the caller's to
                // choose: a connection speaking this layer's frames under a
                // different token would be lying to the peer about what it is.
                .alpn = &.{"h3"},
                .parameters = options.parameters,
                .verification = options.verification,
                .local_cid = options.local_cid,
                .initial_destination = options.initial_destination,
                .token = options.token,
            }, seed),
            .max_field_section_size = options.max_field_section_size,
        };
    }

    pub fn deinit(self: *Connection, gpa: Allocator) void {
        var it = self.requests.valueIterator();
        while (it.next()) |req| req.deinit(gpa);
        self.requests.deinit(gpa);
        self.ignored_uni.deinit(gpa);
        self.control_parser.deinit(gpa);
        self.events.deinit(gpa);
        self.transport.deinit(gpa);
        self.* = undefined;
    }

    pub fn start(self: *Connection, gpa: Allocator) !void {
        return self.transport.start(gpa);
    }

    pub fn setTime(self: *Connection, now_ns: u64) void {
        self.transport.setTime(now_ns);
    }

    pub fn nextTimeout(self: *const Connection) ?u64 {
        return self.transport.nextTimeout();
    }

    pub fn onTimeout(self: *Connection, gpa: Allocator, now_ns: u64) !void {
        return self.transport.onTimeout(gpa, now_ns);
    }

    pub fn nextEvent(self: *Connection) ?Event {
        if (self.event_cursor >= self.events.items.len) return null;
        const event = self.events.items[self.event_cursor];
        self.event_cursor += 1;
        return event;
    }

    pub fn send(self: *Connection, gpa: Allocator, dest: []u8) !usize {
        return self.transport.send(gpa, dest);
    }

    /// Feed one datagram, then translate whatever the transport surfaced.
    pub fn receive(self: *Connection, gpa: Allocator, datagram: []const u8) !void {
        self.transport.receive(gpa, datagram) catch |err| return err;
        try self.drainTransport(gpa);
    }

    /// Translate whatever the transport has surfaced without feeding it a
    /// datagram first — for callers (and tests) that drive the transport
    /// directly.
    pub fn poll(self: *Connection, gpa: Allocator) !void {
        return self.drainTransport(gpa);
    }

    fn drainTransport(self: *Connection, gpa: Allocator) !void {
        while (self.transport.nextEvent()) |event| {
            switch (event) {
                .established => try self.onEstablished(gpa),
                .stream_readable => |e| try self.onReadable(gpa, e.id, e.fin),
                .stream_reset => |e| {
                    // The peer abandoned a response. RFC 9204 §4.4.2 would have
                    // us emit a Stream Cancellation; with a zero-capacity table
                    // it releases nothing, and §2.2.2.2 lets us omit it.
                    if (self.requests.getPtr(e.id)) |req| {
                        req.fin_seen = true;
                    }
                },
                .peer_closed => |e| try self.events.append(gpa, .{
                    .peer_closed = .{ .code = e.code, .application = e.application },
                }),
                .idle_timeout => try self.events.append(gpa, .idle_timeout),
                .stateless_reset => try self.events.append(gpa, .{
                    .peer_closed = .{ .code = 0, .application = false },
                }),
                // Address tokens and Retry are transport bookkeeping the HTTP
                // layer has nothing to say about.
                .new_token, .retry_received, .stream_stop_sending => {},
            }
        }
    }

    /// QUIC is up: open our three unidirectional streams and send SETTINGS.
    /// §3.2/§6.2: each endpoint opens its control stream and sends SETTINGS as
    /// its first frame; RFC 9204 §4.2 adds the two QPACK streams. All three
    /// exist even though the QPACK ones will stay silent (zero table
    /// capacity): §4.2 requires the peer to *allow* them, and opening them
    /// keeps this endpoint symmetric with ones that do use the table.
    fn onEstablished(self: *Connection, gpa: Allocator) !void {
        assert(!self.h3_ready);

        const control = try self.transport.openStream(gpa, false);
        const encoder = try self.transport.openStream(gpa, false);
        const decoder = try self.transport.openStream(gpa, false);
        self.control_out = control;
        self.qpack_encoder_out = encoder;
        self.qpack_decoder_out = decoder;

        // Each unidirectional stream leads with its type varint (§6.2).
        var buf: [64]u8 = undefined;
        var len: usize = quic.varint.encode(&buf, @backingInt(frame.StreamType.control));
        // SETTINGS, the mandatory first frame (§6.2.1). We advertise our
        // field-section bound; QPACK capacity and blocked streams stay at
        // their defaults of zero by *omission* — §7.2.4.2 makes omitted and
        // default indistinguishable, so sending zeros would say nothing.
        len += frame.writeSettings(buf[len..], &.{
            .{ .id = frame.Setting.max_field_section_size, .value = self.max_field_section_size },
        });
        _ = try self.transport.write(gpa, control, buf[0..len]);

        var type_buf: [8]u8 = undefined;
        const enc_len = quic.varint.encode(&type_buf, @backingInt(frame.StreamType.qpack_encoder));
        _ = try self.transport.write(gpa, encoder, type_buf[0..enc_len]);
        const dec_len = quic.varint.encode(&type_buf, @backingInt(frame.StreamType.qpack_decoder));
        _ = try self.transport.write(gpa, decoder, type_buf[0..dec_len]);

        self.h3_ready = true;
        try self.events.append(gpa, .established);
    }

    // ── Sending requests ─────────────────────────────────────────────────────

    /// Open a request stream and send the header section. Returns the stream
    /// ID. `body` may follow via `writeBody`; `fin` here ends the request
    /// immediately (a GET).
    pub fn request(
        self: *Connection,
        gpa: Allocator,
        fields: []const qpack.FieldLine,
        fin: bool,
    ) !u64 {
        if (!self.h3_ready) return error.StreamStateError;
        // §5.2: once GOAWAY names an ID, requests at or above it would be
        // ignored; refusing locally is kinder than sending into a void.
        if (self.goaway_id != null) return error.StreamStateError;

        const id = try self.transport.openStream(gpa, true);

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(gpa);
        try qpack.encodeSection(gpa, &encoded, fields);

        var header: [16]u8 = undefined;
        const header_len = frame.writeFrameHeader(
            &header,
            @backingInt(frame.FrameType.headers),
            encoded.items.len,
        );
        _ = try self.transport.write(gpa, id, header[0..header_len]);
        _ = try self.transport.write(gpa, id, encoded.items);
        if (fin) try self.transport.finishStream(id);

        // Track it so the response has somewhere to land.
        try self.requests.put(gpa, id, .{});
        return id;
    }

    /// Send request body bytes as one DATA frame.
    pub fn writeBody(self: *Connection, gpa: Allocator, id: u64, bytes: []const u8, fin: bool) !void {
        var header: [16]u8 = undefined;
        const header_len = frame.writeFrameHeader(
            &header,
            @backingInt(frame.FrameType.data),
            bytes.len,
        );
        _ = try self.transport.write(gpa, id, header[0..header_len]);
        _ = try self.transport.write(gpa, id, bytes);
        if (fin) try self.transport.finishStream(id);
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// The oldest undelivered field section for `stream`, ownership passed to
    /// the caller.
    pub fn takeSection(self: *Connection, stream: u64) ?qpack.FieldSection {
        const req = self.requests.getPtr(stream) orelse return null;
        if (req.sections.items.len == 0) return null;
        return req.sections.orderedRemove(0);
    }

    pub fn readBody(self: *Connection, stream: u64) []const u8 {
        const req = self.requests.getPtr(stream) orelse return &.{};
        return req.body.items;
    }

    pub fn consumeBody(self: *Connection, stream: u64, n: usize) void {
        const req = self.requests.getPtr(stream) orelse return;
        assert(n <= req.body.items.len);
        const rest = req.body.items.len - n;
        std.mem.copyForwards(u8, req.body.items[0..rest], req.body.items[n..]);
        req.body.shrinkRetainingCapacity(rest);
    }

    fn onReadable(self: *Connection, gpa: Allocator, id: u64, fin: bool) !void {
        // §2.1 of RFC 9000: the two low bits type the stream. Client-initiated
        // bidirectional (0b00) are our requests; server-initiated
        // unidirectional (0b11) are control/QPACK/push; the other two do not
        // occur (we open no other bidi kinds, servers cannot open bidi toward
        // us in HTTP/3 — §6.1 gives server-initiated bidirectional streams no
        // meaning, and our transport parameters allow none).
        switch (id & 0x3) {
            0b00 => try self.onRequestData(gpa, id, fin),
            0b11 => try self.onUniData(gpa, id, fin),
            else => return self.fail(0x0101), // H3_GENERAL_PROTOCOL_ERROR
        }
    }

    fn onRequestData(self: *Connection, gpa: Allocator, id: u64, fin: bool) !void {
        const req = self.requests.getPtr(id) orelse return; // reset or unknown
        if (fin) req.fin_seen = true;

        while (true) {
            const bytes = self.transport.read(id);
            if (bytes.len == 0) break;
            const parse_result = req.parser.next(gpa, bytes) catch |err| return self.failFrame(err);
            const result = parse_result orelse {
                self.transport.consume(gpa, id, bytes.len);
                break;
            };
            // The item is handled *before* the bytes are consumed, because it
            // borrows from them: `consume` compacts the reassembly buffer, and
            // a payload used after that points into moved memory. This is the
            // borrowed-buffer defect class this repository has now hit three
            // times (HTTP/2 header values, the negotiated ALPN, and here), and
            // as before it was a test that caught it, not a review.
            defer self.transport.consume(gpa, id, result.consumed);

            // Whether the stream is finished *after* this item: the FIN has
            // been seen and nothing remains beyond what this item consumed.
            // `read(id)` cannot answer that here — the consume above is
            // deferred, so the buffer still contains this item's own bytes.
            const stream_done = req.fin_seen and bytes.len == result.consumed;

            switch (result.item) {
                .frame => |f| try self.onRequestFrame(gpa, id, req, f, stream_done),
                .body_chunk => |chunk| {
                    // §4.1: DATA before HEADERS is H3_FRAME_UNEXPECTED. The
                    // parser cannot know — order is semantics, not framing.
                    if (req.state == .awaiting_headers) return self.fail(0x0105);
                    if (req.state == .trailers_received) return self.fail(0x0105);
                    req.saw_data = true;
                    try req.body.appendSlice(gpa, chunk.bytes);
                    if (chunk.last) {
                        try self.events.append(gpa, .{ .body = .{
                            .stream = id,
                            .fin = stream_done,
                        } });
                    }
                },
            }
        }
    }

    fn onRequestFrame(
        self: *Connection,
        gpa: Allocator,
        id: u64,
        req: *Request,
        f: frame.Frame,
        stream_done: bool,
    ) !void {
        switch (f) {
            .headers => |section_bytes| {
                if (req.state == .trailers_received) return self.fail(0x0105);

                var section = qpack.decodeSection(gpa, section_bytes, .{
                    .max_field_section_size = self.max_field_section_size,
                }) catch |err| return self.failQpack(err);
                errdefer section.deinit(gpa);

                const is_trailers = req.saw_data;
                if (!validResponseSection(&section, is_trailers)) {
                    // The errdefer above frees the section — `fail` returns an
                    // error, so freeing here too would be a double deinit on
                    // poisoned memory (and was, briefly).
                    return self.fail(0x010e); // H3_MESSAGE_ERROR
                }

                if (is_trailers) {
                    req.state = .trailers_received;
                } else {
                    req.state = .headers_received;
                }
                try req.sections.append(gpa, section);
                try self.events.append(gpa, .{ .headers = .{
                    .stream = id,
                    .fin = stream_done,
                } });
            },
            // §7.2.5: PUSH_PROMISE references a push ID, and this client never
            // sent MAX_PUSH_ID, so no push ID is small enough (§4.6).
            .push_promise => return self.fail(0x0108), // H3_ID_ERROR
            // §7.2: control-stream frames on a request stream.
            .settings, .goaway, .cancel_push, .max_push_id => return self.fail(0x0105),
            .unknown => {}, // §9: ignore
            .data => unreachable, // delivered as body_chunk
        }
    }

    fn onUniData(self: *Connection, gpa: Allocator, id: u64, fin: bool) !void {
        _ = fin;
        // A stream being ignored: discard whatever arrives (§6.2.4 — data on
        // an unknown stream type is not an error, it is just not read).
        if (self.ignored_uni.contains(id)) {
            const junk = self.transport.read(id);
            self.transport.consume(gpa, id, junk.len);
            return;
        }

        // Classify the stream if this is its first data.
        if (!matches(self.control_in, id) and !matches(self.qpack_encoder_in, id) and
            !matches(self.qpack_decoder_in, id))
        {
            const bytes = self.transport.read(id);
            if (bytes.len == 0) return;
            var rest: []const u8 = bytes;
            const need = quic.varint.peekLen(bytes[0]);
            if (bytes.len < need) return; // type varint still split; wait
            const stream_type = quic.varint.take(&rest) catch unreachable;
            self.transport.consume(gpa, id, need);

            switch (stream_type) {
                @backingInt(frame.StreamType.control) => {
                    // §6.2.1: at most one control stream per peer. The second
                    // is not "extra capacity", it is a peer whose bookkeeping
                    // disagrees with ours about something as basic as which
                    // stream carries SETTINGS.
                    if (self.control_in != null) return self.fail(0x0104);
                    self.control_in = id;
                },
                @backingInt(frame.StreamType.qpack_encoder) => {
                    if (self.qpack_encoder_in != null) return self.fail(0x0104);
                    self.qpack_encoder_in = id;
                },
                @backingInt(frame.StreamType.qpack_decoder) => {
                    if (self.qpack_decoder_in != null) return self.fail(0x0104);
                    self.qpack_decoder_in = id;
                },
                @backingInt(frame.StreamType.push) => {
                    // §4.6: a push stream names a push ID, and we never raised
                    // MAX_PUSH_ID above its initial zero-allowance.
                    return self.fail(0x0108);
                },
                else => {
                    // §6.2.4: unknown types (grease included) are ignored, not
                    // errors. Remember the decision so later bytes are drained
                    // rather than re-classified.
                    try self.ignored_uni.put(gpa, id, {});
                    const junk = self.transport.read(id);
                    self.transport.consume(gpa, id, junk.len);
                    return;
                },
            }
        }

        if (matches(self.control_in, id)) return self.onControlData(gpa, id);
        if (matches(self.qpack_encoder_in, id)) {
            const bytes = self.transport.read(id);
            // RFC 9204 §3.2.3: we advertised zero table capacity, so the
            // peer's encoder stream must stay empty.
            qpack.onEncoderStreamData(bytes) catch |err| return self.failQpack(err);
            return;
        }
        if (matches(self.qpack_decoder_in, id)) {
            var bytes = self.transport.read(id);
            const before = bytes.len;
            while (true) {
                const instruction = qpack.parseDecoderInstruction(&bytes) catch |err|
                    return self.failQpack(err);
                const parsed = instruction orelse break;
                qpack.applyDecoderInstruction(parsed) catch |err| return self.failQpack(err);
            }
            self.transport.consume(gpa, id, before - bytes.len);
            return;
        }
    }

    fn onControlData(self: *Connection, gpa: Allocator, id: u64) !void {
        while (true) {
            const bytes = self.transport.read(id);
            if (bytes.len == 0) break;
            const result = self.control_parser.next(gpa, bytes) catch |err| {
                return self.failFrame(err);
            };
            const item = result orelse {
                self.transport.consume(gpa, id, bytes.len);
                break;
            };
            // Same borrowed-buffer rule as the request path: use, then consume.
            defer self.transport.consume(gpa, id, item.consumed);

            const f = switch (item.item) {
                .frame => |f| f,
                // DATA on the control stream (§7.2.1: request/push only).
                .body_chunk => return self.fail(0x0105),
            };

            // §6.2.1: SETTINGS first, exactly once. Unknown frames do not
            // count as "first" in the forgiving direction — a control stream
            // opening with grease then SETTINGS is fine (§9 says ignore means
            // ignore) — but any *known* frame before SETTINGS is
            // H3_MISSING_SETTINGS.
            if (self.peer_settings == null) {
                switch (f) {
                    .settings => |payload| {
                        var settings: frame.Settings = .{};
                        var it = frame.SettingsIterator.init(payload);
                        while (it.next() catch |err| return self.failFrame(err)) |setting| {
                            settings.apply(setting);
                        }
                        self.peer_settings = settings;
                        continue;
                    },
                    .unknown => continue,
                    else => return self.fail(0x010a), // H3_MISSING_SETTINGS
                }
            }

            switch (f) {
                // §7.2.4: a second SETTINGS anywhere is H3_FRAME_UNEXPECTED.
                .settings => return self.fail(0x0105),
                .goaway => |goaway_id| {
                    // §5.2: an ID that grows would un-reject requests the
                    // previous GOAWAY already disowned.
                    if (self.goaway_id) |previous| {
                        if (goaway_id > previous) return self.fail(0x0108);
                    }
                    self.goaway_id = goaway_id;
                    try self.events.append(gpa, .{ .goaway = .{ .id = goaway_id } });
                },
                // §7.2.3: CANCEL_PUSH names a push we never allowed.
                .cancel_push => return self.fail(0x0108),
                // §7.2.7: only the client sends MAX_PUSH_ID.
                .max_push_id => return self.fail(0x0105),
                .headers, .push_promise => return self.fail(0x0105),
                .unknown => {},
                .data => unreachable,
            }
        }
    }

    /// The peer's settings, once its SETTINGS frame has arrived.
    pub fn peerSettings(self: *const Connection) ?frame.Settings {
        return self.peer_settings;
    }

    /// Close the connection with an H3 application error code.
    fn fail(self: *Connection, code: u64) Error {
        self.close_code = code;
        self.transport.close(code, true);
        return error.H3Error;
    }

    fn failFrame(self: *Connection, err: frame.Error) Error {
        self.close_code = frame.errorCode(err);
        self.transport.close(self.close_code.?, true);
        return err;
    }

    fn failQpack(self: *Connection, err: qpack.Error) Error {
        self.close_code = qpack.errorCode(err);
        self.transport.close(self.close_code.?, true);
        return err;
    }
};

fn matches(maybe: ?u64, id: u64) bool {
    return maybe != null and maybe.? == id;
}

/// §4.3's rules for a *response* section, which is what a client receives.
/// A bool rather than an error, so the caller controls the wire code.
fn validResponseSection(section: *const qpack.FieldSection, is_trailers: bool) bool {
    var seen_regular = false;
    var seen_status = false;

    for (section.fields.items) |field| {
        if (field.name.len == 0) return false;
        if (field.name[0] == ':') {
            // §4.3: pseudo-fields come first — one after a regular field means
            // the sender's notion of the message shape differs from ours.
            if (seen_regular) return false;
            // §4.3.2: trailers carry no pseudo-fields at all.
            if (is_trailers) return false;
            // The only response pseudo-field is :status (§4.3.2); a request
            // pseudo-field in a response is a confusion of direction.
            if (!std.mem.eql(u8, field.name, ":status")) return false;
            if (seen_status) return false; // duplicates forbidden (§4.3)
            if (field.value.len != 3) return false;
            for (field.value) |c| {
                if (c < '0' or c > '9') return false;
            }
            seen_status = true;
            continue;
        }
        seen_regular = true;

        // §4.2: field names are lowercase in HTTP/3; an uppercase byte is
        // malformed rather than merely unusual.
        for (field.name) |c| {
            if (c >= 'A' and c <= 'Z') return false;
        }
        // §4.2: connection-specific fields do not exist in HTTP/3 — the
        // connection is QUIC's business. `te` is banned outright in responses
        // (only requests may carry it, and only as "trailers").
        for ([_][]const u8{
            "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te",
        }) |banned| {
            if (std.mem.eql(u8, field.name, banned)) return false;
        }
    }

    // §4.3.2: a non-interim response has exactly one :status; trailers none.
    if (!is_trailers and !seen_status) return false;
    return true;
}

/// Convenience for building the four request pseudo-fields plus extras, in
/// §4.3.1's required shape.
pub fn requestFields(
    method: []const u8,
    scheme: []const u8,
    authority: []const u8,
    path: []const u8,
    extra: []const qpack.FieldLine,
    buf: []qpack.FieldLine,
) []const qpack.FieldLine {
    assert(buf.len >= 4 + extra.len);
    buf[0] = .{ .name = ":method", .value = method };
    buf[1] = .{ .name = ":scheme", .value = scheme };
    buf[2] = .{ .name = ":authority", .value = authority };
    buf[3] = .{ .name = ":path", .value = path };
    for (extra, 0..) |field, i| buf[4 + i] = field;
    return buf[0 .. 4 + extra.len];
}

const testing = std.testing;
const quic_conn = quic.connection;

const H3Peer = struct {
    conn: Connection,
    peer: quic_conn.Established,
    client_cid: quic.packet.ConnectionId,
    /// The server's next unidirectional stream id (pattern 0b11).
    next_uni: u64 = 3,

    fn deinit(self: *H3Peer, gpa: Allocator) void {
        self.peer.deinit(gpa);
        self.conn.deinit(gpa);
    }

    /// Inject `stream_bytes` as a QUIC STREAM frame on `stream_id`.
    fn inject(self: *H3Peer, gpa: Allocator, stream_id: u64, offset: u64, bytes: []const u8, fin: bool) !void {
        var frames: [1200]u8 = undefined;
        const frames_len = quic.frame.encode(&frames, .{ .stream = .{
            .id = stream_id,
            .offset = offset,
            .data = bytes,
            .fin = fin,
            .had_length = true,
        } });
        var packet_buf: [1400]u8 = undefined;
        const packet_len = try self.peer.seal(&packet_buf, self.client_cid, frames[0..frames_len]);
        try self.conn.receive(gpa, packet_buf[0..packet_len]);
    }
};

fn establishH3(gpa: Allocator, seed_byte: u8) !H3Peer {
    const client_cid = quic.packet.ConnectionId.init(&.{ 0xe0, 0xe1, seed_byte }) catch unreachable;
    const server_cid = quic.packet.ConnectionId.init(&.{ 0x60, seed_byte }) catch unreachable;
    const initial_dcid = quic.packet.ConnectionId.init(
        &.{ 0x19, 0x29, 0x39, 0x49, 0x59, 0x69, 0x79, seed_byte },
    ) catch unreachable;

    var conn = try Connection.init(.{
        .host = "example.com",
        .verification = null, // the fixture cannot sign; see quic/connection.zig
        .local_cid = client_cid,
        .initial_destination = initial_dcid,
    }, @splat(seed_byte));
    errdefer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: quic.transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 256 * 1024,
        .initial_max_stream_data_uni = 64 * 1024,
        .initial_max_streams_bidi = 16,
        .initial_max_streams_uni = 8,
    };
    var peer = try quic_conn.establish(
        gpa,
        &conn.transport,
        client_cid,
        server_cid,
        initial_dcid,
        &server_params,
    );
    errdefer peer.deinit(gpa);

    // Surface the established event into the HTTP/3 layer: it opens the three
    // unidirectional streams and queues SETTINGS.
    try conn.poll(gpa);
    const first_event = conn.nextEvent().?;
    try testing.expectEqual(Event.established, first_event);

    return .{ .conn = conn, .peer = peer, .client_cid = client_cid };
}

test "http3: connecting opens the three streams and leads with SETTINGS" {
    // §3.2, §6.2, RFC 9204 §4.2: each endpoint opens a control stream whose
    // first frame is SETTINGS, plus the two QPACK streams. All of that must be
    // on the wire without waiting for a request — a server may not send *its*
    // SETTINGS until it sees ours, and two endpoints politely waiting for each
    // other is a hang that only happens against real peers.
    const gpa = testing.allocator;
    var h3 = try establishH3(gpa, 0x81);
    defer h3.deinit(gpa);

    var out: [quic_conn.max_datagram]u8 = undefined;
    const len = try h3.conn.send(gpa, &out);
    try testing.expect(len > 0);

    var plain: [quic_conn.max_datagram]u8 = undefined;
    var rest = try h3.peer.open(&plain, out[0..len]);
    // Collect the STREAM frames: three unidirectional streams (client uni
    // pattern 0b10: ids 2, 6, 10).
    var saw_control_payload: ?[]const u8 = null;
    var uni_count: usize = 0;
    while (rest.len > 0) {
        switch (try quic.frame.parse(&rest)) {
            .stream => |sf| {
                try testing.expectEqual(@as(u64, 0b10), sf.id & 0x3);
                uni_count += 1;
                if (sf.id == 2) saw_control_payload = sf.data;
            },
            else => {},
        }
    }
    try testing.expectEqual(@as(usize, 3), uni_count);

    // The control stream: type 0x00, then a SETTINGS frame carrying our
    // field-section bound.
    const control = saw_control_payload.?;
    try testing.expectEqual(@as(u8, 0x00), control[0]); // stream type
    try testing.expectEqual(@as(u8, 0x04), control[1]); // SETTINGS frame type
    const settings_view: []const u8 = control[3..]; // skip length byte
    var it = frame.SettingsIterator.init(settings_view);
    const setting = (try it.next()).?;
    try testing.expectEqual(@as(u64, frame.Setting.max_field_section_size), setting.id);
    try testing.expectEqual(@as(u64, 64 * 1024), setting.value);
}

test "http3: a request goes out and its response comes back, body and all" {
    const gpa = testing.allocator;
    var h3 = try establishH3(gpa, 0x82);
    defer h3.deinit(gpa);

    // Flush our control/QPACK streams.
    var out: [quic_conn.max_datagram]u8 = undefined;
    _ = try h3.conn.send(gpa, &out);

    // Send a GET.
    var field_buf: [8]qpack.FieldLine = undefined;
    const fields = requestFields("GET", "https", "example.com", "/thing", &.{}, &field_buf);
    const stream = try h3.conn.request(gpa, fields, true);
    try testing.expectEqual(@as(u64, 0), stream); // first client bidi stream

    const request_len = try h3.conn.send(gpa, &out);
    try testing.expect(request_len > 0);
    var plain: [quic_conn.max_datagram]u8 = undefined;
    var rest = try h3.peer.open(&plain, out[0..request_len]);
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(gpa);
    var fin_seen = false;
    while (rest.len > 0) {
        switch (try quic.frame.parse(&rest)) {
            .stream => |sf| if (sf.id == 0) {
                try request_bytes.appendSlice(gpa, sf.data);
                if (sf.fin) fin_seen = true;
            },
            else => {},
        }
    }
    try testing.expect(fin_seen);

    // The server decodes the request with its own QPACK decoder.
    var parser: frame.Parser = .{};
    defer parser.deinit(gpa);
    const parsed = (try parser.next(gpa, request_bytes.items)).?;
    var section = try qpack.decodeSection(gpa, parsed.item.frame.headers, .{});
    defer section.deinit(gpa);
    try testing.expectEqualStrings(":method", section.fields.items[0].name);
    try testing.expectEqualStrings("GET", section.fields.items[0].value);
    try testing.expectEqualStrings("/thing", section.fields.items[3].value);

    // The server responds: control stream first (type + SETTINGS), then the
    // response on stream 0 — HEADERS(:status 200, content-type) + DATA.
    var control_bytes: [64]u8 = undefined;
    var control_len: usize = quic.varint.encode(&control_bytes, 0x00);
    control_len += frame.writeSettings(control_bytes[control_len..], &.{});
    try h3.inject(gpa, h3.next_uni, 0, control_bytes[0..control_len], false);
    try testing.expect(h3.conn.peerSettings() != null);

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(gpa);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(gpa);
    try qpack.encodeSection(gpa, &encoded, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    });
    var header: [16]u8 = undefined;
    var header_len = frame.writeFrameHeader(&header, 0x01, encoded.items.len);
    try response.appendSlice(gpa, header[0..header_len]);
    try response.appendSlice(gpa, encoded.items);
    header_len = frame.writeFrameHeader(&header, 0x00, 5);
    try response.appendSlice(gpa, header[0..header_len]);
    try response.appendSlice(gpa, "hello");

    try h3.inject(gpa, 0, 0, response.items, true);

    // Events: headers then body, then the section and bytes are takeable.
    var saw_headers = false;
    var saw_body = false;
    while (h3.conn.nextEvent()) |event| {
        switch (event) {
            .headers => |e| {
                try testing.expectEqual(@as(u64, 0), e.stream);
                saw_headers = true;
            },
            .body => |e| {
                try testing.expectEqual(@as(u64, 0), e.stream);
                try testing.expect(e.fin);
                saw_body = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_headers);
    try testing.expect(saw_body);

    var got = h3.conn.takeSection(0).?;
    defer got.deinit(gpa);
    try testing.expectEqualStrings(":status", got.fields.items[0].name);
    try testing.expectEqualStrings("200", got.fields.items[0].value);
    try testing.expectEqualStrings("hello", h3.conn.readBody(0));
    h3.conn.consumeBody(0, 5);
    try testing.expectEqual(@as(usize, 0), h3.conn.readBody(0).len);
}

test "http3: the control stream's first frame must be SETTINGS, and only one control stream exists" {
    const gpa = testing.allocator;

    // A GOAWAY before SETTINGS: H3_MISSING_SETTINGS (§6.2.1). Grease frames do
    // not count — §9's ignore means ignore — but a *known* frame does.
    {
        var h3 = try establishH3(gpa, 0x83);
        defer h3.deinit(gpa);
        var bytes: [32]u8 = undefined;
        var len: usize = quic.varint.encode(&bytes, 0x00); // control stream type
        len += frame.writeFrameHeader(bytes[len..], 0x07, 1); // GOAWAY
        bytes[len] = 0;
        len += 1;
        try testing.expectError(error.H3Error, h3.inject(gpa, 3, 0, bytes[0..len], false));
        try testing.expectEqual(@as(?u64, 0x010a), h3.conn.close_code); // H3_MISSING_SETTINGS
    }

    // A second control stream: H3_STREAM_CREATION_ERROR (§6.2.1). The second
    // is not extra capacity — it is a peer whose bookkeeping disagrees with
    // ours about which stream carries SETTINGS.
    {
        var h3 = try establishH3(gpa, 0x84);
        defer h3.deinit(gpa);
        var bytes: [32]u8 = undefined;
        var len: usize = quic.varint.encode(&bytes, 0x00);
        len += frame.writeSettings(bytes[len..], &.{});
        try h3.inject(gpa, 3, 0, bytes[0..len], false);

        var second: [8]u8 = undefined;
        const second_len = quic.varint.encode(&second, 0x00);
        try testing.expectError(error.H3Error, h3.inject(gpa, 7, 0, second[0..second_len], false));
        try testing.expectEqual(@as(?u64, 0x0104), h3.conn.close_code);
    }

    // A second SETTINGS on the (single) control stream: H3_FRAME_UNEXPECTED.
    {
        var h3 = try establishH3(gpa, 0x85);
        defer h3.deinit(gpa);
        var bytes: [48]u8 = undefined;
        var len: usize = quic.varint.encode(&bytes, 0x00);
        len += frame.writeSettings(bytes[len..], &.{});
        const first_len = len;
        len += frame.writeSettings(bytes[len..], &.{});
        try testing.expectError(error.H3Error, h3.inject(gpa, 3, 0, bytes[0..len], false));
        try testing.expectEqual(@as(?u64, 0x0105), h3.conn.close_code);
        _ = first_len;
    }
}

test "http3: unknown unidirectional streams are ignored, push streams are refused" {
    const gpa = testing.allocator;
    var h3 = try establishH3(gpa, 0x86);
    defer h3.deinit(gpa);

    // A greased stream type: ignored entirely, along with everything sent on
    // it, now and later (§6.2.4). An endpoint that errors on it is what
    // greasing exists to catch.
    var bytes: [32]u8 = undefined;
    var len: usize = quic.varint.encode(&bytes, 0x21 + 0x1f * 2);
    @memcpy(bytes[len..][0..4], "junk");
    len += 4;
    try h3.inject(gpa, 3, 0, bytes[0..len], false);
    try h3.inject(gpa, 3, @intCast(len), "more junk later", false);
    try testing.expect(h3.conn.close_code == null);

    // A push stream (type 0x01): we never sent MAX_PUSH_ID, so no push ID is
    // permitted and the stream itself is H3_ID_ERROR (§4.6).
    var push: [8]u8 = undefined;
    const push_len = quic.varint.encode(&push, 0x01);
    try testing.expectError(error.H3Error, h3.inject(gpa, 7, 0, push[0..push_len], false));
    try testing.expectEqual(@as(?u64, 0x0108), h3.conn.close_code);
}

test "http3: the request stream grammar — DATA before HEADERS is an error, trailers end it" {
    const gpa = testing.allocator;

    // DATA first: §4.1 names it H3_FRAME_UNEXPECTED. The frame parser cannot
    // know — order is semantics — so the check lives in the connection.
    {
        var h3 = try establishH3(gpa, 0x87);
        defer h3.deinit(gpa);
        var out: [quic_conn.max_datagram]u8 = undefined;
        _ = try h3.conn.send(gpa, &out);
        var field_buf: [8]qpack.FieldLine = undefined;
        const fields = requestFields("GET", "https", "example.com", "/", &.{}, &field_buf);
        const stream = try h3.conn.request(gpa, fields, true);
        _ = try h3.conn.send(gpa, &out);

        var bytes: [16]u8 = undefined;
        var len = frame.writeFrameHeader(&bytes, 0x00, 3);
        @memcpy(bytes[len..][0..3], "早"); // any bytes
        len += 3;
        try testing.expectError(error.H3Error, h3.inject(gpa, stream, 0, bytes[0..len], false));
        try testing.expectEqual(@as(?u64, 0x0105), h3.conn.close_code);
    }

    // SETTINGS on a request stream: the classic HTTP/2 reflex (§7.2.4).
    {
        var h3 = try establishH3(gpa, 0x88);
        defer h3.deinit(gpa);
        var out: [quic_conn.max_datagram]u8 = undefined;
        _ = try h3.conn.send(gpa, &out);
        var field_buf: [8]qpack.FieldLine = undefined;
        const fields = requestFields("GET", "https", "example.com", "/", &.{}, &field_buf);
        const stream = try h3.conn.request(gpa, fields, true);
        _ = try h3.conn.send(gpa, &out);

        var bytes: [16]u8 = undefined;
        const len = frame.writeFrameHeader(&bytes, 0x04, 0);
        try testing.expectError(error.H3Error, h3.inject(gpa, stream, 0, bytes[0..len], false));
        try testing.expectEqual(@as(?u64, 0x0105), h3.conn.close_code);
    }
}

test "http3: response validation — :status is required and connection headers are banned" {
    const gpa = testing.allocator;

    const cases = [_]struct { fields: []const qpack.FieldLine, seed: u8 }{
        // No :status at all (§4.3.2).
        .{ .seed = 0x89, .fields = &.{.{ .name = "content-type", .value = "text/plain" }} },
        // A request pseudo-field in a response: direction confusion.
        .{ .seed = 0x8a, .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":status", .value = "200" },
        } },
        // Pseudo-field after a regular field (§4.3).
        .{ .seed = 0x8b, .fields = &.{
            .{ .name = "server", .value = "x" },
            .{ .name = ":status", .value = "200" },
        } },
        // Connection-specific header (§4.2): the connection is QUIC's business.
        .{ .seed = 0x8c, .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "transfer-encoding", .value = "chunked" },
        } },
        // Uppercase field name (§4.2).
        .{ .seed = 0x8d, .fields = &.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "X-Thing", .value = "v" },
        } },
        // A :status that is not three digits.
        .{ .seed = 0x8e, .fields = &.{.{ .name = ":status", .value = "cat" }} },
    };

    for (cases) |case| {
        var h3 = try establishH3(gpa, case.seed);
        defer h3.deinit(gpa);
        var out: [quic_conn.max_datagram]u8 = undefined;
        _ = try h3.conn.send(gpa, &out);
        var field_buf: [8]qpack.FieldLine = undefined;
        const fields = requestFields("GET", "https", "example.com", "/", &.{}, &field_buf);
        const stream = try h3.conn.request(gpa, fields, true);
        _ = try h3.conn.send(gpa, &out);

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(gpa);
        try qpack.encodeSection(gpa, &encoded, case.fields);
        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(gpa);
        var header: [16]u8 = undefined;
        const header_len = frame.writeFrameHeader(&header, 0x01, encoded.items.len);
        try response.appendSlice(gpa, header[0..header_len]);
        try response.appendSlice(gpa, encoded.items);

        try testing.expectError(error.H3Error, h3.inject(gpa, stream, 0, response.items, true));
        try testing.expectEqual(@as(?u64, 0x010e), h3.conn.close_code); // H3_MESSAGE_ERROR
    }
}

test "http3: GOAWAY refuses new requests and its ID may only shrink" {
    const gpa = testing.allocator;
    var h3 = try establishH3(gpa, 0x8f);
    defer h3.deinit(gpa);
    var out: [quic_conn.max_datagram]u8 = undefined;
    _ = try h3.conn.send(gpa, &out);

    var bytes: [64]u8 = undefined;
    var len: usize = quic.varint.encode(&bytes, 0x00);
    len += frame.writeSettings(bytes[len..], &.{});
    // GOAWAY id 8.
    len += frame.writeFrameHeader(bytes[len..], 0x07, 1);
    bytes[len] = 8;
    len += 1;
    try h3.inject(gpa, 3, 0, bytes[0..len], false);

    var saw_goaway = false;
    while (h3.conn.nextEvent()) |event| {
        switch (event) {
            .goaway => |e| {
                try testing.expectEqual(@as(u64, 8), e.id);
                saw_goaway = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_goaway);

    // §5.2: new requests would land at or above the named ID; refusing
    // locally beats sending into a void the server already disowned.
    var field_buf: [8]qpack.FieldLine = undefined;
    const fields = requestFields("GET", "https", "example.com", "/", &.{}, &field_buf);
    try testing.expectError(error.StreamStateError, h3.conn.request(gpa, fields, true));

    // A shrinking GOAWAY is legal (the server narrowed what it will finish)...
    var shrink: [8]u8 = undefined;
    var shrink_len = frame.writeFrameHeader(&shrink, 0x07, 1);
    shrink[shrink_len] = 4;
    shrink_len += 1;
    try h3.inject(gpa, 3, @intCast(len), shrink[0..shrink_len], false);

    // ...but a growing one would un-disown requests already rejected (§5.2).
    var grow: [8]u8 = undefined;
    var grow_len = frame.writeFrameHeader(&grow, 0x07, 1);
    grow[grow_len] = 6;
    grow_len += 1;
    try testing.expectError(
        error.H3Error,
        h3.inject(gpa, 3, @intCast(len + shrink_len), grow[0..grow_len], false),
    );
    try testing.expectEqual(@as(?u64, 0x0108), h3.conn.close_code);
}

test "http3: the peer's QPACK encoder stream must stay silent at zero capacity" {
    const gpa = testing.allocator;
    var h3 = try establishH3(gpa, 0x90);
    defer h3.deinit(gpa);

    // The stream itself is fine (§4.2 requires allowing it)...
    var bytes: [8]u8 = undefined;
    const type_len = quic.varint.encode(&bytes, 0x02);
    try h3.inject(gpa, 3, 0, bytes[0..type_len], false);
    try testing.expect(h3.conn.close_code == null);

    // ...but any instruction on it inserts into a table we advertised (by
    // omission) as zero-capacity (RFC 9204 §3.2.3).
    try testing.expectError(
        error.EncoderStreamError,
        h3.inject(gpa, 3, @intCast(type_len), &.{0x3f}, false),
    );
    try testing.expectEqual(@as(?u64, 0x0201), h3.conn.close_code);
}
