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
    /// RFC 8441 §3: an extended CONNECT was asked for before the peer advertised
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL. Named separately from `StreamStateError`
    /// because the remedy differs: this one is answered by waiting, or by not
    /// using the extension at all against this peer.
    ExtendedConnectNotEnabled,
} || quic.connection.Error || frame.Error || qpack.Error;

/// What this connection reports upward. IDs only — see the module comment.
///
/// **The end of a stream is reported exactly once, but which event carries it depends
/// on how QUIC delivered the bytes.** It rides on `headers.fin` when the FIN arrived
/// with the field section, on `body.fin` when it arrived with the last body bytes, and
/// on a `body` event with *no* bytes when it arrived on its own afterwards — which is
/// legal and ordinary, since a client closes its sending side after the request and the
/// transport may carry that in a later packet. An application must therefore treat all
/// three as the same signal; every consumer in this repository does, and the connection
/// fuzz target asserts that the sections and body bytes are identical across those
/// deliveries and that the end appears once. This was an unwritten three-way contract
/// until that target found the two shapes disagreeing.
pub const Event = union(enum) {
    /// The QUIC and HTTP/3 layers are both up: SETTINGS sent, streams open.
    established,
    /// RFC 9297: an HTTP Datagram arrived for `stream`. Carries the length only, like
    /// `body`: `readDatagram` hands out the payload until `consumeDatagram`.
    datagram: struct { stream: u64, len: usize },
    /// A field section arrived on `stream`; `takeSection` yields it.
    /// `fin` says the stream ended with it.
    headers: struct { stream: u64, fin: bool },
    /// Body bytes arrived on `stream`; `readBody`/`consumeBody` access them.
    body: struct { stream: u64, fin: bool },
    /// §5.2: the server is shutting down; requests on streams at or above
    /// `id` were not processed and are safe to retry elsewhere.
    goaway: struct { id: u64 },
    /// §4.1.1: the peer abruptly terminated `stream`, giving `code`.
    ///
    /// The code is reported rather than swallowed because the whole point of
    /// §4.1.1's vocabulary is what the application may do next:
    /// `H3_REQUEST_REJECTED` says the request was never processed and may be
    /// retried as though never sent, while `H3_REQUEST_CANCELLED` promises nothing
    /// of the kind. An implementation that drops the code makes that distinction
    /// unusable no matter how carefully the peer chose it.
    stream_reset: struct { stream: u64, code: u64 },
    /// The peer closed the connection (either layer's mechanism).
    peer_closed: struct { code: u64, application: bool },
    /// The transport idled out (§10.1 of RFC 9000), silently.
    idle_timeout,
};

/// One request stream's receive state: §4.1's grammar as a state machine, so
/// what is accepted is visible in one place.
const QueuedDatagram = struct { stream: u64, payload: []u8 };

/// RFC 9297 §2.1 rides on RFC 9221, so enabling the HTTP/3 setting has to enable the
/// transport parameter too — and derived here rather than left to the caller, because a
/// connection that advertised one without the other would negotiate a feature it then
/// could not use. §3 of RFC 9221 recommends 65535, meaning "any DATAGRAM frame that
/// fits inside a QUIC packet", which is exactly the promise this layer can keep: the
/// frame cannot be larger than a packet anyway, and the inbound queue is bounded by
/// count rather than by advertised size.
fn datagramParameters(
    given: quic.transport.Parameters,
    enable: bool,
) quic.transport.Parameters {
    if (!enable) return given;
    var params = given;
    if (params.max_datagram_frame_size == 0) params.max_datagram_frame_size = 65535;
    return params;
}

/// How many inbound HTTP Datagrams this connection holds before dropping the oldest.
pub const max_queued_datagrams = 32;

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
    /// Whether the end of the stream has been reported upward. One flag, because the
    /// end can be learned two ways — riding with the last frame, or arriving alone
    /// afterwards — and the application must hear about it exactly once.
    end_reported: bool = false,
    /// §4.4: this stream carries a CONNECT tunnel, so only DATA may follow.
    ///
    /// Set on a server when the CONNECT request arrives, and on a client when a 2xx
    /// answers a CONNECT it sent — those are the two moments §4.4 calls the method
    /// "completed". A non-2xx answer is a refusal, not a tunnel, and the stream
    /// stays an ordinary exchange.
    tunnel: bool = false,
    /// Client side only: a CONNECT went out on this stream, so a 2xx makes it a
    /// tunnel. Distinct from `tunnel` because the request is sent a round trip
    /// before the answer that decides.
    sent_connect: bool = false,
    /// Decoded sections in arrival order, waiting for `takeSection`.
    sections: std.ArrayList(qpack.FieldSection) = .empty,
    /// Body bytes waiting for the application.
    body: std.ArrayList(u8) = .empty,
    fin_seen: bool = false,
    /// Whether this side has finished sending on the stream. RFC 9297 §2.1 makes it
    /// the condition for sending a datagram: "HTTP/3 Datagrams MUST NOT be sent unless
    /// the corresponding stream's send side is open", and a datagram associated with a
    /// stream we have said everything on has nothing left to be associated with.
    fin_sent: bool = false,

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
    /// RFC 9220 §3: advertise SETTINGS_ENABLE_CONNECT_PROTOCOL. Off by default and
    /// the application's decision, because it is a promise about what this endpoint
    /// will *serve* — a server announcing it and then refusing every extended
    /// CONNECT has told its peers something untrue. Sending it as a client has no
    /// effect (RFC 8441 §3), so it is only meaningful on a server.
    enable_connect_protocol: bool = false,
    /// RFC 9297 §2.1.1: whether to advertise SETTINGS_H3_DATAGRAM, which is what makes
    /// QUIC DATAGRAM frames usable for HTTP Datagrams. Off by default: §2 requires an
    /// association with "an HTTP request that explicitly supports them", so an
    /// application that has no such extension gains nothing and would only "stick
    /// out" (§4).
    enable_datagram: bool = false,
};

pub const ServerOptions = struct {
    /// The certificate chain and signing key for the TLS handshake QUIC carries.
    identity: *const @import("../tls13/identity.zig").Identity,
    parameters: quic.transport.Parameters = .server_defaults,
    local_cid: quic.packet.ConnectionId,
    /// What the client is addressing now — the Initial keys derive from it.
    destination: quic.packet.ConnectionId,
    /// What the client's first Initial carried, which §7.3 of RFC 9000 has the
    /// server report. Differs from `destination` only after a Retry.
    original_destination: quic.packet.ConnectionId,
    peer_cid: quic.packet.ConnectionId,
    after_retry: bool = false,
    max_field_section_size: u64 = 64 * 1024,
    /// RFC 9220 §3, as in `Options`.
    enable_connect_protocol: bool = false,
    /// RFC 9297 §2.1.1: whether to advertise SETTINGS_H3_DATAGRAM, which is what makes
    /// QUIC DATAGRAM frames usable for HTTP Datagrams. Off by default: §2 requires an
    /// association with "an HTTP request that explicitly supports them", so an
    /// application that has no such extension gains nothing and would only "stick
    /// out" (§4).
    enable_datagram: bool = false,
};

pub const Connection = struct {
    /// Which end this is. HTTP/3 is less symmetric than QUIC beneath it: the two
    /// roles read different stream ID patterns, validate different pseudo-fields,
    /// and GOAWAY means a different kind of identifier in each direction.
    role: quic.transport.Role = .client,
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
    /// The GOAWAY *we* sent, which bounds what we will still accept. Separate
    /// from `goaway_id` because the two directions constrain different things:
    /// the peer's tells us what it will not serve, ours is a promise we have to
    /// keep.
    local_goaway_id: ?u64 = null,

    /// Request streams by ID.
    requests: std.AutoHashMapUnmanaged(u64, Request) = .empty,
    /// RFC 9297 datagrams waiting for the application, and how many were dropped.
    ///
    /// Bounded for the reason RFC 9221 §5.3 makes unavoidable: datagrams have no flow
    /// control, so a peer's sending rate is limited by congestion control and nothing
    /// else. Dropped counts are observable because a drop here is indistinguishable to
    /// the application from one on the network, and an application tuning its own rate
    /// needs to be able to tell.
    datagram_queue: std.ArrayList(QueuedDatagram) = .empty,
    datagrams_dropped: u64 = 0,
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
    /// Whether we advertise RFC 9220's SETTINGS_ENABLE_CONNECT_PROTOCOL.
    enable_connect_protocol: bool = false,
    /// RFC 9297 §2.1.1: whether to advertise SETTINGS_H3_DATAGRAM, which is what makes
    /// QUIC DATAGRAM frames usable for HTTP Datagrams. Off by default: §2 requires an
    /// association with "an HTTP request that explicitly supports them", so an
    /// application that has no such extension gains nothing and would only "stick
    /// out" (§4).
    enable_datagram: bool = false,

    pub fn init(options: Options, seed: [64]u8) !Connection {
        return .{
            .transport = try quic.connection.Connection.initClient(.{
                .host = options.host,
                // §3.1: the ALPN token for HTTP/3 is "h3". Not the caller's to
                // choose: a connection speaking this layer's frames under a
                // different token would be lying to the peer about what it is.
                .alpn = &.{"h3"},
                .parameters = datagramParameters(options.parameters, options.enable_datagram),
                .verification = options.verification,
                .local_cid = options.local_cid,
                .initial_destination = options.initial_destination,
                .token = options.token,
            }, seed),
            .max_field_section_size = options.max_field_section_size,
            .enable_connect_protocol = options.enable_connect_protocol,
            .enable_datagram = options.enable_datagram,
        };
    }

    /// The server side. Takes what the first datagram carried, because a server
    /// does not choose when a connection starts — see `quic.connection.initServer`.
    pub fn initServer(options: ServerOptions, seed: [64]u8) !Connection {
        return .{
            .role = .server,
            .transport = try quic.connection.Connection.initServer(.{
                .identity = options.identity,
                // §3.1: "h3" and nothing else. A server that accepted another
                // token for these frames would be misdescribing itself.
                .alpn = &.{"h3"},
                .parameters = datagramParameters(options.parameters, options.enable_datagram),
                .local_cid = options.local_cid,
                .destination = options.destination,
                .original_destination = options.original_destination,
                .peer_cid = options.peer_cid,
                .after_retry = options.after_retry,
            }, seed),
            .max_field_section_size = options.max_field_section_size,
            .enable_connect_protocol = options.enable_connect_protocol,
            .enable_datagram = options.enable_datagram,
        };
    }

    pub fn deinit(self: *Connection, gpa: Allocator) void {
        var it = self.requests.valueIterator();
        while (it.next()) |req| req.deinit(gpa);
        self.requests.deinit(gpa);
        for (self.datagram_queue.items) |entry| gpa.free(entry.payload);
        self.datagram_queue.deinit(gpa);
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

    /// RFC 9297 §2.1: the largest HTTP Datagram payload that can be sent for `stream`,
    /// or null when datagrams are not usable on this connection.
    ///
    /// The Quarter Stream ID's varint sits in front of every payload, so the room left
    /// depends on which stream it is for. Offered rather than left to the caller for
    /// the same reason the transport offers `maxDatagramPayload`: re-deriving an
    /// overhead is how a sender produces frames its peer must reject.
    pub fn maxDatagramPayload(self: *const Connection, stream: u64) ?usize {
        if (!self.datagramsAllowed()) return null;
        const budget = self.transport.maxDatagramPayload() orelse return null;
        const prefix = quic.varint.encodedLen(stream / 4);
        if (budget <= prefix) return null;
        return budget - prefix;
    }

    /// Whether HTTP Datagrams may be sent (RFC 9297 §2.1.1).
    ///
    /// Both directions of two different negotiations have to line up, which is why this
    /// is one function rather than a field: §2.1.1 requires the *setting* to have been
    /// "both sent and received with a value of 1", and RFC 9221 §3 requires the peer's
    /// `max_datagram_frame_size` to be non-zero before a DATAGRAM frame may be sent at
    /// all. Either missing means silence, not an error.
    pub fn datagramsAllowed(self: *const Connection) bool {
        if (!self.enable_datagram) return false;
        const peer = self.peer_settings orelse return false;
        if (!peer.h3_datagram) return false;
        return self.transport.datagramsAllowed();
    }

    /// RFC 9297 §2.1: send an HTTP Datagram associated with `stream`.
    pub fn sendDatagram(
        self: *Connection,
        gpa: Allocator,
        stream: u64,
        payload: []const u8,
    ) !void {
        if (!self.datagramsAllowed()) return error.DatagramsUnsupported;
        // §2.1: "HTTP/3 Datagrams MUST NOT be sent unless the corresponding stream's
        // send side is open." A datagram for a stream we have finished sending on has
        // nothing to be associated with.
        // §2.1: the association is a client-initiated bidirectional stream, divided by
        // four — so an ID that is not one cannot be named by a Quarter Stream ID at all.
        // Checked before the stream's state, because "this is not a stream a datagram
        // can belong to" is a different answer from "that stream is finished", and the
        // caller acts differently on each.
        if (stream % 4 != 0) return error.DatagramStreamInvalid;
        const req = self.requests.getPtr(stream) orelse return error.DatagramStreamClosed;
        if (req.fin_sent) return error.DatagramStreamClosed;

        var buf: [quic.connection.max_datagram]u8 = undefined;
        const prefix = quic.varint.encode(&buf, stream / 4);
        if (prefix + payload.len > buf.len) return error.DatagramTooLarge;
        @memcpy(buf[prefix..][0..payload.len], payload);
        try self.transport.sendDatagram(gpa, buf[0 .. prefix + payload.len]);
    }

    /// The oldest HTTP Datagram that has arrived, with the stream it belongs to.
    pub fn readDatagram(self: *const Connection) ?struct { stream: u64, payload: []const u8 } {
        if (self.datagram_queue.items.len == 0) return null;
        const entry = self.datagram_queue.items[0];
        return .{ .stream = entry.stream, .payload = entry.payload };
    }

    /// Release what `readDatagram` returned.
    pub fn consumeDatagram(self: *Connection, gpa: Allocator) void {
        if (self.datagram_queue.items.len == 0) return;
        gpa.free(self.datagram_queue.orderedRemove(0).payload);
    }

    fn onDatagram(self: *Connection, gpa: Allocator) !void {
        const raw = self.transport.readDatagram() orelse return;
        defer self.transport.consumeDatagram(gpa);

        // §2.1: "Receipt of a QUIC DATAGRAM frame whose payload is too short to allow
        // parsing the Quarter Stream ID field MUST be treated as an HTTP/3 connection
        // error of type H3_DATAGRAM_ERROR."
        var rest = raw;
        const quarter = quic.varint.take(&rest) catch
            return self.failFrame(error.DatagramError);
        // §2.1: "The largest legal QUIC stream ID value is 2^62-1, so the largest legal
        // value of the Quarter Stream ID field is 2^60-1."
        if (quarter > (@as(u64, 1) << 60) - 1) return self.failFrame(error.DatagramError);
        const stream = quarter * 4;

        // §2.1: a datagram for a stream that does not exist yet is dropped or buffered
        // — "SHALL either drop that datagram silently or buffer it temporarily". Dropped
        // here: buffering costs memory a peer chooses the size of, and this layer's
        // rule is that such a thing needs a bound before it needs a feature. And "if a
        // datagram is received after the corresponding stream's receive side is closed,
        // the received datagrams MUST be silently dropped".
        const owner = self.requests.getPtr(stream) orelse {
            self.datagrams_dropped += 1;
            return;
        };
        // §2.1: dropped once the receive side is closed, for both roles — the exchange
        // it belonged to is over.
        if (owner.fin_seen) {
            self.datagrams_dropped += 1;
            return;
        }

        if (self.datagram_queue.items.len == max_queued_datagrams) {
            gpa.free(self.datagram_queue.orderedRemove(0).payload);
            self.datagrams_dropped += 1;
        }
        const owned = try gpa.dupe(u8, rest);
        errdefer gpa.free(owned);
        try self.datagram_queue.append(gpa, .{ .stream = stream, .payload = owned });
        try self.events.append(gpa, .{ .datagram = .{
            .stream = stream,
            .len = owned.len,
        } });
    }

    /// Feed one datagram, then translate whatever the transport surfaced.
    pub fn receive(self: *Connection, gpa: Allocator, datagram: []const u8) !void {
        self.transport.receive(gpa, datagram) catch |err| return err;
        try self.drainTransport(gpa);
    }

    /// The same, for a datagram that arrived on a particular path (§9.3).
    ///
    /// An endpoint serving many peers on one socket must use this, or a peer that
    /// moves goes unnoticed; see `quic.connection.Connection.receiveOn`.
    pub fn receiveOn(self: *Connection, gpa: Allocator, datagram: []const u8, path: u64) !void {
        self.transport.receiveOn(gpa, datagram, path) catch |err| return err;
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
                .datagram => try self.onDatagram(gpa),
                .stream_readable => |e| try self.onReadable(gpa, e.id, e.fin),
                .stream_reset => |e| {
                    // The peer abandoned a response. RFC 9204 §4.4.2 would have
                    // us emit a Stream Cancellation; with a zero-capacity table
                    // it releases nothing, and §2.2.2.2 lets us omit it.
                    if (self.requests.getPtr(e.id)) |req| {
                        req.fin_seen = true;
                    }
                    try self.events.append(gpa, .{ .stream_reset = .{
                        .stream = e.id,
                        .code = e.code,
                    } });
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
        var advertised: [3]frame.Setting = undefined;
        advertised[0] = .{
            .id = frame.Setting.max_field_section_size,
            .value = self.max_field_section_size,
        };
        var advertised_len: usize = 1;
        // RFC 9220 §3. Sent only when true, for the same reason the QPACK zeros are
        // omitted: the registered default is 0, and §7.2.4.2 makes an omitted
        // setting and its default indistinguishable. Sending 0 explicitly would be
        // bytes that say nothing — and RFC 8441 §3 forbids ever following a 1 with a
        // 0, which cannot arise here because HTTP/3 sends SETTINGS exactly once.
        if (self.enable_connect_protocol) {
            advertised[advertised_len] = .{ .id = frame.Setting.enable_connect_protocol, .value = 1 };
            advertised_len += 1;
        }
        // RFC 9297 §2.1.1, and the same omit-when-false rule. §2.1.1 recommends always
        // sending 1 to avoid "sticking out" (§4); that recommendation is about a
        // deployment's traffic analysis posture rather than about correctness, and it
        // is the application that knows whether it wants to receive datagrams at all —
        // so it is an option, and the reasoning is here rather than lost.
        if (self.enable_datagram) {
            advertised[advertised_len] = .{ .id = frame.Setting.h3_datagram, .value = 1 };
            advertised_len += 1;
        }
        len += frame.writeSettings(buf[len..], advertised[0..advertised_len]);
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
        // RFC 8441 §3: an extended CONNECT may be sent only once the peer has said
        // it understands one. Refused locally rather than sent hopefully, because a
        // peer without the extension does not merely decline it — `:protocol` is an
        // undefined pseudo-field there, so §4.3 makes the whole request malformed
        // and the stream is spent for nothing.
        for (fields) |field| {
            if (!std.mem.eql(u8, field.name, ":protocol")) continue;
            const peer = self.peer_settings orelse return error.ExtendedConnectNotEnabled;
            if (!peer.enable_connect_protocol) return error.ExtendedConnectNotEnabled;
        }
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

        // Track it so the response has somewhere to land. §4.4: remember whether
        // this was a CONNECT, because a 2xx answer to one turns the stream into a
        // tunnel where only DATA is permitted — and by then the request is gone.
        var sent_connect = false;
        for (fields) |field| {
            if (std.mem.eql(u8, field.name, ":method")) {
                sent_connect = std.mem.eql(u8, field.value, "CONNECT");
            }
        }
        // `fin_sent` is recorded here rather than beside the `finishStream` above,
        // because the entry does not exist yet at that point — RFC 9297 §2.1 reads this
        // flag to decide whether a datagram may be sent, and a flag set on an absent
        // entry is a flag that is always false.
        try self.requests.put(gpa, id, .{ .sent_connect = sent_connect, .fin_sent = fin });
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
        if (fin) {
            try self.transport.finishStream(id);
            // RFC 9297 §2.1 needs to know the send side has closed; recorded at every
            // point a FIN leaves, because a flag that is right in two places out of
            // three is worse than none.
            if (self.requests.getPtr(id)) |req| req.fin_sent = true;
        }
    }

    /// Send a response header section on a request stream.
    ///
    /// Mirrors `request`, and deliberately does not reuse it: a response goes on
    /// a stream the *peer* opened, so there is nothing to open and no stream ID
    /// to return, and the field section that is valid differs.
    pub fn respond(
        self: *Connection,
        gpa: Allocator,
        stream: u64,
        fields: []const qpack.FieldLine,
        fin: bool,
    ) !void {
        assert(self.role == .server);
        if (!self.requests.contains(stream)) return error.StreamStateError;

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(gpa);
        try qpack.encodeSection(gpa, &encoded, fields);

        var header: [16]u8 = undefined;
        const header_len = frame.writeFrameHeader(
            &header,
            @backingInt(frame.FrameType.headers),
            encoded.items.len,
        );
        _ = try self.transport.write(gpa, stream, header[0..header_len]);
        _ = try self.transport.write(gpa, stream, encoded.items);
        if (fin) {
            try self.transport.finishStream(stream);
            if (self.requests.getPtr(stream)) |req| req.fin_sent = true;
        }
    }

    /// §4.1.1: cancel an exchange, in whichever directions are still open.
    ///
    /// "Implementations SHOULD cancel requests by abruptly terminating any
    /// directions of a stream that are still open": the sending part is reset and
    /// reading is aborted on the receiving part. Both, because either alone leaves
    /// the peer working — a reset with no STOP_SENDING lets a server keep producing
    /// a response nobody will read, and a STOP_SENDING with no reset leaves the
    /// server waiting for a request body that will never come.
    ///
    /// `code` is the application's, since only it knows which of §4.1.1's meanings
    /// applies. A client cancelling because the response stopped being interesting
    /// wants `H3_REQUEST_CANCELLED`; a server refusing without looking wants
    /// `H3_REQUEST_REJECTED`, which §4.1.1 forbids for anything it has processed.
    ///
    /// Idempotent: cancelling twice, or cancelling a stream that has already ended,
    /// does nothing. A cancel racing the last of a response is ordinary rather than
    /// exceptional, and §4.1.1 says a client MAY use a complete response it has
    /// already received.
    pub fn cancel(self: *Connection, gpa: Allocator, id: u64, code: u64) void {
        // Reset what we are still sending. The transport refuses this once the
        // stream is in a terminal state, which is the "already ended" case.
        self.transport.resetStream(id, code) catch {};
        // And stop what is still arriving. §3.5 of RFC 9000 makes this a request
        // that the peer reset its own sending side, which is how the other
        // direction actually stops rather than merely being ignored.
        self.transport.stopSending(id, code) catch {};

        // Locally the exchange is over: no further events for it, and the state is
        // released. Anything still in flight arrives for an unknown stream and is
        // dropped, which is what `onRequestData`'s missing-entry path already does.
        if (self.requests.fetchRemove(id)) |entry| {
            var state = entry.value;
            state.deinit(gpa);
        }
    }

    /// §5.2: announce that this endpoint is shutting down.
    ///
    /// The identifier means different things in each direction, which is the one
    /// thing about GOAWAY worth being careful with: from a server it is a
    /// client-initiated bidirectional *stream ID*, and requests on streams at or
    /// above it were not processed and may be retried elsewhere. From a client it
    /// is a *push ID*. This endpoint never permits pushes, so a client's GOAWAY
    /// can only ever carry zero.
    pub fn goaway(self: *Connection, gpa: Allocator, id: u64) !void {
        if (!self.h3_ready) return error.StreamStateError;
        // A GOAWAY that raised the limit would un-refuse requests the previous
        // one disowned, and the peer has already acted on that promise.
        if (self.local_goaway_id) |previous| {
            if (id > previous) return error.StreamStateError;
        }
        const value = switch (self.role) {
            .server => id,
            .client => 0,
        };
        var buf: [32]u8 = undefined;
        const len = frame.writeGoaway(&buf, value);
        _ = try self.transport.write(gpa, self.control_out.?, buf[0..len]);
        self.local_goaway_id = value;

        // §5.2: "Upon sending a GOAWAY frame, the endpoint SHOULD explicitly cancel
        // any requests or pushes that have identifiers greater than or equal to the
        // one indicated, in order to clean up transport state for the affected
        // streams." Without this the promise is made and the streams are left open,
        // so both ends keep flow-control and stream state for exchanges neither
        // intends to finish.
        //
        // H3_REQUEST_REJECTED, for the same reason the refusal path uses it: these
        // are requests this endpoint has decided not to process, and §4.1.1's
        // "as though they had never been sent" is what makes the GOAWAY identifier
        // useful to a client choosing what to retry.
        if (self.role == .server) {
            var doomed: [32]u64 = undefined;
            var found: usize = 0;
            var it = self.requests.iterator();
            while (it.next()) |kv| {
                if (kv.key_ptr.* < value) continue;
                if (found == doomed.len) break;
                doomed[found] = kv.key_ptr.*;
                found += 1;
            }
            // Collected first: cancelling mutates the map being walked.
            for (doomed[0..found]) |id_above| self.cancel(gpa, id_above, 0x010b);
        }
    }

    /// The largest stream ID a `goaway` may name and still be honest: one past
    /// everything seen, so nothing in flight is disowned retroactively.
    pub fn nextRequestStreamId(self: *const Connection) u64 {
        var highest: ?u64 = null;
        var it = self.requests.keyIterator();
        while (it.next()) |key| {
            if (highest == null or key.* > highest.?) highest = key.*;
        }
        return if (highest) |h| h + 4 else 0;
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

    /// Whether the peer has finished sending on `stream`. What `sweepAll` needs to
    /// know before tearing a child pipeline down, and only the connection can
    /// answer it — the FIN arrives at this layer.
    pub fn inboundFinished(self: *const Connection, stream: u64) bool {
        const req = self.requests.getPtr(stream) orelse return true;
        return req.fin_seen;
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
        //
        // The pattern differs by role and this is the whole of the difference:
        // client-initiated bidirectional (0b00) carries requests in one
        // direction and responses in the other, so both ends read it; the
        // unidirectional streams a peer opens are 0b10 from a client and 0b11
        // from a server. Reading the wrong one would mean a server treating its
        // *own* control stream as the peer's.
        const peer_uni: u64 = switch (self.role) {
            .client => 0b11,
            .server => 0b10,
        };
        const kind = id & 0x3;
        if (kind == 0b00) return self.onRequestData(gpa, id, fin);
        if (kind == peer_uni) return self.onUniData(gpa, id, fin);
        // §6.1: server-initiated bidirectional streams have no meaning in
        // HTTP/3, and our transport parameters allow a client none.
        return self.fail(0x0101); // H3_GENERAL_PROTOCOL_ERROR
    }

    fn onRequestData(self: *Connection, gpa: Allocator, id: u64, fin: bool) !void {
        if (self.role == .server and !self.requests.contains(id)) {
            // A client opening a bidirectional stream *is* the request arriving;
            // there is nothing to have registered it in advance. §5.2: after
            // GOAWAY, streams at or above the named ID are refused rather than
            // half-served, which is what makes the ID a promise the client can
            // rely on when retrying elsewhere.
            if (self.local_goaway_id) |limit| {
                if (id >= limit) {
                    // §4.1.1: *rejected*, not cancelled. The distinction is the
                    // client's licence to retry: a rejected request "can be
                    // treated as though it had never been sent at all", while
                    // H3_REQUEST_CANCELLED (0x010c) says nothing about whether
                    // the server acted on it. Nothing here has been processed —
                    // the stream is refused before any state is created — so
                    // §4.1.1's stronger promise is the one to make, and §5.2
                    // depends on it: the GOAWAY identifier is only a promise the
                    // client can rely on if requests above it are rejected.
                    self.transport.resetStream(id, 0x010b) catch {}; // H3_REQUEST_REJECTED
                    return;
                }
            }
            try self.requests.put(gpa, id, .{});
        }
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
                        if (stream_done) req.end_reported = true;
                        try self.events.append(gpa, .{ .body = .{
                            .stream = id,
                            .fin = stream_done,
                        } });
                    }
                },
            }
        }

        // §7.1: "When a stream terminates cleanly, if the last frame on the stream was
        // truncated, this MUST be treated as a connection error of type
        // H3_FRAME_ERROR." Up to here a half-arrived frame means "wait for more"; a
        // clean end is what turns it into a promise the peer broke. Checked before
        // the end is reported, because the alternative is telling the application a
        // message finished when its sender never finished sending it.
        if (req.fin_seen and req.parser.midFrame()) return self.failFrame(error.FrameError);

        // A FIN that arrives on its own, after the last frame was already consumed.
        // Nothing reported the end in that case, because the loop above only learns
        // "finished" while it holds an item — and `read` returns nothing here.
        //
        // Legal and ordinary: §4.1 has the client close its sending side after the
        // request, and QUIC may carry that STREAM frame in a later packet than the
        // data. Every test and both endpoints in this repository happen to set the
        // FIN *with* the last frame, which is why an exchange could hang here for a
        // peer that does not — a server waiting for a request body that is already
        // complete. Found by the connection fuzz target's whole-versus-fragmented
        // comparison, where the same bytes ended the stream in one delivery and did
        // not in the other.
        if (req.fin_seen and !req.end_reported) {
            req.end_reported = true;
            try self.events.append(gpa, .{ .body = .{ .stream = id, .fin = true } });
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
        // §4.4: "Once the CONNECT method has completed, only DATA frames are
        // permitted to be sent on the stream ... Receipt of any other known frame
        // type MUST be treated as a connection error of type H3_FRAME_UNEXPECTED."
        // Unknown types stay ignorable — §9 makes that a separate rule, and an
        // extension may define its own frames for a tunnel.
        //
        // Without this a tunnel accepts trailers, which means a peer can put field
        // semantics into a byte stream a proxy is relaying verbatim.
        if (req.tunnel) switch (f) {
            .data, .unknown => {},
            else => return self.fail(0x0105), // H3_FRAME_UNEXPECTED
        };

        switch (f) {
            .headers => |section_bytes| {
                if (req.state == .trailers_received) return self.fail(0x0105);

                var section = qpack.decodeSection(gpa, section_bytes, .{
                    .max_field_section_size = self.max_field_section_size,
                }) catch |err| return self.failQpack(err);
                errdefer section.deinit(gpa);

                const is_trailers = req.saw_data;
                // A server validates requests, a client validates responses.
                // Sharing one function would mean accepting `:status` in a
                // request and `:method` in a response, which is exactly the
                // confusion §4.3 exists to forbid.
                const valid = switch (self.role) {
                    .client => validResponseSection(&section, is_trailers),
                    .server => validRequestSection(
                        &section,
                        is_trailers,
                        self.enable_connect_protocol,
                    ),
                };
                if (!valid) {
                    // The errdefer above frees the section — `fail` returns an
                    // error, so freeing here too would be a double deinit on
                    // poisoned memory (and was, briefly).
                    return self.fail(0x010e); // H3_MESSAGE_ERROR
                }

                if (is_trailers) {
                    req.state = .trailers_received;
                } else {
                    req.state = .headers_received;
                    // §4.4's "completed", from each side's point of view.
                    switch (self.role) {
                        .server => if (isConnectSection(&section)) {
                            req.tunnel = true;
                        },
                        .client => if (req.sent_connect and isSuccessSection(&section)) {
                            req.tunnel = true;
                        },
                    }
                }
                try req.sections.append(gpa, section);
                if (stream_done) req.end_reported = true;
                try self.events.append(gpa, .{ .headers = .{
                    .stream = id,
                    .fin = stream_done,
                } });
            },
            // §7.2.5: PUSH_PROMISE travels server to client. Reaching a client
            // it names a push ID we never permitted, since we send no
            // MAX_PUSH_ID (§4.6); reaching a server it is the wrong direction
            // entirely.
            .push_promise => return switch (self.role) {
                .client => self.fail(0x0108), // H3_ID_ERROR
                .server => self.fail(0x0105), // H3_FRAME_UNEXPECTED
            },
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
                // §7.2.3: CANCEL_PUSH names a push. This endpoint never
                // promises one in either direction, so any ID in it refers to
                // nothing.
                .cancel_push => return self.fail(0x0108),
                // §7.2.7: MAX_PUSH_ID travels client to server. A server
                // receiving it is being *offered* permission to push, which it
                // simply does not take up — §4.6 makes server push optional, and
                // declining is done by never sending a PUSH_PROMISE rather than
                // by refusing the frame. A client receiving one is a role
                // confusion and is H3_FRAME_UNEXPECTED.
                .max_push_id => switch (self.role) {
                    .server => {},
                    .client => return self.fail(0x0105),
                },
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

/// Whether a validated request section is a CONNECT, extended or not (§4.4,
/// RFC 9220 §4). Both are tunnels; the extended form merely also carries a scheme
/// and path so the target can be named.
fn isConnectSection(section: *const qpack.FieldSection) bool {
    for (section.fields.items) |field| {
        if (std.mem.eql(u8, field.name, ":method")) {
            return std.mem.eql(u8, field.value, "CONNECT");
        }
    }
    return false;
}

/// Whether a validated response section carries a 2xx status, which is what §4.4
/// makes the signal that a tunnel is open. The section has already been validated,
/// so `:status` is present and three digits.
fn isSuccessSection(section: *const qpack.FieldSection) bool {
    for (section.fields.items) |field| {
        if (std.mem.eql(u8, field.name, ":status")) {
            return field.value[0] == '2';
        }
    }
    return false;
}

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

/// Whether a received *request* field section is one §4.3.1 permits.
///
/// The rules read like a list but are one idea: a request's shape is fixed, and
/// anything that could be read two ways is rejected rather than guessed at. That
/// is what keeps request smuggling out — the same reason the HTTP/1.1 decoder in
/// this repository is a flat state machine.
fn validRequestSection(
    section: *const qpack.FieldSection,
    is_trailers: bool,
    connect_protocol: bool,
) bool {
    var seen_regular = false;
    var seen: struct {
        method: bool = false,
        scheme: bool = false,
        authority: bool = false,
        path: bool = false,
        protocol: bool = false,
    } = .{};
    var method: []const u8 = &.{};
    var path: []const u8 = &.{};
    var scheme: []const u8 = &.{};

    for (section.fields.items) |field| {
        if (field.name.len == 0) return false;
        if (field.name[0] == ':') {
            // §4.3: pseudo-fields precede regular ones, and trailers have none.
            if (seen_regular) return false;
            if (is_trailers) return false;
            if (field.value.len == 0 and !std.mem.eql(u8, field.name, ":authority")) return false;

            if (std.mem.eql(u8, field.name, ":method")) {
                if (seen.method) return false;
                seen.method = true;
                method = field.value;
            } else if (std.mem.eql(u8, field.name, ":scheme")) {
                if (seen.scheme) return false;
                seen.scheme = true;
                scheme = field.value;
            } else if (std.mem.eql(u8, field.name, ":authority")) {
                if (seen.authority) return false;
                seen.authority = true;
            } else if (std.mem.eql(u8, field.name, ":path")) {
                if (seen.path) return false;
                seen.path = true;
                path = field.value;
            } else if (std.mem.eql(u8, field.name, ":protocol")) {
                // RFC 9220's extended CONNECT. §4.3 permits a pseudo-field this
                // document does not define only when "an extension could negotiate
                // a modification of this restriction" — so it is defined here
                // exactly when we advertised the setting, and malformed otherwise.
                // RFC 8441 §3 relies on that: it is why a client must wait for the
                // setting rather than try and see.
                if (!connect_protocol) return false;
                if (seen.protocol) return false;
                seen.protocol = true;
            } else {
                // §4.3: an unknown pseudo-field is malformed, unlike an unknown
                // regular field. The set is closed on purpose — a peer inventing
                // one is not extending HTTP, it is disagreeing about the message.
                return false;
            }
            continue;
        }
        seen_regular = true;

        for (field.name) |c| {
            if (c >= 'A' and c <= 'Z') return false;
        }
        // §4.2: the connection is QUIC's business, so these do not exist.
        for ([_][]const u8{
            "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade",
        }) |banned| {
            if (std.mem.eql(u8, field.name, banned)) return false;
        }
        // §4.2: `te` may appear, but only as exactly "trailers".
        if (std.mem.eql(u8, field.name, "te") and !std.mem.eql(u8, field.value, "trailers")) {
            return false;
        }
    }

    if (is_trailers) return true;

    // §4.3.1: CONNECT is the one shape that differs, and it differs in both
    // directions — it must omit :scheme and :path, and must carry :authority.
    if (seen.method and std.mem.eql(u8, method, "CONNECT")) {
        if (seen.protocol) {
            // RFC 9220 §4: extended CONNECT reinstates :scheme and :path.
            return seen.scheme and seen.path and seen.authority;
        }
        return !seen.scheme and !seen.path and seen.authority;
    }

    if (!seen.method or !seen.scheme or !seen.path) return false;
    // §4.3.1: an empty :path is malformed except for OPTIONS *, and for http(s)
    // URIs the path must begin with "/". Both are cases where two readings exist
    // and the RFC picks one.
    if (path.len == 0) return false;
    const http_scheme = std.mem.eql(u8, scheme, "http") or std.mem.eql(u8, scheme, "https");
    if (http_scheme and path[0] != '/' and !std.mem.eql(u8, path, "*")) return false;
    if (std.mem.eql(u8, path, "*") and !std.mem.eql(u8, method, "OPTIONS")) return false;
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

// ── Server role ─────────────────────────────────────────────────────────────

var h3_identity: @import("../tls13/identity.zig").Identity = undefined;

/// Drives datagrams between two HTTP/3 connections until neither has more to
/// send. Bounded, because a handshake that has not settled is a defect and an
/// unbounded loop would hang the suite rather than report it.
/// Bounded pumping: moves datagrams both ways until neither side has anything to
/// say, or `rounds` is exhausted.
pub fn pumpH3(gpa: Allocator, a: *Connection, b: *Connection, rounds: usize) !void {
    var buf: [1500]u8 = undefined;
    var round: usize = 0;
    while (round < rounds) : (round += 1) {
        var moved = false;
        for ([_][2]*Connection{ .{ a, b }, .{ b, a } }) |pair| {
            const from, const to = pair;
            // Bounded per direction as well as per round: two endpoints that
            // each answer the other's acknowledgement would otherwise spin
            // forever, and a hung suite reports nothing.
            var datagrams: usize = 0;
            while (datagrams < 64) : (datagrams += 1) {
                const n = try from.send(gpa, &buf);
                if (n == 0) break;
                moved = true;
                try to.receive(gpa, buf[0..n]);
            }
            if (datagrams == 64) return error.DidNotSettle;
            try from.poll(gpa);
        }
        if (!moved) return;
    }
    return error.DidNotSettle;
}

/// Pump until one side fails the connection, for tests whose subject *is* the
/// failure. `pumpH3` propagates it, which is right everywhere else.
fn pumpUntilFailure(gpa: Allocator, a: *Connection, b: *Connection, rounds: usize) void {
    pumpH3(gpa, a, b, rounds) catch {};
}

pub const TestPair = struct { client: Connection, server: Connection };

/// A handshaken client and server, shared with `multiplex.zig`'s tests and the
/// fuzz targets. Public because those live in other modules, not because an
/// application has any use for it.
pub fn testPair(gpa: Allocator) !TestPair {
    return testPairWith(gpa, .{});
}

/// Which extensions the pair negotiates. A struct rather than positional flags: two
/// bools in a call are two chances to swap them.
pub const TestPairOptions = struct {
    /// RFC 9220 §3's setting, which is all the extension changes about setup.
    connect_protocol: bool = false,
    /// RFC 9297 §2.1.1's setting, and with it RFC 9221's transport parameter.
    datagram: bool = false,
};

/// `connect_protocol` makes the server advertise RFC 9220's setting, which is the
/// only difference the extension makes to a connection's setup.
///
/// Public because the WebSocket binding in `http3/websocket.zig` needs a pair with
/// the extension enabled, and a second copy of this setup would be a second thing to
/// keep in step with the handshake.
pub fn testPairWith(gpa: Allocator, options: TestPairOptions) !TestPair {
    const connect_protocol = options.connect_protocol;
    h3_identity = quic.server.testIdentity();
    const client_cid = quic.packet.ConnectionId.init(&.{ 0xc0, 0xc1, 0xc2, 0xc3 }) catch unreachable;
    const server_cid = quic.packet.ConnectionId.init(&.{ 0x50, 0x51, 0x52, 0x53 }) catch unreachable;
    const dcid = quic.packet.ConnectionId.init(
        &.{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 },
    ) catch unreachable;

    var client = try Connection.init(.{
        .host = "example.com",
        .verification = null,
        .local_cid = client_cid,
        .initial_destination = dcid,
        // Deliberately not `enable_connect_protocol`: RFC 8441 §3 says receipt by a
        // server "does not have any impact", so a client advertising it says nothing,
        // and a test asserting the server saw nothing is asserting something real.
        .enable_datagram = options.datagram,
    }, @splat(0x71));
    errdefer client.deinit(gpa);
    var server = try Connection.initServer(.{
        .identity = &h3_identity,
        .local_cid = server_cid,
        .destination = dcid,
        .original_destination = dcid,
        .peer_cid = client_cid,
        .enable_connect_protocol = connect_protocol,
        .enable_datagram = options.datagram,
    }, @splat(0x72));
    errdefer server.deinit(gpa);
    try client.start(gpa);
    return .{ .client = client, .server = server };
}

test "http3 server: a request and response cross a connection made of our own two ends" {
    // The whole stack against itself with no fixture anywhere: QUIC handshake,
    // both control streams, SETTINGS in both directions, QPACK, request
    // validation, response generation.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);

    try pumpH3(gpa, client, server, 16);

    // Both sides saw SETTINGS from the other, which is what "established" means
    // at this layer rather than merely at QUIC's.
    try testing.expect(client.peerSettings() != null);
    try testing.expect(server.peerSettings() != null);

    var buf: [8]qpack.FieldLine = undefined;
    const fields = requestFields("GET", "https", "example.com", "/index.html", &.{}, &buf);
    const stream = try client.request(gpa, fields, true);
    try pumpH3(gpa, client, server, 8);

    // The server saw it as a request, on the stream the client opened.
    var saw_request = false;
    while (server.nextEvent()) |event| switch (event) {
        .headers => |h| {
            try testing.expectEqual(stream, h.stream);
            try testing.expect(h.fin);
            var section = server.takeSection(h.stream).?;
            defer section.deinit(gpa);
            try testing.expectEqualStrings(":method", section.fields.items[0].name);
            try testing.expectEqualStrings("GET", section.fields.items[0].value);
            saw_request = true;
        },
        else => {},
    };
    try testing.expect(saw_request);

    try server.respond(gpa, stream, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    }, false);
    try server.writeBody(gpa, stream, "hello from h3", true);
    try pumpH3(gpa, client, server, 8);

    var saw_response = false;
    var body_done = false;
    while (client.nextEvent()) |event| switch (event) {
        .headers => |h| {
            var section = client.takeSection(h.stream).?;
            defer section.deinit(gpa);
            try testing.expectEqualStrings(":status", section.fields.items[0].name);
            try testing.expectEqualStrings("200", section.fields.items[0].value);
            saw_response = true;
        },
        .body => |b| {
            try testing.expectEqualStrings("hello from h3", client.readBody(b.stream));
            client.consumeBody(b.stream, "hello from h3".len);
            if (b.fin) body_done = true;
        },
        else => {},
    };
    try testing.expect(saw_response and body_done);
}

test "http3 server: a malformed request is rejected rather than served" {
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    // §4.3.1: a request with no :path is malformed. The client here is a
    // deliberate liar — nothing in the normal API can produce this.
    _ = try client.request(gpa, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    }, true);

    // The server closes with H3_MESSAGE_ERROR rather than guessing a path.
    var buf: [1500]u8 = undefined;
    const n = try client.send(gpa, &buf);
    try testing.expectError(error.H3Error, server.receive(gpa, buf[0..n]));
    try testing.expectEqual(@as(u64, 0x010e), server.close_code.?);
}

test "http3 server: request validation follows §4.3.1, including CONNECT" {
    const gpa = testing.allocator;

    const cases = [_]struct {
        fields: []const qpack.FieldLine,
        valid: bool,
        note: []const u8,
        /// Whether RFC 9220's setting was advertised. `:protocol` is only a defined
        /// pseudo-field when it was (§4.3), so the same fields are valid or
        /// malformed depending on this.
        connect_protocol: bool = false,
    }{
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "h" },
            .{ .name = ":path", .value = "/" },
        }, .valid = true, .note = "the ordinary shape" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
        }, .valid = true, .note = ":authority may be absent when Host is present" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/" },
        }, .valid = false, .note = ":scheme is required" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":path", .value = "/other" },
        }, .valid = false, .note = "a duplicate pseudo-field admits two readings" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "index.html" },
        }, .valid = false, .note = "an http path must be rooted" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "OPTIONS" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "*" },
        }, .valid = true, .note = "OPTIONS * is the exception" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "*" },
        }, .valid = false, .note = "and only for OPTIONS" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":authority", .value = "h:443" },
        }, .valid = true, .note = "CONNECT carries authority alone" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "h:443" },
        }, .valid = false, .note = "CONNECT with scheme and path needs :protocol" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/chat" },
            .{ .name = ":authority", .value = "h:443" },
        }, .valid = true, .note = "extended CONNECT reinstates both", .connect_protocol = true },
        // The same request, unnegotiated: §4.3 makes an undefined pseudo-field
        // malformed, which is the mechanism RFC 8441 §3 counts on.
        .{ .fields = &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/chat" },
            .{ .name = ":authority", .value = "h.test" },
        }, .valid = false, .note = ":protocol without the setting is malformed" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":unknown", .value = "x" },
        }, .valid = false, .note = "the pseudo-field set is closed" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = "connection", .value = "close" },
        }, .valid = false, .note = "connection-specific fields do not exist here" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = "te", .value = "gzip" },
        }, .valid = false, .note = "te may only be \"trailers\"" },
        .{ .fields = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = "te", .value = "trailers" },
        }, .valid = true, .note = "and that one is allowed" },
        .{ .fields = &.{
            .{ .name = "x", .value = "1" },
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
        }, .valid = false, .note = "pseudo-fields come first" },
        .{ .fields = &.{
            .{ .name = "Accept", .value = "*/*" },
            .{ .name = ":method", .value = "GET" },
        }, .valid = false, .note = "and names are lowercase" },
    };

    for (cases) |case| {
        var section: qpack.FieldSection = .{};
        defer section.deinit(gpa);
        for (case.fields) |field| {
            try section.fields.append(gpa, .{
                .name = try gpa.dupe(u8, field.name),
                .value = try gpa.dupe(u8, field.value),
            });
        }
        const got = validRequestSection(&section, false, case.connect_protocol);
        if (got != case.valid) {
            std.debug.print("case failed: {s}\n", .{case.note});
            return error.ValidationDisagrees;
        }
    }

    // Trailers: no pseudo-fields at all, and that is the only rule left.
    var trailers: qpack.FieldSection = .{};
    defer trailers.deinit(gpa);
    try trailers.fields.append(gpa, .{
        .name = try gpa.dupe(u8, "x-checksum"),
        .value = try gpa.dupe(u8, "abc"),
    });
    try testing.expect(validRequestSection(&trailers, true, false));
    try trailers.fields.append(gpa, .{
        .name = try gpa.dupe(u8, ":method"),
        .value = try gpa.dupe(u8, "GET"),
    });
    try testing.expect(!validRequestSection(&trailers, true, false));
}

test "http3 server: GOAWAY names a stream ID and refuses requests at or above it" {
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    // One request served normally, so there is a real boundary to draw.
    var buf: [8]qpack.FieldLine = undefined;
    const first = try client.request(gpa, requestFields("GET", "https", "h", "/a", &.{}, &buf), true);
    try pumpH3(gpa, client, server, 8);
    while (server.nextEvent()) |event| switch (event) {
        .headers => |h| {
            var section = server.takeSection(h.stream).?;
            section.deinit(gpa);
        },
        else => {},
    };

    // §5.2: the ID is one past what has been accepted, so nothing in flight is
    // disowned retroactively.
    const limit = server.nextRequestStreamId();
    try testing.expect(limit > first);
    try server.goaway(gpa, limit);
    try pumpH3(gpa, client, server, 8);

    // The client learned the limit, and a raised one is refused locally.
    try testing.expectEqual(limit, client.goaway_id.?);
    try testing.expectError(error.StreamStateError, server.goaway(gpa, limit + 4));

    // Once the client knows, it refuses locally rather than sending into a void.
    try testing.expectError(error.StreamStateError, client.request(gpa, requestFields(
        "GET",
        "https",
        "h",
        "/b",
        &.{},
        &buf,
    ), true));
}

test "http3 server: a request already in flight when GOAWAY is sent is reset, not served" {
    // The half of §5.2 that matters and that a local check cannot cover: a
    // request the client sent *before* learning of the GOAWAY. The promise the ID
    // makes is that such a request was not processed, so the client may retry it
    // on another connection — serving it anyway would make that promise false,
    // and a client that retried would have the request executed twice.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    // The server draws the line before anything has arrived, so the very first
    // request is already at or above it.
    try server.goaway(gpa, 0);

    // The client has not heard yet, so nothing stops it locally.
    var buf: [8]qpack.FieldLine = undefined;
    const id = try client.request(gpa, requestFields("GET", "https", "h", "/late", &.{}, &buf), true);
    try pumpH3(gpa, client, server, 8);

    // The server never took it on: no stream state, and no headers event.
    try testing.expect(!server.requests.contains(id));
    while (server.nextEvent()) |event| switch (event) {
        .headers => return error.RequestWasServedAnyway,
        else => {},
    };
    // And it is still up: refusing a request is not failing the connection.
    try testing.expect(server.close_code == null);

    // §4.1.1: the code says *rejected*, which is what licenses the client to retry
    // as though the request had never been sent. H3_REQUEST_CANCELLED would look
    // right and promise less, so the value is asserted rather than the fact that
    // some reset happened.
    const receiver = &client.transport.streams.get(.init(id)).?.recv.?;
    try testing.expectEqual(@as(?u64, 0x010b), receiver.reset_code);
}

test "http3 server: MAX_PUSH_ID is accepted and never acted on" {
    // §4.6: server push is optional. A server declines by never promising one,
    // not by rejecting the frame — a client offering permission is being
    // conformant, and failing the connection over it would break interop with
    // every client that sends it by default.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var payload: [16]u8 = undefined;
    var len = frame.writeFrameHeader(
        &payload,
        @backingInt(frame.FrameType.max_push_id),
        quic.varint.encodedLen(100),
    );
    len += quic.varint.encode(payload[len..], 100);
    _ = try client.transport.write(gpa, client.control_out.?, payload[0..len]);
    try pumpH3(gpa, client, server, 8);

    // Still up, and still no push stream in existence.
    try testing.expect(server.close_code == null);
    var buf: [8]qpack.FieldLine = undefined;
    _ = try client.request(gpa, requestFields("GET", "https", "h", "/", &.{}, &buf), true);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(server.close_code == null);
}

// ── Request cancellation (§4.1.1) ─────────────────────────────────────────────

test "http3: a cancelled request stops both directions" {
    // §4.1.1: "abruptly terminating any directions of a stream that are still
    // open". Both, and the test checks both, because either alone leaves the peer
    // working on an exchange nobody will finish.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var buf: [8]qpack.FieldLine = undefined;
    const id = try client.request(gpa, requestFields("GET", "https", "h", "/big", &.{}, &buf), false);
    try pumpH3(gpa, client, server, 8);
    while (server.nextEvent()) |_| {}

    // The response is no longer of interest.
    client.cancel(gpa, id, 0x010c); // H3_REQUEST_CANCELLED
    try pumpH3(gpa, client, server, 8);

    // The server was told to stop writing, and told the client had stopped reading.
    const sender = &server.transport.streams.get(.init(id)).?.send.?;
    try testing.expectEqual(@as(?u64, 0x010c), sender.stop_sending_code);
    const receiver = &server.transport.streams.get(.init(id)).?.recv.?;
    try testing.expectEqual(@as(?u64, 0x010c), receiver.reset_code);

    // And locally the exchange is gone rather than merely quiet.
    try testing.expect(!client.requests.contains(id));
}

test "http3: the reset code reaches the application" {
    // The distinction §4.1.1 draws is only usable if the code survives the trip:
    // H3_REQUEST_REJECTED licenses a retry, H3_REQUEST_CANCELLED does not.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var buf: [8]qpack.FieldLine = undefined;
    const id = try client.request(gpa, requestFields("GET", "https", "h", "/gone", &.{}, &buf), true);
    try pumpH3(gpa, client, server, 8);
    while (server.nextEvent()) |_| {}
    while (client.nextEvent()) |_| {}

    // The server refuses it without processing.
    server.cancel(gpa, id, 0x010b); // H3_REQUEST_REJECTED
    try pumpH3(gpa, client, server, 8);

    var saw: ?u64 = null;
    while (client.nextEvent()) |event| switch (event) {
        .stream_reset => |e| {
            try testing.expectEqual(id, e.stream);
            saw = e.code;
        },
        else => {},
    };
    try testing.expectEqual(@as(?u64, 0x010b), saw);
}

test "http3: cancelling twice, or after the end, does nothing" {
    // A cancel racing the last of a response is ordinary. It must not fail, and it
    // must not produce a second reset — §13.3 of RFC 9000 requires a RESET_STREAM's
    // content not to change once sent.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    // Left open: a request whose FIN has been acknowledged has a *terminal* sending
    // part, and §3.3 of RFC 9000 forbids RESET_STREAM from there — so that case
    // exercises the refusal in the transport rather than the idempotence here.
    var buf: [8]qpack.FieldLine = undefined;
    const id = try client.request(gpa, requestFields("GET", "https", "h", "/twice", &.{}, &buf), false);
    try pumpH3(gpa, client, server, 8);

    client.cancel(gpa, id, 0x010c);
    const first = client.transport.streams.get(.init(id)).?.send.?.reset_code;
    client.cancel(gpa, id, 0x0101); // a different code, deliberately
    const second = client.transport.streams.get(.init(id)).?.send.?.reset_code;
    try testing.expectEqual(first, second);
    try testing.expectEqual(@as(?u64, 0x010c), second);
}

test "http3: GOAWAY cleans up the streams it disowns" {
    // §5.2: "Upon sending a GOAWAY frame, the endpoint SHOULD explicitly cancel any
    // requests ... with identifiers greater than or equal to the one indicated, in
    // order to clean up transport state for the affected streams." Announcing the
    // line and leaving the streams open keeps state on both ends for exchanges
    // neither intends to finish.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    // Two requests in flight.
    var buf: [8]qpack.FieldLine = undefined;
    const first = try client.request(gpa, requestFields("GET", "https", "h", "/a", &.{}, &buf), true);
    const second = try client.request(gpa, requestFields("GET", "https", "h", "/b", &.{}, &buf), true);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(server.requests.contains(first));
    try testing.expect(server.requests.contains(second));

    // The line falls between them.
    try server.goaway(gpa, second);
    try testing.expect(server.requests.contains(first));
    try testing.expect(!server.requests.contains(second));

    try pumpH3(gpa, client, server, 8);
    // The client learns why, with the code that lets it retry elsewhere.
    var saw: ?u64 = null;
    while (client.nextEvent()) |event| switch (event) {
        .stream_reset => |e| if (e.stream == second) {
            saw = e.code;
        },
        else => {},
    };
    try testing.expectEqual(@as(?u64, 0x010b), saw);
}

// ── CONNECT tunnels (§4.4) ────────────────────────────────────────────────────

test "http3 server: a CONNECT tunnel carries DATA and nothing else" {
    // §4.4: "Once the CONNECT method has completed, only DATA frames are permitted
    // to be sent on the stream ... Receipt of any other known frame type MUST be
    // treated as a connection error of type H3_FRAME_UNEXPECTED." Without the rule a
    // tunnel accepts trailers, which puts field semantics into a byte stream a proxy
    // relays verbatim.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    // A CONNECT: authority and nothing else (§4.3.1).
    const connect = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    };
    const id = try client.request(gpa, &connect, false);
    try pumpH3(gpa, client, server, 8);

    // Accepted, and recognised as a tunnel.
    try testing.expect(server.requests.contains(id));
    try testing.expect(server.requests.get(id).?.tunnel);
    try testing.expect(server.close_code == null);

    // Tunnel bytes are fine.
    try client.writeBody(gpa, id, "tunnelled", false);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(server.close_code == null);

    // A reserved frame type still is: §7.2.8 permits them "on any stream where
    // frames are allowed", for padding, and §9 requires unknown types be ignored.
    // A tunnel that refuses one would break a peer padding its own traffic.
    var grease: [16]u8 = undefined;
    const grease_len = frame.writeFrameHeader(&grease, 0x21, 0); // 0x1f * 0 + 0x21
    _ = try client.transport.write(gpa, id, grease[0..grease_len]);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(server.close_code == null);

    // A HEADERS frame is not.
    const trailers = [_]qpack.FieldLine{.{ .name = "x-late", .value = "1" }};
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(gpa);
    try qpack.encodeSection(gpa, &encoded, &trailers);
    var header: [16]u8 = undefined;
    const header_len = frame.writeFrameHeader(
        &header,
        @backingInt(frame.FrameType.headers),
        encoded.items.len,
    );
    _ = try client.transport.write(gpa, id, header[0..header_len]);
    _ = try client.transport.write(gpa, id, encoded.items);
    pumpUntilFailure(gpa, client, server, 8);

    try testing.expectEqual(@as(?u64, 0x0105), server.close_code); // H3_FRAME_UNEXPECTED
}

test "http3 client: a refused CONNECT is not a tunnel" {
    // §4.4 makes a 2xx the signal that the tunnel is open. A refusal is an ordinary
    // response, and treating it as a tunnel would reject the trailers that any
    // ordinary response may carry — the distinction is not decoration.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    const connect = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    };
    const id = try client.request(gpa, &connect, false);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(client.requests.get(id).?.sent_connect);

    // The proxy declines.
    const refusal = [_]qpack.FieldLine{.{ .name = ":status", .value = "502" }};
    try server.respond(gpa, id, &refusal, false);
    try server.writeBody(gpa, id, "no tunnel", false);
    try pumpH3(gpa, client, server, 8);

    try testing.expect(!client.requests.get(id).?.tunnel);

    // So trailers are still legal on it.
    const trailers = [_]qpack.FieldLine{.{ .name = "x-reason", .value = "refused" }};
    try server.respond(gpa, id, &trailers, true);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(client.close_code == null);
}

test "http3 client: a 2xx to CONNECT makes the stream a tunnel" {
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    const connect = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    };
    const id = try client.request(gpa, &connect, false);
    try pumpH3(gpa, client, server, 8);

    const accepted = [_]qpack.FieldLine{.{ .name = ":status", .value = "200" }};
    try server.respond(gpa, id, &accepted, false);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(client.requests.get(id).?.tunnel);

    // Now a HEADERS frame from the proxy is a connection error.
    const trailers = [_]qpack.FieldLine{.{ .name = "x-late", .value = "1" }};
    try server.respond(gpa, id, &trailers, true);
    pumpUntilFailure(gpa, client, server, 8);
    try testing.expectEqual(@as(?u64, 0x0105), client.close_code);
}

// ── Extended CONNECT (RFC 9220) ───────────────────────────────────────────────

test "http3: extended CONNECT needs the peer's permission first" {
    // RFC 8441 §3, carried into HTTP/3 by RFC 9220 §3: the setting exists because
    // `:protocol` and the new reading of `:authority` change the meaning of an
    // existing message shape, and §9 of RFC 9114 requires that be negotiated. A
    // client that guesses does not get a polite refusal — §4.3 makes its request
    // malformed, so the stream is spent.
    const gpa = testing.allocator;
    var pair = try testPair(gpa); // the server does not advertise it
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    try testing.expect(!client.peerSettings().?.enable_connect_protocol);

    const upgrade = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.test" },
    };
    try testing.expectError(
        error.ExtendedConnectNotEnabled,
        client.request(gpa, &upgrade, false),
    );

    // An ordinary CONNECT is unaffected: it needs no extension.
    const plain = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    };
    _ = try client.request(gpa, &plain, false);
}

test "http3: an advertised setting makes extended CONNECT usable end to end" {
    const gpa = testing.allocator;
    var pair = try testPairWith(gpa, .{ .connect_protocol = true });
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    try testing.expect(client.peerSettings().?.enable_connect_protocol);
    // RFC 8441 §3: "Receipt of this parameter by a server does not have any
    // impact." So the client's side of the connection never advertises it.
    try testing.expect(!server.peerSettings().?.enable_connect_protocol);

    const upgrade = [_]qpack.FieldLine{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    const id = try client.request(gpa, &upgrade, false);
    try pumpH3(gpa, client, server, 8);

    // Accepted as a request, and §4.4's tunnel rules apply to it — the extended
    // form is still CONNECT.
    try testing.expect(server.close_code == null);
    try testing.expect(server.requests.get(id).?.tunnel);

    var section = server.takeSection(id) orelse return error.NoSection;
    defer section.deinit(gpa);
    var saw_protocol = false;
    for (section.fields.items) |field| {
        if (std.mem.eql(u8, field.name, ":protocol")) {
            try testing.expectEqualStrings("websocket", field.value);
            saw_protocol = true;
        }
    }
    try testing.expect(saw_protocol);
}

test "http3: a setting value other than 0 or 1 is a settings error" {
    // RFC 8441 §3: "The value of the parameter MUST be 0 or 1." The rule lives in
    // `SettingsIterator`, alongside §7.2.4's other payload rules, so this drives it
    // there — the connection inherits the wire code from the iterator's error, which
    // `frame.errorCode` maps to H3_SETTINGS_ERROR.
    var buf: [32]u8 = undefined;
    var len = quic.varint.encode(&buf, frame.Setting.enable_connect_protocol);
    len += quic.varint.encode(buf[len..], 2);
    var it = frame.SettingsIterator.init(buf[0..len]);
    try testing.expectError(error.SettingsError, it.next());
    try testing.expectEqual(@as(u64, 0x0109), frame.errorCode(error.SettingsError));

    // 0 and 1 both pass, and 0 means the extension stays off.
    for ([_]u64{ 0, 1 }) |value| {
        var ok_len = quic.varint.encode(&buf, frame.Setting.enable_connect_protocol);
        ok_len += quic.varint.encode(buf[ok_len..], value);
        var ok_it = frame.SettingsIterator.init(buf[0..ok_len]);
        var settings: frame.Settings = .{};
        settings.apply((try ok_it.next()).?);
        try testing.expectEqual(value == 1, settings.enable_connect_protocol);
    }

    // And the identifier is inside the duplicate mask: at 0x08 it sat one bit
    // outside the `u8` it used to be, so a repeat would have gone unnoticed.
    var dup_len = quic.varint.encode(&buf, frame.Setting.enable_connect_protocol);
    dup_len += quic.varint.encode(buf[dup_len..], 1);
    dup_len += quic.varint.encode(buf[dup_len..], frame.Setting.enable_connect_protocol);
    dup_len += quic.varint.encode(buf[dup_len..], 1);
    var dup_it = frame.SettingsIterator.init(buf[0..dup_len]);
    _ = try dup_it.next();
    try testing.expectError(error.SettingsError, dup_it.next());
}

test "http3: a FIN that arrives on its own still ends the request" {
    // §4.1: a client closes its sending side after the request, and QUIC is free to
    // carry that STREAM frame in a later packet than the data it follows. Every test
    // here, and both endpoints in this repository, happen to set the FIN together
    // with the last frame — so a peer that does not could leave a server waiting for
    // a request body that had already arrived in full.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var fields: [8]qpack.FieldLine = undefined;
    const request = requestFields("POST", "https", "example.test", "/upload", &.{}, &fields);
    const id = try client.request(gpa, request, false);
    try client.writeBody(gpa, id, "payload", false);
    // Deliberately delivered before the FIN exists, so the server consumes every
    // byte and then hears nothing more until the FIN arrives alone.
    try pumpH3(gpa, client, server, 8);

    var saw_end = false;
    while (server.nextEvent()) |event| switch (event) {
        .body => |e| {
            const chunk = server.readBody(e.stream);
            server.consumeBody(e.stream, chunk.len);
            if (e.fin) saw_end = true;
        },
        .headers => |e| {
            var section = server.takeSection(e.stream) orelse continue;
            section.deinit(gpa);
            if (e.fin) saw_end = true;
        },
        else => {},
    };
    try testing.expect(!saw_end); // nothing has ended yet

    try client.transport.finishStream(id);
    try pumpH3(gpa, client, server, 8);

    while (server.nextEvent()) |event| switch (event) {
        .body => |e| {
            const chunk = server.readBody(e.stream);
            server.consumeBody(e.stream, chunk.len);
            if (e.fin) saw_end = true;
        },
        else => {},
    };
    try testing.expect(saw_end);

    // And exactly once: a second delivery of the same FIN must not repeat it.
    try pumpH3(gpa, client, server, 4);
    while (server.nextEvent()) |event| switch (event) {
        .body => |e| try testing.expect(!e.fin),
        else => {},
    };
}

test "http3: a truncated frame at a clean stream end is a frame error" {
    // §7.1: "When a stream terminates cleanly, if the last frame on the stream was
    // truncated, this MUST be treated as a connection error of type H3_FRAME_ERROR."
    // A stream that ends mid-frame is not a short read to wait on — the peer has
    // promised bytes it will never send, and treating that as an ordinary end would
    // hand the application a message the sender never finished.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var fields: [8]qpack.FieldLine = undefined;
    const request = requestFields("POST", "https", "example.test", "/cut", &.{}, &fields);
    const id = try client.request(gpa, request, false);
    try pumpH3(gpa, client, server, 8);
    while (server.nextEvent()) |event| switch (event) {
        .headers => |e| {
            var section = server.takeSection(e.stream) orelse continue;
            section.deinit(gpa);
        },
        else => {},
    };

    // A DATA frame that claims eight bytes and delivers three, then a clean end.
    var header: [16]u8 = undefined;
    const header_len = frame.writeFrameHeader(&header, @backingInt(frame.FrameType.data), 8);
    _ = try client.transport.write(gpa, id, header[0..header_len]);
    _ = try client.transport.write(gpa, id, "abc");
    try client.transport.finishStream(id);
    pumpUntilFailure(gpa, client, server, 8);

    try testing.expectEqual(@as(?u64, 0x0106), server.close_code); // H3_FRAME_ERROR
}

test "http3: a frame header cut in half at a clean end is a frame error too" {
    // §7.1 covers a truncated *header*, not only a truncated payload: a two-byte type
    // varint with one byte delivered leaves the parser holding half a promise. This is
    // the case `midFrame` needs `header_len` for — the state alone still reads "between
    // frames", since no type has been decoded yet.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var fields: [8]qpack.FieldLine = undefined;
    const request = requestFields("POST", "https", "example.test", "/half", &.{}, &fields);
    const id = try client.request(gpa, request, false);
    try pumpH3(gpa, client, server, 8);
    while (server.nextEvent()) |event| switch (event) {
        .headers => |e| {
            var section = server.takeSection(e.stream) orelse continue;
            section.deinit(gpa);
        },
        else => {},
    };

    // 0x4242 is a two-byte varint; only its first byte goes out.
    var header: [16]u8 = undefined;
    const header_len = frame.writeFrameHeader(&header, 0x4242, 0);
    try testing.expect(header_len > 1);
    _ = try client.transport.write(gpa, id, header[0..1]);
    try client.transport.finishStream(id);
    pumpUntilFailure(gpa, client, server, 8);

    try testing.expectEqual(@as(?u64, 0x0106), server.close_code); // H3_FRAME_ERROR
}

test "http3: a frame delivered in pieces before a clean end is not truncated" {
    // The false positive the first version of `midFrame` had: the parser keeps the
    // completed frame's payload in its accumulation buffer, because the item it just
    // returned borrows it. A peer whose HEADERS frame arrived in two QUIC packets and
    // then ended the stream is delivering legally, and must not be told otherwise.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(gpa);
    try qpack.encodeSection(gpa, &encoded, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/split" },
    });
    var header: [16]u8 = undefined;
    const header_len = frame.writeFrameHeader(
        &header,
        @backingInt(frame.FrameType.headers),
        encoded.items.len,
    );
    const id = try client.transport.openStream(gpa, true);
    _ = try client.transport.write(gpa, id, header[0..header_len]);
    // The payload in two deliveries, each pumped, so the parser has to accumulate.
    _ = try client.transport.write(gpa, id, encoded.items[0 .. encoded.items.len / 2]);
    try pumpH3(gpa, client, server, 4);
    _ = try client.transport.write(gpa, id, encoded.items[encoded.items.len / 2 ..]);
    try pumpH3(gpa, client, server, 4);
    try client.transport.finishStream(id);
    try pumpH3(gpa, client, server, 8);

    try testing.expect(server.close_code == null);
}

test "http3: a stream ending between frames is not a frame error" {
    // The other side of §7.1, and the one that keeps the check from being a blanket
    // refusal: a stream may end at a frame boundary, and that is the ordinary case.
    // A `midFrame` that answered "yes" too eagerly would fail every request.
    const gpa = testing.allocator;
    var pair = try testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var fields: [8]qpack.FieldLine = undefined;
    const request = requestFields("POST", "https", "example.test", "/whole", &.{}, &fields);
    const id = try client.request(gpa, request, false);
    try client.writeBody(gpa, id, "complete", false);
    // Separately, so the FIN arrives with the buffer already drained — the path the
    // previous commit added, now also carrying the §7.1 check.
    try pumpH3(gpa, client, server, 8);
    try client.transport.finishStream(id);
    try pumpH3(gpa, client, server, 8);

    try testing.expect(server.close_code == null);
    var ended = false;
    while (server.nextEvent()) |event| switch (event) {
        .headers => |e| {
            var section = server.takeSection(e.stream) orelse continue;
            section.deinit(gpa);
            if (e.fin) ended = true;
        },
        .body => |e| {
            const chunk = server.readBody(e.stream);
            server.consumeBody(e.stream, chunk.len);
            if (e.fin) ended = true;
        },
        else => {},
    };
    try testing.expect(ended);
}

test "http3: a bodyless request reports its end once, whichever packet the FIN rides in" {
    // The three-way contract on `Event`, stated as a test because the connection fuzz
    // target found the two deliveries disagreeing about it and nothing had written it
    // down: a request with no body ends either on `headers.fin`, when the FIN arrived
    // with the field section, or on a `body` event carrying no bytes, when it arrived
    // afterwards. Exactly once, either way.
    const gpa = testing.allocator;

    for ([_]bool{ true, false }) |fin_with_headers| {
        var pair = try testPair(gpa);
        const client = &pair.client;
        const server = &pair.server;
        defer client.deinit(gpa);
        defer server.deinit(gpa);
        try pumpH3(gpa, client, server, 16);

        var fields: [8]qpack.FieldLine = undefined;
        const request = requestFields("GET", "https", "example.test", "/none", &.{}, &fields);
        const id = try client.request(gpa, request, fin_with_headers);
        try pumpH3(gpa, client, server, 8);
        if (!fin_with_headers) {
            // The FIN on its own, after the field section was consumed.
            try client.transport.finishStream(id);
            try pumpH3(gpa, client, server, 8);
        }

        var ends: usize = 0;
        var sections: usize = 0;
        var body_bytes: usize = 0;
        while (server.nextEvent()) |event| switch (event) {
            .headers => |e| {
                var section = server.takeSection(e.stream) orelse continue;
                section.deinit(gpa);
                sections += 1;
                if (e.fin) ends += 1;
            },
            .body => |e| {
                const chunk = server.readBody(e.stream);
                body_bytes += chunk.len;
                server.consumeBody(e.stream, chunk.len);
                if (e.fin) ends += 1;
            },
            else => {},
        };

        try testing.expectEqual(@as(usize, 1), sections);
        try testing.expectEqual(@as(usize, 0), body_bytes);
        try testing.expectEqual(@as(usize, 1), ends);
        try testing.expect(server.close_code == null);
    }
}

test "http3: RFC 9297 datagrams travel with their stream, and the rules that bound them" {
    // The mapping in one test: SETTINGS_H3_DATAGRAM in both directions, the Quarter
    // Stream ID in front of the payload, and each of §2.1's drop rules.
    const gpa = testing.allocator;
    var pair = try testPairWith(gpa, .{ .datagram = true });
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    // §2.1.1: both sent and received with a value of 1, *and* RFC 9221 §3's transport
    // parameter — either missing means datagrams stay unusable.
    try testing.expect(client.peerSettings().?.h3_datagram);
    try testing.expect(client.datagramsAllowed());
    try testing.expect(server.datagramsAllowed());

    var fields: [8]qpack.FieldLine = undefined;
    // Two requests, and the datagram goes on the *second*. Stream 0 has a Quarter
    // Stream ID of 0, so a mapping that forgot the prefix entirely would look correct
    // on it — the first version of this test used stream 0 and did not notice.
    _ = try client.request(
        gpa,
        requestFields("POST", "https", "example.test", "/first", &.{}, &fields),
        false,
    );
    const stream = try client.request(
        gpa,
        requestFields("POST", "https", "example.test", "/flow", &.{}, &fields),
        false, // the send side stays open: §2.1 requires it for sending datagrams
    );
    try testing.expect(stream > 0);
    try testing.expectEqual(@as(u64, 1), stream / 4);
    try pumpH3(gpa, client, server, 8);
    // The server has to know the stream before a datagram for it can be delivered.
    while (server.nextEvent()) |_| {}

    // §2.1: the association is the stream ID divided by four, in front of the payload.
    try client.sendDatagram(gpa, stream, "tick");
    try pumpH3(gpa, client, server, 8);

    var got: ?struct { stream: u64, len: usize } = null;
    while (server.nextEvent()) |event| switch (event) {
        .datagram => |d| got = .{ .stream = d.stream, .len = d.len },
        else => {},
    };
    try testing.expectEqual(stream, got.?.stream);
    const received = server.readDatagram().?;
    try testing.expectEqual(stream, received.stream);
    try testing.expectEqualStrings("tick", received.payload);
    server.consumeDatagram(gpa);

    // And back the other way, which is what makes them bidirectional (§2).
    try server.sendDatagram(gpa, stream, "tock");
    try pumpH3(gpa, client, server, 8);
    var back: ?[]const u8 = null;
    while (client.nextEvent()) |event| switch (event) {
        .datagram => back = client.readDatagram().?.payload,
        else => {},
    };
    try testing.expectEqualStrings("tock", back.?);
    client.consumeDatagram(gpa);

    // §2.1: a Quarter Stream ID naming a stream that does not exist is dropped
    // silently, not an error — "SHALL either drop that datagram silently or buffer it".
    const dropped_before = server.datagrams_dropped;
    var unknown: [9]u8 = undefined;
    // Quarter 1024, so stream 4096 — a client-initiated bidirectional ID that exists in
    // the numbering and not on this connection.
    const unknown_len = quic.varint.encode(&unknown, 1024);
    unknown[unknown_len] = 'x';
    try client.transport.sendDatagram(gpa, unknown[0 .. unknown_len + 1]);
    try pumpH3(gpa, client, server, 8);
    try testing.expect(server.datagrams_dropped > dropped_before);

    // §2.1: "the largest legal value of the Quarter Stream ID field is 2^60-1", and a
    // larger one is a connection error of type H3_DATAGRAM_ERROR — not a drop, because
    // a value that cannot name a stream means the peer is not speaking this mapping.
    var oversized: [9]u8 = undefined;
    const n = quic.varint.encode(&oversized, (@as(u64, 1) << 60));
    try client.transport.sendDatagram(gpa, oversized[0..n]);
    pumpUntilFailure(gpa, client, server, 4);
    try testing.expectEqual(@as(?u64, frame.errorCode(error.DatagramError)), server.close_code);
    try testing.expectEqual(@as(u64, 0x33), frame.errorCode(error.DatagramError));
}

test "http3: datagrams need the setting from both sides, and an open send side" {
    // The two refusals §2.1 and §2.1.1 require, and they are refusals rather than
    // silent drops because a caller that cannot send needs to know before it builds a
    // protocol on top.
    const gpa = testing.allocator;

    // A pair that never advertised the setting.
    var plain = try testPair(gpa);
    defer plain.client.deinit(gpa);
    defer plain.server.deinit(gpa);
    try pumpH3(gpa, &plain.client, &plain.server, 16);
    try testing.expect(!plain.client.datagramsAllowed());
    try testing.expectError(
        error.DatagramsUnsupported,
        plain.client.sendDatagram(gpa, 0, "x"),
    );

    var pair = try testPairWith(gpa, .{ .datagram = true });
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    try pumpH3(gpa, client, server, 16);

    var fields: [8]qpack.FieldLine = undefined;
    const stream = try client.request(
        gpa,
        requestFields("GET", "https", "example.test", "/done", &.{}, &fields),
        true, // finished sending, which §2.1 makes the disqualifying condition
    );
    try testing.expectError(
        error.DatagramStreamClosed,
        client.sendDatagram(gpa, stream, "too late"),
    );

    // §2.1: the association is a client-initiated bidirectional stream, so an ID that
    // is not one cannot be named by a Quarter Stream ID at all.
    try testing.expectError(
        error.DatagramStreamInvalid,
        client.sendDatagram(gpa, 3, "wrong kind"),
    );

    // §2.1.1 in isolation: the *setting* must have been received with a value of 1, and
    // that is a separate negotiation from RFC 9221's transport parameter. Cleared
    // directly, because a pair that disabled both would pass this check for the wrong
    // reason — which is what the first version of this test did.
    const open_stream = try client.request(
        gpa,
        requestFields("POST", "https", "example.test", "/still-open", &.{}, &fields),
        false,
    );
    try client.sendDatagram(gpa, open_stream, "fine");
    try testing.expect(client.transport.datagramsAllowed());
    client.peer_settings.?.h3_datagram = false;
    try testing.expect(!client.datagramsAllowed());
    try testing.expectError(
        error.DatagramsUnsupported,
        client.sendDatagram(gpa, open_stream, "not fine"),
    );
}
