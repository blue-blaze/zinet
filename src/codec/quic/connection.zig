//! A QUIC connection: datagrams in, events out, no sockets involved.
//!
//! The same shape as `http2/connection.zig` and for the same reason — everything
//! interesting about a protocol is testable without I/O if the layer that speaks
//! it never touches a socket. `receive` takes one UDP payload; `send` fills one.
//! Task 12 attaches those two to a datagram endpoint.
//!
//! This layer owns the parts of RFC 9000 that make a handshake reach the far end:
//! packet assembly and coalescing (§12.2), the CRYPTO stream's reassembly (§7.5),
//! Retry and address validation (§8.1, §17.2.5), and the §7.3 connection ID
//! check that authenticates packet headers. Streams and flow control are the next
//! layer up; loss recovery and congestion control the one after. Both are absent
//! here rather than stubbed, and the two places it shows are marked: ACK
//! generation reports a single range, and nothing is retransmitted.
//!
//! **Randomness and time are parameters, not calls.** Connection IDs come from
//! the caller, as does the handshake seed, so a whole handshake is reproducible
//! byte for byte in a test. That is the same rule the rest of the repository
//! follows for `std.Io` and the clock, applied to the two other things a QUIC
//! connection would otherwise reach for globally.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const client = @import("client.zig");
const crypto = @import("crypto.zig");
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const transport = @import("transport.zig");
const varint = @import("varint.zig");
const cid_mod = @import("cid.zig");

const ConnectionId = packet.ConnectionId;
const Level = client.Level;

pub const Error = error{
    /// §7.5: more out-of-order CRYPTO data than the buffer allows. A real limit:
    /// without it a peer sends one byte at a huge offset and we allocate to
    /// match.
    CryptoBufferExceeded,
    /// §7.3: the peer's transport parameters disagree with the packet headers.
    ConnectionIdMismatch,
    /// The peer violated a rule that leaves no way to continue.
    ProtocolViolation,
    /// §6.2: the server offers no version we speak. There is nothing to fall
    /// back to, so the connection ends.
    VersionNegotiationFailed,
    /// A datagram we were asked to write does not fit the buffer given.
    BufferTooSmall,
    /// §10.3: the peer sent a stateless reset. Not an error in the protocol
    /// sense — the peer lost its state — but the connection is over.
    StatelessReset,
    /// The connection is closed and will not send or receive again.
    ConnectionClosed,
};

/// §14.1: any datagram containing an Initial packet that a client sends must be
/// at least this large. It is an anti-amplification rule rather than an MTU one:
/// the server may send no more than three times what it has received from an
/// unvalidated address, so a small Initial would cap the server's first flight
/// below the size of a certificate chain. Forgetting it looks like a server that
/// silently ignores the connection.
pub const min_initial_datagram = 1200;

/// The largest datagram this implementation will send. §14 requires an endpoint
/// to work with 1200 and permits probing higher; probing is path MTU discovery,
/// which belongs with loss recovery.
pub const max_datagram = 1452;

/// §7.5's bound on held-back CRYPTO data. Sized for a certificate chain arriving
/// entirely out of order, which is the worst legitimate case.
pub const max_crypto_pending = 64 * 1024;

/// §19.7 sets no bound on a NEW_TOKEN, so this one is ours. A token is opaque and
/// only ever handed back, so a cap costs nothing but refusing an oversized one
/// keeps a server from choosing how much we store.
pub const max_token_len = 512;

/// CONNECTION_CLOSE reason phrases are diagnostics, so a long one is truncated
/// rather than refused: the error code is what the connection acts on.
pub const max_reason_len = 256;

/// What the connection tells its caller. Every slice borrows storage inside the
/// connection and is valid until the next call to `receive` or `send` — the same
/// contract as an `Event` in the pipeline, and stated because the alternative is
/// an allocation per event.
pub const Event = union(enum) {
    /// The handshake finished and the peer is authenticated. `alpn` is what was
    /// negotiated; for HTTP/3 it is "h3".
    established: struct { alpn: []const u8 },
    /// §19.7: a token to present on the next connection to this server, which
    /// lets that one skip address validation. Worth surfacing rather than
    /// keeping, because it outlives the connection.
    new_token: []const u8,
    /// The peer closed. `application` distinguishes §19.19 from §19.20, which
    /// matters because an application error code means something only to the
    /// application.
    peer_closed: struct { code: u64, application: bool, reason: []const u8 },
    /// §10.3: the peer has lost its state.
    stateless_reset,
    /// A Retry was accepted and the handshake restarted. Surfaced because it
    /// changes the connection ID and invalidates any packet already in flight.
    retry_received,
};

pub const Options = struct {
    /// Sent as SNI and matched against the certificate.
    host: []const u8,
    /// RFC 9001 §8.1: mandatory. For HTTP/3, "h3".
    alpn: []const []const u8,
    /// Our own transport parameters. `initial_source_connection_id` is filled in
    /// from `local_cid`, so a caller cannot set the two inconsistently.
    parameters: transport.Parameters,
    /// How to authenticate the server. Null skips it and has to be written down.
    verification: ?@import("verify.zig").Options,
    /// The connection ID we will be addressed by. Chosen by the caller because
    /// it must be unpredictable, and this layer takes its randomness as a
    /// parameter rather than reaching for a global source.
    local_cid: ConnectionId,
    /// §7.2: the Destination Connection ID for our first Initial packet, chosen
    /// at random by the client. Both endpoints derive Initial keys from it, so it
    /// is also the only secret protecting Initial packets — which is to say it
    /// protects nothing against anyone who saw it, and that is by design.
    initial_destination: ConnectionId,
    /// §8.1: a token from a previous connection or a Retry, replayed to skip
    /// address validation. Empty is normal.
    token: []const u8 = &.{},
};

/// One packet number space: RFC 9000 §12.3 has three, and 0-RTT shares the
/// application space with 1-RTT.
const Space = struct {
    send: ?crypto.Keys = null,
    recv: ?crypto.Keys = null,
    /// The next packet number to use. §17.2.5.3: never reset, not even after a
    /// Retry, because the peer may have seen the earlier numbers.
    next_pn: u64 = 0,
    /// Largest we have had acknowledged, which decides how many bytes of packet
    /// number to send (§17.1).
    largest_acked: ?u64 = null,
    /// Largest we have received, which is what we acknowledge.
    largest_received: ?u64 = null,
    /// Whether something ack-eliciting has arrived since we last acknowledged.
    ack_pending: bool = false,
    /// How far our own CRYPTO stream has been put into packets. Not consumed
    /// from the TLS engine's buffer until the handshake is done, because a Retry
    /// requires resending the ClientHello byte for byte — rewinding this offset
    /// *is* that resend.
    crypto_sent: u64 = 0,
    /// Inbound CRYPTO reassembly.
    crypto: CryptoStream = .{},

    fn deinit(self: *Space, gpa: Allocator) void {
        self.crypto.deinit(gpa);
    }
};

/// Reassembly for one encryption level's CRYPTO stream (§7.5).
///
/// The TLS engine requires bytes in order, and CRYPTO frames may arrive out of
/// order, so the gap has to be held. The common case — everything in order —
/// allocates nothing: bytes go straight through and only the offset advances.
const CryptoStream = struct {
    /// How many bytes have been handed to the TLS engine.
    consumed: u64 = 0,
    /// Out-of-order data, kept sorted by offset.
    pending: std.ArrayList(Chunk) = .empty,
    /// Total bytes held, against `max_crypto_pending`.
    buffered: usize = 0,

    const Chunk = struct {
        offset: u64,
        bytes: []u8,
    };

    fn deinit(self: *CryptoStream, gpa: Allocator) void {
        for (self.pending.items) |chunk| gpa.free(chunk.bytes);
        self.pending.deinit(gpa);
    }

    /// Take one CRYPTO frame's data, delivering whatever is now contiguous.
    fn accept(
        self: *CryptoStream,
        gpa: Allocator,
        offset: u64,
        data: []const u8,
        engine: *client.Client,
        level: Level,
    ) !void {
        if (data.len == 0) return;

        // Wholly old: a retransmission of something already delivered. Normal.
        if (offset + data.len <= self.consumed) return;

        if (offset <= self.consumed) {
            const skip: usize = @intCast(self.consumed - offset);
            const fresh = data[skip..];
            try engine.provide(gpa, level, fresh);
            self.consumed += fresh.len;
            try self.drain(gpa, engine, level);
            return;
        }

        // A gap: hold it. The copy is not optional — `data` points into the
        // caller's datagram, which is reused for the next one. This is the rule
        // that has now caught defects twice in this repository, in HTTP/2 header
        // values and in the negotiated ALPN.
        if (self.buffered + data.len > max_crypto_pending) return error.CryptoBufferExceeded;
        const copy = try gpa.dupe(u8, data);
        errdefer gpa.free(copy);

        var index: usize = 0;
        while (index < self.pending.items.len and self.pending.items[index].offset < offset) {
            index += 1;
        }
        try self.pending.insert(gpa, index, .{ .offset = offset, .bytes = copy });
        self.buffered += data.len;
    }

    fn drain(
        self: *CryptoStream,
        gpa: Allocator,
        engine: *client.Client,
        level: Level,
    ) !void {
        while (self.pending.items.len > 0) {
            const chunk = self.pending.items[0];
            if (chunk.offset > self.consumed) return;

            defer {
                gpa.free(chunk.bytes);
                self.buffered -= chunk.bytes.len;
                _ = self.pending.orderedRemove(0);
            }

            if (chunk.offset + chunk.bytes.len <= self.consumed) continue; // fully old
            const skip: usize = @intCast(self.consumed - chunk.offset);
            const fresh = chunk.bytes[skip..];
            try engine.provide(gpa, level, fresh);
            self.consumed += fresh.len;
        }
    }
};

pub const Connection = struct {
    engine: client.Client,
    spaces: [Level.count]Space = .{ .{}, .{}, .{} },

    /// Ours, the peer's, and the bookkeeping §7.3 checks against.
    local: cid_mod.Local,
    remote: cid_mod.Remote,
    /// §7.2: what we put in our first Initial, kept because Initial keys derive
    /// from it and because §7.3 compares the server's report against it.
    original_destination: ConnectionId,
    /// The Source Connection ID from a Retry, if one happened.
    retry_source: ?ConnectionId = null,

    parameters: transport.Parameters,
    peer_parameters: ?transport.Parameters = null,

    /// §8.1's address validation token, replayed in every Initial we send.
    token_buf: [max_token_len]u8 = undefined,
    token_len: usize = 0,

    /// §17.2.5.2: at most one Retry, and only before any other server packet.
    retry_seen: bool = false,
    server_packet_seen: bool = false,
    /// §7.2: whether a valid Initial packet has arrived from the server, which is
    /// the moment the destination connection ID becomes fixed.
    server_initial_seen: bool = false,

    established: bool = false,
    /// §4.1.2 of RFC 9001: the server's HANDSHAKE_DONE confirms the handshake,
    /// which is when Initial and Handshake keys may be discarded.
    handshake_confirmed: bool = false,
    closed: bool = false,
    /// A CONNECTION_CLOSE we owe the peer.
    pending_close: ?struct { code: u64, application: bool } = null,

    events: std.ArrayList(Event) = .empty,
    /// Storage the events borrow. A fixed buffer rather than an allocation per
    /// event, which is why `Event`'s slices are documented as valid only until
    /// the next call.
    reason_buf: [max_reason_len]u8 = undefined,
    event_token_buf: [max_token_len]u8 = undefined,

    pub fn initClient(options: Options, seed: [64]u8) !Connection {
        var parameters = options.parameters;
        // §7.3: this is not the caller's to choose. It must be the connection ID
        // we are actually addressed by, or the peer's check fails for a reason
        // that looks like an attack.
        parameters.initial_source_connection_id = options.local_cid;

        var encoded: [512]u8 = undefined;
        const params_len = transport.encode(&encoded, &parameters, .client);

        var self: Connection = .{
            .engine = try client.Client.init(.{
                .host = options.host,
                .alpn = options.alpn,
                .transport_parameters = encoded[0..params_len],
                .verification = options.verification,
            }, seed),
            .local = .init(options.local_cid),
            .remote = .init(options.initial_destination, parameters.active_connection_id_limit),
            .original_destination = options.initial_destination,
            .parameters = parameters,
        };

        if (options.token.len > max_token_len) return error.BufferTooSmall;
        @memcpy(self.token_buf[0..options.token.len], options.token);
        self.token_len = options.token.len;

        // §5.2: Initial keys come from the client's chosen destination connection
        // ID, and both ends use that same value even after the server picks its
        // own.
        const initial = crypto.InitialKeys.derive(options.initial_destination.slice());
        self.spaces[@backingInt(Level.initial)].send = initial.client;
        self.spaces[@backingInt(Level.initial)].recv = initial.server;

        return self;
    }

    pub fn deinit(self: *Connection, gpa: Allocator) void {
        for (&self.spaces) |*space| space.deinit(gpa);
        self.engine.deinit(gpa);
        self.events.deinit(gpa);
        self.* = undefined;
    }

    /// Begin: produces the ClientHello into the Initial space.
    pub fn start(self: *Connection, gpa: Allocator) !void {
        try self.engine.start(gpa);
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.established;
    }

    pub fn peerParameters(self: *const Connection) ?transport.Parameters {
        return self.peer_parameters;
    }

    /// The token to keep for a future connection, if the server gave one.
    pub fn addressToken(self: *const Connection) []const u8 {
        return self.token_buf[0..self.token_len];
    }

    pub fn nextEvent(self: *Connection) ?Event {
        if (self.events.items.len == 0) return null;
        return self.events.orderedRemove(0);
    }

    /// Ask to close, which will be sent by the next `send`.
    pub fn close(self: *Connection, code: u64, application: bool) void {
        if (self.closed) return;
        self.pending_close = .{ .code = code, .application = application };
    }

    fn spaceFor(self: *Connection, level: Level) *Space {
        return &self.spaces[@backingInt(level)];
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// Process one UDP payload.
    ///
    /// Packets that cannot be decrypted are dropped silently, not reported:
    /// RFC 9001 §5.3 requires it, because an off-path attacker who could kill a
    /// connection with one forged packet would need no other capability.
    pub fn receive(self: *Connection, gpa: Allocator, datagram: []const u8) !void {
        if (self.closed) return;

        // §10.3: a stateless reset is indistinguishable from a short-header
        // packet until the last 16 bytes are compared against a token we hold, so
        // it is checked before parsing rather than after failing to.
        if (datagram.len >= 21) {
            const candidate = datagram[datagram.len - cid_mod.stateless_reset_token_len ..];
            if (self.remote.matchesResetToken(candidate[0..cid_mod.stateless_reset_token_len])) {
                self.closed = true;
                try self.events.append(gpa, .stateless_reset);
                return;
            }
        }

        var offset: usize = 0;
        while (offset < datagram.len) {
            // §12.2: coalesced packets. A parse failure ends the datagram rather
            // than the connection — the rest is not necessarily addressed to us,
            // and §12.2 says an endpoint that cannot process a packet skips the
            // remainder.
            const parsed = packet.parse(datagram[offset..], self.local.initialId().len) catch return;
            const slice = datagram[offset..][0..parsed.end];
            offset += parsed.end;

            switch (parsed.packet) {
                .version_negotiation => |vn| {
                    // §6.2: discard it outright once any other packet has been
                    // processed. Otherwise an attacker who can inject one packet
                    // could tear down an established connection — and unlike a
                    // protected packet, this one carries no authentication at all.
                    if (self.server_packet_seen) return;
                    // §6.2: a Version Negotiation listing the version we already
                    // sent is invalid and must be discarded, because a genuine
                    // server would have answered normally instead.
                    if (vn.offers(.v1)) return;
                    // We speak exactly one version, so there is nothing to fall
                    // back to. This ends the attempt rather than being ignored.
                    self.closed = true;
                    return error.VersionNegotiationFailed;
                },
                .retry => |retry| try self.handleRetry(gpa, retry, slice),
                .protected => |protected| try self.handleProtected(gpa, protected, slice),
            }
        }
    }

    fn handleRetry(
        self: *Connection,
        gpa: Allocator,
        retry: packet.Retry,
        slice: []const u8,
    ) !void {
        // §17.2.5.2: a client accepts at most one Retry, and none after any other
        // server packet has been processed. Both halves close the same hole: a
        // Retry costs us a full ClientHello resend, so an attacker able to inject
        // them repeatedly would have an amplification lever.
        if (self.retry_seen or self.server_packet_seen) return;

        // §5.8: the integrity tag is computed over a pseudo-packet that includes
        // the *original* destination connection ID. Including it is what stops a
        // captured Retry from being replayed into a different connection.
        const without_tag = slice[0 .. slice.len - packet.retry_integrity_tag_len];
        if (!crypto.verifyRetry(
            self.original_destination.slice(),
            without_tag,
            retry.integrity_tag,
        )) return; // forged: drop, do not fail

        // §17.2.5.2: a zero-length token is discarded — there would be nothing
        // to replay, so the Retry would cost a round trip and achieve nothing.
        if (retry.token.len == 0 or retry.token.len > max_token_len) return;

        // §17.2.5.1: the Retry's Source Connection ID must differ from what we
        // used as our destination. If a server echoed it back, re-deriving
        // Initial keys would produce the same keys and the "new" handshake would
        // be indistinguishable from the old one — so this is discarded rather
        // than followed.
        if (retry.source.eql(&self.original_destination)) return;

        @memcpy(self.token_buf[0..retry.token.len], retry.token);
        self.token_len = retry.token.len;
        self.retry_seen = true;
        self.retry_source = retry.source;

        // §7.3: the peer must later report this, which is what makes an injected
        // Retry detectable after the fact even if it got past the tag.
        self.remote = .init(retry.source, self.parameters.active_connection_id_limit);

        // §5.2: Initial keys are re-derived from the Retry's Source Connection
        // ID, which is now our destination.
        const keys = crypto.InitialKeys.derive(retry.source.slice());
        const initial = self.spaceFor(.initial);
        initial.send = keys.client;
        initial.recv = keys.server;

        // Resend the ClientHello byte for byte. **This is the difference from a
        // HelloRetryRequest**: a Retry does not enter the TLS transcript, so the
        // ClientHello must be identical and the transcript untouched. Rewinding
        // the send offset is that resend, and it is why this layer does not
        // consume the engine's output until the handshake finishes.
        initial.crypto_sent = 0;

        // §17.2.5.3: packet numbers are *not* reset. The peer may have seen the
        // earlier ones, and reusing a number would reuse an AEAD nonce.
        try self.events.append(gpa, .retry_received);
    }

    fn handleProtected(
        self: *Connection,
        gpa: Allocator,
        protected: packet.Protected,
        slice: []const u8,
    ) !void {
        if (!protected.version.isSupported()) return;

        const level: Level = switch (protected.long_type orelse .zero_rtt) {
            .initial => .initial,
            .handshake => .handshake,
            // A client never receives 0-RTT, and a short header is 1-RTT.
            .zero_rtt => if (protected.long_type == null) .one_rtt else return,
            .retry => return,
        };

        const sp = self.spaceFor(level);
        // No keys for this level yet: drop. This is the ordinary case for a
        // Handshake packet coalesced with the Initial that carries the keys for
        // it — which is why it is not an error. A real implementation may buffer
        // here; dropping costs a retransmission and keeps the state machine
        // small enough to reason about.
        var recv_keys = sp.recv orelse return;

        // A short header is only ours if its destination connection ID is.
        if (protected.long_type == null and !self.local.accepts(&protected.destination)) return;

        if (level == .initial) {
            // §7.2: once a valid Initial has arrived from the server, a later one
            // with a *different* Source Connection ID must be discarded. Without
            // this, anyone able to inject a packet could move the connection to a
            // connection ID of their choosing, and every subsequent packet we sent
            // would be addressed wherever they liked.
            if (self.server_initial_seen and !protected.source.eql(&self.remote.active())) return;

            // §17.2.2: a server's Initial packet must carry no token. A non-empty
            // one means the peer is confused about which role it has, and §17.2.2
            // permits discarding rather than failing — which is the right choice
            // for a packet whose protection anyone who saw the handshake can forge.
            if (protected.token.len != 0) return;
        }

        var work: [max_datagram]u8 = undefined;
        if (slice.len > work.len) return;
        @memcpy(work[0..slice.len], slice);
        const buf = work[0..slice.len];

        const pn_len = crypto.unprotectHeader(buf, protected.pn_offset, &recv_keys.header);
        const truncated = readPacketNumber(buf[protected.pn_offset..][0..pn_len]);
        const pn = packet.decodePacketNumber(sp.largest_received, truncated, pn_len);

        const header = buf[0 .. protected.pn_offset + pn_len];
        const body_start = protected.pn_offset + pn_len;
        const body_end = protected.pn_offset + protected.remainder_len;
        if (body_end > buf.len or body_start > body_end) return;

        var plain: [max_datagram]u8 = undefined;
        const plain_len = recv_keys.open(
            &plain,
            pn,
            header,
            buf[body_start..body_end],
        ) catch {
            // §5.3: a failure to decrypt is a discarded packet, never a
            // connection error. Write the counter back so the integrity limit in
            // §6.6 keeps counting across packets.
            sp.recv = recv_keys;
            return;
        };
        sp.recv = recv_keys;

        // Only now is the packet known to be genuine, so only now may it change
        // any state. Everything above this line is reversible — and that ordering
        // is the point: state changed by an unauthenticated packet is state an
        // attacker controls.
        self.server_packet_seen = true;

        if (level == .initial) {
            // §7.2: the server's first Initial packet chooses the connection ID
            // the client uses from then on. **A client may have to change this
            // twice during establishment** — once for a Retry and once for the
            // server's Initial — which is why accepting the Retry above does not
            // fix it. Getting that wrong breaks only handshakes that involve a
            // Retry, so it would pass every test against a server that never
            // sends one.
            if (!self.server_initial_seen) {
                self.remote = .init(protected.source, self.parameters.active_connection_id_limit);
                self.server_initial_seen = true;
            }
        }
        if (sp.largest_received == null or pn > sp.largest_received.?) {
            sp.largest_received = pn;
        }

        try self.handleFrames(gpa, level, plain[0..plain_len]);
    }

    fn handleFrames(
        self: *Connection,
        gpa: Allocator,
        level: Level,
        payload: []const u8,
    ) !void {
        const frame_space: frame.Space = switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .one_rtt => .one_rtt,
        };

        var rest = payload;
        while (rest.len > 0) {
            const f = frame.parse(&rest) catch return error.ProtocolViolation;

            // §12.4: not bookkeeping. This is what stops application data from
            // riding in an unauthenticated Initial packet.
            if (!f.allowedIn(frame_space)) return error.ProtocolViolation;

            if (f.isAckEliciting()) self.spaceFor(level).ack_pending = true;

            switch (f) {
                .padding, .ping => {},
                .ack => |ack| {
                    var it = ack.iterator();
                    const sp = self.spaceFor(level);
                    while (it.next()) |range| {
                        if (sp.largest_acked == null or range.largest > sp.largest_acked.?) {
                            sp.largest_acked = range.largest;
                        }
                    }
                },
                .crypto => |c| {
                    const sp = self.spaceFor(level);
                    try sp.crypto.accept(gpa, c.offset, c.data, &self.engine, level);
                    try self.afterHandshakeProgress(gpa);
                },
                .new_token => |token| {
                    if (token.len > max_token_len) return error.ProtocolViolation;
                    @memcpy(self.event_token_buf[0..token.len], token);
                    try self.events.append(gpa, .{ .new_token = self.event_token_buf[0..token.len] });
                },
                .new_connection_id => |n| {
                    // §19.15: an endpoint that chose a zero-length connection ID
                    // has said it is not addressed by ID, so being given more is
                    // a contradiction rather than a courtesy.
                    if (!self.local.usesConnectionIds()) return error.ProtocolViolation;
                    const issued = ConnectionId.init(n.id) catch
                        return error.ProtocolViolation;
                    self.remote.insert(
                        n.sequence,
                        n.retire_prior_to,
                        issued,
                        n.reset_token.*,
                    ) catch return error.ProtocolViolation;
                },
                .retire_connection_id => |sequence| {
                    self.local.retire(sequence) catch return error.ProtocolViolation;
                },
                .handshake_done => {
                    // §4.1.2 of RFC 9001: only the server sends this, and it is
                    // what confirms the handshake for a client.
                    self.handshake_confirmed = true;
                    self.discardHandshakeKeys();
                },
                .connection_close => |c| {
                    const len = @min(c.reason.len, max_reason_len);
                    @memcpy(self.reason_buf[0..len], c.reason[0..len]);
                    self.closed = true;
                    try self.events.append(gpa, .{ .peer_closed = .{
                        .code = c.error_code,
                        .application = c.is_application,
                        .reason = self.reason_buf[0..len],
                    } });
                    return;
                },
                // Streams and flow control are the next layer's. Refusing them
                // here rather than ignoring them keeps "implemented" honest: a
                // peer that opens a stream gets an error instead of silence.
                else => return error.ProtocolViolation,
            }
        }
    }

    /// After CRYPTO data reaches the TLS engine, new keys may exist and the
    /// handshake may have completed.
    fn afterHandshakeProgress(self: *Connection, gpa: Allocator) !void {
        const suite = self.engine.suite() orelse return;

        if (self.engine.secrets(.handshake)) |pair| {
            const sp = self.spaceFor(.handshake);
            if (sp.send == null) {
                sp.send = .fromSecret(suite, pair.client.slice());
                sp.recv = .fromSecret(suite, pair.server.slice());
            }
        }
        if (self.engine.secrets(.one_rtt)) |pair| {
            const sp = self.spaceFor(.one_rtt);
            if (sp.send == null) {
                sp.send = .fromSecret(suite, pair.client.slice());
                sp.recv = .fromSecret(suite, pair.server.slice());
            }
        }

        if (!self.engine.isComplete() or self.established) return;

        // The handshake is done as far as TLS is concerned. Before saying so, the
        // transport parameters have to be checked — including §7.3's connection
        // ID comparison, which is the whole reason those parameters carry
        // connection IDs.
        const raw = self.engine.transportParameters();
        const peer = transport.decode(raw, .server) catch return error.ProtocolViolation;
        transport.checkConnectionIds(&peer, .server, .{
            .peer_source = self.remote.active(),
            .original_destination = self.original_destination,
            .retry_source = self.retry_source,
        }) catch |err| return switch (err) {
            error.ConnectionIdMismatch => error.ConnectionIdMismatch,
            else => error.ProtocolViolation,
        };

        self.peer_parameters = peer;
        self.local.setPeerLimit(peer.active_connection_id_limit);
        self.established = true;
        try self.events.append(gpa, .{ .established = .{ .alpn = self.engine.alpn() } });
    }

    fn discardHandshakeKeys(self: *Connection) void {
        // §4.9 of RFC 9001: once the handshake is confirmed these keys must go,
        // so that a packet protected with them can no longer be processed.
        for ([_]Level{ .initial, .handshake }) |level| {
            const sp = self.spaceFor(level);
            sp.send = null;
            sp.recv = null;
        }
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Fill `dest` with the next datagram to send, returning its length, or zero
    /// if there is nothing to send.
    pub fn send(self: *Connection, gpa: Allocator, dest: []u8) !usize {
        _ = gpa;
        if (self.closed) return 0;
        if (dest.len < min_initial_datagram) return error.BufferTooSmall;

        const limit = @min(dest.len, max_datagram);

        // Which levels have something to say. Decided up front because §14.1's
        // padding goes in the *last* packet of the datagram, and a packet cannot
        // be padded after it has been sealed.
        var wants: [Level.count]bool = @splat(false);
        var last: ?Level = null;
        for ([_]Level{ .initial, .handshake, .one_rtt }) |level| {
            if (!self.hasSomethingToSend(level)) continue;
            wants[@backingInt(level)] = true;
            last = level;
        }
        const final = last orelse return 0;

        // §14.1 applies when the datagram contains an Initial packet at all, not
        // only when that is all it contains.
        const needs_padding = wants[@backingInt(Level.initial)];

        var len: usize = 0;
        for ([_]Level{ .initial, .handshake, .one_rtt }) |level| {
            if (!wants[@backingInt(level)]) continue;
            const pad_to: usize = if (level == final and needs_padding) min_initial_datagram else 0;
            len += try self.writePacket(dest[len..limit], level, pad_to -| len);
        }

        assert(len <= limit);
        assert(!needs_padding or len >= min_initial_datagram);
        return len;
    }

    fn hasSomethingToSend(self: *Connection, level: Level) bool {
        const sp = self.spaceFor(level);
        if (sp.send == null) return false;

        // Handshake bytes waiting to go out.
        const pending = self.engine.output(level);
        if (pending.len > sp.crypto_sent) return true;

        if (sp.ack_pending) return true;

        // A CONNECTION_CLOSE goes at the highest level we have keys for, since
        // that is the one the peer is most likely able to read.
        if (self.pending_close != null and self.highestSendLevel() == level) return true;

        // Retirements owed for the peer's connection IDs need 1-RTT.
        if (level == .one_rtt and self.remote.pendingRetire().len > 0) return true;

        return false;
    }

    fn highestSendLevel(self: *Connection) Level {
        if (self.spaceFor(.one_rtt).send != null) return .one_rtt;
        if (self.spaceFor(.handshake).send != null) return .handshake;
        return .initial;
    }

    /// The Length field of a long header is a varint whose size depends on the
    /// payload length, which is not known until the payload is written. Rather
    /// than compute the payload twice, it is always encoded in two bytes: §16
    /// explicitly permits a non-minimal encoding, and two bytes hold 16383 —
    /// more than any datagram this implementation sends. The cost is at most one
    /// byte per packet; the alternative is two sources of truth for a length.
    const length_field_len = 2;

    fn writePacket(
        self: *Connection,
        dest: []u8,
        level: Level,
        pad_to: usize,
    ) !usize {
        const sp = self.spaceFor(level);
        var send_keys = sp.send.?;
        const pn = sp.next_pn;
        const pn_len = packet.packetNumberLen(pn, sp.largest_acked);

        const is_short = level == .one_rtt;
        var cursor: usize = 0;

        if (is_short) {
            if (dest.len < 1) return error.BufferTooSmall;
            // §17.3: form bit clear, fixed bit set, spin and key phase zero.
            dest[0] = packet.fixed_bit | (@as(u8, pn_len - 1) & 0x03);
            cursor = 1;
            const destination = self.remote.active();
            @memcpy(dest[cursor..][0..destination.len], destination.slice());
            cursor += destination.len;
        } else {
            const long_type: packet.LongType = if (level == .initial) .initial else .handshake;
            dest[0] = packet.header_form_bit | packet.fixed_bit |
                (@as(u8, @backingInt(long_type)) << 4) | (@as(u8, pn_len - 1) & 0x03);
            cursor = 1;
            std.mem.writeInt(u32, dest[cursor..][0..4], @backingInt(packet.Version.v1), .big);
            cursor += 4;

            const destination = self.remote.active();
            dest[cursor] = destination.len;
            cursor += 1;
            @memcpy(dest[cursor..][0..destination.len], destination.slice());
            cursor += destination.len;

            const source = self.local.initialId();
            dest[cursor] = source.len;
            cursor += 1;
            @memcpy(dest[cursor..][0..source.len], source.slice());
            cursor += source.len;

            if (level == .initial) {
                const token = self.token_buf[0..self.token_len];
                cursor += varint.encode(dest[cursor..], token.len);
                @memcpy(dest[cursor..][0..token.len], token);
                cursor += token.len;
            }
        }

        const length_offset = cursor;
        if (!is_short) cursor += length_field_len;
        const pn_offset = cursor;
        packet.encodePacketNumber(dest[cursor..][0..pn_len], pn, pn_len);
        cursor += pn_len;

        // Room for the payload, keeping the authentication tag in mind.
        if (cursor + crypto.tag_len >= dest.len) return error.BufferTooSmall;
        const payload_room = dest.len - cursor - crypto.tag_len;
        var payload: [max_datagram]u8 = undefined;
        const payload_len = self.writeFrames(
            payload[0..@min(payload_room, payload.len)],
            level,
            // Padding is expressed in terms of the finished datagram, so work
            // back through this packet's own overhead.
            if (pad_to > cursor + crypto.tag_len) pad_to - cursor - crypto.tag_len else 0,
        );
        if (payload_len == 0) return 0;

        if (!is_short) {
            // The Length field covers the packet number and the protected
            // payload, tag included.
            const covered = pn_len + payload_len + crypto.tag_len;
            assert(covered <= varint.max_value);
            _ = varint.encodeIn(dest[length_offset..][0..length_field_len], covered, length_field_len);
        }

        const header = dest[0..cursor];
        const sealed = try send_keys.seal(dest[cursor..], pn, header, payload[0..payload_len]);
        sp.send = send_keys;
        const total = cursor + sealed;

        // RFC 9001 §5.4.2: header protection last, because its sample comes from
        // the ciphertext. Writing these two the other way round makes every
        // packet fail authentication at the peer.
        crypto.protectHeader(dest[0..total], pn_offset, pn_len, &send_keys.header);

        sp.next_pn += 1;
        sp.ack_pending = false;
        if (self.pending_close != null and self.highestSendLevel() == level) {
            self.closed = true;
            self.pending_close = null;
        }
        return total;
    }

    fn writeFrames(
        self: *Connection,
        dest: []u8,
        level: Level,
        pad_to: usize,
    ) usize {
        const sp = self.spaceFor(level);
        var len: usize = 0;

        // ACK first: it is the smallest useful thing in the packet, and putting
        // it ahead of CRYPTO means a packet that has to be truncated still
        // acknowledges. Only a single range is produced — the full range set
        // belongs with loss recovery, and reporting one range is correct but
        // pessimistic rather than wrong.
        if (sp.ack_pending) {
            if (sp.largest_received) |largest| {
                // A single range. The full range set belongs with loss recovery;
                // acknowledging only the largest is pessimistic — it makes the
                // peer retransmit what it need not have — but never wrong, and
                // being explicit about that beats a half-built range tracker.
                const f: frame.Frame = .{ .ack = .{
                    .largest = largest,
                    .delay = 0,
                    .first_range = 0,
                    .range_count = 0,
                    .ranges = &.{},
                    .ecn = null,
                } };
                const need = frame.encodedLen(f);
                if (len + need <= dest.len) len += frame.encode(dest[len..], f);
            }
        }

        if (self.pending_close) |close_request| {
            if (self.highestSendLevel() == level) {
                const f: frame.Frame = .{ .connection_close = .{
                    .error_code = close_request.code,
                    .is_application = close_request.application,
                    .frame_type = null,
                    .reason = &.{},
                } };
                const need = frame.encodedLen(f);
                if (len + need <= dest.len) len += frame.encode(dest[len..], f);
            }
        }

        // CRYPTO: whatever the TLS engine has produced and we have not sent.
        const pending = self.engine.output(level);
        if (pending.len > sp.crypto_sent) {
            const offset = sp.crypto_sent;
            const available = pending[@intCast(offset)..];
            // The frame's own header costs an offset varint, a length varint and
            // the type byte, so the payload cannot simply be the remaining room.
            const overhead = 1 + varint.encodedLen(offset) + varint.encodedLen(available.len);
            if (len + overhead + 1 <= dest.len) {
                const room = dest.len - len - overhead;
                const take = @min(room, available.len);
                const f: frame.Frame = .{ .crypto = .{
                    .offset = offset,
                    .data = available[0..take],
                } };
                len += frame.encode(dest[len..], f);
                sp.crypto_sent += take;
            }
        }

        if (level == .one_rtt) {
            const owed = self.remote.pendingRetire();
            var sent: usize = 0;
            for (owed) |sequence| {
                const f: frame.Frame = .{ .retire_connection_id = sequence };
                const need = frame.encodedLen(f);
                if (len + need > dest.len) break;
                len += frame.encode(dest[len..], f);
                sent += 1;
            }
            if (sent > 0) self.remote.clearPendingRetire(sent);
        }

        // §14.1's padding, and §19.1's frame for it.
        if (pad_to > len) {
            const want = @min(pad_to - len, dest.len - len);
            const f: frame.Frame = .{ .padding = want };
            // PADDING encodes one byte per unit, so the frame's length is its
            // count; asking for `want` produces exactly `want` bytes.
            const written = frame.encode(dest[len..], f);
            assert(written == want);
            len += written;
        }

        return len;
    }
};

fn readPacketNumber(bytes: []const u8) u64 {
    var value: u64 = 0;
    for (bytes) |byte| value = (value << 8) | byte;
    return value;
}

// ── Tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const handshake = @import("handshake.zig");
const tls = @import("tls.zig");

fn cid(bytes: []const u8) ConnectionId {
    return ConnectionId.init(bytes) catch unreachable;
}

/// A minimal server that speaks packets, built on `client.TestServer` for the
/// handshake itself. Like that one it is a second implementation rather than a
/// mirror of the code under test: it derives its own keys, assembles its own
/// packets and would notice if the client's idea of either were wrong.
const PacketServer = struct {
    inner: client.TestServer,
    local_cid: ConnectionId,
    initial_send: crypto.Keys,
    initial_recv: crypto.Keys,
    handshake_send: ?crypto.Keys = null,
    handshake_recv: ?crypto.Keys = null,
    next_pn: [2]u64 = .{ 0, 0 },
    inbound_crypto: [2]std.ArrayList(u8) = .{ .empty, .empty },
    flight_buf: [4096]u8 = undefined,
    hello_out: []const u8 = &.{},
    /// Only ever non-empty in the test that checks §17.2.2 refuses it.
    send_token: []const u8 = &.{},

    fn init(seed: u8, client_dcid: ConnectionId, local_cid: ConnectionId) PacketServer {
        const keys = crypto.InitialKeys.derive(client_dcid.slice());
        return .{
            .inner = .init(seed),
            .local_cid = local_cid,
            .initial_send = keys.server,
            .initial_recv = keys.client,
        };
    }

    fn deinit(self: *PacketServer, gpa: Allocator) void {
        for (&self.inbound_crypto) |*list| list.deinit(gpa);
    }

    fn levelIndex(level: Level) usize {
        return switch (level) {
            .initial => 0,
            .handshake => 1,
            .one_rtt => unreachable,
        };
    }

    /// Decrypt every packet in a datagram and collect the CRYPTO bytes.
    fn receive(self: *PacketServer, gpa: Allocator, datagram: []const u8) !void {
        var offset: usize = 0;
        while (offset < datagram.len) {
            const parsed = packet.parse(datagram[offset..], self.local_cid.len) catch return;
            const slice = datagram[offset..][0..parsed.end];
            offset += parsed.end;

            const protected = switch (parsed.packet) {
                .protected => |p| p,
                else => continue,
            };
            const long = protected.long_type orelse continue;
            const index: usize = switch (long) {
                .initial => 0,
                .handshake => 1,
                else => continue,
            };
            var keys = switch (index) {
                0 => self.initial_recv,
                1 => self.handshake_recv orelse continue,
                else => unreachable,
            };

            var work: [max_datagram]u8 = undefined;
            @memcpy(work[0..slice.len], slice);
            const buf = work[0..slice.len];
            const pn_len = crypto.unprotectHeader(buf, protected.pn_offset, &keys.header);
            const pn = readPacketNumber(buf[protected.pn_offset..][0..pn_len]);
            const header = buf[0 .. protected.pn_offset + pn_len];
            const body = buf[protected.pn_offset + pn_len .. protected.pn_offset + protected.remainder_len];

            var plain: [max_datagram]u8 = undefined;
            const plain_len = keys.open(&plain, pn, header, body) catch continue;
            if (index == 0) self.initial_recv = keys else self.handshake_recv = keys;

            var rest: []const u8 = plain[0..plain_len];
            while (rest.len > 0) {
                const f = frame.parse(&rest) catch break;
                switch (f) {
                    .crypto => |c| {
                        const list = &self.inbound_crypto[index];
                        if (c.offset != list.items.len) continue; // tests send in order
                        try list.appendSlice(gpa, c.data);
                    },
                    else => {},
                }
            }
        }
    }

    fn clientHello(self: *PacketServer) []const u8 {
        return self.inbound_crypto[0].items;
    }

    /// Produce the server's reply: an Initial with the ServerHello, coalesced
    /// with a Handshake packet carrying the rest of the flight.
    fn reply(
        self: *PacketServer,
        dest: []u8,
        client_dcid: ConnectionId,
        alpn: []const u8,
        parameters: []const u8,
    ) !usize {
        const hello = self.inner.writeServerHello(self.clientHello());
        self.hello_out = hello;

        var len = try self.writeLongPacket(dest, .initial, client_dcid, hello);

        const suite = self.inner.schedule.?.suite;
        const secrets = self.inner.handshake_secrets.?;
        self.handshake_send = .fromSecret(suite, secrets.server.slice());
        self.handshake_recv = .fromSecret(suite, secrets.client.slice());

        const flight = self.inner.writeFlight(&self.flight_buf, alpn, parameters);
        len += try self.writeLongPacket(dest[len..], .handshake, client_dcid, flight);
        return len;
    }

    pub fn writeLongPacket(
        self: *PacketServer,
        dest: []u8,
        long_type: packet.LongType,
        destination: ConnectionId,
        crypto_data: []const u8,
    ) !usize {
        const index: usize = if (long_type == .initial) 0 else 1;
        var keys = if (index == 0) self.initial_send else self.handshake_send.?;
        const pn = self.next_pn[index];
        const pn_len: u4 = 4;

        var cursor: usize = 0;
        dest[0] = packet.header_form_bit | packet.fixed_bit |
            (@as(u8, @backingInt(long_type)) << 4) | (pn_len - 1);
        cursor = 1;
        std.mem.writeInt(u32, dest[cursor..][0..4], @backingInt(packet.Version.v1), .big);
        cursor += 4;
        dest[cursor] = destination.len;
        cursor += 1;
        @memcpy(dest[cursor..][0..destination.len], destination.slice());
        cursor += destination.len;
        dest[cursor] = self.local_cid.len;
        cursor += 1;
        @memcpy(dest[cursor..][0..self.local_cid.len], self.local_cid.slice());
        cursor += self.local_cid.len;
        if (long_type == .initial) {
            cursor += varint.encode(dest[cursor..], self.send_token.len);
            @memcpy(dest[cursor..][0..self.send_token.len], self.send_token);
            cursor += self.send_token.len;
        }

        const length_offset = cursor;
        cursor += 2;
        const pn_offset = cursor;
        packet.encodePacketNumber(dest[cursor..][0..pn_len], pn, pn_len);
        cursor += pn_len;

        var payload: [4096]u8 = undefined;
        const f: frame.Frame = .{ .crypto = .{ .offset = 0, .data = crypto_data } };
        const payload_len = frame.encode(&payload, f);

        _ = varint.encodeIn(
            dest[length_offset..][0..2],
            pn_len + payload_len + crypto.tag_len,
            2,
        );

        const header = dest[0..cursor];
        const sealed = try keys.seal(dest[cursor..], pn, header, payload[0..payload_len]);
        if (index == 0) self.initial_send = keys else self.handshake_send = keys;
        const total = cursor + sealed;
        crypto.protectHeader(dest[0..total], pn_offset, pn_len, &keys.header);
        self.next_pn[index] += 1;
        return total;
    }
};

fn testOptions(local: ConnectionId, initial_dcid: ConnectionId) Options {
    return .{
        .host = "example.com",
        .alpn = &.{"h3"},
        .parameters = .client_defaults,
        // Null deliberately: the test server cannot sign a CertificateVerify,
        // because std can verify RSA signatures but not produce them. The real
        // validation path is covered against RFC 8448's genuine signature in
        // verify.zig.
        .verification = null,
        .local_cid = local,
        .initial_destination = initial_dcid,
    };
}

test "connection: a handshake completes over real datagrams" {
    // The point of the whole file: the client's packets are parsed, decrypted and
    // answered by something that derived its own keys. Every layer beneath is
    // exercised for real — packet assembly, header protection, AEAD, framing,
    // CRYPTO reassembly, the TLS state machine and the transport parameters.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xc1, 0xc2, 0xc3, 0xc4 });
    const server_cid = cid(&.{ 0x51, 0x52, 0x53, 0x54, 0x55 });
    const initial_dcid = cid(&.{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x31));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server: PacketServer = .init(0x9a, initial_dcid, server_cid);
    defer server.deinit(gpa);

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);

    // §14.1: the client's Initial datagram is padded to 1200 bytes. Not a style
    // point — a server may send no more than three times what it received from an
    // unvalidated address, so a short Initial caps the server's first flight
    // below the size of a certificate chain, and the handshake stalls.
    try testing.expectEqual(@as(usize, min_initial_datagram), first);

    try server.receive(gpa, out[0..first]);
    try testing.expect(server.clientHello().len > 0);

    // The server's transport parameters, including the §7.3 connection IDs it is
    // obliged to report.
    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_streams_bidi = 10,
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = initial_dcid,
    };
    var params_buf: [256]u8 = undefined;
    const params_len = transport.encode(&params_buf, &server_params, .server);

    var reply_buf: [max_datagram]u8 = undefined;
    const reply_len = try server.reply(&reply_buf, client_cid, "h3", params_buf[0..params_len]);

    try conn.receive(gpa, reply_buf[0..reply_len]);

    try testing.expect(conn.isEstablished());
    var saw_established = false;
    while (conn.nextEvent()) |event| {
        switch (event) {
            .established => |e| {
                saw_established = true;
                // The negotiated protocol survives, which is the property a
                // borrowed-buffer bug destroys: this is the same assertion that
                // caught the ALPN defect one layer down.
                try testing.expectEqualStrings("h3", e.alpn);
            },
            else => {},
        }
    }
    try testing.expect(saw_established);

    // The peer's parameters came through and mean what they say.
    const peer = conn.peerParameters().?;
    try testing.expectEqual(@as(u64, 1 << 20), peer.initial_max_data);
    try testing.expectEqual(@as(u64, 10), peer.initial_max_streams_bidi);

    // And §7.2's rule held: we are now addressing the server by the connection ID
    // it chose, not the random value we invented.
    try testing.expect(conn.remote.active().eql(&server_cid));

    // The client's Finished goes out at the Handshake level, and the server
    // accepts it — which means both ends computed the same transcript.
    const second = try conn.send(gpa, &out);
    try testing.expect(second > 0);
    try server.receive(gpa, out[0..second]);
    const verify_data = server.inbound_crypto[1].items;
    try testing.expect(verify_data.len > 4);
    try server.inner.verifyClientFinished(verify_data[4..]);
}

test "connection: §7.3 rejects a server that reports the wrong connection id" {
    // The security property, now end to end rather than in isolation. An attacker
    // who rewrote the Source Connection ID in the server's Initial header would
    // produce exactly this: parameters that do not match the headers.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 1, 2, 3, 4 });
    const server_cid = cid(&.{ 5, 6, 7, 8, 9 });
    const initial_dcid = cid(&.{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x42));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server: PacketServer = .init(0x5c, initial_dcid, server_cid);
    defer server.deinit(gpa);

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);
    try server.receive(gpa, out[0..first]);

    // The server signs a *different* source connection ID than the one its
    // packets carried.
    var params: transport.Parameters = .{
        .initial_source_connection_id = cid(&.{ 5, 6, 7, 8, 0xff }),
        .original_destination_connection_id = initial_dcid,
    };
    var params_buf: [256]u8 = undefined;
    const params_len = transport.encode(&params_buf, &params, .server);

    var reply_buf: [max_datagram]u8 = undefined;
    const reply_len = try server.reply(&reply_buf, client_cid, "h3", params_buf[0..params_len]);

    try testing.expectError(
        error.ConnectionIdMismatch,
        conn.receive(gpa, reply_buf[0..reply_len]),
    );
    try testing.expect(!conn.isEstablished());
}

test "connection: a Retry is verified, restarts the handshake, and happens once" {
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x11, 0x22 });
    const initial_dcid = cid(&.{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 });
    const retry_cid = cid(&.{ 0xbb, 0xcc, 0xdd });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x55));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var out: [max_datagram]u8 = undefined;
    const before = try conn.send(gpa, &out);
    try testing.expectEqual(@as(usize, min_initial_datagram), before);
    const pn_before = conn.spaceFor(.initial).next_pn;

    var retry: [64]u8 = undefined;
    const token = "opaque-address-token";
    const retry_len = writeRetry(&retry, client_cid, retry_cid, token, initial_dcid);

    // A forged Retry — one bit of the tag flipped — is dropped, not acted on.
    var forged: [64]u8 = undefined;
    @memcpy(forged[0..retry_len], retry[0..retry_len]);
    forged[retry_len - 1] ^= 0x01;
    try conn.receive(gpa, forged[0..retry_len]);
    try testing.expect(!conn.retry_seen);
    try testing.expect(conn.addressToken().len == 0);

    // The genuine one is accepted.
    try conn.receive(gpa, retry[0..retry_len]);
    try testing.expect(conn.retry_seen);
    try testing.expectEqualStrings(token, conn.addressToken());
    try testing.expect(conn.remote.active().eql(&retry_cid));

    // §17.2.5.3: packet numbers are *not* reset. Reusing one would reuse an AEAD
    // nonce, which is the single worst thing that can be done with a key.
    try testing.expectEqual(pn_before, conn.spaceFor(.initial).next_pn);

    // The ClientHello is resent byte for byte, because a Retry — unlike a
    // HelloRetryRequest — does not enter the TLS transcript. The offset rewind is
    // what performs the resend.
    const after = try conn.send(gpa, &out);
    try testing.expectEqual(@as(usize, min_initial_datagram), after);
    try testing.expect(conn.spaceFor(.initial).crypto_sent > 0);

    // §17.2.5.2: a second Retry is ignored. Otherwise an attacker could make us
    // resend a ClientHello indefinitely — each one a full 1200-byte datagram, so
    // it is an amplification lever as well as a stall.
    //
    // The second Retry carries a *different* token and connection ID on purpose.
    // Replaying the first one would make this assertion vacuous: "the token did
    // not change" would hold whether or not the packet was processed.
    var second: [64]u8 = undefined;
    const other_cid = cid(&.{ 0x77, 0x88, 0x99 });
    const second_len = writeRetry(&second, client_cid, other_cid, "a-different-token", initial_dcid);
    try conn.receive(gpa, second[0..second_len]);
    try testing.expectEqualStrings(token, conn.addressToken());
    try testing.expect(conn.remote.active().eql(&retry_cid));
}

test "connection: out-of-order CRYPTO frames are reassembled" {
    // §7.5. The TLS engine needs bytes in order; the network does not provide
    // them that way. Worth testing on its own because the reordering that breaks
    // it is rare enough in practice to survive a lot of manual testing.
    const gpa = testing.allocator;

    var stream: CryptoStream = .{};
    defer stream.deinit(gpa);

    var engine = try client.Client.init(.{
        .host = "example.com",
        .alpn = &.{"h3"},
        .transport_parameters = &.{},
        .verification = null,
    }, @splat(0x7e));
    defer engine.deinit(gpa);
    try engine.start(gpa);

    // Feed a ServerHello backwards, in three pieces, using a real one so that
    // the engine actually parses what comes out.
    var server: client.TestServer = .init(0x33);
    const hello = server.writeServerHello(engine.output(.initial));

    const third = hello.len / 3;
    try stream.accept(gpa, third * 2, hello[third * 2 ..], &engine, .initial);
    try testing.expectEqual(@as(u64, 0), stream.consumed);
    try testing.expect(stream.buffered > 0);

    try stream.accept(gpa, third, hello[third .. third * 2], &engine, .initial);
    try testing.expectEqual(@as(u64, 0), stream.consumed);

    try stream.accept(gpa, 0, hello[0..third], &engine, .initial);
    // All three delivered once the gap closed.
    try testing.expectEqual(@as(u64, hello.len), stream.consumed);
    try testing.expectEqual(@as(usize, 0), stream.buffered);
    try testing.expect(engine.secrets(.handshake) != null);

    // A retransmission of data already delivered is ignored rather than fed
    // twice, which would desynchronise the TLS transcript.
    try stream.accept(gpa, 0, hello[0..third], &engine, .initial);
    try testing.expectEqual(@as(u64, hello.len), stream.consumed);

    // And an overlapping retransmission delivers only the new part.
    try stream.accept(gpa, hello.len - 4, hello[hello.len - 4 ..], &engine, .initial);
    try testing.expectEqual(@as(u64, hello.len), stream.consumed);
}

test "connection: the CRYPTO reassembly buffer is bounded" {
    // §7.5's CRYPTO_BUFFER_EXCEEDED. Without a bound a peer sends one byte at a
    // huge offset, repeatedly, and we allocate to match — the cheapest possible
    // memory attack on a handshake.
    const gpa = testing.allocator;

    var stream: CryptoStream = .{};
    defer stream.deinit(gpa);

    var engine = try client.Client.init(.{
        .host = "h",
        .alpn = &.{"h3"},
        .transport_parameters = &.{},
        .verification = null,
    }, @splat(0x11));
    defer engine.deinit(gpa);

    const chunk: [1024]u8 = @splat(0xaa);
    var offset: u64 = 8; // always past `consumed`, so nothing is ever delivered
    var accepted: usize = 0;
    while (offset < max_crypto_pending * 2) : (offset += chunk.len) {
        stream.accept(gpa, offset, &chunk, &engine, .initial) catch |err| {
            try testing.expectEqual(error.CryptoBufferExceeded, err);
            break;
        };
        accepted += 1;
    }
    try testing.expect(stream.buffered <= max_crypto_pending);
    try testing.expect(accepted > 0); // the bound is a bound, not a refusal
}

test "connection: a coalesced datagram is processed packet by packet" {
    // §12.2. The server's reply in the handshake test is already two packets in
    // one datagram; this asserts the property directly, including that a
    // trailing packet we have no keys for does not discard the one before it.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x21, 0x22, 0x23 });
    const server_cid = cid(&.{ 0x31, 0x32 });
    const initial_dcid = cid(&.{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x63));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server: PacketServer = .init(0x71, initial_dcid, server_cid);
    defer server.deinit(gpa);

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);
    try server.receive(gpa, out[0..first]);

    var params: transport.Parameters = .{
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = initial_dcid,
    };
    var params_buf: [256]u8 = undefined;
    const params_len = transport.encode(&params_buf, &params, .server);

    var reply_buf: [max_datagram]u8 = undefined;
    const reply_len = try server.reply(&reply_buf, client_cid, "h3", params_buf[0..params_len]);

    // The reply really is more than one packet: the ServerHello is in an Initial
    // and the rest of the flight in a Handshake packet.
    const one = try packet.parse(reply_buf[0..reply_len], client_cid.len);
    try testing.expect(one.end < reply_len);

    try conn.receive(gpa, reply_buf[0..reply_len]);
    try testing.expect(conn.isEstablished());
}

test "connection: an undecryptable packet is dropped, never fatal" {
    // RFC 9001 §5.3. If a packet that fails authentication could kill a
    // connection, an off-path attacker needs no capability beyond guessing a
    // connection ID — and connection IDs travel in the clear.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x91, 0x92 });
    const initial_dcid = cid(&.{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x27));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var out: [max_datagram]u8 = undefined;
    _ = try conn.send(gpa, &out);

    // Garbage that parses as an Initial packet but cannot possibly authenticate.
    var junk: [200]u8 = undefined;
    var cursor: usize = 0;
    junk[0] = packet.header_form_bit | packet.fixed_bit | 0x03;
    cursor = 1;
    std.mem.writeInt(u32, junk[cursor..][0..4], @backingInt(packet.Version.v1), .big);
    cursor += 4;
    junk[cursor] = client_cid.len;
    cursor += 1;
    @memcpy(junk[cursor..][0..client_cid.len], client_cid.slice());
    cursor += client_cid.len;
    junk[cursor] = 0;
    cursor += 1;
    cursor += varint.encode(junk[cursor..], 0);
    cursor += varint.encode(junk[cursor..], 100);
    @memset(junk[cursor..][0..100], 0x5a);

    try conn.receive(gpa, junk[0 .. cursor + 100]);
    try testing.expect(!conn.closed);
    try testing.expect(!conn.isEstablished());
    // Nothing was learned from it, which is the part that matters: state changed
    // by an unauthenticated packet is state an attacker controls.
    try testing.expect(conn.spaceFor(.initial).largest_received == null);
}

test "connection: a stateless reset ends the connection without a protocol error" {
    // §10.3. The token is matched against every connection ID we hold, because a
    // resetting server answers with the token for whichever ID it could not
    // process — see cid.zig. This checks the wiring: a reset must not be treated
    // as a decryption failure, or the connection would sit waiting out its idle
    // timeout instead of failing at once.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xaa, 0xbb });
    const initial_dcid = cid(&.{ 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x19));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    const token: [cid_mod.stateless_reset_token_len]u8 = @splat(0x7f);
    try conn.remote.insert(1, 0, cid(&.{ 0xcc, 0xdd }), token);

    var reset: [64]u8 = undefined;
    @memset(&reset, 0x3c);
    reset[0] = packet.fixed_bit; // looks like a short header
    @memcpy(reset[reset.len - token.len ..], &token);

    try conn.receive(gpa, &reset);
    try testing.expect(conn.closed);
    try testing.expectEqual(Event.stateless_reset, conn.nextEvent().?);
}

test "connection: a peer's CONNECTION_CLOSE is reported with its code" {
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x01, 0x02, 0x03, 0x04 });
    const server_cid = cid(&.{ 0x05, 0x06 });
    const initial_dcid = cid(&.{ 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x88));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server: PacketServer = .init(0x44, initial_dcid, server_cid);
    defer server.deinit(gpa);

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);
    try server.receive(gpa, out[0..first]);

    // The server answers with a CONNECTION_CLOSE in an Initial packet instead of
    // a ServerHello, which is what a server refusing the connection does.
    var payload: [64]u8 = undefined;
    const f: frame.Frame = .{
        .connection_close = .{
            .error_code = 0x0a, // PROTOCOL_VIOLATION
            .is_application = false,
            .frame_type = 0x06,
            .reason = "no",
        },
    };
    const payload_len = frame.encode(&payload, f);

    var close_packet: [256]u8 = undefined;
    var cursor: usize = 0;
    close_packet[0] = packet.header_form_bit | packet.fixed_bit | 0x03;
    cursor = 1;
    std.mem.writeInt(u32, close_packet[cursor..][0..4], @backingInt(packet.Version.v1), .big);
    cursor += 4;
    close_packet[cursor] = client_cid.len;
    cursor += 1;
    @memcpy(close_packet[cursor..][0..client_cid.len], client_cid.slice());
    cursor += client_cid.len;
    close_packet[cursor] = server_cid.len;
    cursor += 1;
    @memcpy(close_packet[cursor..][0..server_cid.len], server_cid.slice());
    cursor += server_cid.len;
    cursor += varint.encode(close_packet[cursor..], 0);
    const length_offset = cursor;
    cursor += 2;
    const pn_offset = cursor;
    packet.encodePacketNumber(close_packet[cursor..][0..4], 0, 4);
    cursor += 4;
    _ = varint.encodeIn(close_packet[length_offset..][0..2], 4 + payload_len + crypto.tag_len, 2);
    var keys = server.initial_send;
    const sealed = try keys.seal(
        close_packet[cursor..],
        0,
        close_packet[0..cursor],
        payload[0..payload_len],
    );
    const total = cursor + sealed;
    crypto.protectHeader(close_packet[0..total], pn_offset, 4, &keys.header);

    try conn.receive(gpa, close_packet[0..total]);
    try testing.expect(conn.closed);

    const event = conn.nextEvent().?;
    try testing.expectEqual(@as(u64, 0x0a), event.peer_closed.code);
    try testing.expect(!event.peer_closed.application);
    try testing.expectEqualStrings("no", event.peer_closed.reason);
}

test "connection: §14.1 pads a datagram containing an Initial, and nothing else" {
    // §14.1 applies to datagrams that contain an Initial packet — not to every
    // datagram. Padding everything would waste most of a kilobyte per
    // acknowledgement for the life of the connection; padding nothing stalls the
    // handshake, because a server may send no more than three times what it
    // received from an unvalidated address.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x71, 0x72 });
    const server_cid = cid(&.{ 0x73, 0x74 });
    const initial_dcid = cid(&.{ 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x1d));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server: PacketServer = .init(0x2e, initial_dcid, server_cid);
    defer server.deinit(gpa);

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);
    try testing.expectEqual(@as(usize, min_initial_datagram), first);

    // Nothing more to say until the server answers: an empty datagram is not
    // padded into existence.
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));

    try server.receive(gpa, out[0..first]);
    var params: transport.Parameters = .{
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = initial_dcid,
    };
    var params_buf: [256]u8 = undefined;
    const params_len = transport.encode(&params_buf, &params, .server);
    var reply_buf: [max_datagram]u8 = undefined;
    const reply_len = try server.reply(&reply_buf, client_cid, "h3", params_buf[0..params_len]);
    try conn.receive(gpa, reply_buf[0..reply_len]);
    try testing.expect(conn.isEstablished());

    // The client now owes an ACK at Initial and a Finished at Handshake, so this
    // datagram contains an Initial packet and is padded.
    const second = try conn.send(gpa, &out);
    try testing.expectEqual(@as(usize, min_initial_datagram), second);

    // Once the handshake is confirmed the Initial keys are gone, so a later
    // datagram carries no Initial packet and is not padded. This is the half of
    // §14.1 that an implementation padding unconditionally would get wrong, and
    // it would only ever show up as wasted bandwidth — never as a failure.
    conn.handshake_confirmed = true;
    conn.discardHandshakeKeys();
    conn.spaceFor(.one_rtt).ack_pending = true;
    conn.spaceFor(.one_rtt).largest_received = 0;
    const third = try conn.send(gpa, &out);
    try testing.expect(third > 0);
    try testing.expect(third < min_initial_datagram);
}

test "connection: §7.2 changes the destination connection id twice when a Retry happens" {
    // The rule the RFC states outright and an implementation is likely to get
    // wrong: "a client might have to change the connection ID it sets in the
    // Destination Connection ID field twice during connection establishment: once
    // in response to a Retry packet and once in response to an Initial packet
    // from the server." Fixing it at the Retry breaks only handshakes that involve
    // a Retry — so it passes every test against a server that never sends one.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x61, 0x62 });
    const initial_dcid = cid(&.{ 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57 });
    const retry_cid = cid(&.{ 0xa1, 0xa2, 0xa3 });
    const server_cid = cid(&.{ 0xb1, 0xb2, 0xb3, 0xb4 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x3a));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var out: [max_datagram]u8 = undefined;
    _ = try conn.send(gpa, &out);

    // First change: the Retry.
    var retry: [64]u8 = undefined;
    const retry_len = writeRetry(&retry, client_cid, retry_cid, "tok", initial_dcid);
    try conn.receive(gpa, retry[0..retry_len]);
    try testing.expect(conn.remote.active().eql(&retry_cid));

    // The resent Initial goes to the Retry's connection ID, and its Initial keys
    // were re-derived from that same value (§5.2 of RFC 9001) — otherwise the
    // server could not read it.
    const resent = try conn.send(gpa, &out);
    try testing.expectEqual(@as(usize, min_initial_datagram), resent);

    var server: PacketServer = .init(0x4b, retry_cid, server_cid);
    defer server.deinit(gpa);
    try server.receive(gpa, out[0..resent]);
    try testing.expect(server.clientHello().len > 0);

    // Second change: the server's Initial, whose Source Connection ID differs
    // from the Retry's. §7.2 permits exactly this.
    var params: transport.Parameters = .{
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = initial_dcid,
        .retry_source_connection_id = retry_cid,
    };
    var params_buf: [256]u8 = undefined;
    const params_len = transport.encode(&params_buf, &params, .server);
    var reply_buf: [max_datagram]u8 = undefined;
    const reply_len = try server.reply(&reply_buf, client_cid, "h3", params_buf[0..params_len]);
    try conn.receive(gpa, reply_buf[0..reply_len]);

    try testing.expect(conn.remote.active().eql(&server_cid));
    // And §7.3's check passed with all three connection IDs in play — the
    // original destination, the Retry's source, and the server's own.
    try testing.expect(conn.isEstablished());
}

test "connection: §7.2 discards a later Initial that changes the source connection id" {
    // Once a valid server Initial has arrived, the destination connection ID is
    // fixed. Honouring a change would let anyone able to inject one packet
    // redirect every subsequent packet we send to a connection ID of their
    // choosing.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x81, 0x82 });
    const server_cid = cid(&.{ 0x83, 0x84 });
    const initial_dcid = cid(&.{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x2b));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server: PacketServer = .init(0x5d, initial_dcid, server_cid);
    defer server.deinit(gpa);

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);
    try server.receive(gpa, out[0..first]);

    var params: transport.Parameters = .{
        .initial_source_connection_id = server_cid,
        .original_destination_connection_id = initial_dcid,
    };
    var params_buf: [256]u8 = undefined;
    const params_len = transport.encode(&params_buf, &params, .server);
    var reply_buf: [max_datagram]u8 = undefined;
    const reply_len = try server.reply(&reply_buf, client_cid, "h3", params_buf[0..params_len]);
    try conn.receive(gpa, reply_buf[0..reply_len]);
    try testing.expect(conn.remote.active().eql(&server_cid));

    // A second Initial claiming a different source, at a *higher* packet number
    // than anything the real server sent. That is what makes this observable:
    // §7.2's rule discards the whole packet, so none of its frames are processed
    // and the largest received packet number does not move.
    //
    // Asserting only "the connection ID did not change" would be vacuous — the
    // `server_initial_seen` gate already prevents that — and the rule's stated
    // purpose is consistency rather than confidentiality: it avoids unpredictable
    // outcomes from processing several Initial packets that disagree about who
    // sent them. The packet is genuinely encrypted with the right Initial keys,
    // because those are derivable by anyone who saw the handshake, which is
    // exactly why this check cannot rely on decryption failing.
    const before = conn.spaceFor(.initial).largest_received;
    var impostor: PacketServer = .init(0x5d, initial_dcid, cid(&.{ 0xff, 0xfe }));
    defer impostor.deinit(gpa);
    impostor.next_pn[0] = 99;
    var second_buf: [max_datagram]u8 = undefined;
    const second_len = try impostor.writeLongPacket(&second_buf, .initial, client_cid, "junk");
    try conn.receive(gpa, second_buf[0..second_len]);

    try testing.expectEqual(before, conn.spaceFor(.initial).largest_received);
    try testing.expect(conn.remote.active().eql(&server_cid));

    // The same packet with the *right* source connection ID is processed, which
    // proves the test above is checking the source check rather than something
    // incidental about the packet.
    var honest: PacketServer = .init(0x5d, initial_dcid, server_cid);
    defer honest.deinit(gpa);
    honest.next_pn[0] = 99;
    const third_len = try honest.writeLongPacket(&second_buf, .initial, client_cid, "junk");
    try conn.receive(gpa, second_buf[0..third_len]);
    try testing.expectEqual(@as(?u64, 99), conn.spaceFor(.initial).largest_received);
}

test "connection: a server's Initial carrying a token is discarded" {
    // §17.2.2: only a client puts a token in an Initial packet. A server doing so
    // is confused about its role, and since Initial protection is forgeable by
    // anyone who saw the handshake, discarding beats failing.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x11, 0x12 });
    const server_cid = cid(&.{ 0x13, 0x14 });
    const initial_dcid = cid(&.{ 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x6c));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server: PacketServer = .init(0x7e, initial_dcid, server_cid);
    defer server.deinit(gpa);
    server.send_token = "should-not-be-here";

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);
    try server.receive(gpa, out[0..first]);

    var buf: [max_datagram]u8 = undefined;
    const len = try server.writeLongPacket(&buf, .initial, client_cid, "hello");
    try conn.receive(gpa, buf[0..len]);

    // Dropped before it could teach us anything.
    try testing.expect(conn.spaceFor(.initial).largest_received == null);
    try testing.expect(!conn.server_initial_seen);
}

test "connection: a Retry echoing our own connection id is discarded" {
    // §17.2.5.1. If the server echoed the value back, re-deriving Initial keys
    // would produce the keys we already have, so the "new" handshake would be
    // indistinguishable from the old one — and an attacker could replay it.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x31, 0x32 });
    const initial_dcid = cid(&.{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x4d));
    defer conn.deinit(gpa);
    try conn.start(gpa);
    var out: [max_datagram]u8 = undefined;
    _ = try conn.send(gpa, &out);

    var retry: [64]u8 = undefined;
    const len = writeRetry(&retry, client_cid, initial_dcid, "tok", initial_dcid);
    try conn.receive(gpa, retry[0..len]);
    try testing.expect(!conn.retry_seen);

    // A zero-length token is refused too: there would be nothing to replay, so
    // the Retry would cost a round trip and achieve nothing.
    const empty = writeRetry(&retry, client_cid, cid(&.{ 1, 2, 3 }), "", initial_dcid);
    try conn.receive(gpa, retry[0..empty]);
    try testing.expect(!conn.retry_seen);
}

test "connection: a Version Negotiation packet is only acted on before anything else" {
    // §6.2: it carries no authentication at all, so once any protected packet has
    // been processed it must be discarded. Otherwise one injected packet ends an
    // established connection.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x41, 0x42 });
    const initial_dcid = cid(&.{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x5e));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    // Version Negotiation offering only a version we do not speak.
    var vn: [64]u8 = undefined;
    var cursor: usize = 0;
    vn[0] = packet.header_form_bit | packet.fixed_bit;
    cursor = 1;
    std.mem.writeInt(u32, vn[cursor..][0..4], 0, .big); // version 0 identifies it
    cursor += 4;
    vn[cursor] = client_cid.len;
    cursor += 1;
    @memcpy(vn[cursor..][0..client_cid.len], client_cid.slice());
    cursor += client_cid.len;
    vn[cursor] = 0;
    cursor += 1;
    std.mem.writeInt(u32, vn[cursor..][0..4], 0xff00_001d, .big); // a draft version
    cursor += 4;

    try testing.expectError(error.VersionNegotiationFailed, conn.receive(gpa, vn[0..cursor]));

    // One that lists the version we already sent is invalid (§6.2) and discarded:
    // a genuine server would have answered normally.
    var fresh = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x5e));
    defer fresh.deinit(gpa);
    try fresh.start(gpa);
    std.mem.writeInt(u32, vn[cursor - 4 ..][0..4], @backingInt(packet.Version.v1), .big);
    try fresh.receive(gpa, vn[0..cursor]);
    try testing.expect(!fresh.closed);
}

/// Build a Retry packet with a valid integrity tag over `original_dcid`.
fn writeRetry(
    dest: []u8,
    destination: ConnectionId,
    source: ConnectionId,
    token: []const u8,
    original_dcid: ConnectionId,
) usize {
    var cursor: usize = 0;
    dest[0] = packet.header_form_bit | packet.fixed_bit |
        (@as(u8, @backingInt(packet.LongType.retry)) << 4);
    cursor = 1;
    std.mem.writeInt(u32, dest[cursor..][0..4], @backingInt(packet.Version.v1), .big);
    cursor += 4;
    dest[cursor] = destination.len;
    cursor += 1;
    @memcpy(dest[cursor..][0..destination.len], destination.slice());
    cursor += destination.len;
    dest[cursor] = source.len;
    cursor += 1;
    @memcpy(dest[cursor..][0..source.len], source.slice());
    cursor += source.len;
    @memcpy(dest[cursor..][0..token.len], token);
    cursor += token.len;

    const tag = crypto.retryIntegrityTag(original_dcid.slice(), dest[0..cursor]);
    @memcpy(dest[cursor..][0..crypto.tag_len], &tag);
    return cursor + crypto.tag_len;
}
