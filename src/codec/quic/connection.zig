//! A QUIC connection: datagrams in, events out, no sockets involved.
//!
//! The same shape as `http2/connection.zig` and for the same reason — everything
//! interesting about a protocol is testable without I/O if the layer that speaks
//! it never touches a socket. `receive` takes one UDP payload; `send` fills one.
//! Task 12 attaches those two to a datagram endpoint.
//!
//! This layer owns the parts of RFC 9000 that make packets reach the far end:
//! assembly and coalescing (§12.2), the CRYPTO stream's reassembly (§7.5), Retry
//! and address validation (§8.1, §17.2.5), the §7.3 connection ID check that
//! authenticates packet headers, and the wiring from frames to `streams.zig`.
//! Loss recovery and congestion control are the next layer up, and absent here
//! rather than stubbed: ACK generation reports a single range, and nothing is
//! retransmitted.
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
const recovery = @import("recovery.zig");
const varint = @import("varint.zig");
const cid_mod = @import("cid.zig");
const stream_mod = @import("stream.zig");
const streams_mod = @import("streams.zig");

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
} || Allocator.Error;
// Allocation failure is included rather than folded into a protocol error, for the
// reason stream.zig gives: telling the peer PROTOCOL_VIOLATION because malloc
// failed sends it looking for a bug it does not have.

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
    /// §10.1: the idle timeout elapsed. The close is silent — nothing is sent,
    /// because a peer idle that long may be gone, and a CONNECTION_CLOSE to a
    /// vanished peer is a packet an attacker can observe and spoof around.
    idle_timeout,
    /// A Retry was accepted and the handshake restarted. Surfaced because it
    /// changes the connection ID and invalidates any packet already in flight.
    retry_received,
    /// Data is readable on a stream. The bytes stay in the stream's reassembly
    /// buffer; the application reads them with `read` and releases flow control
    /// credit with `consume`. Delivering the slice here would mean either copying
    /// it or promising a lifetime this layer cannot keep.
    stream_readable: struct { id: u64, fin: bool },
    /// §19.4: the peer abandoned its side of a stream.
    stream_reset: struct { id: u64, code: u64 },
    /// §19.5: the peer no longer wants what we are sending on a stream, and §3.5
    /// obliges us to reset it.
    stream_stop_sending: struct { id: u64, code: u64 },
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
    /// §4's initial windows and §4.6's stream counts, as we advertise them. The
    /// values in `parameters` and these must agree, so they are derived from
    /// `parameters` rather than given twice.
    stream_window: u64 = 256 * 1024,
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
    /// Every packet number received, as ranges. This is both what we
    /// acknowledge — all of it, not just the largest — and §12.3's duplicate
    /// detection, which can only happen after packet protection is removed.
    /// One structure for both on purpose: a duplicate check against anything
    /// other than what we acknowledge would be a second source of truth.
    received: recovery.AckRanges = .{},
    /// When the packet that is currently `received.largest()` arrived, for the
    /// ACK frame's delay field.
    largest_received_at: u64 = 0,
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

const Close = struct { code: u64, application: bool };

pub const LifeState = enum {
    active,
    /// We sent CONNECTION_CLOSE and answer further packets with it (§10.2.1).
    closing,
    /// The peer terminated (CONNECTION_CLOSE or a stateless reset): nothing
    /// more may be sent, not even a close (§10.2.2, §10.3.1) — a packet sent
    /// now would make the peer answer, and two endpoints doing that to each
    /// other close nothing.
    draining,
    /// The terminal period ended or the connection failed outright; the owner
    /// may discard all state.
    drained,
};

/// What one sent packet carried, for §13.3: when the packet is acknowledged
/// its content is released, and when it is lost its *information* — not the
/// packet — is queued to be sent again.
const SentMeta = struct {
    number: u64,
    ack_eliciting: bool = false,
    /// The CRYPTO range this packet carried, `len == 0` if none.
    crypto_offset: u64 = 0,
    crypto_len: u64 = 0,
    /// The STREAM frames it carried. Bounded, and the writer respects the bound
    /// by simply starting a new packet: a limit the writer can exceed is not a
    /// limit.
    streams: [max_stream_frames_per_packet]StreamRange = undefined,
    stream_count: u8 = 0,
    /// Stream IDs whose MAX_STREAM_DATA rode in this packet.
    credits: [max_credit_frames_per_packet]u64 = undefined,
    credit_count: u8 = 0,
    /// Stream IDs whose RESET_STREAM rode in this packet.
    resets: [max_credit_frames_per_packet]u64 = undefined,
    reset_count: u8 = 0,
    /// RETIRE_CONNECTION_ID sequence numbers carried.
    retires: [cid_mod.max_stored]u64 = undefined,
    retire_count: u8 = 0,
    carried_max_data: bool = false,
    carried_max_streams: [2]bool = .{ false, false },

    const StreamRange = struct { id: u64, offset: u64, len: u64, fin: bool };

    fn worthKeeping(self: *const SentMeta) bool {
        return self.ack_eliciting;
    }
};

/// STREAM frames per packet. The packet writer starts refusing stream frames at
/// this point; the data simply waits for the next packet, which costs nothing.
const max_stream_frames_per_packet = 8;
/// MAX_STREAM_DATA and RESET_STREAM frames per packet, same mechanism.
const max_credit_frames_per_packet = 8;

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
    /// §10's connection lifecycle. Everything before termination is `.active`;
    /// the two shutdown states exist because §10.2 gives them *opposite* rules
    /// about sending — closing answers packets with CONNECTION_CLOSE, draining
    /// must send nothing at all — and a bool cannot hold opposite obligations.
    state: LifeState = .active,
    /// When the closing or draining period ends and the connection may be
    /// discarded (§10.2: three times the PTO).
    terminal_deadline: u64 = 0,
    /// The close we sent (or will send), kept after sending because §10.2.1
    /// requires answering packets received while closing with it again.
    close_info: ?Close = null,
    /// Packets received while closing, for §10.2.1's rate limit on responses.
    closing_received: u64 = 0,
    /// §10.1: when the last authenticated packet arrived or the idle timer was
    /// otherwise restarted.
    idle_restarted_at: u64 = 0,
    /// §10.1's second restart rule: sending an ack-eliciting packet restarts
    /// the timer, but only the first one since last receiving. Without this an
    /// endpoint retransmitting into a void keeps its own connection alive
    /// forever.
    idle_sent_since_receive: bool = false,
    /// A CONNECTION_CLOSE we owe the peer.
    pending_close: ?Close = null,

    // ── Loss detection and congestion control (RFC 9002) ────────────────────
    /// The caller's clock, advanced through `setTime`. Injected rather than
    /// read, like every other clock in this repository: recovery is nothing
    /// *but* time arithmetic, and a wall clock would make every timing rule
    /// untestable.
    now_ns: u64 = 0,
    loss: recovery.Spaces = .{},
    rtt: recovery.Rtt = .{},
    congestion: recovery.Congestion = .init(max_datagram),
    /// What each in-flight packet carried, per space, so that an acknowledgement
    /// can release it and a loss can requeue it. Parallel to `loss`'s own
    /// bookkeeping and correlated by packet number — recovery deliberately does
    /// not know what a packet contains.
    sent_meta: [3]std.ArrayList(SentMeta) = .{ .empty, .empty, .empty },
    /// A PTO fired and the next packet at this level must elicit an
    /// acknowledgement (§6.2.4). For a client this is also §8.1's obligation:
    /// not sending here can deadlock the handshake against the server's
    /// anti-amplification limit.
    probe_pending: [Level.count]bool = @splat(false),
    /// Credit frames whose packet was lost, re-armed for regeneration. These
    /// resend the *current* value rather than the lost one (§13.3: retransmit
    /// the information, not the frame).
    rearm_max_data: bool = false,
    rearm_max_streams: [2]bool = .{ false, false },
    credit_rearm: std.ArrayList(u64) = .empty,

    streams: streams_mod.Streams,
    /// Whether a stream has something to put in a packet. A flag rather than a
    /// scan, because `hasSomethingToSend` runs for every datagram and walking every
    /// stream to answer "is there anything" would make an idle connection with many
    /// streams cost more than a busy one with few.
    pending_stream_data: bool = false,
    /// Round-robin cursor over streams, so one busy stream cannot starve the rest.
    /// §2.3 leaves prioritisation to the application; this is the floor beneath any
    /// scheme it chooses.
    send_cursor: u64 = 0,

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
            .streams = .init(.client, .{
                // Derived from the transport parameters rather than configured
                // separately: two places to state the same window is two places
                // for them to disagree, and the peer would believe the parameters.
                .local_max_data = parameters.initial_max_data,
                .local_max_stream_data = parameters.initial_max_stream_data_bidi_local,
                .local_max_streams_bidi = parameters.initial_max_streams_bidi,
                .local_max_streams_uni = parameters.initial_max_streams_uni,
            }),
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
        self.streams.deinit(gpa);
        for (&self.spaces) |*space| space.deinit(gpa);
        self.engine.deinit(gpa);
        self.events.deinit(gpa);
        self.loss.deinit(gpa);
        for (&self.sent_meta) |*list| list.deinit(gpa);
        self.credit_rearm.deinit(gpa);
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

    /// Advance the connection's clock. Call before `receive` and `send` with a
    /// monotonic reading; the connection never reads a clock itself. Injection
    /// is what lets every RTT, loss and PTO rule below be tested against a
    /// schedule the test writes.
    pub fn setTime(self: *Connection, now_ns: u64) void {
        self.now_ns = @max(self.now_ns, now_ns);
    }

    /// The connection has left `.active` and may (once `.drained`) be freed.
    pub fn lifecycle(self: *const Connection) LifeState {
        return self.state;
    }

    fn enterTerminal(self: *Connection, target: LifeState) void {
        assert(target == .closing or target == .draining);
        // Draining trumps closing (§10.2.2: once the peer has spoken, we send
        // nothing), and neither goes backwards.
        if (self.state == .drained) return;
        if (self.state == .draining and target == .closing) return;
        self.state = target;
        // §10.2: the terminal period is three PTOs — long enough for our close
        // (or the peer's) to be retransmitted through ordinary loss.
        self.terminal_deadline = self.now_ns + 3 * self.rtt.probeTimeout(.application);
    }

    /// §10.1: the effective idle timeout, or null when idling is unlimited.
    /// Enforced only once the peer's parameters are authenticated, because the
    /// effective value is the minimum of the two advertisements and half of
    /// that pair is unknown before then.
    fn idleDeadline(self: *const Connection) ?u64 {
        const peer = self.peer_parameters orelse return null;
        const ours = self.parameters.max_idle_timeout_ms;
        const theirs = peer.max_idle_timeout_ms;
        const effective_ms = if (ours == 0)
            theirs
        else if (theirs == 0)
            ours
        else
            @min(ours, theirs);
        if (effective_ms == 0) return null;
        // §10.1: never below three PTOs, or a slow path's ordinary
        // retransmission delays get misread as absence.
        const span = @max(effective_ms *| std.time.ns_per_ms, 3 * self.rtt.probeTimeout(.application));
        return self.idle_restarted_at +| span;
    }

    /// When the caller should next call `onTimeout`, as an absolute time on the
    /// injected clock, or null if no timer is armed.
    pub fn nextTimeout(self: *const Connection) ?u64 {
        switch (self.state) {
            .drained => return null,
            .closing, .draining => return self.terminal_deadline,
            .active => {},
        }
        var earliest = self.loss.nextTimeout(&self.rtt, self.handshake_confirmed);
        if (self.idleDeadline()) |idle| {
            if (earliest == null or idle < earliest.?) earliest = idle;
        }
        return earliest;
    }

    /// The loss/probe timer fired. Declares time-threshold losses if any are
    /// due; otherwise this is a PTO (§6.2), and the next packet sent will probe.
    /// §8.1 makes the probe an obligation for a client, not an optimisation: a
    /// server that has not validated the address may not send more than three
    /// times what it received, so a client that goes silent can deadlock the
    /// handshake with both sides waiting for the other.
    pub fn onTimeout(self: *Connection, gpa: Allocator, now_ns: u64) !void {
        self.setTime(now_ns);

        switch (self.state) {
            .closing, .draining => {
                // §10.2: the terminal period has run its course; everything may
                // now be discarded, including the state that would have answered
                // a straggling packet.
                if (self.now_ns >= self.terminal_deadline) self.state = .drained;
                return;
            },
            .drained => return,
            .active => {},
        }

        if (self.idleDeadline()) |idle| {
            if (self.now_ns >= idle) {
                // §10.1: the close is *silent*. There is nobody demonstrably
                // there to tell, and CONNECTION_CLOSE sent into a void is a
                // template an observer can use.
                self.state = .drained;
                try self.events.append(gpa, .idle_timeout);
                return;
            }
        }

        var any_lost = false;
        for ([_]Level{ .initial, .handshake, .one_rtt }) |level| {
            if (self.spaceFor(level).send == null) continue;
            const lost = try self.loss.detectLostOnTimer(
                gpa,
                recoverySpace(level),
                self.now_ns,
                &self.rtt,
            );
            if (lost.len == 0) continue;
            any_lost = true;
            var latest: ?recovery.Sent = null;
            for (lost) |p| {
                self.congestion.onLost(p);
                if (latest == null or p.time_sent > latest.?.time_sent) latest = p;
                if (self.takeMeta(level, p.number)) |meta| try self.onPacketLost(gpa, level, &meta);
            }
            if (latest.?.in_flight) self.congestion.onCongestion(latest.?.time_sent, self.now_ns);
        }
        if (any_lost) return;

        // A probe timeout — but only if one was actually due. `onTimeout` is
        // callable at any moment (a caller with several timers may be early or
        // late), and fabricating a probe whenever it happens to be called would
        // send PINGs no schedule asked for and double the backoff for free.
        const pto = self.loss.nextTimeout(&self.rtt, self.handshake_confirmed) orelse return;
        if (self.now_ns < pto) return;
        self.loss.onProbeTimeout();
        const level = self.highestSendLevel();
        self.probe_pending[@backingInt(level)] = true;
    }

    pub fn nextEvent(self: *Connection) ?Event {
        if (self.events.items.len == 0) return null;
        return self.events.orderedRemove(0);
    }

    /// Ask to close, which will be sent by the next `send`.
    pub fn close(self: *Connection, code: u64, application: bool) void {
        if (self.state != .active) return;
        self.close_info = .{ .code = code, .application = application };
        self.pending_close = self.close_info;
    }

    // ── The application's view of streams ────────────────────────────────────

    /// Open a stream, returning its ID. Fails with StreamLimitError until the
    /// handshake has authenticated the peer's §4.6 limits, because before that we
    /// have no permission to open anything.
    pub fn openStream(self: *Connection, gpa: Allocator, bidirectional: bool) Error!u64 {
        const id = self.streams.open(gpa, bidirectional) catch |err| {
            try self.mapStreamError(err);
            unreachable;
        };
        return id.value;
    }

    /// Queue data on a stream, returning how many bytes were accepted. A short
    /// write is flow control rather than failure, and it is the caller's business
    /// to try again once a MAX_DATA or MAX_STREAM_DATA arrives.
    pub fn write(self: *Connection, gpa: Allocator, id: u64, data: []const u8) Error!usize {
        const n = self.streams.write(gpa, .init(id), data) catch |err| {
            try self.mapStreamError(err);
            unreachable;
        };
        if (n > 0) self.pending_stream_data = true;
        return n;
    }

    /// End our side of a stream (§19.8's FIN).
    pub fn finishStream(self: *Connection, id: u64) Error!void {
        const s = self.streams.get(.init(id)) orelse return error.ProtocolViolation;
        const sender = &(s.send orelse return error.ProtocolViolation);
        sender.finish() catch |err| {
            try self.mapStreamError(err);
            unreachable;
        };
        self.pending_stream_data = true;
    }

    /// Abandon our side of a stream (§19.4).
    pub fn resetStream(self: *Connection, id: u64, code: u64) Error!void {
        const s = self.streams.get(.init(id)) orelse return error.ProtocolViolation;
        const sender = &(s.send orelse return error.ProtocolViolation);
        _ = sender.abandon(code) catch |err| {
            try self.mapStreamError(err);
            unreachable;
        };
        self.pending_stream_data = true;
    }

    /// Readable bytes on a stream. They stay in the stream's buffer until
    /// `consume`, which is what releases flow control credit — a reader that never
    /// consumes stalls the peer, which is the honest outcome.
    pub fn read(self: *Connection, id: u64) []const u8 {
        const s = self.streams.get(.init(id)) orelse return &.{};
        const recv = &(s.recv orelse return &.{});
        return recv.readable();
    }

    pub fn consume(self: *Connection, gpa: Allocator, id: u64, n: usize) void {
        self.streams.consume(gpa, .init(id), n);
    }

    /// Take a stream's reset code, which is what lets the stream be forgotten.
    pub fn takeStreamReset(self: *Connection, gpa: Allocator, id: u64) ?u64 {
        return self.streams.takeReset(gpa, .init(id));
    }

    fn recoverySpace(level: Level) recovery.Space {
        return switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .one_rtt => .application,
        };
    }

    /// Find and remove the record of what packet `number` carried. Null for
    /// packets that carried nothing retransmittable — those were tracked for
    /// congestion but have nothing to release or requeue.
    fn takeMeta(self: *Connection, level: Level, number: u64) ?SentMeta {
        const list = &self.sent_meta[@backingInt(level)];
        for (list.items, 0..) |meta, i| {
            if (meta.number == number) return list.orderedRemove(i);
        }
        return null;
    }

    /// The packet was acknowledged: release what it carried.
    fn onPacketAcked(self: *Connection, level: Level, meta: *const SentMeta) void {
        _ = level;
        for (meta.streams[0..meta.stream_count]) |range| {
            const s = self.streams.get(.init(range.id)) orelse continue;
            const sender = &(s.send orelse continue);
            sender.markRangeAcked(range.offset, range.len, range.fin);
        }
        for (meta.resets[0..meta.reset_count]) |id| {
            const s = self.streams.get(.init(id)) orelse continue;
            const sender = &(s.send orelse continue);
            // §3.1: RESET_STREAM acknowledged moves reset_sent to reset_recvd,
            // which is `markAcked`'s fin_acked path for a reset stream.
            sender.markAcked(sender.acked, true);
        }
        // CRYPTO, credit and retirement frames need nothing on acknowledgement:
        // their effect was already applied when they were written.
    }

    /// The packet was declared lost: queue its *information* to be resent
    /// (§13.3 — the information, never the packet).
    fn onPacketLost(self: *Connection, gpa: Allocator, level: Level, meta: *const SentMeta) !void {
        if (meta.crypto_len > 0) {
            // The engine's output buffer still holds these bytes — it is not
            // consumed until the handshake completes, for exactly this reason
            // (and for Retry). Rewinding the watermark *is* the retransmission.
            const sp = self.spaceFor(level);
            sp.crypto_sent = @min(sp.crypto_sent, meta.crypto_offset);
        }
        for (meta.streams[0..meta.stream_count]) |range| {
            const s = self.streams.get(.init(range.id)) orelse continue;
            const sender = &(s.send orelse continue);
            sender.rewind(range.offset, range.fin);
            self.pending_stream_data = true;
        }
        for (meta.resets[0..meta.reset_count]) |id| {
            const s = self.streams.get(.init(id)) orelse continue;
            const sender = &(s.send orelse continue);
            // The reset writer uses `fin_sent` as its "already sent" marker;
            // clearing it is the re-arm.
            if (sender.state == .reset_sent) {
                sender.fin_sent = false;
                self.pending_stream_data = true;
            }
        }
        for (meta.credits[0..meta.credit_count]) |id| {
            // Re-armed by ID, and the frame regenerated from *current* state:
            // §13.3 says the most recent value, and the lost one may be stale.
            var known = false;
            for (self.credit_rearm.items) |existing| {
                if (existing == id) known = true;
            }
            if (!known) try self.credit_rearm.append(gpa, id);
        }
        for (meta.retires[0..meta.retire_count]) |sequence| {
            self.remote.requeueRetire(sequence);
        }
        if (meta.carried_max_data) self.rearm_max_data = true;
        if (meta.carried_max_streams[0]) self.rearm_max_streams[0] = true;
        if (meta.carried_max_streams[1]) self.rearm_max_streams[1] = true;
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
        switch (self.state) {
            .active => {},
            .closing => {
                // §10.2.1: answer with the CONNECTION_CLOSE again, but not once
                // per packet — an attacker replaying captured packets would have
                // a packet generator otherwise. Exponential spacing: the 1st,
                // 2nd, 4th, 8th... packet each provoke one response.
                self.closing_received += 1;
                if (std.math.isPowerOfTwo(self.closing_received)) {
                    self.pending_close = self.close_info;
                }
                return;
            },
            // §10.2.2 and §10.3.1: nothing is processed and nothing is sent.
            .draining, .drained => return,
        }

        // §10.3: a stateless reset is indistinguishable from a short-header
        // packet until the last 16 bytes are compared against a token we hold, so
        // it is checked before parsing rather than after failing to.
        if (datagram.len >= 21) {
            const candidate = datagram[datagram.len - cid_mod.stateless_reset_token_len ..];
            if (self.remote.matchesResetToken(candidate[0..cid_mod.stateless_reset_token_len])) {
                // §10.3.1: enter draining, send nothing further. The reset means
                // the peer has no state; a close sent at it would only provoke
                // another reset.
                self.enterTerminal(.draining);
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
                    // back to. This ends the attempt rather than being ignored —
                    // and there is no one to tell, so the state is terminal at
                    // once.
                    self.state = .drained;
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
        const pn = packet.decodePacketNumber(sp.received.largest(), truncated, pn_len);

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
        // §10.1: receiving and processing a packet restarts the idle timer, and
        // re-arms the "first ack-eliciting send restarts it too" rule.
        self.idle_restarted_at = self.now_ns;
        self.idle_sent_since_receive = false;

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
        // §12.3: a packet number already processed is discarded, and the check
        // can only happen here — after protection is removed — because the
        // number was encrypted. The set consulted is the same one the ACK frame
        // is built from: one structure, so the two can never disagree.
        if (sp.received.contains(pn)) return;
        const previous_largest = sp.received.largest();
        if (previous_largest == null or pn > previous_largest.?) {
            sp.largest_received_at = self.now_ns;
        }
        sp.received.add(pn);

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
                    const sp = self.spaceFor(level);
                    if (sp.largest_acked == null or ack.largest > sp.largest_acked.?) {
                        sp.largest_acked = ack.largest;
                    }
                    try self.handleAck(gpa, level, ack);
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
                    self.discardHandshakeKeys(gpa);
                },
                .connection_close => |c| {
                    const len = @min(c.reason.len, max_reason_len);
                    @memcpy(self.reason_buf[0..len], c.reason[0..len]);
                    // §10.2.2: the peer's close puts us in draining, where
                    // nothing more is sent. Answering a close with a close makes
                    // two endpoints keep each other awake.
                    self.enterTerminal(.draining);
                    try self.events.append(gpa, .{ .peer_closed = .{
                        .code = c.error_code,
                        .application = c.is_application,
                        .reason = self.reason_buf[0..len],
                    } });
                    return;
                },
                .stream => |sf| {
                    const id: stream_mod.Id = .init(sf.id);
                    try self.mapStreamError(self.streams.receiveStream(
                        gpa,
                        id,
                        sf.offset,
                        sf.data,
                        sf.fin,
                    ));
                    if (self.streams.get(id)) |s| {
                        if (s.recv) |*r| {
                            if (r.readable().len > 0 or sf.fin) {
                                try self.events.append(gpa, .{ .stream_readable = .{
                                    .id = sf.id,
                                    .fin = r.final_size != null,
                                } });
                            }
                        }
                    }
                },
                .reset_stream => |sf| {
                    try self.mapStreamError(self.streams.receiveReset(
                        gpa,
                        .init(sf.id),
                        sf.error_code,
                        sf.final_size,
                    ));
                    try self.events.append(gpa, .{ .stream_reset = .{
                        .id = sf.id,
                        .code = sf.error_code,
                    } });
                },
                .stop_sending => |sf| {
                    try self.mapStreamError(self.streams.receiveStopSending(
                        gpa,
                        .init(sf.id),
                        sf.error_code,
                    ));
                    try self.events.append(gpa, .{ .stream_stop_sending = .{
                        .id = sf.id,
                        .code = sf.error_code,
                    } });
                },
                .max_data => |limit| self.streams.receiveMaxData(limit),
                .max_stream_data => |sf| try self.mapStreamError(
                    self.streams.receiveMaxStreamData(gpa, .init(sf.id), sf.limit),
                ),
                .max_streams_bidi => |n| try self.mapStreamError(
                    self.streams.receiveMaxStreams(true, n),
                ),
                .max_streams_uni => |n| try self.mapStreamError(
                    self.streams.receiveMaxStreams(false, n),
                ),
                .stream_data_blocked => |sf| try self.mapStreamError(
                    self.streams.receiveStreamDataBlocked(gpa, .init(sf.id)),
                ),
                // §19.12 and §19.14 are signals that the peer wants to send more.
                // They carry no obligation — a receiver must not wait for one
                // before extending credit (§4.2) — so there is nothing to do but
                // acknowledge the packet, which happens above.
                .data_blocked, .streams_blocked_bidi, .streams_blocked_uni => {},
                // §19.17 and §19.18 belong with path validation, which is
                // connection migration's business. Refused rather than ignored:
                // answering a PATH_CHALLENGE without validating the path is worse
                // than not answering, and silently dropping it would make
                // migration fail in a way no log explains.
                .path_challenge, .path_response => return error.ProtocolViolation,
            }
        }
    }

    /// Translate a stream-layer error into this layer's, which is where the QUIC
    /// error code is decided. Kept in one place so that a new call site cannot
    /// quietly map FLOW_CONTROL_ERROR onto something more convenient.
    /// Resolve an ACK frame against loss recovery: sample the RTT, release what
    /// was acknowledged, requeue what was lost, and tell the congestion
    /// controller both.
    fn handleAck(self: *Connection, gpa: Allocator, level: Level, ack: frame.Ack) !void {
        const resolution = try self.loss.resolve(
            gpa,
            recoverySpace(level),
            ack,
            self.now_ns,
            &self.rtt,
        );

        if (resolution.rtt_sample) |sample| {
            // §18.2: the peer's ack_delay is in microseconds, scaled by its own
            // ack_delay_exponent. Saturating arithmetic on purpose: the field is
            // attacker-chosen, and §5.3's floor inside `sample` is what defuses
            // it — but only if the scaling does not trap first.
            const exponent: u6 = @intCast(@min(
                if (self.peer_parameters) |peer| peer.ack_delay_exponent else 3,
                20,
            ));
            const delay_us = std.math.shl(u64, ack.delay, exponent);
            const delay_ns = delay_us *| std.time.ns_per_us;
            self.rtt.sample(sample, delay_ns, self.handshake_confirmed);
        }

        for (resolution.acked) |p| {
            self.congestion.onAck(p, self.now_ns);
            if (self.takeMeta(level, p.number)) |meta| self.onPacketAcked(level, &meta);
        }

        var latest_lost: ?recovery.Sent = null;
        for (resolution.lost) |p| {
            self.congestion.onLost(p);
            if (latest_lost == null or p.time_sent > latest_lost.?.time_sent) latest_lost = p;
            if (self.takeMeta(level, p.number)) |meta| try self.onPacketLost(gpa, level, &meta);
        }
        if (latest_lost) |p| {
            if (p.in_flight) self.congestion.onCongestion(p.time_sent, self.now_ns);
            const duration = recovery.Spaces.persistentCongestionDuration(&self.rtt);
            if (recovery.Spaces.isPersistentCongestion(resolution.lost, resolution.acked, duration)) {
                self.congestion.onPersistentCongestion();
            }
        }
    }

    fn mapStreamError(self: *Connection, result: streams_mod.Error!void) Error!void {
        _ = self;
        result catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            // Every one of these is a connection error under §11.1. They differ in
            // the code sent to the peer, which task 8 will carry; the effect here
            // is the same.
            error.FlowControlError,
            error.StreamLimitError,
            error.StreamStateError,
            error.FinalSizeError,
            error.ProtocolViolation,
            error.ReassemblyBufferExceeded,
            => error.ProtocolViolation,
        };
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
        // §5.3 caps the peer's claimed ack_delay at this once the handshake is
        // confirmed; taking it from the *authenticated* parameters is the point.
        self.rtt.max_ack_delay = peer.max_ack_delay_ms *| std.time.ns_per_ms;
        self.local.setPeerLimit(peer.active_connection_id_limit);
        // §7.4: the peer's limits only exist once the handshake authenticated
        // them. Applying them earlier would mean trusting unauthenticated numbers
        // about how much we may send.
        self.streams.applyPeerParameters(&peer);
        self.established = true;
        try self.events.append(gpa, .{ .established = .{ .alpn = self.engine.alpn() } });
    }

    fn discardHandshakeKeys(self: *Connection, gpa: Allocator) void {
        // §4.9 of RFC 9001: once the handshake is confirmed these keys must go,
        // so that a packet protected with them can no longer be processed.
        for ([_]Level{ .initial, .handshake }) |level| {
            const sp = self.spaceFor(level);
            sp.send = null;
            sp.recv = null;
            // RFC 9001 §4.9: the space's recovery state goes with its keys.
            // Keeping it would arm a PTO for packets that can never be
            // acknowledged now, and the probe it sent could not be protected.
            self.loss.discard(gpa, recoverySpace(level));
            self.sent_meta[@backingInt(level)].clearAndFree(gpa);
        }
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Fill `dest` with the next datagram to send, returning its length, or zero
    /// if there is nothing to send.
    pub fn send(self: *Connection, gpa: Allocator, dest: []u8) !usize {
        // §10's send-side rules have exactly two enforcement points, one per
        // granularity, and this is the packet-level one: draining sends nothing
        // at all, and closing sends only when a close is owed. The frame-level
        // one is `terminal` in `writeFrames`, which decides what may share the
        // packet with that close. `hasSomethingToSend` deliberately has no
        // state check of its own — a third copy of the same rule is a third
        // thing to keep correct.
        switch (self.state) {
            .active => {},
            .closing => if (self.pending_close == null) return 0,
            .draining, .drained => return 0,
        }
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
            len += try self.writePacket(gpa, dest[len..limit], level, pad_to -| len);
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
        if (self.probe_pending[@backingInt(level)]) return true;

        // A CONNECTION_CLOSE goes at the highest level we have keys for, since
        // that is the one the peer is most likely able to read.
        if (self.pending_close != null and self.highestSendLevel() == level) return true;

        // Retirements owed for the peer's connection IDs need 1-RTT.
        if (level == .one_rtt and self.remote.pendingRetire().len > 0) return true;

        if (level == .one_rtt and self.established) {
            // Stream data is the one thing the congestion window gates (§7):
            // acknowledgements, credit and probes must still flow when the
            // window is full, or the very acknowledgements that would reopen it
            // are blocked behind it.
            if (self.pending_stream_data and self.congestion.available() > 0) return true;
            if (self.rearm_max_data or self.rearm_max_streams[0] or
                self.rearm_max_streams[1] or self.credit_rearm.items.len > 0) return true;
            if (self.streams.maxDataUpdate() != null) return true;
            if (self.streams.maxStreamsUpdate(true) != null) return true;
            if (self.streams.maxStreamsUpdate(false) != null) return true;
            if (self.creditOwed() != null) return true;
        }

        return false;
    }

    /// The first stream owed a MAX_STREAM_DATA, if any.
    fn creditOwed(self: *Connection) ?struct { id: u64, limit: u64 } {
        var it = self.streams.map.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr;
            const recv = &(s.recv orelse continue);
            if (recv.creditUpdate(self.streams.config.local_max_stream_data)) |limit| {
                return .{ .id = entry.key_ptr.*, .limit = limit };
            }
        }
        return null;
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
        gpa: Allocator,
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
        var meta: SentMeta = .{ .number = pn };
        const payload_len = self.writeFrames(
            payload[0..@min(payload_room, payload.len)],
            level,
            // Padding is expressed in terms of the finished datagram, so work
            // back through this packet's own overhead.
            if (pad_to > cursor + crypto.tag_len) pad_to - cursor - crypto.tag_len else 0,
            &meta,
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

        // Hand the packet to loss recovery and the congestion controller.
        // §2: in-flight means ack-eliciting or padded — a pure-ACK packet is
        // neither counted against the window nor ever probed for.
        const record: recovery.Sent = .{
            .number = pn,
            .time_sent = self.now_ns,
            .size = total,
            .ack_eliciting = meta.ack_eliciting,
            .in_flight = meta.ack_eliciting or pad_to > 0,
        };
        try self.loss.onSent(gpa, recoverySpace(level), record);
        self.congestion.onSent(record);
        if (record.ack_eliciting and !self.idle_sent_since_receive) {
            // §10.1's second restart rule, once per quiet period: the *first*
            // ack-eliciting packet since last receiving restarts the timer, but
            // retransmissions after it must not — an endpoint whose own probes
            // keep resetting its own idle clock never times out at all.
            self.idle_sent_since_receive = true;
            self.idle_restarted_at = self.now_ns;
        }
        if (meta.worthKeeping()) {
            try self.sent_meta[@backingInt(level)].append(gpa, meta);
        }

        if (self.pending_close != null and self.highestSendLevel() == level) {
            self.pending_close = null;
            if (self.state == .active) self.enterTerminal(.closing);
        }
        return total;
    }

    fn writeFrames(
        self: *Connection,
        dest: []u8,
        level: Level,
        pad_to: usize,
        meta: *SentMeta,
    ) usize {
        const sp = self.spaceFor(level);
        var len: usize = 0;
        // §10.2.1 again, at the frame level: the first close packet goes out
        // while still `.active`, so it may carry whatever else was queued; the
        // re-sends provoked by later packets carry the close alone.
        const terminal = self.state != .active;

        // ACK first: it is the smallest useful thing in the packet, and putting
        // it ahead of CRYPTO means a packet that has to be truncated still
        // acknowledges. Every received range is reported, not just the largest —
        // reporting less makes the peer retransmit what arrived (§13.2.3).
        if (sp.ack_pending and !terminal) {
            if (sp.received.largest() != null) {
                const ranges = sp.received.slice();
                const first = ranges[0];

                // The additional ranges, encoded through `gapTo` — `descend`'s
                // inverse, so the arithmetic that built the set is the same
                // arithmetic that serializes it.
                var extra: [recovery.max_ack_ranges * 16]u8 = undefined;
                var extra_len: usize = 0;
                var previous_smallest = first.smallest;
                for (ranges[1..]) |range| {
                    extra_len += varint.encode(
                        extra[extra_len..],
                        frame.Ack.gapTo(previous_smallest, range.largest),
                    );
                    extra_len += varint.encode(extra[extra_len..], range.largest - range.smallest);
                    previous_smallest = range.smallest;
                }

                // §13.2.5: how long the largest packet sat here unacknowledged,
                // in microseconds scaled down by our own ack_delay_exponent.
                const held_ns = self.now_ns - @min(sp.largest_received_at, self.now_ns);
                const delay = (held_ns / std.time.ns_per_us) >>
                    @intCast(@min(self.parameters.ack_delay_exponent, 20));

                const f: frame.Frame = .{ .ack = .{
                    .largest = first.largest,
                    .delay = delay,
                    .first_range = first.largest - first.smallest,
                    .range_count = ranges.len - 1,
                    .ranges = extra[0..extra_len],
                    .ecn = null,
                } };
                const need = frame.encodedLen(f);
                if (len + need <= dest.len) len += frame.encode(dest[len..], f);
            }
        }

        // A probe (§6.2.4). PING is the cheapest ack-eliciting frame; anything
        // else ack-eliciting in this packet would also do, but a guaranteed one
        // beats hoping.
        if (self.probe_pending[@backingInt(level)] and !terminal) {
            const f: frame.Frame = .ping;
            if (len + frame.encodedLen(f) <= dest.len) {
                len += frame.encode(dest[len..], f);
                self.probe_pending[@backingInt(level)] = false;
                meta.ack_eliciting = true;
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
        if (pending.len > sp.crypto_sent and !terminal) {
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
                meta.crypto_offset = offset;
                meta.crypto_len = take;
                meta.ack_eliciting = true;
                sp.crypto_sent += take;
            }
        }

        if (level == .one_rtt and self.established and !terminal) {
            len += self.writeStreamFrames(dest[len..], meta);
        }

        if (level == .one_rtt and !terminal) {
            const owed = self.remote.pendingRetire();
            var sent: usize = 0;
            for (owed) |sequence| {
                if (meta.retire_count == meta.retires.len) break;
                const f: frame.Frame = .{ .retire_connection_id = sequence };
                const need = frame.encodedLen(f);
                if (len + need > dest.len) break;
                len += frame.encode(dest[len..], f);
                meta.retires[meta.retire_count] = sequence;
                meta.retire_count += 1;
                meta.ack_eliciting = true;
                sent += 1;
            }
            if (sent > 0) self.remote.clearPendingRetire(sent);
        }

        // RFC 9001 §5.4.2: header protection samples 16 bytes starting four
        // bytes past the start of the packet number, so everything from there —
        // packet number, payload, tag — must reach 20 bytes. The tag gives 16
        // and the number at least one; a payload under four (a lone PING probe)
        // leaves the sampler reading past the packet, which `sampleFor` asserts
        // against rather than silently protecting with someone else's bytes.
        if (len > 0 and len < 4) {
            const want = 4 - len;
            len += frame.encode(dest[len..], .{ .padding = want });
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

    /// Write whatever the streams have to say into one packet's payload.
    ///
    /// Control frames come first and data last, which is deliberate: a MAX_DATA that
    /// loses its place to stream data is a window that does not open, and the sender
    /// it was meant to unblock waits a round trip for the next chance. Stream data,
    /// by contrast, is never lost by being deferred — there is always another packet.
    fn writeStreamFrames(self: *Connection, dest: []u8, meta: *SentMeta) usize {
        var len: usize = 0;

        // Re-armed credit: a packet carrying these frames was lost, and §13.3
        // says resend the information — the *current* value, not the lost one,
        // which may be stale by now.
        if (self.rearm_max_data) {
            const f: frame.Frame = .{ .max_data = self.streams.recv_max_data };
            if (len + frame.encodedLen(f) <= dest.len) {
                len += frame.encode(dest[len..], f);
                self.rearm_max_data = false;
                meta.carried_max_data = true;
                meta.ack_eliciting = true;
            }
        }
        for (0..2) |i| {
            if (!self.rearm_max_streams[i]) continue;
            const bidirectional = i == 0;
            const limit = self.streams.local_max_streams[i];
            const f: frame.Frame = if (bidirectional)
                .{ .max_streams_bidi = limit }
            else
                .{ .max_streams_uni = limit };
            if (len + frame.encodedLen(f) <= dest.len) {
                len += frame.encode(dest[len..], f);
                self.rearm_max_streams[i] = false;
                meta.carried_max_streams[i] = true;
                meta.ack_eliciting = true;
            }
        }
        while (self.credit_rearm.items.len > 0 and meta.credit_count < meta.credits.len) {
            const id = self.credit_rearm.items[self.credit_rearm.items.len - 1];
            const current: ?u64 = blk: {
                const stream = self.streams.get(.init(id)) orelse break :blk null;
                const recv = &(stream.recv orelse break :blk null);
                if (recv.state != .recv) break :blk null;
                break :blk recv.max_data;
            };
            const limit = current orelse {
                // The stream is gone or past needing credit; the frame with it.
                _ = self.credit_rearm.pop();
                continue;
            };
            const f: frame.Frame = .{ .max_stream_data = .{ .id = id, .limit = limit } };
            if (len + frame.encodedLen(f) > dest.len) break;
            len += frame.encode(dest[len..], f);
            _ = self.credit_rearm.pop();
            meta.credits[meta.credit_count] = id;
            meta.credit_count += 1;
            meta.ack_eliciting = true;
        }

        if (self.streams.maxDataUpdate()) |limit| {
            const f: frame.Frame = .{ .max_data = limit };
            if (len + frame.encodedLen(f) <= dest.len) {
                len += frame.encode(dest[len..], f);
                self.streams.applyMaxDataSent(limit);
                meta.carried_max_data = true;
                meta.ack_eliciting = true;
            }
        }

        for ([_]bool{ true, false }) |bidirectional| {
            if (self.streams.maxStreamsUpdate(bidirectional)) |limit| {
                const f: frame.Frame = if (bidirectional)
                    .{ .max_streams_bidi = limit }
                else
                    .{ .max_streams_uni = limit };
                if (len + frame.encodedLen(f) <= dest.len) {
                    len += frame.encode(dest[len..], f);
                    self.streams.applyMaxStreamsSent(bidirectional, limit);
                    meta.carried_max_streams[if (bidirectional) 0 else 1] = true;
                    meta.ack_eliciting = true;
                }
            }
        }

        while (self.creditOwed()) |owed| {
            if (meta.credit_count == meta.credits.len) break;
            const f: frame.Frame = .{ .max_stream_data = .{ .id = owed.id, .limit = owed.limit } };
            if (len + frame.encodedLen(f) > dest.len) break;
            len += frame.encode(dest[len..], f);
            self.streams.get(.init(owed.id)).?.recv.?.applyCredit(owed.limit);
            meta.credits[meta.credit_count] = owed.id;
            meta.credit_count += 1;
            meta.ack_eliciting = true;
        }

        // §19.4: a reset replaces any data still queued, so it goes out before we
        // consider sending on that stream.
        var reset_it = self.streams.map.iterator();
        while (reset_it.next()) |entry| {
            const s = entry.value_ptr;
            const sender = &(s.send orelse continue);
            if (sender.state != .reset_sent or sender.reset_code == null) continue;
            if (sender.fin_sent) continue; // already sent, awaiting acknowledgement
            const f: frame.Frame = .{ .reset_stream = .{
                .id = entry.key_ptr.*,
                .error_code = sender.reset_code.?,
                .final_size = sender.written,
            } };
            if (meta.reset_count == meta.resets.len) break;
            if (len + frame.encodedLen(f) > dest.len) break;
            len += frame.encode(dest[len..], f);
            sender.fin_sent = true;
            meta.resets[meta.reset_count] = entry.key_ptr.*;
            meta.reset_count += 1;
            meta.ack_eliciting = true;
        }

        // Stream data, round robin: one frame per stream per pass, which is the rule
        // http2/flow.zig's scheduler follows and for the same reason — a stream with
        // a lot to say must not be able to hold the others off.
        //
        // **The share matters as much as the order.** Giving the first stream all
        // the remaining room means one frame fills the packet and the rotation never
        // gets a turn, so a starved stream looks like a hung request rather than an
        // error. QUIC has no frame size limit to fall back on, unlike HTTP/2, so the
        // budget has to be divided explicitly.
        var progressed = false;
        const waiting = self.countSendable();
        if (waiting == 0) {
            if (self.creditOwed() == null) self.pending_stream_data = false;
            return len;
        }
        var visited: usize = 0;
        const total = self.streams.map.count();
        // §7: stream data is what the congestion window gates. The budget is
        // consulted as the packet fills so a partial window still sends a
        // partial packet.
        var budget: usize = @intCast(@min(self.congestion.available(), @as(u64, dest.len)));
        while (visited < total) : (visited += 1) {
            if (meta.stream_count == meta.streams.len) break;
            const id_value = self.nextSendable() orelse break;
            const s = self.streams.get(.init(id_value)).?;
            const sender = &s.send.?;

            const outstanding = sender.written - sender.sent;
            const fin_pending = sender.fin_written and !sender.fin_sent;
            if (outstanding == 0 and !fin_pending) continue;

            // The frame's own header costs a type byte, a stream ID, an offset and a
            // length, so the payload cannot simply be the remaining room.
            const overhead = 1 + varint.encodedLen(id_value) +
                varint.encodedLen(sender.sent) + varint.encodedLen(outstanding);
            if (len + overhead >= dest.len) break;
            const room = dest.len - len - overhead;
            // An equal share of what is left, so every waiting stream fits. A
            // stream wanting less than its share leaves the rest to the others,
            // because the divisor is recomputed as the packet fills.
            const share = @max(room / @max(self.countSendable(), 1), 1);
            const take: usize = @intCast(@min(@min(@min(room, share), outstanding), @as(u64, budget)));
            if (take == 0 and !(fin_pending and outstanding == 0)) break;

            const offset = sender.sent;
            const f: frame.Frame = .{ .stream = .{
                .id = id_value,
                .offset = offset,
                .data = sender.unsent()[0..take],
                .fin = fin_pending and take == outstanding,
                .had_length = true,
            } };
            if (len + frame.encodedLen(f) > dest.len) break;
            len += frame.encode(dest[len..], f);
            sender.markSent(take, f.stream.fin);
            budget -= take;
            meta.streams[meta.stream_count] = .{
                .id = id_value,
                .offset = offset,
                .len = take,
                .fin = f.stream.fin,
            };
            meta.stream_count += 1;
            meta.ack_eliciting = true;
            progressed = true;
        }

        if (!progressed and self.creditOwed() == null) self.pending_stream_data = false;
        return len;
    }

    /// How many streams have something to put in a packet.
    fn countSendable(self: *Connection) usize {
        var total: usize = 0;
        var it = self.streams.map.valueIterator();
        while (it.next()) |s| {
            const sender = &(s.send orelse continue);
            if (sender.written > sender.sent) total += 1;
            if (sender.fin_written and !sender.fin_sent) total += 1;
        }
        return total;
    }

    /// The next stream with something to send, advancing the round-robin cursor.
    fn nextSendable(self: *Connection) ?u64 {
        var best: ?u64 = null;
        var wrapped: ?u64 = null;
        var it = self.streams.map.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr;
            const sender = &(s.send orelse continue);
            const has_data = sender.written > sender.sent;
            const has_fin = sender.fin_written and !sender.fin_sent;
            if (!has_data and !has_fin) continue;
            const id_value = entry.key_ptr.*;
            if (id_value >= self.send_cursor) {
                if (best == null or id_value < best.?) best = id_value;
            } else {
                if (wrapped == null or id_value < wrapped.?) wrapped = id_value;
            }
        }
        const chosen = best orelse wrapped orelse return null;
        self.send_cursor = chosen + 1;
        return chosen;
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
/// Test fixture: a minimal QUIC server that derives its own keys. Pub so the
/// HTTP/3 layer's tests can drive a real peer over real datagrams.
pub const PacketServer = struct {
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

pub fn testOptions(local: ConnectionId, initial_dcid: ConnectionId) Options {
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
    try testing.expect(conn.state == .active);
    try testing.expect(!conn.isEstablished());
    // Nothing was learned from it, which is the part that matters: state changed
    // by an unauthenticated packet is state an attacker controls.
    try testing.expect(conn.spaceFor(.initial).received.largest() == null);
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
    try testing.expect(conn.state != .active);
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
    try testing.expect(conn.state != .active);

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
    conn.discardHandshakeKeys(gpa);
    conn.spaceFor(.one_rtt).ack_pending = true;
    conn.spaceFor(.one_rtt).received.add(0);
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
    const before = conn.spaceFor(.initial).received.largest();
    var impostor: PacketServer = .init(0x5d, initial_dcid, cid(&.{ 0xff, 0xfe }));
    defer impostor.deinit(gpa);
    impostor.next_pn[0] = 99;
    var second_buf: [max_datagram]u8 = undefined;
    const second_len = try impostor.writeLongPacket(&second_buf, .initial, client_cid, "junk");
    try conn.receive(gpa, second_buf[0..second_len]);

    try testing.expectEqual(before, conn.spaceFor(.initial).received.largest());
    try testing.expect(conn.remote.active().eql(&server_cid));

    // The same packet with the *right* source connection ID is processed, which
    // proves the test above is checking the source check rather than something
    // incidental about the packet.
    var honest: PacketServer = .init(0x5d, initial_dcid, server_cid);
    defer honest.deinit(gpa);
    honest.next_pn[0] = 99;
    const third_len = try honest.writeLongPacket(&second_buf, .initial, client_cid, "junk");
    try conn.receive(gpa, second_buf[0..third_len]);
    try testing.expectEqual(@as(?u64, 99), conn.spaceFor(.initial).received.largest());
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
    try testing.expect(conn.spaceFor(.initial).received.largest() == null);
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
    try testing.expect(fresh.state == .active);
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

/// Drive a client to an established handshake against a `PacketServer`, leaving
/// both able to exchange 1-RTT packets. Returns the server's 1-RTT keys so the
/// test can read what the client sends.
/// Test fixture: 1-RTT seal/open for an established connection. Pub for the
/// same reason as PacketServer.
pub const Established = struct {
    server: PacketServer,
    send: crypto.Keys,
    recv: crypto.Keys,
    client_cid: ConnectionId,
    next_pn: u64 = 0,

    pub fn deinit(self: *Established, gpa: Allocator) void {
        self.server.deinit(gpa);
    }

    /// Decrypt a 1-RTT packet and return its frames' payload.
    pub fn open(self: *Established, dest: []u8, datagram: []const u8) ![]const u8 {
        var offset: usize = 0;
        while (offset < datagram.len) {
            // A short header carries no connection ID length, so the receiver
            // supplies its own — and the receiver here is the server, so it is the
            // *server's* connection ID that appears in the client's packets. Using
            // the client's length reads the packet number from the wrong offset and
            // every packet fails to authenticate.
            const parsed = try packet.parse(datagram[offset..], self.server.local_cid.len);
            const slice = datagram[offset..][0..parsed.end];
            offset += parsed.end;
            const protected = switch (parsed.packet) {
                .protected => |pr| pr,
                else => continue,
            };
            if (protected.long_type != null) continue; // not 1-RTT

            var work: [max_datagram]u8 = undefined;
            @memcpy(work[0..slice.len], slice);
            const buf = work[0..slice.len];
            const pn_len = crypto.unprotectHeader(buf, protected.pn_offset, &self.recv.header);
            const pn = readPacketNumber(buf[protected.pn_offset..][0..pn_len]);
            const header = buf[0 .. protected.pn_offset + pn_len];
            const body = buf[protected.pn_offset + pn_len ..];
            const n = try self.recv.open(dest, pn, header, body);
            return dest[0..n];
        }
        return &.{};
    }

    /// Build a 1-RTT packet carrying `frames`.
    pub fn seal(self: *Established, dest: []u8, destination: ConnectionId, frames: []const u8) !usize {
        const pn = self.next_pn;
        const pn_len: u4 = 4;
        var cursor: usize = 0;
        dest[0] = packet.fixed_bit | (pn_len - 1);
        cursor = 1;
        @memcpy(dest[cursor..][0..destination.len], destination.slice());
        cursor += destination.len;
        const pn_offset = cursor;
        packet.encodePacketNumber(dest[cursor..][0..pn_len], pn, pn_len);
        cursor += pn_len;
        const sealed = try self.send.seal(dest[cursor..], pn, dest[0..cursor], frames);
        const total = cursor + sealed;
        crypto.protectHeader(dest[0..total], pn_offset, pn_len, &self.send.header);
        self.next_pn += 1;
        return total;
    }
};

pub fn establish(
    gpa: Allocator,
    conn: *Connection,
    client_cid: ConnectionId,
    server_cid: ConnectionId,
    initial_dcid: ConnectionId,
    server_params: *transport.Parameters,
) !Established {
    var server: PacketServer = .init(0xa7, initial_dcid, server_cid);
    errdefer server.deinit(gpa);

    var out: [max_datagram]u8 = undefined;
    const first = try conn.send(gpa, &out);
    try server.receive(gpa, out[0..first]);

    server_params.initial_source_connection_id = server_cid;
    server_params.original_destination_connection_id = initial_dcid;
    var params_buf: [256]u8 = undefined;
    const params_len = transport.encode(&params_buf, server_params, .server);

    var reply: [max_datagram]u8 = undefined;
    const reply_len = try server.reply(&reply, client_cid, "h3", params_buf[0..params_len]);
    try conn.receive(gpa, reply_len_slice(&reply, reply_len));

    // The client's Finished, so the server's own state machine completes.
    const second = try conn.send(gpa, &out);
    try server.receive(gpa, out[0..second]);

    const suite = server.inner.schedule.?.suite;
    const app = server.inner.application_secrets.?;
    return .{
        .server = server,
        .send = .fromSecret(suite, app.server.slice()),
        .recv = .fromSecret(suite, app.client.slice()),
        .client_cid = client_cid,
    };
}

fn reply_len_slice(buf: []u8, len: usize) []const u8 {
    return buf[0..len];
}

test "connection: a stream carries data to the peer and back" {
    // The point of wiring streams to packets: application bytes cross a real
    // datagram in both directions, through flow control, framing, AEAD and header
    // protection, with a peer that derived its own keys.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xc0, 0xc1, 0xc2 });
    const server_cid = cid(&.{ 0x50, 0x51 });
    const initial_dcid = cid(&.{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x64));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);
    try testing.expect(conn.isEstablished());

    // §4.6: the peer's limits only became usable when the handshake authenticated
    // them, so opening works now and would not have before.
    const id = try conn.openStream(gpa, true);
    try testing.expectEqual(@as(u64, 0), id); // client-initiated bidirectional, index 0

    const request = "GET / HTTP/3-ish";
    try testing.expectEqual(request.len, try conn.write(gpa, id, request));
    try conn.finishStream(id);

    var out: [max_datagram]u8 = undefined;
    const len = try conn.send(gpa, &out);
    try testing.expect(len > 0);

    // The server reads the stream frame out of a genuine 1-RTT packet.
    var plain: [max_datagram]u8 = undefined;
    var rest = try peer.open(&plain, out[0..len]);
    try testing.expect(rest.len > 0);

    var saw: ?frame.Stream = null;
    while (rest.len > 0) {
        const f = try frame.parse(&rest);
        switch (f) {
            .stream => |sf| saw = sf,
            else => {},
        }
    }
    const got = saw.?;
    try testing.expectEqual(id, got.id);
    try testing.expectEqual(@as(u64, 0), got.offset);
    try testing.expectEqualStrings(request, got.data);
    try testing.expect(got.fin);

    // And the reply comes back the same way: the server answers on the same
    // bidirectional stream.
    const response = "hello from the server";
    var frames: [128]u8 = undefined;
    const frames_len = frame.encode(&frames, .{ .stream = .{
        .id = id,
        .offset = 0,
        .data = response,
        .fin = true,
        .had_length = true,
    } });
    var packet_buf: [max_datagram]u8 = undefined;
    const packet_len = try peer.seal(&packet_buf, client_cid, frames[0..frames_len]);
    try conn.receive(gpa, packet_buf[0..packet_len]);

    var readable = false;
    while (conn.nextEvent()) |event| {
        switch (event) {
            .stream_readable => |e| {
                try testing.expectEqual(id, e.id);
                try testing.expect(e.fin);
                readable = true;
            },
            else => {},
        }
    }
    try testing.expect(readable);
    try testing.expectEqualStrings(response, conn.read(id));

    // Consuming is what releases flow control credit, and it is also what lets the
    // stream be forgotten once both halves are done.
    conn.consume(gpa, id, response.len);
    try testing.expectEqual(@as(usize, 0), conn.read(id).len);
}

test "connection: §4.1's connection window is enforced across streams over real packets" {
    // The two-level check, end to end. The peer grants a small connection window
    // and a large per-stream one, so a second stream is refused credit even though
    // its own window is untouched — and the refusal is a short write rather than an
    // error, because flow control is not a failure.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xd0, 0xd1 });
    const server_cid = cid(&.{ 0x60, 0x61 });
    const initial_dcid = cid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x71));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 100,
        .initial_max_stream_data_bidi_remote = 1000,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    const a = try conn.openStream(gpa, true);
    const b = try conn.openStream(gpa, true);

    const payload: [80]u8 = @splat('x');
    try testing.expectEqual(@as(usize, 80), try conn.write(gpa, a, &payload));
    // Only 20 of the connection's 100 bytes are left, so the second stream gets
    // 20 despite having 1000 of its own.
    try testing.expectEqual(@as(usize, 20), try conn.write(gpa, b, &payload));
    try testing.expectEqual(@as(usize, 0), try conn.write(gpa, b, &payload));
    try testing.expect(conn.streams.isBlocked());

    // A MAX_DATA from the peer opens it again: 400 total, 100 spent, so the next
    // write is bounded by the payload rather than by either window.
    var frames: [32]u8 = undefined;
    const frames_len = frame.encode(&frames, .{ .max_data = 400 });
    var packet_buf: [max_datagram]u8 = undefined;
    const packet_len = try peer.seal(&packet_buf, client_cid, frames[0..frames_len]);
    try conn.receive(gpa, packet_buf[0..packet_len]);

    try testing.expect(!conn.streams.isBlocked());
    try testing.expectEqual(@as(usize, 80), try conn.write(gpa, b, &payload));
    // And the connection window is what stops it again: 300 were granted beyond
    // the 100 already spent, so 80 + 80 + 80 + 60 exhausts it.
    try testing.expectEqual(@as(usize, 80), try conn.write(gpa, b, &payload));
    try testing.expectEqual(@as(usize, 80), try conn.write(gpa, b, &payload));
    try testing.expectEqual(@as(usize, 60), try conn.write(gpa, b, &payload));
    try testing.expect(conn.streams.isBlocked());
}

test "connection: two streams share the wire round robin" {
    // §2.3 leaves prioritisation to the application, so the floor beneath any
    // scheme is that one stream with a lot to say cannot hold the others off. The
    // failure this prevents is a starved stream, which looks like a hung request
    // rather than an error.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xe0, 0xe1 });
    const server_cid = cid(&.{ 0x70, 0x71 });
    const initial_dcid = cid(&.{ 8, 7, 6, 5, 4, 3, 2, 1 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x35));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    const a = try conn.openStream(gpa, true);
    const b = try conn.openStream(gpa, true);

    // Enough on each that neither fits in one packet.
    const bulk: [4000]u8 = @splat('b');
    _ = try conn.write(gpa, a, &bulk);
    _ = try conn.write(gpa, b, &bulk);

    // **Both streams appear in the very first packet.** That is the assertion worth
    // making: "both appear eventually" would pass with a first-come scheduler too,
    // once the first stream simply ran out of data. Sharing the packet is the
    // property, and the failure it prevents is a starved stream — which looks like a
    // hung request rather than an error.
    var out: [max_datagram]u8 = undefined;
    const len = try conn.send(gpa, &out);
    try testing.expect(len > 0);

    var plain: [max_datagram]u8 = undefined;
    var rest = try peer.open(&plain, out[0..len]);
    var bytes_a: usize = 0;
    var bytes_b: usize = 0;
    while (rest.len > 0) {
        const f = try frame.parse(&rest);
        switch (f) {
            .stream => |sf| {
                if (sf.id == a) bytes_a += sf.data.len;
                if (sf.id == b) bytes_b += sf.data.len;
            },
            else => {},
        }
    }
    try testing.expect(bytes_a > 0);
    try testing.expect(bytes_b > 0);
    // Roughly equal shares, since neither stream asked for less than its share.
    const ratio = @max(bytes_a, bytes_b) / @max(@min(bytes_a, bytes_b), 1);
    try testing.expect(ratio <= 2);

    // And both keep making progress on the next pass rather than one being
    // permanently behind.
    const second = try conn.send(gpa, &out);
    rest = try peer.open(&plain, out[0..second]);
    var again_a = false;
    var again_b = false;
    while (rest.len > 0) {
        const f = try frame.parse(&rest);
        switch (f) {
            .stream => |sf| {
                if (sf.id == a) again_a = true;
                if (sf.id == b) again_b = true;
            },
            else => {},
        }
    }
    try testing.expect(again_a and again_b);
}

test "connection: a peer's RESET_STREAM is reported and the stream is reclaimed" {
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xf0, 0xf1 });
    const server_cid = cid(&.{ 0x80, 0x81 });
    const initial_dcid = cid(&.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x46));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 4096,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    const id = try conn.openStream(gpa, true);
    _ = try conn.write(gpa, id, "partial");

    // The server abandons its side, claiming it sent 12 bytes.
    var frames: [64]u8 = undefined;
    const frames_len = frame.encode(&frames, .{ .reset_stream = .{
        .id = id,
        .error_code = 0x2a,
        .final_size = 12,
    } });
    var packet_buf: [max_datagram]u8 = undefined;
    const packet_len = try peer.seal(&packet_buf, client_cid, frames[0..frames_len]);
    try conn.receive(gpa, packet_buf[0..packet_len]);

    var code: ?u64 = null;
    while (conn.nextEvent()) |event| {
        switch (event) {
            .stream_reset => |e| code = e.code,
            else => {},
        }
    }
    try testing.expectEqual(@as(?u64, 0x2a), code);
    // §4.5: the 12 bytes are charged to the connection window even though none
    // arrived, because the peer spent that credit.
    try testing.expectEqual(@as(u64, 12), conn.streams.recv_used);

    // Taking the reset and abandoning our own half lets the stream go.
    try testing.expectEqual(@as(?u64, 0x2a), conn.takeStreamReset(gpa, id));
    try conn.resetStream(id, 0);
    conn.streams.get(.init(id)).?.send.?.markAcked(7, true);
    conn.streams.reapIfFinished(gpa, .init(id));
    try testing.expect(conn.streams.get(.init(id)) == null);
    // The credit stays charged after the stream is gone.
    try testing.expectEqual(@as(u64, 12), conn.streams.recv_used);
}

test "connection: MAX_STREAM_DATA goes out as the application consumes" {
    // §4.2: a receiver credits what it has room for, and it must not wait for a
    // STREAM_DATA_BLOCKED before doing so — waiting would block the sender for at
    // least a round trip, and indefinitely if it never sends one.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x0a, 0x0b });
    const server_cid = cid(&.{ 0x90, 0x91 });
    const initial_dcid = cid(&.{ 9, 9, 8, 8, 7, 7, 6, 6 });

    var options = testOptions(client_cid, initial_dcid);
    // The connection window is deliberately close to the stream window, so that one
    // stream's consumption clears the half-window threshold at both levels. With a
    // 64 KiB connection window, 900 bytes would not be worth a MAX_DATA — correctly
    // — and the test would then prove nothing about the connection level.
    options.parameters.initial_max_data = 1200;
    options.parameters.initial_max_stream_data_bidi_local = 1000;
    options.parameters.initial_max_streams_bidi = 4;

    var conn = try Connection.initClient(options, @splat(0x57));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 4096,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    const id = try conn.openStream(gpa, true);

    // The server fills most of the stream's window.
    const bulk: [900]u8 = @splat('s');
    var frames: [1024]u8 = undefined;
    const frames_len = frame.encode(&frames, .{ .stream = .{
        .id = id,
        .offset = 0,
        .data = &bulk,
        .fin = false,
        .had_length = true,
    } });
    var packet_buf: [max_datagram]u8 = undefined;
    const packet_len = try peer.seal(&packet_buf, client_cid, frames[0..frames_len]);
    try conn.receive(gpa, packet_buf[0..packet_len]);
    try testing.expectEqual(@as(usize, 900), conn.read(id).len);

    // Received but unread: there is nowhere to put more, so no credit is due.
    try testing.expect(conn.creditOwed() == null);

    conn.consume(gpa, id, 900);
    const owed = conn.creditOwed().?;
    try testing.expectEqual(id, owed.id);
    try testing.expectEqual(@as(u64, 1900), owed.limit);

    // And it actually goes out on the wire, together with the connection-level
    // MAX_DATA that the same consumption earned.
    var out: [max_datagram]u8 = undefined;
    const len = try conn.send(gpa, &out);
    var plain: [max_datagram]u8 = undefined;
    var rest = try peer.open(&plain, out[0..len]);

    var saw_stream_credit = false;
    var saw_connection_credit = false;
    while (rest.len > 0) {
        const f = try frame.parse(&rest);
        switch (f) {
            .max_stream_data => |sf| {
                try testing.expectEqual(id, sf.id);
                try testing.expectEqual(@as(u64, 1900), sf.limit);
                saw_stream_credit = true;
            },
            .max_data => saw_connection_credit = true,
            else => {},
        }
    }
    try testing.expect(saw_stream_credit);
    try testing.expect(saw_connection_credit);
    // Sent once: repeating a limit the peer already has is pure overhead (§4.1
    // requires it to be ignored).
    try testing.expect(conn.creditOwed() == null);
}

test "connection: credit frames keep their place when the packet is full" {
    // The ordering inside a packet matters exactly when the packet is full, which
    // is the case this test constructs. A MAX_DATA that loses its place to stream
    // data is a window that does not open, and the sender it was meant to unblock
    // waits a round trip for the next chance. Stream data deferred loses nothing —
    // there is always another packet.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0x1a, 0x1b });
    const server_cid = cid(&.{ 0xa0, 0xa1 });
    const initial_dcid = cid(&.{ 3, 3, 3, 3, 4, 4, 4, 4 });

    var options = testOptions(client_cid, initial_dcid);
    options.parameters.initial_max_data = 2000;
    options.parameters.initial_max_stream_data_bidi_local = 1500;
    options.parameters.initial_max_streams_bidi = 4;

    var conn = try Connection.initClient(options, @splat(0x2c));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    const id = try conn.openStream(gpa, true);

    // The peer fills the stream's window, we read it all, and credit is now owed at
    // both levels.
    const bulk: [1400]u8 = @splat('f');
    var frames: [1600]u8 = undefined;
    const frames_len = frame.encode(&frames, .{ .stream = .{
        .id = id,
        .offset = 0,
        .data = &bulk,
        .fin = false,
        .had_length = true,
    } });
    var packet_buf: [max_datagram]u8 = undefined;
    const packet_len = try peer.seal(&packet_buf, client_cid, frames[0..frames_len]);
    try conn.receive(gpa, packet_buf[0..packet_len]);
    conn.consume(gpa, id, 1400);
    try testing.expect(conn.creditOwed() != null);
    try testing.expect(conn.streams.maxDataUpdate() != null);

    // And we have far more to send than one packet holds, so the packet will be
    // full and something has to be left out.
    const outbound: [8000]u8 = @splat('o');
    _ = try conn.write(gpa, id, &outbound);

    var out: [max_datagram]u8 = undefined;
    const len = try conn.send(gpa, &out);
    var plain: [max_datagram]u8 = undefined;
    var rest = try peer.open(&plain, out[0..len]);

    var saw_max_data = false;
    var saw_max_stream_data = false;
    var stream_bytes: usize = 0;
    while (rest.len > 0) {
        const f = try frame.parse(&rest);
        switch (f) {
            .max_data => saw_max_data = true,
            .max_stream_data => saw_max_stream_data = true,
            .stream => |sf| stream_bytes += sf.data.len,
            else => {},
        }
    }

    // Both credit frames made it, and the stream data filled what was left rather
    // than the other way round.
    try testing.expect(saw_max_data);
    try testing.expect(saw_max_stream_data);
    try testing.expect(stream_bytes > 1000);
    // The packet really was full: there is more to send.
    try testing.expect(conn.pending_stream_data);
}

test "connection: the ACK reports every received range, and a duplicate packet is discarded" {
    // Two properties of one structure. The packet numbers received are kept as
    // ranges, and the ACK frame reports all of them — reporting only the largest
    // makes the peer retransmit everything in the gap, which after loss recovery
    // exists is no longer merely pessimistic but wrong. And §12.3's duplicate
    // discard consults the same set, so the two can never disagree about what
    // has been processed.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xc0, 0xc1, 0xc2 });
    const server_cid = cid(&.{ 0x50, 0x51 });
    const initial_dcid = cid(&.{ 0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x71));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    // Two PINGs with a packet number missing between them.
    var ping_frame: [4]u8 = undefined;
    const ping_len = frame.encode(&ping_frame, .ping);
    var first_buf: [256]u8 = undefined;
    const first_len = try peer.seal(&first_buf, client_cid, ping_frame[0..ping_len]);
    try conn.receive(gpa, first_buf[0..first_len]);

    peer.next_pn += 1; // the hole
    var second_buf: [256]u8 = undefined;
    const second_len = try peer.seal(&second_buf, client_cid, ping_frame[0..ping_len]);
    try conn.receive(gpa, second_buf[0..second_len]);

    const sp = conn.spaceFor(.one_rtt);
    try testing.expectEqual(@as(usize, 2), sp.received.slice().len);

    // The client's ACK carries both ranges.
    var out: [max_datagram]u8 = undefined;
    const len = try conn.send(gpa, &out);
    try testing.expect(len > 0);
    var plain: [max_datagram]u8 = undefined;
    var rest = try peer.open(&plain, out[0..len]);
    var saw_ack: ?frame.Ack = null;
    while (rest.len > 0) {
        switch (try frame.parse(&rest)) {
            .ack => |ack| saw_ack = ack,
            else => {},
        }
    }
    const ack = saw_ack.?;
    try testing.expectEqual(@as(u64, 1), ack.range_count);
    const high = ack.first();
    try testing.expectEqual(sp.received.slice()[0].largest, high.largest);
    var it = ack.iterator();
    const low = it.next().?;
    try testing.expectEqual(sp.received.slice()[1].largest, low.largest);
    // And the hole is not covered: acknowledging a packet never received is how
    // a sender is convinced its loss never happened.
    try testing.expect(!ack.covers(high.largest - 1));

    // §12.3: the same datagram again — same packet number — is discarded
    // before its frames are seen. The observable consequence is what matters:
    // an undiscarded duplicate re-arms `ack_pending`, so a replayed packet
    // provokes a fresh ACK — and an attacker replaying one captured packet
    // turns the connection into a packet generator. Discarded, there is
    // nothing to say.
    try conn.receive(gpa, second_buf[0..second_len]);
    try testing.expectEqual(@as(usize, 2), sp.received.slice().len);
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));
}

test "connection: lost stream data is retransmitted at its original offset" {
    // §6.1.1 end to end: four packets of stream data, an ACK that covers only
    // the newest, and the oldest — three below it — is declared lost. What goes
    // out again is the *information* (§13.3): a STREAM frame at the original
    // offset, rebuilt from the send queue, not a copy of the lost packet.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xc3, 0xc4, 0xc5 });
    const server_cid = cid(&.{ 0x52, 0x53 });
    const initial_dcid = cid(&.{ 0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x72));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    const id = try conn.openStream(gpa, true);
    const first_pn = conn.spaceFor(.one_rtt).next_pn;

    // Four packets, four bytes of stream data each.
    var out: [max_datagram]u8 = undefined;
    for ([_][]const u8{ "aaaa", "bbbb", "cccc", "dddd" }) |chunk| {
        try testing.expectEqual(chunk.len, try conn.write(gpa, id, chunk));
        try testing.expect(try conn.send(gpa, &out) > 0);
    }
    try testing.expectEqual(first_pn + 4, conn.spaceFor(.one_rtt).next_pn);

    // The server acknowledges only the newest. first_pn is exactly
    // packet_threshold below it, so it alone crosses §6.1.1's line; the two
    // between stay outstanding.
    var frames: [64]u8 = undefined;
    const frames_len = frame.encode(&frames, .{ .ack = .{
        .largest = first_pn + 3,
        .delay = 0,
        .first_range = 0,
        .range_count = 0,
        .ranges = &.{},
        .ecn = null,
    } });
    var packet_buf: [256]u8 = undefined;
    const packet_len = try peer.seal(&packet_buf, client_cid, frames[0..frames_len]);
    try conn.receive(gpa, packet_buf[0..packet_len]);

    // The acknowledgement produced an RTT sample...
    try testing.expect(conn.rtt.smoothed != null);

    // ...and the loss produced a retransmission, from the very start of what
    // the peer never confirmed.
    const resend_len = try conn.send(gpa, &out);
    try testing.expect(resend_len > 0);
    var plain: [max_datagram]u8 = undefined;
    var rest = try peer.open(&plain, out[0..resend_len]);
    var saw: ?frame.Stream = null;
    while (rest.len > 0) {
        switch (try frame.parse(&rest)) {
            .stream => |sf| saw = sf,
            else => {},
        }
    }
    const sf = saw.?;
    try testing.expectEqual(@as(u64, 0), sf.offset);
    try testing.expectEqualStrings("aaaa", sf.data[0..4]);
}

test "connection: a probe timeout sends a PING rather than going silent" {
    // §6.2 and §8.1 together. With something ack-eliciting outstanding a timer
    // is armed; when it fires with no loss to declare, the next packet carries
    // a PING. For a client this is an obligation, not an optimisation: a server
    // that has not validated the address may send at most three times what it
    // received (§8.1), so a client that goes silent after loss leaves both
    // sides waiting for the other — a deadlock that presents as a hung
    // connection on exactly the networks that lose packets.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xc6, 0xc7, 0xc8 });
    const server_cid = cid(&.{ 0x54, 0x55 });
    const initial_dcid = cid(&.{ 0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x73));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    // Confirm the handshake so only the application space is in play; the
    // fixture never acknowledges, and handshake packets left outstanding would
    // arm their own timers.
    conn.handshake_confirmed = true;
    conn.discardHandshakeKeys(gpa);

    // Nothing ack-eliciting outstanding: no PTO. The only timer armed is the
    // idle timeout, far away — an idle connection that probes forever is
    // traffic the application never asked for, and a NAT binding kept alive by
    // accident.
    const idle_only = conn.nextTimeout().?;

    const id = try conn.openStream(gpa, true);
    _ = try conn.write(gpa, id, "hello");
    var out: [max_datagram]u8 = undefined;
    try testing.expect(try conn.send(gpa, &out) > 0);

    // With data in flight, the PTO is the nearer of the two timers.
    const deadline = conn.nextTimeout().?;
    try testing.expect(deadline > 0);
    try testing.expect(deadline < idle_only);

    // The timer fires with nothing acknowledged: a probe, not a loss.
    try conn.onTimeout(gpa, deadline);
    const probe_len = try conn.send(gpa, &out);
    try testing.expect(probe_len > 0);

    var plain: [max_datagram]u8 = undefined;
    var rest = try peer.open(&plain, out[0..probe_len]);
    var saw_ping = false;
    while (rest.len > 0) {
        switch (try frame.parse(&rest)) {
            .ping => saw_ping = true,
            else => {},
        }
    }
    try testing.expect(saw_ping);

    // §6.2: the next deadline backs off, because the first probe may itself
    // have been lost and probing at a fixed cadence floods a congested path.
    const next_deadline = conn.nextTimeout().?;
    try testing.expect(next_deadline > deadline);
}

test "connection: closing answers packets with the close again, rate limited, then drains" {
    // §10.2.1 has three rules pulling in different directions: a peer that
    // missed the CONNECTION_CLOSE must be able to provoke it again (its ACK was
    // the only proof of delivery and there is none); an attacker replaying one
    // captured packet must not get a packet generator; and nothing *else* may
    // be sent, or the connection keeps living under a different name.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xc9, 0xca, 0xcb });
    const server_cid = cid(&.{ 0x56, 0x57 });
    const initial_dcid = cid(&.{ 0x14, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x74));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    // Queue more stream data than one datagram holds, so that after the close
    // goes out there is still data waiting — and "the replies carry only the
    // close" below is a claim about suppression, not about an empty queue.
    const id = try conn.openStream(gpa, true);
    const big: [3000]u8 = @splat('x');
    try testing.expectEqual(big.len, try conn.write(gpa, id, &big));

    conn.close(0x42, true);
    var out: [max_datagram]u8 = undefined;
    const first_len = try conn.send(gpa, &out);
    try testing.expect(first_len > 0);
    try testing.expectEqual(LifeState.closing, conn.state);
    try testing.expect(conn.pending_stream_data);

    // Closed means closed: stream API refuses, and with nothing provoking a
    // response there is nothing to send.
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));

    // Each arriving packet may provoke the close again — 1st and 2nd do, the
    // 3rd (not a power of two) does not, the 4th does. The replies carry the
    // close and nothing else: no ACK, no stream data, however much was queued.
    var ping_frame: [4]u8 = undefined;
    const ping_len = frame.encode(&ping_frame, .ping);
    var expectations = [_]bool{ true, true, false, true };
    for (&expectations) |expect_reply| {
        var in_buf: [256]u8 = undefined;
        const in_len = try peer.seal(&in_buf, client_cid, ping_frame[0..ping_len]);
        try conn.receive(gpa, in_buf[0..in_len]);

        const reply_len = try conn.send(gpa, &out);
        if (!expect_reply) {
            try testing.expectEqual(@as(usize, 0), reply_len);
            continue;
        }
        try testing.expect(reply_len > 0);
        var plain: [max_datagram]u8 = undefined;
        var rest = try peer.open(&plain, out[0..reply_len]);
        var saw_close = false;
        while (rest.len > 0) {
            switch (try frame.parse(&rest)) {
                .connection_close => |c| {
                    saw_close = true;
                    try testing.expectEqual(@as(u64, 0x42), c.error_code);
                    try testing.expect(c.is_application);
                },
                .padding, .ping => {},
                // Anything else violates §10.2.1's "no packets other than those
                // containing CONNECTION_CLOSE".
                else => return error.TestUnexpectedResult,
            }
        }
        try testing.expect(saw_close);
    }

    // §10.2: after three PTOs the closing period ends and everything may go.
    const deadline = conn.nextTimeout().?;
    try conn.onTimeout(gpa, deadline);
    try testing.expectEqual(LifeState.drained, conn.state);
    try testing.expect(conn.nextTimeout() == null);
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));
}

test "connection: the peer's close puts us in draining, where nothing is sent" {
    // §10.2.2. The opposite obligation from closing — answering a close with a
    // close (or an ACK of it) keeps two endpoints awake at each other over a
    // connection both have declared dead.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xcc, 0xcd, 0xce });
    const server_cid = cid(&.{ 0x58, 0x59 });
    const initial_dcid = cid(&.{ 0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x75));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    // Queue stream data first, so "sends nothing" is a real claim about
    // suppression rather than an empty queue.
    const id = try conn.openStream(gpa, true);
    _ = try conn.write(gpa, id, "queued but never sent");

    // And close from our side *without sending yet*: the race where both ends
    // close at once. The peer's close arriving first moves us to draining, and
    // §10.2.2 says draining sends nothing — including the close we still owe.
    // An implementation that lets the pending close through behaves like
    // closing while claiming to drain, and the two states have opposite rules.
    conn.close(0x7, true);

    var frames: [64]u8 = undefined;
    const frames_len = frame.encode(&frames, .{
        .connection_close = .{
            .error_code = 0x9,
            .is_application = false,
            // §19.19: the transport variant carries the offending frame type; only
            // the application variant (0x1d) omits the field.
            .frame_type = 0,
            .reason = "bye",
        },
    });
    var in_buf: [256]u8 = undefined;
    const in_len = try peer.seal(&in_buf, client_cid, frames[0..frames_len]);
    try conn.receive(gpa, in_buf[0..in_len]);

    while (conn.nextEvent()) |event| {
        switch (event) {
            .peer_closed => |c| {
                try testing.expectEqual(@as(u64, 0x9), c.code);
                try testing.expectEqualStrings("bye", c.reason);
            },
            else => {},
        }
    }
    try testing.expectEqual(LifeState.draining, conn.state);

    // Nothing goes out — not the queued stream data, not an ACK of the close.
    var out: [max_datagram]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));

    // Later packets are ignored entirely, even a provocation that in the
    // closing state would earn a reply.
    var ping_frame: [4]u8 = undefined;
    const ping_len = frame.encode(&ping_frame, .ping);
    const ping_packet = try peer.seal(&in_buf, client_cid, ping_frame[0..ping_len]);
    try conn.receive(gpa, in_buf[0..ping_packet]);
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));
    try testing.expect(conn.nextEvent() == null);

    // And our own close() is too late to change anything: draining sends
    // nothing, so there is nothing for it to arm.
    conn.close(0x1, true);
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));
    try testing.expectEqual(LifeState.draining, conn.state);

    const deadline = conn.nextTimeout().?;
    try conn.onTimeout(gpa, deadline);
    try testing.expectEqual(LifeState.drained, conn.state);
}

test "connection: the idle timeout closes silently, and traffic restarts it" {
    // §10.1. Silent on purpose: a peer idle that long may be gone, and a
    // CONNECTION_CLOSE sent into a void is a template an observer can replay.
    // The effective value is the *minimum* of the two advertisements — a peer
    // must not be able to keep us holding state longer than we offered.
    const gpa = testing.allocator;

    const client_cid = cid(&.{ 0xcf, 0xd0, 0xd1 });
    const server_cid = cid(&.{ 0x5a, 0x5b });
    const initial_dcid = cid(&.{ 0x16, 0x26, 0x36, 0x46, 0x56, 0x66, 0x76, 0x86 });

    var conn = try Connection.initClient(testOptions(client_cid, initial_dcid), @splat(0x76));
    defer conn.deinit(gpa);
    try conn.start(gpa);

    var server_params: transport.Parameters = .{
        .initial_max_data = 1 << 20,
        .initial_max_stream_data_bidi_remote = 64 * 1024,
        .initial_max_streams_bidi = 4,
        // Below the client's 30 s, so this is the one that governs.
        .max_idle_timeout_ms = 5_000,
    };
    var peer = try establish(gpa, &conn, client_cid, server_cid, initial_dcid, &server_params);
    defer peer.deinit(gpa);

    // Confirm the handshake: the fixture never acknowledges, and the PTO for
    // the outstanding handshake packets would otherwise sit in front of the
    // idle deadline in everything below.
    conn.handshake_confirmed = true;
    conn.discardHandshakeKeys(gpa);

    const first_deadline = conn.nextTimeout().?;
    try testing.expect(first_deadline >= 5 * std.time.ns_per_s);
    try testing.expect(first_deadline < 30 * std.time.ns_per_s);

    // A packet arriving restarts the clock. Without this, a chatty connection
    // dies at exactly the same moment as an abandoned one.
    conn.setTime(2 * std.time.ns_per_s);
    var ping_frame: [4]u8 = undefined;
    const ping_len = frame.encode(&ping_frame, .ping);
    var in_buf: [256]u8 = undefined;
    const in_len = try peer.seal(&in_buf, client_cid, ping_frame[0..ping_len]);
    try conn.receive(gpa, in_buf[0..in_len]);
    const restarted = conn.nextTimeout().?;
    try testing.expect(restarted >= first_deadline + 2 * std.time.ns_per_s);

    // Early wakeups do nothing — the deadline is a fact, not a suggestion.
    try conn.onTimeout(gpa, restarted - 1);
    try testing.expectEqual(LifeState.active, conn.state);

    // At the deadline the connection ends without a packet: nothing to send,
    // no CONNECTION_CLOSE, only the event telling the owner why.
    try conn.onTimeout(gpa, restarted);
    try testing.expectEqual(LifeState.drained, conn.state);
    var saw_idle = false;
    while (conn.nextEvent()) |event| {
        if (event == .idle_timeout) saw_idle = true;
    }
    try testing.expect(saw_idle);
    var out: [max_datagram]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try conn.send(gpa, &out));
}
