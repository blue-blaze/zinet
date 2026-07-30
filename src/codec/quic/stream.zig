//! QUIC streams: RFC 9000 §2, §3 and the per-stream half of §4.
//!
//! One stream, in isolation. The collection — connection-level flow control and
//! §4.6's stream counts — is `streams.zig`, because those limits are about the
//! relationship *between* streams and putting them here would mean every stream
//! holding a pointer to shared state it does not own.
//!
//! §3 describes two state machines, one for the sending part and one for the
//! receiving part, and they are two types here rather than one. A bidirectional
//! stream has both; a unidirectional stream has whichever its direction implies.
//! Merging them would produce a state space where most combinations are
//! unreachable, and the unreachable ones are where bugs hide.
//!
//! **The rule most worth getting exactly right is §4.5's final size.** Once known
//! it cannot change, and connection-level flow control is accounted against it
//! rather than against bytes actually received. Both halves matter: the first
//! stops a peer from rewriting history, and the second stops a reset stream from
//! holding connection credit forever — which would eventually deadlock a
//! connection that never did anything wrong.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const transport = @import("transport.zig");

pub const Error = error{
    /// §4.1: the peer sent more than its flow control limit allows.
    FlowControlError,
    /// §4.5: the final size changed, or data arrived at or beyond it.
    FinalSizeError,
    /// §3.3: a frame arrived for a stream in a state that does not permit it, or
    /// for a direction that cannot carry it.
    StreamStateError,
    /// §2.2: different data at an offset already received. Detected where it is
    /// visible; see `Reassembler.insert`.
    ProtocolViolation,
    /// More buffered out-of-order data than this implementation will hold. Flow
    /// control should prevent it, but a limit that depends on the peer honouring
    /// a promise is not a limit.
    ReassemblyBufferExceeded,
} || Allocator.Error;
// Allocation failure is included rather than collapsed into a protocol error,
// because it says something entirely different: the peer did nothing wrong and
// the connection is not at fault. A CONNECTION_CLOSE carrying
// FLOW_CONTROL_ERROR because malloc failed would send the peer looking for a bug
// it does not have.

/// §2.1: the two least significant bits of a stream ID.
pub const Kind = enum(u2) {
    client_bidi = 0x00,
    server_bidi = 0x01,
    client_uni = 0x02,
    server_uni = 0x03,

    pub fn initiator(self: Kind) transport.Role {
        return switch (self) {
            .client_bidi, .client_uni => .client,
            .server_bidi, .server_uni => .server,
        };
    }

    pub fn isBidirectional(self: Kind) bool {
        return switch (self) {
            .client_bidi, .server_bidi => true,
            .client_uni, .server_uni => false,
        };
    }

    /// The lowest stream ID of this kind, which is also the value its two type
    /// bits contribute (§4.6's `first_stream_id_of_type`).
    pub fn first(self: Kind) u64 {
        return @backingInt(self);
    }
};

/// §2.1: stream IDs are 62-bit, because they are varints.
pub const max_id = (@as(u64, 1) << 62) - 1;
/// §4.6: a count above this would imply an ID that does not fit a varint.
pub const max_streams = @as(u64, 1) << 60;

pub const Id = struct {
    value: u64,

    pub fn init(value: u64) Id {
        assert(value <= max_id);
        return .{ .value = value };
    }

    pub fn kind(self: Id) Kind {
        return @fromBackingInt(@intCast(@as(u2, @truncate(self.value))));
    }

    /// Which of this kind's streams this is, counting from zero. §4.6's limits are
    /// expressed in these terms, not in stream IDs.
    pub fn index(self: Id) u64 {
        return self.value >> 2;
    }

    pub fn make(stream_kind: Kind, index_value: u64) Id {
        assert(index_value < max_streams);
        return .{ .value = (index_value << 2) | stream_kind.first() };
    }

    /// Can `role` send data on this stream? False for the receiving end of a
    /// unidirectional stream — which is what makes a STREAM frame arriving there
    /// a STREAM_STATE_ERROR rather than merely surprising.
    pub fn canSend(self: Id, role: transport.Role) bool {
        const k = self.kind();
        if (k.isBidirectional()) return true;
        return k.initiator() == role;
    }

    pub fn canReceive(self: Id, role: transport.Role) bool {
        const k = self.kind();
        if (k.isBidirectional()) return true;
        return k.initiator() != role;
    }

    /// Did `role` open this stream? §3.2 distinguishes streams we created from
    /// those the peer created, because only the latter can be implicitly opened.
    pub fn isLocallyInitiated(self: Id, role: transport.Role) bool {
        return self.kind().initiator() == role;
    }
};

/// §3.1's states for the part of a stream this endpoint sends on.
pub const SendState = enum {
    /// Created and able to accept data from the application.
    ready,
    /// Data has been sent.
    send,
    /// A STREAM frame with FIN has been sent; only retransmission remains.
    data_sent,
    /// Everything sent has been acknowledged. Terminal.
    data_recvd,
    /// RESET_STREAM sent.
    reset_sent,
    /// That reset was acknowledged. Terminal.
    reset_recvd,

    pub fn isTerminal(self: SendState) bool {
        return self == .data_recvd or self == .reset_recvd;
    }
};

/// §3.2's states for the part of a stream this endpoint receives on.
pub const RecvState = enum {
    recv,
    /// A FIN arrived, so the final size is known (§4.5).
    size_known,
    /// All data arrived, but the application has not consumed it.
    data_recvd,
    /// The application consumed everything. Terminal.
    data_read,
    /// RESET_STREAM arrived.
    reset_recvd,
    /// The application was told about the reset. Terminal.
    reset_read,

    pub fn isTerminal(self: RecvState) bool {
        return self == .data_read or self == .reset_read;
    }
};

/// Reassembly for one stream's inbound data (§2.2).
///
/// The application needs an ordered byte stream, so gaps have to be held. Data
/// that arrives in order is appended and never copied twice; data that arrives
/// early is copied, because the source points into the datagram being processed
/// and that datagram is reused.
pub const Reassembler = struct {
    /// Contiguous data the application has not read yet.
    ready: std.ArrayList(u8) = .empty,
    /// The stream offset of `ready.items[0]`.
    base: u64 = 0,
    /// Out-of-order data, sorted by offset.
    pending: std.ArrayList(Chunk) = .empty,
    pending_bytes: usize = 0,

    const Chunk = struct {
        offset: u64,
        bytes: []u8,
    };

    pub fn deinit(self: *Reassembler, gpa: Allocator) void {
        self.ready.deinit(gpa);
        for (self.pending.items) |chunk| gpa.free(chunk.bytes);
        self.pending.deinit(gpa);
    }

    /// One past the last contiguous byte available, in stream offsets.
    pub fn contiguousEnd(self: *const Reassembler) u64 {
        return self.base + self.ready.items.len;
    }

    /// Data the application can read now.
    pub fn readable(self: *const Reassembler) []const u8 {
        return self.ready.items;
    }

    /// Mark `n` bytes as consumed by the application. This is what releases flow
    /// control credit — §4.1 accounts credit against data *received*, but a
    /// receiver only advertises more once it has somewhere to put it.
    pub fn consume(self: *Reassembler, n: usize) void {
        assert(n <= self.ready.items.len);
        const rest = self.ready.items.len - n;
        std.mem.copyForwards(u8, self.ready.items[0..rest], self.ready.items[n..]);
        self.ready.shrinkRetainingCapacity(rest);
        self.base += n;
    }

    /// Accept stream data at `offset`.
    ///
    /// `max_buffered` bounds held-back out-of-order bytes. Flow control ought to
    /// make it unreachable, which is exactly why it is here: a limit that depends
    /// on the peer honouring its own promise is not a limit.
    pub fn insert(
        self: *Reassembler,
        gpa: Allocator,
        offset: u64,
        data: []const u8,
        max_buffered: usize,
    ) Error!void {
        if (data.len == 0) return;

        const end = self.contiguousEnd();
        // Wholly delivered already: an ordinary retransmission.
        if (offset + data.len <= end) {
            try self.checkOverlap(offset, data);
            return;
        }

        if (offset <= end) {
            // §2.2: the overlapping prefix must match what we already have.
            // Detected here because here it is cheap and visible. Data the
            // application has already consumed is gone, so this check is partial
            // by construction — which is why §2.2 makes it MAY rather than MUST.
            const overlap: usize = @intCast(end - offset);
            try self.checkOverlap(offset, data[0..overlap]);
            try self.ready.appendSlice(gpa, data[overlap..]);
            try self.drain(gpa);
            return;
        }

        // A gap. The copy is not optional: `data` points into the caller's
        // datagram, which is reused for the next one.
        if (self.pending_bytes + data.len > max_buffered) return error.ReassemblyBufferExceeded;
        const copy = try gpa.dupe(u8, data);
        errdefer gpa.free(copy);

        var index: usize = 0;
        while (index < self.pending.items.len and self.pending.items[index].offset < offset) {
            index += 1;
        }
        // A retransmission of something already pending at the same offset.
        if (index < self.pending.items.len and self.pending.items[index].offset == offset) {
            const existing = self.pending.items[index];
            const shared = @min(existing.bytes.len, data.len);
            // No explicit free here: `errdefer` owns `copy` on the error path.
            if (!std.mem.eql(u8, existing.bytes[0..shared], data[0..shared])) {
                return error.ProtocolViolation;
            }
            if (data.len <= existing.bytes.len) {
                gpa.free(copy);
                return;
            }
            // The new one extends further: replace it.
            gpa.free(existing.bytes);
            self.pending_bytes -= existing.bytes.len;
            self.pending.items[index] = .{ .offset = offset, .bytes = copy };
            self.pending_bytes += copy.len;
            return;
        }

        try self.pending.insert(gpa, index, .{ .offset = offset, .bytes = copy });
        self.pending_bytes += copy.len;
    }

    fn checkOverlap(self: *const Reassembler, offset: u64, data: []const u8) Error!void {
        if (offset + data.len <= self.base) return; // already consumed: cannot check
        const from = @max(offset, self.base);
        const to = @min(offset + data.len, self.contiguousEnd());
        if (to <= from) return;
        const ours = self.ready.items[@intCast(from - self.base)..@intCast(to - self.base)];
        const theirs = data[@intCast(from - offset)..@intCast(to - offset)];
        if (!std.mem.eql(u8, ours, theirs)) return error.ProtocolViolation;
    }

    fn drain(self: *Reassembler, gpa: Allocator) Error!void {
        while (self.pending.items.len > 0) {
            const chunk = self.pending.items[0];
            const end = self.contiguousEnd();
            if (chunk.offset > end) return;

            defer {
                gpa.free(chunk.bytes);
                self.pending_bytes -= chunk.bytes.len;
                _ = self.pending.orderedRemove(0);
            }

            if (chunk.offset + chunk.bytes.len <= end) continue; // fully covered
            const overlap: usize = @intCast(end - chunk.offset);
            try self.checkOverlap(chunk.offset, chunk.bytes[0..overlap]);
            try self.ready.appendSlice(gpa, chunk.bytes[overlap..]);
        }
    }
};

/// The receiving part of one stream: §3.2's state machine plus §4.1's per-stream
/// flow control.
pub const Recv = struct {
    state: RecvState = .recv,
    /// The largest offset the peer may reach, which is what we advertised.
    max_data: u64,
    /// One past the largest offset received. §4.1 accounts credit against this
    /// rather than against bytes, because the gaps still have to be held.
    highest_offset: u64 = 0,
    /// §4.5: known once a FIN or RESET_STREAM arrives, and immutable after.
    final_size: ?u64 = null,
    /// The application error code from a RESET_STREAM, if one arrived.
    reset_code: ?u64 = null,
    buffer: Reassembler = .{},

    pub fn init(initial_max_data: u64) Recv {
        return .{ .max_data = initial_max_data };
    }

    pub fn deinit(self: *Recv, gpa: Allocator) void {
        self.buffer.deinit(gpa);
    }

    /// How much of the connection's flow control this stream has consumed.
    ///
    /// §4.5 requires this to be the final size once known, even if data is
    /// missing — otherwise a stream reset with a gap in it would hold connection
    /// credit for the life of the connection, and a peer doing that on many
    /// streams would deadlock a connection that never broke a rule.
    ///
    /// It is `highest_offset` alone rather than `final_size orelse
    /// highest_offset`, because those are always equal once the final size is
    /// known: §4.5 forbids data beyond it, a FIN frame's own end *is* it, and
    /// `reset` raises `highest_offset` to it explicitly. Writing both would be a
    /// second source of truth for one quantity — the mistake this codebase has
    /// now made three times, in the ACK arithmetic, in the connection ID set, and
    /// here. **The single line in `reset` that raises `highest_offset` is §4.5's
    /// accounting mechanism**, and the test asserts that rather than this.
    pub fn flowControlUsed(self: *const Recv) u64 {
        return self.highest_offset;
    }

    /// Apply a STREAM frame. Returns how much new connection-level credit this
    /// consumed, so the caller can check the connection limit.
    pub fn receive(
        self: *Recv,
        gpa: Allocator,
        offset: u64,
        data: []const u8,
        fin: bool,
        max_buffered: usize,
    ) Error!u64 {
        // §4.5: offset+len cannot exceed the varint range. Checked by the frame
        // parser too, but this is the layer that would wrap.
        const end = std.math.add(u64, offset, data.len) catch return error.FinalSizeError;
        if (end > max_id + 1) return error.FinalSizeError;

        // **The consistency check comes before the "already handled" exit.** §4.5
        // requires reporting a changed final size "even after a stream is
        // closed", and the reason is the same one that governs a repeated
        // NEW_CONNECTION_ID in cid.zig: a retransmission must be accepted, a
        // contradiction must be refused, and having handled something already is
        // not grounds for skipping the check. Exiting first makes the check
        // conditional on timing, so a peer could get a contradiction accepted by
        // sending it late.
        if (self.final_size) |known| {
            // §4.5: data at or beyond the final size, and a FIN that disagrees
            // about where the stream ends. Both are the peer rewriting history.
            if (end > known) return error.FinalSizeError;
            if (fin and end != known) return error.FinalSizeError;
        } else if (fin) {
            // A FIN whose final size is below what we already received.
            if (end < self.highest_offset) return error.FinalSizeError;
        }

        // §3.3: a receiver may see these frames in any state because of delayed
        // delivery, so once the stream is reset the data itself is discarded —
        // but only after the check above.
        if (self.state == .reset_recvd or self.state == .reset_read) return 0;

        // §4.1: the limit applies to the offset, not to the byte count, because
        // the receiver must hold the gap as well.
        if (end > self.max_data) return error.FlowControlError;

        const before = self.flowControlUsed();
        if (end > self.highest_offset) self.highest_offset = end;
        if (fin) {
            self.final_size = end;
            if (self.state == .recv) self.state = .size_known;
        }

        try self.buffer.insert(gpa, offset, data, max_buffered);

        if (self.final_size) |known| {
            if (self.buffer.contiguousEnd() == known) {
                if (self.state == .size_known) self.state = .data_recvd;
                if (self.buffer.ready.items.len == 0) self.state = .data_read;
            }
        }

        return self.flowControlUsed() - before;
    }

    /// Apply a RESET_STREAM frame (§19.4). Returns the new connection-level credit
    /// this consumed, which may be positive even though no data arrived — that is
    /// the point of §4.5's accounting.
    pub fn reset(self: *Recv, gpa: Allocator, code: u64, final_size: u64) Error!u64 {
        // Again, consistency before the early exit: a repeated RESET_STREAM is an
        // ordinary retransmission, while one that reports a different final size
        // is §4.5's error whatever state the stream is in.
        if (self.final_size) |known| {
            if (final_size != known) return error.FinalSizeError;
        } else if (final_size < self.highest_offset) {
            // §4.5: a reset cannot claim the stream ended before data we already
            // have. Accepting it would make the two ends disagree about how much
            // connection credit was consumed, and that disagreement is permanent.
            return error.FinalSizeError;
        }

        if (final_size > self.max_data) return error.FlowControlError;

        if (self.state == .reset_recvd or self.state == .reset_read) return 0;

        const before = self.flowControlUsed();
        self.final_size = final_size;
        // §4.5's accounting, in one line: the credit the peer spent is what it
        // says it sent, not what arrived. Removing this releases credit for data
        // that will never be delivered, and the two endpoints then disagree about
        // the connection window permanently — there is no mechanism to
        // resynchronise.
        self.highest_offset = @max(self.highest_offset, final_size);
        self.reset_code = code;
        self.state = .reset_recvd;

        // §4.4: buffered data is discarded. The credit stays accounted for,
        // because the peer spent it.
        self.buffer.deinit(gpa);
        self.buffer = .{};

        return self.flowControlUsed() - before;
    }

    /// Data the application can read.
    pub fn readable(self: *const Recv) []const u8 {
        return self.buffer.readable();
    }

    /// Consume `n` bytes, advancing the state machine if that finishes the stream.
    pub fn consume(self: *Recv, n: usize) void {
        self.buffer.consume(n);
        if (self.state == .data_recvd and self.buffer.ready.items.len == 0) {
            self.state = .data_read;
        }
    }

    /// The limit to advertise in MAX_STREAM_DATA, or null if there is no point.
    ///
    /// §4.2: a receiver credits what it has room for. Returning null in a state
    /// where the final size is known is not an optimization — §3.3 says a
    /// MAX_STREAM_DATA frame there is pointless, and sending one anyway invites
    /// the peer to send data past a FIN.
    pub fn creditUpdate(self: *const Recv, window: u64) ?u64 {
        if (self.state != .recv) return null;
        const target = self.buffer.base + window;
        // Only when it actually grows: §4.1 requires ignoring a limit that does
        // not increase, so sending one is pure overhead.
        if (target <= self.max_data) return null;
        // And only when it has grown enough to be worth a frame. Half the window
        // is the usual heuristic; the cost of getting it wrong is either wasted
        // packets or a stalled sender.
        if (target - self.max_data < window / 2) return null;
        return target;
    }

    pub fn applyCredit(self: *Recv, limit: u64) void {
        if (limit > self.max_data) self.max_data = limit;
    }
};

/// The sending part of one stream: §3.1's state machine plus the sender's half of
/// §4.1's flow control.
pub const Send = struct {
    state: SendState = .ready,
    /// The largest offset the peer will accept.
    max_data: u64,
    /// How much the application has handed us.
    written: u64 = 0,
    /// How much has been put into packets.
    sent: u64 = 0,
    /// How much the peer has acknowledged.
    acked: u64 = 0,
    /// Set when the application ends the stream.
    fin_written: bool = false,
    fin_sent: bool = false,
    /// §3.5: a STOP_SENDING arrived, so a RESET_STREAM is owed.
    stop_sending_code: ?u64 = null,
    reset_code: ?u64 = null,

    pub fn init(peer_max_data: u64) Send {
        return .{ .max_data = peer_max_data };
    }

    /// How many more bytes flow control permits right now.
    pub fn available(self: *const Send) u64 {
        if (self.written >= self.max_data) return 0;
        return self.max_data - self.written;
    }

    /// Is this stream blocked by its own flow control limit? §4.1 asks for a
    /// STREAM_DATA_BLOCKED frame in that case, which is a signal rather than a
    /// requirement — but a sender that never sends it can stall for a whole round
    /// trip waiting for credit the receiver had no reason to extend.
    pub fn isBlocked(self: *const Send) bool {
        return self.state == .send and self.written == self.max_data and !self.fin_written;
    }

    /// Record that the application wrote `n` bytes. The caller must have checked
    /// `available` and the connection limit first.
    pub fn write(self: *Send, n: u64) Error!void {
        if (self.state.isTerminal() or self.state == .reset_sent) return error.StreamStateError;
        if (self.fin_written) return error.StreamStateError;
        if (self.written + n > self.max_data) return error.FlowControlError;
        self.written += n;
        if (self.state == .ready and n > 0) self.state = .send;
    }

    /// The application has no more data (§3.1's "Data Sent" transition happens
    /// when the FIN actually goes out, not here).
    pub fn finish(self: *Send) Error!void {
        if (self.state.isTerminal() or self.state == .reset_sent) return error.StreamStateError;
        self.fin_written = true;
        if (self.state == .ready) self.state = .send;
    }

    /// Record that bytes and possibly the FIN went into a packet.
    pub fn markSent(self: *Send, n: u64, fin: bool) void {
        assert(self.sent + n <= self.written);
        self.sent += n;
        if (fin) {
            assert(self.fin_written);
            assert(self.sent == self.written);
            self.fin_sent = true;
            self.state = .data_sent;
        } else if (self.state == .ready and n > 0) {
            self.state = .send;
        }
    }

    /// Record acknowledgement up to `offset`.
    pub fn markAcked(self: *Send, offset: u64, fin_acked: bool) void {
        if (offset > self.acked) self.acked = offset;
        if (self.state == .reset_sent) {
            if (fin_acked) self.state = .reset_recvd;
            return;
        }
        if (self.state == .data_sent and self.acked == self.written and fin_acked) {
            self.state = .data_recvd;
        }
    }

    /// The application, or a STOP_SENDING, abandons this direction.
    pub fn abandon(self: *Send, code: u64) Error!u64 {
        if (self.state.isTerminal()) return error.StreamStateError;
        if (self.state == .reset_sent) return self.written; // already reset
        self.reset_code = code;
        self.state = .reset_sent;
        // §4.5: the final size a RESET_STREAM reports is what the sender wrote,
        // so that both ends agree on the credit consumed even though the data
        // never arrives.
        return self.written;
    }

    /// Apply a STOP_SENDING frame (§19.5, §3.5).
    pub fn stopSending(self: *Send, code: u64) Error!void {
        if (self.state.isTerminal()) return;
        // §3.5: this *requests* a reset, and an endpoint in Ready or Send must
        // comply. Recording it rather than acting immediately keeps the decision
        // with the layer that owns packets.
        self.stop_sending_code = code;
    }

    /// §3.5: does the peer's STOP_SENDING oblige us to send a RESET_STREAM?
    pub fn owesReset(self: *const Send) bool {
        if (self.stop_sending_code == null) return false;
        return self.state == .ready or self.state == .send or self.state == .data_sent;
    }

    pub fn applyCredit(self: *Send, limit: u64) void {
        // §4.1: a limit that does not increase must be ignored. Loss and
        // reordering make a smaller value ordinary, not hostile.
        if (limit > self.max_data) self.max_data = limit;
    }
};

/// A whole stream. Which halves are live depends on the ID and our role, so both
/// are optional rather than both being present and one being inert — an inert
/// half is a half that can still be called.
pub const Stream = struct {
    id: Id,
    send: ?Send,
    recv: ?Recv,

    pub fn init(id: Id, role: transport.Role, limits: Limits) Stream {
        return .{
            .id = id,
            .send = if (id.canSend(role)) .init(limits.peer_max_stream_data) else null,
            .recv = if (id.canReceive(role)) .init(limits.local_max_stream_data) else null,
        };
    }

    pub fn deinit(self: *Stream, gpa: Allocator) void {
        if (self.recv) |*r| r.deinit(gpa);
    }

    /// Both directions are finished, so the stream can be forgotten.
    pub fn isFinished(self: *const Stream) bool {
        const send_done = if (self.send) |s| s.state.isTerminal() else true;
        const recv_done = if (self.recv) |r| r.state.isTerminal() else true;
        return send_done and recv_done;
    }
};

pub const Limits = struct {
    /// What we advertised for streams the peer sends on.
    local_max_stream_data: u64,
    /// What the peer advertised for streams we send on.
    peer_max_stream_data: u64,
};

const testing = std.testing;

test "stream: §2.1's two low bits decide everything about a stream" {
    // Worth a test rather than trusting the arithmetic, because every other rule
    // in §3 and §4.6 is expressed in terms of these two bits, and getting the
    // encoding backwards would make a server treat its own streams as the
    // client's.
    try testing.expectEqual(Kind.client_bidi, Id.init(0).kind());
    try testing.expectEqual(Kind.server_bidi, Id.init(1).kind());
    try testing.expectEqual(Kind.client_uni, Id.init(2).kind());
    try testing.expectEqual(Kind.server_uni, Id.init(3).kind());
    try testing.expectEqual(Kind.client_bidi, Id.init(4).kind());

    // §4.6's limits count streams of a kind, not stream IDs.
    try testing.expectEqual(@as(u64, 0), Id.init(0).index());
    try testing.expectEqual(@as(u64, 1), Id.init(4).index());
    try testing.expectEqual(@as(u64, 3), Id.init(15).index());
    try testing.expectEqual(@as(u64, 15), Id.make(.server_uni, 3).value);

    // A unidirectional stream can only be written by its initiator. This is what
    // makes a STREAM frame on the wrong end a STREAM_STATE_ERROR.
    const client_uni = Id.make(.client_uni, 0);
    try testing.expect(client_uni.canSend(.client));
    try testing.expect(!client_uni.canSend(.server));
    try testing.expect(client_uni.canReceive(.server));
    try testing.expect(!client_uni.canReceive(.client));

    // Bidirectional streams work in both directions for both roles.
    const bidi = Id.make(.client_bidi, 7);
    try testing.expect(bidi.canSend(.client) and bidi.canSend(.server));
    try testing.expect(bidi.canReceive(.client) and bidi.canReceive(.server));
    try testing.expect(bidi.isLocallyInitiated(.client));
    try testing.expect(!bidi.isLocallyInitiated(.server));
}

test "stream: out-of-order data is reassembled and read in order" {
    const gpa = testing.allocator;
    var r: Reassembler = .{};
    defer r.deinit(gpa);

    try r.insert(gpa, 6, "world", 4096);
    try testing.expectEqual(@as(usize, 0), r.readable().len);

    try r.insert(gpa, 0, "hello ", 4096);
    try testing.expectEqualStrings("hello world", r.readable());
    try testing.expectEqual(@as(usize, 0), r.pending_bytes);

    // Reading advances the base, which is what releases flow control credit.
    r.consume(6);
    try testing.expectEqualStrings("world", r.readable());
    try testing.expectEqual(@as(u64, 6), r.base);
    try testing.expectEqual(@as(u64, 11), r.contiguousEnd());

    // A retransmission of consumed data is ignored rather than delivered twice,
    // which would corrupt the stream the application sees.
    try r.insert(gpa, 0, "hello ", 4096);
    try testing.expectEqualStrings("world", r.readable());

    // And an overlapping retransmission delivers only what is new.
    try r.insert(gpa, 9, "ld!", 4096);
    try testing.expectEqualStrings("world!", r.readable());
}

test "stream: different data at the same offset is refused where it is visible" {
    // §2.2 makes this MAY rather than MUST, and the reason is in the code: data
    // the application has consumed is gone, so the check cannot be complete. It is
    // still worth doing, because silently accepting a contradiction corrupts the
    // byte stream the application sees, and nothing downstream would report it.
    const gpa = testing.allocator;
    var r: Reassembler = .{};
    defer r.deinit(gpa);

    try r.insert(gpa, 0, "abcdef", 4096);
    try testing.expectError(error.ProtocolViolation, r.insert(gpa, 2, "XX", 4096));
    // The identical bytes are fine.
    try r.insert(gpa, 2, "cd", 4096);

    // The same applies to two pending chunks at one offset.
    var other: Reassembler = .{};
    defer other.deinit(gpa);
    try other.insert(gpa, 10, "hello", 4096);
    try testing.expectError(error.ProtocolViolation, other.insert(gpa, 10, "HELLO", 4096));
    // A longer chunk that agrees on its prefix replaces the shorter one.
    try other.insert(gpa, 10, "hello there", 4096);
    try testing.expectEqual(@as(usize, 11), other.pending_bytes);
}

test "stream: reassembly is bounded even though flow control should prevent it" {
    // A limit that depends on the peer honouring its own promise is not a limit.
    const gpa = testing.allocator;
    var r: Reassembler = .{};
    defer r.deinit(gpa);

    const chunk: [256]u8 = @splat(0x5a);
    var offset: u64 = 1; // always past the contiguous end, so nothing is delivered
    var accepted: usize = 0;
    while (offset < 8192) : (offset += chunk.len) {
        r.insert(gpa, offset, &chunk, 1024) catch |err| {
            try testing.expectEqual(error.ReassemblyBufferExceeded, err);
            break;
        };
        accepted += 1;
    }
    try testing.expect(r.pending_bytes <= 1024);
    try testing.expect(accepted > 0); // a bound, not a refusal
}

test "stream: §4.1's limit applies to the offset, not the byte count" {
    // A receiver has to hold the gap, so a single byte at offset 1000 costs 1001
    // bytes of window. Accounting bytes instead would let a peer make a receiver
    // buffer far more than it advertised.
    const gpa = testing.allocator;
    var recv: Recv = .init(100);
    defer recv.deinit(gpa);

    try testing.expectError(
        error.FlowControlError,
        recv.receive(gpa, 99, "ab", false, 4096),
    );
    // Exactly at the limit is allowed; §4.1's limit is the maximum offset.
    _ = try recv.receive(gpa, 98, "ab", false, 4096);
    try testing.expectEqual(@as(u64, 100), recv.highest_offset);
}

test "stream: §4.5's final size cannot change, in any of the three ways" {
    const gpa = testing.allocator;

    // (1) Data at or beyond a known final size.
    {
        var recv: Recv = .init(1000);
        defer recv.deinit(gpa);
        _ = try recv.receive(gpa, 0, "hello", true, 4096);
        try testing.expectEqual(@as(?u64, 5), recv.final_size);
        try testing.expectError(
            error.FinalSizeError,
            recv.receive(gpa, 5, "more", false, 4096),
        );
    }

    // (2) A FIN that disagrees with an established final size.
    {
        var recv: Recv = .init(1000);
        defer recv.deinit(gpa);
        _ = try recv.receive(gpa, 0, "hello", true, 4096);
        try testing.expectError(
            error.FinalSizeError,
            recv.receive(gpa, 0, "hi", true, 4096),
        );
        // The identical FIN again is a retransmission and is fine.
        _ = try recv.receive(gpa, 0, "hello", true, 4096);
    }

    // (3) A final size below data already received.
    {
        var recv: Recv = .init(1000);
        defer recv.deinit(gpa);
        _ = try recv.receive(gpa, 10, "xyz", false, 4096);
        try testing.expectError(
            error.FinalSizeError,
            recv.receive(gpa, 0, "ab", true, 4096),
        );
        // And through RESET_STREAM, which carries a final size for the same
        // reason: both ends must agree on the credit consumed.
        try testing.expectError(error.FinalSizeError, recv.reset(gpa, 7, 5));
        // A reset at or above what we have is accepted.
        _ = try recv.reset(gpa, 7, 13);
        try testing.expectEqual(RecvState.reset_recvd, recv.state);
        // A second reset must agree with the first.
        try testing.expectError(error.FinalSizeError, recv.reset(gpa, 7, 20));
    }
}

test "stream: a reset stream still accounts for its connection credit" {
    // §4.5, and the half that is easy to miss. If a reset stream released the
    // credit for data that never arrived, the two endpoints would disagree about
    // how much of the connection window was spent — permanently, since there is
    // no mechanism to resynchronise. Conversely, holding credit for a stream that
    // will never deliver would deadlock a connection that broke no rule.
    const gpa = testing.allocator;
    var recv: Recv = .init(1000);
    defer recv.deinit(gpa);

    // Two bytes arrive, then the stream is reset claiming 500 bytes were sent.
    const first = try recv.receive(gpa, 0, "ab", false, 4096);
    try testing.expectEqual(@as(u64, 2), first);

    const on_reset = try recv.reset(gpa, 0x10, 500);
    // The credit jumps to the final size even though 498 bytes never arrived —
    // the peer spent them, so they are spent. Asserting `highest_offset` directly
    // is the point: that is the quantity §4.5 governs, and a `flowControlUsed`
    // that special-cased `final_size` would be a second way to compute it.
    try testing.expectEqual(@as(u64, 498), on_reset);
    try testing.expectEqual(@as(u64, 500), recv.highest_offset);
    try testing.expectEqual(@as(u64, 500), recv.flowControlUsed());

    // Buffered data is discarded (§4.4) but the accounting survives it.
    try testing.expectEqual(@as(usize, 0), recv.readable().len);

    // A reset beyond the advertised limit is still a flow control error: the
    // peer cannot claim to have spent credit it never had.
    var other: Recv = .init(100);
    defer other.deinit(gpa);
    try testing.expectError(error.FlowControlError, other.reset(gpa, 0, 101));
}

test "stream: the receive state machine follows §3.2" {
    const gpa = testing.allocator;
    var recv: Recv = .init(1000);
    defer recv.deinit(gpa);

    try testing.expectEqual(RecvState.recv, recv.state);
    _ = try recv.receive(gpa, 0, "abc", false, 4096);
    try testing.expectEqual(RecvState.recv, recv.state);

    // A FIN makes the size known. Data may still be missing.
    _ = try recv.receive(gpa, 10, "xyz", true, 4096);
    try testing.expectEqual(RecvState.size_known, recv.state);
    try testing.expectEqual(@as(?u64, 13), recv.final_size);

    // Filling the gap moves to Data Recvd, which persists until the application
    // has read everything — §3.2 tracks delivery to the application, which the
    // sender cannot observe.
    _ = try recv.receive(gpa, 3, "defghij", false, 4096);
    try testing.expectEqual(RecvState.data_recvd, recv.state);
    try testing.expectEqualStrings("abcdefghijxyz", recv.readable());

    recv.consume(13);
    try testing.expectEqual(RecvState.data_read, recv.state);
    try testing.expect(recv.state.isTerminal());

    // §3.3: a delayed frame arriving after a reset is discarded rather than being
    // an error, because the network can deliver it at any time.
    var after_reset: Recv = .init(1000);
    defer after_reset.deinit(gpa);
    _ = try after_reset.reset(gpa, 1, 10);
    try testing.expectEqual(@as(u64, 0), try after_reset.receive(gpa, 0, "late", false, 4096));

    // But §4.5 applies "even after a stream is closed": data beyond the final size
    // is still an error. Being discarded and being unchecked are different things,
    // and a receiver that conflated them would let a peer get a contradiction
    // accepted simply by sending it late.
    try testing.expectError(
        error.FinalSizeError,
        after_reset.receive(gpa, 8, "overrun", false, 4096),
    );
}

test "stream: MAX_STREAM_DATA is sent only when it would say something new" {
    // §4.1 requires ignoring a limit that does not increase, so sending one is
    // pure overhead. And §3.3 makes it pointless once the size is known —
    // sending one there invites the peer to write past a FIN.
    const gpa = testing.allocator;
    var recv: Recv = .init(1000);
    defer recv.deinit(gpa);

    const window: u64 = 1000;
    // Nothing consumed yet, so the limit would not move.
    try testing.expect(recv.creditUpdate(window) == null);

    _ = try recv.receive(gpa, 0, &@as([600]u8, @splat('x')), false, 4096);
    recv.consume(600);
    // Now the window can move by 600, which is over the half-window threshold.
    try testing.expectEqual(@as(?u64, 1600), recv.creditUpdate(window));

    // A small consumption is not worth a frame.
    var small: Recv = .init(1000);
    defer small.deinit(gpa);
    _ = try small.receive(gpa, 0, "abc", false, 4096);
    small.consume(3);
    try testing.expect(small.creditUpdate(window) == null);

    // Once the final size is known there is nothing to credit. The consumption
    // here is deliberately large enough to clear the half-window threshold, so
    // that the state check is what makes the difference — a three-byte stream
    // would return null for the wrong reason and the test would prove nothing.
    var done: Recv = .init(1000);
    defer done.deinit(gpa);
    _ = try done.receive(gpa, 0, &@as([600]u8, @splat('y')), true, 4096);
    done.consume(600);
    try testing.expectEqual(RecvState.data_read, done.state);
    try testing.expect(done.creditUpdate(window) == null);

    // A credit that does not increase is ignored (§4.1).
    recv.applyCredit(500);
    try testing.expectEqual(@as(u64, 1000), recv.max_data);
    recv.applyCredit(1600);
    try testing.expectEqual(@as(u64, 1600), recv.max_data);
}

test "stream: the send state machine follows §3.1" {
    var send: Send = .init(100);
    try testing.expectEqual(SendState.ready, send.state);

    try send.write(10);
    try testing.expectEqual(SendState.send, send.state);
    try testing.expectEqual(@as(u64, 90), send.available());

    send.markSent(10, false);
    try testing.expectEqual(SendState.send, send.state);

    try send.finish();
    send.markSent(0, true);
    try testing.expectEqual(SendState.data_sent, send.state);

    // Writing after a FIN is a state error, not silently dropped: the
    // application has already promised the stream ended.
    try testing.expectError(error.StreamStateError, send.write(1));

    // Only the acknowledgement of everything, FIN included, is terminal.
    send.markAcked(5, false);
    try testing.expectEqual(SendState.data_sent, send.state);
    send.markAcked(10, true);
    try testing.expectEqual(SendState.data_recvd, send.state);
    try testing.expect(send.state.isTerminal());
}

test "stream: flow control blocks the sender rather than letting it overrun" {
    var send: Send = .init(10);
    try send.write(10);
    try testing.expectEqual(@as(u64, 0), send.available());
    try testing.expect(send.isBlocked());
    try testing.expectError(error.FlowControlError, send.write(1));

    // Credit unblocks it. A decrease is ignored, because loss and reordering make
    // a smaller value ordinary rather than hostile.
    send.applyCredit(5);
    try testing.expectEqual(@as(u64, 10), send.max_data);
    send.applyCredit(20);
    try testing.expect(!send.isBlocked());
    try send.write(10);

    // A stream that has written its FIN is not "blocked": there is nothing left
    // to send, so announcing a block would be a lie that costs a frame.
    var finished: Send = .init(4);
    try finished.write(4);
    try finished.finish();
    try testing.expect(!finished.isBlocked());
}

test "stream: STOP_SENDING obliges a RESET_STREAM, and the reset reports what was written" {
    // §3.5: STOP_SENDING is a request, and an endpoint in Ready or Send must
    // comply. §4.5: the RESET_STREAM reports the final size the sender reached, so
    // both ends agree on the credit consumed even though the data never arrives.
    var send: Send = .init(1000);
    try send.write(40);
    send.markSent(40, false);

    try testing.expect(!send.owesReset());
    try send.stopSending(0x99);
    try testing.expect(send.owesReset());

    const final_size = try send.abandon(0x99);
    try testing.expectEqual(@as(u64, 40), final_size);
    try testing.expectEqual(SendState.reset_sent, send.state);
    // The obligation is discharged.
    try testing.expect(!send.owesReset());

    // Writing after a reset is a state error (§3.3: no STREAM frames after
    // RESET_STREAM).
    try testing.expectError(error.StreamStateError, send.write(1));
    try testing.expectError(error.StreamStateError, send.finish());

    send.markAcked(40, true);
    try testing.expectEqual(SendState.reset_recvd, send.state);
    try testing.expect(send.state.isTerminal());

    // A STOP_SENDING for an already-terminal stream is dropped: §3.5 says there
    // is little value in it, and the network can deliver it late.
    try send.stopSending(1);
    try testing.expect(!send.owesReset());
}

test "stream: a unidirectional stream has exactly one live half" {
    const gpa = testing.allocator;
    const limits: Limits = .{ .local_max_stream_data = 100, .peer_max_stream_data = 200 };

    // A client's own unidirectional stream: send only.
    var ours: Stream = .init(Id.make(.client_uni, 0), .client, limits);
    defer ours.deinit(gpa);
    try testing.expect(ours.send != null);
    try testing.expect(ours.recv == null);
    try testing.expectEqual(@as(u64, 200), ours.send.?.max_data);

    // The server's unidirectional stream, seen by the client: receive only.
    // Both halves present with one inert would be a half that can still be
    // called, which is the shape that produces "worked but did nothing".
    var theirs: Stream = .init(Id.make(.server_uni, 0), .client, limits);
    defer theirs.deinit(gpa);
    try testing.expect(theirs.send == null);
    try testing.expect(theirs.recv != null);
    try testing.expectEqual(@as(u64, 100), theirs.recv.?.max_data);

    // A bidirectional stream has both, and each takes its limit from the right
    // side: ours from what the peer granted, theirs from what we advertised.
    var both: Stream = .init(Id.make(.client_bidi, 0), .client, limits);
    defer both.deinit(gpa);
    try testing.expectEqual(@as(u64, 200), both.send.?.max_data);
    try testing.expectEqual(@as(u64, 100), both.recv.?.max_data);
    try testing.expect(!both.isFinished());
}
