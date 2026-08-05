//! Connection ID management, RFC 9000 §5.1, §19.15 and §19.16.
//!
//! Each endpoint issues connection IDs and the peer puts one of them in the
//! Destination Connection ID field of every packet it sends. So there are two
//! sets with different rules, and they are separate types here rather than one
//! type with a role flag — the checks that matter differ, and a flag would let
//! the wrong check run.
//!
//! * `Remote` holds what the peer issued to us. We choose one to send to.
//! * `Local` holds what we issued to the peer. We use it to recognise inbound
//!   packets and to know which of our IDs the peer has stopped using.
//!
//! **The distinction worth getting right is duplicate sequence numbers.** A
//! NEW_CONNECTION_ID repeating a sequence number with the *same* connection ID
//! is an ordinary retransmission — QUIC frames are retransmitted on loss, so
//! refusing it would kill healthy connections on any lossy path. Repeating one
//! with a *different* value is §5.1.1's PROTOCOL_VIOLATION, because it means the
//! peer is trying to make the two endpoints disagree about what a sequence
//! number denotes. Both cases are tested, in both directions.

const std = @import("std");
const assert = std.debug.assert;

const packet = @import("packet.zig");
const transport = @import("transport.zig");

const ConnectionId = packet.ConnectionId;

pub const stateless_reset_token_len = transport.stateless_reset_token_len;

/// §10.3.2: the token for a connection ID, derived from one static key.
///
/// The alternative the RFC names first — a random secret per connection — is the
/// one that cannot work, and it says so: stateless reset exists *for* the case
/// where state was lost, so a token that has to be remembered is a token that is
/// gone exactly when it is needed. Deriving it from `HMAC(key, cid)` means an
/// endpoint that has forgotten everything can still produce the token for a
/// connection ID that arrives in a packet.
///
/// Two consequences follow and are load-bearing rather than incidental. The key
/// is an operational input, because a key generated per process cannot outlive a
/// restart and a fleet's members must each recognise the others' tokens. And the
/// token is per connection ID, which is what §10.3.2 requires ("the same
/// stateless reset token MUST NOT be used for multiple connection IDs") and what
/// makes revealing one end exactly one connection.
///
/// The label keeps this key's outputs distinct from any other use of the same
/// bytes, which matters because the seed here also seeds connection ID selection.
pub fn statelessResetToken(
    key: *const [32]u8,
    id: ConnectionId,
) [stateless_reset_token_len]u8 {
    var mac: std.crypto.auth.hmac.sha2.HmacSha256 = .init(key);
    mac.update("zinet stateless reset");
    mac.update(id.slice());
    var digest: [32]u8 = undefined;
    mac.final(&digest);
    return digest[0..stateless_reset_token_len].*;
}

pub const Error = error{
    /// §5.1.1: the peer issued more connection IDs than we said we would store.
    /// A real limit rather than advice: without it the peer decides how much
    /// memory we spend on IDs.
    ConnectionIdLimitError,
    /// §5.1.1: the same sequence number with a different connection ID, or a
    /// `retire_prior_to` above the sequence number in the same frame.
    ProtocolViolation,
    /// §19.16: a RETIRE_CONNECTION_ID for a sequence number we never issued.
    /// Distinct because it says the peer is acknowledging something that does
    /// not exist, which no amount of reordering can produce.
    ConnectionIdNotIssued,
    /// No unretired connection ID is left to send to. Reached only if the peer
    /// retires everything it gave us, which §5.1.1 forbids.
    ConnectionIdExhausted,
};

/// How many of the peer's connection IDs we are willing to hold at once. This is
/// the compile-time ceiling; `active_connection_id_limit` is what we advertise
/// and may be lower. Both exist because the advertised value is a promise to the
/// peer while this is a bound on our own storage — and a promise cannot be
/// allowed to allocate.
pub const max_stored = 8;

comptime {
    assert(max_stored >= transport.min_active_connection_id_limit);
}

const Entry = struct {
    sequence: u64,
    id: ConnectionId,
    token: ?[stateless_reset_token_len]u8,
};

/// The connection IDs the peer issued to us.
pub const Remote = struct {
    entries: [max_stored]Entry = undefined,
    len: usize = 0,
    /// Index into `entries` of the one we are sending to.
    active_index: usize = 0,
    /// The highest `retire_prior_to` the peer has sent, so a reordered
    /// NEW_CONNECTION_ID below it can be retired immediately (§5.1.2).
    retire_prior_to: u64 = 0,
    /// Sequence numbers we owe the peer a RETIRE_CONNECTION_ID for. Bounded by
    /// the same ceiling as storage, because a retirement is only ever owed for
    /// something that was stored.
    pending_retire: [max_stored]u64 = undefined,
    pending_retire_len: usize = 0,
    /// What we advertised in `active_connection_id_limit`. The peer exceeding it
    /// is a connection error, so it has to be remembered rather than assumed.
    limit: u64,

    /// Start from the peer's connection ID observed during the handshake, which
    /// §5.1.1 defines as sequence number zero.
    pub fn init(initial: ConnectionId, limit: u64) Remote {
        assert(limit >= transport.min_active_connection_id_limit);
        var self: Remote = .{ .limit = @min(limit, max_stored) };
        self.entries[0] = .{ .sequence = 0, .id = initial, .token = null };
        self.len = 1;
        return self;
    }

    /// The connection ID to put in outgoing packets.
    pub fn active(self: *const Remote) ConnectionId {
        assert(self.len > 0);
        return self.entries[self.active_index].id;
    }

    pub fn activeSequence(self: *const Remote) u64 {
        assert(self.len > 0);
        return self.entries[self.active_index].sequence;
    }

    /// The stateless reset token for the ID in use, if the peer gave one.
    /// §10.3: only the token belonging to the connection ID currently in use can
    /// validate a reset, which is why this is not "any token we hold".
    pub fn activeToken(self: *const Remote) ?[stateless_reset_token_len]u8 {
        assert(self.len > 0);
        return self.entries[self.active_index].token;
    }

    /// Does `token` match any token the peer gave us for a currently held ID?
    ///
    /// §10.3.1 deliberately checks all of them, not only the active one: a
    /// stateless reset is sent by a server that has *lost* its state, so it may
    /// answer with the token for whichever ID the packet it could not process
    /// happened to use.
    pub fn matchesResetToken(self: *const Remote, token: *const [stateless_reset_token_len]u8) bool {
        for (self.entries[0..self.len]) |entry| {
            const known = entry.token orelse continue;
            // Constant time: a reset token is a secret, and an attacker able to
            // learn it by timing could reset the connection at will.
            if (std.crypto.timing_safe.eql([stateless_reset_token_len]u8, known, token.*)) return true;
        }
        return false;
    }

    /// Apply a NEW_CONNECTION_ID frame (§19.15).
    pub fn insert(
        self: *Remote,
        sequence: u64,
        retire_prior_to: u64,
        id: ConnectionId,
        token: [stateless_reset_token_len]u8,
    ) Error!void {
        // §19.15: this is checked by the frame parser too, but the check lives
        // here as well because this is the only path that acts on the values.
        if (retire_prior_to > sequence) return error.ProtocolViolation;

        // First: does the peer already claim to have issued this sequence?
        for (self.entries[0..self.len]) |entry| {
            if (entry.sequence != sequence) continue;
            // A retransmission of the same ID. QUIC retransmits frames on loss,
            // so this is normal and must not be an error.
            if (entry.id.eql(&id)) return;
            // §5.1.1: the same sequence number with a different value. The peer
            // is trying to make the two ends disagree about what a sequence
            // number means.
            return error.ProtocolViolation;
        }

        // §5.1.2: retire_prior_to may rise, and everything below it goes.
        if (retire_prior_to > self.retire_prior_to) {
            self.retire_prior_to = retire_prior_to;
            try self.retireBelow(retire_prior_to);
        }

        if (sequence < self.retire_prior_to) {
            // A NEW_CONNECTION_ID that arrives below the current watermark is
            // already retired. It still has to be acknowledged as retired,
            // because the peer holds the ID until told otherwise.
            try self.pushRetire(sequence);
        } else {
            // §5.1.1: the peer may not push us past what we advertised. Counted
            // after retirement, since retiring is what makes room.
            if (self.len >= self.limit) return error.ConnectionIdLimitError;
            assert(self.len < max_stored);
            self.entries[self.len] = .{ .sequence = sequence, .id = id, .token = token };
            self.len += 1;
        }

        // **Providing and retiring in one frame are simultaneous, not
        // sequential.** §5.1.1 lets a peer at its limit rotate by retiring one ID
        // and providing another in the same NEW_CONNECTION_ID, so the set can
        // only be judged once both halves have been applied. Judging earlier
        // rejects a legal rotation — and only when the peer happens to be at its
        // limit, which is the kind of defect that survives a long time.
        //
        // Non-emptiness is an assertion rather than a check because §19.15's
        // `retire_prior_to <= sequence_number` already guarantees it: the ID a
        // frame provides is always at or above the watermark that frame sets, so
        // it always survives its own sweep. Those two rules are one rule, and
        // the bound rejected at the top of this function is the enforcement.
        assert(self.len > 0);
        if (self.active_index >= self.len) self.active_index = 0;
    }

    /// Switch to a different connection ID, for §9.5's migration rule: a new path
    /// must use a new connection ID, or an observer can link the two paths and
    /// migration stops hiding anything.
    ///
    /// Returns the sequence number now in use, or null if nothing unused is
    /// available — the caller must then not migrate rather than reuse.
    /// Switch to another connection ID the peer issued (§5.1.2).
    ///
    /// Has no caller in the library, and that is a statement about scope rather than
    /// an oversight: rotating the ID we send to is what a *migrating* client does
    /// (§9.5 forbids reusing one across local addresses), and client-initiated
    /// migration is not implemented. See HTTP3.md.
    pub fn rotate(self: *Remote) ?u64 {
        const current = self.entries[self.active_index].sequence;
        for (self.entries[0..self.len], 0..) |entry, i| {
            if (entry.sequence == current) continue;
            self.active_index = i;
            return entry.sequence;
        }
        return null;
    }

    /// Retire the ID in use and move to another, then owe the peer a
    /// RETIRE_CONNECTION_ID for it.
    /// Retire the ID currently in use and move to the next (§19.16).
    ///
    /// Also without a caller, for the same reason as `rotate`.
    pub fn retireActive(self: *Remote) Error!u64 {
        const sequence = self.entries[self.active_index].sequence;
        if (self.len == 1) return error.ConnectionIdExhausted;
        try self.pushRetire(sequence);
        self.remove(self.active_index);
        self.active_index = 0;
        return sequence;
    }

    /// Sequence numbers a RETIRE_CONNECTION_ID is owed for.
    pub fn pendingRetire(self: *const Remote) []const u64 {
        return self.pending_retire[0..self.pending_retire_len];
    }

    /// A packet carrying this RETIRE_CONNECTION_ID was lost: put the sequence
    /// back so the frame is sent again. §13.3 — the peer is waiting to reuse
    /// the slot, and an unacknowledged retirement holds it forever. A duplicate
    /// retirement at the peer is harmless (it retires nothing the second time),
    /// so requeueing is safe even if the original was in fact delivered.
    pub fn requeueRetire(self: *Remote, sequence: u64) void {
        for (self.pending_retire[0..self.pending_retire_len]) |existing| {
            if (existing == sequence) return;
        }
        if (self.pending_retire_len == self.pending_retire.len) return;
        self.pending_retire[self.pending_retire_len] = sequence;
        self.pending_retire_len += 1;
    }

    /// Called once a RETIRE_CONNECTION_ID has been acknowledged as sent.
    pub fn clearPendingRetire(self: *Remote, sent: usize) void {
        assert(sent <= self.pending_retire_len);
        const rest = self.pending_retire_len - sent;
        std.mem.copyForwards(u64, self.pending_retire[0..rest], self.pending_retire[sent..self.pending_retire_len]);
        self.pending_retire_len = rest;
    }

    /// How many IDs we hold. Exposed for the limit assertions in tests and for
    /// deciding whether migration is possible.
    pub fn count(self: *const Remote) usize {
        return self.len;
    }

    fn retireBelow(self: *Remote, watermark: u64) Error!void {
        var i: usize = 0;
        while (i < self.len) {
            if (self.entries[i].sequence >= watermark) {
                i += 1;
                continue;
            }
            try self.pushRetire(self.entries[i].sequence);
            const was_active = i == self.active_index;
            self.remove(i);
            if (was_active) self.active_index = 0;
            // Do not advance: `remove` moved a different entry into this slot.
        }
        // Deliberately no "did that empty the set" check here: the frame being
        // applied may itself provide a replacement. `insert` asks once both
        // halves are done.
    }

    fn remove(self: *Remote, index: usize) void {
        assert(index < self.len);
        self.len -= 1;
        if (index != self.len) {
            self.entries[index] = self.entries[self.len];
            if (self.active_index == self.len) self.active_index = index;
        }
    }

    fn pushRetire(self: *Remote, sequence: u64) Error!void {
        for (self.pending_retire[0..self.pending_retire_len]) |queued| {
            if (queued == sequence) return; // already owed
        }
        if (self.pending_retire_len == max_stored) return error.ConnectionIdLimitError;
        self.pending_retire[self.pending_retire_len] = sequence;
        self.pending_retire_len += 1;
    }
};

/// The connection IDs we issued to the peer.
pub const Local = struct {
    entries: [max_stored]Entry = undefined,
    len: usize = 0,
    /// The next sequence number to hand out. Monotonic: §5.1.1 requires it, and
    /// reusing one would make a RETIRE_CONNECTION_ID ambiguous.
    next_sequence: u64 = 1,
    /// The highest sequence number ever issued, so a RETIRE_CONNECTION_ID above
    /// it can be recognised as impossible.
    highest_issued: u64 = 0,
    /// What the peer advertised: how many of our IDs it will hold. We may not
    /// exceed it, for the same reason it may not exceed ours.
    peer_limit: u64 = transport.min_active_connection_id_limit,

    /// Start from the connection ID we used during the handshake, sequence zero.
    ///
    /// A zero-length ID is legal (§5.1) and means this endpoint has chosen not
    /// to be addressed by connection ID at all — it routes by address instead.
    /// Such an endpoint must never issue more, which `canIssue` enforces.
    pub fn init(first: ConnectionId) Local {
        var self: Local = .{};
        self.entries[0] = .{ .sequence = 0, .id = first, .token = null };
        self.len = 1;
        return self;
    }

    /// Once the peer's transport parameters are known, its limit applies.
    pub fn setPeerLimit(self: *Local, limit: u64) void {
        assert(limit >= transport.min_active_connection_id_limit);
        self.peer_limit = limit;
    }

    /// §19.15: an endpoint using a zero-length connection ID must not issue any,
    /// and must treat receiving one as a PROTOCOL_VIOLATION. Both follow from
    /// the same fact — it has said it does not use connection IDs — so the rule
    /// lives in one place.
    pub fn usesConnectionIds(self: *const Local) bool {
        assert(self.len > 0);
        return self.entries[0].id.len != 0;
    }

    /// Is there room to issue another? False when the peer's limit is reached, or
    /// when this endpoint uses zero-length IDs.
    pub fn canIssue(self: *const Local) bool {
        if (!self.usesConnectionIds()) return false;
        return self.len < @min(self.peer_limit, max_stored);
    }

    /// Issue a new connection ID, returning its sequence number for the
    /// NEW_CONNECTION_ID frame.
    pub fn issue(
        self: *Local,
        id: ConnectionId,
        token: [stateless_reset_token_len]u8,
    ) Error!u64 {
        if (!self.usesConnectionIds()) return error.ProtocolViolation;
        if (!self.canIssue()) return error.ConnectionIdLimitError;
        assert(id.len != 0);

        const sequence = self.next_sequence;
        self.next_sequence += 1;
        self.highest_issued = sequence;
        self.entries[self.len] = .{ .sequence = sequence, .id = id, .token = token };
        self.len += 1;
        return sequence;
    }

    /// The ID and stateless reset token issued under `sequence`, or null if it was
    /// never issued or has since been retired.
    ///
    /// This exists so the frame that announces an issued ID can be built from the
    /// one record of it rather than from a copy kept alongside: a NEW_CONNECTION_ID
    /// that has to be retransmitted must carry the same ID and token as the packet
    /// that was lost, and two copies of that are two chances to disagree.
    pub fn issued(self: *const Local, sequence: u64) ?struct {
        id: ConnectionId,
        token: [stateless_reset_token_len]u8,
    } {
        for (self.entries[0..self.len]) |entry| {
            if (entry.sequence != sequence) continue;
            // Sequence zero is the handshake ID, which has no token of its own —
            // it was never announced in a frame, so there is nothing to rebuild.
            const token = entry.token orelse return null;
            return .{ .id = entry.id, .token = token };
        }
        return null;
    }

    /// Apply a RETIRE_CONNECTION_ID frame (§19.16).
    pub fn retire(self: *Local, sequence: u64) Error!void {
        // §19.16: retiring something never issued. Not reordering — a sequence
        // number above the highest we ever handed out cannot exist, so the peer
        // is either confused or probing.
        if (sequence > self.highest_issued) return error.ConnectionIdNotIssued;

        for (self.entries[0..self.len], 0..) |entry, i| {
            if (entry.sequence != sequence) continue;
            self.len -= 1;
            if (i != self.len) self.entries[i] = self.entries[self.len];
            return;
        }
        // Already retired. A retransmitted RETIRE_CONNECTION_ID, which is normal.
    }

    /// Does an inbound packet's Destination Connection ID belong to us?
    ///
    /// A zero-length local ID matches only a zero-length destination, which is
    /// what makes address-routed endpoints work.
    pub fn accepts(self: *const Local, destination: *const ConnectionId) bool {
        for (self.entries[0..self.len]) |entry| {
            if (entry.id.eql(destination)) return true;
        }
        return false;
    }

    /// The ID we used during the handshake, which §7.3's
    /// `initial_source_connection_id` must report.
    pub fn initialId(self: *const Local) ConnectionId {
        assert(self.len > 0);
        // Sequence zero may have been retired, so it is not simply entries[0].
        for (self.entries[0..self.len]) |entry| {
            if (entry.sequence == 0) return entry.id;
        }
        return self.entries[0].id;
    }

    pub fn count(self: *const Local) usize {
        return self.len;
    }
};

const testing = std.testing;

fn cid(bytes: []const u8) ConnectionId {
    return ConnectionId.init(bytes) catch unreachable;
}

fn resetToken(byte: u8) [stateless_reset_token_len]u8 {
    return @splat(byte);
}

test "cid: a repeated sequence number is a retransmission or an attack, depending" {
    // The distinction this file exists to get right. QUIC retransmits frames on
    // loss, so the same NEW_CONNECTION_ID arriving twice is ordinary — refusing
    // it would kill healthy connections on any lossy path. The same sequence
    // number with a *different* value is §5.1.1's PROTOCOL_VIOLATION, because it
    // makes the two ends disagree about what a sequence number denotes.
    var remote: Remote = .init(cid(&.{ 1, 1, 1, 1 }), 4);

    try remote.insert(1, 0, cid(&.{ 2, 2, 2, 2 }), resetToken(0xa1));
    try testing.expectEqual(@as(usize, 2), remote.count());

    // Identical retransmission: accepted, and does not grow the set.
    try remote.insert(1, 0, cid(&.{ 2, 2, 2, 2 }), resetToken(0xa1));
    try testing.expectEqual(@as(usize, 2), remote.count());

    // Same sequence, different value.
    try testing.expectError(
        error.ProtocolViolation,
        remote.insert(1, 0, cid(&.{ 3, 3, 3, 3 }), resetToken(0xa1)),
    );
}

test "cid: the peer cannot push us past the limit we advertised" {
    // §5.1.1. Without this the peer decides how much memory we spend on
    // connection IDs, which is exactly the class of thing the whole codebase
    // refuses to leave to a peer.
    var remote: Remote = .init(cid(&.{1}), 3);
    try remote.insert(1, 0, cid(&.{2}), resetToken(1));
    try remote.insert(2, 0, cid(&.{3}), resetToken(2));
    try testing.expectEqual(@as(usize, 3), remote.count());

    try testing.expectError(
        error.ConnectionIdLimitError,
        remote.insert(3, 0, cid(&.{4}), resetToken(3)),
    );

    // Retiring makes room, which is why the count is checked after retirement
    // rather than before: a frame that retires one and provides one is legal and
    // is how a peer rotates at the limit.
    try remote.insert(3, 1, cid(&.{4}), resetToken(3));
    try testing.expectEqual(@as(usize, 3), remote.count());
    // Sequence 0 was retired and is owed a RETIRE_CONNECTION_ID.
    try testing.expectEqualSlices(u64, &.{0}, remote.pendingRetire());
}

test "cid: retire_prior_to sweeps everything below it, including the active one" {
    var remote: Remote = .init(cid(&.{ 0, 0 }), 5);
    try remote.insert(1, 0, cid(&.{ 1, 1 }), resetToken(1));
    try remote.insert(2, 0, cid(&.{ 2, 2 }), resetToken(2));
    try testing.expectEqual(@as(u64, 0), remote.activeSequence());

    // The peer retires 0 and 1 while providing 3.
    try remote.insert(3, 2, cid(&.{ 3, 3 }), resetToken(3));

    // Two retirements owed, and we are no longer sending to a retired ID — that
    // last part is the one that matters: continuing to use a retired connection
    // ID means the peer has no route for our packets and the connection dies
    // silently.
    try testing.expectEqual(@as(usize, 2), remote.pendingRetire().len);
    const still_held = remote.activeSequence();
    try testing.expect(still_held >= 2);
    try testing.expectEqual(@as(usize, 2), remote.count());
}

test "cid: a NEW_CONNECTION_ID below the watermark is retired, not stored" {
    // §5.1.2 with reordering: retire_prior_to=5 arrives first, then a
    // NEW_CONNECTION_ID for sequence 3. Storing it would resurrect something the
    // peer has already stopped honouring. It still has to be *acknowledged* as
    // retired, because the peer holds the ID until told.
    var remote: Remote = .init(cid(&.{9}), 4);
    try remote.insert(5, 5, cid(&.{5}), resetToken(5));
    const before = remote.count();

    try remote.insert(3, 0, cid(&.{3}), resetToken(3));
    try testing.expectEqual(before, remote.count());

    var found = false;
    for (remote.pendingRetire()) |sequence| {
        if (sequence == 3) found = true;
    }
    try testing.expect(found);
}

test "cid: retire_prior_to above its own sequence number is refused" {
    // §19.15. It would mean "retire everything below N" in a frame that provides
    // something below N, which cannot be satisfied.
    var remote: Remote = .init(cid(&.{1}), 4);
    try testing.expectError(
        error.ProtocolViolation,
        remote.insert(2, 3, cid(&.{2}), resetToken(2)),
    );
}

test "cid: §19.15's retire_prior_to bound is what keeps the set non-empty" {
    // These are one rule rather than two. `retire_prior_to <= sequence_number`
    // means the ID a frame provides is always at or above the watermark that
    // same frame sets, so it always survives its own sweep — a NEW_CONNECTION_ID
    // cannot empty the set. That is why `insert` asserts non-emptiness instead of
    // checking for it: rejecting the bound *is* the enforcement, and a second
    // check would be a second source of truth for the same invariant.
    var remote: Remote = .init(cid(&.{1}), 4);
    try remote.insert(1, 0, cid(&.{2}), resetToken(1));

    // A sweep that retires everything held still leaves what it provided, and
    // that is what we are now sending to.
    try remote.insert(9, 9, cid(&.{9}), resetToken(9));
    try testing.expectEqual(@as(usize, 1), remote.count());
    try testing.expectEqual(@as(u64, 9), remote.activeSequence());
    try testing.expect(remote.active().eql(&cid(&.{9})));
    // Both older IDs are owed a retirement.
    try testing.expectEqual(@as(usize, 2), remote.pendingRetire().len);

    // And the bound being relied on is refused when violated.
    try testing.expectError(
        error.ProtocolViolation,
        remote.insert(12, 13, cid(&.{12}), resetToken(12)),
    );
}

test "cid: migration needs a different connection id, and says so when it cannot" {
    // §9.5: probing a new path with the same connection ID lets an observer link
    // the two paths, which defeats the point of migration.
    var remote: Remote = .init(cid(&.{1}), 4);
    try testing.expect(remote.rotate() == null); // only one held: do not migrate

    try remote.insert(1, 0, cid(&.{2}), resetToken(1));
    const rotated = remote.rotate().?;
    try testing.expectEqual(@as(u64, 1), rotated);
    try testing.expectEqual(@as(u64, 1), remote.activeSequence());
}

test "cid: a stateless reset token is matched across every held id, in constant time" {
    // §10.3.1. A stateless reset comes from a server that has lost its state, so
    // it answers with the token for whichever connection ID the packet it could
    // not process used — not necessarily the one we consider active. Checking
    // only the active token would make resets go unrecognised, and the
    // connection would then wait out its idle timeout instead of failing fast.
    var remote: Remote = .init(cid(&.{1}), 4);
    try remote.insert(1, 0, cid(&.{2}), resetToken(0x11));
    try remote.insert(2, 0, cid(&.{3}), resetToken(0x22));

    try testing.expect(remote.matchesResetToken(&resetToken(0x11)));
    try testing.expect(remote.matchesResetToken(&resetToken(0x22)));
    try testing.expect(!remote.matchesResetToken(&resetToken(0x33)));

    // Sequence 0 came from the handshake and has no token: §5.1.1 only carries
    // one in NEW_CONNECTION_ID, and the server's is in its transport parameters.
    var only_initial: Remote = .init(cid(&.{1}), 4);
    try testing.expect(only_initial.activeToken() == null);
    try testing.expect(!only_initial.matchesResetToken(&resetToken(0)));
}

test "cid: retiring one we never issued is refused" {
    // §19.16. No amount of reordering produces a sequence number above the
    // highest ever handed out, so this is the peer being wrong — and accepting
    // it would let a peer make us forget IDs by guessing numbers.
    var local: Local = .init(cid(&.{ 7, 7 }));
    local.setPeerLimit(4);
    const first = try local.issue(cid(&.{ 8, 8 }), resetToken(1));
    try testing.expectEqual(@as(u64, 1), first);

    try testing.expectError(error.ConnectionIdNotIssued, local.retire(2));

    try local.retire(1);
    try testing.expectEqual(@as(usize, 1), local.count());
    // A retransmitted retirement for something already gone is fine, because
    // frames are retransmitted on loss.
    try local.retire(1);
    try testing.expectEqual(@as(usize, 1), local.count());
}

test "cid: an endpoint using zero-length ids must not issue any" {
    // §19.15: a zero-length connection ID says this endpoint is addressed by
    // address rather than by ID. Issuing one would contradict that, and both
    // halves of the rule follow from the same fact, so they share an
    // implementation.
    var local: Local = .init(.empty);
    try testing.expect(!local.usesConnectionIds());
    try testing.expect(!local.canIssue());
    try testing.expectError(error.ProtocolViolation, local.issue(cid(&.{1}), resetToken(1)));

    // And it accepts only zero-length destinations.
    try testing.expect(local.accepts(&ConnectionId.empty));
    try testing.expect(!local.accepts(&cid(&.{1})));
}

test "cid: we may not exceed the peer's advertised limit either" {
    // The mirror of the earlier test. Symmetry is the point: the limit is a
    // promise in both directions, and an implementation that enforces only the
    // inbound half is the one that gets its connections closed by a correct peer.
    var local: Local = .init(cid(&.{1}));
    local.setPeerLimit(2);
    _ = try local.issue(cid(&.{2}), resetToken(2));
    try testing.expect(!local.canIssue());
    try testing.expectError(error.ConnectionIdLimitError, local.issue(cid(&.{3}), resetToken(3)));

    // Once the peer retires one, there is room again.
    try local.retire(1);
    try testing.expect(local.canIssue());
}

test "cid: an inbound packet is ours only if its destination is one we issued" {
    var local: Local = .init(cid(&.{ 0xde, 0xad }));
    local.setPeerLimit(4);
    _ = try local.issue(cid(&.{ 0xbe, 0xef }), resetToken(1));

    try testing.expect(local.accepts(&cid(&.{ 0xde, 0xad })));
    try testing.expect(local.accepts(&cid(&.{ 0xbe, 0xef })));
    try testing.expect(!local.accepts(&cid(&.{ 0xbe, 0xee })));
    // A prefix is not a match: connection IDs are compared whole, and a length
    // check that passed on a prefix would let one connection's packets be
    // delivered to another.
    try testing.expect(!local.accepts(&cid(&.{0xde})));

    // The handshake ID survives retirement of later ones, because §7.3's
    // initial_source_connection_id refers to it forever.
    _ = try local.issue(cid(&.{ 1, 2 }), resetToken(2));
    try local.retire(2);
    try testing.expect(local.initialId().eql(&cid(&.{ 0xde, 0xad })));
}

test "cid: sequence numbers are never reused" {
    // §5.1.1. Reuse would make a RETIRE_CONNECTION_ID ambiguous: the peer would
    // be retiring a number that had denoted two different IDs.
    var local: Local = .init(cid(&.{1}));
    local.setPeerLimit(max_stored);

    var issued: [4]u64 = undefined;
    for (&issued, 0..) |*slot, i| {
        slot.* = try local.issue(cid(&.{ 2, @intCast(i) }), resetToken(@intCast(i)));
    }
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4 }, &issued);

    // Retire them all and issue again: the numbering continues rather than
    // restarting.
    for (issued) |sequence| try local.retire(sequence);
    const next = try local.issue(cid(&.{ 3, 3 }), resetToken(9));
    try testing.expectEqual(@as(u64, 5), next);
}

test "cid: a pending retirement is queued once and cleared when sent" {
    var remote: Remote = .init(cid(&.{0}), 5);
    try remote.insert(1, 0, cid(&.{1}), resetToken(1));
    try remote.insert(2, 0, cid(&.{2}), resetToken(2));
    try remote.insert(3, 2, cid(&.{3}), resetToken(3));

    try testing.expectEqual(@as(usize, 2), remote.pendingRetire().len);
    // A repeated sweep does not queue the same sequence twice: the frame that
    // carries it may itself be retransmitted, and a queue that grew per
    // retransmission would be unbounded growth driven by the peer.
    try remote.insert(4, 2, cid(&.{4}), resetToken(4));
    try testing.expectEqual(@as(usize, 2), remote.pendingRetire().len);

    remote.clearPendingRetire(1);
    try testing.expectEqual(@as(usize, 1), remote.pendingRetire().len);
    remote.clearPendingRetire(1);
    try testing.expectEqual(@as(usize, 0), remote.pendingRetire().len);
}

test "cid: a reset token is per connection id and stable across forgetting everything" {
    // The two properties §10.3.2 needs at once: an endpoint that has lost all
    // state recomputes the same token from the connection ID in the packet, and
    // no two connection IDs share a token.
    const key: [32]u8 = @splat(7);
    const a = cid(&.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const b = cid(&.{ 1, 2, 3, 4, 5, 6, 7, 9 });

    try testing.expectEqual(statelessResetToken(&key, a), statelessResetToken(&key, a));
    try testing.expect(!std.mem.eql(
        u8,
        &statelessResetToken(&key, a),
        &statelessResetToken(&key, b),
    ));

    // A different static key gives a different token for the same ID, which is
    // what makes the key rather than the ID the secret.
    const other: [32]u8 = @splat(8);
    try testing.expect(!std.mem.eql(
        u8,
        &statelessResetToken(&key, a),
        &statelessResetToken(&other, a),
    ));
}
