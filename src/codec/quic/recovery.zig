//! Loss detection and congestion control, RFC 9002.
//!
//! Pure arithmetic over injected time: nothing here reads a clock, allocates, or
//! knows what a packet contains. That makes every rule in §5, §6 and §7 testable
//! against a schedule the test writes, which matters more here than anywhere else
//! in the stack — a congestion controller that is subtly wrong does not fail, it
//! just performs badly on paths nobody is testing.
//!
//! Three things in this file exist to resist a peer rather than the network, and
//! each is marked where it appears:
//!
//! * **§5.3's floor on subtracting `ack_delay`.** A peer that reports an enormous
//!   delay would otherwise drive the RTT estimate to nothing, and a tiny RTT means
//!   spurious retransmissions and a sender that congests the path on the peer's
//!   behalf.
//! * **§5.2's rule that `min_rtt` uses the *unadjusted* sample.** It is the one
//!   quantity the peer cannot influence, which is exactly why the floor above can
//!   be trusted.
//! * **§13.2.3's bound on remembered ACK ranges.** A peer sending every other
//!   packet number produces one range per packet, and remembering them all is
//!   memory the peer chooses.

const std = @import("std");
const assert = std.debug.assert;

const frame = @import("frame.zig");

/// §6.1.1: how far below the largest acknowledged packet a gap must be before the
/// packet is declared lost. Three, from the RFC's kPacketThreshold.
pub const packet_threshold = 3;

/// §6.1.2: the time threshold is `9/8 * max(smoothed_rtt, latest_rtt)`, expressed
/// as a numerator and denominator so the arithmetic stays integral. Floating point
/// here would make the same input produce different results on different targets.
pub const time_threshold_numerator = 9;
pub const time_threshold_denominator = 8;

/// §6.1.2's kGranularity: the smallest timer this implementation will set, and the
/// floor under every computed delay. One millisecond.
pub const granularity_ns: u64 = 1_000_000;

/// §5.3's initial RTT before any sample exists. 333 ms, from the RFC's kInitialRtt.
pub const initial_rtt_ns: u64 = 333 * std.time.ns_per_ms;

/// §13.2.3: how many ACK ranges to remember. A peer that acknowledges every other
/// packet produces one range per packet, so this is a bound on memory the peer
/// would otherwise choose. Dropping the oldest costs the peer a spurious
/// retransmission, which is the right trade: correctness is preserved because §19.3
/// requires the largest received packet number to be retained, and that is the one
/// this never drops.
pub const max_ack_ranges = 32;

/// §12.3's three spaces. Loss detection keeps separate state for each, because a
/// packet in one space can only be acknowledged in that space.
pub const Space = enum {
    initial,
    handshake,
    application,

    pub const count = 3;
};

/// The set of packet numbers received in one space, as descending ranges (§19.3.1).
pub const AckRanges = struct {
    /// Descending by `largest`, non-overlapping, non-adjacent.
    ranges: [max_ack_ranges]frame.Ack.Range = undefined,
    len: usize = 0,

    pub fn largest(self: *const AckRanges) ?u64 {
        if (self.len == 0) return null;
        return self.ranges[0].largest;
    }

    pub fn isEmpty(self: *const AckRanges) bool {
        return self.len == 0;
    }

    pub fn slice(self: *const AckRanges) []const frame.Ack.Range {
        return self.ranges[0..self.len];
    }

    /// Does this set already contain `pn`? §12.3 requires discarding a packet whose
    /// number has already been processed, and that check has to happen after packet
    /// protection is removed — which is why it lives here rather than at the parser.
    pub fn contains(self: *const AckRanges, pn: u64) bool {
        for (self.ranges[0..self.len]) |range| {
            if (pn <= range.largest and pn >= range.smallest) return true;
            if (pn > range.largest) return false; // descending, so no later range can hold it
        }
        return false;
    }

    /// Record that `pn` was received, merging with neighbours. A range evicted
    /// by the bound is dropped silently, which §13.2.3 permits for received
    /// packet numbers: the cost is a retransmission the peer need not have made.
    pub fn add(self: *AckRanges, pn: u64) void {
        _ = self.addRange(pn, pn);
    }

    /// Record the inclusive range `[smallest, largest]`, merging with anything it
    /// touches or overlaps. Overlap is not an error: stream retransmission resends
    /// suffixes, so their acknowledgements legitimately cover ground twice.
    ///
    /// Returns the range that did **not** survive the bound, if any — either the
    /// evicted lowest range or, when the new range would itself be the lowest,
    /// the new range. The caller decides what that means: for received packet
    /// numbers it is safely ignored (§13.2.3), but for tracking acknowledged
    /// stream offsets it must be treated as *not acknowledged* and the data
    /// resent, because a forgotten acknowledgement never comes back.
    pub fn addRange(self: *AckRanges, smallest: u64, largest_in: u64) ?frame.Ack.Range {
        assert(smallest <= largest_in);
        var s = smallest;
        var l = largest_in;

        // Skip the ranges entirely above: those whose smallest is beyond l + 1.
        var lo: usize = 0;
        while (lo < self.len and self.ranges[lo].smallest > l +| 1) lo += 1;

        // Absorb every range that touches or overlaps [s, l].
        var hi = lo;
        while (hi < self.len and self.ranges[hi].largest +| 1 >= s) : (hi += 1) {
            s = @min(s, self.ranges[hi].smallest);
            l = @max(l, self.ranges[hi].largest);
        }

        if (hi > lo) {
            // Merge [lo, hi) into one.
            self.ranges[lo] = .{ .largest = l, .smallest = s };
            const removed = hi - lo - 1;
            if (removed > 0) {
                var i = lo + 1;
                while (i + removed < self.len) : (i += 1) self.ranges[i] = self.ranges[i + removed];
                self.len -= removed;
            }
            return null;
        }

        // Nothing touched: a fresh range at `lo`.
        var evicted: ?frame.Ack.Range = null;
        if (self.len == max_ack_ranges) {
            // The bound. Drop the lowest range — unless that is where this one
            // goes, in which case the new range is the one that does not fit.
            if (lo == self.len) return .{ .largest = l, .smallest = s };
            evicted = self.ranges[self.len - 1];
            self.len -= 1;
        }
        var i = self.len;
        while (i > lo) : (i -= 1) self.ranges[i] = self.ranges[i - 1];
        self.ranges[lo] = .{ .largest = l, .smallest = s };
        self.len += 1;
        return evicted;
    }
};

/// §5's round-trip time estimator.
pub const Rtt = struct {
    /// The most recent sample, unadjusted.
    latest: u64 = 0,
    /// §5.2: the minimum over the connection, **from unadjusted samples**. This is
    /// the one figure the peer cannot inflate, which is what makes it usable as a
    /// floor when deciding whether a reported `ack_delay` is plausible.
    min: u64 = 0,
    /// §5.3's smoothed_rtt. Null until the first sample.
    smoothed: ?u64 = null,
    /// §5.3's rttvar.
    variance: u64 = 0,
    /// The peer's advertised max_ack_delay (§18.2), in nanoseconds.
    max_ack_delay: u64 = 25 * std.time.ns_per_ms,

    /// The estimate to use before any sample exists.
    pub fn current(self: *const Rtt) u64 {
        return self.smoothed orelse initial_rtt_ns;
    }

    /// Take a sample. `ack_delay` is what the peer reported, already scaled by its
    /// `ack_delay_exponent`.
    ///
    /// `handshake_confirmed` gates the subtraction: §5.3 caps `ack_delay` at
    /// `max_ack_delay` only after the handshake is confirmed, because before that
    /// the peer has not yet had its `max_ack_delay` believed — and §13.2.1 requires
    /// it to acknowledge handshake packets immediately anyway.
    pub fn sample(self: *Rtt, latest_rtt: u64, ack_delay: u64, handshake_confirmed: bool) void {
        self.latest = latest_rtt;

        if (self.smoothed == null) {
            // §5.3: the first sample initialises rather than blends.
            self.min = latest_rtt;
            self.smoothed = latest_rtt;
            self.variance = latest_rtt / 2;
            return;
        }

        // §5.2: min_rtt tracks the *unadjusted* sample. Adjusting it first would let
        // a peer lower it by over-reporting delay, and every later plausibility
        // check is measured against it.
        self.min = @min(self.min, latest_rtt);

        var adjusted = latest_rtt;
        const capped = if (handshake_confirmed) @min(ack_delay, self.max_ack_delay) else ack_delay;
        // **§5.3's floor.** Subtract the peer's reported delay only when the result
        // stays at or above min_rtt. A peer reporting an enormous delay would
        // otherwise drive the estimate towards zero, and a tiny RTT means a short
        // PTO, spurious retransmissions, and a sender congesting the path on the
        // peer's behalf.
        if (latest_rtt >= self.min + capped) adjusted = latest_rtt - capped;

        const smoothed = self.smoothed.?;
        const difference = if (smoothed > adjusted) smoothed - adjusted else adjusted - smoothed;
        // §5.3: rttvar = 3/4 * rttvar + 1/4 * difference
        self.variance = (self.variance * 3 + difference) / 4;
        // §5.3: smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted
        self.smoothed = (smoothed * 7 + adjusted) / 8;
    }

    /// §6.1.2's loss delay: how long after a packet was sent it may be declared lost
    /// on time alone.
    pub fn lossDelay(self: *const Rtt) u64 {
        const base = @max(self.current(), self.latest);
        const scaled = base * time_threshold_numerator / time_threshold_denominator;
        // The floor matters: without it a connection with a sub-millisecond RTT
        // declares packets lost faster than the timer that would detect it can fire.
        return @max(scaled, granularity_ns);
    }

    /// §6.2.1's probe timeout, before exponential backoff.
    ///
    /// `space` decides whether `max_ack_delay` is included: §6.2.1 excludes it for
    /// Initial and Handshake, because §13.2.1 requires those to be acknowledged
    /// immediately, so a peer's advertised delay does not apply. Including it there
    /// makes handshake loss take a third of a second longer to notice than it should.
    pub fn probeTimeout(self: *const Rtt, space: Space) u64 {
        const base = self.current() + @max(self.variance * 4, granularity_ns);
        return switch (space) {
            .initial, .handshake => base,
            .application => base + self.max_ack_delay,
        };
    }
};

/// A packet this endpoint sent and has not yet resolved.
pub const Sent = struct {
    number: u64,
    /// When it went out, in the caller's monotonic nanoseconds.
    time_sent: u64,
    /// Bytes on the wire, for congestion accounting.
    size: u64,
    /// §2: whether it obliges the peer to acknowledge. Only these arm the PTO,
    /// because a packet the peer need not acknowledge cannot be detected as lost.
    ack_eliciting: bool,
    /// §2: whether it counts against the congestion window. Packets containing only
    /// ACK frames do not.
    in_flight: bool,
};

/// What resolving an ACK produced.
pub const Resolution = struct {
    /// Packets the ACK newly acknowledged.
    acked: []const Sent,
    /// Packets now considered lost.
    lost: []const Sent,
    /// The RTT sample this ACK yielded, if it acknowledged the largest packet.
    rtt_sample: ?u64,
};

/// §7's congestion controller: NewReno, as RFC 9002 Appendix B describes it.
pub const Congestion = struct {
    /// The largest datagram this endpoint sends, which scales every window below.
    max_datagram_size: u64,
    /// Bytes permitted in flight.
    window: u64,
    /// §7.3: below this, the controller is in slow start.
    slow_start_threshold: u64 = std.math.maxInt(u64),
    /// Bytes currently in flight.
    in_flight: u64 = 0,
    /// §7.3.2: when the current recovery period began. A congestion event during a
    /// recovery period does not reduce the window again — otherwise a single loss
    /// burst halves the window once per lost packet, and the connection collapses
    /// to the minimum on the first bad moment.
    recovery_start: ?u64 = null,
    /// Growth accumulator for congestion avoidance, so integer division does not
    /// discard the increment on every acknowledgement.
    growth: u64 = 0,

    /// §7.2: the initial window is ten datagrams, bounded below by 14720 bytes and
    /// above by nothing in particular — the RFC's formula, transcribed.
    pub fn init(max_datagram_size: u64) Congestion {
        return .{
            .max_datagram_size = max_datagram_size,
            .window = @min(10 * max_datagram_size, @max(14_720, 2 * max_datagram_size)),
        };
    }

    /// §7.2's minimum congestion window: two datagrams. A window below this cannot
    /// keep a single packet in flight while waiting for an acknowledgement.
    pub fn minimumWindow(self: *const Congestion) u64 {
        return 2 * self.max_datagram_size;
    }

    pub fn isSlowStart(self: *const Congestion) bool {
        return self.window < self.slow_start_threshold;
    }

    /// How many more bytes may be sent right now.
    pub fn available(self: *const Congestion) u64 {
        if (self.in_flight >= self.window) return 0;
        return self.window - self.in_flight;
    }

    pub fn onSent(self: *Congestion, packet: Sent) void {
        if (!packet.in_flight) return;
        self.in_flight += packet.size;
    }

    /// §7.3.1 and §7.3.3: acknowledged bytes grow the window, slowly or quickly
    /// depending on which phase we are in.
    pub fn onAck(self: *Congestion, packet: Sent, now: u64) void {
        if (!packet.in_flight) return;
        self.in_flight -= @min(self.in_flight, packet.size);

        // §7.3.2: a packet sent before the recovery period began says nothing about
        // the path now, so it does not grow the window.
        if (self.recovery_start) |start| {
            if (packet.time_sent <= start) return;
            self.recovery_start = null;
        }
        _ = now;

        if (self.isSlowStart()) {
            // §7.3.1: one for one.
            self.window += packet.size;
            return;
        }
        // §7.3.3: one datagram per window of data. Accumulated rather than divided
        // each time, because integer division would round the increment to zero for
        // any window above the datagram size and the window would never grow.
        self.growth += packet.size * self.max_datagram_size;
        if (self.growth >= self.window) {
            self.window += self.growth / self.window * 1;
            const consumed = self.growth / self.window * self.window;
            self.growth -= @min(self.growth, consumed);
        }
    }

    pub fn onLost(self: *Congestion, packet: Sent) void {
        if (!packet.in_flight) return;
        self.in_flight -= @min(self.in_flight, packet.size);
    }

    /// §7.3.2: halve the window, once per recovery period.
    ///
    /// `sent_time` is when the *lost* packet was sent, which is what decides whether
    /// this is a new congestion event or part of one already being recovered from.
    pub fn onCongestion(self: *Congestion, sent_time: u64, now: u64) void {
        if (self.recovery_start) |start| {
            if (sent_time <= start) return; // already recovering from this event
        }
        self.recovery_start = now;
        self.window = @max(self.window / 2, self.minimumWindow());
        self.slow_start_threshold = self.window;
        self.growth = 0;
    }

    /// §7.6.1: after an idle period the window is not trustworthy. Not implemented
    /// as pacing — that is a performance concern — but the window is left alone
    /// rather than grown, which is the conservative half of the rule.
    pub fn onPersistentCongestion(self: *Congestion) void {
        // §7.6.2: collapse to the minimum. Distinguished from an ordinary congestion
        // event because persistent congestion means *everything* in a window was
        // lost, which is evidence the path changed rather than that it is merely
        // busy.
        self.window = self.minimumWindow();
        self.slow_start_threshold = self.window;
        self.recovery_start = null;
        self.growth = 0;
    }
};

/// §6's loss detection for one packet number space.
pub const Spaces = struct {
    /// Packets sent and not yet acknowledged or declared lost, ascending by number.
    sent: [Space.count]std.ArrayList(Sent) = .{ .empty, .empty, .empty },
    /// The largest packet number acknowledged in each space.
    largest_acked: [Space.count]?u64 = .{ null, null, null },
    /// §6.1.2: the time the earliest currently-unacknowledged ack-eliciting packet
    /// was sent, per space, which is what the loss timer is set against.
    loss_time: [Space.count]?u64 = .{ null, null, null },
    /// §6.2: consecutive PTO expirations, for exponential backoff.
    pto_count: u32 = 0,
    /// The buffers `resolve` reports through, so a caller gets slices rather than an
    /// allocation per ACK.
    acked_scratch: std.ArrayList(Sent) = .empty,
    lost_scratch: std.ArrayList(Sent) = .empty,

    pub fn deinit(self: *Spaces, gpa: std.mem.Allocator) void {
        for (&self.sent) |*list| list.deinit(gpa);
        self.acked_scratch.deinit(gpa);
        self.lost_scratch.deinit(gpa);
    }

    fn index(space: Space) usize {
        return @backingInt(space);
    }

    pub fn onSent(
        self: *Spaces,
        gpa: std.mem.Allocator,
        space: Space,
        packet: Sent,
    ) !void {
        const list = &self.sent[index(space)];
        // Ascending by construction: packet numbers only increase (§12.3).
        assert(list.items.len == 0 or list.items[list.items.len - 1].number < packet.number);
        try list.append(gpa, packet);
    }

    /// Bytes in flight across every space, which is what the congestion window
    /// bounds.
    pub fn bytesInFlight(self: *const Spaces) u64 {
        var total: u64 = 0;
        for (&self.sent) |*list| {
            for (list.items) |packet| {
                if (packet.in_flight) total += packet.size;
            }
        }
        return total;
    }

    /// Is anything ack-eliciting outstanding? §6.2.1 arms the PTO only then, because
    /// nothing else can be detected as lost.
    pub fn hasAckElicitingOutstanding(self: *const Spaces) bool {
        for (&self.sent) |*list| {
            for (list.items) |packet| {
                if (packet.ack_eliciting) return true;
            }
        }
        return false;
    }

    /// Apply an ACK frame, returning what it resolved.
    ///
    /// The RTT sample is produced only when the ACK covers the largest packet number
    /// we sent (§5.1). Measuring against any acknowledged packet would let a peer
    /// choose which sample we take by delaying one acknowledgement, and choosing the
    /// sample means choosing the PTO.
    pub fn resolve(
        self: *Spaces,
        gpa: std.mem.Allocator,
        space: Space,
        ack: frame.Ack,
        now: u64,
        rtt: *const Rtt,
    ) !Resolution {
        const i = index(space);
        const list = &self.sent[i];
        self.acked_scratch.clearRetainingCapacity();
        self.lost_scratch.clearRetainingCapacity();

        const previous_largest = self.largest_acked[i];
        if (previous_largest == null or ack.largest > previous_largest.?) {
            self.largest_acked[i] = ack.largest;
        }

        // Collect the acknowledged packets, keeping the rest.
        var kept: std.ArrayList(Sent) = .empty;
        defer kept.deinit(gpa);
        var largest_newly_acked: ?Sent = null;

        for (list.items) |packet| {
            if (!ack.covers(packet.number)) {
                try kept.append(gpa, packet);
                continue;
            }
            try self.acked_scratch.append(gpa, packet);
            if (largest_newly_acked == null or packet.number > largest_newly_acked.?.number) {
                largest_newly_acked = packet;
            }
        }

        var rtt_sample: ?u64 = null;
        if (largest_newly_acked) |newest| {
            // §5.1: only the largest acknowledged packet yields a sample, and only if
            // it is ack-eliciting — an ACK-only packet's timing says nothing about
            // when the peer chose to respond.
            if (newest.number == ack.largest and newest.ack_eliciting) {
                rtt_sample = now - newest.time_sent;
            }
        }

        // §6.1: detect loss among what remains.
        list.clearRetainingCapacity();
        const loss_delay = rtt.lossDelay();
        const largest = self.largest_acked[i].?;
        var earliest_outstanding: ?u64 = null;

        for (kept.items) |packet| {
            const gap_exceeded = packet.number + packet_threshold <= largest;
            const time_exceeded = now >= packet.time_sent + loss_delay and packet.number < largest;
            if (gap_exceeded or time_exceeded) {
                try self.lost_scratch.append(gpa, packet);
                continue;
            }
            try list.append(gpa, packet);
            if (packet.ack_eliciting) {
                if (earliest_outstanding == null or packet.time_sent < earliest_outstanding.?) {
                    earliest_outstanding = packet.time_sent;
                }
            }
        }

        self.loss_time[i] = earliest_outstanding;
        if (self.acked_scratch.items.len > 0) self.pto_count = 0;

        return .{
            .acked = self.acked_scratch.items,
            .lost = self.lost_scratch.items,
            .rtt_sample = rtt_sample,
        };
    }

    /// §6.1.2: packets that have now aged past the loss delay, without any new ACK.
    /// Called when the loss timer fires.
    pub fn detectLostOnTimer(
        self: *Spaces,
        gpa: std.mem.Allocator,
        space: Space,
        now: u64,
        rtt: *const Rtt,
    ) ![]const Sent {
        const i = index(space);
        const list = &self.sent[i];
        self.lost_scratch.clearRetainingCapacity();
        const largest = self.largest_acked[i] orelse return self.lost_scratch.items;
        const loss_delay = rtt.lossDelay();

        var kept: std.ArrayList(Sent) = .empty;
        defer kept.deinit(gpa);
        var earliest_outstanding: ?u64 = null;

        for (list.items) |packet| {
            if (packet.number < largest and now >= packet.time_sent + loss_delay) {
                try self.lost_scratch.append(gpa, packet);
                continue;
            }
            try kept.append(gpa, packet);
            if (packet.ack_eliciting) {
                if (earliest_outstanding == null or packet.time_sent < earliest_outstanding.?) {
                    earliest_outstanding = packet.time_sent;
                }
            }
        }

        list.clearRetainingCapacity();
        try list.appendSlice(gpa, kept.items);
        self.loss_time[i] = earliest_outstanding;
        return self.lost_scratch.items;
    }

    /// The next time a timer should fire, or null if none is armed.
    ///
    /// §6.2.1: the loss timer takes precedence over the PTO, because a packet that
    /// can be declared lost on time alone should be retransmitted rather than probed
    /// for.
    pub fn nextTimeout(self: *const Spaces, rtt: *const Rtt, handshake_confirmed: bool) ?u64 {
        var earliest_loss: ?u64 = null;
        for (self.loss_time, 0..) |maybe, i| {
            const at = maybe orelse continue;
            const deadline = at + rtt.lossDelay();
            if (earliest_loss == null or deadline < earliest_loss.?) earliest_loss = deadline;
            _ = i;
        }
        if (earliest_loss) |at| return at;

        // §6.2.1: no PTO while nothing ack-eliciting is outstanding. Arming one
        // anyway makes an idle connection send probes forever.
        if (!self.hasAckElicitingOutstanding()) return null;

        var earliest: ?u64 = null;
        for (&self.sent, 0..) |*list, i| {
            const space: Space = @fromBackingInt(@intCast(i));
            // §6.2.1: the application space's PTO is not armed until the handshake is
            // confirmed, because 1-RTT packets cannot be acknowledged before then.
            if (space == .application and !handshake_confirmed) continue;
            var oldest: ?u64 = null;
            for (list.items) |packet| {
                if (!packet.ack_eliciting) continue;
                if (oldest == null or packet.time_sent < oldest.?) oldest = packet.time_sent;
            }
            const at = oldest orelse continue;
            const backoff = std.math.shl(u64, 1, @min(self.pto_count, 16));
            const deadline = at + rtt.probeTimeout(space) * backoff;
            if (earliest == null or deadline < earliest.?) earliest = deadline;
        }
        return earliest;
    }

    /// §6.2: the PTO fired, so the next one waits twice as long.
    pub fn onProbeTimeout(self: *Spaces) void {
        self.pto_count += 1;
    }

    /// §7.6: was every ack-eliciting packet sent across a period of at least
    /// `duration` declared lost?
    ///
    /// This is what distinguishes "the path is busy" from "the path is gone". Wrong
    /// in the permissive direction, it collapses the window on an ordinary loss
    /// burst; wrong in the strict direction, it leaves a sender hammering a path that
    /// has disappeared.
    ///
    /// §7.6.1 has two halves and the second is easy to miss: the period must be long
    /// enough **and every packet sent within it must have been lost**. `acked` is
    /// what supplies the second half — a packet acknowledged from inside the window
    /// proves the path was working, so whatever else was lost was congestion rather
    /// than disappearance. Omitting that check turns any long-lived connection with
    /// two widely separated losses into a window collapse.
    pub fn isPersistentCongestion(
        lost: []const Sent,
        acked: []const Sent,
        duration: u64,
    ) bool {
        var earliest: ?u64 = null;
        var latest: ?u64 = null;
        for (lost) |packet| {
            if (!packet.ack_eliciting) continue;
            if (earliest == null or packet.time_sent < earliest.?) earliest = packet.time_sent;
            if (latest == null or packet.time_sent > latest.?) latest = packet.time_sent;
        }
        const from = earliest orelse return false;
        const to = latest.?;
        // No separate "at least two packets" check: a single packet spans no time, and
        // `duration` is always positive, so the comparison below already rejects it.
        // A second guard for the same fact would be a second thing to keep correct.
        if (to - from < duration) return false;

        // §7.6.1's other half.
        for (acked) |packet| {
            if (!packet.ack_eliciting) continue;
            if (packet.time_sent >= from and packet.time_sent <= to) return false;
        }
        return true;
    }

    /// §7.6.1's persistent congestion duration.
    pub fn persistentCongestionDuration(rtt: *const Rtt) u64 {
        const pto = rtt.current() + @max(rtt.variance * 4, granularity_ns) + rtt.max_ack_delay;
        // kPersistentCongestionThreshold is 3.
        return pto * 3;
    }

    /// Discard a space's state, as §4.9 of RFC 9001 requires when its keys go.
    pub fn discard(self: *Spaces, gpa: std.mem.Allocator, space: Space) void {
        const i = index(space);
        self.sent[i].clearAndFree(gpa);
        self.largest_acked[i] = null;
        self.loss_time[i] = null;
    }
};

const testing = std.testing;

/// An ACK frame covering one contiguous range, for tests.
fn singleAck(largest: u64, smallest: u64) frame.Ack {
    return .{
        .largest = largest,
        .delay = 0,
        .first_range = largest - smallest,
        .range_count = 0,
        .ranges = &.{},
        .ecn = null,
    };
}

const ms = std.time.ns_per_ms;

test "recovery: ACK ranges merge, and closing a gap joins two into one" {
    var set: AckRanges = .{};

    set.add(5);
    set.add(6);
    try testing.expectEqual(@as(usize, 1), set.len);
    try testing.expectEqual(@as(u64, 6), set.ranges[0].largest);
    try testing.expectEqual(@as(u64, 5), set.ranges[0].smallest);

    // A gap creates a second range, descending.
    set.add(9);
    try testing.expectEqual(@as(usize, 2), set.len);
    try testing.expectEqual(@as(u64, 9), set.ranges[0].largest);
    try testing.expectEqual(@as(u64, 6), set.ranges[1].largest);

    // Filling the hole merges them, which is the case a naive implementation gets
    // wrong: it extends one side and leaves an adjacent range behind, so the ACK
    // frame claims a gap that does not exist and the peer retransmits for nothing.
    set.add(8);
    set.add(7);
    try testing.expectEqual(@as(usize, 1), set.len);
    try testing.expectEqual(@as(u64, 9), set.ranges[0].largest);
    try testing.expectEqual(@as(u64, 5), set.ranges[0].smallest);

    // Duplicates change nothing, and §12.3's duplicate check reads the same state.
    try testing.expect(set.contains(7));
    try testing.expect(!set.contains(4));
    set.add(7);
    try testing.expectEqual(@as(usize, 1), set.len);
    try testing.expectEqual(@as(?u64, 9), set.largest());
}

test "recovery: the remembered range set is bounded, keeping the largest" {
    // §13.2.3. A peer acknowledging every other packet number produces one range per
    // packet, so without a bound this is memory the peer chooses. Dropping the
    // *lowest* range is what keeps §19.3's requirement intact: the largest received
    // packet number must always be reported, because the peer uses it to reconstruct
    // packet numbers (§17.1).
    var set: AckRanges = .{};

    var pn: u64 = 0;
    while (pn < max_ack_ranges * 4) : (pn += 2) set.add(pn);

    try testing.expectEqual(@as(usize, max_ack_ranges), set.len);
    try testing.expectEqual(@as(?u64, max_ack_ranges * 4 - 2), set.largest());
    // The ranges stay descending and disjoint, which is what §19.3.1's encoding
    // requires.
    for (set.ranges[1..set.len], 0..) |range, i| {
        try testing.expect(range.largest < set.ranges[i].smallest);
    }
}

test "recovery: §5.3's first sample initialises rather than blends" {
    var rtt: Rtt = .{};
    try testing.expectEqual(initial_rtt_ns, rtt.current());

    rtt.sample(100 * ms, 0, true);
    try testing.expectEqual(@as(u64, 100 * ms), rtt.smoothed.?);
    try testing.expectEqual(@as(u64, 50 * ms), rtt.variance);
    try testing.expectEqual(@as(u64, 100 * ms), rtt.min);

    // The second blends: 7/8 of 100 plus 1/8 of 200 is 112.5.
    rtt.sample(200 * ms, 0, true);
    try testing.expectEqual(@as(u64, 112_500_000), rtt.smoothed.?);
    // And min_rtt does not rise.
    try testing.expectEqual(@as(u64, 100 * ms), rtt.min);
}

test "recovery: §5.3's floor stops a peer from destroying the RTT estimate" {
    // The security property. A peer that reports an enormous ack_delay would
    // otherwise drive the estimate towards zero — and a tiny RTT means a short PTO,
    // spurious retransmissions, and a sender that congests the path on the peer's
    // behalf. §5.3 only subtracts when the result stays at or above min_rtt.
    var rtt: Rtt = .{ .max_ack_delay = 25 * ms };
    rtt.sample(100 * ms, 0, true);

    // A plausible delay is subtracted.
    rtt.sample(120 * ms, 10 * ms, true);
    const after_plausible = rtt.smoothed.?;
    // 7/8 * 100 + 1/8 * 110 = 101.25
    try testing.expectEqual(@as(u64, 101_250_000), after_plausible);

    // An implausible one is not: 100 ms of delay claimed on a 105 ms sample would
    // leave 5 ms, below the 100 ms minimum this path has ever shown.
    rtt.sample(105 * ms, 100 * ms, true);
    try testing.expect(rtt.smoothed.? > 100 * ms);

    // And after the handshake is confirmed the claim is capped at what the peer
    // advertised, so even a plausible-looking lie is bounded by its own promise.
    var capped: Rtt = .{ .max_ack_delay = 5 * ms };
    capped.sample(100 * ms, 0, true);
    capped.sample(200 * ms, 90 * ms, true);
    // Only 5 ms may be subtracted, so the adjusted sample is 195 rather than 110.
    try testing.expectEqual(@as(u64, (100 * 7 + 195) * ms / 8), capped.smoothed.?);

    // Before confirmation the cap does not apply (§5.3), because the peer's
    // max_ack_delay has not been authenticated yet — but the min_rtt floor still
    // does, which is why the cap's absence is not a hole.
    var early: Rtt = .{ .max_ack_delay = 5 * ms };
    early.sample(100 * ms, 0, false);
    early.sample(105 * ms, 100 * ms, false);
    try testing.expect(early.smoothed.? > 100 * ms);
}

test "recovery: §5.2's min_rtt uses the unadjusted sample" {
    // It is the one figure the peer cannot inflate, which is exactly what makes the
    // floor above trustworthy. Adjusting it first would let a peer lower it by
    // over-reporting delay, and then every later plausibility check would be
    // measured against a value the peer chose.
    var rtt: Rtt = .{ .max_ack_delay = 100 * ms };
    rtt.sample(200 * ms, 0, true);
    try testing.expectEqual(@as(u64, 200 * ms), rtt.min);

    // A sample of 150 ms with 100 ms of claimed delay: min_rtt takes 150, not 50.
    rtt.sample(150 * ms, 100 * ms, true);
    try testing.expectEqual(@as(u64, 150 * ms), rtt.min);
}

test "recovery: §6.2.1 excludes max_ack_delay from the handshake spaces" {
    // §13.2.1 requires Initial and Handshake packets to be acknowledged immediately,
    // so the peer's advertised delay does not apply there. Including it makes
    // handshake loss take a third of a second longer to notice than it should — on
    // every connection, and invisibly.
    var rtt: Rtt = .{ .max_ack_delay = 25 * ms };
    rtt.sample(100 * ms, 0, true);

    const handshake_pto = rtt.probeTimeout(.handshake);
    const application_pto = rtt.probeTimeout(.application);
    try testing.expectEqual(handshake_pto + 25 * ms, application_pto);
    try testing.expectEqual(rtt.probeTimeout(.initial), handshake_pto);

    // §6.2.1's floor: with no variance the term is kGranularity rather than zero, so
    // a PTO is never shorter than the timer that implements it.
    var flat: Rtt = .{ .max_ack_delay = 0 };
    flat.sample(10 * ms, 0, true);
    flat.variance = 0;
    try testing.expectEqual(10 * ms + granularity_ns, flat.probeTimeout(.handshake));
}

test "recovery: §6.1.2's loss delay has a floor" {
    var rtt: Rtt = .{};
    rtt.sample(80 * ms, 0, true);
    // 9/8 of max(smoothed, latest) = 9/8 * 80 = 90.
    try testing.expectEqual(@as(u64, 90 * ms), rtt.lossDelay());

    // On a very fast path the scaled value would be below the timer granularity, and
    // declaring packets lost faster than a timer can fire means declaring them lost
    // at the wrong moment.
    var fast: Rtt = .{};
    fast.sample(100_000, 0, true); // 100 µs
    try testing.expectEqual(granularity_ns, fast.lossDelay());
}

test "recovery: §6.1.1 declares a packet lost once three higher ones are acknowledged" {
    const gpa = testing.allocator;
    var spaces: Spaces = .{};
    defer spaces.deinit(gpa);
    var rtt: Rtt = .{};
    rtt.sample(50 * ms, 0, true);

    // Five packets, one every millisecond.
    var pn: u64 = 0;
    while (pn < 5) : (pn += 1) {
        try spaces.onSent(gpa, .application, .{
            .number = pn,
            .time_sent = pn * ms,
            .size = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        });
    }

    // Acknowledging 3 leaves 0 exactly at the threshold and 1, 2 inside it.
    var result = try spaces.resolve(gpa, .application, singleAck(3, 3), 4 * ms, &rtt);
    try testing.expectEqual(@as(usize, 1), result.acked.len);
    try testing.expectEqual(@as(usize, 1), result.lost.len);
    try testing.expectEqual(@as(u64, 0), result.lost[0].number);
    // The RTT sample comes from the largest acknowledged packet: 4 ms - 3 ms.
    try testing.expectEqual(@as(?u64, 1 * ms), result.rtt_sample);

    // 1 and 2 are still outstanding, and 4 is above the largest acknowledged.
    try testing.expectEqual(@as(usize, 3), spaces.sent[2].items.len);

    // Acknowledging 4 pushes 1 past the threshold as well.
    result = try spaces.resolve(gpa, .application, singleAck(4, 4), 5 * ms, &rtt);
    try testing.expectEqual(@as(usize, 1), result.lost.len);
    try testing.expectEqual(@as(u64, 1), result.lost[0].number);
}

test "recovery: §6.1.2 declares a packet lost on time, but only below the largest" {
    const gpa = testing.allocator;
    var spaces: Spaces = .{};
    defer spaces.deinit(gpa);
    var rtt: Rtt = .{};
    rtt.sample(50 * ms, 0, true);
    const loss_delay = rtt.lossDelay(); // 56.25 ms

    try spaces.onSent(gpa, .application, .{
        .number = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try spaces.onSent(gpa, .application, .{
        .number = 1,
        .time_sent = 1 * ms,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    // Acknowledging only 1 leaves 0 below the largest, so time can condemn it — but
    // not yet.
    const result = try spaces.resolve(gpa, .application, singleAck(1, 1), 2 * ms, &rtt);
    try testing.expectEqual(@as(usize, 0), result.lost.len);

    // Once the loss delay has passed, the timer finds it.
    const lost = try spaces.detectLostOnTimer(gpa, .application, loss_delay + 1, &rtt);
    try testing.expectEqual(@as(usize, 1), lost.len);
    try testing.expectEqual(@as(u64, 0), lost[0].number);

    // A packet *above* the largest acknowledged is never lost on time alone: there is
    // no evidence the peer received anything later, so it may simply still be in
    // flight. Declaring it lost would retransmit data that is about to be
    // acknowledged, which wastes the window at exactly the wrong moment.
    var fresh: Spaces = .{};
    defer fresh.deinit(gpa);
    try fresh.onSent(gpa, .application, .{
        .number = 10,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    _ = try fresh.resolve(gpa, .application, singleAck(5, 5), 1 * ms, &rtt);
    const none = try fresh.detectLostOnTimer(gpa, .application, 10 * loss_delay, &rtt);
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "recovery: only the largest acknowledged packet yields an RTT sample" {
    // §5.1. Measuring against any acknowledged packet would let a peer choose which
    // sample we take by holding one acknowledgement back — and choosing the sample
    // means choosing the PTO, which means choosing when we retransmit.
    const gpa = testing.allocator;
    var spaces: Spaces = .{};
    defer spaces.deinit(gpa);
    var rtt: Rtt = .{};

    try spaces.onSent(gpa, .application, .{
        .number = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try spaces.onSent(gpa, .application, .{
        .number = 1,
        .time_sent = 100 * ms,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });

    // An ACK covering both, whose largest is 1: the sample is 1's age, not 0's.
    const result = try spaces.resolve(gpa, .application, singleAck(1, 0), 150 * ms, &rtt);
    try testing.expectEqual(@as(usize, 2), result.acked.len);
    try testing.expectEqual(@as(?u64, 50 * ms), result.rtt_sample);

    // An ACK whose largest we never sent yields no sample at all.
    var other: Spaces = .{};
    defer other.deinit(gpa);
    try other.onSent(gpa, .application, .{
        .number = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    const no_sample = try other.resolve(gpa, .application, singleAck(5, 0), 10 * ms, &rtt);
    try testing.expectEqual(@as(usize, 1), no_sample.acked.len);
    try testing.expect(no_sample.rtt_sample == null);

    // Nor does an ACK-only packet, whose timing says nothing about when the peer
    // chose to respond.
    var quiet: Spaces = .{};
    defer quiet.deinit(gpa);
    try quiet.onSent(gpa, .application, .{
        .number = 0,
        .time_sent = 0,
        .size = 30,
        .ack_eliciting = false,
        .in_flight = false,
    });
    const from_ack = try quiet.resolve(gpa, .application, singleAck(0, 0), 10 * ms, &rtt);
    try testing.expect(from_ack.rtt_sample == null);
}

test "recovery: NewReno grows one for one in slow start and one datagram per window after" {
    var cc: Congestion = .init(1200);
    // §7.2: ten datagrams, floored at 14720.
    try testing.expectEqual(@as(u64, 12_000), cc.window);
    try testing.expect(cc.isSlowStart());

    const packet: Sent = .{
        .number = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    cc.onSent(packet);
    try testing.expectEqual(@as(u64, 1200), cc.in_flight);
    try testing.expectEqual(@as(u64, 10_800), cc.available());

    cc.onAck(packet, 1 * ms);
    try testing.expectEqual(@as(u64, 0), cc.in_flight);
    // Slow start: one for one.
    try testing.expectEqual(@as(u64, 13_200), cc.window);

    // A congestion event halves the window and leaves slow start.
    cc.onCongestion(0, 10 * ms);
    try testing.expectEqual(@as(u64, 6_600), cc.window);
    try testing.expectEqual(@as(u64, 6_600), cc.slow_start_threshold);
    try testing.expect(!cc.isSlowStart());

    // Congestion avoidance grows far more slowly: a full window of acknowledged data
    // adds about one datagram.
    const before = cc.window;
    var sent: u64 = 0;
    var pn: u64 = 100;
    while (sent < before) : (sent += 1200) {
        const later: Sent = .{
            .number = pn,
            .time_sent = 20 * ms,
            .size = 1200,
            .ack_eliciting = true,
            .in_flight = true,
        };
        pn += 1;
        cc.onSent(later);
        cc.onAck(later, 30 * ms);
    }
    const growth = cc.window - before;
    try testing.expect(growth > 0);
    try testing.expect(growth <= 2 * 1200);
}

test "recovery: §7.3.2's recovery period halves the window once per event" {
    // Without this a loss burst halves the window once per lost packet, and a
    // connection collapses to the minimum on the first bad moment — which looks like
    // a network problem rather than a bug, and would be blamed on one.
    var cc: Congestion = .init(1200);
    const start = cc.window;

    // Three packets sent at the same time are one congestion event.
    cc.onCongestion(5 * ms, 100 * ms);
    const after_first = cc.window;
    try testing.expectEqual(start / 2, after_first);

    cc.onCongestion(6 * ms, 101 * ms);
    cc.onCongestion(7 * ms, 102 * ms);
    try testing.expectEqual(after_first, cc.window);

    // A packet sent *after* the recovery period began is new evidence, so it reduces
    // the window again.
    cc.onCongestion(150 * ms, 200 * ms);
    try testing.expect(cc.window < after_first);

    // §7.2's minimum is a floor: repeated events cannot drive it below two datagrams.
    var i: usize = 0;
    var when: u64 = 300 * ms;
    while (i < 20) : (i += 1) {
        cc.onCongestion(when, when + ms);
        when += 10 * ms;
    }
    try testing.expectEqual(cc.minimumWindow(), cc.window);
}

test "recovery: an acknowledgement from before the recovery period does not grow the window" {
    // §7.3.2. A packet sent before the congestion event says nothing about the path
    // as it is now, so treating its acknowledgement as evidence of capacity undoes
    // the reduction that event just made.
    var cc: Congestion = .init(1200);
    const old: Sent = .{
        .number = 0,
        .time_sent = 1 * ms,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    cc.onSent(old);
    cc.onCongestion(1 * ms, 50 * ms);
    const after = cc.window;

    cc.onAck(old, 60 * ms);
    try testing.expectEqual(after, cc.window);
    // But the bytes leave flight regardless: they are no longer on the wire whatever
    // they say about capacity.
    try testing.expectEqual(@as(u64, 0), cc.in_flight);

    // A packet sent after the event does grow it, and ends the recovery period.
    const fresh: Sent = .{
        .number = 1,
        .time_sent = 60 * ms,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    };
    cc.onSent(fresh);
    cc.onAck(fresh, 70 * ms);
    try testing.expect(cc.window > after);
    try testing.expect(cc.recovery_start == null);
}

test "recovery: §7.6 distinguishes a busy path from a vanished one" {
    var rtt: Rtt = .{ .max_ack_delay = 25 * ms };
    rtt.sample(100 * ms, 0, true);
    const duration = Spaces.persistentCongestionDuration(&rtt);

    // Two packets far enough apart: the path is gone.
    const spread = [_]Sent{
        .{ .number = 0, .time_sent = 0, .size = 1200, .ack_eliciting = true, .in_flight = true },
        .{ .number = 1, .time_sent = duration + 1, .size = 1200, .ack_eliciting = true, .in_flight = true },
    };
    try testing.expect(Spaces.isPersistentCongestion(&spread, &.{}, duration));

    // §7.6.1's second half: a packet acknowledged from inside that window proves the
    // path was working, so what was lost was congestion rather than disappearance.
    // Without this check, any long-lived connection with two widely separated losses
    // collapses its window — and the two losses need not be related at all.
    const one_arrived = [_]Sent{
        .{ .number = 2, .time_sent = duration / 2, .size = 1200, .ack_eliciting = true, .in_flight = true },
    };
    try testing.expect(!Spaces.isPersistentCongestion(&spread, &one_arrived, duration));

    // An acknowledgement from outside the window says nothing about it.
    const outside = [_]Sent{
        .{ .number = 3, .time_sent = duration * 3, .size = 1200, .ack_eliciting = true, .in_flight = true },
    };
    try testing.expect(Spaces.isPersistentCongestion(&spread, &outside, duration));

    // Two packets close together: an ordinary loss burst. Treating this as persistent
    // congestion collapses the window on every hiccup.
    const burst = [_]Sent{
        .{ .number = 0, .time_sent = 0, .size = 1200, .ack_eliciting = true, .in_flight = true },
        .{ .number = 1, .time_sent = 1 * ms, .size = 1200, .ack_eliciting = true, .in_flight = true },
    };
    try testing.expect(!Spaces.isPersistentCongestion(&burst, &.{}, duration));

    // A single loss, however old, spans no time and so is never persistent
    // congestion. No explicit count check is needed for that, which is why there
    // isn't one.
    const single = [_]Sent{
        .{ .number = 0, .time_sent = 0, .size = 1200, .ack_eliciting = true, .in_flight = true },
    };
    try testing.expect(!Spaces.isPersistentCongestion(&single, &.{}, duration));

    // And packets that were never ack-eliciting do not count towards it, since their
    // loss was never detectable in the first place.
    const acks_only = [_]Sent{
        .{ .number = 0, .time_sent = 0, .size = 30, .ack_eliciting = false, .in_flight = false },
        .{ .number = 1, .time_sent = duration + 1, .size = 30, .ack_eliciting = false, .in_flight = false },
    };
    try testing.expect(!Spaces.isPersistentCongestion(&acks_only, &.{}, duration));

    var cc: Congestion = .init(1200);
    cc.onPersistentCongestion();
    try testing.expectEqual(cc.minimumWindow(), cc.window);
}

test "recovery: the PTO backs off, and is not armed when nothing is outstanding" {
    const gpa = testing.allocator;
    var spaces: Spaces = .{};
    defer spaces.deinit(gpa);
    var rtt: Rtt = .{ .max_ack_delay = 25 * ms };
    rtt.sample(100 * ms, 0, true);

    // §6.2.1: nothing outstanding, no timer. Arming one anyway makes an idle
    // connection probe forever, which is both traffic and a way to keep a NAT
    // binding alive that the application never asked for.
    try testing.expect(spaces.nextTimeout(&rtt, true) == null);

    try spaces.onSent(gpa, .application, .{
        .number = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    const first = spaces.nextTimeout(&rtt, true).?;
    try testing.expectEqual(rtt.probeTimeout(.application), first);

    // Each expiry doubles the wait.
    spaces.onProbeTimeout();
    try testing.expectEqual(rtt.probeTimeout(.application) * 2, spaces.nextTimeout(&rtt, true).?);
    spaces.onProbeTimeout();
    try testing.expectEqual(rtt.probeTimeout(.application) * 4, spaces.nextTimeout(&rtt, true).?);

    // An acknowledgement resets the backoff, because the path has just proved it
    // works.
    _ = try spaces.resolve(gpa, .application, singleAck(0, 0), 50 * ms, &rtt);
    try testing.expectEqual(@as(u32, 0), spaces.pto_count);

    // §6.2.1: the application space is not probed before the handshake is confirmed,
    // because 1-RTT packets cannot be acknowledged yet.
    var early: Spaces = .{};
    defer early.deinit(gpa);
    try early.onSent(gpa, .application, .{
        .number = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try testing.expect(early.nextTimeout(&rtt, false) == null);
    try testing.expect(early.nextTimeout(&rtt, true) != null);
}

test "recovery: an ACK-only packet is neither in flight nor probed for" {
    // §2's two flags are separate for a reason: a packet containing only ACK frames
    // does not count against the congestion window (§13.2.7 is about PADDING; ACK
    // frames are exempt by §2) and cannot be detected as lost, since the peer owes it
    // no acknowledgement.
    const gpa = testing.allocator;
    var spaces: Spaces = .{};
    defer spaces.deinit(gpa);
    var rtt: Rtt = .{};
    rtt.sample(50 * ms, 0, true);

    try spaces.onSent(gpa, .application, .{
        .number = 0,
        .time_sent = 0,
        .size = 40,
        .ack_eliciting = false,
        .in_flight = false,
    });
    try testing.expectEqual(@as(u64, 0), spaces.bytesInFlight());
    try testing.expect(!spaces.hasAckElicitingOutstanding());
    try testing.expect(spaces.nextTimeout(&rtt, true) == null);

    var cc: Congestion = .init(1200);
    cc.onSent(.{
        .number = 0,
        .time_sent = 0,
        .size = 40,
        .ack_eliciting = false,
        .in_flight = false,
    });
    try testing.expectEqual(@as(u64, 0), cc.in_flight);
}

test "recovery: discarding a space forgets its packets" {
    // RFC 9001 §4.9: when a space's keys go, so does its loss recovery state. Keeping
    // it would arm a timer for packets that can no longer be acknowledged, and the
    // probe it eventually sent could not be protected.
    const gpa = testing.allocator;
    var spaces: Spaces = .{};
    defer spaces.deinit(gpa);
    var rtt: Rtt = .{};
    rtt.sample(50 * ms, 0, true);

    try spaces.onSent(gpa, .initial, .{
        .number = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
    });
    try testing.expect(spaces.hasAckElicitingOutstanding());

    spaces.discard(gpa, .initial);
    try testing.expect(!spaces.hasAckElicitingOutstanding());
    try testing.expect(spaces.nextTimeout(&rtt, true) == null);
    try testing.expect(spaces.largest_acked[0] == null);
}

test "recovery: each space is resolved independently" {
    // §12.3: a packet number in one space says nothing about another, so an ACK in
    // the Handshake space must not resolve or condemn anything in the application
    // space. Sharing the state would make a handshake ACK retransmit application
    // data, or worse, acknowledge it.
    const gpa = testing.allocator;
    var spaces: Spaces = .{};
    defer spaces.deinit(gpa);
    var rtt: Rtt = .{};
    rtt.sample(50 * ms, 0, true);

    for ([_]Space{ .handshake, .application }) |space| {
        var pn: u64 = 0;
        while (pn < 5) : (pn += 1) {
            try spaces.onSent(gpa, space, .{
                .number = pn,
                .time_sent = pn * ms,
                .size = 1200,
                .ack_eliciting = true,
                .in_flight = true,
            });
        }
    }

    const result = try spaces.resolve(gpa, .handshake, singleAck(4, 0), 10 * ms, &rtt);
    try testing.expectEqual(@as(usize, 5), result.acked.len);
    try testing.expectEqual(@as(usize, 0), spaces.sent[1].items.len);
    // The application space is untouched.
    try testing.expectEqual(@as(usize, 5), spaces.sent[2].items.len);
    try testing.expect(spaces.largest_acked[2] == null);
}

test "recovery: addRange merges overlaps, because retransmission makes them ordinary" {
    var set: AckRanges = .{};

    _ = set.addRange(10, 20);
    _ = set.addRange(30, 40);
    try testing.expectEqual(@as(usize, 2), set.len);

    // A range overlapping both absorbs both. This is the case stream
    // retransmission produces: a resent suffix is acknowledged over ground an
    // earlier acknowledgement already covered.
    _ = set.addRange(15, 35);
    try testing.expectEqual(@as(usize, 1), set.len);
    try testing.expectEqual(@as(u64, 40), set.ranges[0].largest);
    try testing.expectEqual(@as(u64, 10), set.ranges[0].smallest);

    // Touching counts as merging: [41, 45] extends [10, 40] rather than
    // standing next to it, since an ACK frame may not encode adjacent ranges.
    _ = set.addRange(41, 45);
    try testing.expectEqual(@as(usize, 1), set.len);
    try testing.expectEqual(@as(u64, 45), set.ranges[0].largest);

    // A wholly-contained range changes nothing.
    _ = set.addRange(12, 13);
    try testing.expectEqual(@as(usize, 1), set.len);
}

test "recovery: addRange reports the range the bound rejected" {
    // For received packet numbers the report is ignored (§13.2.3 permits the
    // spurious retransmission it causes). For acknowledged stream offsets it must
    // not be: an acknowledgement forgotten is data never released and never
    // resent, so the caller treats the reported range as unacknowledged and
    // rewinds. The return value is what makes that caller possible.
    var set: AckRanges = .{};
    var base: u64 = 100;
    while (set.len < max_ack_ranges) : (base += 10) _ = set.addRange(base, base + 1);

    // A new lowest range does not fit: it is the one reported.
    const refused = set.addRange(1, 2);
    try testing.expect(refused != null);
    try testing.expectEqual(@as(u64, 1), refused.?.smallest);
    try testing.expectEqual(@as(usize, max_ack_ranges), set.len);

    // A new highest range fits by evicting the lowest, which is reported.
    const lowest_before = set.ranges[set.len - 1];
    const evicted = set.addRange(10_000, 10_001);
    try testing.expect(evicted != null);
    try testing.expectEqual(lowest_before.smallest, evicted.?.smallest);
    try testing.expectEqual(@as(?u64, 10_001), set.largest());

    // A merge never evicts anything: the set does not grow.
    const merged = set.addRange(10_000, 10_005);
    try testing.expect(merged == null);
}
