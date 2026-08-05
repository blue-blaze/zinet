//! The collection of streams: RFC 9000 §3.2's implicit creation, §4.1's
//! connection-level flow control, and §4.6's stream counts.
//!
//! Separate from `stream.zig` because these limits are about the relationship
//! *between* streams. A single stream cannot know whether the connection window
//! is exhausted, and giving each one a pointer to shared state it does not own is
//! how that knowledge leaks into the wrong place.
//!
//! **Two orderings here are security properties rather than tidiness.**
//!
//! §3.2 requires that receiving a frame for stream N implicitly create every
//! lower-numbered stream of the same kind. §21.8 points out what that means: a
//! peer opening stream 4000000 asks for a million streams in one frame. So the
//! §4.6 limit is checked **against the highest ID, once, before anything is
//! created**. Checking it while creating them would allocate a million streams
//! and then refuse — the attack succeeds and the error message is beside the
//! point.
//!
//! Connection-level credit is accumulated from each stream's increment rather
//! than recomputed by summing the streams. Finished streams are forgotten, so a
//! sum over live streams would silently release their credit and let a peer send
//! more than the connection window ever allowed.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const stream_mod = @import("stream.zig");
const transport = @import("transport.zig");

const Id = stream_mod.Id;
const Kind = stream_mod.Kind;
const Stream = stream_mod.Stream;

pub const Error = error{
    /// §4.6: the peer opened more streams than it was permitted.
    StreamLimitError,
    /// §19.11: a MAX_STREAMS frame allowing an ID that cannot be encoded. Separate
    /// from `StreamLimitError` because the two describe different faults and §20.1
    /// gives them different codes: one says the peer used too many streams, the
    /// other that the frame itself is malformed. Collapsing them would send a peer
    /// looking for a stream it never opened.
    FrameEncodingError,
    /// §4.1: more data than the connection window allows.
    FlowControlError,
    /// §3.2: a frame for a stream that cannot exist, or for a direction that
    /// cannot carry it.
    StreamStateError,
} || stream_mod.Error;

/// How many streams this implementation will hold at once, whatever the peer's
/// limit allows. A compile-time ceiling separate from the advertised limit, for
/// the same reason `cid.zig` has one: the advertised value is a promise to the
/// peer, and a promise cannot be allowed to allocate.
pub const max_concurrent = 512;

/// Held-back out-of-order bytes per stream. The per-stream flow control limit
/// ought to bound this; this bounds it when the peer does not cooperate.
pub const max_reassembly_per_stream = 256 * 1024;

pub const Config = struct {
    /// What we advertised: `initial_max_data`.
    local_max_data: u64,
    /// What we advertised for streams the peer sends on.
    local_max_stream_data: u64,
    /// §4.6: how many bidirectional and unidirectional streams the peer may open.
    local_max_streams_bidi: u64,
    local_max_streams_uni: u64,

    /// The peer's corresponding values, from its transport parameters.
    peer_max_data: u64 = 0,
    peer_max_stream_data_bidi_local: u64 = 0,
    peer_max_stream_data_bidi_remote: u64 = 0,
    peer_max_stream_data_uni: u64 = 0,
    peer_max_streams_bidi: u64 = 0,
    peer_max_streams_uni: u64 = 0,
};

/// Index into the per-direction arrays. §4.6 keeps separate limits for
/// bidirectional and unidirectional streams.
const Direction = enum(u1) { bidi = 0, uni = 1 };

fn directionOf(kind: Kind) Direction {
    return if (kind.isBidirectional()) .bidi else .uni;
}

pub const Streams = struct {
    role: transport.Role,
    config: Config,
    map: std.AutoHashMapUnmanaged(u64, Stream) = .empty,

    /// §4.6: the number of peer-initiated streams of each direction that have
    /// been created, implicitly or otherwise. Kept even for streams since
    /// forgotten, because the limit is cumulative over the connection's life —
    /// closing a stream does not give the peer another.
    remote_opened: [2]u64 = .{ 0, 0 },
    /// The same for streams we opened.
    local_opened: [2]u64 = .{ 0, 0 },
    /// §4.6: what the peer will let us open, which may grow via MAX_STREAMS.
    peer_max_streams: [2]u64 = .{ 0, 0 },
    /// What we advertised, which grows as we credit the peer.
    local_max_streams: [2]u64 = .{ 0, 0 },

    /// §4.1: connection-level receive accounting. `used` accumulates each
    /// stream's increment rather than being summed over live streams, because
    /// finished streams are forgotten and a sum would release their credit.
    recv_max_data: u64,
    recv_used: u64 = 0,
    /// Bytes the application has read across all streams, which is what decides
    /// when a larger MAX_DATA is worth sending.
    recv_consumed: u64 = 0,

    recv_window: u64,

    /// The send side of the same.
    send_max_data: u64 = 0,
    send_used: u64 = 0,

    pub fn init(role: transport.Role, config: Config) Streams {
        return .{
            .role = role,
            .config = config,
            .local_max_streams = .{ config.local_max_streams_bidi, config.local_max_streams_uni },
            .peer_max_streams = .{ config.peer_max_streams_bidi, config.peer_max_streams_uni },
            .recv_max_data = config.local_max_data,
            .recv_window = config.local_max_data,
            .send_max_data = config.peer_max_data,
        };
    }

    pub fn deinit(self: *Streams, gpa: Allocator) void {
        var it = self.map.valueIterator();
        while (it.next()) |s| s.deinit(gpa);
        self.map.deinit(gpa);
        self.* = undefined;
    }

    /// Once the peer's transport parameters arrive, its limits apply.
    pub fn applyPeerParameters(self: *Streams, params: *const transport.Parameters) void {
        self.config.peer_max_data = params.initial_max_data;
        self.config.peer_max_stream_data_bidi_local = params.initial_max_stream_data_bidi_local;
        self.config.peer_max_stream_data_bidi_remote = params.initial_max_stream_data_bidi_remote;
        self.config.peer_max_stream_data_uni = params.initial_max_stream_data_uni;
        self.peer_max_streams = .{ params.initial_max_streams_bidi, params.initial_max_streams_uni };
        self.send_max_data = params.initial_max_data;
    }

    pub fn get(self: *Streams, id: Id) ?*Stream {
        return self.map.getPtr(id.value);
    }

    pub fn count(self: *const Streams) usize {
        return self.map.count();
    }

    /// The per-stream limit that applies to what *we* send on `id`.
    ///
    /// §18.2 splits this three ways, and the split is easy to get backwards: for a
    /// stream we opened, the peer's `bidi_local` value does not apply — that one
    /// describes streams *it* opened. Getting it wrong produces a sender that
    /// stalls at the wrong offset, or one that overruns and gets closed.
    fn sendLimitFor(self: *const Streams, id: Id) u64 {
        const kind = id.kind();
        if (!kind.isBidirectional()) return self.config.peer_max_stream_data_uni;
        return if (id.isLocallyInitiated(self.role))
            // We opened it, so from the peer's point of view it is remote.
            self.config.peer_max_stream_data_bidi_remote
        else
            self.config.peer_max_stream_data_bidi_local;
    }

    fn limitsFor(self: *const Streams, id: Id) stream_mod.Limits {
        return .{
            .local_max_stream_data = self.config.local_max_stream_data,
            .peer_max_stream_data = self.sendLimitFor(id),
        };
    }

    /// Open a stream of our own, returning its ID.
    pub fn open(self: *Streams, gpa: Allocator, bidirectional: bool) Error!Id {
        const kind: Kind = switch (self.role) {
            .client => if (bidirectional) .client_bidi else .client_uni,
            .server => if (bidirectional) .server_bidi else .server_uni,
        };
        const direction = directionOf(kind);
        const index = self.local_opened[@backingInt(direction)];

        // §4.6: we may not exceed the peer's limit. Enforced on our own side too,
        // because an implementation that only checks the inbound half is the one
        // whose connections get closed by a correct peer.
        if (index >= self.peer_max_streams[@backingInt(direction)]) {
            return error.StreamLimitError;
        }
        if (self.map.count() >= max_concurrent) return error.StreamLimitError;

        const id = Id.make(kind, index);
        try self.map.put(gpa, id.value, .init(id, self.role, self.limitsFor(id)));
        self.local_opened[@backingInt(direction)] = index + 1;
        return id;
    }

    /// Are we able to open another stream of this direction right now? §19.14 asks
    /// for a STREAMS_BLOCKED frame when not, which is a debugging signal rather
    /// than a requirement.
    pub fn canOpen(self: *const Streams, bidirectional: bool) bool {
        const direction: Direction = if (bidirectional) .bidi else .uni;
        const i = @backingInt(direction);
        return self.local_opened[i] < self.peer_max_streams[i] and self.map.count() < max_concurrent;
    }

    /// Find or create the stream `id` refers to, applying §3.2 and §4.6.
    ///
    /// Returns null when the stream existed and has already been finished and
    /// forgotten — a late frame for it is not an error, since the network can
    /// deliver one at any time. §4.5 explicitly permits forgetting the final size
    /// of a closed stream rather than committing state to it forever.
    fn ensure(self: *Streams, gpa: Allocator, id: Id) Error!?*Stream {
        if (self.map.getPtr(id.value)) |existing| return existing;

        const kind = id.kind();
        const direction = directionOf(kind);
        const i = @backingInt(direction);

        if (id.isLocallyInitiated(self.role)) {
            // §3.2: a stream we would have opened. If it does not exist and its
            // index is below what we have opened, it finished and was forgotten.
            // Above that, the peer is referring to a stream that cannot exist.
            if (id.index() < self.local_opened[i]) return null;
            return error.StreamStateError;
        }

        // A peer-initiated stream. §3.2: everything below it of the same kind must
        // be created too.
        const wanted = id.index() + 1;
        if (wanted <= self.remote_opened[i]) return null; // finished and forgotten

        // **The limit is checked against the highest ID, before anything is
        // created.** §21.8: a frame naming stream 4000000 asks for a million
        // streams. Checking while creating them would allocate the million and
        // then refuse, which is the attack succeeding with a tidy error message
        // attached.
        if (wanted > self.local_max_streams[i]) return error.StreamLimitError;

        const to_create = wanted - self.remote_opened[i];
        if (self.map.count() + to_create > max_concurrent) return error.StreamLimitError;

        var index = self.remote_opened[i];
        while (index < wanted) : (index += 1) {
            const each = Id.make(kind, index);
            try self.map.put(gpa, each.value, .init(each, self.role, self.limitsFor(each)));
        }
        self.remote_opened[i] = wanted;

        return self.map.getPtr(id.value).?;
    }

    /// Apply an inbound STREAM frame (§19.8).
    pub fn receiveStream(
        self: *Streams,
        gpa: Allocator,
        id: Id,
        offset: u64,
        data: []const u8,
        fin: bool,
    ) Error!void {
        // §19.8: a STREAM frame on a stream we cannot receive on. For a
        // unidirectional stream we opened, the peer writing to it is not a
        // misunderstanding — it is the peer using a channel that does not exist.
        if (!id.canReceive(self.role)) return error.StreamStateError;

        const s = (try self.ensure(gpa, id)) orelse return;
        const recv = &s.recv.?;

        const increment = try recv.receive(
            gpa,
            offset,
            data,
            fin,
            max_reassembly_per_stream,
            self.connectionRoom(),
        );
        self.recv_used += increment;
        self.reapIfFinished(gpa, id);
    }

    /// Apply an inbound RESET_STREAM frame (§19.4).
    pub fn receiveReset(
        self: *Streams,
        gpa: Allocator,
        id: Id,
        code: u64,
        final_size: u64,
    ) Error!void {
        // §19.4: a RESET_STREAM for a send-only stream is a STREAM_STATE_ERROR.
        if (!id.canReceive(self.role)) return error.StreamStateError;

        const s = (try self.ensure(gpa, id)) orelse return;
        const recv = &s.recv.?;

        const increment = try recv.reset(gpa, code, final_size, self.connectionRoom());
        self.recv_used += increment;
        self.reapIfFinished(gpa, id);
    }

    /// Apply an inbound STOP_SENDING frame (§19.5).
    pub fn receiveStopSending(self: *Streams, gpa: Allocator, id: Id, code: u64) Error!void {
        // §19.5: a STOP_SENDING for a receive-only stream is a STREAM_STATE_ERROR.
        if (!id.canSend(self.role)) return error.StreamStateError;

        const s = (try self.ensure(gpa, id)) orelse return;
        try s.send.?.stopSending(code);
    }

    /// Apply an inbound MAX_STREAM_DATA frame (§19.10).
    pub fn receiveMaxStreamData(self: *Streams, gpa: Allocator, id: Id, limit: u64) Error!void {
        // §19.10: for a receive-only stream this is a STREAM_STATE_ERROR — the
        // peer is granting us credit on a stream we cannot write to.
        if (!id.canSend(self.role)) return error.StreamStateError;

        const s = (try self.ensure(gpa, id)) orelse return;
        s.send.?.applyCredit(limit);
    }

    /// Apply an inbound MAX_DATA frame (§19.9).
    pub fn receiveMaxData(self: *Streams, limit: u64) void {
        // §4.1: a limit that does not increase must be ignored. Reordering makes a
        // smaller value ordinary rather than hostile.
        if (limit > self.send_max_data) self.send_max_data = limit;
    }

    /// Apply an inbound MAX_STREAMS frame (§19.11).
    pub fn receiveMaxStreams(self: *Streams, bidirectional: bool, streams: u64) Error!void {
        // §4.6 and §19.11: above 2^60 the resulting stream ID would not fit a
        // varint, and the code for it is FRAME_ENCODING_ERROR — §4.6 names both that
        // and TRANSPORT_PARAMETER_ERROR in one sentence, for the frame and the
        // parameter respectively, and the parameter half is in `transport.zig`.
        if (streams > stream_mod.max_streams) return error.FrameEncodingError;
        const i: usize = if (bidirectional) 0 else 1;
        if (streams > self.peer_max_streams[i]) self.peer_max_streams[i] = streams;
    }

    /// Apply an inbound STREAM_DATA_BLOCKED frame (§19.13). It carries no
    /// obligation — it is the peer telling us it wants to write — but the state
    /// check still applies.
    pub fn receiveStreamDataBlocked(self: *Streams, gpa: Allocator, id: Id) Error!void {
        if (!id.canReceive(self.role)) return error.StreamStateError;
        _ = try self.ensure(gpa, id);
    }

    /// Write to a stream, returning how many bytes were accepted.
    ///
    /// Bounded by both levels of §4.1: the stream's own limit and the connection's.
    /// A short write is normal and means flow control, not failure.
    pub fn write(self: *Streams, gpa: Allocator, id: Id, data: []const u8) Error!usize {
        const s = self.map.getPtr(id.value) orelse return error.StreamStateError;
        const send = &(s.send orelse return error.StreamStateError);

        const stream_room = send.available();
        const connection_room = if (self.send_used >= self.send_max_data)
            0
        else
            self.send_max_data - self.send_used;

        const take: usize = @intCast(@min(@min(stream_room, connection_room), data.len));
        if (take == 0) return 0;

        try send.write(gpa, data[0..take]);
        self.send_used += take;
        return take;
    }

    /// Is the connection as a whole blocked by §4.1's limit? §19.12 asks for a
    /// DATA_BLOCKED frame in that case.
    pub fn isBlocked(self: *const Streams) bool {
        return self.send_used >= self.send_max_data;
    }

    /// Note that the application has consumed `n` bytes from `id`, which is what
    /// releases connection-level credit.
    pub fn consume(self: *Streams, gpa: Allocator, id: Id, n: usize) void {
        const s = self.map.getPtr(id.value) orelse return;
        const recv = &(s.recv orelse return);
        recv.consume(n);
        self.recv_consumed += n;
        self.reapIfFinished(gpa, id);
    }

    /// Take a stream's reset code, telling the application about it and letting the
    /// stream be forgotten. Without this a reset stream is never finished, so the
    /// map grows for the life of the connection at the peer's discretion.
    pub fn takeReset(self: *Streams, gpa: Allocator, id: Id) ?u64 {
        const s = self.map.getPtr(id.value) orelse return null;
        const recv = &(s.recv orelse return null);
        const code = recv.takeReset() orelse return null;
        self.reapIfFinished(gpa, id);
        return code;
    }

    /// The limit to advertise in MAX_DATA, or null if it would say nothing new.
    pub fn maxDataUpdate(self: *const Streams) ?u64 {
        const target = self.recv_consumed + self.recv_window;
        if (target <= self.recv_max_data) return null;
        if (target - self.recv_max_data < self.recv_window / 2) return null;
        return target;
    }

    pub fn applyMaxDataSent(self: *Streams, limit: u64) void {
        if (limit > self.recv_max_data) self.recv_max_data = limit;
    }

    /// The limit to advertise in MAX_STREAMS, or null if it would say nothing new.
    ///
    /// §4.6: implementations may raise the limit as streams close, to keep the
    /// number available roughly constant. That is what this does, and it is why
    /// `remote_opened` is cumulative: the credit granted is cumulative too.
    pub fn maxStreamsUpdate(self: *const Streams, bidirectional: bool) ?u64 {
        const i: usize = if (bidirectional) 0 else 1;
        const initial = if (bidirectional)
            self.config.local_max_streams_bidi
        else
            self.config.local_max_streams_uni;
        if (initial == 0) return null;

        const live = self.liveRemoteStreams(if (bidirectional) true else false);
        const target = self.remote_opened[i] - live + initial;
        if (target <= self.local_max_streams[i]) return null;
        if (target - self.local_max_streams[i] < @max(initial / 2, 1)) return null;
        return target;
    }

    pub fn applyMaxStreamsSent(self: *Streams, bidirectional: bool, limit: u64) void {
        const i: usize = if (bidirectional) 0 else 1;
        if (limit > self.local_max_streams[i]) self.local_max_streams[i] = limit;
    }

    fn liveRemoteStreams(self: *const Streams, bidirectional: bool) u64 {
        var total: u64 = 0;
        var it = self.map.keyIterator();
        while (it.next()) |key| {
            const id = Id.init(key.*);
            if (id.isLocallyInitiated(self.role)) continue;
            if (id.kind().isBidirectional() != bidirectional) continue;
            total += 1;
        }
        return total;
    }

    /// How much of §4.1's connection window is left.
    ///
    /// Passed *into* the stream rather than checked after it returns, because a
    /// frame that violates flow control must not change any state — and checking
    /// afterwards means the stream's offset has already advanced. Exceeding this
    /// is a FLOW_CONTROL_ERROR even when every individual stream stayed inside its
    /// own limit, which is the entire point of having two levels.
    fn connectionRoom(self: *const Streams) u64 {
        if (self.recv_used >= self.recv_max_data) return 0;
        return self.recv_max_data - self.recv_used;
    }

    /// Forget a stream once both directions are terminal.
    ///
    /// §4.5 permits this explicitly, and the counters make it safe: a late frame
    /// for a forgotten stream is recognised by its index rather than by finding it
    /// in the map, so forgetting does not resurrect it.
    pub fn reapIfFinished(self: *Streams, gpa: Allocator, id: Id) void {
        const s = self.map.getPtr(id.value) orelse return;
        if (!s.isFinished()) return;
        var owned = self.map.fetchRemove(id.value).?;
        owned.value.deinit(gpa);
    }
};

const testing = std.testing;

fn testConfig() Config {
    return .{
        .local_max_data = 10_000,
        .local_max_stream_data = 1_000,
        .local_max_streams_bidi = 4,
        .local_max_streams_uni = 2,
        .peer_max_data = 10_000,
        .peer_max_stream_data_bidi_local = 1_000,
        .peer_max_stream_data_bidi_remote = 1_000,
        .peer_max_stream_data_uni = 1_000,
        .peer_max_streams_bidi = 3,
        .peer_max_streams_uni = 2,
    };
}

test "streams: §3.2 creates every lower-numbered stream of the same kind" {
    const gpa = testing.allocator;
    var streams: Streams = .init(.server, testConfig());
    defer streams.deinit(gpa);

    // A client opening its third bidirectional stream implicitly opens the first
    // two. Both endpoints must agree on the creation order, which is the reason
    // for the rule.
    const third = Id.make(.client_bidi, 2);
    try streams.receiveStream(gpa, third, 0, "hi", false);

    try testing.expectEqual(@as(usize, 3), streams.count());
    try testing.expect(streams.get(Id.make(.client_bidi, 0)) != null);
    try testing.expect(streams.get(Id.make(.client_bidi, 1)) != null);
    try testing.expect(streams.get(third) != null);
    try testing.expectEqual(@as(u64, 3), streams.remote_opened[0]);

    // Unidirectional streams are a separate space: opening a bidirectional one
    // creates no unidirectional ones.
    try testing.expectEqual(@as(u64, 0), streams.remote_opened[1]);

    // Only the named stream carries the data.
    try testing.expectEqualStrings("hi", streams.get(third).?.recv.?.readable());
    try testing.expectEqual(@as(usize, 0), streams.get(Id.make(.client_bidi, 0)).?.recv.?.readable().len);
}

test "streams: §4.6's limit is checked before anything is created" {
    // §21.8's attack: a frame naming stream 4000000 asks for a million streams.
    // Checking the limit while creating them would allocate the million and then
    // refuse — the attack succeeds and the error message is beside the point. This
    // test would still pass with the check in the wrong place, so what makes it
    // meaningful is the assertion that *nothing* was created.
    const gpa = testing.allocator;
    var streams: Streams = .init(.server, testConfig());
    defer streams.deinit(gpa);

    const far = Id.make(.client_bidi, 1_000_000);
    try testing.expectError(
        error.StreamLimitError,
        streams.receiveStream(gpa, far, 0, "x", false),
    );
    try testing.expectEqual(@as(usize, 0), streams.count());
    try testing.expectEqual(@as(u64, 0), streams.remote_opened[0]);

    // The limit is four, so index 3 is the last one allowed and index 4 is not.
    try streams.receiveStream(gpa, Id.make(.client_bidi, 3), 0, "x", false);
    try testing.expectEqual(@as(usize, 4), streams.count());
    try testing.expectError(
        error.StreamLimitError,
        streams.receiveStream(gpa, Id.make(.client_bidi, 4), 0, "x", false),
    );
    // And still four: the refusal created nothing.
    try testing.expectEqual(@as(usize, 4), streams.count());
}

test "streams: we may not exceed the peer's limit either" {
    // The mirror of the rule above. An implementation that enforces only the
    // inbound half is the one whose connections get closed by a correct peer.
    const gpa = testing.allocator;
    var streams: Streams = .init(.client, testConfig());
    defer streams.deinit(gpa);

    // The peer allows three bidirectional streams.
    try testing.expectEqual(@as(u64, 0), (try streams.open(gpa, true)).index());
    try testing.expectEqual(@as(u64, 1), (try streams.open(gpa, true)).index());
    try testing.expectEqual(@as(u64, 2), (try streams.open(gpa, true)).index());
    try testing.expect(!streams.canOpen(true));
    try testing.expectError(error.StreamLimitError, streams.open(gpa, true));

    // MAX_STREAMS raises it; a value that does not increase is ignored (§19.11).
    try streams.receiveMaxStreams(true, 2);
    try testing.expect(!streams.canOpen(true));
    try streams.receiveMaxStreams(true, 5);
    try testing.expect(streams.canOpen(true));
    try testing.expectEqual(@as(u64, 3), (try streams.open(gpa, true)).index());

    // §4.6 with §19.11: a count above 2^60 implies an unencodable stream ID, and the
    // code for it is FRAME_ENCODING_ERROR rather than STREAM_LIMIT_ERROR. This test
    // asserted the latter until §19.11 was read against it: §20.1 defines
    // STREAM_LIMIT_ERROR as "received a frame for a stream identifier that exceeded
    // its advertised stream limit", which is not what happened — nothing opened a
    // stream, the frame is simply malformed. §11 does permit a generic code in place
    // of a specific one, but STREAM_LIMIT_ERROR is neither generic nor applicable,
    // and it points the peer at its own stream usage instead of at its encoder.
    try testing.expectError(
        error.FrameEncodingError,
        streams.receiveMaxStreams(true, stream_mod.max_streams + 1),
    );

    // Unidirectional streams have their own budget, untouched by the above.
    try testing.expect(streams.canOpen(false));
    const uni = try streams.open(gpa, false);
    try testing.expectEqual(Kind.client_uni, uni.kind());
    try testing.expect(uni.canSend(.client));
    try testing.expect(!uni.canReceive(.client));
}

test "streams: §4.1's connection limit binds even when every stream is inside its own" {
    // The whole point of two levels: one stream cannot consume the connection's
    // buffer, and many streams together cannot either.
    const gpa = testing.allocator;
    var config = testConfig();
    config.local_max_data = 1_500;
    config.local_max_stream_data = 1_000;
    config.local_max_streams_bidi = 10;
    var streams: Streams = .init(.server, config);
    defer streams.deinit(gpa);

    const payload: [1000]u8 = @splat('a');
    // One stream fills its own window exactly.
    try streams.receiveStream(gpa, Id.make(.client_bidi, 0), 0, &payload, false);
    try testing.expectEqual(@as(u64, 1000), streams.recv_used);

    // A second stream stays inside *its* window but would take the connection
    // past 1500.
    try testing.expectError(error.FlowControlError, streams.receiveStream(
        gpa,
        Id.make(.client_bidi, 1),
        0,
        &payload,
        false,
    ));

    // What fits, fits.
    try streams.receiveStream(gpa, Id.make(.client_bidi, 1), 0, payload[0..500], false);
    try testing.expectEqual(@as(u64, 1500), streams.recv_used);
}

test "streams: a reset stream keeps its connection credit charged" {
    // §4.5 at the connection level. If a reset released credit for data that never
    // arrived, the two endpoints would disagree about the connection window
    // permanently. And because finished streams are forgotten, the accounting has
    // to accumulate increments rather than sum over live streams — a sum would
    // release the credit the moment the stream disappeared.
    const gpa = testing.allocator;
    var streams: Streams = .init(.server, testConfig());
    defer streams.deinit(gpa);

    const id = Id.make(.client_bidi, 0);
    try streams.receiveStream(gpa, id, 0, "ab", false);
    try testing.expectEqual(@as(u64, 2), streams.recv_used);

    // The peer resets it, claiming 600 bytes were sent.
    try streams.receiveReset(gpa, id, 0x10, 600);
    try testing.expectEqual(@as(u64, 600), streams.recv_used);

    // Neither half is terminal yet: the reset has not been reported to the
    // application, and our own sending side is still open. Both have to finish
    // before the stream can be forgotten.
    try testing.expect(streams.get(id) != null);
    try testing.expectEqual(@as(?u64, 0x10), streams.takeReset(gpa, id));
    try testing.expect(streams.get(id) != null);

    _ = try streams.get(id).?.send.?.abandon(0);
    streams.get(id).?.send.?.markAcked(0, true);
    streams.reapIfFinished(gpa, id);
    try testing.expect(streams.get(id) == null);
    // And the credit stays charged after the stream is gone, which is what makes
    // accumulating increments rather than summing live streams necessary.
    try testing.expectEqual(@as(u64, 600), streams.recv_used);

    // Taking the reset twice yields nothing: it is a transition, not a query.
    try testing.expect(streams.takeReset(gpa, id) == null);
}

test "streams: a late frame for a forgotten stream is not an error" {
    // The network can deliver one at any time, and §4.5 explicitly permits
    // forgetting a closed stream's final size rather than committing state to it
    // forever. The counters are what make forgetting safe: a late frame is
    // recognised by its index, so it does not resurrect the stream.
    const gpa = testing.allocator;
    var streams: Streams = .init(.server, testConfig());
    defer streams.deinit(gpa);

    const id = Id.make(.client_uni, 0);
    try streams.receiveStream(gpa, id, 0, "done", true);
    streams.consume(gpa, id, 4);
    // A unidirectional stream the peer opened has only a receiving half, so
    // reading everything finishes it.
    try testing.expect(streams.get(id) == null);
    try testing.expectEqual(@as(u64, 1), streams.remote_opened[1]);

    // A retransmission arrives late. It is neither an error nor a new stream.
    try streams.receiveStream(gpa, id, 0, "done", true);
    try testing.expectEqual(@as(usize, 0), streams.count());
    try testing.expectEqual(@as(u64, 1), streams.remote_opened[1]);
    // And the credit it consumed is not charged twice.
    try testing.expectEqual(@as(u64, 4), streams.recv_used);
}

test "streams: frames on the wrong direction are STREAM_STATE_ERROR" {
    const gpa = testing.allocator;
    var streams: Streams = .init(.server, testConfig());
    defer streams.deinit(gpa);

    // A server's own unidirectional stream: the client cannot write to it. This is
    // not a misunderstanding but the peer using a channel that does not exist.
    const ours = Id.make(.server_uni, 0);
    _ = try streams.open(gpa, false);
    try testing.expectError(
        error.StreamStateError,
        streams.receiveStream(gpa, ours, 0, "x", false),
    );
    try testing.expectError(error.StreamStateError, streams.receiveReset(gpa, ours, 0, 0));

    // And the reverse: a client's unidirectional stream cannot be told to stop
    // sending by us... but it *can* be, that is what STOP_SENDING is for. What
    // cannot happen is the peer granting us credit on it, since we never write.
    const theirs = Id.make(.client_uni, 0);
    try streams.receiveStream(gpa, theirs, 0, "x", false);
    try testing.expectError(
        error.StreamStateError,
        streams.receiveMaxStreamData(gpa, theirs, 500),
    );
    try testing.expectError(
        error.StreamStateError,
        streams.receiveStopSending(gpa, theirs, 0),
    );
}

test "streams: a frame for a locally initiated stream we never opened is refused" {
    // §3.2. The peer cannot know about a stream we have not created, so this is
    // either confusion or an attempt to make us allocate one.
    const gpa = testing.allocator;
    var streams: Streams = .init(.client, testConfig());
    defer streams.deinit(gpa);

    const never = Id.make(.client_bidi, 5);
    try testing.expectError(
        error.StreamStateError,
        streams.receiveStream(gpa, never, 0, "x", false),
    );
    try testing.expectEqual(@as(usize, 0), streams.count());

    // Once we have opened it, the same frame is fine.
    var i: usize = 0;
    while (i < 3) : (i += 1) _ = try streams.open(gpa, true);
    try streams.receiveMaxStreams(true, 10);
    while (i < 6) : (i += 1) _ = try streams.open(gpa, true);
    try streams.receiveStream(gpa, never, 0, "x", false);
    try testing.expectEqualStrings("x", streams.get(never).?.recv.?.readable());
}

test "streams: §18.2's three per-stream limits are not interchangeable" {
    // Getting these backwards produces a sender that stalls at the wrong offset,
    // or one that overruns and gets closed by a correct peer — and both look like
    // "it mostly works".
    const gpa = testing.allocator;
    var config = testConfig();
    config.peer_max_stream_data_bidi_local = 111;
    config.peer_max_stream_data_bidi_remote = 222;
    config.peer_max_stream_data_uni = 333;
    var streams: Streams = .init(.client, config);
    defer streams.deinit(gpa);

    // A stream we opened is *remote* from the peer's point of view, so the peer's
    // `bidi_remote` limit governs what we may send on it.
    const ours = try streams.open(gpa, true);
    try testing.expectEqual(@as(u64, 222), streams.get(ours).?.send.?.max_data);

    // A stream the peer opened is local to it, so `bidi_local` governs.
    const theirs = Id.make(.server_bidi, 0);
    try streams.receiveStream(gpa, theirs, 0, "x", false);
    try testing.expectEqual(@as(u64, 111), streams.get(theirs).?.send.?.max_data);

    // And a unidirectional stream we opened uses the third value.
    const uni = try streams.open(gpa, false);
    try testing.expectEqual(@as(u64, 333), streams.get(uni).?.send.?.max_data);
}

test "streams: writing is bounded by both levels of flow control" {
    const gpa = testing.allocator;
    var config = testConfig();
    config.peer_max_data = 700;
    config.peer_max_stream_data_bidi_remote = 500;
    var streams: Streams = .init(.client, config);
    defer streams.deinit(gpa);

    const a = try streams.open(gpa, true);
    const b = try streams.open(gpa, true);

    const payload: [1000]u8 = @splat('z');
    // The stream's own limit truncates the first write.
    try testing.expectEqual(@as(usize, 500), try streams.write(gpa, a, &payload));
    try testing.expectEqual(@as(usize, 0), try streams.write(gpa, a, &payload));

    // The connection's limit truncates the second, even though that stream has
    // its whole window free. A short write is flow control, not failure.
    try testing.expectEqual(@as(usize, 200), try streams.write(gpa, b, &payload));
    try testing.expect(streams.isBlocked());
    try testing.expectEqual(@as(usize, 0), try streams.write(gpa, b, &payload));

    // MAX_DATA unblocks the connection; a value that does not increase is ignored.
    streams.receiveMaxData(600);
    try testing.expect(streams.isBlocked());
    streams.receiveMaxData(1200);
    try testing.expect(!streams.isBlocked());
    try testing.expectEqual(@as(usize, 300), try streams.write(gpa, b, &payload));
}

test "streams: MAX_DATA and MAX_STREAMS are sent only when they would say something" {
    const gpa = testing.allocator;
    var config = testConfig();
    config.local_max_data = 1_000;
    config.local_max_stream_data = 1_000;
    var streams: Streams = .init(.server, config);
    defer streams.deinit(gpa);

    try testing.expect(streams.maxDataUpdate() == null);

    const payload: [600]u8 = @splat('q');
    const id = Id.make(.client_bidi, 0);
    try streams.receiveStream(gpa, id, 0, &payload, false);
    // Received but not read: the receiver has nowhere to put more, so no credit.
    try testing.expect(streams.maxDataUpdate() == null);

    streams.consume(gpa, id, 600);
    try testing.expectEqual(@as(?u64, 1600), streams.maxDataUpdate());
    streams.applyMaxDataSent(1600);
    try testing.expect(streams.maxDataUpdate() == null);

    // §4.6: the stream limit rises as streams close, keeping the number available
    // roughly constant. `remote_opened` is cumulative because the credit is.
    var counts: Streams = .init(.server, config);
    defer counts.deinit(gpa);
    try testing.expect(counts.maxStreamsUpdate(true) == null);

    var index: u64 = 0;
    while (index < 4) : (index += 1) {
        const each = Id.make(.client_bidi, index);
        try counts.receiveStream(gpa, each, 0, "x", true);
        counts.consume(gpa, each, 1);
        _ = try counts.get(each).?.send.?.abandon(0);
        counts.get(each).?.send.?.markAcked(0, true);
        counts.reapIfFinished(gpa, each);
    }
    try testing.expectEqual(@as(usize, 0), counts.count());
    // Four opened, none live, initial budget four: the peer may now reach eight.
    try testing.expectEqual(@as(?u64, 8), counts.maxStreamsUpdate(true));
    counts.applyMaxStreamsSent(true, 8);
    try testing.expect(counts.maxStreamsUpdate(true) == null);
    // And the raised limit is honoured.
    try counts.receiveStream(gpa, Id.make(.client_bidi, 7), 0, "x", false);
}

test "streams: the number held at once is bounded regardless of the advertised limit" {
    // A compile-time ceiling separate from what we advertise, for the same reason
    // cid.zig has one: the advertised value is a promise to the peer, and a promise
    // cannot be allowed to allocate.
    const gpa = testing.allocator;
    var config = testConfig();
    config.local_max_streams_bidi = max_concurrent * 4;
    var streams: Streams = .init(.server, config);
    defer streams.deinit(gpa);

    try testing.expectError(
        error.StreamLimitError,
        streams.receiveStream(gpa, Id.make(.client_bidi, max_concurrent), 0, "x", false),
    );
    try testing.expectEqual(@as(usize, 0), streams.count());

    // Exactly at the ceiling is allowed.
    try streams.receiveStream(gpa, Id.make(.client_bidi, max_concurrent - 1), 0, "x", false);
    try testing.expectEqual(@as(usize, max_concurrent), streams.count());
}

test "streams: transport parameters replace the placeholder limits" {
    // Until the handshake completes the peer's limits are unknown, and unknown
    // must mean zero rather than generous — a client that assumed a window would
    // overrun a server that granted none.
    const gpa = testing.allocator;
    var streams: Streams = .init(.client, .{
        .local_max_data = 1000,
        .local_max_stream_data = 100,
        .local_max_streams_bidi = 2,
        .local_max_streams_uni = 2,
    });
    defer streams.deinit(gpa);

    try testing.expect(!streams.canOpen(true));
    try testing.expectEqual(@as(u64, 0), streams.send_max_data);

    var params: transport.Parameters = .{
        .initial_max_data = 5000,
        .initial_max_stream_data_bidi_remote = 900,
        .initial_max_streams_bidi = 3,
    };
    streams.applyPeerParameters(&params);

    try testing.expect(streams.canOpen(true));
    try testing.expectEqual(@as(u64, 5000), streams.send_max_data);
    const id = try streams.open(gpa, true);
    try testing.expectEqual(@as(u64, 900), streams.get(id).?.send.?.max_data);
}
