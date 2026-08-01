//! A channel with no socket, for testing pipelines and handlers.
//!
//! Netty's `EmbeddedChannel`, and for the same reason: the interesting part of a
//! protocol implementation is what the pipeline does with bytes, and attaching
//! that to a real socket to find out makes the test slower, flakier and worse at
//! saying what went wrong. Everything in `src/codec` is tested through this.
//!
//! ```zig
//! var channel: zinet.EmbeddedChannel = undefined;
//! try channel.init(gpa, io, .initFunction(buildMyCodec));
//! defer channel.deinit();
//!
//! try channel.writeInbound(try Message.initBytes(gpa, "GET / HTTP/1.1\r\n\r\n"));
//! var request = channel.readInbound().?;   // whatever the decoder produced
//! defer request.deinit(gpa);
//! ```
//!
//! Two things about the design are worth knowing, because they are what the
//! obvious version gets wrong:
//!
//! **Outbound messages keep their type.** A recorder that turned everything into
//! bytes would make the middle of a pipeline untestable: an encoder whose output
//! is another handler's input — `http2.OutgoingHeaders` reaching the multiplexer,
//! a `Datagram` reaching an endpoint — produces no bytes at all, and asserting on
//! "nothing was written" is not the same as asserting on what it wrote.
//! `readOutbound` therefore hands back the `Message`, and `outboundBytes` is the
//! convenience for the common case.
//!
//! **`finish` reports what nobody read.** A test that asserts on the first two
//! messages and ignores a third is a test that passes while the codec emits
//! nonsense. `finish` returns the count left over so a test can insist it is
//! zero, which is the assertion most tests actually want and none of them would
//! write by hand.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const pipeline_mod = @import("pipeline.zig");
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;
const HandlerContext = pipeline_mod.HandlerContext;
const Event = pipeline_mod.Event;
const Message = @import("message.zig").Message;
const Initializer = @import("channel.zig").Initializer;

pub const Error = pipeline_mod.Error;

/// Everything the channel saw, in order.
pub const Record = struct {
    /// Messages that reached the sink, oldest first. Ownership passes to whoever
    /// calls `readOutbound`.
    outbound: std.ArrayList(Message) = .empty,
    /// Messages that reached the tail, oldest first.
    inbound: std.ArrayList(Message) = .empty,
    /// How many times the pipeline flushed, and how many times it closed.
    flushes: usize = 0,
    closes: usize = 0,
    /// Errors that travelled to the tail. A pipeline whose handler failed and
    /// whose test did not notice is a test that proved nothing, so these are
    /// recorded rather than logged.
    errors: std.ArrayList(anyerror) = .empty,
    /// Events that reached the tail, by type name — the event itself is borrowed
    /// for the callback's duration and must not be retained.
    events: std.ArrayList([]const u8) = .empty,
    active: bool = false,
    inactive: bool = false,
    read_completes: usize = 0,

    fn deinit(self: *Record, gpa: Allocator) void {
        for (self.outbound.items) |*message| message.deinit(gpa);
        self.outbound.deinit(gpa);
        for (self.inbound.items) |*message| message.deinit(gpa);
        self.inbound.deinit(gpa);
        self.errors.deinit(gpa);
        self.events.deinit(gpa);
    }
};

pub const EmbeddedChannel = struct {
    gpa: Allocator,
    io: Io,
    pipeline: *Pipeline,
    record: Record = .{},

    /// Initialised in place rather than returned by value: the sink holds this
    /// struct's address, so moving it after construction would leave the pipeline
    /// writing into a stale one.
    pub fn init(self: *EmbeddedChannel, gpa: Allocator, io: Io, initializer: ?Initializer) !void {
        self.* = .{ .gpa = gpa, .io = io, .pipeline = undefined };
        self.pipeline = try Pipeline.create(.{
            .gpa = gpa,
            .io = io,
            .sink = self.sink(),
            .owner = self,
        });
        errdefer self.pipeline.destroy();

        // The application's handlers first, then the tail — which is the *last*
        // thing an inbound message reaches and therefore where a decoder's output
        // lands. Adding the tail first puts it upstream of the codec, so it
        // catches raw bytes and the codec never sees them: the mistake produces a
        // channel that appears to work and reports one message where there should
        // be three.
        if (initializer) |init_fn| {
            try init_fn.initFn(init_fn.context, self.pipeline);
        }

        const tail = try gpa.create(Tail);
        tail.* = .{ .channel = self };
        errdefer gpa.destroy(tail);
        _ = try self.pipeline.addLast("embedded-tail", .initOwned(tail));
    }

    /// Frees the pipeline and anything the channel is still holding.
    pub fn deinit(self: *EmbeddedChannel) void {
        self.pipeline.destroy();
        self.record.deinit(self.gpa);
        self.* = undefined;
    }

    // ── Driving the pipeline ────────────────────────────────────────────────

    /// Fire a message inbound, as a socket read would.
    pub fn writeInbound(self: *EmbeddedChannel, message: Message) void {
        self.pipeline.fireRead(message);
    }

    /// Fire bytes inbound. The common case, and it copies — the pipeline owns
    /// what it is given.
    pub fn writeInboundBytes(self: *EmbeddedChannel, bytes: []const u8) !void {
        self.pipeline.fireRead(try Message.initBytes(self.gpa, bytes));
    }

    /// Feed bytes inbound in fixed-size pieces.
    ///
    /// This exists because the single most valuable property a stream decoder has
    /// is that its output does not depend on how its input was chopped up, and
    /// the only way to check that is to chop it up. Four real defects in this
    /// repository were found this way.
    pub fn writeInboundChunked(self: *EmbeddedChannel, bytes: []const u8, chunk: usize) !void {
        assert(chunk > 0);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const take = @min(chunk, bytes.len - offset);
            try self.writeInboundBytes(bytes[offset..][0..take]);
            offset += take;
        }
    }

    /// Write a message outbound from the tail, as a handler would.
    pub fn writeOutbound(self: *EmbeddedChannel, message: Message) Error!void {
        return self.pipeline.write(message);
    }

    pub fn flush(self: *EmbeddedChannel) Error!void {
        return self.pipeline.flush();
    }

    pub fn fireActive(self: *EmbeddedChannel) void {
        self.pipeline.fireActive();
    }

    pub fn fireInactive(self: *EmbeddedChannel) void {
        self.pipeline.fireInactive();
    }

    pub fn fireReadComplete(self: *EmbeddedChannel) void {
        self.pipeline.fireReadComplete();
    }

    pub fn fireEvent(self: *EmbeddedChannel, event: Event) void {
        self.pipeline.fireEvent(event);
    }

    pub fn fireError(self: *EmbeddedChannel, err: anyerror) void {
        self.pipeline.fireError(err);
    }

    // ── Reading what happened ───────────────────────────────────────────────

    /// The oldest message that reached the tail, ownership passed to the caller,
    /// or null.
    pub fn readInbound(self: *EmbeddedChannel) ?Message {
        if (self.record.inbound.items.len == 0) return null;
        return self.record.inbound.orderedRemove(0);
    }

    /// The oldest message that reached the sink, ownership passed to the caller.
    pub fn readOutbound(self: *EmbeddedChannel) ?Message {
        if (self.record.outbound.items.len == 0) return null;
        return self.record.outbound.orderedRemove(0);
    }

    /// Every outbound byte so far, concatenated, without consuming anything.
    ///
    /// Non-byte messages are skipped rather than an error: a pipeline that emits
    /// both — an encoder that writes a header message and then raw body bytes —
    /// is a normal shape, and a test asking for bytes wants the bytes.
    pub fn outboundBytes(self: *EmbeddedChannel, gpa: Allocator) Allocator.Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        for (self.record.outbound.items) |message| {
            if (message.bytes()) |bytes| try out.appendSlice(gpa, bytes);
        }
        return out.toOwnedSlice(gpa);
    }

    /// Drops every outbound message recorded so far, so a test can assert on one
    /// exchange at a time.
    pub fn clearOutbound(self: *EmbeddedChannel) void {
        for (self.record.outbound.items) |*message| message.deinit(self.gpa);
        self.record.outbound.clearRetainingCapacity();
    }

    pub fn inboundCount(self: *const EmbeddedChannel) usize {
        return self.record.inbound.items.len;
    }

    pub fn outboundCount(self: *const EmbeddedChannel) usize {
        return self.record.outbound.items.len;
    }

    pub fn flushCount(self: *const EmbeddedChannel) usize {
        return self.record.flushes;
    }

    pub fn closeCount(self: *const EmbeddedChannel) usize {
        return self.record.closes;
    }

    /// Errors that reached the tail.
    pub fn errorSlice(self: *const EmbeddedChannel) []const anyerror {
        return self.record.errors.items;
    }

    /// Type names of events that reached the tail.
    pub fn eventNames(self: *const EmbeddedChannel) []const []const u8 {
        return self.record.events.items;
    }

    pub fn isActive(self: *const EmbeddedChannel) bool {
        return self.record.active and !self.record.inactive;
    }

    /// End the channel and report how many messages nobody read.
    ///
    /// Fires `onInactive` first, because a codec with buffered state may emit on
    /// the way down — an HTTP decoder finishing a body delimited by
    /// connection close, a WebSocket handler sending its closing frame. A test
    /// that stopped before this would miss it.
    ///
    /// The return value is what makes this more than a teardown: a test that
    /// checked the first two messages and ignored a third would otherwise pass
    /// while the codec produced nonsense.
    pub fn finish(self: *EmbeddedChannel) Leftover {
        if (!self.record.inactive) self.pipeline.fireInactive();
        return .{
            .inbound = self.record.inbound.items.len,
            .outbound = self.record.outbound.items.len,
        };
    }

    pub const Leftover = struct {
        inbound: usize,
        outbound: usize,

        /// Whether every message the channel produced was read.
        pub fn isEmpty(self: Leftover) bool {
            return self.inbound == 0 and self.outbound == 0;
        }
    };

    // ── The sink and the tail handler ───────────────────────────────────────

    fn sink(self: *EmbeddedChannel) Sink {
        return .{ .context = self, .vtable = &sink_vtable };
    }

    const sink_vtable: Sink.VTable = .{
        .write = sinkWrite,
        .flush = sinkFlush,
        .close = sinkClose,
    };

    /// Consumes the message unconditionally, including on failure — the contract
    /// every `Sink` in this codebase holds to. Here "consuming" means keeping it,
    /// which is the whole point.
    fn sinkWrite(context: *anyopaque, message: Message) Error!void {
        const self: *EmbeddedChannel = @ptrCast(@alignCast(context));
        var owned = message;
        self.record.outbound.append(self.gpa, owned) catch {
            owned.deinit(self.gpa);
            return error.OutOfMemory;
        };
    }

    fn sinkFlush(context: *anyopaque) Error!void {
        const self: *EmbeddedChannel = @ptrCast(@alignCast(context));
        self.record.flushes += 1;
    }

    fn sinkClose(context: *anyopaque) Error!void {
        const self: *EmbeddedChannel = @ptrCast(@alignCast(context));
        self.record.closes += 1;
    }

    /// The handler at the tail: catches whatever the pipeline delivers.
    const Tail = struct {
        channel: *EmbeddedChannel,

        pub fn onRead(self: *Tail, ctx: *HandlerContext, message: Message) !void {
            _ = ctx;
            var owned = message;
            self.channel.record.inbound.append(self.channel.gpa, owned) catch {
                owned.deinit(self.channel.gpa);
                return error.OutOfMemory;
            };
        }

        pub fn onActive(self: *Tail, ctx: *HandlerContext) !void {
            _ = ctx;
            self.channel.record.active = true;
        }

        pub fn onInactive(self: *Tail, ctx: *HandlerContext) !void {
            _ = ctx;
            self.channel.record.inactive = true;
        }

        pub fn onReadComplete(self: *Tail, ctx: *HandlerContext) !void {
            _ = ctx;
            self.channel.record.read_completes += 1;
        }

        pub fn onEvent(self: *Tail, ctx: *HandlerContext, event: Event) !void {
            _ = ctx;
            // Only the name: the event is borrowed for the callback's duration,
            // and retaining the pointer is the one thing the rules forbid.
            self.channel.record.events.append(self.channel.gpa, event.name()) catch {};
        }

        pub fn onError(self: *Tail, ctx: *HandlerContext, err: anyerror) void {
            _ = ctx;
            self.channel.record.errors.append(self.channel.gpa, err) catch {};
        }
    };
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const backend = @import("backend");
const Buffer = @import("buffer.zig").Buffer;

/// A codec that frames on newlines, so the tests have something with state.
const LineDecoder = struct {
    buffer: std.ArrayList(u8) = .empty,

    pub fn onRead(self: *LineDecoder, ctx: *HandlerContext, message: Message) !void {
        var owned = message;
        defer owned.deinit(ctx.gpa());
        const bytes = owned.bytes() orelse return;
        try self.buffer.appendSlice(ctx.gpa(), bytes);

        while (std.mem.indexOfScalar(u8, self.buffer.items, '\n')) |index| {
            const line = self.buffer.items[0..index];
            ctx.fireRead(try Message.initBytes(ctx.gpa(), line));
            const rest = self.buffer.items.len - index - 1;
            std.mem.copyForwards(u8, self.buffer.items[0..rest], self.buffer.items[index + 1 ..]);
            self.buffer.shrinkRetainingCapacity(rest);
        }
    }

    /// Outbound: append a newline, so the test can watch the encode direction.
    pub fn onWrite(self: *LineDecoder, ctx: *HandlerContext, message: Message) !void {
        _ = self;
        var owned = message;
        defer owned.deinit(ctx.gpa());
        const bytes = owned.bytes() orelse return;
        var out = try Buffer.initFrom(ctx.gpa(), bytes, .{});
        errdefer out.deinit(ctx.gpa());
        try out.writeBytes(ctx.gpa(), "\n");
        try ctx.write(Message.initBuffer(&out));
    }

    pub fn deinit(self: *LineDecoder, gpa: Allocator) void {
        self.buffer.deinit(gpa);
    }
};

fn buildLines(pipeline: *Pipeline) anyerror!void {
    const decoder = try pipeline.gpa.create(LineDecoder);
    decoder.* = .{};
    errdefer pipeline.gpa.destroy(decoder);
    _ = try pipeline.addLast("lines", .initOwned(decoder));
}

fn newChannel(gpa: Allocator, io: Io) !*EmbeddedChannel {
    const channel = try gpa.create(EmbeddedChannel);
    try channel.init(gpa, io, .initFunction(buildLines));
    return channel;
}

test "embedded: inbound bytes come out as decoded messages" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const channel = try newChannel(gpa, threaded.io());
    defer {
        channel.deinit();
        gpa.destroy(channel);
    }

    try channel.writeInboundBytes("first\nsecond\npartial");
    try testing.expectEqual(@as(usize, 2), channel.inboundCount());

    var first = channel.readInbound().?;
    defer first.deinit(gpa);
    try testing.expectEqualStrings("first", first.bytes().?);

    var second = channel.readInbound().?;
    defer second.deinit(gpa);
    try testing.expectEqualStrings("second", second.bytes().?);

    // The partial line is held by the decoder, not delivered.
    try testing.expect(channel.readInbound() == null);
    try channel.writeInboundBytes(" line\n");
    var third = channel.readInbound().?;
    defer third.deinit(gpa);
    try testing.expectEqualStrings("partial line", third.bytes().?);
}

test "embedded: chunked input produces the same messages as one write" {
    // The property that matters most for a stream decoder, and the reason
    // `writeInboundChunked` exists rather than each codec's tests writing it.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const input = "alpha\nbeta\ngamma\n";

    var whole: [3][]const u8 = undefined;
    {
        const channel = try newChannel(gpa, threaded.io());
        defer {
            channel.deinit();
            gpa.destroy(channel);
        }
        try channel.writeInboundBytes(input);
        for (&whole) |*slot| {
            var message = channel.readInbound().?;
            defer message.deinit(gpa);
            slot.* = try gpa.dupe(u8, message.bytes().?);
        }
    }
    defer for (whole) |piece| gpa.free(piece);

    // One byte at a time: every frame boundary falls in a different place.
    const channel = try newChannel(gpa, threaded.io());
    defer {
        channel.deinit();
        gpa.destroy(channel);
    }
    try channel.writeInboundChunked(input, 1);
    try testing.expectEqual(@as(usize, 3), channel.inboundCount());
    for (whole) |expected| {
        var message = channel.readInbound().?;
        defer message.deinit(gpa);
        try testing.expectEqualStrings(expected, message.bytes().?);
    }
    try testing.expect(channel.finish().isEmpty());
}

test "embedded: outbound messages keep their type and reach the sink encoded" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const channel = try newChannel(gpa, threaded.io());
    defer {
        channel.deinit();
        gpa.destroy(channel);
    }

    try channel.writeOutbound(try Message.initBytes(gpa, "hello"));
    try channel.flush();

    // The encoder ran: the newline is the codec's, not the test's.
    const bytes = try channel.outboundBytes(gpa);
    defer gpa.free(bytes);
    try testing.expectEqualStrings("hello\n", bytes);
    try testing.expectEqual(@as(usize, 1), channel.flushCount());

    // And the message itself is available rather than only its bytes, which is
    // what makes the middle of a pipeline testable.
    var message = channel.readOutbound().?;
    defer message.deinit(gpa);
    try testing.expectEqualStrings("hello\n", message.bytes().?);
    try testing.expectEqual(@as(usize, 0), channel.outboundCount());
}

test "embedded: finish reports messages nobody read" {
    // A test that asserts on some output and ignores the rest passes while the
    // codec emits nonsense. This is the assertion that catches it.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const channel = try newChannel(gpa, threaded.io());
    defer {
        channel.deinit();
        gpa.destroy(channel);
    }

    try channel.writeInboundBytes("one\ntwo\nthree\n");
    var only = channel.readInbound().?;
    only.deinit(gpa);

    const leftover = channel.finish();
    try testing.expect(!leftover.isEmpty());
    try testing.expectEqual(@as(usize, 2), leftover.inbound);
    try testing.expectEqual(@as(usize, 0), leftover.outbound);
}

test "embedded: lifecycle, events and errors are all observable" {
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    const channel = try newChannel(gpa, threaded.io());
    defer {
        channel.deinit();
        gpa.destroy(channel);
    }

    try testing.expect(!channel.isActive());
    channel.fireActive();
    try testing.expect(channel.isActive());

    const Marker = struct { value: u32 };
    var marker: Marker = .{ .value = 7 };
    channel.fireEvent(.init(&marker));
    try testing.expectEqual(@as(usize, 1), channel.eventNames().len);

    channel.fireError(error.SomethingBroke);
    try testing.expectEqual(@as(usize, 1), channel.errorSlice().len);
    try testing.expectEqual(anyerror.SomethingBroke, channel.errorSlice()[0]);

    channel.fireReadComplete();
    try testing.expectEqual(@as(usize, 1), channel.record.read_completes);

    _ = channel.finish();
    try testing.expect(!channel.isActive());
}

test "embedded: a channel with no codec passes messages straight through" {
    // The degenerate case, and worth checking: a pipeline of nothing but the tail
    // must still deliver inbound and still let outbound reach the sink.
    const gpa = testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    var channel: EmbeddedChannel = undefined;
    try channel.init(gpa, threaded.io(), null);
    defer channel.deinit();

    try channel.writeInboundBytes("raw");
    var inbound = channel.readInbound().?;
    defer inbound.deinit(gpa);
    try testing.expectEqualStrings("raw", inbound.bytes().?);

    try channel.writeOutbound(try Message.initBytes(gpa, "out"));
    const bytes = try channel.outboundBytes(gpa);
    defer gpa.free(bytes);
    try testing.expectEqualStrings("out", bytes);
}
