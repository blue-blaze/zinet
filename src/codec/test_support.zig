//! Shared scaffolding for codec tests.
//!
//! Codecs are exercised without sockets: a pipeline is wired to a recording
//! sink, bytes are fired in with `Pipeline.fireRead`, and decoded messages are
//! captured by a collector handler at the tail. Only test code references this
//! file, so nothing here ends up in a release build.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const pipeline_mod = @import("../pipeline.zig");

const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;

/// Captures every byte written towards the socket.
pub const RecordingSink = struct {
    gpa: Allocator,
    written: std.ArrayList(u8) = .empty,
    flushes: usize = 0,
    closes: usize = 0,

    pub fn sink(self: *RecordingSink) Sink {
        return .{ .context = self, .vtable = &.{
            .write = writeImpl,
            .flush = flushImpl,
            .close = closeImpl,
        } };
    }

    fn writeImpl(context: *anyopaque, msg: Message) pipeline_mod.Error!void {
        const self: *RecordingSink = @ptrCast(@alignCast(context));
        var owned = msg;
        defer owned.deinit(self.gpa);
        try self.written.appendSlice(self.gpa, owned.bytes() orelse "");
    }

    fn flushImpl(context: *anyopaque) pipeline_mod.Error!void {
        const self: *RecordingSink = @ptrCast(@alignCast(context));
        self.flushes += 1;
    }

    fn closeImpl(context: *anyopaque) pipeline_mod.Error!void {
        const self: *RecordingSink = @ptrCast(@alignCast(context));
        self.closes += 1;
    }

    pub fn deinit(self: *RecordingSink) void {
        self.written.deinit(self.gpa);
    }
};

/// Collects inbound messages at the tail of the pipeline so a test can assert
/// on what a decoder produced. Owns copies of the bytes it sees.
pub const Collector = struct {
    gpa: Allocator,
    messages: std.ArrayList([]u8) = .empty,
    /// Non-byte messages, recorded by type name only.
    others: std.ArrayList([]const u8) = .empty,
    errors: std.ArrayList(anyerror) = .empty,
    events: usize = 0,

    pub fn onRead(
        self: *Collector,
        ctx: *HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        if (owned.bytes()) |bytes| {
            try self.messages.append(self.gpa, try self.gpa.dupe(u8, bytes));
        } else {
            try self.others.append(self.gpa, owned.typeName());
        }
    }

    pub fn onError(self: *Collector, _: *HandlerContext, err: anyerror) void {
        self.errors.append(self.gpa, err) catch {};
    }

    pub fn onEvent(
        self: *Collector,
        ctx: *HandlerContext,
        event: pipeline_mod.Event,
    ) pipeline_mod.Error!void {
        self.events += 1;
        ctx.fireEvent(event);
    }

    pub fn deinit(self: *Collector, gpa: Allocator) void {
        for (self.messages.items) |item| gpa.free(item);
        self.messages.deinit(gpa);
        self.others.deinit(gpa);
        self.errors.deinit(gpa);
    }

    /// Concatenation of every collected byte message, for tests that only care
    /// about the total.
    pub fn joined(self: *const Collector, gpa: Allocator) Allocator.Error![]u8 {
        var total: usize = 0;
        for (self.messages.items) |item| total += item.len;
        const out = try gpa.alloc(u8, total);
        var offset: usize = 0;
        for (self.messages.items) |item| {
            @memcpy(out[offset..][0..item.len], item);
            offset += item.len;
        }
        return out;
    }
};

/// A pipeline with a recording sink, ready for a codec under test.
pub const Fixture = struct {
    gpa: Allocator,
    threaded: *Io.Threaded,
    sink_impl: *RecordingSink,
    pipeline: *Pipeline,
    collector: ?*Collector = null,

    pub fn init(gpa: Allocator) !Fixture {
        const threaded = try gpa.create(Io.Threaded);
        threaded.* = .init(gpa, .{});
        errdefer {
            threaded.deinit();
            gpa.destroy(threaded);
        }

        const sink_impl = try gpa.create(RecordingSink);
        sink_impl.* = .{ .gpa = gpa };
        errdefer gpa.destroy(sink_impl);

        const pipeline = try Pipeline.create(.{
            .gpa = gpa,
            .io = threaded.io(),
            .sink = sink_impl.sink(),
        });
        return .{
            .gpa = gpa,
            .threaded = threaded,
            .sink_impl = sink_impl,
            .pipeline = pipeline,
        };
    }

    pub fn deinit(fixture: *Fixture) void {
        fixture.pipeline.destroy();
        if (fixture.collector) |collector| {
            collector.deinit(fixture.gpa);
            fixture.gpa.destroy(collector);
        }
        fixture.sink_impl.deinit();
        fixture.gpa.destroy(fixture.sink_impl);
        fixture.threaded.deinit();
        fixture.gpa.destroy(fixture.threaded);
    }

    /// Installs a codec using its pipeline-building function.
    pub fn addCodec(
        fixture: *Fixture,
        comptime build: fn (pipeline: *Pipeline) anyerror!void,
    ) !void {
        try build(fixture.pipeline);
    }

    /// Appends a collector at the tail and returns it. The fixture owns it.
    pub fn addCollector(fixture: *Fixture) !*Collector {
        std.debug.assert(fixture.collector == null);
        const collector = try fixture.gpa.create(Collector);
        collector.* = .{ .gpa = fixture.gpa };
        errdefer fixture.gpa.destroy(collector);
        _ = try fixture.pipeline.addLast("collector", .init(collector));
        fixture.collector = collector;
        return collector;
    }

    /// Bytes that reached the sink.
    pub fn written(fixture: *const Fixture) []const u8 {
        return fixture.sink_impl.written.items;
    }

    pub fn clearWritten(fixture: *Fixture) void {
        fixture.sink_impl.written.clearRetainingCapacity();
    }
};
