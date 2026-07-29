//! Values that travel through a pipeline.
//!
//! Netty passes `Object` along its pipeline and relies on `instanceof` plus
//! reference counting to sort out types and lifetimes. Zinet uses a tagged
//! union instead, so the common cases (owned bytes, shared bytes) are checked
//! by the compiler, and reserves a single type-erased variant for protocol
//! objects such as an HTTP request.
//!
//! # Ownership
//!
//! A `Message` **owns** its payload. Passing a message to a function transfers
//! that ownership: the callee must either forward it onwards or release it with
//! `deinit`. This is the single rule that keeps the pipeline leak free, and it
//! is restated at every API that accepts a `Message`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("buffer.zig").Buffer;
const SharedBuffer = @import("pool.zig").SharedBuffer;

/// Identity of a Zig type at run time.
///
/// `@typeName` yields a distinct, fully qualified string per type, and the
/// compiler interns it, so comparing the string's address is a sound and
/// allocation-free type check.
pub const TypeId = [*:0]const u8;

pub fn typeId(comptime T: type) TypeId {
    return @typeName(T).ptr;
}

/// A payload of any type, owned by the message that holds it.
///
/// Created by `Message.initAny`, which heap-allocates the value so it can
/// outlive the stack frame that produced it — a `Message` is routinely handed
/// to another task, so referring to caller stack memory would be a
/// use-after-return.
pub const Any = struct {
    ptr: *anyopaque,
    id: TypeId,
    /// Releases the payload and its allocation.
    destroyFn: *const fn (ptr: *anyopaque, gpa: Allocator) void,

    pub fn name(any: Any) []const u8 {
        return std.mem.span(any.id);
    }
};

/// A unit of data flowing through a pipeline.
pub const Message = union(enum) {
    /// Bytes owned outright by this message.
    buffer: Buffer,
    /// A window into reference counted bytes shared with other messages.
    view: SharedBuffer.View,
    /// A protocol object of a type the core framework knows nothing about.
    any: Any,

    /// Wraps `owned` (ownership transferred; the source is left empty).
    pub fn initBuffer(owned: *Buffer) Message {
        return .{ .buffer = owned.move() };
    }

    /// Copies `bytes` into a newly allocated buffer.
    pub fn initBytes(gpa: Allocator, source: []const u8) Buffer.Error!Message {
        var owned = try Buffer.initFrom(gpa, source, .{});
        return .{ .buffer = owned.move() };
    }

    /// Wraps `view` (ownership of its reference transferred).
    pub fn initView(view: SharedBuffer.View) Message {
        return .{ .view = view };
    }

    /// Moves `value` to the heap and wraps it as a type-erased payload.
    ///
    /// When the message is released, `T.deinit(&value, gpa)` is called if `T`
    /// declares it, and the allocation is freed.
    pub fn initAny(gpa: Allocator, comptime T: type, value: T) Allocator.Error!Message {
        const boxed = try gpa.create(T);
        boxed.* = value;
        return .{ .any = .{
            .ptr = boxed,
            .id = typeId(T),
            .destroyFn = destroyAny(T),
        } };
    }

    fn destroyAny(comptime T: type) *const fn (ptr: *anyopaque, gpa: Allocator) void {
        return struct {
            fn destroy(ptr: *anyopaque, gpa: Allocator) void {
                const boxed: *T = @ptrCast(@alignCast(ptr));
                if (@hasDecl(T, "deinit")) boxed.deinit(gpa);
                gpa.destroy(boxed);
            }
        }.destroy;
    }

    /// Releases the payload. Call exactly once per message.
    pub fn deinit(message: *Message, gpa: Allocator) void {
        switch (message.*) {
            .buffer => |*owned| owned.deinit(gpa),
            .view => |*window| window.release(),
            .any => |any| any.destroyFn(any.ptr, gpa),
        }
        message.* = undefined;
    }

    /// Transfers ownership out of `message`.
    ///
    /// The source is left holding an empty buffer rather than `undefined`, so a
    /// stray `deinit` on it is a no-op instead of a use-after-free. This
    /// mirrors `Buffer.move` and removes a whole class of ownership bug from
    /// handler code, where a `defer deinit` and a forward often coexist.
    pub fn move(message: *Message) Message {
        const moved = message.*;
        message.* = .{ .buffer = .empty };
        return moved;
    }

    /// The readable bytes of a byte-oriented message, or `null` for a
    /// type-erased payload.
    pub fn bytes(message: *const Message) ?[]const u8 {
        return switch (message.*) {
            .buffer => |*owned| owned.readableSlice(),
            .view => |window| window.bytes(),
            .any => null,
        };
    }

    /// Number of readable bytes, or zero for a type-erased payload.
    pub fn len(message: *const Message) usize {
        return if (message.bytes()) |slice| slice.len else 0;
    }

    /// Borrows the payload as `*T` when the message holds a `T`.
    ///
    /// Ownership stays with the message.
    pub fn get(message: *const Message, comptime T: type) ?*T {
        switch (message.*) {
            .any => |any| {
                if (any.id != typeId(T)) return null;
                return @ptrCast(@alignCast(any.ptr));
            },
            else => return null,
        }
    }

    /// Moves a `T` payload out of the message, releasing the box.
    ///
    /// Returns `null` — and leaves the message untouched — when it holds
    /// something else. On success the message is left empty, so a deferred
    /// `deinit` remains safe.
    pub fn take(message: *Message, gpa: Allocator, comptime T: type) ?T {
        switch (message.*) {
            .any => |any| {
                if (any.id != typeId(T)) return null;
                const boxed: *T = @ptrCast(@alignCast(any.ptr));
                const value = boxed.*;
                gpa.destroy(boxed);
                message.* = .{ .buffer = .empty };
                return value;
            },
            else => return null,
        }
    }

    /// Human-readable payload type, for diagnostics.
    pub fn typeName(message: *const Message) []const u8 {
        return switch (message.*) {
            .buffer => "buffer",
            .view => "view",
            .any => |any| any.name(),
        };
    }
};

/// A notification with no payload data of its own, used for out-of-band
/// signalling between handlers (Netty's "user event").
///
/// Unlike `Message`, an `Event` is **borrowed**: the code that fires it owns
/// the value for the duration of the call. Handlers must not retain the
/// pointer past the callback. This keeps signalling allocation free.
pub const Event = struct {
    ptr: *const anyopaque,
    id: TypeId,

    pub fn init(value: anytype) Event {
        const Pointer = @TypeOf(value);
        const info = @typeInfo(Pointer);
        comptime assert(info == .pointer and info.pointer.size == .one);
        return .{ .ptr = value, .id = typeId(info.pointer.child) };
    }

    /// Borrows the event payload when it is a `T`.
    pub fn get(event: Event, comptime T: type) ?*const T {
        if (event.id != typeId(T)) return null;
        return @ptrCast(@alignCast(event.ptr));
    }

    pub fn is(event: Event, comptime T: type) bool {
        return event.id == typeId(T);
    }

    pub fn name(event: Event) []const u8 {
        return std.mem.span(event.id);
    }
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "Message: buffer variant owns its bytes" {
    const gpa = testing.allocator;
    var message = try Message.initBytes(gpa, "payload");
    defer message.deinit(gpa);

    try testing.expectEqualStrings("payload", message.bytes().?);
    try testing.expectEqual(@as(usize, 7), message.len());
    try testing.expectEqualStrings("buffer", message.typeName());
}

test "Message: initBuffer empties the source buffer" {
    const gpa = testing.allocator;
    var owned = try Buffer.initFrom(gpa, "moved", .{});
    var message = Message.initBuffer(&owned);
    defer message.deinit(gpa);

    owned.deinit(gpa); // Must not double free.
    try testing.expectEqualStrings("moved", message.bytes().?);
}

test "Message: view variant holds a reference for its lifetime" {
    const gpa = testing.allocator;
    const shared = try SharedBuffer.createFrom(gpa, "0123456789");

    var message = Message.initView(try shared.view(2, 4));
    try testing.expectEqual(@as(u32, 2), shared.referenceCount());
    shared.release();

    try testing.expectEqualStrings("2345", message.bytes().?);
    try testing.expectEqualStrings("view", message.typeName());
    message.deinit(gpa);
}

test "Message: any variant round trips a typed payload" {
    const gpa = testing.allocator;
    const Ping = struct { sequence: u64 };

    var message = try Message.initAny(gpa, Ping, .{ .sequence = 42 });
    defer message.deinit(gpa);

    try testing.expect(message.bytes() == null);
    try testing.expectEqual(@as(usize, 0), message.len());
    try testing.expectEqual(@as(u64, 42), message.get(Ping).?.sequence);

    const Pong = struct { sequence: u64 };
    try testing.expect(message.get(Pong) == null); // Distinct type, same shape.
}

test "Message: any variant releases nested resources through deinit" {
    const gpa = testing.allocator;
    const Request = struct {
        body: []u8,

        pub fn deinit(request: *@This(), allocator: Allocator) void {
            allocator.free(request.body);
        }
    };

    var message = try Message.initAny(gpa, Request, .{
        .body = try gpa.dupe(u8, "nested allocation"),
    });
    try testing.expectEqualStrings("nested allocation", message.get(Request).?.body);
    message.deinit(gpa); // Frees `body` too; the leak checker proves it.
}

test "Message: take moves the payload out and frees the box" {
    const gpa = testing.allocator;
    const Frame = struct { opcode: u8 };

    var message = try Message.initAny(gpa, Frame, .{ .opcode = 0x1 });
    const frame = message.take(gpa, Frame).?;
    try testing.expectEqual(@as(u8, 0x1), frame.opcode);

    var other = try Message.initBytes(gpa, "bytes");
    defer other.deinit(gpa);
    try testing.expect(other.take(gpa, Frame) == null); // Wrong variant, untouched.
    try testing.expectEqualStrings("bytes", other.bytes().?);
}

test "Message: move transfers ownership and leaves the source releasable" {
    const gpa = testing.allocator;
    var message = try Message.initBytes(gpa, "transfer");
    var moved = message.move();
    defer moved.deinit(gpa);
    try testing.expectEqualStrings("transfer", moved.bytes().?);

    // Releasing the moved-from message must be harmless: handler code routinely
    // arms a `defer deinit` and then forwards ownership onwards.
    message.deinit(gpa);
}

test "Message: take leaves the source releasable" {
    const gpa = testing.allocator;
    const Frame = struct { opcode: u8 };
    var message = try Message.initAny(gpa, Frame, .{ .opcode = 0x2 });
    const frame = message.take(gpa, Frame).?;
    try testing.expectEqual(@as(u8, 0x2), frame.opcode);
    message.deinit(gpa);
}

test "Event: borrowed payload is matched by type" {
    const Upgraded = struct { protocol: []const u8 };
    const Closed = struct {};

    const upgraded: Upgraded = .{ .protocol = "websocket" };
    const event = Event.init(&upgraded);

    try testing.expect(event.is(Upgraded));
    try testing.expect(!event.is(Closed));
    try testing.expectEqualStrings("websocket", event.get(Upgraded).?.protocol);
    try testing.expect(event.get(Closed) == null);
    try testing.expect(std.mem.endsWith(u8, event.name(), "Upgraded"));
}
