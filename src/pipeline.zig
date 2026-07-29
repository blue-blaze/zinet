//! The interception chain: Zinet's equivalent of Netty's `ChannelPipeline`.
//!
//! A pipeline is a doubly linked list of handlers with two directions of
//! travel:
//!
//! ```
//!                                      I/O request
//!                                          |
//!  +---------+  inbound  +---------+  ...  +---------+
//!  |  head   | --------> | codec   | ----> |  tail   |   inbound: head -> tail
//!  |         | <-------- |         | <---- |         |   outbound: tail -> head
//!  +---------+ outbound  +---------+  ...  +---------+
//!       |
//!    socket
//! ```
//!
//! Inbound events (a socket became readable, bytes arrived, the peer went
//! away) start at the head and travel towards the tail. Outbound requests
//! (write these bytes, flush, close) start at the tail and travel towards the
//! head, where they reach the `Sink` — the socket in production, a recorder in
//! tests.
//!
//! # Why a run-time vtable
//!
//! A comptime-composed chain would be faster, but protocol upgrades need to
//! rewrite the chain while it is running: a WebSocket handshake replaces the
//! HTTP codec with the WebSocket codec on the very read that completes the
//! handshake. That capability is the whole point of a pipeline, so the chain
//! is dynamic and dispatch goes through a vtable, exactly like
//! `std.mem.Allocator` and `std.Io`.
//!
//! # Ownership rules
//!
//! * A `Message` handed to `onRead` or `onWrite` is **owned** by the callee.
//!   Forward it (`ctx.fireRead`, `ctx.write`) to pass ownership on, or release
//!   it with `Message.deinit`. Doing neither leaks; doing both double frees.
//! * A callback that returns an error must have already disposed of the
//!   message it was given.
//! * A `Sink` always consumes the message it is given, including on failure.
//! * An `Event` is **borrowed** for the duration of the callback.
//! * A handler added with `Handler.initOwned` is destroyed by the pipeline.
//!   One added with `Handler.init` is not; its storage must outlive the
//!   pipeline.
//!
//! # Self-referential
//!
//! Handler contexts point back at their pipeline, so a `Pipeline` must not be
//! copied or moved once initialized. Initialize it in place at a stable
//! address (`Pipeline.init`) or on the heap (`Pipeline.create`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

const message_mod = @import("message.zig");

pub const Message = message_mod.Message;
pub const Event = message_mod.Event;

/// Error type of handler callbacks.
///
/// A pipeline accepts handlers written by anyone, including code that does not
/// exist yet, so the error set genuinely cannot be closed. Inbound failures are
/// converted into `onError` notifications rather than propagated to the caller,
/// which keeps `anyerror` from spreading into the framework's own signatures.
pub const Error = anyerror;

/// Terminal end of the outbound direction: where a write finally goes.
///
/// Implemented by `Channel` in production and by test doubles in unit tests,
/// which is what lets the pipeline be exercised with no sockets involved.
pub const Sink = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Consumes `message` unconditionally, including when it fails.
        write: *const fn (context: *anyopaque, message: Message) Error!void,
        flush: *const fn (context: *anyopaque) Error!void = noopFlush,
        close: *const fn (context: *anyopaque) Error!void = noopClose,

        fn noopFlush(_: *anyopaque) Error!void {}
        fn noopClose(_: *anyopaque) Error!void {}
    };

    pub fn write(sink: Sink, msg: Message) Error!void {
        return sink.vtable.write(sink.context, msg);
    }

    pub fn flush(sink: Sink) Error!void {
        return sink.vtable.flush(sink.context);
    }

    pub fn close(sink: Sink) Error!void {
        return sink.vtable.close(sink.context);
    }
};

/// A participant in the interception chain.
///
/// Rather than hand-rolling a vtable, build one from a struct type with
/// `Handler.init`: every optional callback the type declares is wired up, and
/// the rest default to "forward to the next handler".
pub const Handler = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Diagnostic name of the handler type.
        type_name: []const u8 = "handler",

        onAdded: ?*const fn (context: *anyopaque, ctx: *HandlerContext) Error!void = null,
        onRemoved: ?*const fn (context: *anyopaque, ctx: *HandlerContext) void = null,

        // Inbound.
        onActive: ?*const fn (context: *anyopaque, ctx: *HandlerContext) Error!void = null,
        onInactive: ?*const fn (context: *anyopaque, ctx: *HandlerContext) Error!void = null,
        onRead: ?*const fn (context: *anyopaque, ctx: *HandlerContext, msg: Message) Error!void = null,
        onReadComplete: ?*const fn (context: *anyopaque, ctx: *HandlerContext) Error!void = null,
        onEvent: ?*const fn (context: *anyopaque, ctx: *HandlerContext, event: Event) Error!void = null,
        onError: ?*const fn (context: *anyopaque, ctx: *HandlerContext, err: Error) void = null,

        // Outbound.
        onWrite: ?*const fn (context: *anyopaque, ctx: *HandlerContext, msg: Message) Error!void = null,
        onFlush: ?*const fn (context: *anyopaque, ctx: *HandlerContext) Error!void = null,
        onClose: ?*const fn (context: *anyopaque, ctx: *HandlerContext) Error!void = null,

        /// Releases the handler itself. Set only for handlers the pipeline owns.
        destroy: ?*const fn (context: *anyopaque, gpa: Allocator) void = null,
    };

    /// Builds a handler that borrows `instance`; the caller keeps ownership and
    /// must outlive the pipeline.
    pub fn init(instance: anytype) Handler {
        return .{ .context = instance, .vtable = vtableFor(@TypeOf(instance), false) };
    }

    /// Builds a handler the pipeline owns: when the handler is removed or the
    /// pipeline is torn down, `instance.deinit(gpa)` runs (if declared) and the
    /// allocation is freed.
    pub fn initOwned(instance: anytype) Handler {
        return .{ .context = instance, .vtable = vtableFor(@TypeOf(instance), true) };
    }

    fn vtableFor(comptime Pointer: type, comptime owned: bool) *const VTable {
        const info = @typeInfo(Pointer);
        comptime assert(info == .pointer and info.pointer.size == .one);
        const T = info.pointer.child;

        return comptime &.{
            .type_name = if (@hasDecl(T, "handler_name")) T.handler_name else @typeName(T),
            .onAdded = wrap(T, "onAdded", Error!void),
            .onRemoved = wrap(T, "onRemoved", void),
            .onActive = wrap(T, "onActive", Error!void),
            .onInactive = wrap(T, "onInactive", Error!void),
            .onRead = wrapMessage(T, "onRead"),
            .onReadComplete = wrap(T, "onReadComplete", Error!void),
            .onEvent = wrapEvent(T, "onEvent"),
            .onError = wrapError(T, "onError"),
            .onWrite = wrapMessage(T, "onWrite"),
            .onFlush = wrap(T, "onFlush", Error!void),
            .onClose = wrap(T, "onClose", Error!void),
            .destroy = if (owned) destroyFn(T) else null,
        };
    }

    fn wrap(
        comptime T: type,
        comptime decl: []const u8,
        comptime Result: type,
    ) ?*const fn (context: *anyopaque, ctx: *HandlerContext) Result {
        if (!@hasDecl(T, decl)) return null;
        return struct {
            fn call(context: *anyopaque, ctx: *HandlerContext) Result {
                const self: *T = @ptrCast(@alignCast(context));
                return @field(T, decl)(self, ctx);
            }
        }.call;
    }

    fn wrapMessage(
        comptime T: type,
        comptime decl: []const u8,
    ) ?*const fn (context: *anyopaque, ctx: *HandlerContext, msg: Message) Error!void {
        if (!@hasDecl(T, decl)) return null;
        return struct {
            fn call(context: *anyopaque, ctx: *HandlerContext, msg: Message) Error!void {
                const self: *T = @ptrCast(@alignCast(context));
                return @field(T, decl)(self, ctx, msg);
            }
        }.call;
    }

    fn wrapEvent(
        comptime T: type,
        comptime decl: []const u8,
    ) ?*const fn (context: *anyopaque, ctx: *HandlerContext, event: Event) Error!void {
        if (!@hasDecl(T, decl)) return null;
        return struct {
            fn call(context: *anyopaque, ctx: *HandlerContext, event: Event) Error!void {
                const self: *T = @ptrCast(@alignCast(context));
                return @field(T, decl)(self, ctx, event);
            }
        }.call;
    }

    fn wrapError(
        comptime T: type,
        comptime decl: []const u8,
    ) ?*const fn (context: *anyopaque, ctx: *HandlerContext, err: Error) void {
        if (!@hasDecl(T, decl)) return null;
        return struct {
            fn call(context: *anyopaque, ctx: *HandlerContext, err: Error) void {
                const self: *T = @ptrCast(@alignCast(context));
                return @field(T, decl)(self, ctx, err);
            }
        }.call;
    }

    fn destroyFn(comptime T: type) *const fn (context: *anyopaque, gpa: Allocator) void {
        return struct {
            fn destroy(context: *anyopaque, gpa: Allocator) void {
                const self: *T = @ptrCast(@alignCast(context));
                if (@hasDecl(T, "deinit")) self.deinit(gpa);
                gpa.destroy(self);
            }
        }.destroy;
    }
};

/// A handler's seat in the chain, and its handle on the rest of the framework.
///
/// Handlers never touch the pipeline's links directly; everything they need —
/// the allocator, the `Io`, the neighbouring handlers — is reached through the
/// context they are handed on every callback.
pub const HandlerContext = struct {
    pipeline: *Pipeline,
    prev: ?*HandlerContext,
    next: ?*HandlerContext,
    handler: Handler,
    /// Caller-provided identity, used by `Pipeline.find`. Not copied: the
    /// string must outlive the pipeline (a literal, normally).
    name: []const u8,
    /// Set when the context has been unlinked but not yet freed.
    removed: bool,
    /// Intrusive link for the deferred-free list, so removing a handler during
    /// event propagation cannot fail on allocation.
    pending_next: ?*HandlerContext,

    pub fn gpa(ctx: *const HandlerContext) Allocator {
        return ctx.pipeline.gpa;
    }

    pub fn io(ctx: *const HandlerContext) Io {
        return ctx.pipeline.io;
    }

    /// Opaque handle on the owning channel, set by whoever built the pipeline.
    pub fn owner(ctx: *const HandlerContext) ?*anyopaque {
        return ctx.pipeline.owner;
    }

    // -- Inbound: towards the tail ----------------------------------------

    pub fn fireActive(ctx: *HandlerContext) void {
        invokeActive(nextInbound(ctx));
    }

    pub fn fireInactive(ctx: *HandlerContext) void {
        invokeInactive(nextInbound(ctx));
    }

    /// Passes ownership of `msg` to the next inbound handler.
    pub fn fireRead(ctx: *HandlerContext, msg: Message) void {
        invokeRead(nextInbound(ctx), ctx.pipeline, msg);
    }

    pub fn fireReadComplete(ctx: *HandlerContext) void {
        invokeReadComplete(nextInbound(ctx));
    }

    pub fn fireEvent(ctx: *HandlerContext, event: Event) void {
        invokeEvent(nextInbound(ctx), event);
    }

    pub fn fireError(ctx: *HandlerContext, err: Error) void {
        invokeError(nextInbound(ctx), ctx.pipeline, err);
    }

    // -- Outbound: towards the head ---------------------------------------

    /// Passes ownership of `msg` to the next outbound handler.
    pub fn write(ctx: *HandlerContext, msg: Message) Error!void {
        return invokeWrite(prevOutbound(ctx), ctx.pipeline, msg);
    }

    pub fn flush(ctx: *HandlerContext) Error!void {
        return invokeFlush(prevOutbound(ctx));
    }

    pub fn writeAndFlush(ctx: *HandlerContext, msg: Message) Error!void {
        try ctx.write(msg);
        return ctx.flush();
    }

    pub fn close(ctx: *HandlerContext) Error!void {
        return invokeClose(prevOutbound(ctx));
    }

    fn nextInbound(ctx: *HandlerContext) ?*HandlerContext {
        var cursor = ctx.next;
        while (cursor) |candidate| : (cursor = candidate.next) {
            if (!candidate.removed) return candidate;
        }
        return null;
    }

    fn prevOutbound(ctx: *HandlerContext) ?*HandlerContext {
        var cursor = ctx.prev;
        while (cursor) |candidate| : (cursor = candidate.prev) {
            if (!candidate.removed) return candidate;
        }
        return null;
    }
};

// -- Invocation ------------------------------------------------------------
//
// Each `invokeX` runs one handler's callback, or forwards past it when the
// handler does not implement that event. Inbound failures are turned into
// `onError` notifications; outbound failures travel back to the initiator.

fn invokeActive(maybe_ctx: ?*HandlerContext) void {
    const ctx = maybe_ctx orelse return;
    const callback = ctx.handler.vtable.onActive orelse return ctx.fireActive();
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    callback(ctx.handler.context, ctx) catch |err| notifyError(ctx, err);
}

fn invokeInactive(maybe_ctx: ?*HandlerContext) void {
    const ctx = maybe_ctx orelse return;
    const callback = ctx.handler.vtable.onInactive orelse return ctx.fireInactive();
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    callback(ctx.handler.context, ctx) catch |err| notifyError(ctx, err);
}

fn invokeRead(maybe_ctx: ?*HandlerContext, pipeline: *Pipeline, msg: Message) void {
    const ctx = maybe_ctx orelse {
        // Nothing downstream wanted the message; releasing it here is what
        // makes "forward or free" safe to follow.
        var unowned = msg;
        unowned.deinit(pipeline.gpa);
        pipeline.stats.unhandled_inbound += 1;
        return;
    };
    const callback = ctx.handler.vtable.onRead orelse return ctx.fireRead(msg);
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    callback(ctx.handler.context, ctx, msg) catch |err| notifyError(ctx, err);
}

fn invokeReadComplete(maybe_ctx: ?*HandlerContext) void {
    const ctx = maybe_ctx orelse return;
    const callback = ctx.handler.vtable.onReadComplete orelse return ctx.fireReadComplete();
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    callback(ctx.handler.context, ctx) catch |err| notifyError(ctx, err);
}

fn invokeEvent(maybe_ctx: ?*HandlerContext, event: Event) void {
    const ctx = maybe_ctx orelse return;
    const callback = ctx.handler.vtable.onEvent orelse return ctx.fireEvent(event);
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    callback(ctx.handler.context, ctx, event) catch |err| notifyError(ctx, err);
}

fn invokeError(maybe_ctx: ?*HandlerContext, pipeline: *Pipeline, err: Error) void {
    const ctx = maybe_ctx orelse {
        pipeline.stats.unhandled_errors += 1;
        return;
    };
    const callback = ctx.handler.vtable.onError orelse return ctx.fireError(err);
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    callback(ctx.handler.context, ctx, err);
}

/// Reports a failure raised *by* `ctx`'s handler, starting at that same
/// handler so it gets the first chance to deal with its own failure.
fn notifyError(ctx: *HandlerContext, err: Error) void {
    const callback = ctx.handler.vtable.onError orelse return ctx.fireError(err);
    callback(ctx.handler.context, ctx, err);
}

fn invokeWrite(maybe_ctx: ?*HandlerContext, pipeline: *Pipeline, msg: Message) Error!void {
    const ctx = maybe_ctx orelse {
        var unowned = msg;
        unowned.deinit(pipeline.gpa);
        pipeline.stats.unhandled_outbound += 1;
        return error.PipelineHasNoSink;
    };
    const callback = ctx.handler.vtable.onWrite orelse return ctx.write(msg);
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    return callback(ctx.handler.context, ctx, msg);
}

fn invokeFlush(maybe_ctx: ?*HandlerContext) Error!void {
    const ctx = maybe_ctx orelse return;
    const callback = ctx.handler.vtable.onFlush orelse return ctx.flush();
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    return callback(ctx.handler.context, ctx);
}

fn invokeClose(maybe_ctx: ?*HandlerContext) Error!void {
    const ctx = maybe_ctx orelse return;
    const callback = ctx.handler.vtable.onClose orelse return ctx.close();
    ctx.pipeline.enter();
    defer ctx.pipeline.leave();
    return callback(ctx.handler.context, ctx);
}

/// An ordered chain of handlers, plus the head and tail sentinels that
/// terminate it.
pub const Pipeline = struct {
    gpa: Allocator,
    io: Io,
    sink: Sink,
    /// Opaque handle on whatever owns this pipeline; `Channel` puts itself
    /// here so handlers can reach it.
    owner: ?*anyopaque,
    head: *HandlerContext,
    tail: *HandlerContext,
    /// Nesting level of in-flight callbacks. Contexts removed while this is
    /// nonzero are freed once it returns to zero, so a handler may remove
    /// itself from inside a callback.
    depth: usize,
    pending_free: ?*HandlerContext,
    stats: Stats,

    pub const Options = struct {
        gpa: Allocator,
        io: Io,
        sink: Sink,
        owner: ?*anyopaque = null,
    };

    pub const Stats = struct {
        /// Inbound messages that reached the tail unclaimed.
        unhandled_inbound: usize = 0,
        /// Outbound messages that found no sink.
        unhandled_outbound: usize = 0,
        /// Failures that reached the tail unhandled.
        unhandled_errors: usize = 0,
    };

    /// Initializes a pipeline in place. The address of `pipeline` must remain
    /// stable for its whole life.
    pub fn init(pipeline: *Pipeline, options: Options) Allocator.Error!void {
        pipeline.* = .{
            .gpa = options.gpa,
            .io = options.io,
            .sink = options.sink,
            .owner = options.owner,
            .head = undefined,
            .tail = undefined,
            .depth = 0,
            .pending_free = null,
            .stats = .{},
        };

        const head = try options.gpa.create(HandlerContext);
        errdefer options.gpa.destroy(head);
        const tail = try options.gpa.create(HandlerContext);

        head.* = .{
            .pipeline = pipeline,
            .prev = null,
            .next = tail,
            .handler = .{ .context = pipeline, .vtable = &head_vtable },
            .name = "head",
            .removed = false,
            .pending_next = null,
        };
        tail.* = .{
            .pipeline = pipeline,
            .prev = head,
            .next = null,
            .handler = .{ .context = pipeline, .vtable = &tail_vtable },
            .name = "tail",
            .removed = false,
            .pending_next = null,
        };
        pipeline.head = head;
        pipeline.tail = tail;
    }

    /// Heap-allocates and initializes a pipeline.
    pub fn create(options: Options) Allocator.Error!*Pipeline {
        const pipeline = try options.gpa.create(Pipeline);
        errdefer options.gpa.destroy(pipeline);
        try pipeline.init(options);
        return pipeline;
    }

    /// Releases every handler the pipeline owns, then its own bookkeeping.
    pub fn deinit(pipeline: *Pipeline) void {
        assert(pipeline.depth == 0); // Tearing down mid-callback is a bug.

        var cursor = pipeline.head.next;
        while (cursor) |ctx| {
            cursor = ctx.next;
            if (ctx == pipeline.tail) break;
            if (ctx.handler.vtable.onRemoved) |callback| {
                callback(ctx.handler.context, ctx);
            }
            pipeline.freeContext(ctx);
        }
        pipeline.drainPendingFree();
        pipeline.gpa.destroy(pipeline.head);
        pipeline.gpa.destroy(pipeline.tail);
        pipeline.* = undefined;
    }

    /// Counterpart of `create`.
    pub fn destroy(pipeline: *Pipeline) void {
        const gpa = pipeline.gpa;
        pipeline.deinit();
        gpa.destroy(pipeline);
    }

    fn enter(pipeline: *Pipeline) void {
        pipeline.depth += 1;
    }

    fn leave(pipeline: *Pipeline) void {
        assert(pipeline.depth > 0);
        pipeline.depth -= 1;
        if (pipeline.depth == 0) pipeline.drainPendingFree();
    }

    fn drainPendingFree(pipeline: *Pipeline) void {
        var cursor = pipeline.pending_free;
        pipeline.pending_free = null;
        while (cursor) |ctx| {
            cursor = ctx.pending_next;
            pipeline.freeContext(ctx);
        }
    }

    fn freeContext(pipeline: *Pipeline, ctx: *HandlerContext) void {
        if (ctx.handler.vtable.destroy) |destroy_handler| {
            destroy_handler(ctx.handler.context, pipeline.gpa);
        }
        pipeline.gpa.destroy(ctx);
    }

    // -- Chain edits -------------------------------------------------------

    /// Appends `handler` just before the tail. `name` must outlive the
    /// pipeline.
    pub fn addLast(
        pipeline: *Pipeline,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        return pipeline.insertBefore(pipeline.tail, name, handler);
    }

    /// Inserts `handler` just after the head.
    pub fn addFirst(
        pipeline: *Pipeline,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        return pipeline.insertAfter(pipeline.head, name, handler);
    }

    pub fn addBefore(
        pipeline: *Pipeline,
        existing: *HandlerContext,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        assert(existing != pipeline.head);
        return pipeline.insertBefore(existing, name, handler);
    }

    pub fn addAfter(
        pipeline: *Pipeline,
        existing: *HandlerContext,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        assert(existing != pipeline.tail);
        return pipeline.insertAfter(existing, name, handler);
    }

    fn insertBefore(
        pipeline: *Pipeline,
        existing: *HandlerContext,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        const before = existing.prev.?;
        return pipeline.link(before, existing, name, handler);
    }

    fn insertAfter(
        pipeline: *Pipeline,
        existing: *HandlerContext,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        const after = existing.next.?;
        return pipeline.link(existing, after, name, handler);
    }

    fn link(
        pipeline: *Pipeline,
        before: *HandlerContext,
        after: *HandlerContext,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        assert(before.next == after);
        assert(after.prev == before);

        const ctx = try pipeline.gpa.create(HandlerContext);
        ctx.* = .{
            .pipeline = pipeline,
            .prev = before,
            .next = after,
            .handler = handler,
            .name = name,
            .removed = false,
            .pending_next = null,
        };
        before.next = ctx;
        after.prev = ctx;

        if (handler.vtable.onAdded) |callback| {
            pipeline.enter();
            const outcome = callback(handler.context, ctx);
            pipeline.leave();

            _ = outcome catch |err| {
                // A handler that could not be added must not be left in the
                // chain, where it would receive events it never initialized
                // for. The insertion is undone and the failure returned.
                //
                // Only the context is released, never the handler: ownership of
                // an `initOwned` instance transfers on a *successful* add, so
                // the caller's `errdefer` still covers it. Freeing it here would
                // be the second half of a double free.
                before.next = after;
                after.prev = before;
                pipeline.gpa.destroy(ctx);
                return err;
            };
        }
        return ctx;
    }

    /// Unlinks `ctx` and releases it. Safe to call from inside a callback,
    /// including from the handler being removed.
    pub fn remove(pipeline: *Pipeline, ctx: *HandlerContext) void {
        assert(ctx != pipeline.head);
        assert(ctx != pipeline.tail);
        assert(ctx.pipeline == pipeline);
        assert(!ctx.removed);

        const before = ctx.prev.?;
        const after = ctx.next.?;
        before.next = after;
        after.prev = before;
        ctx.removed = true;

        if (ctx.handler.vtable.onRemoved) |callback| {
            pipeline.enter();
            defer pipeline.leave();
            callback(ctx.handler.context, ctx);
        }

        if (pipeline.depth == 0) {
            pipeline.freeContext(ctx);
        } else {
            // `ctx.next` and `ctx.prev` stay valid so an in-flight
            // propagation that started here can still find its way onwards.
            ctx.pending_next = pipeline.pending_free;
            pipeline.pending_free = ctx;
        }
    }

    /// Removes the handler named `name`, if present. Returns whether it was.
    pub fn removeNamed(pipeline: *Pipeline, name: []const u8) bool {
        const ctx = pipeline.find(name) orelse return false;
        pipeline.remove(ctx);
        return true;
    }

    /// Swaps `existing` for `handler`, keeping the position in the chain.
    ///
    /// This is how a protocol upgrade rewrites the pipeline: insert the
    /// replacement at the same seat, then retire the old handler.
    pub fn replace(
        pipeline: *Pipeline,
        existing: *HandlerContext,
        name: []const u8,
        handler: Handler,
    ) Error!*HandlerContext {
        assert(existing != pipeline.head);
        assert(existing != pipeline.tail);
        const replacement = try pipeline.insertBefore(existing, name, handler);
        pipeline.remove(existing);
        return replacement;
    }

    /// First handler with this name, or `null`.
    pub fn find(pipeline: *Pipeline, name: []const u8) ?*HandlerContext {
        var cursor = pipeline.head.next;
        while (cursor) |ctx| : (cursor = ctx.next) {
            if (ctx == pipeline.tail) break;
            if (ctx.removed) continue;
            if (std.mem.eql(u8, ctx.name, name)) return ctx;
        }
        return null;
    }

    /// Number of live handlers, excluding the head and tail sentinels.
    pub fn count(pipeline: *Pipeline) usize {
        var total: usize = 0;
        var cursor = pipeline.head.next;
        while (cursor) |ctx| : (cursor = ctx.next) {
            if (ctx == pipeline.tail) break;
            if (!ctx.removed) total += 1;
        }
        return total;
    }

    /// Handler names from head to tail, written into `out`. Returns the slice
    /// actually used. Diagnostics only.
    pub fn names(pipeline: *Pipeline, out: [][]const u8) [][]const u8 {
        var used: usize = 0;
        var cursor = pipeline.head.next;
        while (cursor) |ctx| : (cursor = ctx.next) {
            if (ctx == pipeline.tail) break;
            if (ctx.removed) continue;
            if (used == out.len) break;
            out[used] = ctx.name;
            used += 1;
        }
        return out[0..used];
    }

    // -- Entry points ------------------------------------------------------

    pub fn fireActive(pipeline: *Pipeline) void {
        invokeActive(HandlerContext.nextInbound(pipeline.head));
    }

    pub fn fireInactive(pipeline: *Pipeline) void {
        invokeInactive(HandlerContext.nextInbound(pipeline.head));
    }

    /// Passes ownership of `msg` to the first inbound handler.
    pub fn fireRead(pipeline: *Pipeline, msg: Message) void {
        invokeRead(HandlerContext.nextInbound(pipeline.head), pipeline, msg);
    }

    pub fn fireReadComplete(pipeline: *Pipeline) void {
        invokeReadComplete(HandlerContext.nextInbound(pipeline.head));
    }

    pub fn fireEvent(pipeline: *Pipeline, event: Event) void {
        invokeEvent(HandlerContext.nextInbound(pipeline.head), event);
    }

    pub fn fireError(pipeline: *Pipeline, err: Error) void {
        invokeError(HandlerContext.nextInbound(pipeline.head), pipeline, err);
    }

    /// Passes ownership of `msg` to the last outbound handler.
    pub fn write(pipeline: *Pipeline, msg: Message) Error!void {
        return invokeWrite(HandlerContext.prevOutbound(pipeline.tail), pipeline, msg);
    }

    pub fn flush(pipeline: *Pipeline) Error!void {
        return invokeFlush(HandlerContext.prevOutbound(pipeline.tail));
    }

    pub fn writeAndFlush(pipeline: *Pipeline, msg: Message) Error!void {
        try pipeline.write(msg);
        return pipeline.flush();
    }

    pub fn close(pipeline: *Pipeline) Error!void {
        return invokeClose(HandlerContext.prevOutbound(pipeline.tail));
    }
};

// -- Sentinels -------------------------------------------------------------

/// The head terminates the outbound direction by handing everything to the
/// sink. It is transparent to inbound events.
const head_vtable: Handler.VTable = .{
    .type_name = "head",
    .onWrite = headWrite,
    .onFlush = headFlush,
    .onClose = headClose,
};

fn headWrite(context: *anyopaque, ctx: *HandlerContext, msg: Message) Error!void {
    _ = ctx;
    const pipeline: *Pipeline = @ptrCast(@alignCast(context));
    return pipeline.sink.write(msg);
}

fn headFlush(context: *anyopaque, ctx: *HandlerContext) Error!void {
    _ = ctx;
    const pipeline: *Pipeline = @ptrCast(@alignCast(context));
    return pipeline.sink.flush();
}

fn headClose(context: *anyopaque, ctx: *HandlerContext) Error!void {
    _ = ctx;
    const pipeline: *Pipeline = @ptrCast(@alignCast(context));
    return pipeline.sink.close();
}

/// The tail terminates the inbound direction. Anything that gets this far was
/// not claimed by a handler, so it is released and counted.
const tail_vtable: Handler.VTable = .{
    .type_name = "tail",
    .onRead = tailRead,
    .onError = tailError,
};

fn tailRead(context: *anyopaque, ctx: *HandlerContext, msg: Message) Error!void {
    _ = ctx;
    const pipeline: *Pipeline = @ptrCast(@alignCast(context));
    var unowned = msg;
    unowned.deinit(pipeline.gpa);
    pipeline.stats.unhandled_inbound += 1;
}

fn tailError(context: *anyopaque, ctx: *HandlerContext, err: Error) void {
    const pipeline: *Pipeline = @ptrCast(@alignCast(context));
    pipeline.stats.unhandled_errors += 1;
    std.log.scoped(.zinet).debug("unhandled pipeline error at {s}: {s}", .{
        ctx.name,
        @errorName(err),
    });
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

/// Records everything that reaches the outbound end of a pipeline.
const RecordingSink = struct {
    gpa: Allocator,
    written: std.ArrayList(u8) = .empty,
    flushes: usize = 0,
    closes: usize = 0,
    fail_write: bool = false,

    fn sink(self: *RecordingSink) Sink {
        return .{ .context = self, .vtable = &.{
            .write = writeImpl,
            .flush = flushImpl,
            .close = closeImpl,
        } };
    }

    fn writeImpl(context: *anyopaque, msg: Message) Error!void {
        const self: *RecordingSink = @ptrCast(@alignCast(context));
        var owned = msg;
        defer owned.deinit(self.gpa); // A sink always consumes the message.
        if (self.fail_write) return error.SinkClosed;
        try self.written.appendSlice(self.gpa, owned.bytes() orelse "");
    }

    fn flushImpl(context: *anyopaque) Error!void {
        const self: *RecordingSink = @ptrCast(@alignCast(context));
        self.flushes += 1;
    }

    fn closeImpl(context: *anyopaque) Error!void {
        const self: *RecordingSink = @ptrCast(@alignCast(context));
        self.closes += 1;
    }

    fn deinit(self: *RecordingSink) void {
        self.written.deinit(self.gpa);
    }
};

/// Test scaffolding: a pipeline wired to a recording sink.
const Fixture = struct {
    threaded: *Io.Threaded,
    sink_impl: *RecordingSink,
    pipeline: *Pipeline,
    gpa: Allocator,

    fn init(gpa: Allocator) !Fixture {
        const threaded = try gpa.create(Io.Threaded);
        threaded.* = .init(gpa, .{});

        const sink_impl = try gpa.create(RecordingSink);
        sink_impl.* = .{ .gpa = gpa };

        const pipeline = try Pipeline.create(.{
            .gpa = gpa,
            .io = threaded.io(),
            .sink = sink_impl.sink(),
        });
        return .{
            .threaded = threaded,
            .sink_impl = sink_impl,
            .pipeline = pipeline,
            .gpa = gpa,
        };
    }

    fn deinit(fixture: *Fixture) void {
        fixture.pipeline.destroy();
        fixture.sink_impl.deinit();
        fixture.gpa.destroy(fixture.sink_impl);
        fixture.threaded.deinit();
        fixture.gpa.destroy(fixture.threaded);
    }

    fn written(fixture: *const Fixture) []const u8 {
        return fixture.sink_impl.written.items;
    }
};

/// Appends its label to a shared trace on every event it sees, then forwards.
const TracingHandler = struct {
    label: []const u8,
    trace: *std.ArrayList(u8),
    gpa: Allocator,

    fn note(self: *TracingHandler, what: []const u8) void {
        self.trace.appendSlice(self.gpa, self.label) catch unreachable;
        self.trace.append(self.gpa, ':') catch unreachable;
        self.trace.appendSlice(self.gpa, what) catch unreachable;
        self.trace.append(self.gpa, ' ') catch unreachable;
    }

    pub fn onActive(self: *TracingHandler, ctx: *HandlerContext) Error!void {
        self.note("active");
        ctx.fireActive();
    }

    pub fn onRead(self: *TracingHandler, ctx: *HandlerContext, msg: Message) Error!void {
        self.note("read");
        ctx.fireRead(msg);
    }

    pub fn onWrite(self: *TracingHandler, ctx: *HandlerContext, msg: Message) Error!void {
        self.note("write");
        return ctx.write(msg);
    }

    pub fn onInactive(self: *TracingHandler, ctx: *HandlerContext) Error!void {
        self.note("inactive");
        ctx.fireInactive();
    }
};

test "Pipeline: starts out empty with only its sentinels" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit();

    try testing.expectEqual(@as(usize, 0), fixture.pipeline.count());
    try testing.expect(fixture.pipeline.find("missing") == null);
}

test "Pipeline: inbound runs head to tail, outbound runs tail to head" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(gpa);

    var first: TracingHandler = .{ .label = "first", .trace = &trace, .gpa = gpa };
    var second: TracingHandler = .{ .label = "second", .trace = &trace, .gpa = gpa };
    _ = try fixture.pipeline.addLast("first", .init(&first));
    _ = try fixture.pipeline.addLast("second", .init(&second));
    try testing.expectEqual(@as(usize, 2), fixture.pipeline.count());

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "in"));
    try testing.expectEqualStrings("first:read second:read ", trace.items);

    trace.clearRetainingCapacity();
    try fixture.pipeline.writeAndFlush(try Message.initBytes(gpa, "out"));
    try testing.expectEqualStrings("second:write first:write ", trace.items);
    try testing.expectEqualStrings("out", fixture.written());
    try testing.expectEqual(@as(usize, 1), fixture.sink_impl.flushes);
}

test "Pipeline: addFirst, addBefore and addAfter place handlers precisely" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(gpa);
    var handlers: [4]TracingHandler = undefined;
    for (&handlers, 0..) |*handler, i| {
        handler.* = .{
            .label = switch (i) {
                0 => "b",
                1 => "a",
                2 => "c",
                else => "d",
            },
            .trace = &trace,
            .gpa = gpa,
        };
    }

    const b = try fixture.pipeline.addLast("b", .init(&handlers[0]));
    _ = try fixture.pipeline.addFirst("a", .init(&handlers[1]));
    const c = try fixture.pipeline.addAfter(b, "c", .init(&handlers[2]));
    _ = try fixture.pipeline.addBefore(c, "d", .init(&handlers[3]));

    var buffer: [8][]const u8 = undefined;
    const listed = fixture.pipeline.names(&buffer);
    try testing.expectEqual(@as(usize, 4), listed.len);
    try testing.expectEqualStrings("a", listed[0]);
    try testing.expectEqualStrings("b", listed[1]);
    try testing.expectEqualStrings("d", listed[2]);
    try testing.expectEqualStrings("c", listed[3]);
}

test "Pipeline: handlers without a callback are transparent" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    // Declares only onWrite, so inbound reads pass straight through it.
    const WriteOnly = struct {
        seen: usize = 0,
        pub fn onWrite(self: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            self.seen += 1;
            return ctx.write(msg);
        }
    };
    var write_only: WriteOnly = .{};
    _ = try fixture.pipeline.addLast("write-only", .init(&write_only));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "unclaimed"));
    try testing.expectEqual(@as(usize, 1), fixture.pipeline.stats.unhandled_inbound);
    try testing.expectEqual(@as(usize, 0), write_only.seen);

    try fixture.pipeline.write(try Message.initBytes(gpa, "claimed"));
    try testing.expectEqual(@as(usize, 1), write_only.seen);
}

test "Pipeline: a handler that consumes a message ends propagation" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    const Consumer = struct {
        consumed: usize = 0,
        pub fn onRead(self: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            self.consumed += owned.len();
        }
    };
    var consumer: Consumer = .{};
    _ = try fixture.pipeline.addLast("consumer", .init(&consumer));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "12345"));
    try testing.expectEqual(@as(usize, 5), consumer.consumed);
    try testing.expectEqual(@as(usize, 0), fixture.pipeline.stats.unhandled_inbound);
}

test "Pipeline: an inbound handler can turn a read into a write" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    const Echo = struct {
        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            errdefer {
                var owned = msg;
                owned.deinit(ctx.gpa());
            }
            try ctx.writeAndFlush(msg);
        }
    };
    var echo: Echo = .{};
    _ = try fixture.pipeline.addLast("echo", .init(&echo));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "ping"));
    try testing.expectEqualStrings("ping", fixture.written());
    try testing.expectEqual(@as(usize, 1), fixture.sink_impl.flushes);
}

test "Pipeline: inbound failures reach the raising handler first" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    const Failing = struct {
        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            var owned = msg;
            owned.deinit(ctx.gpa()); // Own the message before failing.
            return error.DecodeFailed;
        }
    };
    const Catcher = struct {
        caught: ?Error = null,
        pub fn onError(self: *@This(), _: *HandlerContext, err: Error) void {
            self.caught = err;
        }
    };

    var failing: Failing = .{};
    var catcher: Catcher = .{};
    // The catcher sits downstream, which is where a failure propagates to.
    _ = try fixture.pipeline.addLast("failing", .init(&failing));
    _ = try fixture.pipeline.addLast("catcher", .init(&catcher));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "bad frame"));
    try testing.expectEqual(@as(?Error, error.DecodeFailed), catcher.caught);
    try testing.expectEqual(@as(usize, 0), fixture.pipeline.stats.unhandled_errors);
}

test "Pipeline: unhandled failures are counted at the tail" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    fixture.pipeline.fireError(error.ConnectionResetByPeer);
    try testing.expectEqual(@as(usize, 1), fixture.pipeline.stats.unhandled_errors);
}

test "Pipeline: outbound failures propagate back to the initiator" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();
    fixture.sink_impl.fail_write = true;

    try testing.expectError(
        error.SinkClosed,
        fixture.pipeline.write(try Message.initBytes(gpa, "doomed")),
    );
}

test "Pipeline: lifecycle callbacks fire on add, remove and teardown" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    const Lifecycle = struct {
        added: usize = 0,
        removed: usize = 0,
        pub fn onAdded(self: *@This(), _: *HandlerContext) Error!void {
            self.added += 1;
        }
        pub fn onRemoved(self: *@This(), _: *HandlerContext) void {
            self.removed += 1;
        }
    };

    var lifecycle: Lifecycle = .{};
    const ctx = try fixture.pipeline.addLast("lifecycle", .init(&lifecycle));
    try testing.expectEqual(@as(usize, 1), lifecycle.added);

    fixture.pipeline.remove(ctx);
    try testing.expectEqual(@as(usize, 1), lifecycle.removed);
    try testing.expectEqual(@as(usize, 0), fixture.pipeline.count());
}

test "Pipeline: owned handlers are freed by the pipeline" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    const Owned = struct {
        scratch: []u8,
        pub fn deinit(self: *@This(), allocator: Allocator) void {
            allocator.free(self.scratch);
        }
        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            ctx.fireRead(msg);
        }
    };

    const first = try gpa.create(Owned);
    first.* = .{ .scratch = try gpa.dupe(u8, "state") };
    const ctx = try fixture.pipeline.addLast("owned-removed", .initOwned(first));
    fixture.pipeline.remove(ctx); // Frees `first` and its scratch.

    const second = try gpa.create(Owned);
    second.* = .{ .scratch = try gpa.dupe(u8, "state") };
    _ = try fixture.pipeline.addLast("owned-teardown", .initOwned(second));
    // Fixture teardown frees `second`; the leak checker proves both paths.
}

test "Pipeline: replace swaps a handler in place, as a protocol upgrade does" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(gpa);

    var before: TracingHandler = .{ .label = "http", .trace = &trace, .gpa = gpa };
    var after: TracingHandler = .{ .label = "ws", .trace = &trace, .gpa = gpa };
    var downstream: TracingHandler = .{ .label = "app", .trace = &trace, .gpa = gpa };

    const codec = try fixture.pipeline.addLast("codec", .init(&before));
    _ = try fixture.pipeline.addLast("app", .init(&downstream));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "GET /"));
    try testing.expectEqualStrings("http:read app:read ", trace.items);

    trace.clearRetainingCapacity();
    _ = try fixture.pipeline.replace(codec, "codec", .init(&after));
    try testing.expectEqual(@as(usize, 2), fixture.pipeline.count());

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "frame"));
    try testing.expectEqualStrings("ws:read app:read ", trace.items);

    var buffer: [4][]const u8 = undefined;
    const listed = fixture.pipeline.names(&buffer);
    try testing.expectEqualStrings("codec", listed[0]);
    try testing.expectEqualStrings("app", listed[1]);
}

test "Pipeline: a handler may replace itself while handling a read" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(gpa);
    var successor: TracingHandler = .{ .label = "ws", .trace = &trace, .gpa = gpa };

    // Mirrors the WebSocket upgrade: the handshake handler consumes the
    // request, installs its successor, and retires itself — all from inside
    // its own callback.
    const Upgrader = struct {
        successor: *TracingHandler,
        upgraded: bool = false,

        pub fn onRead(self: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            assert(!self.upgraded);
            _ = try ctx.pipeline.replace(ctx, "codec", .init(self.successor));
            self.upgraded = true;
        }
    };
    var upgrader: Upgrader = .{ .successor = &successor };
    _ = try fixture.pipeline.addLast("codec", .init(&upgrader));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "Upgrade: websocket"));
    try testing.expect(upgrader.upgraded);
    try testing.expectEqual(@as(usize, 1), fixture.pipeline.count());

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "frame"));
    try testing.expectEqualStrings("ws:read ", trace.items);
}

test "Pipeline: removing a handler mid-propagation defers the free" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(gpa);
    var downstream: TracingHandler = .{ .label = "next", .trace = &trace, .gpa = gpa };

    const SelfRemoving = struct {
        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            ctx.pipeline.remove(ctx);
            // Forwarding after removal must still work: the context is not
            // freed until propagation unwinds.
            ctx.fireRead(msg);
        }
    };
    var self_removing: SelfRemoving = .{};
    _ = try fixture.pipeline.addLast("once", .init(&self_removing));
    _ = try fixture.pipeline.addLast("next", .init(&downstream));

    fixture.pipeline.fireRead(try Message.initBytes(gpa, "first"));
    try testing.expectEqualStrings("next:read ", trace.items);
    try testing.expectEqual(@as(usize, 1), fixture.pipeline.count());

    trace.clearRetainingCapacity();
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "second"));
    try testing.expectEqualStrings("next:read ", trace.items);
}

test "Pipeline: full event surface reaches every handler in order" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(gpa);
    var first: TracingHandler = .{ .label = "1", .trace = &trace, .gpa = gpa };
    var second: TracingHandler = .{ .label = "2", .trace = &trace, .gpa = gpa };
    _ = try fixture.pipeline.addLast("1", .init(&first));
    _ = try fixture.pipeline.addLast("2", .init(&second));

    fixture.pipeline.fireActive();
    fixture.pipeline.fireReadComplete();
    fixture.pipeline.fireInactive();
    try testing.expectEqualStrings("1:active 2:active 1:inactive 2:inactive ", trace.items);

    try fixture.pipeline.close();
    try testing.expectEqual(@as(usize, 1), fixture.sink_impl.closes);
}

test "Pipeline: user events travel inbound and can be matched by type" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    const HandshakeDone = struct { protocol: []const u8 };
    const Listener = struct {
        seen: ?[]const u8 = null,
        forwarded: usize = 0,
        pub fn onEvent(self: *@This(), ctx: *HandlerContext, event: Event) Error!void {
            if (event.get(HandshakeDone)) |done| self.seen = done.protocol;
            self.forwarded += 1;
            ctx.fireEvent(event);
        }
    };

    var upstream: Listener = .{};
    var downstream: Listener = .{};
    _ = try fixture.pipeline.addLast("upstream", .init(&upstream));
    _ = try fixture.pipeline.addLast("downstream", .init(&downstream));

    const done: HandshakeDone = .{ .protocol = "websocket" };
    fixture.pipeline.fireEvent(.init(&done));

    try testing.expectEqualStrings("websocket", upstream.seen.?);
    try testing.expectEqualStrings("websocket", downstream.seen.?);
}

test "Pipeline: a message with no sink is released, not leaked" {
    const gpa = testing.allocator;
    const threaded = try gpa.create(Io.Threaded);
    threaded.* = .init(gpa, .{});
    defer {
        threaded.deinit();
        gpa.destroy(threaded);
    }

    const Rejecting = struct {
        fn sink() Sink {
            return .{ .context = undefined, .vtable = &.{ .write = writeImpl } };
        }
        fn writeImpl(_: *anyopaque, msg: Message) Error!void {
            var owned = msg;
            owned.deinit(testing.allocator);
            return error.NotConnected;
        }
    };

    const pipeline = try Pipeline.create(.{
        .gpa = gpa,
        .io = threaded.io(),
        .sink = Rejecting.sink(),
    });
    defer pipeline.destroy();

    try testing.expectError(
        error.NotConnected,
        pipeline.write(try Message.initBytes(gpa, "no route")),
    );
}

test "Pipeline: removeNamed and find operate by name" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(gpa);
    var handler: TracingHandler = .{ .label = "x", .trace = &trace, .gpa = gpa };
    _ = try fixture.pipeline.addLast("x", .init(&handler));

    try testing.expect(fixture.pipeline.find("x") != null);
    try testing.expect(fixture.pipeline.removeNamed("x"));
    try testing.expect(!fixture.pipeline.removeNamed("x"));
    try testing.expect(fixture.pipeline.find("x") == null);
}

test "Pipeline: a handler whose onAdded fails is not left in the chain" {
    const gpa = testing.allocator;
    var fixture = try Fixture.init(gpa);
    defer fixture.deinit();

    const Refuser = struct {
        pub fn onAdded(_: *@This(), _: *HandlerContext) Error!void {
            return error.RefusingToJoin;
        }
        pub fn onRead(_: *@This(), ctx: *HandlerContext, msg: Message) Error!void {
            // Would double free if the handler really were still in the chain,
            // because the message is also released by the tail.
            _ = ctx;
            _ = msg;
            unreachable;
        }
    };

    // Ownership stays with the caller when the add fails, which is what makes
    // this `errdefer` correct rather than a double free.
    const refuser = try gpa.create(Refuser);
    refuser.* = .{};
    defer gpa.destroy(refuser);

    try testing.expectError(
        error.RefusingToJoin,
        fixture.pipeline.addLast("refuser", .initOwned(refuser)),
    );
    try testing.expectEqual(@as(usize, 0), fixture.pipeline.count());
    try testing.expect(fixture.pipeline.find("refuser") == null);

    // The chain is intact: a read still reaches the tail rather than a freed
    // context.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "after"));
    try testing.expectEqual(@as(usize, 1), fixture.pipeline.stats.unhandled_inbound);
}
