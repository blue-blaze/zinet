//! A tiny Redis-compatible server, to show the RESP codec from the server side.
//!
//! ```
//! zig build run-redis-server -- 6380
//! redis-cli -p 6380 set greeting hello
//! ```
//!
//! Supports `PING`, `ECHO`, `SET`, `GET`, `DEL` and `EXISTS`, which is enough for
//! a real client library to connect and exercise the protocol. Everything else
//! gets an error reply, which is what a real server does for an unknown command
//! and what clients are built to tolerate.
//!
//! The store is shared between connections and therefore behind a lock — the one
//! place in a Zinet program that needs one, because it is the one piece of state
//! that is not per connection. Handler state never is, which is the point of the
//! one-task-per-connection rule.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Io = std.Io;

const default_port = 6380;

/// Shared key-value store.
const Store = struct {
    gpa: std.mem.Allocator,
    mutex: zinet.Spinlock = .init,
    entries: std.StringHashMapUnmanaged([]u8) = .empty,

    fn deinit(self: *Store) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.gpa.free(entry.key_ptr.*);
            self.gpa.free(entry.value_ptr.*);
        }
        self.entries.deinit(self.gpa);
    }

    fn set(self: *Store, key: []const u8, value: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const owned_value = try self.gpa.dupe(u8, value);
        errdefer self.gpa.free(owned_value);

        if (self.entries.getPtr(key)) |slot| {
            self.gpa.free(slot.*);
            slot.* = owned_value;
            return;
        }
        const owned_key = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(owned_key);
        try self.entries.put(self.gpa, owned_key, owned_value);
    }

    /// Copies the value into `arena`, so the caller can hold it without holding
    /// the lock.
    fn get(self: *Store, arena: std.mem.Allocator, key: []const u8) !?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const found = self.entries.get(key) orelse return null;
        return try arena.dupe(u8, found);
    }

    fn remove(self: *Store, key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.entries.fetchRemove(key) orelse return false;
        self.gpa.free(entry.key);
        self.gpa.free(entry.value);
        return true;
    }

    fn exists(self: *Store, key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.contains(key);
    }
};

var store: Store = undefined;

/// Answers commands. A command arrives as an array of bulk strings.
const CommandHandler = struct {
    pub fn onRead(_: *CommandHandler, ctx: *zinet.HandlerContext, msg: zinet.Message) !void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        const incoming = owned.get(zinet.RedisIncoming) orelse return;

        // Replies are built in an arena that lives until the write completes,
        // which it does synchronously inside `writeAndFlush`.
        var arena: std.heap.ArenaAllocator = .init(ctx.gpa());
        defer arena.deinit();

        const reply = dispatch(&arena, incoming.value) catch |err| switch (err) {
            error.OutOfMemory => return err,
        };
        return ctx.writeAndFlush(
            try zinet.Message.initAny(ctx.gpa(), zinet.RedisValue, reply),
        );
    }

    fn dispatch(
        arena: *std.heap.ArenaAllocator,
        value: zinet.RedisValue,
    ) error{OutOfMemory}!zinet.RedisValue {
        const args = value.elements() orelse
            return .{ .err = "ERR expected an array of arguments" };
        if (args.len == 0) return .{ .err = "ERR empty command" };

        const name = args[0].text() orelse return .{ .err = "ERR malformed command name" };
        var upper: [32]u8 = undefined;
        if (name.len > upper.len) return .{ .err = "ERR unknown command" };
        for (name, 0..) |byte, index| upper[index] = std.ascii.toUpper(byte);
        const command = upper[0..name.len];

        const allocator = arena.allocator();

        if (std.mem.eql(u8, command, "PING")) {
            if (args.len == 1) return .{ .simple = "PONG" };
            return .{ .bulk = args[1].text() orelse "" };
        }
        if (std.mem.eql(u8, command, "ECHO")) {
            if (args.len != 2) return wrongArity("echo");
            return .{ .bulk = args[1].text() orelse "" };
        }
        if (std.mem.eql(u8, command, "SET")) {
            if (args.len < 3) return wrongArity("set");
            const key = args[1].text() orelse return wrongArity("set");
            const payload = args[2].text() orelse return wrongArity("set");
            store.set(key, payload) catch return .{ .err = "ERR out of memory" };
            return .{ .simple = "OK" };
        }
        if (std.mem.eql(u8, command, "GET")) {
            if (args.len != 2) return wrongArity("get");
            const key = args[1].text() orelse return wrongArity("get");
            const found = store.get(allocator, key) catch
                return .{ .err = "ERR out of memory" };
            // A missing key is the null bulk string, not an error.
            return .{ .bulk = found };
        }
        if (std.mem.eql(u8, command, "DEL")) {
            var removed: i64 = 0;
            for (args[1..]) |arg| {
                const key = arg.text() orelse continue;
                if (store.remove(key)) removed += 1;
            }
            return .{ .integer = removed };
        }
        if (std.mem.eql(u8, command, "EXISTS")) {
            var found: i64 = 0;
            for (args[1..]) |arg| {
                const key = arg.text() orelse continue;
                if (store.exists(key)) found += 1;
            }
            return .{ .integer = found };
        }

        return .{ .err = "ERR unknown command" };
    }

    fn wrongArity(comptime name: []const u8) zinet.RedisValue {
        return .{ .err = "ERR wrong number of arguments for '" ++ name ++ "' command" };
    }
};

fn buildPipeline(pipeline: *zinet.Pipeline) anyerror!void {
    try zinet.redis.addCodec(pipeline, .{});

    const handler = try pipeline.gpa.create(CommandHandler);
    handler.* = .{};
    errdefer pipeline.gpa.destroy(handler);
    _ = try pipeline.addLast("commands", .initOwned(handler));
}

var shutdown_requested: std.atomic.Value(bool) = .init(false);

fn onSignal(_: std.posix.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug.deinit() == .leak) std.process.exit(1);
    const gpa = debug.allocator();

    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();
    const io = threaded.io();

    var iterator = try std.process.Args.Iterator.initAllocator(init.args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();
    const port = if (iterator.next()) |text|
        try std.fmt.parseInt(u16, text, 10)
    else
        default_port;

    store = .{ .gpa = gpa };
    defer store.deinit();

    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESTART,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);

    const server = try zinet.Server.listen(.{
        .gpa = gpa,
        .io = io,
        .address = .{ .ip4 = .unspecified(port) },
        .child = .{ .initializer = .initFunction(buildPipeline) },
    });
    defer server.deinit();
    try server.serve();

    // Announced because a benchmark run against a Debug build of this example once produced a
    // handshake cost four times the real one, and nothing in its output said which build it was.
    // Debug builds say so loudly: the mode was logged quietly once already and a
    // measurement was still taken against one and briefly believed.
    switch (@import("builtin").mode) {
        .Debug => std.debug.print("build: debug — unoptimized, not a performance measurement\n", .{}),
        else => std.debug.print("build: {t}\n", .{@import("builtin").mode}),
    }
    std.debug.print("listening on {d}\n", .{server.port()});

    while (!shutdown_requested.load(.acquire)) {
        const duration: Io.Clock.Duration = .{
            .raw = .fromMilliseconds(50),
            .clock = .awake,
        };
        duration.sleep(io) catch break;
    }

    std.debug.print("shutting down\n", .{});
    server.stopAccepting();
    _ = server.shutdownGracefully(.{ .timeout = .fromSeconds(2) });
}
