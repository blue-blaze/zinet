//! Minimal reproducer for the one zio defect that affects Zinet. Deliberately
//! outside the build: it needs a `zio` import that only `-Dio=zio` provides, and
//! a file that never compiles is a file that rots. To run it, drop it into a
//! project that depends on zio and build it as an executable.
//!
//! zio panics on `net_receive` against a *stream* socket.
//!
//! `recvmsg` on a connected socket does not fill `msg_name`; the kernel reports
//! `msg_namelen = 0` and leaves the buffer untouched. zio declares that buffer
//! `undefined`, ignores the returned length, and converts it unconditionally:
//!
//!   src/io.zig:2347  .from = zioIpToStdIo(storage.ip),
//!   src/io.zig:1830  else => unreachable,
//!
//! So the family byte is whatever was on the stack. std.Io.Threaded performs the
//! same conversion but defines the case away:
//!
//!   std/Io/Threaded.zig:13982  else => .{ .ip4 = .loopback(0) },
//!
//! Expected: `net_receive` succeeds and `from` holds some defined value.
//! Actual (Debug/ReleaseSafe): "reached unreachable code" in zioIpToStdIo.
//! ReleaseFast would silently produce a garbage address instead.
//!
//! The write-up, including the one-line fix and the evidence that it works, is in
//! zio-net-receive.md next to this file.

const std = @import("std");
const zio = @import("zio");
const Io = std.Io;

fn writeOnce(io: Io, server: *Io.net.Server) void {
    const accepted = server.accept(io) catch return;
    defer accepted.close(io);
    var out: [8]u8 = undefined;
    var writer = accepted.writer(io, &out);
    writer.interface.writeAll("hi") catch return;
    writer.interface.flush() catch return;
}

pub fn main() !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug.deinit();

    const rt = try zio.Runtime.init(debug.allocator(), .{});
    defer rt.deinit();
    const io = rt.io();

    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    var future = try io.concurrent(writeOnce, .{ io, &server });
    defer future.await(io);

    var peer = server.socket.address;
    const client = try peer.connect(io, .{ .mode = .stream });
    defer client.close(io);

    var scratch: [64]u8 = undefined;
    var incoming: Io.net.IncomingMessage = .init;
    const deadline = Io.Timestamp.now(io, .awake).addDuration(.fromSeconds(2));
    const result = try io.operateTimeout(.{ .net_receive = .{
        .socket_handle = client.socket.handle,
        .message_buffer = (&incoming)[0..1],
        .data_buffer = &scratch,
        .flags = .{},
    } }, .{ .deadline = deadline.withClock(.awake) });

    const maybe_err, const count = result.net_receive;
    std.debug.print("err={any} count={d} data={s}\n", .{ maybe_err, count, incoming.data });
}
