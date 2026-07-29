//! The same `std.Io` seam as `threaded.zig`, backed by
//! [zio](https://github.com/lalinsky/zio) instead of the standard library's
//! thread pool. Selected with `-Dio=zio`.
//!
//! Why this file exists at all: `std.Io.Evented` is declared in 0.16.0 but none
//! of its three backends compile, so there is no way to run Zinet on fibers
//! using only the standard library. zio implements every field of
//! `std.Io.VTable` and works on Linux, Windows and the BSDs, which makes it the
//! available answer today.
//!
//! This is the *only* file in the repository that imports zio, and nothing the
//! library itself does reaches it. A consumer depending on `zinet` gets the
//! threaded seam and no third-party code; the dependency is marked lazy, so it is
//! not even downloaded unless this backend is selected.
//!
//! One known difference from the threaded backend, which is a zio defect rather
//! than a design difference: `operateTimeout` with `.net_receive` panics on a
//! *stream* socket, because `recvmsg` leaves `msg_name` untouched on a connected
//! socket and zio converts that buffer unconditionally (`src/io.zig:2406` into
//! `src/io.zig:1871`, `else => unreachable`), where the standard library defines
//! the case away (`std/Io/Threaded.zig:14181`). That primitive is what
//! `Channel.receiveBounded` and `tls.PumpReader` are built on, so anything using
//! ticks, task hopping or TLS is affected until it is fixed upstream.

const std = @import("std");
const zio = @import("zio");
const Io = std.Io;

pub const Runtime = struct {
    /// A pointer, because `zio.Runtime.init` allocates and returns one.
    rt: *zio.Runtime,

    pub const name = "zio";

    pub fn init(gpa: std.mem.Allocator) !Runtime {
        return .{ .rt = try zio.Runtime.init(gpa, .{}) };
    }

    pub fn deinit(rt: *Runtime) void {
        rt.rt.deinit();
        rt.* = undefined;
    }

    pub fn io(rt: *Runtime) Io {
        return rt.rt.io();
    }
};
