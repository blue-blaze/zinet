//! The `std.Io` implementation the tests, examples and benchmarks run on, in its
//! default form: the standard library's thread pool.
//!
//! Zinet takes its `Io` as a parameter, so choosing a backend is the
//! application's business, not the library's. This module exists so that the
//! *tests* can be pointed at a different one with a build flag — see
//! `src/backend/zio.zig` — without the library itself acquiring a dependency.
//! Nothing under `src/` other than test blocks, `examples/` and `bench/` uses it.
//!
//! On this backend every task is an OS thread, which is the reason
//! `Io.Threaded`'s concurrency budget is the scarcest resource Zinet has: a
//! plain connection costs two tasks, a TLS one costs one.

const std = @import("std");
const Io = std.Io;

pub const Runtime = struct {
    threaded: Io.Threaded,

    /// Named so it can be reported by a test that cares which backend it is on.
    pub const name = "threaded";

    /// Fallible for uniformity with backends whose setup can fail. This one
    /// cannot.
    pub fn init(gpa: std.mem.Allocator) !Runtime {
        return .{ .threaded = .init(gpa, .{}) };
    }

    pub fn deinit(rt: *Runtime) void {
        rt.threaded.deinit();
        rt.* = undefined;
    }

    /// Must be called once the runtime is at its final address: the returned
    /// `Io` carries a pointer to it.
    pub fn io(rt: *Runtime) Io {
        return rt.threaded.io();
    }
};
