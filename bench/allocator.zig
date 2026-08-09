//! Which allocator a benchmark measures through, and why that is a decision rather than a
//! detail.
//!
//! Every benchmark here used `DebugAllocator`, because a leak failing the run is worth having.
//! But `DebugAllocator` returns pages to the kernel as it frees them, so on a protocol that
//! allocates per request it costs more than the network does. A profile of the HTTP/2 server
//! under load settled it: of the samples where the server was doing anything at all, **51 % were
//! in the allocator** — `__munmap` alone was 7 % of the whole profile — against 26 % in `readv`
//! and `__sendmsg` and 11 % in the protocol itself.
//!
//! That made HTTP/2 and HTTP/3 look slower than HTTP/1.1 for a reason belonging to neither: they
//! allocate a stream channel, a pipeline and a handler per request, while an HTTP/1.1 connection
//! allocates a request arena and nothing else. The harness was charging them for its own choice
//! of allocator — the same shape of mistake as measuring a Debug build, which this repository
//! has already made once.
//!
//! So the default is `smp_allocator`, which is what a server built from this would deploy with,
//! and the leak check is one argument away:
//!
//! ```
//! ./zig-out/bin/http2_bench 1 32 3 4              # measure
//! ./zig-out/bin/http2_bench 1 32 3 4 leakcheck    # check for leaks instead
//! ```
//!
//! Both are worth running and they answer different questions. The leak-checking run is the one
//! to believe about correctness; the default is the one to believe about speed.

const std = @import("std");

/// The word that selects the leak-checking allocator, recognised in any argument position so
/// that it can be appended to a role invocation without disturbing the positional arguments.
pub const leak_check_flag = "leakcheck";

pub const Choice = struct {
    debug: std.heap.DebugAllocator(.{}) = .init,
    leak_check: bool = false,

    /// Scans the raw arguments, which is deliberately done without allocating: choosing the
    /// allocator cannot depend on having one.
    pub fn init(args: std.process.Args) Choice {
        return .{ .leak_check = wantsLeakCheck(args) };
    }

    pub fn allocator(self: *Choice) std.mem.Allocator {
        return if (self.leak_check) self.debug.allocator() else std.heap.smp_allocator;
    }

    /// Fails the process on a leak, so that a leak-checking run cannot pass quietly.
    pub fn deinit(self: *Choice) void {
        if (!self.leak_check) return;
        if (self.debug.deinit() == .leak) {
            std.log.err("benchmark leaked memory", .{});
            std.process.exit(1);
        }
    }
};

fn wantsLeakCheck(args: std.process.Args) bool {
    var iterator = args.iterate();
    while (iterator.next()) |raw| {
        if (std.mem.eql(u8, raw, leak_check_flag)) return true;
    }
    return false;
}
