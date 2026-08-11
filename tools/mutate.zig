//! Mutation self-checking, as a build step rather than a habit.
//!
//! Every bound and every rule in this repository is supposed to be enforced by a test. The way
//! that has been verified, repeatedly, is by hand: break the fix on purpose, run the suite, and
//! require it to fail. That practice has earned its keep — it is how a writability bound was
//! found to be checked in the wrong place, how a `max_tcp_reply` ceiling was found to be
//! unobservable, and how a DNS read deadline was found to be no bound at all. It has also found
//! several checks that *no* input could distinguish, which were then deleted.
//!
//! REVIEW.md's thesis is that a reviewer's attention is not a control. Neither is a habit. This
//! turns the catalogue into something the build runs:
//!
//! ```
//! zig build mutate            # every mutation
//! zig build mutate -- dns     # only those whose name contains "dns"
//! ```
//!
//! For each mutation: apply it to the source, run `zig build test`, require that the run fails,
//! and put the file back. A mutation the suite *survives* is reported as a survivor and makes
//! the step fail, because it means the rule it broke is enforced by nothing.
//!
//! Two properties matter more than the checking itself.
//!
//! **The tree is always restored.** The original bytes are held in memory *and* written to a
//! backup file before anything is modified, and the backup is removed only after the restore is
//! verified byte for byte. If a previous run died between those points, the next run refuses to
//! start and says which file to restore from where. A tool that can leave a mutation behind is
//! worse than no tool: the mutation would then be indistinguishable from a bug someone wrote.
//!
//! **A stale mutation is an error, not a skip.** Each entry must match its file exactly once.
//! Zero matches means the code moved and the entry is now checking nothing; more than one means
//! the entry is ambiguous about what it breaks. Either way the step fails and names the entry,
//! because a catalogue that quietly stops applying is the thing this file exists to prevent.

const std = @import("std");
const Io = std.Io;

const log = std.log.scoped(.mutate);

/// What a mutation is expected to do to the build.
const Expect = enum {
    /// A test must fail. The strongest outcome: some assertion observed the difference.
    test_failure,
    /// The build must fail to compile. Weaker — it says the code will not build without the
    /// rule, not that a test covers it — and recorded as such so nobody mistakes one for the
    /// other.
    compile_error,
    /// The build must *pass*. Only the canary wants this: it is how the harness proves it is
    /// running the tests rather than failing for its own reasons.
    survives,
};

const Mutation = struct {
    /// Short, and descriptive of the *rule* rather than of the edit.
    name: []const u8,
    path: []const u8,
    find: []const u8,
    replace: []const u8,
    expect: Expect = .test_failure,
    /// Why breaking this should be caught, in one line, for whoever reads a survivor report.
    because: []const u8,
};

/// The catalogue. Every entry here has been run by hand at the commit that introduced it; this
/// file is what keeps them running afterwards.
const catalogue = [_]Mutation{
    .{
        .name = "dns/rdata-containment",
        .path = "src/codec/dns.zig",
        .find = "if (inner.at != rdata_start + rdlength) return error.BadRecord;",
        .replace = "if (inner.at > rdata_start + rdlength) return error.BadRecord;",
        .because = "RDLENGTH must contain the name exactly; stopping short leaves bytes that are neither name nor padding",
    },
    .{
        .name = "dns/tcp-fallback",
        .path = "src/codec/dns/resolver.zig",
        .find = "if (!self.options.tcp_fallback) return error.Truncated;",
        .replace = "if (true) return error.Truncated;",
        .because = "a truncated datagram answer must be asked again over TCP (RFC 1035 §4.2.2)",
    },
    .{
        .name = "dns/tcp-reply-ceiling",
        .path = "src/codec/dns/resolver.zig",
        .find = "if (announced > self.options.max_tcp_reply) return error.Truncated;",
        .replace = "if (announced > 65535) return error.Truncated;",
        .because = "a sixteen-bit length prefix is the peer's claim, and must not decide what this process allocates",
    },
    .{
        .name = "server/connection-ceiling",
        .path = "src/bootstrap.zig",
        .find = "if (server.liveCount() >= limit) {",
        .replace = "if (false and limit == 0) {",
        .because = "max_connections must refuse past its ceiling rather than accept without bound",
    },
    .{
        .name = "server/refusal-is-not-failure",
        .path = "src/bootstrap.zig",
        .find = "_ = server.stats.refused_at_capacity.fetchAdd(1, .monotonic);",
        .replace = "_ = server.stats.rejected.fetchAdd(1, .monotonic);",
        .because = "at-capacity and unable-to-serve are different facts and must not share a counter",
    },
    .{
        .name = "datagram/tick-attribution",
        .path = "src/datagram.zig",
        .find = "if (due(next_tick, now)) {",
        .replace = "if (channel.options.tick_interval != null) {",
        .because = "close polling must not set the tick cadence; each deadline answers for itself",
    },
    .{
        .name = "http1/transfer-coding-count",
        .path = "src/codec/http.zig",
        .find = "if (codings != 1) return .unsupported;",
        .replace = "if (codings == 0) return .unsupported;",
        .because = "`gzip, chunked` is not chunked; framing every hop must agree on cannot be guessed",
    },
    .{
        .name = "tls13/plaintext-alert-window",
        .path = "src/codec/tls13/session.zig",
        .find = ".alert => if (keyed) .refuse else .accept,",
        .replace = ".alert => if (keyed and false) .refuse else .accept,",
        .because = "an unprotected alert after keys exist is unauthenticated, and acting on it lets anyone truncate the connection",
    },
    .{
        .name = "quic/fin-after-reap",
        .path = "src/codec/quic/connection.zig",
        .find = "} else if (sf.fin) {",
        .replace = "} else if (false) {",
        .because = "a FIN whose stream was already reaped is still a close, and HTTP/3 makes it a connection error",
    },
    .{
        .name = "http3/pending-sections-ceiling",
        .path = "src/codec/http3/connection.zig",
        .find = "if (req.sections.items.len >= self.max_pending_sections) return self.fail(0x0107);",
        .replace = "if (false) return self.fail(0x0107);",
        .because = "§4.1 permits unlimited interim responses, each of which allocates a section",
    },
    .{
        .name = "http3/pending-events-ceiling",
        .path = "src/codec/http3/connection.zig",
        .find = "if (self.events.items.len - self.event_cursor >= self.max_pending_events) {",
        .replace = "if (false) {",
        .because = "\"the application will keep up\" is not a bound",
    },
    .{
        .name = "protobuf/negative-int-width",
        .path = "src/codec/protobuf.zig",
        .find = "    const wide: i64 = value;\n    return @bitCast(wide);",
        .replace = "    const wide: i64 = value;\n    return @bitCast(wide & 0xffffffff);",
        .because = "a negative int32 is a 64-bit two's complement varint, which is ten bytes",
    },
    .{
        .name = "protobuf/nesting-bound",
        .path = "src/codec/protobuf.zig",
        .find = "    if (depth >= limits.max_nesting_depth) return error.NestingTooDeep;",
        .replace = "    if (depth >= 1_000_000) return error.NestingTooDeep;",
        .because = "a peer can announce any nesting depth in a handful of bytes",
    },
    .{
        .name = "quic/post-handshake-ticket",
        .path = "src/codec/quic/client.zig",
        .find = "                .new_session_ticket => {},",
        .replace = "                .new_session_ticket => return error.UnexpectedMessage,",
        .because = "a legal NewSessionTicket killed every connection to an OpenSSL-based server",
    },
    .{
        .name = "channel/flush-not-past-close",
        .path = "src/channel.zig",
        .find = "fn moreDataFollows(rest: []const Outbound) bool {",
        .replace = "fn moreDataFollows(rest: []const Outbound) bool { if (rest.len >= 0) return true;",
        .because = "batching a flush past a close loses the bytes a closing handshake exists to send",
    },
    .{
        .name = "http3/short-write-residue",
        .path = "src/codec/http3/connection.zig",
        .find = "if (offset == bytes.len) return;",
        .replace = "if (offset <= bytes.len) return;",
        .because = "bytes QUIC did not accept must be staged, or a frame header goes out with a payload that never follows",
    },
};

/// A mutation nothing can possibly depend on. It belongs in the catalogue permanently: if this
/// one is ever reported as caught, the tool is failing the child build for a reason unrelated to
/// the mutation — which is exactly what happened the first time it was written, when a child
/// that could not resolve its cache directory made all twelve entries look caught while running
/// no tests at all.
const canary: Mutation = .{
    .name = "canary/must-survive",
    .path = "src/root.zig",
    .find = "//! Zinet",
    .replace = "//! Zinet (mutated by the canary; nothing should notice)",
    .expect = .survives,
    .because = "a doc comment: if breaking this 'fails' the suite, the harness is broken, not the code",
};

const Outcome = enum { caught, survived, stale, ambiguous };

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The child build needs this process's environment. `std.process.spawn` hands a child an
    // empty one by default, and `zig build` without HOME cannot resolve its cache — it exits
    // with "unable to resolve zig cache directory" before running a single test, which from
    // here is indistinguishable from a mutation the suite caught. The first version of this
    // tool reported twelve out of twelve caught while running no tests at all; the self-check
    // in the catalogue is what exposed it, and is the reason it stays there.
    var environ: std.process.Environ.Map = .init(gpa);
    defer environ.deinit();
    try environ.putPosixBlock(init.environ.block.view());

    var iterator = try std.process.Args.Iterator.initAllocator(init.args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();

    // build.zig passes the compiler's own path, so the child build uses the same one that is
    // running this — picking `zig` off PATH would silently measure a different toolchain.
    const zig_exe = iterator.next() orelse {
        log.err("usage: mutate <zig executable> [name filter]", .{});
        return error.MissingZigExecutable;
    };
    const filter = iterator.next();

    var caught: usize = 0;
    var survived: usize = 0;
    var skipped: usize = 0;
    var broken: usize = 0;

    for (catalogue ++ [_]Mutation{canary}) |mutation| {
        if (filter) |needle| {
            if (std.mem.indexOf(u8, mutation.name, needle) == null) {
                skipped += 1;
                continue;
            }
        }

        const outcome = try run(gpa, io, .{
            .zig_exe = zig_exe,
            .environ = &environ,
        }, mutation);
        switch (outcome) {
            .caught => {
                caught += 1;
                log.info("caught   {s}", .{mutation.name});
            },
            .survived => {
                survived += 1;
                if (mutation.expect == .survives) {
                    log.err("BROKEN HARNESS {s}", .{mutation.name});
                    log.err("         the build failed on a change nothing depends on, so every", .{});
                    log.err("         \"caught\" in this run is unreliable: {s}", .{mutation.because});
                } else {
                    log.err("SURVIVED {s}", .{mutation.name});
                    log.err("         nothing failed when this was broken: {s}", .{mutation.because});
                    log.err("         {s}", .{mutation.path});
                }
            },
            .stale => {
                broken += 1;
                log.err("STALE    {s}: no match in {s}", .{ mutation.name, mutation.path });
                log.err("         the code moved and this entry now checks nothing", .{});
            },
            .ambiguous => {
                broken += 1;
                log.err("AMBIGUOUS {s}: more than one match in {s}", .{ mutation.name, mutation.path });
            },
        }
    }

    log.info("{d} caught, {d} survived, {d} stale or ambiguous, {d} filtered out", .{
        caught, survived, broken, skipped,
    });
    if (survived > 0 or broken > 0) std.process.exit(1);
}

/// Where the child build gets its compiler and its caches.
const Toolchain = struct {
    zig_exe: []const u8,
    environ: *const std.process.Environ.Map,
};

fn run(gpa: std.mem.Allocator, io: Io, toolchain: Toolchain, mutation: Mutation) !Outcome {
    const cwd = Io.Dir.cwd();
    const original = try cwd.readFileAlloc(io, mutation.path, gpa, .limited(4 << 20));
    defer gpa.free(original);

    const occurrences = std.mem.count(u8, original, mutation.find);
    if (occurrences == 0) return .stale;
    if (occurrences > 1) return .ambiguous;

    const mutated = try std.mem.replaceOwned(u8, gpa, original, mutation.find, mutation.replace);
    defer gpa.free(mutated);

    // The backup exists for the case this program does not get to finish: a crash between the
    // write and the restore would otherwise leave a mutation in the tree, and a mutation left in
    // the tree is indistinguishable from a defect someone introduced.
    const backup_path = try std.fmt.allocPrint(gpa, "{s}.mutate-backup", .{mutation.path});
    defer gpa.free(backup_path);
    if (cwd.access(io, backup_path, .{})) |_| {
        log.err("a backup already exists: {s}", .{backup_path});
        log.err("a previous run did not finish; restore it over {s} before continuing", .{mutation.path});
        return error.UnfinishedPreviousRun;
    } else |_| {}

    try cwd.writeFile(io, .{ .sub_path = backup_path, .data = original });
    try cwd.writeFile(io, .{ .sub_path = mutation.path, .data = mutated });

    const build_failed = runTests(io, toolchain) catch |err| {
        try restore(io, cwd, mutation.path, original, backup_path);
        return err;
    };
    try restore(io, cwd, mutation.path, original, backup_path);

    return switch (mutation.expect) {
        .test_failure, .compile_error => if (build_failed) .caught else .survived,
        // Inverted on purpose: for the canary, a passing build is the expected outcome and a
        // failing one means the harness is broken.
        .survives => if (build_failed) .survived else .caught,
    };
}

/// Puts the file back and verifies it, then removes the backup. The order matters: the backup is
/// the only copy that survives this process dying, so it goes last.
fn restore(io: Io, cwd: Io.Dir, path: []const u8, original: []const u8, backup_path: []const u8) !void {
    try cwd.writeFile(io, .{ .sub_path = path, .data = original });
    var check_buffer: [4096]u8 = undefined;
    var file = try cwd.openFile(io, path, .{});
    defer file.close(io);
    var reader = file.reader(io, &check_buffer);
    var offset: usize = 0;
    while (true) {
        const chunk = reader.interface.peekGreedy(1) catch break;
        if (offset + chunk.len > original.len) return error.RestoreMismatch;
        if (!std.mem.eql(u8, chunk, original[offset..][0..chunk.len])) return error.RestoreMismatch;
        offset += chunk.len;
        reader.interface.toss(chunk.len);
    }
    if (offset != original.len) return error.RestoreMismatch;
    try cwd.deleteFile(io, backup_path);
}

/// True when the build failed, which is what a caught mutation looks like.
///
/// The child's output is inherited on purpose. A tool that hides the build it depends on is a
/// tool whose "caught" cannot be distinguished from "did not run", which is the mistake this
/// function was written with the first time.
fn runTests(io: Io, toolchain: Toolchain) !bool {
    var child = try std.process.spawn(io, .{
        // This process's environment, which is what lets the child find its caches. Passing
        // `--global-cache-dir` was tried first and this toolchain rejects the flag its own
        // `--help` advertises, so the environment is the supported route.
        .environ_map = toolchain.environ,
        .argv = &.{ toolchain.zig_exe, "build", "test" },
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| code != 0,
        else => true,
    };
}
