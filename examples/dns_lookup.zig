//! `zig build run-dns-lookup -- <server-ip> <name> [more names...]`
//!
//! Resolves names against a DNS server given by address, and prints what came
//! back. No server is defaulted: sending every name a program looks up to a
//! third party is the application's decision, not a library's.
//!
//! Compare against `dig`:
//!
//!     dig @1.1.1.1 +short example.com
//!     zig build run-dns-lookup -- 1.1.1.1 example.com

const std = @import("std");
const zinet = @import("zinet");
const backend = @import("backend");
const Io = std.Io;

const log = std.log.scoped(.example);

pub fn main(init: std.process.Init.Minimal) !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug_allocator.deinit() == .leak) std.process.exit(1);
    const gpa = debug_allocator.allocator();

    var runtime = try backend.Runtime.init(gpa);
    defer runtime.deinit();
    const io = runtime.io();

    var iterator = try std.process.Args.Iterator.initAllocator(init.args, gpa);
    defer iterator.deinit();
    _ = iterator.skip();

    const server_text = try gpa.dupe(u8, iterator.next() orelse {
        log.err("usage: dns_lookup <server-ip> <name> [name...]", .{});
        std.process.exit(2);
    });
    defer gpa.free(server_text);

    // Every argument is copied: the iterator's strings do not outlive it.
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |name| gpa.free(name);
        names.deinit(gpa);
    }
    while (iterator.next()) |arg| try names.append(gpa, try gpa.dupe(u8, arg));

    if (names.items.len == 0) {
        log.err("usage: dns_lookup <server-ip> <name> [name...]", .{});
        std.process.exit(2);
    }

    const server = Io.net.Ip4Address.parse(server_text, 53) catch {
        log.err("not an IPv4 address: {s}", .{server_text});
        std.process.exit(2);
    };

    var resolver = zinet.dns.resolver.Resolver.init(.{
        .gpa = gpa,
        .io = io,
        .servers = &.{.{ .ip4 = server }},
    });

    var failures: usize = 0;
    for (names.items) |name| {
        const answer = resolver.resolve(name, 0) catch |err| {
            log.err("{s}: {s}", .{ name, @errorName(err) });
            failures += 1;
            continue;
        };
        if (!answer.canonical.eqlText(name)) {
            log.info("{s} is a CNAME for {s}", .{ name, answer.canonical.slice() });
        }
        for (answer.slice()) |address| {
            switch (address) {
                .ip4 => |v4| log.info("{s} A {d}.{d}.{d}.{d} (ttl {d})", .{
                    name, v4.bytes[0], v4.bytes[1], v4.bytes[2], v4.bytes[3], answer.ttl,
                }),
                .ip6 => |v6| {
                    var text: [64]u8 = undefined;
                    var written: usize = 0;
                    for (0..8) |group| {
                        if (group > 0) {
                            text[written] = ':';
                            written += 1;
                        }
                        const value = std.mem.readInt(u16, v6.bytes[group * 2 ..][0..2], .big);
                        written += (std.fmt.bufPrint(text[written..], "{x}", .{value}) catch
                            return error.BufferTooSmall).len;
                    }
                    log.info("{s} AAAA {s} (ttl {d})", .{ name, text[0..written], answer.ttl });
                },
            }
        }
    }

    if (failures > 0) std.process.exit(1);
}
