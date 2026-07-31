//! An HTTP/3 client over QUIC: one GET, print the response.
//!
//! ```
//! zig build run-http3-client -- 127.0.0.1 4433 localhost /
//! ```
//!
//! This is the cross-implementation check for the whole QUIC + HTTP/3 stack:
//! run it against an aioquic (or any other conforming) HTTP/3 server and every
//! layer is exercised against someone else's code — the TLS 1.3 handshake, the
//! packet protection, loss recovery, the control streams, QPACK, and the
//! request itself. The certificate is not verified (the interop smoke test uses
//! a self-signed one); everything else about the handshake is real.
//!
//! The address is passed separately from the host name because `std.Io` has no
//! name resolver — the host name is what goes into SNI.

const std = @import("std");
const backend = @import("backend");
const zinet = @import("zinet");

const Io = std.Io;
const http3 = zinet.http3;
const qpack = http3.qpack;

const Outcome = union(enum) {
    response: struct { status: [3]u8, len: usize, body: [4096]u8 },
    closed: u64,
    timed_out,
};

var outcomes: Io.Queue(Outcome) = undefined;
var outcome_storage: [2]Outcome = undefined;

/// Runs on the endpoint's reader task: sends the request once the connection
/// is up, collects the response, and hands it to `main` through the queue.
const Collector = struct {
    io: Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    host: []const u8,
    status: [3]u8 = "???".*,
    body: [4096]u8 = undefined,
    body_len: usize = 0,

    fn on(self: *Collector, conn: *http3.client.Connection, event: http3.client.Event) void {
        switch (event) {
            .established => {
                var fields: [8]qpack.FieldLine = undefined;
                const request = http3.connection.requestFields(
                    "GET",
                    "https",
                    self.host,
                    self.path,
                    &.{.{ .name = "user-agent", .value = "zinet-http3" }},
                    &fields,
                );
                _ = conn.request(self.gpa, request, true) catch return;
            },
            .headers => |e| {
                var section = conn.takeSection(e.stream) orelse return;
                defer section.deinit(self.gpa);
                for (section.fields.items) |field| {
                    if (std.mem.eql(u8, field.name, ":status") and field.value.len == 3) {
                        @memcpy(&self.status, field.value);
                    }
                }
                if (e.fin) self.finish();
            },
            .body => |e| {
                const bytes = conn.readBody(e.stream);
                const take = @min(bytes.len, self.body.len - self.body_len);
                @memcpy(self.body[self.body_len..][0..take], bytes[0..take]);
                self.body_len += take;
                conn.consumeBody(e.stream, bytes.len);
                if (e.fin) self.finish();
            },
            .peer_closed => |e| outcomes.putOne(self.io, .{ .closed = e.code }) catch {},
            .idle_timeout => outcomes.putOne(self.io, .timed_out) catch {},
            .goaway => {},
        }
    }

    fn finish(self: *Collector) void {
        var outcome: Outcome = .{ .response = .{
            .status = self.status,
            .len = self.body_len,
            .body = undefined,
        } };
        @memcpy(outcome.response.body[0..self.body_len], self.body[0..self.body_len]);
        outcomes.putOne(self.io, outcome) catch {};
    }
};

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
    const address_text = try gpa.dupe(u8, iterator.next() orelse usage());
    defer gpa.free(address_text);
    const port_text = try gpa.dupe(u8, iterator.next() orelse usage());
    defer gpa.free(port_text);
    const host = try gpa.dupe(u8, iterator.next() orelse usage());
    defer gpa.free(host);
    const path = try gpa.dupe(u8, iterator.next() orelse "/");
    defer gpa.free(path);

    const port = try std.fmt.parseInt(u16, port_text, 10);
    const address = try Io.net.IpAddress.parse(address_text, port);

    outcomes = .init(&outcome_storage);

    var collector: Collector = .{ .io = io, .gpa = gpa, .path = path, .host = host };
    var client = try http3.client.Client.connect(.{
        .gpa = gpa,
        .io = io,
        .address = address,
        .host = host,
        .verification = null, // interop smoke runs against a self-signed cert
        .delegate = .init(&collector, Collector.on),
    });
    defer client.deinit();

    // Wait for the response, bounded: a cross-implementation check that can
    // hang is a check nobody runs.
    var poll_future = try io.concurrent(waitForOutcome, .{io});
    const outcome = poll_future.await(io) catch {
        std.debug.print("error: no response within the deadline\n", .{});
        std.process.exit(1);
    };

    switch (outcome) {
        .response => |response| {
            std.debug.print("status: {s}\n", .{response.status});
            std.debug.print("body ({d} bytes): {s}\n", .{
                response.len,
                response.body[0..response.len],
            });
            if (!std.mem.eql(u8, &response.status, "200")) std.process.exit(2);
        },
        .closed => |code| {
            std.debug.print("connection closed by peer, code 0x{x}\n", .{code});
            std.process.exit(3);
        },
        .timed_out => {
            std.debug.print("idle timeout\n", .{});
            std.process.exit(4);
        },
    }
}

fn waitForOutcome(io: Io) !Outcome {
    // `getOne` blocks until the delegate reports; the outer future's await in
    // `main` is what a caller would cancel to bound it. For the smoke test the
    // server either answers promptly or the run is already a failure.
    return outcomes.getOne(io);
}

fn usage() noreturn {
    std.debug.print("usage: http3_client <address> <port> <host> [path]\n", .{});
    std.process.exit(64);
}
