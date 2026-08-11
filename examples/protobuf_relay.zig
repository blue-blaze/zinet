//! Reads length-prefixed protobuf messages from stdin, decodes them, and writes
//! each one back re-encoded from the decoded value.
//!
//! ```
//! zig build run-protobuf_relay < in.bin > out.bin
//! ```
//!
//! It exists to be driven by somebody else's implementation. `scripts/protobuf-interop.py`
//! encodes messages with Google's Python `protobuf`, feeds them here, and parses
//! what comes back — so a difference in either direction shows up as a decode
//! failure on the Python side rather than as a passing test written against our
//! own encoder. The unit tests check fixed vectors; this checks a live peer.
//!
//! The message is a subset of `google.protobuf.FileDescriptorProto`, chosen
//! because Python's protobuf ships it pre-generated, so the interop script needs
//! no `protoc` and no `.proto` file. The subset is also the point: the fields
//! this schema does not declare have to survive being skipped, which is
//! protobuf's forward compatibility and the thing most likely to be got wrong.
//!
//! SECURITY: this reads from a pipe, not a socket, and has no peer to
//! authenticate. Every bound the decoder takes is stated below rather than left
//! at a default, because a relay is exactly where an unbounded length would hurt.

const std = @import("std");
const zinet = @import("zinet");
const backend = @import("backend");
const protobuf = zinet.protobuf;

const log = std.log.scoped(.example);

/// A subset of `FileDescriptorProto`: name, package, and the nested message
/// types, each with its fields. Enough nesting to be worth checking, and short
/// of the whole descriptor on purpose.
const FileDescriptorProto = struct {
    name: []const u8 = "",
    package: []const u8 = "",
    message_type: []const DescriptorProto = &.{},

    pub const proto = .{ .name = 1, .package = 2, .message_type = 4 };
};

const DescriptorProto = struct {
    name: []const u8 = "",
    field: []const FieldDescriptorProto = &.{},

    pub const proto = .{ .name = 1, .field = 2 };
};

const FieldDescriptorProto = struct {
    name: []const u8 = "",
    number: i32 = 0,
    json_name: []const u8 = "",

    pub const proto = .{ .name = 1, .number = 3, .json_name = 10 };
};

const limits: protobuf.Limits = .{
    .max_message_len = 1 << 20,
    .max_nesting_depth = 8,
    .max_elements = 4096,
};

pub fn main(init: std.process.Init.Minimal) !void {
    _ = init;
    switch (@import("builtin").mode) {
        .Debug => log.warn("build: debug — unoptimized, not a performance measurement", .{}),
        else => log.info("build: {t}", .{@import("builtin").mode}),
    }

    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer if (debug.deinit() == .leak) @panic("leak");
    const gpa = debug.allocator();

    var runtime = try backend.Runtime.init(gpa);
    defer runtime.deinit();
    const io = runtime.io();

    var stdin_buffer: [4096]u8 = undefined;
    var stdout_buffer: [4096]u8 = undefined;
    var stdin = std.Io.File.stdin().readerStreaming(io, &stdin_buffer);
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);

    // Everything at once: a relay is not where streaming matters, and reading the
    // whole input keeps the framing logic in one visible place.
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);
    while (true) {
        var chunk: [4096]u8 = undefined;
        const n = stdin.interface.readSliceShort(&chunk) catch break;
        if (n == 0) break;
        try input.appendSlice(gpa, chunk[0..n]);
    }

    var relayed: usize = 0;
    var pos: usize = 0;
    while (pos < input.items.len) {
        const rest = input.items[pos..];
        const prefix = protobuf.decodeVarint(rest) catch |err| {
            log.err("length prefix at offset {d}: {t}", .{ pos, err });
            return error.InvalidInput;
        };
        if (prefix.value > limits.max_message_len) {
            log.err("message at offset {d} announces {d} bytes", .{ pos, prefix.value });
            return error.InvalidInput;
        }
        const length: usize = @intCast(prefix.value);
        if (rest.len - prefix.len < length) {
            log.err("message at offset {d} is truncated", .{pos});
            return error.InvalidInput;
        }
        const body = rest[prefix.len..][0..length];
        pos += prefix.len + length;

        var decoded = protobuf.decode(FileDescriptorProto, gpa, body, limits) catch |err| {
            log.err("message {d}: {t}", .{ relayed, err });
            return error.InvalidInput;
        };
        defer decoded.deinit(gpa);

        // Re-encoded from the decoded value rather than echoed, so that a field
        // this decoder dropped or widened comes back wrong instead of coming back
        // unchanged.
        const size = protobuf.encodedLen(FileDescriptorProto, &decoded.value);
        const out = try gpa.alloc(u8, size);
        defer gpa.free(out);
        const written = protobuf.encode(FileDescriptorProto, out, &decoded.value);

        var out_prefix: [protobuf.max_length_prefix_len]u8 = undefined;
        const out_prefix_len = protobuf.encodeVarint(&out_prefix, written);
        try stdout.interface.writeAll(out_prefix[0..out_prefix_len]);
        try stdout.interface.writeAll(out[0..written]);
        relayed += 1;
    }
    try stdout.interface.flush();
    log.info("relayed {d} messages", .{relayed});
}
