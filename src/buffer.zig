//! Byte buffers with an explicit ownership model.
//!
//! `Buffer` is Zinet's answer to Netty's `ByteBuf`: a growable byte store with
//! separate reader and writer positions, so that producing and consuming code
//! do not have to agree on a shared cursor.
//!
//! Unlike Netty, a `Buffer` is **not** reference counted. It has exactly one
//! owner at any point in time. Ownership is transferred by value (`move`) and
//! released by exactly one call to `deinit`. Reference counted sharing is
//! available as a separate, opt-in layer (see `SharedBuffer`), so that the
//! common case pays neither the atomics nor the complexity.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Where a buffer's memory goes when it is released.
///
/// A pooled buffer travels arbitrarily far from the pool that handed it out —
/// into a message, along a pipeline, into a write queue — and whoever finally
/// releases it has no idea where it came from. Carrying the recycler in the
/// buffer is what lets recycling work without every intermediate step knowing
/// about pools.
pub const Recycler = struct {
    context: *anyopaque,
    /// Takes the buffer back. Must not call `Buffer.deinit`, which would recurse.
    releaseFn: *const fn (context: *anyopaque, buffer: *Buffer) void,

    pub fn release(recycler: Recycler, buffer: *Buffer) void {
        recycler.releaseFn(recycler.context, buffer);
    }
};

/// A growable byte buffer with independent reader and writer indices.
///
/// Layout of `bytes`:
///
/// ```
/// +-------------------+------------------+------------------+
/// | discardable bytes |  readable bytes  |  writable bytes  |
/// +-------------------+------------------+------------------+
/// 0      <=      reader_index   <=   writer_index   <=   capacity
/// ```
///
/// The class invariant `0 <= reader_index <= writer_index <= bytes.len` holds
/// on entry to and exit from every public function, and is checked by
/// `assertInvariants` in safe builds.
pub const Buffer = struct {
    /// Backing store. Owned by this buffer; may be empty (`&.{}`) before the
    /// first write, in which case no allocation has been performed yet.
    bytes: []u8,
    /// Index of the next byte to be read.
    reader_index: usize,
    /// Index of the next byte to be written.
    writer_index: usize,
    /// Hard upper bound on `bytes.len`. Growth beyond this fails with
    /// `error.BufferFull` rather than allocating without limit.
    max_capacity: usize,
    /// Set when this buffer came from a pool, so `deinit` returns it there
    /// instead of to the allocator.
    recycler: ?Recycler = null,

    /// Default ceiling for a buffer that does not need a tighter bound.
    /// 16 MiB is far above any sane frame size yet still bounded.
    pub const default_max_capacity: usize = 16 * 1024 * 1024;

    pub const Error = error{
        /// Growing the buffer would exceed `max_capacity`.
        BufferFull,
    } || Allocator.Error;

    pub const ReadError = error{
        /// Fewer readable bytes than the operation requires.
        EndOfBuffer,
    };

    pub const Options = struct {
        /// Bytes to reserve up front. Zero means "do not allocate yet".
        capacity: usize = 0,
        max_capacity: usize = default_max_capacity,
    };

    /// An empty buffer that owns nothing. Safe to `deinit` as-is; safe to
    /// write to, which allocates on demand.
    pub const empty: Buffer = .{
        .bytes = &.{},
        .reader_index = 0,
        .writer_index = 0,
        .max_capacity = default_max_capacity,
        .recycler = null,
    };

    /// Creates a buffer, reserving `options.capacity` bytes.
    ///
    /// The caller owns the result and must release it with `deinit`.
    pub fn init(gpa: Allocator, options: Options) Error!Buffer {
        assert(options.capacity <= options.max_capacity);
        var buffer: Buffer = .{
            .bytes = &.{},
            .reader_index = 0,
            .writer_index = 0,
            .max_capacity = options.max_capacity,
        };
        if (options.capacity > 0) {
            buffer.bytes = try gpa.alloc(u8, options.capacity);
        }
        buffer.assertInvariants();
        return buffer;
    }

    /// Creates a buffer that owns a copy of `source`, positioned so that all
    /// of `source` is readable.
    ///
    /// The caller owns the result and must release it with `deinit`.
    pub fn initFrom(gpa: Allocator, source: []const u8, options: Options) Error!Buffer {
        assert(options.max_capacity >= source.len);
        var buffer = try init(gpa, .{
            .capacity = @max(options.capacity, source.len),
            .max_capacity = options.max_capacity,
        });
        errdefer buffer.deinit(gpa);
        @memcpy(buffer.bytes[0..source.len], source);
        buffer.writer_index = source.len;
        buffer.assertInvariants();
        return buffer;
    }

    /// Releases the buffer: back to its pool when it came from one, otherwise
    /// to `gpa`. Call exactly once per buffer.
    pub fn deinit(buffer: *Buffer, gpa: Allocator) void {
        if (buffer.recycler) |recycler| {
            recycler.release(buffer);
            buffer.* = undefined;
            return;
        }
        gpa.free(buffer.bytes);
        buffer.* = undefined;
    }

    /// Transfers ownership out of `buffer`, leaving it empty.
    ///
    /// This makes ownership transfer explicit at call sites: after `move`, the
    /// source buffer is still valid but owns nothing, so a stray `deinit` on
    /// it is harmless and cannot double free.
    pub fn move(buffer: *Buffer) Buffer {
        const moved = buffer.*;
        buffer.* = .{
            .bytes = &.{},
            .reader_index = 0,
            .writer_index = 0,
            .max_capacity = buffer.max_capacity,
            .recycler = null,
        };
        return moved;
    }

    /// Asserts the class invariant. Compiles to nothing in `ReleaseFast`.
    pub fn assertInvariants(buffer: *const Buffer) void {
        assert(buffer.reader_index <= buffer.writer_index);
        assert(buffer.writer_index <= buffer.bytes.len);
        assert(buffer.bytes.len <= buffer.max_capacity);
    }

    // -- Capacity ----------------------------------------------------------

    pub fn capacity(buffer: *const Buffer) usize {
        return buffer.bytes.len;
    }

    /// Number of bytes available to read.
    pub fn readableLen(buffer: *const Buffer) usize {
        buffer.assertInvariants();
        return buffer.writer_index - buffer.reader_index;
    }

    /// Number of bytes that can be written without growing.
    pub fn writableLen(buffer: *const Buffer) usize {
        buffer.assertInvariants();
        return buffer.bytes.len - buffer.writer_index;
    }

    pub fn isReadable(buffer: *const Buffer) bool {
        return buffer.readableLen() > 0;
    }

    /// The readable region. Invalidated by any operation that may grow or
    /// compact the buffer.
    pub fn readableSlice(buffer: *const Buffer) []const u8 {
        buffer.assertInvariants();
        return buffer.bytes[buffer.reader_index..buffer.writer_index];
    }

    /// Mutable view of the readable region, for in-place transformations such
    /// as WebSocket unmasking.
    pub fn readableSliceMut(buffer: *Buffer) []u8 {
        buffer.assertInvariants();
        return buffer.bytes[buffer.reader_index..buffer.writer_index];
    }

    /// The writable region. Invalidated by any operation that may grow or
    /// compact the buffer.
    pub fn writableSlice(buffer: *Buffer) []u8 {
        buffer.assertInvariants();
        return buffer.bytes[buffer.writer_index..];
    }

    /// Ensures at least `additional` writable bytes are available, growing or
    /// compacting as needed.
    ///
    /// Prefers reclaiming already-read space over allocating: if discarding
    /// read bytes alone satisfies the request, no allocation happens.
    pub fn ensureWritable(buffer: *Buffer, gpa: Allocator, additional: usize) Error!void {
        buffer.assertInvariants();
        if (buffer.writableLen() >= additional) return;

        const readable = buffer.readableLen();
        // Checked before anything else uses it. An unchecked `readable +
        // additional` would wrap in ReleaseFast, where the assertions that
        // would have caught it are compiled out, and the compaction path below
        // would then hand back a slice shorter than the caller was promised.
        const required = std.math.add(usize, readable, additional) catch
            return error.BufferFull;

        if (required <= buffer.bytes.len) {
            buffer.discardReadBytes();
            assert(buffer.writableLen() >= additional);
            return;
        }
        if (required > buffer.max_capacity) return error.BufferFull;

        const new_capacity = @min(
            buffer.max_capacity,
            @max(growCapacity(buffer.bytes.len), required, 64),
        );
        assert(new_capacity >= required);

        // Compact first so the copy performed by realloc is not wasted on
        // bytes that have already been consumed.
        buffer.discardReadBytes();
        buffer.bytes = try gpa.realloc(buffer.bytes, new_capacity);

        buffer.assertInvariants();
        assert(buffer.writableLen() >= additional);
    }

    /// Moves readable bytes to the front, reclaiming discardable space.
    pub fn discardReadBytes(buffer: *Buffer) void {
        buffer.assertInvariants();
        if (buffer.reader_index == 0) return;
        const readable = buffer.readableLen();
        if (readable > 0) {
            std.mem.copyForwards(
                u8,
                buffer.bytes[0..readable],
                buffer.bytes[buffer.reader_index..buffer.writer_index],
            );
        }
        buffer.reader_index = 0;
        buffer.writer_index = readable;
        buffer.assertInvariants();
    }

    /// Drops all content, keeping the allocation for reuse.
    pub fn clear(buffer: *Buffer) void {
        buffer.reader_index = 0;
        buffer.writer_index = 0;
        buffer.assertInvariants();
    }

    /// Growth factor of 1.5, which reuses freed blocks better than doubling.
    /// Growth factor of 1.5, saturating rather than wrapping. A request that
    /// large fails on the allocation instead, which is the honest failure.
    fn growCapacity(current: usize) usize {
        return current +| (current / 2) +| 1;
    }

    // -- Writing -----------------------------------------------------------

    pub fn writeBytes(buffer: *Buffer, gpa: Allocator, source: []const u8) Error!void {
        try buffer.ensureWritable(gpa, source.len);
        @memcpy(buffer.bytes[buffer.writer_index..][0..source.len], source);
        buffer.writer_index += source.len;
        buffer.assertInvariants();
    }

    pub fn writeByte(buffer: *Buffer, gpa: Allocator, byte: u8) Error!void {
        try buffer.writeBytes(gpa, &.{byte});
    }

    /// Writes `byte` `n` times.
    pub fn writeByteNTimes(buffer: *Buffer, gpa: Allocator, byte: u8, n: usize) Error!void {
        try buffer.ensureWritable(gpa, n);
        @memset(buffer.bytes[buffer.writer_index..][0..n], byte);
        buffer.writer_index += n;
        buffer.assertInvariants();
    }

    /// Writes `value` in the given byte order.
    pub fn writeInt(
        buffer: *Buffer,
        gpa: Allocator,
        comptime T: type,
        value: T,
        endian: std.builtin.Endian,
    ) Error!void {
        const size = @divExact(@typeInfo(T).int.bits, 8);
        try buffer.ensureWritable(gpa, size);
        std.mem.writeInt(T, buffer.bytes[buffer.writer_index..][0..size], value, endian);
        buffer.writer_index += size;
        buffer.assertInvariants();
    }

    /// Reserves `n` writable bytes and returns them for direct filling. The
    /// writer index has already advanced past them, so the caller must fill
    /// the whole slice.
    ///
    /// The returned slice is invalidated by any subsequent buffer operation.
    pub fn reserve(buffer: *Buffer, gpa: Allocator, n: usize) Error![]u8 {
        try buffer.ensureWritable(gpa, n);
        const reserved = buffer.bytes[buffer.writer_index..][0..n];
        buffer.writer_index += n;
        buffer.assertInvariants();
        return reserved;
    }

    /// Advances the writer index over bytes written directly into
    /// `writableSlice`.
    pub fn commit(buffer: *Buffer, n: usize) void {
        assert(n <= buffer.writableLen());
        buffer.writer_index += n;
        buffer.assertInvariants();
    }

    // -- Reading -----------------------------------------------------------

    /// Consumes and returns the next `n` readable bytes.
    ///
    /// The returned slice aliases the buffer and is invalidated by any
    /// subsequent buffer operation. It does **not** transfer ownership.
    pub fn readBytes(buffer: *Buffer, n: usize) ReadError![]const u8 {
        if (buffer.readableLen() < n) return error.EndOfBuffer;
        const taken = buffer.bytes[buffer.reader_index..][0..n];
        buffer.reader_index += n;
        buffer.assertInvariants();
        return taken;
    }

    pub fn readByte(buffer: *Buffer) ReadError!u8 {
        const taken = try buffer.readBytes(1);
        return taken[0];
    }

    pub fn readInt(
        buffer: *Buffer,
        comptime T: type,
        endian: std.builtin.Endian,
    ) ReadError!T {
        const size = @divExact(@typeInfo(T).int.bits, 8);
        if (buffer.readableLen() < size) return error.EndOfBuffer;
        const taken = buffer.bytes[buffer.reader_index..][0..size];
        buffer.reader_index += size;
        buffer.assertInvariants();
        return std.mem.readInt(T, taken, endian);
    }

    /// Returns the next `n` readable bytes without consuming them.
    pub fn peekBytes(buffer: *const Buffer, n: usize) ReadError![]const u8 {
        if (buffer.readableLen() < n) return error.EndOfBuffer;
        return buffer.bytes[buffer.reader_index..][0..n];
    }

    pub fn peekInt(
        buffer: *const Buffer,
        comptime T: type,
        endian: std.builtin.Endian,
    ) ReadError!T {
        const size = @divExact(@typeInfo(T).int.bits, 8);
        const taken = try buffer.peekBytes(size);
        return std.mem.readInt(T, taken[0..size], endian);
    }

    /// Skips `n` readable bytes.
    pub fn skip(buffer: *Buffer, n: usize) ReadError!void {
        if (buffer.readableLen() < n) return error.EndOfBuffer;
        buffer.reader_index += n;
        buffer.assertInvariants();
    }

    /// Index of the first occurrence of `byte` in the readable region,
    /// relative to `reader_index`.
    pub fn indexOfByte(buffer: *const Buffer, byte: u8) ?usize {
        return std.mem.indexOfScalar(u8, buffer.readableSlice(), byte);
    }

    /// Index of the first occurrence of `needle` in the readable region,
    /// relative to `reader_index`.
    pub fn indexOf(buffer: *const Buffer, needle: []const u8) ?usize {
        return std.mem.indexOf(u8, buffer.readableSlice(), needle);
    }

    /// Copies the readable region into a freshly allocated slice, without
    /// consuming it. The caller owns the result.
    pub fn dupeReadable(buffer: *const Buffer, gpa: Allocator) Allocator.Error![]u8 {
        return gpa.dupe(u8, buffer.readableSlice());
    }

    /// Consumes `n` readable bytes into a new `Buffer` owned by the caller.
    pub fn splitOff(buffer: *Buffer, gpa: Allocator, n: usize) (Error || ReadError)!Buffer {
        if (buffer.readableLen() < n) return error.EndOfBuffer;
        const source = buffer.bytes[buffer.reader_index..][0..n];
        var split = try Buffer.initFrom(gpa, source, .{ .max_capacity = buffer.max_capacity });
        errdefer split.deinit(gpa);
        buffer.reader_index += n;
        buffer.assertInvariants();
        return split;
    }

    /// `std.Io.Writer`-compatible adapter, so buffers can be filled by any
    /// code that formats into a writer.
    ///
    /// The adapter borrows the buffer; the buffer must outlive it.
    pub fn writerAdapter(buffer: *Buffer, gpa: Allocator, scratch: []u8) WriterAdapter {
        return .init(buffer, gpa, scratch);
    }

    pub const WriterAdapter = struct {
        interface: std.Io.Writer,
        buffer: *Buffer,
        gpa: Allocator,
        err: ?Error,

        pub fn init(buffer: *Buffer, gpa: Allocator, scratch: []u8) WriterAdapter {
            return .{
                .interface = .{
                    .vtable = &.{ .drain = drain },
                    .buffer = scratch,
                },
                .buffer = buffer,
                .gpa = gpa,
                .err = null,
            };
        }

        /// Per the `std.Io.Writer` contract: `buffer[0..end]` is consumed
        /// first, then each slice of `data`, with the last slice repeated
        /// `splat` times. The return value counts only bytes consumed from
        /// `data`.
        fn drain(
            io_w: *std.Io.Writer,
            data: []const []const u8,
            splat: usize,
        ) std.Io.Writer.Error!usize {
            const adapter: *WriterAdapter = @alignCast(@fieldParentPtr("interface", io_w));
            assert(data.len >= 1);

            adapter.append(io_w.buffered()) catch return error.WriteFailed;
            io_w.end = 0;

            var consumed: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                adapter.append(bytes) catch return error.WriteFailed;
                consumed += bytes.len;
            }
            const last = data[data.len - 1];
            for (0..splat) |_| {
                adapter.append(last) catch return error.WriteFailed;
                consumed += last.len;
            }
            return consumed;
        }

        fn append(adapter: *WriterAdapter, bytes: []const u8) Error!void {
            adapter.buffer.writeBytes(adapter.gpa, bytes) catch |err| {
                adapter.err = err;
                return err;
            };
        }
    };
};

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "Buffer: empty is safe to deinit and grows on demand" {
    const gpa = testing.allocator;
    var buffer: Buffer = .empty;
    defer buffer.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), buffer.capacity());
    try testing.expectEqual(@as(usize, 0), buffer.readableLen());
    try testing.expect(!buffer.isReadable());

    try buffer.writeBytes(gpa, "hello");
    try testing.expectEqual(@as(usize, 5), buffer.readableLen());
    try testing.expectEqualStrings("hello", buffer.readableSlice());
}

test "Buffer: init reserves capacity without making bytes readable" {
    const gpa = testing.allocator;
    var buffer = try Buffer.init(gpa, .{ .capacity = 32 });
    defer buffer.deinit(gpa);

    try testing.expectEqual(@as(usize, 32), buffer.capacity());
    try testing.expectEqual(@as(usize, 0), buffer.readableLen());
    try testing.expectEqual(@as(usize, 32), buffer.writableLen());
}

test "Buffer: initFrom copies the source and leaves it readable" {
    const gpa = testing.allocator;
    var source: [4]u8 = .{ 1, 2, 3, 4 };
    var buffer = try Buffer.initFrom(gpa, &source, .{});
    defer buffer.deinit(gpa);

    source = .{ 9, 9, 9, 9 }; // Proves the buffer holds a copy.
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, buffer.readableSlice());
}

test "Buffer: read and peek round trip integers in both byte orders" {
    const gpa = testing.allocator;
    var buffer: Buffer = .empty;
    defer buffer.deinit(gpa);

    try buffer.writeInt(gpa, u32, 0xdeadbeef, .big);
    try buffer.writeInt(gpa, u32, 0xdeadbeef, .little);
    try buffer.writeInt(gpa, i16, -2, .big);

    try testing.expectEqual(@as(u32, 0xdeadbeef), try buffer.peekInt(u32, .big));
    try testing.expectEqual(@as(u32, 0xdeadbeef), try buffer.readInt(u32, .big));
    try testing.expectEqual(@as(u32, 0xdeadbeef), try buffer.readInt(u32, .little));
    try testing.expectEqual(@as(i16, -2), try buffer.readInt(i16, .big));
    try testing.expectEqual(@as(usize, 0), buffer.readableLen());
}

test "Buffer: reading past the end reports EndOfBuffer and consumes nothing" {
    const gpa = testing.allocator;
    var buffer = try Buffer.initFrom(gpa, "ab", .{});
    defer buffer.deinit(gpa);

    try testing.expectError(error.EndOfBuffer, buffer.readBytes(3));
    try testing.expectError(error.EndOfBuffer, buffer.readInt(u32, .big));
    try testing.expectError(error.EndOfBuffer, buffer.peekBytes(3));
    try testing.expectError(error.EndOfBuffer, buffer.skip(3));
    try testing.expectEqual(@as(usize, 2), buffer.readableLen());
}

test "Buffer: discardReadBytes reclaims consumed space" {
    const gpa = testing.allocator;
    var buffer = try Buffer.init(gpa, .{ .capacity = 8 });
    defer buffer.deinit(gpa);

    try buffer.writeBytes(gpa, "abcdefgh");
    try testing.expectEqual(@as(usize, 0), buffer.writableLen());

    _ = try buffer.readBytes(6);
    buffer.discardReadBytes();

    try testing.expectEqual(@as(usize, 0), buffer.reader_index);
    try testing.expectEqual(@as(usize, 2), buffer.writer_index);
    try testing.expectEqualStrings("gh", buffer.readableSlice());
    try testing.expectEqual(@as(usize, 6), buffer.writableLen());
    try testing.expectEqual(@as(usize, 8), buffer.capacity());
}

test "Buffer: ensureWritable compacts before it allocates" {
    const gpa = testing.allocator;
    var buffer = try Buffer.init(gpa, .{ .capacity = 8 });
    defer buffer.deinit(gpa);

    try buffer.writeBytes(gpa, "abcdefgh");
    _ = try buffer.readBytes(8);

    try buffer.ensureWritable(gpa, 8);
    try testing.expectEqual(@as(usize, 8), buffer.capacity()); // No growth.
}

test "Buffer: growth respects max_capacity" {
    const gpa = testing.allocator;
    var buffer = try Buffer.init(gpa, .{ .capacity = 4, .max_capacity = 16 });
    defer buffer.deinit(gpa);

    try buffer.writeByteNTimes(gpa, 'x', 16);
    try testing.expectEqual(@as(usize, 16), buffer.readableLen());
    try testing.expectError(error.BufferFull, buffer.writeByte(gpa, 'y'));
    try testing.expect(buffer.capacity() <= 16);
}

test "Buffer: clear keeps the allocation" {
    const gpa = testing.allocator;
    var buffer = try Buffer.initFrom(gpa, "payload", .{});
    defer buffer.deinit(gpa);

    const before = buffer.capacity();
    buffer.clear();
    try testing.expectEqual(@as(usize, 0), buffer.readableLen());
    try testing.expectEqual(before, buffer.capacity());
}

test "Buffer: move transfers ownership and leaves the source empty" {
    const gpa = testing.allocator;
    var source = try Buffer.initFrom(gpa, "owned", .{});
    var moved = source.move();
    defer moved.deinit(gpa);

    // Deinit of the emptied source must not double free.
    source.deinit(gpa);
    try testing.expectEqualStrings("owned", moved.readableSlice());
}

test "Buffer: reserve and commit fill the buffer in place" {
    const gpa = testing.allocator;
    var buffer: Buffer = .empty;
    defer buffer.deinit(gpa);

    const reserved = try buffer.reserve(gpa, 4);
    @memcpy(reserved, "abcd");
    try testing.expectEqualStrings("abcd", buffer.readableSlice());

    try buffer.ensureWritable(gpa, 2);
    const writable = buffer.writableSlice();
    writable[0] = 'e';
    writable[1] = 'f';
    buffer.commit(2);
    try testing.expectEqualStrings("abcdef", buffer.readableSlice());
}

test "Buffer: search helpers are relative to reader_index" {
    const gpa = testing.allocator;
    var buffer = try Buffer.initFrom(gpa, "GET /path HTTP/1.1\r\n", .{});
    defer buffer.deinit(gpa);

    try testing.expectEqual(@as(?usize, 3), buffer.indexOfByte(' '));
    try testing.expectEqual(@as(?usize, 18), buffer.indexOf("\r\n"));

    _ = try buffer.readBytes(4);
    try testing.expectEqual(@as(?usize, 5), buffer.indexOfByte(' '));
    try testing.expectEqual(@as(?usize, null), buffer.indexOfByte('G'));
}

test "Buffer: splitOff yields an independently owned buffer" {
    const gpa = testing.allocator;
    var buffer = try Buffer.initFrom(gpa, "headerbody", .{});
    defer buffer.deinit(gpa);

    var head = try buffer.splitOff(gpa, 6);
    defer head.deinit(gpa);

    try testing.expectEqualStrings("header", head.readableSlice());
    try testing.expectEqualStrings("body", buffer.readableSlice());

    try testing.expectError(error.EndOfBuffer, buffer.splitOff(gpa, 5));
}

test "Buffer: dupeReadable hands out an owned copy" {
    const gpa = testing.allocator;
    var buffer = try Buffer.initFrom(gpa, "copy me", .{});
    defer buffer.deinit(gpa);

    const copy = try buffer.dupeReadable(gpa);
    defer gpa.free(copy);
    try testing.expectEqualStrings("copy me", copy);
    try testing.expectEqual(@as(usize, 7), buffer.readableLen());
}

test "Buffer: writerAdapter appends formatted output" {
    const gpa = testing.allocator;
    var buffer: Buffer = .empty;
    defer buffer.deinit(gpa);

    var scratch: [16]u8 = undefined;
    var adapter = buffer.writerAdapter(gpa, &scratch);
    try adapter.interface.print("{s} {d}\r\n", .{ "HTTP/1.1", 200 });
    try adapter.interface.writeAll("Content-Length: 0\r\n\r\n");
    try adapter.interface.flush();
    try testing.expect(adapter.err == null);

    try testing.expectEqualStrings(
        "HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
        buffer.readableSlice(),
    );
}

test "Buffer: writerAdapter handles splat and an unbuffered scratch" {
    const gpa = testing.allocator;
    var buffer: Buffer = .empty;
    defer buffer.deinit(gpa);

    var adapter = buffer.writerAdapter(gpa, &.{});
    try adapter.interface.splatByteAll('-', 5);
    try adapter.interface.writeAll("|");
    var chunks: [2][]const u8 = .{ "ab", "cd" };
    try adapter.interface.writeVecAll(&chunks);
    try adapter.interface.flush();
    try testing.expect(adapter.err == null);

    try testing.expectEqualStrings("-----|abcd", buffer.readableSlice());
}

test "Buffer: interleaved writes and reads keep invariants over many rounds" {
    const gpa = testing.allocator;
    var buffer = try Buffer.init(gpa, .{ .capacity = 3, .max_capacity = 1024 });
    defer buffer.deinit(gpa);

    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const random = prng.random();

    var written_total: usize = 0;
    var read_total: usize = 0;
    for (0..512) |_| {
        const write_len = random.intRangeAtMost(usize, 0, 24);
        for (0..write_len) |i| {
            try buffer.writeByte(gpa, @truncate(written_total + i));
        }
        written_total += write_len;

        const read_len = @min(buffer.readableLen(), random.intRangeAtMost(usize, 0, 24));
        const taken = try buffer.readBytes(read_len);
        for (taken, 0..) |byte, i| {
            try testing.expectEqual(@as(u8, @truncate(read_total + i)), byte);
        }
        read_total += read_len;
        buffer.assertInvariants();
    }
    try testing.expectEqual(written_total - read_total, buffer.readableLen());
}

test "Buffer: an impossible growth request fails instead of overflowing" {
    const gpa = testing.allocator;
    var buffer = try Buffer.initFrom(gpa, "abcdef", .{});
    defer buffer.deinit(gpa);

    // `readable + additional` overflows usize here. It has to be rejected on
    // arithmetic grounds before any capacity comparison uses the sum: in
    // ReleaseFast a wrapped sum would look like a small request and the
    // compaction path would return a slice far shorter than promised.
    try testing.expectError(
        error.BufferFull,
        buffer.ensureWritable(gpa, std.math.maxInt(usize)),
    );
    try testing.expectError(
        error.BufferFull,
        buffer.ensureWritable(gpa, std.math.maxInt(usize) - 3),
    );

    // The buffer is untouched by the failed requests.
    try testing.expectEqualStrings("abcdef", buffer.readableSlice());
}
