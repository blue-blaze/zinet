//! Fuzz targets.
//!
//! Run them the way the compiler intends:
//!
//! ```
//! zig build fuzz            # loops forever, reports coverage
//! zig build test            # replays the corpus, so CI covers these too
//! ```
//!
//! # What these assert
//!
//! "It did not crash" is a weak oracle, so every target here also checks a
//! property that a wrong implementation would violate:
//!
//! * **Chunk independence.** A stream decoder must produce the same result
//!   whether its input arrives in one piece or in arbitrary fragments. This is
//!   the property real networks attack constantly and unit tests rarely cover
//!   at scale, because the interesting split points are the ones nobody thinks
//!   to write down.
//! * **Round-trip identity.** Whatever an encoder produces, the matching
//!   decoder must recover.
//! * **No leaks, per input.** Each iteration runs on its own
//!   `DebugAllocator`, so the exact input that leaked is the one reported,
//!   rather than a total at the end of the run.
//! * **Model equivalence.** `Buffer` is compared against a trivially correct
//!   `ArrayList` model.

const std = @import("std");
const backend = @import("backend");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Smith = std.testing.Smith;

const buffer_mod = @import("buffer.zig");
const frame = @import("codec/frame.zig");
const http = @import("codec/http.zig");
const http2 = @import("codec/http2.zig");
const json = @import("codec/json.zig");
const pipeline_mod = @import("pipeline.zig");
const pool_mod = @import("pool.zig");
const permessage_deflate = @import("codec/permessage_deflate.zig");
const redis = @import("codec/redis.zig");
const websocket = @import("codec/websocket.zig");
const quic = @import("codec/quic.zig");
const http3 = @import("codec/http3.zig");

const Buffer = buffer_mod.Buffer;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;
const Sink = pipeline_mod.Sink;

/// Longest input a target will build. Bounded so a failing case stays small
/// enough to read.
const max_input = 4096;

// -- Shared scaffolding ----------------------------------------------------

/// Swallows everything written outbound. Fuzz targets exercise decoders, so
/// what a handler writes back is not the property under test.
const NullSink = struct {
    gpa: Allocator,
    closes: usize = 0,

    fn sink(self: *NullSink) Sink {
        return .{ .context = self, .vtable = &.{
            .write = writeImpl,
            .flush = flushImpl,
            .close = closeImpl,
        } };
    }

    fn writeImpl(context: *anyopaque, msg: Message) pipeline_mod.Error!void {
        const self: *NullSink = @ptrCast(@alignCast(context));
        var owned = msg;
        owned.deinit(self.gpa);
    }

    fn flushImpl(_: *anyopaque) pipeline_mod.Error!void {}

    fn closeImpl(context: *anyopaque) pipeline_mod.Error!void {
        const self: *NullSink = @ptrCast(@alignCast(context));
        self.closes += 1;
    }
};

/// Renders whatever reaches the tail into one flat transcript.
///
/// Comparing transcripts is what makes chunk independence checkable: two runs
/// agree only if they saw the same messages, in the same order, with the same
/// contents, and hit the same errors at the same points.
const Transcript = struct {
    gpa: Allocator,
    out: std.ArrayList(u8) = .empty,

    fn deinit(self: *Transcript) void {
        self.out.deinit(self.gpa);
    }

    fn line(self: *Transcript, comptime format: []const u8, args: anytype) void {
        self.out.print(self.gpa, format, args) catch @panic("OOM in transcript");
    }

    /// Records a decoded message. Bytes are written as-is; protocol objects get
    /// a canonical rendering.
    fn record(self: *Transcript, msg: *const Message) void {
        if (msg.get(http.Request)) |request| return self.recordRequest(request);
        if (msg.get(http.IncomingResponse)) |response| return self.recordResponse(response);
        if (msg.get(websocket.Frame)) |ws_frame| return self.recordFrame(ws_frame);
        if (msg.bytes()) |payload| {
            self.line("MSG {d}:", .{payload.len});
            self.out.appendSlice(self.gpa, payload) catch @panic("OOM in transcript");
            self.line("\n", .{});
            return;
        }
        self.line("OTHER {s}\n", .{msg.typeName()});
    }

    fn recordRequest(self: *Transcript, request: *const http.Request) void {
        self.line("REQ {s} {s} {s} keep_alive={}\n", .{
            request.method.name(),
            request.target,
            request.version.name(),
            request.keep_alive,
        });
        for (request.headers.items()) |header| {
            self.line("  H {s}={s}\n", .{ header.name, header.value });
        }
        self.line("  BODY {d}:", .{request.body.len});
        self.out.appendSlice(self.gpa, request.body) catch @panic("OOM in transcript");
        self.line("\n", .{});
    }

    fn recordResponse(self: *Transcript, response: *const http.IncomingResponse) void {
        self.line("RES {s} {d} {s} keep_alive={}\n", .{
            response.version.name(),
            response.status.code(),
            response.reason,
            response.keep_alive,
        });
        for (response.headers.items()) |header| {
            self.line("  H {s}={s}\n", .{ header.name, header.value });
        }
        self.line("  BODY {d}:", .{response.body.len});
        self.out.appendSlice(self.gpa, response.body) catch @panic("OOM in transcript");
        self.line("\n", .{});
    }

    fn recordFrame(self: *Transcript, ws_frame: *const websocket.Frame) void {
        self.line("WS {s} close_code={?d} {d}:", .{
            @tagName(ws_frame.opcode),
            if (ws_frame.close_code) |code| code.value() else null,
            ws_frame.payload.len,
        });
        self.out.appendSlice(self.gpa, ws_frame.payload) catch @panic("OOM in transcript");
        self.line("\n", .{});
    }

    fn err(self: *Transcript, e: anyerror) void {
        self.line("ERR {s}\n", .{@errorName(e)});
    }
};

/// Tail handler that writes everything it sees into a transcript.
const Recorder = struct {
    transcript: *Transcript,

    pub fn onRead(self: *Recorder, ctx: *HandlerContext, msg: Message) pipeline_mod.Error!void {
        var owned = msg;
        defer owned.deinit(ctx.gpa());
        self.transcript.record(&owned);
    }

    pub fn onError(self: *Recorder, _: *HandlerContext, e: anyerror) void {
        self.transcript.err(e);
    }

    /// Recording events makes a protocol upgrade visible in the transcript, so
    /// chunk independence covers the handshake and not just the frames after
    /// it.
    pub fn onEvent(
        self: *Recorder,
        _: *HandlerContext,
        event: pipeline_mod.Event,
    ) pipeline_mod.Error!void {
        self.transcript.line("EVENT {s}\n", .{event.name()});
    }
};

/// A pipeline wired to a null sink and a transcript, with no sockets involved.
const Rig = struct {
    gpa: Allocator,
    sink_impl: *NullSink,
    recorder: *Recorder,
    pipeline: *Pipeline,

    fn init(gpa: Allocator, io: Io, transcript: *Transcript) !Rig {
        const sink_impl = try gpa.create(NullSink);
        sink_impl.* = .{ .gpa = gpa };
        errdefer gpa.destroy(sink_impl);

        const recorder = try gpa.create(Recorder);
        recorder.* = .{ .transcript = transcript };
        errdefer gpa.destroy(recorder);

        const pipeline = try Pipeline.create(.{
            .gpa = gpa,
            .io = io,
            .sink = sink_impl.sink(),
        });
        return .{
            .gpa = gpa,
            .sink_impl = sink_impl,
            .recorder = recorder,
            .pipeline = pipeline,
        };
    }

    /// Must be called after the codec under test has been installed.
    fn finishSetup(rig: *Rig) !void {
        _ = try rig.pipeline.addLast("recorder", .init(rig.recorder));
    }

    fn deinit(rig: *Rig) void {
        rig.pipeline.destroy();
        rig.gpa.destroy(rig.recorder);
        rig.gpa.destroy(rig.sink_impl);
    }

    /// Fires `payload` as a single inbound read.
    fn feed(rig: *Rig, payload: []const u8) !void {
        var chunk = try Buffer.initFrom(rig.gpa, payload, .{});
        errdefer chunk.deinit(rig.gpa);
        rig.pipeline.fireRead(.initBuffer(&chunk));
        rig.pipeline.fireReadComplete();
    }

    /// Ends the stream, which is when a decoder must report unfinished input.
    fn finish(rig: *Rig) void {
        rig.pipeline.fireInactive();
    }
};

/// How an input gets split across reads.
const Splitter = struct {
    smith: *Smith,

    /// Feeds `payload` in fragments of fuzzer-chosen sizes.
    fn feedFragmented(self: Splitter, rig: *Rig, payload: []const u8) !void {
        var offset: usize = 0;
        while (offset < payload.len) {
            const remaining = payload.len - offset;
            const cap: u32 = @intCast(@min(remaining, std.math.maxInt(u32)));
            const take = self.smith.valueRangeAtMost(u32, 1, cap);
            try rig.feed(payload[offset..][0..take]);
            offset += take;
        }
    }
};

/// Runs `install` over `payload` twice — once whole, once fragmented — and
/// requires both transcripts to match.
fn expectChunkIndependent(
    gpa: Allocator,
    io: Io,
    smith: *Smith,
    payload: []const u8,
    comptime install: fn (pipeline: *Pipeline) anyerror!void,
) !void {
    var whole: Transcript = .{ .gpa = gpa };
    defer whole.deinit();
    {
        var rig = try Rig.init(gpa, io, &whole);
        defer rig.deinit();
        try install(rig.pipeline);
        try rig.finishSetup();
        try rig.feed(payload);
        rig.finish();
    }

    var fragmented: Transcript = .{ .gpa = gpa };
    defer fragmented.deinit();
    {
        var rig = try Rig.init(gpa, io, &fragmented);
        defer rig.deinit();
        try install(rig.pipeline);
        try rig.finishSetup();
        const splitter: Splitter = .{ .smith = smith };
        try splitter.feedFragmented(&rig, payload);
        rig.finish();
    }

    return expectSameTranscript(payload, &whole, &fragmented);
}

/// Fails with a diff when two transcripts of the same bytes disagree. Shared by
/// every chunk-independence target, so they all report the same way.
fn expectSameTranscript(
    payload: []const u8,
    whole: *const Transcript,
    fragmented: *const Transcript,
) !void {
    if (std.mem.eql(u8, whole.out.items, fragmented.out.items)) return;

    var at: usize = 0;
    while (at < @min(whole.out.items.len, fragmented.out.items.len) and
        whole.out.items[at] == fragmented.out.items[at]) : (at += 1)
    {}
    std.debug.print(
        \\chunk dependence detected
        \\input ({d} bytes): {f}
        \\first difference at byte {d}
        \\whole ({d} bytes):
        \\{f}
        \\fragmented ({d} bytes):
        \\{f}
        \\
    , .{
        payload.len,
        std.ascii.hexEscape(payload, .lower),
        at,
        whole.out.items.len,
        std.ascii.hexEscape(whole.out.items, .lower),
        fragmented.out.items.len,
        std.ascii.hexEscape(fragmented.out.items, .lower),
    });
    return error.ChunkDependence;
}

/// Runs one fuzz iteration on its own allocator and fails if that allocator
/// still holds anything afterwards.
///
/// The leak check has to happen after every `defer` inside `body` has run,
/// which is why `body` is a separate function rather than a block: a `defer`
/// in the caller would be checked too early and report the iteration's own
/// scratch buffers as leaks.
fn withLeakCheck(
    harness: *Harness,
    smith: *Smith,
    comptime body: fn (harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void,
) anyerror!void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    const result = body(harness, smith, debug.allocator());
    const leaked = debug.deinit() == .leak;
    try result;
    if (leaked) return error.MemoryLeaked;
}

/// Shared across iterations because spinning up an `Io` per input would
/// dominate the run time. Nothing here is stateful with respect to the input.
///
/// The runtime comes from `backend`, which is what `-Dio=` selects — it used to be a
/// `std.Io.Threaded` constructed here, so `zig build fuzz -Dio=zio` built the fiber backend
/// and then fuzzed on threads anyway. Every target ran on the one backend regardless of the
/// flag, while the README counted the fuzz targets among what runs on fibers. The harness
/// self-check below already used `backend.Runtime`, which is how the two came to disagree:
/// the only code path that named the backend correctly was the one testing the rig.
const Harness = struct {
    runtime: backend.Runtime,

    fn init(gpa: std.mem.Allocator) !Harness {
        return .{ .runtime = try .init(gpa) };
    }

    fn deinit(self: *Harness) void {
        self.runtime.deinit();
    }

    fn io(self: *Harness) Io {
        return self.runtime.io();
    }
};

// -- HTTP ------------------------------------------------------------------

fn installHttpDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try http.RequestDecoder.addTo(pipeline, .{
        // Small limits so the fuzzer can reach the boundary checks with short
        // inputs.
        .max_request_line = 256,
        .max_header_bytes = 512,
        .max_header_count = 16,
        .max_body_length = 1024,
    });
}

/// Builds something that looks enough like HTTP to get past the first few
/// bytes, so the fuzzer spends its time inside the state machine rather than
/// bouncing off the request line.
fn buildHttpish(smith: *Smith, out: *std.ArrayList(u8), gpa: Allocator) !void {
    const methods = [_][]const u8{ "GET", "POST", "PUT", "HEAD", "DELETE", "WEIRD", "" };
    const targets = [_][]const u8{ "/", "/echo", "/a?b=c", "*", "http://h/p", "" };
    const versions = [_][]const u8{ "HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/1.", "" };
    const header_names = [_][]const u8{
        "Host",              "Content-Length", "Transfer-Encoding", "Connection",
        "Trailer",           "X-A",            "Content-Length ",   "",
        "Transfer-Encoding", "Expect",
    };
    const header_values = [_][]const u8{
        "h",       "0",          "5",     "chunked",      "identity",
        "chunked", "keep-alive", "close", "100-continue", "",
    };

    const request_count = smith.valueRangeAtMost(u8, 1, 3);
    for (0..request_count) |_| {
        try out.print(gpa, "{s} {s} {s}\r\n", .{
            methods[smith.index(methods.len)],
            targets[smith.index(targets.len)],
            versions[smith.index(versions.len)],
        });

        while (!smith.eosWeightedSimple(3, 1)) {
            try out.print(gpa, "{s}:{s}\r\n", .{
                header_names[smith.index(header_names.len)],
                header_values[smith.index(header_values.len)],
            });
        }
        try out.appendSlice(gpa, "\r\n");

        // Body, possibly inconsistent with whatever headers were emitted. That
        // inconsistency is the point.
        switch (smith.value(enum(u2) { none, fixed, chunked, garbage })) {
            .none => {},
            .fixed => {
                const len = smith.valueRangeAtMost(u8, 0, 8);
                for (0..len) |_| try out.append(gpa, smith.value(u8));
            },
            .chunked => {
                while (!smith.eosWeightedSimple(2, 1)) {
                    const len = smith.valueRangeAtMost(u8, 0, 6);
                    try out.print(gpa, "{x}\r\n", .{len});
                    for (0..len) |_| try out.append(gpa, smith.value(u8));
                    try out.appendSlice(gpa, "\r\n");
                }
                try out.appendSlice(gpa, "0\r\n\r\n");
            },
            .garbage => {
                const len = smith.valueRangeAtMost(u8, 0, 16);
                for (0..len) |_| try out.append(gpa, smith.value(u8));
            },
        }
    }
}

fn fuzzHttp(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzHttpBody);
}

fn fuzzHttpBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);

    // Half the budget on plausible HTTP, half on arbitrary bytes: the first
    // reaches deep states, the second finds the checks that assume structure.
    if (smith.value(bool)) {
        try buildHttpish(smith, &input, gpa);
    } else {
        var scratch: [max_input]u8 = undefined;
        const len = smith.slice(&scratch);
        try input.appendSlice(gpa, scratch[0..len]);
    }
    if (input.items.len > max_input) input.shrinkRetainingCapacity(max_input);

    try expectChunkIndependent(gpa, harness.io(), smith, input.items, installHttpDecoder);
}

test "fuzz: HTTP request decoder" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzHttp, .{ .corpus = &http_corpus });
}

// -- HTTP responses --------------------------------------------------------

/// The response decoder has more states than any other decoder here — four body
/// framings, one of which is "until the connection closes" — so it is the one
/// with the most room for a chunk-dependent bug.
fn installResponseDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try http.ResponseDecoder.addTo(pipeline, .{
        .max_status_line = 256,
        .max_header_bytes = 512,
        .max_header_count = 16,
        .max_body_length = 1024,
    });
}

fn buildResponseish(smith: *Smith, out: *std.ArrayList(u8), gpa: Allocator) !void {
    const codes = [_][]const u8{ "200 OK", "204 No Content", "304 Not Modified", "404 Not Found", "500 ", "100 Continue", "999 Odd" };
    const versions = [_][]const u8{ "HTTP/1.1", "HTTP/1.0", "HTTP/2", "" };

    var responses = smith.valueRangeAtMost(u8, 1, 3);
    while (responses > 0) : (responses -= 1) {
        try out.print(gpa, "{s} {s}\r\n", .{
            versions[smith.index(versions.len)],
            codes[smith.index(codes.len)],
        });

        // Framing headers, chosen so that conflicting and absent combinations
        // both come up.
        const framing = smith.valueRangeAtMost(u8, 0, 3);
        const body_len = smith.valueRangeAtMost(u8, 0, 24);
        switch (framing) {
            0 => try out.print(gpa, "Content-Length: {d}\r\n", .{body_len}),
            1 => try out.appendSlice(gpa, "Transfer-Encoding: chunked\r\n"),
            2 => {
                try out.print(gpa, "Content-Length: {d}\r\n", .{body_len});
                try out.appendSlice(gpa, "Transfer-Encoding: chunked\r\n");
            },
            // 3: no framing header at all, so the body runs until close.
            else => {},
        }
        if (smith.boolWeighted(1, 3)) {
            try out.appendSlice(gpa, "Connection: close\r\n");
        }
        var extra = smith.valueRangeAtMost(u8, 0, 2);
        while (extra > 0) : (extra -= 1) {
            try out.print(gpa, "X-H{d}: v{d}\r\n", .{ extra, extra });
        }
        try out.appendSlice(gpa, "\r\n");

        if (framing == 1) {
            var chunks = smith.valueRangeAtMost(u8, 0, 3);
            while (chunks > 0) : (chunks -= 1) {
                const size = smith.valueRangeAtMost(u8, 0, 8);
                try out.print(gpa, "{x}\r\n", .{size});
                try out.appendNTimes(gpa, 'z', size);
                try out.appendSlice(gpa, "\r\n");
            }
            try out.appendSlice(gpa, "0\r\n\r\n");
        } else {
            try out.appendNTimes(gpa, 'b', body_len);
        }
        if (smith.eosWeightedSimple(1, 3)) break;
    }
}

fn fuzzResponse(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzResponseBody);
}

fn fuzzResponseBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);

    if (smith.value(bool)) {
        try buildResponseish(smith, &input, gpa);
    } else {
        var scratch: [max_input]u8 = undefined;
        const len = smith.slice(&scratch);
        try input.appendSlice(gpa, scratch[0..len]);
    }
    if (input.items.len > max_input) input.shrinkRetainingCapacity(max_input);

    try expectChunkIndependent(gpa, harness.io(), smith, input.items, installResponseDecoder);
}

test "fuzz: HTTP response decoder" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzResponse, .{ .corpus = &response_corpus });
}

const response_corpus = [_][]const u8{
    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    // No framing header: the body runs to the close.
    "HTTP/1.0 200 OK\r\n\r\nrest of the stream is the body",
    // Bodyless statuses whose Content-Length must not be believed.
    "HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
    "HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n",
    // Conflicting framing.
    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
    // Two pipelined responses.
    "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nAHTTP/1.1 500 \r\nContent-Length: 0\r\n\r\n",
    "not a status line at all\r\n",
};

const http_corpus = [_][]const u8{
    "GET / HTTP/1.1\r\nHost: h\r\n\r\n",
    "POST /e HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
    "POST /e HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    "GET / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
};

// -- Framing decoders ------------------------------------------------------

fn installLineDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try frame.LineBasedFrameDecoder.addTo(pipeline, .{ .max_length = 64 });
}

fn installLengthFieldDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try frame.LengthFieldBasedFrameDecoder.addTo(pipeline, .{
        .length_field_width = .two,
        .max_frame_length = 256,
    });
}

fn fuzzFraming(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzFramingBody);
}

fn installFixedLengthDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try frame.FixedLengthFrameDecoder.addTo(pipeline, .{ .frame_length = 5 });
}

fn installDelimiterDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try frame.DelimiterBasedFrameDecoder.addTo(pipeline, .{
        // Multi-byte delimiters are where this decoder differs from the line
        // one: a delimiter can straddle a read boundary, and the discard path
        // has to keep enough tail to notice.
        .delimiters = &.{ "\r\n", "\n", "||" },
        .max_length = 32,
    });
}

fn fuzzFramingBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var scratch: [max_input]u8 = undefined;
    const len = smith.slice(&scratch);
    const payload = scratch[0..len];

    // Both decoders resynchronize after an over-long frame rather than giving
    // up, so chunk independence is a stronger claim for them than for HTTP.
    try expectChunkIndependent(gpa, harness.io(), smith, payload, installLineDecoder);
    try expectChunkIndependent(gpa, harness.io(), smith, payload, installLengthFieldDecoder);
    try expectChunkIndependent(gpa, harness.io(), smith, payload, installFixedLengthDecoder);
    try expectChunkIndependent(gpa, harness.io(), smith, payload, installDelimiterDecoder);
}

test "fuzz: framing decoders" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzFraming, .{ .corpus = &framing_corpus });
}

const framing_corpus = [_][]const u8{
    "one\ntwo\r\nthree\n",
    "\n\n\n",
    "no newline at all",
    "\x00\x03abc\x00\x00\x00\x02xy",
    // Delimiter cases: the two-byte forms and a boundary that splits one.
    "a||b||c",
    "one\r\ntwo\nthree||four",
    // Over-long, then a good frame behind it.
    "0123456789012345678901234567890123456789||ok||",
    // Exact multiples and a remainder, for the fixed-length decoder.
    "abcdefghij",
    "abcdefghijk",
};

// -- JSON ------------------------------------------------------------------

fn installJsonDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try json.JsonObjectDecoder.addTo(pipeline, .{ .max_length = 64 });
}

fn installJsonStreamingDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try json.JsonObjectDecoder.addTo(pipeline, .{
        .max_length = 64,
        .stream_array_elements = true,
    });
}

fn fuzzJsonBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var scratch: [max_input]u8 = undefined;
    const len = smith.slice(&scratch);
    const payload = scratch[0..len];

    // Chunk independence is a sharper claim here than for the other framers,
    // because this decoder carries a scan position across reads rather than
    // rescanning: an off-by-one in that bookkeeping shows up as a frame that
    // appears only when the bytes arrive whole, or only when they are split.
    try expectChunkIndependent(gpa, harness.io(), smith, payload, installJsonDecoder);
    try expectChunkIndependent(gpa, harness.io(), smith, payload, installJsonStreamingDecoder);
}

fn fuzzJson(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzJsonBody);
}

test "fuzz: JSON value framing" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzJson, .{ .corpus = &json_corpus });
}

const json_corpus = [_][]const u8{
    "{}",
    "{\"a\":1}{\"b\":2}",
    // Whitespace only: consumed rather than accumulated.
    "   \n\t  ",
    "[1,2,3]",
    // Structural bytes inside a string, an escaped quote, and a backslash
    // immediately before the closing quote.
    "{\"s\":\"}{][ \\\" \\\\\"}",
    // A close with nothing open, with a good value behind it.
    "}{\"a\":1}",
    // Truncated, at each of the places a value can be cut.
    "{\"a\":",
    "{\"s\":\"unterminated",
    "[{\"a\":1},",
    // Deep nesting, and more than the configured maximum.
    "[[[[[[[[[[1]]]]]]]]]]",
    "{\"k\":\"0123456789012345678901234567890123456789012345678901234567890123456789\"}",
    // Scalars, which only the streaming mode frames.
    "[1,-2.5e3,true,false,null,\"x,y\"]",
    "42",
};

// -- HTTP/2 ----------------------------------------------------------------

/// Records one stream's pipeline into the connection's transcript, so chunk
/// independence covers what the *application* saw rather than only what the
/// connection admitted to.
const Http2StreamRecorder = struct {
    transcript: *Transcript,

    pub fn onRead(self: *Http2StreamRecorder, ctx: *HandlerContext, msg: Message) pipeline_mod.Error!void {
        const gpa = ctx.gpa();
        var owned = msg;
        defer owned.deinit(gpa);

        if (owned.take(gpa, http2.Headers)) |taken| {
            var headers = taken;
            defer headers.deinit(gpa);
            self.transcript.line("H2 HEADERS {d} end={} trailers={}\n", .{
                headers.stream_id, headers.end_stream, headers.trailers,
            });
            for (headers.fields) |field| {
                self.transcript.line("  {s}={s}\n", .{ field.name, field.value });
            }
            return;
        }
        if (owned.bytes()) |body| self.transcript.line("H2 DATA {d}\n", .{body.len});
    }

    pub fn onInactive(self: *Http2StreamRecorder, ctx: *HandlerContext) pipeline_mod.Error!void {
        self.transcript.line("H2 STREAM END\n", .{});
        ctx.fireInactive();
    }

    pub fn onEvent(
        self: *Http2StreamRecorder,
        ctx: *HandlerContext,
        event: pipeline_mod.Event,
    ) pipeline_mod.Error!void {
        self.transcript.line("H2 STREAM EVENT {s}\n", .{event.name()});
        ctx.fireEvent(event);
    }
};

/// Builds a recorder for every stream. The pipeline owns each one, since nothing
/// needs it after the stream ends.
const Http2Streams = struct {
    transcript: *Transcript,

    pub fn initPipeline(self: *Http2Streams, pipeline: *Pipeline) anyerror!void {
        const recorder = try pipeline.gpa.create(Http2StreamRecorder);
        recorder.* = .{ .transcript = self.transcript };
        errdefer pipeline.gpa.destroy(recorder);
        _ = try pipeline.addLast("recorder", .initOwned(recorder));
    }
};

/// Feeds `payload` to a server codec, whole or fragmented, recording both the
/// connection's events and every stream's.
fn transcribeHttp2(
    gpa: Allocator,
    io: Io,
    transcript: *Transcript,
    payload: []const u8,
    splitter: ?Splitter,
) !void {
    var sink_impl: NullSink = .{ .gpa = gpa };
    var streams: Http2Streams = .{ .transcript = transcript };
    var recorder: Recorder = .{ .transcript = transcript };

    const pipeline = try Pipeline.create(.{ .gpa = gpa, .io = io, .sink = sink_impl.sink() });
    defer pipeline.destroy();

    _ = try http2.addServerCodec(pipeline, .{ .streams = .init(&streams) });
    _ = try pipeline.addLast("parent", .init(&recorder));
    pipeline.fireActive();

    var rig: Rig = .{
        .gpa = gpa,
        .sink_impl = &sink_impl,
        .recorder = &recorder,
        .pipeline = pipeline,
    };
    if (splitter) |fragments| {
        try fragments.feedFragmented(&rig, payload);
    } else {
        try rig.feed(payload);
    }
    pipeline.fireInactive();
}

/// Assembles a byte stream that gets past the preface, because random bytes never
/// do: without a valid preface every input would be rejected at byte 24 and the
/// entire protocol would go untested.
fn buildHttp2Stream(gpa: Allocator, smith: *Smith, out: *Buffer) !void {
    // A peer speaking something else, occasionally, so that path is covered too.
    if (smith.boolWeighted(1, 32)) {
        try out.writeBytes(gpa, "GET / HTTP/1.1\r\nHost: fuzz.test\r\nAccept: */*\r\n\r\n");
        return;
    }
    try out.writeBytes(gpa, http2.client_preface);

    // §3.4 requires SETTINGS first. Skipping it now and then covers the check.
    if (!smith.boolWeighted(1, 16)) {
        try http2.frame.writeSettings(out, gpa, &.{
            .{ .id = .initial_window_size, .value = smith.valueRangeAtMost(u32, 0, 200_000) },
            .{ .id = .max_frame_size, .value = 16_384 },
        });
    }

    // Header blocks that HPACK can actually decode, so the layers above the
    // decoder get exercised rather than only its error paths.
    const blocks = [_][]const u8{
        // :method GET, :scheme http, :path /
        "\x82\x86\x84",
        // The same plus a literal authority.
        "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff",
        // :status 200, which is malformed in a request and so exercises §8.
        "\x88",
        // A literal never-indexed field.
        "\x82\x86\x84\x10\x08password\x06secret",
        // Trailers: no pseudo-headers at all.
        "\x40\x0ax-checksum\x03abc",
    };

    var remaining = smith.valueRangeAtMost(u8, 1, 12);
    while (remaining > 0) : (remaining -= 1) {
        const kinds = [_]http2.frame.FrameType{
            .data,                           .headers, .priority, .rst_stream,    .settings,
            .push_promise,                   .ping,    .goaway,   .window_update, .continuation,
            @fromBackingInt(@intCast(0xef)),
        };
        const kind = kinds[smith.index(kinds.len)];
        const stream_id: u31 = switch (smith.valueRangeAtMost(u8, 0, 4)) {
            0 => 0,
            1 => 1,
            2 => 3,
            3 => 5,
            else => 2,
        };

        var flags: u8 = 0;
        if (smith.boolWeighted(2, 3)) flags |= http2.frame.Flags.end_headers;
        if (smith.boolWeighted(1, 3)) flags |= http2.frame.Flags.end_stream;
        if (smith.boolWeighted(1, 6)) flags |= http2.frame.Flags.padded;
        if (smith.boolWeighted(1, 8)) flags |= http2.frame.Flags.priority;

        var scratch: [256]u8 = undefined;
        const payload: []const u8 = switch (kind) {
            .headers, .continuation, .push_promise => if (smith.boolWeighted(3, 4))
                blocks[smith.index(blocks.len)]
            else
                scratch[0..smith.slice(&scratch)],
            .ping => brk: {
                const len = @min(8, smith.slice(&scratch));
                @memset(scratch[len..8], 0);
                break :brk scratch[0..8];
            },
            .rst_stream, .window_update => brk: {
                std.mem.writeInt(u32, scratch[0..4], smith.valueRangeAtMost(u32, 0, 12), .big);
                break :brk scratch[0..4];
            },
            .priority => brk: {
                _ = smith.slice(scratch[0..5]);
                break :brk scratch[0..5];
            },
            .settings => brk: {
                const count = smith.valueRangeAtMost(u8, 0, 3);
                var index: usize = 0;
                while (index < count) : (index += 1) {
                    const entry = scratch[index * 6 ..][0..6];
                    std.mem.writeInt(u16, entry[0..2], smith.valueRangeAtMost(u16, 0, 8), .big);
                    std.mem.writeInt(u32, entry[2..6], smith.valueRangeAtMost(u32, 0, 70_000), .big);
                }
                break :brk scratch[0 .. count * 6];
            },
            .goaway => brk: {
                const extra = @min(scratch.len - 8, smith.valueRangeAtMost(u8, 0, 16));
                @memset(scratch[0 .. 8 + extra], 0);
                break :brk scratch[0 .. 8 + extra];
            },
            else => scratch[0..smith.slice(&scratch)],
        };

        try http2.frame.writeFrame(out, gpa, kind, .{ .bits = flags }, stream_id, payload);
    }
}

fn fuzzHttp2Body(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var stream: Buffer = .empty;
    defer stream.deinit(gpa);
    try buildHttp2Stream(gpa, smith, &stream);
    const payload = stream.readableSlice();

    // HTTP/2 has three nested places to get chunk independence wrong — the
    // connection preface, the frame boundary, and the header block — and a socket
    // respects none of them.
    var whole: Transcript = .{ .gpa = gpa };
    defer whole.deinit();
    try transcribeHttp2(gpa, harness.io(), &whole, payload, null);

    var fragmented: Transcript = .{ .gpa = gpa };
    defer fragmented.deinit();
    try transcribeHttp2(gpa, harness.io(), &fragmented, payload, .{ .smith = smith });

    try expectSameTranscript(payload, &whole, &fragmented);
}

fn fuzzHttp2(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzHttp2Body);
}

test "fuzz: HTTP/2 connection" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzHttp2, .{ .corpus = &http2_corpus });
}

const http2_corpus = [_][]const u8{
    "",
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    // A preface with a SETTINGS frame behind it, which is the ordinary opening.
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
};

// -- HPACK -----------------------------------------------------------------

fn fuzzHpackBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    const hpack = http2.hpack;

    // A field list the fuzzer chose, encoded and decoded again. Round-tripping is
    // the natural oracle for a compressor, and HPACK's dynamic table makes it a
    // sharper one than it looks: the two sides only stay in step if insertion and
    // eviction agree exactly, and they diverge silently when they do not.
    var encoder: hpack.Encoder = .init(4096);
    defer encoder.deinit(gpa);
    var decoder: hpack.Decoder = .init(4096);
    defer decoder.deinit(gpa);

    const names = [_][]const u8{
        ":method",    ":path",  ":scheme", ":status",                         ":authority",
        "cookie",     "date",   "etag",    "x-custom",                        "content-type",
        "user-agent", "accept", "x",       "a-longer-header-name-than-usual",
    };

    var rounds = smith.valueRangeAtMost(u8, 1, 4);
    while (rounds > 0) : (rounds -= 1) {
        var fields: std.ArrayList(hpack.Field) = .empty;
        defer fields.deinit(gpa);
        var values: std.ArrayList([]u8) = .empty;
        defer {
            for (values.items) |value| gpa.free(value);
            values.deinit(gpa);
        }

        var count = smith.valueRangeAtMost(u8, 0, 8);
        while (count > 0) : (count -= 1) {
            var scratch: [96]u8 = undefined;
            const len = smith.slice(&scratch);
            const value = try gpa.dupe(u8, scratch[0..len]);
            try values.append(gpa, value);
            try fields.append(gpa, .{
                .name = names[smith.index(names.len)],
                .value = value,
                .never_indexed = smith.boolWeighted(1, 8),
            });
        }

        var block: Buffer = .empty;
        defer block.deinit(gpa);
        try encoder.encode(&block, gpa, fields.items);

        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        var decoded: std.ArrayList(hpack.Field) = .empty;
        try decoder.decode(gpa, arena.allocator(), block.readableSlice(), &decoded, .{
            .max_string_len = 4096,
            .max_header_list_size = 64 * 1024,
            .max_fields = 64,
        });

        if (decoded.items.len != fields.items.len) return error.HpackFieldCount;
        for (fields.items, decoded.items) |sent, got| {
            if (!std.mem.eql(u8, sent.name, got.name)) return error.HpackName;
            if (!std.mem.eql(u8, sent.value, got.value)) return error.HpackValue;
            if (sent.never_indexed != got.never_indexed) return error.HpackNeverIndexed;
        }

        // The two dynamic tables must stay in step, or every later block decodes to
        // something else entirely.
        if (encoder.table.size != decoder.table.size) return error.HpackTableSize;
        if (encoder.table.count() != decoder.table.count()) return error.HpackTableCount;
    }

    // And arbitrary bytes must be refused rather than crash or allocate without
    // bound. A header block is attacker-controlled input by definition.
    var junk: [512]u8 = undefined;
    const junk_len = smith.slice(&junk);
    var loose: hpack.Decoder = .init(4096);
    defer loose.deinit(gpa);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var decoded: std.ArrayList(hpack.Field) = .empty;
    loose.decode(gpa, arena.allocator(), junk[0..junk_len], &decoded, .{}) catch {};
}

fn fuzzHpack(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzHpackBody);
}

test "fuzz: HPACK round trip" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzHpack, .{ .corpus = &.{
        "",
        "\x82\x86\x84",
        "\x40\x0acustom-key\x0dcustom-header",
    } });
}

// -- Huffman ---------------------------------------------------------------

fn fuzzHuffmanBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    const huffman = http2.huffman;

    var source: [1024]u8 = undefined;
    const len = smith.slice(&source);
    const plain = source[0..len];

    const encoded = try gpa.alloc(u8, huffman.encodedLen(plain));
    defer gpa.free(encoded);
    const written = huffman.encode(encoded, plain);

    // The length has to be predictable before the fact, because that is what lets a
    // decoder size an allocation exactly and check a limit before filling it.
    if (try huffman.decodedLen(written) != plain.len) return error.HuffmanLength;

    const back = try gpa.alloc(u8, plain.len);
    defer gpa.free(back);
    if (!std.mem.eql(u8, plain, try huffman.decode(back, written))) return error.HuffmanRoundTrip;

    // Arbitrary bytes: §5.2 makes most of them invalid padding, and every one of
    // them has to be refused rather than read past the end.
    var junk: [256]u8 = undefined;
    const junk_len = smith.slice(&junk);
    var out: [2048]u8 = undefined;
    _ = huffman.decode(&out, junk[0..junk_len]) catch {};
    _ = huffman.decodedLen(junk[0..junk_len]) catch {};
}

fn fuzzHuffman(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzHuffmanBody);
}

test "fuzz: Huffman round trip" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzHuffman, .{ .corpus = &.{
        "",
        "www.example.com",
        "\xff\xff\xff\xff",
    } });
}

// -- WebSocket -------------------------------------------------------------

fn installWebSocketCodec(pipeline: *Pipeline) anyerror!void {
    const codec = try pipeline.gpa.create(websocket.FrameCodec);
    // Server role, so nothing here masks and the transcript is a pure function
    // of the input bytes — which is what chunk independence needs.
    codec.* = .init(.server, .{
        .max_frame_payload = 512,
        .max_message_length = 2048,
    });
    errdefer pipeline.gpa.destroy(codec);
    _ = try pipeline.addLast(websocket.FrameCodec.handler_name, .initOwned(codec));
}

/// Emits frames that are structurally plausible: the fuzzer picks the opcode,
/// the flags and the length encoding, so it explores the header space instead
/// of failing the very first bit check.
fn buildWebSocketFrames(smith: *Smith, out: *std.ArrayList(u8), gpa: Allocator) !void {
    while (!smith.eosWeightedSimple(3, 1)) {
        const opcode = smith.value(u4);
        const fin = smith.boolWeighted(1, 3);
        // Reserved bits are usually zero, because a decoder that rejects them
        // too eagerly would never reach the rest of the header.
        const rsv: u3 = if (smith.boolWeighted(8, 1)) 0 else smith.value(u3);
        const masked = smith.boolWeighted(1, 8);
        const payload_len = smith.valueRangeAtMost(u16, 0, 300);

        var first: u8 = opcode;
        if (fin) first |= 0x80;
        first |= @as(u8, rsv) << 4;
        try out.append(gpa, first);

        // Length encoding is chosen independently of the actual length, so
        // non-minimal encodings — which the decoder must reject — get covered.
        const mask_bit: u8 = if (masked) 0x80 else 0;
        switch (smith.value(enum(u2) { short, extended, huge, mismatched })) {
            .short => try out.append(gpa, mask_bit | @as(u8, @intCast(@min(payload_len, 125)))),
            .extended => {
                try out.append(gpa, mask_bit | 126);
                try out.append(gpa, @intCast(payload_len >> 8));
                try out.append(gpa, @truncate(payload_len));
            },
            .huge => {
                try out.append(gpa, mask_bit | 127);
                var be: [8]u8 = @splat(0);
                std.mem.writeInt(u64, &be, payload_len, .big);
                try out.appendSlice(gpa, &be);
            },
            .mismatched => try out.append(gpa, mask_bit | smith.value(u7)),
        }

        var key: [4]u8 = @splat(0);
        if (masked) {
            smith.bytes(&key);
            try out.appendSlice(gpa, &key);
        }

        const actual = @min(payload_len, 300);
        for (0..actual) |i| {
            const byte = smith.value(u8);
            try out.append(gpa, if (masked) byte ^ key[i % 4] else byte);
        }
    }
}

fn fuzzWebSocket(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzWebSocketBody);
}

fn fuzzWebSocketBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);

    if (smith.value(bool)) {
        try buildWebSocketFrames(smith, &input, gpa);
    } else {
        var scratch: [max_input]u8 = undefined;
        const len = smith.slice(&scratch);
        try input.appendSlice(gpa, scratch[0..len]);
    }
    if (input.items.len > max_input) input.shrinkRetainingCapacity(max_input);

    try expectChunkIndependent(gpa, harness.io(), smith, input.items, installWebSocketCodec);
}

test "fuzz: WebSocket frame decoder" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzWebSocket, .{ .corpus = &websocket_corpus });
}

const websocket_corpus = [_][]const u8{
    // Masked "hi" text frame, which is what a conforming client sends.
    "\x81\x82\x01\x02\x03\x04\x69\x6b",
    // Unmasked, so a server must reject it.
    "\x81\x02hi",
    // Ping with no payload.
    "\x89\x80\x00\x00\x00\x00",
    // Fragmented text: first fragment, then continuation.
    "\x01\x81\x00\x00\x00\x00a\x80\x81\x00\x00\x00\x00b",
};

// -- Buffer ----------------------------------------------------------------

/// Applies a fuzzer-chosen sequence of operations to a `Buffer` and to an
/// `ArrayList` standing in as the obviously-correct model, then requires the
/// two to agree.
///
/// The model is only the readable bytes: everything `Buffer` adds on top —
/// the split read and write cursors, compaction, growth — is invisible to a
/// correct implementation and must stay that way.
fn fuzzBuffer(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzBufferBody);
}

fn fuzzBufferBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var subject: Buffer = .empty;
    defer subject.deinit(gpa);

    var model: std.ArrayList(u8) = .empty;
    defer model.deinit(gpa);
    // Offset of the model's read cursor, mirroring the buffer's.
    var read_at: usize = 0;

    while (!smith.eosWeightedSimple(12, 1)) {
        switch (smith.value(enum(u3) { write, read, peek, discard, clear, skip, grow })) {
            .write => {
                var scratch: [64]u8 = undefined;
                const len = smith.slice(&scratch);
                try subject.writeBytes(gpa, scratch[0..len]);
                try model.appendSlice(gpa, scratch[0..len]);
            },
            .read => {
                const available: u32 = @intCast(model.items.len - read_at);
                if (available == 0) {
                    try std.testing.expectError(error.EndOfBuffer, subject.readBytes(1));
                    continue;
                }
                const want = smith.valueRangeAtMost(u32, 1, available);
                const got = try subject.readBytes(want);
                try std.testing.expectEqualSlices(u8, model.items[read_at..][0..want], got);
                read_at += want;
            },
            .peek => {
                const available: u32 = @intCast(model.items.len - read_at);
                if (available == 0) continue;
                const want = smith.valueRangeAtMost(u32, 1, available);
                const got = try subject.peekBytes(want);
                try std.testing.expectEqualSlices(u8, model.items[read_at..][0..want], got);
            },
            .discard => subject.discardReadBytes(),
            .clear => {
                subject.clear();
                model.clearRetainingCapacity();
                read_at = 0;
            },
            .skip => {
                const available: u32 = @intCast(model.items.len - read_at);
                if (available == 0) continue;
                const want = smith.valueRangeAtMost(u32, 1, available);
                try subject.skip(want);
                read_at += want;
            },
            .grow => {
                const want = smith.valueRangeAtMost(u16, 0, 512);
                subject.ensureWritable(gpa, want) catch |err| switch (err) {
                    error.BufferFull => {},
                    else => return err,
                };
            },
        }

        // The invariant that matters: readable bytes match the model, always.
        try std.testing.expectEqualSlices(
            u8,
            model.items[read_at..],
            subject.readableSlice(),
        );
    }
}

test "fuzz: Buffer against a model" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzBuffer, .{ .corpus = &.{ "", "\x01\x02\x03\x04" } });
}

// -- Round trips -----------------------------------------------------------
//
// Chunk independence checks that a decoder reads a stream consistently. These
// check the other direction: that whatever an encoder writes, the matching
// decoder recovers exactly. A framing bug that is symmetric — both sides off by
// the same amount — survives a decoder-only test and dies here.

const test_support = @import("codec/test_support.zig");

fn fuzzWebSocketRoundTrip(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzWebSocketRoundTripBody);
}

fn fuzzWebSocketRoundTripBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    // Payloads are generated up front so they stay alive for the whole encode:
    // `OutboundFrame` borrows its payload.
    var payloads: std.ArrayList([]u8) = .empty;
    defer {
        for (payloads.items) |item| gpa.free(item);
        payloads.deinit(gpa);
    }
    var opcodes: std.ArrayList(websocket.Opcode) = .empty;
    defer opcodes.deinit(gpa);

    while (!smith.eosWeightedSimple(4, 1) and payloads.items.len < 8) {
        // Control frames have their own length rules, and close frames carry a
        // status code in the payload, so the plain "payload survives" invariant
        // is checked with data frames.
        const opcode: websocket.Opcode = if (smith.value(bool)) .text else .binary;
        const len = smith.valueRangeAtMost(u16, 0, 400);
        const payload = try gpa.alloc(u8, len);
        errdefer gpa.free(payload);
        smith.bytes(payload);
        try payloads.append(gpa, payload);
        try opcodes.append(gpa, opcode);
    }

    // Encode as a server, which does not mask.
    var encoder = try test_support.Fixture.init(gpa);
    defer encoder.deinit();
    _ = try websocket.FrameCodec.addTo(encoder.pipeline, .server, .{
        .max_frame_payload = 1024,
    });
    for (payloads.items, opcodes.items) |payload, opcode| {
        try encoder.pipeline.write(try Message.initAny(gpa, websocket.OutboundFrame, .{
            .opcode = opcode,
            .payload = payload,
        }));
    }

    // Decode as a client, which is the role that expects unmasked frames.
    var transcript: Transcript = .{ .gpa = gpa };
    defer transcript.deinit();
    var rig = try Rig.init(gpa, undefined, &transcript);
    defer rig.deinit();
    const codec = try gpa.create(websocket.FrameCodec);
    codec.* = .init(.client, .{ .max_frame_payload = 1024 });
    errdefer gpa.destroy(codec);
    _ = try rig.pipeline.addLast(websocket.FrameCodec.handler_name, .initOwned(codec));
    try rig.finishSetup();
    try rig.feed(encoder.written());

    var expected: Transcript = .{ .gpa = gpa };
    defer expected.deinit();
    for (payloads.items, opcodes.items) |payload, opcode| {
        var reference: websocket.Frame = .{ .opcode = opcode, .payload = payload };
        expected.recordFrame(&reference);
    }

    try std.testing.expectEqualStrings(expected.out.items, transcript.out.items);
}

test "fuzz: WebSocket frames survive an encode and decode" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzWebSocketRoundTrip, .{ .corpus = &.{ "", "\x01\x02" } });
}

fn fuzzLengthFieldRoundTrip(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzLengthFieldRoundTripBody);
}

fn fuzzLengthFieldRoundTripBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    const width = smith.value(enum(u3) { one, two, three, four, eight });
    const field: frame.LengthFieldWidth = switch (width) {
        .one => .one,
        .two => .two,
        .three => .three,
        .four => .four,
        .eight => .eight,
    };
    const endian: std.builtin.Endian = if (smith.value(bool)) .big else .little;
    const max_payload: u16 = if (field == .one) 200 else 1000;

    var payloads: std.ArrayList([]u8) = .empty;
    defer {
        for (payloads.items) |item| gpa.free(item);
        payloads.deinit(gpa);
    }

    var encoder = try test_support.Fixture.init(gpa);
    defer encoder.deinit();
    _ = try frame.LengthFieldPrepender.addTo(encoder.pipeline, .{
        .length_field_width = field,
        .endian = endian,
    });

    while (!smith.eosWeightedSimple(4, 1) and payloads.items.len < 8) {
        const len = smith.valueRangeAtMost(u16, 0, max_payload);
        const payload = try gpa.alloc(u8, len);
        errdefer gpa.free(payload);
        smith.bytes(payload);
        try payloads.append(gpa, payload);
        try encoder.pipeline.write(try Message.initBytes(gpa, payload));
    }

    var transcript: Transcript = .{ .gpa = gpa };
    defer transcript.deinit();
    var rig = try Rig.init(gpa, undefined, &transcript);
    defer rig.deinit();
    const decoder = try gpa.create(frame.LengthFieldBasedFrameDecoder);
    decoder.* = .init(.{
        .length_field_width = field,
        .endian = endian,
        .initial_bytes_to_strip = field.byteCount(),
        .max_frame_length = 4096,
    });
    errdefer gpa.destroy(decoder);
    _ = try rig.pipeline.addLast(
        frame.LengthFieldBasedFrameDecoder.handler_name,
        .initOwned(decoder),
    );
    try rig.finishSetup();
    try rig.feed(encoder.written());

    var expected: Transcript = .{ .gpa = gpa };
    defer expected.deinit();
    for (payloads.items) |payload| {
        var reference: Message = try Message.initBytes(gpa, payload);
        defer reference.deinit(gpa);
        expected.record(&reference);
    }

    try std.testing.expectEqualStrings(expected.out.items, transcript.out.items);
}

test "fuzz: length-prefixed frames survive an encode and decode" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzLengthFieldRoundTrip, .{ .corpus = &.{ "", "\x03\x04" } });
}

// -- Pool and shared buffers -----------------------------------------------

/// Drives a `BufferPool` and `SharedBuffer` through a fuzzer-chosen sequence of
/// operations, checking the invariants that make recycling safe:
///
/// * an acquired buffer is at least as large as asked for, and is empty;
/// * a pooled buffer released through `deinit` goes back to the pool rather
///   than to the allocator, which is what the `Recycler` exists to guarantee;
/// * every accounted request is either a hit or a miss;
/// * no reference-counted buffer outlives its last reference.
fn fuzzPool(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzPoolBody);
}

fn fuzzPoolBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var pool = try pool_mod.BufferPool.init(gpa, .{
        .min_buffer_capacity = 64,
        .max_buffer_capacity = 1024,
        .max_buffers_per_class = 4,
    });
    defer pool.deinit();

    var live: std.ArrayList(Buffer) = .empty;
    defer {
        for (live.items) |*item| item.deinit(gpa);
        live.deinit(gpa);
    }

    var shared: std.ArrayList(*pool_mod.SharedBuffer) = .empty;
    defer {
        for (shared.items) |item| item.release();
        shared.deinit(gpa);
    }

    var acquires: usize = 0;

    while (!smith.eosWeightedSimple(10, 1)) {
        switch (smith.value(enum(u3) { acquire, release_pool, release_deinit, share, retain, drop, grow })) {
            .acquire => {
                const wanted = smith.valueRangeAtMost(u16, 0, 2048);
                var acquired = try pool.acquire(wanted);
                errdefer acquired.deinit(gpa);
                try std.testing.expect(acquired.capacity() >= wanted);
                try std.testing.expectEqual(@as(usize, 0), acquired.readableLen());
                try live.append(gpa, acquired);
                acquires += 1;
            },
            // Two ways back to the pool that must be equivalent: naming the
            // pool, or just releasing the buffer and letting its recycler do it.
            .release_pool => {
                if (live.items.len == 0) continue;
                var item = live.swapRemove(smith.index(live.items.len));
                pool.release(&item);
            },
            .release_deinit => {
                if (live.items.len == 0) continue;
                var item = live.swapRemove(smith.index(live.items.len));
                item.deinit(gpa);
            },
            .share => {
                if (live.items.len == 0) continue;
                var item = live.swapRemove(smith.index(live.items.len));
                errdefer item.deinit(gpa);
                const box = try pool_mod.SharedBuffer.create(gpa, &item);
                try shared.append(gpa, box);
            },
            .retain => {
                if (shared.items.len == 0) continue;
                const box = shared.items[smith.index(shared.items.len)];
                const before = box.referenceCount();
                _ = box.retain();
                try std.testing.expectEqual(before + 1, box.referenceCount());
                box.release();
                try std.testing.expectEqual(before, box.referenceCount());
            },
            .drop => {
                if (shared.items.len == 0) continue;
                const box = shared.swapRemove(smith.index(shared.items.len));
                box.release();
            },
            .grow => {
                if (live.items.len == 0) continue;
                const item = &live.items[smith.index(live.items.len)];
                const wanted = smith.valueRangeAtMost(u16, 0, 4096);
                item.ensureWritable(gpa, wanted) catch |err| switch (err) {
                    error.BufferFull => {},
                    else => return err,
                };
            },
        }
    }

    const stats = pool.snapshotStats();
    try std.testing.expectEqual(acquires, stats.hits + stats.misses);
}

test "fuzz: BufferPool and SharedBuffer operation sequences" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzPool, .{ .corpus = &.{ "", "\x00\x01\x02\x03\x04\x05" } });
}

// -- WebSocket upgrade -----------------------------------------------------

fn installWebSocketUpgrade(pipeline: *Pipeline) anyerror!void {
    try websocket.addServerUpgrade(pipeline, .{
        .codec = .{ .max_frame_payload = 512, .max_message_length = 2048 },
    });
}

/// Builds an upgrade request whose every interesting field the fuzzer controls,
/// optionally followed by frames.
///
/// The frames matter as much as the handshake: a client is allowed to put its
/// first frame in the same packet as the upgrade request, which means those
/// bytes are sitting in the HTTP decoder's accumulation buffer at the moment the
/// handshake replaces it. Losing them there would be invisible to any test that
/// upgrades and then waits for a fresh read.
fn buildUpgrade(smith: *Smith, out: *std.ArrayList(u8), gpa: Allocator) !void {
    const methods = [_][]const u8{ "GET", "POST", "PUT" };
    const paths = [_][]const u8{ "/", "/ws", "/other" };
    const versions = [_][]const u8{ "13", "12", "", "abc" };
    const upgrades = [_][]const u8{ "websocket", "WebSocket", "h2c", "" };
    const connections = [_][]const u8{ "Upgrade", "upgrade, keep-alive", "keep-alive", "" };

    try out.print(gpa, "{s} {s} HTTP/1.1\r\nHost: h\r\n", .{
        methods[smith.index(methods.len)],
        paths[smith.index(paths.len)],
    });

    if (smith.boolWeighted(1, 6)) {
        try out.print(gpa, "Upgrade: {s}\r\n", .{upgrades[smith.index(upgrades.len)]});
    }
    if (smith.boolWeighted(1, 6)) {
        try out.print(gpa, "Connection: {s}\r\n", .{connections[smith.index(connections.len)]});
    }
    if (smith.boolWeighted(1, 6)) {
        try out.print(
            gpa,
            "Sec-WebSocket-Version: {s}\r\n",
            .{versions[smith.index(versions.len)]},
        );
    }
    if (smith.boolWeighted(1, 6)) {
        // A conforming key is 16 random bytes in base64; the fuzzer also gets to
        // send one of the wrong length.
        var raw: [16]u8 = @splat(0);
        smith.bytes(&raw);
        const keep = smith.valueRangeAtMost(u8, 0, 16);
        var encoded: [24]u8 = undefined;
        const base64 = std.base64.standard.Encoder;
        const written = base64.encode(&encoded, raw[0..keep]);
        try out.print(gpa, "Sec-WebSocket-Key: {s}\r\n", .{written});
    }
    try out.appendSlice(gpa, "\r\n");

    // Frames riding along in the same read as the upgrade.
    if (smith.value(bool)) {
        try buildWebSocketFrames(smith, out, gpa);
    }
}

fn fuzzUpgrade(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzUpgradeBody);
}

fn fuzzUpgradeBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);

    if (smith.boolWeighted(1, 4)) {
        var scratch: [max_input]u8 = undefined;
        const len = smith.slice(&scratch);
        try input.appendSlice(gpa, scratch[0..len]);
    } else {
        try buildUpgrade(smith, &input, gpa);
    }
    if (input.items.len > max_input) input.shrinkRetainingCapacity(max_input);

    try expectChunkIndependent(gpa, harness.io(), smith, input.items, installWebSocketUpgrade);
}

test "fuzz: WebSocket upgrade" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzUpgrade, .{ .corpus = &upgrade_corpus });
}

const upgrade_corpus = [_][]const u8{
    "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    // Upgrade and first frame in one read.
    "GET / HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" ++
        "\x81\x82\x01\x02\x03\x04\x69\x6b",
    // A plain request, which must be passed through rather than upgraded.
    "GET /plain HTTP/1.1\r\nHost: h\r\n\r\n",
};

// -- Harness self-check ----------------------------------------------------
//
// A fuzz target that observes nothing passes every input. These tests assert
// that the rig really does see what the targets claim to compare.

test "the rig records requests, frames, errors and events" {
    const gpa = std.testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    var transcript: Transcript = .{ .gpa = gpa };
    defer transcript.deinit();
    {
        var rig = try Rig.init(gpa, threaded.io(), &transcript);
        defer rig.deinit();
        try installHttpDecoder(rig.pipeline);
        try rig.finishSetup();
        try rig.feed("GET /seen HTTP/1.1\r\nHost: h\r\n\r\nnot a request");
        rig.finish();
    }

    // A decoded request, rendered in full.
    try std.testing.expect(std.mem.indexOf(u8, transcript.out.items, "REQ GET /seen") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript.out.items, "H Host=h") != null);
    // And the failure that followed it.
    try std.testing.expect(std.mem.indexOf(u8, transcript.out.items, "ERR ") != null);
}

test "the upgrade rig sees the handshake and the frame that shared its read" {
    const gpa = std.testing.allocator;
    var threaded = try backend.Runtime.init(gpa);
    defer threaded.deinit();

    var transcript: Transcript = .{ .gpa = gpa };
    defer transcript.deinit();
    {
        var rig = try Rig.init(gpa, threaded.io(), &transcript);
        defer rig.deinit();
        try installWebSocketUpgrade(rig.pipeline);
        try rig.finishSetup();
        // Corpus entry with the upgrade and the first frame in one read.
        try rig.feed(upgrade_corpus[1]);
        rig.finish();
    }

    // The handshake completed...
    try std.testing.expect(std.mem.indexOf(u8, transcript.out.items, "EVENT ") != null);
    // ...and the frame that arrived in the same read was not lost with the HTTP
    // decoder it was buffered in.
    try std.testing.expect(std.mem.indexOf(u8, transcript.out.items, "WS text") != null);
    try std.testing.expect(std.mem.indexOf(u8, transcript.out.items, "hi") != null);
}

// -- Redis RESP ------------------------------------------------------------

fn installRedisDecoder(pipeline: *Pipeline) anyerror!void {
    _ = try redis.Decoder.addTo(pipeline, .{
        .limits = .{
            // Small limits so the fuzzer reaches the boundary checks with short
            // inputs.
            .max_line = 128,
            .max_bulk = 512,
            .max_elements = 32,
            .max_depth = 6,
        },
    });
}

/// Builds a RESP value, recursing into aggregates the way the decoder does.
fn buildResp(smith: *Smith, out: *std.ArrayList(u8), gpa: Allocator, depth: u8) !void {
    const markers = "+-:$*_#,(!=%~>";
    const marker = markers[smith.index(markers.len)];

    // Past a certain depth, stop generating aggregates so the input stays short
    // enough to be interesting rather than just deep.
    const aggregate = marker == '*' or marker == '%' or marker == '~' or marker == '>';
    if (aggregate and depth >= 3) {
        try out.appendSlice(gpa, ":0\r\n");
        return;
    }

    switch (marker) {
        '+', '-', '(' => {
            const words = [_][]const u8{ "OK", "ERR nope", "12345678901234567890", "" };
            try out.print(gpa, "{c}{s}\r\n", .{ marker, words[smith.index(words.len)] });
        },
        ':' => {
            const numbers = [_][]const u8{ "0", "-1", "42", "9223372036854775807", "notanumber" };
            try out.print(gpa, ":{s}\r\n", .{numbers[smith.index(numbers.len)]});
        },
        '_' => try out.appendSlice(gpa, "_\r\n"),
        '#' => {
            const values = [_][]const u8{ "t", "f", "maybe" };
            try out.print(gpa, "#{s}\r\n", .{values[smith.index(values.len)]});
        },
        ',' => {
            const values = [_][]const u8{ "3.5", "inf", "-inf", "nan", "notafloat" };
            try out.print(gpa, ",{s}\r\n", .{values[smith.index(values.len)]});
        },
        '$', '!', '=' => {
            // Declared and actual lengths are chosen separately, so mismatches —
            // the case that decides where the next value starts — come up.
            const declared = smith.valueRangeAtMost(u8, 0, 8);
            const actual = smith.valueRangeAtMost(u8, 0, 8);
            if (smith.boolWeighted(1, 8)) {
                try out.print(gpa, "{c}-1\r\n", .{marker});
                return;
            }
            try out.print(gpa, "{c}{d}\r\n", .{ marker, declared });
            try out.appendNTimes(gpa, 'p', actual);
            try out.appendSlice(gpa, "\r\n");
        },
        '*', '~', '>' => {
            const count = smith.valueRangeAtMost(u8, 0, 3);
            if (smith.boolWeighted(1, 8)) {
                try out.print(gpa, "{c}-1\r\n", .{marker});
                return;
            }
            try out.print(gpa, "{c}{d}\r\n", .{ marker, count });
            for (0..count) |_| try buildResp(smith, out, gpa, depth + 1);
        },
        '%' => {
            const pairs = smith.valueRangeAtMost(u8, 0, 2);
            try out.print(gpa, "%{d}\r\n", .{pairs});
            for (0..@as(usize, pairs) * 2) |_| try buildResp(smith, out, gpa, depth + 1);
        },
        else => unreachable,
    }
}

fn fuzzRedis(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzRedisBody);
}

fn fuzzRedisBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);

    if (smith.value(bool)) {
        var values = smith.valueRangeAtMost(u8, 1, 4);
        while (values > 0) : (values -= 1) {
            try buildResp(smith, &input, gpa, 0);
            if (smith.eosWeightedSimple(1, 3)) break;
        }
    } else {
        var scratch: [max_input]u8 = undefined;
        const len = smith.slice(&scratch);
        try input.appendSlice(gpa, scratch[0..len]);
    }
    if (input.items.len > max_input) input.shrinkRetainingCapacity(max_input);

    try expectChunkIndependent(gpa, harness.io(), smith, input.items, installRedisDecoder);
}

test "fuzz: Redis RESP decoder" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzRedis, .{ .corpus = &redis_corpus });
}

const redis_corpus = [_][]const u8{
    "+OK\r\n",
    "-ERR nope\r\n",
    ":-1\r\n",
    "$5\r\nhello\r\n",
    "$-1\r\n",
    "$0\r\n\r\n",
    "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n",
    "*-1\r\n",
    // Nested, and the flattened map form.
    "*2\r\n*1\r\n:1\r\n%1\r\n+k\r\n#t\r\n",
    // Every RESP3 scalar.
    "_\r\n#t\r\n,inf\r\n(123\r\n!4\r\nboom\r\n=7\r\ntxt:abc\r\n~1\r\n:1\r\n>1\r\n+p\r\n",
    // A declared length that disagrees with what follows.
    "$2\r\nabcdef\r\n",
    // A nesting bomb.
    "*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n+deep\r\n",
    "?not a marker\r\n",
};

// -- WebSocket permessage-deflate -----------------------------------------

fn installDeflateCodec(pipeline: *Pipeline) anyerror!void {
    const codec = try pipeline.gpa.create(websocket.FrameCodec);
    codec.* = .init(.server, .{
        .max_frame_payload = 512,
        .max_message_length = 2048,
    });
    errdefer pipeline.gpa.destroy(codec);
    // Small enough that the fuzzer reaches the bomb guard with short inputs.
    codec.enableDeflate(.{ .max_decompressed_size = 8192 });
    _ = try pipeline.addLast(websocket.FrameCodec.handler_name, .initOwned(codec));
}

/// Emits frames whose RSV1 bit is often set and whose payload is sometimes a
/// real DEFLATE stream, so the fuzzer explores both the inflater and the
/// bookkeeping around it rather than only the header checks.
fn buildDeflateFrames(smith: *Smith, out: *std.ArrayList(u8), gpa: Allocator) !void {
    var deflate: permessage_deflate.Deflate = .init(.{});
    defer deflate.deinit(gpa);

    while (!smith.eosWeightedSimple(2, 1)) {
        const compressed = smith.boolWeighted(4, 1);
        const fin = smith.boolWeighted(4, 1);
        const opcode: u4 = if (smith.boolWeighted(4, 1)) 0x1 else smith.value(u4);

        var payload: []u8 = &.{};
        defer if (payload.len != 0) gpa.free(payload);

        if (compressed and smith.boolWeighted(3, 1)) {
            // A genuinely compressed payload, so the inflater sees valid input
            // often enough to exercise what happens after it succeeds.
            var plain: [64]u8 = undefined;
            const len = smith.slice(&plain);
            payload = try deflate.compress(gpa, plain[0..len]);
        } else {
            var scratch: [64]u8 = undefined;
            const len = smith.slice(&scratch);
            payload = try gpa.dupe(u8, scratch[0..len]);
        }

        var first: u8 = opcode;
        if (fin) first |= 0x80;
        if (compressed) first |= 0x40;
        try out.append(gpa, first);

        // Server role, so inbound frames must be masked to get past the header
        // check; an unmasked one is a useful case too, just a shallower one.
        const masked = smith.boolWeighted(8, 1);
        const short_len: u8 = @intCast(@min(payload.len, 125));
        try out.append(gpa, if (masked) short_len | 0x80 else short_len);
        if (masked) try out.appendSlice(gpa, &.{ 0x00, 0x00, 0x00, 0x00 });
        try out.appendSlice(gpa, payload[0..short_len]);
    }
}

fn fuzzDeflate(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzDeflateBody);
}

fn fuzzDeflateBody(harness: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);

    if (smith.value(bool)) {
        try buildDeflateFrames(smith, &input, gpa);
    } else {
        var scratch: [max_input]u8 = undefined;
        const len = smith.slice(&scratch);
        try input.appendSlice(gpa, scratch[0..len]);
    }
    if (input.items.len > max_input) input.shrinkRetainingCapacity(max_input);

    try expectChunkIndependent(gpa, harness.io(), smith, input.items, installDeflateCodec);
}

test "fuzz: WebSocket permessage-deflate decoder" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzDeflate, .{ .corpus = &deflate_corpus });
}

const deflate_corpus = [_][]const u8{
    // The compressed "Hello" from RFC 7692 §7.2.3.1, masked with a zero key so
    // a server accepts it.
    "\xc1\x87\x00\x00\x00\x00\xf2\x48\xcd\xc9\xc9\x07\x00",
    // The BFINAL form of §7.2.3.4.
    "\xc1\x88\x00\x00\x00\x00\xf3\x48\xcd\xc9\xc9\x07\x00\x00",
    // Fragmented, with RSV1 on the first frame only.
    "\x41\x83\x00\x00\x00\x00\xf2\x48\xcd\x80\x84\x00\x00\x00\x00\xc9\xc9\x07\x00",
    // RSV1 on a continuation, which RFC 7692 §6.1 forbids.
    "\x41\x82\x00\x00\x00\x00hi\xc0\x82\x00\x00\x00\x00hi",
    // RSV1 on a control frame, likewise forbidden.
    "\xc9\x80\x00\x00\x00\x00",
    // Garbage behind a set RSV1 bit.
    "\xc1\x84\x00\x00\x00\x00\xff\xfe\xfd\xfc",
    // An empty compressed payload.
    "\xc1\x80\x00\x00\x00\x00",
    // A single 0x00, which is an empty uncompressed block and decodes to nothing.
    "\xc1\x81\x00\x00\x00\x00\x00",
};

// -- Seeded stress ---------------------------------------------------------
//
// `zig build test` only replays the corpus, which is a handful of inputs.
// These tests drive the same bodies with pseudo-random `Smith` input so an
// ordinary test run covers thousands of cases, and a failure is reproducible
// from the printed seed.

/// Iterations per stress loop.
///
/// 400 for a long time, and measured to be too few: the HTTP/3 connection target found a
/// real disagreement between whole and fragmented delivery at iteration 1263, which every
/// run before that had missed. Raised with the cost measured rather than guessed — the
/// whole fuzz step takes about two minutes here at this count, and about six at 4000.
const stress_iterations = 1500;

/// Bytes a `Smith` can actually draw varied values from, which uniformly random
/// bytes are not.
///
/// `std/testing/Smith.zig` consumes eight bytes per draw, reads them as a
/// little-endian u64, and — if that value falls outside the range the caller asked
/// for — substitutes the range's *minimum* instead. Random bytes therefore give a
/// value near 2^63 on every draw, which is out of range for every small range a
/// target asks about, so every draw returns the minimum: `boolWeighted` is always
/// false, `valueRangeAtMost(u8, 1, 8)` is always 1, `slice` is always empty. These
/// stress loops ran four hundred iterations of one degenerate input each until this
/// was measured.
///
/// So the input is a sequence of small little-endian u64s: mostly tiny, so the
/// narrow ranges that select frame types and branches are hit; some moderate; a few
/// arbitrary, to keep exercising the out-of-range fallback that random bytes were
/// accidentally testing exclusively.
fn stressInput(random: std.Random, buf: []u8) usize {
    const draws = random.intRangeAtMost(usize, 0, buf.len / 8);
    for (0..draws) |i| {
        const value: u64 = switch (random.intRangeAtMost(u8, 0, 19)) {
            0...13 => random.intRangeAtMost(u64, 0, 7),
            14...17 => random.intRangeAtMost(u64, 0, 255),
            else => random.int(u64),
        };
        std.mem.writeInt(u64, buf[i * 8 ..][0..8], value, .little);
    }
    return draws * 8;
}

fn runStress(
    comptime body: fn (harness: *Harness, smith: *Smith) anyerror!void,
    seed: u64,
) !void {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();

    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();

    var input: [512]u8 = undefined;
    for (0..stress_iterations) |iteration| {
        const len = stressInput(random, &input);
        var smith: Smith = .{ .in = input[0..len] };
        body(&harness, &smith) catch |err| {
            std.debug.print(
                "stress failure: seed={d} iteration={d}: {s}\ninput: {f}\n",
                .{ seed, iteration, @errorName(err), std.ascii.hexEscape(input[0..len], .lower) },
            );
            return err;
        };
    }
}

test "stress: HTTP request decoder over random inputs" {
    try runStress(fuzzHttp, 0xA11CE);
}

test "stress: framing decoders over random inputs" {
    try runStress(fuzzFraming, 0xB0B);
}

test "stress: JSON value framing over random inputs" {
    try runStress(fuzzJson, 0x150F);
}

test "stress: HTTP/2 connection over random inputs" {
    try runStress(fuzzHttp2, 0x2000);
}

test "stress: HTTP/3 connection over random inputs" {
    try runStress(fuzzHttp3Connection, 0x3000);
}

test "stress: HPACK over random inputs" {
    try runStress(fuzzHpack, 0x7541);
}

test "stress: Huffman over random inputs" {
    try runStress(fuzzHuffman, 0xB00B);
}

test "stress: WebSocket frame decoder over random inputs" {
    try runStress(fuzzWebSocket, 0xC0FFEE);
}

test "stress: Buffer against a model over random inputs" {
    try runStress(fuzzBuffer, 0xD00D);
}

test "stress: WebSocket round trip over random inputs" {
    try runStress(fuzzWebSocketRoundTrip, 0xE11E);
}

test "stress: length-prefixed round trip over random inputs" {
    try runStress(fuzzLengthFieldRoundTrip, 0xF00F);
}

test "stress: BufferPool and SharedBuffer over random inputs" {
    try runStress(fuzzPool, 0x1234F);
}

test "stress: WebSocket upgrade over random inputs" {
    try runStress(fuzzUpgrade, 0x5150);
}

test "stress: HTTP response decoder over random inputs" {
    try runStress(fuzzResponse, 0xC0DE);
}

test "stress: Redis RESP decoder over random inputs" {
    try runStress(fuzzRedis, 0x1234ABCD);
}

test "stress: WebSocket permessage-deflate over random inputs" {
    try runStress(fuzzDeflate, 0xDEF1A7E);
}

// -- QUIC varint -------------------------------------------------------------

fn fuzzQuicVarintBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    _ = gpa;
    const varint = quic.varint;

    // Round trip at the minimal length, and at every longer legal length:
    // §16 explicitly permits non-minimal encodings, so all of them must
    // decode to the same value or two conforming peers disagree about the
    // same bytes.
    const value = smith.valueRangeAtMost(u64, 0, varint.max_value);
    var buf: [8]u8 = undefined;
    const min_len = varint.encode(&buf, value);
    var rest: []const u8 = buf[0..min_len];
    if (try varint.take(&rest) != value) return error.VarintRoundTrip;
    if (rest.len != 0) return error.VarintRoundTrip;

    for ([_]u4{ 1, 2, 4, 8 }) |len| {
        if (len < min_len) continue;
        _ = varint.encodeIn(&buf, value, len);
        if (varint.peekLen(buf[0]) != len) return error.VarintPeek;
        var wide: []const u8 = buf[0..len];
        if (try varint.take(&wide) != value) return error.VarintNonMinimal;
    }

    // Arbitrary bytes decode or refuse; either way no crash, and `take` never
    // consumes past what `peekLen` promised.
    var junk: [16]u8 = undefined;
    const junk_len = smith.slice(&junk);
    var slice: []const u8 = junk[0..junk_len];
    const before = slice.len;
    if (varint.take(&slice)) |_| {
        if (before - slice.len != varint.peekLen(junk[0])) return error.VarintConsumed;
    } else |_| {}
}

fn fuzzQuicVarint(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzQuicVarintBody);
}

test "fuzz: QUIC varint round trip and arbitrary bytes" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzQuicVarint, .{ .corpus = &.{
        "",
        "\x00",
        "\xc0\x00\x00\x00\x00\x00\x00\x01",
    } });
}

// -- QUIC frames -------------------------------------------------------------

fn fuzzQuicFrameBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    _ = gpa;

    // Arbitrary bytes: parse until refusal or exhaustion. The parser must
    // neither crash nor loop — every iteration consumes at least one byte.
    var payload: [512]u8 = undefined;
    const len = smith.slice(&payload);
    var rest: []const u8 = payload[0..len];
    while (rest.len > 0) {
        const remaining = rest.len;
        const parsed = quic.frame.parse(&rest) catch break;
        if (rest.len >= remaining) return error.FrameNoProgress;

        // Whatever parsed must re-encode into exactly `encodedLen` bytes and
        // parse back equal in type. (Full structural equality is checked by
        // the unit tests; the property here is that the encoder and parser
        // agree about *lengths*, because a disagreement there desynchronizes
        // every frame after this one in the packet.)
        const need = quic.frame.encodedLen(parsed);
        if (need > 600) continue; // ACK ranges borrow from input; skip giants
        var out: [600]u8 = undefined;
        const written = quic.frame.encode(&out, parsed);
        if (written != need) return error.FrameLengthLied;
        var back: []const u8 = out[0..written];
        const again = quic.frame.parse(&back) catch return error.FrameReparse;
        if (std.meta.activeTag(again) != std.meta.activeTag(parsed)) return error.FrameChanged;
    }
}

fn fuzzQuicFrame(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzQuicFrameBody);
}

test "fuzz: QUIC frame parser on arbitrary bytes" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzQuicFrame, .{
        .corpus = &.{
            "\x01\x01\x01", // PING, PING, PING
            "\x02\x05\x00\x00\x00", // a minimal ACK
            "\x08\x00hello", // STREAM without length
            "\x18", // truncated NEW_CONNECTION_ID
        },
    });
}

// -- QUIC packets ------------------------------------------------------------

fn fuzzQuicPacketBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    _ = gpa;

    // The parser sees attacker bytes before any key is applied, so this is the
    // most exposed parser in the stack: arbitrary bytes at every legal local
    // CID length, walking coalesced packets the way `Connection.receive` does.
    var datagram: [1500]u8 = undefined;
    const len = smith.slice(&datagram);
    const local_cid_len = smith.valueRangeAtMost(u8, 0, 20);

    var offset: usize = 0;
    while (offset < len) {
        const parsed = quic.packet.parse(datagram[offset..len], local_cid_len) catch break;
        if (parsed.end == 0) return error.PacketNoProgress;
        offset += parsed.end;
        if (offset > len) return error.PacketOverran;
    }
}

fn fuzzQuicPacket(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzQuicPacketBody);
}

test "fuzz: QUIC packet parser on arbitrary bytes" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzQuicPacket, .{
        .corpus = &.{
            "",
            "\x40\x01\x02\x03", // short header
            "\xc0\x00\x00\x00\x01\x00\x00", // long header, v1
            "\x80\x00\x00\x00\x00", // version negotiation shape
        },
    });
}

// -- QUIC ACK ranges ---------------------------------------------------------

fn fuzzAckRangesBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    _ = gpa;

    // The range set against a plain bitmap model. The bound makes exact
    // equality impossible by design — eviction loses information — so the
    // properties are one-sided where they must be and exact where they can be:
    //  * no false positives: contains(pn) implies the model saw pn;
    //  * the largest is exact: §19.3 requires it never be evicted;
    //  * the wire invariants hold: descending, disjoint, non-adjacent.
    const universe = 512;
    var model: [universe]bool = @splat(false);
    var set: quic.recovery.AckRanges = .{};
    var highest: ?u64 = null;

    var steps = smith.valueRangeAtMost(u16, 1, 200);
    while (steps > 0) : (steps -= 1) {
        if (smith.boolWeighted(3, 1)) {
            const pn = smith.valueRangeAtMost(u64, 0, universe - 1);
            set.add(pn);
            model[@intCast(pn)] = true;
            if (highest == null or pn > highest.?) highest = pn;
        } else {
            const from = smith.valueRangeAtMost(u64, 0, universe - 1);
            const span = smith.valueRangeAtMost(u64, 0, 40);
            const to = @min(from + span, universe - 1);
            _ = set.addRange(from, to);
            var pn = from;
            while (pn <= to) : (pn += 1) model[@intCast(pn)] = true;
            if (highest == null or to > highest.?) highest = to;
        }
    }

    if (highest) |top| {
        if (set.largest() != top) return error.AckLostLargest;
    }
    var previous: ?quic.frame.Ack.Range = null;
    for (set.slice()) |range| {
        if (range.smallest > range.largest) return error.AckInverted;
        if (previous) |before| {
            // Strictly below, with a gap: adjacent ranges must have merged.
            if (range.largest + 1 >= before.smallest) return error.AckNotDisjoint;
        }
        previous = range;
        var pn = range.smallest;
        while (pn <= range.largest) : (pn += 1) {
            if (!model[@intCast(pn)]) return error.AckFalsePositive;
        }
    }
}

fn fuzzAckRanges(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzAckRangesBody);
}

test "fuzz: QUIC ACK ranges against a bitmap model" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzAckRanges, .{ .corpus = &.{
        "",
        "\x01\x02\x03\x04\x05\x06\x07\x08",
    } });
}

// -- HTTP/3 connection -------------------------------------------------------

/// The state machine above the frame parser: which frame is permitted on which
/// stream in which state, and what the peer is told when one is not.
///
/// The frame-parser target next door covers reassembly. This one covers the layer
/// that has the state — request streams with their own grammar, a control stream
/// whose rules differ, tunnels, GOAWAY in both directions, cancellation — and it is
/// the layer the equivalent HTTP/2 target has repeatedly found defects in.
///
/// The property is chunk independence again, one level up, because that is where a
/// stateful reader gets it wrong: bytes are delivered to the connection either in one
/// write or in pieces *with the connection driven between them*, so a frame can be
/// half-arrived when the reader returns and has to resume from its own state. The
/// event transcripts must be identical. Body bytes are recorded as bytes rather than
/// per-event, for the same reason the parser target does it: DATA is delivered as it
/// arrives, so a split frame legitimately produces more events carrying the same
/// bytes.
fn fuzzHttp3ConnectionBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    // Which of the two stream kinds the bytes land on. The control stream has its own
    // rules (§7.2: SETTINGS once and first, GOAWAY monotonic, no DATA), so fuzzing
    // only request streams would leave that half of the state machine unvisited.
    const on_control = smith.boolWeighted(1, 2);

    // A *sequence of frames* rather than arbitrary bytes, which is the difference
    // between fuzzing the state machine and fuzzing the parser next door. Raw bytes
    // were tried first and do not reach this layer: a request stream whose first
    // frame is not a well-formed field section is failed with H3_MESSAGE_ERROR
    // (§4.1.2) before any state exists, so almost every input exercised that one
    // rejection and nothing else. A mutation to the "stream finished" condition
    // survived both the unit suite and the raw-bytes version of this target; it does
    // not survive this one.
    var built: std.ArrayList(u8) = .empty;
    defer built.deinit(gpa);
    try buildH3Stream(gpa, smith, on_control, &built);
    const input = built.items;
    // Whether the stream ends after the bytes. Without this the FIN path is never
    // reached, and a whole class of rules lives there: which frame may be the last
    // (§4.1), a truncated frame at a clean end (§7.1), and on the control stream
    // §6.2.1's H3_CLOSED_CRITICAL_STREAM. The first version of this target omitted
    // it, and a mutation that decided "stream finished" without checking that the
    // item consumed the whole buffer went unnoticed by the unit suite *and* by this
    // target — because `fin_seen` was never true in either run.
    const finish = smith.boolWeighted(1, 2);
    // Whether a genuine, valid HEADERS frame goes first. Without one almost nothing
    // gets past the front door: a request stream whose first frame is not a
    // well-formed field section is failed with H3_MESSAGE_ERROR immediately (§4.1.2),
    // so random bytes would only ever exercise that one rejection. With the prefix,
    // the fuzzer's bytes are read in `headers_received` — where DATA, trailers,
    // tunnels and the rest of the grammar actually live.
    const prefixed = !on_control and smith.boolWeighted(3, 1);

    var whole: std.ArrayList(u8) = .empty;
    defer whole.deinit(gpa);
    const whole_failed = try h3ConnectionTranscript(gpa, .{
        .input = input,
        .on_control = on_control,
        .finish = finish,
        .prefixed = prefixed,
    }, null, &whole);

    var split: std.ArrayList(u8) = .empty;
    defer split.deinit(gpa);
    const split_failed = try h3ConnectionTranscript(gpa, .{
        .input = input,
        .on_control = on_control,
        .finish = finish,
        .prefixed = prefixed,
    }, smith, &split);

    if (whole_failed != split_failed) {
        std.debug.print("h3 outcome differs: whole_failed={} split_failed={}\n", .{
            whole_failed, split_failed,
        });
        return error.H3ConnectionOutcomeDiffers;
    }
    if (!std.mem.eql(u8, whole.items, split.items)) {
        // Printed rather than merely reported: the two transcripts *are* the bug
        // report, and reconstructing them from a seed is work the next reader should
        // not have to do.
        std.debug.print(
            "h3 transcripts differ (control={} finish={} prefixed={} bytes={d}):\n  whole: {f}\n  split: {f}\n",
            .{
                on_control,                               finish,
                prefixed,                                 input.len,
                std.ascii.hexEscape(whole.items, .lower), std.ascii.hexEscape(split.items, .lower),
            },
        );
        return error.H3ConnectionTranscriptDiffers;
    }
}

/// Feeds `input` to a server connection and records what it reports. With `smith`,
/// the bytes go in fuzzer-chosen pieces and the connection is driven between them.
/// Returns whether the exchange ended in an error, which is itself part of the
/// comparison.
const H3Case = struct {
    input: []const u8,
    on_control: bool,
    finish: bool,
    prefixed: bool,
};

fn h3ConnectionTranscript(
    gpa: Allocator,
    case: H3Case,
    smith: ?*Smith,
    out: *std.ArrayList(u8),
) !bool {
    var pair = try http3.connection.testPair(gpa);
    const client = &pair.client;
    const server = &pair.server;
    defer client.deinit(gpa);
    defer server.deinit(gpa);
    // Settle the handshake and both control streams first, so the transcript is
    // about the fuzzer's bytes rather than about connection setup.
    http3.connection.pumpH3(gpa, client, server, 16) catch return true;
    while (server.nextEvent()) |_| {}

    const stream = if (case.on_control)
        client.control_out orelse return true
    else
        client.transport.openStream(gpa, true) catch return true;

    var failed = false;
    var ends: usize = 0;
    if (case.prefixed) {
        h3WriteValidHeaders(gpa, client, stream) catch return true;
        http3.connection.pumpH3(gpa, client, server, 4) catch return true;
        try recordH3Events(gpa, server, out, &ends);
    }
    if (smith) |chooser| {
        var offset: usize = 0;
        while (offset < case.input.len) {
            const remaining = case.input.len - offset;
            // Small pieces on purpose. With chunks as large as the built stream, the
            // "fragmented" run is the whole run again and the comparison proves
            // nothing — which is how a mutation to the "stream finished" condition
            // first slipped through this target.
            const chunk_len: usize = chooser.valueRangeAtMost(u16, 1, @intCast(@min(8, remaining)));
            _ = client.transport.write(gpa, stream, case.input[offset..][0..chunk_len]) catch {
                failed = true;
                break;
            };
            offset += chunk_len;
            // Driving here is the point: the server resumes mid-frame.
            http3.connection.pumpH3(gpa, client, server, 4) catch {
                failed = true;
                break;
            };
            try recordH3Events(gpa, server, out, &ends);
        }
    } else {
        _ = client.transport.write(gpa, stream, case.input) catch {
            failed = true;
        };
    }

    if (!failed and case.finish) {
        client.transport.finishStream(stream) catch {
            failed = true;
        };
    }
    if (!failed) {
        http3.connection.pumpH3(gpa, client, server, 8) catch {
            failed = true;
        };
    }
    try recordH3Events(gpa, server, out, &ends);

    // One marker per reported end, at a fixed place rather than where it happened.
    for (0..ends) |_| try out.appendSlice(gpa, "|END;");

    // Terminal states are terminal: once the connection has been failed, nothing
    // further may be reported. A state machine that keeps emitting after closing is
    // telling the application about a connection that no longer exists.
    if (server.close_code) |code| {
        try out.appendSlice(gpa, "CLOSE:");
        try out.appendSlice(gpa, &std.mem.toBytes(code));
        try out.append(gpa, ';');
        if (server.nextEvent() != null) return error.H3EventsAfterClose;
    }
    return failed;
}

/// A sequence of HTTP/3 frames, mostly well-formed, for the stream kind named.
/// Well-formed most of the time on purpose: the interesting rules are about which
/// frame is permitted *where*, and a stream that dies on its first frame never
/// reaches them.
fn buildH3Stream(gpa: Allocator, smith: *Smith, on_control: bool, out: *std.ArrayList(u8)) !void {
    var remaining = smith.valueRangeAtMost(u8, 1, 8);
    while (remaining > 0) : (remaining -= 1) {
        // Weighted by what the stream kind permits, which is not a nicety: §7.2 makes
        // most types fatal on the wrong stream, so choosing uniformly means the
        // connection dies on the first frame and the *sequence* rules — trailers after
        // DATA, a second HEADERS, FIN placement — are never reached. Measured: with a
        // uniform choice this target never once produced two events.
        //
        // The wrong type still appears, one time in eight, because "fatal on the wrong
        // stream" is itself a rule worth exercising.
        const kind: u64 = if (on_control) switch (smith.valueRangeAtMost(u8, 0, 5)) {
            0, 1 => 0x07, // GOAWAY, whose identifier must not increase (§7.2.6)
            2 => 0x0d, // MAX_PUSH_ID, which must not decrease (§7.2.7)
            3 => 0x21, // reserved: 0x1f * 0 + 0x21
            4 => 0x4242, // a type we do not know, which §9 says to ignore
            else => 0x00, // DATA, which §7.2.1 forbids here
        } else switch (smith.valueRangeAtMost(u8, 0, 7)) {
            0, 1, 2 => 0x00, // DATA
            3, 4 => 0x01, // HEADERS: a request, trailers, or a second one
            5 => 0x21, // reserved
            6 => 0x4242, // unknown
            else => 0x04, // SETTINGS, which §7.2.4 forbids off the control stream
        };

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(gpa);

        if (kind == 0x01 and smith.boolWeighted(4, 1)) {
            // A field section QPACK can decode, so the layers above it are reached
            // rather than only its error path. Sometimes a request, sometimes
            // trailers, sometimes a response — which is malformed at a server and so
            // exercises §4.3's direction rules.
            const fields: []const http3.qpack.FieldLine = switch (smith.valueRangeAtMost(u8, 0, 3)) {
                0 => &.{
                    .{ .name = ":method", .value = "POST" },
                    .{ .name = ":scheme", .value = "https" },
                    .{ .name = ":authority", .value = "fuzz.test" },
                    .{ .name = ":path", .value = "/" },
                },
                1 => &.{
                    .{ .name = ":method", .value = "CONNECT" },
                    .{ .name = ":authority", .value = "fuzz.test:443" },
                },
                2 => &.{.{ .name = "x-checksum", .value = "abc" }},
                else => &.{.{ .name = ":status", .value = "200" }},
            };
            try http3.qpack.encodeSection(gpa, &payload, fields);
        } else if (kind == 0x04) {
            // Settings the iterator will accept, and occasionally a value it must
            // reject (RFC 8441 §3 permits only 0 or 1 for 0x08).
            var buf: [16]u8 = undefined;
            var n = quic.varint.encode(&buf, 0x06); // MAX_FIELD_SECTION_SIZE
            n += quic.varint.encode(buf[n..], smith.valueRangeAtMost(u16, 0, 4096));
            n += quic.varint.encode(buf[n..], 0x08); // ENABLE_CONNECT_PROTOCOL
            n += quic.varint.encode(buf[n..], smith.valueRangeAtMost(u8, 0, 2));
            try payload.appendSlice(gpa, buf[0..n]);
        } else if (kind == 0x03 or kind == 0x07 or kind == 0x0d) {
            // These carry one varint, and the identifier rules (§7.2.6's monotonic
            // GOAWAY, §7.2.7's non-decreasing MAX_PUSH_ID) are what is under test.
            var buf: [8]u8 = undefined;
            const n = quic.varint.encode(&buf, smith.valueRangeAtMost(u8, 0, 16));
            try payload.appendSlice(gpa, buf[0..n]);
        } else {
            var scratch: [64]u8 = undefined;
            const n = smith.slice(&scratch);
            try payload.appendSlice(gpa, scratch[0..n]);
        }

        var header: [16]u8 = undefined;
        // A length that lies, now and then: §7.1 makes a payload that ends early or
        // late an H3_FRAME_ERROR, and that check is only reached if the length is
        // sometimes wrong.
        const declared = if (smith.boolWeighted(1, 16))
            smith.valueRangeAtMost(u8, 0, 32)
        else
            payload.items.len;
        const header_len = http3.frame.writeFrameHeader(&header, kind, declared);
        try out.appendSlice(gpa, header[0..header_len]);
        try out.appendSlice(gpa, payload.items);

        if (on_control and remaining == 1 and smith.boolWeighted(1, 8)) {
            // Trailing junk after the last frame, which a stateful reader has to hold
            // rather than mistake for a frame header.
            var scratch: [8]u8 = undefined;
            const n = smith.slice(&scratch);
            try out.appendSlice(gpa, scratch[0..n]);
        }
    }
}

/// A well-formed request header section, written as a HEADERS frame. §4.3.1's
/// mandatory set for anything but CONNECT, so the server accepts it and moves on.
fn h3WriteValidHeaders(gpa: Allocator, conn: *http3.connection.Connection, stream: u64) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(gpa);
    try http3.qpack.encodeSection(gpa, &encoded, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "fuzz.test" },
        .{ .name = ":path", .value = "/" },
    });
    var header: [16]u8 = undefined;
    const header_len = http3.frame.writeFrameHeader(
        &header,
        @backingInt(http3.frame.FrameType.headers),
        encoded.items.len,
    );
    _ = try conn.transport.write(gpa, stream, header[0..header_len]);
    _ = try conn.transport.write(gpa, stream, encoded.items);
}

fn recordH3Events(
    gpa: Allocator,
    conn: *http3.connection.Connection,
    out: *std.ArrayList(u8),
    ends: *usize,
) !void {
    while (conn.nextEvent()) |event| switch (event) {
        .established => try out.appendSlice(gpa, "EST;"),
        // RFC 9297 datagrams are not part of this target's alphabet: the transcript is
        // built from stream frames, and a datagram cannot arrive from one. Recorded
        // rather than ignored so that a future generator emitting them cannot silently
        // produce transcripts that compare equal by omission.
        .datagram => try out.appendSlice(gpa, "DG;"),
        .headers => |e| {
            try out.appendSlice(gpa, "H:");
            // The end is *counted*, not recorded here. Which event carries it depends on
            // whether QUIC delivered the FIN with the field section, with the last body
            // bytes, or on its own afterwards — the same delivery-dependent detail that
            // already makes body bytes rather than body *events* the thing compared. What
            // must match is the sections, the bytes, and that the end appears exactly
            // once, so the count is compared as a suffix instead of a position.
            if (e.fin) ends.* += 1;
            // The section itself, so that two runs differing in *what* they decoded
            // are caught and not only two runs differing in event order.
            if (conn.takeSection(e.stream)) |taken| {
                var section = taken;
                defer section.deinit(gpa);
                for (section.fields.items) |field| {
                    try out.appendSlice(gpa, field.name);
                    try out.append(gpa, '=');
                    try out.appendSlice(gpa, field.value);
                    try out.append(gpa, ',');
                }
            }
            try out.append(gpa, ';');
        },
        .body => |e| {
            // Bytes, not events: see the note on the target above.
            const chunk = conn.readBody(e.stream);
            try out.appendSlice(gpa, chunk);
            conn.consumeBody(e.stream, chunk.len);
            if (e.fin) ends.* += 1;
        },
        .goaway => |e| {
            try out.appendSlice(gpa, "GO:");
            try out.appendSlice(gpa, &std.mem.toBytes(e.id));
            try out.append(gpa, ';');
        },
        .stream_reset => |e| {
            try out.appendSlice(gpa, "RST:");
            try out.appendSlice(gpa, &std.mem.toBytes(e.code));
            try out.append(gpa, ';');
        },
        .peer_closed => |e| {
            try out.appendSlice(gpa, "PEER:");
            try out.appendSlice(gpa, &std.mem.toBytes(e.code));
            try out.append(gpa, ';');
        },
        .idle_timeout => try out.appendSlice(gpa, "IDLE;"),
    };
}

fn fuzzHttp3Connection(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzHttp3ConnectionBody);
}

test "fuzz: HTTP/3 connection state machine" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzHttp3Connection, .{
        .corpus = &.{
            "",
            "\x01\x00", // an empty HEADERS: a field section with no fields
            "\x00\x05hello", // DATA with no HEADERS before it (§4.1: unexpected)
            "\x04\x00", // a second SETTINGS, which §7.2.4 forbids
            "\x07\x04", // GOAWAY
            "\x0d\x00", // MAX_PUSH_ID
            "\x21\x02ab", // a reserved type, which must be ignored
            "\x01\x04\x00\x00\xd1\xd7", // HEADERS with an indexed :method GET, :scheme https
        },
    });
}

// -- HTTP/3 frames -----------------------------------------------------------

fn fuzzHttp3FrameBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    // Chunk independence, the repository's central fuzz property, for the one
    // parser in the HTTP/3 stack that reassembles a stream: whatever items a
    // whole-buffer parse yields, a parse over arbitrary fragments must yield
    // identically — HTTP/3 frames arrive in whatever pieces QUIC's packetizer
    // chose, so the fragmentation is the peer's choice, not ours.
    var bytes: [768]u8 = undefined;
    const len = smith.slice(&bytes);
    const input = bytes[0..len];

    var whole_transcript: std.ArrayList(u8) = .empty;
    defer whole_transcript.deinit(gpa);
    var whole_failed = false;
    {
        var parser: http3.frame.Parser = .{};
        defer parser.deinit(gpa);
        transcribeH3(gpa, &parser, input, &whole_transcript) catch {
            whole_failed = true;
        };
    }

    var split_transcript: std.ArrayList(u8) = .empty;
    defer split_transcript.deinit(gpa);
    var split_failed = false;
    {
        var parser: http3.frame.Parser = .{};
        defer parser.deinit(gpa);
        var offset: usize = 0;
        outer: while (offset < input.len) {
            const chunk_len: usize = smith.valueRangeAtMost(u16, 1, @intCast(@min(64, input.len - offset)));
            const chunk = input[offset .. offset + chunk_len];
            offset += chunk_len;
            transcribeH3(gpa, &parser, chunk, &split_transcript) catch {
                split_failed = true;
                break :outer;
            };
        }
    }

    if (whole_failed != split_failed) return error.H3ErrorDisagrees;
    if (!whole_failed) {
        if (!std.mem.eql(u8, whole_transcript.items, split_transcript.items)) {
            return error.H3ChunkDependent;
        }
    } else {
        // Up to the failure point the transcripts must still agree: an error
        // must not depend on where the chunk boundaries fell either.
        const shorter = @min(whole_transcript.items.len, split_transcript.items.len);
        if (!std.mem.eql(u8, whole_transcript.items[0..shorter], split_transcript.items[0..shorter])) {
            return error.H3ChunkDependent;
        }
    }
}

/// Append a canonical record of every parsed item, so two parses can be
/// compared byte for byte. Body chunks are folded together, because how DATA
/// is split across deliveries is explicitly not part of the contract — only
/// the bytes and the boundary are.
fn transcribeH3(
    gpa: Allocator,
    parser: *http3.frame.Parser,
    input: []const u8,
    out: *std.ArrayList(u8),
) !void {
    var rest = input;
    while (rest.len > 0) {
        const result = (try parser.next(gpa, rest)) orelse break;
        rest = rest[result.consumed..];
        switch (result.item) {
            .frame => |f| {
                try out.append(gpa, 'F');
                try out.append(gpa, @backingInt(std.meta.activeTag(f)));
                switch (f) {
                    .headers => |p| try out.appendSlice(gpa, p),
                    .settings => |p| try out.appendSlice(gpa, p),
                    .cancel_push, .goaway, .max_push_id => |v| {
                        try out.appendSlice(gpa, &std.mem.toBytes(v));
                    },
                    .push_promise => |p| {
                        try out.appendSlice(gpa, &std.mem.toBytes(p.push_id));
                        try out.appendSlice(gpa, p.field_section);
                    },
                    .unknown => |u| {
                        try out.appendSlice(gpa, &std.mem.toBytes(u.frame_type));
                        try out.appendSlice(gpa, u.payload);
                    },
                    .data => unreachable,
                }
                try out.append(gpa, ';');
            },
            .body_chunk => |chunk| {
                try out.appendSlice(gpa, chunk.bytes);
                if (chunk.last) try out.appendSlice(gpa, "|END;");
            },
        }
    }
}

fn fuzzHttp3Frame(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzHttp3FrameBody);
}

test "fuzz: HTTP/3 frame parser chunk independence" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzHttp3Frame, .{
        .corpus = &.{
            "\x04\x00", // empty SETTINGS
            "\x00\x05hello\x01\x02hh", // DATA then HEADERS
            "\x21\x03abc", // grease frame
            "\x07\x01\x08", // GOAWAY
        },
    });
}

// -- QPACK -------------------------------------------------------------------

fn fuzzQpackBody(_: *Harness, smith: *Smith, gpa: Allocator) anyerror!void {
    const qpack = http3.qpack;

    // Round trip: random fields (some binary, some marked never-index) encode
    // and decode back to the same names, values and N bits.
    var names: [4][24]u8 = undefined;
    var values: [4][48]u8 = undefined;
    var fields: [4]qpack.FieldLine = undefined;
    const count: usize = smith.valueRangeAtMost(u8, 0, 4);
    for (0..count) |i| {
        var name_len: usize = smith.valueRangeAtMost(u8, 1, 24);
        smith.bytes(names[i][0..name_len]);
        // Names with ':' collide with pseudo-field parsing at higher layers but
        // are legal for the codec itself; keep them, the codec must carry them.
        const value_len: usize = smith.valueRangeAtMost(u8, 0, 48);
        smith.bytes(values[i][0..value_len]);
        _ = &name_len;
        fields[i] = .{
            .name = names[i][0..name_len],
            .value = values[i][0..value_len],
            .never_index = smith.boolWeighted(3, 1),
        };
    }

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(gpa);
    try qpack.encodeSection(gpa, &encoded, fields[0..count]);

    var section = try qpack.decodeSection(gpa, encoded.items, .{});
    defer section.deinit(gpa);
    if (section.fields.items.len != count) return error.QpackCount;
    for (fields[0..count], section.fields.items) |sent, got| {
        if (!std.mem.eql(u8, sent.name, got.name)) return error.QpackName;
        if (!std.mem.eql(u8, sent.value, got.value)) return error.QpackValue;
        if (sent.never_index != got.never_index) return error.QpackNeverIndex;
    }

    // Arbitrary bytes: decode refuses or succeeds, never crashes and never
    // leaks (the leak check around this body is the second half of the claim).
    var junk: [256]u8 = undefined;
    const junk_len = smith.slice(&junk);
    if (qpack.decodeSection(gpa, junk[0..junk_len], .{
        .max_field_section_size = 1 << 20,
    })) |*ok| {
        var owned = ok.*;
        owned.deinit(gpa);
    } else |_| {}

    // Decoder-stream instructions: arbitrary bytes parse incrementally without
    // crashing, and whatever parses applies or refuses per the zero-capacity
    // rules.
    var stream: []const u8 = junk[0..junk_len];
    while (true) {
        const parsed = qpack.parseDecoderInstruction(&stream) catch break;
        const instruction = parsed orelse break;
        qpack.applyDecoderInstruction(instruction) catch break;
    }
}

fn fuzzQpack(harness: *Harness, smith: *Smith) anyerror!void {
    return withLeakCheck(harness, smith, fuzzQpackBody);
}

test "fuzz: QPACK sections round trip and survive arbitrary bytes" {
    var harness: Harness = try .init(std.testing.allocator);
    defer harness.deinit();
    try std.testing.fuzz(&harness, fuzzQpack, .{
        .corpus = &.{
            "",
            "\x00\x00\xd1", // prefix + :method GET
            "\x00\x00\xff\xff\xff\xff", // huge index
        },
    });
}
