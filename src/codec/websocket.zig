//! WebSocket (RFC 6455): the handshake and the frame codec.
//!
//! Two handlers live here:
//!
//! * `Handshaker` completes the HTTP upgrade and then **rewrites its own
//!   pipeline**, swapping the HTTP codec for the WebSocket codec. That is the
//!   capability a static, compile-time pipeline could not provide, and the
//!   reason Zinet's chain is dynamic.
//! * `FrameCodec` decodes and encodes frames, reassembles fragments, and
//!   answers control frames.
//!
//! # What is enforced
//!
//! * A client-to-server frame must be masked, and a server-to-client frame must
//!   not be. Both are protocol errors in the other direction.
//! * Control frames are never fragmented and carry at most 125 bytes.
//! * Reserved bits must be clear, since no extension is negotiated.
//! * Payloads and reassembled messages are bounded by configuration.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../buffer.zig").Buffer;
pub const pmd = @import("permessage_deflate.zig");
const codec_mod = @import("codec.zig");
const pipeline_mod = @import("../pipeline.zig");

const ByteToMessageDecoder = codec_mod.ByteToMessageDecoder;
const CodecError = codec_mod.Error;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Frame opcodes. Values are the wire encoding.
pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
    _,

    /// Control opcodes are 0x8 and above; they may not be fragmented.
    pub fn isControl(opcode: Opcode) bool {
        return @backingInt(opcode) & 0x8 != 0;
    }

    pub fn isKnown(opcode: Opcode) bool {
        return switch (opcode) {
            .continuation, .text, .binary, .close, .ping, .pong => true,
            _ => false,
        };
    }
};

/// Close status codes this codec produces or recognizes.
pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status = 1005,
    abnormal = 1006,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    internal_error = 1011,
    _,

    pub fn value(code: CloseCode) u16 {
        return @backingInt(code);
    }
};

/// A complete WebSocket message, delivered inbound and accepted outbound.
///
/// Fragmented frames are reassembled before delivery, so a handler always sees
/// whole messages. The payload is owned by the message that carries this value.
pub const Frame = struct {
    opcode: Opcode,
    payload: []const u8,
    /// Present on a close frame that carried a status code.
    close_code: ?CloseCode = null,

    /// Releases the payload. Called through `Message`'s destructor.
    pub fn deinit(frame: *Frame, gpa: Allocator) void {
        gpa.free(@constCast(frame.payload));
    }

    /// Text payload, or null when this is not a text frame.
    pub fn text(frame: Frame) ?[]const u8 {
        return if (frame.opcode == .text) frame.payload else null;
    }
};

/// A frame to send. Borrows its payload, which must live until the write
/// returns; the encoder serializes synchronously.
pub const OutboundFrame = struct {
    opcode: Opcode = .text,
    payload: []const u8 = "",
    /// Sent as the first two payload bytes of a close frame.
    close_code: ?CloseCode = null,
    /// Client-to-server frames must be masked. A server leaves this false.
    mask: bool = false,

    pub fn textFrame(payload: []const u8) OutboundFrame {
        return .{ .opcode = .text, .payload = payload };
    }

    pub fn binaryFrame(payload: []const u8) OutboundFrame {
        return .{ .opcode = .binary, .payload = payload };
    }

    pub fn closeFrame(code: CloseCode, reason: []const u8) OutboundFrame {
        return .{ .opcode = .close, .close_code = code, .payload = reason };
    }
};

/// Header of one frame as it appears on the wire.
const FrameHeader = struct {
    fin: bool,
    /// The "Per-Message Compressed" bit, set only on the first frame of a
    /// message and only when `permessage-deflate` is in use.
    compressed: bool,
    opcode: Opcode,
    masked: bool,
    payload_len: u64,
    mask_key: [4]u8,
    /// Total header size in bytes.
    header_len: usize,
};

pub const Role = enum {
    /// Expects masked frames inbound, sends unmasked.
    server,
    /// Expects unmasked frames inbound, sends masked.
    client,

    fn expectsMaskedInbound(role: Role) bool {
        return role == .server;
    }

    fn masksOutbound(role: Role) bool {
        return role == .client;
    }
};

/// Decodes frames into `Frame` messages and encodes `OutboundFrame` messages.
pub const FrameCodec = struct {
    decoder: ByteToMessageDecoder(FrameCodec),
    options: Options,
    role: Role,
    /// Opcode of the fragmented message being reassembled, if any.
    fragment_opcode: ?Opcode = null,
    /// Payload accumulated across fragments.
    fragments: std.ArrayList(u8) = .empty,
    /// Set once a close frame has been seen, so nothing is decoded after it.
    closed: bool = false,
    /// Set once a close frame has been sent, so the closing handshake is
    /// announced exactly once however it was triggered.
    close_sent: bool = false,
    /// Set once a protocol violation has been reported.
    ///
    /// RFC 6455 §7.1.7 requires a protocol error to *fail* the connection, not
    /// to be skipped: the frame boundaries are no longer trustworthy, so there
    /// is nothing to resynchronize to. Without this latch the offending bytes
    /// stay accumulated and every later read re-reports the same violation,
    /// which a peer can turn into an unbounded error storm by dribbling bytes
    /// after one bad frame header.
    failed: bool = false,
    /// Compression state, present exactly when `permessage-deflate` was
    /// negotiated. The handshakers install it; nothing pays for it otherwise.
    deflate: ?pmd.Deflate = null,
    /// Whether the message currently being reassembled arrived compressed.
    ///
    /// Read from RSV1 on the first frame, because RFC 7692 §6.1 puts the bit
    /// only there — continuations inherit it.
    fragments_compressed: bool = false,

    pub const handler_name = "websocket-frame-codec";

    pub const Options = struct {
        /// Largest single frame payload accepted.
        max_frame_payload: usize = 1024 * 1024,
        /// Largest reassembled message accepted across fragments.
        max_message_length: usize = 4 * 1024 * 1024,
        /// Answer inbound pings automatically. Almost always what a server
        /// wants; disable it to implement custom keep-alive accounting.
        auto_pong: bool = true,
        /// Echo an inbound close frame back, completing the closing handshake.
        auto_close: bool = true,
        /// Code sent when this side initiates the close.
        close_code: CloseCode = .normal,
    };

    pub fn init(role: Role, options: Options) FrameCodec {
        return .{
            .decoder = .{
                .options = .{
                    // A whole frame, header included, must fit while it is being
                    // accumulated.
                    .max_cumulation = options.max_frame_payload + 14,
                },
            },
            .options = options,
            .role = role,
        };
    }

    /// Allocates a codec and installs it at the end of `pipeline`.
    pub fn addTo(
        pipeline: *Pipeline,
        role: Role,
        options: Options,
    ) !*FrameCodec {
        const codec = try pipeline.gpa.create(FrameCodec);
        codec.* = .init(role, options);
        errdefer pipeline.gpa.destroy(codec);
        _ = try pipeline.addLast(handler_name, .initOwned(codec));
        return codec;
    }

    /// Turns on `permessage-deflate`. Called by a handshaker once the extension
    /// has been negotiated, never by the application directly.
    pub fn enableDeflate(self: *FrameCodec, options: pmd.Deflate.Options) void {
        assert(self.deflate == null);
        self.deflate = .init(options);
    }

    pub fn deinit(self: *FrameCodec, gpa: Allocator) void {
        if (self.deflate) |*deflate| deflate.deinit(gpa);
        self.fragments.deinit(gpa);
        self.decoder.deinit(gpa);
    }

    pub fn onRead(self: *FrameCodec, ctx: *HandlerContext, msg: Message) CodecError!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onInactive(self: *FrameCodec, ctx: *HandlerContext) CodecError!void {
        const result = self.decoder.onInactive(self, ctx);
        if (self.fragment_opcode != null) {
            self.fragments.clearAndFree(ctx.gpa());
            self.fragment_opcode = null;
            return error.IncompleteMessage;
        }
        return result;
    }

    /// Called by the accumulating decoder; see the contract in `codec.zig`.
    pub fn decode(
        self: *FrameCodec,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        if (self.failed) {
            cumulation.clear();
            return null;
        }
        return self.decodeFrame(ctx, cumulation) catch |err| {
            self.failed = true;
            self.fragments.clearAndFree(ctx.gpa());
            self.fragment_opcode = null;
            cumulation.clear();
            return err;
        };
    }

    fn decodeFrame(
        self: *FrameCodec,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        const header = try self.parseHeader(cumulation) orelse return null;
        if (cumulation.readableLen() < header.header_len + header.payload_len) return null;

        try cumulation.skip(header.header_len);
        const payload = try cumulation.readBytes(@intCast(header.payload_len));

        // Unmasking happens on a private copy: the accumulation buffer may hold
        // the next frame too, and mutating it in place would be visible there.
        //
        // Ownership of `decoded` passes to the handler below, which is why there
        // is no `errdefer` here: a second release path would double free.
        const decoded = try ctx.gpa().dupe(u8, payload);
        if (header.masked) unmask(decoded, header.mask_key);

        if (header.opcode.isControl()) {
            return self.handleControl(ctx, header, decoded);
        }
        return self.handleData(ctx, header, decoded);
    }

    /// Reads a frame header, or returns null when it is not all here yet.
    fn parseHeader(self: *FrameCodec, cumulation: *Buffer) CodecError!?FrameHeader {
        if (self.closed) return error.WebSocketClosed;

        const readable = cumulation.readableSlice();
        if (readable.len < 2) return null;

        const first = readable[0];
        const second = readable[1];

        // RSV2 and RSV3 are never defined by anything Zinet speaks. RSV1 is the
        // "Per-Message Compressed" bit, so it is only legal once
        // `permessage-deflate` has been negotiated.
        if (first & 0x30 != 0) return error.ReservedBitsSet;
        const compressed = first & 0x40 != 0;
        if (compressed and self.deflate == null) return error.ReservedBitsSet;

        const fin = first & 0x80 != 0;
        const opcode: Opcode = @fromBackingInt(@intCast(@as(u4, @truncate(first & 0x0F))));
        if (!opcode.isKnown()) return error.UnknownOpcode;

        // RFC 7692 §6.1: never on a control frame, and never on a continuation.
        // Allowing it there would leave the message's compression state
        // ambiguous, which is a decoding fork rather than a cosmetic issue.
        if (compressed and (opcode.isControl() or opcode == .continuation)) {
            return error.ReservedBitsSet;
        }

        const masked = second & 0x80 != 0;
        if (masked != self.role.expectsMaskedInbound()) return error.MaskingViolation;

        const short_len: u7 = @truncate(second & 0x7F);
        var cursor: usize = 2;
        var payload_len: u64 = short_len;

        switch (short_len) {
            126 => {
                if (readable.len < cursor + 2) return null;
                payload_len = std.mem.readInt(u16, readable[cursor..][0..2], .big);
                cursor += 2;
                // A two-byte length must not encode what one byte could.
                if (payload_len < 126) return error.InvalidPayloadLength;
            },
            127 => {
                if (readable.len < cursor + 8) return null;
                payload_len = std.mem.readInt(u64, readable[cursor..][0..8], .big);
                cursor += 8;
                if (payload_len < 65536) return error.InvalidPayloadLength;
                // The high bit must be clear per RFC 6455.
                if (payload_len & (1 << 63) != 0) return error.InvalidPayloadLength;
            },
            else => {},
        }

        if (opcode.isControl()) {
            if (!fin) return error.FragmentedControlFrame;
            if (payload_len > 125) return error.ControlFrameTooLarge;
        }
        if (payload_len > self.options.max_frame_payload) return error.FrameTooLong;

        var mask_key: [4]u8 = @splat(0);
        if (masked) {
            if (readable.len < cursor + 4) return null;
            mask_key = readable[cursor..][0..4].*;
            cursor += 4;
        }

        return .{
            .fin = fin,
            .compressed = compressed,
            .opcode = opcode,
            .masked = masked,
            .payload_len = payload_len,
            .mask_key = mask_key,
            .header_len = cursor,
        };
    }

    /// Applies the WebSocket masking transform in place.
    fn unmask(payload: []u8, key: [4]u8) void {
        for (payload, 0..) |*byte, index| byte.* ^= key[index % 4];
    }

    /// Handles ping, pong and close. Takes ownership of `payload`.
    fn handleControl(
        self: *FrameCodec,
        ctx: *HandlerContext,
        header: FrameHeader,
        payload: []u8,
    ) CodecError!?Message {
        const gpa = ctx.gpa();
        switch (header.opcode) {
            .ping => {
                defer gpa.free(payload);
                if (self.options.auto_pong) {
                    try self.send(ctx, .{ .opcode = .pong, .payload = payload }, true);
                }
                return null;
            },
            .pong => {
                // Delivered so an application can measure round-trip time.
                errdefer gpa.free(payload);
                return try Message.initAny(gpa, Frame, .{
                    .opcode = .pong,
                    .payload = payload,
                });
            },
            .close => {
                errdefer gpa.free(payload);
                self.closed = true;
                const code: ?CloseCode = if (payload.len >= 2)
                    @fromBackingInt(@intCast(std.mem.readInt(u16, payload[0..2], .big)))
                else
                    null;
                const reason = if (payload.len > 2) payload[2..] else payload[0..0];

                if (self.options.auto_close) {
                    try self.send(ctx, .{
                        .opcode = .close,
                        .close_code = code orelse .normal,
                        .payload = reason,
                    }, true);
                }
                return try Message.initAny(gpa, Frame, .{
                    .opcode = .close,
                    .payload = payload,
                    .close_code = code,
                });
            },
            else => unreachable, // isControl covers only these three.
        }
    }

    /// Handles text, binary and continuation frames, reassembling fragments.
    /// Takes ownership of `payload`.
    fn handleData(
        self: *FrameCodec,
        ctx: *HandlerContext,
        header: FrameHeader,
        payload: []u8,
    ) CodecError!?Message {
        const gpa = ctx.gpa();

        if (header.opcode == .continuation) {
            const opcode = self.fragment_opcode orelse {
                gpa.free(payload);
                return error.UnexpectedContinuation;
            };
            defer gpa.free(payload);
            try self.appendFragment(gpa, payload);
            if (!header.fin) return null;

            const complete = try self.fragments.toOwnedSlice(gpa);
            self.fragment_opcode = null;
            // No `errdefer` here: `deliver` takes ownership on every path.
            return try self.deliver(ctx, opcode, complete, self.fragments_compressed);
        }

        // A new data frame while a fragmented message is open is a violation.
        if (self.fragment_opcode != null) {
            gpa.free(payload);
            return error.InterleavedDataFrame;
        }

        if (header.fin) {
            return try self.deliver(ctx, header.opcode, payload, header.compressed);
        }

        defer gpa.free(payload);
        self.fragment_opcode = header.opcode;
        self.fragments_compressed = header.compressed;
        try self.appendFragment(gpa, payload);
        return null;
    }

    /// Builds the message to hand downstream, decompressing it first when the
    /// sender marked it compressed.
    ///
    /// Takes ownership of `payload` on **every** path, failures included, so a
    /// caller must not arm its own `errdefer` for it. Getting that wrong is a
    /// double free, which is how the fuzzer found the first version of this.
    fn deliver(
        self: *FrameCodec,
        ctx: *HandlerContext,
        opcode: Opcode,
        payload: []u8,
        compressed: bool,
    ) CodecError!?Message {
        const gpa = ctx.gpa();
        if (!compressed) {
            errdefer gpa.free(payload);
            return try Message.initAny(gpa, Frame, .{ .opcode = opcode, .payload = payload });
        }

        // `parseHeader` refuses RSV1 unless the extension is on, so this cannot
        // be null here.
        const deflate = &self.deflate.?;
        defer gpa.free(payload);
        const plain = try deflate.decompress(gpa, payload);
        errdefer gpa.free(plain);
        return try Message.initAny(gpa, Frame, .{ .opcode = opcode, .payload = plain });
    }

    fn appendFragment(self: *FrameCodec, gpa: Allocator, payload: []const u8) CodecError!void {
        if (self.fragments.items.len + payload.len > self.options.max_message_length) {
            self.fragments.clearAndFree(gpa);
            self.fragment_opcode = null;
            return error.MessageTooLarge;
        }
        try self.fragments.appendSlice(gpa, payload);
    }

    // -- Encoding ---------------------------------------------------------

    /// Turns a plain close request into the closing handshake RFC 6455 §5.5.1
    /// requires.
    ///
    /// Dropping the TCP connection without a close frame leaves the peer unable
    /// to tell an orderly shutdown from a broken network, which is the whole
    /// reason the closing handshake exists — third-party servers report it as an
    /// error. Sending the frame here works because a close travels the same
    /// outbound queue as writes, so the frame is guaranteed to reach the socket
    /// before the shutdown does.
    ///
    /// Reaching this callback is the caller's job: `ctx.close()` and
    /// `Pipeline.close` arrive here, but `Channel.requestClose` deliberately goes
    /// under the pipeline and so skips the handshake. From another task, use
    /// `Channel.submitClose`, which travels to the reader task and closes through
    /// the pipeline.
    pub fn onClose(self: *FrameCodec, ctx: *HandlerContext) CodecError!void {
        if (!self.close_sent) {
            self.send(ctx, .{
                .opcode = .close,
                .close_code = self.options.close_code,
                .payload = "",
            }, true) catch {
                // The connection is going away regardless; failing to announce
                // it politely must not stop it.
            };
        }
        return ctx.close();
    }

    pub fn onWrite(self: *FrameCodec, ctx: *HandlerContext, msg: Message) CodecError!void {
        var owned = msg;
        if (owned.get(OutboundFrame)) |frame| {
            defer owned.deinit(ctx.gpa());
            return self.send(ctx, frame.*, false);
        }
        return ctx.write(owned.move());
    }

    /// Serializes one frame and writes it towards the socket.
    ///
    /// `flush` is true for frames this codec generates on its own — a pong, or
    /// the echo of a close — because nothing else will ask for a flush and the
    /// peer is waiting for them. Frames written by the application are left
    /// unflushed so the application keeps control of batching.
    fn send(
        self: *FrameCodec,
        ctx: *HandlerContext,
        frame: OutboundFrame,
        flush: bool,
    ) CodecError!void {
        const gpa = ctx.gpa();
        const mask = frame.mask or self.role.masksOutbound();
        if (frame.opcode == .close) self.close_sent = true;

        // RFC 7692 §6.1: only data messages are compressed, and a message may be
        // sent uncompressed at any time — which is what makes skipping short
        // payloads legal rather than a deviation.
        var body: []const u8 = frame.payload;
        var compressed: ?[]u8 = null;
        defer if (compressed) |owned| gpa.free(owned);
        if (self.deflate) |*deflate| {
            const compressible = !frame.opcode.isControl() and
                frame.close_code == null and
                deflate.shouldCompress(frame.payload);
            if (compressible) {
                const encoded = try deflate.compress(gpa, frame.payload);
                // Compression that made the message longer is worth discarding:
                // the extension permits either form, so send the shorter one.
                if (encoded.len < frame.payload.len) {
                    compressed = encoded;
                    body = encoded;
                } else {
                    gpa.free(encoded);
                }
            }
        }

        var payload_len = body.len;
        if (frame.close_code != null) payload_len += 2;
        if (frame.opcode.isControl() and payload_len > 125) return error.ControlFrameTooLarge;

        var out = try Buffer.init(gpa, .{ .capacity = payload_len + 14 });
        errdefer out.deinit(gpa);

        const rsv1: u8 = if (compressed != null) 0x40 else 0x00;
        try out.writeByte(gpa, 0x80 | rsv1 | @as(u8, @backingInt(frame.opcode)));
        try writeLength(&out, gpa, payload_len, mask);

        var key: [4]u8 = @splat(0);
        if (mask) {
            // RFC 6455 §5.3 requires the masking key to come from a strong
            // source of entropy, and requires that seeing one key must not make
            // the next one guessable. That is not decoration: masking exists so
            // that a client cannot choose the bytes that appear on the wire, and
            // an intermediary tricked into reading those bytes as a second
            // request is the cache-poisoning attack it prevents. A wall-clock
            // seed, or any non-cryptographic generator whose state can be
            // recovered from a few observed keys, fails that requirement — so
            // the key comes from the injected `Io`'s CSPRNG, per frame.
            ctx.io().random(&key);
            try out.writeBytes(gpa, &key);
        }

        const body_start = out.writer_index;
        if (frame.close_code) |code| {
            try out.writeInt(gpa, u16, code.value(), .big);
        }
        try out.writeBytes(gpa, body);
        if (mask) unmask(out.bytes[body_start..out.writer_index], key);

        if (flush) return ctx.writeAndFlush(.initBuffer(&out));
        return ctx.write(.initBuffer(&out));
    }

    fn writeLength(
        out: *Buffer,
        gpa: Allocator,
        payload_len: usize,
        mask: bool,
    ) CodecError!void {
        const mask_bit: u8 = if (mask) 0x80 else 0;
        if (payload_len < 126) {
            try out.writeByte(gpa, mask_bit | @as(u8, @intCast(payload_len)));
        } else if (payload_len <= std.math.maxInt(u16)) {
            try out.writeByte(gpa, mask_bit | 126);
            try out.writeInt(gpa, u16, @intCast(payload_len), .big);
        } else {
            try out.writeByte(gpa, mask_bit | 127);
            try out.writeInt(gpa, u64, payload_len, .big);
        }
    }
};

// -- Handshake -------------------------------------------------------------

const http = @import("http.zig");

/// GUID from RFC 6455 used to derive the `Sec-WebSocket-Accept` value.
const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Length of a base64-encoded SHA-1 digest.
const accept_len = 28;

/// Fired inbound once the upgrade has completed, so an application handler can
/// learn that the connection is now speaking WebSocket.
pub const HandshakeComplete = struct {
    /// Value of `Sec-WebSocket-Protocol` that was selected, if any.
    protocol: ?[]const u8 = null,
};

/// Computes `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
pub fn acceptKey(key: []const u8, out: *[accept_len]u8) void {
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    var hasher: std.crypto.hash.Sha1 = .init(.{});
    hasher.update(key);
    hasher.update(handshake_guid);
    hasher.final(&digest);
    _ = std.base64.standard.Encoder.encode(out, &digest);
}

/// Completes the server side of the WebSocket upgrade, then rewrites the
/// pipeline to speak WebSocket.
///
/// This is the handler that justifies a dynamic pipeline. On the read that
/// carries a valid upgrade request it:
///
/// 1. writes the `101 Switching Protocols` response,
/// 2. removes the HTTP request decoder and response encoder,
/// 3. installs `FrameCodec` in their place,
/// 4. replaces itself with nothing, and
/// 5. fires `HandshakeComplete` so the application handler can react.
///
/// All of that happens from inside its own callback, which the pipeline supports
/// by deferring the release of removed handlers until propagation unwinds.
pub const Handshaker = struct {
    options: Options,
    upgraded: bool = false,

    pub const handler_name = "websocket-handshaker";

    pub const Options = struct {
        /// Frame codec settings for the upgraded connection.
        codec: FrameCodec.Options = .{},
        /// Subprotocols this server accepts, in order of preference. Empty
        /// accepts the connection without selecting one.
        protocols: []const []const u8 = &.{},
        /// Only upgrade requests for this path are handled; others are passed
        /// downstream. Null accepts any path.
        path: ?[]const u8 = null,
        /// Names of the handlers to remove on upgrade. Defaults match
        /// `http.addServerCodec`.
        http_decoder_name: []const u8 = http.RequestDecoder.handler_name,
        http_encoder_name: []const u8 = http.ResponseEncoder.handler_name,
        /// Accept `permessage-deflate` when the client offers it.
        ///
        /// Off by default: it is worth real bandwidth on chatty text protocols
        /// and costs 128 KiB of window per connection that uses it, so it is the
        /// application's call rather than a default.
        permessage_deflate: ?pmd.Deflate.Options = null,
    };

    pub fn init(options: Options) Handshaker {
        return .{ .options = options };
    }

    /// Allocates a handshaker and installs it at the end of `pipeline`.
    pub fn addTo(pipeline: *Pipeline, options: Options) !*Handshaker {
        const handshaker = try pipeline.gpa.create(Handshaker);
        handshaker.* = .init(options);
        errdefer pipeline.gpa.destroy(handshaker);
        _ = try pipeline.addLast(handler_name, .initOwned(handshaker));
        return handshaker;
    }

    pub fn onRead(
        self: *Handshaker,
        ctx: *HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        var owned = msg;
        const request = owned.get(http.Request) orelse {
            // Already upgraded, or something else entirely: not ours.
            return ctx.fireRead(owned.move());
        };

        // A request that is not trying to become a WebSocket belongs to whatever
        // handler serves plain HTTP on this connection, so pass it on rather
        // than failing: one port can serve both.
        if (!self.isForUs(request)) return ctx.fireRead(owned.move());

        defer owned.deinit(ctx.gpa());
        if (self.upgraded) return error.UnexpectedHttpRequest;
        try self.performUpgrade(ctx, request);
    }

    /// Whether this request is an attempt to upgrade on a path we serve.
    ///
    /// A request that merely looks like an upgrade — it names the protocol or
    /// carries a key — counts, so that a malformed attempt is reported instead
    /// of silently falling through to the HTTP routes.
    fn isForUs(self: *const Handshaker, request: *const http.Request) bool {
        if (self.options.path) |wanted| {
            if (!std.mem.eql(u8, request.path(), wanted)) return false;
        }
        if (request.headers.has("sec-websocket-key")) return true;
        const upgrade = request.headers.get("upgrade") orelse return false;
        return std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "websocket");
    }

    fn performUpgrade(
        self: *Handshaker,
        ctx: *HandlerContext,
        request: *http.Request,
    ) pipeline_mod.Error!void {
        var validated = try validate(request, self.options.protocols);
        validated.deflate = selectDeflate(request, self.options.permessage_deflate != null);

        var accept: [accept_len]u8 = undefined;
        acceptKey(validated.key, &accept);

        try self.writeResponse(ctx, &accept, validated.protocol, validated.deflate);
        try self.rewritePipeline(ctx, validated.deflate);

        self.upgraded = true;
        var complete: HandshakeComplete = .{ .protocol = validated.protocol };
        ctx.fireEvent(.init(&complete));
    }

    const Validated = struct {
        key: []const u8,
        protocol: ?[]const u8,
        /// Whether `permessage-deflate` was offered and accepted.
        deflate: bool = false,
    };

    /// Checks every condition RFC 6455 puts on the opening handshake.
    fn validate(
        request: *const http.Request,
        protocols: []const []const u8,
    ) pipeline_mod.Error!Validated {
        if (request.method != .get) return error.UpgradeMethodNotAllowed;
        if (request.version != .http_1_1) return error.UpgradeVersionNotSupported;
        if (!request.isUpgrade("websocket")) return error.NotAnUpgradeRequest;

        const version = request.headers.get("sec-websocket-version") orelse
            return error.MissingWebSocketVersion;
        if (!std.mem.eql(u8, std.mem.trim(u8, version, " \t"), "13")) {
            return error.UnsupportedWebSocketVersion;
        }

        const key = request.headers.get("sec-websocket-key") orelse
            return error.MissingWebSocketKey;
        const trimmed_key = std.mem.trim(u8, key, " \t");
        // A key is 16 random bytes, base64-encoded.
        if (trimmed_key.len != 24) return error.MalformedWebSocketKey;

        return .{
            .key = trimmed_key,
            .protocol = selectProtocol(request, protocols),
        };
    }

    /// Whether to accept the client's `permessage-deflate` offer, if any.
    ///
    /// Declining is always safe — the extension is optional — so an offer that
    /// asks for something unsupported simply goes unanswered rather than failing
    /// the connection.
    fn selectDeflate(request: *const http.Request, enabled: bool) bool {
        if (!enabled) return false;
        const offered = request.headers.get("sec-websocket-extensions") orelse return false;
        return pmd.selectOffer(offered) != null;
    }

    /// Picks the first offered subprotocol the server also accepts.
    fn selectProtocol(
        request: *const http.Request,
        protocols: []const []const u8,
    ) ?[]const u8 {
        if (protocols.len == 0) return null;
        const offered = request.headers.get("sec-websocket-protocol") orelse return null;
        for (protocols) |wanted| {
            var candidates = std.mem.splitScalar(u8, offered, ',');
            while (candidates.next()) |raw| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " \t"), wanted)) {
                    return wanted;
                }
            }
        }
        return null;
    }

    /// Writes `101 Switching Protocols` as raw bytes.
    ///
    /// Raw rather than an `http.Response`, because the response encoder is about
    /// to be removed and because an upgrade response must not carry the framing
    /// headers the encoder would add.
    fn writeResponse(
        self: *Handshaker,
        ctx: *HandlerContext,
        accept: *const [accept_len]u8,
        protocol: ?[]const u8,
        deflate: bool,
    ) pipeline_mod.Error!void {
        _ = self;
        const gpa = ctx.gpa();
        var out = try Buffer.init(gpa, .{ .capacity = 256 });
        errdefer out.deinit(gpa);

        var scratch: [64]u8 = undefined;
        var adapter = out.writerAdapter(gpa, &scratch);
        const writer = &adapter.interface;

        try writer.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
        try writer.writeAll("Upgrade: websocket\r\n");
        try writer.writeAll("Connection: Upgrade\r\n");
        try writer.print("Sec-WebSocket-Accept: {s}\r\n", .{accept});
        if (protocol) |selected| {
            try writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{selected});
        }
        if (deflate) {
            // Both `no_context_takeover` parameters are stated even though the
            // client may not have asked: RFC 7692 §7.1.1 lets a server impose
            // them, and this implementation has to.
            try writer.print("Sec-WebSocket-Extensions: {s}\r\n", .{pmd.server_response});
        }
        try writer.writeAll("\r\n");
        try writer.flush();
        if (adapter.err) |err| return err;

        return ctx.writeAndFlush(.initBuffer(&out));
    }

    /// Swaps the HTTP codec for the WebSocket codec, then retires this handler.
    fn rewritePipeline(
        self: *Handshaker,
        ctx: *HandlerContext,
        deflate: bool,
    ) pipeline_mod.Error!void {
        const pipeline = ctx.pipeline;

        // Install the frame codec where this handler sits, so it sees inbound
        // bytes before the application handler that follows.
        const codec = try pipeline.gpa.create(FrameCodec);
        codec.* = .init(.server, self.options.codec);
        if (deflate) codec.enableDeflate(self.options.permessage_deflate.?);
        errdefer pipeline.gpa.destroy(codec);
        _ = try pipeline.addBefore(ctx, FrameCodec.handler_name, .initOwned(codec));

        // The HTTP codec has no further role; the connection is not HTTP now.
        _ = pipeline.removeNamed(self.options.http_decoder_name);
        _ = pipeline.removeNamed(self.options.http_encoder_name);

        // And neither does this handler.
        pipeline.remove(ctx);
    }
};

/// Installs the server-side upgrade path: HTTP codec plus handshaker.
///
/// After a successful handshake the pipeline holds `FrameCodec` in place of the
/// HTTP handlers, and whatever application handlers were added after this call.
pub fn addServerUpgrade(pipeline: *Pipeline, options: Handshaker.Options) !void {
    try http.addServerCodec(pipeline, .{}, .{});
    _ = try Handshaker.addTo(pipeline, options);
}

/// Length of a base64-encoded 16-byte nonce.
const key_len = 24;

/// Performs the client side of the WebSocket upgrade, then rewrites the pipeline
/// to speak WebSocket.
///
/// The mirror of `Handshaker`, and it inverts every part of it: this one *sends*
/// the upgrade request (from `onActive`, on the connection's own task) and
/// *validates* the response, where the server receives and answers.
///
/// The validation is the substance. RFC 6455 §4.1 makes the client responsible
/// for checking that the server really completed a WebSocket handshake and did
/// not just happen to return 101, because a client that skips those checks will
/// happily start framing whatever the peer sends next.
pub const ClientHandshaker = struct {
    options: Options,
    /// The nonce sent in `Sec-WebSocket-Key`, kept to verify the answer.
    key: [key_len]u8 = @splat(0),
    sent: bool = false,
    upgraded: bool = false,
    /// Set when the server accepted the compression offer.
    deflate_agreed: bool = false,

    pub const handler_name = "websocket-client-handshaker";

    pub const Options = struct {
        /// Frame codec settings for the upgraded connection.
        codec: FrameCodec.Options = .{},
        /// Request target, which is the resource being opened.
        target: []const u8 = "/",
        /// Value for the required `Host` header.
        host: []const u8 = "",
        /// Subprotocols to offer, in order of preference. Empty offers none, and
        /// then the server selecting one is a protocol error.
        protocols: []const []const u8 = &.{},
        /// Extra headers for the upgrade request, such as `Authorization`.
        headers: []const http.Header = &.{},
        /// Names of the handlers to remove on upgrade. Defaults match
        /// `http.addClientCodec`.
        http_decoder_name: []const u8 = http.ResponseDecoder.handler_name,
        http_encoder_name: []const u8 = http.RequestEncoder.handler_name,
        /// Offer `permessage-deflate`. The server may decline, in which case the
        /// connection proceeds uncompressed.
        permessage_deflate: ?pmd.Deflate.Options = null,
    };

    pub fn init(options: Options) ClientHandshaker {
        return .{ .options = options };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*ClientHandshaker {
        const handshaker = try pipeline.gpa.create(ClientHandshaker);
        handshaker.* = .init(options);
        errdefer pipeline.gpa.destroy(handshaker);
        _ = try pipeline.addLast(handler_name, .initOwned(handshaker));
        return handshaker;
    }

    /// Sends the upgrade request as soon as the connection is up.
    pub fn onActive(self: *ClientHandshaker, ctx: *HandlerContext) pipeline_mod.Error!void {
        try self.sendUpgrade(ctx);
        ctx.fireActive();
    }

    fn sendUpgrade(self: *ClientHandshaker, ctx: *HandlerContext) pipeline_mod.Error!void {
        assert(!self.sent);

        // RFC 6455 §4.1: 16 freshly random bytes, base64-encoded. Its job is to
        // prove the answer was computed for *this* handshake rather than
        // replayed or served from a cache, so it has to be unpredictable.
        var nonce: [16]u8 = @splat(0);
        ctx.io().random(&nonce);
        _ = std.base64.standard.Encoder.encode(&self.key, &nonce);

        const gpa = ctx.gpa();
        var out = try Buffer.init(gpa, .{ .capacity = 256 });
        errdefer out.deinit(gpa);

        var scratch: [64]u8 = undefined;
        var adapter = out.writerAdapter(gpa, &scratch);
        const writer = &adapter.interface;

        // Written as raw bytes rather than an `http.OutgoingRequest`, for the
        // same reason the server writes its 101 raw: the request encoder is
        // about to be removed, and an upgrade must not carry the framing headers
        // it would add.
        if (!http.isRequestTargetValid(self.options.target)) return error.InvalidTarget;
        try writer.print("GET {s} HTTP/1.1\r\n", .{self.options.target});

        if (self.options.host.len == 0) return error.MissingHost;
        if (!http.isFieldValueValid(self.options.host)) return error.InvalidHeader;
        try writer.print("Host: {s}\r\n", .{self.options.host});

        try writer.writeAll("Upgrade: websocket\r\n");
        try writer.writeAll("Connection: Upgrade\r\n");
        try writer.print("Sec-WebSocket-Key: {s}\r\n", .{&self.key});
        try writer.writeAll("Sec-WebSocket-Version: 13\r\n");
        if (self.options.permessage_deflate != null) {
            try writer.print("Sec-WebSocket-Extensions: {s}\r\n", .{pmd.client_offer});
        }

        if (self.options.protocols.len > 0) {
            try writer.writeAll("Sec-WebSocket-Protocol: ");
            for (self.options.protocols, 0..) |protocol, index| {
                if (!http.isFieldValueValid(protocol)) return error.InvalidHeader;
                if (index > 0) try writer.writeAll(", ");
                try writer.writeAll(protocol);
            }
            try writer.writeAll("\r\n");
        }
        for (self.options.headers) |header| {
            if (!http.isFieldNameValid(header.name)) return error.InvalidHeader;
            if (!http.isFieldValueValid(header.value)) return error.InvalidHeader;
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }
        try writer.writeAll("\r\n");
        try writer.flush();
        if (adapter.err) |err| return err;

        self.sent = true;
        return ctx.writeAndFlush(.initBuffer(&out));
    }

    pub fn onRead(
        self: *ClientHandshaker,
        ctx: *HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        var owned = msg;
        const response = owned.get(http.IncomingResponse) orelse {
            // Frames, once upgraded, or something else entirely.
            return ctx.fireRead(owned.move());
        };
        defer owned.deinit(ctx.gpa());

        if (self.upgraded) return error.UnexpectedHttpResponse;
        try self.completeUpgrade(ctx, response);
    }

    fn completeUpgrade(
        self: *ClientHandshaker,
        ctx: *HandlerContext,
        response: *const http.IncomingResponse,
    ) pipeline_mod.Error!void {
        const protocol = try self.validate(response);
        try self.rewritePipeline(ctx);

        self.upgraded = true;
        var complete: HandshakeComplete = .{ .protocol = protocol };
        ctx.fireEvent(.init(&complete));
    }

    /// Checks every condition RFC 6455 §4.1 puts on the server's answer.
    ///
    /// Returns the negotiated subprotocol, if any.
    fn validate(
        self: *ClientHandshaker,
        response: *const http.IncomingResponse,
    ) pipeline_mod.Error!?[]const u8 {
        if (response.status.code() != 101) return error.UpgradeRejected;

        const upgrade = response.headers.get("upgrade") orelse return error.MissingUpgradeHeader;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "websocket")) {
            return error.MissingUpgradeHeader;
        }
        if (!response.headers.hasToken("connection", "upgrade")) {
            return error.MissingConnectionUpgrade;
        }

        // The one check that actually ties the answer to this handshake. Without
        // it a cache or a confused server could satisfy the client with a reply
        // meant for someone else.
        const accept = response.headers.get("sec-websocket-accept") orelse
            return error.MissingAcceptHeader;
        var expected: [accept_len]u8 = undefined;
        acceptKey(&self.key, &expected);
        if (!std.mem.eql(u8, std.mem.trim(u8, accept, " \t"), &expected)) {
            return error.AcceptMismatch;
        }

        // A server may not invent an extension the client did not offer, and the
        // only one this client ever offers is `permessage-deflate`. Anything
        // accepted on terms we cannot honour has to fail the connection rather
        // than proceed and decode garbage, per RFC 7692 §7.
        const extensions = response.headers.get("sec-websocket-extensions");
        if (self.options.permessage_deflate == null) {
            if (extensions) |value| {
                if (std.mem.trim(u8, value, " \t").len > 0) return error.UnsupportedExtension;
            }
        } else {
            const trimmed_extensions = if (extensions) |value|
                std.mem.trim(u8, value, " \t")
            else
                null;
            self.deflate_agreed = pmd.acceptResponse(
                if (trimmed_extensions) |value| (if (value.len == 0) null else value) else null,
            ) catch |err| switch (err) {
                error.UnexpectedExtension => return error.UnsupportedExtension,
                error.MalformedExtensionParameters,
                error.UnsupportedExtensionParameters,
                => return error.UnsupportedExtensionParameters,
            };
        }

        const selected = response.headers.get("sec-websocket-protocol") orelse return null;
        const trimmed = std.mem.trim(u8, selected, " \t");
        // Selecting a subprotocol that was never offered is a protocol error,
        // including the case where none were offered at all.
        for (self.options.protocols) |offered| {
            if (std.ascii.eqlIgnoreCase(trimmed, offered)) return offered;
        }
        return error.UnsupportedProtocol;
    }

    /// Swaps the HTTP codec for the WebSocket codec, then retires this handler.
    fn rewritePipeline(self: *ClientHandshaker, ctx: *HandlerContext) pipeline_mod.Error!void {
        const pipeline = ctx.pipeline;

        const codec = try pipeline.gpa.create(FrameCodec);
        codec.* = .init(.client, self.options.codec);
        if (self.deflate_agreed) codec.enableDeflate(self.options.permessage_deflate.?);
        errdefer pipeline.gpa.destroy(codec);
        _ = try pipeline.addBefore(ctx, FrameCodec.handler_name, .initOwned(codec));

        // Removing the response decoder is what hands its accumulated bytes
        // downstream: a server may put its first frame in the same packet as the
        // 101, and those bytes are sitting in the decoder at this moment.
        _ = pipeline.removeNamed(self.options.http_decoder_name);
        _ = pipeline.removeNamed(self.options.http_encoder_name);

        pipeline.remove(ctx);
    }
};

/// Installs the client-side upgrade path: response decoder plus handshaker.
///
/// The request encoder is deliberately absent. The handshaker writes its own
/// upgrade request as raw bytes, and after the upgrade there is no HTTP left to
/// encode — so adding one would only mean removing it again.
pub fn addClientUpgrade(
    pipeline: *Pipeline,
    tracker: *http.MethodTracker,
    options: ClientHandshaker.Options,
) !void {
    const decoder = try http.ResponseDecoder.addTo(pipeline, .{});
    decoder.tracker = tracker;
    // The handshaker's request never goes through an encoder, so the tracker
    // would not otherwise learn that a GET is outstanding — and without that the
    // decoder cannot tell a bodyless 101 from a response with a body.
    try tracker.push(.get);
    _ = try ClientHandshaker.addTo(pipeline, options);
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;
const test_support = @import("test_support.zig");

/// Builds a client-to-server frame: masked, as the protocol requires.
fn clientFrame(
    out: *std.ArrayList(u8),
    gpa: Allocator,
    opcode: Opcode,
    fin: bool,
    payload: []const u8,
) !void {
    const key = [4]u8{ 0x1A, 0x2B, 0x3C, 0x4D };
    try out.append(gpa, (if (fin) @as(u8, 0x80) else 0) | @backingInt(opcode));
    if (payload.len < 126) {
        try out.append(gpa, 0x80 | @as(u8, @intCast(payload.len)));
    } else if (payload.len <= std.math.maxInt(u16)) {
        try out.append(gpa, 0x80 | 126);
        var length: [2]u8 = undefined;
        std.mem.writeInt(u16, &length, @intCast(payload.len), .big);
        try out.appendSlice(gpa, &length);
    } else {
        try out.append(gpa, 0x80 | 127);
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, payload.len, .big);
        try out.appendSlice(gpa, &length);
    }
    try out.appendSlice(gpa, &key);
    for (payload, 0..) |byte, index| {
        try out.append(gpa, byte ^ key[index % 4]);
    }
}

/// Collects decoded frames.
const FrameCollector = struct {
    gpa: Allocator,
    frames: std.ArrayList(Frame) = .empty,
    errors: std.ArrayList(anyerror) = .empty,

    pub fn onRead(
        self: *FrameCollector,
        ctx: *HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        var owned = msg;
        if (owned.get(Frame) == null) {
            owned.deinit(ctx.gpa());
            return;
        }
        try self.frames.append(self.gpa, owned.take(ctx.gpa(), Frame).?);
    }

    pub fn onError(self: *FrameCollector, _: *HandlerContext, err: anyerror) void {
        self.errors.append(self.gpa, err) catch {};
    }

    fn deinit(self: *FrameCollector) void {
        for (self.frames.items) |*frame| frame.deinit(self.gpa);
        self.frames.deinit(self.gpa);
        self.errors.deinit(self.gpa);
    }
};

const CodecHarness = struct {
    fixture: test_support.Fixture,
    collector: *FrameCollector,

    fn init(gpa: Allocator, role: Role, options: FrameCodec.Options) !CodecHarness {
        var fixture = try test_support.Fixture.init(gpa);
        errdefer fixture.deinit();

        _ = try FrameCodec.addTo(fixture.pipeline, role, options);

        const collector = try gpa.create(FrameCollector);
        collector.* = .{ .gpa = gpa };
        errdefer gpa.destroy(collector);
        _ = try fixture.pipeline.addLast("collector", .init(collector));

        return .{ .fixture = fixture, .collector = collector };
    }

    fn deinit(harness: *CodecHarness) void {
        const gpa = harness.fixture.gpa;
        harness.fixture.deinit();
        harness.collector.deinit();
        gpa.destroy(harness.collector);
    }

    fn feed(harness: *CodecHarness, bytes: []const u8) !void {
        harness.fixture.pipeline.fireRead(
            try Message.initBytes(harness.fixture.gpa, bytes),
        );
    }

    fn frames(harness: *const CodecHarness) []const Frame {
        return harness.collector.frames.items;
    }

    fn errors(harness: *const CodecHarness) []const anyerror {
        return harness.collector.errors.items;
    }
};

test "FrameCodec: decodes a masked text frame" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .text, true, "hello websocket");

    try harness.feed(wire.items);

    try testing.expectEqual(@as(usize, 1), harness.frames().len);
    try testing.expectEqual(Opcode.text, harness.frames()[0].opcode);
    try testing.expectEqualStrings("hello websocket", harness.frames()[0].payload);
}

test "FrameCodec: decodes every payload length encoding" {
    const gpa = testing.allocator;

    for ([_]usize{ 0, 1, 125, 126, 200, 65535, 65536, 70000 }) |length| {
        var harness = try CodecHarness.init(gpa, .server, .{
            .max_frame_payload = 128 * 1024,
        });
        defer harness.deinit();

        const payload = try gpa.alloc(u8, length);
        defer gpa.free(payload);
        for (payload, 0..) |*byte, index| byte.* = @truncate(index);

        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try clientFrame(&wire, gpa, .binary, true, payload);

        try harness.feed(wire.items);
        try testing.expectEqual(@as(usize, 1), harness.frames().len);
        try testing.expectEqualSlices(u8, payload, harness.frames()[0].payload);
    }
}

test "FrameCodec: reassembles a fragmented message" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .text, false, "frag");
    try clientFrame(&wire, gpa, .continuation, false, "ment");
    try clientFrame(&wire, gpa, .continuation, true, "ed!");

    try harness.feed(wire.items);

    try testing.expectEqual(@as(usize, 1), harness.frames().len);
    try testing.expectEqual(Opcode.text, harness.frames()[0].opcode);
    try testing.expectEqualStrings("fragmented!", harness.frames()[0].payload);
}

test "FrameCodec: a control frame may interleave with fragments" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .text, false, "part1");
    try clientFrame(&wire, gpa, .ping, true, "beat");
    try clientFrame(&wire, gpa, .continuation, true, "part2");

    try harness.feed(wire.items);

    try testing.expectEqual(@as(usize, 1), harness.frames().len);
    try testing.expectEqualStrings("part1part2", harness.frames()[0].payload);
    // The ping was answered automatically: an unmasked pong on the wire.
    const written = harness.fixture.written();
    try testing.expectEqual(@as(usize, 6), written.len);
    try testing.expectEqual(@as(u8, 0x8A), written[0]);
    try testing.expectEqualStrings("beat", written[2..]);
}

test "FrameCodec: a frame split across reads is decoded once complete" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .text, true, "byte at a time");

    for (wire.items, 0..) |byte, index| {
        try harness.feed(&.{byte});
        const expected: usize = if (index + 1 == wire.items.len) 1 else 0;
        try testing.expectEqual(expected, harness.frames().len);
    }
    try testing.expectEqualStrings("byte at a time", harness.frames()[0].payload);
}

test "FrameCodec: a close frame is delivered and echoed" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);
    var code: [2]u8 = undefined;
    std.mem.writeInt(u16, &code, @backingInt(CloseCode.going_away), .big);
    try payload.appendSlice(gpa, &code);
    try payload.appendSlice(gpa, "bye");

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .close, true, payload.items);

    try harness.feed(wire.items);

    try testing.expectEqual(@as(usize, 1), harness.frames().len);
    try testing.expectEqual(Opcode.close, harness.frames()[0].opcode);
    try testing.expectEqual(CloseCode.going_away, harness.frames()[0].close_code.?);

    const written = harness.fixture.written();
    try testing.expectEqual(@as(u8, 0x88), written[0]);
    try testing.expectEqual(@as(u8, 5), written[1]);
    try testing.expectEqualStrings("bye", written[4..]);
}

test "FrameCodec: protocol violations are reported" {
    const gpa = testing.allocator;

    const Vector = struct { wire: []const u8, want: anyerror };
    const vectors = [_]Vector{
        // Unmasked client frame.
        .{ .wire = &.{ 0x81, 0x01, 'x' }, .want = error.MaskingViolation },
        // Reserved bits set.
        .{ .wire = &.{ 0xC1, 0x81, 0, 0, 0, 0, 'x' }, .want = error.ReservedBitsSet },
        // Unknown opcode.
        .{ .wire = &.{ 0x83, 0x80, 0, 0, 0, 0 }, .want = error.UnknownOpcode },
        // Fragmented control frame.
        .{ .wire = &.{ 0x09, 0x80, 0, 0, 0, 0 }, .want = error.FragmentedControlFrame },
        // Control frame with an oversized payload.
        .{ .wire = &.{ 0x89, 0xFE, 0, 200 }, .want = error.ControlFrameTooLarge },
        // A continuation with nothing to continue.
        .{ .wire = &.{ 0x80, 0x80, 0, 0, 0, 0 }, .want = error.UnexpectedContinuation },
        // A two-byte length that should have been one byte.
        .{ .wire = &.{ 0x82, 0xFE, 0, 5 }, .want = error.InvalidPayloadLength },
    };

    for (vectors) |vector| {
        var harness = try CodecHarness.init(gpa, .server, .{});
        defer harness.deinit();
        try harness.feed(vector.wire);
        try testing.expectEqual(@as(usize, 1), harness.errors().len);
        try testing.expectEqual(vector.want, harness.errors()[0]);
    }
}

test "FrameCodec: a data frame during reassembly is rejected" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .text, false, "open");
    try clientFrame(&wire, gpa, .text, true, "interrupting");

    try harness.feed(wire.items);
    try testing.expectEqual(@as(anyerror, error.InterleavedDataFrame), harness.errors()[0]);
}

test "FrameCodec: an oversized frame and message are refused" {
    const gpa = testing.allocator;

    {
        var harness = try CodecHarness.init(gpa, .server, .{ .max_frame_payload = 8 });
        defer harness.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try clientFrame(&wire, gpa, .binary, true, "0123456789");
        try harness.feed(wire.items);
        try testing.expectEqual(@as(anyerror, error.FrameTooLong), harness.errors()[0]);
    }
    {
        var harness = try CodecHarness.init(gpa, .server, .{ .max_message_length = 8 });
        defer harness.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        try clientFrame(&wire, gpa, .text, false, "12345");
        try clientFrame(&wire, gpa, .continuation, false, "67890");
        try harness.feed(wire.items);
        try testing.expectEqual(@as(anyerror, error.MessageTooLarge), harness.errors()[0]);
    }
}

test "FrameCodec: a server encodes unmasked frames" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    try harness.fixture.pipeline.write(
        try Message.initAny(gpa, OutboundFrame, .textFrame("pong back")),
    );

    const written = harness.fixture.written();
    try testing.expectEqual(@as(u8, 0x81), written[0]); // FIN + text
    try testing.expectEqual(@as(u8, 9), written[1]); // No mask bit.
    try testing.expectEqualStrings("pong back", written[2..]);
}

test "FrameCodec: a client encodes masked frames that a server can decode" {
    const gpa = testing.allocator;

    var client = try CodecHarness.init(gpa, .client, .{});
    defer client.deinit();
    try client.fixture.pipeline.write(
        try Message.initAny(gpa, OutboundFrame, .textFrame("through the mask")),
    );

    const on_wire = client.fixture.written();
    try testing.expectEqual(@as(u8, 0x81), on_wire[0]);
    try testing.expect(on_wire[1] & 0x80 != 0); // Mask bit set.

    var server = try CodecHarness.init(gpa, .server, .{});
    defer server.deinit();
    try server.feed(on_wire);

    try testing.expectEqual(@as(usize, 1), server.frames().len);
    try testing.expectEqualStrings("through the mask", server.frames()[0].payload);
}

test "FrameCodec: close frames round trip through the encoder" {
    const gpa = testing.allocator;
    var encoder = try CodecHarness.init(gpa, .server, .{});
    defer encoder.deinit();

    try encoder.fixture.pipeline.write(try Message.initAny(
        gpa,
        OutboundFrame,
        .closeFrame(.policy_violation, "no"),
    ));

    const written = encoder.fixture.written();
    try testing.expectEqual(@as(u8, 0x88), written[0]);
    try testing.expectEqual(@as(u8, 4), written[1]);
    try testing.expectEqual(
        @as(u16, 1008),
        std.mem.readInt(u16, written[2..4], .big),
    );
    try testing.expectEqualStrings("no", written[4..]);
}

test "FrameCodec: randomly split frame streams decode identically" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x9F5);
    const random = prng.random();

    for (0..32) |_| {
        var harness = try CodecHarness.init(gpa, .server, .{});
        defer harness.deinit();

        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(gpa);
        var expected: usize = 0;

        for (0..random.intRangeAtMost(usize, 1, 6)) |_| {
            const length = random.intRangeAtMost(usize, 0, 300);
            const payload = try gpa.alloc(u8, length);
            defer gpa.free(payload);
            random.bytes(payload);
            try clientFrame(&wire, gpa, .binary, true, payload);
            expected += 1;
        }

        var offset: usize = 0;
        while (offset < wire.items.len) {
            const chunk = random.intRangeAtMost(usize, 1, wire.items.len - offset);
            try harness.feed(wire.items[offset..][0..chunk]);
            offset += chunk;
        }

        try testing.expectEqual(@as(usize, 0), harness.errors().len);
        try testing.expectEqual(expected, harness.frames().len);
    }
}

// -- Handshake tests -------------------------------------------------------

// The example key and expected accept value come from RFC 6455 section 1.3.
test "acceptKey: matches the RFC 6455 example" {
    var accept: [accept_len]u8 = undefined;
    acceptKey("dGhlIHNhbXBsZSBub25jZQ==", &accept);
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &accept);
}

/// Records frames and handshake events after an upgrade.
const AppHandler = struct {
    gpa: Allocator,
    frames: std.ArrayList(Frame) = .empty,
    handshakes: usize = 0,
    protocol: ?[]const u8 = null,
    errors: std.ArrayList(anyerror) = .empty,

    pub fn onRead(
        self: *AppHandler,
        ctx: *HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        var owned = msg;
        if (owned.get(Frame) == null) {
            owned.deinit(ctx.gpa());
            return;
        }
        try self.frames.append(self.gpa, owned.take(ctx.gpa(), Frame).?);
    }

    pub fn onEvent(
        self: *AppHandler,
        ctx: *HandlerContext,
        event: pipeline_mod.Event,
    ) pipeline_mod.Error!void {
        if (event.get(HandshakeComplete)) |complete| {
            self.handshakes += 1;
            self.protocol = complete.protocol;
        }
        ctx.fireEvent(event);
    }

    pub fn onError(self: *AppHandler, _: *HandlerContext, err: anyerror) void {
        self.errors.append(self.gpa, err) catch {};
    }

    fn deinit(self: *AppHandler) void {
        for (self.frames.items) |*frame| frame.deinit(self.gpa);
        self.frames.deinit(self.gpa);
        self.errors.deinit(self.gpa);
    }
};

/// HTTP codec + handshaker + application handler, as a real server would be.
const UpgradeHarness = struct {
    fixture: test_support.Fixture,
    app: *AppHandler,

    fn init(gpa: Allocator, options: Handshaker.Options) !UpgradeHarness {
        var fixture = try test_support.Fixture.init(gpa);
        errdefer fixture.deinit();

        try addServerUpgrade(fixture.pipeline, options);

        const app = try gpa.create(AppHandler);
        app.* = .{ .gpa = gpa };
        errdefer gpa.destroy(app);
        _ = try fixture.pipeline.addLast("app", .init(app));

        return .{ .fixture = fixture, .app = app };
    }

    fn deinit(harness: *UpgradeHarness) void {
        const gpa = harness.fixture.gpa;
        harness.fixture.deinit();
        harness.app.deinit();
        gpa.destroy(harness.app);
    }

    fn feed(harness: *UpgradeHarness, bytes: []const u8) !void {
        harness.fixture.pipeline.fireRead(
            try Message.initBytes(harness.fixture.gpa, bytes),
        );
    }
};

const valid_upgrade_request =
    "GET /chat HTTP/1.1\r\n" ++
    "Host: example.com\r\n" ++
    "Upgrade: websocket\r\n" ++
    "Connection: Upgrade\r\n" ++
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
    "Sec-WebSocket-Version: 13\r\n" ++
    "\r\n";

test "Handshaker: a valid upgrade is accepted and the pipeline is rewritten" {
    const gpa = testing.allocator;
    var harness = try UpgradeHarness.init(gpa, .{});
    defer harness.deinit();

    var names: [8][]const u8 = undefined;
    try testing.expectEqual(@as(usize, 4), harness.fixture.pipeline.names(&names).len);

    try harness.feed(valid_upgrade_request);

    // The 101 response went out verbatim.
    const written = harness.fixture.written();
    try testing.expect(std.mem.startsWith(u8, written, "HTTP/1.1 101 Switching Protocols\r\n"));
    try testing.expect(std.mem.indexOf(
        u8,
        written,
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
    ) != null);
    try testing.expect(std.mem.endsWith(u8, written, "\r\n\r\n"));

    // The HTTP handlers and the handshaker are gone; the frame codec replaced
    // them, ahead of the application handler.
    const listed = harness.fixture.pipeline.names(&names);
    try testing.expectEqual(@as(usize, 2), listed.len);
    try testing.expectEqualStrings(FrameCodec.handler_name, listed[0]);
    try testing.expectEqualStrings("app", listed[1]);
    try testing.expectEqual(@as(usize, 1), harness.app.handshakes);
}

test "Handshaker: frames flow through immediately after the upgrade" {
    const gpa = testing.allocator;
    var harness = try UpgradeHarness.init(gpa, .{});
    defer harness.deinit();

    // The upgrade request and the first frame arrive in the same read, which is
    // what a client that does not wait for the response will do.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try wire.appendSlice(gpa, valid_upgrade_request);
    try clientFrame(&wire, gpa, .text, true, "first message");

    try harness.feed(wire.items);

    try testing.expectEqual(@as(usize, 1), harness.app.frames.items.len);
    try testing.expectEqualStrings("first message", harness.app.frames.items[0].payload);
    try testing.expectEqual(@as(usize, 0), harness.app.errors.items.len);
}

test "Handshaker: a subprotocol is negotiated when both sides offer one" {
    const gpa = testing.allocator;
    var harness = try UpgradeHarness.init(gpa, .{
        .protocols = &.{ "chat.v2", "chat.v1" },
    });
    defer harness.deinit();

    try harness.feed(
        "GET /chat HTTP/1.1\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Sec-WebSocket-Protocol: chat.v1, chat.v3\r\n" ++
            "\r\n",
    );

    try testing.expect(std.mem.indexOf(
        u8,
        harness.fixture.written(),
        "Sec-WebSocket-Protocol: chat.v1\r\n",
    ) != null);
    try testing.expectEqualStrings("chat.v1", harness.app.protocol.?);
}

test "Handshaker: invalid handshakes are rejected" {
    const gpa = testing.allocator;

    const Vector = struct { wire: []const u8, want: anyerror };
    const vectors = [_]Vector{
        .{
            .wire = "POST /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            .want = error.UpgradeMethodNotAllowed,
        },
        .{
            .wire = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n" ++
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            .want = error.NotAnUpgradeRequest,
        },
        .{
            .wire = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            .want = error.MissingWebSocketVersion,
        },
        .{
            .wire = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
            .want = error.UnsupportedWebSocketVersion,
        },
        .{
            .wire = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Version: 13\r\n\r\n",
            .want = error.MissingWebSocketKey,
        },
        .{
            .wire = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: short\r\nSec-WebSocket-Version: 13\r\n\r\n",
            .want = error.MalformedWebSocketKey,
        },
    };

    for (vectors) |vector| {
        var harness = try UpgradeHarness.init(gpa, .{});
        defer harness.deinit();

        try harness.feed(vector.wire);
        try testing.expectEqual(@as(usize, 1), harness.app.errors.items.len);
        try testing.expectEqual(vector.want, harness.app.errors.items[0]);
        // A failed handshake leaves the pipeline as it was.
        var names: [8][]const u8 = undefined;
        try testing.expectEqual(@as(usize, 4), harness.fixture.pipeline.names(&names).len);
        try testing.expectEqualStrings("", harness.fixture.written());
    }
}

test "Handshaker: a plain HTTP request is passed to the application" {
    const gpa = testing.allocator;

    // A handler that answers plain HTTP, standing in for an application's
    // routes on the same port as the WebSocket endpoint.
    const HttpRoutes = struct {
        served: usize = 0,

        pub fn onRead(
            self: *@This(),
            ctx: *HandlerContext,
            msg: Message,
        ) pipeline_mod.Error!void {
            var owned = msg;
            defer owned.deinit(ctx.gpa());
            const request = owned.get(http.Request) orelse return;
            self.served += 1;
            const response: http.Response = .{
                .status = .ok,
                .body = "plain http\n",
                .keep_alive = request.keep_alive,
            };
            try ctx.writeAndFlush(try Message.initAny(ctx.gpa(), http.Response, response));
        }
    };

    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    try addServerUpgrade(fixture.pipeline, .{ .path = "/chat" });

    var routes: HttpRoutes = .{};
    _ = try fixture.pipeline.addLast("routes", .init(&routes));

    // Not an upgrade at all.
    fixture.pipeline.fireRead(try Message.initBytes(gpa, "GET /health HTTP/1.1\r\nHost: a\r\n\r\n"));
    try testing.expectEqual(@as(usize, 1), routes.served);
    try testing.expect(std.mem.startsWith(u8, fixture.written(), "HTTP/1.1 200 OK\r\n"));

    // An upgrade for a path this handshaker does not serve.
    fixture.clearWritten();
    fixture.pipeline.fireRead(try Message.initBytes(
        gpa,
        "GET /other HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    ));
    try testing.expectEqual(@as(usize, 2), routes.served);
    try testing.expect(std.mem.startsWith(u8, fixture.written(), "HTTP/1.1 200 OK\r\n"));

    // And the path it does serve still upgrades.
    fixture.clearWritten();
    fixture.pipeline.fireRead(try Message.initBytes(gpa, valid_upgrade_request));
    try testing.expect(std.mem.startsWith(u8, fixture.written(), "HTTP/1.1 101"));
}

test "Handshaker: a server response is echoed back to a client codec" {
    const gpa = testing.allocator;
    var harness = try UpgradeHarness.init(gpa, .{});
    defer harness.deinit();

    try harness.feed(valid_upgrade_request);
    harness.fixture.clearWritten();

    // Send a message from the server side and confirm a client-role codec
    // decodes it, which exercises both halves of the frame codec together.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .text, true, "ping from client");
    try harness.feed(wire.items);
    try testing.expectEqualStrings("ping from client", harness.app.frames.items[0].payload);

    try harness.fixture.pipeline.write(
        try Message.initAny(gpa, OutboundFrame, .textFrame("reply from server")),
    );

    var client = try CodecHarness.init(gpa, .client, .{});
    defer client.deinit();
    try client.feed(harness.fixture.written());
    try testing.expectEqual(@as(usize, 1), client.frames().len);
    try testing.expectEqualStrings("reply from server", client.frames()[0].payload);
}

test "FrameCodec: a protocol violation is reported once, not once per read" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    // An unmasked client frame is a protocol error a server must fail on
    // (RFC 6455 §5.1). Once failed, further bytes are discarded rather than
    // re-examined, so a peer cannot amplify one bad frame into an error per
    // read by dribbling.
    try harness.feed("\x81\x02hi");
    try testing.expectEqual(@as(usize, 1), harness.errors().len);
    try testing.expectEqual(@as(anyerror, error.MaskingViolation), harness.errors()[0]);

    for (0..32) |_| try harness.feed("\x00");
    try testing.expectEqual(@as(usize, 1), harness.errors().len);

    // Even a well-formed frame after the failure is not decoded: the frame
    // boundaries are no longer trustworthy.
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try clientFrame(&wire, gpa, .text, true, "later");
    try harness.feed(wire.items);

    try testing.expectEqual(@as(usize, 0), harness.frames().len);
    try testing.expectEqual(@as(usize, 1), harness.errors().len);
}

// -- ClientHandshaker ------------------------------------------------------

/// A pipeline with the client upgrade path and a frame collector at the tail.
const ClientUpgradeHarness = struct {
    fixture: test_support.Fixture,
    tracker: *http.MethodTracker,
    frames_seen: *UpgradeCollector,

    const UpgradeCollector = struct {
        gpa: Allocator,
        items: std.ArrayList(Frame) = .empty,
        errors: std.ArrayList(anyerror) = .empty,
        upgrades: usize = 0,
        protocol: ?[]const u8 = null,

        pub const handler_name = "frame-collector";

        pub fn onRead(self: *UpgradeCollector, ctx: *HandlerContext, msg: Message) CodecError!void {
            var owned = msg;
            if (owned.take(ctx.gpa(), Frame)) |frame| {
                try self.items.append(self.gpa, frame);
                return;
            }
            owned.deinit(ctx.gpa());
        }

        pub fn onEvent(
            self: *UpgradeCollector,
            ctx: *HandlerContext,
            event: pipeline_mod.Event,
        ) CodecError!void {
            if (event.get(HandshakeComplete)) |complete| {
                self.upgrades += 1;
                self.protocol = complete.protocol;
            }
            ctx.fireEvent(event);
        }

        pub fn onError(self: *UpgradeCollector, _: *HandlerContext, err: anyerror) void {
            self.errors.append(self.gpa, err) catch {};
        }

        pub fn deinit(self: *UpgradeCollector, gpa: Allocator) void {
            for (self.items.items) |*frame| frame.deinit(gpa);
            self.items.deinit(gpa);
            self.errors.deinit(gpa);
        }
    };

    fn init(gpa: Allocator, options: ClientHandshaker.Options) !ClientUpgradeHarness {
        var fixture = try test_support.Fixture.init(gpa);
        errdefer fixture.deinit();

        const tracker = try gpa.create(http.MethodTracker);
        tracker.* = .{};
        errdefer gpa.destroy(tracker);

        try addClientUpgrade(fixture.pipeline, tracker, options);

        const collector = try gpa.create(UpgradeCollector);
        collector.* = .{ .gpa = gpa };
        errdefer gpa.destroy(collector);
        _ = try fixture.pipeline.addLast(UpgradeCollector.handler_name, .init(collector));

        return .{ .fixture = fixture, .tracker = tracker, .frames_seen = collector };
    }

    fn deinit(self: *ClientUpgradeHarness) void {
        const gpa = self.fixture.gpa;
        self.fixture.deinit();
        self.frames_seen.deinit(gpa);
        gpa.destroy(self.frames_seen);
        gpa.destroy(self.tracker);
    }

    fn feed(self: *ClientUpgradeHarness, bytes: []const u8) !void {
        self.fixture.pipeline.fireRead(try Message.initBytes(self.fixture.gpa, bytes));
    }

    /// The `Sec-WebSocket-Key` the handshaker actually sent, read back out of
    /// the request on the wire.
    fn sentKey(self: *const ClientUpgradeHarness) []const u8 {
        const written = self.fixture.written();
        const marker = "Sec-WebSocket-Key: ";
        const start = std.mem.indexOf(u8, written, marker).? + marker.len;
        const end = std.mem.indexOfPos(u8, written, start, "\r\n").?;
        return written[start..end];
    }

    /// Builds the `101` a conforming server would return for what was sent.
    fn serverAnswer(
        self: *const ClientUpgradeHarness,
        out: []u8,
        extra: []const u8,
    ) ![]const u8 {
        var accept: [accept_len]u8 = undefined;
        acceptKey(self.sentKey(), &accept);
        return std.fmt.bufPrint(
            out,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" ++
                "Connection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n{s}\r\n",
            .{ &accept, extra },
        );
    }
};

test "ClientHandshaker: sends a conforming upgrade request" {
    var harness = try ClientUpgradeHarness.init(testing.allocator, .{
        .host = "example.com",
        .target = "/chat",
    });
    defer harness.deinit();

    harness.fixture.pipeline.fireActive();
    const written = harness.fixture.written();

    try testing.expect(std.mem.startsWith(u8, written, "GET /chat HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, written, "Host: example.com\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, written, "Upgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, written, "Connection: Upgrade\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, written, "Sec-WebSocket-Version: 13\r\n") != null);
    // A 16-byte nonce is 24 base64 characters.
    try testing.expectEqual(@as(usize, 24), harness.sentKey().len);
}

test "ClientHandshaker: two handshakes do not reuse a nonce" {
    // The key exists to tie the answer to this handshake, so a fixed one would
    // defeat the purpose.
    var first = try ClientUpgradeHarness.init(testing.allocator, .{ .host = "h" });
    defer first.deinit();
    first.fixture.pipeline.fireActive();

    var second = try ClientUpgradeHarness.init(testing.allocator, .{ .host = "h" });
    defer second.deinit();
    second.fixture.pipeline.fireActive();

    try testing.expect(!std.mem.eql(u8, first.sentKey(), second.sentKey()));
}

test "ClientHandshaker: a valid answer upgrades and frames arrive" {
    var harness = try ClientUpgradeHarness.init(testing.allocator, .{ .host = "h" });
    defer harness.deinit();

    harness.fixture.pipeline.fireActive();
    var buffer: [256]u8 = undefined;
    const answer = try harness.serverAnswer(&buffer, "");

    // The server's first frame shares the packet with its 101, which is the case
    // that only works because removing the response decoder hands its
    // accumulated bytes downstream. A server does not mask.
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(testing.allocator);
    try stream.appendSlice(testing.allocator, answer);
    try stream.appendSlice(testing.allocator, "\x81\x05hello");

    try harness.feed(stream.items);

    try testing.expectEqual(@as(usize, 0), harness.frames_seen.errors.items.len);
    try testing.expectEqual(@as(usize, 1), harness.frames_seen.upgrades);
    try testing.expectEqual(@as(usize, 1), harness.frames_seen.items.items.len);
    try testing.expectEqualStrings("hello", harness.frames_seen.items.items[0].payload);

    // The HTTP handlers are gone and the frame codec has taken their place.
    try testing.expect(harness.fixture.pipeline.find(http.ResponseDecoder.handler_name) == null);
    try testing.expect(harness.fixture.pipeline.find(ClientHandshaker.handler_name) == null);
    try testing.expect(harness.fixture.pipeline.find(FrameCodec.handler_name) != null);
}

test "ClientHandshaker: an outbound frame after upgrade is masked" {
    var harness = try ClientUpgradeHarness.init(testing.allocator, .{ .host = "h" });
    defer harness.deinit();

    harness.fixture.pipeline.fireActive();
    var buffer: [256]u8 = undefined;
    try harness.feed(try harness.serverAnswer(&buffer, ""));
    harness.fixture.clearWritten();

    try harness.fixture.pipeline.write(
        try Message.initAny(testing.allocator, OutboundFrame, .textFrame("hi")),
    );

    const on_wire = harness.fixture.written();
    try testing.expectEqual(@as(u8, 0x81), on_wire[0]);
    // RFC 6455 §5.1: every client-to-server frame must be masked.
    try testing.expect(on_wire[1] & 0x80 != 0);
    try testing.expectEqual(@as(u8, 2), on_wire[1] & 0x7F);
}

test "ClientHandshaker: rejects every non-conforming answer" {
    const Case = struct {
        extra: []const u8,
        /// Replaces the whole answer when set, for cases the helper cannot build.
        raw: ?[]const u8 = null,
        expected: anyerror,
    };
    const cases = [_]Case{
        .{
            .raw = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            .extra = "",
            .expected = error.UpgradeRejected,
        },
        .{
            .raw = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: x\r\n\r\n",
            .extra = "",
            .expected = error.MissingUpgradeHeader,
        },
        .{
            .raw = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n" ++
                "Connection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n",
            .extra = "",
            .expected = error.MissingUpgradeHeader,
        },
        .{
            .raw = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" ++
                "Sec-WebSocket-Accept: x\r\n\r\n",
            .extra = "",
            .expected = error.MissingConnectionUpgrade,
        },
        .{
            .raw = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n\r\n",
            .extra = "",
            .expected = error.MissingAcceptHeader,
        },
        // A well-formed 101 whose accept value was computed for another key.
        .{
            .raw = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            .extra = "",
            .expected = error.AcceptMismatch,
        },
        // Extensions and subprotocols the client never offered.
        .{ .extra = "Sec-WebSocket-Extensions: permessage-deflate\r\n", .expected = error.UnsupportedExtension },
        .{ .extra = "Sec-WebSocket-Protocol: chat\r\n", .expected = error.UnsupportedProtocol },
    };

    for (cases) |case| {
        var harness = try ClientUpgradeHarness.init(testing.allocator, .{ .host = "h" });
        defer harness.deinit();
        harness.fixture.pipeline.fireActive();

        var buffer: [512]u8 = undefined;
        const answer = case.raw orelse try harness.serverAnswer(&buffer, case.extra);
        try harness.feed(answer);

        try testing.expectEqual(@as(usize, 0), harness.frames_seen.upgrades);
        try testing.expectEqual(@as(usize, 1), harness.frames_seen.errors.items.len);
        try testing.expectEqual(case.expected, harness.frames_seen.errors.items[0]);
        // The pipeline was not rewritten, so nothing will try to frame what
        // follows as WebSocket.
        try testing.expect(harness.fixture.pipeline.find(FrameCodec.handler_name) == null);
    }
}

test "ClientHandshaker: a subprotocol it offered is accepted and reported" {
    var harness = try ClientUpgradeHarness.init(testing.allocator, .{
        .host = "h",
        .protocols = &.{ "chat", "superchat" },
    });
    defer harness.deinit();

    harness.fixture.pipeline.fireActive();
    try testing.expect(std.mem.indexOf(
        u8,
        harness.fixture.written(),
        "Sec-WebSocket-Protocol: chat, superchat\r\n",
    ) != null);

    var buffer: [512]u8 = undefined;
    try harness.feed(try harness.serverAnswer(
        &buffer,
        "Sec-WebSocket-Protocol: superchat\r\n",
    ));

    try testing.expectEqual(@as(usize, 1), harness.frames_seen.upgrades);
    try testing.expectEqualStrings("superchat", harness.frames_seen.protocol.?);
}

test "ClientHandshaker: an answer split across reads still upgrades" {
    var harness = try ClientUpgradeHarness.init(testing.allocator, .{ .host = "h" });
    defer harness.deinit();

    harness.fixture.pipeline.fireActive();
    var buffer: [256]u8 = undefined;
    const answer = try harness.serverAnswer(&buffer, "");

    for (answer) |byte| try harness.feed(&.{byte});

    try testing.expectEqual(@as(usize, 0), harness.frames_seen.errors.items.len);
    try testing.expectEqual(@as(usize, 1), harness.frames_seen.upgrades);
}

test "FrameCodec: closing sends a close frame before the connection goes" {
    // Dropping TCP without a close frame is what a third-party server reports as
    // "no close frame received or sent". The frame has to be on the wire before
    // the shutdown, which works because both travel the same outbound queue.
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    try harness.fixture.pipeline.close();

    const on_wire = harness.fixture.written();
    try testing.expectEqual(@as(usize, 4), on_wire.len);
    try testing.expectEqual(@as(u8, 0x88), on_wire[0]); // FIN + close.
    try testing.expectEqual(@as(u8, 2), on_wire[1]); // Two bytes of payload.
    try testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, on_wire[2..4], .big));
    try testing.expectEqual(@as(usize, 1), harness.fixture.sink_impl.closes);
}

test "FrameCodec: the close frame is announced exactly once" {
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    // An inbound close is echoed, which already completes this side's half.
    try harness.feed("\x88\x82\x00\x00\x00\x00\x03\xe8");
    const after_echo = harness.fixture.written().len;
    try testing.expect(after_echo > 0);

    // So the application closing afterwards must not send a second one.
    try harness.fixture.pipeline.close();
    try testing.expectEqual(after_echo, harness.fixture.written().len);
    try testing.expectEqual(@as(usize, 1), harness.fixture.sink_impl.closes);
}

// -- permessage-deflate ----------------------------------------------------

/// A codec harness with compression already negotiated.
fn deflateHarness(gpa: Allocator, role: Role) !CodecHarness {
    var harness = try CodecHarness.init(gpa, role, .{});
    errdefer harness.deinit();
    const ctx = harness.fixture.pipeline.find(FrameCodec.handler_name).?;
    const codec: *FrameCodec = @ptrCast(@alignCast(ctx.handler.context));
    codec.enableDeflate(.{ .min_compress_size = 1 });
    return harness;
}

test "FrameCodec: RSV1 is refused until permessage-deflate is negotiated" {
    // RFC 6455 §5.2: a reserved bit with no extension behind it must fail the
    // connection, because the receiver cannot know what the frame means.
    const gpa = testing.allocator;
    var harness = try CodecHarness.init(gpa, .server, .{});
    defer harness.deinit();

    // A masked, compressed-marked text frame.
    try harness.feed(&.{ 0xc1, 0x80, 0x00, 0x00, 0x00, 0x00 });
    try testing.expectEqual(@as(usize, 0), harness.frames().len);
    try testing.expectEqual(@as(usize, 1), harness.errors().len);
    try testing.expectEqual(@as(anyerror, error.ReservedBitsSet), harness.errors()[0]);
}

test "FrameCodec: RSV2 and RSV3 stay refused even with compression on" {
    const gpa = testing.allocator;
    var harness = try deflateHarness(gpa, .server);
    defer harness.deinit();

    // RSV2 set.
    try harness.feed(&.{ 0xa1, 0x80, 0x00, 0x00, 0x00, 0x00 });
    try testing.expectEqual(@as(usize, 1), harness.errors().len);
    try testing.expectEqual(@as(anyerror, error.ReservedBitsSet), harness.errors()[0]);
}

test "FrameCodec: RSV1 on a control frame is refused" {
    // RFC 7692 §6.1 forbids it, and honouring it would leave the message's
    // compression state ambiguous.
    const gpa = testing.allocator;
    var harness = try deflateHarness(gpa, .server);
    defer harness.deinit();

    // A compressed-marked ping.
    try harness.feed(&.{ 0xc9, 0x80, 0x00, 0x00, 0x00, 0x00 });
    try testing.expectEqual(@as(usize, 1), harness.errors().len);
    try testing.expectEqual(@as(anyerror, error.ReservedBitsSet), harness.errors()[0]);
}

test "FrameCodec: decodes the compressed \"Hello\" from RFC 7692 §7.2.3.1" {
    // The wire bytes come from the RFC, so this checks against the spec rather
    // than against Zinet's own encoder.
    const gpa = testing.allocator;
    var harness = try deflateHarness(gpa, .client);
    defer harness.deinit();

    // Unmasked because the harness is a client reading a server's frame.
    try harness.feed(&.{ 0xc1, 0x07, 0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00 });

    try testing.expectEqual(@as(usize, 0), harness.errors().len);
    try testing.expectEqual(@as(usize, 1), harness.frames().len);
    try testing.expectEqualStrings("Hello", harness.frames()[0].payload);
}

test "FrameCodec: decodes a compressed message split across fragments" {
    // The fragmentation example from §7.2.3.1: RSV1 on the first frame only, and
    // the compressed stream split at an arbitrary byte. Reassembly has to happen
    // before decompression, since neither half inflates alone.
    const gpa = testing.allocator;
    var harness = try deflateHarness(gpa, .client);
    defer harness.deinit();

    try harness.feed(&.{ 0x41, 0x03, 0xf2, 0x48, 0xcd });
    try testing.expectEqual(@as(usize, 0), harness.frames().len);
    try harness.feed(&.{ 0x80, 0x04, 0xc9, 0xc9, 0x07, 0x00 });

    try testing.expectEqual(@as(usize, 0), harness.errors().len);
    try testing.expectEqual(@as(usize, 1), harness.frames().len);
    try testing.expectEqualStrings("Hello", harness.frames()[0].payload);
}

test "FrameCodec: an uncompressed message still arrives when compression is on" {
    // RFC 7692 lets either side send a message uncompressed at any time, which
    // is what makes skipping small payloads legal.
    const gpa = testing.allocator;
    var harness = try deflateHarness(gpa, .client);
    defer harness.deinit();

    try harness.feed(&.{ 0x81, 0x02, 'h', 'i' });
    try testing.expectEqual(@as(usize, 1), harness.frames().len);
    try testing.expectEqualStrings("hi", harness.frames()[0].payload);
}

test "FrameCodec: a compressed frame round trips through the codec" {
    const gpa = testing.allocator;

    // The server compresses, the client decompresses.
    var server = try deflateHarness(gpa, .server);
    defer server.deinit();

    const payload = test_support.repeat("compress me, compress me, compress me", 4);
    try server.fixture.pipeline.write(try Message.initAny(
        gpa,
        OutboundFrame,
        .textFrame(payload),
    ));

    const wire = server.fixture.written();
    // RSV1 must be set, and the frame must be shorter than the payload.
    try testing.expectEqual(@as(u8, 0xc1), wire[0]);
    try testing.expect(wire.len < payload.len);

    var client = try deflateHarness(gpa, .client);
    defer client.deinit();
    try client.feed(wire);

    try testing.expectEqual(@as(usize, 0), client.errors().len);
    try testing.expectEqual(@as(usize, 1), client.frames().len);
    try testing.expectEqualStrings(payload, client.frames()[0].payload);
}

test "FrameCodec: an incompressible payload is sent uncompressed" {
    // Compression that makes a message longer is discarded, so RSV1 stays clear
    // and the peer sees a plain frame.
    const gpa = testing.allocator;
    var harness = try deflateHarness(gpa, .server);
    defer harness.deinit();

    // Random-looking bytes do not compress.
    var noise: [64]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    prng.random().bytes(&noise);

    try harness.fixture.pipeline.write(try Message.initAny(
        gpa,
        OutboundFrame,
        .binaryFrame(&noise),
    ));

    const wire = harness.fixture.written();
    // Opcode binary with FIN, and no RSV1.
    try testing.expectEqual(@as(u8, 0x82), wire[0]);
    try testing.expectEqualSlices(u8, &noise, wire[2..]);
}

test "FrameCodec: a control frame is never compressed" {
    const gpa = testing.allocator;
    var harness = try deflateHarness(gpa, .server);
    defer harness.deinit();

    try harness.fixture.pipeline.write(try Message.initAny(
        gpa,
        OutboundFrame,
        .{ .opcode = .ping, .payload = "ping payload that is long enough to tempt the encoder" },
    ));

    const wire = harness.fixture.written();
    try testing.expectEqual(@as(u8, 0x89), wire[0]); // FIN + ping, no RSV1.
}

test "Handshaker: accepts permessage-deflate only when asked to" {
    const gpa = testing.allocator;
    const request = "GET /chat HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n" ++
        "\r\n";

    {
        // Disabled by default, so the offer goes unanswered and the connection
        // proceeds uncompressed. Declining is always safe.
        var harness = try UpgradeHarness.init(gpa, .{});
        defer harness.deinit();
        try harness.feed(request);
        const response = harness.fixture.written();
        try testing.expect(std.mem.indexOf(u8, response, "101 Switching Protocols") != null);
        try testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Extensions") == null);
        try testing.expect(harness.fixture.pipeline.find(FrameCodec.handler_name) != null);
    }
    {
        var harness = try UpgradeHarness.init(gpa, .{ .permessage_deflate = .{} });
        defer harness.deinit();
        try harness.feed(request);
        const response = harness.fixture.written();
        // Both no_context_takeover parameters are stated, because this
        // implementation cannot carry a window across messages and the peer has
        // to know.
        try testing.expect(std.mem.indexOf(
            u8,
            response,
            "Sec-WebSocket-Extensions: permessage-deflate; " ++
                "client_no_context_takeover; server_no_context_takeover",
        ) != null);
        // The response must not echo client_max_window_bits, which would promise
        // a window this implementation does not use.
        try testing.expect(std.mem.indexOf(u8, response, "max_window_bits") == null);
    }
}

test "Handshaker: declines an offer that constrains the server's window" {
    // `server_max_window_bits` is a request, not a hint, so an offer carrying it
    // cannot be accepted and ignored.
    const gpa = testing.allocator;
    var harness = try UpgradeHarness.init(gpa, .{ .permessage_deflate = .{} });
    defer harness.deinit();

    try harness.feed("GET /chat HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_max_window_bits=10\r\n" ++
        "\r\n");

    const response = harness.fixture.written();
    // Upgraded, but without compression.
    try testing.expect(std.mem.indexOf(u8, response, "101 Switching Protocols") != null);
    try testing.expect(std.mem.indexOf(u8, response, "Sec-WebSocket-Extensions") == null);
}
