//! HTTP/1.1 message types.
//!
//! The parser and serializer live alongside these in this module; this section
//! is only about how a request and a response are represented.
//!
//! # Memory
//!
//! An HTTP message owns one arena. Header names, values, the target and the
//! body all point into it, so releasing a message is a single arena teardown
//! rather than a walk over every field. That matters because a request has an
//! unpredictable number of small, short-lived strings, which is exactly the
//! shape an arena is best at.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Buffer = @import("../buffer.zig").Buffer;

/// Request methods this codec recognizes. Anything else is `.other`, with the
/// spelling preserved, because a proxy must be able to forward what it does not
/// understand.
pub const Method = union(enum) {
    get,
    head,
    post,
    put,
    delete,
    connect,
    options,
    trace,
    patch,
    other: []const u8,

    pub fn parse(text: []const u8) Method {
        const table = .{
            .{ "GET", Method.get },
            .{ "HEAD", Method.head },
            .{ "POST", Method.post },
            .{ "PUT", Method.put },
            .{ "DELETE", Method.delete },
            .{ "CONNECT", Method.connect },
            .{ "OPTIONS", Method.options },
            .{ "TRACE", Method.trace },
            .{ "PATCH", Method.patch },
        };
        inline for (table) |entry| {
            if (std.mem.eql(u8, text, entry[0])) return entry[1];
        }
        return .{ .other = text };
    }

    pub fn name(method: Method) []const u8 {
        return switch (method) {
            .get => "GET",
            .head => "HEAD",
            .post => "POST",
            .put => "PUT",
            .delete => "DELETE",
            .connect => "CONNECT",
            .options => "OPTIONS",
            .trace => "TRACE",
            .patch => "PATCH",
            .other => |text| text,
        };
    }

    /// Whether a response to this method may carry a body.
    pub fn allowsResponseBody(method: Method) bool {
        return switch (method) {
            .head, .connect => false,
            else => true,
        };
    }
};

pub const Version = enum {
    http_1_0,
    http_1_1,

    pub fn parse(text: []const u8) ?Version {
        if (std.mem.eql(u8, text, "HTTP/1.1")) return .http_1_1;
        if (std.mem.eql(u8, text, "HTTP/1.0")) return .http_1_0;
        return null;
    }

    pub fn name(version: Version) []const u8 {
        return switch (version) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
        };
    }

    /// Connections persist by default in 1.1 and close by default in 1.0.
    pub fn keepAliveByDefault(version: Version) bool {
        return version == .http_1_1;
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// An ordered list of headers, preserving both order and duplicates because
/// both are observable in HTTP (`Set-Cookie`, for instance).
pub const Headers = struct {
    entries: std.ArrayList(Header) = .empty,

    pub fn deinit(headers: *Headers, gpa: Allocator) void {
        headers.entries.deinit(gpa);
    }

    /// Appends a header. Neither string is copied; both must outlive the list,
    /// which is what the owning message's arena guarantees.
    pub fn append(
        headers: *Headers,
        gpa: Allocator,
        name: []const u8,
        value: []const u8,
    ) Allocator.Error!void {
        try headers.entries.append(gpa, .{ .name = name, .value = value });
    }

    pub fn len(headers: *const Headers) usize {
        return headers.entries.items.len;
    }

    pub fn items(headers: *const Headers) []const Header {
        return headers.entries.items;
    }

    /// First value for `name`, compared case-insensitively as HTTP requires.
    pub fn get(headers: *const Headers, name: []const u8) ?[]const u8 {
        for (headers.entries.items) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.value;
        }
        return null;
    }

    pub fn has(headers: *const Headers, name: []const u8) bool {
        return headers.get(name) != null;
    }

    /// Whether any value of `name` contains `token`, case-insensitively.
    ///
    /// Header values such as `Connection: keep-alive, Upgrade` are
    /// comma-separated token lists, so a plain equality check is wrong.
    pub fn hasToken(headers: *const Headers, name: []const u8, token: []const u8) bool {
        for (headers.entries.items) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.name, name)) continue;
            var tokens = std.mem.splitScalar(u8, entry.value, ',');
            while (tokens.next()) |raw| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " \t"), token)) return true;
            }
        }
        return false;
    }
};

/// A decoded request. Owns the arena its strings live in.
pub const Request = struct {
    arena: std.heap.ArenaAllocator,
    method: Method,
    /// Request target exactly as it appeared on the wire.
    target: []const u8,
    version: Version,
    headers: Headers,
    /// Complete body. Empty when the request had none.
    body: []const u8,
    /// Whether the connection may be reused after this exchange.
    keep_alive: bool,

    /// Creates an empty request whose arena is a child of `gpa`.
    pub fn init(gpa: Allocator) Request {
        return .{
            .arena = .init(gpa),
            .method = .get,
            .target = "",
            .version = .http_1_1,
            .headers = .{},
            .body = "",
            .keep_alive = true,
        };
    }

    /// Releases the arena and everything in it.
    ///
    /// The signature takes an allocator it does not use so that `Message`'s
    /// type-erased destructor can call it uniformly.
    pub fn deinit(request: *Request, _: Allocator) void {
        request.arena.deinit();
    }

    /// Allocator for strings that must live as long as this request.
    pub fn allocator(request: *Request) Allocator {
        return request.arena.allocator();
    }

    /// Path portion of the target, without the query string.
    pub fn path(request: *const Request) []const u8 {
        const mark = std.mem.indexOfScalar(u8, request.target, '?') orelse
            return request.target;
        return request.target[0..mark];
    }

    /// Query string without the leading `?`, or null when there is none.
    pub fn query(request: *const Request) ?[]const u8 {
        const mark = std.mem.indexOfScalar(u8, request.target, '?') orelse return null;
        return request.target[mark + 1 ..];
    }

    /// Whether this request asks to switch protocols to `protocol`.
    pub fn isUpgrade(request: *const Request, protocol: []const u8) bool {
        if (!request.headers.hasToken("connection", "upgrade")) return false;
        const upgrade = request.headers.get("upgrade") orelse return false;
        return std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), protocol);
    }
};

/// A response to be encoded.
///
/// # Ownership
///
/// A response owns nothing: `headers` and `body` are borrowed. They only need to
/// stay alive for the duration of the write, because the encoder serializes the
/// whole response into a buffer before `write` returns. In practice that means a
/// stack array of headers is fine, and so is anything allocated in the arena of
/// the request being answered.
///
/// Deliberately borrowing rather than owning: a response is assembled from
/// strings that already exist somewhere else, and making it own copies would
/// mean an allocator field, a `deinit`, and a way for the caller's allocator and
/// the encoder's to disagree.
pub const Response = struct {
    status: Status = .ok,
    version: Version = .http_1_1,
    /// Headers to send, in order. Framing headers are ignored; see
    /// `ResponseEncoder`.
    headers: []const Header = &.{},
    body: []const u8 = "",
    /// Whether to keep the connection open. The encoder writes the matching
    /// `Connection` header.
    keep_alive: bool = true,
    /// Send the body using chunked transfer encoding instead of
    /// `Content-Length`. Useful when the length is not known up front; the
    /// streaming case is served by `Chunk` messages.
    chunked: bool = false,
};

/// Status codes, kept to the ones a server actually emits plus an escape hatch.
pub const Status = enum(u16) {
    continue_ = 100,
    switching_protocols = 101,
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    request_timeout = 408,
    length_required = 411,
    payload_too_large = 413,
    uri_too_long = 414,
    upgrade_required = 426,
    request_header_fields_too_large = 431,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    http_version_not_supported = 505,
    _,

    pub fn code(status: Status) u16 {
        return @intFromEnum(status);
    }

    pub fn phrase(status: Status) []const u8 {
        return switch (status) {
            .continue_ => "Continue",
            .switching_protocols => "Switching Protocols",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .no_content => "No Content",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .not_modified => "Not Modified",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .request_timeout => "Request Timeout",
            .length_required => "Length Required",
            .payload_too_large => "Payload Too Large",
            .uri_too_long => "URI Too Long",
            .upgrade_required => "Upgrade Required",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .http_version_not_supported => "HTTP Version Not Supported",
            _ => "Unknown",
        };
    }

    /// Responses with these statuses never carry a body.
    pub fn allowsBody(status: Status) bool {
        return switch (status.code()) {
            100...199, 204, 304 => false,
            else => true,
        };
    }
};

// -- Request decoding ------------------------------------------------------

const codec_mod = @import("codec.zig");
const pipeline_mod = @import("../pipeline.zig");

const ByteToMessageDecoder = codec_mod.ByteToMessageDecoder;
const CodecError = codec_mod.Error;
const HandlerContext = pipeline_mod.HandlerContext;
const Message = pipeline_mod.Message;
const Pipeline = pipeline_mod.Pipeline;

/// Parses HTTP/1.1 requests out of a byte stream.
///
/// The parser is an explicit state machine rather than recursive descent: HTTP
/// framing errors are the classic source of request smuggling, and a flat state
/// machine makes it possible to see, in one place, exactly which byte sequences
/// are accepted. It also means a request split across any number of reads costs
/// nothing extra to handle.
///
/// ```
/// request_line -> headers -> +-> fixed_body  -+-> (emit) -> request_line
///                            +-> chunk_size --+
///                            +-> (no body) ---+
/// ```
///
/// Rejected outright:
///
/// * both `Content-Length` and `Transfer-Encoding` present, or a repeated or
///   inconsistent `Content-Length` — the request smuggling vectors,
/// * a request line or header block over its configured limit,
/// * a body larger than `max_body_length`.
pub const RequestDecoder = struct {
    decoder: ByteToMessageDecoder(RequestDecoder),
    options: Options,
    state: State = .request_line,
    /// The request being assembled, owned until it is emitted.
    pending: ?Request = null,
    /// Bytes of body still expected in `fixed_body`, or of the current chunk.
    remaining: usize = 0,
    /// Body assembled so far, allocated in the pending request's arena.
    body: std.ArrayList(u8) = .empty,
    /// Bytes consumed by the current request's header block, for the limit.
    header_bytes: usize = 0,

    pub const handler_name = "http-request-decoder";

    pub const State = enum {
        request_line,
        headers,
        fixed_body,
        chunk_size,
        chunk_data,
        /// Consuming the CRLF that follows a chunk's data.
        chunk_data_end,
        /// Consuming trailer headers after the final chunk.
        trailers,
        /// A fatal parse failure was reported and everything after it is
        /// discarded.
        ///
        /// HTTP/1 framing is not resynchronizable: once a request line, a
        /// header block or a chunk header is malformed, the decoder cannot know
        /// where the next message begins, so continuing to parse would be
        /// guesswork. Without this state the offending bytes stay in the
        /// accumulation buffer and every later read re-parses them, raising the
        /// same error again — an error storm a peer can trigger with one bad
        /// byte followed by a slow dribble. Netty calls this state
        /// `BAD_MESSAGE`; the application is expected to close the connection
        /// when it sees the first error.
        bad_message,
    };

    pub const Options = struct {
        /// Longest request line, which bounds the URI.
        max_request_line: usize = 8 * 1024,
        /// Longest header block, counting names, values and line endings.
        max_header_bytes: usize = 16 * 1024,
        /// Most headers in one request.
        max_header_count: usize = 100,
        /// Largest body this decoder will assemble in memory.
        max_body_length: usize = 1024 * 1024,
    };

    pub fn init(options: Options) RequestDecoder {
        return .{
            .decoder = .{
                .options = .{
                    // The residue limit must accommodate the largest single unit
                    // the parser waits for, which is a whole body.
                    .max_cumulation = @max(
                        options.max_body_length,
                        options.max_header_bytes + options.max_request_line,
                    ) + 2,
                },
            },
            .options = options,
        };
    }

    /// Allocates a decoder and installs it at the end of `pipeline`.
    pub fn addTo(pipeline: *Pipeline, options: Options) !*RequestDecoder {
        const decoder = try pipeline.gpa.create(RequestDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *RequestDecoder, gpa: Allocator) void {
        self.discardPending();
        self.decoder.deinit(gpa);
    }

    pub fn onRead(self: *RequestDecoder, ctx: *HandlerContext, msg: Message) CodecError!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    /// Hands bytes that follow the last parsed request to whatever replaces this
    /// decoder, which is how a protocol upgrade keeps the client's first
    /// post-upgrade bytes.
    pub fn onRemoved(self: *RequestDecoder, ctx: *HandlerContext) void {
        self.decoder.onRemoved(ctx);
    }

    /// Reports a request that the peer abandoned half-way.
    ///
    /// The generic decoder only notices leftover *unparsed* bytes, but a
    /// truncated body has already been consumed into the pending request, so
    /// that check is not enough on its own.
    pub fn onInactive(self: *RequestDecoder, ctx: *HandlerContext) CodecError!void {
        const result = self.decoder.onInactive(self, ctx);
        if (self.pending != null) {
            self.discardPending();
            self.state = .request_line;
            self.remaining = 0;
            self.header_bytes = 0;
            return error.IncompleteMessage;
        }
        return result;
    }

    /// Releases a half-parsed request, so a connection that dies mid-request
    /// leaks nothing.
    fn discardPending(self: *RequestDecoder) void {
        if (self.pending) |*request| {
            // `body` lives in the request's arena, so the arena teardown covers
            // it; dropping the handle is enough.
            self.body = .empty;
            request.deinit(request.arena.child_allocator);
            self.pending = null;
        }
    }

    /// Called by the accumulating decoder; see the contract in `codec.zig`.
    pub fn decode(
        self: *RequestDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        if (self.state == .bad_message) {
            // Consuming without emitting is a legal decode outcome, so the
            // accumulation buffer drains instead of growing.
            cumulation.clear();
            return null;
        }
        return self.dispatch(ctx, cumulation) catch |err| {
            self.enterBadMessage(cumulation);
            return err;
        };
    }

    fn dispatch(
        self: *RequestDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        return switch (self.state) {
            .request_line => self.decodeRequestLine(ctx, cumulation),
            .headers => self.decodeHeaders(ctx, cumulation),
            .fixed_body => self.decodeFixedBody(ctx, cumulation),
            .chunk_size => self.decodeChunkSize(cumulation),
            .chunk_data => self.decodeChunkData(cumulation),
            .chunk_data_end => self.decodeChunkDataEnd(cumulation),
            .trailers => self.decodeTrailers(ctx, cumulation),
            .bad_message => unreachable, // Handled by the caller.
        };
    }

    /// Latches the failure: the half-built request is released and the rest of
    /// the stream is written off, so the error is reported exactly once no
    /// matter how the peer fragments what follows.
    fn enterBadMessage(self: *RequestDecoder, cumulation: *Buffer) void {
        self.discardPending();
        self.state = .bad_message;
        self.remaining = 0;
        self.header_bytes = 0;
        cumulation.clear();
    }

    /// Extracts the next CRLF- or LF-terminated line, or null when incomplete.
    ///
    /// Returns the line without its ending, and how many bytes it occupied.
    fn takeLine(cumulation: *Buffer, limit: usize) CodecError!?struct { []const u8, usize } {
        const readable = cumulation.readableSlice();
        const newline = std.mem.indexOfScalar(u8, readable, '\n') orelse {
            if (readable.len > limit) return error.HeaderTooLong;
            return null;
        };
        if (newline > limit) return error.HeaderTooLong;
        const end = if (newline > 0 and readable[newline - 1] == '\r') newline - 1 else newline;
        return .{ readable[0..end], newline + 1 };
    }

    fn decodeRequestLine(
        self: *RequestDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        const taken = try takeLine(cumulation, self.options.max_request_line) orelse return null;
        const line, const consumed = taken;

        // A leading empty line before a request is tolerated, as RFC 9112
        // recommends for robustness.
        if (line.len == 0) {
            try cumulation.skip(consumed);
            return null;
        }

        var request: Request = .init(ctx.gpa());
        errdefer request.deinit(ctx.gpa());
        const arena = request.allocator();

        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const method_text = fields.next() orelse return error.MalformedRequestLine;
        const target_text = fields.next() orelse return error.MalformedRequestLine;
        const version_text = fields.next() orelse return error.MalformedRequestLine;
        if (fields.next() != null) return error.MalformedRequestLine;

        request.method = .parse(try arena.dupe(u8, method_text));
        request.target = try arena.dupe(u8, target_text);
        request.version = Version.parse(version_text) orelse
            return error.UnsupportedHttpVersion;
        request.keep_alive = request.version.keepAliveByDefault();

        try cumulation.skip(consumed);
        self.pending = request;
        self.header_bytes = consumed;
        self.state = .headers;
        return null;
    }

    fn decodeHeaders(
        self: *RequestDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        assert(self.pending != null);
        const request = &self.pending.?;
        const arena = request.allocator();

        while (true) {
            const taken = try takeLine(cumulation, self.options.max_header_bytes) orelse
                return null;
            const line, const consumed = taken;

            self.header_bytes += consumed;
            if (self.header_bytes > self.options.max_header_bytes) {
                return error.HeaderTooLong;
            }

            if (line.len == 0) {
                try cumulation.skip(consumed);
                return self.finishHeaders(ctx, cumulation);
            }
            // Obsolete line folding is a smuggling vector; reject it.
            if (line[0] == ' ' or line[0] == '\t') return error.ObsoleteLineFolding;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse
                return error.MalformedHeader;
            const name = line[0..colon];
            if (name.len == 0) return error.MalformedHeader;
            // Whitespace between the name and the colon is forbidden.
            if (name[name.len - 1] == ' ' or name[name.len - 1] == '\t') {
                return error.MalformedHeader;
            }
            // A name that is not a token, or a value carrying a control
            // character such as a bare CR, is rejected rather than passed on.
            // An intermediary that disagrees with this parser about where the
            // field ends is how a request gets smuggled past it.
            if (!isFieldNameValid(name)) return error.MalformedHeader;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!isFieldValueValid(value)) return error.MalformedHeader;

            if (request.headers.len() >= self.options.max_header_count) {
                return error.TooManyHeaders;
            }
            try request.headers.append(
                arena,
                try arena.dupe(u8, name),
                try arena.dupe(u8, value),
            );
            try cumulation.skip(consumed);
        }
    }

    /// Decides how the body is framed once the header block is complete.
    fn finishHeaders(
        self: *RequestDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        const request = &self.pending.?;
        const headers = &request.headers;

        if (headers.has("connection")) {
            request.keep_alive = !headers.hasToken("connection", "close");
        }

        const has_length = headers.has("content-length");
        const chunked = headers.hasToken("transfer-encoding", "chunked");

        // Both framings at once is the canonical request smuggling setup.
        if (has_length and headers.has("transfer-encoding")) {
            return error.ConflictingFraming;
        }
        if (headers.has("transfer-encoding") and !chunked) {
            return error.UnsupportedTransferEncoding;
        }

        if (chunked) {
            self.body = .empty;
            self.state = .chunk_size;
            return null;
        }

        if (has_length) {
            const length = try parseContentLength(headers);
            if (length > self.options.max_body_length) return error.BodyTooLarge;
            if (length == 0) return self.emit(ctx);
            self.remaining = length;
            self.body = .empty;
            self.state = .fixed_body;
            return null;
        }

        _ = cumulation;
        return self.emit(ctx);
    }

    /// Parses `Content-Length`, rejecting the ambiguous spellings that
    /// intermediaries disagree about.
    fn parseContentLength(headers: *const Headers) CodecError!usize {
        var seen: ?usize = null;
        for (headers.items()) |entry| {
            if (!std.ascii.eqlIgnoreCase(entry.name, "content-length")) continue;
            const text = std.mem.trim(u8, entry.value, " \t");
            // A comma-separated list is only acceptable when every element
            // agrees, and even then it is safer to refuse.
            const value = std.fmt.parseInt(usize, text, 10) catch
                return error.MalformedContentLength;
            if (seen) |previous| {
                if (previous != value) return error.ConflictingFraming;
            }
            seen = value;
        }
        return seen orelse error.MalformedContentLength;
    }

    fn decodeFixedBody(
        self: *RequestDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        assert(self.pending != null);
        const available = @min(self.remaining, cumulation.readableLen());
        if (available == 0) return null;

        const arena = self.pending.?.allocator();
        const chunk = try cumulation.readBytes(available);
        try self.body.appendSlice(arena, chunk);
        self.remaining -= available;
        if (self.remaining > 0) return null;
        return self.emit(ctx);
    }

    fn decodeChunkSize(self: *RequestDecoder, cumulation: *Buffer) CodecError!?Message {
        const taken = try takeLine(cumulation, 64) orelse return null;
        const line, const consumed = taken;

        // Chunk extensions follow a semicolon and are ignored.
        const size_text = blk: {
            const semicolon = std.mem.indexOfScalar(u8, line, ';') orelse break :blk line;
            break :blk line[0..semicolon];
        };
        const trimmed = std.mem.trim(u8, size_text, " \t");
        if (trimmed.len == 0) return error.MalformedChunkSize;
        const size = std.fmt.parseInt(usize, trimmed, 16) catch
            return error.MalformedChunkSize;

        if (self.body.items.len + size > self.options.max_body_length) {
            return error.BodyTooLarge;
        }

        try cumulation.skip(consumed);
        self.remaining = size;
        self.state = if (size == 0) .trailers else .chunk_data;
        return null;
    }

    fn decodeChunkData(self: *RequestDecoder, cumulation: *Buffer) CodecError!?Message {
        assert(self.pending != null);
        const available = @min(self.remaining, cumulation.readableLen());
        if (available == 0) return null;

        const arena = self.pending.?.allocator();
        const chunk = try cumulation.readBytes(available);
        try self.body.appendSlice(arena, chunk);
        self.remaining -= available;
        if (self.remaining == 0) self.state = .chunk_data_end;
        return null;
    }

    fn decodeChunkDataEnd(self: *RequestDecoder, cumulation: *Buffer) CodecError!?Message {
        const taken = try takeLine(cumulation, 2) orelse return null;
        const line, const consumed = taken;
        if (line.len != 0) return error.MalformedChunk;
        try cumulation.skip(consumed);
        self.state = .chunk_size;
        return null;
    }

    fn decodeTrailers(
        self: *RequestDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        assert(self.pending != null);
        const request = &self.pending.?;
        const arena = request.allocator();

        while (true) {
            const taken = try takeLine(cumulation, self.options.max_header_bytes) orelse
                return null;
            const line, const consumed = taken;

            if (line.len == 0) {
                try cumulation.skip(consumed);
                return self.emit(ctx);
            }

            // Trailers are bounded by the same budget as the header block;
            // otherwise a peer could send an unbounded trailer section.
            self.header_bytes += consumed;
            if (self.header_bytes > self.options.max_header_bytes) {
                return error.HeaderTooLong;
            }

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse
                return error.MalformedHeader;
            const name = line[0..colon];
            if (!isFieldNameValid(name)) return error.MalformedHeader;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!isFieldValueValid(value)) return error.MalformedHeader;

            if (isForbiddenTrailer(name)) {
                // RFC 9110 §6.5.1: fields that decide framing, routing or how
                // the content is interpreted must be ignored when they arrive in
                // a trailer. Merging them into the request would let a peer
                // change, after the body has been read and framed, what the
                // application believes it received.
                try cumulation.skip(consumed);
                continue;
            }

            if (request.headers.len() >= self.options.max_header_count) {
                return error.TooManyHeaders;
            }
            try request.headers.append(
                arena,
                try arena.dupe(u8, name),
                try arena.dupe(u8, value),
            );
            try cumulation.skip(consumed);
        }
    }

    /// Field names that carry no meaning in a trailer and are dropped there.
    fn isForbiddenTrailer(name: []const u8) bool {
        const forbidden = [_][]const u8{
            "content-length", "transfer-encoding", "host",          "trailer",
            "expect",         "connection",        "te",            "authorization",
            "content-type",   "content-encoding",  "content-range", "cache-control",
        };
        for (forbidden) |entry| {
            if (std.ascii.eqlIgnoreCase(name, entry)) return true;
        }
        return false;
    }

    /// Hands the finished request to the pipeline and resets for the next one,
    /// which is what makes keep-alive and pipelining work.
    fn emit(self: *RequestDecoder, ctx: *HandlerContext) CodecError!?Message {
        assert(self.pending != null);
        var request = self.pending.?;
        request.body = self.body.items;

        self.pending = null;
        self.body = .empty;
        self.remaining = 0;
        self.header_bytes = 0;
        self.state = .request_line;

        errdefer request.deinit(ctx.gpa());
        return try Message.initAny(ctx.gpa(), Request, request);
    }
};

// -- Response encoding -----------------------------------------------------

/// One piece of a streaming response body.
///
/// Write a `Response` with `chunked = true` first, then any number of `Chunk`s,
/// then a `Chunk` with `last = true`. This is how a response whose length is
/// unknown up front is produced without buffering all of it.
pub const Chunk = struct {
    data: []const u8 = "",
    /// Marks the terminating zero-length chunk.
    last: bool = false,
};

/// Serializes `Response` and `Chunk` messages into bytes.
///
/// Framing headers are written by the encoder, not the caller: `Content-Length`
/// for a normal response, `Transfer-Encoding: chunked` for a streaming one, and
/// the `Connection` header matching `Response.keep_alive`. Any of those supplied
/// by the caller are dropped, because two sources of framing truth is exactly
/// what the request smuggling checks in the decoder exist to prevent.
pub const ResponseEncoder = struct {
    options: Options = .{},

    pub const handler_name = "http-response-encoder";

    pub const Options = struct {
        /// Bytes reserved for the head of a response before its body.
        initial_capacity: usize = 512,
        /// Sent as `Server` unless empty.
        server_name: []const u8 = "zinet",
    };

    pub fn init(options: Options) ResponseEncoder {
        return .{ .options = options };
    }

    /// Allocates an encoder and installs it at the end of `pipeline`.
    pub fn addTo(pipeline: *Pipeline, options: Options) !*ResponseEncoder {
        const encoder = try pipeline.gpa.create(ResponseEncoder);
        encoder.* = .init(options);
        errdefer pipeline.gpa.destroy(encoder);
        _ = try pipeline.addLast(handler_name, .initOwned(encoder));
        return encoder;
    }

    pub fn onWrite(
        self: *ResponseEncoder,
        ctx: *HandlerContext,
        msg: Message,
    ) CodecError!void {
        var owned = msg;
        if (owned.get(Response)) |response| {
            defer owned.deinit(ctx.gpa());
            return self.writeResponse(ctx, response);
        }
        if (owned.get(Chunk)) |chunk| {
            defer owned.deinit(ctx.gpa());
            return self.writeChunk(ctx, chunk);
        }
        // Neither of ours: raw bytes or another codec's payload.
        return ctx.write(owned.move());
    }

    fn writeResponse(
        self: *ResponseEncoder,
        ctx: *HandlerContext,
        response: *const Response,
    ) CodecError!void {
        // Validated before a single byte is written, so a rejected response
        // never reaches the socket half-formed.
        for (response.headers) |header| {
            if (isReserved(header.name)) continue;
            try validateHeader(header);
        }
        try validateHeaderValue(self.options.server_name);

        const gpa = ctx.gpa();
        var out = try Buffer.init(gpa, .{
            .capacity = self.options.initial_capacity + response.body.len,
        });
        errdefer out.deinit(gpa);

        var scratch: [64]u8 = undefined;
        var adapter = out.writerAdapter(gpa, &scratch);
        const writer = &adapter.interface;

        try writer.print("{s} {d} {s}\r\n", .{
            response.version.name(),
            response.status.code(),
            response.status.phrase(),
        });

        for (response.headers) |header| {
            if (isReserved(header.name)) continue;
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }
        if (self.options.server_name.len > 0 and !hasHeader(response.headers, "server")) {
            try writer.print("Server: {s}\r\n", .{self.options.server_name});
        }
        try writer.print("Connection: {s}\r\n", .{
            if (response.keep_alive) "keep-alive" else "close",
        });

        const body_allowed = response.status.allowsBody();
        if (!body_allowed) {
            // A bodyless status takes no framing header at all.
        } else if (response.chunked) {
            try writer.writeAll("Transfer-Encoding: chunked\r\n");
        } else {
            try writer.print("Content-Length: {d}\r\n", .{response.body.len});
        }
        try writer.writeAll("\r\n");

        if (body_allowed and response.body.len > 0) {
            if (response.chunked) {
                try writeChunkInto(writer, response.body);
                try writeChunkInto(writer, ""); // Terminating chunk.
            } else {
                try writer.writeAll(response.body);
            }
        }
        try writer.flush();
        if (adapter.err) |err| return err;

        return ctx.write(.initBuffer(&out));
    }

    fn writeChunk(
        self: *ResponseEncoder,
        ctx: *HandlerContext,
        chunk: *const Chunk,
    ) CodecError!void {
        _ = self;
        return writeChunkMessage(ctx, chunk);
    }
};

/// Whether `name` is a valid field name, that is an RFC 9110 §5.1 token.
///
/// The token rule is what keeps a field name from containing the colon that
/// would start a second field, the space that would make it a request line, or
/// the CR and LF that would end the header block early.
pub fn isFieldNameValid(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        const ok = switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9' => true,
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        };
        if (!ok) return false;
    }
    return true;
}

/// Whether `value` is a valid field value: visible characters, space and
/// horizontal tab (RFC 9110 §5.5).
///
/// Every control character is refused rather than only CR and LF. A bare CR is
/// enough to desynchronize an intermediary that terminates lines differently
/// from this parser, which is the same family of attack as the smuggling
/// vectors the framing checks reject.
pub fn isFieldValueValid(value: []const u8) bool {
    for (value) |byte| {
        const ok = byte == '\t' or (byte >= 0x20 and byte != 0x7F);
        if (!ok) return false;
    }
    return true;
}

/// Installs a full HTTP/1.1 server codec: request decoding inbound, response
/// encoding outbound.
pub fn addServerCodec(
    pipeline: *Pipeline,
    decoder_options: RequestDecoder.Options,
    encoder_options: ResponseEncoder.Options,
) !void {
    _ = try RequestDecoder.addTo(pipeline, decoder_options);
    _ = try ResponseEncoder.addTo(pipeline, encoder_options);
}

/// Header names the encoders control; caller-supplied copies are ignored,
/// because two sources of framing truth is what smuggling is made of.
const reserved_headers = [_][]const u8{
    "content-length",
    "transfer-encoding",
    "connection",
};

// -- Shared writing helpers ------------------------------------------------
//
// Used by both encoders: the rules for serializing a header safely do not
// depend on which direction it is travelling.

/// Serializes one `Chunk` of a streaming body. Shared by both encoders, since a
/// chunk looks the same in a request as in a response.
fn writeChunkMessage(ctx: *HandlerContext, chunk: *const Chunk) CodecError!void {
    const gpa = ctx.gpa();
    var out = try Buffer.init(gpa, .{ .capacity = chunk.data.len + 32 });
    errdefer out.deinit(gpa);

    var scratch: [32]u8 = undefined;
    var adapter = out.writerAdapter(gpa, &scratch);
    const writer = &adapter.interface;

    if (chunk.data.len > 0) try writeChunkInto(writer, chunk.data);
    // The zero-length chunk plus its (empty) trailer section is the whole
    // terminator: "0\r\n\r\n".
    if (chunk.last) try writeChunkInto(writer, "");
    try writer.flush();
    if (adapter.err) |err| return err;

    if (out.readableLen() == 0) {
        out.deinit(gpa);
        return;
    }
    return ctx.write(.initBuffer(&out));
}

/// Writes one chunk in `chunked` transfer encoding.
fn writeChunkInto(writer: *std.Io.Writer, data: []const u8) CodecError!void {
    try writer.print("{x}\r\n", .{data.len});
    if (data.len > 0) try writer.writeAll(data);
    try writer.writeAll("\r\n");
}

fn isReserved(name: []const u8) bool {
    for (reserved_headers) |reserved| {
        if (std.ascii.eqlIgnoreCase(name, reserved)) return true;
    }
    return false;
}

/// Rejects a header the peer could use to forge a response.
///
/// Applications routinely echo something they were sent — a request header,
/// a query parameter — back out in a response header. If a CR or LF
/// survived that round trip, the peer would be writing the response
/// framing: everything after its `\r\n\r\n` becomes, as far as any client
/// or cache in between is concerned, a second response the server never
/// wrote. That is HTTP response splitting, and the only reliable place to
/// stop it is here, where the bytes are serialized. Netty validates its
/// headers by default for the same reason.
fn validateHeader(header: Header) CodecError!void {
    if (!isFieldNameValid(header.name)) return error.InvalidHeader;
    if (!isFieldValueValid(header.value)) return error.InvalidHeader;
}

fn validateHeaderValue(value: []const u8) CodecError!void {
    if (!isFieldValueValid(value)) return error.InvalidHeader;
}

fn hasHeader(headers: []const Header, name: []const u8) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
    }
    return false;
}

// -- Client side -----------------------------------------------------------
//
// The naming follows one rule: **inbound messages own their storage, outbound
// messages borrow it.** So the server side has an owning `Request` and a
// borrowing `Response`, and the client side mirrors it with an owning
// `IncomingResponse` and a borrowing `OutgoingRequest`. The direction a message
// travels decides who has to keep its bytes alive, and that is what the names
// record.

/// A decoded response. Owns the arena its strings live in.
pub const IncomingResponse = struct {
    arena: std.heap.ArenaAllocator,
    version: Version,
    /// The status as sent. Non-exhaustive, because a server may use a code this
    /// library does not name.
    status: Status,
    /// Reason phrase exactly as it appeared, which may be empty.
    reason: []const u8,
    headers: Headers,
    /// Complete body. Empty when the response had none.
    body: []const u8,
    /// Whether the connection may be reused for another exchange.
    keep_alive: bool,

    pub fn init(gpa: Allocator) IncomingResponse {
        return .{
            .arena = .init(gpa),
            .version = .http_1_1,
            .status = .ok,
            .reason = "",
            .headers = .{},
            .body = "",
            .keep_alive = true,
        };
    }

    /// Takes an allocator it does not use so `Message`'s type-erased destructor
    /// can call it uniformly.
    pub fn deinit(response: *IncomingResponse, _: Allocator) void {
        response.arena.deinit();
    }

    pub fn allocator(response: *IncomingResponse) Allocator {
        return response.arena.allocator();
    }

    /// Whether the status is in the 2xx range.
    pub fn isSuccess(response: *const IncomingResponse) bool {
        const code = response.status.code();
        return code >= 200 and code < 300;
    }
};

/// A request to send. Borrows everything, like `Response` does.
pub const OutgoingRequest = struct {
    method: Method = .get,
    /// Request target. Must be an origin-form path for an ordinary request.
    target: []const u8 = "/",
    version: Version = .http_1_1,
    /// `Host` is required by HTTP/1.1 and written for you when set here; supply
    /// it in `headers` instead if you need unusual placement.
    host: []const u8 = "",
    /// Headers to send, in order. Framing headers are ignored; see
    /// `RequestEncoder`.
    headers: []const Header = &.{},
    body: []const u8 = "",
    keep_alive: bool = true,
    /// Send the body chunked instead of with `Content-Length`, for a length that
    /// is not known up front. Follow with `Chunk` messages.
    chunked: bool = false,
};

/// Records the methods of requests that have been sent but not yet answered.
///
/// A response cannot be framed without knowing what it answers: a `HEAD`
/// response carries `Content-Length` but no body, and a `2xx` to `CONNECT`
/// switches to a tunnel. Netty solves this by fusing its client encoder and
/// decoder into one duplex handler so they can share a queue; Zinet keeps them
/// as two handlers sharing this.
///
/// Not synchronized, and does not need to be: like all handler state it is
/// touched only from the connection's own task. See `addClientCodec` for what
/// that means for a client that wants to send from somewhere else.
pub const MethodTracker = struct {
    /// Ring of methods awaiting responses.
    pending: [max_pipelined]Method = @splat(.get),
    head: usize = 0,
    len: usize = 0,

    /// How many requests may be in flight at once. HTTP/1.1 pipelining deeper
    /// than this is refused rather than tracked, because an unbounded queue here
    /// would be a peer-controlled allocation.
    pub const max_pipelined = 32;

    pub fn push(tracker: *MethodTracker, method: Method) CodecError!void {
        if (tracker.len == max_pipelined) return error.TooManyPendingRequests;
        tracker.pending[(tracker.head + tracker.len) % max_pipelined] = method;
        tracker.len += 1;
    }

    pub fn pop(tracker: *MethodTracker) ?Method {
        if (tracker.len == 0) return null;
        const method = tracker.pending[tracker.head];
        tracker.head = (tracker.head + 1) % max_pipelined;
        tracker.len -= 1;
        return method;
    }

    pub fn count(tracker: *const MethodTracker) usize {
        return tracker.len;
    }
};

/// Serializes `OutgoingRequest` and `Chunk` messages into bytes.
///
/// Framing headers belong to the encoder, exactly as on the response side:
/// `Content-Length` or `Transfer-Encoding`, and the `Connection` header matching
/// `keep_alive`. Caller-supplied copies are dropped, because two sources of
/// framing truth is what request smuggling is made of.
///
/// Header names and values are validated before a single byte is emitted. The
/// outbound direction needs this as much as the inbound one: a client that
/// copies a server-controlled value into a request header would otherwise let
/// that server inject a whole second request into the stream.
pub const RequestEncoder = struct {
    options: Options = .{},
    /// Shared with the `ResponseDecoder`, so it can frame what comes back.
    tracker: ?*MethodTracker = null,

    pub const handler_name = "http-request-encoder";

    pub const Options = struct {
        /// Bytes reserved for the head of a request before its body.
        initial_capacity: usize = 512,
        /// Sent as `User-Agent` unless empty.
        user_agent: []const u8 = "zinet",
    };

    pub fn init(options: Options) RequestEncoder {
        return .{ .options = options };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*RequestEncoder {
        const encoder = try pipeline.gpa.create(RequestEncoder);
        encoder.* = .init(options);
        errdefer pipeline.gpa.destroy(encoder);
        _ = try pipeline.addLast(handler_name, .initOwned(encoder));
        return encoder;
    }

    pub fn onWrite(self: *RequestEncoder, ctx: *HandlerContext, msg: Message) CodecError!void {
        var owned = msg;
        if (owned.get(OutgoingRequest)) |request| {
            defer owned.deinit(ctx.gpa());
            return self.writeRequest(ctx, request);
        }
        if (owned.get(Chunk)) |chunk| {
            defer owned.deinit(ctx.gpa());
            return writeChunkMessage(ctx, chunk);
        }
        // Not ours; raw bytes pass through.
        return ctx.write(owned.move());
    }

    fn writeRequest(
        self: *RequestEncoder,
        ctx: *HandlerContext,
        request: *const OutgoingRequest,
    ) CodecError!void {
        // Validated up front: a half-written request is just as exploitable as a
        // whole one, so nothing may reach the socket before every field is known
        // to be safe.
        for (request.headers) |header| {
            if (isReserved(header.name)) continue;
            try validateHeader(header);
        }
        try validateHeaderValue(self.options.user_agent);
        try validateHeaderValue(request.host);
        if (!isRequestTargetValid(request.target)) return error.InvalidTarget;

        const gpa = ctx.gpa();
        var out = try Buffer.init(gpa, .{
            .capacity = self.options.initial_capacity + request.body.len,
        });
        errdefer out.deinit(gpa);

        var scratch: [64]u8 = undefined;
        var adapter = out.writerAdapter(gpa, &scratch);
        const writer = &adapter.interface;

        try writer.print("{s} {s} {s}\r\n", .{
            request.method.name(),
            request.target,
            request.version.name(),
        });

        if (request.host.len > 0 and !hasHeader(request.headers, "host")) {
            try writer.print("Host: {s}\r\n", .{request.host});
        }
        for (request.headers) |header| {
            if (isReserved(header.name)) continue;
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }
        if (self.options.user_agent.len > 0 and !hasHeader(request.headers, "user-agent")) {
            try writer.print("User-Agent: {s}\r\n", .{self.options.user_agent});
        }
        try writer.print("Connection: {s}\r\n", .{
            if (request.keep_alive) "keep-alive" else "close",
        });

        if (request.chunked) {
            try writer.writeAll("Transfer-Encoding: chunked\r\n");
        } else if (request.body.len > 0 or methodExpectsBody(request.method)) {
            try writer.print("Content-Length: {d}\r\n", .{request.body.len});
        }
        try writer.writeAll("\r\n");

        if (request.body.len > 0) {
            if (request.chunked) {
                try writeChunkInto(writer, request.body);
            } else {
                try writer.writeAll(request.body);
            }
        }
        try writer.flush();
        if (adapter.err) |err| return err;

        // Recorded only once the request is fully serialized, so a rejected
        // request does not leave the decoder expecting a response to it.
        if (self.tracker) |tracker| try tracker.push(request.method);

        return ctx.write(.initBuffer(&out));
    }

    /// Whether a `Content-Length: 0` is worth sending for an empty body.
    ///
    /// A GET with no body should not carry one; a POST or PUT with no body
    /// should, because some servers treat its absence as a malformed request.
    fn methodExpectsBody(method: Method) bool {
        return switch (method) {
            .post, .put, .patch => true,
            else => false,
        };
    }
};

/// Rejects a target that would break the request line.
///
/// Space would create extra fields and CR or LF would end the line early, both
/// of which let a caller-supplied path forge a request.
pub fn isRequestTargetValid(target: []const u8) bool {
    if (target.len == 0) return false;
    for (target) |byte| {
        if (byte <= 0x20 or byte == 0x7F) return false;
    }
    return true;
}

/// Turns a stream of response bytes into `IncomingResponse` messages.
///
/// The mirror of `RequestDecoder`, but response framing has a rule requests do
/// not (RFC 9112 §6.3), and it is the one clients get wrong: when there is
/// neither `Transfer-Encoding: chunked` nor `Content-Length`, **the body runs
/// until the connection closes**. A decoder that only ever emits on a complete
/// frame would hang on such a response forever.
pub const ResponseDecoder = struct {
    decoder: ByteToMessageDecoder(ResponseDecoder),
    options: Options,
    state: State = .status_line,
    pending: ?IncomingResponse = null,
    remaining: usize = 0,
    body: std.ArrayList(u8) = .empty,
    header_bytes: usize = 0,
    /// Method of the request this response answers, needed for framing.
    request_method: Method = .get,
    /// Shared with the `RequestEncoder`.
    tracker: ?*MethodTracker = null,

    pub const handler_name = "http-response-decoder";

    pub const State = enum {
        status_line,
        headers,
        fixed_body,
        chunk_size,
        chunk_data,
        chunk_data_end,
        trailers,
        /// Body continues until the peer closes. Bytes are deliberately left in
        /// the accumulation buffer rather than copied out, so that the residue
        /// limit bounds them and `decodeLast` can deliver them at end of stream.
        until_close,
        /// A 2xx answer to CONNECT: everything after the header block belongs to
        /// the tunnel, not to HTTP. The response is emitted immediately and this
        /// decoder stops looking at the stream.
        tunnel,
        /// See `RequestDecoder.State.bad_message`.
        bad_message,
    };

    pub const Options = struct {
        /// Longest status line, which bounds the reason phrase.
        max_status_line: usize = 8 * 1024,
        max_header_bytes: usize = 16 * 1024,
        max_header_count: usize = 100,
        /// Largest body this decoder will assemble in memory. Also the ceiling
        /// on a body that runs until close.
        max_body_length: usize = 1024 * 1024,
    };

    pub fn init(options: Options) ResponseDecoder {
        return .{
            .decoder = .{
                .options = .{
                    .max_cumulation = @max(
                        options.max_body_length,
                        options.max_header_bytes + options.max_status_line,
                    ) + 2,
                },
            },
            .options = options,
        };
    }

    pub fn addTo(pipeline: *Pipeline, options: Options) !*ResponseDecoder {
        const decoder = try pipeline.gpa.create(ResponseDecoder);
        decoder.* = .init(options);
        errdefer pipeline.gpa.destroy(decoder);
        _ = try pipeline.addLast(handler_name, .initOwned(decoder));
        return decoder;
    }

    pub fn deinit(self: *ResponseDecoder, gpa: Allocator) void {
        self.discardPending();
        self.decoder.deinit(gpa);
    }

    pub fn onRead(self: *ResponseDecoder, ctx: *HandlerContext, msg: Message) CodecError!void {
        return self.decoder.onRead(self, ctx, msg);
    }

    pub fn onRemoved(self: *ResponseDecoder, ctx: *HandlerContext) void {
        self.decoder.onRemoved(ctx);
    }

    /// Reports a response the peer abandoned half-way.
    ///
    /// A body that runs until close is *completed* by the close, so it is not a
    /// failure; every other unfinished state is.
    pub fn onInactive(self: *ResponseDecoder, ctx: *HandlerContext) CodecError!void {
        const result = self.decoder.onInactive(self, ctx);
        if (self.pending != null) {
            self.discardPending();
            self.reset();
            return error.IncompleteMessage;
        }
        return result;
    }

    fn reset(self: *ResponseDecoder) void {
        self.state = .status_line;
        self.remaining = 0;
        self.header_bytes = 0;
    }

    fn discardPending(self: *ResponseDecoder) void {
        if (self.pending) |*response| {
            self.body = .empty;
            response.deinit(response.arena.child_allocator);
            self.pending = null;
        }
    }

    pub fn decode(
        self: *ResponseDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        switch (self.state) {
            .bad_message => {
                cumulation.clear();
                return null;
            },
            .tunnel => {
                // Not ours any more. Leaving the bytes alone lets whatever
                // replaces this handler pick them up, the same way an upgrade
                // works.
                return null;
            },
            else => {},
        }
        return self.dispatch(ctx, cumulation) catch |err| {
            self.enterBadMessage(cumulation);
            return err;
        };
    }

    /// Last chance at end of stream, which is where an until-close body lands.
    pub fn decodeLast(
        self: *ResponseDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        if (self.state == .until_close) {
            const available = cumulation.readableLen();
            if (available > self.options.max_body_length) return error.BodyTooLarge;
            if (available > 0) {
                const arena = self.pending.?.allocator();
                const chunk = try cumulation.readBytes(available);
                try self.body.appendSlice(arena, chunk);
            }
            // The close ends the response, and it also ends the connection, so
            // keep-alive is not on offer whatever the headers said.
            self.pending.?.keep_alive = false;
            return self.emit(ctx);
        }
        return self.decode(ctx, cumulation);
    }

    fn dispatch(
        self: *ResponseDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        return switch (self.state) {
            .status_line => self.decodeStatusLine(ctx, cumulation),
            .headers => self.decodeHeaders(ctx, cumulation),
            .fixed_body => self.decodeFixedBody(ctx, cumulation),
            .chunk_size => self.decodeChunkSize(cumulation),
            .chunk_data => self.decodeChunkData(cumulation),
            .chunk_data_end => self.decodeChunkDataEnd(cumulation),
            .trailers => self.decodeTrailers(ctx, cumulation),
            // Waiting for more bytes, or for the close that ends the body.
            .until_close => null,
            .tunnel, .bad_message => unreachable, // Handled by the caller.
        };
    }

    fn enterBadMessage(self: *ResponseDecoder, cumulation: *Buffer) void {
        self.discardPending();
        self.state = .bad_message;
        self.remaining = 0;
        self.header_bytes = 0;
        cumulation.clear();
    }

    fn decodeStatusLine(
        self: *ResponseDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        const taken = try RequestDecoder.takeLine(cumulation, self.options.max_status_line) orelse
            return null;
        const line, const consumed = taken;

        // Tolerate a stray empty line between responses, as for requests.
        if (line.len == 0) {
            try cumulation.skip(consumed);
            return null;
        }

        var response: IncomingResponse = .init(ctx.gpa());
        errdefer response.deinit(ctx.gpa());
        const arena = response.allocator();

        // `HTTP/1.1 200 OK` — the reason phrase is optional and may contain
        // spaces, so it is whatever follows the code.
        const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse
            return error.MalformedStatusLine;
        response.version = Version.parse(line[0..first_space]) orelse
            return error.UnsupportedHttpVersion;

        const rest = std.mem.trimStart(u8, line[first_space + 1 ..], " ");
        if (rest.len < 3) return error.MalformedStatusLine;
        const code_text = rest[0..3];
        const code = std.fmt.parseInt(u16, code_text, 10) catch
            return error.MalformedStatusLine;
        if (code < 100) return error.MalformedStatusLine;
        response.status = @enumFromInt(code);

        const reason = if (rest.len > 3) std.mem.trim(u8, rest[3..], " \t") else "";
        if (!isFieldValueValid(reason)) return error.MalformedStatusLine;
        response.reason = try arena.dupe(u8, reason);
        response.keep_alive = response.version.keepAliveByDefault();

        try cumulation.skip(consumed);
        self.pending = response;
        self.header_bytes = consumed;
        self.state = .headers;

        // Claim the method this answers. A 1xx does not complete an exchange, so
        // it must not consume the entry — except 101, which ends HTTP on this
        // connection altogether and so is as final as any 2xx.
        if (code >= 200 or code == 101) {
            if (self.tracker) |tracker| {
                self.request_method = tracker.pop() orelse .get;
            }
        }
        return null;
    }

    fn decodeHeaders(
        self: *ResponseDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        assert(self.pending != null);
        const response = &self.pending.?;
        const arena = response.allocator();

        while (true) {
            const taken = try RequestDecoder.takeLine(
                cumulation,
                self.options.max_header_bytes,
            ) orelse return null;
            const line, const consumed = taken;

            self.header_bytes += consumed;
            if (self.header_bytes > self.options.max_header_bytes) {
                return error.HeaderTooLong;
            }

            if (line.len == 0) {
                try cumulation.skip(consumed);
                return self.finishHeaders(ctx);
            }
            if (line[0] == ' ' or line[0] == '\t') return error.ObsoleteLineFolding;

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse
                return error.MalformedHeader;
            const name = line[0..colon];
            if (name.len == 0) return error.MalformedHeader;
            if (name[name.len - 1] == ' ' or name[name.len - 1] == '\t') {
                return error.MalformedHeader;
            }
            if (!isFieldNameValid(name)) return error.MalformedHeader;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!isFieldValueValid(value)) return error.MalformedHeader;

            if (response.headers.len() >= self.options.max_header_count) {
                return error.TooManyHeaders;
            }
            try response.headers.append(
                arena,
                try arena.dupe(u8, name),
                try arena.dupe(u8, value),
            );
            try cumulation.skip(consumed);
        }
    }

    /// Applies RFC 9112 §6.3 in its stated order.
    fn finishHeaders(self: *ResponseDecoder, ctx: *HandlerContext) CodecError!?Message {
        const response = &self.pending.?;
        const headers = &response.headers;

        if (headers.has("connection")) {
            response.keep_alive = !headers.hasToken("connection", "close");
        }

        const code = response.status.code();

        // 1. Some statuses and some methods have no body, whatever the headers
        //    say. Believing a `Content-Length` here is a classic desync: the
        //    server sent no body, so those bytes are the *next* response.
        if (!response.status.allowsBody() or !self.request_method.allowsResponseBody()) {
            // A 2xx to CONNECT means the rest of the stream is a tunnel.
            if (self.request_method == .connect and code >= 200 and code < 300) {
                const message = try self.emit(ctx);
                self.state = .tunnel;
                return message;
            }
            // An informational response leaves the exchange open, so the next
            // status line follows.
            return self.emit(ctx);
        }

        const has_length = headers.has("content-length");
        const chunked = headers.hasToken("transfer-encoding", "chunked");

        if (has_length and headers.has("transfer-encoding")) {
            return error.ConflictingFraming;
        }
        if (headers.has("transfer-encoding") and !chunked) {
            return error.UnsupportedTransferEncoding;
        }

        // 2. Chunked.
        if (chunked) {
            self.body = .empty;
            self.state = .chunk_size;
            return null;
        }

        // 3. Content-Length.
        if (has_length) {
            const length = try RequestDecoder.parseContentLength(headers);
            if (length > self.options.max_body_length) return error.BodyTooLarge;
            if (length == 0) return self.emit(ctx);
            self.remaining = length;
            self.body = .empty;
            self.state = .fixed_body;
            return null;
        }

        // 4. Neither: the body is however many bytes arrive before the close.
        //    This is the rule requests do not have.
        self.body = .empty;
        self.state = .until_close;
        return null;
    }

    fn decodeFixedBody(
        self: *ResponseDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        assert(self.pending != null);
        const available = @min(self.remaining, cumulation.readableLen());
        if (available == 0) return null;

        const arena = self.pending.?.allocator();
        const chunk = try cumulation.readBytes(available);
        try self.body.appendSlice(arena, chunk);
        self.remaining -= available;
        if (self.remaining > 0) return null;
        return self.emit(ctx);
    }

    fn decodeChunkSize(self: *ResponseDecoder, cumulation: *Buffer) CodecError!?Message {
        const taken = try RequestDecoder.takeLine(cumulation, 64) orelse return null;
        const line, const consumed = taken;

        const size_text = blk: {
            const semicolon = std.mem.indexOfScalar(u8, line, ';') orelse break :blk line;
            break :blk line[0..semicolon];
        };
        const trimmed = std.mem.trim(u8, size_text, " \t");
        if (trimmed.len == 0) return error.MalformedChunkSize;
        const size = std.fmt.parseInt(usize, trimmed, 16) catch
            return error.MalformedChunkSize;

        if (self.body.items.len + size > self.options.max_body_length) {
            return error.BodyTooLarge;
        }

        try cumulation.skip(consumed);
        self.remaining = size;
        self.state = if (size == 0) .trailers else .chunk_data;
        return null;
    }

    fn decodeChunkData(self: *ResponseDecoder, cumulation: *Buffer) CodecError!?Message {
        assert(self.pending != null);
        const available = @min(self.remaining, cumulation.readableLen());
        if (available == 0) return null;

        const arena = self.pending.?.allocator();
        const chunk = try cumulation.readBytes(available);
        try self.body.appendSlice(arena, chunk);
        self.remaining -= available;
        if (self.remaining == 0) self.state = .chunk_data_end;
        return null;
    }

    fn decodeChunkDataEnd(self: *ResponseDecoder, cumulation: *Buffer) CodecError!?Message {
        const taken = try RequestDecoder.takeLine(cumulation, 2) orelse return null;
        const line, const consumed = taken;
        if (line.len != 0) return error.MalformedChunkSize;
        try cumulation.skip(consumed);
        self.state = .chunk_size;
        return null;
    }

    fn decodeTrailers(
        self: *ResponseDecoder,
        ctx: *HandlerContext,
        cumulation: *Buffer,
    ) CodecError!?Message {
        assert(self.pending != null);
        const response = &self.pending.?;
        const arena = response.allocator();

        while (true) {
            const taken = try RequestDecoder.takeLine(
                cumulation,
                self.options.max_header_bytes,
            ) orelse return null;
            const line, const consumed = taken;

            if (line.len == 0) {
                try cumulation.skip(consumed);
                return self.emit(ctx);
            }

            self.header_bytes += consumed;
            if (self.header_bytes > self.options.max_header_bytes) {
                return error.HeaderTooLong;
            }

            const colon = std.mem.indexOfScalar(u8, line, ':') orelse
                return error.MalformedHeader;
            const name = line[0..colon];
            if (!isFieldNameValid(name)) return error.MalformedHeader;
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (!isFieldValueValid(value)) return error.MalformedHeader;

            if (RequestDecoder.isForbiddenTrailer(name)) {
                try cumulation.skip(consumed);
                continue;
            }
            if (response.headers.len() >= self.options.max_header_count) {
                return error.TooManyHeaders;
            }
            try response.headers.append(
                arena,
                try arena.dupe(u8, name),
                try arena.dupe(u8, value),
            );
            try cumulation.skip(consumed);
        }
    }

    fn emit(self: *ResponseDecoder, ctx: *HandlerContext) CodecError!?Message {
        assert(self.pending != null);
        var response = self.pending.?;
        response.body = self.body.items;

        self.pending = null;
        self.body = .empty;
        self.reset();

        return try Message.initAny(ctx.gpa(), IncomingResponse, response);
    }
};

/// Installs the client codec: request encoder and response decoder, wired to a
/// shared `MethodTracker`.
///
/// ## Which task may send
///
/// The encoder runs wherever `write` is called from, and a pipeline is not safe
/// to drive from two tasks at once, so `ctx.write` and `Pipeline.write` belong to
/// the connection's own task — `onActive` for the first request, or a handler
/// reacting to an event.
///
/// From any other task, use `Channel.submitWrite`, which queues the request for
/// the reader task and so still runs it through this encoder. That needs
/// `task_capacity` set when the channel is created; see `Channel.Task`.
/// `Channel.write` remains available for bytes that are already encoded, and
/// bypasses the pipeline by design.
///
/// This is where Netty's `writeAndFlush` hops to the event loop thread. Zinet
/// makes the hop explicit rather than automatic, because the queue it travels
/// through is bounded and a caller has to be told when it is full.
pub fn addClientCodec(
    pipeline: *Pipeline,
    tracker: *MethodTracker,
    options: struct {
        decoder: ResponseDecoder.Options = .{},
        encoder: RequestEncoder.Options = .{},
    },
) !void {
    const decoder = try ResponseDecoder.addTo(pipeline, options.decoder);
    decoder.tracker = tracker;
    const encoder = try RequestEncoder.addTo(pipeline, options.encoder);
    encoder.tracker = tracker;
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "Method: known verbs parse to their tags, others keep their spelling" {
    const get: Method = .get;
    const head: Method = .head;
    const post: Method = .post;
    const delete: Method = .delete;

    try testing.expectEqual(get, Method.parse("GET"));
    try testing.expectEqual(delete, Method.parse("DELETE"));
    try testing.expectEqualStrings("PROPFIND", Method.parse("PROPFIND").other);
    try testing.expectEqualStrings("GET", get.name());
    try testing.expect(!head.allowsResponseBody());
    try testing.expect(post.allowsResponseBody());
}

test "Version: parsing and keep-alive defaults" {
    try testing.expectEqual(Version.http_1_1, Version.parse("HTTP/1.1").?);
    try testing.expectEqual(Version.http_1_0, Version.parse("HTTP/1.0").?);
    try testing.expect(Version.parse("HTTP/2") == null);
    try testing.expect(Version.http_1_1.keepAliveByDefault());
    try testing.expect(!Version.http_1_0.keepAliveByDefault());
}

test "Headers: lookup ignores case and token lists are split" {
    const gpa = testing.allocator;
    var headers: Headers = .{};
    defer headers.deinit(gpa);

    try headers.append(gpa, "Content-Type", "text/plain");
    try headers.append(gpa, "Connection", "keep-alive, Upgrade");
    try headers.append(gpa, "Set-Cookie", "a=1");
    try headers.append(gpa, "Set-Cookie", "b=2");

    try testing.expectEqualStrings("text/plain", headers.get("content-type").?);
    try testing.expect(headers.has("CONNECTION"));
    try testing.expect(!headers.has("missing"));
    try testing.expect(headers.hasToken("connection", "upgrade"));
    try testing.expect(headers.hasToken("connection", "KEEP-ALIVE"));
    try testing.expect(!headers.hasToken("connection", "close"));

    // Duplicates are preserved in order.
    try testing.expectEqual(@as(usize, 4), headers.len());
    try testing.expectEqualStrings("a=1", headers.get("set-cookie").?);
}

test "Request: target splits into path and query" {
    const gpa = testing.allocator;
    var request: Request = .init(gpa);
    defer request.deinit(gpa);

    request.target = "/search?q=zig&page=2";
    try testing.expectEqualStrings("/search", request.path());
    try testing.expectEqualStrings("q=zig&page=2", request.query().?);

    request.target = "/plain";
    try testing.expectEqualStrings("/plain", request.path());
    try testing.expect(request.query() == null);
}

test "Request: upgrade detection needs both headers" {
    const gpa = testing.allocator;
    var request: Request = .init(gpa);
    defer request.deinit(gpa);
    const arena = request.allocator();

    try request.headers.append(arena, "Upgrade", "websocket");
    try testing.expect(!request.isUpgrade("websocket")); // No Connection header.

    try request.headers.append(arena, "Connection", "Upgrade");
    try testing.expect(request.isUpgrade("websocket"));
    try testing.expect(!request.isUpgrade("h2c"));
}

test "Status: codes, phrases and body rules" {
    try testing.expectEqual(@as(u16, 404), Status.not_found.code());
    try testing.expectEqualStrings("Not Found", Status.not_found.phrase());
    try testing.expect(Status.ok.allowsBody());
    try testing.expect(!Status.no_content.allowsBody());
    try testing.expect(!Status.switching_protocols.allowsBody());

    const custom: Status = @enumFromInt(599);
    try testing.expectEqual(@as(u16, 599), custom.code());
    try testing.expectEqualStrings("Unknown", custom.phrase());
}

// -- Request decoder tests -------------------------------------------------

const test_support = @import("test_support.zig");

/// Collects decoded requests so tests can assert on them.
const RequestCollector = struct {
    gpa: Allocator,
    requests: std.ArrayList(*Request) = .empty,
    errors: std.ArrayList(anyerror) = .empty,

    pub fn onRead(
        self: *RequestCollector,
        ctx: *HandlerContext,
        msg: Message,
    ) pipeline_mod.Error!void {
        var owned = msg;
        if (owned.get(Request) == null) {
            owned.deinit(ctx.gpa());
            return;
        }
        // Keep the request alive for the test by re-boxing it on the heap.
        const boxed = try self.gpa.create(Request);
        boxed.* = owned.take(ctx.gpa(), Request).?;
        try self.requests.append(self.gpa, boxed);
    }

    pub fn onError(self: *RequestCollector, _: *HandlerContext, err: anyerror) void {
        self.errors.append(self.gpa, err) catch {};
    }

    fn deinit(self: *RequestCollector) void {
        for (self.requests.items) |request| {
            request.deinit(self.gpa);
            self.gpa.destroy(request);
        }
        self.requests.deinit(self.gpa);
        self.errors.deinit(self.gpa);
    }
};

/// A pipeline of `RequestDecoder` followed by a `RequestCollector`.
const DecoderHarness = struct {
    fixture: test_support.Fixture,
    collector: *RequestCollector,

    fn init(gpa: Allocator, options: RequestDecoder.Options) !DecoderHarness {
        var fixture = try test_support.Fixture.init(gpa);
        errdefer fixture.deinit();

        _ = try RequestDecoder.addTo(fixture.pipeline, options);

        const collector = try gpa.create(RequestCollector);
        collector.* = .{ .gpa = gpa };
        errdefer gpa.destroy(collector);
        _ = try fixture.pipeline.addLast("collector", .init(collector));

        return .{ .fixture = fixture, .collector = collector };
    }

    fn deinit(harness: *DecoderHarness) void {
        const gpa = harness.fixture.gpa;
        harness.fixture.deinit();
        harness.collector.deinit();
        gpa.destroy(harness.collector);
    }

    fn feed(harness: *DecoderHarness, bytes: []const u8) !void {
        harness.fixture.pipeline.fireRead(
            try Message.initBytes(harness.fixture.gpa, bytes),
        );
    }

    fn requests(harness: *const DecoderHarness) []const *Request {
        return harness.collector.requests.items;
    }

    fn errors(harness: *const DecoderHarness) []const anyerror {
        return harness.collector.errors.items;
    }
};

test "RequestDecoder: a minimal GET request" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    try harness.feed("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n");

    try testing.expectEqual(@as(usize, 1), harness.requests().len);
    const request = harness.requests()[0];
    try testing.expectEqual(@as(Method, .get), request.method);
    try testing.expectEqualStrings("/index.html", request.target);
    try testing.expectEqual(Version.http_1_1, request.version);
    try testing.expectEqualStrings("example.com", request.headers.get("host").?);
    try testing.expectEqualStrings("", request.body);
    try testing.expect(request.keep_alive);
}

test "RequestDecoder: a POST with Content-Length" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    try harness.feed(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 11\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "hello world",
    );

    try testing.expectEqual(@as(usize, 1), harness.requests().len);
    const request = harness.requests()[0];
    try testing.expectEqual(@as(Method, .post), request.method);
    try testing.expectEqualStrings("hello world", request.body);
    try testing.expectEqualStrings("text/plain", request.headers.get("content-type").?);
}

test "RequestDecoder: a request split byte by byte decodes once complete" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    const wire = "POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
    for (wire, 0..) |byte, index| {
        try harness.feed(&.{byte});
        const expected: usize = if (index + 1 == wire.len) 1 else 0;
        try testing.expectEqual(expected, harness.requests().len);
    }
    try testing.expectEqualStrings("body", harness.requests()[0].body);
}

test "RequestDecoder: pipelined requests all decode from one read" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    try harness.feed(
        "GET /one HTTP/1.1\r\nHost: a\r\n\r\n" ++
            "GET /two HTTP/1.1\r\nHost: b\r\n\r\n" ++
            "POST /three HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi",
    );

    try testing.expectEqual(@as(usize, 3), harness.requests().len);
    try testing.expectEqualStrings("/one", harness.requests()[0].target);
    try testing.expectEqualStrings("/two", harness.requests()[1].target);
    try testing.expectEqualStrings("/three", harness.requests()[2].target);
    try testing.expectEqualStrings("hi", harness.requests()[2].body);
}

test "RequestDecoder: chunked bodies are reassembled, trailers included" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    try harness.feed(
        "POST /upload HTTP/1.1\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "5\r\nhello\r\n" ++
            "1;ext=1\r\n \r\n" ++ // A chunk extension is ignored.
            "5\r\nworld\r\n" ++
            "0\r\n" ++
            "X-Checksum: abc\r\n" ++
            "\r\n",
    );

    try testing.expectEqual(@as(usize, 1), harness.requests().len);
    const request = harness.requests()[0];
    try testing.expectEqualStrings("hello world", request.body);
    try testing.expectEqualStrings("abc", request.headers.get("x-checksum").?);
}

test "RequestDecoder: keep-alive follows the version and the Connection header" {
    const gpa = testing.allocator;

    {
        var harness = try DecoderHarness.init(gpa, .{});
        defer harness.deinit();
        try harness.feed("GET / HTTP/1.0\r\nHost: a\r\n\r\n");
        try testing.expect(!harness.requests()[0].keep_alive);
    }
    {
        var harness = try DecoderHarness.init(gpa, .{});
        defer harness.deinit();
        try harness.feed("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        try testing.expect(harness.requests()[0].keep_alive);
    }
    {
        var harness = try DecoderHarness.init(gpa, .{});
        defer harness.deinit();
        try harness.feed("GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
        try testing.expect(!harness.requests()[0].keep_alive);
    }
}

test "RequestDecoder: request smuggling vectors are rejected" {
    const gpa = testing.allocator;

    const vectors = [_]struct { wire: []const u8, want: anyerror }{
        // Content-Length together with Transfer-Encoding.
        .{
            .wire = "POST / HTTP/1.1\r\nContent-Length: 6\r\n" ++
                "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            .want = error.ConflictingFraming,
        },
        // Two disagreeing Content-Length headers.
        .{
            .wire = "POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
            .want = error.ConflictingFraming,
        },
        // A Transfer-Encoding this decoder will not interpret.
        .{
            .wire = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
            .want = error.UnsupportedTransferEncoding,
        },
        // Obsolete line folding.
        .{
            .wire = "GET / HTTP/1.1\r\nHost: a\r\n  continued\r\n\r\n",
            .want = error.ObsoleteLineFolding,
        },
        // Whitespace before the colon.
        .{
            .wire = "GET / HTTP/1.1\r\nHost : a\r\n\r\n",
            .want = error.MalformedHeader,
        },
        // A non-numeric Content-Length.
        .{
            .wire = "POST / HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n",
            .want = error.MalformedContentLength,
        },
        // A malformed chunk size.
        .{
            .wire = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            .want = error.MalformedChunkSize,
        },
    };

    for (vectors) |vector| {
        var harness = try DecoderHarness.init(gpa, .{});
        defer harness.deinit();

        try harness.feed(vector.wire);
        try testing.expectEqual(@as(usize, 0), harness.requests().len);
        try testing.expectEqual(@as(usize, 1), harness.errors().len);
        try testing.expectEqual(vector.want, harness.errors()[0]);
    }
}

test "RequestDecoder: malformed request lines are rejected" {
    const gpa = testing.allocator;

    const vectors = [_]struct { wire: []const u8, want: anyerror }{
        .{ .wire = "GET\r\n\r\n", .want = error.MalformedRequestLine },
        .{ .wire = "GET /\r\n\r\n", .want = error.MalformedRequestLine },
        .{ .wire = "GET / HTTP/1.1 extra\r\n\r\n", .want = error.MalformedRequestLine },
        .{ .wire = "GET / HTTP/2\r\n\r\n", .want = error.UnsupportedHttpVersion },
    };

    for (vectors) |vector| {
        var harness = try DecoderHarness.init(gpa, .{});
        defer harness.deinit();
        try harness.feed(vector.wire);
        try testing.expectEqual(vector.want, harness.errors()[0]);
    }
}

test "RequestDecoder: limits on the request line, headers and body" {
    const gpa = testing.allocator;

    {
        var harness = try DecoderHarness.init(gpa, .{ .max_request_line = 32 });
        defer harness.deinit();
        try harness.feed("GET /" ++ ("x" ** 64) ++ " HTTP/1.1\r\n");
        try testing.expectEqual(@as(anyerror, error.HeaderTooLong), harness.errors()[0]);
    }
    {
        var harness = try DecoderHarness.init(gpa, .{ .max_header_count = 2 });
        defer harness.deinit();
        try harness.feed("GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n");
        try testing.expectEqual(@as(anyerror, error.TooManyHeaders), harness.errors()[0]);
    }
    {
        var harness = try DecoderHarness.init(gpa, .{ .max_body_length = 8 });
        defer harness.deinit();
        try harness.feed("POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n");
        try testing.expectEqual(@as(anyerror, error.BodyTooLarge), harness.errors()[0]);
    }
    {
        var harness = try DecoderHarness.init(gpa, .{ .max_body_length = 8 });
        defer harness.deinit();
        try harness.feed(
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFF\r\n",
        );
        try testing.expectEqual(@as(anyerror, error.BodyTooLarge), harness.errors()[0]);
    }
}

test "RequestDecoder: a half-received request at end of stream leaks nothing" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    try harness.feed("POST /partial HTTP/1.1\r\nContent-Length: 100\r\n\r\nonly-some");
    harness.fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 0), harness.requests().len);
    try testing.expectEqual(@as(anyerror, error.IncompleteMessage), harness.errors()[0]);
}

test "RequestDecoder: randomly split requests decode identically" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x4444);
    const random = prng.random();

    const wire = "GET /a HTTP/1.1\r\nHost: h\r\n\r\n" ++
        "POST /b HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello" ++
        "POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";

    for (0..32) |_| {
        var harness = try DecoderHarness.init(gpa, .{});
        defer harness.deinit();

        var offset: usize = 0;
        while (offset < wire.len) {
            const chunk_len = random.intRangeAtMost(usize, 1, wire.len - offset);
            try harness.feed(wire[offset..][0..chunk_len]);
            offset += chunk_len;
        }

        try testing.expectEqual(@as(usize, 0), harness.errors().len);
        try testing.expectEqual(@as(usize, 3), harness.requests().len);
        try testing.expectEqualStrings("", harness.requests()[0].body);
        try testing.expectEqualStrings("hello", harness.requests()[1].body);
        try testing.expectEqualStrings("abc", harness.requests()[2].body);
    }
}

// -- Response encoder tests ------------------------------------------------

/// A pipeline with only the response encoder, so writes land in the sink.
fn encoderFixture(gpa: Allocator) !test_support.Fixture {
    var fixture = try test_support.Fixture.init(gpa);
    errdefer fixture.deinit();
    _ = try ResponseEncoder.addTo(fixture.pipeline, .{ .server_name = "" });
    return fixture;
}

test "ResponseEncoder: a response with a body gets Content-Length" {
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    const response: Response = .{
        .status = .ok,
        .body = "hello",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    };

    try fixture.pipeline.write(try Message.initAny(gpa, Response, response));

    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n" ++
            "hello",
        fixture.written(),
    );
}

test "ResponseEncoder: keep_alive drives the Connection header" {
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    const response: Response = .{ .status = .not_found, .keep_alive = false };
    try fixture.pipeline.write(try Message.initAny(gpa, Response, response));

    try testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        fixture.written(),
    );
}

test "ResponseEncoder: framing headers supplied by the caller are ignored" {
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    // A caller must not be able to contradict the real framing.
    const response: Response = .{
        .body = "abc",
        .headers = &.{
            .{ .name = "Content-Length", .value = "999" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
            .{ .name = "Connection", .value = "close" },
            .{ .name = "X-Keep", .value = "yes" },
        },
    };

    try fixture.pipeline.write(try Message.initAny(gpa, Response, response));

    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "X-Keep: yes\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Content-Length: 3\r\n" ++
            "\r\n" ++
            "abc",
        fixture.written(),
    );
}

test "ResponseEncoder: a bodyless status carries no framing header" {
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    const response: Response = .{ .status = .no_content, .body = "ignored" };
    try fixture.pipeline.write(try Message.initAny(gpa, Response, response));

    try testing.expectEqualStrings(
        "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n",
        fixture.written(),
    );
}

test "ResponseEncoder: a chunked response with a known body is self-terminating" {
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    const response: Response = .{ .body = "hello world", .chunked = true };
    try fixture.pipeline.write(try Message.initAny(gpa, Response, response));

    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "b\r\nhello world\r\n" ++
            "0\r\n\r\n",
        fixture.written(),
    );
}

test "ResponseEncoder: a streamed body is sent as separate chunks" {
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    const head: Response = .{ .chunked = true };
    try fixture.pipeline.write(try Message.initAny(gpa, Response, head));
    fixture.clearWritten();

    try fixture.pipeline.write(try Message.initAny(gpa, Chunk, .{ .data = "part one " }));
    try fixture.pipeline.write(try Message.initAny(gpa, Chunk, .{ .data = "part two" }));
    try fixture.pipeline.write(try Message.initAny(gpa, Chunk, .{ .last = true }));

    try testing.expectEqualStrings(
        "9\r\npart one \r\n" ++
            "8\r\npart two\r\n" ++
            "0\r\n\r\n",
        fixture.written(),
    );
}

test "ResponseEncoder: raw byte writes pass through" {
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    try fixture.pipeline.write(try Message.initBytes(gpa, "opaque bytes"));
    try testing.expectEqualStrings("opaque bytes", fixture.written());
}

test "ResponseEncoder: the Server header is added unless overridden" {
    const gpa = testing.allocator;

    {
        var fixture = try test_support.Fixture.init(gpa);
        defer fixture.deinit();
        _ = try ResponseEncoder.addTo(fixture.pipeline, .{});
        const response: Response = .{};
        try fixture.pipeline.write(try Message.initAny(gpa, Response, response));
        try testing.expect(std.mem.indexOf(u8, fixture.written(), "Server: zinet\r\n") != null);
    }
    {
        var fixture = try test_support.Fixture.init(gpa);
        defer fixture.deinit();
        _ = try ResponseEncoder.addTo(fixture.pipeline, .{});
        const response: Response = .{
            .headers = &.{.{ .name = "Server", .value = "custom" }},
        };
        try fixture.pipeline.write(try Message.initAny(gpa, Response, response));
        try testing.expect(std.mem.indexOf(u8, fixture.written(), "Server: custom") != null);
        try testing.expect(std.mem.indexOf(u8, fixture.written(), "Server: zinet") == null);
    }
}

test "http: a response encoded by Zinet is decodable as a request line shape" {
    // Round-trip sanity: the encoder's output parses as HTTP, checked by
    // splitting the head and confirming every line ends with CRLF.
    const gpa = testing.allocator;
    var fixture = try encoderFixture(gpa);
    defer fixture.deinit();

    const response: Response = .{
        .body = "payload",
        .headers = &.{
            .{ .name = "X-A", .value = "1" },
            .{ .name = "X-B", .value = "2" },
        },
    };
    try fixture.pipeline.write(try Message.initAny(gpa, Response, response));

    const wire = fixture.written();
    const split = std.mem.indexOf(u8, wire, "\r\n\r\n").?;
    const head = wire[0..split];
    try testing.expectEqualStrings("payload", wire[split + 4 ..]);

    var lines = std.mem.splitSequence(u8, head, "\r\n");
    var count: usize = 0;
    while (lines.next()) |line| {
        try testing.expect(line.len > 0);
        count += 1;
    }
    // Status line, two custom headers, Connection, Content-Length.
    try testing.expectEqual(@as(usize, 5), count);
}

test "RequestDecoder: a malformed request is reported once, not once per read" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    // HTTP/1 framing cannot be resynchronized, so the decoder must write the
    // connection off after the first failure. A peer that sends one bad line
    // and then dribbles bytes would otherwise trigger an error per read.
    try harness.feed("not a request line\r\n");
    try testing.expectEqual(@as(usize, 1), harness.errors().len);
    try testing.expectEqual(@as(anyerror, error.MalformedRequestLine), harness.errors()[0]);

    for (0..16) |_| try harness.feed("x");
    try harness.feed("GET / HTTP/1.1\r\nHost: h\r\n\r\n");

    try testing.expectEqual(@as(usize, 1), harness.errors().len);
    // Nothing is parsed after the failure either: trusting the stream again
    // would mean guessing where a message starts.
    try testing.expectEqual(@as(usize, 0), harness.requests().len);
}

test "RequestDecoder: ending a stream after a malformed request adds no further error" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    try harness.feed("GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n");
    try testing.expectEqual(@as(usize, 1), harness.errors().len);

    harness.fixture.pipeline.fireInactive();
    try testing.expectEqual(@as(usize, 1), harness.errors().len);
}

test "ResponseEncoder: a header value cannot forge response framing" {
    const gpa = testing.allocator;
    var fixture = try test_support.Fixture.init(gpa);
    defer fixture.deinit();
    _ = try ResponseEncoder.addTo(fixture.pipeline, .{ .server_name = "" });

    // The classic response-splitting payload: an application echoes something
    // it was sent into a header, and the peer supplies line endings plus a
    // response of its own.
    const injected = [_]Header{.{
        .name = "X-Echo",
        .value = "ok\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nowned",
    }};
    try testing.expectError(error.InvalidHeader, fixture.pipeline.write(
        try Message.initAny(gpa, Response, .{
            .status = .ok,
            .headers = &injected,
            .body = "hi",
        }),
    ));
    // Nothing at all was emitted: a partially written response would be just as
    // exploitable as the whole one.
    try testing.expectEqual(@as(usize, 0), fixture.written().len);

    // A bare CR, a NUL and a newline in the name are refused too.
    const vectors = [_]Header{
        .{ .name = "X-A", .value = "a\rb" },
        .{ .name = "X-B", .value = "a\x00b" },
        .{ .name = "X\nY", .value = "fine" },
        .{ .name = "X Y", .value = "fine" },
        .{ .name = "X:Y", .value = "fine" },
        .{ .name = "", .value = "fine" },
    };
    for (vectors) |vector| {
        const one = [_]Header{vector};
        try testing.expectError(error.InvalidHeader, fixture.pipeline.write(
            try Message.initAny(gpa, Response, .{ .headers = &one, .body = "" }),
        ));
    }

    // A legitimate value with a tab is still accepted: the rule is "no control
    // characters", not "no whitespace".
    const fine = [_]Header{.{ .name = "X-Tabbed", .value = "a\tb" }};
    try fixture.pipeline.write(
        try Message.initAny(gpa, Response, .{ .headers = &fine, .body = "" }),
    );
    try testing.expect(std.mem.indexOf(u8, fixture.written(), "X-Tabbed: a\tb\r\n") != null);
}

test "RequestDecoder: a control character in a header is rejected" {
    const vectors = [_][]const u8{
        // Bare CR inside a value: an intermediary that treats CR alone as a
        // line ending sees a different message than this parser does.
        "GET / HTTP/1.1\r\nX-A: a\rb\r\n\r\n",
        "GET / HTTP/1.1\r\nX-A: a\x00b\r\n\r\n",
        // Names that are not tokens.
        "GET / HTTP/1.1\r\nX\x01Y: v\r\n\r\n",
        "GET / HTTP/1.1\r\nX(Y): v\r\n\r\n",
    };

    for (vectors) |vector| {
        var harness = try DecoderHarness.init(testing.allocator, .{});
        defer harness.deinit();

        try harness.feed(vector);
        try testing.expectEqual(@as(usize, 0), harness.requests().len);
        try testing.expectEqual(@as(usize, 1), harness.errors().len);
        try testing.expectEqual(@as(anyerror, error.MalformedHeader), harness.errors()[0]);
    }
}

test "RequestDecoder: a trailer cannot introduce framing or routing headers" {
    var harness = try DecoderHarness.init(testing.allocator, .{});
    defer harness.deinit();

    // The trailer tries to add a Host and a second Content-Length after the
    // body has already been framed, plus one field that is legitimate there.
    try harness.feed(
        "POST /x HTTP/1.1\r\nHost: real\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "3\r\nabc\r\n" ++
            "0\r\nHost: forged\r\nContent-Length: 99\r\nX-Checksum: ok\r\n\r\n",
    );

    try testing.expectEqual(@as(usize, 0), harness.errors().len);
    try testing.expectEqual(@as(usize, 1), harness.requests().len);
    const request = harness.requests()[0];
    try testing.expectEqualStrings("abc", request.body);
    // The forged fields were dropped; the real Host still stands.
    try testing.expectEqualStrings("real", request.headers.get("host").?);
    try testing.expect(request.headers.get("content-length") == null);
    // A trailer that carries no framing meaning is kept.
    try testing.expectEqualStrings("ok", request.headers.get("x-checksum").?);
}

// -- Client codec ----------------------------------------------------------

/// Captures decoded responses so tests can assert on their contents.
const ResponseCollector = struct {
    gpa: Allocator,
    items: std.ArrayList(IncomingResponse) = .empty,
    errors: std.ArrayList(anyerror) = .empty,

    pub const handler_name = "response-collector";

    pub fn onRead(
        self: *ResponseCollector,
        ctx: *HandlerContext,
        msg: Message,
    ) CodecError!void {
        var owned = msg;
        if (owned.take(ctx.gpa(), IncomingResponse)) |response| {
            try self.items.append(self.gpa, response);
            return;
        }
        owned.deinit(ctx.gpa());
    }

    pub fn onError(self: *ResponseCollector, _: *HandlerContext, err: anyerror) void {
        self.errors.append(self.gpa, err) catch {};
    }

    pub fn deinit(self: *ResponseCollector, gpa: Allocator) void {
        for (self.items.items) |*response| response.deinit(gpa);
        self.items.deinit(gpa);
        self.errors.deinit(gpa);
    }
};

/// A pipeline with the client codec and a response collector at the tail.
const ClientFixture = struct {
    fixture: test_support.Fixture,
    tracker: *MethodTracker,
    collected: *ResponseCollector,

    fn init(gpa: Allocator, options: ResponseDecoder.Options) !ClientFixture {
        var fixture = try test_support.Fixture.init(gpa);
        errdefer fixture.deinit();

        const tracker = try gpa.create(MethodTracker);
        tracker.* = .{};
        errdefer gpa.destroy(tracker);

        try addClientCodec(fixture.pipeline, tracker, .{ .decoder = options });

        const collected = try gpa.create(ResponseCollector);
        collected.* = .{ .gpa = gpa };
        errdefer gpa.destroy(collected);
        _ = try fixture.pipeline.addLast("collected", .init(collected));

        return .{ .fixture = fixture, .tracker = tracker, .collected = collected };
    }

    fn deinit(self: *ClientFixture) void {
        const gpa = self.fixture.gpa;
        self.fixture.deinit();
        self.collected.deinit(gpa);
        gpa.destroy(self.collected);
        gpa.destroy(self.tracker);
    }

    fn feed(self: *ClientFixture, bytes: []const u8) !void {
        self.fixture.pipeline.fireRead(try Message.initBytes(self.fixture.gpa, bytes));
    }

    fn send(self: *ClientFixture, request: OutgoingRequest) !void {
        try self.fixture.pipeline.write(
            try Message.initAny(self.fixture.gpa, OutgoingRequest, request),
        );
    }

    fn items(self: *const ClientFixture) []const IncomingResponse {
        return self.collected.items.items;
    }

    fn errors(self: *const ClientFixture) []const anyerror {
        return self.collected.errors.items;
    }
};

test "ResponseDecoder: a Content-Length response" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.feed(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
    );

    try testing.expectEqual(@as(usize, 1), client.items().len);
    const response = &client.items()[0];
    try testing.expectEqual(@as(u16, 200), response.status.code());
    try testing.expectEqualStrings("OK", response.reason);
    try testing.expectEqualStrings("hello", response.body);
    try testing.expectEqualStrings("text/plain", response.headers.get("content-type").?);
    try testing.expect(response.keep_alive);
    try testing.expect(response.isSuccess());
}

test "ResponseDecoder: a chunked response with a trailer" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "5\r\nhello\r\n2\r\n, \r\n5\r\nworld\r\n0\r\nX-Sum: 7\r\n\r\n");

    try testing.expectEqual(@as(usize, 1), client.items().len);
    try testing.expectEqualStrings("hello, world", client.items()[0].body);
    try testing.expectEqualStrings("7", client.items()[0].headers.get("x-sum").?);
}

test "ResponseDecoder: a body with no framing header runs until the close" {
    // The rule requests do not have (RFC 9112 §6.3). A decoder that waits for a
    // complete frame would hang on this forever.
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.feed("HTTP/1.0 200 OK\r\n\r\nsome body bytes");
    // Nothing yet: only the close ends the body.
    try testing.expectEqual(@as(usize, 0), client.items().len);

    try client.feed(" and more");
    try testing.expectEqual(@as(usize, 0), client.items().len);

    client.fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 0), client.errors().len);
    try testing.expectEqual(@as(usize, 1), client.items().len);
    try testing.expectEqualStrings("some body bytes and more", client.items()[0].body);
    // The connection is gone, so keep-alive is not on offer.
    try testing.expect(!client.items()[0].keep_alive);
}

test "ResponseDecoder: an empty until-close body is still delivered" {
    // The case that made the base class always call `decodeLast`: there are no
    // leftover bytes to notice at end of stream, only a held response.
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.feed("HTTP/1.0 204 No Content\r\n\r\n");
    // 204 has no body at all, so it lands immediately rather than waiting.
    try testing.expectEqual(@as(usize, 1), client.items().len);

    try client.feed("HTTP/1.0 200 OK\r\nX-A: b\r\n\r\n");
    try testing.expectEqual(@as(usize, 1), client.items().len);
    client.fixture.pipeline.fireInactive();

    try testing.expectEqual(@as(usize, 2), client.items().len);
    try testing.expectEqualStrings("", client.items()[1].body);
}

test "ResponseDecoder: a HEAD response ignores Content-Length" {
    // Believing the length here is a desync: the server sent no body, so those
    // bytes are the next response. Getting this wrong is how a client ends up
    // reading a response into the previous one's body.
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.send(.{ .method = .head, .target = "/thing", .host = "example" });
    try client.feed("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");

    try testing.expectEqual(@as(usize, 2), client.items().len);
    try testing.expectEqualStrings("", client.items()[0].body);
    try testing.expectEqualStrings("hi", client.items()[1].body);
}

test "ResponseDecoder: 204 and 304 carry no body whatever the headers say" {
    for ([_][]const u8{ "204 No Content", "304 Not Modified" }) |status| {
        var client = try ClientFixture.init(testing.allocator, .{});
        defer client.deinit();

        var line: [128]u8 = undefined;
        const head = try std.fmt.bufPrint(
            &line,
            "HTTP/1.1 {s}\r\nContent-Length: 3\r\n\r\n",
            .{status},
        );
        try client.feed(head);
        // The next response's bytes must not be eaten as a body.
        try client.feed("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

        try testing.expectEqual(@as(usize, 2), client.items().len);
        try testing.expectEqualStrings("", client.items()[0].body);
        try testing.expectEqualStrings("ok", client.items()[1].body);
    }
}

test "ResponseDecoder: an informational response does not consume the exchange" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.send(.{ .method = .head, .target = "/", .host = "h" });
    try testing.expectEqual(@as(usize, 1), client.tracker.count());

    // A 100 Continue arrives first; the HEAD is still outstanding.
    try client.feed("HTTP/1.1 100 Continue\r\n\r\n");
    try testing.expectEqual(@as(usize, 1), client.tracker.count());

    // So the final response is still framed as a HEAD's: no body.
    try client.feed("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n");
    try testing.expectEqual(@as(usize, 0), client.tracker.count());
    try testing.expectEqual(@as(usize, 2), client.items().len);
    try testing.expectEqualStrings("", client.items()[1].body);
}

test "ResponseDecoder: pipelined responses are matched to their methods in order" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.send(.{ .method = .get, .target = "/a", .host = "h" });
    try client.send(.{ .method = .head, .target = "/b", .host = "h" });
    try client.send(.{ .method = .get, .target = "/c", .host = "h" });

    try client.feed("HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA" ++
        "HTTP/1.1 200 OK\r\nContent-Length: 77\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nC");

    try testing.expectEqual(@as(usize, 3), client.items().len);
    try testing.expectEqualStrings("A", client.items()[0].body);
    try testing.expectEqualStrings("", client.items()[1].body); // HEAD
    try testing.expectEqualStrings("C", client.items()[2].body);
}

test "ResponseDecoder: conflicting framing is refused" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.feed("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\nhello");

    try testing.expectEqual(@as(usize, 0), client.items().len);
    try testing.expectEqual(@as(usize, 1), client.errors().len);
    try testing.expectEqual(@as(anyerror, error.ConflictingFraming), client.errors()[0]);
}

test "ResponseDecoder: a malformed status line is reported once, not once per read" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.feed("NOT HTTP AT ALL\r\n");
    try testing.expectEqual(@as(usize, 1), client.errors().len);

    // The fatal-error latch means later bytes are discarded rather than
    // re-parsed into the same error again.
    for (0..5) |_| try client.feed("more rubbish\r\n");
    try testing.expectEqual(@as(usize, 1), client.errors().len);
}

test "ResponseDecoder: chunk independence over a byte-at-a-time delivery" {
    const stream = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "3\r\nabc\r\n0\r\n\r\n" ++
        "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";

    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    for (stream) |byte| try client.feed(&.{byte});

    try testing.expectEqual(@as(usize, 0), client.errors().len);
    try testing.expectEqual(@as(usize, 2), client.items().len);
    try testing.expectEqualStrings("abc", client.items()[0].body);
    try testing.expectEqual(@as(u16, 404), client.items()[1].status.code());
    try testing.expectEqualStrings("no", client.items()[1].body);
}

test "RequestEncoder: writes a request line, headers and framing" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.send(.{
        .method = .post,
        .target = "/submit?x=1",
        .host = "example.com",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .body = "hi",
    });

    try testing.expectEqualStrings(
        "POST /submit?x=1 HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "User-Agent: zinet\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Content-Length: 2\r\n" ++
            "\r\nhi",
        client.fixture.written(),
    );
}

test "RequestEncoder: a GET with no body sends no Content-Length" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.send(.{ .method = .get, .target = "/", .host = "h", .keep_alive = false });

    try testing.expectEqualStrings(
        "GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: zinet\r\nConnection: close\r\n\r\n",
        client.fixture.written(),
    );
}

test "RequestEncoder: a header value cannot forge a second request" {
    // The outbound mirror of response splitting: a client that echoes a
    // server-controlled value into a request header would otherwise let that
    // server inject a whole request of its own.
    const vectors = [_]OutgoingRequest{
        .{ .host = "h", .headers = &.{.{
            .name = "X-Echo",
            .value = "a\r\nGET /admin HTTP/1.1\r\nHost: h\r\n\r\n",
        }} },
        .{ .host = "h", .headers = &.{.{ .name = "X-A", .value = "bare\rcr" }} },
        .{ .host = "h", .headers = &.{.{ .name = "X\r\nY", .value = "v" }} },
        .{ .host = "h\r\nX-Injected: 1", .headers = &.{} },
    };

    for (vectors) |request| {
        var client = try ClientFixture.init(testing.allocator, .{});
        defer client.deinit();

        try testing.expectError(error.InvalidHeader, client.send(request));
        // Nothing at all reached the socket: a half-written request is as
        // exploitable as a whole one.
        try testing.expectEqualStrings("", client.fixture.written());
        // And a rejected request must not leave the decoder expecting a reply.
        try testing.expectEqual(@as(usize, 0), client.tracker.count());
    }
}

test "RequestEncoder: a target with a space or control byte is refused" {
    for ([_][]const u8{ "/a b", "/a\r\nb", "/a\x00b", "" }) |target| {
        var client = try ClientFixture.init(testing.allocator, .{});
        defer client.deinit();

        try testing.expectError(
            error.InvalidTarget,
            client.send(.{ .target = target, .host = "h" }),
        );
        try testing.expectEqualStrings("", client.fixture.written());
    }
}

test "RequestEncoder: a chunked request streams through Chunk messages" {
    var client = try ClientFixture.init(testing.allocator, .{});
    defer client.deinit();

    try client.send(.{ .method = .post, .target = "/s", .host = "h", .chunked = true });
    try client.fixture.pipeline.write(
        try Message.initAny(testing.allocator, Chunk, .{ .data = "one" }),
    );
    try client.fixture.pipeline.write(
        try Message.initAny(testing.allocator, Chunk, .{ .last = true }),
    );

    try testing.expectEqualStrings(
        "POST /s HTTP/1.1\r\nHost: h\r\nUser-Agent: zinet\r\n" ++
            "Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "3\r\none\r\n" ++
            "0\r\n\r\n",
        client.fixture.written(),
    );
}

test "MethodTracker: refuses to pipeline deeper than its bound" {
    var tracker: MethodTracker = .{};
    for (0..MethodTracker.max_pipelined) |_| try tracker.push(.get);
    try testing.expectError(error.TooManyPendingRequests, tracker.push(.get));

    // Draining makes room again, and order is preserved.
    try testing.expectEqual(Method.get, tracker.pop().?);
    try tracker.push(.head);
    for (0..MethodTracker.max_pipelined - 2) |_| _ = tracker.pop();
    try testing.expectEqual(Method.get, tracker.pop().?);
    try testing.expectEqual(Method.head, tracker.pop().?);
    try testing.expect(tracker.pop() == null);
}
