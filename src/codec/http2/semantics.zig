//! HTTP semantics over HTTP/2 framing: RFC 9113 §8.
//!
//! The framing layers below say nothing about HTTP. This is where a header list
//! becomes a request or a response, and where the rules that make that translation
//! safe are enforced.
//!
//! Two of those rules are security properties rather than tidiness, and they are the
//! reason this file exists separately from the codec that calls it:
//!
//! * **Connection-specific fields are forbidden** (§8.2.2). `Connection`,
//!   `Transfer-Encoding`, `Keep-Alive`, `Proxy-Connection` and `Upgrade` describe a
//!   single HTTP/1.1 hop, and HTTP/2 has no hops to describe. Letting one through a
//!   gateway that translates back to HTTP/1.1 is request smuggling: the gateway
//!   emits framing headers the HTTP/2 sender chose. The HTTP/1.1 decoder in this
//!   repository already refuses two sources of framing truth; this is the same
//!   argument arriving from the other direction.
//! * **Field names must be lowercase** (§8.2.1). Not a style rule: `Content-Length`
//!   and `content-length` compare unequal as bytes, so a peer that sends both is
//!   handing two different values to any component that matches case-sensitively.
//!
//! §8.1.1 makes every violation here a *stream* error of type `PROTOCOL_ERROR` —
//! the message is malformed, not the connection.

const std = @import("std");
const assert = std.debug.assert;

const hpack = @import("hpack.zig");

pub const Error = error{
    /// §8.1.1: the message cannot be translated to HTTP semantics. A stream error;
    /// the connection is fine and its other streams are unaffected.
    MalformedMessage,
};

/// The request pseudo-headers of §8.3.1.
pub const Request = struct {
    method: []const u8,
    /// Absent only for `CONNECT` (§8.5).
    scheme: ?[]const u8,
    path: ?[]const u8,
    authority: ?[]const u8,

    pub fn isConnect(request: Request) bool {
        return connectMethod(request.method);
    }
};

/// Whether a method names a tunnel (§8.5). One function so that the connection
/// layer, which sequences frames before anything is validated, and `Request`,
/// which sees a validated message, cannot disagree about what a CONNECT is.
pub fn connectMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "CONNECT");
}

/// Whether a decoded request field list is a CONNECT, from the raw fields. The
/// connection layer needs this before validation has happened: §8.5's rule is about
/// which *frames* may follow, so it has to be known while frames are being
/// sequenced.
pub fn isConnectRequest(fields: []const hpack.Field) bool {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, ":method")) return connectMethod(field.value);
    }
    return false;
}

/// Whether a decoded response field list carries a 2xx, which §8.5 makes the signal
/// that the tunnel is open. A refusal is an ordinary response and not a tunnel.
pub fn isSuccessResponse(fields: []const hpack.Field) bool {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, ":status")) {
            return field.value.len == 3 and field.value[0] == '2';
        }
    }
    return false;
}

/// The response pseudo-header of §8.3.2.
pub const Response = struct {
    status: u16,

    /// §8.1: an informational response is not the final one, so a client must keep
    /// reading rather than treating it as the answer.
    pub fn isInformational(response: Response) bool {
        return response.status >= 100 and response.status < 200;
    }
};

/// Fields no HTTP/2 message may carry (§8.2.2). `te` is handled separately, because
/// it is permitted with exactly one value.
const forbidden = [_][]const u8{
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
};

/// Checks the rules that apply to every field of every message.
fn validateField(field: hpack.Field) Error!void {
    if (field.name.len == 0) return error.MalformedMessage;

    for (field.name, 0..) |byte, index| {
        // §8.2.1: uppercase is malformed. Comparing bytes is the whole point — a
        // peer sending both spellings of a framing header would otherwise hand two
        // values to anything matching case-sensitively.
        if (byte >= 'A' and byte <= 'Z') return error.MalformedMessage;
        // A NUL or a newline in a field name is how a header injection starts.
        if (byte == 0 or byte == '\n' or byte == '\r' or byte == ' ') {
            return error.MalformedMessage;
        }
        // A colon is legal only as the first character, where it marks a
        // pseudo-header. Whether one is allowed at all is the caller's business.
        if (byte == ':' and index != 0) return error.MalformedMessage;
    }

    // §8.2.2, and the reason it is not merely tidiness: see the module comment.
    if (field.name[0] != ':') {
        for (forbidden) |name| {
            if (std.mem.eql(u8, field.name, name)) return error.MalformedMessage;
        }
        // §8.2.2: TE is allowed, but only to say "trailers".
        if (std.mem.eql(u8, field.name, "te") and !std.mem.eql(u8, field.value, "trailers")) {
            return error.MalformedMessage;
        }
    }

    for (field.value) |byte| {
        // §8.2.1: a NUL, CR or LF in a value is an injection attempt against
        // anything that serializes this back to HTTP/1.1.
        if (byte == 0 or byte == '\n' or byte == '\r') return error.MalformedMessage;
    }
    return;
}

/// True when `name` is a pseudo-header.
fn isPseudo(name: []const u8) bool {
    return name.len > 0 and name[0] == ':';
}

/// Walks the fields, applying the ordering rule of §8.3 and the per-field rules,
/// and hands each pseudo-header to `collect`.
fn walk(fields: []const hpack.Field, collect: anytype) Error!void {
    var regular_seen = false;
    for (fields) |field| {
        try validateField(field);
        if (isPseudo(field.name)) {
            // §8.3: pseudo-headers must all precede the regular fields, so that a
            // receiver knows the request line is complete before it starts on the
            // headers.
            if (regular_seen) return error.MalformedMessage;
            try collect.pseudo(field);
        } else {
            regular_seen = true;
        }
    }
}

/// Validates a request header list and extracts its pseudo-headers (§8.3.1).
pub fn validateRequest(fields: []const hpack.Field) Error!Request {
    var collector: struct {
        method: ?[]const u8 = null,
        scheme: ?[]const u8 = null,
        path: ?[]const u8 = null,
        authority: ?[]const u8 = null,

        fn pseudo(self: *@This(), field: hpack.Field) Error!void {
            // §8.3: a repeated pseudo-header is malformed, and so is one this
            // direction does not define — `:status` in a request, or anything
            // invented.
            const slot: *?[]const u8 =
                if (std.mem.eql(u8, field.name, ":method"))
                    &self.method
                else if (std.mem.eql(u8, field.name, ":scheme"))
                    &self.scheme
                else if (std.mem.eql(u8, field.name, ":path"))
                    &self.path
                else if (std.mem.eql(u8, field.name, ":authority"))
                    &self.authority
                else
                    return error.MalformedMessage;
            if (slot.* != null) return error.MalformedMessage;
            slot.* = field.value;
        }
    } = .{};

    try walk(fields, &collector);

    const method = collector.method orelse return error.MalformedMessage;
    if (method.len == 0) return error.MalformedMessage;

    // §8.5: CONNECT names an authority and nothing else. Any other method needs the
    // full triple.
    if (connectMethod(method)) {
        if (collector.scheme != null or collector.path != null) return error.MalformedMessage;
        if (collector.authority == null) return error.MalformedMessage;
        return .{
            .method = method,
            .scheme = null,
            .path = null,
            .authority = collector.authority,
        };
    }

    const scheme = collector.scheme orelse return error.MalformedMessage;
    const path = collector.path orelse return error.MalformedMessage;
    if (scheme.len == 0) return error.MalformedMessage;
    // §8.3.1: for http and https the path must not be empty, and OPTIONS may use
    // "*". Anything else with an empty path has no target.
    if (path.len == 0) return error.MalformedMessage;

    return .{
        .method = method,
        .scheme = scheme,
        .path = path,
        .authority = collector.authority,
    };
}

/// Validates a response header list and extracts `:status` (§8.3.2).
pub fn validateResponse(fields: []const hpack.Field) Error!Response {
    var collector: struct {
        status: ?[]const u8 = null,

        fn pseudo(self: *@This(), field: hpack.Field) Error!void {
            if (!std.mem.eql(u8, field.name, ":status")) return error.MalformedMessage;
            if (self.status != null) return error.MalformedMessage;
            self.status = field.value;
        }
    } = .{};

    try walk(fields, &collector);

    const text = collector.status orelse return error.MalformedMessage;
    // §8.3.2: exactly three digits. Accepting more would let "2000" or "20" through
    // to code that compares against 200.
    if (text.len != 3) return error.MalformedMessage;
    const status = std.fmt.parseInt(u16, text, 10) catch return error.MalformedMessage;
    if (status < 100) return error.MalformedMessage;
    return .{ .status = status };
}

/// Validates a trailer block (§8.1). Trailers carry no pseudo-headers: the request
/// or response line was settled by the first block, and a second `:status` would be
/// a second answer.
pub fn validateTrailers(fields: []const hpack.Field) Error!void {
    for (fields) |field| {
        try validateField(field);
        if (isPseudo(field.name)) return error.MalformedMessage;
    }
}

// -- Tests -----------------------------------------------------------------

const testing = std.testing;

test "semantics: a well-formed request" {
    const request = try validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "accept", .value = "*/*" },
    });
    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("https", request.scheme.?);
    try testing.expectEqualStrings("/index.html", request.path.?);
    try testing.expectEqualStrings("example.test", request.authority.?);
    try testing.expect(!request.isConnect());

    // §8.3.1: authority is the only optional one.
    const no_authority = try validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
    });
    try testing.expect(no_authority.authority == null);
}

test "semantics: §8.3.1 requires the triple, once each" {
    // Each of the three missing in turn.
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
    }));
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
    }));
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
    }));

    // Repeated, which would leave a receiver choosing between two request lines.
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
    }));

    // Empty, which is not the same as absent and is just as unusable.
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "" },
    }));

    // A pseudo-header from the other direction, or one simply invented.
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":status", .value = "200" },
    }));
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":invented", .value = "x" },
    }));
}

test "semantics: §8.3 pseudo-headers must all come first" {
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "accept", .value = "*/*" },
        // Too late: a receiver has already started on the headers.
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
    }));
}

test "semantics: §8.5 CONNECT names an authority and nothing else" {
    const request = try validateRequest(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    });
    try testing.expect(request.isConnect());
    try testing.expect(request.scheme == null and request.path == null);
    try testing.expectEqualStrings("example.test:443", request.authority.?);

    // A scheme or a path with CONNECT is malformed, and so is a missing authority.
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "x" },
        .{ .name = ":scheme", .value = "https" },
    }));
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "CONNECT" },
    }));
}

test "semantics: §8.2.2 forbids the fields that describe one HTTP/1.1 hop" {
    // Each of these, forwarded by a gateway translating back to HTTP/1.1, is
    // framing the HTTP/2 sender chose — which is what request smuggling is.
    for ([_][]const u8{
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    }) |name| {
        try testing.expectError(error.MalformedMessage, validateRequest(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/" },
            .{ .name = name, .value = "x" },
        }));
    }

    // TE survives, but only saying "trailers".
    _ = try validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "trailers" },
    });
    try testing.expectError(error.MalformedMessage, validateRequest(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "te", .value = "gzip" },
    }));
}

test "semantics: §8.2.1 rejects uppercase names and injected control bytes" {
    const base = [_]hpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
    };

    for ([_]hpack.Field{
        // Uppercase: `Content-Length` and `content-length` are unequal as bytes, so
        // a peer sending both hands two values to a case-sensitive matcher.
        .{ .name = "Content-Length", .value = "0" },
        .{ .name = "X-Odd", .value = "1" },
        // A colon anywhere but the front.
        .{ .name = "x:y", .value = "1" },
        // Control bytes in a name, and a space, which HTTP/1.1 would read as the
        // end of the name.
        .{ .name = "x y", .value = "1" },
        .{ .name = "x\ny", .value = "1" },
        .{ .name = "", .value = "1" },
        // Control bytes in a value, which is a header injection against anything
        // serializing this back to HTTP/1.1.
        .{ .name = "x", .value = "a\r\nevil: yes" },
        .{ .name = "x", .value = "a\x00b" },
    }) |bad| {
        var fields: [4]hpack.Field = undefined;
        @memcpy(fields[0..3], &base);
        fields[3] = bad;
        try testing.expectError(error.MalformedMessage, validateRequest(&fields));
    }
}

test "semantics: §8.3.2 wants exactly three digits" {
    try testing.expectEqual(@as(u16, 200), (try validateResponse(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    })).status);
    try testing.expect((try validateResponse(&.{
        .{ .name = ":status", .value = "100" },
    })).isInformational());

    // Two digits or four would otherwise reach code comparing against 200.
    for ([_][]const u8{ "20", "2000", "", "2 0", "abc", "099", "+20", "20\x00" }) |bad| {
        try testing.expectError(
            error.MalformedMessage,
            validateResponse(&.{.{ .name = ":status", .value = bad }}),
        );
    }

    // Missing, repeated, or a request pseudo-header in a response.
    try testing.expectError(error.MalformedMessage, validateResponse(&.{
        .{ .name = "content-type", .value = "text/plain" },
    }));
    try testing.expectError(error.MalformedMessage, validateResponse(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":status", .value = "404" },
    }));
    try testing.expectError(error.MalformedMessage, validateResponse(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = ":method", .value = "GET" },
    }));
}

test "semantics: trailers carry no pseudo-headers" {
    try validateTrailers(&.{
        .{ .name = "x-checksum", .value = "abc" },
        .{ .name = "grpc-status", .value = "0" },
    });
    // A second :status would be a second answer to the same request.
    try testing.expectError(error.MalformedMessage, validateTrailers(&.{
        .{ .name = ":status", .value = "200" },
    }));
    // The field rules still apply.
    try testing.expectError(error.MalformedMessage, validateTrailers(&.{
        .{ .name = "Connection", .value = "close" },
    }));
}
