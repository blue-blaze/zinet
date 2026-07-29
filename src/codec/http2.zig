//! HTTP/2 (RFC 9113) and HPACK (RFC 7541).
//!
//! Cleartext HTTP/2 with prior knowledge is what this speaks. `h2` over TLS is
//! not reachable and the reason is upstream rather than here: RFC 9113 §3.1
//! identifies `h2` by ALPN, and `std.crypto.tls.Client` offers no way to send it.
//! See [HTTP2.md](../../HTTP2.md).

pub const flow = @import("http2/flow.zig");
pub const frame = @import("http2/frame.zig");
pub const hpack = @import("http2/hpack.zig");
pub const headers = @import("http2/headers.zig");
pub const stream = @import("http2/stream.zig");
pub const huffman = @import("http2/huffman.zig");

pub const ErrorCode = frame.ErrorCode;
pub const FrameType = frame.FrameType;
pub const Settings = frame.Settings;
pub const client_preface = frame.client_preface;

test {
    _ = flow;
    _ = frame;
    _ = hpack;
    _ = headers;
    _ = stream;
    _ = huffman;
}
