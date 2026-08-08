//! HTTP/2 (RFC 9113) and HPACK (RFC 7541).
//!
//! Both transports RFC 9113 defines: cleartext with prior knowledge (§3.2) and `h2`
//! negotiated by ALPN over TLS (§3.1). The second was unreachable for as long as
//! `std.crypto.tls.Client` was the only TLS available — it offers no way to send an
//! ALPN protocol — and became reachable when the TLS 1.3 handshake in
//! `codec/tls13` was written for QUIC. See [HTTP2.md](../../HTTP2.md).

pub const codec = @import("http2/codec.zig");
pub const connection = @import("http2/connection.zig");
pub const flow = @import("http2/flow.zig");
pub const frame = @import("http2/frame.zig");
pub const hpack = @import("http2/hpack.zig");
pub const headers = @import("http2/headers.zig");
pub const semantics = @import("http2/semantics.zig");
pub const stream = @import("http2/stream.zig");
pub const huffman = @import("http2/huffman.zig");
pub const limits = @import("http2/limits.zig");
pub const multiplex = @import("http2/multiplex.zig");

pub const ErrorCode = frame.ErrorCode;
pub const FrameType = frame.FrameType;
pub const Settings = frame.Settings;
pub const client_preface = frame.client_preface;

pub const Codec = codec.Codec;
pub const Headers = multiplex.Headers;
pub const OutgoingHeaders = multiplex.OutgoingHeaders;
pub const StreamChannel = multiplex.StreamChannel;
pub const InboundComplete = multiplex.InboundComplete;
pub const StreamReset = multiplex.StreamReset;
pub const WritabilityChanged = multiplex.WritabilityChanged;
pub const addClientCodec = codec.addClientCodec;
pub const addServerCodec = codec.addServerCodec;

test {
    _ = codec;
    _ = connection;
    _ = flow;
    _ = frame;
    _ = hpack;
    _ = headers;
    _ = semantics;
    _ = stream;
    _ = huffman;
    _ = limits;
    _ = multiplex;
}
