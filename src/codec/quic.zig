//! QUIC transport, RFC 9000 / 9001 / 9002.
//!
//! This exists because HTTP/3 needs it and nothing in the standard library
//! provides it. Netty does not implement QUIC either — `netty-incubator-codec-quic`
//! binds to Cloudflare's Quiche through JNI — so there is no upstream shape to
//! copy for this half, only the specification.
//!
//! Layered bottom-up, and each layer is testable without a socket:
//!
//! * `varint` — §16, the encoding everything else is built from
//! * `packet` — §17, headers, connection IDs and packet number recovery
//! * `frame` — §19, every frame type, parsed and serialized
//! * `crypto` — RFC 9001 §5, packet protection and header protection

pub const varint = @import("quic/varint.zig");
pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const crypto = @import("quic/crypto.zig");

pub const ConnectionId = packet.ConnectionId;
pub const Version = packet.Version;

test {
    _ = varint;
    _ = packet;
    _ = frame;
    _ = crypto;
}
