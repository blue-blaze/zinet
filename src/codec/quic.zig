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
//! * `tls` — RFC 8446 §7.1's key schedule, in the engine shape RFC 9001 §4 needs
//! * `handshake` — RFC 8446 §4's messages and extensions, with RFC 9001 §8's rules
//! * `verify` — certificate chains and CertificateVerify (§4.4.2, §4.4.3)
//! * `transport` — §18's transport parameters, which TLS carries and QUIC means
//! * `cid` — §5.1's connection ID sets, one per direction
//! * `stream` — §2, §3 and the per-stream half of §4: one stream in isolation
//! * `streams` — §3.2's implicit creation, §4.1's connection window, §4.6's counts
//! * `recovery` — RFC 9002: ACK ranges, RTT, loss detection, NewReno
//! * `client` — the client half of the handshake: bytes in, keys out
//! * `connection` — datagrams in, events out: packets, Retry, connection IDs

pub const varint = @import("quic/varint.zig");
pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const crypto = @import("quic/crypto.zig");
pub const tls = @import("quic/tls.zig");
pub const handshake = @import("quic/handshake.zig");
pub const verify = @import("quic/verify.zig");
pub const transport = @import("quic/transport.zig");
pub const cid = @import("quic/cid.zig");
pub const stream = @import("quic/stream.zig");
pub const streams = @import("quic/streams.zig");
pub const recovery = @import("quic/recovery.zig");
pub const client = @import("quic/client.zig");
pub const server = @import("quic/server.zig");
pub const connection = @import("quic/connection.zig");
/// RFC 8448 test vectors, shared by the tests of the layers above.
pub const rfc8448 = @import("quic/rfc8448.zig");

pub const ConnectionId = packet.ConnectionId;
pub const Version = packet.Version;

test {
    _ = varint;
    _ = packet;
    _ = frame;
    _ = crypto;
    _ = tls;
    _ = handshake;
    _ = verify;
    _ = transport;
    _ = cid;
    _ = stream;
    _ = streams;
    _ = recovery;
    _ = client;
    _ = server;
    _ = connection;
    _ = rfc8448;
}
