//! TLS 1.3 for TCP, assembled from parts that already existed for QUIC.
//!
//! `codec/quic/` contains the complete TLS 1.3 handshake engine (key schedule,
//! messages, certificate verification, the client state machine) because QUIC
//! needed one and the standard library's `tls.Client` exports neither secrets
//! nor an engine-shaped API. What QUIC does *not* have is the record layer —
//! RFC 9001 §4.1 replaces it with packet protection. This module adds that
//! record layer, which is the difference between "TLS 1.3 for QUIC" and
//! "TLS 1.3 for TCP".

pub const record = @import("tls13/record.zig");
pub const session = @import("tls13/session.zig");
pub const client = @import("tls13/client.zig");
pub const identity = @import("tls13/identity.zig");

test {
    _ = record;
    _ = session;
    _ = client;
    _ = identity;
}
