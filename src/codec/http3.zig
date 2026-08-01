//! HTTP/3, RFC 9114, over the QUIC transport in `codec/quic`.
//!
//! Netty's codec-http3 (like its QUIC) is an incubator repository binding to
//! Quiche for the transport; here both halves are implemented, because the
//! zero-dependency rule leaves no other option. The layering mirrors
//! `codec/quic.zig`:
//!
//! * `frame` — §6 and §7: stream types, frame types, SETTINGS, the incremental
//!   parser (HTTP/3 frames ride streams, so reframing is back), and grease
//! * `qpack` — RFC 9204: the static table, field line representations, and the
//!   instruction streams, in the zero-capacity mode every connection starts in
//!
//! Where HTTP/2 concepts went is worth recording once: flow control and stream
//! multiplexing belong to QUIC (§4.1 note), so there is no WINDOW_UPDATE and
//! no PRIORITY; header compression is QPACK (RFC 9204) rather than HPACK,
//! because HPACK's dynamic table assumes the total ordering TCP gave and QUIC
//! streams do not have; and the frame types HTTP/2 used for all of those are
//! reserved as errors (§7.2.9) to catch a peer that translated instead of
//! reimplemented.

pub const frame = @import("http3/frame.zig");
pub const qpack = @import("http3/qpack.zig");
pub const connection = @import("http3/connection.zig");
pub const multiplex = @import("http3/multiplex.zig");
pub const client = @import("http3/client.zig");
pub const server = @import("http3/server.zig");

pub const Headers = multiplex.Headers;
pub const OutgoingHeaders = multiplex.OutgoingHeaders;
pub const StreamChannel = multiplex.StreamChannel;
pub const InboundComplete = multiplex.InboundComplete;
pub const StreamReset = multiplex.StreamReset;

test {
    _ = frame;
    _ = qpack;
    _ = connection;
    _ = multiplex;
    _ = client;
    _ = server;
}
