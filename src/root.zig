//! Zinet — an event-driven network application framework for Zig, in the
//! spirit of Java's Netty.
//!
//! Design principles:
//!
//! * **Dependency injection.** Nothing in Zinet reaches for a global
//!   allocator or a global I/O implementation. Both `std.mem.Allocator` and
//!   `std.Io` are passed in by the caller, exactly like the standard library
//!   does. This keeps the framework testable and lets the application pick
//!   its own I/O backend (`std.Io.Threaded` today, an evented backend
//!   tomorrow).
//! * **Explicit ownership.** Every heap-allocated value has exactly one
//!   owner at any moment. Ownership transfers are documented at the API
//!   boundary. Where sharing is genuinely required, an opt-in reference
//!   counted wrapper is used rather than making every type refcounted.
//! * **Bounded resources.** Every buffer, queue and protocol limit has an
//!   explicit, caller-visible maximum. No unbounded growth anywhere.
//! * **Assertions.** Invariants, preconditions and postconditions are
//!   asserted. Assertions are a form of documentation that cannot rot.

const std = @import("std");

pub const bootstrap = @import("bootstrap.zig");
pub const channel_pool = @import("channel_pool.zig");
pub const ChannelPool = channel_pool.Pool;
pub const buffer = @import("buffer.zig");
pub const channel = @import("channel.zig");
pub const codec = @import("codec/codec.zig");
pub const frame = @import("codec/frame.zig");
pub const http = @import("codec/http.zig");
pub const http2 = @import("codec/http2.zig");
pub const quic = @import("codec/quic.zig");
pub const tls13 = @import("codec/tls13.zig");
pub const http3 = @import("codec/http3.zig");
pub const dns = @import("codec/dns.zig");
pub const json = @import("codec/json.zig");
pub const websocket = @import("codec/websocket.zig");
pub const event_loop = @import("event_loop.zig");
pub const lock = @import("lock.zig");
pub const message = @import("message.zig");
pub const pipeline = @import("pipeline.zig");
pub const datagram = @import("datagram.zig");
pub const tls = @import("tls.zig");
pub const permessage_deflate = @import("codec/permessage_deflate.zig");
pub const pool = @import("pool.zig");
pub const redis = @import("codec/redis.zig");
pub const text = @import("codec/text.zig");
pub const timeout = @import("handler/timeout.zig");

pub const Buffer = buffer.Buffer;
pub const BufferPool = pool.BufferPool;
pub const Base64Decoder = text.Base64Decoder;
pub const Base64Encoder = text.Base64Encoder;
pub const Base64Variant = text.Base64Variant;
pub const ByteToMessageDecoder = codec.ByteToMessageDecoder;
pub const Delimiters = frame.Delimiters;
pub const DelimiterBasedFrameDecoder = frame.DelimiterBasedFrameDecoder;
pub const FixedLengthFrameDecoder = frame.FixedLengthFrameDecoder;
pub const JsonObjectDecoder = json.JsonObjectDecoder;
pub const Utf8Validator = text.Utf8Validator;
pub const Channel = channel.Channel;
pub const ChannelInitializer = channel.Initializer;
pub const ChildConfig = bootstrap.ChildConfig;
pub const Event = message.Event;
pub const EventLoop = event_loop.EventLoop;
pub const EventLoopGroup = event_loop.EventLoopGroup;
pub const Handler = pipeline.Handler;
pub const HandlerContext = pipeline.HandlerContext;
pub const HttpChunk = http.Chunk;
pub const HttpIncomingResponse = http.IncomingResponse;
pub const HttpMethod = http.Method;
pub const HttpMethodTracker = http.MethodTracker;
pub const HttpOutgoingRequest = http.OutgoingRequest;
pub const HttpRequest = http.Request;
pub const HttpRequestDecoder = http.RequestDecoder;
pub const HttpRequestEncoder = http.RequestEncoder;
pub const HttpResponse = http.Response;
pub const HttpResponseDecoder = http.ResponseDecoder;
pub const HttpResponseEncoder = http.ResponseEncoder;
pub const HttpStatus = http.Status;
pub const IdleCloser = timeout.IdleCloser;
pub const IdleState = timeout.IdleState;
pub const IdleStateEvent = timeout.IdleStateEvent;
pub const IdleStateHandler = timeout.IdleStateHandler;
pub const LengthFieldBasedFrameDecoder = frame.LengthFieldBasedFrameDecoder;
pub const LengthFieldPrepender = frame.LengthFieldPrepender;
pub const LengthFieldWidth = frame.LengthFieldWidth;
pub const LineBasedFrameDecoder = frame.LineBasedFrameDecoder;
pub const Datagram = datagram.Datagram;
pub const DatagramChannel = datagram.DatagramChannel;
pub const DatagramEndpoint = datagram.Endpoint;
pub const TlsConnection = tls.Connection;
pub const TlsClient = tls.Client;
pub const CaBundle = tls.CaBundle;

pub const RedisCommand = redis.Command;
pub const RedisDecoder = redis.Decoder;
pub const RedisEncoder = redis.Encoder;
pub const RedisIncoming = redis.Incoming;
pub const RedisValue = redis.Value;

pub const Message = message.Message;
pub const MessageToByteEncoder = codec.MessageToByteEncoder;
pub const MessageToMessageDecoder = codec.MessageToMessageDecoder;
pub const MessageToMessageEncoder = codec.MessageToMessageEncoder;
pub const Pipeline = pipeline.Pipeline;
pub const Server = bootstrap.Server;
pub const ServerOptions = bootstrap.ServerOptions;
pub const SharedBuffer = pool.SharedBuffer;
pub const Sink = pipeline.Sink;
pub const Spinlock = lock.Spinlock;
pub const WebSocketClientHandshaker = websocket.ClientHandshaker;
pub const WebSocketFrame = websocket.Frame;
pub const WebSocketFrameCodec = websocket.FrameCodec;
pub const WebSocketHandshakeComplete = websocket.HandshakeComplete;
pub const WebSocketHandshaker = websocket.Handshaker;
pub const WebSocketOutboundFrame = websocket.OutboundFrame;
pub const connect = bootstrap.connect;

/// Semantic version of the framework.
pub const version = std.SemanticVersion{ .major = 0, .minor = 1, .patch = 0 };

test {
    // Submodule tests are pulled in here as modules are added.
    std.testing.refAllDecls(@This());
    _ = bootstrap;
    _ = buffer;
    _ = channel;
    _ = codec;
    _ = event_loop;
    _ = frame;
    _ = http;
    _ = http2;
    _ = quic;
    _ = tls13;
    _ = http3;
    _ = dns;
    _ = channel_pool;
    _ = json;
    _ = lock;
    _ = message;
    _ = pipeline;
    _ = datagram;
    _ = tls;
    _ = permessage_deflate;
    _ = pool;
    _ = redis;
    _ = text;
    _ = timeout;
    _ = websocket;
    // Socket-level integration for the HTTP client, kept in its own file so the
    // fuzz module does not have to compile the socket layer.
    _ = @import("codec/http_client_test.zig");
}

test "smoke: toolchain and module wiring" {
    try std.testing.expectEqual(@as(usize, 0), version.major);
    try std.testing.expectEqual(@as(usize, 1), version.minor);
}
