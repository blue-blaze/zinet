# HTTP/2 in Zinet

This was an evaluation that concluded "not now". It is now an implementation record.
The evaluation's own §4.3 said what would change the answer — *a concrete cleartext
use appears* — and named the order to build in: frame layer, HPACK, stream states,
then the write scheduler and the backpressure decision last, because that decision is
the one that touches the rest of the framework. That is the order this was built in,
and the last item did turn out to be the only one that changed anything outside
`src/codec/http2/`.

**What works:** the protocol, over cleartext with prior knowledge *and over TLS with `h2`
negotiated by ALPN*. 8357 lines in `src/codec/http2/`, 126 tests, three fuzz targets, and CI
steps that check both transports against `curl` with `nghttp2` underneath it on every run.

**What did not, and now does:** `h2` over TLS. This section used to say it "cannot be
*negotiated*", because RFC 9113 §3.1 identifies `h2` by ALPN and `std.crypto.tls.Client`
offers no way to send one. That was true of the standard library's client and stopped being
the whole story when the TLS 1.3 handshake here was written — QUIC needed it first, so it
stopped being a choice and became a prerequisite. `tls13.client.Client` sends ALPN and
`tls13.server.Server` selects it; see [Reachability](#reachability) for what the constraint
was and [TLS.md](TLS.md) for what replaced it.

## Contents

* [Reachability](#reachability)
* [The layers, and the decision in each](#the-layers-and-the-decision-in-each)
* [Backpressure: the one framework change](#backpressure-the-one-framework-change)
* [Every limit, and what it stops](#every-limit-and-what-it-stops)
* [What found the defects](#what-found-the-defects)
* [Deliberately not done](#deliberately-not-done)

## Reachability

RFC 9113 §3 lists three ways to arrive at HTTP/2:

| Path | Needs | State |
|---|---|---|
| `h2c` with prior knowledge | a peer configured for cleartext HTTP/2 | **Works.** `addServerCodec` / `addClientCodec` |
| `h2c` via `Upgrade:` | the HTTP/1.1 upgrade dance | Removed from the specification in §3.2 |
| `h2` over TLS | ALPN advertising `h2` | **Works.** See below |

All three reachable paths now work, and the third took the longest way round.

§3.1 identifies `h2` by ALPN, and `std.crypto.tls.Client` cannot send it —
`Client.Options` has no ALPN field, the `ClientHello` is assembled from five
extensions of which ALPN is not one, and
`tls.ExtensionType.application_layer_protocol_negotiation` exists in
`std/crypto/tls.zig` as an enum constant that appears nowhere else. That is still
true on Zig 0.17-dev: `alpn` occurs zero times in `Client.zig`.

So this was listed as blocked upstream for two protocols' worth of work. What
unblocked it was not the standard library but QUIC: RFC 9001 needs the TLS 1.3
handshake as an engine rather than a `Reader`/`Writer` pair, so one had to be
written, and an engine that assembles its own `ClientHello` can put ALPN in it. A
record layer later, the same engine runs on TCP. The record is in
[TLS.md](TLS.md).

Nothing in the HTTP/2 implementation is conditional on the transport. `h2` over
TLS is the negotiated protocol name being checked and nothing else — which is
what the CI step proves: `curl --http2` against `tls13_server` returns
`HTTP/2 200` with nghttp2 doing the negotiating on the other side.

Prior knowledge is not a consolation prize. It is what gRPC between services uses, and
what a reverse proxy uses to reach a backend. What it cannot do is talk to a browser.

## The layers, and the decision in each

Each file below is a layer, and each one exists as a separate file because it has a
decision in it that is worth finding.

### `frame.zig` — RFC 9113 §4, §6

All ten frame types, parsed and serialized, with every length and stream-identifier
rule in §6.

**Severity is not decided here.** §5.4 splits failures into connection errors, which
end everything, and stream errors, which reset one stream — and which applies often
depends on context a parser does not have. So parsing returns a plain Zig error that
maps one-to-one onto an `ErrorCode`, and `connection.zig` decides severity with an RFC
citation at each site. The frame layer is also not a pipeline handler: HTTP/2's frames
are internal machinery, since what reaches an application is a stream's headers and
body rather than a `WINDOW_UPDATE`. Netty draws the line in the same place.

`Flags` is accessors rather than a packed struct with one name per bit, because bit
0x1 is `END_STREAM` on `DATA` and `ACK` on `SETTINGS`, and a struct field would invite
reading the wrong one.

### `huffman.zig` — RFC 7541 Appendix B

The canonical code, decoded through a `comptime`-built DFA indexed four bits at a time.

**The table is verified structurally, not only by round trip.** The Appendix C vectors
pin the actual bit values, but only for the octets those strings use — and a round trip
proves nothing about a typo in an unused entry, because encode and decode would agree
on the same wrong code. Kraft's equality checks all 257 lengths at once: a prefix-free
code is complete exactly when the sum of 2^-len is one, and any single wrong length
breaks it. Prefix-freeness itself is asserted while the DFA is built, so two symbols
landing on one node fails the build.

### `hpack.zig` — RFC 7541

Integer and string primitives, the static table, the dynamic table with eviction, and
both directions.

**Decoded fields are always copied into the caller's arena.** The cheap implementation
hands back slices into the tables — but the dynamic table evicts, and it evicts *while
a later field in the same block is still being decoded*, so a size update or an
insertion can free what a previous field pointed at. Static entries are program
constants and are borrowed; everything else is copied. It is the same copy
`http.Request` makes, for the same reason.

**The limits are charged during the decode, not after.** One indexed field is a single
byte on the wire and 42 bytes of header list, so a small block can name a very large
one — the same shape as the zip bomb the WebSocket compression path had to bound.
Checking the total afterwards means having already built it.

Verified against the RFC 7541 Appendix C sequences including the dynamic table size
after each step: 57, 110, 164 for the request examples, and 222, 222, 215 for the
responses, where the last one evicts three entries to add two.

### `headers.zig` — RFC 9113 §6.10

Reassembling a header block across `CONTINUATION` frames.

The frame boundaries are not part of the block: HPACK decodes over the concatenation.
That is why §6.10 forbids interleaving any frame, from any stream, into one — the
header block is the single place HTTP/2 stops being multiplexed. Tested by cutting a
real HPACK block at all eighteen possible positions and requiring identical fields.

**The CONTINUATION flood of 2024 needs two bounds, not one.** A byte ceiling alone
still admits an unbounded number of *empty* `CONTINUATION` frames, which cost no memory
but pin the connection; a frame ceiling alone admits sixteen frames of 16 KiB. Both are
tested.

### `stream.zig` — RFC 9113 §5.1, §5.1.1, §5.1.2

The state machine, the identifier rules, and the reset rate limit.

**`closed` is two states, not one**, because §5.1 gives the same late frame two
different severities: after `RST_STREAM` it is a *stream* error, after `END_STREAM` a
*connection* error. That is not arbitrary. A `RST_STREAM` and a frame already in flight
cross on the wire constantly, so punishing the connection for a race the peer could not
avoid would be wrong; anything after `END_STREAM` means the two sides no longer agree
about what the stream is. The error set names the severity, so the connection layer
cannot get it wrong by accident.

### `flow.zig` — RFC 9113 §5.2, §6.9

Both window levels, and the write scheduler.

**A window is signed**, because §6.9.2 says a change to
`SETTINGS_INITIAL_WINDOW_SIZE` "can cause the available space in a flow-control window
to become negative". That is not an error: it means the sender has already sent bytes
it is no longer entitled to and must wait for credit covering the shortfall.

**Flow control charges the whole `DATA` payload including padding** (§6.1), which is
more than the application sees. That has a test rather than a comment, because getting
it wrong is invisible until a peer pads its frames — and then the two sides' windows
drift apart and the connection stalls with neither side at fault.

The scheduler is round robin with a cap of one frame per stream per pass. Round robin
stops a chatty stream starving a quiet one; the per-pass cap turns a megabyte on one
stream into sixty-four frames interleaved with everyone else's rather than sixty-four
back to back. **A stream with no credit is stepped over, never waited on** — that one
line is the deadlock argument below, and it has a test that fails if a blocked stream
can hold up a stream that has credit.

### `connection.zig` — RFC 9113 §3.4, §6.5, §6.7, §6.8

The piece that drives every layer below it. Bytes in through `poll`, application events
out, and anything owed the peer accumulated in `out` for the caller to flush.

That seam is what makes the protocol testable without a socket, and the tests use it to
wire a client and a server to each other so every byte one side writes is parsed by the
other with no test-only shortcut between them.

Severity is acted on here. A stream error never surfaces: `RST_STREAM` goes out, the
stream is dropped, and `poll` carries on — the peer's other streams never noticed. A
connection error writes `GOAWAY` and returns an error, and the caller must flush before
closing or the peer learns nothing about why.

### `multiplex.zig` — one `Pipeline` per stream

Netty's `Http2MultiplexHandler` and `Http2StreamChannel`.

The evaluation worried this contradicted the threading model. Written down carefully it
does not, and the reason is worth stating exactly: Zinet gives each connection one
reader task and handler state is lock free because of that, but the guarantee was
always "one task per connection", never "one pipeline per task". `dispatch` is an
ordinary function call from the parent's reader task, so every child pipeline runs
there. Multiplexing is logical, not parallel.

**Inbound `END_STREAM` half-closes; it does not tear the stream down.** The first
version conflated them, and that made an asynchronous reply impossible — a handler
could only respond from inside the callback that told it the request had arrived, since
its pipeline was destroyed on the way out. Now the inbound end is an
`InboundComplete` event and the pipeline is torn down when the *connection* says the
stream is over, in whichever direction closed last.

### `semantics.zig` — RFC 9113 §8

Where a header list becomes a request or a response. Two of its rules are security
properties rather than tidiness:

**Connection-specific fields are refused** (§8.2.2). `Connection`,
`Transfer-Encoding`, `Keep-Alive`, `Proxy-Connection` and `Upgrade` each describe a
single HTTP/1.1 hop, and HTTP/2 has no hops. A gateway that forwards one while
translating back to HTTP/1.1 emits framing headers the HTTP/2 sender chose, which is
request smuggling — the same argument the HTTP/1.1 decoder here already makes about two
sources of framing truth, arriving from the other direction.

**Field names must be lowercase** (§8.2.1). `Content-Length` and `content-length` are
unequal as bytes, so a peer sending both hands two different values to anything
matching case-sensitively.

Both are stream errors per §8.1.1: the message is malformed, not the connection.

**A CONNECT tunnel carries DATA and nothing else** (§8.5). The construction rules — no
`:scheme`, no `:path`, an `:authority` naming host and port — were checked here from the
start; which *frames* may follow was not, and that half is a MUST too: "Frame types
other than DATA or stream management frames (RST_STREAM, WINDOW_UPDATE, and PRIORITY)
MUST NOT be sent on a connected stream and MUST be treated as a stream error if
received." Until it was added, a tunnel accepted a second HEADERS block as trailers like
any other exchange, which lets a peer put field semantics into a byte stream a proxy
relays verbatim. `connection.zig` tracks it per stream, because §8.5 is about frame
sequencing and that happens before anything is validated: a server marks the tunnel when
the CONNECT arrives, a client when a 2xx answers one — a refusal is an ordinary response
that may carry trailers like any other. The same rule in HTTP/3 is a *connection* error
(§4.4 of RFC 9114); here §8.5 says stream error, and §5.4 permits the generic code where
no type is named. The proxying itself is absent, as it is in HTTP/3: opening a TCP
connection to the authority and relaying is an application, not a codec.

### `codec.zig` — the entry points

`addServerCodec` and `addClientCodec`. One handler nearest the socket, owning the
connection and the multiplexer. An application that wants per-request handlers puts
them in the stream initializer and needs nothing in the parent pipeline at all.

## Backpressure: the one framework change

The evaluation identified this as the real cost, and it was right that it is the only
part that touches the rest of the framework. It turned out to be statable in one
sentence and to cost less than feared.

Everywhere else, Zinet's outbound queue is bounded and **blocks the producer**, and
write water marks are listed in the README under "deliberately absent" because blocking
is backpressure that cannot be ignored. That argument is sound, and it is specifically
about a connection carrying one exchange.

It does not survive HTTP/2. With many exchanges sharing one credit pool, a writer
blocked because one stream's window is exhausted is a writer that is sending *nothing*
— including on the streams that still have credit, and including the frames the peer is
waiting for before it will send the `WINDOW_UPDATE` that would release the block. The
thing that unblocks the writer can only arrive if the writer is not blocked.

So the boundary is:

> **Blocking where one exchange owns the connection, water marks where many share it.**

Not a preference. A consequence of whether the thing that would unblock the producer
can arrive while it is blocked.

And the exception does not cost the "nothing is unbounded" invariant, because there are
two mechanisms rather than one. Netty's write queue is unbounded, so its water marks
are the only defence and an application that ignores them is merely misbehaving. Here
the marks are **advice** — heed them and the ceiling is never reached — and
`max_pending` is the **rule**: exceeding it fails the write.
[examples/http2_server.zig](examples/http2_server.zig) writes in 16 KiB chunks against
a 64 KiB mark and resumes on `WritabilityChanged`, because this is the shape HTTP/2
forces and it deserves demonstrating rather than describing.

## Every limit, and what it stops

The evaluation observed that an unusually large share of HTTP/2 is bounds rather than
parsing. That held up. Every one of these is a published denial-of-service class:

| Bound | Default | Stops |
|---|---|---|
| `max_concurrent_streams` | 128 | Unbounded concurrent state per connection (§5.1.2) |
| reset rate | 200 / 30 s | **Rapid Reset**, CVE-2023-44487 |
| `max_continuation_frames` | 16 | **CONTINUATION flood** (2024), the empty-frame half |
| `max_block_size` | 16 KiB | The same flood's memory half |
| `max_header_list_size` | 32 KiB | HPACK header-list bomb, charged per field while decoding |
| `max_string_len` | 8 KiB | One enormous header name or value |
| `max_fields` | 128 | Many tiny fields, which cost little size but a slot each |
| control frame rate | 100 / 10 s | `SETTINGS` and `PING` floods — each obliges a reply |
| idle frame rate | 10 000 / 10 s | `WINDOW_UPDATE`, `PRIORITY`, empty `DATA`, unknown types |
| `max_pending` | 256 KiB | An application that ignores its water mark |
| `max_frame_size` | 16 KiB | §6.5.2's own ceiling on one frame |

The reset and frame rates are a shape nothing else in this codebase has. Every other
limit here is a ceiling on a *quantity*, which works because the resource is held.
These attacks hold nothing — a reset stream frees its slot immediately, a `PING` is
answered and forgotten, an empty `DATA` frame occupies no memory. What they consume is
work, and work is only bounded per unit of time. Time is injected rather than read, and
a clock that goes backwards cannot open the gate.

## What it costs

`zig build bench-http2_bench` measures the two axes HTTP/2 has: connections, and requests in
flight on each. The load generator speaks HTTP/2 over a raw socket — a pre-encoded HPACK block
and frame headers only, no decoder — so the numbers are the server's cost rather than a round
trip through this implementation twice.

The result is a clean statement of what multiplexing is for here. Sixty-four connections with
one stream each serve 41.5 k req/s, which is indistinguishable from HTTP/1.1 at the same
concurrency: with one request in flight per connection, this framing costs nothing measurable
and buys nothing either. Thirty-two streams on **one** connection serve 105 k, and 128 streams
on one connection 115–137 k. The mechanism is not clever scheduling — it is that one read
gathers many requests and one write scatters many responses, so the syscall stops being a
per-request cost.

Which also means the ceiling is one core: a connection here has exactly one reader task, so
1 × 64 (125.7 k) beats 8 × 8 (88.3 k), and eight connections of 128 streams reach 142.8 k rather
than eight times a single connection's figure. The tables are in
[bench/README.md](bench/README.md).

## What found the defects

Worth recording, because the three methods found different things and none of them
would have found the others'.

**Chunk independence** — the fuzz oracle that had already found four defects elsewhere
in this repository — covers HTTP/2's three nested places to get fragmentation wrong: the
connection preface, the frame boundary, and the header block. Random bytes test almost
nothing here, since without a valid preface every input dies at byte 24, so the target
assembles a frame stream instead.

**Two-sided tests**, wiring a client and a server made of this same implementation to
each other, found a defect no one-sided test could see: the client treated the response
it had asked for as trailers on its own request, because `headers_seen` conflated
sending a header block with receiving one, and §8.1's "a second block is trailers" is
strictly about the receive direction.

**`curl`** found four more, every one of which had passed the entire test suite:

1. A response with no body never ended its stream, because `flush` routed the
   END_STREAM-only case through the scheduler and the scheduler skips a candidate with
   nothing pending. A zero-length `DATA` frame is not waiting for credit.
2. The input bound was checked *before* parsing, so a 300 KiB upload — one socket read
   holding many frames — looked like an attack. The bound belongs on the residue.
3. A stream was torn down when its inbound half closed, which is exactly when a server
   has learned what to reply to.
4. One write pass is not enough. A pass grants each stream one frame, but a peer that
   has finished its request sends nothing more, so there is no next read to carry the
   next pass and a large response stopped halfway.

The lesson is not that the tests were weak. It is that a test suite written alongside an
implementation shares its assumptions, and another implementation does not. That is why
the repository's rule is that every protocol is checked against somebody else's code, in
CI rather than by hand.

## Deliberately not done

| Thing | Why |
|---|---|
| The priority tree (§5.3) | §5.3.1 deprecates the scheme and §5.3 permits ignoring it. `PRIORITY` is parsed, reported and counted against the idle-frame limit; it is not acted on. Netty's default scheduler weights by it, which is the difference. |
| Sending `PUSH_PROMISE` | Receiving one works — the promised stream is reserved and reported. Sending one has no convenience API, because server push is disabled by default in every current browser and `SETTINGS_ENABLE_PUSH` is 0 here as a result. The frame layer can write it if that changes. |
| `h2` over TLS | Not a decision. See [Reachability](#reachability). |
| Automatic `content-length` | The HTTP/1.1 encoder controls framing headers because two sources of framing truth is what smuggling is made of. HTTP/2 frames itself, so `content-length` is advisory and left to the application. |
