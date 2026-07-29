# HTTP/2 in Zinet: an evaluation

This is an evaluation, not a plan of record. It asks three questions in order —
*can* Zinet speak HTTP/2 at all, *what would it cost*, and *what would it break*
— and reaches a conclusion for each. No HTTP/2 code exists.

**Conclusion up front: not now.** One upstream gap makes the version of HTTP/2
that people actually use unreachable, and the framework change it would force is
a reversal of a decision Zinet argued for on the merits. The precise conditions
that would change the answer are in [When to revisit](#when-to-revisit).

## 1. Reachability: what can be spoken today

HTTP/2 arrives three ways (RFC 9113 §3):

| Path | Needs | Available? |
|---|---|---|
| `h2` over TLS | ALPN advertising `h2` | **No** |
| `h2c` via `Upgrade:` | HTTP/1.1 upgrade dance | Removed from the spec in RFC 9113 §3.2 |
| `h2c` with prior knowledge | A server configured for cleartext HTTP/2 | Yes |

The first row is the blocking one, and it is upstream. `std.crypto.tls.Client`
never offers ALPN:

* `Client.Options` (`std/crypto/tls/Client.zig`) has fields for `host`, `ca`,
  buffers, `entropy`, `realtime_now`, `ssl_key_log`, `allow_truncation_attacks`
  and `alert`. There is no ALPN field, so there is no way for a caller to ask
  for one.
* The `ClientHello` is assembled from exactly five extensions —
  `supported_versions`, `signature_algorithms`, `supported_groups`,
  `psk_key_exchange_modes`, `key_share` — plus SNI. ALPN is not among them.
* `tls.ExtensionType.application_layer_protocol_negotiation` exists in
  `std/crypto/tls.zig` as an enum constant and appears nowhere else in the
  standard library.

RFC 9113 §3.1 is unambiguous that `h2` is identified by ALPN. A client that does
not send it gets HTTP/1.1 from every conforming server, which is the correct
behaviour and also the end of the road. This cannot be worked around from
Zinet's side without hand-writing a TLS `ClientHello`, which would mean
replacing the standard library's TLS client — the opposite of the reason for
using it.

On the server side the situation is the one D5 already recorded: there is no
`std.crypto.tls.Server` at all, so `h2` over TLS cannot be accepted either.

That leaves cleartext HTTP/2 with prior knowledge. It is genuinely used —
gRPC between services, a reverse proxy talking to a backend — but it is not the
case that motivates HTTP/2: no browser will ever use it, and no public API is
reachable with it. So the honest summary is that roughly 5000 lines of
protocol work (§2) would buy a transport usable only where both ends are
configured for cleartext, on a machine the operator controls.

For reference, `std.http` itself has no HTTP/2: `std.http.Version` lists only
`HTTP/1.0` and `HTTP/1.1`, and there is no HPACK anywhere in the standard
library. Everything below would be written from scratch.

## 2. Cost: what would have to be built

| Piece | Rough size | Notes |
|---|---|---|
| Frame layer | ~600 | 9-byte header, ten frame types, `max_frame_size` negotiation |
| HPACK (RFC 7541) | ~900 | Static table of 61 entries, dynamic table with eviction, canonical Huffman table, prefixed integers |
| Stream state machine | ~700 | RFC 9113 §5.1, per stream, plus ID validity and half-close rules |
| Flow control + write scheduler | ~500 | Two window levels, `WINDOW_UPDATE`, fair interleaving |
| Connection management | ~300 | `SETTINGS`, `PING`, `GOAWAY`, `RST_STREAM` |
| Multiplexed child pipelines | ~400 | Framework change, see §3 |
| Tests and fuzz targets | ~1500 | HPACK round trips, state machine transitions, every bound below |

That is on the order of 5000 lines against a `src/` tree that is currently
20083, so a quarter of the codebase for one protocol. The estimate is not the
argument against it — HTTP/1.1 plus its client is 2988 lines and was worth it —
but it sets the bar for what the protocol has to buy, and §1 says it currently
buys cleartext-only.

An unusually large share of that work is bounds rather than parsing. Every one of
these is a published denial-of-service class with its own explicit limit:

* **Rapid Reset** (CVE-2023-44487): open a stream, immediately `RST_STREAM`,
  repeat. Streams closed this way do not count against
  `SETTINGS_MAX_CONCURRENT_STREAMS`, so the limit has to be on resets per
  interval — a rate limit, which is a shape Zinet does not have anywhere yet.
* **CONTINUATION flood** (2024): unbounded `CONTINUATION` frames that never
  complete a header block. Needs a cap on frames per header block *and* on
  accumulated header bytes before the block completes.
* **HPACK header-list bomb**: the same shape as the zip bomb D4 dealt with, and
  the same answer — `SETTINGS_MAX_HEADER_LIST_SIZE` enforced *while* decoding,
  not after.
* **Frame floods**: `SETTINGS`, `PING` and `WINDOW_UPDATE` all demand a response
  and all cost nothing to send.

Zinet's discipline (every limit explicit and caller-visible) is exactly right for
this, which is a point in favour of doing it here rather than elsewhere. It is
also a warning: the protocol is not finished when it works, it is finished when
each of these has a bound and a test.

## 3. Fit: what it would break

### The multiplexing conflict that turns out not to be one

The obvious worry is that HTTP/2 runs many concurrent exchanges over one
connection while Zinet gives each connection exactly one reader task, and that
handler state is lock free *because* of that. Written down carefully, these do
not conflict. Netty's own answer — `Http2MultiplexHandler` creating a child
`Http2StreamChannel` with its own pipeline per stream — keeps every child on the
parent's event loop. Multiplexing is logical, not parallel.

The same move works here: one reader task decodes frames and dispatches each to a
per-stream `Pipeline`. N pipelines on one task preserves the guarantee, which is
about one task per connection and never was about one pipeline per task. So this
is work (§2's "multiplexed child pipelines") but not a contradiction.

### The write path, which is a real structural change

Zinet's outbound side is a single bounded FIFO drained by one writer task. HTTP/2
needs frames from different streams interleaved, so a large `DATA` frame for one
stream cannot be allowed to sit in front of another stream's `HEADERS`. That
means per-stream send queues plus a scheduler choosing between them, replacing
the FIFO for this protocol. Sizeable, but ordinary.

### The backpressure model, which is the actual objection

This is the part that decides the design rather than the schedule.

Zinet's backpressure is stated in the README as a deliberate difference from
Netty: the outbound queue is bounded and **blocks the producer**, and write water
marks are listed under "Deliberately absent" because blocking is backpressure
that cannot be ignored.

HTTP/2 has its own credit-based flow control, per stream *and* per connection.
Combine the two and the failure is not inefficiency, it is a deadlock: a writer
task blocked because a stream's window is exhausted is a writer task that is not
sending anything — including on the streams that still have credit, and including
the frames the peer is waiting for before it will send the `WINDOW_UPDATE` that
would release the block. The thing that unblocks the writer can only arrive if
the writer is not blocked.

So under HTTP/2 the writer must never block on a window. It has to park the
stream and move on, which means a stream's pending bytes must be bounded
somewhere the application can see, which means the application has to be *told*
to stop rather than stopped by blocking — which is Netty's write water marks,
the facility Zinet argued it did not need. HTTP/2 is the case where that argument
does not hold, and the reason is precise: blocking a producer is safe when the
connection carries one exchange, and is a deadlock when it carries many that
share a credit pool.

Zinet already has half of the replacement: `isWritable` and `pendingOutbound`
were added (phase three, A4) for observability. Turning those into the primary
mechanism for one protocol, while blocking remains the mechanism everywhere else,
would leave the framework with two backpressure models and a rule about which
applies where. That is the cost that is not measured in lines.

### What survives unchanged

Worth recording, because it is the reason this is a "not now" rather than a
"no": the fuzzing story holds up. Chunk independence still applies — the
connection is still one byte stream that must decode identically however it is
fragmented — and it is the invariant that found four real bugs. HPACK gains a
round-trip oracle for free. So HTTP/2 would be testable to the standard the rest
of the codebase is held to.

## 4. When to revisit

The answer changes when any of these does:

1. **`std.crypto.tls.Client` gains ALPN.** This alone makes `h2` clients
   reachable and is by far the cheapest change upstream — an options field and an
   extension in the `ClientHello`. It would move HTTP/2 from "unreachable" to
   "expensive".
2. **`std.crypto.tls.Server` appears.** Needed for `h2` servers, and already
   recorded as blocking server-side TLS generally.
3. **A concrete cleartext use appears.** gRPC between services on a controlled
   network is a real target that needs neither of the above. If that is the goal,
   the evaluation above is a plan rather than a rejection — and the order to
   build in is frame layer, HPACK, stream states, then the write scheduler and
   the water-mark decision last, because that decision is the one that touches
   the rest of the framework.

Until then, the framework-level piece worth extracting independently is the
multiplexed child pipeline from §3: it is not HTTP/2-specific, it is what any
multiplexed protocol needs, and unlike the backpressure question it costs the
existing design nothing.
