# Review findings

A full-path review of Zinet — accept, channel, pipeline, buffers, codecs — plus
a fuzz suite built to attack the parts a review reads past, and what a later
round of work on the client sides turned up.

## Summary

Eighteen defects, seven of them serious. Eleven came out of the review and the
fuzzer; three surfaced while implementing the client side of each protocol, and
four more while adding compression and TLS. Of those seven later ones, five were
found only because the code was run against other people's implementations or
under the fuzzer rather than by reading — and one of those only because the check
was run repeatedly.

From the review and the fuzzer:

| # | Severity | What | Where |
|---|---|---|---|
| F1 | major | HTTP decoder had no fatal-error latch: one bad byte plus a dribble is an unbounded error storm | `codec/http.zig` |
| F2 | major | Line decoder dropped good frames that shared a read with an over-long one | `codec/frame.zig` |
| F3 | major | Length-field decoder did the same, and re-parsed a corrupt length forever | `codec/frame.zig` |
| F4 | major | WebSocket codec had no protocol-failure latch | `codec/websocket.zig` |
| R2.1 | major | Use-after-free: nothing kept a `*Channel` alive for the cross-task writes the API advertises | `channel.zig` |
| R4.1 | major | Latent heap overflow: unchecked addition ahead of the checked one in `ensureWritable` | `buffer.zig` |
| R6.1 | major | HTTP response splitting: the encoder validated no header it wrote | `codec/http.zig` |
| R6.2/6.3 | hardening | Decoder accepted control characters in headers; trailers could inject framing and routing fields | `codec/http.zig` |
| R8.1 | major | HTTP/2 client read the response it asked for as trailers on its own request | `codec/http2/stream.zig` |
| R8.2 | major | A response with no body never ended its stream: END_STREAM went through the write scheduler, which skips anything with nothing pending | `codec/http2/connection.zig` |
| R8.3 | major | Input bound checked before parsing rather than on the residue, so one read holding many frames looked like an attack | `codec/http2/codec.zig` |
| R8.4 | major | A stream's pipeline was destroyed when its inbound half closed, making an asynchronous reply impossible | `codec/http2/multiplex.zig` |
| R8.5 | major | One write pass per read is not enough: a peer that has finished asking sends nothing to carry the next pass | `codec/http2/codec.zig` |
| R2.2/2.3, R1.1, R1.3, R3.2 | minor | Busy-spin on empty reads, two inbound limits, millisecond deadline rounding, `serve` twice under ReleaseFast, failed `onAdded` left in the chain | various |

Everything above is FIXED, each with a regression test. What follows is the
detail, kept because the reasoning matters more than the diff.

## Found later, while building the client sides

Three more defects turned up once the same protocols were implemented in the
other direction. Two of them were found by running against other people's code
rather than by reading, which is the argument for doing that.

| # | Severity | What | Where |
|---|---|---|---|
| C1 | major | WebSocket mask keys came from the wall clock, which RFC 6455 §5.3 forbids | `codec/websocket.zig` |
| C2 | major | No closing handshake: nothing ever *sent* a close frame | `codec/websocket.zig` |
| C3 | minor | `decodeLast` was skipped when nothing was buffered, losing an empty until-close body | `codec/codec.zig` |

- C1 FIXED (**major, weak entropy**) `FrameCodec` seeded a `DefaultPrng` from
  `Timestamp.now().toMilliseconds()`, above a comment claiming mask keys "only
  need to be unpredictable to a passive observer". That is not what masking is
  for. RFC 6455 §5.3 requires the key to come from a strong source of entropy
  *and* requires that seeing one key must not make the next guessable, because
  masking exists so that a client cannot choose the bytes that appear on the
  wire — an intermediary tricked into reading those bytes as a second request is
  the cache-poisoning attack it prevents. A millisecond clock is fully
  predictable, and xoshiro's state can be recovered from a handful of observed
  keys, so both halves of the requirement failed. Keys now come from the injected
  `Io`'s CSPRNG (`io.random`), per frame, which also removed the `seed` parameter
  rather than adding API.
- C2 FIXED (**major, protocol**) The codec echoed an inbound close but had no
  path that *initiated* one, so an application closing the connection dropped TCP
  without a close frame. Found by pointing the new client at the third-party
  `websockets` library, which reported `no close frame received or sent`: the peer
  cannot tell an orderly shutdown from a broken network, which is the whole reason
  RFC 6455 §5.5.1 specifies a closing handshake. `onClose` now sends the frame
  first. That works because a close travels the same outbound queue as writes, so
  ordering needs no extra machinery — the same property that makes
  `ChannelPromise` unnecessary. Note that `Channel.requestClose` bypasses the
  pipeline by design and so does *not* perform the handshake.
- C3 FIXED (minor) `ByteToMessageDecoder.onInactive` returned early when the
  accumulation buffer was empty, so `decodeLast` was never called. An HTTP
  response whose body runs until the connection closes can be empty
  (`200 OK\r\n\r\n` then close), and such a response was therefore never
  delivered at all. `drainLast` now makes at least one call with an empty buffer,
  as Netty does; only consuming bytes earns another round, so termination is still
  guaranteed.

## Found later still, while adding compression and TLS

Four defects, all of them mine and all of them introduced by the feature that
found them. Recorded because each one is a specific instance of a rule this
codebase already states, which is the useful part.

| # | Severity | What | Where |
|---|---|---|---|
| D1 | major | Double free: `deliver` took ownership of the payload while both callers still held an `errdefer` for it | `codec/websocket.zig` |
| D2 | major | Nothing was ever sent: `tls.Client.flush` encrypts into the output writer without flushing it | `tls.zig` |
| D3 | minor | The first request bypassed the pipeline, so no encoder ran | `tls.zig` |
| D4 | minor | A submitted close raced the loop cancellation that followed it, so the closing handshake was sometimes skipped | `examples/ws_client.zig` |

- D1 FIXED (**major, memory**) Adding `permessage-deflate` introduced a single
  delivery path, `deliver`, that decompresses when the sender marked a message
  compressed. It frees the payload on every path — including the failure path,
  since the decompressor's output replaces it. Both call sites still had the
  `errdefer gpa.free(payload)` they needed before, so a message that failed to
  inflate was freed twice. Found by the new permessage-deflate fuzz target under
  `DebugAllocator`, which is precisely the case a reader skims: the *successful*
  path is correct and the ownership comment above it was still accurate for the
  old shape. The fix removes the callers' `errdefer` and states the contract in
  `deliver`'s doc comment, because the rule this violated — a function that
  consumes unconditionally must say so — is one the codebase relies on for
  `Sink.write` and `Channel.submit` too.
- D2 FIXED (**major, silent stall**) The TLS client completed a handshake, the
  HTTP encoder ran, `sinkWrite` reported writing 91 bytes — and OpenSSL's server
  never saw a request. `std.crypto.tls.Client.flush` prepares a ciphertext record
  and calls `advance` on the output writer; it does not flush that writer, and
  neither does `end`. The finished record sat in the socket writer's buffer.
  Flushing a TLS session is therefore two steps, and this is worth writing down
  because the failure is indistinguishable from a peer that never answered: there
  is no error, no partial write, and both sides block. Found only by running
  against a real TLS server, since there is no in-process one to run against.
- D3 FIXED (minor, but the same mistake twice) The first version of the TLS API
  offered one send function, which queued bytes for the session directly. That
  skips the pipeline, so `OutgoingRequest` reached the writer as a message with no
  bytes and was dropped. This is exactly the distinction `Channel.write` versus
  `Channel.submitWrite` exists to make, established when task hopping was added;
  the TLS connection now mirrors it name for name. Worth recording as evidence
  that the distinction needs to be in the API rather than in the documentation:
  a single `send` invites this bug every time.
- D4 FIXED (minor, and instructive) The WebSocket client example submitted a
  close and then cancelled its event loops on the next line. `submitClose` only
  *queues* the close, so the cancellation frequently won: the reader task was
  aborted before it ran the close through the pipeline, and the third-party peer
  reported `no close frame received or sent` — the exact symptom C2 was fixed to
  remove, reintroduced one layer up. Found by promoting the WebSocket
  interoperability check into CI and running it repeatedly: it failed roughly one
  run in five, which is why it had not been noticed before. The example now waits
  for the channel to close, with a deadline. Recorded because the general lesson
  applies to every asynchronous close: submitting one is not performing one, and a
  test that runs once cannot tell the difference.

## Method

The review walked the call path rather than the file list: accept → register →
`Channel.serve` → the two per-connection tasks → pipeline propagation → codecs,
then the data structures underneath.

The fuzz suite exists because reviewing found the *first* class of bug and
missed the rest. Its oracle is not "did it crash" — that catches almost nothing
in a parser that returns errors rather than dereferencing wild pointers. It is:

* **Chunk independence.** A stream decoder must produce identical output whether
  its input arrives whole or in fuzzer-chosen fragments. Real networks attack
  this constantly and unit tests rarely cover it at scale, because the
  interesting split points are the ones nobody thinks to write down. This one
  invariant found four bugs.
* **Round-trip identity.** Whatever an encoder writes, the matching decoder
  recovers. Catches framing errors that are symmetric, and so invisible to a
  decoder-only test.
* **Model equivalence.** `Buffer` against a trivially correct `ArrayList`.
* **No leaks, per input.** Every iteration gets its own `DebugAllocator`, so the
  input that leaked is the one reported.

Two self-check tests assert the harness actually observes what the targets
compare, because a fuzz target that sees nothing passes everything. One of them
immediately caught a mistake in the corpus itself.

## Fuzz findings

All three were the same bug class: a decode failure and the accumulating
decoder's drain loop interacting badly. Found by asserting *chunk
independence* — the same bytes fed whole and fed in fuzzer-chosen fragments
must produce identical output. Every one of them needs a peer to send
something malformed, so every one is reachable from the network.

- F1 FIXED (**major**) `http.RequestDecoder` had no fatal-error latch. Malformed
  bytes stayed in the accumulation buffer, so every later read re-parsed them
  and raised the same error again: one bad byte plus a slow dribble is an
  unbounded error storm. Now a fatal parse failure enters `State.bad_message`,
  which reports once and discards the rest of the connection, the way Netty's
  `BAD_MESSAGE` state does.
- F2 FIXED (**major**) `LineBasedFrameDecoder` dropped good frames. Returning
  `error.FrameTooLong` from `decode` aborts the drain loop, so anything behind
  the over-long line in the same read stayed buffered — and was discarded
  wholesale at end of stream. A peer sending `<over-long>\n<valid command>\n` in
  one segment had its valid command silently ignored. Resynchronizable failures
  are now reported with `ctx.fireError` and decoding continues, which is what
  Netty does from inside its decode loop.
- F3 FIXED (**major**) `LengthFieldBasedFrameDecoder` had both problems:
  `FrameTooLong` hid the frames behind it (same fix), and `CorruptFrame`
  consumed no bytes at all, so a bad length header was re-parsed forever. A
  desynchronized length-prefixed stream cannot be resynchronized, so that one is
  now latched.
- F4 FIXED (**major**) `websocket.FrameCodec` had no latch either; an unmasked
  client frame produced 250+ `MaskingViolation` reports in one fuzz case.
  RFC 6455 §7.1.7 requires failing the connection on a protocol error, so it is
  latched.

Each fix is pinned by a regression test asserting "reported once, not once per
read", and the framing tests now assert that a rejected frame does not take its
neighbours with it.

## R1 accept path (bootstrap.zig, event_loop.zig)

- R1.1 FIXED (minor) `awaitQuiet` compared deadlines with `toMilliseconds()`, so
  a sub-millisecond timeout rounded to 0 and the loop exited before waiting at
  all. Compared in nanoseconds now.
- R1.2 OK `Channel.create` failure and `register` failure both close
  the stream in `admit`; verified non-overlapping with `Channel.destroy`, which
  deliberately does not close. No double close.
- R1.3 FIXED (minor) `serve()` asserted `state == idle`. Assertions are compiled
  out in ReleaseFast, where a second `serve` would have quietly started a second
  set of acceptors on the same socket. It is a compare-and-swap now, returning
  `error.AlreadyServing`.

## R2 Channel (channel.zig)

- R2.1 FIXED (**major, use-after-free**) Nothing kept a `*Channel` alive for
  other tasks. `serve` destroyed the channel when its read loop ended, but
  `Channel.write` is advertised as callable "from any task" and the README sells
  exactly that (a chat server broadcasting to its peers). A broadcaster holding
  `ctx.owner()` after the peer disconnected read freed memory; the `isOpen()`
  check in `write` narrowed the window but `outbound_storage` was freed
  regardless.

  The channel is now reference counted, with the important part being *what got
  split*: ending the connection (`teardown` — close the socket, dismantle the
  pipeline) is now separate from releasing the memory (last `release`). A holder
  therefore finds a channel that is closed but structurally intact, so its
  `write` fails cleanly instead of reading a dangling pointer, and a producer
  blocked in `putOne` when the peer vanishes still has queue storage to return
  from. `retain`/`release` are the public contract, and `requestClose` on a dead
  channel is a no-op because its compare-and-swap can no longer succeed — which
  also stops it from calling `shutdown` on a file descriptor the kernel may have
  handed to someone else.
- R2.2 FIXED (minor) `readLoop` treated `readVec == 0` as "nothing this round"
  and retried, reallocating the inbound buffer every time. The buffer is now
  reused across empty reads, and a run of 64 of them ends the connection rather
  than spinning a core on a stream that is neither delivering bytes nor
  reporting an end.

  Follow-up, recorded for honesty: reading `Io.net.Stream.Reader.readVec` closely
  afterwards shows it maps `n == 0` to `error.EndOfStream`, and the bounded path
  added later maps a zero-length receive to end-of-stream too. So the guard is
  unreachable through either path as they stand today. It is kept because
  `Io.Reader`'s published contract does permit returning 0 and the cost is one
  comparison, but it is untestable defensive code and should be deleted if that
  contract is ever tightened.
- R2.3 FIXED (minor) `acquireInbound` applied `max_inbound_capacity` only on the
  unpooled path, so configuring a pool silently swapped the channel's inbound
  ceiling for the pool's. Both paths now apply the channel's limit.
- R2.4 OK `serve` closes the outbound queue before cancelling the writer, and
  `writeLoop`'s deferred `drainOutbound` runs after its own `close`, so every
  queued message is freed exactly once on every path.

## R3 Pipeline (pipeline.zig)

- R3.1 OK `depth`/`pending_free` correctly defers frees during propagation, and
  `nextInbound`/`prevOutbound` skip removed-but-not-yet-freed contexts, so a
  handler removing itself mid-callback is safe. `notifyError` is only ever
  reached from inside an `enter()`/`leave()` scope, so it does not need its own.
- R3.2 FIXED (minor) `link()` left a handler in the chain when its `onAdded`
  failed, where it would go on receiving events it never initialized for. The
  insertion is now undone and the failure returned. Note the deliberate
  asymmetry: only the *context* is freed, never the handler, because ownership of
  an `initOwned` instance transfers on a successful add — freeing it here would
  be the second half of a double free with the caller's `errdefer`.
- R3.3 OK `Pipeline.deinit` fires `onRemoved` head-to-tail while downstream
  contexts are still linked, which is what makes
  `ByteToMessageDecoder.onRemoved` able to flush its residue during teardown.

## R4 Buffer, pool, messages (buffer.zig, pool.zig, message.zig)

- R4.1 FIXED (**latent heap overflow**) `ensureWritable` compared
  `readable + additional` against the current capacity *before* the checked
  addition below it. In ReleaseFast that sum wraps, the comparison then picks the
  compaction path, and the assertion that would have caught the short buffer is
  compiled out — so the function returns a writable slice smaller than it
  promised and the caller writes past it. Not reachable with today's callers,
  every one of which bounds `additional` by a protocol limit, but one careless
  `reserve` away. The checked addition now comes first and everything downstream
  reuses it. `growCapacity` is saturating for the same reason.
- R4.2 OK `BufferPool` asserts at `init` that its size-class bounds are powers of
  two and correctly ordered, which is what makes `classIndexFor`'s
  `ceilPowerOfTwoAssert` and `log2_int` safe and its result in range. These are
  configuration values — code, not peer input — so assertions are the right
  instrument.
- R4.3 OK The `Recycler` path is exercised by a fuzz target that releases pooled
  buffers both ways (naming the pool, and plain `deinit`) and checks the
  accounting; `release` clears the recycler first, so a discarded buffer frees
  normally instead of recursing.

## R5 Codec base and framing (codec/codec.zig, codec/frame.zig)

- R5.1 The `decode` contract is now stated precisely, because the fuzz findings
  turned on it: returning a message must consume bytes, returning `null` may
  consume bytes (a decoder resynchronizing) or none (needing more input), and
  **returning an error aborts the drain loop**. That last clause is the one that
  made F2 and F3 bugs possible, so recoverable failures now report through
  `ctx.fireError` and let the loop continue.
- R5.2 OK `enforceResidueLimit` bounds *undecoded* residue rather than input per
  read, so one read carrying many messages is not mistaken for one oversized
  one. Peak memory is `max_cumulation` plus one read.
- R5.3 OK `onRemoved` forwarding the residue downstream is what makes a protocol
  upgrade lossless; the WebSocket upgrade fuzz target covers it with the first
  frame deliberately sharing the upgrade request's read.

## R6 HTTP/1.1 (codec/http.zig)

- R6.1 FIXED (**major, response splitting — CWE-113**) `ResponseEncoder` wrote
  header names and values with no validation. Applications routinely echo
  something they were sent into a response header; a CR or LF surviving that
  round trip lets the peer write the response framing and forge a second
  response that any client or cache in between will believe. Names must now be
  RFC 9110 tokens and values must be free of control characters, checked before
  a single byte is emitted — a half-written response is just as exploitable as a
  whole one.
- R6.2 FIXED (**hardening**) The decoder accepted control characters in header
  names and a bare CR inside values. An intermediary that disagrees with this
  parser about where a field ends is how a request gets smuggled past it, which
  is the same family of attack as the framing vectors already rejected.
- R6.3 FIXED (**hardening**) Trailer parsing was the laxest path in the file: no
  name validation, no byte accounting, and every field merged straight into the
  request's headers. A peer could therefore add a `Host` or `Content-Length`
  *after* the body had been framed and change what the application believed it
  received. Trailers are now validated, counted against `max_header_bytes`, and
  filtered per RFC 9110 §6.5.1.
- R6.4 FIXED (**major**) No fatal-error latch; see F1.
- R6.5 OK Framing headers remain the encoder's exclusive property, and the
  decoder's smuggling rejections (`Content-Length` with `Transfer-Encoding`,
  conflicting duplicates, obsolete line folding, non-`chunked` encodings) are
  each covered by a test.

## R7 WebSocket (codec/websocket.zig)

- R7.1 FIXED (**major**) No protocol-failure latch; see F4.
- R7.2 OK Payload ownership across `decode`'s branches is the subtle part —
  the duplicated payload is handed to `handleControl` or `handleData` and there
  is deliberately no `errdefer` at the top, because a second release path would
  double free. Verified by reading and covered by the leak check on every fuzz
  iteration.
- R7.3 OK The handshake, the run-time pipeline rewrite and the residue handover
  are covered by a dedicated fuzz target, including the case that motivated
  `onRemoved` forwarding: the client's first frame arriving in the same read as
  its upgrade request. A harness self-check asserts the target really observes
  the handshake, so it cannot pass by testing nothing.

## R8 HTTP/2 (codec/http2/)

Five defects, found by three different methods. None of the methods would have
found the others' — which is the point of running all three.

Found by wiring a client and a server made of this same implementation to each
other, so that every byte one side writes is parsed by the other:

- R8.1 FIXED (**major**) The client treated the response it had asked for as
  trailers on its own request. `headers_seen` was set both when a header block was
  *sent* and when one was *received*, and §8.1's "a second block is trailers"
  is strictly about the receive direction. A one-sided test cannot see this, because
  one side never does both.

Found by `curl` — every one of these passed the entire test suite first:

- R8.2 FIXED (**major**) A response with no body never ended its stream. `flush`
  routed the END_STREAM-only case through the write scheduler, and the scheduler
  skips any candidate with nothing pending, so the stream was parked for ever. A
  zero-length `DATA` frame is not waiting for credit: §6.9 charges the payload and
  this one has none, so it must bypass the scheduler entirely.
- R8.3 FIXED (**major**) The input bound was checked *before* parsing rather than
  on the residue after it. One socket read routinely delivers many frames, so a
  300 KiB upload looked like an attack. The same edit added the missing
  `discardReadBytes`, without which the accumulation's capacity grew for the life
  of the connection although its contents never did.
- R8.4 FIXED (**major**) A stream's pipeline was torn down when its inbound half
  closed — which is exactly when a server has learned what to reply to. So a
  handler could only respond from inside the callback that told it the request had
  arrived, and an asynchronous reply was impossible. Inbound `END_STREAM` is now an
  `InboundComplete` event, and the pipeline is destroyed when the connection says
  the stream is over in both directions.
- R8.5 FIXED (**major**) One write pass is not enough. A pass grants each stream a
  single frame, which is what interleaves them, but a peer that has finished its
  request sends nothing more — so there is no next read to carry the next pass and a
  large response stopped halfway. The codec now runs passes until one grants
  nothing, which is also what makes water marks usable: writability events fire
  inside the loop, so a handler writing in chunks refills as the queue drains.

Verified rather than assumed:

- R8.6 OK Chunk independence covers HTTP/2's three nested fragmentation points —
  the connection preface, the frame boundary, and the header block. Random bytes
  would test almost nothing, since without a valid preface every input dies at byte
  24, so the target assembles a frame stream instead. Self-checked by injecting a
  deliberate chunk dependence, which is caught at the first iteration of the first
  seed.
- R8.7 OK The Huffman table is verified structurally, not only by round trip. A
  round trip proves nothing about a typo in an entry the test vectors do not use,
  because encode and decode would agree on the same wrong code. Kraft's equality
  checks all 257 lengths at once, and prefix-freeness is asserted while the decoding
  DFA is built at comptime.
- R8.8 OK Flow control charges the whole `DATA` payload including padding (§6.1),
  which is more than the application sees. It has a test rather than a comment
  because getting it wrong is invisible until a peer pads its frames, and then the
  two sides' windows drift apart and the connection stalls with neither at fault.
- R8.9 OK Each published denial-of-service class has an explicit bound and a test:
  Rapid Reset (CVE-2023-44487) by reset rate, the 2024 CONTINUATION flood by *two*
  bounds because a byte ceiling alone still admits unbounded empty frames, the HPACK
  header-list bomb by charging per field during the decode, and the `SETTINGS`,
  `PING` and empty-`DATA` floods by rate. The rate limits are a shape nothing else in
  this codebase needs, because what those attacks consume is work rather than a held
  resource.
