# Review findings

A full-path review of Zinet — accept, channel, pipeline, buffers, codecs — plus
a fuzz suite built to attack the parts a review reads past, and what a later
round of work on the client sides turned up.

## Summary

Twenty-seven defects, twelve of them serious. Eleven came out of the review and
the fuzzer; three surfaced while implementing the client side of each protocol,
four more while adding compression and TLS, and **nine while adding the server
sides** — TLS, QUIC and HTTP/3 — which is where the list stops being a list of
mistakes and starts having a shape. See
[Found while adding the server sides](#found-while-adding-the-server-sides).

Of the later sixteen, most were found only because the code was run against other
people's implementations, under the fuzzer, or through a deliberate mutation of a
rule to see whether any test noticed. Reading did not find them.

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

## Shapes, not instances

By the time the QUIC sending sides were finished, the same few mistakes had been
made often enough to be worth naming. What follows is each shape, its symptom, the
instances, and — where one exists — the check that turns it from something to
remember into something the build enforces. That last column is the point: a shape
that has recurred seven times will recur again, and a reviewer's attention is not a
control.

### A rule implemented twice

**Symptom: break one copy and the whole suite still passes.** Two statements of one
rule are not redundancy, because they drift, and the drift is silent — each copy
looks correct in isolation. Worse, they are usually *not* equivalent, so which one
survives a refactor decides behaviour.

Instances: ACK's `-2` in range decoding; HANDSHAKE_DONE's `hasSomethingToSend`
clause; STOP_SENDING's "size already known" test, written once where the request is
recorded and once where the frame is sent; NEW_CONNECTION_ID's "still ours to
announce" test; and the filter picking an entry's owning connection ID, written in
both `sweep` and teardown, where the second copy's absence is a double free rather
than a miscount.

Twice the two copies were unequal and the *weaker* one was the one that had a test.
STOP_SENDING's interesting case is a request made before the FIN arrives and rendered
pointless by it, which only the send-time check catches. So the resolution is not
"delete a duplicate" but "decide where the question is asked" — at the moment the
answer is needed — and remove the other.

No mechanical check. What works is the mutation habit: break one copy on purpose and
require that a named test fails.

### A key cut and never put in the lock

**Symptom: a function, complete and sometimes unit-tested, that nothing calls.** The
rule is written down; the code path that owes it never asks.

Instances, in order: `Send.owesReset`, so a received STOP_SENDING got an event and no
RESET_STREAM, leaving the peer's stream open forever; `acceptor.mintToken` for
`.new_token`, so the token machinery existed and no token was ever issued;
`cid.Local.issue`, so no spare connection ID was ever announced; `Frame.isProbing`,
documented against §9.1 and never consulted, so migration detection did not exist;
and PATH_RESPONSE, which was *blocked* by a comment confusing "answer a challenge"
with "migrate to a path".

This shape has a mechanical check, and it found something worse than an unused
function. In Zig a function body is analysed only when something reaches it, so
**never called and never compiled are the same condition**. `IdleCloser.init` called
an `EnumSet` constructor that does not exist in this version and shipped anyway,
because its only caller was `addReadTimeout` and nothing called that. `refAllDecls`
was already present and did not help: it is one level deep, and referencing a
re-exported type analyses none of its methods. `refAllDeep` in `root.zig` recurses,
and was verified by restoring the broken call with the new test disabled — the build
still fails.

The check tells you a declaration compiles, not that anything uses it. The remaining
question is per case: wire it, test it, or say why it has no caller. `cid.Remote.rotate`
and `retireActive` now say: rotating the ID we send to is what a migrating client does,
and client-initiated migration is not implemented.

A mechanical sweep for the shape, run again after the HTTP/3 work: count every
occurrence of each `pub fn`'s name in production code, in tests, and in the examples,
and subtract its definitions. Eight functions had none anywhere. Seven are now
exercised or gone — `Buffer.readByte`, `dns.Message.questionSlice`,
`EmbeddedChannel.clearOutbound` and `closeCount`, and `http2.Codec.ping` and `goAway`
have tests; `websocket.Frame.isText` was deleted, because `text()` answers the same
question and returns the payload with it. `tls.Connection.protocolVersion` is exercised
by the https-client example, which now *asserts* the version rather than printing it.
The one that remains, `quic.cid.Remote.retireActive`, is waiting on §9.2
client-initiated migration and says so in its own comment.

The sweep has a known blind spot worth writing down: a name that appears in a comment
counts as a use. `http2.Codec.ping` was missed for exactly that reason and only turned
up while reading the code next to `goAway`. The floor it produces is real; the list it
produces is not complete.

### A rule stated where nothing consults it

Close to the above and worth separating, because the remedy is the opposite. A
predicate that states a fact authoritatively while the real decision is made
elsewhere is worse than no predicate: the next reader believes it is the source of
truth. `Frame.carriesHeaderBlock` named the set {HEADERS, PUSH_PROMISE, CONTINUATION}
while the routing switch decided, and `Assembler.guard` enforced the sequence. It was
deleted rather than wired, because the routing switch has to enumerate frame types
anyway.

### Returned by value with a pointer into itself

**Symptom: a value that is correct where it is built and wrong one assignment later.**
If a struct's field points at something constructed alongside it, returning it by
value copies the pointer and drops the target.

Instances: QUIC transport parameters, where the encoded slice pointed into a buffer
that died with the constructor's frame; and the HTTP/3 server's listen initializer.
`EventLoopGroup` and `backend.Runtime` must be initialised in place for the same
reason.

No clean mechanical check was found. Scanning for structs holding both a fixed buffer
and a slice produces mostly false positives, because function parameter lists look the
same to a regex, and the true cases are about what the slice *points at* rather than
its type. The rule that does work is structural: **a type with a field pointing into
itself takes `init(*Self)` and offers no by-value constructor**, so the mistake cannot
be expressed.

### One name, two jobs

**Symptom: the rule is hard to state without saying "except when".** Instances:
`destination` used for both the connection ID we are addressed by and the one the
client originally chose, which §7.3 requires be kept apart; and a single key-phase
field for both directions, when the endpoint that starts a rotation writes in the new
generation a round trip before its peer follows. Both were resolved by splitting the
name, and in both cases the split made a rule that had been awkward to write become
obvious.

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

Two more came from taking the same property one layer up, to the HTTP/3
*connection* rather than its frame parser. Both were found while building that
target, and the second one only after the first was fixed — which is the argument
for the target existing.

- F5 FIXED (**major, silent hang**) `http3.connection` never reported the end of a
  request or response when the FIN arrived *after* the last frame had been consumed.
  The end was only noticed while the read loop held an item, and a FIN that arrives
  on its own finds the buffer empty. §4.1 has a client close its sending side after
  the request, and QUIC may carry that STREAM frame in a later packet — so a server
  would wait forever for a body that had already arrived in full. Nothing caught it
  because every test, and both endpoints here, set the FIN together with the last
  frame; the fuzz target's whole-versus-fragmented comparison found the same bytes
  ending the stream in one delivery and not in the other. Now a `Request` records
  whether the end was reported, and a lone FIN reports it exactly once.
- F6 FIXED (**test infrastructure, and it invalidated thirteen tests**) The
  `stress: … over random inputs` loops fed uniformly random bytes to a
  `std.testing.Smith`. That is not what a `Smith` consumes: it takes eight bytes per
  draw, reads them as a little-endian u64, and substitutes the *minimum* of the
  requested range whenever the value falls outside it
  (`std/testing/Smith.zig`). Random bytes give a value near 2^63 every time, so every
  draw returned its minimum — `boolWeighted` always false, every range always its low
  end, every `slice` empty. Thirteen stress tests were running four hundred iterations
  of one degenerate input each. Measured, not inferred: with random bytes the HTTP/3
  connection target never once produced more than one event; with the input shaped as
  small little-endian u64s it reaches request/response sequences, which is how F5
  surfaced.

## Found while adding the server sides

Nine defects, all mine, all introduced by the work that found them. This is the
most interesting batch, because they are not nine unrelated mistakes — they are
four shapes, each appearing more than once, and knowing the shapes is worth more
than knowing the fixes.

| # | Severity | Shape | What | Where |
|---|---|---|---|---|
| S1 | **major** | dangling pointer | Transport parameters encoded into a local buffer, handed to the engine as a slice, and the connection returned by value | `codec/quic/connection.zig` |
| S2 | **major** | dangling pointer | The pipeline initializer built as a local and given to an endpoint that uses it after `listen` returns | `codec/http3/server.zig` |
| S3 | **major** | one name, two jobs | A server needs the connection ID the client uses *now* for keys and the one from *before* a Retry for §7.3; one field held both | `codec/quic/connection.zig` |
| S4 | **major** | one name, two jobs | `key_phase` served both the write generation and the read generation, which differ for a round trip after a rotation | `codec/quic/connection.zig` |
| S5 | major | one rule, two places | `writeFrames` would emit HANDSHAKE_DONE but `hasSomethingToSend` did not know the frame existed | `codec/quic/connection.zig` |
| S6 | **major** | deliver before blocking | A request coalesced with the client Finished sat decrypted while the read loop blocked for a second one | `codec/tls13/driver.zig` |
| S7 | major | off-by-one at a boundary | `sealRecords` emitted one extra zero-length record, consuming a sequence number and breaking everything after it | `codec/tls13/session.zig` |
| S8 | major | wrong length prefix | §4.4.2's `certificate_list` is a *three*-byte vector, unlike most of TLS | `codec/quic/server.zig` |
| S9 | major | tail in the wrong place | `EmbeddedChannel` added its tail handler upstream of the codec, so raw bytes reached it and the codec saw nothing | `embedded.zig` |

All FIXED, each with a regression test, and each mutation checked to confirm the
test fails when the rule is removed.

### The two dangling pointers are the same mistake

S1 and S2 are both "a pointer into a frame that is about to end", and both were
invisible until a socket was involved.

S1 is the more instructive. `initClient` encoded its transport parameters into a
512-byte local, handed the engine a slice of it, and returned the connection by
value — so the slice pointed into a dead frame by the time `start` read it. **It
had been that way through the entire aioquic interop check, passing, because the
bytes happened to still be intact.** What exposed it was adding `initServer`:
that function's own 512-byte local reuses the same stack, so the ClientHello went
out carrying the *server's* parameters and the server rejected them.

The fix is not "be careful" but "make it impossible": the engines keep an inline
array, which moves with the struct and cannot dangle.

S2 is the same shape one layer up — `Server.listen` gave a datagram endpoint the
address of a local initializer, and the endpoint's reader task builds the pipeline
*after* `listen` returns. Every sans-io test passed; the first real socket
segfaulted in `Io.now`. Fixed by making the handler its own initializer, which the
server owns.

The lesson both times: **returning a struct by value is a decision.** If anything
inside it points at anything constructed alongside it, the value cannot be
returned. The `EventLoopGroup` in this repository says so in its own doc comment,
and the pool's tests still segfaulted for exactly that reason before it was read.

### One name doing two jobs

S3 and S4 both look like a missing field and are really a missing distinction.

S3: RFC 9001 §5.2 derives Initial keys from the connection ID the client is
addressing *now*; RFC 9000 §7.3 has the server report the one from the client's
*first* Initial. A Retry makes those different, and after a Retry the original
survives only inside the token — there is no other copy anywhere. One field for
both meant every handshake involving a Retry decrypted nothing while every
handshake without one worked perfectly.

S4: the endpoint that *starts* a key update writes in the new generation
immediately, but its peer is still writing in the old one until it notices and
answers. For that round trip the send phase and the receive phase differ. With one
field, the initiator's read path concluded the peer's replies were in "the current
phase", tried the new keys on packets protected with the old ones, and discarded
them — traffic stopping in exactly one direction, and only after a rotation.

Splitting the field also made §6.2's response rule expressible as what it actually
is: rotate the write keys *unless we are already writing in this generation*, which
is precisely how "the peer answering our update" is told from "the peer starting
one". A rule that is hard to state is usually a rule whose state is modelled
wrongly.

### One rule in two places, for the sixth time

S5 is the sixth instance in this repository of a rule implemented twice and the
copies diverging. The packet writer would happily emit HANDSHAKE_DONE; nothing
ever asked it to write a packet, because `hasSomethingToSend` had no clause for
it. The suite stayed green and the client simply never confirmed its handshake.

The symptom is always identical — break one copy and every test passes — which is
why the pattern is worth naming rather than fixing case by case. Previous five:
the ACK `-2`, the non-empty connection ID check, `flowControlUsed`, the three
closing gates, QPACK's 62-bit bound, and the record layer's sequence number.

### What the self-checks found

The mutation self-check earned its keep eight times this round, and three of those
findings were about the *tests* rather than the code. Those are worth listing,
because a weak test is invisible in a passing suite:

* **A test using an uninitialised buffer.** Removing DNS's "compression pointers
  must go backwards" rule left the suite green: the forward target happened to
  hold bytes that looked like another pointer, so the hop budget caught it
  instead. Zeroing the buffer makes the target a valid root label, and then only
  the rule under test can reject it.
* **A test that could not distinguish two spellings.** Relaxing the A-record length
  check from `!= 4` to `>= 4` changed nothing, because the test only used a *short*
  RDATA. A long one distinguishes them — and the long case is the dangerous one,
  since taking the first four bytes and ignoring the rest hands a caller an address
  the server never sent.
* **Five tests that had never run.** Removing the resolver's canonical-name filter
  left the suite green because `dns.zig` had no `test { _ = resolver; }`. This one
  is the worst of the three, because it is completely invisible in a passing suite:
  **the only symptom is the test count.**

Two more findings were tests that covered the wrong half of a rule: HTTP/3's
post-GOAWAY refusal was only tested through the *client's* local check, never
reaching the server path, and the pool's "do not store a dead connection" was
tested by closing the connection *after* releasing it. Both now test the case that
actually happens — a request already in flight, a connection that dies while
borrowed.

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
