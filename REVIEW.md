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

## Found by the in-process TLS pairing

**F8 FIXED (major, silent stall)** A reply that arrived while `tls.Connection`'s reader
was parked was not delivered until the client sent something else — or until the peer
closed. Found within an hour of the standard library's TLS client being pointed at our
server in-process, which is the argument for that pairing existing: `openssl s_client` and
`curl` had never provoked it, because both send a request and then read to end of stream.

The cause is a contract, not an oversight in either implementation. `tls.Client`'s reader
"writes exclusively to the buffer": its `readVec` returns *zero* and reports plaintext by
advancing `end`. And `Io.Reader.readVec` fills as much of the destination as it can — it
copies what is buffered and then, while the destination still has room, calls the vtable
again. Our read loop handed it a whole 16 KiB inbound `Buffer`, so after copying a 31-byte
answer it went straight back to blocking on the socket, holding the answer it already had.
End of stream is where those bytes finally came out, via `readVec`'s own
`EndOfStream => if (n == 0) … else 0` — which is exactly why every client checked until now
looked fine.

The fix is to say what the loop actually wants: `fill(1)`, then take everything buffered.
It blocks until there is at least one plaintext byte and returns as soon as there is one.
It also removed the `max_empty_reads` counter and its heuristic, because a record carrying
only handshake bytes no longer reaches this layer at all — std's fill loop keeps going
until plaintext appears, and a zero-length read has stopped being a thing that can happen.

Confirmed by mutation: restoring the `readVec`-into-the-whole-chunk shape fails the new
round-trip assertion. Re-checked in both directions afterwards — our client against
`openssl s_server -www` (status 200) and `curl --http2` against our server
(http=2 status=200).

Diagnosing it took five measurements, and each one eliminated a plausible story: the
server's flush does both steps and pushed exactly 53 bytes; the client received exactly
those 53 bytes; its reader consumed all of them (`seek == end`); its loop was alive, since
a second outbound message went out promptly and only that loop sends; and the delayed
bytes arrived intact. What remained was the boundary between the two readers.

## The shape that was checked, and where it was not

F8's shape — a reader that reports through its own buffer while the loop above reads only
the return value — was swept for elsewhere the moment it was understood, because that is
the difference between fixing an instance and fixing a class.

It exists in exactly one other place: `Channel.readLoop`, the plain socket path every
non-TLS connection uses. It is *immune*, and the reason is one line: the reader is built
unbuffered, so `defaultReadVec` always takes the branch that streams into the caller's
destination and there is nowhere for bytes to hide. That was stated as an optimisation —
"no intermediate copy" — and is now stated as the invariant it actually is, with an
assertion, because the next person to add a buffer there for throughput would reintroduce
F8 in the path with the widest reach.

The sweep also removed something worse than nothing. That loop tolerated a run of
zero-length reads and then declared the stream broken. Neither of its two paths can
produce a zero: `receiveBounded` maps a zero-length receive to `.ended`, since on a stream
socket that is the orderly shutdown, and the unbuffered `readVec` cannot return zero while
holding bytes. So the tolerance guarded nothing — and would have *hidden* the one case
that can arise, turning a delivery bug into sixty-four silent retries and an
`error.Unexpected`. It is an assertion now.

Separately, running the fiber backend to check all this found that three TLS server socket
tests were panicking there rather than skipping: they postdate the
`skipIfReadDeadlinesAreBroken` guard, and the fiber build had not been re-run since.
`zig build test -Dio=zio` is green again, and the README's count of skipped tests was
four and is eight.

## An unwritten contract, found by the target that was just fixed

The HTTP/3 connection target — the one whose input generation had to be repaired before it
could reach anything — found a disagreement between whole and fragmented delivery at
iteration 1263 of its stress loop. Every run before it had used four hundred, so it was
inside the machine and unreached the whole time.

The two transcripts, which the target now prints rather than merely reporting:

    whole: H:1 :method=CONNECT,:authority=fuzz.test:443,;
    split: H:0 :method=CONNECT,:authority=fuzz.test:443,;|END;

A bodyless request, and the same bytes. Delivered at once, the end rides on the field
section's `fin`; delivered in pieces, the section arrives without it and a later `body`
event carrying no bytes brings the end instead. Reported exactly once either way, with
identical sections and identical (empty) content.

**This one is not a defect, and saying so required checking rather than assuming.** Every
consumer in the repository handles both carriers — `multiplex.dispatch` finishes the stream
on either, and so do `http3.server` and `http3.client`. What was wrong is that the contract
was nowhere: `Event` said `fin` means "the stream ended with it" and never said the end may
instead arrive alone, which is precisely what the FIN fix (F5) made possible. It is written
on `Event` now, and pinned by a test that drives a bodyless request both ways and requires
exactly one end from each.

So the oracle was refined rather than the code: the *count* of reported ends is compared,
and its position is normalised away — the same treatment body bytes already had, for the
same reason. Which event carries the end is a fact about how QUIC packetized, not about the
message.

Two things worth keeping from the episode. A fuzz target should print the disagreement it
found; reconstructing two transcripts from a seed is work the next reader should not have
to repeat. And an iteration count is a measurement, not a preference: four hundred was
enough to find nothing and 1263 was needed, so the loops run 1500 now, which costs about
two minutes for the whole fuzz step against six at four thousand.

## A stated blocker that was one code path away

Sending a QUIC stateless reset was listed as absent, with a reason: §10.3 needs a key
that outlives the process, "an operational input this layer does not take". Implementing
it started by checking that claim, and the claim was false. `Options.seed` had always been
an injected parameter, and the HMAC derivation §10.3.2 recommends was already running — it
produced the tokens announced in NEW_CONNECTION_ID frames. The mechanism was complete; the
gap was `.drop => return` for an unroutable short-header packet, plus a transport parameter
that had an encoder and no caller.

This is a different failure from a documented gap that is real. A reason that sounds like a
design constraint stops anyone from looking, including the person who wrote it. The check
that would have caught it is cheap and mechanical: **for every stated blocker, name the
input that is missing and then grep for it.** Here the grep was `Options.seed`, and it was
sitting in the same file as the code that was supposedly waiting for it.

Two things were worth getting exactly right rather than approximately, and both came from
reading §10.3 rather than from what the shape of the code suggested. The size of a reset is
bounded from *both* ends — smaller than the packet that triggered it (§10.3.3, so a loop of
resets shrinks to nothing without any per-peer state) and at least 21 bytes (§10.3, or a
peer discards it as too small to be a packet) — and those two rules conflict for a trigger
of 21 bytes or fewer, which therefore gets no answer at all. The RFC names that trade-off
in the same section. And the rate limit is global rather than per remote address, departing
from §10.3.3's suggestion, because a per-address limit needs a map keyed by something the
peer chooses and this layer exists to answer unknown packets without allocating anything an
attacker can grow.

Checked from outside the test suite as well as inside it: a raw UDP probe sends a
short header addressed to a connection ID nobody issued and gets back 48 bytes where it
used to get silence — form bit clear, fixed bit set, smaller than the 64 bytes that
triggered it, the token stable across two probes while the padding differs.

## An audit of §10 and §19's MUSTs, and what it cost to look

Reading a specification against the code — rather than reading the code — has found every
protocol defect in this repository that the fuzzer did not. So RFC 9000 §10 (connection
termination) and §19 (frame types) were gone through statement by statement. Most of it was
already right, and saying which parts is the point of an audit: §10.1's idle timeout floor of
three PTOs, including the subtle second rule that only the *first* ack-eliciting packet since
a receive restarts the timer; §10.2's closing and draining periods and §10.2.1's exponential
limit on answering packets while closing; §10.3.1's constant-time comparison before parsing;
§12.4's unknown frame type; §19.7's empty NEW_TOKEN; §19.15's zero-length-ID contradiction;
§19.16 and §19.20's role checks. Twelve of those were verified individually.

Four things were not right, and the largest was not a missing branch but a missing habit.

**§11.1: a protocol violation was detected and never signalled.** A malformed frame made
`receive` return an error, the caller marked the connection finished, and *nothing was sent*.
§11.1 is one sentence: errors that make the connection unusable "MUST be signaled using a
CONNECTION_CLOSE frame". The peer's only way to learn was its own idle timeout, minutes
later. This was established with a probe rather than by reading — the connection stayed in
`.active` with no close queued, and the next `send` produced zero bytes — because the
comment in `http3/client.zig` asserted the opposite ("the connection has already recorded
the failure and queued the CONNECTION_CLOSE if one is owed"). A comment that describes what
should happen is indistinguishable from one that describes what does.

**The wire form of that close was malformed anyway.** §19.19 gives the transport variant
(0x1c) a mandatory Frame Type field — "a value of 0 ... is used when the frame type is
unknown" — and the application variant (0x1d) none. This file's parser had always read it
that way. The encoder wrote it only when the caller supplied a value, and the send path
supplies `null`. So every transport-level close was one varint short, and the reason phrase
that followed would be read from the wrong bytes. Nothing caught it because nothing had ever
encoded that shape: application closes (0x1d) are what the HTTP/3 layer sends, and the one
test that encoded 0x1c happened to name a frame type. Fixing §11.1 turned this from
unreachable into the common path, which is how it surfaced.

**§10.2.3: an application close was not converted for early packets.** Type 0x1d "MUST be
replaced by a CONNECTION_CLOSE of type 0x1c when sending the frame in Initial or Handshake
packets", with the reason phrase cleared and APPLICATION_ERROR as the code, so that
application state does not leak into packets with weaker protection.

**§12.4: a packet with no frames at all was accepted.** The loop over frames had nothing to
iterate and returned happily. It is the cheapest malformed packet there is.

One finding was not a violation, and establishing that mattered as much as the fixes.
`mapStreamError` collapsed every stream-layer fault into PROTOCOL_VIOLATION with a comment
saying a later task would carry the specific codes. §11 explicitly permits this: "a generic
error code ... can always be used in place of specific error codes". So it was never
non-conforming — but §20.1 defines those codes so a peer can tell which of its own rules it
broke, and a peer told PROTOCOL_VIOLATION for exceeding a flow control window looks for a
different bug than one told FLOW_CONTROL_ERROR. The distinction already existed in the error
type and was being discarded one line from the wire. It is carried now. The same reading
corrected one code that *was* wrong: a MAX_STREAMS frame above 2^60 reported
STREAM_LIMIT_ERROR, which §20.1 defines as a stream identifier exceeding an advertised
limit — not what happened. §19.11 names FRAME_ENCODING_ERROR, and an existing test had
frozen the wrong answer.

## Two tests that found real defects while being written

Both halves of the datagram work produced a defect *from the test*, and both were the
kind no amount of re-reading the code would have shown.

**A datagram queued and never sent.** `send` asks `hasSomethingToSend` which levels are
worth writing a packet for, and that function knew about crypto bytes, ACKs, path
challenges, connection IDs and tokens — not about the new queue. So a datagram went out
only when something *reliable* happened to be due, and an application sending nothing but
datagrams would have sent nothing at all. RFC 9221 §5's "SHOULD be sent as soon as
possible" became "whenever something else is". The end-to-end test failed with the payload
still in the queue, which is exactly what it was written to notice.

**A test blind to the thing it was testing.** The first version of the RFC 9297 test sent
its datagram on stream 0, whose Quarter Stream ID is also 0 — so a mapping that omitted the
prefix entirely produced identical bytes and the test passed. The mutation that removes the
prefix survived, which is the signal that the test was wrong rather than the code right. It
uses the second request stream now, and asserts the quarter is 1 before relying on it.

A third finding came from a compiler assertion rather than a test, and is worth recording
because it did its job: the transport parameter decoder tracked duplicates in a `u32`
bitmap indexed by parameter identifier, with `assert(id_value <= 0x10)` to say so. RFC
9221's identifier is 0x20. The assertion fired on the first datagram-enabled handshake
instead of a bit silently shifting out of range, which is the difference between an
assertion that documents an invariant and a comment that claims one.

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

### An assertion where a type would have done

**Symptom: the mutation that should break it does not.** Making a bound explicit is only
half the job; where it is enforced decides whether it can be got wrong again. HTTP/2's
writability transitions were bounded by a runtime assertion, and shrinking the caller's
buffer back to its old size failed *no test* — the assertion lived in the callee, and the
caller's array was still whatever the caller said. Changing the signature to demand
`*[max_writability_transitions]Writability` turned the same mutation into a compilation
error: `expected type '*[64]T', found '*[8]T'`.

The general form: when a caller and a callee must agree about a size, an assertion asks them
to agree at run time and a type makes them agree at compile time. The second is the one that
survives someone editing only one side. This was found by self-checking the fix rather than
by review — the mutation not failing is what said the check was in the wrong place.

### A rule enforced before the data it displaces

**Symptom: the same bytes mean different things depending on how the network split them.**
HTTP/3's critical-stream rule — §6.2.1 makes closing a control stream a connection error —
was checked before the delivery's bytes were processed. A GOAWAY arriving with the FIN
therefore failed the connection with the GOAWAY unparsed, while the identical bytes split
across two deliveries produced the GOAWAY event *and then* failed. The connection's account
of what its peer had said depended on fragmentation, which is exactly what this repository's
central fuzz invariant forbids.

Data that arrived before a close is data that was received; the close is what happens next.
The general form: when a rule ends a connection, apply it *after* the input in hand, or the
rule silently rewrites history. Found by the fuzzer within one run of `-Dio=` finally
reaching the fuzz harness — which is its own finding, below.

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
- F7 FIXED (**major**) §7.1 was unimplemented: "When a stream terminates cleanly, if the
  last frame on the stream was truncated, this MUST be treated as a connection error of
  type H3_FRAME_ERROR." A stream ending mid-frame was simply the end. Worse after F5,
  which made that end *reportable*: the application was told a message had finished when
  its sender had promised bytes it never sent. Found by reading §7.1 next to the code F5
  had just changed, and confirmed by a test before it was fixed. `frame.Parser.midFrame`
  now answers "between frames or not" in one place, and the check runs where a clean end
  is concluded.

  The mutation self-check earned its keep twice on this one. Reducing `midFrame` to
  `state != .type` passed the suite, which exposed that a truncated frame *header* — a
  two-byte type varint with one byte delivered — had no test. And writing the predicate
  in the first place got it wrong in the other direction: it also treated a non-empty
  accumulation buffer as "part-way through", when that buffer deliberately still holds
  the *completed* frame's payload, because the item just returned borrows it. A peer
  whose HEADERS frame arrived in two QUIC packets before a clean end would have been
  told H3_FRAME_ERROR for a legal delivery. Both directions now have a test.
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

## Two lessons about the work rather than the code

Recorded here because both cost real time in this round and neither is a property of Zinet.

**A self-check needs its own backups, named for the file rather than its basename.**
Mutation self-checking works by breaking the fix on purpose and requiring the new test to
fail. That means copying files aside and restoring them, and copying to
`/tmp/<basename>.bak` collided `http2/connection.zig` with `http3/connection.zig` — one
overwrote the other, and the restore put HTTP/3's contents into HTTP/2's file. Worse, the
recovery attempt used `git checkout <file>`, which discarded HTTP/3 changes that were
finished but not yet committed. Both files were recovered from the surviving copies and the
patches redone, but the rule is cheap and absolute: back up to an explicitly named path per
file, and restore from the backup, never from git, while uncommitted work exists.

**A flaky test is worse than a missing one, and its flakiness is usually the diagnosis.**
The TLS handshake timeout added in this round passed, then failed on a loaded machine with
`ConnectionResetByPeer` instead of `HandshakeTimeout`. The cause was not the machine: the
client compared the clock to decide whether a zero-byte read meant a timeout, and a timer
firing a hair before the nanosecond it was given made it conclude "reset". `readSocket`
already reported an orderly zero-byte read as `error.EndOfStream`, so zero could only ever
mean the deadline and the comparison was both redundant and wrong. The flake was pointing at
a real defect in the fix, one that would have mattered in production at exactly the moment a
server was busiest.

**A measurement's build mode is part of the measurement.** The cost of a TLS handshake was
measured with `openssl s_time` against `zig-out/bin/tls13_server` and came out at 4.3 ms. That
binary comes from `zig build examples`, which honours `-Doptimize`, whose default is Debug — so
an unoptimized server was being compared against OpenSSL's optimized one. In `ReleaseFast` the
same server does 0.83 ms and is slightly *faster* than `openssl s_server`. Two of the three
conclusions in TLS.md were therefore wrong, including a "2.8 ms remainder where this
implementation is actually slow" that does not exist, and a recommendation to go and profile it.
Nothing in the server's output said which build it was, and nothing in the method required an
optimized one.

The correction is not "be careful". Benchmarks registered in `build.zig` are built `.fast`
regardless of `-Doptimize`, so the same measurement expressed as `bench/tls_bench.zig` could not
have gone wrong that way — which is why the handshake measurement now lives there, and why it
reports the server's and the client's engine cost separately rather than one aggregate that hides
which side is being paid for. Every server example additionally prints its build mode on startup.
This is the same shape as `zig build mutate`: a habit that produced a wrong answer replaced by a
build step that cannot.

Worth stating because it is the reason to trust the new number: the engine benchmark and the
socket measurement were taken through different paths, one of them with an external client, and
they agree to within a microsecond on the one difference both can see — 80 µs saved by signing
with Ed25519 instead of ECDSA P-256.

## What the HTTP/2 and HTTP/3 benchmarks found

Three defects, none of which any test, fuzz target or interop run had reached, all found within
an hour of pointing a load generator at the HTTP/3 server. They belong together because they
share a cause: every existing check sends a handful of requests per connection, and all three
faults need either a hundred requests or thirty-two of them at once.

**An HTTP/3 connection stopped serving after exactly `initial_max_streams_bidi` requests.**
§3.1 puts a stream's send side into `data_recvd` when its FIN is *acknowledged*, so the last
moment a stream can become finished is inside `onPacketAcked` — and nothing reaped it there.
`maxStreamsUpdate` decides how much credit to grant from how many streams are *live*, so a
server that never forgot a finished stream never raised the peer's limit. The connection served
100 requests, went silent, and sat there until its idle timeout. Nothing failed; the throughput
was 31 req/s instead of 35 800. Fixed by reaping on acknowledgement, which also stops a
long-lived connection accumulating every stream it ever served.

**An application refused for want of stream credit could never learn it had some.** The
delegate's events were all about streams that exist — `headers`, `body`, `stream_reset` — so a
client whose every stream had closed had no callback left. The credit arrived and changed
nothing observable. There is now a `stream_credit` event, emitted only when a MAX_STREAMS frame
actually *raises* the limit, because a peer may repeat one it has already sent and that should
wake nobody.

**Asking for one stream too many destroyed the connection.** `openStream` handed its own local
limit check to `mapStreamError`, which closes the connection — so an endpoint that wanted a
stream the peer had not permitted yet told that peer it had violated STREAM_LIMIT_ERROR and shut
down. It is the exact inversion of §4.6 and §19.14: the peer exceeding *our* limit is a
connection error, and *us* wanting more than the peer has allowed is a wait, whose frame is
STREAMS_BLOCKED. This was the worst of the three, because it is self-inflicted and because the
peer is blamed for it.

Two of the three are now unit tests at the transport level, both verified by reverting the fix
and watching them fail. The third is exercised by the benchmark, and its event exists because
the benchmark could not be written without it.

The lesson is not about QUIC. Every one of these needed *volume* to appear, and the entire test
suite is built from small, precise exchanges — which is the right shape for checking a protocol
rule and the wrong shape for checking that a connection still works on its ten-thousandth
request. A benchmark is a load test that happens to report numbers; that it reports numbers is
why it gets run, and finding these was worth more than the numbers were.

## The benchmark that measured itself, twice

Two of the three HTTP protocols looked slower than HTTP/1.1. Neither was.

**Every benchmark ran on `DebugAllocator`**, because a leak failing the run is worth having. It
also returns pages to the kernel as it frees them — and HTTP/2 and HTTP/3 allocate a stream
channel, a pipeline and a handler per request, where an HTTP/1.1 connection allocates a request
arena and nothing else. A profile of the HTTP/2 server settled the size of it: **51 % of the
samples in which the server was doing anything were in the allocator**, `__munmap` alone 7 % of the
whole profile, against 26 % in `readv` and `__sendmsg` and 11 % in the protocol. Switching to
`smp_allocator` took HTTP/2's single-request cost from 98 µs to 59 µs — exactly HTTP/1.1's — and
eight connections of 128 streams from 142.8 k to 396.5 k req/s. HTTP/1.1 gained almost nothing,
which is the asymmetry in one sentence.

This is the second time this repository has published numbers dominated by the harness's own
choice: the first was measuring a TLS handshake against a Debug build. The pattern is the same and
so is the correction — make the honest configuration the default and put the other behind a flag,
rather than relying on remembering. `bench/allocator.zig` is the default; `leakcheck` is the flag.

**The other half was real, and it was a policy inverted.** With the allocator out of the way,
HTTP/3 was still bounded well below its CPU, and the benchmark's refusal counter said by what:
stream credit. `maxStreamsUpdate` announced a raised limit only when it could grant at least half
the allowance more, and the most it can *ever* grant is `initial - live`. A stream stays live until
its FIN is acknowledged, so on a busy connection most of the allowance is live and the limit
stopped moving at all — one connection with 128 requests in flight served 45 k req/s and spent the
rest of its time being told no. The trigger is now the credit the *peer* has left, with a small
floor on the increment so a frame is not spent per stream close, and the default allowance is
chosen against `streams.max_concurrent` — the hard cap on stream state — instead of being a round
number. 45 k became 129 k, and the refusals went to zero.

Worth separating the two, because they are different kinds of finding. The first was the harness
lying about the code. The second was the code being wrong in a way only the harness could show:
every test in this repository sends a handful of requests, and this needed a hundred in flight
before the rule that governs them misfired.

## What comparing against another framework found

[velo](https://github.com/blue-blaze/velo) is a pure-Zig web framework on `std.Io` with the same
influences and no third-party dependencies — near enough a peer that its numbers are worth being
measured against, and it ships a load generator with a pipelining depth flag. Running that
generator against both servers, one at a time on the same machine, found something this
repository's own benchmarks could not have.

**At pipeline depth 64 the two served within 5 % of the same requests per second, and this server
spent 9.0 µs of CPU per request against velo's 1.6 µs.** The throughput column hid it because the
generator was near saturation; the CPU column is the one that survives a saturated client, which
is exactly why velo's own README leads with it.

The cause was one `sendmsg` per response. `ctx.writeAndFlush` queues bytes and then a flush, and
the writer task honoured every flush — so 64 pipelined responses cost 64 syscalls where one would
do. The writer now takes everything already queued in one pass and flushes once: 294 k req/s
became 440 k, CPU per request 9.0 µs became 1.51 µs, and the p99 halved. That also puts this server
ahead of velo at 8 connections and level with it at 64.

Both wrong turns on the way are worth keeping, because each is a general shape.

**A counter that is not updated atomically with the thing it counts cannot answer "is the queue
empty".** The first attempt read the channel's `pending` counter to decide whether more work was
queued. `pending` is incremented *after* `putOne`, so the writer can take an item and decrement
before the producer has counted it; the counter momentarily reads non-zero on an empty queue, and
a writer that trusts it skips the flush and then blocks holding the only copy of the response.
Every request timed out. The queue's own `get` answers the question atomically because it is the
only thing that can.

**A batching rule must not look past the end of the connection.** The second attempt deferred
every flush to the end of the batch. When a batch was `[flush, close]` the deferred flush ran in
the close prong — by which time the socket was no longer writable — and a closing handshake's
farewell went missing. Two existing tests caught it, which is the system working: the rule is now
narrow (defer only while more *data* follows in the same batch) and it is in the mutation
catalogue, so the next person to widen it has to argue with a failing test rather than with a
comment.

One unrelated flake surfaced while verifying all this, and it is recorded because its diagnosis is
the interesting half. The HTTP/3 migration test asserts that the client's local address *changed*
after `migrate`, which is what makes the run a migration rather than a reopened socket. Under the
load of a full `zig build check` it failed once: the kernel handed back the ephemeral port the
previous socket had just freed. That is a legal choice, and a move to the same address is not a new
path — so the run was inconclusive rather than wrong, and the test now retries a bounded three
times and names the cause if it never gets a different port. The bound is small deliberately: §9.5
spends a spare connection ID per move and `active_connection_id_limit` is 4, so an unbounded retry
would trade one flake for another.

The general lesson is about the *choice of metric* rather than about writes. Every benchmark in
this repository reports throughput and latency, and both were within noise of a competitor while a
5.5x difference in cost per request sat underneath them. A saturated client makes throughput a
measurement of the client; CPU per request is what stays a measurement of the server.
