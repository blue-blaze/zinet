# HTTP/3 in Zinet

HTTP/3 runs over QUIC, and that one sentence decided the shape of everything below.
Netty — the project this framework translates — does not implement QUIC:
`netty-incubator-codec-quic` is a JNI binding to Cloudflare's Quiche, and
`netty-incubator-codec-http3` sits on that binding. So for this half of the work there
was no upstream shape to translate, only five RFCs: 9000 (transport), 9001 (TLS),
9002 (recovery), 9114 (HTTP/3), 9204 (QPACK). Under the zero-dependency rule, binding
to a C library was not an option; the transport had to be written.

**What works:** HTTP/3 in *both* directions, end to end. The QUIC transport underneath —
handshake, packet protection, streams with three levels of flow control, loss detection,
NewReno, connection lifecycle, connection migration, stateless reset — is checked against
RFC test vectors byte for byte and interoperates with aioquic (a Python implementation
sharing no code with this one) in CI on every run, in both roles: our client against its
server *and* its client against our server. Either direction exercises the TLS 1.3
handshake, packet protection, loss recovery, the control streams, QPACK and the request
semantics against someone else's reading of the same five documents.

**What did not, and now does:** the server role. This section used to say it was blocked
"for a reason that is upstream and specific" — there is no `std.crypto.tls.Server`, and a
QUIC server must sign every handshake. That stopped being a blocker when the TLS 1.3
handshake here was written, which QUIC needed anyway; see [TLS.md](TLS.md). What remains of
the constraint is narrower and still true: a server here can present ECDSA P-256 or Ed25519
certificates but not RSA ones, because `std.crypto.Certificate.rsa` verifies RSA signatures
without being able to produce them.

A short list of protocol features is still deliberately absent; each is refused explicitly
rather than half-built — see [Deliberately not done](#deliberately-not-done).

## Contents

* [Why QUIC had to be written, and what std did provide](#why-quic-had-to-be-written-and-what-std-did-provide)
* [The layers](#the-layers)
* [Verified against whom](#verified-against-whom)
* [The rule that kept being the bug](#the-rule-that-kept-being-the-bug)
* [The server side](#the-server-side)
* [QPACK at zero capacity is not a stub](#qpack-at-zero-capacity-is-not-a-stub)
* [Where time and randomness come from](#where-time-and-randomness-come-from)
* [Deliberately not done](#deliberately-not-done)

## Why QUIC had to be written, and what std did provide

The standard library has no QUIC. What it does have is every cryptographic *part*
QUIC needs: `std.crypto.tls.hkdfExpandLabel` is public and generic over the HKDF
type — it is exactly RFC 9001 §5.1's derivation function; the three AEADs are all
present; `std.crypto.core.aes` exposes the raw block operation header protection
needs; X25519 and certificate parsing are there. Before any code was committed, RFC
9001 Appendix A.1 was reproduced byte for byte from those parts alone, which is what
turned "should be possible" into "is".

What std lacks is a *shape*: `std.crypto.tls.Client` is a blocking, one-shot
handshake with its own record layer and no way to export secrets. QUIC needs the
opposite — handshake messages without record framing, carried in CRYPTO frames at
three encryption levels, with the handshake and 1-RTT secrets handed out as they
become derivable. So `src/codec/quic/` contains a TLS 1.3 handshake *engine*
(`tls.zig`, `handshake.zig`, `verify.zig`, `client.zig`) built from std's parts:
std's HKDF, std's hashes, std's AEADs, std's X25519, std's certificate parser — and
none of std's `tls.Client`. The key schedule is verified against every intermediate
value RFC 8448 publishes, including its genuine RSA-PSS `CertificateVerify` signature
over a transcript this code computed itself.

## The layers

`src/codec/quic/` and `src/codec/http3/` are separate on purpose: they are different
layers from different RFCs, and QUIC can carry other things. Each layer is testable
without a socket; exactly one file in the HTTP/3 stack touches one.

| File | RFC | What it decides |
|---|---|---|
| `quic/varint.zig` | 9000 §16 | Non-minimal encodings are *legal* and accepted |
| `quic/packet.zig` | 9000 §17 | Deliberately does **not** parse packet numbers — header protection encrypts them, so parsing is two-phase |
| `quic/frame.zig` | 9000 §19 | Unknown frame types are a connection error (the opposite of HTTP/2) |
| `quic/crypto.zig` | 9001 §5 | AEAD before header protection on send, the reverse on receive; §6.6's usage limits live in `Keys`, where no code path can bypass them |
| `quic/tls.zig` | 8446 §7.1 | The key schedule, verified against RFC 8448 |
| `quic/handshake.zig` | 8446 §4 | Messages and extensions; length prefixes are reserved and back-filled, never hand-computed |
| `quic/verify.zig` | 8446 §4.4 | Certificate chains and CertificateVerify, with injected time |
| `quic/transport.zig` | 9000 §18 | Transport parameters; the connection-ID entries are an *authentication mechanism*, not bookkeeping |
| `quic/cid.zig` | 9000 §5.1 | Connection ID sets — two types for the two directions, because they run different checks |
| `quic/stream.zig` | 9000 §2–3 | One stream: two state machines, reassembly, stream-level flow control |
| `quic/streams.zig` | 9000 §3.2, §4 | Implicit creation, the connection window, stream counts |
| `quic/recovery.zig` | 9002 | Pure time arithmetic: ACK ranges, RTT, loss, PTO, NewReno — knows nothing about packets' contents |
| `quic/connection.zig` | 9000 | Datagrams in, events out; the §10 lifecycle; no sockets |
| `http3/frame.zig` | 9114 §6–7 | The incremental parser — HTTP/3 frames ride streams, so reframing is back; DATA streams unbuffered |
| `http3/qpack.zig` | 9204 | The static table, both literal forms, and the instruction streams, at zero table capacity |
| `http3/connection.zig` | 9114 | SETTINGS, the stream grammar, field validation, GOAWAY; requests out, responses in |
| `http3/client.zig` | — | The one file with a socket: the connection mounted on a `datagram.Endpoint` |

Two structural facts carried more weight than any single rule:

**QUIC abolishes reframing; HTTP/3 brings it back.** A QUIC frame is parsed from
exactly one packet's payload — the datagram is the message boundary, and
`quic/frame.zig` never buffers. An HTTP/3 frame arrives in however many pieces the
peer's packetizer chose, so `http3/frame.zig` is incremental, buffers everything
except DATA (which streams, unbounded, because bodies are), and is held to the
repository's chunk-independence property by fuzzing: one byte at a time must produce
exactly what one call produces, including agreement on whether and where parsing
fails.

**Ignore-rules point in opposite directions at adjacent layers.** Unknown QUIC frame
types are a connection error (§19: extensions are negotiated, so an unknown type
means the peers disagree about what was agreed). Unknown HTTP/3 frame types must be
ignored (§9: extensions deploy by just sending them, and grease keeps that path
honest) — except the four values HTTP/2 used for PRIORITY, PING, WINDOW_UPDATE and
CONTINUATION, which are reserved as errors to catch a peer that translated HTTP/2
frame for frame instead of reimplementing. Unknown transport parameters: ignore.
Unknown HTTP/3 settings: ignore, except HTTP/2's four leftovers: error. Every one of
these has a test asserting its direction, because each is exactly the mistake a
developer carrying habits from the neighbouring layer would make.

## Verified against whom

Every protocol in this repository is checked against someone else's code, and the
QUIC stack extends that practice downward to someone else's *numbers*:

* **RFC 9001 Appendix A**, byte for byte: the Initial secrets (A.1, including the
  intermediate PRKs — comparing only the final keys would let a salt error and a
  label error cancel), the complete protected client packet (A.3, all 135 bytes,
  whose decrypted payload is then fed to the frame parser — the test is of a usable
  stack, not of hex strings), and the ChaCha20 short packet (A.5).
* **RFC 8448**, every published intermediate of the key schedule, plus its genuine
  RSA-PSS CertificateVerify signature verified over a self-computed transcript.
* **RFC 9204 Appendix B.1**, the RFC's own encoded bytes — a round trip cannot see
  an error that is symmetrical in encoder and decoder; the RFC's bytes can.
* **aioquic**, in CI on both platforms: a full connection and request against an
  implementation sharing no code, no language and no author with this one. The
  fixture tests are the same exchange against this repository's own second
  implementation (`PacketServer` derives its own keys from the same RFCs through
  separate code paths); aioquic is the check that both readings weren't wrong
  together.
* The end-to-end UDP test **drops the first ClientHello on purpose**, because that
  is the case that separates a working timer path from a decorative one: a lost
  ClientHello can never be declared lost by the ACK-driven mechanism — the ACK would
  come from the very server that never received it. It forced the PTO probe to carry
  data (§6.2.4) rather than just a PING, which was a real defect the happy path
  would never have shown.

Vectors are fetched from the RFC text, never recalled from memory. That rule was
paid for twice (two wrong bytes in A.5, one misremembered clause of §7.2) before it
became a rule.

## The rule that kept being the bug

Five times during this work, a deliberate mutation of load-bearing arithmetic left
the entire test suite green. The symptom was identical every time: **the same rule
was implemented twice, and the surviving copy covered for the broken one.**

1. The ACK range `-2` (§19.3.1) — validation in the parser, output in the iterator.
2. The CID set's non-empty check — a branch duplicating what §19.15's
   `retire_prior_to <= sequence_number` already enforces.
3. `flowControlUsed` — `final_size orelse highest_offset`, two values §4.5 makes
   provably equal once a final size exists.
4. The closing-state send gates — three copies across `send`,
   `hasSomethingToSend` and `writeFrames`.
5. QPACK's 62-bit integer bound — once inside the decode loop, once (dead) after it.

Each fix was the same: collapse to a single implementation, name the inverse
operation and put it adjacent (`Ack.descend` / `Ack.gapTo`), test the pair against
each other, and document where the deleted copy used to be. The mutation self-check —
break the rule, demand a precise test failure, restore from a backup copy — is how
all five were found, and it caught weak *tests* four further times (assertions that
held whether or not the code under test ran). A self-check that passes is a finding
about the test, not permission to move on.

The other recurring defect class was borrowed buffers: an inbound string retained
past the life of the buffer it points into. It appeared here twice more (the
negotiated ALPN; HTTP/3 frame payloads used after `consume` compacted the reassembly
buffer they borrow from), after two earlier appearances in HTTP/2. It is why events
in this stack carry stream IDs and never slices, and why every inbound string is
copied at the boundary.

## The server side

There is one, and the constraint that used to prevent it survives in reduced form:
**the standard library can verify RSA signatures but cannot produce them** —
`std.crypto.Certificate.rsa` has no signing half. A TLS 1.3 server signs a
`CertificateVerify` on every handshake, so a server here presents ECDSA P-256 or
Ed25519 certificates and cannot present an RSA one. That is a deployment
limitation, not a missing feature, and it is reported at certificate-load time as
`error.UnsupportedKeyType` rather than as a handshake failure later.

Three files make up the server, and the division is the same "no sockets until the
last layer" the client side follows:

* **`quic/acceptor.zig`** — what a server does *before* a connection exists.
  §8.1's whole shape is that no state is created until an address is validated, and
  the state that would have been created is handed to the client to hold, as a
  token. So this file allocates nothing: it classifies a first packet into drop,
  Version Negotiation, Retry, or accept. Tokens are HMAC-authenticated over their
  own contents — address, expiry, kind, connection ID — and the checks happen in
  that order, MAC first, because reading the address or the expiry before it is
  acting on attacker-controlled bytes. The signing key is a parameter, since a
  server that generated one internally could not be a fleet member.
* **`quic/connection.zig`** — the same `Connection` as the client, with
  `initServer`. Almost all of RFC 9000 is role-neutral, so the handshake is a union
  whose methods forward and the ten call sites that drive it do not know which end
  they are. What genuinely differs is marked with the section that makes it so: the
  key halves swap, §14.1's anti-amplification limit applies on the sending side,
  and §19.20's HANDSHAKE_DONE travels one way only.
* **`http3/server.zig`** — one UDP socket, many connections, demultiplexed by
  Destination Connection ID, each request stream getting its own `Pipeline` through
  `http3/multiplex.zig`.

**§14.1's anti-amplification limit is the rule most worth reading twice.** Until
the client's address is validated a server may send at most three times what it
received, and the credit is counted *before* anything is parsed. Counting only
what turns out to be valid would let an attacker buy amplification with garbage,
which is the exact thing being prevented. The 1200-byte padding obligation yields
to the budget rather than breaking it — §14.1 says outright that a server may be
unable to expand a datagram.

The server's shape differs from every other server in this repository, and the
reason is structural rather than incidental. A TCP server gets a new socket per
connection and can give each one a task blocked in a read. A QUIC server gets one
socket for everybody, so demultiplexing is the application's job rather than the
kernel's, and every connection is driven from the endpoint's single reader task.
The threading model's guarantee survives the change: "one task per connection, so
handler state needs no locks" becomes "one task for the endpoint, so no
connection's state is touched concurrently". Nothing in a stream handler can tell
the difference.

Interop runs in both directions in CI. Our client fetches from aioquic's server,
and aioquic's client fetches from ours — which is the harder direction, because
everything a server does and a client does not is on that path: issuing connection
IDs, signing a `CertificateVerify`, the amplification limit, and the connection ID
demultiplexing.

## QPACK at zero capacity is not a stub

QPACK is HPACK redesigned for a transport that reorders — the dynamic table moves
its updates onto dedicated unidirectional streams and stamps each field section with
the table state it requires. This implementation runs the mode RFC 9204 defines as
the *default*: `SETTINGS_QPACK_MAX_TABLE_CAPACITY` of zero, no dynamic table on
either side. §3.2.3 sets every connection's capacity to zero until a SETTINGS says
otherwise, and obliges an encoder facing zero to send nothing on its encoder stream.
Every conforming peer therefore interoperates with this endpoint by construction —
aioquic did, first try.

Within the mode, everything is implemented and policed: the 99-entry static table
(Appendix A verbatim, indexed from 0 where HPACK indexes from 1), both literal
representations, Huffman (shared with `http2/huffman.zig`, since §4.1.2 adopts RFC
7541's table unmodified — but *not* the prefixed integer, which QPACK requires at 62
bits where the HTTP/2 implementation is deliberately 32), the never-indexed bit
carried through the type system in both directions, the field-section size limit
enforced field by field during decoding, and the instruction streams held to the
zero-capacity promise: the peer's encoder stream must exist and must stay empty, and
a Section Acknowledgment acknowledges work that never happened. The dynamic table is
a compression-ratio feature, never a requirement, and the seam for adding it is
explicit (instruction parsing is separate from the zero-capacity judgements).

## Where time and randomness come from

Nothing below `http3/client.zig` reads a clock, and nothing anywhere reads a global
CSPRNG. The QUIC connection takes time through `setTime`/`nextTimeout`/`onTimeout`,
which is what makes every rule in RFC 9002 testable against a schedule the test
writes — RTT smoothing, the §5.3 floor that stops a peer's claimed `ack_delay` from
destroying the estimate, loss thresholds, PTO backoff, the idle timeout, the §10.2
terminal periods. Randomness (connection IDs, the handshake seed) is a parameter;
`Client.connect` draws it from `Io.randomSecure` when the caller doesn't, and tests
inject a seed and get reproducible connections.

At the socket, the endpoint's `tick_interval` (added to `DatagramChannel` for this,
mirroring `Channel.Tick`) puts a deadline on the read, because a peer going quiet is
exactly when the timers matter and exactly when no datagram will arrive to run them.
A tick is only a wakeup; whether a timer fired is the connection's decision against
its own injected clock.

## Deliberately not done

Each of these is refused explicitly — an error or a documented absence — rather than
half-implemented, because a feature that works only against peers that never
exercise it is worse than one that is honestly absent.

| Absent | Why, and what the refusal looks like |
|---|---|
| RSA server certificates | Upstream: std cannot produce RSA signatures. The server role itself exists; `error.UnsupportedKeyType` at load time is the refusal. |
| HelloRetryRequest | `error.HelloRetryRequestUnsupported`. Correct support needs §4.4.1's transcript replacement; a half version fails only against servers that send HRR. RFC 9001 §4.7 points QUIC at its own Retry instead — which *is* implemented, including the §17.2.5 integrity checks. |
| 0-RTT | Not attempted. The §3.2.3 QPACK interaction and the anti-replay obligations arrive with it. |
| Session resumption | Not attempted, and a NewSessionTicket is therefore ignored — but only since it was found to be *fatal*. `quic.client` treated every post-handshake TLS message as a violation, so every connection to an OpenSSL-based server died on its first 1-RTT packet, silently. §4.6's messages are legal at any time; the ticket is now ignored and a TLS KeyUpdate stays fatal because §6 of RFC 9001 requires it. See REVIEW.md. |
| QPACK dynamic table | The zero-capacity mode above; a ratio feature with an explicit seam. |
| ~~Connection migration~~ | Mostly done, and the row is kept because what is missing is a design change rather than a branch. Working: §8.2.2 responses (unconditional, expanded to 1200, sent once); §8.2.1 challenges, repeated until answered, abandoned on §8.2.4's timer; §9.3 detection — a non-probing packet, from a new path, carrying the highest packet number, only after the handshake is confirmed — with §9.1's probing/non-probing split doing the work it was defined for; §9.3's mandatory validation of the new address; §9.4's congestion and RTT reset, with §9.4's port-only exception left to the caller that holds the addresses; §5.1.1 spare connection IDs, issued with stateless reset tokens and routed before they are announced. **And now §9.2 client-initiated migration**: `quic.connection.migrate` refuses before the handshake is confirmed (§9), refuses when the peer sent `disable_active_migration` (§18.2), refuses without a spare connection ID because §9.5 forbids reusing one from two local addresses, changes the ID and retires the one left behind (§9.5 with §5.1.2), resets congestion state immediately rather than on validation — §9.4's "on confirming a peer's ownership" is about a peer that moved, and here the peer has not — and arms a challenge for the new path (§8.2). `http3.client.Client.migrate` is the socket half: `std.Io` cannot rebind, so the endpoint is replaced, and the order is load-bearing — stop the old reader, migrate, open the new one, because doing it the other way would race the reader task for connection state and the one-reader-task rule is what makes handler state need no locks. The packet the move produces carries RETIRE_CONNECTION_ID, which §9.1 does *not* classify as probing, so the peer sees the migration under §9.3 without waiting for application data — checked over real sockets against our own server. **Absent: §9.3.3's probe of the previously active path**, which contains an off-path attacker forwarding copies of packets. It needs `send` to say which path each datagram belongs to, and `send` produces one datagram with one implicit destination. And `preferred_address` (§9.6), a server-initiated move, independent of the above. |
| ~~WebSocket over HTTP/3~~ | **Done** (RFC 9220), and it needed less protocol code than the row it replaced suggested. RFC 9220 delegates the semantics to RFC 8441, which delegates to RFC 6455 — "using the HTTP/2 stream from the CONNECT transaction as if it were the TCP connection" — so the binding is a handshake check and a mount point for `websocket.FrameCodec`, the same codec the HTTP/1.1 upgrade path uses. What the delegation makes easy to get wrong, and what `checkRequest` therefore states: `Sec-WebSocket-Key` and `Sec-WebSocket-Accept` are **not** processed (RFC 8441 §5 — `:protocol` superseded them, and computing an accept hash would be inventing a requirement); `Connection` and `Upgrade` MUST NOT appear; `:scheme`, `:path` and `:authority` stop being optional once `:protocol` is present (§4); and masking is unchanged, because §5 excludes only RFC 6455 §10.8 — so a client still masks and a server still refuses masked frames. An unknown `:protocol` gets 501 as §3 recommends. Bytes that arrive before the 200 are dropped rather than fed to the codec: §5 puts the connection in OPEN only after the handshake, and forwarding them would let a peer drive the frame state machine on a stream about to be refused. Checked end to end over two real HTTP/3 connections with the real encoder on both sides. **Not done: unreliable WebSocket messages**, which need HTTP Datagrams — see the row below. RFC 9220 itself does not use datagrams, so this binding is complete without them. |
| ~~HTTP Datagrams (RFC 9297)~~ | **Done, and it needed RFC 9221 underneath first** — which is the part reading RFC 9297 alone makes easy to miss. The transport now has the extension: `max_datagram_frame_size` (0x20), the 0x30/0x31 frame types with the LEN bit, `sendDatagram`/`readDatagram`, and §3's two receive-side MUSTs — a DATAGRAM frame arriving when we advertised nothing, or one larger than we advertised, is a PROTOCOL_VIOLATION, and the size compared is the whole frame including type and length, because that is what §3 defines the parameter as. §5.2's "not retransmitted upon loss detection" is structural rather than checked: every other payload leaves a note in the packet's record so a loss can re-send it, and a datagram deliberately leaves none, while still being ack-eliciting. §5.3 gives them no flow control, so both queues are bounded by count and drops are counted — the only thing between a peer and this process's memory is a limit stated here. On top of that, §2.1's mapping: SETTINGS_H3_DATAGRAM (0x33) negotiated in both directions as §2.1.1 requires *and* the transport parameter, a Quarter Stream ID in front of every payload, H3_DATAGRAM_ERROR (0x33) for a payload too short to parse or a quarter above 2^60-1, silent drops for a stream that does not exist or whose receive side has closed, and a refusal to send once the send side is closed. **What is not done: the Capsule Protocol (§3)**, which is what would carry HTTP Datagrams over HTTP/2 and HTTP/1.1 and over HTTP/3 when DATAGRAM frames are unavailable. It is a stream encoding of the same payloads rather than a different feature, and §3.5 notes an extension defined only over transports with DATAGRAM frames "might not need a stream encoding". **Verified in-process on both roles with six mutations, and not yet against another implementation**: no endpoint in this repository turns the setting on — §2 requires an HTTP extension that defines datagram semantics, and the WebSocket binding above is the reliable kind — so there is nothing for the aioquic scripts to exchange datagrams with yet. Stated rather than implied, because "the handshake still interoperates" is not the same claim. |
| ~~Stateless reset~~ | **Done, and the row is kept because the reason it was absent was wrong in a way worth recording.** Receiving one worked already: a reset is indistinguishable from a short-header packet until its last 16 bytes are compared against a token the peer gave us, so `quic.connection` checks that *before* parsing rather than after failing to (§10.3), then enters draining and sends nothing further (§10.3.1, because a close aimed at a peer with no state only provokes another reset). Sending one was described here as blocked on "a key that survives a restart — an operational input this layer does not take". That was false: `Options.seed` has always been that input, and the HMAC derivation §10.3.2 recommends was already being used for the tokens announced in NEW_CONNECTION_ID frames. What was actually missing was one code path — an unroutable short-header packet returned instead of being answered — plus the `stateless_reset_token` transport parameter, without which a reset is recognised only for IDs announced in a later frame, which is to say not for a connection that never needed a spare. Both are in. The size rules are one function (`acceptor.statelessResetLen`): every reset is strictly smaller than the packet that triggered it, so §10.3.3's looping ends structurally rather than by watching for it, and a trigger of 21 bytes or fewer gets no answer at all because no size is both valid and smaller — a trade-off §10.3.3 names. A global rate limit bounds reflection at a spoofed address; per-address limits would need a map keyed by something the peer chooses, which is the one thing this layer refuses to allocate. **The caveat that remains is §21.11's**: sharing a seed across a fleet means an instance without state can reset a connection another instance is still serving, so packets for a given connection ID must keep arriving at the instance that holds it. |
| ~~Extended CONNECT (RFC 9220)~~ | **Done**, negotiation and binding both — the row above records the WebSocket half, which this one used to say was "not yet". `SETTINGS_ENABLE_CONNECT_PROTOCOL` (0x08) is now sent by a server whose application opts in — off by default, because the setting is a promise about what this endpoint will *serve*, and announcing it while refusing every extended CONNECT tells peers something untrue. A client refuses to send one before the setting arrives, rather than trying and hoping: RFC 8441 §3 explains why that matters, since a peer without the extension does not decline politely — `:protocol` is an undefined pseudo-field there, so §4.3 makes the whole request malformed and the stream is spent. The same rule now runs in our own validator, which used to accept `:protocol` unconditionally: §4.3 permits a pseudo-field this document does not define **only** where "an extension could negotiate a modification of this restriction", so it is defined exactly when we advertised the setting. A value other than 0 or 1 is `H3_SETTINGS_ERROR`, enforced in `SettingsIterator` where §7.2.4's other payload rules already live — which is also where 0x08 turned out to sit one bit outside the duplicate-detection mask. The binding that was absent from this row — mounting `websocket.FrameCodec` on such a stream — is the WebSocket row above, and is done. |
| ~~CONNECT (§4.4)~~ | The framing rules, done; the proxying, deliberately not. §4.3.1's shape was already accepted — a CONNECT names an authority and omits scheme and path, and RFC 9220's extended form reinstates them alongside `:protocol` — but nothing enforced §4.4's other half: **once the method has completed, only DATA is permitted, and any other known frame type MUST be a connection error**. A tunnel that accepts trailers lets a peer put field semantics into a byte stream a proxy relays verbatim. Now tracked per stream, on a server when the CONNECT arrives and on a client when a 2xx answers one — a refusal is an ordinary response, and treating it as a tunnel would reject the trailers any response may carry. Reserved and unknown frame types stay ignorable there (§7.2.8, §9), because a peer may pad a tunnel. What is absent is the proxy itself: opening a TCP connection to the authority and relaying, which is an application rather than a codec. |
| ~~Request cancellation~~ | Done. §4.1.1 in both directions: `Connection.cancel(id, code)` resets what this side is sending *and* aborts reading what is arriving, because either alone leaves the peer working — a reset without STOP_SENDING lets a server keep producing a response nobody will read. The code is the caller's, since only it knows which of §4.1.1's meanings applies, and the code the *peer* chose is now reported as a `stream_reset` event and routed to the stream's own pipeline: dropping it made §4.1.1's distinction between "rejected, retry freely" and "cancelled, promises nothing" unusable however carefully a peer chose it. §5.2's follow-on obligation is met too — sending GOAWAY now cancels the requests at or above the identifier, so the promise no longer leaves transport state behind on both ends. |
| ~~Key update~~ | Done. §6 is wired into the connection: the Key Phase bit, a rotation answered rather than merely tolerated, the previous generation's read keys held for three PTOs (§6.4), §6.5's minimum interval, and §6.6's usage limits triggering a rotation without being asked. The send phase and the receive phase are separate fields, because the endpoint that starts a rotation writes in the new generation a round trip before its peer follows. |
| Server push | Refused in both directions. As a client, never sending MAX_PUSH_ID makes every push ID an H3_ID_ERROR (§4.6). As a server, a client's MAX_PUSH_ID is *accepted and never acted on* — §4.6 makes push optional and declining means never sending a PUSH_PROMISE, not failing the connection over a frame that conformant clients send by default. |

## What it costs, and what measuring it found

`zig build bench-http3_bench` puts HTTP/3 on the same axis as the other two protocols: same
machine, same response body, same process shape. One connection with 32 requests in flight serves
about 126 k req/s and with 128 in flight 129 k, which is where HTTP/2 lands on one connection too;
eight connections reach 155 k. At eight requests in flight HTTP/3 is *faster* than HTTP/2 — 59.6 k
against 52.5 k — because eight small responses coalesce into fewer datagrams than TCP writes. A
single request at a time costs 73 µs against HTTP/1.1's and HTTP/2's 59 µs, and that 14 µs is
packet protection and acknowledgement bookkeeping: the transport's price, not the HTTP mapping's.
The tables are in [bench/README.md](bench/README.md).

**Those figures are three times what they were this morning, and both causes are worth naming**
because neither was the protocol.

The first was the benchmark's own allocator. `DebugAllocator` unmaps pages as it frees, and an
HTTP/3 request allocates a stream channel, a pipeline and a handler; half the server's working
profile was the allocator. That is a harness artifact and it is fixed in the harness.

The second was ours. **`initial_max_streams_bidi` was the binding constraint on a connection long
before its CPU was**, and the credit policy behind it had a bug of the kind that only volume
finds: `maxStreamsUpdate` announced more streams only when it could grant at least half the
allowance more, while the most it can *ever* grant is `initial - live`. A stream stays live until
its FIN is acknowledged, so a busy connection had most of its allowance live and the limit stopped
moving at all — one connection with 128 requests in flight served 45 k req/s and spent the rest of
its time being refused. The trigger is now how much credit the *peer* has left, and the default
allowance is chosen against `streams.max_concurrent` — the hard cap on stream state — rather than
being a round number. Refusals went to zero and throughput from 45 k to 129 k.

None of this was measurable until the benchmark found three further defects, each needing volume —
a hundred requests on one connection, or thirty-two at once — that no test, fuzz target or aioquic
run had produced. A connection stopped serving after exactly 100 requests because finished streams
were never reaped, so the credit reaping enables was never granted; an application refused for want
of credit had no event that could tell it to try again; and asking for one stream too many *closed
the connection*, blaming the peer for a rule it had not broken. The write-up is in
[REVIEW.md](REVIEW.md).

## Numbers

The QUIC and HTTP/3 stack is roughly 28,000 lines across the two directories,
carrying 312 of the repository's 825 tests plus seven of its 22 fuzz targets. All of
it runs under the leak-checking allocator, on threads and on fibers, on Linux and
macOS, in Debug, ReleaseSafe and ReleaseFast — and against aioquic in CI on every
push, in both directions.
