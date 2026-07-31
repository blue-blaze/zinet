# HTTP/3 in Zinet

HTTP/3 runs over QUIC, and that one sentence decided the shape of everything below.
Netty — the project this framework translates — does not implement QUIC:
`netty-incubator-codec-quic` is a JNI binding to Cloudflare's Quiche, and
`netty-incubator-codec-http3` sits on that binding. So for this half of the work there
was no upstream shape to translate, only five RFCs: 9000 (transport), 9001 (TLS),
9002 (recovery), 9114 (HTTP/3), 9204 (QPACK). Under the zero-dependency rule, binding
to a C library was not an option; the transport had to be written.

**What works:** an HTTP/3 client, end to end. The QUIC transport underneath it —
handshake, packet protection, streams with three levels of flow control, loss
detection, NewReno, connection lifecycle — is complete for the client role, checked
against RFC test vectors byte for byte, and interoperates with aioquic (a Python
implementation sharing no code with this one) in CI on every run: one GET crossing
that boundary exercises the TLS 1.3 handshake, packet protection, loss recovery, the
control streams, QPACK and the request semantics against someone else's reading of
the same five documents.

**What does not:** the server role, for a reason that is upstream and specific — see
[the server-side constraint](#the-server-side-constraint). A short list of protocol
features is deliberately absent; each is refused explicitly rather than half-built —
see [Deliberately not done](#deliberately-not-done).

## Contents

* [Why QUIC had to be written, and what std did provide](#why-quic-had-to-be-written-and-what-std-did-provide)
* [The layers](#the-layers)
* [Verified against whom](#verified-against-whom)
* [The rule that kept being the bug](#the-rule-that-kept-being-the-bug)
* [The server-side constraint](#the-server-side-constraint)
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

## The server-side constraint

There is no QUIC server here, and the reason is one missing upstream capability with
a sharp edge: **the standard library can verify RSA signatures but cannot produce
them** — `std.crypto.Certificate.rsa` has no secret-key or signing half. A TLS 1.3
server must sign a `CertificateVerify` on every handshake. Ed25519 and ECDSA can
sign, so a future server is possible with an ECDSA or Ed25519 certificate — but it
could never serve an RSA certificate, and the test fixtures cannot sign at all,
which is why the certificate verification path is covered by RFC 8448's genuine
signature rather than fixture-generated ones.

The same constraint shaped the interop test: the aioquic server's certificate is
ECDSA P-256, and that CI step is the first thing in the repository that would catch
an RSA-only assumption.

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
| Server role | Upstream: std cannot produce RSA signatures (above). Client-only is stated at every layer. |
| HelloRetryRequest | `error.HelloRetryRequestUnsupported`. Correct support needs §4.4.1's transcript replacement; a half version fails only against servers that send HRR. RFC 9001 §4.7 points QUIC at its own Retry instead — which *is* implemented, including the §17.2.5 integrity checks. |
| 0-RTT | Not attempted. The §3.2.3 QPACK interaction and the anti-replay obligations arrive with it. |
| QPACK dynamic table | The zero-capacity mode above; a ratio feature with an explicit seam. |
| Connection migration | Client-side, single-path. PATH_CHALLENGE is explicitly refused in the connection with a comment explaining why answering a challenge on an unvalidated path is worse than not answering. |
| Key update in the connection | `crypto.Keys.update` implements §6's "quic ku" and is tested; the connection layer does not yet rotate. The §6.6 AEAD usage limits that make rotation mandatory *are* enforced, in `Keys`, where they cannot be bypassed. |
| Server push | Refused by never inviting it: this client never sends MAX_PUSH_ID, so §4.6 makes every push ID the server could use an H3_ID_ERROR. |

## Numbers

The QUIC and HTTP/3 stack is roughly 18,000 lines across the two directories,
carrying 202 of the repository's 609 tests plus six of its 21 fuzz targets. All of
it runs under the leak-checking allocator, on threads and on fibers, on Linux and
macOS, in Debug, ReleaseSafe and ReleaseFast — and against aioquic in CI on every
push.
