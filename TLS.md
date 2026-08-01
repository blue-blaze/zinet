# TLS 1.3

Zinet contains a TLS 1.3 implementation. This is a record of why, what it does,
and what it does not — because "we wrote our own TLS" is a claim that should be
met with suspicion, and the useful response to suspicion is detail.

## Why there is one at all

It was not the plan. Zinet started with `std.crypto.tls.Client`, which works and
is in the standard library, and [src/tls.zig](src/tls.zig) still uses it. Three
things it cannot do turned into three things Zinet could not do:

| Wanted | Blocked by |
|---|---|
| Announce `h2` over TLS | `tls.Client.Options` has no ALPN field, and RFC 9113 §3.1 identifies HTTP/2 by ALPN. Every conforming server therefore answered HTTP/1.1. |
| TLS on the server side | `std/crypto/tls/` contains `Client.zig` and nothing else. |
| QUIC at all | RFC 9001 does not use TLS records. It needs the handshake as a state machine that hands out keys and consumes messages — an engine, not a `Reader`/`Writer` pair. |

The third is what forced the issue. QUIC could not be built on
`std.crypto.tls.Client` in any form, so implementing the TLS 1.3 handshake became
a prerequisite for HTTP/3 rather than a choice. And once that engine existed —
tested against RFC 8448's published traces and interoperating with `aioquic` — the
other two were a record layer away.

So the order of events is worth being exact about: the handshake was written for
QUIC, verified there, and only then carried to TCP. The parts that are shared are
shared in fact and not merely in intent.

## What it is made of

```
codec/quic/handshake.zig    RFC 8446 §4: the messages, parsed and built
codec/quic/tls.zig          RFC 8446 §7.1: the key schedule
codec/quic/client.zig       the client half of the handshake, as an engine
codec/quic/server.zig       the server half
codec/quic/verify.zig       certificate chain and signature verification
codec/tls13/record.zig      RFC 8446 §5: the record layer — TCP only
codec/tls13/session.zig     engine + records = a TLS connection, sans-io
codec/tls13/identity.zig    certificate chain and private key loading
codec/tls13/driver.zig      the socket-driving half, shared by both roles
codec/tls13/client.zig      a client connection under a Pipeline
codec/tls13/server_connection.zig   an accepting server
```

The division that matters: **the engine knows nothing about records, and the
record layer knows nothing about the handshake.** QUIC carries handshake messages
in CRYPTO frames; TCP carries them in records. Both hand the engine bytes and ask
for bytes back, tagged with an encryption level. That is the entire interface, and
it is why one engine serves both transports.

`session.zig` is where records and engine meet, and it is sans-io: bytes in,
bytes out, no sockets. Every rule in it is testable without a socket, and most of
the tests are.

## The record layer

RFC 8446 §5, and the interesting parts are the ones that differ from QUIC's packet
protection even though the cryptography is identical.

**Sequence numbers live with the keys.** §5.3 has a per-key sequence number that
resets on every key change and is never transmitted. Putting it inside `Keys`
rather than beside them means "new keys" and "reset the counter" cannot come
apart — a failure mode that produces a connection which works until the first key
update.

**A decryption failure is fatal here and not in QUIC.** QUIC drops an
unauthenticated packet and carries on, because a packet is a self-contained unit
and an attacker can inject one. TLS runs on a stream: a record that will not
decrypt means the stream position is no longer known, and there is nothing to
resynchronise to. So one is a discard and the other closes the connection, and
the two layers say so in their own words rather than sharing a helper that would
have to be right for both.

**The real content type is the last non-zero byte** of the decrypted plaintext
(§5.2), because padding is zeros appended after it. An all-zero plaintext is
therefore malformed rather than empty, and a zero-length handshake fragment is
too — while a zero-length `application_data` record is perfectly legal, and is how
some implementations pad traffic patterns.

**Records are rejected before they are buffered.** An unknown content type or an
oversized length fails immediately rather than after accumulating up to 16 KiB,
which is the difference between a bounded parser and one whose memory use a peer
chooses.

Verified byte for byte against RFC 8448's §3 trace: the ClientHello record, the
ServerHello record, the server flight, the client Finished, a session ticket,
application data in both directions, and both alerts. The sequence numbering is
checked implicitly by that — the ticket is the server's application record 0 and
the data record is number 1, so getting the counter wrong changes the nonce and
the comparison fails.

## The two sessions

`ClientSession` and `ServerSession` share their record handling and their alert
handling by calling the same functions, and differ where TLS differs. One
asymmetry is worth stating because it is easy to get wrong and hard to notice:

**A server's write keys advance at its own Finished; its read keys wait for the
client's.** That is what makes 0.5-RTT data possible — a server may send
application data before the client has finished authenticating — and it means the
two directions change generation at different moments. One flag for both would
fail to decrypt exactly one message: the client's Finished, which is the one that
completes the handshake.

Post-handshake messages are handled in the session rather than the engine, since
the engine's job ends when the handshake does. `NewSessionTicket` is ignored
(there is no resumption yet). A `KeyUpdate` is answered, and the reply is sealed
under the *old* write key before rotating — §4.6.3, and the opposite order
produces a message the peer cannot read.

## The driver

`driver.zig` holds what a TLS connection does with a socket: the read loop, the
outbound queue, the socket read with a deadline, and two flush rules. It takes
`conn: anytype`, so client and server connections share one implementation while
differing only in how they are created and how their handshake starts.

That sharing is not tidiness. This repository has been bitten six times by one
rule implemented in two places, and the symptom is always the same: break one
copy and the entire test suite stays green. The two flush rules in here are
exactly the kind of thing that goes wrong that way:

* **Flush before blocking in a read.** A client that queues a request just after
  the reader task entered a read would otherwise wait for a reply to a request
  never sent.
* **Deliver before the first read.** A request/response client writes its Finished
  and its first request in one segment. The handshake loop consumes both, so the
  request is already decrypted and waiting by the time the pipeline exists —
  and a read loop that blocks first waits for a second request that will never
  come. The connection simply hangs.

The second was found by `curl` and not by any test here, because `openssl
s_client` closes without sending anything and so never produces the case. There is
now a regression test that drives a bare socket to coalesce the two writes
deliberately.

## Server identity

`identity.zig` loads a certificate chain and a private key from PEM. PKCS#8 and
SEC1 are both accepted; RSA is rejected with `error.UnsupportedKeyType`, and the
reason is not laziness:

**`std.crypto.Certificate.rsa` can verify RSA signatures but not produce them.** A
TLS 1.3 server signs a `CertificateVerify` on every handshake, so a server here can
present ECDSA P-256 or Ed25519 certificates and not the RSA ones most CAs still
issue. That is a real limitation on deployment, and it is reported as a named
error at load time rather than as a handshake failure later.

## What is checked, and against what

* **RFC 8448** — the published handshake traces, byte for byte: key schedule, the
  four traffic secrets, and every record in the trace.
* **RFC 9001 Appendix A** — QUIC's packet protection vectors, which share the key
  schedule.
* **OpenSSL `s_server`** — the client, in three configurations: ALPN offering
  `h2,http/1.1` and getting `h2`, a server offering only `http/1.1`, and no ALPN
  at all.
* **`curl` and `openssl s_client`** — the server. `curl` gets `HTTP/1.1 200` over
  TLS and, with `--http2`, `HTTP/2 200` negotiated by ALPN with nghttp2 on the
  other side. `s_client` reports the version and the agreed protocol
  independently, rather than this implementation reporting on itself.
* **`aioquic`** — both directions of HTTP/3, which exercises the same engine over
  a completely different transport against code sharing none of ours.

All of it runs in CI.

## What it does not do

Stated rather than left to be discovered:

* **No TLS 1.2.** A peer that cannot do 1.3 is refused. The version negotiation
  extension is checked and nothing else is offered.
* **No resumption or 0-RTT.** Tickets are ignored on receipt; none are issued.
* **No client certificates.** A `CertificateRequest` is not sent by the server, and
  a client `Certificate` message is refused as a peer inventing an exchange.
* **One key exchange group: X25519.** A client offering only P-256 is refused with
  `NoSupportedGroup`, and the server never sends a HelloRetryRequest — it has
  nothing to ask for.
* **No renegotiation**, which TLS 1.3 removed anyway, and no session tickets, and
  no OCSP stapling.
* **No certificate revocation checking.** Chain verification is signatures, names
  and validity dates.

The cipher suites are the three RFC 8446 mandates and recommends:
`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`.

## Should you use it

For talking to your own services, or to anything modern, with ECDSA or Ed25519
certificates: it is tested about as thoroughly as the rest of this repository,
which is to say against published vectors and against other people's
implementations, in CI, under a leak-checking allocator.

For anything where a TLS bug is a security incident and a mature implementation is
available: use the mature one. Zinet takes its TLS the same way it takes its `Io`
— [src/tls.zig](src/tls.zig) is still there, wrapping `std.crypto.tls.Client`, and
an application that wants the standard library's implementation on the client side
can have it.
