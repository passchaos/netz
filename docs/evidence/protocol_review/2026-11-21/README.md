# QUIC/HTTP/WebSocket/WebTransport review, 2026-11-21

Base revision: `28dd7d76`, Zig 0.16.0, macOS aarch64. This is a focused
correctness and interface review of connection setup, CRYPTO/stream ownership,
fallback and shutdown paths. It fixes the confirmed QUIC handshake defect and
records remaining design findings without changing their behavior.

## Fixed: Handshake CRYPTO flights were single-datagram

`prepareHandshakeCrypto` sealed the complete Handshake-level CRYPTO flight into
one UDP datagram and rejected it with `DatagramTooLarge` when it exceeded the
endpoint limit. Real certificate flights routinely exceed a safe MTU:

- The H3 endpoint default is 4 KiB (`receive_policy.default_endpoint_max_datagram_size`).
- A normal 3-4 KiB certificate chain plus CertificateVerify and Finished can
  cross that bound.
- At a 1200-byte path MTU almost any real chain fails.
- Client mTLS flights have the same problem, and the server's
  `receiveClientHandshakeCryptoFromDatagram` created a fresh reassembler per
  datagram, so it also required the client flight to arrive in one datagram.

The fix adds MTU-bounded Handshake packetization (`sendHandshakeProgress`,
`handshakeFlightWireLen`, `handshakeFlightPacketCount`,
`largestHandshakeChunk`) and keeps one CRYPTO reassembler across client
datagrams. Each packet carries one contiguous CRYPTO range and consumes a fresh
packet number.

### Packet-number ownership

`HandshakeFlight` previously had no `next_packet_number`. After sending the
client Finished flight, the caller still pointed CONNECTION_CLOSE at the first
packet number of that flight, so an error on the post-send path could reuse an
AEAD nonce. The flight now records the first unused packet number, and
retransmissions stride by the complete flight size instead of one.

### Evidence

| Gate | Result | Artifact |
| --- | --- | --- |
| 1200-byte endpoints, 16-entry certificate chain (4928 bytes), server auth + mTLS, Threaded + zio | 36/36 | `handshake-fragmentation-debug.log` |
| Existing handshake/PTO/certificate/prepared-verifier regressions | 63/63 | `handshake-regression-debug.log` |
| Direct H3 and ordered protocol policy end-to-end | 108/108 | `http-h3-debug.log` |

The end-to-end case previously required 8192-byte datagrams to pass; it now
runs at 1200 bytes. Client and server flights both span multiple packets, and
the server reassembles the client Certificate flight across datagrams.

```sh
zig build test-quic \
  '-Dtest-filter=QUIC Handshake CRYPTO flight packetizes' \
  '-Dtest-filter=QUIC default CRYPTO limit' --summary all

zig build test-quic \
  '-Dtest-filter=QUIC handshake' '-Dtest-filter=certificate' \
  '-Dtest-filter=prepared' '-Dtest-filter=handshake PTO' --summary all

zig build test-http \
  '-Dtest-filter=unified HTTP direct H3' \
  '-Dtest-filter=unified HTTP protocol policy' --summary all
```

## Fixed: minor interface hygiene

`http.ResponseSink.discard()` pointed at a `const` context through
`@constCast`. The storage is now writable even though the stateless callbacks
never access it, removing a latent UB footgun from a public constructor.

## Open findings

These are source-level findings, not reproduced defects, and are intentionally
left out of this batch.

| ID | Area | Finding | Suggested direction |
| --- | --- | --- | --- |
| P1 | HTTP Pool Alt-Svc fallback | After an H3 *connection* failure the body was never read, yet fallback for an idempotent method still calls `bodySource().prepareReplay()`. A single-pass Reader is rejected even though no byte was consumed. | Track whether the attempt consumed source bytes; require rewind only after consumption. |
| P2 | QUIC anti-amplification | `InitialHandshakeFlight` reserves the complete Initial+Handshake flight before sending. Large chains therefore depend on PTO-driven budget growth from client retransmissions; correctness holds, but the first valid send can be delayed. | Send the prefix that fits, retain an ACK-aware CRYPTO cursor, and continue as the budget grows. |
| P3 | WebTransport options | The legacy Protected adapter returns `WebTransportNotNegotiated` for caller configuration it cannot support (`initial_flow_limits`). That reads as a peer negotiation failure rather than an unsupported option. | Add a distinct configuration error and update the option docs. |
| P4 | HTTP H3 options | `Client.Options.http3.handshake.handshake.alpn_protocols` nests two `handshake` levels because the facade wraps the native handshake options. | Add flat accessors or a `quic` sub-struct while keeping the existing fields as deprecated aliases. |
| P5 | WebSocket byte-stream adapter | `websocket.stream_connection.Connection.close()` has no deadline form and `receiveMessage()` has no absolute-deadline variant; the adapter is documented as caller-driven byte-stream framing. | Add deadline variants if H2/H3 extended-CONNECT embedders need bounded framing reads. |

Counts include imported support tests and overlap between bundles. The evidence
is scoped loopback and source-boundary verification; it is not a new
external-peer matrix or performance claim.
