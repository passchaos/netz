# WebTransport application-protocol negotiation interoperability

The gate uses the local `moq-dev/web-transport` reference at reviewed clean
commit `b2a4cfde90641be15777892eb36cd07dec0a7ee3`, specifically
`rs/web-transport-quinn` 0.11.12 and `rs/web-transport-proto` 0.6.1. The reference
client validates that a selected protocol was offered and exposes the result
through `Session.protocol()`. Its `sfv` serializer/parser independently handles
quoted Structured Field strings. The gate rejects a different or dirty
reference tree and records source, manifest, lockfile and executable hashes.

Build the Rust peer separately, then run the gate with already-built native
server/client executables:

```sh
cargo build --release --locked --manifest-path tools/interop/webtransport_protocol/Cargo.toml
uv run --script tools/interop/webtransport_protocol/run.py \
  /absolute/path/to/netz-webtransport-protocol-server \
  /absolute/path/to/netz-webtransport-protocol-client \
  tools/interop/webtransport_protocol/target/release/netz-webtransport-protocol-peer \
  --output /tmp/webtransport-protocol.json
```

The parent build integration exposes `interop-webtransport-protocol`. The
runner compiles nothing. It pins Python `hpack` 4.1.0 through PEP 723 and uses
OpenSSL to generate one short-lived P-256 identity. The reference semantic
client pins that certificate. Native QUIC/TLS fixture configuration follows the
existing wtransport gate. Cargo.lock pins 174 dependencies plus the fixture package,
including Quinn 0.11.11, rustls 0.23.43 and Tokio 1.53.1.

In the reference-client/Netz-server direction, three separate connections test:

| Case | Ordered client offers | Server support order | Selected result | Application traffic |
| --- | --- | --- | --- | --- |
| Ordered overlap | `p2`, `p1` | `p1`, `p2`, escaped identifier | `p2` at both ends | One DATAGRAM and one bidi stream |
| Escaped identifier | `q"u\oted`, `p1` | Same support order | `q"u\oted` at both ends | One DATAGRAM and one bidi stream |
| Required no overlap | `absent` | Same support order | Exact HTTP 406 rejection | Zero application DATAGRAMs/streams |

Netz must inspect the actual `WT-Available-Protocols` field, preserve offer
order, choose the first offered supported value, and expose the decoded
selection. The reference client's actual `Session.protocol()` must match it.
The required rejection first checks `NoCommonApplicationProtocol` and that no
success response has been submitted, then sends 406 and drives its delivery
boundary. The reference client must observe that exact status before app I/O.

In the Netz-client/reference-peer direction, one QUIC/H3 connection carries
five CONNECTs: `/ordered`, `/missing`, `/unoffered`, `/escaped`, and `/reuse`.
The reference request codec validates the full requests and their decoded
offer lists. Its normal `Connecting.respond` API refuses an unoffered protocol,
so the fixture deliberately writes two malformed successes through Quinn and
the public response encoder: missing required `WT-Protocol`, then selected
`unoffered`. Both must fail in Netz with
`ApplicationProtocolNegotiationFailed`, exact `WT_ALPN_ERROR` `0x0817b3dd` on
both CONNECT directions, and `WT_SESSION_GONE` `0x170d7b68` on the optimistic
server UNI associated with that CONNECT. The peer sends that UNI before the
bad head and withholds a healthy sibling echo until it observes both scoped
cancellations. The connection must remain alive with its original Session.

The surviving Session exchanges DATAGRAMs after each bad success and a bidi
stream after both. Escaped negotiation and a final new Session also exchange
DATAGRAMs. The native client requires one retained Session after each error,
three accepted Sessions by the end, five exact DATAGRAM replies and one exact
stream reply, with no rejected-session bytes delivered through sibling APIs.
The reference's SETTINGS advertise its legacy WebTransport wire profile; this
gate checks application negotiation and isolation on that supported profile,
while draft-16 Session flow-control interoperability remains separate coverage.

The Rust peer captures the actual incoming request and submitted response
HEADERS bytes. `wire.py` independently reads their RFC 9204 static/literal field
sections, using the pinned HPACK Huffman decoder. It checks exact
`WT-Available-Protocols` and `WT-Protocol` field values, including the quote and
backslash escapes. Dynamic QPACK is disabled by the peer's settings; the reader
rejects dynamic references and truncated/oversized frames. Fixed raw/Huffman
vectors check that reader separately. This is a bounded fixture reader, not a
general HTTP/3 implementation.

Results include all semantic selections, offer/header bytes, decoded values,
CONNECT and optimistic-stream reset codes, session/connection counts and
application payloads. Success and failure reports retain all process logs and
source/executable hashes. The runner rejects source or executable mutation
during the gate. Readiness uses event queues with one ten-second deadline;
native operations have five-second absolute deadlines, reference modes have
25-second outer deadlines, and every runner subprocess wait is bounded.

The native fixtures are `netz_server.zig` and `netz_client.zig`, sharing only
the certificate/report helpers in `fixture.zig`. They use the production zio
backend and WebTransport APIs. The Rust peer is a standalone executable;
this fixture introduces no FFI or language bindings and leaves the existing
browser, wtransport and benchmark gates intact.
