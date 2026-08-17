# netz WebTransport parity audit

This audit compares netz with the WebTransport implementations available under
`~/Work`: `quicz` and modern Rust `wtransport`. It records wire-version
differences explicitly because draft WebTransport stream association changed
over time.

## Current direct evidence

Run:

```sh
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
zig build bench-webtransport-datagram -Doptimize=ReleaseFast
```

`run-webtransport-handshake-stream` now covers one real QUIC/TLS handshake,
HTTP/3 SETTINGS and extended CONNECT negotiation, then:

- client-opened bidirectional stream with server reverse-direction echo,
- client-to-server unidirectional stream,
- server-to-client unidirectional stream,
- session/transport stream limits and stream-ID direction validation,
- shared HTTP/3 request/WebTransport bidi and push/WebTransport uni ID
  allocation, preventing sibling protocol stream collisions.

The existing handshake runtime test combines those stream paths with a
WebTransport DATAGRAM round trip and transport statistics.

## Feature comparison

| Area | netz | `~/Work/quicz` | `~/Work/wtransport` |
| --- | --- | --- | --- |
| CONNECT / SETTINGS | Handshake, protected and dev runtimes | Codec/session helpers | Production async endpoint/session |
| DATAGRAM | Dev, protected, real-handshake, batch receive, payload budget/stats | Codec/session counters | Production send/receive |
| Bidirectional streams | Real-handshake open/send/receive, reverse direction, lifecycle/limits | Session registry and old-draft prefix codec | Production async bidi streams |
| Unidirectional streams | Real-handshake both directions, lifecycle/limits | Session registry and header codec | Production async uni streams |
| Close/drain capsule codec | Strict UTF-8 close and drain codecs/state | Close codec/state | Session lifecycle |
| Stream association wire format | Modern `0x41` frame type + Session ID; uni `0x54` + Session ID | Audited code writes only Session ID for bidi streams | Modern `0x41` + Session ID and `0x54` + Session ID |

## Important interoperability correction

`~/Work/quicz/src/h3/webtransport.zig` encodes a bidirectional stream prefix as
only the Session ID. The audited `wtransport-proto` implementation defines
`WEBTRANSPORT_STREAM = 0x41` and serializes that special frame type followed
directly by Session ID (without the ordinary H3 payload-length field). Netz
implements and tests the latter format:

```text
session stream id 256 -> 40 41 41 00
                         ^^^^ frame type 0x41
                              ^^^^^ session id 256
```

Accepting only the modern explicit prefix avoids confusing a legacy
Session-ID-only prefix with an ordinary HTTP/3 DATA/HEADERS frame.

## Remaining gaps

1. Expose equivalent stream APIs on preconfigured protected and development
   runtimes; the production-oriented real-handshake path is covered first.
2. Support incremental reads/writes on long-lived streams rather than the
   current complete-FIN receive object.
3. Integrate CLOSE/DRAIN capsule transmission and reception into runtime
   session shutdown.
4. Add external `wtransport` client/server interoperability runs and browser
   WebTransport evidence.
5. Add sustained stream throughput, concurrent stream, reset and STOP_SENDING
   benchmarks; the existing benchmark covers DATAGRAM round trips only.
