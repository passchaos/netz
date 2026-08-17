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
zig build bench-webtransport-stream -Doptimize=ReleaseFast
```

`run-webtransport-handshake-stream` now covers one real QUIC/TLS handshake,
HTTP/3 SETTINGS and extended CONNECT negotiation, then:

- client-opened bidirectional stream with server reverse-direction echo,
- client-to-server unidirectional stream,
- server-to-client unidirectional stream,
- caller-buffer incremental reads before FIN with immediate flow-credit return,
- mapped 32-bit RESET_STREAM and STOP_SENDING lifecycle events,
- runtime WT_DRAIN_SESSION/WT_CLOSE_SESSION send and receive over the
  long-lived Extended CONNECT stream,
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
| Bidirectional streams | Real-handshake open/send, reverse direction, whole-FIN compatibility receive plus caller-buffer incremental reads, reset/stop and lifecycle/limits | Session registry and old-draft prefix codec | Production async bidi streams with read/reset/stop |
| Unidirectional streams | Real-handshake both directions, incremental reads, reset/stop and lifecycle/limits | Session registry and header codec | Production async uni streams with read/reset/stop |
| Close/drain capsule codec | Real-handshake runtime send/receive, split frame/capsule parsing, clean-FIN close, UTF-8/1024-byte validation and SESSION_GONE stream cleanup | Close codec/state; audited session helper handles close/drain but accepts bare capsule fallback | Session close lifecycle; current driver handles close while drain support is absent |
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

## Incremental stream and cancellation evidence

`HandshakeClientSession` and `AcceptedHandshakeSession` expose `readStream`,
`resetStream`, and `stopStream`. `readStream` copies only the next contiguous
prefix into caller storage, releases it to QUIC flow control immediately, and
returns data/FIN, RESET_STREAM, or STOP_SENDING events. The runtime maps
WebTransport's 32-bit application error space into HTTP/3 codes while skipping
reserved codepoints and exposes both mapped and raw values on receive.

The real-handshake test sends 96 KiB through an 8 KiB advertised stream window,
reads it with 2-3 KiB caller buffers before FIN, verifies payload and flow
progress, and then exchanges both reset and stop events. Thus a successful test
cannot be explained by retaining a complete body behind the advertised window.

The benchmark uses one 4 MiB real-handshake bidirectional transfer, a 64 KiB
stream window and 16 KiB caller storage:

```text
read events:       3913
checksum:          534773760
median elapsed:    59.68 ms
median throughput: 67 MiB/s
```

These are the median elapsed time and corresponding integer throughput from
three consecutive 2026-08-18 same-host `ReleaseFast` runs. This is an internal
streaming baseline; no equal-wire wtransport/quicz ratio is claimed.

## Session drain and close lifecycle

Handshake sessions now keep their Extended CONNECT request/response stream open
after successful HEADERS instead of using the aggregate HTTP/3 helper that
immediately sent FIN. `drain`, `close`, and `receiveSessionEvent` operate on
that stream:

- WT_DRAIN_SESSION remains advisory; streams and datagrams stay usable.
- WT_CLOSE_SESSION carries a 32-bit code plus at most 1024 bytes of UTF-8,
  sends CONNECT FIN immediately, and makes new stream/datagram operations fail.
- a peer close or clean CONNECT FIN produces a typed terminal event; clean FIN
  maps to code zero and an empty reason.
- session termination sends RESET_STREAM/STOP_SENDING with WT_SESSION_GONE for
  every non-terminal associated stream direction.
- malformed close length/UTF-8 resets the CONNECT stream with H3_MESSAGE_ERROR.

The CONNECT stream uses a fixed-size incremental state machine. HTTP/3 DATA
frame headers and Capsule Protocol varints may split at any byte boundary;
unknown capsule values are skipped without allocation or whole-value buffering.
Focused tests sweep every split point around an unknown capsule followed by
WT_DRAIN_SESSION, while real-handshake tests cover drain, post-drain stream
traffic, detailed close, clean-FIN close and post-close rejection.

## Remaining gaps

1. Expose equivalent stream APIs on preconfigured protected and development
   runtimes; the production-oriented real-handshake path is covered first.
2. Add partial-write return semantics; current sends accept caller chunks and
   internally pump flow control until each chunk is submitted.
3. Add external `wtransport` client/server interoperability runs and browser
   WebTransport evidence.
4. Add concurrent stream, stream-churn and cancellation-under-loss benchmarks;
   sustained incremental stream throughput now has a real-handshake baseline.
