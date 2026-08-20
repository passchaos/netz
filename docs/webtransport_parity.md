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
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast
```

The external interoperability gate builds the audited `~/Work/wtransport`
checkout at `d96cbb8` and exercises both directions over real TLS
1.3/QUIC/HTTP/3 connections. The wtransport-client/netz-server half verifies a
successful Extended CONNECT at `/interop`, bidirectional DATAGRAM exchange, a
client-created bidirectional stream and its reverse direction, client- and
server-created unidirectional streams, and a `CLOSE_WEBTRANSPORT_SESSION` with
code 77/reason `netz done`. The netz-client/wtransport-server half repeats
CONNECT, DATAGRAM and both stream-direction checks. The gate exposed three
cross-stack assumptions now covered in production code: Client Finished can
follow an Initial ACK in the same UDP datagram, modern peers may omit the older
Capsule-Protocol and per-session stream-limit settings, and HTTP/3 critical
stream IDs must not be hidden from WebTransport association based only on
their numeric values.

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
| CONNECT / SETTINGS | Handshake, protected and dev runtimes; handshake and protected CONNECT streams remain open for Capsule Protocol traffic | Codec/session helpers | Production async endpoint/session |
| DATAGRAM | Dev, protected, real-handshake, batch receive, payload budget/stats | Codec/session counters | Production send/receive |
| Bidirectional streams | Real-handshake open/send, reverse direction, whole-FIN compatibility receive plus caller-buffer incremental reads, reset/stop and lifecycle/limits | Session registry and old-draft prefix codec | Production async bidi streams with read/reset/stop |
| Unidirectional streams | Real-handshake both directions, incremental reads, reset/stop and lifecycle/limits | Session registry and header codec | Production async uni streams with read/reset/stop |
| Close/drain capsule codec | Real-handshake and protected runtime send/receive, split frame/capsule parsing, clean-FIN close and UTF-8/1024-byte validation; real-handshake SESSION_GONE stream cleanup | Close codec/state; audited session helper handles close/drain but accepts bare capsule fallback | Session close lifecycle; current driver handles close while drain support is absent |
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
`writeStream`, `writeStreams`, `finishStream`, `resetStream`, and `stopStream`.
`readStream`
copies only the next contiguous prefix into caller storage, releases it to QUIC
flow control immediately, and returns data/FIN, RESET_STREAM, or STOP_SENDING
events. `writeStream` waits for positive transport credit but submits at most
one packet-sized application prefix and returns its actual length, allowing
callers to round-robin many active streams; `finishStream` submits FIN
independently. `writeStreams` stages one fair packet-sized slice per sendable
stream through QUIC's stateful packet batch and commits registry/caller offsets
only for the socket-visible prefix. This provides allocation-free concurrent
stream progress without hiding flow control behind per-stream write-all tasks.
The runtime maps
WebTransport's 32-bit application error space into HTTP/3 codes while skipping
reserved codepoints and exposes both mapped and raw values on receive.

The real-handshake test sends 96 KiB through an 8 KiB advertised stream window,
reads it with 2-3 KiB caller buffers before FIN, verifies payload and flow
progress, and then exchanges both reset and stop events. Thus a successful test
cannot be explained by retaining a complete body behind the advertised window.

The benchmark uses one 4 MiB real-handshake bidirectional transfer, a 64 KiB
stream window, 16 KiB caller storage, partial writes and independent FIN:

```text
partial writes:    4036
read events:       4037
checksum:          534773760
median elapsed:    96.43 ms
median throughput: 41 MiB/s
```

These are the median elapsed time and corresponding integer throughput from
three consecutive 2026-08-18 same-host `ReleaseFast` runs after switching the
benchmark to one-packet partial writes. This deliberately prioritizes
caller-controlled fairness over the write-all helper's throughput; it is an
internal baseline and no equal-wire wtransport/quicz ratio is claimed.

The benchmark now also accepts `--streams` and `--transfer-bytes`. A four-stream
1 MiB-per-stream real-handshake run completed at 70 MiB/s aggregate with 3971
socket-visible partial writes, exercising the batch API rather than four
sequential write loops. The local `wtransport` API exposes independent async
stream writes but no one-call cross-stream packet batch or visible-prefix
commit result.

The benchmark also accepts `--stream-window`, `--one-rtt-datagram-size`, and
`--disable-pacing`. Connection receive credit scales with stream count instead
of the former fixed two-window cap. Three real-handshake runs with four 4-MiB
streams, 1-MiB per-stream windows and 8-KiB datagrams measured 188-195 MiB/s
aggregate, versus the obsolete 26 MiB/s result from the 128-KiB connection-
credit/4-KiB-datagram configuration. Batch validation occurs before any
association prefix is sent, so a bad later stream cannot expose a partial batch.

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

The lightweight preconfigured-key protected runtime also establishes
WebTransport with incremental HTTP/3 request/response HEADERS rather than the
aggregate helpers that set QUIC FIN. `sendSessionData` and
`receiveSessionData` expose bounded caller-buffer DATA on that long-lived
Extended CONNECT stream in both directions. Its typed `drain`, `close`, and
`receiveSessionEvent` APIs now reuse the shared incremental Capsule state
machine after HTTP/3 removes DATA framing. A fixed reader buffer is sized for a
maximum legal CLOSE capsule and retains bytes after the first event, including
DRAIN and a 1024-byte-reason CLOSE in one DATA payload. Clean FIN maps to
close code zero; partial capsules at FIN fail, malformed capsules cancel the
request with H3_MESSAGE_ERROR, and operations after local close fail.

The protected end-to-end test fragments HTTP/3 across five-byte QUIC STREAM
payloads, receives DRAIN, exchanges a DATAGRAM after that advisory event,
receives a detailed client CLOSE, and completes the opposite CONNECT direction
with FIN. Thus a pass cannot be explained by a CONNECT stream that ended
immediately after status 200. Associated bidi/uni streams and SESSION_GONE
cleanup remain on the production-oriented handshake runtime because the
lightweight protected transport does not own a stateful recovery connection.

## Remaining gaps

1. Expose associated bidi/uni stream APIs on preconfigured protected and
   development runtimes. Protected CONNECT/Capsule lifecycle is now
   long-lived, but the lightweight protected HTTP/3 runtime deliberately lacks
   a full `one_rtt.Connection`; association streams must not be advertised
   until ACK, recovery, flow control and reset/stop state share one connection
   owner.
2. Add browser WebTransport evidence. The checked-in wtransport gate now
   covers both client/server directions across CONNECT, DATAGRAM, and
   bidirectional/unidirectional streams; its wtransport-client half also checks
   the detailed session-close capsule.
3. Add larger long-run stream-churn distributions; concurrent packet-batched
   stream throughput and cancellation-under-loss now have real-handshake
   baselines. The
   same benchmark now accepts `--reset-every` and `--reset-after-bytes`, raises
   both QUIC and WebTransport negotiated stream limits to the requested shape,
   and validates every reset code/direction alongside FIN/data checksums. A
   64-stream smoke reset 32 streams after 256 bytes while the other 32 delivered
   16 KiB each: 532,480 verified bytes, 350 read events, and complete terminal
   coverage. `--loss-pct=5` enables a fixed-seed endpoint interceptor only
   after the authenticated CONNECT. A cancelable client transport-progress
   future now keeps ACK/loss/PTO processing live after the last local FIN/reset
   until the server validates completion, fixing the prior large-stream
   teardown deadlock. Five 64-stream runs each considered 320 server datagrams,
   dropped the same 21, delivered all 32 RESET_STREAM and 32 FIN terminal
   events, and verified 532,480 bytes/checksum 67,891,200.
   The same endpoint hook now supports real packet reordering rather than only
   loss: `--reorder-every=5` held exactly 112 of 561 datagrams in three 8-stream
   runs, then sent each after its successor while preserving QUIC packet-number
   state. Every run verified 2,097,152 bytes/checksum 267,386,880 at 175-183
   MiB/s. With `--fault-direction=client`, three runs reordered the actual
   STREAM/FIN direction: 121-123 of 605-615 client datagrams were held, all
   bytes/checksum still matched, and throughput was 153-161 MiB/s. Batch-tail
   holds are flushed explicitly so reordering cannot become hidden loss. The
   remaining gap is
   external wtransport/browser interop rather than basic cancellation recovery
   at the benchmark's maximum stream count.
