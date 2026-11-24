# QUIC target receive and WebTransport stream events, 2026-11-24

Base revision: `2cf639c5`, Zig 0.16.0, macOS aarch64.

[The baseline](target-before.log) exposes two distinct failures: QUIC blocking
receive waits on a local unidirectional stream, and a targeted WebTransport
reader misses STOP while a whole reader owns that bidirectional stream's
receive data. The two roots report 136/139 passing with three failure entries;
the QUIC case appears again as a WebTransport dependency. Local unidirectional
WebTransport STOP delivery already passes and remains supported.

QUIC `receiveStreamId*` now validates its receive-side capability before waiting,
using the existing role/direction predicate. `pollStreamId` keeps its nullable
query contract. The ordinary, timeout and deadline paths preserve caller data
and lazy send-state allocation on rejection.

WebTransport polls sending-side state before applying the receive-mode filter.
One constant-time helper processes a registered stream's STOP for both targeted
and whichever-ready polling; new associations use the same helper without a
second registry scan. STOP leaves whole-stream bytes and reader mode intact,
and the original whole reader completes after FIN arrives.

The dual-role wire test also exposed H3 server reverse-bidirectional traffic
being rejected as a new request. Under a detached adapter, the server request
router now preserves STREAM/RESET/STOP for a known locally sent server bidi,
using QUIC send state or compacted local history. Ordinary H3 role validation
remains strict. The additional reverse RESET test checks exact code delivery
and completion of the unaffected send direction under one shared deadline.

All new target/event tests use zio and protected UDP where peer traffic is
required. Tests cover both endpoint roles and ordinary/relative/deadline reads.
The unidirectional QUIC test uses an initialized endpoint and connection; its
outer budget detects an erroneous indefinite wait without changing production
timeout semantics.

| Gate | Result | Artifact |
| --- | --- | --- |
| Original target/event baseline | Expected failures, 136/139 passing, QUIC duplicate | [target-before.log](target-before.log) |
| Target receive and STOP cases (Debug) | 139/139 | [target.Debug.log](target.Debug.log) |
| Three-protocol direction/routing/event overlap (Debug) | 309/310, 1 platform skip | [overlap.Debug.log](overlap.Debug.log) |
| Three-protocol direction/routing/event overlap (ReleaseSafe) | 309/310, 1 platform skip | [overlap.ReleaseSafe.log](overlap.ReleaseSafe.log) |

The overlap includes QUIC receive-target, role/direction, FIN/reset event and
invalid unidirectional-control tests; WTP targeted, whole, incremental,
automatic-grant and flow tests; H3 strict server-bidi rejection and CONNECT
DATAGRAM cases. The skip is the Linux-only incremental UDP GRO test. Counts
include imported support tests and repeated dependency cases across roots.

```sh
zig build test-quic test-webtransport \
  '-Dtest-filter=QUIC stream receive target admission' \
  '-Dtest-filter=WebTransport stream read target admission' -j1 --summary all
```

ReleaseSafe uses the overlap scope with `-Doptimize=ReleaseSafe`. Native Windows
CI includes the new QUIC and WTP target filters plus strict H3 server-bidi
rejection alongside the existing transport/admission bundle. Its result is
recorded after the matching Windows job finishes.

[Targeted stream event contracts](../../../stream_target_events.md) distinguish
receive-direction admission from sending-side control event delivery.
