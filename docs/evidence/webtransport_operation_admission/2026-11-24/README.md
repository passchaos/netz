# WebTransport operation admission, 2026-11-24

Base revision: `3e67f99a`, Zig 0.16.0, macOS aarch64.

Four original regressions fail on initialized, protected-UDP CONNECT pairs:

- Callback DATAGRAM send parses buffered CLOSE before H3 rejects the reader.
- Callback DATAGRAM receive advances Session flow rejection before admission.
- Dispatcher-bound DATAGRAM receive performs the same cleanup before rejection.
- Deferred lifecycle observation advances flow rejection during a borrowed
  callback.

[The baseline](admission-before.log) records 103/107 passing with those four
failures. The cases originally lived in the DATAGRAM test module; they now live
with the shared owner rules in `webtransport/runtime/owner/tests.zig`.

`owner.zig` admits buffered application access and independently owned blocking
receivers before Session parsing, queue access, cleanup or timer refresh.
Lifecycle entry guards reject callback reentry, and deferred observers preserve
the existing borrow. Blocking DATAGRAM and Session-event receivers, including
deadline-bound event cleanup, reject both H3 dispatcher binding and the client
Session dispatcher field before any lifecycle work. Ordinary event polling
keeps its shared-endpoint nonblocking path.

Local DRAIN/CLOSE and pending-close preparation reject callbacks before creating
retry state. Relative DATAGRAM receive facades directly construct one deadline
and delegate to their deadline forms, removing repeated Session preflight and
deferred observation. Public method names and signatures remain intact.

The seven owner tests exercise six DATAGRAM send forms, twelve receive forms,
both receiver roles, buffered CLOSE retention, zero rejected batch counts,
unchanged caller buffers and destinations, five Session-event forms, six local
DRAIN/CLOSE forms and dispatcher-bound event waits. Callback release is followed
by actual event delivery, resumed flow rejection or protected-UDP DATAGRAM
exchange to prove continued progress.

| Gate | Result | Artifact |
| --- | --- | --- |
| Four original owner regressions | Expected failures, 103/107 passing | [admission-before.log](admission-before.log) |
| Owner/control/flow/termination overlap (Debug) | 271/271 | [overlap.Debug.log](overlap.Debug.log) |
| Owner/control/flow/termination overlap (ReleaseSafe) | 271/271 | [overlap.ReleaseSafe.log](overlap.ReleaseSafe.log) |

Counts include imported support tests and overlapping existing cases. The
selected bundle covers DATAGRAM pacing/QPACK, CONNECT FIN/RESET/STOP_SENDING,
CLOSE/DRAIN event ordering, stream and data grants, parser allocation retry and
connection termination.

```sh
zig build test-webtransport \
  '-Dtest-filter=WebTransport operation admission' \
  '-Dtest-filter=WebTransport DATAGRAM' \
  '-Dtest-filter=WebTransport CONNECT' \
  '-Dtest-filter=WebTransport flow' \
  '-Dtest-filter=CLOSE' '-Dtest-filter=DRAIN' \
  '-Dtest-filter=connection termination' -j1 --summary all
```

ReleaseSafe uses the same filters with `-Doptimize=ReleaseSafe`. Native Windows
CI additionally runs the operation-admission filter through `test-webtransport`
alongside the existing HTTP/H3 DATAGRAM/WebSocket transport checks. Its result
is recorded separately from local runtime verification.

[The public contract](../../../webtransport_operation_admission.md) documents
ownership, progress preservation and relative-deadline delegation.
