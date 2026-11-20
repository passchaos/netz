# Timed and ordinary socket read ownership

Reviewed on 2026-11-20 with Zig 0.16.0 on macOS aarch64. The delivery base
is `9a5cf383`; baseline tracing used an isolated checkout of `43cf33d2` and
an independent copy of the pinned zio sources. Diagnostic changes are excluded
from the delivery.

The existing packed-response-head cancellation test uses a no-deadline
survivor and a later request on the same TCP connection. It stalled both on
an unchanged `b0d5d8ec` baseline and during earlier HTTP body-source work.

`baseline-kqueue-trace.log` shows fd 5's socket read watcher initially tagged
`fffffffffffffffe`. A timed read then submits EV_ADD/EV_ENABLE with udata 0,
replacing that watcher. Its completion queues EV_DELETE with udata
`ffffffffffffffff`. The next ordinary net_recv parks in the socket registry,
which still records an owner, so it never re-registers the deleted watcher.
The server sends the survivor and eventually closes; the client remains in
CLOSE_WAIT without its pending read completing.

The fix belongs to netz's stream I/O adapter. A connected socket now stays on
the socket read surface: native zio `net.readBuf` for matching tasks, or a
joined `std.Io.netRead` task for portable/wrapped-vtable operation. It uses
the native completion/timer path and preserves accepted bytes or EOF when cleanup
races completion. File I/O no longer aliases socket watcher ownership.

`native-isolated-proof.log` records 96/96 passing tests after the native
socket fix, including the original no-deadline survivor gate. Delivery checks
also cover a copied zio vtable, portable read errors/EOF, timeout joins,
pre-expired deadlines, and cancellation with already-consumed bytes.

Successful scoped checks (counts include imported support tests):

| Scope | Result | Captured output |
| --- | --- | --- |
| HTTP/socket Debug | 108 passed, 3 skipped (111 total) | [debug-http.log](debug-http.log) |
| HTTP/socket ReleaseFast | 108 passed, 3 skipped (111 total) | [releasefast-http.log](releasefast-http.log) |
| WebSocket Debug | 98 passed, 0 skipped (98 total) | [debug-websocket.log](debug-websocket.log) |
| MQTT Debug | 70 passed, 0 skipped (70 total) | [debug-mqtt.log](debug-mqtt.log) |
| gRPC Debug | 79 passed, 0 skipped (79 total) | [debug-grpc.log](debug-grpc.log) |

HTTP checks use `test-http` with filters `ordinary H2`, `stream timed reader`,
`stream native timed writer`, and `TLS bounded read interruptions`, under both
Debug and ReleaseFast. The three skipped cases are Linux-only native write
checks. Each H2 survivor remains a no-deadline request.

WebSocket checks select its bounded/local read-interruption cases and active
writer-buffer cleanup. MQTT checks select `MQTT local read interruptions` and
gRPC checks select the reconnecting health Watch interruption and active Watch
admission-backoff cases. These retain the original partial TLS record, frame,
packet and stream assertions. Group/futex hooks inject socket-task admission
and cancellation; datagram tests retain their batch hook. The fixture's
shared delegate remains valid through all worker joins.

An intermediate fixture failure and a transient sibling regexz compile error
were corrected by their respective owners before the successful checks. A
batch compile was stopped by the host's swap-growth guard; final checks ran
one protocol at a time using the normal Zig wrapper. Those unsuccessful
attempts remain in `/tmp/netz-http-socket-read-*` and are excluded from these
passing counts.

`source-hashes.sha256` records the delivered sources and the two live regexz
sources involved in the transient compile error. This batch does not rerun
whole-protocol interoperability or performance suites.
