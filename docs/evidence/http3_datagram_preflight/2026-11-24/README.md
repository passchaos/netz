# HTTP/3 DATAGRAM owner admission, 2026-11-24

Base revision: `9ab39deb`, Zig 0.16.0, macOS aarch64.

Three baseline regressions fail: a callback-reader rejection retains the
previous send count (7), a dispatcher-bound receive retains its previous count
(7), and receiveWithProgress invokes protocol inspection once before rejecting
callback-reader reentry. [The baseline log](preflight-before.log) records all
three on initialized protected UDP CONNECT pairs.

Receive owner/deadline/stream/association/negotiation admission now runs before
protocol callbacks or queue delivery. The shared owned, caller-buffer and
batch loops live in `http3/runtime/datagram/receive.zig`; runtime exports retain
their existing names as aliases. Client timeout send and both unbounded receive
batch facades clear progress before their own early guards. Completed batch
prefixes remain intact after work begins.

Buffered protocol inspection is nonblocking and receives a null deadline.
Entry admission, maintenance and socket waits keep the caller's original
budget; a fulfilled payload does not need another timed wait or a deadline-only
inspection. Protocol rejection still propagates after direct fulfillment.
WebTransport's inspector can attempt nonblocking scoped cleanup, while its
maintenance keeps credit/pacing waits within the operation deadline.

| Gate | Result | Artifact |
| --- | --- | --- |
| Baseline preflight cases | Expected failures, 59/62 including support tests | [preflight-before.log](preflight-before.log) |
| CONNECT DATAGRAM cases (Debug) | 84/84 | [datagram.Debug.log](datagram.Debug.log) |
| CONNECT DATAGRAM cases (ReleaseSafe) | 84/84 | [datagram.ReleaseSafe.log](datagram.ReleaseSafe.log) |
| WebTransport datagram flow/termination overlap | 107/107 | [webtransport-overlap.Debug.log](webtransport-overlap.Debug.log) |
| Windows test compilation and linking | 8/8 steps | [windows-compile.log](windows-compile.log) |

Counts include imported support tests and overlap. Tests cover both H3 roles,
owned/direct/batch receivers, callback and dispatcher rejection, invalid stream,
expired deadline, disabled negotiation, unchanged output buffers, zero rejected
progress, fulfilled protected UDP payloads with deadline-sensitive inspection,
and propagation of a real protocol-error tag after direct delivery. Existing
QPACK, pacing, terminal packet ordering and caller-buffer semantics remain
inside the selected DATAGRAM bundle. WebTransport overlap includes grant
maintenance and connection termination around caller-buffer delivery.

```sh
zig build test-http3 '-Dtest-filter=HTTP/3 CONNECT DATAGRAM' --summary all
zig build test-http3 '-Dtest-filter=HTTP/3 CONNECT DATAGRAM' \
  -Doptimize=ReleaseSafe --summary all
zig build test-webtransport '-Dtest-filter=flow datagram' \
  '-Dtest-filter=connection termination during datagram receive' \
  '-Dtest-filter=completed datagram receive synchronizes' --summary all
zig build test-compile '-Dtest-filter=HTTP/3 CONNECT DATAGRAM' \
  -Dtarget=x86_64-windows --summary all
```

The native Windows CI command now includes the H3 DATAGRAM filter alongside
HTTP metadata and generic WebSocket adapter checks. The local Windows compile
result does not itself prove native execution. The [public DATAGRAM contract](../../../http3_datagrams.md)
explains caller-owned progress and callback ownership.
