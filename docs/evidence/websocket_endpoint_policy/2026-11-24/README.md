# WebSocket endpoint identity and TLS budget — 2026-11-24

Named WS clients formatted an IPv6 host as `::1:port`, which the Upgrade
validator rejected with `InvalidHost`. Bracketed IPv6 input also reached the
hostname connector without normalization. Named/resolved-address WSS clients
and the vail URI path omitted the common `tls_handshake_timeout`, so a silent
peer could outlive that budget and fail only when the peer closed the socket.
The [baseline](before.log) captures these two regressions (39/41 passed).

WS/WSS now reuse `internal/endpoint_host.zig` for DNS/IP identity and default
authority formatting. TLS receives the host without IPv6 brackets; Upgrade
receives `[address]:port`. An explicit `ConnectOptions.host` remains independent
of the destination and TLS identity and skips allocation of the unused default
authority. This removes one allocation/free per overridden named connect;
there is no throughput or latency benchmark claim.

All three WSS transport setup paths use `client/tls_policy.zig` before selecting
the TLS backend. Precedence is nested vail timeout, explicit TLS timeout, then
the common TLS handshake timeout. An absolute caller deadline still caps the
attempt.

The live regressions use one zio runtime per test and real loopback sockets:

- Four cleartext Upgrade handshakes inspect the actual Host for raw, bracketed
  and expanded IPv6, bounded/unbounded connects and an explicit authority.
- Eight silent peers exercise standard/vail TLS through host, address, URI and
  adopted-stream entry points. A 10 ms common TLS budget must return `Timeout`
  before the peer closes after 120 ms.
- Twenty-one successful TLS/Upgrade handshakes use an IPv6 listener whose peer
  waits 30 ms. A two-second explicit TLS timeout overrides a zero common
  timeout; a nested vail timeout also overrides a zero explicit TLS timeout.
  They cover the same entry points, separate literal TLS identities and an
  independent HTTP authority. The vail client pins the fixture's public key.

The Debug overlap run also covers hostname and bracketed URI connects,
resolved-address WSS, authenticated HTTP CONNECT proxying, resolver deadlines,
caller TLS deadlines and adopted-stream cleanup. ReleaseSafe includes the
WebSocket interface-binding socket-setup regression because named endpoint
parsing shares that boundary. Linux and Windows native CI select the three
new endpoint-policy tests.

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline before the production fix | 39/41 passed, 2 expected failures | [before.log](before.log) |
| Debug endpoint policy and affected connection paths | 53/53 passed | [Debug.log](Debug.log) |
| ReleaseSafe endpoint policy and WebSocket interface binding | 94/94 passed | [ReleaseSafe.log](ReleaseSafe.log) |

```sh
zig build test-websocket '-Dtest-filter=WebSocket named endpoint' '-Dtest-filter=WSS named endpoint' '-Dtest-filter=WSS common handshake budget' '-Dtest-filter=WebSocket client connects by host name' '-Dtest-filter=WebSocket client connects by bracketed IPv6 URI' '-Dtest-filter=WSS client connects to resolved address' '-Dtest-filter=WebSocket WSS URI authenticates origin through HTTP CONNECT proxy' '-Dtest-filter=WebSocket URI resolver consumes' '-Dtest-filter=WSS caller deadline bounds TLS handshake' '-Dtest-filter=WSS connect options forward TLS timeout' '-Dtest-filter=WebSocket caller-connected timeouts own stream cleanup' -j1 --summary all
zig build test-websocket test-http '-Dtest-filter=WebSocket named endpoint' '-Dtest-filter=WSS named endpoint' '-Dtest-filter=WSS common handshake budget' '-Dtest-filter=WebSocket network interface reaches' -Doptimize=ReleaseSafe -j1 --summary all
```
