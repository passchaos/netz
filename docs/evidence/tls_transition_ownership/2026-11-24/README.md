# TLS transition socket ownership — 2026-11-24

A caller deadline can expire after TCP connect wins its race but before TLS
starts. The HTTP/1 vail and WSS deadline wrappers checked that timestamp before
entering their common TLS setup function, leaving the connected stream without
an error cleanup owner. They returned `Timeout` with zero socket closes. Named
and resolved-address constructors share these wrappers; WSS uses the same
wrapper for standard and vail TLS.

Deadline validation now runs inside the common setup function, after its raw
stream close guard and before socket options, authority allocation or TLS
initialization. A successful TLS initialization then transfers ownership to
the TLS connection, whose own guard protects the remaining client setup.
HTTP/2 already followed this ordering and remains the control implementation.

The shared `internal/testing/tls_transition.zig` fixture calls public connection
constructors over a real IPv4 loopback socket. Its wrapped IO clock expires
only after the underlying TCP connect succeeds. The connect timer stays
pending until cancellation so the connected result must reach the next owner.
The fixture requires `Timeout`, exactly one observed socket close, zero TLS or
HTTP writes, and EOF from the actual peer. It rescues a leaked socket when the
baseline assertion fails and joins the connect race before replacing its IO
delegate. Tests cover named/address routes for standard and vail H1/WSS and
both H2 routes (ten transitions total).

The baseline has two distinct defects and four failures because H1 tests also
run as imports of the H2 and WebSocket focused roots. The H2 ownership control
passes. Existing successful H1 TLS1.2 and mTLS/KeyUpdate fixtures now call the
public timeout and absolute-deadline constructors respectively. WSS positive
IPv6/authority/budget tests and adopted-stream error cleanup form the overlap
verification set. Native Linux and Windows CI select the transition tests.

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline before the production fix | 90/94 passed, 4 expected failures from 2 defects | [before.log](before.log) |
| Debug transition regressions and affected TLS/adoption paths | 118/118 passed | [Debug.log](Debug.log) |

```sh
zig build test-http1 test-http2 test-websocket '-Dtest-filter=deadline expires after TCP connect' -j1 --summary failures
zig build test-http1 test-http2 test-websocket '-Dtest-filter=deadline expires after TCP connect' '-Dtest-filter=HTTP/1 vail TLS client exposes mTLS metadata and key updates' '-Dtest-filter=HTTP/1 negotiates TLS 1.2 with ALPN' '-Dtest-filter=HTTP1 TLS connection deadline bounds a silent handshake' '-Dtest-filter=HTTP/1 TLS stream adoption owns invalid timeout cleanup' '-Dtest-filter=WebSocket caller-connected timeouts own stream cleanup' '-Dtest-filter=WSS named endpoint' '-Dtest-filter=WSS common handshake budget' -j1 --summary all
```
