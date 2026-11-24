# HTTP/1 named endpoint identity — 2026-11-24

H1 named TCP and standard/vail TLS constructors validated their input only as
`HostName`, rejecting raw/bracketed IPv6. Vail resolved-address connects also
formatted the separate TLS host as `host:port`, producing an unbracketed IPv6
default HTTP authority. The baseline captures three failing live tests.

H1 and H2 now share `internal/tcp_connect/named.zig`, which parses DNS/IP input,
captures the original connect deadline, allocates the default authority and
opens the socket with the existing source/interface binding policy. The caller
owns the stream and authority on success. Invalid input, budget and OOM reject
before network admission; a failed connect releases the allocated authority.

H1 TLS identities are normalized without IPv6 brackets. Default literal
authorities use canonical IP formatting (`[::1]:port`), while request-level Host
overrides remain independent. Standard TLS address constructors retain their
explicit authority parameter. Vail address constructors validate and allocate
their default authority before opening TCP, and their common TLS transition
owns both resources at entry. The socket owner changes after TLS initialization
as before. This also removes authority allocation after the TLS handshake.

The live regressions cover four cleartext and sixteen TLS request/response
exchanges on IPv6 loopback: raw, bracketed and expanded literals; bounded and
unbounded connects; standard/vail TLS; named/resolved-address routes; and an
independent request Host. The vail peer is authenticated by its pinned public
key; standard TLS disables certificate verification for the localhost fixture.
Additional admission tests use a failing allocator and unavailable IO so a
network attempt cannot satisfy invalid-host, expired/foreign-clock budget or
OOM assertions. A zio regression reads the actual interface option and checks
the accepted source tuple for `[::1]` with both local-address and device binds.

The overlap preserves existing H1 DNS/IPv6 URI behavior, H2 authority-allocation
deadline rules and H1/H2 TLS transition cleanup. Linux/Windows native CI select
the new endpoint tests; unsupported TCP interface binding skips only that
platform-specific check.

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline before production changes | 19/22 passed, 3 expected failures | [before.log](before.log) |
| Live IPv6 and shared H1/H2 connection overlap | 71/71 passed | [Debug.log](Debug.log) |
| H1/H2 identity, budget and OOM admission | 47/47 passed | [preflight.Debug.log](preflight.Debug.log) |
| IPv6 source/interface binding | 17/17 passed | [binding.Debug.log](binding.Debug.log) |

```sh
zig build test-http1 '-Dtest-filter=HTTP1 named endpoint' '-Dtest-filter=HTTP1 TLS address endpoint' -j1 --summary failures
zig build test-http1 test-http2 '-Dtest-filter=HTTP1 named endpoint' '-Dtest-filter=HTTP1 TLS address endpoint' '-Dtest-filter=HTTP/2 host connection validates' '-Dtest-filter=HTTP/2 IP and host authority allocation cannot renew' '-Dtest-filter=deadline expires after TCP connect' '-Dtest-filter=HTTP/1 client connects by host name' '-Dtest-filter=HTTP/1 client sends request to bracketed IPv6 URI' -j1 --summary all
zig build test-http1 test-http2 '-Dtest-filter=HTTP1 named endpoint validates' '-Dtest-filter=HTTP/2 host connection validates' -j1 --summary all
zig build test-http1 '-Dtest-filter=HTTP1 named endpoint retains IPv6 network interface' -j1 --summary all
```
