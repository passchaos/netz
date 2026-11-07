# Unified HTTP proxy routing validation

`http.Client` and `http.Pool` now accept one cleartext HTTP/1.1 proxy route.
Cleartext HTTP requests use absolute-form targets; HTTPS requests establish an
HTTP/1.1 CONNECT tunnel before origin TLS/ALPN. Proxy headers remain
proxy-only, and an HTTP/3 pool is rejected while a proxy is configured.

| Gate | Result | Evidence |
| --- | --- | --- |
| Unified HTTP proxy and pool Debug | 216/216 tests | `http-proxy.Debug.log` |
| Complete HTTP module Debug | 2558/2558 tests | `http.Debug.log` |

The focused regression starts a real loopback HTTP/1.1 proxy. Two pooled
requests to the same origin reuse one proxy connection, send absolute-form
targets, preserve the origin `Host`, forward `Proxy-Authorization`, and keep
application headers separate. A second regression sends CONNECT to the proxy,
verifies the origin TLS certificate through a pinned key, completes an HTTP/1.1
request over the tunnel, and proves `Proxy-Authorization` never reaches the
origin.

Limitations are documented in `docs/http_proxy.md`: cleartext HTTP/1.1 proxy
transport only, no HTTPS-to-proxy, PAC or proxy authentication challenges, and
no HTTP/3 through the proxy.

Reproduce with:

```sh
zig build test-lib -Dtest-filter='unified HTTP' --summary all
zig build test-lib -Dtest-filter=HTTP --summary all
```
