# Unified HTTP proxy routing

`http.Client` and `http.Pool` accept one fixed cleartext HTTP/1.1 proxy route:

```zig
var client = try http.Client.init(allocator, io, .{
    .http_proxy = .{
        .uri = "http://127.0.0.1:8080",
        .headers = &.{.{
            .name = "Proxy-Authorization",
            .value = "Basic ...",
        }},
    },
});
```

`http.Pool` uses the same `client.http_proxy` field. A pool can reuse an idle
proxy connection for later requests to the same origin, subject to the normal
connection, idle and deadline budgets.

## Routing

| Target | Transport |
| --- | --- |
| `http://` | One HTTP/1.1 connection to the proxy; requests use absolute-form targets and the origin `Host`. |
| `https://` | HTTP/1.1 `CONNECT host:port` to the proxy, then certificate-verified TLS and ALPN to the origin. |
| HTTP/3 | Rejected while `http_proxy` is set; Alt-Svc must not bypass the configured proxy. |

Proxy headers are sent only to the proxy. CONNECT headers never reach the
origin, and origin headers never become proxy authentication. The origin
hostname, TLS SNI, certificate identity and `:authority` remain bound to the
requested origin; the proxy resolves the CONNECT authority.

`http_proxy` and `socks5_proxy` are mutually exclusive. Cleartext H2
prior-knowledge is rejected because an HTTP/1.1 proxy cannot carry it without a
tunnel, and `.http2_only` is rejected for cleartext `http://` targets; HTTPS
CONNECT can still negotiate h2. The proxy URI must use `http://`, must not
contain userinfo, a query or a fragment, and its path must be empty or `/`.

## Deadlines and redirects

One absolute deadline covers proxy DNS/TCP, CONNECT, origin TLS/ALPN and the
request. Redirects re-enter the same proxy route and retain the configured
proxy headers; cross-origin credential isolation still applies to origin
headers, cookies and client identity.

`http.Client.requestUri` and `http.Pool.requestUri` select the correct
absolute-form or origin-form target automatically. Direct users of
`Client.connectUri` plus `Connection.request` must pass the full absolute URI
when `Connection.isForwardProxy()` is true.

HTTPS CONNECT negotiates the origin protocol normally, including `h2`. The
pool's shared HTTP/2 owner can reuse one tunneled connection for later requests
to the same origin, with independent streams and deadlines.

## Limits

The proxy transport is cleartext HTTP/1.1. HTTPS-to-proxy, proxy
authentication challenges, PAC files and proxy auto-selection are not
implemented. HTTP/3 through a proxy is not synthesized. The proxy route is
fixed for the lifetime of one Client or Pool.

Focused coverage is available with:

```sh
zig build test-lib -Dtest-filter='unified HTTP' --summary all
```

The regressions exercise a reused cleartext absolute-form proxy connection and
an HTTPS CONNECT tunnel that verifies origin TLS and keeps proxy authorization
off the origin request.
