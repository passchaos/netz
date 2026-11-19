# Unified HTTP pool request ownership

`http.Pool.requestUri` and its timeout/deadline variants aggregate ordinary
HTTP/2 requests through one frame owner per active origin. A later request can
join the same connection while an earlier response is waiting. Each request
keeps its own deadline and cancellation; canceling one stream does not close
the connection or cancel another stream. `http2_shared_requests` bounds retained
requests, concurrent streams, upload quanta and control/output work. Peer
SETTINGS also bound stream admission.

The owner acquires an ordinary unified TCP lease. This preserves the existing
socket and combined TCP/H3 budgets, origin key, TLS verification, ALPN choice,
ticket caches and idle-return accounting. Negotiated HTTP/1.1 returns to the
exclusive request path. Public `acquireUri` leases remain exclusive and never
share a frame reader with ordinary requests.

## HTTP proxy routing

`client.http_proxy` selects one cleartext HTTP/1.1 proxy for the pool.
Cleartext HTTP requests use absolute-form targets; HTTPS requests use CONNECT
before origin TLS. Proxy headers remain proxy-only, idle proxy connections are
reused per origin, SOCKS5 and HTTP proxy routes are mutually exclusive, and an
HTTP/3 pool is rejected while a proxy is configured. See
[HTTP proxy routing](http_proxy.md) for target selection and limitations.

One HTTP/2 dispatch case retains exclusive aggregation:

| Request/configuration | Current owner | Preserved behavior |
| --- | --- | --- |
| `client.http2_limits.enable_push = true` | Existing HTTP/2 aggregate/push reader | Parent response proceeds through real `PUSH_PROMISE` and pushed-frame processing |

This case is covered by a separate exclusive-path regression and does not count
as shared-request coverage. Push-enabled connections retain the existing
non-reusable policy; callers needing promised-request handles use an exclusive
lease and the low-level push APIs.

Traditional `CONNECT` uses the shared per-origin owner. The request writer
keeps the CONNECT method metadata, omits `:path`/`:scheme`, and closes an empty
request half at HEADERS. A 2xx response completes at HEADERS as a tunnel head
and retires the connection instead of returning it to the idle pool; a rejected
response is read as an ordinary bounded HTTP response and leaves the connection
reusable. The shared aggregate path rejects CONNECT request bodies and trailers
because it cannot expose tunnel bytes; callers that need the tunnel itself use
`openConnectTunnel`.

The shared regression submits its second request only after the server receives
the first, checks request trailers and response ownership, cancels a pending
request while its sibling remains active, and completes a later request with
one allowed TCP connection. The separate Hyper/rustls `h2-shared` mode uses
server barriers and a response-body drop notification to check late admission,
server-observed cancellation, surviving traffic and reuse over one pinned TLS
connection. Existing Hyper H1/H2 modes remain separate two-request gates.
The canonical zio regression receives a held response head and a later
same-connection probe before cancellation, exercising ownership of packed
HPACK header storage while preserving the sibling and later connection reuse.

Duplex push support requires the single connection pump and stream polling to
route `PUSH_PROMISE` and promised HEADERS/DATA through the existing bounded push
state while preserving connection-wide HPACK order and flow-control credit.
The owners are `src/http2/runtime/duplex/client_owner.zig`, the client pump hooks
and `ClientDuplexStream` polling in `src/http2/runtime.zig`, and the helpers under
`src/http2/runtime/push*`. A shared push consumer must submit commands to that
owner; it cannot borrow the raw connection's reader. Promise quotas, parent and
child cancellation, interleaved HPACK, oversized pushes and later reuse require
focused tests before removing the explicit-push fallback.
