# netz usage guide

This guide is the practical entry point for applications built on `netz`. It
shows the recommended public APIs for HTTP, WebSocket, WebTransport and QUIC,
with the ownership, deadline and close contracts that matter in real use. The
per-protocol parity documents remain the feature authority; this page is the
"which API do I call" map.

Every snippet below mirrors a runnable example under `examples/`; run
`zig build examples` to compile-check all of them.

## 1. Add the dependency

```zig
// build.zig.zon
.dependencies = .{
    .netz = .{ .path = "../netz" },
},
```

```zig
// build.zig
const netz = b.dependency("netz", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("netz", netz.module("netz"));
```

## 2. Initialize the runtime

All protocol APIs take an allocator and a `std.Io` value; there are no hidden
global sockets or event loops.

```zig
var backend = try netz.runtime.Backend.init(allocator);
defer backend.deinit();
const io = backend.io();
```

- `netz.runtime.Backend` selects the execution backend (zio by default).
- Logging uses kron directly. Install one global logger before starting
  workers; see `examples/logging.zig` and [logging.md](logging.md).
- Keep one owner per connection: a QUIC connection, HTTP/2 connection or
  HTTP/3 connection is driven by one task at a time. Handles borrow that
  owner.

## 3. Choose the entry point

| Task | Recommended entry |
| --- | --- |
| One-shot HTTP request with protocol fallback | `netz.http.Client.requestUri*` |
| Reuse connections across requests | `netz.http.Pool.requestUri*`; add `.http3 = .{}` for Alt-Svc HTTP/3 |
| Prefer HTTP/3 with TCP fallback | `netz.http.Client` or `Pool.Options.client` with `.protocol_policy = .prefer_http3` |
| Explicit direct HTTP/3 | `netz.http.Client` with `.http3_only`, or `http3.runtime.HandshakeClient` |
| Incremental request/response bodies | `Client.connectUri` + `Connection.startRequest`, or `Pool.startRequest` |
| HTTP server | `http1.runtime.Server`, `http2.runtime.Server`, `http3.runtime.HandshakeServer` (aliases: `netz.streaming.http1/http2/http3`) |
| WebSocket client/server | `websocket.runtime.Client/Server`; custom transports use `websocket.stream_connection` |
| WebTransport | `webtransport.runtime.Client/Server` (HTTP/3) or the HTTP/2 capsule adapter |
| Raw QUIC | `quic.handshake.*` plus `quic.one_rtt.Connection` |

## 4. HTTP client quick start

```zig
var client = try netz.http.Client.init(allocator, io, .{
    // Cleartext local servers default to HTTP/1. For HTTPS the same policy
    // offers H2/H1 in one TLS handshake.
    .protocol_policy = .http1_only,
});
defer client.deinit();

var response = try client.requestUriWithTimeout(uri, .{
    .method = "GET",
    .headers = &.{.{ .name = "accept", .value = "text/plain" }},
}, .fromSeconds(5));
defer response.deinit();

std.debug.print("{t} {d}: {s}\n", .{
    response.protocol(),
    response.status(),
    response.body(),
});
```

- `response.protocol()` returns `http1`, `http2` or `http3`.
- `response.header(name)` and `response.headers()` expose repeated fields and
  trailers without allocation; they borrow the owned response.
- `body` is the simplest request body. For uploads larger than memory use
  `.body_source = .{ .reader = ... }` (see [http_bodies.md](http_bodies.md)).
- Duplex handles stream one exchange: write the request body and call
  `finishBody()` before `readResponse()`; reading before the body is finished
  returns `error.InvalidWriterState`.
- Redirects: `requestUriFollowingRedirects*`; the chain shares one deadline.
- Errors: `error.Timeout` for expired or non-positive budgets, protocol errors
  for malformed peers, `error.ConnectionClosed` after a terminal close.

Protocol policy:

| Policy | Behavior |
| --- | --- |
| `.prefer_http2` (default) | HTTPS offers H2 then H1 in one ALPN handshake; cleartext defaults to H1. |
| `.prefer_http3` | Tries authenticated QUIC/H3 first, then falls back to H2/H1 under `http3.preference_timeout`. |
| `.http3_only` | Requires QUIC/TLS 1.3; no TCP fallback. |
| `.http1_only` / `.http2_only` | Pin the wire version. Cleartext H2 requires prior knowledge. |

HTTP/3 cannot be selected by a TCP TLS handshake: TCP ALPN negotiates `h2` or
`http/1.1`, while H3 requires a QUIC connection whose own TLS handshake offers
the `h3` ALPN. `.prefer_http3` therefore probes QUIC first and only falls back
to the TCP ALPN list after H3 is infeasible or exceeds
`http3.preference_timeout`.

Server authentication is on by default for the unified client: H1/H2 use the
platform roots, and the H3 route installs the same platform-root verifier when
no explicit trust material is configured. Set `.tls.server_verifier` to pin a
key; `http3.handshake.handshake.server_auth` configures H3 directly.

The pool's Alt-Svc H3 backend follows the same rule: unset
`Pool.Options.http3.handshake.handshake` trust fields inherit
`Pool.Options.client.tls`, then fall back to platform roots. A TCP
`client.tls.ca_bundle` has no QUIC equivalent, so Alt-Svc H3 requires explicit
H3 trust in that case and `Pool.init` returns
`error.UnsupportedH3TrustConfiguration` instead of connecting unverified.
`prefer_http3` on the direct client keeps the request on TCP in the same
situation; `http3_only` fails at `Client.init`.

For a private CA that must cover both H1/H2 and H3, load a reusable native
store with `netz.tls.trust.SystemStore.initWithPaths` and assign
`.tls.system_store`; the H3 routes inherit it. `.tls.ca_bundle` only applies to
TCP TLS. In minimal containers, `.tls.root_source = .bundled` selects the
compiled-in Mozilla roots for both transports.

The direct H3 route loads a platform-root store per connection when no
reusable store is configured. For repeated `prefer_http3` connections, create
one `SystemStore` and assign `.tls.system_store`, or use `Pool`, which keeps a
single store for its lifetime. A caller-provided `system_store` is borrowed:
keep it alive for every Client/Pool that inherits it.

Proxy routes (mutually exclusive):

| Option | TCP | HTTP/3 | Notes |
| --- | --- | --- | --- |
| `.http_proxy` | HTTP/1.1 CONNECT | ineligible | Cleartext proxy; `http3_only` rejects it. |
| `.socks5_proxy` | CONNECT | UDP ASSOCIATE | Proxy-side destination DNS; `http3_only` accepts it. |

If a SOCKS5 proxy rejects or cannot describe the UDP relay, `prefer_http3`
falls back to TCP through the same proxy instead of failing the request.

Connection reuse:

```zig
var pool = try netz.http.Pool.init(allocator, io, .{
    .client = .{ .protocol_policy = .prefer_http2 },
    .max_connections = 64,
    .max_idle_connections = 32,
    .max_idle_per_origin = 8,
});
defer pool.deinit();

var first = try pool.requestUri(uri, .{ .method = "GET" });
defer first.deinit();
var second = try pool.requestUri(uri, .{ .method = "GET" });
defer second.deinit();
```

The pool negotiates each origin once, retains the selected protocol, and
bounds idle/leased/connecting sockets. `max_idle_per_origin` must not exceed
`max_idle_connections`; the constructor rejects that combination with
`error.InvalidPoolOptions`. An optional `Pool.Options.http3` enables the shared
Alt-Svc dispatcher route; `.http3 = .{}` is valid and uses inherited trust,
generated connection IDs, and the default H3 limits.

Runnable: `zig build run-http-unified-client` (one-shot plus pooled reuse) and
`zig build run-http-duplex` (incremental bodies and trailers).

Common client recipes, each a runnable local example:

| Task | Example |
| --- | --- |
| Query strings, URL-encoded POST, HEAD | `zig build run-http-client-forms` |
| JSON request and response bodies | `zig build run-http-client-json` |
| Stream a chunked download into a file | `zig build run-http-download` |
| Stream 20 MiB after raising the body cap | `zig build run-http-large-body-stream` |
| Multipart upload (`curl -F`) | `zig build run-http-upload-multipart` |
| Cookie persistence across pooled requests | `zig build run-http-cookie-session` |
| Relative redirect chains (`curl -L`) | `zig build run-http-redirects` |
| HTTPS with a pinned server key (`curl --cacert`) | `zig build run-http-https-client` |
| Map a hostname to a local origin (`curl --resolve`) | `zig build run-http-custom-resolver` |
| HTTPS through an HTTP CONNECT proxy (`curl -x`) | `zig build run-http-proxy-client` |
| HTTP/2 over TLS (`curl --http2`) | `zig build run-http-h2-tls` |
| `prefer_http3` selection (`curl --http3`) | `zig build run-http-h3-prefer` |
| Pooled H2 origin upgraded to Alt-Svc H3 | `zig build run-http-pool-alt-svc-h3` |
| Routed server with graceful shutdown | `zig build run-http-server-routes` |
| Managed `serveUntil` loop with shutdown event | `zig build run-http-server-serve-until` |
| Stream an upload from a Reader (`curl -T`) | `zig build run-http-upload-reader` |

## 5. HTTP server quick start

The smallest HTTP/1.1 server:

```zig
var server = try netz.http1.runtime.Server.listen(
    allocator,
    io,
    .{ .ip4 = .loopback(0) },
    .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
);
defer server.deinit();

var connection = try server.accept();
defer connection.close();
var request = try connection.readRequest(.{});
defer request.deinit(server.allocator);
try connection.writeResponse(.{
    .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
    .body = "hello",
    .request_method = request.request.method,
});
```

`Server.serveUntil` is the managed production loop: it bounds concurrent
connections and requests per connection, applies accept/connection error
policies, and stops when a `std.Io.Event` is set. The handler returns
`ResponseOptions`; its body must outlive the handler call (use static or
context-owned storage). See `zig build run-http-server-serve-until`.

- HTTP/2 h2c: `zig build run-http2-h2c`.
- HTTP/3 (real QUIC/TLS handshake): `zig build run-http3-handshake`.
- Incremental request and response bodies: `zig build run-http-streaming`.
- Chunked uploads with trailers: `zig build run-http-chunked`.
- Concurrent handlers and pull bodies: see [http_streaming.md](http_streaming.md).

## 6. WebSocket

Client and server over one TCP connection:

```zig
var server = try netz.websocket.runtime.Server.listen(
    allocator, io, .{ .ip4 = .loopback(0) },
    .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
);
defer server.deinit();
// Server task: accept(), receiveMessage(), sendText(), then receive the Close.
```

```zig
var client = try netz.websocket.runtime.Client.connectUri(
    allocator, io, "ws://127.0.0.1:8080/chat",
    .{ .protocols = &.{"chat.v1"} },
);
defer client.close();

try client.sendText("hello");
var message = try client.receiveMessage();
defer message.deinit(allocator);
try client.sendClose(.normal_closure, "bye");
```

- After either side starts the closing handshake, only the Close frame may be
  sent; other writes return `error.ConnectionClosed`.
- `closeWithDeadline`/`closeWithTimeout` are resumable: a failed or timed-out
  Close write leaves the connection open for the unbounded `close`.
- Arbitrary-slice single-frame sends avoid payload joins:
  `sendTextSlices`, `sendBinarySlices`, and their timeout/deadline forms.
  Text slices are validated as one UTF-8 message across slice boundaries.
- For caller-supplied byte streams use `websocket.stream_connection`; its
  bounded forms require `read_deadline_fn`/`write_deadline_fn` and otherwise
  return `error.DeadlineUnsupported`.

Runnable: `zig build run-websocket-echo` (cleartext) and
`zig build run-websocket-wss-echo` (WSS with a pinned server key).

## 7. WebTransport

HTTP/3 WebTransport owns a CONNECT session; streams and DATAGRAMs borrow it.
The URI form derives SNI, authority and path from one HTTPS URL and verifies
the server against the system trust store by default. Connection IDs are
caller-generated per connection (8-byte original DCID, 4-byte local CID):

```zig
var original_dcid: [8]u8 = undefined;
var client_cid: [4]u8 = undefined;
try std.Io.randomSecure(io, &original_dcid);
try std.Io.randomSecure(io, &client_cid);

var client = try netz.webtransport.runtime.HandshakeClientSession.connectUriWithTimeout(
    allocator,
    io,
    .{ .ip4 = .unspecified(0) },
    "https://example.com/wt",
    .{ .h3 = .{ .handshake = .{
        .original_destination_connection_id = &original_dcid,
        .local_connection_id = &client_cid,
    } } },
    .fromSeconds(10),
);
defer client.deinit();

const stream_id = try client.openBidirectionalStream();
try client.sendStream(stream_id, "hello", true);

var event = try client.receiveStream();
defer event.deinit();
```

Use `connect`/`connectWithTimeout` with explicit `authority`/`path` when the
server address is already resolved (the address-based form shown in
`examples/webtransport/webtransport_handshake_stream.zig`).

- Server: `webtransport.runtime.HandshakeServer.bind` then `accept()`.
- Streams: `openBidirectionalStream`/`openUnidirectionalStream`,
  `sendStream`/`writeStream`, `receiveStream`, `resetStream`,
  `stopSending`, `finishStream`.
- Slice sends: HTTP/3 sessions (including `webtransport.runtime` endpoint
  sessions) expose `sendStreamSlices`; HTTP/2 sessions and endpoint facades
  expose `sendStreamSlicesWithTimeout/Deadline`. The H2 session writes the
  capsule header plus borrowed payload slices directly, so keep the slices
  valid until the call (including bounded-write retries) completes; the H2
  endpoint facades stage one command buffer.
- DATAGRAMs: `sendDatagram(s)`, `receiveDatagram(s)Into` with deadlines.
- Session termination: a peer CLOSE is reported as a session event; close
  metadata remains valid until deinit. See
  [webtransport_close_metadata.md](webtransport_close_metadata.md).
- HTTP/2 capsule WebTransport is available under `webtransport.h2`; see
  [webtransport_http2_capsules.md](webtransport_http2_capsules.md).

Runnable: `zig build run-webtransport-handshake-stream` (streams),
`zig build run-webtransport-datagram-echo` (unreliable DATAGRAMs), and
`zig build run-webtransport-h2-capsule-echo` (HTTP/2 capsule streams with
slice sends).

## 8. QUIC directly

Use the handshake helpers for full QUIC/TLS, or `quic.one_rtt.Connection` for
preconfigured-key transports:

```sh
zig build run-quic-echo
zig build run-quic-handshake-echo
zig build run-quic-datagram-echo
zig build run-quic-close
```

- 0-RTT: `quic.zero_rtt` plus the handshake early-data options; see the
  zero-RTT tests and [quicz_parity.md](quicz_parity.md).
- One owner drives each connection; ACKs, timers and loss recovery are
  serviced by the receive path.

## 9. Deadline, close and error conventions

- Every blocking operation has `WithDeadline` (absolute awake-clock) and, for
  public APIs, `WithTimeout` (relative). A non-positive timeout returns
  `error.Timeout` before I/O; a wrong clock or expired deadline is rejected
  before state changes.
- Nested operations keep the earlier deadline instead of renewing it.
- Close semantics: H1/H2 send close-notify/GOAWAY; direct H3 sends
  CONNECTION_CLOSE(NO_ERROR). `closeWithTimeout` bounds shutdown output and
  still releases the transport when the budget expires.
- Errors are module-level unions (for example `netz.http.Error`,
  `netz.websocket.Error`, `netz.webtransport.Error`). Protocol violations are
  distinct from transport unavailability, so fallback policies never treat
  TLS verification or certificate failures as "try another protocol".
- `error.CryptoBufferTooLarge` during a QUIC/H3 handshake means the peer's TLS
  flight exceeded `max_crypto_buffer` (256 KiB default). Raise
  `http3.handshake.handshake.max_crypto_buffer` (or the equivalent low-level
  QUIC option); storage grows with received data up to that bound.
- Slice sends follow the same deadline and close rules as contiguous sends.
  HTTP/3 reports the committed logical prefix so callers can retry only the
  suffix; the HTTP/2 session retains the pending capsule and resumes it with
  `resumeWriteWithTimeout`/`resumeWriteWithDeadline`.

## 10. Limits and defaults

The cross-protocol resource table lives in
[protocol_api_map.md](protocol_api_map.md). Common defaults:

| Resource | Default |
| --- | --- |
| HTTP body (unified facade) | 16 MiB; applies to buffered and streamed bodies, raise `http1_limits`/`http2_limits.max_body_bytes` or `http3.handshake.session.max_body_bytes` |
| HTTP/3 body override | `http3.handshake.session.max_body_bytes` |
| QUIC CRYPTO reassembly | 256 KiB (`max_crypto_buffer`) |
| QUIC 1-RTT datagram | 1200 bytes (`one_rtt.Config`), PMTUD opt-in |
| WebSocket frame/message | 16 MiB |
| WebTransport | `Limits` session/stream/DATAGRAM queues |

## 11. Where to go next

- [protocol_api_map.md](protocol_api_map.md): ownership, deadlines, errors and
  known asymmetries for every protocol.
- [http-overview.md](http-overview.md): HTTP versions, unified APIs, defaults.
- [http_protocol_policy.md](http_protocol_policy.md): H3/H2/H1 selection and
  fallback.
- [http_bodies.md](http_bodies.md), [http_streaming.md](http_streaming.md):
  uploads, duplex handles and streaming bodies.
- [websocket_stream_adapter.md](websocket_stream_adapter.md),
  [webtransport_parity.md](webtransport_parity.md),
  [quicz_parity.md](quicz_parity.md): protocol specifics.
- `examples/README.md`: all runnable examples and benchmark commands.
