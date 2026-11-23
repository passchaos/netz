# QUIC/HTTP/WebSocket/WebTransport API map

This is the entry point for choosing a transport and understanding its
ownership, deadline and limit contracts. Per-protocol parity documents remain
the feature authority; this page records the cross-protocol shape and the known
asymmetries.

## Entry points

| Layer | Client | Server / listener | Incremental I/O |
| --- | --- | --- | --- |
| QUIC | `quic.handshake.connect*` / `connectFrom*` | `quic.handshake.accept*`, `quic.runtime.Endpoint` | `one_rtt.Connection` streams and DATAGRAMs |
| HTTP | `http.Client`, `http.Pool`, `http.Connection` | `http1.runtime.Server`, `http2.runtime.Server`, `http3.runtime.HandshakeServer` | `http.Connection.startRequest`, `http.Pool.startRequest`, `RequestHandle` |
| WebSocket | `websocket.runtime` clients, `websocket.stream_connection` | runtime listeners/servers, caller-supplied byte streams | runtime message APIs, `stream_connection.Connection` |
| WebTransport | `webtransport.runtime.Client` / `EndpointClient` | `webtransport.runtime.Server` / `EndpointServer` | `Session`, stream IDs, DATAGRAMs, slice sends |
| WebTransport over HTTP/2 | `webtransport.h2.runtime.connect*` / `h2.EndpointClient` | `webtransport.h2.runtime.accept*` / `h2.EndpointServer` | capsule virtual streams, DATAGRAMs, slice sends |

`netz.http` is the unified HTTP facade. `netz.streaming.http1/http2/http3` are
aliases for the version-specific streaming owners, not another transport.

Scatter/gather message sends:

| Layer | Contiguous | Slice form |
| --- | --- | --- |
| WebSocket runtime | `sendText`/`sendBinary` | `sendTextSlices`/`sendBinarySlices` (compression-aware) |
| WebSocket stream adapter | `sendText`/`sendBinary` | `sendTextSlices`/`sendBinarySlices` via `write_slices_fn` |
| WebTransport H3 client/server sessions | `sendStream` | `sendStreamSlices` (borrowed slices) |
| WebTransport H2 session | `sendStreamWith*` | `sendStreamSlicesWith*` (zero-copy header + slices) |
| WebTransport H2 endpoint facades | `sendStreamWith*` | `sendStreamSlicesWith*` (staged command buffer; the reconnecting client and endpoint listener forward the same forms) |

All slice forms have `WithTimeout` and `WithDeadline` counterparts where the
contiguous form does; borrowed slices must outlive the call, including bounded
write retries.

## Ownership

- One task owns a QUIC connection, HTTP/2 connection or HTTP/3 connection at a
  time. Response/body callbacks run on that owner; handlers never read the
  shared socket.
- `http.Client` owns a one-shot connection; `http.Connection` retains it for
  explicit reuse; `http.Pool` adds admission, idle reuse and shared H2/H3
  dispatchers. A `RequestHandle`/`StreamHandle` borrows its connection or pool.
- HTTP/3 direct connections are heap-stable `ConnectionValue.http3` owners.
  `Pool.Options.client` controls primary H1/H2/H3 leases; `Pool.Options.http3`
  controls the optional Alt-Svc dispatcher backend.
- `websocket.stream_connection` never owns the byte stream; the caller supplies
  `read_fn`/`write_fn`/`close_fn`. Runtime connections own their sockets.
  Optional slice callbacks (`write_slices_fn`, `write_slices_deadline_fn`)
  receive the encoded header plus borrowed payload slices.
- WebTransport `Session`, stream and DATAGRAM handles borrow the owning client
  or server connection. Close/terminal events remain owned until deinit.
  Scatter/gather stream sends (H3 `sendStreamSlices*`, H2 session
  `sendStreamSlices*`) borrow the caller's payload slices until the call
  completes, including bounded-write retries; the H2 endpoint command queue
  copies its input.

## Deadlines and cancellation

- Public `WithDeadline` forms take an absolute awake-clock timestamp;
  `WithTimeout` converts once at the boundary. Nested operations keep the
  earlier deadline rather than renewing it.
- QUIC receive loops use two spellings: `*WithTimeout` takes a relative
  `std.Io.Duration` and rejects a non-positive budget with `error.Timeout`;
  `*Timeout` (no `With`) takes `std.Io.Timeout`, which can also express
  `none` or an absolute deadline for supervisor loops.
- Reader-backed HTTP uploads compose source reads and network writes under one
  deadline. A canceled source read joins before borrowed storage is released.
- HTTP/3 handshake selection uses `http3.preference_timeout` for the H3 probe
  under `prefer_http3`; TCP fallback keeps the original request deadline.
- `websocket.stream_connection` exposes deadline and relative-timeout forms
  when its transport supplies `read_deadline_fn`/`write_deadline_fn`;
  otherwise they return `error.DeadlineUnsupported`. Its
  `closeWithDeadline`/`closeWithTimeout` are resumable: a rejected or failed
  Close write leaves the connection open for the unbounded `close`.
  Runtime connections expose deadline forms directly.
- Close paths: H1/H2 send close-notify/GOAWAY; direct H3 `Connection.close()`
  sends CONNECTION_CLOSE(NO_ERROR). `closeWithDeadline`/`closeWithTimeout`
  bound that shutdown output with one awake-clock budget and still release the
  transport when the budget expires. `closeWithoutCloseNotify` retires locally
  without another socket write.

## TLS server authentication

Trust configuration uses a different field spelling per transport, but the
precedence is the same: explicit verifier, then CA material, then a reusable
native store, then the selected root source.

| Transport | Field | Default behavior |
| --- | --- | --- |
| Unified HTTP (H1/H2) | `Client.Options.tls.server_verifier` / `ca_bundle` / `environ` / `system_store` / `root_source` | Platform roots verify the server. |
| Unified HTTP (H3, direct) | Same `tls.*` fields, copied into `http3.handshake.handshake`; `server_auth` and `system_store` may also be set directly under `http3.handshake`. | `tls.server_verifier` is copied to H3; with no explicit trust material the client installs a platform-root verifier, matching H1/H2. |
| Unified HTTP Pool (Alt-Svc H3) | `Pool.Options.http3.handshake.handshake`; unset fields inherit `Pool.Options.client.tls` | Same inheritance and platform-root default as the direct H3 route; empty connection IDs are generated per connection, so `.http3 = .{}` enables the backend. `Pool.Options.client.tls.ca_bundle` has no QUIC representation, so Alt-Svc H3 reports `error.UnsupportedH3TrustConfiguration` at `Pool.init` unless H3 trust is explicit. |
| WebSocket WSS | `ConnectOptions.vail_tls.server_verifier`, or `connectUriTls(..., TlsClientOptions.ca_bundle)` | Platform roots verify the server unless a verifier/CA bundle is supplied. |
| WebSocket over H3 | `websocket.runtime.h3.UriConnectOptions.h3.handshake.server_auth` / `system_store` / `system_environ` / `root_source` | URI connects install platform roots when no explicit QUIC trust material is set; low-level session connects keep the explicit-configuration contract. |
| WebTransport / direct QUIC | `HandshakeClientOptions.handshake.server_auth` (`pinned_ecdsa_p256_public_key`, `verify_trust`), `system_store`, `system_environ`, `root_source` | The low-level QUIC handshake verifies only when one of these is set. `webtransport.runtime.EndpointClient` URI connects install platform roots by default; the lower-level session and address helpers, and `http3.runtime.HandshakeClient.connectUri*`/`requestUri*`, require explicit configuration. The unified `netz.http.Client` H3 route also installs platform roots automatically. |

A pinned ECDSA P-256 key (`pinned_ecdsa_p256_public_key`) checks possession and
the certificate public key without a CA chain; it does not replace hostname
policy for general WebPKI deployments. `tls.verify_host = false` is a TCP TLS
compatibility opt-out: QUIC native-store verification always checks the
certificate identity, so supply an explicit `server_auth` verifier when a
custom QUIC policy is required.

A TCP `ca_bundle` cannot be converted into the QUIC trust representation. When
it is set without explicit H3 trust material, `prefer_http3` keeps the request
on TCP and `http3_only` fails at `Client.init` with
`error.UnsupportedH3TrustConfiguration`; set `http3.handshake.handshake`
(`server_auth`, `system_store`, `system_environ`, or `root_source`) to enable
H3 for private CAs.

## Bounded resources

| Resource | Default / owner |
| --- | --- |
| QUIC CRYPTO reassembly | 256 KiB per encryption level (`max_crypto_buffer`); storage grows with received data up to that limit |
| QUIC handshake datagram | 1200 bytes (minimum path MTU) |
| QUIC 1-RTT send datagram | 1200 bytes (`one_rtt.Config`); `setApplicationDatagramSize` raises the socket cap too; PMTUD opt-in |
| QUIC endpoint datagram | 65,535 bytes generic; H3 facade 4096 (socket/receive cap) |
| HTTP body | 16 MiB per request/response in the unified facade |
| HTTP head | 64 KiB H1; protocol-specific H2/H3 limits |
| WebSocket | `max_frame_bytes`/`max_message_bytes`, 16 MiB defaults |
| WebTransport | Session/stream/DATAGRAM queues and flow-control limits in `Limits` |

Raising the HTTP body limit for H3 requires
`http3.handshake.session.max_body_bytes`; H1/H2 use
`http1_limits.max_body_bytes`/`http2_limits.max_body_bytes`.

Large certificate chains can exceed the 256 KiB handshake CRYPTO budget and
surface `error.CryptoBufferTooLarge`. Raise `max_crypto_buffer` on the QUIC
handshake client/server options (H3 clients:
`options.nativeHandshake().max_crypto_buffer`); the limit does not grow
automatically.

## Error taxonomy

- `error.Timeout` means an operation deadline or configured phase budget
  expired. `error.Canceled` means the caller canceled the operation.
- `error.RequestBodyReadFailed` is a source failure, distinct from a transport
  failure. HTTP retries/fallback require an explicitly replayable body source.
- `error.WebTransportNotNegotiated` means the peer did not negotiate the
  requested WebTransport capability. `UnsupportedWebTransportOption` means the
  selected adapter cannot honor a caller option at all.
- `error.HandshakeSendFailed` means the client could not submit its final
  protected Handshake flight; the connection is not established.
- TLS verification, certificate and client-identity failures are never treated
  as transport unavailability for protocol fallback.

## Known asymmetries

| Item | Current state |
| --- | --- |
| H3 options nesting | `http3.handshake.handshake` still stores the native QUIC/TLS options, but `nativeHandshake()`/`sessionOptions()` provide flat mutable access. |
| WebSocket byte-stream deadlines | Optional transport callbacks enable bounded receive/send/close and relative-timeout forms; two-slice writes avoid payload copies for unmasked server frames. Runtime connections additionally expose arbitrary-slice `sendTextSlices*`/`sendMessageSlices*` forms. Without deadline callbacks the bounded forms report `DeadlineUnsupported`. |
| WebSocket send-only close | HTTP/1 and HTTP/2 expose `sendClose` without waiting for the peer. HTTP/3 completes the handshake through `closeWithTimeout`, which surfaces in-flight application frames as `CloseHandshakeEvent.application` so one call can drain and close. |
| WebSocket frame reception | HTTP/1 and HTTP/2 distinguish `receiveFrame` (returns control frames) from `receiveFrameAuto` (services Pong/Close replies). HTTP/3 always services automatic replies; its `receiveFrameAuto*` forms alias the plain forms so generic call sites stay source-compatible. |
| WebTransport H2 key update | HTTP/3 WebTransport exposes `initiateKeyUpdate` and local/peer key-update counters on sessions and endpoints. HTTP/2 capsule facades do not expose key update; call `http2.runtime.Connection.updateTrafficKeys` before transferring the connection to an endpoint owner. |
| WebTransport H2 reconnecting metadata | TLS metadata accessors live on `Session`, `EndpointClient`, `EndpointServer` and pending requests. The reconnecting facade owns generation state and does not expose metadata directly; use the non-reconnecting endpoint when channel binding or certificate inspection is required. |
| Pool Alt-Svc fallback | A setup failure can use TCP without rewinding; a started request keeps method/replay gating. |
| QUIC anti-amplification | The server plans the largest unacknowledged CRYPTO prefix that fits the allowance and advances the delivered range from client ACKs; client PTO probes run on an independent timer. |

The full QUIC suite includes real-UDP timing tests that can rotate under heavy
host load; each observed failure passes in isolation. Migration-path tests skip
when the host does not configure a `127.0.0.0/8` alias.

## Verification entry points

- Protocol suites: `zig build test-http`, `test-http1`, `test-http2`,
  `test-http3`, `test-quic`, `test-websocket`, `test-webtransport`; the public
  package surface is `test-package`, and `test-compile` compiles both test
  roots without running them. `test-lib` runs the whole library in one binary;
  on a heavily loaded host its real-UDP and tight-timing tests can rotate, so
  triage with the protocol-scoped steps first.
- Bounded fuzz corpus replays: `zig build fuzz-parsers`, `fuzz-stateful`,
  `fuzz-http1-connection`, `fuzz-http1-tls-connection`,
  `fuzz-http2-connection`, `fuzz-http2-tls-connection`,
  `fuzz-http3-connection`, and `fuzz-webtransport-endpoint`. Add `--fuzz=N`
  for coverage-guided runs.
- Performance baselines: `bench-http1-pipeline`, `bench-http1-body`,
  `bench-http2-h2c`, `bench-quic-handshake-stream`,
  `bench-webtransport-stream`, and `bench-webtransport-datagram` (ReleaseFast,
  same-application-shape loopback). Recent numbers and variance notes live in
  `docs/evidence/protocol_review/`.
- The pass-by-pass review ledger and archived logs live in
  `docs/evidence/protocol_review/`.

See [HTTP overview](http-overview.md), [HTTP streaming](http_streaming.md),
[direct H3](http_direct_h3.md), [WebSocket adapter](websocket_stream_adapter.md),
[WebTransport parity](webtransport_parity.md) and
[QUIC parity](quicz_parity.md) for protocol-specific details.
