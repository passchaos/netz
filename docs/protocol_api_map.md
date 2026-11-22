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
| WebTransport | `webtransport.runtime.Client` / `EndpointClient` | `webtransport.runtime.Server` / `EndpointServer` | `Session`, stream IDs, DATAGRAMs |

`netz.http` is the unified HTTP facade. `netz.streaming.http1/http2/http3` are
aliases for the version-specific streaming owners, not another transport.

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
- WebTransport `Session`, stream and DATAGRAM handles borrow the owning client
  or server connection. Close/terminal events remain owned until deinit.

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
| WebSocket byte-stream deadlines | Optional transport callbacks enable bounded receive/send/close and relative-timeout forms; two-slice writes avoid payload copies for unmasked server frames. Without deadline callbacks the bounded forms report `DeadlineUnsupported`. |
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
- The pass-by-pass review ledger and archived logs live in
  `docs/evidence/protocol_review/`.

See [HTTP overview](http-overview.md), [HTTP streaming](http_streaming.md),
[direct H3](http_direct_h3.md), [WebSocket adapter](websocket_stream_adapter.md),
[WebTransport parity](webtransport_parity.md) and
[QUIC parity](quicz_parity.md) for protocol-specific details.
