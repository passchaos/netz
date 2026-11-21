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
- Reader-backed HTTP uploads compose source reads and network writes under one
  deadline. A canceled source read joins before borrowed storage is released.
- HTTP/3 handshake selection uses `http3.preference_timeout` for the H3 probe
  under `prefer_http3`; TCP fallback keeps the original request deadline.
- `websocket.stream_connection` has no built-in deadline forms. Its transport
  callbacks must implement caller-owned cancellation; runtime connections
  expose the deadline forms.
- Close paths: H1/H2 send close-notify/GOAWAY; direct H3 `Connection.close()`
  sends CONNECTION_CLOSE(NO_ERROR). `closeWithoutCloseNotify` and
  `closeWithDeadline` retire locally without another socket write.

## Bounded resources

| Resource | Default / owner |
| --- | --- |
| QUIC CRYPTO reassembly | 256 KiB per encryption level, grown on demand |
| QUIC handshake datagram | 1200 bytes (minimum path MTU) |
| QUIC 1-RTT send datagram | 1200 bytes (`one_rtt.Config`); PMTUD opt-in |
| QUIC endpoint datagram | 65,535 bytes generic; H3 facade 4096 (socket/receive cap) |
| HTTP body | 16 MiB per request/response in the unified facade |
| HTTP head | 64 KiB H1; protocol-specific H2/H3 limits |
| WebSocket | `max_frame_bytes`/`max_message_bytes`, 16 MiB defaults |
| WebTransport | Session/stream/DATAGRAM queues and flow-control limits in `Limits` |

Raising the HTTP body limit for H3 requires
`http3.handshake.session.max_body_bytes`; H1/H2 use
`http1_limits.max_body_bytes`/`http2_limits.max_body_bytes`.

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
| H3 options nesting | `http3.handshake.handshake` wraps the native QUIC/TLS options; documented, flat accessors are future work. |
| WebSocket byte-stream deadlines | Not provided; use the runtime connections when bounded framing reads are required. |
| Pool Alt-Svc fallback | A setup failure can use TCP without rewinding; a started request keeps method/replay gating. |
| QUIC anti-amplification | The complete server flight is reserved before sending; large chains rely on PTO-driven budget growth. |
| H3 GRO test | One response-batch test hangs at the audited baseline; recorded separately. |

See [HTTP overview](http-overview.md), [HTTP streaming](http_streaming.md),
[direct H3](http_direct_h3.md), [WebSocket adapter](websocket_stream_adapter.md),
[WebTransport parity](webtransport_parity.md) and
[QUIC parity](quicz_parity.md) for protocol-specific details.
