# netz documentation map

Start with the first two documents. They define the architecture and the rules
every change must satisfy. The per-protocol parity documents are the feature and
interop authority for their protocol; the benchmark baseline is the historical
performance record.

## Start here

| Document | Purpose |
| --- | --- |
| [architecture.md](architecture.md) | Layered design, performance invariants P1-P10, memory/concurrency doctrine, change acceptance checklist, known structural gaps. |
| [http-overview.md](http-overview.md) | HTTP/1.1, HTTP/2 and HTTP/3 functionality, unified APIs, defaults, ownership boundaries and verified integration findings. |
| [http_direct_h3.md](http_direct_h3.md) | Explicit H3 through Client/Connection, shared request APIs, TLS configuration and the Pool routing boundary. |
| [http_protocol_policy.md](http_protocol_policy.md) | Ordered H3/H2/H1 selection, bounded connection fallback and common Client/Pool policies. |
| [http_bodies.md](http_bodies.md) | Common request body sources, bounded shared H2 Reader uploads and explicit replay across retries, fallback and redirects. |
| [architecture/optimization-backlog.md](architecture/optimization-backlog.md) | November 19 project review: reproduced relay/rate defects, prioritized optimization work, structural findings, and validation requirements. |
| [trust_roots.md](trust_roots.md) | System versus compiled-in Mozilla trust roots, precedence, protocol surfaces, and store reuse. |
| [build.md](build.md) | Build, test, fuzz, interop, release-archive, and evidence gates. |
| [http_forms.md](http_forms.md) | URL-encoded and streaming multipart forms, `body_source`, limits, and HTTP/3 caveats. |
| [performance-playbook.md](performance-playbook.md) | How to profile, author benchmarks, run fixed-binary A/B, record evidence, and decide retain versus reject. |
| [benchmark-baseline.md](benchmark-baseline.md) | Current and historical benchmark results with commands, hashes, and caveats. |

## Protocol parity and completeness

| Document | Protocol / reference |
| --- | --- |
| [coverage.md](coverage.md) | Feature-level coverage inventory and bounded fuzz/live-network verification targets. |
| [grpc_parity.md](grpc_parity.md) | gRPC behavior, xDS, official C++ interop scenarios, channel features. |
| [hyper_parity.md](hyper_parity.md) | HTTP/1.1, HTTP/2 and HTTP/3 behavior, reference peers and implementation evidence. |
| [quicz_parity.md](quicz_parity.md) | QUIC behavior versus quicz. |
| [proxy_parity.md](proxy_parity.md) | SOCKS5, HTTP CONNECT, Shadowsocks, Trojan, VLESS/VMess, TUIC, and Hysteria coverage and verification status. |
| [vpn_mesh_parity.md](vpn_mesh_parity.md) | WireGuard, mesh disco, and DERP frame/relay coverage and verification status. |
| [rumqtt_parity.md](rumqtt_parity.md) | MQTT client, broker, bridge, reconnect, and fuzz behavior versus rumqtt. |
| [websocket_zig_parity.md](websocket_zig_parity.md) | WebSocket behavior versus websocket.zig, including Autobahn results. |
| [webtransport_parity.md](webtransport_parity.md) | WebTransport behavior versus wtransport, including HTTP/2 capsules and browser gates. |

## Performance deep dives

| Document | Topic |
| --- | --- |
| [grpc_shared_performance.md](grpc_shared_performance.md) | Shared request storage and official gRPC benchmark boundaries. |
| [mqtt_commit_log_costs.md](mqtt_commit_log_costs.md) | Durable commit-log cost model. |
| [mqtt_deadline_performance.md](mqtt_deadline_performance.md) | Deadline handling cost in the MQTT runtime. |
| [mqtt_empty_session_performance.md](mqtt_empty_session_performance.md) | Empty-session overhead. |
| [native_timed_read_performance.md](native_timed_read_performance.md) | Native timed-read cost. |
| [stream_read_deadlines.md](stream_read_deadlines.md) | Stream read deadline semantics and cost. |
| [http_client_pool.md](http_client_pool.md) | HTTP client pooling behavior. |
| [logging.md](logging.md) | Process-wide kron logging setup and overhead rules. |

## Design notes

| Document | Topic |
| --- | --- |
| [http_streaming.md](http_streaming.md) | Server streaming ownership plus the client duplex `RequestHandle` for HTTP/1, HTTP/2, and HTTP/3. |
| [websocket_stream_adapter.md](websocket_stream_adapter.md) | RFC 6455 framing over a caller-supplied byte stream, including close-state and peer-close metadata contracts. |
| [http3_complete_requests.md](http3_complete_requests.md) | Complete-request HTTP/3 path. |
| [http3_complete_responses.md](http3_complete_responses.md) | Complete-response HTTP/3 path. |
| [http3_multipath.md](http3_multipath.md) | Application-level multipath over independent QUIC connections, the cross-host probe, and the multi-NIC test recipe. |
| [http_digest.md](http_digest.md) | RFC 9530 content/representation digests, algorithm preferences and streaming integrity verification. |
| [authentication.md](authentication.md) | HTTP/WebSocket/WebTransport/MQTT credential transport, TLS client identity, verifier and admission boundaries. |
| [http_proxy.md](http_proxy.md) | HTTP proxy behavior. |
| [webtransport_http2_capsules.md](webtransport_http2_capsules.md) | WebTransport over HTTP/2 capsule protocol. |
| [webtransport_application_protocol.md](webtransport_application_protocol.md) | WebTransport application protocol negotiation. |
| [webtransport_close_metadata.md](webtransport_close_metadata.md) | Close metadata semantics. |
| [webtransport_session_removal.md](webtransport_session_removal.md) | Session removal and generation handling. |
| [mqtt_delivery_and_disconnect.md](mqtt_delivery_and_disconnect.md) | Delivery and disconnect ordering. |
| [mqtt_session_expiry_restart.md](mqtt_session_expiry_restart.md) | Session expiry across restart. |
| [mqtt_shared_properties.md](mqtt_shared_properties.md) | Shared subscription property handling. |
| [mqtt_will_delay.md](mqtt_will_delay.md) | Will delay semantics. |
| [mqtt_will_lifecycle.md](mqtt_will_lifecycle.md) | Will lifecycle. |
| [weft-integration-requests.md](weft-integration-requests.md) | External integration requests. |

## gRPC / xDS notes

| Document | Topic |
| --- | --- |
| [grpc_ads.md](grpc_ads.md) | Aggregated Discovery Service. |
| [grpc_bootstrap.md](grpc_bootstrap.md) | Bootstrap configuration. |
| [grpc_cds.md](grpc_cds.md) | Cluster Discovery Service. |
| [grpc_channelz.md](grpc_channelz.md) | Channelz. |
| [grpc_circuit.md](grpc_circuit.md) | Circuit breaking. |
| [grpc_client_target.md](grpc_client_target.md) | Client target parsing. |
| [grpc_cluster_impl.md](grpc_cluster_impl.md) | Cluster implementation. |
| [grpc_connection_race.md](grpc_connection_race.md) | Connection race handling. |
| [grpc_delta_xds.md](grpc_delta_xds.md) | Delta xDS. |
| [grpc_eds.md](grpc_eds.md), [grpc_eds_drop.md](grpc_eds_drop.md) | Endpoint discovery and drop behavior. |
| [grpc_federation.md](grpc_federation.md) | Federation. |
| [grpc_goaway_recovery.md](grpc_goaway_recovery.md) | GOAWAY recovery. |
| [grpc_hedging_commitment.md](grpc_hedging_commitment.md) | Hedging commitment. |
| [grpc_ip_literals.md](grpc_ip_literals.md) | IP literal targets. |
| [grpc_lds.md](grpc_lds.md) | Listener Discovery Service. |
| [grpc_lrs.md](grpc_lrs.md), [grpc_lrs_automatic.md](grpc_lrs_automatic.md), [grpc_lrs_registration.md](grpc_lrs_registration.md) | Load reporting. |
| [grpc_rds.md](grpc_rds.md) | Route Discovery Service. |
| [grpc_sds.md](grpc_sds.md) | Secret Discovery Service. |
| [grpc_shared_terminal_deadline.md](grpc_shared_terminal_deadline.md) | Shared terminal deadlines. |
| [grpc_xds_routing.md](grpc_xds_routing.md), [grpc_xds_runtime.md](grpc_xds_runtime.md), [grpc_xds_sotw.md](grpc_xds_sotw.md) | xDS routing and runtime. |

## Evidence

`docs/evidence/` contains machine-readable evidence files grouped by area
(`http1/`, `hpack_huffman/`, `quic_padding_scan/`, `mqtt_retained/`,
`grpc_response/`, and so on). Each file records the change, benchmark command,
binary and source hashes, results, tests, and caveats. Audit them with:

```sh
zig build verify-evidence
```
