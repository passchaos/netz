# netz vs `~/Work/rumqtt` MQTT parity audit

This audit records evidence for the MQTT portion of the netz improvement goal.
Rumqtt contains both a production broker (`rumqttd`) and clients
(`rumqttc`), so feature and microbenchmark comparisons are kept separate from
whole-broker throughput claims.

## Current feature comparison

| Area | netz | rumqtt reference |
| --- | --- | --- |
| MQTT versions | MQTT 3.1.1 and MQTT 5 packet/runtime support | `rumqttc`: MQTT 3.1.1/5; audited `rumqttd` README still lists MQTT 5 unchecked |
| QoS | QoS 0/1/2 connection state, out-of-order acknowledgements, negative acknowledgements and Receive Maximum | Broker/client QoS 0/1/2 and reconnect retransmission |
| MQTT 5 capabilities | Properties, topic aliases, maximum packet/QoS, retain/wildcard/shared/subscription-ID capability enforcement | Rich v5 client packet/state support |
| Shared subscriptions | Trie-indexed `{group, filter}` routing with allocation-free match, RoundRobin/Random/Sticky and stable Rendezvous hashing | RoundRobin/Random/Sticky broker strategies |
| Topic routing | Exact, `+`, `#`, `$SYS`, No Local and shared groups | Hash maps, logs and broker scheduler |
| Runtime transports | Blocking TCP client/server plus `std.Io.async` concurrent server helper; verified native TLS client; MQTT 3.1.1/5 WebSocket client/server over WS and client-side WSS | Tokio client networking over TCP/TLS/WebSocket/proxy; audited rumqttd WebSocket path has an MQTT 5 TODO |
| Broker persistence | Not yet a full broker session/log store | Datalog, retained messages, graveyard/persistent sessions and reconnect state |

Netz now exceeds the audited rumqtt shared-selection policy surface by adding
Rendezvous hashing. This provides deterministic topic affinity and the
important low-remapping invariant: when one member joins, only topics that
select that new member move. It does not replace rumqttd's broader durable
broker architecture.

## Shared router benchmark

Run:

```sh
zig build bench-mqtt-router -Doptimize=ReleaseFast
```

2026-08-17 same-host `ReleaseFast` ranges over three runs:

```text
4098-filter indexed match:        328-338 ns/op
4098-filter linear scan:          109-111 us/op
indexed speedup:                  327-333x

64-member RoundRobin selection:   267-271 ns/op
64-member Sticky selection:       290-294 ns/op
64-member Random selection:       282-286 ns/op
64-member Rendezvous selection:   1.25-1.34 us/op
```

Every selection path uses the same topic-filter trie; the strategy work is
only paid after a shared group matches. Count-only preflight never advances a
RoundRobin cursor or Random PRNG, so `MatchBufferTooSmall` is transactional.
Random state and the precomputed Rendezvous seed are scoped to each
`{ShareName, TopicFilter}` group instead of coupling unrelated subscriptions.

The corresponding rumqtt router benchmark source in
`~/Work/rumqtt/benchmarks/router/routernxn.rs` is currently commented out, so
there is no honest same-command throughput number to quote. The strategy
comparison is direct source/behavior evidence; the netz timing above is a
reproducible internal baseline rather than a claimed whole-broker speed ratio.

## MQTT-over-WebSocket transport

Run the persistent QoS 1 transport smoke benchmark with:

```sh
zig build bench-mqtt-websocket -Doptimize=ReleaseFast
```

It opens one MQTT 5 session, then measures 2,000 sequential 1 KiB
PUBLISH/PUBACK exchanges after 100 warmups. The benchmark is a reproducible
netz baseline, not yet a rumqtt speed ratio; an equal-wire rumqtt driver still
belongs to the common broker-load work below.

2026-08-17 same-host `ReleaseFast` smoke result:

```text
ns/publish+PUBACK: 13,231
operations/s:      75,579
```

The adapter requires `Sec-WebSocket-Protocol: mqtt` on both client and server.
It reuses the TCP runtime's MQTT negotiation, QoS 0/1/2, inflight, topic-alias,
and capability state rather than maintaining a second protocol state machine.
Like rumqtt's audited `ws_stream_tungstenite` adapter, each write is one binary
WebSocket message while reads expose a continuous byte stream: an MQTT packet
may span messages and one message may contain bytes from multiple packets.
Client masking is done in place on the temporary encoded packet to avoid an
extra payload copy.

The audited rumqtt client supports MQTT 3.1.1 and MQTT 5 over WebSocket, while
the rumqttd server path still contains `TODO: Add support for V5 protocol with
websockets`. Netz tests both versions end to end on its client and server and
also covers cross-message packet reassembly, QoS 1, QoS 2, and strict
subprotocol rejection. Client `wss://` uses the existing HTTP/1 TLS transport;
the netz WebSocket server currently expects cleartext WS or an external TLS
terminator.

## Native MQTT-over-TLS transport

`mqtt.tls_runtime.Client` accepts host names, literal addresses with an explicit
TLS identity, and `mqtts://`/`ssl://` URIs (default port 8883). It reuses the
same Zig 0.16 TLS client as HTTPS/WSS, including operating-system roots,
caller-managed CA bundles, hostname verification, and explicit truncation
policy. TCP_NODELAY defaults on for latency-sensitive MQTT control packets and
can be disabled for batching-oriented deployments.

The in-repository TLS 1.3 peer uses project-local vail primitives and performs a
real encrypted handshake and application-record exchange. End-to-end tests
cover MQTT 5 CONNECT, verified localhost CA/SAN, QoS 1 PUBLISH/PUBACK, and MQTT
3.1.1 through `mqtts://`; no OpenSSL process or public network endpoint is
required.

Run the steady-state 1 KiB QoS 1 baseline with:

```sh
zig build bench-mqtt-tls -Doptimize=ReleaseFast
```

2026-08-18 same-host `ReleaseFast` smoke result after 100 warmups and 2,000
measured PUBLISH/PUBACK exchanges:

```text
ns/publish+PUBACK: 13,674
operations/s:      73,126
```

This is a reproducible netz baseline rather than an equal-wire rumqtt speed
claim. Unlike rumqtt's feature-gated rustls/native-tls split, the netz API is
available through one built-in Zig TLS transport; rumqtt still has broader
client-certificate/mTLS configuration.

## Remaining work before broad superiority

1. Add retained-message storage and delivery rules, including retain-handling
   behavior for new/replaced/shared subscriptions.
2. Add persistent broker sessions, offline queues, Will Delay processing and
   reconnect retransmission equivalent to rumqttd's graveyard/log machinery.
3. Add native MQTT TLS server and server-side WSS termination, plus client
   certificate/mTLS support; verified native TLS and WSS clients are available.
4. Build one identical multi-client publish/subscribe load driver for both
   brokers and capture throughput, tail latency, allocation and peak memory.
5. Add MQTT protocol conformance/interoperability suites beyond in-repository
   codec and runtime tests.
