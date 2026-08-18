# netz vs rumqtt and Mosquitto MQTT parity audit

This audit records evidence for the MQTT portion of the netz improvement goal.
The source references are `~/Work/rumqtt` at `e886a78` and
`~/Work/mosquitto` at `5cd25465`. Rumqtt contains both a production broker
(`rumqttd`) and clients (`rumqttc`); Mosquitto supplies a mature broker,
persistence format, and conformance suite. Feature, internal microbenchmark,
and equal-wire broker results are kept separate.

## Current feature comparison

| Area | netz | rumqtt / Mosquitto references |
| --- | --- | --- |
| MQTT versions | MQTT 3.1.1 and MQTT 5 packet/runtime; live broker currently MQTT 5 TCP | rumqtt clients support 3.1.1/5; Mosquitto broker supports both |
| Live broker dispatch | Bounded connection slots and queues; SUBSCRIBE/UNSUBSCRIBE; QoS 0/1/2 fanout; downstream Receive Maximum; cleanup | Both references are production brokers with broader lifecycle support |
| QoS | Runtime and live broker QoS 0/1/2, including exactly-once route at PUBREL | Both brokers support QoS 0/1/2 |
| Shared subscriptions | Trie-indexed `{group, filter}`, RoundRobin/Random/Sticky/Rendezvous; broker defaults to RoundRobin | rumqttd has RoundRobin/Random/Sticky; Mosquitto rotates each shared leaf list |
| Topic routing | Exact, `+`, `#`, `$SYS`, No Local, shared groups | Both references provide production topic indexes |
| Fanout ownership | One ref-counted topic/payload allocation shared by every downstream delivery | Mirrors Mosquitto's `mosquitto__base_msg` reference-counted fanout |
| Publisher acknowledgement | Route before PUBACK; MQTT 5 reason `0x10` when no live match | Matches Mosquitto `handle_publish.c`; rumqttd uses its router event path |
| Retained messages | Separate bounded Store with full MQTT 5 rules; not yet composed into live Broker | Both production brokers integrate retained delivery |
| Broker sessions | Separate bounded Session Store; not yet composed into live Broker | rumqttd graveyard/datalog and Mosquitto persisted sessions are integrated |
| Will lifecycle | Separate indexed scheduler; not yet composed into live Broker | Both production brokers integrate Will publication |
| Broker persistence | No disk commitlog yet | rumqttd datalog/segments; Mosquitto persisted sessions, subscriptions, inflight/queued messages and retained base-message store |

Netz now exceeds the audited rumqtt shared-selection policy surface by adding
Rendezvous hashing. This provides deterministic topic affinity and the
important low-remapping invariant: when one member joins, only topics that
select that new member move. It does not replace rumqttd's broader durable
broker architecture or Mosquitto's integrated persistence and protocol
surface.

## Equal-wire live broker comparison

`examples/bench_mqtt_broker.zig` is one external MQTT 5 TCP client workload,
not a broker-specific adapter. It connects subscribers first, verifies every
SUBACK, then connects publishers. Each measured input is a QoS 1 PUBLISH and
each subscriber receives and PUBACKs one QoS 1 delivery. The timer starts only
after warmup deliveries have drained and ends when the last measured
subscriber delivery is acknowledged. The checksum catches missing or
mis-sized payloads.

The netz broker is a finite process for deterministic teardown:

```sh
zig build run-mqtt-broker -Doptimize=ReleaseFast -- \
  --bind=127.0.0.1:18883 --connections=8 \
  --max-queued-deliveries=1024 --max-outgoing-inflight=64
```

Run the same driver against any broker address:

```sh
zig build bench-mqtt-broker -Doptimize=ReleaseFast -- \
  --address=127.0.0.1:PORT --publishers=4 --subscribers=4 \
  --warmup-messages=1000 --messages=20000 --payload-bytes=256
```

2026-08-18 same-host `ReleaseFast` validation:

```text
broker      publishes/s   deliveries/s   checksum
netz             46,375        185,501   20,580,000
Mosquitto        27,745        110,982   20,580,000
rumqttd          15,490         61,962   20,580,000
```

Mosquitto was built from the audited checkout in Release mode with TLS,
WebSocket, HTTP API, clients, plugins and tests disabled, then configured with
64 inflight and 1,024 queued messages. Rumqttd used its release binary and
MQTT 5 listener from `rumqttd.toml`. The workload shape and payload bytes were
identical; equal checksums prove all 80,000 measured deliveries completed.
This result is evidence for this bounded live QoS 1 fanout shape only. It does
not benchmark the QoS 2 path or claim netz exceeds Mosquitto or rumqttd in
persistence, offline sessions, retained/Will integration, tail latency, memory
use, or broader conformance.

## Live QoS 2 dispatch

The broker now follows the audited Mosquitto lifecycle rather than treating
QoS 2 as QoS 1 with extra acknowledgements:

- inbound PUBLISH bytes are deep-owned in a broker-wide bounded store,
- PUBREC is written only after that transaction is stored,
- a DUP=1 PUBLISH with the same Packet Identifier is validated and
  acknowledged without creating another Application Message,
- topic routing happens only when PUBREL arrives,
- a repeated or unknown PUBREL receives PUBCOMP without routing again, matching
  Mosquitto's lost-PUBCOMP recovery behavior,
- downstream QoS remains `min(source QoS, subscription QoS)`,
- downstream PUBREC/PUBREL/PUBCOMP state shares the runtime's fixed Packet
  Identifier tables and Receive Maximum queue,
- disconnect removes all pending transactions owned by that live connection.

Rumqttd likewise records the QoS 2 PUBLISH in its ACK log and appends it to the
commitlog only after PUBREL. Netz keeps this live store deliberately
in-memory; durable Session continuation across reconnect remains separate
work.

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
subprotocol rejection. Client `wss://` uses the existing HTTP/1 TLS transport.
Netz additionally terminates WSS natively with the same strict `mqtt`
subprotocol and MQTT 3.1.1/5 state machine as WS. The TLS listener supports
concurrent serving and optional/required client certificates; verified peer
chains remain visible through `Connection.peerCertificates()`.

## Native MQTT-over-TLS transport

`mqtt.tls_runtime.Client` accepts host names, literal addresses with an explicit
TLS identity, and `mqtts://`/`ssl://` URIs (default port 8883). It reuses the
same Zig 0.16 TLS client as HTTPS/WSS, including operating-system roots,
caller-managed CA bundles, hostname verification, and explicit truncation
policy. Setting `ConnectOptions.client_identity` selects the vail TLS 1.3
stream client so it can answer CertificateRequest with Ed25519, ECDSA, or SM2
identity material. The vail path maps the same system/caller CA and hostname
policy by default, or accepts a pinned/custom `server_verifier`; clients
without an identity keep the standard-library TLS path.

`mqtt.tls_runtime.Server` is a native TLS 1.3 listener backed by project-local
vail primitives. It accepts caller-provided DER certificate chains and
Ed25519/ECDSA/SM2 signers, generates fresh handshake/key-exchange/signature
entropy per connection, supports configured TLS 1.3 cipher-suite preference,
fragments large MQTT writes into bounded TLS records, and preserves byte-stream
semantics when records and MQTT Control Packets have different boundaries. The
accepted transport enters the same MQTT broker-side CONNECT, capability, Topic
Alias, inflight and QoS state machine used by TCP and WebSocket. Client and
server both default TCP_NODELAY on for latency-sensitive control packets and
allow callers to retain Nagle for batching-oriented deployments.

`ListenOptions.client_auth` adds runtime-selectable optional or required mTLS,
rather than rumqttd's process-wide `verify-client-cert` build feature. It emits
TLS 1.3 CertificateRequest, validates the returned chain through a caller
callback or pinned Ed25519/ECDSA/SM2/RSA key, verifies client
CertificateVerify possession and Finished, and keeps an owned peer DER chain
available from `Connection.peerCertificates()` until close. Optional mode
accepts the standards-compliant empty client Certificate response; required
mode rejects it.

End-to-end tests cover a real production-listener handshake with verified
localhost CA/SAN, MQTT 5 CONNECT and QoS 1 PUBLISH/PUBACK, plus MQTT 3.1.1
through `mqtts://`. Native Zig client/server mTLS tests prove client
CertificateVerify, peer-chain exposure, CA/SAN verification, and bad server-pin
rejection. The explicit
`zig build interop-mqtt-mtls-openssl` gate additionally proves authenticated,
ECDSA and RSA-PSS client identities, anonymous-rejected, untrusted-rejected,
and optional-anonymous TLS 1.3 paths against OpenSSL's real
client-certificate implementation.

Run the steady-state 1 KiB QoS 1 baseline with:

```sh
zig build bench-mqtt-tls -Doptimize=ReleaseFast
```

2026-08-18 same-host `ReleaseFast`, median of three runs after 100 warmups and
2,000 measured PUBLISH/PUBACK exchanges through the production TLS server and
MQTT broker-side runtime:

```text
ns/publish+PUBACK: 19,427
operations/s:      51,473
```

This is a reproducible netz baseline rather than an equal-wire rumqtt speed
claim. Unlike rumqtt's feature-gated rustls/native-tls split, the netz API is
available through one built-in Zig TLS transport.

The audited rumqttd rustls path can require a client certificate only when
built with `verify-client-cert`; its native-tls path cannot authenticate
clients. Netz exposes optional/required policy per listener without a feature
split, returns verified peer chains to the application, and provides a native
vail-backed client-identity path. External clients such as OpenSSL also
interoperate with the server.

## Retained-message store

`mqtt.retained.Store` owns Topic Names, payloads, and variable-length MQTT 5
properties under per-message, message-count, and aggregate-byte limits.
Replacing a topic is transactional, and only an empty PUBLISH with RETAIN=1
deletes retained state. The audited rumqttd path instead removes an entry for
any empty payload before checking RETAIN.

Subscription-time delivery implements the MQTT 5 rules directly:

- Retain Handling 0 always sends matching retained messages.
- Retain Handling 1 sends only for a new non-shared subscription; the router's
  `subscribeWithStatus` reports replacement atomically.
- Retain Handling 2 sends none.
- Shared subscriptions receive no retained messages at subscribe time, as
  required by MQTT 5 section 3.8.4.
- Delivery QoS is `min(publish QoS, subscription QoS)` and the RETAIN flag is
  always 1 for retained messages delivered because of SUBSCRIBE.
- Message Expiry Interval is reduced by monotonic elapsed time, expired entries
  are skipped/pruned, and the adjusted property is emitted by the delivery
  encoder.
- Publisher identity is retained for No Local filtering, and Subscription
  Identifiers are injected from the matching subscription when encoding.
- Topic Alias is removed from stored state, while a client-supplied
  Subscription Identifier is rejected.

Rumqttd explicitly contains `TODO: use retain forward rules` and another TODO
for updating an existing DataRequest so retained messages can be forwarded on
every re-subscribe. It also suppresses retained delivery for shared
subscriptions, which agrees with the specification but was previously
undocumented in netz.

Run the internal lookup baseline with:

```sh
zig build bench-mqtt-retained -Doptimize=ReleaseFast
```

2026-08-18 same-host `ReleaseFast` smoke result with 4,096 retained entries:

```text
exact lookup:            138 ns/op
wildcard full scan:  325,232 ns/op
wildcard matches:       4,096/op
```

The exact path uses the topic hash index and both lookup paths write into
caller-owned buffers without allocation. The wildcard scan deliberately
returns every entry, so this is an internal scaling baseline rather than a
whole-broker comparison.

## Persistent Session Store

`mqtt.session.Store` uses generation-checked handles so a duplicate ClientID
takeover immediately invalidates the previous connection. It implements MQTT
3.1.1 CleanSession and MQTT 5 Clean Start/Session Expiry semantics, including
Session Present, expiry overrides on DISCONNECT, explicit discard, and
monotonic expiry pruning.

Server Session State contains:

- complete Subscription options and Subscription Identifiers,
- bounded offline QoS 1/2 PUBLISH queues with owned MQTT 5 properties,
- sent but unacknowledged QoS 1/2 PUBLISH packets,
- PUBREL state awaiting PUBCOMP,
- received QoS 2 Packet Identifiers awaiting completion,
- Message Expiry countdown and connection-scoped Topic Alias rejection.

On resumed Sessions, PUBLISH packets retain their original Packet Identifier
and are retransmitted with DUP=1, while PUBREL packets are resumed with the
original identifier. Negative PUBREC terminates the QoS 2 flow. ACK lookup is
O(1) by Packet Identifier and supports valid out-of-order PUBACK/PUBREC/PUBCOMP
completion.

This exceeds two audited rumqttd graveyard limitations: it has no Session
Expiry cleanup, and `Outgoing::register_ack`/`register_pubcomp` explicitly
reject out-of-order acknowledgements. Rumqttd still has a broader disk-backed
commitlog and production scheduler, so this is not yet whole-broker
superiority.

Run:

```sh
zig build bench-mqtt-session -Doptimize=ReleaseFast
```

2026-08-18 same-host `ReleaseFast` result with 4,096 Sessions:

```text
resume:                    44 ns/op
offline queue:            169 ns/message
reconnect drain (4 msgs): 494 ns/session
```

The benchmark measures in-memory state operations and does not include socket
or disk I/O.

## Will Delay scheduler

`mqtt.will_scheduler.Scheduler` deep-owns the Will Message and MQTT 5 Will
Properties, indexes entries by ClientID, and orders deadlines with an indexed
binary min-heap. Accepted CONNECT reserves heap capacity so subsequent network
close/reconnect/Session-end transitions do not allocate.

Covered lifecycle rules include:

- normal DISCONNECT 0x00 cancels the Will,
- ungraceful close schedules at `min(Will Delay, Session Expiry)`,
- DISCONNECT 0x04 requests the Will while still honoring Will Delay,
- a DISCONNECT Session Expiry override can shorten that deadline,
- Session end or Clean Start=1 makes the old Will immediately due,
- Clean Start=0 reconnect before the deadline cancels the delayed Will,
- reconnect at/after the deadline cannot suppress it,
- a live duplicate ClientID follows the same positive-delay/clean-start rules,
- accepted CONNECT replacement is transactional on validation/allocation failure,
- Will Delay is stripped when encoding the resulting PUBLISH, while Message
  Expiry starts at publication and is forwarded unchanged.

Rumqttd computes the same minimum delay but spreads lifecycle ownership across
a per-link Tokio timeout/channel, a global `will_handlers` mutex map, and a
router `last_wills` map. The netz scheduler provides one bounded transactional
state machine, deterministic caller-buffer polling, deadline introspection, and
generation-safe release handles.

Run:

```sh
zig build bench-mqtt-will -Doptimize=ReleaseFast
```

2026-08-18 same-host `ReleaseFast`, 4,096 Wills over 50 cycles:

```text
set:          158 ns/op
schedule:       8 ns/op
poll+release: 209 ns/op
```

These are the median values from three consecutive runs of the in-process
scheduler benchmark. It measures owned-state installation, deadline scheduling,
polling and release; it is not an equal-wire broker throughput comparison with
rumqttd.

## Remaining work before broad superiority

1. Add a durable disk/replicated commitlog for retained/session/offline/Will
   state.
2. Add a native client-identity option for WSS; native MQTT TLS client/server
   mTLS and WS/WSS server transports are available.
3. Compose the existing retained/session/Will stores into the live Broker,
   including durable QoS 2 continuation across reconnect.
4. Extend the equal-wire driver with concurrent publisher windows, latency
   percentiles, allocations and peak RSS; keep Mosquitto and rumqttd in every
   comparison.
5. Run Mosquitto's protocol/conformance and interoperability suites against
   netz in addition to in-repository codec/runtime tests.
