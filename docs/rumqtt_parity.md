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
| Retained messages | Bounded owned store, O(1) exact lookup, wildcard delivery, MQTT 5 expiry countdown and full subscription-time rules | HashMap store with expiry; audited routing has Retain Forward Rules/re-subscribe TODOs |
| Runtime transports | Blocking TCP client/server plus `std.Io.async` concurrent server helper; verified native TLS client; MQTT 3.1.1/5 WebSocket client/server over WS and client-side WSS | Tokio client networking over TCP/TLS/WebSocket/proxy; audited rumqttd WebSocket path has an MQTT 5 TODO |
| Broker sessions | Bounded Session Store with Session Expiry, full subscription options/identifiers, offline QoS 1/2 queue, incoming/outgoing QoS 2 and reconnect retransmission | Graveyard restores filter names, tracker cursors and PUBREL IDs; no Session Expiry cleanup |
| Will lifecycle | Owned indexed min-heap scheduler for Will Delay, Session-end deadline, reconnect cancellation, Clean Start/takeover and DISCONNECT actions | Per-link Tokio timeout/channel plus router Last Will map |
| Broker log persistence | In-memory retained/session stores; no disk commitlog yet | Datalog, segments and graveyard state |

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
2. Add native MQTT TLS server and server-side WSS termination, plus client
   certificate/mTLS support; verified native TLS and WSS clients are available.
3. Build one identical multi-client publish/subscribe load driver for both
   brokers and capture throughput, tail latency, allocation and peak memory.
4. Add MQTT protocol conformance/interoperability suites beyond in-repository
   codec and runtime tests.
