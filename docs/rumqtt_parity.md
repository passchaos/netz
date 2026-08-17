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
| TCP runtime | Blocking client/server plus `std.Io.async` concurrent server helper | Tokio client/broker networking, TLS, WebSocket and proxy options |
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

## Remaining work before broad superiority

1. Add retained-message storage and delivery rules, including retain-handling
   behavior for new/replaced/shared subscriptions.
2. Add persistent broker sessions, offline queues, Will Delay processing and
   reconnect retransmission equivalent to rumqttd's graveyard/log machinery.
3. Add TLS and MQTT-over-WebSocket runtime transports.
4. Build one identical multi-client publish/subscribe load driver for both
   brokers and capture throughput, tail latency, allocation and peak memory.
5. Add MQTT protocol conformance/interoperability suites beyond in-repository
   codec and runtime tests.
