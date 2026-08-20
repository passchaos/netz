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
| MQTT versions | MQTT 3.1.1 and MQTT 5 packet/runtime; one live TCP broker listener auto-detects both versions | rumqtt clients support 3.1.1/5; Mosquitto broker supports both |
| Live broker dispatch | Bounded connection slots and queues; SUBSCRIBE/UNSUBSCRIBE; QoS 0/1/2 fanout; downstream Receive Maximum; cleanup | Both references are production brokers with broader lifecycle support |
| QoS | Runtime and live broker QoS 0/1/2, including exactly-once route at PUBREL | Both brokers support QoS 0/1/2 |
| Shared subscriptions | Trie-indexed `{group, filter}`, RoundRobin/Random/Sticky/Rendezvous; broker defaults to RoundRobin | rumqttd has RoundRobin/Random/Sticky; Mosquitto rotates each shared leaf list |
| Topic routing | Exact, `+`, `#`, `$SYS`, No Local, shared groups | Both references provide production topic indexes |
| Fanout ownership | One ref-counted topic/payload/property allocation shared by every downstream delivery | Mirrors Mosquitto's `mosquitto__base_msg` reference-counted fanout |
| Publisher acknowledgement | Route before PUBACK; MQTT 5 reason `0x10` when no matching subscription | Matches Mosquitto `handle_publish.c`; rumqttd uses its router event path |
| Retained messages | Bounded Store integrated into live publish/subscribe, with expiry, Retain Handling, No Local, shared suppression, QoS and identifiers | Both production brokers integrate retained delivery |
| Broker sessions | Live Session Present/Clean Start/Expiry/takeover, persistent subscriptions, offline QoS 1/2 queues and reconnect retransmission | rumqttd graveyard/datalog and Mosquitto persisted sessions are integrated |
| Will lifecycle | Indexed scheduler integrated into live Broker: abnormal close, DISCONNECT 0x04, Delay/Session Expiry, reconnect cancellation and retained Will | Both production brokers integrate Will publication |
| Keep Alive | Broker enforces the negotiated 1.5x inbound inactivity deadline with exact half-second precision, zero-disable semantics and Will/Session cleanup | Mosquitto uses a broker-wide deadline ring and disconnects clients that exceed Keep Alive x 1.5 |
| MQTT 5 Enhanced Authentication | Initial multi-step AUTH before CONNACK, owned method binding, re-authentication traffic gate and broker policy callback | Mosquitto plugin start/continue callbacks and active re-authentication; rumqtt codec/runtime coverage is narrower |
| Broker persistence | Atomic versioned snapshots for retained messages, scheduled Wills, durable Sessions, outgoing QoS 1/2 and inbound QoS 2 transactions | rumqttd datalog/segments; Mosquitto persisted sessions, subscriptions, bidirectional client-message state and retained/Will base messages |

Netz now exceeds the audited rumqtt shared-selection policy surface by adding
Rendezvous hashing. This provides deterministic topic affinity and the
important low-remapping invariant: when one member joins, only topics that
select that new member move. It does not replace rumqttd's broader durable
broker architecture or Mosquitto's full persistence plugin and protocol
surface.

## Atomic broker snapshots

The live broker now follows the durability shape audited in Mosquitto
`persist_write.c` and `mosquitto_write_file`: serialize a coherent in-memory
view, write a restricted temporary file, `fsync` it, then atomically replace
the destination. Netz uses Zig 0.16 `std.Io.File.Atomic` rather than hand-written
temporary-name logic.

The versioned binary format has whole-file and per-section CRC32 checks and
persists:

- unexpired retained messages, forwarding properties and publisher identity,
- durable ClientID Session metadata and stable router identity,
- complete subscription options and Subscription Identifier,
- offline queued QoS 1/2 messages,
- outgoing inflight QoS 1/2 state, Packet Identifier and PUBREL continuation,
- scheduled Wills with ClientID, full Application Message properties, canonical
  publisher identity and exact remaining delay,
- inbound QoS 2 Application Message bodies awaiting PUBREL, keyed by stable
  Session route identity rather than a short-lived connection slot.

`Broker.saveSnapshot` is a quiescent shutdown/admin operation: it holds the
broker state lock and rejects live clients, pending broker QoS 2 transactions
or Wills rather than racing a network writer that has emitted but not yet
acknowledged a frame. `Broker.restoreSnapshot` has the same transient-state
gate and is intended for startup; it decodes retained and Session sections into
temporary stores, rebuilds a temporary router, and commits all three only after
every validation/allocation succeeds.
Corrupt CRC, unsupported version, duplicate identity and configured bound
failures therefore leave current broker state unchanged.

The snapshot records wall-clock save time plus exact remaining nanoseconds for
Session/Message Expiry and Will deadlines. Restore deducts broker downtime
instead of extending lifetimes across a new monotonic-clock epoch. Sessions
that were online at save are restored offline; outgoing inflight PUBLISH
packets resume with DUP, while QoS 2 transactions already awaiting PUBCOMP
resume directly at PUBREL even after Application Message expiry. A restored
Will that expired during downtime enters the due heap immediately; a not-yet-
due Will remains indexed by ClientID and can still be canceled by a continued
Session reconnect. Pending inbound QoS 2 expiry is also reduced during downtime.
After reconnect, broker event parsing deliberately exposes an otherwise unknown
PUBREL to the broker; stable Session identity resolves its persisted body, which
is routed exactly once before PUBCOMP. A repeated PUBREL receives another
idempotent PUBCOMP without a second delivery.

Tests cover atomic replacement, CRC corruption rollback, downtime expiry,
retained state, subscriptions, offline queue, outgoing inflight retransmission,
and a real new-broker reconnect with Session Present plus restored live
routing. Scheduled-Will tests cover downtime deadline reduction, canonical
publisher restoration, reconnect cancellation, driver publication after an
actual broker restart and retained-Will storage. This snapshot surface still
has narrower online autosave/plugin integration than Mosquitto, but tests now
also cover inbound QoS 2 body ownership, downtime expiry, Clean Start cleanup,
real broker restart, Session Present, post-restart PUBREL routing and duplicate
PUBREL idempotence.

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
  --max-queued-deliveries=1024 --max-outgoing-inflight=64 \
  --persistence=netz-mqtt.db
```

The finite example restores that snapshot before accepting clients and saves
again after all configured connections exit. `--no-restore` starts from an
empty in-memory state but still writes the final snapshot.

Run the same sequential (window-one) driver against any broker address:

```sh
zig build bench-mqtt-broker -Doptimize=ReleaseFast -- \
  --address=127.0.0.1:PORT --publishers=4 --subscribers=4 \
  --warmup-messages=1000 --messages=20000 --payload-bytes=256
```

2026-08-18 same-host `ReleaseFast` window-one validation:

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
persistence, offline sessions, Will integration, tail latency, memory use, or
broader conformance.

The broker hot path now retains each connection's encoded PUBLISH output
buffer after first use; repeated delivery allocates only the stateless codec's
temporary variable section rather than a second output buffer. A failing-
allocator socket test proves that no second allocation occurs after warmup.
Plan flushing also removed quadratic prefix searches for overlapping
subscriptions: the first visit drains the slot queue and later matches are
constant-work empty checks, keeping the pass O(matches). The external workload
accepts `--overlapping-subscriptions=1..3` for exact/+/# stress shapes.

The same equal-wire driver accepts `--publisher-window=N`: each publisher
submits up to N QoS 1 PUBLISH packets before reading the corresponding PUBACKs.
It reports publish-completion p50/p99/p99.9 plus client-side allocation calls,
cumulative allocated bytes and peak live bytes. The window mode exposed both an
inflight-hole unsigned-subtraction panic and two production hot-path problems:
plain MQTT TCP retained Nagle, and Session draining rescanned every consumed
queue tombstone for every outgoing packet. Saturating hole accounting covers
the first problem. Plain TCP now defaults TCP_NODELAY on both accepted and
connected sockets (with an explicit opt-out), while each Session retains a
queue-head cursor and resets its logical storage when the live queue empties.
Online Session Expiry zero clients now also use the live connection's inflight
table and one shared Publication instead of deep-cloning every QoS 1/2 fanout
into durable Session storage; persistent/offline Sessions retain the owned
retransmission path.

On 2026-08-20, three consecutive same-host `ReleaseFast` runs used four
publishers, four subscribers, 1,000 warmups, 20,000 measured 256-byte QoS 1
publishes, fanout four, and a publisher window of 64. Rumqttd `e886a78` ran
with one MQTT 5 listener, 1,024 router outgoing packets and 1,024 connection
inflight packets. Both brokers received the exact same newly built netz client
binary. Broker RSS was sampled from `/proc/PID/status` every 2 ms while the
driver was alive; the table reports the median of each three-run metric:

```text
broker    pub/s    deliveries/s   p50 ms   p99 ms   p99.9 ms   client allocs   client peak B   broker peak RSS KiB
netz      55,505        222,023    1.813    3.921       4.795         504,105         504,170                 6,436
rumqttd    6,902         27,609    1.335   41.100      41.800         672,121         504,436                17,632
```

Every run completed 80,000 measured deliveries with checksum 20,580,000. In
this bounded windowed shape, netz delivered 8.04x rumqttd's median throughput,
used 25.0% fewer client allocation calls and 63.5% less broker peak RSS. Netz's
median completion was 1.36x slower, but its p99 and p99.9 were respectively
10.48x and 8.72x lower. Client cumulative allocation was 120,171,264 bytes for
netz versus a median 133,108,088 bytes for rumqttd. These are equal-driver
results for this workload, not a persistence, QoS 2, crash-safety or broad
conformance verdict.

The queue cursor was selected from measurement rather than assumption. Before
the change, `perf record -F 997 -g` attributed about 50-53% of broker cycle
samples to `Broker.flushSlotLocked`; annotation placed 43% of the atom-core
samples on the null test while scanning the consumed queue prefix. After the
cursor change the same symbol accounted for 4.9% of atom-core samples. The
transient-session fast path then raised the unprofiled three-run range from
37,098-40,021 to 53,843-54,197 publishes/s. Finally, moving the large runtime
Connection into its stable broker slot before constructing the async client
task removed a redundant closure/worker-stack copy. The task now owns only the
compact CONNECT parse tree, and attach-time errors follow the normal unregister
cleanup path. Median broker peak RSS fell from 9,344 to 8,496 KiB while the
three-run range remained 54,655-55,781 publishes/s. The finite production
example then moved from the SMP allocator's per-worker caches to libc's shared
allocator. Median peak RSS fell to 6,436 KiB with a 54,847-56,486 publishes/s
range; callers of the broker library retain explicit allocator control.

The same shape was also run three times against a release build of audited
Mosquitto `5cd25465`, configured with 64 inflight and 1,024 queued messages.
Its per-metric medians were 7,025 publishes/s, 28,100 deliveries/s, 4.922 ms
p50, 44.307 ms p99, 46.752 ms p99.9, 672,109 client allocations, 504,223
client peak bytes, and 3,868 KiB broker peak RSS. Netz therefore delivered
7.90x its throughput with 2.72x lower p50 and 11.30x lower p99, but used 1.66x
the broker RSS in this eight-client run. Mosquitto's smaller RSS remains a
clear memory target rather than being hidden by the throughput result.

The production driver also covers durable online Sessions through
`--session-expiry-seconds=300`. Three otherwise identical window-64 runs gave
these per-metric medians:

```text
broker       pub/s   deliveries/s   p50 ms   p99 ms   p99.9 ms   client allocs   broker peak RSS KiB
netz        39,146        156,586    2.769    5.711       6.404         504,113                 6,456
Mosquitto    6,341         25,365    4.102   44.989      45.953         672,117                 3,804
rumqttd      6,999         27,996    1.037   40.942      41.756         672,129                17,448
```

All nine runs completed 80,000 measured deliveries with checksum 20,580,000.
For this reconnect-safe QoS 1 shape, netz delivered 6.17x Mosquitto and 5.59x
rumqttd throughput, with respectively 7.88x and 7.17x lower p99. Netz used
69.7% more broker RSS than Mosquitto but 63.0% less than rumqttd. The durable
netz path is 29.5% below its transient-session median because each destination
must deep-own payload and acknowledgement state until completion; that cost is
now measured rather than hidden. Persistence crash windows and broader
conformance remain separate gaps.

Durable Session publications now store Topic Name and payload in one contiguous
allocation per destination instead of two. This preserves independent
reconnect ownership and the existing snapshot views while removing one
allocator round trip from every durable fanout. Three reruns of the expiry-300
shape measured 38,738-40,299 publishes/s (median 39,077), p99
5.467-5.664 ms, p99.9 5.973-6.577 ms and 6,476 KiB median broker peak RSS.
Throughput remained effectively flat versus the prior 39,146 median, while
tail latency improved about 1.7-1.9%; the main value is simpler bounded
ownership rather than a claimed throughput step.

## MQTT 3.1.1/5 broker interoperability

The live TCP listener now follows Mosquitto's version negotiation model: the
configured protocol is only an initial parser default, while CONNECT selects
MQTT 3.1.1 or MQTT 5 independently for every accepted socket.

- MQTT 3.1.1 and MQTT 5 publishers/subscribers can share one listener and route
  between versions.
- Empty clean-session Client IDs receive secure random UUID-style identities
  with a copied, configurable prefix. MQTT 5 reports the value through Assigned
  Client Identifier and the client runtime preserves it after CONNACK cleanup;
  MQTT 3.1.1 uses the unique identity internally without an unavailable
  property. Multiple anonymous clients therefore cannot accidentally take over
  the same empty-string Session, and an MQTT 5 client can reconnect using its
  assigned value.
- MQTT 5 Application Message properties are preserved for MQTT 5 destinations
  and omitted when encoding the same fanout for an MQTT 3.1.1 destination.
- MQTT 3.1.1 CleanSession=0 resumes subscriptions and offline QoS 1/2 state
  indefinitely, while CleanSession=1 discards that Session.
- CONNACK Session Present, SUBACK, UNSUBACK and QoS ACK packets use each
  connection's wire format. MQTT 5-only reason codes are downgraded to the
  success-only MQTT 3.1.1 ACK representation.
- QoS 2 still routes only at PUBREL and completes PUBREC/PUBREL/PUBCOMP across
  both versions.

These paths are covered with mixed-version, multi-filter UNSUBACK, persistent
Session/offline QoS 1, and QoS 2 end-to-end tests.

## MQTT 5 Enhanced Authentication

The shared runtime now implements the state ownership that previously existed
only as raw AUTH packet helpers:

- CONNECT Authentication Method is deep-owned by the connection and remains
  fixed for every AUTH and successful CONNACK packet.
- A client `ClientAuthHandler` can answer multiple server AUTH Continue
  Authentication challenges before CONNACK.
- Server `acceptPending` exposes typed challenge/response helpers so an
  application authentication mechanism can finish before Session acceptance;
  successful CONNACK is blocked until explicit application authorization and
  can carry copied final Authentication Data.
- Active clients or servers can start/accept re-authentication; normal
  PUBLISH/SUBSCRIBE/PING traffic is rejected in both directions until AUTH
  Success, and a peer that sends such traffic receives DISCONNECT Protocol
  Error.
- `readBrokerEvent` exposes AUTH and the live broker has an optional policy
  callback for re-authentication rather than treating AUTH as an unexpected
  packet.
- a missing or changed Authentication Method is rejected; peer-initiated
  mismatch emits DISCONNECT Protocol Error as Mosquitto does.
- send-side phase transitions are committed transactionally around network
  writes, and rejected inbound packets release their owned packet buffers.

End-to-end tests mirror Mosquitto's
`09-extended-auth-multistep-reauth.py`: a mirror-method initial challenge,
successful CONNACK, active multi-step re-authentication, traffic gating, return
to PING, plus bad-method Protocol Error. The runtime deliberately supplies
protocol orchestration and policy hooks, not a built-in SCRAM or credential
database.

## Broker Keep Alive enforcement

The broker now turns the Keep Alive parsed from CONNECT into an enforced
inbound inactivity deadline instead of retaining it as informational state:

- a non-zero interval closes the TCP Network Connection after exactly 1.5x the
  negotiated value, preserving the half second for odd values rather than
  truncating to whole seconds;
- MQTT 5 Server Keep Alive replaces the CONNECT value on both sides of the
  accepted connection, so the advertised override is the value the broker
  enforces;
- Keep Alive zero disables the deadline as required by MQTT;
- one deadline covers an ordinary complete Control Packet, so a peer cannot
  evade Keep Alive by trickling a small packet. As in Mosquitto, progress on a
  large packet renews the budget only while more than 1,000 bytes remain;
- timeout is an ungraceful disconnect and follows the existing Session and
  Will paths. An immediate Will is routed, while durable Session State is
  retained according to its Session Expiry policy.

Mosquitto's audited `src/keepalive.c` schedules clients at
`last_msg_in + keepalive*3/2`, while `lib/packet_mosq.c` refreshes progress for
large partial packets. Netz preserves those semantics without a timer task per
client by applying Zig 0.16 timed socket reads directly in each already-owned
broker reader. Tests cover exact timeout arithmetic including the maximum
u16 value, byte-progress renewal beyond one whole timeout, post-timeout Will
routing, and a live Keep Alive zero connection remaining usable past the
one-second expiry boundary.

## Live retained-message integration

The bounded retained Store is now part of `mqtt.broker.Broker` rather than an
isolated utility:

- a released QoS 0/1/2 PUBLISH atomically applies retained replacement or
  empty-payload deletion while the broker state lock is held,
- Topic Alias is expanded by the runtime and stripped from stored/forwarded
  state,
- SUBSCRIBE uses the router's atomic new-versus-replacement result for Retain
  Handling 1,
- replay is suppressed for Retain Handling 2, shared subscriptions, and
  matching No Local publisher identity,
- retained delivery QoS is `min(stored QoS, subscription QoS)`, RETAIN is one,
  and Subscription Identifier is preserved in the replay,
- Message Expiry starts at the original publish (including time spent awaiting
  QoS 2 PUBREL), is decremented on replay, and is checked again after time
  queued behind Receive Maximum,
- replay enters the same bounded per-client queue as live fanout, so a large
  retained set cannot bypass outgoing backpressure,
- live fanout now deep-owns and forwards MQTT 5 Application Message properties
  through one Mosquitto-style ref-counted Publication.

Mosquitto likewise updates retained state from the routed base message and
queues retained matches according to whether `sub__add` inserted or replaced
the subscription. The netz integration additionally keeps all replay planning
within its explicit store/queue memory limits.

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

## Live Will lifecycle

`mqtt.will_scheduler.Scheduler` is now driven by the live broker rather than
remaining an in-process planning utility:

- accepted CONNECT atomically installs the owned Will and applies prior
  ClientID reconnect/takeover semantics,
- any valid graceful DISCONNECT cancels the Will except reason `0x04`, which
  explicitly requests publication,
- network EOF/reset schedules an ungraceful Will,
- the deadline is `min(Will Delay Interval, Session Expiry Interval)`, including
  a Session Expiry override on DISCONNECT,
- reconnect with Clean Start=0 before the deadline cancels the pending Will,
  while a due/clean-start takeover cannot suppress committed publication,
- one concurrent generation-futex driver services every deadline; schedule,
  cancellation and broker shutdown wake it without one sleeping task per
  client,
- Will Delay is stripped before creating the normal PUBLISH, while Content
  Type, Correlation Data, User Properties and Message Expiry are forwarded,
- Will routing reuses the exact bounded QoS/retained/fanout queue, so retained
  Wills are replayable to later subscribers and downstream Receive Maximum
  still applies.

Mosquitto uses one ordered Will-delay list in its event loop; rumqttd instead
spawns a Tokio timeout/channel per disconnected link. Netz keeps Mosquitto's
single-driver ownership model while using the indexed heap's O(log n)
reschedule/cancel operations and generation-safe handles.

## Live persistent subscription Sessions

The first live Session Store integration closes the subscription/session
continuity loop:

- the runtime server now exposes a two-stage `acceptPending`/`finish` API, so a
  stateful broker reads CONNECT and opens Session State before emitting
  CONNACK,
- the compatibility `accept` API still performs both stages for stateless
  servers,
- CONNACK Session Present comes from the Session Store rather than a static
  listener option,
- successful SUBSCRIBE and UNSUBSCRIBE mutate both the live router and the
  deeply owned Session subscription set under the same broker lock,
- Session resume rebuilds router entries with QoS, No Local, Retain As
  Published, Retain Handling and Subscription Identifier intact,
- Clean Start discards prior subscriptions, and a DISCONNECT Session Expiry
  override of zero removes the Session immediately,
- duplicate ClientID takeover invalidates the old generation, removes its
  router ownership and wakes the old reader before restoring exactly one live
  subscription owner,
- a failed CONNACK or setup path rolls the opened Session offline and removes
  provisional router/Will ownership.

This mirrors the audited Mosquitto ordering: restore Session State, set Session
Present, send CONNACK, then make queued/inflight state writable. The Session
Store's transmission state is now wired into the broker network path as
described below.

### Offline QoS and reconnect transmission

- Every persistent Session has a stable route identity independent of its
  generation-checked connection handle. The topic router therefore keeps
  offline subscriptions indexed without stale slot identities.
- Online and offline persistent QoS 1/2 fanout, including retained replay,
  enters the Session Store; it is the sole owner of those Packet Identifiers.
  QoS 0 remains on the lightweight live queue and, like Mosquitto's default
  `queue_qos0_messages=false`, is dropped while the Session is offline.
- CONNACK is written before the first Session transmission, then drain obeys
  the peer's current Receive Maximum.
- PUBACK/PUBREC/PUBCOMP are dispatched to Session State when it owns that
  Packet Identifier; unrelated transient deliveries continue using the
  connection runtime.
- Reconnect retransmits QoS 1/2 PUBLISH with DUP and the original Packet
  Identifier. An await-PUBCOMP transaction resumes directly with PUBREL.
- Negative PUBREC, out-of-order valid ACKs, Message Expiry and a lower
  reconnect Receive Maximum retain the Store's existing bounded semantics.
- Session deletion/expiry removes the stable router identity before future
  matching, including shared-subscription selection.

This follows Mosquitto's queued/inflight split and reconnect reset while
avoiding the audited rumqttd limitation that rejects valid out-of-order ACKs.

## Shared router benchmark

Run:

```sh
zig build bench-mqtt-router -Doptimize=ReleaseFast
```

2026-08-19 same-host `ReleaseFast` ranges over three runs after combining
ordinary/shared count and emit work into two total trie traversals:

```text
4098-filter indexed match:        191-205 ns/op
4098-filter linear scan:          102-103 us/op
indexed speedup:                  499-540x

64-member RoundRobin selection:   160-166 ns/op
64-member Sticky selection:       173-178 ns/op
64-member Random selection:       166-169 ns/op
64-member Rendezvous selection:   1.23-1.24 us/op
```

Ordinary and shared subscriptions now share the same count traversal and the
same emit traversal instead of independently walking the topic levels. Every
selection path uses that topic-filter trie; the strategy work is
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
subprotocol rejection. Client `wss://` uses the generic WebSocket TLS
transport. Setting `ConnectOptions.client_identity` selects the shared
vail-backed TLS 1.3 client, which sends Ed25519/ECDSA/SM2 identities and maps
the same system/caller CA plus hostname policy or a pin/custom
`server_verifier`. Cleartext address-based `connect` rejects configured TLS
credentials instead of silently dropping them.

Netz additionally terminates WSS natively with the same strict `mqtt`
subprotocol and MQTT 3.1.1/5 state machine as WS. The TLS listener supports
concurrent serving and optional/required client certificates; verified peer
chains remain visible through `Connection.peerCertificates()`. End-to-end
tests prove the public MQTT WSS client performs authenticated CONNECT and QoS 1
PUBLISH/PUBACK while the server observes the exact verified client DER chain.
Mosquitto exposes the analogous client certificate/key capability through
`mosquitto_tls_set` regardless of whether MQTT is carried directly or over
WebSocket; netz now preserves that transport parity with typed in-memory
identities instead of requiring certificate/key file paths.

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

2026-08-19 CPU-0-pinned `ReleaseFast` result with 4,096 retained entries:

```text
exact lookup:          96-99 ns/op
wildcard full scan: 162,061-162,368 ns/op
wildcard matches:       4,096/op
```

The exact path uses the topic hash index and both lookup paths write into
caller-owned buffers without allocation. The wildcard scan deliberately
returns every entry, so this is an internal scaling baseline rather than a
whole-broker comparison. When caller capacity can hold the whole retained
store, a wildcard result cannot overflow; match and delivery planning therefore
emit in one scan instead of count-then-emit. A same-command three-run A/B
against commit `b501e96` reduced this full-result workload from
330,460-331,975 ns/op to 162,061-162,368 ns/op, a 2.04-2.05x improvement.
Smaller caller buffers retain the two-pass transactional preflight and return
`MatchBufferTooSmall` without partial output. Tests cover expiry, No Local,
Subscription Identifier and leading-`$` behavior on the fast path.

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

`zig build interop-mqtt-mosquitto-vectors -Doptimize=ReleaseFast` now runs seventeen
raw MQTT scenarios derived directly from Mosquitto `5cd25465`'s packet
generators: the seven/no-topic-tree QoS 1 no-matching-subscriber PUBACK sequence
(including retained-tree creation) and subscription-identifier replacement
with exact forwarded PUBLISH bytes; it also ports Mosquitto's hostile
non-CONNECT-initial-packet shape for all packet types 2-15, using a declared
~250 MiB Remaining Length without sending its body. Netz closes every malformed
connection before that allocation/read and accepts a subsequent valid MQTT 5
CONNECT. A QoS 2 vector additionally proves the Application Message is not
routed before PUBREL, then checks publisher PUBREC/PUBCOMP plus the independent
subscriber PUBLISH/PUBREC/PUBREL/PUBCOMP sequence byte-for-byte. A mixed-version
case uses a Mosquitto-generated MQTT 3.1.1 subscriber and MQTT 5 publisher on
the same listener, checking exact v5 PUBACK plus property-free v3 QoS 1
PUBLISH/PUBACK translation. The sixth scenario ports the wire-observable
subset of Mosquitto's
`11-persistent-subscription-no-local.py`: reconnect reports Session Present,
the restored No Local subscription suppresses self-delivery while PUBACK stays
successful, and re-subscribing replaces the option so the next self-publish is
forwarded with an independent Packet Identifier. This also corrected netz's
prior 0x10 PUBACK: No Local suppresses delivery but does not mean that no
subscription matched. The seventh scenario directly ports Mosquitto's
`02-subpub-qos0-send-retain.py`: retained messages are installed before
SUBSCRIBE, then Retain Handling 0/1/2 are each exercised twice to prove
always-send, new-subscription-only and never-send behavior with exact RETAIN
bits. The eighth scenario directly ports Mosquitto's
`02-subpub-qos0-topic-alias.py`: a publisher establishes alias 3, then reuses
it with an empty Topic Name; the subscriber receives the resolved full Topic
Name with the connection-scoped alias removed. The gate builds a finite netz
broker. The ninth scenario ports Mosquitto's MQTT 5
`04-retain-qos0-repeated.py` lifecycle and its clear boundary: retained replay
survives UNSUBSCRIBE/resubscribe, UNSUBACK bytes are exact, and a zero-length
retained PUBLISH removes the value so a later subscription receives nothing.
The tenth scenario ports a bounded form of Mosquitto's
`02-subpub-b2c-topic-alias.py`: after the subscriber advertises Topic Alias
Maximum 2, netz now automatically establishes alias 1 on the first forwarded
PUBLISH and sends the repeated topic with an empty Topic Name plus alias 1.
Alias assignment remains per Network Connection and is committed only after a
successful write.
The eleventh scenario ports Mosquitto's
`12-prop-response-topic-correlation-data.py`: Response Topic and Correlation
Data survive exact broker fanout to the responder, whose response on the
advertised topic reaches the requester byte-for-byte.
The twelfth scenario ports Mosquitto's retained Message Expiry vector with a
timing-tolerant immediate check: the forwarded interval is 2 or 1 seconds, the
entry is absent after three seconds, and a non-expiring retained control still
replays.
The thirteenth scenario ports Mosquitto's Receive Maximum 1 QoS 2 vector: two
publisher transactions complete, but the subscriber cannot observe the second
PUBLISH until PUBREC/PUBREL/PUBCOMP returns credit for the first.
The fourteenth scenario directly ports Mosquitto's Maximum Packet Size 40
QoS 1 vector. Two oversized self-deliveries are discarded while publisher
PUBACK/PING keep the socket live, then a boundary-fitting PUBLISH is forwarded.
This exposed and fixed netz closing transient live connections on
`OutgoingPacketTooLarge`; durable Session and live delivery queues now share
the same discard-and-continue policy.
The fifteenth scenario ports Mosquitto's QoS 2 Maximum Packet Size companion:
an oversized released message completes publisher PUBREC/PUBREL/PUBCOMP but
creates no downstream transaction, then a fitting message completes both the
publisher and independent subscriber QoS 2 handshakes.
The sixteenth scenario ports Mosquitto's multi-level retained clear vector on
one MQTT 5 connection: three nested topics replay through `#`, middle and leaf
tombstones return no-match PUBACK 0x10, and subsequent wildcard replay proves
ancestor/child retained trie nodes survive independent deletion.
The seventeenth scenario directly ports Mosquitto's five-client shared QoS 0
vector: an ordinary subscription receives all three messages, while two shared
groups independently select exactly one member and rotate through the upstream
receiver sequence without duplicate group delivery.
The gate builds a finite netz broker,
imports upstream `mqtt_packets.py`/`mqtt5_props.py`, and compares complete wire
packets; all seventeen scenarios pass. This is deliberately described as a selected
wire-vector subset: Mosquitto's Python harness hardcodes its own `-v -c/-p`
broker CLI and many tests depend on Mosquitto config, logs, reload, persistence
or plugins, so passing these vectors is not proxy evidence for the entire suite.

1. Add incremental autosave or a replicated commitlog for crash windows between
   quiescent snapshots.
2. Extend the production-scale publisher-window, latency, allocation and RSS
   comparison above to Mosquitto and additional concurrency/fanout shapes;
   the current result covers netz versus rumqttd at one bounded QoS 1 shape.
3. Expand the selected Mosquitto-derived raw wire gate above, or add a broker
   process adapter capable of preserving the upstream harness's config/reload/
   persistence semantics. Seventeen passing packet-vector scenarios do not cover
   the full protocol/conformance suite.
