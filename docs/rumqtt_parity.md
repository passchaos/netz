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
| MQTT versions | MQTT 3.1.1 and MQTT 5 packet/runtime; TCP, Unix-domain, WebSocket and secure listeners auto-detect both versions. MQTT 5 Topic Alias uses sparse per-connection storage and supports the complete non-zero u16 range instead of imposing a private small-table cap. | rumqtt clients support 3.1.1/5; Mosquitto broker supports both |
| Trusted proxy ingress | Opt-in, bounded HAProxy PROXY v1/v2 parsing before MQTT CONNECT, TLS or WS/WSS Upgrade, with IPv4/IPv6/Unix endpoints, LOCAL/UNKNOWN handling, CRC32C, ALPN/authority/unique-id/network-namespace, and nested SSL TLVs exposed as owned connection metadata | Mosquitto supports listener-level PROXY v1/v2, including address replacement and selected SSL TLVs; rumqttd has no equivalent listener surface in the audited tree |
| Live broker dispatch | Bounded connection slots and queues; SUBSCRIBE/UNSUBSCRIBE; QoS 0/1/2 fanout; downstream Receive Maximum; cleanup | Both references are production brokers with broader lifecycle support |
| QoS | Runtime and live broker QoS 0/1/2, including exactly-once route at PUBREL; broker Maximum QoS caps subscription grants and live/durable delivery | Both brokers support QoS 0/1/2; Mosquitto applies its listener Maximum QoS to grants, delivery, and Wills |
| Application Message size policy | Independent payload-byte cap for live QoS 0/1/2 PUBLISH and Will acceptance; MQTT 5 returns Packet Too Large while MQTT 3.1.1 completes representable acknowledgements | Mosquitto `message_size_limit`; rumqttd `max_payload_size` |
| Outgoing QoS policy | MQTT-compliant min(source, subscription) by default; explicit `upgrade_outgoing_qos` compatibility mode covers live, retained and durable Session delivery | Mosquitto exposes the same non-standard opt-in; rumqttd follows its configured routing policy |
| Shared subscriptions | Trie-indexed `{group, filter}`, RoundRobin/Random/Sticky/Rendezvous; broker defaults to RoundRobin | rumqttd has RoundRobin/Random/Sticky; Mosquitto rotates each shared leaf list |
| Topic routing | Exact, `+`, `#`, `$SYS`, No Local, shared groups | Both references provide production topic indexes |
| Listener topic namespaces and policy | Heterogeneous TCP/Unix/TLS/WS/Unix-WS/WSS `PendingSource`s can share one Broker core and deadline driver. Per-listener namespaces map PUBLISH/Will topics and ordinary/shared filters into canonical broker space, then strip the destination prefix from live, retained and durable Session delivery. Each listener may override CONNECT/CONNACK policy and add CONNECT plus live publish/subscribe/unsubscribe/delivery authorization on top of mandatory broker-wide policy; its negotiated Maximum QoS controls subscription grants plus live and durable delivery | Mosquitto `mount_point` applies a literal prefix at ingress and removes it per destination listener; Maximum QoS, authentication and selected limits may be listener-scoped with `per_listener_settings` |
| Fanout ownership | One ref-counted topic/payload/property allocation shared by every downstream delivery | Mirrors Mosquitto's `mosquitto__base_msg` reference-counted fanout |
| Publisher acknowledgement | Route before PUBACK; MQTT 5 reason `0x10` when no matching subscription | Matches Mosquitto `handle_publish.c`; rumqttd uses its router event path |
| Retained messages | Bounded Store integrated into live publish/subscribe, with expiry, Retain Handling, No Local, shared suppression, QoS and identifiers. Original Client ID provenance is deep-owned and persisted so replay can recheck the publisher's current write authorization; this Mosquitto-compatible check is enabled by default and explicitly configurable | Both production brokers integrate retained delivery; Mosquitto defaults `check_retain_source` on to prevent revoked publishers' stored messages from replaying |
| Broker sessions | Live Session Present/Clean Start/Expiry/takeover, including an active deadline task that atomically retires idle expired Sessions from routing and inbound QoS 2 state without waiting for later client traffic; pre-registration CONNECT authorization with transport source, PROXY metadata and verified peer chains, pre-mutation PUBLISH/SUBSCRIBE/UNSUBSCRIBE access control, per-recipient delivery authorization before live/retained/offline queue mutation plus reconnect-time rechecks, unique assigned identifiers with an allow/deny policy for zero-length Client IDs, persistent subscriptions, offline QoS 1/2 queues and reconnect retransmission, plus Mosquitto-compatible opt-in offline QoS 0 queueing | rumqttd graveyard/datalog and Mosquitto persisted sessions are integrated; Mosquitto exposes `allow_zero_length_clientid`, password files, certificate identity/subject usernames, distinct read/write/subscribe/unsubscribe ACLs and `queue_qos0_messages` |
| Will lifecycle | Indexed scheduler integrated into live Broker: abnormal close, DISCONNECT 0x04, Delay/Session Expiry, reconnect cancellation, retained Will, and publication-time write authorization | Both production brokers integrate Will publication; Mosquitto rechecks its write ACL when the Will becomes due |
| Keep Alive | Broker enforces the negotiated 1.5x inbound inactivity deadline with exact half-second precision, zero-disable semantics and Will/Session cleanup; optional maximum accepts MQTT 5 with Server Keep Alive replacement and refuses over-limit/zero MQTT 3.1.1 CONNECTs | Mosquitto uses a broker-wide deadline ring and disconnects clients that exceed Keep Alive x 1.5; `max_keepalive` has the same version-specific negotiation/refusal behavior |
| CONNECT and PING liveness | Optional absolute CONNECT/CONNACK packet deadline covers TCP, native TLS, WS and WSS; partial MQTT bytes, WebSocket message boundaries and control frames cannot renew it. Clients also expose an absolute PINGREQ/PINGRESP round-trip timeout on the same transports, preserving interleaved broker packets in a bounded ordered queue (plus one recoverable overflow packet already removed from the wire) | rumqttd exposes `connection_timeout_ms` around its initial packet read; rumqttc detects a PINGREQ that remains unacknowledged while continuing to dispatch other events; Mosquitto relies on its listener/event-loop timeout machinery |
| Client reconnect | An owning reconnect client deep-copies CONNECT credentials/properties/Will and accepts cleartext TCP or borrowed native-TLS/WS/WSS connectors. It retries with bounded fixed, linear, or exponential delay, optional unbiased full/equal jitter, and makes backoff interruptible through `std.Io.Event`. Its single-owner bounded poll API continuously reconnects, negotiates Server Keep Alive, sends PINGREQ while idle, rejects a missing PINGRESP within a configurable deadline, preserves partially received TCP packets across poll timeouts, and exposes ordered connect/publish/QoS/ping/DISCONNECT/AUTH events; `serveUntil` provides a cancellation-aware callback driver with automatic event cleanup. A bounded multi-producer `CommandQueue` feeds publish/subscribe/unsubscribe/disconnect/manual-ack/flush/re-auth operations to `serveQueuedUntil`, retains the loop as sole socket owner, provides owned asynchronous PUBLISH/SUBSCRIBE/UNSUBSCRIBE/DISCONNECT/manual acknowledgements with correlated typed callbacks or a bounded blocking/nonblocking `CompletionQueue`, and bounds command work between network reads. Completion-queue SUBACK/UNSUBACK reason codes and properties are deep-owned beyond the network callback. Queued graceful disconnect supports MQTT 5 reason codes/properties, emits MQTT 3.1.1's minimal packet, completes only after the write, and then stops instead of reconnecting. Inbound QoS 1/2 acknowledgement is automatic by default or application-controlled with MQTT 5 reason codes/properties; accepted manual QoS 2 transactions are persisted before PUBREC, suppress duplicate delivery, and resume through PUBREL/PUBCOMP. It applies outbound acknowledgements and drives arbitrary multi-step server-initiated MQTT 5 re-authentication through the CONNECT authentication callback while preserving its returned properties. It retains outgoing QoS 1/2 across transport loss, replays PUBLISH with DUP and its original Packet Identifier when Session Present is true, resumes outgoing QoS 2 directly at PUBREL after PUBREC, clears stale QoS state when the broker reports no Session, and replays only broker-accepted subscriptions into that fresh Session. | rumqttc continuously reconnects while polled and moves inflight requests back to its pending queue; libmosquitto exposes fixed/progressive reconnect delay control |
| MQTT 5 Enhanced Authentication | Initial multi-step AUTH before CONNACK, owned method binding, re-authentication traffic gate and broker policy callback | Mosquitto plugin start/continue callbacks and active re-authentication; rumqtt codec/runtime coverage is narrower |
| MQTT 5 information preferences | Configurable Response Information is emitted only when CONNECT explicitly requests it; Request Problem Information defaults to enabled and an explicit zero removes Reason String/User Property from server ACK/AUTH packets while retaining functional authentication properties and the reason code | Both references parse/model the CONNECT fields, but the audited Mosquitto documentation labels them supported but unused and rumqttd does not apply them in its router |
| MQTT 5 Server Reference | CONNACK/DISCONNECT property access, redirect-reason validation, URI and host:port parsing, bounded loop-detecting opt-in redirect chains, authorization callback, and automatic TCP/TLS/WS/WSS CONNACK redirect helpers; TLS/WSS derive certificate identity from every new authority | The audited rumqtt codecs expose the property/reasons but no automatic client redirection; Mosquitto documents Server Reference as supported but unused |
| Broker persistence | Atomic versioned snapshots plus an opt-in fsynced append journal for retained messages, scheduled Wills, durable Sessions, opt-in queued QoS 0, outgoing QoS 1/2 and inbound QoS 2 transactions | rumqttd datalog/segments; Mosquitto persisted sessions, subscriptions, bidirectional client-message state and retained/Will base messages |
| Observability | `Broker.stats()` takes one allocation-free, state-locked snapshot of live connections, connected/offline Sessions, ordinary/shared subscriptions, retained state, live queues, durable queues/inflight, inbound QoS 2 and scheduled Wills, including owned byte gauges. `publishSystemStats()` and `system_stats_interval` publish the snapshot as retained QoS 0 `$SYS` messages through normal routing and ACL checks | Mosquitto periodically publishes its broader counter/gauge set through `$SYS`; rumqttd exposes metrics through its server architecture |

Netz now exceeds the audited rumqtt shared-selection policy surface by adding
Rendezvous hashing. This provides deterministic topic affinity and the
important low-remapping invariant: when one member joins, only topics that
select that new member move. It does not replace rumqttd's broader durable
broker architecture or Mosquitto's full persistence plugin and protocol
surface.

PROXY v2 support is also stricter and broader than the audited Mosquitto
decoder: it rejects non-stream transport metadata on the TCP listener, can
verify the optional CRC32C TLV, retains standard ALPN, authority, unique-id,
network-namespace and all defined SSL sub-TLVs, and can require either proxied
TLS or a proxy-verified client certificate. These assertions are deliberately
available only on explicitly configured trusted-proxy listeners. The broker's
transport-aware CONNECT authorization callback receives them together with the
effective source address and any directly verified mTLS certificate chain.
The same parser precedes MQTT TCP, TLS, WS, and WSS application handshakes; an
optional absolute header timeout prevents incomplete proxy prefaces from
holding listener workers indefinitely.

The selected Mosquitto-derived process gate enables a five-second CONNECT
deadline on every one of its finite broker processes, so all 141 raw scenarios
also exercise the bounded admission path rather than merely proving the option
in an isolated unit test.
Three retained-source scenarios persist and restart the standalone broker after
storing a retained PUBLISH, mirroring Mosquitto's CVE-2018-12546 regression
shape. The default `check_retain_source` path rechecks the deep-owned original
Client ID against current write policy and suppresses replay after revocation;
`--no-check-retain-source` demonstrates the explicit compatibility opt-out.

## Server Reference redirects

MQTT 5 Server Reference handling now goes beyond the audited reference clients,
which expose reason codes and property bytes but do not follow them. Netz binds
the property to Use Another Server / Server Moved, accepts explicit MQTT,
MQTTS, WS, and WSS URIs plus the common host:port form, canonicalizes host case
and default ports for loop detection, and rejects credentials, query/fragment
data, invalid hosts, zero ports, and TCP references containing paths.

Following redirects is deliberately opt-in and bounded. A policy controls the
maximum hop count, transport changes, and a per-hop authorization callback.
The TCP, TLS, and WebSocket client families expose automatic CONNACK helpers;
TLS/WSS reconnect through their normal URI paths so SNI and certificate host
validation are derived again from the redirected authority. Runtime tests use
two real TCP and two real WebSocket servers, while the Mosquitto-derived process
gate verifies exact redirect CONNACK bytes. DISCONNECT references use the same
parser and chain through takeDisconnectTarget, leaving application state replay
and the reconnect decision explicit.

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
- offline queued QoS 1/2 messages and opt-in queued QoS 0 messages,
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

## Incremental commit log

`Broker.createCommitLog`, `restoreCommitLog`, `appendCommit`, and
`compactCommitLog`
add an opt-in append journal alongside periodic snapshots. Each record contains
one coherent live-state image with a monotonically increasing sequence number,
CRC32-protected header and payload, and a matching commit footer. The
implementation fsyncs the complete record before reporting success; recovery
accepts and truncates only an incomplete final record, while bad magic,
sequence, header CRC, payload CRC, or footer is rejected instead of silently
hiding committed corruption. Compaction writes a new one-record generation
through `std.Io.File.Atomic` and replaces the old history only after the
temporary file has been synced; append automatically takes this path before a
configured journal-size bound would be exceeded.

When `--commit-log=PATH` is enabled in the production example, the broker records
protocol-visible durable boundaries before CONNACK, SUBACK, UNSUBACK,
PUBACK/PUBREC/PUBCOMP, durable outgoing delivery, disconnect/Will scheduling,
Will publication, and Session expiry can be observed by a peer. This first
version intentionally journals complete state images so every private store is
covered uniformly; compact typed delta records and group commit are performance
work, not missing recovery semantics. The `interop-mqtt-commit-log` build step
creates a durable subscription, receives PUBACK for an offline queued message,
immediately kills the broker without any periodic or shutdown snapshot, and
requires Session Present plus the exact delivery after restart. Unit coverage
additionally verifies multi-generation replay, atomic compaction, torn-tail
truncation, committed corruption rejection, and transactional broker-state
preservation when the newest image cannot decode.

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
  --persistence=netz-mqtt.db --autosave-interval-seconds=30
```

The finite example restores that snapshot before accepting clients and saves
again after all configured connections exit. With the autosave interval above,
it also writes live checkpoints while clients remain connected;
`--no-restore` starts from an empty in-memory state but still writes periodic
and final snapshots. `zig build interop-mqtt-live-autosave
-Doptimize=ReleaseFast` creates a durable subscription, waits for an autosave,
kills the broker without its final save, restores the database in a fresh
process, and verifies Session Present plus live routing through the restored
subscription. The same process gate now takes that Session offline, queues an
opt-in QoS 0 message, waits for a later atomic checkpoint, kills the broker,
and requires the exact packet once immediately after reconnect before proving
the restored connection remains usable with PING.

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
buffer after first use. The codec prevalidates every property, computes the
complete Remaining Length, reserves once, and writes fixed header, topic,
Packet Identifier, every MQTT 5 property type and payload directly into that
retained output. The shared property writer uses the same exact-length direct
path for CONNECT, ACK, SUBSCRIBE and the other control packets. Neither layer
allocates temporary variable-header or property buffers; failing-allocator
codec and socket tests prove warmed writes are allocation-free while parsing
verifies exact wire parity and invalid input leaves prior output unchanged.
CONNECT itself now applies the same direct path across MQTT 3.1.1/5 Client ID,
Will properties/topic/payload and username/password instead of assembling and
copying a whole temporary variable payload. CONNACK and QoS PUBACK/PUBREC/
PUBREL/PUBCOMP use the same retained-capacity path while preserving MQTT 5's
shortest legal omission of reason code and Property Length. SUBSCRIBE,
SUBACK, UNSUBSCRIBE and UNSUBACK preflight complete filter/reason lists and
also write directly after one final reservation. Warmed mixed-property and
multi-filter tests run these writers under a fail-first allocator. DISCONNECT
and enhanced-authentication AUTH complete the same treatment, including their
zero-length and reason-plus-properties MQTT 5 forms.
PINGREQ and PINGRESP now expose an exact two-byte caller-buffer encoder, and
the shared TCP/TLS/WebSocket runtime sends those bytes directly instead of
constructing a fresh ArrayList for every keep-alive exchange. A real TCP test
runs PINGRESP through a fail-first connection allocator and validates the peer
bytes, while codec tests prove PINGREQ/PINGRESP wire parity. This is a stricter
allocation boundary than the audited rumqtt codecs' `BytesMut` writer path,
without changing their equivalent two-byte MQTT wire representation. The
common property-free PUBACK/PUBREC/PUBREL/PUBCOMP path likewise encodes the
complete four- or five-byte packet into caller storage and sends it directly.
It preserves MQTT 5's shortest success form, validates negative reason codes,
and leaves arbitrary diagnostic properties on the general property-capable
codec path. If Request Problem Information filtering removes every diagnostic
property, the result also returns to the fixed path. A real TCP
fail-first-allocator test covers all four packet types and both wire lengths;
unlike the audited rumqttd writers, this hot path does not depend on spare
`BytesMut` capacity. The
Mosquitto-derived 132-scenario packet gate and MQTT 3.1.1/5 WS/WSS gate remain
green. CPU-0-pinned 1-KiB QoS 1 regression runs measured 10.437 us per
PUBLISH/PUBACK over WebSocket (95,805 operations/s) and 11.541 us over native
TLS (86,640 operations/s). These check the shared packet receive/send paths
rather than isolating one control codec.
PUBLISH encoding now exposes a validated prefix-only form. Plain TCP, native
TLS, WS, and WSS submit that retained prefix together with the borrowed
application payload, so payload size no longer drives the MQTT connection's
packet scratch capacity. MQTT-over-WebSocket still preserves one MQTT packet per
binary message: its new two-part WebSocket writer emits one frame and carries a
continuous client mask across both slices through bounded stack scratch rather
than concatenating the message. V3.1.1 and MQTT 5 tests compare the prefix plus
borrowed payload byte-for-byte with the original contiguous encoder,
including QoS 1, DUP, retain, a multibyte Remaining Length, and properties. A
real TCP test sends two 1-KiB packets, disables all allocation after warmup, and
verifies the prefix scratch remains smaller than the payload while the peer
parses the complete bytes. WebSocket tests independently verify one-frame
masked client and unmasked server messages assembled from two parts. The full 1,646-test suite, 132-scenario
Mosquitto-derived wire gate, and MQTT 3.1.1/5 WS/WSS gate remain green. Five
CPU-0 native-TLS samples measured 11.292-11.761 us per QoS 1 PUBLISH/PUBACK
(11.445 us mean). Five WebSocket samples measured 10.448-10.859 us with a
10.450-us median and 10.534-us mean.
Property-free DISCONNECT now follows the same design: normal shutdown uses its
canonical two bytes and an MQTT 5 error reason uses three bytes, both from
caller-owned storage. The TCP runtime test sends a non-zero Keep Alive timeout
reason through a fail-first allocator and validates the exact peer bytes. The
audited rumqtt implementations again encode into a growable `BytesMut`; the
netz path has no retained-capacity prerequisite.
Property-free MQTT 5 AUTH packets also use caller-owned storage, including the
distinct four-byte Continue/Re-authenticate form whose zero Property Length is
mandatory. Request Problem Information suppression takes this path when only
diagnostic properties remain. Exact wire tests and a real TCP fail-first
allocator test cover the two- and four-byte forms; rumqttc's audited AUTH
writer always targets a growable `BytesMut` and emits the longer form even for
Success.
Bare CONNACK has a fixed encoder as well: MQTT 3.1.1 uses four bytes and MQTT
5 adds its mandatory zero Property Length byte. The runtime selects it when no
explicit or implicit capability properties were generated, most importantly
for connection refusals that should remain reportable under allocator
pressure. A fail-first TCP test sends exact MQTT 5 and 3.1.1 refusal packets.
Accepted MQTT 5 sessions retain the general encoder whenever negotiated
capabilities need to be advertised.
All variable-size runtime control writers now share the connection's retained
packet buffer rather than allocating and freeing a temporary list per send. A
second retained property-list scratch covers generated CONNACK capabilities
and Request Problem Information filtering. A real TCP regression warms and
then replays property-bearing CONNACK, PUBACK, SUBACK, UNSUBACK, DISCONNECT,
and AUTH under a fail-first allocator, comparing every replay packet with its
warmup bytes. PUBLISH continues to use the same packet scratch, while the fixed
control encoders above bypass it entirely.
Property-free SUBACK/UNSUBACK additionally expose exact-length caller-buffer
encoders, including multi-byte Remaining Length. The runtime writes them into
the retained packet scratch and avoids property encoding entirely. Validation
happens before output mutation; tests cover short storage, MQTT 3.1.1's absent
UNSUBACK reason list, MQTT 5 reason lists, and the 128-byte Remaining Length
boundary. In contrast, the audited rumqttd SUBACK/UNSUBACK writers first
collect mapped reason bytes into another `Vec<u8>` before copying them into
`BytesMut`.
TCP and TLS packet readers now collect only the at-most-five-byte MQTT fixed
header on the stack, validate the complete packet length, then allocate the
public owned packet exactly once at its final size. This removes the former
incremental ArrayList growth and ownership-transfer work without weakening
absolute CONNECT/PING deadlines or broker Keep Alive progress renewal. A real
TCP test permits exactly one allocation and forbids resizing for a packet with
a multi-byte Remaining Length; a second sends only an oversized header and
proves rejection happens before any allocation. Rumqttd instead starts each
connection with a retained 10-KiB `BytesMut` receive buffer, favoring pooled
read-ahead at the cost of that per-connection reservation.
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

## Broker capability enforcement

The broker now treats its advertised MQTT 5 capabilities as inbound policy,
not only CONNACK metadata. Maximum QoS caps SUBACK grants and the subscription
state stored in both the router and durable Session Store. Live fanout, queued
Session routes, and Session retransmission encoding apply the same cap as a
defense against state restored or retained across a stricter configuration.
The listener-wide cap also applies to MQTT 3.1.1 connections even though that
protocol cannot advertise it in CONNACK. CONNECT rejects a Will above Maximum
QoS, and rejects a retained Will when Retain Available is false; MQTT 5 peers
receive reason `0x9b` or `0x9a`, respectively.
Post-CONNECT PUBLISH violations receive the same precise MQTT 5 DISCONNECT
reasons before the broker closes the Network Connection. Receive Maximum
overflow is likewise mapped to DISCONNECT `0x93`; MQTT 3.1.1 peers receive the
only representation available to that protocol, a connection close. A Topic
Alias outside the negotiated inbound range receives DISCONNECT `0x94`.
Clients that ignore disabled Shared Subscription, Subscription Identifier, or
Wildcard Subscription capabilities receive `0x9e`, `0xa1`, or `0xa2` rather
than a generic local error or silent close. The high-level client still rejects
such SUBSCRIBE attempts before writing them.
Malformed MQTT 5 traffic is mapped at the same broker boundary: protocol
violations receive DISCONNECT `0x82`, malformed packet/UTF-8 failures receive
`0x81`, and configured packet-size violations receive `0x95` when the peer's
own outbound limit permits the response.

This matches the audited Mosquitto control points: `src/handle_subscribe.c`
caps requested subscription QoS, `src/database.c` caps outbound delivery QoS,
and `src/handle_connect.c` rejects unsupported Will QoS and retain settings.
Mosquitto's `src/read_handle.c` maps the corresponding post-CONNECT failures
to the same MQTT 5 DISCONNECT reasons.
Focused tests cover the advertised property and SUBACK, live delivery, durable
Session reconnect delivery, Session packet encoding, and both Will refusal
reason codes, plus raw non-compliant PUBLISH packets for both capabilities and
Receive Maximum overflow, and an out-of-range Topic Alias.
The three subscription capability flags also have raw-wire negative tests.
An invalid-control-flags wire case verifies the general Protocol Error path.

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

- a non-zero interval closes plain TCP, native vail-backed TLS, WS, and WSS
  Network Connections after exactly 1.5x the negotiated value, preserving the
  half second for odd values rather than truncating to whole seconds;
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
broker reader. The TLS record layer now applies the same absolute deadline
across each encrypted header/body read while preserving already-decrypted
buffered plaintext. The standard Zig TLS client now applies the deadline only
when its internal record parser requests more ciphertext, preserving buffered
plaintext while recovering the underlying Timeout from `std.Io.Reader`'s
generic `ReadFailed`. WebSocket carries that absolute deadline across frame
and message boundaries; Ping/Pong traffic cannot renew MQTT activity, while
MQTT payload progress above the same 1,000-byte threshold can. Tests cover
exact timeout arithmetic including the maximum u16 value, byte-progress
renewal beyond one whole timeout, native TLS/WS/WSS timeout, standard-TLS MQTT
and WSS client timeout, cross-message large-packet progress, post-timeout Will
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
  QoS 0 remains on the lightweight live queue while the subscriber is online.
  Like Mosquitto, the broker drops it for an offline Session by default; the
  `queue_qos0_messages` option (example switch `--queue-qos0-messages`) opts
  durable Sessions into bounded offline storage. Queued QoS 0 uses no Packet
  Identifier or QoS 1/2 inflight credit, and is retired after its socket write.
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
- If an offline queued PUBLISH is selected into inflight state but encoding or
  socket submission fails before the peer can receive it, the broker rolls that
  selection back as unsent. Reconnect therefore sets DUP only for a packet that
  may actually have reached a prior Network Connection, not for a locally
  failed first attempt; a focused Store test and 20 repeated broker resume runs
  cover both sides of the boundary.
- A selected queued QoS 0 message remains Session-owned until the detached
  socket write commits. Write failure or disconnect returns it to the queue,
  and a concurrent live snapshot includes the selected message ahead of the
  remaining queue. This preserves queue order, byte/count bounds and crash
  durability without inventing a wire Packet Identifier or ACK state.

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
WS and WSS listeners may additionally require an exact Origin allowlist; a
configured policy rejects missing, duplicate, or non-matching Origin headers
before the 101 response, while the default remains disabled for native clients.
Like rumqtt's audited `ws_stream_tungstenite` adapter, each write is one binary
WebSocket message while reads expose a continuous byte stream: an MQTT packet
may span messages and one message may contain bytes from multiple packets.
Client masking is done in place on the temporary encoded packet to avoid an
extra payload copy. Broker Keep Alive enforcement also remains packet-scoped:
one absolute deadline spans WebSocket fragments, messages, and control frames,
so Ping/Pong traffic cannot keep an otherwise idle MQTT session alive.

`zig build interop-mqtt-websocket-mosquitto -Doptimize=ReleaseFast` now imports
the audited Mosquitto `mqtt_packets.py` generators and `WebsocketWrapper` as an
external peer. It runs MQTT 3.1.1 and MQTT 5 over both WS and certificate-
verified TLS 1.3 WSS. Every case sends a 65,556-byte QoS 1 PUBLISH split across
two WebSocket messages, coalesces a following MQTT PINGREQ into the second
message, checks the exact PUBACK and PINGRESP, then verifies a netz-originated
QoS 1 PUBLISH byte-for-byte before acknowledging it and disconnecting. The
finite netz process validates the client ID, topic, complete payload pattern,
and disconnect, so success cannot be inferred from the HTTP upgrade alone.
`zig build interop-mqtt-websocket-origin -Doptimize=ReleaseFast` separately
ports Mosquitto's `13-websocket-bad-origin.py` request shape: a disallowed
origin is closed before upgrade, then an allowed origin completes WebSocket and
MQTT 5 negotiation on the same finite server process.

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
supports an ALPN protocol list with mandatory overlap when configured,
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

Direct MQTT TLS clients can likewise send an ordered ALPN offer without
requiring a client certificate. This selects the vail-backed client path,
retains normal system/caller-CA and hostname verification, and makes the
server-selected value available through `Connection.negotiatedAlpn()` on both
ends. The same client path now retains the complete verified server certificate
chain and exposes it through `Connection.peerCertificates()` for native MQTT
TLS and WSS; server-side mTLS continues to expose the verified client chain.
Both endpoint roles also expose RFC 8446 exporter keying material for
application authentication and channel binding, together with typed
`negotiatedCipherSuite()` and `negotiatedTranscriptHash()` metadata for native
TLS and vail-backed WSS. Unsupported cleartext and standard-library TLS paths
return null instead of synthesizing negotiation state.
MQTT-over-WebSocket can select the vail path independently of client identity,
so ordinary WSS clients receive the same metadata and exporter/KeyUpdate
surface instead of requiring mTLS as an accidental feature flag.
The same transports expose explicit RFC 8446 application traffic-key rotation
and sent/received update counters. Native MQTT TLS tests require a reciprocal
update before PING/DISCONNECT, proving MQTT framing survives both new epochs.
This covers rumqttc's configurable TLS ALPN surface and Mosquitto's
client/bridge ALPN option while also giving server applications the negotiated
identity directly. Empty ALPN lists preserve the existing standard-library TLS
client path.

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

The reconnect layer's network owner remains synchronous internally. The public
managed worker accepts owned PUBLISH, SUBSCRIBE, UNSUBSCRIBE, manual ACK,
graceful DISCONNECT, pending-PUBLISH flush and re-authentication commands with
typed, correlated completion callbacks. A bounded `CompletionQueue` adapter
additionally provides blocking and nonblocking consumption with deep-owned
SUBACK/UNSUBACK reason codes and properties. Further parity work is ergonomic
integration with application-specific async executors rather than missing
operations or completion storage. Re-authentication properties are deep-owned
until the initiating AUTH write completes. The single-owner bounded poll path, callback
driver, managed background-thread wrapper, optional application-controlled QoS
1/2 acknowledgements, and bounded command queue already support explicit
client-initiated re-authentication and drive both directions of
multi-step MQTT 5 re-authentication, idle
keep-alive and automatic reconnect without competing socket readers. Current
tests cover real two-connection QoS 1 PUBLISH/DUP and outgoing QoS 2 PUBREL
continuation, incoming QoS 1 delivery across a keep-alive cycle, inbound QoS 2
continuation after transport loss, manual QoS 1/2 acknowledgements with MQTT 5
diagnostics, manual QoS 2 duplicate suppression and reconnect continuation,
silent-broker PING timeout followed by
Session-Present replay, fresh-session cleanup, accepted-only subscription
replay, Session Present suppression of redundant SUBSCRIBE, bounded delay math,
prompt cancellation during a thirty-second backoff, and multi-step live AUTH
including callback-produced User Properties and missing-handler failure.
Native TLS, cleartext WebSocket and authenticated WSS connector tests each
establish two successive MQTT sessions through the same reconnect client.

The public `listener_namespace.Namespace` module defines Mosquitto-compatible
mount points. It validates literal UTF-8 prefixes, enforces MQTT's u16 wire
limit after concatenation, preserves the `$share/{group}/` wrapper while
prefixing only its nested Topic Filter, maps PUBLISH/Will topics into canonical
broker space, and refuses to expose a canonical topic outside a destination
namespace. `Broker.init` plus `serveListeners` runs finite
TCP/Unix/TLS/WS/Unix-WS/WSS
accept counts concurrently over one router, retained store, Session store, Will
scheduler and deadline driver. `serveListenersUntil` adds a long-running,
gracefully cancellable supervisor with configurable per-listener concurrency
and error policy; the legacy `Broker.listen`/`serve` remains a single-TCP
convenience. Each accepted connection deep-owns its namespace, so
live and durable Session delivery always strips according to the current
destination listener. Durable Sessions retain canonical subscriptions across
listener changes: queued topics visible through the reconnecting listener are
projected into its namespace, while queued topics outside that listener's view
are dropped rather than leaking names or blocking later delivery. Cross-listener
tests cover TCP/WSS routing, mounted/global subscription visibility, retained
replay, namespaced Will publication, durable reconnects and shared groups.
Listener-local CONNECT and packet authorization compose as additional gates
after broker-wide policy, so exposing one less-restricted endpoint cannot
accidentally bypass a global credential or ACL requirement. Read authorization
is re-evaluated against the destination's current listener before retained,
live, or resumed durable delivery. Delayed Will authorization stays broker-wide
because a Will may outlive the borrowed listener configuration that accepted it.
Listeners can also opt into Mosquitto-compatible
`use_username_as_client_id`: authorization sees the original wire CONNECT,
then Session, Will, takeover and live ACL state consistently use the required
username as the effective Client ID. Missing usernames receive Not Authorized;
tests prove two different wire Client IDs with one username resume/take over the
same durable Session. The 141-scenario Mosquitto-derived wire gate runs the
same policy through the standalone broker option, including exact Session
Present, takeover DISCONNECT and missing-username refusal bytes.
`zig build interop-mqtt-listener-mount-mosquitto -Doptimize=ReleaseFast`
also ports Mosquitto's `10-listener-mount-point.py` process shape for both
MQTT 3.1.1 and MQTT 5, verifying canonical ingress and destination-specific
egress against Mosquitto's independent wire-packet helpers.
Raw MQTT and MQTT-over-WebSocket additionally expose Unix-domain server/client
paths, including `PendingSource` integration with both Broker serving modes.
They reuse the normal MQTT and WebSocket state machines while rejecting PROXY
configuration and TCP-only NODELAY behavior on the local transport. Real socket
tests complete MQTT 5 QoS 1 in both raw and WebSocket forms, including bounded
concurrent serving of independent clients with per-connection result reporting.
Standalone TCP, Unix, TLS, WS, and WSS servers also share a long-running
`serveUntil` worker supervisor with cancellation, connection reuse, error
observation, and independent accept/connection failure policies.

`zig build interop-mqtt-mosquitto-vectors -Doptimize=ReleaseFast` now runs 141
raw MQTT scenarios derived directly from Mosquitto `5cd25465`'s packet
generators: two PROXY protocol cases consume Mosquitto's v1 TCP4 and v2 IPv4
prefaces before completing MQTT 5 CONNECT and PING on the same stream; the
seven/no-topic-tree QoS 1 no-matching-subscriber PUBACK sequence
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
broker. Eight additional credential cases port Mosquitto's anonymous,
username-without-password, and wrong-password refusals for MQTT 3.1.1 and 5,
then prove valid username/password connections remain usable in both versions. The broker
evaluates this policy before Session/Will/router registration and the finite
example exposes `--username` plus `--password` for static credentials. The
same gate ports Mosquitto's denied-subscription and denied-publish plugin
behavior for MQTT 3.1.1 and 5: denied filters return SUBACK 0x80/0x87, denied
QoS 1/2 publications return the version-appropriate PUBACK/PUBREC without
retained or routing mutation, and PING plus a later allowed publish prove the
connection remains usable. The QoS 2 case immediately reuses the denied
Packet Identifier for that allowed QoS 1 publish, directly covering
Mosquitto's stale inbound-state regression. The example exposes exact
deny-topic/filter options solely as a deterministic policy fixture; library
applications provide their own callbacks. Separate outgoing read and
UNSUBSCRIBE callbacks now match Mosquitto's four-way ACL model. The gate
checks MQTT 5 mixed denied/allowed UNSUBACK reason codes, MQTT 3.1.1's
success-only UNSUBACK while the denied subscription remains installed,
recipient-specific live delivery suppression, and retained replay suppression
without deleting the retained Application Message. Durable queued/inflight
PUBLISH packets are rechecked before reconnect transmission so a policy change
cannot leak an older message or leave it blocking the Session queue. Will
publication has a separate source-aware write check at the due instant; a
denied retained Will is consumed without routing or retained-store mutation.
The ninth
scenario ports Mosquitto's MQTT 5
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
The eighteenth scenario isolates the core retransmission semantics from
Mosquitto's client-to-broker QoS 2 reconnect vector: original and DUP PUBLISH
with one Packet Identifier receive PUBREC without early routing, and one PUBREL
creates exactly one independent downstream QoS 2 transaction.
The nineteenth scenario verifies Mosquitto's PUBREL idempotence boundary:
repeating a completed PUBREL and sending an unknown Packet Identifier both
return PUBCOMP, while the subscriber observes no duplicate Application Message.
Two companion scenarios directly port Mosquitto's
`03-publish-qos2-reuse-mid.py` for MQTT 3.1.1 and MQTT 5. A second non-DUP
PUBLISH reuses an identifier that is still waiting for PUBREL but carries a
different topic and payload. Netz acknowledges both PUBLISH packets with
PUBREC, atomically replaces the pending transaction, and releases only the
replacement Application Message after PUBREL; the subscriber's bounded silence
check rejects stale delivery of the original message. DUP retransmissions
remain stricter and must match the stored transaction byte-for-byte.
The twentieth scenario sends the server-only Subscription Identifier property
on a client PUBLISH. Netz rejects the connection before routing and then
accepts a fresh MQTT 5 client/PING, proving the finite broker remains healthy.
The twenty-first scenario unsubscribes an existing and missing filter in one
packet, checks ordered MQTT 5 reason codes 0x00/0x11, then proves the removed
route stays silent while PING remains usable.
The twenty-second scenario gives two live subscribers opposite Retain As
Published settings, then verifies the same retained QoS 1 source PUBLISH is
forwarded with RETAIN cleared for one and preserved for the other.
The twenty-third scenario replaces one retained topic including its User
Property, then proves a later subscriber receives only the new payload/property
once; PING immediately after replay catches stale duplicate retention.
The twenty-fourth scenario ports Mosquitto's retained property bundle: Payload
Format, Content Type, Response Topic, Correlation Data and User Property survive
storage and replay byte-for-byte.
The twenty-fifth scenario clears a retained value with a property-bearing
zero-length tombstone, proves neither old nor tombstone properties replay, and
then verifies a replacement live PUBLISH contains only its new User Property.
The twenty-sixth scenario overlaps an exact and wildcard subscription for one
client. Netz now merges the router matches into one PUBLISH and appends both
Subscription Identifier properties (3 then 9), instead of emitting duplicate
Application Messages with one identifier each. The gate also gives the two
subscriptions QoS 0 and QoS 1 and verifies the merged delivery takes the maximum
granted QoS. One match also enables Retain As Published, proving the merged
retained source preserves RETAIN when any matching subscription requests it.
The same reduction now happens before durable Session enqueueing. An in-process
reconnect regression proves that an offline persistent client receives one
queued PUBLISH with both identifiers, the maximum effective QoS, and Retain As
Published combined from all matching subscriptions.
Three additional negative cases directly port Mosquitto's
`03-publish-bad-flags.py` QoS/retain capability violations and
`12-prop-maximum-packet-size-broker.py` boundary behavior. They compare the
advertised CONNACK properties and exact DISCONNECT `0x9b`, `0x9a`, and `0x95`
packets after raw clients deliberately ignore those limits.
Eight additional MQTT 3.1.1/5 cases port Mosquitto's QoS 0, QoS 1, and Will
Application Message size-limit vectors and add the corresponding QoS 2 case.
The example broker exposes an
independent `--max-payload-size`; a payload exactly at the boundary is routed,
oversized QoS 0 is discarded while both connections stay usable, and oversized
QoS 1/2 receives MQTT 5 PUBACK/PUBREC `0x95` (or completes the property-free
MQTT 3.1.1 acknowledgement handshake) without downstream delivery. Oversized Wills are refused before Session/Will
registration with MQTT 5 CONNACK `0x95` or legacy v3 CONNACK `0x05`, while a
boundary-sized Will is installed and published after an ungraceful close.
Five more raw cases verify exact `0x94`, `0x93`, `0x9e`, `0xa1`, and `0xa2`
DISCONNECT packets for Topic Alias, Receive Maximum, shared-subscription,
Subscription Identifier, and wildcard-subscription violations. The latter
three cover capability controls that rumqtt's codecs model but the audited
Mosquitto broker does not expose as listener switches.
Another case combines the wire-observable behavior from Mosquitto's
`07-will-properties.py` and `07-will-disconnect-with-will.py`: DISCONNECT
reason `0x04` publishes the Will, a leading zero Will Delay property is
removed, and ordered User Property, Response Topic, Correlation Data, Payload
Format Indicator and Content Type values reach the subscriber byte-for-byte.
The final case ports Mosquitto's MQTT 5 Assigned Client Identifier vector. Two
simultaneous anonymous clients receive distinct complete
`netz-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` identifiers, the remaining CONNACK
capabilities match byte-for-byte, and a PING on the first connection proves
that assigning the second identifier did not accidentally take over the first
anonymous Session. This strengthens the upstream vector's prefix-only check
without presenting the existing in-process broker tests as external evidence.
The Server Keep Alive case ports Mosquitto's `12-prop-server-keepalive.py`
against the new example-broker `--server-keep-alive` policy switch. A client
requests 61 seconds, the exact CONNACK advertises the configured 60-second
replacement after netz's fixed capabilities, and a subsequent PING proves the
negotiated connection remains usable.
Six maximum-Keep-Alive cases port Mosquitto's
`01-connect-max-keepalive.py` boundary for MQTT 3.1.1 and extend it to MQTT 5.
Requests above 100 seconds and zero (which would disable Keep Alive) receive
legacy CONNACK return code 2 in MQTT 3.1.1, while MQTT 5 accepts them with an
exact Server Keep Alive value of 100. Requests exactly at the limit are
accepted without an unnecessary override, and MQTT 5 PING verifies each
accepted connection remains usable. The policy lives in shared
`runtime.AcceptOptions`, so TCP, TLS, WS and WSS accept paths cannot diverge;
the broker resolves it before Session registration to keep refusals
side-effect-free.
Three zero-length Client ID policy cases extend the existing assigned-ID
coverage with Mosquitto's `01-connect-zero-length-id.py` deny branch. The
production broker switch rejects clean-start anonymous MQTT 3.1.1 with return
code 2 and MQTT 5 with reason 0x80 before creating Session or Will state; a
named MQTT 5 client then connects and answers PING on the same listener.
Four malformed-Will cases directly port Mosquitto's `07-will-no-flag.py` and
`07-will-null-topic.py` for MQTT 3.1.1 and MQTT 5. They remove the complete
Will Payload field while keeping CONNECT's declared length self-consistent, or
supply an empty Will Topic carrying binary payload bytes. Netz rejects every
connection before installing Session/Will state, then accepts a valid MQTT 5
CONNECT and PING on the same finite broker process.
Two companion cases port Mosquitto's `07-will-null.py` for MQTT 3.1.1 and
MQTT 5. They distinguish the malformed missing field above from a valid
zero-length Will Payload, then require an exact empty PUBLISH after the source
disconnects ungracefully. A following PINGRESP proves that publication occurs
once and leaves the subscriber connection usable.
The duplicate Client ID case directly ports Mosquitto's
`01-connect-take-over.py`: the replacement receives a successful CONNACK, the
displaced MQTT 5 peer now receives DISCONNECT `0x8e` (Session Taken Over)
instead of an unexplained EOF, and the replacement remains responsive to
PING. The in-process takeover test also verifies the reason code while
retaining its existing single-subscription-owner assertion.
The eight-case Will takeover matrix directly ports Mosquitto's
`07-will-takeover.py` across MQTT 3.1.1 and MQTT 5. It combines transient and
durable old Sessions with clean and continuing replacement connections, checks
Session Present and the MQTT 5 takeover DISCONNECT, and proves byte-for-byte
that the old Will is suppressed only when both connections preserve the same
Session. This exposed and fixed zero-delay Wills being published during a live
durable-Session takeover; Will Delay controls publication after disconnect,
not cancellation by a replacement that has already resumed the Session.
The Session Expiry case ports the timing-observable core of Mosquitto's
`05-session-expiry-v5.py`: a three-second DISCONNECT override keeps a Session
present beyond the one-second CONNECT value, the Session is absent after the
new deadline, and a zero DISCONNECT override removes the replacement
immediately. Exact CONNACK bytes distinguish every Session Present transition.
The broker also exposes Mosquitto's administrative
`persistent_client_expiration` behavior as
`persistent_session_expiry_seconds`: it caps a longer MQTT 5 Session Expiry and
also gives MQTT 3.1.1 CleanSession=0 an otherwise unavailable finite lifetime,
without lengthening a client's shorter or zero MQTT 5 expiry. The cap is
applied again to MQTT 5 DISCONNECT overrides and to the Session lifetime used
to bound Will Delay, so neither path can bypass the administrative maximum.
An additional idle-expiry case constrains the broker to one pending inbound
QoS 2 transaction, leaves that transaction owned by a disconnected one-second
Session, and keeps an unrelated connection online without CONNECT/PUBLISH
traffic during expiry. That existing connection can then acquire and complete
the sole QoS 2 slot, proving the shared deadline task removed the Session, its
router entries, and pending transaction proactively rather than relying on a
later registration or routing operation to prune it.
The Clean Start/offline QoS 1 case ports Mosquitto's
`05-clean-session-qos1.py`: a persistent subscriber disconnects after
subscribing, receives the exact queued QoS 1 PUBLISH with Session Present on
resume, acknowledges it, and reconnects with Clean Start to delete the old
Session. A final persistent reconnect reports no Session Present and answers
PING before any stale delivery, proving both queue drain and cleanup.
Two companion scenarios port Mosquitto's
`03-publish-b2c-disconnect-qos1.py` for MQTT 3.1.1 and MQTT 5. The subscriber
receives but does not acknowledge the first QoS 1 delivery, closes abruptly,
then reconnects with Session Present. Netz retransmits the same payload and
Packet Identifier with DUP=1; after PUBACK, an immediate PINGRESP proves the
inflight transaction was removed rather than delivered again.
Four MQTT 3.1.1/5 offline QoS 0 scenarios cover both values of Mosquitto's
`queue_qos0_messages` policy. Each persistent subscriber disconnects before a
QoS 0 publication and reconnects with Session Present. With the default, an
immediate PINGRESP proves the message was dropped; with the opt-in enabled, the
exact property-free QoS 0 PUBLISH precedes PINGRESP, proving single delivery
without a Packet Identifier.
Two more scenarios port Mosquitto's
`03-publish-b2c-disconnect-qos2.py` for MQTT 3.1.1 and MQTT 5. The first
reconnect observes the unacknowledged QoS 2 PUBLISH with its original Packet
Identifier and DUP=1. After PUBREC and a second abrupt disconnect, the next
Session resume starts directly with PUBREL for that identifier instead of
replaying the Application Message. PUBCOMP followed by PINGRESP proves the
second-stage transaction is retired.
Two more scenarios directly port Mosquitto issue 1322's
`02-subpub-qos2-1322.py` for MQTT 3.1.1 and MQTT 5. A durable publisher
completes five QoS 2 transactions using Packet Identifier 1 on five successive
Network Connections while a second topic gains a subscriber midway through.
Only the current topic-one messages are delivered; ordered PINGRESP checks on
the late topic-two subscriber prove the earlier unmatched message never leaks
from stale inbound QoS 2 state after reconnect or identifier reuse.
Two additional MQTT 3.1.1/5 scenarios directly port Mosquitto's
`03-publish-c2b-disconnect-qos2.py`. A durable publisher disconnects after
PUBREC, reconnects and retransmits the PUBLISH, completes PUBREL/PUBCOMP, then
disconnects again as if PUBCOMP were lost. The next Session resume repeats
PUBREL and receives PUBCOMP without a second subscriber delivery. This exposed
the MQTT 3.1.1 PUBREL DUP flag being rejected and the fresh connection's
receive accounting not recognizing an idempotent completed transaction; both
are now reconciled without weakening MQTT 5 reserved-flag validation.
Four MQTT 3.1.1/5 scenarios cover Mosquitto's non-standard
`upgrade_outgoing_qos` switch. A retained and an ordinary live QoS 0
Application Message are each delivered at the subscriber's granted QoS 1 when
the opt-in is enabled, with the full PUBLISH/PUBACK exchange checked. The
default remains the MQTT-required minimum QoS, and the same policy is applied
before durable Session enqueueing.
Two MQTT 3.1.1/5 scenarios derive the wire-observable queue behavior from
Mosquitto's `03-publish-qos1-queued-bytes.py`. The example broker now exposes
`--max-session-queued-payload-bytes`; each durable Session tracks queued
Application Message payload bytes independently of its count and total owned
memory bounds. A message that reaches the configured threshold is retained,
later messages are dropped while the publisher still receives its successful
QoS 1 acknowledgement, and reconnect delivers exactly the retained prefix.
Draining or expiring a queued message immediately returns byte budget.
Two companion MQTT 3.1.1/5 scenarios cover Mosquitto's
`max_inflight_bytes` behavior. A durable subscriber advertises enough Receive
Maximum credit for all messages, but the broker's independent per-Session
inflight payload window releases only the first two QoS 1 messages. The third
remains queued until a PUBACK frees byte budget, then arrives on the same
connection. The example switch is
`--max-session-inflight-payload-bytes`; zero disables the optional limit.
Eight MQTT 5 scenarios directly port Mosquitto's
`03-publish-b2c-qos1-len.py` and `03-publish-b2c-qos2-len.py`. For each QoS,
the downstream client acknowledges with Packet Identifier only, an explicit
success reason, a reason plus empty Property Length, and a reason plus User
Property. QoS 2 verifies both PUBREC/PUBREL progression and every corresponding
PUBCOMP form; an ordered PINGRESP proves each variant released state.
The offline Message Expiry case directly ports Mosquitto's
`02-subpub-qos1-message-expiry.py`: two QoS 1 messages with one- and ten-second
lifetimes are queued while a persistent subscriber is disconnected. After two
seconds, reconnect reports Session Present, omits the expired message, delivers
only the survivor with its interval reduced to a timing-tolerant 9-6 seconds,
and answers PING immediately after its PUBACK to rule out a stale second
delivery.
The companion Will Message Expiry case directly ports Mosquitto's
`02-subpub-qos1-message-expiry-will.py`. Two ungracefully disconnected clients
publish QoS 1 Wills into an offline durable Session: the ten-second Will is
delivered after reconnect with a reduced 9-6 second interval, while the
one-second Will has expired and is absent. This proves the expiry clock begins
when each Will is actually published rather than when its CONNECT installs it.
The delayed-Will reconnect case directly ports Mosquitto's
`07-will-delay-reconnect.py`: an ungraceful disconnect schedules a three-second
Will for a durable Session, reconnecting the same Client ID after one second
reports Session Present, and a subscriber receives PINGRESP after the original
deadline instead of the canceled Will.
Two companion cases directly port Mosquitto issue 1273's
`07-will-reconnect-1273.py` for MQTT 3.1.1 and MQTT 5. A durable client sends a
normal DISCONNECT after installing a Will, reconnects with the same Client ID
and a replacement Will, and receives Session Present. Exact live PUBLISH bytes
on both sides of the reconnect plus an ordered PINGRESP prove the canceled old
Will is never resurrected.
Three companion cases port Mosquitto's
`07-will-delay-session-expiry.py`, `07-will-delay-session-expiry2.py`, and
`07-will-delay-session-expiry-0.py`. They time the external delivery when
Session Expiry is shorter than Will Delay, when Will Delay is shorter, and when
Session Expiry is zero, proving the broker uses the required minimum deadline
and publishes immediately in the zero-expiry case.
Two more cases port both clean and persistent branches of Mosquitto's
`07-will-delay.py`. Each holds the subscriber read open for two seconds to
prove the three-second Will is not published early, then requires the exact
PUBLISH during the following bounded interval, proving the scheduled Will is
not lost in either Session mode.
An additional full-range Topic Alias case extends Mosquitto's small-alias wire
vectors: a broker configured with Topic Alias Maximum 65,535 advertises that
exact value, accepts alias 65,535 on a client PUBLISH, resolves a following
empty Topic Name, and forwards both messages over the same connection. Sparse
per-connection tables allocate only the aliases actually used rather than
reserving 65,535 pointers for every client.
The gate builds a finite netz broker,
imports upstream `mqtt_packets.py`/`mqtt5_props.py`, and compares complete wire
packets. Four additional wire cases verify absent/zero/one Request Response
Information plus both the default-enabled diagnostic path and Request Problem
Information suppression while preserving an exact negative PUBACK reason; all
141 scenarios pass. This is deliberately described as a selected
wire-vector subset: Mosquitto's Python harness hardcodes its own `-v -c/-p`
broker CLI and many tests depend on Mosquitto config, logs, reload, persistence
or plugins, so passing these vectors is not proxy evidence for the entire suite.

1. **Completed for single-node crash durability:** `Broker.saveLiveSnapshot`
   checkpoints while clients remain connected. A persistence mutex serializes
   snapshot writers,
   while the broker state barrier is held only long enough to encode a detached
   immutable image; file write, fsync, and atomic replacement happen after
   traffic is unblocked. Durable connected Sessions restore offline with
   queued and outgoing inflight QoS state intact; a connected Will is persisted
   with ungraceful-crash semantics and its effective delay starts at the
   checkpoint.
   Volatile online QoS 0/transient connection queues and transient inbound QoS
   2 transactions remain intentionally excluded; opt-in offline QoS 0 and
   inbound QoS 2 owned by a durable Session are restored.
   Tests cover both direct state and a real active broker connection remaining
   usable after checkpoint, followed by restore. The production example now
   accepts `--autosave-interval-seconds=N`, and the process gate above proves a
   periodic checkpoint survives forced termination with both subscription
   metadata and an opt-in offline QoS 0 delivery intact. The append journal
   closes the interval between checkpoints for protocol-visible durable
   mutations. Cross-node replication/consensus remains separate work.
2. Extend the production-scale publisher-window, latency, allocation and RSS
   comparison above to Mosquitto and additional concurrency/fanout shapes;
   the current result covers netz versus rumqttd at one bounded QoS 1 shape.
3. Expand the selected Mosquitto-derived raw wire gate above, or add a broker
   process adapter capable of preserving the upstream harness's config/reload/
   persistence semantics. The 141 passing packet-vector scenarios do not cover
   the full protocol/conformance suite.
