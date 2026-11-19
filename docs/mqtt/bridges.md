# MQTT broker bridges and redirects

[Back to the rumqtt parity index](../rumqtt_parity.md).

## One-way inbound broker bridge

`mqtt.bridge.Bridge` is deliberately a small, inbound-only topology primitive.
It owns its `reconnect.Client` and copies the rule strings and MQTT CONNECT
fields. `init` preserves the fixed-address cleartext API; `initHost` also copies
the hostname and re-resolves it on each retry; `initConnector` accepts transport
adapters such as `mqtt.tls_runtime.HostReconnectConnector`. The local `Broker`,
shutdown event, and `std.Io` backing state remain borrowed until `deinit`. For
`initConnector`, the connector context and every referenced transport option
(including CA bundles, locks, certificate/key slices, and callbacks) are also
borrowed for the complete Bridge lifetime; only the MQTT CONNECT options passed
separately are deep-copied. All bridge and client methods remain single-owner;
only shutdown signaling (and, when needed, shutting down the active socket to
wake a blocking read) may happen from another thread. `initMany`, `initHostMany`,
and `initConnectorMany` deep-copy every rule. QoS 0/1 bridges install all
missing filters in one SUBSCRIBE. QoS 2 bridges seed the reconnect client's
durable subscription set before CONNECT, so a fresh Session replays each rule
and a resumed Session can deliver queued PUBLISH/PUBREL packets immediately. A
partial refusal closes the unusable transport before retrying only missing
filters. Duplicate or intersecting filters are rejected so every
inbound Topic Name has exactly one mapping. An optional `remote_prefix` is
stripped before `local_prefix` is prepended; the production config adapter
constructs the effective subscription from Mosquitto's
`topic FILTER in QOS LOCAL_PREFIX REMOTE_PREFIX` form. Configured outbound and
`both` rules use the `OutboundBridge` engine described below; its optional
inbound half reuses this same delivery code and the same remote Client.

Each instance subscribes to one or more validated, pairwise-disjoint remote
filters at QoS 0, 1 or 2. Filter intersection handles `+`, terminal `#`, empty
levels, shared-filter wrappers, and MQTT's leading-`$` wildcard exclusion. It
selects exactly one matching rule, removes its optional literal remote prefix,
prepends its optional literal local prefix, then calls the trusted
`Broker.publishLocal` boundary. A bidirectional bridge instead supplies its
broker-local source identity so No Local prevents immediate return traffic.
Both boundaries reject
DUP, Packet Identifier, Topic Alias, and Subscription Identifier state because
all four belong to a particular network transaction or subscription. It applies
the broker's normal topic/property/payload limits, retained store, read ACL,
bounded live and durable Session queues, expiry, commit log, and flush order.
It has no synthetic publishing identity, so source write ACL and No Local do
not apply; deployments should treat possession of the Broker pointer as the
trust boundary.
For MQTT 5 the bridge requests Retain As Published, so upstream retained state
can populate the local retained store. MQTT 3.1.1 has no equivalent subscription
bit: its initial retained replay preserves RETAIN, while later live deliveries
may arrive with RETAIN cleared by the upstream broker.

The bridge does not add an intermediate unbounded queue. The reconnect event
itself owns a QoS 0/1 publication until injection completes, and a remote QoS 1
PUBACK is emitted only afterward. A failed QoS 1 injection therefore leaves the
remote transaction eligible for redelivery while the connection or persistent
Session survives. QoS 2 uses the broker's bounded `BridgeQoS2Store`: the mapped
message and connection-independent properties are synchronously appended to the
local commit log before PUBREC; PUBREL atomically admits the message to local
retained/Session/live routing and installs a released tombstone; PUBCOMP is sent
only after that boundary. The released tombstone remains until a future
Session Present=false proves the upstream transaction is gone, so a process
restart still rejects a delayed duplicate PUBLISH. A failed live
destination write is then owned by normal connection cleanup or durable Session
retry and cannot stop the independent upstream bridge after PUBCOMP. Duplicate
PUBLISH packets are surfaced to the store for full topic/payload/property
comparison instead of being accepted by Packet Identifier alone. A recreated
Bridge restores pending and released receive markers from the broker store
before reading a resumed Session, while Session Present=false durably retires all old
transactions and advances a separately persisted epoch before a new one begins,
including the no-active-transaction crash window. QoS 2 construction therefore
requires a stable
16-byte `bridge_id`, unchanged Client ID/rules, a non-zero upstream Session
lifetime, and an already enabled local commit log; it fails closed rather than
claiming crash-safe exactly-once admission without those prerequisites.
MQTT exposes no remote Session generation token or distributed transaction, so
simultaneous loss/recreation of independently persisted local and upstream
brokers remains outside this guarantee; operators must retain both stores and
keep the configured Client ID, `bridge_id`, and rule mapping paired.
The same inbound data path is reused by a bidirectional bridge. Its local
source subscriptions suppress bridge-originated injection, and MQTT 5 applies
No Local to the remote subscriptions as well. MQTT 3.1 and 3.1.1 have no
wire-level No Local bit, so a bidirectional legacy configuration requires
Mosquitto's private bridge mode and treats a peer rejection as terminal instead
of falling back to an unsafe ordinary client connection.
Tests exercise both directions over one live remote Session, prove that the
inbound message is absent from the local outbound source, and recreate the
bridge between remote QoS 2 PUBREC and PUBREL to verify durable recovery and
exactly-once local admission.

MQTT 3.1's CONNACK acknowledgement byte predates Session Present and is wholly
reserved by the original specification. Low-level netz clients and servers
therefore default to strict mode: parsers preserve the raw byte but do not
assign Session semantics, and servers emit zero. `V31ConnAckMode.mosquitto`
explicitly enables Mosquitto's de-facto bit-0 Session Present extension.
Mosquitto-style configured listeners and MQTT 3.1 configured bridges select
that mode so persistent-session interoperability remains intentional rather
than silently masquerading as standard MQTT 3.1 behavior.

The automated in-process integration tests include a real hostname-authenticated
TLS 1.3 bridge using a local CA and `HostReconnectConnector`; it injects an
upstream QoS 1 publication and observes that the remote PUBACK follows completed
local broker routing. Separate two-loopback-broker tests exercise `Bridge.connect`/`step` with a
retained MQTT 5 QoS 1 publication and two disjoint rules installed in one
SUBSCRIBE. They verify rule-specific topic prefixes, preserved User Property
and RETAIN state,
connection-scoped Topic Alias removal, local Subscription Identifier
generation, local retained storage, and eventual remote PUBACK completion. A
second two-broker persistent-session test now fault-injects the bridge just
before `Broker.publishLocal`, after the reconnect client has already surfaced
the upstream QoS 1 Packet Identifier but before any local queue, retained
store, commit-log, or downstream write can change. The bridge therefore
withholds its upstream PUBACK without leaving a local ghost delivery, then
reconnects to an upstream Session that reports Session Present and redelivers
the same Packet Identifier with DUP set. The retry reuses the exact production
inject-and-ack path, and the test proves completion only by observing the local
delivery exactly once and then using a bridge PING barrier before checking that
the upstream inflight transaction has cleared. This fault gate verifies the
pre-injection acknowledgement boundary; durable commit-log failure handling is
still a separate transactional concern.
A third two-broker test, derived from Mosquitto's QoS 2 bridge disconnect
vectors, drives MQTT 3.1.1 and MQTT 5 through real
upstream and downstream handshakes. It proves no local PUBLISH is visible
before PUBREL, rejects a content-mismatched DUP against the staged transaction,
destroys and recreates the Bridge after PUBREC, resumes without an interleaved
SUBSCRIBE, injects the message exactly once, and observes upstream PUBCOMP only
after the journaled local release.

## One-way outbound broker bridge

`Broker.openLocalConsumer` provides an in-process subscription source without
connecting back through a listener. A
stable 128-bit identity maps to a Session key that cannot be represented by an
MQTT UTF-8 Client ID, preventing network-client takeover. The consumer's rules
use the ordinary Router, retained replay, bounded Session queues, message
expiry, and commit-log persistence. `pollLocalConsumer` returns deep-owned
PUBLISH or PUBREL events outside the Broker lock; QoS 0 completion, QoS 1/2
acknowledgement, and pre-transfer retry are explicit. Unacknowledged QoS 1 and
QoS 2 stages resume after journal restore with their Packet Identifier and DUP
semantics intact.

Each handle has one serialized owner. Closing it preserves durable
subscriptions and restores a selected, incomplete QoS 0 event to the queue;
reopening issues a fresh generation, so stale handles cannot poll, acknowledge,
retry, or close the replacement. QoS 1/2 messages continue to queue while the
consumer is closed, and newly arriving offline QoS 0 follows the broker's
`queue_qos0_messages` setting. This is a trusted internal API: network-client
read ACLs do not apply, while retained-source authorization still does.
Queue, payload-byte, inflight, expiry, and Receive Maximum limits use the
ordinary Session implementation. A failed event allocation returns the
transmission to that Session; every returned event crosses the commit-log
boundary, including a PUBREL following a failed PUBREC-state write. Retried
PUBLISH events preserve the original DUP flag.

The Session API validates each ACK reason before changing transaction state,
Receive Maximum credit, or persistent generation. Codecs and the direct API
share the packet-specific MQTT 5 policy: PUBACK/PUBREC accept nine reason
codes, PUBREL/PUBCOMP accept Success and Packet Identifier Not Found, and
Packet Too Large (`0x95`) is rejected for every QoS ACK. Exhaustive tests cover
all 256 byte values and compare Session statistics and encoded snapshots after
invalid ACKs; valid negative PUBREC still terminates the delivery and releases
its credit.

The public connection ACK application APIs now use `AckPacket.validate` before
releasing outgoing identifiers/credit or sending PUBREL. Typed ACKs receive
the same version, DUP, reason and property validation as both ACK writers;
invalid metadata no longer completes a publication or advances QoS 2 merely
because it bypassed the wire parser. The ACK and its properties remain
borrowed by the state operation. `runtime/acknowledgement/apply.zig` owns this
transition policy, with adjacent tests for all 256 reasons across MQTT
3.1/3.1.1/5, independent incoming/outgoing identifier spaces, sibling
publications, invalid properties/DUP, and exact legal PUBREL retransmission.
Invalid ACKs perform no allocation or socket write and preserve the original
QoS stage so a later valid acknowledgement can continue the exchange.

Single-event Session drains retain only a genuinely unsent inflight suffix.
After PUBREC, selecting one PUBREL no longer advertises already-sent later
PUBLISH packets as pending work. The regression combines multiple QoS 2
transactions, the inflight payload-byte cap, one-event drains, and PUBCOMP
credit release, matching the production broker's delivery loop.

`src/mqtt/broker/local_consumer_tests.zig` covers all QoS levels, retained
replay, stale handles, close/reopen, flow control, negative PUBREC, offline
authorization, registration and poll allocation failures, failed journal
writes, and restart from each QoS 2 phase. The production configuration runner
uses this API directly for `topic ... out|both` rules through
`mqtt.bridge.outbound.LocalBridge`, with no loopback listener or source-side
socket. It registers the source before starting listener service so startup
publications already have a bounded durable route. Mixed `in`, `out`, and
`both` rules share one remote MQTT Session and reconnect lifecycle.

Outbound configuration reuses hostname-verified TLS 1.3, encrypted-key mTLS,
ALPN, multiple-address failover/failback, automatic/once startup and retained
local/remote status with remote Last Will. A fixed consumer identity derives
from the connection name; reusing it with changed subscriptions is rejected.
QoS 2 uses the broker commit log plus a separate identity-bound coordinator
journal named from the persistence path and consumer ID. It binds the local
receipt state to the remote client snapshot before wire progress, so restart
resumes the remote Packet Identifier and PUBREL phase. Source completion is
committed before clearing its broker transaction. An empty coordinator with a
remaining broker PUBREL finishes PUBCOMP without publishing again. Loss of
required remote Session state fails closed. The broker and coordinator stores
must be retained together.

Tests cover all QoS levels, five QoS 2 restart boundaries, and the production
configuration process through cleartext and native TLS/mTLS, an unavailable
primary address, topic-prefix mapping, retained connection state, and process
kill/restart. A Mosquitto-derived MQTT 3.1.1/5 process matrix additionally
checks configured Receive Maximum and Topic Alias Maximum on CONNECT, keeps the
local receive and remote outgoing packet limits independent, applies the
smaller configured/CONNACK outgoing packet size, and verifies both values of
the outgoing RETAIN policy on forwarded PUBLISH packets. Network-source
outbound tests are explicitly imported into the library gate as well.

Bridge identity and upstream credentials accept Mosquitto's current
`remote_clientid`, `remote_username`, and `remote_password` directives as well
as their legacy `clientid`, `username`, and `password` aliases. Each pair maps
to one owned field and shares duplicate-directive rejection, so an alias cannot
silently override its modern spelling.

Native MQTT TLS listeners advertise `mqtt` ALPN when the peer offers it while
accepting legacy clients with no ALPN extension. An offered list without
`mqtt` is rejected rather than silently accepting another protocol. Internal
consumer commits wait outside the broker locks while a provisional CONNECT
registration attaches or rolls back, so concurrent admission cannot turn an
otherwise valid bridge ACK into a fatal SnapshotBusy result.

Configured outbound bridges also support Mosquitto-style `start_type lazy`,
`threshold`, and `idle_timeout`. The broker signals the local consumer directly
when a matching delivery is durably queued, so an offline bridge sleeps without
polling and does not open its target connection below the configured threshold.
Once activated it drains the whole queue, retains sub-threshold work across a
broker restart, and disconnects only after the queue and coordinated QoS 2
transaction are both empty for the complete idle interval. Configuration
rejects zero durations/counts, inbound-only lazy bridges, and thresholds above
a finite `max_queued_messages`, which would otherwise make activation
unreachable.
The activation threshold applies to new queued batches. An already connected
target or a coordinated QoS 2 transaction resumes immediately, and restored
local in-flight work also bypasses the threshold. Local QoS 0/PUBCOMP journal
completion is retried before entering the queue wait, even when the target has
disconnected and no queued message remains. Bounded real-TCP recovery tests
cover coordinator-clear, broker-PUBCOMP and QoS 0 journal failures, source
reopening with one in-flight QoS 1 delivery below a threshold of two, and the
return to idle after completion.
A bounded source-locked port of Mosquitto's `15-persist-bridge-queue.py`
extends that evidence across both brokers. After a warmup establishes the
persistent remote Session, the target checkpoints and stops; sixteen local QoS
1 publications are acknowledged into the active bridge's durable source queue,
then the local broker checkpoints and is killed. Restoring the target Session
and local broker drains all sixteen in exact order. The lazy bridge's idle
state is the completion barrier; a second local checkpoint/restart leaves it
inactive, while the target subscriber's PING proves no completed delivery was
resurrected. The same process scenario then publishes new QoS 1 work after
that empty-queue restart, requires another online/offline notification cycle,
and checks exact target delivery followed by an empty PING barrier.

Configured remote connections also expose Mosquitto's
`bridge_receive_maximum`, `bridge_max_topic_alias`,
`bridge_max_packet_size`, and `bridge_outgoing_retain`. Receive Maximum is
independent from the local outgoing inflight window and inherits the effective
global `max_inflight_messages` when omitted. The Topic Alias setting controls
both the CONNECT advertisement and the local ceiling applied to the remote
CONNACK value. The outgoing complete-packet limit treats zero as unlimited and
uses the smaller non-zero configured or negotiated value; an oversized
forwarded PUBLISH is retired for that destination without terminating the
bridge. This also covers Session Present=true replay after the remote limit
shrinks: the reconnect Session removes only the oversized QoS 1/2 PUBLISH,
keeps the connection usable, and reports local Quota Exceeded `0x97` through
the delivery observer. The outbound bridge propagates that legal reason to its
source; its durable QoS 2 coordinator commits a target rejection before
clearing the source transaction. A pending PUBREL is never discarded because
the peer has already accepted that QoS 2 PUBLISH. Disabling outgoing RETAIN
strips it from forwarded publications and remote state notifications in both
MQTT 3.1.1 and MQTT 5. The default-on
`bridge_attempt_unsubscribe` sends mapped remote filters after every outbound
connection and waits for a successful UNSUBACK before forwarding, except for
filters still used by the same bidirectional bridge. This prevents a persistent
Session from replaying subscriptions left by an older inbound configuration
without tearing down current inbound subscriptions. Legal PUBLISH traffic
interleaved before an UNSUBACK is retained in wire order, acknowledged, and
deliberately discarded; disabling the option omits the cleanup packet.

Synchronous SUBSCRIBE now also retains PUBLISH packets received before SUBACK,
as permitted by MQTT's section 3.8.4. Earlier queued packets keep their original
position, the complete SUBACK still validates Packet Identifier and reason
count, and later typed reads deliver the preserved messages. SUBSCRIBE,
UNSUBSCRIBE use `runtime/acknowledgement/retained.zig` for recoverable responses;
PING uses `runtime/acknowledgement/wait.zig`. Both paths share the configured
pending-packet bound and emergency overflow retention, and preserve the
original deadline. Queue refusal occurs before a SUBSCRIBE write or Packet
Identifier mutation. Adjacent MQTT 3.1/3.1.1/5 wire tests cover early retained
traffic, older pending traffic, overflow recovery, and mismatched SUBACKs. A
two-connection MQTT 3.1.1/5 reconnect test proves fresh-Session subscription
replay accepts early QoS 1 publications and delivers them through normal
application polling and PUBACK handling.
The focused client/runtime, reconnect, TLS, WebSocket and Unix matrix passes
245 tests in Debug and ReleaseFast. Package reachability and the two-Mosquitto
OutboundBridge gate also pass, including QoS 0/1/2 and durable restart recovery.

The same correlated-response queue now also enforces
`Limits.max_pending_packet_bytes`, defaulting to 32 MiB, independently of the
256-packet count limit. Its accounting covers complete MQTT wire packets,
including Topic and Properties, and returns byte credit as soon as an ordinary
reader takes ownership. Count/byte refusal precedes queue allocation or
compaction; allocation failure leaves both counters unchanged. An already-read
overflow packet still follows the queued prefix and is separately bounded by
`max_packet_size`. Zero byte credit disables correlated-response helpers before
their request write. The queue lifecycle lives in
`runtime/acknowledgement/pending.zig`, with adjacent exact-limit, compaction,
overflow, integer-boundary and allocation-failure tests. Real connections cover
SUBSCRIBE across MQTT 3.1/3.1.1/5, and PING/UNSUBSCRIBE across MQTT 3.1.1/5,
including recovery of the retained packets and the still-pending response.
On 64-bit targets the byte policy adds eight bytes to the compact live
connection limits, while its counter adds eight bytes to the on-demand queue.
The focused queue/client/runtime/reconnect, TLS, WebSocket and Unix matrix
passes 253 tests in Debug and ReleaseFast; package reachability passes two tests.

Bounded PING now applies its original absolute deadline to PINGREQ output as
well as PINGRESP input. A blocked socket/TLS/WebSocket write can no longer
outlive the liveness budget before response waiting begins. Interrupted output
marks the MQTT connection unusable, matching the existing packet-write failure
contract. An observed-writer regression cancels a real TCP request write for
both relative and absolute PING calls; the focused PING, TLS/mTLS/WebSocket,
clock-domain and reconnect-poll matrix passes 104 tests in Debug and ReleaseFast.

`Connection` and reconnect `Client` now expose `subscribeWithTimeout`,
`subscribeWithDeadline`, `unsubscribeWithTimeout` and `unsubscribeWithDeadline`.
Each call validates its awake-clock budget before state changes and retains one
absolute timestamp through request output, interleaved packet preservation,
and the correlated SUBACK/UNSUBACK. The common exchange implementation lives
in `runtime/acknowledgement/exchange.zig`; existing blocking APIs use that same
path with no deadline. Reconnect cache updates still commit only after broker
acknowledgement, while a timeout retires the failed connection and preserves
the previous subscription cache. Fresh-Session subscription replay also uses
the original CONNECT deadline rather than starting unbounded SUBACK waits.
Adjacent wire tests cover successful and stalled responses, write cancellation,
combined write/read budget consumption, queued PUBLISH ownership, zero/expired
budgets and foreign clock domains. Reconnect tests cover relative/absolute
cache updates and fresh-Session replay in MQTT 3.1.1 and MQTT 5.
The focused runtime/client/reconnect, queue, TLS, WebSocket and Unix matrix
passes 262 tests in Debug and ReleaseFast; package reachability passes two tests,
and the two-Mosquitto OutboundBridge gate passes its QoS/restart matrix.

Outgoing PUBLISH, SUBSCRIBE and UNSUBSCRIBE now reserve identifiers from the
same connection-local sender space, as required by MQTT 5 section 2.2.1
(`MQTT-2.2.1-3`). A subscription command keeps its identifier after a successful
write followed by timeout or pending-queue failure. It releases that identifier
only after a parsed, property-validated SUBACK/UNSUBACK with the expected reason
count and SUBACK grants at or below each requested maximum QoS; legacy
UNSUBACK remains identifier-only. Ordinary typed readers also
settle late responses. A later exchange queues earlier known subscription ACKs
in wire order while waiting for its own identifier. Wrong-stage, malformed and
wrong-count acknowledgements cannot release an active command, and PUBLISH
completion rejects publication ACKs addressed to a subscription command.
Reservation, encoding and packet-size preflight failures roll back command
ownership and the allocation cursor. These control commands do not consume
the QoS PUBLISH Receive Maximum window. Shared allocation and sparse/dense
storage live under `runtime/packet_identifiers/`, with adjacent tests for the
complete 1..65,535 shared space, wraparound, independent incoming ownership,
allocation rollback and MQTT 3.1/3.1.1/5 late-ACK recovery.
Each submitted SUBSCRIBE owns an ordered QoS snapshot before transport output,
following the requested-maximum semantics in MQTT 3.1.1/5 sections 3.8.3 and
3.8.4. A valid identifier, reason count and individual reason code cannot hide
a grant above its corresponding request: both correlated completion and typed
readers return `UnexpectedPacket` without releasing command ownership. Lower
grants and failure reasons remain valid. Caller mutation, receive timeout,
decode-allocation retries and reverse-order ACKs retain the original limits;
completion, pre-write rollback, connection reset and close release the owned
snapshot. The metadata implementation lives in
`runtime/packet_identifiers/control.zig`, with adjacent real TCP regressions
for MQTT 3.1/3.1.1/5 and exhaustive pre-output allocation-failure coverage.
Validation covers the Debug MQTT/session matrix, focused Debug/ReleaseFast
identifier and subscription tests, package reachability, and real Mosquitto
publish, Mosquitto CLI client and rumqttc 0.25.1 interoperability gates.

Reconnect clients now connect the durable Session sender index to the
Connection's allocation space through a live borrowed ownership view. New
SUBSCRIBE/UNSUBSCRIBE and direct PUBLISH reservations avoid durable staged,
inflight and PUBREL identifiers, including Session Present recovery. Durable
immediate/staged publications and queue drains likewise avoid connection-owned
commands. `Session.Store.packetIdentifierOwnership` lazily promotes only the
hash-map descriptor into stable storage, retaining its existing entries and
keeping the view valid across Store/Client moves, Session table growth and
rehashing. `beginImmediatePublishAvoiding`, `stageImmediatePublishAvoiding` and
`drainIntoAvoiding` borrow connection reservations only for their call, so no
Network Connection pointer is persisted in a Session snapshot. The live view
must be detached before its Session is deleted or replaced; the reconnect
owner installs it after Session recovery and closes the Connection before
retiring that Session.

Wire QoS counters and ACK processing retain their existing owners: the durable
Store handles durable publication ACKs, while the Connection handles its own
publications and subscription commands. The shared reservation view does not
double-charge Receive Maximum or copy the durable identifier set. Identifier
exhaustion restores the allocation cursor, keeps an unselected queued message
owned, and returns any already-selected drain prefix instead of losing it
behind later identifier exhaustion. Adjacent tests cover both directions of
subscription/PUBLISH collisions, staged and queued work, PUBREL, live deletion,
OOM during descriptor promotion, complete identifier exhaustion, Store/Client
moves and Session Present across MQTT 3.1.1/5. MQTT 3.1 direct interleaving is
also covered, while its CONNACK has no Session Present flag. The real Mosquitto
publish gate additionally verifies staged PUBLISH mixed with controls and
unconfirmed QoS 1 recovery followed by a new subscription.

Subscription requests can now be submitted separately with `writeSubscribe`
or `writeUnsubscribe`, retaining their returned identifiers for later
`completeSubscribe`/`completeUnsubscribe`. Each API has timeout and absolute
deadline variants. Several commands can remain in flight together; completion
can select any active identifier and extracts its ACK from the pending queue
without reordering other ACKs or application packets. Pending ACKs can complete
even when the ordinary queue is full or its count/byte quota is zero. A receive
timeout leaves the submitted command available for completion under a new
budget on the same usable Network Connection, with no extra request write.
An interrupted request write still retires the connection because its wire
prefix is ambiguous.

Both correlated completion and ordinary typed SUBACK/UNSUBACK readers now
retain complete raw packets until decoding succeeds. Property/reason allocation
failure preserves the original packet position, byte accounting and command
identifier; a later call retries that same ACK. This includes an ACK read
directly from TCP into the emergency slot. Non-allocation syntax/state failures
consume the invalid ACK while leaving command ownership intact. The PUBLISH
completion path shares the same retained-packet reader, preserving its
allocation and deadline recovery behavior. The implementation lives in
`runtime/acknowledgement/control/` and `retained.zig`, with
adjacent allocation, reverse-order, quota, expired/foreign-budget and timeout
regressions. The real Mosquitto publish gate now also submits two subscription
commands at a time and completes them in reverse order for MQTT 3.1/3.1.1/5
under ordinary, relative-timeout and absolute-deadline APIs.

```zig
const packet_id = try connection.writeSubscribeWithTimeout(
    &.{.{ .topic_filter = "events/#" }}, .{}, .fromSeconds(1),
);
// If this wait times out or returns OutOfMemory, retain packet_id and call
// completeSubscribe again under a new budget on the same usable connection.
var suback = try connection.completeSubscribeWithTimeout(packet_id, .fromSeconds(1));
defer suback.deinit(allocator);
```

The reconnect deadline now also spans recovery of existing QoS 1/2 state after
CONNACK. PUBLISH prefix/payload output and PUBREL replay receive the same
absolute timestamp, and each drain checks that budget before selecting the
next durable transaction. Interrupted writes retire the connection while
preserving the original Packet Identifier and retransmission state; later
queued publications retain first-send `DUP=0`. `flushPendingWithTimeout` and
`flushPendingWithDeadline` expose the same boundary for staged publications
and deferred QoS 2 release. Recovery scheduling lives in `reconnect/replay.zig`.
The packet transport's bounded parts writer joins cancellation before borrowed
packet slices are released, retaining the ordinary TCP/TLS scatter/gather and
TLS flush policy plus one WebSocket binary message. The standard TLS adapter
restores the underlying socket error from `WriteFailed`, so deadline
cancellation returns `Timeout` while actual network failures retain their
original cause. Adjacent real-connection tests cover three-generation MQTT
3.1.1/5 recovery for QoS 1, QoS 2 PUBLISH and PUBREL, a later untouched
publication, staged flush, zero/expired budgets, and complete 48-KiB PUBLISH
delivery or canceled output through TCP, standard TLS, vail TLS 1.3/1.2 and WS.
The focused runtime/client/reconnect, queue, TLS, WebSocket and Unix matrix
passes 267 tests in Debug and ReleaseFast; package reachability passes two tests,
and the two-Mosquitto OutboundBridge QoS/restart matrix remains green.

After a successful MQTT 5 target CONNACK, outbound QoS 0/1 PUBLISH packets use
the lower of the source QoS and the peer's Maximum QoS, and clear RETAIN when
Retain Available is false. A source QoS 1 delivery lowered to target QoS 0 is
completed only after that target socket write succeeds, so no nonexistent
PUBACK is awaited. The bridge opts into the reconnect client's QoS-1-only
capability policy, so a Session Present=true replay obeys capabilities that
tightened since the previous connection: lowering to QoS 0 retires the stored
Packet Identifier only after the replacement socket write, while clearing
RETAIN without lowering QoS still waits for the original PUBACK. General
reconnect clients remain strict by default. Durable source QoS 2 is never
silently weakened: when the peer Maximum QoS is lower than 2, the bridge sends
no target PUBLISH, creates no coordinator transaction, and terminates an MQTT
5 source transaction with the PUBREC-valid Implementation Specific Error
`0x83`; legacy sources fail closed because their PUBREC cannot carry a negative
reason. When target QoS 2 is available but RETAIN is not, the durable handshake
is preserved and only the target RETAIN flag is cleared. In-process
broker-local, reconnect, and two-wire tests cover fresh and resumed Sessions,
target non-delivery, exact negative acknowledgement, socket-write completion,
and removal of Session receipt, inflight, and coordinator state.

The reconnect client retains one bounded owned failed CONNACK instead of
collapsing every protocol refusal into an opaque error. Applications may
borrow or take that typed refusal, or explicitly lower an owned CONNECT Will
from its capability properties before retrying. Configured and programmatic
bridges apply this only to the remote notification Will they generated:
`0x9b` plus Maximum QoS lowers QoS, and `0x9a` plus Retain Available false
clears RETAIN. An opt-in target fallback also consumes MQTT 5 Unsupported
Protocol Version `0x84`, atomically switches the owned CONNECT to MQTT 3.1.1,
drops unrepresentable MQTT 5 CONNECT properties and applies the requested
private-bridge marker; non-empty Will properties fail closed, and unsafe
standard-legacy fallback is rejected for bidirectional bridges. At most three
changed fields can cause immediate retries, so a repeated or unrelated refusal
remains terminal and caller-supplied Wills are never silently modified without
that explicit fallback. A source-locked production-configuration process test
observes MQTT 5 QoS 1/Retain, QoS 0/Retain, QoS 0/non-Retain, then MQTT 3.1.1
private mode before accepting the bridge and validating its online state
publication; the in-process lifecycle test additionally verifies the offline
notification and graceful disconnect.

Mosquitto-compatible `try_private` defaults on for MQTT 3.1 and 3.1.1 bridges.
Netz emits the private protocol-level marker, immediately retries a one-way
bridge on the same endpoint with its configured standard level after an
Unsupported Protocol Version CONNACK, and remembers that fallback for later
reconnects. Bidirectional legacy bridges fail closed instead. A netz broker
accepting a private bridge marks its legacy subscriptions no-local and
retain-as-published, which provides loop prevention and retained-flag fidelity
unavailable in standard MQTT 3.1/3.1.1 subscription options. MQTT 5 never emits
this private extension.

The source-locked process gate now completely ports Mosquitto's
`06-bridge-no-local.py`: MQTT 3.1 and 3.1.1 use their actual private CONNECT
markers, while MQTT 5 uses its explicit No Local option. Each self-publication
must be followed directly by PINGRESP with no echoed PUBLISH. A separate
publisher then proves the same subscription still delivers, and a final PING
barrier rejects extra or delayed self messages.

`bridge_bind_address` accepts a numeric IPv4 or IPv6 source address and binds
an ephemeral local port before every cleartext or TLS connection attempt.
Hostname lookup is restricted to the selected address family, numeric family
mismatches fail during configuration, and fallback/reconnect attempts preserve
the bind. The implementation uses zio's native cancelable bind/connect path;
foreign `std.Io` backends receive `OptionUnsupported` instead of silently
ignoring the requested source address.

`bridge_tcp_keepalive` accepts Mosquitto's three positive values: idle seconds,
probe interval seconds, and failed-probe count. Each successful remote socket
enables `SO_KEEPALIVE` and applies all three TCP parameters before cleartext or
TLS protocol negotiation. Missing platform support and Unix-domain transports
fail explicitly instead of leaving a partially configured connection alive;
the Linux process gate traces all four successful `setsockopt` calls.

`bridge_tcp_user_timeout` configures Linux `TCP_USER_TIMEOUT` in milliseconds
on every remote bridge connection, including fallback and reconnect attempts.
The omitted state leaves the kernel default untouched, while explicit zero is
preserved as a real `setsockopt` request; values follow Mosquitto's non-negative
C `int` range. The same optional socket policy is carried by the MQTT and
WebSocket runtimes across TCP, TLS, WS, and WSS before protocol handshakes.
Unsupported platforms and Unix-domain transports fail explicitly rather than
silently discarding it. The process gate traces successful cleartext and TLS
bridge sockets and checks the actual keepalive and `TCP_USER_TIMEOUT` syscall
values.

`bridge_ciphers_tls1.3` accepts an ordered colon-separated list of the TLS 1.3
cipher suites implemented by vail. The list is parsed and owned with the rest
of the bridge configuration, then reused by every TLS connection and reconnect.
Unknown names, empty elements, duplicates, and a configured cipher list without
a trust source fail before listeners start. The process gate constrains a live
bridge ClientHello to ChaCha20-Poly1305 and checks the negotiated suite from an
OpenSSL TLS server.

The configured bridge runtime deep-copies complete validated bridge records,
including rules, secondary endpoints, credentials, TLS paths and cipher lists,
into move-stable generation entries. Linux `SIGHUP` reparses the complete
configuration and fully constructs every replacement generation before changing
the running bridge set. The bridge supervisor reserves all required slot
capacity, then waits behind a commit gate while password/ACL/CRL state and
TLS/WSS identities are also prepared. A failure in any subsystem leaves every
active bridge, security policy, and identity generation untouched. New and
removed bridge names take effect
immediately; an existing bridge with `bridge_reload_type immediate` reconnects
at once, while the default `lazy` policy preserves its established connection
and adopts the newest pending generation only at its next natural disconnected
boundary. Repeated lazy reloads replace the unactivated pending generation.
Bridge supervision and cancellation are independent from listeners, so ordinary
MQTT clients stay connected throughout either reload mode. The process gate is
derived from Mosquitto's `06-bridge-config-reload.py` at source revision
`5cd2546511596a269dbf53f85858c623b09ebdd6` (file SHA-256
`6ad3507ff44b52ab06794335e5eca0071d633ffb38584aaea0d5a21ca4d1f997`) and
extends it with invalid-parse and failed-TLS-staging rollback, repeated-lazy,
bridge removal/addition, cross-subsystem rollback, and local-client continuity
checks.

TLS and WSS listeners expose the matching `ciphers_tls1.3` directive alongside
their existing TLS 1.2 `ciphers` policy. The ordered list is deep-owned by the
configuration and passed to every vail server handshake; unknown or duplicate
suites, empty list elements, use outside a listener, and use without a complete
server identity fail before any socket is bound. The configured-broker process
gate restricts both MQTT/TLS and WSS to AES-256-GCM/SHA-384, forces the OpenSSL
client to that suite, and independently checks the Python WSS client's
negotiated cipher.

`bridge_require_ocsp true` promotes stapled OCSP from opportunistic input to a
mandatory trust condition on every TLS connection and reconnect. Netz's vail
ClientHello requests the RFC 6066 status response by default, preserving RFC
7633 Must-Staple behavior even without the explicit bridge option. Missing,
expired, malformed, unknown, revoked, or incorrectly signed responses fail
before MQTT CONNECT. The bounded trust cache fingerprints the complete
leaf-aligned staple state, so a prior successful response cannot authorize a
later missing or revoked one. The process gate creates signed good and revoked
responses, serves them through OpenSSL TLS 1.3, and also covers no staple.

`mqtt.bridge.OutboundBridge` treats both ends as ordinary MQTT peers: it owns a
reconnecting source subscriber and a reconnecting target publisher. Rules use
Mosquitto's mapping order: subscribe to `local_prefix + filter`, strip the
local prefix from each delivered Topic Name, then prepend `remote_prefix`.
Fixed addresses, independently re-resolved hostname pairs, and arbitrary
connector pairs are available; `initEndpoints` permits mixed endpoint kinds.
Rule strings and hostname targets are copied, while connector contexts remain
borrowed. Duplicate or intersecting effective source filters are rejected so a
message never has ambiguous mapping semantics.
The MQTT rule that `prefix/#` also matches the parent `prefix` is handled
explicitly: a non-empty remote prefix maps that parent, while an empty final
Topic Name is consumed rather than emitted or treated as a transport failure.

Configured outbound bridges implement Mosquitto's `local_cleansession`
separately from the remote `cleansession`; when omitted it inherits the remote
setting. Clean local startup atomically replaces any earlier internal
subscription Session, and clean shutdown removes its routes and queued
deliveries from both live state and the persistence journal. The process gate
queues QoS 0 while the remote is unavailable, restarts the local broker, proves
the stale message is absent, and then forwards a fresh message. Because the
bridge's QoS 1/2 contract depends on a recoverable source Session, combining
outbound QoS 1/2 with a clean local Session is rejected during configuration
instead of silently weakening delivery guarantees.
`local_clientid` is deep-owned and selects both the broker-internal source
Session and the outbound journal identity. Its default is
`local.<remote_clientid>`, and duplicate identities across outbound bridges are
rejected before listeners open. An explicit identity therefore survives a
connection-block rename while an intentional identity change starts a distinct
local Session.

QoS 0 is forwarded after the target socket write, with the expected
fire-and-forget loss window. QoS 1 requires a persistent source Session. The
bridge withholds PUBACK from its source subscription until the target PUBACK is
accepted. If the target transport fails, a resumed target Session receives the
original Packet Identifier with DUP; a fresh target Session causes a new
PUBLISH from the source event that remains owned by the bridge. If the source
PUBACK itself is ambiguous, its broker may redeliver and the target may observe
a duplicate, which is the intentional at-least-once contract. This source ACK
is the acknowledgement for the broker-to-bridge subscription hop; it does not
delay the original application's earlier publish acknowledgement from the
source broker.
Target MQTT 5 negative PUBACK reasons are propagated to the source Session.
Message Expiry is never renewed: reconnect replay uses the target Session
store's remaining lifetime, while a fresh target Session receives a newly
published copy only if the source delivery still has time remaining. A target
QoS 1 PUBLISH still awaiting PUBACK is released from the target Session when
its Message Expiry Interval elapses, even if the target keeps the connection
open and never acknowledges; the bridge then completes the source with success
instead of waiting for an acknowledgement that can no longer arrive.
After QoS 1 target completion, one bounded in-memory fingerprint suppresses an
identical source DUP when its PUBACK was lost and rejects a changed retry; it is
retired on fresh source Session or legal non-DUP identifier reuse. This narrows
the live-process duplicate window for the intentionally at-least-once QoS 1
path. QoS 2 uses the durable coordinator described below instead.

The bridge serializes one source publication through the target acknowledgement
boundary and has no unbounded intermediate queue. While waiting for the target,
it alternates bounded polling of both reconnect clients so Keep Alive, AUTH,
disconnect, and retry traffic continue to make progress. A second QoS 1
delivery cannot be starved by an indivisible reconnect: an established
endpoint's short fairness turn reports transport loss without starting a TLS
handshake, the next disconnected-endpoint turn retains the caller's full
connection budget, and servicing the opposite endpoint remains capped at the
short fairness interval after that reconnect completes. A second QoS 1
delivery is left to the persistent source Session rather than copied into a
bridge queue. Topic Alias, Subscription
Identifier, DUP, and Packet Identifier are connection-scoped and never cross
the bridge; other MQTT 5 Application Message properties and the configurable
RETAIN bit do. The reconnect client now exposes a pre-wire QoS 1/2 primitive:
`stagePublish` owns the canonical message and stable Packet Identifier without
writing the transport, an online `writeSessionSnapshot` can then be included
in a caller's atomic record, and `flushPending` performs the first send with
DUP clear. Restoring that pre-wire snapshot conservatively sends the same
Packet Identifier with DUP set; `discardStagedPublish` can roll back only
before selection. Its opt-in deferred outbound QoS 2 release likewise surfaces
PUBREC after moving durable state to `await_pubcomp`, but holds PUBREL until a
snapshot succeeds and `flushPending` explicitly releases it. A reconnect in
the same process cannot bypass that gate; restoring the committed snapshot can
resume PUBREL directly. On the source side, `stageIncomingQoS2` records an
`await_pubrel` marker without writing PUBREC; it can be snapshotted with target
state or safely discarded until a PUBREC write begins.

The outbound bridge's optional `CoordinatorOptions` supplies the atomic
cross-broker boundary. It requires a stable 16-byte `bridge_id`, a journal
directory/path, and persistent source and target CONNECT settings.
`mode = .create` initializes the identity-bound journal; `mode = .restore`
validates the bridge ID, protocols, Client IDs, rules, prefixes, requested QoS,
and retain policy before restoring either Session. QoS 2 rules without this
coordinator, or with either transient Session, fail during construction.
Creating a coordinator can also attach to an existing persistent source
Session. Network and broker-local sources initialize their first nonzero
Session epoch before staging a transaction, and restored Sessions retain the
committed epoch. Real TCP cases cover the complete MQTT 3.1.1/5 source-target
matrix with fresh and preserved targets, stopping both before any transaction
is staged and before the first target wire write, then restoring through
source PUBCOMP without changing the Session epochs.
The two-Mosquitto gate separately seeds the source subscription, queues an
offline QoS 2 message, creates the coordinator on the preserved source Session,
and requires one target delivery and no second delivery after journal restore.

The coordinator stores one bounded transaction with both reconnect snapshots
and both Session epochs. It commits the source receive marker and target staged
PUBLISH before either acknowledgement or target write; after fsync, the target
PUBLISH may be sent. Target PUBREC is advanced durably to `await_pubcomp` before
PUBREL, and target PUBCOMP is committed as `target_complete` before source
PUBREC. When source PUBREL arrives, the source marker and coordinator
transaction are removed and fsynced before source PUBCOMP. A crash before the
first target write restores the same target Packet Identifier with DUP; a crash
after the durable PUBREC transition resumes at PUBREL without another target
PUBLISH; a crash after the final clear but before source PUBCOMP is resolved by
idempotently acknowledging the source's repeated PUBREL. A negative target
PUBREC is journaled and propagated as the source PUBREC reason without sending
target PUBREL. If an active transaction reconnects with Session Present false
on either leg, the bridge returns `SourceSessionLost` or `TargetSessionLost`
instead of creating a second target Application Message.
Coordinator recovery validates the saved transaction against both checkpoint
QoS Stores before applying wall-clock Session expiry. A valid pending
transaction whose source or target Session expired reports `SourceSessionLost`
or `TargetSessionLost` before opening a Network Connection; expired state does
not disguise a malformed transaction binding. Once the target's success or
rejection is durable, target Session loss no longer blocks upstream completion
and cannot cause a second target publication. A terminal transaction whose
source Session expired is retired in the journal before restore succeeds;
an injected retirement fsync failure propagates without reporting success,
and a fresh owner can retry without replaying the completed target.
Clock-controlled regressions cover both pending phases, both terminal results,
expiry on either or both endpoints, repeat restoration, and a valid-CRC record
with a mismatched source Packet Identifier. Real TCP verifies source completion
after target expiry; the two-Mosquitto gate independently expires one-second
source and target Sessions after a pre-wire crash and requires the corresponding
ownership-loss error without any target reconnect or replay.
Message Expiry during bridge downtime is handled independently of Session
expiry. A saved target PUBLISH still awaiting PUBREC is durably recorded as a
completed delivery when its message expires, so recovery can finish the source
handshake without replaying stale application bytes. A target transaction
already awaiting PUBCOMP remains at PUBREL even after Message Expiry. Live
coordinator commits use one expiry timestamp and retain PUBLISH ownership until
the coherent terminal record is synced; expiry encountered during replay is
reconciled before source acknowledgement. Real TCP and two-Mosquitto crash
cases cover expired PUBLISH suppression, source PUBREC/PUBCOMP completion and
accepted PUBREL-only recovery; clock-controlled cases verify repeat restoration,
all QoS 2 phases, unchanged corruption checks and failed-fsync retry.
Once target PUBREC or a terminal target outcome is durable, an otherwise identical source
retransmission may omit Message Expiry, matching Mosquitto's expired-message
retry. Targets still awaiting PUBREC require a nonincreasing expiry value;
changed payload, topic, Packet Identifier, retain flag or stable properties
remain invalid, and the accepted-transaction retry cannot create a new target delivery.

A bidirectional configured bridge uses one remote Session, with local-source
exclusion and MQTT 5 No Local or mandatory MQTT 3.1.1 private-bridge semantics
providing loop prevention. In-process wire tests cover MQTT
3.1.1/5 target reconnect with both resumed and fresh Sessions, both
cross-version directions, exact DUP/Packet Identifier behavior, ACK ordering,
property filtering, QoS 0, a normal two-Broker route, the QoS 2 durable
boundaries above, negative PUBREC, and both Session-loss failures. An idle
two-peer regression additionally advances both
one-second Keep Alive state machines through alternating `step` calls and
observes both PINGRESPs.
`zig build interop-mqtt-outbound-bridge-mosquitto -Doptimize=ReleaseFast`
adds an external process boundary: by default it validates and builds the
audited Mosquitto `5cd25465` checkout in a disposable directory, starts
independent source and target
Mosquitto brokers, and runs the netz bridge between them. A Mosquitto-generated
MQTT 3.1.1 source publication reaches an MQTT 5 target subscriber at QoS 0; the
reverse-version case uses QoS 1 plus RETAIN, checks the live delivery with
RETAIN cleared, then reconnects a new target subscriber and reads the retained
copy with RETAIN set. Four additional baseline cases cover the complete
MQTT 3.1.1/5 source-target protocol matrix at QoS 2 and complete handshakes on
the publisher-to-source-broker, source-broker-to-bridge,
bridge-to-target-broker, and target-broker-to-subscriber hops. The source
publisher's broker-local acknowledgement is deliberately
not presented as the bridge subscription ACK boundary; that ordering remains
covered by the controlled disconnect tests above. Every baseline case
verify the exact `local/sensors/room` to `remote/sensors/room` mapping and
payload. The runner stops the bridge through its own cancellation event and
requires a clean exit instead of treating process termination as success.
A fourth MQTT 5 case stops the target process after both Bridge Sessions are
established, then publishes a retained QoS 1 message into the live source. The
source Mosquitto log proves it has sent that delivery to the Bridge but has not
received the Bridge subscription's PUBACK while the target is absent. Starting
a new, empty target process causes the Bridge to republish from the still-owned
source delivery; the gate observes target receipt before the source PUBACK and
then reads the retained message through a newly connected target subscriber.
A fifth MQTT 5 case keeps the target broker Session alive behind a fault
proxy. The proxy forwards the first QoS 1 PUBLISH into Mosquitto, discards its
PUBACK, and closes only the Bridge-facing TCP connection. It verifies
Session Present on reconnect, then holds the retransmission until it has checked
the original Packet Identifier, `DUP=1`, QoS, RETAIN, topic, and payload. The
source Mosquitto still has no Bridge PUBACK at that point; forwarding the held
retry and target PUBACK completes both broker transactions and retained replay.
A sixth MQTT 5 case exercises the durable coordinator before its first target
wire boundary. A fault proxy accepts and drops the Bridge's initial QoS 2
PUBLISH, proving target Mosquitto has received none, then the runner kills the
Bridge. A new process opens the same journal and requires Session Present from
both brokers; it retransmits the same target Packet Identifier with `DUP=1`.
Only that replay reaches Mosquitto, and the target subscriber receives one
Application Message. A seventh case lets target Mosquitto accept one QoS 2
PUBLISH and PUBREL, then drops the returned PUBCOMP. After another process
restart, the proxy rejects any second PUBLISH, observes the same target Packet
Identifier resumed directly at PUBREL, and forwards PUBCOMP. Source Mosquitto
then records the Bridge's PUBREC/PUBCOMP completion; the target subscriber
receives no second Application Message. These cases cover the pre-target-wire
and `target_await_pubcomp` crash boundaries. An eighth case puts the fault
proxy on the source leg: after target completion it drops the Bridge's source
PUBCOMP, confirms source Mosquitto has not observed that acknowledgement, and
kills the Bridge after the journal clear. Restoring the now-empty coordinator
requires both Sessions, accepts source Mosquitto's repeated PUBREL, and returns
PUBCOMP without any second target PUBLISH or subscriber delivery. The
external gate also restarts each broker independently after a durable pre-wire
transaction. Losing the source Session makes the restored Bridge exit with
`SourceSessionLost` before it reconnects to the target; losing the target
Session makes it exit with `TargetSessionLost` immediately after the fresh
CONNACK and before any PUBLISH. A final MQTT 5 case gives target Mosquitto a
read-only ACL. Mosquitto receives exactly one bridge PUBLISH and returns
`PUBREC 0x87` (Not authorized); wire observers verify the Bridge sends no
target PUBREL, propagates the same negative PUBREC to the source Session, and
delivers no Application Message to the target subscriber. A clean restart from
the resulting empty journal produces no replay. This real-broker case also
guards the coordinator invariant that a terminal negative PUBREC removes target
inflight state before the `target_rejected` record is committed. The in-process
fault matrix continues to cover identity mismatch and malformed coordinator
state.

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
Mosquitto-style adapter maps `proxy_protocol_v2_require_tls` and
`require_certificate` to those transport checks. Its CN username mode accepts
the SSL TLV commonName only after verified connection/session certificate
evidence passes, then applies the normal MQTT UTF-8 and non-empty identity
checks before authorization. Full Subject mapping is unavailable because the
PROXY v2 SSL TLV supplies only CN. The broker's
transport-aware CONNECT authorization callback receives them together with the
effective source address and any directly verified mTLS certificate chain.
The same parser precedes MQTT TCP, TLS, WS, and WSS application handshakes; an
optional absolute header timeout prevents incomplete proxy prefaces from
holding listener workers indefinitely.
A source-locked production-process pair covers Mosquitto's
`21-proxy-v2-local.py` and `21-proxy-v2-lost-connection.py`. Netz intentionally
diverges from the former's close behavior: the PROXY v2 specification requires
`LOCAL` to be accepted while its forwarding address is ignored, so the exact
upstream header proceeds through CONNECT and PING using the real transport
peer. The truncated IPv4 case closes partway through its declared address
block; a subsequent valid proxied CONNECT/PING proves that EOF retires only
that peer and does not poison the finite production listener.

The selected Mosquitto-derived process gate enables a five-second CONNECT
deadline on every one of its finite broker processes, so all 294 curated raw
scenarios
also exercise the bounded admission path rather than merely proving the option
in an isolated unit test.
It also source-locks Mosquitto's `01-connect-uname-or-anon.py` Cartesian matrix:
all eight `allow_anonymous`/password-file/username combinations execute through
the production configuration runner under MQTT 3.1, MQTT 3.1.1, and MQTT 5.
The 24 real CONNECTs require successful named and anonymous admission when
allowed, legacy return code `0x05` or MQTT 5 reason `0x87` when denied, and a
live credentialless deny-all listener when anonymous admission is disabled
without a password file.
The companion source lock for
`01-connect-uname-password-denied-no-will.py` proves authorization precedes
duplicate-Client-ID takeover. Its strengthened production replay keeps an
independent observer connected while MQTT 3.1.1 and MQTT 5 attackers reuse a
live authenticated victim's Client ID with a wrong password. Each attacker
receives the version-correct refusal, both victims remain PING-responsive, and
the observer receives no victim Will.
Mosquitto's `09-pwfile-parse-invalid.py` parser-robustness source is also
locked. Netz additionally matches the upstream parser's zero-entry behavior:
an empty or comment-only configured password file is a valid generation rather
than a startup/reload error. A production SIGHUP replay atomically replaces a
populated file with an empty one, administratively disconnects the live named
user without publishing its Will, rejects subsequent MQTT 3.1.1/5 named
CONNECTs with their version-correct reasons, and keeps anonymous admission and
an existing anonymous observer usable.
The source-locked `09-acl-empty-file.py` CVE regression covers the corresponding
zero-rule authorization boundary. Empty/comment-only ACL files remain valid in
both global and `per_listener_settings` scopes: anonymous MQTT 3.1.1/5 clients
can CONNECT, SUBSCRIBE and PING, while QoS 1 publication receives the
version-correct result and no matching delivery escapes the default deny.
The same gate source-locks Mosquitto revision `5cd25465`'s
`01-connect-unix-socket.py` and runs its portable wire behavior through the
production config example: `listener 0 PATH` deep-owns one raw Unix-domain
endpoint, accepts an MQTT 3.1.1 CONNECT, returns the exact successful CONNACK,
and removes the filesystem socket after normal broker teardown. Unix listeners
share authentication, ACL, mount-point, admission, and capacity policy with IP
listeners. A high-bit-plus-config-index listener identity keeps retained-source
authorization distinct from every 16-bit TCP port, while reload requires the
same owned path. TLS, WebSocket, PROXY, `socket_domain`, and `bind_interface`
combinations fail before any endpoint is opened rather than being ignored.
The retained-source matrix persists and restarts the standalone broker after
storing a retained PUBLISH. It source-locks the basic MQTT 3.1.1/5 retained
restart shapes in Mosquitto's `15-persist-retain-v3-1-1.py` and
`15-persist-retain-v5-0.py`, then strengthens them by locking the ACL-reload
wire boundary in
Mosquitto's `04-retain-check-source.py`, its CVE-2018-12546
`04-retain-check-source-persist.py`, and the cross-listener
`04-retain-check-source-persist-diff-port.py` regressions. MQTT 3.1.1 and MQTT
5 each cover global and per-listener ACLs with both anonymous and named source
identities. The default `check_retain_source` path rechecks the deep-owned
original identity and stable source-listener ID against current write policy,
then suppresses replay after revocation; `--no-check-retain-source`
demonstrates the explicit compatibility opt-out.

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

