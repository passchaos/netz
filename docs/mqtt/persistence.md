# MQTT persistence, retained state, and Will scheduling

[Back to the rumqtt parity index](../rumqtt_parity.md).

## Atomic broker snapshots

The live broker now follows the durability shape audited in Mosquitto
`persist_write.c` and `mosquitto_write_file`: serialize a coherent in-memory
view, write a restricted temporary file, `fsync` it, then atomically replace
the destination. Netz additionally syncs the containing directory after the
rename on supported POSIX targets, so a successful checkpoint also makes its
new directory entry crash-durable rather than only its file contents. Directory
sync failures propagate after the atomic replacement and do not falsely
acknowledge a durable generation. Netz uses Zig 0.16 `std.Io.File.Atomic` rather
than hand-written temporary-name logic.

The versioned binary format has whole-file and per-section CRC32 checks and
persists:

- unexpired retained messages, forwarding properties, publisher identity,
  source username, and stable source-listener identity,
- durable ClientID Session metadata and stable router identity,
- complete subscription options and Subscription Identifier,
- offline queued QoS 1/2 messages and opt-in queued QoS 0 messages,
- outgoing inflight QoS 1/2 state, Packet Identifier and PUBREL continuation,
- scheduled Wills with ClientID, source username/listener identity, full
  Application Message properties, canonical publisher identity and exact
  remaining delay,
- inbound QoS 2 Application Message bodies and source identity awaiting PUBREL,
  keyed by stable Session route identity rather than a short-lived connection
  slot,
- staged inbound bridge QoS 2 messages and released tombstones, keyed by a
  stable bridge identity, upstream Session epoch, and Packet Identifier.

Adding the bridge transaction section advanced the on-disk snapshot version
from 4 to 5; persisting the bridge Session epoch independently of active
transactions advances it to 6. Restore deliberately rejects older versions
rather than guessing at absent transaction state. Persisting the complete
retained-source ACL identity advances it to 7 for the same fail-closed reason;
deployments carrying a version-4/5/6 snapshot or commit log must migrate or
start from a fresh state file before upgrading.

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
routing. A source-hash-locked production-process port of Mosquitto
`15-persist-publish-properties-v5-0.py` now preserves Payload Format, Content
Type, Response Topic, binary Correlation Data, four ordered User Properties,
and decreasing Message Expiry through two snapshot/restart generations. Exact
PUBLISH comparison proves both property order and deep ownership across the
restore-save-restore boundary, while an inbound Topic Alias is correctly
removed as connection-scoped state before either snapshot replay.
The source-locked bounded port of Mosquitto
`15-persist-client-drop-expired-messages.py` gives two durable Sessions four
shared QoS 1 publications, with the final two also retained, then lets every
Message Expiry interval elapse while the broker is stopped. Both Sessions
retain Session Present and their subscriptions, but reconnect PING barriers,
one replacement SUBSCRIBE, and an independent wildcard retained probe observe
no PUBLISH. A second snapshot/restart repeats all three empty barriers, proving
restore-time queue and retained cleanup is itself durable rather than only a
lazy in-memory filter.
The source-locked `15-persist-client-v5-0.py` companion deliberately treats
Maximum Packet Size as MQTT 5 connection state rather than copying
Mosquitto's persisted database field. A Session first advertises a 40-byte
limit and queues a larger PUBLISH before snapshot. Reconnecting after restart
with a 256-byte limit receives and acknowledges that message, proving the old
connection's limit did not leak. A second oversized offline PUBLISH is then
discarded under a new 40-byte reconnect; another snapshot and 256-byte
reconnect remain empty, proving the current-connection decision was durably
retired without poisoning Session Present or its subscription.
A source-locked extension of
`15-persist-client-msg-out-dup-v3-1-1.py` runs the complete outgoing QoS 2
snapshot state machine for MQTT 3.1.1 and MQTT 5. The first restored delivery
uses Packet Identifier 1 without DUP; an abrupt reconnect retransmits that
identifier with DUP, and another broker generation does the same. After PUBREC
is persisted, the following generation resumes directly at PUBREL instead of
replaying the Application Message. PUBCOMP plus a PING barrier is snapshotted,
and a fifth generation proves the completed transaction cannot revive.
The source-locked `15-persist-client-v3-1-1.py`,
`15-persist-client-msg-out-v3-1-1.py`,
`15-persist-client-msg-out-queue-v3-1-1.py`, and
`15-persist-client-msg-out-clear-v3-1-1.py` production path now runs in MQTT
3.1.1 and MQTT 5. An initial broker snapshots three durable
subscriptions plus offline QoS 1/2 deliveries; the restored broker emits both
messages without acknowledgement, then Clean Start atomically removes the
subscriptions and restored outgoing inflight state. A third broker requires
Session Present false, no stale delivery, and a no-subscriber publication
result, proving the cleanup itself survived another snapshot/restart.
SUBSCRIBE filter updates now commit the durable Session policy and router
index together under the broker state lock. Previously, a route-allocation
failure could occur after `Store.setSubscription` had accepted a new filter,
leaving an offline persistent Session with an unindexed subscription. The
inline `Router.PreparedSubscription` prepares a reversible route without an
extra transaction-record allocation; `broker/subscription_change.zig` then
updates Session storage and commits only after both succeed. Session allocation
or byte-limit failures restore the prepared route, while a per-Session count
refusal is checked before route allocation so one packet can still report
independent successes and quota results. Existing filters remain replaceable
at the cap. Rollback preserves old QoS, No Local and Subscription Identifier
policy without allocating. A real broker regression runs MQTT 3.1, 3.1.1 and
5 through a failed new-filter allocation and verifies the previously accepted
subscription still queues offline traffic. The targeted subscription/router/
retained/Session Debug and ReleaseFast gates pass 130/130 tests each;
public-module checks pass 2/2.

Source-locked ports of `15-persist-subscription-v3-1-1.py` and
`15-persist-subscription-v5-0.py` add a separate three-generation subscription
path. QoS 0/1/2 grants restore with exact live delivery, MQTT 5 preserves
Subscription Identifiers 100/101/102, and the second generation removes the
QoS 2 filter. The third generation routes only QoS 0/1, returns MQTT 5 No
matching subscribers for the removed topic, and answers PING before any stale
delivery, proving the UNSUBSCRIBE tombstone survived another snapshot.
Four additional source-locked process ports cover
`11-persistent-subscription.py`, `11-persistent-subscription-no-local.py`,
`11-subscription-id.py`, and `02-subscribe-persistence-flipflop.py`. The focused
`--only-subscription-lifecycle` gate runs three real broker generations for each
of MQTT 3.1.1 and MQTT 5. A persistent subscriber receives its own ordinary
publication before and after restart; MQTT 5's No Local filter excludes self
publications while accepting another client's publication. Transport EOF is
observed after DISCONNECT before the helper publishes, so the next snapshot
contains provably unsent offline deliveries. Reconnect receives those messages
without a new SUBSCRIBE and with exact Subscription Identifiers 53/54. A
persistent/clean-transient/fresh-persistent sequence then leaves exactly one
subscription owner, using the two-byte identifier 131 on MQTT 5. The third
broker restores only this new subscription: no duplicate old owner or removed
No Local filter can reappear. PING barriers verify absence of extra messages
and completion of acknowledgements without sleep-based delivery assumptions.
The scenario lives under `tools/interop/mqtt_scenarios/` rather than expanding
the config runner's monolithic scenario bodies. Independent wire-image tests
reject wrong DUP/QoS flags, zero Packet Identifiers, changed Subscription
Identifiers/payloads, error PUBACKs, and mismatched acknowledgement identifiers.
The ReleaseSafe process gate passes all six broker generations, and the helper
and source-lock checker suites pass 8/8 and 6/6 tests respectively. It is also
included in the ordinary `interop-mqtt-broker-config` gate. Run just this scope
with:

```sh
zig build interop-mqtt-broker-config -Doptimize=ReleaseSafe -- \
  --only-subscription-lifecycle \
  --mosquitto-test-root ~/Work/mosquitto/test
```
Scheduled-Will tests cover downtime deadline reduction, canonical publisher
restoration, reconnect cancellation, driver publication after an actual broker
restart and retained-Will storage. This snapshot surface still has narrower
persistence-plugin integration than Mosquitto, but supports both
elapsed-time and persistent-change-count live autosave. An
`autosave_interval` of zero disables either runtime trigger, matching
Mosquitto, without disabling startup restore or the final shutdown snapshot.
Mosquitto's `retained_persistence` alias feeds the same owned persistence
policy and shares duplicate-directive rejection with `persistence`; the
connection-scoped Maximum Packet Size restore gate exercises that alias across
four broker generations.
Linux SIGHUP can atomically switch that policy among elapsed-time,
persistent-change-count, and disabled modes while retaining the original
snapshot target. A fixed management tick applies the new interval before its
next due check; change-count enablement services any durable debt since the
last snapshot, while periodic/manual writes acknowledge the same generation so
switching modes cannot duplicate an already persisted checkpoint. Changing
`persistence`, `persistence_location`, or `persistence_file` remains a
restart-only operation and fails the complete reload transaction.
Broker-initiated shutdown also detaches every still-connected durable Session
before the final snapshot, arming its expiry deadline from shutdown time rather
than restoring it indefinitely connected. A Mosquitto-issue-derived regression
keeps a subscribed MQTT 5 Session live, shuts down the broker without a client
DISCONNECT, snapshots the resulting offline state, restores it, and proves a
future lookup beyond the 60-second interval removes the Session.
On Linux the production config runner also maps `SIGUSR1` to an on-demand live
checkpoint. Its signal handler performs only a lock-free atomic flag store; a
bounded `std.Io` supervisor poll consumes the request and runs normal locked,
atomic-replacement persistence. The process gate verifies this for both
`autosave_on_changes` modes by proving no snapshot exists after a retained-
PUBLISH/PING barrier, requesting a checkpoint, killing the broker without its
shutdown save, then restarting from that signal-created snapshot and reading
the exact retained message. Tests also cover
inbound QoS 2 body ownership, downtime expiry, Clean Start cleanup, real broker
restart, Session Present, post-restart PUBREL routing and duplicate PUBREL
idempotence.

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
temporary file has been synced, then syncs the parent directory before
reporting success; append automatically takes this path before a configured
journal-size bound would be exceeded. The initial journal creation follows the
same file-sync, rename, and directory-sync sequence.

The [delivery and disconnect rules](../mqtt_delivery_and_disconnect.md) preserve
per-filter Subscription Identifier multiplicity and place successful normal
DISCONNECT/Will cancellation before physical shutdown. They also describe the
explicit sync-failure result and writer-quiescence boundary.

When `--commit-log=PATH` is enabled in the production example, the broker records
successful protocol-visible durable decisions before CONNACK, SUBACK, UNSUBACK,
PUBACK/PUBREC/PUBCOMP, durable outgoing delivery, disconnect/Will scheduling,
Will publication, and Session expiry can be observed by a peer. This first
version intentionally journals complete state images so every private store is
covered uniformly; compact typed delta records and group commit are performance
work, not missing recovery semantics. The `interop-mqtt-commit-log` build step
creates a durable subscription, receives PUBACK for an offline queued message,
immediately kills the broker without any periodic or shutdown snapshot, and
requires Session Present plus the exact delivery after restart. That
source-hash-locked process flow now mirrors Mosquitto's
`11-subscription-id.py`: the durable subscription carries identifier 53, and
the recovered queued PUBLISH must reproduce that exact property after SIGKILL.
The same crash/restart sequence is source-locked to Mosquitto's
`11-message-expiry.py`: a five-second delivery expires during downtime, a
100-second delivery survives with a strictly reduced interval, and a third
delivery without an expiry remains intact; both surviving messages retain
Subscription Identifier 53 and their original order.
The broker-to-client QoS 1 inflight path strengthens Mosquitto's
`03-publish-b2c-disconnect-qos1.py` for both MQTT 3.1.1 and MQTT 5 with real
process loss. After the first unacknowledged PUBLISH is durably selected, the
broker is killed; the next generation must preserve its Packet Identifier and
payload while setting DUP. PUBACK completion is then journaled before a second
kill, and a third generation's PING barrier proves the completed transaction
cannot reappear.
The outgoing QoS 2 path is independently source-locked to Mosquitto's
`15-persist-client-msg-out-v5-0.py` and uses three broker generations. The
first is killed after the durable subscriber has accepted its PUBLISH and the
broker has emitted PUBREL. The second must resume directly at PUBREL with the
original Packet Identifier, never retransmit the Application Message, and is
killed after PUBCOMP has crossed a PING barrier. The third reconnect then uses
another PING barrier to prove the completed transaction was durably removed.
The inverse QoS 2 direction strengthens Mosquitto's
`03-publish-c2b-disconnect-qos2.py` for MQTT 3.1.1 and MQTT 5. A persistent
publisher reaches the durable PUBREC boundary and the broker is killed before
PUBREL. After restart, a same-identifier DUP PUBLISH receives PUBREC without
early fanout; PUBREL then routes the original Application Message exactly once
and receives PUBCOMP. After the observer acknowledges that delivery and the
broker is killed again, a third generation answers a repeated PUBREL
idempotently while a PING barrier on the observer proves there is no duplicate
delivery.
An independent source-hash-locked branch mirrors Mosquitto's
`04-retain-check-source-persist.py`: it commits a retained publication, kills
the broker, clones that journal into isolated policy runs, and proves the
restored publisher identity suppresses replay after write access is revoked.
Disabling `check_retain_source` on the second clone must expose the exact
retained PUBLISH, proving that denial did not merely delete the stored value.
The retained mutation path also strengthens Mosquitto's
`15-persist-retain-clear.py` for MQTT 3.1.1 and MQTT 5. Two retained sibling
messages first survive a process kill. After restart, an empty retained
PUBLISH clears only one topic and is observed live with RETAIN unset; the
broker is killed immediately after the journal boundary. A third generation
must replay the untouched sibling and then answer PING without resurrecting
the deleted value, distinguishing durable deletion from loss of the complete
retained store.
The active Session deadline path is source-locked to Mosquitto's
`15-persist-client-expired-session.py`. A two-second MQTT 5 Session first owns
a subscription and a verified unacknowledged queued delivery, while an
unrelated long-lived Session remains as a recovery control. With no later
durable client operation, the deadline driver removes the expired Session, its
route, and its inflight message and appends that deletion. An immediate
`SIGKILL` followed by restart preserves the control Session but returns
Session Present false for the expired ClientID; PING barriers before and after
a new publication prove neither its old queue nor subscription was revived.
The commit-log gate also covers the persistent delayed-Will branch from
Mosquitto's `15-persist-client-will-persistent.py`: after the disconnect that
schedules the retained QoS 1 Will is durably committed, the broker is killed
before its deadline. On restart the restored observer receives the Will once
at the remaining deadline, and a fresh subscriber then receives the retained
copy with the correct RETAIN bit.
A source-locked clean-Session companion ports the crash branch of Mosquitto's
`15-persist-client-will-clean.py`. A QoS 1 retained Will carries Payload
Format, Content Type, User Property and a 30-second Will Delay, but its Session
Expiry is zero. SIGKILL leaves the CONNECT commit as the last durable boundary;
restart therefore publishes the Will immediately, preserves all application
properties while removing Will Delay, delivers RETAIN=false to an existing
subscription, and stores a RETAIN=true replay. A third broker generation
answers the original subscriber's PING without publishing the Will again.
The matching negative branch sends a normal DISCONNECT from the same
clean-Session, delayed retained QoS 1 shape, waits for its cancellation commit,
and kills the broker immediately. After restart both the existing subscriber
and a fresh retained replay subscription receive PINGRESP directly, proving
that neither a live nor retained Will escaped and that cancellation did not
depend on later socket cleanup.
The complementary cancellation path is source-locked to Mosquitto's
`07-will-delay-reconnect.py` and adds a process-crash boundary after
cancellation. A persistent client schedules a three-second Will, reconnects
with the same Client ID before the deadline, and requires Session Present.
After the resulting cancellation grows the journal, the broker is killed
immediately. A persistent observer must report Session Present after restart;
once the old deadline has passed, an ordered PINGRESP proves the canceled Will
was not resurrected by replay. Only after that barrier does the source
reconnect and require Session Present, so its reconnect cannot mask a restored
Will by canceling it again.
Unit coverage
additionally verifies multi-generation replay, atomic compaction, torn-tail
truncation, committed corruption rejection, and transactional broker-state
preservation when the newest image cannot decode.
Run the process gate with its upstream identity check enabled using:

```sh
zig build interop-mqtt-commit-log -Doptimize=ReleaseFast -- \
  --mosquitto-test-root=/path/to/mosquitto/test
```

Journal and change-count autosave are independent durability backends. Every
recorded durable boundary attempts an eligible autosave even when journal
encoding, append, or fsync fails, while still returning the journal error before
the corresponding protocol acknowledgement becomes visible. Normal MQTT 5
DISCONNECT persists Will cancellation/scheduling and Session Expiry overrides at
that boundary rather than relying on later socket cleanup. Registration errors
also journal durable cleanup already performed by expiry or Clean Start. A due
Will is retried only while no publication effect escaped; once retained or
durable Session state changes, the Will is consumed and that partial prefix is
persisted, preventing duplicate delivery on a later deadline pass. Focused
tests cover journal-failure autosave fallback, graceful Session removal
recovery, failed Clean Start cleanup, and post-mutation Will failure handling.

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

The benchmark clock is provided by zio-backed `std.Io`; the 2026-08-19 values
below predate that migration and remain historical Threaded evidence.

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

The benchmark clock is provided by zio-backed `std.Io`; the 2026-08-18 values
below predate that migration and remain historical Threaded evidence.

2026-08-18 same-host `ReleaseFast` result with 4,096 Sessions:

```text
resume:                    44 ns/op
offline queue:            169 ns/message
reconnect drain (4 msgs): 494 ns/session
```

The benchmark measures in-memory state operations and does not include socket
or disk I/O.

## Will Delay scheduler

Session Store replacement prepares the new owned ClientID, slot, and indexes
through `prepareOpen` before retiring the prior Session; `commitOpen` applies
the generation, lifetime, route, and retransmission changes without allocation.
Dropping the preparation preserves old state and releases any reserved empty
slot. Clean Start, transient takeover, and expired
Session replacement use the final Session count and byte total for admission,
including credit for the state being replaced. An allocation or limit failure
therefore preserves the old handle, subscriptions, queued/inflight QoS state,
and accounting. Borrowed ClientID input is copied before its Session storage
is retired. Successful replacement invalidates the old generation and installs
a new route identity; the broker records that durable transition only after
Session admission commits. Fault injection and final-budget replacement cases
cover connected, offline, transient, and expired lifetimes.

Resumed CONNECT also prepares subscription routing before Session generation,
expiry, retransmission state, or owner changes. `Router.beginSubscriptionBatch`
reserves a bounded rollback journal, preserves prior delivery policies and
subscription identifiers, and can rebuild missing ordinary/shared routes.
Commit and rollback allocate nothing; aborted preparation removes only its
new entries, restores existing metadata, and preserves shared-group selection
state. Existing stable Session routes are reused rather than re-indexed.
Clean Start and transient takeover skip restoration of state that cannot be
continued. Real TCP fault injection for MQTT 3.1/3.1.1/5 covers subscription
copy and batch journal reservation failures, including a replacement requesting
Session Expiry zero: the original handle, owner, Will, expiry, and in-flight
window remain valid, and the old client can acknowledge then receive fresh
traffic. A successful-resume case proves missing normal/shared route rebuild,
subscription identifiers, No Local, and Retain As Published.
The focused Router, Session, Will, broker admission/lifecycle, and persistence
gate passes 254/254 tests in Debug and ReleaseFast; public-module package
checks pass 2/2.

The broker reserves stable `runtime.Connection` storage after CONNECT policy
checks and before Session/Will/router admission. Allocation failure therefore
cannot advance an existing Session generation, detach its live owner, cancel
its Will, or apply Clean Start. Completed negotiation moves the accepted
transport into that reservation, then transfers ownership to the attached
client slot; failures and quota refusals release unused storage. This remains
per-CONNECT allocation rather than preallocation for every capacity slot.
TCP fault injection covers MQTT 3.1/3.1.1/5 with both continued and Clean Start
replacement, including acknowledgement of the prior in-flight publication and
continued delivery. Authorization refusal precedes this allocation, and Session
quota refusal still sends the expected CONNACK while cleaning the reservation.
The focused lifecycle, routing, admission, listener/deadline, protocol, and
persistence gate passes 306/306 tests in Debug and ReleaseFast; public-module
package checks pass 2/2.

Successful CONNECT responses are also prepared before the Session commit.
`PendingAcceptedClient.prepareFinish` owns the exact CONNACK bytes and scalar
negotiation for the prospective Session Present and assigned ClientID. Property
validation, response allocation, and peer Maximum Packet Size checks therefore
finish before takeover. CONNECT policy completion and the final prepared
admission both recheck the original absolute deadline; timeout/deadline variants
retain its earlier bound. `finishPrepared` writes those prepared bytes and
applies negotiated aliases, limits, capabilities, Keep Alive, and authentication
only after successful transmission. Existing synchronous finish APIs use the
same path. Known preparation failures preserve the old Session/owner/Will and
in-flight acknowledgement capability for continued and Clean Start connects.
Network or journal failures after the actual Session commit still follow the
documented provisional rollback/persistence boundary. Tests cover abort and
allocation-free commit, copied response properties, exact versus one-byte-short
packet limits, and rejected oversized, expired, or allocation-failed responses.
Synchronous CONNACK writes continue to borrow and return the connection's
existing control-packet scratch buffer, retaining allocation-free writes after
warm-up; independently prepared acceptance responses keep their own bytes.
The focused runtime, Session/Will/router, broker admission/lifecycle, listener,
protocol, deadline, and persistence gate passes 546/546 tests in Debug and
ReleaseFast; public-module package checks pass 2/2.

Broker CONNECT admission now prepares the Will before Session replacement and
old-owner detachment. `prepareConnectWithSource` owns the new message and
reserves scheduler capacity without changing the prior Will; `commitConnect`
applies reconnect semantics without allocation under the same broker state
lock. Session preparation failure drops that temporary Will. Will validation,
allocation, count, and byte-limit failures therefore preserve the prior
Session, subscription routes, live owner, Will, and publisher association.
Will quota rejection sends CONNACK 0x97 for MQTT 5 and 0x03 for MQTT 3.1/3.1.1.
TCP regressions exercise all three protocol versions and both Clean Start
values, verify continued message delivery, and inject Will-copy, scheduler-index,
and Session-preparation allocation failures. Scheduler fault injection also
covers every preparation allocation, unchanged delayed-Will deadlines on abort,
owned source/property data, and allocation-free commit. This ordering follows
Mosquitto's `will__read` before `connect__on_authorised` takeover. Journal
regressions distinguish rejected preparation from an already-committed
replacement whose provisional connection is later aborted.

CONNECT rollback also closes the persistence visibility boundary before its
caller releases the reserved slot. A fully cleaned aborted registration can
be checkpointed while that slot remains unavailable for reuse; another CONNECT
still in progress continues to cause `SnapshotBusy`. Failed CONNACK writes and
failed provisional journal syncs append the corrected image, including when
rollback removes only newly provisional state and leaves no net durable
change. If another admission or a journal I/O failure prevents the correction,
the broker retains pending journal work under its persistence mutex and retries
it when a connection attaches or a claimed slot is released. A successful
final append clears that pending work; provisional appends cannot do so.
Autosave still runs independently after journal failure and retries when an
admission settles. Real TCP and injected sync failures cover fresh Sessions,
committed Clean Start replacement, resumed subscription/queue preservation,
and a parked concurrent CONNECT. Journal and atomic-snapshot restart images
must both match the fully rolled-back state without reviving a rejected Will.
A socket-close gate inspects corrected journal and snapshot images while the
aborted slot is still reserved, before the admission caller can release it.

The combined Session, Will, broker admission/lifecycle/listener, and persistence
gate passes 313/313 tests in Debug and ReleaseFast. The rollback, reserved-slot,
and provisional-snapshot gate checks that close boundary and passes 79/79 in both modes;
the public-module package check passes 2/2.

`mqtt.will_scheduler.Scheduler` deep-owns the Will Message and MQTT 5 Will
Properties, indexes entries by ClientID, and orders deadlines with an indexed
binary min-heap. Accepted CONNECT reserves heap capacity so subsequent network
close/reconnect/Session-end transitions do not allocate.

Will checkpoint decoding treats an omitted Will Delay as its MQTT default of
zero, matching entry admission and the reference broker's immediate-Will
behavior. It retains the original property list: an omitted delay stays absent,
and absent Message Expiry remains distinct from an explicit zero expiry.
Consistent previously written records need no format migration. The separate
Will snapshot codec still rejects mismatches between properties and redundant
delay/expiry fields, and remaining delay beyond the Session/Will bound.
Scheduled and live checkpoint cases cover absent, zero, and positive properties;
TCP restart cases cover MQTT 3.1, 3.1.1, and 5 through both snapshot and journal,
recover the immediate Will once, and preserve its retained message.
The focused Will lifecycle, broker Will/restart/persistence, and CONNECT
rollback gate passes 149/149 tests in Debug and ReleaseFast; the public-module
package check passes 2/2.

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

The benchmark clock is provided by zio-backed `std.Io`; the 2026-08-18 values
below predate that migration and remain historical Threaded evidence.

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

