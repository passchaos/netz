# MQTT live integration checks

[Back to the rumqtt parity index](../rumqtt_parity.md).

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

