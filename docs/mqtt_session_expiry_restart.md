# MQTT persistent Session expiry restart parity

`interop-mqtt-session-expiry-restart` runs all five active variants from the
source-locked Mosquitto `15-persist-client-expired-session.py` through netz's
configured production broker. It keeps the 100-message queue, exact payloads,
20-message shared tail, 30-publication retained prefix, and both replacement
subscription choices. A sixth scenario combines 40 shared messages and the
retained prefix with QoS 2. The upstream commented-out combined cases are not
counted as completed upstream variants.

| Scenario | Resubscribe | Shared tail | Retained prefix | QoS |
| --- | --- | --- | --- | --- |
| Queue | No | 0 | 0 | 1 |
| Queue and replacement subscription | Yes | 0 | 0 | 1 |
| Shared queue | No | 20 | 0 | 1 |
| Shared queue and replacement subscription | Yes | 20 | 0 | 1 |
| Retained queue | No | 0 | 30 | 1 |
| Supplemental shared retained queue | No | 40 | 30 | 2 |

Each scenario completes four process generations:

1. Establish persistent subscriptions, disconnect their consumers, and publish
   100 exact messages. The second subscriber joins at the original tail
   boundary. Retained replay at that SUBSCRIBE is acknowledged separately.
   A successful process exit creates the first coherent snapshot.
2. Restore the expiring subscriber with Session Present, verify five distinct
   initial deliveries, and leave them unacknowledged. Send MQTT 5 DISCONNECT
   with Session Expiry 1, observe transport EOF, and save another snapshot.
   This uses the public protocol's expiry update in place of the upstream
   test's private database timestamp edit. Wait at least 1.2 seconds after
   process exit, so expiration occurs during broker downtime.
3. Restore the expired subscriber with Session Present false. PING before any
   SUBSCRIBE proves its old queue is absent; optional resubscription gets no
   old delivery. The surviving sibling receives its exact tail, and a fresh
   retained probe receives the final retained payload with RETAIN set. All
   acknowledgements complete before another snapshot is saved.
4. Restore again to prove deletion and completion were durable. PING rejects
   revived queued messages. A new non-retained publication routes according
   to the replacement-subscription choice; the sibling's existing subscription
   still receives it. A second retained probe receives the same retained
   payload. Explicit zero-expiry disconnects remove the persistent consumers.

Every expected PUBLISH checks the complete Topic Name, payload, QoS, RETAIN,
DUP, non-zero Packet Identifier and empty MQTT 5 property section. QoS 2
consumption permits PUBLISH/PUBREL interleaving while rejecting unknown,
repeated or malformed releases. PINGRESP barriers reject extra application
messages and incomplete QoS handshakes; EOF cannot satisfy a barrier. Source
acknowledgements distinguish a routed publication from MQTT 5's
No Matching Subscribers result. The standalone oracle tests mutate wire
flags, topics, payloads, identifiers and release packets, and challenge both
late PUBLISH and EOF on an empty expected queue.

Run:

```sh
zig build interop-mqtt-session-expiry-restart -Doptimize=ReleaseFast --summary all -- --mosquitto-test-root="$HOME/Work/mosquitto/test"
```

This also runs in the default configured-broker gate. Source verification
precedes broker startup; the process source catalog now locks 37 files.
The focused target additionally runs its packet-oracle tests. The existing
commit-log Session test checks autonomous live expiry followed by SIGKILL;
this matrix checks snapshot downtime expiry with shared queue ownership,
retained data and replacement subscriptions.

[The six completed process records](evidence/mqtt_session_expiry_restart/2026-10-28.json)
include source fingerprints, gate-input hashes and elapsed times. Current netz
runtime behavior passed the matrix. This work adds independent production
regression coverage and makes no new throughput or broad superiority claim.
