# MQTT remaining work

[Back to the rumqtt parity index](../rumqtt_parity.md).

## Remaining work before broad superiority

Automatic Keep Alive output from the reconnecting client's bounded poll now
uses that poll's original deadline. Expired polls return before sending a probe
or retiring a still-live transport, and blocked PINGREQ writes retire only the
current Network Connection while preserving owned QoS messages for reconnect.
PING response timing starts after the full request write succeeds. Public split
PINGREQ/PINGRESP writers expose timeout and deadline forms through
`runtime/ping.zig`, retaining packet-direction checks and shared transport
retirement on ambiguous output. Real TCP blocked-write tests cover MQTT 3.1,
3.1.1 and 5, both budget forms, server/client output, and pending QoS ownership.

The shared `fuzz-parsers` target dispatches every bounded input through the
MQTT Fixed Header and MQTT 3.1/3.1.1/5 CONNECT, CONNACK, PUBLISH, ACK,
SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, DISCONNECT and AUTH parsers. Default
tests replay valid and malformed seeds plus deterministic truncation/bit-flip/
random mutations with leak checks; Zig's `--fuzz` mode adds coverage guidance.
The companion `fuzz-stateful` target interleaves bounded Session open/takeover,
disconnect/expiry, subscription, queued and immediate publication, outgoing
QoS 1/2 acknowledgement, incoming QoS 2, and snapshot round-trip operations.
The separate `fuzz-mqtt-live-broker` target starts the production TCP broker,
one publisher and two subscribers for each bounded input. An independent model
checks ordered exact-topic SUBSCRIBE/UNSUBSCRIBE, live QoS 0 publication,
retained write/replacement/deletion and Retain Handling 0 replay. Explicit
PINGREQ/PINGRESP barriers prove each expected queue is complete without timing
sleeps, including a final empty barrier that rejects delayed extra delivery.
A fresh 2026-11-01 run passed the live broker and TLS live broker gates at
3/3 each; see `docs/evidence/live_fuzz/2026-11-01.json`.
`fuzz-mqtt-tls-live-broker` reuses that exact state oracle with the production
heterogeneous-listener broker path and three certificate-pinned native TLS 1.3
clients. It requires `mqtt` ALPN, AES-128-GCM/SHA-256 metadata, and one
reciprocal KeyUpdate per connection before subscriptions, retained mutations,
delivery ordering, and PING barriers proceed.
`fuzz-mqtt-reconnect` separately drives the production reconnect Client against
a scripted real TCP peer across one bounded operation history. It checks QoS 1
and QoS 2 success, lost-PUBACK/PUBREC PUBLISH replay with a stable Packet
Identifier and DUP, lost-PUBCOMP PUBREL-only replay, fresh-Session transaction
discard, preserved-Session resume, and ordered accepted-subscription replay.
`fuzz-mqtt-tls-reconnect` reuses the same peer and state oracle through the
native TLS reconnect connector. Every initial or replacement connection is
certificate-pinned and must report `mqtt` ALPN plus AES-128-GCM/SHA-256 before
QoS replay or subscription recovery can proceed.
Subscription recovery now records the successfully acknowledged prefix while
replaying a fresh broker Session. A refused SUBACK, timeout, or transport loss
keeps the unconfirmed suffix pending. If the next MQTT 3.1.1/5 CONNACK preserves
that partially restored Session, only the suffix is replayed; a fresh Session
restarts all desired filters. The original subscription options, Subscription
Identifier and User Properties remain owned for retries, and filters seeded
while recovery is pending join its suffix. An interleaved PUBLISH remains
available through the normal event poll. Real TCP regressions cover seeded and
previously accepted filters, repeated refusals, lost Sessions, timeout and
transport loss, then prove a later fully restored Session receives no redundant
SUBSCRIBE. MQTT 3.1 continues restoring all filters because its CONNACK has no
Session Present flag.
`fuzz-mqtt-wss-reconnect` adds HTTP/1 Upgrade, WebSocket framing/masking, and
MQTT byte-stream reassembly to the same recovery schedule. Its vail-backed WSS
connections must report `http/1.1` ALPN, AES-128-GCM/SHA-256, and the pinned
server certificate on every replacement transport.
`fuzz-mqtt-bridge` then composes a scripted upstream TCP peer, production
inbound Bridge, local production broker, live subscriber and retained-state
probe. Its model checks QoS 0/1 topic mapping, acknowledgement ordering,
retained replacement/deletion, fresh/resumed upstream Sessions, ordered bridge
subscription replay, DUP normalization, User Property preservation, and the
non-transfer of upstream Topic Alias/Subscription Identifier state.
`fuzz-mqtt-tls-bridge` runs that complete model through a certificate-pinned
native TLS connector and validates `mqtt` ALPN plus AES-128-GCM/SHA-256 after
every upstream reconnect before routing continues. Durable QoS 2 has its own
`fuzz-mqtt-bridge-qos2` target: every real upstream
transaction is durably staged before PUBREC, remains invisible locally before
PUBREL, then either completes exactly once, resumes after transport loss, is
restored by a newly constructed Bridge, or is discarded when CONNACK reports a
fresh Session and advances the bridge epoch. The same model checks downstream
QoS 2 completion, DUP normalization, property isolation, and final retained
replay. `fuzz-mqtt-outbound-bridge` covers the non-coordinated cross-broker
path with independent real source and target TCP peers: QoS 0/1 mapping, target
delivery before source PUBACK, retained propagation, target retransmission
under preserved/fresh Sessions, source Session transitions, subscription
replay, DUP normalization, and connection-scoped property isolation.
`fuzz-mqtt-tls-bridge-qos2` carries the durable inbound QoS 2 state machine
through a certificate-pinned native TLS upstream and verifies the selected
certificate, `mqtt` ALPN, AES-128-GCM, and SHA-256 transcript after every
transport reconnect and full Bridge recreation.
`fuzz-mqtt-tls-outbound-bridge` runs the same source/target state machine over
two independent certificate-pinned TLS connectors. Both broker legs must
report `mqtt` ALPN and AES-128-GCM/SHA-256 after every reconnect before source
acknowledgement ordering, target resend, and Session transitions continue.
`fuzz-mqtt-outbound-bridge-qos2` completes this bounded bridge matrix with two
production brokers, a durable coordinator, live publisher/subscriber and
restartable OutboundBridge. It verifies exactly-once delivery across
pre-target-wire and target-PUBREL journal restoration, independent
source/target reconnects, retained replacement/deletion, and connection-scoped
property isolation. `fuzz-mqtt-tls-outbound-bridge-qos2` applies that same
durability oracle to two native-TLS broker listeners: publisher, subscriber,
source, and target connections are certificate-pinned, while every bridge
reconnect and journal recreation must renegotiate `mqtt` ALPN with
AES-128-GCM/SHA-256 before exactly-once progress resumes. Cross-process crash
injection below the filesystem syscall
boundary remains the responsibility of the commit-log and atomic-file fault
tests rather than the socket fuzzers.

The reconnect layer retains one synchronous network owner internally, but its
public managed worker can run either on a dedicated OS thread or as a task on
the Client's existing `std.Io` executor. `runQueuedAsync` and
`runQueuedEventsAsync` return the same `QueuedRun`/`QueuedEventRun` handles as
the thread-backed forms, so producers retain identical stop, wait,
timeout/deadline, terminal-error, and deinit contracts; deinit joins the thread
or awaits the I/O task only after requesting graceful shutdown. The worker
accepts owned PUBLISH, SUBSCRIBE, UNSUBSCRIBE, manual ACK,
graceful DISCONNECT, pending-PUBLISH flush and re-authentication commands with
typed, correlated completion callbacks. A bounded `CompletionQueue` adapter
additionally provides blocking, relative-timeout, absolute-deadline, and
nonblocking consumption with deep-owned SUBACK/UNSUBACK reason codes and
properties. A bounded `ClientEventQueue` also offers blocking, relative-
timeout, absolute-deadline, and nonblocking consumption and transfers complete
packet events to consumer threads without introducing a
second socket reader. The owned `PublishDeliveryQueue` now provides the same
four receive modes for terminal outbound PUBLISH results, including a caller-
owned awake-clock deadline that composes with earlier stages. All three queues
expose their timeout-capable error sets at the reconnect module boundary.
Re-authentication properties are deep-owned
until the initiating AUTH write completes. The single-owner bounded poll path,
callback
driver, thread- or `std.Io`-task-backed managed wrapper, optional
application-controlled QoS
1/2 acknowledgements, an owned bounded terminal-delivery queue, and the bounded
command queue already support explicit
client-initiated re-authentication and drive both directions of
multi-step MQTT 5 re-authentication, idle
keep-alive and automatic reconnect without competing socket readers. Current
reconnect clients expose bounded initial-connect timeout/deadline calls, and
the existing poll deadline now covers initial/replacement connection attempts
and retry backoff instead of only established packet reads. Raw, TLS, and
WebSocket connectors receive that same absolute attempt budget; custom
connectors without bounded support fail explicitly. Current
connection APIs also accept relative timeouts and caller-owned absolute
deadlines for CONNECT, PINGRESP, and ordered client or broker packet events.
The CONNECT budget starts before the initial request write and is retained
through every enhanced-authentication reply and the final CONNACK; a timed
write retires the connection because its committed wire prefix is ambiguous.
Receive budgets span the complete MQTT Control Packet and preserve partial TCP,
TLS, or WebSocket framing for a later call. The reconnect poller accepts an
awake-clock absolute deadline while still shortening individual waits for
Keep Alive and shutdown checks; neither mechanism renews the application
budget. Partial TCP/TLS/WebSocket packets and packets queued during PING remain
resumable after timeout; TLS packet transports now retain their own fixed-header
and payload progress instead of relying on stack-local framing state.
MQTT 5 reconnect clients accept an empty Client ID, including Clean Start=0.
After an accepted CONNACK, they deep-own the Assigned Client Identifier and
expose it through `clientId()`; every later CONNECT reuses that identity across
transport loss. A new client configured with an empty MQTT 5 ID can learn the
same identity from a validated Session snapshot, including version-one images.
Explicitly configured IDs still require an exact snapshot match. Saving before
assignment fails with `InvalidClientId`; rejected CONNACKs and failed identity
allocation leave the client unassigned. QoS Store replacement prepares all
allocations before retiring the old Store, so a failed replacement leaves its
handles and durable state usable for inspection. If allocation fails after a
broker reports Session loss, the client retains that loss across retries and
rejects snapshots of the obsolete QoS state until replacement succeeds, even
if the next CONNACK reports Session Present.
Real TCP cases cover QoS 1 PUBLISH and QoS 2 PUBREL recovery with preserved/lost
Sessions and Client reconstruction. TCP/TLS/WSS state-machine cases also verify
the assigned identity on every replacement CONNECT before QoS or subscription
recovery. The Mosquitto publish gate independently checks server assignment,
snapshot reconstruction, QoS 1/2 delivery and persisted No Local subscriptions.

MQTT reconnect Session lifetime now follows the effective CONNACK Session
Expiry and successful client DISCONNECT overrides. `sessionExpiryInterval()`
exposes that value on the reconnect owner and packet Connection, while copied
CONNECT properties retain the requested interval for future attempts. Offline
expiry begins once when the connection is retired; repeated retirement does
not renew it. Expiry is checked before each connection attempt, so waiting for
the CONNACK of a successfully resumed Session does not expire it again.
An elapsed lifetime prevents old Packet Identifiers and both
QoS 2 directions from replaying even if a later peer reports Session Present.
Desired subscriptions remain available for fresh recovery.
`reconnect.ConnectEvent.session_present` preserves the broker's raw CONNACK
bit. `session_resumed` and `Client.sessionResumed()` additionally require that
the local Session survived expiry and any earlier failed reset. Durable inbound
QoS 2 imports require this actual resumption and return `SessionLost` for a
fresh or locally expired Session. First attachment to a preserved peer Session
can still import application-owned durable markers. Publish recovery and bridge
epochs use the same result: lost source ownership prevents target replay, lost
target ownership rejects pending outbound QoS 2, and inbound bridges durably
retire old transactions before accepting a new Session. Real TCP regressions
cover peer Session Present with local expiry, failed reset, repeated imports,
fresh bridge epochs, and commit-log restoration after inbound retirement.
Version-three reconnect images additionally persist the effective interval
and remaining lifetime, subtract wall-clock downtime on restore, and keep
the remaining duration across repeated save/restore. Online images
conservatively start the expiry budget at their saved time. Expired images restore subscriptions
with an empty QoS Store; zero-interval images omit obsolete QoS state, and the
0xffffffff lifetime remains unlimited. Version-one/two images retain their
prior lifetime behavior. Snapshot restore remains transactional for malformed
metadata, configured subscription conflicts and allocation failures.
Server-selected persistence can be restored with the same Clean Start=false CONNECT configuration,
while a transient configuration without negotiated persistence still cannot
write a Session snapshot. The Mosquitto publish gate independently expires a
one-second DISCONNECT override, reconstructs the client, and verifies fresh
subscription replay and delivery without the old staged QoS 2 publication.

Reconnect clients can also encode an identity-bound Session snapshot while
online under their single-owner API and transactionally restore it only while
no Network Connection is active. The versioned CRC envelope binds protocol and
Client ID, deducts wall-clock downtime from
Message Expiry, restores outgoing QoS 1/2 at the exact PUBLISH/PUBREL stage,
and preserves deferred inbound QoS 2 `await_pubrel`/`release_pending` markers.
Version two also restores deep-owned desired subscription filters, QoS/options,
MQTT 5 SUBSCRIBE properties, and the first unconfirmed recovery filter. After
client reconstruction, a preserved broker Session resumes only that suffix;
a lost Session restarts all desired subscriptions. Compatible caller-seeded
filters merge within `max_subscriptions`, while conflicting saved and configured
options or properties reject the entire restore. Version-one QoS-only images
remain readable and preserve the caller's seeded subscriptions.
Decode uses a temporary one-Session store and owned subscription list and swaps
only after full validation;
online restore attempts, transient CONNECT configurations, non-empty
destination state, foreign identities, trailing bytes, and corrupt checksums
fail without changing the current Session. Standalone reconnect clients now
also expose atomic file save/load helpers with a 128 MiB read ceiling, 0600
snapshot permissions where supported, file fsync before rename, and parent
directory fsync after replacement. Missing, oversized, corrupt, foreign, or
protocol-mismatched files leave the destination Session unchanged; a temporary
file sync failure cannot replace an installed snapshot. `OutboundBridge`
now supplies its own identity-bound commit-log coordinator to atomically
compose both broker legs and its QoS 2 transaction; without that explicit
coordinator the cross-broker QoS 2 path remains fail-closed.
Every
public MQTT connection-level absolute-deadline entry point validates the
awake-clock domain before sending PINGREQ, consuming a queued event, or reading
transport bytes, so a mismatched timestamp cannot mutate protocol state. Current
MQTT-over-TLS server accept APIs also carry one caller-owned deadline through
TCP listener acceptance, trusted PROXY parsing, the TLS 1.3 handshake, and
complete MQTT CONNECT admission and the final CONNACK write; configured proxy,
TLS, and CONNECT limits can only shorten it. A timed-out accept closes a
concurrently completed socket that
lost the timer race, so it cannot consume the next caller's connection.
Two-phase server admission exposes matching challenge and response deadline
methods, allowing one absolute timestamp to span every enhanced-authentication
round and the final CONNACK without silently restarting the budget. Pending
admissions retain the effective CONNECT deadline, so broker-managed
authentication policy, ordinary challenge/response calls, authorization
refusals, and successful CONNACK writes inherit that same budget
automatically; an explicit shorter deadline can tighten but never extend it.
Raw TCP server accept and already-accepted-stream APIs expose the same bounded
admission contract, including listener acceptance and a shared budget with a
trusted PROXY preface when enabled.
Raw Unix-domain MQTT listeners expose matching end-to-end timeout/deadline
forms for pending and completed CONNECT admission, including listener
acceptance and an already accepted-stream timeout/deadline pair. Raw TCP
exposes the same pair, and an
already-open client transport can negotiate CONNECT/CONNACK under either a
relative timeout or a caller-owned absolute deadline without reopening it.
WS, Unix-WS, and WSS server accept APIs carry the same outer deadline from
listener acceptance through WebSocket Upgrade and MQTT CONNECT; WSS
additionally includes TLS and trusted PROXY parsing in that unchanged
timestamp, and canceled TCP accepts cannot consume a later connection.
Current
tests cover real two-connection QoS 1 PUBLISH/DUP and outgoing QoS 2 PUBREL
continuation, incoming QoS 1 delivery across a keep-alive cycle, inbound QoS 2
continuation after transport loss, manual QoS 1/2 acknowledgements with MQTT 5
diagnostics, manual QoS 2 duplicate suppression and reconnect continuation,
QoS 0/1/2 publish-delivery callback timing and ACK properties,
silent-broker PING timeout followed by
Session-Present replay, fresh-session cleanup, accepted-only subscription
replay, Session Present suppression of redundant SUBSCRIBE, bounded delay math,
prompt cancellation during a thirty-second backoff, and multi-step live AUTH
including callback-produced User Properties and missing-handler failure.
Native TLS, cleartext WebSocket and authenticated WSS connector tests each
establish two successive MQTT sessions through the same reconnect client.
Every owned asynchronous producer operation offers immediate bounded enqueue,
a `*AsyncTimeout` form, and a `*AsyncWithDeadline` form. The bounded variants
wait for consumer capacity while retaining deep ownership, report queue closure
distinctly, and still report protocol completion through the original
correlated callback. Absolute awake-clock deadlines are also forwarded through
the managed `QueuedRun` callback and completion-queue conveniences, so a caller
can share one budget across multiple stages without renewing a relative timeout.
Managed `QueuedRun` and `QueuedEventRun` workers additionally expose
`isFinished`, cancelable `wait`, and relative/absolute bounded waits. Their
move-stable completion state publishes the exact terminal poll or handler error
before waking every waiter; waiting never joins or frees the worker, while
`deinit` remains the single resource-reclamation boundary. Real loopback tests
run both worker modes through terminal handler failure, concurrent waiters,
bounded wait expiry, owned event-queue transfer, and clean shutdown. This lets
supervisors compose multiple reconnect loops without hanging on an event queue
after one side has already failed or reserving a dedicated thread per client.
A separate zio-backed test schedules both the broker and reconnect owner on one
`std.Io` executor, then completes an owned PUBLISH command, graceful DISCONNECT,
terminal wait, and teardown. The task Future lives in the existing move-stable
run state, so choosing the executor path does not add a third heap allocation.
`Client.publishOneAttempt` exposes the complementary low-level boundary for
coordinators: on a retryable QoS 1/2 write failure it returns immediately with
the retained Packet Identifier and leaves reconnect/replay to later `pollWith*`
calls, while the original `publish` convenience retains automatic reconnect.
It refuses while older replay/queue work is pending, then atomically assigns the
returned Packet Identifier to that call's exact Application Message. A full
Receive Maximum returns `InflightFull` without sending an older packet or
silently queueing the new message, local pre-wire failures remove its state,
and transport failures alone retain it for DUP replay. An online MQTT 5 publish
with Message Expiry zero is still emitted once on the current connection
instead of being mistaken for an already-expired offline queue entry.
This covers both rumqttc-style `try_*` and waiting send behavior without
introducing another network reader.

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
convenience. Once every finite connection worker exits, `serveListeners` stops
and joins the deadline driver, then synchronously completes only the Will and
Session deadlines already due at that boundary. Its return therefore includes
an immediate Will from the final disconnected client without publishing a
future delayed Will early. Each accepted connection deep-owns its namespace, so
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
same durable Session. The 294-scenario Mosquitto-derived wire gate runs the
same policy through the standalone broker option, including exact Session
Present, takeover DISCONNECT and missing-username refusal bytes. A fresh
2026-11-01 run passed all 294 scenarios with 5000 ms CONNECT deadlines; see
`docs/evidence/mqtt_mosquitto_vectors/2026-11-01.json`.
`zig build interop-mqtt-listener-mount-mosquitto -Doptimize=ReleaseFast`
also ports Mosquitto's `10-listener-mount-point.py` process shape for both
MQTT 3.1.1 and MQTT 5, verifying canonical ingress and destination-specific
egress against Mosquitto's independent wire-packet helpers. The two listeners
and broker share one zio-backed `std.Io`; the runner rejects readiness records
that do not contain `client_io=python-socket server_io=zio-std-io`.
Raw MQTT and MQTT-over-WebSocket additionally expose Unix-domain server/client
paths, including `PendingSource` integration with both Broker serving modes.
They reuse the normal MQTT and WebSocket state machines while rejecting PROXY
configuration and TCP-only NODELAY behavior on the local transport. Real socket
tests complete MQTT 5 QoS 1 in both raw and WebSocket forms, including bounded
concurrent serving of independent clients with per-connection result reporting.
Standalone TCP, Unix, TLS, WS, and WSS servers also share a long-running
`serveUntil` worker supervisor with cancellation, connection reuse, error
observation, and independent accept/connection failure policies.

The production broker example's exclusive `--config=PATH` path now exercises
the public strict file loader rather than translating configuration into CLI
flags. Its bounded `include_dir` support processes directories in declaration
order and top-level regular `.conf` files in Mosquitto's case-insensitive-first,
upper-case-first order. Included files retain independent listener context,
nested includes and special files fail closed, and every file is parsed before
any listener bind. The in-memory parser performs no filesystem expansion.
By default one loaded Mosquitto-style `password_file` and `acl_file` are
shared by all listener policies. With `per_listener_settings true`, each file
directive belongs to its preceding listener and is loaded into stable,
listener-indexed storage before any socket is bound. Cross-listener process
tests prove that credentials and write ACLs cannot leak between ports, and an
invalid later listener file prevents every earlier listener from opening.
Global `allow_anonymous` is order-independent and defaults to false.
Mosquitto's recommended `listener_allow_anonymous` always belongs to its
preceding listener and overrides the global value; with
`per_listener_settings true`, the legacy `allow_anonymous` spelling remains
listener-local. A listener whose effective policy is false requires a valid
username/password or certificate identity, while an anonymous-capable listener
permits absent credentials but rejects credentials that are supplied and
invalid. `mqtt.password_file` recognizes current
Argon2id, `$7$` PBKDF2-SHA512, and legacy `$6$` salted SHA-512 records. It
decodes and validates all entries before binding, rejects plaintext, duplicate
users, invalid UTF-8/lengths and unbounded file/user/KDF inputs, wipes owned
hash storage at teardown, compares fixed-size hashes in constant time, and
serializes password derivation so simultaneous Argon2 CONNECTs cannot multiply
the configured memory bound. The process gate checks successful and rejected
MQTT 3.1.1/5 authentication, all three hash formats (including an independent
libargon2 vector), wrong/unknown/missing credentials, mixed protected TCP plus
anonymous WebSocket listeners, shared routing/mount policy, and snapshot
restart. The same gate now verifies user/anonymous `topic` scopes, `%u`
patterns, default deny and deny precedence over real TCP/WebSocket traffic.
It additionally source-locks Mosquitto
`01-connect-listener-allow-anonymous.py` at SHA-256
`56b58590c474efa5f7bf1ad8dc7277d4ba42b7a69e7e7b8f16ac924813f9b214`
and runs its nine global/listener precedence combinations through two real
listeners under both MQTT 3.1.1 and MQTT 5. Three additional cases leave one
listener unoverridden to exercise inherited default-false, explicit-false, and
explicit-true global policy. The complete matrix checks 48 CONNECT/CONNACK
outcomes.
It also checks an exact 50-byte full-packet boundary, MQTT 5 Maximum Packet
Size advertisement and 0x95 disconnect, MQTT 3.1.1 close behavior, WebSocket
1009 translation, plus version-correct QoS 0/1 and Will payload-limit handling.
The same real-process gate covers `retain_available false`: MQTT 5 TCP and
WebSocket CONNACK packets advertise Retain Available 0, retained PUBLISH receives
0x9A, retained Will CONNECT is refused with 0x9A, and MQTT 3.1.1 closes both
unrepresentable violation paths. The TCP QoS 1 case now reproduces and
source-locks Mosquitto's complete `03-publish-qos1-retain-disabled.py` input,
including its Packet Identifier, and requires DISCONNECT 0x9A rather than a
PUBACK.
It also ports the policy matrix from Mosquitto's
`01-connect-zero-length-id.py` through the configuration path. Global disable
is enforced on TCP and WebSocket with MQTT 5 reason 0x80 and MQTT 3.1.1 reason
0x02. With `per_listener_settings true`, one listener can reject while another
retains the default; successful MQTT 5 admission includes a unique `netz-`
Assigned Client Identifier with Clean Start either true or false. MQTT 3.1.1
clean-session admission remains usable, while its non-clean empty-ID form is
refused independently of the configuration setting.
The configuration process gate also enables `upgrade_outgoing_qos` and checks
both MQTT 3.1.1 and MQTT 5: retained replay and ordinary live fanout upgrade a
QoS 0 publication to the subscription's QoS 1, allocate a Packet Identifier,
and complete the PUBACK exchange. The default remains the standards-compliant
minimum-QoS rule.
The same gate source-locks `max_inflight_messages` behavior to Mosquitto
`03-publish-qos1-max-inflight.py`,
`03-publish-qos2-max-inflight.py`, and
`03-publish-qos2-max-inflight-exceeded.py`. With a configured value of one,
MQTT 5 CONNACK advertises Receive Maximum 1, both MQTT 3.1.1 and MQTT 5 hold a
second outgoing QoS 1/2 PUBLISH until the first handshake completes, and a
second unresolved incoming QoS 2 PUBLISH receives MQTT 5 DISCONNECT 0x93 or a
3.1.1 connection close. A zero-value process case verifies omission of the
Receive Maximum property, whose MQTT 5 default is 65,535. Session snapshot
tests also lower the configured window
below restored inflight state: restoration retains the transactions, while
retransmission and newly queued delivery obey the new smaller limit.
The same MQTT 3.1.1/5 process matrix configures `max_inflight_bytes 10`
independently of a count window of five. It verifies that two six-byte QoS 2
payloads cross the threshold, that PUBREC/PUBREL does not prematurely release
the byte budget, and that the third PUBLISH appears only after PUBCOMP.
The configuration gate also creates offline durable Sessions for MQTT 3.1.1
and MQTT 5 and exercises `max_queued_messages 2` independently from
`max_queued_bytes 10`. In both cases the first two messages are restored in
order, the third is silently dropped while its publisher receives a successful
PUBACK, and a PING barrier proves that no hidden delivery remains. This mirrors
Mosquitto's current threshold-before-admission behavior, including retaining
the message that crosses a payload-byte threshold.
Like Mosquitto's current ACL-file plugin, SUBSCRIBE and UNSUBSCRIBE themselves
are admitted while `read` rules filter every concrete live/retained/resumed
delivery. Listener-local `certfile` and `keyfile` select the native TLS/WSS
server paths. The pair is mandatory, all configured identities are validated
before the first bind, and the public loader accepts leaf-first PEM certificate
chains with unencrypted P-256/P-384/P-521 SEC1 or PKCS#8, RFC 8410 Ed25519 PKCS#8,
and 2048/3072/4096-bit RSA PKCS#1 or PKCS#8 keys, including TLS-compatible
constrained RSA-PSS PKCS#8. PBES2-encrypted PKCS#8 accepts bounded PBKDF2 with
HMAC-SHA1/SHA-256/SHA-384/SHA-512 and AES-128/256-CBC; its password is read
from a separate bounded one-line `keyfile_password_file`. RSA private material
owns its decoded DER, uses
vail's validated CRT representation and prepared Montgomery contexts, and is
wiped on teardown. The loader rejects malformed or non-canonical DER,
unsupported RSA parameters, legacy PEM encryption, other-curve keys, oversized
inputs and
leaf/key mismatches. Real OpenSSL clients restricted to matching ECDSA-P384,
ECDSA-P521, Ed25519, or RSA-PSS/RSAE signature schemes complete MQTT/TLS and WSS handshakes
through the production configuration path; both PKCS#8 and traditional PKCS#1
RSA PEM encodings are exercised. Listener-local `cafile`
now requests and verifies client
certificates on TLS and WSS; `require_certificate true` additionally rejects
an empty TLS 1.3 Certificate response. The bounded public CA loader
rejects non-CA, expired/not-yet-valid, duplicate-subject, wrong-usage, malformed
and oversized inputs before any bind; CertificateRequest carries each exact DER
CA Name. The process gate verifies MQTT/TLS and its CA-name advertisement
through OpenSSL, WSS through a hostname-verifying Python TLS client, and
missing/wrong-CA/wrong-EKU rejection before MQTT CONNECT. A separate process
case accepts both anonymous and trusted-certificate clients through one
optional-certificate listener. TCP/TLS `capath` non-recursively and
deterministically loads `.pem` files and OpenSSL rehash certificate links under
hard entry/file/byte/certificate limits, combines with `cafile` when both are
configured, and applies the same CA validation before bind. Empty, malformed,
duplicate-subject and oversized directories fail closed; the process gate
proves two independent directory CAs, an untrusted client, rehash links, and
multi-listener startup atomicity. WebSocket `capath` is rejected explicitly,
matching Mosquitto's documented unsupported transport without silently ignoring
the setting. On Linux, `SIGHUP` atomically prepares bridge definitions together
with the password, ACL, server certificate/private key/password, client CA
bundle/directory, and CRL file contents named by the initial configuration.
Every replacement and bridge slot reservation succeeds before the shared commit
gate opens; any missing or invalid file preserves the complete old bridge,
policy, and server-identity generations. Existing
clients immediately use new ACL rules. After a successful password-file swap,
the broker compares the old and new parsed credential for each established
username: unchanged credentials stay online, while removed or modified entries
receive MQTT 5 Administrative Action (or direct MQTT 3.1.1 closure), cancel
their Wills, and preserve any durable Session for authenticated reconnect.
TLS policy changes affect later TLS/WSS handshakes without rebinding the
listener. A short-lock, ref-counted generation keeps every
in-flight handshake on the server identity, CA names, trust roots, and CRLs it
selected and reclaims retired material after the final lease, while established
connections only retain traffic keys and authenticated peer metadata. The signal handler only sets a lock-free
`sig_atomic_t`; file I/O, parsing, locking, swapping, destruction, and logging
run in the normal `std.Io` supervisor. Real process gates rotate both MQTT/TLS
and WSS server identities and client CA roots, prove old connections survive
while new clients use the new trust roots, verify updated CertificateRequest CA
names, and verify malformed replacements roll back. The password/ACL gate keeps
an unchanged authenticated subscriber online, revokes a removed credential on
the live connection without publishing its Will, and proves a failed later
reload disconnects nobody. It now source-locks Mosquitto revision `5cd25465`'s
`23-security-password-file-reload.py` and
`23-security-acl-file-reload.py` by exact file SHA-256. Those upstream tests
terminate Mosquitto with exit code 3 after a valid security file becomes
malformed. Netz instead prepares the complete replacement before commit: an
unsupported password hash and an invalid ACL directive are exercised as
separate live SIGHUP transactions, each leaves the old parsed credentials and
ACL generation active, preserves existing PING/PUBLISH delivery, and rejects
the uncommitted username. The process stays available, so this is an explicit
stronger-availability divergence rather than relabeling Mosquitto's expected
termination as identical behavior. The same production gate source-locks Mosquitto
`09-acl-change.py`: an MQTT 3.1.1 durable Session queues two QoS 1 messages
while offline, SIGHUP removes read access for one topic, and reconnect reports
Session Present while delivering only the still-authorized message. PUBACK
followed by an immediate PINGRESP proves the denied queued entry was removed
rather than delivered or left blocking the Session head. A companion
source-locks Mosquitto `15-persist-client-msg-modify-acl.py` across three
production broker generations. The first snapshots two offline QoS 1 entries;
the second starts with a narrower ACL, restores Session Present, delivers only
the authorized entry and persists that cleanup; the third restores the same
Session and answers PING with no stale delivery. This proves restart-time
snapshot restore cannot preserve pre-restart authorization or resurrect a
denied queue tombstone. Another starts with client A accepted and client B
revoked, swaps the CRL through SIGHUP and proves
that outcome reverses, then supplies a signature-mutated CRL and proves the
failed reload retains the prior policy on the same live listener. Bridge
definitions are one exception: `bridge_reload_type lazy|immediate` selects
per-bridge generation replacement on the same SIGHUP without rebinding
listeners. Per-listener resolved anonymous policy,
`allow_zero_length_clientid`, resolved global/listener auto-ID prefixes,
accepted protocol versions, Maximum QoS,
Maximum Keep Alive, and inbound/outbound Topic Alias ceilings are committed
under the same security generation lock. Existing connections retain their
negotiated capabilities, while each later CONNECT takes one fixed-capacity stack
snapshot after parsing and before Session/Will/route mutation, so admission,
CONNACK capabilities, and assigned identifiers cannot mix generations or borrow
replaced prefix storage. The parser uses an all-version superset for these
reloadable listeners and the snapshot performs the authoritative version
admission, allowing a reload to both enable and disable MQTT 3.1/3.1.1/5.
Listener count/order, bind address, transport protocol, TLS/authentication paths,
mount, other Client ID policy, PROXY, Origin, and connection-limit changes fail the
complete transaction with `ListenerConfigurationRequiresRestart` instead of
being silently ignored. Autosave policy is the other exception:
`autosave_interval` and
`autosave_on_changes` switch atomically among time, durable-change, and disabled
modes. The process gate exercises every transition, rejects a changed
persistence target without changing the active policy, and restores retained
state from debt written immediately when change autosave is re-enabled.
Listener topology, the other listener policies/limits, and the persistence
enable/target still require restart.
The complete configuration gate now passes with OpenSSL 3.6.5, including exact
CertificateRequest CA-name decoding, live client-CA rotation, mTLS, CRL and
TLS/WSS rollback. The earlier 3.6.5 failure was a process-gate synchronization
bug rather than a TLS wire mismatch: `select()` cannot see lines already
decoded into Python's `TextIOWrapper`. The line waiter now drains that buffer
non-blockingly before waiting on the descriptor, with a deterministic two-line
regression. A separate restart helper retries only transport loss while a
test broker is killed and rebound under an automatically reconnecting bridge;
completed MQTT refusals remain immediate failures. Twenty consecutive bridge
reload runs and the complete broker-configuration matrix passed after the
change.
Broker plugins are intentionally outside the target scope and are not counted
as a standards gap. CA files may contain non-CA certificates whose KeyUsage
authorizes `cRLSign`; these are retained separately from client trust anchors
and CertificateRequest names. Direct and multi-hop delegated indirect CRLs are
accepted only after the signer path reaches the certificate issuer or a shared
configured trust anchor. A leaf receives coverage only when its CRL
distribution point names that CRL issuer with matching scope and reasons.
`use_identity_as_username`
strictly extracts one owned UTF-8 Subject CN before every broker/listener
authorization callback; `use_subject_as_username` uses the complete Subject in
OpenSSL's RFC 2253 form, including reverse RDN order and escaping. Both ignore
wire username/password and feed the certificate identity into `%u` ACLs,
`use_username_as_clientid`, Session and Will state. CN mode takes precedence
when both are configured, matching Mosquitto. TCP and WSS process cases verify
the full Subject and CN-priority paths, while a trusted certificate without CN
is Not Authorized in CN mode.
Listener-local `crlfile` composes with the same trust callback. Every list must
match and verify under one `cafile` CA; update windows, unsupported critical or
scope-changing extensions and canonical leaf serials are checked before bind.
Direct RFC 5280 delta CRLs are paired with a compatible complete base, the
newest supplied delta wins, and `removeFromCRL` plus newly revoked serials are
applied atomically during the TLS client-authentication decision. Indirect
base/delta lists signed by a configured CA use the same composition rules;
orphan, mismatched, duplicate-number, unauthorized-signer, and unbound-scope
inputs fail closed before bind.
The OpenSSL process gate keeps non-revoked TLS/WSS clients live, rejects a
revoked client before MQTT CONNECT, rejects a tampered CRL before any port
opens, and independently runs 2048-bit RSA, P-384/SHA-384, and Ed25519 CA/leaf/CRL
success/revocation pairs through the production configuration path. The
P-384 and Ed25519 paths also reject authenticated signature mutations before
any listener binds.

`zig build interop-mqtt-mosquitto-vectors -Doptimize=ReleaseFast` now runs 294
raw MQTT scenarios derived directly from Mosquitto `5cd25465`'s packet
generators. A complete source-locked port of
`01-connect-disconnect-v5.py` sends all four legal normal-DISCONNECT encodings:
Remaining Length 0, reason-only length 1, an empty Property Length, and one
User Property. Every case closes a Will-bearing connection while an independent
subscriber's PING barrier proves that normal shutdown canceled the Will. Two
source-locked persistence scenarios then port Mosquitto's
`15-persist-client-msg-in-v3-1-1.py` and
`15-persist-client-msg-in-v5-0.py`: two inbound QoS 2 PUBLISH packets reach
PUBREC, the broker writes a process-restart snapshot, reconnect reports Session
Present, and both PUBREL packets release their original Application Messages
exactly once through complete downstream QoS 2 handshakes. A complete
source-locked port of `11-persistent-subscription.py` restores MQTT 3.1.1/5
subscriptions after an orderly process snapshot and requires the exact
self-directed QoS 1 PUBLISH plus PUBACK without another SUBSCRIBE. Both
deliveries complete through acknowledgement and PING barriers. Two companion
cases SIGKILL the journal-backed broker while the subscribed client remains
connected, immediately after durable SUBACK; journal restoration must preserve
that same self-subscription without an EOF or final snapshot saving its state.
The crash helper verifies the exit status of its own process. A complete
source-locked port of `21-proxy-v1-bad.py` then rejects all 22 malformed v1
prefaces: an unknown TCP family, an overlong header, missing endpoint/port
fields, zero or overflowing ports, invalid IPv4 addresses, and IPv4 text under
TCP6. Each peer is closed without MQTT parsing, after which a valid PROXY v1
CONNECT and PING complete on the same finite listener worker. A complete port
of `21-proxy-v2-bad-header.py` adds twelve v2 failures covering signature,
version, command, unspecified family, short or zero IPv4/IPv6/Unix address
blocks, a truncated SSL TLV, an outer TLV length beyond the declared PROXY
payload, and an oversized nested SSL sub-TLV. All twelve connections close
before MQTT, then a valid v2 CONNECT/PING proves listener recovery. Six
existing source-locked PROXY protocol cases also consume Mosquitto's v1 TCP4
and v2 IPv4/IPv6 prefaces before completing MQTT 5 CONNECT and PING on the
same stream, then reject the upstream fixture's 501-byte IPv4, IPv6, and Unix
v2 payloads before CONNECT while a fresh bounded connection remains usable;
the seven/no-topic-tree QoS 1 no-matching-subscriber PUBACK sequence
(including retained-tree creation) and subscription-identifier replacement
with exact forwarded PUBLISH bytes. The no-subscriber scenario is now locked
to the complete upstream `03-publish-qos1-no-subscribers-v5.py` source hash and
replays all seven publications: three absent topic prefixes, one retained
write that creates the topic-tree node, then the same three prefixes again.
Every PUBACK remains reason `0x10`, proving retained storage alone cannot be
miscounted as a matching subscription. The gate also source-locks and ports
Mosquitto's hostile
non-CONNECT-initial-packet shape for all packet types 2-15, using a declared
~250 MiB Remaining Length without sending its body. Netz closes every malformed
connection before that allocation/read and accepts a subsequent valid MQTT 5
CONNECT. This locks the adversarial input shape and early-rejection behavior,
not Mosquitto's separate process-VMS sampling assertion. A QoS 2 vector
additionally proves the Application Message is not
routed before PUBREL, then checks publisher PUBREC/PUBCOMP plus the independent
subscriber PUBLISH/PUBREC/PUBREL/PUBCOMP sequence byte-for-byte. A mixed-version
case uses a Mosquitto-generated MQTT 3.1.1 subscriber and MQTT 5 publisher on
the same listener, checking exact v5 PUBACK plus property-free v3 QoS 1
PUBLISH/PUBACK translation. The sixth source-locked scenario ports the
wire-observable
subset of Mosquitto's
`11-persistent-subscription-no-local.py`: reconnect reports Session Present,
the restored No Local subscription suppresses self-delivery while PUBACK stays
successful, and re-subscribing replaces the option so the next self-publish is
forwarded with an independent Packet Identifier. This also corrected netz's
prior 0x10 PUBACK: No Local suppresses delivery but does not mean that no
subscription matched. The seventh source-locked scenario directly ports Mosquitto's
`02-subpub-qos0-send-retain.py`: retained messages are installed before
SUBSCRIBE, then Retain Handling 0/1/2 are each exercised twice to prove
always-send, new-subscription-only and never-send behavior with exact RETAIN
bits. The eighth scenario directly ports Mosquitto's
`02-subpub-qos0-topic-alias.py`: a publisher establishes alias 3, then reuses
it with an empty Topic Name; the subscriber receives the resolved full Topic
Name with the connection-scoped alias removed. The gate builds a finite netz
broker. Eight additional credential cases port Mosquitto's anonymous,
username-without-password, and wrong-password refusals for MQTT 3.1.1 and 5;
the latter two upstream vectors are source-locked,
then prove valid username/password connections remain usable in both versions. The broker
evaluates this policy before Session/Will/router registration and the finite
example exposes `--username` plus `--password` for static credentials. The
same gate source-locks the wire-observable subset of Mosquitto's
denied-subscription and denied-publish plugin behavior for MQTT 3.1.1 and 5:
denied filters return SUBACK 0x80/0x87, denied
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
The ninth source-locked scenario ports the MQTT 5 branch of Mosquitto's
`04-retain-qos0-repeated.py` lifecycle and its clear boundary: retained replay
survives UNSUBSCRIBE/resubscribe, UNSUBACK bytes are exact, and a zero-length
retained PUBLISH removes the value so a later subscription receives nothing.
The tenth scenario ports a bounded form of Mosquitto's
`02-subpub-b2c-topic-alias.py`: after the subscriber advertises Topic Alias
Maximum 2, netz now automatically establishes alias 1 on the first forwarded
PUBLISH and sends the repeated topic with an empty Topic Name plus alias 1.
Alias assignment remains per Network Connection and is committed only after a
successful write.
The source lock covers that test together with Mosquitto's
`02-subpub-qos0-topic-alias.py`. The production configuration gate verifies
listener-local defaults and complete u16 parser bounds, CONNACK advertisement,
inbound alias resolution and out-of-range DISCONNECT 0x94, broker-to-client
alias negotiation as the minimum of client and broker limits, and independent
zero-disable semantics for both directions.
The eleventh scenario source-locks both Mosquitto
`12-prop-response-topic.py` and
`12-prop-response-topic-correlation-data.py`: Response Topic alone,
Correlation Data alone, and both properties together survive exact broker
fanout to the responder, whose response on the advertised topic reaches the
requester byte-for-byte.
`zig build interop-mqtt-mosquitto-clients -Doptimize=ReleaseFast` adds a
separate independent-client boundary. It builds `mosquitto_pub` and
`mosquitto_sub` from pinned Mosquitto commit `5cd25465`, then connects those
real libmosquitto clients to the netz broker over MQTT 3.1, MQTT 3.1.1, and
MQTT 5. Each version verifies exact topic, payload, delivered QoS, and retain
flag for QoS 0/1/2 fanout plus retained replay. A final MQTT 5 pair publishes
Response Topic and binary Correlation Data through the CLI property API and requires
libmosquitto's formatted decoder to reproduce both values exactly. This is
client-process interoperability evidence, distinct from the source-derived raw
packet fixtures below. A fresh 2026-11-01 run passed MQTT 3.1/3.1.1/5 with
libmosquitto 2.1.0, QoS 0/1/2 fanout, retained replay, Response Topic and
binary Correlation Data; see
`docs/evidence/mqtt_mosquitto_clients/2026-11-01.json`.
`zig build interop-mqtt-rumqttc -Doptimize=ReleaseFast` adds a second
independent client implementation. Its committed Cargo lock pins rumqttc
0.25.1 and the runner builds with `--offline --locked`. Each protocol drives
ConnAck, exact QoS 2 SubAck, QoS 0/1/2 publish completion and single
self-delivery, retained publication/replay with no duplicate PUBLISH before
disconnect, automatic incoming acknowledgement, and graceful DISCONNECT. It
also creates a persistent subscription, disconnects, publishes QoS 1 through
an independent connection while the subscriber is offline, and reconnects
with the same Client ID. The reconnect must report Session Present and deliver
the queued message exactly once without another SUBSCRIBE; rumqttc's outgoing
PUBACK is observed. MQTT 3.1.1 uses Clean Session false, while MQTT 5 uses
Clean Start false and a nonzero Session Expiry Interval. The MQTT 5 path also
requires Response Topic, binary Correlation Data, and User Property to survive
broker fanout as typed rumqttc values. This keeps libmosquitto and rumqttc
evidence independent. A fresh 2026-11-01 run passed both MQTT 3.1.1 and MQTT 5
with QoS 0/1/2, retained single delivery, automatic acknowledgement, Response
Topic/Correlation Data/User Property, Session Present resume and offline QoS 1
delivery; see `docs/evidence/mqtt_rumqttc/2026-11-01.json`.
`zig build interop-mqtt-rumqttc-crash -Doptimize=ReleaseFast` extends that
independent-client boundary across process failure. A first rumqttc process
creates MQTT 3.1.1 and MQTT 5 persistent QoS 1/2 subscriptions, disconnects
them, and uses distinct publisher connections to queue one message at each QoS
while both subscribers are offline. After each publisher completes PUBACK or
PUBREC/PUBREL/PUBCOMP, the runner sends SIGKILL to the
still-listening broker. A new broker process restores the same fsynced commit
log on a different port, and a new rumqttc process reconnects both Client IDs.
It requires Session Present and receives each queued message without
SUBSCRIBE. Manual acknowledgement then holds all four deliveries at the exact
post-PUBLISH/pre-PUBACK-or-PUBREC boundary before a second SIGKILL. The next
process must receive `DUP=1` with every original Packet Identifier, send
explicit PUBACK/PUBREC, observe each PUBREL/PUBCOMP completion, and pass
unrelated QoS 1 protocol barriers. After a third SIGKILL/restart, final fresh
clients require that none of the acknowledged deliveries reappear. The MQTT 5
path exercises the Session Expiry property throughout. This is external client
evidence for single-node queued and outgoing-inflight crash recovery, distinct
from the raw-packet commit-log fixtures and from orderly same-process reconnect.
The twelfth scenario ports Mosquitto's retained Message Expiry vector with a
timing-tolerant immediate check: the forwarded interval is 2 or 1 seconds, the
entry is absent after three seconds, and a non-expiring retained control still
replays.
The thirteenth and fourteenth scenarios are source-hash-locked ports of
Mosquitto's `02-subpub-qos2-receive-maximum-1.py` and
`02-subpub-qos2-receive-maximum-2.py`. Three publisher transactions complete
for each advertised window. The subscriber receives exactly one or two initial
PUBLISH packets, remains silent after PUBREC/PUBREL, and releases each queued
PUBLISH only after PUBCOMP returns one complete QoS 2 transaction slot. A final
PINGRESP proves all three transactions retired without duplicate delivery.
The next scenario directly ports Mosquitto's Maximum Packet Size 40
QoS 1 vector. Two oversized self-deliveries are discarded while publisher
PUBACK/PING keep the socket live, then a boundary-fitting PUBLISH is forwarded.
This exposed and fixed netz closing transient live connections on
`OutgoingPacketTooLarge`; durable Session and live delivery queues now share
the same discard-and-continue policy.
Its QoS 2 Maximum Packet Size companion verifies that
an oversized released message completes publisher PUBREC/PUBREL/PUBCOMP but
creates no downstream transaction, then a fitting message completes both the
publisher and independent subscriber QoS 2 handshakes.
The source-locked multi-level retained clear vector ports Mosquitto's
`04-retain-clear-multiple.py` on one MQTT 5 connection: three nested topics
replay through `#`, middle and leaf
tombstones return no-match PUBACK 0x10, and subsequent wildcard replay proves
ancestor/child retained trie nodes survive independent deletion.
The source-locked five-client shared QoS 0 scenario directly ports Mosquitto's
`02-shared-qos0-v5.py`: an ordinary subscription receives all three messages,
while two shared
groups independently select exactly one member and rotate through the upstream
receiver sequence without duplicate group delivery.
The following scenario isolates the source-locked core retransmission semantics
from Mosquitto's `03-publish-c2b-disconnect-qos2.py`: original and DUP PUBLISH
with one Packet Identifier receive PUBREC without early routing, and one PUBREL
creates exactly one independent downstream QoS 2 transaction.
The nineteenth scenario verifies Mosquitto's PUBREL idempotence boundary:
repeating a completed PUBREL and sending an unknown Packet Identifier both
return PUBCOMP, while the subscriber observes no duplicate Application Message.
Two companion source-locked MQTT 3.1.1/5 scenarios start from Mosquitto's
`03-publish-qos2-reuse-mid.py` but retain MQTT 5 section 4.3.3's receiver
semantics instead of Mosquitto's replacement extension. A second non-DUP
PUBLISH reuses an identifier that is still waiting for PUBREL and carries a
different topic and payload. Netz acknowledges both PUBLISH packets with
PUBREC, preserves the first pending Application Message, and releases it
exactly once after PUBREL; the subscriber's bounded silence check rejects
delivery of the conflicting retry.
The twentieth scenario sends the server-only Subscription Identifier property
on a client PUBLISH. Netz sends Protocol Error `0x82`, rejects the connection
before routing, and then accepts a fresh MQTT 5 client/PING, proving the finite
broker remains healthy.
The twenty-first scenario unsubscribes an existing and missing filter in one
packet, checks ordered MQTT 5 reason codes 0x00/0x11, then proves the removed
route stays silent while PING remains usable.
The twenty-second scenario gives two live subscribers opposite Retain As
Published settings, then verifies the same retained QoS 1 source PUBLISH is
forwarded with RETAIN cleared for one and preserved for the other.
The twenty-third scenario replaces one retained topic including its User
Property, then proves a later subscriber receives only the new payload/property
once; PING immediately after replay catches stale duplicate retention.
The twenty-fourth source-locked scenario ports the in-process wire-observable
subset of Mosquitto's retained property bundle: Payload Format, Content Type,
Response Topic, Correlation Data and User Property survive storage and replay
byte-for-byte. Mosquitto's separate broker-restart step is not claimed by this
scenario.
The twenty-fifth scenario clears a retained value with a property-bearing
zero-length tombstone, proves neither old nor tombstone properties replay, and
then verifies a replacement live PUBLISH contains only its new User Property.
The source-hash-locked `02-subpub-qos0-subscription-id.py` scenario first
installs identifiers 1 and 14 plus one unnumbered filter and verifies all three
initial deliveries. It then replaces the same filters to remove the first
identifier, change 14 to 19, and add 21 to the third. Exact self-delivered MQTT
5 PUBLISH bytes prove all three replacement directions; a final PING barrier
rejects stale or duplicate identifiers. The twenty-sixth scenario overlaps an
exact and wildcard subscription for one
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
A source-hash-locked two-version port of Mosquitto's
`02-subpub-recover-subscriptions.py` now keeps a broker process alive across
disconnect/reconnect, requires Session Present without a repeated SUBSCRIBE,
and proves the ordinary subscription remains routed in MQTT 3.1.1 and MQTT 5.
The MQTT 5 case also proves the shared subscription is restored and routed.
A second source-hash-locked two-version port covers Mosquitto issue #874 via
`02-subscribe-persistence-flipflop.py`. Per protocol version, four subscriber
connections alternate one Client ID between persistent and clean Sessions,
require every clean transition to report Session Present false, and rebuild the
subscription; a fifth connection publishes and the gate verifies the exact QoS
1 PUBLISH/PUBACK flow. The MQTT 5 adaptation sets an explicit 60-second Session
Expiry Interval on persistent connections, preserving the upstream intent under
MQTT 5's different persistence rules.
A source-hash-locked MQTT 3.1.1/5 port of Mosquitto's issue #505 regression,
`02-subhier-crash.py`, builds sibling `topic/a` and `topic/b` subscription
leaves, removes the first, then repeats the entire tree lifecycle. The process
gate strengthens the upstream crash-only check: QoS 1 publisher acknowledgments
synchronize each route decision, an exact PINGRESP proves the removed leaf no
longer delivers, and an exact PUBLISH proves the surviving leaf remains routed.
A source-hash-locked port of all 23 filter/topic pairs in Mosquitto's
`03-pattern-matching.py` runs each pair under MQTT 3.1.1 and MQTT 5. The 46
process scenarios cover leading and trailing empty levels, repeated separators,
single- and multi-level wildcards, and `foo/#` matching the zero-level `foo`
topic. Each scenario verifies live delivery clears RETAIN, UNSUBSCRIBE suppresses
routing through an exact no-match QoS 1 PUBACK plus PING barrier, resubscribe
replays the retained message with RETAIN set, and an empty retained tombstone is
delivered live but absent after a second resubscribe.
Three additional source-locked negative cases directly port Mosquitto's
`03-publish-bad-flags.py` QoS/retain capability violations and
`12-prop-maximum-packet-size-broker.py` boundary behavior. They compare the
advertised CONNACK properties and exact DISCONNECT `0x9b`, `0x9a`, and `0x95`
packets after raw clients deliberately ignore those limits.
The same source-locked gate ports both QoS companions. From
`12-prop-maximum-packet-size-publish-qos1.py`, a 40-byte client limit drops
two oversized self-deliveries without stalling their publisher PUBACKs or a
subsequent PING; the next fitting PUBLISH is delivered and acknowledged. From
`12-prop-maximum-packet-size-publish-qos2.py`, an oversized released
Application Message is dropped without leaving downstream QoS 2 state, while
the next fitting PUBLISH completes publisher PUBREC/PUBCOMP and the independent
subscriber PUBLISH/PUBREC/PUBREL/PUBCOMP sequence.
Eight additional source-locked MQTT 3.1.1/5 cases port Mosquitto's QoS 0,
QoS 1, and Will Application Message size-limit vectors and add the corresponding
QoS 2 case.
The example broker exposes an
independent `--max-payload-size`; a payload exactly at the boundary is routed,
oversized QoS 0 is discarded while both connections stay usable, and oversized
QoS 1/2 receives MQTT 5 PUBACK/PUBREC `0x83` (Implementation Specific Error,
as documented by Mosquitto) or completes the property-free
MQTT 3.1.1 acknowledgement handshake without downstream delivery.
The pinned Mosquitto checkout and its payload-limit fixture still use `0x95`
in PUBACK despite the packet-specific MQTT 5 reason-code table. This replay
preserves the source payload boundary and delivery checks while requiring
the legal `0x83` acknowledgement instead.
Oversized Wills are refused before Session/Will
registration with MQTT 5 CONNACK `0x95` or legacy v3 CONNACK `0x05`, while a
boundary-sized Will is installed and published after an ungraceful close.
Five more raw cases verify exact `0x94`, `0x93`, `0x9e`, `0xa1`, and `0xa2`
DISCONNECT packets for Topic Alias, Receive Maximum, shared-subscription,
Subscription Identifier, and wildcard-subscription violations. The latter
three cover capability controls that rumqtt's codecs model but the audited
Mosquitto broker does not expose as listener switches.
Another source-locked case combines the wire-observable behavior from
Mosquitto's
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
The shared MQTT 5 CONNACK codec also rejects an explicitly present but empty
Assigned Client Identifier on both parse and write paths, so lower-level users
cannot bypass the same MQTT-3.2.2-16 invariant enforced by the runtime.
The source-locked Server Keep Alive case ports Mosquitto's
`12-prop-server-keepalive.py`
against the new example-broker `--server-keep-alive` policy switch. A client
requests 61 seconds, the exact CONNACK advertises the configured 60-second
replacement after netz's fixed capabilities, and a subsequent PING proves the
negotiated connection remains usable.
Six maximum-Keep-Alive cases source-lock Mosquitto's
`01-connect-max-keepalive.py`, port its MQTT 3.1.1 boundary, and extend it to
MQTT 5.
Requests above 100 seconds and zero (which would disable Keep Alive) receive
legacy CONNACK return code 2 in MQTT 3.1.1, while MQTT 5 accepts them with an
exact Server Keep Alive value of 100. Requests exactly at the limit are
accepted without an unnecessary override, and MQTT 5 PING verifies each
accepted connection remains usable. The policy lives in shared
`runtime.AcceptOptions`, so TCP, TLS, WS and WSS accept paths cannot diverge;
the broker resolves it before Session registration to keep refusals
side-effect-free.
The production configuration gate also checks Mosquitto's `max_keepalive 0`
sentinel for MQTT 3.1.1 and MQTT 5: both accept a client-requested zero Keep
Alive, MQTT 5 omits Server Keep Alive, and PING proves both connections remain
usable.
Three zero-length Client ID policy cases extend the existing assigned-ID
coverage with Mosquitto's `01-connect-zero-length-id.py` deny branch. The
production broker switch rejects clean-start anonymous MQTT 3.1.1 with return
code 2 and MQTT 5 with reason 0x80 before creating Session or Will state; a
named MQTT 5 client then connects and answers PING on the same listener.
The same gate source-locks Mosquitto's Assigned Client Identifier vector and
the complete twelve-connection matrix from `01-connect-auto-id.py`. Six real
two-listener broker configurations prove the `auto-` default, global
`auto_id_prefix` inheritance, listener-local override, and fallback to the
global prefix when only the sibling listener overrides it. Every MQTT 5
CONNACK carries a UUID-shaped identifier with the selected prefix, and the two
listeners never reuse an identifier. The existing simultaneous WebSocket pair
independently checks listener-local assignment and connection takeover
isolation; parser tests enforce the 50-byte and MQTT UTF-8 bounds before any
listener opens.
The deprecated Mosquitto `clientid_prefixes` directive is also supported as a
global admission rule. Explicit MQTT 3.1.1 and MQTT 5 Client Identifiers are
checked before authentication callbacks or Session mutation and receive the
version-correct Not Authorized CONNACK when they do not match. Empty MQTT 5
identifiers are checked again after collision-safe assignment, so a compatible
`auto_id_prefix` succeeds without creating a bypass. Configuration owns and
validates the UTF-8 prefix, rejects duplicates, and rejects the documented
incompatible combination with listener `use_username_as_clientid`. This
deprecated directive participates in the SIGHUP transaction rather than
requiring a restart. The production config gate reloads `secure-` to `next-`,
keeps the already accepted connection usable, rejects clients matching only the
old prefix, accepts clients matching the new prefix, applies the reloaded
`auto_id_prefix` to assigned identifiers, and preserves the committed policy
when a restart-required global change aborts the reload. The focused process
gate is
`zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- --only-required-client-id-prefix`,
which reported `admission=true reload=true rollback=true
existing-connection-retained=true` on 2026-11-02.
Four source-locked malformed-Will cases directly port Mosquitto's
`07-will-no-flag.py` and
`07-will-null-topic.py` for MQTT 3.1.1 and MQTT 5. They remove the complete
Will Payload field while keeping CONNECT's declared length self-consistent, or
supply an empty Will Topic carrying binary payload bytes. Netz rejects every
connection before installing Session/Will state, then accepts a valid MQTT 5
CONNECT and PING on the same finite broker process.
A source-hash-locked companion ports Mosquitto issue 573191's
`07-will-delay-invalid-573191.py`: an empty MQTT 5 Will Topic is rejected with
the precise Topic Name Invalid CONNACK after its Will Delay property has been
decoded. A `std.testing.allocator` codec regression checks that both CONNECT
and Will property allocations are released on this late parse failure, while
the strengthened process case requests a persistent Session, waits past the
declared delay, and proves the same Client ID receives Session Present false
before completing PING on the still-healthy broker.
Two source-locked companion cases port Mosquitto's `07-will-null.py` for MQTT 3.1.1 and
MQTT 5. They distinguish the malformed missing field above from a valid
zero-length Will Payload, then require an exact empty PUBLISH after the source
disconnects ungracefully. A following PINGRESP proves that publication occurs
once and leaves the subscriber connection usable.
The source-locked duplicate Client ID case directly ports Mosquitto's
`01-connect-take-over.py`: the replacement receives a successful CONNACK, the
displaced MQTT 5 peer now receives DISCONNECT `0x8e` (Session Taken Over)
instead of an unexplained EOF, and the replacement remains responsive to
PING. The in-process takeover test also verifies the reason code while
retaining its existing single-subscription-owner assertion.
The source-locked eight-case Will takeover matrix directly ports Mosquitto's
`07-will-takeover.py` across MQTT 3.1.1 and MQTT 5. It combines transient and
durable old Sessions with clean and continuing replacement connections, checks
Session Present and the MQTT 5 takeover DISCONNECT, and proves byte-for-byte
that the old Will is suppressed only when both connections preserve the same
Session. This exposed and fixed zero-delay Wills being published during a live
durable-Session takeover; Will Delay controls publication after disconnect,
not cancellation by a replacement that has already resumed the Session.
The source-locked Session Expiry case ports the timing-observable core of Mosquitto's
`05-session-expiry-v5.py`: a three-second DISCONNECT override keeps a Session
present beyond the one-second CONNECT value, the Session is absent after the
new deadline, and a zero DISCONNECT override removes the replacement
immediately. The source-locked `05-session-expiry-kick.py` crash path now
separately closes TCP without MQTT DISCONNECT after selecting a one-second
expiry, waits while the broker's active deadline driver removes the Session,
then requires Session Present false and a working PING on the same Client ID.
Exact CONNACK bytes distinguish every Session Present transition.
An additional Mosquitto `property__process_disconnect` vector covers
MQTT-3.14.2-2: when CONNECT selected Session Expiry zero, a non-zero
DISCONNECT override receives exact Protocol Error `0x82`. Validation happens
before Will or Session mutation; a real broker test verifies that the invalid
packet still triggers the Will as an ungraceful close and cannot manufacture a
resumable Session.
The established runtime also enforces the complete MQTT 5 Table 3-10 sender
direction for DISCONNECT reason codes before I/O. A client cannot impersonate
server conditions such as Server Busy, Session Taken Over, redirection, or
unsupported capabilities; a server cannot send the client-only Disconnect with
Will Message reason. A table-driven codec test covers every valid reason code,
and a raw client sending Server Busy receives exact Protocol Error `0x82`
before a fresh connection completes CONNECT/PING.
Protocol-negotiation cases mirror Mosquitto's
`read_and_verify_protocol_version`: MQTT 3.1 uses `MQIsdp` plus level 3, while
`MQTT` plus level 3 remains a mismatched-name refusal with the legacy
four-byte Unsupported Protocol Version CONNACK. Level 6 receives MQTT 5 reason
`0x84` with an empty property section, and an invalid protocol name remains a
fail-closed connection error. Real TCP and WebSocket tests complete MQTT 3.1
CONNECT/PING/DISCONNECT, and broker coverage performs QoS 1 subscribe,
self-publish, delivery, and acknowledgement on the same level-3 connection.
The broker also exposes Mosquitto's administrative
`persistent_client_expiration` behavior through both the production config
directive and `persistent_session_expiry_seconds`: it caps a longer MQTT 5
Session Expiry and
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
The configuration gate parses Mosquitto's positive `s/h/d/w/m/y` duration
syntax with checked u32 conversion and fail-closed duplicate, missing-unit,
zero, negative, and overflow handling. Its real MQTT 3.1.1/5 process cases
show Session Present on an immediate reconnect and no Session Present after
the configured one-second offline cap elapses.
The same gate source-locks Mosquitto's
`01-connect-global-max-connections.py` and `01-connect-max-connections.py`,
and separates the live-connection rules
from `global_max_clients`: two listeners share one admitted-client slot, an
excess MQTT 5 peer is closed without a CONNACK, and the second listener can
reuse the slot after the first client disconnects. The strict parser accepts a
positive bound or Mosquitto's `-1` unlimited spelling and rejects zero, other
negative values, overflow, missing values, and duplicate directives. Netz
claims this slot after the transport-specific `PendingSource` has completed
CONNECT parsing; listener worker counts independently bound connections still
in TCP, TLS, WebSocket, or CONNECT setup. The production config runner maps
listener `max_connections` to a separate per-listener admitted-client counter,
keeps one additional accept worker available to close excess peers promptly,
and continues accepting after capacity is released. A fourth process-level
connection proves production service does not stop after the former finite
accept budget. The repository gate's finite test mode uses the same limits
while retaining a separate deterministic accept budget.
The source-locked Clean Start/offline QoS 1 case ports the MQTT 5 branch of
Mosquitto's `05-clean-session-qos1.py`: a persistent subscriber disconnects after
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
Two source-hash-locked MQTT 3.1.1/5 scenarios strengthen Mosquitto's
`02-subpub-qos0-queued-bytes.py` scope check. The standalone broker runs with a
one-byte durable queued-payload limit while a seven-byte QoS 0 Application
Message is routed to an online transient subscriber. Exact CONNACK, SUBACK,
PUBLISH and PINGRESP bytes prove the offline Session budget neither drops nor
duplicates live fanout.
Two source-locked scenarios port Mosquitto's
`03-publish-b2c-disconnect-qos2.py` for MQTT 3.1.1 and MQTT 5. The first
reconnect observes the unacknowledged QoS 2 PUBLISH with its original Packet
Identifier and DUP=1. After PUBREC and a second abrupt disconnect, the next
Session resume starts directly with PUBREL for that identifier instead of
replaying the Application Message. PUBCOMP followed by PINGRESP proves the
second-stage transaction is retired.
Two more source-locked scenarios directly port Mosquitto issue 1322's
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
the fresh connection's receive accounting not recognizing an idempotent
completed transaction; it is now reconciled without depending on the obsolete
MQTT 3.1 PUBREL DUP bit. Both supported versions require the `0x2` PUBREL fixed
flags from MQTT-3.6.1-1.
Four MQTT 3.1.1/5 source-locked scenarios cover Mosquitto's non-standard
`upgrade_outgoing_qos` switch. A retained and an ordinary live QoS 0
Application Message are each delivered at the subscriber's granted QoS 1 when
the opt-in is enabled, with the full PUBLISH/PUBACK exchange checked. The
default remains the MQTT-required minimum QoS, and the same policy is applied
before durable Session enqueueing.
Two source-hash-locked MQTT 3.1.1/5 scenarios derive the wire-observable queue
behavior from Mosquitto's `03-publish-qos1-queued-bytes.py` and its 400-byte
configuration fixture. The example broker now exposes
`--max-session-queued-payload-bytes`; each durable Session tracks queued
Application Message payload bytes independently of its count and total owned
memory bounds. A message that reaches the configured threshold is retained,
later messages are dropped while the publisher still receives its successful
QoS 1 acknowledgement, and reconnect delivers exactly the retained prefix.
Draining or expiring a queued message immediately returns byte budget.
Two companion source-hash-locked MQTT 3.1.1/5 scenarios and one MQTT 5 QoS 2
stress scenario cover the `max_inflight_bytes` behavior in Mosquitto's
`02-subpub-qos2-max-inflight-bytes.py`. A durable subscriber advertises enough
Receive Maximum credit for all messages, but the broker's independent per-Session
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
Both upstream length-test source files are hash-verified before any broker
process starts, so a changed ACK form or terminal expectation cannot silently
retain the old eight-scenario claim.
The source-locked offline Message Expiry case directly ports Mosquitto's
`02-subpub-qos1-message-expiry.py`: two QoS 1 messages with one- and ten-second
lifetimes are queued while a persistent subscriber is disconnected. After two
seconds, reconnect reports Session Present, omits the expired message, delivers
only the survivor with its interval reduced to a timing-tolerant 9-6 seconds,
and answers PING immediately after its PUBACK to rule out a stale second
delivery.
The source-locked companion Will Message Expiry case directly ports Mosquitto's
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
Two companion source-locked cases directly port Mosquitto issue 1273's
`07-will-reconnect-1273.py` for MQTT 3.1.1 and MQTT 5. A durable client sends a
normal DISCONNECT after installing a Will, reconnects with the same Client ID
and a replacement Will, and receives Session Present. Exact live PUBLISH bytes
on both sides of the reconnect plus an ordered PINGRESP prove the canceled old
Will is never resurrected.
Three companion source-locked cases port Mosquitto's
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
Information suppression while preserving an exact negative PUBACK reason. A
deep-topic case then goes one level beyond Mosquitto's implementation-specific
200-level hierarchy cap while remaining far below MQTT's 65,535-byte UTF-8
field limit; exact SUBACK and self-delivered PUBLISH bytes prove netz retains
standards-valid iterative routing. A companion MQTT 5 case exercises a flat
65,535-byte Topic Name—the maximum representable UTF-8 field—through a
multibyte Remaining Length, exact SUBACK, routing, and byte-identical
self-delivery. Two source-hash-locked issue-1412 companion cases exercise a
65,535-byte Topic Filter made entirely of empty slash-separated levels under
MQTT 3.1.1 and MQTT 5. Both complete SUBSCRIBE and exact self-delivery, then
complete a multibyte-length UNSUBSCRIBE and use PUBACK plus PINGRESP as an
ordered barrier proving route removal and connection health. This deliberately
validates MQTT's full UTF-8 field limit rather than copying Mosquitto's private
200-level rejection policy. The shared public Topic Name and Topic Filter
validators also reject 65,536-byte inputs before router mutation or packet
output, while accepting the 65,535-byte boundary. The outbound QoS 2 gate also
directly ports Mosquitto's source-hash-locked Receive Maximum 1 and 2 cases
with three messages each. It
fills the negotiated window, proves the next PUBLISH remains withheld through
PUBREC/PUBREL, returns one slot only at PUBCOMP, and requires each queued
PUBLISH immediately after that release. The source-locked QoS 1 inflight-expiry
case ports Mosquitto's `03-publish-qos1-max-inflight-expire.py`, keeps
an expiring delivery unacknowledged at Receive Maximum 1, then proves its
expiry releases credit for the next queued delivery without a stale PUBACK.
The QoS 2 inflight-byte case additionally proves that PUBREC alone does not
release payload-byte credit: the queued PUBLISH appears only after PUBCOMP,
and four cycles verify that the byte accounting is reusable. The inbound QoS 2
overflow case now covers both protocol versions and the exact advertised
Receive Maximum: MQTT 5 receives DISCONNECT 0x93, while MQTT 3.1.1 closes
without an unrepresentable reason packet. Server-side admission enforces the
configured inbound limit in MQTT 3.1.1 even though only MQTT 5 can advertise it
as a CONNACK property. All 287 curated scenarios pass. The MQTT 3.1 additions
also verify successful 23-character ASCII and multibyte Client Identifiers and
the required Identifier Rejected CONNACK for 24 characters. They additionally
exercise retransmitted PUBREL, SUBSCRIBE, and UNSUBSCRIBE packets with the
version-3.1 DUP bit while retaining strict 3.1.1/5 fixed-header validation. A separate
source-hash-locked adapter now executes every scenario in Mosquitto's complete
`AUTH.json`, `CONNECT.json`, `CONNACK.json`, `DISCONNECT.json`, `FLOW.json`,
`FORBIDDEN.json`, `OTHER.json`, `PINGREQ.json`, `PINGRESP.json`,
`PUBACK.json`, `PUBREC.json`, `PUBREL.json`, `PUBCOMP.json`, `REGRESSION.json`,
`SUBACK.json`, `SUBSCRIBE.json`, `UNSUBACK.json`, `UNSUBSCRIBE.json`, and
`PUBLISH.json` files: 1,825 upstream scenarios across MQTT 3.1, MQTT 3.1.1 and
MQTT 5. The nine formerly excluded level-3 CONNECT/CONNACK cases now run in
isolated broker processes, preserving the upstream harness's fresh-broker
Session Present assumptions without rewriting its byte-exact expectations.

`PUBLISH.json` is now complete at 160/160. Its two `QoS 2 Dup flow*3`
scenarios encode Mosquitto's private finite tolerance for repeated non-DUP
PUBLISH packets, which conflicts with MQTT 3.1/3.1.1/5 receiver retransmission
semantics. The adapter therefore uses two source-locked standards replays: it
verifies each entire original action list and inherited close expectation,
preserves all three source PUBLISH packets, requires PUBREC after each one,
then sends PUBREL, requires PUBCOMP, and proves the connection remains live.
Any group, test, occurrence, byte sequence, or terminal-policy drift fails the
gate rather than silently weakening this correction.
The entire upstream file hashes, exclusion identities, reason vocabulary, and
per-file included counts are independently asserted, so upstream fixture
additions or renamed exclusions fail closed.

The gate also retains 259 upstream scenarios whose packets are portable but
whose expected DISCONNECT reason conflicts with the MQTT 5 text. Each audited
override names the exact `(file, group, test, action index)`, verifies the
hash-locked source action still expects its original bytes, and substitutes one
exact expected packet before the normal socket comparison. One hundred fourteen
cover section 2.2.2.2: a known Property Identifier used in a Control Packet where it is not
valid is Malformed Packet `0x81`, while Mosquitto's PUBACK, PUBREC, PUBREL,
PUBCOMP, and PUBLISH fixtures expect `0x82`. Four PUBREL reserved Fixed Header
flag cases likewise retain the `MQTT-2.1.3-1` Malformed Packet classification.
Four AUTH reserved-flag cases use the same rule, and one truncated AUTH
variable header retains Malformed Packet `0x81`. Four DISCONNECT reserved-flag
cases, 22 disallowed DISCONNECT Property cases, and five invalid/truncated
CONNACK header cases follow the same classifications. Three PUBLISH Topic Name
cases, nine fully
parsed SUBSCRIBE semantic cases, and four UNSUBSCRIBE cases covering an empty
payload (`MQTT-3.10.3-2`), zero-length Topic Filters (`MQTT-4.7.3-1`), and
Packet Identifier zero (`MQTT-2.2.1-3`) retain Protocol Error `0x82` where
Mosquitto expects `0x81`. Thus these are still executed byte-level scenarios,
not exclusions or permissive comparisons. Two further exact replacements cover
the semantically equivalent deterministic ordering of configured CONNACK
properties. The CONNECT subset adds 50 Property Context corrections, seven
malformed or strict-policy UTF-8 Client Identifier corrections, and 30
equivalent successful CONNACK property-order replacements. Eleven source cases
that only require EOF also accept one exact pre-close `CONNACK 0x81`, as
permitted by MQTT 5 section 3.1.4; these are separately enumerated rather than
accepted through a wildcard.
All source bytes, replacement bytes, identities, reasons, and the aggregate
259-replacement count are locked. The gate launches netz with the
fixture's Receive Maximum 20, Maximum Packet Size 2,000,000, and Topic Alias
Maximum 10, plus the explicit Mosquitto-compatible strict UTF-8 policy. The base
wire codec always rejects MQTT-forbidden NUL and Unicode noncharacters; the
explicit policy additionally rejects discouraged C0/C1 controls on CONNECT
identity and Will fields and on later PUBLISH/SUBSCRIBE/UNSUBSCRIBE topic fields.
The default runtime policy continues to accept those discouraged control
characters. Both formerly configuration-dependent PUBLISH scenarios
and the DISCONNECT Session Expiry transition therefore execute instead of
being excluded.
Strict connection validation now applies the same control-character policy to
every MQTT 5 UTF-8 property string and User Property key/value in CONNECT,
Will, CONNACK, PUBLISH, acknowledgements, subscription controls, DISCONNECT,
and AUTH; Binary Data remains opaque. This closes the previous gap where only
identity, Will Topic, Topic Name, and Topic Filter fields received the
configured Mosquitto-compatible check. Both client connect and server accept
options expose the policy, so every peer direction has the same boundary.
The adapter preserves the upstream payload DSL, group/test inheritance,
explicit response bytes, connection-liveness expectations, and MQTT 3.1.1
helper publications with full QoS 0/1/2 handshakes; it rejects other
non-portable action types instead of silently skipping them. Where an upstream
MQTT 5 case requires only EOF,
the adapter additionally permits one exact `0x81`/`0x82` diagnostic before
requiring closure, consistent with MQTT 5 section 4.13. The complete files
exposed three runtime gaps: reserved Control Packet type zero now has a
distinct error and is rejected from the first byte before an independently
malformed Remaining Length can overwrite its Protocol Error classification;
unknown and multi-byte Property Identifiers are parsed as Variable Byte
Integers and classified as Malformed Packet; and the broker now handles stale
but well-formed QoS acknowledgments idempotently. Unknown PUBACK/PUBCOMP are
ignored, while an accepted unknown PUBREC receives its required same-ID PUBREL;
wrong-stage identifiers remain errors and no inflight accounting is released.
The FLOW file additionally exposed that duplicate successful PUBREC must
retransmit PUBREL without changing its inflight stage, and that established
MQTT 5 connections must receive Protocol Error `0x82` before closing on a
wrong-stage acknowledgement. `OTHER.json` adds exact MQTT 3.1.1/5 wire
coverage for self-delivery at QoS 1/2, retained delivery and deletion, No Local,
negative downstream PUBREC, and PUBLISH property propagation. It exposed one
observable ordering gap: for a QoS 1 self-publish, Mosquitto writes the routed
PUBLISH before the publisher PUBACK. Netz now pre-flushes only the publisher's
own matched slot before its PUBACK; unrelated slow subscribers remain queued
and cannot delay that acknowledgement. The finite conformance broker now
preserves concurrent accepts while aggregating and ignoring expected
per-connection errors, allowing the upstream helper publisher to overlap its
subscriber.
The PUBLISH subset exposed three further broker boundaries. Network clients are
now denied writes to broker-owned `$SYS` and `$share` namespaces by default,
while Mosquitto's `$SYS/broker/connection/+/state` bridge-status shape and
ordinary dollar-prefixed application topics remain permitted. The policy is
explicitly configurable and checks both the client-visible and listener-mapped
canonical topic, so a mount prefix can neither hide nor inject a reserved
namespace. It suppresses protected client Wills after CONNECT authorization
but before they enter persistent Session state, and does not restrict trusted
`Broker.publishLocal` system metrics. Parsed PUBLISH,
SUBSCRIBE, and UNSUBSCRIBE semantic failures now pass through the broker's MQTT
5 DISCONNECT mapper instead of closing with unexplained EOF; an illegal
client-originated Subscription Identifier is rejected by the shared connection
runtime before Topic Alias or QoS state can change and is independently
verified as `0x82`; server-originated delivery identifiers remain valid.
Inbound PUBLISH admission is transactional across connection-scoped Topic
Alias and QoS Packet Identifier state: semantic rejection cannot replace an
alias, and an alias-allocation failure rolls back a newly reserved inflight
slot.
Outgoing Topic Alias registration completes all fallible local allocation
before transport I/O. Once a TCP, TLS, or WebSocket write is attempted, any
error permanently retires that Network Connection: stream APIs cannot prove
whether zero, some, or all bytes reached the peer, so neither alias mappings
nor other connection-scoped state may be reused. Reconnect creates fresh alias
tables while durable QoS retransmission remains Session-scoped.
Broker and reconnect Session retransmissions now project their canonical
stored Topic Name through that fresh connection-local table: the first send
carries the full Topic Name plus alias, later sends may omit the Topic Name,
and a reconnect establishes it again. The borrowed payload is sent separately
from the encoded prefix, and an automatic alias representation that would
exceed Maximum Packet Size falls back to the original full-topic packet.
The owning reconnect client also retires this unusable handle immediately
across publish, subscribe, unsubscribe, manual acknowledgement, keep-alive,
authentication, and graceful-disconnect paths. The decision uses the runtime's
transport-origin marker rather than matching error names, so purely local
validation and allocation errors before wire interaction leave the established
connection available for correction.
The reconnect poller also maps peer-originated parse/direction violations to
the same audited reason table used by the broker. MQTT 5 clients make a
best-effort DISCONNECT before retiring the connection (with server-only reason
codes reduced to Protocol Error); MQTT 3.1.1 clients close directly. Once an
event has been consumed, state/allocation or authentication-callback failure
also retires the connection silently because the event cannot be replayed. A
valid negative PUBACK/PUBREC/PUBCOMP remains an application result and leaves
the connection usable.
An unnegotiated live AUTH now follows the same diagnostic boundary, and normal
or failing AUTH handlers share the connection's writer mutex with fanout so
their packets cannot interleave. Finally,
inbound QoS 2 retains the first Application Message for an identifier until
PUBREL: every later same-identifier PUBLISH receives PUBREC regardless of DUP,
but conflicting bytes cannot replace or duplicate the original delivery.
The SUBSCRIBE audit additionally corrected the parser's reason boundary. A
well-formed Property Identifier used outside its allowed Control Packet context
now has a distinct wire-parse error and produces Malformed Packet `0x81` across
CONNECT/Will/CONNACK/PUBLISH/ACK/SUBSCRIBE/SUBACK/UNSUBSCRIBE/UNSUBACK/
DISCONNECT/AUTH parsing, while local encoder APIs retain their existing
`InvalidProperty` contract. A complete Topic Filter missing its following
Subscription Options byte is likewise malformed. MQTT 3.1.1 reserved
Subscription Options and QoS value 3, plus MQTT 5 reserved bits 6/7, map to
`0x81`; parsed MQTT 5 Maximum QoS 3, Retain Handling 3, an empty subscription
payload, empty filters, and Packet Identifier zero remain Protocol Error
`0x82`. A real broker test verifies the `0x81`/`0x82` split over two independent
connections.
Run it against the audited Mosquitto `5cd25465` checkout with:

```sh
zig build interop-mqtt-mosquitto-packet-sequences -Doptimize=ReleaseFast -- \
  --mosquitto-test-root=/nav_env/Work/mosquitto/test
```

The manifest pins SHA-256 hashes for all nineteen complete JSON inputs and the
imported `mqtt_packets.py` generator, so a changed
upstream fixture cannot silently reuse the recorded scenario count.
The CONNECT gate also permits twelve exact MQTT 5 Malformed Packet
diagnostics where Mosquitto's fixture only requires EOF, including the case
whose group label says v3.1.1 but whose wire-level protocol byte is `05`.
This remains a packet-file gate rather than a claim over Mosquitto's entire
Python harness, which hardcodes its own `-v -c/-p`
broker CLI and many tests depend on configuration outside netz's strict subset,
logs, reload, persistence details or plugins, so passing these vectors is not
proxy evidence for the entire suite.

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
   usable after checkpoint, followed by restore. The production example accepts
   `--autosave-interval-seconds=N` and `--autosave-change-count=N`; the latter
   counts broker operations that change snapshot-backed durable state instead
   of elapsed time, providing the first bounded Mosquitto-style
   `autosave_on_changes` policy surface. The process gate above proves
   a periodic checkpoint survives forced termination with both subscription
   metadata and an opt-in offline QoS 0 delivery intact. The append journal
   closes the interval between checkpoints for protocol-visible durable
   mutations. Cross-node replication/consensus remains separate work.
2. Reduce the production broker deficits exposed by the five-shape
   publisher-window, latency, allocation and RSS matrices above. Netz currently
   trails Mosquitto across the measured QoS 2 shapes and in several QoS 1
   shapes, while broker RSS remains an active deficit. QoS 2 and its completed
   3,600-second durable-Session variant now use the same artifact, CPU, order,
   completion and queue-capacity controls. The durable matrix also trails
   Mosquitto across all five shapes, so scheduling, tail latency, and
   per-connection memory remain active work.
   The connection-local Packet Identifier tracker now replaces five embedded
   65,536-bit tables (40 KiB in every connection, even before QoS traffic)
   with independent incoming/outgoing sparse stage maps. Each direction
   promotes transactionally after 1,024 live identifiers to bounded packed
   tables, retaining the complete 1..65,535 identifier space without allowing
   stage-map hash overhead to grow without bound. Incoming stages use 16 KiB;
   outgoing stages now use 32 KiB to cover subscription commands as well as
   QoS PUBLISH, with expected control-response counts allocated only when
   needed. Incoming and outgoing maps
   remain physically separate for the runtime's concurrent reader and
   serialized writer, while QoS 2 stage transitions are allocation-free. A
   five-pair, CPU-0/1, fixed-binary 32-publisher/32-subscriber comparison
   (`0b51301a` baseline, `09825721` candidate) with
   window 4, 64-byte payloads, 10 warmups and 200 measured publishes reduced
   the netz broker's 2-ms sampled peak RSS from 36,348-36,364 KiB to
   6,352-6,368 KiB (82.5% by medians). Every arm completed 6,400 measured
   deliveries with the same checksum; candidate throughput was higher in all
   five short runs, but the small workload is retained as memory evidence, not
   a throughput claim. The `MQTT_STATS=true` mode of
   `zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast` now emits
   validated broker-process RSS records. Finite broker admission now keeps
   the parsed pending client on the heap, isolates certificate, refusal,
   accepted-client and Session setup frames from the parked read loop, and
   prewarms a live delivery queue only before a restored or new subscription
   becomes routable; the configured queue bound and allocation-free route
   commit remain unchanged. Seven `c3fe1516`
   parent/current 64-connection runs measured netz at
   5,868-7,844 / 5,884-5,948 KiB
   (6,188 / 5,932 KiB medians, a 4.1% reduction) and Mosquitto at
   3,820-3,916 / 3,800-3,904 KiB (3,904 / 3,808 KiB medians). The parent's
   roughly 7.8-MiB netz outlier is retained in the range. The median
   netz-minus-Mosquitto gap fell from 2,284 to 2,124 KiB (7.0%). Every arm
   retained 6,400 deliveries and checksum 356,160. The independent-peer
   memory gap therefore remains.
   A later `/proc/PID/smaps_rollup` capture separated a 64-connection
   balanced run's 11,276-KiB RSS into 8,848 KiB anonymous and 2,428 KiB
   file-backed memory. The largest anonymous mapping was 4,864 KiB, matching
   the per-slot cost of an inline maximum-sized MQTT transport union. Boxing
   only its WebSocket member reduced the verified full-matrix netz RSS in all
   five shapes, including 10,948 to 10,236 KiB for balanced 32×32. Mosquitto
   still uses materially less memory in every shape, so connection-state
   sizing remains active work.
   Broker admission now also keeps the runtime Connection out of the
   preallocated capacity table and allocates the maximum 86-byte generated
   Client ID only for clients that actually connect with an empty ID. The
   48-byte listener ACL descriptor is likewise allocated only for connections
   whose listener configures an overlay. A trusted PROXY listener now owns its
   296-byte parsed metadata descriptor out of line; direct TCP, TLS, WebSocket,
   and WSS connections retain only an optional pointer. The 88-byte queue,
   cursor, and overflow record used by blocking `ping*` calls is likewise
   allocated before the first PINGREQ, so broker connections and event-loop
   clients do not reserve it. The incoming/outgoing Packet Identifier
   descriptors and the two 32-byte Topic Alias tables also keep independent
   lazy pointers, matching the runtime's concurrent-reader/serialized-writer
   ownership while avoiding each structure until its direction first needs a
   Packet Identifier or an alias mapping. Finally, each established connection keeps
   a 16-byte projection of the 64-byte public `Limits`: socket tuning, PROXY
   parsing policy, and admission timeout remain in listener/connector state,
   while packet size and blocking-PING queue size survive in that projection;
   the remaining certificate-identity bit joins the connection's existing
   flags. Connection-owned mount prefixes omit the general Namespace ownership
   flag, Enhanced Authentication stores its already allocated method using the
   protocol's u16 string length instead of a second machine word, and assigned
   Client IDs plus listener mount prefixes likewise reuse their allocations
   through pointers and MQTT-bounded u16 lengths. Negotiated QoS and
   availability flags share one 16-bit capability word; the complete raw
   CONNECT protocol-level byte keeps its optional presence in that same word,
   so malformed values such as zero remain distinguishable from an unread
   level. The TCP transport retains a 448-byte, seven-cache-line read-ahead
   region that still covers the benchmark's complete four-packet small-message
   window; larger packets keep their exact-allocation fallback. None of these
   changes adds an allocation. Stack-first outgoing property staging now keeps
   eight descriptors in caller storage and retains only an exact overflow
   slice for larger sets. Together these changes reduce the audited 64-bit
   `runtime.Connection` from 1,408 to 784 bytes (624 bytes saved per ordinary
   QoS 0 live connection without aliases). The
   four delivery/route/Session
   scratch lists, transient QoS map, counters, and optional delivery-writer
   pointer now share one 152-byte `ClientBuffers` descriptor allocated only
   when a connection first subscribes, publishes through the router, or writes
   Session state. Disconnect destroys that descriptor and all retained queue,
   scratch, and map capacity instead of leaving it attached to an idle reusable
   slot. The slot's generated Client ID uses its existing allocation through a
   pointer plus the generator's bounded u7 length, and the borrowed CONNECT
   username uses a pointer plus its MQTT-native u16 length. Both lengths, the
   31-bit connection generation, and the active/Session/graceful flags share
   one u64. The same word holds presence bits for the 16-byte Session and Will
   handles and the optional retained-source identity, avoiding all three
   optional tags. On the audited 64-bit target these changes reduce each idle
   `ClientSlot` from 1,824 to 96 bytes; the default 1,024-slot broker therefore
   reserves 1,769,472 fewer bytes before clients connect. Stable Connection
   storage is allocated after CONNECT policy checks and before Session
   admission, then transferred to the slot after successful CONNACK. Generated IDs, optional ACL
   metadata, and client buffers remain owned until the client task releases its
   borrowed policy/CONNECT views, and all optional storage is freed on
   rollback, disconnect, or broker destruction. Raw TCP, TLS, WebSocket,
   Client ID takeover, generated-ID reuse, ACL denial, buffer-allocation
   rollback, PROXY, blocking-PING, Topic Alias and Packet Identifier two-stage
   allocation failure/transfer, compact-limit projection, and allocator leak
   tests cover the ownership paths. Fully occupied brokers that publish or
   subscribe still retain the required Connection and buffer state, so the
   slot result is deterministic capacity-headroom plus disconnected-retention
   evidence; the Connection reduction also applies to steady-state non-PROXY
   clients that use the event-driven keep-alive path and have not installed
   aliases or QoS state.
   The broker's Will publisher association index now follows the same
   demand-driven rule. Broker initialization no longer reserves the configured
   65,536-Will maximum when no CONNECT has supplied a Will. A Will-bearing
   registration reserves its one prospective entry before Session or Will
   state changes, so allocation failure retains the existing atomic rollback
   boundary and the later commit remains allocation-free. Four-sample ABBA
   process captures for both one and 64 idle MQTT connections reduced anonymous
   RSS by 132 KiB at the median in both shapes, with non-overlapping ranges.
   A separate eight-arm fixed-binary ABBA used CPUs 0/1/2 for client, server,
   and 2-ms RSS sampling; 32 publishers, 32 subscribers, a four-message window,
   256 warmups, 3,200 measured durable QoS 2 publishes, 102,400 verified
   deliveries, 64-byte payloads, and 3,600-second Sessions. The baseline
   `784f299fde94049ac2ba4701fa2dbbaad8adbac7bf41c6f31e613281cd446885`
   and candidate
   `8c3a87ea92bb343776c04549d170b5f9ed1a4f8e46f81dcf56465ab8e0287b8f`
   moved median peak RSS from 7,914 to 7,608 KiB (3.87%); the candidate's
   7,676-KiB maximum remained below the baseline's 7,720-KiB minimum.
   Throughput medians were identical at 3,056 publishes/s, while p50 and p99
   median ratios were 1.0021x and 0.9979x. This is a fixed broker-state memory
   result, not a general durable QoS 2 throughput claim.
   The broker-wide inbound QoS 2 transaction map is now demand-driven as well.
   Initialization no longer reserves all 4,096 entries; a first non-duplicate
   PUBLISH reserves one map slot before allocating or owning Pending message
   state, so map OOM leaves no transaction while the later exactly-once commit
   remains allocation-free. Broker allocator telemetry now emits every exact
   allocation above 64 KiB. A serial durable QoS 2 capture removed the
   1,318,944-byte startup block: total requested bytes fell from 1,856,191 to
   538,047 and peak live bytes from 1,611,966 to 293,822, with every byte freed.
   The remaining 245,920-byte fixed block belongs to the independent bridge
   QoS 2 store. Four-sample ABBA `/proc` captures reduced anonymous RSS by 16
   KiB at one idle connection and 14 KiB at 64 idle connections. An eight-arm
   CPU-0/1/2 fixed-binary durable 32x32 comparison used the same 256 warmups,
   3,200 measured publishes, four-message publisher window, 64-byte payloads,
   102,400 verified deliveries, and 3,600-second Sessions. Baseline
   `edf1b553ca25b260b90e6c467255178116054c5ad72ec0aab3e8f4f40b9d7811`
   and candidate
   `7084703e42f344fb80c61755b28582992de014dc7806632b6a03f32441eaaf08`
   moved median peak RSS from 7,576 to 6,362 KiB (16.0%); the candidate's
   6,572-KiB maximum remained below the baseline's 7,552-KiB minimum.
   Throughput medians were 3,072 and 3,072.5 publishes/s, while p50 and p99
   median ratios were 1.00005x and 0.9940x. The map therefore grows to the live
   transaction set without weakening duplicate detection, Receive Maximum, or
   PUBREL exactly-once routing.
   The independent bridge QoS 2 store now applies the same rule to both its
   transaction and Session-epoch arrays. A new transaction reserves an entry
   before owning its mapped PUBLISH; a new bridge epoch reserves its marker
   before mutation; snapshot restore reserves only the encoded epoch/entry
   counts. Replacement remains capacity-neutral, and `complete` retains the
   removed slot so durable-deletion failure can still restore a released
   tombstone with `appendAssumeCapacity`. Serial allocator telemetry removed
   the final 245,920-byte startup block: total requested bytes fell from
   538,559 to 255,655 and peak live bytes from 294,334 to 11,430, with no
   allocation above 64 KiB and zero live bytes after teardown. Baseline
   `128bcae103655462bc3c922f2de1a8a29e99b63d8c5d5a5a2c5bc656428da207`
   and candidate
   `fa4a480eb94ed82c41afe3647319cd7bbe881d85fbfed7d4b4ac4303891446ea`
   four-sample idle ABBA captures reduced anonymous RSS by 8 KiB at one
   connection and 6 KiB at 64 connections. A separate eight-arm ordinary
   durable 32x32 control produced median throughput, p50, and p99 ratios of
   0.9988x, 0.9919x, and 1.0004x; its RSS ranges overlapped, so the result is
   retained as allocator/startup-memory evidence rather than an active-RSS or
   throughput claim. Durable inbound/outbound bridge QoS 2 fuzz targets over
   TCP and authenticated TLS preserve stage/duplicate/release/rollback,
   Session-loss, epoch, snapshot, and configured-bridge behavior.
   The complete two-Mosquitto outbound matrix additionally exposed a finite-
   runner shutdown race: a valid control byte could close reconnect clients
   before the control task set its Event, surfacing `ConnectionUnavailable`
   after PUBCOMP. The production run loop now gives an observed shutdown
   precedence over transport errors, while the finite tool awaits the control
   task and treats already-closed endpoints as an idempotent disconnect. The
   complete v3.1.1/v5 QoS 0/1/2, restart, Session-loss, negative-PUBREC, delayed-
   ACK, and topic-remap Mosquitto matrix now exits cleanly.
   Delivery policy dispatch keeps the owned global/listener callback tables
   behind borrowed pointers and resolves a destination Session's Client ID only
   when one of those tables actually supplies a delivery callback. Retained
   replay uses the same stack-first property staging and retained overflow
   rather than allocating and freeing a temporary list for every stored
   message. A fail-on-first-allocation test proves common stack reuse while
   preserving Message Expiry rewriting; the fixed five-shape broker comparison
   remained within its existing mixed run-to-run range, so this is allocation
   and code-path evidence rather than a throughput claim.
   Subscriber delivery backing now follows the same demand-driven principle as
   Mosquitto's per-client message nodes: SUBSCRIBE prewarms only the common
   16-message asynchronous window rather than the configured hard maximum.
   Route preflight first reclaims any consumed prefix, then grows geometrically
   but never beyond that maximum; every fallible allocation precedes the
   Publication and queue commit, so failure cannot expose a partial fanout.
   The queue append itself remains allocation-free. On 64-bit targets each
   `Delivery` is 48 bytes, so the 2,048- and 3,200-message benchmark limits no
   longer reserve 96 and 150 KiB respectively for every subscriber before a
   backlog exists. Three fixed-binary QoS 1 allocator samples kept allocation
   calls unchanged in all five shapes while reducing fanout-32 median peak live
   bytes from 9,164,653 to 6,043,501 (34.1%) and balanced-32x32 from
   11,131,511 to 7,658,907 (31.2%). With 3,600-second durable QoS 2 Sessions,
   which do not use this transient queue for QoS 1/2 delivery, the corresponding
   reductions were 9,197,580 to 6,081,916 (33.9%) and 11,098,901 to
   6,203,237 (44.1%). All 60 allocator runs freed every counted byte. Complete QoS 1,
   transient QoS 2, and durable QoS 2 four-sample matrices preserved exact
   delivery counts and checksums across all 240 broker runs; their timing moved
   in both directions, so
   this is a memory result rather than a general throughput claim.
   Persistent Sessions now also maintain one conservative earliest Application
   Message expiry deadline. Enqueue and single-packet drain return immediately
   from expiry pruning when no message has an expiry or the deadline is still
   in the future, instead of walking both queued and inflight arrays. Once due,
   the existing exact scan removes expired PUBLISH records and repairs the next
   deadline; a stale early deadline after ACK/drop is safe. Snapshot restore and
   QoS 0 write rollback both rebuild the hint, while QoS 2 records awaiting
   PUBCOMP remain deliberately non-expiring. A fixed-binary, CPU-0/client and
   CPU-1/server, seven-pair AB/BA test used 32 publishers, 32 subscribers, a
   four-message publisher window, 1,000 warmups, 10,000 measured QoS 2
   publishes, 320,000 verified deliveries, and 3,600-second Sessions. The
   candidate won throughput and p99 in five of seven pairs; median paired
   candidate/baseline ratios were 1.014 for throughput and 0.976 for p99.
   Allocation counts and bytes were identical. This is a modest targeted
   no-expiry fast-path result, not closure of the broader durable QoS 2 gap.
   Multi-destination offline fanout now mirrors Mosquitto's shared base-message
   ownership more closely. One reference-counted broker Publication owns the
   immutable Topic Name and payload while every Session continues to own its
   QoS, Retain flag, Subscription Identifiers, expiry accounting, Packet
   Identifier state, logical byte budget, and snapshot representation. Online
   Session delivery normally keeps the established storage-cache path, avoiding
   the per-source allocation cost measured by a rejected all-destination
   sharing prototype. When a multi-destination QoS 1 TCP PUBLISH already owns
   a packet allocation with a `Publication`-sized prefix, however, the broker
   transfers that allocation into one Publication shared by online durable
   Session entries and transient destinations. Borrowed small packets do not
   activate this exception. A new `bench-mqtt-session` AB/BA sub-benchmark
   holds 256 messages for 64 offline Sessions. Its seven-pair median measured
   336 versus 812 ns per
   destination, while backing allocations fell from 16,896 to 768 (95.5%) and
   incremental live bytes from 11,345,920 to 3,052,544 (73.1%). All logical
   16,384 deliveries remain independently accounted and teardown returns the
   counting allocator to zero. The benchmark binary and captured output hashes
   are `a2bfe1e2a2e8a14afe3724641180f7f60cf1e906c40193a29e52ad4881b56020`
   and `07630da78b56333ae2c31f4dae44fc61b924edd81005fcbc764d951fd48eb6f9`.
   A seven-sample fixed-binary QoS 1 durable allocator comparison kept the four
   stack-buffer shapes at baseline levels and reduced the 4-KiB shape from
   2,370 to 2,331 allocations, 15,495,237 to 15,175,749 cumulative requested
   bytes, and 6,322,177 to 6,032,215 peak live bytes. All 70 broker runs ended
   with zero live bytes. A separate seven-pair, long fixed-binary A/B completed
   40,000 deliveries per arm with checksum 10,780,000; median throughput moved
   from 19,090 to 19,362 publishes/s, the median paired ratio was 1.017, and the
   candidate won all seven pairs. This supports the targeted large-packet path,
   not a general broker throughput claim.
   Released inbound QoS 2 transactions now extend the same shared ownership to
   durable fanout without first allocating and copying another base message.
   When persistent Sessions and multiple subscriptions make that route
   possible, pending storage reserves an aligned Publication header; PUBREL
   converts it in place, and the last concurrent destination release returns
   it to the bounded pending cache through a synchronized allocator adapter.
   The Session Store tracks persistent Session presence in O(1), while route
   selection remains correctly deferred until PUBREL. Single-subscription and
   pure transient brokers retain their prior storage path; this excludes a
   measured transient large-payload regression from the adopted design.
   Seven-sample fixed-binary durable allocator captures reduced fanout-32 from
   833 to 745 allocations (10.6%), balanced-32x32 from 1,242 to 1,181 (4.9%),
   and the 4-KiB shape from 2,431 to 2,400 allocations while reducing its
   cumulative requested bytes 1.4% and peak live bytes 3.4%. A three-sample
   transient control kept allocation counts and cumulative bytes unchanged in
   all five shapes. A final seven-pair 4-KiB durable A/B completed 40,000
   deliveries per arm with checksum 10,780,000; the candidate won every pair
   and moved median throughput from 11,133 to 11,241 publishes/s (1.0%). This
   is a targeted ownership/copy result rather than closure of the broader
   durable QoS 2 scheduling gap.
   [Shared Publication metadata](../mqtt_shared_properties.md) now extends this
   ownership to source property strings and binary values. Each Session keeps
   independent descriptors, subscription identifiers, expiry and logical byte
   accounting; unrelated or reordered caller metadata is still deep-owned.
   A four-pair fixed-binary 64-Session/256-message comparison reduced the
   metadata/shared row from 100,608 to 18,688 allocations and 32,520,448 to
   6,650,112 incremental live bytes, with a paired median enqueue-time ratio
   of 0.2975. All 224 benchmark records validated content and zero teardown
   bytes. Empty-property controls retain identical allocation/byte counts.
   Exact QoS 1/2 production snapshot peers additionally found and guard a
   baseline packet-adoption bug: compacted Topic/payload bytes could overwrite
   old parser property slices before subsequent destinations copied them.
   A stable complete source metadata view now follows Publication adoption,
   preserving properties for routing and ACLs. These are Session-store memory
   and correctness results; process RSS and whole-broker throughput are not
   established by this benchmark.
   Session drain now keeps its current-connection Receive Maximum usage as
   explicit bounded state instead of counting sent PUBLISH records across the
   inflight array on every call. The counter excludes unsent/retry PUBLISH and
   `await_pubcomp` PUBREL state, resets across disconnect/restore, and is
   exported through per-Session and aggregate statistics. A 16,384-inflight,
   seven-pair fixed-binary microbenchmark reduced full-window empty-drain time
   from 62,906 to 38,136 ns by medians (paired median 0.6058x, 7/7 wins).
   Ordinary-window durable QoS 2 end-to-end throughput stayed neutral across
   the five fixed shapes at 0.9993x, 1.0080x, 0.9886x, 1.0043x and 1.0034x.
   A follow-up adds an exact pending-send count and a conservative lowest-slot
   cursor, preserves slot-order retransmission, and replaces the independent
   empty-slot count with `items.len - inflight_count`. With no pending
   retransmission, the same 16,384-inflight drain is now independent of the
   array length: a seven-pair fixed-binary run moved from 42,261 ns to 10 ns by
   medians (paired median 0.0002366x, 7/7 wins). Blocked PUBREL or an actually
   pending suffix still requires work proportional to the candidates examined;
   this is not presented as an end-to-end 4,226x claim. The final ordinary-
   window durable QoS 2 control remained neutral at 1.0035x, 0.9999x, 1.0142x,
   0.9982x and 1.0158x across the five fixed shapes.
   A subsequent ordering audit caught an independent MQTT-4.6.0-1 violation:
   after an early acknowledgement created a reusable low array slot, a newer
   PUBLISH could occupy that slot and replay before older unacknowledged
   messages. Inflight entries now carry an allocation-free circular order
   chain, and both reconnect drain and snapshot serialization follow it rather
   than physical slot order. A regression proves `two,three,four` after the
   former `four,two,three` hole-reuse case through both direct reconnect and
   restore. The links consume existing alignment padding (`Inflight` remains
   128 bytes and `Session` 400 bytes). Seven fixed-binary Session pairs kept
   resume at 1.000x and reconnect drain at 0.9969x by paired medians; a final
   five-shape durable QoS 2 control remained mixed at 0.9994x, 1.0070x,
   0.9938x, 0.9854x and 1.0058x, so no general speed claim is attached to this
   correctness fix.
   Inflight slot reuse no longer scans the optional array for a tombstone.
   Packet Identifier zero marks private free slots, whose indices form a list
   stored entirely in existing `Inflight` tail padding; the active order head
   carries the free-list head. There is no extra allocation, `Session` stays
   400 bytes, and removing the optional tag reduces each physical slot from
   144 to 128 bytes (256 KiB saved at 16,384 slots). A seven-pair, CPU-11
   16,384-inflight tail-churn benchmark moved from 15,935 to 147 ns/op by
   medians (paired median 0.00921x, 7/7 wins), while resume stayed 1.000x and
   reconnect drain measured 0.9897x. The final ordinary-window durable QoS 2
   control was neutral at 0.9981x, 1.0011x, 0.9941x, 1.0017x and 1.0068x.
   The broker's connection loop now also supplies one reusable output slot to
   the `BrokerEvent` reader instead of returning that large tagged union by
   value. The public return-value API remains available as a wrapper, and the
   caller-output contract leaves the slot untouched on failure. ReleaseFast
   assembly shrank the loop's stack frame from `0xa70` to `0xa00` bytes and
   removed the intermediate vector-sized event copies. Across five fixed
   AB/BA pairs, the 32-publisher shape won all pairs at a 1.0153x throughput
   median with p50/p99 ratios of 0.9841x/0.9842x; serial, fanout, balanced, and
   4-KiB shapes remained neutral, so this is a targeted receive-loop result
   rather than a general broker speed claim.
   Synchronous durable Session flushing now also records whether its locked
   selection left another unsent transmission. A final successful write can
   therefore skip the second state-mutex acquisition and empty drain probe.
   Concurrent producers retain their own flush notification, while shared
   writer tasks continue draining until empty so fanout batching is unchanged.
   A seven-pair fixed-binary durable QoS 2 matrix was neutral in all five
   shapes; a matched 100,000-message serial profile reduced
   `flushSlotLocked` from 211 samples (4.35%) to 156 (3.22%).
   PUBACK, terminal PUBREC, and PUBCOMP processing now also retain the
   per-connection writer mutex across the immediately following durable
   Session flush. The former success path released it and called `flushSlot`,
   which reacquired the same mutex before selecting the next packet. A shared
   helper now calls `flushSlotLocked` directly and releases the mutex on every
   success/error path. Persistent state still finalizes before network bytes,
   and exactly-once/Receive Maximum ordering is unchanged. Eight fixed-binary
   CPU-0/1 pairs used 1,000 warmups and 10,000 measured serial durable QoS 2
   publishes. Instructions improved by a 0.998182 paired median (7/8 wins) and
   p99 by 0.963928 (6/8 wins); throughput/p50 stayed neutral at 0.998355 and
   1.001291. Matched 100,000-message profiles were load-sensitive but reduced
   `ClientTask.runLoop` from 10.56% to 10.07% and `flushSlotLocked` from 2.82%
   to 2.53%. Both focused optimization modes and all 1,825 source-locked
   Mosquitto packet sequences pass. This is bounded scheduling/lock evidence,
   not closure of the serial QoS 2 or RSS gap.
   Normal-subscription routing now also consumes the broker's complete
   `subscriptionCount()` output capacity in one trie traversal. Previously it
   counted and then emitted even when no shared group existed, although only a
   shared-selection cursor or insufficient capacity requires that transaction
   boundary. Shared subscriptions, small buffers, wildcard frontier overflow,
   No Local and `$SYS` retain the existing paths. Eight fixed-binary serial
   durable QoS 2 pairs reduced broker instructions by 4.16% with 8/8 wins,
   raised throughput 0.36% (5/8), and reduced p50/p99 by 3.88%/4.99% with 5/8
   and 6/8 wins. A 100,000-message profile reduced `matchTrie` from 2.59% to
   1.41%. Debug/ReleaseFast router gates passed 62 tests and focused live,
   No Local, shared, and QoS 2 broker gates passed 47 tests. This closes the
   common double traversal while preserving the broader serial/RSS gap.
   zio's runtime-task timed-I/O path now also preserves the already-ready
   operation fast path without arming a timer, then directly links a blocking
   operation to its deadline. Natural completion removes that timer without
   completing a generic race-group sibling; timeout and external cancellation
   still wait for the underlying I/O to settle. Sixteen fixed-binary CPU-0/1
   durable QoS 2 serial pairs reduced broker instructions by 0.634% with 16/16
   wins, raised throughput 2.36% (15/16), and reduced p50/p99 by 1.69%/0.85%
   with 13/16 and 12/16 wins. The complete zio suite passed 767 tests, focused
   timed-I/O coverage passed under Debug, ReleaseFast, single-executor, pinned,
   poll, and epoll configurations, Netz Keep Alive passed 54/54 across TCP,
   TLS, and WebSocket, and all 1,825 source-locked Mosquitto sequences passed.
   Keep Alive timing, large-packet progress renewal, and timeout-resumable
   framing remain unchanged.
   MQTT stream framing also commits every TLS plaintext prefix before another
   read can return `Canceled`, `ConcurrencyUnavailable`, or `Timeout`. The
   original local-loop cursor could lose bytes returned before cancellation
   or executor rejection, even while the underlying TLS record was intact.
   The extracted `runtime/transport/stream_receive.zig` keeps that progress in
   the packet state, retains a complete Fixed Header across allocation failure,
   and retries allocation without consuming payload as Remaining Length.
   Deterministic cursor/allocation tests cover ordinary and aligned-prefix
   ownership. Real TCP, native TLS 1.2/1.3, standard TLS 1.3 and WebSocket
   exchanges interrupt split Remaining Length and PUBLISH bodies, then verify
   exact QoS 1/2 payloads, same-identifier ACK completion, the following packet,
   and continued PING traffic. MQTT state and traffic accounting advance only
   after a complete packet arrives; Keep Alive still renews only while the
   outstanding body exceeds the existing 1,000-byte progress threshold.
   WS/WSS also retain one complete decoded WebSocket message if appending it
   to MQTT's byte stream fails allocation. Retry consumes that retained message
   before reading another, preserving split/coalesced packet order and the
   already-committed permessage-deflate receive context. Pending bytes remain
   bounded by the existing message/packet windows, use the WebSocket allocator
   for release, and are freed after append, rejection, or transport close.
   Focused OOM regressions cover first-message append, growth after a partial
   MQTT header, packet allocation, repeated failures, invalid text/oversize
   input, and closing with pending ownership. Real WS/WSS compressed exchanges
   prove exact first and following packets under context takeover after retry.
   Client and broker event decoders also retain complete MQTT packets until
   metadata and protocol-state validation commits. Queued packets stay at their
   original index; new owned packets reuse the existing inline receive slot.
   A caller-buffer decode OOM copies bytes back into TCP read-ahead without an
   allocation or retained caller pointer. Restored packets carry prior traffic
   accounting, so retries never count the same wire bytes twice. Property,
   Topic Alias and QoS allocation failures preserve the first event and its
   following packets across repeated retries. Typed PUBLISH/AUTH and correlated
   ACK readers can adopt that retained prefix ahead of a later queue overflow,
   including when new interleaving quotas are disabled; allocation failure
   during adoption leaves ownership intact. Semantic errors still discard the
   failed packet, and local close releases every retained byte. These changes
   reuse existing connection padding and the receive slot instead of growing
   the 64-bit Connection or packet descriptor layouts.
   Connection traffic counters now follow their actual ownership boundary too.
   The single protocol reader and externally serialized writer update private
   atomic snapshots with load/store instead of multi-writer RMW. Broker
   aggregation is deferred: live `stats()` combines active slot snapshots with
   the retired lifetime total, while unregister and pre-admission close flush
   a final delta once. The ordinary public immediate sink remains unchanged.
   Twelve clean fixed-binary durable QoS 2 serial pairs completed 40,000 exact
   deliveries per arm. Broker cycles improved by a 1.032222
   baseline/candidate median with 12/12 wins, instructions by 1.000876 with
   12/12, throughput by 1.006236 with 10/12, and p50 by 1.010936 with 11/12;
   p99 was neutral at 1.001168. A four-pair five-shape control kept fanout,
   balanced, and 4-KiB throughput neutral while publishers-32 improved 2.19%.
   Exact live/offline statistics, Debug/ReleaseFast focused MQTT tests, and all
   1,825 Mosquitto packet sequences pass. This is a synchronization-cost result,
   not closure of the broader serial or RSS gap.
   The broker caller-output reader now also constructs events directly from
   the transport's single `OwnedPacket` type. Validation occurs in place and
   the caller's event slot changes only after packet-specific parsing succeeds;
   return-by-value compatibility remains. This removed one 48-byte run-loop
   temporary, reduced its stack frame from `0xbb0` to `0xb80`, shrank the
   function by 424 bytes and the broker ELF `.text` by 1,676 bytes. Twelve
   clean serial pairs reduced broker instructions by a 1.006130
   baseline/candidate median with 12/12 wins, raised throughput 1.010833 with
   9/12, and reduced p50/p99 by 1.015487/1.013144 with 11/12 and 12/12 wins.
   Cycles were neutral. Four-pair controls reduced instructions in every arm of
   all five shapes, while throughput remained neutral to positive outside the
   noisy short serial control. Focused Debug/ReleaseFast gates pass 136 tests
   and the Mosquitto source-locked gate remains 1,825/1,825.
   PUBLISH encoding now also carries the already validated Properties length
   from wire preflight into direct prefix emission instead of rescanning the
   same list. Public writers retain every topic, payload-format, QoS, Packet
   Identifier, property-context, duplicate, size, and overflow check. Sixteen
   clean durable QoS 2 serial pairs reduced broker instructions by a 1.004498
   baseline/candidate median with 16/16 wins, improved cycles by 1.010746 with
   11/16, throughput by 1.007156 with 12/16, and p50 by 1.014379 with 13/16;
   p99 was neutral. Four-pair five-shape controls showed consistent instruction
   reductions but mixed neutral throughput, so no general all-shape speedup is
   claimed. Focused Debug/ReleaseFast gates pass 138 tests and all 1,825 source-
   locked Mosquitto sequences remain green.
   Inbound QoS 2 PUBREL release now also shares one awake-clock snapshot between
   Message Expiry evaluation and route enqueue instead of looking up the same
   executor clock twice inside one atomic release. Eight fixed-binary serial
   pairs completed 40,000 exact deliveries per arm; broker instructions
   improved by a 1.002510 baseline/candidate median with 8/8 wins and cycles by
   1.007600 with 8/8 wins. Throughput and latency were mixed and receive no
   improvement claim. Two-pair publishers, fanout, balanced and 4-KiB controls
   improved instructions by 0.36-0.57% median while timing remained mixed.
   Persistence, exactly-once release, expiry and PUBCOMP ordering are unchanged;
   this is deterministic redundant-work removal, not closure of the broader
   serial or RSS gap.
   MQTT's Control Packet type field exhaustively uses non-zero `u4` values.
   After preserving the reserved-zero check, packet framing now converts that
   nibble directly instead of executing an unreachable generic enum failure
   path. Eight fixed-binary serial pairs reduced broker instructions by a
   1.009357 median with 8/8 wins and a 1.008045-1.010145 range. Every arm of
   two-pair publishers, fanout, balanced and 4-KiB controls also improved
   instructions, by 0.75-2.21% median. Timing/cycles were noisy and mixed, so
   no latency or throughput claim is made. Exhaustive type mapping, reserved
   precedence and all packet-sequence gates preserve exact wire behavior.
   Transient delivery writers now follow the same demand-driven lifecycle as
   their queues. Accepting a QoS 1/2 subscription no longer starts a parked
   connection-lifetime coroutine. The first multi-destination route that
   actually selects asynchronous delivery starts that destination's writer
   while its generation is stable; an allocation or scheduler-capacity failure
   leaves the delivery on the existing synchronous path. Once fanout exists,
   every destination still has its independent writer, bounded queue, writer
   mutex, and transport-error isolation, so a slow peer cannot occupy a shared
   worker needed by a healthy peer. One-sample fixed-shape stack telemetry moved
   serial from 4 to 3 peak active stacks and publishers-32 from 35 to 34, while
   fanout-32, balanced-32x32, and 4-KiB fanout stayed at 66, 97, and 13. Broker
   allocation calls likewise fell by exactly one in the two single-destination
   shapes and stayed unchanged in the three actual-fanout shapes. A four-sample
   ABBA serial process capture measured 3,984 versus 3,980 KiB median RSS; that
   is only sampler granularity, and timing moved in both directions, so this is
   a deterministic coroutine-lifecycle result rather than an RSS, latency, or
   throughput claim. A preceding attempt to lower zio's initial stack commit
   from 256 to 64 KiB was rejected: its matched four-sample 2x2 capture regressed
   median netz RSS from 4,070 to 4,256 KiB, consistent with Linux charging
   anonymous pages when touched rather than when made writable. The 8-MiB
   virtual ceiling and 256-KiB default remain unchanged. Allocator-matrix
   identity copies are now stripped before capture, reducing one current
   artifact from 269,472,865 to 9,180,207 bytes without changing the executed
   loadable code; exact post-strip hashes remain recorded. Focused delivery and
   fanout tests pass 142/142, the production live-broker fuzz gate passes 3/3,
   package tests pass 22/22, and the Mosquitto `5cd25465` same-client gate
   preserves all 4,000 expected deliveries. Full records are in
   [the lazy delivery-writer evidence](../evidence/mqtt_lazy_delivery_writer/2026-10-29.json).
   Production Broker listeners now also enforce Keep Alive through the shared
   lifecycle deadline driver instead of arming and clearing an I/O timer for
   every packet read. One atomic per active Connection stores an exact awake-
   clock deadline; complete packets and >1,000-byte remaining body progress
   extend it without taking the broker state mutex. The driver claims an expiry
   with compare-and-exchange, so a concurrent renewal defeats a stale wake.
   First installation is serialized with its slot/generation scan. Standalone
   runtime server reads keep their original timed API, and TCP/TLS/WS/WSS retain
   the 1.5x timeout, zero-disable, partial-packet and WebSocket-control rules.
   This mirrors Mosquitto's centralized `keepalive.c` lifecycle while reusing
   netz's bounded slot table rather than allocating a 98,303-entry default
   timing ring. `runtime.Connection` grows 824 to 832 bytes for the atomic;
   preallocated `ClientSlot` stays 96 bytes. Eight fixed-binary durable serial
   QoS 2 pairs reduced broker instructions 5.54% and cycles 10.49% by paired
   medians with 8/8 wins for each. Timing remained noisy and the final direct
   Mosquitto comparison still measured 22,091 versus 31,651 publishes/s, so
   the durable QoS 2 serial/RSS gap remains active. Focused Keep Alive/broker tests
   pass 221/221, TLS/WSS composition passes 131/131, live-broker fuzz passes
   3/3, package tests pass 22/22, and Mosquitto gates pass 294 selected vectors
   plus all 1,825 source-locked sequences. Full PMU, profile and lifecycle
   evidence is recorded in
   [the managed Keep Alive evidence](../evidence/mqtt_managed_keep_alive/2026-10-29.json).
   A follow-up replaced the per-packet weak-CAS renewal loop with one strong
   compare/exchange, relying on the Connection's single receive owner and the
   lifecycle driver's sole concurrent expiry claim. Focused Keep Alive tests
   passed 131/131, but eight fixed-binary 100k durable QoS 2 serial pairs
   regressed broker instructions 0.135%, elapsed time 1.60%, p50 1.89%, and
   p99 7.47%; cycles were mixed. On this AArch64 LSE target, changing the CAS
   primitive did not remove the profiled cost and harmed code generation. The
   original exact weak-CAS loop remains. Full rows are in
   [the rejected strong-CAS evidence](../evidence/mqtt_keepalive_strong_cas_rejected/2026-10-30.json).
   A subsequent detached-Session prototype retained the broker's refcounted
   `Publication` across the unlocked socket write and copied only MQTT property
   descriptors. The fallback still deep-copied Session-owned or alias-rewritten
   bytes, and durable state remained committed before network-visible progress.
   Although focused ownership and durable QoS 2 tests passed, eight fixed-binary
   serial pairs regressed broker instructions and cycles by 0.43% and 0.67% at
   paired medians, with only 2/8 and 3/8 wins. Throughput and p50/p99 were also
   neutral-to-negative. The implementation was removed. A future ownership
   attempt must avoid growing every `PublishTransmission` and instead use a
   broker-only selection sidecar or a lower transport boundary. Full results
   are recorded in
   [the rejected shared-Publication detach evidence](../evidence/mqtt_shared_publication_detach_rejected/2026-10-30.json).
   The accepted follow-up keeps `PublishTransmission` unchanged. A broker-only
   one-item Session drain returns the shared `Publication` as a sidecar, while
   ordinary drains use a comptime-separated implementation with no owner
   branch. Detach copies property descriptors, retains the sidecar, and keeps
   Topic Name, payload and variable-length property values borrowed through the
   unlocked synchronous write. Restored, ordinary and partially shared-property
   messages retain the existing deep copy. Three fixed-binary serial sets at
   10,000, 40,000 and 100,000 measured durable QoS 2 publishes reduced broker
   instructions by 0.59%, 0.57% and 0.58% at paired medians. The 100,000-message
   decision set also improved cycles 0.45%, throughput 0.47% and p50 1.18%; p99
   was neutral. Five-shape controls reduced instructions in every shape, by
   0.94% for fanout, 1.41% for balanced 32x32 and 4.84% for 4-KiB payloads;
   timing and sampled RSS remained workload-noisy and receive no broad claim.
   A matching profile reduced `memcpyFast` self samples from 1.82% to 1.04%
   and removed the prior Topic Name/payload copy below Session flush.
   The refreshed source-locked Mosquitto matrix puts netz at 0.717x/0.962x/
   1.106x/1.061x/1.044x throughput in serial, publishers-32, fanout-32,
   balanced-32x32 and large-payload order. All measured broker RSS shapes still
   trail Mosquitto, and a longer 100,000-message serial comparison measured
   22,316 versus 33,184 publishes/s, so the serial/RSS gap remains active.
   Debug and ReleaseFast focused gates pass 217/217, package tests pass 22/22,
   live-broker fuzz passes 3/3, all 1,825 Mosquitto sequences pass, and commit-
   log, restart, listener-mount and 40-run external matrix gates pass. Full
   evidence is recorded in
   [the shared-Publication sidecar evidence](../evidence/mqtt_shared_publication_sidecar/2026-10-30.json).
   A follow-up tried to extend the same owner path to a single durable route by
   adopting an already prefixed inbound QoS 2 `Pending` into a refcounted
   `Publication`. Ownership, OOM and persistence tests passed, and the serial
   throughput median rose 0.64%, but fixed broker instructions regressed 0.18%
   with only 2/8 wins; p50/p99 also moved 0.86%/0.34% slower. Publication
   initialization, property ownership and refcount work outweighed the removed
   copies, so the source change was removed before broader gates. Future serial
   work must keep this path single-owner or reduce selection/locking work rather
   than constructing a Publication solely for sidecar eligibility. Full rows
   are retained in
   [the rejected single-route adoption evidence](../evidence/mqtt_single_route_publication_adoption_rejected/2026-10-30.json).
   Another follow-up returned stable route identity and the exact pending-
   suffix bit from the broker-only Session selection, removing subsequent
   `routeId` and `hasUnselectedTransmission` lookups. The model gate passed and
   instructions improved 0.56%, but cycles regressed 1.35% with only 1/8 wins;
   throughput, p50 and p99 also regressed 0.76%, 1.29% and 0.44%. Enlarging the
   inlined selection result and writing metadata was therefore costlier than
   the two lookups, and the implementation was removed. A future attempt must
   cache route/work state outside `DetachableTransmission` and retain the same
   cycles guard. Full rows are in
   [the rejected selection-metadata evidence](../evidence/mqtt_session_selection_metadata_rejected/2026-10-30.json).
   A narrower variant kept every struct layout unchanged and returned only the
   pending-suffix bit through a separate out parameter. It still regressed
   instructions and cycles by 0.28%/0.66%, each with only 2/8 wins, while
   p50/p99 moved 1.23%/1.98% slower. Even the extra inlined store and threaded
   output cost more than the later lookup, so this implementation was also
   removed. Any future outgoing-work cache must update an existing `ClientSlot`
   state bit at lifecycle boundaries rather than return metadata from Session
   selection. Full rows are in
   [the rejected pending-out evidence](../evidence/mqtt_session_pending_out_rejected/2026-10-30.json).
   A follow-up applied that rule to inbound durable QoS 2: the live connection
   slot already carries `session_persistent`, so candidates replaced the
   route-ID-to-Session expiry lookup on both PUBLISH/PUBREL, then on PUBLISH
   only. Debug assertions proved the cached bit equal to Store state, and
   focused Debug/ReleaseFast durability coverage passed 125/125. Neither
   candidate passed the fixed-binary PMU guard. The two-stage version improved
   instructions only 0.17% with 5/8 wins but regressed cycles 0.72% with 2/8
   wins. The narrower PUBLISH-only version regressed instructions 0.32% with
   2/8 wins and cycles 0.29% with 3/8 wins; p50 also regressed 2.89%. Both
   source variants were removed. This rules out adding generation/fallback
   selection around the cached bit merely to replace the small Store lookup;
   future work must remove a larger scheduling/ownership boundary without
   growing these hot paths. Full rows are in
   [the rejected persistence-cache evidence](../evidence/mqtt_publisher_persistence_cache_rejected/2026-10-30.json).
   The next candidate reduced PUBREL's three `state_mutex` acquisitions to one
   across pending removal, bounded in-memory decode, route planning, and pending
   recycling. Persistence writes, downstream network dispatch, and PUBCOMP all
   remained after state unlock and the existing durable commit. Serial 10k and
   40k decision sets improved cycles by 0.96% and 1.48% at paired medians, with
   instructions neutral, so the candidate advanced to the five-shape QoS 2
   guard. It then failed the fanout boundary: fanout-32 cycles regressed 5.78%
   with 0/4 wins, throughput regressed 1.40%, and p50/p99 regressed 1.47%/1.39%,
   also 0/4 wins. Holding the global state lock while materializing 32
   destinations blocked their writers more than the removed lock handoffs
   saved. The production change was removed before crash gates. Full serial and
   five-shape rows are in
   [the rejected single-lock evidence](../evidence/mqtt_pubrel_single_lock_rejected/2026-10-30.json).
   A narrower follow-up attempted the same lock coalescing only when the
   router had at most one subscription. Eight 100k-message serial pairs
   initially improved broker instructions/cycles by 0.38%/1.38%, while p50
   and p99 improved 0.50%/1.15%. Fanout-32 stayed neutral, but six
   balanced-32x32 pairs exposed a 2.84% cycles regression because the inlined
   single-route transaction enlarged every PUBREL stack frame from 0x480 to
   0x580 bytes. Moving only route construction out of line restored balanced
   cycles but regressed serial p50/p99 1.56%/0.59%. Splitting complete general
   and single-route transactions reduced both generated frames to 0x3e0 and
   improved balanced cycles/timing, yet its unavoidable topology check still
   regressed balanced instructions by 0.05-0.07% with zero or one win in four
   pairs. All source variants were removed before crash gates. Future serial
   work must not add a per-PUBREL topology branch; it must remove work shared
   by concurrent shapes or select a distinct implementation outside the packet
   hot path. Full rows are in
   [the rejected single-route evidence](../evidence/mqtt_pubrel_single_route_lock_rejected/2026-10-30.json).
   A receive-path audit then measured the existing 448-byte TCP read-ahead
   before changing it. A uprobe on the fixed baseline broker counted exactly
   420,005 transport reads for 5,000 warmup plus 100,000 measured durable
   serial QoS 2 publishes: one read for each 282-byte PUBLISH and each 4-byte
   PUBREL/PUBREC/PUBCOMP, plus the five connection/subscription control
   packets. Larger read-ahead therefore cannot reduce this workload's read or
   io_uring-operation count. Instead, TCP packet assembly now specializes its
   mutually exclusive plain, inactivity-timeout, absolute-deadline and managed-
   observer policies, plus caller-storage presence, at compile time. The
   assembly and read helpers remain explicitly out of line: an inlined
   prototype cut instructions but expanded `EventReceive.read` from 3,768 to
   13,416 code bytes, grew its stack from 752 to 1,184 bytes, and regressed
   serial cycles 1.63% plus p50/p99 3.51%/1.91%. The retained form reduces that
   reader to 3,632 code bytes, leaves every connection layout and the 448/128-
   byte read-ahead/caller buffers unchanged, and removes optional-deadline
   state from the untimed managed path.

   Fixed-binary QoS 2 controls measured candidate/baseline instructions and
   cycles at 0.9879/0.9676 for serial 100k, 0.9913/0.9872 for publishers-32
   100k, 0.9890/0.9312 for fanout-32, and 0.9903/0.9434 for balanced-32x32.
   Throughput was neutral for serial and publishers-32 and improved 1.77%/
   1.47% for fanout/balanced. A short 4-KiB control initially reported an
   unfavorable 3.87% instruction move; the retained 100k follow-up made
   throughput neutral, cycles 1.23% lower, and instructions mixed at +0.18%.
   Both results remain in the evidence. Complete MQTT tests, focused TCP
   fragmentation/timeout/borrow tests, 294 Mosquitto wire vectors, and all
   1,825 source-locked packet sequences pass. Full raw rows, hashes, code-size
   and stack-frame evidence are in
   [the receive-policy specialization evidence](../evidence/mqtt_receive_policy_specialization/2026-10-30.json).
3. Expand the source-hash-locked process gate beyond its current 294 curated
   scenarios. The strict broker configuration adapter now locks twenty-nine
   upstream process sources:
   persistent subscription self-delivery, persisted No Local, queued
   Subscription Identifiers, persistent/clean-session flipflop,
   QoS 0 Wills with global and per-listener policy,
   Windows-CRLF configuration, missing root configuration, include-directory
   loading, the Unix listener,
   bridge reload, bridge QoS/Retain/Protocol-Version CONNACK capability
   refusals, mTLS identity reload, change-count autosave, listener anonymous
   policy, username-or-anonymous policy, authentication-before-takeover
   ordering, password-file parser robustness, empty-ACL default deny, two
   password/ACL invalid-reload cases, and the good/revoked client-certificate
   CRL process cases. The focused CRL gate maps those two exact upstream
   behaviors onto the stronger RSA, P-384 and Ed25519 listener matrix, including
   good-client CONNECT, revoked-client rejection and tampered-CRL failure before
   any listener opens. Three persistence sources bind MQTT 5 durable outgoing
   delivery, retained property bundles and downtime-expired queued messages to
   a focused three-generation MQTT 3.1.1/5 restart gate. That gate additionally
   verifies QoS 2 DUP/PUBREL restoration, Clean Start cleanup, retained
   properties and expiry pruning rather than depending on Mosquitto's internal
   database-count assertions. Mosquitto's broad `16-config-huge.py` parser and
   repeated-reload scenario is also source-locked. Its focused replacement
   exercises both global and `per_listener_settings` policy resolution while
   atomically swapping anonymous/password, zero-length Client ID, assigned-ID
   prefix, accepted-version, Maximum QoS/Keep Alive and Topic Alias policy;
   existing clients remain live and a changed listener port rolls back the
   complete reload. Dynamic listener topology remains an explicit
   restart-required boundary rather than a silently ignored setting. The
   CRLF case admits MQTT 3.1.1 and MQTT 5 through the production process. A
   missing root file has a distinct loader error that the CLI maps to exit 3
   plus the exact path before any listener opens; dependent include/security
   file failures retain their own classifications. The mTLS case keeps both a
   certificate-CN-mapped WSS Session and a full RFC 2253 Subject-mapped TCP
   Session live across SIGHUP, then proves both with PING. The autosave case
   strengthens the upstream one-change checkpoint with disabled, change-count,
   periodic, target-switch, rollback, and retained-state restart phases. The
   bridge case strengthens upstream immediate/lazy replacement with lazy
   supersession, add/remove, cross-subsystem preparation failure rollback, and
   live local-client continuity. The gate also verifies a complete Unix process
   lifecycle and proves Netz's transactional reload rollback divergence through
   a real SIGHUP broker process. The independent
   `interop-mqtt-broker-includes` target locks Mosquitto's
   `16-config-includedir.py` and exercises ordered `A.conf`/`a.conf` files across
   two include directories, paths with spaces, ignored extensions and nested
   files, and three listener policies. Exact CONNACK properties and SUBACK QoS
   prove each source's effect. The root file remains byte-identical while
   included files change authentication, assigned-ID prefixes, Maximum QoS and
   Topic Alias policy. A later malformed source or missing password dependency
   rolls back earlier policy changes; removing the fault permits another
   successful SIGHUP. Adding/deleting a policy fragment changes payload limits
   on the already connected publisher, while MQTT 3.1.1/5 peers retain PING and
   exact publication delivery across those reloads. Startup cases also reject
   malformed, missing-security, symlink and nested-include sources before any
   listener opens. This target runs in the default config gate as well. The
   nineteen
   behavior-bearing broker packet JSON files are
   already included completely; the only unselected JSON file is
   `ZZ-broker-check.json`, whose sole test is an empty end-of-suite sentinel.
   The remaining upstream Python process suite still contains portable
   lifecycle and configuration behavior that the current curated gate does
   not cover. The dedicated [Will process lifecycle gate](../mqtt_will_lifecycle.md)
   additionally verifies both source-locked Will variants and publication-time
   ACL reload behavior without changing the runtime callback lifetime contract.
   The [delayed Will process gate](../mqtt_will_delay.md) additionally covers nine
   source-locked MQTT 5 scenarios for the minimum Will Delay/Session Expiry
   deadline, zero-expiry publication, resumed-Session cancellation, and Clean
   Start replacement. Three further cases verify delayed DISCONNECT reason
   0x04, normal DISCONNECT suppression and distinct replacement payload
   ownership. Each case checks exact packets, timed negative intervals,
   Session Present and duplicate-free cleanup; the shared source catalog now
   locks 36 process files. Current runtime behavior passes the gate.
   The [persistent Session expiry restart gate](../mqtt_session_expiry_restart.md)
   additionally covers all five active variants of
   `15-persist-client-expired-session.py`, keeping each 100-message queue,
   the 20-message shared tail, the 30-publication retained prefix and both
   replacement-subscription choices. A sixth QoS 2 scenario combines shared
   and retained ownership. Four snapshot/process generations verify initial
   queue recovery, five unacknowledged deliveries, expiry during downtime,
   Session Present, exact sibling and retained delivery, durable queue and
   subscription deletion, and replacement routing. The source catalog now
   locks 38 process files; its packet oracle rejects late delivery and EOF
   instead of accepting either as evidence of an empty queue.

   A dedicated production-process gate now source-locks Mosquitto issue
   #575314 through `01-connect-575314.py`. It compares MQTT 5 CONNECT packets
   carrying 5,001 repeated User Properties against a byte-balanced 65,000-byte
   Client Identifier. Four 500-connection phases run A/B/B/A through the
   ReleaseFast configured broker, validate every CONNACK, and measure broker
   user+system CPU directly from `/proc` rather than client wall time. Both
   arms therefore total the upstream test's 1,000 connections. On the recorded
   AArch64 run, the packets were 65,053 and 65,017 bytes; repeated properties
   consumed 22 CPU ticks versus 10 for the Client Identifier, a 2.2x ratio
   under Mosquitto's source threshold of 20x. The implementation's repeatable
   property duplicate check exits in O(1), while decode, value validation,
   context validation and authentication-property checks remain sequential.
   Evidence is recorded in
   `docs/evidence/mqtt_connect_property_linear/2026-10-29.json`.

3. **Prometheus exposition (new).** `mqtt.broker_prometheus.render(allocator, broker.stats())`
   emits deterministic Prometheus text exposition 0.0.4 from one coherent
   stats snapshot: 33 fixed-order metric families (`# HELP`/`# TYPE` plus one
   sample) covering connections, monotonic MQTT/publish/byte counters, session
   and retained-store gauges, queue/inflight/QoS2/will ownership, optional
   application-reported heap gauges, and the 1/5/15-minute Mosquitto EWMA load
   rates as gauges with a `window` label. Counter families use `_total`;
   instantaneous values and rates are gauges, so a Prometheus counter reset
   cannot misclassify broker state. `mqtt_broker_heap_current_bytes` and
   `mqtt_broker_heap_maximum_bytes` appear only when
   `Broker.Options.heap_source` is configured, mirroring Mosquitto's
   `WITH_MEMORY_TRACKING` build option; the production config example supplies
   its `memory_limit` limiter. The broker embeds no HTTP server; applications
   serve the bytes from their own admin endpoint. Unit tests lock the sample
   mapping, conditional heap families and byte-stable output.

