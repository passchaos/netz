# MQTT feature matrix and broker semantics

[Back to the rumqtt parity index](../rumqtt_parity.md).

## Current feature comparison

Hostname and URI clients now preserve the complete resolved TCP connection
policy error set, including `ConcurrencyUnavailable` from Happy Eyeballs
admission. Adjacent public-client regressions exhaust executor capacity across
ordinary and deadline-owned hostname/URI connects and verify the original
error without leaking resolver storage. The durable QoS 2 bridge fuzz gate
compiles and passes again after this error-set repair. Evidence is in
`docs/evidence/mqtt_connect_concurrency/2026-10-31.json`.

Broker teardown now collects shared Session-writer errors while holding the
slot writer lock, after any in-flight flush has finished publishing its result
and before the slot becomes reusable. A writer failure arriving after the
reader exits therefore reaches that connection's result instead of leaking
into the next connection generation. Expected transport-close errors remain
filtered, earlier reader/delivery errors retain precedence, and durable cleanup
failures keep their existing precedence. Error settlement lives in
`broker/session_writer/retirement.zig`; adjacent regressions cover late fatal
and transport errors, error precedence, and clean reuse of a one-slot Broker.

Reconnect polling now recovers retryable automatic output failures under its
original budget instead of terminating `serveUntil`. One bounded owned-event
slot retains applied PUBLISH, PUBREC, PUBREL and AUTH metadata through response
or PUBREL-replay failure. An event ready within the remaining budget is returned
before reconnect; an expired/disabled-reconnect call leaves it for the next
poll. Known QoS 2 PUBLISH retransmissions do not refill this slot and reconnect
directly when their repeated PUBREC fails. Snapshot writes/restores remain busy
until the retained event has been returned. Socket failure is observed before
callback cleanup, so a local authentication callback returning a network-shaped
error still propagates rather than being retried as transport loss. Polling
lives in `reconnect/poll.zig`; adjacent real TCP tests verify continued serving,
alias-backed delivery ordering, duplicate suppression, owned control properties,
callback-error propagation and refusal of PUBREL before manual PUBREC.

Synchronous fanout now validates the selected recipient's connection generation
while holding its writer lock. A disconnected target's stale route plan cannot
touch a reused slot, and its socket failure wakes only that target's reader
instead of aborting the publication's source connection. Healthy recipients
continue receiving, while local state/persistence errors still propagate.
The common guarded path in `broker/fanout/flush.zig` also covers shared-writer
fallback; the publisher's own acknowledgement/delivery path retains its direct
error handling. Real TCP tests inject recipient resets across MQTT 3.1.1/5,
all three source QoS levels, and persistent/transient subscriptions, then verify
source PING and surviving fanout delivery. This fixes the offline-QoS0 gate's
disconnect/routing race without relying on timing sleeps.

MQTT 5 protocol-error DISCONNECT output now shares the original CONNECT,
reauthentication, typed/event receive or reconnect-poll deadline. A blocked
diagnostic cannot extend that budget or replace the original peer error.
Authentication violations retire their Network Connection even when an
expired deadline or packet-size limit prevents diagnostic output. Initial
authentication callback failures and invalid callback response methods remain
local errors: they retire the incomplete exchange without sending a peer-fault
diagnostic. A provably pre-wire CONNECT rejection instead rolls back its
authentication preparation, allowing a corrected attempt on the same socket.
Public `writeDisconnectWithTimeout`/`writeDisconnectWithDeadline`
preserve packet-direction/property validation and update Session Expiry only
after successful complete output. Their encoder and write policy live in
`runtime/disconnect.zig`. Real TCP regressions exercise initial AUTH/CONNACK
method mismatches, direct callback failures, typed and event reads, both
reauthentication roles, poll diagnostics and post-write expiry ownership.

Reconnect polling now applies the caller's original deadline to automatic
PUBACK/PUBREC/PUBCOMP output, outbound PUBREL replay, and authentication callback
responses. An interrupted first PUBLISH acknowledgement retains its owned
Application Message before another connection attempt or later wire event;
known QoS 2 retransmissions never refill that delivery slot.
The pending message also retains alias-resolved names after transport teardown.
Session snapshot writes/restores return `SnapshotBusy` until the application
drains a retained event, preventing a marker-only snapshot from losing delivery.
Automatic PUBREL handling completes its Session marker before PUBCOMP output;
the Application Message was already delivered. Repeated PUBREL is answered
idempotently without a marker, so an ambiguously visible PUBCOMP cannot leave
stale state suppressing a new PUBLISH with the same identifier. Deferred
application-controlled release retains its existing durable boundary.
Tests cover blocked and fully visible
failed writes, both poll budget forms, all three MQTT versions, snapshot
round trips, identifier reuse, manual duplicate suppression and a callback that
exhausts the original deadline before its AUTH response is written.
Authentication callbacks remain synchronous and must return promptly; their
execution cannot be preempted by this socket deadline.

Received alias-only PUBLISH messages now own their resolved Topic Name
independently of the connection's Topic Alias table. Typed, client-event,
broker-event and caller-buffer results retain the old topic after that alias
is replaced or the connection is closed. Normal Topic Names keep their packet
backing; only names omitted on the wire need the additional owned string.
The common decoder in `runtime/receive/publish.zig` prepares that ownership
before committing QoS receive state. Allocation failure retains the complete
packet for retry, including typed reads and reusable caller storage, without
changing the alias binding or consuming a receive slot. Adjacent tests cover
QoS 1/2, coalesced following packets, table replacement, and connection teardown.
Real TCP, TLS 1.2/1.3, WebSocket and WSS exchanges also queue an alias replacement
while waiting for PINGRESP, then retain both publications after closing the client.

Typed subscriptions now share `mqtt.validateSubscription` across Router direct,
prepared and batch updates, Session storage, local-consumer preflight and
SUBSCRIBE writing. Invalid filters, reserved QoS/Retain Handling values,
Shared Subscription No Local and identifiers outside `1..268435455` are
rejected before allocation or subscription mutation. This closes the Router's
previous acceptance of Retain Handling 3, which Mosquitto's
`src/handle_subscribe.c` rejects. Failed new routes and replacements preserve
live routing, stored metadata, batch state and existing writer output. The
wire writer also retains version-specific option validation for MQTT 3.1 and
3.1.1; incoming packet parsing retains its Malformed Packet/Protocol Error
classification. Legal MQTT 5 ordinary/shared option and identifier boundaries
are checked through Router, Session storage and encode/parse round trips in
`src/mqtt/subscription/validation_tests.zig`.

Router subscription churn now reuses detached entry/node slots and prunes
empty literal and `+` branches without changing any live route or shared-group
index. Trie ownership lives in `src/mqtt/router/tree.zig`; parent links make
cleanup iterative, including thousands of empty topic levels. Subscription
failure also removes any unused prefix built before a later allocation failed,
and uncommitted batches retain allocation-free rollback. Storage follows peak
live/prepared routes rather than cumulative subscription history. Dedicated
regressions cover changing normal/shared filters, recycled representatives,
shared join order, overlapping wildcard routes, every insertion allocation
failure and the public Broker local-consumer open/publish/close path.

| Area | netz | rumqtt / Mosquitto references |
| --- | --- | --- |
| Listener socket family | Mosquitto-style `socket_domain ipv4|ipv6` and `bind_interface` are listener-local across TCP, TLS, WS, and WSS. Omitted bind addresses become the selected family's wildcard, explicit address-family mismatches fail configuration when no interface overrides the address, and IPv6-only sockets set `IPV6_V6ONLY` before bind. With neither an address nor `socket_domain`, the configured runner opens separate IPv4 and IPv6 wildcard sockets when supported; both share the logical listener's admission cap and policy. A named interface takes precedence over the listener address and contributes its first address from each selected family without requiring privileged `SO_BINDTODEVICE`. Backend, interface, or explicitly selected family limitations fail closed; only an unavailable family in an all-family listener is skipped. | Mosquitto likewise enumerates all supported families by default, creates a separate socket for each, resolves `bind_interface` through `getifaddrs`, and restricts a listener to the configured family; rumqttd has no equivalent audited listener option |
| MQTT versions | MQTT 3.1, MQTT 3.1.1 and MQTT 5 packet/runtime; TCP, Unix-domain, WebSocket and secure listeners auto-detect all three versions. MQTT 3.1 preserves its `MQIsdp` protocol name, level-3 CONNECT quirks, required 1-23-character Client Identifier, and legacy CONNACK/QoS control shapes instead of being aliased to 3.1.1. Listener-local `accept_protocol_versions` admits any exact combination of `3`, `4`, and `5` and sends version-correct refusal CONNACKs before Session, Will, or route registration. MQTT 5 Topic Alias uses sparse per-connection storage and supports the complete non-zero u16 range instead of imposing a private small-table cap. | rumqtt clients support 3.1.1/5; Mosquitto broker supports 3.1/3.1.1/5 and exposes the same listener version policy |
| Trusted proxy ingress | Opt-in, bounded HAProxy PROXY v1/v2 parsing before MQTT CONNECT, TLS or WS/WSS Upgrade, with IPv4/IPv6/Unix endpoints, LOCAL/UNKNOWN handling, CRC32C, ALPN/authority/unique-id/network-namespace, and nested SSL TLVs exposed as owned connection metadata. The production Mosquitto-style config exposes listener-local `enable_proxy_protocol 1|2` and `proxy_protocol_v2_require_tls`; on cleartext v2 listeners, `require_certificate` requires verified connection/session certificate evidence and `use_identity_as_username` accepts only a validated SSL-TLV commonName. Local TLS termination and full-Subject identity remain invalid with v2 | Mosquitto supports listener-level PROXY v1/v2, including address replacement and selected SSL TLVs; rumqttd has no equivalent listener surface in the audited tree |
| Live broker dispatch | Bounded connection slots and queues; SUBSCRIBE/UNSUBSCRIBE; QoS 0/1/2 fanout; downstream Receive Maximum; cleanup | Both references are production brokers with broader lifecycle support |
| QoS | Runtime and live broker QoS 0/1/2, including exactly-once route at PUBREL; broker Maximum QoS caps subscription grants and live/durable delivery. Mosquitto-compatible global `max_inflight_messages` defaults to 20, bounds each client's incoming and outgoing QoS 1/2 transactions, advertises MQTT 5 Receive Maximum, enforces the same unadvertised bound for MQTT 3.1.1, and maps zero to the protocol default of 65,535 while retaining independent aggregate/memory bounds. Global `max_inflight_bytes` independently bounds outgoing QoS 1/2 payload bytes for transient connections and durable Sessions through final acknowledgement, and defaults to unlimited | Both brokers support QoS 0/1/2; Mosquitto applies its listener Maximum QoS to grants, delivery, and Wills and exposes the same global inflight settings |
| Packet and Application Message size policy | Mosquitto-style global `max_packet_size` defaults to 2,000,000 bytes, caps complete inbound MQTT Control Packets across TCP/TLS/WS/WSS, and is advertised in MQTT 5 CONNACK. The independent `message_size_limit` payload-byte cap covers live QoS 0/1/2 PUBLISH and Will acceptance; MQTT 5 uses Implementation Specific Error for PUBACK/PUBREC and Packet Too Large for CONNACK/DISCONNECT, while MQTT 3.1.1 completes representable acknowledgements | Mosquitto exposes both `max_packet_size` and `message_size_limit`; rumqttd exposes `max_payload_size` |
| Retain availability policy | Mosquitto-style global `retain_available` defaults true. When disabled, MQTT 5 CONNACK advertises Retain Available 0 and retained PUBLISH or Will use receives reason 0x9A; MQTT 3.1.1 closes because it cannot represent that reason. The policy is shared by TCP/TLS/WS/WSS listeners | Mosquitto exposes global `retain_available`; rumqttd has retained-message storage but no equivalent audited configuration switch |
| Outgoing QoS policy | MQTT-compliant min(source, subscription) by default; explicit `upgrade_outgoing_qos` compatibility mode covers live, retained and durable Session delivery | Mosquitto exposes the same non-standard opt-in; rumqttd follows its configured routing policy |
| Shared subscriptions | Trie-indexed `{group, filter}`, RoundRobin/Random/Sticky/Rendezvous; broker defaults to RoundRobin | rumqttd has RoundRobin/Random/Sticky; Mosquitto rotates each shared leaf list |
| Topic routing | Exact, `+`, `#`, `$SYS`, No Local, shared groups. Network-client PUBLISH and Will writes to broker-owned `$SYS` and `$share` namespaces are denied by default, with Mosquitto's `$SYS/broker/connection/+/state` exception and an explicit opt-out; trusted local producers retain `$SYS` access | Both references provide production topic indexes; Mosquitto applies the same built-in `$SYS`/`$share` write protection before configured ACLs |
| Listener topic namespaces and policy | Heterogeneous TCP/Unix/TLS/WS/Unix-WS/WSS `PendingSource`s can share one Broker core and deadline driver. Per-listener namespaces map PUBLISH/Will topics and ordinary/shared filters into canonical broker space, then strip the destination prefix from live, retained and durable Session delivery. Each listener may override CONNECT/CONNACK policy and add CONNECT plus live publish/subscribe/unsubscribe/delivery authorization on top of mandatory broker-wide policy; its negotiated Maximum QoS controls subscription grants plus live and durable delivery | Mosquitto `mount_point` applies a literal prefix at ingress and removes it per destination listener; Maximum QoS, authentication and selected limits may be listener-scoped with `per_listener_settings` |
| Broker configuration | Public `mqtt.broker_config` parses and deep-owns a strict Mosquitto-style subset for TCP/Unix/TLS/WebSocket/WSS listeners, including `listener 0 PATH` raw Unix endpoints with stable listener identity and teardown cleanup, bounded ordered main-file `include_dir` expansion, and inbound, outbound, mixed, or bidirectional `connection` bridges sharing one remote Session with one or more DNS/IPv4/bracketed-IPv6 targets on a single `address` or `addresses` directive. The aliases share duplicate-directive validation and feed the same primary-preferred periodic failback or round-robin failover runtime. Bridge configuration also supports disjoint `topic ... in|out|both ...` QoS 0/1/2 rules, local/remote prefix mapping, MQTT 3.1/3.1.1/5 Session selection, upstream credentials, Keep Alive, fixed or stateful decorrelated-jitter restart policy with stable-connection reset, automatic, one-shot, or threshold-triggered lazy outbound lifecycle with idle disconnect, retained local/remote connection-state notifications, and vail-backed TLS 1.3 with explicit CA files, bounded OpenSSL-style CA directories, operating-system CA trust, hostname verification, ALPN, and optional encrypted-key mTLS. The production runner supervises bridge generations behind a bridge-local cancellation domain, propagates fatal bridge failures into whole-service shutdown, and supports per-bridge `bridge_reload_type lazy|immediate` replacement without interrupting listeners or ordinary clients. It uses an identity-and-mapping-derived stable ID plus a crash-safe journal for persistent QoS 2. It also provides a Mosquitto-compatible `memory_limit` hard cap over broker-owned heap allocations (zero means unlimited), exact thread-safe allocation/resize/remap accounting, and live SIGHUP limit changes that do not forcibly release existing state; separate cross-listener caps govern simultaneously admitted connections through `global_max_connections` and active/offline Sessions through `global_max_clients`. Listener-local P-256/P-384/P-521/Ed25519 and 2048/3072/4096-bit RSA PEM `certfile`/`keyfile`, PBES2-encrypted PKCS#8 keys with file-backed passwords, ordered OpenSSL-style TLS 1.2 and TLS 1.3 cipher-suite policies, optional or required client certificates through strict `cafile` and bounded TCP/TLS `capath` trust sources plus `require_certificate`, Ed25519, P-256 ECDSA/SHA-256, P-384 ECDSA/SHA-384, or 1024-4096-bit RSA PKCS#1 v1.5 SHA-256 `crlfile` with directly signed base/delta composition, exact repeatable `websockets_origin` allowlists and a bounded global `websockets_headers_size`, verified certificate-CN and OpenSSL-compatible RFC 2253 full-Subject usernames through `use_identity_as_username`/`use_subject_as_username`, mount points, anonymous and zero-length Client ID policy with global or per-listener assigned-ID prefixes, deprecated global `clientid_prefixes` admission, Maximum QoS/Keep Alive, inbound and broker-created Topic Alias limits, username-derived Client IDs, connection and bidirectional inflight bounds, offline QoS 0, global outgoing QoS upgrade and TCP_NODELAY policy, per-bridge TCP keepalive and Linux TCP user-timeout policy, global or `per_listener_settings`-isolated password/ACL/zero-length-ID settings, and snapshot/autosave settings are supported. All config and security files, server identities, CA bundles/directories and CRLs are validated before any listener is opened. Linux SIGHUP reloads bridge definitions plus the configured password/ACL and TLS/WSS identity/key-password/CA/CRL file contents; bridge parse or preparation failure retains all active bridge generations, while security parse/load failure retains the complete old policy and TLS generations. Successful password changes selectively administratively disconnect live users whose parsed credential changed or disappeared without publishing their Wills. Public `mqtt.password_file` validates and verifies Mosquitto Argon2id, `$7$` PBKDF2-SHA512, and legacy `$6$` salted SHA-512 entries, rejects plaintext/malformed/duplicate/unreasonably expensive input before listening, uses constant-time hash comparison, and serializes KDF work to bound concurrent Argon2 memory. Public `mqtt.acl_file` implements anonymous/user topic rules, global `%u`/`%c` patterns, read/write/readwrite access, default deny and deny precedence. The production example's exclusive `--config=PATH` mode creates all listeners and bridges over one shared Broker and enforces each transport/authentication/ACL policy | Mosquitto additionally supports broader listener reload policies and many additional listener/global controls; rumqttd uses its own structured configuration |
| Fanout ownership | One ref-counted topic/payload/property allocation shared by every downstream delivery | Mirrors Mosquitto's `mosquitto__base_msg` reference-counted fanout |
| Publisher acknowledgement | Route and durable commit before PUBACK; a self-matched PUBLISH is written first on the shared connection, while unrelated slow subscribers cannot delay PUBACK; MQTT 5 reason `0x10` when no subscription matches | Matches Mosquitto `handle_publish.c`; rumqttd uses its router event path |
| Retained messages | Bounded Store integrated into live publish/subscribe, with expiry, Retain Handling, No Local, shared suppression, QoS and identifiers. Expired entries are always suppressed lazily; optional Mosquitto-compatible `retain_expiry_interval` also drives periodic physical pruning through the shared lifecycle timer and persists each non-empty cleanup to snapshots/journals. Original effective Client ID, username, and stable source-listener identity are deep-owned and persisted so replay can recheck the publisher's current global or per-listener write authorization; Mosquitto-compatible `check_retain_source` defaults on and can be disabled explicitly | Both production brokers integrate retained delivery; Mosquitto defaults `check_retain_source` on to prevent revoked publishers' stored messages from replaying and persists source ID, username, and listener port |
| Broker sessions | Live Session Present/Clean Start/Expiry/takeover, including an active deadline task that atomically retires idle expired Sessions from routing and inbound QoS 2 state without waiting for later client traffic; pre-registration CONNECT authorization with transport source, PROXY metadata and verified peer chains, pre-mutation PUBLISH/SUBSCRIBE/UNSUBSCRIBE access control, per-recipient delivery authorization before live/retained/offline queue mutation plus reconnect-time rechecks, unique assigned identifiers with an allow/deny policy for zero-length Client IDs, persistent subscriptions, offline QoS 1/2 queues and reconnect retransmission, Mosquitto-compatible `global_max_clients` across active and unexpired offline Sessions, global `max_queued_messages`/`max_queued_bytes`, plus opt-in offline QoS 0 queueing. Capacity refusal is pre-registration and returns MQTT 5 Server Busy; MQTT 3.1.1 closes because it has no equivalent code. Queue limits govern new admission and fail closed during snapshot restore if persisted state exceeds the configured bounds. SUBSCRIBE capacity is enforced per filter: MQTT 5 now returns `0x97` and MQTT 3.1.1 `0x80` only for over-limit new filters while same-packet authorized filters still succeed, existing filters still replace in place at capacity, and ACL-denied filters keep their distinct failure reason. | rumqttd graveyard/datalog and Mosquitto persisted sessions are integrated; Mosquitto exposes `allow_zero_length_clientid`, password files, certificate identity/subject usernames, distinct read/write/subscribe/unsubscribe ACLs, `max_queued_messages`, `max_queued_bytes`, and `queue_qos0_messages` |
| Will lifecycle | Indexed scheduler integrated into live Broker: abnormal close, DISCONNECT 0x04, Delay/Session Expiry, reconnect cancellation, retained Will, and publication-time write authorization | Both production brokers integrate Will publication; Mosquitto rechecks its write ACL when the Will becomes due |
| Keep Alive | Broker enforces the negotiated 1.5x inbound inactivity deadline with exact half-second precision, zero-disable semantics and Will/Session cleanup; optional maximum accepts MQTT 5 with Server Keep Alive replacement and refuses over-limit/zero MQTT 3.1.1 CONNECTs. The Mosquitto-style listener `max_keepalive` parser maps zero to no administrative maximum | Mosquitto uses a broker-wide deadline ring and disconnects clients that exceed Keep Alive x 1.5; `max_keepalive` has the same version-specific negotiation/refusal behavior |
| CONNECT and PING liveness | Raw TCP, MQTT-over-TLS, WS, and WSS clients expose address, hostname, and validated URI entry points as appropriate; secure address APIs accept an independent TLS identity. Client `network_connect_timeout` gives DNS resolution and every TCP address attempt one absolute budget across TCP, native TLS, WS and WSS; native TLS and WSS also apply their independent TLS handshake timeout on both vail and standard-library clients. Every transport exposes caller-owned absolute-deadline entry points spanning DNS/TCP setup, TLS and HTTP Upgrade where applicable, CONNECT, every enhanced-authentication round, and final CONNACK while retaining stricter configured phase limits. MQTT WS/WSS proxy entry points extend that same absolute budget across proxy DNS/TCP, authority-form HTTP CONNECT and origin TLS without exposing proxy headers to the origin Upgrade. HTTP-redirect-aware WS/WSS entry points retain one deadline across every 3xx DNS/TCP/proxy/TLS/Upgrade hop and the later MQTT CONNECT/CONNACK; the combined MQTT 5 path retains that same timestamp across nested HTTP and Server Reference redirect chains. All four transports also expose matching relative-timeout wrappers that convert once at API entry. Partial MQTT bytes and unrelated protocol traffic cannot renew these deadlines. Clients also expose an absolute PINGREQ/PINGRESP round-trip timeout on all transports, preserving interleaved broker packets in a bounded ordered queue (plus one recoverable overflow packet already removed from the wire) | rumqttd exposes `connection_timeout_ms` around its initial packet read; rumqttc detects a PINGREQ that remains unacknowledged while continuing to dispatch other events; Mosquitto relies on its listener/event-loop timeout machinery |
| Client reconnect | An owning reconnect client deep-copies CONNECT credentials/properties/Will plus raw hostname or canonical `mqtt://`/`tcp://` targets. Native-TLS reconnect connectors cover fixed addresses, DNS hostnames, and `mqtts://`/`ssl://` URIs, re-resolving names and deriving SNI on each attempt; WS/WSS connectors retain the same URI behavior. A separate HTTP-proxy connector opens a fresh CONNECT tunnel for every WS/WSS attempt, keeps proxy and origin headers isolated, honors reconnect-owned absolute deadlines, and forwards both TLS 1.2 and TLS 1.3 resumption tickets to WSS. The HTTP-redirect connector restarts a bounded 3xx chain on every reconnect and forwards cached tickets to the initial origin; WebSocket policy preserves them only across same-origin hops and clears them before any cross-origin handshake. These encrypted connectors remain borrowed because they can reference caller-managed certificates and callbacks. The client retries with bounded fixed, linear, or exponential delay, optional unbiased full/equal jitter, or stateful decorrelated jitter. A caller can delay the first attempt after an established transport closes and reset decorrelated history only after a configured stable-connection period; the absolute retry deadline survives shorter `connectWithDeadline` calls. All backoff waits remain interruptible through `std.Io.Event`. Its single-owner bounded poll API continuously reconnects, negotiates Server Keep Alive, sends PINGREQ while idle, rejects a missing PINGRESP within a configurable deadline, preserves partially received TCP packets across poll timeouts, and exposes ordered connect/publish/QoS/ping/DISCONNECT/AUTH events; `serveUntil` provides a cancellation-aware callback driver with automatic event cleanup. A bounded multi-producer `CommandQueue` feeds publish/subscribe/unsubscribe/disconnect/manual-ack/flush/re-auth operations to `serveQueuedUntil`, retains the loop as sole socket owner, provides owned asynchronous PUBLISH/SUBSCRIBE/UNSUBSCRIBE/DISCONNECT/manual acknowledgements with correlated typed callbacks or a bounded blocking/nonblocking `CompletionQueue`, and bounds command work between network reads. Its PUBLISH producer offers immediate full-queue rejection and timeout-bounded capacity waiting. Completion-queue SUBACK/UNSUBACK reason codes and properties are deep-owned beyond the network callback. Queued graceful disconnect supports MQTT 5 reason codes/properties, emits MQTT 3.1.1's minimal packet, completes only after the write, and then stops instead of reconnecting. Inbound QoS 1/2 acknowledgement is automatic by default or application-controlled with MQTT 5 reason codes/properties; accepted manual QoS 2 transactions are persisted before PUBREC, suppress duplicate delivery, and resume through PUBREL/PUBCOMP. An opt-in deferred inbound-QoS2 release policy surfaces PUBREL without deleting the Session marker or sending PUBCOMP; `completeIncomingQoS2` emits PUBCOMP only after the application establishes its own release boundary, retains the marker across write failure, and then completes it after a successful write. The Bridge combines this with its broker-owned durable store for end-to-end inbound QoS 2. An optional publish-delivery observer reports QoS 0 after the socket write, QoS 1 at PUBACK, and QoS 2 only at PUBCOMP or a negative PUBREC, including borrowed MQTT 5 diagnostics; Mosquitto exposes an equivalent terminal publish callback while rumqtt exposes lower-level incoming/outgoing events. It applies outbound acknowledgements and drives arbitrary multi-step client-initiated, server-challenged MQTT 5 re-authentication through the CONNECT authentication callback while preserving its returned properties. It retains outgoing QoS 1/2 across transport loss, replays PUBLISH with DUP and its original Packet Identifier when Session Present is true, resumes outgoing QoS 2 directly at PUBREL after PUBREC, clears stale QoS state when the broker reports no Session, and replays only broker-accepted subscriptions into that fresh Session. | rumqttc continuously reconnects while polled and owns its hostname in `MqttOptions`; libmosquitto exposes hostname-based sync/async reconnect plus fixed/progressive reconnect delay control |
| Broker bridges | `mqtt.bridge.Bridge` owns one reconnect client targeting a fixed address, re-resolved cleartext hostname, or caller-supplied connector such as native TLS; the production config adapter selects the vail TLS 1.3 data plane with CA and hostname verification plus optional mTLS, plus one or more non-overlapping remote subscription rules (QoS 0/1/2), maps each remote Topic Name by stripping its optional remote prefix before adding the rule-specific local prefix, and can publish retained local/remote connection state with a remote Last Will. Remote QoS 1 is manually acknowledged only after local routing completes. QoS 2 requires an explicit stable bridge identity, persistent upstream Session and enabled local commit log; it durably stages before PUBREC, atomically injects at PUBREL, and retains a released tombstone until PUBCOMP is written. `mqtt.bridge.OutboundBridge` composes a broker-local source Session with one remote reconnect Session and supports outbound, mixed-direction, and `both` rules without opening a second remote connection. MQTT 5 uses No Local on both bridge-facing subscription sides; MQTT 3.1 and 3.1.1 require the private bridge extension without fallback. Successful target CONNACK capabilities cap ordinary outbound QoS, clear unsupported RETAIN, and reject rather than silently weaken durable QoS 2 when the target Maximum QoS is lower. Outbound QoS 2 uses a separate identity-bound coordinator journal, while inbound QoS 2 uses the broker commit log and restores receive markers into the same remote reconnect client. Both directions strip connection-scoped Topic Alias and Subscription Identifier metadata and add no unbounded intermediate queue. | Rumqttd's `BridgeLink` is one-way in the audited tree; Mosquitto supports explicit in/out/both rules with local/remote prefix remapping on one bridge connection |
| MQTT 5 Enhanced Authentication | Initial multi-step AUTH before CONNACK, owned method binding, interleaved re-authentication traffic and broker policy callback; unnegotiated/mismatched live AUTH receives Protocol Error before close | Mosquitto plugin start/continue callbacks and active re-authentication; rumqtt codec/runtime coverage is narrower |
| MQTT 5 information preferences | Configurable Response Information is emitted only when CONNECT explicitly requests it; Request Problem Information defaults to enabled and an explicit zero removes Reason String/User Property from server ACK/AUTH packets while retaining functional authentication properties and the reason code | Both references parse/model the CONNECT fields, but the audited Mosquitto documentation labels them supported but unused and rumqttd does not apply them in its router |
| MQTT 5 Server Reference | CONNACK/DISCONNECT property access, redirect-reason validation, URI and host:port parsing, bounded loop-detecting opt-in redirect chains, authorization callback, and automatic TCP/TLS/WS/WSS CONNACK redirect helpers; TLS/WSS derive certificate identity from every new authority, while proxy-routed WS/WSS redirects issue a fresh CONNECT for every authority through the same configured proxy. The combined WS/WSS helper first completes HTTP redirects for each MQTT hop and feeds the actual authenticated final URI into MQTT loop detection, default-transport selection and authorization rather than the pre-redirect load-balancer URI | The audited rumqtt codecs expose the property/reasons but no automatic client redirection; Mosquitto documents Server Reference as supported but unused |
| Broker persistence | Atomic versioned snapshots plus opt-in interval- or durable-change-count-driven live checkpoints, with both the replacement file and its parent directory synced on supported POSIX targets; and a separate opt-in fsynced append journal with the same directory-durable initialization/compaction, for retained messages, scheduled Wills, durable Sessions, opt-in queued QoS 0, outgoing QoS 1/2 and inbound QoS 2 transactions | rumqttd datalog/segments; Mosquitto persisted sessions, subscriptions, bidirectional client-message state and retained/Will base messages; Mosquitto can interpret its autosave threshold as elapsed seconds or persistence changes |
| Observability | `Broker.stats()` takes one allocation-free, state-locked snapshot of uptime, admitted CONNECT count, live connections, the process high-water connection count, cumulative expired Sessions, complete MQTT Control Packet/message and MQTT-byte counters, inbound/outbound/dropped PUBLISH counters and payload-byte counters, connected/offline Sessions, ordinary/shared subscriptions, retained state, live queues, durable queues/inflight, inbound QoS 2 and scheduled Wills, including owned byte gauges. State-backed gauges form one coherent instant; wire and PUBLISH counters are independently sampled lock-free atomics and include each complete operation, so callers that need an exact asynchronous boundary use a same-connection acknowledgement or PING barrier and observe the counter afterward. `publishSystemStats()` and `system_stats_interval` publish the snapshot as retained QoS 0 `$SYS` messages through normal routing and ACL checks; production config exposes Mosquitto-compatible global `sys_interval` with a 10-second default and zero-disable behavior. Metrics include `$SYS/broker/version` (`netz version 0.1.0`), `$SYS/broker/uptime`, Mosquitto's `$SYS/broker/clients/active` and `$SYS/broker/clients/inactive` aliases alongside `connected`/`disconnected`, `$SYS/broker/messages/stored` and its `$SYS/broker/store/messages/count` alias plus `$SYS/broker/store/messages/bytes` for durable queued messages, `$SYS/broker/packet/out/count` and `$SYS/broker/packet/out/bytes` for outbound MQTT packets, `$SYS/broker/connections/socket/count` for cumulative accepted listener transports (including peers later refused), cumulative message/byte/client/PUBLISH topics, optional application-reported `$SYS/broker/heap/current` and `$SYS/broker/heap/maximum` gauges when `Broker.Options.heap_source` is set, and 1/5/15-minute EWMA socket, connection, message, PUBLISH, drop, and byte rates. Wire counters span TCP/TLS/WS/WSS, count CONNECT before admission and successful CONNACK/control writes, and exclude lower-transport framing. PUBLISH counters saturate instead of wrapping. Drops count per destination rejected by a live or durable queue bound or negotiated Maximum Packet Size; ordinary no-match, ACL denial, and expiry are distinct outcomes. Like Mosquitto, `$SYS` updates actually written to subscribers contribute to the following sent-PUBLISH and total-message/byte snapshots | Mosquitto periodically publishes a broad counter/gauge and rolling-load set through `$SYS`; rumqttd exposes metrics through its server architecture |

The configured runner also supports Mosquitto's `pid_file` lifecycle with a
stronger ownership boundary than the audited reference's truncate-and-remove
implementation. It opens the final path without following a symbolic link and
holds a nonblocking exclusive advisory lock for the process lifetime. A
concurrent configured broker therefore fails before listener creation, a stale
file after forced termination is reclaimable, and normal cleanup removes only
the unchanged inode and exact PID contents owned by that process. Replacing the
path externally cannot make the exiting broker delete the replacement. The
path is restart-required on SIGHUP.

The complete restart-required SIGHUP set is
`global_max_clients`, `global_max_connections`, `max_packet_size`,
`max_inflight_messages`, `max_inflight_bytes`, `max_queued_messages`,
`max_queued_bytes`, `pid_file`, `websocket_headers_size`, and
`set_tcp_nodelay`. A reload that changes any of them is rejected transactionally
with `GlobalConfigurationRequiresRestart`, and the running broker keeps its
previous capacity and policy. These fields bound preallocated slot tables,
per-connection buffers, or process-level identity, so applying them live would
require unbounded reallocation or listener recreation. Every `Config` field is
exhaustively classified at compile time in
`examples/support/mqtt_reload_compatibility.zig`, so a newly added field cannot
be silently ignored by the reload path.

Native MQTT clients now also expose SOCKS5 transport composition through the
public, protocol-independent `proxy.socks5` module and
`mqtt.socks5_runtime`. The RFC 1928 layer sends DNS names to the proxy instead
of resolving the broker locally, supports IPv4/IPv6/domain CONNECT targets and
all three reply address forms, maps every standard reply code, and keeps proxy
DNS/TCP, RFC 1929 authentication, and CONNECT under one absolute deadline.
Username/password callers may retain Mosquitto-compatible no-auth fallback or
require authentication, in which case the client advertises only method 0x02
and rejects downgrade. Cleartext and hostname-verified TLS clients expose
ordinary, CONNACK-preserving, timeout/deadline, and reconnect adapters; the TLS
reconnector retains TLS 1.2/1.3 tickets without changing the origin SNI. The
independent Python gate covers delayed-method timeout, no-auth, successful and
failed RFC 1929 authentication, remote-only broker DNS, MQTT 5 PING/DISCONNECT,
TLS 1.3 certificate/hostname verification, and fresh cleartext/TLS reconnect
tunnels. This was implemented after auditing Mosquitto's
`lib/socks_mosq.c` and its `03-publish-socks*.py` process cases under
`/nav_env/Work/mosquitto`.

The same SOCKS5 tunnel now composes with MQTT-over-WS/WSS without a second MQTT
state machine: deadline-aware WebSocket caller-stream APIs perform cleartext or
origin-authenticated TLS Upgrade, and `mqtt.websocket_runtime.Client` adopts
the negotiated `mqtt` connection while preserving the remaining absolute
budget. The cross-protocol peer gate proves remote proxy DNS, Host/SNI
isolation, TLS 1.3 hostname verification, and MQTT CONNECT/PING/DISCONNECT over
both WS and WSS. A fresh 2026-11-01 run passed HTTP/HTTPS, WS/WSS, MQTT-over-WS
and MQTT-over-WSS through remote-DNS SOCKS5 with TLS 1.3 hostname verification
and one absolute deadline; see `docs/evidence/websocket_socks5/2026-11-01.json`.

MQTT-over-WebSocket HTTP redirects and reconnect connectors also accept the
same first-class SOCKS5 route. Every reconnect restarts the complete redirect
chain and opens a new tunnel for every authority; one caller deadline spans the
SOCKS, TLS, Upgrade, MQTT authentication, and CONNACK phases. The independent
multi-authority gate runs the connector twice, requires four WSS tunnels after
the two-tunnel WS redirect, and proves Authorization is present at each initial
origin but absent after the cross-port redirect. A fresh 2026-11-01 run
repeated one WS redirect and two WSS reconnect chains across exactly six
tunnels with isolated credentials; see
`docs/evidence/websocket_socks5_redirect/2026-11-01.json`.

## MQTT 3.1/3.1.1/5 broker interoperability

The live TCP listener now follows Mosquitto's version negotiation model: the
configured protocol is only an initial parser default, while CONNECT selects
MQTT 3.1.1 or MQTT 5 independently for every accepted socket.

- MQTT 3.1, MQTT 3.1.1 and MQTT 5 publishers/subscribers can share one listener and route
  between versions.
- Empty clean-session Client IDs receive secure random UUID-style identities
  with a copied, configurable prefix. MQTT 5 reports the value through Assigned
  Client Identifier and the client runtime preserves it after CONNACK cleanup;
  successful MQTT 5 handshakes reject a missing or empty assignment for an
  empty requested ID and reject an unsolicited replacement for a non-empty ID.
  MQTT 3.1.1 uses the unique identity internally without an unavailable
  property. Multiple anonymous clients therefore cannot accidentally take over
  the same empty-string Session, and an MQTT 5 client can reconnect using its
  assigned value.
- MQTT 5 Application Message properties are preserved for MQTT 5 destinations
  and omitted when encoding the same fanout for an MQTT 3.1.1 destination.
- Clients reject unsolicited CONNACK Response Information and Authentication
  Method properties before committing negotiated or authentication state;
  servers emit Response Information only after an explicit CONNECT request.
- MQTT 3.1.1 CleanSession=0 resumes subscriptions and offline QoS 1/2 state
  indefinitely, while CleanSession=1 discards that Session.
- CONNACK Session Present, SUBACK, UNSUBACK and QoS ACK packets use each
  connection's wire format. A Clean Start request forces Session Present off
  in server responses, while clients reject a peer that returns the forbidden
  combination under either MQTT 3.1.1 or MQTT 5. MQTT 5-only reason codes are
  downgraded to the success-only MQTT 3.1.1 ACK representation.
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
MQTT-2.1.3-1 classifies invalid fixed-header reserved flags as a Malformed
Packet. Ten Mosquitto-derived raw cases span PUBACK/PUBREC/PUBREL/PUBCOMP,
SUBSCRIBE/UNSUBSCRIBE, PINGREQ/PINGRESP, PUBLISH QoS 0 with DUP, and PUBLISH QoS 3;
each receives exact DISCONNECT `0x81`. The runtime validates fixed-header
syntax before endpoint direction or state, so a packet invalid in both ways is
still reported as malformed. A distinct `InvalidPacketDirection` error keeps
legal encodings sent by the wrong endpoint mapped to Protocol Error `0x82`.
Every established runtime write and read boundary also enforces the endpoint
direction assigned by MQTT 5 Table 2-1 (and shared by MQTT 3.1.1): CONNECT,
SUBSCRIBE, UNSUBSCRIBE, and PINGREQ are client-only, while CONNACK, SUBACK,
UNSUBACK, and PINGRESP are server-only. PUBLISH, all four QoS acknowledgements,
DISCONNECT, and MQTT 5 AUTH remain bidirectional subject to their more specific
state and reason-code rules. Public writers fail before allocation, state
mutation, or I/O. Four raw Mosquitto-derived negative vectors send each
server-only packet type from a client, require exact DISCONNECT Protocol Error
`0x82`, and then prove the finite broker still accepts a healthy CONNECT/PING.

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
- A broker authentication policy can instead call `rejectAuthentication` with
  a validated non-success CONNACK reason. Authorization and rejection are
  mutually exclusive, and the property-free refusal is sent before any
  Session, Will, or routing state becomes visible.
- `setAuthenticatedUsername` deep-owns a mechanism-established UTF-8 identity
  with the pending connection's allocator, clears the obsolete wire password,
  and freezes identity after authorization or rejection. Connect policy,
  Session/Will registration, publish ACLs, delivery ACLs and retained-source
  tracking therefore observe the same username.
- Active clients can start and servers can accept re-authentication while
  ordinary PUBLISH, QoS acknowledgement, subscription and PING traffic keeps
  using the established identity, as permitted by MQTT 5 section 4.12.1.
  Initial authentication still gates traffic until successful CONNACK. AUTH
  methods and sender-specific reason codes remain bound throughout the exchange.
- Synchronous re-authentication readers select AUTH from a bounded queue while
  preserving other packets in wire order. Timeout/deadline variants retain the
  exchange and queued packets across a shorter caller budget; local decoding
  failure and queue overflow preserve consumed bytes for retry. A DISCONNECT
  ends the wait and remains available with its diagnostics to ordinary readers.
  Live-broker tests verify QoS 1/2 progress, receive counters, subscriptions and
  the mechanism-established username before AUTH Success.
- Valid DISCONNECT packets retire the shared runtime across typed, client-event
  and broker-event readers. PING, QoS and subscription completion waits stop
  with `ConnectionClosed` without waiting for another packet or peer EOF, while
  preserving preceding queued traffic and the owned DISCONNECT diagnostics.
  An earlier queued ACK can still complete its exchange; packets following the
  terminal boundary are released, including the emergency overflow slot. A
  live AUTH wait retains a terminal diagnostic in that slot even when ordinary
  traffic has exhausted the pending packet-count or byte quota. A
  successfully sent DISCONNECT is also the final MQTT packet and interrupts
  the underlying TCP, TLS or WebSocket transport without releasing caller
  ownership. Invalid peer DISCONNECT syntax or properties remain protocol
  errors so the owner can send the appropriate MQTT 5 diagnostic before closing.
- Direct synchronous re-authentication uses the same method/state validation
  and Protocol Error DISCONNECT as the event reader. A changed Authentication
  Method retires the connection after its diagnostic write.
- A typed reader expecting CONNECT, CONNACK, PUBLISH, a QoS acknowledgement,
  subscription control, PING or AUTH also handles DISCONNECT as a terminal
  packet. It returns `ConnectionClosed` while retaining the packet for
  `readDisconnect` or an ordinary event reader. Repeated typed attempts cannot
  discard that diagnostic or read beyond it. Direct `readDisconnect` decoding
  retains the exact complete packet on local allocation failure and releases
  post-terminal queued data only after successful validation and consumption.
- Client and broker event readers retain the same complete DISCONNECT packet
  across local property-decoding allocation failures, including timeout,
  Keep Alive, caller-storage and reserved-prefix variants. Short TCP terminal
  packets own their bytes before read-ahead is consumed, so retries never
  depend on a caller's temporary storage. The reserved-prefix broker path now
  consumes pending packets before transport read-ahead and obeys both local
  and peer termination. Caller-output events remain untouched on failure;
  complete packet traffic counters are charged once across decode retries.
  A connection-owned terminal slot preserves these retries without allocating
  pending queue state for ordinary borrowed TCP acknowledgements. Broker slot
  and listener capacity availability are published together during cleanup;
  local socket shutdown is not an acknowledgement of server-side cleanup.
- A live broker policy can reject re-authentication with a validated
  DISCONNECT reason and optional properties. A successful write atomically
  retires the connection, stops its event loop and prevents any later MQTT
  operation from reusing the rejected authentication state.
- AUTH reason codes follow MQTT 5 Table 3-11 at every shared TCP/TLS/WS/WSS
  read and write boundary: only clients can send Re-authenticate `0x19`, only
  servers can send Success `0x00`, and Continue Authentication `0x18` remains
  bidirectional. Public writers reject wrong-direction codes before I/O; a raw
  client sending AUTH Success receives DISCONNECT Protocol Error `0x82`.
- `readBrokerEvent` exposes AUTH and the live broker has an optional policy
  callback for re-authentication rather than treating AUTH as an unexpected
  packet.
- a missing or changed Authentication Method is rejected; peer-initiated
  mismatch emits DISCONNECT Protocol Error as Mosquitto does.
- a source-locked production-process port of Mosquitto's
  `09-auth-bad-method.py` sends CONNECT with Authentication Method `basic`
  while no mechanism is configured and requires the exact property-free
  CONNACK Bad Authentication Method `0x8c` response.
- send-side phase transitions are committed transactionally around network
  writes, and rejected inbound packets release their owned packet buffers.

A source-locked production-process port now directly executes Mosquitto's
`09-extended-auth-multistep-reauth.py`: a mirror-method initial challenge,
successful CONNACK, PING, active multi-step re-authentication, return to PING,
and changed-method DISCONNECT Protocol Error `0x82`, all through the live
broker callback. Internal end-to-end tests additionally prove ordinary traffic
is gated during initial authentication and remains usable during
re-authentication. The runtime deliberately supplies
protocol orchestration and policy hooks, not a built-in SCRAM or credential
database; the deterministic mirror policy exists only in the interop fixture.
The same source-locked production-process gate completely ports Mosquitto's
five-case `09-extended-auth-single.py` matrix: plugin failure closes without a
packet, an unknown method returns `0x8c`, bad single-step data returns `0x87`,
valid single-step data succeeds with the bound method, and mirror data returns
the exact reversed final Authentication Data. The successful CONNACKs retain
Netz's independently advertised bounded runtime capabilities.
A third source-locked process case directly ports
`09-extended-auth-reauth.py`: initial `repeat` authentication succeeds, the
client starts re-authentication with the bound method and data, and the policy
returns an exact property-free Not Authorized DISCONNECT `0x87`. The broker
then terminates that connection normally rather than leaving a readable or
writable half-closed state.
The source-locked portable identity/ACL core of
`09-extended-auth-change-username.py` runs two distinct process cases: an
anonymous subscriber may subscribe but its QoS 1 write receives `0x87` and no
delivery, while the `change` mechanism establishes `new_username` and the same
publish produces both a successful PUBACK and its authorized QoS 1 delivery.
Mosquitto repeats identical wire traffic under global and per-listener config;
Netz covers those policy scopes in its separate configuration matrix instead
of duplicating this single-listener vector.

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

