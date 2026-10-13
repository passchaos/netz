# netz vs rumqtt and Mosquitto MQTT parity audit

This audit records evidence for the MQTT portion of the netz improvement goal.
The source references are `~/Work/rumqtt` at `e886a78` and
`~/Work/mosquitto` at `5cd25465`. Rumqtt contains both a production broker
(`rumqttd`) and clients (`rumqttc`); Mosquitto supplies a mature broker,
persistence format, and conformance suite. Feature, internal microbenchmark,
and same-client broker results are kept separate.

## Current feature comparison

| Area | netz | rumqtt / Mosquitto references |
| --- | --- | --- |
| Listener socket family | Mosquitto-style `socket_domain ipv4|ipv6` and `bind_interface` are listener-local across TCP, TLS, WS, and WSS. Omitted bind addresses become the selected family's wildcard, explicit address-family mismatches fail configuration when no interface overrides the address, and IPv6-only sockets set `IPV6_V6ONLY` before bind. With neither an address nor `socket_domain`, the configured runner opens separate IPv4 and IPv6 wildcard sockets when supported; both share the logical listener's admission cap and policy. A named interface takes precedence over the listener address and contributes its first address from each selected family without requiring privileged `SO_BINDTODEVICE`. Backend, interface, or explicitly selected family limitations fail closed; only an unavailable family in an all-family listener is skipped. | Mosquitto likewise enumerates all supported families by default, creates a separate socket for each, resolves `bind_interface` through `getifaddrs`, and restricts a listener to the configured family; rumqttd has no equivalent audited listener option |
| MQTT versions | MQTT 3.1.1 and MQTT 5 packet/runtime; TCP, Unix-domain, WebSocket and secure listeners auto-detect both versions. Listener-local `accept_protocol_versions` admits `4`, `5`, or both and sends version-correct refusal CONNACKs before Session, Will, or route registration; unsupported MQTT 3.1 configuration fails closed. MQTT 5 Topic Alias uses sparse per-connection storage and supports the complete non-zero u16 range instead of imposing a private small-table cap. | rumqtt clients support 3.1.1/5; Mosquitto broker supports 3.1/3.1.1/5 and exposes the same listener version policy |
| Trusted proxy ingress | Opt-in, bounded HAProxy PROXY v1/v2 parsing before MQTT CONNECT, TLS or WS/WSS Upgrade, with IPv4/IPv6/Unix endpoints, LOCAL/UNKNOWN handling, CRC32C, ALPN/authority/unique-id/network-namespace, and nested SSL TLVs exposed as owned connection metadata. The production Mosquitto-style config exposes listener-local `enable_proxy_protocol 1|2` and `proxy_protocol_v2_require_tls`; on cleartext v2 listeners, `require_certificate` requires verified connection/session certificate evidence and `use_identity_as_username` accepts only a validated SSL-TLV commonName. Local TLS termination and full-Subject identity remain invalid with v2 | Mosquitto supports listener-level PROXY v1/v2, including address replacement and selected SSL TLVs; rumqttd has no equivalent listener surface in the audited tree |
| Live broker dispatch | Bounded connection slots and queues; SUBSCRIBE/UNSUBSCRIBE; QoS 0/1/2 fanout; downstream Receive Maximum; cleanup | Both references are production brokers with broader lifecycle support |
| QoS | Runtime and live broker QoS 0/1/2, including exactly-once route at PUBREL; broker Maximum QoS caps subscription grants and live/durable delivery. Mosquitto-compatible global `max_inflight_messages` defaults to 20, bounds each client's incoming and outgoing QoS 1/2 transactions, advertises MQTT 5 Receive Maximum, enforces the same unadvertised bound for MQTT 3.1.1, and maps zero to the protocol default of 65,535 while retaining independent aggregate/memory bounds. Global `max_inflight_bytes` independently bounds outgoing QoS 1/2 payload bytes for transient connections and durable Sessions through final acknowledgement, and defaults to unlimited | Both brokers support QoS 0/1/2; Mosquitto applies its listener Maximum QoS to grants, delivery, and Wills and exposes the same global inflight settings |
| Packet and Application Message size policy | Mosquitto-style global `max_packet_size` defaults to 2,000,000 bytes, caps complete inbound MQTT Control Packets across TCP/TLS/WS/WSS, and is advertised in MQTT 5 CONNACK. The independent `message_size_limit` payload-byte cap covers live QoS 0/1/2 PUBLISH and Will acceptance; MQTT 5 uses Implementation Specific Error for PUBACK/PUBREC and Packet Too Large for CONNACK/DISCONNECT, while MQTT 3.1.1 completes representable acknowledgements | Mosquitto exposes both `max_packet_size` and `message_size_limit`; rumqttd exposes `max_payload_size` |
| Retain availability policy | Mosquitto-style global `retain_available` defaults true. When disabled, MQTT 5 CONNACK advertises Retain Available 0 and retained PUBLISH or Will use receives reason 0x9A; MQTT 3.1.1 closes because it cannot represent that reason. The policy is shared by TCP/TLS/WS/WSS listeners | Mosquitto exposes global `retain_available`; rumqttd has retained-message storage but no equivalent audited configuration switch |
| Outgoing QoS policy | MQTT-compliant min(source, subscription) by default; explicit `upgrade_outgoing_qos` compatibility mode covers live, retained and durable Session delivery | Mosquitto exposes the same non-standard opt-in; rumqttd follows its configured routing policy |
| Shared subscriptions | Trie-indexed `{group, filter}`, RoundRobin/Random/Sticky/Rendezvous; broker defaults to RoundRobin | rumqttd has RoundRobin/Random/Sticky; Mosquitto rotates each shared leaf list |
| Topic routing | Exact, `+`, `#`, `$SYS`, No Local, shared groups. Network-client PUBLISH and Will writes to broker-owned `$SYS` and `$share` namespaces are denied by default, with Mosquitto's `$SYS/broker/connection/+/state` exception and an explicit opt-out; trusted local producers retain `$SYS` access | Both references provide production topic indexes; Mosquitto applies the same built-in `$SYS`/`$share` write protection before configured ACLs |
| Listener topic namespaces and policy | Heterogeneous TCP/Unix/TLS/WS/Unix-WS/WSS `PendingSource`s can share one Broker core and deadline driver. Per-listener namespaces map PUBLISH/Will topics and ordinary/shared filters into canonical broker space, then strip the destination prefix from live, retained and durable Session delivery. Each listener may override CONNECT/CONNACK policy and add CONNECT plus live publish/subscribe/unsubscribe/delivery authorization on top of mandatory broker-wide policy; its negotiated Maximum QoS controls subscription grants plus live and durable delivery | Mosquitto `mount_point` applies a literal prefix at ingress and removes it per destination listener; Maximum QoS, authentication and selected limits may be listener-scoped with `per_listener_settings` |
| Broker configuration | Public `mqtt.broker_config` parses and deep-owns a strict Mosquitto-style subset for TCP/TLS/WebSocket/WSS listeners, bounded ordered main-file `include_dir` expansion, and inbound, outbound, mixed, or bidirectional `connection` bridges sharing one remote Session with one or more DNS/IPv4/bracketed-IPv6 `address` targets with primary-preferred periodic failback or round-robin failover, disjoint `topic ... in|out|both ...` QoS 0/1/2 rules, local/remote prefix mapping, MQTT 3.1.1/5 Session selection, upstream credentials, Keep Alive, fixed or stateful decorrelated-jitter restart policy with stable-connection reset, automatic, one-shot, or threshold-triggered lazy outbound lifecycle with idle disconnect, retained local/remote connection-state notifications, and vail-backed TLS 1.3 with explicit CA files, bounded OpenSSL-style CA directories, operating-system CA trust, hostname verification, ALPN, and optional encrypted-key mTLS. The production runner supervises bridge generations behind a bridge-local cancellation domain, propagates fatal bridge failures into whole-service shutdown, and supports per-bridge `bridge_reload_type lazy|immediate` replacement without interrupting listeners or ordinary clients. It uses an identity-and-mapping-derived stable ID plus a crash-safe journal for persistent QoS 2. It also provides separate cross-listener caps for simultaneously admitted connections through `global_max_connections` and active/offline Sessions through `global_max_clients`, listener-local P-256/P-384/P-521/Ed25519 and 2048/3072/4096-bit RSA PEM `certfile`/`keyfile`, PBES2-encrypted PKCS#8 keys with file-backed passwords, ordered OpenSSL-style TLS 1.2 and TLS 1.3 cipher-suite policies, optional or required client certificates through strict `cafile` and bounded TCP/TLS `capath` trust sources plus `require_certificate`, Ed25519, P-256 ECDSA/SHA-256, P-384 ECDSA/SHA-384, or 1024-4096-bit RSA PKCS#1 v1.5 SHA-256 `crlfile` with directly signed base/delta composition, exact repeatable `websockets_origin` allowlists and a bounded global `websockets_headers_size`, verified certificate-CN and OpenSSL-compatible RFC 2253 full-Subject usernames through `use_identity_as_username`/`use_subject_as_username`, mount points, anonymous and zero-length Client ID policy with global or per-listener assigned-ID prefixes, deprecated global `clientid_prefixes` admission, Maximum QoS/Keep Alive, inbound and broker-created Topic Alias limits, username-derived Client IDs, connection and bidirectional inflight bounds, offline QoS 0, global outgoing QoS upgrade and TCP_NODELAY policy, per-bridge TCP keepalive and Linux TCP user-timeout policy, global or `per_listener_settings`-isolated password/ACL/zero-length-ID settings, and snapshot/autosave settings. All config and security files, server identities, CA bundles/directories and CRLs are validated before any listener is opened. Linux SIGHUP reloads bridge definitions plus the configured password/ACL and TLS/WSS identity/key-password/CA/CRL file contents; bridge parse or preparation failure retains all active bridge generations, while security parse/load failure retains the complete old policy and TLS generations. Successful password changes selectively administratively disconnect live users whose parsed credential changed or disappeared without publishing their Wills. Public `mqtt.password_file` validates and verifies Mosquitto Argon2id, `$7$` PBKDF2-SHA512, and legacy `$6$` salted SHA-512 entries, rejects plaintext/malformed/duplicate/unreasonably expensive input before listening, uses constant-time hash comparison, and serializes KDF work to bound concurrent Argon2 memory. Public `mqtt.acl_file` implements anonymous/user topic rules, global `%u`/`%c` patterns, read/write/readwrite access, default deny and deny precedence. The production example's exclusive `--config=PATH` mode creates all listeners and bridges over one shared Broker and enforces each transport/authentication/ACL policy | Mosquitto additionally supports broader listener reload policies and many additional listener/global controls; rumqttd uses its own structured configuration |
| Fanout ownership | One ref-counted topic/payload/property allocation shared by every downstream delivery | Mirrors Mosquitto's `mosquitto__base_msg` reference-counted fanout |
| Publisher acknowledgement | Route and durable commit before PUBACK; a self-matched PUBLISH is written first on the shared connection, while unrelated slow subscribers cannot delay PUBACK; MQTT 5 reason `0x10` when no subscription matches | Matches Mosquitto `handle_publish.c`; rumqttd uses its router event path |
| Retained messages | Bounded Store integrated into live publish/subscribe, with expiry, Retain Handling, No Local, shared suppression, QoS and identifiers. Expired entries are always suppressed lazily; optional Mosquitto-compatible `retain_expiry_interval` also drives periodic physical pruning through the shared lifecycle timer and persists each non-empty cleanup to snapshots/journals. Original effective Client ID, username, and stable source-listener identity are deep-owned and persisted so replay can recheck the publisher's current global or per-listener write authorization; Mosquitto-compatible `check_retain_source` defaults on and can be disabled explicitly | Both production brokers integrate retained delivery; Mosquitto defaults `check_retain_source` on to prevent revoked publishers' stored messages from replaying and persists source ID, username, and listener port |
| Broker sessions | Live Session Present/Clean Start/Expiry/takeover, including an active deadline task that atomically retires idle expired Sessions from routing and inbound QoS 2 state without waiting for later client traffic; pre-registration CONNECT authorization with transport source, PROXY metadata and verified peer chains, pre-mutation PUBLISH/SUBSCRIBE/UNSUBSCRIBE access control, per-recipient delivery authorization before live/retained/offline queue mutation plus reconnect-time rechecks, unique assigned identifiers with an allow/deny policy for zero-length Client IDs, persistent subscriptions, offline QoS 1/2 queues and reconnect retransmission, Mosquitto-compatible `global_max_clients` across active and unexpired offline Sessions, global `max_queued_messages`/`max_queued_bytes`, plus opt-in offline QoS 0 queueing. Capacity refusal is pre-registration and returns MQTT 5 Server Busy; MQTT 3.1.1 closes because it has no equivalent code. Queue limits govern new admission and fail closed during snapshot restore if persisted state exceeds the configured bounds. SUBSCRIBE capacity is enforced per filter: MQTT 5 now returns `0x97` and MQTT 3.1.1 `0x80` only for over-limit new filters while same-packet authorized filters still succeed, existing filters still replace in place at capacity, and ACL-denied filters keep their distinct failure reason. | rumqttd graveyard/datalog and Mosquitto persisted sessions are integrated; Mosquitto exposes `allow_zero_length_clientid`, password files, certificate identity/subject usernames, distinct read/write/subscribe/unsubscribe ACLs, `max_queued_messages`, `max_queued_bytes`, and `queue_qos0_messages` |
| Will lifecycle | Indexed scheduler integrated into live Broker: abnormal close, DISCONNECT 0x04, Delay/Session Expiry, reconnect cancellation, retained Will, and publication-time write authorization | Both production brokers integrate Will publication; Mosquitto rechecks its write ACL when the Will becomes due |
| Keep Alive | Broker enforces the negotiated 1.5x inbound inactivity deadline with exact half-second precision, zero-disable semantics and Will/Session cleanup; optional maximum accepts MQTT 5 with Server Keep Alive replacement and refuses over-limit/zero MQTT 3.1.1 CONNECTs. The Mosquitto-style listener `max_keepalive` parser maps zero to no administrative maximum | Mosquitto uses a broker-wide deadline ring and disconnects clients that exceed Keep Alive x 1.5; `max_keepalive` has the same version-specific negotiation/refusal behavior |
| CONNECT and PING liveness | Raw TCP, MQTT-over-TLS, WS, and WSS clients expose address, hostname, and validated URI entry points as appropriate; secure address APIs accept an independent TLS identity. Client `network_connect_timeout` gives DNS resolution and every TCP address attempt one absolute budget across TCP, native TLS, WS and WSS; native TLS and WSS also apply their independent TLS handshake timeout on both vail and standard-library clients. Every transport exposes caller-owned absolute-deadline entry points spanning DNS/TCP setup, TLS and HTTP Upgrade where applicable, CONNECT, every enhanced-authentication round, and final CONNACK while retaining stricter configured phase limits. All four transports also expose matching relative-timeout wrappers that convert once at API entry. Partial MQTT bytes and unrelated protocol traffic cannot renew these deadlines. Clients also expose an absolute PINGREQ/PINGRESP round-trip timeout on all transports, preserving interleaved broker packets in a bounded ordered queue (plus one recoverable overflow packet already removed from the wire) | rumqttd exposes `connection_timeout_ms` around its initial packet read; rumqttc detects a PINGREQ that remains unacknowledged while continuing to dispatch other events; Mosquitto relies on its listener/event-loop timeout machinery |
| Client reconnect | An owning reconnect client deep-copies CONNECT credentials/properties/Will plus raw hostname or canonical `mqtt://`/`tcp://` targets. Native-TLS reconnect connectors cover fixed addresses, DNS hostnames, and `mqtts://`/`ssl://` URIs, re-resolving names and deriving SNI on each attempt; WS/WSS connectors retain the same URI behavior. These encrypted connectors remain borrowed because they can reference caller-managed certificates and callbacks. The client retries with bounded fixed, linear, or exponential delay, optional unbiased full/equal jitter, or stateful decorrelated jitter. A caller can delay the first attempt after an established transport closes and reset decorrelated history only after a configured stable-connection period; the absolute retry deadline survives shorter `connectWithDeadline` calls. All backoff waits remain interruptible through `std.Io.Event`. Its single-owner bounded poll API continuously reconnects, negotiates Server Keep Alive, sends PINGREQ while idle, rejects a missing PINGRESP within a configurable deadline, preserves partially received TCP packets across poll timeouts, and exposes ordered connect/publish/QoS/ping/DISCONNECT/AUTH events; `serveUntil` provides a cancellation-aware callback driver with automatic event cleanup. A bounded multi-producer `CommandQueue` feeds publish/subscribe/unsubscribe/disconnect/manual-ack/flush/re-auth operations to `serveQueuedUntil`, retains the loop as sole socket owner, provides owned asynchronous PUBLISH/SUBSCRIBE/UNSUBSCRIBE/DISCONNECT/manual acknowledgements with correlated typed callbacks or a bounded blocking/nonblocking `CompletionQueue`, and bounds command work between network reads. Its PUBLISH producer offers immediate full-queue rejection and timeout-bounded capacity waiting. Completion-queue SUBACK/UNSUBACK reason codes and properties are deep-owned beyond the network callback. Queued graceful disconnect supports MQTT 5 reason codes/properties, emits MQTT 3.1.1's minimal packet, completes only after the write, and then stops instead of reconnecting. Inbound QoS 1/2 acknowledgement is automatic by default or application-controlled with MQTT 5 reason codes/properties; accepted manual QoS 2 transactions are persisted before PUBREC, suppress duplicate delivery, and resume through PUBREL/PUBCOMP. An opt-in deferred inbound-QoS2 release policy surfaces PUBREL without deleting the Session marker or sending PUBCOMP; `completeIncomingQoS2` emits PUBCOMP only after the application establishes its own release boundary, retains the marker across write failure, and then completes it after a successful write. The Bridge combines this with its broker-owned durable store for end-to-end inbound QoS 2. An optional publish-delivery observer reports QoS 0 after the socket write, QoS 1 at PUBACK, and QoS 2 only at PUBCOMP or a negative PUBREC, including borrowed MQTT 5 diagnostics; Mosquitto exposes an equivalent terminal publish callback while rumqtt exposes lower-level incoming/outgoing events. It applies outbound acknowledgements and drives arbitrary multi-step client-initiated, server-challenged MQTT 5 re-authentication through the CONNECT authentication callback while preserving its returned properties. It retains outgoing QoS 1/2 across transport loss, replays PUBLISH with DUP and its original Packet Identifier when Session Present is true, resumes outgoing QoS 2 directly at PUBREL after PUBREC, clears stale QoS state when the broker reports no Session, and replays only broker-accepted subscriptions into that fresh Session. | rumqttc continuously reconnects while polled and owns its hostname in `MqttOptions`; libmosquitto exposes hostname-based sync/async reconnect plus fixed/progressive reconnect delay control |
| Broker bridges | `mqtt.bridge.Bridge` owns one reconnect client targeting a fixed address, re-resolved cleartext hostname, or caller-supplied connector such as native TLS; the production config adapter selects the vail TLS 1.3 data plane with CA and hostname verification plus optional mTLS, plus one or more non-overlapping remote subscription rules (QoS 0/1/2), maps each remote Topic Name by stripping its optional remote prefix before adding the rule-specific local prefix, and can publish retained local/remote connection state with a remote Last Will. Remote QoS 1 is manually acknowledged only after local routing completes. QoS 2 requires an explicit stable bridge identity, persistent upstream Session and enabled local commit log; it durably stages before PUBREC, atomically injects at PUBREL, and retains a released tombstone until PUBCOMP is written. `mqtt.bridge.OutboundBridge` composes a broker-local source Session with one remote reconnect Session and supports outbound, mixed-direction, and `both` rules without opening a second remote connection. MQTT 5 uses No Local on both bridge-facing subscription sides; MQTT 3.1.1 requires the private bridge extension without fallback. Outbound QoS 2 uses a separate identity-bound coordinator journal, while inbound QoS 2 uses the broker commit log and restores receive markers into the same remote reconnect client. Both directions strip connection-scoped Topic Alias and Subscription Identifier metadata and add no unbounded intermediate queue. | Rumqttd's `BridgeLink` is one-way in the audited tree; Mosquitto supports explicit in/out/both rules with local/remote prefix remapping on one bridge connection |
| MQTT 5 Enhanced Authentication | Initial multi-step AUTH before CONNACK, owned method binding, re-authentication traffic gate and broker policy callback; unnegotiated/mismatched live AUTH receives Protocol Error before close | Mosquitto plugin start/continue callbacks and active re-authentication; rumqtt codec/runtime coverage is narrower |
| MQTT 5 information preferences | Configurable Response Information is emitted only when CONNECT explicitly requests it; Request Problem Information defaults to enabled and an explicit zero removes Reason String/User Property from server ACK/AUTH packets while retaining functional authentication properties and the reason code | Both references parse/model the CONNECT fields, but the audited Mosquitto documentation labels them supported but unused and rumqttd does not apply them in its router |
| MQTT 5 Server Reference | CONNACK/DISCONNECT property access, redirect-reason validation, URI and host:port parsing, bounded loop-detecting opt-in redirect chains, authorization callback, and automatic TCP/TLS/WS/WSS CONNACK redirect helpers; TLS/WSS derive certificate identity from every new authority | The audited rumqtt codecs expose the property/reasons but no automatic client redirection; Mosquitto documents Server Reference as supported but unused |
| Broker persistence | Atomic versioned snapshots plus opt-in interval- or durable-change-count-driven live checkpoints, with both the replacement file and its parent directory synced on supported POSIX targets; and a separate opt-in fsynced append journal with the same directory-durable initialization/compaction, for retained messages, scheduled Wills, durable Sessions, opt-in queued QoS 0, outgoing QoS 1/2 and inbound QoS 2 transactions | rumqttd datalog/segments; Mosquitto persisted sessions, subscriptions, bidirectional client-message state and retained/Will base messages; Mosquitto can interpret its autosave threshold as elapsed seconds or persistence changes |
| Observability | `Broker.stats()` takes one allocation-free, state-locked snapshot of uptime, admitted CONNECT count, live connections, the process high-water connection count, cumulative expired Sessions, complete MQTT Control Packet/message and MQTT-byte counters, inbound/outbound/dropped PUBLISH counters and payload-byte counters, connected/offline Sessions, ordinary/shared subscriptions, retained state, live queues, durable queues/inflight, inbound QoS 2 and scheduled Wills, including owned byte gauges. State-backed gauges form one coherent instant; wire and PUBLISH counters are independently sampled lock-free atomics and include each complete operation, so callers that need an exact asynchronous boundary use a same-connection acknowledgement or PING barrier and observe the counter afterward. `publishSystemStats()` and `system_stats_interval` publish the snapshot as retained QoS 0 `$SYS` messages through normal routing and ACL checks; production config exposes Mosquitto-compatible global `sys_interval` with a 10-second default and zero-disable behavior. Metrics include `$SYS/broker/uptime`, cumulative message/byte/client/PUBLISH topics, and 1/5/15-minute EWMA connection, message, PUBLISH, drop, and byte rates. Wire counters span TCP/TLS/WS/WSS, count CONNECT before admission and successful CONNACK/control writes, and exclude lower-transport framing. PUBLISH counters saturate instead of wrapping. Drops count per destination rejected by a live or durable queue bound or negotiated Maximum Packet Size; ordinary no-match, ACL denial, and expiry are distinct outcomes. Like Mosquitto, `$SYS` updates actually written to subscribers contribute to the following sent-PUBLISH and total-message/byte snapshots | Mosquitto periodically publishes a broad counter/gauge and rolling-load set through `$SYS`; rumqttd exposes metrics through its server architecture |

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
No Local to the remote subscriptions as well. MQTT 3.1.1 has no wire-level No
Local bit, so a bidirectional configuration requires Mosquitto's private bridge
mode and treats a peer rejection as terminal instead of falling back to an
unsafe ordinary client connection.
Tests exercise both directions over one live remote Session, prove that the
inbound message is absent from the local outbound source, and recreate the
bridge between remote QoS 2 PUBREC and PUBREL to verify durable recovery and
exactly-once local admission.
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

Configured remote connections also expose Mosquitto's
`bridge_receive_maximum`, `bridge_max_topic_alias`,
`bridge_max_packet_size`, and `bridge_outgoing_retain`. Receive Maximum is
independent from the local outgoing inflight window and inherits the effective
global `max_inflight_messages` when omitted. The Topic Alias setting controls
both the CONNECT advertisement and the local ceiling applied to the remote
CONNACK value. The outgoing complete-packet limit treats zero as unlimited and
uses the smaller non-zero configured or negotiated value; an oversized
forwarded PUBLISH is retired for that destination without terminating the
bridge. Disabling outgoing RETAIN strips it from forwarded publications and
remote state notifications in both MQTT 3.1.1 and MQTT 5. The default-on
`bridge_attempt_unsubscribe` sends mapped remote filters after every outbound
connection and waits for a successful UNSUBACK before forwarding, except for
filters still used by the same bidirectional bridge. This prevents a persistent
Session from replaying subscriptions left by an older inbound configuration
without tearing down current inbound subscriptions. Legal PUBLISH traffic
interleaved before an UNSUBACK is retained in wire order, acknowledged, and
deliberately discarded; disabling the option omits the cleanup packet.

Mosquitto-compatible `try_private` defaults on for MQTT 3.1.1 bridges. Netz
emits the private protocol-level marker, immediately retries the same endpoint
with standard MQTT 3.1.1 after an Unsupported Protocol Version CONNACK, and
remembers that fallback for later reconnects. A netz broker accepting a private
bridge marks its legacy subscriptions no-local and retain-as-published, which
provides loop prevention and retained-flag fidelity unavailable in standard
MQTT 3.1.1 subscription options. MQTT 5 never emits this private extension.

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
published copy only if the source delivery still has time remaining.
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

The selected Mosquitto-derived process gate enables a five-second CONNECT
deadline on every one of its finite broker processes, so all 225 curated raw
scenarios
also exercise the bounded admission path rather than merely proving the option
in an isolated unit test.
The retained-source matrix persists and restarts the standalone broker after
storing a retained PUBLISH, source-locking the ACL-reload wire boundary in
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
routing. Scheduled-Will tests cover downtime deadline reduction, canonical
publisher restoration, reconnect cancellation, driver publication after an
actual broker restart and retained-Will storage. This snapshot surface still
has narrower persistence-plugin integration than Mosquitto, but supports both
elapsed-time and persistent-change-count live autosave. An
`autosave_interval` of zero disables either runtime trigger, matching
Mosquitto, without disabling startup restore or the final shutdown snapshot.
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

When `--commit-log=PATH` is enabled in the production example, the broker records
protocol-visible durable boundaries before CONNACK, SUBACK, UNSUBACK,
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

## Same-client live broker comparison

`examples/bench_mqtt_broker.zig` is one external MQTT 5 TCP client workload,
not a broker-specific adapter. It connects subscribers first, verifies every
SUBACK, then connects publishers. Each measured input is a QoS 1 PUBLISH and
each subscriber receives and PUBACKs one QoS 1 delivery. The timer starts only
after warmup deliveries have drained and ends when the last measured
subscriber delivery is acknowledged. The checksum catches missing or
mis-sized payloads.
The current driver obtains `std.Io` from zio and runs all subscriber readers in
an `std.Io.Group`; event barriers delimit connection readiness, drained warmup,
and the measured interval without polling an OS-thread counter. Its structured
result records always identify `client_io=zio-std-io` and accept only the
explicit `netz/zio-std-io`, `mosquitto/mosquitto-event-loop`, or standalone
external server identity pair. This is not an equal-wire claim: the gate does
not capture or equalize TCP segmentation, acknowledgements, kernel buffering,
or broker-specific control traffic.
The maintained comparison requires every expected fanout delivery, so its
runner gives both brokers the same queue capacity: at least the historical
1,024-message bound and large enough for the longer of the warmup and measured
phases. This prevents a valid bounded-queue drop from turning a long run into a
misleading Keep Alive timeout.
`MQTT_MAX_QUEUED_MESSAGES` may raise that common bound, but the runner rejects
an override smaller than either phase.
Structured timing, memory, and verification records bind that capacity as
`server_queue_capacity`, so results with different loss budgets cannot be
mistaken for an equal-configuration comparison.

The netz broker is a finite process for deterministic teardown:

```sh
zig build run-mqtt-broker -Doptimize=ReleaseFast -- \
  --bind=127.0.0.1:18883 --connections=8 \
  --max-queued-deliveries=1024 --max-outgoing-inflight=64 \
  --persistence=netz-mqtt.db --autosave-interval-seconds=30 \
  --autosave-change-count=100
```

The finite example restores that snapshot before accepting clients and saves
again after all configured connections exit. With the autosave interval above,
it also writes live checkpoints while clients remain connected;
`--no-restore` starts from an empty in-memory state but still writes periodic
and final snapshots. The change-count option currently writes after 100 broker
operations that change snapshot-backed state. A compound publish/fanout or
lifecycle operation counts once, and periodic `$SYS` refreshes are excluded so
telemetry cannot force checkpoint churn. Both positive thresholds may be
enabled together; either trigger writes the same atomic destination, and the
broker serializes concurrent snapshot writers. Both require `--persistence`
and are rejected with `--commit-log`, which already journals each
protocol-visible durable boundary. Change-triggered checkpoint failures remain
pending for retry and are exposed by `Broker.persistentChangeAutosaveError`
rather than retroactively failing an MQTT operation whose in-memory mutation
has already committed. `zig build interop-mqtt-live-autosave
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

The repository now also packages the complete local Mosquitto comparison as a
single build step. It builds the audited checkout with non-broker components
disabled, allocates independent loopback ports, waits for each broker's ready
marker, runs the same already-built netz client against both processes, checks
the complete result shape, derived rates, latency ordering, backend identities,
and independently calculated checksum, then tears down every child:

```sh
zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast
MQTT_STATS=true zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast
zig build compare-mqtt-mosquitto-matrix -Doptimize=ReleaseFast
MQTT_QOS=2 zig build compare-mqtt-mosquitto-matrix -Doptimize=ReleaseFast
```

`MOSQUITTO_BIN` may select an existing executable, while `MOSQUITTO_ROOT`
overrides the default `~/Work/mosquitto` checkout used for an isolated build.
Source builds require the audited `5cd25465` revision unless
`MOSQUITTO_COMMIT` explicitly selects another revision;
`PUBLISHERS`, `SUBSCRIBERS`, `WARMUP_MESSAGES`, `MESSAGES`, `PAYLOAD_BYTES`,
and `PUBLISHER_WINDOW` select a bounded smoke or longer measurement;
`MQTT_QOS=1|2` selects the complete acknowledgement flow. Building
Mosquitto requires its normal development dependencies, including cJSON
headers; the gate reports that requirement rather than silently using an
unrelated system broker. `MQTT_STATS=true` additionally samples each broker's
resident memory from Linux `/proc/PID/status` every 2 ms and emits validated
machine-readable memory records without changing the client workload.

The matrix command is deliberately stricter than the configurable one-shape
runner. It fixes five complementary shapes, requires three available CPUs, and
pins the common netz driver, active broker, and RSS sampler separately. Each
shape runs four paired samples in `netz, Mosquitto, Mosquitto, netz` ABBA
order. The matrix refuses an injected `MOSQUITTO_BIN`, requires the audited
checkout to be clean, and builds revision
`5cd2546511596a269dbf53f85858c623b09ebdd6` for that run. Artifacts under
`zig-out/mqtt-broker-matrix/run.*` retain the actual binaries, source-state and
build logs, runners/checkers/config helper, per-run broker/result/RSS logs, and
CPU/order metadata. SHA-256 binds every executable and tool. The checker
requires the exact directory structure, recomputes all hashes, reruns the
single-shape workload/checksum/rate validation for every pair, verifies the
ABBA schedule, and caps each artifact at 32 MiB and the matrix at 128 MiB.
Both brokers use `TCP_NODELAY`; Mosquitto's per-packet verbose logging is
disabled so logging and delayed ACKs cannot manufacture a comparison result.

The pre-QoS-1-writer aarch64 Linux capture used CPUs 0/1/2 for
client/server/sampler, Zig 0.16.0, four ABBA samples per shape, one exact
subscription per subscriber, MQTT 5 QoS 1, and 2-ms broker RSS sampling. All
40 broker runs completed their expected deliveries and independently
recomputed checksums. Its complete artifact is
`zig-out/mqtt-broker-qos2-writer-qos1-final3` (23,221,848 bytes);
the stored summary SHA-256 is
`5f32c63cbd4c0167a4f99c1b1d7f44794d9da516a5a79ee36c053996bc762574`.
Rates and p99 are medians; brackets show every sample.

| shape (publishers × subscribers, payload, window) | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial (1×1, 256 B, 1) | 29,708 [29,294–29,828] | 41,822 [39,404–43,340] | 0.710× | 0.032 / 0.030 | 3.51 / 2.96 |
| publishers-32 (32×1, 64 B, 4) | 50,590 [49,486–51,128] | 67,296 [64,537–69,070] | 0.752× | 0.851 / 1.243 | 5.05 / 4.21 |
| fanout-32 (1×32, 64 B, 4) | 2,843 [2,836–2,849] | 4,474 [4,473–4,503] | 0.635× | 1.357 / 0.571 | 4.52 / 3.13 |
| balanced-32x32 (32×32, 64 B, 4) | 4,187 [4,002–4,238] | 4,549 [4,454–4,742] | 0.920× | 23.002 / 17.443 | 8.68 / 11.31 |
| large-payload (4×4, 4096 B, 16) | 19,621 [19,525–19,652] | 23,874 [23,426–25,035] | 0.822× | 2.371 / 3.824 | 3.69 / 4.11 |

That matrix exposes rather than hides the then-current deficit. Netz reaches
0.635–0.920× Mosquitto's median throughput across all five shapes. Its p99 is
lower in the publisher-heavy and 4-KiB shapes and higher in the other three.
Median broker RSS is higher in three shapes and lower in balanced 32×32 and
4-KiB. The balanced RSS range is wide because the faster common client can
build different transient broker backlogs, so the isolated fixed-driver A/B
below remains the evidence for the connection-layout change.
Client allocation counts are identical because both arms run the same fixed
netz client binary; they bind harness cost and catch shape drift rather than
measuring broker-internal allocations. An earlier diagnostic run had left
Mosquitto's per-packet verbose logging enabled and misleadingly favored netz
in high-fanout/windowed shapes; those values are intentionally discarded. The
accepted matrix explicitly aligns `TCP_NODELAY=true` on both brokers and omits
verbose packet logging. These results identify broker scheduling, serial
latency, and per-connection memory as the next optimization targets.

The same driver and strict artifact pipeline now cover QoS 2. Subscriber tasks
consume interleaved PUBLISH and PUBREL events through one socket reader, track
the bounded set of pending Packet Identifiers, and send PUBREC/PUBCOMP without
assuming adjacent control packets. Publisher completion similarly demultiplexes
interleaved PUBREC/PUBCOMP packets per connection and applies each transition
through the production runtime state machine. This preserves the configured
publisher window instead of serializing QoS 2 to an easier window-one shape.
The current CPU-0/1/2 capture at
`zig-out/mqtt-broker-qos2-writer-final3` (23,221,979 bytes; summary SHA-256
`1df7a0be6e51b819ccde56b9c5d0d99e972a54f95b43cb555dde16149c18a465`)
completed all 40 ABBA runs with exact delivery counts and independently
recomputed checksums. Rates and p99 are medians:

| QoS 2 shape | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 14,979 [14,893–15,080] | 18,098 [15,041–21,828] | 0.828× | 0.074 / 0.066 | 4.59 / 2.96 |
| publishers-32 | 27,382 [24,877–27,780] | 31,874 [31,371–32,317] | 0.859× | 3.891 / 3.477 | 5.67 / 3.30 |
| fanout-32 | 2,144 [2,060–2,206] | 2,251 [2,222–2,274] | 0.952× | 1.655 / 1.467 | 5.87 / 3.13 |
| balanced-32x32 | 2,234 [2,224–2,248] | 2,575 [2,544–2,596] | 0.868× | 54.674 / 44.353 | 6.55 / 3.59 |
| large-payload | 14,411 [14,042–14,623] | 14,868 [14,738–15,124] | 0.969× | 3.939 / 4.598 | 5.55 / 3.41 |

This matrix still exposes a throughput and RSS deficit rather than making a
broad superiority claim, but the fanout and large-payload medians are now
within 5% and 4% of Mosquitto respectively. The same fixed binaries, source
lock, completion checks, CPU assignment, queue bounds, and retained artifacts
continue to make that gap directly measurable.

The runner and both strict checkers now accept
`MQTT_SESSION_EXPIRY_SECONDS=0..4294967295` and bind its canonical value into
the driver result, run-order, environment, shape, allocator, and completion
records. A nonzero value keeps each MQTT 5 publisher and subscriber Session
durable while the connection remains online; this matrix measures the cost of
durable Session ownership during live traffic, not disconnected queue replay.
The 3,600-second QoS 2 capture at
`zig-out/mqtt-broker-durable-qos2-matrix-final` (23,132,475 bytes; summary
SHA-256 `efc6de9d35fd92e85813a9883e547c8a9abdf89a0387abe2d256f2c28ea7d861`;
aggregate file-hash digest
`db57b9318f1a424ad29044fe0707bec3d782a9e68aed6fab7704837740fd2f66`)
completed all 40 ABBA broker runs with exact delivery counts and checksums.
Rates and p99 are medians:

| durable QoS 2 shape | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 12,650 [12,312–12,724] | 20,311 [18,719–21,220] | 0.623× | 0.081 / 0.057 | 4.56 / 2.96 |
| publishers-32 | 23,403 [23,301–23,456] | 32,431 [32,298–32,726] | 0.722× | 5.120 / 3.440 | 5.49 / 3.28 |
| fanout-32 | 1,521 [1,517–1,532] | 2,265 [2,249–2,279] | 0.672× | 2.625 / 1.466 | 5.63 / 3.13 |
| balanced-32x32 | 1,515 [1,462–1,528] | 2,548 [2,512–2,580] | 0.595× | 83.261 / 44.896 | 6.42 / 3.60 |
| large-payload | 10,656 [10,490–10,668] | 14,341 [14,249–15,076] | 0.743× | 5.667 / 4.963 | 5.52 / 3.42 |

As with the transient QoS 2 capture, this durable result exposes a throughput,
tail-latency, and RSS deficit in all five shapes. Separate QoS 1 and QoS 2
two-publisher/two-subscriber smoke runs also completed 400 deliveries per
broker with checksum 23,320, covering both acknowledgement flows before the
full durable QoS 2 capture.

Broker-owned allocations now have a separate diagnostic matrix rather than
being inferred from the common client's counters. Run it with:

```sh
zig build bench-mqtt-broker-allocator-matrix -Doptimize=ReleaseFast
MQTT_QOS=2 zig build bench-mqtt-broker-allocator-matrix -Doptimize=ReleaseFast
```

The broker's explicit allocator is wrapped only when its opt-in
`--allocator-stats` flag is present. The ordinary production and performance
matrix paths continue to use `c_allocator`; every allocator record is marked
`timing_usable=false` because thread-safe counting changes the hot path. The
five-shape runner pins client and server separately, gives both processes a
60-second bound, retains the exact broker, driver, runner and checker, binds each with
SHA-256, and repeats every shape four times. Both endpoints use
`TCP_NODELAY=true`. Its checker validates the workload result, exact artifact
tree,
identity hashes, allocation-size bucket sum, allocated/freed-byte equality and
zero live bytes after complete broker teardown, then independently regenerates
the summary.

The QoS 2 allocator capture at
`zig-out/mqtt-broker-qos2-allocator-final` (22,360,709 bytes; summary SHA-256
`358aee6e4b00098c566e5119f96e4bed9e72cb9d664aa733a3c153c64334a541`)
completed all fifteen runs with zero live bytes. It records the additional
four-stage transaction ownership directly: balanced-32x32 used 11,197 broker
allocations (0.109 per delivery), while serial and large-payload used 2,606
and a median of 8,837 respectively. These are allocation diagnostics only; the
thread-safe counting allocator marks timing as unusable.

Inbound QoS 2 `Pending` transactions now place the Topic Name, payload, source
Client ID, and optional username in one allocation while retaining separate
deep ownership for nested MQTT properties. Completed or disconnected
transactions return that allocation to an intrusive power-of-two size-class
cache owned by the Store. The cache has no per-block metadata allocation and is
hard-bounded by both the configured pending-transaction limit and 1 MiB;
blocks above 64 KiB are freed immediately. The slices preserve their existing
API and snapshot representation. Tests prove the one-allocation layout,
bounded reuse, and exhaustive failure cleanup with nested User Properties.

The corrected three-sample matrix at `zig-out/mqtt-qos2-cache-final`
(22,363,733 bytes; summary SHA-256
`0c3d9a510fb882059fcf8fa132bb1f7645f61936145a2e7d8e6c28079f24b11a`)
completed all fifteen runs with zero live bytes. Relative to the pre-change
QoS 2 baseline, allocation counts fell 48.5-64.2% across all five shapes:
serial 2,606 to 1,327, publishers-32 13,356 to 4,780, fanout-32 7,491 to
2,887, balanced-32x32 11,197 to 4,413, and large-payload 8,837 to a 4,550
median. Balanced allocation density fell from 0.109 to 0.043 per delivery;
cumulative requested bytes fell 2.8%, while the 1-MiB cache bound makes the
retention tradeoff explicit.

The matching 3,600-second durable-Session allocator capture at
`zig-out/mqtt-broker-durable-qos2-allocator-final` (22,370,470 bytes; summary
SHA-256 `8621642a739ba033a6c0fde6ed6acb549fe1769d6a03ffa6b7b28c77defaa2ad`;
aggregate file-hash digest
`f7da261081d729ebc3546ce130ce2e2e354aafcbd8c84bb8b4d8a41bf864d571`)
completed all fifteen runs with `live_bytes=0`. Median allocation counts were
2,609 serial (5.096/publish), 13,487 publishers-32 (3.293/publish), 221,831
fanout-32 (3.385/delivery), 332,797 balanced-32x32 (3.250/delivery), and
28,495 large-payload (3.478/delivery). These figures include durable Session
ownership, startup, warmup, measured traffic, and complete teardown; timing is
intentionally unusable under the counting allocator.

Durable Session delivery now materializes its detached canonical transmission
into connection-slot scratch rather than allocating and freeing temporary
storage for every message. The writer mutex gives that storage one owner,
while detachment still completes under the broker state lock, persistence
still completes before socket I/O, and no Session-owned slice escapes the
unlock boundary. Disconnect releases the scratch, and any byte or property
storage above 64 KiB is released immediately after its write so a single
exceptional message cannot leave large storage pinned to every live slot. A
fail-first unit test proves a warmed ordinary PUBLISH detaches without another
allocation, and a separate boundary test proves both small-buffer retention
and oversized release.

The final three-sample durable allocator matrix at
`zig-out/mqtt-session-write-scratch-allocator-final` (22,368,160 bytes;
summary SHA-256
`ccdd62a64941d0ccead1865d88dfa3866d1f8a17cd950dc0fbfee1755792da35`;
aggregate file-hash digest
`84f771ce7fc799dd40e4a35c19fb5662a9d4e41dc6cefb35b21362dd2c557c5d`)
completed all fifteen runs with `live_bytes=0`. Against the immediately
preceding durable capture, median allocation counts fell 49.0%, 64.5%, 66.5%,
66.5%, and 61.1% in shape order. Serial moved from 2,609 to 1,330 allocations
(5.096 to 2.598/publish), publishers-32 from 13,487 to 4,783 (3.293 to
1.168/publish), fanout-32 from 221,831 to 74,407 (3.385 to 1.135/delivery),
balanced-32x32 from 332,797 to 111,645 (3.250 to 1.090/delivery), and
large-payload from 28,495 to 11,089 (3.478 to 1.354/delivery).

A five-pair alternating-order, fixed-binary durable balanced-32x32 A/B at
`zig-out/mqtt-session-write-scratch-ab` (36,716,215 bytes; aggregate file-hash
digest `2da53d9d1aa6181282d33a476227a6b2cc783ba7425ae8bd9812f316aebafc56`)
used baseline broker `99bacf17`, candidate `679d0e41`, and fixed driver
`d92ecf95`, with 1,000 warmups and 10,000 measured QoS 2 publishes per arm.
Every arm completed 320,000 deliveries with checksum 18,656,000. Paired
medians were +0.3% throughput, -0.5% p50, and -0.2% p99; all ranges overlap,
so timing is neutral and the exact allocator reduction is the supported result.

Completed outgoing Session messages now return their coallocated Topic Name
and payload block to a Store-owned power-of-two cache. The cache implementation
is shared with inbound QoS 2 storage rather than duplicating allocator policy,
while each Store keeps independent ownership. Session reuse retains no more
blocks than the configured Session limit and no more than 1 MiB total; blocks
above 64 KiB are freed immediately. The byte limits and `owned_wire_bytes`
gauges continue to charge exact live Topic Name, payload, and property bytes
rather than size-class rounding or idle cache capacity. Tests cover block-count
and byte ceilings, oversized release, exact Session accounting, pointer reuse,
allocation-free steady-state enqueue/drain/ACK, and cache teardown.

The final three-sample matrix at
`zig-out/mqtt-session-wire-cache-allocator-final2` (22,376,564 bytes; summary
SHA-256 `a5a7a9b4c1834d20b85db9b83386d06d26e1ae14ec3b90c58ad380345d3e9de6`;
aggregate file-hash digest
`48ebad386bccce09f14a4297f5272414d7b3bf3f9933298564a8a260f0120c8a`)
completed all fifteen runs with `live_bytes=0`. Relative to the preceding
Session-write-scratch capture, allocation counts fell another 48.0%, 90.9%,
99.0%, 99.0%, and 78.2% in shape order: serial used 692 allocations
(1.352/publish), publishers-32 437 (0.107/publish), fanout-32 756
(0.012/delivery), balanced-32x32 1,106 (0.011/delivery), and large-payload
2,414 (0.295/delivery). Median peak live bytes varied from -0.1% to +2.0%; the
largest increase was 143,250 bytes in the 4-KiB shape and remains below the
explicit 1-MiB cache ceiling.

A two-shape, five-pair alternating-order fixed-binary A/B at
`zig-out/mqtt-session-wire-cache-ab-final` (36,737,527 bytes; aggregate
file-hash digest
`1218260adc6b7c82164ee0242c171141ec1dd7330e5aa4c526e96d9f6bbd77fb`)
used baseline broker `679d0e41`, candidate `a5b0dc64`, and fixed driver
`d92ecf95`, with a 3,600-second Session Expiry, 1,000 warmups, and 10,000
measured QoS 2 publishes per arm. Every balanced arm completed 320,000
deliveries with checksum 18,656,000; every 4-KiB arm completed 40,000 with
checksum 10,780,000. Paired throughput/p50/p99 medians were
-1.1%/+1.3%/+0.5% for balanced-32x32 and -0.6%/+0.0%/+0.7% for large-payload.
The ranges overlap and timing is neutral; the repeatable allocator reduction
is the supported result.

The broker's detached transmission now preserves typed metadata plus deep
copies of its visible Topic Name, payload, and every variable-length MQTT 5
property value. After the persistence barrier, the connection applies its
current Topic Alias state and performs the only wire encoding. This removes
the former state-lock encode followed by an unlocked parse and second encode;
it does not borrow Session memory outside the lock, move persistence or socket
I/O into the lock, or change the alias oversize fallback. Tests cover QoS
capping, QoS 0 completion metadata, deep-copy independence for User Properties,
allocation-free scratch reuse, and the existing real durable reconnect that
establishes then reuses a Topic Alias.

The three-sample allocator regression artifact at
`zig-out/mqtt-session-detach-allocator-final` (22,382,296 bytes; summary
SHA-256 `cc9e9ab6808582b5cbf49f01d409ae53c48f7c318a4efb429810e9adca603971`;
aggregate file-hash digest
`6a60453eb78711d6bd19c715d73f2c6e3673477490a578999d0dcaa332c13128`)
completed all fifteen runs with `live_bytes=0` and reproduced the cache-era
allocation density: fanout-32 and balanced-32x32 both remained at 0.011
allocations per delivery.

A two-shape, five-pair alternating-order fixed-binary A/B at
`zig-out/mqtt-session-detach-ab` (36,751,745 bytes; aggregate file-hash digest
`e6887b8977a282f9551f5d9e7e866987ff84847780045e6db53f71d8a0a8a58b`)
used baseline broker `a5b0dc64`, candidate `f3513c44`, and fixed driver
`6e528bd1`, again with a 3,600-second Session Expiry, 1,000 warmups, and 10,000
measured QoS 2 publishes per arm. Every balanced arm completed 320,000
deliveries with checksum 18,656,000, and every 4-KiB arm completed 40,000 with
checksum 10,780,000. The candidate won throughput in all ten pairs. Paired
throughput/p50/p99 medians improved 6.1%/5.7%/5.7% for balanced-32x32 and
4.1%/1.2%/4.1% for large-payload.

A fresh full comparison after the Session wire-cache and detached-transmission
changes is retained at
`zig-out/mqtt-broker-durable-qos2-matrix-post-optimization` (23,144,586
bytes; summary SHA-256
`80fcf8c52a8eae177aa21cebe90b237ebfcaa979ab8f8610444088361f1fdc45`;
aggregate file-hash digest
`a7ffb1515db834ae6047964b25f520141eeb6d5454be14746bfe2b45da55303c`).
All 40 broker runs completed with the required delivery count and checksum.
Rates and p99 are medians:

| current durable QoS 2 shape | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 13,021 [12,687–13,100] | 22,025 [20,538–22,639] | 0.591× | 0.081 / 0.055 | 4.59 / 2.96 |
| publishers-32 | 21,631 [21,337–22,817] | 31,259 [30,767–31,484] | 0.692× | 5.587 / 3.501 | 5.50 / 3.37 |
| fanout-32 | 1,502 [1,446–1,548] | 2,270 [2,258–2,292] | 0.662× | 2.785 / 1.465 | 5.64 / 3.14 |
| balanced-32x32 | 1,547 [1,404–1,569] | 2,578 [2,559–2,610] | 0.600× | 81.520 / 44.495 | 6.46 / 3.54 |
| large-payload | 10,410 [10,236–11,107] | 14,415 [14,395–14,720] | 0.722× | 5.757 / 4.796 | 5.63 / 3.40 |

Absolute movement from the earlier full matrix is not treated as causal
because both brokers shifted with host load; the fixed-binary comparisons above
remain the optimization evidence. The new matrix still exposes a cross-shape
broker deficit. A separate `strace -f -c` diagnostic at
`zig-out/mqtt-durable-current-strace` (4,370 bytes; aggregate file-hash digest
`dbb090fb73303f8253cd463b5ab079c5ed99bb26efb18f198ec7120d77becfca`)
observed 327,160 `io_uring_enter` calls while completing 320,000 balanced
deliveries. Instrumented timing is not used as a benchmark result; the syscall
count identifies cross-connection write scheduling as the next architectural
target.

The durable cross-connection target is now addressed by two serving-scope
Session delivery workers rather than one coroutine per connected Session. A
fixed ring has one entry and one compact state per broker slot, coalesces a
queued duplicate, and records at most one rerun while a slot is being drained.
The existing per-slot writer mutex still serializes every control and delivery
write; same-connection delivery and destinations at the 16-message high
watermark stay on the ordered publisher path. Worker errors are returned to
the owning client task before slot reuse, and serving teardown broadcasts to
and joins both workers. This bounds long-lived writer stacks independently of
the connection limit. The rejected per-Session prototype reached similar
throughput but raised balanced broker RSS from about 7.0 MiB to 14.9 MiB; its
64-KiB zio initial-stack override was also removed because zio deliberately
keeps 256 KiB available for panic/error paths while retaining an 8-MiB virtual
growth ceiling.

The initial shared-pool five-pair fixed-binary, CPU-0/client and CPU-1/server
A/B is retained
at `zig-out/mqtt-durable-shared2-ab-final` (63,667,135 bytes; aggregate
file-hash digest
`2146ea99f81fb0bc0377de777671c34c7ed39f2b5c8e7d59dd8afb17511570df`).
It used 1,000 warmups, 10,000 measured QoS 2 publishes, 3,600-second Sessions,
and an independently sampled CPU-2 RSS peak. Every balanced arm completed
320,000 deliveries with checksum 18,656,000; every 4-KiB arm completed 40,000
with checksum 10,780,000. Paired candidate/baseline medians were:

| durable shape | publish/s baseline / candidate | paired throughput | p50 candidate / baseline | p99 candidate / baseline | RSS KiB baseline / candidate |
| --- | ---: | ---: | ---: | ---: | ---: |
| balanced-32x32 | 1,813 / 2,713 | 1.489x [1.433-1.632] | 0.640x | 0.639x | 6,976 / 8,148 |
| large-payload | 12,652 / 15,273 | 1.213x [1.207-1.223] | 0.798x | 0.823x | 5,632 / 5,652 |

All ten throughput pairs won. The fixed baseline/candidate/driver SHA-256
values are
`fbd216b8cf4f0240ced742f85d805372c795102c90578bec20c8e2c53bf3ff94`,
`30b6a86286dbdc8ff82c97701812e0ac029557ac6f62a218e416f36ecfe84b69`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
A same-shape `strace -f -c` diagnostic at
`zig-out/mqtt-durable-shared2-strace-final` (36,304,303 bytes; aggregate
file-hash digest
`247adcc68230d909505dc38d6da4198a38373da61b1550c900cddbb4d5eb994b`)
reduced `io_uring_enter` from 114,102 to 63,454 for 102,400 measured
deliveries (-44.4%). Its timing remains diagnostic-only; the paired run above
is the performance evidence.

The final pool is lazy: entering a serving scope only publishes its fixed
queue and callback context. It allocates no stack and starts no writer until a
multi-target online durable route first selects asynchronous delivery. A
single destination, QoS 0 traffic, and brokers serving only transient Sessions
therefore retain the original task count. The lifecycle regression separately
proves an unused scope stops without spawning and two started idle waiters are
broadcast and joined.

The matching three-shape, five-pair final-binary run is retained at
`zig-out/mqtt-durable-lazy-shared2-ab-final` (63,688,110 bytes; aggregate
file-hash digest
`21cd20890dda288025a91dcc98366c6ac7126c4b20acd994115c9b58dc86a248`).
Its serial shape proves the negative case: median throughput was 19,040 versus
18,878 publish/s (paired ratio 0.997x), p50 was 43.258 versus 43.481 us, and
RSS was 4,860 versus 4,824 KiB, so an unused pool has no measurable resident
stack cost. Balanced-32x32 retained a 1.489x paired throughput median, 0.638x
p50 and 0.640x p99; RSS was 6,928 versus 8,716 KiB. The 4-KiB shape retained
a 1.213x throughput median, 0.819x p50 and 0.818x p99, with RSS at 5,636 versus
5,664 KiB. Every one of the fifteen baseline/candidate pairs completed its
exact delivery count and checksum. The final candidate SHA-256 is
`333148f1b4437441eb3db0727ca4f98ad7733c67808d17bcc90d2ddfaa6d52b4`.
Three matching 102,400-delivery diagnostics at
`zig-out/mqtt-durable-lazy-shared2-strace-final` recorded 63,733-81,254
`io_uring_enter` calls (73,296 median), 35.8% below the 114,102-call baseline.
The artifact is 36,352,861 bytes with aggregate digest
`1def46da118b0fa29aad00efdeff9842a4ace1fabccd46e980cf0463df5616fa`.

The serial QoS 2 profile then exposed validation rather than allocation as the
largest avoidable CPU cost. Netz now validates a network Topic Name's MQTT
UTF-8 profile once while reading its length-prefixed wire string, then checks
only the Topic Name-specific wildcard rule. Topic Alias application no longer
repeats the validation already completed transactionally before inflight state
is committed. Broker routing uses explicitly named validated Router and
Session paths after network parsing, local-publish, Will, or snapshot ingress;
the public Router, retained-store, Session-store, and QoS2-store APIs retain
their defensive validation. Non-retained publications also skip the retained
store entirely, and the broker's QoS 2 pending path reuses the CONNECT-validated
Client ID and username instead of decoding them for every message. This matches
the audited Mosquitto `5cd25465` structure: `packet__read_string` validates
UTF-8 at packet ingress and `handle_publish.c` performs the remaining Topic
Name check before database/routing work.

A seven-pair fixed-binary serial A/B is retained at
`zig-out/mqtt-validated-ingress-ab-final2` (63,726,852 bytes; aggregate digest
`e968026569990076d0120e697f7df2cf3f11be7d34aa0eacada6acca8455858c`).
With one publisher, one subscriber, 1,000 warmups, 10,000 measured 256-byte
QoS 2 publishes and 3,600-second Sessions, candidate/baseline paired medians
were 1.033x throughput and 0.969x p50. The candidate won throughput in six of
seven pairs; p99 was noisy and inconclusive, while RSS stayed neutral at
0.996x.
Every arm completed 10,000 deliveries with checksum 2,695,000. The fixed
baseline/candidate hashes are
`333148f1b4437441eb3db0727ca4f98ad7733c67808d17bcc90d2ddfaa6d52b4`
and `beb97b847532fe3bd004b8c35cdc210d9c1a2b10caaef0414929c31dc5a5a0cc`.
Matched 100,000-message `perf` captures reduced the combined sampled share of
the MQTT UTF-8 validator and decoder from 19.3% to 7.4%, with zero lost
samples. The final p99 and remaining serial gap are therefore attributed to
clock/I/O scheduling rather than hidden validation work.

The follow-up fixed-binary syscall capture at
`zig-out/mqtt-serial-syscalls` confirmed that syscall volume was not the
serial deficit. Across 1,000 warmups plus 10,000 measured durable QoS 2
publishes, the netz broker made 78,453 syscalls (78,357
`io_uring_enter`) while Mosquitto made 198,989: 44,003 `sendto`, 44,013
`read`, 88,012 `epoll_ctl`, and 22,813 `epoll_pwait`. The traced timings are
diagnostic only. A zio prototype that completed writable socket sends inline
was rejected after fixed-binary cross-protocol pairs regressed HTTP/1,
WebSocket, MQTT-over-WebSocket, MQTT-over-TLS, and HTTP/2 throughput to
0.866x, 0.954x, 0.928x, 0.893x, and 0.871x. Its evidence remains at
`zig-out/zio-direct-send-cross` (113,709,948 bytes; aggregate digest
`eed8e3556d1438b3d9a6e8330da80c01d6f7765fb494ac6243d5ec58d13b4d69`).

The retained change instead exposes zio's already refreshed per-loop awake
timestamp through `cachedAwakeNow`, with exact-clock fallback outside the
matching runtime, while leaving `std.Io.Clock.now` untouched. MQTT uses that
snapshot only for same-event-loop-turn keep-alive, inbound QoS 2, routing,
Message Expiry, and Session-drain bookkeeping. A matching
5,000-warmup/100,000-message CPU profile at
`zig-out/mqtt-cached-awake-profile-final` (37,234,702 bytes; aggregate digest
`7a8788136caf27fc13314a613ffd01b392e8131dca2fdcc7e87aec67daaf140e`)
reduced `__kernel_clock_gettime` from 24.5% of samples, including 13.2% below
protocol `std.Io` calls, to 12.7% entirely below the event-loop refresh; both
profiles lost zero samples.

The final remote-zio fixed-binary five-pair matrix is retained at
`zig-out/mqtt-cached-awake-final-ab` (63,798,176 bytes; aggregate digest
`9f6c0000a2a9b70fa8eae9d332251da30a78647f1a987bccbd99ae8cf5f430ee`).
It used CPUs 0/1/2, 1,000 warmups, 10,000 measured durable QoS 2 publishes,
and exact delivery/checksum validation. Baseline/candidate/driver SHA-256
values are
`beb97b847532fe3bd004b8c35cdc210d9c1a2b10caaef0414929c31dc5a5a0cc`,
`b5008a3cbddc9200a414e084b44860a19baf5e1cb718d2fc3ad9348e2e4bec28`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Paired throughput/p50/p99 medians were 1.018x/0.989x/0.946x for serial,
1.021x/0.959x/1.136x for publishers-32, 1.078x/0.899x/0.843x for fanout-32,
1.038x/0.946x/0.950x for balanced-32x32, and 1.025x/0.986x/0.947x for the
4-KiB shape. Publisher-heavy p99 was noisy and inconclusive; throughput won
four or five pairs in every shape and all five fanout pairs. A separate
100,000-message serial control at `zig-out/mqtt-cached-awake-ab-long` was
throughput-neutral at 1.003x, so the result does not claim a durable serial
throughput improvement. Seven-pair transport controls at
`zig-out/mqtt-cached-awake-transports-ab` were also neutral: 1.009x for
MQTT-over-WebSocket and 1.003x for MQTT-over-TLS.

The remaining UTF-8 profile was not a license to weaken MQTT validation.
`validateMqttUtf8StringWithPolicy` now validates the common all-ASCII case in
one pass and returns without constructing a UTF-8 view or decoding each byte
as a code point. It still rejects NUL, applies the stricter C0/DEL policy when
requested, and hands the suffix beginning at the first non-ASCII byte to the
complete UTF-8/noncharacter validator. Tests cover all-ASCII acceptance,
embedded NUL after a multibyte character, strict ASCII controls, mixed UTF-8,
surrogates, overlong encodings, and every Unicode noncharacter boundary.

The final five-pair fixed-binary matrix at
`zig-out/mqtt-ascii-validation-final2` (63,807,571 bytes; aggregate digest
`24df711c34b2923e11251e9c0e9afd627dfff95345ac213c2c7d4ab39ffa4bf1`)
pinned client/server/RSS sampling to CPUs 5/7/13 and used the cached-time
build as its baseline. Baseline/candidate/driver hashes were
`b5008a3cbddc9200a414e084b44860a19baf5e1cb718d2fc3ad9348e2e4bec28`,
`9a0ae6df6a55ebc8f671c657860c7f36e9c6dfcc2c0a59dff94e24b70d601f57`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Paired throughput/p50 medians were 1.012x/0.993x for serial,
1.003x/0.967x for publishers-32, 1.005x/1.002x for fanout-32,
1.011x/0.979x for balanced-32x32, and 1.013x/1.013x for the 4-KiB shape.
All throughput medians were positive but small; each of the first four shapes
won three of five pairs and the 4-KiB shape won all five, so this is supporting
CPU/path-length evidence rather than a broad throughput claim. RSS was neutral.
In the matching
5,000-warmup/100,000-message profile at
`zig-out/mqtt-ascii-validation-profile-final2` (37,242,840 bytes; aggregate
digest
`bb24319466455d41c78edde198cec09f228fc277e794f78036014b6ad4879d1f`),
the former 4.95% validator and 3.70% UTF-8 decoder entries disappeared from
the top sampled symbols with zero lost samples.

Two bounded parallel-flush prototypes were removed rather than committed.
Lazy group scheduling was neutral for balanced and regressed fanout; forced
concurrency improved balanced throughput about 4% but regressed fanout
throughput and p50. Smaller default-path experiments that skipped unused
delivery-ACL or repeated Session validation work were likewise inconsistent
across fanout and balanced. The then-adopted transient design instead starts
one persistent writer only after a transient client processes its first QoS 1
or QoS 2 subscription.
The publisher retains routing, persistence, and PUBREC/PUBCOMP ordering;
self-delivery remains synchronous so its PUBLISH precedes PUBACK/PUBCOMP on the
shared connection. It signals other destination writers rather than waiting on
unrelated subscriber sockets. Every connection still has one serialized writer;
PINGRESP first drains older delivery work, writer failure shuts down and wakes
the owning reader, and teardown joins the writer before the slot can be reused.
At that stage durable Sessions remained on the original synchronous path
because their detach operations serialize on shared Session/persistence state;
the fixed shared pool above now supplies bounded cross-connection concurrency.
A 16-delivery internal high watermark returns a lagging destination to
synchronous backpressure before the configured hard queue/drop limit. QoS 0
retains the original synchronous route and creates no per-connection writer.

Seven CPU-0/1 fixed-binary, order-alternated transient QoS 2 balanced-32x32
pairs used 1,000 warmups and 10,000 measured 64-byte publishes at window 4.
Every arm completed 320,000 deliveries with checksum 18,656,000. Median
throughput moved from 1,591 to 2,240 publishes/s; the paired throughput median
was 1.417x with 7/7 wins. Paired p50 and p99 medians were 0.653x and 0.682x.
The exact final-binary QoS 1 matrix above was the synchronous-path control for
this QoS 2 change. Three shorter RSS pairs measured 6,544 KiB baseline versus
6,708 KiB candidate medians for transient QoS 2.
Three durable QoS 2 control pairs, which also start no writer, measured 6,624
versus 6,620 KiB and overlapping timing. The baseline broker, candidate broker,
fixed driver, and complete paired log have SHA-256 values
`cadec82a5d73be2c98beb865f5ae9d0a7c724d66d51d04cfd6b00e34f1bfcbaa`,
`cc2c445614e2c49687c0a32281f3bb765795f3999f640014531d51539941bcad`,
`dda118b3c68c0c24f4a77ad9e3c5b939f6df17c6904de7bb131c971e07aafc36`,
and `326fec275da8588cfc4a03ce41b67bdad1344e5ba2f5bd1b17b8adb77d47d839`
respectively.

The same bounded writer now covers multi-destination transient QoS 1 delivery.
Publisher PUBACK no longer waits for unrelated subscriber socket writes;
self-delivery remains synchronous, and the 16-delivery watermark still
converts a lagging target to caller-owned backpressure. Source QoS 0 remains
synchronous unless the broker is configured to upgrade its outgoing QoS.
Writer creation follows the effective local Maximum QoS, so a QoS-0-only
connection allocates no writer.

An immediate pre-change matrix is retained at
`zig-out/mqtt-broker-matrix/run.20261002T094138Z.1428572` (23,252,125 bytes;
summary SHA-256
`85ee91fe87aec1b52b30375ae70b35bec52410256836e97fb4b7dc121b91ad95`).
Two consecutive final-binary captures are retained at
`zig-out/mqtt-broker-matrix/run.20261002T120130Z.1729461` (23,251,737 bytes;
summary SHA-256
`2e9586944c14fe6d7813e6aeb7c789c1c500d97c8a44fb0c1bde0dda6aeb4b16`)
and `zig-out/mqtt-broker-matrix/run.20261002T120212Z.1739418` (23,251,726
bytes; summary SHA-256
`54d69bc147b50d53e1eddb1fce5c80fde25513596308b54c33e365ed426abe1f`).
All 120 broker runs completed their exact delivery counts and checksums. The
two final-binary netz medians versus the immediate baseline were 29,452–29,635
versus 27,958 publish/s for serial, 50,482–50,784 versus 50,190 for
publishers-32, 4,214–4,219 versus 2,863 for fanout-32, 3,945–4,065 versus
4,131 for balanced-32x32, and 24,793–25,206 versus 20,159 for large-payload.
Thus fanout-32 improved 47.2–47.4% and large-payload improved 23.0–25.0%;
serial and publishers-32 improved 5.3–6.0% and 0.6–1.2%, while noisy balanced
32×32 regressed 1.6–4.5%.
Normalizing each ABBA capture to its co-run audited Mosquitto binary produced
0.953–0.956× for fanout-32 versus 0.651× before, and 1.001–1.030× for
large-payload versus 0.818× before. Fanout p99 fell from 1.346 ms to
0.824–0.835 ms. The expected writer cost was about 112 KiB of median broker
RSS in fanout-32; the 4-KiB shape added 62–94 KiB. These are bounded
multi-subscriber and large-payload gains, not a universal MQTT superiority
claim; serial and publisher-heavy scheduling remain visible targets.

A five-pair fixed-binary balanced-32x32 A/B at
`zig-out/mqtt-qos2-cache-ab` (36,706,710 bytes; aggregate file-hash digest
`bd7b0a350ed4e607a87120f007689ec428c9060a387f1ee83f9ef958fe0e33cc`)
moved raw median throughput from 1,551 to 1,559 publishes/s; paired medians
were -0.4% throughput, -0.5% p50, and -0.1% p99. A separate 50,000-publish,
32-publisher/one-subscriber five-pair run at
`zig-out/mqtt-qos2-cache-publishers-ab/run.20260930` (15,461 bytes;
aggregate file-hash digest
`8ebee9d1afb5b395be318d0a57df5d4db9f508bf4738b9fb4ec0057ca4513d5c`)
had paired medians of -0.2% throughput, +0.2% p50, and +0.4% p99. Both timing
sets are neutral with overlapping ranges; the exact allocator reduction is the
supported result.

The first complete capture is
`zig-out/mqtt-broker-allocator-matrix/run.20260930T-final3` (22,253,198
bytes); summary SHA-256 is
`6d5696584282e90ebf0c6554134b77f75aab17a466149a3f5c0b1d910a15cfe9`.
All 20 runs returned `live_bytes=0`. Counts include broker startup, warmup,
measured traffic and teardown, so the per-message values below are diagnostic
normalizations rather than steady-state timing claims.

| shape | median allocs | allocs/publish | allocs/delivery | median allocated bytes | ≤64 B / 65–256 B allocs |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 5,235 | 10.225 | 10.225 | 6,643,666 | 1,941 / 2,005 |
| publishers-32 | 39,460 | 9.634 | 9.634 | 9,624,238 | 13,200 / 26,213 |
| fanout-32 | 159,619 | 77.939 | 2.436 | 24,358,273 | 76,393 / 80,844 |
| balanced-32x32 | 421,950 | 131.859 | 4.121 | 60,112,229 | 114,533 / 303,850 |
| large-payload | 28,423 | 13.878 | 3.470 | 26,237,225 | 10,946 / 13,104 |

The dominant balanced cost is therefore not its one route-array allocation per
PUBLISH: 418,383 of the median 421,950 allocations are at most 256 bytes.
Future broker work should first isolate and amortize per-delivery property,
packet and queue ownership in those two buckets, then use the unchanged
performance matrix to prove that lower allocation pressure also improves
throughput and tail latency.

The per-connection reduction comes from keeping the WebSocket-specific
transport state out of line. `PacketTransport` previously embedded the full
WebSocket connection as its largest union member, so every plain TCP MQTT
connection occupied that size even though it never used HTTP, TLS, WebSocket,
or compression state. WebSocket/WSS construction now owns one fallible boxed
transport object, including cleanup on allocation failure, while TCP and the
pointer-backed TLS variants stay inline. A six-pair fixed-binary ABBA check of
the balanced 32×32 shape (`bd36916d` baseline, `546e101b` candidate, fixed
`00aaf0a8` driver) measured 10,920–10,956 versus 10,232–10,256 KiB netz RSS;
the paired median ratio was 0.935 (-6.5%). The paired throughput ratio was
0.993, so this is retained as a memory-layout win rather than a throughput
claim. The complete A/B artifact is
`zig-out/mqtt-transport-box-ab/run.20260929`. Compared with its immediately
preceding full matrix, the first post-boxing capture lowered netz median RSS
in all five shapes: 3.0%, 7.5%, 8.9%, 6.5%, and 1.7% in table order.

TCP packet parsing first combined the mandatory Control Packet byte and first
Remaining Length byte in one read. A fixed-binary six-pair ABBA isolated that
step at +5.9% median serial throughput. The parser now goes further with a
512-byte connection-local read-ahead buffer: common small packets need one
transport read, bytes from a coalesced following packet remain buffered, and
large packets continue directly into their exact owned allocation. Tests cover
split-header timeout/resume, two coalesced packets, the large-packet transition,
and retry after allocation failure without consuming buffered bytes.

For the final read-ahead binary, two traced runs of 4,096 measured plus 128
warmup QoS 1 publishes reduced `io_uring_enter` from 33,811/33,810 to
12,862/13,000 calls (-61.8% by medians). A separate six-pair fixed-binary ABBA
with old driver `a1110499`, baseline broker `38e4fa6c`, and candidate broker
`0f5eaa7a` measured 18,659–19,347 versus 29,092–29,960 publishes/s. All six
pairs improved; the paired throughput-ratio median was 1.557, p50 ratio 0.650,
p99 ratio 0.655, and RSS ratio 1.005 (3,480 versus 3,496 KiB medians). The
bounded artifacts are `zig-out/mqtt-readahead-final-strace/run.20260930` and
`zig-out/mqtt-readahead-final-ab/run.20260930`. The final full matrix completed
all 40 broker runs, but its common client also contains read-ahead, so the
table is a fair current same-client comparison rather than server-only causal
evidence.

The Session-route aggregation plan now accepts caller-owned storage for up to
32 raw Session matches. This removes its route-array, identifier-array, and
hash-index allocations from the common fanout path while retaining the prior
indexed heap fallback above that threshold. A failing-allocator test exercises
all 32 scratch entries with overlapping identifiers and validates the merged
QoS/retain result; a 33-route test covers the fallback. A six-pair fixed-binary
ABBA with driver `0d3875ff`, baseline broker `0f5eaa7a`, and candidate broker
`31a38344` found serial throughput neutral (paired median ratio 1.001) and
fanout-32 throughput 1.027, with median p50 and p99 ratios 0.950 and 0.970.
RSS was effectively unchanged. The artifact is
`zig-out/mqtt-session-plan-ab/run.20260930`; the full matrix completed all 40
runs, while the fixed-binary result remains the causal evidence.

Outgoing live fanout and durable Session replay use eight caller-stack property
slots while holding that connection's writer mutex. Property descriptors
continue to borrow their immutable Publication or Session values only through
the synchronous encode/write call. Larger sets use one exact connection-owned
overflow slice whose capacity is retained, preserving allocation-free warmed
delivery without carrying a full `ArrayList` in every connection. A fail-first
second Session write proves that a warmed property-bearing Topic Alias replay
needs no new allocation. The earlier three-sample five-shape allocator matrix at
`zig-out/mqtt-property-scratch-final2` (22,231,273 bytes; summary SHA-256
`737976e8f6a1a6358bb2cda094c3c9e60741ff9dcee2ce7e7a982520390382a8`)
completed all fifteen broker runs with `live_bytes=0`. Against the preceding
four-sample matrix above, allocation counts fell 25.7%, 33.1%, 46.2%, 69.5%,
and 30.6% in table order. The balanced shape dropped from 421,950 to 128,765
allocations and from 60,112,229 to 17,893,589 cumulative requested bytes;
peak live bytes remained effectively unchanged. Because the counting
allocator changes the hot path and labels timing unusable, these results are
allocation evidence rather than a throughput claim.

The broker's single-reader TCP event loop first used a 16-byte caller buffer
to remove the per-PUBACK/PUBREC/PUBREL/PUBCOMP/PINGREQ/short-DISCONNECT owned
packet allocation. It now uses a bounded 128-byte buffer, covering common
small PUBLISH packets without inflating every task stack to the transport's
full 512-byte read-ahead capacity. Once the packet length is known, eligible
fragmented bytes remain in connection-owned read-ahead across timeout and are
copied to caller storage only when complete; this avoids retaining a pointer
into temporary caller memory. Larger packets fall back to the existing exact
owned allocation, while TLS/WS/WSS retain their existing owned paths. Focused
fail-first tests cover a borrowed PUBACK, destruction without freeing caller
memory, undersized-buffer fallback without consuming read-ahead, and a
split three-byte prefix followed by timeout/resume without allocation.

The final three-sample matrix at `zig-out/mqtt-borrow-128-final` (22,239,361
bytes; summary SHA-256
`d984b37b5ccb209b04be818272c2ebea9d09e95e9dd9cd26022147da8e923c54`)
completed all fifteen broker runs with zero live bytes. Relative to the
16-byte caller-buffer matrix, allocation counts fell another 19.8%, 19.3%,
and 19.3% for publishers-32, fanout-32, and balanced-32x32; the 256-byte serial
and 4-KiB payloads deliberately remain on the owned fallback. Balanced 32x32
fell from 18,109 to 14,621 allocations, or 0.177 to 0.143 per measured
delivery. Relative to the original 421,950-allocation baseline, the combined
property-scratch and caller-buffer work removes 96.5% of broker allocations in
that shape. A fixed-client five-pair, alternating-order comparison at
`zig-out/mqtt-read-ahead-borrow-128-ab/run.20260930` measured candidate
throughput higher in three pairs and moved the median from 3,640 to 3,813
publishes/s (4.8%); ranges overlap, so this is retained as no-regression
evidence rather than a general throughput claim. The `runLoop` native stack
frame grows only by the selected 112-byte buffer delta (0xe70 to 0xee0), and
the process-RSS samples were too noisy for a separate memory claim.

Network-originated publications now retain their match output in a bounded
publisher-slot scratch for up to 32 registered subscriptions. The plan remains
stable while the global state mutex is released for persistence and socket
writes, but is cleared before that sole reader can process its next PUBLISH;
local publications, due Wills, system metrics, stale publisher identities, and
larger subscription sets keep independent exact owned storage. Disconnect
releases the retained capacity. A fail-first test proves warmed reuse without
allocation, checks shared-subscription round-robin advancement, and verifies
that the over-bound fallback fails before moving that cursor. The three-sample
matrix at `zig-out/mqtt-route-slot-scratch-final2` (22,252,606 bytes; summary
SHA-256
`5c66fe00cdafdccdc16c3cdb38b4c6ea5437ea191bd2cd022d51d9139e1a6855`)
completed all fifteen broker runs with zero live bytes. Relative to the prior
128-byte receive-scratch matrix, allocation counts fell 19.7%, 24.4%, 23.5%,
23.4%, and 19.8% in table order. Balanced 32x32 moved from 14,621 to 11,197
allocations (0.109 per measured delivery) and cumulative requested bytes fell
from 17,142,677 to 11,885,461; peak live bytes changed by only about 2 KiB. A
fixed-client, five-pair alternating-order A/B at
`zig-out/mqtt-route-slot-scratch-ab/run.20260930-final` (37,186,446 bytes;
aggregate file-hash digest
`cd34aa824adadd7e3a2dbd8cd142a31e9a3652c0bb1a83d6e9f13c5a8e53eedb`)
moved median throughput from 3,589 to 3,885 publishes/s (8.2%, four of five
paired wins) and median p99 from 33.20 to 29.59 ms (10.9%, four of five wins).
The ranges overlap, so this remains workload-specific supporting evidence
rather than a general throughput claim.

The default empty listener namespace now maps an inbound Topic Name through an
explicit `MappedTopic` borrowed result rather than allocating an identical
copy. Non-empty mount points still own their canonical prefix concatenation,
and the existing `mapTopicAlloc` API keeps its always-owning contract. The
borrowed packet remains alive throughout ACL checks, QoS 2 staging, retained
storage, route planning and shared-Publication construction, each of which
either consumes it synchronously or deep-copies state that escapes the call.
A fail-first namespace test verifies pointer identity and allocation-free
destruction for the empty prefix, alongside owned non-empty-prefix cleanup.
The final three-sample matrix at
`zig-out/mqtt-topic-borrow-current-final` (22,264,280 bytes; summary SHA-256
`79dcab464e9ad353f5d206f6af7a1ac6013936b5db6eb84a5724f9d542767c06`)
completed all fifteen broker runs with zero live bytes. Relative to the
route-scratch matrix, allocation counts fell another 24.6%, 32.6%, 30.8%,
30.9%, and 24.6% in table order. Balanced 32x32 moved from 11,197 to 7,741
allocations, or 0.109 to 0.076 per measured delivery; the combined sequence
has removed 98.2% of the original 421,950 broker allocations. A longer
fixed-client five-pair A/B at
`zig-out/mqtt-topic-borrow-long-ab/run.20260930` used 1,000 warmups and 10,000
measured publishes per arm. The candidate won two pairs and moved median
throughput from 3,688 to 3,617 publishes/s (-1.9%) with heavily overlapping
ranges, so no throughput conclusion is drawn from that noisy run; the exact
allocation reduction is the supported result.

Shared broker `Publication` state now coallocates its aligned reference-counted
header with the contiguous Topic Name and payload tail. Properties retain their
independent deep-owned representation because their nested UTF-8/binary values
have separate lifetimes and cleanup, but the common property-free fanout path
now needs one allocation per incoming publication instead of one for bytes and
one for metadata. Release reconstructs the exact aligned allocation only after
the final atomic reference is dropped. A fail-after-one test proves the
property-free construction boundary and physical layout, while an exhaustive
allocation-failure test covers nested User Property ownership and two-reference
release. The final three-sample matrix at
`zig-out/mqtt-publication-coalloc-final` (22,262,696 bytes; summary SHA-256
`8025616b208cb08d1c0e81a20f3f545e91192e7db5de6b0eeaf726c7a5e9e7c2`)
completed all fifteen broker runs with zero live bytes. Relative to the topic-
borrow matrix, allocation counts fell another 32.6%, 48.3%, 44.4%, 44.6%, and
32.7% in table order. Balanced 32x32 moved from 7,741 to 4,285 allocations, or
0.076 to 0.042 per measured delivery; cumulative requested bytes and peak live
bytes are unchanged because the same bytes now share one allocation. Across
the optimization sequence this removes 99.0% of the original 421,950 broker
allocations in that shape. A fixed-client five-pair long A/B at
`zig-out/mqtt-publication-coalloc-ab/run.20260930` (37,086,178 bytes;
aggregate file-hash digest
`d6ad78fdef719c835ebb286b687c5e7d48e3b0c66a53c9f6bf690b50449846a7`)
moved median throughput from 2,446 to 3,620 publishes/s with four candidate
wins, but the unusually wide and overlapping host-load ranges make this only
supporting evidence rather than a general throughput claim.

Owned TCP, TLS and WebSocket broker PUBLISH packets now reserve one
16-byte-aligned `Publication`-sized prefix on their packet allocation. TCP/TLS
stream readers preserve that prefix with partial bytes across a timeout. Once ACL,
retained-state, durable-Session and route-plan work has succeeded, an
unprefixed-topic live fanout can clone forwarding properties and compact the
Topic Name plus payload into that same allocation before transferring
ownership to the shared `Publication`. Alias-resolved topics, listener mount
points, QoS 2 staging, and route misses retain their prior ownership paths. A
timed TCP-read regression verifies that the prefixed allocation survives
partial-body timeout/resume, while the TLS live-broker fuzz covers the stream
transport path and allocation-failure coverage proves that nested User Property
cloning leaves the original packet owner intact.
The three-sample matrix at
`zig-out/mqtt-large-packet-adoption-final4` (22,278,397 bytes; summary SHA-256
`598b9f26aae6fc9f56ed9f213ef6f577ec3248aff2572c62a8faa4e406003e23`)
completed all fifteen broker runs with zero live bytes. Relative to the
preceding coallocation matrix, the 256-byte serial shape fell from 1,326 to
686 allocations (2.590 to 1.340 per publish), while the 4-KiB shape fell from
4,479 to 2,303 allocations (2.187 to 1.125 per publish, 48.6%). The 4-KiB
shape's cumulative requested bytes fell from 24,492,977 to 15,540,913
(36.5%). Publisher-32, fanout-32, and balanced-32x32 allocation counts remain
unchanged because those 64-byte packets already use caller-owned stack
storage; their peak-live values remain within a few KiB of the prior matrix.
As before, the counting allocator makes these allocation and ownership
measurements rather than timing evidence.
A three-pair alternating-order fixed-client A/B at
`zig-out/mqtt-large-packet-adoption-ab/run.20260930` (22,162,412 bytes;
aggregate file-hash digest
`48cd19d76390337ccc513dcff721d870831977eb93d88d47850213d45b271be4`)
used four publishers, four subscribers, a 4-KiB payload, window 16, 1,000
warmups and 10,000 measured publishes per arm. Every arm completed 40,000
deliveries with checksum 10,780,000. Median throughput moved from 20,022 to
19,871 publishes/s (-0.8%), median p50 from 1.149 to 1.139 ms, and median p99
from 2.312 to 2.308 ms. The ranges overlap and the candidate won one of three
throughput pairs, so this is recorded as no clear timing regression rather
than a speedup claim; the exact allocation and byte reductions above are the
supported result.

Broker PUBLISH counters now use a dedicated group of saturating atomics.
Receive, successful-send, payload-byte and drop accounting no longer acquires
the global routing/Session mutex for every network event; state-backed gauges
remain protected and coherent under that mutex, while cumulative wire and
PUBLISH counters are documented as independently sampled. Unit tests cover
ordinary values, concurrent updates, and saturation at `maxInt(usize)`. The
allocator matrix at `zig-out/mqtt-publish-counters-final` (22,284,193 bytes;
summary SHA-256
`a79638a694006f201df5d572a85ed7104a096f05633ae9ce56ba1cb0fefb1b2b`)
reproduced the prior allocation counts and cumulative requested bytes in every
shape with zero live bytes. A five-pair fixed-binary, alternating-order
balanced-32x32 A/B at
`zig-out/mqtt-publish-counters-ab/run.20260930` (36,967,124 bytes; aggregate
file-hash digest
`2e198741c690d3ed6ec419edac738e645d18a5dc6fcb921b9df2f8eee1f98330`)
used 1,000 warmups and 10,000 measured publishes per arm. Every arm completed
320,000 deliveries with checksum 18,656,000. Raw medians moved from 2,891 to
3,374 publishes/s (+16.7%), p50 from 16.335 to 13.642 ms (-16.5%), and p99
from 38.655 to 32.154 ms (-16.8%). The paired-ratio medians were +19.0%,
-15.7%, and -16.3% respectively; candidate p99 won all five pairs. Throughput
won three of five pairs and the host-load ranges overlap, so these remain
workload-specific supporting measurements rather than a general superiority
claim.

The slot writer now performs its durable-Session selection and, when that
queue is empty, its live-delivery dequeue inside one state-lock acquisition.
Durable work retains strict priority; a durable mutation is unlocked and
persisted before any socket write or subsequent live dequeue, and an encoded
Session packet is now owned by a defer before that persistence step so an I/O
failure cannot leak it. The allocator matrix at
`zig-out/mqtt-single-dequeue-lock-final` (22,279,881 bytes; summary SHA-256
`d6eeec90ac44c464f45ed4242573cf61242109f1d509dcc24d516e746a592181`)
reproduced the previous allocation counts and cumulative requested bytes in
all five shapes with zero live bytes. A five-pair fixed-binary,
alternating-order balanced-32x32 A/B at
`zig-out/mqtt-single-dequeue-lock-ab/run.20260930` (37,027,612 bytes;
aggregate file-hash digest
`0483aa60061cf94d917d5cd63830d1430a98bdb3e179ef9ded957b4ec08d946b`)
completed 320,000 deliveries per arm with checksum 18,656,000. Raw medians
moved from 3,514 to 3,582 publishes/s (+1.9%), p50 from 17.846 to 14.920 ms
(-16.4%), and p99 from 35.082 to 33.126 ms (-5.6%). Paired-ratio medians were
+0.6%, -12.3%, and -2.9% respectively. Throughput and p99 each won three of
five pairs, p50 won four, and the wide host-load ranges overlap, so these are
supporting latency/no-regression measurements rather than a general speedup
claim.

Live overlapping-subscription merge now uses the routing transaction's queue
tail instead of linearly scanning each destination's complete pending queue.
Every broker Publication is unique to one route operation, and that operation
holds `state_mutex` while it materializes all destinations, so an earlier raw
match for the same client can only be the current tail; an older equal pointer
cannot exist because queued Publications remain referenced. A local queue test
covers consumed-prefix and non-tail rejection, while a live MQTT 5 test proves
that two overlapping subscriptions still produce one PUBLISH with both
Subscription Identifiers and no duplicate delivery. The three-sample matrix at
`zig-out/mqtt-tail-merge-allocator-final` (22,280,513 bytes; summary SHA-256
`4b4e51b1eef76c76eef638fe35e12e86f2f60e876e5d1b2f3da07919a413a21c`)
reproduced all five prior allocation counts and cumulative requested-byte
totals, including 4,285 allocations (0.042 per delivery) for balanced-32x32,
and all fifteen runs ended with zero live bytes. Two independent five-pair
fixed-binary balanced-32x32 A/B sets at `zig-out/mqtt-tail-merge-ab`
(36,634,384 bytes; aggregate file-hash digest
`5bf9744678bbd9c7b4956e4f57800336d08413c94579889df3f9eabd8d5739ab`)
completed 320,000 deliveries per arm with checksum 18,656,000. Across all ten
pairs the candidate won seven throughput pairs, seven p50 pairs, and eight p99
pairs; paired-ratio medians were +2.2%, -6.3%, and -6.4% respectively. Raw
throughput medians moved from 3,555 to 3,698 publishes/s. The samples include
wide host-load outliers, so this remains workload-specific supporting evidence
for the bounded-complexity improvement rather than a general throughput claim.

The property-free live-delivery path now avoids asking the runtime for a
monotonic timestamp for every subscriber write. `Publication.remainingExpiry`
returns immediately when no Message Expiry Interval exists, so that common
path supplies a constant timestamp that cannot affect the result; publications
with expiry retain the prior just-before-encode clock sample and decrement or
discard behavior. The three-sample allocator matrix at
`zig-out/mqtt-expiry-clock-final` (22,283,277 bytes; summary SHA-256
`271453b8d69fbcbee595f7187c4e6a8c3ebba0785d0f9dfea748b4642b042489`)
completed all fifteen runs with zero live bytes. Four shapes exactly reproduced
their prior allocation counts and cumulative requested bytes. The timing-
sensitive 4-KiB stream-read shape ranged from 2,303 to 2,307 allocations with
a 2,307 median, a four-allocation/608-byte difference from the preceding
median and no ownership change in this patch. Two independent five-pair
fixed-binary balanced-32x32 A/B sets at `zig-out/mqtt-expiry-clock-ab`
(36,637,782 bytes; aggregate file-hash digest
`9e620b6a5686dc451b56b7d4ece51ec19a504f6766c1788ff1d849344267386c`)
completed 320,000 deliveries per arm with checksum 18,656,000. The candidate
won nine of ten throughput pairs, seven p50 pairs, and eight p99 pairs;
paired-ratio medians were +5.3%, -23.1%, and -13.4% respectively. Raw medians
moved from 3,913 to 4,102 publishes/s, 14.556 to 9.084 ms p50, and 29.805 to
27.268 ms p99. Latency samples remain visibly bimodal, so the result is
workload-specific evidence for removing the redundant clock query rather than
a general latency claim.

The numeric comparison below is the 2026-08-18 same-host `ReleaseFast`
window-one run from the former Threaded client harness. It remains historical
evidence and must not be cited as current zio performance:

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
The standalone `FixedHeader.write` entry point now prevalidates and reserves
exactly its two-to-five-byte header before writing. An invalid Remaining Length
or allocation failure therefore leaves existing output intact instead of
exposing a partial Control Packet byte, while even the maximum Remaining Length
does not reserve its unsupplied 256-MiB body. One-byte-capacity fail-first and
exact five-byte-capacity regressions lock both boundaries.
The public Remaining Length, UTF-8 string, and Binary Data writers now also
validate and reserve their complete encoded field before appending any byte.
Exact-capacity fail-first tests force the allocation boundary after the first
legacy write would have succeeded and verify that all three outputs remain
empty, while the existing round trips preserve their wire representation.
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
Mosquitto-derived 225-scenario packet gate and MQTT 3.1.1/5 WS/WSS gate remain
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
masked client and unmasked server messages assembled from two parts. The full
Netz test suite, 225-scenario
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

The same-client driver accepts `--publisher-window=N`: each publisher
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
- Active clients can start and servers can accept re-authentication; normal
  PUBLISH/SUBSCRIBE/PING traffic is rejected in both directions until AUTH
  Success, and a peer that sends such traffic receives DISCONNECT Protocol
  Error.
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

The current executable obtains its monotonic clock from zio-backed `std.Io` and
prints `io backend: zio-std-io`. The numbers below predate that migration and
remain historical Threaded evidence.

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
The maintained client and local server both obtain `std.Io` from zio, the
server runs through `std.Io.async`, and the result identifies both endpoints as
`zio-std-io`. The numeric result below predates that migration and remains a
historical Threaded baseline.

2026-08-17 same-host historical `ReleaseFast` smoke result:

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
The WS/WSS endpoint obtains its `std.Io` from `netz.runtime.Backend`; readiness
and success records require `client_io=python-socket server_io=zio-std-io`. The
same gate also runs MQTT 5 behind Mosquitto-shaped PROXY v1 WS and PROXY v2 WSS
prefaces before the HTTP or TLS handshake.
`zig build interop-mqtt-websocket-origin -Doptimize=ReleaseFast` separately
ports Mosquitto's `13-websocket-bad-origin.py` request shape: a disallowed
origin is closed before upgrade, then an allowed origin completes WebSocket and
MQTT 5 negotiation on the same finite zio-backed server process; its runner
requires the same backend identity rather than accepting a generic listening
message.

The audited rumqtt client supports MQTT 3.1.1 and MQTT 5 over WebSocket, while
the rumqttd server path still contains `TODO: Add support for V5 protocol with
websockets`. Netz tests both versions end to end on its client and server and
also covers cross-message packet reassembly, QoS 1, QoS 2, and strict
subprotocol rejection. Client `wss://` uses the generic WebSocket TLS
transport. Setting `ConnectOptions.client_identity` or a TLS version policy
selects the shared vail-backed TLS 1.2/1.3 client, which sends supported
client identities and maps
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

The native vail transport now negotiates TLS 1.2 and TLS 1.3. Callers can
require either version or offer both with TLS 1.3 preference. The TLS 1.2
profile is deliberately modern: ECDHE with AES-GCM or ChaCha20-Poly1305,
mandatory Extended Master Secret and secure-renegotiation signaling, no CBC,
static-RSA key exchange, or renegotiation. Listener `tls_version`/`ciphers` and
bridge `bridge_tls_version`/`bridge_ciphers` map this policy explicitly.
TLS 1.2 clients filter a configured identity against CertificateRequest's
certificate types, signature algorithms, and acceptable CA distinguished
names. Compatible P-521 identities are supported; when no identity is suitable
the client sends an empty Certificate so optional mTLS can continue and
required mTLS is rejected by the server at the protocol boundary.
The `interop-tls12-client-auth-openssl` process gate independently verifies
both a matching certificate and an unmatched optional-mTLS request through
the same shared stream used by MQTT TLS and WSS. The server rejects a client
CertificateVerify algorithm it did not advertise.
The matching `interop-tls13-client-auth-openssl` gate verifies that TLS 1.3
uses the same CA-aware selection and empty-certificate fallback. Unknown TLS
1.3 CertificateRequest extensions are ignored for forward compatibility, but
duplicate extension types remain fatal across the complete 16-bit namespace
without an arbitrary count ceiling. Repeated signature-algorithm values remain
acceptable in TLS 1.2/1.3 ClientHello and TLS 1.3 CertificateRequest vectors.
A present certificate-authorities extension must contain at least one non-empty
DistinguishedName; omitting it permits any issuer. Non-empty request contexts
are rejected during the initial handshake and remain reserved for post-handshake
auth. TLS 1.3 servers can additionally send OID filters; clients enforce Key
Usage and Extended Key Usage subsets on the leaf, reject repeated or malformed
recognized filters and prohibited anyExtendedKeyUsage requests, and ignore
unrecognized OIDs. CertificateRequest accepts and exposes the standard empty
status-request signal, rejects non-empty forms and recognized extensions that
are illegal in that message, and ignores only genuinely unknown extensions.
Client identities can carry leaf or per-entry OCSP staples; clients send them
only when requested, while servers reject unsolicited staples and preserve the
CertificateEntry association for trust verification.
Servers validate the complete CertificateRequest and its
nested vector lengths before writing ServerHello, preserving transactional
failure for invalid authentication configuration.
HTTP/1, HTTP/2, WSS, and MQTT round-trip tests force TLS 1.2, while OpenSSL
interoperability covers both endpoint roles and good/missing/revoked OCSP.
The shared stream also exposes RFC 5077 TLS 1.2 ticket issuance and resumption:
servers use an application-owned bounded keyring and generate a unique sealing
nonce per connection, while clients can transfer an owned ticket cache into a
later connection. TLS 1.3 ticket extension parsing covers the complete 16-bit
namespace, rejects duplicates, recognized misplaced extensions and the
RFC-forbidden 65,535-byte vector, while ignoring genuinely unknown extensions.
Cached state is bound to the server identity, ALPN, cipher suite, and lifetime;
an unauthentic ticket falls back to a full handshake.
The reconnect client owns the newest TLS 1.2 ticket independently of each
short-lived Network Connection and supplies it only through ticket-aware
native TLS/WSS connectors. A renewed ticket replaces and securely destroys the
prior cache; an expired cache is destroyed before dialing, while an
unauthentic ticket is replaced after the server's full-handshake fallback, so
neither stale form can poison later reconnect attempts. The shared stream's bidirectional
`interop-tls12-ticket-openssl` process gate independently proves both netz
client and netz server resumption against OpenSSL rather than relying only on
self-interoperability.
The versioned stream additionally exposes RFC 8446 TLS 1.3 PSK-DHE tickets:
post-handshake messages are authenticated and retained instead of discarded,
and the server issues a fresh stateless ticket after either a full or resumed
handshake. The shared parser preserves finite RFC 8446 early-data limits even
though MQTT leaves early data disabled; zero-lifetime tickets are consumed and
discarded without failing the live connection or replacing an older cache entry.
Client caches and server keyrings expire tickets at the exact advertised
lifetime boundary and reject timestamps before issuance.
The bidirectional
`interop-tls13-ticket-openssl` gate validates
both endpoint roles against OpenSSL. MQTT reconnect now owns, ages, renews, and
reuses these TLS 1.3 tickets across both native TLS and WSS connections. Its
connector contract carries TLS 1.2 and TLS 1.3 state together, preserving
version fallback without sharing ticket state between protocols. Early data
remains disabled, so MQTT CONNECT ordering is unchanged.
Configured TLS bridges use the same reconnect-owned lifecycle for both ticket
versions. Before a multi-address attempt, the connector validates each cached
ticket against the selected endpoint hostname and lifetime; a failover target
therefore performs a full handshake instead of receiving another host's
resumption state.
Configured MQTT TLS and WSS listeners can enable either version with
`tls12_session_tickets true` or `tls13_session_tickets true`, an explicit
matching `*_session_ticket_server_id`, and a bounded
`*_session_ticket_lifetime`. Each logical listener owns independent, securely
generated process-lifetime TLS 1.2 and TLS 1.3 keyrings shared by its IPv4/IPv6
sockets, preventing the protocols from sharing an AEAD key/nonce domain. The
configuration rejects missing identities, policies that do not offer the
configured ticket version, zero or overlong lifetimes, and TLS
client-authentication combinations whose peer identity cannot safely survive
stateless resumption. Dedicated Python/OpenSSL gates verify both versions on
configured MQTT/TLS and MQTT-over-WSS listeners through complete MQTT 5
CONNECT/PING/DISCONNECT exchanges.

`mqtt.tls_runtime.Client` accepts host names, literal addresses with an explicit
TLS identity, and `mqtts://`/`ssl://` URIs (default port 8883). It reuses the
same Zig 0.16 TLS client as HTTPS/WSS, including operating-system roots,
caller-managed CA bundles, hostname verification, and explicit truncation
policy. Setting `ConnectOptions.client_identity` or a non-default TLS version
policy selects the vail TLS 1.2/1.3
stream client so it can answer CertificateRequest with Ed25519, ECDSA, or SM2
identity material. The vail path maps the same system/caller CA and hostname
policy by default, or accepts a pinned/custom `server_verifier`; clients
without an identity keep the standard-library TLS path.

`mqtt.tls_runtime.Server` is a native TLS 1.2/1.3 listener backed by project-local
vail primitives. It accepts caller-provided DER certificate chains and
Ed25519/ECDSA/SM2 signers, generates fresh handshake/key-exchange/signature
entropy per connection, supports separate TLS 1.2 and TLS 1.3 cipher-suite preference,
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
surface instead of requiring mTLS as an accidental feature flag. Native MQTT
TLS and MQTT-over-WSS options both expose the shared `stapled_ocsp` /
`request_ocsp` policy; requiring a staple selects vail automatically and
rejects the TLS connection before MQTT or WebSocket bytes are emitted.
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
and optional-anonymous TLS 1.3 paths plus required ECDSA mTLS over TLS 1.2
against OpenSSL's real
client-certificate implementation. The netz endpoint obtains `std.Io` from
zio, and the gate requires every readiness/result record to identify
`client_io=openssl-sync server_io=zio-std-io`.

Run the steady-state 1 KiB QoS 1 baseline with:

```sh
zig build bench-mqtt-tls -Doptimize=ReleaseFast
```

The maintained client and local TLS server now obtain `std.Io` from zio, the
server is scheduled with `std.Io.async`, and the structured result identifies
both endpoint runtimes as `zio-std-io`.

The numbers below are the 2026-08-18 same-host `ReleaseFast` Threaded baseline,
the median of three runs after 100 warmups and 2,000 measured PUBLISH/PUBACK
exchanges through the production TLS server and MQTT broker-side runtime:

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

## zio timed-I/O runtime fast path

The runtime dependency now pins the pushed `passchaos/zio` commit
`aa1a91f768f4ff9ae92c9937c6b8ef5d0d0e8851`. It includes the direct waiter
change from `4f12748e`: a timed I/O operation inside a runtime task uses the
completion's `Waiter` timer instead of building a general two-member
`Group(.race)`. The blocking/no-task fallback is retained, and both timeout and
external cancellation explicitly cancel and join the outstanding I/O
completion. The follow-up also avoids refreshing the event-loop clock when a
timer already carries an absolute deadline; relative durations still receive a
fresh origin, and `poll` refreshes every clock before expiry checks. Dedicated
tests cover natural completion, timeout, cancellation, absolute-deadline
firing, and cached-clock preservation under default, epoll, poll,
single-executor, and pinned scheduling; the complete zio suite passed 763 tests
with 8 platform skips.

A five-pair, fixed-binary, AB/BA, CPU-pinned MQTT 5 QoS 2 comparison accepted
only samples with no concurrent Zig compiler. Candidate/baseline paired medians
were 1.0584x throughput with 0.9210x p50 for serial traffic, 0.9973x/1.0040x
for publishers-32, 1.0110x/0.9551x for fanout-32, 1.0010x/0.9892x for balanced
32x32, and 1.0176x/0.9476x for the 4-KiB shape. The 4-KiB candidate won all
five throughput pairs and lowered p99 in all five. Seven additional pairs put
MQTT-over-WebSocket at 1.0053x throughput with 6/7 wins and native
MQTT-over-TLS at a neutral 0.9998x. A matched `perf` capture removed
`Group.groupCallback` and `Loop.cancelLocal` from the sampled target path;
`timedWaitForIoClock` self cost moved from 3.11% to 0.48%, with direct waiter
and timer-clear work visible instead. These percentages describe different
total runtimes and are structural evidence, not absolute CPU-time ratios.

For the follow-up absolute-deadline change, a seven-pair CPU-thread-time
microbenchmark reduced absolute timer arm plus clear from 133 to 61 ns/op
(0.4656x median, 7/7 wins). A five-pair MQTT rerun isolated the broker and
driver on CPUs 10 and 11 outside concurrent build affinity; throughput paired
medians were 1.0042x, 1.0122x, 1.0037x, 1.0046x, and 1.0074x across serial,
publishers-32, fanout-32, balanced-32x32, and 4-KiB shapes. The profile's
`clock_gettime` self share fell from 16.35% to 11.54%, with the former 6.17%
waiter child path absent. End-to-end movement is therefore positive to neutral,
while the removed clock read is the primary supported result.

The TCP/TLS/WebSocket packet framing paths now retain the `FixedHeader` they
already decoded to establish the complete packet length and pass it into
`OwnedPacket`, rather than decoding Remaining Length a second time. The common
TCP caller-buffer and uninterrupted owned paths, TLS stream path, and
WebSocket aggregation path all reuse that result; only a large TCP body resumed
by a later call reparses its retained header, avoiding extra steady-state
connection storage. Five fixed-binary CPU-10/11 QoS 2 pairs produced
candidate/baseline throughput medians of 1.0046x, 1.0022x, 1.0041x, 0.9989x,
and 1.0008x across serial, publishers-32, fanout-32, balanced-32x32, and 4-KiB
shapes. The ranges overlap, so no end-to-end speedup is claimed. In matched
100,000-publish profiles, the former 1.33% `FixedHeader.parse` child path below
`readTcpPacketWithPolicy` disappeared. The baseline/candidate broker hashes
are `74cff6622c25318b1d0f6c6fb45a4056af6fcdcb282d049b8fc0a5a2e5959d53`
and `7555c1775b84778f985c69e411f7e52a1761151a3be72493a6df395182b41975`;
the unchanged driver hash is
`30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.

PUBLISH and publish-acknowledgement decoding now continue that ownership chain:
their whole-packet `parse` APIs retain complete standalone validation, while
the broker passes the already bounded Remaining Length payload and header flags
to `parsePayload`. This removes another fixed-header decode from incoming
PUBLISH, PUBACK, PUBREC, PUBREL, and PUBCOMP processing without trusting
unframed network input or adding connection state. Against the framing-only
baseline, five fixed-binary CPU-10/11 QoS 2 pairs produced throughput medians
of 1.0088x, 1.0135x, 1.0025x, 1.0003x, and 1.0002x in serial,
publishers-32, fanout-32, balanced-32x32, and 4-KiB order. The overlapping
ranges again limit the conclusion to no observed regression. In matched
100,000-publish profiles, `FixedHeader.parse` fell from 1.64% to 0.66% self
samples and remained only under outbound `Connection.writePacket`; its
receive-side broker paths disappeared. The framing-only baseline and final
candidate broker hashes are
`7555c1775b84778f985c69e411f7e52a1761151a3be72493a6df395182b41975`
and `51866c4694a3fc96d28491d5d5204f103b97ecb88ccf7acff32ed45ecccf3253`.

Internally generated control packets now use a private typed-write path as
well. CONNECT, CONNACK, publish acknowledgements, subscription controls, PING,
DISCONNECT, and AUTH retain direction, authentication-state, peer-size,
deadline, and transport-failure validation, but no longer decode their own
freshly encoded Fixed Header. Arbitrary Session/restored bytes remain on the
fully validating raw path. Against the preframed-parser baseline, five fixed-
binary CPU-10/11 QoS 2 pairs produced throughput medians of 1.0101x, 1.0006x,
0.9989x, 1.0238x, and 1.0053x in serial, publishers-32, fanout-32,
balanced-32x32, and 4-KiB order. Ranges overlap, so no universal speedup is
claimed. The matched 100,000-publish profile no longer contains
`FixedHeader.parse`; the prior profile's remaining 0.66% came only from
outbound `Connection.writePacket`. The baseline/candidate broker hashes are
`51866c4694a3fc96d28491d5d5204f103b97ecb88ccf7acff32ed45ecccf3253`
and `dccf66204cdb25779951c4ae42a2fd37085710d8e45e69b98b972addceeb2836`.

Both fixed WebTransport binaries also completed 10,000 real
QUIC/TLS/HTTP/3 1-KiB DATAGRAM sends and receives, in batches of 16 with 64
maximum in flight, zero timeouts, and identical checksum. Host compilation
prevented a clean timed pair, so no WebTransport speed claim is made. The full
method, ratios, binary hashes, perf interpretation, and evidence boundary are
recorded in `docs/benchmark-baseline.md`.

## Remaining work before broad superiority

The shared `fuzz-parsers` target dispatches every bounded input through the
MQTT Fixed Header and MQTT 3.1.1/5 CONNECT, CONNACK, PUBLISH, ACK,
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

The reconnect layer's network owner remains synchronous internally. The public
managed worker accepts owned PUBLISH, SUBSCRIBE, UNSUBSCRIBE, manual ACK,
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
Further parity work is ergonomic integration with
application-specific async executors rather than missing operations, event
delivery, or completion storage. Re-authentication properties are deep-owned
until the initiating AUTH write completes. The single-owner bounded poll path,
callback
driver, managed background-thread wrapper, optional application-controlled QoS
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
Reconnect clients can also encode an identity-bound Session snapshot while
online under their single-owner API and transactionally restore it only while
no Network Connection is active. The versioned CRC envelope binds protocol and
Client ID, deducts wall-clock downtime from
Message Expiry, restores outgoing QoS 1/2 at the exact PUBLISH/PUBREL stage,
and preserves deferred inbound QoS 2 `await_pubrel`/`release_pending` markers.
Decode uses a temporary one-Session store and swaps only after full validation;
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
`deinit` remains the single resource-reclamation boundary. This lets supervisors
compose multiple reconnect loops without hanging on an event queue after one
side has already failed.
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
same durable Session. The 225-scenario Mosquitto-derived wire gate runs the
same policy through the standalone broker option, including exact Session
Present, takeover DISCONNECT and missing-username refusal bytes.
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
`allow_anonymous false` requires a valid username/password, while an
anonymous-capable listener permits absent credentials but rejects credentials
that are supplied and invalid. `mqtt.password_file` recognizes current
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
reload disconnects nobody. Another starts with client A accepted and client B
revoked, swaps the CRL through SIGHUP and proves
that outcome reverses, then supplies a signature-mutated CRL and proves the
failed reload retains the prior policy on the same live listener. Bridge
definitions are the exception: `bridge_reload_type lazy|immediate` selects
per-bridge generation replacement on the same SIGHUP without rebinding
listeners. Listener topology, anonymous policy, limits, and persistence
settings still require restart.
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

`zig build interop-mqtt-mosquitto-vectors -Doptimize=ReleaseFast` now runs 225
raw MQTT scenarios derived directly from Mosquitto `5cd25465`'s packet
generators: two source-locked PROXY protocol cases consume Mosquitto's v1 TCP4
and v2 IPv4
prefaces before completing MQTT 5 CONNECT and PING on the same stream; the
seven/no-topic-tree QoS 1 no-matching-subscriber PUBACK sequence
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
real libmosquitto clients to the netz broker over MQTT 3.1.1 and MQTT 5. Each
version verifies exact topic, payload, delivered QoS, and retain flag for QoS
0/1/2 fanout plus retained replay. A final MQTT 5 pair publishes Response
Topic and binary Correlation Data through the CLI property API and requires
libmosquitto's formatted decoder to reproduce both values exactly. This is
client-process interoperability evidence, distinct from the source-derived raw
packet fixtures below.
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
evidence independent.
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
Two companion MQTT 3.1.1/5 scenarios start from Mosquitto's
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
incompatible combination with listener `use_username_as_clientid`. As with the
other main-file values, changing this deprecated directive currently requires
a process restart; netz does not claim Mosquitto's SIGHUP behavior for it.
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
Three protocol-negotiation cases mirror Mosquitto's
`read_and_verify_protocol_version`: a structurally valid `MQTT` CONNECT with
level 3 receives the legacy four-byte Unsupported Protocol Version CONNACK,
level 6 receives MQTT 5 reason `0x84` with an empty property section, and an
invalid protocol name remains a fail-closed connection error. A following
valid MQTT 5 CONNECT/PING proves that these refusals do not poison the finite
listener. Netz still implements only MQTT 3.1.1 and MQTT 5; the level-3 reply
is an unambiguous negotiation response, not MQTT 3.1 support.
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
as a CONNACK property. All 225 curated scenarios pass. A separate
source-hash-locked adapter now executes every scenario in Mosquitto's complete
`AUTH.json`, `DISCONNECT.json`, `FLOW.json`, `FORBIDDEN.json`, `OTHER.json`,
`PINGREQ.json`, `PINGRESP.json`,
`PUBACK.json`, `PUBREC.json`, `PUBREL.json`, `PUBCOMP.json`, `REGRESSION.json`,
`SUBACK.json`, `SUBSCRIBE.json`, `UNSUBACK.json`, `UNSUBSCRIBE.json`, and
`PUBLISH.json` files: 1,372 upstream scenarios across MQTT 3.1.1 and MQTT 5.
It additionally runs 145 of 146 scenarios in the complete, hash-locked
`CONNACK.json` and 299 of 307 in `CONNECT.json`, for 1,816 source-derived
sequences total. The nine exclusions are exact `(group, test)` identities
rather than pattern skips; all use obsolete MQTT protocol level 3 outside
netz's declared 3.1.1/5 scope.

`PUBLISH.json` is now complete at 160/160. Its two `QoS 2 Dup flow*3`
scenarios encode Mosquitto's private finite tolerance for repeated non-DUP
PUBLISH packets, which conflicts with MQTT 3.1.1/5 receiver retransmission
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

The manifest pins SHA-256 hashes for all seventeen complete JSON inputs and the
audited `CONNECT.json` and `CONNACK.json` subset sources,
and the imported `mqtt_packets.py` generator, so a changed
upstream fixture cannot silently reuse the recorded scenario count.
The adapter intentionally does not claim complete-file coverage for
`CONNECT.json` or `CONNACK.json`; both contain MQTT 3.1 protocol-level cases,
outside netz's declared MQTT 3.1.1/5 scope.
The CONNECT subset also permits twelve exact MQTT 5 Malformed Packet
diagnostics where Mosquitto's fixture only requires EOF, including the case
whose group label says v3.1.1 but whose wire-level protocol byte is `05`.
This is deliberately described as a selected
wire-vector subset: Mosquitto's Python harness hardcodes its own `-v -c/-p`
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
   promotes transactionally after 1,024 live identifiers to a bounded 16-KiB
   two-bit table, retaining the complete 1..65,535 identifier space without
   allowing hash overhead to grow without bound. Incoming and outgoing maps
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
   clients do not reserve it. The two 32-byte Packet Identifier direction
   descriptors and the two 32-byte Topic Alias tables also keep independent
   lazy pointers, matching the runtime's concurrent-reader/serialized-writer
   ownership while avoiding each structure until its direction first sees QoS
   1/2 traffic or an alias mapping. Finally, each established connection keeps
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
   storage is allocated before sending a successful CONNACK and transferred to
   the slot only after that write succeeds. Generated IDs, optional ACL
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
3. Expand the source-hash-locked gate beyond its current 1,816 upstream packet
   sequences, and extend the strict broker configuration adapter toward the
   upstream harness's remaining listener-reload/general-CRL/persistence
   semantics.
   The 225
   curated scenarios, seventeen complete portable JSON files, audited 299/307
   `CONNECT.json`, and 145/146 `CONNACK.json` subsets still do not cover the
   full protocol/conformance suite.
