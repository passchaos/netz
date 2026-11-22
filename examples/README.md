# netz examples

These examples mirror the shape of the `~/Work/hyper` and
`~/Work/tungstenite-rs` examples: start a small local server, connect a client,
print the exchange, then exit. They are self-contained and do not require
external network access.

## Layout

```text
examples/
  http/          HTTP/1.1, HTTP/2 h2c, HTTP/3, unified client recipes
                 (forms, JSON, download, multipart, cookies, redirects),
                 streaming and chunked bodies
  quic/          preconfigured-key and real-handshake QUIC smoke tests
  websocket/     WebSocket echo over HTTP/1
  mqtt/          finite MQTT broker and Mosquitto-style configuration runner
  grpc/          gRPC unary over HTTP/2 h2c
  webtransport/  WebTransport over HTTP/3 handshake and streams
  benchmarks/    native protocol and transport benchmarks
  support/       shared benchmark allocators, samplers, and fixtures
  logging.zig    process-wide kron logging setup
```

Run all example compile checks:

```sh
zig build examples
```

Run individual examples:

```sh
zig build run-http-unified-client
zig build run-http-client-forms
zig build run-http-client-json
zig build run-http-download
zig build run-http-upload-multipart
zig build run-http-cookie-session
zig build run-http-redirects
zig build run-http-https-client
zig build run-http-proxy-client
zig build run-http-h2-tls
zig build run-http-h3-prefer
zig build run-http-server-routes
zig build run-http-upload-reader
zig build run-http1-hello
zig build run-http2-h2c
zig build run-http-duplex
zig build run-http-streaming
zig build run-http-chunked
zig build run-http3-handshake
zig build run-http3-multipath
zig build run-http3-fetch
zig build run-quic-echo
zig build run-quic-handshake-echo
zig build run-quic-datagram-echo
zig build run-quic-close
zig build run-websocket-echo
zig build run-mqtt-broker
zig build run-grpc-h2c
zig build run-webtransport-handshake-stream
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast -- \
  --write-strategy=auto
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast -- \
  --large-body --write-strategy=vectored
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=fixed --warmup=20 --iterations=200
taskset -c 0 zig build bench-http-content-coding -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=visitor --frame=stream --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=visitor --frame=stream_gap --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=service --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=datagram_copy --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=datagram_borrowed --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast -- \
  --stream-fragments=4 --warmup=200 --iterations=10000
taskset -c 0 zig build bench-quic-endpoint-cid-sync -Doptimize=ReleaseFast -- \
  --iterations=2000000
taskset -c 0 zig build bench-quic-connection-router -Doptimize=ReleaseFast -- \
  --iterations=10000000
taskset -c 0 zig build bench-quic-endpoint-timers -Doptimize=ReleaseFast -- \
  --iterations=2000000
taskset -c 0 zig build bench-io-deadline -Doptimize=ReleaseFast -- \
  --samples=5 --warmup=2000 --iterations=50000
taskset -c 0 zig build bench-quic-endpoint-pending -Doptimize=ReleaseFast -- \
  --iterations=2000000
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --mode=aggregate --samples=5 --connections=4 --streams=1 \
  --bytes-per-stream=1048576 --server-topology=shared \
  --shared-receive-batch=32
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --netz-only --mode=aggregate --samples=3 --connections=4 --streams=1 \
  --bytes-per-stream=1048576 --server-topology=independent
zig build bench-websocket-frame -Doptimize=ReleaseFast
zig build bench-websocket-receive-buffer -Doptimize=ReleaseFast
zig build bench-websocket-h3-echo -Doptimize=ReleaseFast
zig build bench-websocket-slices-ab -Doptimize=ReleaseFast
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
```

The MQTT broker API exposes `Broker.saveSnapshot` and
`Broker.restoreSnapshot`. Snapshots use restricted temporary files, fsync,
atomic replacement, versioned sections and CRC validation. Save is a quiescent
shutdown/admin operation; restore is intended for startup before accepting
clients. See `docs/rumqtt_parity.md` for the persisted state surface and
current persisted surface, including inbound QoS 2 transactions awaiting
PUBREL, and remaining incremental-autosave exclusions.

The finite `run-mqtt-broker` example enables this with
`--persistence=netz-mqtt.db`; it restores on startup and snapshots after the
configured connection batch exits. Pass `--no-restore` to replace an existing
database with a fresh run.

The same example accepts an exclusive `--config=PATH` mode backed by the public
`mqtt.broker_config` parser. It implements a strict, fail-closed Mosquitto-style
subset and starts every configured raw MQTT or MQTT-over-WebSocket listener on
one shared Broker core. For example:

```text
queue_qos0_messages true
global_max_clients 16384
global_max_connections -1
auto_id_prefix auto-
max_inflight_messages 20
max_inflight_bytes 0
max_queued_messages 1000
max_queued_bytes 0
persistent_client_expiration 2m
retain_expiry_interval 60
sys_interval 10
websockets_headers_size 4096
set_tcp_nodelay false
password_file users.pw
acl_file access.acl
persistence true
persistence_location state
persistence_file broker.db
autosave_interval 30
autosave_on_changes false

listener 1883 127.0.0.1
socket_domain ipv4
bind_interface lo
accept_protocol_versions 4,5
enable_proxy_protocol 1
listener_allow_anonymous false
max_qos 1
max_keepalive 60
max_topic_alias 10
max_topic_alias_broker 10
max_connections 16

listener 8080 127.0.0.1
socket_domain ipv4
protocol websockets
websockets_origin https://console.example
listener_auto_id_prefix tenant-
certfile server-chain.pem
keyfile server-key.pem
tls_version tlsv1.2
ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305
cafile client-ca.pem
crlfile client-revocations.pem
require_certificate true
use_identity_as_username true
mount_point tenant/
listener_allow_anonymous true
max_connections 16

connection upstream
address broker.example:1883 backup.example:1883
round_robin true
topic sensors/# in 1 local/ remote/
cleansession false
local_cleansession false
local_clientid local.netz-upstream
remote_clientid netz-upstream
bridge_receive_maximum 20
bridge_max_topic_alias 10
bridge_max_packet_size 0
bridge_outgoing_retain true
bridge_attempt_unsubscribe true
try_private true
bridge_bind_address 192.0.2.10
bridge_tcp_keepalive 60 10 3
bridge_tcp_user_timeout 30000
restart_timeout 5 30 120
bridge_cafile upstream-ca.pem
bridge_certfile bridge-client-chain.pem
bridge_keyfile bridge-client-key.pem
bridge_keyfile_password_file bridge-client-key.password
bridge_alpn mqtt
bridge_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305
bridge_ciphers_tls1.3 TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384
bridge_require_ocsp true
bridge_tls_version tlsv1.3
```

The accepted directives are exactly `listener`, `protocol`, `socket_domain`,
`bind_interface`, `certfile`,
`keyfile`, `keyfile_password_file`, `cafile`, `capath`, `crlfile`, `require_certificate`,
`tls_version`, `ciphers`,
`use_identity_as_username`, `use_subject_as_username`, `mount_point`,
`allow_anonymous`, `listener_allow_anonymous`, `auto_id_prefix`,
`listener_auto_id_prefix`,
`accept_protocol_versions`,
`websockets_origin`,
`enable_proxy_protocol`, `proxy_protocol_v2_require_tls`,
`max_qos`, `max_keepalive`, `max_topic_alias`,
`max_topic_alias_broker`,
`allow_zero_length_clientid`, `use_username_as_clientid`, `max_connections`, `max_packet_size`,
`message_size_limit`, `max_inflight_messages`, `max_inflight_bytes`,
`max_queued_messages`,
`max_queued_bytes`, `retain_available`, `upgrade_outgoing_qos`,
`check_retain_source`, `queue_qos0_messages`,
`persistent_client_expiration`,
`retain_expiry_interval`,
`sys_interval`, `websockets_headers_size`, `set_tcp_nodelay`,
`global_max_clients`, `global_max_connections`, `password_file`, `acl_file`, `persistence`,
`retained_persistence`,
`persistence_location`, `persistence_file`,
`autosave_interval`, `autosave_on_changes`, `connection`, `address`, `addresses`, `topic`,
`cleansession`, `local_cleansession`, `local_clientid`,
`bridge_protocol_version`,
`bridge_session_expiry_interval`, `keepalive_interval`,
`bridge_receive_maximum`, `bridge_max_topic_alias`,
`bridge_max_packet_size`, `bridge_outgoing_retain`,
`bridge_attempt_unsubscribe`, `try_private`, `bridge_bind_address`,
`bridge_tcp_keepalive`, `bridge_tcp_user_timeout`, `clientid`, `remote_clientid`,
`username`, `remote_username`, `password`, `remote_password`, `restart_timeout`,
`bridge_cafile`, `bridge_capath`,
`bridge_tls_use_os_certs`, `bridge_certfile`, `bridge_keyfile`,
`bridge_keyfile_password_file`, `bridge_alpn`, `bridge_ciphers`, `bridge_ciphers_tls1.3`,
`bridge_require_ocsp`, `bridge_insecure`,
`bridge_tls_version`, `round_robin`, `start_type`, `threshold`, `idle_timeout`, `notifications`,
`notifications_local_only`, and `notification_topic`. Unknown directives,
duplicates, bad values, and listener or bridge options before their owning
declaration are errors. In
production config mode, each listener's `max_connections` is its simultaneous
admitted-client limit and the broker keeps accepting after clients disconnect.
The repository's process gate sets `NETZ_MQTT_CONFIG_FINITE_TEST=1` to use the
sum of those values solely as a deterministic test-exit budget; applications
must not use that test-only switch. Global `max_packet_size` defaults to
Mosquitto's 2,000,000-byte
full MQTT Control Packet limit, applies to TCP/Unix/TLS/WS/WSS, and is advertised to
MQTT 5 clients. Global `message_size_limit` independently bounds PUBLISH and
Will payload bytes; zero keeps the Mosquitto unlimited default. Oversized
payloads are rejected while representable QoS flows complete. Each listener
accepts MQTT 3.1, MQTT 3.1.1 and MQTT 5 by default. Listener-local
`listener 0 PATH` selects a raw MQTT Unix-domain stream listener and deep-owns
the path until teardown, when the socket file is removed. Unix listeners share
the same Broker, authentication, ACL, mount-point, admission, and capacity
policy as IP listeners, but reject WebSocket, TLS/client-certificate, PROXY,
`socket_domain`, and `bind_interface` settings before any endpoint is opened.
Listener-local
`socket_domain ipv4|ipv6` constrains TCP, TLS, WebSocket, and WSS sockets to one
address family. When the `listener` line omits its bind address, the directive
selects `0.0.0.0` or `::`; an explicit address from the other family is
rejected. IPv6 listeners set `IPV6_V6ONLY` before bind, so an IPv4-mapped
connection cannot bypass the policy. Backends that cannot apply that pre-bind
option return `OptionUnsupported` instead of silently creating a dual-stack
socket. Without an explicit bind address or `socket_domain`, netz opens
separate IPv4 and IPv6 wildcard sockets, skips a socket family only when the
platform reports that family unsupported, and applies one shared logical
listener connection limit across both sockets.
Listener-local `bind_interface` resolves the named interface's first IPv4 and
IPv6 addresses at startup without requiring `SO_BINDTODEVICE` privileges. It
takes precedence over the address on the `listener` line, while
`socket_domain` still selects one family. Missing interfaces, interfaces with
no usable address, unsupported platforms, and an unavailable explicitly
selected family fail before serving; when no family is selected, an unavailable
family is skipped in the same way as the default wildcard listener.

Each `connection` creates one independently reconnecting bridge.
One `address` directive containing one or more `host[:port]` targets (or
bracketed IPv6 targets with required ports) and one or more explicit
`topic FILTER in|out|both QOS [LOCAL_PREFIX] [REMOTE_PREFIX]` rules are required.
Inbound bridges subscribe remotely to
`REMOTE_PREFIX + FILTER`, strip `REMOTE_PREFIX` from each delivered Topic
Name, then prepend `LOCAL_PREFIX` before local broker routing. Outbound bridges
subscribe directly to the local broker's persistent Session at
`LOCAL_PREFIX + FILTER`, remove `LOCAL_PREFIX`, and publish
`REMOTE_PREFIX + Topic Name` without a loopback socket. Empty prefixes may be
omitted or written as `""`. A connection may mix `in`, `out`, and `both`
rules; each direction must remain pairwise disjoint after its own source-prefix
expansion. Both directions share exactly one remote Client and MQTT Session.
The local source excludes bridge-injected publications, while MQTT 5 remote
subscriptions use No Local. MQTT 3.1 and MQTT 3.1.1 bidirectional bridges require the
private bridge protocol and fail instead of falling back when the peer rejects
it, preventing an undetectable publication loop. With the default
`round_robin false`, connection attempts
fall through the ordered targets, but the first target remains primary: a
secondary connection is retired after the configured restart cap so the next
attempt probes the primary again. `round_robin true` instead rotates after each
failure or disconnect and leaves a successful target active until it fails. One
`restart_timeout` value selects a fixed delay. Two values select bounded
decorrelated jitter; an optional third value is the stable-connection period
in seconds after which the delay resets to the base. Reconnects after an
established connection wait for the selected delay, while the initial startup
attempt remains immediate. MQTT 3.1.1 is the bridge default;
`bridge_protocol_version mqttv31` selects MQTT 3.1 and
`bridge_protocol_version mqttv50` selects MQTT 5. `remote_username` and
`remote_password` configure upstream authentication, with a password requiring
a username. Mosquitto's legacy `username`, `password`, and `clientid` spellings
are exact aliases for the corresponding `remote_*` directives; mixing either
spelling of the same field is a duplicate configuration error. When
`remote_clientid` is omitted, the unique connection name is used as the stable
Client ID. MQTT 3.1 remote Client IDs must contain 1-23
characters, so longer connection names require an explicit shorter
`remote_clientid`. Configured MQTT 3.1 bridges explicitly enable Mosquitto's
non-standard CONNACK Session Present bit; low-level clients remain strict by
default because the original 3.1 acknowledgement byte is wholly reserved.
`bridge_receive_maximum` is the non-zero MQTT 5
Receive Maximum and defaults to the effective global `max_inflight_messages`
(including its zero-as-65,535 spelling). `bridge_max_topic_alias` defaults to
10, may be zero to disable aliases, and bounds both the CONNECT advertisement
and aliases accepted from the remote CONNACK. `bridge_max_packet_size` bounds
complete MQTT packets sent to the remote; zero is unlimited, and MQTT 5 uses
the smaller of this value and the remote CONNACK Maximum Packet Size. An
oversized forwarded PUBLISH is dropped for that destination without tearing
down the bridge.
`bridge_outgoing_retain false` clears RETAIN from all remote PUBLISH packets in
MQTT 3.1, MQTT 3.1.1 and MQTT 5, including remote state notifications.
`bridge_attempt_unsubscribe` defaults true for outbound rules: after every
remote CONNECT it sends mapped-filter UNSUBSCRIBE packets before publishing,
except for filters still used by the same bidirectional bridge, so a persistent
Session cannot retain subscriptions left by an earlier inbound configuration.
Set it false only when that cleanup is intentionally unwanted.
Interleaved stale deliveries remain ordered, are protocol-acknowledged, and are
dropped rather than terminating the bridge. `try_private` defaults true for
pre-v5 MQTT and emits Mosquitto's private bridge protocol marker. A peer that
refuses that protocol level is retried immediately on the same endpoint with
the configured standard MQTT 3.1 or 3.1.1 level, and later reconnects retain
the successful fallback. Bidirectional legacy bridges never take this fallback
because losing private mode would remove their loop-prevention guarantee.
Incoming private bridges receive no-local and retain-as-published subscription
semantics, preventing loops without losing the original RETAIN flag. MQTT 5
does not emit the private marker, and `try_private false` always uses the
standard protocol level. `bridge_bind_address` accepts one
numeric IPv4 or IPv6 address and binds an ephemeral local port before every
cleartext or TLS connection attempt, including fallback and reconnect attempts.
DNS results are restricted to the configured local address family, while a
numeric remote address from the other family is rejected during configuration.
This operation requires the production zio backend; lower-level callers using
another `std.Io` backend receive `OptionUnsupported` rather than an unbound
connection.
`bridge_tcp_keepalive IDLE INTERVAL COUNT` enables TCP keepalive and configures
the positive idle and retry intervals in seconds plus the positive failed-probe
count. All three values are required and bounded by the non-negative C `int`
range. The complete policy is applied before every cleartext or TLS handshake;
platforms missing any required socket option and Unix-domain transports fail
with `SocketOptionUnsupported` rather than using a partial policy.
`bridge_tcp_user_timeout` is an optional non-negative millisecond value up to
2,147,483,647. When omitted, every bridge socket retains the operating-system
default; an explicit zero is passed to the kernel rather than treated as
omitted. The policy is applied to every cleartext or TLS connection and
reconnect before protocol negotiation. It is currently supported on Linux;
an explicit value on other platforms or on a Unix-domain transport fails with
`SocketOptionUnsupported` instead of being ignored. QoS 2 additionally requires
`persistence true`, a non-clean remote
Session, and for MQTT 5 a non-zero `bridge_session_expiry_interval`; the runner
derives a stable bridge identity from the connection identity and mappings and opens a
crash-safe broker journal beside the configured snapshot. A process gate runs
real broker instances, begins through an unavailable first address, verifies
round-robin failover plus inbound and outbound prefix mapping and QoS 1/2
delivery, kills both upstream and local brokers at persistence boundaries, and
verifies automatic resubscription and outbound recovery. A separate
three-broker case verifies secondary takeover followed by active failback when
the primary becomes available.

`local_cleansession` controls the broker-internal source Session used by
outbound rules and defaults to the value of `cleansession`, matching Mosquitto.
When true, opening the source removes any previous subscriptions and queued
deliveries, and closing it removes the replacement Session durably. A process
restart gate verifies that an offline queued QoS 0 message is not replayed
while a newly published message is still forwarded. Outbound QoS 1/2 requires
a persistent local Session to preserve its delivery contract, so those rules
combined with `local_cleansession true` fail before listeners open.
`local_clientid` selects the stable identity of the broker-internal source
Session and its outbound journal. It defaults to `local.<remote_clientid>`;
duplicate outbound local IDs are rejected before listeners open. Changing an
explicit local ID deliberately starts a different source Session, while
renaming a bridge with the same explicit ID keeps its persistence identity.

Bridge TLS uses the vail TLS 1.2/1.3 data plane with hostname verification.
Trust comes from a bounded explicit `bridge_cafile`, a non-recursive
OpenSSL-style `bridge_capath`, operating-system roots enabled by
`bridge_tls_use_os_certs true`, or any combination. Directory loading accepts
`.pem` files and safe `hhhhhhhh.N` rehash links, deduplicates link targets, and
enforces entry, certificate, per-file, and aggregate-byte limits before any
listener opens. Optional bridge mTLS uses
the same strictly parsed P-256/P-384/P-521/Ed25519/RSA identity loader as the
server and supports PBES2-encrypted PKCS#8 through
`bridge_keyfile_password_file`. `bridge_alpn` supplies one protocol offer.
`bridge_ciphers_tls1.3` accepts an ordered colon-separated list of supported
IANA TLS 1.3 suite names and applies it to every initial and reconnect
ClientHello. Empty components, duplicates, aliases such as `DEFAULT`, and
unknown names fail during configuration rather than falling back to another
cipher policy.
`bridge_ciphers` independently accepts the modern TLS 1.2 ECDHE+AEAD OpenSSL
names implemented by Vail. `bridge_tls_version tlsv1.2` permits TLS 1.2 and
prefers TLS 1.3 when the peer offers it; `tlsv1.3` requires TLS 1.3. Listener
`tls_version` and `ciphers` apply the same policy to MQTT TLS and WSS.
`bridge_require_ocsp true` requires every initial and reconnect TLS handshake
to carry a current, correctly signed `good` OCSP staple bound to the presented
leaf and issuer. Missing, expired, malformed, unknown, and revoked responses
fail the TLS handshake before MQTT CONNECT is sent. Vail clients request OCSP
by default so RFC 7633 Must-Staple certificates remain usable even when this
explicit Mosquitto policy is left false.
`bridge_insecure true` remains rejected rather than weakening authentication.
Every configured CA and client identity is loaded before any listener binds.
Bridge notifications default on. The configured or
`$SYS/broker/connection/<remote-client-id>/state` topic starts as retained
`0`, changes to retained `1` only after connection and subscription setup, and
returns to `0` before reconnect. Unless `notifications_local_only true` is
set, the remote CONNECT also carries a retained QoS 1 `0` Will and publishes
retained `1` after setup. Notification acknowledgements share the reconnect
client state machine without being confused with inbound bridge traffic.
`start_type automatic` is the default and keeps reconnecting. `start_type once`
makes the configured address sequence only once, then leaves that Bridge
stopped after initial failure or after its first established connection ends;
other bridges and local listeners continue running. Outbound bridges also
support `start_type lazy`: the default `threshold 10` defers the remote
connection until that many local messages are durably queued, after which the
whole queue is drained. The default `idle_timeout 60` disconnects only after
the queue and any coordinated QoS 2 transaction remain empty for that many
seconds. New arrivals wake the bridge without polling, including across the
idle-disconnect boundary. A finite `max_queued_messages` smaller than the lazy
threshold is rejected as unreachable; inbound-only lazy and mixed-direction
connections are likewise rejected.
`accept_protocol_versions` restricts that listener to `4`, `5`, or `4,5`;
version-denied clients receive the protocol-specific Unsupported Protocol
Version CONNACK before close. MQTT 3.1 (level 3), empty sets, duplicate values,
and unknown versions fail configuration because netz does not implement MQTT
3.1 and will not advertise a policy it cannot honor. Repeating
`websockets_origin` builds an exact, case-sensitive Origin allowlist for its
WebSocket or WSS listener; once configured, a missing or unmatched Origin is
rejected during HTTP Upgrade. Using it on a raw MQTT listener fails
configuration. Listener-local `enable_proxy_protocol` accepts only `1` or
`2` and consumes the required HAProxy header before MQTT, TLS, or WebSocket
handshakes. On a cleartext version 2 listener,
`proxy_protocol_v2_require_tls true` requires the SSL TLV's TLS assertion;
`require_certificate true` additionally requires its successful verification
status and connection/session certificate bit. Adding
`use_identity_as_username true` uses the validated, non-empty MQTT UTF-8 SSL
TLV commonName for authentication and ACLs. Version 2 remains incompatible
with local `certfile`/`keyfile` termination and
`use_subject_as_username`. These listener options trust the proxy's
assertions, so the port must not be reachable except through that trusted
proxy. Global
`websockets_headers_size` defaults to 4096 bytes and
accepts 1..65,535, bounding the complete HTTP Upgrade head for every WS/WSS
listener before MQTT parsing. The legacy `packet_buffer_size` alias is not
accepted because netz's raw MQTT framing uses an independent exact packet
limit. Global `global_max_clients` defaults to 16,384 and bounds active
plus unexpired offline Sessions across all listeners. A new MQTT 5 client over
the limit receives Server Busy; MQTT 3.1.1 is closed because it has no matching
CONNACK code. The Mosquitto `-1` form maps to the implementation's bounded
2,147,483,647-session ceiling; zero and other negative values are rejected.
`global_max_connections` independently bounds simultaneously admitted clients
across all listeners and defaults to `-1` (unlimited). Excess peers are closed
without a CONNACK and capacity is reusable as soon as an established client
disconnects; `-1` maps to the bounded 2,147,483,647-client implementation
ceiling, while zero and other negative values are rejected. Because the
portable `PendingSource` boundary returns after transport setup and CONNECT
parsing, the shared broker slot is claimed immediately after that boundary;
per-listener accept worker counts continue to bound pre-CONNECT work.
Global
`max_inflight_messages` defaults to 20 and bounds each client's incoming and
outgoing QoS 1/2 transactions. MQTT 5 advertises the incoming limit as Receive
Maximum; MQTT 3.1.1 enforces the same limit without a property. A peer that
exceeds it receives MQTT 5 DISCONNECT 0x93 or a 3.1.1 connection close. Zero
disables this per-client count limit by using MQTT's default 65,535-transaction
maximum and omitting the redundant property; independent aggregate and memory
bounds still apply. Global `max_inflight_bytes` defaults to zero (unlimited)
and independently bounds each client's outgoing QoS 1/2 payload bytes, for
both transient connections and durable Sessions. The message that crosses
this threshold is sent, then later messages wait; QoS 2 payload bytes remain
charged until PUBCOMP. Global `max_queued_messages`
defaults to 1,000 queued
Application Messages per Session and `max_queued_bytes` defaults to zero
(unlimited payload bytes). A zero message limit is also unlimited. The message
that reaches or crosses a configured threshold is retained, matching
Mosquitto; later messages are dropped until delivery or expiry releases queue
capacity. QoS 0 uses these limits only when `queue_qos0_messages` is enabled.
Snapshot restore applies the configured byte and queue limits fail closed, so
durable state must be drained before lowering them below already persisted
usage. Global
`retain_available` defaults to true. When false, MQTT 5 CONNACK advertises
Retain Available 0 and rejects retained PUBLISH or retained Will use with reason
0x9A; MQTT 3.1.1 closes the connection because it cannot represent that reason.
Listener-local `max_topic_alias` and `max_topic_alias_broker` both default to
10 and accept the full 0..65,535 range. The former is advertised in MQTT 5
CONNACK and bounds aliases accepted from clients; zero omits the property and
rejects all inbound aliases. The latter caps automatic broker-to-client alias
creation after taking the minimum with the client's CONNECT capability; zero
disables outgoing aliases. MQTT 3.1.1 ignores both settings.
Listener-local `max_keepalive` defaults to zero, meaning no administrative
maximum. A positive value caps MQTT 5 clients with Server Keep Alive and
refuses MQTT 3.1.1 clients that request a larger value; zero also permits a
client to disable its own Keep Alive.
Global `persistent_client_expiration` is unset by default. When configured, it
accepts a positive integer followed by `s`, `h`, `d`, `w`, `m`, or `y` and caps
the offline lifetime of persistent MQTT 3.1.1 and MQTT 5 Sessions without
lengthening a shorter client-selected MQTT 5 Session Expiry Interval.
Global `retain_expiry_interval` is off by default. A value from 1 through
10,000,000 schedules a retained-store scan at that many minutes, physically
removing MQTT 5 retained messages whose Message Expiry Interval elapsed even
when no later subscription or replacement accesses them. Values above the
Mosquitto cap are rejected instead of silently truncated. Periodic removals
advance snapshot-change autosave and append-journal state like other durable
mutations.
Global `sys_interval` defaults to 10 seconds and accepts 0..65,535;
zero disables periodic retained `$SYS` publication. Non-zero values drive the
broker's shared lifecycle timer, while explicit `publishSystemStats` calls remain
available independently.
Global `set_tcp_nodelay` defaults to false like Mosquitto. Enabling it
disables Nagle's algorithm on accepted raw MQTT, MQTT-over-TLS, WebSocket, and
WSS TCP connections; Unix-domain listeners are unaffected.
`allow_zero_length_clientid` and the legacy `auto_id_prefix` follow
`per_listener_settings`. The newer `listener_auto_id_prefix` always applies
to its listener and overrides the inherited prefix; both prefixes are limited
to 50 valid MQTT UTF-8 bytes and default to Mosquitto's `auto-`. Accepted
clients receive a collision-safe broker-generated ID, advertised through MQTT
5 Assigned Client Identifier;
when disabled, MQTT 5 returns 0x80 and MQTT 3.1.1 returns Identifier Rejected.
MQTT 5 also permits this assignment with Clean Start false; an MQTT 3.1.1
non-clean Session still requires a non-empty stable ID.
Global `upgrade_outgoing_qos` defaults to false, preserving MQTT's required
minimum of publication and subscription QoS. Enabling this non-standard
Mosquitto compatibility option instead delivers live, retained, and durable
messages at the subscription QoS.
Global `check_retain_source` defaults to true and rechecks the original
publisher's current write ACL before retained replay. The broker persists the
effective Client ID, username, and source listener port, so this remains exact
after restart and with `per_listener_settings true`; an unknown or ambiguous
source listener fails closed. Set it to false only when intentionally retaining
messages after their publisher loses write permission.
`password_file`
accepts Mosquitto's current Argon2id hashes, `$7$`
PBKDF2-SHA512 hashes, and legacy `$6$` salted SHA-512 hashes. Plaintext, unknown
or malformed hashes, duplicate usernames, files over 1 MiB, more than 4,096
users, and excessive KDF parameters fail closed before any listener is opened.
Hash comparison is constant-time and concurrent KDF work is serialized to cap
Argon2 memory amplification. Global `allow_anonymous` is order-independent and
defaults to false. `listener_allow_anonymous` is the recommended listener-local
override and takes precedence over the global value whether or not
`per_listener_settings` is enabled. For Mosquitto compatibility,
`allow_anonymous` remains listener-local when `per_listener_settings true`.
A listener whose effective anonymous policy is false requires a password file
or certificate-identity authentication; an anonymous-capable listener accepts
absent credentials but still rejects invalid credentials when a username is
supplied. `certfile` and
`keyfile` are listener-local and must occur together. Their presence upgrades
`protocol mqtt` to native MQTT/TLS and `protocol websockets` to WSS. Before any
port is opened, every identity is loaded from a leaf-first PEM certificate
chain and P-256/P-384/P-521 SEC1 or PKCS#8, RFC 8410 Ed25519 PKCS#8, or
2048/3072/4096-bit RSA PKCS#1/PKCS#8 private key. TLS-compatible constrained
RSA-PSS PKCS#8 keys are also supported. `keyfile_password_file` supplies one
non-empty line for PBES2-encrypted PKCS#8 using bounded PBKDF2-HMAC-SHA1,
SHA-256, SHA-384 or SHA-512 with AES-128-CBC or AES-256-CBC. Inputs are bounded,
strictly decoded, prepared for allocation-free handshake signing, and checked
against the leaf public key. `include_dir` is supported by the
file-loading API and only in the main file. It expands top-level regular `.conf`
files in Mosquitto's case-sensitive alphabetical order (for example, `A.conf`,
`a.conf`, `B.conf`, `b.conf`). Multiple directories retain declaration order;
nesting, special `.conf` files, oversized files/sets, and excessive directory/
file counts fail closed. The in-memory `parse` API deliberately has no
filesystem expansion. Other curves, legacy PEM encryption, plugins, and full
Mosquitto configuration remain outside this subset and fail
closed. `cafile` and/or `capath` enable optional
client certificates on a TLS listener; `require_certificate true` makes the
certificate mandatory. Every PEM CA is bounded, unique by DER
Subject, currently valid, and constrained for CA/keyCertSign/clientAuth use;
its exact DER Subject is advertised in TLS 1.3 CertificateRequest. `capath` is
non-recursive and deterministically loads bounded `.pem` regular files plus
OpenSSL `rehash` certificate links; empty, malformed, duplicate-subject, and
oversized directories fail before any listener is opened. Matching Mosquitto's
transport limitation without silently weakening authentication, `capath` is
rejected for WebSocket listeners. Optional
`crlfile` PEM lists must be signed by a unique configured CA; Ed25519, P-256
ECDSA with SHA-256, P-384 ECDSA with SHA-384, or 1024-4096-bit RSA PKCS#1
v1.5 signatures with SHA-256, cRLSign, thisUpdate/nextUpdate, extensions and leaf
serials are validated before bind. A complete CRL may be accompanied by
directly signed RFC 5280 delta CRLs; the newest compatible delta is composed
with its base, including `removeFromCRL`, before client authentication.
Revoked clients are rejected during TLS. Indirect, orphan/mismatched delta,
expired, future, malformed and unmatched CRLs fail closed. When
`use_identity_as_username true` is also set, the verified leaf's unique Subject
CN replaces any wire username and the wire password is ignored before password,
ACL, Session, Client ID, or Will policy. The CN is converted from supported
X.509 DirectoryString encodings, must satisfy MQTT UTF-8/u16 bounds, and is
deeply owned; missing, duplicate, legacy-encoded, malformed, or NUL-containing
CN values are Not Authorized. This mode is a valid authentication source when
the effective anonymous policy is false and does not use `password_file` on
that listener. A
password file does not encrypt credentials on raw TCP/WS; use TLS/WSS, a
trusted network, or a proxy.
`acl_file` accepts Mosquitto `user NAME`,
`topic [read|write|readwrite|deny] FILTER`, and global `pattern` rules whose `%u` and
`%c` substitutions occupy a complete topic level. Topic rules before the first
`user` apply to anonymous clients. Access is denied by default, explicit deny
rules take precedence, write rules cover PUBLISH and Will admission, and read
rules are checked against every concrete live, retained, or resumed delivery.
As in Mosquitto's current ACL-file plugin, SUBSCRIBE/UNSUBSCRIBE requests can be
installed even when no read rule grants them; unauthorized publications remain
undeliverable. Unknown directives/access modes and malformed patterns fail
before listeners are bound. On Linux, `SIGHUP` atomically reloads the
`password_file`, `acl_file`, `certfile`, `keyfile`, `keyfile_password_file`,
`cafile`, `capath`, and `crlfile` contents named by the initial configuration.
All replacement files are parsed before any active set is changed; any missing,
malformed, unsigned,
mismatched, or otherwise invalid file keeps the complete previous policy and
TLS identities.
Existing clients immediately observe new ACL rules. A successful password-file
reload compares parsed credentials per listener and username: unchanged users
stay connected, while removed or modified users receive MQTT 5 Administrative
Action (MQTT 3.1.1 closes directly), have their Will canceled, and must
authenticate again. Server-certificate, client-CA, and CRL changes apply to
later TLS/WSS handshakes without rebinding the listener. In-flight handshakes
retain their complete TLS policy generation until completion, while established
TLS connections retain traffic keys and authenticated peer metadata without
depending on the old files. SIGHUP also updates each existing listener's
resolved global/`listener_allow_anonymous` policy,
`allow_zero_length_clientid`, resolved global/listener auto-ID
prefix, accepted protocol versions, Maximum QoS/Keep Alive, and both Topic Alias
ceilings under the same security generation lock. Existing clients retain their
negotiated state, while later CONNECT attempts take one owned fixed-capacity
policy snapshot before Session admission and use the new values.
Changing listener topology or any other listener transport/admission field
fails the complete reload instead of being ignored. The persistence
enable/location/file remain fixed until restart.
Mosquitto's `retained_persistence` spelling is an exact alias for `persistence`;
the two names share duplicate-directive validation and cannot override each
other in one configuration.
When persistence is enabled, `autosave_on_changes true` treats
`autosave_interval` as a durable-change threshold; otherwise it is a periodic
seconds interval. Matching Mosquitto, zero disables either form of runtime
autosave while preserving startup restore and the final shutdown snapshot.
SIGHUP on Linux may change `autosave_interval` and `autosave_on_changes` among
periodic, durable-change-count, and disabled modes without rebinding listeners.
All bridge/security/persistence reload inputs are prepared before commit; a
changed persistence target fails the whole transaction and preserves the old
autosave policy. On Linux, `SIGUSR1` requests an immediate live checkpoint through an
allocation-free signal flag consumed by the normal `std.Io` supervisor; it
never performs allocator, locking, or filesystem work in the signal handler.
Run the end-to-end gate with
`zig build interop-mqtt-broker-config -Doptimize=ReleaseFast`.

`--autosave-change-count=N` additionally writes a live snapshot after `N`
broker operations that change snapshot-backed state, including durable Session,
subscription, queued-delivery, acknowledgement, inbound QoS 2, retained-message,
and Will lifecycle transitions. One operation counts once even when it changes
several stores or fans out to several durable Sessions. Periodic `$SYS` refreshes
are excluded so telemetry cannot force checkpoint churn. The option requires
`--persistence`, and `N` must be greater than zero. It may be combined with
`--autosave-interval-seconds=N`; both triggers target the same atomic snapshot
file, and whichever trigger becomes due writes the next checkpoint. Snapshot
autosave modes are intentionally incompatible with `--commit-log`, whose
fsynced records provide a separate durability policy. Change-triggered writes
are best effort after the corresponding broker mutation has committed; failures
remain pending for a later retry and are available through
`Broker.persistentChangeAutosaveError`.

Trusted reverse proxies can prepend HAProxy PROXY protocol metadata with
`--proxy-protocol=1` or `--proxy-protocol=2`. For v2,
`--proxy-v2-require-tls` and `--proxy-v2-require-client-certificate` reject
connections whose SSL TLV lacks the corresponding authenticated edge state.
`--proxy-header-timeout-ms=N` places one absolute deadline over the complete
preface.
Never expose such a listener directly to untrusted clients because PROXY
metadata is an assertion made by the connecting peer.

`--system-interval-seconds=N` periodically publishes the coherent broker
statistics snapshot as retained QoS 0 `$SYS` topics. Applications embedding
the library can call `Broker.stats()` or `Broker.publishSystemStats()` directly.

The URI helpers derive Host / `:authority` / `:scheme` from the URI. Host names,
IPv4 literals, and bracketed IPv6 literals such as `http://[::1]:8080/` are
supported by the HTTP/1, HTTP/2 h2c, and WebSocket client examples.
WebSocket connections over HTTP/1, RFC 8441, and RFC 9220 expose
`sendBinarySlices`; it sends any number of borrowed slices, including empty
ones, as one FIN-terminated binary frame without requiring a plaintext join.
`sendBinaryParts` remains the two-slice compatibility wrapper.
`bench-websocket-slices-ab` exercises that API over HTTP/1, RFC 8441, and RFC
9220. It compares direct eight-slice sends with a caller-prejoined buffer, pins
one CPU, alternates run order, validates every echo/checksum record, and reports
five-sample medians without imposing a performance threshold.

HTTP/1 WebSocket servers can stop after parsing the Upgrade request and make an
application decision before any 101 bytes are sent. The same API is available
on TCP, Unix-domain, and native TLS listeners:

```zig
var pending = try server.receiveUpgradeRequest(.{});
var pending_open = true;
defer if (pending_open) pending.deinit();

if (!std.mem.eql(u8, pending.target(), "/chat")) {
    try pending.notFound();
    pending_open = false;
    return;
}
if (!std.mem.eql(
    u8,
    pending.header("Authorization") orelse "",
    "Bearer example-token",
)) {
    try pending.reject(401, "Unauthorized", &.{
        .{ .name = "WWW-Authenticate", .value = "Bearer" },
    }, "authentication required\n");
    pending_open = false;
    return;
}

var ws = try pending.acceptWithHeaders(&.{
    .{ .name = "X-Admission", .value = "accepted" },
});
pending_open = false;
defer ws.close();
```

`PendingUpgrade` owns the accepted transport until acceptance, rejection, or
`deinit`. Header-validation and write errors do not consume that ownership. The
configured opening-handshake deadline remains the same absolute deadline while
the application checks routing or credentials. WSS pending requests also expose
the verified peer certificate chain and negotiated TLS cipher/hash metadata.

`bench-http1-pipeline` mirrors Hyper's `hello_world_16`: one persistent
loopback TCP connection carries batches of sixteen bodyless requests and
thirteen-byte bodies. The ordinary server path automatically generates the
same 29-byte IMF-fixdate as Hyper, so each response is 89 wire bytes without a
benchmark-only header. It performs untimed warmup batches before
measurement. Pin both reference executables to the same CPU when collecting
comparison evidence; see `docs/hyper_parity.md` for exact commands and captured
same-host results.

`bench-http1-body` sends and receives 1 MiB on one persistent HTTP/1
connection. `--mode=fixed` uses one Content-Length contribution in each
direction; `--mode=chunked` preserves 64 application chunks of 16 KiB.
Both peers consume bodies incrementally. The same-shape Hyper harness lives in
`tools/hyper_http1_body` and is run through:

```sh
taskset -c 0 tools/bench_hyper_http1_body.sh \
  --mode=fixed --warmup=20 --iterations=200
```

The wrapper uses the checked-in Cargo lockfile and offline mode, and expects the
reference checkout at `~/Work/hyper`.

`bench-http2-h2c` mirrors Hyper's `http2_consecutive_x1_empty`,
`http2_consecutive_x1_req_10b`, `http2_consecutive_x1_req_100kb`, and
`http2_parallel_x10_empty` on persistent prior-knowledge connections. It also
includes Hyper's `http2_parallel_x10_req_10kb_100_chunks_max_window`: ten
concurrent streams each carry 100 round-robin 10-KiB contributions under max
connection/stream windows. The
`http2_parallel_x10_res_1mb` scenario sends ten bodyless requests and streams a
1-MiB response on every stream without client-side body aggregation. The
`http2_parallel_x10_duplex_1mb_aggregate` and
`http2_parallel_x10_duplex_1mb_streaming` scenarios use the same ten 1-MiB
POST bodies and ten 1-MiB responses, differing only in whether the client
retains or callback-streams the response bodies. Run either scenario with
`--stats` in a fresh process to compare allocation and peak-live memory. The
benchmark uses the runtime's default automatic Date and Hyper-style receive
windows so steady-state wire sizes and flow-control shape match the reference. The 100-KiB
server path consumes DATA through `readRequestStreaming` without aggregation.

The `http2_shared_consecutive_x1_empty` scenario keeps the same one-connection,
empty-response wire shape while routing every sequential request through the
bounded `SharedDispatcher` and a cloneable `SharedSender`. It isolates sender
queue, pool lease, per-stream observer, and active-cancellation wake readiness
from HTTP/2 payload work:

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_shared_consecutive_x1_empty
```

`bench-http2-flow` exercises the same ten 1-MiB responses with an 8-KiB stream
window and the RFC default 65,535-byte connection window. The server's batch
scheduler advances streams round-robin, waits for WINDOW_UPDATE only when every
unfinished stream is blocked, and the client continuously returns credit while
streaming DATA. Its same-shape Hyper harness is run with:

```sh
taskset -c 0 tools/bench_hyper_http2_flow.sh \
  --warmup=5 --iterations=20
```

Pass `--priority` to opt into RFC 9218 for an internal mixed-urgency workload.
The default remains round-robin so the Hyper comparison retains identical
scheduling semantics:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --warmup=2 --iterations=5
```

Pass `--adaptive` to enable Hyper-style receive-window growth on both peers.
Like Hyper, this overrides the fixed window arguments with the RFC default
65,535-byte starting point, samples DATA with dedicated PING round trips, and
caps the learned target at 16 MiB by default:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --adaptive --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=2 --iterations=5
```

`run-http3-handshake` is the protected-loopback counterpart to the public
HTTP/3 fetcher: it starts a local QUIC/H3 server, performs a full client
handshake, exchanges one POST/200 response, and exits without relying on
external network access.

`bench-http3-handshake-transfer` uses the same zio-backed `std.Io` path for
real-handshake upload and download. `--endpoint-datagram-size=N` controls the
physical UDP receive capacity and `--receive-batch-datagrams=N` selects a
bounded 1-through-16 receive batch. Keep the endpoint value identical when
using those options for a batch-policy A/B. The integrated HTTP/3 default is
4,096 bytes; standalone QUIC endpoints retain their 65,535-byte default.

`bench-http3-quic-go --socket-traffic` provides a no-privilege alternative to
the separate `--capture` evidence mode. It disables GSO on both implementations
and reports complete-run userspace UDP datagram and payload-byte counters for
both endpoints. The strict checker verifies workload identity, endpoint roles,
counter conservation, one record per endpoint, netz transport loss totals, and
quic-go qlog packet-drop categories. These counters do not replace kernel PCAP
evidence and their throughput samples are deliberately marked
`timing_usable=false`.
Add `--netz-max-pacing-rate-bytes-per-second=N` to apply an explicit positive
rate ceiling to the netz endpoint in each role pair. The paired quic-go process
does not apply that ceiling, but records it as experiment metadata; zero in an
output record means the option was not set. The comparison summary includes
both endpoint executable SHA-256 values for fixed-binary repetitions.

The QUIC examples are preconfigured-key transport smoke tests that bypass TLS
so individual 1-RTT features are easy to inspect:

- `run-quic-echo` sends STREAM data from a local client to server and echoes it
  back on the same bidirectional stream.
- `run-quic-handshake-echo` performs the same STREAM exchange after a real
  local QUIC/TLS handshake, covering raw handshake-backed transport without
  HTTP/3 framing.
- `bench-quic-handshake-stream` performs fresh real handshakes and measures raw
  one- or multi-stream upload throughput. Its defaults match the 5 × 64 MiB
  shape of `~/Work/quicz/examples/quic_bench_hs.zig`; `--streams=4`,
  `--iterations`, `--transfer-bytes`, and `--batch-packets` tune the comparison.
  `--mode=lifecycle-churn` repeatedly closes FIN/echo and RESET_STREAM batches
  under a small renewable stream limit. Add either `--loss-pct=N` (and optional
  `--rtt-us=N`) or `--reorder-every=N` to fault both directions after the real
  handshake; the benchmark verifies exact terminal counts, stream IDs,
  checksum, deterministic injection counts, and both endpoint statistics.
- `bench-quic-handshake-external` measures fresh certificate-verified QUIC v1
  connects for all four netz/quic-go client/server role pairs. It pins the two
  processes to distinct CPUs and verifies a round-specific echo plus peer close
  outside each timed connect sample.
- `bench-quic-persistent-external` covers the complementary long-lived shapes
  against the audited quic-go v0.59 fixture. `--mode=echo` measures one
  outstanding 1-KiB STREAM round trip after warmup; `--mode=aggregate` uses a
  synchronized GO barrier for four parallel independent UDP connections and
  both sender roles. A strict dual-log verifier recomputes every checksum and
  requires the complete DONE/DONE_ACK exchange from all connections.
  Aggregate mode also accepts `--server-topology=shared` for netz/netz client-
  and server-originated transfers in which all server connections share one UDP
  socket and one CID-routing/timer owner; the default remains one socket per
  connection.
- `run-quic-datagram-echo` exercises RFC 9221 DATAGRAM send, receive queueing,
  and echo.
- `interop-quic-handshake-fault` covers QUIC v1/v2, both netz/quic-go endpoint
  pairings, and both handshake directions under one deterministic
  first-datagram loss or one-bit corruption. All 16 cases still require
  certificate/ALPN/version, exact two-stream echo, peer close, and exact proxy
  counters.
- `interop-quic-quic-go-churn` exercises 32/64 raw QUIC unidirectional streams
  in both client/server sender roles and both netz/quic-go connection pairings.
  Half RESET after an acknowledged 256-byte prefix and half finish at 16 KiB;
  a user-space relay forces loss or pair reordering in both terminal phases.
- `bench-http3-quic-go-multistream` exercises true concurrent HTTP/3 request
  streams against quic-go with 4- and 16-stream upload/download samples in both
  connection-role pairings. Every stream carries an index-distinct payload,
  and a strict dual-log verifier requires exact per-stream and aggregate proof
  from both endpoints before accepting a sample.
- `bench-webtransport-datagram` keeps its lightweight ping-pong baseline by
  default; `--payload-bytes=1..1024` selects an exact payload size while
  preserving the historical default when omitted. `--burst`,
  `--iterations=N`, and `--send-timeout-ms=N` switch to a real QUIC/TLS +
  HTTP/3 WebTransport session and measure deadline-bounded DATAGRAM sends under
  congestion backpressure. `--batch-size=N` (up to 64) groups the burst into
  ordered socket batches and reports both logical DATAGRAM count and API call
  count. `--max-in-flight=N` keeps at most `N` successfully submitted but not
  yet consumed DATAGRAMs outstanding, allowing long large-payload runs without
  measuring avoidable loopback UDP queue loss. It is burst-only; omitting it
  retains the original unbounded sender (`max_in_flight=0` in the result).
  `--receive-into` selects the authenticated session's caller-buffer receive
  API and reports `receive_mode=caller-buffer`; the default owning path remains
  available as `receive_mode=owning` for allocation/performance comparisons.
  Caller-buffer mode receives batches matching the send batch, capped by the
  in-flight window, and reports the effective `receive_batch_size`.
- `bench-webtransport-stream` measures real-handshake associated STREAM
  transfer, fair cross-stream batching, cancellation, loss, and reordering.
  `--send-timeout-ms=N` supplies one absolute budget shared by every payload
  write and FIN in the measured transfer. Its bounded internal churn shape
  configures both peers for and accepts up to 256 streams;
  `--send-all --stream-slices=N` sends one logical stream from `N` borrowed
  slices without a caller-side join, allowing direct contiguous/vectored A/B
  runs while retaining identical bytes and checksum;
  `NETZ_WEBTRANSPORT_CHURN_STREAMS`,
  `NETZ_WEBTRANSPORT_CHURN_BYTES`, and `NETZ_WEBTRANSPORT_CHURN_RUNS` tune the
  repeatability gate.
- `interop-webtransport-wtransport-churn` runs 32/64 concurrent associated
  unidirectional streams in both netz/wtransport sender roles, resets every
  second stream after an acknowledged 256-byte prefix, and verifies the
  remaining FIN streams under deterministic loss and reordering. A user-space
  UDP relay faults wtransport's outbound path without requiring privileges.
- `run-quic-close` sends an application close frame and verifies that the peer
  enters draining with the expected error code and reason phrase.

`run-http3-fetch` is the public-network example. By default it fetches
`https://robotics.bytedance.com/`; `--verify` enables system trust-store
certificate validation, `--discover` performs best-effort Alt-Svc discovery
using an HTTP/3 HEAD probe before issuing the final request, and
`--alt-svc='h3=":443"; ma=2592000'` lets interop tests provide a known
HTTP/3 alternative service explicitly.
The same verified path accepts cross-signed roots when the system bundle holds
the self-signed certificate for the identical Subject and public key. For an
independent public endpoint, run:

```sh
zig build run-http3-fetch -Doptimize=ReleaseFast -- \
  '--alt-svc=h3=":443"; ma=86400' --verify --expect-status=200 \
  --min-body-bytes=100000 https://cloudflare-quic.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- \
  '--alt-svc=h3=":8443"; ma=86400' --verify --expect-status=200 \
  --min-body-bytes=400 https://quic.tech/
```

`zig build interop-http3-public -Doptimize=ReleaseFast` runs the maintained
ByteDance, Cloudflare, quiche, and Meta cases together. It is an optional
network gate rather than part of `zig build test`. Set
`NETZ_HTTP3_PUBLIC_TIMEOUT_SECONDS` to change the per-origin outer timeout.

`run-webtransport-handshake-stream` performs a real QUIC/TLS + HTTP/3
WebTransport CONNECT, then exercises a client-opened bidirectional echo,
client-to-server unidirectional data, and a server-to-client unidirectional
stream. It uses the modern `0x41 + Session ID` bidirectional association prefix
implemented by wtransport.

## I/O backend note

Zig 0.16 and netz provide these related layers:

- `std.Io.Uring` / `std.Io.Evented`, a standard backend whose networking
  vtable still marks `listen`, `accept`, `connect`, `read`, and `write` as
  unavailable in Zig 0.16.
- zio, which supplies a complete `std.Io` implementation and uses io_uring
  with automatic epoll fallback on Linux (plus portable backends elsewhere).
- No protocol API exposes the lower-level `std.os.linux.IoUring`; doing so
  would bypass `std.Io` cancellation, deadline, and ownership semantics.

Because netz runtimes take a `std.Io` value, protocol code stays backend-neutral.
`netz.runtime.Backend.init()` owns zio and exposes only its `std.Io` value, so
backend or platform details do not spread through protocol implementations.
Initialization fails explicitly instead of silently switching to a thread-pool
I/O model. Runnable examples also use `std.Io.async` for in-process concurrency;
only benchmark fixtures select specialized backends for controlled measurement.

HTTP/1-2, WS/WSS, MQTT TCP/TLS/WS/WSS, and cleartext HTTP proxy endpoints expose
the shared `AddressConnectPolicy`. `.ordered` remains the compatibility default
and attempts resolver results sequentially. Opt-in `.happy_eyeballs` stable-
interleaves IPv6/IPv4 results, starts the first immediately, defaults to a
250-ms stagger and two in-flight attempts, advances immediately after a path
failure, and keeps one absolute caller/connect deadline over the complete race.
External cancellation waits for every connect task to settle, and every
successful unselected socket is closed before return. Literal IPs bypass both
resolution and racing.
Owning HTTP/3 URI clients and the ordinary HTTP/3 pool expose the same opt-in
policy through `HandshakeClientOptions.address_connect_policy`. Each QUIC
attempt owns an independent endpoint and connection IDs; dual-family callers
provide the opposite-family bind through `alternate_local_address`. WebSocket
H3 and WebTransport URI clients inherit this behavior. Only the first attempt
may resume or send 0-RTT, so a later winner reports rejection and the safe
request is replayed once. The dispatcher-shared HTTP/3 pool uses its primary
and `migration_local_address` sockets under one receive owner; the unified HTTP
pool exposes the same secondary bind in `PoolHttp3Options`. CID-routed inboxes
isolate concurrent handshakes, the winning route is promoted on either socket,
and loser inboxes are closed before their workers are joined.
For blackholed UDP routes, `HandshakeClientOptions.address_attempt_timeout`
can bound each QUIC/TLS address attempt while the total
`connect_timeout` or caller deadline remains unchanged. This applies to owning
HTTP/3/WebSocket/WebTransport clients and ordinary/shared HTTP/3 pools. If a
0-RTT packet may have reached a timed-out address, fallback proceeds at 1-RTT
and reports early data rejected so the safe request is replayed exactly once.
