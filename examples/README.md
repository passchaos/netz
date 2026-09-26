# netz examples

These examples mirror the shape of the `~/Work/hyper` and
`~/Work/tungstenite-rs` examples: start a small local server, connect a client,
print the exchange, then exit. They are self-contained and do not require
external network access.

Run all example compile checks:

```sh
zig build examples
```

Run individual examples:

```sh
zig build run-http1-hello
zig build run-http2-h2c
zig build run-http3-handshake
zig build run-http3-fetch
zig build run-quic-echo
zig build run-quic-handshake-echo
zig build run-quic-datagram-echo
zig build run-quic-close
zig build run-websocket-echo
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast -- \
  --write-strategy=auto
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast -- \
  --large-body --write-strategy=vectored
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=fixed --warmup=20 --iterations=200
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=visitor --frame=stream --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- \
  --mode=visitor --frame=stream_gap --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast -- \
  --stream-fragments=4 --warmup=200 --iterations=10000
taskset -c 0 zig build bench-quic-endpoint-cid-sync -Doptimize=ReleaseFast -- \
  --iterations=2000000
taskset -c 0 zig build bench-quic-connection-router -Doptimize=ReleaseFast -- \
  --iterations=10000000
taskset -c 0 zig build bench-quic-endpoint-timers -Doptimize=ReleaseFast -- \
  --iterations=2000000
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
accept_protocol_versions 4,5
enable_proxy_protocol 1
allow_anonymous false
max_qos 1
max_keepalive 60
max_topic_alias 10
max_topic_alias_broker 10
max_connections 16

listener 8080 127.0.0.1
protocol websockets
websockets_origin https://console.example
listener_auto_id_prefix tenant-
certfile server-chain.pem
keyfile server-key.pem
cafile client-ca.pem
crlfile client-revocations.pem
require_certificate true
use_identity_as_username true
mount_point tenant/
allow_anonymous true
max_connections 16
```

The accepted directives are exactly `listener`, `protocol`, `certfile`,
`keyfile`, `cafile`, `capath`, `crlfile`, `require_certificate`,
`use_identity_as_username`, `use_subject_as_username`, `mount_point`,
`allow_anonymous`, `auto_id_prefix`, `listener_auto_id_prefix`,
`accept_protocol_versions`,
`websockets_origin`,
`enable_proxy_protocol`,
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
`password_file`, `acl_file`, `persistence`, `persistence_location`, `persistence_file`,
`autosave_interval`, and `autosave_on_changes`. Unknown directives, duplicates,
bad values, and listener options before the first listener are errors. This
bounded example interprets each listener's `max_connections` as its finite
accept count. Global `max_packet_size` defaults to Mosquitto's 2,000,000-byte
full MQTT Control Packet limit, applies to TCP/TLS/WS/WSS, and is advertised to
MQTT 5 clients. Global `message_size_limit` independently bounds PUBLISH and
Will payload bytes; zero keeps the Mosquitto unlimited default. Oversized
payloads are rejected while representable QoS flows complete. Each listener
accepts MQTT 3.1.1 and MQTT 5 by default.
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
handshakes. Version 2 cannot be combined with local TLS termination or
certificate-derived usernames; proxy-asserted TLS identity requires the
lower-level `proxy_v2_require_tls` and certificate flags. Global
`websockets_headers_size` defaults to 4096 bytes and
accepts 1..65,535, bounding the complete HTTP Upgrade head for every WS/WSS
listener before MQTT parsing. The legacy `packet_buffer_size` alias is not
accepted because netz's raw MQTT framing uses an independent exact packet
limit. Global
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
Argon2 memory amplification. A listener with `allow_anonymous false` requires a
password file; an anonymous-capable listener accepts absent credentials but
still rejects invalid credentials when a username is supplied. `certfile` and
`keyfile` are listener-local and must occur together. Their presence upgrades
`protocol mqtt` to native MQTT/TLS and `protocol websockets` to WSS. Before any
port is opened, every identity is loaded from a leaf-first PEM certificate
chain and an unencrypted P-256/P-384 SEC1 or PKCS#8, or RFC 8410 Ed25519
private key, bounded and strictly
decoded, and checked for a matching leaf key. `include_dir` is supported by the
file-loading API and only in the main file. It expands top-level regular `.conf`
files in Mosquitto's case-sensitive alphabetical order (for example, `A.conf`,
`a.conf`, `B.conf`, `b.conf`). Multiple directories retain declaration order;
nesting, special `.conf` files, oversized files/sets, and excessive directory/
file counts fail closed. The in-memory `parse` API deliberately has no
filesystem expansion. RSA, other curves, encrypted keys, reload, plugin,
bridge, and full Mosquitto configuration remain outside this subset and fail
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
`crlfile` PEM lists must be signed by a unique configured CA; P-256 ECDSA or
1024-4096-bit RSA PKCS#1 v1.5 signatures with SHA-256, cRLSign,
thisUpdate/nextUpdate, extensions and leaf serials are validated before bind.
Revoked clients are rejected during TLS. Ed25519-signed, indirect, delta,
expired, future, malformed and unmatched CRLs fail closed. When
`use_identity_as_username true` is also set, the verified leaf's unique Subject
CN replaces any wire username and the wire password is ignored before password,
ACL, Session, Client ID, or Will policy. The CN is converted from supported
X.509 DirectoryString encodings, must satisfy MQTT UTF-8/u16 bounds, and is
deeply owned; missing, duplicate, legacy-encoded, malformed, or NUL-containing
CN values are Not Authorized. This mode is a valid authentication source for
`allow_anonymous false` and does not use `password_file` on that listener. A
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
before listeners are bound.
When persistence is enabled, `autosave_on_changes true` treats
`autosave_interval` as a durable-change threshold; otherwise it is a periodic
seconds interval. Run the end-to-end gate with
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
  default; `--burst --iterations=N --send-timeout-ms=N` switches to a real
  QUIC/TLS + HTTP/3 WebTransport session and measures deadline-bounded
  DATAGRAM sends under congestion backpressure. `--batch-size=N` (up to 64)
  groups the burst into ordered socket batches and reports both logical
  DATAGRAM count and API call count.
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
