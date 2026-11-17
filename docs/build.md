# Build, test, and release gates

This is the detailed build and verification guide referenced from
[README.md](../README.md). Architecture and performance rules remain in
[architecture.md](architecture.md); protocol coverage is inventoried in
[coverage.md](coverage.md).

```sh
zig build test
zig build test-compile -Dtarget=x86_64-windows-gnu
# Linux and Windows portable targets pass on ubuntu-latest; macOS targets
# compile on the portable-macos job with the host SDK. Non-macOS hosts must pass
# -Dmacos-sdk=<root> for the vail Security/CoreFoundation framework links.
# Build a deterministic source archive containing pinned harnessz, vail,
# vort, pbz, and zio.
zig build release-source
# Extract the archive in isolation and compile its public-package test.
zig build verify-release-source
# Report stale or unresolved source hashes recorded under docs/evidence.
# Add --strict to fail on any stale hash or unresolved path. CI uses
# --max-unresolved=24 so only known fixture-relative names stay unresolved.
zig build verify-evidence
```

Runnable examples are under `examples/` and are wired into the build:

```sh
zig build examples
zig build run-http1-hello
zig build run-http2-h2c
zig build run-http3-handshake
zig build run-webtransport-handshake-stream
zig build bench-webtransport-stream -Doptimize=ReleaseFast
# Isolate 64-stream steady batch selection/frame staging without UDP I/O.
zig build bench-webtransport-stream-batch -Doptimize=ReleaseFast
# Bidirectional wtransport interop for CONNECT admission metadata, DATAGRAM,
# bidi/uni streams, mapped RESET_STREAM/STOP_SENDING codes, post-cancellation
# reuse, Session drain, and connection-level close.
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast
# Run the browser-facing protocol against real Chromium and Firefox network
# stacks. Each gate verifies the launched browser version, launcher and process
# image SHA-256 across both phases, and page User-Agent; Firefox also verifies
# its CONNECT User-Agent plus exact RESET_STREAM code 71 and post-reset Session
# reuse. Firefox STOP_SENDING remains a separately documented browser gap.
# Override CHROME/FIREFOX when it is not on PATH.
zig build interop-webtransport-chrome -Doptimize=ReleaseFast
FIREFOX=/path/to/firefox zig build interop-webtransport-firefox -Doptimize=ReleaseFast
# Requires h2spec 2.6.0 on PATH, or H2SPEC=/absolute/path/to/h2spec. The gate
# rejects other reported versions, always enables strict mode, and rejects
# empty, skipped, or failed runs. Supplying H2SPEC_SOURCE_ROOT and
# H2SPEC_GO_ARCHIVE additionally verifies the locked upstream commit, official
# Go 1.22.2 archive, injected version, clean checkout, and exact binary hash.
zig build interop-http2-h2spec -Doptimize=ReleaseFast
# Also run the same strict suite over TLS 1.3 with mandatory h2 ALPN.
zig build interop-http2-h2spec -Doptimize=ReleaseFast -- --tls
# Or force the HTTP/2 TLS 1.2 profile while retaining mandatory h2 ALPN.
zig build interop-http2-h2spec -Doptimize=ReleaseFast -- --tls12
# Build the locked local Hyper reference offline, then verify chunked bodies,
# negotiated trailers, and Expect/100-continue handshakes in both directions.
# The netz client also proves 103-before-100 handling and a bodyless 417 early
# final response that makes the incomplete HTTP/1 exchange non-reusable.
zig build interop-http1-hyper -Doptimize=ReleaseFast
# Both netz HTTP/1 endpoints obtain std.Io from zio; the gate asserts
# zio-std-io versus the audited Hyper fixture's hyper-tokio runtime identity.
# Build the locked local Hyper reference offline, then verify POST headers,
# multi-frame bodies/trailers, body-bearing cloneable shared senders with
# distinct absolute deadlines plus terminal request trailers, three 64-KiB
# callback-streamed SharedSender responses with final-head/trailer validation,
# active Shared producer cancellation while the sole reader is blocked, and
# bidirectional cancellation of a 128-KiB response at an 8-KiB stream window
# while a concurrent sibling completes on the same connection.
zig build interop-http2-hyper-client -Doptimize=ReleaseFast
# Negotiate `http/1.1` and `h2` with independent Hyper/rustls servers through
# the same high-level authority pool, then prove one miss plus one reuse on each
# selected transport.
zig build interop-http-unified-hyper -Doptimize=ReleaseFast
# Exercise netz HTTP/1.1 and HTTP/2 servers with installed curl/libcurl/nghttp,
# then reverse the HTTP/2 role against nghttpd: cleartext plus certificate-
# verified TLS, H1 chunked and H2 multiplexed bodies/trailers, ALPN, and
# persistent same-connection reuse in every applicable matrix arm.
zig build interop-http-external-clients -Doptimize=ReleaseFast
# Compare repeated Set-Cookie ingestion, default/explicit Path matching,
# Cookie ordering, and both directions of Netscape cookies.txt exchange with
# the installed curl/libcurl cookie engine.
zig build interop-http-cookie-curl -Doptimize=ReleaseFast
# All netz HTTP/2 interop endpoints obtain `std.Io` from the zio-backed runtime;
# the Hyper and direct h2 peers identify their Tokio execution backend in the
# success records, and the h2spec server schedules accepted sockets with zio.
# Build the repository-owned fixture against pinned quic-go v0.59.0 and verify
# HTTP/3 POST bodies/trailers,
# ordered 103/102 responses, and streamed responses/trailers over
# certificate-checked QUIC v1 and v2 in both directions,
# including H3_REQUEST_CANCELLED followed by same-connection reuse in both
# directions. The reverse case closes a partially-read quic-go response body
# and requires netz to observe the exact cancellation before serving stream 4.
zig build interop-http3-quic-go -Doptimize=ReleaseFast
# Run the corresponding bidirectional RFC 9220 WebSocket gate, including
# subprotocol/permessage-deflate negotiation, Ping/Pong, Close, and QUIC v1/v2.
zig build interop-websocket-h3-quic-go -Doptimize=ReleaseFast
# The benchmark defaults to QUIC v1; select v2 with the environment variable.
NETZ_WEBSOCKET_H3_INTEROP_VERSION=2 \
  zig build bench-websocket-h3-quic-go -Doptimize=ReleaseFast -- \
  --warmup=20 --iterations=1000 --payload-bytes=4096
# Use Hyper's HTTP/2 Extended CONNECT server to validate netz RFC 8441 frame
# masking, text exchange, Ping/Pong, and the WebSocket Close handshake.
# The netz endpoint obtains std.Io from zio; the gate asserts zio-std-io
# against the audited Hyper fixture's hyper-tokio execution backend.
zig build interop-websocket-hyper-h2 -Doptimize=ReleaseFast
# Build the quic-go fixtures from the repository-owned, checksum-locked module
# and run
# certificate-verified, ALPN-checked two-stream echoes in both directions,
# including a quic-go server that forces a Retry/address-validation round trip,
# plus two netz-initiated 1-RTT key updates with ACK gating and peer decryption,
# followed by quic-go RESET_STREAM, STOP_SENDING, and rolling flow-control
# and stream-limit renewal probes, client/server unidirectional streams,
# four-datagram Initial/application loss recovery, and exact application-close
# codes/reasons in both directions. A separate path gate issues additional
# Connection IDs, rejects a pre-probe switch, validates PATH_CHALLENGE /
# PATH_RESPONSE, migrates from 127.0.0.1 through 127.0.0.2 to 127.0.0.3
# with distinct source ports, and completes a stream after each switch. A
# loss variant drops the first PATH_RESPONSE on both candidate paths and
# requires timer-driven PATH_CHALLENGE retries before either switch. A separate
# same-IP source-port rebinding drops four datagrams, recovers by PTO,
# and verifies that NAT rebinding does not start active path validation.
zig build interop-quic-quic-go -Doptimize=ReleaseFast
# The shared netz QUIC peer client/server obtain std.Io from zio. The quic-go
# and s2n-quic gates assert zio-std-io against their netpoll/Tokio runtimes.
# The s2n matrix also holds each netz-emitted RESET_STREAM and STOP_SENDING
# once, sends a sibling STREAM first, then verifies exact cancellation codes
# and sibling completion in both endpoint-role directions. It additionally
# enables s2n-quic's native RFC 9221 provider and exchanges three DATAGRAMs
# each way in both endpoint-role directions. The gate verifies two distinct
# small payloads without assuming delivery order, an exact 1163-byte netz
# path boundary, s2n's exact 62-byte payload under a 64-byte advertised frame
# limit, local oversized-send rejection, a reliable stream 4 echo, and final
# application close. Netz remains zio-backed and consumes only std.Io. It also
# runs a bounded 32-stream mixed lifecycle in both directions: every stream
# delivers a verified 256-byte prefix, then alternating streams finish 16 KiB
# or reset with an index-specific code before the final application close.
# Separate loss/reorder variants make netz the sender in both endpoint roles
# and inject exactly one outbound fault in the RESET phase and FIN phase.
zig build interop-quic-s2n -Doptimize=ReleaseFast
# A second independent RFC 9221 gate uses Quinn's native DATAGRAM API in both
# endpoint-role directions. It verifies unordered small payloads, Quinn's
# conservative 55-byte send boundary under netz's 64-byte frame limit, netz's
# exact 1171-byte path/header boundary against Quinn's 8-byte CID, local
# oversized rejection, reliable stream 4, close 57/58, ALPN/SNI, and explicit
# zio-std-io versus quinn-tokio-rustls runtime identities. Deterministic loss
# and true pair-reordering variants make netz the outbound sender in each role:
# Quinn proves the dropped first DATAGRAM is never retransmitted, observes the
# reordered pair, and completes the reliable sibling stream and close.
zig build interop-quic-quinn -Doptimize=ReleaseFast
# Defaults to the digest-locked Autobahn Testsuite 25.10.1 Docker image. Hosts
# without a container runtime can set absolute AUTOBAHN_WSTEST,
# AUTOBAHN_TESTSUITE_PACKAGE, and AUTOBAHN_PYPY_ARCHIVE paths; local mode
# verifies the official wheel/archive and extracted interpreter SHA-256 values,
# byte-compares all installed suite files with the wheel, and checks the exact
# PyPy/Autobahn versions plus complete dependency freeze before execution.
# Optional trailing arguments select individual case IDs; with none, the report
# verifier requires the exact versioned set of all 517 cases from the sole
# `netz` agent and the locked per-case status baseline, rejecting
# count-preserving substitutions or accepted-but-regressed statuses. Pass
# --tls before case IDs to run the same gate over native TLS 1.3 WSS. The
# long-lived netz endpoint uses 64 reusable zio-backed std.Io workers.
zig build interop-websocket-autobahn -Doptimize=ReleaseFast
zig build interop-websocket-autobahn -Doptimize=ReleaseFast -- --tls
# Without Docker, exercise the same adapter over real cleartext/TLS sockets,
# including concurrent echoes, protocol-error isolation, and worker reuse.
zig build interop-websocket-autobahn-smoke -Doptimize=ReleaseFast
# Exercise MQTT mTLS against OpenSSL and MQTT 3.1/3.1.1/5 listener mounts,
# WS/WSS plus PROXY v1/v2, and Origin policy with Mosquitto 5cd25465 helpers.
# Every netz endpoint receives std.Io from zio and the runners assert its
# zio-std-io runtime identity.
zig build interop-mqtt-mtls-openssl -Doptimize=ReleaseFast
zig build interop-mqtt-listener-mount-mosquitto -Doptimize=ReleaseFast
# Build pinned Mosquitto 5cd25465 CLI clients and run MQTT 3.1/3.1.1/5 against
# netz, checking QoS 0/1/2 fanout, retained replay, and MQTT 5
# Response Topic plus Correlation Data through libmosquitto's decoder.
zig build interop-mqtt-mosquitto-clients -Doptimize=ReleaseFast
# Run netz's synchronous QoS 1/2 completion against the pinned Mosquitto
# broker, reversing completion order while retaining self-delivered messages.
zig build interop-mqtt-publish-mosquitto -Doptimize=ReleaseFast
# Build locked rumqttc 0.25.1 offline and independently exercise the same
# MQTT 3.1.1/5 QoS completion/single-delivery, retained, persistent Session
# recovery with offline QoS 1 delivery, and MQTT 5 property boundaries.
zig build interop-mqtt-rumqttc -Doptimize=ReleaseFast
# Use new rumqttc processes on both sides of a broker SIGKILL/restart and
# require MQTT 3.1.1/5 queued and unacknowledged QoS 1/2 to recover from the
# broker's fsynced commit log without another SUBSCRIBE, including stable
# Packet Identifiers, DUP retransmission, and durable ACK handshake removal.
zig build interop-mqtt-rumqttc-crash -Doptimize=ReleaseFast
# Exercise strict config parsing, shared TCP/Unix/TLS/WebSocket/WSS broker state,
# policy, global/per-listener Mosquitto password hashes, authentication
# rejection, isolated ACL read/write/deny/pattern behavior, OpenSSL-verified
# hard broker-owned heap limits with live SIGHUP updates,
# optional/required TLS client authentication, acceptable CA names and
# certificate CN/full-Subject username/Client-ID mapping, P-256/P-384/RSA/Ed25519
# signed CRL revocation, strict
# key/CA/EKU/identity/CRL rejection, snapshot restore, and a two-broker inbound
# bridge prefix/reconnect plus QoS 1/2 scenario through the production example.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast

# Ordered include_dir files, policy reload and rollback with existing clients.
zig build interop-mqtt-broker-includes -Doptimize=ReleaseFast -- \
  --mosquitto-test-root="$HOME/Work/mosquitto/test"
# Prove that a one-byte memory_limit fails before listen, then lower a live
# broker's hard allocation ceiling without interrupting an admitted client.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-memory-limit --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Source-lock Mosquitto's global/listener anonymous-admission matrix across
# MQTT 3.1.1 and MQTT 5, including explicit per-listener precedence.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-listener-anonymous --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Source-lock Mosquitto's allow-anonymous/password-file/username Cartesian
# matrix across MQTT 3.1, MQTT 3.1.1, and MQTT 5 (24 real CONNECTs).
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-username-or-anonymous --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Source-lock authentication-before-takeover ordering across MQTT 3.1.1/5,
# retaining the legitimate connection and suppressing its Will.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-authentication-takeover --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Reload a configured password file to an empty zero-user generation, revoke
# the live named client without its Will, and preserve anonymous policy.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-empty-password-reload --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Source-lock Mosquitto's empty/comment-only ACL CVE regression across global
# and per-listener policy under MQTT 3.1.1/5.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-empty-acl --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Prove strict hostname rejection, explicit bridge_insecure compatibility, and
# retained CA-chain rejection over TLS 1.2/1.3, leaving the TLS 1.2 OpenSSL
# group preference at its default to exercise X25519 selection.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-bridge-insecure --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Exercise Netz as both TLS 1.2 client and server against OpenSSL peers forced
# to P-384 and P-521, using the explicit tlsv1.2-only config extension.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-bridge-tls12-groups --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Source-lock Mosquitto's `listener 0 PATH` Unix-domain process case, including
# MQTT 3.1.1 admission and normal socket-file cleanup.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-unix-listener --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Source-lock Mosquitto's invalid password/ACL reload processes and verify that
# netz atomically rolls both failures back instead of terminating the broker.
zig build interop-mqtt-broker-config -Doptimize=ReleaseFast -- \
  --only-security-reload --mosquitto-test-root=/nav_env/Work/mosquitto/test
# Build the pinned Mosquitto checkout and bridge two independent broker
# processes through netz across MQTT versions and QoS 0/1/2. QoS 2 covers the
# complete MQTT 3.1.1/5 source-target protocol matrix. Its fault gate also
# kills and restores netz before the first target wire delivery, after a
# dropped target PUBCOMP, and after a dropped source PUBCOMP. It verifies the
# durable replay stage and final journal-clear boundary without duplicate
# target Application Messages, plus source-first fail-closed recovery when
# either broker loses the required persistent Session and propagation of a
# Mosquitto ACL-generated negative PUBREC without target delivery.
zig build interop-mqtt-outbound-bridge-mosquitto -Doptimize=ReleaseFast
zig build interop-mqtt-websocket-mosquitto -Doptimize=ReleaseFast
zig build interop-mqtt-websocket-origin -Doptimize=ReleaseFast
# Drive the browser WebSocket API from Chrome against netz. The gate checks
# Origin rejection/acceptance, subprotocol and permessage-deflate negotiation,
# compressed text, binary data, automatic Pong, and a clean Close handshake.
zig build interop-websocket-chrome -Doptimize=ReleaseFast
zig build interop-websocket-chrome -Doptimize=ReleaseFast -- --tls
zig build run-websocket-echo
zig build run-http3-fetch
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify --head
# Optional diagnostic: performs a preliminary HTTPS HEAD Alt-Svc discovery.
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify --discover
# Independent CDN path with a cross-signed GTS Root R4 chain.
zig build run-http3-fetch -- '--alt-svc=h3=":443"; ma=86400' --verify --expect-status=200 --min-body-bytes=100000 https://cloudflare-quic.com/
# Independent quiche deployment on a non-default HTTP/3 port.
zig build run-http3-fetch -- '--alt-svc=h3=":8443"; ma=86400' --verify --expect-status=200 --min-body-bytes=400 https://quic.tech/
# Run all maintained public HTTP/3 status/body and WebPKI checks.
zig build interop-http3-public -Doptimize=ReleaseFast
```

`run-http3-handshake` is the self-contained local HTTP/3 counterpart to the
public fetch tool: it binds a QUIC/H3 server on loopback, performs a protected
client handshake, exchanges one request/response, and exits.
The HTTP/2 interop step starts a loopback h2c server and runs the external
h2spec server suite. Additional h2spec selectors can be passed after `--`, for
example `-- generic/3.4`. The public HTTP/3 URI client resolves all same-family
DNS answers and retries
transient UDP path failures such as QUIC handshake timeouts on the next
address, which makes CDN-backed origins more robust when one anycast edge is
temporarily dropping UDP/443. Vail's shared TLS trust policy also recognizes a
server-supplied cross-signed form of a system anchor by exact Subject, public-key
algorithm, and public-key bytes. It still validates every presented chain link,
hostname, and the validity of both the terminal certificate and configured
anchor; a same-name certificate with another key is not trusted. The default
system/bundle verifier also enforces leaf digital-signature and serverAuth
usage when those extensions are present, requires every presented intermediate
to be a CA with keyCertSign when constrained, observes pathLen, and rejects
unknown critical extensions. Explicit pins and custom verifiers retain their
caller-defined policy.

Native microbenchmarks are also wired into the build.  Prefer `ReleaseFast`
when collecting performance evidence.  The current local baseline and
comparison gaps are recorded in `docs/benchmark-baseline.md`:

```sh
zig build bench -Doptimize=ReleaseFast
# These six microbenchmarks use the shared harnessz sampler: --iterations is
# the operation count per sample, --samples is the number of timed samples
# (default 10), and --warmup is the number of untimed samples (default 1).
# Reported ns/op is the median sample divided by --iterations, and every
# scenario also prints its sample min/p50/p90/p99/mean/stddev.
zig build bench-http1-parse -Doptimize=ReleaseFast -- \
  --iterations=100000 --samples=10
zig build bench-quic-padding-parse -Doptimize=ReleaseFast
zig build bench-http3-capsule -Doptimize=ReleaseFast
zig build bench-http2-hpack -Doptimize=ReleaseFast
zig build bench-http3-qpack -Doptimize=ReleaseFast
zig build bench-http-content-coding -Doptimize=ReleaseFast
# Optional regression gate: record a baseline once, then compare later runs.
# The JSON store keeps the raw samples plus an environment fingerprint
# (build mode, architecture and CPU count), so unlike hosts fail loudly.
zig build bench-http1-parse -Doptimize=ReleaseFast -- \
  --baseline=benchmarks/baselines/http1-parse.json --update-baseline
zig build bench-http1-parse -Doptimize=ReleaseFast -- \
  --baseline=benchmarks/baselines/http1-parse.json
# --max-regression-ratio=<ratio> (default 1.05) controls the median gate;
# regressions must also be significant under harnessz's robust rank-sum test.
# The same flow for all six sampler-backed benchmarks:
zig build bench-record -Doptimize=ReleaseFast
zig build bench-gate -Doptimize=ReleaseFast
# Pass --warn-only to report regressions without failing on a noisy host:
zig build bench-gate -Doptimize=ReleaseFast -- --warn-only
# Baselines live in benchmarks/baselines/ and carry an environment
# fingerprint, so record and gate on the same host/build mode. Run the gate on
# a quiet host and re-run a flagged scenario before treating it as a
# regression; sustained host-state shifts can move one scenario at a time.
taskset -c 0 zig build bench-http-content-coding -Doptimize=ReleaseFast
# The common owned parser retains up to 16 validated header descriptors during
# its counting pass, avoiding a second parse while preserving exact allocation
# for larger header sets.
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=fixed --warmup=20 --iterations=200
# Run five CPU-pinned ABBA-order samples of the zio-backed pipeline plus fixed
# and chunked bodies against the Cargo.lock-pinned Hyper fixture.
zig build bench-http1-hyper -Doptimize=ReleaseFast
zig build bench-http2-hpack -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
# Shared gRPC persistent ping-pong or per-roundtrip RPC creation on one channel.
taskset -c 0 zig build bench-grpc-shared -Doptimize=ReleaseFast -- \
  --mode=persistent --payload=4096 --warmup=100 --iterations=2000
# Requires the pinned official grpc-cpp TCP benchmark binary; see
# docs/grpc_shared_performance.md for its build and comparison boundaries.
zig build bench-grpc-cpp -Doptimize=ReleaseFast -- --cpu=0 --samples=5
# Isolate SharedSender queue/pool/observer overhead on one h2c connection.
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_shared_consecutive_x1_empty
# Compare netz and Hyper clients against one fixed Hyper server while each
# batch cancels a flow-blocked response, waits for server-observed cancellation,
# completes its concurrent sibling, and proves connection reuse.
zig build bench-http2-cancel-hyper -Doptimize=ReleaseFast
zig build bench-http3-dev -Doptimize=ReleaseFast -- --iterations=1000
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=4
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
zig build bench-http3-capsule -Doptimize=ReleaseFast
zig build bench-http3-qpack -Doptimize=ReleaseFast
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- --netz-only --mode=upload --warmup=1 --iterations=1 --streams=4 --body-bytes=65536
# On Linux with CAP_NET_RAW, retain bounded PCAP evidence for both mixed role
# pairs. Run separately from timing or allocator measurements.
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- --capture --mode=upload --warmup=2 --iterations=5 --streams=4 --body-bytes=4194304
# Without packet-capture privileges, compare complete userspace UDP payload
# counts with GSO disabled. This mode is also separate from timing and memory.
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- --socket-traffic --mode=download --warmup=2 --iterations=5 --streams=4 --body-bytes=4194304
# Apply a 64 MiB/s ceiling only to each netz endpoint. The paired quic-go
# process records the setting as experiment metadata without applying it.
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- --socket-traffic --mode=download --warmup=2 --iterations=5 --streams=4 --body-bytes=4194304 --netz-max-pacing-rate-bytes-per-second=67108864
zig build bench-websocket-frame -Doptimize=ReleaseFast
zig build bench-websocket-receive-buffer -Doptimize=ReleaseFast
zig build bench-websocket-echo -Doptimize=ReleaseFast
# Compare pre-close allocator retention with 128 established WebSocket
# connections while only eight perform the 4 KiB workload. The runner pins
# websocket.zig's audited revision and validates the complete matched records.
zig build bench-websocket-mostly-idle -Doptimize=ReleaseFast
zig build bench-websocket-h2-echo -Doptimize=ReleaseFast
zig build bench-websocket-h3-echo -Doptimize=ReleaseFast -- --warmup=20 --iterations=200
zig build bench-websocket-hyper-h2 -Doptimize=ReleaseFast -- --warmup=20 --iterations=1000 --payload-bytes=4096
zig build bench-websocket-h3-quic-go -Doptimize=ReleaseFast -- --warmup=20 --iterations=1000 --payload-bytes=4096
zig build bench-mqtt-router -Doptimize=ReleaseFast
zig build bench-mqtt-acl -Doptimize=ReleaseFast
zig build bench-mqtt-websocket -Doptimize=ReleaseFast
taskset -c 0 zig build bench-mqtt-tls -Doptimize=ReleaseFast
zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast
# Add verifier-checked 2-ms broker RSS sampling on Linux.
MQTT_STATS=true zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast
# Run five fixed QoS 1 concurrency/fanout/payload shapes as four ABBA samples.
# The driver, broker, and RSS sampler use separate CPUs; the clean audited
# Mosquitto source is rebuilt and all hash-bound artifacts are retained. This
# is a same-client workload comparison, not a TCP equal-wire claim.
zig build compare-mqtt-mosquitto-matrix -Doptimize=ReleaseFast
# Exercise the same artifact, scheduling, completion, and queue-capacity gates
# with interleaved QoS 2 PUBLISH/PUBREC/PUBREL/PUBCOMP transactions.
MQTT_QOS=2 zig build compare-mqtt-mosquitto-matrix -Doptimize=ReleaseFast
# Keep every MQTT 5 connection's Session durable for one hour and bind that
# value into every result, run-order, environment, shape, and completion record.
MQTT_QOS=2 MQTT_SESSION_EXPIRY_SECONDS=3600 \
  zig build compare-mqtt-mosquitto-matrix -Doptimize=ReleaseFast
# Profile broker-owned allocation counts, bytes, size buckets and teardown
# across the same five shapes. This diagnostic deliberately marks timing as
# unusable because its thread-safe counting allocator changes the hot path.
zig build bench-mqtt-broker-allocator-matrix -Doptimize=ReleaseFast
MQTT_QOS=2 zig build bench-mqtt-broker-allocator-matrix -Doptimize=ReleaseFast
MQTT_QOS=2 MQTT_SESSION_EXPIRY_SECONDS=3600 \
  zig build bench-mqtt-broker-allocator-matrix -Doptimize=ReleaseFast
# The latest verified five-shape run and the preceding fixed-binary A/B show
# that out-of-line MQTT WebSocket transport state cuts balanced-32x32 netz
# broker RSS by 6.5% without a supported throughput claim. See the parity doc.
# The current matrix also includes a 512-byte TCP packet read-ahead path; a
# fixed-old-client serial A/B reduced io_uring_enter calls 61.8% and raised
# median broker throughput 55.7%.
# Small Session-route plans use caller-owned scratch; fixed-binary fanout-32
# A/B improved median broker throughput 2.7% while serial remained neutral.
# Online fanout and durable Session PUBLISHes use eight stack-first property
# descriptors and retain one exact overflow slice only for larger sets. The
# earlier verified three-sample allocator matrix cuts allocation counts by
# 25.7-69.5% across all five shapes; timing remains intentionally excluded from
# this instrumentation-heavy diagnostic.
# Subscriber delivery queues prewarm only the common 16-message asynchronous
# window, then reclaim consumed prefix storage and grow geometrically up to the
# configured hard limit during transactional route preflight. A fixed-binary
# three-sample allocator comparison reduced fanout-32 and balanced-32x32 broker
# peak live bytes by 34.1% and 31.2% without adding allocation calls.
# Persistent Sessions maintain a conservative earliest Message Expiry deadline,
# so ordinary no-expiry enqueue/drain operations skip a full queued+inflight
# prune scan. A seven-pair fixed-binary durable QoS 2 run improved median
# throughput 1.4% and reduced median p99 2.4%.
# Fanout to multiple offline persistent Sessions shares one immutable Topic
# Name/payload owner while retaining independent per-Session QoS, properties,
# expiry and Packet Identifiers. The 64-session offline benchmark cuts backing
# allocations 95.5% and live bytes 73.1% versus per-destination cloning.
# A multi-destination QoS 1 TCP PUBLISH that already owns a prefixed packet
# allocation extends that same Publication through online durable and transient
# destinations. Borrowed small packets keep the warmed Session-cache path. In
# the 4-KiB durable shape this cuts peak live bytes 4.6%; a seven-pair fixed-
# binary A/B improved median throughput 1.4% with seven candidate wins.
# Multi-destination durable QoS 2 reserves the same header before pending
# storage only when persistent Sessions exist, then transfers that cached block
# into the shared Publication at PUBREL. Fanout-32 allocations fall 10.6% and
# 4-KiB peak live bytes 3.4%; pure transient and single-target paths are kept
# unchanged after explicit negative controls.
# The broker's single-reader TCP loop also supplies 128 bytes of caller storage
# for ACKs and common small PUBLISH packets. Eligible fragmented packets remain
# in connection-owned read-ahead across timeouts, while oversized packets, TLS,
# and WebSocket keep the resumable owned path. Balanced-32x32 now measures
# 0.143 broker allocations per delivery.
# Network publishers retain a bounded 32-match route-plan scratch in their
# connection slot; larger/local/Will plans keep exact owned storage. This
# lowers balanced-32x32 to 0.109 broker allocations per delivery without
# changing shared-subscription cursor semantics.
# Empty listener namespaces borrow validated inbound Topic Names through an
# explicit lifetime-carrying result, while configured mount points retain
# owned concatenation. This lowers balanced-32x32 again to 0.076 allocations
# per delivery without changing the existing always-owning public helper.
# Shared broker Publications coallocate their ref-counted header with the
# contiguous Topic Name and payload. Empty-property fanout therefore needs one
# allocation per incoming publication rather than separate object and byte
# allocations, lowering balanced-32x32 to 0.042 allocations per delivery.
# Broker reads that exceed the 128-byte caller buffer reserve an aligned
# Publication prefix. The live fanout path adopts and compacts that allocation
# after validation/routing preflight, eliminating the second allocation and
# duplicate live payload buffer. Three-sample results lower 256-byte serial and 4-KiB payload
# shapes from 2.590/2.187 to 1.340/1.125 allocations per publish; the 4-KiB
# shape's cumulative requested bytes fall 36.5%, with paired throughput medians
# remaining within 0.8%.
# Broker PUBLISH counters use saturating atomics instead of taking the global
# routing/Session mutex after every successful fanout write. A five-pair
# balanced-32x32 A/B raised the median from 2,891 to 3,374 publishes/s and
# reduced median p99 from 38.66 to 32.15 ms; host-load ranges still overlap.
# A live queue drain now performs its empty durable-Session probe and live
# dequeue under one state-lock acquisition. Durable selection still precedes
# live delivery and all persistence/socket I/O remains outside the lock; a
# five-pair balanced-32x32 run reduced median p50 by 16.4%.
# Live overlapping-subscription merge now checks only the destination queue
# tail instead of scanning its full backlog. Two fixed-binary five-pair
# balanced-32x32 runs produced 7/10 throughput wins with a +2.2% paired median,
# while paired p50/p99 medians fell 6.3%/6.4%; allocator counts are unchanged.
# Property-free live fanout now skips the per-delivery monotonic-clock read;
# Message Expiry publications still sample immediately before encoding. Two
# more fixed-binary five-pair runs produced 9/10 throughput wins with a +5.3%
# paired median and reduced the paired p99 median by 13.4%.
# Pending inbound QoS 2 transactions coallocate Topic Name, payload, source
# identity, and use a bounded size-class cache after PUBREL. The QoS 2 matrix
# cuts broker allocations 48.5-64.2%; balanced-32x32 falls from 0.109 to 0.043
# allocations per delivery with neutral fixed-binary timing evidence.
# Durable Session transmissions use connection-slot detached scratch while
# keeping persistence and socket I/O outside the state lock. A 64-KiB retention
# ceiling bounds the tradeoff and removes the former encode/parse/re-encode
# round trip; fixed-binary balanced and 4-KiB throughput improve 6.1% and 4.1%.
# Completed Session Topic Name/payload blocks also enter a 64-KiB-per-block,
# 1-MiB-total Store cache shared in implementation with pending QoS 2 storage.
# Balanced and fanout durable QoS 2 fall to 0.011/0.012 allocations/delivery;
# two-shape fixed-binary timing remains neutral.
# Exact-delivery runs use at least 1,024 queue slots and cover the longer phase.
# An explicit override must be at least that derived common bound.
# Router subscription totals are maintained transactionally, so broker route
# planning no longer scans the tombstone-preserving subscription table before
# every PUBLISH. See docs/benchmark-baseline.md for the fixed-binary A/B.
# A synchronous durable writer also records whether its locked selection left
# any unsent Session work, avoiding the second empty lock/drain probe after the
# common final packet; shared fanout writers still drain continuously.
MQTT_MAX_QUEUED_MESSAGES=5000 MESSAGES=5000 \
  zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast
zig build bench-quic-short-packet -Doptimize=ReleaseFast
zig build bench-quic-padding-parse -Doptimize=ReleaseFast
zig build bench-quic-lb -Doptimize=ReleaseFast
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=1 --verbose
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=4 --verbose
taskset -c 0 zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=200 --skip-server-verification
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=lifecycle-churn --iterations=4096 --streams=16 --loss-pct=5
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=lifecycle-churn --iterations=4096 --streams=16 --reorder-every=5
zig build bench-quic-quic-go -Doptimize=ReleaseFast -- --warmup=2 --iterations=5 --bytes-per-stream=4194304 --chunk-bytes=16384 --stream-window=1048576
zig build bench-quic-quic-go -Doptimize=ReleaseFast -- --netz-only --streams=1 --warmup=0 --iterations=1 --bytes-per-stream=262144
zig build test-quic-persistent-bench -Doptimize=ReleaseFast
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- --mode=both --samples=5 --connections=4 --warmup=200 --iterations=5000 --payload-bytes=1024 --bytes-per-stream=1048576
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- --netz-only --mode=aggregate --samples=3 --connections=4 --streams=1 --bytes-per-stream=1048576 --server-topology=independent
# Strict shared-socket scaling matrix: each connection count runs both sender
# directions and emits aggregate-retention/work-normalized summaries.
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- --netz-only --mode=aggregate --samples=3 --connection-counts=1,4,16,64 --streams=1 --bytes-per-stream=1048576 --server-topology=shared
# Capture one perf.data file per sender/count/run from the selected netz role.
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- --netz-only --mode=aggregate --samples=1 --connections=64 --streams=1 --bytes-per-stream=16777216 --server-topology=shared --profile-role=server --profile-dir=/tmp/netz-quic-profile
# Exercise shared-endpoint scheduling with 128 connections on one server UDP
# socket. Shared netz/netz mode accepts up to 256 connections;
# independent/cross-stack comparisons retain their 16-connection bound.
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- --netz-only --mode=aggregate --samples=1 --connections=128 --streams=1 --bytes-per-stream=65536 --payload-bytes=1024 --server-topology=shared --timeout-ms=120000
zig build bench-quic-handshake-external -Doptimize=ReleaseFast -- --netz-only
zig build bench-quic-handshake-quinn -Doptimize=ReleaseFast -- --samples=5 --warmup=10 --iterations=100
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast -- \
  --scenario=datagram --datagram-payload-bytes=256 --warmup=100 --iterations=1000
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream_gap --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=service --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=datagram_copy --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=datagram_borrowed --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- --payload-bytes=1024 --iterations=10000
taskset -c 0 zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- --burst --batch-size=16 --max-in-flight=64 --receive-into --payload-bytes=1024 --iterations=10000
zig build bench-quic-ack-ranges -Doptimize=ReleaseFast
zig build bench-quic-stream-window -Doptimize=ReleaseFast
zig build bench-quic-ticket-keyring -Doptimize=ReleaseFast
zig build bench-quic-stream-ids -Doptimize=ReleaseFast -- --iterations=2000000
zig build bench-quic-endpoint-cid-sync -Doptimize=ReleaseFast -- --iterations=2000000
zig build bench-quic-connection-router -Doptimize=ReleaseFast -- --iterations=10000000
```

The built-in HTTP/1 parse, pipeline, and streaming-body benchmarks obtain
`std.Io` from `netz.runtime.Backend` and report `io backend: zio-std-io`; the
networked benchmarks schedule their local server through `std.Io.async`.
The external Hyper gate verifies complete workload records, runtime identities,
the pinned Hyper revision, fixed binary hashes, and odd ABBA-order samples
before computing medians. Older HTTP/1 measurements remain labeled as Threaded
evidence.
The built-in HTTP/3 development, real-handshake transfer, QPACK, and Capsule
benchmarks obtain `std.Io` from `netz.runtime.Backend` and report
`io backend: zio-std-io`; the network benchmarks schedule their local peer
through `std.Io.async`. Historical Threaded measurements remain labeled as
such in the benchmark baseline.
The built-in HTTP/2 h2c, flow-control, and HPACK benchmarks follow the same
model; h2c and flow-control schedule their local server with `std.Io.async`.
The shared gRPC TCP benchmark uses the same backend and validates both endpoint
message counts, complete payloads and terminal statuses. Persistent-stream and
RPC-creation measurements, allocation telemetry and official grpc-cpp workload
comparisons are described in `docs/grpc_shared_performance.md`.
The built-in WebSocket frame and H1/H2/H3 echo benchmarks also use zio-provided
`std.Io`; echo servers and concurrent H1 clients are scheduled with
`std.Io.async`/`std.Io.Group`, and result records identify both endpoints as
`zio-std-io`. Older WebSocket timing ranges remain historical Threaded data
unless their section explicitly records a zio-era rerun.
The MQTT router, TLS, WebSocket, and external broker driver likewise obtain
`std.Io` from zio. Local TLS/WS servers and concurrent broker subscribers use
`std.Io.async`/`std.Io.Group`; the Mosquitto comparison identifies its netz
client as `zio-std-io`, the netz server as `zio-std-io`, and the reference
server as `mosquitto-event-loop`.
The QUIC ACK-range, connection-router, PADDING, short-packet, receive-window,
and ticket-keyring microbenchmarks obtain their monotonic clock from the same
zio-backed `std.Io` and report that identity.
The endpoint CID synchronization, pending-ready-index, timer scheduler, and
receive-stream-ID benchmarks likewise create their UDP endpoint and monotonic
clock through zio-backed `std.Io`; they perform no peer network traffic.
The raw QUIC DATAGRAM throughput, 1-RTT send/receive, and UDP GSO/GRO
benchmarks also use zio for endpoint I/O and timing. The DATAGRAM receiver is
scheduled through `std.Io.async`, with cooperative `std.Io` sleeps replacing
manual OS-thread yields.
The independent raw DATAGRAM latency comparison uses certificate-verified
netz and Quinn processes, pins the client/server to distinct CPUs, reuses fixed
ReleaseFast binaries, requires an odd sample count, and alternates the netz and
Quinn clients against each fixed server. Its one-outstanding 32-byte ping-pong
times only post-handshake RTTs and verifies every sequence, checksum, control
FIN, negotiated payload limit, and application close. `--window=N` switches to
windowed ping-pong: every round sends N sequence-tagged DATAGRAMs before reading
N echoes, accepts arrival reordering while rejecting duplicates or omissions,
and reports the total logical DATAGRAM count. Window mode enables netz's
automatic GSO send path and `recvmmsg` receive drain while Quinn retains its
native runtime batching:

```sh
zig build bench-quic-datagram-quinn -Doptimize=ReleaseFast -- \
  --samples=5 --warmup=200 --iterations=5000
zig build bench-quic-datagram-quinn -Doptimize=ReleaseFast -- \
  --samples=5 --warmup=50 --iterations=500 --payload-bytes=256 --window=16
```
The WebTransport DATAGRAM round-trip/burst, incremental stream, and steady
stream-batch benchmarks likewise obtain endpoint I/O and monotonic time from
zio. Their local server work runs through `std.Io.async`; no public Threaded
fallback or OS-thread worker is exposed.
The real-handshake QUIC STREAM benchmark uses the same zio-owned `std.Io` in
upload, handshake, echo, churn, fault, and aggregate modes. Aggregate
connections run as a `std.Io.Group` instead of creating OS threads or private
I/O backends. The HTTP/3 real-handshake transfer benchmark also keeps its
client connection pump alive while the short-lived server drains reliable
response recovery, so a lost final ACK is answered after the server's PTO
retransmission instead of turning successful DATA delivery into teardown
timeout.
Multi-stream HTTP/3 transfer runs now enable cross-stream body batching by
default after bounded zio receive batching removed the previous small-queue
regression. Single-stream runs remain sequential; pass
`--disable-body-batch` to retain a multi-stream A/B control.
Integrated HTTP/3 and WebTransport endpoints default their physical UDP
receive capacity to 4,096 bytes, while standalone QUIC endpoints retain the
65,535-byte generic default. Generated QUIC `max_udp_payload_size` transport
parameters are capped to that physical capacity, and an oversized raw override
is rejected rather than advertising a receive size the endpoint cannot honor.
The transfer benchmark exposes `--endpoint-datagram-size=N` and
`--receive-batch-datagrams=N` (1 through 16) for same-binary receive-policy
comparisons; all protocol I/O remains zio-backed `std.Io`.
The persistent QUIC runner accepts `--server-topology=compare --netz-only` to
run an odd, mirrored-order fixed-binary A/B between independent server sockets
and the shared server endpoint, with identical ACK policy and strict per-run
payload/checksum checks. The pinned zio revision implements multi-slot UDP
receive for `std.Io.net.Socket.receiveManyTimeout`, so the shared endpoint's
bounded receive batch is a real backend batch. Protocol code still consumes
only `std.Io`.
The MQTT retained/session/Will schedulers and QUIC-LB routing benchmark also
obtain their monotonic benchmark clock from zio-backed `std.Io`.

The aggregate `bench` step runs the current protocol microbenchmarks:

- HTTP/1 borrowed request-head parsing versus owned full request parsing,
- HTTP/1 persistent 16-request pipeline round trips with caller-storage batch
  parsing, small-response coalescing, and transactional large fixed-body
  vectored batches that borrow payloads, matching Hyper's `hello_world_16`
  benchmark shape,
- HTTP/2 HPACK stateful dynamic-table encode/decode versus stateless helpers,
- HTTP/2 persistent h2c round trips matching Hyper's consecutive empty,
  consecutive 10-byte/100-KiB-request, and parallel x10 empty end-to-end
  shapes,
- HTTP/3 cleartext development request/response round trips,
- HTTP/3 real-handshake paced upload/download throughput with configurable
  body size, direction mode, stream count, round-robin scheduling quantum,
  endpoint and 1-RTT datagram size, receive batch count, paced body chunk size,
  optional cross-stream body packet batching, and iteration count,
- HTTP/3 client request lifecycle tracking through one stream-ID-keyed map,
  with allocation-free standard-method semantics and owned custom methods,
- HTTP/3 server active-request lifecycle tracking through one stream-ID-keyed
  priority map with direct lowest-ID caching for GOAWAY drain,
- HTTP/3 Alt-Svc `h3` / `h3-29` endpoint discovery parsing and origin-relative connection target resolution for real-site upgrade hints,
- HTTP/3 Capsule Protocol parsing/iteration and caller-buffer encoding for
  CONNECT-stream extension payloads,
- HTTP/3 QPACK field-section encoding against a populated dynamic table,
- HTTP/3 QPACK 512-entry reference-set encoding with a large-only
  table-relative bitmap that preserves first-reference ordering and
  one-shot exact-block output reservation, plus scenario/iteration selection
  for isolated profiling,
- HTTP/3 QPACK dynamic-table churn with single-allocation name/value ownership,
  prehashed exact-match index keys, a newest-name exact-match fast path, and
  byte-verified collision fallback,
- HTTP/3 QPACK owned decoding with direct-to-final-block string materialization
  and one-shot compact stack-plan reservation,
- WebSocket masked frame encoding with allocating, caller-buffer, and
  header-only streaming paths, plus retained no-context-takeover
  permessage-deflate throughput and wire-size reporting, Vort-backed bounded
  caller-buffer inflation without a per-connection 64-KiB decoder window;
  stream transports
  share nested `runtime/message/` helpers for bounded-slab receive growth,
  compressed-fragment partitioning, Close-state send admission, and owned
  message finalization,
- WebSocket persistent 4 KiB binary echo over one real upgraded connection,
  using caller-buffer receive and explicit in-place client masking, plus a
  negotiated permessage-deflate mode with logical-throughput reporting,
- QUIC receive-loop timer selection through read-only connection references,
  avoiding full connection-state copies in HTTP/3, WebSocket, and WebTransport,
- QUIC stream credit/stats/pagination queries through read-only connection
  references, avoiding equivalent copies in WebTransport stream scheduling,
- bidirectional cross-process WebTransport comparison against `wtransport`
  for stream upload and one-outstanding DATAGRAM ping-pong, with separate
  client/server CPUs, matching application payloads and requested windows,
  deterministic byte validation, receiver-confirmed completion, warmups, and
  machine-readable output; results are labeled `same-application-shape`
  because the implementations expose different effective DATAGRAM overhead
  and not enough packetization controls for an equal-wire claim,
- MQTT subscription-router combined ordinary/shared count+emit trie matching
  versus a linear filter scan, retained connection PUBLISH encoding scratch,
  and linear-time overlapping-subscription broker flush plans,
- QUIC AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and SM4-GCM short-packet
  sealing with caller-provided storage versus the allocating convenience
  wrapper, plus connection-lifetime pure-Zig AES-GCM and header-key contexts
  that avoid per-packet key/GHASH setup, keep byte-reversed blocks, cached
  powers, and four-way scheduled products in NEON registers during 16-block
  PMULL reduction on capable ARM64 targets, and refresh on key updates,
- bounded QUIC DATAGRAM receive queuing in an O(1) ring under
  `quic/one_rtt/datagram_queue.zig`, with exact one-time capacity reservation,
  direct full-queue reuse for equal-size payloads, a capacity-bounded
  exact-size popped-payload recycle pool, newest-data retention, packet-number
  rollback, and explicit payload ownership,
- QUIC long PADDING run parsing for Initial padding and PMTUD/probe payloads,
- QUIC-LB encrypted server-ID extraction with the draft's three-pass
  load-balancer optimization,
- real-handshake raw QUIC STREAM upload throughput with configurable aggregate
  bytes, one or multiple streams, iteration count, and userspace packet batch
  size, including ACK-driven packet-threshold retransmission and
  allocation-free receive consumption,
- QUIC Linux `UDP_SEGMENT` batching versus same- and multi-destination
  `sendmmsg`, plus `UDP_GRO` coalesced receive versus plain per-datagram
  receive,
- QUIC 1-RTT stateful sequential send versus stateful batched protection with
  reusable scratch, full recovery/flow accounting, and UDP GSO/sendmmsg
  submission, with shared `one_rtt/frame_traits.zig` classification for
  ACK-eliciting/in-flight/retransmission/ECN/path-validation/HANDSHAKE_DONE/ACK
  watermark and STREAM-byte metadata,
- stateless QUIC 1-RTT single-packet sizing and caller-buffer send with direct
  frame encoding into the final packet's plaintext region followed by in-place
  AEAD, while the ownership wrapper performs one exact packet allocation,
- end-to-end QUIC 1-RTT UDP_GRO owning-batch cursor receive versus per-packet receive,
  including decryption, frame parsing, state application, and cleanup, plus a
  single-datagram in-place service path for state-only event loops.
- QUIC ACK range generation with allocating ownership versus caller-provided
  stack storage, plus allocation-free transactional recovery application
  directly from arbitrary wire-range counts,
- bounded QUIC receive-stream compaction across long absolute offsets, including
  retained-memory reduction versus the previous absolute-offset buffer model.

External cross-process comparisons remain separate from the aggregate step.
`bench-quic-quic-go` runs certificate-verified raw QUIC STREAM upload with one
or four streams, both sender roles, separate client/server CPUs, and a fresh
connection per sample. Untimed control and stream preludes precede the timed
payload, while DONE/DONE_ACK require exact byte, FIN, and checksum validation.
Both endpoints also emit complete-connection userspace UDP payload/datagram
counters; the runner joins them per sample and retains teardown observation
deltas. Netz processes use zio behind the `std.Io` protocol boundary. A strict
checker independently recomputes every measured-round checksum and requires
matching sender, receiver-completion, runtime, shape, and throughput records.
The quic-go v0.59.0 peer is built from the repository-owned, checksum-locked
module under `tools/interop/quic_go_module`; `--netz-only` remains available
for an all-netz control without treating it as a cross-library comparison.
Results remain `same-application-shape`: the counters demonstrate that
ACK/pacing, packetization, and application scheduling are not externally
equalized, and kernel/interface capture is still required for an equal-wire
claim. Add `--stats` to record whole-process peak RSS for both implementations,
plus separately labeled netz explicit-allocator and Go runtime-heap telemetry.
`bench-quic-persistent-external` complements that fresh-connection harness with
four certificate-verified netz/quic-go role pairs on two pinned CPUs. Its
`echo` mode measures one outstanding 1-KiB STREAM round trip on one persistent
connection after warmup; `aggregate` starts four independent UDP
endpoint/connections through one GO barrier and transfers 1 MiB per connection
in both sender directions. Every result requires a peer-verified DONE/DONE_ACK,
exact byte count, FIN, independently recomputed checksum, and matching server
completion record. Netz endpoints run on zio while the protocol and harness
only consume `std.Io`; per-result `client_io` and `server_io` fields distinguish
that path from quic-go's netpoll runtime and make legacy backend records fail
strict validation. It deliberately reports `same-application-shape`: endpoint
workers share one process CPU, but this is not a shared-socket QUIC listener or
an equal-wire comparison.
Pass `--server-topology=shared` to benchmark both netz/netz sender directions
with one server UDP socket and the production endpoint dispatcher. That mode
uses a bounded caller-buffer receive drain (32 messages by default, selectable
with `--shared-receive-batch=1..64`) and records the selected batch size in
every strictly verified result. Its default `--server-ack-every=4` is a
negotiated, client-originated ACK_FREQUENCY request: both endpoints advertise
support, but the server does not request sparser client ACKs, preserving the
download control. Independent topology retains ACK/2. An explicit option still
overrides either default; delays below 1 ms exercise the legacy local benchmark
policy without sending ACK_FREQUENCY.
Combine `--netz-only` with `--connection-counts=1,4,...` to run a strictly
increasing shared- or independent-topology scaling matrix. Every count retains
the ordinary exact checksum/completion/socket counters. The summary reports
aggregate throughput relative to the first count, work-normalized elapsed time,
and per-connection throughput without assuming that a fixed two-CPU layout can
scale aggregate throughput linearly.
For repeatable process-local profiling, pass
`--profile-role=client|server --profile-dir=PATH` with `--netz-only`. Each
sender/count/run writes a uniquely named `perf.data` file while preserving the
same strict result verification. Aggregate checksum verification uses the exact
256-byte period of its affine payload generator, so multi-GiB gates remain
constant-time instead of replaying every logical byte in Python.
The Zig sender/receiver verifier uses the same compile-time period table for
exact block comparison, periodic fill, and checksum prefix sums. It still
rejects any corrupted byte, while keeping application verification from
dominating the timed QUIC path; `test-quic-persistent-bench` locks cycle edges,
arbitrary offsets, wrap boundaries, 1-MiB payloads, and corruption detection in
Debug and ReleaseFast.

`bench-http3-quic-go` runs certificate-verified HTTP/3 upload/download in both
client/server role pairings, with a fresh connection and untimed ready request
per sample, matching payloads, flow windows, 1280-byte steady-state MTU, and
1152-byte effective application chunks. Receiver-side byte, EOF, checksum, and
status validation is mandatory. Netz endpoints use zio behind the `std.Io`
protocol boundary. Config, result, server-completion, and memory records name
both endpoint runtimes; strict checkers reject legacy or mismatched backend,
owner, shape, timeout, throughput, and checksum records. `--netz-only` provides
a two-process zio gate when the external fixture is unavailable. Set
`NETZ_HTTP3_INTEROP_VERSION=2` to force QUIC v2; result and memory records carry
`quic_version`, and strict checkers reject a mismatched peer/version run. The
multi-stream aggregate gate exercises
both v1 and v2 by default. Results are labeled `same-application-shape`
because quic-go's GSO/GRO and ACK/packetization policy are not all externally
controllable. Add `--stats` for whole-process peak RSS plus separately scoped
netz explicit-allocator and Go runtime-heap telemetry.
`--netz-max-pacing-rate-bytes-per-second=N` applies the optional production
pacing ceiling to netz endpoints only. Every config and socket-traffic record
includes `netz_max_pacing_rate_bytes_per_second`; zero means the default
unlimited ceiling. This keeps rate-controlled loss experiments explicit and
does not change normal benchmark or library defaults. Socket-traffic comparison
records also bind both endpoint executable SHA-256 values so repeated runs can
prove that their binaries stayed fixed.
An independent `--capture` run uses a Linux `AF_PACKET/SOCK_DGRAM` socket on
`lo` to capture both mixed role pairs by their unique server ports. It requires
`CAP_NET_RAW`, a third CPU, and enough `net.core.rmem_max` for the requested
16-MiB packet receive buffer (Linux reports the doubled effective size). The
capture retains the single loopback `PACKET_HOST` IPv4 copy, disables quic-go
GSO, stores a bounded 128-byte prefix in `zig-out/http3-captures`, and
independently recomputes directional UDP datagrams, UDP payload bytes, IP
bytes, and packet-size-sequence hashes. The runner rejects packet-socket drops,
PCAP/log/hash/workload mismatches, or a changed quic-go binary across role
pairs.
Capture-run timing is explicitly unusable for performance comparison, and
matching totals or size sequences alone are not called equal-wire.
`bench-websocket-hyper-h2` and
`bench-websocket-h3-quic-go` use the same two-CPU, dual-role layout for
persistent RFC 8441/RFC 9220 binary echo, with handshake and warmup outside the
measured interval and byte-exact validation at both peers. They are also
labeled `same-application-shape`. Both runners accept `--stats` for
whole-process RSS plus separately scoped runtime allocation telemetry. Their
strict verifiers require distinct client-result and server-completion records
and independently recompute every measured payload checksum. Both H2 and H3
netz endpoints use zio behind `std.Io`; their config, result, completion, and
memory records bind both endpoint runtimes and the timeout, and their verifiers
reject legacy backend or mismatched timing records. Zio executor bookkeeping
uses the runtime allocator rather than the benchmark counting allocator, so
`netz-explicit` remains scoped to protocol workload allocations. Allocation
counters are not compared across languages.
`bench-webtransport-wtransport` provides the
analogous stream upload and DATAGRAM ping-pong comparison described above. It
also accepts `--stats` for four-process peak RSS and separately scoped netz
explicit-allocation / Rust system-requested-allocation telemetry. Its strict
verifier checks every stream sample or the aggregate DATAGRAM result plus an
independent server-completion record. All netz WebTransport interop, benchmark,
and churn endpoints use zio behind `std.Io`; their records identify
`zio-std-io` versus the peer's `wtransport-quinn-tokio` runtime, and the
verifiers reject missing or mismatched identities.
Add `--traffic` in a separate run to join complete-connection userspace UDP
payload bytes and logical datagram counts from the netz endpoint and Quinn
connection statistics. This records wire-shape differences without presenting
userspace accounting as kernel/interface capture; `--traffic` and `--stats`
are deliberately mutually exclusive.

The build script pins the package to Zig `0.16.0`.
The development package manifest uses sibling `../vail`, `../vort`,
`../pbz`, and `../webpkiz` checkouts and pins `zio` by immutable URL and content hash. CI checks
out exact vail, vort, pbz, and webpkiz commits into that layout. The published path set
includes all example, benchmark, documentation, test, and interop sources
referenced by the build graph. The
`release-source` target emits `zig-out/artifacts/netz-<version>-source.tar.gz`
and its `.sha256` sidecar
with those exact vail, vort, pbz, and webpkiz commits plus the hash-verified zio package
under `deps/`, rewrites the release manifest to local paths, and records
SHA-256 for every packaged file in `RELEASE-MANIFEST.json`. It rejects dirty
source repositories or dependency revision drift. `verify-release-source` checks the
whole-archive checksum, archive shape and internal file hashes, extracts it
outside the workspace layout, builds its
public-package test, then imports the `.tar.gz` itself through a `file://` URL
and Zig package hash from a separate consumer package. All hash and build
stages use isolated local or global Zig caches.
Pushing a `v<SemVer>` tag whose value exactly matches `build.zig.zon` runs the
full test gate, rebuilds and verifies these artifacts, and publishes them to an
idempotently updateable GitHub Release; malformed or version-mismatched tags
fail before publication.
