# netz vs gRPC Core parity audit

This audit tracks the gRPC part of the netz improvement goal. The primary
reference is `~/Work/grpc` at `03d65cc67c`, especially
`doc/PROTOCOL-HTTP2.md`, `doc/http-grpc-status-mapping.md`, and the CHTTP2
metadata/framing implementation.

## Current scope

Netz now exposes `netz.grpc` as a transport-oriented gRPC layer over its
existing HTTP/2 runtime:

- caller-buffer and `ArrayList` writers for the one-byte compressed flag,
  four-byte big-endian message length, and opaque message payload,
- a bounded iterator that accepts multiple coalesced messages without assuming
  that HTTP/2 DATA boundaries align with gRPC messages,
- all canonical gRPC status codes and strict decimal status parsing,
- `grpc-timeout` parsing/formatting for H/M/S/m/u/n units, with the protocol's
  eight-digit bound and upward rounding that never shortens a requested
  deadline,
- gRPC content-type, `TE: trailers`, method path, compression flag, and reserved
  custom-metadata validation,
- `-bin` metadata APIs that emit standard Base64 without padding, accept both
  padded and unpadded input, split proxy-combined comma values, preserve empty
  binary values, and decode repeated HTTP/2 fields through caller-provided
  bounded scratch,
- tolerant `grpc-message` percent decoding that preserves malformed percent
  sequences as required by the protocol,
- reserved `grpc-status-details-bin` support for `google.rpc.Status`, with
  owned client envelopes, borrowed `Any` iteration, canonical protobuf/Base64
  output, and validation that an explicitly present code matches the non-OK
  terminal `grpc-status`. Unknown protobuf fields and bounded groups are
  preserved, repeated singular fields follow protobuf's last-value rule, and
  malformed containers, invalid UTF-8, ambiguous duplicate metadata and
  contradictory status codes are rejected,
- strict allocation-free RFC 6750 Bearer metadata parsing that rejects absent,
  duplicate, malformed, or ambiguous credentials; token comparison visits all
  bytes at a matching public length. A caller-buffer constructor emits the
  canonical Authorization value and always marks it HPACK Never Indexed for
  unary, sequential-streaming, and duplex request options. Server rejection emits trailers-only
  `UNAUTHENTICATED` without retiring the HTTP/2 channel. Duplex servers expose
  the same check immediately after request HEADERS and before reading DATA,
  after which the existing bounded drain safely retires a rejected upload,
- shared unary, sequential and duplex HTTP status fallback when a broken
  intermediary omits `grpc-status`, including HTTP 200 UNKNOWN results,
- typed `identity`, `deflate`, and `gzip` algorithms plus
  `grpc-accept-encoding` parsing/formatting that ignores unknown extensions,
- accepted-encoding field selection follows the most recent non-repeatable
  `grpc-accept-encoding` declaration, matching gRPC Core metadata storage and
  its compression policy. A later empty, identity-only, or unknown-only value
  withdraws previously advertised gzip/deflate capabilities. Known algorithms
  within the final comma-separated value remain usable. Unary, client/server
  streaming, duplex and gRPC-Web requests share this selection, with real
  response compression/fallback and decoded-message checks on reused channels,
- per-message gzip and RFC 1950 zlib-wrapped `deflate` compression using the
  package-local focused DEFLATE backend, with no cross-message codec state,
- per-message compression opt-out on sequential and duplex client/server
  writers while retaining the stream's negotiated `grpc-encoding`,
- strict single-stream decompression with checksum/trailer validation,
  decompressed-size limits, raw-deflate and trailing-data rejection,
- gRPC Core-compatible compression fallback when an encoded message is not
  smaller, and server response fallback when the client did not advertise the
  requested response encoding,
- unary HTTP/2 client/server helpers with initial metadata, trailing metadata,
  trailers-only errors, configurable message-size limits, and explicit
  ownership for decoded request and response messages. Malformed unary
  metadata or envelopes receive `RST_STREAM(INTERNAL_ERROR)` and retire local
  HTTP/2 concurrency, response-semantics, and flow-window state even if the
  best-effort reset write fails,
- cleartext and TLS server accept timeout/deadline entry points covering socket
  acceptance through HTTP/2 bootstrap, plus bounded unary and sequential
  streaming request reads. An idle pre-request timeout leaves the channel
  reusable; an aggregate timeout after stream admission retains the lower
  HTTP/2 fail-closed behavior because parser state is not resumable,
- unary client deadlines captured once from `grpc-timeout` at API entry and
  enforced locally with the awake clock across request setup and the complete
  HTTP/2 exchange; expiration returns `error.Timeout`, while a null timeout
  remains unbounded. After expiry, best-effort CANCEL and connection-credit
  return share a separate bounded terminal cleanup budget, described below,
- one default transparent unary retry for REFUSED_STREAM before response
  commitment, without charging configured retry attempts or throttle tokens.
  The same request body and metadata are replayed, and the original absolute
  deadline supplies the remaining timeout on the retry. The caller can disable
  this recovery through `UnaryCallOptions.transparent_retry`. Any observed
  response head, including informational evidence, prevents this transparent
  replay; a second refusal remains visible unless an explicit policy permits
  another uncommitted attempt,
- explicit opt-in unary retry policies for replay-safe methods, with at most
  five configured attempts plus the independent transparent recovery,
  configured retryable status codes, exponential jittered
  backoff, server `grpc-retry-pushback-ms`, and standard
  `grpc-previous-rpc-attempts` metadata. Retries occur only for trailers-only
  responses or typed pre-response resets before the call is committed. Pushback
  follows gRPC Core's known non-repeatable metadata behavior: the final wire
  value wins, and a malformed or negative final value disables retry instead
  of allowing an earlier intermediary-prepended delay to override it. One
  absolute `std.Io` awake-clock deadline bounds every attempt and backoff while
  each retry advertises the
  remaining `grpc-timeout`. An optional thread-safe channel/service throttler
  applies gRPC's milli-token algorithm, debiting configured retryable failures
  before eligibility and replenishing successful RPCs without exceeding its
  maximum,
- owned standard service-config JSON parsing for global `retryThrottling` and
  method `retryPolicy`, including protobuf Duration strings, canonical status
  names, gRPC Core's five-attempt clamp, duplicate-selector rejection, and
  exact-method then service then default policy selection. Unknown unrelated
  service-config fields are ignored, and a more-specific config without a
  retry policy deliberately disables a broader inherited retry. Method
  `timeout`, `maxRequestMessageBytes`, and `maxResponseMessageBytes` are also
  applied to unary, sequential-streaming, and duplex calls, taking the stricter
  bound when the caller supplied its own timeout or directional message limit.
  `waitForReady` follows the same exact-method, service, then default selection,
  while an explicitly set per-call value takes precedence. Streaming policies
  do not silently enable retry without a complete replay buffer,
- sequential request/response message-stream helpers over HTTP/2
  `RequestWriter`, `ResponseWriter`, and borrowed DATA callbacks,
- sequential client-stream deadlines captured once before request setup and
  enforced across flow-control waits, request FIN, and the complete streaming
  response read. Expiry sends `RST_STREAM(CANCEL)` without creating a second
  frame reader, and callers may explicitly cancel even after request FIN,
- step-driven bidirectional streams whose single owner alternates request and
  response progress without racing the connection frame reader, including a
  server reply before request FIN and a later client message on the same RPC,
- bidirectional client deadlines captured once before request setup and
  enforced across flow-control writes, request half-close, and response-event
  reads. An RPC-deadline timeout sends `RST_STREAM(CANCEL)` and makes later
  operations terminal, while a caller-selected shorter read timeout remains
  resumable; explicit `cancel` uses the same stream-local reset path,
- callback-borrowed decoded messages with owned initial/trailing metadata,
  resumable byte-exact writes when flow control exposes a peer event, and
  independently tracked request/response half closes,
- validated final request/response HEADERS callbacks before the first DATA
  bytes, so message encoding is known before incremental decoding,
- bounded incremental reassembly when the five-byte gRPC prefix or payload
  crosses any callback, while several messages in one callback are delivered
  immediately,
- a zero-copy path for complete uncompressed messages and one exact-size
  allocation only when a message spans callbacks,
- independent gzip/deflate context per streamed message, terminal
  `grpc-status`/trailer parsing, and HTTP/2 stream reset for a truncated request
  message at END_STREAM,
- `writeMessageOrReadResponse`, which turns HTTP/2 `ResponseAvailable` into an
  owned typed gRPC response when a server returns before a flow-control-blocked
  client upload finishes; the request direction is half-closed, partial-write
  accounting is retained, and trailers-only OK/error status remains visible.
- typed unary and streaming client responses for peer `RST_STREAM`, preserving
  the HTTP/2 reason while mapping REFUSED_STREAM, CANCEL, ENHANCE_YOUR_CALM, and
  INADEQUATE_SECURITY to the gRPC status codes required by the protocol.
- typed duplex terminal events for both `grpc-status` trailers (including a
  true trailers-only early response) and peer `RST_STREAM`; a terminal early
  response closes the still-open upload before yielding the owned result.
  Servers can finish an early response and then drain the request half under
  an independent cleanup deadline, preserving the committed gRPC status while
  safely consuming a late FIN or peer reset instead of overwriting it with an
  extra teardown-time `RST_STREAM(CANCEL)`.
- standard `grpc.health.v1.Health/Check` protobuf messages and unary client/
  server helpers over persistent h2c and TLS channels, including the 200-byte
  service-name bound, `NOT_FOUND` for unknown services, and
  `INVALID_ARGUMENT` for malformed requests,
- a concurrent health registry with the standard default `SERVING` status,
  per-service updates/removal, graceful shutdown, and timeout/deadline-aware
  Watch cursors that emit an immediate snapshot and subsequent status changes,
- `grpc.health.v1.Health/Watch` client/server transport adapters over h2c and
  TLS, with incremental status delivery before END_STREAM, timeout/deadline
  reads, explicit client `RST_STREAM(CANCEL)`, server cancellation observation,
  and connection reuse after a canceled watch.
- self-contained gRPC Server Reflection v1/v1alpha wire codecs and a
  thread-safe opaque-descriptor registry covering file, symbol, extension,
  extension-number, and service-list queries, including transitive dependency
  expansion and standard embedded `NOT_FOUND`/`UNIMPLEMENTED` responses,
- transactional import of standard serialized `FileDescriptorSet` values from
  protoc, pbz, or another generator. The schema-free importer retains each
  original `FileDescriptorProto` byte string and automatically indexes file
  dependencies, nested message/enum/field/oneof symbols, services/methods, and
  extensions without making pbz a mandatory transport dependency,
- bidirectional Server Reflection v1/v1alpha client sessions and server
  handlers over h2c and TLS. One stream accepts ordered repeated queries,
  owns each decoded response beyond the DATA callback, supports timeout retry
  and explicit cancellation, and finishes with OK after request half-close.
  Malformed requests terminate with `INVALID_ARGUMENT`; cancellation releases
  the stream while preserving the HTTP/2 connection for later RPCs,
- dependency-free `grpc.pbz.ClientTransport(Service)` and
  `ServerTransport(Service, Handler)` adapters for the generic clients and
  handlers emitted by `protoc-gen-pbz`. They construct and validate canonical
  fully-qualified method paths and map unary, client-streaming,
  server-streaming, and bidirectional methods onto the owning gRPC runtime
  with typed generated request/response codecs. Handler failures become a
  configurable non-OK gRPC status. Generated clients preserve owned status
  text, optional HTTP status, and optional HTTP/2 reset reason across
  `RpcFailed`, with borrow-or-take APIs. Malformed protobuf and wrong unary
  request cardinality produce trailers-only `INVALID_ARGUMENT` while
  preserving the channel. Server request-event reads use one absolute
  awake-clock deadline derived from `grpc-timeout`; the generated adapter maps
  expiry to trailers-only `DEADLINE_EXCEEDED` and rechecks before each response
  message and final status. Synchronous handler computation is not preempted,
  but an expired handler cannot subsequently commit OK. `pbz` remains a lazy
  integration dependency rather than a requirement of the core transport.

Payloads intentionally remain opaque. This keeps gRPC transport reusable with
generated or dynamic protobuf implementations; the user-owned
`~/project-z/pbz` library is the natural protobuf layer but is not forced into
every netz build.

## Reproduction

Run the local unary h2c example:

```sh
zig build run-grpc-h2c -Doptimize=ReleaseFast
```

Run all codec/runtime and end-to-end tests:

```sh
zig build test
```

Run the focused process-boundary gate against the audited upstream gRPC C++
interop server:

```sh
zig build interop-grpc-cpp -Doptimize=ReleaseFast
```

Run the reverse-direction gate, with the upstream C++ client exercising a
one-shot netz server for each scenario:

```sh
zig build interop-grpc-cpp-client -Doptimize=ReleaseFast
```

The upstream gates require the exact `.bazelversion` release from the pinned
gRPC checkout. They accept that version's ordinary label and the official
`- (@non-git)` package label. `GRPC_BAZEL_OUTPUT_USER_ROOT` can relocate
Bazel's regenerable output tree to a filesystem with sufficient space; custom
Bazel runtime-library or compiler environments remain ordinary shell
configuration (`LD_LIBRARY_PATH`, `CC`, and `CXX`).

Run the independent Server Reflection gate, with upstream's official
`grpc_cli` querying a one-shot zio-backed netz h2c server:

```sh
zig build interop-grpc-reflection -Doptimize=ReleaseFast
```

Generate pbz bindings and exercise all four generated client/handler RPC
shapes over one real h2c channel, including typed handler failure mapping.
Both endpoints share zio's `std.Io`, and the local server is scheduled through
`std.Io.async` rather than a manually managed OS thread:

```sh
zig build interop-grpc-pbz -Doptimize=ReleaseFast
```

By default both C++ gates verify `~/Work/grpc` is at
`03d65cc67c450ccbb58a8a45627c4da83a886ccd`, builds
the relevant `//test/cpp/interop` executable with Bazel, and bounds both
readiness and execution. The forward gate runs the upstream server first over
h2c and then over TLS with upstream's CA/server fixtures; netz connects to the
loopback address while independently validating `foo.test.google.fr` and ALPN
`h2`. The reverse gate runs each scenario against separate h2c and TLS netz
server processes; the official client verifies the deterministic localhost
certificate. Both netz executables obtain `std.Io` from the zio-backed runtime.
At this pinned Linux revision, gRPC C++ constructs its default Posix
EventEngine; terminal records and runner assertions identify the role pair as
`zio-std-io` and `grpc-cpp-posix-event-engine`. Set `GRPC_ROOT` to use the same
pinned source revision elsewhere,
or set `GRPC_CPP_INTEROP_SERVER`/`GRPC_CPP_INTEROP_CLIENT` to an already-built
executable. `BAZEL`
may select a non-default Bazel/Bazelisk executable; the script verifies it
matches upstream's checked-in `.bazelversion`. The harness is reproducible even
when a host lacks that exact Bazel release, but such a host cannot establish an
external pass until the pinned tool or a prebuilt server is supplied.

On 2026-09-26, both complete h2c/TLS directions
passed on Linux AArch64 against the same pinned upstream commit with Bazel
8.7.0 and GCC. The netz client completed the full forward harness, including
the canonical compressed-streaming and status-message cases, while the
official C++ client completed twenty-two scenarios per transport. The upstream
client's hard-coded 1 ms sleeping-server deadline can expire before either a
cleartext or TLS accept creates an RPC; the runner accepts that local
`DEADLINE_EXCEEDED` outcome only while the netz server remains alive and has
not logged an accepted connection.

On 2025-09-07 both bidirectional TLS gates passed against upstream commit
`03d65cc67c450ccbb58a8a45627c4da83a886ccd` using Bazel 8.7.0 and GCC on
Linux x86_64. The pinned Bazel output root was placed on tmpfs because this
host's disk-backed extraction stalled in journal waits; that is a host build
performance workaround, not a protocol exception. The successful command was:

```sh
BAZEL=/tmp/bazel87-netz CC=/usr/bin/gcc GRPC_CPP_BUILD_TIMEOUT=20m \
  zig build interop-grpc-cpp -Doptimize=ReleaseFast
BAZEL=/tmp/bazel87-netz CC=/usr/bin/gcc GRPC_CPP_BUILD_TIMEOUT=20m \
  zig build interop-grpc-cpp-client -Doptimize=ReleaseFast
```

The independent C++ server build completed all 3492 Bazel actions and the
process-boundary client reported all four scenarios below as successful. Large
responses crossed multiple HTTP/2 DATA frames, additionally exercising decoder
progress events that contain a message fragment but no completed gRPC message.
The reverse gate builds upstream's `interop_client` and verifies `ping_pong`,
`empty_unary`, `large_unary`, `rpc_soak`, `channel_soak`, `half_duplex`,
`slow_consumer`, `empty_stream`,
`cancel_after_begin`,
`client_compressed_unary`,
`server_compressed_unary`,
`client_compressed_streaming`, `server_compressed_streaming`,
`authenticated_empty_unary`,
`status_code_and_message`, `special_status_message`,
`unimplemented_method`, `unimplemented_service`,
`client_streaming`, `server_streaming`,
`cancel_after_first_response`, `timeout_on_sleeping_server`, and
`custom_metadata` over both transports. Client streaming checks all four
canonical request payload sizes and the exact aggregate response; server
streaming checks all four canonical response messages. The metadata case runs
a 271828-byte unary request and a bidirectional request on one channel,
requiring the expected 314159-byte responses plus exact ASCII initial-metadata
and raw binary trailing-metadata echoes. Each case requires both the C++
client's successful exit and a netz marker proving the expected terminal
condition. For the upstream test's hard-coded 1 ms deadline, the harness also
records the legitimate race where the client reaches local
`DEADLINE_EXCEEDED` before the cleartext or TLS server accept finishes and no
server RPC exists.
The four compression cases use gRPC Core's own test-only call inspector. The
client-compressed unary and streaming cases first send the canonical false
probe and require netz to return `INVALID_ARGUMENT`, then verify compressed
and identity messages. Streaming uses one gzip RPC whose second request opts
out per message. The server-compressed cases require gzip and identity
responses independently; streaming uses one response stream whose first
message is compressed and second is identity. The forward gate exercises the
inverse direction on one persistent channel: netz sends and receives the same
unary and streaming matrices, checks every message compressed bit, validates
the negotiated `grpc-encoding: gzip`, and validates exact decompressed protobuf
payloads. Both directions run over h2c and certificate-verified TLS.
The ordinary status case requests `UNKNOWN` with an exact ASCII message over
both unary and bidirectional RPCs. The special status case proves
`grpc-message` percent encoding and decoding preserves CR/LF, tabs, BMP ☺,
and non-BMP 😈 text byte-for-byte through the independent C++ peer.
The routing cases distinguish the registered test service's deliberately
unimplemented method from an entirely unregistered service and require a
trailers-only `UNIMPLEMENTED` result for each. The forward harness performs
both calls consecutively on its persistent channel, proving the errors retire
only their RPC streams.
The basic unary cases additionally require the canonical empty protobuf round
trip and identity-framed 271828-byte request/314159-byte response payloads in
both independent implementation directions.
The half-duplex case sends all four canonical response-size requests before
half-closing, then requires the peer to emit the four responses in order. Both
netz and C++ server paths therefore prove response production begins only
after request END_STREAM rather than reusing ping-pong behavior.
The slow-consumer case retains upstream's 2000 responses of 1030 bytes and
20 ms application delay. It exceeds both the initial stream and connection
windows, requiring repeated WINDOW_UPDATE-driven progress while preserving all
message boundaries. The one-shot netz server performs a bounded two-phase
GOAWAY/PING synchronization after its final response, proving the peer
transport received all DATA before teardown.
The RPC soak is pinned to 100 sequential large-unary calls on one channel,
with the canonical 271828-byte request and 314159-byte response. The official
C++ side allows zero failures, enforces a 5-second per-iteration latency bound
and a 60-second overall bound; the netz side validates every decompressed
payload before advancing.
The matching channel soak uses the same 100 iterations and payload bounds but
reconstructs the channel for every RPC. It exercises TCP and HTTP/2 setup on
h2c plus TLS 1.3, certificate verification, and `h2` ALPN on TLS. The netz
fixture counts only connections that complete the large unary RPC, tolerates
speculative TLS connections abandoned before any request, and completes a
bounded graceful HTTP/2 shutdown before releasing each successful connection.
The cancellation matrix now includes cancellation immediately after request
metadata, with no request message, and cancellation after the first duplex
response. The netz server requires an actual peer `RST_STREAM(CANCEL)` in both
cases; the netz client then reuses its channel for subsequent RPCs.

The reflection gate passed again after the zio migration on 2026-09-15 against
the same pinned upstream revision and its Linux Posix EventEngine. Its ready,
completion, and runner records bind `grpc-cpp-posix-event-engine` to
`zio-std-io`. The earlier 2026-09-07 run used the same upstream
revision, Bazel 8.7.0, and GCC. It generates a standard descriptor set with the
system `protoc`, imports it into the netz registry, and requires official
`grpc_cli` queries to discover both reflection protocol versions plus the
fixture service, list its unary method, and render its request message type.
Every query also requires a server-side completion marker. The successful
command on this host was:

```sh
BAZEL=/tmp/bazel87-netz CC=/usr/bin/gcc GRPC_CPP_BUILD_TIMEOUT=20m \
  zig build interop-grpc-reflection -Doptimize=ReleaseFast
```

Set `GRPC_CLI` to a prebuilt official client to skip its Bazel build. Otherwise
the gate verifies `GRPC_ROOT` is at the pinned revision and that the selected
`BAZEL` matches upstream's checked-in `.bazelversion`.

The netz client exercises upstream's canonical `FullDuplexCall` contract:

- ping-pong alternation with request sizes 27182, 8, 1828, and 45904 bytes
  and corresponding zero-filled responses of 31415, 9, 2653, and 58979
  bytes, followed by an OK half-close;
- echoed `x-grpc-test-echo-initial` initial metadata and raw
  `x-grpc-test-echo-trailing-bin` trailing metadata on a large duplex call;
- `RST_STREAM(CANCEL)` after the first response, followed by a successful empty
  duplex RPC on the same HTTP/2 channel; and
- a short `grpc-timeout` while the C++ service waits for another request, with
  a typed `DEADLINE_EXCEEDED` terminal result.

`tools/interop/grpc_cpp_messages.zig` encodes and validates only the bounded
subset of `grpc.testing.SimpleRequest`/`Response` and
`StreamingOutputCallRequest`/`Response` needed by these cases, including
presence-preserving protobuf `BoolValue` compression controls. It pins its
field-number assumptions to the audited source revision and
strictly rejects malformed, non-canonical, oversized, or unexpected protobuf
input; it is a fixture codec, not a replacement for generated `pbz` bindings.

The test suite covers message truncation/limits, invalid compressed flags,
timeout/status parsing, non-shortening timeout rounding, status-message
encoding, gzip/deflate round trips, decompression limits, raw-deflate and
trailing-data rejection, tiny-message compression fallback, asymmetric
request/response negotiation, unaccepted-response fallback, successful unary
calls before their local deadline, silent-server deadline expiry with an
observed `RST_STREAM(CANCEL)`, trailers-only errors with custom metadata, and a
real HTTP 503 response without `grpc-status`. Stream tests sweep every byte split
across three coalesced messages, split a prefix across separate HTTP/2 writes,
force large gzip/deflate messages across small DATA frames in both directions,
verify independent compressed members, and require RST_STREAM(INTERNAL_ERROR)
for incomplete unary and streaming request messages. The unary regression
runs with one concurrent-stream slot and completes a valid RPC on the same
connection after the malformed stream; a failing-write state test verifies
that local credit and windows are still retired. The duplex test sends client message one,
observes the server's reply while the request half remains open, then sends
client message two and completes both halves. A second duplex test covers an
early trailers-only PERMISSION_DENIED response and proves subsequent writes are
rejected. The sequential early-return test gives exactly one
framed message send credit, then verifies that the next write receives a
trailers-only CANCELLED response with decoded `grpc-message` and without
sending the second message, matching the request-stream behavior covered by
upstream gRPC Core's `ServerEarlyReturnTest`.
The fixture peer drains the request through its empty FIN before closing TCP
and asserts that only the first framed message arrived, avoiding a transport
reset race from closing with unread upload bytes.

## Remaining work before broad gRPC parity

1. Generated pbz clients and handlers now have netz transport adapters for all
   four RPC shapes, including owned typed failure details. The process gate now
   obtains both endpoint handles from zio-backed `std.Io`, schedules its local
   server through `std.Io.async`, and reports both runtimes as `zio-std-io`.
   The background SharedChannel now schedules concurrent unary calls through
   per-endpoint owners, as described below. Shared streaming and duplex
   capabilities now use those owners for independent send and receive progress.
2. Transport composition is now covered: `grpc.runtime.Client`,
   `grpc.runtime.Server`, and `grpc.runtime.TlsServer` own persistent HTTP/2
   channels. The TLS path enforces `h2` ALPN and retains certificate-
   verification policy; h2c and TLS tests exchange multiple unary calls on one
   connection, and the owning h2c wrappers also compose multi-message request
   and response streams. A focused grpc-cpp gate is now available for external
   server checks of full duplex, metadata, cancellation/channel reuse, and
   deadline propagation over h2c and certificate-verified TLS. The reverse gate
   covers upstream-client ping-pong, client/server streaming, empty-stream
   completion, cancellation, deadline behavior, unary/bidirectional
   custom-metadata echo, and the canonical client/server compressed unary and
   streaming cases against netz over both transports. The forward gate
   independently covers the same gzip/identity unary and per-message streaming
   matrices against the C++ server, plus the canonical ordinary and Unicode
   status-message cases. A dedicated authenticated EmptyCall sends an RFC 6750
   Bearer credential through grpc-cpp's metadata interceptor over h2c and TLS;
   the netz server uses its strict, allocation-free parser and constant-time
   token comparison before dispatch. Local channel-reuse coverage additionally
   rejects a bad token with trailers-only `UNAUTHENTICATED`, then accepts a
   valid token on the same HTTP/2 connection. Cloud identity discovery, token
   issuance, refresh, and JWT signature verification remain application or
   identity-provider responsibilities rather than transport behavior.
3. Add broader conformance/interop runners. Reflection accepts standard
   descriptor sets directly and
   is covered by an independent official `grpc_cli` process-boundary gate.
   Health `Check` and `Watch` transport semantics are implemented, including
   incremental delivery, cancellation, and consumption-driven client Watch
   reconnection/backoff. SharedChannel now applies healthCheckConfig to
   same-connection endpoint admission for concurrent unary and streaming calls.
   Unary transport deadlines are already enforced locally as described above.

The current tests establish concurrent shared unary and streaming calls,
sequential streaming, and single-owner step-driven bidirectional streaming; broader gRPC Core feature
parity remains open.

The 2026-10-26 gRPC-Web verification exposed an HTTP/2 aggregate deadline
regression: the terminal CANCEL reused the expired read deadline, and a partial
response could first exhaust that deadline trying to return connection credit.
Both control writes now share one fresh absolute cleanup deadline after Timeout.
`http2.runtime.Limits.terminal_cleanup_timeout` defaults to 10 ms; this is the
maximum additional transport-write budget on the return path, not a renewed RPC
or response-read deadline. Zero skips those transport writes and still retires
local credit, stream ownership and windows. Negative values are rejected before
I/O. OOM before the operation deadline takes the earlier operation/cleanup bound;
expiry during a refund never renews the budget for CANCEL. Any failed or partial
terminal write prevents further writes and leaves the channel unusable because
discarded aggregate parser state cannot be resumed.

The original silent-peer unary cancellation regression now passes. TCP,
certificate-pinned TLS 1.2 and TLS 1.3 tests also observe exact WINDOW_UPDATE
credit followed by CANCEL after a partial response-body timeout, through both
aggregate and callback-streaming reads. Injected blocked/partial socket writes
verify bounded cancellation, preserved original errors, task cancellation/join,
stream retirement, zero-budget opt-out, and the earlier OOM deadline bound.

The unary RPC deadline now also reaches complete HTTP/2 request output. The
aggregate and callback HTTP/2 request APIs previously validated the deadline
before sending but used an unbounded complete-request sender. HEADERS,
CONTINUATION, batched HEADERS/DATA, subsequent DATA and upload flow-control
waits, and trailers now retain the same absolute budget as the response read.
Ordinary and explicit-retry unary tests block real TCP header/body writes and
exhaust a one-byte peer stream window; Timeout retires the upload without a
new RPC attempt. A complete-frame flow-control timeout may send CANCEL within
the existing terminal cleanup budget, while an indeterminate partial wire
write forbids another frame. Pre-output OOM retains channel reuse.

Unary calls now consume a terminal response received during an incomplete
upload instead of exposing HTTP/2 ResponseAvailable. The complete-request
transport keeps one response reader, resumes the exact request suffix after
intermediate heads, and cancels an unnecessary suffix after response
completion without fabricating a short Content-Length entity. Trailers-only
PERMISSION_DENIED preserves its status message and custom metadata; a following
server NO_ERROR does not replace that status. Ordinary and explicit-retry
calls are tested with an eight-byte stream window and one concurrent slot,
including a successful RPC on the same channel after the early rejection.
When a reset releases the last peer-advertised concurrent slot, the next call
synchronizes that retirement under its own existing deadline before sending
new request headers. This preserves the completed gRPC status while supporting
peers such as Node 26.10 that defer stream-map removal until a receive batch
finishes. The reset and new HEADERS remain ordered without renewing either RPC
deadline.

TLS 1.3 KeyUpdate responses are included in bounded read/write budgets. A local
timeout or executor failure retains the exact old-epoch response ciphertext;
read, application-write, or explicit pending-write completion resumes that
record before activating the next write epoch. KeyUpdate bytes contribute zero
application progress. A bounded call that encounters another write owner returns
`WriteInProgress`. Socket-backed tests authenticate the next application record
after zero-byte and partial-ciphertext failures and after a blocked read-side
KeyUpdate response, checking that the epoch transition happens once.

Sequential and duplex client stream termination now uses the same finite
`terminal_cleanup_timeout` budget. Deadline-triggered CANCEL, explicit stream
cancellation, and destruction retire local ownership and both indexed windows
even when a reset cannot be sent. An output failure prevents destructor retry
and further terminal writes; successful cancellation remains stream-local.
The duplex client's request-half FIN after an early terminal response is also
bounded, preserving the parsed gRPC status when output fails. Buffered sibling
responses remain available, and an unfinished declared Content-Length uses
CANCEL instead of a malformed FIN. A consumed but incompletely decoded HPACK
block retires channel reuse, while a completely decoded oversized block can still be
reset without losing the shared decoder. Regression coverage includes blocked
TCP and certificate-pinned TLS 1.2/1.3 output, partial control writes, reset
history OOM, and zero cleanup budget.
The TLS probes hold the actual encrypted socket write after the verified
handshake and check retained ciphertext plus task cancellation/join and no
destructor resubmission, avoiding a TCP ACK race for tiny control frames.

Server response writers and duplex streams now use the same finite terminal
cleanup policy for explicit reset and destruction. This also bounds gRPC
duplex failure cleanup and gRPC-Web abandoned-request conversion. Reset timeout,
partial output, and reset-history OOM release request ownership, response
semantics, priority state, and both stream windows even when the frame cannot
be sent. A failed terminal write makes the channel unusable and suppresses
destructor retries; successful cancellation preserves admitted siblings.
The request reader retains its scoped callback cancellation behavior, and
pending-request overflow cancellation shares one absolute cleanup deadline.
Real certificate-pinned TLS 1.2/1.3 probes hold server ciphertext output and
verify cancellation/join, retained records, and no later resubmission.

Discarded HTTP/2 request-reader state now uses one bounded terminal deadline
across connection-credit refunds, current-stream CANCEL, and queued-sibling
cancellation. This covers internal OOM and transport Timeout as well as
application rejection, preserving the original error after cleanup failure.
A partial WINDOW_UPDATE forbids subsequent control writes; local held credit
is still restored when output fails or cleanup writes are disabled. CONNECT
abandonment and tunnel reset/abort use the same finite cleanup policy.

## gRPC-Web unary and server streaming support

The production h2c/TLS gRPC server now speaks the gRPC-Web wire protocol
(https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md) for unary RPCs.
`grpc.web.parseContentType` classifies all six media types
(`application/grpc-web[+proto|+json]` and `application/grpc-web-text[+proto|+json]`,
case-insensitive with HTTP parameter tolerance) while rejecting plain
`application/grpc` so the two paths cannot be confused. `ServerConnection.readUnaryWeb`
performs the content-type negotiation, omits the browser-forbidden `te:
trailers` requirement, accepts exactly one length-prefixed request message, and
base64-decodes `-text` entities into request-owned storage; `writeUnaryWeb`
returns the negotiated media type and delivers terminal `grpc-status`,
`grpc-message`, pushback, and custom (including binary) metadata in one `0x80`
in-body trailers frame with no HTTP trailer block, while trailers-only errors
remain in the response headers. Compression negotiation reuses the standard
gRPC algorithms and grpc-accept-encoding rules. Pure codec tests cover all media
types, text decode ownership, malformed base64, and zero/duplicate message
rejection; real h2c loopback tests exercise binary and base64 unary calls with
custom trailer metadata and a trailers-only UNAUTHENTICATED response.

Server streaming is supported through the same server connection:
`readStreamingWeb` negotiates the wire, delivers exactly one request message
(browser client streaming is not part of gRPC-Web and zero or multiple request
messages reset the stream), and `startStreamingWeb` returns a streaming writer
whose messages become data frames and whose `finish` appends the single `0x80`
trailers frame. `-text` uploads decode incrementally through bounded stack
storage, including independently padded chunks split inside a frame or across
HTTP/2 DATA writes. The message decoder enforces the declared and decompressed
size limits before application delivery, rejects partial messages at END_STREAM,
and rejects a second request message before invoking the application callback.
`-text` responses stream through an allocation-free standard-base64 filter
(768-byte input chunks, at most two buffered bytes). Each completed gRPC message
flushes its padded tail immediately, so the client can decode it while the RPC
remains open. Large server streams never materialize a full response.
Real h2c loopback tests cover binary and base64 multi-message streams plus the
multiple-request rejection. Browser client streaming and duplex remain out of
scope for gRPC-Web itself.

Request content type and response wire are negotiated independently. Both
`readUnaryWeb` and `readStreamingWeb` return the response type in `content_type`;
they decode the upload according to its own Content-Type and choose the response
from repeated or combined Accept fields, including q weights and wildcard
specificity. Without Accept the response retains the request's wire. The
allocation-free `grpc.web.negotiateResponseContentType` helper exposes the same
policy for custom adapters; explicit rejection of every compatible type returns
`NoAcceptableWebContentType`. The payload's proto/json format is retained.

Body trailers use the same reserved-name checks as ordinary gRPC metadata,
plus lowercase key and printable-ASCII value validation because DATA bypasses
the HTTP header validator. Duplicate reserved status fields, CR/LF, NUL, and
invalid names are rejected before the terminal frame is written, so a streaming
writer can retry `finish` with valid metadata. Binary metadata remains base64.
Real h2c and certificate-pinned TLS tests wait for the client to independently
decode each empty or short text message before sending the next one, then
verify the exact terminal block and an inverse text-to-binary unary call on the
same channel. Two-byte DATA uploads cover in-frame padding, size limits,
truncation, malformed base64, a second request, and reuse after stream resets.

`grpc.web.http1` provides the corresponding HTTP/1.1 server adapter. Use
`readRequest(&connection, options)` with an existing cleartext or TLS HTTP/1
connection. Its result is either an owned `request` or a `handled` HTTP status
for a completed preflight or rejection. A request exposes `writeUnary` and
`startServerStream`, with the same binary/text negotiation, compression,
message limits and body trailers as HTTP/2. HTTP/1.1 server streams use chunked
transfer coding with one final gRPC-Web status frame and no HTTP trailers;
each text message flushes independently. Incoming field names are normalized
for standard binary-metadata and authorization helpers. Request-selected
Connection: close retires the connection, and dropping a request without a
response prevents a later reply from being assigned to the wrong exchange.
This adapter targets HTTP/1.1; no additional obsolete HTTP support is provided.

An application can dispatch one accepted HTTP/1.1 connection as follows (the
HTTP/1 server owns the listener and the connection is closed by its caller):

```zig
const options: netz.grpc.web.http1.Options = .{ .cors_policy = .{
    .allowed_origins = &.{"https://app.example"},
    .allow_credentials = true,
} };
switch (try netz.grpc.web.http1.readRequest(&connection, options)) {
    .handled => {}, // Preflight or rejection already has its response.
    .request => |value| {
        var request = value;
        defer request.deinit();
        try request.writeUnary(.{ .message = request.request.message.payload });
    },
}
```

CORS is opt-in through `Options.cors_policy`. The transport-neutral
`grpc.web.cors` policy validates serialized origins, compares scheme/host and
normalized default ports, checks POST preflight methods and every requested
header name, and produces owned response fields. Credentialed requests require
an explicit origin list; wildcard origins with credentials are rejected before
I/O. No-Origin clients continue normally. Policies control allowed request
headers, exposed response metadata, credentials and preflight max-age. Responses
vary on Origin and preflight request fields; HTTP/1.1 responses also vary on
Accept. Duplicate Origin/method fields and malformed values are rejected, and
denied origins receive no permission headers or application callback. CORS
permission checks complement the existing authentication helpers.

The HTTP/1.1 loopback gate covers cleartext and certificate-pinned TLS,
preflight and forbidden origins, malformed requests, binary and text unary,
gzip responses, multi-message streams, trailers-only authentication failures,
connection reuse, close semantics, and exhaustive request-admission allocation
failures. Shared response-field construction also covers the heap-field branch
and exhaustive allocation failures.
Shared initial-field construction now lives in `web/response_headers.zig`,
including stable storage for status text and retry pushback across both HTTP
transports.

An independent Chromium gate runs the official pinned `grpc-web` 2.1.1 JS SDK
against a zio-backed netz endpoint. It verifies credentialed binary/text unary,
exposed custom metadata, a blocked foreign-Origin preflight, trailers-only
UNAUTHENTICATED, and text server streaming. The server waits for a separate Ack
RPC triggered by the first decoded 32-KiB message before sending message two
or terminal status, so successful delivery requires incremental SDK parsing.
The JS codecs are opaque fixture messages, not production language bindings.

```sh
zig build interop-grpc-web-chrome -Doptimize=ReleaseFast
zig build interop-grpc-web-chrome -Doptimize=ReleaseFast -- --tls
zig build interop-grpc-web-chrome -Doptimize=ReleaseFast -- --tls --http2
```

The HTTPS gate also abandons an authenticated idle TLS connection without
close_notify and requires the endpoint to continue serving all RPCs. Partial
HTTP requests retain their failure behavior. The HTTPS gate pins only its
temporary certificate's SPKI in Chromium. The
runner defaults to `/usr/bin/chromium`; set `CHROME` to another compatible
Chromium executable.

`grpc.web.http2` now provides the same owned-request/handled-status dispatch on
HTTP/2. `grpc.runtime.ServerConnection.readWebRequest`, `readWebRequestWithTimeout`
and `readWebRequestWithDeadline` expose it through the existing gRPC listeners.
Preflights and policy/protocol rejections receive complete HTTP responses on
their own streams before application dispatch. The returned request writes unary
or streaming gRPC-Web responses with policy-controlled permission/exposure fields
and Vary: Accept. Its accepted compression and message-size bounds come from the
validated request and owning server. Dropping an unanswered request cancels only
that stream and retires its local state. Local conversion failures also abandon
the admitted request while preserving the original error.

HTTP/1.1 and HTTP/2 share the same media/CORS classifier. HTTP/2 tests use one
concurrent-stream slot and require reuse after 204, 403, 400, 405, 415, 406 and
413 responses, a dropped-request CANCEL, binary/text negotiation, and streaming
body trailers. Allocation-failure sweeps cover request and response ownership.
`ServerStreamWriter.finishWithOptions` carries terminal retry pushback as well
as status/message and custom metadata; the HTTP/2 request wrapper uses the same
TerminalOptions interface as HTTP/1.1.

The browser runner's `--tls --http2` mode uses the production TLS HTTP/2 listener
and the same official grpc-web SDK probes. DevTools response metadata must
report `h2`, so a fallback to HTTP/1.1 cannot satisfy the gate. The stream-delivery
Ack uses a separately verified Node HTTP/2 control session in this mode, keeping
one frame reader on each server connection while the stream waits for browser
delivery. HTTP/1.1 gates retain the SDK Ack RPC and idle TLS-close probe. Browser
permission checks, exposed unary failure status and incremental stream delivery
are validated on both modern HTTP transports.

## Rich error details

`grpc.status_details.encodeAlloc` builds a standard `google.rpc.Status` image
from a canonical non-OK status, a UTF-8 message and opaque `Any` entries.
Applications may instead supply an image from their own generated protobuf
codec. `UnaryResponseOptions.status_details` and `grpc.TerminalOptions.status_details`
accept those raw protobuf bytes. Native sequential and duplex writers expose
`finishWithOptions`; gRPC-Web unary, trailers-only and server-streaming paths
use the same option. The reserved field remains unavailable through custom
metadata, preventing an application from bypassing its status validation.

```zig
const details = try netz.grpc.status_details.encodeAlloc(
    allocator,
    .invalid_argument,
    "invalid item",
    &.{.{ .type_url = "type.googleapis.com/example.FieldViolation", .value = encoded_violation }},
);
defer allocator.free(details);
try stream.finishWithOptions(.{
    .status = .invalid_argument,
    .status_message = "invalid item",
    .status_details = details,
});
```

Unary, sequential and duplex client responses own an optional `status_details`.
Its `view.code` distinguishes an omitted code field from an explicit zero;
`view.message` and `view.details()` borrow the owned image until response
`deinit`. Each iterator result supplies `type_url` and raw `value`, leaving the
application's schema above the transport. The image, including unknown fields,
remains available as `bytes`. Details with OK status, multiple reserved values,
missing/malformed terminal status, invalid Base64/protobuf or a conflicting
code fail response conversion. A missing code is accepted under the protocol's
explicit-field consistency rule. A details message need not equal grpc-message.

The pbz adapter retains an independent owned copy in `RpcFailure`; taking that
failure preserves its details across later calls. Server adapters can configure
`handler_error_details`, validated with `handler_error_status` at initialization.
The common bounded protobuf reader is shared with reflection, and native
terminal-field construction lives beside the streaming writer in
`src/grpc/stream/terminal.zig`.

TCP and certificate-pinned TLS matrices use one concurrent stream slot and
exercise unary trailers-only errors, errors after streamed DATA, duplex
trailers-only and trailing HEADERS, sender validation/retry, and deliberate
peer status contradictions. A final unary RPC proves channel reuse after
every response path. Allocation-failure sweeps cover envelope creation,
Base64 decode, clone, terminal parsing and response-field construction.
The generated pbz process fixture checks transferred details after a later
successful call. The official Chromium grpc-web SDK also checks exact
google.rpc.Status bytes exposed by CORS on its UNAUTHENTICATED response over
HTTP/1.1 and TLS HTTP/2.

## Intermediary response status policy

All native client RPC shapes now share `src/grpc/response_metadata.zig` for
terminal status and entity classification. A canonical `grpc-status` takes
precedence over the HTTP status, including trailers-only errors with a missing
or non-gRPC Content-Type. Trailing status takes precedence over an initial
status. When no status is present, the upstream HTTP-to-gRPC table applies;
HTTP 200 produces an owned UNKNOWN result with a diagnostic message. Sequential
and duplex completion use the same result as unary completion. Malformed or
duplicate status fields in the selected section also produce UNKNOWN with a
diagnostic rather than allowing the first duplicate to report success.

Non-gRPC entities are discarded without message callbacks or compression
negotiation. A non-200 intermediary error entity is also discarded when the
proxy preserved `application/grpc` but omitted status at classification time.
Aggregate unary decoding can also use the already received terminal status
to recognize a complete gRPC body on a non-200 response, preserving its earlier
message behavior. Streamed readers classify the entity from initial metadata
before delivering DATA. Proper gRPC messages
retain bounded framing and compression checks, and messages received before a
missing terminal status remain observable alongside the failed RPC result.
Explicit unary OK still requires exactly one response message. Error details
retain their independent protobuf/status consistency validation and ownership.

TCP and certificate-pinned TLS matrices run all three client APIs through one
concurrent stream slot, including empty HTTP 200 responses, proxy HTML,
preserved gRPC media types on HTTP errors, explicit status over HTTP 503,
missing media type with trailing status, messages before missing status,
normal completion, rich errors, and malformed/duplicate status. Later calls
on the same channel prove completion retires stream ownership. Allocation
failure sweeps cover terminal diagnostics and decoded details, including errors
after earlier successful allocations.

```sh
zig build interop-grpc-response -Doptimize=ReleaseFast
```

This separate process gate uses a raw Node HTTP/2 peer with one advertised
concurrent stream slot. A pinned official `@grpc/grpc-js` 1.14.0 client and the
zio-backed netz unary, sequential and duplex client reuse their persistent
channels across 23 common cases, with three additional unary cases. A second
native channel exercises two shared RPCs with deferred consumption. The peer
validates complete request envelopes or exact rejected-upload prefixes and
counts all 102 physical attempts: 26 reference RPCs, 74 native RPCs and one
additional transparent refusal attempt on each original client. It covers
every HTTP mapping, explicit status precedence,
missing/trailing metadata, rich status, messages before terminal failure, and
scheme-normalized Host/:authority pairs with default ports, percent-encoded
unreserved host bytes and equivalent IPv6 representations. The added unary
cases reject 32 KiB messages before request completion and require preserved
status messages and custom trailers plus a subsequent successful call. A TCP
relay triggers server NO_ERROR only after observing complete response
END_STREAM and asserts both independent clients received that wire sequence.
The refusal case checks that both physical attempts omit configured attempt
metadata and return the successful message through the same connection.
The reference runner waits for its asynchronous stream closure before starting
another call; native calls reuse the one-slot channel directly.
The two observed SDK differences are reported explicitly: grpc-js produces
INTERNAL on DATA FIN without `grpc-status`, and RESOURCE_EXHAUSTED when it reads
the fixture's HTML body as an oversized message envelope. Netz applies the
documented UNKNOWN fallback and discards that non-gRPC entity. The gate checks
the pinned SDK's actual outcomes alongside netz's required behavior and does
not claim those malformed responses have identical SDK results.

The owning h2c client's IP-address connection now also supplies its numeric
`address:port` authority automatically through the HTTP/2 runtime. Unary,
sequential, duplex, generated pbz, health and reflection calls may omit the
per-call authority when using that endpoint. An explicit per-call authority
retains precedence. IPv6 defaults use `[address]:port`; socket interface and
flow metadata stay out of the HTTP origin. TLS constructors retain their
hostname or explicitly configured authority and certificate/SNI identity.
The same independent response-policy gate now omits netz's per-call authority
and requires the raw Node peer to observe the exact connected address/port in
the 65 native RPCs that use the constructor default, including correct `http`
scheme and connection reuse. Nine further native calls supply equivalent Host
and authority fields and must complete successfully on that same connection.

## Wait-for-ready reconnecting channels

`grpc.runtime.Channel` is a lazy, single-owner channel distinct from the
already-connected `grpc.runtime.Client`. It accepts cleartext IP/hostname,
TLS hostname/resolved-address, or custom connectors and retains a quiescent
HTTP/2 connection per ready endpoint across calls. Unary, sequential-streaming
and duplex starts support explicit `wait_for_ready`; service-config
`waitForReady` applies only
when the call did not explicitly select fail-fast or waiting behavior.

One awake-clock RPC deadline is captured before connection readiness and then
reused by HTTP/2 request setup, every explicit retry attempt, stream writes and
response reads. Connection waiting therefore cannot renew `grpc-timeout`.
Unavailable targets use gRPC Core's connection-backoff defaults: one second
initial delay, 1.6 multiplier, plus/minus 20 percent jitter, 120-second base
cap and 20-second minimum connect attempt, all configurable for tests and
deployments.
Scheduled backoff survives a shorter caller deadline, successful SETTINGS
resets it, and `resetConnectionBackoff` permits an explicit immediate retry.
`cancelWaits` interrupts backoff without racing the sole connection owner.

Wait-for-ready is not an RPC replay policy. Once an RPC reaches a connection,
transport failure returns to that caller; the broken channel connection is
retired and a later call may reconnect. Existing transparent REFUSED_STREAM
recovery and configured replay-safe unary retry remain the only automatic
request replays. Real TCP tests cover two refused connection attempts followed
by success, decreasing on-wire timeout, fail-fast override, deadline and
cancellation, scheduled-backoff retention, and reconnecting only the later RPC
after a committed request loses its transport.

Pre-resolved endpoint sets add `pick_first` and `round_robin` selection without
changing single-target construction. Each endpoint owns independent HTTP/2
state, consecutive-failure count and scheduled backoff. `pick_first` walks the
ordered list until one endpoint becomes ready, then stays on that endpoint
until it becomes unusable. `round_robin` rotates only across READY connections;
`warmWithDeadline`/`warmWithTimeout` explicitly and sequentially establish the
set so an unconnected or backed-off sibling never delays a call while another
endpoint is ready. A failed endpoint is skipped without advancing or resetting
healthy siblings, and a non-retryable endpoint remains disabled until
`resetConnectionBackoff`.

Top-level service config now accepts the standard ordered
`loadBalancingConfig` list plus deprecated `loadBalancingPolicy`, chooses the
first supported `pick_first` or `round_robin` entry, and supports
`pick_first.shuffleAddressList`. Explicit Channel options override service
config. Real two-server tests prove stable ordered pick-first selection,
READY-only A/B/A/B round robin over persistent connections, and endpoint-local
backoff that does not reattempt or block a healthy sibling.

Hostname Channel targets now resolve every unique system A/AAAA address through
a background polling worker; callers may inject the same allocator-owned,
deadline-aware `AddressResolver` contract used by other netz transports. The
first warm or RPC leaves `IDLE` and starts resolution. Subsequent connection
failures request re-resolution, successful results observe gRPC Core's default
30-second minimum refresh interval, and resolver failures retry with independent
gRPC backoff. Result delivery is acknowledged before another query may publish,
so a slow Channel owner cannot lose an intermediate error or leak replaced
address storage.

Address updates are applied transactionally at the single-owner Channel seam.
Unchanged addresses retain their HTTP/2 connection and endpoint backoff;
removed addresses close only after active operations are quiescent, and new
addresses start independently. Resolver failure or an empty update does not
discard an existing READY endpoint. Cleartext resolved addresses retain the
original hostname authority just as TLS addresses retain SNI, verification
identity, and authority. `requestNameResolution` and the bounded
`refreshNameResolutionWithDeadline`/`refreshNameResolutionWithTimeout` APIs
support control-plane refresh, while `connectivityState` exposes
IDLE/CONNECTING/READY/TRANSIENT_FAILURE. Real TCP tests cover unchanged-address
connection reuse, address replacement, authority preservation, resolver-error
fallback, and wait-for-ready recovery after every old endpoint fails.

Connectivity observation now follows grpc-core's last-observed-state contract
without borrowing the movable Channel value. `watchConnectivity` returns an
independently reference-counted cursor with generation-stamped snapshots, so a
READY-to-TRANSIENT_FAILURE-to-READY ABA sequence is still observable even when
the final enum equals the cursor's prior state. Bounded next-change and
wait-for-READY operations support concurrent independent watchers, cancellation
and timeout; Channel destruction broadcasts SHUTDOWN and the cursor remains
valid until explicitly released. Tests cover immediate stale-generation
completion, timeout then reuse, task cancellation, multi-watcher broadcast,
real READY notification and shutdown after the Channel storage is gone.

Connectivity-watch deadlines also bound tracker-mutex admission. A blocking
wait owns a small heap node shared with the tracker, so timeout or cancellation
can abandon that node atomically without waiting to remove a stack pointer
under a contended lock. Notification and abandonment race once; a notification
that already won preserves its exact snapshot. The publisher retains its node
reference through the event wake, while abandoned nodes are reclaimed by the
next tracker access or final tracker release. Ordinary active registration
does not scan the waiter list unless an abandoned node needs cleanup. Spurious
event wakes recheck the caller's original absolute deadline instead of ending
the watch early. Changed generations and SHUTDOWN remain immediately available
with a zero timeout and allocate no wait node. Blocking waits now expose
`OutOfMemory` in their error set; a failed allocation leaves the cursor and
tracker unchanged for retry. Adjacent connectivity tests hold registration
and unregistration locks beyond a 10-ms deadline, cover cancellation, both
notification races, node reclamation, allocation failure and repeated spurious
wakes. The grpc-cpp process fixture observes real channel transition/READY
notifications over h2c and verified TLS, then reads retained SHUTDOWN after
Channel destruction. Evidence is recorded in
`evidence/grpc_connectivity_deadline/2026-10-28.json`.

The resolver worker and connectivity tracker are background control-plane
work. Connection creation, HTTP/2 ownership and picker mutation remain
serialized at the intentionally single-owner Channel boundary. A fully
concurrent subchannel manager must therefore own stable heap subchannels and
publish quiescent connections into that boundary; running `Connection` methods
from watcher tasks would violate the current ownership contract and is not
implied by these observation APIs.


## Reconnecting client Health Watch

`grpc.health.ReconnectingWatch` owns a dedicated lazy Channel and automatically
rebuilds `grpc.health.v1.Health/Watch` as the caller drives next-event or
wait-for-SERVING operations. It follows the locally audited gRPC Core
`subchannel_stream_client.cc` and `health_check_client.cc` policy: a stream
that ends before delivering a valid health response uses exponential jittered
backoff (1 s initial, 1.6 multiplier, 0.2 jitter, 120 s maximum base). A stream
that delivered any valid status restarts immediately and resets that backoff.
Even terminal OK restarts Watch. UNIMPLEMENTED disables further watches and
assumes the backend is healthy; UNKNOWN, NOT_SERVING, and SERVICE_UNKNOWN do
not make it healthy.

Events expose decoded health status, retry deadline and typed RPC/reset or
transport failure, and explicit check disablement. A failure clears the last
observed serving state. `waitForServingWith{Timeout,Deadline}` consumes retry
and unhealthy events under one caller budget. The owning handle can move
because its private Channel lives on the heap; the service name is copied,
while target configuration and metadata remain borrowed for its lifetime.
Task cancellation and retry-wait timeout retain the scheduled retry deadline.
Explicit cancellation is terminal and releases the active stream under the
existing finite HTTP/2 terminal cleanup policy.

```zig
var health_watch = try netz.grpc.health.ReconnectingWatch.init(
    allocator,
    io,
    .{ .tls_host = .{ .host = "backend.example", .port = 443 } },
    .{ .watch = .{ .service = "demo.Echo" } },
);
defer health_watch.deinit();
try health_watch.waitForServingWithTimeout(.fromSeconds(30));
```

The caller must continue driving the handle to observe later state changes.
This dedicated connection preserves single-owner HTTP/2 frame reading; it
does not modify another application's Channel picker. A concurrent per-backend
health-gated picker and standard `healthCheckConfig` integration remain work
for the subchannel manager.

`health.startWatchWith{Timeout,Deadline}` and the matching runtime.Client
methods also bound request HEADERS and DATA output. They intentionally omit
`grpc-timeout`: the setup operation's deadline is not the lifetime of Health
Watch. Later bounded reads retain a live stream on timeout, and any pending
request suffix uses that read's operation budget. Real h2c tests cover
consecutive failures, terminal OK, backoff reset, UNIMPLEMENTED, malformed
protobuf, retry sleep cancellation, resumable active reads, explicit
cancellation, and zero peer-window request-output timeout. Certificate-pinned
TLS tests check reconnects, logical authority, `h2` ALPN, and retained peer
certificates; the pre-existing ordinary streaming deadline gates verify the
shared request builder still advertises and enforces actual RPC lifetimes.


## Health Watch and business duplex streams on one connection

The owning `runtime.Client` can now start a Health Watch and business duplex
RPCs together. Its single caller alternates event reads; HTTP/2 routes sibling
frames and decodes shared HPACK state in wire order, while each gRPC stream
keeps independent compression, incremental framing, metadata and final status.
Completing or canceling one stream leaves its siblings active. The real h2c
gate sends business response bytes before the first health update, retains
that response while Watch is read, finishes the business RPC, and then
observes a subsequent NOT_SERVING update on the same connection. Health gzip
and business deflate negotiation exercise independent decoder state.

This establishes the shared-connection stream primitive needed by a background
subchannel owner. The existing Channel still waits for quiescent stream state
before connection selection, and `ReconnectingWatch` still owns its dedicated
Channel. SharedChannel now uses this primitive for background unary dispatch
and per-backend health-gated selection, as described in its section below.
Standard `healthCheckConfig` also constructs reconnecting client Health Watches
as described below.


The pinned grpc-cpp forward gate independently verifies two concurrent
FullDuplexCall streams on the same connection over h2c and certificate-verified
TLS. It reads their differently sized responses in reverse stream order,
checks initial metadata on both, cancels the first stream, then sends and
receives another message on the surviving stream before its final OK. The
strict result marker includes `multiplexed_duplex=2+cancel-isolated`.

The local 2026-10-27 verification passed 1039/1039 combined HTTP/2 and gRPC
tests, 20/20 package checks, and the ReleaseFast compact-state gate. Connection
and client-stream sizes retain their existing assertions in both checked and
optimized modes. Hyper h2c/TLS interop also passed. On this host the grpc-cpp
reference was rebuilt with `CC=/usr/bin/gcc CXX=/usr/bin/g++` because the
PATH-selected Clang could not locate the C++ standard headers; compiler
selection remains an ordinary caller-provided environment.


## Service-configured client Health Watch

`ServiceConfig.healthCheckServiceName()` exposes the owned standard global
`healthCheckConfig.serviceName`. As in the locally audited gRPC Core client
channel parser and optional JSON-field loader, a missing or null config,
missing/null serviceName, or an empty config object leaves checking disabled.
An explicitly empty string enables overall server health. Unknown extension
fields are ignored, while malformed objects, non-string service names,
duplicate known fields and invalid UTF-8 are rejected. JSON integer arrays are
rejected even though Zig's generic byte-slice JSON decoder would accept them.

`ReconnectingWatch.initWithServiceConfig` returns a nullable owning Watch.
Disabled construction allocates nothing and performs no connection I/O.
`Options.service_override` has first priority and can explicitly select the
empty service; a non-empty `watch.service` is next, followed by the configured
name. The selected name is copied and load-balancing policy is inherited
through the existing Channel constructor. Explicit Channel options still win,
and the ServiceConfig can be destroyed after construction. The existing
Health Watch service-name bound is checked before transport I/O.

```zig
var config = try netz.grpc.ServiceConfig.parse(allocator,
    \\{"healthCheckConfig":{"serviceName":"demo.Echo"}}
);
defer config.deinit();
if (try netz.grpc.health.ReconnectingWatch.initWithServiceConfig(
    allocator, io, target, .{}, &config,
)) |configured| {
    var watch = configured;
    defer watch.deinit();
    try watch.waitForServingWithTimeout(.fromSeconds(30));
}
```

The local gates cover disabled construction with a failing allocator and a
connector probe, name ownership after JSON/config destruction, explicit name
and balancing precedence, transactional allocation failure, and real h2c
named/overall Watch delivery and cancellation without grpc-timeout. This
configures the existing consumption-driven Watch; applying those live health
updates to a background per-subchannel application picker remains open.


## Shared client event pump and polling

Client duplex response handling now supports a pump-and-poll owner loop.
`http2.runtime.Connection.pumpClientDuplexWith{Timeout,Deadline}` consumes one
input frame, handles connection control, assembles/decompresses HEADERS in wire
order and routes application input. Its result contains a stream-ID hint or
reports partial/control progress. `pumpClientDuplexWithDeadlineOrWake` races
that sole frame read against a caller-owned command event. Both tasks require
concurrency admission; admission failure and cancellation join all tasks and
retain any complete frame, while a simultaneous completed frame takes
precedence over an ordinary command wake. Partial transport and HPACK input
remain in their existing connection-owned buffers.

`ClientDuplexStream.pollResponseEvent[WithDeadline]` consumes only routed events
and synthetic stream completion; it never reads transport input.
`grpc.ClientDuplex.pollResponseEvent[WithDeadline]` adds the existing gRPC
metadata, framing, compression, terminal-status and RPC-deadline semantics.
`health.ClientWatch.pollNextWithDeadline` exposes the same path for health
status updates. Polling DATA can return receive credit, and terminal cleanup
can write control frames, so callers should supply a finite output deadline.
Watch request resumption is explicit through `resumeRequestWithDeadline` and
is kept outside the poll path because it can need flow-control input.

An owner drains active streams with poll operations, processes commands, then
pumps one input frame under its earliest operation/timer deadline or command
wake. Completed handles are removed from the active set. This keeps an idle
Health Watch from blocking a ready sibling RPC and supports RPC expiry even
when no frame arrives. GOAWAY is recorded once and reported by each affected
stream's poll, rather than only by whichever stream happened to read it.

The h2c gate sends business replies while withholding health DATA until the
business RPC completes, then sends the health update on that same connection.
Other gates cover HPACK order and partial sections, transport-prefix retention,
concurrency admission failure, task cancellation/join, command/frame races,
synthetic completion and GOAWAY. The pinned grpc-cpp dual-stream gate also
uses this poll/pump path for h2c and verified TLS. A complete background
subchannel manager and health-driven application picker remain integration
work on top of this primitive.


The final pump/poll verification passed 1060/1060 combined HTTP/2 and gRPC
tests and 20/20 package tests. The pinned grpc-cpp dual-stream gate uses the
wake-capable pump on the zio backend over h2c and verified TLS. Malformed DATA
also returns its consumed credit within the same operation deadline: a blocked
refund preserves the original protocol error, restores local accounting and
retires connection writes/reuse. A real saturated TCP regression bounds that
return path and prevents an unbounded refund from hiding inside a poll.


## Background shared unary channels and health-aware endpoint selection

`grpc.SharedChannel` owns a stable heap state and one background `std.Io`
worker per static endpoint or unique resolved hostname address. Each worker
exclusively owns its ordinary Channel, HTTP/2 connection, Health Watch and
application duplex streams.
`channel.sender()` and `sender.clone()` return reference-counted handles that
may issue concurrent unary calls. Callers enqueue stack-owned commands under
the shared mutex and wait on per-call events. Deadline or task cancellation
removes a queued command immediately, or wakes its owner and joins stream
retirement before returning. Sender handles and connectivity cursors may
outlive SharedChannel destruction; subsequent sends then fail with
SharedChannelClosed while retained watchers observe terminal SHUTDOWN.

Connection attempts begin on the first call or explicit `connect()`. Endpoint
workers connect in parallel and expose independent health-derived connectivity
through `watchEndpointConnectivity`. `pick_first` stays with a ready selected
endpoint, while `round_robin` advances across ready endpoints with available
concurrency credit. Connection and health retries use the existing gRPC
backoff defaults. Each hostname source has an independent background resolver,
including hostname entries mixed with static endpoints in a resolved target.
Every physical address preserves the original logical authority, TLS server
name, certificate-verification policy and transport limits.

Resolution starts on the first call, explicit `connect()`, or name-resolution
request. `requestNameResolution()` coalesces refresh requests and retains the
ordinary resolver's minimum interval and failure backoff; endpoint connection
failure also requests a refresh. Successful
`refreshNameResolutionWithDeadline/Timeout` calls await a new published result
from every hostname source; any failure is reported as soon as it is observed.
Its deadline or caller cancellation ends only that wait; the channel still
owns discovery.
`endpointCount()` and `watchEndpointConnectivity(index)` describe the latest
candidate address list. A retained cursor remains attached to its original
endpoint when a later list changes its ordinal.

An address update reuses unchanged workers, connections and Health Watches.
A candidate list replaces its current source once the current source has no
READY worker, a candidate is READY after all initial state notifications, or
every candidate has failed. Until then, the old READY source still serves new
calls while candidates independently connect and pass their health gates.
Resolver errors preserve the last valid membership. A valid empty list retires
the source immediately and reports NoAddressReturned. Removed workers stop
admitting calls, cancel their Health Watch, drain active RPCs under their
original deadlines, then close the transport and reclaim their own state.
Constructor and candidate allocation/admission failures clean up provisional
workers without replacing an existing valid list. Channel destruction joins
resolver callbacks before returning, including when retained Sender handles
keep the already-closed shared state alive.

`SharedChannelOptions.service_config_json` is parsed into owned state. Its
method timeout, directional message limits, waitForReady and retry policies
apply to unary sends, and its load-balancing config and healthCheckConfig
select endpoint policy and health service. Explicit options override those
policies; `disable_health_check` suppresses Watch. Health is checked on the
same connection that serves application RPCs. NOT_SERVING, UNKNOWN and
SERVICE_UNKNOWN prevent later admission but leave active RPCs running.
UNIMPLEMENTED disables checking for that connection and permits calls. A
terminated Watch retries after backoff when it received no status, or
immediately after a status response. Connection loss retires active RPCs and
reconnects for later calls; it does not implicitly replay a committed call.

Each RPC owns one absolute awake deadline captured before queuing. The common
unary retry driver also provides transparent pre-response REFUSED_STREAM
recovery, configured replay-safe attempts, pushback, throttling and previous
attempt metadata. A spurious futex wake cannot turn into an early RPC Timeout.
Uploads are staged once and consume only current flow-control credit in bounded
byte turns; they never read the socket to obtain more credit. The owner's sole
wakeable frame pump supplies WINDOW_UPDATE and peer-response progress for every
active stream. Header/data output uses the configurable operation_timeout
(default 20 s) capped by the RPC deadline. Idle input waits have no artificial
poll interval; commands wake the reader, and only RPC/backoff timers bound input.

Unary responses retain standard decoded messages, metadata, status text, rich
status details and typed resets. The advanced `transport.body` view is
normalized to an uncompressed gRPC frame, allowing the decoded payload to alias
one owned response allocation. `was_compressed` still records the actual peer
message flag. Destruction closes the queue, cancels/joins endpoint workers and
releases transport state before the owner reference is dropped.

```zig
var channel = try netz.grpc.SharedChannel.init(allocator, io, target, .{
    .service_config_json =
        \\{"healthCheckConfig":{"serviceName":"demo.Service"},
        \\"loadBalancingConfig":[{"round_robin":{}}]}
    ,
});
defer channel.deinit();
var sender = channel.sender();
defer sender.deinit();
var result = try sender.unary(.{
    .path = "/demo.Service/Unary", .message = payload,
    .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second },
});
defer result.deinit();
```

The local suite proves reversed completion of simultaneous unary calls on one
connection, same-connection health admission and endpoint switch, active-RPC
survival after NOT_SERVING, timeout and caller cancellation, reference-counted
shutdown, transparent refusal recovery, configured retry metadata, exact staged
upload suffixes, and allocator/concurrency-admission cleanup. Broader production
scheduling and conformance evidence remain open beyond these manager surfaces.


The initial shared-unary verification passed 1071/1071 combined HTTP/2 and gRPC
tests and 20/20 package tests. The pinned grpc-cpp forward gate creates the
background SharedChannel with healthCheckConfig, submits two concurrent unary
calls through reference-counted send handles, validates their differently
sized protobuf responses, and reports `shared_unary=2+health-gated` over h2c and
certificate-verified TLS on the zio backend.

The hostname manager's targeted verification passed 140/140 shared-channel
tests and 20/20 public package tests. Real TCP cases cover duplicate/reordered
addresses, mixed hostname/static sources and logical authorities, DNS errors
with a retained healthy connection, empty-list retirement, health-gated
candidate switching while an old RPC drains, blocked-lookup cancellation with
retained senders and a zero async budget, resolver concurrency admission,
replacement allocation failure, and connector-cancellation recovery. The
grpc-cpp shared gate now uses hostname targets and an allocator-owned duplicate
address result over h2c and verified TLS, then refreshes the unchanged address
after its concurrent unary calls; both publications produce one endpoint.

## Bounded message delivery for background stream owners

The incremental Decoder exposes feedLimited(bytes, max_messages, context,
consume), returning exact consumed-byte and delivered-message counts. It stops
at a complete message boundary and leaves the remaining input with the caller;
partial prefixes and payloads retain the existing decoder ownership rules.
Compression remains independent for each message, including empty messages.

ClientDuplex.pollResponseEventLimited and its WithDeadline form bound callback
delivery from already-routed DATA. A DATA frame containing several messages
stays owned across polls until its exact remaining suffix is consumed.
Informational/initial metadata and terminal status retain their existing
lifetimes. A terminal event follows every message in the last DATA frame.
Short operation deadlines preserve pending DATA while the original RPC
deadline still governs cancellation; callback/protocol failure discards the
held frame and retires the stream before a later stream can reuse the channel.
The client receive state machine lives in stream/duplex/client_receive.zig.

stageMessage retains a normal framed request message without socket input or
output. A background owner advances it with pollResumeMessageWithDeadline and
then sends an empty request FIN with finishRequestWithDeadline. This provides
the bounded send/receive primitives required by shared streaming handles.

Verification passed 140/140 targeted decoder/duplex tests, including every
prefix/payload split, compressed and empty messages, a paused coalesced DATA
frame while a sibling RPC completes, short-operation-timeout recovery, and
callback rejection followed by connection reuse. The combined HTTP/2 and gRPC
suite passed 1083/1083 tests, public package checks passed 20/20, and the pinned
grpc-cpp forward gate passed h2c and certificate-verified TLS.

## Shared streaming capabilities and bounded receive credit

The reproducible shared TCP performance workloads and their official grpc-cpp
comparison boundaries are documented in [grpc_shared_performance.md](grpc_shared_performance.md).

SharedChannelSender.startDuplex accepts StreamingRequestOptions and returns an
owning SharedClientDuplex. Its writer() and reader() methods create retained
SharedStreamWriter and SharedStreamReader capabilities. A read may run
concurrently with a write on the same RPC; each direction allows one outstanding
operation and reports InvalidStreamState for overlapping operations in that
direction. Writer/Reader clones share the same RPC. The owning duplex cancels
and joins transport retirement on destruction, while retained capabilities
observe the completed cancellation or channel closure.

The shared queue applies method timeout, directional message limits and
waitForReady from the owned service config. One absolute RPC deadline begins
before admission and is emitted in grpc-timeout when HEADERS are committed.
Each endpoint exclusively owns the HTTP/2 stream and encoder. Writers submit
borrowed message commands, stage compression/framing once, and wait for the
exact final byte to be committed. writeFinalMessage finishes the request with
that message; finishRequest sends an empty FIN after earlier messages. An
operation deadline or task cancellation on a write cancels/joins the RPC before
return, so an abandoned command cannot expose caller-owned bytes to a worker.
Reader operation timeouts leave the RPC available for later reads.
Caller operation deadlines must use the awake clock; other clock domains
return Timeout before composition with the RPC deadline or transport progress.

The endpoint copies encoded response DATA into a bounded per-RPC ring. Its
capacity is the transport's maximum receive stream window (including configured
adaptive growth), limited by SharedChannelOptions.max_buffered_stream_bytes
(default 16 MiB). A receive window above this ceiling fails stream admission
with InvalidSharedOptions. Accepted DATA returns connection credit through
low-watermark refills when at most half the connection window remains. The
reader acknowledges encoded bytes as it dequeues them; the endpoint batches
stream grants until half a window is acknowledged or the receive window is
exhausted. Padding credit returns immediately. This keeps a paused reader from
exhausting connection credit needed by siblings. A reader retains at most one
dequeued chunk plus its bounded message decoder, so a message larger than the
stream window can still complete without buffering an unbounded message list.

The reader owns framing/decompression and returns owned events for information,
initial metadata, one decoded message, and terminal gRPC status. Metadata and
status retain typed resets, compression flags and rich status details. A wire
terminal received before the deadline remains readable after queued DATA is
consumed. Decoder/protocol or allocation failure preserves its original error
and cancels the transport. Known terminal socket-close errors during credit
output restore local accounting so complete buffered DATA/trailers can still
be delivered; uncertain partial output retires connection writes/reuse.

The owner now also commits a terminal staged beside final raw DATA in the
same turn as the encoded bytes enter the ring. The former next-turn deadline
check could replace that already parsed result with Timeout. One completion
helper releases the transport and publishes terminal state plus retirement
together; message decoding and truncated-envelope errors remain consumer-owned.
Real TCP regressions hold that exact turn boundary through deadline expiry and
then reuse the only peer stream slot. The independent response-policy gate now
additionally exercises a shared native connection for DATA FIN/missing-status
and subsequent normal completion, consuming both after their original deadline.
See [the terminal deadline evidence](grpc_shared_terminal_deadline.md).

HTTP fallback bodies with a non-gRPC media type are discarded under the RPC
deadline and return deferred stream credit as their bytes are consumed. A
broken intermediary's body can exceed the stream window without stalling the
fallback status; the same channel remains available for subsequent RPCs.

Unary, server-streaming, client-streaming and bidi patterns all use the same
shared transport primitive. Health admission and DNS candidate selection apply
before opening. A retired endpoint rejects later calls and drains its existing
shared streams before transport teardown, under their original deadlines.
Channel destruction joins all active shared streams before returning.

The HTTP/2 duplex primitive also exposes pollResponseEventWithCreditPolicy and
its AndDeadline form to select immediate or low-watermark connection credit.
releaseResponseStreamCreditBatchedWithDeadline returns the acknowledged amount
or zero when the caller must retain its consumed-byte acknowledgement. The
existing immediate receive/release entry points preserve their wire behavior.
ClientDuplex.pollRawResponseEventBatchedWithDeadline applies the same policy to
encoded gRPC DATA without mixing raw and decoded receive modes.

    var rpc = try sender.startDuplex(.{
        .path = "/demo.Echo/Bidi", .wait_for_ready = true,
        .timeout = .{ .value = 5, .unit = .second },
    });
    defer rpc.deinit();
    var writer = rpc.writer();
    defer writer.deinit();
    var reader = rpc.reader();
    defer reader.deinit();
    try writer.writeMessage(payload);
    try writer.finishRequest();
    while (true) {
        var event = try reader.next();
        defer event.deinit(allocator);
        if (event == .terminal) break;
    }

## Shared RPC lock admission

Background SharedChannel unary, explicit-retry unary and duplex startup now
retain the caller's original awake deadline through both initial state admission
and queue admission. Owned service configuration is immutable after channel
construction and remains alive through the retained Sender/State references;
method timeout resolution therefore happens before the first lock wait. Explicit
timeouts, inherited service-config timeouts and stricter configured caps all
use the timestamp captured at logical RPC entry. Calls without an RPC timeout
still use cancelable mutex admission.

An admission Timeout or Canceled result leaves queue links, demand, retry
attempts and endpoint selection untouched. A duplex call allocated before
queue admission may be retired by its sole opening owner without reacquiring
the shared mutex: it has never been submitted to a worker and no capability has
been returned to the user. This releases the provisional call and parent
reference even while another owner still holds the state lock. Registered jobs
continue using the existing worker/cancellation retirement protocol so producer
buffers remain alive until the endpoint no longer borrows them.

The regressions cover eighteen explicit/inherited/capped RPC deadline outcomes,
four no-timeout cancellation cases, two direct timed queue admissions and two
post-allocation stream admission failures. Each observes the original error
while the state mutex remains occupied, verifies unchanged queue/reference
counts, and checks that the unsubmitted stream allocation is released once.
The fixed-version grpc-cpp gate also holds a live native shared State mutex
before unary and duplex calls, requires both 10 ms timeouts without queuing,
then completes the existing concurrent unary, health admission and duplex
exchange over h2c and verified TLS. Evidence is recorded in
`docs/evidence/grpc_shared_admission/2026-10-29.json`.

This establishes pre-submission lock admission. Registered-job cancellation
is covered separately below because it must preserve request ownership after
the interrupted caller has already returned.

## Shared RPC interruption and asynchronous retirement

Queued and assigned SharedChannel jobs are now reference-counted objects rather
than caller-stack records. Unary jobs deep-own their path, authority, scheme,
ASCII and binary metadata, and request message. Streaming calls deep-own the
same request description, while their admission job retains the stream call.
The queue or endpoint holds an independent job reference until it publishes a
result or destroys a late result whose caller has already departed. This is the
same lifetime boundary used by gRPC Core's queued subchannel calls: the queue
keeps a referenced call object and cancellation invalidates the queued entry
without requiring the surface call to wait for transport cleanup.

One atomic completion state arbitrates endpoint completion against caller
Timeout/Canceled. If interruption wins, the caller marks the job abandoned,
publishes deferred queue cleanup and returns without acquiring the shared state
mutex or waiting for endpoint retirement. A best-effort lock handoff removes a
queued job immediately when the mutex is free; otherwise the current or next
mutex owner inherits cleanup. An assigned job retains its endpoint wake object,
so it can notify the single connection owner safely even when resolver churn or
channel shutdown retires that endpoint at the same time. The endpoint remains
the sole HTTP/2 owner and therefore emits cancellation before admitting later
work on that connection. If completion wins the race, its release store makes
the response/error visible and transfers the result exactly once.

Focused regressions hold the state mutex across both timeout and executor
cancellation, for queued and assigned calls, and require the caller to return
without an uncancelable mutex or retirement wait. Ownership tests mutate every
caller input after departure, inject allocation failures at each clone point,
destroy late successful responses, and verify parent, stream and wake
references return to baseline. The existing real-TCP cancellation/reuse test
passes ten consecutive runs, preserving RST_STREAM(CANCEL) before the next RPC
on the same HTTP/2 connection.

That narrower timing also exposed a pre-existing error-path bug in the HTTP/2
GOAWAY, RST_STREAM and WINDOW_UPDATE owned-frame readers: an unexpected stream
frame was freed manually and then again by `errdefer`. All three readers now
leave error cleanup to the single owner, with a real-connection regression that
delivers an unexpected HEADERS frame to each API and requires
`UnexpectedFrame` without a leak or double free. The complete gRPC filter set,
package surface and pinned grpc-cpp h2c/TLS matrix pass after the change.
Evidence is recorded in
`docs/evidence/grpc_shared_retirement/2026-10-29.json`.

## Shared active-stream cancellation

An admitted `SharedClientDuplex` now exposes cancellation separately from
transport retirement. `requestCancel()` atomically publishes cancellation and
wakes the one endpoint owner without acquiring the shared state mutex or
waiting for an HTTP/2 reset. The call retains that endpoint wake object, so the
notification remains valid if resolver churn retires the worker concurrently.
This follows gRPC Core's active-call pattern: surface cancellation sets an
atomic once and schedules the transport cancel batch asynchronously while call
references keep its state alive.

The existing `cancel()` remains the compatibility join with no deadline.
`cancelWithDeadline()` and `cancelWithTimeout()` request the same cancellation
but bound the optional join with one caller-owned awake timestamp; a timeout
does not revoke the already published cancellation. `deinit()` is now
non-blocking: it requests cancellation and releases only the user's reference,
while the endpoint reference owns HTTP/2 cleanup and final destruction.
Writer and reader capabilities can outlive that owning handle and observe the
terminal cancellation. A write attempted after the atomic publication returns
`Canceled` immediately rather than the less precise `ConnectionClosed`.

The synthetic regression holds the state mutex, withholds endpoint retirement,
and verifies request cancellation, a 1 ms bounded join, and destruction perform
zero mutex or unbounded retirement waits while wake/call/State references stay
valid. A real TCP regression requests cancellation and immediately starts a
unary call on the same channel; the single endpoint owner still sends
RST_STREAM(CANCEL) first, the peer observes the exact code, and the following
RPC succeeds on that connection. The pinned grpc-cpp h2c and verified-TLS
matrix independently performs `requestCancel()`, a bounded retirement join and
unary reuse through the same SharedChannel, and binds this case into its exact
terminal record. The legacy joining cancellation regression continues to pass.
Evidence is recorded in
`docs/evidence/grpc_shared_stream_cancel/2026-10-29.json`.

## Shared stream operation deadlines and ownership

Shared reader and writer operations now carry their deadline through state-lock
admission instead of entering the unbounded internal lock path. An admission
Timeout or executor Canceled result occurs before any cursor, payload or
endpoint-visible command changes ownership, so it remains retryable on the same
RPC. For reads, one atomic busy flag rejects concurrent consumers without a
cleanup lock. The first terminal failure is also published atomically, allowing
decoder/allocation failures and operation interruption to retain their precise
cause without reacquiring State before returning.

Once a write is published, its command is heap-owned and reference-counted. It
deep-copies the request payload and keeps independent caller/endpoint
references, so a timed or canceled caller can atomically abandon the command,
publish the first failure, wake the endpoint and return immediately. The
endpoint may still stage or finish the exact owned bytes, but its late
completion only drops endpoint ownership; it cannot signal or access the
departed caller's stack. Completion that wins the race publishes its result
once and remains visible to the caller. Allocation failure before publication
releases every partial command/payload allocation and leaves the RPC unchanged.

Read lock admission distinguishes an empty wait from already committed local
evidence. Metadata, DATA and terminal status committed before the RPC deadline
remain consumable afterwards, preserving the existing terminal-deadline
contract. A caller-selected read deadline still bounds mutex admission even
when buffered work exists. Once an admitted reader is waiting, executor
cancellation or RPC-deadline expiry atomically fails and wakes the stream; a
shorter read-only timeout keeps the cursor and RPC resumable.

Synthetic regressions hold State across read/write admission for both Timeout
and Canceled, then interrupt already-published read/write operations while the
same mutex remains occupied. They require zero unbounded cleanup waits, exact
first errors, reset atomic read ownership, byte-exact payload retention after
the caller overwrites its buffer, and complete State/call/command reclamation.
The pinned grpc-cpp h2c and verified-TLS gate independently times out write and
read admission under the held State, retries the complete request and response
on that same duplex, then verifies asynchronous cancellation, bounded
retirement and unary reuse. Its terminal record is locked to
`shared_duplex=2+bounded+operation-deadline+async-cancel-reuse`. Evidence is
recorded in
`docs/evidence/grpc_shared_stream_operations/2026-10-29.json`.
