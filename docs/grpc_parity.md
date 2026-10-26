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
- explicit opt-in unary retry policies for replay-safe methods, with at most
  five total attempts, configured retryable status codes, exponential jittered
  backoff, server `grpc-retry-pushback-ms`, and standard
  `grpc-previous-rpc-attempts` metadata. Retries occur only for trailers-only
  responses before the call is committed; one absolute `std.Io` awake-clock
  deadline bounds every attempt and backoff while each retry advertises the
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
  Streaming policies do not silently enable retry without a complete replay
  buffer; recognized `waitForReady` is rejected until the channel owns a
  reconnect policy,
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
   Higher-level concurrent scheduling policy remains above the intentionally
   single-owner duplex step loop.
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
   incremental Watch delivery and cancellation, but automatic client Watch
   reconnection/backoff remains application policy. Unary transport deadlines
   are already enforced locally as described above.

The current tests establish unary, sequential streaming, and single-owner
step-driven bidirectional streaming; this is still not broad gRPC Core feature
parity.

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

TLS 1.3 KeyUpdate responses are included in bounded read/write budgets. A local
timeout or executor failure retains the exact old-epoch response ciphertext;
read, application-write, or explicit pending-write completion resumes that
record before activating the next write epoch. KeyUpdate bytes contribute zero
application progress. A bounded call that encounters another write owner returns
`WriteInProgress`. Socket-backed tests authenticate the next application record
after zero-byte and partial-ciphertext failures and after a blocked read-side
KeyUpdate response, checking that the epoch transition happens once.

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
zio-backed netz unary, sequential and duplex clients each reuse one channel
across the same 22 cases. The peer validates exact request envelopes and counts
all 88 exchanges. It covers every HTTP mapping, explicit status precedence,
missing/trailing metadata, rich status, messages before terminal failure, and
scheme-normalized Host/:authority pairs with default ports, percent-encoded
unreserved host bytes and equivalent IPv6 representations.
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
the 57 native RPCs that use the constructor default, including correct `http`
scheme and connection reuse. Nine further native calls supply equivalent Host
and authority fields and must complete successfully on that same connection.
