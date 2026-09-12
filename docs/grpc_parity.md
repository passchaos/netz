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
- HTTP status fallback mapping when a broken intermediary omits `grpc-status`,
- typed `identity`, `deflate`, and `gzip` algorithms plus
  `grpc-accept-encoding` parsing/formatting that ignores unknown extensions,
- per-message gzip and RFC 1950 zlib-wrapped `deflate` compression using the
  package-local focused DEFLATE backend, with no cross-message codec state,
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
- unary client deadlines captured once from `grpc-timeout` at API entry and
  enforced locally with the awake clock across request setup and the complete
  HTTP/2 exchange; expiration returns `error.Timeout` and emits
  `RST_STREAM(CANCEL)`, while a null timeout remains unbounded,
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
`grpc_cli` querying a one-shot netz h2c server:

```sh
zig build interop-grpc-reflection -Doptimize=ReleaseFast
```

Generate pbz bindings and exercise all four generated client/handler RPC
shapes over one real h2c channel, including typed handler failure mapping:

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
certificate. Set `GRPC_ROOT` to use the same pinned source revision elsewhere,
or set `GRPC_CPP_INTEROP_SERVER`/`GRPC_CPP_INTEROP_CLIENT` to an already-built
executable. `BAZEL`
may select a non-default Bazel/Bazelisk executable; the script verifies it
matches upstream's checked-in `.bazelversion`. The harness is reproducible even
when a host lacks that exact Bazel release, but such a host cannot establish an
external pass until the pinned tool or a prebuilt server is supplied.

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
`empty_stream`, `client_streaming`, `server_streaming`,
`cancel_after_first_response`, `timeout_on_sleeping_server`, and
`custom_metadata` over both transports. Client streaming checks all four
canonical request payload sizes and the exact aggregate response; server
streaming checks all four canonical response messages. The metadata case runs
a 271828-byte unary request and a bidirectional request on one channel,
requiring the expected 314159-byte responses plus exact ASCII initial-metadata
and raw binary trailing-metadata echoes. Each case requires both the C++
client's successful exit and a netz marker proving the expected terminal
condition. For the upstream test's hard-coded 1 ms TLS deadline, the harness
also records the legitimate race where the client reaches local
`DEADLINE_EXCEEDED` before the TLS accept finishes and no server RPC exists.

The reflection gate passed on 2026-09-07 against the same pinned upstream
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
subset of `grpc.testing.StreamingOutputCallRequest`/`Response` needed by these
cases. It pins its field-number assumptions to the audited source revision and
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

## Remaining work before broad gRPC parity

1. Generated pbz clients and handlers now have netz transport adapters for all
   four RPC shapes, including owned typed failure details. Async/concurrent
   scheduling policy remains above the intentionally single-owner duplex step
   loop.
2. Transport composition is now covered: `grpc.runtime.Client`,
   `grpc.runtime.Server`, and `grpc.runtime.TlsServer` own persistent HTTP/2
   channels. The TLS path enforces `h2` ALPN and retains certificate-
   verification policy; h2c and TLS tests exchange multiple unary calls on one
   connection, and the owning h2c wrappers also compose multi-message request
   and response streams. A focused grpc-cpp gate is now available for external
   server checks of full duplex, metadata, cancellation/channel reuse, and
   deadline propagation over h2c and certificate-verified TLS. The reverse gate
   covers upstream-client ping-pong, client/server streaming, empty-stream
   completion, cancellation, deadline behavior, and unary/bidirectional
   custom-metadata echo against netz over both transports. Broader upstream
   compression, status, and authentication cases remain future work.
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
