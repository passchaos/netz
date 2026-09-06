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
  user-owned `~/project-z/vort` library, with no cross-message codec state,
- strict single-stream decompression with checksum/trailer validation,
  decompressed-size limits, raw-deflate and trailing-data rejection,
- gRPC Core-compatible compression fallback when an encoded message is not
  smaller, and server response fallback when the client did not advertise the
  requested response encoding,
- unary HTTP/2 client/server helpers with initial metadata, trailing metadata,
  trailers-only errors, configurable message-size limits, and explicit
  ownership for decoded request and response messages,
- unary client deadlines captured once from `grpc-timeout` at API entry and
  enforced locally with the awake clock across request setup and the complete
  HTTP/2 exchange; expiration returns `error.Timeout` and emits
  `RST_STREAM(CANCEL)`, while a null timeout remains unbounded,
- sequential request/response message-stream helpers over HTTP/2
  `RequestWriter`, `ResponseWriter`, and borrowed DATA callbacks,
- step-driven bidirectional streams whose single owner alternates request and
  response progress without racing the connection frame reader, including a
  server reply before request FIN and a later client message on the same RPC,
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
- standard `grpc.health.v1.Health/Check` protobuf messages and unary client/
  server helpers over persistent h2c and TLS channels, including the 200-byte
  service-name bound, `NOT_FOUND` for unknown services, and
  `INVALID_ARGUMENT` for malformed requests,
- a concurrent health registry with the standard default `SERVING` status,
  per-service updates/removal, graceful shutdown, and timeout/deadline-aware
  Watch cursors that emit an immediate snapshot and subsequent status changes.

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

By default the gate verifies `~/Work/grpc` is at
`03d65cc67c450ccbb58a8a45627c4da83a886ccd`, builds
`//test/cpp/interop:interop_server` with Bazel, starts it with insecure
credentials on a temporary loopback port, and bounds both readiness and client
execution. Set `GRPC_ROOT` to use the same pinned source revision elsewhere, or
set `GRPC_CPP_INTEROP_SERVER` to an already-built server executable. `BAZEL`
may select a non-default Bazel/Bazelisk executable; the script verifies it
matches upstream's checked-in `.bazelversion`. The harness is reproducible even
when a host lacks that exact Bazel release, but such a host cannot establish an
external pass until the pinned tool or a prebuilt server is supplied.

On 2026-09-02 the full gate passed against upstream commit
`03d65cc67c450ccbb58a8a45627c4da83a886ccd` using Bazel 8.7.0 and GCC on
Linux x86_64. The pinned Bazel output root was placed on tmpfs because this
host's disk-backed extraction stalled in journal waits; that is a host build
performance workaround, not a protocol exception. The successful command was:

```sh
BAZEL=/tmp/bazel87-netz CC=/usr/bin/gcc GRPC_CPP_BUILD_TIMEOUT=3m \
  timeout 5m zig build interop-grpc-cpp -Doptimize=ReleaseFast
```

The independent C++ server build completed all 3492 Bazel actions and the
process-boundary client reported all four scenarios below as successful. Large
responses crossed multiple HTTP/2 DATA frames, additionally exercising decoder
progress events that contain a message fragment but no completed gRPC message.
The reverse gate also passed on 2026-09-02 with the same upstream revision,
Bazel 8.7.0, and GCC. It built upstream's `interop_client` and verified
`ping_pong`, `empty_stream`, `cancel_after_first_response`, and
`timeout_on_sleeping_server` against separate netz server processes. Each case
requires both the C++ client's successful exit and a netz marker proving that
the expected request completion, cancellation, or deadline condition was
observed; this prevents a client-only result from masking a server-side fault.

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
for an incomplete request message. The duplex test sends client message one,
observes the server's reply while the request half remains open, then sends
client message two and completes both halves. A second duplex test covers an
early trailers-only PERMISSION_DENIED response and proves subsequent writes are
rejected. The sequential early-return test gives exactly one
framed message send credit, then verifies that the next write receives a
trailers-only CANCELLED response with decoded `grpc-message` and without
sending the second message, matching the request-stream behavior covered by
upstream gRPC Core's `ServerEarlyReturnTest`.

## Remaining work before broad gRPC parity

1. Build generated service/client bindings on `pbz`, including declarative
   method shapes, application cancellation, and async/concurrent scheduling
   policies above the intentionally single-owner duplex step loop.
2. Transport composition is now covered: `grpc.runtime.Client`,
   `grpc.runtime.Server`, and `grpc.runtime.TlsServer` own persistent HTTP/2
   channels. The TLS path enforces `h2` ALPN and retains certificate-
   verification policy; h2c and TLS tests exchange multiple unary calls on one
   connection, and the owning h2c wrappers also compose multi-message request
   and response streams. A focused grpc-cpp gate is now available for external
   server checks of full duplex, metadata, cancellation/channel reuse, and
   deadline propagation. The reverse gate covers upstream-client ping-pong,
   empty-stream completion, cancellation, and deadline behavior against netz.
   A broader upstream matrix, including reverse custom metadata and TLS, remains
   future work.
3. Add higher-level application cancellation and streaming deadline policy,
   retry policy, reflection, and broader conformance/interop runners. Health
   `Check` and the concurrent state/cursor semantics needed by `Watch` are now
   implemented. A transport-level `Watch` adapter still needs incremental
   message delivery without waiting for END_STREAM, cancellation, and retry/
   backoff policy; it is not claimed as complete. Unary transport deadlines
   are already enforced locally as described above.

The current tests establish unary, sequential streaming, and single-owner
step-driven bidirectional streaming; this is still not broad gRPC Core feature
parity.
