# netz vs `~/Work/websocket.zig` parity audit

This audit records direct evidence for the WebSocket portion of the broader
netz improvement goal. It distinguishes feature coverage from measured hot
paths so a codec microbenchmark is not mistaken for complete server
superiority.

## Feature comparison

| Area | netz | `websocket.zig` reference |
| --- | --- | --- |
| HTTP/1 Upgrade client/server | Covered, including host names, IPv4/IPv6, Unix-domain listener/client transports, two-phase application admission before 101 with request metadata, custom acceptance fields, and final 3xx-5xx rejection, client `ConnectAttempt` access to rejected status/headers/trailers/bounded body while legacy `connect*` retains `InvalidResponse`, strict duplicate critical-header checks, upgrade-body rejection, optional client DNS/TCP connect budgets, caller-owned relative/absolute connection deadlines spanning DNS/TCP, TLS where applicable, and the complete HTTP Upgrade, optional absolute request/response-head deadlines over WS/WSS that are not renewed by trickled bytes, and long-running bounded TCP/Unix/TLS supervisors with graceful cancellation plus accept/connection error policy | Covered with configurable handshake parsing, pre-101 handler callbacks and custom response headers, a Unix listener, client TCP/TLS connect timeouts, a server-side handshake timeout, worker pools and coordinated shutdown |
| WSS client/server | Covered through shared TLS transports with host/CA verification, separate resolved-address plus TLS-host connection, optional client identities, caller-provided server identities, optional/required client certificates, verified peer chains and concurrent serving | Client covered; 0.16 README labels the branch experimental, while the audited server API terminates cleartext WebSocket |
| HTTP/2 and HTTP/3 WebSocket (RFC 8441/RFC 9220) | Covered through extended CONNECT client/server adapters. The authenticated HTTP/3 path negotiates CONNECT over QUIC/TLS, preserves masking direction, subprotocol, Origin and permessage-deflate validation, and exchanges data/control/Close frames across split HTTP/3 DATA framing | Neither transport is present in the audited source |
| permessage-deflate | Negotiated and exercised by HTTP/1 and H2 runtimes with no-context-takeover, actual LZ77/Huffman compression and expansion fallback | Negotiation/decompression exists, but audited 0.16 client/server send compression code is disabled |
| Fragmentation / aggregate limits | Strict assembler and runtime message limits, UTF-8 validation after fragmented text assembly | Fragment assembly and configurable message/buffer limits |
| Receive/send ownership | `parseFrameInto`, `receiveMessageInto`, and its absolute-deadline variant use caller storage, including permessage-deflate output with reusable connection scratch on HTTP/1 and RFC 8441; HTTP/1, RFC 8441, and HTTP/3 clients expose `sendBinaryInPlace` for the reference's mutable post-send contract while safe `[]const u8` sends remain available | Reader returns borrowed payloads and allocates/pools compressed output; client send APIs require mutable payloads and leave them masked |
| Close / Ping / Pong | Typed close parsing/writing, close-state guards, automatic Pong and Close replies, deadline-bounded typed peer-Close reads, plus deadline-bounded active Ping/Pong round trips that preserve interleaved application frames for both HTTP/1 Upgrade and RFC 8441. Partial Close frames remain resumable after timeout | Handler callbacks and automatic default control replies |
| Concurrent sends | Serialized by per-connection `std.Io.Mutex`; writers recheck Close state after acquiring it, and HTTP/1, RFC 8441, plus RFC 9220 runtime tests exercise concurrent sends (the H2/H3 cases share one compressed encoder) | Documented thread-safe connection writes |
| TCP/TLS latency policy | TCP_NODELAY defaults on for ordinary accepted and client TCP/WSS sockets; WSS header + first payload bytes fill one TLS record/network write; configurable in runtime limits/connect options | Server enables NODELAY, audited client leaves Nagle enabled unless the embedding application changes the socket |
| I/O abstraction | HTTP/1, HTTP/2, and HTTP/3 adapters consume only `std.Io`; backend selection stays outside the protocol API | Custom epoll/kqueue/Windows server backends |

RFC 8441 now has process-boundary interoperability evidence in addition to the
in-process tests and benchmark:

```sh
zig build interop-websocket-hyper-h2 -Doptimize=ReleaseFast
```

The gate builds the audited `~/Work/hyper` checkout offline, enables Hyper's
HTTP/2 Extended CONNECT setting, and verifies the `CONNECT` method,
`:protocol = websocket`, path and WebSocket version before accepting its
upgraded byte stream. A netz client then sends masked text split across three
WebSocket fragments, validates Hyper's unmasked response, exchanges Ping/Pong
payloads, and completes a deadline-bounded Close 1000/`done` handshake while
checking Hyper's echoed close details. The Hyper fixture parses and writes RFC
6455 framing independently, so this is external RFC 8441 wire evidence rather
than a second netz endpoint.

RFC 9220 now has an owning authenticated HTTP/3 client/server runtime in
`websocket.runtime.h3`. It enables `SETTINGS_ENABLE_CONNECT_PROTOCOL`, waits
for peer SETTINGS, and requires the server to advertise that capability before
opening Extended CONNECT with `:protocol = websocket`. It validates version,
Origin, and subprotocol fields, then carries masked client and unmasked server
frames through streaming HTTP/3 DATA. A real QUIC/TLS test forces each frame
across five-byte HTTP/3 stream contributions and verifies fragmented text,
automatic Ping/Pong, and bidirectional Close. The same test negotiates
permessage-deflate with no-context-takeover and exercises a compressed
fragmented text message.

`zig build interop-websocket-h3-quic-go -Doptimize=ReleaseFast` adds
bidirectional process-boundary coverage against the independently maintained
quic-go v0.59.0 HTTP/3 stack, for both QUIC v1 and v2. In each direction it
requires peer SETTINGS support, TLS certificate verification on the client,
Origin and subprotocol negotiation, masked fragmented client text, an unmasked
server response, two independently reset no-context-takeover
permessage-deflate messages in both directions,
Ping/Pong, and an echoed Close 1000/`done`. Netz limits each HTTP/3 stream
contribution to five bytes, which drives quic-go beyond its automatic
100-packet first key-update threshold; the QUIC v2 cases explicitly select the
pinned v0.59 compatibility profile while the library default remains RFC 9369.
The Go fixture
implements its own bounded RFC 6455 frame reader/writer, so this is external
wire evidence rather than two netz adapters sharing a codec.

`zig build interop-websocket-chrome -Doptimize=ReleaseFast` now drives Chrome's
native browser WebSocket API against the HTTP/1 runtime. The first connection
comes from a disallowed origin and must fail before Upgrade; a second origin is
accepted and verifies client-preferred subprotocol selection, actual
permessage-deflate traffic in both directions, text and binary messages,
browser-generated Pong for a server Ping, and a clean 1001 close with the exact
reason. Passing `-- --tls` repeats the same matrix over native TLS 1.3 using a
fresh short-lived certificate and an exact Chrome SPKI pin rather than a global
certificate-error bypass. The captured gate used Chrome 146.0.7680.164. Chrome
does not expose Pong frames or compressed-wire flags to JavaScript, so those
two properties are asserted by the independent netz server endpoint on the
same real browser connection while the browser verifies decoded payloads and
close metadata. Browser coverage for RFC 8441/9220 remains limited by the
standard browser WebSocket API's HTTP version selection and current browser
support.

`websocket.runtime.TlsServer` performs TLS 1.3 before the same transport-neutral
HTTP Upgrade parser and frame state machine used by cleartext `Server`.
End-to-end tests cover verified localhost CA/SAN, strict subprotocol selection,
encrypted binary echo, public-client mTLS with server pin verification and
application-visible client certificate chains, and the shared close/ownership
path. Setting `ConnectOptions.tls_identity` on the existing TLS host/URI
helpers selects the same vail stream transport as native MQTT TLS; absent a
pin/custom verifier, it maps caller CA bundles or system roots plus hostname
verification. TLS
client reads are true short reads, so a small Upgrade response no longer waits
for a caller's larger scratch buffer to fill.

HTTP/1 TCP, Unix, and native TLS servers expose the same two-phase admission
surface. `receiveUpgradeRequest*` parses and validates the opening handshake but
does not send 101; its owning `PendingUpgrade` exposes the target, request
headers, and authenticated WSS certificate/cipher/hash metadata. Applications
may then call `acceptWithHeaders` to add validated response fields or `reject`
with a final 3xx-5xx response and body; convenience 403, 404, and 429 helpers
cover common policy outcomes. Rejections always add `Connection: close`, and
both outcomes prevent applications from overriding WebSocket negotiation or
HTTP body-framing fields. The original absolute handshake deadline remains in
force across the application decision instead of being renewed before the
response write. A pending value owns the transport until one outcome succeeds;
validation or write failures leave that ownership with the caller so `deinit`
can close it deterministically. Existing `accept*` entry points remain
compatible wrappers that receive and immediately accept. End-to-end TCP, Unix,
and WSS tests inspect credentials before 101; the TCP tests additionally prove
that no response is sent before admission, custom acceptance fields survive the
wire, a 401 response carries its body and closes, and delayed admission expires
the original deadline. This closes the reference server's pre-upgrade handler
gap without introducing a callback or worker-pool policy into the transport.
RFC 8441 now exposes the same decision boundary through
`H2Server.receiveUpgradeRequest*` and `PendingH2Upgrade`. Applications can
inspect the CONNECT stream ID, path, scheme, authority, and request fields
before any 200 response, then accept with additional response fields or reject
with a final 3xx-5xx response. `rejectWithBody` can additionally send an
ordinary HTTP/2 DATA body and final trailers; framing fields remain adapter-
owned so the generated Content-Length matches the bytes on the wire. Rejecting
or dropping a pending value terminates only that HTTP/2 stream, leaving sibling
requests and the shared HPACK state usable. Deadline variants retain their
original absolute budget across the application decision. Real h2c tests cover
metadata, custom acceptance fields, Content-Length and END_STREAM-delimited
rejection bodies, trailers, body-limit cancellation, 401 rejection followed by
a successful sibling request, and delayed-decision timeout. Existing
`H2Server.accept*` calls remain immediate compatibility wrappers.
`H2Client.openAttempt*` completes the other side of that policy: final non-2xx
status, response fields, bounded body, and trailers remain owned and
inspectable, while `requireAccepted` and the legacy `open*` wrappers retain
strict WebSocket negotiation and `InvalidStatus` behavior after draining the
complete rejection. The body bound is the caller-owned HTTP/2 connection's
`Limits.max_body_bytes`; an overflow cancels only that stream. The underlying
HTTP/2 attempt API retires rejected streams immediately, so the connection can
issue a sibling request after authentication failure.
RFC 9220 exposes the corresponding `Server.receiveUpgradeRequest*` and
`receiveSessionUpgradeRequest*` entry points. Its `PendingUpgrade` owns the
HTTP/3 session while the decision is pending, exposes CONNECT
path/authority/headers, preserves the original handshake deadline through the
application decision, and can either add accepted response fields or emit a
final 3xx-5xx rejection. A pending value created from a caller-owned session
returns that session after rejection or destruction; acceptance still
transfers it into the WebSocket connection.
`rejectWithBody` adds ordinary HTTP/3 DATA and final trailers, with automatic
Content-Length when a body is present and framing fields kept under the
adapter's control. Short-lived rejection drains reliable QUIC recovery before
session teardown on a best-effort bounded budget. Existing `accept*` methods
remain immediate wrappers.
`Client.connect*Attempt*` retains the complete non-2xx response body and
trailers under `Limits.max_rejection_body_bytes`, rejects an oversized declared
Content-Length before allocating or reading DATA, and skips bounded 1xx heads
before the final response. Declared-length bodies use one exact retained
allocation even when DATA arrives fragmented; unknown-length rejections keep
the bounded incremental path. Compatibility `connect*` calls still return
`InvalidResponse`, but only after draining the rejection. Caller-owned HTTP/3
sessions are restored after a complete rejection without an unnecessary
stream cancellation; limit failures abandon only the affected CONNECT stream.
Authenticated transport tests cover 103 followed by body/trailers, automatic
Content-Length, split DATA without Content-Length, legacy draining, body-limit
cancellation, explicit server rejection and dropped pending requests, and a
successful sibling request on both reused client and server sessions.

The reference has a richer callback-oriented standalone server surface and
pooled-buffer/thread-pool configuration. Netz has broader protocol integration
(shared HTTP/TLS APIs and RFC 8441), but those are different strengths rather
than proof that every server workload is faster.

`websocket.runtime.UnixServer` and `Client.connectUnix` now cover the local
IPC transport exposed by the reference. They reuse the ordinary HTTP/1 Upgrade,
subprotocol, permessage-deflate, frame and close state machines rather than
forking a Unix-only protocol path. The client requires an explicit HTTP Host
authority because a filesystem socket path is not one; the listener deliberately
does not apply the TCP-only NODELAY option. Both HTTP/1 and WebSocket Unix
listeners expose the same bounded `serveConcurrent` shape as TCP. An end-to-end test negotiates a
subprotocol and compression, exchanges text in both directions, and closes over
a real filesystem Unix socket.

Client `ConnectOptions.connect_timeout` now bounds hostname resolution and all
TCP address attempts with one awake-clock deadline for WS, WSS, literal-IP,
hostname, URI and Unix-socket helpers. The connect task is cancellation-aware,
and a connection that wins concurrently with the timer is explicitly closed if
it was not selected. This is separate from the TLS and HTTP Upgrade handshake
budgets, so enabling it cannot silently shorten a configured response-head
deadline. Standard-library and vail-backed WSS clients both honor the public
`ConnectOptions.tls_handshake_timeout`; the nested vail option may override it
when a distinct policy is required. The audited websocket.zig client also exposes connect timeouts; netz
now covers the same liveness boundary without its POSIX-only nonblocking/poll
implementation.

HTTP/1 Upgrade clients now also accept typed `ConnectOptions.extra_headers`,
matching the reference client's custom handshake-header facility without its
raw string injection surface. The option is shared by WS, WSS, and Unix-socket
entry points. Header syntax is validated, and fields owned by the
runtime (Host, Upgrade, Connection, Origin, WebSocket negotiation fields) or
capable of adding an HTTP request body (Content-Length, Transfer-Encoding and
Trailer) are rejected before any request bytes are sent. This supports common
Authorization and Cookie handshakes without permitting duplicate critical
fields or ambiguous body framing. The fully encoded request head is also
checked against `Limits.max_head_bytes` before the first transport write.
HTTP/1 Upgrade parsing now also threads explicit `Limits.max_request_headers`
and `Limits.max_response_headers` into every WS/WSS handshake request/response
parser call, so header-count bounds are independent from the byte budget on
both server and client paths.

## Direct frame hot-path evidence

Run:

```sh
zig build bench-websocket-frame -Doptimize=ReleaseFast
taskset -c 0 zig build bench-websocket-receive-buffer -Doptimize=ReleaseFast
```

The receive-buffer benchmark exercises 8,192 coalesced eight-byte frames over
20 iterations. Five CPU-0 runs measured 2.14-2.17 ns/frame for the retained
read-window implementation versus 489.24-497.03 ns/frame for eager tail
compaction, a 226-231x synthetic speedup. More importantly, it reduced copied
bytes from 5,368,053,760 to 1,305,600: HTTP/1, RFC 8441, and RFC 9220 receive
paths are now amortized linear rather than quadratic when a transport read
contains many small frames. The benchmark is intentionally adversarial and is
not presented as an end-to-end network throughput ratio.

The 2026-08-17 same-host sample ranges for 200,000 masked 4 KiB binary frames:

```text
netz allocating masked frame:        85-97 ns/op
netz caller-buffer masked frame:      71-82 ns/op
netz header-only stream preparation:  0.54-0.56 ns/op
websocket.zig header + copy/mask:      101-127 ns/op
```

The reference measurement calls `proto.writeFrameHeader`, copies the immutable
payload into scratch, then calls its SIMD `proto.mask`. Copying is required for
an equivalent contract: the reference client API accepts `[]u8` and masks it
in place, while netz accepts `[]const u8` and preserves caller memory.
The same benchmark now includes incremental UTF-8 validation of 4 KiB ASCII
and sparse-Unicode telemetry messages. A vector high-bit scan skips complete
ASCII blocks only while no multibyte sequence is pending, then resumes after
the original byte state machine completes each Unicode code point. One CPU-0
run measured 40.32 ns/message versus 2007.79 ns for the directly invoked
scalar ASCII path (49.80x), and 301.08 versus 2184.19 ns for sparse Unicode
(7.25x). Split multibyte sequences plus valid and invalid high bytes at every
offset across several vector boundaries retain direct regression coverage.
Masked client text uses the same no-copy validator: it XORs and checks ASCII
blocks as vectors, preserves all four mask phases across partial transport
reads, and falls back to the incremental code-point state machine only when
needed. One CPU-0 same-process run measured 58.37 ns per 4 KiB message versus
2097.76 ns for the former scalar XOR/feed loop, a 35.94x speedup.
HTTP/1, RFC 8441, and RFC 9220 receive paths also reuse the `FrameHeader` they
already parsed to size their transport read instead of decoding the same
variable-length header again in the complete-frame codec. The frame benchmark's
same-process masked short-frame loop measured 4.30 ns/frame with header reuse
versus 7.85 ns/frame for the former duplicate parse, a 1.83x reduction in that
fixed parser component. Length-boundary and masked/unmasked equivalence tests
cover both allocating and caller-buffer predecoded APIs.
Aggregate H1 and RFC 8441 receives now also assign UTF-8 ownership to the
incremental `MessageAssembler`: message-mode frame parsing skips its whole-frame
scan, and finalization trusts only the assembler's internal proof for
uncompressed text. Compressed text and externally constructed messages retain
the final validation pass. Thus ordinary complete text is validated once while
fragmented text still rejects a malformed sequence at the decisive byte.
Caller-buffer H1/RFC 8441 receives retain their existing transport-read
fail-fast validator but no longer rescan the complete uncompressed message;
the shared resumable state carries the validation proof across continuation
frames and timeout retries. RFC 9220 now advances that same validator after
each completed WebSocket fragment instead of waiting for the complete message.
Compressed caller-buffer text remains validated after inflation.

Netz's actual unmasked TCP server path prepares only the validated stack header
and uses one vectored network write for header + borrowed payload. Masked
clients copy and mask in one SIMD pass through a fixed 16 KiB stack scratch,
so payload size no longer drives heap allocation.

The same command also measures one 4 KiB repeated telemetry-like message
through no-context-takeover compression. Complete and discontiguous messages
now use project-local vort fixed-DEFLATE sync-flush encoders, whose small-input
hash paths avoid clearing Zig flate's roughly 224 KiB compressor state per
message. The chunked encoder keeps plaintext discontiguous while a bounded
16 KiB rolling dictionary preserves matches across caller slices.

```text
permessage-deflate: 5.55-5.88 us/message, 4096 -> 69 wire bytes
16-slice streaming: 5.77-6.10 us/message, 4096 -> 69 wire bytes, no join
```

These are three CPU-14-pinned `ReleaseFast` runs on 2026-08-20. Compared with
the original standard-library encoder baseline, the fragmented path is
8.4-8.9x faster. Adjacent slice coalescing, rolling history and one shared
fixed block also reduce the first vort chunked path's 463-byte payload to the
same 69 bytes as the complete-message path. This remains an
internal encoder baseline and compression-ratio example, not a cross-library
speed ratio: the audited websocket.zig 0.16 send paths currently hard-code
`compressed = false`, so no equal compressed-send workload exists there.

## Persistent echo evidence

The end-to-end benchmark uses one real HTTP/1 upgraded connection, 20 untimed
warmup exchanges, then 200 measured 4 KiB binary echo round trips. Client
requests are masked, server replies are unmasked, both wire frames use minimal
16-bit extended lengths, and both clients copy the echoed application payload
back into their mutable send buffer before the next round. Handshake time is
excluded. This evidence covers the public backend-neutral `std.Io` TCP runtime.

The same executable accepts `--compression`, negotiating permessage-deflate on
both endpoints and exercising retained send/receive scratch plus direct caller-
buffer inflation over a real upgraded connection. Five 2026-08-20 CPU-0 runs
measured 29.44-31.14 us/roundtrip (250.91-265.34 logical payload MiB/s),
4.6-5.0x lower latency than the previous 144.6-147.5 us range. Three four-
connection CPU 0-7 runs measured 12.09-12.18 us aggregate/roundtrip and
641.52-645.95 logical MiB/s, versus the previous 45.96 us/169.98 MiB/s. These
are internal compressed-runtime baselines because the
audited websocket.zig outbound compressor remains disabled.

Adding `--fragmented` sends the same client payload as sixteen application
slices while the server continues to echo one complete message. Three CPU-14
runs measured 35.80-36.60 us/roundtrip and 213.48-218.24 logical MiB/s after
the runtime began batching small masked and unmasked compressed continuation
frames. The same workload previously took 129.24 us/roundtrip before batching.
The complete-message control measured 30.65-30.91 us/roundtrip, so preserving
sixteen RFC 6455 frame boundaries costs 16.8-19.4% rather than multiplying
socket writes sixteenfold. All runs verified checksum 51,000.

RFC 8441 has a separate `bench-websocket-h2-echo` gate with the same warmup,
iteration, payload and compression shape. Three CPU-14 complete-message runs
measured 37.91-38.44 us/roundtrip and 203.23-206.05 logical MiB/s; sixteen-
slice runs measured 43.66-44.00 us and 177.56-178.94 MiB/s. Before coalescing
the RFC 6455 frame sequence into one flow-controlled tunnel write, the same
fragmented gate took 98.55-137.68 us. The batch therefore reduces latency by
2.2-3.2x while preserving every WebSocket frame boundary; its remaining
15.1-16.0% cost versus one frame is the real framing/masking work. Each run
verified checksum 51,000.
After removing RFC 8441's payload-sized send-frame buffer, five CPU-0 runs of
the same sixteen-slice compressed workload measured 37.032-38.500 us/roundtrip
(37.651 us mean, 37.372 us median, 1.55% relative standard deviation,
202.91-210.96 logical MiB/s). The common sixteen-frame case still uses one
bounded stack batch, so the prior coalescing benefit is retained while the
connection no longer owns a duplicate encoded-message allocation.
The HTTP/2 Extended CONNECT, traditional CONNECT, and tunnel-response builders
now stage their pseudo-headers and ordinary headers in 16-entry stack buffers,
matching the ordinary HTTP/2 request/response path. Larger application header
sets retain an exact heap fallback. A fail-first unit test proves the full
common stack capacity does not allocate and that the first overflow reports OOM
cleanly before a successful fallback allocation. The 1,595-test suite and the
external Hyper RFC 8441 fragmented-text/Ping/Pong/bounded-Close gate remain
green, as does the broader bidirectional Hyper h2c/TLS gate. Five CPU-0 4-KiB
RFC 8441 echo runs measured 31.105-31.955 us/roundtrip (31.507 us mean, 0.94%
standard deviation, 244.48-251.16 logical MiB/s). This is a persistent-connection
regression sample; the one-time CONNECT allocation removal is intentionally not
presented as a steady-state echo throughput gain.
RFC 8441 server application frames now keep their RFC 6455 header on the stack
and pass it with the borrowed payload to `Tunnel.writeParts`. HTTP/2 applies
DATA frame sizing and connection/stream flow control across that logical join,
including a DATA frame that contains the end of the WebSocket header and the
start of its payload, without retaining a payload-sized frame buffer. An
8-KiB-window regression sends more than 16 KiB to force multiple WINDOW_UPDATE
and client masking cycles, then verifies the complete message plus zero retained
frame scratch. Client frames still require
masking, but now stream through the same bounded 16-KiB stack scratch used by
HTTP/1 WebSocket instead of retaining the complete masked frame. The
constrained-window regression verifies zero retained frame scratch in both
directions and uses the two-part API so HTTP/2 DATA framing crosses both the
WebSocket header/payload and application-slice joins. A separate negotiated
permessage-deflate test verifies the two borrowed slices are compressed as one
binary message in both directions and still do not grow frame scratch.
Five CPU-0 4-KiB regression samples after adding H2 two-part writes measured
30.987-32.321 us/roundtrip (31.394 us mean, 31.072 us median, 1.63% relative
standard deviation, 241.71-252.11 logical MiB/s). The range
overlaps the earlier samples, so it is recorded as no demonstrated steady-state
speedup; the proven improvement is eliminating payload-sized retained scratch
on both directions of the ordinary single-frame path. The full 1,604-test suite
and the bidirectional Hyper RFC 8441 gate remain green.

The first compressed frame is copied once from the transport/caller frame
buffer into retained compressed scratch. This is intentional: Zig's raw
inflater may overwrite output before consuming aliased input. A regression test
checks that scratch holds the exact wire payload before caller-buffer inflate.
Uncompressed binary messages also accept two borrowed application slices. The
server submits header plus both slices without concatenation, using
scatter/gather where the transport supports it; the client masks both through
bounded stack chunks while carrying the RFC 6455 mask offset across the slice
boundary. The receiver still observes one binary frame, which lets
MQTT-over-WebSocket avoid concatenating its encoded packet prefix and application
payload without changing message boundaries. Header-length parity tests cover
the 125/126/65535 transitions and a bidirectional runtime test covers continuous
masking across the join. When permessage-deflate is negotiated, the same API
feeds both borrowed slices directly to the retained Vort encoder rather than
allocating and copying a contiguous plaintext message. A fail-after-warmup
runtime test verifies that repeated compressed two-part sends do not allocate
through the connection allocator.

Netz uses `sendBinaryInPlace` and `receiveMessageInto`; the former deliberately
leaves caller storage masked, matching websocket.zig's mutable-input contract,
while the latter assembles fragments and handles control frames without a
message allocation. With permessage-deflate, the decompressed message lands
directly in the caller buffer. TCP and RFC 8441 connections retain bounded
compressed-wire scratch plus a reusable receive DEFLATE history window. Both
complete and fragmented sends use vort's native raw fixed-block sync flush;
the fragmented form feeds per-slice token plans into one block without joining
plaintext and carries up to 16 KiB of prior plaintext as match history. Both
paths remove the RFC 7692 suffix and set RSV1 only when the wire payload is
strictly smaller; incompressible/small input is sent unchanged rather than
paying expansion, and payloads below 32 bytes skip compressor setup entirely.
No-context-takeover resets codec state for every message
while retaining wire buffers. RFC 8441 caller-buffer receive now writes each
uncompressed frame directly into application storage and each compressed
continuation directly into codec scratch; it no longer allocates every frame
or retains a second whole-message buffer. Vort's current hash parser allocates temporary
match state per compressed send; receive-side codec storage is allocation-free
after first-use warmup. The H2 adapter retains tunnel/frame and codec scratch
but avoids separate application-message and decompressed-message allocations.
Buffered regressions prove both an uncompressed fragmented message with an
interleaved control frame and a warmed compressed fragmented message complete
without another caller-allocator allocation. A CPU-0 ReleaseFast regression
run measured 31.566 us/roundtrip for one 4-KiB frame and 37.087 us for sixteen
fragments, with checksum 51,000 in both cases; these overlap the prior ranges
and document that removing the duplicate receive buffer did not trade memory
for a visible throughput regression.
Fragmented compressed sends no longer concatenate plaintext first: each caller
slice feeds the same bit-packed DEFLATE stream directly, UTF-8 is validated
across slice boundaries with four bytes of state, and only compressed wire
scratch remains. A wire-level regression also verifies that requested frame
count/FIN boundaries survive compression and only the first frame carries RSV1.
Tests cover a zlib-generated dynamic-DEFLATE fixture, fragmented compressed
text with interleaved PING, send/receive scratch reuse under failing allocators,
actual wire shrink plus RSV1, expansion fallback without RSV1, output overflow,
and H2 compressed caller storage in both directions.
The authenticated HTTP/3 adapter now uses the same chunked-input Vort encoder
and incremental UTF-8 validation. It retains only compressed output, preserves
the caller's fragment count on the wire, and no longer allocates a joined
plaintext message before sending RFC 9220 DATA.
TCP and RFC 8441 receive APIs now also complete the RFC 6455 failure handshake:
malformed frames send Close 1002, invalid message UTF-8 sends 1007, and frame,
aggregate-message, or decompression limits send 1009 before returning the typed
local error. Nested frame/message readers suppress duplicate Close frames.
Both transports also expose absolute-deadline message reads. RFC 8441 carries
the same deadline through HTTP/2 frame parsing, connection-control frames,
WebSocket fragmentation and Ping/Pong handling, so upper-layer inactivity
budgets cannot be extended by transport control traffic.
One earlier four-connection `--stats` run made 7,151 allocations, allocated
48,068,236 cumulative bytes and peaked at 1,240,114 live bytes while verifying
checksum 111,600. Vort's fixed-sync-flush encoder now writes directly into the
connection-owned output list and resets retained arena-backed token/hash/history
workspace between no-context-takeover messages. A 2026-08-23 one-connection,
220-exchange rerun reduced allocator calls from 1,791 to 33 and cumulative
allocation from 11,885,411 to 231,619 bytes for complete 4 KiB messages. The
sixteen-fragment form likewise used 33 calls and 231,707 cumulative bytes; both
retained about 114 KiB live at report time. A failing-allocator regression
proves that a warmed fragmented encode performs no further caller-allocation.

```sh
taskset -c 0 zig build bench-websocket-echo -Doptimize=ReleaseFast

zig build-exe -OReleaseFast -lc \
  --dep websocket --dep counting_allocator \
  -Mroot=benchmarks/reference/websocket_zig_echo.zig \
  --dep build \
  -Mwebsocket=/home/passchaos/Work/websocket.zig/src/websocket.zig \
  -Mcounting_allocator=examples/support/counting_allocator.zig \
  -Mbuild=benchmarks/reference/websocket_zig_build_options.zig \
  -femit-bin=/tmp/bench-websocket-zig-echo
taskset -c 0 /tmp/bench-websocket-zig-echo --tcp-nodelay
```

Twenty alternating CPU-0 samples with TCP_NODELAY enabled on both clients:

```text
netz:
  9.146-10.537 us/roundtrip
  median 9.501 us, trimmed mean 9.539 us

websocket.zig:
  13.231-14.406 us/roundtrip
  median 13.630 us, trimmed mean 13.702 us

netz latency advantage:
  1.435x by median, 1.436x by trimmed mean
```

A CPU-0 `ReleaseFast` regression run on 2026-09-04 after adding two-phase
admission measured 9.513 us/roundtrip, 105,117 roundtrips/s, and 822.44 MiB/s
of uncompressed-equivalent wire throughput. Handshake time is excluded, so the
sample confirms that the new pre-101 control path did not alter the established
frame hot path; it is not presented as a new throughput improvement.

The websocket.zig public client defaults to Nagle enabled and writes its masked
header then payload separately. Five default-socket samples were about
41.09-41.38 ms/roundtrip, while netz's vectored header+payload submission was
10.26-10.71 us in that run. This roughly 3,915x cliff is specifically Linux
Nagle/delayed-ACK interaction, not a broad library ratio. `strace -f -c`
recorded about 442 netz sendmsg calls versus 443 reference sendmsg plus 228
writev calls for 220 total exchanges. The tuned TCP_NODELAY comparison above is
the primary implementation result.

### Four concurrent persistent connections

The same benchmark accepts `--connections=4`. All clients finish 20 warmup
exchanges, wait on one start event, then execute 200 measured round trips each.
Aggregate latency divides wall time to the slowest client by all 800 measured
round trips; handshake, warmup, shutdown, and joins remain outside the timed
interval. Both processes were restricted to CPUs 0-7.

```sh
taskset -c 0-7 zig build bench-websocket-echo \
  -Doptimize=ReleaseFast -- --connections=4
taskset -c 0-7 /tmp/bench-websocket-zig-echo \
  --tcp-nodelay --connections=4
```

Twenty alternating samples:

```text
netz:
  3.788-4.802 us aggregate/roundtrip
  median 4.150 us, trimmed mean 4.173 us
  median 240,993 roundtrips/s, 1,885.51 wire MiB/s

websocket.zig:
  4.912-5.653 us aggregate/roundtrip
  median 5.212 us, trimmed mean 5.221 us
  median 191,883 roundtrips/s, 1,501.28 wire MiB/s

netz aggregate-latency advantage:
  1.256x by median, 1.251x by trimmed mean
```

### Mixed payload and higher-concurrency coverage

Both checked-in echo harnesses now accept `--mixed` and use the identical
deterministic `1, 7, 125, 126, 1024, 4096`-byte schedule. This crosses the
RFC 6455 7-bit/16-bit payload-length boundary while retaining tiny control-like,
medium and 4-KiB application messages. Reports use the exact 200-iteration
schedule rather than multiplying by an average, and both sides verify the same
payload checksum. The websocket.zig fixture's fixed 16-entry benchmark arrays
were replaced with bounded dynamic storage and its connection cap was raised to
256, matching netz. Passing `--latency` now records every measured exchange
and reports p50, p99 and p99.9 separately for each payload size. Sampling is
opt-in so ordinary throughput and allocator runs retain their previous
instrumentation shape.

Three CPU-0..31 runs at 64 concurrent persistent connections produced:

```text
netz:
  0.940-0.988 us aggregate/roundtrip
  1,011,630-1,063,066 roundtrips/s

websocket.zig:
  1.274-1.406 us aggregate/roundtrip
  710,848-784,670 roundtrips/s

netz advantage:
  1.289-1.496x across the observed throughput ranges
```

All runs verified 22,753,024 logical payload bytes and checksum 4,846,784. The
netz harness now gives its blocking handlers an unlimited async resource limit;
the former default could strand connections above the host's CPU count behind
handlers waiting for their next echo. The websocket.zig reference uses its
blocking worker implementation, and its fixed 16-entry benchmark bookkeeping
was replaced with bounded dynamic arrays. Both harnesses now permit 256
connections rather than imposing an artificial 16-connection ceiling.

Five alternating CPU-0..31 runs at 128 connections with `--mixed --latency`
extended the equal-shape evidence beyond the earlier 64-connection point. All
runs verified 45,506,048 logical payload bytes and checksum 9,762,432. Median
aggregate results were 1,283 ns/roundtrip and 779,291 roundtrips/s for netz,
versus 1,639 ns and 610,007 roundtrips/s for websocket.zig, a 1.28x throughput
advantage. Median-of-run per-class latency percentiles were:

```text
payload   netz p50/p99/p99.9 us   websocket.zig p50/p99/p99.9 us
1 B       96.6 / 426 / 1777       154.6 / 487 / 2180
7 B       88.7 / 345 / 783        148.5 / 460 / 1252
125 B     93.0 / 430 / 1264       149.7 / 645 / 2900
126 B     92.2 / 325 / 1570       149.6 / 436 / 2280
1024 B    95.4 / 333 / 813        154.0 / 496 / 2381
4096 B    98.9 / 439 / 970        157.6 / 513 / 1509
```

Netz is lower at every reported class/percentile in this five-run summary.
The sample count per class is also printed (4,224 or 4,352 here), making
schedule or aggregation drift visible rather than silently comparing different
distributions.

The maximum shared 256-connection setting also completed three alternating
CPU-0..31 latency runs. Median aggregate results were 1,062 ns/roundtrip and
941,113 roundtrips/s for netz versus 1,394 ns and 717,186 roundtrips/s for the
reference, a 1.31x advantage. All runs verified 91,012,096 logical payload
bytes, checksum 19,800,064, and matching per-class sample counts of 8,448 or
8,704. Per-run tail values remain scheduler-sensitive at this saturation
level, so the 128-connection table above is the detailed class comparison.

One `strace -f -c` run recorded about 1,768 netz `sendmsg` calls. The
reference recorded about 1,772 `sendmsg` plus 892 `writev` calls: its client
still sends mask/header separately from payload. Tracing perturbs latency, so
these counts explain submission shape but are not timing samples.

Server handshake policy also includes an optional exact Origin allowlist for
both HTTP/1.1 Upgrade and RFC 8441. When configured, a missing, duplicate, or
non-matching Origin is rejected before the successful handshake; leaving the
list empty preserves native-client behavior. The MQTT adapter exposes the same
policy for WS and WSS, and its Mosquitto-derived process gate ports the raw
allowed/denied request shape from `13-websocket-bad-origin.py`.
Any WSS client can opt into the vail transport to retain and expose the
authenticated server certificate chain; a client certificate remains optional.
mTLS servers expose the verified client chain through
the same `peerCertificates()` API. Both vail-backed endpoint roles expose TLS
exporter keying material for channel binding plus typed negotiated cipher-suite
and transcript-hash metadata. Cleartext and Zig standard-library TLS paths
return null rather than claiming unavailable negotiation details.
Vail-backed WSS additionally exposes RFC 8446 application traffic-key updates
and counters. A client/server mTLS test requests a reciprocal update and then
exchanges a complete WebSocket message under the rotated epochs.
An ordinary-client test exercises the same metadata, exporter and reciprocal-
update path without presenting a client certificate.
RFC 8441 connections forward the complete peer-chain, ALPN, cipher/hash,
exporter, KeyUpdate and counter API to their shared parent HTTP/2 TLS
connection, so an application cannot accidentally inspect or rotate only one
logical WebSocket stream.
`interop-websocket-hyper-h2` now runs both h2c and TLS modes. In TLS mode the
audited Hyper fixture uses rustls to request KeyUpdate before RFC 8441 setup;
netz verifies the server certificate, `h2` ALPN and typed suite/hash, derives an
exporter through the WebSocket object, compares it byte-for-byte with rustls's
independent output, returns exactly one update, and then
completes fragmented text, Ping/Pong and bounded Close on the rotated keys.

Both stream WebSocket and RFC 8441 adapters now expose absolute-deadline frame
reads plus `closeWithTimeout`. A close step sends Close at most once, consumes
interleaved Ping/Pong frames under one non-renewing deadline, and returns either
the owned peer Close details or an owned text/binary/continuation frame that was
already in flight. Applications can process returned data and call another
bounded step without duplicating Close. Tests cover silent peers, control-frame
trickling, successful close details, in-flight data, WSS, and HTTP/2 extended
CONNECT. This is stricter shutdown liveness than the audited websocket.zig
close helper, which writes Close and closes the socket without waiting for a
peer response. Both TCP/WSS and RFC 8441 close senders encode the bounded
125-byte control payload in stack storage, avoiding a transient allocation at
the shutdown boundary. RFC 8441 now uses that fixed-buffer path for every Ping,
Pong and Close frame, including automatic Pong and Close replies. A fresh H2
tunnel no longer allocates or retains `send_frame_buffer` capacity merely to
exchange control traffic. Ordinary and compressed-fragment application writes
now use borrowed server payloads or bounded client masking, so the H2 adapter no
longer owns a send-frame growable buffer. A bidirectional compressed-fragment
regression, including a 64-KiB fail-after-warmup case, verifies message bytes,
frame boundaries and no post-warmup caller allocation after removing that field.
The same bounded batch/stream fallback handles uncompressed fragmentation; a
40-KiB bidirectional test crosses the 16-KiB masking boundary. A
real h2c test checks a client Ping, server Pong and
bidirectional Close while both sides retain zero send-frame scratch. A
CPU-0-pinned 4-KiB echo run after this change measured 33.075 us/roundtrip and
236.20 logical MiB/s; this is a regression sample rather than a new
cross-library comparison.

Both HTTP/1 Upgrade/WSS and RFC 8441 connections now expose relative-timeout
counterparts for frame, owned-message, and caller-buffer message receives. One
absolute deadline continues through fragmented messages and interleaved control
frames. Partial wire frames, the owning message assembler, caller-buffer offsets,
compression mode, and incremental UTF-8 validation remain resumable after a
timeout; caller-buffer retries must present the same storage so already written
bytes cannot be silently lost.
Ping and Close progress also expose timeout and absolute-deadline continuation
forms on both transports. A caller can handle an interleaved application frame
and resume with either its original total deadline or a new bounded wait
without retransmitting the Ping or Close control frame.
RFC 8441 setup now has matching `openWithDeadline`/`openWithTimeout` and
`acceptWithDeadline`/`acceptWithTimeout` entry points. They delegate to the
HTTP/2 Extended CONNECT deadline primitives, so interleaved control frames and
fragmented HPACK cannot renew the handshake budget; client timeout cancels the
uncompleted stream and prevents reuse of ambiguous aggregate decoder state.
Dropping an established RFC 8441 adapter before completing its WebSocket Close
handshake now abandons only that Extended CONNECT stream with
`RST_STREAM(CANCEL)` and releases its parent HTTP/2 stream/window state. A real
h2c regression holds `MAX_CONCURRENT_STREAMS` at one, observes the first
stream's exact reset, then completes a second WebSocket on the same reusable
connection; an ordinarily completed Close remains an idempotent no-op at
adapter destruction.

## Remaining evidence before a broad completion claim

All TCP/TLS and RFC 8441 timeout APIs derive awake-clock deadlines once at
entry, while their absolute-deadline counterparts now reject other clock
domains before sending Ping/Close or mutating incremental receive state. The
HTTP/3 adapter applies the same validation before pumping QUIC.
The authenticated HTTP/3 adapter now also applies this contract to RFC 9220
session establishment itself. Client connect APIs preserve one absolute
awake-clock timestamp across QUIC/TLS, peer SETTINGS, Extended CONNECT, and
the response head; server accept APIs preserve it across the first QUIC
Initial, TLS, peer SETTINGS/request processing, and the 200 response. Existing
HTTP/3 sessions expose matching bounded adapter entry points. A cross-phase
regression completes QUIC/TLS, withholds CONNECT past the original deadline,
and verifies that the server does not start a fresh post-handshake budget.
URI entry points accept a complete HTTPS URL and derive DNS target, SNI,
authority, and the raw path/query while retaining HTTP/3's multi-address
fallback. Their timeout/deadline forms keep that same absolute budget through
resolution, every QUIC/TLS attempt, SETTINGS, and the CONNECT response.
Direct-address and URI clients also expose attempt variants that preserve a
non-2xx Extended CONNECT status, owned response headers, bounded body, and
trailers for application authentication, redirect, or retry policy. The
compatibility connect helpers continue to map those responses to
`InvalidResponse` after draining the entity. Caller-owned HTTP/3 sessions
expose matching attempt variants; abandoning an incomplete attempt resets only
its CONNECT stream, while a fully consumed rejection restores the session
without a redundant cancellation.
HTTP/3 WebSocket connections now expose the same typed Ping and Close progress
events as HTTP/1 and RFC 8441. Timeout/deadline continuations return in-flight
application frames with ownership and resume without retransmitting the control
frame; peer Close code/reason metadata remains owned until event deinit. Strict
passive Close receives likewise expose untimed, timeout, and absolute-deadline
forms, while `sendCloseFrame(null)` supports a valid metadata-free Close.
RFC 9220 also matches the HTTP/1 and RFC 8441 borrowed binary-parts send API:
server frames retain scatter/gather input through HTTP/3 DATA framing, clients
apply one continuous mask through bounded scratch, and negotiated compression
consumes the slices without allocating a joined plaintext message.
Its caller-buffer receive APIs likewise assemble uncompressed messages directly
into application storage, reuse connection-owned compressed input/inflater
scratch, and preserve partial-frame plus completed-fragment progress across
timeout retries while requiring the same output buffer for resumed messages.
RFC 8441 and H3 clients additionally expose `sendBinaryInPlace`: callers
opting into mutable post-send storage avoid the immutable client's masking
copy, matching the HTTP/1/reference API while keeping safe `[]const u8`
alternatives. The synchronous H2 tunnel send consumes the borrowed masked
payload before ownership returns even when flow control divides it into DATA.
All H3 message, fragmentation, control, Close, and key-update send entry points
serialize complete write sequences. This protects compression scratch and stops
concurrent callers from interleaving one RFC 6455 frame across HTTP/3 DATA.
The authenticated H3 server connection also reads its established Extended
CONNECT stream through a targeted request-event API. A ready sibling HTTP/3
request therefore remains queued for its own consumer instead of being
mistaken for malformed WebSocket traffic; the real handshake exchange test
interleaves such a sibling, completes its 204 response, and continues the
WebSocket data/control/Close sequence on the original stream.
All HTTP/1, RFC 8441, and RFC 9220 application-send entry points now also
apply `Limits.max_frame_bytes` and `Limits.max_message_bytes` before acquiring
the send mutex, allocating compressor scratch, or mutating an in-place client
buffer. This includes text, binary, two-slice binary, and fragmented messages;
fragmented sends bound every caller-selected frame and their logical aggregate.
Ping, Pong, and Close additionally obey the configured frame bound as well as
RFC 6455's 125-byte control-frame limit, matching receive-side enforcement.
Configured-limit failures consistently return `MessageTooLarge`, while only
unrepresentable aggregate wire lengths retain `PayloadTooLarge`. A shared
validation matrix, transport-specific pre-I/O tests, and a real TCP exact-limit
exchange cover these boundaries. The audited Tungstenite configuration applies
its similarly named frame/message limits only to incoming data; netz deliberately
uses one symmetric resource policy for both directions.
HTTP/1, RFC 8441, and HTTP/3 writers also validate connection Close state after
acquiring their send mutex, so a sender queued behind Close cannot append a
data or control frame after the closing handshake has begun. Ping and Close
deadline APIs revalidate their absolute budget after lock contention. Close
flags use acquire/release atomics because a sole receive owner and concurrent
application writers may observe those transitions on different threads.
Allocating receives on every transport preserve `was_compressed` provenance
after decompression, so callers and concurrency regressions can distinguish an
RSV1 message from an uncompressed fallback without inspecting wire storage.
The HTTP/1 Upgrade regression also drives two writers through the negotiated
permessage-deflate encoder concurrently and accepts either complete-message
order while requiring exact decompressed payloads.
HTTP/3 receive paths now use the same RFC 6455 failure mapping as HTTP/1 and
RFC 8441, sending 1002 for malformed framing, 1007 for invalid text, and 1009
for configured frame/message limits while preserving the original local error.
Cleartext server acceptance likewise exposes timeout and absolute-deadline
forms for the complete HTTP/1.1 Upgrade after TCP accept, while preserving a
stricter configured handshake limit. Already accepted HTTP/1 connections can
be upgraded with either a relative timeout or caller-owned deadline. WSS server
acceptance carries that budget through both TLS 1.3 and HTTP Upgrade, with each
configured phase timeout able to shorten but never renew it; already-accepted
TLS streams expose the same relative and absolute forms. Unix-domain WebSocket
listeners expose the same post-accept Upgrade deadline contract without
applying TCP-only socket options.

1. **Completed at 128 connections:** the equal-shape mixed-payload benchmark
   now reports per-class p50/p99/p99.9 and retains matching checksum/sample
   counts. The maximum 256-connection setting also completes with matching
   accounting and a 1.31x median aggregate advantage; use longer runs when
   investigating scaling beyond these short saturation samples.
2. Compare buffer-pool behavior and peak memory under many mostly-idle
   connections; the reference exposes explicit small/large buffer pools. The
   netz echo benchmark now accepts `--stats` and reports thread-safe allocation
   counts, cumulative bytes, peak live bytes and size buckets. Four cleartext
   connections used 54 allocations and 52,784 peak live bytes in the captured
   smoke; one connection used 15 allocations and 13,196 peak live bytes. Four
   compressed connections used 106 allocations and 1,139,720 peak live bytes,
   dominated by sixteen retained 64-KiB codec windows. Add equal telemetry to
   the websocket.zig harness and extend beyond 16 mostly-idle connections before
   making a memory ratio. The fixed 16-connection benchmark bookkeeping has
   since been replaced by bounded dynamic arrays and the cap raised to 256 in
   both harnesses. Equal 64-connection mixed-payload telemetry initially
   recorded 1,095 allocations and 851,974 peak live bytes for netz versus 402
   allocations and 683,242 peak live bytes for websocket.zig. The dominant
   difference was ArrayList's geometric growth retaining roughly 6.5 KiB for
   each 4,104-byte cleartext frame. The TCP receive path now grows retained
   storage to the exact delivered byte count while preserving reuse. A matched
   rerun used 572,420 peak live bytes for netz versus 683,242 for websocket.zig
   (16.2% lower); netz also ended before deferred connection teardown with
   286,592 live bytes versus 363,580 (21.2% lower). Exact growth causes more
   small allocation/remap events across the mixed schedule, so the result is a
   resident-memory advantage rather than an allocation-count claim. Three
   matched 128-connection mixed runs then produced identical telemetry on every
   repetition: netz used 1,145,860 peak live bytes and ended with 575,232 live
   bytes, versus websocket.zig's 1,311,690 peak and 671,932 final live bytes.
   Netz therefore retained 12.6% less at peak and 14.4% less at report time at
   twice the earlier concurrency. It made 2,823 allocation calls versus 595,
   preserving the explicit trade-off: exact growth lowers resident memory but
   intentionally performs more small allocator operations. Receive growth now
   rounds only to a bounded 256-byte slab. This coalesces the common split
   frame-header/payload reads while retaining at most 255 bytes of slack per
   connection, instead of returning to ArrayList's geometric over-allocation.
   A 64-connection mixed smoke kept the same 1,095 allocation count but lowered
   peak live bytes from 652,544 with a 512-byte slab prototype to 619,520; it
   also reduced exact-growth event sizes from the earlier audit. Three matched
   256-connection runs were likewise byte-stable: netz used 2,290,692 peak and
   1,150,464 final live bytes versus websocket.zig's 2,528,794 peak and
   1,286,588 final bytes, reductions of 9.4% and 10.6% at the maximum supported
   benchmark concurrency.
3. Keep the external Autobahn gate current.
   `zig build interop-websocket-autobahn -Doptimize=ReleaseFast` runs the
   Dockerized Autobahn Testsuite 25.10.1 fuzzing client against the dedicated
   long-lived netz echo endpoint. Passing `--tls` runs the identical cases over
   native TLS 1.3 WSS using the checked-in localhost test identity. On
   2026-08-21, the full WSS run completed all 517 cases with the same result as
   cleartext: behavior counts `OK=514` and `INFORMATIONAL=3`, and close-behavior
   counts `OK=514` and `INFORMATIONAL=3`. The cleartext run likewise completed
   all 517 cases with
   behavior counts `OK=514` and `INFORMATIONAL=3`;
   close-behavior counts were `OK=514` and `INFORMATIONAL=3`. The 54
   compression cases previously reported as `UNIMPLEMENTED` now complete as
   `OK`: the server echoes `server_max_window_bits=9` when offered and bounds
   every emitted Vort LZ77 distance to that negotiated 512-byte window. The
   four fail-fast UTF-8 cases previously reported as `NON-STRICT` are also now
   `OK`: invalid text is rejected as soon as the decisive byte arrives, even
   before the current frame or a fragmented message has completed. The
   runner accepts only the explicit `OK`, `NON-STRICT`, and `INFORMATIONAL`
   behavior statuses and `OK` and `INFORMATIONAL` close statuses, reports every
   non-OK case, and exits unsuccessfully for `UNIMPLEMENTED`, failure, missing,
   or unknown statuses. Optional case IDs select a faster focused run. This is
   external RFC 6455/RFC 7692 conformance evidence for both cleartext HTTP/1.1
   Upgrade and WSS. RFC 8441 now has the separate Hyper process gate described
   above, although it is a focused lifecycle check rather than the 517-case
   Autobahn suite. The remaining three non-OK Autobahn results are
   inherently
   informational in Testsuite source: 7.1.6 explicitly allows implementation-
   defined close ordering, while 7.13.1 and 7.13.2 state that behavior for
   private-use close codes 5000 and 65535 is undefined. They are reported by
   that category rather than inflated into a 517-case pass claim.
4. Add an equal-wire compressed echo comparison if the reference re-enables
   its currently disabled outbound compressor; until then the netz timing is
   only an internal baseline.

The handshake capacity audit now includes real 80-request / 80-response-field
round trips for HTTP/1 Upgrade, RFC 8441, and RFC 9220. HTTP/1 uses its explicit
100-field request/response limits and a 16-KiB head budget; HTTP/2 uses its
256-field and 16-KiB header-list limits. HTTP/3 uses a 1200-byte QUIC datagram
limit with 64-byte never-indexed values, so success requires actual STREAM
fragmentation rather than QPACK repetition. The H3 client completes the normal
attempt-to-connection promotion after inspecting all 80 response fields, while
the server independently verifies all 80 request fields. H1/H2 capacity tests
live under `runtime/handshake/` instead of enlarging the existing handshake
header test file. The shared HTTP/1 and RFC 8441 handshake policy now lives
beside those tests in `runtime/handshake/headers.zig`: singleton lookup,
reserved/framing-field validation, legacy RFC 8441 rejection, extension
selection, and duplicate-aware subprotocol preference are no longer embedded
in the roughly ten-thousand-line runtime root. Private aliases retain existing
call and test shapes; the public API is unchanged and the root is about 270
lines smaller.
HTTP/1 Upgrade, RFC 8441, and RFC 9220 request/success-response descriptor
assembly now shares `runtime/handshake/storage.zig`: up to 16 fields remain on
the stack and larger sets use one exact allocation. HTTP/1 rejection fields and
the Host-completion writer use the same policy. The storage test proves the
common path under an allocator that rejects every allocation and verifies the
first overflow reports OOM; the three 80+80 wire tests cover each fallback.
Subprotocol offer serialization uses a 128-byte stack buffer, while duplicate
token detection uses 16 stack slots before exact fallback; H1, RFC 8441, and
RFC 9220 now share that grammar and preference implementation. Final isolated
`bench-websocket-echo --stats` smokes reported 18 allocations / 9,916 peak live
bytes at one connection and 51 / 39,664 bytes at four connections, identical
to the immediately preceding descriptor-only run. Latency was 9.224 and 9.733
us/roundtrip respectively. This is no-regression evidence; whole-connection
telemetry is dominated by other retained allocations and does not isolate the
removed temporary handshake buffers.

HTTP/1 clients now expose `ConnectAttempt` through direct-address and WS/WSS URI
helpers, with relative/absolute deadline variants. A non-101 final
response retains owned status, headers, decoded chunked trailers, and a body
bounded by `Limits.max_rejection_body_bytes`; the transport is closed before a
direct address attempt returns. `requireAccepted` keeps the established API's
`InvalidResponse` mapping, while successful attempts preserve bytes coalesced
after the 101 head and transfer them without another copy into the WebSocket
receive buffer. Bodyless interim 1xx responses are skipped under the same
absolute deadline and `Limits.max_informational_responses` bound.
