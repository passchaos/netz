# netz vs `~/Work/websocket.zig` parity audit

This audit records direct evidence for the WebSocket portion of the broader
netz improvement goal. It distinguishes feature coverage from measured hot
paths so a codec microbenchmark is not mistaken for complete server
superiority.

## Feature comparison

| Area | netz | `websocket.zig` reference |
| --- | --- | --- |
| HTTP/1 Upgrade client/server | Covered, including host names, IPv4/IPv6, Unix-domain listener/client transports, strict duplicate critical-header checks, upgrade-body rejection, optional absolute request/response-head deadlines over WS/WSS that are not renewed by trickled bytes, and long-running bounded TCP/Unix/TLS supervisors with graceful cancellation plus accept/connection error policy | Covered with configurable handshake parsing, handler callbacks, a Unix listener, a server-side handshake timeout, worker pools and coordinated shutdown |
| WSS client/server | Covered through shared TLS transports with host/CA verification, optional client identities, caller-provided server identities, optional/required client certificates, verified peer chains and concurrent serving | Client covered; 0.16 README labels the branch experimental, while the audited server API terminates cleartext WebSocket |
| HTTP/2 WebSocket (RFC 8441) | Covered through extended CONNECT client/server adapters | Not present in the audited source |
| permessage-deflate | Negotiated and exercised by HTTP/1 and H2 runtimes with no-context-takeover, actual LZ77/Huffman compression and expansion fallback | Negotiation/decompression exists, but audited 0.16 client/server send compression code is disabled |
| Fragmentation / aggregate limits | Strict assembler and runtime message limits, UTF-8 validation after fragmented text assembly | Fragment assembly and configurable message/buffer limits |
| Receive/send ownership | `parseFrameInto`, `receiveMessageInto`, and its absolute-deadline variant use caller storage, including permessage-deflate output with reusable connection scratch on HTTP/1 and RFC 8441; `sendBinaryInPlace` explicitly offers the reference's mutable post-send contract while safe `[]const u8` sends remain available | Reader returns borrowed payloads and allocates/pools compressed output; client send APIs require mutable payloads and leave them masked |
| Close / Ping / Pong | Typed close parsing/writing, close-state guards, automatic Pong and Close replies, plus deadline-bounded active Ping/Pong round trips that preserve interleaved application frames for both HTTP/1 Upgrade and RFC 8441 | Handler callbacks and automatic default control replies |
| Concurrent sends | Serialized by per-connection `std.Io.Mutex` and covered by a runtime test | Documented thread-safe connection writes |
| TCP/TLS latency policy | TCP_NODELAY defaults on for ordinary accepted and client TCP/WSS sockets; WSS header + first payload bytes fill one TLS record/network write; configurable in runtime limits/connect options | Server enables NODELAY, audited client leaves Nagle enabled unless the embedding application changes the socket |
| Linux io_uring experiment | Cleartext client helper | Custom epoll/kqueue/Windows server backends |

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

## Direct frame hot-path evidence

Run:

```sh
zig build bench-websocket-frame -Doptimize=ReleaseFast
```

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
excluded. This evidence covers the ordinary TCP runtime, not the separate
io_uring adapter.

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

## Remaining evidence before a broad completion claim

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
