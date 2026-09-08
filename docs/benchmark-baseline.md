# netz benchmark baseline

This file records reproducible local baselines used while working toward the
long-running goal of comparing and improving netz against the HTTP/QUIC
implementations under `~/Work`.

The numbers below are **not** a completion claim.  They are a starting point for
repeatable comparisons: same host, same compiler, explicit commands, and raw
outputs that can be re-run after future optimizations.

## Host and toolchain

Captured on 2026-08-12.

```text
OS: Linux robot-NUC13RNGi5 6.8.0-136-generic x86_64
CPU: 13th Gen Intel(R) Core(TM) i9-13900K, 32 logical CPUs
Zig: 0.16.0
Build mode: -Doptimize=ReleaseFast
```

## Commands

```sh
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- --mode=fixed --warmup=20 --iterations=200
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- --mode=chunked --warmup=20 --iterations=200
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- --mode=chunked --chunk-bytes=1024 --warmup=10 --iterations=100
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
zig build bench-http3-qpack -Doptimize=ReleaseFast
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=4
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast -- --stream-fragments=4
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream --warmup=200 --iterations=5000
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
taskset -c 0 zig build bench-mqtt-tls -Doptimize=ReleaseFast
```

Two 2026-09-04 post-close-semantics MQTT-over-TLS regression samples used one
persistent native TLS 1.3 connection, 100 warmup exchanges, and 2,000 measured
1-KiB QoS 1 publish/PUBACK round trips. They measured 11.693-11.812 us per
operation and 84,658-85,518 operations/s on CPU 0. This is an internal hot-path
guard for the shared vail record stream, not a cross-library performance claim.

## Current netz results

### HTTP/1 persistent 16-request pipeline

Captured on 2026-08-17. This benchmark mirrors
`~/Work/hyper/benches/pipeline.rs::hello_world_16`: each iteration sends
sixteen bodyless GET requests on one persistent loopback TCP connection and
receives sixteen `"Hello, World!"` responses. Hyper automatically adds a
29-byte Date value; netz now generates the same IMF-fixdate in its ordinary
server path, so both responses are 89 wire bytes without benchmark-only headers.
Netz runs 200 untimed warmup batches before 2,000 measured
batches. CPU 0 pinning is required on this hybrid-core host; unpinned samples
are not used for the comparison.

```sh
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast

cd /home/passchaos/Work/hyper
cargo bench --bench pipeline hello_world_16 --features full
HYPER_BENCH=$(
  find target/release/deps -maxdepth 1 -type f \
    -name 'pipeline-*' -executable -print -quit
)
taskset -c 0 "$HYPER_BENCH" --bench hello_world_16
```

```text
netz (five samples):
  0.711-0.752 us/request
  11.38-12.03 us/16-request batch
  1.330-1.406 million requests/s

hyper (five samples):
  0.836-0.866 us/request
  13.38-13.85 us/16-request batch
```

Both ranges contain five CPU-0-pinned samples. The Hyper binary was built from
revision `084473f728f9d07b3be5845475aa2f62ed9ff579` with
`rustc 1.98.0-nightly (e7815e522 2026-06-04)`.

Netz is about **1.11-1.22x faster** for this same-host, same-shape sample. The
runtime path uses caller-owned head/header/body output arrays, borrowed receive
storage, one prefix compaction per pipeline, persistent write scratch,
header/body vectored writes and one transactional response-batch flush. This is
a focused HTTP/1 pipeline result, not a whole-library superiority claim. The
implementation audit and remaining HTTP/1/HTTP/2 evidence are in
`docs/hyper_parity.md`.

The automatic-Date path was recaptured on 2026-09-04 with three CPU-0 runs:
netz measured 0.733-0.750 us/request (11.73-12.00 us/batch), while Hyper
measured 0.844-0.846 us/request (13.50-13.54 us/batch).
HTTP/1 aggregate message-boundary logic now lives under
`runtime/message/framing.zig`: head limits, Content-Length and
Transfer-Encoding classification, decoded chunk limits, trailer limits,
method-aware close-delimited responses, interim-response classification, and
automatic 100-continue eligibility share one pure module and focused tests.
The runtime also delegates legal HTTP/1.1 non-final transfer-coding responses
directly to the core parser instead of sanitizing and reparsing the head,
removing three temporary allocations while preserving Transfer-Encoding and
stripping conflicting Content-Length. HTTP/1.0 Transfer-Encoding remains a
hard error and has a real TCP regression.

The same executable now accepts `--large-body`. With sixteen 64-KiB fixed
responses, the runtime validates the whole pipeline but borrows bodies into a
single writev rather than building a 1-MiB concatenation. Three CPU-0 samples
were 10.66–10.79 us/request, down from a captured 15.43 us/request on the old
copying path (1.43–1.45x faster). This is an internal branch comparison rather
than an equal-shape Hyper result.

### HTTP/1 persistent bidirectional 1-MiB bodies

Captured on 2026-08-19 against the checked-in same-shape Hyper harness under
`tools/hyper_http1_body`. Both sides use one persistent TCP_NODELAY connection,
20 warmups, 200 measured round trips, streaming receive, and 1 MiB in each
direction. Fixed mode uses one exact Content-Length body; chunked mode uses
64 × 16-KiB application chunks.

```text
fixed (five samples):
  netz:  268.72-270.10 us/op, 7,404-7,442 aggregate MiB/s
  hyper: 288.61-293.14 us/op, 6,822-6,929 aggregate MiB/s

chunked (five samples):
  netz:  284.04-286.06 us/op, 6,991-7,041 aggregate MiB/s
  hyper: 414.64-417.45 us/op, 4,790-4,823 aggregate MiB/s
```

Netz is 1.07-1.09x faster in the fixed workload and 1.45-1.47x faster in the
chunked workload. The reusable implementation changes are TCP_NODELAY, direct
socket-to-callback fixed-body delivery, retained chunk/vector scratch, batched
`writeChunks`, wide POSIX writev submission, and 64-KiB chunked read-ahead into
the persistent connection buffer. Read-ahead can span several chunk boundaries
or a pipelined suffix, but callbacks still receive one wire chunk at a time and
the suffix remains buffered for the next message. These are focused workload
results, not a whole-library superiority claim.

### HTTP/2 persistent consecutive and parallel round trips

Captured on 2026-08-17 against Hyper's
`http2_consecutive_x1_empty`, `http2_consecutive_x1_req_10b`,
`http2_consecutive_x1_req_100kb`, and `http2_parallel_x10_empty` benchmarks.
Each scenario uses a persistent prior-knowledge connection and both processes
were pinned to CPU 0. Netz and Hyper both generate Date through their default
server paths, while netz matches Hyper's 1-MiB server receive windows and uses
untimed warmup so steady-state wire,
flow-control and calibration shapes match.

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast

cd /home/passchaos/Work/hyper
cargo bench --bench end_to_end http2_consecutive_x1_empty \
  --features full --no-run
HYPER_H2_BENCH=$(
  find target/release/deps -maxdepth 1 -type f \
    -name 'end_to_end-*' -executable -print -quit
)
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_consecutive_x1_empty
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_consecutive_x1_req_10b
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_consecutive_x1_req_100kb
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_parallel_x10_empty
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_parallel_x10_req_10kb_100_chunks_max_window
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_parallel_x10_res_1mb
```

```text
empty GET (five samples):
  netz:   9.55-9.96 us/op
  hyper: 12.51-12.54 us/op
  netz latency advantage: 1.26-1.31x

10-byte POST (five samples):
  netz:  10.09-10.38 us/op
  hyper: 41.15-41.37 ms/op

100-KiB POST (five samples):
  netz:  23.52-23.57 us/op
  hyper: 37.24-38.68 us/op
  netz latency advantage: 1.58-1.64x

parallel x10 empty GET (five samples):
  netz:  26.35-26.60 us/batch, 2.63-2.66 us/request
  hyper: 47.50-48.46 us/batch, 4.75-4.85 us/request
  netz batch-latency advantage: 1.79-1.84x

parallel x10, 100 x 10-KiB request chunks/stream, max windows:
  netz:  1.64-1.74 ms/batch, 164-174 us/request
  hyper: 3.36-3.40 ms/batch, 336-340 us/request
  netz batch-latency advantage: 1.93-2.07x

parallel x10, 1-MiB response/stream, max windows (2026-08-19):
  netz:  1.663-1.671 ms/batch, 166.3-167.1 us/request
  hyper: 2.957-3.035 ms/batch, 295.7-303.5 us/request
  netz batch-latency advantage: 1.77-1.82x
```

A three-run 2026-09-04 CPU-0 post-change recapture of the first four shapes
measured netz at 9.980-10.288 us, 10.516-10.525 us, 23.173-23.279 us and
27.611-27.808 us/batch; matching Hyper spot samples were 12.514 us,
41.012 ms, 37.168 us and 47.994 us/batch.
Outbound HTTP/2 hop-by-hop filtering now lives in `runtime/headers/connection.zig` and
collects every `Connection` field before mutating the header list. Common
requests use eight stack entries instead of the former fixed 256-entry array;
larger sets allocate their exact count. Tests cover a 257th late nomination,
allocation-failure rollback, request-only `TE: trailers`, and request/response
high-level wire paths. Three CPU-0 post-change runs measured the six standard
shapes at 9.850-10.044 us, 10.270-10.397 us, 23.062-23.288 us,
27.372-27.503 us/batch, 168.481-169.305 us/request, and
169.684-170.277 us/request respectively, within the preceding ranges.
The remaining pure HTTP/2 header logic now lives in the same nested hierarchy:
`runtime/headers/message.zig` owns Content-Length parsing, pseudo-header order,
URI/authority validation, trailer restrictions, request lookups, and
request-aware response body semantics. Focused tests under
`runtime/headers/tests/` cover those rules while real connection tests remain
at the integration layer. This removes another 565 lines from `runtime.zig`
without changing public types. Three CPU-0 post-extraction runs measured the
six standard shapes at 9.802-9.992 us, 10.264-10.469 us, 23.112-23.242 us,
27.437-27.504 us/batch, 169.371-171.263 us/request, and
170.763-173.576 us/request respectively, within the previous ranges.
HTTP/2's transport-facing frame boundary now follows the same nested layout:
`runtime/frame/io.zig` owns borrowed/owned reads and scatter/gather writes,
while `runtime/frame/wire.zig` owns envelope validation and direct fixed-frame
and batch encoding. HEADERS plus CONTINUATION batches reserve their complete
encoded size before appending, so allocator failure leaves the caller's batch
unchanged and successful multi-frame assembly performs a single capacity
check. Focused tests cover envelope rules, exact flags/payload partitioning,
preallocated reuse, and allocation-failure rollback.
The reader retains the measured 64-KiB coalescing window and grows exactly to
the frame boundary only when a legal frame is larger. A trial 16-KiB default
reduced idle capacity, but regressed the large-body benchmark by requiring an
extra initial read, so it was rejected rather than trading throughput for a
memory-only improvement. The audited Hyper/h2 generic framed reader starts at
8 KiB, but its async scheduling and buffer ownership differ from this blocking
runtime; the local fixed-CPU result remains the deciding evidence here.
The connection/stream flow-window primitive now lives under
`runtime/flow/window.zig`, matching the audited h2 model's signed window domain:
SETTINGS reductions may make a stream negative, but arithmetic cannot escape
the signed 32-bit protocol range. Zero-length DATA reservations and receives
remain legal even while a stream window is negative, so an empty END_STREAM
does not wait for credit it does not consume. Focused tests cover blocked send,
receive violations, both bounds, and transactional failure.
Three fixed-binary CPU-0 runs after the flow-window extraction measured the
six standard shapes at 10.094-10.227 us, 10.490-10.584 us,
23.210-23.398 us, 27.898-28.111 us/batch, 170.335-171.941 us/request, and
175.235-176.246 us/request. This is a regression guard rather than a speedup
claim; the change centralizes arithmetic and fixes edge semantics.
Three fixed-binary CPU-0 runs after the extraction measured the six standard
shapes at 10.022-10.066 us, 10.548-10.626 us, 23.229-23.273 us,
27.626-27.768 us/batch, 168.581-169.911 us/request, and
170.828-172.510 us/request respectively. These stay within the established
range; the one-shot build invocation outliers were excluded because build and
measurement were not isolated. After rejecting the smaller read-ahead trial,
three final fixed-binary runs measured 9.923-10.035 us, 10.449-10.565 us,
23.243-23.372 us, 27.951-28.156 us/batch, 167.797-168.067 us/request, and
173.706-174.753 us/request.

The h2c harness now accepts `--scenario=<name>` and `--stats`, with allocator
snapshots taken after warmup and exact allocation sizes reported alongside the
size buckets. On the consecutive empty GET shape, the initial telemetry found
exactly six allocations per exchange: the two owned HPACK outputs at each
endpoint plus 19-byte request and 11-byte response frame copies. Aggregate
request and response readers now borrow ordinary wire frames from the reusable
64-KiB frame-reader buffer, while frames dequeued from the pending application
queue retain their owning fallback. A post-change run removed both frame sizes
and measured exactly four allocations per exchange (8,000 over 2,000 measured
requests), down 33.3% from 12,000; cumulative requested bytes fell from
1,316,000 to 1,256,000. Five fixed-binary CPU-0 samples measured
9.606-9.880 us/op. This is allocation/copy evidence and a local regression
range, not a new cross-stack speed ratio. Reproduce the isolated shape with:

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_consecutive_x1_empty --stats
```

The remaining descriptor-array and string-block allocations at each endpoint
are now coalesced into one aligned allocation without changing the public
`HeaderField` slices. The same warmed empty exchange therefore fell again from
four to two allocations per request (4,000 over 2,000 measured requests), with
one 409-byte request-header block and one 219-byte response-header block.
Cumulative requested bytes remained exactly 1,256,000, confirming that this
step removes allocator calls rather than payload ownership. Five post-coalesce
fixed-binary CPU-0 samples measured 9.642-9.931 us/op; the earlier
four-allocation sample remains above to separate the two optimizations, and no
throughput gain is claimed from their overlapping latency ranges.
For the consecutive 10-byte POST shape, exact-size telemetry then identified
the remaining transient 143-byte block as `ArrayList` geometric growth despite
an already validated `Content-Length: 10`; `toOwnedSlice` subsequently allocated
and copied a 10-byte result. Exact reservation plus direct ownership transfer
removed that over-allocation and copy. A warmed run fell from four to three
allocations per request and from 2,010,096 to 1,724,096 cumulative requested
bytes over 2,000 requests; its remaining per-request allocations are exactly
the request HPACK block, 10-byte body and response HPACK block.
The symmetric aggregate response path is now covered by
`http2_consecutive_x1_res_10b`. Before exact reservation it allocated a
143-byte geometric body buffer and then copied into a 10-byte result, taking
16.843 us/op in the captured baseline. Exact `Content-Length` reservation and
direct transfer reduced the warmed shape from four to three allocations per
request and cumulative requested bytes from 2,008,096 to 1,722,096 over 2,000
requests. Five fixed-binary CPU-0 samples measured 10.006-10.363 us/op. The
remaining allocations are the request HPACK block, response HPACK block and
exact 10-byte response body.
The aggregate parallel response reader now uses the same borrowed-frame cursor
as its streaming counterpart. On `http2_parallel_x10_empty`, this removed one
11-byte owned frame per response: a warmed 2,000-batch run fell from 80,000 to
60,000 allocation calls and from 16,420,000 to 16,200,000 cumulative requested
bytes. The single before/after timings were 28.607 and 28.363 us/batch, so this
records the deterministic allocation/copy reduction without claiming a latency
improvement.
The client request and server response batch writers now alternate between two
connection-owned HPACK encoders. Before staging a batch, the inactive encoder
copies live compression state while retaining its entry, index, string and
encoded-block capacities; commit is a pointer-free swap. On the same warmed
parallel x10 run this removed the remaining ten batch-level clone allocations
per batch, reducing measured calls from 60,000 to 40,000 and cumulative
requested bytes from 16,200,000 to 12,560,000. The exact-size list now contains
only the 20,000 request and 20,000 response owned HPACK blocks. The single
telemetry sample was 27.415 us/batch; five subsequent fixed-binary CPU-0 runs
measured 26.258-26.431 us/batch. This is recorded as an internal regression
range rather than a new cross-stack ratio.

`strace` confirmed equal steady-state wire sizes: empty exchanges use 19-byte
requests and 11-byte responses; POST exchanges use 43-byte requests and
11-byte responses. The large POST gap is specifically Hyper's two-write
HEADERS/DATA path hitting Linux's Nagle/delayed-ACK interaction on this host,
not a general whole-library ratio. Netz preserves both HTTP/2 frames but submits
their four slices in one `sendmsg`; larger, fragmented or flow-blocked messages
fall back to ordinary frame writes. The 100-KiB case uses TCP_NODELAY, matched
receive windows, vectored DATA bursts, a connection-level multi-frame receive
buffer and callback-based streaming request consumption. The client now has a
symmetric callback-based response API with owned initial/trailing headers,
strict streamed Content-Length accounting, continuous flow-credit return, and
RST_STREAM cancellation on consumer failure. The server-side `ResponseWriter`
provides the corresponding multi-call body producer with flow-control waiting,
transactional cumulative length validation, trailer/FIN completion and
unfinished-writer cancellation. The client-side `RequestWriter` adds the same
multi-call upload and trailer lifecycle, then hands the live stream to owned or
callback-streaming response receive without first aggregating request bytes.
An early response encountered while the upload waits for WINDOW_UPDATE is
retained in one bounded owned-frame slot and returned as `ResponseAvailable`;
the writer records any successfully sent prefix and transfers that response
without losing HPACK or wire ordering.
Bodyless parallel batches use
transactional HPACK staging, one request/response submission in each direction,
and stream-ID-based response reordering. See `docs/hyper_parity.md` for the
implementation audit and additional H2 comparison work.
Body-bearing request batches add transactional credit preflight, staged HEADERS,
round-robin borrowed DATA contributions, and server-side interleaved streaming
request demultiplexing without body aggregation.
The response-body batch uses the symmetric server scheduler and client
stream-ID demultiplexer: ten borrowed 1-MiB payloads are framed round-robin,
using the same 16-KiB per-stream turn as Hyper's locked h2 0.4.15 scheduler,
and callbacks account response DATA without retaining a 10-MiB aggregate.
These ranges establish advantages for the named loopback workloads only; they
do not establish whole-library HTTP/2 superiority.

### HTTP/2 flow-controlled parallel responses

The RFC 9218 selector now chooses urgency and the lowest stream-ID
non-incremental winner in one candidate pass. Three CPU-0-pinned priority-mode
runs with ten 1-MiB responses and 8-KiB stream windows measured 7.79–7.96
ms/batch (1.26–1.28 GiB/s), versus 8.03 ms/batch immediately before scan
fusion.

Captured on 2026-08-19 with ten bodyless requests and one 1-MiB response per
stream. Both implementations use a persistent h2c connection, a 16-KiB maximum
DATA frame size, an 8-KiB initial stream window, the RFC default 65,535-byte
connection window, a barrier before response creation, 5 warmups and 20
measured batches. Both clients consume all streams concurrently and return
WINDOW_UPDATE while DATA is arriving.

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --warmup=5 --iterations=20
taskset -c 0 tools/bench_hyper_http2_flow.sh \
  --warmup=5 --iterations=20
```

The netz workload also accepts `--priority`. This enables RFC 9218 on both
peers and assigns one urgency-0 non-incremental, four urgency-2 incremental,
and five urgency-5 incremental requests in the default ten-stream batch:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=2 --iterations=5
```

Two sets of three CPU-0-pinned 2026-08-19 runs completed in
7.880-8.015 ms/batch (1,247-1,268 body MiB/s). This is an internal scheduler
baseline because the locked h2 0.4.15 reference has no RFC 9218
urgency/incremental scheduler.

```text
five CPU-0-pinned samples:
  netz:  7.367-7.447 ms/batch, 1,342-1,357 body MiB/s
  hyper: 10.192-10.379 ms/batch, 963-981 body MiB/s
  netz batch-latency advantage: 1.37-1.41x
```

Three alternating 2026-09-04 runs with runtime-generated Date measured netz at
7.586-7.660 ms/batch (1,305-1,318 MiB/s) and Hyper at
10.155-10.196 ms/batch (980-984 MiB/s), a 1.33-1.34x latency advantage. A
short-run A/B against the saved pre-change netz binary showed 7.487 ms median
versus 7.482 ms with the former fixed field (0.07%, within run noise).

The reusable change is a blocking-runtime multi-stream DATA scheduler: it
reserves only bytes being emitted in the current round, rotates the starting
stream after progress, and pumps SETTINGS/PING/WINDOW_UPDATE plus member-stream
RST_STREAM while blocked. Payloads remain borrowed and HPACK/scratch validation
still completes before HEADERS are written. This is focused backpressure and
fairness evidence, not a whole-stack superiority claim.

The same benchmark now covers a priority/flow-control cancellation race:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --cancel-after=8 --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=0 --iterations=1
```

The client accepts eight scheduled DATA callbacks, then rejects the batch and
sends RST_STREAM(CANCEL) for all unfinished streams. Timing includes server
observation of the reset batch. Five CPU-0 runs measured 230.4-241.2 us/batch.
The cancellation path now coalesces all resets into one transport write instead
of one write per stream and removes canceled send/receive-window entries. Reset
is the precise lifecycle boundary: ordinary half-close keeps its windows until
the opposite direction completes, while local, peer, pushed-stream, and batch
RST_STREAM paths retire both indexed entries immediately. A `--stats`
sample made 293 allocations and peaked at 1,287,988 live bytes. This closes the
previous priority-aware cancellation timing gap; there is no equal Hyper/h2
RFC 9218 scheduler workload, so it remains internal evidence.

### HTTP/3 QPACK dynamic encode

```text
HTTP/3 QPACK dynamic encode benchmark
  iterations: 100000, table entries: 512, fields/block: 32
  encoded bytes/block: 68, references/block: 32
  ns/block: 864-882, ns/field: 27
  dynamic table churn: 945-968 ns/insert
  checksum: 10000000
```

Dynamic entries own name and value in one contiguous allocation rather than two independent blocks. This removes one allocation/free pair per insert/eviction while retaining separate borrowed slices. The immediately preceding two-block build measured 1,235-1,268 ns/block; the indexed lookup workload improved by about 1.40-1.47x. Quicz duplicates name and value separately and inserts at array index zero, adding a second allocation and an O(n) shift under churn.

The same executable now includes a 512-field/512-unique-reference section to
expose reference-set bookkeeping that the ordinary 32-field block cannot.
Three CPU-14 baseline runs took 50.50-65.60 us/block (98-128 ns/field). A
sort/compact prototype reduced that large shape to 18.70-18.79 us but enlarged
the shared encoder enough to regress the ordinary block from 917 ns to about
1,247 ns, so the implementation was rejected and fully rolled back. The
large-section number remains a checked-in optimization gate rather than hiding
the trade-off.

### QUIC 1-RTT send

```text
QUIC 1-RTT send benchmark
  iterations: 1000, packets/batch: 32, payload bytes/packet: 1024
  stateful batch GSO available after run: true
  stateful sequential: 109760 ns/batch, 3430 ns/packet
  stateful batched:    98012 ns/batch, 3062 ns/packet
  stateful batch relative packet throughput: 1.11x
  total packets/path: 32000
```

The 1-RTT send path now centralizes frame classification in
`one_rtt/frame_traits.zig`. Single-packet validation hands its collected traits
to packet preparation instead of rescanning for ACK-eliciting, in-flight,
retransmission, HANDSHAKE_DONE and largest-ACK metadata; batch preflight caches
the same result and no longer rescans every packet for automatic ECN. Focused
tests pin ACK/PADDING/close, unreliable DATAGRAM, path validation, STREAM byte
totals and ACK watermark semantics. Three CPU-0 fixed-binary runs measured
stateful sequential sends at 106.649-108.672 us/batch and batched sends at
95.348-97.660 us/batch, preserving a 1.11x batch throughput advantage.
The bounded QUIC DATAGRAM receive queue now lives in
`one_rtt/datagram_queue.zig`. Its first successful admission reserves exactly
the configured ring bound, so later enqueue/overwrite operations allocate
nothing and retain no geometric capacity beyond policy. Tests exercise
wrap-around removal by packet number, stable survivor order, capacity-one
replacement, caller ownership after OOM, and newest-data retention. The public
queue/drop counters and packet-routing API are unchanged.
Stateless `one_rtt.sendFramesInto` now accepts one caller-owned final packet
buffer, encodes frames directly into its plaintext region, seals AEAD in place,
and submits it without heap allocation. Its exact sizing helper validates every
frame before output mutation. The compatibility `sendFrames` wrapper now uses
one exact packet allocation instead of separate plaintext and protected-packet
allocations. A real UDP test proves caller-buffer transmission under a
fail-first endpoint allocator, another proves the wrapper succeeds when only
one allocation is permitted, and short-buffer rejection occurs before I/O.

### QUIC 1-RTT receive

On 2026-09-05 the current-key receive paths were changed to compute the
short-header protection mask once, using the negotiated cipher suite, and then
reuse that preview for packet-number unmasking and AEAD open. A Key Phase
mismatch leaves the complete datagram unchanged for the existing next/previous
generation fallback. Five post-change CPU-0 samples measured 1.900-1.908
us/packet for the allocating path (1.907 median), 1.403-1.417 us/packet for
in-place service (1.409 median), and 1.396-1.404 us/packet for the borrowed
visitor (1.400 median). The three immediately preceding samples had medians of
1.958, 1.465, and 1.466 us/packet respectively: 2.6%, 3.8%, and 4.5% median
reductions. GRO's median moved from 1.675 to 1.657 us/packet (1.1%). AES-128,
AES-256, ChaCha20, and SM4 tests verify both successful open and byte-for-byte
preservation on phase mismatch.

The receive benchmark now accepts `--mode=all|gro|plain|service|visitor`,
`--frame=padding|stream`, `--warmup=N`, and `--iterations=N`. The STREAM shape
fills each 1,152-byte plaintext with one ordered stream-zero frame, drains it
through `pollStreamId`, and verifies the exact byte total, so it includes the
receive preflight and stream-buffer path that padding-only packets do not.

For the common one-STREAM packet, receive preflight now builds only one
`RecvState.Preflight` and a one-frame descriptor store. It retains the same
stream-ID, final-size, overlap/conflict, receive-window, stream-credit, and
connection-credit validation before the packet-number recorder or connection
state mutates, while skipping unrelated multi-stream, connection-ID, and path
validation shadows. Seven CPU-0, order-alternated 5,000-iteration A/B pairs
measured the following integer ns/packet medians:

| STREAM receive path | Before | After | Median reduction | Pair outcomes |
| --- | ---: | ---: | ---: | ---: |
| borrowed visitor | 1328 | 1308 | 1.5% | 7/7 faster |
| in-place service | 1336 | 1298 | 2.8% | 7/7 faster |

Five equivalent padding visitor pairs moved from a 1397 ns/packet baseline
median to 1395 ns/packet, a noise-level 0.1% difference. An all-mode STREAM run
after this first-stage preflight change measured GRO 1347, allocating plain
1532, in-place service 1320, and borrowed visitor 1322 ns/packet over 270,000
packets per path. These are internal same-host regression measurements, not a
cross-library throughput comparison.

The new connection-level suite test passes a FIN-terminated single STREAM and a
second STREAM after a key-phase update through `Connection.receivePacket` for
AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, ChaCha20-Poly1305/SHA-256, and
SM4-GCM/SM3. It exposed a stale SHA-2-only key-update helper in netz; key
updates now use Vail's suite-aware QUIC traffic-secret derivation, including
HKDF-SM3.

`RecvState` now stores received-byte presence as a packed, capacity-retaining
word bitmap rather than one `bool` byte per buffered payload byte. Ordered
append grows and fills the new words once; overlap checks, sparse gap filling,
cloning, and non-word-aligned prefix compaction use the same bit representation.
Dedicated model and stream tests cover set/clear ranges across 64-bit
boundaries, every prefix shift from 0 through 130 bits, sparse-tail gap filling,
conflicts, FIN, and sliding receive windows. This cuts bitmap storage to about
one eighth of the former representation.

Measured immediately against the retained single-STREAM-preflight binary, five
order-alternated visitor pairs reduced the median from 1324 to 1166 ns/packet
(11.9%, 5/5 faster). A separate seven-pair service run reduced the median from
1328 to 1172 ns/packet (11.7%, 7/7 faster). A 20,000-iteration final profile
measured 1185 ns/packet; `compiler_rt.memset` fell from about 11.5% in the
original STREAM profile to 0.22% of samples, `ReceivedBitmap.resize` accounted
for 0.58%, and AEAD GHASH/CTR again dominated. A long padding-only comparison,
which never enters stream storage, varied by about 0.9% between binaries and is
treated as code-layout/system noise rather than a claimed effect.
The final all-mode STREAM run measured GRO 1138, allocating plain 1387,
in-place service 1161, and borrowed visitor 1166 ns/packet over 270,000 packets
per path.

The receive benchmark now also exposes `--mode=gro_service`, which applies all
segments from one kernel UDP_GRO receive synchronously through connection-owned
storage instead of allocating an owning datagram and `ReceivedPacket` array.
Three order-varied CPU-0 runs over 162,000 STREAM packets per path measured the
owning GRO mode at 1142, 1155, and 1157 ns/packet and state-only GRO at 687,
688, and 696 ns/packet. The median fell from 1155 to 688 ns/packet, a 40.4%
latency reduction or about 1.68x packet throughput. A failing-allocator test
proves the second state-only batch needs no allocation after the receive/frame
scratch has been warmed.

```text
QUIC 1-RTT receive benchmark
  iterations: 1000, packets/batch: 54, payload bytes/packet: 1152
  GRO batch:    90727 ns/batch, 1680 ns/packet
  plain packet: 103063 ns/batch, 1908 ns/packet
  GRO relative packet throughput: 1.13x
  total packets/path: 54000
```

Ordinary non-GRO event loops can now call `Connection.servicePacket` to apply
one datagram without returning owned decrypt/frame diagnostics. It uses the
same current-key in-place path and retained frame array as GRO service, with an
owning fallback only for key-phase transitions. Three ReleaseFast runs measured
1.50-1.64 us/packet versus 1.92-2.07 us/packet for owning `receivePacket`, a
1.17-1.38x packet-throughput improvement. The audited quicz short-packet open
path allocates plaintext and connection-id ownership per packet.

`Connection.visitPacket*` now exposes those transient frames synchronously, so
HTTP/3 can route control/QPACK/request/response frames without restoring owned
plaintext and frame-array lifetimes. The same-shape benchmark's borrowed
visitor was 1.49-2.38 us/packet in three ReleaseFast runs, within measurement
noise of state-only service at 1.53-2.36 us/packet and faster than the matching
owning path at 1.92-2.83 us/packet. Handshake HTTP/3 uses the visitor on its
ordinary non-GRO packet pump. HTTP/3 retains a lazy owning GRO suffix because
it deliberately routes only one coalesced packet per application turn; pure
connection-state consumers can instead use the timer-aware state-only batch
pump to decrypt and apply every segment in lazily grown, connection-owned
receive storage with one cumulative ACK decision. The raw endpoint exposes the
same borrowed batch shape for caller-provided 65,535-byte GRO storage, while
its owning batch API and HTTP/3 cursor retain their existing lifetimes.

### QUIC recovery ACK range application

`bench-quic-ack-ranges` now includes a complete recovery cycle that tracks 128
payload groups and retires them with two 64-range ACK frames. Recovery validates
the descending range chain before mutation, then matches directly from wire
ranges instead of allocating a second decoded-range array. The ReleaseFast
baseline is 8.9 us/cycle on this host. Failing-allocator and malformed-range
tests prove allocation-free application and transactional rejection.

The audited quicz frame decoder allocates `AckRange[range_count]` for every ACK.
Netz still owns ranges at its generic parser boundary, but its recovery queue no
longer performs another allocation/copy.

### QUIC UDP batch send / receive

```text
QUIC UDP batch benchmark
  send iterations: 5000, packets/batch: 54, bytes/packet: 1200
  GSO available after run: true
  UDP_SEGMENT: 14421 ns/batch, 267 ns/packet
  sendmmsg:    95034 ns/batch, 1759 ns/packet
  GSO relative packet throughput: 6.58x
  total datagrams/path: 270000
QUIC UDP receive benchmark
  receive iterations: 5000, packets/batch: 54, bytes/packet: 1200
  GRO available after run: true
  UDP_GRO:    20640 ns/batch, 382 ns/packet
  plain recv: 31318 ns/batch, 579 ns/packet
  GRO relative packet throughput: 1.51x
  total datagrams/path: 270000
```

### HTTP/3 real-handshake paced transfer

HTTP/3 server responses now use the same runtime-generated Date policy as
HTTP/1 and HTTP/2. Development, protected, and authenticated runtimes cover
aggregate, streaming, Push, and CONNECT final responses; explicit fields win,
informational responses omit the generated value, and pure codec calls remain
deterministic. The short-lived response view is stack-first and marks generated
Date values never-indexed to avoid QPACK dynamic-table churn. The response
assembly and tests live in a focused `runtime/server/response.zig` module rather
than adding more policy code to the large runtime root. Two CPU-0
development-runtime smoke runs with the default enabled measured 11.078-11.154
us/request (89,653-90,262 requests/s).

A repeated 1 MiB real-handshake download exposed a short-lived-session race:
the paced writer had submitted the final DATA/FIN packet, but the server then
destroyed its unacknowledged recovery state before a dropped tail packet could
be retransmitted. Handshake clients and servers now expose an explicit,
deadline-bounded recovery-idle drain; ordinary response sends retain their
low-latency socket-submission contract. A deterministic test drops the first
DATA/FIN packet and requires PTO retransmission, exact response bytes, FIN, and
an empty recovery queue. The benchmark uses the drain before teardown and one
absolute 30-second client receive deadline. Five CPU-0 1 MiB download
iterations then completed at 105.87-126.36 MiB/s (120.41 MiB/s mean, 6.18%
standard deviation).
The same recovery drain now covers upload response tails, and both benchmark
directions use one absolute 30-second response budget. A two-iteration CPU-0
1 MiB upload smoke completed at 145.48-151.32 MiB/s (148.40 MiB/s mean).
The single-connection `serveConnection` convenience API now applies the same
bounded drain automatically using a configurable five-second default. The
multi-connection endpoint callback loop instead remains nonblocking and
refreshes the selected dispatcher's aggregate timer after application sends,
so its shared owner services the new PTO on a later loop turn. Focused tests
cover invalid drain budgets and the no-timer-before-send / PTO-after-handler
transition.
As part of the same maintenance pass, HTTP/3 URI authority parsing, DNS
deduplication, multi-address resolution, and absolute connect-budget helpers
were moved into `runtime/client/uri.zig`, while the shared runtime error set
moved to `runtime/error.zig`. Public `UriEndpoint`, `UriRequestOptions`,
`uriEndpoint`, and `uriRequestTargetAlloc` names remain compatibility
re-exports; URI, HTTP/3, and full-suite tests cover the extracted code.
Multi-address DNS collection no longer silently discards unique results after
the former fixed 32-address scratch fills. Lookup now runs as an asynchronous
producer while the caller drains the standard 16-result queue, and unique
addresses remain in a 16-entry stack collector before exact dynamic growth.
Tests cover 40 unique results plus a duplicate through a 16-slot queue, spill
OOM without corrupting the retained prefix, an empty closed queue, and real
localhost lookup. Resolver errors are awaited before the empty-result check so
specific DNS failures are not collapsed into `NoAddressReturned`.
Reusable message, Push, and critical-stream send scratch now lives under
`runtime/send/scratch.zig`; the root keeps private aliases so no public or hot
path call shape changes. The HTTP/3 runtime root fell by roughly 450 lines
across these extractions. QPACK encode/decode connection state and its private
rollback/index/blocked-stream algorithms now live together in
`runtime/qpack/state.zig`; fourteen pure state-machine and allocation-failure
tests moved with them to `runtime/qpack/state_tests.zig`, while socket-backed
integration tests remain at the runtime layer. The root keeps public type
aliases plus only the two internal methods required by send rollback and the
existing white-box cancellation check. A post-move QPACK sample measured
827 ns/block and 25 ns/field, within the prior 816-905 ns/block range.
The same send submodule now owns an MTU-aware packetizer shared by full
handshake connections, the lightweight preconfigured-key protected runtime,
and cleartext development endpoints.
The fast path preserves the prior single-packet call for already fitting frame
groups; the fallback measures the exact protected packet size, repacks adjacent
frames, and splits an oversized STREAM descriptor without changing byte order
or FIN.
This fixes large HEADERS under the normal 1200-byte path MTU: an 80-request /
80-response-header WebTransport handshake previously failed with
`DatagramTooLarge`, and now completes without raising the configured MTU.
Development and lightweight protected WebTransport runtimes have matching
80+80 coverage. Handshake and protected cases explicitly use a 1200-byte
datagram limit and 64-byte never-indexed values, so the regression cannot pass
through QPACK repetition alone; the ordinary response case also verifies DATA
and final FIN after fragmentation. A 256-byte field-section setting still
rejects the set with `ExcessiveLoad`. CONNECT header assembly, protocol
validation/response shaping, and admission/capacity tests are grouped under
`webtransport/runtime/connect/`.
The cleartext development request, response-head, response-prefix, body, and
associated-stream send paths use the same complete-plan-before-send policy. An
explicit 1200-byte UDP/STREAM configuration with 80 never-indexed 64-byte
fields now completes both CONNECT and ordinary final response/body/FIN paths
instead of surfacing `DatagramTooLarge`; deterministic planning failures remain
rollback-safe before the first socket attempt.
Their STREAM framing, streaming-head registration, informational response
offset commit, body-chunk rollback, request cancellation, and retained
DATAGRAM cloning now live together in `runtime/development/send.zig`. Tests
verify contiguous STREAM offsets with exactly one final FIN and that a clone
allocation failure leaves the source packet owned and the retained queue empty.
Three CPU-0 development samples during a heavily loaded host measured
12.910-15.323 us/request; the spread is retained only as a functional benchmark
pass and does not replace the isolated range above.
The complete development send helper set has now moved into that module,
including whole-message packetization, response-prefix offsets, request
cancellation, body-chunk state and retained DATAGRAM cloning. Cloning allocates
the exact frame wire length and writes directly into final ownership instead
of growing an ArrayList and converting it to another allocation. The runtime
root is now 24,076 lines. A later loaded-host sample ranged
12.992-21.114 us/request and is likewise not used for a performance verdict.
The legacy single-stream development receive helper now lives in
`runtime/development/receive.zig`, separate from the stricter multi-request
buffer. On FIN-complete contiguous streams it transfers the reassembly
ArrayList into the owned response instead of duplicating the complete HTTP/3
message. Expected peer/stream filtering, irrelevant unidirectional-stream
discard, deadline behavior, packet ownership, and the configured stream-buffer
limit remain unchanged. A loaded-host CPU-0 smoke measured 14.155 us/request
and is recorded only as functional evidence.
Development request/response ownership and bounded batch result types now live
in `runtime/development/message.zig`; public names remain aliases from the
runtime root. Allocation-failure enumeration covers both batch arrays and
their cleanup, while the existing concurrent server tests continue to access
the same public fields and counters.
The preconfigured-key protection scratch and packet-number/socket-prefix commit
backend now live in `runtime/send/protected.zig`; `runtime.zig` retains a
private type alias, so existing call shapes and white-box allocation checks stay
unchanged while another roughly 160 lines leave the root. A packetizer unit
test forces more than 64 output packets and verifies every packet stays within
its MTU, offsets remain contiguous across batch flushes, bytes are unchanged,
and FIN appears exactly once on the final fragment.
Three CPU-0 `bench-http3-dev` samples after the shared packetizer measured
10.879, 11.255, and 13.659 us/request (73,206-91,916 requests/s). This overlaps
the prior 10.698, 11.060, and 13.624 us/request range, so the exact sizing
preflight has no measurable stable small-message regression on this host.
A final isolated three-run sample after every cleartext send path was connected
to the packetizer measured 10.939, 11.042, and 11.568 us/request
(86,438-91,408 requests/s), tightening that no-regression evidence.
The bounded cleartext retained-DATAGRAM FIFO and its count/byte/ownership tests
were also moved under `runtime/development/datagram_queue.zig`; cross-frame
routing coverage remains with the integration layer. This keeps queue policy
independent without creating a flat collection of additional runtime files.
Development associated-stream receive reassembly, per-session/client send
offsets, per-peer server ID cursors, prefix classification, and their lifecycle
tests now live together in `runtime/development/streams.zig`. Public stream,
match, direction, role, and debug-count names remain root aliases, while the
runtime root sheds roughly another 700 lines.
Client/server request lifecycle state and its white-box tests now live under
`runtime/stream/lifecycle.zig`. The module owns outstanding/active indexes,
request decode semantics, priorities, GOAWAY transitions, and drain-floor
comparisons; `runtime.zig` supplies only reader adaptation and the three
buffered-stream floor values. Public shutdown/retry enums remain root aliases,
and callers use count/empty/state methods instead of reaching into arrays.
This removes roughly 350 more lines from the root without changing wire paths.
Aggregate protected/handshake request and response reassembly now lives under
`runtime/stream/buffered/`, with request and response ownership separated and
shared QPACK dependency inspection isolated in `common.zig`. Their indexing,
ready selection, reset FIFO, and allocation-failure tests move with the
implementation. Response reset routing now reserves all reset storage and
checks QPACK dependencies before mutating either buffered or streaming state;
an integration failure-injection test verifies that decoder-feedback OOM keeps
the original stream indexed and retryable. This removes roughly another 700
lines from `runtime.zig` without adding files to the crowded runtime root.
Outbound body indexing, Content-Length accounting, lightweight flow-limit
state, and DATA batch scratch now live in `runtime/stream/outbound_body.zig`
with their indexing white-box test. Connection and protected send orchestration
remain in the root until their transport-specific callbacks can be separated;
callers no longer inspect the body's entry/index collections for lifecycle
decisions.
Incremental message parsing and multiplexed reader scheduling now live in
`runtime/stream/reader.zig` and `runtime/stream/set.zig`; their parser, QPACK
retry, index-repair, reset-FIFO, and fairness tests are colocated in dedicated
test modules. The root accesses reader identity, detach readiness, decoded-head
adoption, and receive-credit state through narrow methods, while development
peer migration uses reserved bulk-adoption helpers rather than manipulating the
set's arrays and indexes. Together with outbound body extraction this removes
roughly another 1,900 lines from `runtime.zig`.
Server-push receive state now lives in `runtime/stream/push/state.zig`, with
promise/stream dual indexes, reordered prefix parsing, cancellation FIFO, and
stable-ID round-robin scheduling hidden behind narrow lookup/iteration methods.
Its five state-machine tests moved to the sibling `state_tests.zig`; the
cancellation test now constructs real encoded push-stream prefixes rather than
manually mutating internal maps.
Role-aware HTTP/3 control-stream receive logic now lives in
`runtime/control/receive.zig`, including GOAWAY ID checks, client/server-only
frame validation, QPACK stream classification, critical-stream closure rules,
and transactional rollback of a complete control update. Focused role, batched
priority, and critical-stream tests live in `runtime/control/receive_tests.zig`;
transport close-code and socket-offset tests remain in the integration layer.
Control and QPACK critical-stream emission now lives beside it in
`runtime/control/send.zig`. The module owns frame construction, SETTINGS and
stream-prefix emission, priority and push controls, QPACK encoder instructions
and decoder feedback, while continuing to use the shared packetizer and
protected-send state directly. Splitting, scratch-reuse, and allocation-failure
rollback tests moved to `runtime/control/send_tests.zig`; focused QPACK, HTTP/3,
WebTransport, and WebSocket runs pass after the move. At this point the runtime
root is 26,792 lines, down 7,181 lines (about 21%) from the 33,973-line start of
this extraction pass, without adding more files to the crowded runtime root.
Three post-move CPU-0 `bench-http3-dev` samples measured 10.904, 10.951, and
10.942 us/request (91,307-91,708 requests/s), matching the preceding
10.941-11.234 us/request range without a visible small-message regression.
Pure dynamic QPACK request/response/streaming-head writer tests now live in
`runtime/qpack/tests/writer.zig`, protected speculative-compression coverage is
separate in `runtime/qpack/tests/integration.zig`, and request-priority admission/reconciliation
coverage lives beside request routing under
`runtime/receive/routing/tests/request.zig`. The development DATAGRAM
coalescing/retention test likewise moved beside its send implementation. These
moves remove test-only blocks from the runtime root without widening production
APIs or changing wire behavior.
Protected QPACK request/response transport cases are further separated into
`runtime/qpack/tests/request_transport.zig` and `response_transport.zig`; Push
control, event, aggregate/deadline, and send-scratch cases live under
`runtime/stream/push/tests/`. Protected client response and deadline cases live
under `runtime/client/tests/`, while server base, GRO, limits, lifecycle, receive,
and streaming cases live under `runtime/server/tests/`. Across this pass the H3
runtime root fell from 23,888 to 18,327 lines and from 88 to 42 inline test
declarations, without changing exported protocol types or wire behavior.
Authenticated request/response, Push, streaming-head, DATA, batch-progress, and
trailer send orchestration is now split again under `runtime/send/message.zig`
and `runtime/send/body.zig`, with focused white-box tests under
`runtime/send/tests/`. Both handshake-backed and preconfigured-key callers keep
their existing signatures through private root aliases. Protected batch send
now validates `sent_count <= protected_count <= staged_count` before committing
any HTTP/3 stream state, matching the full-connection invariant. The runtime
root is now 25,276 lines, down 8,697 lines (about 26%) from the 33,973-line
start of this extraction pass. Three CPU-0 post-split development samples
measured 10.972, 10.904, and 10.895 us/request (91,139-91,776 requests/s), with
no visible regression from the immediately preceding range.
Server-side request packet routing and lifecycle/priority coordination now live
in `runtime/receive/routing/request.zig`, with packet-level tests under the
nested `runtime/receive/routing/tests/` directory. Repeated RESET_STREAM frames
with the same peer, stream ID, and application code are idempotent while
conflicting peers or codes are rejected, avoiding a duplicate-event assertion
before the application consumes the first reset. RFC 9114/9204 connection-error
classification and close emission are centralized in
`runtime/receive/connection_error.zig`; handshake and lightweight protected
client/server receive paths now emit the exact stream-creation,
closed-critical-stream, frame, SETTINGS, ID, and QPACK application codes while
local allocation/timeout/transport and request-stream message failures are not
incorrectly promoted to connection errors. Wire/state tests cover both
stateful and preconfigured-key close paths. The root is now 24,886 lines, down
9,087 lines (about 27%) from 33,973. Three CPU-0
development samples after the receive/error changes measured 11.413, 11.052,
and 10.855 us/request (87,619-92,115 requests/s), within the established host
variance.
Handshake and lightweight protected clients now share the same response, Push,
control, QPACK, and reset dispatcher in `runtime/receive/routing/response.zig`;
the protected path no longer maintains a second frame-classification loop and
now flushes Insert Count Increment feedback as soon as encoder-stream progress
creates it. Tests accumulate QPACK decoder-stream bytes across packet boundaries
instead of assuming that an increment and later section acknowledgment share a
datagram. The runtime root is 24,530 lines after this extraction. Three CPU-0
samples measured 11.189, 10.948, and 10.957 us/request
(89,369-91,338 requests/s), within the preceding range.
The response dispatcher is now the single implementation used by both
handshake-backed and lightweight protected clients; the latter no longer
duplicates control/QPACK/Push/reset classification and now flushes QPACK Insert
Count Increment feedback immediately after processing encoder-stream packets.
The migrated response-reset OOM test and a focused feedback-routing test live
beside it. The runtime root is 24,519 lines after dead-helper cleanup; three
CPU-0 samples measured 11.125, 10.965, and 10.950 us/request
(89,881-91,317 requests/s), again within the established range.
The shared HTTP/3 packetizer now treats a socket-visible prefix followed by an
error as an ambiguous logical write: stateful connections install
`H3_INTERNAL_ERROR`, and the lightweight protected sender becomes unusable, so
callers cannot regenerate different QPACK/stream bytes at an already-visible
offset. A zero-visible-prefix failure remains retryable, while the explicit
body-batch progress API continues to commit only `sent_count` and retry its
suffix. Fault-injection tests cover an in-batch partial send, a failure after a
completed 64-packet batch, zero-progress retryability, and exact body-prefix
commit. Five hot CPU-0 development samples measured 10.760-11.154 us/request
(89,648-92,931 requests/s), with a 10.795 us/request median; an earlier cold,
system-noisy sample reached 18.999 us/request and is not used as regression
evidence.
A follow-up switched the stateful packetizer itself to the explicit
`sendManyProgress` result so internal reservation/accounting cannot be mistaken
for socket-visible progress. Existing small-window/backpressure tests and the
full suite pass with that correction. Three CPU-0 samples measured 10.924,
11.018, and 11.497 us/request (86,976-91,537 requests/s), still overlapping the
established range.
Shared-endpoint HTTP/3 uploads now accept multiple borrowed body slices as one
DATA frame and one QUIC packet without concatenating the payload. A fixed-clock
regression verifies zero socket calls and unchanged body/STREAM/FIN state when
pacing rejects the attempt, followed by exactly one socket call for the same
slices after timer progress. This is syscall and retry-accounting evidence; no
throughput claim is made without a stable comparative benchmark.
The shared-pool batch upload wrapper sends one DATA contribution for each of
several active request streams through the same `sendMany` submission. Its
progress result preserves both a socket-visible prefix count and a simultaneous
send error; fault injection verifies that only that prefix advances HTTP/3 body
state and the untouched suffix remains retryable.
HTTP/3 CONNECT DATAGRAM negotiation, send-side lifecycle checks, terminal
observation, queue polling/draining, and authenticated packet-order routing now
live beside the registry in `runtime/datagram/routing.zig`. The router preserves
DATAGRAM order around FIN/RESET/CONNECTION_CLOSE, validates transport-dropped
payloads, emits `H3_DATAGRAM_ERROR` for malformed Quarter Stream IDs, and keeps
the first terminal state stable until queued payloads drain. Registry traversal
uses narrow association accessors rather than exposing its storage layout. The
five-run 1-MiB real-handshake download remained functional at 118.75 MiB/s mean
on the loaded host; this is a regression smoke, not a new throughput claim.
The cleartext aggregate request buffer now lives in
`runtime/development/request_buffer.zig`. It exposes peer/stream metadata and a
pre-reserved ownership-transfer callback to the per-peer streaming layer rather
than exposing its entry array. Datagram validation now rejects a packet that
mixes two request stream IDs before mutating either reassembler, covered by a
dedicated transactional regression test.
Cleartext server peer coordination now lives under
`runtime/development/server_peer/`: each peer owns its buffered and streaming
requests, lifecycle, QPACK state, outbound body state, response offsets, and
send scratch. The root server retains socket locking and packet emission but
uses semantic response/cancellation contexts instead of reconstructing peer
state transitions from individual fields. Partial-request adoption and
pre-admission reset handling tests move with the coordinator.
Three CPU-0 `bench-http3-dev` smoke samples after the stream/development state
extractions measured 10.872, 10.790, and 10.869 us/request
(91,975-92,678 requests/s), within and slightly tighter than the prior
10.939-11.568 us/request range. An unpinned run immediately after the full test
suite measured 17.123 us/request and is retained only as scheduler-noise
evidence, not as a regression signal.
After moving the per-peer coordinator behind semantic response/cancellation
interfaces, three further CPU-0 samples measured 11.234, 10.941, and
11.062 us/request (89,010-91,393 requests/s), still within the same baseline.

HTTP/3 codec header assembly previously used fixed 64-element descriptor
arrays in request, response, streaming, informational, and Push Promise
writers. Those paths now use a shared 16-element stack buffer with an exact
allocation fallback, so ordinary messages reduce stack use while larger valid
field sections no longer fail as `InvalidFrame`. Static, dynamic, streaming,
informational, Push Promise, automatic-Date, and allocation-failure tests cover
80 application headers plus their pseudo/default fields.

`bench-http3-handshake-transfer` starts a loopback HTTP/3 server, creates a
fresh QUIC/H3 client connection per iteration, streams a fixed-size body in the
selected direction, and reports aggregate bytes/s. Both upload and download
modes use the handshake runtime's paced body sender: `CongestionLimited` and
`FlowControlBlocked` drive peer packet processing so ACK/MAX_* frames can reopen
send credit instead of turning large transfers into synchronous failures.
`--streams` splits the requested byte count across concurrent client-initiated
request streams, matching the shape of quicz's 4-stream aggregate benchmark.
`--round-robin-chunk-bytes` controls the per-stream scheduling quantum used by
multi-stream upload/download helpers; the default is 64 KiB, while smaller
values are useful for probing ACK/credit fairness without editing source.
`--one-rtt-datagram-size` and `--paced-body-chunk-bytes` override the benchmark's
default single-stream/multi-stream transfer sizing knobs, making it possible to
search stable packet-size-aware configurations without source edits. The
benchmark now creates a fresh loopback server/client pair per iteration and
reports mean/stddev MiB/s, matching quicz's multi-iteration benchmark shape.
`--ack-eliciting-threshold` controls the server ACK policy; the default of four
is the stable winner from the same-host 2/4/8/16/32 scan. Packet-size-aware
cross-stream body batches are available through
`sendRequestBodyBatchPaced`/`sendResponseBodyBatchPaced`, and
`--enable-body-batch` measures that path. It remains opt-in because this host's
sysctl-capped 212,992-byte UDP receive queue makes four-packet GSO bursts
slightly slower than sequential submissions.
`--enable-gro-receive` enables the timer-aware owning-batch receive path. It is
also opt-in on this host: the path now completes long uploads/downloads without
stalling, but its burst shape is slower and noisier under the same small receive
queue.
`--verbose` prints per-iteration throughput lines (`[iter N]`) for diagnosing
long or stuck multi-iteration runs. `--trace-iteration` additionally prints
coarse lifecycle stages (bind, connect, transfer, join) for each iteration.

```sh
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=16777216 --mode=upload --streams=4 --verbose
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=1048576 --mode=upload --streams=1
```

Current 5-iteration 1 MiB upload smoke sample:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 1
  iterations: 5
  body bytes/iteration: 1048576
  total body bytes: 5242880
  status total: 1000
  ns/iteration: 5055264
  bytes/s: 207422566
  MiB/s: 197
  mean MiB/s: 201.88
  stddev MiB/s: 26.15
  stddev percent: 12.95
```

Current 16 MiB single-stream upload result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 1
  iterations: 1
  body bytes/iteration: 16777216
  total body bytes: 16777216
  status total: 200
  ns/iteration: 633723309
  bytes/s: 26474039
  MiB/s: 24
```

Current 16 MiB single-stream download result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: download
  streams: 1
  iterations: 1
  body bytes/iteration: 16777216
  total body bytes: 16777216
  status total: 200
  ns/iteration: 630802886
  bytes/s: 26596606
  MiB/s: 25
```

Current 16 MiB / 4-stream upload result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 4
  body batch: false
  1-RTT datagram bytes: 8192
  paced body chunk bytes: 3000
  server ACK-eliciting threshold: 4
  iterations: 5
  body bytes/iteration: 16777216
  total body bytes: 83886080
  status total: 4000
  ns/iteration: 123919485
  bytes/s: 135388038
  MiB/s: 129
  mean MiB/s: 129.36
  stddev MiB/s: 5.50
  stddev percent: 4.25
```

This CPU-0-pinned sample was captured on 2026-08-17 after moving
ACK-driven packet-threshold recovery into QUIC's timer-servicing blocking
receive path. Before that fix, all client body-send calls could return while
dropped STREAM ranges remained pending; the client then waited for responses
and recovered only through exponentially backed-off PTO probes. The same
16 MiB / four-stream trace previously stalled after the server consumed about
9.4 MiB. All five iterations above delivered every stream through FIN.

Current 16 MiB / 4-stream download result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: download
  streams: 4
  iterations: 1
  body bytes/iteration: 16777216
  total body bytes: 16777216
  status total: 800
  ns/iteration: 134534611
  bytes/s: 124705574
  MiB/s: 118
```

After moving RFC 9218 scheduler offsets into candidate storage and carrying
the originating response index beside each fixed packet-staging slot, a
CPU-0-pinned three-iteration 16 MiB / 4-stream download regression run measured:

```text
per iteration: 54.75 / 55.19 / 55.16 MiB/s
mean: 55.03 MiB/s
stddev: 0.20 MiB/s (0.37%)
status total: 2400
verified body bytes: 50331648
```

The hot commit path no longer linearly scans small response sets or hashes
large response sets to recover an index. Up to sixteen responses remain fully
allocation-free at scheduler setup; larger sets now allocate one exact
candidate array and one temporary duplicate-ID set instead of four separate
work areas. A separate CPU-0 17-stream run forced that heap-backed path,
verified all 17,825,792 body bytes and status total 3,400, and completed at
53.97 MiB/s. Candidate refresh now accumulates the RFC 9218 selection in the
same pass instead of rescanning the full array; the same pinned 17-stream shape
then completed at 54.04 MiB/s. The roughly 0.13% difference is noise-level, so
the result establishes no regression while the removed pass is retained as a
direct CPU-work reduction for larger stream sets. Splitting QUIC's per-stream
flow-control query from its connection/congestion/PMTU snapshot then removed
three more repeated connection-level reads per response; the same shape measured
54.23 MiB/s, likewise a no-regression result rather than a significant change.
These are internal regression samples, not an equal-wire comparison with quicz.

This is now a real-handshake, paced single-stream and 4-stream upload/download
result with the same 16 MiB transfer size as the quicz reference benchmark
family. It is still not a completion claim: the next evidence step is to close
the same-host quicz gap below and add memory/allocation evidence.

### Same-host reference comparison against `~/Work/quicz`

Captured on the same host with `/tmp/quicz-bench-hs` compiled from
`~/Work/quicz/examples/quic_bench_hs.zig` using:

```sh
zig build-exe -OReleaseFast --dep quicz \
  -Mroot=/home/passchaos/Work/quicz/examples/quic_bench_hs.zig \
  -Mquicz=/home/passchaos/Work/quicz/src/lib.zig -lc \
  -femit-bin=/tmp/quicz-bench-hs
timeout 600s /tmp/quicz-bench-hs
```

Relevant quicz output:

```text
Stream Upload 228.77 MB/s  (stddev 3.3%, 5 iters x 64 MB)
Multi-Stream (4x) 244.85 MB/s  (stddev 2.8%, 5 iters x 64 MB, 4 streams)
Echo Latency P50=10.5us  P99=14.3us  P99.9=377.8us  (5000 iters)
Handshake Rate 1154.7 conn/s  (100 handshakes in 0.087 s)
Aggregate (4 conns) 512.50 MB/s  (4 concurrent conns x 64 MB in 0.500 s)
```

To align transfer size with quicz's real-handshake throughput run, netz was
also measured with `--body-bytes=67108864`:

```sh
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=upload --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=67108864 --mode=upload --streams=4 --verbose
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=4
```

```text
netz upload streams=1:   117.76 MiB/s mean, 5 iterations
netz download streams=1: 123 MiB/s, 129,894,689 bytes/s, one iteration
netz upload streams=4:   141.78 MiB/s mean, 2.76% stddev, 5 iterations
netz download streams=4: 32 MiB/s, 34,579,902 bytes/s, one iteration
```

Transport-only context against the quicz real-handshake STREAM baselines:

| Scenario | historical quicz raw QUIC STREAM | netz HTTP/3 DATA |
|---|---:|---:|
| 64 MiB single-stream upload | 228.77 MB/s | 117.76 MiB/s mean (5 iters) |
| 64 MiB 4-stream aggregate upload | 244.85 MB/s | 141.78 MiB/s mean (5 iters) |

These are deliberately **not** presented as a throughput ratio:
`quic_bench_hs.zig` calls raw `sendOnStream`, while netz also performs HTTP/3
DATA framing, request/response processing, and QPACK/session work. The netz
samples are CPU-0 pinned; the historical quicz values were not. A fresh
CPU-0-pinned quicz run produced 15.97 MB/s single-stream and 16.12 MB/s
four-stream because pinning both same-process endpoints to one CPU changes the
scheduling shape dramatically. Netz's raw benchmark showed the same scheduling
sensitivity. No equal-wire, equal-CPU quicz HTTP/3 benchmark is currently
available, so neither raw transport result is accepted as an H3 superiority
claim.

Fresh 5-iteration netz single-stream sample:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 1
  iterations: 5
  body bytes/iteration: 67108864
  total body bytes: 335544320
  status total: 1000
  ns/iteration: 550419981
  bytes/s: 121923015
  MiB/s: 116
  mean MiB/s: 117.76
  stddev MiB/s: 12.25
  stddev percent: 10.40
```

A matching CPU-0-pinned five-iteration 64 MiB / four-stream run now completes:

```text
per-iteration MiB/s: 143.53, 140.85, 146.05, 134.70, 143.78
mean MiB/s: 141.78
stddev MiB/s: 3.91
stddev percent: 2.76
```

This result combines a 6000-byte adaptive DATA chunk for 64 MiB multi-stream
runs with an ACK-eliciting threshold of four. Thresholds 2, 4, 8, 16, and 32
produced 129.07, 137.06, 112.87, 110.17, and 85.87 MiB/s means respectively.
The shorter 16 MiB/four-stream shape retains 3000-byte packets and improved
from the previous 69.43 MiB/s sample to 129.36 MiB/s with threshold four.

The optional cross-stream body batch completed five 64 MiB iterations at
134.89 MiB/s mean and 2.38% stddev. It is not the default on this host because
the sequential path is slightly faster with the small kernel receive queue.
The API still provides exact protected-packet sizing, per-DATA prefix ownership,
and socket-visible-prefix commit semantics for hosts that can absorb bursts.

The first recovery-cache stage retained a bounded four-block stack per
power-of-two payload class, with a global 1 MiB idle-byte cap. ACK/forget paths recycle without
allocating, and retransmission candidates expose only the logical encoded
payload rather than bucket slack. A 10-pair alternating CPU-0 A/B against
commit `28e8698` was throughput-neutral:

```text
recovery cache: 139.285 MiB/s mean, 4.890 MiB/s stddev
baseline:       139.315 MiB/s mean, 3.194 MiB/s stddev
delta:          -0.02%
```

One 64 MiB/four-stream `--stats` pair showed:

```text
                         recovery cache    baseline
allocations:             168,178           183,819
cumulative allocated:    385,898,699 B     464,527,093 B
peak live:                83,950,631 B      94,586,109 B
```

That is 8.5% fewer allocation calls, 16.9% fewer cumulative allocated bytes,
and 11.2% lower peak live memory in the captured pair, without measurable
throughput loss.

The original four-block depth later became visible again after other hot-path
allocations were removed: a thread-safe `--stats` rerun found 392-673 exact
4096-byte allocations and 403-684 recovery-cache misses in three otherwise
identical 16 MiB/four-stream uploads. The near one-to-one counts came from
3000-byte STREAM payloads rounding to the 4-KiB cache class, then being released
in ACK bursts deeper than four. Recovery storage now keeps four direct slots
per class and links overflow blocks through their own inactive payload bytes.
This keeps acquire/release O(1) and allocation-free, adds only one head pointer
per size class, and retains the existing 1 MiB global cap instead of reserving
large fixed slot arrays per connection. Size-isolation, full-budget, overflow,
logical-prefix and deinit tests cover the new ownership scheme.

CPU sampling of the same workload showed the larger remaining cost in
`RecvState.Preflight.insertTracked`: ordered, non-overlapping STREAM frames
still scanned every payload byte to prove they were new. Preflight now checks
frame ranges first and counts an append beyond both retained and packet-local
state in O(frames); overlapping/reordered frames retain the original bytewise
conflict and duplicate accounting. A matched five-pair CPU-0 A/B, each process
running five 16 MiB/four-stream iterations, measured 114.11 MiB/s mean for the
cached old binary and 152.69 MiB/s after both changes, a 33.8% improvement
(median improvement 33.5%). All 25 iterations in each side verified the exact
80 MiB aggregate and status total. Thread-safe final telemetry made 839-900
allocations with 304-349 exact 4-KiB allocations, versus the pre-change median
1195 allocations and 603 exact 4-KiB allocations: reductions of 29.6% and
49.6%. Median cumulative allocated bytes fell from 31.27 MB to 24.38 MB
(22.0%), while median peak live bytes fell from 28.29 MB to 23.89 MB (15.5%).
These stats include one 16 MiB transfer body retained by the benchmark.

The next profile showed recovery ACK compaction spending about 12% of sampled
cycles rebuilding two hash indexes after every range ACK. Those indexes were
also maintained for every sent packet even though the hot ACK path already
walks the ordered recovery queue. Removing both maps keeps monotonic new-packet
validation O(1) through a cached maximum and uses bounded linear scans only for
single-packet rollback/acknowledgement and handshake-group queries. A five-pair
CPU-0 A/B of the same 16 MiB/four-stream workload measured 148.94 MiB/s mean
with indexes and 191.33 MiB/s without them, a 28.5% improvement (27.5% at the
median). Three serial 5%-loss runs remained within noise at 2.86-2.90 MiB/s,
dropped exactly 25 of 504 datagrams, reported 25 transport losses, and verified
all 4 MiB. Three `--stats` runs made 746-894 allocations (825 median) and
280-341 exact 4-KiB allocations (284 median). Recovery-burst variance made
cumulative and peak byte totals overlap the indexed samples, so no memory-byte
claim is made for this second step. Ordered removal, ACK compaction,
original/retransmission lookup and
allocation-failure tests now assert behavior rather than internal map layout.

The following current-source profile found the read-only loss-timer selector
spending 13.5% of samples repeatedly scanning sent-packet metadata to find the
latest ordinary ACK-eliciting PTO anchor. The tracker already cached the latest
ACK-eliciting in-flight packet for generic PTO calculation, so the non-PMTU
query now returns that entry directly when it is an ordinary packet and keeps
the full scan only when a PMTU probe owns the cache or directly mutated test
metadata violates the production invariant. In five alternating CPU-0 pairs of
five 16 MiB/four-stream uploads, the exact pre-change binary averaged 181.29
MiB/s (182.04 median) and the fast-path binary averaged 194.97 MiB/s (195.57
median), improvements of 7.5% and 7.4%. Every side transferred 80 MiB and
reported status total 4000. A post-change profile reduced
`lossDetectionTimerDeadline` self samples from 13.5% to 2.0%. A 5%-loss run
dropped exactly 25/504 datagrams, reported 25 transport losses, and verified
all 4 MiB at 2.92 MiB/s. This step adds no allocation; telemetry retained the
existing ACK-burst variance, so no memory improvement is claimed.

That post-change profile also attributed 2.7% of samples to
`hasAcknowledgedEctBeyondEcnWatermark`, which rescanned retained packet metadata
after each ACK. The tracker now records the highest packet number ever
acknowledged with ECT(0), ECT(1), or CE and compares it directly with the
largest ACK covered by validated ECN counters. Besides making the query O(1),
the monotonic watermark remains correct after acknowledged packet metadata is
compacted; a dedicated regression crosses the 256-packet compaction threshold,
then consumes the outstanding ACK_ECN baseline. Five alternating CPU-0 pairs
against the exact PTO-fast-path binary measured 179.69 MiB/s mean (182.60
median) before and 198.49 MiB/s mean (207.70 median) after, captured gains of
10.5% and 13.7%. All 25 iterations on each side transferred exactly 80 MiB and
reported status total 4000. The target scan disappeared from a normally
completed post-change profile. A 5%-loss run still dropped exactly 25/504
datagrams, reported 25 transport losses, and verified all 4 MiB. This state is
allocation-free and no memory reduction is claimed.

The packet-level validate-before-mutate pass and the later ACK application used
to run `precheckAckRanges` twice over the same single-ACK packet. The preflight
now returns a shape-bound validation token carrying its private summary; the
apply path verifies the ACK fields, range-slice identity, and path epoch before
reusing it. Multi-frame packets retain the original independent validation so
no earlier frame can commit before a later malformed ACK is rejected. Five
alternating CPU-0 pairs against the exact pre-change binary measured 198.23
MiB/s mean (195.98 median) before and 205.85 MiB/s mean (202.65 median) after
across two clean, order-balanced sets of ten one-iteration pairs, gains of 3.4%
for both mean and median. Every run transferred 16 MiB and reported status
total 800. `precheckAckRanges` fell from 5.35% to 1.67% of sampled cycles; a
5%-loss run dropped exactly 25/504 datagrams, reported 25 transport losses, and
verified all 4 MiB at 2.86 MiB/s.

The remaining sent-packet exact index is deliberately best-effort because every
lookup already falls back to binary search on the production-ordered metadata
array. Prefix compaction previously removed every retired key and then rewrote
every surviving map value. It now clears the map in O(1), retaining its
allocation for later inserts while old retained packets use binary search. Two
clean order-balanced sets of twenty one-iteration pairs measured 184.40 MiB/s
mean for the retained repair path and 197.94 MiB/s after clear-on-compaction
(+7.3%); medians were approximately 193.7 and 198.7 MiB/s (+2.6%). The
`refreshPacketIndexFrom` symbol disappeared from the follow-up profile. A
5%-loss run dropped exactly 25/504 datagrams, reported 25 transport losses, and
verified all 4 MiB at 2.90 MiB/s.

Recovery ACK compaction then stopped copying every `PendingDatagram` into a
loop temporary and copying ACKed entries again before recycling. It now scans
entries by pointer, recycles matches in place, and copies only survivors that
actually move toward the queue head. A clean order-balanced set of twenty
one-iteration pairs measured 212.30 MiB/s mean for the prior build and 230.49
MiB/s for the pointer-based compaction (+8.6%); medians were 202.05 and 231.06
MiB/s (+14.4%). The follow-up profile reduced ACK-apply self samples to 2.73%
and left no standalone recovery-entry copy hotspot. A 5%-loss run dropped
exactly 25/504 datagrams, reported 25 transport losses, and verified all 4 MiB
at 2.90 MiB/s.

The clean recovery queue now also records whether original packet numbers stay
monotonic. When no retransmission copies exist, a single continuous ACK range
uses two binary searches to locate the affected queue slice, recycles only that
slice, and moves the trailing survivors once. Multi-range ACKs, retransmission
groups, forgotten originals, and synthetic out-of-order insertion retain the
existing per-entry membership scan. Two order-balanced sets totaling forty
one-iteration process pairs completed 40/40 on both sides. The fixed prior
binary averaged 222.69 MiB/s and the candidate averaged 231.80 MiB/s (+4.1%);
the median within-pair ratio improved 2.2% (mean ratio +7.1%). The host showed
distinct roughly 200 and 260 MiB/s scheduling modes, so the independently
sorted median delta is intentionally not used as evidence. In the follow-up
profile, recovery `entryAcked`/`containsRange` membership fell from about 2.5%
inclusive to 0.51%, while the selected-slice retirement/move accounted for
about 1.32%. Three direct 5%-loss runs each dropped exactly 25/504 datagrams,
reported 25 transport losses, and verified all 4 MiB.

Single-packet send preparation formerly walked the same frame slice separately
for wire length, retransmittable length, ACK-eliciting/in-flight traits, pending
HANDSHAKE_DONE detection, and the largest ACK carried. Those pure observations
now share the existing wire-length pass; validation and flow-control mutation
retain their original order. A clean order-balanced set of twenty one-iteration
pairs measured 212.86 MiB/s mean before and 235.37 MiB/s after (+10.6%); all
runs transferred exactly 16 MiB with status total 800. `Frame.wireLen` no longer
appeared as a standalone top profile entry. A 5%-loss run still dropped exactly
25/504 datagrams, reported 25 transport losses, and verified all 4 MiB.

The benchmark's former local counter used plain integers across client/server
threads and could undercount racing allocator calls. It now reuses the shared
atomic counting allocator, reports exact sizes and recovery-cache hit/miss
totals, and is the authoritative source for the numbers above.

Receive preflight no longer clones the heap-backed path-validation state for
every authenticated packet, and its distinct-stream shadow starts in fixed
packet-local storage. A same-command 16 MiB/four-stream upload A/B against
commit `1757907` reduced allocation calls from 34,980 to 29,223-29,300
(16.2-16.5%), while cumulative allocated bytes fell from 102,829,311 to
100,431,864-100,595,813 (2.2-2.3%). The three post-change samples measured
270.48-274.31 MiB/s versus the captured 191.95 MiB/s baseline sample; the
allocation delta is the stable conclusion, while the large single-run
throughput swing should be treated as promising rather than a final ratio.
Failing-allocator and duplicate-PATH_RESPONSE tests cover the new no-path
fast path and packet-local transactional response tracking.

The synchronous non-GRO visitor/service pump now receives UDP directly into a
connection-owned buffer instead of allocating and shrinking one endpoint
buffer per packet. Against the post-preflight baseline above, the same 16
MiB/four-stream `--stats` shape dropped again from 29,223-29,300 allocation
calls to 15,210-15,268 (47.8-48.1%), and from 100.4-100.6 MB cumulative
allocation to 25.8-27.1 MB (73.1-74.3%). Three runs measured 175.15-281.39
MiB/s; like the previous single-run spread this supports a no-regression smoke,
not a stable throughput ratio. Caller-buffer endpoint and two-packet
connection-reuse tests verify borrowed lifetime and storage reuse; GRO remains
on its owning batch API because one kernel receive may outlive a single packet
callback.

The next receive-preflight step shares one packet-local STREAM-frame shadow
across every distinct stream instead of allocating an ArrayList for the first
frame on each stream. The same 16 MiB/four-stream shape fell from
15,210-15,268 to 9,519-9,585 allocation calls (37.2-37.4%); cumulative
allocation fell from 25.8-27.1 MB to 24.4-25.6 MB. Three smoke runs measured
237.49-275.42 MiB/s. Caller-storage, cross-stream overlap, and heap-spill tests
cover both the common fixed-capacity path and packets exceeding it.
The benchmark allocator now also reports the most frequent exact allocation
sizes, which identified the remaining 144-byte hot bucket as short-lived
runtime work rather than retained body ownership. ClientHello ALPN parsing was
one confirmed contributor and now stores up to 16 offered protocol views inline
without an auxiliary allocation; parser tests cover multi-ALPN round trips and
allocation-free teardown. The 16 MiB/four-stream smoke remained at 275.41
MiB/s with 9,551 allocations, while cumulative allocation fell from the prior
24.4-25.6 MB range to 24,085,274 bytes in the captured run.

Stack sampling then identified the dominant steady-state 144-byte allocation
at `sendWithEcnAtRaw`: every STREAM packet built a temporary rollback-credit
ArrayList even though ordinary packets touch one stream. That journal now uses
16 fixed entries and spills only unusually wide packets. Against the prior
9,519-9,585 range, three identical 16 MiB/four-stream runs used only
2,525-2,532 allocations (73.4-73.6% fewer) while sustaining 241.94-272.26
MiB/s. A failing-allocator STREAM send test proves warmed recovery/sent storage
no longer hides a rollback-journal allocation.

The next exact-size sample traced 160-byte churn to ACK range decoding in the
in-place visitor path. `parseFrameInto` now decodes ACK pairs into retained
connection storage, so ACK processing no longer allocates/free a range slice
for every feedback packet. Two stable 16 MiB/four-stream samples used only
1,162-1,189 allocations versus 2,525-2,532 before (53.0-54.0% fewer), with
214.45-225.55 MiB/s. One noisy run exercised substantially more recovery and
is excluded from the stable allocation range rather than being hidden. Caller
storage and insufficient-range tests cover the new parser contract.

Timer-aware HTTP/3 GRO validation used the same 64 MiB/four-stream shape:

```text
upload, five iterations:
  samples: 117.83, 122.24, 103.24, 123.80, 121.55 MiB/s
  mean: 117.73 MiB/s, stddev: 6.38%

download, three iterations:
  samples: 87.01, 84.43, 106.60 MiB/s
  mean: 92.68 MiB/s, stddev: 10.68%
```

Both directions completed every iteration. The transport test additionally
drops the original STREAM packet and proves that a GRO batch receive fires PTO,
sends packet-number 1 as a recovery probe, and returns the response afterward.
GRO therefore no longer suppresses recovery timers; it remains disabled by
default solely because it is slower on this host.

The earlier run completed iteration 0 at 33.92 MiB/s and then timed out. A
single traced 16 MiB run showed all four client send loops complete while the
server stopped at roughly 9.4 MiB. ACK processing had already classified old
packets as packet-threshold losses and removed their congestion accounting, but
the HTTP/3 receive pump did not drain those recovery candidates. The corrected
blocking QUIC pump immediately retransmits a bounded set after each received
ACK, stopping transactionally at congestion or pacing limits. PTO remains the
fallback rather than the primary repair mechanism.

The current evidence shows netz is **reliable and substantially faster than its
previous H3 baseline**, but does not establish superiority over quicz HTTP/3
because an equal-wire reference is missing. Raising the
single-stream 1-RTT datagram budget to 8192 bytes, disabling HyStart for the
low-RTT single-stream benchmark, and using a 7200-byte paced DATA chunk closes
much of the previous 3 MiB/s cliff, but quicz still leads on
64 MiB four-stream aggregate throughput. Releasing all active streaming response
reader capacity before each multi-response packet receive stabilizes the 64 MiB
four-stream download case, but quicz still leads substantially. The next
optimization target is reducing per-packet recovery ownership and STREAM/DATA
framing overhead, then retesting batching on a host with a larger UDP receive
queue. A completion audit cannot pass
until this gap is closed with measured same-host evidence.

### Allocation / peak-live evidence

`bench-http3-handshake-transfer` supports `--stats`, which wraps the benchmark's
allocator and reports allocation counts, remaps, total allocated/freed bytes,
live bytes, and peak live bytes. This is intended to make transfer-path memory
work visible before further optimization.

```sh
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1 --stats
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=upload --streams=1 --stats
```

Historical stats samples below predate the thread-safe shared counter and may
undercount racing client/server allocations. They remain only as provenance;
the post-fix 16 MiB/four-stream evidence above is authoritative.

```text
16 MiB upload streams=1:
  alloc count: 89254
  remap count: 4697
  total allocated bytes: 248079087
  peak live bytes: 18022064
  allocation buckets:
    <=64: count=28812, bytes=486182
    <=256: count=17747, bytes=2288067
    <=1K: count=8280, bytes=4490099
    <=4K: count=9889, bytes=23322296
    <=16K: count=24798, bytes=200343435
    <=64K: count=8, bytes=217296
    >64K: count=3, bytes=16916528

64 MiB upload streams=1:
  alloc count: 359369
  remap count: 18527
  total allocated bytes: 994566095
  peak live bytes: 69991771
  allocation buckets:
    <=64: count=116957, bytes=1987374
    <=256: count=71353, bytes=9181107
    <=1K: count=32856, bytes=17816435
    <=4K: count=39073, bytes=92460728
    <=16K: count=99583, bytes=804544983
    <=64K: count=8, bytes=217296
    >64K: count=7, bytes=68083856
```

The single-stream DATA prefix fast path is enabled only for `streams=1`, where
its payload lifetime is simple. Together with outbound body frame-scratch reuse,
it reduces the 64 MiB single-stream upload cumulative allocation from about
1.29 GiB to about 995 MiB. The `<=16K` bucket still dominates with about 99k
allocations and 805 MiB of traffic, so future multi-stream payload-buffer work
still needs explicit per-send or per-stream lifetime isolation.

Rejected experiments after validation:

- Changing the aggregate timer-query chain from by-value to read-only pointer
  receivers removed the large copies visible in generated code:
  `nextTimerDeadline`'s stack frame fell from about 23 KiB to 152 bytes and
  total `memcpy` self samples fell from 5.69% to 1.25%. End-to-end behavior did
  not follow that micro-level improvement. In a strict serial, order-balanced
  20-pair run the baseline completed 20/20 processes while the candidate
  completed 19/20; across the 19 completed pairs mean throughput fell from
  231.57 to 213.79 MiB/s (-7.7%) and median throughput fell from 259.05 to
  208.44 MiB/s (-19.5%). A narrower follow-up kept every public receiver ABI
  unchanged and used pointer helpers only inside the blocking timer pump. It
  improved the 19 completed pairs by 2.9% mean/3.9% median, but still timed out
  in 1/20 candidate processes while the baseline completed 20/20. Both
  receiver variants were removed.
- A narrower ACK experiment preserved the by-value `ValidatedAck` token but
  added a pointer-based `SentPacketTracker` validation wrapper for the packet
  preflight. It removed one tracker materialization and reduced the generated
  validation stack frame, but did not show a stable end-to-end improvement
  under concurrent host load. The wrapper was removed and no quantitative
  claim is retained.
- Combining PATH_CHALLENGE/PATH_RESPONSE counting in the general receive
  preflight and carrying the challenge count into apply removed two frame-slice
  scans, but did not show a stable end-to-end improvement under concurrent host
  load. The count plumbing was removed and no quantitative claim is retained.
- Splitting the large general receive preflight into a no-inline slow path let
  single-ACK packets avoid its CID/PATH/STREAM stack storage and reduced the
  hot apply function's generated stack frame from about 7.9 KiB to 3.4 KiB.
  Opposite-order CPU-1 sets under concurrent host load did not agree, so the
  unstable split was removed and no quantitative claim is retained.
- Preparing the received-packet ACK-range insertion before frame validation and
  committing that exact action afterward removed the second freshness lookup
  while preserving validate-before-mutate semantics. Direct equivalence tests
  covered append, extension, merge, insertion, bounded eviction, duplicate,
  too-old, and ECN cases. End-to-end runs under concurrent host load were
  neutral while `applyReceivedFramesForDestination` self samples increased, so
  the token and tests were removed and no quantitative claim is retained.
- Replacing the STREAM gap-fill tail loop with a standard-library scalar slice
  search stopped updating `contiguous_end` for every present byte, but two
  opposite-order CPU-1 sets under concurrent host load did not agree. The
  original compact loop was restored and no quantitative claim is retained.
- A follow-up explicitly scanned sixteen byte-bitmap flags at a time; generated
  code used 128-bit loads and tests covered sparse tails, overlap, and
  transactional receive. It still timed out in one candidate process while the
  baseline completed every run, and its completed-pair median ratio was
  slightly negative. The vector scan was removed.
- Letting ACK-driven time-threshold loss skip the ordered prefix that the
  immediately preceding packet-threshold pass had already marked reduced the
  time-threshold function below the profile reporting cutoff while preserving
  the two existing loss generations and callback order. The candidate timed
  out in one of twenty reverse-order runs while the baseline completed all
  runs, so the hint and its equivalence test were removed.
- Hoisting a single recovery ACK range's fixed bounds out of the per-entry
  retransmission fallback preserved exact 5% loss behavior across forty runs
  per side, but the two opposite-order sets were neutral and disagreed in
  mean/median direction. The duplicate compaction helper was removed.
- Directly constructing the first ACK range for frames with no additional
  ranges, while isolating the 32-range decode scratch in no-inline slow helpers,
  reduced the common validation stack frame from about 1080 to 664 bytes. Two
  opposite-order CPU-1 sets completed 40/40 processes per side, but their
  median within-pair changes were -0.37% and +0.30%; the apparent aggregate
  mean gain followed the host's bimodal scheduling rather than a stable pair
  improvement. The split decode path was removed.
- Passing the validated-ACK summary by pointer instead of by-value optional
  preserved all focused tests but regressed a clean order-balanced 20-pair run
  from 202.26 to 200.48 MiB/s mean (median -1.2%). The pointer ABI was removed.
- Moving largest-ACK watermark updates to the range level and passing known
  packet indices into `markPacketAcknowledged` removed redundant per-packet
  comparisons, but a clean order-balanced 20-pair run regressed from 211.65 to
  208.91 MiB/s mean (median -2.0%). The change was removed.
- A single-STREAM-packet preflight specialization used one-entry stack shadows
  and skipped the general CID/path setup while preserving full STREAM, final
  size, flow-control, and duplicate validation. A clean order-balanced 20-pair
  run was neutral at 205.41 versus 206.12 MiB/s mean, with an unchanged median
  (200.27 versus 200.18 MiB/s), so the duplicate path was removed.
- Lazily copying the peer/local connection-ID preflight pools only when a
  NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frame appeared passed CID, STREAM,
  and transactional preflight tests, but a clean order-balanced 20-pair run was
  effectively neutral: 195.98 versus 197.45 MiB/s mean, while the median moved
  from 198.70 to 197.23 MiB/s. The branchy optional shadows were removed.
- Extending the validated-ACK token with a cached
  `newly_acked_ack_eliciting` decision removed the RTT helper's range scan, but
  a clean order-balanced 20-pair run was neutral at 196.72 versus 196.58 MiB/s
  and the candidate timed out once while the baseline did not. The extension
  was removed.
- Treating only the dense STREAM prefix as implicitly present, while retaining
  byte flags for sparse tails, passed receive/preflight tests but regressed a
  clean order-balanced 20-pair run from 200.02 to 192.23 MiB/s mean (-3.9%);
  the median moved from 200.37 to 198.56 MiB/s. The fast path was removed.
- Extending the single-ACK validation token to replace the separate plain-ACK
  ECN fallback precheck passed focused tests but regressed a clean,
  order-balanced 20-pair run from 202.38 to 199.37 MiB/s mean (median -1.7%).
  The extension was removed while retaining token reuse for ACK application.
- Packing the STREAM receive-presence bitmap from one byte per stream byte to
  one bit preserved cross-word gap filling, compaction, overlap, preflight and
  sliding-window tests, but a clean order-balanced ten-pair run regressed from
  210.44 to 183.60 MiB/s mean and 209.38 to 182.21 MiB/s median. The packed
  representation was removed; linear byte flags remain faster on this CPU.
- Removing `SentPacketTracker`'s best-effort exact hash index passed focused
  lookup, rollback, and allocation tests and reduced first server 1-RTT-send
  allocations from four to three. In a clean process-level-timeout comparison,
  however, the indexed baseline completed all five runs while the no-index
  candidate timed out in two of five. The prototype was removed; throughput
  samples captured while earlier timed-out benchmark processes were still live
  are intentionally not reported.
- Splitting ACK coverage validation into a count-only preflight avoided reading
  ECN and acknowledgement fields during the packet-level transactional pass,
  but five alternating 16 MiB/four-stream samples averaged 201.85 MiB/s for
  the retained shared precheck and 197.56 MiB/s for the specialized version
  (-2.1%; median -3.9%). The duplicate helper was removed.
- An earlier attempt to widen `AckResult` with the plain-ACK ECN decision also
  passed focused tests but showed no stable throughput improvement. It was
  removed; its measurements overlapped later-discovered stray benchmark
  processes and are not retained as quantitative evidence.
- Treating an empty STREAM receive bitmap as an implicitly contiguous retained
  buffer removed the per-chunk boolean `memset` from ordered traffic and
  materialized the bitmap only after a gap. It passed receive, overlap,
  preflight, and sliding-window tests, but five alternating 16 MiB/four-stream
  samples fell from 196.47 to 178.38 MiB/s mean (-9.2%). The representation
  change and its tests were removed.
- Starting the read-only time-threshold deadline scan at the existing
  `first_unacknowledged_index` cursor was correct for sorted production packet
  metadata and retained the full-scan fallback for synthetic out-of-order
  insertion, but did not show a stable end-to-end improvement. The change and
  its tests were removed; contaminated measurements from before stray benchmark
  processes were discovered are intentionally omitted.
- Replacing ACK-time recovery-index rebuilding with either a lazy queue-head
  cursor or targeted updates for moved entries preserved all recovery tests but
  regressed the same 16 MiB/four-stream benchmark. Five alternating process
  pairs measured 151.41 MiB/s for the retained full rebuild versus 147.93
  MiB/s for targeted updates; the cursor variant was similarly slower and more
  variable. Both experiments were removed.
- Reusing a single shared DATA payload scratch buffer, per-stream payload
  scratch, and pre-sizing each temporary DATA payload all reduced single-stream
  allocation counts, but they caused 64 MiB 4-stream validation timeouts or
  `StreamBufferTooLarge` failures.
- Enabling the DATA prefix fast path for multi-stream upload regressed 64 MiB
  4-stream throughput, so it remains single-stream-only.
- Replacing paced multi-stream upload with a naive event-loop style
  `sendRequestBody` loop triggered `DatagramTooLarge`; multi-stream batching
  needs packet-size-aware grouping rather than bypassing the paced chunker.
- A first batch-body prototype grouped chunks by STREAM-frame count and hit
  `DatagramTooLarge`. The current API instead queries exact protected packet
  length at each packet-number offset, isolates DATA-prefix storage, and
  commits only the socket-visible QUIC batch prefix.
- Replacing the generic `sendConnectionFrames` splitter with conservative
  `wireLen()`-based grouping avoided `DatagramTooLarge` but caused 64 MiB
  4-stream download timeouts; packet-size-aware batching needs to be scoped to
  the new batch-body API rather than changing all HTTP/3 frame sends.
- Multi-stream `--paced-body-chunk-bytes` scans before the ACK-driven recovery
  fix incorrectly made larger chunks look unstable. The benchmark now retains
  3000 bytes below 64 MiB and uses 6000 bytes for the quicz-shaped 64 MiB
  aggregate; 12/14/16 KiB datagram experiments were slower or much noisier.
- Multi-stream `--round-robin-chunk-bytes` scans did not find a better stable
  default either: 16 KiB timed out on upload and hit `StreamBufferTooLarge` on
  download; 32 KiB improved download to ~40 MiB/s but still timed out on upload.

Future multi-stream payload-buffer work needs per-send or per-stream lifetime
isolation, not one shared mutable buffer or a change that increases the
multi-stream send/receive critical section.

## Raw QUIC real-handshake STREAM comparison

Captured on 2026-08-17 with a fresh TLS 1.3/QUIC handshake per iteration:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --iterations=3 --transfer-bytes=67108864 --streams=1 --verbose
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --iterations=3 --transfer-bytes=67108864 --streams=4 --verbose
```

```text
netz single stream:
  samples: 298.21, 318.45, 318.43 MiB/s
  mean: 311.69 MiB/s, stddev: 3.06%
  payload bytes received: 201326592

netz four streams:
  samples: 317.32, 313.78, 312.95 MiB/s
  mean: 314.68 MiB/s, stddev: 0.60%
  payload bytes received: 201326592
```

The historical same-host quicz run recorded above produced 228.77 MB/s
single-stream and 244.85 MB/s four-stream means. Those values were not
CPU-pinned. A new `taskset -c 0 /tmp/quicz-bench-hs` run produced 15.97 MB/s
and 16.12 MB/s because both same-process endpoints contend for one CPU; a
matching pinned netz probe was similarly scheduling-bound. The prior 1.36x and
1.29x ratios are therefore withdrawn. Future raw QUIC claims require an
equivalent endpoint CPU layout, not merely a shared host and transfer size.

This comparison intentionally disables GSO/GRO. The host clamps
`net.core.rmem_max` to 212,992 bytes, so a same-process multi-packet burst can
overflow the effective UDP receive queue and create artificial loss. The
benchmark defaults to one submitted packet per userspace batch while retaining
`--batch-packets` for tuned hosts. Dedicated GSO/GRO benchmarks remain the
evidence for coalesced I/O performance.

The transport changes supporting this run are not benchmark-only shortcuts:
STREAM packet validation now borrows existing receive state instead of cloning
the retained body, applications can borrow and incrementally consume
contiguous STREAM data without allocation, and ACK-driven packet-threshold
losses can be retransmitted in a bounded drain before waiting for PTO.

### Raw QUIC TLS 1.3 handshake latency, rate, and memory

Captured on 2026-08-19 using authenticated P-256 CertificateVerify, X25519,
TLS_AES_128_GCM_SHA256, and fresh loopback QUIC endpoints for every sample:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=handshake --iterations=200
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=handshake --iterations=100 --stats
```

Three consecutive samples after the optimization were:

```text
connections/s: 824.1, 830.7, 817.6
p50:           1179.1, 1172.1, 1185.2 us
p99:           1409.9, 1367.8, 1712.8 us
```

The first two values came from 200-iteration runs; the final value came from
the 100-iteration allocator run. A later validation pair under varying host
load sustained 797.2 and 806.2 conn/s, so the faster pair is evidence of the
captured improvement rather than a guaranteed floor. The allocator run ended
with zero live bytes, 9,201 allocations (92.0 per connection), 15,001,739
cumulative bytes and an 88,276-byte peak. Before exact Initial packet sizing it
used 16,701 allocations
(167.0 per connection), 1,700 remaps and 22,185,904 cumulative bytes. The new
wire-length calculation removes speculative encrypt/allocate/free probes and
reserves exact long-header packet storage, reducing allocation calls by 44.9%,
remaps by 88.2%, and cumulative allocated bytes by 32.4%.

The benchmark also stopped creating one OS thread per connection and now uses
the existing `std.Io` executor, while the immutable long-term P-256 key is
materialized once and each handshake still creates a fresh CertificateVerify
signature and validates it against the pinned public key. Relative to the
original captured 638.0 conn/s sample, the current 824.1-830.7 conn/s pair is
29.2-30.2% higher. The current quicz sample remains faster and skips server
CertificateVerify validation, so this is an internal improvement rather than
a cross-stack superiority claim.

`--skip-server-verification` now exposes that policy difference explicitly
without removing the server Certificate or its fresh P-256 CertificateVerify
signature. Five CPU-0-pinned 200-connection runs measured p50
657.9-833.0 us, p99 1.328-9.971 ms, and 449.6-1426.7 conn/s; the middle samples
were 668.8 us and 881.9 conn/s. Three matching runs of the audited quicz
handshake-only artifact measured p50 800.3-811.9 us, p99 3.005-5.813 ms and
538.4-788.6 conn/s. Netz is therefore faster at p50 in four of five captured
runs and has the higher median rate, but host scheduling still produces enough
tail/rate variance that this is evidence of a closed verification-cost gap, not
a universal handshake-superiority claim. A 100-connection `--stats` run ended
with zero live bytes and used 9,001 allocations, 14,985,675 cumulative bytes
and an 88,276-byte peak.

### Raw QUIC real-handshake 1 KiB echo latency

Captured on 2026-08-20 with one real authenticated handshake followed by 5,000
ordered 1 KiB STREAM round trips on stream 0. Both endpoints run sequentially
on CPU 0, ACKs are piggybacked on the next request/response, and every returned
payload byte is checked before its latency sample is accepted:

```sh
taskset -c 0 zig build bench-quic-handshake-stream \
  -Doptimize=ReleaseFast -- --mode=echo
taskset -c 0 /tmp/quicz-echo-only
```

Three consecutive pinned runs:

```text
netz:
  p50:   10.44-10.57 us
  p99:   15.22-15.53 us
  p99.9: 31.89-47.02 us
  rate:  92,252-93,030 round trips/s

quicz:
  p50:   10.5-10.7 us
  p99:   16.0-19.5 us
  p99.9: 206.3-211.2 us
```

Netz is 0.99-1.02x quicz at p50, 1.03-1.28x faster at p99, and 4.4-6.6x lower
at p99.9 in these controlled runs. The new `sendWithPendingAck` transport API
combines an application response with its cumulative ACK, and receiving an
ACK-of-ACK prunes old received packet-number ranges. A subsequent perf profile
showed sent-packet ACK/loss processing repeatedly scanning the full resolved
metadata prefix: cost grew with connection lifetime despite one new packet per
round. `SentPacketTracker` now retains a first-unacknowledged cursor, uses
binary range boundaries for cumulative ACK validation, and starts recovery
scans at the unresolved suffix. A 5,000-round `--stats` run made 159 total
allocations, ended with zero live bytes, and verified all 5,120,000 echoed
payload bytes.

Sent-packet metadata now also compacts acknowledged contiguous prefixes in
256-packet batches. The tracker retains the retired packet-number interval for
duplicate cumulative ACK validation, while unresolved/lost packets keep full
RTT, ECN, PMTU and recovery fields. A CPU-0 50,000-round `--stats` run sustained
92,374.6 round trips/s at p50/p99/p99.9 10.659/15.583/18.106 us, made 149
allocations, allocated 685,276 cumulative bytes, peaked at 560,036 live bytes,
and ended at zero. Metadata is therefore bounded by unresolved work rather than
connection lifetime without regressing the ACK-cursor latency result.

### Raw QUIC stream-open rate

Captured on 2026-08-20 after one real handshake. Like quicz's stream-churn
case, the timed region reserves 100,000 locally initiated bidirectional stream
IDs without transmitting STREAM frames:

```sh
taskset -c 0 zig build bench-quic-handshake-stream \
  -Doptimize=ReleaseFast -- --mode=stream-churn
taskset -c 0 /tmp/quicz-stream-churn-only
```

```text
netz:   680.2M, 778.0M, 777.7M streams/s
quicz:   48.1M,  52.0M,  51.7M streams/s
```

This controlled artifact puts netz at 13.1-16.2x the quicz stream-open rate.
The new transport API enforces negotiated bidi/uni stream limits, returns the
RFC stream-ID sequences for both endpoint roles, and creates stream flow state
lazily on first use. A 100,000-stream `--stats` run made no allocations in the
timed loop: the whole real-handshake process made 92 allocations, ended with
zero live bytes, and returned the expected final ID 399,996 and checksum
19,999,800,000. This is a stream-reservation microbenchmark, not evidence for
wire-level open/close throughput.

The on-wire `--mode=lifecycle-churn` path now optionally injects loss or
reordering in both directions after handshake completion. Its lifecycle pump
waits on both UDP endpoints in one readiness operation, bounded by the earliest
transport timer on either connection and one absolute awake-clock benchmark
deadline. This avoids both a fixed 1 ms polling quantum in the clean path and
starving reverse ACKs until PTO. Every run verifies the exact FIN/reset split,
last stream ID, checksum, cumulative MAX_STREAMS renewal, and deterministic
per-direction fault counts. A 128-stream/16-credit smoke completed clean, 5%
loss, and every-fifth-datagram reordering runs in 6.01, 8.17, and 4.11 ms of
timed lifecycle work. The loss run considered/dropped 276/14 client datagrams
and 284/16 server datagrams; the reorder run held exactly 45 of 228 and 45 of
227 respectively. These short unpinned runs are correctness and scheduler
regression evidence, not throughput comparisons. Reproduce them with:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=lifecycle-churn --iterations=128 --streams=16
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=lifecycle-churn --iterations=128 --streams=16 --loss-pct=5
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=lifecycle-churn --iterations=128 --streams=16 --reorder-every=5
```

After adding path-epoch recovery isolation, CPU-pinned 256-stream reruns
completed with the same exact 128 FIN / 128 reset split, final stream ID 1020,
and checksum 26,496. The 5% bidirectional-loss run considered/dropped 556/27
client and 562/28 server datagrams, reported 11/18 transport losses, and
completed at 18,924-23,812 streams/s. The every-fifth-datagram reorder run held
91/455 client and 90/454 server datagrams and completed at 26,016-35,446
streams/s.
These remain deterministic fault/recovery checks rather than cross-stack speed
claims. A 4,096-stream loss run exceeded the benchmark's fixed 30-second
deadline and is not used as performance evidence.

### Raw QUIC four-connection aggregate throughput

Captured on 2026-08-20 with the same shape as quicz's thread-per-connection
scaling case: four worker threads, one independent `std.Io` per worker, one
real handshake and one 64 MiB upload per connection. The aggregate timer
includes worker creation, handshakes, transfers and teardown:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=aggregate --connections=4 --transfer-bytes=67108864
timeout 180 /tmp/quicz-aggregate-only
```

```text
netz:  730.35, 790.22, 900.57 MiB/s
quicz: 503.23, 513.22, 533.10 MB/s
```

The conservative cross-unit ratio (netz MiB/s divided by quicz MB/s without
giving netz the 1.048576 unit conversion advantage) is 1.37-1.79x. Every netz
worker must report exactly 64 MiB received before the result is accepted. A
separate four-connection × 16 MiB `--stats` run verified 64 MiB aggregate,
made 160,993 allocation calls, allocated 700,944,509 cumulative bytes and had
8,473,284 summed worker peak bytes, with zero live bytes at worker teardown.
This is connection-level parallel scaling evidence, not a single-connection or
HTTP/3 claim.

### Raw QUIC deterministic loss recovery

Captured on 2026-08-20 using the quicz loss shape: one real handshake, a 4 MiB
single-stream upload, seeded xorshift client-to-server packet loss, and optional
50 us one-way busy-wait delay for a configured 100 us RTT. The interceptor is
enabled only after handshake completion, so TLS setup is not faulted:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=1
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=5
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=1 --rtt-us=100
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=5 --rtt-us=100
```

Three-run ranges against a freshly compiled quicz loss-only binary:

| Scenario | netz MiB/s | quicz MB/s | Conservative ratio |
| --- | ---: | ---: | ---: |
| 1% loopback | 255.19-289.29 | 220.84-236.72 | 1.08-1.31x |
| 5% loopback | 286.99-314.31 | 216.79-223.64 | 1.28-1.45x |
| 1% / 100 us RTT | 121.13-131.24 | 98.73-105.03 | 1.15-1.33x |
| 5% / 100 us RTT | 116.43-127.62 | 95.88-98.42 | 1.18-1.33x |

The ratio again does not normalize MB/s versus MiB/s in netz's favor. Each
run verifies all 4,194,304 receive bytes and reports considered/dropped
datagrams plus transport-declared loss. The seeded 5% cases consistently
dropped 25 of 504 client datagrams. A 5%/100 us `--stats` run made 31,254
allocations, allocated 231,757,047 cumulative bytes, peaked at 832,363 live
bytes and ended with zero live bytes. The endpoint interceptor consumes dropped
datagrams from QUIC's send perspective, including batch submissions, so normal
packet-number/recovery semantics remain active.

The same real-handshake gate now accepts
`--mode=reorder --reorder-every=5`. The client endpoint holds every fifth
outgoing datagram,
sends its successor first, then releases the held packet; handshake traffic is
excluded by enabling the hook only for the 4 MiB STREAM upload. Three CPU 0-7
runs verified all 4,194,304 bytes, considered 504-610 datagrams, held 100-122,
and reported 33-160 packets declared lost while completing at 310.38-379.01
MiB/s. A no-drop control through the same fault-mode path measured 313.00-
466.71 MiB/s. The wide first-run spread is reported rather than converted into
a speed claim; the durable result is successful byte-exact recovery under real
client STREAM packet reordering.

`--mode=corrupt --corrupt-every=20` covers authenticated corruption rather than
ordinary loss. The endpoint copies every selected client datagram, flips one
ciphertext bit and leaves caller storage/recovery metadata untouched; the peer
discards `AuthenticationFailed` packets and normal PTO/ACK recovery restores
their STREAM ranges. Three CPU 0-7 runs corrupted exactly 25 of 504 datagrams,
reported exactly 25 transport losses, verified all 4,194,304 bytes, and
completed at 276.51-464.70 MiB/s. As with reordering, the wide scheduling range
precludes a speed verdict; this is deterministic AEAD-rejection/recovery
evidence.

## WebSocket frame encoding comparison

Captured on 2026-08-17 in `ReleaseFast` with 200,000 masked 4 KiB binary
frames. The payload length and first mask byte vary per iteration so the
compiler cannot fold frame generation out of the loop.

```sh
zig build bench-websocket-frame -Doptimize=ReleaseFast
```

Representative netz samples:

```text
allocating masked frame:       85-97 ns/op
caller-buffer masked frame:    71-82 ns/op
header-only stream preparation: 0.54-0.56 ns/op
```

The same command now includes retained RFC 7692 no-context-takeover complete
and 16-slice compressor cases. Three CPU-14-pinned 2026-08-20 samples encoded
a repeated 4 KiB telemetry-like message in 5.55-5.88 us and reduced its wire
payload from 4,096 to 69 bytes. The discontiguous path took 5.77-6.10 us
without a plaintext join and produced 69 bytes using a bounded 16 KiB rolling
dictionary and one fixed block shared across all slices. Versus the prior
standard-library 51.10 us fragmented baseline, this is an 8.4-8.9x latency
improvement. It also recovers the first slice-local vort path's 463-byte wire
payload completely relative to the complete-message vort path. This is an
internal baseline rather than a reference ratio:
the audited websocket.zig 0.16 outbound compression paths currently force
`compressed = false`.

The caller-buffer path copies and masks in one SIMD pass and preserves the
caller's `[]const u8`. The header-only path is what unmasked server sends use:
the runtime emits the stack-resident header and borrowed payload with one
vectored TCP write, so frame preparation neither allocates nor copies the
payload. WSS similarly writes both slices before one TLS/network flush;
client sends mask fixed stack chunks without modifying caller memory. The
HTTP/2 extended-CONNECT adapter retains a per-connection encoding buffer
because its DATA writer currently accepts one contiguous byte stream.

A direct same-input reference was compiled against
`~/Work/websocket.zig/src/proto.zig` using its stack `writeFrameHeader`, a
payload copy (needed to preserve the same immutable-input contract), and
`proto.mask`. Three same-host samples were:

```sh
zig build-exe -OReleaseFast -lc --dep proto \
  -Mroot=benchmarks/reference/websocket_zig_frame.zig \
  -Mproto=/home/passchaos/Work/websocket.zig/src/proto.zig \
  -femit-bin=/tmp/bench-websocket-zig
/tmp/bench-websocket-zig
```

```text
websocket.zig header + payload copy/mask: 101, 103, 127 ns/op
```

Thus the current netz caller-buffer path is faster in the captured runs, while
the normal unmasked server runtime avoids the payload copy entirely. This is a
codec/send-hot-path comparison; end-to-end evidence follows.

### WebSocket persistent 4 KiB echo

One real HTTP/1 upgraded connection performs 20 warmup and 200 measured binary
echoes. Both implementations use mutable client input, masked requests,
unmasked responses, caller/reader-owned receive storage, and copy each echo
back to the next send buffer. Handshake time is excluded; this comparison uses
the public backend-neutral `std.Io` TCP runtime.

Twenty alternating CPU-0 samples with TCP_NODELAY enabled on both clients:

```text
netz:
  9.146-10.537 us, median 9.501 us, trimmed mean 9.539 us
websocket.zig:
  13.231-14.406 us, median 13.630 us, trimmed mean 13.702 us
netz advantage:
  1.435x by median, 1.436x by trimmed mean
```

Without TCP_NODELAY, websocket.zig's two-write masked client path measured
about 41.09-41.38 ms/roundtrip, versus 10.26-10.71 us for netz. That exceptional
~3,915x gap is a Linux Nagle/delayed-ACK cliff and is not generalized beyond
this socket/write shape. `strace -f -c` showed about 442 netz sendmsg calls,
while the reference used 443 sendmsg plus 228 writev calls for the same 220
exchanges.

Commands:

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

Four-connection mode uses one start barrier after every client finishes warmup
and reports aggregate latency across 800 measured round trips. Twenty
alternating samples on CPUs 0-7:

```text
netz:
  3.788-4.802 us aggregate/roundtrip
  median 4.150 us, trimmed mean 4.173 us
  median 240,993 roundtrips/s, 1,885.51 wire MiB/s

websocket.zig:
  4.912-5.653 us aggregate/roundtrip
  median 5.212 us, trimmed mean 5.221 us
  median 191,883 roundtrips/s, 1,501.28 wire MiB/s

netz advantage:
  1.256x by median, 1.251x by trimmed mean
```

```sh
taskset -c 0-7 zig build bench-websocket-echo \
  -Doptimize=ReleaseFast -- --connections=4
taskset -c 0-7 /tmp/bench-websocket-zig-echo \
  --tcp-nodelay --connections=4
```

One traced run showed approximately 1,768 netz `sendmsg` calls, versus 1,772
reference `sendmsg` plus 892 `writev` calls. These counts include warmup and
handshake/shutdown traffic; tracing overhead is excluded from timing evidence.

With `--compression`, the real persistent WebSocket echo benchmark negotiates
permessage-deflate. Five CPU-0 samples after moving complete-message compression
to vort's native raw fixed-DEFLATE sync-flush path were 29.44-31.14
us/roundtrip and 250.91-265.34 logical payload MiB/s. This is 4.6-5.0x lower
latency than the previous Zig-flate 144.6-147.5 us range; the new path avoids
clearing roughly 224 KiB of compressor state per no-context-takeover message.
Three four-connection CPU 0-7 runs measured 12.09-12.18 us aggregate/roundtrip
and 641.52-645.95 logical MiB/s, versus the previous 45.96 us/169.98 MiB/s. A
four-connection `--stats` sample made 7,151 allocations, allocated 48,068,236
cumulative bytes, peaked at 1,240,114 live bytes, and verified checksum 111,600.

`--compression --fragmented` sends the same 4 KiB client message as sixteen
compressed WebSocket frames. Three CPU-14 runs measured 35.80-36.60
us/roundtrip and 213.48-218.24 logical MiB/s, versus 129.24 us before batching
the small masked/unmasked frame sequence and 30.65-30.91 us for the one-frame
control. Thus wire-visible fragmentation retains a 16.8-19.4% latency cost but
no longer multiplies transport submissions by the frame count. Each run
verified checksum 51,000.

The RFC 8441 counterpart is:

```sh
taskset -c 14 zig build bench-websocket-h2-echo \
  -Doptimize=ReleaseFast -- --fragmented
```

Three complete-message controls measured 37.91-38.44 us/roundtrip and
203.23-206.05 logical MiB/s. Three sixteen-slice runs measured 43.66-44.00 us
and 177.56-178.94 MiB/s, versus 98.55-137.68 us before H2 batching. Encoding
the RFC 6455 frames into retained connection scratch and calling the existing
flow-controlled tunnel writer once yields a 2.2-3.2x fragmented-path gain; the
remaining 15.1-16.0% cost against the one-frame control represents actual
frame header/mask handling. All samples verified checksum 51,000.

## MQTT 5 windowed QoS 1 broker fanout

Captured on 2026-08-20 with one external client binary driving both brokers:

```sh
zig build bench-mqtt-broker -Doptimize=ReleaseFast -- \
  --address=127.0.0.1:PORT --publishers=4 --subscribers=4 \
  --warmup-messages=1000 --messages=20000 --payload-bytes=256 \
  --publisher-window=64
```

Each measured PUBLISH fans out to all four QoS 1 subscribers. Every run
completed 20,000 publishes and 80,000 deliveries with checksum 20,580,000.
Three consecutive runs gave:

```text
netz publishes/s:     56,486 / 54,847 / 55,505
netz p50 ms:           1.742 /  1.818 /  1.813
netz p99 ms:           3.696 /  4.077 /  3.921
netz p99.9 ms:         3.925 /  4.795 /  4.923
netz broker peak KiB:  6,436 /  6,428 /  6,440

rumqttd publishes/s:   7,218 /  6,902 /  6,642
rumqttd p50 ms:        1.335 /  1.277 /  1.340
rumqttd p99 ms:       41.154 / 41.047 / 41.100
rumqttd p99.9 ms:     42.006 / 41.800 / 41.373
rumqttd broker KiB:   17,716 / 17,576 / 17,632
```

The entries above remain in run order; the cross-broker summary in
`docs/rumqtt_parity.md` computes medians per metric. Netz made 504,105 client
allocation calls and allocated 120,171,264 cumulative bytes in every run.
Rumqttd required 672,117-672,129 calls and 133,107,836-133,108,592 bytes.
Client peak-live remained approximately 504 KiB for both. Broker RSS was
sampled from `/proc/PID/status` every 2 ms while the load driver was alive.

The netz result includes TCP_NODELAY by default for ordinary MQTT TCP, a
Session queue-head cursor, and a shared-Publication fast path for online
Session Expiry zero clients. Before the cursor, a 40,000-publish profile
assigned 50-53% of broker cycles to `Broker.flushSlotLocked`, with the
consumed-prefix null scan dominating its annotation. The cursor reduced that
symbol to 4.9% in the matching atom-core report. Avoiding durable deep copies
for transient online Sessions then raised the three-run range from
37,098-40,021 to 53,843-54,197 publishes/s. The broker task closure now carries
only the owned CONNECT parse tree after moving its much larger runtime
Connection into the stable slot; this removed a redundant per-worker stack
copy and reduced median broker peak RSS from 9,344 to 8,496 KiB while retaining
54,655-55,781 publishes/s. Finally, the production example uses libc's shared
allocator rather than one SMP cache per worker: the same three-run shape held
54,847-56,486 publishes/s while median broker peak RSS fell again to 6,436 KiB.
Library users still select their allocator through `Broker.listen`. This
comparison is specific to the bounded QoS 1 shape and is not a broad broker or
persistence verdict.

The same driver now accepts `--session-expiry-seconds=N` to force the durable
online Session path rather than the expiry-zero shared-Publication fast path.
With expiry 300 seconds and the otherwise identical window-64 shape, three
netz runs measured 38,531 / 39,228 / 39,146 publishes/s, p99
5.713 / 5.620 / 5.711 ms, and 6,456 KiB broker peak RSS in every run. All
80,000 deliveries completed with checksum 20,580,000. This explicitly bounds
the cost of retaining reconnect-safe QoS 1 payload/inflight state instead of
silently generalizing the transient-session result.
Topic and payload ownership is now coalesced into one allocation for each
durable queued publication. A three-run rerun remained at 38,738-40,299
publishes/s with p99 5.467-5.664 ms and 6,472-6,492 KiB broker peak RSS,
confirming the allocation-count simplification without overstating it as a
throughput improvement.

## MQTT shared-subscription router

Captured on 2026-08-19 with:

```sh
zig build bench-mqtt-router -Doptimize=ReleaseFast
```

Three-run ranges:

```text
4098-filter trie match:            191-205 ns/op
4098-filter linear scan:           102-103 us/op
trie speedup:                      499-540x
64-member shared RoundRobin:       160-166 ns/op
64-member shared Sticky:           173-178 ns/op
64-member shared Random:           166-169 ns/op
64-member shared Rendezvous hash:  1.23-1.24 us/op
```

RoundRobin, Random and Sticky match rumqttd's configurable shared-subscription
strategies. Netz additionally supports stable Rendezvous hashing for
topic-affine assignment with low remapping when group membership changes.
Strategy state is per `{ShareName, TopicFilter}` and only advances after output
capacity preflight succeeds. Ordinary/shared routes are counted together and
emitted together, so a publish traverses the topic trie twice rather than four
times while retaining ordinary-before-shared output ordering.

`~/Work/rumqtt/benchmarks/router/routernxn.rs` is commented out in the audited
checkout, so these numbers are recorded as a netz baseline rather than a direct
whole-broker throughput ratio. See `docs/rumqtt_parity.md` for the feature and
remaining-work audit.

## WebTransport runtime smoke and DATAGRAM baseline

Validated on 2026-08-17:

```sh
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
zig build bench-webtransport-datagram -Doptimize=ReleaseFast
```

```text
WebTransport handshake streams ok: bidi=4, uni=14, server_uni=15

WebTransport datagram runtime benchmark
  iterations: 10000
  datagrams: 20000
  payload bytes: 27
  ns/roundtrip: 13242
  ns/datagram: 6621
  datagrams/s: 151031
```

The stream smoke uses real QUIC/TLS and HTTP/3 CONNECT rather than the
cleartext development transport. It validates modern bidirectional association
(`0x41 + Session ID`), both unidirectional directions, reverse-direction bidi
data, >1-packet stream fragmentation, per-session stream credit and shared
HTTP/3/WebTransport stream-ID allocation. The DATAGRAM number remains a netz
baseline; no equivalent same-command quicz/wtransport result was captured.
The cross-stream writer now keeps batch membership generations in the existing
stream registry index. Duplicate validation is linear and allocation-free,
selected checks are O(1), and the all-prefix-sent steady path scans candidates
once while maintaining a fixed stable-priority top-64 window. The prefix path
continues to re-evaluate credit after each association write and now marks before
that write, preventing a newly blocked high-priority stream from starving its
siblings. A CPU-0 64-stream/16-KiB smoke verified all 1,048,576 bytes across 320
partial writes with checksum 133,693,440; repeated fixed-binary throughput varied
19-40 MiB/s, so only correctness/no-deadlock is claimed.
Development and lightweight protected endpoint sends now share one stack-first
WebTransport DATAGRAM codec under `runtime/datagram/`: payloads whose Quarter
Stream ID plus body fit 4 KiB need no WebTransport-layer allocation, while
larger payloads allocate their exact wire size once. Previously only the
development endpoint had the stack path; protected sends always grew an
ArrayList before QUIC protection. Tests cover wire parity, invalid-session
preflight before allocation, allocation-free common encoding, and exact
fallback OOM. Owned QUIC/protected/handshake DATAGRAM lifetimes are colocated
in the same nested module without moving mutable QUIC connection state.
Three fixed-binary CPU-0 cleartext DATAGRAM runs after the extraction measured
7.940-8.103 us/roundtrip (246,820-251,883 datagrams/s) with the exact existing
checksum. This is an internal regression range; it does not isolate the new
protected-only allocation removal and is not an external throughput ratio.

The same executable accepts `--burst` to exercise the authenticated HTTP/3
WebTransport runtime and its deadline-bounded congestion backpressure:

```sh
zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- \
  --burst --iterations=1000 --send-timeout-ms=1000
```

A final post-change smoke attempted, sent, and received all 1,000 DATAGRAMs
with zero timeouts. The 35-byte workload measured 5.808 us p50 / 15.416 us
p99 send latency, 5.11 logical MiB/s, and the exact checksum 3,549,000. This is an
internal backpressure regression baseline, not a cross-stack throughput claim.
The original cleartext ping-pong mode and output remain the default.
After the protected stack-send integration, the same 1,000-DATAGRAM bounded
burst again attempted/sent/received all 1,000 with zero timeout and checksum
3,549,000. The loaded-host sample was 10.483 us p50 / 17.998 us p99 and
3.32 logical MiB/s, so it is recorded as lifecycle evidence rather than a new
performance baseline.

The multi-stream benchmark now scales connection credit with stream count and
exposes stream-window/datagram/pacing controls. Four 4-MiB streams with 1-MiB
stream windows and 8-KiB datagrams completed at 188-195 MiB/s aggregate across
three ReleaseFast runs. This replaces the earlier 26 MiB/s result whose fixed
128-KiB connection window unintentionally serialized four streams.

The benchmark also accepts `--loss-pct=N`. Handshake and CONNECT setup remain
reliable; a fixed-seed endpoint interceptor starts immediately before the
associated-stream phase, so STREAM/RESET_STREAM/ACK loss decisions are exactly
repeatable without conflating certificate setup. Five consecutive runs of:

```sh
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- \
  --streams=16 --transfer-bytes=16384 --stream-window=65536 \
  --reset-every=2 --reset-after-bytes=256 --loss-pct=5
```

The benchmark now keeps a cancelable client receive future alive after its last
FIN/reset so ACK, loss and PTO state continue progressing until the server has
validated every terminal event. This removes the prior large-stream teardown
deadlock. Five 64-stream runs considered 320 server datagrams and dropped the
same 21 every time. All 32 reset streams reported application code 42 after
their 256-byte prefix, all 32 non-reset streams reached FIN, and every run
verified 532,480 bytes and checksum 67,891,200. Elapsed time ranged
10.656-14.923 ms (34-47 MiB/s); read-event fragmentation varied independently
from the exact terminal/byte result. This is deterministic
cancellation/recovery evidence, not an equal-wire wtransport throughput
comparison.

`--reorder-every=N` now exercises the complementary non-loss case. The endpoint
owns every selected datagram, sends the next packet first, then releases the
held packet; QUIC packet numbers and recovery metadata are therefore committed
normally rather than rewritten by the harness. Three CPU 0-7 runs of:

```sh
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- \
  --streams=8 --transfer-bytes=262144 --stream-window=65536 \
  --one-rtt-datagram-size=4096 --reorder-every=5
```

held exactly 112 of 561 considered server datagrams per run, verified all
2,097,152 bytes and checksum 267,386,880, and completed in 10.92-11.40 ms
(175-183 MiB/s). The benchmark reports held/considered counts separately from
loss, and rejects combining both injectors so the network shape remains
unambiguous.

The benchmark also accepts `--fault-direction=client`, placing the same hook on
the sender of WebTransport STREAM/FIN packets rather than on server ACKs. Three
runs of the command above plus `--fault-direction=client` considered 605-615
client datagrams, held 121-123, verified the same 2,097,152 bytes/checksum
267,386,880, and completed in 12.37-13.07 ms (153-161 MiB/s). A held packet at
the end of a batch is now explicitly flushed, preventing the emulator from
turning an intended reorder into accidental loss.

## Reference context from `~/Work`

The closest available reference document is
`~/Work/quicz/docs/en/benchmark.md`.  Its headline numbers are not directly
comparable because they were collected on a different platform and with
different benchmark definitions, but they define the comparison target shape:

- quicz real-handshake single-stream throughput: about **310-440 MB/s** on
  macOS loopback, real TLS 1.3 handshake, 8.9 KiB datagrams, no GSO.
- quicz 4-stream aggregate: about **304 MB/s** on the same real-handshake
  benchmark family.
- quicz echo latency: about **21.7 us p50** / **77.3 us p99** for a 1 KiB full
  QUIC round trip after a real handshake.
- quicz documentation also highlights platform effects: Linux GSO/GRO can
  dominate throughput comparisons and must be recorded separately.

For netz, raw QUIC STREAM and DATAGRAM throughput have same-host reference
runs, but only DATAGRAM currently retains a direct performance verdict. STREAM
needs equivalent endpoint CPU placement after the single-CPU scheduling audit.
HTTP/3 remains separate because it includes H3 framing, QPACK, and session
bookkeeping and has no equal-wire quicz reference.

WebSocket stream transports now share `runtime/message/buffer.zig` and
`runtime/message/state.zig` for bounded 256-byte-slab receive growth,
compressed-fragment partitioning, Close-state admission, and owned message
finalization. The common growth helper now computes its rounded capacity with
checked addition, so an unrepresentable request returns OOM instead of wrapping
in optimized builds. Allocation-failure, overflow, compression-provenance,
invalid-deflate, invalid-UTF-8, and balanced-fragment tests live beside those
helpers rather than in the runtime root. Public frame/message limit semantics
are unchanged.
A CPU-0 fixed-binary 4-KiB echo check after the extraction produced
9.574-16.533 us/roundtrip while unrelated host load was active. The spread is
too wide for a performance verdict, so it is retained only as a functional
benchmark pass and does not replace the isolated ranges above.

## Gaps before a completion audit can pass

- Extend the same-host raw QUIC matrix to echo latency, handshake rate,
  loss/reordering, stream churn, and multi-connection aggregate throughput.
- Record allocation/peak-memory metrics for the benchmark processes.
- Add loss/reordering benchmark cases or interop-runner style scenarios for
  handshake loss, transfer loss, and corruption.
- Keep public HTTP/3 smoke (`https://robotics.bytedance.com/ --verify --head`)
  as a reachability gate, but do not treat it as a throughput benchmark.
