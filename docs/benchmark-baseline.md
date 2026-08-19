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
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
zig build bench-http3-qpack -Doptimize=ReleaseFast
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=4
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
```

## Current netz results

### HTTP/1 persistent 16-request pipeline

Captured on 2026-08-17. This benchmark mirrors
`~/Work/hyper/benches/pipeline.rs::hello_world_16`: each iteration sends
sixteen bodyless GET requests on one persistent loopback TCP connection and
receives sixteen `"Hello, World!"` responses. Hyper automatically adds a
29-byte Date value; netz supplies a same-length Date field so both responses
are 89 wire bytes. Netz runs 200 untimed warmup batches before 2,000 measured
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
were pinned to CPU 0. Netz supplies Hyper's same-length Date value, matches its
1-MiB server receive windows, and uses untimed warmup so steady-state wire,
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
of one write per stream and removes canceled receive-window entries. A `--stats`
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

### QUIC 1-RTT receive

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
ordinary non-GRO packet pump; GRO retains its lazy owning suffix because the
application deliberately routes only one coalesced packet per call.

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

QUIC recovery now retains a bounded four-block stack per power-of-two payload
class, with a global 1 MiB idle-byte cap. ACK/forget paths recycle without
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

Current stats samples:

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
  p50:   20.65-20.71 us
  p99:   30.53-31.97 us
  p99.9: 38.74-47.98 us
  rate:  47,780-47,995 round trips/s

quicz:
  p50:   10.4-10.5 us
  p99:   16.1-16.4 us
  p99.9: 205.4-212.9 us
```

The netz implementation has a slower median and p99 but a 4.3-5.5x lower
p99.9 tail in this controlled run. This is not a whole-stack superiority
claim. The new `sendWithPendingAck` transport API combines an application
response with its cumulative ACK, and receiving an ACK-of-ACK now prunes old
received packet-number ranges. A 5,000-round `--stats` run made 159 total
allocations, ended with zero live bytes, and verified all 5,120,000 echoed
payload bytes.

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

The same command now includes a retained RFC 7692 no-context-takeover
compressor case. Three CPU-0-pinned 2026-08-19 runs encoded a repeated 4 KiB
telemetry-like message in 50.94-51.08 us and reduced its wire payload from
4,096 to 54 bytes. This is an internal baseline rather than a reference ratio:
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
the ordinary TCP runtime rather than the io_uring adapter.

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

zig build-exe -OReleaseFast -lc --dep websocket \
  -Mroot=benchmarks/reference/websocket_zig_echo.zig \
  --dep build \
  -Mwebsocket=/home/passchaos/Work/websocket.zig/src/websocket.zig \
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
permessage-deflate. Three CPU-0 samples were 144.6-147.5 us/roundtrip and
52.95-54.02 logical payload MiB/s. Four concurrent connections reached 45.96
us aggregate/roundtrip and 169.98 logical MiB/s on CPUs 0-7.

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
netz publishes/s:     37,098 / 39,381 / 40,021
netz p50 ms:           2.860 /  2.712 /  2.676
netz p99 ms:           6.865 /  6.631 /  6.551
netz p99.9 ms:         9.538 /  8.020 /  9.022
netz broker peak KiB: 11,944 / 11,292 / 10,836

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

The netz result includes TCP_NODELAY by default for ordinary MQTT TCP and a
Session queue-head cursor. Before the cursor, a 40,000-publish profile assigned
50-53% of broker cycles to `Broker.flushSlotLocked`, with the consumed-prefix
null scan dominating its annotation. Afterward that symbol fell to 4.9% in the
matching atom-core report. This comparison is specific to the bounded QoS 1
shape and is not a broad broker or persistence verdict.

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

The multi-stream benchmark now scales connection credit with stream count and
exposes stream-window/datagram/pacing controls. Four 4-MiB streams with 1-MiB
stream windows and 8-KiB datagrams completed at 188-195 MiB/s aggregate across
three ReleaseFast runs. This replaces the earlier 26 MiB/s result whose fixed
128-KiB connection window unintentionally serialized four streams.

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

## Gaps before a completion audit can pass

- Extend the same-host raw QUIC matrix to echo latency, handshake rate,
  loss/reordering, stream churn, and multi-connection aggregate throughput.
- Record allocation/peak-memory metrics for the benchmark processes.
- Add loss/reordering benchmark cases or interop-runner style scenarios for
  handshake loss, transfer loss, and corruption.
- Keep public HTTP/3 smoke (`https://robotics.bytedance.com/ --verify --head`)
  as a reachability gate, but do not treat it as a throughput benchmark.
