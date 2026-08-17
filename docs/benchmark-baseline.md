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
```

`strace` confirmed equal steady-state wire sizes: empty exchanges use 19-byte
requests and 11-byte responses; POST exchanges use 43-byte requests and
11-byte responses. The large POST gap is specifically Hyper's two-write
HEADERS/DATA path hitting Linux's Nagle/delayed-ACK interaction on this host,
not a general whole-library ratio. Netz preserves both HTTP/2 frames but submits
their four slices in one `sendmsg`; larger, fragmented or flow-blocked messages
fall back to ordinary frame writes. The 100-KiB case uses TCP_NODELAY, matched
receive windows, vectored DATA bursts, a connection-level multi-frame receive
buffer and callback-based streaming consumption. Bodyless parallel batches use
transactional HPACK staging, one request/response submission in each direction,
and stream-ID-based response reordering. See `docs/hyper_parity.md` for the
implementation audit and remaining H2 comparison work.

### HTTP/3 QPACK dynamic encode

```text
HTTP/3 QPACK dynamic encode benchmark
  iterations: 100000, table entries: 512, fields/block: 32
  encoded bytes/block: 68, references/block: 32
  ns/block: 899, ns/field: 28
  checksum: 10000000
```

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
codec/send-hot-path comparison, not an end-to-end connection throughput claim;
a full concurrent echo/load benchmark remains separate work.

## MQTT shared-subscription router

Captured on 2026-08-17 with:

```sh
zig build bench-mqtt-router -Doptimize=ReleaseFast
```

Three-run ranges:

```text
4098-filter trie match:            328-338 ns/op
4098-filter linear scan:           109-111 us/op
trie speedup:                      327-333x
64-member shared RoundRobin:       267-271 ns/op
64-member shared Sticky:           290-294 ns/op
64-member shared Random:           282-286 ns/op
64-member shared Rendezvous hash:  1.25-1.34 us/op
```

RoundRobin, Random and Sticky match rumqttd's configurable shared-subscription
strategies. Netz additionally supports stable Rendezvous hashing for
topic-affine assignment with low remapping when group membership changes.
Strategy state is per `{ShareName, TopicFilter}` and only advances after output
capacity preflight succeeds.

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
