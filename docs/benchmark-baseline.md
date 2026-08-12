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

```sh
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=4
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
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
  iterations: 1
  body bytes/iteration: 16777216
  total body bytes: 16777216
  status total: 800
  ns/iteration: 136766171
  bytes/s: 122670802
  MiB/s: 116
```

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
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=upload --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=upload --streams=4
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=4
```

```text
netz upload streams=1:   118 MiB/s, 123,836,123 bytes/s, ns/iter 541,916,703
netz download streams=1: 120 MiB/s, 126,242,863 bytes/s, ns/iter 531,585,407
netz upload streams=4:   34 MiB/s, 36,160,595 bytes/s, ns/iter 1,855,856,161
netz download streams=4: 33 MiB/s, 35,205,406 bytes/s, ns/iter 1,906,209,052
```

This same-host comparison shows netz is **improved but not yet
performance-competitive** on large real-handshake transfers. Raising the
single-stream 1-RTT datagram budget to 8192 bytes and the paced DATA chunk to
7200 bytes closes much of the previous 3 MiB/s cliff, but quicz still leads on
64 MiB 4-stream aggregate throughput. Releasing all active streaming response
reader capacity before each multi-response packet receive stabilizes the 64 MiB
four-stream download case, but quicz still leads substantially. The next
optimization target is packet batching across concurrent streams and reducing
per-DATA-frame send overhead. A completion audit cannot pass
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
  alloc count: 102636
  remap count: 4697
  total allocated bytes: 326402938
  peak live bytes: 17064487

64 MiB upload streams=1:
  alloc count: 414772
  remap count: 18527
  total allocated bytes: 1316295798
  peak live bytes: 69767885
```

The 64 MiB upload currently allocates about 1.3 GiB cumulatively, which confirms
that the next throughput work should reduce per-DATA-frame temporary allocation,
frame-slice construction, and remap churn rather than only tuning QUIC windows.

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

For netz, the current results above are microbenchmarks plus paced
real-handshake 16 MiB upload/download benchmarks with single-stream and
4-stream shapes.  These now match the transfer size and aggregate-stream shape
used by the quicz benchmark family, but they still lack the same-host reference
run and memory/allocation evidence required before claiming performance parity
or superiority.

## Gaps before a completion audit can pass

- Close the same-host large-transfer throughput gap against `~/Work/quicz`.
- Record allocation/peak-memory metrics for the benchmark processes.
- Add loss/reordering benchmark cases or interop-runner style scenarios for
  handshake loss, transfer loss, and corruption.
- Keep public HTTP/3 smoke (`https://robotics.bytedance.com/ --verify --head`)
  as a reachability gate, but do not treat it as a throughput benchmark.
