# netz benchmark baseline

This file records reproducible local baselines used while working toward the
long-running goal of comparing and improving netz against the HTTP/QUIC
implementations under `~/Work`.

The numbers below are **not** a completion claim.  They are a starting point for
repeatable comparisons: same host, same compiler, explicit commands, and raw
outputs that can be re-run after future optimizations.
Unless a section explicitly identifies a zio-era rerun, measurements captured
before 2026-09-15 used `std.Io.Threaded` and remain historical evidence only.
Current benchmark output names the backend so results from different execution
models cannot be silently combined.
Since 2026-11-08, `bench-http1-parse`, `bench-quic-padding-parse`,
`bench-http3-capsule`, `bench-http2-hpack`, `bench-http3-qpack`, and
`bench-http-content-coding` use the
shared `harnessz` sampler. `--iterations` is the
operation count per sample, `--samples` (default 10) is the number of timed
samples, and `--warmup` (default 1) is the number of untimed samples. Reported
ns/op is the median sample divided by `--iterations`, and each scenario prints
its min/p50/p90/p99/mean/stddev. Numeric results recorded before this change
used one timed block; pass `--samples=1 --warmup=0` for a directly comparable
single-block measurement. The same six benchmarks accept
`--baseline=<relative-path>` with `--update-baseline` to record raw samples and
an environment fingerprint, then `--baseline=<relative-path>` alone to compare
later runs; `--max-regression-ratio` (default 1.05) sets the median gate, and a
ratio regression must also be significant under the robust rank-sum test
before it fails. A fingerprint mismatch reports `EnvironmentMismatch` instead
of comparing different build modes or machines. The `bench-record` and
`bench-gate` build steps apply the same flow to all six benchmarks and write
`benchmarks/baselines/*.json`; record and gate on the same host and build mode.
Run the gate on a quiet host and re-run a flagged scenario before treating it
as a regression: a sustained host-state shift can move one scenario without a
code change. `--warn-only` reports the same regression lines without failing
the build, which keeps local runs on a loaded host informative.
The raw QUIC DATAGRAM throughput, 1-RTT send/receive, and UDP GSO/GRO
benchmarks now obtain endpoint I/O and clocks from zio; the DATAGRAM receiver
uses `std.Io.async` and cooperative `std.Io` sleeps. Numeric results in those
sections that predate 2026-09-15 are historical Threaded evidence unless
explicitly labeled as zio-era runs.
The WebTransport DATAGRAM round-trip/burst, incremental stream, and steady
stream-batch benchmarks also use zio-backed `std.Io`; their local server work
is scheduled with `std.Io.async`. Their older numeric results are historical
Threaded evidence unless a section explicitly records a zio-era rerun.
The real-handshake QUIC STREAM benchmark now uses one zio backend across every
mode, including network-fault runs. Its aggregate mode schedules connection
workers with `std.Io.Group`; previously recorded values remain historical
Threaded evidence until explicitly rerun under zio.
The MQTT retained/session/Will state benchmarks and QUIC-LB routing benchmark
now obtain their monotonic clock from zio-backed `std.Io`; their older numeric
results remain historical Threaded evidence.
As of 2026-09-15, the ACK-range, connection-router, PADDING parser,
short-packet protection, receive sliding-window, session-ticket keyring,
endpoint CID synchronization, pending-ready-index, timer scheduler, and
receive-stream-ID microbenchmarks all obtain their endpoint, where needed, and
monotonic clock from
`netz.runtime.Backend` and print `zio-std-io`. Their previously recorded
optimization comparisons remain useful as same-harness historical evidence,
but are not current zio performance measurements unless a later paragraph
explicitly identifies a zio rerun.

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
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast -- \
  --write-strategy=vectored
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast -- \
  --large-body --write-strategy=flatten
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
taskset -c 0 zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast -- --scenario=datagram --datagram-payload-bytes=256 --warmup=100 --iterations=1000
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream_gap --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=service --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=datagram_copy --frame=datagram --warmup=500 --iterations=10000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=datagram_borrowed --frame=datagram --warmup=500 --iterations=10000
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
taskset -c 0 zig build bench-io-deadline -Doptimize=ReleaseFast -- --samples=5 --warmup=2000 --iterations=50000
taskset -c 0 zig build bench-mqtt-tls -Doptimize=ReleaseFast
```

Two historical 2026-09-04 post-close-semantics MQTT-over-TLS regression samples
used the former `std.Io.Threaded` harness with one
persistent native TLS 1.3 connection, 100 warmup exchanges, and 2,000 measured
1-KiB QoS 1 publish/PUBACK round trips. They measured 11.693-11.812 us per
operation and 84,658-85,518 operations/s on CPU 0. This is an internal hot-path
guard for the shared vail record stream, not a cross-library performance claim.

## Detailed sections

| Document | Contents |
| --- | --- |
| [current-results.md](benchmarks/current-results.md) | HTTP/1, HTTP/2, HTTP/3, QUIC send/receive, gRPC, and zio-era smokes |
| [quic-stream.md](benchmarks/quic-stream.md) | Raw QUIC real-handshake STREAM comparison |
| [websocket.md](benchmarks/websocket.md) | WebSocket frame encoding comparison |
| [mqtt.md](benchmarks/mqtt.md) | MQTT 5 QoS 1 fanout and shared-subscription router |
| [webtransport.md](benchmarks/webtransport.md) | WebTransport runtime/DATAGRAM baseline and wtransport comparison |
| [archive.md](benchmarks/archive.md) | Reference context, rejected optimization ideas, and remaining gaps |
