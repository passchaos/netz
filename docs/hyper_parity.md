# netz vs `~/Work/hyper` HTTP/1 and HTTP/2 audit

This audit tracks direct same-host evidence for the HTTP/1 and HTTP/2 portion
of the netz improvement goal. Hyper's benchmark definitions are used where
possible instead of comparing unrelated codec microbenchmarks.

## HTTP/1 16-request pipeline

Hyper's `benches/pipeline.rs::hello_world_16` sends sixteen identical
bodyless requests on one TCP connection and enables `pipeline_flush(true)` for
sixteen `"Hello, World!"` responses. Hyper automatically adds a 29-byte Date
value, so the netz benchmark supplies the same-length field and sends the same
89 response bytes per request. Netz performs 200 untimed warmup batches before
its 2,000 measured batches, matching the calibration intent of Rust's Bencher.

Equivalent netz command:

```sh
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
```

To remove this host's P-core/E-core scheduler variance, both compiled binaries
were pinned to CPU 0. The reference checkout was Hyper revision
`084473f728f9d07b3be5845475aa2f62ed9ff579`, built with
`rustc 1.98.0-nightly (e7815e522 2026-06-04)` and run with:

```sh
cd ~/Work/hyper
cargo bench --bench pipeline hello_world_16 --features full
HYPER_BENCH=$(
  find target/release/deps -maxdepth 1 -type f \
    -name 'pipeline-*' -executable -print -quit
)
taskset -c 0 "$HYPER_BENCH" --bench hello_world_16
```

2026-08-17 ranges, each from five pinned process runs:

```text
hyper hello_world_16:
  13.38-13.85 us / 16-request batch
  0.836-0.866 us/request

netz bench-http1-pipeline:
  11.56-11.76 us / 16-request batch
  0.723-0.735 us/request
  1.361-1.384 million requests/s
```

Netz is about 1.14-1.20x faster in this captured workload.

## Implementation evidence

The result is backed by reusable runtime changes rather than a pre-rendered
benchmark response:

- persistent clients/connections retain request/response header descriptors,
  trailer rendering and encoding buffers;
- non-chunked bodies are borrowed and sent with header+body vectored TCP I/O
  (or one TLS flush) instead of copied into a temporary whole-message buffer;
- `Connection.writeResponses` validates and flushes a response pipeline in one
  transport write, matching Hyper's `pipeline_flush` scheduling shape;
- `Connection.readRequestBatchInto` parses request heads and bodies into caller
  storage, borrows one receive buffer and consumes its prefix once per batch;
- borrowed head parsing scans CRLF-delimited lines once instead of first
  scanning for CRLFCRLF and then rescanning every header line.

The batch read path intentionally rejects chunked bodies because their complete
wire boundary requires body parsing; existing owned request APIs remain the
general path.

## Current feature comparison

| Area | netz | hyper |
| --- | --- | --- |
| HTTP/1 client/server | Blocking std.Io, TLS client, io_uring experiments, persistent/pipelined serving | Async runtime integration, mature ecosystem |
| HTTP/1 strictness | Host/authority, TE/CL, CONNECT/HEAD/status body semantics, trailers, 100-continue | Mature RFC behavior and broad production use |
| HTTP/2 | h2c client/server, Upgrade, HPACK, push, priorities, flow control, tunnels/RFC 8441 | Tokio h2 integration and production client/server |
| Direct pipeline sample | 0.723-0.735 us/request pinned | 0.836-0.866 us/request pinned |

## Remaining evidence

1. Add same-shape Hyper comparisons for fixed 1 MB bodies, chunked bodies and
   HTTP/2 consecutive/parallel workloads.
2. Measure allocation count and peak memory, not only elapsed time.
3. Add external h2spec and broad HTTP conformance/interoperability evidence.
4. Compare cancellation, backpressure and fairness under concurrent streams;
   one synchronous loopback pipeline is not whole-library superiority.
