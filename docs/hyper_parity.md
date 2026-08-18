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
  11.38-12.03 us / 16-request batch
  0.711-0.752 us/request
  1.330-1.406 million requests/s
```

Netz is about 1.11-1.22x faster in this captured workload.

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

## HTTP/2 consecutive and parallel round trips

Hyper's `benches/end_to_end.rs` defines consecutive empty GET, consecutive
10-byte and 100-KiB POST, and parallel x10 empty GET scenarios on persistent
HTTP/2 connections. The netz h2c benchmark mirrors them with 1,000 untimed
warmup iterations for small messages (100 for 100 KiB) and 2,000 measured
iterations:

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast

cd ~/Work/hyper
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

The reference revision/toolchain are the same as the HTTP/1 comparison above.
Syscall traces verified equal steady-state wire shapes:

- empty: 19-byte request and 11-byte response for each implementation;
- 10-byte POST: 43 request bytes (24-byte HEADERS + 19-byte DATA) and an
  11-byte response for each implementation;
- 100-KiB POST: the same Content-Length and 16-KiB DATA framing, consumed
  incrementally by both servers rather than retained as one application body.

2026-08-17 ranges, each from five CPU-0-pinned process runs:

```text
http2_consecutive_x1_empty:
  netz:   9.55-9.96 us/op
  hyper: 12.51-12.54 us/op
  netz is about 1.26-1.31x faster

http2_consecutive_x1_req_10b:
  netz:  10.09-10.38 us/op
  hyper: 41.15-41.37 ms/op

http2_consecutive_x1_req_100kb:
  netz:  23.52-23.57 us/op
  hyper: 37.24-38.68 us/op
  netz is about 1.58-1.64x faster

http2_parallel_x10_empty:
  netz:  26.35-26.60 us/10-request batch
         2.63-2.66 us/request
  hyper: 47.50-48.46 us/10-request batch
         4.75-4.85 us/request
  netz is about 1.79-1.84x faster per batch
```

The 10-byte result is a specific Linux TCP scheduling cliff, not a general
3,500x whole-stack claim. In the audited Hyper run, HEADERS and DATA are two
small `writev` calls and the response follows about 41 ms later. Netz preserves
the same two HTTP/2 frames and 43 wire bytes but submits their four borrowed
slices in one `sendmsg`, avoiding Nagle/delayed-ACK interaction. Larger bodies,
trailers, fragmented header blocks and flow-control-blocked streams use the
normal multi-write fallback.

HTTP/1 now also exposes the Body-style send boundary that was previously only
available for HTTP/2:

- `Client.startRequest` returns a stateful `RequestWriter`; fixed-length bodies
  are checked transactionally across writes, unknown HTTP/1.1 entity bodies use
  chunked transfer coding, and `finishTrailers` emits only fields announced by
  `Trailer`;
- `Connection.startResponse` provides the server counterpart and shares the
  existing HEAD, 1xx/204/304, and successful CONNECT body-suppression rules;
- chunk headers, borrowed application bytes, and CRLF are sent as vectored
  slices without a body-sized concatenation;
- a request writer owns the connection until its response is consumed, while a
  response writer releases it only after a complete fixed body or terminating
  chunk. Abandonment marks the HTTP/1 connection unusable because, unlike
  HTTP/2 RST_STREAM, HTTP/1 has no per-message reset that can restore framing.
- `Connection.readRequestStreaming` and `Client.requestStreaming` provide the
  receive-side counterpart. Fixed-length, chunked, trailer-bearing and
  close-delimited bodies are delivered as borrowed callback slices without a
  body-sized allocation; returned start-line/header/trailer metadata remains
  owned, and bytes already read from the next pipelined message stay buffered.
  `RequestWriter.readResponseStreaming` performs the same one-time response
  handoff after an incremental upload. Callback or framing failure poisons the
  HTTP/1 connection rather than risking reuse at an unknown message boundary.

Reusable implementation changes behind all four H2 results:

- a shared Zig 0.16 stream-vector helper correctly reserves `netWrite`'s final
  data element as its splat pattern and handles partial writes;
- HTTP/1, HTTP/2 and WebSocket now use that single reviewed helper instead of
  three subtly incorrect copies;
- HPACK encoders retain their block scratch between HEADERS writes;
- common request/response descriptor lists use stack storage, with exact
  allocation fallback for larger caller header sets;
- a one-frame body with available flow credit is submitted together with its
  HEADERS frame without concatenating or copying application bytes;
- DATA frames are submitted in vectored bursts, TCP_NODELAY avoids delayed-ACK
  stalls at flow-window boundaries, and connection/stream receive windows are
  independently configurable;
- one connection read buffer can retain several coalesced frames, while
  ordinary owning APIs still receive independent frame copies;
- `readRequestStreaming` returns an owned request head/trailers and delivers
  borrowed DATA slices to a callback without body-sized aggregation;
- `requestStreaming` provides the symmetric client path: response DATA is
  delivered as borrowed callback slices while the returned status, initial
  headers and trailers remain owned. It skips valid informational responses,
  strictly accounts Content-Length, returns flow credit while the body is
  arriving, and sends RST_STREAM(CANCEL) when the callback fails, matching
  Hyper's `Incoming` frame-stream lifecycle without requiring an async body
  object;
- `startResponse` returns a stateful `ResponseWriter` for server-side streaming
  bodies. Separate writes preserve flow-control backpressure, cumulative
  Content-Length is validated before each frame is sent, DATA FIN and trailers
  terminate exactly once, and dropping an unfinished writer sends
  RST_STREAM(CANCEL). This mirrors Hyper/h2's `SendStream` lifecycle in the
  blocking runtime rather than requiring callers to reach private frame APIs;
- `startRequest` provides the client-side counterpart. `RequestWriter` accepts
  bounded or length-unbounded DATA chunks, request trailers and transactional
  length retries, remains responsible for cancellation after request-body FIN,
  and hands off exactly once to either aggregate or callback-streaming response
  receive. This matches Hyper's request `Body` → h2 `SendStream` ownership
  boundary without aggregating the upload first. If response HEADERS or a peer
  reset arrives while upload DATA is blocked on flow control, netz preserves
  the one owned application frame, reports partial write progress through the
  writer state, closes the request half and transfers the response to either
  receive mode instead of discarding it. The pending storage stays bounded to
  one frame because control returns to the caller immediately, paralleling
  Hyper's independently driven response future/body pipe;
- `requestBatchInto` opens bodyless streams together, accepts response frames in
  any stream order, and returns owned responses in request order;
- `writeResponseBatch` validates and encodes a bodyless response set before one
  submission; a deep-cloned HPACK encoder is committed only after the wire
  write succeeds, so a failed batch cannot desynchronize compression state;
- large batch header blocks retain normal HEADERS/CONTINUATION framing.

## Current feature comparison

| Area | netz | hyper |
| --- | --- | --- |
| HTTP/1 client/server | Blocking std.Io, TLS client, io_uring experiments, persistent/pipelined serving, stateful fixed/chunked writers and callback-streaming fixed/chunked/close-delimited readers | Async runtime integration, mature ecosystem and generic Body polling |
| HTTP/1 strictness | Host/authority, TE/CL, CONNECT/HEAD/status body semantics, trailers, 100-continue | Mature RFC behavior and broad production use |
| HTTP/2 | h2c client/server, Upgrade, HPACK, push, priorities, flow control, tunnels/RFC 8441 | Tokio h2 integration and production client/server |
| HTTP/1 direct pipeline sample | 0.711-0.752 us/request pinned | 0.836-0.866 us/request pinned |
| HTTP/2 consecutive empty | 9.55-9.96 us/op pinned | 12.51-12.54 us/op pinned |
| HTTP/2 consecutive 10-byte POST | 10.09-10.38 us/op pinned, coalesced frame submission | 41.15-41.37 ms/op pinned, delayed-ACK cliff on this host |
| HTTP/2 consecutive 100-KiB POST | 23.52-23.57 us/op pinned, streaming receive | 37.24-38.68 us/op pinned |
| HTTP/2 parallel x10 empty | 26.35-26.60 us/batch pinned | 47.50-48.46 us/batch pinned |

## Remaining evidence

1. Add same-shape Hyper comparisons for fixed 1-MiB bodies, chunked bodies and
   body-bearing HTTP/2 parallel workloads.
2. Measure allocation count and peak memory, not only elapsed time.
3. Add external h2spec and broad HTTP conformance/interoperability evidence.
4. Compare cancellation, backpressure and fairness under concurrent streams;
   one synchronous loopback pipeline is not whole-library superiority.
