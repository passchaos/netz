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
- small response pipelines remain coalesced for minimal syscall/iovec overhead,
  while pipelines above 16 KiB validate every response first, retain only
  encoded heads/chunk framing, and borrow fixed bodies into one writev instead
  of copying the entire batch;
- `Connection.readRequestBatchInto` parses request heads and bodies into caller
  storage, borrows one receive buffer and consumes its prefix once per batch;
- borrowed head parsing scans CRLF-delimited lines once instead of first
  scanning for CRLFCRLF and then rescanning every header line.

The batch read path intentionally rejects chunked bodies because their complete
wire boundary requires body parsing; existing owned request APIs remain the
general path.

The pipeline benchmark accepts `--large-body` (16 × 64 KiB responses) to cover
the borrowed-body branch. Three CPU-0-pinned ReleaseFast runs completed at
10.66–10.79 us/request versus 15.43 us/request with the former whole-batch
copy, a 1.43–1.45x local improvement. The default same-shape Hyper 13-byte
benchmark remains coalesced and measured 0.742 us/request after this change.

## HTTP/1 bidirectional 1-MiB streaming bodies

Hyper's existing `end_to_end` benchmark includes fixed-size HTTP/1 bodies, but
does not expose a runnable 1-MiB fixed/chunked pair. The checked-in
`tools/hyper_http1_body` harness therefore imports the audited local Hyper
revision without modifying `~/Work/hyper`; `bench-http1-body` mirrors it.
Its Cargo lockfile pins the support crates and the wrapper builds offline after
the initial dependency cache is populated.
Both use one persistent connection, current-thread event loops, TCP_NODELAY,
20 warmup plus 200 measured round trips, a 1-MiB request and response, and
borrowed streaming receive. Fixed mode sends one exact Content-Length body per
direction. Chunked mode preserves 64 application chunks of 16 KiB per
direction; Hyper's `StreamBody` and netz's `writeChunks` retain those same
boundaries. Both include the same Date value.

Commands:

```sh
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=fixed --warmup=20 --iterations=200
taskset -c 0 tools/bench_hyper_http1_body.sh \
  --mode=fixed --warmup=20 --iterations=200

taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=chunked --warmup=20 --iterations=200
taskset -c 0 tools/bench_hyper_http1_body.sh \
  --mode=chunked --warmup=20 --iterations=200
```

2026-08-19 ranges, each from five CPU-0-pinned process runs:

```text
fixed Content-Length, 1 MiB each direction:
  netz:  268.72-270.10 us/round-trip, 7,404-7,442 aggregate MiB/s
  hyper: 288.61-293.14 us/round-trip, 6,822-6,929 aggregate MiB/s
  netz is about 1.07-1.09x faster

chunked, 64 x 16 KiB each direction:
  netz:  284.04-286.06 us/round-trip, 6,991-7,041 aggregate MiB/s
  hyper: 414.64-417.45 us/round-trip, 4,790-4,823 aggregate MiB/s
  netz is about 1.45-1.47x faster
```

H1 enables TCP_NODELAY, fixed readers deliver socket bytes directly to
callbacks, chunk descriptors and vectored slice lists retain connection
scratch, and `writeChunks` batches many caller boundaries without concatenating
payloads. On POSIX, large HTTP/1 batches use the platform IOV limit instead of
Zig Threaded's portable eight-iovec cap. Chunked readers now read up to 64 KiB
directly into their retained connection buffer. One transport read may span
multiple size/data/CRLF records or reach the next pipelined message, while the
parser still invokes the callback at each wire-chunk boundary and commits only
the current message. This removes repeated exact-boundary reads without
aggregating a whole body. Both modes demonstrate an advantage in these named
loopback workloads; neither establishes whole-library superiority.

The same gate also covers a finer streaming shape without changing either
implementation: 1 MiB each direction as 1,024 x 1-KiB chunks, 10 warmups and
100 measured round trips. Three CPU-0 runs measured netz at 581.64-590.26 us
(3,388-3,438 aggregate MiB/s) versus Hyper at 2.031-2.653 ms
(753-984 MiB/s), a conservative 3.44-4.56x latency advantage. This stresses
boundary preservation rather than bulk copy: netz renders descriptors into
retained scratch and submits borrowed slices up to the POSIX IOV limit, while
the callback reader still observes every application chunk.

`bench-http1-body --stats` now adds the same thread-safe allocator telemetry as
the H2/WebSocket benchmarks. A short 1-MiB smoke used 37 allocations and
1,063,364 peak live bytes for fixed framing, versus 45 allocations and
1,288,250 peak live bytes for 64 x 16-KiB chunked framing. In both cases the
1-MiB application payload dominates live memory; retained chunk/vector scratch
adds roughly 225 KiB for chunked framing and allocation counts stay constant
across body bytes after warmup. Equal Hyper allocator instrumentation is still
required for a memory ratio.

## HTTP/2 consecutive and parallel round trips

Hyper's `benches/end_to_end.rs` defines consecutive empty GET, consecutive
10-byte and 100-KiB POST, parallel x10 empty GET, max-window chunked request,
and max-window 1-MiB response scenarios on persistent HTTP/2 connections. The
netz h2c benchmark mirrors them with 1,000 untimed warmup iterations for small
messages (100 for 100 KiB) and 2,000 measured iterations. The 10-stream body
workloads use 5 warmups and 20 measured batches because each batch transfers
about 10 MiB:

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
taskset -c 0 "$HYPER_H2_BENCH" \
  --bench http2_parallel_x10_req_10kb_100_chunks_max_window
taskset -c 0 "$HYPER_H2_BENCH" \
  --bench http2_parallel_x10_res_1mb
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

http2_parallel_x10_req_10kb_100_chunks_max_window:
  netz:  1.64-1.74 ms/10-stream batch
         164-174 us/request
  hyper: 3.36-3.40 ms/10-stream batch
         336-340 us/request
  netz is about 1.93-2.07x faster per batch

http2_parallel_x10_res_1mb (2026-08-19):
  netz:  1.663-1.671 ms/10-stream batch
         166.3-167.1 us/request
  hyper: 2.957-3.035 ms/10-stream batch
         295.7-303.5 us/request
  netz is about 1.77-1.82x faster per batch
```

For the response case, Hyper supplies one `Full<Bytes>` per stream. The locked
h2 0.4.15 scheduler splits it at the default 16-KiB frame limit and requeues
the stream after each frame. Netz uses the same 16-KiB round-robin contribution,
so the comparison matches not only body and window sizes but also DATA
interleaving.

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

Reusable implementation changes behind these H2 results:

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
- `requestBodyBatchInto` extends that boundary to DATA when the complete batch
  fits currently available connection and per-stream flow-control credit. It
  transactionally stages every HPACK block, then sends application-sized DATA
  contributions round-robin without copying payloads. The server counterpart,
  `readRequestBatchStreamingInto`, routes interleaved DATA by stream ID into
  callbacks, validates each Content-Length and owns each head/trailer set.
  Insufficient credit is rejected before wire I/O rather than entering a
  blocking half-duplex deadlock;
- `writeResponseBatch` validates and encodes a bodyless response set before one
  submission; a deep-cloned HPACK encoder is committed only after the wire
  write succeeds, so a failed batch cannot desynchronize compression state;
- `writeResponseBodyBatch` extends the server boundary to complete bodies that
  need not fit current connection and per-stream credit. It stages all HPACK
  state and allocation before wire I/O, borrows payloads, submits each stream's
  application contribution round-robin, and pumps WINDOW_UPDATE while every
  unfinished stream is blocked. The scheduler rotates its starting stream so a
  small connection update cannot repeatedly favor stream zero. The
  corresponding `requestBatchStreamingInto` client path demultiplexes
  interleaved DATA by request index, continuously returns flow credit,
  validates each declared length, and retains only owned response metadata
  rather than a batch-sized body aggregate;
- large batch header blocks retain normal HEADERS/CONTINUATION framing.

### HTTP/2 constrained-window parallel responses

The max-window Hyper workload does not exercise response backpressure. A
checked-in companion harness therefore uses the same Hyper revision through a
local path dependency without modifying `~/Work/hyper`. Both peers run ten
bodyless requests, wait until all ten handlers exist, then concurrently stream
1 MiB per response with a 16-KiB maximum DATA frame size, an 8-KiB stream
window and the RFC default 65,535-byte connection window. Both clients drain
all response bodies concurrently.

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --warmup=5 --iterations=20
taskset -c 0 tools/bench_hyper_http2_flow.sh \
  --warmup=5 --iterations=20
```

2026-08-19 ranges, each from five CPU-0-pinned process runs:

```text
netz:  7.367-7.447 ms/10-stream batch
       1,342-1,357 body MiB/s
hyper: 10.192-10.379 ms/10-stream batch
       963-981 body MiB/s
netz is about 1.37-1.41x faster per batch
```

This evidence covers normal WINDOW_UPDATE-driven completion and round-robin
progress. End-to-end tests separately verify a member-stream reset is observed
while the server is blocked on response credit. It remains one synchronous
loopback shape, not a claim about all priorities, cancellation races or network
conditions.

### RFC 9218 priority-aware response scheduling

When `SETTINGS_NO_RFC7540_PRIORITIES=1` is enabled, the same flow-controlled
batch writer now applies the Priority request field and later
`PRIORITY_UPDATE` signals to DATA selection:

- the lowest urgency that currently has both connection and stream credit is
  selected first;
- non-incremental responses at that urgency complete one at a time in ascending
  stream-ID order;
- incremental responses at that urgency share each application-chunk pass and
  rotate their starting stream;
- a high-urgency stream with zero stream credit does not idle usable
  connection credit that a lower-urgency stream can consume;
- priority is re-read each pass, so an update received while the writer pumps
  WINDOW_UPDATE can affect the next DATA burst.

The ordinary benchmark path remains round-robin so the Hyper comparison above
keeps its previous equal scheduling shape. An opt-in internal workload uses one
urgency-0 non-incremental stream, four urgency-2 incremental streams and five
urgency-5 incremental streams:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=2 --iterations=5
```

Two sets of three CPU-0-pinned 2026-08-19 runs:

```text
7.880-8.015 ms/10-stream batch
1,247-1,268 body MiB/s
```

This is an internal overhead/repeatability baseline, not a cross-stack ratio.
The audited Hyper dependency, h2 0.4.15, queues streams without RFC 9218
urgency/incremental state and therefore cannot run an equal semantic workload.
End-to-end tests prove non-incremental stream-ID order, incremental sharing,
Priority-header ordering, PRIORITY_UPDATE precedence, and use of lower-urgency
connection credit while a more urgent stream has no stream credit.

## Current feature comparison

| Area | netz | hyper |
| --- | --- | --- |
| HTTP/1 client/server | Blocking std.Io, TLS client, io_uring experiments, persistent/pipelined serving, stateful fixed/chunked writers and callback-streaming fixed/chunked/close-delimited readers | Async runtime integration, mature ecosystem and generic Body polling |
| HTTP/1 strictness | Host/authority, TE/CL, CONNECT/HEAD/status body semantics, trailers, 100-continue | Mature RFC behavior and broad production use |
| HTTP/2 | h2c client/server, Upgrade, HPACK, push, priorities, flow control, tunnels/RFC 8441 | Tokio h2 integration and production client/server |
| HTTP/1 direct pipeline sample | 0.711-0.752 us/request pinned | 0.836-0.866 us/request pinned |
| HTTP/1 fixed 1-MiB duplex | 268.72-270.10 us/op pinned | 288.61-293.14 us/op pinned |
| HTTP/1 chunked 1-MiB duplex | 284.04-286.06 us/op pinned | 414.64-417.45 us/op pinned |
| HTTP/2 consecutive empty | 9.55-9.96 us/op pinned | 12.51-12.54 us/op pinned |
| HTTP/2 consecutive 10-byte POST | 10.09-10.38 us/op pinned, coalesced frame submission | 41.15-41.37 ms/op pinned, delayed-ACK cliff on this host |
| HTTP/2 consecutive 100-KiB POST | 23.52-23.57 us/op pinned, streaming receive | 37.24-38.68 us/op pinned |
| HTTP/2 parallel x10 empty | 26.35-26.60 us/batch pinned | 47.50-48.46 us/batch pinned |
| HTTP/2 parallel x10 × 100 × 10-KiB request chunks | 1.64-1.74 ms/batch pinned | 3.36-3.40 ms/batch pinned |
| HTTP/2 parallel x10 × 1-MiB responses | 1.663-1.671 ms/batch pinned | 2.957-3.035 ms/batch pinned |
| HTTP/2 parallel x10 × 1-MiB responses, 8-KiB stream window | 7.367-7.447 ms/batch pinned | 10.192-10.379 ms/batch pinned |

RFC 9218 scheduling now selects urgency and the lowest-ID exclusive
non-incremental stream in one candidate scan rather than two. The priority-aware
10-stream/1-MiB/8-KiB-window benchmark measured 7.79–7.96 ms/batch and
1.26–1.28 GiB/s across three CPU-0 runs; the immediately preceding two-scan
sample was 8.03 ms/batch. HTTP/2 and HTTP/3 both carry replacement-order tests.

## Remaining evidence

1. Add a cancellation-race benchmark that combines reset timing with the
   priority-aware flow scheduler. **Completed:** `bench-http2-flow --priority
   --cancel-after=8` opens ten 1-MiB responses behind 8-KiB stream/65,535-byte
   connection windows, processes eight priority-scheduled DATA callbacks, then
   cancels all unfinished members. The client now writes every RST_STREAM in
   one batch instead of one transport write per stream and drops their retained
   send/receive-window entries. Unlike generic half-close cleanup, this happens
   only at RST_STREAM, where both directions are terminal. Five CPU-0 runs took 230.4-241.2 us from request
   submission through server observation of the reset batch. One `--stats` run
   used 293 allocations and 1,287,988 peak live bytes. Hyper/h2 has no RFC 9218
   scheduler, so this is internal timing evidence rather than a cross-stack
   ratio.
2. Run the new `bench-http2-flow --stats` allocator telemetry on the full
   netz/Hyper comparison matrix. The netz benchmark now reports allocation
   calls, cumulative allocated/freed bytes, live bytes, peak live bytes and
   size buckets through a shared thread-safe benchmark allocator; a two-stream
   64-KiB/8-KiB-window smoke observed 293 allocations and 288,461 peak live
   bytes. Equal instrumentation is still needed on the Hyper harness before
   making a memory ratio.
   On the full 10-stream/1-MiB/8-KiB-window shape, call-stack sampling showed
   WINDOW_UPDATE flow pumping allocating one 13-byte OwnedFrame per control
   frame. The server now consumes those frames directly from retained reader
   storage. Three CPU-0 runs used exactly 1,910 allocations versus 12,948 before
   (85.2% fewer), while peak live bytes stayed 1,286,109 because the eliminated
   frames were transient. Stable runs measured 7.20-7.23 ms/batch; one noisy
   10.81-ms sample is retained as variance rather than folded into a speed
   ratio. Exact-size allocation reporting remains available for the next audit.
   Owned decoded header blocks now place every name/value string in one shared
   allocation rather than two allocations per field. The same full flow shape
   used exactly 1,488 allocations versus 1,910 before (22.1% fewer) across
   three runs; stable samples were 7.08-7.10 ms/batch and peak live memory
   remained about 1.29 MB. Push-promise ownership uses the same block-aware
   deinitializer, and tests cover both ordinary and pushed headers.
3. Add external h2spec and broad HTTP conformance/interoperability evidence.
4. Compare cancellation, backpressure and fairness under concurrent streams;
   one synchronous loopback pipeline is not whole-library superiority.
