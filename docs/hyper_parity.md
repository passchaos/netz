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
- server `Limits.request_head_timeout` applies one absolute deadline to each
  request head over TCP or TLS, starts while the connection is idle before its
  first byte, does not reset on trickled bytes, resets for each persistent
  request (and each unbuffered member of a pipeline batch), and stops before
  body reads; unsupported raw io_uring use fails explicitly rather than
  silently dropping the policy;
- client `Limits.response_head_timeout` applies one absolute deadline from the
  first required response byte through the final response head. Partial bytes
  and informational 1xx heads do not renew it, while body reads remain outside
  the budget. The same policy covers aggregate and streaming responses,
  Expect/100-continue, CONNECT and generic Upgrade over cleartext and TLS; the
  raw io_uring helper rejects its unsupported timed-read configuration before
  opening a socket;
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

The parser also mirrors Hyper's explicitly opt-in HTTP/1 compatibility
controls while preserving strict defaults.
`allow_multiple_spaces_in_request_line_delimiters` accepts repeated ASCII SP
between method, target and version, and
`allow_spaces_after_header_name_in_responses` accepts SP/HTAB immediately
before a response field colon. Direction-specific
`ignore_invalid_headers_in_requests` and
`ignore_invalid_headers_in_responses` can skip an otherwise malformed header
line, but still reject NUL and bare CR rather than permitting ambiguous line
boundaries. Response whitespace tolerance never affects requests or trailers,
preserving the request-smuggling boundary described by Hyper's public API.
Both owned and caller-buffer head parsers share these rules. The corresponding
local Hyper/httparse tests and netz parity tests pass on the same
malformed/default and accepted/opt-in wire forms:

```sh
cd ~/Work/hyper
cargo test --features full \
  test_parse_allow_request_with_multiple_spaces_in_request_line
cargo test --features full \
  test_parse_allow_response_with_spaces_before_colons
cd ~/.cargo/registry/src/rsproxy.cn-e3de039b2554c837/httparse-1.10.1
cargo test test_ignore_header_line_with_whitespaces_after_header_name_in_request
cargo test test_ignore_header_line_with_whitespaces_after_header_name_in_response

cd ~/project-z/netz
zig test -ODebug \
  --test-filter 'HTTP/1 Hyper-shaped parser compatibility' ...
zig test -ODebug \
  --test-filter 'HTTP/1 invalid-header compatibility' ...
```

The streaming chunked-body reader now applies the same opt-in obs-fold policy
to trailers instead of silently retaining a stricter second parser. Strict
mode continues to reject folded trailers. Compatibility mode unfolds each
continuation to one SP, owns the resulting values independently of receive
buffer compaction, and works when every trailer byte arrives in a separate
transport read. Focused request and response regressions cover both directions,
matching Hyper's documented response-side obsolete-line-folding behavior.

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
across body bytes after warmup. The Hyper harness now accepts the same
`--stats` switch, enabled through an opt-in `allocation-stats` Cargo feature so
ordinary timing runs retain the system allocator directly. Its process-wide
atomic wrapper reports requested allocation/free/reallocation bytes and the
same size buckets without recursively allocating.

A matched CPU-0 run of the documented 1-MiB-per-direction, twenty-warmup,
hundred-iteration matrix measured:

```text
fixed:
  netz   286.850 us/op, 489 allocations, 1,063,300 peak live bytes
  Hyper  307.999 us/op, 4,899 allocations, 2,461,724 peak live bytes

16-KiB chunked:
  netz   304.222 us/op, 495 allocations, 1,269,638 peak live bytes
  Hyper  440.550 us/op, 34,417 allocations, 2,153,292 peak live bytes
```

Netz therefore used 90.0% fewer allocation calls and 56.8% less peak live
memory in fixed mode, and 98.6% fewer calls plus 41.0% less peak live memory in
chunked mode for this exact process-wide workload. Hyper's fixed-body run also
requested 100,692,363 cumulative bytes versus netz's 1,095,970; its chunked
run requested 3,469,637 versus netz's 1,309,426. These are allocator-request
counters rather than RSS measurements and include setup plus warmup on both
sides.

The benchmark evidence is complemented by a strict process-boundary semantic
gate. `zig build interop-http1-hyper -Doptimize=ReleaseFast` builds against the
audited local Hyper checkout and runs the same scenarios over fresh cleartext
and TLS 1.3 connections in both directions. The encrypted half uses the
checked-in localhost identity and each client validates that certificate.
Each peer sends a POST with two chunked DATA contributions, explicitly
negotiates `TE: trailers`, and terminates with a request trailer. The receiving
peer verifies method, query-bearing target, custom header, reconstructed body,
and trailer. The response path repeats the two-chunk plus terminal-trailer
shape with status 201 and exact response metadata. Each direction then performs
an `Expect: 100-continue` exchange. The sender withholds its declared request
body until the other implementation emits an HTTP/1.1 100 response, and the
receiver verifies the body plus final response. Hyper observes netz's interim
response through its `on_informational` extension. Netz now exposes the same
shape through `InformationalObserver` on aggregate and streaming client reads;
callbacks receive each ordered borrowed 1xx head, while a configurable count
limit prevents an endless interim-response chain from causing unbounded work.
The Hyper fixture sends 103 Early Hints and 102 Processing with distinct
headers before a final 200, and the netz client validates every status/header
over both cleartext and certificate-verified TLS. Netz also uses
`RequestWriter.waitForContinue`, which consumes preceding non-100 1xx
responses and returns a typed owned final response if the server rejects the
expectation before the body. The external client gate exercises both
branches against raw wire responses in the same Hyper/Tokio fixture: a 103
Early Hints followed by 100 Continue releases the exact ten-byte body, while a
417 response causes netz to send zero body bytes, return the owned rejection,
reject further writes through the stale writer, and mark the connection
unusable. The peer waits for EOF and fails if any declared-body byte arrives,
so this is observable process-boundary evidence rather than an in-process state
assertion. The netz HTTP/1 server uses the same parser, streaming-body state,
vectored writer, persistent connection, and CONNECT tunnel surface over either
raw TCP or its native TLS transport. This is functional HTTP/1.1 and HTTPS
interoperability evidence rather than a benchmark proxy.

The same process gate now exercises that CONNECT surface directly in both
endpoint roles over cleartext and TLS. Each server writes its protocol preface
immediately after the 200 response so the receiving HTTP implementation must
preserve any already-read tunnel suffix during parser handoff. The clients then
send 17/18-byte opaque payloads and validate exact replies in the reverse
direction. Hyper uses `upgrade::on` with `with_upgrades`, while netz uses
`openConnectTunnel` and `acceptConnectTunnel`; the gate awaits tunnel-task
completion instead of inferring success from the HTTP status.

Generic HTTP/1.1 `101 Switching Protocols` now has the same explicit transport
handoff rather than being available only through the WebSocket adapter. The
client validates `Connection: Upgrade`, the selected Upgrade token, empty HTTP
body/trailers, and then exposes any bytes read past the response head. The
server validates the corresponding request before sending 101 and transferring
its buffered request suffix. The Hyper process gate exercises both endpoint
roles over cleartext and TLS with protocol `netz-test`, bidirectional opaque
payloads, and an immediate server preface; the netz-server direction uses
Hyper's generic `upgrade::on`/`with_upgrades` path rather than WebSocket code.

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
  any stream order, and returns owned responses in request order.
  `requestBatchWithInformationalInto` adds borrowed, ordered 1xx callbacks
  correlated by request index and stream ID; the body-bearing and streaming
  batch variants expose the same observer contract, and each stream keeps an
  independent bounded informational-response count;
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
| HTTP/1 client/server | Blocking std.Io, native TLS 1.3 client/server, io_uring experiments, persistent/pipelined serving, bounded concurrent TCP/Unix/TLS listeners, long-running supervisors with cancellation plus accept/connection error policy, configurable DNS/TCP connect, TLS handshake, and caller-owned absolute per-request-head deadlines over TCP/TLS, stateful fixed/chunked writers, client/server Expect/100-continue, observable bounded informational responses, and callback-streaming fixed/chunked/close-delimited readers. A caller-owned request deadline preserves a partial head for an explicit later retry, while configured Slowloris protection retains its fail-closed connection policy. A thread-safe bounded HTTP/HTTPS client pool reuses idle connections per scheme/authority, exposes exclusive leases for streaming APIs, caps the combined idle/leased/connecting population, reports that live count, and offers relative/absolute FIFO capacity waits with wakeups on release, failure, eviction and close. It also enforces a monotonic idle timeout, evicts least-recently-used idle entries, discards non-reusable responses, and retries a stale reused connection once only for idempotent methods. Certificate-verified HTTPS interop with Hyper is exercised in both endpoint roles | Async runtime integration, mature ecosystem and generic Body polling; its server header-read timeout has equivalent absolute per-head semantics |
| HTTP/1 strictness | Host/authority, TE/CL, CONNECT/HEAD/status body semantics, trailers, 100-continue, ordered 1xx observation and bounded interim chains | Mature RFC behavior and broad production use |
| HTTP/2 | Prior-knowledge TCP/Unix client/server, h2c Upgrade, and native TLS 1.3 client/server with mandatory `h2` ALPN, optional/required client authentication, and separate resolved-address plus TLS-host/authority connection; configurable DNS/TCP connect budgets; bounded concurrent and long-running supervised TCP/Unix/TLS serving; an authority-keyed, total/idle-bounded exclusive connection pool for cleartext and verified TLS that reuses HPACK state, offers FIFO timeout/deadline capacity waits, retries a stale reused socket once only for idempotent methods, and discards GOAWAY, active-stream and push-capable connections; HPACK, bounded ordered informational callbacks, push, priorities, flow control, graceful GOAWAY draining, public Last-Stream-ID retry classification, tunnels/RFC 8441, explicit absolute-deadline PING round trips, and single-reader inactivity-aware keep-alive cycles with active/idle policy; certificate-verified TLS interop with Hyper/h2 is exercised in both endpoint roles, including 1xx, push, and push opt-out | Tokio h2 integration and production client/server, including automatic background keep-alive interval/timeout/idle policy |
| HTTP/1 direct pipeline sample | 0.711-0.752 us/request pinned | 0.836-0.866 us/request pinned |
| HTTP/1 fixed 1-MiB duplex | 268.72-270.10 us/op pinned | 288.61-293.14 us/op pinned |
| HTTP/1 chunked 1-MiB duplex | 284.04-286.06 us/op pinned | 414.64-417.45 us/op pinned |

The Hyper process gate now also establishes a dedicated persistent connection
for two URI-based requests through `http1.client_pool.Pool`, in both cleartext
and certificate-verified TLS modes. Hyper counts exactly two requests on that
single accepted socket, while netz verifies case-insensitive authority reuse
and one idle pooled connection afterward. This is direct cross-process evidence
for the pool rather than inference from the standalone persistent Client tests.
| HTTP/2 consecutive empty | 9.55-9.96 us/op pinned | 12.51-12.54 us/op pinned |
| HTTP/2 consecutive 10-byte POST | 10.09-10.38 us/op pinned, coalesced frame submission | 41.15-41.37 ms/op pinned, delayed-ACK cliff on this host |
| HTTP/2 consecutive 100-KiB POST | 23.52-23.57 us/op pinned, streaming receive | 37.24-38.68 us/op pinned |
| HTTP/2 parallel x10 empty | 26.35-26.60 us/batch pinned | 47.50-48.46 us/batch pinned |
| HTTP/2 parallel x10 × 100 × 10-KiB request chunks | 1.64-1.74 ms/batch pinned | 3.36-3.40 ms/batch pinned |
| HTTP/2 parallel x10 × 1-MiB responses | 1.663-1.671 ms/batch pinned | 2.957-3.035 ms/batch pinned |
| HTTP/2 parallel x10 × 1-MiB responses, 8-KiB stream window | 7.367-7.447 ms/batch pinned | 10.192-10.379 ms/batch pinned |

Both bounded client pools now treat idle sockets as reclaimable rather than as
permanent occupants of the global connection budget. If an acquisition for a
new authority reaches `max_connections` while another authority has idle
capacity, the least-recently-used idle socket is closed and its accounting slot
is transferred directly to the new connection attempt. Checked-out leases are
never evicted, and a genuinely all-leased/all-connecting pool still returns or
waits on `ConnectionLimitReached`. Cross-authority TCP regressions for HTTP/1
and HTTP/2 set total and idle capacity to one, proving the second origin
connects, the first socket observes EOF, and the live count never exceeds one.
Capacity waits now use a shared allocation-free intrusive FIFO admission queue
rather than generation broadcasts. New acquisitions cannot barge ahead of
blocked callers; timeout/cancellation unlinks a stack-owned ticket and wakes its
successor. Real TCP tests hold the sole slot, enqueue two waiters in a known
order, and prove that they acquire in that order.
HTTP/1 pooled one-shot requests also expose an end-to-end absolute deadline: a
single timestamp spans FIFO capacity waiting, a new DNS/TCP/TLS connection when
needed, stale-idempotent retry, and the complete response. HTTP/2 pooled
one-shot requests expose the same contract through TLS and SETTINGS bootstrap;
both pools provide relative-timeout wrappers that convert once at API entry.

Both protocol `Limits` now also expose a TCP connect timeout used by literal-IP,
hostname, URI, Unix-socket and pooled connection paths. Host resolution and all
address attempts share one awake-clock deadline; a concurrently completed but
unselected socket is closed. HTTP/1 direct-address, hostname, Unix, standard TLS
and vail TLS constructors additionally accept a caller-owned absolute deadline.
HTTP/1 TLS servers expose matching post-accept timeout/deadline forms for the
complete TLS handshake, including already accepted streams; configured TLS
handshake limits remain stricter.
The standard-library TLS client initializer and low-level complete-request /
request-aware-response stream adapters likewise expose relative-timeout and
absolute-deadline pairs, allowing protocol upgrade adapters to choose either
budget form without duplicating timestamp conversion.
HTTP/2 direct-address, hostname, Unix and TLS constructors expose the same
contract through the complete SETTINGS bootstrap. TLS paths preserve the outer
deadline across DNS/TCP and TLS while all paths retain stricter phase limits.
HTTP/2 TLS servers expose matching post-accept timeout/deadline forms spanning
TLS 1.3, ALPN validation, and the HTTP/2 preface/SETTINGS bootstrap.
Cleartext TCP and Unix-domain HTTP/2 servers expose the same post-accept
timeout/deadline contract for their complete preface/SETTINGS bootstrap; TCP
also accepts an already-dispatched stream under either a relative timeout or a
caller timestamp. TLS already-accepted streams expose the same pair across TLS,
ALPN validation, and HTTP/2 bootstrap.
Both protocol constructors also provide relative-timeout wrappers that convert
the end-to-end budget once at entry.
Ordinary timeout-based APIs remain separate from HTTP
response/preface handshake budgets, and failed pool connects continue to return
their reserved capacity slot.

Native HTTP/1 vail TLS client and server connections expose their authenticated
peer chain, negotiated ALPN/cipher suite/hash, RFC 8446 exporter, explicit
KeyUpdate and update counters. The client keeps the standard-library HTTPS
path as its compatibility default and offers `connectVailTlsHost` /
`requestUriVailTls` when those advanced features are required. CONNECT/Upgrade
tunnels preserve the vail connection and KeyUpdate access after the HTTP parser
hands off the encrypted byte stream. The Hyper HTTP/1 process gate now runs its
HTTPS client direction through that vail path: rustls sends a real reciprocal
KeyUpdate before the response, netz verifies the server chain and negotiation
metadata, responds exactly once, and completes the remaining HTTP/1 scenarios.

RFC 9218 scheduling now selects urgency and the lowest-ID exclusive
non-incremental stream in one candidate scan rather than two. The priority-aware
10-stream/1-MiB/8-KiB-window benchmark measured 7.79–7.96 ms/batch and
1.26–1.28 GiB/s across three CPU-0 runs; the immediately preceding two-scan
sample was 8.03 ms/batch. HTTP/2 and HTTP/3 both carry replacement-order tests.

HTTP/1 CONNECT and Upgrade tunnels now expose timeout and absolute-deadline
reads across cleartext, standard-library TLS, and vail TLS transports. Bytes
that the HTTP parser read past the switching response/request are returned
before validating or arming the timeout, while later TLS record reads retain
one absolute caller budget. A regression covers buffered upgrade bytes, a
silent-peer timeout, and successful reuse of the same tunnel afterward.
Complete aggregate HTTP/1 client requests and streaming request writers also
expose response timeout/deadline methods. Their deadline spans informational
heads, the final head, fixed/chunked/close-delimited body, and trailers; a
configured response-head timeout is still enforced when it expires earlier.
Because HTTP/1 cannot cancel one exchange independently, timeout marks the
connection unusable so pools cannot replay against ambiguous leftover bytes.
One-shot HTTP and HTTPS URI helpers additionally accept an end-to-end absolute
deadline spanning DNS/TCP, standard or vail TLS, request emission, and the same
complete response boundary, while retaining every stricter phase timeout.
Relative-timeout wrappers convert their budget once at the one-shot API entry.
The reusable low-level TCP stream adapters now expose the same timeout/deadline
pair for buffered requests and request-aware responses. One deadline covers
the complete head/body/trailer sequence while bytes already read for the next
pipelined exchange remain in caller-owned storage. Both buffered and
unbuffered request-aware response adapters retain informational-response
callbacks on their bounded variants without granting the final response a new
budget after each 1xx head.

HTTP/2 aggregate and callback-streaming client requests now expose relative-
timeout and absolute-deadline forms on both complete requests and split
request/response flows. One deadline covers the complete response, including
permitted connection-control traffic and fragmented header blocks, without
renewal. A timeout sends RST_STREAM(CANCEL) best-effort and marks the connection
unusable because discarded HPACK/body state cannot safely be reconstructed;
client pools consequently discard that lease. Netz also exposes
one-shot HTTP/HTTPS URI deadline helpers that preserve that same absolute
timestamp across DNS/TCP, TLS, SETTINGS bootstrap, and the complete response;
matching relative-timeout wrappers convert once before any network work.
h2c Upgrade one-shot and existing-stream helpers provide the same timeout and
absolute-deadline forms: one caller budget spans TCP when applicable, the
HTTP/1.1 101 response, HTTP/2 SETTINGS bootstrap, and the complete stream-1
response without renewal, while stricter connect and handshake limits remain
in force. The upgrade request may carry a fixed-length or chunked body plus
trailers; the server returns those complete HTTP/1.1 bytes as the already
half-closed HTTP/2 stream 1 request, matching RFC 7540 section 3.2 semantics.
Server-side `acceptUpgradeWithTimeout` and `acceptUpgradeWithDeadline` apply
one outer budget after TCP accept through the complete Upgrade request and the
HTTP/2 SETTINGS exchange rather than granting a fresh timeout after 101.
HTTP/2 Extended CONNECT now exposes matching request/response timeout and
absolute-deadline forms. The client checks the deadline before request emission,
then preserves it across informational or connection-control frames, fragmented
HPACK, and the final successful response head; timeout cancels the stream and
makes discarded aggregate state ineligible for pooled reuse. The server reader
carries one deadline through the complete request header block and preserves a
partially received frame for retry when no stream has yet been admitted.
All public HTTP/1 and HTTP/2 request/response and pool deadline entry points
reject timestamps outside the awake-clock domain before parsing, writing, or
reserving pool capacity, matching the constructor deadline contract.
Netz also exposes
`Connection.pingWithTimeout(data, timeout)` and
`Connection.pingWithDeadline(data, deadline)` for a bounded HTTP/2
liveness round trip and `KeepAlive.run(connection)` for repeatable scheduled
keep-alive cycles. Passive PING, GOAWAY, RST_STREAM, WINDOW_UPDATE, and RFC
9218 PRIORITY_UPDATE readers now provide both timeout and absolute-deadline
variants, and HTTP/2 tunnels
provide `readWithTimeout` alongside `readWithDeadline`. The keep-alive driver
waits until a full interval of peer receive inactivity, supports Hyper-shaped
active-stream versus `while_idle` policy, and
then requires the matching ACK within a separate timeout. Both use awake-clock
absolute deadlines: stale ACKs and interleaved SETTINGS, PING, WINDOW_UPDATE,
PRIORITY, GOAWAY, and extension control traffic cannot renew the ACK budget.
Interleaved application frames are retained in wire order for the next request/
response reader. `Limits.max_pending_ping_frames` bounds that queue; the frame
that reaches the cap remains recoverable even though the probe returns
`MessageTooLarge`. Local cleartext tests cover silent-peer timeout, stale-ACK
and control-frame pressure, receive-activity rescheduling, idle skip/opt-in,
active response preservation, request/response frame preservation, queue-cap
preservation, partial-frame timeout recovery, one-budget control-frame waits,
and tunnel timeout recovery; native TLS tests cover both direct PING and
scheduled idle keep-alive. Unlike Hyper's continuously polled background
connection driver,
the blocking netz driver deliberately runs one cycle at a time and must be the
sole frame reader; applications repeat it from their owning event loop.

Inbound HPACK decoding now enforces `Limits.max_header_list_size` while walking
the compressed block rather than after materializing every header. Static,
dynamic and Huffman-backed fields are charged using RFC 9113's uncompressed
`name + value + 32` accounting before allocating application-visible output.
After the limit is crossed, the decoder still consumes and validates the rest
of the block and applies incremental-indexing updates, keeping the connection's
compression context synchronized for later streams without retaining oversized
output. Failing-allocator tests cover the allocation-free non-indexed rejection
path, while a second block proves indexed state survives an oversized first
block. Incremental literals also interpret all six name-index bits correctly;
the high index bit is no longer confused with the Never Indexed marker from
the separate four-bit representation. HPACK dynamic-table entries and decoded
dynamic indexed fields now each keep name/value bytes in one contiguous
allocation; eviction, clear, clone and allocation-failure tests cover the
single-owner invariant while the public field slices remain unchanged. A
warmed-table regression verifies each additional insertion needs one string
allocation rather than two. Decoder tables additionally omit the encoder-only
name and exact-value hash indexes: inbound wire references are positional, so
maintaining those maps spent two probes and retained capacity without serving
a decode operation. The HPACK benchmark reports encoder and decoder churn
separately; three pinned ReleaseFast runs measured 277-282 ns/insert with
reverse indexes and 46-50 ns/insert for the decoder's positional-only table.
Allocation, eviction, clone and failure-path tests verify the no-index
lifecycle while encoder lookup behavior remains unchanged.
HPACK and QPACK now also share one canonical Huffman codec module. HPACK's
encoder writes compressed string bytes directly into its already-reserved
header-block output instead of allocating a temporary encoded slice and then
copying it. A warmed retained-scratch regression uses a failing allocator to
prove compressed never-indexed fields need no transient allocation. Three
pinned ReleaseFast HPACK runs measured 261-265 ns for stateful encode-only,
down from 316-319 ns immediately before this change.
The runtime owning decode path now materializes names and values directly into
one stack-staged byte sequence, then performs exactly two output allocations:
the field descriptors and their shared contiguous string block. It no longer
allocates per Huffman/dynamic field and then clones every field into that final
block. Offset-based plans keep slices valid while scratch grows, and bounded
decode still consumes incremental-indexing fields after an output limit so the
connection table stays synchronized. Three pinned runs measured the new owned
path at 1,246-1,253 ns for this seven-field benchmark.
HTTP/2 receive paths now decode the overwhelmingly common END_HEADERS block
directly from the buffered frame instead of first copying it into a temporary
ArrayList. Fragmented HEADERS and PUSH_PROMISE sequences retain one assembly
buffer per connection because each continuation read invalidates the previous
frame borrow; consecutive fragmented round trips verify stable capacity and
backing storage. A focused single-frame test verifies that this scratch remains
entirely unallocated. The full 1,594-test suite, strict h2spec 147/147 run,
bidirectional Hyper h2c/TLS gate, and h2 Push/1xx gate remain green. Five
CPU-0 runs of the matched h2c matrix measured 9.555-9.920 us for consecutive
empty requests, 10.051-10.498 us for 10-byte requests, 22.744-22.921 us for
100-KiB requests, 25.630-25.815 us per ten-request empty batch, 1.658-1.707 ms
for the ten-stream request-body batch, and 1.685-1.703 ms for the ten-stream
1-MiB response batch. These are current regression ranges; the dated matched
Hyper comparison above remains the cross-stack evidence.
The bidirectional Hyper process gate now exercises that boundary directly over
h2c and TLS. A netz client waits through an idle interval, receives Hyper/h2's
PING ACK, and completes another request on the same connection. In the reverse
direction Hyper enables its actual 25 ms background keep-alive with idle probes
using the harness's Tokio-backed implementation of Hyper's timer interface,
waits 100 ms, and then completes another request through the netz server. This
proves netz services external PINGs rather than relying only on local peers.
The same process gate now runs two URI requests through `http2.client_pool.Pool`
over both h2c and certificate-verified TLS, requires distinct response bodies,
and verifies one idle/total connection afterward while the Hyper process
confirms that both requests arrived on its single accepted connection.
Single-stream cancellation and ordinary GOAWAY now use caller-buffer frame
encoders: the fixed 13-byte RST_STREAM always stays on the stack, and common
GOAWAY debug strings use a bounded 256-byte stack path with an exact heap
fallback only for larger diagnostics. The public helpers retain ArrayList
compatibility while wire-parity and short-buffer tests cover the direct form.
Late DATA, HEADERS, and duplicate RST_STREAM frames for locally reset streams
are ignored through a bounded, configurable `Limits.max_reset_stream_history`
ring with an O(1) membership index. The default retains 64 stream IDs, while
zero disables tolerance; unlike
Rust h2's time-based reset retention this stays deterministic under a blocking
runtime without an always-running timer task. Capacity is reserved before a
RST_STREAM becomes visible, including batch cancellation, so allocation failure
cannot leave wire and local reset state inconsistent.
The remaining fixed control helpers expose the same allocation-free boundary:
PING encodes its complete 17-byte frame and WINDOW_UPDATE its complete 13-byte
frame into exact caller-owned arrays. Their compatibility writers still grow
the destination only once and encode directly into its final storage, while
wire-parity tests and the zero-window-increment rejection cover the new API.
The runtime already wrote these two frame types as a stack header plus borrowed
payload, so it deliberately keeps that scatter/gather path rather than copying
them into a second contiguous buffer. A pinned full h2c benchmark after this
API addition measured 10.120 us for consecutive empty requests, 22.990 us for
100-KiB requests, and 27.482 us per ten-request empty batch; these are a
regression sample, not a claim that this helper-only addition accelerates the
runtime. h2spec strict remains 147/147, and the bidirectional Hyper h2c/TLS
keep-alive, cancellation and GOAWAY gate remains green.

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
   netz/Hyper comparison matrix. **Completed for the primary constrained-window
   shape:** both harnesses now report allocation calls, realloc/remap calls,
   cumulative bytes, live bytes, peak live bytes and common size buckets from
   thread-safe process-wide allocator wrappers. The Hyper wrapper delegates to
   `System` and records requested sizes without recursively allocating;
   `tools/bench_hyper_http2_flow.sh` enables it only when passed `--stats`.
   The netz benchmark reports allocation
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
   Three matched CPU-0 runs of the documented 10-stream/1-MiB/8-KiB-window,
   five-warmup/twenty-iteration shape were repeated on 2026-08-27. Netz took
   7.433-7.458 ms/batch (7.448 ms median) versus Hyper's 10.096-10.126 ms
   (10.122 ms median), a 1.36x median throughput advantage. Both sides verified
   the identical 262,144,000-byte checksum. Netz used exactly 1,606 allocation
   calls, 1,569,363 cumulative allocated bytes and 1,288,070 peak live bytes;
   Hyper used 54,086-54,224 allocation calls, 11,664-11,760 reallocations,
   298,232,879-299,587,537 cumulative allocated bytes and 1,346,882-1,346,885
   peak live bytes. Against the median Hyper run, netz therefore used 97.0%
   fewer allocation calls, 99.5% fewer cumulative requested bytes and 4.4%
   less peak live memory. These process-wide counters include runtime setup and
   warmup in both implementations and are a matched workload result, not a
   universal allocator or RSS claim.
3. Keep the external h2spec gate current. The h2c adapter passes all 147 tests
   in h2spec v2.6.0 strict server mode (`H2SPEC=/tmp/h2spec-download/h2spec zig
   build interop-http2-h2spec -Doptimize=ReleaseFast`, reconfirmed 2026-08-21).
   The gate now supplies `--strict` itself and parses h2spec's summary so an
   empty selection, skipped case, or failed case cannot be mistaken for a
   successful conformance run. This covers the external h2c wire checks but
   does not replace broader HTTP client interoperability evidence. The native
   TLS 1.3 HTTP/2 runtime separately has an end-to-end encrypted request test
   that verifies `h2` ALPN and the transport-derived `https` pseudo-header,
   plus no-common-ALPN rejection and required-client-certificate tests; verified
   peer chains are exposed on accepted server connections, and the vail-backed
   HTTP/2 client retains and exposes the authenticated server chain. Both vail
   TLS endpoint roles expose RFC 8446 exporter keying material for channel
   binding and typed `negotiatedCipherSuite()` /
   `negotiatedAlpn()` / `negotiatedTranscriptHash()` metadata for authentication policy and
   diagnostics. `updateTrafficKeys(request_peer_update)` sends RFC 8446
   KeyUpdate under the current epoch, rotates afterward, transparently handles
   fragmented peer updates, performs requested reciprocal updates, and exposes
   sent/received counters; the encrypted HTTP/2 test exchanges a request after
   both directions rotate. The bidirectional Hyper TLS gate independently uses
   rustls's production `refresh_traffic_keys()` API in each peer direction,
   requires netz to observe/respond exactly once, and continues HTTP/2 traffic
   on the rotated epochs. Passing `--tls` to
   the same h2spec command runs all 147 strict cases through TLS 1.3 and
   negotiated `h2` when h2spec is built with a current Go TLS stack that offers
   an X25519 key share.
   Bidirectional interoperability now has a separate process boundary rather
   than being inferred from those h2spec server-only results:
   `zig build interop-http2-hyper-client -Doptimize=ReleaseFast` builds a
   one-shot server from the audited `~/Work/hyper` checkout and drives it with
   a netz client. Hyper verifies the POST method, query-bearing path, request
   header, body, and request trailer; netz verifies Hyper's 201 status, response
   header, two DATA frames joined into `hyper-response`, and terminal response
   trailer. The same gate then reverses the roles: an audited Hyper client sends
   two DATA frames joined into `hyper-request` plus a terminal trailer to a netz
   server, which verifies the complete request and uses its stateful response
   writer to send two DATA contributions plus a terminal trailer. Hyper verifies
   that response. Both cancellation halves now advertise an 8-KiB stream
   receive window and the standard 65,535-byte connection window, open the
   cancel target and a sibling concurrently, and declare a 128-KiB target
   response. The receiver consumes exactly 8 KiB, proving that the response is
   unfinished and has exhausted its stream credit, then sends
   `RST_STREAM(CANCEL)`. The sender does not release a 16-KiB sibling response
   until it observes that exact cancellation; the sibling then completes on
   the same HTTP/2 connection. Hyper's server body-drop signal verifies the
   netz-client direction, while the netz server verifies Hyper's reset code.
   The netz client additionally discards DATA already in flight for its locally
   reset stream, restoring the shared credit so those bytes cannot be mistaken
   for or starve the concurrent sibling; the callback-error path likewise
   restores the triggering DATA's charged connection credit before
   cancellation. A deterministic buffered-frame regression also forces that
   cleanup WINDOW_UPDATE to fail with a terminal peer-close error after the
   late DATA and sibling response have arrived together. The client ignores
   only `SocketUnconnected`/`ConnectionResetByPeer` in this reset-cleanup path,
   restores the rolled-back local connection credit, and still returns the
   complete sibling response with exact final window accounting; ordinary
   capacity-release write failures remain observable. The gate builds the
   locked Rust harness offline after its
   crates are cached and fails on either process or
   any exact value mismatch. The same command now repeats the complete
   bidirectional request/trailer and concurrent cancellation scenarios over
   TLS 1.3: the netz client validates the fixture certificate and both sides
   require ALPN `h2`. This is direct encrypted Hyper interoperability rather
   than an inference from local TLS tests. The matrix also exercises graceful
   shutdown in both directions. Hyper starts its recommended two-phase GOAWAY
   while stream 7 is active; netz answers the synchronization PING, drains that
   stream through the narrowed boundary, and refuses to open stream 9. On a
   fresh reverse connection, netz sends `GOAWAY(last_stream_id=7, NO_ERROR)`,
   completes stream 7, and Hyper refuses a subsequent request. Both cases run
   over h2c and certificate-verified TLS, so this is peer-visible draining
   evidence rather than inference from local GOAWAY tests.
   `zig build interop-http2-h2-push -Doptimize=ReleaseFast` adds direct
   server-push evidence with Hyper's audited low-level h2 dependency, because
   Hyper's high-level client intentionally sends SETTINGS_ENABLE_PUSH=0. In
   the enabled direction, the h2 server promises stream 2 from request stream
   1; netz validates the complete promised GET pseudo-header set, consumes the
   independent 200 response and exact CSS body, and also completes the parent
   response. In the reverse direction, the h2 client disables push and netz
   must reject `promisePush` before returning the normal 204 parent response.
   Both scenarios run over h2c and certificate-verified TLS. The same gate now
   also exchanges ordered 103 Early Hints and 102 Processing heads before a
   200 response in both directions. Netz exposes borrowed informational-head
   callbacks on aggregate and streaming request APIs, caps each chain with
   `Limits.max_informational_responses`, and applies that bound even to legacy
   skip-only and pushed-response paths. Multiplexed aggregate, body-bearing and
   streaming batches additionally report request index and stream ID, with
   interleaved local tests proving correlation and per-stream bounds. The h2
   client explicitly polls its
   informational queue and checks both statuses; netz checks both statuses and
   their distinct headers.
4. **Completed:** combine the bidirectional process-boundary cancellation
   cases with constrained flow-control windows and concurrent streams. The
   gate described above verifies exact CANCEL codes, target-only termination,
   connection-credit recovery, and sibling completion in both directions. This
   remains a focused loopback interoperability case rather than a
   whole-library superiority claim.
5. RFC 8441 server application frames now submit the stack-resident WebSocket
   header and borrowed application payload through a two-slice HTTP/2 tunnel
   write. The tunnel treats both slices as one flow-controlled byte sequence,
   allowing DATA frame and window boundaries to cross the join without a
   payload-sized concatenation. A constrained 8-KiB stream-window test sends
   more than 16 KiB, forcing repeated WINDOW_UPDATE and client masking cycles,
   and confirms that the H2 WebSocket adapter
   retains no frame scratch after sending in either direction; client masking
   uses a bounded 16-KiB stack buffer. `H2Connection.sendBinaryParts` retains
   one RFC 6455 message across both caller slices, and the underlying tunnel's
   slice writer permits HTTP/2 DATA frames to cross either logical join. The
   existing bidirectional Hyper RFC 8441
   process gate remains the external interoperability check. Five CPU-0 4-KiB
   echo samples after adding H2 two-part writes measured 30.987-32.321
   us/roundtrip (31.394 us mean, 31.072 us median, 1.63% relative standard
   deviation); this overlaps the prior range and is not presented as
   a latency improvement. The full
   1,604-test suite, 147-case h2spec strict gate, and bidirectional Hyper h2c/TLS
   request, cancellation, keep-alive and GOAWAY matrix remain green.
   Compressed fragmented RFC 8441 messages now use the same tunnel sequence:
   server fragments remain borrowed, common client batches use fixed stack
   storage, and oversized client fragments stream through bounded masking
   chunks. This removes the H2 adapter's final payload-sized send-frame buffer
   without giving up the common 16-frame coalescing behavior. Five CPU-0 runs
   of that 4-KiB/16-fragment compressed workload measured 37.032-38.500
   us/roundtrip (37.651 us mean, 37.372 us median, 1.55% relative standard
   deviation). A 64-KiB bidirectional regression forces the oversized masking
   fallback and disables the connection allocator after warmup on both peers.
   Uncompressed fragmentation uses the same bounded batching strategy, with a
   40-KiB bidirectional regression crossing the masking boundary.
