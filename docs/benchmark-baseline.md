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
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
taskset -c 0 zig build bench-mqtt-tls -Doptimize=ReleaseFast
```

Two historical 2026-09-04 post-close-semantics MQTT-over-TLS regression samples
used the former `std.Io.Threaded` harness with one
persistent native TLS 1.3 connection, 100 warmup exchanges, and 2,000 measured
1-KiB QoS 1 publish/PUBACK round trips. They measured 11.693-11.812 us per
operation and 84,658-85,518 operations/s on CPU 0. This is an internal hot-path
guard for the shared vail record stream, not a cross-library performance claim.

## Current netz results

### HTTP/1 persistent 16-request pipeline

The current HTTP/1 parse, pipeline, and streaming-body executables obtain
`std.Io` from `netz.runtime.Backend` and print `io backend: zio-std-io`. The
pipeline and body benchmarks schedule their local server through
`std.Io.async`; the body's protocol counting allocator remains separate from
the runtime allocator. `zig build bench-http1-hyper -Doptimize=ReleaseFast`
builds the locked local Hyper fixture once, then runs fixed binaries on one CPU
in an odd ABBA-order sample set. Its strict checker requires the complete
workload, derived timing, endpoint runtime identities, fixed Hyper revision,
Cargo.lock hash, and executable hashes before reporting medians.

The 2026-09-15 five-sample run on an NVIDIA Jetson AGX Thor (`aarch64`, Linux
6.8.12-1021-tegra, CPU 0, Zig 0.16.0, Rust 1.98.0, Hyper
`084473f728f9d07b3be5845475aa2f62ed9ff579`) measured:

```text
16-request pipeline:
  netz/zio:        749-799 ns/request, median 761 ns
  Hyper/Tokio:     842-854 ns/request, median 851 ns
  median speedup:  1.118x

1-MiB fixed body in each direction:
  netz/zio:        722.152-747.392 us/round-trip, median 740.191 us
  Hyper/Tokio:     768.572-783.444 us/round-trip, median 779.315 us
  median speedup:  1.053x

1-MiB chunked body in each direction, 64 x 16 KiB:
  netz/zio:        724.570-754.458 us/round-trip, median 748.436 us
  Hyper/Tokio:     951.686-967.723 us/round-trip, median 953.148 us
  median speedup:  1.274x
```

The pipeline netz/Hyper binary SHA-256 values were respectively
`0a443139e7636c667406d60b6bd137617900582cc361fe0abab0f53e18a8390e` and
`0b0e23887ff763c443087df4b34733aaeb2ca5adf0f72b0b1d0d90a26a937989`;
the body binaries were
`7e4f46e0ce2996878520f7c7a2e81c9c5818e99dabac1fa096c3cf47991a2c11` and
`9dd31d895c446f17dba2f2c449113be37bcc95bfb1f2cd18e5a40c83f15af4f4`.
The fixture lockfile hash was
`db336fa1c2df67362ee6cc7209176e082e14b7ae428cbc32ebb0c552d4936b9d`.
These are focused same-application-shape loopback results, not a whole-library
superiority claim.

The older results in the following historical subsection predate the zio
migration and remain `std.Io.Threaded` evidence only.

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

In that historical Threaded capture, netz was about **1.11-1.22x faster** for
this same-host, same-shape sample. The
runtime path uses caller-owned head/header/body output arrays, borrowed receive
storage, one prefix compaction per pipeline, persistent write scratch,
header/body vectored writes and one transactional response-batch flush. This is
a focused HTTP/1 pipeline result, not a whole-library superiority claim. The
implementation audit and remaining HTTP/1/HTTP/2 evidence are in
`docs/hyper_parity.md`.

The pipeline runner now accepts
`--write-strategy=auto|vectored|flatten` and reports the selected policy, so
the same payload/checksum can compare the connection-level I/O shape without
changing the benchmark. A 2026-09-09 unpinned smoke under unrelated host load
completed all 32,000 requests with identical checksums. For 13-byte responses,
auto/vectored/flatten measured 1374/1429/1342 ns/request; for sixteen 64-KiB
responses per batch they measured 10661/10011/13941 ns/request. These single
samples are functional and directional evidence only, not replacements for the
isolated five-sample ranges above. They support retaining the existing auto
choice: coalesce small pipelines and borrow large bodies through vectored I/O.

The automatic-Date path was recaptured on 2026-09-04 with three CPU-0 runs:
netz measured 0.733-0.750 us/request (11.73-12.00 us/batch), while Hyper
measured 0.844-0.846 us/request (13.50-13.54 us/batch).
The standalone HTTP/1 parser benchmark now accepts
`--scenario=borrowed|owned|owned_checked` and `--iterations=N`, allowing CPU
profiles to isolate borrowed parsing from ownership costs. A 20-million-parse
profile attributed 22.6% of user samples to `parseHeaderLine` and 18.1% to
scalar searches. Strict header parsing now validates the field-name token while
locating its colon, and validates the value while tracking its trailing-OWS
boundary; a 256-entry token table follows picohttpparser's classification
strategy. Five CPU-0 5-million-parse samples improved from 333-335 ns/op to
280-282 ns/op (334 to 282 ns median, 15.6%). Five ordinary 100,000-iteration
runs measured 283-288 ns borrowed, 828-838 ns owned, and 881-886 ns for
owned plus explicit Host validation.
The next profile identified duplicate request-framing scans: the borrowed head
path parsed `Content-Length` once to choose framing and again to return the
length, while TE+CL handling separately rescanned field names to choose the
must-close safeguard. One internal scan now returns framing, parsed length and
the smuggling-safe close decision together. Five CPU-0 5-million-parse runs
measured 264-265 ns/op, reducing the isolated median from 282 to 264 ns (6.4%)
and from the pre-pass 334 to 264 ns (21.0%). A dedicated regression preserves
the existing rule that valid final `chunked` overrides even malformed
Content-Length syntax while forcing connection close.
The following profile placed ordinary Host validation at about 10% of sampled
cycles. It previously scanned a typical `example.com` repeatedly for a URI
marker, forbidden delimiters, brackets and a port colon. One structural pass
now performs those checks together while preserving bracketed IPv6 and strict
decimal-port validation. Five CPU-0 5-million-parse samples measured
237-239 ns/op, improving the isolated median from 264 to 238 ns (9.8%) and from
the pre-pass 334 to 238 ns (28.7%). Five default-shape runs measured
240-242 ns borrowed, 795-797 ns owned and 818-822 ns owned plus explicit Host
validation. Existing Host regressions cover URI/userinfo/list delimiters,
queries/fragments, unbracketed IPv6, mixed brackets and port overflow.
Finally, explicitly inlining the now compact `parseHeaderLine` hot helper
removed its call boundary in both borrowed and owned loops. Five CPU-0
5-million-parse samples measured 231-234 ns/op (231 ns median), another 2.9%
below 238 ns. Five default-shape runs measured 236-241 ns borrowed,
766-769 ns owned and 791-796 ns owned plus Host validation. Two attempted
alternatives were rejected by A/B evidence: scalar CRLF/header fusion regressed
to 259-261 ns/op, and vectorized colon search followed by token validation
regressed to 253-257 ns/op.
The ordinary no-obs-fold owned parser now retains up to sixteen validated
header descriptors on the stack during its counting pass. Common requests copy
those descriptors into the one exact result allocation instead of parsing and
validating every line a second time; larger sets preserve the prior exact-count
allocation and second fill pass, so no geometric attacker-controlled scratch is
introduced. Seven CPU-0, order-alternated fixed-binary pairs at
`zig-out/http1-header-single-pass-ab` (24,775,320 bytes; aggregate file-hash
digest `3720f5740a69e13253d4774ebe2bb6d533f3af78ffe58ac077edfa6b3136b061`)
used parser binaries `3b0e2e34`/`c2a452da`. The five-million-parse owned
scenario improved in all seven pairs from 920 ns/op median (920-928) to
580 ns/op (580-582), a 37.0% reduction. The separate 16-request persistent
pipeline control used binaries `e8d53279`/`ea584e02` and moved from 794 to
803 ns/request by paired medians (+1.1%) with overlapping ranges; that runtime
uses its caller-buffer borrowed parser, so no pipeline improvement is claimed.
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

In that historical Threaded capture, netz was 1.07-1.09x faster in the fixed
workload and 1.45-1.47x faster in the chunked workload. The reusable
implementation changes are TCP_NODELAY, direct
socket-to-callback fixed-body delivery, retained chunk/vector scratch, batched
`writeChunks`, wide POSIX writev submission, and 64-KiB chunked read-ahead into
the persistent connection buffer. Read-ahead can span several chunk boundaries
or a pipelined suffix, but callbacks still receive one wire chunk at a time and
the suffix remains buffered for the next message. These are focused workload
results, not a whole-library superiority claim.

### HTTP/2 persistent consecutive and parallel round trips

The current executable obtains `std.Io` from the zio backend and schedules its
local server through `std.Io.async`; it prints `io backend: zio-std-io`. The
numeric results in this section were captured before that migration and remain
historical `std.Io.Threaded` evidence until a fixed-binary zio run is recorded.

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
The single-stream streaming-request reader now borrows its initial wire frame
under the same pending-owned fallback. The 100-KiB POST scenario removed one
26-byte HEADERS allocation per request, reducing the warmed 2,000-request run
from 6,020 to 4,020 allocation calls and from 1,902,112 to 1,850,112 cumulative
requested bytes. Its 23.533-us sample stays within the established range, so
only the allocation/copy reduction is claimed.

The h2c harness also contains an internal A/B for the combined body-bearing
request and large-response case. Both modes send ten concurrent 1-MiB POST
bodies and receive ten 1-MiB responses with identical frame scheduling; only
the client response ownership policy changes:

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_parallel_x10_duplex_1mb_aggregate --stats
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_parallel_x10_duplex_1mb_streaming --stats
```

Three alternating CPU-0 paired runs with exact 1-MiB bodies measured
6.744-7.020 ms/batch for aggregation and 3.422-3.540 ms/batch for callback
streaming, a 1.91-1.97x latency advantage for this workload. Aggregation made
166 measured allocations totaling 52,488,942 bytes and peaked at 10,640,263
live bytes in every run. Streaming
made 116 allocations totaling 60,142 bytes and peaked at 155,557 live bytes.
The exact-size report attributes the material difference to fifty eliminated
1,048,576-byte response-body allocations (ten responses across five measured
batches). This is an internal API-shape comparison rather than an external-
library superiority claim.

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

This benchmark now uses the same zio-backed `std.Io` boundary and schedules
its server with `std.Io.async`. The HPACK microbenchmark also obtains its clock
from zio. Existing numeric results in this HTTP/2 section predate the migration
and are retained as historical `std.Io.Threaded` baselines.

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

The cross-client cancellation benchmark fixes the server to Hyper and is
reproducible with:

```sh
zig build bench-http2-cancel-hyper -Doptimize=ReleaseFast
```

Each measured batch starts a 128-KiB flow-blocked response and a concurrent
16-KiB sibling on one persistent connection. Both clients consume exactly the
8-KiB stream window and cancel the target; the Hyper server gates the sibling
on its incomplete response body being dropped after stream cancellation, and a
final request proves connection reuse. The existing reverse-direction
interoperability gate separately decodes and requires `RST_STREAM(CANCEL)`.
Five samples alternate netz and Hyper client order across dedicated CPUs, with
twenty warmups and 1,000 measured batches per process. Repeated long runs gave
netz median times of 132.2-153.6 us/batch and Hyper medians of
143.3-200.2 us/batch, a 1.044-1.433x advantage for netz. Short 100-batch
exploratory medians varied from a 0.939x regression to a 1.229x advantage and
are not used for the performance claim. All long runs reported the expected
24,576,000-byte checksum, 1,020 server-observed cancellations, and 1,020
sibling completions per sample. The netz explicit allocator peak was
203,352-203,385 bytes; Hyper's process-wide Rust requested-byte peak was
144,750 bytes. These scopes differ, so no allocator ratio is claimed. BusyBox
`time` reported client-process MaxRSS medians of 11,264-12,288 KiB for netz and
11,264 KiB for Hyper, so no RSS advantage is claimed. A strict checker verifies
the workload, timing arithmetic, server observations, memory arithmetic, RSS
source, binary hashes, pinned Cargo lock and Hyper revision. This is a focused
same-server cancellation/recovery result, not a general HTTP/2 throughput
claim.

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
QPACK owned field-section decode now co-locates its `HeaderField` descriptors and
contiguous name/value bytes in one aligned allocation, while the deallocator
still accepts the prior separate `block_storage` layout used by other callers.
Both literal and dynamic decoder tests assert one final allocation, pointer
layout and exhaustive allocation-failure cleanup. Five CPU-0 dynamic-decode
runs measured 751-762 ns/block in four stable samples with one 835-ns outlier,
versus the preceding 835-857 ns range (838-ns median).
The follow-up owned builder retains encoded string plans rather than first
decoding into a 16-KiB stack-backed staging list and copying those bytes again
at finalization. It now decodes or copies each string directly into the final
co-located allocation. Three interleaved 1,000,000-iteration CPU-0 runs measured
638-653 ns/block versus 759-773 ns/block at the preceding commit (1.16-1.21x
faster). A 40-field mixed Huffman/literal/dynamic allocation-failure test covers
the heap plan fallback and final-allocation cleanup.
Pre-sizing the stack-fallback plan list to its 32-field inline budget removes
the geometric grow/remap sequence from ordinary owned sections while retaining
the same heap migration above that bound. Four stable interleaved CPU-0 runs
measured 590-599 ns/block versus 634-647 ns/block at the direct-to-final commit
(1.06-1.10x faster); one cold 921-ns baseline outlier was excluded.

The same executable now includes a 512-field/512-unique-reference section to
expose reference-set bookkeeping that the ordinary 32-field block cannot.
Three CPU-14 baseline runs took 50.50-65.60 us/block (98-128 ns/field). A
sort/compact prototype reduced that large shape to 18.70-18.79 us but enlarged
the shared encoder enough to regress the ordinary block from 917 ns to about
1,247 ns, so the implementation was rejected and fully rolled back. The
accepted large-only hash-membership path now preserves first-reference order
without rescanning the growing reference list. Five CPU-0 samples measured
14.10-14.59 us/block (27-28 ns/field), down from the immediately preceding
49.10-49.45 us/block CPU-0 baseline, or 3.37-3.51x faster. The same runs kept
the ordinary 32-field block at 821-827 ns/block after isolating hash-backed
emission from its linear stack path. These are internal before/after results,
not an equal-wire cross-library comparison.
The follow-up replaces that large-only hash membership with a bitmap relative
to the dynamic table's oldest live absolute index. Its space is bounded by the
current table entry count rather than the lifetime insertion count. Five CPU-0
samples measured 11.02-11.28 us/block (21-22 ns/field), another 1.24-1.32x
improvement over the hash version and 4.35-4.49x over the original linear
deduplication baseline; the 32-field block remained at 804-826 ns/block.
Use `--scenario=encode|large|churn|decode` and `--iterations=N` to isolate one
phase for profiling; omitting both options retains the combined default run.
In the isolated 512-reference scenario, combining the already-computed name and
value digests directly for the exact-match index removed a redundant 16-byte
Wyhash pass. Three interleaved CPU-0 comparisons measured 9.83-9.99 us/block
versus 10.98-11.19 us/block at the preceding bitmap commit (1.10-1.14x faster).
The index still stores both digests and verifies the original strings after a
hit; a forced combined-hash collision test covers key separation.
For large sections in which every field is an exact dynamic match, the encoder
now computes the final indexed representation length and reserves output plus
reference capacity once before emission. Five CPU-0 samples measured
9.40-9.54 us/block (18 ns/field), versus 9.82-9.87 us/block in three
interleaved runs at the preceding prehashed-index commit (1.03-1.05x faster).
Mixed static, name-only, literal, and never-indexed sections retain the general
encoder; focused round-trip and second-allocation failure tests cover both
branches and the pre-prefix rollback boundary.
Dynamic lookup now checks the newest same-name entry before computing the value
digest or probing the exact index. When that entry is also an exact match, as in
both populated encode scenarios, the second hash and map lookup disappear; an
older exact value still takes precedence over a newer name-only match. Three
interleaved CPU-0 large-section comparisons measured 9.22-9.33 us/block versus
9.45-9.57 us/block at the preceding reservation commit (1.01-1.04x faster).
Two 1,000,000-iteration 32-field comparisons measured 711-715 ns/block versus
733-736 ns/block.

### QUIC prepared packet protection

The maintained short-packet executable obtains its monotonic clock from
zio-backed `std.Io` and reports `io backend: zio-std-io`. Numeric results in
this subsection predate that migration unless explicitly labeled otherwise and
remain historical Threaded evidence; the backend change itself is not a crypto
throughput claim.

Every AES connection keeps an AES header-protection key schedule for each
current send/receive key generation. Builds linked to Vail's optional
AWS-LC-compatible backend additionally keep an initialized AES-GCM context.
This matches the connection-owned packet/header key design in Quinn, quiche,
and s2n-quic: key setup is paid when the connection is created or its key phase
changes rather than once per packet. AES-128-GCM and AES-256-GCM use the
prepared path; ChaCha20 and SM4 retain the allocation-free Zig path.

The short-packet benchmark reports value-key and prepared-key seal/open paths
separately. It distinguishes always-available prepared connection keys from
the optional prepared AEAD context. To reproduce with an AWS-LC checkout whose
static library has been built under `build/crypto`, run:

```sh
taskset -c 0 zig build bench-quic-short-packet -Doptimize=ReleaseFast \
  -Daws-lc-path=/path/to/aws-lc -Daws-lc-link=true
```

Five CPU-0 runs on 2026-09-12 used the BoringSSL-compatible static crypto
library already built by the local tquic checkout. Medians are reported below.
Every operation includes short-header construction/removal and header
protection, so these figures measure the complete protected short-packet
primitive rather than AEAD alone.

| 85-byte short packet | Value-key median | Prepared-key median | Throughput gain |
| --- | ---: | ---: | ---: |
| AES-128-GCM seal | 545 ns | 206 ns | 2.64x |
| AES-128-GCM open | 544 ns | 251 ns | 2.17x |
| AES-256-GCM seal | 558 ns | 225 ns | 2.48x |
| AES-256-GCM open | 564 ns | 272 ns | 2.07x |

The same benchmark showed no material prepared-wrapper change for ChaCha20
(0.99-1.00x). Suite-wide equivalence tests cover seal, in-place seal, phase
mismatch preservation, open, and key replacement. A connection-level test
proves that AES connections select prepared send/receive keys and continue
exchanging STREAM data across a key update, while ChaCha20 and SM4 remain on
their existing paths.

On 2026-09-18, seven CPU-0 runs of one fixed default-backend binary (without
AWS-LC) measured AES-128 prepared seal at 244-250 ns versus 292-381 ns for the
value-key path (1.19-1.54x), and prepared open at 302-303 ns versus 328-332 ns
(1.08-1.09x). AES-256 prepared seal measured 269-271 ns versus 324-346 ns
(1.19-1.28x), and prepared open measured 380 ns versus 395 ns (1.03-1.04x).
The pure-Zig prepared path calls the same AEAD primitive directly and caches
only the AES header schedule; the ChaCha control remained 0.99-1.02x. Each AES
connection consequently owns two 432-byte prepared-key objects in one
allocation. ChaCha20 and SM4 connections retain no prepared-key allocation.

Prepared header-protection state now stores one tagged AES-128 or AES-256 key
schedule instead of two mutually exclusive optional schedules. This follows
the suite-specific header-key ownership in quiche/tquic and reduces
`PreparedPacketProtectionKeys` from 1,792 to 1,600 bytes (10.7%). A live AES
QUIC connection owns one send and one receive object, so its fixed prepared-key
footprint falls by 384 bytes without changing allocation count. Tests compare
all four traffic suites against the value-key path and exercise replacement
across AES-128, AES-256, and ChaCha20 tags. Seven CPU-0, fixed-binary,
order-alternated 100,000-operation pairs kept AES-128 prepared seal/open at
205-225/251-257 ns and AES-256 at 224-242/269-273 ns on the candidate; the
corresponding baseline ranges were 205-210/251-256 and
225-228/271-275 ns. These overlap and are treated as throughput-neutral. Seven
matching real-handshake, four-stream, 16-MiB-upload pairs completed every
three-iteration arm with 50,331,648 bytes and status total 2,400. Median
throughput moved from 162.15 to 162.32 MiB/s with 4/7 candidate wins, also
noise-level; the retained benefit is the deterministic prepared-key memory
reduction.

Connection ownership now groups prepared AES send and receive keys into one
stable pair allocation. Direct preconfigured connections with AES in only one
direction retain a single-object allocation, while ChaCha20/SM4 pairs allocate
none; this keeps the public mixed-suite configuration compatible. A
linked-backend 100-handshake allocator run fell
from 7,901 to 7,701 allocations, exactly two fewer allocations per benchmark
round because each round constructs a client and server connection. Requested
bytes were effectively unchanged (7,693,101 to 7,692,942) and peak live bytes
remained 58,579. Seven CPU-0 fixed-binary, alternating-order 100-handshake
pairs were timing-neutral: median connection rate moved from 1,036.0 to
1,033.7/s (-0.2%) and median P50 from 901,089 to 904,134 ns (+0.3%). The
ownership policy and allocation-count regression live in
`src/quic/one_rtt/prepared_keys.zig`.
With Vail `b6dd7b6` additionally replacing its two mutually exclusive AES-GCM
context slots with one suite-selected context, each netz prepared object is now
1,008 bytes and the pair allocation is 2,016 bytes. The same 100-handshake
current-stack run retained 7,701 allocations while total requested bytes fell
to 7,456,115 and peak live bytes to 56,211. Vail's independent seven-pair
traffic-crypto benchmark was timing-neutral, so this follow-up is also treated
as an ownership/memory improvement rather than a throughput claim. The
connection set also caches direct send/receive pointers next to its cold
ownership tag, avoiding a union switch in every packet operation. Against a
fixed binary with the same Vail state and pair allocation but tagged accessors,
seven CPU-0 order-alternated H3 pairs moved the four-stream 16-MiB upload
median from 160.63 to 163.40 MiB/s (+1.7%, 6/7 wins). Every three-iteration arm
verified 50,331,648 bytes and status total 2,400; this is a small
workload-specific result, not a general throughput claim.

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
Recovery payload emission now also consumes the classification result from
that validation pass. When every encoded payload byte is retransmittable it
writes all frames directly, while mixed STREAM/DATAGRAM and ACK payloads keep
the selective path. The classifier itself now handles each frame tag with one
switch instead of three. In the final 50,000-iteration CPU-0 profile of the
four-STREAM-descriptor shape, the former standalone
`frame_traits.classify` hotspot (9.26% before) disappeared from the reported
hot list; the remaining aggregate `Traits.observe` entry accounted for 2.09%
of sampled user cycles. A label-parsed rerun used the exact cached pre-change
binary and a freshly built final binary, pinned both to CPU 0, performed 1,000
warmups per invocation, and alternated execution order across five
50,000-iteration pairs. It moved the sequential median from 114.635 to 111.895
us/batch (2.4% lower, final faster in 5/5 pairs) and the batch median from
101.473 to 98.525 us/batch (2.9% lower, final faster in 4/5 pairs). One baseline
batch sample was a 116.687-us high tail and one final batch pair was 0.36%
slower, so the medians are retained without an all-pairs claim. Direct batch
and single-packet mixed-DATAGRAM tests verify that unreliable bytes are still
absent from recovery. The benchmark accepts `--warmup=N` and `--iterations=N`
so longer profiles do not require a source edit. It now also accepts
`--scenario=datagram` and `--datagram-payload-bytes=1..1024` to isolate the
public DATAGRAM batch sender. That mode compares 32 sequential logical payload
sends against one packed batch and reports both logical payloads and actual
QUIC packet numbers. On the published `8acb1db8` baseline, a CPU-0 256-byte,
1,000-iteration run measured 102.619 us/batch (3,206 ns/payload, 32,000
packets) sequentially and 20.950 us/batch (654 ns/payload, 8,000 packets)
packed, a 4.89x relative payload-rate gain. This is a sender-only local
microbenchmark and is the fixed baseline for the next pure-DATAGRAM
bookkeeping optimization; it is not a cross-stack claim.

The follow-up specializes the shared batch state machine at compile time for
the public pure-DATAGRAM path. It keeps the same congestion, pacing, ECN,
anti-amplification, sent-packet, key-update, nonce, and socket-prefix commit
logic, while skipping constant frame-trait classification, STREAM credit
planning, empty recovery-payload tracking, and their rollback scans. The
generic STREAM/mixed-frame batch path is unchanged. Fixed ReleaseFast binaries
(`d2014ce1750b4668bc633fea8204cc18ea2e639df0cf47668b99315ab1e60026`
baseline, `8f052801cbeb7fc319556c3dd866ea0a3a34de65aefee089bd25d91e444ac1b1`
candidate) were pinned to CPU 0 and alternated by pair:

| DATAGRAM payload | Pairs | Baseline packed median | Specialized median | Reduction | Pair wins |
|---:|---:|---:|---:|---:|---:|
| 32 B | 5 | 18.733 us/batch | 5.651 us/batch | 69.8% | 5/5 |
| 256 B | 7 | 20.907 us/batch | 16.766 us/batch | 19.8% | 7/7 |
| 1024 B | 5 | 60.396 us/batch | 55.737 us/batch | 7.7% | 5/5 |

Each invocation used 100 warmups and 20,000 measured 32-payload batches. A
five-pair STREAM-batch control was timing-neutral amid a host-speed shift
(165.471 versus 166.287 us/batch medians with overlapping samples), as expected
because it still instantiates the generic path. This isolates the improvement
to pure DATAGRAM bookkeeping; it is not an end-to-end result.
### Raw QUIC DATAGRAM latency against Quinn

The native Quinn RFC 9221 fixture now also supports a strict raw DATAGRAM
ping-pong benchmark. It runs four role pairs so each client implementation is
measured once against a fixed Quinn server and once against a fixed netz
server. Every run uses a fresh certificate-verified QUIC v1 connection, a
1200-byte steady-state MTU, disabled PMTU discovery, a 32-byte payload, one
outstanding DATAGRAM, 200 warmups, and 5,000 measured post-handshake RTTs.
The runner pins client/server to CPUs 0/1, hashes all three ReleaseFast
binaries and the Quinn lockfile, requires five samples, and alternates A/B then
B/A order. A strict Python verifier reconstructs all 5,200 payloads and their
checksum, checks p50/p90/p99/p99.9 ordering, config/result/server-completion
records, negotiated limits, control-stream FINs, and application close 59.

The 2026-09-16 fixed-binary run reported:

| Fixed server | Client | p50 median (us) | p50 range (us) | p99 median (us) | p99.9 median (us) |
|---|---|---:|---:|---:|---:|
| Quinn | netz | 45.296 | 44.769-45.750 | 61.963 | 70.537 |
| Quinn | Quinn | 50.546 | 49.399-53.529 | 66.879 | 75.649 |
| netz | netz | 47.315 | 46.649-48.194 | 62.426 | 85.825 |
| netz | Quinn | 44.288 | 42.935-44.695 | 65.602 | 73.112 |

Against the fixed Quinn server, netz's median p50 was 11.6% lower (1.116x).
Against the fixed netz server, netz's median p50 was 6.4% higher (0.936x).
The direction changes with the fixed peer, so this is explicitly
`same-application-shape` evidence and does not support a universal latency or
throughput claim. The command is
`zig build bench-quic-datagram-quinn -Doptimize=ReleaseFast -- --samples=5
--warmup=200 --iterations=5000`.

The same harness now accepts `--window=1..64`. A window sends all
sequence-tagged payloads before receiving its complete echo set, accepts
arrival reordering, and rejects duplicates, omissions, or out-of-window
sequences. The verifier additionally binds warmup, iterations, payload size,
window, total logical DATAGRAMs, bytes, checksum, control FIN, and close into
the result schema. For windowed runs, netz uses automatic GSO when available
and caller-buffer `recvmmsg`; Quinn retains its runtime-selected batching.
Packetization remains implementation-specific, so these results are
`same-application-shape`, not equal-wire.

A 2026-09-17 fixed-binary CPU-0/client, CPU-1/server matrix used five ABBA
samples, 50 warmups, 500 measured windows, and window 16. The same netz
client/server and Quinn binary hashes were retained across all three payload
sizes. Netz greedily packs multiple DATAGRAM frames into one QUIC packet up to
the 1200-byte path and configured frame-count bounds, matching the strategy in
the audited Quinn and quiche implementations; the logical payload prefix
remains exact if a socket accepts only a packet prefix.

| Payload | Fixed server | netz p50 median/range (us) | Quinn p50 median/range (us) | netz/Quinn speed |
|---:|---|---:|---:|---:|
| 32 B | Quinn | 54.148 / 53.713–55.241 | 50.927 / 47.685–52.778 | 0.941x |
| 32 B | netz | 60.954 / 59.676–61.363 | 53.639 / 53.390–55.834 | 0.880x |
| 256 B | Quinn | 97.296 / 94.371–97.861 | 83.890 / 78.890–85.103 | 0.862x |
| 256 B | netz | 113.417 / 112.241–114.307 | 100.371 / 96.732–108.084 | 0.885x |
| 1024 B | Quinn | 195.196 / 194.020–196.622 | 156.511 / 142.825–160.640 | 0.802x |
| 1024 B | netz | 256.197 / 255.669–260.493 | 202.741 / 200.918–208.289 | 0.791x |

The 32-byte result is near parity, with Quinn ahead by 6.3% against its own
server and 13.6% against the fixed netz server. Larger payloads still favor
Quinn by roughly 12–21%, leaving a
concrete packet-protection/event-loop optimization target rather than a broad
performance-win claim. Tests independently prove three small payloads share
one packet, five 500-byte payloads map to three packets, a one-packet partial
socket send commits exactly two logical payloads, and packet-number exhaustion
is rejected before emission. Earlier diagnostic runs without packing are not
treated as a baseline because they were not interleaved against the final
binary.
The fixed final hashes were
`6b5f21da81827e8ad08f36163e5558cf93cf6e37585f3e22af0f5605ac00f5cc`
for the netz client,
`d4b94844aa581b82965acfbd7b2d626f5a3c5f84819bf0d47976e9e7c3d2c1e0`
for the netz server, and
`e3aac9cece02e028b5909e869c2fd86ed249174c21e2b79907460f0a70f45215`
for the Quinn fixture.

After the pure-DATAGRAM specialization, the final same-shape window matrix used
netz client/server hashes
`64ba9891a367464057364c2feae3e3ca476018c1b748594074d7d5ab9be2c9b6` /
`52081c6bde32f192f509a19886f0b89cbf2f236b7827e6b2952094e96accf716`
and the same Quinn binary. Its p50 medians were:

| Payload | Fixed server | netz p50 (us) | Quinn p50 (us) | netz/Quinn speed |
|---:|---|---:|---:|---:|
| 32 B | Quinn | 56.556 | 62.472 | 1.105x |
| 32 B | netz | 50.806 | 56.742 | 1.117x |
| 256 B | Quinn | 88.324 | 85.268 | 0.965x |
| 256 B | netz | 95.714 | 91.677 | 0.958x |
| 1024 B | Quinn | 185.723 | 164.204 | 0.884x |
| 1024 B | netz | 229.825 | 188.788 | 0.821x |

Thus the 32-byte window workload now favors netz in both fixed-server
comparisons. The 256-byte cases are within 5%; the 1024-byte cases still favor
Quinn, leaving large-payload protection and event-loop work as the next target.
These remain implementation-packetized, same-application-shape comparisons.

The bounded QUIC DATAGRAM receive queue now lives in
`one_rtt/datagram_queue.zig`. Its first successful admission reserves exactly
the configured ring bound, so later enqueue/overwrite operations allocate
nothing and retain no geometric capacity beyond policy. Tests exercise
wrap-around removal by packet number, stable survivor order, capacity-one
replacement, caller ownership after OOM, and newest-data retention. The public
queue/drop counters and packet-routing API are unchanged.
The queue now additionally retains a capacity-bounded pool of exact-size
payload allocations after application pops. Repeated fixed-size DATAGRAM
bursts therefore allocate the ring and first full window once, then reuse that
storage; different sizes replace cached entries safely. Focused tests prove a
full warmed burst succeeds under a fail-first allocator, preserve
consume-on-small-buffer behavior and partial batch progress, and retain
drop-oldest accounting. The earlier single-slot step's fixed-binary
CPU-0/client, CPU-1/Quinn-server A/B used
five 200-warmup/5,000-RTT pairs with alternating order. Median p50 moved only
44.666 to 44.416 us (0.6%, 3/5 wins) and p99 61.047 to 60.547 us (0.8%). The
reverse fixed-Quinn-client/netz-server comparison moved p50 44.334 to 44.231
us (0.2%, 3/5 wins), with one noisy candidate p99 tail. These timing results
are performance-neutral; the supported improvement is the deterministic
steady-state payload-allocation removal, not a latency claim.
The connection additionally exposes blocking, relative-timeout, and
absolute-deadline caller-buffer DATAGRAM receive APIs, including up-to-64-item
batch forms with exact partial-progress counts. Existing queued data keeps FIFO
priority; otherwise fitting DATAGRAMs are copied directly from authenticated
frames into caller storage. Non-GRO endpoints drain ready UDP messages through
one backend receive and one cumulative ACK decision; GRO endpoints consume the
existing shared-segment view. Tests cover single and multi-frame delivery,
GRO segments, short-buffer consumption/error, zero timeout, empty/oversized
batches, and disabled negotiation. The raw Quinn matrix now uses this path.
An order-balanced fixed-binary A/B used five 200-warmup/5,000-RTT pairs per
direction. Against the fixed Quinn server, the client p50 median moved from
44.250 to 43.769 us (1.1% lower, candidate faster in 4/5 pairs). Against the
fixed Quinn client, the netz server p50 median moved from 44.009 to 43.205 us
(1.8% lower, candidate faster in 4/5 pairs). The p99 samples were noisy and
included a candidate high tail, so this is a small workload-specific p50
improvement rather than a tail-latency or general QUIC performance claim.
Single DATAGRAM sends now also append a pending delayed ACK when both frames
fit the path packet. This matches the unified packet builders in Quinn, quiche,
and s2n-quic and avoids a separate ACK packet in request/response workloads. A
full-size DATAGRAM that cannot fit the ACK falls back to the original send and
leaves the ACK scheduled; validation, allocation, anti-amplification,
congestion, and pacing failures before socket submission have the same safe
fallback. Real-UDP tests verify the combined frame order, exact ACK range, one
socket-visible datagram, and the full-size fallback.

The fixed baseline binaries for this step were SHA-256
`2ba8edf58157f4fa301c40f695cdf275feca5ab72e787f5ab7f1457687db69fa`
(client) and
`af97a63417c75c5f44d225a5f32f7d50cb9c65e1254578fe80fab94d63dbf017`
(server); the final binaries were
`024bd317fe37fd8ae9c92010a3eaf6cf24101cbe778ab7345e2af170e8e73883`
and `244bfb698a7b5ef5661bdb149aed4a2746210a69ff8fe77017e9adb2ecb9398a`.
Five order-alternated 200-warmup/5,000-RTT pairs on CPUs 0/1 moved the netz
client p50 against a fixed Quinn server from 43.556 to 41.787 us (4.1% lower,
5/5 wins), and the netz server p50 against a fixed Quinn client from 43.954 to
42.649 us (3.0% lower, 5/5 wins). Median p99 moved from 60.555 to 57.278 us
and 63.435 to 61.454 us respectively, with 5/5 wins in both directions; the
ranges overlap, so these remain workload-specific latency results rather than
a broad tail-latency claim.
The resulting fixed-binary four-role matrix measured netz at 42.019 us versus
Quinn at 52.166 us p50 with the Quinn server (1.241x), and netz at 35.972 us
versus Quinn at 43.204 us with the netz server (1.201x). The corresponding p99
medians were 57.223 versus 67.834 us and 44.444 versus 60.862 us. Netz leads
both fixed-peer comparisons in this capture, but the benchmark still compares
the same application shape rather than identical executor, syscall, or wire
behavior, so the result remains scoped to this raw one-outstanding DATAGRAM
workload.
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
append uses an implicit all-present dense prefix without allocating bitmap
words; the first gap materializes the packed representation. Overlap checks,
sparse gap filling, cloning, and non-word-aligned prefix compaction then use
that same explicit bit representation.
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

`--frame=stream_gap` keeps the same 54 packets, payload bytes, packet numbers,
and stream offsets but swaps every adjacent datagram before submission. Each
even-offset packet therefore fills a gap and must advance across the already
buffered odd packet. `ReceivedBitmap.firstUnsetFrom` now skips complete machine
words with `ctz(~word)` instead of testing every bit while retaining the same
packed representation, sparse-tail handling, and conflict checks. Seven
CPU-0, order-alternated 5,000-iteration fixed-binary pairs measured visitor
median 2258 -> 1956 ns/packet (13.4% lower, 7/7 faster) and in-place service
2266 -> 1968 ns/packet (13.2% lower, 7/7 faster). The ordinary ordered STREAM
shape stayed within noise at 1204 -> 1203 ns visitor and 1218 -> 1216 ns
service. A separate seven-pair real TLS/HTTP/3 four-stream upload run verified
80 MiB and status total 4000 per process: mean latency moved 84.746 -> 72.527
ms/iteration and median 82.492 -> 72.817 ms, with every candidate run faster.
This is an internal reordered/gap-fill optimization result, not a cross-stack
or equal-wire comparison.

After the later packed-word, range-precheck, and zio-batching changes, the
implicit dense-prefix representation was evaluated again against fixed
ReleaseFast binaries. Ordered STREAM bytes now advance the bitmap's logical
length without allocating or filling words; the first actual gap materializes
the old packed representation transactionally. Byte-buffer and bitmap
capacity are both reserved before either logical length changes, so allocation
failure preserves the complete dense prefix, byte count, and FIN state. The
implementation and bitmap model tests now live separately in
`src/quic/stream/received_bitmap.zig`, reducing `src/quic/stream.zig` by about
300 lines. This matches the sparse receive-range principle in Quinn, quiche,
and tquic while preserving netz's byte-exact overlap-conflict checks.

The receive benchmark baseline SHA-256 was
`67af2f79d95e1d1f9c88d95e0de7938374c97172887c8d1547c6d1097ca7f32a`
and the final candidate was
`a5874c09951a68de83de4857ce902f159e59450cd896c7be4f2240686c2efeac`.
Seven CPU-0, order-alternated, 5,000-iteration visitor pairs moved ordered
STREAM median from 3001 to 2942 ns/packet (2.0%, 7/7 wins). The reordered
`stream_gap` control moved from 3175 to 3194 ns/packet (-0.6%, 4/7 wins); its
overlapping range is treated as noise rather than a regression claim.

The corresponding real TLS/HTTP/3 four-stream upload used baseline SHA-256
`d97b6c90e6c69ba2289d255f41fb48ecba7ff6a4b104257d559aea738069573a`
and candidate SHA-256
`66413befc85a749a304ad331da41722a959f39b578122bbab09a5d1c80bba455`.
Seven CPU-0, order-alternated runs of three 16-MiB iterations moved median
throughput from 146.90 to 146.31 MiB/s (-0.4%, 3/7 wins), which is noise-level.
Seven matching allocator pairs had medians of 698 to 658 calls (5.7%) and 151
to 119 exact 136-byte allocations. The 16-MiB application body dominates byte
totals, so median cumulative allocation and peak changed only 0.041% and
0.005%.
The supported claim is therefore fewer ordered-stream allocations plus a small
isolated receive-path improvement, not higher end-to-end throughput.

HTTP/3 clients previously stored every outstanding request across parallel
stream-ID, index, and semantics arrays plus a hash index, and copied every
method string independently. The lifecycle now owns one stream-ID-keyed map.
Its value stores the response-relevant method classification and Extended
CONNECT bit; the standard GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH
methods are inline tags, while extension methods retain an owned exact string
so send retries cannot alias caller memory. The implementation and its
allocation/failure tests moved to
`src/http3/runtime/stream/lifecycle/client.zig`; server priority and GOAWAY
tracking remain in the parent lifecycle module. This follows Hyper/http's
typed standard-method representation while preserving netz's exact custom-
method retry checks and HEAD/traditional-CONNECT response semantics.

The fixed dense-prefix baseline SHA-256 for the real TLS/HTTP/3 upload was
`66413befc85a749a304ad331da41722a959f39b578122bbab09a5d1c80bba455`;
the final single-map lifecycle candidate was
`be0ee3d3328088c6aa727703dbb94f78767c12be7d05705aece34bf4917c21f2`.
Seven CPU-0, order-alternated runs of three 16-MiB/four-stream iterations moved
median throughput from 144.52 to 145.63 MiB/s (+0.8%, 6/7 wins) and median
latency from 110.752 to 109.647 ms/iteration (1.0% lower). Seven matching
allocator pairs moved the median from 658 to 652 calls; cumulative allocation
and peak were each 120 bytes lower in six of seven candidate runs. One candidate
allocator outlier exercised additional recovery-cache growth, so these results
support the simpler ownership model and removal of routine method copies, not a
broad HTTP/3 throughput claim.

The server side now uses the same single-source-of-truth layout: one
stream-ID-to-priority map replaces the active-request array plus its parallel
stream-ID-to-array-index map. The directly cached lowest active stream ID keeps
the common GOAWAY drain query O(1); only removing that exact lowest stream scans
the remaining map. The implementation and its unordered-insertion, priority,
drain, and allocation-failure tests moved to
`src/http3/runtime/stream/lifecycle/server.zig`. Against client-single-map
baseline SHA-256
`be0ee3d3328088c6aa727703dbb94f78767c12be7d05705aece34bf4917c21f2`,
the final server-single-map binary SHA-256 was
`ad4e9c8ec5e6f62f5737d70fb83a3b894a22686b19ffb13abd7f04bf589e5077`.
Seven CPU-0 order-alternated 16-MiB/four-stream upload pairs were throughput-
neutral: 148.86 versus 148.76 MiB/s medians (-0.07%, 3/7 candidate wins). Seven
allocator pairs moved the median from 652 to 651 calls and reduced cumulative
and peak bytes by 192. This is a structural simplification with a small
deterministic allocation reduction, not a throughput improvement claim.

A follow-up avoids treating every byte inside the allocated receive buffer as
an actual overlap. Before either transactional preflight or committed insert
performs byte-wise duplicate/conflict validation, the packed bitmap now checks
the intersection a machine word at a time. Filling an entirely absent gap can
therefore account the range directly while genuine partial/full retransmissions
retain exact byte comparison and conflict rejection. Five CPU-0, order-
alternated 5,000-iteration fixed-binary pairs measured visitor median
2734 -> 1970 ns/packet and in-place service median 2751 -> 1983 ns/packet
(27.9% lower for both, 5/5 faster). The ordinary ordered STREAM controls moved
1813 -> 1816 ns/packet for visitor and 1844 -> 1837 ns/packet for service,
within 0.5% in both cases. These absolute values reflect the host load during
this run and are used only for paired before/after evidence.

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

The maintained ACK-range executable uses one zio-backed `std.Io` clock for all
allocation, caller-storage, stale-check, sent-validation, and recovery-cycle
arms and prints the backend identity. Older values below are historical
Threaded measurements and are not mixed with later zio runs.

`bench-quic-ack-ranges` now includes a complete recovery cycle that tracks 128
payload groups and retires them with two 64-range ACK frames. Recovery validates
the descending range chain before mutation, then matches directly from wire
ranges instead of allocating a second decoded-range array. The ReleaseFast
baseline is 8.9 us/cycle on this host. Failing-allocator and malformed-range
tests prove allocation-free application and transactional rejection.

The audited quicz frame decoder allocates `AckRange[range_count]` for every ACK.
Netz still owns ranges at its generic parser boundary, but its recovery queue no
longer performs another allocation/copy.

The receive transaction's earlier sent-packet validation-only pass now streams
wire ACK ranges and proves each range's exact sent coverage with binary
boundaries plus the compacted acknowledged prefix. It no longer materializes a
decoded-range array or visits every retained packet merely to reject an
optimistic ACK; the later apply pass still computes the unchanged ECN, path,
RTT, congestion, and newly-acknowledged summaries. A fixed-binary, CPU-0, nine-
pair order-alternated run reduced validation of one cumulative ACK over 4,096
sent packets from 3,123-3,671 ns/op (3,142 median) to 24-25 ns/op (25 median),
a 99.2% median reduction or 125.7x throughput improvement, with the candidate
faster in 9/9 pairs. The benchmark's following recovery phase initially moved
about 4% because the preceding validation workload became roughly 125x shorter;
a seven-pair control that measured recovery first instead produced 4,765 ns/cycle
candidate versus 4,827 ns/cycle baseline medians, and normalized disassembly of
`Queue.applyAck` was identical. Tests cover allocation failure, generated sparse
ACKs, never-sent holes, retired-prefix crossings, `u64` range width overflow, and
the conservative unsorted-metadata fallback. Real TLS 1.3 1-MiB gates then held
24/120 datagrams under every-fifth reordering with zero transport loss, and
dropped 6/126 datagrams under seeded 5% loss with six reported transport losses;
both verified every payload byte. These are internal ACK-validation and
correctness results, not a cross-library throughput claim.

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
The development runtime benchmark accepts `--iterations=N` (default 1,000) so
long profiling runs can collect enough samples without changing its source.
Inbound request and response head validation now collects pseudo-header and
Content-Length lookup metadata during the same semantic scan. Content-Length
errors remain deferred until after structural and field-size validation,
preserving the prior error precedence. Five interleaved CPU-0 runs over 100,000
cleartext request/response exchanges measured 10.29-10.42 us/request versus
10.49-10.53 us/request at the preceding commit (1.01-1.02x faster).

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
bounded shutdown automatically using a configurable five-second default. One
absolute deadline covers both GOAWAY phases and the subsequent recovery drain,
so pacing cannot make graceful shutdown outlive that budget. The
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
modes now run on the shared zio backend and pass only `std.Io` into the HTTP/3
and QUIC stack; the server side is scheduled with `std.Io.async` instead of a
manually spawned OS thread. The `bench-http3-dev`, QPACK, and Capsule
executables use the same zio-provided clock/I/O boundary and print
`io backend: zio-std-io`. Both upload and download
modes use the handshake runtime's paced body sender: `CongestionLimited` and
`FlowControlBlocked` drive peer packet processing so ACK/MAX_* frames can reopen
send credit instead of turning large transfers into synchronous failures.
`--streams` splits the requested byte count across concurrent client-initiated
request streams, matching the shape of quicz's 4-stream aggregate benchmark.
`--round-robin-chunk-bytes` controls the per-stream scheduling quantum used by
multi-stream upload/download helpers; the default is 64 KiB, while smaller
values are useful for probing ACK/credit fairness without editing source.
`--endpoint-datagram-size`, `--one-rtt-datagram-size`, and
`--paced-body-chunk-bytes` override the benchmark's receive and transfer sizing
knobs. `--receive-batch-datagrams` selects 1 through 16 retained UDP datagrams
without changing the executable, making fixed-binary policy comparisons
possible. The benchmark creates a fresh loopback server/client pair per
iteration and reports mean/stddev MiB/s, matching quicz's multi-iteration
benchmark shape.

Integrated HTTP/3 and WebTransport endpoints now default their physical UDP
receive capacity to 4,096 bytes; generic QUIC endpoints retain 65,535. The
handshake caps generated `max_udp_payload_size` advertisements to the endpoint
capacity and rejects oversized raw transport-parameter overrides. At the HTTP/3
default, the cursor drains up to sixteen independent UDP datagrams through one
zio `std.Io` receive operation, retains at most 64 KiB of encrypted datagrams,
and authenticates/applies exactly one packet per upper-layer turn. Endpoints
whose capacity only permits one slot retain the single-packet path.
Preferred-address migration likewise remains on the dual-socket single-packet
path. A real zio regression proves that callback
failure commits only the visited packet, preserves the unread suffix in order,
does not advance it on an invalid deadline, and triggers the configured ACK
threshold only when the second packet is consumed.
The endpoint also honors `std.Io`'s partial receive result: when a backend
returns a non-empty datagram prefix together with an error from a later drain,
netz exposes and accounts for that prefix instead of dropping bytes already
removed from the socket. A zero-count result still propagates the error.
`--ack-eliciting-threshold` controls the server ACK policy; the default of four
is the stable winner from the same-host 2/4/8/16/32 scan. Packet-size-aware
cross-stream body batches are available through
`sendRequestBodyBatchPaced`/`sendResponseBodyBatchPaced`, and
multi-stream runs now enable that path by default. `--disable-body-batch`
retains the sequential A/B control, while `--enable-body-batch` can explicitly
select batching at any stream count. The default changed only after zio and
the HTTP/3 cursor gained bounded receive batching; before those changes this
host's small UDP receive queue made bursts slower than sequential submission.
`--enable-gro-receive` enables the timer-aware owning-batch receive path. It is
also opt-in on this host: the path now completes long uploads/downloads without
stalling, but its burst shape is slower and noisier under the same small receive
queue.

A 2026-09-15 same-binary receive-policy A/B used ReleaseFast executable SHA-256
`3ca5bfbd06f7f61043fc3e40bba73b34221f443a6b4cb50fdb4f3e5816f1c8ac`,
CPU 0, a 4,096-byte endpoint, and seven order-alternated 16 MiB/four-stream
download pairs. Batch 16 achieved an 86.02 MiB/s median versus 67.20 MiB/s for
batch 1 (1.280x, 6/7 paired wins). Every arm reported `zio-std-io`, exactly
16,777,216 body bytes, and status total 800. This is a same-process receive
policy result, not an equal-wire cross-stack claim. The bidirectional tquic
HTTP/3 gate also passed with and without Retry after the default changed.

Five fixed-binary, CPU-0, order-alternated 16-MiB/four-stream comparisons
against commit `8cc373ae` measured non-GRO cursor batching at 75.75 MiB/s
download median versus 67.53 MiB/s before (1.122x, 5/5 paired wins). Upload,
where the benchmark peer rather than the HTTP/3 receiver carries most payload
work, measured 114.29 versus 115.13 MiB/s (0.993x, overlapping ranges, 3/5
wins). One-stream upload/download medians were 162.93/141.37 MiB/s after and
155.48/138.24 MiB/s before. All arms verified 16,777,216 body bytes and the
expected status totals; these are same-process regression measurements, not an
equal-wire cross-stack claim.
With that receive path in place, seven same-binary, order-alternated
four-stream comparisons also favored cross-stream body sending in every pair:
upload median rose from 103.35 to 112.77 MiB/s (1.091x) and download from
73.41 to 80.27 MiB/s (1.093x). Multi-stream benchmark mode therefore enables
body batching by default; single-stream mode remains sequential.

A 2026-09-22 body-batch send-path audit removed the HTTP/3 layer's second exact
packet-length walk immediately before `Connection.sendManyProgress`. The QUIC
batch preflight already validates every packet's frame lengths, packet-number
overhead, current PMTU, and endpoint datagram limit before reserving flow or
congestion credit, recovery ownership, packet numbers, or socket output. A new
small-MTU regression verifies that an oversized body batch still returns
`DatagramTooLarge` with unchanged body offset/FIN state, no completion callback,
no sent-packet increment, and no UDP datagram. Fixed ReleaseFast binaries,
CPU 0, and seven order-alternated 16-MiB/four-stream pairs at an explicit
3,000-byte body chunk measured:

| Direction | Before SHA-256 | Before median | After SHA-256 | After median | Paired result |
|---|---|---:|---|---:|---:|
| upload | `4f777fd91e9ef46b7d9b3bf132605afcfaa75b3ac97c6c5d3d0a29509ee5077b` | 149 MiB/s | `02135fc0dc0f43f29b01dec362e0548a9e335c677ed1c6f6143cba16b656907a` | 155 MiB/s | 7/7 wins, 1.040x |
| download | same | 76 MiB/s | same | 77 MiB/s | 5 wins, 1 tie, 1 loss, 1.013x |

The upload improvement is consistent; the download delta is close to host
noise and is not presented as a general speed claim. A separate same-binary,
order-alternated five-pair policy comparison then changed the benchmark-only
sub-64-MiB multi-stream chunk from 3,000 to 5,000 bytes. Upload medians moved
from 139 to 197 MiB/s (1.417x, 5/5 wins) and download from 82 to 103 MiB/s
(1.256x, 5/5 wins). The 64-MiB benchmark retains its separately established
6,000-byte policy, and production's conservative 1,024-byte default remains
unchanged for standard 1,200-byte paths. Final five-sample 5,000-byte runs
verified 83,886,080 bytes and status total 4,000 in each direction: upload
mean 203.28 MiB/s (19.57% standard deviation, 129.76–235.07) and download mean
113.54 MiB/s (0.82%, 111.96–114.69).
`--verbose` prints per-iteration throughput lines (`[iter N]`) for diagnosing
long or stuck multi-iteration runs. `--trace-iteration` additionally prints
coarse lifecycle stages (bind, connect, transfer, join) for each iteration.

A 2026-09-15 ReleaseFast migration smoke ran 20 cleartext requests, one
four-stream 64-KiB upload, one matching download, 1,000 iterations of each
QPACK scenario, and the default one-million-iteration Capsule workload. Every
command completed and printed `io backend: zio-std-io`; the request status
totals and transfer byte counts were exact. These short runs establish the new
runtime path and are not performance comparisons.

```sh
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=16777216 --mode=upload --streams=4 --verbose
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=1048576 --mode=upload --streams=1
```

Historical pre-zio 5-iteration 1 MiB upload smoke sample:

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

Historical pre-zio 16 MiB single-stream upload result:

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

Historical pre-zio 16 MiB single-stream download result:

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

Historical pre-zio 16 MiB / 4-stream upload result:

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

Historical pre-zio 16 MiB / 4-stream download result:

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
internal result with the same 16 MiB transfer size as the quicz reference
benchmark family. The cross-process quic-go comparison below covers the former
single-stream full-stack gap and now includes an externally verified 4/16-stream
shape. Capture-backed equal-wire comparison remains open.
An opt-in, strictly verified capture pipeline now exists for the quic-go
comparison below; the remaining gap is a real artifact from a host permitted
to open the packet socket, followed by ACK/frame/cipher equivalence analysis.

### HTTP/3 versus quic-go, same application shape

`bench-http3-quic-go` builds against quic-go v0.59.0 from the audited,
repository-owned Go module under `tools/interop`, so it no longer depends on a
separate quicz checkout. It runs both sender roles for upload and download.
Client and server are pinned to separate CPUs. Every sample creates a fresh
certificate-verified
QUIC v1 or forced-v2 H3 connection, completes an untimed `/benchmark/ready` request, then
times 1, 4, or 16 request bodies through receiver-validated status, headers,
EOF, bytes, and checksums. This prevents congestion, QPACK, and retired-stream
history from one sample changing the next. Both sides use a fixed 1 MiB stream
window by default; connection credit is that window times at least eight, and
therefore grows to 16 MiB for the 16-stream shape. The steady-state MTU is 1280
bytes and the effective application chunk is 1152 bytes. Netz explicitly
disables GSO/GRO; quic-go reports its implementation defaults. The current
netz client and server use zio behind `std.Io`. Config, client-owned result,
server-completion, and memory records carry `client_io` and `server_io`; the
strict checker also verifies endpoint ownership, the complete benchmark shape,
finite recomputed throughput, and exact bytes/checksum.

```sh
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --mode=upload --warmup=2 --iterations=5 --body-bytes=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --timeout-ms=30000

zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --mode=download --warmup=2 --iterations=5 --body-bytes=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --timeout-ms=30000

# Run separately from timing and allocation measurements. Requires Linux
# CAP_NET_RAW and three available CPUs; artifacts are written under
# zig-out/http3-captures/.
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --capture --mode=upload --warmup=2 --iterations=5 --streams=4 \
  --body-bytes=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000

NETZ_HTTP3_INTEROP_VERSION=2 \
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --mode=upload --warmup=2 --iterations=5 --streams=4 \
  --body-bytes=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000

NETZ_HTTP3_INTEROP_VERSION=2 \
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --netz-only --stats --mode=upload --warmup=1 --iterations=1 \
  --streams=4 --body-bytes=65536 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000
```

The opt-in capture mode starts a dedicated Linux `AF_PACKET`/`SOCK_DGRAM`
packet socket on a third pinned CPU before each server. It filters the loopback
single cooked IPv4 copy (`PACKET_HOST`) by the pair's unique UDP server port.
Direction is reconstructed from that port rather than inferred from the packet
type. Both netz endpoints already disable GSO; the runner
sets `QUIC_GO_DISABLE_GSO=true`, and the Go fixture independently rejects a
connection whose `ConnectionState().GSO` remains enabled. Each classic-PCAP
artifact uses DLT_RAW, retains at most 128 bytes per packet, and is capped at
512 MiB. Its original IP
length and captured IPv4/UDP headers are sufficient to recompute directional
datagram counts, UDP payload bytes, IP bytes, and ordered packet-size hashes
without retaining complete encrypted application payloads. The strict checker
first validates the ordinary client result and server completion, then
reparses the PCAP and requires zero packet-socket drops, matching port/shape,
binary and capture-tool hashes, header arithmetic, and enough sender bytes to
cover every warmup and measured body. A cross-role checker requires the same
workload, tool, CPUs, and quic-go binary before reporting totals and
directional size-sequence equality. Capture artifacts cover complete process
pairs, including handshakes, ready/close requests, ACKs, and teardown, and the
artifact directory retains the exact capture script alongside the PCAPs and
endpoint logs, plus the pinned quic-go `go.mod` and `go.sum`. Their
timings are labeled `timing_usable=false`; equal aggregate counts or packet
sizes do not by themselves establish equal QUIC frames, ACK policy, cipher, or
application scheduling. `--capture`, `--stats`, and `--netz-only` are therefore
kept as separate evidence modes.

This host has no effective `CAP_NET_RAW`: the capability probe fails with
`AF_PACKET was denied` before starting either benchmark process. Parser, PCAP
round-trip, per-pair verifier, comparison, GSO-contract, and fail-closed
permission tests are reproducible here, but no capture numbers are recorded as
if they had been observed. A privileged capture host is still required to run
the command above and decide whether the captured shapes are sufficiently
matched for any stronger timing claim.

A 2026-09-15 migration gate exercised QUIC v1 with one stream and QUIC v2
with four streams in both upload/download directions and both mixed role pairs.
The v2 four-stream records each verified 262,144 logical bytes and checksum
33,423,360. With memory telemetry enabled, every netz process finished with
`live_bytes=0`; the runner correctly labeled the available RSS tool as
`busybox-time-maxrss`. A separate zio-only v2 four-stream gate passed both
directions under the same schema. These are one-sample functional and
evidence-pipeline checks, not performance comparisons.

Historical pre-zio CPU-0/client, CPU-1/server samples on 2026-09-08 measured:

| Sender implementation | Upload | Download |
|---|---:|---:|
| netz | 169.75-175.54 MiB/s | 169.03-176.47 MiB/s |
| quic-go | 45.25-124.16 MiB/s | 50.55-73.21 MiB/s |

Every sample verified status 200, exactly 4,194,304 logical bytes, and checksum
534,773,760. The wide upload ranges are retained instead of compressed into a
single ratio. These measurements used the former `std.Io.Threaded` harness and
must not be cited as zio performance. This is `same-application-shape` evidence,
not equal-wire and not
a whole-library superiority claim. The new opt-in capture path can now measure
kernel-visible UDP datagram counts/bytes and size sequences with GSO disabled,
but a privileged-host artifact plus ACK/frame/cipher analysis is still required
before claiming identical wire work. The important result is that a reproducible
full-stack comparison now exists and fails closed on any header, byte, EOF, or
checksum mismatch.

The aggregate response receive path was revalidated on 2026-09-14 after a
quic-go download consistently stopped once roughly 336 KiB had arrived. The
HTTP/3 layer had already copied each contiguous response prefix into its own
bounded reassembly, but the QUIC receive cursor remained unchanged until FIN,
so the peer eventually exhausted stream credit while the client waited for the
rest of the response. Aggregate routing now commits only the contiguous copied
prefix back to QUIC immediately; streaming responses retain their existing
application-read-driven backpressure. A focused 8-byte-window test verifies
that two 6-byte prefixes advance both the transport read offset and advertised
stream limit before FIN.

The benchmark fixture also now budgets the wire bytes retained by aggregate
reassembly rather than only the logical body: quic-go's 1152-byte application
writes produce 911 DATA frames for a 1 MiB body, requiring 2733 bytes of DATA
frame headers plus the bounded response-header margin. With the transport
window still fixed at 1 MiB, single-, 4-, and 16-stream downloads passed for
QUIC v1 and v2 in both endpoint-role pairings. The 16-stream cases verified
16,777,216 aggregate bytes, all 16 streams, and checksum 2,139,095,040. These
are one-sample functional gates, not throughput claims. The full tquic gate
also passed in both directions with Retry on and off, GET/Range/POST digest,
and bidirectional GOAWAY/drain/reject-next-stream coverage. Its public netz
client and server now run on zio behind `std.Io`; the runner requires
`zio-std-io` for the netz endpoint and the audited `tquic-mio` identity for
the tquic endpoint in every success record.

The completed aggregate response now transfers its reassembly allocation into
the owned result after all fallible validation and decoding have succeeded,
instead of duplicating the complete encoded stream and then freeing the
original. This follows the same broad ownership principle as Quinn's
chunk-collecting `read_to_end`, while retaining the consumption-driven credit
behavior exposed by quiche's `recv_body`. Allocators that cannot shrink the
reassembly allocation in place keep the prior copy fallback; an induced
resize-plus-allocation failure verifies that the original response remains
retryable.

Three order-alternated fixed-binary memory pairs used one warmup plus three
measured fresh connections, a 16 MiB response, a 1 MiB transport stream window,
and the quic-go-server/netz-client direction. The median netz explicit peak
fell from 99,644,791 to 78,618,808 bytes (-21.1%), cumulative allocation from
348,387,294 to 281,102,735 bytes (-19.3%), and whole-process peak RSS from
420,400 to 353,104 KiB (-16.0%). Every run freed all explicit allocations and
verified the complete response. Five separately order-alternated throughput
pairs, with three measured responses per process, overlapped: the baseline and
candidate medians were 15.725 and 15.804 MiB/s, while the paired throughput
ratio median was 0.992 and the candidate won 1/5 pairs. The change is therefore
retained as a memory reduction with no throughput-improvement claim. The frozen
ReleaseFast client SHA-256 values were
`26c14a80ac78300856281149c3e7e90577e36768b7a8365c32575e4d88585a9a`
for the baseline and
`473cf866d9150636431c1e122c5bf1041590118ea79519dc076c62640f07a8a5`
for the candidate.

The symmetric aggregate request path now uses the same two-phase transfer and
returns QUIC receive credit as each contiguous prefix is copied into HTTP/3
ownership. A deterministic 8-byte connection/stream-window test advances two
6-byte prefixes before FIN. A dedicated single-stream `--aggregate-upload`
mode in `bench-http3-handshake-transfer` exercises `receiveRequest()` rather
than the benchmark's default streaming receiver; `--flow-control-bytes` keeps
the historical 256 MiB default unless explicitly set. With 256 KiB of credit,
the final binary completed a 1 MiB aggregate upload, while the frozen baseline
stopped at 253,952 bytes and was terminated by the 10-second comparison limit.

For the copy-cost comparison, three order-alternated fixed-binary memory pairs
used 16 MiB requests, one stream, the default 256 MiB credit, and three measured
iterations. Median explicit peak allocation fell from 104,304,658 to 65,633,749
bytes (-37.1%), and median cumulative allocation fell from 279,031,715 to
168,674,704 bytes (-39.5%). Five separate throughput pairs, five iterations
each, measured baseline/candidate medians of 59.00/67.15 MiB/s; the paired
ratio median was +13.7% with 4/5 wins, but the 57.40-64.74 and 64.14-68.25
MiB/s ranges overlap slightly. This is a positive result for that bounded
aggregate shape, not a general HTTP/3 throughput claim. Every run verified
83,886,080 bytes and status total 1000. The final ReleaseFast binary SHA-256
values were
`0e5e7e978ae23043d5f7820fb98c5bb2cc5776da25d92b5951f3468cfef0fa55`
for the baseline and
`8ff68b3300e10dac770d74af0a15ea915a8cee9e73bc40d54dbca087cc4277b2`
for the candidate. The ordinary streaming upload mode remains the default and
passed the v1/v2 four-stream quic-go matrix after this change.

The concurrent gate is reproducible with:

```sh
zig build bench-http3-quic-go-multistream -Doptimize=ReleaseFast --summary all
```

It runs QUIC v1 and v2 with 4 and 16 streams, upload and download, both role
pairings, two warmups, and five measured samples. Set
`NETZ_HTTP3_MULTISTREAM_VERSIONS=1` or `=2` to narrow the matrix. All request
streams are created before transfer. For the pinned quic-go v0.59 peer, v2
selects its historical RFC 9001 key-update label compatibility profile; the
library default remains RFC 9369. Result, completion, and memory records include
`quic_version`, and the verifier rejects missing or mismatched versions.
The Zig upload client and download server use paced cross-stream body batches;
the opposite receive paths consume whichever stream is ready. The Go client
uses a goroutine start barrier and the Go server holds each round until every
handler has entered. Stream indices are carried independently of QUIC stream
ordering, payload bytes vary by index, and the verifier requires one unique
client result plus one server-completion record per sample with all streams
finished and independently validated. An explicit final request/response
barrier precedes connection close.
The DATA phase uses one caller-owned awake-clock deadline across every paced
batch send, receive-progress wait, pacing wait, response receive, and recovery
drain. The public bounded batch APIs report the exact socket-visible committed
chunk prefix; the priority scheduler reports committed body bytes separately
for every response, so timeout and partial socket errors never imply that an
already-sent prefix is safe to replay. Authenticated aggregate request and
paced-response deadline APIs now carry that same timestamp through QUIC stream
admission, SETTINGS/QPACK instructions, HEADERS, body, trailers, and response
receive. Their packetizer checks before every socket attempt and bounds pacing
waits; a zero-packet timeout remains retryable, while a timeout after a
socket-visible multi-packet prefix retires the connection without attempting
an unbounded close write. Streaming head APIs retain their separate blocking
contract, so this benchmark continues to label its measured batch-body scope
explicitly.

The complete post-barrier gate passed on 2026-09-09. Its 16-stream samples
carried 262,144 bytes per stream, 4,194,304 aggregate bytes, and aggregate
checksum 534,773,760:

| Mode | netz sender MiB/s (range; mean; median) | quic-go sender MiB/s (range; mean; median) |
|---|---:|---:|
| upload | 147.124-179.582; 159.152; 159.188 | 106.246-108.165; 107.233; 107.506 |
| download | 72.460-98.869; 83.197; 82.212 | 48.716-50.733; 49.870; 49.936 |

Every 4- and 16-stream sample passed the independent dual-log verifier. These
figures are `same-application-shape`, not equal-wire:
kernel/interface capture and equalized GSO/GRO, ACK, packetization, cipher, and
application scheduling remain prerequisites for a general throughput ratio.

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
available. The quic-go benchmark above supplies a full-stack
same-application-shape reference, but neither it nor these raw transport
numbers are treated as equal-wire H3 superiority evidence.

The process harness also accepts `--stats`. As with the raw QUIC comparison,
GNU time's whole-process maximum RSS is the cross-language metric; netz's
explicit allocator and Go's `runtime.MemStats` remain separately labeled
runtime diagnostics rather than a shared allocation definition:

```sh
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --warmup=1 --iterations=3 --body-bytes=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --stats
```

The complete upload/download, client/server-role matrix measured:

| Mode | Implementation workload | Process peak RSS (KiB) | Runtime allocation count | Runtime allocated bytes | Runtime peak/reserved bytes |
|---|---|---:|---:|---:|---:|
| upload | netz sender/client | 9,984 | 5,982 | 17,173,866 | peak live 6,490,848 |
| upload | quic-go receiver/server | 19,712 | 185,059 | 10,568,592 | ending HeapSys 12,189,696 |
| upload | quic-go sender/client | 22,528 | 74,921 | 15,565,816 | ending HeapSys 16,482,304 |
| upload | netz receiver/server | 7,936 | 454 | 5,849,150 | peak live 4,520,667 |
| download | netz receiver/client | 10,240 | 442 | 8,335,289 | peak live 7,014,161 |
| download | quic-go sender/server | 23,296 | 78,303 | 15,160,104 | ending HeapSys 16,416,768 |
| download | quic-go receiver/client | 19,968 | 185,369 | 10,890,568 | ending HeapSys 12,255,232 |
| download | netz sender/server | 9,772 | 4,698 | 13,823,909 | peak live 6,300,315 |

All eight process records cover one warmup plus three measured fresh
connections. The strict sample verifier independently requires exactly samples
1 through 3 with matching mode, role pair, 4,194,304 bytes, checksum
534,773,760, status 200, and completion. The memory verifier requires the
expected role/implementation/runtime scope, positive RSS and runtime counters,
and zero post-teardown live bytes for both netz processes in each mode. Default
benchmark runs neither instantiate the counting allocator nor call Go
`ReadMemStats` or GNU time.

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

The same ordered, no-retransmission invariant now accelerates fragmented ACKs.
After validating the complete descending ACK chain transactionally, recovery
walks the ascending pending queue and the ACK ranges once from lowest to
highest instead of testing every packet against every range. Out-of-order
originals, forgotten originals, and groups with retransmission copies keep the
general membership scan. A fixed-binary, CPU-0, seven-pair run of
`bench-quic-ack-ranges` reduced the 128-packet/64-range recovery cycle from
12,990-13,122 ns (13,050 median) to 4,837-4,982 ns (4,854 median), a 62.8%
median reduction or 2.69x throughput improvement, with the candidate faster in
7/7 pairs. Direct tests compare irregular-width/gap output and 64 generated
sparse/dense ACK patterns against queues forced through the conservative path;
a separate multi-range case proves retransmission copies still use that
fallback. Existing tests retain allocation-free large-range, out-of-order, and
transactional invalid-ACK coverage.

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

The connection loss timer now follows Quinn, quiche, and tquic by retaining
the next RFC 9002 time-threshold loss deadline when ACK/loss state changes,
rather than rescanning all retained sent-packet metadata every time an endpoint
mirrors the connection timer. PMTU probe transitions, path resets, RTT updates,
explicit acknowledgements, and both packet- and time-threshold loss paths
refresh the cached value. A fixed-binary, CPU-0, seven-pair microbenchmark with
256 sent records, 255 acknowledged records, and one in-range loss candidate
reduced the complete
`Connection.lossDetectionTimerDeadline` query from 125.12-126.58 ns (125.93
median) to 3.08-3.11 ns (3.09 median), about 40.8x, with 7/7 wins.

Five order-interleaved 16-connection, 16-MiB-total shared-server pairs against
parent `bae40ca3` completed exactly in both sender directions. Client-sender
throughput was 56.412-69.628 MiB/s (62.744 median) before and 56.649-62.927
MiB/s (60.822 median) after, with 2/5 candidate wins. Server-sender throughput
was 73.391-93.500 MiB/s (80.275 median) before and 77.666-115.835 MiB/s
(82.260 median) after, with 4/5 candidate wins and a 2.5% median increase. Both raw
ranges overlap, so the server-sender result is supporting evidence rather than
a general throughput claim; the isolated timer-query reduction is the strong
performance result. Every arm verified 16,777,216 bytes, checksum 2,139,095,040,
all 16 connections, and the completion exchange.

The same fixed parent/candidate HTTP/3 binaries were then run in five
order-interleaved pairs, each arm performing three real-handshake, four-stream,
16-MiB uploads. Parent throughput was 125.96-134.84 MiB/s (130.87 median),
while the cached-loss-time path measured 133.60-138.15 MiB/s (134.64 median),
a 2.9% median increase with 5/5 candidate wins. Every arm verified 48 MiB and
status total 2,400. This is same-host HTTP/3 regression evidence; it does not
replace the equal-wire cross-stack gap.

Two narrower alternatives were measured and removed. Merely starting the
read-time sent-packet scan at the first unacknowledged index made the isolated
query cheap, but a longer 16-connection, 64-MiB-per-arm shared run favored it
in only 1/5 client-sender and 2/5 server-sender pairs; client-sender median
fell from 41.898 to 32.231 MiB/s. Separately skipping endpoint-timer refresh
after an empty socket-free stream poll lost all 5/5 client-sender pairs and
moved its median from 65.424 to 55.055 MiB/s. Both experiments were fully
removed; the retained implementation instead moves loss-time discovery into
the existing ACK/loss pass, matching the recovery structure of the audited
implementations.

A subsequent recovery-payload ownership experiment grouped sustained 4-KiB
blocks into 64-KiB chunks. One captured ordinary-cache run made 2,101
allocation calls, including 1,761 exact 4-KiB allocations, with 3,871 cache
hits, 1,775 misses, 266 idle blocks, and 1,045,025 idle bytes. The dynamic
grouped candidate reduced the corresponding capture to 462 allocation calls,
67 calls of at most 4 KiB, and 110 64-KiB calls; it recorded 5,515 cache hits,
131 misses, 262 idle blocks, and 1,048,849 idle bytes. Peak explicit live bytes
were effectively unchanged at 24,756,635 before and 24,784,283 after.

That allocation-count reduction did not survive the fixed-binary HTTP/3 gate.
In five order-interleaved pairs of three 16-MiB/four-stream uploads per arm, a
fixed-capacity grouped version won 1/5 pairs and moved the median from 144.22
to 140.73 MiB/s (-2.4%); its parent/candidate ranges were 129.63-160.21 and
134.38-146.51 MiB/s. A dynamic-group version won 2/5 pairs and moved the
median from 145.83 to 143.97 MiB/s (-1.3%); its parent/candidate ranges were
119.76-149.09 and 140.57-146.80 MiB/s. Both grouped implementations were fully
removed. The benchmark retains only opt-in cache block/byte telemetry so later
work can distinguish a cache near its one-MiB idle limit from a first-activity
high-water mark; no allocator or throughput improvement is claimed.

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
All netz numbers in the tables above predate the zio migration and remain
historical `std.Io.Threaded` baselines. They must not be cited as current zio
performance; a fresh fixed-binary, CPU-pinned, odd-sample run is required.

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
  change and its tests were removed at that point. The receive pipeline has
  since moved from byte flags to packed words, added word-level gap scans and
  range prechecks, and gained zio receive batching. Re-evaluating the same
  representation on this newer baseline is recorded below; the older negative
  result remains here because it must not be generalized to the new pipeline.
- Keeping the packed bitmap but replacing its per-byte checks with one slice
  comparison for the already-contiguous portion of a partially overlapping
  STREAM frame also passed focused and QUIC-wide tests. Seven CPU-0,
  order-alternated fixed-binary pairs of the five-iteration 16 MiB/four-stream
  H3 upload moved median latency from 81.389 to 81.962 ms/iteration (+0.7%);
  the candidate was faster in only 1/7 pairs and had two pronounced high-tail
  samples. The fast path and its dedicated test were removed.
- Passing the single-STREAM preflight result into frame application removed a
  second overlap-validation scan while retaining fallible buffer/bitmap commit.
  Focused conflict and transactional tests plus the full QUIC suite passed, and
  profiling split the old `insertTracked` symbol into validation and commit.
  The real H3 result was nevertheless neutral: seven CPU-0 order-alternated
  pairs averaged 105.931 ms/iteration for baseline and 105.982 ms for the
  candidate (+0.05%); the paired-ratio median was +0.21% latency and the
  candidate won only 3/7 pairs. The token and commit split were removed.
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

The new `bench-quic-quic-go` process harness supplies that equivalent two-CPU
layout against quic-go v0.59.0 from the repository-owned, checksum-locked Go
module. It runs both client/server sender roles with a
fresh certificate-verified QUIC v1 connection per sample. An untimed fixed
control stream exchanges CONFIG/READY before 1 or 4 unidirectional data streams
transfer deterministic payloads; t1 occurs only after the receiver verifies
every byte and FIN and returns DONE with the exact aggregate checksum. The
sender returns DONE_ACK before the receiver closes the connection. Both
processes disable GSO and do not enable UDP_GRO; both use fixed 1 MiB stream and 8 MiB
connection windows, and the measured 1-RTT MTU is 1280 bytes.

```sh
zig build bench-quic-quic-go -Doptimize=ReleaseFast -- \
  --warmup=2 --iterations=5 --bytes-per-stream=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --timeout-ms=30000
```

The current harness runs every netz endpoint on zio and exposes only `std.Io`
to the QUIC implementation. Config, sender result, receiver completion, socket
traffic, and optional memory records carry `client_io` and `server_io`; the
strict checkers reject missing or role-inconsistent backend identities and
independently recompute each measured-round checksum. `--netz-only` provides a
two-process zio control without invoking quic-go. A
2026-09-15 ReleaseFast smoke with one fresh connection per direction and a
256-KiB payload verified checksum 33,423,360, exact bidirectional socket
accounting, and completion exchange at 56.446 MiB/s client-send and 65.788
MiB/s server-send. These are single-sample runtime checks, not comparative
performance evidence.
The final schema was also exercised against quic-go v0.59.0 for both role pairs
and both sender directions, with and without memory telemetry; every 64-KiB
sample verified checksum 8,355,840, completion exchange, paired socket traffic,
and runtime identity. A reduced 32-stream matrix additionally passed loss and
reordering in both directions and role pairs after the shared churn commands
moved to zio. These are migration gates rather than performance samples.

The cross-library measurements below were captured before this zio migration
and remain historical `std.Io.Threaded` baselines. They must not be cited as
zio performance; a new fixed-binary, CPU-pinned, order-interleaved quic-go run
is required for a current ratio.

CPU-0/client and CPU-1/server samples on 2026-09-08 measured:

| Streams | Sender | Role pair | Throughput |
|---:|---|---|---:|
| 1 | netz | netz client + quic-go server | 227.48-228.77 MiB/s |
| 1 | netz | quic-go client + netz server | 172.74-185.68 MiB/s |
| 1 | quic-go | quic-go client + netz server | 43.78-72.31 MiB/s |
| 1 | quic-go | netz client + quic-go server | 59.01-126.12 MiB/s |
| 4 | netz | netz client + quic-go server | 210.53-216.66 MiB/s |
| 4 | netz | quic-go client + netz server | 145.62-147.99 MiB/s |
| 4 | quic-go | quic-go client + netz server | 116.83-121.03 MiB/s |
| 4 | quic-go | netz client + quic-go server | 115.01-122.68 MiB/s |

Each 1-stream sample verified 4,194,304 bytes and checksum 534,773,760; each
4-stream sample verified 16,777,216 bytes and checksum 2,139,095,040. The wide
single-stream quic-go ranges and netz's role sensitivity are retained instead
of compressed into a ratio. This is `same-application-shape`, not equal-wire:
both processes disable GSO and do not enable UDP_GRO, but quic-go advertises a
different maximum UDP payload, uses per-stream goroutines while netz
round-robins one event loop, and retains implementation-specific
ACK/pacing/packetization. Capture-level UDP byte and
datagram accounting at the kernel/interface boundary is still required before
a general raw STREAM superiority claim.

The harness now also records complete-connection UDP payload bytes and logical
datagram counts at both processes' userspace socket boundaries. The counters
start before handshake and end after the benchmark close exchange, so they
include Initial, Handshake, 1-RTT data, ACK/control, and teardown traffic. GSO
is disabled for both stacks; netz disables GRO, while the audited quic-go
v0.59 receive path uses `recvmmsg` batching and does not enable Linux UDP_GRO.
Every counted logical segment is therefore one socket-visible UDP payload. The
runner joins client and server records by role pair/sample, rejects
missing/duplicate records and impossible negative
send-versus-peer-receive deltas, and preserves positive deltas when one endpoint
stops receiving after connection close. Telemetry is printed out-of-band rather
than sent over the measured QUIC connection.

Three CPU-0/client + CPU-1/server samples used `--warmup=1 --iterations=3`
with the same 4 MiB-per-stream shape and measured these complete-connection
ranges:

| Streams | Sender implementation | Total UDP datagrams | Total UDP payload bytes | Payload overhead |
|---:|---|---:|---:|---:|
| 1 | netz | 3,950-4,195 | 4,323,315-4,334,573 | 3.08-3.34% |
| 1 | quic-go | 7,318-7,328 | 4,448,566-4,454,107 | 6.06-6.19% |
| 4 | netz | 15,687-20,057 | 17,275,226-17,497,963 | 2.97-4.30% |
| 4 | quic-go | 29,661-30,103 | 18,357,564-18,895,334 | 9.42-12.62% |

The ranges combine both client/server role pairings for each sender
implementation rather than attributing peer ACK cost to only one process. All
24 measured connections retained exact application bytes, checksum, FIN, and
two endpoint telemetry records. Most one-stream directions had exact
send/peer-receive equality. Positive teardown/read-stop deltas remained visible
(one 29-byte quic-go close response in the stable one-stream case and larger
ACK tails in some four-stream cases) instead of being silently subtracted.

These socket-boundary numbers demonstrate that the workloads are **not
equal-wire**: quic-go's sender shapes use materially more ACK/control traffic
and roughly twice as many UDP datagrams in these samples. They strengthen the
fairness audit but do not replace a kernel packet capture, since this host
denies unprivileged `tcpdump`, passwordless elevation, and user/network
namespaces. Future promotion still requires capture-backed IP/UDP accounting
plus equalized GRO, ACK/pacing, packetization, and application scheduling.

### Raw QUIC persistent echo and multi-connection aggregate versus quic-go

`bench-quic-persistent-external` fills the persistent echo and process-level
multi-connection gaps in the raw QUIC matrix. It uses the repository-owned,
checksum-locked quic-go v0.59.0 module and pins client/server processes to
separate CPUs, disables GSO on both peers, does not enable GRO, and performs a
certificate-verified QUIC v1 handshake before timing. The runner exercises all
four netz/quic-go client/server combinations in alternating order. Each result
is accepted only after the peer has consumed and validated exact payload bytes,
FIN, and checksum and the DONE/DONE_ACK exchange completes; a separate server
record must independently agree.

The netz side of the current harness uses zio as its execution backend and
passes only `std.Io` into QUIC. Every result and server-completion record names
both endpoint runtimes (`zio-std-io` or `quic-go-netpoll`), and the strict
checker and summary reject missing or mismatched runtime identities. The
historical measurements below predate that migration and were collected with
the former `std.Io.Threaded` harness; they remain historical baselines, not zio
performance evidence. New zio performance claims require a fresh fixed-binary,
CPU-pinned, order-interleaved run.

A 2026-09-15 ReleaseFast migration smoke used four connections, one 256-KiB
stream per connection, and both sender roles. The shared-server topology
verified 1,048,576 bytes and checksum 133,693,440 at 63.686 MiB/s upload and
78.468 MiB/s download; the independent topology verified the same payload at
81.419 and 77.144 MiB/s. A separate 2-warmup/20-measurement persistent echo
run verified all 22,528 bytes and checksum 2,872,320. Every record identified
both endpoints as `zio-std-io`. These single-sample results establish runtime
and verifier coverage only; they are not comparative performance evidence.

```sh
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --mode=echo --samples=5 --warmup=200 --iterations=5000 \
  --payload-bytes=1024 --timeout-ms=30000
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --mode=aggregate --samples=5 --connections=4 --streams=1 \
  --bytes-per-stream=1048576 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=60000
```

The 2026-09-10 echo run produced these medians of each run's P50, with 5,000
measured 1-KiB round trips after 200 warmups:

| Fixed server | netz client | quic-go client | netz latency advantage |
|---|---:|---:|---:|
| quic-go | 24.172 us | 25.851 us | 1.069x |
| netz | 23.729 us | 24.361 us | 1.027x |

Against the fixed quic-go server, median P99/P99.9 values were 29.346/37.456
us for netz and 33.599/41.540 us for quic-go. Against the fixed netz server,
they were 27.273/36.060 us for netz and 30.586/43.463 us for quic-go. Every run verified
5,324,800 echoed bytes including warmup and checksum 678,912,000.

The aggregate run used four simultaneous independent endpoint/connection
workers in each process and one 1-MiB unidirectional stream per connection. A
GO record was sent only after all four TLS/QUIC handshakes and control streams
were ready. The timed interval includes per-connection payload/buffer
construction, stream prelude/setup, all payload and FIN transmission,
byte/checksum validation, and DONE/DONE_ACK completion. It is therefore a
complete application-transfer cost rather than an isolated steady-state send
loop. Five runs produced:

| Fixed endpoint | Sender implementation | Median MiB/s | Range MiB/s | Netz / quic-go |
|---|---|---:|---:|---:|
| quic-go server | client: netz / quic-go | 152.580 / 111.179 | 140.160-162.861 / 110.880-111.999 | 1.372x |
| netz server | client: netz / quic-go | 73.333 / 101.045 | 55.856-123.198 / 100.273-101.974 | 0.726x |
| netz client | server: netz / quic-go | 66.736 / 100.897 | 51.345-109.791 / 98.920-101.474 | 0.661x |
| quic-go client | server: netz / quic-go | 149.825 / 112.307 | 136.079-160.929 / 110.288-112.968 | 1.334x |

All 40 aggregate result records and 40 independent server completion records
verified 4,194,304 bytes and checksum 534,773,760. The mixed-role results show
that a netz sender is faster in both mixed-role comparisons, while the netz/netz control
is materially slower and more variable when eight endpoint workers share the
two pinned process CPUs. This is useful evidence of both the sender fast path
and a remaining same-process scheduling bottleneck, not a universal superiority
claim. This original topology uses one UDP socket per connection; the following
shared-server extension isolates the alternative production ownership model.

Raw QUIC now also exposes `quic.endpoint_server.Server`, a protocol-neutral
single-owner loop for bounded concurrent TLS handshakes, CID routing, aggregate
timers, socket-free stream polling/sending, and explicit post-application ACK
policy. It follows the same bounded endpoint-work design as the audited Quinn
driver, which caps receive/event work before yielding. The dispatcher now also
drains ACK-driven packet-threshold retransmissions before returning a routed
packet, matching netz's blocking and visitor receive paths instead of delaying
repair until PTO. A direct two-client real-handshake test verifies distinct
handles and echo payloads over one UDP socket; a focused dispatcher regression
drops packet numbers 0-3, delivers an ACK for packet 4, and observes immediate
retransmissions 5 and 6.

The persistent aggregate harness accepts this production topology with:

```sh
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --mode=aggregate --samples=3 --connections=4 --streams=1 \
  --bytes-per-stream=1048576 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=60000 \
  --server-topology=shared
```

The runner labels it `endpoint_topology=shared-server-udp`, rejects incompatible
mode/role combinations, and keeps its result set separate from independent-UDP
summaries. Five verified 4 x 1-MiB client-upload samples measured
56.554-64.812 MiB/s (59.627 median), with exact 4,194,304-byte and
534,773,760 checksum agreement on both sides. Seven manual order-alternated
same-binary pairs measured 57.026-69.958 MiB/s (62.757 median) for the shared
server versus 80.979-93.000 MiB/s (87.565 median) for four server sockets, or
0.717x. This closes the missing executable shared-socket shape but deliberately
records its remaining allocation/scheduling deficit rather than presenting it
as a speedup. The audited quic-go fixture and Go toolchain were unavailable for
this capture, so no new cross-library ratio is claimed. Separate verified
smokes covered four connections with four 256-KiB streams each (4 MiB total)
and eight connections with one 256-KiB stream each (2 MiB total), including
exact FIN, byte, checksum, and DONE/DONE_ACK validation.

The shared endpoint now also exposes caller-buffer `receiveVisiting*` APIs. For
an established non-GRO connection on the current key phase, the dispatcher
routes and decrypts in place, applies transport frames through retained frame
scratch, and exposes borrowed packet/frame views only for the duration of the
callback. Unknown-CID and handshake traffic keeps the owning path, and key
updates keep the safe allocating fallback because an in-place failed-key trial
cannot preserve ciphertext for another generation. The endpoint server adapter
applies negotiated ACK policy after a successful callback. A failing-allocator
real-UDP test covers warmed established packets, including a rotated one-byte
CID; separate tests cover callback error propagation and the key-update
fallback.

`HandshakeServerSession.processRequestPacketView` exposes the matching HTTP/3
boundary: custom shared loops can apply an authenticated borrowed packet during
the dispatcher callback without constructing an owning `ReceivedPacket`. The
existing owning method delegates to this path, and a regression releases the
source packet immediately after the call before polling the retained request.
The built-in HTTP/3 `EndpointServer.receiveManyOnce` now connects that path to
the bounded caller-buffer dispatcher. Borrowed packets are fully applied inside
the call; only stable request, connection, close, failure, and owned-unrouted
events escape. One real UDP regression routes two complete requests in one
batch, overwrites the caller buffer, and then validates both retained request
heads; another admits and promotes two concurrent real TLS handshakes through
the same API. The existing single-event receive APIs remain unchanged for
compatibility.
The shared authenticated client pool now exposes the symmetric bounded
`receiveManyOnce` path. `HandshakeClient.processResponsePacketView` lets its
dispatcher apply established response packets before caller receive storage is
reused, while response and push stream state retains the data needed by later
poll/read calls. The owning packet API remains source-compatible. A real
two-origin TLS regression queues both responses, observes more than one event
in a batch, overwrites the receive
buffer, and then validates both response statuses and bodies. Empty and
oversized event slices, non-positive poll intervals, and idle timeout are
covered separately. This is a functionality and ownership result; no
throughput ratio is claimed.

A same-host, same-command three-sample A/B against commit `17109fda` measured
the caller-buffer shared server at 64.455-79.452 MiB/s (69.691 median) versus
the owning baseline at 51.322-64.565 MiB/s (64.454 median), an 8.1% median
increase. Every arm independently verified 4,194,304 bytes, checksum
534,773,760, four completed connections, and the completion exchange. The
ranges overlap and only three samples were collected, so this is a regression
sample supporting the allocation-path change, not a general throughput claim.

The persistent shared topology now covers both sender roles. Server-originated
transfers use the same single socket owner and explicitly resumable state
machine as uploads: unidirectional stream reservation and every prelude, data,
FIN, and completion-control send are nonblocking, while routed packet and
timer events resume connections held by pacing, congestion, or flow control.
The endpoint server exposes the dispatcher's socket-free unidirectional stream
poll so applications do not introduce a competing UDP receiver. Five verified
16-connection, 16-MiB runs transferred 80 MiB in each direction. Client-sender
samples measured 62.790-79.786 MiB/s (71.458 median), while server-sender
samples measured 80.013-96.256 MiB/s (84.688 median). The server-sender runs
handled 2,783-3,402 timer events and sent 14,755-14,842 datagrams, providing
direct coverage of backpressure recovery across all connections. The ranges
overlap, so these measurements establish bidirectional completion and scaling
coverage rather than a directional throughput advantage. A separate four-
connection/four-stream smoke verified 4 MiB, every FIN, checksum, and the
DONE/DONE_ACK exchange in both directions.

A same-connection transmit-batch candidate was also evaluated and removed. It
staged up to four resumable STREAM packets per socket submission using the
existing exact protected/socket-visible prefix result. Five order-alternated
16-connection, 16-MiB server-sender pairs measured 86.307, 105.154, 95.560,
95.648, and 88.004 MiB/s for the retained one-packet path (95.560 median),
versus 81.025, 69.699, 99.228, 93.564, and 70.437 MiB/s for batches of four
(81.025 median). Only one of five pairs favored batching, and its median was
15.2% lower; a batch size of 32 also produced an intermittent tail timeout at
16 connections. The current Threaded backend already uses `sendmmsg`, while
QUIC pacing limits useful per-connection bursts, so the additional protection
and staging work is not retained.

A narrower dispatcher candidate reused the already-resolved connection-table
entry when checking whether authenticated packet processing changed local CID
routes, instead of looking the same handle up again. Five fixed-binary,
order-interleaved 16-connection, 16-MiB-total pairs against parent 857f6329
did not support retaining it. Client-sender throughput was 54.146-60.556 MiB/s
(57.195 median) before and 53.267-67.029 MiB/s (54.890 median) after, with 2/5
candidate wins. Server-sender throughput was 84.686-112.349 MiB/s (93.718
median) before and 69.022-113.377 MiB/s (85.711 median) after, with 1/5
candidate wins. The ranges overlap, but both medians moved lower and the pair
outcomes were unfavorable. Every arm verified 16,777,216 bytes, checksum
2,139,095,040, all sixteen connections, and the completion exchange. The
candidate was fully removed; this evidence rules out another locally cheaper
hash lookup as an end-to-end shared-owner improvement on its own.

A follow-up attempted to remove the shared upload application copy by visiting
the contiguous bytes already retained in each QUIC receive stream. The first
callback-scoped version committed flow-control credit through the existing
nonblocking retry path. Five fixed-binary, order-interleaved 16-connection,
16-MiB-total upload pairs measured 53.732-62.595 MiB/s (59.810 median) for
the retained copying path and 46.512-62.856 MiB/s (51.846 median) for the
borrowed path. The candidate won 2/5 pairs and its median was 13.3% lower.
Every arm verified 16,777,216 bytes, checksum 2,139,095,040, all sixteen
connections, and the completion exchange. One exploratory candidate smoke
also received 27,166 datagrams versus the previously recorded 14,758 for this
shape, but later packet counts varied; that observation is retained only as a
warning that receive-credit timing can change wire work, not as a causal ratio.

A narrower correction used exactly the old transactional
releaseReceivedCapacity path after the borrowed callback, preserving the
ordinary MAX_DATA/MAX_STREAM_DATA send timing. Four-connection smoke then
matched the retained path at 1,112 received upload datagrams. Two fixed-binary
16-connection ABBA pairs nevertheless favored the retained upload path both
times: parent measured 46.340/66.429 MiB/s and candidate measured
42.949/54.673 MiB/s. The untouched server-sender control split 1/2, confirming
substantial host variance but providing no evidence for an upload gain. Both
borrowed APIs, their tests, and the benchmark integration were fully removed;
the transport retains its existing explicit availableReceivedStream plus
releaseReceivedCapacity primitives for callers whose ownership model already
makes that tradeoff worthwhile.

The next shared-loop step follows Quinn's bounded receive-cycle design: one
bounded receive operation drains already-ready UDP messages nonblocking, or
waits for one when the socket starts empty, into a reusable caller buffer. The
portable Zig Threaded backend still invokes
`recvmsg` once per datagram (this is not a false `recvmmsg` claim), but the
batch amortizes deadline setup, polling, dispatcher entry, and application-loop
scheduling. Netz exposes the limit through
`Endpoint.receiveManyBytesInto*`, `Dispatcher.receiveManyVisitingWithDeadline`,
and `Server.receiveManyVisitingWithDeadline`; the benchmark defaults to the
same 32-message Unix batch width used by the audited Quinn checkout. Existing
GRO APIs remain separate because their segments share one source/control
record. New Initials stop the batch and retain the already-read suffix until
admission publishes its CID route; callback or protocol errors likewise retain
the unprocessed suffix, preventing batch-only packet loss. Tests cover warmed
zero-allocation established batches, callback-error recovery, Initial admission
ordering, deadline validation, and the real two-client handshake server path.

The benchmark now records and strictly verifies `server_receive_batch`, and
rejects summaries that mix batch sizes. A same-binary five-sample comparison
of the verified four-connection, 4 x 1-MiB upload measured batch 1 at
66.467-80.259 MiB/s (70.990 median) and batch 32 at 51.544-97.483 MiB/s
(86.325 median), a 21.6% median gain. The low batch-32 outlier is retained
rather than discarded. Separate batch-16/32 exploration reached 94.287 and
99.341 MiB/s medians in quieter samples, supporting 32 as the bounded default
without treating those non-paired runs as the headline ratio. Batch-32 scaling
smokes verified 8 MiB over eight connections at 92.107 MiB/s median and 16 MiB
over sixteen connections at 78.435 MiB/s median, with exact byte, checksum,
connection-completion, and DONE/DONE_ACK validation in every run.

Profiling the 16-connection shared server exposed another scaling cost in its
handshake-completion channel. The queue previously stored the roughly 9-KiB
EstablishedConnection inline, reserving about 1.1 MiB for the default 128
pending handshakes and copying the value through worker, queue, poll, and final
stable allocation. GDB samples during steady-state receive repeatedly stopped
in a 9,064-byte completion temporary clear, and ReleaseFast disassembly showed
about a 41.6-KiB stack frame for the batch receive wrapper. The endpoint owner
now preallocates the final stable connection, the worker constructs directly
into it, and the completion queue transfers only a success/failure tag through
a record statically capped at four machine words. The receive wrapper stack
fell to about 24.5 KiB, while the default completion queue's element storage
is capped at 4 KiB. The final connection allocation count is unchanged.

Five order-interleaved 16-connection, 16-MiB total uploads measured
71.515-85.421 MiB/s (79.110 median) with the pointer queue and
70.240-85.514 MiB/s (77.489 median) with the inline queue. The 2.1% higher
candidate median and overlapping ranges do not establish a throughput gain;
the change is retained for the approximately 280x bounded queue-memory
reduction and smaller hot receive stack, not presented as a throughput win.
Every run verified 16,777,216 bytes, checksum 2,139,095,040, all 16
connections, and the completion exchange.

Once all handshake workers have been consumed, the server now uses the atomic
active-worker count to bypass the empty completion queue, empty admission-map
expiry scan, and 5-ms handshake-poll deadline cap. A newly admitted Initial
increments the count before its worker can run, and a completed worker remains
counted until its queue record is consumed, so zero cannot hide pending
handshake work. Five order-interleaved comparisons against the pointer-queue
baseline, again using 16 connections and 16 MiB total, measured
62.892-83.443 MiB/s (68.005 median) with the idle-handshake fast path and
61.822-80.120 MiB/s (62.878 median) without it, an 8.2% median increase. The
ranges overlap, so this is supporting regression evidence rather than a broad
throughput claim; focused tests separately cover both zero and nonzero worker
states and real concurrent handshakes.

The batch dispatcher now also accepts an already-composed std.Io.Timeout. The
server validates the public caller deadline once, applies any active handshake
cap, and passes that absolute timestamp through without a second awake-clock
validation/read in the dispatcher. Public deadline entry points still reject
expired or cross-clock timestamps, and the timeout entry point also supports
the unbounded form used by lower-level event loops. Five order-interleaved
16-connection, 16-MiB comparisons against commit 8035e52b measured
63.805-87.090 MiB/s (74.840 median) after this change and
64.986-78.193 MiB/s (70.608 median) before it, a 6.0% median increase. The
ranges overlap, so the result supports removing duplicate per-batch work but
is not treated as an independent throughput claim.

The bench-quic-endpoint-pending executable measures the dispatcher's
pre-socket check for application packets retained by a completed handshake.
Its original full connection-table scan measured 71.60-76.33 ns at 16
connections, 570.78-617.82 ns at 128, and 4822.24-5121.12 ns at 1,024, while a
direct known-handle empty check stayed at 6.19-8.16 ns. Connections now notify
a dispatcher-owned ready index when `preloadReceivedDatagram` changes their
single pending slot from empty to occupied. Registration reserves the index
capacity before binding the no-allocation callback; replacement transfers the
binding, and unregister/deinit remove it before connection storage can move or
expire. This preserves direct post-registration preload users as well as the
usual handshake-promotion path without an O(connection count) fallback scan.
Three CPU-0 ReleaseFast runs with the same anti-elision barrier measured empty
index lookup at 0.88-0.96 ns for 1 connection, 0.76-0.79 ns for 16, 0.76 ns
for 128, and 0.76-0.77 ns for 1,024. Matching parent-commit runs measured
6.77-7.46, 70.29-76.24, 568.62-603.95, and 4794.96-5124.73 ns. The
1,024-connection medians therefore fell from 4848.59 to 0.76 ns (about 6,380x).
This is an isolated idle-dispatch cost result, not an end-to-end throughput
claim. A post-change shared-server smoke transferred 16,777,216 bytes in each
direction across sixteen connections with the exact 2,139,095,040 checksum and
completion exchange. Its single upload/download samples were 81.016 and
114.163 MiB/s, respectively, so they are retained as reliability evidence, not
as an independent throughput result.

Raw QUIC now also exposes `Connection.sendWithTimeout` and
`Connection.sendWithDeadline` for bounded STREAM/control sends that may need
peer flow-control or congestion progress. The helper keeps one absolute
awake-clock budget, services connection timers, applies ACK policy to packets
consumed only for progress, and leaves unrelated application data buffered.
The persistent benchmark previously freed those progress packets without ACKing
them. In multi-connection uploads, reliable MAX_DATA/MAX_STREAM_DATA packets
could consequently remain in flight until the receiver's control-packet
congestion window filled: pre-fix 2 x 16-MiB runs repeatedly left one transfer
at 8,387,712 bytes, and a 16 x 9-MiB run completed only 15/16 connections with
the last at the same offset. With the bounded send helper, the same 16 x 9-MiB
shape completed upload and download with exact 150,994,944 bytes, checksum
19,251,855,360, all sixteen connections, and the completion exchange. The
single post-fix samples were 41.516 MiB/s upload and 75.123 MiB/s download, so
this is reliability evidence across the initial 8-MiB connection window, not a
comparative throughput claim. Interop utilities that intentionally consume
packets only to advance transport state now use the state-only ACK-applying
receive path for the same reason. Receive reassembly also now measures its
bounded live window from the application read cursor, forcing compaction when
a retained consumed prefix would otherwise make a valid in-window frame look
oversized. Finally, an orphaned reliable recovery group whose sent copies are
all marked lost exposes a stable immediate PTO instead of recomputing "now"
on every scheduler query. With all three corrections, three consecutive
16 x 9-MiB bidirectional runs completed exactly; upload measured
51.206-51.988 MiB/s (51.973 median) and download 81.235-90.804 MiB/s
(83.065 median). A further 16 x 16-MiB run completed 268,435,456 bytes per
direction with checksum 34,225,520,640. These results remain
same-application-shape reliability data rather than a cross-stack throughput
claim.

The shared persistent benchmark now emits strictly checked receive-loop and
socket counters so future work can distinguish configured batch width from
actual batching. One verified 16-connection, 16-MiB upload with a configured
batch of 32 used 12,665 receive calls for 14,758 UDP datagrams, only 1.17
datagrams per call on average, while still reaching a maximum of 23. It
returned 14,743 events: 14,710 packets, 16 connections, and 17 timers. The
endpoint sent 14,785 datagrams / 605,774 UDP payload bytes and received
17,446,671 bytes. The checker requires event-class totals to match, one or more
events per successful call, connected events to match the requested connection
count, returned-event maxima to fit the configured bound, and accumulated
received datagrams to equal the endpoint socket counter. A high-level call can
read more than one socket batch when an entire batch is discarded or handed to
pending handshake workers, so its datagram maximum is reported but not bounded
by the per-socket batch size. This shows that batching
captures bursts but the typical call is close to a singleton, so reducing
per-call dispatcher work is higher leverage than increasing the batch width.

The same shared harness can now isolate the server's local ACK cadence with
the server-ack-every and server-ack-delay-us options; both values are recorded
in the client result, server completion, and summary, and mixed-policy result
sets are rejected. TLS-handshake-established connections and this benchmark
now default to an ACK after every second ack-eliciting application packet or
25 ms, whichever comes first. This matches the RFC 9000 recommendation and the
default cadence used by the audited Quinn and tquic implementations. The
low-level one-RTT ConnectionConfig deliberately retains its historical 1/0
default for callers that do not drive transport timers. ACK-policy overrides
remain limited to the shared netz/netz topology so cross-peer comparisons
cannot silently change shape.

Five verified 16-connection, 16-MiB samples measured 68.146-84.832 MiB/s
(77.088 median) with the historical 1/0 policy and 70.167-88.472 MiB/s
(77.220 median) with 2 packets / 25 ms. The throughput ranges overlap, so this
does not establish a throughput improvement. The 2/25-ms policy did reduce
server UDP sends from 14,780-14,787 to 7,456-7,460, approximately 49.6%, while
all samples retained exact bytes, checksum, connection completion, and the
DONE/DONE_ACK exchange. Default-path smoke runs without explicit ACK options
also completed at 1, 4, and 16 connections and recorded the expected 2/25-ms
policy; the 16-connection run sent 7,454 server datagrams at 76.832 MiB/s.

Short-delay concurrency exposed a separate issue: 2 packets / 1 ms succeeds
for one connection but originally timed out for four and sixteen connections.
The endpoint timer selector allowed a stale ACK-delay deadline to outrank the
close lifecycle after an application close; servicing it attempted a normal
ACK in closing state and surfaced ConnectionClosed from the shared loop. The
selector now exposes only close-response and close-expiry work while closing,
only close expiry while draining, and no timers once closed or idle-timed-out.
The previously failing four- and sixteen-connection 2/1-ms runs now complete;
the timer-aware handshake default uses 2/25 ms, while the low-level one-RTT
configuration remains 1/0 for timer-unaware callers.

Delayed ACKs also exposed a short-lived HTTP/3 completion edge. A client could
return the final response or push event with one ACK-eliciting STREAM/FIN still
behind its 25-ms timer, then stop driving receive while the server waited for
reliable-response recovery to drain. HTTP/3 packetization now opportunistically
appends that cumulative ACK to the first response packet when its frame and MTU
budgets permit; failure leaves the ACK pending and sends the application packet
unchanged. Client aggregate, multiplexed, and push completion additionally make
a nonblocking final ACK attempt before returning their terminal event. The
previously timing-out 4-stream/1-MiB download completed 5/5 runs after the fix;
throughput ranged from 45.84 to 48.33 MiB/s under visible host scheduling noise,
so this is reliability evidence rather than a throughput claim. Focused tests
cover STREAM-before-ACK wire ordering, frame-budget fallback, oversize rollback,
and clearing the delayed-ACK deadline at response and push completion.

The zio multi-message receive update exposed the complementary loss case in
the single-process transfer benchmark: its final ACK could be sent and lost,
after which the client stopped driving the connection while the server waited
for reliable response recovery. The benchmark now continues bounded HTTP/3
control polling until the server reports an empty recovery queue. A real zio
handshake regression deliberately drops that terminal ACK, requires the server
to send a PTO retransmission, and then verifies that client polling produces a
fresh ACK and lets the server finish. Five consecutive 16-MiB/four-stream runs
completed in all four upload/download and ordinary/body-batch shapes; the
download means were 65.80 and 72.32 MiB/s, respectively. These timings are
recorded only as post-fix stability evidence.

The server and dispatcher now both expose batch visitor entry points taking an
already-composed std.Io.Timeout. Public WithDeadline forms retain strict
awake-clock and expiry validation, while the shared benchmark can compose its
absolute budget once and pass it through every receive turn. Five
order-interleaved 16-connection, 16-MiB comparisons against commit b0544f2c
measured 68.192-78.576 MiB/s (69.963 median) with the server-level timeout path
and 57.507-69.848 MiB/s (67.376 median) before it, a 3.8% median increase. The
ranges overlap, so this supports removing a redundant per-call clock read but
is not treated as an independent throughput claim.

Endpoint CID mirroring now carries a monotonic revision on the fixed-size local
CID pool. Initial registration, successful NEW_CONNECTION_ID issuance, and an
actual RETIRE_CONNECTION_ID advance it; repeated retirement and failed
transactional sends do not. The dispatcher caches that revision plus the route
metadata which can change on migration. Ordinary STREAM/ACK packets therefore
skip active-CID enumeration, collision probes, router replacement, and stale
route scans with one revision/metadata comparison, while CID or path changes
still complete a full synchronization before returning the packet.
`bench-quic-endpoint-cid-sync` measures this isolated CPU cost with four active
CIDs. Three CPU-0 ReleaseFast ABBA runs over two million calls measured forced
synchronization at 627-637 ns/op and the unchanged-revision fast path at
9 ns/op, or 66.01-66.92x relative call throughput. Direct tests also assert
that a normal authenticated PING does not increment the full-sync counter,
whereas issuance and retirement each increment it exactly once. This is a
hot-path microbenchmark, not a whole-connection throughput ratio.

The bench-quic-endpoint-timers executable isolates how the endpoint timer
scheduler scales before changing its data structure. It covers ordinary
non-earliest updates, an unchanged write to the cached earliest entry, moving
that entry later, removing and rearming the earliest connection,
earliestDeadline reads, and a bounded due scan whose only due entry is at the
array tail. At one connection, operations labelled non-earliest necessarily
collapse to the sole (and therefore earliest) entry. The remove measurements
include both operations so every timed iteration starts with the same number
of armed connections.

Three CPU-0 ReleaseFast runs on the 2026-09-13 Linux AArch64 host with two
million fast-path iterations and at least 64 million examined entries per
scan-sensitive case measured:

| Connections | Non-earliest update | Unchanged earliest | Postpone earliest | Remove + rearm earliest | earliestDeadline | Bounded due scan |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 10.35-11.20 ns | 10.11-10.24 ns | 10.21-10.35 ns | 24.92-25.35 ns | 1.15-2.66 ns | 1.15-1.53 ns |
| 16 | 11.93-11.95 ns | 55.80-62.65 ns | 41.11-42.29 ns | 64.06-65.47 ns | 1.15-2.34 ns | 7.32-7.70 ns |
| 128 | 12.20-12.34 ns | 401.58-413.53 ns | 348.28-352.75 ns | 412.69-414.28 ns | 1.15-2.37 ns | 50.82-74.03 ns |
| 1024 | 11.92-11.96 ns | 3165.51-3179.04 ns | 3106.69-3110.58 ns | 3175.62-3176.15 ns | 1.15-2.60 ns | 408.43-470.82 ns |

The cached read and non-earliest update remain constant, while all three
cached-earliest mutations expose the current full-array recomputation. Most
notably, an identical timer write costs about 3.17 us at 1,024 connections even
though it cannot change ordering. This evidence makes an exact no-op update
fast path the next low-risk experiment. A heap is not yet justified: it would
also add ordering work to the measured 12 ns ordinary-update path. The bounded
due scan is intentionally linear because it provides a stable per-event-loop
snapshot, but the benchmark keeps its independent scaling cost visible.

The benchmark was then extended to distinguish three more scheduler changes.
Three CPU-0 runs after the exact-update fast path measured:

| Connections | Advance current earliest | Non-earliest becomes earliest | Remove + rearm non-earliest |
|---:|---:|---:|---:|
| 1 | 9.30-9.44 ns | 9.35-9.50 ns | 23.73-23.90 ns |
| 16 | 32.56-32.71 ns | 9.37-9.48 ns | 24.37-24.47 ns |
| 128 | 338.50-360.39 ns | 10.02-10.34 ns | 36.54-36.79 ns |
| 1024 | 3108.29-3109.39 ns | 10.00-10.08 ns | 24.52-24.85 ns |

This exposes a second unnecessary scan: moving the already-earliest timer
earlier cannot invalidate its position. In contrast, a non-earliest timer can
become earliest and a non-earliest timer can be removed in constant time. The
audited Quinn driver similarly avoids resetting an unchanged runtime timer;
tquic uses a double-ended priority queue for its multi-connection endpoint.
The local measurements do not justify adopting that queue wholesale because
it would impose logarithmic maintenance on the two fast cases above. They do
justify separately eliminating the current-earliest advance scan.

That monotonic fast path now keeps the cached index when the current earliest
timer's new deadline is equal or earlier, while still updating an observable
timer-kind change. Three adjacent CPU-0 runs reduced the 1,024-connection
advance-earliest case from 3108.29-3109.39 ns to 8.48-8.69 ns per update, a
358-367x latency reduction. At the same size, a true postponement still
measured 3106.64-3107.64 ns, a non-earliest timer becoming earliest measured
10.00-10.16 ns, and non-earliest remove-plus-rearm measured 24.49-24.52 ns.
The remaining scans therefore stay visible and the array/index design retains
its constant-time ordinary-update behavior.

An indexed binary min-heap candidate was also implemented and tested, using
the existing handle-to-slot map as its reverse index, then fully removed. At
1,024 connections it reduced a true earliest postponement from about 3.11 us
to 190.83 ns and earliest remove-plus-rearm from about 3.17 us to 224.35 ns.
However, a non-earliest timer becoming earliest increased from about 10 ns to
166.44 ns; at 16 connections the heap was slower for every measured
order-changing update/removal. Two order-reversed real 16-connection shared
server pairs were also inconclusive: heap versus array measured 85.467 versus
88.502 MiB/s, then 103.706 versus 88.340 MiB/s. With no stable end-to-end gain
and a clear cost in the ordinary small endpoint sizes, the tquic-style heap is
not retained. These rejected results delimit when a future adaptive structure
might become worthwhile instead of treating lower asymptotic complexity as a
performance claim.

An adaptive follow-up retained the unordered array below 128 armed connections
and heapified the same entry storage above that point, with a 64-entry exit
threshold. It reused the handle-to-slot map as the reverse index and pruned
future subtrees during bounded due snapshots. Five CPU-0 microbenchmark runs
at 1,024 connections reduced median earliest postponement from 3,109.39 to
195.03 ns, earliest remove-plus-rearm from 3,172.40 to 226.85 ns, and one due
entry among 1,024 from 409.23 to 4.64 ns. A non-earliest entry becoming the new
minimum rose from 10.10 to 167.36 ns, while the 16-connection array path stayed
within 2%. Deterministic model tests covered 5,000 mixed updates, removals,
threshold transitions, heap/index invariants, and exact due snapshots.

The candidate was nevertheless removed after the real shared-endpoint control.
Five order-alternated 128-connection, one-socket, 64-KiB-per-connection pairs
showed extreme host/scheduling variance and worse candidate medians: upload
18.678 versus 54.551 MiB/s and download 10.375 versus 29.150 MiB/s. Ranges
overlapped, so these values do not isolate timer cost, but they provide no
end-to-end basis for retaining the extra ordering work. The existing array and
cached-minimum implementation remains the production choice.

The evidence harness itself now permits up to 256 connections only for a
netz/netz shared-server endpoint; independent-socket and cross-stack shapes
retain the existing 16-connection cap. Its readiness reader validates the
complete comma-separated port count and terminating newline before starting
clients. Before that fix one of ten 128-connection A/B arms consumed a partial
server readiness line and failed locally with `InvalidArgument`; afterward all
ten arms completed both directions with exact 8,388,608-byte, 128/128 and
checksum 1,069,547,520 validation. This expands functional scaling evidence
and fixes a measurement race, but the wide throughput spread remains an
explicit scheduler/benchmark-stability gap.

The selected follow-up keeps the array/index design and returns immediately
when an existing connection's timer kind and deadline are both unchanged.
Three adjacent CPU-0 runs reduced the 1,024-connection unchanged-earliest case
from 3165.51-3179.04 ns to 6.78-6.90 ns per update, a 459-469x latency
reduction. The 1,024-connection ordinary non-earliest update measured
8.78-8.99 ns; a genuinely postponed earliest timer remained
3105.56-3114.79 ns and remove-plus-rearm remained 3170.05-3172.24 ns. Thus the
optimization removes only the provable no-op scan without hiding the remaining
linear operations or imposing heap maintenance on ordinary updates.

The bounded due query now checks the cached earliest deadline before scanning
the stable timer array. This preserves the bounded snapshot when any timer is
due, while making the common all-future receive turn independent of connection
count. Five CPU-0 ReleaseFast ABBA rounds against parent `1f3a5a97`, with two
adjacent samples per arm, used two million iterations at 16 connections and
62,500 at 1,024 connections. They reduced the 16-connection all-future query
from 7.31-9.03 ns/op to 0.38 ns/op. At 1,024 connections it fell from
407.25-424.34 ns/op to 0.38-0.42 ns/op. The
one-due-at-array-tail control remained 7.69-9.24 versus 7.70-9.21 ns/op at 16
connections and 408.67-410.45 versus 408.31-409.79 ns/op at 1,024, confirming
that due snapshot work stays visible. This matches Quinn and tquic's endpoint
designs, which consult the next deadline before processing timeout work.

Five fixed-binary, order-interleaved 16-connection, 16-MiB-total shared-server
pairs completed exactly in both sender directions. Client-sender throughput was
69.545-81.820 MiB/s (71.618 median) before and 51.981-87.514 MiB/s (72.599
median) after, with 3/5 pair wins. Server-sender throughput was 80.111-97.652
MiB/s (82.052 median) before and 72.933-94.584 MiB/s (84.589 median) after,
also with 3/5 wins. The wide overlapping ranges make this end-to-end no-
regression evidence, not a throughput improvement claim. Every arm verified
16,777,216 bytes, checksum 2,139,095,040, all 16 connections, and the
completion exchange.

Shared dispatcher receive timeout composition now compares absolute raw values
when the transport timer and caller deadline use the same clock. The normal
shared-server path uses the awake clock for both, so it no longer performs two
`durationFromNow` clock reads on every socket-wait turn. A focused test passes
an unusable `std.Io` and still selects both possible same-clock minima, proving
that branch is clock-read-free. A separate fixed-clock test retains the generic
cross-clock behavior, observes exactly two reads, and orders deadlines by
remaining duration rather than incomparable epochs.

Five fixed-binary, order-interleaved 16-connection, 16-MiB-total pairs against
parent `f232a0b3` completed exactly in both sender directions. Client-sender
throughput was 68.990-81.605 MiB/s (73.906 median) before and
72.643-80.460 MiB/s (76.276 median) after, with 4/5 candidate wins.
Server-sender throughput was 74.444-92.247 MiB/s (80.120 median) before and
80.281-92.579 MiB/s (83.786 median) after, also with 4/5 candidate wins. The
raw ranges overlap, so these results support removing fixed receive-turn work
but do not establish a throughput gain. Every arm verified 16,777,216 bytes,
checksum 2,139,095,040, all 16 connections, and the completion exchange.

The shared dispatcher's caller-buffer batch now also returns a bounded snapshot
of due timers instead of at most one timer per receive call. Each connection is
visited once per snapshot, so an immediately rearmed connection cannot starve
its peers or UDP receive. If PTO transmission is temporarily pacing-limited,
the endpoint replaces the already-due loss entry with the connection's exact
future pacing wake-up and continues through the snapshot; a 16-connection
pressure run caught the prior error propagation after 10/16 downloads, while
the corrected run completed all 16. Direct public-API tests cover a two-event
capacity bound, a third timer left for the next call, UDP data remaining queued
until due timers are serviced, and progress past a paced connection.

Three fixed-binary, order-interleaved comparisons against parent `d605cd55`
used the shared-server aggregate shape with 16 connections, one 1-MiB stream
per connection, and receive batch 32. In the timer-heavy server-sender direction,
the baseline used 2,800-3,368 receive calls (3,266 median) for 2,586-3,124 timer
events, while the timer-batch candidate used 1,008-1,135 calls (1,088 median)
for 2,797-3,372 timer events: a 66.7% median call-count reduction. Throughput
was 77.996-85.504 MiB/s (80.651 median) before and 75.629-87.950 MiB/s
(84.438 median) after. Client-sender throughput was 69.609-93.420 MiB/s
(79.518 median) before and 63.189-79.369 MiB/s (73.885 median) after. Both
throughput ranges overlap, and the upload median moved lower, so this is retained
as bounded scheduling/call-amortization evidence, not a throughput improvement.
Every arm verified 16,777,216 bytes, checksum 2,139,095,040, all 16
connections, and the completion exchange.

The caller-buffer independent-message receive path no longer zeroes every
ancillary-data slot before calling the I/O backend. The kernel/backend writes
the received control-message prefix and returns its exact length; unused suffixes
and unused batch slots are never parsed. This follows Quinn's Linux receive path,
which uses `MaybeUninit` ancillary storage, while preserving initialized message
descriptors. At the default batch width this removes an unconditional 2,304-byte
stack write per receive call on this Linux AArch64 ABI (4,608 bytes at the public
maximum of 64). A real four-datagram UDP regression receives ECT(0), ECT(1),
CE, and then Not-ECT in one batch, proving that control metadata neither crosses
slots nor leaks into a later unmarked datagram.

Five fixed-binary, order-interleaved 4 x 16-MiB comparisons against parent
`bcb678e7` were directionally mixed. Client-sender throughput was
32.023-42.752 MiB/s (36.655 median) before and 34.380-39.088 MiB/s
(35.953 median) after; the candidate won 2/5 pairs. Server-sender throughput was
39.733-48.835 MiB/s (46.162 median) before and 41.839-55.302 MiB/s
(48.243 median) after; the candidate won 4/5 pairs. Both ranges overlap, so no
throughput improvement is claimed; the change is retained for the definite
elimination of unused initialization and its direct ECN correctness coverage.
Every run verified 67,108,864 bytes, checksum 8,556,380,160, four completed
connections, and the completion exchange.

The persistent benchmark runner now accepts `--netz-only`, which runs the
netz/netz pair in independent topology without requiring Go or an external
fixture; its strict summary still requires both sender roles and every requested
sample. On the same final binary, three 4 x 1-MiB shared samples measured
85.365-102.847 MiB/s (96.750 median) for the client sender and
67.411-85.390 MiB/s (75.982 median) for the server sender. Three independent
samples measured 88.226-102.534 MiB/s (94.295 median) and
52.909-92.712 MiB/s (87.691 median), respectively. The resulting median ratios
are 1.026x and 0.867x, but both pairs have heavily overlapping ranges and the
topologies were not order-interleaved, so this supersedes the stale 0.717x
observation only as a current noisy baseline, not as evidence that the shared
topology has conclusively reached parity.

The topology runner now has a strict `--server-topology=compare --netz-only`
mode. It reuses one ReleaseFast executable, pins client/server to CPUs 0/1,
uses an odd sample count, mirrors independent/shared order on alternating
rounds, fixes both topologies to ACK-every=2 and 25 ms, and validates every
payload, checksum, completion exchange, backend identity, and topology before
summarizing. A 2026-09-15 five-sample zio-era run with four connections and
one 1-MiB stream per connection measured:

```text
sender          independent median  shared median  shared/independent
client             66.070 MiB/s      43.653 MiB/s       0.661x
server             63.710 MiB/s      41.337 MiB/s       0.649x
```

The independent ranges were 55.443-67.770 and 56.237-74.028 MiB/s; shared
ranges were 41.649-44.977 and 36.148-58.804 MiB/s. This is a same-stack
topology baseline that quantifies the shared endpoint scheduling gap; it is not
a cross-library speed claim.

That gap was traced below the QUIC dispatcher: zio v0.17.0 implemented the
multi-slot `std.Io` network receive operation with one `recvmsg`, so the
caller's 32-message buffer normally returned one datagram. Netz now pins zio
commit `54cb18f05d3feaec431353de85d5d10dac93d37b`, which implements the same
`std.Io.net.Socket.receiveManyTimeout` contract with native multi-slot UDP
receive (`recvmmsg` when no ancillary buffers are needed and a portable drain
fallback otherwise). Direct Linux zio/`std.Io` and QUIC-endpoint regressions
queue multiple datagrams and require one call to return all of them in order;
the latter covers the ancillary-control path used for ECN. No zio or
OS-specific API enters the QUIC layer.

A fixed-binary, CPU-0/1, five-pair shared-only A/B against the v0.17.0 binary
measured 65.915 versus 42.417 MiB/s client-sender medians (1.554x, 4/5 paired
wins) and 65.633 versus 48.363 MiB/s server-sender medians (1.357x, 3/5 paired
wins). The candidate ranges remained wide, so these are workload-specific
medians rather than a general speed claim. More directly, completed shared
runs returned as many as 32 events from one receive call, whereas the old
backend returned at most one packet event in the upload path and three total
events in the timer-heavy download path. Ten subsequent shared runs completed
both sender directions with exact 4,194,304-byte payloads, checksum
534,773,760, four completions, and DONE/DONE_ACK.

The strict topology gate was then rerun on the final candidate with the same
four connections, 1 MiB per connection, ACK/2, 25-ms delay, and mirrored
ordering:

```text
sender          independent median  shared median  shared/independent
client             70.158 MiB/s      72.318 MiB/s       1.031x
server             64.338 MiB/s      67.712 MiB/s       1.052x
```

Independent ranges were 65.909-77.678 and 61.757-69.883 MiB/s; shared ranges
were 70.069-77.274 and 44.199-69.233 MiB/s. The overlapping ranges do not show
that shared is faster, but this controlled run no longer reproduces the prior
0.661x/0.649x median deficit. The remaining work is wider connection-count and
host coverage plus capture-backed equal-wire comparison.

The endpoint CID router, CID synchronization, pending-ready-index, timer
scheduler, and receive-stream-ID benchmarks now obtain their UDP endpoint,
where needed, and monotonic clock from zio-backed `std.Io`; each prints the
runtime identity. Their historical A/B numbers below predate that runtime
migration. The endpoint CID router uses
`HashMap.getAdapted` with the borrowed CID
slice from the datagram instead of zero-filling and copying it into a 20-byte
fixed key for every lookup. Stored keys remain fixed-size and owned, and all
registration, collision, mixed-length longest-prefix, removal, long-header, and
greased fixed-bit semantics are unchanged. This follows the same parsed-CID-to-
route separation used by the audited Quinn and tquic endpoint implementations.
The new `bench-quic-connection-router` measures 64 registered 16-byte CIDs with
ten million rotating hits and same-length misses. Five CPU-0 ReleaseFast ABBA
runs reduced hit latency from 51.80-52.23 ns (51.98 median) to 28.38-29.02 ns
(28.62 median), a 44.9% reduction with 5/5 wins. Miss latency fell from
38.90-39.72 ns (39.56 median) to 11.86-13.14 ns (12.03 median), a 69.6%
reduction with 5/5 wins.

Five fixed-binary order-interleaved 16-connection, 16-MiB-total shared-server
pairs against parent `d567941f` also completed exactly. Server-sender throughput
was 73.684-87.131 MiB/s (85.021 median) before and 83.277-104.812 MiB/s
(90.453 median) after; the candidate won all five pairs and the median paired
ratio was 1.053x. Client-sender throughput was 62.231-82.841 MiB/s
(73.173 median) before and 59.452-116.552 MiB/s (86.686 median) after, with
3/5 wins. Both raw ranges overlap, so the isolated lookup result is the strong
claim and the transfer result is supporting evidence, not a whole-topology
throughput verdict. Every arm verified 16,777,216 bytes, checksum
2,139,095,040, all 16 connections, and the completion exchange.

Two adjacent scheduling experiments were rejected. Coalescing all packet/timer
events for one connection into one end-of-batch application wake-up reduced the
timer-heavy server-sender notification median by 45.8%, but reduced throughput
from 82.749 to 79.553 MiB/s and won only 1/5 pairs; immediate ACK-driven send
opportunities were more valuable than fewer callback invocations. Moving the
server send plus timer refresh behind a dispatcher wrapper also failed to show
a stable benefit and was removed. The existing per-packet application wake-up
and direct server send path are therefore retained.

The shared endpoint server now also exposes a socket-free `streamSendCredit`
snapshot for nonblocking application loops. The persistent server-sender used
to retry its full 1,152-byte payload chunk even when a stream window had a
smaller positive tail. Because `trySend` is deliberately transactional, a
1,024-byte advertised stream window left 1,008 bytes after the 16-byte prelude
and the full chunk could never commit. The sender now submits the positive
prefix allowed by connection, stream, congestion, and datagram credit; zero
credit still performs the original attempt so QUIC can emit DATA_BLOCKED or
STREAM_DATA_BLOCKED. Timeout diagnostics retain per-connection credit, cwnd,
in-flight, recovery, pacing, and next-timer state for future failures.

A fixed-binary real TLS/QUIC regression against parent `3ccbb9d3` used one
shared-server connection, a 1,024-byte stream window, and a 65,536-byte
server-originated payload. The parent timed out in `stage=payload` with offset
zero; the candidate transferred all 65,536 bytes, verified checksum 8,355,840,
and completed the DONE/DONE_ACK exchange. A 16-connection pressure run then
transferred 64 MiB per connection (1,073,741,824 bytes total), checksum
136,902,082,560, and all completion exchanges in about 195 seconds. Three
order-interleaved 16-connection, 16-MiB-total pairs were noisy: server-sender
candidate throughput was 82.035-105.988 MiB/s versus parent
78.725-102.589 MiB/s with 2/3 wins, while client-sender was
63.328-83.471 versus 70.786-100.162 MiB/s with 1/3 wins. All ranges overlap,
so the retained claim is progress/reliability, not throughput improvement.
The shared `transfer.sendPayloads` helper had the same fixed-chunk assumption
on the blocking client and independent server paths. It now consumes any
positive `SendCredit.available()` prefix before blocking for more transport
progress, while a zero-credit one-byte probe retains DATA_BLOCKED and
STREAM_DATA_BLOCKED signaling. Against parent `4fe04ace`, the same one-
connection, 1,024-byte-window, 65,536-byte shared run timed out during the
client-sender payload at offset zero; the candidate completed both sender
directions with exact bytes, checksum, and DONE/DONE_ACK. The candidate also
completed both directions in the independent topology. Three fixed-binary,
order-interleaved standard-window shared pairs were noisy: client-sender
throughput was 70.175-82.803 MiB/s (75.876 median) before and
64.423-86.394 MiB/s (77.895 median) after; server-sender was
69.777-87.339 MiB/s (79.613 median) before and 75.609-91.790 MiB/s
(82.877 median) after. The candidate won 2/3 pairs in both directions and all
ranges overlap, so this remains a correctness/progress result.
Raw `one_rtt.Connection` now exposes the reusable `sendStream`,
`sendStreamWithTimeout`, and `sendStreamWithDeadline` forms behind that fix.
They send one contiguous logical payload across exact MTU, connection, stream,
congestion, and pacing boundaries; `committed_out` reports the socket-visible
data prefix on every return, and FIN is emitted only with the last prefix.
Direct tests force a five-byte window into 4/5/3-byte chunks, resume from a
five-byte timeout prefix, validate empty FIN, and inject `NetworkDown` after a
visible first packet before retrying the exact suffix of a 2,000-byte payload.
The persistent benchmark invokes this helper only for short credit tails, so
its ordinary full-chunk fast path is unchanged. Three paired standard-window
reruns of the final benchmark path against parent `efcdd342` showed wide host
scheduling noise even though both ReleaseFast executables had identical hot-
function addresses and the benchmark source was identical. Client-sender
throughput was 65.690-79.945 MiB/s before and 67.040-72.981 MiB/s after; the
candidate won 1/3 pairs. Server-sender throughput was 69.517-86.863 MiB/s
before and 78.616-92.544 MiB/s after; the candidate won 2/3 pairs. Both ranges
overlap, so this is not treated as an API performance result; the direct
progress and retry tests are the claim.
The same raw connection surface now has `sendStreamSlices`,
`sendStreamSlicesWithTimeout`, and `sendStreamSlicesWithDeadline`. They stage
adjacent borrowed slices as consecutive STREAM frames and fill each packet
across slice boundaries without changing the connection's one-packet fairness
policy; committed bytes are reported across the logical concatenation. Direct
tests cover empty slices, a five-byte flow-credit prefix crossing a slice
boundary, offset-overflow
preflight with no packet or stream-state mutation, a socket-visible packet
prefix followed by exact suffix retry, and FIN only on the final packet.
This is a functionality/copy-avoidance result; no throughput claim is made.
The shared stateful send preflight now also charges connection and stream flow
control by each stream's new highest-offset increment rather than summing
STREAM payload lengths. Sparse offsets therefore include their gap, while
overlap and retransmission-shaped frames consume no duplicate credit. The same
transactional accounting covers single sends, partial socket batch prefixes,
and accepted 0-RTT imports; a per-batch shadow rejects conflicting FIN/final
sizes before the first packet is sent. Direct tests cover sparse and overlapping
frames, partial rollback, FIN-only stream materialization, same-packet and
cross-packet final-size conflicts, 0-RTT multi-stream reserve failure, and
0-RTT sparse/overlap accounting.

Five CPU-0 fixed-binary order-interleaved pairs against parent `aa15da55` used
the existing 32-packet raw send benchmark with 50,000 iterations per arm. For
one STREAM descriptor per packet, parent batch cost was 3,219-3,574 ns/packet
(3,499 median) and the corrected path was 3,407-3,574 ns/packet (3,530 median).
With four descriptors per packet, parent was 3,611-3,688 ns/packet (3,655
median) and the corrected path was 3,649-3,750 ns/packet (3,692 median). The
candidate won 1/5 pairs in both shapes and both ranges overlap. This records an
approximately 1% median validation cost for closing protocol correctness gaps;
it is not treated as a performance improvement.

The shared-server benchmark now negotiates draft-07 ACK_FREQUENCY instead of
silently installing a benchmark-only receive policy. Both endpoints advertise
`min_ack_delay=1000`; the client appends one ACK_FREQUENCY request to its first
non-empty 1-RTT packet, while the server deliberately does not make the reverse
request. The wire Ack-Eliciting Threshold is a tolerance, not the local trigger
count: wire value 3 requests an ACK on the fourth ack-eliciting packet. The
receive path now performs that `+1` conversion with saturation. The requested
maximum ACK delay remains the peer's transport-parameter value, so the policy
does not lengthen PTO. Low-level keyed connections retain their 1/0 defaults,
and handshake users must opt in to sending the request after peer capability is
known.

Five fixed-binary, order-interleaved 16-connection, 16-MiB-total pairs compared
parent `017a3473` with server ACK/2 against the negotiated client request for
server ACK/4. The parent and candidate executable SHA-256 values were
`a17c6f4596040cd9a230e24dee0c5b1c81fdbb9d966ff2e7cc8f922e6484c593`
and `7a0d8fc6897283145071a3c117d2cf6db59098e8fcab36a97c9bd0eac282b672`.
Client-sender samples were 65.267, 56.383, 57.579, 66.328, and 57.252
MiB/s for the parent versus 90.483, 76.974, 68.014, 81.159, and 55.224
MiB/s for the candidate. Their medians were 57.579 and 76.974 MiB/s, a
33.7% increase with 4/5 paired wins. The ranges, 56.383-66.328 and
55.224-90.483 MiB/s, overlap, so this does not establish a universal or
per-run win. Server UDP sends fell from 10,579-12,304 datagrams (10,950
median) to 4,377-4,472 (4,445 median), a 59.4% median reduction.

The server-sender control retained the client's ordinary ACK behavior. Parent
samples were 78.970, 95.858, 80.281, 78.660, and 85.087 MiB/s; candidate
samples were 80.489, 87.458, 76.407, 90.833, and 85.733 MiB/s. Medians were
80.281 and 85.733 MiB/s with 3/5 candidate wins, but the ranges overlap. This
is evidence against the systematic download regression seen with bidirectional
requests, not a download speedup claim. Every arm verified 16,777,216 bytes,
checksum 2,139,095,040, all 16 connections, and DONE/DONE_ACK completion.
Direct tests additionally prove first-packet HANDSHAKE_DONE/ACK_FREQUENCY
coalescing, socket-failure retry without consuming the sequence or pending
request, PTO retransmission after a successful send, explicit-request override,
and rejection when the peer did not advertise support. A post-freeze rebuild
reproduced the candidate hash, and a two-connection shared smoke reported
ACK/4 while completing exact upload and download verification.

The follow-up recovery path now mirrors audited Quinn
`d9c8c4c695fc64292d9b117844ea6924ca0d0815`: when the peer advertised
ACK_FREQUENCY support, every application-data PTO probe also carries
IMMEDIATE_ACK so the sparse ACK policy cannot delay recovery feedback. The
hint is ack-eliciting and congestion-accounted but not retained in the recovery
payload; every later PTO creates a fresh request. A full-MTU reliable payload
keeps all data and omits the optional byte. Direct tests cover a pure-DATAGRAM
flight, single and two-probe reliable recovery, exact-MTU fallback, socket zero
progress, partial batch progress, and the original unnegotiated PING path.

A ReleaseFast real TLS/QUIC 4-MiB loss run dropped exactly 25/504 datagrams,
reported 25 transport losses, and verified all bytes. Five fixed-binary,
order-interleaved 1-MiB pairs at 5% seeded loss and 100 us configured RTT used
parent `c3f85d99` (`770015f1a18753f64449e3dd49424e1c7bfe2b155936c54e090d419c7680f546`)
and candidate
`ff0b8337cfa57c821675feb517ad732aff0232109b094ce3b842f13ce1c91a9c`.
Parent elapsed times were 10.161, 9.314, 10.213, 9.131, and 9.272 ms;
candidate times were 9.543, 9.294, 9.821, 9.946, and 9.373 ms. The candidate
won 3/5 pairs, while independently sorted medians were 9.314 and 9.543 ms and
the ranges overlap. This is protocol/recovery evidence with no throughput or
latency improvement claim. Every arm deterministically dropped 6/126
datagrams, reported six transport losses, and verified 1,048,576 bytes.

ACK_FREQUENCY requests can now also select an explicit Requested Max Ack Delay
instead of inheriting the peer transport parameter. This follows Quinn's PTO
safety rule: a larger request widens application-data PTO only after the packet
is socket-visible; while several requests are unconfirmed, PTO retains their
maximum possible delay; an ACK covering any copy of the newest recovery group
commits that value and may then lower the bound. RTT ACK-delay capping, idle
minimums, keep-alive floors, stateless-reset draining, persistent-congestion
thresholds, PTO jitter, and path resets use the same effective value. The
no-sample application-data PTO now also follows RFC 9002/Quinn's initial RTT +
4*rttvar + max_ack_delay formula: with the 100-ms initial RTT and 25-ms peer
delay it is 325 ms, rather than the former under-estimated 200 ms. Direct tests
cover 25-to-80-ms widening, an unconfirmed 10-ms downshift that remains at
80 ms, confirmation down to 10 ms, ACK of a retransmission copy, explicit
packet-number acknowledgement, invalid values below `min_ack_delay` or at the
2^14-ms limit, and socket failure leaving the original 25-ms PTO unchanged.
The shared benchmark leaves the request override null, so its established ACK/4
policy is unchanged; a post-change two-connection upload/download smoke verified
exact bytes, checksum, connection completion, and ACK/4. A new 4-MiB 5%-loss run
again dropped 25/504 datagrams, reported 25 transport losses, and verified all
bytes.

Five final-source, fixed-binary, order-interleaved 1-MiB pairs at 5% seeded
loss and 100 us configured RTT compared parent `6cd4611c`
(`aa13d564246e92a7a0c75d7fa25e35843be842e039c4d561ce47add5f058e12b`)
with candidate
`e1a73a652292414199c6b1277fbea2526785fbdfbc7b79f66f4a0f067cf8fb2a`.
Parent elapsed times were 9.409, 9.552, 9.760, 10.740, and 9.332 ms; candidate
times were 10.490, 9.699, 9.256, 9.276, and 9.390 ms. The candidate won 2/5
pairs; independently sorted medians were 9.552 and 9.390 ms and ranges overlap.
Every arm deterministically dropped 6/126 datagrams, reported six transport
losses, and verified 1,048,576 bytes. This step is retained for protocol and
recovery correctness, with no throughput or latency improvement claim.

One follow-up packet-protection shortcut was tested and rejected. The ordinary
single-packet path already computes protected length in `prepareFramesForSend`;
the candidate reused that value for sent metadata and the final sealing helper
instead of recomputing it twice. Five fixed-binary CPU-0 pairs of the
32-packet/1-KiB send microbenchmark moved sequential median only from 138,952
to 138,631 ns/batch (0.23%, 3/5 wins), while the batch control was likewise
noise-level. The parent/candidate send-benchmark SHA-256 values were
`2034af763f6044020917dfd7bb7ef41ccaec61ecf72e76a2d1ab14e86d68cac3` and
`5691f247827163eb8263da81526bf7ce56590952484217ae93e20872bbb8f284`.
Five order-interleaved 16-MiB/four-stream real TLS/HTTP/3 upload
pairs measured parent 136.50-145.20 MiB/s (142.68 median) and candidate
138.72-147.46 MiB/s (142.33 median), with 2/5 candidate wins. Every run
verified 16,777,216 bytes and status total 800; those binaries hashed to
`987d2e01b5cffee31268c01d6b8eb2dcb9cfc2b5ca825af27f3471e86ac0f3e1` and
`894c3503e775abf5cd87aa0102b98d8204404d924a5d919976cbe1701646b674`.
The implementation was removed;
these overlapping results do not justify adding another internal API parameter.

### Raw QUIC mixed FIN/reset recovery versus quic-go

The separate process gate below exercises terminal stream churn instead of
timing it:

```sh
zig build interop-quic-quic-go-churn -Doptimize=ReleaseFast
```

It runs 32- and 64-stream cases for both connection-role pairings, both
client/server sender roles, and deterministic loss/reordering, with two runs
per combination by default. Every unidirectional stream carries a 12-byte
index prelude and an acknowledged 256-byte payload prefix. Every second stream
then resets with code `0x4000 + index`; only after the receiver observes all
exact codes do the remaining streams continue to 16 KiB and FIN. A
bidirectional sibling opened before churn completes afterward, followed by
control-stream FIN in both directions and an exact application close.

All four actual sender endpoints use the same unprivileged UDP relay. The
client tells it to fault the client-to-server or server-to-client path as
appropriate, and each RESET and FIN phase deterministically incurs exactly one
drop or one completed pair reorder. The independent verifier recomputes the
payload checksum, FIN/reset counts, reset mask and error-code sum, requires both
phase counters, and cross-checks the client's cumulative counters against the
proxy. Netz additionally checks RESET final size when it is the receiver;
quic-go v0.59 exposes the exact remote stream ID and error code but not the
peer's final size through its public `StreamError`.
The raw benchmark/churn peer and its protocol tests are built from the same
repository-owned, checksum-locked Go module as the HTTP/3 fixtures; the
loss/reorder relay remains a separate process.

The captured default 32-case two-run matrix completed every case. The 32-stream
shape verified 16 FIN, 16 RESET, 266,240 application bytes, checksum
33,945,600, mask `0x00000000aaaaaaaa`, and code sum 262,400. The 64-stream
shape verified 32 FIN, 32 RESET, 532,480 bytes, checksum 67,891,200, mask
`0xaaaaaaaaaaaaaaaa`, and code sum 525,312. Each case reported two drops or
two completed reorder pairs—one in each terminal phase. This closes the former
external raw-transfer loss/reorder and mixed-churn gap. It remains bounded
loopback recovery evidence, not a throughput or equal-wire result.

### Raw QUIC handshake fault recovery versus quic-go

```sh
zig build interop-quic-handshake-fault -Doptimize=ReleaseFast
```

The gate runs 16 authenticated cases: QUIC v1/v2, both netz/client and
netz/server role pairings, both client- and server-outbound handshake
directions, and either one forced first-datagram loss or one last-ciphertext-bit
corruption. The unprivileged relay disarms after exactly one fault. Its strict
verifier cross-checks direction, implementation scope, version, and counters,
then requires both peer logs to prove certificate validation, `hq-interop`, two
exact streams, 10 echoed bytes, and application close.
The quic-go sides are the repository-owned `raw_echo_server` and
`raw_echo_client` commands in `tools/interop/quic_go_module`, pinned to quic-go
v0.59.0 by `go.mod` and `go.sum`. The runner selects a local Go toolchain and
builds them with `GOTOOLCHAIN=local` and `-mod=readonly`, so this gate no longer
borrows peer source or module metadata from a mutable `~/Work` checkout.

The first real client-loss run exposed a gap hidden by same-library injection:
netz split its post-quantum ClientHello across two 1200-byte Initial datagrams.
After offset zero was lost, quic-go ACKed the surviving suffix; netz accepted
that ACK-only Initial as handshake progress and stopped retransmitting the
ClientHello. The response filter now authenticates candidate Initials and
requires non-empty CRYPTO offset zero before leaving the PTO loop. Direct wire
tests reject ACK-only and suffix-only Initials and accept the offset-zero form.
All 16 external cases and the pre-existing complete quic-go lifecycle
matrix pass after the fix. This is deterministic recovery evidence, not a
performance or equal-wire result.

The complete `interop-quic-quic-go` lifecycle matrix is now self-contained as
well. Its repository-owned `lifecycle_client` and extended `raw_echo_server`
cover 19 process scenarios: v1/v2 echo, Retry and two key updates, reset/stop,
flow-control and stream-credit renewal, unidirectional streams, Initial and
application PTO recovery, exact application close, two-hop active migration
with and without a dropped probe response, and same-IP NAT rebinding. During
the migration-loss conversion, a delayed duplicate PATH_RESPONSE exposed an
over-strict netz receive path. Netz now ignores responses that do not match an
outstanding challenge, as Quinn, quiche, and tquic do, while retaining same-
packet STREAM processing; encrypted regression coverage locks that behavior.

The same harness accepts `--stats` for process and allocator memory evidence:

```sh
zig build bench-quic-quic-go -Doptimize=ReleaseFast -- \
  --warmup=1 --iterations=3 --bytes-per-stream=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --stats
```

GNU time measures whole-process maximum resident set size for every client and
server process. This is the directly comparable cross-language metric. Netz
also wraps its explicit allocator and requires zero live bytes after teardown;
quic-go reports `runtime.MemStats` heap counters. Allocation counts, cumulative
allocated bytes, netz peak-live bytes, and Go `HeapSys` are implementation- and
runtime-specific diagnostics and are therefore not divided into cross-language
ratios. The three-measured-connection run above produced:

| Streams | Implementation workload | Process peak RSS (KiB) | Runtime allocation count | Runtime allocated bytes | Runtime peak/reserved bytes |
|---:|---|---:|---:|---:|---:|
| 1 | netz sender | 9,248-9,336 | 9,190-12,053 | 29,914,732-32,383,622 | peak live 6,301,599-6,304,088 |
| 1 | netz receiver | 3,328-3,584 | 318-341 | 1,579,928-1,603,277 | peak live 319,319-321,809 |
| 1 | quic-go sender | 26,368-26,624 | 103,129-103,674 | 29,403,816-30,041,488 | ending HeapSys 20,676,608-20,709,376 |
| 1 | quic-go receiver | 10,752-11,008 | 56,668-60,240 | 2,274,320-2,515,000 | ending HeapSys 3,932,160 |
| 4 | netz sender | 27,440-27,608 | 41,224-67,016 | 129,347,669-160,471,876 | peak live 24,982,425-25,000,639 |
| 4 | netz receiver | 6,908-7,212 | 362-393 | 12,100,091-12,331,038 | peak live 3,128,072-3,171,815 |
| 4 | quic-go sender | 51,332-51,456 | 402,043-406,112 | 106,536,616-107,394,072 | ending HeapSys 54,165,504-54,198,272 |
| 4 | quic-go receiver | 13,312-19,968 | 265,700-301,569 | 11,257,960-19,460,168 | ending HeapSys 8,060,928-12,255,232 |

Each range combines the two endpoint-role placements for that sender/receiver
workload. The verifier required all 16 process records, positive RSS and
runtime counters, the expected allocator scope, and `live_bytes=0` for every
netz process. `--stats` is opt-in: default throughput runs do not instantiate
the counting allocator, call Go `ReadMemStats`, or launch through GNU time.

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

WebTransport incremental and whole-stream pollers enumerate active QUIC receive
stream IDs through `receivedStreamIdsAfterInto`. The stable pagination contract
must survive swap-removal, but the common transport layout appends increasing
stream IDs. An ordered-tail fast path now appends those IDs directly and falls
back to the existing bounded insertion sort only after reclamation has made the
physical table unordered. The dedicated public-API microbenchmark uses 64
active receive streams and validates every sorted ID on every iteration:

```sh
taskset -c 0 zig build bench-quic-stream-ids -Doptimize=ReleaseFast -- \
  --iterations=2000000
```

Ten alternating fixed-binary pairs measured 1,083.82-1,085.17 ns/enumeration
before and 97.56-97.76 ns/enumeration after, with checksum 16,384,000,000 in
every run. Median cost fell from 1,084.55 to 97.64 ns (91.0%, 11.1x). The
ordinary one-stream WebTransport throughput guard moved only +0.17% in median,
while the 64-stream end-to-end benchmark remained dominated by a host UDP
queue bimodality and moved about -1.0% in median. Therefore this is recorded as
a verified stream-enumeration CPU reduction, not an end-to-end throughput
claim. Existing pagination tests continue to remove a stream between pages and
require the remaining IDs in order, covering the unordered fallback.

### Raw QUIC TLS 1.3 handshake latency, rate, and memory

The cross-process counterpart uses a long-running server and a fresh client
UDP endpoint plus full handshake for every sample:

```sh
zig build bench-quic-handshake-external -Doptimize=ReleaseFast
zig build bench-quic-handshake-external -Doptimize=ReleaseFast -- --netz-only
```

Both processes are pinned to distinct CPUs. Each run performs 10 untimed warmup
connections followed by 100 measured connections, repeated five times with
reversed role-pair order on alternating runs. TLS is fixed to QUIC v1, X25519,
TLS_AES_128_GCM_SHA256, and verified localhost certificates. Only the client
`connect`/`Dial` call is timed; endpoint creation, a round-indexed 16-byte
echo, application close, and teardown remain outside. Accordingly the reported
rate is explicitly `connects_per_second_from_timed_sum`, not whole-process
connection throughput. The quic-go client/server executable and its tests live
in the same repository-owned v0.59.0 module as the HTTP/3 and raw-stream peers.
The strict verifier reconstructs every total and
percentile from 100 sample records and requires a matching server completion
record for all 110 connections, 3,520 echoed bytes, checksum 5,995, and peer
close.
This benchmark's quic-go executable and unit tests are also built from
`tools/interop/quic_go_module` with `GOTOOLCHAIN=local` and
`-mod=readonly`. The full lifecycle and handshake-fault gates now use the
repository-owned raw peer commands described above as well.

The pinned Quinn revision
`d9c8c4c695fc64292d9b117844ea6924ca0d0815` now provides the same executable
four-role matrix when the audited quic-go fixture is unavailable:

```sh
zig build bench-quic-handshake-quinn -Doptimize=ReleaseFast -- \
  --samples=5 --warmup=10 --iterations=100
```

Both stacks are restricted to QUIC v1, TLS 1.3, X25519,
TLS_AES_128_GCM_SHA256, certificate verification, and disabled TLS resumption.
The runner hashes the fixed ReleaseFast netz/Quinn binaries and Quinn lockfile,
pins clients and servers to separate CPUs (the first two available by default),
and uses odd ABBA-ordered samples. A
strict matrix verifier checks that order plus every raw handshake sample,
aggregate, server completion, runtime identity, echo byte/checksum, and close.
The client keeps its fresh endpoint alive for 20 ms after the untimed echo and
100 ms after the final connection so the long-running peer observes the
already-submitted CONNECTION_CLOSE; neither grace interval enters the
connect-only timing.

The Quinn matrix now generates one CA-signed P-256 leaf and supplies the exact
same leaf and private scalar to both server implementations. The environment
record includes its DER length and SHA-256, and every client sample records UDP
datagrams/bytes at connect completion. This removes the earlier comparison's
self-signed 308-byte netz identity versus CA-signed roughly 468-byte Quinn
identity confounder. With the shared identity, both clients receive one
1,200-byte server datagram against Quinn; netz returns after two client
datagrams/1,283 bytes, while Quinn returns after three/2,538 bytes. These are
userspace UDP counters, not kernel packet capture, but they exclude extra netz
receive scheduling as the source of the fixed-Quinn-server gap.

Client-side phase timing around the production trust callback measured a
representative nine-connection median split of 0.94 ms before trust, 1.31 ms
inside X.509 path verification, and 0.94 ms after trust. The dominant repeated
operation was therefore the unchanged leaf-to-CA signature verification.
`tls.trust_cache.BundleVerifierCache` is now an opt-in, caller-owned, bounded
cache for clients that intentionally retain one trust bundle and verification
time snapshot across connections. Its SHA-256 key covers the exact server name,
chain count, and length-delimited DER bytes; only successful path checks are
cached, and TLS CertificateVerify still runs for every handshake. The Quinn
benchmark uses 64 caller-provided entries and requires one cold miss followed
by hits for every remaining connection.

A same-binary, CPU-7/client and CPU-13/server, five-pair ABBA run against a
fixed Quinn server measured the uncached path at 2.283 ms P50, 9.280 ms P99,
and 376.0 connects/s from the median timed sum. The cached path measured 1.709
ms, 6.757 ms, and 508.2 connects/s: 25.1% lower P50 and 35.2% higher derived
rate. The P99 improvement is retained as local evidence only because this host
has unrelated scheduler load.

The final shared-identity 5 x 100 matrix used netz SHA-256
`58c4fc0e50db7e57ee4e6f86d98136c2c03d2bb77fadea4508790d454c3f0666`
and Quinn SHA-256
`cd14eca7908d20123d4c822c71e1d5ca09037dfc5109688361f80dbe347ef4cd`:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + Quinn server | 1.679 ms | 8.312 ms | 550.3 |
| Quinn client + Quinn server | 1.311 ms | 3.175 ms | 738.8 |
| Quinn client + netz server | 2.272 ms | 8.013 ms | 406.6 |
| netz client + netz server | 2.055 ms | 4.462 ms | 455.8 |

Against the fixed Quinn server, the remaining netz-client P50 gap is 28.0%
(0.781x); against the fixed netz server, netz is 9.5% lower at P50 (1.105x).
The direction still depends on the server. This matrix is now equal in server
certificate bytes but remains same-security-policy rather than equal-wire: the
client packetization differs materially, as the UDP counters above show.

The next client CPU pass replaced five overlapping whole-transcript hashes with
one negotiated incremental transcript state plus cheap boundary snapshots. It
retains the exact TLS ordering for authenticated, PSK, client-certificate,
SHA-384, and SM3 paths; focused tests compare every snapshot against the former
one-shot construction. A fixed-Quinn-server 5x100 ABBA run compared the already
published cache baseline binary
`36f290466c5d7fc37c4baf05137dd584ab28a8c4f7b08ed4855f3cf663e8d5dd`
with the incremental binary
`07ed8888345aaf0b9fcb2b996d5470529855fc558d3b96b85a6964c66b759853`.
Median P50 fell from 1.586 to 1.275 ms (19.6%, four of five paired wins),
median timed-sum rate rose from 615.7 to 730.2 connects/s (18.6%), and median
P99 moved from 4.360 to 3.110 ms. The tail result remains local evidence on
this loaded host.

The final post-change shared-identity 5x100 matrix on the same CPUs used netz
SHA-256
`07ed8888345aaf0b9fcb2b996d5470529855fc558d3b96b85a6964c66b759853`
and Quinn SHA-256
`cd14eca7908d20123d4c822c71e1d5ca09037dfc5109688361f80dbe347ef4cd`:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + Quinn server | 1.136 ms | 3.797 ms | 765.8 |
| Quinn client + Quinn server | 1.051 ms | 4.628 ms | 834.1 |
| Quinn client + netz server | 1.270 ms | 6.357 ms | 675.2 |
| netz client + netz server | 1.617 ms | 3.781 ms | 593.1 |

Against the fixed Quinn server, netz is now 8.1% higher at P50 (0.925x), down
from the prior matrix's 28.0% gap. The fixed-netz-server direction measured
netz at 0.785x in this run, reinforcing that whole-pair scheduling and server
behavior still prevent an isolated client ranking. All four pairs retained the
same median connect-time UDP datagram and byte counts as before the transcript
change.

The server now uses the same incremental transcript owner. In addition to
removing its overlapping hashes, this corrected the authenticated-client
application-secret boundary to the server Finished, as required by TLS 1.3; a
P-384 mTLS test now exchanges protected STREAM data after both identities are
verified, where it previously checked only metadata. A fixed-Quinn-client
5x100 ABBA compared client-only incremental binary
`07ed8888345aaf0b9fcb2b996d5470529855fc558d3b96b85a6964c66b759853`
with both-role incremental binary
`58ad398e697d727bf32ec4a0e01df7b2a20e9eab25bcd134ccc6ada0d37d3868`.
Median P50 moved from 2.234 to 2.140 ms (4.2%, three of five paired wins),
while median timed-sum rate moved from 395.4 to 390.8 connects/s. These
conflicting small changes are treated as performance-neutral; the retained
benefit is less duplicate work and the corrected mTLS traffic-secret boundary.
The final both-role incremental 5x100 matrix used netz SHA-256
`58ad398e697d727bf32ec4a0e01df7b2a20e9eab25bcd134ccc6ada0d37d3868`: fixed
Quinn server measured netz/Quinn at 1.618/1.357 ms P50 (netz 0.839x), while
fixed netz server measured 1.972/2.201 ms (netz 1.116x). The higher absolute
latencies than the immediately preceding run demonstrate host-load sensitivity;
the same-binary A/B above remains the attribution evidence.

The historical 2026-09-16 5 x 100 full-handshake capture used netz binary SHA-256
`fbb112f461774e4edb8fa8f05f46b78af138f3ce348ffade25d3d57929d307b6`
and Quinn binary SHA-256
`931a0f03e7821268eb93cc0388d8302162304821c1987877e2f2800f683c63f1`:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + Quinn server | 2.565 ms | 6.649 ms | 375.3 |
| Quinn client + Quinn server | 1.312 ms | 2.700 ms | 741.4 |
| Quinn client + netz server | 2.208 ms | 6.551 ms | 436.2 |
| netz client + netz server | 1.517 ms | 3.340 ms | 546.5 |

Against the fixed Quinn server, netz's p50 was 1.95x higher (0.512x). Against
the fixed netz server, netz's p50 was 28.2% lower (1.393x). The direction
reverses with the server, so this establishes a concrete netz-client/Quinn
server optimization target but not a general client or server ranking. The
historical benchmark remains `same-security-policy`: executor design,
packetization, socket plumbing, and certificate representation were not
equalized. The shared-identity matrix above supersedes it for current
fixed-server comparisons.

The current netz client and server run on zio behind `std.Io`. Handshake
samples, aggregate results, and server completions carry `client_io`,
`server_io`, `endpoint_role`, and `timeout_ms`; the strict verifier rejects
missing, mismatched, legacy-backend, or wrong-owner records. A 2026-09-15
ReleaseFast 5 x 100 order-interleaved rerun produced these zio-era medians:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + quic-go server | 1.365 ms | 1.863 ms | 718.1 |
| quic-go client + quic-go server | 1.044 ms | 2.150 ms | 925.0 |
| quic-go client + netz server | 0.870 ms | 1.735 ms | 1,120.0 |
| netz client + netz server | 0.981 ms | 1.369 ms | 963.7 |

All 2,200 connections completed the authenticated echo/close exchange and all
20 result plus 20 server-completion records verified checksum 5,995. Against
a fixed quic-go server the netz-client P50 is 1.31x higher and its derived rate
is 0.78x; against a fixed netz server its P50 is 1.13x higher and rate 0.86x.
The current zio client handshake path therefore remains a concrete performance
gap. The netz/netz tail is lower in this run, but the workloads are not
equal-wire and the per-run P99 ranges overlap, so this is not a broad tail
superiority claim.

The historical 2026-09-09 CPU-0/client and CPU-1/server medians after the exact
trust-anchor and P-256 verification optimizations were:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + quic-go server | 0.609 ms | 1.009 ms | 1,608.2 |
| quic-go client + quic-go server | 0.506 ms | 1.047 ms | 1,864.7 |
| quic-go client + netz server | 0.656 ms | 1.090 ms | 1,478.7 |
| netz client + netz server | 0.749 ms | 0.787 ms | 1,332.1 |

These are complete role-pair results, not separable client/server costs. The
2026-09-09 table predates the zio migration and is retained as a
`std.Io.Threaded` baseline, not current zio performance. The
same-server comparisons leave netz's client handshake path as a concrete
remaining latency target: 1.20x the quic-go client P50 against the quic-go
server and 1.14x against the netz server in this capture. The harness does not
equalize executor implementation, syscall batching, certificate
representation, or kernel wire shape, so it is a same-security-policy
optimization baseline rather than an equal-wire or broad superiority claim.

The benchmark's one-certificate chain configures that same certificate as its
trust anchor. The former verifier still checked the anchor's self-signature
after hostname validation, adding a second P-256 verification on top of TLS
1.3 CertificateVerify. Trust-anchor signatures are not part of path
validation: possession comes from the separately verified CertificateVerify,
while configuring the anchor is the trust decision. The shared vail verifier
recognizes an exact anchor and the cross-signed form of the same Subject and
SubjectPublicKeyInfo, checks both validity intervals, and skips only the trust
anchor's issuer signature. It continues to verify every leaf and intermediate
signature; dedicated tests also reject a same-subject/different-key certificate
and expired or not-yet-valid equivalent anchors.

A same-build 3x500 A/B against the quic-go server measured the old path at
1.171 ms P50 and 845.9 derived connects/s, versus 0.741 ms and 1,331.4/s after
the change: 36.7% lower P50 and 57.4% higher rate from the timed sums. In the
canonical 5x100 capture above, the old 1.191 ms baseline fell 36.2% to 0.759
ms. A follow-up 2,000-connection `perf` sample measured 0.752 ms P50; the old
`Certificate.Bundle.verify` P-256 path had accounted for about 33% of sampled
cycles, while the optimized trust callback accounted for 0.51% and the
mandatory TLS CertificateVerify became the dominant user-space path. This
gain applies to exact-anchor deployments such as this benchmark, not to a
normal leaf-to-CA chain where the leaf signature remains mandatory.

The remaining TLS CertificateVerify profile then exposed a second independent
cost: Zig's generic ECDSA verifier computed `u1*G` and `u2*Q` separately before
adding the points even though P-256 provides a variable-time public
double-scalar primitive for exactly that verification equation. Vail's P-256
TLS verifier now uses `P256.mulDoubleBasePublic`; DER parsing, canonical/nonzero
`r`/`s` checks, the TLS 1.3 role-specific context, transcript hashing, public
key validation, and error mapping remain unchanged. Thirty-two deterministic
key/signature cases are checked against the stdlib verifier, with wrong
transcripts, zero and non-canonical scalar negatives, and a direct client-role
context test. The P-384, Ed25519, RSA-PSS, and SM2 paths are untouched.

A five-pair CPU-0 microbenchmark measured the stdlib P-256 verifier at
433.560-438.650 us and the double-scalar path at 284.567-286.806 us per
verification, a stable 34-35% reduction. The same-build external 3x500 result
then moved from the exact-anchor path's 0.741 ms P50 and 1,331.4 derived
connects/s to 0.598 ms and 1,644.6/s, another 19.2% lower P50 and 23.5% higher
rate. The canonical 5x100 result in the table measured 0.609 ms and 1,608.2/s.
Relative to the original 1.191 ms/833.7 baseline, the two changes together
lowered P50 by 48.9% and raised the timed-sum rate by 92.9%. A final
2,000-connection `perf` sample measured 0.608 ms P50 and showed
`mulDoubleBasePublic` under the mandatory CertificateVerify path, with the
eliminated trust-anchor self-verification still absent.

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

Established connections now keep reusable protected-packet, receive-datagram,
frame, and ACK-range storage together in one lifecycle module. Reliable frames
encode directly into stable recovery ownership; mixed/non-retransmittable
frames, PMTU probes, and PTO IMMEDIATE_ACK augmentation encode directly into
the final packet payload before in-place AEAD. This removes the redundant
path-sized plaintext scratch allocation entirely. It follows the reusable-
buffer principle visible in Quinn's endpoint `RecvState` and tquic's endpoint
receive loop, plus quiche's caller-output send interface, while retaining
netz's connection-local ownership and zio/`std.Io` boundary. Direct tests
decrypt the mixed-frame wire result and cover scratch-init allocation rollback.
The implementation and dedicated tests live in `src/quic/one_rtt/scratch.zig`
and `src/quic/one_rtt/tests/scratch.zig`.

In a 100-iteration local client+server handshake run with server verification
skipped, the fixed baseline used 8,001 allocations, 14,469,287 cumulative
bytes, and an 88,289-byte peak. The direct-encoding build used 7,801 allocations,
11,773,513 cumulative bytes, and a 61,333-byte peak: 2.5% fewer allocations,
18.6% fewer allocated bytes, and a 30.5% lower peak. With P-256
CertificateVerify enabled, the corresponding counts were 8,501 to 8,301,
14,507,829 to 11,812,274 bytes, and 88,370 to 61,414 peak bytes.

Seven CPU-0, order-alternated, 200-handshake comparisons used baseline SHA-256
`5cbf897b6c89defa292b082265802c1a47f92a3463622e72ea7deef4ece426e1`
and candidate SHA-256
`11427ea0239aaba6c4d88d7734908e36fae2b6f3a2b7a771d74a35b66f167452`.
In quicz-aligned mode, median P50 moved from 600.753 to 596.874 us (0.6%,
4/7 wins), and median rate from 1,503.5 to 1,511.5 connections/s (0.5%,
4/7 wins). With CertificateVerify, median P50 moved from 919.422 to 912.597 us
(0.7%, 7/7 wins), while median rate moved from 1,013.7 to 1,021.3/s (0.7%,
6/7 wins). These timing differences are noise-level; the supported claim is
reduced allocation and memory without a measured handshake-latency regression.
A seven-pair first-echo control moved the one-round median from 146.945 to
127.427 us with 7/7 paired wins. One 5,000-round steady-state control moved
from 16.287 to 15.519 us; it is only supporting evidence, not a broad
steady-state speed claim.

The s2n-quic process matrix now also covers cancellation reordering in both
endpoint-role directions. A reusable one-shot interop state arms immediately
before netz emits RESET_STREAM(41) or STOP_SENDING(42), holds exactly that
protected datagram, sends stream 4's complete `world` packet first, and then
flushes the held cancellation. Both the netz-client/s2n-server and
s2n-client/netz-server cases require one held datagram, peer-visible exact
error codes, sibling completion before cancellation observation, and the final
application close. The fault state and its deterministic contract test live in
`tools/interop/support/one_shot_reorder.zig`; the existing loss-retransmission
cases remain separate.

The same s2n-quic gate now includes a clean-network, bounded mixed lifecycle
in both endpoint-role directions. It opens one persistent control stream and
32 concurrent data streams, verifies a deterministic 256-byte prefix on every
stream, then alternates 16 full 16-KiB FIN completions with 16 RESET_STREAM
terminations. Reset codes are `0x4000 + stream_index`; both independent peers
must report 266,240 accepted bytes, checksum 33,945,600, reset mask
`0x00000000aaaaaaaa`, reset-code sum 262,400, and the expected application
close. The protocol implementations are isolated in
`tools/interop/support/s2n_churn*.zig` and
`tools/interop/quic_s2n/src/churn.rs`, keeping the peer entry points focused on
transport setup and scenario routing. The churn protocol now separates RESET
and FIN terminal work with authenticated control markers. Four additional
connections make netz the outbound sender as client and server, under loss and
real pair reordering. A reusable phased interceptor arms immediately before
each terminal phase and requires exactly one dropped datagram or completed
hold/flush pair in each phase. The receiver acknowledges all exact resets
before the second arm, then verifies every FIN payload before returning the
same aggregate result. This proves recovery without depending on encrypted
packet parsing; it covers netz outbound faults only and does not claim injected
s2n-quic outbound loss. This remains reliability coverage rather than a
throughput comparison.

The s2n-quic process matrix also enables its native unstable RFC 9221
DATAGRAM provider and runs a separate bidirectional DATAGRAM connection for
each endpoint-role pairing. Each peer sends two distinct small payloads and
one boundary payload, and each receiver validates the three-member set without
assuming DATAGRAM ordering. Netz advertises a 64-byte maximum DATAGRAM frame,
so s2n-quic successfully sends the exact 62-byte length-present payload and
rejects a 65-byte application payload locally as exceeding peer transport
limits. Netz uses a 1200-byte path datagram size, reports and successfully
sends its exact 1163-byte application boundary, and rejects 1164 bytes locally.
After both unreliable directions finish, client-initiated stream 4 completes a
FIN-terminated `world` echo and the peer application close is verified as 57
or 58. Both strict process cases report `zio-std-io` for the netz endpoint and
`s2n-quic-tokio` for the independent fixture. This is functional negotiation,
boundary, isolation, and lifecycle evidence; it is not a throughput result.

An independent Quinn process matrix reuses the same wire-control protocol and
runs the same two endpoint-role pairings at audited Quinn commit
`d9c8c4c695fc64292d9b117844ea6924ca0d0815`. Quinn's public
`max_datagram_size()` intentionally subtracts its conservative nine-byte
DATAGRAM frame bound from netz's advertised 64-byte limit, so the exact Quinn
payload boundary is 55 bytes and 56 bytes returns `TooLarge`. In the opposite
direction, Quinn's eight-byte short-header CID gives netz an exact 1171-byte
payload boundary for the fixed 1200-byte path, and netz rejects 1172 bytes.
Both sides again validate two distinct small payloads plus the boundary as an
unordered set, reliable stream 4, application close 57/58, certificate trust,
ALPN/SNI, and `zio-std-io` versus `quinn-tokio-rustls`. The Zig protocol is
shared in `tools/interop/support/native_datagram.zig`; the independent Quinn
adapter remains isolated under `tools/interop/quic_quinn/`. Four additional
connections make netz the outbound DATAGRAM sender as client and server under
one deterministic loss or real hold/send/flush reordering fault. Quinn requires
the loss case to omit exactly the first payload, completes the reliable stream
4 exchange, then waits another 100 ms to prove it was not retransmitted. The
reorder case requires the second small payload before the first and still
receives all three payloads. Both peers require exactly one injected fault and
the expected application close. This is functional reliability evidence, not
a performance claim, and does not inject faults into Quinn's outbound path.

The next zio receive-path step gives direct endpoint-backed handshake sources
one reusable datagram allocation. Each returned datagram keeps a scoped release
hook, so a nested flight receive falls back to the source's owning path while
the preceding bytes remain live. Routed dispatcher inboxes expose no
caller-buffer capability and retain their existing owning FIFO semantics. At
successful establishment the reader allocation transfers into the connection's
1-RTT receive scratch instead of overlapping a second path-sized allocation.
This follows Quinn's allocate-once endpoint `recv_buf` and tquic's receive buffer
outside its endpoint loop, while keeping netz's zio/`std.Io` boundary and
explicit source ownership. The reusable reader is isolated in
`src/quic/handshake/datagram_reader.zig`; tests cover reuse, nested lifetime,
owning-source fallback, transfer identity, validation failure, and allocation-
failure rollback.

The fixed baseline for this step is the preceding direct-packet-scratch binary
SHA-256
`11427ea0239aaba6c4d88d7734908e36fae2b6f3a2b7a771d74a35b66f167452`;
the final receive-reuse candidate is
`a3d4f0f7068cff7a6b5281a35e9d0a62b5f1f7233fd23335c169764394646cf8`.
In 100 fresh local client+server handshakes with verification skipped,
allocation calls fell from 7,801 to 7,001 (10.3%), cumulative allocated bytes
from 11,773,609 to 7,014,691 (40.4%), and peak live bytes from 61,333 to 52,098
(15.1%). With CertificateVerify enabled, the corresponding values were 8,301
to 7,501 calls (9.6%), 11,812,079 to 7,053,071 bytes (40.3%), and 61,414 to
52,179 peak bytes (15.0%). Both modes ended at zero live bytes. Exact 8,900-byte
allocations fell from four to two per handshake: one receive allocation per
endpoint remains and becomes that connection's established receive scratch.

Seven CPU-0-pinned, order-alternated, 200-handshake pairs showed no stable
latency change. In quicz-aligned mode, median P50 moved from 578.520 to 581.150
us (candidate 2/7 wins) while median rate moved from 1,568.2 to 1,574.3/s
(3/7 wins). With CertificateVerify, median P50 moved from 895.262 to 896.132 us
(3/7 wins), and median rate from 1,053.6 to 1,052.3/s (3/7 wins). A seven-pair
first-echo control moved from 104.528 to 106.186 us with 4/7 wins, and one
5,000-round steady control was effectively unchanged at 15.574 versus 15.575
us. These timings are noise-level controls; the supported result is lower
allocation volume and peak memory without a measured application-data
regression.

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

The current frame benchmark obtains its monotonic clock from zio-backed
`std.Io` and prints `io backend: zio-std-io`. The H1, RFC 8441, and RFC 9220
self-echo benchmarks use the same backend for both endpoints; their local
servers and concurrent H1 clients run as `std.Io` tasks, and structured result
records require `client_io=zio-std-io server_io=zio-std-io`. Numeric results in
this WebSocket section that do not explicitly say they were rerun after the
2026-09-15 migration remain historical `std.Io.Threaded` evidence.

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

On 2026-09-30, a CPU-0-pinned `ReleaseFast` fixed-binary A/B measured the
package-local encoder after replacing its byte-at-a-time contiguous match
scan with a two-block SIMD prefix scan. Seven alternating pairs produced:

```text
                              range (us/message)  median
baseline                      5.516-5.549         5.526
SIMD contiguous match scan    4.195-4.215         4.203
candidate/baseline paired ratio                  0.7605

16-slice control baseline     10.090-10.116       10.102
16-slice control candidate    10.098-10.119       10.100
```

All seven complete-message pairs favored the candidate, a 23.9% median
reduction. Every run retained the 69-byte wire payload and checksum
`8351760000`; this first A/B left the 16-slice discontiguous cursor path
unchanged. The ignored evidence directory
`zig-out/websocket-vort-match-ab/` contains the paired log and the exact
5,546,296-byte baseline plus 5,548,344-byte candidate binaries. Their SHA-256
identities are `8224fa43e4b178284c26f7d2d62ad42377b3f934cee3d69c147133ae378f37ab`
and `c12e8a08229218e57c7eafa1cad9d86ede228980697e0e4706fe3afdd4f8db36`.

A second 2026-09-30 fixed-binary A/B applies the same SIMD prefix comparison
to each pair of currently contiguous spans in the chunk cursors. It does not
join plaintext, and it advances the two cursors independently across unequal
slice boundaries and empty slices. Seven alternating CPU-0 pairs produced:

```text
                              range (us/message)  median
16-slice baseline             10.101-10.120       10.112
16-slice SIMD span scan        5.814-5.908         5.818
candidate/baseline paired ratio                   0.5758

contiguous baseline            4.197-4.222         4.200
contiguous candidate           4.199-4.204         4.201
contiguous paired ratio                            1.0000
```

All seven fragmented pairs favored the candidate, a 42.4% median reduction,
while the previously optimized contiguous control remained neutral. Every run
retained the 69-byte wire payload and checksum `8351760000`. The exact
5,548,344-byte baseline, 5,550,616-byte candidate, and final paired log are in
`zig-out/websocket-vort-chunk-match-ab/`; their SHA-256 identities are
`c12e8a08229218e57c7eafa1cad9d86ede228980697e0e4706fe3afdd4f8db36`,
`8a7f7bc3bc9a55a335f37c5471d9432aca8e9e1b0b7abf873f08dd48b458d97e`,
and `70d549525df781433c18cfdf6abda7c3d67d932db4c419df20165f80549fd47b`.

The caller-buffer path copies and masks in one SIMD pass and preserves the
caller's `[]const u8`. Binary sends additionally accept arbitrary borrowed
application slices while retaining one FIN-terminated WebSocket frame. The
header-only path is what unmasked server sends use: HTTP/1 submits bounded
header/payload vectors directly, and HTTP/2/HTTP/3 preserve the ordered slices
through their tunnel/body writers without a payload-sized plaintext join. WSS
coalesces slices into bounded TLS records; clients mask fixed stack chunks
while carrying the mask phase across every slice. Negotiated compression also
consumes the slice list as one logical message.

### Native WebSocket caller join versus direct slices

Captured on 2026-09-09 with the dedicated H1/H2/H3 self-echo gate:

```sh
zig build bench-websocket-slices-ab -Doptimize=ReleaseFast
```

The default gate pins the process to the smallest CPU in its allowed affinity
set (CPU 0 for this run), alternates `contiguous` and `slices` execution order,
and takes the median of five samples. Each sample performs 20 warmups followed
by 1,000 measured round trips with one persistent connection, no compression,
and one 4,096-byte FIN binary frame divided into eight application slices at
both endpoints. `contiguous` joins those slices into a caller-owned
preallocated buffer before immutable `sendBinary`; `slices` calls
`sendBinarySlices` directly. Neither shape uses WebSocket continuation-frame
fragmentation.

| Transport | Caller-joined median/round trip | Direct-slices median/round trip | slices / contiguous |
|---|---:|---:|---:|
| HTTP/1 upgrade | 10.391 us | 10.476 us | 1.008 |
| RFC 8441 over h2c | 11.029 us | 11.056 us | 1.002 |
| RFC 9220 over H3 | 86.039 us | 87.952 us | 1.022 |

The 2026-09-15 zio rerun used the same CPU-0, five-sample alternating shape,
20-warmup/1,000-measured, 4-KiB/eight-part configuration. Every record
identified both endpoints as `zio-std-io`, transferred 8,192,000 logical bytes,
and produced checksum 255,000:

| Transport | Caller-joined range; median | Direct-slices range; median | slices / contiguous |
|---|---:|---:|---:|
| HTTP/1 upgrade | 15.837-16.359 us; 16.042 us | 16.200-18.181 us; 16.530 us | 1.030 |
| RFC 8441 over h2c | 16.941-17.384 us; 17.057 us | 17.169-17.575 us; 17.340 us | 1.017 |
| RFC 9220 over H3 | 136.130-144.065 us; 138.932 us | 137.948-142.750 us; 141.480 us | 1.018 |

These are internal API-shape comparisons, not cross-library results. The older
table above remains useful as historical Threaded evidence; it must not be
combined with the zio ranges.

Every input sample reported 8,192,000 logical bytes and checksum 255,000. The
strict verifier also requires the exact protocol/transport, persistent
self-role pair, shape, part count, warmup/iteration count, fixed payload
schedule, disabled compression, and completion marker; it rejects missing or
even sample sets. There is deliberately no performance threshold. On this
host and workload direct slices were within 2.2% of caller joining across all
three transports while avoiding the caller-side plaintext join. Before the
transport-path optimization, the same gate measured ratios of 1.506, 1.017,
and 1.382 respectively. H1 had routed the nine header/payload vectors through
the generic eight-iovec `std.Io` path, requiring an extra write; it now uses
the existing POSIX wide-iovec path. H3 had made every application slice a
separate paced DATA contribution; its transactionally advanced cursor now
groups borrowed ranges across slice boundaries up to the same packet-sized
limit as contiguous sends. When descriptor boundaries would otherwise add a
packet, only the minimum leading prefix is copied into bounded scratch. These
are local end-to-end API-shape measurements,
not an external implementation comparison or an equal-wire/kernel-capture
claim. Different payload sizes, slice counts, kernel iovec behavior, and QUIC
packetization can move the crossover.
For a syscall-shape sanity check, `strace -f -c` over two warmups and 20
measured round trips reported 46 `sendmsg` calls for both current H1 shapes;
the pre-optimization direct-slices binary required 68. The analogous H3 trace
reported 312 `sendmmsg` calls for contiguous and 294 for direct slices; the
pre-optimization direct-slices binary required 584. These counts include
handshake and teardown traffic and therefore support only the eliminated-extra-
submission diagnosis, not a wire-byte or throughput claim.

The runner accepts `NETZ_WEBSOCKET_SLICES_SAMPLES` (odd),
`NETZ_WEBSOCKET_SLICES_WARMUP`, `NETZ_WEBSOCKET_SLICES_ITERATIONS`,
`NETZ_WEBSOCKET_SLICES_PARTS` (2 through 64), and
`NETZ_WEBSOCKET_SLICES_CPU` for reproducible follow-up sweeps.
Separate 2-, 16-, and 64-part gates completed over all three transports with
exact logical-byte/checksum validation. Their short single samples are retained
as boundary-correctness evidence only, not as performance measurements.

A direct same-input reference was compiled against
`~/Work/websocket.zig/src/proto.zig` using its stack `writeFrameHeader`, a
payload copy (needed to preserve the same immutable-input contract), and
`proto.mask`. Three same-host samples were:
The checked-in reference driver now uses zio's `std.Io` only for its monotonic
clock and reports `clock backend: zio-std-io`; the older values below predate
that migration.

```sh
zig build-exe -OReleaseFast -lc --dep proto --dep zio \
  -Mroot=benchmarks/reference/websocket_zig_frame.zig \
  -Mproto=/home/passchaos/Work/websocket.zig/src/proto.zig \
  --dep zio_options \
  -Mzio=zig-pkg/zio-0.17.0-xHbVVI_jJQC3YbgU7JydwAV7MuASkOTd73YqBaKlFFUz/src/zio.zig \
  -Mzio_options=benchmarks/reference/zio_options.zig \
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
  --dep websocket --dep counting_allocator --dep zio \
  -Mroot=benchmarks/reference/websocket_zig_echo.zig \
  --dep build \
  -Mwebsocket=/home/passchaos/Work/websocket.zig/src/websocket.zig \
  -Mcounting_allocator=examples/support/counting_allocator.zig \
  --dep zio_options \
  -Mzio=zig-pkg/zio-0.17.0-xHbVVI_jJQC3YbgU7JydwAV7MuASkOTd73YqBaKlFFUz/src/zio.zig \
  -Mbuild=benchmarks/reference/websocket_zig_build_options.zig \
  -Mzio_options=benchmarks/reference/zio_options.zig \
  -femit-bin=/tmp/bench-websocket-zig-echo
taskset -c 0 /tmp/bench-websocket-zig-echo --tcp-nodelay
```

The reference driver now gets its client I/O and clock from zio. The audited
`websocket.zig` server API still owns its documented blocking worker thread, so
that implementation detail remains part of the reference rather than being
relabeled as a zio server. The historical cross-library numbers below predate
the driver migration and are not current zio evidence.

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
The package-self-containment pass on 2026-09-10 replaced that external backend
with a focused in-tree fixed-Huffman encoder using a reusable 4K-entry hash
chain. A pinned 1,000-round 4-KiB run measured 22.296 us/roundtrip and 350.40
logical MiB/s with checksum 255,000; a 200-round direct-slices run measured
21.237 us/roundtrip. These samples preserve the 69-byte wire payload while
removing the private sibling-repository dependency.

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

A fresh 2026-09-30 zio-era syscall audit showed that batching the wire write
had not batched secure mask generation: an H1 run with five warmups and twenty
measured sixteen-frame messages made 403 `getrandom` calls. Filling sixteen
independent RFC 6455 mask keys in one CSPRNG request reduced this to 28 calls,
one per message plus three setup calls. The same bounded strategy is used by
H1, RFC 8441, and RFC 9220 batch writers.

Seven alternating CPU-0 fixed-binary pairs with fifty warmups produced:

| Workload | Baseline range / median | Candidate range / median | Paired median ratio |
|---|---:|---:|---:|
| H1 compressed, 1,000 rounds | 141.956-149.281 / 143.901 us | 69.735-71.309 / 70.876 us | 0.4929 |
| H2 compressed, 1,000 rounds | 119.854-122.356 / 121.229 us | 31.160-31.586 / 31.329 us | 0.2581 |
| H3 compressed, 500 rounds | 144.640-148.644 / 145.937 us | 55.171-59.143 / 56.293 us | 0.3833 |

Every primary pair favored the candidate and retained checksum 255,000 for H1
and H2 or 127,500 for H3. Five-pair uncompressed-fragmented controls measured
107.344 to 16.477 us median on H2 (paired ratio 0.1545) and 191.387 to 105.028
us on H3 (0.5415), showing that secure-random dispatch rather than compression
was the shared bottleneck. Fifteen-pair ordinary single-frame H2/H3 controls
had overlapping ranges and paired ratios 1.0108/1.0121; the changed batch path
is not executed there, so no single-frame result is claimed.

The ignored `zig-out/websocket-fragmented-echo-ab/` directory retains the
fixed binaries and `mask-batch-paired-final.log` with SHA-256
`db784ed3fbec15c31fda81235564dc07c9de26d6132f56f8faee9bd8906f005f`.
Baseline/candidate binary identities are respectively
`8db861f5b0552515a03863e9a9e724c078382bad188a6d3368e3c65bb69ab3c0` /
`ced67738076f3bc2dc5a40f8834d52edc6c0ff2d85ba90d46033199993587096`
for H1,
`07a71e3872c4b6087c7d3f6ebb9c0a6b4209a44ca5859b27595316dd3eec07ea` /
`1f7bb090f3c05363f25829b0a31315db7deb03847faec4c4d832915223dc1396`
for H2, and
`03cdb3961dbbf0f09eab0c862c5aff68e52ac04ac389e5a7e4b2548a846efee8` /
`489871a713a53442a140759c7cef6f7d4244795dd5d7dcdb321a6803a649f03d`
for H3.

The H1 batch was then extended to uncompressed fragmented messages. Masked
client frames whose conservative header bound plus payload fits the existing
16 KiB scratch are encoded into one bounded buffer; unmasked server frames use
borrowed payloads and groups of at most sixteen header/payload vectors. Larger
messages retain the streaming fallback. The benchmark now accepts
`--fragmented` without `--compression` and directly exercises this path.

Seven alternating CPU-0 fixed-binary pairs with fifty warmups and 1,000
measured 4 KiB round trips produced 143.041-146.236 us (144.530 us median) for
the baseline and 53.681-54.944 us (54.664 us median) for the candidate. Every
pair favored the candidate; the paired median ratio was 0.3768, a 62.3%
reduction, and every run retained checksum 255,000. Compressed-fragmented and
ordinary uncompressed single-frame controls had paired median ratios 1.0021
and 0.9987. A five-warmup, twenty-message `strace` run reduced `getrandom`
calls from 403 to 28.

The exact baseline/candidate SHA-256 identities are
`de75d747ccb06475155edd07fe5dd0d3b389ecbc3c357de251b703898cc29cdb`
and `b25278fc3c47df867d567f00be12a6632ab68f5eed0ea64f5dc46cbed54addfb`.
The ignored `zig-out/websocket-h1-fragment-batch-ab/paired-final.log` evidence has
SHA-256
`2dcaff447dd51d7a28d516c2cb8b9d7ddf55bee6af4939625d2c22d7b1d77833`.

The cross-process `bench-websocket-hyper-h2` harness runs a persistent RFC
8441 binary echo against Hyper 1.11.0 (`084473f7`) in both client/server role
pairings. Client and server are pinned to separate CPUs; h2c setup, peer
SETTINGS, Extended CONNECT, READY, and 20 warmups are outside the timed loop.
Both sides use TCP_NODELAY, fixed 1 MiB stream / 8 MiB connection windows, a
16 KiB HTTP/2 frame limit, no adaptive receive windows, no compression, and
one outstanding 4 KiB message. Client frames carry fresh random masks. Both
peers validate every round-dependent payload and require Close(1000, `done`).
The external netz endpoints obtain `std.Io` from zio. Config, result, completion
and memory records identify `zio-std-io` versus `hyper-tokio`, include the
timeout, and are rejected if timing derivatives or runtime identities disagree.
The performance and RSS numbers below were captured with the former
`std.Io.Threaded` harness and are retained as historical baselines, not current
zio performance evidence.

```sh
zig build bench-websocket-hyper-h2 -Doptimize=ReleaseFast -- \
  --warmup=20 --iterations=1000 --payload-bytes=4096 --timeout-ms=30000
```

Five CPU-0/client and CPU-1/server runs measured:

| Role pair | Latency | Logical payload throughput |
|---|---:|---:|
| netz client + Hyper server | 20.33-22.29 us/roundtrip | 350.42-384.33 MiB/s |
| Hyper client + netz server | 21.07-23.28 us/roundtrip | 335.58-370.76 MiB/s |

Every pair verified 4,096,000 bytes in each direction and aggregate checksum
522,240,000. Results belong to complete role pairs rather than isolating one
library's cost. They are `same-application-shape`, not
equal-wire: the two implementations retain distinct HTTP/2 scheduling, HPACK,
frame packing, masking, syscall, and executor behavior. No cross-library speed
ratio is inferred.

The same command accepts `--stats`. In this mode the runner builds only the
Hyper benchmark binary with its `allocation-stats` feature, wraps all four
client/server processes with GNU or BusyBox time, records the exact RSS source,
and requires one structured result, one server-completion record, two config
records and two memory records for each role pair. The
functional verifier independently recomputes the checksum across all measured
rounds, so a memory record cannot satisfy a missing echo result. Three runs of
the default 20-warmup/1,000-measured/4-KiB workload recorded:

| Implementation | Endpoint role | Process peak RSS (KiB) | Allocations | Requested bytes | Peak requested live bytes | End live bytes |
|---|---|---:|---:|---:|---:|---:|
| netz | client | 2,304 | 2,097 | 4,279,502 | 81,719 | 0 |
| netz | server | 2,048 | 2,091 | 4,279,498 | 77,109 | 0 |
| Hyper | client | 3,328 | 7,250 | 12,743,488 | 89,883 | 1,618 |
| Hyper | server | 3,328 | 7,237 | 12,723,177 | 83,756 | 1,671 |

The three runs reproduced these values exactly on this host. Whole-process
maximum RSS is the cross-language metric. Netz's explicit allocator and Rust's
global `System`-allocator requested-byte counters have different scopes and are
not treated as a cross-language allocation ratio. The netz counter starts after
argument parsing and proves zero live bytes after full H2/WebSocket/runtime
teardown. Zio executor bookkeeping intentionally uses the runtime allocator and
is excluded from that explicit protocol-allocation scope. Hyper counts from
process start; the benchmark now waits for the
server upgrade/echo task, propagates the client connection-driver result, and
drops the Tokio runtime before taking its final snapshot. Default runs do not
enable the Rust allocation feature, the netz wrapper, or an external time
wrapper.

The RFC 9220 HTTP/3 benchmark also accepts `--warmup=N` and `--iterations=N`
(defaults 20 and 200), allowing longer profiling runs without source edits.
Its QUIC timer selector and the directly invoked read-only deadline helpers now
take `*const Connection` instead of copying the roughly 7.5-KiB connection
state on every receive-loop poll. Six fixed-binary CPU-0 A/B pairs over 5,000
complete-message echoes measured 48.14-48.53 us/roundtrip versus
54.45-54.81 us (11.3-11.9% lower latency). Four fragmented pairs measured
49.48-49.61 us versus 54.33-54.81 us (8.7-9.7% lower). The corresponding perf
sample removed `nextTimerDeadline` as a visible symbol and reduced aggregate
`memcpy` samples from 9.52% to 1.58%; a compile-time receiver assertion guards
against reintroducing the by-value copy.

### RFC 9220 WebSocket versus quic-go, same application shape

`bench-websocket-h3-quic-go` extends the bidirectional correctness peer with a
persistent binary-echo workload. The peer shares the repository-owned module
that pins quic-go v0.59.0, rather than borrowing a separate quicz checkout.
Both processes are pinned to separate CPUs and use certificate-verified QUIC
v1 by default (or forced v2 via `NETZ_WEBSOCKET_H3_INTEROP_VERSION=2`), a
1280-byte steady-state MTU, 1 MiB stream /
8 MiB connection windows, no WebSocket compression, and one 4 KiB binary
message outstanding at a time. The netz endpoints now run on zio behind
`std.Io`. Config, result, server-completion, and memory records bind both
endpoint runtimes and the timeout; the strict checker also verifies the full
shape and recomputes all three timing-derived metrics. The RFC 9220 handshake
and 20 warmup echoes finish before one interval times 1,000 measured round
trips. Payload contents change with the round, and both peers independently
validate every byte; they also require a normal WebSocket Close after the timed
loop.

```sh
zig build bench-websocket-h3-quic-go -Doptimize=ReleaseFast -- \
  --warmup=20 --iterations=1000 --payload-bytes=4096 --timeout-ms=30000
```

Historical pre-zio runs on CPU 0/client and CPU 1/server measured:

| Role pair | Latency | Logical payload throughput |
|---|---:|---:|
| netz client + quic-go server | 101.80-103.39 us/roundtrip | 75.57-76.75 MiB/s |
| quic-go client + netz server | 102.25-103.34 us/roundtrip | 75.60-76.41 MiB/s |

Every process pair verified 4,096,000 sent and received application bytes and
aggregate checksum 522,240,000. The result belongs to each complete role pair;
it does not isolate either library's client or server cost. It is
`same-application-shape`, not equal-wire: netz explicitly disables GSO/GRO,
while quic-go uses implementation defaults, and ACK timing, packetization,
cipher exposure, syscall counts, and UDP datagram counts/bytes have not been
equalized. No cross-library speed ratio is inferred from the overlapping
ranges. These measurements used the former `std.Io.Threaded` harness and are
not current zio performance evidence.

A 2026-09-15 ReleaseFast zio migration smoke ran three measured 1-KiB echoes
after one warmup in both role pairings. Each pair verified 3,072 sent and
received bytes plus checksum 391,680. With memory telemetry enabled, both netz
roles ended at `live_bytes=0`, and whole-process RSS was labeled
`busybox-time-maxrss`. This is a one-sample functional and evidence-pipeline
gate, not a performance comparison.

The same command accepts `--stats`. The runner then wraps all four processes
with GNU time and requires a unique structured client result, server-completion
record, and two memory records for each role pair. The verifier independently
recomputes the checksum across the 1,000 measured rounds, so allocator
telemetry cannot stand in for a missing application result. Three consecutive
runs of the default workload recorded:

| Implementation | Endpoint role | Process peak RSS (KiB) | Allocations | Allocated bytes | Peak/ending heap detail |
|---|---|---:|---:|---:|---|
| netz | client | 3,840 | 109 | 123,880-123,912 | peak explicit live 81,977-81,990; end live 0 |
| netz | server | 3,584 | 105 | 122,331-122,372 | peak explicit live 74,471; end live 0 |
| quic-go | client | 13,056 | 104,970-105,014 | 3,301,232-3,305,576 | ending HeapSys 8,093,696 |
| quic-go | server | 13,056 | 105,480-105,538 | 3,170,472-3,183,744 | ending HeapSys 8,126,464 |

Whole-process maximum RSS is the cross-language metric. The netz explicit
allocator and Go runtime heap counters have different semantics and are not a
cross-language allocation ratio. Both netz roles reached zero explicit live
bytes after the HTTP/3, WebSocket, and former threaded runtime teardown. The quic-go
server now waits for `ListenAndServe` to exit before its final heap snapshot.
Default benchmark runs do not enable either runtime's allocation telemetry or
GNU time. These observations retain the same `same-application-shape` boundary
as the timing results above.

## MQTT 5 windowed QoS 1 broker fanout

The current driver obtains `std.Io` from zio, schedules subscriber readers in
an `std.Io.Group`, and uses events for readiness and warmup barriers. The
Mosquitto runner validates a structured result for each server, including
complete publish/delivery counts, derived rates, latency ordering, an
independently calculated checksum, and `client_io=zio-std-io` paired with
`server_io=zio-std-io` or `mosquitto-event-loop`. A 2026-09-15 default-size
migration gate completed 2,000 publishes and 4,000 deliveries against each
server with checksum 1,029,000. It was one unpinned sequential run, so it is
correctness evidence rather than a new performance comparison.
The maintained runner now derives one shared per-client queue capacity: at
least the historical 1,024-message bound and large enough for the longer of the
warmup and measured publish counts. This matches the driver's exact-delivery
contract: a smaller configured bound may legitimately drop QoS fanout after
acknowledging the publisher, leaving subscribers waiting until Keep Alive
expiry. `MQTT_MAX_QUEUED_MESSAGES` can increase, but cannot lower, the derived
capacity.
Timing, memory, and verification records expose the value as
`server_queue_capacity`.

The comparison below predates the migration and remains historical
`std.Io.Threaded` evidence.

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

Connection-local MQTT Packet Identifier state is now adaptive rather than five
embedded 65,536-bit tables. Independent incoming and outgoing maps use sparse
storage for ordinary negotiated inflight windows and promote after 1,024 live
IDs to bounded 16-KiB two-bit tables; this preserves the full identifier space,
directional reader/writer isolation, allocation-free QoS 2 stage changes, and a
32-KiB worst-case bound across both directions. Five alternating fixed-binary
32-publisher/32-subscriber runs (window 4, 64-byte payload, 10 warmups and 200
measured publishes; `0b51301a` baseline, `09825721` candidate) reduced netz
broker peak RSS from 36,348-36,364 KiB to 6,352-6,368 KiB, with all runs
completing 6,400 deliveries and checksum 356,160. This short shape is memory
evidence rather than a throughput result.
The maintained Mosquitto comparison can now set `MQTT_STATS=true` to sample
both broker processes from `/proc/PID/status` every 2 ms and emit verifier-
checked memory records. The broker now moves the 3-KiB parsed pending client
out of each finite connection coroutine and isolates large certificate,
refusal, accepted-client, and Session admission frames from the steady-state
read loop, and reserves the full live-delivery queue only before a restored or
new subscription becomes routable. The configured 1,024-delivery capacity and
allocation-free route mutation are unchanged. Seven `c3fe1516` parent/current
runs of the same fixed-binary 64-connection shape measured netz at
5,868-7,844 / 5,884-5,948 KiB, with medians falling from 6,188 to 5,932 KiB
(4.1%). Mosquitto measured 3,820-3,916 / 3,800-3,904 KiB, with medians 3,904
and 3,808 KiB. The parent's roughly 7.8-MiB netz outlier is retained in the
range. The median netz-minus-Mosquitto gap fell from 2,284 to 2,124 KiB
(7.0%). All 14 arms completed 6,400 deliveries with checksum 356,160. This
narrows but does not close the independent-peer memory gap and remains memory
evidence rather than a throughput claim.

Transient QoS 2 broker fanout now uses one lazy writer per subscribed
connection instead of making a publisher wait for every unrelated subscriber
socket. The writer starts only after a QoS 2 subscription is processed, shares
the existing per-connection write serialization, preserves PINGRESP as an
ordered output barrier, and is joined before slot reuse. Self-delivery stays on
the synchronous path so its PUBLISH precedes PUBACK/PUBCOMP on the shared
connection. A queue depth of 16 returns that destination to synchronous
backpressure before the configured hard queue/drop limit. QoS 0/1 and durable
Session delivery retain their original synchronous paths.

A fixed-binary CPU-0/client and CPU-1/server A/B used 32 publishers, 32
subscribers, MQTT 5 QoS 2, a four-message publisher window, 1,000 warmups and
10,000 measured 64-byte publishes. All fourteen arms completed 320,000
deliveries with checksum 18,656,000. Baseline/candidate throughput medians were
1,591/2,240 publishes/s; the paired candidate/baseline median was 1.417x with
7/7 wins. Paired p50 and p99 medians fell to 0.653x and 0.682x. The exact
final-binary QoS 1 five-shape matrix exercises the synchronous route and is the
current-path control; no QoS 1 speedup is attributed to this change. Three
5,000-publish RSS pairs measured transient QoS 2 medians of 6,544 KiB baseline
and 6,708 KiB candidate. Three durable-Session QoS 2 controls, which also start
no writer, measured 6,624/6,620 KiB with overlapping timing.

The retained baseline broker, candidate broker, fixed driver, and complete
paired log have SHA-256 values
`cadec82a5d73be2c98beb865f5ae9d0a7c724d66d51d04cfd6b00e34f1bfcbaa`,
`cc2c445614e2c49687c0a32281f3bb765795f3999f640014531d51539941bcad`,
`dda118b3c68c0c24f4a77ad9e3c5b939f6df17c6904de7bb131c971e07aafc36`,
and `326fec275da8588cfc4a03ce41b67bdad1344e5ba2f5bd1b17b8adb77d47d839`
respectively. The strict QoS 1/QoS 2 five-shape matrix summary hashes are
`5f32c63cbd4c0167a4f99c1b1d7f44794d9da516a5a79ee36c053996bc762574`
and `1df7a0be6e51b819ccde56b9c5d0d99e972a54f95b43cb555dde16149c18a465`.

## MQTT shared-subscription router

The maintained executable obtains its clock from zio-backed `std.Io` and names
that backend in its output. The numeric ranges below predate this migration and
remain historical Threaded evidence.

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

The authenticated burst mode now accepts `--batch-size=N` (maximum 64) and
uses the exact-prefix DATAGRAM batch sender. HTTP/3 pre-encodes all Quarter
Stream ID prefixes into reusable registry-owned storage, while QUIC reports
the socket-visible input prefix independently from packet numbers consumed by
protection. Five alternating CPU-0 ReleaseFast pairs with 1,000 35-byte
DATAGRAMs measured 2.81-3.37 MiB/s for batch size 1 and 3.49-4.10 MiB/s for
batch size 16; median throughput rose from 2.91 to 3.76 MiB/s (1.29x), and API
calls fell from 1,000 to 63. Every run received all 1,000 DATAGRAMs with
checksum 3,549,000. The benchmark raises only its own bounded receive queue to
the requested iteration count so this sender comparison does not conflate
intentional production queue eviction with kernel/socket throughput.

The multi-stream benchmark now scales connection credit with stream count and
exposes stream-window/datagram/pacing controls. Four 4-MiB streams with 1-MiB
stream windows and 8-KiB datagrams completed at 188-195 MiB/s aggregate across
three ReleaseFast runs. This replaces the earlier 26 MiB/s result whose fixed
128-KiB connection window unintentionally serialized four streams.
Read-only QUIC stream queries now borrow `Connection` instead of copying its
roughly 7.5-KiB state for every credit, stats, and active-ID pagination probe.
Five fixed-binary CPU-0 A/B pairs with the default 64-KiB stream window and a
4-MiB single stream measured 270-272 MiB/s versus 236-240 MiB/s (1.13-1.15x
throughput). Four equivalent runs with four 4-MiB streams measured 276-278
MiB/s versus 211-213 MiB/s (1.30-1.32x). The 64-MiB single-stream profile
reduced aggregate `memcpy` samples from 10.93% to 3.42%; the former copies
under incremental polling and stream-credit queries disappeared. Compile-time
receiver assertions guard the four hot query APIs. These are internal A/B
results and do not replace the differently configured 8-KiB/1-MiB-window
baseline above.

The benchmark also accepts `--loss-pct=N`. Handshake and CONNECT setup remain
reliable; a fixed-seed endpoint interceptor starts immediately before the
associated-stream phase, so STREAM/RESET_STREAM/ACK loss decisions are exactly
repeatable without conflating certificate setup. Five consecutive runs of:

```sh
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- \
  --streams=16 --transfer-bytes=16384 --stream-window=65536 \
  --reset-every=2 --reset-after-bytes=256 --loss-pct=5 \
  --send-timeout-ms=30000
```

The benchmark now keeps a bounded client transport pump alive after its last
FIN/reset so ACK, loss and PTO state continue progressing until the server has
validated every terminal event and torn down its Session. The worker calls
`serviceTransportWithTimeout` in 10 ms intervals, checks an atomic stop flag,
and is awaited cooperatively instead of canceling an in-flight UDP receive.
Handshake clients and rejected-handshake sessions also expose
`serviceTransportWithDeadline`, and the stateful protected client forwards both
bounded service APIs. This removes the prior large-stream teardown deadlock.
The send-all, fair `writeStreams`, and FIN paths share one absolute awake-clock
deadline created immediately before the associated-stream workload; the
default is 30 seconds and `--send-timeout-ms` overrides it. In single-stream
`--send-all` mode, `--stream-slices=N` selects the zero-join scatter/gather
sender. Slice descriptors are built before timing and the output includes the
selected count, so `N=1` and `N=8` provide an equivalent-byte/checksum A/B
shape. Five alternating CPU-0 ReleaseFast pairs with a 1-MiB payload and pacing
disabled measured 288-305 MiB/s for one slice and 295-307 MiB/s for eight
slices; medians were 304 and 299 MiB/s respectively (0.98x). Every run
delivered 1,048,576 bytes with checksum 133,693,440 in 287 receive events. This
small loopback sample demonstrates parity and no material vectored-path
regression; it is not a cross-library throughput claim. Five 64-stream
runs considered 320 server datagrams and dropped the
same 21 every time. All 32 reset streams reported application code 42 after
their 256-byte prefix, all 32 non-reset streams reached FIN, and every run
verified 532,480 bytes and checksum 67,891,200. Elapsed time ranged
10.656-14.923 ms (34-47 MiB/s); read-event fragmentation varied independently
from the exact terminal/byte result. This is deterministic
cancellation/recovery evidence, not an equal-wire wtransport throughput
comparison.

A fixed-binary CPU-0 liveness A/B used a 4 MiB transfer, eight input slices,
`--send-all --enable-gro-receive`, and an outer 2-second watchdog. The baseline
timed out in all 7 runs after the application transfer had completed; the
bounded-service candidate completed all 7 in 13.944-14.951 ms at 267-286 MiB/s,
with 358-359 read events and checksum 534,773,760. All 7 non-GRO control pairs
completed in both arms: the baseline median was 22.365 ms, the candidate median
was 22.216 ms, and the paired candidate/baseline median was 0.990. The result
establishes teardown liveness without claiming a throughput speedup. The fixed
baseline binary, candidate binary, and paired log have SHA-256 values
`73e897a03ed825da1538ecb0c0cf0789ab22fbc2fe57e3d853cdd3c793b12b98`,
`a9b58c65373cf4cb0eb50cee3c3ec6dcc6990bf3b265b3946220dc2127a61271`, and
`9e8f51a99d4da29f5349fcc6bfa84c422cd1641e5b2ac078652394deab0a2d3f`,
respectively.

The internal harness terminal table was subsequently raised from 64 to a
bounded 256 entries. Three 128-stream/64-KiB mixed FIN/reset runs under seeded
5% server-direction loss each delivered 64 RESET_STREAM terminals, 64 FINs,
4,210,688 bytes, checksum 536,862,720, and dropped exactly 96 of 1,540-1,545
considered datagrams. Three matching all-FIN client-direction reorder runs
delivered 8,388,608 bytes and checksum 1,069,547,520 while holding 522-524 of
2,610-2,620 datagrams. The measured loopback rates ranged 98-134 MiB/s for the
mixed loss shape and 25-28 MiB/s for reorder, but these remain scheduler- and
fault-shape-sensitive correctness observations rather than comparative
throughput claims. The external wtransport harness retains its 64-stream cap
because its independently verified wire result carries a `u64` reset mask.
Both benchmark peers now set `max_session_streams` from the requested shape;
previously the newly enlarged terminal table could accept a value above 128
while the runtime correctly rejected it at its independent default limit. At
the bounded ceiling of 256 streams, one 16-KiB mixed loss run delivered 128
RESET_STREAM terminals plus 128 FINs, 2,129,920 bytes/checksum 271,564,800, and
dropped 84 of 1,280 considered datagrams. One all-FIN client-reorder run
delivered 4,194,304 bytes/checksum 534,773,760 while holding 335 of 1,679
datagrams. The parser still rejects 257 streams before network setup.

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

The external lifecycle gate extends that evidence across both roles with the
independent audited `wtransport` implementation:

```sh
zig build interop-webtransport-wtransport-churn -Doptimize=ReleaseFast
```

It runs 32- and 64-stream cases twice in each sender direction under
deterministic loss and pair reordering. Netz's outbound direction uses its
seeded 5% endpoint interceptor; wtransport's outbound direction crosses an unprivileged
loopback UDP relay that remains transparent for the handshake and is armed
only around the RESET and FIN phases. Half the streams
deliver an acknowledged 256-byte prefix and then RESET_STREAM with application
code `0x4000 + index`; the other half continue to 16 KiB and FIN only after
wtransport has reported every reset. A bidi sibling opened before cancellation
then completes after that barrier. The independent verifier derives expected
bytes, checksum, FIN/reset counts, reset bit mask, and application-code sum from
the requested shape and also requires a real drop/hold count and peer close.
For the proxy direction it checks that both RESET and FIN phases actually hit
the selected fault and that the sender and proxy report identical counters.
The proxy now uses one deterministic single-shot arm in each terminal phase,
so every captured wtransport-sender case drops exactly two datagrams or
completes exactly two reorder pairs overall, independent of the 32/64-stream
size. Netz sends retain the seeded continuous endpoint schedule: the latest
two-run matrix dropped 11/31 datagrams or held 49/100-101 for the 32/64-stream
shapes.
The 32-stream shape verifies 266,240 bytes/checksum 33,945,600, mask
`0x00000000aaaaaaaa`, and code sum 262,400; the 64-stream shape verifies
532,480/67,891,200, mask `0xaaaaaaaaaaaaaaaa`, and code sum 525,312. This is
external recovery/lifecycle evidence for both client-outbound fault scopes,
not a production-network or throughput comparison.

### WebTransport steady stream-batch staging

`bench-webtransport-stream-batch` isolates the production steady-state batch
selection and STREAM-frame staging path from UDP queues, packet protection, and
commit bookkeeping. It registers 64 streams with varied priorities and nonzero
offsets, stages one 1-KiB slice per stream, validates the complete descriptor
checksum, and deliberately performs no socket I/O or registry mutation:

```sh
taskset -c 0 zig build bench-webtransport-stream-batch \
  -Doptimize=ReleaseFast -- --warmup=20000 --iterations=300000
```

Steady staging previously looked up every selected stream in the registry a
second time solely to recover `send_offset`. `OrderedWrite` now carries that
offset from the first lookup; staging contains no I/O, commit, or registry
mutation between the snapshot and frame construction. A direct test uses a
nonzero offset and verifies that staging neither advances it nor records sent
bytes.

Ten alternating fixed-binary CPU-0 pairs measured 1,213.699-1,245.951
ns/staging before and 1,010.843-1,135.826 ns/staging after. Median cost fell
from 1,217.593 to 1,019.589 ns (16.3%, 1.19x), with checksum 52,761,600,000 in
every 300,000-iteration run. Baseline SHA-256 was
`cf3c9d71c20908aab6c33e4f7b9ce457a9a7ffb08e204344c2def43ed271c1a0`;
candidate SHA-256 was
`60ac76743f1574180f8a4653302a2c101be1cc445fe129cbf042e58534aead2c`.
This is an internal staging CPU result, not an end-to-end throughput or
cross-library claim; the existing UDP-backed 64-stream benchmark remains the
appropriate system-level guard and remains susceptible to this host's receive
queue bimodality.

## WebTransport versus wtransport, same application shape

The external wtransport gate now has a separate benchmark mode that leaves its
existing correctness conversation unchanged. Run both implementation-role
directions on separate CPUs with:

```sh
zig build bench-webtransport-wtransport -Doptimize=ReleaseFast -- \
  --mode=stream --warmup=20 --iterations=5 --streams=1 \
  --bytes-per-stream=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000

zig build bench-webtransport-wtransport -Doptimize=ReleaseFast -- \
  --mode=datagram-pingpong --warmup=200 --iterations=5000 \
  --payload-bytes=32 --timeout-ms=30000
```

The runner selects two CPUs from its current affinity mask and pins the client
and server separately. Each pair performs a real QUIC v1/TLS/HTTP/3 CONNECT,
with every netz endpoint running on zio behind `std.Io` and the Rust peer using
its Tokio multi-thread runtime over wtransport/Quinn. Config, result,
server-completion, traffic, and memory records carry `client_io` and
`server_io`; the strict verifier rejects legacy or mismatched identities,
requires one config from each endpoint, validates the complete configured
shape, and recomputes stream throughput. Each pair then
opens one dedicated bidirectional WebTransport control stream, and validates
the fixed big-endian `CONFIG`/`CONFIG_ACK` exchange before timing. Stream
rounds open and associate every data stream before `ROUND_READY`/`GO`; the
sender writes deterministic bytes in the configured application chunks and
stops its timer only after the receiver has checked every byte and FIN and
returned checksum-bound `ROUND_DONE`. The sender then returns `ROUND_ACK`, the
receiver emits an empty reverse FIN on every data stream, and the sender
verifies those FINs before starting the next round. Reverse-half work therefore
cannot be coalesced into the timed `ROUND_DONE` packet, and bidirectional stream
lifecycle/credit is not leaked across warmups. The harness sets both QUIC
MAX_STREAMS and netz's
legacy WebTransport stream SETTINGS from the total configured workload rather
than relying on the default 16-stream cap. DATAGRAM
latency keeps exactly one request outstanding and stops each sample only after
receiving and byte-checking its matching echo. Warmups follow the same path but
are excluded from reported samples. Stream mode closes the workload with
`BENCHMARK_DONE`/`BENCHMARK_ACK`; DATAGRAM mode binds those messages to the
aggregate byte count and checksum. The client then sends
`CLOSE_READY`, receives `CLOSE_ACK`, finishes its control-stream send
direction, and requires the server FIN; the server symmetrically requires the
client FIN before finishing its direction. Netz flushes the pending transport
ACK after observing the peer FIN. Thus success and traffic snapshots no longer
depend on the former 100 ms sleep. No QUIC close frame is part of the
measurement or its success condition, preventing a transport close from
overtaking the result boundary. `--timeout-ms` bounds handshake, control, and
receive operations. Each stream round also creates one absolute awake-clock
send deadline after `GO`; every netz payload chunk and FIN reuses that timestamp.
The Rust sender uses the equivalent Tokio instant for every `write_all` in the
round. The runner's independent 180-second process deadline remains an outer
watchdog rather than the stream sender's only bound.

Output uses stable `key=value` lines and always records role pair, requested and
effective stream windows, payload/chunk shape, certificate policy, GSO/GRO,
pacing, checksum, and `complete=true`. The harness deliberately reports
`benchmark_scope=same-application-shape`, not equal-wire: both sides use a
1200-byte path MTU, QUIC v1, disabled GSO, matching advertised flow windows,
the same application chunks, and separate CPU placement. Netz explicitly
disables GRO; Quinn opportunistically enables it without a public wtransport
switch, so the Rust output records `gro=implementation-default`. The current
APIs also produce different maximum WebTransport DATAGRAM payloads (1170 for
netz and 1161 for wtransport in the smoke run) and do not expose every ACK or
packet coalescing knob. Userspace UDP accounting below quantifies the resulting
shape, while kernel/interface capture is still required before upgrading this
evidence to a strict equal-wire comparison.

ReleaseFast smoke coverage has passed in both role directions for one and four
streams at 64 KiB per stream and for ten measured 32-byte ping-pongs. The
four-stream rounds verified 262,144 logical bytes, four FINs, and checksum
33,423,360 on both receivers; ping-pong verified checksum 32,178. These short
runs establish harness correctness only and are not retained as performance
claims.

A 2026-09-15 zio migration smoke used two 64-KiB streams, one warmup, and three
measured rounds in both role pairs, followed by three measured 32-byte
DATAGRAM round trips. Each stream pair verified 393,216 aggregate bytes and
checksum 50,135,040; each DATAGRAM pair verified 128 bytes including warmup
and checksum 10,166. Both netz endpoint roles ended with `live_bytes=0`, and
the available whole-process RSS source was labeled `busybox-time-maxrss`. A
separate 32-stream churn gate passed loss and pair reordering in both sender
directions with 16 FINs, 16 resets, 266,240 bytes, checksum 33,945,600, reset
mask `0x00000000aaaaaaaa`, and code sum 262,400. These are functional and
evidence-pipeline gates, not performance comparisons.

The historical pre-zio CPU-0/client, CPU-1/server run used 20 warmups plus five
measured iterations and explicitly gave the netz endpoint the RFC 9000-style
local ACK policy of one ACK per two ack-eliciting packets or 25 ms, while
preserving an immediate ACK for reordering gaps of three packets. Five runs
(25 samples per role pair) measured 141.489-145.081 MiB/s with the wtransport
client sender and 207.671-210.863 MiB/s with the netz client sender. Four 4-MiB
streams measured 80.14-83.35 MiB/s and 194.44-195.46 MiB/s respectively; every
sample verified 16,777,216 bytes, four FINs, and checksum 2,139,095,040. The
five 200-warmup/5,000-sample 32-byte DATAGRAM ping-pong runs measured
wtransport-client p50/p90/p99/p99.9 ranges of 28.815-29.549 /
32.002-33.843 / 34.706-36.471 / 38.404-42.725 us and netz-client ranges of
29.632-29.804 / 33.207-33.807 / 34.536-35.829 / 37.897-39.480 us, with
checksum 15,084,056 in both directions. These are same-application-shape
cross-process samples, not equal-wire ratios or whole-library superiority
claims. They were captured with the former `std.Io.Threaded` netz harness and
must not be cited as current zio performance.

Five historical order-alternated A/B pairs isolated the ACK-policy change.
Both arms used the same benchmark code, workload, CPU assignment, and
`--traffic` instrumentation; A passed `--netz-ack-every=1` and
`--netz-max-ack-delay-us=0`, while B passed `--netz-ack-every=2` and
`--netz-max-ack-delay-us=25000`. Pair order alternated A/B then B/A to reduce
time-order bias. For wtransport-client + netz-server, median stream throughput
rose from 113.135 to 142.935 MiB/s (26.3%) and complete-connection datagrams
fell from 180,658-180,752 to 135,855-136,226 (about 24.8%). The opposite role
pair's median remained effectively flat, 209.520 versus 209.068 MiB/s, as
expected because wtransport remains its receiver. This is a benchmark-local
policy selection through the public handshake configuration; the library
default remains the conservative one-packet/zero-delay behavior.

Both modes also accept `--stats`. Only this opt-in path enables the netz
counting allocator, builds the Rust peer with its system-allocation wrapper,
and wraps all four processes with GNU time. The strict verifier requires the
exact number of stream sample records (or one DATAGRAM percentile record), one
separate server-completion record, and two memory records per role pair. It
independently reconstructs stream and DATAGRAM checksums, so memory output
cannot substitute for application completion. Three historical pre-zio
default-shape runs recorded the following whole-process peak RSS:

| Mode | Implementation | Endpoint role | Process peak RSS (KiB) |
|---|---|---|---:|
| 1 x 4 MiB stream upload | netz | client/sender | 10,240 |
| 1 x 4 MiB stream upload | wtransport | client/sender | 11,520-11,776 |
| 1 x 4 MiB stream upload | netz | server/receiver | 4,352 |
| 1 x 4 MiB stream upload | wtransport | server/receiver | 6,144-6,400 |
| 32-byte DATAGRAM ping-pong | netz | client | 3,840 |
| 32-byte DATAGRAM ping-pong | wtransport | client | 6,144-6,400 |
| 32-byte DATAGRAM ping-pong | netz | server | 3,840 |
| 32-byte DATAGRAM ping-pong | wtransport | server | 6,144 |

For the stream shape, netz client/server peak explicit live bytes were
6,522,634-6,523,146 and 570,488-871,368; the wtransport client/server peak
requested live bytes were 8,456,194-8,518,298 and 3,252,091-3,253,272. For
DATAGRAM ping-pong, the corresponding netz peaks were 95,067-95,092 and
55,651-55,721, while wtransport reported 3,166,100-3,166,168 and
3,154,072-3,154,140. All four netz runs in every repetition ended at zero
explicit live bytes after complete WebTransport/HTTP/3/QUIC/runtime teardown.
Rust retains about 2.2 KiB of process-global requested allocations after the
Tokio runtime is dropped; this is not treated as a leak. Whole-process maximum
RSS is the cross-language metric, and the differently scoped allocator
counters are not used as a cross-language ratio. These memory observations
retain the same `same-application-shape` boundary as the timing results.

The historical `--traffic` pass was a separate opt-in because netz's
thread-safe endpoint counters add atomic work. It joined one complete-connection
record from each endpoint after handshake, all warmup and measured work, the
benchmark
acknowledgment, `CLOSE_ACK`, and the bidirectional control-stream FIN exchange.
Netz reports successful socket I/O;
wtransport reports Quinn `ConnectionStats.udp_tx/udp_rx`. Both count UDP
payload bytes without IP/UDP headers and logical datagrams under GSO/GRO, but
this is userspace evidence rather than kernel/interface capture. Three default
runs recorded:

| Mode / role pair | Total UDP payload bytes | Total logical UDP datagrams |
|---|---:|---:|
| stream, wtransport client + netz server | 110,476,141-110,567,252 | 135,893-135,972 |
| stream, netz client + wtransport server | 108,986,418-109,001,281 | 114,967-115,318 |
| DATAGRAM, wtransport client + netz server | 827,115-827,122 | 15,623 |
| DATAGRAM, netz client + wtransport server | 826,649-826,651 | 15,625 |

The stream connection transports 25 total 4-MiB application rounds (20
warmups plus five measured). Its 1.47-1.58 MB total-payload and roughly
20.6-21.0 thousand datagram differences show that ACK/control traffic and packet
scheduling are materially different even though the application shape matches.
The DATAGRAM shapes are much closer but still not byte-identical. Endpoint
observation deltas were non-negative; Quinn-client/netz-server stream runs had
664-739 client tail datagrams (794,934-885,638 bytes) not yet observed when the
server snapshot was taken, while the reverse role pair differed by one final
1200-byte client datagram and zero to three server datagrams (0-101 bytes).
These timing-boundary deltas are printed rather than hidden. `--traffic` and `--stats` must run
separately, and neither changes the ordinary benchmark path.

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

For netz, raw QUIC STREAM and DATAGRAM throughput now have same-host,
two-process references. Persistent 1-KiB echo and four-connection aggregate
STREAM shapes also have direct quic-go controls, but remain
`same-application-shape`; the aggregate matrix exposes a netz/netz worker
scheduling bottleneck that must be addressed before a broad scaling claim.
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

The dedicated mostly-idle HTTP/1 WebSocket memory gate is reproducible with:

```sh
zig build bench-websocket-mostly-idle -Doptimize=ReleaseFast
```

It fixes websocket.zig at `efa879736bd438bea8b86a91f220ba408de57273`,
hashes both compiled binaries, and alternates three samples. All 128 connections
complete their real Upgrade and a classification echo; eight active connections
then complete two warmups and twenty measured 4-KiB round trips while the other
120 stay established. Both harnesses snapshot the same counting allocator
before any connection closes. Two independent three-sample runs were
byte-identical: netz used 340,480 live/peak bytes and websocket.zig used
1,317,836 live/peak bytes, making the reference 3.871x larger at this
explicit-allocation boundary. BusyBox `time` independently measured
whole-process MaxRSS medians of 38,912-39,936 KiB for netz and
160,256-160,768 KiB for websocket.zig, a 4.013-4.132x ratio that includes the
reference blocking server's one OS thread per connection. The strict
checker independently validates topology, workload, checksum, runtime identity,
snapshot phase, allocation arithmetic, sample cardinality, alternating order,
reference revision, binary hashes, and RSS source. Explicit allocator results
exclude runtime stacks, allocator internals, and kernel socket buffers; MaxRSS
includes the first two but not kernel socket memory. The two scopes are reported
separately.

The current-key borrowed visitor receive path now prevalidates each packet
number once and carries that fact into ACK-range commit. Ordered traffic can
extend the newest range directly; reordered packets retain the complete
bounded-range validation, duplicate rejection, range merge, and ECN accounting
paths. A deterministic tracker regression covers continuous extension, a gap,
gap closure, all ECN codepoints, and a duplicate after merge. The existing
connection-level regression independently verifies that a duplicate packet is
dropped before STREAM side effects or visitor delivery.

Five order-alternated fixed-binary runs on 2026-09-28 used the same
`bench-quic-one-rtt-receive` visitor/STREAM workload with 500 warmups and
20,000 iterations (1,080,000 packets per arm). Baseline `34c38fb4` measured
2,891-2,924 ns/packet with a 2,911 ns median; candidate `0e722992` measured
2,876-2,899 ns/packet with a 2,891 ns median. The candidate won all five pairs
and reduced the median by 0.7%. This is a same-host internal receive-hot-path
result, not an end-to-end or cross-stack throughput claim.

## Gaps before a completion audit can pass

- Extend the new cross-process raw QUIC aggregate matrix into connection-count
  scaling and a shared-socket event-loop shape. Persistent echo, four
  independent connections, fresh handshakes, transfer loss/reordering, and
  32/64-stream mixed FIN/reset churn are now covered in every relevant role
  direction.
- Capture the raw QUIC process matrix at the kernel/interface boundary on a
  host that permits pcap. The current complete-connection userspace UDP
  counters prove the existing shapes differ and therefore remain
  `same-application-shape`.
- Keep public HTTP/3 smoke (`https://robotics.bytedance.com/ --verify --head`)
  as a reachability gate, but do not treat it as a throughput benchmark.
