# Shared gRPC performance evidence

The native TCP benchmark exercises SharedChannelSender.startDuplex and the
retained writer/reader capabilities against a local netz server. Both endpoints
use zio-backed std.Io. The server checks every request byte; the client checks
every response byte and requires an OK terminal status. A result is emitted
only after the server has confirmed every message and RPC completion.

The persistent mode exchanges messages on one bidirectional RPC. Warmup,
stream admission and terminal cleanup are outside the measured interval. The
calls mode creates a fresh bidirectional RPC for each roundtrip on one shared
channel, including admission, one request/reply, request FIN, terminal status
and owning-handle destruction in that interval. Connection establishment stays
outside both intervals. All calls use identity compression. The default
65,535-byte stream receive window makes large messages exercise repeated credit
return. --stream-window and --connection-window independently set the initial
receive windows on both endpoints; --adaptive-window enables BDP growth with
--adaptive-window-max as its ceiling. Stream windows must be positive,
connection windows must be at least 65535, and benchmark windows are capped at
16 MiB. An adaptive ceiling must cover both initial windows.

Payloads use the pre-encoded string field shape of upstream EchoRequest and
EchoResponse. A zero-byte string uses the empty protobuf message. This measures
native transport work with caller-owned serialized input. Protobuf encoding is
outside time; full byte comparison and per-roundtrip latency clock reads are
inside time. Reported logical bytes count the string payload in both directions,
matching the upstream benchmark's byte count, while protobuf_bytes records its
actual serialized size.

## Reproduction and result validation

    zig build bench-grpc-shared -Doptimize=ReleaseFast -- \
      --mode=persistent --payload=4096 --warmup=100 --iterations=2000
    zig build bench-grpc-shared -Doptimize=ReleaseFast -- \
      --mode=calls --payload=262144 --warmup=100 --iterations=2000
    zig build bench-grpc-shared -Doptimize=ReleaseFast -- \
      --mode=persistent --payload=262144 --warmup=100 --iterations=2000 --stats
    zig build bench-grpc-shared -Doptimize=ReleaseFast -- \
      --mode=persistent --payload=262144 --stream-window=1048576 \
      --connection-window=1048576 --warmup=100 --iterations=2000
    zig build bench-grpc-shared -Doptimize=ReleaseFast -- \
      --mode=persistent --payload=262144 --adaptive-window \
      --adaptive-window-max=1048576 --warmup=100 --iterations=2000
    zig build test-grpc-benchmark-checker

The result record reports average wall-clock roundtrip time, roundtrips per
second, and nearest-rank p50/p95/p99 latency. The independent
tools/interop/grpc_benchmark_check.py verifier checks timing arithmetic, message
counts, protobuf/logical byte counts, terminal-call counts and runtime identity.
It requires exactly one result and one matching peer completion. Pass a saved
benchmark log as its positional argument.

Schema-two records include initial connection/stream windows, the adaptive
policy and cap, and both final stream targets observed by the server after
draining the connection. Result and peer-completion records must agree.
Fixed windows cannot change; adaptive targets must stay between the initial
stream window and its cap. Historical schema-one records retain their implicit
fixed defaults. The official comparison runner requires native fixed defaults
and rejects records from a changed window policy.

Allocation telemetry is opt-in. Its measured delta includes explicit protocol
allocations from both netz endpoints, including the shared ring consumer,
HTTP/2 framing and gRPC codec. Backend runtime allocations and pre-encoded
input/response/sample arrays use the backing allocator and are excluded.
live_bytes is the protocol allocation snapshot after the timed interval, before
stream/channel cleanup. Run allocation samples separately: the counting
allocator's synchronization can affect timings.

## Official grpc-cpp TCP comparison

Use the local grpc checkout at
03d65cc67c450ccbb58a8a45627c4da83a886ccd and build its official benchmark:

    cd ~/Work/grpc
    CC=/usr/bin/gcc CXX=/usr/bin/g++ bazel build \
      --compilation_mode=opt --lockfile_mode=off \
      //test/cpp/microbenchmarks:bm_fullstack_streaming_ping_pong
    cd /nav_env/project-z/netz
    zig build bench-grpc-cpp -Doptimize=ReleaseFast -- --cpu=0 --samples=5

The runner uses TCP BM_StreamingPingPongMsgs for the persistent mode and TCP
BM_StreamingPingPong with one ping-pong per call for the calls mode. It runs
0, 512, 4096 and 262144-byte string payloads, pins both implementations' process
threads to the selected CPU, alternates implementation order between samples,
and uses grpc-cpp's real_time wall-clock field. It starts or reuses the official
local port-allocation helper before sampling. Each reference kernel has a
200 ms minimum measurement interval; native samples use the requested fixed
iteration count after warmup.

Raw logs, reference JSON, source revisions, native worktree state, executable
SHA-256 fingerprints and summary.json are retained in a fresh temporary
directory. --output selects a new directory explicitly. --grpc-root selects
the upstream checkout; --iterations and --warmup control native samples.

These are two independently implemented TCP echo workloads. grpc-cpp includes
protobuf serialization and parsing, uses its official CompletionQueue fixture,
and retains its default HTTP/2 tuning. The native fixture uses pre-encoded
messages, explicit full-byte validation, and SharedChannel's owned events and
consumption-driven stream credit. The comparison establishes local workload
performance and exposes follow-up work; it does not establish equal packet,
allocator, threading or protobuf costs across the two stacks. TLS, concurrent
streams, compression and sustained churn require separate performance evidence.

## 2026-10-28 baseline

The clean 5726dc94 checkout passed the public bench-grpc-cpp build step with five
alternating samples on aarch64 CPU 0, using Zig 0.16.0 ReleaseFast and the pinned
grpc-cpp optimized build. Each native sample used 100 warmup and 2000 measured
roundtrips. Executable fingerprints, all native result/completion records,
reference wall/CPU times and allocation samples are retained in
[the evidence JSON](evidence/grpc_shared/2026-10-28.json).

| Native mode | String bytes | Native median us/roundtrip | grpc-cpp median us/roundtrip | Native / grpc-cpp |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 29.65 | 43.34 | 0.684 |
| Persistent RPC | 512 | 29.98 | 44.75 | 0.670 |
| Persistent RPC | 4096 | 33.30 | 49.36 | 0.675 |
| Persistent RPC | 262144 | 1011.07 | 387.68 | 2.608 |
| RPC per roundtrip | 0 | 76.65 | 123.87 | 0.619 |
| RPC per roundtrip | 512 | 77.11 | 125.75 | 0.613 |
| RPC per roundtrip | 4096 | 82.95 | 130.27 | 0.637 |
| RPC per roundtrip | 262144 | 1133.37 | 496.31 | 2.284 |

Three separate counted samples per shape used the same warmup/iteration counts.
The medians below describe the explicit allocation delta of both native
endpoints; their instrumented timings are excluded from the comparison above.

| Native mode | String bytes | Allocations/roundtrip | Requested bytes/roundtrip |
| --- | ---: | ---: | ---: |
| Persistent RPC | 4096 | 8.25 | 29026 |
| Persistent RPC | 262144 | 106.00 | 2360561 |
| RPC per roundtrip | 4096 | 26.15 | 98260 |
| RPC per roundtrip | 262144 | 122.53 | 2429783 |

The current native fixture has shorter small-message roundtrip times in these
workloads. At 256 KiB its persistent and per-call times are 2.61x and 2.28x the
reference. Native default-window waits, input chunk allocation/copying and
owned-message materialization need separate causal measurements before
selecting a production optimization. The byte totals expose allocation
pressure, but do not alone establish which cost dominates elapsed time.

A separate 199 Hz DWARF perf run captured 2051 user-cycle samples with no lost
samples over 10000 measured persistent 256 KiB roundtrips. It used the same
native executable fingerprint and validated all 10100 warmup/measured message
pairs. Profile metadata and self-symbol rows are included in the evidence JSON.
User-cycle samples show __kernel_clock_gettime at 18.55%, the benchmark's full
byte mem.eql validation at 12.73%, memcpy at 6.99% self, and the shared worker
tick at 3.48% self. zio task spawning, yielding, cleanup and scheduling are also
visible. These fractions describe sampled user work, not wall-clock waiting
or a directly comparable grpc-cpp profile. They make deadline/output-task and
window-update orchestration part of the next investigation alongside copying.

## Window isolation and credit batching

A fixed executable at clean 459d9e1f compared five window policies on CPU 0,
using 100 warmup and 1000 measured 256 KiB roundtrips in each of five samples.
Policy order reversed on alternating samples. Initial and observed final
windows, all result/completion records and binary fingerprints are retained in
[the window experiment](evidence/grpc_shared/2026-10-28-windows.json).

| Policy | Persistent us/roundtrip | Per-call us/roundtrip |
| --- | ---: | ---: |
| Fixed 65535-byte defaults | 1009.52 | 1124.61 |
| Stream 1 MiB, connection default | 996.80 | 1140.86 |
| Connection 1 MiB, stream default | 996.23 | 1080.60 |
| Both initial windows 1 MiB | 981.38 | 1122.81 |
| Adaptive from defaults, capped at 1 MiB | 969.44 | 1125.98 |

Adaptive targets grew on both endpoints and stayed within the cap. Larger
fixed windows and adaptive growth did not remove the large-message gap: the
observed changes stayed near 0-4%, while every shape still took about 1 ms.
Increasing default buffering is therefore not supported as the main remedy by
this experiment.

### Current 256-KiB window and frame-size tuning

The benchmark now accepts `--max-frame-size` and records it in both result and
peer-completion lines. Three CPU-0 pairs of 1,000 persistent 256-KiB
roundtrips compared 1-MiB stream/connection windows with 16-KiB frames against
the same windows with 64-KiB frames. Median roundtrip time fell from 741.1 to
706.5 us (4.67%) and p50 from 728.6 to 699.2 us (4.04%), with 3/3 paired wins;
p99 improved in two pairs. A single default-window reference run measured about
836 us, so the combined 1-MiB/64-KiB shape is about 15.5% faster than the
default shape for netz-to-netz traffic. This does not close the grpc-cpp
comparison: grpc-cpp advertises its own 16-KiB frame limit and window policy,
and the cross-stack fixture must keep those peer settings. The option is a
reproducible tuning path for deployments where both endpoints are netz. Full
records are in
[the frame-size evidence](evidence/grpc_shared_frame_size/2026-11-01.json).

The production shared owner now uses low-watermark connection refills and
batches consumer-acknowledged stream credit. Stream updates cover only dequeued
encoded bytes; an exhausted window flushes available acknowledged bytes even
below the batching threshold. Padding returns immediately. Legacy immediate
credit entry points retain their behavior. Wire tests verify combined update
counts, tiny-window progress, exact credit accounting and uncertain-prefix
fail-closed behavior. The HTTP/2 ClientDuplexStream remains 120 bytes.

An isolated clean cc134032 candidate was compared with clean 491a6c02 using the
same 65535-byte windows, 100 warmup and 2000 measured roundtrips. Five samples
alternated the executable order; byte validation stayed enabled and allocation
telemetry stayed disabled. Both executables include the preceding HTTP fallback
body-credit fix, so the changed code is the response-credit batching. Full
records and fingerprints are retained in
[the batching A/B](evidence/grpc_shared/2026-10-28-credit-batching.json).

| Mode | String bytes | Before us/roundtrip | Batched us/roundtrip | Speedup |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 29.82 | 18.44 | 1.617x |
| Persistent RPC | 512 | 30.04 | 18.83 | 1.595x |
| Persistent RPC | 4096 | 33.34 | 23.70 | 1.407x |
| Persistent RPC | 262144 | 1014.35 | 944.92 | 1.073x |
| RPC per roundtrip | 0 | 77.15 | 65.80 | 1.173x |
| RPC per roundtrip | 512 | 78.07 | 66.71 | 1.170x |
| RPC per roundtrip | 4096 | 82.64 | 72.84 | 1.135x |
| RPC per roundtrip | 262144 | 1137.24 | 1083.65 | 1.049x |

The retained optimization reduces window-update work and materially improves
small-message persistent streams. Large-message improvements remain 5-7% in
these samples; the earlier grpc-cpp large-message gap still requires further
deadline/output-task and data-copying analysis. These A/B figures compare two
native implementations. The external fixture was also rerun below.

The clean cc134032 public bench-grpc-cpp step then repeated five alternating
samples against the pinned official TCP kernels. It used the same CPU, native
warmup/iteration counts and pre-encoded/full-byte-validation boundaries as the
original comparison. Full native/completion and reference records are retained
in [the refreshed comparison](evidence/grpc_shared/2026-10-28-credit-grpc-cpp.json).

| Mode | String bytes | Native us/roundtrip | grpc-cpp us/roundtrip | Native / grpc-cpp |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 18.29 | 43.82 | 0.417 |
| Persistent RPC | 512 | 18.87 | 45.02 | 0.419 |
| Persistent RPC | 4096 | 23.64 | 49.79 | 0.475 |
| Persistent RPC | 262144 | 944.58 | 392.77 | 2.405 |
| RPC per roundtrip | 0 | 64.54 | 124.31 | 0.519 |
| RPC per roundtrip | 512 | 65.46 | 125.26 | 0.523 |
| RPC per roundtrip | 4096 | 71.36 | 131.46 | 0.543 |
| RPC per roundtrip | 262144 | 1087.56 | 501.34 | 2.169 |

The fresh results preserve the small-message advantage in these independent
workloads. Large persistent and per-call messages still take 2.41x and 2.17x
the reference wall time; broad gRPC performance superiority remains unproven.

## Native timed socket writes

The internal runtime adapter now uses zio's timed NetSend directly when the
std.Io belongs to the currently mounted zio execution context. The runtime's
main task is eligible too. Reserved-thread blockingIo, foreign runtimes,
non-runtime threads, wrapped vtables and no-suspend regions use the existing
portable socket-writer path. No zio type appears in the protocol API.

The direct operation preserves socket error mapping and the original awake
deadline. zio waits for an interrupted operation to finish, keeps a natural
committed prefix that races timeout/cancellation, and arms a timer only when
the operation needs to park. This removes the extra writer/timer tasks of the
generic std.Io.Select wrapper. Tests fill a real TCP send queue, interrupt the
write, mutate the caller buffer after return, drain the exact known prefix and
prove that a later marker arrives without abandoned bytes.

Clean 05ea78f3 was compared with clean 1bc897b9 on CPU 0 using the same windows,
100 warmup and 2000 measured roundtrips. Five samples alternated executable
order; every payload and terminal status was validated. The final sample set
ran after protocol verification completed. Full records are retained in
[the native timed-write A/B](evidence/grpc_shared/2026-10-28-native-timed-write.json).

| Mode | String bytes | Select us/roundtrip | Native timed us/roundtrip | Speedup |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 18.40 | 17.30 | 1.064x |
| Persistent RPC | 512 | 18.89 | 17.68 | 1.068x |
| Persistent RPC | 4096 | 23.83 | 22.05 | 1.081x |
| Persistent RPC | 262144 | 946.94 | 919.71 | 1.030x |
| RPC per roundtrip | 0 | 65.74 | 62.63 | 1.050x |
| RPC per roundtrip | 512 | 66.45 | 64.05 | 1.038x |
| RPC per roundtrip | 4096 | 72.25 | 68.77 | 1.051x |
| RPC per roundtrip | 262144 | 1088.81 | 1000.76 | 1.088x |

The retained change improves these workloads by about 3-9%. The earlier
external comparison remains a separate pre-change snapshot and is not updated
by these two-native-executable figures.


## Deadline frame slices and retained buffers

TCP deadline DATA bursts and combined HEADERS/DATA output now submit borrowed
slices instead of growing the connection's write_batch. The native zio path
can offer sixteen real vectors at once; other std.Io implementations retain
joined writer/timer cancellation and advance by the exact count their socket
writer accepts. Empty slices and short writes across frame boundaries preserve
one absolute deadline. TLS keeps its contiguous staging transaction for record
batching and validation of pending-record plaintext retries.

Clean 383fdb56 was compared with clean 09726856 on CPU 0 with the same five
alternating samples, fixed windows, 100 warmup and 2000 measured roundtrips.
Telemetry was disabled and each payload and terminal status was validated.
These results do not demonstrate a throughput improvement: every median is
within about 1% of its baseline, including a small large-message per-call
regression. The retained benefit is lower protocol buffer occupancy.

| Mode | String bytes | Contiguous us/roundtrip | Borrowed slices us/roundtrip | Speedup |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 17.36 | 17.24 | 1.007x |
| Persistent RPC | 512 | 17.67 | 17.65 | 1.001x |
| Persistent RPC | 4096 | 21.87 | 21.82 | 1.002x |
| Persistent RPC | 262144 | 916.72 | 914.96 | 1.002x |
| RPC per roundtrip | 0 | 61.86 | 61.82 | 1.001x |
| RPC per roundtrip | 512 | 62.66 | 62.65 | 1.000x |
| RPC per roundtrip | 4096 | 68.64 | 68.10 | 1.008x |
| RPC per roundtrip | 262144 | 995.98 | 999.36 | 0.997x |

A separate allocation snapshot used three alternating samples with telemetry,
100 warmup and ten roundtrips. It measures live client + server + protocol
allocations after the measured exchanges and before channel/peer teardown;
preencoded messages, latency storage and runtime allocations use the backing
allocator and are outside this metric. These telemetry runs overlapped protocol
verification, so their elapsed and latency fields are not performance evidence.

| Mode | String bytes | Contiguous live bytes | Borrowed slices live bytes | Saved live bytes |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 214630 | 214630 | 0 |
| Persistent RPC | 512 | 215737 | 215145 | 592 |
| Persistent RPC | 4096 | 224697 | 218729 | 5968 |
| Persistent RPC | 262144 | 312780 | 214625 | 98155 |
| RPC per roundtrip | 0 | 171024 | 171024 | 0 |
| RPC per roundtrip | 512 | 171616 | 171024 | 592 |
| RPC per roundtrip | 4096 | 176992 | 171024 | 5968 |
| RPC per roundtrip | 262144 | 269179 | 171024 | 98155 |

For 262144-byte messages the live protocol allocation median drops by 98155
bytes (about 96 KiB) per client/server connection pair. The per-call after
samples ranged from 171024 to 171123 bytes; the other retained-memory groups
were identical across all three samples. Allocated/freed byte totals during
the ten measured exchanges are identical between versions in the large-message
samples. Allocation counts varied; no per-roundtrip allocation-count reduction
is established. This change removes a retained staging buffer and its copy, while the
main large-message throughput gap remains open.

Server unary responses now also accept `grpc.OwnedResponseMessage`
prefix-reserved storage through `UnaryResponseOptions.owned_message`. An
identity response hands that exact allocation to the HTTP/2 writer without the
`framed` staging copy; compressed responses still allocate a separate framed
buffer. The borrowed `message` field keeps the existing staging path, so
callers that serialize directly into the owned payload avoid one full
response-sized copy. The buffer is borrowed for the synchronous write and
remains caller-owned, so a persistent server reuses one allocation across
responses.

`zig build bench-grpc-unary -Doptimize=ReleaseFast -- --payload=262144
--iterations=200 --warmup=20` selects the owned path by default and accepts
`--borrowed-response` for the staged path. Eight CPU-0 order-interleaved pairs
on 2026-11-06 measured a 404.664 us median round trip for the owned path versus
467.346 us for the borrowed path, a 13.4% reduction with the owned arm faster
in 8/8 pairs. Every arm validated the full 262,144-byte response and completed
200 measured round trips after 20 warmups.

Client unary requests now accept the matching prefix-reserved ownership through
`grpc.OwnedRequestMessage` and `UnaryCallOptions.owned_message`. Ordinary unary
calls hand the caller's identity storage to the HTTP/2 writer without the
intermediate `framed` copy; compression falls back to a separate framed
allocation, and the caller's buffer stays caller-owned and reusable.
`SharedChannel` queues jobs that may outlive the caller, so it copies the owned
payload into job-owned queued storage; owned requests therefore match the
staged path there instead of bypassing the copy.

`zig build bench-grpc-unary -Doptimize=ReleaseFast -- --payload=262144
--iterations=200 --warmup=20 --owned-request` selects the owned request path.
Six CPU-0 order-interleaved pairs on 2026-11-07 measured a 344.508 us median
round trip for the owned path versus 407.778 us for the staged path, a 15.5%
reduction with the owned arm faster in 6/6 pairs. The shared-channel arm
measured 556.300 us versus 559.456 us (0.6%, 6/6), consistent with the queued
copy. Both arms validated request framing on the server and full response
bytes on the client for every measured call.

SharedChannel duplex writes now also accept caller-owned prefix-reserved
storage through `SharedStreamWriter.writeBorrowedMessage` and
`writeFinalBorrowedMessage`. The endpoint owner stages the caller's identity
payload without copying and still writes it in bounded
`max_write_bytes_per_turn` turns, so one large stream cannot monopolize an
owner. The caller's buffer must stay valid until the synchronous call returns;
the owner never frees borrowed storage. Compression still allocates a separate
framed buffer owned by the stream. An early peer response or owner-side
deadline failure completes the write command before returning, so the caller
can safely reuse the buffer.

`bench-grpc-shared` accepts `--borrowed-writes`. Six CPU-0 order-interleaved
pairs at 256 KiB measured persistent ping-pong at 408.686 us versus 472.908 us
(13.58% lower, 6/6) and RPC-per-roundtrip at 487.467 us versus 547.056 us
(10.89% lower, 6/6). Every arm validated the full response and completed the
expected message and terminal-call counts. A `--stats` probe over 20 measured
calls reduced allocation calls from 80 to 60 and allocated bytes from
15,731,220 to 10,488,160, removing one 262,148-byte request copy per call.

[Complete timing and allocation records](evidence/grpc_shared/2026-10-28-deadline-scatter.json)
retain 128 validated result/peer-completion pairs plus source and executable
fingerprints. They do not replace the independent grpc-cpp comparison.

## Shared owner scan-cached awake time

SharedChannel endpoint owners now derive operation deadlines and streaming
expiry decisions from the matching zio event-loop awake snapshot. An I/O poll
refreshes that snapshot before the next owner operation; repeated checks in one
scheduler scan no longer issue separate VDSO clock reads. Foreign `std.Io`
implementations keep their ordinary clock behavior. This follows grpc-core's
`Party` use of `ScopedTimeCache`, including invalidation at blocking boundaries,
without exposing zio in the public gRPC API. Unary timeout classification also
reuses its first result instead of reading the same deadline twice.

Eight fixed-binary AB/BA pairs pinned the complete native client/server process
to CPU 10. Each arm used 100 warmups, 2,000 measured roundtrips, fixed 65,535-
byte stream/connection windows, pre-encoded identity messages, full byte
validation, and exact peer completion. All PMU, throughput and p50 rows below
favor the candidate in every pair except the 256-KiB per-call throughput row,
which won seven of eight.

| Workload | Instructions | Cycles | Throughput | P50 |
| --- | ---: | ---: | ---: | ---: |
| Persistent, 0 bytes | 1.0225x | 1.0650x | 1.0401x | 1.0405x |
| Persistent, 4 KiB | 1.0179x | 1.0577x | 1.0355x | 1.0386x |
| Persistent, 256 KiB | 1.0125x | 1.0433x | 1.0194x | 1.0183x |
| RPC per roundtrip, 256 KiB | 1.0119x | 1.0388x | 1.0115x | 1.0141x |

Matched zero-loss 256-KiB profiles moved `clock_gettime` self samples from
19.50% to 15.41%; its child below `Worker.tick` moved from 8.74% to 4.35%.
Separately sampled percentages are explanatory, while the fixed-binary pairs
are the causal evidence. Debug and ReleaseFast focused gates each pass 181/181,
package tests pass 22/22, and the pinned grpc-cpp forward matrix passes h2c and
certificate-verified TLS across shared unary/duplex, cancellation/reuse,
deadline, health, keepalive, compression and soak scenarios.

This reduces scheduler-clock overhead across message sizes but does not close
the independent grpc-cpp 256-KiB data-copy/window gap. Full identities,
profiles, PMU summaries and verification records are in
[the cached-clock evidence](evidence/grpc_shared_cached_clock/2026-10-29.json).

## Owner-validated buffered response polls

The endpoint owner now uses a dedicated internal poll path after it has already
classified RPC and write expiry against the scan-cached awake timestamp. The
ordinary public HTTP/2 and gRPC poll APIs still perform exact deadline
validation; an explicit regression proves an expired public deadline returns
`Timeout` before consuming an already buffered response. The internal path is
socket-free. If DATA consumption emits WINDOW_UPDATE, the original absolute
deadline continues into the ordinary bounded transport write and is validated
there.

Eight fixed-binary AB/BA pairs compared this change with the published
scan-cached owner baseline. CPU, windows, warmup, iterations, pre-encoded input,
full-byte validation and peer-completion requirements were unchanged.

| Workload | Instructions | Cycles | Throughput | P50 |
| --- | ---: | ---: | ---: | ---: |
| Persistent, 0 bytes | 1.0137x | 1.0232x | 1.0123x | 1.0130x |
| Persistent, 4 KiB | 1.0109x | 1.0219x | 1.0109x | 1.0099x |
| Persistent, 256 KiB | 1.0074x | 1.0118x | 1.0020x | 1.0020x |
| RPC per roundtrip, 256 KiB | 1.0068x | 1.0070x | 1.0000x | 1.0030x |

Instructions and cycles improved in all 32 paired comparisons. The two small-
message shapes also improved throughput and p50 in every pair. The 256-KiB
timing rows were mixed and are treated as neutral rather than promoted as a
latency result. In the matched zero-loss profile, `clock_gettime` moved from
15.41% to 13.81%, and the former 2.06% child under
`pollRawResponseEventBatchedWithDeadline` disappeared from the clock stack.

Debug and ReleaseFast HTTP/2 duplex/gRPC shared-streaming gates pass 200/200,
the focused strict/internal contract passes 132/132, and the pinned grpc-cpp
h2c/TLS matrix passes. Full evidence is recorded in
[the validated-poll evidence](evidence/grpc_shared_validated_poll/2026-10-29.json).

## Retained HTTP/2 read-ahead frames

Duplex receive ownership now retains immutable subspans of the HTTP/2 reader's
64-KiB read-ahead allocation instead of duplicating every complete wire frame.
The reader keeps one atomic block reference and reuses the allocation only when
it is the sole owner. If an application event, sibling queue, or interrupted
read still retains that block, the next socket read transactionally moves only
the incomplete suffix into a new block. This follows grpc-core's refcounted
`Slice`/`SliceBuffer` ownership boundary without changing public `OwnedFrame`:
ordinary readers still receive one exact allocation, and crossing from a shared
duplex queue to that API copies before advancing the queue.

The original 256-KiB trace copied 64 frames per roundtrip: 35 DATA frames, 25
WINDOW_UPDATE frames, three HEADERS frames, and one SETTINGS frame. Twenty-six
of the DATA copies were 16,393 wire bytes. In three deterministic allocation
pairs over ten measured roundtrips, explicit protocol allocations fell from
875 to 210 and allocated bytes from 26,225,795 to 20,975,710. That removes 665
allocations and 5,250,085 bytes per ten roundtrips; live protocol storage grew
by 88 bytes because the connection retains block ownership metadata.

Eight final-source, fixed-binary AB/BA pairs pinned the whole client/server
process to CPU 10. Each arm used the same fixed windows, 100 warmups, 2,000
measured roundtrips, full-byte checks and peer completion as the earlier shared
channel experiments. Ratios greater than one favor retained frames:

| Workload | Instructions | Cycles | Throughput | P50 |
| --- | ---: | ---: | ---: | ---: |
| Persistent, 0 bytes | 1.0076x (8/8) | 1.0026x (7/8) | 1.0031x (7/8) | 1.0035x (6/8) |
| Persistent, 4 KiB | 1.0270x (8/8) | 1.0135x (8/8) | 1.0097x (7/8) | 1.0093x (7/8) |
| Persistent, 256 KiB | 1.0619x (8/8) | 1.0512x (8/8) | 1.0309x (8/8) | 1.0266x (8/8) |
| RPC per roundtrip, 256 KiB | 1.0549x (8/8) | 1.0313x (8/8) | 1.0138x (8/8) | 1.0157x (8/8) |

The first global-owner candidate was not retained because enlarging every
`OwnedFrame` made zero-byte cycles/timing neutral-to-negative. A large-frame-
only variant was rejected more decisively: instructions, cycles, throughput,
p50 and p99 all regressed in 8/8 zero-byte pairs. The accepted split restores
the public 48-byte `OwnedFrame`, keeps the 56-byte retained owner inside duplex
paths, and permits the shared duplex queue to preserve blocks in both endpoint
directions. Predecoded HPACK state is rekeyed transactionally if an ordinary
reader later materializes a queued frame at a new address.

A matched 10,000-roundtrip candidate profile captured about 2,000 user-cycle
samples with zero losses. `memcpyFast` self samples were 3.46%, down from the
previous profile's 5.66%; the former 2.91% memcpy child below
`readOwnedFrameForDuplexWithDeadline` disappeared. Remaining copies belong to
gRPC message staging/reassembly and benchmark validation rather than frame
ownership. Debug and ReleaseFast cross-module gates pass 191/191, the complete
Debug HTTP/2 filter passes 921/921, package tests pass 22/22, and the pinned
grpc-cpp h2c/TLS forward matrix passes. This closes the per-frame read-ahead
copy hotspot but does not by itself replace the independent grpc-cpp
large-message comparison. Full sample rows, allocation records, identities,
failure contracts, and profile metadata are in
[the retained-frame evidence](evidence/grpc_shared_retained_frames/2026-10-30.json).

## Shared decoded-message ownership

The incremental gRPC decoder can now transfer an `OwnedDecodedMessage` to a
successful callback. A message that already crossed DATA boundaries reuses the
decoder's exact reassembly allocation instead of copying it into the
SharedChannel event. A direct, uncompressed, nonempty message that ends at the
input-chunk boundary moves to the allocation start and shrinks that allocation
in place. If the allocator cannot shrink it, the reader falls back to the
previous exact duplicate. Direct decoder callbacks otherwise remain borrowed;
empty and directly compressed messages retain the previous path, and the
public event's allocator/slice/bool layout does not grow.

Decoder state drops ownership before invoking application code. Callback
failure frees the detached payload, bounded decompression frees its encoded
input and transfers only the decoded output, and a SharedChannel allocation
failure retires the call. Focused tests bind allocation identity, callback
failure cleanup, gzip output transfer, and the unchanged borrowed direct path.

Eight fixed-binary AB/BA pairs used CPU 10, fixed 65,535-byte windows, 100
warmups, 2,000 measured roundtrips, full-byte validation and peer completion.
Ratios greater than one favor ownership transfer:

| Workload | Instructions | Cycles | Throughput | P50 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Persistent, 0 bytes | 0.9999x (0/8) | 1.0001x (4/8) | 1.0042x (6/8) | 1.0038x (6/8) | 1.0044x (5/8) |
| Persistent, 4 KiB | 1.0009x (8/8) | 1.0022x (6/8) | 1.0019x (6/8) | 1.0016x (6/8) | 1.0027x (5/8) |
| Persistent, 256 KiB | 1.0271x (8/8) | 1.0371x (8/8) | 1.0910x (8/8) | 1.0882x (7/8) | 1.0867x (8/8) |
| RPC per roundtrip, 256 KiB | 1.0245x (8/8) | 1.0363x (8/8) | 1.0885x (8/8) | 1.0842x (8/8) | 1.0870x (8/8) |

Zero-byte instructions differ by only 0.01% and are treated as neutral. This
small-message boundary rejected variants that owned every decoder result or
enlarged every `Message`, even though those variants helped large messages.

Three deterministic telemetry pairs over ten measured roundtrips show one
fewer exact response-message allocation per roundtrip whenever a nonempty
message can reuse its input or reassembly allocation:

| Workload | Allocations before / after | Allocated bytes before / after | Live bytes before / after |
| --- | ---: | ---: | ---: |
| Persistent, 0 bytes | 60 / 60 | 3,970 / 3,970 | 215,446 / 215,446 |
| Persistent, 4 KiB | 60 / 50 | 249,820 / 208,830 | 219,545 / 219,545 |
| Persistent, 256 KiB | 210 / 200 | 20,975,710 / 18,354,230 | 215,441 / 215,441 |
| RPC per roundtrip, 256 KiB | 389 / 379 median | 21,685,948 / 19,064,468 | 171,720 / 171,720 median |

Each 256-KiB row removes 2,621,480 allocated bytes per ten roundtrips, exactly
ten 262,148-byte framed response buffers, without increasing median live
protocol storage. A 10,000-roundtrip, 199-Hz DWARF profile lost zero samples.
Benchmark full-byte validation and `clock_gettime` account for 16.23% and
16.16% self; `memcpyFast` is 2.89% self. The former Shared reader
`Collector.consume` whole-message duplicate is no longer a principal copy.
At this checkpoint, remaining production copy boundaries included the
outbound `Write.create` caller-input clone, encoded-message staging, and the
decoder's first cross-DATA reassembly copy. The following section removes the
second outbound copy without changing the borrowed Writer contract.

The clean CPU-1 official comparison then ran seven alternating samples against
grpc-cpp `03d65cc67c`:

| Native mode | String bytes | Native median us/roundtrip | grpc-cpp median us/roundtrip | Native / grpc-cpp |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 17.637 | 43.775 | 0.403 |
| Persistent RPC | 512 | 18.081 | 44.979 | 0.402 |
| Persistent RPC | 4096 | 22.157 | 49.542 | 0.447 |
| Persistent RPC | 262144 | 908.913 | 387.996 | 2.343 |
| RPC per roundtrip | 0 | 64.204 | 124.337 | 0.516 |
| RPC per roundtrip | 512 | 64.882 | 124.778 | 0.520 |
| RPC per roundtrip | 4096 | 70.046 | 130.026 | 0.539 |
| RPC per roundtrip | 262144 | 983.617 | 494.586 | 1.989 |

The earlier retained-frame snapshot recorded 2.511x and 2.160x for the two
256-KiB modes. The new result preserves the small-message advantage and narrows
the large-message gap, but does not close it: grpc-core retains segmented
`SliceBuffer` message ownership while the native path still materializes
contiguous outbound and first-reassembly buffers. The following outbound
ownership change removes that contiguous request staging layer. Debug and ReleaseFast gRPC
filters each pass 386/386, package tests pass 22/22, and the pinned grpc-cpp
h2c/TLS matrix passes, including large/streaming/compressed messages,
cancellation/reuse, deadlines, slow consumers and soak. Full raw rows,
identities and failure contracts are in
[the message-ownership evidence](evidence/grpc_shared_message_ownership/2026-10-30.json).

## Shared outbound prefix-reserved ownership

The SharedChannel writer previously cloned the caller payload into its queued
command, then `ClientDuplex.stageMessage` grew another `5 + payload` buffer,
copied the entire request into it, and immediately released the command copy.
grpc-core instead appends a tiny five-byte header slice and retains references
to the message's `SliceBuffer` payload.

The queued command now owns one allocation with five bytes reserved before the
borrowed caller payload. Identity messages and gzip/deflate attempts that fall
back to identity write their prefix into that allocation and transfer it
directly to `PendingMessage`. Successfully compressed messages retain the old
separate compressed-output path and free the command input only after staging
succeeds. `PendingMessage` is still one contiguous slice, so HTTP/2 DATA
packetization, flow-control progress, response interruption and final-message
semantics do not change. Finish-only commands allocate no unused prefix.
The encoding and its adjacent ownership/OOM tests live in the focused
`stream/duplex/outbound_ownership.zig` module rather than enlarging the duplex
state-machine root.

Ownership transfers only after successful staging. Compression or framed-
output OOM leaves the original buffer with the command, and the command detaches
transferred storage exactly once. Tests cover an identity transfer under an
allocator that rejects every allocation, strict gzip roundtrip, every
compressed staging OOM boundary, interrupted command ownership and the exact
single transfer.

Eight fixed-binary AB/BA pairs used CPU 10, fixed 65,535-byte windows, 100
warmups, 2,000 measured roundtrips, full-byte validation and peer completion.
Ratios greater than one favor prefix-reserved ownership:

| Workload | Instructions | Cycles | Throughput | P50 | P99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Persistent, 0 bytes (10,000 rounds) | 1.0056x (8/8) | 1.0011x (6/8) | 1.0007x (4/8) | 1.0011x (4/8) | 1.0013x (5/8) |
| Persistent, 4 KiB | 1.0139x (8/8) | 1.0091x (8/8) | 1.0070x (8/8) | 1.0068x (7/8) | 1.0063x (7/8) |
| Persistent, 256 KiB | 1.0276x (8/8) | 1.0376x (8/8) | 1.1033x (8/8) | 1.1036x (8/8) | 1.1063x (8/8) |
| RPC per roundtrip, 256 KiB | 1.0362x (8/8) | 1.0462x (8/8) | 1.0733x (8/8) | 1.0515x (8/8) | 1.0519x (8/8) |

The zero-byte arm uses 10,000 measured rounds because its initial 2,000-round
timing pairs moved with scheduler noise despite deterministic instruction
improvement. Its final timing ratios remain neutral, so only the 0.56%
instruction reduction is claimed. The command and pending-message layouts do
not grow. Three telemetry pairs over ten measured roundtrips show unchanged
live protocol storage:

| Workload | Allocations before / after | Allocated bytes before / after | Live bytes before / after |
| --- | ---: | ---: | ---: |
| Persistent, 0 bytes | 60 / 50 | 3,970 / 2,620 | 215,446 / 215,446 |
| Persistent, 4 KiB | 50 / 40 | 208,830 / 146,040 | 219,545 / 219,545 |
| Persistent, 256 KiB | 200 / 190 | 18,354,230 / 14,420,710 | 215,441 / 215,441 |
| RPC per roundtrip, 256 KiB | 379 / 339 median | 19,064,468 / 15,130,948 | 171,720 / 171,720 median |

The 256-KiB shapes remove 3,933,520 requested bytes per ten roundtrips. This is
larger than ten payloads because the previous `ArrayList` staging capacity grew
beyond the exact message length. A 10,000-roundtrip 199-Hz DWARF profile
captured 1,689 samples with zero losses. The former Shared client
`stageMessage -> encodeMessageAlloc` whole-request copy no longer appears as a
recognizable memcpy caller. A residual 0.06% `encodeMessageAlloc` child belongs
to the synchronous server response path.

The clean CPU-1 official comparison then ran seven alternating samples against
grpc-cpp `03d65cc67c`:

| Native mode | String bytes | Native median us/roundtrip | grpc-cpp median us/roundtrip | Native / grpc-cpp |
| --- | ---: | ---: | ---: | ---: |
| Persistent RPC | 0 | 17.533 | 43.517 | 0.403 |
| Persistent RPC | 512 | 18.011 | 44.754 | 0.402 |
| Persistent RPC | 4096 | 22.097 | 49.419 | 0.447 |
| Persistent RPC | 262144 | 821.688 | 395.266 | 2.079 |
| RPC per roundtrip | 0 | 64.427 | 123.887 | 0.520 |
| RPC per roundtrip | 512 | 65.763 | 125.037 | 0.526 |
| RPC per roundtrip | 4096 | 70.780 | 130.828 | 0.541 |
| RPC per roundtrip | 262144 | 915.920 | 496.145 | 1.846 |

The preceding decoded-message snapshot recorded 2.343x and 1.989x for the two
256-KiB modes. This change narrows both while preserving the small-message
advantage, but does not close large-message parity. The borrowed public Writer
API still requires one caller-payload clone; the synchronous server response
still stages a framed buffer, and first cross-DATA receive reassembly remains
contiguous. Debug and ReleaseFast gRPC filters each pass 390/390, package tests
pass 22/22, and the pinned grpc-cpp h2c/TLS matrix passes across compression,
large messages, slow consumers, cancellation, deadlines and soak. Full raw
rows, identities and failure contracts are in
[the outbound-ownership evidence](evidence/grpc_shared_outbound_ownership/2026-10-30.json).

## Explicit owned duplex writes

The ordinary direct and `SharedStreamWriter` methods intentionally accept
borrowed payloads, so retained flow-control progress must own a copy before the
method returns. Applications that already allocate a serialization output can
now avoid that boundary. Direct `ClientDuplex` and `ServerDuplex` expose
`allocMessage` plus owned write methods through the common
`DuplexOwnedMessage`; SharedChannel exports the compatible
`SharedStreamOwnedWriteMessage` alias and adds final/options/deadline forms.
The writable payload follows five reserved gRPC prefix bytes in the transport
allocator. Submission consumes the value on success or error, so a caller can
keep `defer message.deinit()`; successful transfer clears optional storage and
makes cleanup a no-op.

The endpoint owner uses the same prefix-reserved staging path measured above.
Identity and compression fallback transfer the exact pointer into
`PendingMessage`; actually compressed output frees the input only after the
separate compressed frame is owned. Invalid deadlines consume locally before
publication, foreign allocator storage is rejected transactionally, and every
command-allocation failure retains a single cleanup owner.

A deterministic allocator test models an application-owned serialized
payload. Borrowed Shared submission uses three allocations—caller payload,
command and queued clone—while its owned form uses two. Direct duplex response
encoding falls from two allocations—caller payload plus framed staging—to one
prefix-reserved allocation. Both remove one allocation and at least
`payload.len` requested bytes. Pointer-identity tests prove the queued/pending
message owns the same allocation. Real direct and shared duplex tests cover
owned gzip, identity, final message, deadline failure and cleanup.

The official grpc-cpp table above remains the borrowed-API workload and is not
relabeled as an owned-input result. A separate attempt to replace every
borrowed duplex staging buffer with one exact allocation was rejected: although
persistent 256-KiB throughput improved about 0.5%, per-call cycles regressed in
7/8 pairs by a 0.31% median. The opt-in API adds the zero-copy construction
contract without taxing existing callers. Evidence is recorded in
[the generic duplex evidence](evidence/grpc_duplex_owned_write/2026-10-30.json),
with the original SharedChannel-only step retained in
[its earlier evidence](evidence/grpc_shared_owned_write/2026-10-30.json).

## Rejected retained-DATA consumer handoff

Three candidates attempted to move large HTTP/2 `DuplexData` retained-frame
ownership directly from the Shared endpoint owner to the consumer decoder,
skipping both frame-to-ring and ring-to-chunk copies. They preserved a copied
small-DATA ring, exact cross-entry order, the existing bounded byte window and
consumer-triggered credit. Tests covered a copied five-byte gRPC prefix followed
by a retained 4-KiB payload, queue OOM ownership, slow-reader sibling progress,
final-DATA terminal commitment and bounded decoder splits.

All three were rejected by the 0-byte fixed-binary guard. Inline queue/current
metadata produced a 0.99701x baseline/candidate instruction ratio with 0/8
wins. Moving all metadata behind a lazy heap pointer improved that to 0.99827x
but still lost 8/8. Restoring direct small-DATA append and a separate original
Reader ring path regressed further to 0.99585x, again 0/8, despite neutral wall
time. No candidate remains in the source tree.

This rules out adding retained-input dispatch to every SharedChannel call. A
future large-message attempt must preserve Call layout and small-DATA code
generation, likely by adding segmented ownership below `ClientDuplex` in the
HTTP/2 transport or selecting a separate large-message implementation. Full
raw paired rows and binary identities are in
[the rejected retained-DATA evidence](evidence/grpc_shared_retained_data_rejected/2026-10-30.json).

## Large-message bottleneck and rejected clock cache (2026-11-02)

A 256-KiB persistent roundtrip measured 839 µs with the default 16-KiB frame
size and 837 µs with a 64-KiB negotiated frame size, so frame count and per-frame
wakeups are not the dominant cost. The same workload scaled linearly with
payload: 1 MiB took 3.47 ms and 4 MiB took 14.93 ms, about 600 MB/s of aggregate
payload throughput. The gap is therefore copy/throughput-bound.

Replacing the direct `Clock.awake.now` reads in the priority/WRR/pick paths
with `netz_runtime.cachedAwakeTimestamp` was then measured with five alternating
256-KiB persistent pairs against an otherwise identical baseline binary. The
candidate's median was 890,066 ns per roundtrip versus 858,614 ns for the
baseline, and three of five pairs were slower. The candidate was reverted; the
direct clock reads remain in those paths. A future attempt should reduce
message copies or segmented ownership rather than clock-source overhead.

Two further controls were measured on the same 256-KiB workload. Client write
turn budgets of 64 KiB, 256 KiB, and 1 MiB produced 846, 844, and 850 µs, so the
64-KiB `max_write_bytes_per_turn` default is not the bottleneck. Disabling the
benchmark's full-byte payload validation (`--no-validate`, which now reports
`validation=length-only`) reduced the median from 859,022 to 801,915 ns per
roundtrip in two of three alternating pairs, about 7%. The
transport gap against grpc-cpp is therefore roughly 2.0x after accounting for
benchmark validation, and the remaining cost is still copy/throughput-bound.

## Steady-state config reclaim fast path (2026-11-02)

`Publication.reclaim` now returns before the seq_cst reader-epoch load when
`retired == null`, which is the steady state between config updates. `retired`
is only mutated under the State mutex. On the same 256-KiB persistent workload,
five alternating wall-time pairs were all faster: median 887,608 ns per
roundtrip versus 907,171 ns for the baseline (2.2%). Three fixed-binary PMU
pairs reduced instructions from a 244,301,950 median to 242,820,199 (0.61%,
3/3 wins); cycles remained load-noisy. The full gRPC Debug gate passes 562/562
with the change retained.

An additional monotonic fast-path load before the abandoned-pending swap
reduced instructions another 0.15% (3/3 fixed-binary PMU pairs) but was
wall-neutral to slightly slower across five alternating pairs (median 843,608
versus 841,579 ns/roundtrip, 2/5 wins). It was not retained; the single swap
remains in the source tree.

## Direct receive-ring decoding (2026-11-02)

The shared reader now feeds the call-owned DATA ring directly to the gRPC
decoder instead of first copying each up-to-64-KiB turn into a private chunk.
The unconsumed ring region remains protected by `head`/`len` while the state
lock is released; a borrowed single-chunk message is duplicated before the ring
advances. This removes one full copy per receive turn for multi-chunk messages.
On the 256-KiB persistent workload, four of five alternating wall pairs were
faster: median 808,907 ns per roundtrip versus 865,963 ns for the baseline
(6.6%). Three fixed-binary PMU pairs reduced instructions from 242,819,212 to
236,558,883 (2.58%, 3/3 wins). The full gRPC Debug gate passes 562/562 with the
change retained.

## Allocator dominates the large-message gap (2026-11-02)

The remaining 256-KiB gap is dominated by the benchmark's allocator choice,
not the transport. The benchmark now exposes `--c-allocator` and reports
`allocator=smp|c`. With the same binary:

- 0/512/4-KiB payloads measured about 18.3/19.4/23.4 µs per roundtrip under
  both allocators.
- 256 KiB measured about 830-915 µs with `std.heap.smp_allocator` and
  **469-492 µs with `std.heap.c_allocator`** (glibc malloc), roughly 1.8x.
- Three PMU pairs showed nearly identical instructions (521.7M versus 522.0M,
  +0.1%) and only about 3% fewer cycles for the system allocator, so the wall
  difference is allocator syscall/lock behavior rather than extra work.

With the system allocator, the netz 256-KiB roundtrip is about 469-490 µs
against the recorded grpc-cpp reference of about 393 µs, roughly 1.2-1.25x
rather than 2.4x. The earlier comparison conflated allocator behavior with
transport cost. Large-message callers should use a caching or system allocator.

`netz.alloc.BlockCache` now provides that caching layer. It retains freed
power-of-two blocks from 4 KiB through 16 MiB, up to a configurable byte cap
(16 MiB by default), behind a short spin-locked free list; blocks with larger
alignment or beyond the cap delegate to the backing allocator. Wrapping
`std.heap.smp_allocator` with the default cap on the same 256-KiB workload:

- 843-854 µs (raw `smp_allocator`) versus **460-481 µs** (cached), about 1.78x
  and 3/3 alternating pairs; this matches the system allocator's 462-492 µs.
- 64 KiB: 224 µs to 118 µs. 0/512/4-KiB payloads stayed within about 1%.
- After 200 roundtrips the cache reported 1,337 hits, 95 misses, and 1.48 MiB
  retained.

The benchmark exposes `--cached-allocator` and reports `allocator=cached`.
The cache is opt-in; `Backend.init` continues to use exactly the allocator the
caller supplies. `netz.runtime.Backend.initCached` heap-owns the cache behind
the runtime facade, so applications can enable it without managing a separate
allocator lifetime. Alternating-pair rows, source hashes and the PMU note are
recorded in
[the allocator evidence](evidence/grpc_shared/2026-11-02-allocator.json).

## Official grpc-cpp comparison with the cached allocator (2026-11-02)

This table records the historical 16-KiB frame default before the 2026-11-02
default change; the 256-KiB-default comparison below supersedes it.

The official `grpc_benchmark.py` harness was rerun at `1fe9791f` with the
cached allocator enabled through a thin wrapper around
`netz-bench-grpc-shared`. grpc-cpp remained at `03d65cc67c`. Five alternating
samples pinned CPU 12, used 100 warmups and 2,000 measured roundtrips, and
validated every netz payload byte. Ratios below are netz / grpc-cpp, so lower
is better.

| Mode | Payload | netz median ns | grpc-cpp median ns | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Persistent | 0 | 17,474 | 43,762 | 0.399 |
| Persistent | 512 | 18,122 | 45,073 | 0.402 |
| Persistent | 4 KiB | 22,295 | 49,970 | 0.446 |
| Persistent | 256 KiB | 443,349 | 398,854 | 1.112 |
| RPC per roundtrip | 0 | 54,368 | 128,150 | 0.424 |
| RPC per roundtrip | 512 | 55,116 | 127,931 | 0.431 |
| RPC per roundtrip | 4 KiB | 59,116 | 134,077 | 0.441 |
| RPC per roundtrip | 256 KiB | 500,531 | 512,543 | 0.977 |

With the cached allocator, netz remains 2.2-2.5x faster for small messages,
is 11.2% slower for the persistent 256-KiB streaming ping-pong, and is 2.3%
faster for the 256-KiB per-call RPC mode. This supersedes the earlier
1.2-1.25x large-message estimate. Full rows and binary identities are in
`docs/evidence/grpc_cpp_official_cached/2026-11-02.json`.

## Rejected larger read turn (2026-11-02)

A separate `max_read_bytes_per_turn` option was measured against the 64-KiB
default while keeping the write turn at 64 KiB. Five ABBA rounds of the
256-KiB persistent workload moved the median from 441,765.5 ns to 448,307.5 ns
(1.5% slower, 2/5 wins). A larger read region did not reduce the persistent
large-message cost; the extra ring region and feed size cost more than any
direct-delivery benefit. The option and code changes were reverted. Rows are
in `docs/evidence/grpc_shared_read_turn_rejected/2026-11-02.json`.

## Large single-stream frame size (2026-11-02)

Both netz endpoints can advertise a 256-KiB HTTP/2
`SETTINGS_MAX_FRAME_SIZE` through `Limits.max_frame_size` (or
`http2.runtime.recommended_large_frame_size`). A 256-KiB message then fits one DATA
frame and takes the decoder's direct path instead of cross-DATA reassembly.
Three ABBA rounds of the persistent 256-KiB workload moved the median from
469,913 ns to 402,441.5 ns (14.4% faster, 3/3 rounds). Small 0/512/4-KiB
persistent and per-call workloads stayed within about 0.7% of the 16-KiB
default.

The library now advertises 256 KiB by default through
`Limits.max_frame_size` (`http2.runtime.recommended_large_frame_size`). A
10-stream 1-MiB flow-control control was neutral-to-slightly faster (paired
median 0.99x, 3/3 rounds), and the full 6,180-test library suite passed.
Peers still start at the RFC 16-KiB value until SETTINGS exchange, and
applications that prefer the old behavior can set `Limits.max_frame_size =
16 * 1024` explicitly. Rows are in
`docs/evidence/grpc_shared_large_frame/2026-11-02.json`.

## Official comparison with the 256-KiB default frames (2026-11-02)

The official harness was rerun at `bb00a721` with the cached allocator and the
256-KiB frame size that is now the netz default on both endpoints. grpc-cpp
remained at `03d65cc67c` with its default frames. Five alternating samples
pinned CPU 12, used 100 warmups and 2,000 measured roundtrips, and validated
every netz payload byte. Ratios are netz / grpc-cpp.

| Mode | Payload | netz median ns | grpc-cpp median ns | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Persistent | 0 | 17,574 | 44,342 | 0.396 |
| Persistent | 512 | 18,105 | 44,924 | 0.403 |
| Persistent | 4 KiB | 22,182 | 50,356 | 0.441 |
| Persistent | 256 KiB | 377,265 | 398,850 | 0.946 |
| RPC per roundtrip | 0 | 54,512 | 124,537 | 0.438 |
| RPC per roundtrip | 512 | 55,136 | 125,742 | 0.438 |
| RPC per roundtrip | 4 KiB | 59,239 | 131,306 | 0.451 |
| RPC per roundtrip | 256 KiB | 421,370 | 510,460 | 0.825 |

Netz wins every measured shape in this configuration, including persistent
256-KiB streaming ping-pong (5.4% faster) and 256-KiB per-call RPCs (17.5%
faster). This is a netz-default versus grpc-cpp-default result, not an
equal-wire claim: netz now advertises 256-KiB frames while grpc-cpp keeps its
default frames. Applications can explicitly select 16 KiB through
`Limits.max_frame_size`; peers still start at the RFC 16-KiB value until
SETTINGS exchange. Rows and identities are in
`docs/evidence/grpc_cpp_official_large_frame/2026-11-02.json`.

The advertised SETTINGS value is `min(max_frame_size, max_frame_payload)`
(never below the RFC 16-KiB minimum). This keeps a caller with a smaller local
allocation ceiling, such as the interop clients' 64-KiB

## Official comparison with borrowed SharedChannel writes (2026-11-07)

The official harness was rerun at `8b83e575` on a clean tree with the native
`--borrowed-writes` arm and grpc-cpp `03d65cc67c`. Five alternating samples
pinned CPU 0, used 100 warmups and 2,000 measured roundtrips, and validated
every netz payload byte. Both sides used the benchmark's default 16-KiB frame
size and 65,535-byte windows; netz used the default `smp` allocator and
pre-encoded messages while grpc-cpp serialized and parsed protobuf. Ratios are
netz / grpc-cpp.

| Mode | Payload | netz median ns | grpc-cpp median ns | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Persistent | 0 | 13,245 | 32,213 | 0.411 |
| Persistent | 512 | 13,641 | 32,819 | 0.416 |
| Persistent | 4 KiB | 16,766 | 35,214 | 0.476 |
| Persistent | 256 KiB | 407,731 | 244,080 | 1.670 |
| RPC per roundtrip | 0 | 47,540 | 86,277 | 0.551 |
| RPC per roundtrip | 512 | 48,031 | 87,058 | 0.552 |
| RPC per roundtrip | 4 KiB | 51,465 | 89,889 | 0.573 |
| RPC per roundtrip | 256 KiB | 482,390 | 315,316 | 1.530 |

The borrowed request path removes one 256-KiB copy per roundtrip from the
SharedChannel client. The 256-KiB ratios improve from the earlier default-shape
2.079x/1.846x record to 1.670x/1.530x in this configuration, while small
messages remain 1.8-2.4x faster than grpc-cpp. This is still a
same-application-shape comparison: grpc-cpp includes protobuf serialization and
parsing while netz uses pre-encoded messages, so it is not an equal-wire or
equal-API claim. Full rows and identities are in
`docs/evidence/grpc_cpp_official_borrowed/2026-11-07/`.

### Large-frame and cached-allocator configuration

The same runner at `43139e7a` with `--netz-max-frame-size=262144
--netz-cached-allocator --netz-borrowed-writes` measured 249.500 us versus
236.982 us for 256-KiB persistent ping-pong (1.053x) and 276.230 us versus
298.508 us for per-call RPCs (0.925x). Small messages remained 1.9-2.4x faster.
A CPU-0 run of the same configuration measured 1.048x and 0.916x, so the result
is stable across CPUs. The per-call large-message mode is now faster than
grpc-cpp in this configuration; persistent ping-pong remains about 5% slower.
Rows are in `docs/evidence/grpc_cpp_official_borrowed/2026-11-07/largeframe/`.
`max_frame_payload`, from advertising a frame it cannot receive.
