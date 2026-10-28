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

The retained change improves these workloads by about 3-9%. DATA output under
a deadline still concatenates borrowed frame headers/payloads into write_batch
before transport submission; avoiding that copy is the next concrete data-path
candidate. The earlier external comparison remains a separate pre-change
snapshot and is not updated by these two-native-executable figures.
