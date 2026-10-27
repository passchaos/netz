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
outside both intervals. All calls use identity compression and the default
65,535-byte stream receive window; large messages exercise repeated credit
return without enlarging the window.

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
    zig build test-grpc-benchmark-checker

The result record reports average wall-clock roundtrip time, roundtrips per
second, and nearest-rank p50/p95/p99 latency. The independent
tools/interop/grpc_benchmark_check.py verifier checks timing arithmetic, message
counts, protobuf/logical byte counts, terminal-call counts and runtime identity.
It requires exactly one result and one matching peer completion. Pass a saved
benchmark log as its positional argument.

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
