# gRPC endpoint connection competition

An ordinary `grpc.Channel` now starts another eligible endpoint when an earlier
TCP/TLS/HTTP2 handshake remains pending. The default connection attempt delay
is 250 ms, matching the audited grpc-core `pick_first` implementation in
`~/Work/grpc/src/core/load_balancing/pick_first/pick_first.cc`.

```zig
var channel = try netz.grpc.Channel.init(allocator, io, .{
    .resolved = .{ .endpoints = endpoints, .policy = .pick_first },
}, .{ .connection_attempt_delay = .fromMilliseconds(250) });
defer channel.deinit();
```

`connection_attempt_delay = null` selects serial attempts. Non-positive delays
are rejected before allocation or network admission. Every eligible endpoint
can be launched, so two permanently stalled earlier addresses cannot prevent
a third healthy endpoint from progressing. IP endpoint families are stably
interleaved while retaining the original public endpoint indices. A mixed
list containing custom or hostname connectors preserves its declared order.
Immediate failures advance without waiting for the stagger timer.

The first complete HTTP/2 handshake supplies the selected connection, which
remains sticky across later calls. A caller-supplied RPC deadline bounds the
entire pass, while each newly launched endpoint receives its own bounded
connect deadline. Retryable failures retain endpoint-local backoff; an
individual attempt timing out cannot terminate an otherwise live wait-for-ready
RPC. Failed or canceled passes report TRANSIENT_FAILURE after all attempts
retire. `cancelWaits()` interrupts an overlapping pass, and callers reset its
cancellation state only after joining that operation.

`internal/connection_race.zig` owns stable result slots and joins every admitted
worker before releasing unselected successful results. TCP/QUIC Happy Eyeballs
uses the same core after address planning. gRPC transports keep their large
connection values in stable endpoint slots, while the selector passes only
indices. A move-stable allocator guard serializes overlapping connector
allocations; application response ownership retains the caller's allocator,
including after Channel destruction.

The shared connect and accept races explicitly reserve concurrency for their
operation and deadline timer. An exhausted async budget therefore cannot
silently execute either blocking half inline. Failed scheduler admission is
reported as `ConcurrencyUnavailable` by connection competition, or through
the standard socket `SystemResources` error by connect/accept.

During cancellation verification, a committed timed write exposed a separate
transport bug: returning its byte count consumed the cancellation request, so
the following handshake read continued to its original deadline. Timed writes
now preserve that progress and re-arm cancellation for the next I/O operation.
A real task-cancellation regression verifies both the three committed bytes
and the following `Canceled` result.

## Verification

Adjacent regressions cover three-endpoint handshake stalls, stable reuse,
immediate failure, per-attempt timeout/backoff, explicit cancellation, delay
validation, missing concurrency, an exhausted async budget, owned responses
after Channel destruction, and a successful losing connection returned during
cancellation. Existing TCP Happy Eyeballs ownership tests exercise the shared
competition core.

```sh
zig build test-lib -Dtest-filter='gRPC connection competition' \
  -Dtest-filter='stream timed socket writer' -Dtest-filter='TCP Happy Eyeballs' \
  --summary all
zig build interop-grpc-connection-race -Doptimize=ReleaseFast --summary all -- \
  --output docs/evidence/grpc_connection_race/2026-10-30.json
```

The independent process gate supplies two real TCP listeners which accept and
drain bytes while withholding all HTTP/2/TLS handshake responses. A third
Node HTTP/2 peer sends exact unary frames and verifies persistent reuse. Both
the pinned grpc-js 1.14.0 SDK and native Channel reach that third endpoint over
h2c, certificate-verified TLS 1.2 and TLS 1.3. The native matrix also verifies
serial opt-out, a short whole-operation deadline and immediate refusal with a
stagger delay longer than the RPC budget. It checks exact authority, TLS
identity, ALPN and peer socket retirement.

The source-bound evidence records the SDK's close behavior independently:
after its two successful calls and `client.close()`, its two stalled sockets
remain live through a five-second retirement wait. Only that reference cohort
is then explicitly retired before the native cases start. Native connection
and cancellation ownership additionally has in-process checks before Channel
or process destruction.

The recorded validation passes 432/432 gRPC/transport Debug tests, 152/152
focused ReleaseFast tests, 22/22 package checks and the three HTTP/2 TLS
state-model tests. Four owning HTTP/3 Happy Eyeballs scenarios cover dual-family
handshakes, policy validation, whole-deadline cancellation and first-attempt-only
0-RTT; the two shared-pool address-race scenarios also pass. The process record
contains twelve native cases and three independent grpc-js comparison rows.
