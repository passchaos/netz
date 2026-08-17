# netz vs `~/Work/quicz` HTTP/QUIC parity audit

This audit tracks the user goal: use the HTTP/QUIC implementations under
`~/Work` as a reference and evolve netz until its feature coverage and
performance are stronger.  It is intentionally evidence-based: each completed
item lists concrete netz code or a runnable command, and each gap remains open
until it has a direct artifact and validation.

## Current validated netz commands

These commands are the lightweight functional smoke set used while improving
parity:

```sh
zig build test
zig build run-quic-echo -Doptimize=ReleaseFast
zig build run-quic-handshake-echo -Doptimize=ReleaseFast
zig build run-quic-datagram-echo -Doptimize=ReleaseFast
zig build run-quic-close -Doptimize=ReleaseFast
zig build run-http3-fetch -Doptimize=ReleaseFast -- --discover --verify --head https://robotics.bytedance.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- --alt-svc='h3=":443"; ma=2592000' --verify --head https://robotics.bytedance.com/
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=upload --streams=2 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=download --streams=1 --verbose
```

Longer performance gates that have been used successfully include:

```sh
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=67108864 --mode=upload --streams=4 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=1 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=4 --verbose
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
zig build bench-quic-datagram -Doptimize=ReleaseFast
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=1 --verbose
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=4 --verbose
```

## Current direct `~/Work/quicz` comparison

A direct run of `~/Work/quicz/examples/quic_bench_hs.zig` with Zig 0.16 and
`-OReleaseFast -lc` produced these loopback real-handshake reference numbers:

```text
quicz Stream Upload:       228.77 MB/s mean, 3.3% stddev, 5 x 64 MiB
quicz Multi-Stream (4x):   244.85 MB/s mean, 2.8% stddev, 5 x 64 MiB
quicz Echo Latency:        P50 10.5us, P99 14.3us, P99.9 377.8us
quicz DATAGRAM:            228.01 MB/s, 1200B payload
netz QUIC DATAGRAM:        297.06 MiB/s, 1200B payload, 16 MiB transfer
netz Stream Upload:        311.69 MiB/s mean, 3.1% stddev, 3 x 64 MiB
netz Multi-Stream (4x):    314.68 MiB/s mean, 0.6% stddev, 3 x 64 MiB
```

`bench-quic-handshake-stream` now provides the previously missing direct
comparison. It performs a fresh TLS 1.3/QUIC handshake per iteration, uses the
same 64 MiB aggregate upload and one-/four-stream shapes, drives CUBIC recovery,
and consumes STREAM data through the allocation-free borrowed receive API.
The captured netz means are about 1.36x and 1.29x the latest same-host quicz
228.77/244.85 MB/s samples recorded in `docs/benchmark-baseline.md`.

The benchmark keeps UDP GSO/GRO disabled and defaults to one submitted packet
per userspace batch because this host clamps `net.core.rmem_max` to 212,992
bytes. Larger same-process loopback bursts overflow that kernel queue and
measure artificial packet-threshold recovery rather than protocol throughput;
`--batch-packets` remains available to test hosts with appropriately tuned
socket buffers. GSO/GRO performance stays covered by the dedicated QUIC batch
benchmarks.

## Feature parity table

| Area from `~/Work/quicz` examples | netz status | Evidence | Remaining work |
| --- | --- | --- | --- |
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered and faster in the current direct real-handshake throughput comparison | `examples/quic_echo.zig`, `examples/quic_handshake_echo.zig`, `examples/bench_quic_handshake_stream.zig`; 64 MiB means 311.69 MiB/s single-stream and 314.68 MiB/s four-stream | Keep the same-host matrix current and add latency/handshake-rate comparisons separately. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered and faster than current quicz DATAGRAM sample | `examples/quic_datagram_echo.zig`, `examples/bench_quic_datagram.zig`, `examples/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo`, `zig build bench-quic-datagram -Doptimize=ReleaseFast` | Keep raw and WebTransport DATAGRAM benchmarks in the comparison matrix. |
| Graceful/application close (`graceful_close`, close lifecycle) | Covered for local preconfigured 1-RTT smoke and tests | `examples/quic_close.zig`, one_rtt lifecycle tests, `zig build run-quic-close` | Add a full client/server CLI-style close demo only if external manual interop requires it. |
| Packet protection / initial keys / key update | Covered by modules and tests | `src/quic/protection.zig`, `src/quic/zero_rtt`, `src/quic/one_rtt/tests/crypto_path.zig`, `zig build test` | Keep vector coverage current as TLS suites evolve. |
| Loss recovery / PTO / retransmission | Partially covered and improved | `src/quic/recovery.zig`, `src/quic/one_rtt/tests/recovery_flow.zig`, bounded multi-candidate packet-threshold retransmission, commits covering orphan PTO and response retransmit | Continue investigating long-run 100% CPU busy loops seen in aggressive HTTP/3 transfer settings. |
| Flow control / stream reset / STOP_SENDING | Covered by implementation and tests | `src/quic/flow_control.zig`, `src/quic/stream.zig`, one_rtt tests | Add higher-level examples if user-facing docs need them. |
| Connection IDs / stateless reset / path validation / migration | Mostly covered in modules/tests | `src/quic/connection_id.zig`, `src/quic/stateless_reset.zig`, `src/quic/path_validation.zig`, lifecycle tests | Add runnable examples matching quicz's many UDP loopback demos if feature demos are required. |
| Retry/token/address validation | Covered at library level | `src/quic/retry_flow.zig`, `src/quic/address_validation_token.zig`, handshake/retry tests | Add public example after external interop is audited. |
| Congestion control (NewReno/CUBIC/HyStart++) | Covered and defaulted to CUBIC for 1-RTT | `src/quic/congestion.zig`, `src/quic/hystart.zig`, congestion tests | Evaluate quicz-style app-limited CUBIC behavior before changing production congestion math. |
| UDP batching / GSO / GRO | Covered at QUIC runtime level | `src/quic/runtime.zig`, `bench-quic-udp-batch`, `bench-quic-one-rtt-send`, `bench-quic-one-rtt-receive` | HTTP/3 direct GRO receive remains unsafe as a default; do not enable without fixing long-run stability. |
| HTTP/3 public fetch and Alt-Svc | Covered for robotics.bytedance.com with discovery and manual Alt-Svc override | `examples/http3_fetch.zig`, `run-http3-fetch --discover --verify --head`, `run-http3-fetch --alt-svc='h3=":443"; ma=2592000' --verify --head` | Broaden public interop matrix beyond one site; recent Cloudflare/Google/Facebook probes did not add passing coverage. |
| HTTP/3 real-handshake upload benchmark | Covered and improved | `examples/bench_http3_handshake_transfer.zig`; 4-stream 64MiB default has reached ~150+ MiB/s in validation | Continue comparing against `~/Work/quicz` throughput and stabilize aggressive chunk/datagram settings. |
| HTTP/3 real-handshake download benchmark | Covered for current benchmark scale | 64KiB/1MiB smoke pass; 4MiB, 16MiB, and 64MiB single-/4-stream download validations pass | Continue long-run stability and apples-to-apples quicz throughput comparisons before declaring performance superiority. |
| QPACK / Capsule / WebTransport | Covered by modules and benchmarks | `bench-http3-qpack`, `bench-http3-capsule`, `bench-webtransport-datagram` | Expand interop examples only after core H3 transfer gaps are closed. |
| TLS backend/process interop examples | Partially covered through netz/vail integration | QUIC handshake tests, `examples/quic_handshake_echo.zig`, HTTP/3 public fetch with `--verify` | netz still lacks quicz-style standalone TLS process echo demos; add only if this becomes a required deliverable. |

## Known blockers before declaring the goal complete

1. **Large HTTP/3 download reliability**: local real-handshake download now
   covers 4MiB/16MiB/64MiB benchmark-scale responses in both single-stream and
   four-stream runs, in addition to the 1MiB smoke tests and protected
   small-window coverage. The remaining work is long-run repeatability rather
   than a basic benchmark-scale functional gap.
2. **Aggressive receive batching**: enabling HTTP/3 GRO receive directly has
   caused long stalls.  The lower-level QUIC GRO benchmark works, but the H3
   runtime path needs more work before it can be defaulted.
3. **Long-run transfer busy loops**: some aggressive body chunk/datagram
   settings produce 100% CPU loops.  Until those are isolated, keep defaults
   conservative.
4. **Complete external interop matrix**: public H3 fetch is proven against
   `robotics.bytedance.com`, including `--discover`, manual `--alt-svc`, and
   `--verify`, but broader server/client interop is not yet audited. Recent
   Cloudflare/Google/Facebook probes failed or timed out and are intentionally
   not counted as coverage.
5. **Broader performance comparison against `~/Work/quicz`**: raw QUIC
   real-handshake STREAM and DATAGRAM throughput now have direct passing
   comparisons where the current netz samples are faster. Echo latency,
   handshake rate, loss simulation, stream churn, and multi-connection
   aggregate throughput still need equivalent netz artifacts before the whole
   quicz benchmark surface can be considered surpassed.

## Next recommended work

1. Extend the direct QUIC comparison with echo latency and handshake-rate
   modes, then loss/churn/multi-connection cases; raw STREAM and DATAGRAM
   throughput now exceed the captured quicz samples.
2. Investigate the aggressive receive batching path so HTTP/3 can safely use
   GRO without stalls.
3. Isolate the remaining long-run busy-loop cases seen with larger packet/body
   chunk settings before raising defaults.
4. Broaden public HTTP/3 interop beyond `robotics.bytedance.com`.
