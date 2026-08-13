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
zig build run-quic-datagram-echo -Doptimize=ReleaseFast
zig build run-quic-close -Doptimize=ReleaseFast
zig build run-http3-fetch -Doptimize=ReleaseFast -- --discover --verify --head https://robotics.bytedance.com/
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
```

## Current direct `~/Work/quicz` comparison

A direct run of `~/Work/quicz/examples/quic_bench_hs.zig` with Zig 0.16 and
`-OReleaseFast -lc` produced these loopback real-handshake reference numbers:

```text
quicz Stream Upload:       217.22 MB/s mean, 4.7% stddev, 5 x 64 MiB
quicz Multi-Stream (4x):   244.57 MB/s mean, 3.0% stddev, 5 x 64 MiB
quicz Echo Latency:        P50 10.7us, P99 23.7us, P99.9 283.6us
quicz DATAGRAM:            228.01 MB/s, 1200B payload
netz QUIC DATAGRAM:        297.06 MiB/s, 1200B payload, 16 MiB transfer
```

The closest currently validated netz run is HTTP/3-over-QUIC rather than raw
QUIC STREAM, so it includes HTTP/3 framing/QPACK/session overhead. Its 4-stream
64MiB upload gate currently reaches about `155.04 MiB/s` mean over 5 iterations
with `0.82%` stddev. This proves the transfer is functional and stable, but it
does **not** yet prove performance superiority over quicz. A true apples-to-
apples raw QUIC real-handshake transfer benchmark for netz remains needed, and
HTTP/3 upload still needs optimization if it is expected to exceed quicz's raw
QUIC throughput.

## Feature parity table

| Area from `~/Work/quicz` examples | netz status | Evidence | Remaining work |
| --- | --- | --- | --- |
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered for local preconfigured 1-RTT smoke | `examples/quic_echo.zig`, `zig build run-quic-echo` | Add a TLS-handshake echo variant if needed for user-facing demos. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered and faster than current quicz DATAGRAM sample | `examples/quic_datagram_echo.zig`, `examples/bench_quic_datagram.zig`, `examples/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo`, `zig build bench-quic-datagram -Doptimize=ReleaseFast` | Keep raw and WebTransport DATAGRAM benchmarks in the comparison matrix. |
| Graceful/application close (`graceful_close`, close lifecycle) | Covered for local preconfigured 1-RTT smoke and tests | `examples/quic_close.zig`, one_rtt lifecycle tests, `zig build run-quic-close` | Add a full client/server CLI-style close demo only if external manual interop requires it. |
| Packet protection / initial keys / key update | Covered by modules and tests | `src/quic/protection.zig`, `src/quic/zero_rtt`, `src/quic/one_rtt/tests/crypto_path.zig`, `zig build test` | Keep vector coverage current as TLS suites evolve. |
| Loss recovery / PTO / retransmission | Partially covered and improved | `src/quic/recovery.zig`, `src/quic/one_rtt/tests/recovery_flow.zig`, commits covering orphan PTO and response retransmit | Continue investigating long-run 100% CPU busy loops seen in aggressive HTTP/3 transfer settings. |
| Flow control / stream reset / STOP_SENDING | Covered by implementation and tests | `src/quic/flow_control.zig`, `src/quic/stream.zig`, one_rtt tests | Add higher-level examples if user-facing docs need them. |
| Connection IDs / stateless reset / path validation / migration | Mostly covered in modules/tests | `src/quic/connection_id.zig`, `src/quic/stateless_reset.zig`, `src/quic/path_validation.zig`, lifecycle tests | Add runnable examples matching quicz's many UDP loopback demos if feature demos are required. |
| Retry/token/address validation | Covered at library level | `src/quic/retry_flow.zig`, `src/quic/address_validation_token.zig`, handshake/retry tests | Add public example after external interop is audited. |
| Congestion control (NewReno/CUBIC/HyStart++) | Covered and defaulted to CUBIC for 1-RTT | `src/quic/congestion.zig`, `src/quic/hystart.zig`, congestion tests | Evaluate quicz-style app-limited CUBIC behavior before changing production congestion math. |
| UDP batching / GSO / GRO | Covered at QUIC runtime level | `src/quic/runtime.zig`, `bench-quic-udp-batch`, `bench-quic-one-rtt-send`, `bench-quic-one-rtt-receive` | HTTP/3 direct GRO receive remains unsafe as a default; do not enable without fixing long-run stability. |
| HTTP/3 public fetch and Alt-Svc | Covered for robotics.bytedance.com | `examples/http3_fetch.zig`, `run-http3-fetch --discover --verify --head` | Broaden public interop matrix beyond one site. |
| HTTP/3 real-handshake upload benchmark | Covered and improved | `examples/bench_http3_handshake_transfer.zig`; 4-stream 64MiB default has reached ~150+ MiB/s in validation | Continue comparing against `~/Work/quicz` throughput and stabilize aggressive chunk/datagram settings. |
| HTTP/3 real-handshake download benchmark | Covered for current benchmark scale | 64KiB/1MiB smoke pass; 4MiB, 16MiB, and 64MiB single-/4-stream download validations pass | Continue long-run stability and apples-to-apples quicz throughput comparisons before declaring performance superiority. |
| QPACK / Capsule / WebTransport | Covered by modules and benchmarks | `bench-http3-qpack`, `bench-http3-capsule`, `bench-webtransport-datagram` | Expand interop examples only after core H3 transfer gaps are closed. |
| TLS backend/process interop examples | Partially covered through netz/vail integration | QUIC handshake tests, HTTP/3 public fetch with `--verify` | netz lacks quicz-style standalone TLS process echo demos; add only if this is a required deliverable. |

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
   `robotics.bytedance.com`, including `--discover` and `--verify`, but broader
   server/client interop is not yet audited.
5. **Performance comparison against `~/Work/quicz`**: an initial direct quicz
   run is now recorded, but netz still lacks a true raw QUIC real-handshake
   apples-to-apples benchmark and the validated HTTP/3 4-stream upload result
   remains below quicz's raw QUIC reference throughput.

## Next recommended work

1. Run longer repeated 64MiB download/upload matrices and compare the numbers
   directly with the relevant `~/Work/quicz` benchmarks; DATAGRAM now has a
   raw benchmark where netz exceeds the captured quicz sample.
2. Investigate the aggressive receive batching path so HTTP/3 can safely use
   GRO without stalls.
3. Isolate the remaining long-run busy-loop cases seen with larger packet/body
   chunk settings before raising defaults.
4. Broaden public HTTP/3 interop beyond `robotics.bytedance.com`.
