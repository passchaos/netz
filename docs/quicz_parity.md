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
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
```

## Feature parity table

| Area from `~/Work/quicz` examples | netz status | Evidence | Remaining work |
| --- | --- | --- | --- |
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered for local preconfigured 1-RTT smoke | `examples/quic_echo.zig`, `zig build run-quic-echo` | Add a TLS-handshake echo variant if needed for user-facing demos. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered for local preconfigured 1-RTT smoke and WebTransport benchmark | `examples/quic_datagram_echo.zig`, `examples/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo` | Add raw QUIC DATAGRAM throughput benchmark if performance parity with `quic_bench_datagram` becomes a target. |
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
| HTTP/3 real-handshake download benchmark | Partially covered | 64KiB and 1MiB smoke pass after benchmark receiver scheduling fix | Large responses (4MiB/16MiB+) still need core runtime/lifecycle investigation before claiming complete download support. |
| QPACK / Capsule / WebTransport | Covered by modules and benchmarks | `bench-http3-qpack`, `bench-http3-capsule`, `bench-webtransport-datagram` | Expand interop examples only after core H3 transfer gaps are closed. |
| TLS backend/process interop examples | Partially covered through netz/vail integration | QUIC handshake tests, HTTP/3 public fetch with `--verify` | netz lacks quicz-style standalone TLS process echo demos; add only if this is a required deliverable. |

## Known blockers before declaring the goal complete

1. **Large HTTP/3 download reliability**: local real-handshake download works for
   small and 1MiB smoke tests, the deterministic handshake streaming response
   test covers 1MiB, and the preconfigured protected runtime now covers 1MiB
   small-window responses with explicit protected-runtime stream-credit
   feedback. Benchmark-scale responses still show queue/recovery sensitivity,
   which is now the top functionality gap.
2. **Aggressive receive batching**: enabling HTTP/3 GRO receive directly has
   caused long stalls.  The lower-level QUIC GRO benchmark works, but the H3
   runtime path needs more work before it can be defaulted.
3. **Long-run transfer busy loops**: some aggressive body chunk/datagram
   settings produce 100% CPU loops.  Until those are isolated, keep defaults
   conservative.
4. **Complete external interop matrix**: public H3 fetch is proven against
   `robotics.bytedance.com`, including `--discover` and `--verify`, but broader
   server/client interop is not yet audited.
5. **Performance comparison against `~/Work/quicz`**: netz has improved, but no
   final apples-to-apples benchmark report proves it exceeds quicz across
   stream, datagram, handshake, upload, and download scenarios.

## Next recommended work

1. Use the protected 1MiB small-window coverage to keep tightening
   response-side flow-control/recovery/lifecycle handling without
   benchmark-layer scheduling hacks.
2. Extend real-handshake download reliability beyond the current 1MiB smoke
   level toward 4MiB/16MiB+ benchmark-scale responses.
3. Once download is reliable, rerun the 64MiB upload/download benchmark matrix.
4. Only then revisit GRO and larger packet/body chunk defaults.
