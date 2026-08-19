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
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=download --streams=4 --verbose
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

## Current `~/Work/quicz` comparison context

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

The old values share a host and aggregate transfer shape but not a controlled
CPU layout. A fresh CPU-0-pinned quicz run produced 15.97/16.12 MB/s because
both same-process endpoints contend for one CPU; a matching netz raw probe was
also scheduling-bound. The previous 1.36x/1.29x raw STREAM ratios are withdrawn
until both stacks use an equivalent endpoint CPU layout.

HTTP/3 is a separate evidence gap: quicz's benchmark calls raw
`sendOnStream`, while `bench-http3-handshake-transfer` includes DATA framing,
request/response/QPACK work, and response completion. No equal-wire quicz H3
benchmark currently exists, so the netz H3 numbers are reported as internal
progress rather than a direct superiority claim.

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
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered; direct performance verdict pending controlled CPU layout | `examples/quic_echo.zig`, `examples/quic_handshake_echo.zig`, `examples/bench_quic_handshake_stream.zig`; historical unpinned 64 MiB netz means were 311.69 MiB/s single-stream and 314.68 MiB/s four-stream | Re-run both stacks with equivalent endpoint CPU placement; same-process single-CPU pinning is scheduling-bound and invalidates the old ratio. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered and faster than current quicz DATAGRAM sample | `examples/quic_datagram_echo.zig`, `examples/bench_quic_datagram.zig`, `examples/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo`, `zig build bench-quic-datagram -Doptimize=ReleaseFast` | Keep raw and WebTransport DATAGRAM benchmarks in the comparison matrix. |
| Graceful/application close (`graceful_close`, close lifecycle) | Covered for local preconfigured 1-RTT smoke and tests | `examples/quic_close.zig`, one_rtt lifecycle tests, `zig build run-quic-close` | Add a full client/server CLI-style close demo only if external manual interop requires it. |
| Packet protection / initial keys / key update | Covered by modules and tests | `src/quic/protection.zig`, `src/quic/zero_rtt`, `src/quic/one_rtt/tests/crypto_path.zig`, `zig build test` | Keep vector coverage current as TLS suites evolve. |
| Loss recovery / PTO / retransmission | Partially covered and improved | Recovery tests cover timer-driven losses and bounded payload caching; recovery also validates then streams arbitrary ACK range counts without a decoded-range allocation, unlike the audited quicz allocating ACK decode. Receive preflight now uses packet-local path/stream shadows instead of cloning heap-backed path-validation state per packet, cutting 16 MiB/four-stream H3 allocation calls by 16.2-16.5% in the captured A/B. | Add broader loss-rate/reordering and long-run recovery benchmarks; aggressive non-default packet/body sizing still needs separate coverage. |
| Flow control / stream reset / STOP_SENDING | Covered by implementation and tests | `src/quic/flow_control.zig`, `src/quic/stream.zig`, one_rtt tests | Add higher-level examples if user-facing docs need them. |
| Connection IDs / stateless reset / path validation / migration | Mostly covered in modules/tests | `src/quic/connection_id.zig`, `src/quic/stateless_reset.zig`, `src/quic/path_validation.zig`, lifecycle tests | Add runnable examples matching quicz's many UDP loopback demos if feature demos are required. |
| Retry/token/address validation | Covered at library level | `src/quic/retry_flow.zig`, `src/quic/address_validation_token.zig`, handshake/retry tests | Add public example after external interop is audited. |
| Congestion control (NewReno/CUBIC/HyStart++) | Covered and defaulted to CUBIC for 1-RTT | `src/quic/congestion.zig`, `src/quic/hystart.zig`, congestion tests | Evaluate quicz-style app-limited CUBIC behavior before changing production congestion math. |
| UDP batching / GSO / GRO | Covered through timer-aware QUIC/HTTP/3 paths | Batch/GRO APIs plus `servicePacket` and synchronous `visitPacket` apply current-key datagrams in place with retained frame scratch; handshake-backed HTTP/3 and WebTransport non-GRO pumps no longer create discarded owned packet diagnostics, while GRO keeps a lazy owning suffix for one-packet application routing; benchmarks cover owning, visitor, in-place and GRO paths | Keep H3 GRO opt-in on this small-rmem host and retest on tuned systems. |
| HTTP/3 public fetch and Alt-Svc | Covered for robotics.bytedance.com with discovery and manual Alt-Svc override | `examples/http3_fetch.zig`, `run-http3-fetch --discover --verify --head`, `run-http3-fetch --alt-svc='h3=":443"; ma=2592000' --verify --head` | Broaden public interop matrix beyond one site; recent Cloudflare/Google/Facebook probes did not add passing coverage. |
| HTTP/3 real-handshake upload benchmark | Covered and reliable at the tested default | `examples/bench_http3_handshake_transfer.zig`; CPU-0-pinned 4-stream 64 MiB upload completed 5/5 iterations at 141.78 MiB/s mean and 2.76% stddev with ACK threshold 4 and adaptive DATA sizing; exact-size cross-stream body batching is also available but opt-in on this small-rmem host | Build an equal-wire quicz H3 reference before making a cross-stack ratio; then reduce netz per-packet recovery/framing cost. |
| HTTP/3 real-handshake download and RFC 9218 response scheduling | Covered for current benchmark scale; feature coverage exceeds the local quicz H3 layer | `HandshakeServerSession.sendResponseBodiesPaced` schedules borrowed complete bodies by the request Priority field and live PRIORITY_UPDATE, serializes non-incremental peers, round-robins incremental peers, bypasses flow-blocked urgent streams, and replans after socket-visible packet prefixes; real-handshake tests cover all four behaviors and the benchmark sends `Priority: u=3, i`. `~/Work/quicz/src/h3` has no Priority field, PRIORITY_UPDATE, urgency, or incremental scheduler. The runtime now supports byte- or packet-cadence cooperative yielding; using a chunk-size-independent three-packet cadence raised five 64MiB/four-stream iterations from 11.35 MiB/s to a stable 44.15 MiB/s mean (3.47% stddev) while retaining full completion. | Continue apples-to-apples quicz throughput work before making a whole-stack performance claim; move same-process loopback pacing policy into a reusable event-loop benchmark harness. |
| QPACK / Capsule / WebTransport | Covered by modules, benchmarks, real-handshake streams and lifecycle controls | QPACK dynamic entries use indexed lookup, FIFO head eviction and one contiguous string allocation versus quicz reverse scans, front insertion and two string allocations; WebTransport adds transactional cross-stream batches and modern 0x41 association | Add external wtransport/browser interop and cancellation-under-loss evidence. |
| TLS backend/process interop examples | Partially covered through netz/vail integration | QUIC handshake tests, `examples/quic_handshake_echo.zig`, HTTP/3 public fetch with `--verify` | netz still lacks quicz-style standalone TLS process echo demos; add only if this becomes a required deliverable. |

## Known blockers before declaring the goal complete

1. **Large HTTP/3 download reliability**: local real-handshake download now
   covers 4MiB/16MiB/64MiB benchmark-scale responses in both single-stream and
   four-stream runs, in addition to the 1MiB smoke tests and protected
   small-window coverage. The remaining work is long-run repeatability rather
   than a basic benchmark-scale functional gap.
2. **Aggressive receive batching**: the prior timer starvation is fixed.
   Timer-aware GRO completed five 64 MiB/four-stream uploads and three
   downloads, including a transport test where PTO fires after a deliberately
   dropped packet. It remains opt-in because throughput is worse on this host,
   not because of a known reliability stall.
3. **Aggressive transfer settings**: the benchmark uses 3000-byte multi-stream
   chunks below 64 MiB and 6000 bytes for quicz-shaped 64 MiB runs. Larger
   12/14/16 KiB datagrams were slower or noisier, while cross-stream GSO
   batching remains opt-in because this host's small receive queue favors
   sequential packet submission.
4. **Complete external interop matrix**: public H3 fetch is proven against
   `robotics.bytedance.com`, including `--discover`, manual `--alt-svc`, and
   `--verify`, but broader server/client interop is not yet audited. Recent
   Cloudflare/Google/Facebook probes failed or timed out and are intentionally
   not counted as coverage.
5. **Broader performance comparison against `~/Work/quicz`**: raw QUIC
   STREAM comparisons need equivalent endpoint CPU placement, and HTTP/3 still
   lacks an equal-wire quicz reference. DATAGRAM has a direct passing sample,
   while echo latency, handshake rate, loss simulation, stream churn, and
   multi-connection aggregate throughput still need controlled equivalent
   artifacts before the whole quicz benchmark surface can be considered
   surpassed.

## Next recommended work

1. Rebuild the raw QUIC comparison with equivalent endpoint CPU placement,
   then add echo latency, handshake-rate, loss/churn, and multi-connection
   cases. The old unpinned ratio is no longer accepted as proof.
2. Re-run HTTP/3 GRO on a host with larger kernel UDP receive buffers; the
   timer/recovery path is now safe, but this host's throughput regresses.
3. Reduce HTTP/3 per-packet recovery ownership and STREAM/DATA framing cost;
   exact-size multi-stream batching now exists but needs a larger-rmem host to
   show a throughput benefit.
4. Broaden public HTTP/3 interop beyond `robotics.bytedance.com`.
