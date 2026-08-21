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
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=100
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=200
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
netz Echo Latency:         P50 20.6us, P99 30.5us, P99.9 38.7us
quicz DATAGRAM:            228.01 MB/s, 1200B payload
netz QUIC DATAGRAM:        297.06 MiB/s, 1200B payload, 16 MiB transfer
netz Stream Upload:        311.69 MiB/s mean, 3.1% stddev, 3 x 64 MiB
netz Multi-Stream (4x):    314.68 MiB/s mean, 0.6% stddev, 3 x 64 MiB
quicz Handshake:           P50 563.4us, P99 775.3us, 1131.3 conn/s
netz Handshake verified:   P50 1172.1us, P99 1367.8us, 830.7 conn/s
netz Handshake skip-verify:P50 657.9-833.0us, P99 1327.7-9971.1us, median 881.9 conn/s
quicz Stream Open:         48.1-52.0M streams/s, 100k streams
netz Stream Open:          680.2-778.0M streams/s, 100k streams
quicz Aggregate (4 conn):  503.2-533.1 MB/s, 4 x 64 MiB
netz Aggregate (4 conn):   730.4-900.6 MiB/s, 4 x 64 MiB
quicz Loss (1/5%):         220.8-236.7 / 216.8-223.6 MB/s
netz Loss (1/5%):          255.2-289.3 / 287.0-314.3 MiB/s
quicz Loss +100us RTT:     98.7-105.0 / 95.9-98.4 MB/s
netz Loss +100us RTT:      121.1-131.2 / 116.4-127.6 MiB/s
```

The original handshake values are fresh same-host ReleaseFast runs. Latency uses 200
fresh real TLS 1.3 connections and rate uses 100. The netz mode pins X25519
and TLS_AES_128_GCM_SHA256, reuses one immutable deterministic P-256 long-term
identity, and reports P50/P99/P99.9 plus aggregate connections/s. Every sample
still creates and validates a fresh server CertificateVerify against a pinned
key, whereas the current quicz workload sets `skip_cert_verify = true`. Netz
also uses an executor worker around its blocking public accept/connect API.
Those security and scheduling differences make this a concrete optimization
baseline, not a performance-superiority verdict.
The netz benchmark now also accepts `--skip-server-verification`, which retains
the server's Certificate and fresh P-256 CertificateVerify signature but skips
the client verification exactly like the audited quicz configuration. Five
CPU-0 runs put netz p50 at 657.9-833.0 us and median rate at 881.9 conn/s; three
quicz runs put p50 at 800.3-811.9 us and median rate at 749.3 conn/s. The broad
netz p99/rate ranges show host scheduling noise, so the result closes the
verification-policy mismatch but does not support a universal handshake claim.

The echo rows use the same 1 KiB/5,000-round real-handshake workload. A fresh
CPU-0-pinned three-run comparison measured netz at P50 10.44-10.57 us, P99
15.22-15.53 us, and P99.9 31.89-47.02 us, versus quicz at P50 10.5-10.7 us,
P99 16.0-19.5 us, and P99.9 206.3-211.2 us. Netz is therefore effectively
tied at p50, faster at p99, and substantially stronger at p99.9. The measured
step came from retaining the first unresolved sent-packet index so cumulative
ACK and loss scans no longer grow with connection lifetime. A following
compaction step retires contiguous acknowledged metadata in 256-packet batches
while retaining interval validation for duplicate cumulative ACKs. A 50,000
round CPU-0 run kept 149 allocations/685,276 cumulative bytes and 560,036 peak
live bytes, ended at zero, and measured 10.659/15.583/18.106 us p50/p99/p99.9.

The stream-open rows are a CPU-0-pinned, same-shape reservation microbenchmark
after a real handshake. Netz returns the complete expected ID sequence with no
timed-loop allocation and is 13.1-16.2x faster in the captured runs. It does
not claim stream close/recycling or on-wire churn, neither of which the quicz
reference loop measures.

The aggregate rows include worker creation, four independent I/O contexts,
real handshakes, four 64 MiB uploads, and teardown. Netz verifies every one of
the 268,435,456 aggregate payload bytes before reporting and is 1.37-1.79x
faster even without normalizing MB/s versus MiB/s in its favor.

The loss rows use the same 4 MiB single-stream, seeded client-to-server drop
policy and optional 100 us RTT delay. Netz verifies full receiver completion
and is conservatively 1.08-1.45x faster across all four scenarios without unit
normalization. Its loss mode reports exact injected and transport-observed loss
and can wrap the full run in allocator telemetry.

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
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered and faster at p99/p99.9 while tied at p50 | `examples/quic_echo.zig`, `examples/quic_handshake_echo.zig`, `examples/bench_quic_handshake_stream.zig`, `--mode=echo`; CPU-0-pinned netz P50/P99/P99.9 ranges were 10.44-10.57 / 15.22-15.53 / 31.89-47.02 us versus quicz 10.5-10.7 / 16.0-19.5 / 206.3-211.2 us. The benchmark verifies 5,120,000 bytes and needs only 159 allocations across 5,000 rounds. | Raw 64 MiB throughput still needs equivalent endpoint CPU placement before a general STREAM verdict. |
| QUIC TLS 1.3 handshake latency/rate (`quic_bench_hs`) | Covered with authenticated and quicz-aligned modes | `examples/bench_quic_handshake_stream.zig`, `--mode=handshake`; verified samples sustained 824.1-830.7 conn/s with P50 1172.1 us. `--skip-server-verification` retains Certificate/signing while matching quicz client policy; five CPU-0 runs measured P50 657.9-833.0 us and median 881.9 conn/s versus three quicz runs at P50 800.3-811.9 us and median 749.3 conn/s. Exact Initial sizing cut allocator calls from 167.0 to 92.0 per connection. | Equalize worker scheduling and reduce p99 variance before a whole-surface handshake claim. |
| QUIC stream-open churn (`quic_bench_hs`) | Covered and faster for the reference reservation workload | `examples/bench_quic_handshake_stream.zig`, `--mode=stream-churn`; CPU-0-pinned netz sustained 680.2-778.0M streams/s versus quicz 48.1-52.0M streams/s, a 13.1-16.2x range. IDs, limit enforcement, both endpoint roles, zero timed-loop allocation, final ID and checksum are validated. | Add a separate on-wire FIN/reset/recycling workload before generalizing this to full stream lifecycle churn. |
| QUIC concurrent aggregate (`quic_bench_hs`) | Covered and faster for four independent connections | `examples/bench_quic_handshake_stream.zig`, `--mode=aggregate --connections=4 --transfer-bytes=67108864`; netz completed at 730.35-900.57 MiB/s versus quicz 503.23-533.10 MB/s, a conservative 1.37-1.79x range, while verifying 4 x 64 MiB at receiver completion. | Add connection-count scaling curves and shared-event-loop comparison before generalizing beyond the four-worker shape. |
| QUIC simulated loss (`quic_bench_hs`) | Covered and faster for all four reference scenarios | `examples/bench_quic_handshake_stream.zig`, `--mode=loss`; 1%/5% loopback and 1%/5% with 100 us RTT were conservatively 1.08-1.45x faster than quicz, with deterministic injected-drop counts, full 4 MiB receiver completion, transport loss counters and optional memory telemetry. | Add bidirectional loss, reordering and corruption cases before generalizing beyond the reference one-way loss model. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered and faster than current quicz DATAGRAM sample | `examples/quic_datagram_echo.zig`, `examples/bench_quic_datagram.zig`, `examples/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo`, `zig build bench-quic-datagram -Doptimize=ReleaseFast` | Keep raw and WebTransport DATAGRAM benchmarks in the comparison matrix. |
| Graceful/application close (`graceful_close`, close lifecycle) | Covered for local preconfigured 1-RTT smoke and tests | `examples/quic_close.zig`, one_rtt lifecycle tests, `zig build run-quic-close` | Add a full client/server CLI-style close demo only if external manual interop requires it. |
| Packet protection / initial keys / key update | Covered by modules and tests | `src/quic/protection.zig`, `src/quic/zero_rtt`, `src/quic/one_rtt/tests/crypto_path.zig`, `zig build test` | Keep vector coverage current as TLS suites evolve. |
| Loss recovery / PTO / retransmission | Partially covered and improved | Recovery tests cover timer-driven losses and bounded payload caching; recovery also validates then streams arbitrary ACK range counts without a decoded-range allocation, unlike the audited quicz allocating ACK decode. Receive preflight now uses packet-local path/stream shadows instead of cloning heap-backed path-validation state per packet, cutting 16 MiB/four-stream H3 allocation calls by 16.2-16.5% in the captured A/B. The real-handshake raw STREAM gate now reorders every fifth client datagram after setup and verifies all 4 MiB: three runs held 100-122 packets and completed at 310.38-379.01 MiB/s. A corruption mode flipped authenticated ciphertext in exactly 25/504 datagrams and recovered all 4 MiB with 25 declared losses. | Add broader reordering/corruption distributions and long-run recovery benchmarks; aggressive non-default packet/body sizing still needs separate coverage. |
| Flow control / stream reset / STOP_SENDING | Covered by implementation and tests | `src/quic/flow_control.zig`, `src/quic/stream.zig`, one_rtt tests | Add higher-level examples if user-facing docs need them. |
| Connection IDs / stateless reset / path validation / migration | Mostly covered in modules/tests | `src/quic/connection_id.zig`, `src/quic/stateless_reset.zig`, `src/quic/path_validation.zig`, lifecycle tests | Add runnable examples matching quicz's many UDP loopback demos if feature demos are required. |
| Retry/token/address validation | Covered at library level | `src/quic/retry_flow.zig`, `src/quic/address_validation_token.zig`, handshake/retry tests | Add public example after external interop is audited. |
| Congestion control (NewReno/CUBIC/HyStart++) | Covered and defaulted to CUBIC for 1-RTT | `src/quic/congestion.zig`, `src/quic/hystart.zig`, congestion tests; ACK processing samples utilization before removing bytes in flight, suppresses NewReno/CUBIC growth while app-limited, and excludes idle time from the CUBIC epoch | Keep comparing long-lived congestion traces under equal loss/RTT schedules. |
| UDP batching / GSO / GRO | Covered through timer-aware QUIC/HTTP/3 paths | Batch/GRO APIs plus `servicePacket` and synchronous `visitPacket` apply current-key datagrams in connection-owned receive storage with retained frame scratch; handshake-backed HTTP/3 and WebTransport non-GRO pumps no longer create discarded owned packet diagnostics or per-packet UDP buffers, while GRO keeps a lazy owning suffix for one-packet application routing. The captured 16 MiB/four-stream H3 step reduced allocation calls another 47.8-48.1%. | Keep H3 GRO opt-in on this small-rmem host and retest on tuned systems. |
| HTTP/3 public fetch and Alt-Svc | Covered for robotics.bytedance.com with discovery and manual Alt-Svc override | `examples/http3_fetch.zig`, `run-http3-fetch --discover --verify --head`, `run-http3-fetch --alt-svc='h3=":443"; ma=2592000' --verify --head` | Broaden public interop matrix beyond one site; recent Cloudflare/Google/Facebook probes did not add passing coverage. |
| HTTP/3 real-handshake upload benchmark | Covered and reliable at the tested default | `examples/bench_http3_handshake_transfer.zig`; CPU-0-pinned 4-stream 64 MiB upload completed 5/5 iterations at 141.78 MiB/s mean and 2.76% stddev with ACK threshold 4 and adaptive DATA sizing; exact-size cross-stream body batching is also available but opt-in on this small-rmem host | Build an equal-wire quicz H3 reference before making a cross-stack ratio; then reduce netz per-packet recovery/framing cost. |
| HTTP/3 real-handshake download and RFC 9218 response scheduling | Covered for current benchmark scale; feature coverage exceeds the local quicz H3 layer | `HandshakeServerSession.sendResponseBodiesPaced` schedules borrowed complete bodies by the request Priority field and live PRIORITY_UPDATE, serializes non-incremental peers, round-robins incremental peers, bypasses flow-blocked urgent streams, and replans after socket-visible packet prefixes; real-handshake tests cover all four behaviors and the benchmark sends `Priority: u=3, i`. `~/Work/quicz/src/h3` has no Priority field, PRIORITY_UPDATE, urgency, or incremental scheduler. The runtime now supports byte- or packet-cadence cooperative yielding; using a chunk-size-independent three-packet cadence raised five 64MiB/four-stream iterations from 11.35 MiB/s to a stable 44.15 MiB/s mean (3.47% stddev) while retaining full completion. | Continue apples-to-apples quicz throughput work before making a whole-stack performance claim; move same-process loopback pacing policy into a reusable event-loop benchmark harness. |
| QPACK / Capsule / WebTransport | Covered by modules, benchmarks, real-handshake streams and lifecycle controls | QPACK dynamic entries use indexed lookup, FIFO head eviction and one contiguous string allocation versus quicz reverse scans, front insertion and two string allocations; WebTransport adds transactional cross-stream batches and modern 0x41 association | Add external wtransport/browser interop and cancellation-under-loss evidence. |
| TLS backend/process interop examples | Covered in both directions through a standalone, certificate-verified quic-go process gate | QUIC handshake tests, `examples/quic_handshake_echo.zig`, `zig build interop-quic-quic-go -Doptimize=ReleaseFast`, HTTP/3 public fetch with `--verify` | Add broader peers and lifecycle cases before making a full interoperability claim. |

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
   Raw QUIC now has a separate process-boundary client gate:
   `zig build interop-quic-quic-go -Doptimize=ReleaseFast` builds quic-go
   v0.59.0 from the audited `~/Work/quicz` fixture, loads its generated
   localhost CA into netz's verifier, requires TLS 1.3 `hq-interop` ALPN, and
   verifies two independent bidirectional STREAM echoes plus FIN. The same gate
   also runs the fixture's certificate-verifying quic-go client against a
   one-shot netz server and checks the same two stream IDs, payloads, FINs, and
   `hq-interop` ALPN. Supporting that standard quic-go client required netz's
   1-RTT connection state to distinguish a legal zero-length Initial Source
   Connection ID from the non-empty IDs required in NEW_CONNECTION_ID frames.
   This is direct two-way QUIC transport evidence, not a local loopback proxy
   for HTTP/3.
5. **Broader performance comparison against `~/Work/quicz`**: raw QUIC
   STREAM comparisons need equivalent endpoint CPU placement, and HTTP/3 still
   lacks an equal-wire quicz reference. DATAGRAM, loss simulation, four-
   connection aggregate throughput, and stream reservation have direct faster
   artifacts, but on-wire stream lifecycle churn remains open. Echo latency
   now has a controlled artifact that is tied/faster across percentiles. Handshake
   latency/rate now has a verification-policy-aligned artifact, but the two
   workloads still need equal worker scheduling and lower tail variance before
   the whole quicz benchmark surface can be considered surpassed.

## Next recommended work

1. Rebuild the raw QUIC comparison with equivalent endpoint CPU placement,
   then add reordering/corruption/on-wire-churn and connection-count scaling
   cases. The handshake artifact includes allocation telemetry;
   equalize certificate verification and endpoint scheduling before comparing
   its rate. The old unpinned ratio is no longer accepted as proof.
2. Re-run HTTP/3 GRO on a host with larger kernel UDP receive buffers; the
   timer/recovery path is now safe, but this host's throughput regresses.
3. Reduce HTTP/3 per-packet recovery ownership and STREAM/DATA framing cost;
   exact-size multi-stream batching now exists but needs a larger-rmem host to
   show a throughput benefit.
4. Broaden public HTTP/3 interop beyond `robotics.bytedance.com`.
