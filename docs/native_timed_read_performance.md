# Native timed socket read experiment

The native NetRecv reader candidate was rejected. The final library retains
its original synchronous std.Io Batch/file-read deadline path. The experiment
is saved to prevent repeating an optimization that lowers instruction count
while consistently increasing CPU cycles.

A current production broker profile led to a candidate that bypassed generic
Batch/file-read dispatch for matching zio tasks. The pinned zio revision already
runs exactly one submitted Batch operation synchronously. The initial extra-task
interpretation was incorrect and was corrected before delivery; no task-removal
claim applies to this candidate.

The candidate passed 141 native I/O checks, 1128 HTTP/2/gRPC/common-I/O checks,
236 HTTP/1/WebSocket/MQTT receive/deadline checks, the package gate, bidirectional
h2c/verified-TLS gRPC interop and MQTT/Mosquitto bridge recovery. Native buffer
checks covered EOF, expired budgets, abortive reset and joined timeout/cancel
storage. Functional parity alone was insufficient to retain the change.

The first fixed-driver comparison used eight serial pairs and two pairs of each
of four production control shapes. Both ReleaseFast brokers used CPU 1 and the
unchanged baseline driver CPU 0, QoS 2, a 3600-second Session Expiry, queue
capacity 100000 and outgoing inflight 64. Serial used 1000 warmups, 10000 measured
publishes, 256-byte payloads and window 1. Every arm validated exact delivery
count and workload checksum. Perf stat covered the broker's user instructions
and cycles, including startup and warmup.

| Shape | Instruction reduction | Elapsed baseline/native | p50 baseline/native | p99 baseline/native |
| --- | ---: | ---: | ---: | ---: |
| serial | 1.943% | 0.9986x | 0.9987x | 1.0015x |
| publishers-32 | 1.174% | 1.0136x | 1.0214x | 1.0214x |
| fanout-32 | 0.694% | 1.0101x | 1.0005x | 1.0342x |
| balanced-32x32 | 0.555% | 1.0078x | 1.0305x | 1.0107x |
| large-payload | 0.343% | 1.0148x | 1.0431x | 1.0191x |

Serial instructions fell about 1.94% with 8/8 paired wins, but cycle count rose
about 2.95% and elapsed/p50 were effectively unchanged. A further sixteen serial
pairs used the same two fixed binaries, fixed driver and workload to resolve
that cycle concern.

| Stability metric | Baseline median | Native median | Baseline/native | Paired native wins |
| --- | ---: | ---: | ---: | ---: |
| instructions:u | 272136666.0 | 266881929.5 | 1.019689x | 16/16 |
| cycles:u | 148299817.0 | 151482947.0 | 0.978987x | 0/16 |
| elapsed_ns | 441586254.0 | 444078655.5 | 0.994387x | 7/16 |
| p50_ns | 37987.5 | 37760.5 | 1.006012x | 10/16 |
| p99_ns | 43302.0 | 43450.0 | 0.996594x | 10/16 |

The stability run again reduced instructions about 1.93%, while cycles rose
about 2.15% in 16/16 pairs. Elapsed was slightly worse and tail/median timings
were mixed. This stable cycle regression outweighed the instruction reduction,
so the runtime candidate and its candidate-only tests were reverted. The source
was checked against c0f04bfb and the restored I/O/package checks were rerun.

[All 64 complete broker runs](evidence/native_timed_read/2026-10-28-broker-ab.json)
retain the first capture, stability capture, exact workloads, checksums, raw
samples and source/executable identities. The candidate snapshot is 80e477b2;
908b5eab only corrected its dispatch comment. Both stability arms use those
same fixed executables. A fresh 100000-message baseline profile lost three of
about 4477 samples and remains orientation evidence only.

One separate current same-client Mosquitto pair completed 10000 deliveries per
arm: netz 22336/s versus Mosquitto 29868/s, with 2-ms sampled peak broker RSS
3904 versus 3028 KiB. One pair is not a broad matrix conclusion; the larger
broker scheduling, durable QoS 2 and memory deficits remain active work.
