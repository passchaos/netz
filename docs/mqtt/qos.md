# MQTT QoS matrices and router results

[Back to the rumqtt parity index](../rumqtt_parity.md).

## Same-client live broker comparison

`examples/benchmarks/bench_mqtt_broker.zig` is one external MQTT 5 TCP client workload,
not a broker-specific adapter. It connects subscribers first, verifies every
SUBACK, then connects publishers. Each measured input is a QoS 1 PUBLISH and
each subscriber receives and PUBACKs one QoS 1 delivery. The timer starts only
after warmup deliveries have drained and ends when the last measured
subscriber delivery is acknowledged. The checksum catches missing or
mis-sized payloads.
The current driver obtains `std.Io` from zio and runs all subscriber readers in
an `std.Io.Group`; event barriers delimit connection readiness, drained warmup,
and the measured interval without polling an OS-thread counter. Its structured
result records always identify `client_io=zio-std-io` and accept only the
explicit `netz/zio-std-io`, `mosquitto/mosquitto-event-loop`, or standalone
external server identity pair. This is not an equal-wire claim: the gate does
not capture or equalize TCP segmentation, acknowledgements, kernel buffering,
or broker-specific control traffic.
The maintained comparison requires every expected fanout delivery, so its
runner gives both brokers the same queue capacity: at least the historical
1,024-message bound and large enough for the longer of the warmup and measured
phases. This prevents a valid bounded-queue drop from turning a long run into a
misleading Keep Alive timeout.
`MQTT_MAX_QUEUED_MESSAGES` may raise that common bound, but the runner rejects
an override smaller than either phase.
Structured timing, memory, and verification records bind that capacity as
`server_queue_capacity`, so results with different loss budgets cannot be
mistaken for an equal-configuration comparison.

The netz broker is a finite process for deterministic teardown:

```sh
zig build run-mqtt-broker -Doptimize=ReleaseFast -- \
  --bind=127.0.0.1:18883 --connections=8 \
  --max-queued-deliveries=1024 --max-outgoing-inflight=64 \
  --persistence=netz-mqtt.db --autosave-interval-seconds=30 \
  --autosave-change-count=100
```

The finite example restores that snapshot before accepting clients and saves
again after all configured connections exit. With the autosave interval above,
it also writes live checkpoints while clients remain connected;
`--no-restore` starts from an empty in-memory state but still writes periodic
and final snapshots. The change-count option currently writes after 100 broker
operations that change snapshot-backed state. A compound publish/fanout or
lifecycle operation counts once, and periodic `$SYS` refreshes are excluded so
telemetry cannot force checkpoint churn. Both positive thresholds may be
enabled together; either trigger writes the same atomic destination, and the
broker serializes concurrent snapshot writers. Both require `--persistence`
and are rejected with `--commit-log`, which already journals each
protocol-visible durable boundary. Change-triggered checkpoint failures remain
pending for retry and are exposed by `Broker.persistentChangeAutosaveError`
rather than retroactively failing an MQTT operation whose in-memory mutation
has already committed. `zig build interop-mqtt-live-autosave
-Doptimize=ReleaseFast` creates a durable subscription, waits for an autosave,
kills the broker without its final save, restores the database in a fresh
process, and verifies Session Present plus live routing through the restored
subscription. The same process gate now takes that Session offline, queues an
opt-in QoS 0 message, waits for a later atomic checkpoint, kills the broker,
and requires the exact packet once immediately after reconnect before proving
the restored connection remains usable with PING.

Run the same sequential (window-one) driver against any broker address:

```sh
zig build bench-mqtt-broker -Doptimize=ReleaseFast -- \
  --address=127.0.0.1:PORT --publishers=4 --subscribers=4 \
  --warmup-messages=1000 --messages=20000 --payload-bytes=256
```

The repository now also packages the complete local Mosquitto comparison as a
single build step. It builds the audited checkout with non-broker components
disabled, allocates independent loopback ports, waits for each broker's ready
marker, runs the same already-built netz client against both processes, checks
the complete result shape, derived rates, latency ordering, backend identities,
and independently calculated checksum, then tears down every child:

```sh
zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast
MQTT_STATS=true zig build compare-mqtt-mosquitto -Doptimize=ReleaseFast
zig build compare-mqtt-mosquitto-matrix -Doptimize=ReleaseFast
MQTT_QOS=2 zig build compare-mqtt-mosquitto-matrix -Doptimize=ReleaseFast
```

`MOSQUITTO_BIN` may select an existing executable, while `MOSQUITTO_ROOT`
overrides the default `~/Work/mosquitto` checkout used for an isolated build.
Source builds require the audited `5cd25465` revision unless
`MOSQUITTO_COMMIT` explicitly selects another revision;
`PUBLISHERS`, `SUBSCRIBERS`, `WARMUP_MESSAGES`, `MESSAGES`, `PAYLOAD_BYTES`,
and `PUBLISHER_WINDOW` select a bounded smoke or longer measurement;
`MQTT_QOS=1|2` selects the complete acknowledgement flow. Building
Mosquitto requires its normal development dependencies, including cJSON
headers; the gate reports that requirement rather than silently using an
unrelated system broker. `MQTT_STATS=true` additionally samples each broker's
resident memory from Linux `/proc/PID/status` every 2 ms and emits validated
machine-readable memory records without changing the client workload.

The matrix command is deliberately stricter than the configurable one-shape
runner. It fixes five complementary shapes, requires three available CPUs, and
pins the common netz driver, active broker, and RSS sampler separately. Each
shape runs four paired samples in `netz, Mosquitto, Mosquitto, netz` ABBA
order. The matrix refuses an injected `MOSQUITTO_BIN`, requires the audited
checkout to be clean, and builds revision
`5cd2546511596a269dbf53f85858c623b09ebdd6` for that run. Artifacts under
`zig-out/mqtt-broker-matrix/run.*` retain the actual binaries, source-state and
build logs, runners/checkers/config helper, per-run broker/result/RSS logs, and
CPU/order metadata. SHA-256 binds every executable and tool. The checker
requires the exact directory structure, recomputes all hashes, reruns the
single-shape workload/checksum/rate validation for every pair, verifies the
ABBA schedule, and caps each artifact at 32 MiB and the matrix at 128 MiB.
Both brokers use `TCP_NODELAY`; Mosquitto's per-packet verbose logging is
disabled so logging and delayed ACKs cannot manufacture a comparison result.

The pre-QoS-1-writer aarch64 Linux capture used CPUs 0/1/2 for
client/server/sampler, Zig 0.16.0, four ABBA samples per shape, one exact
subscription per subscriber, MQTT 5 QoS 1, and 2-ms broker RSS sampling. All
40 broker runs completed their expected deliveries and independently
recomputed checksums. Its complete artifact is
`zig-out/mqtt-broker-qos2-writer-qos1-final3` (23,221,848 bytes);
the stored summary SHA-256 is
`5f32c63cbd4c0167a4f99c1b1d7f44794d9da516a5a79ee36c053996bc762574`.
Rates and p99 are medians; brackets show every sample.

| shape (publishers × subscribers, payload, window) | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial (1×1, 256 B, 1) | 29,708 [29,294–29,828] | 41,822 [39,404–43,340] | 0.710× | 0.032 / 0.030 | 3.51 / 2.96 |
| publishers-32 (32×1, 64 B, 4) | 50,590 [49,486–51,128] | 67,296 [64,537–69,070] | 0.752× | 0.851 / 1.243 | 5.05 / 4.21 |
| fanout-32 (1×32, 64 B, 4) | 2,843 [2,836–2,849] | 4,474 [4,473–4,503] | 0.635× | 1.357 / 0.571 | 4.52 / 3.13 |
| balanced-32x32 (32×32, 64 B, 4) | 4,187 [4,002–4,238] | 4,549 [4,454–4,742] | 0.920× | 23.002 / 17.443 | 8.68 / 11.31 |
| large-payload (4×4, 4096 B, 16) | 19,621 [19,525–19,652] | 23,874 [23,426–25,035] | 0.822× | 2.371 / 3.824 | 3.69 / 4.11 |

That matrix exposes rather than hides the then-current deficit. Netz reaches
0.635–0.920× Mosquitto's median throughput across all five shapes. Its p99 is
lower in the publisher-heavy and 4-KiB shapes and higher in the other three.
Median broker RSS is higher in three shapes and lower in balanced 32×32 and
4-KiB. The balanced RSS range is wide because the faster common client can
build different transient broker backlogs, so the isolated fixed-driver A/B
below remains the evidence for the connection-layout change.
Client allocation counts are identical because both arms run the same fixed
netz client binary; they bind harness cost and catch shape drift rather than
measuring broker-internal allocations. An earlier diagnostic run had left
Mosquitto's per-packet verbose logging enabled and misleadingly favored netz
in high-fanout/windowed shapes; those values are intentionally discarded. The
accepted matrix explicitly aligns `TCP_NODELAY=true` on both brokers and omits
verbose packet logging. These results identify broker scheduling, serial
latency, and per-connection memory as the next optimization targets.

## Current QoS 1 broker matrix

A fresh 2026-11-01 QoS 1 capture on the current broker and driver, using the
same ABBA schedule and pinned CPUs 0/1/2, now measures netz above Mosquitto in
all five shapes: serial 57,246 vs 49,747 (1.151×), publishers-32 80,792 vs
73,221 (1.103×), fanout-32 6,146 vs 5,525 (1.112×), balanced-32x32 5,937 vs
5,132 (1.157×), and large-payload 30,338 vs 29,927 (1.014×). This supersedes
the pre-QoS-1-writer throughput deficit for current code while leaving that
historical capture separately scoped. QoS 2 and durable-Session captures remain
separate measurements.

A balanced-32x32 QoS 1 profile (425 zero-loss `cycles:Pu` samples) places the
delivery flush path first: `flushSlotLockedMode` is 20.36% self and 44.48%
children, `writePublish` is 5.64% self and 18.52% children, `sync.Futex.wait`
is 7.60%, and `AnyTask.yield` is 6.54%. The flush loop takes the global state
lock once per queued delivery. The next candidate is batching transient queue
pops under one critical section and writing outside the lock while preserving
durable session-packet priority, queue order, inflight limits and push-back
rollback. Evidence is in
`docs/evidence/mqtt_broker_profile/2026-11-01-balanced-qos1.json`.

A narrower attempt to skip that Session drain when
`slot.state.session_persistent` is false was rejected: the focused
`broker enforces unsubscribe and outgoing delivery access control` test failed
consistently on three runs with the client observing `ConnectionClosed` while
waiting for a retained PUBLISH. Transient Sessions can still carry Session
packets, so the unconditional drain remains; reverting the change restored
144/144 tests. See
`docs/evidence/mqtt_transient_session_drain_rejected/2026-11-01.json`.

A four-delivery transient queue batching candidate was also rejected. It
improved the targeted QoS 1 balanced shape (p50 3.623 → 3.275 ms, p99
10.639 → 7.833 ms) and serial throughput (57,246 → 61,667/s), but QoS 2
regressed in four of five shapes even after restricting QoS 2 to one delivery
per lock and inlining the helper: serial 27,398 → 27,048/s with p99 0.042 →
0.083 ms, publishers-32 38,309 → 34,993/s, fanout-32 3,100 → 2,808/s and
balanced 3,212 → 2,901/s. The shared flush refactor and reservation bookkeeping
cost more than the saved locks for QoS 2, so the change was reverted. A future
attempt must leave the QoS 2 flush path structurally unchanged. See
`docs/evidence/mqtt_queue_batch_rejected/2026-11-01.json`.

A 2026-11-18 transient-only retry kept every Session packet (including QoS 2)
on the original one-at-a-time path and batched only live-queue deliveries. The
shared macOS host was too noisy for a decision: baseline/candidate balanced
QoS 1 p50 was roughly 3.5–3.9 ms in both arms, p99 ranged from 5.1 ms to
11.9 ms within each arm, and later pairs were dominated by unrelated host load.
The code change was reverted; the experiment remains open until it can run on a
quiet host with the audited Mosquitto matrix. `zig build build-mqtt-bench`
builds the standalone driver used for that comparison.

The remaining gap has moved to tail latency and memory. Balanced-32x32 p99 is
10.64 ms versus 4.22 ms, and serial p999 is 287.9 us versus 69.4 us. Broker RSS
is 1.16–1.65× Mosquitto in four shapes and 0.66× in balanced-32x32. The host
also ran unrelated build/test jobs during this capture, so the throughput
direction is ABBA-paired and consistent across 20 pairs while p99 and RSS
values are noisier. Full per-sample records, build logs, environment hashes and
the strict checker output are in
`docs/evidence/mqtt_broker_matrix/2026-11-01.json`.

A 64-KiB initial coroutine-stack prefix was tested as an RSS reduction and
rejected. Across the same five-shape ABBA matrix it raised median broker RSS in
four shapes (serial +340 KiB, publishers-32 +340 KiB, fanout-32 +332 KiB,
large-payload +1,160 KiB), was only slightly lower in balanced-32x32, and moved
the large-payload throughput ratio from 1.014× to 0.986×. Stack growth and pool
retention make the initial prefix ineffective here; the code change and the
broker-example opt-in were reverted. The comparison and both matrix summaries
are in `docs/evidence/mqtt_broker_stack_prefix_rejected/2026-11-01.json`.


The same driver and strict artifact pipeline now cover QoS 2. Subscriber tasks
consume interleaved PUBLISH and PUBREL events through one socket reader, track
the bounded set of pending Packet Identifiers, and send PUBREC/PUBCOMP without
assuming adjacent control packets. Publisher completion similarly demultiplexes
interleaved PUBREC/PUBCOMP packets per connection and applies each transition
through the production runtime state machine. This preserves the configured
publisher window instead of serializing QoS 2 to an easier window-one shape.
The current CPU-0/1/2 capture at
`zig-out/mqtt-broker-qos2-writer-final3` (23,221,979 bytes; summary SHA-256
`1df7a0be6e51b819ccde56b9c5d0d99e972a54f95b43cb555dde16149c18a465`)
completed all 40 ABBA runs with exact delivery counts and independently
recomputed checksums. Rates and p99 are medians:

| QoS 2 shape | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 14,979 [14,893–15,080] | 18,098 [15,041–21,828] | 0.828× | 0.074 / 0.066 | 4.59 / 2.96 |
| publishers-32 | 27,382 [24,877–27,780] | 31,874 [31,371–32,317] | 0.859× | 3.891 / 3.477 | 5.67 / 3.30 |
| fanout-32 | 2,144 [2,060–2,206] | 2,251 [2,222–2,274] | 0.952× | 1.655 / 1.467 | 5.87 / 3.13 |
| balanced-32x32 | 2,234 [2,224–2,248] | 2,575 [2,544–2,596] | 0.868× | 54.674 / 44.353 | 6.55 / 3.59 |
| large-payload | 14,411 [14,042–14,623] | 14,868 [14,738–15,124] | 0.969× | 3.939 / 4.598 | 5.55 / 3.41 |

This matrix still exposes a throughput and RSS deficit rather than making a
broad superiority claim, but the fanout and large-payload medians are now
within 5% and 4% of Mosquitto respectively. The same fixed binaries, source
lock, completion checks, CPU assignment, queue bounds, and retained artifacts
continue to make that gap directly measurable.

## Current QoS 2 broker matrix

A fresh 2026-11-01 QoS 2 capture on the current broker and driver now measures
netz at parity or above Mosquitto in four of five shapes: serial 27,398 vs
29,880 (0.917×), publishers-32 38,309 vs 38,341 (0.999×), fanout-32 3,100 vs
2,789 (1.112×), balanced-32x32 3,212 vs 2,989 (1.075×), and large-payload
18,039 vs 17,390 (1.037×). Latency is equal in serial and better in fanout,
balanced and large-payload; publishers-32 remains slightly worse at 3.069 ms
versus 2.855 ms p99. Broker RSS is still higher in every shape, at 1.29–1.70×
Mosquitto, so memory is the clearest remaining QoS 2 gap. This capture
supersedes the earlier QoS 2 tables for current-code throughput and latency
while leaving those historical captures separately scoped. Full per-sample
records, build logs, environment hashes and the strict checker output are in
`docs/evidence/mqtt_broker_matrix/2026-11-01-qos2.json`.

A 100,000-message serial QoS 2 perf capture (2,048 cycles:Pu samples, zero
lost) explains the remaining 0.917× as distributed runtime cost rather than a
single protocol hotspot: zio clock/executor/scheduler work is about a quarter
of sampled cycles (`__kernel_clock_gettime` 11.67%, `Executor.run` 3.84%,
`AnyTask.yield` 3.31%, `processCleanup` 2.97%, `Loop.addInternal` 2.57%,
`Loop.poll` 1.77%), while the largest protocol costs are delivery flush
(4.63%), `handlePubRel` (3.41%), route matching (3.18%) and packet receive/parse
(2.98%). Full flat and call-graph reports are in
`docs/evidence/mqtt_broker_profile/2026-11-01.json`.

The runner and both strict checkers now accept
`MQTT_SESSION_EXPIRY_SECONDS=0..4294967295` and bind its canonical value into
the driver result, run-order, environment, shape, allocator, and completion
records. A nonzero value keeps each MQTT 5 publisher and subscriber Session
durable while the connection remains online; this matrix measures the cost of
durable Session ownership during live traffic, not disconnected queue replay.
The 3,600-second QoS 2 capture at
`zig-out/mqtt-broker-durable-qos2-matrix-final` (23,132,475 bytes; summary
SHA-256 `efc6de9d35fd92e85813a9883e547c8a9abdf89a0387abe2d256f2c28ea7d861`;
aggregate file-hash digest
`db57b9318f1a424ad29044fe0707bec3d782a9e68aed6fab7704837740fd2f66`)
completed all 40 ABBA broker runs with exact delivery counts and checksums.
Rates and p99 are medians:

| durable QoS 2 shape | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 12,650 [12,312–12,724] | 20,311 [18,719–21,220] | 0.623× | 0.081 / 0.057 | 4.56 / 2.96 |
| publishers-32 | 23,403 [23,301–23,456] | 32,431 [32,298–32,726] | 0.722× | 5.120 / 3.440 | 5.49 / 3.28 |
| fanout-32 | 1,521 [1,517–1,532] | 2,265 [2,249–2,279] | 0.672× | 2.625 / 1.466 | 5.63 / 3.13 |
| balanced-32x32 | 1,515 [1,462–1,528] | 2,548 [2,512–2,580] | 0.595× | 83.261 / 44.896 | 6.42 / 3.60 |
| large-payload | 10,656 [10,490–10,668] | 14,341 [14,249–15,076] | 0.743× | 5.667 / 4.963 | 5.52 / 3.42 |

As with the transient QoS 2 capture, this durable result exposes a throughput,
tail-latency, and RSS deficit in all five shapes. Separate QoS 1 and QoS 2
two-publisher/two-subscriber smoke runs also completed 400 deliveries per
broker with checksum 23,320, covering both acknowledgement flows before the
full durable QoS 2 capture.

Broker-owned allocations now have a separate diagnostic matrix rather than
being inferred from the common client's counters. Run it with:

```sh
zig build bench-mqtt-broker-allocator-matrix -Doptimize=ReleaseFast
MQTT_QOS=2 zig build bench-mqtt-broker-allocator-matrix -Doptimize=ReleaseFast
```

The broker's explicit allocator is wrapped only when its opt-in
`--allocator-stats` flag is present. The ordinary production and performance
matrix paths continue to use `c_allocator`; every allocator record is marked
`timing_usable=false` because thread-safe counting changes the hot path. The
five-shape runner pins client and server separately, gives both processes a
60-second bound, retains the exact broker, driver, runner and checker, binds each with
SHA-256, and repeats every shape four times. Both endpoints use
`TCP_NODELAY=true`. Its checker validates the workload result, exact artifact
tree,
identity hashes, allocation-size bucket sum, allocated/freed-byte equality and
zero live bytes after complete broker teardown, then independently regenerates
the summary.

The QoS 2 allocator capture at
`zig-out/mqtt-broker-qos2-allocator-final` (22,360,709 bytes; summary SHA-256
`358aee6e4b00098c566e5119f96e4bed9e72cb9d664aa733a3c153c64334a541`)
completed all fifteen runs with zero live bytes. It records the additional
four-stage transaction ownership directly: balanced-32x32 used 11,197 broker
allocations (0.109 per delivery), while serial and large-payload used 2,606
and a median of 8,837 respectively. These are allocation diagnostics only; the
thread-safe counting allocator marks timing as unusable.

Inbound QoS 2 `Pending` transactions now place the Topic Name, payload, source
Client ID, and optional username in one allocation while retaining separate
deep ownership for nested MQTT properties. Completed or disconnected
transactions return that allocation to an intrusive power-of-two size-class
cache owned by the Store. The cache has no per-block metadata allocation and is
hard-bounded by both the configured pending-transaction limit and 1 MiB;
blocks above 64 KiB are freed immediately. The slices preserve their existing
API and snapshot representation. Tests prove the one-allocation layout,
bounded reuse, and exhaustive failure cleanup with nested User Properties.

The corrected three-sample matrix at `zig-out/mqtt-qos2-cache-final`
(22,363,733 bytes; summary SHA-256
`0c3d9a510fb882059fcf8fa132bb1f7645f61936145a2e7d8e6c28079f24b11a`)
completed all fifteen runs with zero live bytes. Relative to the pre-change
QoS 2 baseline, allocation counts fell 48.5-64.2% across all five shapes:
serial 2,606 to 1,327, publishers-32 13,356 to 4,780, fanout-32 7,491 to
2,887, balanced-32x32 11,197 to 4,413, and large-payload 8,837 to a 4,550
median. Balanced allocation density fell from 0.109 to 0.043 per delivery;
cumulative requested bytes fell 2.8%, while the 1-MiB cache bound makes the
retention tradeoff explicit.

The matching 3,600-second durable-Session allocator capture at
`zig-out/mqtt-broker-durable-qos2-allocator-final` (22,370,470 bytes; summary
SHA-256 `8621642a739ba033a6c0fde6ed6acb549fe1769d6a03ffa6b7b28c77defaa2ad`;
aggregate file-hash digest
`f7da261081d729ebc3546ce130ce2e2e354aafcbd8c84bb8b4d8a41bf864d571`)
completed all fifteen runs with `live_bytes=0`. Median allocation counts were
2,609 serial (5.096/publish), 13,487 publishers-32 (3.293/publish), 221,831
fanout-32 (3.385/delivery), 332,797 balanced-32x32 (3.250/delivery), and
28,495 large-payload (3.478/delivery). These figures include durable Session
ownership, startup, warmup, measured traffic, and complete teardown; timing is
intentionally unusable under the counting allocator.

Durable Session delivery now materializes its detached canonical transmission
into connection-slot scratch rather than allocating and freeing temporary
storage for every message. The writer mutex gives that storage one owner,
while detachment still completes under the broker state lock, persistence
still completes before socket I/O, and no Session-owned slice escapes the
unlock boundary. Disconnect releases the scratch, and any byte or property
storage above 64 KiB is released immediately after its write so a single
exceptional message cannot leave large storage pinned to every live slot. A
fail-first unit test proves a warmed ordinary PUBLISH detaches without another
allocation, and a separate boundary test proves both small-buffer retention
and oversized release.

The final three-sample durable allocator matrix at
`zig-out/mqtt-session-write-scratch-allocator-final` (22,368,160 bytes;
summary SHA-256
`ccdd62a64941d0ccead1865d88dfa3866d1f8a17cd950dc0fbfee1755792da35`;
aggregate file-hash digest
`84f771ce7fc799dd40e4a35c19fb5662a9d4e41dc6cefb35b21362dd2c557c5d`)
completed all fifteen runs with `live_bytes=0`. Against the immediately
preceding durable capture, median allocation counts fell 49.0%, 64.5%, 66.5%,
66.5%, and 61.1% in shape order. Serial moved from 2,609 to 1,330 allocations
(5.096 to 2.598/publish), publishers-32 from 13,487 to 4,783 (3.293 to
1.168/publish), fanout-32 from 221,831 to 74,407 (3.385 to 1.135/delivery),
balanced-32x32 from 332,797 to 111,645 (3.250 to 1.090/delivery), and
large-payload from 28,495 to 11,089 (3.478 to 1.354/delivery).

A five-pair alternating-order, fixed-binary durable balanced-32x32 A/B at
`zig-out/mqtt-session-write-scratch-ab` (36,716,215 bytes; aggregate file-hash
digest `2da53d9d1aa6181282d33a476227a6b2cc783ba7425ae8bd9812f316aebafc56`)
used baseline broker `99bacf17`, candidate `679d0e41`, and fixed driver
`d92ecf95`, with 1,000 warmups and 10,000 measured QoS 2 publishes per arm.
Every arm completed 320,000 deliveries with checksum 18,656,000. Paired
medians were +0.3% throughput, -0.5% p50, and -0.2% p99; all ranges overlap,
so timing is neutral and the exact allocator reduction is the supported result.

Completed outgoing Session messages now return their coallocated Topic Name
and payload block to a Store-owned power-of-two cache. The cache implementation
is shared with inbound QoS 2 storage rather than duplicating allocator policy,
while each Store keeps independent ownership. Session reuse retains no more
blocks than the configured Session limit and no more than 1 MiB total; blocks
above 64 KiB are freed immediately. The byte limits and `owned_wire_bytes`
gauges continue to charge exact live Topic Name, payload, and property bytes
rather than size-class rounding or idle cache capacity. Tests cover block-count
and byte ceilings, oversized release, exact Session accounting, pointer reuse,
allocation-free steady-state enqueue/drain/ACK, and cache teardown.

The final three-sample matrix at
`zig-out/mqtt-session-wire-cache-allocator-final2` (22,376,564 bytes; summary
SHA-256 `a5a7a9b4c1834d20b85db9b83386d06d26e1ae14ec3b90c58ad380345d3e9de6`;
aggregate file-hash digest
`48ebad386bccce09f14a4297f5272414d7b3bf3f9933298564a8a260f0120c8a`)
completed all fifteen runs with `live_bytes=0`. Relative to the preceding
Session-write-scratch capture, allocation counts fell another 48.0%, 90.9%,
99.0%, 99.0%, and 78.2% in shape order: serial used 692 allocations
(1.352/publish), publishers-32 437 (0.107/publish), fanout-32 756
(0.012/delivery), balanced-32x32 1,106 (0.011/delivery), and large-payload
2,414 (0.295/delivery). Median peak live bytes varied from -0.1% to +2.0%; the
largest increase was 143,250 bytes in the 4-KiB shape and remains below the
explicit 1-MiB cache ceiling.

A two-shape, five-pair alternating-order fixed-binary A/B at
`zig-out/mqtt-session-wire-cache-ab-final` (36,737,527 bytes; aggregate
file-hash digest
`1218260adc6b7c82164ee0242c171141ec1dd7330e5aa4c526e96d9f6bbd77fb`)
used baseline broker `679d0e41`, candidate `a5b0dc64`, and fixed driver
`d92ecf95`, with a 3,600-second Session Expiry, 1,000 warmups, and 10,000
measured QoS 2 publishes per arm. Every balanced arm completed 320,000
deliveries with checksum 18,656,000; every 4-KiB arm completed 40,000 with
checksum 10,780,000. Paired throughput/p50/p99 medians were
-1.1%/+1.3%/+0.5% for balanced-32x32 and -0.6%/+0.0%/+0.7% for large-payload.
The ranges overlap and timing is neutral; the repeatable allocator reduction
is the supported result.

The broker's detached transmission now preserves typed metadata plus deep
copies of its visible Topic Name, payload, and every variable-length MQTT 5
property value. After the persistence barrier, the connection applies its
current Topic Alias state and performs the only wire encoding. This removes
the former state-lock encode followed by an unlocked parse and second encode;
it does not borrow Session memory outside the lock, move persistence or socket
I/O into the lock, or change the alias oversize fallback. Tests cover QoS
capping, QoS 0 completion metadata, deep-copy independence for User Properties,
allocation-free scratch reuse, and the existing real durable reconnect that
establishes then reuses a Topic Alias.

The three-sample allocator regression artifact at
`zig-out/mqtt-session-detach-allocator-final` (22,382,296 bytes; summary
SHA-256 `cc9e9ab6808582b5cbf49f01d409ae53c48f7c318a4efb429810e9adca603971`;
aggregate file-hash digest
`6a60453eb78711d6bd19c715d73f2c6e3673477490a578999d0dcaa332c13128`)
completed all fifteen runs with `live_bytes=0` and reproduced the cache-era
allocation density: fanout-32 and balanced-32x32 both remained at 0.011
allocations per delivery.

A two-shape, five-pair alternating-order fixed-binary A/B at
`zig-out/mqtt-session-detach-ab` (36,751,745 bytes; aggregate file-hash digest
`e6887b8977a282f9551f5d9e7e866987ff84847780045e6db53f71d8a0a8a58b`)
used baseline broker `a5b0dc64`, candidate `f3513c44`, and fixed driver
`6e528bd1`, again with a 3,600-second Session Expiry, 1,000 warmups, and 10,000
measured QoS 2 publishes per arm. Every balanced arm completed 320,000
deliveries with checksum 18,656,000, and every 4-KiB arm completed 40,000 with
checksum 10,780,000. The candidate won throughput in all ten pairs. Paired
throughput/p50/p99 medians improved 6.1%/5.7%/5.7% for balanced-32x32 and
4.1%/1.2%/4.1% for large-payload.

A fresh full comparison after the Session wire-cache and detached-transmission
changes is retained at
`zig-out/mqtt-broker-durable-qos2-matrix-post-optimization` (23,144,586
bytes; summary SHA-256
`80fcf8c52a8eae177aa21cebe90b237ebfcaa979ab8f8610444088361f1fdc45`;
aggregate file-hash digest
`a7ffb1515db834ae6047964b25f520141eeb6d5454be14746bfe2b45da55303c`).
All 40 broker runs completed with the required delivery count and checksum.
Rates and p99 are medians:

| current durable QoS 2 shape | netz publish/s [range] | Mosquitto publish/s [range] | netz/Mosquitto | p99 ms netz / Mosquitto | broker RSS MiB netz / Mosquitto |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 13,021 [12,687–13,100] | 22,025 [20,538–22,639] | 0.591× | 0.081 / 0.055 | 4.59 / 2.96 |
| publishers-32 | 21,631 [21,337–22,817] | 31,259 [30,767–31,484] | 0.692× | 5.587 / 3.501 | 5.50 / 3.37 |
| fanout-32 | 1,502 [1,446–1,548] | 2,270 [2,258–2,292] | 0.662× | 2.785 / 1.465 | 5.64 / 3.14 |
| balanced-32x32 | 1,547 [1,404–1,569] | 2,578 [2,559–2,610] | 0.600× | 81.520 / 44.495 | 6.46 / 3.54 |
| large-payload | 10,410 [10,236–11,107] | 14,415 [14,395–14,720] | 0.722× | 5.757 / 4.796 | 5.63 / 3.40 |

Absolute movement from the earlier full matrix is not treated as causal
because both brokers shifted with host load; the fixed-binary comparisons above
remain the optimization evidence. The new matrix still exposes a cross-shape
broker deficit. A separate `strace -f -c` diagnostic at
`zig-out/mqtt-durable-current-strace` (4,370 bytes; aggregate file-hash digest
`dbb090fb73303f8253cd463b5ab079c5ed99bb26efb18f198ec7120d77becfca`)
observed 327,160 `io_uring_enter` calls while completing 320,000 balanced
deliveries. Instrumented timing is not used as a benchmark result; the syscall
count identifies cross-connection write scheduling as the next architectural
target.

A fresh 2026-11-01 durable QoS 2 matrix on current code now measures serial
21,292 vs 29,146/s (0.731×), publishers-32 35,087 vs 36,546/s (0.960×),
fanout-32 2,967 vs 2,698/s (1.100×), balanced-32x32 2,924 vs 2,880/s (1.015×)
and large-payload 17,802 vs 17,011/s (1.046×). Four of five shapes are at
parity or above Mosquitto; serial throughput remains the clear deficit. RSS is
1.28–1.92× Mosquitto in every shape, with balanced-32x32 at 6,654 vs 3,472 KiB
because durable Sessions deep-own queued messages. This supersedes the older
durable table for current code; the historical capture remains separately
scoped. Full rows and hashes are in
`docs/evidence/mqtt_broker_matrix/2026-11-01-qos2-durable.json`.

A 100,000-message durable serial QoS 2 profile (3,072 zero-loss `cycles:Pu`
samples) explains the remaining 0.731× as distributed runtime and session-path
cost, not a single cheap hotspot: `__kernel_clock_gettime` is 12.58% self,
the zio waiter/executor/loop stack accounts for roughly half the samples,
`handlePubRel` is 22.04% children, the durable session packet drain/write path
is about 7.8% (`writePreparedSessionTransmission` 5.78%,
`writeSessionPublish` 3.90%, `drainOne...` 1.92%), and the delivery flush path
is 11.72% children. Closing the gap requires reducing per-message runtime
wakeups/clock reads or restructuring the durable session packet path. Evidence
is in `docs/evidence/mqtt_broker_profile/2026-11-01-durable-serial-qos2.json`.

The durable cross-connection target is now addressed by two serving-scope
Session delivery workers rather than one coroutine per connected Session. A
fixed ring has one entry and one compact state per broker slot, coalesces a
queued duplicate, and records at most one rerun while a slot is being drained.
The existing per-slot writer mutex still serializes every control and delivery
write; same-connection delivery and destinations at the 16-message high
watermark stay on the ordered publisher path. Worker errors are returned to
the owning client task before slot reuse, and serving teardown broadcasts to
and joins both workers. This bounds long-lived writer stacks independently of
the connection limit. The rejected per-Session prototype reached similar
throughput but raised balanced broker RSS from about 7.0 MiB to 14.9 MiB; its
64-KiB zio initial-stack override was also removed because zio deliberately
keeps 256 KiB available for panic/error paths while retaining an 8-MiB virtual
growth ceiling.

The initial shared-pool five-pair fixed-binary, CPU-0/client and CPU-1/server
A/B is retained
at `zig-out/mqtt-durable-shared2-ab-final` (63,667,135 bytes; aggregate
file-hash digest
`2146ea99f81fb0bc0377de777671c34c7ed39f2b5c8e7d59dd8afb17511570df`).
It used 1,000 warmups, 10,000 measured QoS 2 publishes, 3,600-second Sessions,
and an independently sampled CPU-2 RSS peak. Every balanced arm completed
320,000 deliveries with checksum 18,656,000; every 4-KiB arm completed 40,000
with checksum 10,780,000. Paired candidate/baseline medians were:

| durable shape | publish/s baseline / candidate | paired throughput | p50 candidate / baseline | p99 candidate / baseline | RSS KiB baseline / candidate |
| --- | ---: | ---: | ---: | ---: | ---: |
| balanced-32x32 | 1,813 / 2,713 | 1.489x [1.433-1.632] | 0.640x | 0.639x | 6,976 / 8,148 |
| large-payload | 12,652 / 15,273 | 1.213x [1.207-1.223] | 0.798x | 0.823x | 5,632 / 5,652 |

All ten throughput pairs won. The fixed baseline/candidate/driver SHA-256
values are
`fbd216b8cf4f0240ced742f85d805372c795102c90578bec20c8e2c53bf3ff94`,
`30b6a86286dbdc8ff82c97701812e0ac029557ac6f62a218e416f36ecfe84b69`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
A same-shape `strace -f -c` diagnostic at
`zig-out/mqtt-durable-shared2-strace-final` (36,304,303 bytes; aggregate
file-hash digest
`247adcc68230d909505dc38d6da4198a38373da61b1550c900cddbb4d5eb994b`)
reduced `io_uring_enter` from 114,102 to 63,454 for 102,400 measured
deliveries (-44.4%). Its timing remains diagnostic-only; the paired run above
is the performance evidence.

The final pool is lazy: entering a serving scope only publishes its fixed
queue and callback context. It allocates no stack and starts no writer until a
multi-target online durable route first selects asynchronous delivery. A
single destination, QoS 0 traffic, and brokers serving only transient Sessions
therefore retain the original task count. The lifecycle regression separately
proves an unused scope stops without spawning and two started idle waiters are
broadcast and joined.

The matching three-shape, five-pair final-binary run is retained at
`zig-out/mqtt-durable-lazy-shared2-ab-final` (63,688,110 bytes; aggregate
file-hash digest
`21cd20890dda288025a91dcc98366c6ac7126c4b20acd994115c9b58dc86a248`).
Its serial shape proves the negative case: median throughput was 19,040 versus
18,878 publish/s (paired ratio 0.997x), p50 was 43.258 versus 43.481 us, and
RSS was 4,860 versus 4,824 KiB, so an unused pool has no measurable resident
stack cost. Balanced-32x32 retained a 1.489x paired throughput median, 0.638x
p50 and 0.640x p99; RSS was 6,928 versus 8,716 KiB. The 4-KiB shape retained
a 1.213x throughput median, 0.819x p50 and 0.818x p99, with RSS at 5,636 versus
5,664 KiB. Every one of the fifteen baseline/candidate pairs completed its
exact delivery count and checksum. The final candidate SHA-256 is
`333148f1b4437441eb3db0727ca4f98ad7733c67808d17bcc90d2ddfaa6d52b4`.
Three matching 102,400-delivery diagnostics at
`zig-out/mqtt-durable-lazy-shared2-strace-final` recorded 63,733-81,254
`io_uring_enter` calls (73,296 median), 35.8% below the 114,102-call baseline.
The artifact is 36,352,861 bytes with aggregate digest
`1def46da118b0fa29aad00efdeff9842a4ace1fabccd46e980cf0463df5616fa`.

The serial QoS 2 profile then exposed validation rather than allocation as the
largest avoidable CPU cost. Netz now validates a network Topic Name's MQTT
UTF-8 profile once while reading its length-prefixed wire string, then checks
only the Topic Name-specific wildcard rule. Topic Alias application no longer
repeats the validation already completed transactionally before inflight state
is committed. Broker routing uses explicitly named validated Router and
Session paths after network parsing, local-publish, Will, or snapshot ingress;
the public Router, retained-store, Session-store, and QoS2-store APIs retain
their defensive validation. Non-retained publications also skip the retained
store entirely, and the broker's QoS 2 pending path reuses the CONNECT-validated
Client ID and username instead of decoding them for every message. This matches
the audited Mosquitto `5cd25465` structure: `packet__read_string` validates
UTF-8 at packet ingress and `handle_publish.c` performs the remaining Topic
Name check before database/routing work.

A seven-pair fixed-binary serial A/B is retained at
`zig-out/mqtt-validated-ingress-ab-final2` (63,726,852 bytes; aggregate digest
`e968026569990076d0120e697f7df2cf3f11be7d34aa0eacada6acca8455858c`).
With one publisher, one subscriber, 1,000 warmups, 10,000 measured 256-byte
QoS 2 publishes and 3,600-second Sessions, candidate/baseline paired medians
were 1.033x throughput and 0.969x p50. The candidate won throughput in six of
seven pairs; p99 was noisy and inconclusive, while RSS stayed neutral at
0.996x.
Every arm completed 10,000 deliveries with checksum 2,695,000. The fixed
baseline/candidate hashes are
`333148f1b4437441eb3db0727ca4f98ad7733c67808d17bcc90d2ddfaa6d52b4`
and `beb97b847532fe3bd004b8c35cdc210d9c1a2b10caaef0414929c31dc5a5a0cc`.
Matched 100,000-message `perf` captures reduced the combined sampled share of
the MQTT UTF-8 validator and decoder from 19.3% to 7.4%, with zero lost
samples. The final p99 and remaining serial gap are therefore attributed to
clock/I/O scheduling rather than hidden validation work.

The follow-up fixed-binary syscall capture at
`zig-out/mqtt-serial-syscalls` confirmed that syscall volume was not the
serial deficit. Across 1,000 warmups plus 10,000 measured durable QoS 2
publishes, the netz broker made 78,453 syscalls (78,357
`io_uring_enter`) while Mosquitto made 198,989: 44,003 `sendto`, 44,013
`read`, 88,012 `epoll_ctl`, and 22,813 `epoll_pwait`. The traced timings are
diagnostic only. A zio prototype that completed writable socket sends inline
was rejected after fixed-binary cross-protocol pairs regressed HTTP/1,
WebSocket, MQTT-over-WebSocket, MQTT-over-TLS, and HTTP/2 throughput to
0.866x, 0.954x, 0.928x, 0.893x, and 0.871x. Its evidence remains at
`zig-out/zio-direct-send-cross` (113,709,948 bytes; aggregate digest
`eed8e3556d1438b3d9a6e8330da80c01d6f7765fb494ac6243d5ec58d13b4d69`).

The retained change instead exposes zio's already refreshed per-loop awake
timestamp through `cachedAwakeNow`, with exact-clock fallback outside the
matching runtime, while leaving `std.Io.Clock.now` untouched. MQTT uses that
snapshot only for same-event-loop-turn keep-alive, inbound QoS 2, routing,
Message Expiry, and Session-drain bookkeeping. A matching
5,000-warmup/100,000-message CPU profile at
`zig-out/mqtt-cached-awake-profile-final` (37,234,702 bytes; aggregate digest
`7a8788136caf27fc13314a613ffd01b392e8131dca2fdcc7e87aec67daaf140e`)
reduced `__kernel_clock_gettime` from 24.5% of samples, including 13.2% below
protocol `std.Io` calls, to 12.7% entirely below the event-loop refresh; both
profiles lost zero samples.

The final remote-zio fixed-binary five-pair matrix is retained at
`zig-out/mqtt-cached-awake-final-ab` (63,798,176 bytes; aggregate digest
`9f6c0000a2a9b70fa8eae9d332251da30a78647f1a987bccbd99ae8cf5f430ee`).
It used CPUs 0/1/2, 1,000 warmups, 10,000 measured durable QoS 2 publishes,
and exact delivery/checksum validation. Baseline/candidate/driver SHA-256
values are
`beb97b847532fe3bd004b8c35cdc210d9c1a2b10caaef0414929c31dc5a5a0cc`,
`b5008a3cbddc9200a414e084b44860a19baf5e1cb718d2fc3ad9348e2e4bec28`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Paired throughput/p50/p99 medians were 1.018x/0.989x/0.946x for serial,
1.021x/0.959x/1.136x for publishers-32, 1.078x/0.899x/0.843x for fanout-32,
1.038x/0.946x/0.950x for balanced-32x32, and 1.025x/0.986x/0.947x for the
4-KiB shape. Publisher-heavy p99 was noisy and inconclusive; throughput won
four or five pairs in every shape and all five fanout pairs. A separate
100,000-message serial control at `zig-out/mqtt-cached-awake-ab-long` was
throughput-neutral at 1.003x, so the result does not claim a durable serial
throughput improvement. Seven-pair transport controls at
`zig-out/mqtt-cached-awake-transports-ab` were also neutral: 1.009x for
MQTT-over-WebSocket and 1.003x for MQTT-over-TLS.

A later extension applies the same per-loop snapshot to the outbound Session
publish, bridge QoS 2 staging/release, and Session release paths. In the same
5,000-message serial QoS 2 comparison (`zig build compare-mqtt-mosquitto`,
window 1), the immediate A/B baseline measured 9.3-11.4k publishes/s with
p50 73-95 us, while the cached-clock version measured 16.0-17.1k with
p50 44-45 us; Mosquitto under the same load band measured 17.7-29.2k. The
paired netz/Mosquitto ratio moved from roughly 0.48-0.52 to 0.60-0.63. This
remains a host-load-sensitive comparison and does not close the serial/RSS
gap; the durable serial deficit is still dominated by task wakeups and
parking. Evidence is in
`docs/evidence/mqtt_cached_clock/2026-11-05.json`.

The remaining UTF-8 profile was not a license to weaken MQTT validation.
`validateMqttUtf8StringWithPolicy` now validates the common all-ASCII case in
one pass and returns without constructing a UTF-8 view or decoding each byte
as a code point. It still rejects NUL, applies the stricter C0/DEL policy when
requested, and hands the suffix beginning at the first non-ASCII byte to the
complete UTF-8/noncharacter validator. Tests cover all-ASCII acceptance,
embedded NUL after a multibyte character, strict ASCII controls, mixed UTF-8,
surrogates, overlong encodings, and every Unicode noncharacter boundary.

The final five-pair fixed-binary matrix at
`zig-out/mqtt-ascii-validation-final2` (63,807,571 bytes; aggregate digest
`24df711c34b2923e11251e9c0e9afd627dfff95345ac213c2c7d4ab39ffa4bf1`)
pinned client/server/RSS sampling to CPUs 5/7/13 and used the cached-time
build as its baseline. Baseline/candidate/driver hashes were
`b5008a3cbddc9200a414e084b44860a19baf5e1cb718d2fc3ad9348e2e4bec28`,
`9a0ae6df6a55ebc8f671c657860c7f36e9c6dfcc2c0a59dff94e24b70d601f57`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Paired throughput/p50 medians were 1.012x/0.993x for serial,
1.003x/0.967x for publishers-32, 1.005x/1.002x for fanout-32,
1.011x/0.979x for balanced-32x32, and 1.013x/1.013x for the 4-KiB shape.
All throughput medians were positive but small; each of the first four shapes
won three of five pairs and the 4-KiB shape won all five, so this is supporting
CPU/path-length evidence rather than a broad throughput claim. RSS was neutral.
In the matching
5,000-warmup/100,000-message profile at
`zig-out/mqtt-ascii-validation-profile-final2` (37,242,840 bytes; aggregate
digest
`bb24319466455d41c78edde198cec09f228fc277e794f78036014b6ad4879d1f`),
the former 4.95% validator and 3.70% UTF-8 decoder entries disappeared from
the top sampled symbols with zero lost samples.

Two bounded parallel-flush prototypes were removed rather than committed.
Lazy group scheduling was neutral for balanced and regressed fanout; forced
concurrency improved balanced throughput about 4% but regressed fanout
throughput and p50. Smaller default-path experiments that skipped unused
delivery-ACL or repeated Session validation work were likewise inconsistent
across fanout and balanced. The then-adopted transient design instead starts
one persistent writer only after a transient client processes its first QoS 1
or QoS 2 subscription.
The publisher retains routing, persistence, and PUBREC/PUBCOMP ordering;
self-delivery remains synchronous so its PUBLISH precedes PUBACK/PUBCOMP on the
shared connection. It signals other destination writers rather than waiting on
unrelated subscriber sockets. Every connection still has one serialized writer;
PINGRESP first drains older delivery work, writer failure shuts down and wakes
the owning reader, and teardown joins the writer before the slot can be reused.
At that stage durable Sessions remained on the original synchronous path
because their detach operations serialize on shared Session/persistence state;
the fixed shared pool above now supplies bounded cross-connection concurrency.
A 16-delivery internal high watermark returns a lagging destination to
synchronous backpressure before the configured hard queue/drop limit. QoS 0
retains the original synchronous route and creates no per-connection writer.

Seven CPU-0/1 fixed-binary, order-alternated transient QoS 2 balanced-32x32
pairs used 1,000 warmups and 10,000 measured 64-byte publishes at window 4.
Every arm completed 320,000 deliveries with checksum 18,656,000. Median
throughput moved from 1,591 to 2,240 publishes/s; the paired throughput median
was 1.417x with 7/7 wins. Paired p50 and p99 medians were 0.653x and 0.682x.
The exact final-binary QoS 1 matrix above was the synchronous-path control for
this QoS 2 change. Three shorter RSS pairs measured 6,544 KiB baseline versus
6,708 KiB candidate medians for transient QoS 2.
Three durable QoS 2 control pairs, which also start no writer, measured 6,624
versus 6,620 KiB and overlapping timing. The baseline broker, candidate broker,
fixed driver, and complete paired log have SHA-256 values
`cadec82a5d73be2c98beb865f5ae9d0a7c724d66d51d04cfd6b00e34f1bfcbaa`,
`cc2c445614e2c49687c0a32281f3bb765795f3999f640014531d51539941bcad`,
`dda118b3c68c0c24f4a77ad9e3c5b939f6df17c6904de7bb131c971e07aafc36`,
and `326fec275da8588cfc4a03ce41b67bdad1344e5ba2f5bd1b17b8adb77d47d839`
respectively.

The same bounded writer now covers multi-destination transient QoS 1 delivery.
Publisher PUBACK no longer waits for unrelated subscriber socket writes;
self-delivery remains synchronous, and the 16-delivery watermark still
converts a lagging target to caller-owned backpressure. Source QoS 0 remains
synchronous unless the broker is configured to upgrade its outgoing QoS.
Writer creation follows the effective local Maximum QoS, so a QoS-0-only
connection allocates no writer.

An immediate pre-change matrix is retained at
`zig-out/mqtt-broker-matrix/run.20261002T094138Z.1428572` (23,252,125 bytes;
summary SHA-256
`85ee91fe87aec1b52b30375ae70b35bec52410256836e97fb4b7dc121b91ad95`).
Two consecutive final-binary captures are retained at
`zig-out/mqtt-broker-matrix/run.20261002T120130Z.1729461` (23,251,737 bytes;
summary SHA-256
`2e9586944c14fe6d7813e6aeb7c789c1c500d97c8a44fb0c1bde0dda6aeb4b16`)
and `zig-out/mqtt-broker-matrix/run.20261002T120212Z.1739418` (23,251,726
bytes; summary SHA-256
`54d69bc147b50d53e1eddb1fce5c80fde25513596308b54c33e365ed426abe1f`).
All 120 broker runs completed their exact delivery counts and checksums. The
two final-binary netz medians versus the immediate baseline were 29,452–29,635
versus 27,958 publish/s for serial, 50,482–50,784 versus 50,190 for
publishers-32, 4,214–4,219 versus 2,863 for fanout-32, 3,945–4,065 versus
4,131 for balanced-32x32, and 24,793–25,206 versus 20,159 for large-payload.
Thus fanout-32 improved 47.2–47.4% and large-payload improved 23.0–25.0%;
serial and publishers-32 improved 5.3–6.0% and 0.6–1.2%, while noisy balanced
32×32 regressed 1.6–4.5%.
Normalizing each ABBA capture to its co-run audited Mosquitto binary produced
0.953–0.956× for fanout-32 versus 0.651× before, and 1.001–1.030× for
large-payload versus 0.818× before. Fanout p99 fell from 1.346 ms to
0.824–0.835 ms. The expected writer cost was about 112 KiB of median broker
RSS in fanout-32; the 4-KiB shape added 62–94 KiB. These are bounded
multi-subscriber and large-payload gains, not a universal MQTT superiority
claim; serial and publisher-heavy scheduling remain visible targets.

A five-pair fixed-binary balanced-32x32 A/B at
`zig-out/mqtt-qos2-cache-ab` (36,706,710 bytes; aggregate file-hash digest
`bd7b0a350ed4e607a87120f007689ec428c9060a387f1ee83f9ef958fe0e33cc`)
moved raw median throughput from 1,551 to 1,559 publishes/s; paired medians
were -0.4% throughput, -0.5% p50, and -0.1% p99. A separate 50,000-publish,
32-publisher/one-subscriber five-pair run at
`zig-out/mqtt-qos2-cache-publishers-ab/run.20260930` (15,461 bytes;
aggregate file-hash digest
`8ebee9d1afb5b395be318d0a57df5d4db9f508bf4738b9fb4ec0057ca4513d5c`)
had paired medians of -0.2% throughput, +0.2% p50, and +0.4% p99. Both timing
sets are neutral with overlapping ranges; the exact allocator reduction is the
supported result.

The first complete capture is
`zig-out/mqtt-broker-allocator-matrix/run.20260930T-final3` (22,253,198
bytes); summary SHA-256 is
`6d5696584282e90ebf0c6554134b77f75aab17a466149a3f5c0b1d910a15cfe9`.
All 20 runs returned `live_bytes=0`. Counts include broker startup, warmup,
measured traffic and teardown, so the per-message values below are diagnostic
normalizations rather than steady-state timing claims.

| shape | median allocs | allocs/publish | allocs/delivery | median allocated bytes | ≤64 B / 65–256 B allocs |
| --- | ---: | ---: | ---: | ---: | ---: |
| serial | 5,235 | 10.225 | 10.225 | 6,643,666 | 1,941 / 2,005 |
| publishers-32 | 39,460 | 9.634 | 9.634 | 9,624,238 | 13,200 / 26,213 |
| fanout-32 | 159,619 | 77.939 | 2.436 | 24,358,273 | 76,393 / 80,844 |
| balanced-32x32 | 421,950 | 131.859 | 4.121 | 60,112,229 | 114,533 / 303,850 |
| large-payload | 28,423 | 13.878 | 3.470 | 26,237,225 | 10,946 / 13,104 |

The dominant balanced cost is therefore not its one route-array allocation per
PUBLISH: 418,383 of the median 421,950 allocations are at most 256 bytes.
Future broker work should first isolate and amortize per-delivery property,
packet and queue ownership in those two buckets, then use the unchanged
performance matrix to prove that lower allocation pressure also improves
throughput and tail latency.

The per-connection reduction comes from keeping the WebSocket-specific
transport state out of line. `PacketTransport` previously embedded the full
WebSocket connection as its largest union member, so every plain TCP MQTT
connection occupied that size even though it never used HTTP, TLS, WebSocket,
or compression state. WebSocket/WSS construction now owns one fallible boxed
transport object, including cleanup on allocation failure, while TCP and the
pointer-backed TLS variants stay inline. A six-pair fixed-binary ABBA check of
the balanced 32×32 shape (`bd36916d` baseline, `546e101b` candidate, fixed
`00aaf0a8` driver) measured 10,920–10,956 versus 10,232–10,256 KiB netz RSS;
the paired median ratio was 0.935 (-6.5%). The paired throughput ratio was
0.993, so this is retained as a memory-layout win rather than a throughput
claim. The complete A/B artifact is
`zig-out/mqtt-transport-box-ab/run.20260929`. Compared with its immediately
preceding full matrix, the first post-boxing capture lowered netz median RSS
in all five shapes: 3.0%, 7.5%, 8.9%, 6.5%, and 1.7% in table order.

TCP packet parsing first combined the mandatory Control Packet byte and first
Remaining Length byte in one read. A fixed-binary six-pair ABBA isolated that
step at +5.9% median serial throughput. The parser now goes further with a
512-byte connection-local read-ahead buffer: common small packets need one
transport read, bytes from a coalesced following packet remain buffered, and
large packets continue directly into their exact owned allocation. Tests cover
split-header timeout/resume, two coalesced packets, the large-packet transition,
and retry after allocation failure without consuming buffered bytes.

For the final read-ahead binary, two traced runs of 4,096 measured plus 128
warmup QoS 1 publishes reduced `io_uring_enter` from 33,811/33,810 to
12,862/13,000 calls (-61.8% by medians). A separate six-pair fixed-binary ABBA
with old driver `a1110499`, baseline broker `38e4fa6c`, and candidate broker
`0f5eaa7a` measured 18,659–19,347 versus 29,092–29,960 publishes/s. All six
pairs improved; the paired throughput-ratio median was 1.557, p50 ratio 0.650,
p99 ratio 0.655, and RSS ratio 1.005 (3,480 versus 3,496 KiB medians). The
bounded artifacts are `zig-out/mqtt-readahead-final-strace/run.20260930` and
`zig-out/mqtt-readahead-final-ab/run.20260930`. The final full matrix completed
all 40 broker runs, but its common client also contains read-ahead, so the
table is a fair current same-client comparison rather than server-only causal
evidence.

The Session-route aggregation plan now accepts caller-owned storage for up to
32 raw Session matches. This removes its route-array, identifier-array, and
hash-index allocations from the common fanout path while retaining the prior
indexed heap fallback above that threshold. A failing-allocator test exercises
all 32 scratch entries with overlapping identifiers and validates the merged
QoS/retain result; a 33-route test covers the fallback. A six-pair fixed-binary
ABBA with driver `0d3875ff`, baseline broker `0f5eaa7a`, and candidate broker
`31a38344` found serial throughput neutral (paired median ratio 1.001) and
fanout-32 throughput 1.027, with median p50 and p99 ratios 0.950 and 0.970.
RSS was effectively unchanged. The artifact is
`zig-out/mqtt-session-plan-ab/run.20260930`; the full matrix completed all 40
runs, while the fixed-binary result remains the causal evidence.

Outgoing live fanout and durable Session replay use eight caller-stack property
slots while holding that connection's writer mutex. Property descriptors
continue to borrow their immutable Publication or Session values only through
the synchronous encode/write call. Larger sets use one exact connection-owned
overflow slice whose capacity is retained, preserving allocation-free warmed
delivery without carrying a full `ArrayList` in every connection. A fail-first
second Session write proves that a warmed property-bearing Topic Alias replay
needs no new allocation. The earlier three-sample five-shape allocator matrix at
`zig-out/mqtt-property-scratch-final2` (22,231,273 bytes; summary SHA-256
`737976e8f6a1a6358bb2cda094c3c9e60741ff9dcee2ce7e7a982520390382a8`)
completed all fifteen broker runs with `live_bytes=0`. Against the preceding
four-sample matrix above, allocation counts fell 25.7%, 33.1%, 46.2%, 69.5%,
and 30.6% in table order. The balanced shape dropped from 421,950 to 128,765
allocations and from 60,112,229 to 17,893,589 cumulative requested bytes;
peak live bytes remained effectively unchanged. Because the counting
allocator changes the hot path and labels timing unusable, these results are
allocation evidence rather than a throughput claim.

The broker's single-reader TCP event loop first used a 16-byte caller buffer
to remove the per-PUBACK/PUBREC/PUBREL/PUBCOMP/PINGREQ/short-DISCONNECT owned
packet allocation. It now uses a bounded 128-byte buffer, covering common
small PUBLISH packets without inflating every task stack to the transport's
full 512-byte read-ahead capacity. Once the packet length is known, eligible
fragmented bytes remain in connection-owned read-ahead across timeout and are
copied to caller storage only when complete; this avoids retaining a pointer
into temporary caller memory. Larger packets fall back to the existing exact
owned allocation, while TLS/WS/WSS retain their existing owned paths. Focused
fail-first tests cover a borrowed PUBACK, destruction without freeing caller
memory, undersized-buffer fallback without consuming read-ahead, and a
split three-byte prefix followed by timeout/resume without allocation.

The final three-sample matrix at `zig-out/mqtt-borrow-128-final` (22,239,361
bytes; summary SHA-256
`d984b37b5ccb209b04be818272c2ebea9d09e95e9dd9cd26022147da8e923c54`)
completed all fifteen broker runs with zero live bytes. Relative to the
16-byte caller-buffer matrix, allocation counts fell another 19.8%, 19.3%,
and 19.3% for publishers-32, fanout-32, and balanced-32x32; the 256-byte serial
and 4-KiB payloads deliberately remain on the owned fallback. Balanced 32x32
fell from 18,109 to 14,621 allocations, or 0.177 to 0.143 per measured
delivery. Relative to the original 421,950-allocation baseline, the combined
property-scratch and caller-buffer work removes 96.5% of broker allocations in
that shape. A fixed-client five-pair, alternating-order comparison at
`zig-out/mqtt-read-ahead-borrow-128-ab/run.20260930` measured candidate
throughput higher in three pairs and moved the median from 3,640 to 3,813
publishes/s (4.8%); ranges overlap, so this is retained as no-regression
evidence rather than a general throughput claim. The `runLoop` native stack
frame grows only by the selected 112-byte buffer delta (0xe70 to 0xee0), and
the process-RSS samples were too noisy for a separate memory claim.

Network-originated publications now retain their match output in a bounded
publisher-slot scratch for up to 32 registered subscriptions. The plan remains
stable while the global state mutex is released for persistence and socket
writes, but is cleared before that sole reader can process its next PUBLISH;
local publications, due Wills, system metrics, stale publisher identities, and
larger subscription sets keep independent exact owned storage. Disconnect
releases the retained capacity. A fail-first test proves warmed reuse without
allocation, checks shared-subscription round-robin advancement, and verifies
that the over-bound fallback fails before moving that cursor. The three-sample
matrix at `zig-out/mqtt-route-slot-scratch-final2` (22,252,606 bytes; summary
SHA-256
`5c66fe00cdafdccdc16c3cdb38b4c6ea5437ea191bd2cd022d51d9139e1a6855`)
completed all fifteen broker runs with zero live bytes. Relative to the prior
128-byte receive-scratch matrix, allocation counts fell 19.7%, 24.4%, 23.5%,
23.4%, and 19.8% in table order. Balanced 32x32 moved from 14,621 to 11,197
allocations (0.109 per measured delivery) and cumulative requested bytes fell
from 17,142,677 to 11,885,461; peak live bytes changed by only about 2 KiB. A
fixed-client, five-pair alternating-order A/B at
`zig-out/mqtt-route-slot-scratch-ab/run.20260930-final` (37,186,446 bytes;
aggregate file-hash digest
`cd34aa824adadd7e3a2dbd8cd142a31e9a3652c0bb1a83d6e9f13c5a8e53eedb`)
moved median throughput from 3,589 to 3,885 publishes/s (8.2%, four of five
paired wins) and median p99 from 33.20 to 29.59 ms (10.9%, four of five wins).
The ranges overlap, so this remains workload-specific supporting evidence
rather than a general throughput claim.

The default empty listener namespace now maps an inbound Topic Name through an
explicit `MappedTopic` borrowed result rather than allocating an identical
copy. Non-empty mount points still own their canonical prefix concatenation,
and the existing `mapTopicAlloc` API keeps its always-owning contract. The
borrowed packet remains alive throughout ACL checks, QoS 2 staging, retained
storage, route planning and shared-Publication construction, each of which
either consumes it synchronously or deep-copies state that escapes the call.
A fail-first namespace test verifies pointer identity and allocation-free
destruction for the empty prefix, alongside owned non-empty-prefix cleanup.
The final three-sample matrix at
`zig-out/mqtt-topic-borrow-current-final` (22,264,280 bytes; summary SHA-256
`79dcab464e9ad353f5d206f6af7a1ac6013936b5db6eb84a5724f9d542767c06`)
completed all fifteen broker runs with zero live bytes. Relative to the
route-scratch matrix, allocation counts fell another 24.6%, 32.6%, 30.8%,
30.9%, and 24.6% in table order. Balanced 32x32 moved from 11,197 to 7,741
allocations, or 0.109 to 0.076 per measured delivery; the combined sequence
has removed 98.2% of the original 421,950 broker allocations. A longer
fixed-client five-pair A/B at
`zig-out/mqtt-topic-borrow-long-ab/run.20260930` used 1,000 warmups and 10,000
measured publishes per arm. The candidate won two pairs and moved median
throughput from 3,688 to 3,617 publishes/s (-1.9%) with heavily overlapping
ranges, so no throughput conclusion is drawn from that noisy run; the exact
allocation reduction is the supported result.

Shared broker `Publication` state now coallocates its aligned reference-counted
header with the contiguous Topic Name and payload tail. Properties retain their
independent deep-owned representation because their nested UTF-8/binary values
have separate lifetimes and cleanup, but the common property-free fanout path
now needs one allocation per incoming publication instead of one for bytes and
one for metadata. Release reconstructs the exact aligned allocation only after
the final atomic reference is dropped. A fail-after-one test proves the
property-free construction boundary and physical layout, while an exhaustive
allocation-failure test covers nested User Property ownership and two-reference
release. The final three-sample matrix at
`zig-out/mqtt-publication-coalloc-final` (22,262,696 bytes; summary SHA-256
`8025616b208cb08d1c0e81a20f3f545e91192e7db5de6b0eeaf726c7a5e9e7c2`)
completed all fifteen broker runs with zero live bytes. Relative to the topic-
borrow matrix, allocation counts fell another 32.6%, 48.3%, 44.4%, 44.6%, and
32.7% in table order. Balanced 32x32 moved from 7,741 to 4,285 allocations, or
0.076 to 0.042 per measured delivery; cumulative requested bytes and peak live
bytes are unchanged because the same bytes now share one allocation. Across
the optimization sequence this removes 99.0% of the original 421,950 broker
allocations in that shape. A fixed-client five-pair long A/B at
`zig-out/mqtt-publication-coalloc-ab/run.20260930` (37,086,178 bytes;
aggregate file-hash digest
`d6ad78fdef719c835ebb286b687c5e7d48e3b0c66a53c9f6bf690b50449846a7`)
moved median throughput from 2,446 to 3,620 publishes/s with four candidate
wins, but the unusually wide and overlapping host-load ranges make this only
supporting evidence rather than a general throughput claim.

Owned TCP, TLS and WebSocket broker PUBLISH packets now reserve one
16-byte-aligned `Publication`-sized prefix on their packet allocation. TCP/TLS
stream readers preserve that prefix with partial bytes across a timeout. Once ACL,
retained-state, durable-Session and route-plan work has succeeded, an
unprefixed-topic live fanout can clone forwarding properties and compact the
Topic Name plus payload into that same allocation before transferring
ownership to the shared `Publication`. Alias-resolved topics, listener mount
points, QoS 2 staging, and route misses retain their prior ownership paths. A
timed TCP-read regression verifies that the prefixed allocation survives
partial-body timeout/resume, while the TLS live-broker fuzz covers the stream
transport path and allocation-failure coverage proves that nested User Property
cloning leaves the original packet owner intact.
The three-sample matrix at
`zig-out/mqtt-large-packet-adoption-final4` (22,278,397 bytes; summary SHA-256
`598b9f26aae6fc9f56ed9f213ef6f577ec3248aff2572c62a8faa4e406003e23`)
completed all fifteen broker runs with zero live bytes. Relative to the
preceding coallocation matrix, the 256-byte serial shape fell from 1,326 to
686 allocations (2.590 to 1.340 per publish), while the 4-KiB shape fell from
4,479 to 2,303 allocations (2.187 to 1.125 per publish, 48.6%). The 4-KiB
shape's cumulative requested bytes fell from 24,492,977 to 15,540,913
(36.5%). Publisher-32, fanout-32, and balanced-32x32 allocation counts remain
unchanged because those 64-byte packets already use caller-owned stack
storage; their peak-live values remain within a few KiB of the prior matrix.
As before, the counting allocator makes these allocation and ownership
measurements rather than timing evidence.
A three-pair alternating-order fixed-client A/B at
`zig-out/mqtt-large-packet-adoption-ab/run.20260930` (22,162,412 bytes;
aggregate file-hash digest
`48cd19d76390337ccc513dcff721d870831977eb93d88d47850213d45b271be4`)
used four publishers, four subscribers, a 4-KiB payload, window 16, 1,000
warmups and 10,000 measured publishes per arm. Every arm completed 40,000
deliveries with checksum 10,780,000. Median throughput moved from 20,022 to
19,871 publishes/s (-0.8%), median p50 from 1.149 to 1.139 ms, and median p99
from 2.312 to 2.308 ms. The ranges overlap and the candidate won one of three
throughput pairs, so this is recorded as no clear timing regression rather
than a speedup claim; the exact allocation and byte reductions above are the
supported result.

Broker PUBLISH counters now use a dedicated group of saturating atomics.
Receive, successful-send, payload-byte and drop accounting no longer acquires
the global routing/Session mutex for every network event; state-backed gauges
remain protected and coherent under that mutex, while cumulative wire and
PUBLISH counters are documented as independently sampled. Unit tests cover
ordinary values, concurrent updates, and saturation at `maxInt(usize)`. The
allocator matrix at `zig-out/mqtt-publish-counters-final` (22,284,193 bytes;
summary SHA-256
`a79638a694006f201df5d572a85ed7104a096f05633ae9ce56ba1cb0fefb1b2b`)
reproduced the prior allocation counts and cumulative requested bytes in every
shape with zero live bytes. A five-pair fixed-binary, alternating-order
balanced-32x32 A/B at
`zig-out/mqtt-publish-counters-ab/run.20260930` (36,967,124 bytes; aggregate
file-hash digest
`2e198741c690d3ed6ec419edac738e645d18a5dc6fcb921b9df2f8eee1f98330`)
used 1,000 warmups and 10,000 measured publishes per arm. Every arm completed
320,000 deliveries with checksum 18,656,000. Raw medians moved from 2,891 to
3,374 publishes/s (+16.7%), p50 from 16.335 to 13.642 ms (-16.5%), and p99
from 38.655 to 32.154 ms (-16.8%). The paired-ratio medians were +19.0%,
-15.7%, and -16.3% respectively; candidate p99 won all five pairs. Throughput
won three of five pairs and the host-load ranges overlap, so these remain
workload-specific supporting measurements rather than a general superiority
claim.

The slot writer now performs its durable-Session selection and, when that
queue is empty, its live-delivery dequeue inside one state-lock acquisition.
Durable work retains strict priority; a durable mutation is unlocked and
persisted before any socket write or subsequent live dequeue, and an encoded
Session packet is now owned by a defer before that persistence step so an I/O
failure cannot leak it. The allocator matrix at
`zig-out/mqtt-single-dequeue-lock-final` (22,279,881 bytes; summary SHA-256
`d6eeec90ac44c464f45ed4242573cf61242109f1d509dcc24d516e746a592181`)
reproduced the previous allocation counts and cumulative requested bytes in
all five shapes with zero live bytes. A five-pair fixed-binary,
alternating-order balanced-32x32 A/B at
`zig-out/mqtt-single-dequeue-lock-ab/run.20260930` (37,027,612 bytes;
aggregate file-hash digest
`0483aa60061cf94d917d5cd63830d1430a98bdb3e179ef9ded957b4ec08d946b`)
completed 320,000 deliveries per arm with checksum 18,656,000. Raw medians
moved from 3,514 to 3,582 publishes/s (+1.9%), p50 from 17.846 to 14.920 ms
(-16.4%), and p99 from 35.082 to 33.126 ms (-5.6%). Paired-ratio medians were
+0.6%, -12.3%, and -2.9% respectively. Throughput and p99 each won three of
five pairs, p50 won four, and the wide host-load ranges overlap, so these are
supporting latency/no-regression measurements rather than a general speedup
claim.

Live overlapping-subscription merge now uses the routing transaction's queue
tail instead of linearly scanning each destination's complete pending queue.
Every broker Publication is unique to one route operation, and that operation
holds `state_mutex` while it materializes all destinations, so an earlier raw
match for the same client can only be the current tail; an older equal pointer
cannot exist because queued Publications remain referenced. A local queue test
covers consumed-prefix and non-tail rejection, while a live MQTT 5 test proves
that two overlapping subscriptions still produce one PUBLISH with both
Subscription Identifiers and no duplicate delivery. The three-sample matrix at
`zig-out/mqtt-tail-merge-allocator-final` (22,280,513 bytes; summary SHA-256
`4b4e51b1eef76c76eef638fe35e12e86f2f60e876e5d1b2f3da07919a413a21c`)
reproduced all five prior allocation counts and cumulative requested-byte
totals, including 4,285 allocations (0.042 per delivery) for balanced-32x32,
and all fifteen runs ended with zero live bytes. Two independent five-pair
fixed-binary balanced-32x32 A/B sets at `zig-out/mqtt-tail-merge-ab`
(36,634,384 bytes; aggregate file-hash digest
`5bf9744678bbd9c7b4956e4f57800336d08413c94579889df3f9eabd8d5739ab`)
completed 320,000 deliveries per arm with checksum 18,656,000. Across all ten
pairs the candidate won seven throughput pairs, seven p50 pairs, and eight p99
pairs; paired-ratio medians were +2.2%, -6.3%, and -6.4% respectively. Raw
throughput medians moved from 3,555 to 3,698 publishes/s. The samples include
wide host-load outliers, so this remains workload-specific supporting evidence
for the bounded-complexity improvement rather than a general throughput claim.

The property-free live-delivery path now avoids asking the runtime for a
monotonic timestamp for every subscriber write. `Publication.remainingExpiry`
returns immediately when no Message Expiry Interval exists, so that common
path supplies a constant timestamp that cannot affect the result; publications
with expiry retain the prior just-before-encode clock sample and decrement or
discard behavior. The three-sample allocator matrix at
`zig-out/mqtt-expiry-clock-final` (22,283,277 bytes; summary SHA-256
`271453b8d69fbcbee595f7187c4e6a8c3ebba0785d0f9dfea748b4642b042489`)
completed all fifteen runs with zero live bytes. Four shapes exactly reproduced
their prior allocation counts and cumulative requested bytes. The timing-
sensitive 4-KiB stream-read shape ranged from 2,303 to 2,307 allocations with
a 2,307 median, a four-allocation/608-byte difference from the preceding
median and no ownership change in this patch. Two independent five-pair
fixed-binary balanced-32x32 A/B sets at `zig-out/mqtt-expiry-clock-ab`
(36,637,782 bytes; aggregate file-hash digest
`9e620b6a5686dc451b56b7d4ece51ec19a504f6766c1788ff1d849344267386c`)
completed 320,000 deliveries per arm with checksum 18,656,000. The candidate
won nine of ten throughput pairs, seven p50 pairs, and eight p99 pairs;
paired-ratio medians were +5.3%, -23.1%, and -13.4% respectively. Raw medians
moved from 3,913 to 4,102 publishes/s, 14.556 to 9.084 ms p50, and 29.805 to
27.268 ms p99. Latency samples remain visibly bimodal, so the result is
workload-specific evidence for removing the redundant clock query rather than
a general latency claim.

The numeric comparison below is the 2026-08-18 same-host `ReleaseFast`
window-one run from the former Threaded client harness. It remains historical
evidence and must not be cited as current zio performance:

```text
broker      publishes/s   deliveries/s   checksum
netz             46,375        185,501   20,580,000
Mosquitto        27,745        110,982   20,580,000
rumqttd          15,490         61,962   20,580,000
```

Mosquitto was built from the audited checkout in Release mode with TLS,
WebSocket, HTTP API, clients, plugins and tests disabled, then configured with
64 inflight and 1,024 queued messages. Rumqttd used its release binary and
MQTT 5 listener from `rumqttd.toml`. The workload shape and payload bytes were
identical; equal checksums prove all 80,000 measured deliveries completed.
This result is evidence for this bounded live QoS 1 fanout shape only. It does
not benchmark the QoS 2 path or claim netz exceeds Mosquitto or rumqttd in
persistence, offline sessions, Will integration, tail latency, memory use, or
broader conformance.

The broker hot path now retains each connection's encoded PUBLISH output
buffer after first use. The codec prevalidates every property, computes the
complete Remaining Length, reserves once, and writes fixed header, topic,
Packet Identifier, every MQTT 5 property type and payload directly into that
retained output. The shared property writer uses the same exact-length direct
path for CONNECT, ACK, SUBSCRIBE and the other control packets. Neither layer
allocates temporary variable-header or property buffers; failing-allocator
codec and socket tests prove warmed writes are allocation-free while parsing
verifies exact wire parity and invalid input leaves prior output unchanged.
The standalone `FixedHeader.write` entry point now prevalidates and reserves
exactly its two-to-five-byte header before writing. An invalid Remaining Length
or allocation failure therefore leaves existing output intact instead of
exposing a partial Control Packet byte, while even the maximum Remaining Length
does not reserve its unsupplied 256-MiB body. One-byte-capacity fail-first and
exact five-byte-capacity regressions lock both boundaries.
The public Remaining Length, UTF-8 string, and Binary Data writers now also
validate and reserve their complete encoded field before appending any byte.
Exact-capacity fail-first tests force the allocation boundary after the first
legacy write would have succeeded and verify that all three outputs remain
empty, while the existing round trips preserve their wire representation.
CONNECT itself now applies the same direct path across MQTT 3.1.1/5 Client ID,
Will properties/topic/payload and username/password instead of assembling and
copying a whole temporary variable payload. CONNACK and QoS PUBACK/PUBREC/
PUBREL/PUBCOMP use the same retained-capacity path while preserving MQTT 5's
shortest legal omission of reason code and Property Length. SUBSCRIBE,
SUBACK, UNSUBSCRIBE and UNSUBACK preflight complete filter/reason lists and
also write directly after one final reservation. Warmed mixed-property and
multi-filter tests run these writers under a fail-first allocator. DISCONNECT
and enhanced-authentication AUTH complete the same treatment, including their
zero-length and reason-plus-properties MQTT 5 forms.
PINGREQ and PINGRESP now expose an exact two-byte caller-buffer encoder, and
the shared TCP/TLS/WebSocket runtime sends those bytes directly instead of
constructing a fresh ArrayList for every keep-alive exchange. A real TCP test
runs PINGRESP through a fail-first connection allocator and validates the peer
bytes, while codec tests prove PINGREQ/PINGRESP wire parity. This is a stricter
allocation boundary than the audited rumqtt codecs' `BytesMut` writer path,
without changing their equivalent two-byte MQTT wire representation. The
common property-free PUBACK/PUBREC/PUBREL/PUBCOMP path likewise encodes the
complete four- or five-byte packet into caller storage and sends it directly.
It preserves MQTT 5's shortest success form, validates negative reason codes,
and leaves arbitrary diagnostic properties on the general property-capable
codec path. If Request Problem Information filtering removes every diagnostic
property, the result also returns to the fixed path. A real TCP
fail-first-allocator test covers all four packet types and both wire lengths;
unlike the audited rumqttd writers, this hot path does not depend on spare
`BytesMut` capacity. The
Mosquitto-derived 287-scenario packet gate and MQTT 3.1/3.1.1/5 WS/WSS gate remain
green. CPU-0-pinned 1-KiB QoS 1 regression runs measured 10.437 us per
PUBLISH/PUBACK over WebSocket (95,805 operations/s) and 11.541 us over native
TLS (86,640 operations/s). These check the shared packet receive/send paths
rather than isolating one control codec.
PUBLISH encoding now exposes a validated prefix-only form. Plain TCP, native
TLS, WS, and WSS submit that retained prefix together with the borrowed
application payload, so payload size no longer drives the MQTT connection's
packet scratch capacity. MQTT-over-WebSocket still preserves one MQTT packet per
binary message: its new two-part WebSocket writer emits one frame and carries a
continuous client mask across both slices through bounded stack scratch rather
than concatenating the message. V3.1.1 and MQTT 5 tests compare the prefix plus
borrowed payload byte-for-byte with the original contiguous encoder,
including QoS 1, DUP, retain, a multibyte Remaining Length, and properties. A
real TCP test sends two 1-KiB packets, disables all allocation after warmup, and
verifies the prefix scratch remains smaller than the payload while the peer
parses the complete bytes. WebSocket tests independently verify one-frame
masked client and unmasked server messages assembled from two parts. The full
Netz test suite, 287-scenario
Mosquitto-derived wire gate, and MQTT 3.1/3.1.1/5 WS/WSS gate remain green. Five
CPU-0 native-TLS samples measured 11.292-11.761 us per QoS 1 PUBLISH/PUBACK
(11.445 us mean). Five WebSocket samples measured 10.448-10.859 us with a
10.450-us median and 10.534-us mean.
Property-free DISCONNECT now follows the same design: normal shutdown uses its
canonical two bytes and an MQTT 5 error reason uses three bytes, both from
caller-owned storage. The TCP runtime test sends a non-zero Keep Alive timeout
reason through a fail-first allocator and validates the exact peer bytes. The
audited rumqtt implementations again encode into a growable `BytesMut`; the
netz path has no retained-capacity prerequisite.
Property-free MQTT 5 AUTH packets also use caller-owned storage, including the
distinct four-byte Continue/Re-authenticate form whose zero Property Length is
mandatory. Request Problem Information suppression takes this path when only
diagnostic properties remain. Exact wire tests and a real TCP fail-first
allocator test cover the two- and four-byte forms; rumqttc's audited AUTH
writer always targets a growable `BytesMut` and emits the longer form even for
Success.
Bare CONNACK has a fixed encoder as well: MQTT 3.1.1 uses four bytes and MQTT
5 adds its mandatory zero Property Length byte. The runtime selects it when no
explicit or implicit capability properties were generated, most importantly
for connection refusals that should remain reportable under allocator
pressure. A fail-first TCP test sends exact MQTT 5 and 3.1.1 refusal packets.
Accepted MQTT 5 sessions retain the general encoder whenever negotiated
capabilities need to be advertised.
All variable-size runtime control writers now share the connection's retained
packet buffer rather than allocating and freeing a temporary list per send. A
second retained property-list scratch covers generated CONNACK capabilities
and Request Problem Information filtering. A real TCP regression warms and
then replays property-bearing CONNACK, PUBACK, SUBACK, UNSUBACK, DISCONNECT,
and AUTH under a fail-first allocator, comparing every replay packet with its
warmup bytes. PUBLISH continues to use the same packet scratch, while the fixed
control encoders above bypass it entirely.
Property-free SUBACK/UNSUBACK additionally expose exact-length caller-buffer
encoders, including multi-byte Remaining Length. The runtime writes them into
the retained packet scratch and avoids property encoding entirely. Validation
happens before output mutation; tests cover short storage, MQTT 3.1.1's absent
UNSUBACK reason list, MQTT 5 reason lists, and the 128-byte Remaining Length
boundary. In contrast, the audited rumqttd SUBACK/UNSUBACK writers first
collect mapped reason bytes into another `Vec<u8>` before copying them into
`BytesMut`.
TCP and TLS packet readers now collect only the at-most-five-byte MQTT fixed
header on the stack, validate the complete packet length, then allocate the
public owned packet exactly once at its final size. This removes the former
incremental ArrayList growth and ownership-transfer work without weakening
absolute CONNECT/PING deadlines or broker Keep Alive progress renewal. A real
TCP test permits exactly one allocation and forbids resizing for a packet with
a multi-byte Remaining Length; a second sends only an oversized header and
proves rejection happens before any allocation. Rumqttd instead starts each
connection with a retained 10-KiB `BytesMut` receive buffer, favoring pooled
read-ahead at the cost of that per-connection reservation.
Plan flushing also removed quadratic prefix searches for overlapping
subscriptions: the first visit drains the slot queue and later matches are
constant-work empty checks, keeping the pass O(matches). The external workload
accepts `--overlapping-subscriptions=1..3` for exact/+/# stress shapes.

The same-client driver accepts `--publisher-window=N`: each publisher
submits up to N QoS 1 PUBLISH packets before reading the corresponding PUBACKs.
It reports publish-completion p50/p99/p99.9 plus client-side allocation calls,
cumulative allocated bytes and peak live bytes. The window mode exposed both an
inflight-hole unsigned-subtraction panic and two production hot-path problems:
plain MQTT TCP retained Nagle, and Session draining rescanned every consumed
queue tombstone for every outgoing packet. Saturating hole accounting covers
the first problem. Plain TCP now defaults TCP_NODELAY on both accepted and
connected sockets (with an explicit opt-out), while each Session retains a
queue-head cursor and resets its logical storage when the live queue empties.
Online Session Expiry zero clients now also use the live connection's inflight
table and one shared Publication instead of deep-cloning every QoS 1/2 fanout
into durable Session storage; persistent/offline Sessions retain the owned
retransmission path.

On 2026-08-20, three consecutive same-host `ReleaseFast` runs used four
publishers, four subscribers, 1,000 warmups, 20,000 measured 256-byte QoS 1
publishes, fanout four, and a publisher window of 64. Rumqttd `e886a78` ran
with one MQTT 5 listener, 1,024 router outgoing packets and 1,024 connection
inflight packets. Both brokers received the exact same newly built netz client
binary. Broker RSS was sampled from `/proc/PID/status` every 2 ms while the
driver was alive; the table reports the median of each three-run metric:

```text
broker    pub/s    deliveries/s   p50 ms   p99 ms   p99.9 ms   client allocs   client peak B   broker peak RSS KiB
netz      55,505        222,023    1.813    3.921       4.795         504,105         504,170                 6,436
rumqttd    6,902         27,609    1.335   41.100      41.800         672,121         504,436                17,632
```

Every run completed 80,000 measured deliveries with checksum 20,580,000. In
this bounded windowed shape, netz delivered 8.04x rumqttd's median throughput,
used 25.0% fewer client allocation calls and 63.5% less broker peak RSS. Netz's
median completion was 1.36x slower, but its p99 and p99.9 were respectively
10.48x and 8.72x lower. Client cumulative allocation was 120,171,264 bytes for
netz versus a median 133,108,088 bytes for rumqttd. These are equal-driver
results for this workload, not a persistence, QoS 2, crash-safety or broad
conformance verdict.

The queue cursor was selected from measurement rather than assumption. Before
the change, `perf record -F 997 -g` attributed about 50-53% of broker cycle
samples to `Broker.flushSlotLocked`; annotation placed 43% of the atom-core
samples on the null test while scanning the consumed queue prefix. After the
cursor change the same symbol accounted for 4.9% of atom-core samples. The
transient-session fast path then raised the unprofiled three-run range from
37,098-40,021 to 53,843-54,197 publishes/s. Finally, moving the large runtime
Connection into its stable broker slot before constructing the async client
task removed a redundant closure/worker-stack copy. The task now owns only the
compact CONNECT parse tree, and attach-time errors follow the normal unregister
cleanup path. Median broker peak RSS fell from 9,344 to 8,496 KiB while the
three-run range remained 54,655-55,781 publishes/s. The finite production
example then moved from the SMP allocator's per-worker caches to libc's shared
allocator. Median peak RSS fell to 6,436 KiB with a 54,847-56,486 publishes/s
range; callers of the broker library retain explicit allocator control.

The same shape was also run three times against a release build of audited
Mosquitto `5cd25465`, configured with 64 inflight and 1,024 queued messages.
Its per-metric medians were 7,025 publishes/s, 28,100 deliveries/s, 4.922 ms
p50, 44.307 ms p99, 46.752 ms p99.9, 672,109 client allocations, 504,223
client peak bytes, and 3,868 KiB broker peak RSS. Netz therefore delivered
7.90x its throughput with 2.72x lower p50 and 11.30x lower p99, but used 1.66x
the broker RSS in this eight-client run. Mosquitto's smaller RSS remains a
clear memory target rather than being hidden by the throughput result.

The production driver also covers durable online Sessions through
`--session-expiry-seconds=300`. Three otherwise identical window-64 runs gave
these per-metric medians:

```text
broker       pub/s   deliveries/s   p50 ms   p99 ms   p99.9 ms   client allocs   broker peak RSS KiB
netz        39,146        156,586    2.769    5.711       6.404         504,113                 6,456
Mosquitto    6,341         25,365    4.102   44.989      45.953         672,117                 3,804
rumqttd      6,999         27,996    1.037   40.942      41.756         672,129                17,448
```

All nine runs completed 80,000 measured deliveries with checksum 20,580,000.
For this reconnect-safe QoS 1 shape, netz delivered 6.17x Mosquitto and 5.59x
rumqttd throughput, with respectively 7.88x and 7.17x lower p99. Netz used
69.7% more broker RSS than Mosquitto but 63.0% less than rumqttd. The durable
netz path is 29.5% below its transient-session median because each destination
must deep-own payload and acknowledgement state until completion; that cost is
now measured rather than hidden. Persistence crash windows and broader
conformance remain separate gaps.

Durable Session publications now store Topic Name and payload in one contiguous
allocation per destination instead of two. This preserves independent
reconnect ownership and the existing snapshot views while removing one
allocator round trip from every durable fanout. Three reruns of the expiry-300
shape measured 38,738-40,299 publishes/s (median 39,077), p99
5.467-5.664 ms, p99.9 5.973-6.577 ms and 6,476 KiB median broker peak RSS.
Throughput remained effectively flat versus the prior 39,146 median, while
tail latency improved about 1.7-1.9%; the main value is simpler bounded
ownership rather than a claimed throughput step.

## Live QoS 2 dispatch

The broker now follows the audited Mosquitto lifecycle rather than treating
QoS 2 as QoS 1 with extra acknowledgements:

- inbound PUBLISH bytes are deep-owned in a broker-wide bounded store,
- PUBREC is written only after that transaction is stored,
- a DUP=1 PUBLISH with the same Packet Identifier is validated and
  acknowledged without creating another Application Message,
- topic routing happens only when PUBREL arrives,
- a repeated or unknown PUBREL receives PUBCOMP without routing again, matching
  Mosquitto's lost-PUBCOMP recovery behavior,
- downstream QoS remains `min(source QoS, subscription QoS)`,
- downstream PUBREC/PUBREL/PUBCOMP state shares the runtime's fixed Packet
  Identifier tables and Receive Maximum queue,
- disconnect removes all pending transactions owned by that live connection.

Rumqttd likewise records the QoS 2 PUBLISH in its ACK log and appends it to the
commitlog only after PUBREL. Netz keeps this live store deliberately
in-memory; durable Session continuation across reconnect remains separate
work.

## Shared router benchmark

The current executable obtains its monotonic clock from zio-backed `std.Io` and
prints `io backend: zio-std-io`. The numbers below predate that migration and
remain historical Threaded evidence.

Run:

```sh
zig build bench-mqtt-router -Doptimize=ReleaseFast
```

2026-08-19 same-host `ReleaseFast` ranges over three runs after combining
ordinary/shared count and emit work into two total trie traversals:

```text
4098-filter indexed match:        191-205 ns/op
4098-filter linear scan:          102-103 us/op
indexed speedup:                  499-540x

64-member RoundRobin selection:   160-166 ns/op
64-member Sticky selection:       173-178 ns/op
64-member Random selection:       166-169 ns/op
64-member Rendezvous selection:   1.23-1.24 us/op
```

Ordinary and shared subscriptions now share the same count traversal and the
same emit traversal instead of independently walking the topic levels. Every
selection path uses that topic-filter trie; the strategy work is
only paid after a shared group matches. Count-only preflight never advances a
RoundRobin cursor or Random PRNG, so `MatchBufferTooSmall` is transactional.
Random state and the precomputed Rendezvous seed are scoped to each
`{ShareName, TopicFilter}` group instead of coupling unrelated subscriptions.

The corresponding rumqtt router benchmark source in
`~/Work/rumqtt/benchmarks/router/routernxn.rs` is currently commented out, so
there is no honest same-command throughput number to quote. The strategy
comparison is direct source/behavior evidence; the netz timing above is a
reproducible internal baseline rather than a claimed whole-broker speed ratio.

## QoS2 serial profile

A 20,000-message serial QoS2 durable-session run (256-byte payload, publisher
window 1, queue capacity 20,000) measured 20,581 publishes/s, p50 40.9 us, and
p99 67.8 us. A 999-Hz `cycles:Pu` DWARF profile captured 915 samples. The
broker spent 55.9% of children parked or waiting, with
`__kernel_clock_gettime` at 13.2% self, `handlePubRel` at 15.4% children
(2.05% self), `flushSlotLockedMode` at 8.6% children (3.4% self), and
`routePublish` at 4.7% children (2.87% self). There is no single large CPU
hotspot: the serial gap is dominated by event-loop wakeups, parking, and clock
reads. Future work should reduce task wakeups or ownership boundaries rather
than reworking the route/flush helpers. Rows, hashes and the command are in
`docs/evidence/mqtt_qos2_serial_profile/2026-11-02.json`.

A 2026-11-19 current-state smoke repeated the same broker workload shape with
the in-repo benchmark client. CPU-pinned runs measured 31,894 publishes/s
(p50 25.4 us, p99 29.2 us, p99.9 32.5 us), and an unpinned run measured 33,613
publishes/s. Both sides reported `zio-std-io`, exact 20,000 deliveries and
checksum 4,962,720. The historical 2026-11-02 figure used a separate driver, so
this is a current-shape smoke rather than a controlled A/B; it shows the
serial path is no longer at the earlier 20,581 publishes/s level. Broker RSS
versus Mosquitto was not measured in this run. See
`docs/evidence/mqtt_qos2_serial_profile/2026-11-19.json`.
