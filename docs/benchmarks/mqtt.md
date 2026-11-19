# MQTT fanout and router results

[Back to the benchmark index](../benchmark-baseline.md).

## MQTT 5 windowed QoS 1 broker fanout

The current driver obtains `std.Io` from zio, schedules subscriber readers in
an `std.Io.Group`, and uses events for readiness and warmup barriers. The
Mosquitto runner validates a structured result for each server, including
complete publish/delivery counts, derived rates, latency ordering, an
independently calculated checksum, and `client_io=zio-std-io` paired with
`server_io=zio-std-io` or `mosquitto-event-loop`. A 2026-09-15 default-size
migration gate completed 2,000 publishes and 4,000 deliveries against each
server with checksum 1,029,000. It was one unpinned sequential run, so it is
correctness evidence rather than a new performance comparison.
The maintained runner now derives one shared per-client queue capacity: at
least the historical 1,024-message bound and large enough for the longer of the
warmup and measured publish counts. This matches the driver's exact-delivery
contract: a smaller configured bound may legitimately drop QoS fanout after
acknowledging the publisher, leaving subscribers waiting until Keep Alive
expiry. `MQTT_MAX_QUEUED_MESSAGES` can increase, but cannot lower, the derived
capacity.
Timing, memory, and verification records expose the value as
`server_queue_capacity`.

The comparison below predates the migration and remains historical
`std.Io.Threaded` evidence.

Captured on 2026-08-20 with one external client binary driving both brokers:

```sh
zig build bench-mqtt-broker -Doptimize=ReleaseFast -- \
  --address=127.0.0.1:PORT --publishers=4 --subscribers=4 \
  --warmup-messages=1000 --messages=20000 --payload-bytes=256 \
  --publisher-window=64
```

Each measured PUBLISH fans out to all four QoS 1 subscribers. Every run
completed 20,000 publishes and 80,000 deliveries with checksum 20,580,000.
Three consecutive runs gave:

```text
netz publishes/s:     56,486 / 54,847 / 55,505
netz p50 ms:           1.742 /  1.818 /  1.813
netz p99 ms:           3.696 /  4.077 /  3.921
netz p99.9 ms:         3.925 /  4.795 /  4.923
netz broker peak KiB:  6,436 /  6,428 /  6,440

rumqttd publishes/s:   7,218 /  6,902 /  6,642
rumqttd p50 ms:        1.335 /  1.277 /  1.340
rumqttd p99 ms:       41.154 / 41.047 / 41.100
rumqttd p99.9 ms:     42.006 / 41.800 / 41.373
rumqttd broker KiB:   17,716 / 17,576 / 17,632
```

The entries above remain in run order; the cross-broker summary in
`docs/rumqtt_parity.md` computes medians per metric. Netz made 504,105 client
allocation calls and allocated 120,171,264 cumulative bytes in every run.
Rumqttd required 672,117-672,129 calls and 133,107,836-133,108,592 bytes.
Client peak-live remained approximately 504 KiB for both. Broker RSS was
sampled from `/proc/PID/status` every 2 ms while the load driver was alive.

The netz result includes TCP_NODELAY by default for ordinary MQTT TCP, a
Session queue-head cursor, and a shared-Publication fast path for online
Session Expiry zero clients. Before the cursor, a 40,000-publish profile
assigned 50-53% of broker cycles to `Broker.flushSlotLocked`, with the
consumed-prefix null scan dominating its annotation. The cursor reduced that
symbol to 4.9% in the matching atom-core report. Avoiding durable deep copies
for transient online Sessions then raised the three-run range from
37,098-40,021 to 53,843-54,197 publishes/s. The broker task closure now carries
only the owned CONNECT parse tree after moving its much larger runtime
Connection into the stable slot; this removed a redundant per-worker stack
copy and reduced median broker peak RSS from 9,344 to 8,496 KiB while retaining
54,655-55,781 publishes/s. Finally, the production example uses libc's shared
allocator rather than one SMP cache per worker: the same three-run shape held
54,847-56,486 publishes/s while median broker peak RSS fell again to 6,436 KiB.
Library users still select their allocator through `Broker.listen`. This
comparison is specific to the bounded QoS 1 shape and is not a broad broker or
persistence verdict.

The same driver now accepts `--session-expiry-seconds=N` to force the durable
online Session path rather than the expiry-zero shared-Publication fast path.
With expiry 300 seconds and the otherwise identical window-64 shape, three
netz runs measured 38,531 / 39,228 / 39,146 publishes/s, p99
5.713 / 5.620 / 5.711 ms, and 6,456 KiB broker peak RSS in every run. All
80,000 deliveries completed with checksum 20,580,000. This explicitly bounds
the cost of retaining reconnect-safe QoS 1 payload/inflight state instead of
silently generalizing the transient-session result.
Topic and payload ownership is now coalesced into one allocation for each
durable queued publication. A three-run rerun remained at 38,738-40,299
publishes/s with p99 5.467-5.664 ms and 6,472-6,492 KiB broker peak RSS,
confirming the allocation-count simplification without overstating it as a
throughput improvement.

Connection-local MQTT Packet Identifier state is now adaptive rather than five
embedded 65,536-bit tables. Independent incoming and outgoing maps use sparse
storage for ordinary negotiated inflight windows and promote after 1,024 live
IDs to bounded 16-KiB two-bit tables; this preserves the full identifier space,
directional reader/writer isolation, allocation-free QoS 2 stage changes, and a
32-KiB worst-case bound across both directions. Five alternating fixed-binary
32-publisher/32-subscriber runs (window 4, 64-byte payload, 10 warmups and 200
measured publishes; `0b51301a` baseline, `09825721` candidate) reduced netz
broker peak RSS from 36,348-36,364 KiB to 6,352-6,368 KiB, with all runs
completing 6,400 deliveries and checksum 356,160. This short shape is memory
evidence rather than a throughput result.
The maintained Mosquitto comparison can now set `MQTT_STATS=true` to sample
both broker processes from `/proc/PID/status` every 2 ms and emit verifier-
checked memory records. At this historical stage, the broker moved the 3-KiB
parsed pending client out of each finite connection coroutine, isolated large
certificate, refusal, accepted-client, and Session admission frames from the
steady-state read loop, and deferred the full live-delivery queue allocation
until a restored or new subscription became routable. The later demand-driven
queue change below replaces that full reservation. Seven `c3fe1516`
runs of the same fixed-binary 64-connection shape measured netz at
5,868-7,844 / 5,884-5,948 KiB, with medians falling from 6,188 to 5,932 KiB
(4.1%). Mosquitto measured 3,820-3,916 / 3,800-3,904 KiB, with medians 3,904
and 3,808 KiB. The parent's roughly 7.8-MiB netz outlier is retained in the
range. The median netz-minus-Mosquitto gap fell from 2,284 to 2,124 KiB
(7.0%). All 14 arms completed 6,400 deliveries with checksum 356,160. This
narrows but does not close the independent-peer memory gap and remains memory
evidence rather than a throughput claim.

The broker slot's generated Client ID now reuses its allocation through a
pointer plus the generator's bounded u7 length, while the borrowed CONNECT
username uses a pointer plus its MQTT-native u16 length. Packing both lengths,
the 31-bit connection generation, the active/Session/graceful flags, and
presence bits for the 16-byte Session and Will handles plus the retained-source
identity into one u64 removes their optional tags and the remaining alignment
holes. The audited 64-bit `ClientSlot` falls from 136 to 96 bytes. Relative to
the original 1,824-byte slot, the default 1,024-slot broker now reserves
1,769,472 fewer bytes before connections arrive. This is a compile-time layout
result; it does not claim a separately measurable RSS or throughput change.

The active MQTT runtime now stores its owned listener namespace as one pointer
plus the protocol's u16 length, packs negotiated QoS and publish/subscription
availability into one 16-bit word, and uses a packed presence bit for the full
raw u8 CONNECT protocol level. Its TCP parser also keeps a seven-cache-line,
448-byte read-ahead region: this still holds the benchmark's complete
four-packet 64-byte-payload publish window, while larger packets retain the
existing exact-allocation path. Outgoing property filtering and synthesis now
use eight caller-stack descriptors; larger sets retain one exact connection-
owned overflow slice, removing the previous 24-byte `ArrayList` from every
connection without reintroducing warmed large-set churn. Together these changes
reduce the audited 64-bit `runtime.Connection` from 1,408 to 784 bytes (624
bytes saved per ordinary QoS 0 live connection without aliases). At 64
simultaneous connections the final
read-ahead reduction alone removes 4,096 bytes of fixed connection state. The
compile-time layout result is intentionally not presented as a process-RSS
claim. A fixed-binary four-sample five-shape comparison against the 512-byte
read-ahead build completed every expected delivery and checksum; normalized
throughput moved in both directions within the observed host variance, so it
is retained as no-regression rather than speedup evidence. The baseline and
candidate summary SHA-256 values are
`99fcd5f3a68fa101f84bece5fcd7bf9a3c8aaf0fce82f817e1fac94630794bc0`
and `cf1bf928ba129239b62149141476e58d221f1e3fbcf8e795980aa9313672954c`.

Delivery authorization now keeps the already-owned global and listener
callback tables behind borrowed pointers. Before resolving a destination
Session's Client ID, live fanout, retained replay, and durable Session drain
first check whether either policy actually supplies a delivery callback. The
default no-ACL path therefore avoids the otherwise unused identity lookup.
Retained replay also uses the connection's stack-first property staging instead
of allocating and freeing a temporary property list for every stored message;
a fail-on-first-allocation unit check proves that a common same-size rebuild
requires no allocation and still rewrites or removes Message Expiry correctly.

Subscriber delivery queues now prewarm only
`min(max_queued_deliveries_per_connection, 16)` entries instead of allocating
their complete configured hard limit when a subscription becomes visible.
Slow-consumer queues reclaim consumed prefix storage first and otherwise grow
geometrically during route preflight, capped by the same hard limit. All
fallible growth happens before a Publication or queue entry is committed, so
the actual fanout mutation remains allocation-free and an OOM cannot expose a
partial route. A 64-bit `Delivery` is 48 bytes; with the matrix's 2,048 and
3,200 limits, the former policy reserved 96 and 150 KiB per subscriber even
when its live queue was empty.

Three fixed-binary QoS 1 allocator samples compared broker binaries
`0e0223d51df6dad9d99e683f78e96e84975358f9955a8c5a314f5f362e87d1db`
and
`5ec1526f842612a4bf33302f45bf74c8df404642f234c10a8ba5fc23317a9688`.
Allocation calls were unchanged in every shape. Fanout-32 cumulative requested
bytes fell from 9,617,559 to 6,496,407 and median peak live bytes from
9,164,653 to 6,043,501 (34.1%). Balanced-32x32 cumulative bytes fell from
11,734,165 to 8,221,333 and peak live bytes from 11,131,511 to 7,658,907
(31.2%). Under 3,600-second durable QoS 2 Sessions, fanout-32 peak live bytes
fell from 9,197,580 to 6,081,916 (33.9%) and balanced-32x32 from 11,098,901 to
6,203,237 (44.1%). Every run ended at zero live bytes. Baseline/candidate QoS 1
allocator summary hashes are
`22b363ffd497acdec8f98581e1939e0812c8dbc2dbd5fd97f43e35a1f667cbc8`
and `21eb0bc71d14288141db33ba684e72249e6023230f9ecece3bb4b19dbbe665d8`;
durable QoS 2 hashes are
`720fc00f6684ca50b4d0ba7ba34bcda2a677c8984b712dc3cb696e7d738fbd14`
and `390d35bf912b6bb61c4d06ae8adf791d39cc8e8f13004629d542f53c767fe49e`.

The complete four-sample QoS 1, transient QoS 2, and durable QoS 2 matrices
also completed all 240 broker runs with exact delivery counts and checksums.
QoS 1 median Netz RSS fell in every shape, including 5,242 to 5,012 KiB for
fanout-32 and 7,542 to 7,090 KiB for balanced-32x32. Transient QoS 2 RSS also
fell in every shape; durable QoS 2 fell in four of five, while its 4-KiB shape
rose 112 KiB. Throughput moved in both directions across the QoS variants, so
these separate ABBA matrices are retained as compatibility/no-obvious-
regression evidence rather than a causal speedup claim. Their baseline and
candidate summary hashes are, respectively,
`fe57ef8d988d8c48db5576fcbba1ec1b7dd13fa134dde5d0d970bd18d175e2f2` /
`eec99c442c06e39e8631bde232d34464832a1078fe3dbdc5d0a8d8705417a8bf`
for QoS 1,
`b5f5fd51b09e6db2b7d70ad3b15c2512124b54e6ee46048664520f5b13241d46` /
`b2033bda248e3fb9bbf1061c4272b1f6770460d036303bf7d47d617d9b1977ce`
for transient QoS 2, and
`19c9a0b6b3570baaa942eed8841632824d8595e0356ee4b7a5e2737fe3e2d36f` /
`43bf8a8e89123009a45e1a7c51eadd4cc10d63ae181ed6c372e51ad6d417a068`
for durable QoS 2.

Persistent Session expiry pruning now has a conservative per-Session earliest
message deadline. The ordinary no-expiry path returns in O(1) instead of
scanning queued and inflight arrays on every enqueue and every single-packet
broker drain. Expiring messages still use the exact scan when the deadline is
due; that scan repairs the next deadline. Snapshot restore, enqueue, immediate
inflight insertion, and QoS 0 rollback all update the hint, while an
`await_pubcomp` QoS 2 record remains exempt from Message Expiry as required.

A fixed-binary, CPU-0/client and CPU-1/server comparison used 32 publishers,
32 subscribers, MQTT 5 QoS 2, 3,600-second Sessions, a four-message publisher
window, 1,000 warmups, and 10,000 measured 64-byte publishes per arm. All seven
AB/BA pairs completed 320,000 deliveries with checksum 18,656,000. The
candidate won throughput and p99 in five pairs; the median paired throughput
ratio was 1.014 and the median paired p99 ratio was 0.976. Client allocation
counts and cumulative bytes were identical. Baseline/candidate broker hashes
are
`5ec1526f842612a4bf33302f45bf74c8df404642f234c10a8ba5fc23317a9688`
and `83ebf9768c5124d3b4b2b95b7c234f4ac1e5b5dac1d724327d9b63d7873f9650`;
the validated paired log SHA-256 is
`7eade410a59b63a8e015411bcf7f89a5a765e4fbaed6bd3d390e23c7988a4dac`.
The complete candidate five-shape matrix also preserved all delivery counts
and checksums; its summary SHA-256 is
`9d68958b426cecfc4c6cd7ae6cbdc79fe26ca7e36c900382249ad8a666cb18e7`.
The remaining cross-broker durable-session gap is still dominated by broader
per-destination ownership and scheduling work.

Offline durable fanout now shares one reference-counted immutable Topic
Name/payload owner across its destination Sessions, matching Mosquitto's split
between a shared base message and per-client delivery state. Each Session still
owns its delivery properties and QoS/Retain/Packet Identifier state, applies
its logical byte limits independently, and serializes the unchanged snapshot
format. Ordinary online persistent delivery keeps the existing cached
independent backing after an all-destination sharing experiment increased
allocation traffic. The narrower exception is a multi-destination QoS 1 TCP
PUBLISH whose owned packet already carries a `Publication`-sized prefix: that
allocation becomes the shared owner for online durable Session entries and any
transient destinations in the same route. A small PUBLISH borrowed from the
128-byte connection stack buffer cannot be adopted and therefore stays on the
cache-backed path without creating an extra source Publication.

`bench-mqtt-session` now includes a same-binary, seven-pair AB/BA comparison
that retains 256 messages across 64 offline Sessions (16,384 logical
deliveries). The final CPU-0 run measured 812 ns per destination for independent
copies and 336 ns for shared bytes, a 58.6% reduction. Across repeated runs the
shared path remained 58.3-75.0% lower. More importantly, every run reduced
backing allocations from 16,896 to 768 (95.5%) and incremental live bytes from
11,345,920 to 3,052,544 (73.1%), with identical logical queue counts and zero
bytes after teardown. The benchmark binary SHA-256 is
`a2bfe1e2a2e8a14afe3724641180f7f60cf1e906c40193a29e52ad4881b56020`;
the captured output hash is
`07630da78b56333ae2c31f4dae44fc61b924edd81005fcbc764d951fd48eb6f9`.
A complete online durable QoS 2 five-shape matrix, where sharing is deliberately
inactive, preserved all delivery counts and checksums and showed mixed timing
within the existing host variance. Its summary SHA-256 is
`97446c6d1693486491dff07926b35c77982787e0d5fb3a35b35673f1ed0bafdc`.

A seven-sample fixed-binary QoS 1 durable allocator comparison exercised the
ingress exception above. All 70 broker runs completed with identical delivery
counts/checksums and zero live bytes after teardown. The four shapes whose
64-byte packets borrow stack storage stayed at baseline allocation levels. In
the deterministic 4-KiB shape, the candidate reduced median allocation calls
from 2,370 to 2,331 (1.6%), cumulative requested bytes from 15,495,237 to
15,175,749 (2.1%), and peak live bytes from 6,322,177 to 6,032,215 (4.6%).
Baseline/candidate broker SHA-256 values are
`7efdc3ccf6b4c66761c2f270b41c73126874bded28dabb616f04a5da1a552fd4`
and `a23755ef9f7e469b6a867ccbab0ea87ceb7e53311b3cbc447d59c18be451badc`;
their allocator summary hashes are
`2c0e4fc564eb0975e2c661056160dbaa2d518e16f466aabd1f9514b74813bb59`
and `a12072a5842b5e60282b67b4e3b63c80531fe8c7d99cf36df15eaeecbc809094`.

A separate CPU-0/client, CPU-1/server seven-pair alternating-order A/B used
four publishers, four subscribers, MQTT 5 QoS 1, 3,600-second Sessions, a
16-message publisher window, 1,000 warmups, and 10,000 measured 4-KiB
publishes per arm. Every arm completed 40,000 deliveries with checksum
10,780,000. Median throughput moved from 19,090 to 19,362 publishes/s (1.4%),
the median paired ratio was 1.017, and the candidate won all seven pairs.
Median p50/p99 changed from 1.245/2.489 ms to 1.210/2.418 ms. The captured log
SHA-256 is
`9aac0c3d68f5f43e8e056decabe7c1115d41461459b3b17f8821241e46abfce4`;
this is targeted large-packet evidence rather than a general broker claim.

Inbound QoS 2 now applies the same ownership model at its later protocol
boundary. When persistent Sessions and more than one subscription make durable
fanout possible, the pending transaction's aligned cache block reserves a
`Publication` header. PUBREL converts that block in place and shares its Topic
Name/payload across all durable destinations; the final concurrent Session or
live-delivery release returns the block through a synchronized adapter to the
original bounded pending cache. Properties remain alive until routing finishes
and are still cloned per destination where MQTT state differs. Route matching
remains deferred until PUBREL, so shared-subscription selection and
subscription changes keep their existing semantics. Single-subscription and
pure transient brokers reserve no prefix and retain their old paths; the latter
restriction was kept because an all-target prototype produced a repeatable
large-payload throughput regression.

Seven fixed-binary durable QoS 2 allocator samples per shape completed all 70
baseline/candidate broker runs with exact deliveries/checksums and zero live
bytes after teardown. Serial was byte-for-byte unchanged. Fanout-32 allocation
calls fell from 833 to 745 (10.6%), and balanced-32x32 from 1,242 to 1,181
(4.9%). In the 4-KiB shape, calls fell from 2,431 to 2,400, cumulative requested
bytes from 15,928,837 to 15,698,861 (1.4%), and peak live bytes from 6,755,201
to 6,525,561 (3.4%). The small balanced shape traded 8,576 bytes of peak live
storage (0.14%) for its lower allocation count. Baseline/candidate broker
SHA-256 values are
`8c1ace2c11f92246679729cf78e5d6ae4f56832fb37f84542998b3316ac57566`
and `d4a47755ca070d20f05d06c71660c12444b54bd15f54e4e4c0707848d622379f`;
their summary hashes are
`7bd59771d5de02de3f2dac13428f316bc6eaaff177549042258fad91a3162aa6`
and `1e7c8d24d8372f1184cabeb9a326692b22921a9b0e8b45d55a3a36de35d1727f`.
A separate three-sample transient QoS 2 control kept allocation counts and
cumulative bytes identical in all five shapes; its baseline/candidate summary
hashes are
`7e5a0682d48662903ab82b824878f1b140c6d1f72ffc26ca9f45a5a63c87d2c7`
and `e30e43845ac7a6e47599343bf70b1b7be51189f6628e1c2c9276bf5ee1ee4ea0`.

The final CPU-0/client, CPU-1/server seven-pair alternating-order A/B used four
publishers, four subscribers, MQTT 5 QoS 2, 3,600-second Sessions, a
16-message window, 1,000 warmups, and 10,000 measured 4-KiB publishes per arm.
Every arm completed 40,000 deliveries with checksum 10,780,000. Candidate
throughput improved from a 11,133 to 11,241 publishes/s median (1.0%), its
median paired ratio was 1.012, and it won all seven pairs. Median p50/p99 moved
from 2.887/5.310 ms to 2.860/5.264 ms. The captured log SHA-256 is
`e08a87129648a770b9664de04fde56b2607b7dca100a1a75e16df0b7ac29820b`;
this remains targeted durable large-payload evidence, not a broad QoS 2 claim.

Online durable cross-connection fanout now uses two fixed serving-scope
Session delivery workers and a bounded per-slot coalescing ring instead of
retaining one coroutine stack per Session. Same-connection and backpressured
destinations remain synchronous, each slot keeps its existing writer
serialization, and shutdown joins both workers before broker teardown. The
first per-Session prototype was rejected despite its speed because balanced
RSS rose from about 7.0 MiB to 14.9 MiB; the zio 64-KiB initial-stack
experiment was removed with it, retaining zio's 256-KiB panic/error-path
default and 8-MiB virtual growth ceiling.

Five fixed-binary pairs at
`zig-out/mqtt-durable-shared2-ab-final` (63,667,135 bytes; aggregate
file-hash digest
`2146ea99f81fb0bc0377de777671c34c7ed39f2b5c8e7d59dd8afb17511570df`)
pinned client/server/RSS sampling to CPUs 0/1/2. With 1,000 warmups and 10,000
measured durable QoS 2 publishes per arm, balanced-32x32 moved from 1,813 to
2,713 publish/s (paired median 1.489x, range 1.433-1.632), p50/p99 fell to
0.640x/0.639x, and broker RSS moved from 6,976 to 8,148 KiB. The 4-KiB shape
moved from 12,652 to 15,273 publish/s (1.213x, range 1.207-1.223), p50/p99
fell to 0.798x/0.823x, and RSS moved only from 5,632 to 5,652 KiB. All ten
throughput pairs won and every arm matched its exact delivery count and
checksum. Baseline/candidate/driver hashes are
`fbd216b8cf4f0240ced742f85d805372c795102c90578bec20c8e2c53bf3ff94`,
`30b6a86286dbdc8ff82c97701812e0ac029557ac6f62a218e416f36ecfe84b69`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
The matched 102,400-delivery `strace` diagnostic at
`zig-out/mqtt-durable-shared2-strace-final` reduced `io_uring_enter` from
114,102 to 63,454 (-44.4%); its instrumented timing is not used as benchmark
evidence.

The final pool starts lazily on the first eligible multi-target durable route,
not when a serving scope opens. The three-shape, five-pair fixed-binary run at
`zig-out/mqtt-durable-lazy-shared2-ab-final` (63,688,110 bytes; aggregate
digest `21cd20890dda288025a91dcc98366c6ac7126c4b20acd994115c9b58dc86a248`)
added a 1x1 serial negative control. Its baseline/candidate medians were
19,040/18,878 publish/s, 43.258/43.481 us p50, and 4,860/4,824 KiB RSS;
the 0.997x paired throughput ratio and lower candidate RSS show that an unused
pool does not retain writer stacks. Balanced-32x32 retained a 1.489x throughput
ratio with p50/p99 at 0.638x/0.640x and RSS at 6,928/8,716 KiB. The 4-KiB
shape retained a 1.213x throughput ratio with p50/p99 at 0.819x/0.818x and RSS
at 5,636/5,664 KiB. All fifteen pairs completed exact delivery counts and
checksums. The final candidate hash is
`333148f1b4437441eb3db0727ca4f98ad7733c67808d17bcc90d2ddfaa6d52b4`.
Three same-shape `strace` runs recorded 63,733-81,254 `io_uring_enter` calls
(73,296 median), 35.8% below the 114,102-call baseline; those instrumented
timings remain diagnostic-only.

The next serial QoS 2 profile found that one already parsed PUBLISH was still
revalidating its Topic Name, source identity, and properties in Topic Alias,
Router, retained, QoS2-store, and Session-store layers. Broker-internal paths
now carry an explicit validated-input contract while every public store/router
entry point retains defensive validation. This follows audited Mosquitto
`5cd25465`, which validates UTF-8 in `packet__read_string` and performs the
remaining PUBLISH Topic Name check before database routing. A seven-pair
fixed-binary run at `zig-out/mqtt-validated-ingress-ab-final2` (63,726,852 bytes;
aggregate digest
`e968026569990076d0120e697f7df2cf3f11be7d34aa0eacada6acca8455858c`)
used one publisher/subscriber, 1,000 warmups and 10,000 measured 256-byte
durable QoS 2 publishes. Candidate/baseline paired medians were 1.033x
throughput, 0.969x p50, and 0.996x RSS; six of seven throughput pairs won,
p99 was noisy and inconclusive, and every arm completed 10,000 deliveries with
checksum 2,695,000.
The baseline/candidate hashes are
`333148f1b4437441eb3db0727ca4f98ad7733c67808d17bcc90d2ddfaa6d52b4`
and `beb97b847532fe3bd004b8c35cdc210d9c1a2b10caaef0414929c31dc5a5a0cc`.
Matched 100,000-message CPU profiles reduced the combined sampled share of the
MQTT UTF-8 validator and decoder from 19.3% to 7.4%; the remaining dominant
userspace hotspot is monotonic-clock sampling around packet/deadline and
Session-expiry boundaries.

The next investigation first ruled out syscall count: an equal 1,000-warmup
plus 10,000-message serial trace recorded 78,453 total syscalls for netz
(78,357 `io_uring_enter`) and 198,989 for Mosquitto. A zio inline-send
prototype was rejected because seven-pair fixed-binary checks regressed all
five HTTP/1, WebSocket, MQTT-over-WebSocket, MQTT-over-TLS, and HTTP/2 controls;
the complete rejected evidence is retained at `zig-out/zio-direct-send-cross`.

The accepted approach reuses zio's event-loop awake-clock snapshot only where
MQTT work is already bounded to the same scheduler scan, retaining exact
`std.Io` clock behavior elsewhere. In a matched 5,000-warmup/100,000-message
profile, the 13.2% sample share below repeated protocol clock reads
disappeared; the
remaining 12.7% `clock_gettime` share came entirely from the event loop's one
refresh per poll. The final five-pair, remote-zio matrix at
`zig-out/mqtt-cached-awake-final-ab` (63,798,176 bytes; aggregate digest
`9f6c0000a2a9b70fa8eae9d332251da30a78647f1a987bccbd99ae8cf5f430ee`)
used baseline/candidate/driver hashes
`beb97b847532fe3bd004b8c35cdc210d9c1a2b10caaef0414929c31dc5a5a0cc`,
`b5008a3cbddc9200a414e084b44860a19baf5e1cb718d2fc3ad9348e2e4bec28`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Paired throughput medians for serial, publishers-32, fanout-32,
balanced-32x32, and 4-KiB were 1.018x, 1.021x, 1.078x, 1.038x, and 1.025x;
p50 ratios were 0.989x, 0.959x, 0.899x, 0.946x, and 0.986x. Publisher-heavy
p99 remained noisy. A five-pair 100,000-message serial control was neutral at
1.003x, and seven-pair MQTT-over-WebSocket/TLS controls were neutral at
1.009x/1.003x, so those shapes are recorded as no-regression rather than
throughput wins.

The next isolated change keeps every MQTT UTF-8 and Mosquitto-compatible
strict-control rule but gives all-ASCII strings a one-pass return before the
general Unicode decoder. The final five-pair fixed-binary matrix at
`zig-out/mqtt-ascii-validation-final2` (63,807,571 bytes; aggregate digest
`24df711c34b2923e11251e9c0e9afd627dfff95345ac213c2c7d4ab39ffa4bf1`)
pinned client/server/RSS sampling to CPUs 5/7/13 and used cached-time
baseline/candidate/driver hashes
`b5008a3cbddc9200a414e084b44860a19baf5e1cb718d2fc3ad9348e2e4bec28`,
`9a0ae6df6a55ebc8f671c657860c7f36e9c6dfcc2c0a59dff94e24b70d601f57`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Serial, publishers-32, fanout-32, balanced-32x32, and 4-KiB paired throughput
medians were 1.012x, 1.003x, 1.005x, 1.011x, and 1.013x. Their p50 ratios were
0.993x, 0.967x, 1.002x, 0.979x, and 1.013x. The first four shapes each won
three of five throughput pairs; 4-KiB won all five. These small changes are
supporting CPU/path-length evidence, not a broad throughput claim, and RSS
remained neutral. A matched 100,000-message profile at
`zig-out/mqtt-ascii-validation-profile-final2` removed the former 4.95%
validator and 3.70% UTF-8 decoder entries from the top sampled symbols with
zero lost samples.

A fixed-binary four-sample matrix compared `a45ddb93` with the final candidate
on 2026-10-02. In serial, publishers-32, fanout-32, balanced-32x32, and
large-payload order, netz median throughput was
28,679 / 49,387 / 4,200 / 3,927 / 25,655 publishes/s before and
28,887 / 50,209 / 4,158 / 4,208 / 24,792 after. The mixed changes and
overlapping ranges are recorded as no-regression evidence, not as a throughput
claim; every arm completed its exact delivery count and checksum. The baseline
and candidate executable SHA-256 values are
`33b512935a2d57f777f02f8fbce8f6afe632fc34495b442e16c5f422e3dde5e8`
and `c93823ed33df1373254fe54074de139de16a1014900f4ce31f54bd4d0efd3bd4`;
their validated summary hashes are
`5754259cd3942286551e8611edfb9126e9c85e46b42e27fbf0136b71d1e615a1`
and `ff2ae72b7c3f7e168da61d75cfd878fc4f9ff0582dd5e2acb91bc8bea684f930`.

Transient QoS 1/2 broker fanout now uses one lazy writer per subscribed
connection instead of making a publisher wait for every unrelated subscriber
socket. The writer starts only after a QoS 1/2 subscription is processed,
subject to the connection's Maximum QoS, shares the existing per-connection
write serialization, preserves PINGRESP as an
ordered output barrier, and is joined before slot reuse. Self-delivery stays on
the synchronous path so its PUBLISH precedes PUBACK/PUBCOMP on the shared
connection. A queue depth of 16 returns that destination to synchronous
backpressure before the configured hard queue/drop limit. This historical
transient design left QoS 0 and durable Session delivery synchronous; the
two-worker pool above now handles eligible durable cross-connection fanout.

A fixed-binary CPU-0/client and CPU-1/server A/B used 32 publishers, 32
subscribers, MQTT 5 QoS 2, a four-message publisher window, 1,000 warmups and
10,000 measured 64-byte publishes. All fourteen arms completed 320,000
deliveries with checksum 18,656,000. Baseline/candidate throughput medians were
1,591/2,240 publishes/s; the paired candidate/baseline median was 1.417x with
7/7 wins. Paired p50 and p99 medians fell to 0.653x and 0.682x. The exact
final-binary QoS 1 five-shape matrix was the historical synchronous-path
control. Three
5,000-publish RSS pairs measured transient QoS 2 medians of 6,544 KiB baseline
and 6,708 KiB candidate. Three durable-Session QoS 2 controls, which also start
no writer, measured 6,624/6,620 KiB with overlapping timing.

The retained baseline broker, candidate broker, fixed driver, and complete
paired log have SHA-256 values
`cadec82a5d73be2c98beb865f5ae9d0a7c724d66d51d04cfd6b00e34f1bfcbaa`,
`cc2c445614e2c49687c0a32281f3bb765795f3999f640014531d51539941bcad`,
`dda118b3c68c0c24f4a77ad9e3c5b939f6df17c6904de7bb131c971e07aafc36`,
and `326fec275da8588cfc4a03ce41b67bdad1344e5ba2f5bd1b17b8adb77d47d839`
respectively. The strict QoS 1/QoS 2 five-shape matrix summary hashes are
`5f32c63cbd4c0167a4f99c1b1d7f44794d9da516a5a79ee36c053996bc762574`
and `1df7a0be6e51b819ccde56b9c5d0d99e972a54f95b43cb555dde16149c18a465`.

Extending that writer to multi-destination transient QoS 1 removes unrelated
subscriber socket writes from the publisher's PUBACK critical path while
retaining synchronous self-delivery, durable Session delivery, QoS 0 delivery,
per-connection write serialization, and the 16-delivery fallback watermark.
An immediate pre-change four-sample five-shape matrix at
`zig-out/mqtt-broker-matrix/run.20261002T094138Z.1428572` had netz medians of
27,958 / 50,190 / 2,863 / 4,131 / 20,159 publish/s in serial,
publishers-32, fanout-32, balanced-32x32, and large-payload order. Two
consecutive final-binary matrices at
`zig-out/mqtt-broker-matrix/run.20261002T120130Z.1729461` and
`zig-out/mqtt-broker-matrix/run.20261002T120212Z.1739418` produced
29,452–29,635 / 50,482–50,784 / 4,214–4,219 / 3,945–4,065 /
24,793–25,206 publish/s in the same order. All 120 broker runs completed exact
delivery counts and checksums. Fanout-32 therefore improved 47.2–47.4%, its
p99 fell from 1.346 ms to 0.824–0.835 ms, and large-payload throughput improved
23.0–25.0%; serial and publishers-32 improved 5.3–6.0% and 0.6–1.2%, while
noisy balanced 32×32 regressed 1.6–4.5%.
The co-run Mosquitto-normalized ratios improved from 0.651x to 0.953–0.956x
for fanout-32 and from 0.818x to 1.001–1.030x for large-payload. Median broker
RSS increased by 112 KiB for fanout-32 and 62–94 KiB for large-payload,
the bounded cost of lazily created subscriber writers. The baseline and two
candidate summary SHA-256 values are
`85ee91fe87aec1b52b30375ae70b35bec52410256836e97fb4b7dc121b91ad95`,
`2e9586944c14fe6d7813e6aeb7c789c1c500d97c8a44fb0c1bde0dda6aeb4b16`,
and `54d69bc147b50d53e1eddb1fce5c80fde25513596308b54c33e365ed426abe1f`.

## MQTT shared-subscription router

The maintained executable obtains its clock from zio-backed `std.Io` and names
that backend in its output. The numeric ranges below predate this migration and
remain historical Threaded evidence.

Captured on 2026-08-19 with:

```sh
zig build bench-mqtt-router -Doptimize=ReleaseFast
```

Three-run ranges:

```text
4098-filter trie match:            191-205 ns/op
4098-filter linear scan:           102-103 us/op
trie speedup:                      499-540x
64-member shared RoundRobin:       160-166 ns/op
64-member shared Sticky:           173-178 ns/op
64-member shared Random:           166-169 ns/op
64-member shared Rendezvous hash:  1.23-1.24 us/op
```

RoundRobin, Random and Sticky match rumqttd's configurable shared-subscription
strategies. Netz additionally supports stable Rendezvous hashing for
topic-affine assignment with low remapping when group membership changes.
Strategy state is per `{ShareName, TopicFilter}` and only advances after output
capacity preflight succeeds. Ordinary/shared routes are counted together and
emitted together, so a publish traverses the topic trie twice rather than four
times while retaining ordinary-before-shared output ordering.

`~/Work/rumqtt/benchmarks/router/routernxn.rs` is commented out in the audited
checkout, so these numbers are recorded as a netz baseline rather than a direct
whole-broker throughput ratio. See `docs/rumqtt_parity.md` for the feature and
remaining-work audit.

The router match and shared-selection helpers now borrow state instead of
copying it: `matchTrie`, the emission helpers and the group-selection helpers
take `*const Router`, group selection takes `*const SharedGroup`, and emission
reads `*const Entry`. Eight CPU-2 alternating pairs of `bench-mqtt-router`
measured router match at 76.0 -> 69.0 ns/op (1.029x), round-robin selection at
139.5 -> 130.0 (1.069x), sticky at 143.0 -> 130.0 (1.100x), random at
148.5 -> 138.0 (1.080x) and rendezvous at 1,001.5 -> 920.5 (1.080x). The
subscription churn scenarios were neutral, and `removeSubscriber` measured
1.023x after an earlier variant that also changed the lookup helpers was
reverted for a consistent 2.5% regression. Benchmark checksums are identical
across both arms. Evidence is in
[the router borrowed emission evidence](../evidence/mqtt_router/2026-11-08-borrowed-emission.json).

The read-only router scenarios now have their own harnessz-sampled benchmark.
`bench_mqtt_router_match` keeps the 4,098-filter trie and 64-member shared-group
setup but samples only `match`, the linear-scan comparison, and the four shared
strategies; destructive subscription churn stays in the fixed-loop
`bench-mqtt-router`. Six baseline entries were recorded (match 74 ns/op, linear
103.3 us/op, round-robin 135 ns, sticky 130 ns, random 138 ns, rendezvous
1.04 us). The benchmark is registered as `bench-mqtt-router-match` and in the
serialized `bench-record`/`bench-gate` sets with
`benchmarks/baselines/mqtt-router.json`. Evidence is in
[the router sampler baseline evidence](../evidence/mqtt_router/2026-11-09-sampler-baseline.json).

