# MQTT empty Session flush experiment

Three empty Session flush candidates were rejected. The production broker keeps
its existing Session selection and ACK paths. Each candidate preserved the
functional checks, but none produced a useful delivery-time improvement across
the measured profiles without a repeatable control CPU cost.

The first candidate queried outgoing work before every Session packet
preparation. The second reported the remaining state from the ACK operation's
existing Session pointer and ended only an eligible coalesced ACK flush with
empty Session and transient connection queues. The third restored the original
ACK path and folded the outgoing-work observation into the already required
route lookup, removing the first candidate's second Session lookup.

All three idle observations included queued messages, sent inflight entries
and writer-owned detached QoS 0. Merely testing for an unselected transmission
would incorrectly skip expiry maintenance for sent messages or the outstanding
QoS 0 writer commit. Session handle validation, send-cursor assertions,
durability barriers, Receive Maximum, QoS 2 phase rules, and transient queue
draining were preserved. These properties are exercised in the archived patches.

Every comparison uses the same fixed baseline client on CPU 0 and ReleaseFast
broker binaries on CPU 1. MQTT 5 QoS 2 Sessions expire after 3600 seconds,
queue capacity is 100000, and broker outgoing inflight is 64. AB/BA order
alternates by pair. Every run validates exact deliveries and workload checksum;
broker process user instructions/cycles include startup and warmup. Both
counters ran at 100 percent in every recorded arm. Delivery timing excludes
CONNECT and warmup. No Mosquitto-versus-netz throughput claim applies here.

| Shape | Publishers | Subscribers | Payload bytes | Window | Warmup publishes | Measured publishes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| serial | 1 | 1 | 256 | 1 | 1000 | 10000 |
| publishers-32 | 32 | 1 | 64 | 4 | 256 | 4096 |
| fanout-32 | 1 | 32 | 64 | 4 | 256 | 2048 |
| balanced-32x32 | 32 | 32 | 64 | 4 | 256 | 3200 |
| large-payload | 4 | 4 | 4096 | 16 | 128 | 2048 |

Cost deltas below are candidate median / baseline median - 1. Negative is
lower cost; positive is higher cost. The initial separate-query matrix has
eight serial pairs and two pairs per control. Both subsequent matrices have
eight pairs per shape.

| Initial candidate | Serial instruction cost | Serial cycle cost | Serial elapsed cost | Decision |
| --- | ---: | ---: | ---: | --- |
| separate status lookup | -0.923% | -0.123% | +0.180% | rejected |
| ACK status | -1.017% | +0.971% | +0.698% | rejected |
| combined route lookup | -0.931% | -0.647% | +0.213% | rejected |

The separate-query controls were mixed; the balanced control had a large
cycle regression in only two pairs. The ACK variant's larger matrix again
lowered serial instructions while increasing cycles; fanout elapsed regressed
in 8/8 pairs and its median cycles rose 2.76%. It was not retained.

The combined route lookup initially lowered serial cycles in 7/8 pairs.
A same-binary followup added sixteen serial pairs, eight publisher-control
pairs and sixteen large-payload pairs. This resolved the serial benefit and
the small control concerns without building another executable. Pooled rows
combine those identical workloads and binary identities from the two captures.

| Combined lookup pooled shape | Pairs | Instruction cost | Cycle cost | Elapsed cost | p50 cost | p99 cost | Lower-cycle pairs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| serial | 24 | -0.917% | -0.365% | +0.213% | +0.232% | +0.252% | 18/24 |
| publishers-32 | 16 | +0.119% | -0.419% | +0.458% | +0.553% | +0.722% | 8/16 |
| large-payload | 24 | -0.004% | +0.500% | +0.103% | -0.169% | +0.923% | 7/24 |

Serial instructions improve in 24/24 pairs, but elapsed remains neutral.
Large-payload cycles regress in 17/24 pairs: +0.50% by pooled medians and
+0.56% by the median paired ratio. The separate followup repeats the cycle
cost at +0.45% with 11/16 regressions. This small repeated control cost, with
no established delivery-time benefit, is insufficient to retain a new hot-path
branch and public helper. Broader broker scheduling, durable QoS 2 and RSS gaps
remain open.

The final combined-query snapshot passed 133 focused checks, 479 related
Session/broker checks, 20 package checks and all 1825 source-locked Mosquitto
packet scenarios. The ACK snapshot passed 139 focused checks, 482 related
checks, the package gate, those same packet scenarios and ten Will lifecycle
cases; the first snapshot passed its 132/478/20 checks and the ten Will cases.
Focused counts overlap their related module groups. Passing these gates did
not establish a performance benefit.

[All 272 complete broker runs](evidence/mqtt_empty_session/2026-10-28-broker-ab.json)
retain raw counters, counter run percentages, exact workload records, individual
samples, paired summaries, clean source/executable identities and validation
counts. Baseline c0f04bfb has identical runtime and build source to main
07e6d4b5. The rejected snapshots are 19870610, 52978248 and 07246e5a.
Complete patches against that baseline are included as
[separate status lookup](evidence/mqtt_empty_session/separate-status-lookup.patch),
[ACK status](evidence/mqtt_empty_session/ack-status.patch) and
[combined route lookup](evidence/mqtt_empty_session/combined-route-lookup.patch),
so the rejected source remains reviewable without an experimental branch.
