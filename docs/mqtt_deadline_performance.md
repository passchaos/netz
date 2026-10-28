# MQTT deadline Session delivery performance

`bench-mqtt-deadline` exercises the owning reconnect client's real
`stagePublish -> flushPendingWithDeadline -> pollWithDeadline` path over one
persistent TCP connection with one outstanding QoS 1 or QoS 2 message. Session
staging, payload ownership, deadline output, acknowledgement parsing and Session
completion are inside each measured delivery. Initial CONNECT and warmup are
outside timing. The source payload allocation and benchmark peer setup are also
outside timing; both endpoints use the native zio std.Io backend.

The peer compares the complete decoded topic and payload, QoS, Packet Identifier,
DUP/RETAIN flags and the negotiated Topic Alias property. QoS 2 requires the
matching PUBREL and terminal PUBCOMP. The client checks each retired Session ID
and verifies empty queued/inflight state after measurement. A graceful
DISCONNECT and a joined successful peer task are required before timing records
are emitted. Result and peer-completion records retain the MQTT version, alias
policy, QoS, counts and actual Zig build mode.

```sh
zig build bench-mqtt-deadline -Doptimize=ReleaseFast -- --protocol=5 --qos=1 --payload=512 --warmup=100 --iterations=5000
python3 tools/interop/mqtt_deadline_bench/check.py run.log --require-release-fast
zig build test-mqtt-deadline-benchmark
```

`--protocol=4` covers MQTT 3.1.1; MQTT 5 enables automatic Topic Alias by default
and `--no-topic-alias` provides its explicit control. `--qos=2` measures the full
four-packet QoS 2 exchange. The peer and verifier reject partial message/ACK
counts, a missing PUBREL, nonempty Session state, inconsistent elapsed/mean
values and invalid profiles. Debug output is useful for functionality checks;
the verifier's `--require-release-fast` mode excludes it from timing evidence.

This workload measures steady delivery through the reconnect client's deadline
flush. Actual network loss and retransmission belong to separate lifecycle and
interop checks. It does not substitute for the broker fanout benchmark, whose
ordinary send path does not call this deadline writer. Performance claims need
clean source/executable fingerprints and multiple alternating runs on a fixed
CPU, with complete message and peer validation in every run.


## Matching native TCP writes

The TCP packet-parts deadline writer uses the existing joined native vectored
socket path when its std.Io matches the currently mounted zio task. It retains
one awake deadline and waits for cancellation to finish before borrowed prefix
or Session payload storage can be reused. Wrapped/foreign/blocking I/O contexts,
TLS and WebSocket retain the full logical-write wrapper. Error propagation and
MQTT transport retirement after uncertain output are preserved.

Real TCP regressions force a short committed prefix and blocked output, then
interrupt by timeout or by cancellation after the peer receives a physical
byte. Caller storage is mutated after return and the peer drains only original
packet bytes. Separate MQTT 3.1.1/5 QoS 1/2 tests retire the failed connection,
retain the Session-owned payload, mutate the caller's source, reconnect to a
preserved Session, verify complete DUP replay with the same Packet Identifier,
and finish the final PUBACK/PUBCOMP with empty queued/inflight state.

Clean 1762e26e was compared with clean aacec183. Both ReleaseFast binaries used
CPU 0, 100 warmup and 5000 measured deliveries, five alternating samples, a
single connection/window and telemetry disabled. Every run required complete
message, acknowledgement and peer validation. Native small-message QoS 1
medians improve by 1.09-1.11x; QoS 2 improves by 1.04-1.08x. The two large-message
medians improve by about 1%, so this change does not close the broader broker
or durable-session throughput gaps.

| MQTT | QoS | Topic Alias | Payload bytes | Wrapper us/delivery | Native us/delivery | Speedup |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| 5 | 1 | enabled | 0 | 11.08 | 9.96 | 1.113x |
| 5 | 1 | enabled | 512 | 12.30 | 11.20 | 1.098x |
| 5 | 1 | enabled | 4096 | 13.29 | 12.16 | 1.093x |
| 5 | 1 | enabled | 262144 | 249.30 | 246.20 | 1.013x |
| 5 | 2 | enabled | 0 | 20.79 | 19.19 | 1.083x |
| 5 | 2 | enabled | 512 | 21.53 | 20.57 | 1.047x |
| 5 | 2 | enabled | 4096 | 22.49 | 21.54 | 1.044x |
| 5 | 2 | enabled | 262144 | 259.81 | 257.12 | 1.010x |
| 3.1.1 | 1 | disabled | 512 | 12.24 | 11.16 | 1.096x |
| 3.1.1 | 1 | disabled | 4096 | 13.18 | 12.07 | 1.092x |
| 3.1.1 | 2 | disabled | 512 | 21.42 | 20.47 | 1.046x |
| 3.1.1 | 2 | disabled | 4096 | 22.37 | 21.38 | 1.046x |
| 5 | 1 | disabled | 512 | 12.19 | 11.10 | 1.098x |
| 5 | 1 | disabled | 4096 | 13.19 | 12.10 | 1.090x |
| 5 | 2 | disabled | 512 | 21.46 | 20.49 | 1.048x |
| 5 | 2 | disabled | 4096 | 22.46 | 21.39 | 1.050x |

All fourteen small/control groups and the large QoS 1 group improved in every paired sample; the large
QoS 2 group improved in four of five. The raw baseline small-message samples
include two slower outliers; the five-sample medians and all source/executable
fingerprints are retained in
[the complete 160 result/peer-completion pairs](evidence/mqtt_deadline/2026-10-28-native-tcp.json).
These are native-versus-native client delivery results, separate from the
independent production broker comparison against Mosquitto.
