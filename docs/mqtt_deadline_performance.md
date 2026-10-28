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
