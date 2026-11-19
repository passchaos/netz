# netz vs rumqtt and Mosquitto MQTT parity audit

This audit records evidence for the MQTT portion of the netz improvement goal.
The source references are `~/Work/rumqtt` at `e886a78` and
`~/Work/mosquitto` at `5cd25465`. Rumqtt contains both a production broker
(`rumqttd`) and clients (`rumqttc`); Mosquitto supplies a mature broker,
persistence format, and conformance suite. Feature, internal microbenchmark,
and same-client broker results are kept separate.

The [empty Session flush experiment](mqtt_empty_session_performance.md)
records three rejected broker candidates and 272 complete fixed-driver runs.
The smallest combined-query candidate repeated a serial instruction reduction,
but delivery time remained neutral and the large-payload CPU control regressed.
The production Session/ACK paths retain their baseline behavior.

## Detailed sections

| Document | Contents |
| --- | --- |
| [feature-matrix.md](mqtt/feature-matrix.md) | Feature comparison, protocol interoperability, capability enforcement, Enhanced Authentication, Keep Alive |
| [bridges.md](mqtt/bridges.md) | Inbound/outbound broker bridges and Server Reference redirects |
| [persistence.md](mqtt/persistence.md) | Snapshots, commit log, retained store, Session store, Will Delay |
| [qos.md](mqtt/qos.md) | QoS 1/2 matrices, live QoS 2, shared router, serial profile |
| [live.md](mqtt/live.md) | Live retained, Will lifecycle, persistent subscription Sessions |
| [transports.md](mqtt/transports.md) | MQTT-over-WebSocket, native TLS, zio timed-I/O fast path |
| [remaining.md](mqtt/remaining.md) | Remaining work before broad superiority |
