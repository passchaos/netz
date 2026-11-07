# MQTT delivery and disconnect validation

Coalesced delivery retains one Subscription Identifier occurrence per matching
filter, including equal values, following MQTT-3.3.4-4. Broker-attached normal
DISCONNECT releases physical shutdown only after its persistence decision;
writer quiescence precedes socket/storage retirement.

| Gate | Result | Evidence |
| --- | --- | --- |
| Focused identifier and disconnect Debug | 178/178 tests | `identifiers-disconnect.Debug.log` |
| Terminal, Will, CONNACK, takeover, journal and identifier ReleaseSafe | 310/310 tests | `termination-durability.ReleaseSafe.log` |
| Independent raw MQTT 5 peer | 5/5 scenarios | `wire.Debug.json` |
| Existing journal SIGKILL recovery | Passed all reported flows | `crash-recovery.Debug.log` |

Counts are Zig's reported focused `test-lib` counts and include imported
dependency tests. `gates.json` stores commands, exit codes, summaries and source
manifests. The independent broker executable is SHA256
`612bb86f2d567864fefe6ad9e194b19457698edc02e25f42fd8a3f640e5bc6e1`;
the raw-peer report separately hashes the launcher, helper and fixture sources.

The peer sends explicit CONNECT/SUBSCRIBE/PUBLISH/PUBACK/PING bytes and parses
received identifier occurrences independently. Transient and durable QoS 0/1
cases each receive one coalesced packet carrying `(7, 7, 7)`. Four journal
generations and three SIGKILLs verify stable Packet Identifier 1, DUP replay and
durable ACK removal. Optional reference mode permits valid per-filter copies.

Native disconnect tests intercept the actual `netShutdown` call and inspect
synced journal state there. They check successful clean-Session Will removal,
one-shot/repeated sync failure with original-error preservation, and a held
writer retaining its connection pointer after shutdown. The existing crash
runner also verifies normal-DISCONNECT Will cancellation, delayed Wills,
Session expiry, retained state and QoS 1/2 recovery.

Initial raw-peer development encountered a launcher restore-argument mismatch,
then one five-second EOF timeout. The argument was corrected; the EOF timeout
did not reproduce. One standalone run, three dispatcher repeats and the fresh
parent run passed. Isolated probes with publisher absent, fully MQTT CONNECTed,
and TCP connected without CONNECT each produced EOF within nine milliseconds.
The original logs, repeated results and probe process states remain under
`initial-probes/`; this evidence does not assign a source cause to that timeout.

Reproduce the independent cases with:

```sh
zig build interop-mqtt-mosquitto-vectors --summary all -- \
  --only-equal-subscription-identifiers
```

The existing crash runner accepts the standalone prebuilt broker:

```sh
zig build build-mqtt-vector-broker --summary all
python3 tools/interop/mqtt_commit_log.py zig-out/bin/netz-mqtt-vector-broker
```
