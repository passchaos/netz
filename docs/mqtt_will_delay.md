# MQTT delayed Will process lifecycle parity

`interop-mqtt-will-delay` runs twelve MQTT 5 scenarios through the configured
production TCP broker. Nine scenarios preserve the timing, Session and Will
parameters from seven source-locked Mosquitto process tests. Three additional
scenarios check non-zero-delay DISCONNECT reason 0x04, normal DISCONNECT
suppression and ownership of a different replacement Will payload.

| Mosquitto source | Variants | Required behavior |
| --- | --- | --- |
| `07-will-delay.py` | Clean Start 0 and 1 | Will Delay 3, Session Expiry 60; publish after the delay |
| `07-will-delay-session-expiry.py` | Will Delay 4, Session Expiry 2 | Publish when the Session expires and reconnect with Session Present 0 |
| `07-will-delay-session-expiry2.py` | Will Delay 2, Session Expiry 4 | Publish after the delay while retaining the Session for reconnect |
| `07-will-delay-session-expiry-0.py` | Will Delay 60, Session Expiry 0 | Publish immediately at Session end |
| `07-will-delay-reconnect.py` | Continue the Session without a new Will | Cancel the old Will through its original deadline and later Session cleanup |
| `07-will-delay-recover.py` | Clean Start 0 and 1 with a new Will | Session continuation cancels the old Will; Clean Start publishes it at Session end |
| `07-will-disconnect-with-will.py` | DISCONNECT reason 0x04 | Publish the registered Will when the Session ends |

The source Will QoS is preserved, including QoS 2 in the delay/expiry and
DISCONNECT cases, while each observer subscribes at QoS 0. Every expected
publication is checked as a complete MQTT packet: topic, payload, flags, QoS,
property boundary and absence of a forwarded Will Delay property. Explicit
PINGREQ/PINGRESP barriers reject trailing or duplicate Wills after delivery,
reconnect and Session cleanup.

The recovery cases also keep the replacement connected beyond the old Will
deadline, then close it without DISCONNECT and verify its newly scheduled Will.
A separate replacement-payload case distinguishes the old Will from the new
one. Session Present checks prove whether expiry removed the source Session or
whether publication left it available for continuation. A normal DISCONNECT
case observes the entire old deadline before cleanup, so cleanup cannot conceal
an incorrectly retained Will.

Source network loss uses TCP write-half shutdown without an MQTT DISCONNECT,
then observes the server's EOF before issuing the next CONNECT. This replaces
the upstream preparatory sleeps with an observable teardown boundary. Delays
and negative intervals use the monotonic clock; early publication, late
publication, any unexpected byte, and observer EOF fail the gate. Socket budgets
are restored after a negative interval. Small oracle regressions separately
verify that queued bytes and observer EOF cannot establish a quiet interval.
The upstream zero Session Expiry is encoded through the protocol's equivalent
default where the shared wire helper omits that zero property.

The three-second delay cases require delivery in `[2.0, 4.5)` seconds. The
two-second delay/expiry cases require `[1.0, 3.5)`, below the wrong later
four-second boundary. Immediate publication must arrive before two seconds.
Quiet replacement and suppression checks extend one second beyond the original
three-second deadline. These bounds are protocol lifecycle checks, not latency
benchmarks.

Run the focused gate with:

```sh
zig build interop-mqtt-will-delay -Doptimize=ReleaseFast --summary all -- --mosquitto-test-root="$HOME/Work/mosquitto/test"
```

It also runs inside `interop-mqtt-broker-config`. The focused target verifies
source fingerprints before starting a broker; missing and altered delayed-Will
sources were challenged independently and rejected before execution. The
configured broker's shared source catalog now contains 36 process files.
Will fingerprints live beside the scenarios in
[`will_sources.py`](../tools/interop/mqtt_scenarios/will_sources.py).

The gate emits one record for each scenario only after its packet, timing,
cleanup and broker-exit checks complete. The summary derives its nine upstream
and three supplemental counts from those records.
[The twelve completed ReleaseFast process records](evidence/mqtt_will_delay/2026-10-28-process.json)
retain source fingerprints, gate-input hashes, broker executable identity,
parameters and elapsed times. Current runtime behavior passed these checks;
this change adds production regression coverage. The independent
[immediate Will and publication-time ACL gate](mqtt_will_lifecycle.md) retains
its existing ten scenarios. Other upstream process and plugin behaviors remain
outside these two Will gates.
