# MQTT Will process lifecycle parity

The configured broker gate binds Mosquitto's `07-will-qos0.py` and
`07-will-per-listener.py` to eight real broker-process scenarios: MQTT 3.1.1
and MQTT 5, each with both Clean Session/Clean Start values, under global and
`per_listener_settings` policy. MQTT 5 sources retain the upstream 60-second
Session Expiry while their default zero Will Delay publishes immediately after
the network connection closes without DISCONNECT.

Every scenario checks the complete QoS 0 Will packet, then keeps its observer
connected through a fresh clean connection with the source Client Identifier.
PINGREQ/PINGRESP barriers reject duplicate or trailing Wills after the original
delivery and after source Session cleanup. The source frame, payload and Session
flags are checked through protocol-shaped wire helpers; a successful CONNACK
must have the expected Session Present bit.

Two additional MQTT 5 scenarios change an ACL file through SIGHUP, once for a
global ACL and once for a listener-local ACL. Both Will sources stay connected
across the policy change. A DISCONNECT with reason 0x04 requests each registered
retained Will. The current ACL allows one and denies the other. The gate proves:

- the allowed Will is delivered exactly and remains in retained storage after
  source transport teardown;
- the denied Will neither routes nor creates a retained message;
- restoring the earlier allow policy cannot resurrect the denied Will;
- clean Session replacement cannot replay the consumed denied Will.

This matches Mosquitto's publication-time write ACL and unconditional Will
cleanup. The broker's existing callback lifetime rule is preserved: borrowed
listener Will callbacks run at CONNECT admission, while the broker-wide Will
callback uses owned source Client Identifier, username and listener identity
when publication becomes due. The production configuration adapter selects the
current source listener policy through that identity.

Run the focused gate with:

```sh
zig build interop-mqtt-will-lifecycle -Doptimize=ReleaseFast --summary all -- --mosquitto-test-root="$HOME/Work/mosquitto/test"
```

It is also included in `interop-mqtt-broker-config`. The configured broker's
source verifier now locks 36 upstream process files and rejects missing or
changed source bytes. Will fingerprints live in
[`will_sources.py`](../tools/interop/mqtt_scenarios/will_sources.py); the scenario
implementation lives in
[`mqtt_scenarios/will_lifecycle.py`](../tools/interop/mqtt_scenarios/will_lifecycle.py).
The [delayed Will gate](mqtt_will_delay.md) now adds nine upstream timing/Session
scenarios and three supplemental cause/ownership checks. The wire-vector gate's
separate 294 curated scenarios are unaffected by this process
coverage expansion. Other upstream plugin, process and configuration behaviors
still require their own parity evidence.
