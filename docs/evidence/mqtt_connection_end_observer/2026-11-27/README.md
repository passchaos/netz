# Listener connection-end observation

Base: `087543755d38614f04110af92f362ebfd0dd07d1`. This feature adds an optional
connection-end observer to the continuous listener supervisor. It reports
raw reader and delivery-writer errors, graceful/administrative disconnect
state and whether managed Keep Alive was claimed expired. The event's Client
ID is borrowed for the callback. Callers copy it when retained.

Observation runs before destruction, outside broker locks, and independently
of the existing error observer and stop policy. The normal filtering of
Timeout, ConnectionResetByPeer and other transport-close errors is unchanged.
Configured example diagnostics use the existing opt-in
`NETZ_MQTT_CONFIG_TRACE_ERRORS=1`; ordinary operation emits no new trace.

The native scope passes 73 tests. The added real-TCP case closes a peer,
checks its raw end error and copied Client ID, and admits a healthy subsequent
client under connection-error policy `stop`. It then checks graceful
DISCONNECT and exactly two observations while the error observer remains at
zero. Calling broker stats from the callback verifies that no state lock is
held. Existing shared-writer retirement precedence remains covered.

Selected Windows compilation passes 8/8 and the configured broker builds
9/9. The original MQTT/capath/WSS liveness sequence passes on macOS immediately
before its first SIGHUP. This probe intercepts that signal to stop at the
precondition; it does not qualify full Linux CA reload or its failure cause.
[`validation.json`](validation.json) keeps the separate checkpoints and binary
identity. Original Python socket deadlines, assertions and CI budgets remain.

The preceding Linux CI reproduces a BrokenPipe while reading old MQTT
PINGRESP before SIGHUP, at age 0.160 seconds. Its broker output contains only
expected negative-certificate accept errors. That gap motivated the new
connection-end observation; it does not establish a TLS/CA/backend cause.
The preceding attempt and exact annotations remain in `prior_ci.json` and
`prior_linux_annotations.json`. Linux causal qualification and full HTTP-family
acceptance remain active.
