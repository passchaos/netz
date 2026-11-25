# Native protocol I/O follow-up — 2026-11-26

[Run 45674858707](https://github.com/passchaos/netz/actions/runs/45674858707)
passed the native Linux protocol regression step. The native Windows step
reported `ConcurrencyUnavailable` from Threaded's timed UDP receive and an
unmapped `CONNECTION_RESET` during the real TLS reconnect fixture. The shared
fixture runner now retains zero-async Threaded coverage on Linux/macOS and
exercises the application zio backend on every platform. Windows protocol
behavior remains covered by the supported application I/O backend; native
Windows verification is pending.

The reconnect fixture previously began the second server accept budget while
the client was still receiving/removing its old-generation handles. An explicit
start event now gives the second connection its original three-second budget
after that cleanup. No operation budget was enlarged. Client and peer failures
print their phase, so the next root-test EOF identifies the actual operation.
The local dual-backend scope passes 135 tests.

The Linux CA diagnostic now proves the old MQTT connection fails before
SIGHUP. Local plain and management-enabled controls, including a delay across
several management ticks, retain all old connections; no reload signal was
delivered in those macOS probes. The fixture now reports early-disconnect age,
broker exit code and available output. The Linux cause is still unproven; this
change does not claim to repair CA reload.

[Validation](validation.json) and the native failure records distinguish these
boundaries. Local Vail differs from the unchanged CI pin, so scoped macOS
results do not replace the next pinned native/full run. Dependency pins and
CI budgets are unchanged.
