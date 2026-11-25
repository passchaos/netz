# Protocol CI regression follow-up — 2026-11-26

[Run 45661507859](https://github.com/passchaos/netz/actions/runs/45661507859)
on `a4a316ef` passed preflight and every platform job, but the complete gate
failed. [The captured annotations](ci-failures.json) identify three root-test
failures and the MQTT client-CA-reload peer failure. The complete process also
ended with code 137 under its existing budget; the annotations do not prove its
last active runtime operation.

The H2 layout failure expected 2,080 bytes but observed 2,240. A scoped size
probe confirms Limits now occupies 544 bytes while the mutable owner remains
1,696 bytes. The test now checks the original non-policy budget, keeping its
optional pointer/slot budgets separate. ReleaseFast retains the 1,616-byte
owner budget and has a 2,160-byte complete Connection.

The standalone WebTransport dispatcher test reached the expected terminal
Capsule error, then invoked a raw DATAGRAM receiver while still bound to the
dispatcher. The fixture now checks `InvalidDispatcherState` at that boundary,
unregisters and returns receive ownership, then runs the common terminal
association matrix. Production owner-admission ordering is preserved.

The HTTP2 reconnect fixture now admits the peer and both concurrent CONNECTs
with `Io.concurrent`. Its actual TLS/Session-generation/reuse test runs with
zero opportunistic async capacity. The original case passed the local before
scope, so the Linux CI `UnexpectedEof` has not been reproduced locally. The next
native protocol scopes remain required verification of that failure.

[Scoped validation](validation.json) records 146 WebTransport and 38 H2 tests
in Debug, plus 28 H2 layout-scope tests in ReleaseFast. [The concise transcript](scoped-tests.log)
retains both reproduced failures and successful checks. Local Vail differs
from the unchanged CI pin; these macOS results do not replace pinned native or
complete acceptance.

The configured broker's reload signal implementation is currently Linux-only.
The peer now supports `--only-client-ca-reload`, establishes old-connection
liveness immediately before SIGHUP, and labels retained-connection EOFs with
the phase, age and broker state. A bounded native Linux CI step runs that
specific case, while native Linux/Windows protocol scopes cover the three
affected root tests. The CA-reload failure is still under investigation; this
change does not claim to repair it. Dependency pins and the complete 30-minute
job/28-minute command budgets are unchanged.
