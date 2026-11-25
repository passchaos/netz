# Native protocol CI failure diagnostics

Run 45693092361 at b4ccfa3e passed native Linux protocol and client CA reload
regressions. Native Windows protocol verification failed, but public annotations
retained process/build exit messages rather than the first specific error. The
complete job failed with exit 137 after exactly 28 minutes, matching the existing
command limit; its last visible phase was WebSocket send-shape validation. This
evidence does not establish an allocator or protocol root cause.

The native protocol step now runs the same layout, dispatcher-rejection and
endpoint-reconnect filters serially with separate logs. It retains every case's
failure and continues the remaining diagnostics before returning a nonzero
status. The five-minute step limit, complete gate limit and dependency pins stay
unchanged. Scoped/default Zig error logs such as `[tls] (err):` and `error(tls):`
are annotated with their preceding test name even when individual test results
say OK. Nine parser cases and workflow shell syntax passed.

This change prepares actionable evidence for the next native run. It does not
claim that the Windows failure or complete-gate termination has been resolved.
