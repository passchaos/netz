# Observed H3 handshake cancellation — 2026-11-25

The native Linux H3 total-deadline regression at `5662a658` returns the expected
`HandshakeTimeout`, then fails while reading an Initial datagram from a silent
peer. The fixture required both crypto/handshake startups to emit Initials
before a 100-ms overall deadline. A valid cancellation during startup can leave
one candidate without an emitted Initial, making that post-timeout assertion
depend on startup scheduling rather than task cleanup.

The short overall-budget check retains 100 ms and the existing bounded return
expectation. A separate real cancellation check observes both target Initials
before canceling the owning connect task. It uses the original handshake group
and crypto configuration, gives startup an independent five-second watchdog,
and bounds each observation wait to two seconds. Both packets must contain at
least 1,200 bytes; cancellation must return `Canceled` after the worker joins.

The large `HandshakeClient` result stays in a stable worker-owned slot, while
the Future returns only completion. Both normal and failed fixture paths join
the worker and dispose of any unexpected successful client before peer/runtime
teardown. One zio runtime is created per fixture, including native Windows.

The two tests live in `client/happy_eyeballs/deadline_tests.zig`, reducing the
larger Happy Eyeballs fixture file while preserving its discovery root. Both
are selected by the native H3 CI step.

| Verification | Result | Evidence |
| --- | --- | --- |
| Native Linux startup/datagram assertion failure | Timeout while reading a post-deadline Initial | [native-linux-before.json](native-linux-before.json) |
| Short budget and observed two-handshake cancellation | 58/58 passed | [Debug.log](Debug.log) |
| Both regressions for Windows | Compiled | [windows.compile.log](windows.compile.log) |
