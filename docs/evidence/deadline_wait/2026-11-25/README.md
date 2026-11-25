# Strict absolute timer waits — 2026-11-25

Native Windows CI at `1778a5af` reports `OutOfMemory` from the existing H3
late-resolver admission fixture, which expected `HandshakeTimeout`. That fixture
returned its addresses after one `Clock.Timestamp.wait`. Native Threaded's
Windows interval conversion truncates nanoseconds to 100-ns units, and its sleep
returns after that native timer completes; one sleep completion is therefore
insufficient to prove that the original clock timestamp has arrived.

Generic timed reads already rechecked their deadline in a loop. TCP, connection
competition, system resolution, acceptance and timed writes each had a one-shot
timer function. The shared `deadline.waitUntil` now loops until the original
timestamp is no longer in the future, propagating cancellation from every sleep.
Those consumers use the same helper, and the H3 late-result fixture establishes
actual expiry through it before arming its allocation fault. Deadline values and
phase timeout errors retain their existing composition.

The deterministic I/O probe completes its first sleep with time still before the
deadline. It either reaches the original timestamp on the second sleep or
returns cancellation there. Both old expectations fail: 7/9 baseline tests pass.
After the change, both cases verify two sleep calls using the identical absolute
timestamp, and preserve `Canceled` from the second wait.

The next native Windows run passes the H3 expiry fixture and exposes the legacy
`TCP connect deadline includes hostname resolution` success test's one-second
budget. It listens only on IPv4 and resolves `localhost`, whose first Windows
candidate can be IPv6. The confirmed native refusal delay is longer than that
budget, so this success fixture uses five seconds on Windows and retains one
second elsewhere. Its resolution/connect path and production deadlines remain
the same.

Scoped overlap covers stream reads and writes, listener acceptance, TCP
connection/lookup deadlines, system DNS, connection result pooling, H3
handshakes/zero RTT and gRPC competition. The three macOS skips are the same
Linux-only abortive TCP reset probe imported by the three protocol roots.

| Verification | Result | Evidence |
| --- | --- | --- |
| Native Windows expired-result failure | `OutOfMemory` at `1778a5af` | [native-windows-before.json](native-windows-before.json) |
| Deterministic early wake/cancellation baseline | 7/9 passed; both new expectations fail | [before.Debug.log](before.Debug.log) |
| Shared strict wait and relevant transport overlap | 291 passed, 3 platform skips | [Debug.log](Debug.log) |
| Relevant regression compilation for Windows | Compiled | [windows.compile.log](windows.compile.log) |
| Native Windows localhost success-fixture budget follow-up | `Timeout` under the original one-second budget | [native-windows-hostname-before.json](native-windows-hostname-before.json) |
| Focused hostname budget/deadline wait follow-up on the local host | 9/9 passed | [hostname-budget.Debug.log](hostname-budget.Debug.log) |
| Focused hostname follow-up compilation for Windows | Compiled | [hostname-budget.windows.compile.log](hostname-budget.windows.compile.log) |
