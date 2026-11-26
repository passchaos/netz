# Typed construction of custom I/O observers

The follow-up survey inspects 18 custom-send VTable installations individually.
Ten retain the delegate's original userdata, so their inherited callbacks
receive the backend context they expect. Eight instead pass a local observer
while inheriting most backend callbacks. These eight share the context error
exposed by the earlier required-flow deadline-task GP; their classification
comes from source inspection, not eight separate failing native baselines.

`forwarded_io.observer` now constructs an immutable table with static lifetime
for a context containing `delegate: std.Io`. Every callback uses the actual
delegate's userdata and token ownership, except explicitly typed overrides.
The context and its delegate remain borrowed and must outlive all operations
and tasks using the I/O. Observers with clock remapping retain the existing
`table` entry and its explicit timeout mapper.

All eight incorrect installations use this constructor. The previously
repaired required-flow observer also uses it, removing its mutable table and
repeated forwarding methods. Pure Batch delegate methods are removed from
two other observers. Three sleep counters now call the real delegate instead
of returning a no-op or fabricated cancellation; all original zero-sleep
assertions remain.

The nine changed files retain their original test names and 287 assertion
statements. Scoped validation covers H3 request/response failure ownership,
malformed CONNECT and HEADERS, endpoint rejection timers and healthy siblings,
ALPN cancellation retry, fatal serve errors and required-flow acceptance.
The required-flow cases exercise POSIX Threaded with zero async capacity and
the application backend with one executor. Windows cross-compilation remains
distinct from native execution.

This constructor removes per-observer mutable table ownership. No latency or
throughput improvement is claimed without measurements. Existing CI budgets,
commands and pins remain, and complete/native qualification, fairness and
workload performance remain part of the active HTTP-family goal.

[validation.json](validation.json) records the inspected contexts, current
source hashes and exact check state. Formatting and native execution have
passed: the two filtered artifacts report 150 and 85 passes, including shared
imported tests. Windows compilation passes all eleven build steps for the two
artifacts. Delivered Linux/Windows and complete qualification remain open.

Prior run 45863309674 is a separate checkpoint: Linux protocol and send-deadline
steps pass, while client CA reload still fails before SIGHUP at 158 ms.
Complete CI now reports a GP at 4830/7490, `WebTransport endpoint control and
datagram sends do not wait for pacing`, in another inherited clock observer.
That clock/wait fixture and the Windows five-minute protocol timeout remain
follow-ups; this source batch does not qualify them.
