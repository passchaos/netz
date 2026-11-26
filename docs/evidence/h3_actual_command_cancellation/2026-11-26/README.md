# Actual H3 command cancellation and shared lifetime rules

The delivered H3 owner loop returned a successful command after its caller's
actual canceled wait, consuming that cancellation notification. The old
completion tests returned fabricated `Canceled` and could not qualify this
backend state. The new baseline uses an actual Future cancellation and a
separate uncanceled owner that emits a protected response before the canceled
wait returns. The peer receives status 200 and the exact `committed` body,
but the caller's next cancellation point returns void instead of `Canceled`.
That baseline fails 1 of 65 scoped cases on the Threaded backend.

H2 and H3 now share the same internal borrowed-command submission and drain
boundary. It validates deadline/cancellation admission, keeps the handler's
stack alive through an uncancelable release wait, reports fully committed
outcomes and rearms actual consumed cancellation on a successful result.
Each engine retains its own protocol dispatch, state and sole receive owner.
The existing H2 internal module path remains a thin entry to that common
implementation.

The original four H3 completion test names remain. Skipped timeout and both
cancellation cases use actual timers/Futures and protected request/response
packets. One deterministic timeout/completion interleaving keeps its synthetic
clock while no longer fabricating a cancellation result. An additional actual
timer case verifies that the owner rejects an expired queued response before
output. H2 and H3 use one fully forwarded probe, with owner dispatch gated
until the command wait is observed; the probe does not recursively acquire an
owner mutex or scan a concurrently changing queue.

[validation.json](validation.json) records final-source validation and limits.
Supported datagram backends are preserved; H2 TCP/futex checks retain Windows
Threaded and application-backend coverage. Windows compilation is distinct
from native execution. The continuous HTTP-family goal remains active, with
native/complete qualification, slow-writer fairness and workload performance
still open.
