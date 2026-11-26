# Complete HTTP/3 pacing-clock delegation

Thirteen dispatcher and endpoint-server fixtures replace backend userdata
while retaining its callbacks. Their clock wrappers also return `Canceled`
for every sleep, including deadline waits. These are source contract findings;
this qualification does not claim thirteen independent crash reproductions.

The fixtures now use the shared native clock helper. Every inherited callback
receives the actual delegate userdata and token owner. Awake time is atomic;
each original clock transition calls `setNow`, notifying an entered deadline
wait. Deadline waits observe actual backend cancellation. Duration sleeps
delegate to the backend and retain the original zero pacing-sleep assertions.
Other clocks and backend timeouts use the helper's existing clock translation.

All original clock epochs and transitions remain. The cases preserve exact
control-frame payloads, packet numbers, send offsets, stream/push admission,
HEADERS/body/FIN progress, retry state, QPACK feedback and receive credit.
The large client control-frame retry case moves to
`src/http3/runtime/endpoint_dispatcher/control_retry_tests.zig`; its test name
and public runtime imports remain intact.

Each fixture runs on supported POSIX Threaded datagram I/O with zero async
capacity and the application backend with one executor. Windows uses the
supported application datagram path. Observer I/O is restored before native
clock, session and endpoint cleanup.

[validation.json](validation.json) records current and immutable original
source hashes, the assertion/clock-transition comparison, formatting, scoped
native execution and Windows compilation. All original 35 test names and 342
assertion statements remain, including the selected 13 names and 201 assertions
after atomic-read and pacing-counter normalization. The final source passes
80 scoped native cases and Windows 8/8 compilation. Compilation remains distinct from
native Windows execution. Complete/native delivered qualification, remaining
contexts, owner structure, fairness and workload performance remain open.

The preceding `7a2e6bcc` complete run ends at its unchanged 28-minute budget,
with the last emitted `6355/7490` gRPC TLS health Watch result marked OK.
Zig 0.16's standard terminal runner prints OK before deinitializing the test's
`std.testing.io`, so that last visible result alone does not qualify cleanup
or identify the next test as stalled. The unchanged `65b9c7fc` macOS scope
containing health Watch and the next TLS reflection case completes all 75
artifact tests and exits zero, including runner cleanup. The log hash is
recorded separately; this does not reproduce or causally resolve the Linux
complete-gate timeout. Existing CI commands, budgets and dependency pins
remain unchanged.
