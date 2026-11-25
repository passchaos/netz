# CA bundle lock admission — 2026-11-25

At `5b83ec15`, verified TCP TLS initialization includes system-root loading in
its handshake budget, but both TLS client implementations acquire a
caller-owned CA bundle using `RwLock.lockShared` without that deadline. When a
writer keeps the bundle locked, a one-second caller deadline or
`handshake_timeout` does not return. The original regressions fail after a
three-second observation budget while the writer is still held (8/10 pass).

The shared `internal/timed_rwlock.zig` helper uses the original awake deadline
for reader admission. It first tries the public shared-lock method; interrupted
successful admission releases that reader. Contention waits on the read/write
lock's existing mutex through `internal/timed_mutex.zig`, releases that mutex,
and retries normal read admission. It does not install reader/writer bits
itself, allocate storage, or create background tasks. Unbounded calls retain
the existing cancelable shared-lock path.

Both TLS 1.3 and versioned TLS 1.2/1.3 verified constructors use this helper.
The admitted shared lock remains held for the complete certificate-verification
phase, with existing scope cleanup releasing it afterward. HTTP/H2 and WSS
transports use the same TLS constructors.

Tests keep a real writer held until the timed TLS operation returns. Separate
deterministic checks expire or cancel immediately after fast-path admission
and require a subsequent writer to acquire the lock. A two-reader fixture
observes both readers waiting, cancels one, releases the writer and requires
the other to finish; its I/O backend rejects additional concurrency admission
to verify the helper's existing futex path.

Commands, results and the original failure log are recorded beside this file.

| Verification | Result | Evidence |
| --- | --- | --- |
| Original held-writer deadline regressions | 8/10 passed; both timed cases fail | [before.Debug.log](before.Debug.log) |
| Read admission/rollback/cancel handoff, TLS budgets, caller-CA HTTP1 persistence, HTTP2 TLS and WSS overlap | 150/150 passed | [Debug.log](Debug.log) |
| CA lock regressions for Windows | Compiled | [windows.compile.log](windows.compile.log) |
| Native Linux/Windows trust startup, CA lock and CA-file authentication | Passed at `1ff6cb48` | [native-platforms.json](native-platforms.json) |

[Local metadata](local-validation.json) records the completed checks. The same
CA lock regressions are selected by the native Linux and Windows trust-startup
CI gate.

[Run 45553631918](https://github.com/passchaos/netz/actions/runs/45553631918)
completed the native Linux job `139000720705` and Windows job `139000720940`
successfully. The trust-startup gate selects system-root loading guards,
configured/caller-owned CA-file authentication, and the read-lock deadline and
cancel/ownership regressions. Both macOS compilation jobs and the portable
Linux/Windows compilation jobs also passed.
