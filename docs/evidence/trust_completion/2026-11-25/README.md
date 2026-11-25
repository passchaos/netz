# Trust result completion boundaries — 2026-11-25

At `1ff6cb48`, bounded system-root loading checks the operation budget after
both successful and failed work. Bundled-root and native-verifier setup checks
after success but directly classifies failures. A source that fails allocation
after expiration therefore reports `OutOfMemory` instead of `Timeout` or
`HandshakeTimeout`; a concurrent cancellation is also masked. Failed task
admission similarly returns `ConcurrencyUnavailable` without a budget check.

The baseline exercises actual bundled-root constructors with an allocator
that expires the original timestamp or queues cancellation when it returns
allocation failure. Budget-live controls require the original `OutOfMemory`.
Admission tests alter the same state inside the I/O concurrency callback.
Six regressions fail in the baseline (44/50 pass).

The shared `tls/trust_completion.zig` helper accepts owned trust results from
both synchronous and asynchronous sources. It checks completion before
classifying a failure or transferring a success, destroys rejected successful
values, and retains the original source error within a live budget. TCP TLS
and QUIC use this boundary for bundled roots and native verifiers; QUIC keeps
its handshake-specific timeout mapping. The asynchronous system-root worker
and receiving owner use the same helper. Watcher/load admission failure also
checks cancellation and the original deadline before returning.

The unbounded system-root path checks cancellation after a source failure,
matching its existing success checkpoint. No deadline is synthesized for that
path. Native Linux/Windows success evidence for the preceding root-loading,
CA-lock and positional-PEM work is recorded in
[the CA bundle lock record](../../ca_bundle_lock/2026-11-25/native-platforms.json).

Verification commands, original failures and completed results are recorded
beside this document.

| Verification | Result | Evidence |
| --- | --- | --- |
| Source/allocation and admission baseline | 44/50 passed; six late/canceled failures | [before.Debug.log](before.Debug.log) |
| Owned completion, resource cleanup, CA authentication, bundle/native availability, CA lock and TLS negotiation | 71/71 passed | [Debug.log](Debug.log) |
| Unified HTTP H3, H3 WebSocket and shared WebTransport constructors | 307/307 passed | [facades.Debug.log](facades.Debug.log) |
| Completion, root-load, CA-lock and CA-file fixtures for Windows | Compiled | [windows.compile.log](windows.compile.log) |
| Native Linux and Windows trust-startup completion regressions at `4f633cc8` | Gate passed | [native-gates.json](native-gates.json) |

[Local metadata](local-validation.json) records each completed exit status.
All Zig commands ran under the shared tree guard and used `-j1` for builds.

The native record covers the exact completed trust-startup steps. The Windows
step passed before its containing job was canceled; this record does not claim
that the entire Windows job or complete workflow succeeded.
