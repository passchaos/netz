# Default H3 pool connection preparation — 2026-11-25

At `9bf05f19`, the exclusive pool's default connector generates connection IDs
before starting its configured `connect_timeout`. Origin, redirect, Alt-Svc,
Alt-Svc redirect and early-data fallback repeat that preparation separately.
Five deterministic regressions fail on the baseline (62/67 passes): each
enters entropy before a backend can reject its required timer admission.

The default connector now establishes one original connection budget at each
entry. Its prepared origin, redirect security, fresh IDs and route selection
live in `handshake_client_pool/default_connector.zig`. Early-data fallback
reuses that preparation and deadline. Both fresh IDs share one entropy request;
the enclosing operation retains the stack storage through joined completion.
ALPN arrays stay in the calling frame rather than escaping an option-builder's
temporary storage. Existing public default-connector and transport exports
retain their paths.

`internal/owned_result_deadline.zig` now owns the shared timer admission,
completion checks and unselected-result cleanup previously implemented in
trust loading. TLS trust completion and loading forward to that helper. A
successful result retains its deinit operation until the original budget and
cancellation state accept transfer. A late success is destroyed; a late
source error becomes the budget/cancellation result. The early-connected
container owns its client through the same zero-argument deinit contract.

Custom transports remain inside that owned operation and receive the remaining
relative timeout. Their timely failures retain the original error; a clock-
advanced callback cannot turn an expired connection budget into an unrelated
connection-refusal error. Tests also preserve origin-bound resumption and
client-identity isolation, ordinary connection reuse, actual CA handshakes,
typed 0-RTT and SOCKS5 Alt-Svc routing.

The prior source's native Linux and Windows trust-startup steps were canceled
at the portable job's 20-minute limit. This does not establish native test
success. [Cancellation evidence](prior-native-cancellation.json) retains exact
jobs and timestamps. Portable jobs now allow 30 minutes, and the native trust
gate streams its log through `tee` with `pipefail` so command failures remain
failures. The first final local check was interrupted by the shared guard's
swap-growth limit; [the interruption record](swap-interruption.guard.log)
retains that outcome. Guard limits and dependencies were unchanged.

[Local metadata](local-validation.json) records source hashes and final
results. All Zig commands ran under the shared tree guard with `-j1`.
Windows compilation remains distinct from native execution.

| Verification | Result | Evidence |
| --- | --- | --- |
| Default connector preparation baseline | 62/67 passed; five failures | [before.Debug.log](before.Debug.log) |
| Debug | 266/266 passed | [Debug.log](Debug.log) |
| ReleaseSafe | 266/266 passed | [ReleaseSafe.log](ReleaseSafe.log) |
| windows-compile | Compiled successfully | [windows-compile.log](windows-compile.log) |
