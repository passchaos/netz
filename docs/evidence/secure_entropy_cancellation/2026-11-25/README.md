# Secure entropy cancellation — 2026-11-25

The native Linux H3 startup deadline regression at `81ea421c` aborted in the
pinned zio runtime's `common.blockInPlaceImpl`. `waitForIo` checks an already
pending task cancellation before submitting the work, but the blocking wrapper
uses `catch unreachable` for that error. Secure random generation uses this
wrapper. A deadline can cancel a handshake while startup is still obtaining
key material or connection identifiers.

Netz now routes protocol entropy through `internal/secure_random.zig`. It
checks cancellation before starting, protects only the entropy operation until
the backend completes, restores the caller's protection, and checks cancellation
again before handing the bytes to the protocol. No allocation, entropy caching,
fallback PRNG, runtime change, or dependency change is introduced. A caller's
enclosing guard retains its pending cancellation. Entropy failures restore the
guard and leave any concurrent cancellation pending for the next checkpoint.
Cancellation of a running entropy operation is deferred until that operation
completes; network waits and the rest of the handshake remain cancelable.

The shared boundary covers TLS key material and nonces, QUIC identifiers,
challenges and reset packets, H3 connectors, WebSocket handshake nonces and
frame masks, and WebTransport endpoint creation. The exclusive H3 default
pool connectors also propagate `Canceled` and `EntropyUnavailable` instead of
converting both to `Unexpected`, including redirects and alternate services.

The deterministic tests exercise cancellation before entry, inside a protected
backend call, success/error guard restoration, and an enclosing guard. A real
zio test pauses immediately before entropy offload, cancels the task while the
gate is closed, then releases it. It must join and return `Canceled` without
panicking. The existing 100-ms owning H3 deadline and the test that observes
both Initials before cancellation remain selected.

| Verification | Result | Evidence |
| --- | --- | --- |
| Deterministic boundary checks before the fix | Three regressions fail; 20/23 pass | [before.Debug.log](before.Debug.log) |
| Native Linux owning H3 deadline before the fix | ABRT in `blockInPlaceImpl` | [native-linux-before.json](native-linux-before.json) |
| H3 entropy, default connectors, total deadline and observed cancellation | Passed | [Debug.log](Debug.log) |
| TLS, QUIC, H1/H2/H3 masking and WebTransport handshake overlap | Passed | [overlap.Debug.log](overlap.Debug.log) |
| Selected H3, TLS, WebSocket and WebTransport regressions for Windows | Compiled | [windows.compile.log](windows.compile.log) |
| Unified HTTP H3/real interface binding and shared WebTransport constructors | 215/215 passed | [constructors.Debug.log](constructors.Debug.log) |
| Native Linux and Windows H3 entropy/startup/cancellation and acquisition regressions | Passed at `bef71120` | [native-platforms.json](native-platforms.json) |
| Native Linux interface binding and native Windows transport overlap | Passed at `bef71120` | [native-platforms.json](native-platforms.json) |
| Linux ARM64/x86-64, Windows x86-64 and macOS ARM64/x86-64 compilation | Passed at `bef71120` | [native-platforms.json](native-platforms.json) |

[Local validation metadata](local-validation.json) records zero exit status for
each completed check. Commands are in the logs; Zig ran under the shared tree
guard, serially with `-j1`.

The native record covers the portable and macOS jobs from
[run 45543653123](https://github.com/passchaos/netz/actions/runs/45543653123).
Linux job `138967947706` and Windows job `138967947574` both completed
successfully, including the H3 step that selects all six new entropy checks and
the two real deadline/cancellation tests. The complete `verify` job was still
running when this scoped evidence was captured.
