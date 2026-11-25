# Effective TCP-to-H3 trust policy — 2026-11-25

TCP TLS gives `server_verifier` precedence over `ca_bundle`. The H3 adapter,
strict client initialization and preference selection previously treated any
configured TCP bundle as requiring separate H3 trust, including a bundle that
the TCP verifier had already replaced. A configuration using a verifier and
bundle therefore authenticated TCP successfully but rejected or skipped H3.

`client_trust.requiresExplicitH3Trust` now centralizes that decision. An active
TCP bundle still requires explicit H3 trust; a configured TCP verifier can be
inherited despite an inactive bundle. Explicit H3 peer policies retain their
existing precedence and client identity continues to inherit independently.

Three distinct regressions fail on `2cba735e`: verifier inheritance, H3-only
initialization and H3 preference selection. The baseline runs them through
two protocol roots, reporting four failing executions and 128/132 passes in
[before.Debug.log](before.Debug.log).

The final checks cover ordinary and deadline-aware inheritance, unchanged
options on rejection, H3-only and Alt-Svc pool constructors, preference routing,
explicit H3 trust precedence and real certificate handshakes. The inherited
verifier authenticates the fixture server with its P-256 public-key pin and no
H3 CA store. The CA fixtures also retain both caller-owned PEM and POSIX
`SSL_CERT_FILE` coverage against conflicting TCP pins. Every native CA/pin
fixture uses one zio runtime and joins or cancels its peer before releasing
endpoint resources.

| Verification | Result | Evidence |
| --- | --- | --- |
| Three distinct effective-policy regressions on the baseline | 128/132 passed; four failing executions across two roots | [before.Debug.log](before.Debug.log) |
| Effective policy, protocol admission, explicit trust precedence and real CA/pin handshakes, Debug | 182/182 passed | [Debug.log](Debug.log) |
| The same selected regressions, ReleaseSafe | 182/182 passed | [ReleaseSafe.log](ReleaseSafe.log) |
| Selected QUIC/HTTP tests for Windows | 11/11 build steps succeeded | [windows-compile.log](windows-compile.log) |

[Local validation metadata](local-validation.json) records the exact results;
[Debug](Debug.log), [ReleaseSafe](ReleaseSafe.log) and
[Windows compilation](windows-compile.log) retain their build summaries.
All Zig commands, including formatting, ran under the shared tree guard with
`-j1`; [guard.log](guard.log) records supervision. Windows compilation is
separate from native execution. The native Linux/Windows trust-startup gate
now includes the `effective trust` filter for these regressions.

```sh
zig build test-quic test-http -j1 '-Dtest-filter=effective trust' '-Dtest-filter=QUIC trust precedence' '-Dtest-filter=QUIC client verifies' '-Dtest-filter=protocol policy' '-Dtest-filter=TCP CA bundle' '-Dtest-filter=TCP trust material' '-Dtest-filter=explicit H3 trust' --summary all
zig build test-quic test-http -j1 -Doptimize=ReleaseSafe '-Dtest-filter=effective trust' '-Dtest-filter=QUIC trust precedence' '-Dtest-filter=QUIC client verifies' '-Dtest-filter=protocol policy' '-Dtest-filter=TCP CA bundle' '-Dtest-filter=TCP trust material' '-Dtest-filter=explicit H3 trust' --summary all
zig build test-quic-compile test-http-compile -j1 -Dtarget=x86_64-windows-gnu '-Dtest-filter=effective trust' '-Dtest-filter=QUIC trust precedence' '-Dtest-filter=QUIC client verifies' '-Dtest-filter=protocol policy' '-Dtest-filter=TCP CA bundle' '-Dtest-filter=TCP trust material' '-Dtest-filter=explicit H3 trust' --summary all
```
