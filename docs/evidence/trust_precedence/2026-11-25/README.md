# Explicit H3 peer-trust precedence — 2026-11-25

At `4f633cc8`, the unified TCP-to-H3 trust adapter fills each unset H3 trust
field independently. An H3 private-CA store or `SSL_CERT_FILE` environment
therefore still inherits the TCP pinned verifier, which has higher priority
during the QUIC handshake. Explicit H3 bundled/native root selection is also
bypassed by that inherited verifier. The policy no longer reflects the H3
choice documented at the adapter boundary.

The adapter now inherits TCP peer-trust fields together only when H3 has no
explicit peer-authentication policy. Explicit H3 verifier, store, environment,
bundled-root and native-root choices retain all their trust fields. Client
identity inherits separately when unset, so mTLS identity configuration remains
independent of peer-root selection.

Five baseline tests fail (33/38 pass). The matrix exercises both ordinary and
deadline-aware policy application, with conflicting TCP verifier, store,
environment, root selection and CA-bundle configuration. Additional tests check
H3/TCP client identity precedence and actual CA-authenticated QUIC handshakes
with a conflicting TCP public-key pin. The caller-owned CA mode runs on all
native platforms; `SSL_CERT_FILE` construction remains POSIX-specific.

Verification commands, baseline failures and results are recorded beside this
document. The native trust-startup gate selects the precedence regressions.

| Verification | Result | Evidence |
| --- | --- | --- |
| Explicit policy inheritance baseline | 33/38 passed; five source-isolation failures | [before.Debug.log](before.Debug.log) |
| Five source choices, ordinary/bounded application, independent client identity, TCP inheritance controls and actual CA handshakes | 49/49 passed | [Debug.log](Debug.log) |
| Unified HTTP direct/pooled H3, H3 WebSocket and shared WebTransport constructors | 314/314 passed | [facades.Debug.log](facades.Debug.log) |
| Precedence and CA authentication fixtures for Windows | Compiled | [windows.compile.log](windows.compile.log) |

[Local metadata](local-validation.json) records the completed checks. Builds
ran under the shared tree guard with `-j1`.

The native trust-startup gate also passed on source commit
`2cba735ea9cab0b9c6f41717ed64dec353b8c776` in
[run 45562766721](https://github.com/passchaos/netz/actions/runs/45562766721).
The [Linux job](https://github.com/passchaos/netz/actions/runs/45562766721/job/139030191299)
completed the gate at 06:55:41 UTC; the
[Windows job](https://github.com/passchaos/netz/actions/runs/45562766721/job/139030191141)
completed it at 06:51:43 UTC. Both gate conclusions were `success`.
[Native gate metadata](native-gates.json) records the source commit, exact jobs
and step timestamps from the public job pages.
