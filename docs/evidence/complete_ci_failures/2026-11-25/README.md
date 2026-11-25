# Complete CI failure corrections — 2026-11-25

Run [45628282132](https://github.com/passchaos/netz/actions/runs/45628282132)
on `40e7a742acf6de53c7d748ca09221ddf74270547` passed preflight and the
native platform jobs. Complete and the dependent verify check ended with
`failure`; the complete command ran from 13:54:39 to 14:22:39 UTC. The
[public annotations](ci-failure-annotations.json) establish four concrete
acceptance failures. They do not certify the remaining complete suite or
identify its final active runtime test.

The WebTransport H2 Python peer could not start because `uv` was absent. The
complete job now installs published `uv` 0.13.0; the script continues to pin
h2 4.3.0, hpack 4.1.0 and hyperframe 6.1.0. Source dependency revisions and
all complete/preflight scopes are preserved.

The RFC 9220 peer client passed X.509 `TrustVerifier` values directly to TLS
`ClientVerifier` fields. It now uses the existing `fromTrustVerifier` adapter,
which retains the same callback and context. The same omitted adapter is
corrected in the other BundleVerifier-based interop entry points, including
forwarding modules used by the QUIC benchmark and shared H3 SOCKS5 pool.
`test-compile-interop` selects registered executables by name or root-source
path and compiles them without starting peers. An empty match fails with
`NoMatchingInteropPrograms`; ordinary test and interop steps retain their
existing dependencies and execution.

The source archive dependency test counted four literal workflow checkout
blocks and one textual occurrence per target. It now checks all three direct
CI checkout templates, the shared composite action used by two jobs, and the
release workflow against the same fixed revisions and token handoff. Target
counts use matrix declarations, including the native Windows runner, rather
than strings in regression commands or conditions.

OpenSSL `s_server -www` emits HTTP/1.0, which is outside the current documented
HTTP version surface. The ticket peer now serves an explicit HTTP/1.1 file
using OpenSSL `-HTTP`, with Content-Length and connection close. The client
requests that file; both TLS 1.2 and TLS 1.3 retain two connections and exact
fresh/resumed assertions in both endpoint roles. Nonempty executable argument
arrays also work with macOS Bash 3.2's nounset behavior.

A separate real-process probe [reproduced](repeated-interrupt-before.json)
repeated interrupts unwinding owned-child cleanup: the wrapper returned 130,
left its child alive and omitted the final error. The wrapper now ignores
further SIGINT/SIGTERM while finishing the original failure's cleanup. The
regression uses an isolated process group and a child that delays termination;
it requires child retirement, the original status and the final progress error.

Validation receipts distinguish scoped compilation, actual peer execution,
Python fixture tests and pending complete/native CI acceptance. Local OpenSSL
calls use a Python subprocess timeout shim because GNU timeout is absent on
this host; that shim validates the fixture's ten-second child duration, not
GNU's CI process-group behavior. The published uv version is checked against
PyPI and matches the installed local runner. A successful scoped gate does not
replace the next complete CI result.

Local validation passes all nine changed interop executable roots, including
modules forwarded through the digest and QUIC benchmark programs. The unmatched
filter fails with its exact diagnostic. Both TLS ticket modes pass against
OpenSSL 3.6.5 in both endpoint roles, and the Python WebTransport H2 gate passes
both directions plus queued endpoint and listener cases. The source archive
suite passes 9/9, progress reporting passes 10/10 and failure formatting passes
6/6. Current source identities and the remaining CI boundary are in
[validation](validation.json). The initial combined native log retains the
macOS Bash3.2 failure; the successful ticket rerun is recorded separately.

The evidence audit passes the existing max-unresolved=24 policy with 3 unresolved,
0 invalid and 0 unreadable entries. Historical stale records remain historical;
this delivery does not refresh their protocol or performance claims.
