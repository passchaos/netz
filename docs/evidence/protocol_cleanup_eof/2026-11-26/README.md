# Intentional old-generation EOF cleanup — 2026-11-26

[Run 45684485249](https://github.com/passchaos/netz/actions/runs/45684485249)
identified the reconnect failure precisely: the client was removing its second
old-generation handle after the peer deliberately closed that TLS connection.
`removeAfterDrop(client, b)` returned `UnexpectedEof`; the peer was still
waiting for the next-generation start event. The new-connection accept budget
was therefore not the failing operation.

The fixture already treats closed endpoint/socket errors as successful terminal
cleanup. It now includes TLS EOF and connection reset at this same intentional
drop boundary. Failures from initial or future CONNECT operations are preserved.
The local Threaded/zero-async and zio/one-executor case scope passes 135 tests.

The native Windows report retained a failed process summary without the first
useful test diagnostic. The annotation helper did not classify GPA leak lines,
so those could be hidden by a later build error. It now reports allocator leak
contexts first, with the owning test and allocation stack. Seven regression
tests pass, including the new leak-before-build-error case. This reporting
change does not assert that the Windows failure is a leak.

[Validation](validation.json) preserves the native failures and local scope.
Native Linux/Windows and complete acceptance remain required. Dependency pins
and operation/CI budgets are unchanged; the Linux CA disconnect cause remains
under investigation.
