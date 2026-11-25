# Complete CI protocol and fixture failures — 2026-11-26

Run [45641634010](https://github.com/passchaos/netz/actions/runs/45641634010)
on 6b17e5f0 ended in 21 minutes with actual failures. The [baseline](ci-baseline.json)
records its aborted root test and peer failures; increasing the job budget would
not repair those failures.

The HTTP/1 borrowed-pipeline fixture supplied an undefined socket address while
asserting non-null request peer metadata. It now supplies valid loopback metadata
for buffered-only connections. No socket I/O is performed or suppressed by that
fixture. The layout test retains the original non-policy owner budgets (304/240
bytes) and 48-byte write scratch while accounting separately for current Limits
storage. Total Client/Connection sizes are 608/544 bytes on this host.

The pending-GRO legacy test expected a raw zero-duration receive to consume a
queued suffix. It now rejects that expired call and proves the pending count is
unchanged, then uses a valid budget to retrieve the prefix. This aligns it with
the already-delivered raw receive admission contract. macOS skips this actual
GRO case; the native Linux connection/command scope now includes it explicitly.

Concurrent H3 Stream commands now check their awake deadline before queue/inline
admission and again before owner execution. All kinds carry the same command
budget; interim heads in a compound command share it. Queued and inline handlers
exercise expired and foreign-clock rejection followed by successful responses.
A deterministic public Stream test expires the original budget between entry
and execution, observes zero adapter writes and unchanged response state, then
starts the response successfully under a new valid deadline. Further bounded
adapter-write propagation remains ongoing work rather than part of this claim.

The Python 3.14 peer rejects the old generated CA with verification error 92,
missing CA keyUsage. Explicit critical CA/leaf constraints and key usage correct
that identity; verification stays strict. [The paired probe](strict-ca-paired.json)
uses the exact legacy generator and the corrected generator under one Python/TLS
runtime. The actual H2 peer subsequently passes in both endpoint directions,
including queued endpoints and listener admission.

OpenSSL ticket and optional-mTLS servers share a complete HTTP/1.1 response file.
Certificate selection is checked against the server's actual incoming Certificate
and CertificateVerify messages, including exact leaf bytes and Finished lengths.
This replaces reliance on the old -www status page's application text. Empty
Certificate lists in unmatched-CA cases are checked separately from matching
single-certificate handshakes for both TLS versions. The checker rejects changed
identities, missing/extra verification messages, protocol mismatch and malformed
wire lengths; its six unit tests are part of the normal complete gate.

[Validation](validation.json) distinguishes actual peer execution, scoped H1/H3
tests, the local GRO skip and the remaining native/full acceptance. The initial
peer log retains the obsolete application-text assertion failure; the successful
transcript revalidation follows separately. Local OpenSSL duration calls use the
previously documented Python timeout shim; the CI GNU timeout behavior is not
inferred from that shim. Source dependency pins and CI budgets are unchanged.

Local Vail was d93847a7, while the unchanged CI pin is 3b772b0c. Local
scoped results are qualified by that dependency boundary; the next pinned
native/complete run remains required acceptance. Vort matches its fixed pin.

The evidence audit passes the existing max-unresolved=24 policy with 3 unresolved
entries and 0 invalid/unreadable entries. Historical stale source records retain
their captured revisions and do not become new performance claims.
