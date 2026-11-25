# Complete CI budget and test progress — 2026-11-25

Run [45611671652](https://github.com/passchaos/netz/actions/runs/45611671652)
on `3eeba20fbbacb36a965efc3adcd3ed49a87a8478` completed both Linux and
Windows native jobs, bounded fuzz replay and QUIC endpoint soak. The complete
test step started at 12:27:39 UTC and was canceled at 12:43:31 UTC when its
containing job reached the 30-minute limit. Its actual test budget was about
16 minutes after setup, release-source validation, fuzz and soak. The canceled
step is missing complete-suite acceptance, not a passing result or a diagnosed
protocol defect. [The baseline receipt](ci-baseline.json) records that boundary.

The workflow now gives preflight and the complete `zig build test -j1` gate
separate 30-minute jobs. They share one local composite action containing the
same nine pinned dependency/toolchain/cache preparation steps. All original
preflight commands and the complete test command remain exact. The existing
`verify` check depends on both jobs and fails unless both succeed; its truth
table includes failed, canceled and skipped outcomes. Other platform jobs are
unchanged. This preserves coverage and the required check while giving the
complete gate its own budget.

The progress option previously configured library, package and focused run
artifacts, leaving standard auxiliary/fuzz test artifacts in Zig's build-server
mode. A last visible completed test therefore could not identify a later
auxiliary runtime wait. The shared runner adapter now visits the completed build
graph and opts every standard test run into terminal progress. Repeated visits
are safe; ordinary executables, custom runners and default mode retain their
existing path. Only the server-protocol switch is removed, preserving producer,
executor, selected seed and cache arguments, standard leak checks and failure
exit status.

Local validation executes the actual project build graph: default parser fuzz
passes 2/2 with its existing runner; progress mode passes the same 2/2 and emits
both test names; the focused HTTP scope passes 104/104; an unmatched protocol
filter still fails with `NoMatchingProtocolTests`. YAML checks compare the new
setup and command lists against the prior workflow. All 16 summary-result
combinations are exercised with the actual Bash block, and only two successes
produce success. [Validation](validation.json) records source hashes, command
scope and [summary results](summary-validation.json). These scoped checks do not
replace the next full CI execution.
