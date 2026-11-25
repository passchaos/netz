# Stack acceptance test progress — 2026-11-25

The frozen stack source `22a293fa` was not accepted by its CI run
45579033941: the Linux and Windows native trust steps, and the complete
test gate, were canceled at their jobs' 30-minute limits. This is missing
acceptance evidence, not a passing test result or a diagnosed runtime defect.
The bounded fuzz replay and QUIC endpoint soak passed on that source.

A guarded local replay of the exact five-root native trust filter set uses
Zig's standard terminal runner and prints each test name. All 501 tests passed
(58, 149, 113, 155 and 26 per executable), with 26/26 build steps succeeding.
This proves the macOS scoped replay; it does not replace native Linux or
Windows execution. [The local replay](native.Debug.log) retains every test name.

`-Dtest-progress=true` now opts library, package and focused tests into the
standard terminal runner. The build helper retains `addRunArtifact`'s
producer, executor, cache and selected random-seed arguments, removing only
the server-protocol switch. Custom runners and the default mode retain their
existing path. Tests still use the standard leak checks and exit status, and
the protocol-root matching guard remains active.

CI uses that progress option plus verbose compiler commands for the native
trust and complete-suite stages. A log that has not reached its first test
name is still compiling; a last active name identifies the runtime boundary
to reproduce. No product implementation or test expectation was removed, and
job limits remain at 30 minutes.

The follow-up `run_test_progress.py` wrapper exposes the last visible test in
an Actions notice every 60 seconds, including a name printed without its result
newline. Its log preserves exact bytes; its console decoder retains split
UTF-8 code points before inserting an annotation. A bounded 16-chunk queue and
8-KiB text window limit observer memory. Five real-child-process tests cover
partial progress before completion, a nonzero exit, build-phase reporting,
large exact output and fragmented UTF-8. Failure-context annotations separately
recognize terminal FAIL, panic and build-server errors, retain the preceding
test name, use the actual log title, escape the Actions payload and cap output
at twelve annotations; five tests and an actual terminal-failure replay pass.

Diagnostic run `45586673594` on `8cb2f3a3` also reached its 30-minute job
limits: the Windows native step ended canceled at 10:04:34 UTC, the complete
gate at 10:04:38 UTC and the Linux native step at 10:04:39 UTC. The follow-up
wrapper therefore publishes its last visible progress in annotations while
the command remains active. [Helper validation](helper-validation.json)
records the ten passing Python checks, source hashes and exact canceled jobs.
