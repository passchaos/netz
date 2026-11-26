# Crash context tied to the executed test artifact

Base revision: `a265f9b7a043f8aad164f9c9ace71bd4f127702a`.
This change repairs crash-context extraction for the existing complete and
native CI commands. Crash attribution and repair require their owning path.

## Reproduced diagnostic failure

The full-library failure summary can be emitted after another test artifact's
output. A replay of the current verbose log structure contains a library test,
an allocator abort, a later fuzz test and then `failed command` naming the
library executable. The original extractor ignored the allocator preface and
associated the delayed signal summary with the later fuzz test. An empty
failed-command log also raised `IndexError` rather than reporting missing output.

## Corrected context ownership

The [extractor](../../../../tools/ci/test_failure_annotations.py) records test
names under the cache executable and the specific invocation that produced
them. A signal summary resolves its `failed command` back to that invocation.
It reports the last visible test for that artifact, explicitly as context;
this is not a causal assertion about which test or task triggered the abort.

Quoted Windows paths and spaces preserve the same cache identity. Repeated
executions start fresh records, and unknown executions do not borrow another
artifact's last test. Signal context ends at the failed command instead of
including unrelated later output. Empty logs report missing command output.

Native crash/panic and allocator abort prefaces are prioritized before ordinary
build errors. The existing twelve-annotation cap and payload escaping remain.
Tests and commands still fail with their original exit status; budgets, pins,
protocol filters and migration inputs are unchanged.

## Focused qualification

[The regressions](../../../../tools/ci/test_failure_annotations_test.py) pass
22 cases, including a real POSIX child that exits through SIGABRT, delayed
summaries, long stacks, quoted Windows paths, repeated artifacts, unknown
artifacts, allocator prefaces, early-error saturation and empty logs. Long
native transport traces before a failed timeout expectation also retain the
active artifact's last visible test. Existing
terminal/server-mode diagnostics, warning exclusion and escaping cases remain.

[validation.json](validation.json) records exact source and result hashes.
Runtime crash attribution remains open until the next actual failing run
provides its artifact context and that owning path is reproduced.

## Located WebTransport removal fixture

The complete run's full public annotations now identify test 4591/7478,
`WebTransport endpoint client removal deadline spans CLOSE RESET and STOP
without renewal`. Its GP enters `Allocator.rawAlloc` through Threaded
`Group.concurrent`. The fixture supplied an `ExpiringSend` observer as userdata
to inherited backend callbacks, so the callback interpreted it as Threaded.

That fixture now uses the existing Native send observer with stable backend
userdata, full typed forwarding, exact remaining-time mapping and a real event
for its synthetic clock watcher. Its selected send advances an atomic clock
only after the chosen first/second/third successful send. The original CLOSE,
RESET, STOP, exact four-send, retry and sibling-ownership assertions remain.
The original endpoint I/O is restored before the observer and fixture are
destroyed.

All seven removal fixtures use the supported native backend runner: POSIX
Threaded and the application backend, with application IOCP on Windows. Their
selected scope passes 118 native cases, including all seven fixture names,
and compiles on Windows in eight build steps. Native pinned Linux/Windows and
the complete run still need qualification. An independent removal command
joins the existing five-minute protocol step after its prior commands.
