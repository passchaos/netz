# QUIC raw receive deadline and backend contract — 2026-11-25

Run [45606143658](https://github.com/passchaos/netz/actions/runs/45606143658)
on `0a11266845509427d57c7455be2521fb9d8f3fe4` completed Linux native
acceptance. Windows still failed `QUIC endpoint dispatcher validates
caller-owned deadlines`, but its stack now reached the single-packet kernel
receive under a live positive timeout. Zig 0.16's Windows Threaded
`batchDrainSubmittedWindows` explicitly returns `ConcurrencyUnavailable` for
concurrent `net_receive`, pending overlapped-I/O support. The native evidence is
recorded in [ci-diagnostic.json](ci-diagnostic.json).

netz's supported asynchronous `runtime.Backend` uses zio and exposes only
`std.Io` to the protocols. Real UDP deadline conformance now runs through that
backend. A separate external-I/O probe still requires `ConcurrencyUnavailable`
for a live budget when timed batch admission is unsupported; capability failure
is never relabeled as a timer expiry.

The expanded admission matrix also reproduced two product inconsistencies on
macOS before the correction: a single-packet expired raw timeout reached timed
I/O, and the new batch normalizer rejected a live raw timeout on another clock.
[The baseline transcript](before.log) records both failed assertions. Raw
`std.Io.Timeout` supports other clocks; explicit `WithDeadline` remains an
awake-clock interface.

The endpoint's parsed, owned-byte, caller-buffer, GRO batch, receive-many and
Version Negotiation paths now normalize and validate raw budgets before buffer
or queued-input admission. Dispatcher owned/visitor/batch entry points and
server batch entry points use the same rule. Receive ownership waits and ICMP
retries retain one absolute bound. Foreign clock epochs are translated using
their remaining duration, sampling awake time first so conversion cannot renew
the consumed budget.

The five admission regressions cover ten receiving forms, zero/negative/expired
budgets, validation before empty output storage, untouched queued datagrams,
held receive locks, live unsupported-I/O errors, and exact clock-conversion
budget loss. Existing actual UDP, GRO, ECN, visitor suffix, cancellation prefix
and server/dispatcher deadline tests cover the affected integration paths.
Debug and ReleaseSafe each finish 52 tests: 50 pass, two platform GRO cases
skip on this macOS host, and none fail. All 10 build steps succeed. Results and
source hashes are recorded in [validation.json](validation.json),
[Debug.log](Debug.log), and [ReleaseSafe.log](ReleaseSafe.log). Scoped macOS
checks do not replace subsequent native Windows and complete-suite acceptance.

The complete CI gate now invokes the existing bounded failure-context annotator
when its streamed command fails. An exact Bash-block integration check records
the old missing annotations, preservation of exit code 7, new failure contexts
and percent escaping, and a clean success branch in
[ci-shell-validation.json](ci-shell-validation.json). Test coverage and job
limits are preserved.
