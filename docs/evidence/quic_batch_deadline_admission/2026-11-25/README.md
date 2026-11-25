# QUIC batch receive deadline admission — 2026-11-25

Run [45601242457](https://github.com/passchaos/netz/actions/runs/45601242457)
on `40f9c9da47f172876365f0dd9cdd045312e83f41` completed the Linux native
job. Windows progressed beyond the earlier Alt-Svc pool construction wait,
then failed the trust regression set in `QUIC endpoint dispatcher validates
caller-owned deadlines`: a zero-duration receive-many call returned
`ConcurrencyUnavailable` instead of `Timeout`. Its public failure stack runs
through `Endpoint.receiveManyBytesIntoTimeout` and
`finishManyKernelBytesInto`. The native failure is recorded in
[ci-diagnostic.json](ci-diagnostic.json).

The raw batch entry points converted their `std.Io.Timeout` without checking
whether its bound was already expired. The socket could therefore request timed
batch I/O capability before rejecting an unusable caller budget. Existing
relative convenience and explicit-deadline forms already rejected non-positive
or incompatible bounds, so the raw surface was inconsistent.

A local backend probe rejects timed batch admission with
`ConcurrencyUnavailable`. Before the fix, the expired-call regression reproduces
the Windows result while the live-budget control passes. This is a failed
assertion with exit 1, rather than a native Windows execution claim.
[The baseline transcript](before.log) records both results.

Raw endpoint and dispatcher batch entry points now share the deadline
normalizer before admission. The endpoint acquires receive ownership under that
absolute deadline and rechecks it before each ICMP-related socket retry.
Unbounded calls retain their unbounded wait, and a live budget preserves the
backend's actual I/O capability error.

The new regressions check zero and negative durations, expired awake timestamps,
incompatible clock domains, validation before an empty output buffer, and
unchanged caller storage with zero I/O-admission calls. A live-budget control
retains `ConcurrencyUnavailable`; a held receive mutex must expire without
entering timed I/O or releasing the existing owner's lock. Existing real UDP
batch, ECN, visitor suffix, timer-bound, and canceled-prefix tests cover the
affected receive paths.

Local Debug and ReleaseSafe each pass 45/45 tests and 10/10 build steps,
including support tests imported by the focused root. Results are recorded in
[validation.json](validation.json), [Debug.log](Debug.log) and
[ReleaseSafe.log](ReleaseSafe.log). These checks establish the scoped macOS
behavior; native Windows and complete-suite acceptance still require the next
CI results. The native trust filter already includes these caller-owned
deadline tests.
