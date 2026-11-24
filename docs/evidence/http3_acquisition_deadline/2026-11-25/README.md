# Shared HTTP/3 acquisition deadlines — 2026-11-25

Pending shared-endpoint acquisitions retained their connection deadline but
did not check it in `poll`. The request driver scheduled only request deadlines
and capacity retry timers. A resolver blocked in cancellable I/O could therefore
outlive the shorter connection phase: synchronous acquisition repeatedly waited
with an expired receive deadline, while a request without an overall deadline
waited for the resolver notification.

Two finite zio regressions configure an 80-ms connection budget and a resolver
that sleeps for 600 ms before returning `UnknownHostName`. On the baseline both
expectations for `HandshakeTimeout` fail with `UnknownHostName`; 61/63 selected
tests pass. The resolver deliberately leaves expiry to the acquisition owner,
while honoring cancellation so timeout teardown can reclaim its state.

The shared `PendingRequestAcquire.poll` now checks its own deadline before
consuming resolution or handshake results, so a late successful handshake cannot
be promoted after that budget. The driver includes pending connection deadlines
in its receive/activity wait and composes all bounds with `internal.deadline`.
Both synchronous acquisition and the request driver use the same check and
existing teardown path, which joins the resolver before releasing its parent,
URI storage and connection reservation.

The driver regression exercises no request timeout, a longer one-second request
timeout, and an earlier 40-ms request timeout. The first two return
`HandshakeTimeout`, and the third preserves `Timeout`. Each returns within
250 ms, confirms the resolver exited, checks empty pool/driver state and zero
shared connection reservations, then reuses the same driver and budget. Native
Linux and Windows CI include these tests in their existing H3 acquisition step.

```sh
zig build test-http3 '-Dtest-filter=HTTP/3 shared acquisition deadline' -j1 --summary all
zig build test-http3 '-Dtest-filter=HTTP/3 shared acquisition deadline' '-Dtest-filter=HTTP/3 shared synchronous acquire' '-Dtest-filter=HTTP/3 shared Happy Eyeballs deadline' '-Dtest-filter=HTTP/3 shared endpoint pending handshake' '-Dtest-filter=HTTP/3 shared endpoint dispatcher drives' '-Dtest-filter=HTTP/3 shared endpoint starts independent' '-Dtest-filter=HTTP/3 shared endpoint promotes concurrent' '-Dtest-filter=HTTP/3 shared endpoint replays early data after address timeout' '-Dtest-filter=HTTP/3 shared endpoint dispatcher replays TLS-rejected early data' -j1 --summary all
```

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline connection-phase budget | 61/63 passed; both new expectations fail | [before.log](before.log) |
| Connection and request deadline precedence after the fix | 63/63 passed | [after.log](after.log) |
| Completion, dual-family, concurrent routes, early data and dispatcher overlap | 74/74 passed | [Debug.log](Debug.log) |
| Native Linux acquisition deadlines, commit `ab52606c` | Passed acquisition step, 2026-11-24 19:45 UTC | [Linux job](https://github.com/passchaos/netz/actions/runs/45472629967/job/138724817312) |
| Native Windows acquisition deadlines, commit `ab52606c` | Passed acquisition step, 2026-11-24 19:45 UTC | [Windows job](https://github.com/passchaos/netz/actions/runs/45472629967/job/138724817523) |
