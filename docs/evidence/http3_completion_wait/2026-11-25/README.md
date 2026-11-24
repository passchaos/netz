# Shared HTTP/3 acquisition completion waits — 2026-11-25

Synchronous shared-endpoint Happy Eyeballs acquisition passed an event to its
resolver, stagger timer and handshake workers, but never waited on that event.
It instead received UDP with periodic `handshake_poll_interval` deadlines.
Silent worker completion therefore remained invisible until the next receive
timeout, and a long configured interval delayed DNS failure and candidate
launches.

The regression uses one zio runtime and a resolver that fails after 20 ms.
With a 10-second poll interval and a 600-ms connect budget, the baseline
returns the expected `UnknownHostName` but fails the assertion that acquisition
finishes within 250 ms. The selected baseline run passed 59/60 tests.

Acquisition now shares the request driver's endpoint/activity wait. It resets
the completion event before reading worker done states, so completion racing
that read remains visible to the next wait. The wait races the sole endpoint
receiver against the notification under the original absolute deadline,
joins both tasks before the next poll changes handshake routes, and retains
an endpoint result completed while cancellation was being drained.

A second zio regression cancels unbounded acquisition during resolution,
checks the resolver has exited and all pool routes/reservations were reclaimed,
then reuses the same endpoint. Existing dual-family success and handshake
deadline tests now use a 10-second poll interval to verify stagger-timer and
handshake notifications advance the race independently of polling.
The overlap also exercises established-response progress, isolated request
deadlines and streamed requests through the dispatcher using the extracted
wait. Native Linux and Windows CI run the two zio completion/cancellation tests.

```sh
zig build test-http3 '-Dtest-filter=HTTP/3 shared synchronous acquire wakes' -j1 --summary failures
zig build test-http3 '-Dtest-filter=HTTP/3 shared synchronous acquire' '-Dtest-filter=HTTP/3 shared Happy Eyeballs deadline' '-Dtest-filter=HTTP/3 shared endpoint pending handshake' '-Dtest-filter=HTTP/3 shared endpoint dispatcher drives' '-Dtest-filter=HTTP/3 shared dispatcher streams' -j1 --summary all
```

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline resolver latency regression | 59/60 passed; expected latency failure | [before.log](before.log) |
| Resolver completion after the fix | Passed; acquisition within 250 ms | [after.log](after.log) |
| Completion, cancellation, dual-family and dispatcher overlap | 69/69 passed | [Debug.log](Debug.log) |
