# Bounded connection result pool — 2026-11-25

Connection competition reserved one result slot and one wake capacity unit per
candidate, although `max_in_flight` already constrained active attempts. The
actual H3 `HandshakeClient` type occupies 19,664 bytes on this host. A 64-target
competition reserved 1,263,648 bytes even with a concurrency limit of one or two.
The two allocation expectations fail on the baseline; the candidate identity
and successful-result cleanup check passes: 62/64 selected tests pass.

The pool now reserves `min(candidate_count, max_in_flight)` stable result slots.
Each slot transitions between available, working and finished. Available slots
form a free list, while working slots retain their original candidate index.
The worker publishes a slot reference after returning from the callback; taking
that completion frees the slot for the next candidate. Group retirement can
continue after the assignment is no longer needed. The selector queue has room
for slot completions plus the launch, deadline and optional cancellation wakes.
Task admission failure, timeout and cancellation join all workers before any
unselected owned result is destroyed.

The allocation probes use refusal callbacks, validating that every original
candidate index is entered exactly once. They measure only competition result
slots and wake storage. Inputs, the executor and actual connection/crypto
allocations are outside the metric. The fixed eight-slot stack cache remains;
heap storage starts when concurrent slot capacity exceeds that cache.

| Result type / bytes | Candidates | Concurrent limit | Before heap bytes | After heap bytes |
| --- | ---: | ---: | ---: | ---: |
| 4-KiB result | 64 | 1 / 2 / 8 | 265,248 | 0 |
| 4-KiB result | 64 | 9 | 265,248 | 37,152 |
| 4-KiB result | 64 | 64 | 265,248 | 265,248 |
| H3 `HandshakeClient`, 19,664 | 64 | 1 / 2 / 8 | 1,263,648 | 0 |
| H3 `HandshakeClient`, 19,664 | 64 | 9 | 1,263,648 | 177,552 |
| H3 `HandshakeClient`, 19,664 | 64 | 64 | 1,263,648 | 1,263,648 |

Each fixed concurrency probe now allocates exactly the same bytes/count for
64 candidates as for a candidate list whose length equals that concurrency.
The all-concurrent case retains the baseline allocation sizes and counts.

The reuse check keeps the first attempt blocked until cancellation, then returns
its 4-KiB successful result. The other slot cycles through 30 refused candidates
and returns the final candidate's success. Every original index is visited once, active callbacks stay at or below
two, the winner retains its payload, and exactly one unselected success is
destroyed. The same check accepts both a runtime slice and a large fixed array.
The overlap includes the prior admission/storage guards, TCP stagger/deadline
and loser cleanup, H3 dual-family/zero RTT, and gRPC connection competition.

| Verification | Result | Evidence |
| --- | --- | --- |
| Allocation/identity baseline | 62/64 passed; two allocation expectations fail | [before.Debug.log](before.Debug.log) |
| Result-size and concurrency matrix | Recorded for both result types | [metadata.json](metadata.json) |
| Pool, identity, ownership and TCP/H3/gRPC overlap | 196/196 passed | [Debug.log](Debug.log) |
| Scoped regressions for Windows | Compiled | [windows.compile.log](windows.compile.log) |
