# Connection race admission — 2026-11-25

Connection competition allocated target/worker storage before processing an
already-expired deadline or settled cancellation event. A large address answer
could therefore return `OutOfMemory` instead of its connection phase's timeout.
H3 owning races also omitted their overall deadline from the common selector,
and generated a later candidate's QUIC identity before checking its attempt
budget. The four initial rejection expectations fail on the baseline:
101/105 selected tests pass, with TCP, H3 and gRPC observing `OutOfMemory`.

The shared admission check runs before address/endpoint planning, before task
admission after storage allocation, and at each connection worker's entry. It
keeps the original awake-clock timestamp and the caller's phase error. A settled
cancel event returns `Canceled`. Admitted workers still publish into stable
owned-result slots; teardown joins them before destroying unselected results.
Explicit optional heap storage also keeps fixed-array targets usable alongside
runtime slices in the generic competition API.

H3 validates the deadline again after resolution, supplies its overall deadline
and `HandshakeTimeout` to the selector, and starts an individual attempt's budget
before generating a fresh identity. Per-address expiry can still select another
candidate while the overall deadline remains valid. Public connection options,
family interleaving and the first-attempt-only early-data policy are retained.

The rejection probes combine nine addresses with a failing allocator and no
concurrent task capacity, proving that settled admission takes precedence over
allocation and task errors. They cover expired/foreign clocks and a set cancel
event, with zero connection callback calls. A scheduler probe sets cancellation
when the first connection task is admitted and verifies that the worker never
enters transport code. The public H3 URI fixture returns nine resolved addresses
at the deadline and rejects any subsequent allocation.

The scoped overlap selects TCP successful-loser cleanup and cancellation, H3
dual-family handshakes, total deadline cancellation and zero RTT, and gRPC
staggering, endpoint indices and owned responses. The live H3 total-deadline
fixture uses one zio runtime, so native Windows can execute its timed UDP checks.

```sh
zig build test-http1 test-http3 test-grpc '-Dtest-filter=connection race admission' '-Dtest-filter=TCP Happy Eyeballs' '-Dtest-filter=HTTP3 owning Happy Eyeballs' '-Dtest-filter=HTTP3 Happy Eyeballs' '-Dtest-filter=gRPC connection competition' -j1 --summary all
```

| Verification | Result | Evidence |
| --- | --- | --- |
| Initial rejected-admission baseline | 101/105 passed; all four new expectations fail | [before.Debug.log](before.Debug.log) |
| Rejection, worker cancellation and live TCP/H3/gRPC overlap | 183/183 passed | [Debug.log](Debug.log) |
| Scoped TCP/H3/gRPC regression compilation for Windows | Compiled | [windows.compile.log](windows.compile.log) |
