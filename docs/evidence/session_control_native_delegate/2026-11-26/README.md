# Authenticated WebTransport session-control I/O ownership

The complete gate on f5dcf94e42d7fd1a2f42fabd42c9265f478ce78b,
[run 45813013101 attempt 1](https://github.com/passchaos/netz/actions/runs/45813013101),
aborted at test 4692/7478, `WebTransport authenticated close deadline resumes
capsule and stream cleanup`, with a segmentation fault at 0x3. The visible stack
enters Threaded Group.concurrent allocator creation. The fixture copied the
Threaded VTable and replaced its userdata with a FixedSendIo pointer, leaving
inherited scheduling callbacks to interpret that pointer as Threaded.

Five related deadline fixtures now borrow the real execution/socket backend
through the existing Native observer and full typed callback forwarding.
Their synthetic awake clock starts at 1,000,000 ns. A selected successful send
can advance it by 2 ns and wake an actual backend event; no callback fabricates
`Canceled`. Endpoint I/O restoration precedes observer destruction and session
cleanup. Peer Futures execute on the actual backend and are awaited or canceled
while their owners remain alive.

The original assertions remain: invalid deadline admission sends nothing;
partial CLOSE/DRAIN resumes its exact capsule; conflicting metadata and
interleaved sends are rejected; RESET/STOP cleanup retains its completed
prefix; terminal event code and reason survive a cleanup timeout; repeated
close sends nothing. The zero-sleep checks now count pacing duration sleeps.
The absolute deadline watcher uses the shared observer's actual cancellable
wait and is intentionally a separate operation.

The original test names are formally registered from two cohesive modules:

- `WebTransport authenticated close deadline resumes capsule and stream cleanup`
- `WebTransport authenticated drain deadline resumes exact capsule`
- `WebTransport server close deadline resumes one exact capsule`
- `WebTransport terminal event survives cleanup timeout`
- `WebTransport deadline cleanup retains completed stream prefix`

The matching local native scope passed 119 tests, including those five fixtures
on POSIX Threaded with zero async capacity and the application backend with
one executor. The same scope compiled for x86_64-windows-gnu in 8/8 build steps.
All Zig invocations were serialized under the shared tree guard.

A separate native CI command selects all five names within the existing
five-minute protocol step. Its failure propagates to the step. Existing native
commands, pins, annotation cap and complete-gate budgets remain intact.
[validation.json](validation.json) records commands, source hashes and limits.
Linux/Windows native qualification of this revision and complete-crash closure
remain pending. The observed HTTP/2 informational StreamReset and Windows H3
Unexpected failures remain independent open findings. The continuous goal is
active.
