# Bounded shared WebTransport Session removal

`webtransport.runtime.EndpointClient` exposes `removeSessionWithTimeout` and
`removeSessionWithDeadline` beside its existing unbounded `removeSession`.
They remove one Session while retaining the HTTP/3 connection and siblings.
A successful removal returns true; an unknown Session returns false with a
usable budget. An expired deadline, non-awake clock, or nonpositive timeout
returns Timeout before modifying the target's terminal state.

```zig
const id = session.id();
const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
    .clock = .awake,
    .raw = .fromSeconds(3),
});
if (try client.removeSessionWithDeadline(id, deadline)) {
    // The borrowed session pointer is now invalid.
}
```

One absolute deadline covers completion of any partial DRAIN, the existing or
new CLOSE capsule, CONNECT FIN, all associated RESET_STREAM/STOP_SENDING output,
and the final STOP_SENDING for an otherwise-unfinished CONNECT receive half.
Pacing and credit/congestion waits service the same connection owner under that
budget. Protocol cancellation precedes ordinary FIN. The server's removal
already uses nonblocking submissions and retains its existing behavior.

Timeout and socket errors retain the Session owner and completed wire progress.
Retry removal with a fresh operation budget. A CLOSE started by a prior explicit
Session close retains its original code and copied reason. A partially sent
HTTP/3 DATA prefix resumes without repeating bytes or interleaving CLOSE into
an unfinished DRAIN frame. RESET_STREAM and STOP_SENDING state is committed only
after socket submission, so retries skip completed directions. A completed CLOSE
is not replayed when later cleanup runs out of time.

The implementation shares terminal stages between bounded and unbounded
removal in `runtime/endpoint_client/terminal.zig`. The cohesive removal controller
lives in `runtime/endpoint_client/remove.zig`; caller-visible Session ownership
is released only after the complete terminal transaction succeeds.

Seven real UDP/QUIC regressions verify both budget forms, one-byte CLOSE progress,
zero/negative/expired/foreign-clock budgets, sibling delivery, a deadline
expiring immediately after CLOSE/RESET/STOP, exact original CLOSE metadata,
congestion timeout/recovery, DRAIN-before-CLOSE framing and cancellation before
FIN after invalid post-CLOSE input. A real authenticated two-Session test uses
one deadline for both removals. The new tests and four existing client test
modules are explicitly registered in the runtime test root; the executed test
list was inspected to confirm the new cases ran.

Run the owning-module checks with:

```sh
zig build test-lib -Dtest-filter='WebTransport endpoint client' -Dtest-filter='WebTransport shared client' -Dtest-filter='WebTransport endpoint server' --summary all
zig build test-package --summary all
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast --summary all
```

Verification passed 219 owning-module checks, 20 public-package checks and the
independent wtransport client/server matrix. The external matrix checks CONNECT,
DATAGRAM limits, both stream directions, exact reset/stop codes, sibling reuse,
DRAIN and close ordering. It corroborates the shared wire semantics; the bounded
removal API itself is exercised by the local UDP and authenticated tests.

[The verification record](evidence/webtransport_removal/2026-10-28.json) retains
the seven executed case names, source fingerprints and both external peer roles.


A terminal HTTP2 connection read (EOF, reset or an already closed transport)
retires connection output before Session cleanup. Such cleanup releases local
ownership without sending a cancellation reset or TLS shutdown record on the
failed transport. Message/capsule failures retain their stream reset behavior,
and an ordinary explicit owner shutdown retains its existing contract.
