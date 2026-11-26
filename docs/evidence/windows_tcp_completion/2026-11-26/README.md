# Windows TCP completion investigation

Investigated protocol revision:
`26de4f0693dce3db3186bca4ff483f5b9a21b135`.
This batch adds a native diagnostic experiment and its CI registration. It
does not change production transport behavior or claim a TLS repair.

## Observed protocol failure

The completed [CI run 45785436516](https://github.com/passchaos/netz/actions/runs/45785436516)
reports this sequence in the original Windows H2 EndpointServer fixture:

```text
WebTransport H2 server fixture peer failed: stage=CLOSE input err=RecordTooLarge
Unexpected NTSTATUS=0xc000020d (CONNECTION_RESET)
FAIL (Unexpected)
```

The bounded public annotation lists the reset before the peer diagnostic; the
peer retains its first failure stage. The peer TLS parser failure is known,
while which bytes reached that parser and why it failed are still open.
The complete job failed separately: its command ran for 28 minutes, exited
137, and included a failed MQTT broker configuration interop node. The public
tail does not establish the cause of that interop failure or a new HTTP crash.

## Candidate mechanism

Threaded Windows `netRead` submits AFD RECEIVE through `deviceIoControl`.
After a cancellation request, that helper waits for the operation to finish
but returns `Canceled` even if the final IO status block records success and
a nonzero `Information` byte count. An incremental TLS reader advances its
saved ciphertext length only when its socket helper returns a count. If the
kernel consumed bytes but that count was lost, the next read could begin in
the middle of a TLS header or ciphertext.

This is a source-level mechanism consistent with the failure, not yet native
causal attribution. Both the TLS partial-record owner and the higher-level
deadline helper already retain successful counts that reach them.

`std.Io.Batch.cancel()` has the required completion contract: it joins pending
operations, removes successfully canceled operations, and retains successful
completions for `next()`. Threaded's Batch AFD RECEIVE uses the same asynchronous
handle, `NO_FAST_IO`, `OVERLAPPED` and normal receive flags as ordinary `netRead`.
No socket mode change, invented AFD flag, busy polling or alternate backend is
needed to test that contract.

The current Threaded `batchCancel` first enters an infinite alertable wait
before issuing `NtCancelIoFileEx`. An idle pending receive may have no queued
completion APC. The experiment arms one native alert on the owning current
thread before canceling a pending Batch, so that initial wait can reach the
actual cancellation and join. This is a separate source-level liveness concern;
the candidate is the Batch completion contract plus this explicit wake, not
an assumption that plain Batch cancellation on an idle socket already works.

## Native probe and limits

[The standalone source](../../../../tools/ci/windows_tcp_completion_probe.zig)
has two Windows TCP tests plus a portable cancellation-contract test. TCP
cases use actual loopback sockets with Threaded zero async capacity:

1. An AFD PEEK confirms the input is readable without consuming it. A worker
   waits for actual parent `Future.cancel`, observes `Canceled`, rearms that
   request immediately before an ordinary receive, and records its error,
   returned count and whether the expected payload reached its buffer.
   The kernel's result is observed; the test does not require the suspected
   loss to occur. A separate actual Batch receive is interrupted after native
   completion and before result dequeue. An await wrapper announces native
   completion and observes real parent cancellation while retaining the
   backend's userdata. It must return five
   bytes, rearm caller cancellation and read the following suffix exactly.
2. A zero-duration Batch await submits an actual pending receive on an idle
   socket. One native self-alert precedes cancellation, which must join it,
   leave its buffer untouched and leave no successful completion. The same
   socket must then receive `reuse` exactly.

The first test separates a raw native race observation from a deterministic
completion-retention assertion. Controlled cancellation after completion does
not itself prove scheduling behavior at the failing H2 close. Bounded CI notices
publish the raw count/buffer result and the candidate checks, including when
the test passes. Compile-only checks cannot establish either native result.

The Windows probe runs serially after the original combined and owned-input
commands in the existing five-minute native protocol step. Its exit status is
combined with protocol failures and its output uses the existing progress and
failure annotators. Both protocol commands and the resolver command remain
unchanged, as do dependency pins, budgets and H2 fixture assertions.

The initial compilation checks and then-current public CI snapshot remain in
[validation.json](validation.json). That initial record does not prove the
corrected probe's native behavior. Native Windows probe acceptance and a
production completion-preserving adapter remain follow-up work.

## Real cancellation follow-up

[Run 45793518173](https://github.com/passchaos/netz/actions/runs/45793518173)
failed in the initial probe: it called `recancel` to initiate cancellation and
hit Threaded's `recancelInner` assertion before the target raw receive. The
API requires a preceding cancellation point that actually returned `Canceled`.
No raw-count or pending-cancel evidence was produced by that aborted test.

Both probe boundaries now use parent `Future.cancel` and a real event wait.
The raw worker rearms only after observing that cancellation; the completed
Batch await returns a real cancellation while its native completion is still
stored. Early read failure also releases the parent's handshake wait before
the parent joins and inspects the result. A portable contract case checks two
actual observations: initial cancellation and the next rearmed cancellation.

The probe now streams through the existing progress tool, after the production
protocol commands, so protocol failures and diagnostic failures both remain
observable within their original budget. The corrected source's qualification
is in [real-cancellation.json](real-cancellation.json); it remains separate from
native Windows kernel behavior and causal attribution of the H2 TLS failure.
