# WebTransport stream reader admission, 2026-11-24

Base revision: `615c5868`, Zig 0.16.0, macOS aarch64.

[Four baseline regressions](admission-before.log) fail, with 104/108 passing
including imported support tests. Dispatcher binding does not prevent
incremental or FIN-complete whole-stream delivery from existing receive state.
Facade lifecycle inspection advances flow rejection before returning an owner
error, and direct composable flow readers parse buffered CLOSE first.

The protected-UDP fixture waits for the complete stream offset and, for whole
delivery, the peer's final size. A body whose FIN remains on UDP cannot satisfy
the whole-stream baseline. Both client and accepted-server roles use the
production QUIC/H3 parsers and the supported zio backend.

The shared H3 receive-owner check now lives in
`webtransport/runtime/owner.zig::receiveH3`. Public stream facades use the
Session owner check before lifecycle observation; incremental, targeted and
whole-stream readers in `runtime/flow/read.zig` use the H3 check before progress
callbacks or buffered polls. Relative timeout facades construct one deadline
at entry and delegate to the matching absolute-deadline form.

The four test groups cover six incremental/targeted forms and three whole
forms on both roles, plus callback/dispatcher rejection at the composable
reader boundary. Rejected reads preserve output bytes, receive offsets,
Session consumed-data credit and registry record counts. Existing poll APIs
deliver those buffered streams while dispatcher binding remains active.
After releasing a callback borrow, Session polling still delivers the original
buffered CLOSE reason.

| Gate | Result | Artifact |
| --- | --- | --- |
| Four reader admission regressions | Expected failures, 104/108 passing | [admission-before.log](admission-before.log) |
| Reader admission (Debug) | 108/108 | [reader.Debug.log](reader.Debug.log) |
| Stream/grant/termination overlap (Debug) | 199/200, 1 platform skip | [overlap.Debug.log](overlap.Debug.log) |
| Stream/grant/termination overlap (ReleaseSafe) | 199/200, 1 platform skip | [overlap.ReleaseSafe.log](overlap.ReleaseSafe.log) |
| Native Windows reader/operation/transport job | Success at `ab2ecc73`, 2m 51s | [native-windows.json](native-windows.json) |

```sh
zig build test-webtransport \
  '-Dtest-filter=WebTransport stream reader admission' -j1 --summary all
```

The overlap keeps the reader and prior operation-admission filters, adding
`WebTransport whole-stream`, `WebTransport incremental`,
`WebTransport automatic grant`, `WebTransport flow`, `WebTransport CONNECT`
and `connection termination`. ReleaseSafe uses the same filters with
`-Doptimize=ReleaseSafe`. Counts include imported support tests.
The skipped overlap is `WebTransport incremental read consumes one UDP GRO
stream batch`: `udpGroSupported()` is Linux-only, so macOS cannot run this
kernel-batching case. The four new owner regressions do not skip.

Native Windows CI includes this filter alongside the prior operation admission
and HTTP/H3 DATAGRAM/WebSocket transport checks. Native evidence is recorded
after the matching source revision's Windows job finishes.

The [native Windows job at `ab2ecc73`](https://github.com/passchaos/netz/actions/runs/45347549331/job/138285824446)
completed successfully in 2m 51s. The public matrix reports success for the
Windows runner, and the run's commit link matches the source revision.
[The snapshot](native-windows.json) records both sources and the exact native
command, which includes all four reader tests and the prior operation-admission
bundle alongside HTTP/H3 DATAGRAM/WebSocket checks. The four reader tests use
zio and have no platform skip. Other workflow jobs have their own status.

[The operation contract](../../../webtransport_operation_admission.md)
describes the public ownership and timeout semantics.
