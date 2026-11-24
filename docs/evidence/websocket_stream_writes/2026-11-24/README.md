# WebSocket byte-stream write failures, 2026-11-24

Base revision: `7b8723d0`, Zig 0.16.0, macOS aarch64.

A generic transport callback returns `!void`, so an error cannot describe how
much of a frame was emitted. The server scatter fallback made the defect
observable: it successfully wrote `81 04`, then the first payload write emitted
`61` and failed. The adapter still accepted another send, which would append a
new frame header inside that incomplete four-byte text payload.
[The baseline regression](prefix-before.log) fails at the expected rejection
of that later send.

Complete-write callback invocation is now centralized in
`websocket/stream_connection/writes.zig`. An invoked callback error preserves
its original error and retires the transport. A capability/deadline rejection
or encoding OOM before callback invocation remains retryable. After a scatter
header succeeds, later preflight failure is also terminal. The adapter retains
input, output and assembler storage until deinit and hides buffered frames
after failure.

Lifecycle flags keep their existing bool storage and use atomic accessors.
Close is committed under the write mutex, and every queued writer rechecks
state after acquiring it. A deterministic regression observes the second
writer's futex wait before releasing the first callback; it covers data,
scatter and repeated Close behind both a successful Close and a failed write.
`abort()` closes the supplied transport at most once without appending a frame.
`peerClose()` observes metadata after receive-side publication.

| Gate | Result | Artifact |
| --- | --- | --- |
| Baseline partial-header regression | Expected failure, 8/9 including support tests | [prefix-before.log](prefix-before.log) |
| Adapter lifecycle cases (Debug) | 36/36 | [adapter.Debug.log](adapter.Debug.log) |
| Adapter lifecycle cases (ReleaseSafe) | 36/36 | [adapter.ReleaseSafe.log](adapter.ReleaseSafe.log) |
| Callback-prefix and independent bounded-callback checks (Debug) | 9/9 | [callback-shapes.Debug.log](callback-shapes.Debug.log) |
| Callback-prefix and independent bounded-callback checks (ReleaseSafe) | 9/9 | [callback-shapes.ReleaseSafe.log](callback-shapes.ReleaseSafe.log) |
| Windows test compilation and linking | 8/8 steps | [windows-compile.log](windows-compile.log) |
| Public package surfaces | 25/25 | [public-package.log](public-package.log) |

Counts include imported support tests and overlap. Error-shape coverage checks
staged server/client frames, header-plus-payload and arbitrary-slice callbacks,
bounded/unbounded sends, WriteFailed/Timeout/Canceled, and exact emitted prefix
lengths. The bounded vector callbacks are deliberately supplied without their
unbounded counterparts. Other cases cover automatic Pong, retained peer Close
metadata, header-success followed by budget expiration, validation/encoding
retry, close-once teardown and already-buffered input.

```sh
zig build test-websocket '-Dtest-filter=WebSocket stream adapter' --summary all
zig build test-websocket '-Dtest-filter=WebSocket stream adapter' \
  -Doptimize=ReleaseSafe --summary all
zig build test-websocket '-Dtest-filter=retires every invoked write callback error' --summary all
zig build test-websocket '-Dtest-filter=retires every invoked write callback error' \
  -Doptimize=ReleaseSafe --summary all
zig build test-compile '-Dtest-filter=WebSocket stream adapter' \
  -Dtarget=x86_64-windows --summary all
zig build test-package '-Dtest-filter=public' --summary all
```

The native Windows CI job now runs both focused HTTP metadata and generic
WebSocket adapter tests. The [public contract](../../../websocket_stream_adapter.md)
explains the stronger failure behavior and lifecycle snapshots.

## Next admission review

Source inspection also found that generic send paths do not apply
`Options.max_frame_bytes`/`max_message_bytes`, and receive message limits are
applied by the assembler after frame decoding. Those admission and allocation
boundaries still need a separate correctness/performance pass; this write
lifecycle change does not establish them as complete.
