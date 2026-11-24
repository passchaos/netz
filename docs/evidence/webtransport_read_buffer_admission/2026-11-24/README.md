# WebTransport read buffer admission, 2026-11-24

Base revision: `2884b0cc`, Zig 0.16.0, macOS aarch64.

[The baseline](admission-before.log) records three failures, 105/108 passing
including imported support tests. Empty incremental polls can produce a
zero-byte nonterminal data event, select incremental reader mode before any
payload delivery, and consume RESET or zero-byte FIN notifications. Public
read/poll facades inspect Session lifecycle before rejecting empty storage.
The callback-owner precedence case already passes on the base.

`stream/read_buffer.zig` now supplies one nonempty-output check. Incremental
read and all ordinary/one-attempt/shared poll paths validate before stream
association, cursor/reader-mode changes or terminal-event delivery. Public
client/server read and poll facades validate after their owner guard and before
lifecycle observation or deferred cleanup. Deadline and callback precedence
retain their existing behavior.

The protected-UDP tests cover both endpoint roles, three lower-level poll
forms, seven public read/poll forms and callback rejection. An empty poll leaves
a FIN-complete stream available to the whole reader. Invalid storage preserves
RESET and EOF events for a later valid poll; that valid EOF still reports zero
bytes with `fin = true`. Flow violation observation and socket packet numbers
remain untouched on empty-buffer rejection. The common buffered-stream fixture
is shared with the previous reader-owner regressions.

| Gate | Result | Artifact |
| --- | --- | --- |
| Three buffer admission regressions | Expected failures, 105/108 passing | [admission-before.log](admission-before.log) |
| Buffer and prior reader-owner cases (Debug) | 112/112 | [reader.Debug.log](reader.Debug.log) |
| Incremental/whole/shared/credit/termination overlap (Debug) | 207/208, 1 platform skip | [overlap.Debug.log](overlap.Debug.log) |
| Incremental/whole/shared/credit/termination overlap (ReleaseSafe) | 207/208, 1 platform skip | [overlap.ReleaseSafe.log](overlap.ReleaseSafe.log) |

The overlap includes the new buffer, prior reader-owner and operation-owner
filters plus `WebTransport whole-stream`, `WebTransport incremental`,
`WebTransport shared endpoint`, `WebTransport buffered`,
`WebTransport automatic grant`, `WebTransport flow`, `WebTransport CONNECT`
and `connection termination`. ReleaseSafe uses the same scope with
`-Doptimize=ReleaseSafe`. Counts include imported support tests. The skip is
`WebTransport incremental read consumes one UDP GRO stream batch`, which is
Linux-only; the four buffer test groups do not skip.

```sh
zig build test-webtransport \
  '-Dtest-filter=WebTransport stream read buffer admission' \
  '-Dtest-filter=WebTransport stream reader admission' -j1 --summary all
```

Native Windows CI includes the new buffer filter alongside existing operation/
reader admission and HTTP/H3 DATAGRAM/WebSocket checks. Native evidence is
recorded after the matching source revision's Windows job finishes.

[The public operation contract](../../../webtransport_operation_admission.md)
documents the buffer requirement and retained terminal-event semantics.
