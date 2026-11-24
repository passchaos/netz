# Closed extension streams after association teardown, 2026-11-24

Base revision: `101381bd`, Zig 0.16.0, macOS aarch64.

[The baseline](closed-before.log) fails with `StreamCreationError`, 104/105
passing including imported support tests. A server-initiated extension bidi
completes FIN in both directions, its delivery is ACKed, and QUIC compacts its
send/receive entries into closed-ID history. After the last detached association
is removed, a fresh authenticated packet carrying old STREAM or RESET reaches
H3 message classification, which rejects the server stream ID despite QUIC
already having retired it.

The server request validator now exposes the generic `streamClosed` query.
Request routing filters retired local and peer STREAM/RESET before detached
association checks or message-role classification. Active extension ownership
and ordinary H3 role validation keep their existing paths. STOP retains its
request-lifecycle cancellation behavior.

The real protected-UDP test drains both directions to FIN, waits for ACK-driven
local stream compaction, asserts both active entries are gone, then removes the
last association. It injects late STREAM and RESET with a new packet number and
sends a normal GET immediately afterward. The GET is received, the connection
stays open and the old send/receive entries remain absent. Active reverse
STREAM/RESET/STOP cases from the prior target-event bundle overlap this check.

The source audit also confirms that send half-close retains live bidi state
until receive completion permits reclamation, and that closed-ID history is
inserted before removing active entries. The routing guard therefore does not
need a separate extension tombstone or an association kept alive indefinitely.

| Gate | Result | Artifact |
| --- | --- | --- |
| Late closed extension baseline | Expected failure, 104/105 passing | [closed-before.log](closed-before.log) |
| Closed and active extension cases (Debug) | 108/108 | [closed.Debug.log](closed.Debug.log) |
| QUIC retirement/H3 role/CONNECT/extension overlap (Debug) | 324/324 | [overlap.Debug.log](overlap.Debug.log) |
| QUIC retirement/H3 role/CONNECT/extension overlap (ReleaseSafe) | 324/324 | [overlap.ReleaseSafe.log](overlap.ReleaseSafe.log) |
| Native Windows closed extension/transport job | Success at `b89c762f`, 3m 17s | [native-windows.json](native-windows.json) |

The overlap includes closed/local stream and recovery checks, H3 strict server-
bidi rejection and CONNECT DATAGRAM cases, and WTP CONNECT/target event cases.
Counts include imported support tests and repeated dependency cases across
protocol roots. ReleaseSafe uses the same scope with `-Doptimize=ReleaseSafe`.

```sh
zig build test-webtransport \
  '-Dtest-filter=WebTransport closed extension routing' \
  '-Dtest-filter=WebTransport stream read target admission' -j1 --summary all
```

Native Windows CI includes the closed-extension filter alongside the previous
transport, ownership and target-event checks. Its result is recorded after the
matching source revision's Windows job finishes.

The [native Windows job at `b89c762f`](https://github.com/passchaos/netz/actions/runs/45360231099/job/138328299278)
completed successfully in 3m 17s. The public matrix success label identifies
the Windows runner and the run's commit link matches the source revision.
[The snapshot](native-windows.json) records those sources and the exact native
command. The late extension case uses zio with no platform skip. Other workflow
jobs have their own status.

[Stream target and lifetime contracts](../../../stream_target_events.md)
describe active extension routing and authoritative closed-stream history.
