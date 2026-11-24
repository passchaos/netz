# WebSocket frame admission and input ownership, 2026-11-24

Base revision: `6d3e4fd6`, Zig 0.16.0, macOS aarch64.

Three baseline regressions fail: an outbound three-byte payload bypasses a
two-byte message limit; a seven-byte masked frame delivered one byte at a time
hits EOF while waiting for a fourteen-byte header; and an oversized
continuation header reads for a body instead of rejecting the declared
aggregate length. [The baseline log](admission-before.log) records all three.

`stream_connection/admission.zig` now owns outbound wire/message limits,
inbound header/message admission, exact incoming header lengths and the
read-ahead window. Outbound staging, masking, UTF-8 scanning and callbacks
follow admission. Frame limits include length-encoding and mask bytes; message
limits apply to application data, while control traffic retains its independent
125-byte RFC cap and still obeys the wire-frame limit.

The shared assembler exposes non-mutating header admission for association,
RSV continuation rules and aggregate message length. Generic readers call it
before requesting the remaining payload and before the owned payload copy.
Small application budgets cap wire read-ahead at the control/application
window; existing spare capacity is reused before a bounded amortized growth.
Default budgets retain the 16 KiB read batch preference.

The receive cursor is committed only after control handling or assembly
succeeds. Allocation failures at wire reservation, payload copy and fragmented
assembly preserve raw input and the accepted prefix. Header/body timeouts and
an automatic Pong rejected before its callback likewise remain retryable.
Malformed headers, message oversize and invalid UTF-8 produce the appropriate
1002/1009/1007 Close when possible, then retire the transport. EOF also becomes
terminal, and local protocol errors do not fabricate a received peer Close.

| Gate | Result | Artifact |
| --- | --- | --- |
| Baseline admission cases | Expected failures, 8/11 including support tests | [admission-before.log](admission-before.log) |
| Generic adapter and assembler (Debug) | 58/58 | [admission.Debug.log](admission.Debug.log) |
| Generic adapter and assembler (ReleaseSafe) | 58/58 | [admission.ReleaseSafe.log](admission.ReleaseSafe.log) |
| Existing native H1/H2/H3 allocation-failure overlap | 96/96 | [runtime-overlap.Debug.log](runtime-overlap.Debug.log) |
| Windows test compilation and linking | 8/8 steps | [windows-compile.log](windows-compile.log) |
| Native Windows metadata/adapter job at `8de454c2` | Success, 3m 36s | [CI job](https://github.com/passchaos/netz/actions/runs/45331030845/job/138232163030), [metadata](native-windows-ci.json) |

Counts include imported support tests and overlap. Tests cover masked/unmasked
roles, staged/vector/scatter callbacks, bounded and unbounded sends, empty and
125/126/65535/65536-byte header transitions, all incoming header widths,
malformed header-only input, exact limits, zero-budget control traffic,
continuation admission, allocation-failure sweeps and timeout/control retries.
An advertised 1 MiB payload with a two-byte message budget is rejected after its
header: the test observes one bounded staging allocation, no payload copy or
body fetch, and a 139-byte maximum staging capacity.

```sh
zig build test-websocket '-Dtest-filter=WebSocket stream adapter' \
  '-Dtest-filter=WebSocket message assembler' --summary all
zig build test-websocket '-Dtest-filter=WebSocket stream adapter' \
  '-Dtest-filter=WebSocket message assembler' -Doptimize=ReleaseSafe --summary all
zig build test-websocket '-Dtest-filter=message allocation failure preserves' --summary all
zig build test-compile '-Dtest-filter=WebSocket stream adapter' \
  '-Dtest-filter=WebSocket message assembler' -Dtarget=x86_64-windows --summary all
```

The native Windows CI job runs the generic adapter filter and completed
successfully at `8de454c2` in 3m 36s. The same run's AArch64 and x86_64 Linux
compile jobs also succeeded. Native job success was verified through the
public workflow matrix panel; no unobserved Windows test count is claimed. The [public contract](../../../websocket_stream_adapter.md) documents
bidirectional limits, control exceptions and input ownership.
