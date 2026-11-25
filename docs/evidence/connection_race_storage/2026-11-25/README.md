# Connection competition parameter storage — 2026-11-25

Every candidate slot stored another copy of its I/O, caller context, deadline
and cancellation event. H3's limits and handshake configuration alone occupy
2,960 bytes on this host. Candidate metadata allocation therefore grew with
both the address count and the context size, even when most addresses never
entered a connection callback.

The race now owns one immutable parameter frame. Each slot stores a reference
to that frame, its target/index and its owned result. Callbacks receive their
context value at transport entry. Selector teardown joins every admitted worker
before closing unselected results or letting the shared frame leave scope.
The callback interface, target ordering and ownership model continue to compose
with TCP, H3 and gRPC connection policies.

Allocation probes compare an empty context, a 4-KiB payload and the actual H3
`Limits` plus `HandshakeClientOptions` types. The result type is `u8`, and every
callback reports refusal without allocating, isolating the competition's slot
and wake storage. Targets and the Threaded backend use a separate allocator.
Each probe checks that every candidate sees the expected payload and target
index, and that all measured allocations are freed.

These are candidate metadata measurements on aarch64 macOS in Debug mode.
Connection objects, crypto state and the shared frame's stack storage are
outside this heap allocation metric.

| Context | Candidates | Before bytes | After bytes | Reduction |
| --- | ---: | ---: | ---: | ---: |
| Empty | 9 | 1,008 | 288 | 71.4% |
| Empty | 64 | 8,224 | 3,104 | 62.3% |
| H3 configuration, 2,960 bytes | 9 | 27,648 | 288 | 99.0% |
| H3 configuration, 2,960 bytes | 64 | 197,664 | 3,104 | 98.4% |
| 4-KiB payload | 9 | 37,872 | 288 | 99.2% |
| 4-KiB payload | 64 | 270,368 | 3,104 | 98.9% |

One/eight-candidate probes allocate no metadata heap storage in either version.
Nine candidates require one allocation, and 64 require two; sharing parameters
reduces allocation sizes without adding a new allocation.

The initial storage-independence expectations fail while the cancellation
ownership checks pass: 58/60 baseline tests pass. After the change, both large
payloads have the same candidate allocation sizes as the empty context. The
ownership probe keeps the first worker blocked until cancellation, then has it
return a successful result; that worker and its cleanup callback both validate
the original payload, and exactly one unselected result is destroyed.

The scoped overlap covers live TCP successful-loser cleanup, deadlines and
external cancellation; H3 dual-family handshakes, total deadlines and zero RTT;
gRPC endpoint competition and owned responses; and the prior admission guards.

| Verification | Result | Evidence |
| --- | --- | --- |
| Candidate allocation baseline | 58/60 passed; two storage expectations fail | [before.Debug.log](before.Debug.log) |
| Allocation measurements | Recorded for 1, 8, 9 and 64 candidates | [metadata.json](metadata.json) |
| Storage, ownership, admission and live TCP/H3/gRPC overlap | 189/189 passed | [Debug.log](Debug.log) |
| Scoped regression compilation for Windows | Compiled | [windows.compile.log](windows.compile.log) |
| Native Linux and Windows storage, lifetime and transport regressions | Passed at `dcb27147` | [native-platforms.json](native-platforms.json) |
