# Automatic Channelz counters for high-level gRPC channels

`grpc.Channel` and `grpc.SharedChannel` now accept the same allocation-free
Channelz observer as the runtime client and server. The observer is opt-in:

```zig
const info = try registry.addChannel("frontend", "dns:///backend:443");
var channel = try grpc.Channel.init(allocator, io, target, .{
    .observer = info.observer(),
});
var shared = try grpc.SharedChannel.init(allocator, io, target, .{
    .observer = info.observer(),
});
```

`Channel` reports one started event and one terminal event for each logical
unary call, including all retry attempts inside that call, and the same pair for
each streaming or duplex stream. `SharedChannel` reports each sender unary call
and each duplex stream. OK terminal responses increment `calls_succeeded`;
non-OK statuses, resets, cancellation and transport failures increment
`calls_failed`.

SharedChannel's child transport channels and the ordinary Channel's internal
Health Watch transport explicitly drop the observer, so internal or duplicated
calls cannot inflate application counters.

| Gate | Result | Evidence |
| --- | --- | --- |
| Focused Channelz Debug | 183/183 tests | `channelz.Debug.log` |
| Focused gRPC Debug | 1059/1059 tests | `grpc.Debug.log` |
| Full library Debug | 6762/6762 tests | `full.Debug.log` |
| Compile | passed | `zig build test-compile` |

The new regressions in `src/grpc/channelz_tests.zig` drive two unary calls (one
OK and one `NOT_FOUND`) and one OK duplex stream through both a high-level
`Channel` and a `SharedChannel`. Each fixture asserts `calls_started = 3`,
`calls_succeeded = 2` and `calls_failed = 1` from a registry-backed Channelz
channel. Source hashes and exact commands are in `gates.json`.

Reproduce with:

```sh
zig build test-lib -Dtest-filter=Channelz --summary all
zig build test-lib -Dtest-filter=grpc --summary all
zig build test-compile
```
