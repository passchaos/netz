# Complete in-process suite after client Channelz observers

| Gate | Result | Evidence |
| --- | --- | --- |
| `test-lib` Debug, deterministic seed, serialized steps | 6758/6758 tests | `test-lib.Debug.log` |

This run covers the complete in-process suite after adding automatic Channelz
observers for both servers and the low-level connected client. It includes the
Channelz channel/subchannel/server/socket/trace surface, official grpc-js
interop, the HTTP proxy route, managed federation status, and shared HTTP/2
request ownership.

Reproduce with:

```sh
zig build test-lib -j1 --seed 0x4a337f0d --summary all
```
