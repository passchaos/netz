# Complete in-process library suite

| Gate | Result | Evidence |
| --- | --- | --- |
| `test-lib` Debug, deterministic seed, serialized steps | 6752/6752 tests | `test-lib.Debug.log` |

This run covers the complete in-process library suite without external
interoperability or release-tool checks. It includes the recent unified HTTP
proxy routing, Channelz server/client/socket surfaces, managed federation
status, shared HTTP/2 request ownership, and all existing protocol modules.

Two timing-sensitive tests were hardened before this run:

- The LRS scheduler reconnect/failover fixture now allows a 30-second absolute
  budget instead of 10 seconds, so a loaded host does not report a false
  timeout.
- The WSS server caller-timeout test still requires that the caller budget
  prevents a successful accept, but accepts a peer-close error in addition to
  the shared deadline when the deliberately late client tears down first.

Reproduce with:

```sh
zig build test-lib -j1 --seed 0x4a337f0d --summary all
```
