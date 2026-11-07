# Complete in-process suite after Channelz

| Gate | Result | Evidence |
| --- | --- | --- |
| `test-lib` Debug, deterministic seed, serialized steps | 6757/6757 tests | `test-lib.Debug.log` |

This run covers the complete in-process library suite after the Channelz
server/client/socket/subchannel/trace work, official grpc-js interop, and the
automatic server-call observer. It also includes the earlier HTTP proxy,
managed federation status, and shared HTTP/2 request-owner changes.

The WSS caller-timeout fixture now gives the client TLS handshake enough time
under host load while still proving the caller budget spans TLS and the
incomplete HTTP upgrade: the caller budget is 2 seconds and the client delays
the HTTP request by 1.5 seconds. The server TLS/HTTP handshake timeouts remain
longer (5 seconds), so only the caller-owned budget can end the attempt.

Reproduce with:

```sh
zig build test-lib -j1 --seed 0x4a337f0d --summary all
```
