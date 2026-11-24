# Ordered TCP hostname connections — 2026-11-25

The default `.ordered` TCP hostname path delegated to Zig's
`HostName.connect`, whose `connectMany` started a task for every DNS address.
This overlapped candidates despite the policy's one-at-a-time contract, could
return a later success ahead of an earlier fatal failure, and could exhaust
the inline DNS producer's 32-result queue when async quota was zero.

Seven deterministic tests intercept DNS/connect operations while using real
Threaded scheduling and loopback sockets. A slow refused first candidate and
ready second peer prove the unbounded, deadline and endpoint `.ordered` paths
overlap on the baseline. Other regressions cover 40 DNS candidates with zero
async quota, missing concurrent admission before DNS, and a fatal first
candidate. Six fail on the baseline: 22/28 selected tests pass. The first-ready
candidate case passes before and after the change, preserving incremental
connection progress rather than waiting for the complete DNS answer.

A stable-address DNS reader now owns the producer, 16-entry queue and completion
state for both address collection and streaming consumers. Ordered TCP keeps
one native connect active and consumes the next DNS address only after a
retryable failure. Ordinary, explicit source-address and network-interface
connectors share that algorithm. Compatibility source binds wrap the entire
DNS/connection operation in the original deadline; previously only individual
IP connects received it. Each path joins DNS and drains its queue before return,
and late successful results remain owned by the existing TCP deadline selector.

The ordering/streaming regressions pass after the fix: 28/28. A separate zio
fixture sends bytes over IPv4 and IPv6 loopback using compatibility timeout,
compatibility absolute-deadline and unified binding entry points. It checks the
accepted source family, IP and port. The overlap includes native interface binds,
connection cancellation, Happy Eyeballs, H3 system DNS and collector/OOM cases,
and H1/H2/WebSocket hostname and resolver paths. Linux and Windows CI run the
focused hostname cases through the H1 suite.

```sh
zig build test-http1 '-Dtest-filter=TCP ordered hostname' '-Dtest-filter=HTTP/1 client connects by host name' -j1 --summary all
zig build test-http1 test-http2 test-http3 test-websocket test-proxy '-Dtest-filter=TCP ordered hostname' '-Dtest-filter=TCP network interface' '-Dtest-filter=TCP bound connect' '-Dtest-filter=TCP resolved bound connect' '-Dtest-filter=TCP connect deadline' '-Dtest-filter=TCP Happy Eyeballs' '-Dtest-filter=client connects by host name' '-Dtest-filter=HTTP3 system resolver' '-Dtest-filter=HTTP/3 URI address collection' '-Dtest-filter=HTTP/3 URI lookup collector' '-Dtest-filter=HTTP/3 URI hostname resolution' '-Dtest-filter=HTTP3 application resolver' '-Dtest-filter=HTTP/3 shared acquisition deadline' '-Dtest-filter=HTTP/3 shared synchronous acquire' '-Dtest-filter=WebSocket URI resolver' '-Dtest-filter=WebSocket redirect chain retains resolver' '-Dtest-filter=resolve localhost' '-Dtest-filter=resolve rejects' -j1 --summary all
```

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline ordering, admission, fatal-error and queue regressions | 22/28 passed; 6 new cases fail | [before.log](before.log) |
| Strict ordering and first-candidate streaming after the fix | 28/28 passed | [after.log](after.log) |
| TCP/DNS, bindings, Happy Eyeballs and H1/H2/H3/WS/proxy overlap | 310 passed, 8 skipped, 0 failed | [Debug.log](Debug.log) |
| Focused hostname source binding and native IPv6 interface confirmation | 23 passed, 2 expected skips, 0 failed | [binding.log](binding.log) |

The eight overlap skips repeat two existing `127.0.0.2` source-tuple cases
across H1/H2/H3/WebSocket test roots. This macOS loopback has `127.0.0.1` and
`::1`, without a configured `127.0.0.2` alias. The focused confirmation selects
those two cases alongside the new hostname source-binding fixture, the native
IPv6 interface/hostname check and the H1 hostname request/response test; exactly
the two alias cases skip. All new cases execute and pass.

```sh
zig build test-http1 '-Dtest-filter=TCP ordered hostname source binding' '-Dtest-filter=TCP bound connect uses the requested IPv4 source' '-Dtest-filter=TCP resolved bound connect falls back' '-Dtest-filter=TCP network interface name and resolved index constrain IPv6' '-Dtest-filter=HTTP/1 client connects by host name' -j1 --summary all
```
