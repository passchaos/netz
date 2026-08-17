# netz vs `~/Work/websocket.zig` parity audit

This audit records direct evidence for the WebSocket portion of the broader
netz improvement goal. It distinguishes feature coverage from measured hot
paths so a codec microbenchmark is not mistaken for complete server
superiority.

## Feature comparison

| Area | netz | `websocket.zig` reference |
| --- | --- | --- |
| HTTP/1 Upgrade client/server | Covered, including host names, IPv4/IPv6, strict duplicate critical-header checks and upgrade-body rejection | Covered with configurable handshake parsing and handler callbacks |
| WSS client | Covered through the shared TLS transport with host verification and CA policy | Covered; 0.16 README labels the branch experimental |
| HTTP/2 WebSocket (RFC 8441) | Covered through extended CONNECT client/server adapters | Not present in the audited source |
| permessage-deflate | Negotiated and exercised by HTTP/1 and H2 runtimes with no-context-takeover | Server-side support exists; the audited 0.16 client explicitly rejects compression configuration |
| Fragmentation / aggregate limits | Strict assembler and runtime message limits, UTF-8 validation after fragmented text assembly | Fragment assembly and configurable message/buffer limits |
| Close / Ping / Pong | Typed close parsing/writing, close-state guards, automatic Pong and Close replies | Handler callbacks and automatic default control replies |
| Concurrent sends | Serialized by per-connection `std.Io.Mutex` and covered by a runtime test | Documented thread-safe connection writes |
| Linux io_uring experiment | Cleartext client helper | Custom epoll/kqueue/Windows server backends |

The reference has a richer callback-oriented standalone server surface and
pooled-buffer/thread-pool configuration. Netz has broader protocol integration
(shared HTTP/TLS APIs and RFC 8441), but those are different strengths rather
than proof that every server workload is faster.

## Direct frame hot-path evidence

Run:

```sh
zig build bench-websocket-frame -Doptimize=ReleaseFast
```

The 2026-08-17 same-host sample ranges for 200,000 masked 4 KiB binary frames:

```text
netz allocating masked frame:        85-97 ns/op
netz caller-buffer masked frame:      71-82 ns/op
netz header-only stream preparation:  0.54-0.56 ns/op
websocket.zig header + copy/mask:      101-127 ns/op
```

The reference measurement calls `proto.writeFrameHeader`, copies the immutable
payload into scratch, then calls its SIMD `proto.mask`. Copying is required for
an equivalent contract: the reference client API accepts `[]u8` and masks it
in place, while netz accepts `[]const u8` and preserves caller memory.

Netz's actual unmasked TCP server path prepares only the validated stack header
and uses one vectored network write for header + borrowed payload. Masked
clients copy and mask in one SIMD pass through a fixed 16 KiB stack scratch,
so payload size no longer drives heap allocation.

## Remaining evidence before a broad completion claim

1. Add an end-to-end concurrent echo/load benchmark with the same payload mix,
   connection count, socket settings and client driver for both projects.
2. Compare buffer-pool behavior and peak memory under many mostly-idle
   connections; the reference exposes explicit small/large buffer pools.
3. Add Autobahn/WebSocket protocol-suite evidence for both implementations
   rather than relying only on in-repository tests.
4. Measure compressed workloads once a truly compressing streaming encoder is
   available; netz currently prioritizes RFC 7692 interoperability over ratio.
