# netz vs `~/Work/websocket.zig` parity audit

This audit records direct evidence for the WebSocket portion of the broader
netz improvement goal. It distinguishes feature coverage from measured hot
paths so a codec microbenchmark is not mistaken for complete server
superiority.

## Feature comparison

| Area | netz | `websocket.zig` reference |
| --- | --- | --- |
| HTTP/1 Upgrade client/server | Covered, including host names, IPv4/IPv6, strict duplicate critical-header checks and upgrade-body rejection | Covered with configurable handshake parsing and handler callbacks |
| WSS client/server | Covered through shared TLS transports with host/CA verification, optional client identities, caller-provided server identities, optional/required client certificates, verified peer chains and concurrent serving | Client covered; 0.16 README labels the branch experimental, while the audited server API terminates cleartext WebSocket |
| HTTP/2 WebSocket (RFC 8441) | Covered through extended CONNECT client/server adapters | Not present in the audited source |
| permessage-deflate | Negotiated and exercised by HTTP/1 and H2 runtimes with no-context-takeover, actual LZ77/Huffman compression and expansion fallback | Negotiation/decompression exists, but audited 0.16 client/server send compression code is disabled |
| Fragmentation / aggregate limits | Strict assembler and runtime message limits, UTF-8 validation after fragmented text assembly | Fragment assembly and configurable message/buffer limits |
| Receive/send ownership | `parseFrameInto` and `receiveMessageInto` use caller storage, including permessage-deflate output with reusable connection scratch; `sendBinaryInPlace` explicitly offers the reference's mutable post-send contract while safe `[]const u8` sends remain available | Reader returns borrowed payloads and allocates/pools compressed output; client send APIs require mutable payloads and leave them masked |
| Close / Ping / Pong | Typed close parsing/writing, close-state guards, automatic Pong and Close replies | Handler callbacks and automatic default control replies |
| Concurrent sends | Serialized by per-connection `std.Io.Mutex` and covered by a runtime test | Documented thread-safe connection writes |
| TCP/TLS latency policy | TCP_NODELAY defaults on for ordinary accepted and client TCP/WSS sockets; WSS header + first payload bytes fill one TLS record/network write; configurable in runtime limits/connect options | Server enables NODELAY, audited client leaves Nagle enabled unless the embedding application changes the socket |
| Linux io_uring experiment | Cleartext client helper | Custom epoll/kqueue/Windows server backends |

`websocket.runtime.TlsServer` performs TLS 1.3 before the same transport-neutral
HTTP Upgrade parser and frame state machine used by cleartext `Server`.
End-to-end tests cover verified localhost CA/SAN, strict subprotocol selection,
encrypted binary echo, public-client mTLS with server pin verification and
application-visible client certificate chains, and the shared close/ownership
path. Setting `ConnectOptions.tls_identity` on the existing TLS host/URI
helpers selects the same vail stream transport as native MQTT TLS; absent a
pin/custom verifier, it maps caller CA bundles or system roots plus hostname
verification. TLS
client reads are true short reads, so a small Upgrade response no longer waits
for a caller's larger scratch buffer to fill.

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

The same command also measures one 4 KiB repeated telemetry-like message
through no-context-takeover compression. Complete and discontiguous messages
now use project-local vort fixed-DEFLATE sync-flush encoders, whose small-input
hash paths avoid clearing Zig flate's roughly 224 KiB compressor state per
message. The chunked encoder keeps plaintext discontiguous and deliberately
limits match search to each caller slice.

```text
permessage-deflate: 5.45-5.51 us/message, 4096 -> 69 wire bytes
16-slice streaming: 8.28-8.37 us/message, 4096 -> 463 wire bytes, no join
```

These are three stable CPU-14-pinned `ReleaseFast` runs on 2026-08-20; a
separate cold/noisy sample was 5.81/9.62 us. Compared with the previous standard-
library encoder baseline, the fragmented path is 6.1-6.2x faster, while its
slice-local match search makes the wire payload larger (463 versus 54 bytes).
This is an explicit speed/ratio trade-off rather than a claim that boundaries
are free. This remains an internal encoder baseline and compression-ratio
example, not a cross-library
speed ratio: the audited websocket.zig 0.16 send paths currently hard-code
`compressed = false`, so no equal compressed-send workload exists there.

## Persistent echo evidence

The end-to-end benchmark uses one real HTTP/1 upgraded connection, 20 untimed
warmup exchanges, then 200 measured 4 KiB binary echo round trips. Client
requests are masked, server replies are unmasked, both wire frames use minimal
16-bit extended lengths, and both clients copy the echoed application payload
back into their mutable send buffer before the next round. Handshake time is
excluded. This evidence covers the ordinary TCP runtime, not the separate
io_uring adapter.

The same executable accepts `--compression`, negotiating permessage-deflate on
both endpoints and exercising retained send/receive scratch plus direct caller-
buffer inflation over a real upgraded connection. Five 2026-08-20 CPU-0 runs
measured 29.44-31.14 us/roundtrip (250.91-265.34 logical payload MiB/s),
4.6-5.0x lower latency than the previous 144.6-147.5 us range. Three four-
connection CPU 0-7 runs measured 12.09-12.18 us aggregate/roundtrip and
641.52-645.95 logical MiB/s, versus the previous 45.96 us/169.98 MiB/s. These
are internal compressed-runtime baselines because the
audited websocket.zig outbound compressor remains disabled.

The first compressed frame is copied once from the transport/caller frame
buffer into retained compressed scratch. This is intentional: Zig's raw
inflater may overwrite output before consuming aliased input. A regression test
checks that scratch holds the exact wire payload before caller-buffer inflate.

Netz uses `sendBinaryInPlace` and `receiveMessageInto`; the former deliberately
leaves caller storage masked, matching websocket.zig's mutable-input contract,
while the latter assembles fragments and handles control frames without a
message allocation. With permessage-deflate, the decompressed message lands
directly in the caller buffer. TCP and RFC 8441 connections retain bounded
compressed-wire scratch plus a reusable receive DEFLATE history window. Both
complete and fragmented sends use vort's native raw fixed-block sync flush;
the fragmented form emits one block per non-empty caller slice without joining
plaintext. Both paths remove the RFC 7692 suffix and set RSV1 only when the
wire payload is strictly smaller; incompressible/small input is sent unchanged rather than
paying expansion, and payloads below 32 bytes skip compressor setup entirely.
No-context-takeover resets codec state for every message
while retaining wire buffers. Vort's current hash parser allocates temporary
match state per compressed send; receive-side codec storage is allocation-free
after first-use warmup. The H2 adapter still owns tunnel-frame/message scratch
but avoids separate compression-output/decompressed-message allocations.
Fragmented compressed sends no longer concatenate plaintext first: each caller
slice feeds the same bit-packed DEFLATE stream directly, UTF-8 is validated
across slice boundaries with four bytes of state, and only compressed wire
scratch remains. A wire-level regression also verifies that requested frame
count/FIN boundaries survive compression and only the first frame carries RSV1.
Tests cover a zlib-generated dynamic-DEFLATE fixture, fragmented compressed
text with interleaved PING, send/receive scratch reuse under failing allocators,
actual wire shrink plus RSV1, expansion fallback without RSV1, output overflow,
and H2 compressed caller storage in both directions.
One four-connection `--stats` run made 7,151 allocations, allocated 48,068,236
cumulative bytes and peaked at 1,240,114 live bytes while verifying checksum
111,600. The high steady allocation count is now dominated by vort's one-shot
token/output ownership and remains the next compression-memory target; it is
reported rather than hidden by the latency result.

```sh
taskset -c 0 zig build bench-websocket-echo -Doptimize=ReleaseFast

zig build-exe -OReleaseFast -lc --dep websocket \
  -Mroot=benchmarks/reference/websocket_zig_echo.zig \
  --dep build \
  -Mwebsocket=/home/passchaos/Work/websocket.zig/src/websocket.zig \
  -Mbuild=benchmarks/reference/websocket_zig_build_options.zig \
  -femit-bin=/tmp/bench-websocket-zig-echo
taskset -c 0 /tmp/bench-websocket-zig-echo --tcp-nodelay
```

Twenty alternating CPU-0 samples with TCP_NODELAY enabled on both clients:

```text
netz:
  9.146-10.537 us/roundtrip
  median 9.501 us, trimmed mean 9.539 us

websocket.zig:
  13.231-14.406 us/roundtrip
  median 13.630 us, trimmed mean 13.702 us

netz latency advantage:
  1.435x by median, 1.436x by trimmed mean
```

The websocket.zig public client defaults to Nagle enabled and writes its masked
header then payload separately. Five default-socket samples were about
41.09-41.38 ms/roundtrip, while netz's vectored header+payload submission was
10.26-10.71 us in that run. This roughly 3,915x cliff is specifically Linux
Nagle/delayed-ACK interaction, not a broad library ratio. `strace -f -c`
recorded about 442 netz sendmsg calls versus 443 reference sendmsg plus 228
writev calls for 220 total exchanges. The tuned TCP_NODELAY comparison above is
the primary implementation result.

### Four concurrent persistent connections

The same benchmark accepts `--connections=4`. All clients finish 20 warmup
exchanges, wait on one start event, then execute 200 measured round trips each.
Aggregate latency divides wall time to the slowest client by all 800 measured
round trips; handshake, warmup, shutdown, and joins remain outside the timed
interval. Both processes were restricted to CPUs 0-7.

```sh
taskset -c 0-7 zig build bench-websocket-echo \
  -Doptimize=ReleaseFast -- --connections=4
taskset -c 0-7 /tmp/bench-websocket-zig-echo \
  --tcp-nodelay --connections=4
```

Twenty alternating samples:

```text
netz:
  3.788-4.802 us aggregate/roundtrip
  median 4.150 us, trimmed mean 4.173 us
  median 240,993 roundtrips/s, 1,885.51 wire MiB/s

websocket.zig:
  4.912-5.653 us aggregate/roundtrip
  median 5.212 us, trimmed mean 5.221 us
  median 191,883 roundtrips/s, 1,501.28 wire MiB/s

netz aggregate-latency advantage:
  1.256x by median, 1.251x by trimmed mean
```

One `strace -f -c` run recorded about 1,768 netz `sendmsg` calls. The
reference recorded about 1,772 `sendmsg` plus 892 `writev` calls: its client
still sends mask/header separately from payload. Tracing perturbs latency, so
these counts explain submission shape but are not timing samples.

## Remaining evidence before a broad completion claim

1. Extend the now-equal-shape 1/4-connection benchmark to mixed payload
   distributions and higher connection counts.
2. Compare buffer-pool behavior and peak memory under many mostly-idle
   connections; the reference exposes explicit small/large buffer pools. The
   netz echo benchmark now accepts `--stats` and reports thread-safe allocation
   counts, cumulative bytes, peak live bytes and size buckets. Four cleartext
   connections used 54 allocations and 52,784 peak live bytes in the captured
   smoke; one connection used 15 allocations and 13,196 peak live bytes. Four
   compressed connections used 106 allocations and 1,139,720 peak live bytes,
   dominated by sixteen retained 64-KiB codec windows. Add equal telemetry to
   the websocket.zig harness and extend beyond 16 mostly-idle connections before
   making a memory ratio. The fixed 16-connection benchmark bookkeeping has
   since been replaced by bounded dynamic arrays and the cap raised to 256. A
   32-connection cleartext smoke completed 6,400 measured round trips with 423
   allocations and 425,312 peak live bytes (about 13.0 KiB/connection including
   both client and server runtime state plus benchmark coordination). A 64-
   connection run exceeded the practical duration of this same-process smoke
   on the current host, so it is not counted as passing evidence.
3. Add Autobahn/WebSocket protocol-suite evidence for both implementations
   rather than relying only on in-repository tests.
4. Add an equal-wire compressed echo comparison if the reference re-enables
   its currently disabled outbound compressor; until then the netz timing is
   only an internal baseline.
