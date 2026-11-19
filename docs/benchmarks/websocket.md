# WebSocket frame encoding comparison

[Back to the benchmark index](../benchmark-baseline.md).

## WebSocket frame encoding comparison

The current frame benchmark obtains its monotonic clock from zio-backed
`std.Io` and prints `io backend: zio-std-io`. The H1, RFC 8441, and RFC 9220
self-echo benchmarks use the same backend for both endpoints; their local
servers and concurrent H1 clients run as `std.Io` tasks, and structured result
records require `client_io=zio-std-io server_io=zio-std-io`. Numeric results in
this WebSocket section that do not explicitly say they were rerun after the
2026-09-15 migration remain historical `std.Io.Threaded` evidence.

Captured on 2026-08-17 in `ReleaseFast` with 200,000 masked 4 KiB binary
frames. The payload length and first mask byte vary per iteration so the
compiler cannot fold frame generation out of the loop.

```sh
zig build bench-websocket-frame -Doptimize=ReleaseFast
```

Representative netz samples:

```text
allocating masked frame:       85-97 ns/op
caller-buffer masked frame:    71-82 ns/op
header-only stream preparation: 0.54-0.56 ns/op
```

The same command now includes retained RFC 7692 no-context-takeover complete
and 16-slice compressor cases. Three CPU-14-pinned 2026-08-20 samples encoded
a repeated 4 KiB telemetry-like message in 5.55-5.88 us and reduced its wire
payload from 4,096 to 69 bytes. The discontiguous path took 5.77-6.10 us
without a plaintext join and produced 69 bytes using a bounded 16 KiB rolling
dictionary and one fixed block shared across all slices. Versus the prior
standard-library 51.10 us fragmented baseline, this is an 8.4-8.9x latency
improvement. It also recovers the first slice-local vort path's 463-byte wire
payload completely relative to the complete-message vort path. This is an
internal baseline rather than a reference ratio:
the audited websocket.zig 0.16 outbound compression paths currently force
`compressed = false`.

On 2026-09-30, a CPU-0-pinned `ReleaseFast` fixed-binary A/B measured the
package-local encoder after replacing its byte-at-a-time contiguous match
scan with a two-block SIMD prefix scan. Seven alternating pairs produced:

```text
                              range (us/message)  median
baseline                      5.516-5.549         5.526
SIMD contiguous match scan    4.195-4.215         4.203
candidate/baseline paired ratio                  0.7605

16-slice control baseline     10.090-10.116       10.102
16-slice control candidate    10.098-10.119       10.100
```

All seven complete-message pairs favored the candidate, a 23.9% median
reduction. Every run retained the 69-byte wire payload and checksum
`8351760000`; this first A/B left the 16-slice discontiguous cursor path
unchanged. The ignored evidence directory
`zig-out/websocket-vort-match-ab/` contains the paired log and the exact
5,546,296-byte baseline plus 5,548,344-byte candidate binaries. Their SHA-256
identities are `8224fa43e4b178284c26f7d2d62ad42377b3f934cee3d69c147133ae378f37ab`
and `c12e8a08229218e57c7eafa1cad9d86ede228980697e0e4706fe3afdd4f8db36`.

A second 2026-09-30 fixed-binary A/B applies the same SIMD prefix comparison
to each pair of currently contiguous spans in the chunk cursors. It does not
join plaintext, and it advances the two cursors independently across unequal
slice boundaries and empty slices. Seven alternating CPU-0 pairs produced:

```text
                              range (us/message)  median
16-slice baseline             10.101-10.120       10.112
16-slice SIMD span scan        5.814-5.908         5.818
candidate/baseline paired ratio                   0.5758

contiguous baseline            4.197-4.222         4.200
contiguous candidate           4.199-4.204         4.201
contiguous paired ratio                            1.0000
```

All seven fragmented pairs favored the candidate, a 42.4% median reduction,
while the previously optimized contiguous control remained neutral. Every run
retained the 69-byte wire payload and checksum `8351760000`. The exact
5,548,344-byte baseline, 5,550,616-byte candidate, and final paired log are in
`zig-out/websocket-vort-chunk-match-ab/`; their SHA-256 identities are
`c12e8a08229218e57c7eafa1cad9d86ede228980697e0e4706fe3afdd4f8db36`,
`8a7f7bc3bc9a55a335f37c5471d9432aca8e9e1b0b7abf873f08dd48b458d97e`,
and `70d549525df781433c18cfdf6abda7c3d67d932db4c419df20165f80549fd47b`.

The caller-buffer path copies and masks in one SIMD pass and preserves the
caller's `[]const u8`. Binary sends additionally accept arbitrary borrowed
application slices while retaining one FIN-terminated WebSocket frame. The
header-only path is what unmasked server sends use: HTTP/1 submits bounded
header/payload vectors directly, and HTTP/2/HTTP/3 preserve the ordered slices
through their tunnel/body writers without a payload-sized plaintext join. WSS
coalesces slices into bounded TLS records; clients mask fixed stack chunks
while carrying the mask phase across every slice. Negotiated compression also
consumes the slice list as one logical message.

### Native WebSocket caller join versus direct slices

Captured on 2026-09-09 with the dedicated H1/H2/H3 self-echo gate:

```sh
zig build bench-websocket-slices-ab -Doptimize=ReleaseFast
```

The default gate pins the process to the smallest CPU in its allowed affinity
set (CPU 0 for this run), alternates `contiguous` and `slices` execution order,
and takes the median of five samples. Each sample performs 20 warmups followed
by 1,000 measured round trips with one persistent connection, no compression,
and one 4,096-byte FIN binary frame divided into eight application slices at
both endpoints. `contiguous` joins those slices into a caller-owned
preallocated buffer before immutable `sendBinary`; `slices` calls
`sendBinarySlices` directly. Neither shape uses WebSocket continuation-frame
fragmentation.

| Transport | Caller-joined median/round trip | Direct-slices median/round trip | slices / contiguous |
|---|---:|---:|---:|
| HTTP/1 upgrade | 10.391 us | 10.476 us | 1.008 |
| RFC 8441 over h2c | 11.029 us | 11.056 us | 1.002 |
| RFC 9220 over H3 | 86.039 us | 87.952 us | 1.022 |

The 2026-09-15 zio rerun used the same CPU-0, five-sample alternating shape,
20-warmup/1,000-measured, 4-KiB/eight-part configuration. Every record
identified both endpoints as `zio-std-io`, transferred 8,192,000 logical bytes,
and produced checksum 255,000:

| Transport | Caller-joined range; median | Direct-slices range; median | slices / contiguous |
|---|---:|---:|---:|
| HTTP/1 upgrade | 15.837-16.359 us; 16.042 us | 16.200-18.181 us; 16.530 us | 1.030 |
| RFC 8441 over h2c | 16.941-17.384 us; 17.057 us | 17.169-17.575 us; 17.340 us | 1.017 |
| RFC 9220 over H3 | 136.130-144.065 us; 138.932 us | 137.948-142.750 us; 141.480 us | 1.018 |

These are internal API-shape comparisons, not cross-library results. The older
table above remains useful as historical Threaded evidence; it must not be
combined with the zio ranges.

Every input sample reported 8,192,000 logical bytes and checksum 255,000. The
strict verifier also requires the exact protocol/transport, persistent
self-role pair, shape, part count, warmup/iteration count, fixed payload
schedule, disabled compression, and completion marker; it rejects missing or
even sample sets. There is deliberately no performance threshold. On this
host and workload direct slices were within 2.2% of caller joining across all
three transports while avoiding the caller-side plaintext join. Before the
transport-path optimization, the same gate measured ratios of 1.506, 1.017,
and 1.382 respectively. H1 had routed the nine header/payload vectors through
the generic eight-iovec `std.Io` path, requiring an extra write; it now uses
the existing POSIX wide-iovec path. H3 had made every application slice a
separate paced DATA contribution; its transactionally advanced cursor now
groups borrowed ranges across slice boundaries up to the same packet-sized
limit as contiguous sends. When descriptor boundaries would otherwise add a
packet, only the minimum leading prefix is copied into bounded scratch. These
are local end-to-end API-shape measurements,
not an external implementation comparison or an equal-wire/kernel-capture
claim. Different payload sizes, slice counts, kernel iovec behavior, and QUIC
packetization can move the crossover.
For a syscall-shape sanity check, `strace -f -c` over two warmups and 20
measured round trips reported 46 `sendmsg` calls for both current H1 shapes;
the pre-optimization direct-slices binary required 68. The analogous H3 trace
reported 312 `sendmmsg` calls for contiguous and 294 for direct slices; the
pre-optimization direct-slices binary required 584. These counts include
handshake and teardown traffic and therefore support only the eliminated-extra-
submission diagnosis, not a wire-byte or throughput claim.

The runner accepts `NETZ_WEBSOCKET_SLICES_SAMPLES` (odd),
`NETZ_WEBSOCKET_SLICES_WARMUP`, `NETZ_WEBSOCKET_SLICES_ITERATIONS`,
`NETZ_WEBSOCKET_SLICES_PARTS` (2 through 64), and
`NETZ_WEBSOCKET_SLICES_CPU` for reproducible follow-up sweeps.
Separate 2-, 16-, and 64-part gates completed over all three transports with
exact logical-byte/checksum validation. Their short single samples are retained
as boundary-correctness evidence only, not as performance measurements.

A direct same-input reference was compiled against
`~/Work/websocket.zig/src/proto.zig` using its stack `writeFrameHeader`, a
payload copy (needed to preserve the same immutable-input contract), and
`proto.mask`. Three same-host samples were:
The checked-in reference driver now uses zio's `std.Io` only for its monotonic
clock and reports `clock backend: zio-std-io`; the older values below predate
that migration.

```sh
zig build-exe -OReleaseFast -lc --dep proto --dep zio \
  -Mroot=benchmarks/reference/websocket_zig_frame.zig \
  -Mproto=/home/passchaos/Work/websocket.zig/src/proto.zig \
  --dep zio_options \
  -Mzio=zig-pkg/zio-0.17.0-xHbVVI_jJQC3YbgU7JydwAV7MuASkOTd73YqBaKlFFUz/src/zio.zig \
  -Mzio_options=benchmarks/reference/zio_options.zig \
  -femit-bin=/tmp/bench-websocket-zig
/tmp/bench-websocket-zig
```

```text
websocket.zig header + payload copy/mask: 101, 103, 127 ns/op
```

Thus the current netz caller-buffer path is faster in the captured runs, while
the normal unmasked server runtime avoids the payload copy entirely. This is a
codec/send-hot-path comparison; end-to-end evidence follows.

### WebSocket persistent 4 KiB echo

One real HTTP/1 upgraded connection performs 20 warmup and 200 measured binary
echoes. Both implementations use mutable client input, masked requests,
unmasked responses, caller/reader-owned receive storage, and copy each echo
back to the next send buffer. Handshake time is excluded; this comparison uses
the public backend-neutral `std.Io` TCP runtime.

A CPU-0-pinned 2026-11-19 zio-era smoke of the netz-self path recorded
13,659 ns/roundtrip, 73,209 roundtrips/s, and 571.95 logical payload MiB/s for
one persistent 4-KiB binary echo (20 warmups, 200 measured). This refreshes
the backend identity and shape only; it is not a new cross-library ratio.

Twenty alternating CPU-0 samples with TCP_NODELAY enabled on both clients:

```text
netz:
  9.146-10.537 us, median 9.501 us, trimmed mean 9.539 us
websocket.zig:
  13.231-14.406 us, median 13.630 us, trimmed mean 13.702 us
netz advantage:
  1.435x by median, 1.436x by trimmed mean
```

Without TCP_NODELAY, websocket.zig's two-write masked client path measured
about 41.09-41.38 ms/roundtrip, versus 10.26-10.71 us for netz. That exceptional
~3,915x gap is a Linux Nagle/delayed-ACK cliff and is not generalized beyond
this socket/write shape. `strace -f -c` showed about 442 netz sendmsg calls,
while the reference used 443 sendmsg plus 228 writev calls for the same 220
exchanges.

Commands:

```sh
taskset -c 0 zig build bench-websocket-echo -Doptimize=ReleaseFast

zig build-exe -OReleaseFast -lc \
  --dep websocket --dep counting_allocator --dep zio \
  -Mroot=benchmarks/reference/websocket_zig_echo.zig \
  --dep build \
  -Mwebsocket=/home/passchaos/Work/websocket.zig/src/websocket.zig \
  -Mcounting_allocator=examples/support/counting_allocator.zig \
  --dep zio_options \
  -Mzio=zig-pkg/zio-0.17.0-xHbVVI_jJQC3YbgU7JydwAV7MuASkOTd73YqBaKlFFUz/src/zio.zig \
  -Mbuild=benchmarks/reference/websocket_zig_build_options.zig \
  -Mzio_options=benchmarks/reference/zio_options.zig \
  -femit-bin=/tmp/bench-websocket-zig-echo
taskset -c 0 /tmp/bench-websocket-zig-echo --tcp-nodelay
```

The reference driver now gets its client I/O and clock from zio. The audited
`websocket.zig` server API still owns its documented blocking worker thread, so
that implementation detail remains part of the reference rather than being
relabeled as a zio server. The historical cross-library numbers below predate
the driver migration and are not current zio evidence.

Four-connection mode uses one start barrier after every client finishes warmup
and reports aggregate latency across 800 measured round trips. Twenty
alternating samples on CPUs 0-7:

```text
netz:
  3.788-4.802 us aggregate/roundtrip
  median 4.150 us, trimmed mean 4.173 us
  median 240,993 roundtrips/s, 1,885.51 wire MiB/s

websocket.zig:
  4.912-5.653 us aggregate/roundtrip
  median 5.212 us, trimmed mean 5.221 us
  median 191,883 roundtrips/s, 1,501.28 wire MiB/s

netz advantage:
  1.256x by median, 1.251x by trimmed mean
```

```sh
taskset -c 0-7 zig build bench-websocket-echo \
  -Doptimize=ReleaseFast -- --connections=4
taskset -c 0-7 /tmp/bench-websocket-zig-echo \
  --tcp-nodelay --connections=4
```

One traced run showed approximately 1,768 netz `sendmsg` calls, versus 1,772
reference `sendmsg` plus 892 `writev` calls. These counts include warmup and
handshake/shutdown traffic; tracing overhead is excluded from timing evidence.

With `--compression`, the real persistent WebSocket echo benchmark negotiates
permessage-deflate. Five CPU-0 samples after moving complete-message compression
to vort's native raw fixed-DEFLATE sync-flush path were 29.44-31.14
us/roundtrip and 250.91-265.34 logical payload MiB/s. This is 4.6-5.0x lower
latency than the previous Zig-flate 144.6-147.5 us range; the new path avoids
clearing roughly 224 KiB of compressor state per no-context-takeover message.
Three four-connection CPU 0-7 runs measured 12.09-12.18 us aggregate/roundtrip
and 641.52-645.95 logical MiB/s, versus the previous 45.96 us/169.98 MiB/s. A
four-connection `--stats` sample made 7,151 allocations, allocated 48,068,236
cumulative bytes, peaked at 1,240,114 live bytes, and verified checksum 111,600.
The package-self-containment pass on 2026-09-10 replaced that external backend
with a focused in-tree fixed-Huffman encoder using a reusable 4K-entry hash
chain. A pinned 1,000-round 4-KiB run measured 22.296 us/roundtrip and 350.40
logical MiB/s with checksum 255,000; a 200-round direct-slices run measured
21.237 us/roundtrip. These samples preserve the 69-byte wire payload while
keeping outbound compression on the focused package-local encoder.

The receive-side transition was measured against sibling Vort revision
`e5c9f078f028c7f852f288104f49b0e1118409f6` for bounded raw-DEFLATE
decoding in both no-context and context-takeover modes. Runtime caller-buffer
decoding no longer allocates or retains Zig flate's separate 64-KiB window per
connection; context takeover supplies its bounded committed history directly
as Vort's preset dictionary. Seven CPU-0, order-alternated, fixed-binary pairs
used 20,000 decodes of the same 69-byte wire message into a 4-KiB caller
buffer. Parent `9779aef2` measured 1070-1081 ns/message (1072 median); Vort
measured 467-471 ns/message (468 median), won every pair, and reduced median
decode time by 56.3% (2.29x throughput). Every arm reported benchmark checksum
`8353707268`. The baseline and candidate binary SHA-256 values were
`e21c50823356607edbbead50d6555bdde1a70a0bff117e9b0da90f6dd0ac587a`
and `e384df772bd672d5237069dfb156804b6f59e48c9e7fdad754b354ab2bdf4b83`.
This is an internal decoder A/B, not a cross-library WebSocket claim.

`--compression --fragmented` sends the same 4 KiB client message as sixteen
compressed WebSocket frames. Three CPU-14 runs measured 35.80-36.60
us/roundtrip and 213.48-218.24 logical MiB/s, versus 129.24 us before batching
the small masked/unmasked frame sequence and 30.65-30.91 us for the one-frame
control. Thus wire-visible fragmentation retains a 16.8-19.4% latency cost but
no longer multiplies transport submissions by the frame count. Each run
verified checksum 51,000.

The RFC 8441 counterpart is:

```sh
taskset -c 14 zig build bench-websocket-h2-echo \
  -Doptimize=ReleaseFast -- --fragmented
```

Three complete-message controls measured 37.91-38.44 us/roundtrip and
203.23-206.05 logical MiB/s. Three sixteen-slice runs measured 43.66-44.00 us
and 177.56-178.94 MiB/s, versus 98.55-137.68 us before H2 batching. Encoding
the RFC 6455 frames into retained connection scratch and calling the existing
flow-controlled tunnel writer once yields a 2.2-3.2x fragmented-path gain; the
remaining 15.1-16.0% cost against the one-frame control represents actual
frame header/mask handling. All samples verified checksum 51,000.

A fresh 2026-09-30 zio-era syscall audit showed that batching the wire write
had not batched secure mask generation: an H1 run with five warmups and twenty
measured sixteen-frame messages made 403 `getrandom` calls. Filling sixteen
independent RFC 6455 mask keys in one CSPRNG request reduced this to 28 calls,
one per message plus three setup calls. The same bounded strategy is used by
H1, RFC 8441, and RFC 9220 batch writers.

Seven alternating CPU-0 fixed-binary pairs with fifty warmups produced:

| Workload | Baseline range / median | Candidate range / median | Paired median ratio |
|---|---:|---:|---:|
| H1 compressed, 1,000 rounds | 141.956-149.281 / 143.901 us | 69.735-71.309 / 70.876 us | 0.4929 |
| H2 compressed, 1,000 rounds | 119.854-122.356 / 121.229 us | 31.160-31.586 / 31.329 us | 0.2581 |
| H3 compressed, 500 rounds | 144.640-148.644 / 145.937 us | 55.171-59.143 / 56.293 us | 0.3833 |

Every primary pair favored the candidate and retained checksum 255,000 for H1
and H2 or 127,500 for H3. Five-pair uncompressed-fragmented controls measured
107.344 to 16.477 us median on H2 (paired ratio 0.1545) and 191.387 to 105.028
us on H3 (0.5415), showing that secure-random dispatch rather than compression
was the shared bottleneck. Fifteen-pair ordinary single-frame H2/H3 controls
had overlapping ranges and paired ratios 1.0108/1.0121; the changed batch path
is not executed there, so no single-frame result is claimed.

The ignored `zig-out/websocket-fragmented-echo-ab/` directory retains the
fixed binaries and `mask-batch-paired-final.log` with SHA-256
`db784ed3fbec15c31fda81235564dc07c9de26d6132f56f8faee9bd8906f005f`.
Baseline/candidate binary identities are respectively
`8db861f5b0552515a03863e9a9e724c078382bad188a6d3368e3c65bb69ab3c0` /
`ced67738076f3bc2dc5a40f8834d52edc6c0ff2d85ba90d46033199993587096`
for H1,
`07a71e3872c4b6087c7d3f6ebb9c0a6b4209a44ca5859b27595316dd3eec07ea` /
`1f7bb090f3c05363f25829b0a31315db7deb03847faec4c4d832915223dc1396`
for H2, and
`03cdb3961dbbf0f09eab0c862c5aff68e52ac04ac389e5a7e4b2548a846efee8` /
`489871a713a53442a140759c7cef6f7d4244795dd5d7dcdb321a6803a649f03d`
for H3.

The H1 batch was then extended to uncompressed fragmented messages. Masked
client frames whose conservative header bound plus payload fits the existing
16 KiB scratch are encoded into one bounded buffer; unmasked server frames use
borrowed payloads and groups of at most sixteen header/payload vectors. Larger
messages retain the streaming fallback. The benchmark now accepts
`--fragmented` without `--compression` and directly exercises this path.

Seven alternating CPU-0 fixed-binary pairs with fifty warmups and 1,000
measured 4 KiB round trips produced 143.041-146.236 us (144.530 us median) for
the baseline and 53.681-54.944 us (54.664 us median) for the candidate. Every
pair favored the candidate; the paired median ratio was 0.3768, a 62.3%
reduction, and every run retained checksum 255,000. Compressed-fragmented and
ordinary uncompressed single-frame controls had paired median ratios 1.0021
and 0.9987. A five-warmup, twenty-message `strace` run reduced `getrandom`
calls from 403 to 28.

The exact baseline/candidate SHA-256 identities are
`de75d747ccb06475155edd07fe5dd0d3b389ecbc3c357de251b703898cc29cdb`
and `b25278fc3c47df867d567f00be12a6632ab68f5eed0ea64f5dc46cbed54addfb`.
The ignored `zig-out/websocket-h1-fragment-batch-ab/paired-final.log` evidence has
SHA-256
`2dcaff447dd51d7a28d516c2cb8b9d7ddf55bee6af4939625d2c22d7b1d77833`.

The cross-process `bench-websocket-hyper-h2` harness runs a persistent RFC
8441 binary echo against Hyper 1.11.0 (`084473f7`) in both client/server role
pairings. Client and server are pinned to separate CPUs; h2c setup, peer
SETTINGS, Extended CONNECT, READY, and 20 warmups are outside the timed loop.
Both sides use TCP_NODELAY, fixed 1 MiB stream / 8 MiB connection windows, a
16 KiB HTTP/2 frame limit, no adaptive receive windows, no compression, and
one outstanding 4 KiB message. Client frames carry fresh random masks. Both
peers validate every round-dependent payload and require Close(1000, `done`).
The external netz endpoints obtain `std.Io` from zio. Config, result, completion
and memory records identify `zio-std-io` versus `hyper-tokio`, include the
timeout, and are rejected if timing derivatives or runtime identities disagree.
The performance and RSS numbers below were captured with the former
`std.Io.Threaded` harness and are retained as historical baselines, not current
zio performance evidence.

```sh
zig build bench-websocket-hyper-h2 -Doptimize=ReleaseFast -- \
  --warmup=20 --iterations=1000 --payload-bytes=4096 --timeout-ms=30000
```

Five CPU-0/client and CPU-1/server runs measured:

| Role pair | Latency | Logical payload throughput |
|---|---:|---:|
| netz client + Hyper server | 20.33-22.29 us/roundtrip | 350.42-384.33 MiB/s |
| Hyper client + netz server | 21.07-23.28 us/roundtrip | 335.58-370.76 MiB/s |

Every pair verified 4,096,000 bytes in each direction and aggregate checksum
522,240,000. Results belong to complete role pairs rather than isolating one
library's cost. They are `same-application-shape`, not
equal-wire: the two implementations retain distinct HTTP/2 scheduling, HPACK,
frame packing, masking, syscall, and executor behavior. No cross-library speed
ratio is inferred.

The same command accepts `--stats`. In this mode the runner builds only the
Hyper benchmark binary with its `allocation-stats` feature, wraps all four
client/server processes with GNU or BusyBox time, records the exact RSS source,
and requires one structured result, one server-completion record, two config
records and two memory records for each role pair. The
functional verifier independently recomputes the checksum across all measured
rounds, so a memory record cannot satisfy a missing echo result. Three runs of
the default 20-warmup/1,000-measured/4-KiB workload recorded:

| Implementation | Endpoint role | Process peak RSS (KiB) | Allocations | Requested bytes | Peak requested live bytes | End live bytes |
|---|---|---:|---:|---:|---:|---:|
| netz | client | 2,304 | 2,097 | 4,279,502 | 81,719 | 0 |
| netz | server | 2,048 | 2,091 | 4,279,498 | 77,109 | 0 |
| Hyper | client | 3,328 | 7,250 | 12,743,488 | 89,883 | 1,618 |
| Hyper | server | 3,328 | 7,237 | 12,723,177 | 83,756 | 1,671 |

The three runs reproduced these values exactly on this host. Whole-process
maximum RSS is the cross-language metric. Netz's explicit allocator and Rust's
global `System`-allocator requested-byte counters have different scopes and are
not treated as a cross-language allocation ratio. The netz counter starts after
argument parsing and proves zero live bytes after full H2/WebSocket/runtime
teardown. Zio executor bookkeeping intentionally uses the runtime allocator and
is excluded from that explicit protocol-allocation scope. Hyper counts from
process start; the benchmark now waits for the
server upgrade/echo task, propagates the client connection-driver result, and
drops the Tokio runtime before taking its final snapshot. Default runs do not
enable the Rust allocation feature, the netz wrapper, or an external time
wrapper.

The RFC 9220 HTTP/3 benchmark also accepts `--warmup=N` and `--iterations=N`
(defaults 20 and 200), allowing longer profiling runs without source edits.
Its QUIC timer selector and the directly invoked read-only deadline helpers now
take `*const Connection` instead of copying the roughly 7.5-KiB connection
state on every receive-loop poll. Six fixed-binary CPU-0 A/B pairs over 5,000
complete-message echoes measured 48.14-48.53 us/roundtrip versus
54.45-54.81 us (11.3-11.9% lower latency). Four fragmented pairs measured
49.48-49.61 us versus 54.33-54.81 us (8.7-9.7% lower). The corresponding perf
sample removed `nextTimerDeadline` as a visible symbol and reduced aggregate
`memcpy` samples from 9.52% to 1.58%; a compile-time receiver assertion guards
against reintroducing the by-value copy.

### RFC 9220 WebSocket versus quic-go, same application shape

`bench-websocket-h3-quic-go` extends the bidirectional correctness peer with a
persistent binary-echo workload. The peer shares the repository-owned module
that pins quic-go v0.59.0, rather than borrowing a separate quicz checkout.
Both processes are pinned to separate CPUs and use certificate-verified QUIC
v1 by default (or forced v2 via `NETZ_WEBSOCKET_H3_INTEROP_VERSION=2`), a
1280-byte steady-state MTU, 1 MiB stream /
8 MiB connection windows, no WebSocket compression, and one 4 KiB binary
message outstanding at a time. The netz endpoints now run on zio behind
`std.Io`. Config, result, server-completion, and memory records bind both
endpoint runtimes and the timeout; the strict checker also verifies the full
shape and recomputes all three timing-derived metrics. The RFC 9220 handshake
and 20 warmup echoes finish before one interval times 1,000 measured round
trips. Payload contents change with the round, and both peers independently
validate every byte; they also require a normal WebSocket Close after the timed
loop.

```sh
zig build bench-websocket-h3-quic-go -Doptimize=ReleaseFast -- \
  --warmup=20 --iterations=1000 --payload-bytes=4096 --timeout-ms=30000
```

Historical pre-zio runs on CPU 0/client and CPU 1/server measured:

| Role pair | Latency | Logical payload throughput |
|---|---:|---:|
| netz client + quic-go server | 101.80-103.39 us/roundtrip | 75.57-76.75 MiB/s |
| quic-go client + netz server | 102.25-103.34 us/roundtrip | 75.60-76.41 MiB/s |

Every process pair verified 4,096,000 sent and received application bytes and
aggregate checksum 522,240,000. The result belongs to each complete role pair;
it does not isolate either library's client or server cost. It is
`same-application-shape`, not equal-wire: netz explicitly disables GSO/GRO,
while quic-go uses implementation defaults, and ACK timing, packetization,
cipher exposure, syscall counts, and UDP datagram counts/bytes have not been
equalized. No cross-library speed ratio is inferred from the overlapping
ranges. These measurements used the former `std.Io.Threaded` harness and are
not current zio performance evidence.

A 2026-09-15 ReleaseFast zio migration smoke ran three measured 1-KiB echoes
after one warmup in both role pairings. Each pair verified 3,072 sent and
received bytes plus checksum 391,680. With memory telemetry enabled, both netz
roles ended at `live_bytes=0`, and whole-process RSS was labeled
`busybox-time-maxrss`. This is a one-sample functional and evidence-pipeline
gate, not a performance comparison.

The same command accepts `--stats`. The runner then wraps all four processes
with GNU time and requires a unique structured client result, server-completion
record, and two memory records for each role pair. The verifier independently
recomputes the checksum across the 1,000 measured rounds, so allocator
telemetry cannot stand in for a missing application result. Three consecutive
runs of the default workload recorded:

| Implementation | Endpoint role | Process peak RSS (KiB) | Allocations | Allocated bytes | Peak/ending heap detail |
|---|---|---:|---:|---:|---|
| netz | client | 3,840 | 109 | 123,880-123,912 | peak explicit live 81,977-81,990; end live 0 |
| netz | server | 3,584 | 105 | 122,331-122,372 | peak explicit live 74,471; end live 0 |
| quic-go | client | 13,056 | 104,970-105,014 | 3,301,232-3,305,576 | ending HeapSys 8,093,696 |
| quic-go | server | 13,056 | 105,480-105,538 | 3,170,472-3,183,744 | ending HeapSys 8,126,464 |

Whole-process maximum RSS is the cross-language metric. The netz explicit
allocator and Go runtime heap counters have different semantics and are not a
cross-language allocation ratio. Both netz roles reached zero explicit live
bytes after the HTTP/3, WebSocket, and former threaded runtime teardown. The quic-go
server now waits for `ListenAndServe` to exit before its final heap snapshot.
Default benchmark runs do not enable either runtime's allocation telemetry or
GNU time. These observations retain the same `same-application-shape` boundary
as the timing results above.

