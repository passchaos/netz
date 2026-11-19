# Benchmark reference context, rejected ideas, and gaps

[Back to the benchmark index](../benchmark-baseline.md).

## Reference context from `~/Work`

The closest available reference document is
`~/Work/quicz/docs/en/benchmark.md`.  Its headline numbers are not directly
comparable because they were collected on a different platform and with
different benchmark definitions, but they define the comparison target shape:

- quicz real-handshake single-stream throughput: about **310-440 MB/s** on
  macOS loopback, real TLS 1.3 handshake, 8.9 KiB datagrams, no GSO.
- quicz 4-stream aggregate: about **304 MB/s** on the same real-handshake
  benchmark family.
- quicz echo latency: about **21.7 us p50** / **77.3 us p99** for a 1 KiB full
  QUIC round trip after a real handshake.
- quicz documentation also highlights platform effects: Linux GSO/GRO can
  dominate throughput comparisons and must be recorded separately.

For netz, raw QUIC STREAM and DATAGRAM throughput now have same-host,
two-process references. Persistent 1-KiB echo and four-connection aggregate
STREAM shapes also have direct quic-go controls, but remain
`same-application-shape`; the aggregate matrix exposes a netz/netz worker
scheduling bottleneck that must be addressed before a broad scaling claim.
HTTP/3 remains separate because it includes H3 framing, QPACK, and session
bookkeeping and has no equal-wire quicz reference.

WebSocket stream transports now share `runtime/message/buffer.zig` and
`runtime/message/state.zig` for bounded 256-byte-slab receive growth,
compressed-fragment partitioning, Close-state admission, and owned message
finalization. The common growth helper now computes its rounded capacity with
checked addition, so an unrepresentable request returns OOM instead of wrapping
in optimized builds. Allocation-failure, overflow, compression-provenance,
invalid-deflate, invalid-UTF-8, and balanced-fragment tests live beside those
helpers rather than in the runtime root. Public frame/message limit semantics
are unchanged.
A CPU-0 fixed-binary 4-KiB echo check after the extraction produced
9.574-16.533 us/roundtrip while unrelated host load was active. The spread is
too wide for a performance verdict, so it is retained only as a functional
benchmark pass and does not replace the isolated ranges above.

The dedicated mostly-idle HTTP/1 WebSocket memory gate is reproducible with:

```sh
zig build bench-websocket-mostly-idle -Doptimize=ReleaseFast
```

It fixes websocket.zig at `efa879736bd438bea8b86a91f220ba408de57273`,
hashes both compiled binaries, and alternates three samples. All 128 connections
complete their real Upgrade and a classification echo; eight active connections
then complete two warmups and twenty measured 4-KiB round trips while the other
120 stay established. Both harnesses snapshot the same counting allocator
before any connection closes. Two independent three-sample runs were
byte-identical: netz used 340,480 live/peak bytes and websocket.zig used
1,317,836 live/peak bytes, making the reference 3.871x larger at this
explicit-allocation boundary. BusyBox `time` independently measured
whole-process MaxRSS medians of 38,912-39,936 KiB for netz and
160,256-160,768 KiB for websocket.zig, a 4.013-4.132x ratio that includes the
reference blocking server's one OS thread per connection. The strict
checker independently validates topology, workload, checksum, runtime identity,
snapshot phase, allocation arithmetic, sample cardinality, alternating order,
reference revision, binary hashes, and RSS source. Explicit allocator results
exclude runtime stacks, allocator internals, and kernel socket buffers; MaxRSS
includes the first two but not kernel socket memory. The two scopes are reported
separately.

The HTTP/1, RFC 8441, and RFC 9220 WebSocket connection layouts now overlay
their mutually exclusive resumable application message, Ping, and Close state
in one shared tagged-union design while keeping automatic Pong/Close state
independent for receive/write races. After the Vort decoder removed the
obsolete Zig-flate window, 64-bit `runtime.Connection` is 1,536 bytes, down
from 1,968 bytes, and `runtime.H2Connection` is 1,568 bytes, down from 2,000
bytes. Each saves 432 bytes of fixed state per live H1 connection or H2
WebSocket tunnel (22.0% and 21.6%, respectively); the H1 reduction is 55,296
bytes across the 128-connection shape above. H3 client and server connections
fall from 18,944/18,352 to 18,512/17,920 bytes, saving the same 432 bytes per
RFC 9220 tunnel (2.3%/2.4%). Compile-time-sensitive unit
assertions fix all four layouts, and the bounded
message/control/queued-auto-Pong regressions cover every variant. This
stack/inline-state reduction is separate from the benchmark's explicit
allocator counters and does not change their reported ratio.
A four-connection ReleaseFast smoke after the change completed 80 measured
4-KiB round trips with checksum 11,160 at 19.024 us aggregate/roundtrip. It
reported 54 allocations and 11,016 peak live bytes. With no matched baseline,
this is functional/no-regression evidence rather than a latency claim.
The corresponding uncompressed RFC 8441 smoke completed twenty measured 4-KiB
round trips with checksum 5,100 at 39.298 us/roundtrip and reported 50 measured
allocations. It likewise serves only as functional/no-regression evidence.
The corresponding RFC 9220 QUIC/TLS smoke completed twenty measured 4-KiB
round trips with checksum 5,100 at 143.666 us/roundtrip and reported 169
measured allocations. The bidirectional quic-go QUIC v1/v2 gate also passed;
the timing remains functional/no-regression evidence without a matched
baseline.

The current-key borrowed visitor receive path now prevalidates each packet
number once and carries that fact into ACK-range commit. Ordered traffic can
extend the newest range directly; reordered packets retain the complete
bounded-range validation, duplicate rejection, range merge, and ECN accounting
paths. A deterministic tracker regression covers continuous extension, a gap,
gap closure, all ECN codepoints, and a duplicate after merge. The existing
connection-level regression independently verifies that a duplicate packet is
dropped before STREAM side effects or visitor delivery.

Five order-alternated fixed-binary runs on 2026-09-28 used the same
`bench-quic-one-rtt-receive` visitor/STREAM workload with 500 warmups and
20,000 iterations (1,080,000 packets per arm). Baseline `34c38fb4` measured
2,891-2,924 ns/packet with a 2,911 ns median; candidate `0e722992` measured
2,876-2,899 ns/packet with a 2,891 ns median. The candidate won all five pairs
and reduced the median by 0.7%. This is a same-host internal receive-hot-path
result, not an end-to-end or cross-stack throughput claim.

HTTP/2 same-origin URI-batch preparation now retains up to sixteen parsed
`std.Uri` views in stack storage, avoiding the former second parse while
writing each request's final `:path`; the first URI also reuses its scheme
parse during origin validation. Larger batches add no allocation and retain a
two-pass fallback. Borrowed parsed-URI pool admission also avoids reparsing the
already validated first origin while preserving endpoint, scheme, userinfo,
port and IPv6 validation. Idle/LRU bookkeeping additionally shares zio's
awake-clock snapshot within one event-loop scan, while foreign backends and
request deadlines retain ordinary fresh-clock behavior. Twenty CPU-0
fixed-binary pairs used the
`http2_shared_consecutive_x1_empty` shape with one persistent h2c connection,
1,000 warmups and 2,000 measured requests. Baseline SHA-256 was
`3d2636d58637653d5f33465886a18ba418a1c8b3f2403c89faf26bd77943e310`
and candidate SHA-256 was
`2f71569cb25a849b5bc2c6cbe72356e884cb9cfbd1e65a2284b7b70d7214a7fb`.
Paired latency fell to 0.970066 (-2.993%, 20/20 wins) and process instructions
to 0.939518 (-6.048%, 20/20). Candidate total static size was 104 bytes smaller.
Measured allocator telemetry was unchanged: 6,000 calls, 1,286,000 requested
bytes, 71,946 live bytes and 140,592 peak bytes per 2,000-request arm. Zero-loss
explanatory
profiles moved `Uri.parse` from 3.54% to 0.99%, `clock_gettime` from 16.81% to
15.46%, removed pool release/admission clock branches, and reduced approximate
event count 4.971%;
the complete bidirectional Hyper h2c/TLS interoperability matrix and focused
Debug/ReleaseFast pool and
SharedSender gates passed.

An executor-local real-clock cache for automatic HTTP `Date` generation was
evaluated and rejected rather than retained. Seven CPU-10, fixed-binary,
order-alternated pairs used exact status/checksum validation for HTTP/1's
16-response pipeline, HTTP/2's persistent SharedSender h2c request, and the
HTTP/3 development request/response path. Candidate/baseline median latency
ratios were 1.019127 (0/7 wins), 1.015796 (0/7), and 1.000663 (3/7)
respectively. Baseline/candidate SHA-256 pairs were
`438c4775e9f0438d1ca8649e318c02f7c16644ac52ad4a47eb0d6189fa12c596` /
`5e93f5f48a50a8ced6a014a0e5c555d192e3b535eb129c3f6e77c3d648d02d71`,
`4ffd53cd74513d9bf65f943dfb697f681684656f3a9e63ebaa9bdf5a6068a8ec` /
`d9f80e18d18106331c5d2459ab6c163bac36f37c27a1e0cb03c08de069381e66`,
and
`143b5480dbfe418978e3c194906ccfdf8817cfc2610f40718a89f306fc1480a0` /
`f8c2a68627b188233ff51b36efad5a5eadb171f03799e467d7f622ddd1e53ae3`.
A 50,000-batch HTTP/1 profile completed 800,000 measured responses with exact
71,200,000-byte checksums in both binaries, but moved from 492,701,045 ns to
499,033,308 ns: these workloads normally generate one Date per event-loop
scan, so the candidate still paid the same VDSO real-clock read plus cache
lookup. The zio experiment at `5700bca8335bd7253b016b2cf3cf124748e5f4e9`
was reverted by `9d9bbc3`; Netz retains its already allocation-free,
per-thread/per-second formatted-value cache and fresh real-clock check, matching
Hyper's freshness model without weakening deadline or timer semantics.

A 2026-10-16 current-source audit deliberately stopped before changing the
QUIC receive path. Five CPU-0 ReleaseFast runs of
`bench-quic-one-rtt-receive --mode=visitor --frame=stream` used 500 warmups and
5,000 iterations (270,000 packets) and measured 2,146-2,166 ns/packet with a
2,155 ns median. A separate 30,000-iteration profile measured 2,161 ns/packet,
captured about 24,000 cycle samples, and lost zero samples. Self shares were
34.39% AES CTR, 15.01% GHASH update, 5.36% PMULL GHASH blocks, 2.63% traffic-key
protect, 2.15% current-key packet open, 1.96% GHASH block-count setup, and
1.91% header-protection masking. The benchmark seals and opens every packet,
so both directions intentionally contribute to those crypto totals.

The remaining visible Netz receive work was individually small:
`applyReceivedFramesForDestinationOrClose` 0.86%, service-frame parsing 0.72%,
QUIC varint decode 0.69%, receive-stream lookup 0.53%, tracked STREAM insertion
0.46%, and STREAM precondition validation 0.39%. `clock_gettime` accounted for
7.80% below zio polling and waiting; it is not a reason to retry the rejected
cached-send-time experiment, because a continuously runnable shared endpoint
can bypass the poll that would advance such a snapshot. The current dominant
optimization boundary is therefore Vail's prepared AES/GHASH implementation
or a materially different crypto backend, followed by runtime scheduling.
No production candidate was retained: removing validation, recovery,
ownership, exact clock, or cancellation work to chase sub-1% self symbols
would not meet the repository's end-to-end evidence threshold.

## Rejected Huffman loop rewrite (2026-11-08)

The HPACK decode hot path was profiled with `perf` on the harnessz-backed
`bench-http2-hpack` benchmark. `internal/hpack_huffman.decodeHuffmanInto` and
`decodedLen` walk the decode trie one bit at a time. A rewrite that replaced
the variable shift with a mask loop, cached the current trie node, and removed
the per-bit `pending_code` accumulator was measured with fixed binaries and
eight CPU-0 alternating pairs at 20,000 iterations per arm. The candidate
regressed `stateful decode-only` from a 1,288.5 ns/op median to 1,701.5 ns/op
(0.757x before/after), `decode-into` from 1,208.5 to 1,639.0 ns/op (0.737x),
and `decode-owned` from 1,241.5 to 1,676.0 ns/op (0.741x). The change was
reverted. A multi-bit table-driven decoder remains a candidate, but it needs
the same fixed-binary A/B treatment and the full Huffman/HPACK/QPACK and fuzz
gates before it can be retained.

## Table-driven Huffman decode (2026-11-08)

The follow-up replaced the root-state walk with a 12-bit lookup table. Each
entry emits up to two completed symbols and records the consumed bit count, or
stores the live trie node when the code is longer than 12 bits. Long codes and
the final buffered suffix still use the existing bit-by-bit trie, so the table
never needs to represent the full 30-bit HPACK code space. The table build
rejects EOS and invalid prefixes at comptime.

The same fixed-binary, CPU-0, eight-pair alternating A/B at 20,000 iterations
per arm produced:

| Scenario | Before ns/op | After ns/op | Speedup |
| --- | ---: | ---: | ---: |
| stateful decode-only | 1,280.5 | 509.5 | 2.513x |
| stateful decode-into | 1,204.0 | 451.0 | 2.670x |
| stateful decode-owned | 1,235.0 | 481.0 | 2.568x |
| stateful roundtrip | 733 | 506 | 1.449x |
| stateless roundtrip | 2,048 | 1,170 | 1.750x |
| encode-only | 257 | 250 | 1.028x |
| encoder table churn | 265 | 266 | 0.996x |
| decoder table churn | 50 | 48 | 1.042x |

Encode and table churn are neutral; every decode shape wins. The focused
Huffman/HPACK/QPACK suite passed 264/264, including a 20,000-input differential
comparison against the original bit-by-bit decoder, the HTTP/2, HTTP/3 and gRPC
filters passed, `fuzz-parsers`/`fuzz-stateful` replayed 4/4, the HTTP/2/HTTP/3
connection fuzzers passed 9/9, and the complete library suite passed
6768/6768 before the final two test-only additions. The root table adds about
22 KiB to the benchmark binary. Full rows and binary hashes are in
[the Huffman evidence](../evidence/hpack_huffman/2026-11-08.json).

The QPACK dynamic-reference benchmark is neutral (32-field encode 0.995x,
512-reference encode 0.997x, churn 0.997x, owned decode 1.005x), because its
block is dominated by dynamic references rather than Huffman literals; the
shared decoder still benefits literal-heavy QPACK field sections.

The retained decoder was also validated against independent peers.
`zig build interop-http-external-clients` passed with curl 8.5.0 (nghttp2
1.59.0) and nghttp2 1.68.1 clients against netz in cleartext and
certificate-verified TLS, including multiplexed body/trailer traffic, and with
netz h2 against nghttpd. `zig build interop-http3-qpack-quic-zig` passed with
quic-zig decoding a netz speculative QPACK field section. The complete
`zig build interop-http3-quic-go` QUIC v1/v2 peer/cancel/redirect/pool/
informational matrix passed as well. That fixture's `go.mod` requires Go 1.24
and the script forces `GOTOOLCHAIN=local`; the host default go1.22.2 cannot
download a toolchain, so the gate was run with a locally extracted go1.24.7
via `GO_BIN`.

The end-to-end gRPC SharedChannel benchmark is neutral in persistent mode
(14,258.5 -> 14,263.5 ns/roundtrip, 0.9996x) because the HPACK dynamic table
indexes repeated headers, and 1.6% faster in per-call mode (48,786.5 ->
48,038.0 ns/roundtrip, 1.0156x) where more header blocks are decoded.

A 13-bit root table was also measured and rejected. Doubling the table from
4,096 to 8,192 entries regressed decode-only from 510.0 to 543.5 ns/op
(0.938x), decode-into from 451.0 to 481.0 ns/op (0.938x), decode-owned from
480.5 to 512.0 ns/op (0.939x), and stateless roundtrip from 1,172.5 to
1,204.0 ns/op (0.974x). The larger table's cache footprint outweighed the
reduced long-code fallbacks; 12 bits remains the retained configuration.

## Single-pass HPACK string decode (2026-11-08)

The HPACK decoder previously walked each Huffman string twice: once through
`decodedLen` to size the output and charge the header-list budget, then again
through `decodeHuffmanInto` to write the bytes. `decodeHuffmanIntoBounded` now
reports `BufferTooShort` for undersized storage, so the decoder can decode each
string once into a 512-byte stack scratch buffer, use the written length for
header-list accounting, and copy or append the already-decoded bytes only when
the field is retained. Strings larger than the scratch buffer keep the exact
length walk, and non-Huffman literals keep their borrowed representation.
Because the scratch pass validates without allocating, the caller-buffer
decoder still performs no output allocation after the header-list limit is
crossed.

Eight CPU-0 alternating fixed-binary pairs of `bench-http2-hpack` at 20,000
iterations and five samples per arm measured:

| Scenario | Before ns/op | After ns/op | Speedup |
| --- | ---: | ---: | ---: |
| stateful decode-only | 515.0 | 420.0 | 1.226x |
| stateful decode-into | 452.5 | 361.0 | 1.253x |
| stateful decode-owned | 483.0 | 387.5 | 1.246x |
| stateful roundtrip | 512.5 | 495.5 | 1.034x |
| stateless roundtrip | 1,172.0 | 1,123.0 | 1.044x |
| encode-only | 250.0 | 256.0 | 0.977x |
| encoder table churn | 265.5 | 267.0 | 0.994x |
| decoder table churn | 49.0 | 50.0 | 0.980x |

The encode path is untouched; the encode-only delta is attributed to code
layout because `encodeBlock` moved by 224 bytes between these two binaries.
Whole-benchmark `perf stat` totals fell from 5,145,297,541 to 4,717,653,117
instructions (-8.3%) and from 1,386,212,821 to 1,248,705,963 core cycles
(-9.9%). QPACK keeps the exact-length two-pass path, so a separate eight-pair
comparison against the committed pre-table decoder measures the complete
Huffman series: 32-field encode 0.997x, 512-reference encode 1.005x,
dynamic-table churn 0.995x and owned dynamic decode 1.006x.
The focused Huffman/HPACK/QPACK suite passed 265/265, the HTTP/2, HTTP/3 and
gRPC filters passed 2718/2718, `fuzz-parsers`/`fuzz-stateful` replayed 4/4, the
HTTP/2/HTTP/3 connection fuzzers passed 9/9, and the complete library suite
passed 6771/6771 with isolated build caches. `interop-http-external-clients`
passed again against curl/nghttp2 after the change. Full rows and binary
hashes are in [the Huffman evidence](../evidence/hpack_huffman/2026-11-08.json).

A follow-up added `encodeHuffmanIntoBounded`, which encodes into a
worst-case-sized buffer and returns the exact length. HPACK `encodeString` now
encodes values up to 320 bytes once into a 512-byte scratch buffer and derives
the prefix length from the result, instead of walking the table for a length
first. Eight CPU-0 alternating fixed-binary pairs measured encode-only at
255.5 -> 249.0 ns/op (1.026x), the stateless roundtrip at 1,097.5 -> 1,061.5
(1.034x), and the decode shapes within 0.6%. Values above the scratch bound
keep the exact-length path, and a non-shrinking encoded form is discarded in
favor of the literal representation.

### HTTP/2 pseudo-header validation (2026-11-09)

`validateHeaderBlock` ran `markRequestPseudo` (up to five name comparisons) and
then up to five more comparisons to capture the pseudo-header value.
`markRequestPseudo` now returns the `RequestPseudo` tag, matching the HTTP/3
classifier, and the caller switches once; the response path also drops a
duplicate `:status` comparison. `validateHeaderBlock` is public for callers
that decode an HPACK block themselves, and `bench-http2-hpack` gained a
`header-validation` scenario over its seven-field request block. Eight CPU-2
alternating pairs measured request header validation at 167.0 -> 152.0 ns/block
(1.106x, 8/8 wins). HPACK encode moved 255.0 -> 250.0 ns/op (1.020x, code
layout); decode-only, decode-into, decode-owned and both roundtrip scenarios
were neutral. The `http2-hpack` baseline was re-recorded with nine entries,
including `header-validation`, under the unpinned cpu32 fingerprint. Evidence
is in
[the header validation evidence](../evidence/http2_header_validation/2026-11-09.json).

Field-name and field-value validation then moved to shared byte tables.
`src/http/field_name.zig` is used by both HTTP/2 and HTTP/3; its table excludes
uppercase and non-token bytes, replacing the per-byte switch and the redundant
uppercase range check. `src/http/field_value.zig` replaced two comparisons per
byte with a 256-byte invalid-byte table. Eight CPU-2 alternating pairs measured
header validation at 154.0 -> 137.5 ns/block for the name table (1.124x, 7/8
wins) and 135.0 -> 131.5 ns/block for the value table (1.038x, 8/8 wins).
Combined with the pseudo-header tag change, the same block moved from 167.0 to
131.5 ns/block. The HPACK encode/decode rows moved only with code layout. The
`http2-hpack` baseline was re-recorded with nine entries. Evidence is in
[the field table evidence](../evidence/http2_header_validation/2026-11-09-field-tables.json).

### HTTP/1 shared value table (2026-11-09)

HTTP/1 carried four copies of the field-value control-byte check: the streaming
head scan, `parseHeaderLine`, `validateHeaderValue`, and `validateReasonPhrase`.
All four now use the inline `field_value.invalidByte` table shared with HTTP/2
and HTTP/3. Eight CPU-2 alternating pairs of `bench-http1-parse` measured owned
parsing at 255.0 -> 235.5 ns/op (1.085x, 8/8 wins) and owned plus Host at
278.0 -> 257.0 ns/op (1.078x, 8/8). Borrowed parsing stayed neutral at
185.0 ns/op because its measured cost is dominated by other work. The
`http1-parse` baseline was re-recorded with its three entries under the
unpinned cpu32 fingerprint. Evidence is in
[the HTTP/1 value table evidence](../evidence/http1/2026-11-09-value-table.json).

### Rejected HTTP/1 line-boundary pre-scan (2026-11-08)

A `LineIterator` variant precomputed all CRLF positions once per head with a
32-byte vector scan, so `next` consumed boundaries instead of restarting the
SIMD CR search per line. Eight CPU-0 alternating fixed-binary pairs of
`bench-http1-parse` regressed borrowed from 182.0 to 200.5 ns/op (0.908x) and
owned plus Host from 276.0 to 286.0 ns/op (0.965x); owned stayed neutral at
254.0 -> 255.0. The extra scan and larger iterator did not pay for the saved
per-line calls, so the change was reverted and the rebuilt benchmark binary
matched the pre-experiment SHA-256 exactly.

### Rejected HTTP/1 manual CR scan (2026-11-09)

Replacing the per-line `std.mem.indexOfScalarPos(..., '\r')` with an inline
byte loop helped the borrowed scenario (187.5 -> 182.0 ns/op, 1.066x, 7/8 wins)
but regressed owned to 240.5 -> 313.5 ns/op (0.803x, 0/8) and owned plus Host to
273.5 -> 336.0 ns/op (0.815x, 0/8). The generic search is SIMD-accelerated and
the inlined loop changed code layout in the owned path, so the change was
reverted and the source hash returned to the value-table revision.

### Rejected combined HPACK static lookup (2026-11-08)

A `findStaticIndexes` helper that returned both the exact static index and the
static name index from one name lookup was measured to avoid the second
`static_name_index.get` and pseudo-name chain per encoded field. Eight CPU-0
alternating fixed-binary pairs of `bench-http2-hpack` regressed encode-only from
554.5 to 589.0 ns/op (0.941x) and the stateful roundtrip from 934.0 to 969.0
ns/op (0.964x); decode shapes stayed neutral. The helper was reverted and the
rebuilt benchmark binary matched the pre-experiment SHA-256 exactly.

### Rejected HPACK exact-hash seed rewrite (2026-11-08)

The `DynamicExactContext.hash` path was also measured. Replacing the two
`std.hash.autoHash` length writes with a single seeded `Wyhash.init` was
neutral: eight CPU-0 alternating pairs at 20,000 iterations per arm measured
encode-only 250.0 -> 249.0 ns/op (1.004x), stateful roundtrip 510.0 -> 506.5
ns/op (1.007x), stateless roundtrip 1,169.5 -> 1,176.5 ns/op (0.994x), and
decode-only 510.0 -> 509.5 ns/op (1.001x). The change was reverted; the
remaining encode cost is not dominated by the length-write instructions.

## MQTT router indexed unsubscribe (2026-11-08)

`Router.subscribe` duplicate detection and `Router.unsubscribe` previously
scanned every stored entry to find a `(subscriber_id, effective_filter,
shared_group)` match. The lookup now scans only the trie route list for the
exact filter (normally one entry), or the shared group's member list for shared
subscriptions, which includes non-representative members. Trie pruning and
shared representative replacement are unchanged.

Eight CPU-0 alternating fixed-binary pairs of `bench-mqtt-router` measured
`unsubscribed exact filters` at 829.0 -> 157.5 ns/op (5.263x), while router
matching stayed at 140.0 ns/op and the shared-selection strategies remained
within noise (round-robin 1.015x, sticky 1.004x, random 1.000x, rendezvous
0.987x). The focused MQTT/router suite passed 1410/1410 and the complete
library suite passed 6770/6770. Full rows and binary hashes are in
[the router evidence](../evidence/mqtt_router/2026-11-08.json).

A second fixed-binary A/B reused the topic-hashed Wyhash state across the 64
rendezvous members, preserving the exact score mapping while removing 63
repeated topic hashes. Under a slower host state (router matches 288.5 ns/op),
the interleaved eight-pair median moved from 2,262.0 to 1,809.0 ns/op (1.25x).
Only the relative ratio is claimed across the two experiments. The complete
library suite passed 6770/6770 after all five router changes.

The entry table also gained a recycled-slot free list; each new subscription
reserves one recycle slot so rollback and normal unsubscribe do not allocate.
The benchmark now times the initial subscribe phase and a resubscribe phase
after a full unsubscribe. Eight CPU-0 alternating pairs measured initial
subscriptions at 1,340.5 -> 605.0 ns/op (2.216x) and resubscribed exact filters
at 933.5 -> 223.0 ns/op (4.186x); unsubscribe moved from 157.5 to 163.5 ns/op
(0.963x) because each removal records a recycle index. Router matching stayed
at 139.0 ns/op.

Shared groups are now indexed by `{name, effective filter}` and their slots are
recycled, removing the linear group scan. The benchmark now creates and removes
1,024 distinct shared groups. Eight CPU-0 alternating pairs measured shared
group subscribe at 3,129.0 -> 1,059.0 ns/op (2.955x) and unsubscribe at
314.0 -> 208.0 ns/op (1.51x); exact-filter and matching phases stayed neutral.

Disconnect cleanup now walks a per-subscriber entry list (one inline index for
the common single-subscription case, a list for larger sets) instead of
scanning every stored entry. The benchmark now calls `removeSubscriber` for
each of the 4,096 exact subscribers. Eight CPU-0 alternating pairs measured
`removeSubscriber` at 2,559.0 -> 193.5 ns/op (13.225x); exact-filter subscribe
moved 610.0 -> 698.5 ns/op (0.873x) because each subscription now updates the
subscriber map. The inline single-entry form avoids a per-subscriber
allocation. Router matching stayed neutral. The full Mosquitto-derived
`interop-mqtt-broker-config` matrix also passed with all five router changes.

Ordinary (non-shared) matching now emits optimistically in one trie traversal
instead of a count pass followed by an emit pass. The emit helpers bounds-check
the caller buffer only on this path; an overflow returns `MatchBufferTooSmall`
with no shared cursor to protect. The trie-stack fallback uses a checked linear
scan. Shared-group matching keeps the two-pass protocol so cursors never
advance on a short caller buffer. Eight CPU-0 alternating fixed-binary pairs
measured router matches at 134.5 -> 74.5 ns/op (1.805x); subscribe,
resubscribe, unsubscribe and removeSubscriber stayed within about 1.4%.

## QUIC PADDING word-at-a-time skip (2026-11-08)

`parseFrameWithAllocator`, `parseFrameInto` and the Initial-flight CRYPTO
reassembler skipped PADDING runs with `std.mem.findNonePos`, which is a scalar
nested loop over each byte. Initial packets are padded to 1200 bytes, so that
loop dominated frame parsing. A shared helper now compares 32-byte vectors
against zero, uses `std.simd.firstTrue` to locate the first non-zero lane, and
finishes with `u128`, `u64` and byte tails. The first-non-zero result and
consumed length are unchanged.

Eight CPU-0 alternating fixed-binary pairs of `bench-quic-padding-parse` at
100,000 iterations and five samples per arm measured:

| Scenario | Before ns/op | After ns/op | Speedup |
| --- | ---: | ---: | ---: |
| padding-only | 319.0 | 26.0 | 12.269x |
| padding before PING | 323.0 | 27.0 | 11.963x |

The `u64` intermediate scan measured 5.39x over the scalar loop; widening to
`u128` added 1.36-1.51x, and the 32-byte vector scan added a further 1.50-1.67x.
The QUIC suite passed 1230/1230 and the complete library suite passed
6771/6771. Evidence is in
[the QUIC padding evidence](../evidence/quic_padding_scan/2026-11-08.json).

## HTTP/3 capsule writer length classification (2026-11-08)

`capsule.writeInto` previously classified each varint length four times:
`encodedLen` computed both lengths, then each `quic.varint.encodeInto`
recomputed its own. The caller-buffer writer now classifies the capsule type
and value length once, checks the combined header and payload bounds with
checked arithmetic, and writes both varints through the new bounds-checked
`quic.varint.encodeIntoWithLen`. The payload copy keeps the existing
overlap-safe `copyForwards` behavior.

Eight CPU-0 alternating fixed-binary pairs of `bench-http3-capsule` at 100,000
iterations and five samples per arm measured caller-buffer encode at 69.0 ->
62.0 ns/op (1.113x); the parse path stayed at 2.0 ns/op. The host was loaded
during the batch, so only the interleaved ratio is claimed. The focused
capsule/varint suite passed 222/222 and the complete library suite passed
6771/6771. Evidence is in
[the capsule write evidence](../evidence/http3_capsule/2026-11-08-write-fast-path.json).

## MQTT topic-filter validation fast path (2026-11-08)

`validTopicFilterLevels` split every filter on `/` and ran separate `#` and
`+` searches per level. It now finds each wildcard with `indexOfAnyPos` and
checks only that position: the wildcard must occupy a complete level, and `#`
must also be the final byte. Filters without wildcards need one SIMD search and
no level walk; wildcard filters avoid the per-level split. The accepted grammar
is unchanged.

Eight CPU-0 alternating fixed-binary pairs of `bench-mqtt-retained` measured
exact lookup at 84.5 -> 44.0 ns/op (1.920x) and the wildcard full scan at
182,448 -> 167,343 ns/op (1.090x). A follow-up vectorized the shared MQTT
UTF-8 ASCII-prefix check in sixteen-byte chunks and measured a further 1.127x
on exact lookup (71.0 -> 63.0 ns/op in a loaded-host batch) with the wildcard
scan neutral. Retained wildcard lookups then began building one
`mqtt.FilterMatcher` per filter, computing its level boundaries once instead of
re-splitting the filter for every stored topic; eight pairs measured the
wildcard full scan at 166,125.5 -> 113,688.5 ns/op (1.461x) with exact lookup
unchanged. A trailing-`#` fast path then reduced literal-prefix filters such as
`devices/#` to one prefix comparison; a new benchmark scenario measured
62,956.5 -> 44,990.5 ns/op (1.399x) for a 4,096-entry match, while exact lookup
and the `devices/+/state` scan stayed neutral. The retained store then gained a
parallel level-index array with each topic's level ends computed once on
insert; wildcard matching uses those ends instead of re-splitting every topic.
Eight pairs measured the `devices/+/state` scan at 118,646.0 -> 81,605.0 ns/op
(1.454x), with exact lookup and the `devices/#` prefix path neutral. The
MQTT/router suite passed 1410/1410, the
complete library suite passed 6771/6771, and the full Mosquitto-derived
`interop-mqtt-broker-config` matrix passed in isolation. Evidence is in
[the retained filter evidence](../evidence/mqtt_retained/2026-11-08-filter-validation.json).

## MQTT retained topic trie (2026-11-08)

Wildcard retained lookups scanned every retained entry and re-matched the
filter against each stored Topic Name. The store now keeps a topic trie next to
the exact-lookup hash index: one node per topic level, child lists for `+`
enumeration and `#` subtree collection, and a `(parent, level)` edge map for
literal descent. Literal lookups scan up to eight siblings before hashing
because topic trees are narrow away from their branch points. Matching walks
the filter with a fixed-size frame stack and marks matches in a preallocated
bitmap, so it stays allocation-free and still emits in entry-table order.
Replacement reuses the stored Topic Name allocation so trie edge keys cannot
dangle, removal unlinks the trie path before freeing the entry, and the
now-unused `mqtt.FilterMatcher` was removed.

Eight CPU-2 alternating fixed-binary pairs of `bench-mqtt-retained` measured:

| Scenario | Before ns/op | After ns/op | Speedup |
| --- | ---: | ---: | ---: |
| exact lookup | 42.0 | 40.0 | 1.038x |
| `devices/+/state`, 4,096 entries | 80,846.0 | 71,324.5 | 1.134x |
| `devices/#`, 4,096 entries | 46,672.0 | 46,672.0 | neutral |
| `devices/+/state`, 4,096 of 16,384 entries | 589,204.5 | 112,863.0 | 5.204x |
| `devices/1234/#`, 4 of 16,384 entries | 179,555.0 | 587.5 | 305.792x |

The host was loaded during the batch, so only interleaved ratios are claimed.
The `devices/#` case is neutral because that filter matches nearly every entry,
so subtree traversal and prefix comparison visit comparable state before the
same 4,096 results are emitted. The MQTT/router suite passed 1412/1412, the
complete library suite passed 6773/6773, and the full Mosquitto-derived
`interop-mqtt-broker-config` matrix passed in isolation. Evidence is in
[the retained trie evidence](../evidence/mqtt_retained/2026-11-08-trie.json).

A follow-up moved trie links from optional `usize` fields (112-byte nodes) to
`u32` sentinels (40-byte nodes), added an explicit `max_index_bytes` budget
charged before an insert commits and returned when removal frees nodes, and
changed the match/delivery helpers to borrow `*const Entry` instead of copying
the entry header per result. Eight CPU-2 alternating pairs against the trie
revision measured `devices/#` at 45,886.0 -> 30,810.5 ns/op (1.455x),
`devices/+/state` on the mixed store at 113,058.5 -> 106,876.0 (1.060x),
`devices/1234/#` at 592.0 -> 549.0 (1.078x), the broad `devices/+/state` scan
neutral at 70,502.5 -> 70,477.5 (0.991x), and exact lookup neutral. An
intermediate node-only build regressed the broad scan to 0.901x; the
Entry-pointer pass recovered it, so the combined change has no
maintained-scenario regression. Evidence is in
[the index budget evidence](../evidence/mqtt_retained/2026-11-08-index-budget.json).

A profile of the same benchmark then showed `memset` at roughly 15%:
`collectMatches` zeroed the whole match bitmap before every wildcard lookup,
which scales with the retained table rather than with the matches. `setMatchBit`
now records the touched word range, `clearMatchBits` clears only that range
after the match, and insert zeroes newly grown words so the bitmap is zero at
every match boundary. Eight CPU-2 alternating pairs measured `devices/1234/#`
at 551.5 -> 288.0 ns/op (1.925x, 8/8 wins); exact lookup, the broad
`devices/+/state` scan, `devices/#`, and the selective `devices/+/state` scan
were neutral because their matches span most of the bitmap. Evidence is in
[the bitmap range clear evidence](../evidence/mqtt_retained/2026-11-08-bitmap-range-clear.json).

The retained benchmark itself moved to the harnessz sampler: warmup plus ten
samples per scenario, min/p50/p90/p99/mean/stddev output, `--scenario`,
`--baseline`, `--update-baseline` and `--warn-only`, and five baseline entries
(`exact`, `wildcard`, `hash`, `selective`, `subtree`) under
`benchmarks/baselines/mqtt-retained.json`. `zig build bench-record` now records
seven sampler-backed benchmarks and 27 scenario entries. The sampler medians
agree with the fixed-loop numbers above; exact lookup reports about 20 ns/op
because the old loop formatted a topic string per iteration and the new loop
reuses one constant filter. The gate is host-sensitive: the record and gate
steps are serialized in `build.zig`, but a quiet host is still required, and
`--warn-only` is for loaded-host diagnostics. Evidence is in
[the sampler baseline evidence](../evidence/mqtt_retained/2026-11-08-sampler-baseline.json).

Filter validation and wildcard detection are now one scan.
`validTopicFilterLevelsKind` returns invalid/literal/wildcard,
`validateTopicFilterKind` exposes the combined result, and retained exact and
wildcard lookups branch on it instead of calling `hasWildcards` after
validation. Eight CPU-2 alternating pairs measured exact lookup at
20.0 -> 17.0 ns/op (1.176x, 8/8 wins; 1.206x in the full-scenario batch). The
wildcard, hash, and subtree scenarios were neutral. The selective
`devices/+/state` replay measured a consistent 1.8% delta (0.982x in two focused
batches), attributed to code layout rather than validation cost because
validation runs once per lookup while the scenario performs 4,096 matches; a
noinline variant measured the same delta. The change is retained as an explicit
trade-off for the 17.6-20.6% exact win. Evidence is in
[the filter kind evidence](../evidence/mqtt_retained/2026-11-08-filter-kind-validation.json).

A CPU-0-pinned 2026-11-19 zio-era smoke of the sampler-backed retained
benchmark recorded exact 19 ns/op, broad `devices/+/state` 71,363 ns/op,
`devices/#` 32,312 ns/op, selective `devices/+/state` 108,016 ns/op, and
selective `devices/1234/#` 267 ns/op. This refreshes the backend identity and
scenario shape only.

## MQTT ACL filter boundary precomputation (2026-11-08)

Every ACL authorization scans all deny rules and then all matching grant
rules. `topicMatchesRule` previously re-split each rule's topic filter on every
check. `Rule` now stores the end offset of up to eight filter levels, computed
once in `initRule` during ACL parse; `topicMatchesRule` walks those boundaries
with the same `#`/`+`/`%c`/`%u` semantics and falls back to the split-based
matcher for deeper filters. The new `bench-mqtt-acl` example measures a
512-rule ACL with a late-matching topic and a topic that matches no rule.

Eight CPU-0 alternating fixed-binary pairs measured:

| Scenario | Before ns/op | After ns/op | Speedup |
| --- | ---: | ---: | ---: |
| late-match | 25,239.5 | 14,270.0 | 1.769x |
| no-match | 17,066.0 | 10,701.0 | 1.595x |

A follow-up splits the topic once per authorization into up to eight level
ends and shares them across the deny and grant passes, so each rule no longer
re-splits the same topic. Eight pairs measured late-match at 14,238.0 ->
11,381.0 ns/op (1.251x) and no-match at 10,669.0 -> 8,372.5 ns/op (1.274x).
The MQTT/router suite passed 1410/1410, the complete library suite passed
6771/6771, and the full Mosquitto-derived `interop-mqtt-broker-config` matrix
passed. Evidence is in
[the ACL evidence](../evidence/mqtt_acl/2026-11-08-filter-boundaries.json).

## CONNECT-UDP capsule header cache (2026-11-08)

The capsule session receive path previously attempted a full `Capsule.parse`
for every stream fragment until a datagram's value bytes were complete, so a
513-byte datagram split into 17-byte fragments re-decoded the same header about
thirty times. `capsule.parseHeader` now exposes the type/length/header length,
and the session caches the expected total length for the incomplete capsule at
the current receive offset. Later fragments return after a length comparison;
a complete capsule is still parsed once before delivery.

Eight CPU-0 alternating fixed-binary pairs of `bench-connect-udp-capsule`
measured caller-buffer receive at 475.0 -> 413.0 ns/datagram (1.150x) and owning
receive at 572.5 -> 506.0 ns/datagram (1.131x); send stayed at 6.0. The host was
loaded during the batch, so only the interleaved ratios are claimed. The
capsule/CONNECT-UDP suite passed 224/224 and the complete library suite passed
6771/6771. Evidence is in
[the CONNECT-UDP evidence](../evidence/connect_udp/2026-11-08-header-cache.json).

## MQTT topic-name validation fast path (2026-11-08)

`validTopicName` previously ran the MQTT UTF-8 validator and a separate
wildcard search over every topic name. It now checks sixteen-byte ASCII chunks
once for high bytes, NUL, `+` and `#`; a chunk with a high byte falls back to
the full UTF-8 validator plus wildcard search. Eight CPU-0 alternating
fixed-binary pairs of `bench-mqtt-session` measured the public enqueue churn at
129.0 -> 122.0 ns/op (1.057x); the full-window drain stayed at 8.0 ns/op. The
MQTT/router suite passed 1410/1410 and the complete library suite passed
6771/6771. Evidence is in
[the topic-name evidence](../evidence/mqtt_session/2026-11-08-topic-name-validation.json).

## Gaps before a completion audit can pass

The shared gRPC TCP baseline is recorded separately in
[grpc_shared_performance.md](../grpc_shared_performance.md), with complete sample
records and the official grpc-cpp fixture boundaries. Its initial 256 KiB
persistent and per-call workloads took 2.61x and 2.28x the reference wall time.
Response-credit batching, native timed writes, retained HTTP/2 read-ahead
frames, and decoded-message ownership have since removed measured scheduling
and copy layers without weakening deadlines, validation or ownership. The
decoded-message ownership change removes one 262,148-byte response recopy per
roundtrip. Prefix-reserved outbound ownership then removes the second request
staging buffer without changing the borrowed Writer contract or HTTP/2
packetization. Eight fixed-binary pairs improve persistent and per-call
256-KiB throughput by a further 10.33% and 7.33%, while zero-byte instructions
improve 0.56%. Seven clean CPU-1 samples refresh the official grpc-cpp
comparison to 2.079x and 1.846x for those large-message modes. SharedChannel
borrowed request storage then removed the remaining queued 256-KiB client copy:
five clean CPU-0 official samples at `8b83e575` measured 1.670x and 1.530x for
the same persistent and per-call modes, while small messages remained 1.8-2.4x
faster than grpc-cpp. With the library's 256-KiB frame default and the opt-in
cached allocator, the current configuration measures 1.053x persistent and
0.925x per-call, making the large per-call mode faster than grpc-cpp. Small-message
native times remain lower in this fixture, but broad gRPC performance
completion is still open. The default SharedChannel path now writes const
payloads of 64 KiB or more as prefix+payload slices instead of cloning them; a
2026-11-19 persistent 256-KiB run measured 398,743 ns/roundtrip versus 474,010
ns for the historical staged path. Generic ClientDuplex, ServerDuplex and
SharedChannel owned-write APIs remain available for callers that serialize
directly into prefix-reserved storage. The synchronous `.message` unary
response path now writes the 5-byte prefix and payload as separate DATA
contributions instead of a contiguous framed copy; a 2026-11-19 follow-up
measured 406,003 ns versus 468,363 ns before the change. First cross-DATA
reassembly remains, and grpc-core retains more general segmented `SliceBuffer`
ownership. Three attempts to pass retained HTTP/2 DATA
through a Shared-call queue were rejected after all lost the 0-byte instruction
guard in 8/8 pairs; future work must preserve the existing Call layout and
small-DATA path.

- Capture the raw QUIC process matrix at the kernel/interface boundary on a
  host that permits pcap. The current complete-connection userspace UDP
  counters prove the existing shapes differ and therefore remain
  `same-application-shape`.
- Keep public HTTP/3 smoke (`https://robotics.bytedance.com/ --verify --head`)
  as a reachability gate, but do not treat it as a throughput benchmark.
