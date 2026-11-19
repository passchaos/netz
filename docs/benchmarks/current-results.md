# Current netz results

[Back to the benchmark index](../benchmark-baseline.md).

## Current netz results

### zio linked deadline I/O

`bench-io-deadline` measures zio only through its public `std.Io` boundary.
The ready shape queues one UDP datagram before each receive. The parked shape
uses a second task on the same single-executor runtime; a bounded queue wakes
that sender only after the receiver is about to submit, so the receive must
park before natural I/O completion. Both shapes compare otherwise-identical
untimed and one-second-deadline operations and validate every payload.

Five CPU-0 process samples per arm were run in alternating order on
2026-10-17. Each process reported the median of five internal order-alternated
50,000-operation samples after 2,000 warmups. Both fixed binaries used Netz
commit `73e3d553`; the baseline used zio parent `1b258ef`, while the candidate
used zio `3c2365b` with linked runtime deadlines and timer construction delayed
until the operation proves it must park. Their SHA-256 values were
`df3ca1ef1dbcb687961f1243036e959639ffc55f6cd8f2caf687b5f38da6041c`
and `c0dbd8840ac42e927d1f1aec4a6580d032a2d5413bc46a24878e52e3e9dbd7fc`.

```text
process-median ns/op       parent untimed  parent timed  linked untimed  linked timed
ready                            2717.49       2878.82         2713.90       2902.19
parked                           2773.03       2930.34         2761.29       2789.95
```

For parked I/O, the per-process median deadline increment fell from 155.16 ns
to 25.92 ns (83.3% lower), and absolute timed latency fell 4.79%; every linked
sample was below every parent timed sample. The already-ready timed path moved
from 2878.82 to 2902.19 ns/op (0.81% higher), with its normalized deadline
increment moving from 164.13 to 187.31 ns. The optimization therefore targets
the real park/wakeup path rather than claiming a universal ready-I/O win.
"Linked" here means the runtime completion and its timer share one rendezvous
and timer-heap lifecycle; it is not Linux `IORING_OP_LINK_TIMEOUT`.

### CONNECT-UDP Capsule Session

`bench-connect-udp-capsule` isolates the shared RFC 9297 Capsule data plane
used by HTTP/1.1 and HTTP/2 CONNECT-UDP. Each receive traverses an unknown
Capsule, an unknown Context ID, a valid 513-byte Context ID 0 payload, and
17-byte stream fragments; send measures the borrowed scatter/gather Capsule
header plus payload path. The owning and caller-buffer receive arms use the
same parser and tunnel source. One warmup grows retained parser storage before
allocation counters and time begin.

Seven ReleaseFast samples from clean commit `06e33d26`, pinned to CPU 0 on
2026-10-18, used 1,000,000 sends and 200,000 receives per arm. The fixed
binary SHA-256 was
`f4e4c1b77d6a7ecf847fae6ac8907936ad058674f8e228b96be0128195276341`.

| Session operation | CPU-0 range | Median | Measured allocations |
| --- | ---: | ---: | ---: |
| Borrowed send | 7-9 ns/datagram | 7 ns/datagram | 0 |
| Caller-buffer fragmented receive | 239-281 ns/datagram | 242 ns/datagram | 0 / 200,000 |
| Owning fragmented receive | 313-318 ns/datagram | 315 ns/datagram | 200,000 / 200,000 |

The caller-buffer API removed the owning arm's one allocation per UDP payload
and reduced this isolated median by 23.2%. `receiveInto` also retains a complete
datagram after `BufferTooShort`, so allocation avoidance does not weaken retry
semantics. This benchmark excludes TCP/TLS, HTTP/2 framing and scheduling,
socket I/O, and peer implementations; it is a Session hot-path result, not a
whole-network or cross-library throughput claim.

### Shared HTTP Content-Encoding decode

```text
HTTP content-coding benchmark
  io backend: zio-std-io
  coding: gzip, iterations: 50000
  payload: 4096 bytes, encoded: 80 bytes
  caller-buffer decode: 2087-2103 ns/representation, median 2092 ns
  incremental decode: 3955-3963 ns/representation, median 3959 ns
  incremental decoder state: 72 bytes
  checksum: 9953158
```

The shared `netz.http.content_coding` layer parses repeated and comma-combined
Content-Encoding fields once, caps nesting at eight codings, and decodes the
stack in reverse application order. HTTP/1, HTTP/2, and HTTP/3 aggregate
requests and responses expose the same allocating and two-workspace
caller-buffer helpers.
Every intermediate representation is independently bounded, so stacking does
not bypass the caller's decompression limit. The implementation uses Vort for
gzip, RFC 1950 `deflate`, Brotli, and Zstandard; gzip and Zstandard accept
concatenated frames while single-stream formats reject trailing bytes. The
incremental API adds an independent encoded-input ceiling, exact successful
step progress, explicit EOF validation, reusable state, and response-head
constructors on request and response heads for every HTTP version. Stacked
streams compose the same Vort
decoders in reverse order through caller-tunable fixed-capacity queues; queue
storage and codec state are retained across reset, every intermediate layer is
bounded, and fragmented input/output propagates backpressure without buffering
the whole representation. The tagged outer state remains 72 bytes and allocates
only the selected codec implementation for a single coding, so gzip/deflate
users do not carry the largest Zstandard decoder inline. Vort's raw incremental
decoder now returns an exact compressed prefix at EOB, allowing gzip/zlib
wrappers to batch input while retaining footer ownership; bounded Huffman prefix
tables and span-based match replay reduce the prior 85,330 ns incremental median
to 3,959 ns (`21.55x`, or
95.36% lower). ARM CRC32 dispatch also moves the whole-body median from 2,850 ns
to 2,092 ns. Five CPU-0 samples against Vort `eed23ef7` establish this
in-repository A/B. Vort's separate same-frame comparison against system
zlib 1.3 measured a `0.719x` full-buffer geometric-mean latency ratio and a
`0.581x` fragmented-input/output ratio across HTTP-like, JSON, and binary
workloads; these are scoped internal comparisons, not a broad industry claim.

### HTTP/1 persistent 16-request pipeline

The current HTTP/1 parse, pipeline, and streaming-body executables obtain
`std.Io` from `netz.runtime.Backend` and print `io backend: zio-std-io`. The
pipeline and body benchmarks schedule their local server through
`std.Io.async`; the body's protocol counting allocator remains separate from
the runtime allocator. `zig build bench-http1-hyper -Doptimize=ReleaseFast`
builds the locked local Hyper fixture once, then runs fixed binaries on one CPU
in an odd ABBA-order sample set. Its strict checker requires the complete
workload, derived timing, endpoint runtime identities, fixed Hyper revision,
Cargo.lock hash, and executable hashes before reporting medians.

The 2026-09-15 five-sample run on an NVIDIA Jetson AGX Thor (`aarch64`, Linux
6.8.12-1021-tegra, CPU 0, Zig 0.16.0, Rust 1.98.0, Hyper
`084473f728f9d07b3be5845475aa2f62ed9ff579`) measured:

```text
16-request pipeline:
  netz/zio:        749-799 ns/request, median 761 ns
  Hyper/Tokio:     842-854 ns/request, median 851 ns
  median speedup:  1.118x

1-MiB fixed body in each direction:
  netz/zio:        722.152-747.392 us/round-trip, median 740.191 us
  Hyper/Tokio:     768.572-783.444 us/round-trip, median 779.315 us
  median speedup:  1.053x

1-MiB chunked body in each direction, 64 x 16 KiB:
  netz/zio:        724.570-754.458 us/round-trip, median 748.436 us
  Hyper/Tokio:     951.686-967.723 us/round-trip, median 953.148 us
  median speedup:  1.274x
```

The pipeline netz/Hyper binary SHA-256 values were respectively
`0a443139e7636c667406d60b6bd137617900582cc361fe0abab0f53e18a8390e` and
`0b0e23887ff763c443087df4b34733aaeb2ca5adf0f72b0b1d0d90a26a937989`;
the body binaries were
`7e4f46e0ce2996878520f7c7a2e81c9c5818e99dabac1fa096c3cf47991a2c11` and
`9dd31d895c446f17dba2f2c449113be37bcc95bfb1f2cd18e5a40c83f15af4f4`.
The fixture lockfile hash was
`db336fa1c2df67362ee6cc7209176e082e14b7ae428cbc32ebb0c552d4936b9d`.
These are focused same-application-shape loopback results, not a whole-library
superiority claim.

A CPU-0-pinned 2026-11-19 zio-era smoke of the current netz-self pipeline
recorded 1,250 ns/request and 799,641 requests/s for depth 16, 13-byte
responses, and 32,000 requests (200 warmup, 2,000 measured). This refreshes the
backend identity only; the Hyper comparison above remains the historical
fixed-binary result.

The older results in the following historical subsection predate the zio
migration and remain `std.Io.Threaded` evidence only.

Captured on 2026-08-17. This benchmark mirrors
`~/Work/hyper/benches/pipeline.rs::hello_world_16`: each iteration sends
sixteen bodyless GET requests on one persistent loopback TCP connection and
receives sixteen `"Hello, World!"` responses. Hyper automatically adds a
29-byte Date value; netz now generates the same IMF-fixdate in its ordinary
server path, so both responses are 89 wire bytes without benchmark-only headers.
Netz runs 200 untimed warmup batches before 2,000 measured
batches. CPU 0 pinning is required on this hybrid-core host; unpinned samples
are not used for the comparison.

```sh
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast

cd /home/passchaos/Work/hyper
cargo bench --bench pipeline hello_world_16 --features full
HYPER_BENCH=$(
  find target/release/deps -maxdepth 1 -type f \
    -name 'pipeline-*' -executable -print -quit
)
taskset -c 0 "$HYPER_BENCH" --bench hello_world_16
```

```text
netz (five samples):
  0.711-0.752 us/request
  11.38-12.03 us/16-request batch
  1.330-1.406 million requests/s

hyper (five samples):
  0.836-0.866 us/request
  13.38-13.85 us/16-request batch
```

Both ranges contain five CPU-0-pinned samples. The Hyper binary was built from
revision `084473f728f9d07b3be5845475aa2f62ed9ff579` with
`rustc 1.98.0-nightly (e7815e522 2026-06-04)`.

In that historical Threaded capture, netz was about **1.11-1.22x faster** for
this same-host, same-shape sample. The
runtime path uses caller-owned head/header/body output arrays, borrowed receive
storage, one prefix compaction per pipeline, persistent write scratch,
header/body vectored writes and one transactional response-batch flush. This is
a focused HTTP/1 pipeline result, not a whole-library superiority claim. The
implementation audit and remaining HTTP/1/HTTP/2 evidence are in
`docs/hyper_parity.md`.

The response-batch encoded bytes, slice list, and offset descriptors now share
one state allocated on first batch use instead of three empty `ArrayList`s in
every connection. The slice and offset-descriptor views additionally share one
pointer-aligned backing allocation, reducing that state from 96 to 72 bytes
and its metadata backing allocations from two to one while retaining warmed
capacity. On 64-bit targets the initial lazy extraction reduces
`runtime_write.Scratch` from 320 to 256 bytes. Streaming `Trailer` names and
their backing bytes are independently allocated only when a writer must retain
an announcement through `finishTrailers`, reducing the scratch again to 192
bytes. The generated
`Trailer:` value uses a 256-byte stack-first buffer with an exact temporary
fallback; complete messages therefore create no persistent trailer state, and
the retained streaming state first fell from 72 to 48 bytes. Its name
descriptors and copied bytes now share one pointer-aligned backing allocation,
reducing that state again to 24 bytes and its first-use allocations from three
to two while retaining warmed capacity. The descriptor and iovec views used
only by multi-chunk streaming writes likewise share one
pointer-aligned backing allocation in a 24-byte state, rather than two backing
allocations in a 48-byte state. Their per-chunk hexadecimal staging is the
platform's exact maximum width (18 bytes on 64-bit targets) rather than 32
bytes, while warmed writes retain capacity. The independent flatten buffer now
lives beside response-batch storage: default small pipelines already own that
state, while an explicit single-message `flatten` policy creates it on first
use.
Content-Length rendering now uses a call-local array sized to the platform's
exact maximum decimal `usize` width instead of retaining a fixed 32-byte array
on every connection. Request Host/TE normalization and final default-header
assembly also mutate one retained descriptor list rather than allocating and
copying through two. A representative cold POST therefore falls from three
scratch allocations and 710 requested bytes first to two allocations and 486
bytes. Final header
descriptors now use 16 uninitialized stack slots with a one-allocation exact
fallback for larger sets, leaving only the encoded-byte allocation on that
common cold request. Switching the warmed scratch to the equivalent streaming
request needs no new allocation. Together these changes reduce the scratch
from 320 to 48 bytes, `Client` from 720 to 448 bytes, and `Connection` from 656
to 384 bytes. Fail-first tests keep each lazy state absent after allocation
failure, and warmed request, batch, and chunk metadata retains capacity. These
are fixed-layout and allocation-lifetime results rather than a latency claim.

The pipeline runner now accepts
`--write-strategy=auto|vectored|flatten` and reports the selected policy, so
the same payload/checksum can compare the connection-level I/O shape without
changing the benchmark. A 2026-09-09 unpinned smoke under unrelated host load
completed all 32,000 requests with identical checksums. For 13-byte responses,
auto/vectored/flatten measured 1374/1429/1342 ns/request; for sixteen 64-KiB
responses per batch they measured 10661/10011/13941 ns/request. These single
samples are functional and directional evidence only, not replacements for the
isolated five-sample ranges above. They support retaining the existing auto
choice: coalesce small pipelines and borrow large bodies through vectored I/O.

The automatic-Date path was recaptured on 2026-09-04 with three CPU-0 runs:
netz measured 0.733-0.750 us/request (11.73-12.00 us/batch), while Hyper
measured 0.844-0.846 us/request (13.50-13.54 us/batch).
The standalone HTTP/1 parser benchmark now accepts
`--scenario=borrowed|owned|owned_checked` and `--iterations=N`, allowing CPU
profiles to isolate borrowed parsing from ownership costs. A 20-million-parse
profile attributed 22.6% of user samples to `parseHeaderLine` and 18.1% to
scalar searches. Strict header parsing now validates the field-name token while
locating its colon, and validates the value while tracking its trailing-OWS
boundary; a 256-entry token table follows picohttpparser's classification
strategy. Five CPU-0 5-million-parse samples improved from 333-335 ns/op to
280-282 ns/op (334 to 282 ns median, 15.6%). Five ordinary 100,000-iteration
runs measured 283-288 ns borrowed, 828-838 ns owned, and 881-886 ns for
owned plus explicit Host validation.
The next profile identified duplicate request-framing scans: the borrowed head
path parsed `Content-Length` once to choose framing and again to return the
length, while TE+CL handling separately rescanned field names to choose the
must-close safeguard. One internal scan now returns framing, parsed length and
the smuggling-safe close decision together. Five CPU-0 5-million-parse runs
measured 264-265 ns/op, reducing the isolated median from 282 to 264 ns (6.4%)
and from the pre-pass 334 to 264 ns (21.0%). A dedicated regression preserves
the existing rule that valid final `chunked` overrides even malformed
Content-Length syntax while forcing connection close.
The following profile placed ordinary Host validation at about 10% of sampled
cycles. It previously scanned a typical `example.com` repeatedly for a URI
marker, forbidden delimiters, brackets and a port colon. One structural pass
now performs those checks together while preserving bracketed IPv6 and strict
decimal-port validation. Five CPU-0 5-million-parse samples measured
237-239 ns/op, improving the isolated median from 264 to 238 ns (9.8%) and from
the pre-pass 334 to 238 ns (28.7%). Five default-shape runs measured
240-242 ns borrowed, 795-797 ns owned and 818-822 ns owned plus explicit Host
validation. Existing Host regressions cover URI/userinfo/list delimiters,
queries/fragments, unbracketed IPv6, mixed brackets and port overflow.
Finally, explicitly inlining the now compact `parseHeaderLine` hot helper
removed its call boundary in both borrowed and owned loops. Five CPU-0
5-million-parse samples measured 231-234 ns/op (231 ns median), another 2.9%
below 238 ns. Five default-shape runs measured 236-241 ns borrowed,
766-769 ns owned and 791-796 ns owned plus Host validation. Two earlier
implementations were rejected by A/B evidence at their then-current revisions:
the first scalar CRLF/header fusion regressed to 259-261 ns/op, and vectorized
colon search followed by token validation regressed to 253-257 ns/op. The
strict-only design below was independently reworked and measured against the
current baseline; it does not retain either rejected implementation.
The ordinary no-obs-fold owned parser now retains up to sixteen validated
header descriptors on the stack during its counting pass. Common requests copy
those descriptors into the one exact result allocation instead of parsing and
validating every line a second time; larger sets preserve the prior exact-count
allocation and second fill pass, so no geometric attacker-controlled scratch is
introduced. Seven CPU-0, order-alternated fixed-binary pairs at
`zig-out/http1-header-single-pass-ab` (24,775,320 bytes; aggregate file-hash
digest `3720f5740a69e13253d4774ebe2bb6d533f3af78ffe58ac077edfa6b3136b061`)
used parser binaries `3b0e2e34`/`c2a452da`. The five-million-parse owned
scenario improved in all seven pairs from 920 ns/op median (920-928) to
580 ns/op (580-582), a 37.0% reduction. The separate 16-request persistent
pipeline control used binaries `e8d53279`/`ea584e02` and moved from 794 to
803 ns/request by paired medians (+1.1%) with overlapping ranges; that runtime
uses its caller-buffer borrowed parser, so no pipeline improvement is claimed.
The borrowed strict parser now likewise avoids a redundant physical-line pass:
it validates each field name and value while locating its terminating CRLF.
Spaces-before-colon and ignore-invalid compatibility policies retain the
original complete-line parser, which is also used as a differential oracle.
The regression matrix compares every possible byte in a representative field
name and value plus every truncation boundary, and fixes the existing rule that
an incomplete malformed field remains `BufferTooShort` until its CRLF arrives.

Twenty CPU-10, fixed-binary, order-alternated pairs used two million borrowed
parses per arm with exact 348,000,000-byte totals. Baseline SHA-256
`d7257413a6a858f19b8743d9e2e3168867e5f7daa691ed3a8fba0856fd93adef`
and candidate
`e74fa2cda556da25a9a53c32719712f16cbdfcede0472df8232c35c05a4583bd`
measured a 0.832031 paired median ratio (-16.797%, 20/20 wins), with
257/214 ns/op standalone medians. Seven paired `perf stat` arms reduced
instructions to 0.859603 (-14.040%, 7/7) and cycles to 0.833336 (-16.666%,
7/7). Equal-duration 10-million-parse profiles moved approximate event count
from 6,700,536,659 to 5,552,467,677 (-17.134%); the former separate
`mem.findPosLinear` CRLF scan disappeared from strict field parsing.

The independent 16-request TCP pipeline used binaries
`fa46bb325e2515b5a89ecebb4f166b7c74e2c9c62f18c356fd29849d9480c9ea` and
`06e076fc9735fe37bb15915dd42dce9a75d6fe0d7901a44bc4627c90f5641aa1`,
500 warmup plus 5,000 measured batches per arm, and exact 7,120,000-byte
checksums with 88,000 server requests. Its paired latency ratio was 0.994490
(-0.551%, 18/20 wins); instructions fell to 0.962999 (-3.700%, 7/7) and
cycles to 0.982606 (-1.739%, 7/7). This is a parser and same-process pipeline
result, not a claim about end-to-end Internet latency. Debug/ReleaseFast HTTP/1
tests, parser/cleartext/TLS connection fuzz gates, and complete bidirectional
Hyper cleartext/TLS interoperability passed.
Absolute-form detection now rejects an empty target or any non-alphabetic
first byte before searching for `://`. RFC 3986 requires a scheme to begin
with an ASCII letter, so ordinary origin-form `/...`, OPTIONS `*`, and invalid
numeric/control prefixes cannot be absolute-form. The public helper retains
full validation for alphabetic schemes, including authority/userinfo/path
rules. A 256-value first-byte regression plus uppercase-scheme coverage binds
that split. `bench-http1-parse` now also accepts
`--target-form=origin|absolute`, with origin remaining the default.

Twenty fixed-binary CPU-10 AB/BA pairs used two million borrowed origin-form
parses per arm and exact 348,000,000-byte totals. Baseline SHA-256 was
`b50f73d9769218f458f85d5a9d9651bef0253d59b645cff724eb7ae9b75c07d5`,
candidate
`1f27a51233dc6bab165f8f5d721bac6476ae10c6e10320d6f833dba813a7e42b`.
Latency, cycles and instructions improved by paired medians of 1.041357,
1.039862 and 1.036547; latency won 19/20 pairs and both counters won 20/20.
Twelve one-million-parse pairs with the extended benchmark improved owned
parsing by 1.008958 median (11/12 latency/cycles, 12/12 instructions) and
owned-plus-explicit-Host validation by 1.028594 (12/12 for all three).

The equal-source absolute-form control used binaries
`081a5907e5d5481d09fc245fbd614b9a0cfd18f9416a288b2bfafdf7916ecacb`
and
`065f4c77114cbd0a6adae3816b33bca866f5de9cec795455e94292cb57bd0c16`.
Across twenty pairs its latency median was exactly 1.000000, cycles 0.999016,
and instructions exactly 1.000000, with ranges crossing 1.0; no absolute-form
change is claimed. A real 16-request persistent pipeline used fixed binaries
`22b0f39d61d17378c0b4a052a283caa7155a755e918c222e214aa10c8f8c6053`
and
`0ad39f5ea2b75d34417a94f1be075aa9ae016416009c966055177529505d540c`.
Twenty 500-warmup/5,000-measured pairs completed 80,000 requests and exact
7,120,000-byte checksums per arm. Elapsed time improved by 1.007725 median
with 17/20 wins and cycles by 1.014609 with 20/20 wins; instructions increased
by 0.159% in every pair because the predictable form branch replaces a longer
scan. The runtime conclusion is lower cycles and latency, not fewer executed
instructions.

Equal-duration 20-million-parse profiles had zero lost samples and moved
approximate event count from 11,140,535,340 to 10,674,843,162. The former
4.01% standalone `absoluteFormAuthority` entry fell below the 0.20% reporting
threshold. These independent profiles explain the call path; fixed-pair
results carry the performance claim. Raw parser, absolute-form control,
owned, pipeline and profile artifacts are retained under
`zig-out/http1-absolute-form-fastpath-ab` and
`zig-out/http1-absolute-form-fastpath-profile`; their combined manifest hashes
to `1abd2c9883be66180a2b763664f4a870773d2c86214be8dd0249e05506bc9f00`.

A 2026-10-19 follow-up audited the remaining HTTP/1 start-line and metadata
hotspots without retaining a production change. The fixed parser baseline was
`065f4c77114cbd0a6adae3816b33bca866f5de9cec795455e94292cb57bd0c16`.
Replacing the two exact HTTP-version comparisons with one `HTTP/1.` prefix
check plus a minor-version dispatch produced candidate
`d94517a84f637693596424850c841d3a87a5d6826c5fa7fa439b5afa16798207`.
Across twenty CPU-10, five-million-parse borrowed origin-form pairs, the
baseline/candidate medians were 0.990888 for latency, 0.991600 for cycles, and
1.014213 for instructions: executed instructions fell in every pair, but the
candidate was slower in 15/20 latency and cycle pairs. Twelve owned pairs were
also slower in 12/12 latency and cycle comparisons, with medians 0.994314 and
0.994323. Twenty absolute-form pairs had latency/cycle medians of 0.982143 and
0.982558, despite a 1.010281 instruction ratio.

The matching 16-request pipeline candidate
`19fc23639ed2db1fec493e984b0ba50fa6e79df4f4095ee69428fd7fad8c7cc4`
did improve elapsed time, cycles, and instructions by baseline/candidate
medians of 1.011533, 1.022609, and 1.018417 with 20/20 wins. That opposite
result was not used to hide the direct parser regressions: two further
fixed-width/minor-first implementations also reduced instructions while
losing parser cycles, and the first candidate enlarged the allocating parser's
generated body by 60 bytes. The audited httparse 1.10.1 reference likewise
recognizes HTTP/1.0 and HTTP/1.1 with two native eight-byte comparisons rather
than a prefix/suffix split. The complete bidirectional Hyper cleartext/TLS gate
passed, so semantics and interoperability were not the rejection reason.

Three subsequent candidates showed the same instruction-versus-cycle trap.
Directed request-line delimiter searches reduced instructions by a 1.014756
ratio but lost latency and cycles in all five screening pairs. Fixed-literal
word comparisons for Host, Content-Length, and Transfer-Encoding reduced
instructions by 0.77% but had baseline/candidate latency and cycle medians of
0.977477 and 0.979029. A fused borrowed Host/framing scan initially measured
1.009238 latency, 1.007518 cycles, and 1.006386 instructions across twenty
pairs, but its owned control regressed latency and cycles in all twelve pairs
at 0.988730 and 0.988348. Restoring the owned implementation removed most of
the borrowed gain, and a borrowed-only state variant then regressed by about
8%. These results identify generated-code layout and dependency-chain
sensitivity rather than a robust eliminated-work win. Every candidate and its
test-only oracle was therefore removed; no start-line, header-comparison, or
metadata-fusion performance claim is retained.

HTTP/1 aggregate message-boundary logic now lives under
`runtime/message/framing.zig`: head limits, Content-Length and
Transfer-Encoding classification, decoded chunk limits, trailer limits,
method-aware close-delimited responses, interim-response classification, and
automatic 100-continue eligibility share one pure module and focused tests.
The runtime also delegates legal HTTP/1.1 non-final transfer-coding responses
directly to the core parser instead of sanitizing and reparsing the head,
removing three temporary allocations while preserving Transfer-Encoding and
stripping conflicting Content-Length. HTTP/1.0 Transfer-Encoding remains a
hard error and has a real TCP regression.

The same executable now accepts `--large-body`. With sixteen 64-KiB fixed
responses, the runtime validates the whole pipeline but borrows bodies into a
single writev rather than building a 1-MiB concatenation. Three CPU-0 samples
were 10.66–10.79 us/request, down from a captured 15.43 us/request on the old
copying path (1.43–1.45x faster). This is an internal branch comparison rather
than an equal-shape Hyper result.

### HTTP/1 persistent bidirectional 1-MiB bodies

Captured on 2026-08-19 against the checked-in same-shape Hyper harness under
`tools/hyper_http1_body`. Both sides use one persistent TCP_NODELAY connection,
20 warmups, 200 measured round trips, streaming receive, and 1 MiB in each
direction. Fixed mode uses one exact Content-Length body; chunked mode uses
64 × 16-KiB application chunks.

```text
fixed (five samples):
  netz:  268.72-270.10 us/op, 7,404-7,442 aggregate MiB/s
  hyper: 288.61-293.14 us/op, 6,822-6,929 aggregate MiB/s

chunked (five samples):
  netz:  284.04-286.06 us/op, 6,991-7,041 aggregate MiB/s
  hyper: 414.64-417.45 us/op, 4,790-4,823 aggregate MiB/s
```

In that historical Threaded capture, netz was 1.07-1.09x faster in the fixed
workload and 1.45-1.47x faster in the chunked workload. The reusable
implementation changes are TCP_NODELAY, direct
socket-to-callback fixed-body delivery, retained chunk/vector scratch, batched
`writeChunks`, wide POSIX writev submission, and 64-KiB chunked read-ahead into
the persistent connection buffer. Read-ahead can span several chunk boundaries
or a pipelined suffix, but callbacks still receive one wire chunk at a time and
the suffix remains buffered for the next message. These are focused workload
results, not a whole-library superiority claim.

A CPU-0-pinned 2026-11-19 zio-era smoke of the netz-self fixed 1-MiB
bidirectional body recorded 269,693 ns/round-trip and 7,415 aggregate MiB/s
(20 warmups, 200 measured). This refreshes the backend identity only.

### HTTP/2 persistent consecutive and parallel round trips

The current executable obtains `std.Io` from the zio backend and schedules its
local server through `std.Io.async`; it prints `io backend: zio-std-io`. The
numeric results in this section were captured before that migration and remain
historical `std.Io.Threaded` evidence until a fixed-binary zio run is recorded.
The in-process 1-MiB response and duplex self-benchmark scenarios are currently
selectable with `--scenario` but skipped by the default run because they
deadlock in the single-executor harness; this is a known open item, not a
performance result.

A single unpinned 2026-11-19 ReleaseFast run of the current in-process harness
(`zig build bench-http2-h2c -Doptimize=ReleaseFast`) recorded:

```text
consecutive x1 empty:              9,941 ns/request   100,589 req/s
shared consecutive x1 empty:      10,655 ns/request    93,852 req/s
consecutive x1 10-byte request:    8,899 ns/request   112,361 req/s
consecutive x1 100-KiB request:   21,367 ns/request    46,799 req/s
consecutive x1 10-byte response:   8,808 ns/request   113,531 req/s
parallel x10 empty:                2,104 ns/request   475,230 req/s
parallel x10 1-MiB request batch: 176,342 ns/request     5,670 req/s
```

The host also ran unrelated builds, so this is a backend-identity and
scenario-coverage refresh, not a fixed-binary comparison or a cross-library
claim.

Captured on 2026-08-17 against Hyper's
`http2_consecutive_x1_empty`, `http2_consecutive_x1_req_10b`,
`http2_consecutive_x1_req_100kb`, and `http2_parallel_x10_empty` benchmarks.
Each scenario uses a persistent prior-knowledge connection and both processes
were pinned to CPU 0. Netz and Hyper both generate Date through their default
server paths, while netz matches Hyper's 1-MiB server receive windows and uses
untimed warmup so steady-state wire,
flow-control and calibration shapes match.

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast

cd /home/passchaos/Work/hyper
cargo bench --bench end_to_end http2_consecutive_x1_empty \
  --features full --no-run
HYPER_H2_BENCH=$(
  find target/release/deps -maxdepth 1 -type f \
    -name 'end_to_end-*' -executable -print -quit
)
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_consecutive_x1_empty
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_consecutive_x1_req_10b
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_consecutive_x1_req_100kb
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_parallel_x10_empty
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_parallel_x10_req_10kb_100_chunks_max_window
taskset -c 0 "$HYPER_H2_BENCH" --bench http2_parallel_x10_res_1mb
```

```text
empty GET (five samples):
  netz:   9.55-9.96 us/op
  hyper: 12.51-12.54 us/op
  netz latency advantage: 1.26-1.31x

10-byte POST (five samples):
  netz:  10.09-10.38 us/op
  hyper: 41.15-41.37 ms/op

100-KiB POST (five samples):
  netz:  23.52-23.57 us/op
  hyper: 37.24-38.68 us/op
  netz latency advantage: 1.58-1.64x

parallel x10 empty GET (five samples):
  netz:  26.35-26.60 us/batch, 2.63-2.66 us/request
  hyper: 47.50-48.46 us/batch, 4.75-4.85 us/request
  netz batch-latency advantage: 1.79-1.84x

parallel x10, 100 x 10-KiB request chunks/stream, max windows:
  netz:  1.64-1.74 ms/batch, 164-174 us/request
  hyper: 3.36-3.40 ms/batch, 336-340 us/request
  netz batch-latency advantage: 1.93-2.07x

parallel x10, 1-MiB response/stream, max windows (2026-08-19):
  netz:  1.663-1.671 ms/batch, 166.3-167.1 us/request
  hyper: 2.957-3.035 ms/batch, 295.7-303.5 us/request
  netz batch-latency advantage: 1.77-1.82x
```

A three-run 2026-09-04 CPU-0 post-change recapture of the first four shapes
measured netz at 9.980-10.288 us, 10.516-10.525 us, 23.173-23.279 us and
27.611-27.808 us/batch; matching Hyper spot samples were 12.514 us,
41.012 ms, 37.168 us and 47.994 us/batch.
Outbound HTTP/2 hop-by-hop filtering now lives in `runtime/headers/connection.zig` and
collects every `Connection` field before mutating the header list. Common
requests use eight stack entries instead of the former fixed 256-entry array;
larger sets allocate their exact count. Tests cover a 257th late nomination,
allocation-failure rollback, request-only `TE: trailers`, and request/response
high-level wire paths. Three CPU-0 post-change runs measured the six standard
shapes at 9.850-10.044 us, 10.270-10.397 us, 23.062-23.288 us,
27.372-27.503 us/batch, 168.481-169.305 us/request, and
169.684-170.277 us/request respectively, within the preceding ranges.
The remaining pure HTTP/2 header logic now lives in the same nested hierarchy:
`runtime/headers/message.zig` owns Content-Length parsing, pseudo-header order,
URI/authority validation, trailer restrictions, request lookups, and
request-aware response body semantics. Focused tests under
`runtime/headers/tests/` cover those rules while real connection tests remain
at the integration layer. This removes another 565 lines from `runtime.zig`
without changing public types. Three CPU-0 post-extraction runs measured the
six standard shapes at 9.802-9.992 us, 10.264-10.469 us, 23.112-23.242 us,
27.437-27.504 us/batch, 169.371-171.263 us/request, and
170.763-173.576 us/request respectively, within the previous ranges.
HTTP/2's transport-facing frame boundary now follows the same nested layout:
`runtime/frame/io.zig` owns borrowed/owned reads and scatter/gather writes,
while `runtime/frame/wire.zig` owns envelope validation and direct fixed-frame
and batch encoding. HEADERS plus CONTINUATION batches reserve their complete
encoded size before appending, so allocator failure leaves the caller's batch
unchanged and successful multi-frame assembly performs a single capacity
check. Focused tests cover envelope rules, exact flags/payload partitioning,
preallocated reuse, and allocation-failure rollback.
The reader retains the measured 64-KiB coalescing window and grows exactly to
the frame boundary only when a legal frame is larger. A trial 16-KiB default
reduced idle capacity, but regressed the large-body benchmark by requiring an
extra initial read, so it was rejected rather than trading throughput for a
memory-only improvement. The audited Hyper/h2 generic framed reader starts at
8 KiB, but its async scheduling and buffer ownership differ from this blocking
runtime; the local fixed-CPU result remains the deciding evidence here.
The connection/stream flow-window primitive now lives under
`runtime/flow/window.zig`, matching the audited h2 model's signed window domain:
SETTINGS reductions may make a stream negative, but arithmetic cannot escape
the signed 32-bit protocol range. Zero-length DATA reservations and receives
remain legal even while a stream window is negative, so an empty END_STREAM
does not wait for credit it does not consume. Focused tests cover blocked send,
receive violations, both bounds, and transactional failure.
Three fixed-binary CPU-0 runs after the flow-window extraction measured the
six standard shapes at 10.094-10.227 us, 10.490-10.584 us,
23.210-23.398 us, 27.898-28.111 us/batch, 170.335-171.941 us/request, and
175.235-176.246 us/request. This is a regression guard rather than a speedup
claim; the change centralizes arithmetic and fixes edge semantics.
Three fixed-binary CPU-0 runs after the extraction measured the six standard
shapes at 10.022-10.066 us, 10.548-10.626 us, 23.229-23.273 us,
27.626-27.768 us/batch, 168.581-169.911 us/request, and
170.828-172.510 us/request respectively. These stay within the established
range; the one-shot build invocation outliers were excluded because build and
measurement were not isolated. After rejecting the smaller read-ahead trial,
three final fixed-binary runs measured 9.923-10.035 us, 10.449-10.565 us,
23.243-23.372 us, 27.951-28.156 us/batch, 167.797-168.067 us/request, and
173.706-174.753 us/request.

The h2c harness now accepts `--scenario=<name>` and `--stats`, with allocator
snapshots taken after warmup and exact allocation sizes reported alongside the
size buckets. On the consecutive empty GET shape, the initial telemetry found
exactly six allocations per exchange: the two owned HPACK outputs at each
endpoint plus 19-byte request and 11-byte response frame copies. Aggregate
request and response readers now borrow ordinary wire frames from the reusable
64-KiB frame-reader buffer, while frames dequeued from the pending application
queue retain their owning fallback. A post-change run removed both frame sizes
and measured exactly four allocations per exchange (8,000 over 2,000 measured
requests), down 33.3% from 12,000; cumulative requested bytes fell from
1,316,000 to 1,256,000. Five fixed-binary CPU-0 samples measured
9.606-9.880 us/op. This is allocation/copy evidence and a local regression
range, not a new cross-stack speed ratio. Reproduce the isolated shape with:

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_consecutive_x1_empty --stats
```

The remaining descriptor-array and string-block allocations at each endpoint
are now coalesced into one aligned allocation without changing the public
`HeaderField` slices. The same warmed empty exchange therefore fell again from
four to two allocations per request (4,000 over 2,000 measured requests), with
one 409-byte request-header block and one 219-byte response-header block.
Cumulative requested bytes remained exactly 1,256,000, confirming that this
step removes allocator calls rather than payload ownership. Five post-coalesce
fixed-binary CPU-0 samples measured 9.642-9.931 us/op; the earlier
four-allocation sample remains above to separate the two optimizations, and no
throughput gain is claimed from their overlapping latency ranges.
For the consecutive 10-byte POST shape, exact-size telemetry then identified
the remaining transient 143-byte block as `ArrayList` geometric growth despite
an already validated `Content-Length: 10`; `toOwnedSlice` subsequently allocated
and copied a 10-byte result. Exact reservation plus direct ownership transfer
removed that over-allocation and copy. A warmed run fell from four to three
allocations per request and from 2,010,096 to 1,724,096 cumulative requested
bytes over 2,000 requests; its remaining per-request allocations are exactly
the request HPACK block, 10-byte body and response HPACK block.
The symmetric aggregate response path is now covered by
`http2_consecutive_x1_res_10b`. Before exact reservation it allocated a
143-byte geometric body buffer and then copied into a 10-byte result, taking
16.843 us/op in the captured baseline. Exact `Content-Length` reservation and
direct transfer reduced the warmed shape from four to three allocations per
request and cumulative requested bytes from 2,008,096 to 1,722,096 over 2,000
requests. Five fixed-binary CPU-0 samples measured 10.006-10.363 us/op. The
remaining allocations are the request HPACK block, response HPACK block and
exact 10-byte response body.
The aggregate parallel response reader now uses the same borrowed-frame cursor
as its streaming counterpart. On `http2_parallel_x10_empty`, this removed one
11-byte owned frame per response: a warmed 2,000-batch run fell from 80,000 to
60,000 allocation calls and from 16,420,000 to 16,200,000 cumulative requested
bytes. The single before/after timings were 28.607 and 28.363 us/batch, so this
records the deterministic allocation/copy reduction without claiming a latency
improvement.
The client request and server response batch writers now alternate between the
live HPACK encoder and a second connection-owned encoder allocated on first
batch use. Before staging a batch, the inactive encoder copies live compression
state while retaining its entry, index, string and encoded-block capacities;
commit is a pointer-free swap. On the same warmed
parallel x10 run this removed the remaining ten batch-level clone allocations
per batch, reducing measured calls from 60,000 to 40,000 and cumulative
requested bytes from 16,200,000 to 12,560,000. The exact-size list now contains
only the 20,000 request and 20,000 response owned HPACK blocks. The single
telemetry sample was 27.415 us/batch; five subsequent fixed-binary CPU-0 runs
measured 26.258-26.431 us/batch. This is recorded as an internal regression
range rather than a new cross-stack ratio.
The single-stream streaming-request reader now borrows its initial wire frame
under the same pending-owned fallback. The 100-KiB POST scenario removed one
26-byte HEADERS allocation per request, reducing the warmed 2,000-request run
from 6,020 to 4,020 allocation calls and from 1,902,112 to 1,850,112 cumulative
requested bytes. Its 23.533-us sample stays within the established range, so
only the allocation/copy reduction is claimed.

The h2c harness also contains an internal A/B for the combined body-bearing
request and large-response case. Both modes send ten concurrent 1-MiB POST
bodies and receive ten 1-MiB responses with identical frame scheduling; only
the client response ownership policy changes:

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_parallel_x10_duplex_1mb_aggregate --stats
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast -- \
  --scenario=http2_parallel_x10_duplex_1mb_streaming --stats
```

Three alternating CPU-0 paired runs with exact 1-MiB bodies measured
6.744-7.020 ms/batch for aggregation and 3.422-3.540 ms/batch for callback
streaming, a 1.91-1.97x latency advantage for this workload. Aggregation made
166 measured allocations totaling 52,488,942 bytes and peaked at 10,640,263
live bytes in every run. Streaming
made 116 allocations totaling 60,142 bytes and peaked at 155,557 live bytes.
The exact-size report attributes the material difference to fifty eliminated
1,048,576-byte response-body allocations (ten responses across five measured
batches). This is an internal API-shape comparison rather than an external-
library superiority claim.

`strace` confirmed equal steady-state wire sizes: empty exchanges use 19-byte
requests and 11-byte responses; POST exchanges use 43-byte requests and
11-byte responses. The large POST gap is specifically Hyper's two-write
HEADERS/DATA path hitting Linux's Nagle/delayed-ACK interaction on this host,
not a general whole-library ratio. Netz preserves both HTTP/2 frames but submits
their four slices in one `sendmsg`; larger, fragmented or flow-blocked messages
fall back to ordinary frame writes. The 100-KiB case uses TCP_NODELAY, matched
receive windows, vectored DATA bursts, a connection-level multi-frame receive
buffer and callback-based streaming request consumption. The client now has a
symmetric callback-based response API with owned initial/trailing headers,
strict streamed Content-Length accounting, continuous flow-credit return, and
RST_STREAM cancellation on consumer failure. The server-side `ResponseWriter`
provides the corresponding multi-call body producer with flow-control waiting,
transactional cumulative length validation, trailer/FIN completion and
unfinished-writer cancellation. The client-side `RequestWriter` adds the same
multi-call upload and trailer lifecycle, then hands the live stream to owned or
callback-streaming response receive without first aggregating request bytes.
An early response encountered while the upload waits for WINDOW_UPDATE is
retained in one bounded owned-frame slot and returned as `ResponseAvailable`;
the writer records any successfully sent prefix and transfers that response
without losing HPACK or wire ordering.
Bodyless parallel batches use
transactional HPACK staging, one request/response submission in each direction,
and stream-ID-based response reordering. See `docs/hyper_parity.md` for the
implementation audit and additional H2 comparison work.
Body-bearing request batches add transactional credit preflight, staged HEADERS,
round-robin borrowed DATA contributions, and server-side interleaved streaming
request demultiplexing without body aggregation.
The response-body batch uses the symmetric server scheduler and client
stream-ID demultiplexer: ten borrowed 1-MiB payloads are framed round-robin,
using the same 16-KiB per-stream turn as Hyper's locked h2 0.4.15 scheduler,
and callbacks account response DATA without retaining a 10-MiB aggregate.
These ranges establish advantages for the named loopback workloads only; they
do not establish whole-library HTTP/2 superiority.

### HTTP/2 flow-controlled parallel responses

This benchmark now uses the same zio-backed `std.Io` boundary and schedules
its server with `std.Io.async`. The HPACK microbenchmark also obtains its clock
from zio. Existing numeric results in this HTTP/2 section predate the migration
and are retained as historical `std.Io.Threaded` baselines.

The RFC 9218 selector now chooses urgency and the lowest stream-ID
non-incremental winner in one candidate pass. Three CPU-0-pinned priority-mode
runs with ten 1-MiB responses and 8-KiB stream windows measured 7.79–7.96
ms/batch (1.26–1.28 GiB/s), versus 8.03 ms/batch immediately before scan
fusion.

Captured on 2026-08-19 with ten bodyless requests and one 1-MiB response per
stream. Both implementations use a persistent h2c connection, a 16-KiB maximum
DATA frame size, an 8-KiB initial stream window, the RFC default 65,535-byte
connection window, a barrier before response creation, 5 warmups and 20
measured batches. Both clients consume all streams concurrently and return
WINDOW_UPDATE while DATA is arriving.

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --warmup=5 --iterations=20
taskset -c 0 tools/bench_hyper_http2_flow.sh \
  --warmup=5 --iterations=20
```

The netz workload also accepts `--priority`. This enables RFC 9218 on both
peers and assigns one urgency-0 non-incremental, four urgency-2 incremental,
and five urgency-5 incremental requests in the default ten-stream batch:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=2 --iterations=5
```

Two sets of three CPU-0-pinned 2026-08-19 runs completed in
7.880-8.015 ms/batch (1,247-1,268 body MiB/s). This is an internal scheduler
baseline because the locked h2 0.4.15 reference has no RFC 9218
urgency/incremental scheduler.

```text
five CPU-0-pinned samples:
  netz:  7.367-7.447 ms/batch, 1,342-1,357 body MiB/s
  hyper: 10.192-10.379 ms/batch, 963-981 body MiB/s
  netz batch-latency advantage: 1.37-1.41x
```

Three alternating 2026-09-04 runs with runtime-generated Date measured netz at
7.586-7.660 ms/batch (1,305-1,318 MiB/s) and Hyper at
10.155-10.196 ms/batch (980-984 MiB/s), a 1.33-1.34x latency advantage. A
short-run A/B against the saved pre-change netz binary showed 7.487 ms median
versus 7.482 ms with the former fixed field (0.07%, within run noise).

The reusable change is a blocking-runtime multi-stream DATA scheduler: it
reserves only bytes being emitted in the current round, rotates the starting
stream after progress, and pumps SETTINGS/PING/WINDOW_UPDATE plus member-stream
RST_STREAM while blocked. Payloads remain borrowed and HPACK/scratch validation
still completes before HEADERS are written. This is focused backpressure and
fairness evidence, not a whole-stack superiority claim.

The same benchmark now covers a priority/flow-control cancellation race:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --cancel-after=8 --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=0 --iterations=1
```

The client accepts eight scheduled DATA callbacks, then rejects the batch and
sends RST_STREAM(CANCEL) for all unfinished streams. Timing includes server
observation of the reset batch. Five CPU-0 runs measured 230.4-241.2 us/batch.
The cancellation path now coalesces all resets into one transport write instead
of one write per stream and removes canceled send/receive-window entries. Reset
is the precise lifecycle boundary: ordinary half-close keeps its windows until
the opposite direction completes, while local, peer, pushed-stream, and batch
RST_STREAM paths retire both indexed entries immediately. A `--stats`
sample made 293 allocations and peaked at 1,287,988 live bytes. This closes the
previous priority-aware cancellation timing gap; there is no equal Hyper/h2
RFC 9218 scheduler workload, so it remains internal evidence.

The cross-client cancellation benchmark fixes the server to Hyper and is
reproducible with:

```sh
zig build bench-http2-cancel-hyper -Doptimize=ReleaseFast
```

Each measured batch starts a 128-KiB flow-blocked response and a concurrent
16-KiB sibling on one persistent connection. Both clients consume exactly the
8-KiB stream window and cancel the target; the Hyper server gates the sibling
on its incomplete response body being dropped after stream cancellation, and a
final request proves connection reuse. The existing reverse-direction
interoperability gate separately decodes and requires `RST_STREAM(CANCEL)`.
Five samples alternate netz and Hyper client order across dedicated CPUs, with
twenty warmups and 1,000 measured batches per process. Repeated long runs gave
netz median times of 132.2-153.6 us/batch and Hyper medians of
143.3-200.2 us/batch, a 1.044-1.433x advantage for netz. Short 100-batch
exploratory medians varied from a 0.939x regression to a 1.229x advantage and
are not used for the performance claim. All long runs reported the expected
24,576,000-byte checksum, 1,020 server-observed cancellations, and 1,020
sibling completions per sample. The netz explicit allocator peak was
203,352-203,385 bytes; Hyper's process-wide Rust requested-byte peak was
144,750 bytes. These scopes differ, so no allocator ratio is claimed. BusyBox
`time` reported client-process MaxRSS medians of 11,264-12,288 KiB for netz and
11,264 KiB for Hyper, so no RSS advantage is claimed. A strict checker verifies
the workload, timing arithmetic, server observations, memory arithmetic, RSS
source, binary hashes, pinned Cargo lock and Hyper revision. This is a focused
same-server cancellation/recovery result, not a general HTTP/2 throughput
claim.

### HTTP/3 QPACK dynamic encode

```text
HTTP/3 QPACK dynamic encode benchmark
  iterations: 100000, table entries: 512, fields/block: 32
  encoded bytes/block: 68, references/block: 32
  ns/block: 864-882, ns/field: 27
  dynamic table churn: 945-968 ns/insert
  checksum: 10000000
```

Dynamic entries own name and value in one contiguous allocation rather than two independent blocks. This removes one allocation/free pair per insert/eviction while retaining separate borrowed slices. The immediately preceding two-block build measured 1,235-1,268 ns/block; the indexed lookup workload improved by about 1.40-1.47x. Quicz duplicates name and value separately and inserts at array index zero, adding a second allocation and an O(n) shift under churn.
QPACK owned field-section decode now co-locates its `HeaderField` descriptors and
contiguous name/value bytes in one aligned allocation, while the deallocator
still accepts the prior separate `block_storage` layout used by other callers.
Both literal and dynamic decoder tests assert one final allocation, pointer
layout and exhaustive allocation-failure cleanup. Five CPU-0 dynamic-decode
runs measured 751-762 ns/block in four stable samples with one 835-ns outlier,
versus the preceding 835-857 ns range (838-ns median).
The follow-up owned builder retains encoded string plans rather than first
decoding into a 16-KiB stack-backed staging list and copying those bytes again
at finalization. It now decodes or copies each string directly into the final
co-located allocation. Three interleaved 1,000,000-iteration CPU-0 runs measured
638-653 ns/block versus 759-773 ns/block at the preceding commit (1.16-1.21x
faster). A 40-field mixed Huffman/literal/dynamic allocation-failure test covers
the heap plan fallback and final-allocation cleanup.
Pre-sizing the stack-fallback plan list to its 32-field inline budget removes
the geometric grow/remap sequence from ordinary owned sections while retaining
the same heap migration above that bound. Four stable interleaved CPU-0 runs
measured 590-599 ns/block versus 634-647 ns/block at the direct-to-final commit
(1.06-1.10x faster); one cold 921-ns baseline outlier was excluded.
The owned-field plan now stores its two Huffman flags and never-indexed state
in one packed byte next to the raw slices and decoded lengths. On 64-bit
targets this reduces each plan from 72 to 56 bytes and the 32-field stack
budget from 2,304 to 1,792 bytes without changing final field ownership or
wire output. Nine CPU-0, order-alternated, fixed-binary comparisons against
parent `e128fb55` used the same explicit anti-elision barrier and three million
decodes per arm. The parent measured 682-710 ns/block (693 median); the compact
plan measured 571-582 ns/block (574 median), won all nine pairs, and reduced
median time by 17.2%. These are internal owned-decode results, not a
cross-library QPACK claim.

The same executable now includes a 512-field/512-unique-reference section to
expose reference-set bookkeeping that the ordinary 32-field block cannot.
Three CPU-14 baseline runs took 50.50-65.60 us/block (98-128 ns/field). A
sort/compact prototype reduced that large shape to 18.70-18.79 us but enlarged
the shared encoder enough to regress the ordinary block from 917 ns to about
1,247 ns, so the implementation was rejected and fully rolled back. The
accepted large-only hash-membership path now preserves first-reference order
without rescanning the growing reference list. Five CPU-0 samples measured
14.10-14.59 us/block (27-28 ns/field), down from the immediately preceding
49.10-49.45 us/block CPU-0 baseline, or 3.37-3.51x faster. The same runs kept
the ordinary 32-field block at 821-827 ns/block after isolating hash-backed
emission from its linear stack path. These are internal before/after results,
not an equal-wire cross-library comparison.
The follow-up replaces that large-only hash membership with a bitmap relative
to the dynamic table's oldest live absolute index. Its space is bounded by the
current table entry count rather than the lifetime insertion count. Five CPU-0
samples measured 11.02-11.28 us/block (21-22 ns/field), another 1.24-1.32x
improvement over the hash version and 4.35-4.49x over the original linear
deduplication baseline; the 32-field block remained at 804-826 ns/block.
Use `--scenario=encode|large|churn|decode` and `--iterations=N` to isolate one
phase for profiling; omitting both options retains the combined default run.
In the isolated 512-reference scenario, combining the already-computed name and
value digests directly for the exact-match index removed a redundant 16-byte
Wyhash pass. Three interleaved CPU-0 comparisons measured 9.83-9.99 us/block
versus 10.98-11.19 us/block at the preceding bitmap commit (1.10-1.14x faster).
The index still stores both digests and verifies the original strings after a
hit; a forced combined-hash collision test covers key separation.
For large sections in which every field is an exact dynamic match, the encoder
now computes the final indexed representation length and reserves output plus
reference capacity once before emission. Five CPU-0 samples measured
9.40-9.54 us/block (18 ns/field), versus 9.82-9.87 us/block in three
interleaved runs at the preceding prehashed-index commit (1.03-1.05x faster).
Mixed static, name-only, literal, and never-indexed sections retain the general
encoder; focused round-trip and second-allocation failure tests cover both
branches and the pre-prefix rollback boundary.
Dynamic lookup now checks the newest same-name entry before computing the value
digest or probing the exact index. When that entry is also an exact match, as in
both populated encode scenarios, the second hash and map lookup disappear; an
older exact value still takes precedence over a newer name-only match. Three
interleaved CPU-0 large-section comparisons measured 9.22-9.33 us/block versus
9.45-9.57 us/block at the preceding reservation commit (1.01-1.04x faster).
Two 1,000,000-iteration 32-field comparisons measured 711-715 ns/block versus
733-736 ns/block.

### QUIC prepared packet protection

The maintained short-packet executable obtains its monotonic clock from
zio-backed `std.Io` and reports `io backend: zio-std-io`. Numeric results in
this subsection predate that migration unless explicitly labeled otherwise and
remain historical Threaded evidence; the backend change itself is not a crypto
throughput claim.

Every AES connection keeps an AES header-protection key schedule and Vail's
pure-Zig AES-GCM context for each current send/receive key generation. The
context retains the expanded AES key and GHASH table, matching the
connection-owned packet/header key design in Quinn, quiche, and s2n-quic: key
setup is paid when the connection is created or its key phase changes rather
than once per packet. AES-128-GCM and AES-256-GCM use the prepared path;
ChaCha20 and SM4 retain the allocation-free one-shot Zig path.

The short-packet benchmark reports value-key and prepared-key seal/open paths
separately. The prepared implementation is self-contained Zig and requires no
external crypto library. Run:

```sh
taskset -c 0 zig build bench-quic-short-packet -Doptimize=ReleaseFast
```

Five historical CPU-0 runs on 2026-09-12 used the former
BoringSSL-compatible backend built by the local tquic checkout. Medians are
reported below.
Every operation includes short-header construction/removal and header
protection, so these figures measure the complete protected short-packet
primitive rather than AEAD alone.

| 85-byte short packet | Value-key median | Prepared-key median | Throughput gain |
| --- | ---: | ---: | ---: |
| AES-128-GCM seal | 545 ns | 206 ns | 2.64x |
| AES-128-GCM open | 544 ns | 251 ns | 2.17x |
| AES-256-GCM seal | 558 ns | 225 ns | 2.48x |
| AES-256-GCM open | 564 ns | 272 ns | 2.07x |

The same benchmark showed no material prepared-wrapper change for ChaCha20
(0.99-1.00x). Suite-wide equivalence tests cover seal, in-place seal, phase
mismatch preservation, open, and key replacement. A connection-level test
proves that AES connections select prepared send/receive keys and continue
exchanging STREAM data across a key update, while ChaCha20 and SM4 remain on
their existing paths.

On 2026-09-18, seven CPU-0 runs of the prior pure-Zig backend measured
AES-128 prepared seal at 244-250 ns versus 292-381 ns for the
value-key path (1.19-1.54x), and prepared open at 302-303 ns versus 328-332 ns
(1.08-1.09x). AES-256 prepared seal measured 269-271 ns versus 324-346 ns
(1.19-1.28x), and prepared open measured 380 ns versus 395 ns (1.03-1.04x).
That earlier prepared path called the same one-shot AEAD primitive and cached
only the AES header schedule; the ChaCha control remained 0.99-1.02x. Each AES
connection consequently owns two 432-byte prepared-key objects in one
allocation. ChaCha20 and SM4 connections retain no prepared-key allocation.

Prepared header-protection state now stores one tagged AES-128 or AES-256 key
schedule instead of two mutually exclusive optional schedules. This follows
the suite-specific header-key ownership in quiche/tquic and reduces
`PreparedPacketProtectionKeys` from 1,792 to 1,600 bytes (10.7%). A live AES
QUIC connection owns one send and one receive object, so its fixed prepared-key
footprint falls by 384 bytes without changing allocation count. Tests compare
all four traffic suites against the value-key path and exercise replacement
across AES-128, AES-256, and ChaCha20 tags. Seven CPU-0, fixed-binary,
order-alternated 100,000-operation pairs kept AES-128 prepared seal/open at
205-225/251-257 ns and AES-256 at 224-242/269-273 ns on the candidate; the
corresponding baseline ranges were 205-210/251-256 and
225-228/271-275 ns. These overlap and are treated as throughput-neutral. Seven
matching real-handshake, four-stream, 16-MiB-upload pairs completed every
three-iteration arm with 50,331,648 bytes and status total 2,400. Median
throughput moved from 162.15 to 162.32 MiB/s with 4/7 candidate wins, also
noise-level; the retained benefit is the deterministic prepared-key memory
reduction.

Connection ownership now groups prepared AES send and receive keys into one
stable pair allocation. Direct preconfigured connections with AES in only one
direction retain a single-object allocation, while ChaCha20/SM4 pairs allocate
none; this keeps the public mixed-suite configuration compatible. A
linked-backend 100-handshake allocator run fell
from 7,901 to 7,701 allocations, exactly two fewer allocations per benchmark
round because each round constructs a client and server connection. Requested
bytes were effectively unchanged (7,693,101 to 7,692,942) and peak live bytes
remained 58,579. Seven CPU-0 fixed-binary, alternating-order 100-handshake
pairs were timing-neutral: median connection rate moved from 1,036.0 to
1,033.7/s (-0.2%) and median P50 from 901,089 to 904,134 ns (+0.3%). The
ownership policy and allocation-count regression live in
`src/quic/one_rtt/prepared_keys.zig`.
With Vail `b6dd7b6` additionally replacing its two mutually exclusive AES-GCM
context slots with one suite-selected context, each netz prepared object is now
1,008 bytes and the pair allocation is 2,016 bytes. The same 100-handshake
current-stack run retained 7,701 allocations while total requested bytes fell
to 7,456,115 and peak live bytes to 56,211. Vail's independent seven-pair
traffic-crypto benchmark was timing-neutral, so this follow-up is also treated
as an ownership/memory improvement rather than a throughput claim. The
connection set also caches direct send/receive pointers next to its cold
ownership tag, avoiding a union switch in every packet operation. Against a
fixed binary with the same Vail state and pair allocation but tagged accessors,
seven CPU-0 order-alternated H3 pairs moved the four-stream 16-MiB upload
median from 160.63 to 163.40 MiB/s (+1.7%, 6/7 wins). Every three-iteration arm
verified 50,331,648 bytes and status total 2,400; this is a small
workload-specific result, not a general throughput claim.

Vail `854a041` replaced the optional external backend with a reusable pure-Zig
AES-GCM context that caches both the expanded AES key and GHASH table. Its
x86_64 VAES/VPCLMUL path is faster than the former AWS-LC backend; this ARM64
host uses the portable implementation. The netz prepared wrapper is now 992
bytes (1,984 bytes for the connection's send/receive pair). One diagnostic
100,000-operation run measured AES-128 prepared seal/open at 204/283 ns versus
337/332 ns for the value-key path, and AES-256 at 220/334 ns versus 326/371 ns.
Nine CPU-0 fixed-binary pairs compared
the prior Vail binary
`1a0a233084afcfcd1b7c2a84d559bf1af7edc196edb523996cb14666e1efec70`
with the new pure-Zig binary
`6d4f9cc5b90f43c80c52e3872efcb1cae01424a6f2c9f6e08a96bae86d6e8738`.
The 1,149-byte DATAGRAM receive median fell from 2,771 to 2,754 ns/packet
(0.61%, 8/9 wins). A separately scheduled five-sample
1024-byte/window-16 Quinn matrix measured netz at 178.769 us against a fixed
Quinn server and 216.974 us against a fixed netz server, versus Quinn-client
medians of 163.612 and 180.510 us. This ARM64 result is directional evidence;
the larger x86 acceleration and the remaining event-loop/payload-delivery gap
need their own fixed-peer runs.

Vail `2f2eb77` subsequently consumes up to sixteen GHASH blocks per reduction
on ARM64 with cached powers and independent PMULL products. A noinline runtime loop
keeps the complete receive-benchmark binary increase to 23,296 bytes; the
rejected fully unrolled prototype added about 301 KiB. Seven fixed-binary
short-packet pairs reduced prepared AES-128 seal/open medians from 206/283 to
135/217 ns (34.5%/23.3%) and AES-256 from 220/334 to 166/270 ns
(24.5%/19.2%), with every pair faster. Nine fixed-binary 1,149-byte DATAGRAM
receive pairs compared
`6d4f9cc5b90f43c80c52e3872efcb1cae01424a6f2c9f6e08a96bae86d6e8738`
with
`efa4d5674787773e7933fc1f0f9938b44e9920b5951c3d0f8fe410b70c9e9c87`;
the median fell from 2,752 to 2,606 ns/packet (5.31%, 9/9 wins). A fresh Quinn
matrix measured netz p50 at 173.594/207.917 us against fixed Quinn/netz
servers, versus Quinn-client medians of 157.621/173.751 us. Because that matrix
was separately scheduled, it remains directional evidence rather than the
causal claim.

### QUIC 1-RTT send

```text
QUIC 1-RTT send benchmark
  iterations: 1000, packets/batch: 32, payload bytes/packet: 1024
  stateful batch GSO available after run: true
  stateful sequential: 109760 ns/batch, 3430 ns/packet
  stateful batched:    98012 ns/batch, 3062 ns/packet
  stateful batch relative packet throughput: 1.11x
  total packets/path: 32000
```

A CPU-0-pinned 2026-11-19 zio-era smoke of the current build recorded
118,884 ns/batch sequential and 111,105 ns/batch batched (3,715/3,472 ns/packet,
1.07x) for 32 x 1-KiB packets. The host also ran unrelated builds, so this is a
backend/shape refresh rather than a regression or speedup claim.

The 1-RTT send path now centralizes frame classification in
`one_rtt/frame_traits.zig`. Single-packet validation hands its collected traits
to packet preparation instead of rescanning for ACK-eliciting, in-flight,
retransmission, HANDSHAKE_DONE and largest-ACK metadata; batch preflight caches
the same result and no longer rescans every packet for automatic ECN. Focused
tests pin ACK/PADDING/close, unreliable DATAGRAM, path validation, STREAM byte
totals and ACK watermark semantics. Three CPU-0 fixed-binary runs measured
stateful sequential sends at 106.649-108.672 us/batch and batched sends at
95.348-97.660 us/batch, preserving a 1.11x batch throughput advantage.
Recovery payload emission now also consumes the classification result from
that validation pass. When every encoded payload byte is retransmittable it
writes all frames directly, while mixed STREAM/DATAGRAM and ACK payloads keep
the selective path. The classifier itself now handles each frame tag with one
switch instead of three. In the final 50,000-iteration CPU-0 profile of the
four-STREAM-descriptor shape, the former standalone
`frame_traits.classify` hotspot (9.26% before) disappeared from the reported
hot list; the remaining aggregate `Traits.observe` entry accounted for 2.09%
of sampled user cycles. A label-parsed rerun used the exact cached pre-change
binary and a freshly built final binary, pinned both to CPU 0, performed 1,000
warmups per invocation, and alternated execution order across five
50,000-iteration pairs. It moved the sequential median from 114.635 to 111.895
us/batch (2.4% lower, final faster in 5/5 pairs) and the batch median from
101.473 to 98.525 us/batch (2.9% lower, final faster in 4/5 pairs). One baseline
batch sample was a 116.687-us high tail and one final batch pair was 0.36%
slower, so the medians are retained without an all-pairs claim. Direct batch
and single-packet mixed-DATAGRAM tests verify that unreliable bytes are still
absent from recovery. The benchmark accepts `--warmup=N` and `--iterations=N`
so longer profiles do not require a source edit. It now also accepts
`--scenario=datagram` and `--datagram-payload-bytes=1..1024` to isolate the
public DATAGRAM batch sender. That mode compares 32 sequential logical payload
sends against one packed batch and reports both logical payloads and actual
QUIC packet numbers. On the published `8acb1db8` baseline, a CPU-0 256-byte,
1,000-iteration run measured 102.619 us/batch (3,206 ns/payload, 32,000
packets) sequentially and 20.950 us/batch (654 ns/payload, 8,000 packets)
packed, a 4.89x relative payload-rate gain. This is a sender-only local
microbenchmark and is the fixed baseline for the next pure-DATAGRAM
bookkeeping optimization; it is not a cross-stack claim.

The follow-up specializes the shared batch state machine at compile time for
the public pure-DATAGRAM path. It keeps the same congestion, pacing, ECN,
anti-amplification, sent-packet, key-update, nonce, and socket-prefix commit
logic, while skipping constant frame-trait classification, STREAM credit
planning, empty recovery-payload tracking, and their rollback scans. The
generic STREAM/mixed-frame batch path is unchanged. Fixed ReleaseFast binaries
(`d2014ce1750b4668bc633fea8204cc18ea2e639df0cf47668b99315ab1e60026`
baseline, `8f052801cbeb7fc319556c3dd866ea0a3a34de65aefee089bd25d91e444ac1b1`
candidate) were pinned to CPU 0 and alternated by pair:

| DATAGRAM payload | Pairs | Baseline packed median | Specialized median | Reduction | Pair wins |
|---:|---:|---:|---:|---:|---:|
| 32 B | 5 | 18.733 us/batch | 5.651 us/batch | 69.8% | 5/5 |
| 256 B | 7 | 20.907 us/batch | 16.766 us/batch | 19.8% | 7/7 |
| 1024 B | 5 | 60.396 us/batch | 55.737 us/batch | 7.7% | 5/5 |

Each invocation used 100 warmups and 20,000 measured 32-payload batches. A
five-pair STREAM-batch control was timing-neutral amid a host-speed shift
(165.471 versus 166.287 us/batch medians with overlapping samples), as expected
because it still instantiates the generic path. This isolates the improvement
to pure DATAGRAM bookkeeping; it is not an end-to-end result.

The public batch preflight now computes the negotiated/path-limited maximum
DATAGRAM payload once per non-empty input slice rather than once per logical
payload. Every payload length is still checked before packet grouping, and the
existing complete packet-plan pass still rejects MTU or packet-number failure
before the first socket submission. An empty batch remains a successful no-op
even when DATAGRAM was not negotiated. Nine CPU-0 fixed-binary pairs used 500
warmups and 10,000 measured 32-payload batches per arm. Baseline/candidate
binaries were
`200c9723c02eba3cc0cdeedde9367655ea998a0d0ba8c259e19f76686c435700`
and `0d18e397a315ee23befc2423af5507f1eeb453aeae3631ed8906e2ba208523f7`:

| Payload | Baseline median | Candidate median | Time reduction | Pair wins |
|---:|---:|---:|---:|---:|
| 32 B | 177 ns/payload | 138 ns/payload | 22.0% | 9/9 |
| 256 B | 514 ns/payload | 472 ns/payload | 8.2% | 9/9 |
| 1024 B | 1,596 ns/payload | 1,549 ns/payload | 2.9% | 9/9 |

The 1024-byte capture hash is
`da8dcef8492b6308c367ece59ac01eca087c38a729cc0488a535c15438200717`.
The separate 32/256-byte capture uses the same binary pair and hashes to
`6584564b2c5f33d28b69911ce1ef7e8f6dcfffc2e8b3eb85de7282d4f3774876`.
A repeated five-sample Quinn matrix moved the netz-client/fixed-Quinn-server
p50 from 183.233 to 181.751 us across separately scheduled runs; Quinn's own
median also moved, so that result is directional compatibility evidence rather
than the causal claim. Two broader experiments were rejected: retaining the
first packet plan regressed the isolated median about 2.6%, while replacing
the payload-limit search with a fixed-point solver was timing-neutral.

The next batch-validation step observes that one QUIC packet per logical
payload is a conservative upper bound. After validating every payload length,
a post-handshake batch whose worst-case last packet number is legal and keeps
the first packet's encoded width can return without materializing a duplicate
packet plan. Width transitions, packet-number exhaustion, HANDSHAKE_DONE, and
pending ACK_FREQUENCY still use the original exact planner. A regression fixes
both sides of that split: two maximum-size packets spanning the 126/127
one-byte/two-byte packet-number boundary fail before emission, while an empty
batch remains a successful no-op even when DATAGRAM was not negotiated.

Nine CPU-0 fixed-binary pairs compared the `f9cb3079` baseline
(`0d18e397a315ee23befc2423af5507f1eeb453aeae3631ed8906e2ba208523f7`)
with candidate
`58420be3b97038e73232d3decb28fcebb5c055371085d3319c4e06da4d403bff`.
Each arm used 500 warmups and 10,000 measured 32-payload batches:

| Payload | Baseline median | Candidate median | Time reduction | Pair wins |
|---:|---:|---:|---:|---:|
| 32 B | 138 ns/payload | 129 ns/payload | 6.5% | 9/9 |
| 256 B | 471 ns/payload | 462 ns/payload | 1.9% | 9/9 |
| 1024 B | 1,577 ns/payload | 1,570 ns/payload | 0.4% | 6/9 |

The complete capture SHA-256 is
`ddf91cbc6021d61f61c9803a8b792798e7be9220b26450d353bff455c2c24354`.
The 1024-byte result is deliberately treated as neutral. Five-sample external
Quinn matrices with the final client/server binaries
`e6912daadffb9c47893b06c73ae4888849ec6437b06a8d52fcc48a9fe35e3e55` /
`271577bbb862cf3a809f7dca3f4d544dfa03164067baa0767b526c79f63c861e`
measured 32-byte netz p50 at 53.352 us against a fixed Quinn server and
49.157 us against a fixed netz server, respectively 1.195x and 1.060x the
Quinn client rate. The 1024-byte p50 remained within the preceding netz range
at 182.242/219.381 us; its cross-stack gap therefore remains open. The 32-byte
and 1024-byte matrix-log hashes are
`b66c5f902850708e8e36444ac81a8c984811662b945390de399c4f65c0a90dc4`
and `6682ccbe832c55713f521b16c9d7014c2c5817fe06c7336a9550eedf169addda`.

### Raw QUIC DATAGRAM latency against Quinn

The native Quinn RFC 9221 fixture now also supports a strict raw DATAGRAM
ping-pong benchmark. It runs four role pairs so each client implementation is
measured once against a fixed Quinn server and once against a fixed netz
server. Every run uses a fresh certificate-verified QUIC v1 connection, a
1200-byte steady-state MTU, disabled PMTU discovery, a 32-byte payload, one
outstanding DATAGRAM, 200 warmups, and 5,000 measured post-handshake RTTs.
The runner pins client/server to CPUs 0/1, hashes all three ReleaseFast
binaries and the Quinn lockfile, requires five samples, and alternates A/B then
B/A order. A strict Python verifier reconstructs all 5,200 payloads and their
checksum, checks p50/p90/p99/p99.9 ordering, config/result/server-completion
records, negotiated limits, control-stream FINs, and application close 59.

The 2026-09-16 fixed-binary run reported:

| Fixed server | Client | p50 median (us) | p50 range (us) | p99 median (us) | p99.9 median (us) |
|---|---|---:|---:|---:|---:|
| Quinn | netz | 45.296 | 44.769-45.750 | 61.963 | 70.537 |
| Quinn | Quinn | 50.546 | 49.399-53.529 | 66.879 | 75.649 |
| netz | netz | 47.315 | 46.649-48.194 | 62.426 | 85.825 |
| netz | Quinn | 44.288 | 42.935-44.695 | 65.602 | 73.112 |

Against the fixed Quinn server, netz's median p50 was 11.6% lower (1.116x).
Against the fixed netz server, netz's median p50 was 6.4% higher (0.936x).
The direction changes with the fixed peer, so this is explicitly
`same-application-shape` evidence and does not support a universal latency or
throughput claim. The command is
`zig build bench-quic-datagram-quinn -Doptimize=ReleaseFast -- --samples=5
--warmup=200 --iterations=5000`.

The same harness now accepts `--window=1..64`. A window sends all
sequence-tagged payloads before receiving its complete echo set, accepts
arrival reordering, and rejects duplicates, omissions, or out-of-window
sequences. The verifier additionally binds warmup, iterations, payload size,
window, total logical DATAGRAMs, bytes, checksum, control FIN, and close into
the result schema. For windowed runs, netz uses automatic GSO when available
and caller-buffer `recvmmsg`; Quinn retains its runtime-selected batching.
Packetization remains implementation-specific, so these results are
`same-application-shape`, not equal-wire.

A 2026-09-17 fixed-binary CPU-0/client, CPU-1/server matrix used five ABBA
samples, 50 warmups, 500 measured windows, and window 16. The same netz
client/server and Quinn binary hashes were retained across all three payload
sizes. Netz greedily packs multiple DATAGRAM frames into one QUIC packet up to
the 1200-byte path and configured frame-count bounds, matching the strategy in
the audited Quinn and quiche implementations; the logical payload prefix
remains exact if a socket accepts only a packet prefix.

| Payload | Fixed server | netz p50 median/range (us) | Quinn p50 median/range (us) | netz/Quinn speed |
|---:|---|---:|---:|---:|
| 32 B | Quinn | 54.148 / 53.713–55.241 | 50.927 / 47.685–52.778 | 0.941x |
| 32 B | netz | 60.954 / 59.676–61.363 | 53.639 / 53.390–55.834 | 0.880x |
| 256 B | Quinn | 97.296 / 94.371–97.861 | 83.890 / 78.890–85.103 | 0.862x |
| 256 B | netz | 113.417 / 112.241–114.307 | 100.371 / 96.732–108.084 | 0.885x |
| 1024 B | Quinn | 195.196 / 194.020–196.622 | 156.511 / 142.825–160.640 | 0.802x |
| 1024 B | netz | 256.197 / 255.669–260.493 | 202.741 / 200.918–208.289 | 0.791x |

The 32-byte result is near parity, with Quinn ahead by 6.3% against its own
server and 13.6% against the fixed netz server. Larger payloads still favor
Quinn by roughly 12–21%, leaving a
concrete packet-protection/event-loop optimization target rather than a broad
performance-win claim. Tests independently prove three small payloads share
one packet, five 500-byte payloads map to three packets, a one-packet partial
socket send commits exactly two logical payloads, and packet-number exhaustion
is rejected before emission. Earlier diagnostic runs without packing are not
treated as a baseline because they were not interleaved against the final
binary.
The fixed final hashes were
`6b5f21da81827e8ad08f36163e5558cf93cf6e37585f3e22af0f5605ac00f5cc`
for the netz client,
`d4b94844aa581b82965acfbd7b2d626f5a3c5f84819bf0d47976e9e7c3d2c1e0`
for the netz server, and
`e3aac9cece02e028b5909e869c2fd86ed249174c21e2b79907460f0a70f45215`
for the Quinn fixture.

After the pure-DATAGRAM specialization, the final same-shape window matrix used
netz client/server hashes
`64ba9891a367464057364c2feae3e3ca476018c1b748594074d7d5ab9be2c9b6` /
`52081c6bde32f192f509a19886f0b89cbf2f236b7827e6b2952094e96accf716`
and the same Quinn binary. Its p50 medians were:

| Payload | Fixed server | netz p50 (us) | Quinn p50 (us) | netz/Quinn speed |
|---:|---|---:|---:|---:|
| 32 B | Quinn | 56.556 | 62.472 | 1.105x |
| 32 B | netz | 50.806 | 56.742 | 1.117x |
| 256 B | Quinn | 88.324 | 85.268 | 0.965x |
| 256 B | netz | 95.714 | 91.677 | 0.958x |
| 1024 B | Quinn | 185.723 | 164.204 | 0.884x |
| 1024 B | netz | 229.825 | 188.788 | 0.821x |

Thus the 32-byte window workload now favors netz in both fixed-server
comparisons. The 256-byte cases are within 5%; the 1024-byte cases still favor
Quinn, leaving large-payload protection and event-loop work as the next target.
These remain implementation-packetized, same-application-shape comparisons.

The 2026-10-13 connection-level GRO follow-up removed a functional blocker in
mixed STREAM/DATAGRAM sessions. Low-level caller-buffer endpoint receives still
reject GRO because they cannot own queued suffixes, while `Connection` now uses
the owning endpoint receive path on GRO sockets, copies only the current segment
into its existing scratch, and leaves every later segment in the endpoint FIFO.
A regression sends one equal-sized STREAM packet followed by two DATAGRAM
packets in one GSO super-packet, verifies that the blocking STREAM API consumes
the first segment, then drains both DATAGRAM suffixes in order; the untimed
state-only path is covered by a second two-segment batch.

The matching windowed benchmark now enables GRO on netz endpoints only when
`--window` exceeds one. A post-rebase three-sample CPU-0/client, CPU-1/server
run used 50 warmups, 500 measured windows, 1,024-byte payloads, and window 16.
Its fixed binary hashes were
`610f91708434a565756f3673df96ddb48b467a92423fb8d36a94d742cb156120`
for the netz client,
`17307fa8f68cfc7492f4140ace69e7085533f30774ca6deafbeec722356688c5`
for the netz server, and
`e7b1708c811ab0af02a0e426b61ad98f7e65ca8efc12ea89c6b4fdf312f18875`
for Quinn revision `d9c8c4c695fc64292d9b117844ea6924ca0d0815`:

| Fixed server | netz p50/p99 (us) | Quinn p50/p99 (us) | netz/Quinn p50 speed |
|---|---:|---:|---:|
| Quinn | 125.436 / 138.149 | 137.010 / 169.280 | 1.092x |
| netz | 122.973 / 132.630 | 122.390 / 147.131 | 0.995x |

This closes the previously recorded 1-KiB/window-16 p50 gap for this bounded
same-application-shape run: netz is faster against the fixed Quinn server and
within 0.5% against the fixed netz server. Three samples are sufficient for the
compatibility/performance gate but not a universal latency claim; longer and
lossy window distributions remain separate work.

The bounded QUIC DATAGRAM receive queue now lives in
`one_rtt/datagram_queue.zig`. Its first successful admission reserves exactly
the configured ring bound, so later enqueue/overwrite operations allocate
nothing and retain no geometric capacity beyond policy. Tests exercise
wrap-around removal by packet number, stable survivor order, capacity-one
replacement, caller ownership after OOM, and newest-data retention. The public
queue/drop counters and packet-routing API are unchanged.
The queue now additionally retains a capacity-bounded pool of exact-size
payload allocations after application pops. Repeated fixed-size DATAGRAM
bursts therefore allocate the ring and first full window once, then reuse that
storage; different sizes replace cached entries safely. Focused tests prove a
full warmed burst succeeds under a fail-first allocator, preserve
consume-on-small-buffer behavior and partial batch progress, and retain
drop-oldest accounting. The earlier single-slot step's fixed-binary
CPU-0/client, CPU-1/Quinn-server A/B used
five 200-warmup/5,000-RTT pairs with alternating order. Median p50 moved only
44.666 to 44.416 us (0.6%, 3/5 wins) and p99 61.047 to 60.547 us (0.8%). The
reverse fixed-Quinn-client/netz-server comparison moved p50 44.334 to 44.231
us (0.2%, 3/5 wins), with one noisy candidate p99 tail. These timing results
are performance-neutral; the supported improvement is the deterministic
steady-state payload-allocation removal, not a latency claim.
When an already-full queue receives another payload of the same size, it now
copies directly into the oldest slot and rotates that slot to the logical tail.
This removes the former extra recycle allocation, keeping equal-size saturated
storage at exactly the configured queue capacity. A fail-first allocator test
locks down the allocation-free overwrite and FIFO order. Nine CPU-0 fixed-
binary pairs compared
`94f30fabbea57d0aa5b1a5f9a91e4eedf677be353b2a9cf6b7aab61fdeceb4c6`
with
`1a0a233084afcfcd1b7c2a84d559bf1af7edc196edb523996cb14666e1efec70`;
each arm used 500 warmups and 10,000 measured 54-packet batches with an
approximately 1,149-byte DATAGRAM payload. Service-path median cost fell from
2,811 to 2,774 ns/packet (1.32%), with the candidate faster in all nine pairs.
The connection additionally exposes blocking, relative-timeout, and
absolute-deadline caller-buffer DATAGRAM receive APIs, including up-to-64-item
batch forms with exact partial-progress counts. Existing queued data keeps FIFO
priority; otherwise fitting DATAGRAMs are copied directly from authenticated
frames into caller storage. Non-GRO endpoints drain ready UDP messages through
one backend receive and one cumulative ACK decision; GRO endpoints consume the
existing shared-segment view. Tests cover single and multi-frame delivery,
GRO segments, short-buffer consumption/error, zero timeout, empty/oversized
batches, and disabled negotiation. The raw Quinn matrix now uses this path.
An order-balanced fixed-binary A/B used five 200-warmup/5,000-RTT pairs per
direction. Against the fixed Quinn server, the client p50 median moved from
44.250 to 43.769 us (1.1% lower, candidate faster in 4/5 pairs). Against the
fixed Quinn client, the netz server p50 median moved from 44.009 to 43.205 us
(1.8% lower, candidate faster in 4/5 pairs). The p99 samples were noisy and
included a candidate high tail, so this is a small workload-specific p50
improvement rather than a tail-latency or general QUIC performance claim.

Latency-sensitive consumers can instead use the blocking, relative-timeout,
or absolute-deadline `visitDatagramBatchIntoServicingTimers*` variants. These
methods receive into caller-owned raw storage, apply and acknowledge the
complete authenticated packet batch, and synchronously visit each DATAGRAM
payload without copying it into either the bounded queue or a second
application buffer. Payload views expire when their callback returns, recursive
receive is rejected with `ConcurrencyUnavailable`, and pre-existing queued
payloads remain untouched. A real-UDP test covers packed ordered delivery, zero
queue growth, callback-error cleanup, recursive-receive rejection, and an
allocation-free warmed receive under a fail-first allocator. One frozen
ReleaseFast binary
(`f0962826104e29c03796e0672c861c2c55e68499242a60984937a8431f3ce375`)
alternated copy and borrowed modes over nine CPU-0 pairs, each with 500 warmups
and 10,000 measured 54-packet batches. The median fell from 2,694 to 2,626
ns/packet (2.52%), with borrowed delivery faster in all nine pairs.
A separate nine-pair fixed-binary control compared the pre-API binary
`efa4d5674787773e7933fc1f0f9938b44e9920b5951c3d0f8fe410b70c9e9c87`
with the same final binary in the existing queue-backed service mode. Medians
were 2,608 and 2,607 ns/packet with 4/9 candidate wins, which is treated as
neutral and rules out a material regression for existing users.
Single DATAGRAM sends now also append a pending delayed ACK when both frames
fit the path packet. This matches the unified packet builders in Quinn, quiche,
and s2n-quic and avoids a separate ACK packet in request/response workloads. A
full-size DATAGRAM that cannot fit the ACK falls back to the original send and
leaves the ACK scheduled; validation, allocation, anti-amplification,
congestion, and pacing failures before socket submission have the same safe
fallback. Real-UDP tests verify the combined frame order, exact ACK range, one
socket-visible datagram, and the full-size fallback.

The fixed baseline binaries for this step were SHA-256
`2ba8edf58157f4fa301c40f695cdf275feca5ab72e787f5ab7f1457687db69fa`
(client) and
`af97a63417c75c5f44d225a5f32f7d50cb9c65e1254578fe80fab94d63dbf017`
(server); the final binaries were
`024bd317fe37fd8ae9c92010a3eaf6cf24101cbe778ab7345e2af170e8e73883`
and `244bfb698a7b5ef5661bdb149aed4a2746210a69ff8fe77017e9adb2ecb9398a`.
Five order-alternated 200-warmup/5,000-RTT pairs on CPUs 0/1 moved the netz
client p50 against a fixed Quinn server from 43.556 to 41.787 us (4.1% lower,
5/5 wins), and the netz server p50 against a fixed Quinn client from 43.954 to
42.649 us (3.0% lower, 5/5 wins). Median p99 moved from 60.555 to 57.278 us
and 63.435 to 61.454 us respectively, with 5/5 wins in both directions; the
ranges overlap, so these remain workload-specific latency results rather than
a broad tail-latency claim.
The resulting fixed-binary four-role matrix measured netz at 42.019 us versus
Quinn at 52.166 us p50 with the Quinn server (1.241x), and netz at 35.972 us
versus Quinn at 43.204 us with the netz server (1.201x). The corresponding p99
medians were 57.223 versus 67.834 us and 44.444 versus 60.862 us. Netz leads
both fixed-peer comparisons in this capture, but the benchmark still compares
the same application shape rather than identical executor, syscall, or wire
behavior, so the result remains scoped to this raw one-outstanding DATAGRAM
workload.
Stateless `one_rtt.sendFramesInto` now accepts one caller-owned final packet
buffer, encodes frames directly into its plaintext region, seals AEAD in place,
and submits it without heap allocation. Its exact sizing helper validates every
frame before output mutation. The compatibility `sendFrames` wrapper now uses
one exact packet allocation instead of separate plaintext and protected-packet
allocations. A real UDP test proves caller-buffer transmission under a
fail-first endpoint allocator, another proves the wrapper succeeds when only
one allocation is permitted, and short-buffer rejection occurs before I/O.

### QUIC 1-RTT receive

On 2026-09-05 the current-key receive paths were changed to compute the
short-header protection mask once, using the negotiated cipher suite, and then
reuse that preview for packet-number unmasking and AEAD open. A Key Phase
mismatch leaves the complete datagram unchanged for the existing next/previous
generation fallback. Five post-change CPU-0 samples measured 1.900-1.908
us/packet for the allocating path (1.907 median), 1.403-1.417 us/packet for
in-place service (1.409 median), and 1.396-1.404 us/packet for the borrowed
visitor (1.400 median). The three immediately preceding samples had medians of
1.958, 1.465, and 1.466 us/packet respectively: 2.6%, 3.8%, and 4.5% median
reductions. GRO's median moved from 1.675 to 1.657 us/packet (1.1%). AES-128,
AES-256, ChaCha20, and SM4 tests verify both successful open and byte-for-byte
preservation on phase mismatch.

The receive benchmark now accepts `--mode=all|gro|plain|service|visitor`,
`--frame=padding|stream|stream_gap|datagram`, `--warmup=N`, and
`--iterations=N`. The STREAM shape fills each 1,152-byte plaintext with one
ordered stream-zero frame, drains it through `pollStreamId`, and verifies the
exact byte total, so it includes the receive preflight and stream-buffer path
that padding-only packets do not. The DATAGRAM shape likewise fills the
plaintext with exactly one length-bearing frame and enables the receiver's
local RFC 9221 limit, isolating the common one-frame receive preflight.

For the common one-STREAM packet, receive preflight now builds only one
`RecvState.Preflight` and a one-frame descriptor store. It retains the same
stream-ID, final-size, overlap/conflict, receive-window, stream-credit, and
connection-credit validation before the packet-number recorder or connection
state mutates, while skipping unrelated multi-stream, connection-ID, and path
validation shadows. Seven CPU-0, order-alternated 5,000-iteration A/B pairs
measured the following integer ns/packet medians:

| STREAM receive path | Before | After | Median reduction | Pair outcomes |
| --- | ---: | ---: | ---: | ---: |
| borrowed visitor | 1328 | 1308 | 1.5% | 7/7 faster |
| in-place service | 1336 | 1298 | 2.8% | 7/7 faster |

Five equivalent padding visitor pairs moved from a 1397 ns/packet baseline
median to 1395 ns/packet, a noise-level 0.1% difference. An all-mode STREAM run
after this first-stage preflight change measured GRO 1347, allocating plain
1532, in-place service 1320, and borrowed visitor 1322 ns/packet over 270,000
packets per path. These are internal same-host regression measurements, not a
cross-library throughput comparison.

The common one-DATAGRAM packet now validates its negotiated frame-size limit
directly before packet mutation instead of constructing unused STREAM,
connection-ID, and path-validation shadows. Disabled negotiation, both wire
types, frame-size failure diagnostics, and whole-packet no-side-effect behavior
remain covered by the existing DATAGRAM receive tests. On 2026-10-03, fixed
ReleaseFast binaries
(`660ec6badcf1d8b3cec444c78adbca2f3dfbd391fd7acd5ad500a7c1335392b9`
baseline and
`94f30fabbea57d0aa5b1a5f9a91e4eedf677be353b2a9cf6b7aab61fdeceb4c6`
candidate) were pinned to CPU 0 and alternated in nine pairs. Every invocation
used 500 warmups and 10,000 measured batches of 54 packets. The service-path
median fell from 2,849 to 2,812 ns/packet, a 1.30% reduction, with the
candidate faster in 9/9 pairs. The latest five-sample 1024-byte/window-16 Quinn
matrix, after the Vail ARM64 PMULL update, measured netz p50 at 173.594 us
against a fixed Quinn server and 207.917 us against a fixed netz server, versus
Quinn-client medians of 157.621 and 173.751 us. That separately scheduled,
implementation-packetized matrix is
directional compatibility evidence; the fixed-binary receive result is the
causal performance evidence, and the large-payload cross-stack gap remains
open.

Vail `6f22077` subsequently groups four independent ARM64 PMULL products before
folding them into each GHASH accumulator. It retains the compact runtime-width
loop instead of instantiating every tail and adds only 776 bytes to this
benchmark's ELF `.text` (1,419,034 to 1,419,810 bytes). Nine clean,
order-alternated fixed-binary CPU-0 pairs, each with 500 warmups and 10,000
measured batches of 54 1,149-byte DATAGRAM packets, reduced the service-path
median from 2,689 to 2,646 ns/packet (1.60%, 9/9 wins). Vail's separate
1,200-byte prepared AES-128-GCM benchmark used seven CPU-0 pairs: seal fell
from 888 to 851 ns/op (4.17%, 6/7 wins), while combined open plus seal fell
from 1,780 to 1,700 ns/op (4.49%, 7/7 wins). Baseline/candidate netz binary
hashes were
`61ac4cd751b7bd8287ef21596919df76b3dc278097023e96914ffdb7c91cdb13`
and `270ea2e206430f27a53babf8ee6d590d720f5b1c2e5aacecb30ff000e0cdf687`.

A fresh five-sample, 50-warmup, 500-window Quinn matrix with the published
Vail `1219d45` measured 1,024-byte/window-16 p50 at 163.460 us for a netz
client against a fixed Quinn server and 189.514 us against a fixed netz server;
the corresponding Quinn-client medians were 139.089 and 166.441 us. The ratios
remain 0.851x and 0.878x, so this separately packetized cross-stack gap remains
open and is not used as causal evidence for the GHASH change.

Vail `bd821ba` then kept byte-reversed message blocks, cached powers, and
unreduced GHASH products in two-lane NEON values throughout the PMULL loop,
removing repeated scalar loads/reversals and general/SIMD-register transfers.
Seven clean CPU-0 fixed-binary pairs reduced the 1,200-byte AES-128-GCM seal
median from 851 to 763 ns/op (10.34%) and combined open plus seal from 1,699 to
1,527 ns/op (10.12%), with every pair faster. Nine corresponding netz
state-service pairs reduced 1,149-byte DATAGRAM receive from 2,641 to 2,565
ns/packet (2.88%, 9/9 wins), while seven caller-buffer delivery pairs moved
from 2,681 to 2,618 ns/packet (2.35%, 7/7 wins). The receive benchmark's ELF
`.text` increased by 252 bytes. Baseline/candidate netz hashes were
`270ea2e206430f27a53babf8ee6d590d720f5b1c2e5aacecb30ff000e0cdf687`
and `cce686dfd90cbb5a31d05b97650398f356814f536319abf6c600f49999348f45`;
Vail binary hashes were
`d4790dc20fb2824ec1ca0ef8bab4afda054f5d420db0593f78be5ba9b7e65428`
and `cc60e806dc7132be2630a834eef4cd9c68dcd490a23f10c3fa32bea857b201cc`.

The subsequent five-sample Quinn matrix with published Vail `cfe6e33` measured
netz-client p50 at 162.155/186.674 us against fixed Quinn/netz servers and
Quinn-client p50 at 136.932/164.674 us. The corresponding 0.844x/0.882x ratios
move in opposite directions from the preceding 0.851x/0.878x capture, so no
cross-process latency gain is attributed to the change; the fixed-binary
in-process reductions above remain the causal evidence.

The new connection-level suite test passes a FIN-terminated single STREAM and a
second STREAM after a key-phase update through `Connection.receivePacket` for
AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, ChaCha20-Poly1305/SHA-256, and
SM4-GCM/SM3. It exposed a stale SHA-2-only key-update helper in netz; key
updates now use Vail's suite-aware QUIC traffic-secret derivation, including
HKDF-SM3.

`RecvState` now stores received-byte presence as a packed, capacity-retaining
word bitmap rather than one `bool` byte per buffered payload byte. Ordered
append uses an implicit all-present dense prefix without allocating bitmap
words; the first gap materializes the packed representation. Overlap checks,
sparse gap filling, cloning, and non-word-aligned prefix compaction then use
that same explicit bit representation.
Dedicated model and stream tests cover set/clear ranges across 64-bit
boundaries, every prefix shift from 0 through 130 bits, sparse-tail gap filling,
conflicts, FIN, and sliding receive windows. This cuts bitmap storage to about
one eighth of the former representation.

Measured immediately against the retained single-STREAM-preflight binary, five
order-alternated visitor pairs reduced the median from 1324 to 1166 ns/packet
(11.9%, 5/5 faster). A separate seven-pair service run reduced the median from
1328 to 1172 ns/packet (11.7%, 7/7 faster). A 20,000-iteration final profile
measured 1185 ns/packet; `compiler_rt.memset` fell from about 11.5% in the
original STREAM profile to 0.22% of samples, `ReceivedBitmap.resize` accounted
for 0.58%, and AEAD GHASH/CTR again dominated. A long padding-only comparison,
which never enters stream storage, varied by about 0.9% between binaries and is
treated as code-layout/system noise rather than a claimed effect.
The final all-mode STREAM run measured GRO 1138, allocating plain 1387,
in-place service 1161, and borrowed visitor 1166 ns/packet over 270,000 packets
per path.

`--frame=stream_gap` keeps the same 54 packets, payload bytes, packet numbers,
and stream offsets but swaps every adjacent datagram before submission. Each
even-offset packet therefore fills a gap and must advance across the already
buffered odd packet. `ReceivedBitmap.firstUnsetFrom` now skips complete machine
words with `ctz(~word)` instead of testing every bit while retaining the same
packed representation, sparse-tail handling, and conflict checks. Seven
CPU-0, order-alternated 5,000-iteration fixed-binary pairs measured visitor
median 2258 -> 1956 ns/packet (13.4% lower, 7/7 faster) and in-place service
2266 -> 1968 ns/packet (13.2% lower, 7/7 faster). The ordinary ordered STREAM
shape stayed within noise at 1204 -> 1203 ns visitor and 1218 -> 1216 ns
service. A separate seven-pair real TLS/HTTP/3 four-stream upload run verified
80 MiB and status total 4000 per process: mean latency moved 84.746 -> 72.527
ms/iteration and median 82.492 -> 72.817 ms, with every candidate run faster.
This is an internal reordered/gap-fill optimization result, not a cross-stack
or equal-wire comparison.

After the later packed-word, range-precheck, and zio-batching changes, the
implicit dense-prefix representation was evaluated again against fixed
ReleaseFast binaries. Ordered STREAM bytes now advance the bitmap's logical
length without allocating or filling words; the first actual gap materializes
the old packed representation transactionally. Byte-buffer and bitmap
capacity are both reserved before either logical length changes, so allocation
failure preserves the complete dense prefix, byte count, and FIN state. The
implementation and bitmap model tests now live separately in
`src/quic/stream/received_bitmap.zig`, reducing `src/quic/stream.zig` by about
300 lines. This matches the sparse receive-range principle in Quinn, quiche,
and tquic while preserving netz's byte-exact overlap-conflict checks.

The receive benchmark baseline SHA-256 was
`67af2f79d95e1d1f9c88d95e0de7938374c97172887c8d1547c6d1097ca7f32a`
and the final candidate was
`a5874c09951a68de83de4857ce902f159e59450cd896c7be4f2240686c2efeac`.
Seven CPU-0, order-alternated, 5,000-iteration visitor pairs moved ordered
STREAM median from 3001 to 2942 ns/packet (2.0%, 7/7 wins). The reordered
`stream_gap` control moved from 3175 to 3194 ns/packet (-0.6%, 4/7 wins); its
overlapping range is treated as noise rather than a regression claim.

The corresponding real TLS/HTTP/3 four-stream upload used baseline SHA-256
`d97b6c90e6c69ba2289d255f41fb48ecba7ff6a4b104257d559aea738069573a`
and candidate SHA-256
`66413befc85a749a304ad331da41722a959f39b578122bbab09a5d1c80bba455`.
Seven CPU-0, order-alternated runs of three 16-MiB iterations moved median
throughput from 146.90 to 146.31 MiB/s (-0.4%, 3/7 wins), which is noise-level.
Seven matching allocator pairs had medians of 698 to 658 calls (5.7%) and 151
to 119 exact 136-byte allocations. The 16-MiB application body dominates byte
totals, so median cumulative allocation and peak changed only 0.041% and
0.005%.
The supported claim is therefore fewer ordered-stream allocations plus a small
isolated receive-path improvement, not higher end-to-end throughput.

HTTP/3 clients previously stored every outstanding request across parallel
stream-ID, index, and semantics arrays plus a hash index, and copied every
method string independently. The lifecycle now owns one stream-ID-keyed map.
Its value stores the response-relevant method classification and Extended
CONNECT bit; the standard GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH
methods are inline tags, while extension methods retain an owned exact string
so send retries cannot alias caller memory. The implementation and its
allocation/failure tests moved to
`src/http3/runtime/stream/lifecycle/client.zig`; server priority and GOAWAY
tracking remain in the parent lifecycle module. This follows Hyper/http's
typed standard-method representation while preserving netz's exact custom-
method retry checks and HEAD/traditional-CONNECT response semantics.

The fixed dense-prefix baseline SHA-256 for the real TLS/HTTP/3 upload was
`66413befc85a749a304ad331da41722a959f39b578122bbab09a5d1c80bba455`;
the final single-map lifecycle candidate was
`be0ee3d3328088c6aa727703dbb94f78767c12be7d05705aece34bf4917c21f2`.
Seven CPU-0, order-alternated runs of three 16-MiB/four-stream iterations moved
median throughput from 144.52 to 145.63 MiB/s (+0.8%, 6/7 wins) and median
latency from 110.752 to 109.647 ms/iteration (1.0% lower). Seven matching
allocator pairs moved the median from 658 to 652 calls; cumulative allocation
and peak were each 120 bytes lower in six of seven candidate runs. One candidate
allocator outlier exercised additional recovery-cache growth, so these results
support the simpler ownership model and removal of routine method copies, not a
broad HTTP/3 throughput claim.

The server side now uses the same single-source-of-truth layout: one
stream-ID-to-priority map replaces the active-request array plus its parallel
stream-ID-to-array-index map. The directly cached lowest active stream ID keeps
the common GOAWAY drain query O(1); only removing that exact lowest stream scans
the remaining map. The implementation and its unordered-insertion, priority,
drain, and allocation-failure tests moved to
`src/http3/runtime/stream/lifecycle/server.zig`. Against client-single-map
baseline SHA-256
`be0ee3d3328088c6aa727703dbb94f78767c12be7d05705aece34bf4917c21f2`,
the final server-single-map binary SHA-256 was
`ad4e9c8ec5e6f62f5737d70fb83a3b894a22686b19ffb13abd7f04bf589e5077`.
Seven CPU-0 order-alternated 16-MiB/four-stream upload pairs were throughput-
neutral: 148.86 versus 148.76 MiB/s medians (-0.07%, 3/7 candidate wins). Seven
allocator pairs moved the median from 652 to 651 calls and reduced cumulative
and peak bytes by 192. This is a structural simplification with a small
deterministic allocation reduction, not a throughput improvement claim.

A follow-up avoids treating every byte inside the allocated receive buffer as
an actual overlap. Before either transactional preflight or committed insert
performs byte-wise duplicate/conflict validation, the packed bitmap now checks
the intersection a machine word at a time. Filling an entirely absent gap can
therefore account the range directly while genuine partial/full retransmissions
retain exact byte comparison and conflict rejection. Five CPU-0, order-
alternated 5,000-iteration fixed-binary pairs measured visitor median
2734 -> 1970 ns/packet and in-place service median 2751 -> 1983 ns/packet
(27.9% lower for both, 5/5 faster). The ordinary ordered STREAM controls moved
1813 -> 1816 ns/packet for visitor and 1844 -> 1837 ns/packet for service,
within 0.5% in both cases. These absolute values reflect the host load during
this run and are used only for paired before/after evidence.

The receive benchmark now also exposes `--mode=gro_service`, which applies all
segments from one kernel UDP_GRO receive synchronously through connection-owned
storage instead of allocating an owning datagram and `ReceivedPacket` array.
Three order-varied CPU-0 runs over 162,000 STREAM packets per path measured the
owning GRO mode at 1142, 1155, and 1157 ns/packet and state-only GRO at 687,
688, and 696 ns/packet. The median fell from 1155 to 688 ns/packet, a 40.4%
latency reduction or about 1.68x packet throughput. A failing-allocator test
proves the second state-only batch needs no allocation after the receive/frame
scratch has been warmed.

```text
QUIC 1-RTT receive benchmark
  iterations: 1000, packets/batch: 54, payload bytes/packet: 1152
  GRO batch:    90727 ns/batch, 1680 ns/packet
  plain packet: 103063 ns/batch, 1908 ns/packet
  GRO relative packet throughput: 1.13x
  total packets/path: 54000
```

A CPU-0-pinned 2026-11-19 zio-era smoke of the same 54 x 1,152-byte PADDING
shape recorded GRO batch 60,678 ns/batch (1,123 ns/packet), plain 92,481
ns/batch (1,712 ns/packet), in-place service 65,628 ns/batch (1,215 ns/packet),
borrowed visitor 65,909 ns/batch (1,220 ns/packet), and state-only GRO 20,242
ns/batch (374 ns/packet). The host also ran unrelated builds, so this is a
backend/shape refresh rather than a regression or speedup claim.

Ordinary non-GRO event loops can now call `Connection.servicePacket` to apply
one datagram without returning owned decrypt/frame diagnostics. It uses the
same current-key in-place path and retained frame array as GRO service, with an
owning fallback only for key-phase transitions. Three ReleaseFast runs measured
1.50-1.64 us/packet versus 1.92-2.07 us/packet for owning `receivePacket`, a
1.17-1.38x packet-throughput improvement. The audited quicz short-packet open
path allocates plaintext and connection-id ownership per packet.

`Connection.visitPacket*` now exposes those transient frames synchronously, so
HTTP/3 can route control/QPACK/request/response frames without restoring owned
plaintext and frame-array lifetimes. The same-shape benchmark's borrowed
visitor was 1.49-2.38 us/packet in three ReleaseFast runs, within measurement
noise of state-only service at 1.53-2.36 us/packet and faster than the matching
owning path at 1.92-2.83 us/packet. Handshake HTTP/3 uses the visitor on its
ordinary non-GRO packet pump. HTTP/3 retains a lazy owning GRO suffix because
it deliberately routes only one coalesced packet per application turn; pure
connection-state consumers can instead use the timer-aware state-only batch
pump to decrypt and apply every segment in lazily grown, connection-owned
receive storage with one cumulative ACK decision. The raw endpoint exposes the
same borrowed batch shape for caller-provided 65,535-byte GRO storage, while
its owning batch API and HTTP/3 cursor retain their existing lifetimes.

### QUIC recovery ACK range application

The maintained ACK-range executable uses one zio-backed `std.Io` clock for all
allocation, caller-storage, stale-check, sent-validation, and recovery-cycle
arms and prints the backend identity. Older values below are historical
Threaded measurements and are not mixed with later zio runs.

`bench-quic-ack-ranges` now includes a complete recovery cycle that tracks 128
payload groups and retires them with two 64-range ACK frames. Recovery validates
the descending range chain before mutation, then matches directly from wire
ranges instead of allocating a second decoded-range array. The ReleaseFast
baseline is 8.9 us/cycle on this host. Failing-allocator and malformed-range
tests prove allocation-free application and transactional rejection.

The audited quicz frame decoder allocates `AckRange[range_count]` for every ACK.
Netz still owns ranges at its generic parser boundary, but its recovery queue no
longer performs another allocation/copy.

The receive transaction's earlier sent-packet validation-only pass now streams
wire ACK ranges and proves each range's exact sent coverage with binary
boundaries plus the compacted acknowledged prefix. It no longer materializes a
decoded-range array or visits every retained packet merely to reject an
optimistic ACK; the later apply pass still computes the unchanged ECN, path,
RTT, congestion, and newly-acknowledged summaries. A fixed-binary, CPU-0, nine-
pair order-alternated run reduced validation of one cumulative ACK over 4,096
sent packets from 3,123-3,671 ns/op (3,142 median) to 24-25 ns/op (25 median),
a 99.2% median reduction or 125.7x throughput improvement, with the candidate
faster in 9/9 pairs. The benchmark's following recovery phase initially moved
about 4% because the preceding validation workload became roughly 125x shorter;
a seven-pair control that measured recovery first instead produced 4,765 ns/cycle
candidate versus 4,827 ns/cycle baseline medians, and normalized disassembly of
`Queue.applyAck` was identical. Tests cover allocation failure, generated sparse
ACKs, never-sent holes, retired-prefix crossings, `u64` range width overflow, and
the conservative unsorted-metadata fallback. Real TLS 1.3 1-MiB gates then held
24/120 datagrams under every-fifth reordering with zero transport loss, and
dropped 6/126 datagrams under seeded 5% loss with six reported transport losses;
both verified every payload byte. These are internal ACK-validation and
correctness results, not a cross-library throughput claim.

### QUIC UDP batch send / receive

```text
QUIC UDP batch benchmark
  send iterations: 5000, packets/batch: 54, bytes/packet: 1200
  GSO available after run: true
  UDP_SEGMENT: 14421 ns/batch, 267 ns/packet
  sendmmsg:    95034 ns/batch, 1759 ns/packet
  GSO relative packet throughput: 6.58x
  total datagrams/path: 270000
QUIC multi-destination UDP send benchmark
  send iterations: 5000, destinations/batch: 54, bytes/packet: 1200
  individual: 115672 ns/batch, 2142 ns/packet
  sendmmsg:   100644 ns/batch, 1863 ns/packet
  batch relative packet throughput: 1.14x
  total datagrams/path: 270000
QUIC UDP receive benchmark
  receive iterations: 5000, packets/batch: 54, bytes/packet: 1200
  GRO available after run: true
  UDP_GRO:    20640 ns/batch, 382 ns/packet
  plain recv: 31318 ns/batch, 579 ns/packet
  GRO relative packet throughput: 1.51x
  total datagrams/path: 270000
```

The multi-destination arm binds 54 independent loopback receivers and submits
one datagram per destination. The addressed endpoint API validates the complete
batch before its first socket operation, retains exact prefix progress after a
partial `sendmmsg`, applies one explicit ECN policy, and uses caller-owned
address/payload views without allocation. Direct tests cover allocation-free
delivery order to two destinations, transactional invalid-input rejection,
socket-traffic accounting, and a backend that accepts exactly one message
before returning `NetworkDown`. The 1.14x sample is an internal socket-boundary
measurement, not yet a QUIC connection throughput claim.

An endpoint-server prototype then separated one protected packet per
Connection from the shared socket flush, matching Quinn's `poll_transmit`
ownership boundary. Prepared packets committed packet numbers, AEAD nonces,
flow/congestion credit, pacing, and recovery before a heterogeneous addressed
batch; socket-unsent suffixes deliberately remained recoverable network loss.
Direct tests decrypted the deferred packet after flush, checked recovery was
already populated, and sent two real TLS connections to different client ports
with exact prepared/socket-visible masks. Duplicate handles were rejected
before mutation. An initially unbounded driver also proved why the socket owner
must retain a turn budget: it remained runnable beyond the benchmark deadline
instead of returning to receive ACK/timer work. Limiting each receive turn to
one batch restored liveness but reduced the four-connection server-sender smoke
to 91.173 MiB/s; eight rounds raised that smoke to 182.537 MiB/s.

The apparent small-shape win did not scale. A verified 64 x 1-MiB run measured
only 86.137 MiB/s server-sender and 132.024 MiB/s client-sender, versus the
retained 145.678 and 141.339 MiB/s medians. Baseline and candidate SHA-256
values were
`0e4ed798c8896590d664bcdbbd4dccb4a4d52f87d99ff6ea5614d0bb973e19d9`
and
`a1413c53408a4c0e394a4d3e84b99dd15ddecde425fc4fb209221a8d361f1a35`.
Every completed arm preserved exact bytes, checksum, connection count, and wire
datagram accounting. The prepared-Connection and Server batch APIs plus the
benchmark state machine were fully removed before commit. zio already
amortizes consecutive socket operations through its I/O submission path; an
additional userspace cross-connection queue delayed packet visibility and
changed burst/ACK scheduling enough to dominate the raw 1.14x socket-boundary
gain. The general addressed UDP primitive remains useful, but it is not
presented as a QUIC connection throughput improvement.

### HTTP/3 real-handshake paced transfer

HTTP/3 server responses now use the same runtime-generated Date policy as
HTTP/1 and HTTP/2. Development, protected, and authenticated runtimes cover
aggregate, streaming, Push, and CONNECT final responses; explicit fields win,
informational responses omit the generated value, and pure codec calls remain
deterministic. The short-lived response view is stack-first and marks generated
Date values never-indexed to avoid QPACK dynamic-table churn. The response
assembly and tests live in a focused `runtime/server/response.zig` module rather
than adding more policy code to the large runtime root. Two CPU-0
development-runtime smoke runs with the default enabled measured 11.078-11.154
us/request (89,653-90,262 requests/s).
The development runtime benchmark accepts `--iterations=N` (default 1,000) so
long profiling runs can collect enough samples without changing its source.
Inbound request and response head validation now collects pseudo-header and
Content-Length lookup metadata during the same semantic scan. Content-Length
errors remain deferred until after structural and field-size validation,
preserving the prior error precedence. Five interleaved CPU-0 runs over 100,000
cleartext request/response exchanges measured 10.29-10.42 us/request versus
10.49-10.53 us/request at the preceding commit (1.01-1.02x faster).

A repeated 1 MiB real-handshake download exposed a short-lived-session race:
the paced writer had submitted the final DATA/FIN packet, but the server then
destroyed its unacknowledged recovery state before a dropped tail packet could
be retransmitted. Handshake clients and servers now expose an explicit,
deadline-bounded recovery-idle drain; ordinary response sends retain their
low-latency socket-submission contract. A deterministic test drops the first
DATA/FIN packet and requires PTO retransmission, exact response bytes, FIN, and
an empty recovery queue. The benchmark uses the drain before teardown and one
absolute 30-second client receive deadline. Five CPU-0 1 MiB download
iterations then completed at 105.87-126.36 MiB/s (120.41 MiB/s mean, 6.18%
standard deviation).
The same recovery drain now covers upload response tails, and both benchmark
directions use one absolute 30-second response budget. A two-iteration CPU-0
1 MiB upload smoke completed at 145.48-151.32 MiB/s (148.40 MiB/s mean).
The single-connection `serveConnection` convenience API now applies the same
bounded shutdown automatically using a configurable five-second default. One
absolute deadline covers both GOAWAY phases and the subsequent recovery drain,
so pacing cannot make graceful shutdown outlive that budget. The
multi-connection endpoint callback loop instead remains nonblocking and
refreshes the selected dispatcher's aggregate timer after application sends,
so its shared owner services the new PTO on a later loop turn. Focused tests
cover invalid drain budgets and the no-timer-before-send / PTO-after-handler
transition.
As part of the same maintenance pass, HTTP/3 URI authority parsing, DNS
deduplication, multi-address resolution, and absolute connect-budget helpers
were moved into `runtime/client/uri.zig`, while the shared runtime error set
moved to `runtime/error.zig`. Public `UriEndpoint`, `UriRequestOptions`,
`uriEndpoint`, and `uriRequestTargetAlloc` names remain compatibility
re-exports; URI, HTTP/3, and full-suite tests cover the extracted code.
Multi-address DNS collection no longer silently discards unique results after
the former fixed 32-address scratch fills. Lookup now runs as an asynchronous
producer while the caller drains the standard 16-result queue, and unique
addresses remain in a 16-entry stack collector before exact dynamic growth.
Tests cover 40 unique results plus a duplicate through a 16-slot queue, spill
OOM without corrupting the retained prefix, an empty closed queue, and real
localhost lookup. Resolver errors are awaited before the empty-result check so
specific DNS failures are not collapsed into `NoAddressReturned`.
Reusable message, Push, and critical-stream send scratch now lives under
`runtime/send/scratch.zig`; the root keeps private aliases so no public or hot
path call shape changes. The HTTP/3 runtime root fell by roughly 450 lines
across these extractions. QPACK encode/decode connection state and its private
rollback/index/blocked-stream algorithms now live together in
`runtime/qpack/state.zig`; fourteen pure state-machine and allocation-failure
tests moved with them to `runtime/qpack/state_tests.zig`, while socket-backed
integration tests remain at the runtime layer. The root keeps public type
aliases plus only the two internal methods required by send rollback and the
existing white-box cancellation check. A post-move QPACK sample measured
827 ns/block and 25 ns/field, within the prior 816-905 ns/block range.
The same send submodule now owns an MTU-aware packetizer shared by full
handshake connections, the lightweight preconfigured-key protected runtime,
and cleartext development endpoints.
The fast path preserves the prior single-packet call for already fitting frame
groups; the fallback measures the exact protected packet size, repacks adjacent
frames, and splits an oversized STREAM descriptor without changing byte order
or FIN.
This fixes large HEADERS under the normal 1200-byte path MTU: an 80-request /
80-response-header WebTransport handshake previously failed with
`DatagramTooLarge`, and now completes without raising the configured MTU.
Development and lightweight protected WebTransport runtimes have matching
80+80 coverage. Handshake and protected cases explicitly use a 1200-byte
datagram limit and 64-byte never-indexed values, so the regression cannot pass
through QPACK repetition alone; the ordinary response case also verifies DATA
and final FIN after fragmentation. A 256-byte field-section setting still
rejects the set with `ExcessiveLoad`. CONNECT header assembly, protocol
validation/response shaping, and admission/capacity tests are grouped under
`webtransport/runtime/connect/`.
The cleartext development request, response-head, response-prefix, body, and
associated-stream send paths use the same complete-plan-before-send policy. An
explicit 1200-byte UDP/STREAM configuration with 80 never-indexed 64-byte
fields now completes both CONNECT and ordinary final response/body/FIN paths
instead of surfacing `DatagramTooLarge`; deterministic planning failures remain
rollback-safe before the first socket attempt.
Their STREAM framing, streaming-head registration, informational response
offset commit, body-chunk rollback, request cancellation, and retained
DATAGRAM cloning now live together in `runtime/development/send.zig`. Tests
verify contiguous STREAM offsets with exactly one final FIN and that a clone
allocation failure leaves the source packet owned and the retained queue empty.
Three CPU-0 development samples during a heavily loaded host measured
12.910-15.323 us/request; the spread is retained only as a functional benchmark
pass and does not replace the isolated range above.
The complete development send helper set has now moved into that module,
including whole-message packetization, response-prefix offsets, request
cancellation, body-chunk state and retained DATAGRAM cloning. Cloning allocates
the exact frame wire length and writes directly into final ownership instead
of growing an ArrayList and converting it to another allocation. The runtime
root is now 24,076 lines. A later loaded-host sample ranged
12.992-21.114 us/request and is likewise not used for a performance verdict.
The legacy single-stream development receive helper now lives in
`runtime/development/receive.zig`, separate from the stricter multi-request
buffer. On FIN-complete contiguous streams it transfers the reassembly
ArrayList into the owned response instead of duplicating the complete HTTP/3
message. Expected peer/stream filtering, irrelevant unidirectional-stream
discard, deadline behavior, packet ownership, and the configured stream-buffer
limit remain unchanged. A loaded-host CPU-0 smoke measured 14.155 us/request
and is recorded only as functional evidence.
Development request/response ownership and bounded batch result types now live
in `runtime/development/message.zig`; public names remain aliases from the
runtime root. Allocation-failure enumeration covers both batch arrays and
their cleanup, while the existing concurrent server tests continue to access
the same public fields and counters.
The preconfigured-key protection scratch and packet-number/socket-prefix commit
backend now live in `runtime/send/protected.zig`; `runtime.zig` retains a
private type alias, so existing call shapes and white-box allocation checks stay
unchanged while another roughly 160 lines leave the root. A packetizer unit
test forces more than 64 output packets and verifies every packet stays within
its MTU, offsets remain contiguous across batch flushes, bytes are unchanged,
and FIN appears exactly once on the final fragment.
Three CPU-0 `bench-http3-dev` samples after the shared packetizer measured
10.879, 11.255, and 13.659 us/request (73,206-91,916 requests/s). This overlaps
the prior 10.698, 11.060, and 13.624 us/request range, so the exact sizing
preflight has no measurable stable small-message regression on this host.
A final isolated three-run sample after every cleartext send path was connected
to the packetizer measured 10.939, 11.042, and 11.568 us/request
(86,438-91,408 requests/s), tightening that no-regression evidence.
The bounded cleartext retained-DATAGRAM FIFO and its count/byte/ownership tests
were also moved under `runtime/development/datagram_queue.zig`; cross-frame
routing coverage remains with the integration layer. This keeps queue policy
independent without creating a flat collection of additional runtime files.
Development associated-stream receive reassembly, per-session/client send
offsets, per-peer server ID cursors, prefix classification, and their lifecycle
tests now live together in `runtime/development/streams.zig`. Public stream,
match, direction, role, and debug-count names remain root aliases, while the
runtime root sheds roughly another 700 lines.
Client/server request lifecycle state and its white-box tests now live under
`runtime/stream/lifecycle.zig`. The module owns outstanding/active indexes,
request decode semantics, priorities, GOAWAY transitions, and drain-floor
comparisons; `runtime.zig` supplies only reader adaptation and the three
buffered-stream floor values. Public shutdown/retry enums remain root aliases,
and callers use count/empty/state methods instead of reaching into arrays.
This removes roughly 350 more lines from the root without changing wire paths.
Aggregate protected/handshake request and response reassembly now lives under
`runtime/stream/buffered/`, with request and response ownership separated and
shared QPACK dependency inspection isolated in `common.zig`. Their indexing,
ready selection, reset FIFO, and allocation-failure tests move with the
implementation. Response reset routing now reserves all reset storage and
checks QPACK dependencies before mutating either buffered or streaming state;
an integration failure-injection test verifies that decoder-feedback OOM keeps
the original stream indexed and retryable. This removes roughly another 700
lines from `runtime.zig` without adding files to the crowded runtime root.
Outbound body indexing, Content-Length accounting, lightweight flow-limit
state, and DATA batch scratch now live in `runtime/stream/outbound_body.zig`
with their indexing white-box test. Connection and protected send orchestration
remain in the root until their transport-specific callbacks can be separated;
callers no longer inspect the body's entry/index collections for lifecycle
decisions.
Incremental message parsing and multiplexed reader scheduling now live in
`runtime/stream/reader.zig` and `runtime/stream/set.zig`; their parser, QPACK
retry, index-repair, reset-FIFO, and fairness tests are colocated in dedicated
test modules. The root accesses reader identity, detach readiness, decoded-head
adoption, and receive-credit state through narrow methods, while development
peer migration uses reserved bulk-adoption helpers rather than manipulating the
set's arrays and indexes. Together with outbound body extraction this removes
roughly another 1,900 lines from `runtime.zig`.
Server-push receive state now lives in `runtime/stream/push/state.zig`, with
promise/stream dual indexes, reordered prefix parsing, cancellation FIFO, and
stable-ID round-robin scheduling hidden behind narrow lookup/iteration methods.
Its five state-machine tests moved to the sibling `state_tests.zig`; the
cancellation test now constructs real encoded push-stream prefixes rather than
manually mutating internal maps.
Role-aware HTTP/3 control-stream receive logic now lives in
`runtime/control/receive.zig`, including GOAWAY ID checks, client/server-only
frame validation, QPACK stream classification, critical-stream closure rules,
and transactional rollback of a complete control update. Focused role, batched
priority, and critical-stream tests live in `runtime/control/receive_tests.zig`;
transport close-code and socket-offset tests remain in the integration layer.
Control and QPACK critical-stream emission now lives beside it in
`runtime/control/send.zig`. The module owns frame construction, SETTINGS and
stream-prefix emission, priority and push controls, QPACK encoder instructions
and decoder feedback, while continuing to use the shared packetizer and
protected-send state directly. Splitting, scratch-reuse, and allocation-failure
rollback tests moved to `runtime/control/send_tests.zig`; focused QPACK, HTTP/3,
WebTransport, and WebSocket runs pass after the move. At this point the runtime
root is 26,792 lines, down 7,181 lines (about 21%) from the 33,973-line start of
this extraction pass, without adding more files to the crowded runtime root.
Three post-move CPU-0 `bench-http3-dev` samples measured 10.904, 10.951, and
10.942 us/request (91,307-91,708 requests/s), matching the preceding
10.941-11.234 us/request range without a visible small-message regression.
Pure dynamic QPACK request/response/streaming-head writer tests now live in
`runtime/qpack/tests/writer.zig`, protected speculative-compression coverage is
separate in `runtime/qpack/tests/integration.zig`, and request-priority admission/reconciliation
coverage lives beside request routing under
`runtime/receive/routing/tests/request.zig`. The development DATAGRAM
coalescing/retention test likewise moved beside its send implementation. These
moves remove test-only blocks from the runtime root without widening production
APIs or changing wire behavior.
Protected QPACK request/response transport cases are further separated into
`runtime/qpack/tests/request_transport.zig` and `response_transport.zig`; Push
control, event, aggregate/deadline, and send-scratch cases live under
`runtime/stream/push/tests/`. Protected client response and deadline cases live
under `runtime/client/tests/`, while server base, GRO, limits, lifecycle, receive,
and streaming cases live under `runtime/server/tests/`. Across this pass the H3
runtime root fell from 23,888 to 18,327 lines and from 88 to 42 inline test
declarations, without changing exported protocol types or wire behavior.
Authenticated request/response, Push, streaming-head, DATA, batch-progress, and
trailer send orchestration is now split again under `runtime/send/message.zig`
and `runtime/send/body.zig`, with focused white-box tests under
`runtime/send/tests/`. Both handshake-backed and preconfigured-key callers keep
their existing signatures through private root aliases. Protected batch send
now validates `sent_count <= protected_count <= staged_count` before committing
any HTTP/3 stream state, matching the full-connection invariant. The runtime
root is now 25,276 lines, down 8,697 lines (about 26%) from the 33,973-line
start of this extraction pass. Three CPU-0 post-split development samples
measured 10.972, 10.904, and 10.895 us/request (91,139-91,776 requests/s), with
no visible regression from the immediately preceding range.
Server-side request packet routing and lifecycle/priority coordination now live
in `runtime/receive/routing/request.zig`, with packet-level tests under the
nested `runtime/receive/routing/tests/` directory. Repeated RESET_STREAM frames
with the same peer, stream ID, and application code are idempotent while
conflicting peers or codes are rejected, avoiding a duplicate-event assertion
before the application consumes the first reset. RFC 9114/9204 connection-error
classification and close emission are centralized in
`runtime/receive/connection_error.zig`; handshake and lightweight protected
client/server receive paths now emit the exact stream-creation,
closed-critical-stream, frame, SETTINGS, ID, and QPACK application codes while
local allocation/timeout/transport and request-stream message failures are not
incorrectly promoted to connection errors. Wire/state tests cover both
stateful and preconfigured-key close paths. The root is now 24,886 lines, down
9,087 lines (about 27%) from 33,973. Three CPU-0
development samples after the receive/error changes measured 11.413, 11.052,
and 10.855 us/request (87,619-92,115 requests/s), within the established host
variance.
Handshake and lightweight protected clients now share the same response, Push,
control, QPACK, and reset dispatcher in `runtime/receive/routing/response.zig`;
the protected path no longer maintains a second frame-classification loop and
now flushes Insert Count Increment feedback as soon as encoder-stream progress
creates it. Tests accumulate QPACK decoder-stream bytes across packet boundaries
instead of assuming that an increment and later section acknowledgment share a
datagram. The runtime root is 24,530 lines after this extraction. Three CPU-0
samples measured 11.189, 10.948, and 10.957 us/request
(89,369-91,338 requests/s), within the preceding range.
The response dispatcher is now the single implementation used by both
handshake-backed and lightweight protected clients; the latter no longer
duplicates control/QPACK/Push/reset classification and now flushes QPACK Insert
Count Increment feedback immediately after processing encoder-stream packets.
The migrated response-reset OOM test and a focused feedback-routing test live
beside it. The runtime root is 24,519 lines after dead-helper cleanup; three
CPU-0 samples measured 11.125, 10.965, and 10.950 us/request
(89,881-91,317 requests/s), again within the established range.
The shared HTTP/3 packetizer now treats a socket-visible prefix followed by an
error as an ambiguous logical write: stateful connections install
`H3_INTERNAL_ERROR`, and the lightweight protected sender becomes unusable, so
callers cannot regenerate different QPACK/stream bytes at an already-visible
offset. A zero-visible-prefix failure remains retryable, while the explicit
body-batch progress API continues to commit only `sent_count` and retry its
suffix. Fault-injection tests cover an in-batch partial send, a failure after a
completed 64-packet batch, zero-progress retryability, and exact body-prefix
commit. Five hot CPU-0 development samples measured 10.760-11.154 us/request
(89,648-92,931 requests/s), with a 10.795 us/request median; an earlier cold,
system-noisy sample reached 18.999 us/request and is not used as regression
evidence.
A follow-up switched the stateful packetizer itself to the explicit
`sendManyProgress` result so internal reservation/accounting cannot be mistaken
for socket-visible progress. Existing small-window/backpressure tests and the
full suite pass with that correction. Three CPU-0 samples measured 10.924,
11.018, and 11.497 us/request (86,976-91,537 requests/s), still overlapping the
established range.
Shared-endpoint HTTP/3 uploads now accept multiple borrowed body slices as one
DATA frame and one QUIC packet without concatenating the payload. A fixed-clock
regression verifies zero socket calls and unchanged body/STREAM/FIN state when
pacing rejects the attempt, followed by exactly one socket call for the same
slices after timer progress. This is syscall and retry-accounting evidence; no
throughput claim is made without a stable comparative benchmark.
The shared-pool batch upload wrapper sends one DATA contribution for each of
several active request streams through the same `sendMany` submission. Its
progress result preserves both a socket-visible prefix count and a simultaneous
send error; fault injection verifies that only that prefix advances HTTP/3 body
state and the untouched suffix remains retryable.
HTTP/3 CONNECT DATAGRAM negotiation, send-side lifecycle checks, terminal
observation, queue polling/draining, and authenticated packet-order routing now
live beside the registry in `runtime/datagram/routing.zig`. The router preserves
DATAGRAM order around FIN/RESET/CONNECTION_CLOSE, validates transport-dropped
payloads, emits `H3_DATAGRAM_ERROR` for malformed Quarter Stream IDs, and keeps
the first terminal state stable until queued payloads drain. Registry traversal
uses narrow association accessors rather than exposing its storage layout. The
five-run 1-MiB real-handshake download remained functional at 118.75 MiB/s mean
on the loaded host; this is a regression smoke, not a new throughput claim.
The cleartext aggregate request buffer now lives in
`runtime/development/request_buffer.zig`. It exposes peer/stream metadata and a
pre-reserved ownership-transfer callback to the per-peer streaming layer rather
than exposing its entry array. Datagram validation now rejects a packet that
mixes two request stream IDs before mutating either reassembler, covered by a
dedicated transactional regression test.
Cleartext server peer coordination now lives under
`runtime/development/server_peer/`: each peer owns its buffered and streaming
requests, lifecycle, QPACK state, outbound body state, response offsets, and
send scratch. The root server retains socket locking and packet emission but
uses semantic response/cancellation contexts instead of reconstructing peer
state transitions from individual fields. Partial-request adoption and
pre-admission reset handling tests move with the coordinator.
Three CPU-0 `bench-http3-dev` smoke samples after the stream/development state
extractions measured 10.872, 10.790, and 10.869 us/request
(91,975-92,678 requests/s), within and slightly tighter than the prior
10.939-11.568 us/request range. An unpinned run immediately after the full test
suite measured 17.123 us/request and is retained only as scheduler-noise
evidence, not as a regression signal.
After moving the per-peer coordinator behind semantic response/cancellation
interfaces, three further CPU-0 samples measured 11.234, 10.941, and
11.062 us/request (89,010-91,393 requests/s), still within the same baseline.

HTTP/3 codec header assembly previously used fixed 64-element descriptor
arrays in request, response, streaming, informational, and Push Promise
writers. Those paths now use a shared 16-element stack buffer with an exact
allocation fallback, so ordinary messages reduce stack use while larger valid
field sections no longer fail as `InvalidFrame`. Static, dynamic, streaming,
informational, Push Promise, automatic-Date, and allocation-failure tests cover
80 application headers plus their pseudo/default fields.

`bench-http3-handshake-transfer` starts a loopback HTTP/3 server, creates a
fresh QUIC/H3 client connection per iteration, streams a fixed-size body in the
selected direction, and reports aggregate bytes/s. Both upload and download
modes now run on the shared zio backend and pass only `std.Io` into the HTTP/3
and QUIC stack; the server side is scheduled with `std.Io.async` instead of a
manually spawned OS thread. The `bench-http3-dev`, QPACK, and Capsule
executables use the same zio-provided clock/I/O boundary and print
`io backend: zio-std-io`. Both upload and download
modes use the handshake runtime's paced body sender: `CongestionLimited` and
`FlowControlBlocked` drive peer packet processing so ACK/MAX_* frames can reopen
send credit instead of turning large transfers into synchronous failures.
`--streams` splits the requested byte count across concurrent client-initiated
request streams, matching the shape of quicz's 4-stream aggregate benchmark.
`--round-robin-chunk-bytes` controls the per-stream scheduling quantum used by
multi-stream upload/download helpers; the default is 64 KiB, while smaller
values are useful for probing ACK/credit fairness without editing source.
`--endpoint-datagram-size`, `--one-rtt-datagram-size`, and
`--paced-body-chunk-bytes` override the benchmark's receive and transfer sizing
knobs. `--receive-batch-datagrams` selects 1 through 16 retained UDP datagrams
without changing the executable, making fixed-binary policy comparisons
possible. The benchmark creates a fresh loopback server/client pair per
iteration and reports mean/stddev MiB/s, matching quicz's multi-iteration
benchmark shape.

Integrated HTTP/3 and WebTransport endpoints now default their physical UDP
receive capacity to 4,096 bytes; generic QUIC endpoints retain 65,535. The
handshake caps generated `max_udp_payload_size` advertisements to the endpoint
capacity and rejects oversized raw transport-parameter overrides. At the HTTP/3
default, the cursor drains up to sixteen independent UDP datagrams through one
zio `std.Io` receive operation, retains at most 64 KiB of encrypted datagrams,
samples the monotonic processing time once for the whole batch, and
authenticates/applies exactly one packet per upper-layer turn. Compact batch
indexes keep that timestamp within the prior connection layout. Endpoints
whose capacity only permits one slot retain the single-packet path.
Preferred-address migration likewise remains on the dual-socket single-packet
path. A real zio regression proves that callback
failure commits only the visited packet, preserves the unread suffix in order,
does not advance it on an invalid deadline, and triggers the configured ACK
threshold only when the second packet is consumed.
The endpoint also honors `std.Io`'s partial receive result: when a backend
returns a non-empty datagram prefix together with an error from a later drain,
netz exposes and accounts for that prefix instead of dropping bytes already
removed from the socket. A zero-count result still propagates the error.
`--ack-eliciting-threshold` controls the server ACK policy; the default of four
is the stable winner from the same-host 2/4/8/16/32 scan. Packet-size-aware
cross-stream body batches are available through
`sendRequestBodyBatchPaced`/`sendResponseBodyBatchPaced`, and
multi-stream runs now enable that path by default. `--disable-body-batch`
retains the sequential A/B control, while `--enable-body-batch` can explicitly
select batching at any stream count. The default changed only after zio and
the HTTP/3 cursor gained bounded receive batching; before those changes this
host's small UDP receive queue made bursts slower than sequential submission.
`--enable-gro-receive` enables the timer-aware owning-batch receive path. It is
also opt-in on this host: the path now completes long uploads/downloads without
stalling, but its burst shape is slower and noisier under the same small receive
queue.

A 2026-09-15 same-binary receive-policy A/B used ReleaseFast executable SHA-256
`3ca5bfbd06f7f61043fc3e40bba73b34221f443a6b4cb50fdb4f3e5816f1c8ac`,
CPU 0, a 4,096-byte endpoint, and seven order-alternated 16 MiB/four-stream
download pairs. Batch 16 achieved an 86.02 MiB/s median versus 67.20 MiB/s for
batch 1 (1.280x, 6/7 paired wins). Every arm reported `zio-std-io`, exactly
16,777,216 body bytes, and status total 800. This is a same-process receive
policy result, not an equal-wire cross-stack claim. The bidirectional tquic
HTTP/3 gate also passed with and without Retry after the default changed.

Five fixed-binary, CPU-0, order-alternated 16-MiB/four-stream comparisons
against commit `8cc373ae` measured non-GRO cursor batching at 75.75 MiB/s
download median versus 67.53 MiB/s before (1.122x, 5/5 paired wins). Upload,
where the benchmark peer rather than the HTTP/3 receiver carries most payload
work, measured 114.29 versus 115.13 MiB/s (0.993x, overlapping ranges, 3/5
wins). One-stream upload/download medians were 162.93/141.37 MiB/s after and
155.48/138.24 MiB/s before. All arms verified 16,777,216 body bytes and the
expected status totals; these are same-process regression measurements, not an
equal-wire cross-stack claim.
With that receive path in place, seven same-binary, order-alternated
four-stream comparisons also favored cross-stream body sending in every pair:
upload median rose from 103.35 to 112.77 MiB/s (1.091x) and download from
73.41 to 80.27 MiB/s (1.093x). Multi-stream benchmark mode therefore enables
body batching by default; single-stream mode remains sequential.

A 2026-09-22 body-batch send-path audit removed the HTTP/3 layer's second exact
packet-length walk immediately before `Connection.sendManyProgress`. The QUIC
batch preflight already validates every packet's frame lengths, packet-number
overhead, current PMTU, and endpoint datagram limit before reserving flow or
congestion credit, recovery ownership, packet numbers, or socket output. A new
small-MTU regression verifies that an oversized body batch still returns
`DatagramTooLarge` with unchanged body offset/FIN state, no completion callback,
no sent-packet increment, and no UDP datagram. Fixed ReleaseFast binaries,
CPU 0, and seven order-alternated 16-MiB/four-stream pairs at an explicit
3,000-byte body chunk measured:

| Direction | Before SHA-256 | Before median | After SHA-256 | After median | Paired result |
|---|---|---:|---|---:|---:|
| upload | `4f777fd91e9ef46b7d9b3bf132605afcfaa75b3ac97c6c5d3d0a29509ee5077b` | 149 MiB/s | `02135fc0dc0f43f29b01dec362e0548a9e335c677ed1c6f6143cba16b656907a` | 155 MiB/s | 7/7 wins, 1.040x |
| download | same | 76 MiB/s | same | 77 MiB/s | 5 wins, 1 tie, 1 loss, 1.013x |

The upload improvement is consistent; the download delta is close to host
noise and is not presented as a general speed claim. A separate same-binary,
order-alternated five-pair policy comparison then changed the benchmark-only
sub-64-MiB multi-stream chunk from 3,000 to 5,000 bytes. Upload medians moved
from 139 to 197 MiB/s (1.417x, 5/5 wins) and download from 82 to 103 MiB/s
(1.256x, 5/5 wins). The 64-MiB benchmark retained its separately established
6,000-byte policy, and production's conservative 1,024-byte default remained
unchanged at that point. The direction-aware production result below
supersedes both benchmark-only policies. Final five-sample 5,000-byte runs
verified 83,886,080 bytes and status total 4,000 in each direction: upload
mean 203.28 MiB/s (19.57% standard deviation, 129.76–235.07) and download mean
113.54 MiB/s (0.82%, 111.96–114.69).
`--verbose` prints per-iteration throughput lines (`[iter N]`) for diagnosing
long or stuck multi-iteration runs. `--trace-iteration` additionally prints
coarse lifecycle stages (bind, connect, transfer, join) for each iteration.

#### Direction-aware paced request and response defaults (2026-10-12)

The paced helper default is now resolved by endpoint role: clients use a
5,000-byte logical request-body batch and servers use an 8,000-byte logical
response/push-body batch. A non-zero `paced_body_chunk_bytes` remains an
explicit override. This distinction matters because a same-binary CPU-0 scan
of the four-stream 16-MiB upload shape measured the following means:

| Logical chunk bytes | 1,024 | 3,000 | 4,000 | 5,000 | 6,000 | 7,000 | 8,000 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| Upload mean MiB/s | 68.73 | 205.30 | 207.82 | 216.28 | 189.22 | 181.04 | 190.37 |

Using 8,000 for both directions therefore regressed a seven-pair upload
control by 11.55%. The role split retains the measured request optimum instead
of hiding that regression behind the download gain. Congestion, connection and
stream flow control, STREAM frame sizing, and the actual datagram limit still
cap each emitted packet. A direct regression verifies that the 8,000-byte
logical response default becomes 1,136 bytes of body capacity for a standard
1,200-byte datagram and remains 8,000 bytes for an 8,192-byte datagram.

The final evidence uses independently compiled ReleaseFast binaries, pins
every run to CPU 0, warms each binary once per shape, and alternates AB/BA order
within each pair. The baseline is clean `162dc380cd796025b22bb872db9c6c130ab9ffcb`
with SHA-256
`f59cdfdda5a161ee8ddf747b1e4855e22a4b3a3afaf8d212b6c4ecb850a35579`;
the direction-aware candidate SHA-256 is
`86e70110399ace34a9380bdf522605aa51d8356a6e7b2745225869449658fb11`.
Every sample completed the exact byte count and four status-200 responses.

| Shape | Baseline samples (MiB/s) | Candidate samples (MiB/s) | Means and population CV | Mean paired change |
|---|---|---|---|---:|
| 16 MiB download, 4 streams | 141.83, 128.45, 139.71, 143.04, 142.36, 142.45, 143.78 | 225.08, 209.68, 221.97, 222.56, 225.41, 224.21, 224.22 | 140.23 (3.53%) to 221.88 (2.30%) | +58.30% |
| 64 MiB download, 4 streams | 145.64, 146.50, 146.99, 148.01, 147.76 | 203.35, 202.38, 202.68, 203.17, 203.68 | 146.98 (0.58%) to 203.05 (0.23%) | +38.15% |
| 16 MiB upload control, 4 streams | 208.84, 207.00, 217.80, 207.45, 206.78, 206.36, 206.93 | 207.06, 208.22, 211.52, 207.64, 208.19, 209.68, 208.17 | 208.74 (1.81%) to 208.64 (0.66%) | -0.02% |

The upload control's seven paired changes span -2.88% to +1.61%; its -0.02%
mean is noise-level, while every download pair improves materially. The exact
fixed-binary command shapes were:

```sh
taskset -c 0 ./bench-http3 --mode=download --streams=4 --body-bytes=16777216 --iterations=1
taskset -c 0 ./bench-http3 --mode=download --streams=4 --body-bytes=67108864 --iterations=1
taskset -c 0 ./bench-http3 --mode=upload --streams=4 --body-bytes=16777216 --iterations=1
```

#### Avoiding congestion-tail response fragments (2026-10-12)

The next response-scheduler change stops treating a transient remainder in the
congestion window as a useful body-chunk size. Before the change, a short
instrumented 1,280-byte-MTU run observed full 1,152-byte contributions followed
by 833-, 48-, and 208-byte contributions when congestion credit fell to 897,
112, and 272 bytes. The scheduler now computes the useful contribution from
the body tail, stream/connection flow credit, logical chunk, and datagram
budget first. If congestion is the only smaller budget, it pumps peer ACKs and
replans instead of emitting a fragment; a genuine flow-control boundary or the
final body tail still sends immediately.

This behavior addresses a pre-change capture signature rather than relying on
throughput alone. In the verified v1 four-stream download artifact
`zig-out/http3-captures/run.ELJ1qP`, the netz server sent 115,030 datagrams and
101,857 of them were 1,125 bytes. The quic-go server sent 102,139 datagrams and
92,710 were 1,188 bytes. Netz also emitted 8,684 sender datagrams between 81
and 999 bytes, versus 77 for quic-go. A fresh kernel capture remains required
to quantify the final wire distribution because the current process lacks
`CAP_NET_RAW`; the existing artifact and temporary capacity trace establish
the optimization target, while the fixed-binary results below establish its
causal throughput effect.

The baseline is clean commit
`bf4ff97cb00ee2df41cc8a43ddb64d17aa615fda` with binary SHA-256
`86e70110399ace34a9380bdf522605aa51d8356a6e7b2745225869449658fb11`.
The candidate SHA-256 is
`10527318f19c22e2e546a651e437ea1d5a743650375ca7b6e011a685fdbc1920`.
Every shape was warmed once per binary, pinned to CPU 0, and alternated AB/BA.

| Shape | Baseline mean (CV) | Candidate mean (CV) | Mean paired change |
|---|---:|---:|---:|
| 16 MiB download, 4 streams, 1,200-byte datagram | 32.19 MiB/s (0.74%) | 52.55 MiB/s (2.19%) | +63.25%, 7/7 wins |
| 16 MiB download, 4 streams, 1,280-byte datagram and 1,152-byte chunk | 32.74 MiB/s (0.49%) | 53.75 MiB/s (0.63%) | +64.15%, 7/7 wins |
| 16 MiB download, 4 streams, default 8-KiB datagram | 222.26 MiB/s (2.55%) | 292.42 MiB/s (1.80%) | +31.66%, 7/7 wins |
| 64 MiB download, 4 streams, default 8-KiB datagram | 204.15 MiB/s (0.15%) | 287.10 MiB/s (0.52%) | +40.63%, 5/5 wins |
| 16 MiB download, 1 stream, default 8-KiB datagram | 270.94 MiB/s (1.28%) | 272.10 MiB/s (0.99%) | +0.45%, noise-level |
| 16 MiB upload, 4 streams, default 8-KiB datagram | 217.23 MiB/s (1.29%) | 218.07 MiB/s (0.50%) | +0.41%, noise-level |

The certificate-verifying quic-go v0.59.0 download gate subsequently completed
all five samples in both endpoint-role pairings with four streams, exact
16,777,216-byte aggregate bodies, checksum 2,139,095,040, four finished
streams, and status 200. This is interoperability evidence only; it is not a
matched baseline/candidate throughput comparison. Unit coverage fixes the
policy boundary: congestion-only partial credit returns zero, while partial
flow credit and the final body tail remain sendable.

A 2026-09-15 ReleaseFast migration smoke ran 20 cleartext requests, one
four-stream 64-KiB upload, one matching download, 1,000 iterations of each
QPACK scenario, and the default one-million-iteration Capsule workload. Every
command completed and printed `io backend: zio-std-io`; the request status
totals and transfer byte counts were exact. These short runs establish the new
runtime path and are not performance comparisons.

A 2026-11-19 zio-era CPU-0 smoke of the same benchmark with 1-MiB bodies
measured 294.20 MiB/s upload and 337.50 MiB/s download for one stream, and
265.02/281.26 MiB/s for four streams. Every run reported status 200 and exact
1,048,576-byte bodies. These are single-iteration runtime smokes, not
comparative performance evidence.

```sh
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=16777216 --mode=upload --streams=4 --verbose
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=1048576 --mode=upload --streams=1
```

Historical pre-zio 5-iteration 1 MiB upload smoke sample:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 1
  iterations: 5
  body bytes/iteration: 1048576
  total body bytes: 5242880
  status total: 1000
  ns/iteration: 5055264
  bytes/s: 207422566
  MiB/s: 197
  mean MiB/s: 201.88
  stddev MiB/s: 26.15
  stddev percent: 12.95
```

Historical pre-zio 16 MiB single-stream upload result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 1
  iterations: 1
  body bytes/iteration: 16777216
  total body bytes: 16777216
  status total: 200
  ns/iteration: 633723309
  bytes/s: 26474039
  MiB/s: 24
```

Historical pre-zio 16 MiB single-stream download result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: download
  streams: 1
  iterations: 1
  body bytes/iteration: 16777216
  total body bytes: 16777216
  status total: 200
  ns/iteration: 630802886
  bytes/s: 26596606
  MiB/s: 25
```

Historical pre-zio 16 MiB / 4-stream upload result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 4
  body batch: false
  1-RTT datagram bytes: 8192
  paced body chunk bytes: 3000
  server ACK-eliciting threshold: 4
  iterations: 5
  body bytes/iteration: 16777216
  total body bytes: 83886080
  status total: 4000
  ns/iteration: 123919485
  bytes/s: 135388038
  MiB/s: 129
  mean MiB/s: 129.36
  stddev MiB/s: 5.50
  stddev percent: 4.25
```

This CPU-0-pinned sample was captured on 2026-08-17 after moving
ACK-driven packet-threshold recovery into QUIC's timer-servicing blocking
receive path. Before that fix, all client body-send calls could return while
dropped STREAM ranges remained pending; the client then waited for responses
and recovered only through exponentially backed-off PTO probes. The same
16 MiB / four-stream trace previously stalled after the server consumed about
9.4 MiB. All five iterations above delivered every stream through FIN.

Historical pre-zio 16 MiB / 4-stream download result:

```text
HTTP/3 real-handshake transfer benchmark
  mode: download
  streams: 4
  iterations: 1
  body bytes/iteration: 16777216
  total body bytes: 16777216
  status total: 800
  ns/iteration: 134534611
  bytes/s: 124705574
  MiB/s: 118
```

After moving RFC 9218 scheduler offsets into candidate storage and carrying
the originating response index beside each fixed packet-staging slot, a
CPU-0-pinned three-iteration 16 MiB / 4-stream download regression run measured:

```text
per iteration: 54.75 / 55.19 / 55.16 MiB/s
mean: 55.03 MiB/s
stddev: 0.20 MiB/s (0.37%)
status total: 2400
verified body bytes: 50331648
```

The hot commit path no longer linearly scans small response sets or hashes
large response sets to recover an index. Up to sixteen responses remain fully
allocation-free at scheduler setup; larger sets now allocate one exact
candidate array and one temporary duplicate-ID set instead of four separate
work areas. A separate CPU-0 17-stream run forced that heap-backed path,
verified all 17,825,792 body bytes and status total 3,400, and completed at
53.97 MiB/s. Candidate refresh now accumulates the RFC 9218 selection in the
same pass instead of rescanning the full array; the same pinned 17-stream shape
then completed at 54.04 MiB/s. The roughly 0.13% difference is noise-level, so
the result establishes no regression while the removed pass is retained as a
direct CPU-work reduction for larger stream sets. Splitting QUIC's per-stream
flow-control query from its connection/congestion/PMTU snapshot then removed
three more repeated connection-level reads per response; the same shape measured
54.23 MiB/s, likewise a no-regression result rather than a significant change.
These are internal regression samples, not an equal-wire comparison with quicz.

This is now a real-handshake, paced single-stream and 4-stream upload/download
internal result with the same 16 MiB transfer size as the quicz reference
benchmark family. The cross-process quic-go comparison below covers the former
single-stream full-stack gap and now includes an externally verified 4/16-stream
shape. Capture-backed equal-wire comparison remains open.
An opt-in, strictly verified capture pipeline now exists for the quic-go
comparison below; the remaining gap is a real artifact from a host permitted
to open the packet socket, followed by ACK/frame/cipher equivalence analysis.

### HTTP/3 versus quic-go, same application shape

`bench-http3-quic-go` builds against quic-go v0.59.0 from the audited,
repository-owned Go module under `tools/interop`, so it no longer depends on a
separate quicz checkout. It runs both sender roles for upload and download.
Client and server are pinned to separate CPUs. Every sample creates a fresh
certificate-verified
QUIC v1 or forced-v2 H3 connection, completes an untimed `/benchmark/ready` request, then
times 1, 4, or 16 request bodies through receiver-validated status, headers,
EOF, bytes, and checksums. This prevents congestion, QPACK, and retired-stream
history from one sample changing the next. Both sides use a fixed 1 MiB stream
window by default; connection credit is that window times at least eight, and
therefore grows to 16 MiB for the 16-stream shape. The steady-state MTU is 1280
bytes and the effective application chunk is 1152 bytes. Netz explicitly
disables GSO/GRO; quic-go reports its implementation defaults. A 2026-11-19 rerun at the current head with the pinned quic-go v0.59.0
fixture and Go 1.24.7 measured upload medians of 131.384 MiB/s for the
netz-client/quic-go-server pairing and 122.452 MiB/s for the
quic-go-client/netz-server pairing (5 samples, 4 streams, 4 MiB per stream,
fresh connection per sample). Every sample verified status 200, 16,777,216
bytes, checksum 2,139,095,040, and four finished streams. The capture arm could
not run on this host because `AF_PACKET` was denied without `CAP_NET_RAW`; the
capture-backed equal-wire comparison therefore remains open. Rows are in
`docs/evidence/http3_quic_go/2026-11-19-rerun.json`.

The current
netz client and server use zio behind `std.Io`. Config, client-owned result,
server-completion, and memory records carry `client_io` and `server_io`; the
strict checker also verifies endpoint ownership, the complete benchmark shape,
finite recomputed throughput, and exact bytes/checksum.

```sh
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --mode=upload --warmup=2 --iterations=5 --body-bytes=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --timeout-ms=30000

zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --mode=download --warmup=2 --iterations=5 --body-bytes=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --timeout-ms=30000

# Run separately from timing and allocation measurements. Requires Linux
# CAP_NET_RAW and three available CPUs; artifacts are written under
# zig-out/http3-captures/.
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --capture --mode=upload --warmup=2 --iterations=5 --streams=4 \
  --body-bytes=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000

# No CAP_NET_RAW is required. Both implementations disable GSO and report
# complete-run userspace UDP datagram and payload-byte counters.
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --socket-traffic --mode=download --warmup=2 --iterations=5 --streams=4 \
  --body-bytes=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000

# Apply a 64 MiB/s ceiling to netz endpoints for controlled receiver-queue
# loss experiments; the normal default remains unlimited.
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --socket-traffic --mode=download --warmup=2 --iterations=5 --streams=4 \
  --body-bytes=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000 \
  --netz-max-pacing-rate-bytes-per-second=67108864

NETZ_HTTP3_INTEROP_VERSION=2 \
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --mode=upload --warmup=2 --iterations=5 --streams=4 \
  --body-bytes=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000

NETZ_HTTP3_INTEROP_VERSION=2 \
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --netz-only --stats --mode=upload --warmup=1 --iterations=1 \
  --streams=4 --body-bytes=65536 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000
```

`--netz-max-pacing-rate-bytes-per-second=N` is netz-specific and requires a
positive value. It is applied to every netz endpoint participating in the
selected role pair; quic-go keeps its own pacing policy and carries the value
only as paired-run metadata. Config, socket-traffic, transport-stat, and
packet-drop records store the exact value, with `0` meaning the option was not
set. This makes capped and uncapped evidence distinguishable without changing
the production or benchmark default. Each socket-traffic comparison also
records the client and server executable SHA-256 values so AB/BA repetitions
can reject binary drift instead of inferring stability from source state.

A ReleaseSafe v1 socket-traffic smoke with one warmup, one measured round,
four 64-KiB streams, and a 1-MiB/s netz ceiling completed both mixed role
pairs with exact bytes and checksums. When netz was the upload sender, the
measured body rate was 1.010 MiB/s, transport loss was zero, and quic-go
reported zero packet drops. The reverse pairing left the quic-go sender
uncapped at 103.562 MiB/s while the netz receiver still recorded the paired
setting. This is configuration/behavior evidence, not a recommended production
rate or a general throughput comparison.

A subsequent fixed-commit (`b618417d`), CPU-0/client and CPU-1/server,
ReleaseFast A/B/B/A run used one warmup plus two measured fresh connections,
four 4-MiB streams, QUIC v1, and socket-traffic accounting. All four arms used
the same netz-client (`3502160c...fad87`), netz-server
(`7bb3b568...f5ab`), and quic-go (`89d1a437...59a15`) executable hashes. With
netz as the upload sender, the two unlimited A arms recorded 1,918 and 2,133
transport losses, matched by 1,928 and 2,144 quic-go `dos_prevention` drops;
both 128-MiB/s B arms recorded zero losses and zero drops. With netz as the
download sender, the unlimited arms recorded 1,413 and 2,592 losses, matched
by 1,416 and 2,598 drops; both capped arms again recorded zero. A one-pass
coarse scan still showed loss at 192 and 256 MiB/s while both 128 and 96 MiB/s
were loss-free on this host. This brackets the local zero-latency receiver-
queue threshold but does not justify a universal default: the production
default stays unlimited, and 128 MiB/s is only an explicit experiment or
deployment policy for a known receiver capacity.

The opt-in capture mode starts a dedicated Linux `AF_PACKET`/`SOCK_DGRAM`
packet socket on a third pinned CPU before each server. It filters the loopback
single cooked IPv4 copy (`PACKET_HOST`) by the pair's unique UDP server port.
Direction is reconstructed from that port rather than inferred from the packet
type. Both netz endpoints already disable GSO; the runner
sets `QUIC_GO_DISABLE_GSO=true`, and the Go fixture independently rejects a
connection whose `ConnectionState().GSO` remains enabled. Each classic-PCAP
artifact uses DLT_RAW, retains at most 128 bytes per packet, and is capped at
512 MiB. Its original IP
length and captured IPv4/UDP headers are sufficient to recompute directional
datagram counts, UDP payload bytes, IP bytes, and ordered packet-size hashes
without retaining complete encrypted application payloads. The strict checker
first validates the ordinary client result and server completion, then
reparses the PCAP and requires zero packet-socket drops, matching port/shape,
binary and capture-tool hashes, header arithmetic, and enough sender bytes to
cover every warmup and measured body. A cross-role checker requires the same
workload, tool, CPUs, and quic-go binary before reporting totals and
directional size-sequence equality. Capture artifacts cover complete process
pairs, including handshakes, ready/close requests, ACKs, and teardown, and the
artifact directory retains the exact capture script alongside the PCAPs and
endpoint logs, plus the pinned quic-go `go.mod` and `go.sum`. Their
timings are labeled `timing_usable=false`; equal aggregate counts or packet
sizes do not by themselves establish equal QUIC frames, ACK policy, cipher, or
application scheduling. `--capture`, `--stats`, and `--netz-only` are therefore
kept as separate evidence modes.

The no-privilege `--socket-traffic` mode wraps quic-go's UDP socket without
hiding its OOB/ECN or batched-receive interfaces, attaches netz's optional
endpoint traffic counters, and forces GSO off for both implementations. It
reports one `traffic_scope=all-rounds` record per endpoint and marks timing as
unusable because the counters add instrumentation overhead. The strict checker
binds both records to the exact workload and runtime roles, then verifies that
the receiving endpoint never observed traffic its peer did not report sending.
Unlike PCAP, this boundary cannot prove packet ordering or inspect encrypted
frame composition.

A QUIC v1 run with two warmups plus five measured rounds, four 4-MiB streams
per round, a 1,152-byte effective application chunk, and a 1,280-byte MTU
reported:

| Direction | Sender | UDP datagrams | UDP payload bytes | Mean payload |
|---|---|---:|---:|---:|
| download | netz server | 106,366 | 126,500,316 | 1,189.293 bytes |
| download | quic-go server | 102,134 | 121,142,495 | 1,186.113 bytes |
| upload | netz client | 106,942 | 127,169,581 | 1,189.145 bytes |
| upload | quic-go client | 102,072 | 121,149,762 | 1,186.905 bytes |

The final netz mean payload is no longer smaller than quic-go's. Netz still
emits 4.14%/4.77% more sender datagrams and 4.42%/4.97% more UDP payload bytes
for download/upload. The structured follow-up makes the cause explicit. Netz
reported 4,257 packet-threshold losses in the download sender role and 3,586
in the upload sender role; the corresponding quic-go receiver qlog reported
4,264 and 3,615 packet drops, all with `dos_prevention` because its bounded
per-connection unprocessed-packet queue was full. Duplicate, payload-decrypt,
and other drop categories were zero, as were netz authentication failures.
The near one-for-one loss/drop counts show that the remaining retransmissions
respond to a real peer processing-queue drop at this benchmark boundary rather
than a packet-number, key-update, or packet-fill defect. A QUIC v2 four-stream
smoke independently passed both role pairings and the same accounting checks.
Kernel capture is still required for packet ordering and encrypted frame-shape
claims.

This host has no effective `CAP_NET_RAW`: the capability probe fails with
`AF_PACKET was denied` before starting either benchmark process. Parser, PCAP
round-trip, per-pair verifier, comparison, GSO-contract, and fail-closed
permission tests are reproducible here, but no capture numbers are recorded as
if they had been observed. A privileged capture host is still required to run
the command above and decide whether the captured shapes are sufficiently
matched for any stronger timing claim.

A 2026-09-15 migration gate exercised QUIC v1 with one stream and QUIC v2
with four streams in both upload/download directions and both mixed role pairs.
The v2 four-stream records each verified 262,144 logical bytes and checksum
33,423,360. With memory telemetry enabled, every netz process finished with
`live_bytes=0`; the runner correctly labeled the available RSS tool as
`busybox-time-maxrss`. A separate zio-only v2 four-stream gate passed both
directions under the same schema. These are one-sample functional and
evidence-pipeline checks, not performance comparisons.

Historical pre-zio CPU-0/client, CPU-1/server samples on 2026-09-08 measured:

| Sender implementation | Upload | Download |
|---|---:|---:|
| netz | 169.75-175.54 MiB/s | 169.03-176.47 MiB/s |
| quic-go | 45.25-124.16 MiB/s | 50.55-73.21 MiB/s |

Every sample verified status 200, exactly 4,194,304 logical bytes, and checksum
534,773,760. The wide upload ranges are retained instead of compressed into a
single ratio. These measurements used the former `std.Io.Threaded` harness and
must not be cited as zio performance. This is `same-application-shape` evidence,
not equal-wire and not
a whole-library superiority claim. The new opt-in capture path can now measure
kernel-visible UDP datagram counts/bytes and size sequences with GSO disabled,
but a privileged-host artifact plus ACK/frame/cipher analysis is still required
before claiming identical wire work. The important result is that a reproducible
full-stack comparison now exists and fails closed on any header, byte, EOF, or
checksum mismatch.

The aggregate response receive path was revalidated on 2026-09-14 after a
quic-go download consistently stopped once roughly 336 KiB had arrived. The
HTTP/3 layer had already copied each contiguous response prefix into its own
bounded reassembly, but the QUIC receive cursor remained unchanged until FIN,
so the peer eventually exhausted stream credit while the client waited for the
rest of the response. Aggregate routing now commits only the contiguous copied
prefix back to QUIC immediately; streaming responses retain their existing
application-read-driven backpressure. A focused 8-byte-window test verifies
that two 6-byte prefixes advance both the transport read offset and advertised
stream limit before FIN.

The benchmark fixture also now budgets the wire bytes retained by aggregate
reassembly rather than only the logical body: quic-go's 1152-byte application
writes produce 911 DATA frames for a 1 MiB body, requiring 2733 bytes of DATA
frame headers plus the bounded response-header margin. With the transport
window still fixed at 1 MiB, single-, 4-, and 16-stream downloads passed for
QUIC v1 and v2 in both endpoint-role pairings. The 16-stream cases verified
16,777,216 aggregate bytes, all 16 streams, and checksum 2,139,095,040. These
are one-sample functional gates, not throughput claims. The full tquic gate
also passed in both directions with Retry on and off, GET/Range/POST digest,
and bidirectional GOAWAY/drain/reject-next-stream coverage. Its public netz
client and server now run on zio behind `std.Io`; the runner requires
`zio-std-io` for the netz endpoint and the audited `tquic-mio` identity for
the tquic endpoint in every success record.

The completed aggregate response now transfers its reassembly allocation into
the owned result after all fallible validation and decoding have succeeded,
instead of duplicating the complete encoded stream and then freeing the
original. This follows the same broad ownership principle as Quinn's
chunk-collecting `read_to_end`, while retaining the consumption-driven credit
behavior exposed by quiche's `recv_body`. Allocators that cannot shrink the
reassembly allocation in place keep the prior copy fallback; an induced
resize-plus-allocation failure verifies that the original response remains
retryable.

Three order-alternated fixed-binary memory pairs used one warmup plus three
measured fresh connections, a 16 MiB response, a 1 MiB transport stream window,
and the quic-go-server/netz-client direction. The median netz explicit peak
fell from 99,644,791 to 78,618,808 bytes (-21.1%), cumulative allocation from
348,387,294 to 281,102,735 bytes (-19.3%), and whole-process peak RSS from
420,400 to 353,104 KiB (-16.0%). Every run freed all explicit allocations and
verified the complete response. Five separately order-alternated throughput
pairs, with three measured responses per process, overlapped: the baseline and
candidate medians were 15.725 and 15.804 MiB/s, while the paired throughput
ratio median was 0.992 and the candidate won 1/5 pairs. The change is therefore
retained as a memory reduction with no throughput-improvement claim. The frozen
ReleaseFast client SHA-256 values were
`26c14a80ac78300856281149c3e7e90577e36768b7a8365c32575e4d88585a9a`
for the baseline and
`473cf866d9150636431c1e122c5bf1041590118ea79519dc076c62640f07a8a5`
for the candidate.

The symmetric aggregate request path now uses the same two-phase transfer and
returns QUIC receive credit as each contiguous prefix is copied into HTTP/3
ownership. A deterministic 8-byte connection/stream-window test advances two
6-byte prefixes before FIN. A dedicated single-stream `--aggregate-upload`
mode in `bench-http3-handshake-transfer` exercises `receiveRequest()` rather
than the benchmark's default streaming receiver; `--flow-control-bytes` keeps
the historical 256 MiB default unless explicitly set. With 256 KiB of credit,
the final binary completed a 1 MiB aggregate upload, while the frozen baseline
stopped at 253,952 bytes and was terminated by the 10-second comparison limit.

For the copy-cost comparison, three order-alternated fixed-binary memory pairs
used 16 MiB requests, one stream, the default 256 MiB credit, and three measured
iterations. Median explicit peak allocation fell from 104,304,658 to 65,633,749
bytes (-37.1%), and median cumulative allocation fell from 279,031,715 to
168,674,704 bytes (-39.5%). Five separate throughput pairs, five iterations
each, measured baseline/candidate medians of 59.00/67.15 MiB/s; the paired
ratio median was +13.7% with 4/5 wins, but the 57.40-64.74 and 64.14-68.25
MiB/s ranges overlap slightly. This is a positive result for that bounded
aggregate shape, not a general HTTP/3 throughput claim. Every run verified
83,886,080 bytes and status total 1000. The final ReleaseFast binary SHA-256
values were
`0e5e7e978ae23043d5f7820fb98c5bb2cc5776da25d92b5951f3468cfef0fa55`
for the baseline and
`8ff68b3300e10dac770d74af0a15ea915a8cee9e73bc40d54dbca087cc4277b2`
for the candidate. The ordinary streaming upload mode remains the default and
passed the v1/v2 four-stream quic-go matrix after this change.

The concurrent gate is reproducible with:

```sh
zig build bench-http3-quic-go-multistream -Doptimize=ReleaseFast --summary all
```

It runs QUIC v1 and v2 with 4 and 16 streams, upload and download, both role
pairings, two warmups, and five measured samples. Set
`NETZ_HTTP3_MULTISTREAM_VERSIONS=1` or `=2` to narrow the matrix. All request
streams are created before transfer. For the pinned quic-go v0.59 peer, v2
selects its historical RFC 9001 key-update label compatibility profile; the
library default remains RFC 9369. Result, completion, and memory records include
`quic_version`, and the verifier rejects missing or mismatched versions.
The Zig upload client and download server use paced cross-stream body batches;
the opposite receive paths consume whichever stream is ready. The Go client
uses a goroutine start barrier and the Go server holds each round until every
handler has entered. Stream indices are carried independently of QUIC stream
ordering, payload bytes vary by index, and the verifier requires one unique
client result plus one server-completion record per sample with all streams
finished and independently validated. An explicit final request/response
barrier precedes connection close.
The DATA phase uses one caller-owned awake-clock deadline across every paced
batch send, receive-progress wait, pacing wait, response receive, and recovery
drain. The public bounded batch APIs report the exact socket-visible committed
chunk prefix; the priority scheduler reports committed body bytes separately
for every response, so timeout and partial socket errors never imply that an
already-sent prefix is safe to replay. Authenticated aggregate request and
paced-response deadline APIs now carry that same timestamp through QUIC stream
admission, SETTINGS/QPACK instructions, HEADERS, body, trailers, and response
receive. Their packetizer checks before every socket attempt and bounds pacing
waits; a zero-packet timeout remains retryable, while a timeout after a
socket-visible multi-packet prefix retires the connection without attempting
an unbounded close write. Streaming head APIs retain their separate blocking
contract, so this benchmark continues to label its measured batch-body scope
explicitly.

The complete post-barrier gate passed on 2026-09-09. Its 16-stream samples
carried 262,144 bytes per stream, 4,194,304 aggregate bytes, and aggregate
checksum 534,773,760:

| Mode | netz sender MiB/s (range; mean; median) | quic-go sender MiB/s (range; mean; median) |
|---|---:|---:|
| upload | 147.124-179.582; 159.152; 159.188 | 106.246-108.165; 107.233; 107.506 |
| download | 72.460-98.869; 83.197; 82.212 | 48.716-50.733; 49.870; 49.936 |

Every 4- and 16-stream sample passed the independent dual-log verifier. These
figures are `same-application-shape`, not equal-wire:
kernel/interface capture and equalized GSO/GRO, ACK, packetization, cipher, and
application scheduling remain prerequisites for a general throughput ratio.

### Same-host reference comparison against `~/Work/quicz`

Captured on the same host with `/tmp/quicz-bench-hs` compiled from
`~/Work/quicz/examples/quic_bench_hs.zig` using:

```sh
zig build-exe -OReleaseFast --dep quicz \
  -Mroot=/home/passchaos/Work/quicz/examples/quic_bench_hs.zig \
  -Mquicz=/home/passchaos/Work/quicz/src/lib.zig -lc \
  -femit-bin=/tmp/quicz-bench-hs
timeout 600s /tmp/quicz-bench-hs
```

Relevant quicz output:

```text
Stream Upload 228.77 MB/s  (stddev 3.3%, 5 iters x 64 MB)
Multi-Stream (4x) 244.85 MB/s  (stddev 2.8%, 5 iters x 64 MB, 4 streams)
Echo Latency P50=10.5us  P99=14.3us  P99.9=377.8us  (5000 iters)
Handshake Rate 1154.7 conn/s  (100 handshakes in 0.087 s)
Aggregate (4 conns) 512.50 MB/s  (4 concurrent conns x 64 MB in 0.500 s)
```

To align transfer size with quicz's real-handshake throughput run, netz was
also measured with `--body-bytes=67108864`:

```sh
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=upload --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=1
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=67108864 --mode=upload --streams=4 --verbose
taskset -c 0 zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=4
```

```text
netz upload streams=1:   117.76 MiB/s mean, 5 iterations
netz download streams=1: 123 MiB/s, 129,894,689 bytes/s, one iteration
netz upload streams=4:   141.78 MiB/s mean, 2.76% stddev, 5 iterations
netz download streams=4: 32 MiB/s, 34,579,902 bytes/s, one iteration
```

Transport-only context against the quicz real-handshake STREAM baselines:

| Scenario | historical quicz raw QUIC STREAM | netz HTTP/3 DATA |
|---|---:|---:|
| 64 MiB single-stream upload | 228.77 MB/s | 117.76 MiB/s mean (5 iters) |
| 64 MiB 4-stream aggregate upload | 244.85 MB/s | 141.78 MiB/s mean (5 iters) |

These are deliberately **not** presented as a throughput ratio:
`quic_bench_hs.zig` calls raw `sendOnStream`, while netz also performs HTTP/3
DATA framing, request/response processing, and QPACK/session work. The netz
samples are CPU-0 pinned; the historical quicz values were not. A fresh
CPU-0-pinned quicz run produced 15.97 MB/s single-stream and 16.12 MB/s
four-stream because pinning both same-process endpoints to one CPU changes the
scheduling shape dramatically. Netz's raw benchmark showed the same scheduling
sensitivity. No equal-wire, equal-CPU quicz HTTP/3 benchmark is currently
available. The quic-go benchmark above supplies a full-stack
same-application-shape reference, but neither it nor these raw transport
numbers are treated as equal-wire H3 superiority evidence.

The process harness also accepts `--stats`. As with the raw QUIC comparison,
GNU time's whole-process maximum RSS is the cross-language metric; netz's
explicit allocator and Go's `runtime.MemStats` remain separately labeled
runtime diagnostics rather than a shared allocation definition:

```sh
zig build bench-http3-quic-go -Doptimize=ReleaseFast -- \
  --warmup=1 --iterations=3 --body-bytes=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --stats
```

The complete upload/download, client/server-role matrix measured:

| Mode | Implementation workload | Process peak RSS (KiB) | Runtime allocation count | Runtime allocated bytes | Runtime peak/reserved bytes |
|---|---|---:|---:|---:|---:|
| upload | netz sender/client | 9,984 | 5,982 | 17,173,866 | peak live 6,490,848 |
| upload | quic-go receiver/server | 19,712 | 185,059 | 10,568,592 | ending HeapSys 12,189,696 |
| upload | quic-go sender/client | 22,528 | 74,921 | 15,565,816 | ending HeapSys 16,482,304 |
| upload | netz receiver/server | 7,936 | 454 | 5,849,150 | peak live 4,520,667 |
| download | netz receiver/client | 10,240 | 442 | 8,335,289 | peak live 7,014,161 |
| download | quic-go sender/server | 23,296 | 78,303 | 15,160,104 | ending HeapSys 16,416,768 |
| download | quic-go receiver/client | 19,968 | 185,369 | 10,890,568 | ending HeapSys 12,255,232 |
| download | netz sender/server | 9,772 | 4,698 | 13,823,909 | peak live 6,300,315 |

All eight process records cover one warmup plus three measured fresh
connections. The strict sample verifier independently requires exactly samples
1 through 3 with matching mode, role pair, 4,194,304 bytes, checksum
534,773,760, status 200, and completion. The memory verifier requires the
expected role/implementation/runtime scope, positive RSS and runtime counters,
and zero post-teardown live bytes for both netz processes in each mode. Default
benchmark runs neither instantiate the counting allocator nor call Go
`ReadMemStats` or GNU time.

Fresh 5-iteration netz single-stream sample:

```text
HTTP/3 real-handshake transfer benchmark
  mode: upload
  streams: 1
  iterations: 5
  body bytes/iteration: 67108864
  total body bytes: 335544320
  status total: 1000
  ns/iteration: 550419981
  bytes/s: 121923015
  MiB/s: 116
  mean MiB/s: 117.76
  stddev MiB/s: 12.25
  stddev percent: 10.40
```

A matching CPU-0-pinned five-iteration 64 MiB / four-stream run now completes:

```text
per-iteration MiB/s: 143.53, 140.85, 146.05, 134.70, 143.78
mean MiB/s: 141.78
stddev MiB/s: 3.91
stddev percent: 2.76
```

This result combines a 6000-byte adaptive DATA chunk for 64 MiB multi-stream
runs with an ACK-eliciting threshold of four. Thresholds 2, 4, 8, 16, and 32
produced 129.07, 137.06, 112.87, 110.17, and 85.87 MiB/s means respectively.
The shorter 16 MiB/four-stream shape retains 3000-byte packets and improved
from the previous 69.43 MiB/s sample to 129.36 MiB/s with threshold four.

The optional cross-stream body batch completed five 64 MiB iterations at
134.89 MiB/s mean and 2.38% stddev. It is not the default on this host because
the sequential path is slightly faster with the small kernel receive queue.
The API still provides exact protected-packet sizing, per-DATA prefix ownership,
and socket-visible-prefix commit semantics for hosts that can absorb bursts.

The first recovery-cache stage retained a bounded four-block stack per
power-of-two payload class, with a global 1 MiB idle-byte cap. ACK/forget paths recycle without
allocating, and retransmission candidates expose only the logical encoded
payload rather than bucket slack. A 10-pair alternating CPU-0 A/B against
commit `28e8698` was throughput-neutral:

```text
recovery cache: 139.285 MiB/s mean, 4.890 MiB/s stddev
baseline:       139.315 MiB/s mean, 3.194 MiB/s stddev
delta:          -0.02%
```

One 64 MiB/four-stream `--stats` pair showed:

```text
                         recovery cache    baseline
allocations:             168,178           183,819
cumulative allocated:    385,898,699 B     464,527,093 B
peak live:                83,950,631 B      94,586,109 B
```

That is 8.5% fewer allocation calls, 16.9% fewer cumulative allocated bytes,
and 11.2% lower peak live memory in the captured pair, without measurable
throughput loss.

The original four-block depth later became visible again after other hot-path
allocations were removed: a thread-safe `--stats` rerun found 392-673 exact
4096-byte allocations and 403-684 recovery-cache misses in three otherwise
identical 16 MiB/four-stream uploads. The near one-to-one counts came from
3000-byte STREAM payloads rounding to the 4-KiB cache class, then being released
in ACK bursts deeper than four. Recovery storage now keeps four direct slots
per class and links overflow blocks through their own inactive payload bytes.
This keeps acquire/release O(1) and allocation-free, adds only one head pointer
per size class, and retains the existing 1 MiB global cap instead of reserving
large fixed slot arrays per connection. Size-isolation, full-budget, overflow,
logical-prefix and deinit tests cover the new ownership scheme.

CPU sampling of the same workload showed the larger remaining cost in
`RecvState.Preflight.insertTracked`: ordered, non-overlapping STREAM frames
still scanned every payload byte to prove they were new. Preflight now checks
frame ranges first and counts an append beyond both retained and packet-local
state in O(frames); overlapping/reordered frames retain the original bytewise
conflict and duplicate accounting. A matched five-pair CPU-0 A/B, each process
running five 16 MiB/four-stream iterations, measured 114.11 MiB/s mean for the
cached old binary and 152.69 MiB/s after both changes, a 33.8% improvement
(median improvement 33.5%). All 25 iterations in each side verified the exact
80 MiB aggregate and status total. Thread-safe final telemetry made 839-900
allocations with 304-349 exact 4-KiB allocations, versus the pre-change median
1195 allocations and 603 exact 4-KiB allocations: reductions of 29.6% and
49.6%. Median cumulative allocated bytes fell from 31.27 MB to 24.38 MB
(22.0%), while median peak live bytes fell from 28.29 MB to 23.89 MB (15.5%).
These stats include one 16 MiB transfer body retained by the benchmark.

The next profile showed recovery ACK compaction spending about 12% of sampled
cycles rebuilding two hash indexes after every range ACK. Those indexes were
also maintained for every sent packet even though the hot ACK path already
walks the ordered recovery queue. Removing both maps keeps monotonic new-packet
validation O(1) through a cached maximum and uses bounded linear scans only for
single-packet rollback/acknowledgement and handshake-group queries. A five-pair
CPU-0 A/B of the same 16 MiB/four-stream workload measured 148.94 MiB/s mean
with indexes and 191.33 MiB/s without them, a 28.5% improvement (27.5% at the
median). Three serial 5%-loss runs remained within noise at 2.86-2.90 MiB/s,
dropped exactly 25 of 504 datagrams, reported 25 transport losses, and verified
all 4 MiB. Three `--stats` runs made 746-894 allocations (825 median) and
280-341 exact 4-KiB allocations (284 median). Recovery-burst variance made
cumulative and peak byte totals overlap the indexed samples, so no memory-byte
claim is made for this second step. Ordered removal, ACK compaction,
original/retransmission lookup and
allocation-failure tests now assert behavior rather than internal map layout.

The following current-source profile found the read-only loss-timer selector
spending 13.5% of samples repeatedly scanning sent-packet metadata to find the
latest ordinary ACK-eliciting PTO anchor. The tracker already cached the latest
ACK-eliciting in-flight packet for generic PTO calculation, so the non-PMTU
query now returns that entry directly when it is an ordinary packet and keeps
the full scan only when a PMTU probe owns the cache or directly mutated test
metadata violates the production invariant. In five alternating CPU-0 pairs of
five 16 MiB/four-stream uploads, the exact pre-change binary averaged 181.29
MiB/s (182.04 median) and the fast-path binary averaged 194.97 MiB/s (195.57
median), improvements of 7.5% and 7.4%. Every side transferred 80 MiB and
reported status total 4000. A post-change profile reduced
`lossDetectionTimerDeadline` self samples from 13.5% to 2.0%. A 5%-loss run
dropped exactly 25/504 datagrams, reported 25 transport losses, and verified
all 4 MiB at 2.92 MiB/s. This step adds no allocation; telemetry retained the
existing ACK-burst variance, so no memory improvement is claimed.

That post-change profile also attributed 2.7% of samples to
`hasAcknowledgedEctBeyondEcnWatermark`, which rescanned retained packet metadata
after each ACK. The tracker now records the highest packet number ever
acknowledged with ECT(0), ECT(1), or CE and compares it directly with the
largest ACK covered by validated ECN counters. Besides making the query O(1),
the monotonic watermark remains correct after acknowledged packet metadata is
compacted; a dedicated regression crosses the 256-packet compaction threshold,
then consumes the outstanding ACK_ECN baseline. Five alternating CPU-0 pairs
against the exact PTO-fast-path binary measured 179.69 MiB/s mean (182.60
median) before and 198.49 MiB/s mean (207.70 median) after, captured gains of
10.5% and 13.7%. All 25 iterations on each side transferred exactly 80 MiB and
reported status total 4000. The target scan disappeared from a normally
completed post-change profile. A 5%-loss run still dropped exactly 25/504
datagrams, reported 25 transport losses, and verified all 4 MiB. This state is
allocation-free and no memory reduction is claimed.

The packet-level validate-before-mutate pass and the later ACK application used
to run `precheckAckRanges` twice over the same single-ACK packet. The preflight
now returns a shape-bound validation token carrying its private summary; the
apply path verifies the ACK fields, range-slice identity, and path epoch before
reusing it. Multi-frame packets retain the original independent validation so
no earlier frame can commit before a later malformed ACK is rejected. Five
alternating CPU-0 pairs against the exact pre-change binary measured 198.23
MiB/s mean (195.98 median) before and 205.85 MiB/s mean (202.65 median) after
across two clean, order-balanced sets of ten one-iteration pairs, gains of 3.4%
for both mean and median. Every run transferred 16 MiB and reported status
total 800. `precheckAckRanges` fell from 5.35% to 1.67% of sampled cycles; a
5%-loss run dropped exactly 25/504 datagrams, reported 25 transport losses, and
verified all 4 MiB at 2.86 MiB/s.

The remaining sent-packet exact index is deliberately best-effort because every
lookup already falls back to binary search on the production-ordered metadata
array. Prefix compaction previously removed every retired key and then rewrote
every surviving map value. It now clears the map in O(1), retaining its
allocation for later inserts while old retained packets use binary search. Two
clean order-balanced sets of twenty one-iteration pairs measured 184.40 MiB/s
mean for the retained repair path and 197.94 MiB/s after clear-on-compaction
(+7.3%); medians were approximately 193.7 and 198.7 MiB/s (+2.6%). The
`refreshPacketIndexFrom` symbol disappeared from the follow-up profile. A
5%-loss run dropped exactly 25/504 datagrams, reported 25 transport losses, and
verified all 4 MiB at 2.90 MiB/s.

Recovery ACK compaction then stopped copying every `PendingDatagram` into a
loop temporary and copying ACKed entries again before recycling. It now scans
entries by pointer, recycles matches in place, and copies only survivors that
actually move toward the queue head. A clean order-balanced set of twenty
one-iteration pairs measured 212.30 MiB/s mean for the prior build and 230.49
MiB/s for the pointer-based compaction (+8.6%); medians were 202.05 and 231.06
MiB/s (+14.4%). The follow-up profile reduced ACK-apply self samples to 2.73%
and left no standalone recovery-entry copy hotspot. A 5%-loss run dropped
exactly 25/504 datagrams, reported 25 transport losses, and verified all 4 MiB
at 2.90 MiB/s.

The clean recovery queue now also records whether original packet numbers stay
monotonic. When no retransmission copies exist, a single continuous ACK range
uses two binary searches to locate the affected queue slice, recycles only that
slice, and moves the trailing survivors once. Multi-range ACKs, retransmission
groups, forgotten originals, and synthetic out-of-order insertion retain the
existing per-entry membership scan. Two order-balanced sets totaling forty
one-iteration process pairs completed 40/40 on both sides. The fixed prior
binary averaged 222.69 MiB/s and the candidate averaged 231.80 MiB/s (+4.1%);
the median within-pair ratio improved 2.2% (mean ratio +7.1%). The host showed
distinct roughly 200 and 260 MiB/s scheduling modes, so the independently
sorted median delta is intentionally not used as evidence. In the follow-up
profile, recovery `entryAcked`/`containsRange` membership fell from about 2.5%
inclusive to 0.51%, while the selected-slice retirement/move accounted for
about 1.32%. Three direct 5%-loss runs each dropped exactly 25/504 datagrams,
reported 25 transport losses, and verified all 4 MiB.

The same ordered, no-retransmission invariant now accelerates fragmented ACKs.
After validating the complete descending ACK chain transactionally, recovery
walks the ascending pending queue and the ACK ranges once from lowest to
highest instead of testing every packet against every range. Out-of-order
originals, forgotten originals, and groups with retransmission copies keep the
general membership scan. A fixed-binary, CPU-0, seven-pair run of
`bench-quic-ack-ranges` reduced the 128-packet/64-range recovery cycle from
12,990-13,122 ns (13,050 median) to 4,837-4,982 ns (4,854 median), a 62.8%
median reduction or 2.69x throughput improvement, with the candidate faster in
7/7 pairs. Direct tests compare irregular-width/gap output and 64 generated
sparse/dense ACK patterns against queues forced through the conservative path;
a separate multi-range case proves retransmission copies still use that
fallback. Existing tests retain allocation-free large-range, out-of-order, and
transactional invalid-ACK coverage.

Single-packet send preparation formerly walked the same frame slice separately
for wire length, retransmittable length, ACK-eliciting/in-flight traits, pending
HANDSHAKE_DONE detection, and the largest ACK carried. Those pure observations
now share the existing wire-length pass; validation and flow-control mutation
retain their original order. A clean order-balanced set of twenty one-iteration
pairs measured 212.86 MiB/s mean before and 235.37 MiB/s after (+10.6%); all
runs transferred exactly 16 MiB with status total 800. `Frame.wireLen` no longer
appeared as a standalone top profile entry. A 5%-loss run still dropped exactly
25/504 datagrams, reported 25 transport losses, and verified all 4 MiB.

The benchmark's former local counter used plain integers across client/server
threads and could undercount racing allocator calls. It now reuses the shared
atomic counting allocator, reports exact sizes and recovery-cache hit/miss
totals, and is the authoritative source for the numbers above.

The connection loss timer now follows Quinn, quiche, and tquic by retaining
the next RFC 9002 time-threshold loss deadline when ACK/loss state changes,
rather than rescanning all retained sent-packet metadata every time an endpoint
mirrors the connection timer. PMTU probe transitions, path resets, RTT updates,
explicit acknowledgements, and both packet- and time-threshold loss paths
refresh the cached value. A fixed-binary, CPU-0, seven-pair microbenchmark with
256 sent records, 255 acknowledged records, and one in-range loss candidate
reduced the complete
`Connection.lossDetectionTimerDeadline` query from 125.12-126.58 ns (125.93
median) to 3.08-3.11 ns (3.09 median), about 40.8x, with 7/7 wins.

Five order-interleaved 16-connection, 16-MiB-total shared-server pairs against
parent `bae40ca3` completed exactly in both sender directions. Client-sender
throughput was 56.412-69.628 MiB/s (62.744 median) before and 56.649-62.927
MiB/s (60.822 median) after, with 2/5 candidate wins. Server-sender throughput
was 73.391-93.500 MiB/s (80.275 median) before and 77.666-115.835 MiB/s
(82.260 median) after, with 4/5 candidate wins and a 2.5% median increase. Both raw
ranges overlap, so the server-sender result is supporting evidence rather than
a general throughput claim; the isolated timer-query reduction is the strong
performance result. Every arm verified 16,777,216 bytes, checksum 2,139,095,040,
all 16 connections, and the completion exchange.

The same fixed parent/candidate HTTP/3 binaries were then run in five
order-interleaved pairs, each arm performing three real-handshake, four-stream,
16-MiB uploads. Parent throughput was 125.96-134.84 MiB/s (130.87 median),
while the cached-loss-time path measured 133.60-138.15 MiB/s (134.64 median),
a 2.9% median increase with 5/5 candidate wins. Every arm verified 48 MiB and
status total 2,400. This is same-host HTTP/3 regression evidence; it does not
replace the equal-wire cross-stack gap.

Two narrower alternatives were measured and removed. Merely starting the
read-time sent-packet scan at the first unacknowledged index made the isolated
query cheap, but a longer 16-connection, 64-MiB-per-arm shared run favored it
in only 1/5 client-sender and 2/5 server-sender pairs; client-sender median
fell from 41.898 to 32.231 MiB/s. Separately skipping endpoint-timer refresh
after an empty socket-free stream poll lost all 5/5 client-sender pairs and
moved its median from 65.424 to 55.055 MiB/s. Both experiments were fully
removed; the retained implementation instead moves loss-time discovery into
the existing ACK/loss pass, matching the recovery structure of the audited
implementations.

A subsequent recovery-payload ownership experiment grouped sustained 4-KiB
blocks into 64-KiB chunks. One captured ordinary-cache run made 2,101
allocation calls, including 1,761 exact 4-KiB allocations, with 3,871 cache
hits, 1,775 misses, 266 idle blocks, and 1,045,025 idle bytes. The dynamic
grouped candidate reduced the corresponding capture to 462 allocation calls,
67 calls of at most 4 KiB, and 110 64-KiB calls; it recorded 5,515 cache hits,
131 misses, 262 idle blocks, and 1,048,849 idle bytes. Peak explicit live bytes
were effectively unchanged at 24,756,635 before and 24,784,283 after.

That allocation-count reduction did not survive the fixed-binary HTTP/3 gate.
In five order-interleaved pairs of three 16-MiB/four-stream uploads per arm, a
fixed-capacity grouped version won 1/5 pairs and moved the median from 144.22
to 140.73 MiB/s (-2.4%); its parent/candidate ranges were 129.63-160.21 and
134.38-146.51 MiB/s. A dynamic-group version won 2/5 pairs and moved the
median from 145.83 to 143.97 MiB/s (-1.3%); its parent/candidate ranges were
119.76-149.09 and 140.57-146.80 MiB/s. Both grouped implementations were fully
removed. The benchmark retains only opt-in cache block/byte telemetry so later
work can distinguish a cache near its one-MiB idle limit from a first-activity
high-water mark; no allocator or throughput improvement is claimed.

Receive preflight no longer clones the heap-backed path-validation state for
every authenticated packet, and its distinct-stream shadow starts in fixed
packet-local storage. A same-command 16 MiB/four-stream upload A/B against
commit `1757907` reduced allocation calls from 34,980 to 29,223-29,300
(16.2-16.5%), while cumulative allocated bytes fell from 102,829,311 to
100,431,864-100,595,813 (2.2-2.3%). The three post-change samples measured
270.48-274.31 MiB/s versus the captured 191.95 MiB/s baseline sample; the
allocation delta is the stable conclusion, while the large single-run
throughput swing should be treated as promising rather than a final ratio.
Failing-allocator and duplicate-PATH_RESPONSE tests cover the new no-path
fast path and packet-local transactional response tracking.

The synchronous non-GRO visitor/service pump now receives UDP directly into a
connection-owned buffer instead of allocating and shrinking one endpoint
buffer per packet. Against the post-preflight baseline above, the same 16
MiB/four-stream `--stats` shape dropped again from 29,223-29,300 allocation
calls to 15,210-15,268 (47.8-48.1%), and from 100.4-100.6 MB cumulative
allocation to 25.8-27.1 MB (73.1-74.3%). Three runs measured 175.15-281.39
MiB/s; like the previous single-run spread this supports a no-regression smoke,
not a stable throughput ratio. Caller-buffer endpoint and two-packet
connection-reuse tests verify borrowed lifetime and storage reuse; GRO remains
on its owning batch API because one kernel receive may outlive a single packet
callback.

The next receive-preflight step shares one packet-local STREAM-frame shadow
across every distinct stream instead of allocating an ArrayList for the first
frame on each stream. The same 16 MiB/four-stream shape fell from
15,210-15,268 to 9,519-9,585 allocation calls (37.2-37.4%); cumulative
allocation fell from 25.8-27.1 MB to 24.4-25.6 MB. Three smoke runs measured
237.49-275.42 MiB/s. Caller-storage, cross-stream overlap, and heap-spill tests
cover both the common fixed-capacity path and packets exceeding it.
The benchmark allocator now also reports the most frequent exact allocation
sizes, which identified the remaining 144-byte hot bucket as short-lived
runtime work rather than retained body ownership. ClientHello ALPN parsing was
one confirmed contributor and now stores up to 16 offered protocol views inline
without an auxiliary allocation; parser tests cover multi-ALPN round trips and
allocation-free teardown. The 16 MiB/four-stream smoke remained at 275.41
MiB/s with 9,551 allocations, while cumulative allocation fell from the prior
24.4-25.6 MB range to 24,085,274 bytes in the captured run.

Stack sampling then identified the dominant steady-state 144-byte allocation
at `sendWithEcnAtRaw`: every STREAM packet built a temporary rollback-credit
ArrayList even though ordinary packets touch one stream. That journal now uses
16 fixed entries and spills only unusually wide packets. Against the prior
9,519-9,585 range, three identical 16 MiB/four-stream runs used only
2,525-2,532 allocations (73.4-73.6% fewer) while sustaining 241.94-272.26
MiB/s. A failing-allocator STREAM send test proves warmed recovery/sent storage
no longer hides a rollback-journal allocation.

The next exact-size sample traced 160-byte churn to ACK range decoding in the
in-place visitor path. `parseFrameInto` now decodes ACK pairs into retained
connection storage, so ACK processing no longer allocates/free a range slice
for every feedback packet. Two stable 16 MiB/four-stream samples used only
1,162-1,189 allocations versus 2,525-2,532 before (53.0-54.0% fewer), with
214.45-225.55 MiB/s. One noisy run exercised substantially more recovery and
is excluded from the stable allocation range rather than being hidden. Caller
storage and insufficient-range tests cover the new parser contract.

Timer-aware HTTP/3 GRO validation used the same 64 MiB/four-stream shape:

```text
upload, five iterations:
  samples: 117.83, 122.24, 103.24, 123.80, 121.55 MiB/s
  mean: 117.73 MiB/s, stddev: 6.38%

download, three iterations:
  samples: 87.01, 84.43, 106.60 MiB/s
  mean: 92.68 MiB/s, stddev: 10.68%
```

Both directions completed every iteration. The transport test additionally
drops the original STREAM packet and proves that a GRO batch receive fires PTO,
sends packet-number 1 as a recovery probe, and returns the response afterward.
GRO therefore no longer suppresses recovery timers; it remains disabled by
default solely because it is slower on this host.

The earlier run completed iteration 0 at 33.92 MiB/s and then timed out. A
single traced 16 MiB run showed all four client send loops complete while the
server stopped at roughly 9.4 MiB. ACK processing had already classified old
packets as packet-threshold losses and removed their congestion accounting, but
the HTTP/3 receive pump did not drain those recovery candidates. The corrected
blocking QUIC pump immediately retransmits a bounded set after each received
ACK, stopping transactionally at congestion or pacing limits. PTO remains the
fallback rather than the primary repair mechanism.

The current evidence shows netz is **reliable and substantially faster than its
previous H3 baseline**, but does not establish superiority over quicz HTTP/3
because an equal-wire reference is missing. Raising the
single-stream 1-RTT datagram budget to 8192 bytes, disabling HyStart for the
low-RTT single-stream benchmark, and using a 7200-byte paced DATA chunk closes
much of the previous 3 MiB/s cliff, but quicz still leads on
64 MiB four-stream aggregate throughput. Releasing all active streaming response
reader capacity before each multi-response packet receive stabilizes the 64 MiB
four-stream download case, but quicz still leads substantially. The next
optimization target is reducing per-packet recovery ownership and STREAM/DATA
framing overhead, then retesting batching on a host with a larger UDP receive
queue. A completion audit cannot pass
until this gap is closed with measured same-host evidence.
All netz numbers in the tables above predate the zio migration and remain
historical `std.Io.Threaded` baselines. They must not be cited as current zio
performance; a fresh fixed-binary, CPU-pinned, odd-sample run is required.

A fresh zio-era process run on 2026-10-15 now supplies a bounded current
baseline for the four-stream QUIC v1 shape. The Jetson `aarch64` host ran Linux
`6.8.12-1021-rt-tegra`, Zig 0.16.0, Go 1.27.2, and pinned client/server
processes to CPUs 0/1. Each role pair completed two warmups and five measured
fresh certificate-verified connections, with four 1-MiB streams, 16-KiB
requested application chunks (1,152-byte effective chunks), 1-MiB stream
windows, disabled netz GSO/GRO, exact 4,194,304-byte/checksum verification, and
independent server-completion records:

| Sender / fixed peer | Median MiB/s | Range MiB/s |
|---|---:|---:|
| netz client / quic-go server, upload | 145.737 | 139.266-166.578 |
| quic-go client / netz server, upload | 148.170 | 148.030-149.207 |
| quic-go server / netz client, download | 65.760 | 55.852-73.717 |
| netz server / quic-go client, download | 162.458 | 152.796-167.907 |

The result records attribute `implementation` to the sender. Consequently the
lower download row measures quic-go's server send path, not netz's client
receive path; a candidate that drained each retained UDP batch before the
aggregate HTTP/3 ready-stream scan left that row unchanged (64.584 to 64.805
MiB/s in matched one-sample smokes) and was removed. The client-upload medians
are effectively tied within the wide netz range, while the netz server sender
is 2.47x the quic-go server median in this same-application-shape capture.
Because the four role pairs ran sequentially rather than in an odd ABBA
fixed-peer schedule and their wire shapes remain unequal, this is current
directional evidence and a corrected attribution baseline, not a general
cross-stack superiority claim.

### Allocation / peak-live evidence

`bench-http3-handshake-transfer` supports `--stats`, which wraps the benchmark's
allocator and reports allocation counts, remaps, total allocated/freed bytes,
live bytes, and peak live bytes. This is intended to make transfer-path memory
work visible before further optimization.

```sh
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1 --stats
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=upload --streams=1 --stats
```

Historical stats samples below predate the thread-safe shared counter and may
undercount racing client/server allocations. They remain only as provenance;
the post-fix 16 MiB/four-stream evidence above is authoritative.

```text
16 MiB upload streams=1:
  alloc count: 89254
  remap count: 4697
  total allocated bytes: 248079087
  peak live bytes: 18022064
  allocation buckets:
    <=64: count=28812, bytes=486182
    <=256: count=17747, bytes=2288067
    <=1K: count=8280, bytes=4490099
    <=4K: count=9889, bytes=23322296
    <=16K: count=24798, bytes=200343435
    <=64K: count=8, bytes=217296
    >64K: count=3, bytes=16916528

64 MiB upload streams=1:
  alloc count: 359369
  remap count: 18527
  total allocated bytes: 994566095
  peak live bytes: 69991771
  allocation buckets:
    <=64: count=116957, bytes=1987374
    <=256: count=71353, bytes=9181107
    <=1K: count=32856, bytes=17816435
    <=4K: count=39073, bytes=92460728
    <=16K: count=99583, bytes=804544983
    <=64K: count=8, bytes=217296
    >64K: count=7, bytes=68083856
```

The single-stream DATA prefix fast path is enabled only for `streams=1`, where
its payload lifetime is simple. Together with outbound body frame-scratch reuse,
it reduces the 64 MiB single-stream upload cumulative allocation from about
1.29 GiB to about 995 MiB. The `<=16K` bucket still dominates with about 99k
allocations and 805 MiB of traffic, so future multi-stream payload-buffer work
still needs explicit per-send or per-stream lifetime isolation.

Rejected experiments after validation:

- Changing the aggregate timer-query chain from by-value to read-only pointer
  receivers removed the large copies visible in generated code:
  `nextTimerDeadline`'s stack frame fell from about 23 KiB to 152 bytes and
  total `memcpy` self samples fell from 5.69% to 1.25%. End-to-end behavior did
  not follow that micro-level improvement. In a strict serial, order-balanced
  20-pair run the baseline completed 20/20 processes while the candidate
  completed 19/20; across the 19 completed pairs mean throughput fell from
  231.57 to 213.79 MiB/s (-7.7%) and median throughput fell from 259.05 to
  208.44 MiB/s (-19.5%). A narrower follow-up kept every public receiver ABI
  unchanged and used pointer helpers only inside the blocking timer pump. It
  improved the 19 completed pairs by 2.9% mean/3.9% median, but still timed out
  in 1/20 candidate processes while the baseline completed 20/20. Both
  receiver variants were removed.
- A narrower ACK experiment preserved the by-value `ValidatedAck` token but
  added a pointer-based `SentPacketTracker` validation wrapper for the packet
  preflight. It removed one tracker materialization and reduced the generated
  validation stack frame, but did not show a stable end-to-end improvement
  under concurrent host load. The wrapper was removed and no quantitative
  claim is retained.
- Combining PATH_CHALLENGE/PATH_RESPONSE counting in the general receive
  preflight and carrying the challenge count into apply removed two frame-slice
  scans, but did not show a stable end-to-end improvement under concurrent host
  load. The count plumbing was removed and no quantitative claim is retained.
- Splitting the large general receive preflight into a no-inline slow path let
  single-ACK packets avoid its CID/PATH/STREAM stack storage and reduced the
  hot apply function's generated stack frame from about 7.9 KiB to 3.4 KiB.
  Opposite-order CPU-1 sets under concurrent host load did not agree, so the
  unstable split was removed and no quantitative claim is retained.
- Preparing the received-packet ACK-range insertion before frame validation and
  committing that exact action afterward removed the second freshness lookup
  while preserving validate-before-mutate semantics. Direct equivalence tests
  covered append, extension, merge, insertion, bounded eviction, duplicate,
  too-old, and ECN cases. End-to-end runs under concurrent host load were
  neutral while `applyReceivedFramesForDestination` self samples increased, so
  the token and tests were removed and no quantitative claim is retained.
- Replacing the STREAM gap-fill tail loop with a standard-library scalar slice
  search stopped updating `contiguous_end` for every present byte, but two
  opposite-order CPU-1 sets under concurrent host load did not agree. The
  original compact loop was restored and no quantitative claim is retained.
- A follow-up explicitly scanned sixteen byte-bitmap flags at a time; generated
  code used 128-bit loads and tests covered sparse tails, overlap, and
  transactional receive. It still timed out in one candidate process while the
  baseline completed every run, and its completed-pair median ratio was
  slightly negative. The vector scan was removed.
- Letting ACK-driven time-threshold loss skip the ordered prefix that the
  immediately preceding packet-threshold pass had already marked reduced the
  time-threshold function below the profile reporting cutoff while preserving
  the two existing loss generations and callback order. The candidate timed
  out in one of twenty reverse-order runs while the baseline completed all
  runs, so the hint and its equivalence test were removed.
- Hoisting a single recovery ACK range's fixed bounds out of the per-entry
  retransmission fallback preserved exact 5% loss behavior across forty runs
  per side, but the two opposite-order sets were neutral and disagreed in
  mean/median direction. The duplicate compaction helper was removed.
- Directly constructing the first ACK range for frames with no additional
  ranges, while isolating the 32-range decode scratch in no-inline slow helpers,
  reduced the common validation stack frame from about 1080 to 664 bytes. Two
  opposite-order CPU-1 sets completed 40/40 processes per side, but their
  median within-pair changes were -0.37% and +0.30%; the apparent aggregate
  mean gain followed the host's bimodal scheduling rather than a stable pair
  improvement. The split decode path was removed.
- Passing the validated-ACK summary by pointer instead of by-value optional
  preserved all focused tests but regressed a clean order-balanced 20-pair run
  from 202.26 to 200.48 MiB/s mean (median -1.2%). The pointer ABI was removed.
- Moving largest-ACK watermark updates to the range level and passing known
  packet indices into `markPacketAcknowledged` removed redundant per-packet
  comparisons, but a clean order-balanced 20-pair run regressed from 211.65 to
  208.91 MiB/s mean (median -2.0%). The change was removed.
- A single-STREAM-packet preflight specialization used one-entry stack shadows
  and skipped the general CID/path setup while preserving full STREAM, final
  size, flow-control, and duplicate validation. A clean order-balanced 20-pair
  run was neutral at 205.41 versus 206.12 MiB/s mean, with an unchanged median
  (200.27 versus 200.18 MiB/s), so the duplicate path was removed.
- Lazily copying the peer/local connection-ID preflight pools only when a
  NEW_CONNECTION_ID or RETIRE_CONNECTION_ID frame appeared passed CID, STREAM,
  and transactional preflight tests, but a clean order-balanced 20-pair run was
  effectively neutral: 195.98 versus 197.45 MiB/s mean, while the median moved
  from 198.70 to 197.23 MiB/s. The branchy optional shadows were removed.
- Extending the validated-ACK token with a cached
  `newly_acked_ack_eliciting` decision removed the RTT helper's range scan, but
  a clean order-balanced 20-pair run was neutral at 196.72 versus 196.58 MiB/s
  and the candidate timed out once while the baseline did not. The extension
  was removed.
- Treating only the dense STREAM prefix as implicitly present, while retaining
  byte flags for sparse tails, passed receive/preflight tests but regressed a
  clean order-balanced 20-pair run from 200.02 to 192.23 MiB/s mean (-3.9%);
  the median moved from 200.37 to 198.56 MiB/s. The fast path was removed.
- Extending the single-ACK validation token to replace the separate plain-ACK
  ECN fallback precheck passed focused tests but regressed a clean,
  order-balanced 20-pair run from 202.38 to 199.37 MiB/s mean (median -1.7%).
  The extension was removed while retaining token reuse for ACK application.
- Packing the STREAM receive-presence bitmap from one byte per stream byte to
  one bit preserved cross-word gap filling, compaction, overlap, preflight and
  sliding-window tests, but a clean order-balanced ten-pair run regressed from
  210.44 to 183.60 MiB/s mean and 209.38 to 182.21 MiB/s median. The packed
  representation was removed; linear byte flags remain faster on this CPU.
- Removing `SentPacketTracker`'s best-effort exact hash index passed focused
  lookup, rollback, and allocation tests and reduced first server 1-RTT-send
  allocations from four to three. In a clean process-level-timeout comparison,
  however, the indexed baseline completed all five runs while the no-index
  candidate timed out in two of five. The prototype was removed; throughput
  samples captured while earlier timed-out benchmark processes were still live
  are intentionally not reported.
- Splitting ACK coverage validation into a count-only preflight avoided reading
  ECN and acknowledgement fields during the packet-level transactional pass,
  but five alternating 16 MiB/four-stream samples averaged 201.85 MiB/s for
  the retained shared precheck and 197.56 MiB/s for the specialized version
  (-2.1%; median -3.9%). The duplicate helper was removed.
- An earlier attempt to widen `AckResult` with the plain-ACK ECN decision also
  passed focused tests but showed no stable throughput improvement. It was
  removed; its measurements overlapped later-discovered stray benchmark
  processes and are not retained as quantitative evidence.
- Treating an empty STREAM receive bitmap as an implicitly contiguous retained
  buffer removed the per-chunk boolean `memset` from ordered traffic and
  materialized the bitmap only after a gap. It passed receive, overlap,
  preflight, and sliding-window tests, but five alternating 16 MiB/four-stream
  samples fell from 196.47 to 178.38 MiB/s mean (-9.2%). The representation
  change and its tests were removed at that point. The receive pipeline has
  since moved from byte flags to packed words, added word-level gap scans and
  range prechecks, and gained zio receive batching. Re-evaluating the same
  representation on this newer baseline is recorded below; the older negative
  result remains here because it must not be generalized to the new pipeline.
- Keeping the packed bitmap but replacing its per-byte checks with one slice
  comparison for the already-contiguous portion of a partially overlapping
  STREAM frame also passed focused and QUIC-wide tests. Seven CPU-0,
  order-alternated fixed-binary pairs of the five-iteration 16 MiB/four-stream
  H3 upload moved median latency from 81.389 to 81.962 ms/iteration (+0.7%);
  the candidate was faster in only 1/7 pairs and had two pronounced high-tail
  samples. The fast path and its dedicated test were removed.
- Passing the single-STREAM preflight result into frame application removed a
  second overlap-validation scan while retaining fallible buffer/bitmap commit.
  Focused conflict and transactional tests plus the full QUIC suite passed, and
  profiling split the old `insertTracked` symbol into validation and commit.
  The real H3 result was nevertheless neutral: seven CPU-0 order-alternated
  pairs averaged 105.931 ms/iteration for baseline and 105.982 ms for the
  candidate (+0.05%); the paired-ratio median was +0.21% latency and the
  candidate won only 3/7 pairs. The token and commit split were removed.
- Starting the read-only time-threshold deadline scan at the existing
  `first_unacknowledged_index` cursor was correct for sorted production packet
  metadata and retained the full-scan fallback for synthetic out-of-order
  insertion, but did not show a stable end-to-end improvement. The change and
  its tests were removed; contaminated measurements from before stray benchmark
  processes were discovered are intentionally omitted.
- Replacing ACK-time recovery-index rebuilding with either a lazy queue-head
  cursor or targeted updates for moved entries preserved all recovery tests but
  regressed the same 16 MiB/four-stream benchmark. Five alternating process
  pairs measured 151.41 MiB/s for the retained full rebuild versus 147.93
  MiB/s for targeted updates; the cursor variant was similarly slower and more
  variable. Both experiments were removed.
- Reusing a single shared DATA payload scratch buffer, per-stream payload
  scratch, and pre-sizing each temporary DATA payload all reduced single-stream
  allocation counts, but they caused 64 MiB 4-stream validation timeouts or
  `StreamBufferTooLarge` failures.
- Enabling the DATA prefix fast path for multi-stream upload regressed 64 MiB
  4-stream throughput, so it remains single-stream-only.
- Replacing paced multi-stream upload with a naive event-loop style
  `sendRequestBody` loop triggered `DatagramTooLarge`; multi-stream batching
  needs packet-size-aware grouping rather than bypassing the paced chunker.
- A first batch-body prototype grouped chunks by STREAM-frame count and hit
  `DatagramTooLarge`. The current API instead queries exact protected packet
  length at each packet-number offset, isolates DATA-prefix storage, and
  commits only the socket-visible QUIC batch prefix.
- Replacing the generic `sendConnectionFrames` splitter with conservative
  `wireLen()`-based grouping avoided `DatagramTooLarge` but caused 64 MiB
  4-stream download timeouts; packet-size-aware batching needs to be scoped to
  the new batch-body API rather than changing all HTTP/3 frame sends.
- Multi-stream `--paced-body-chunk-bytes` scans before the ACK-driven recovery
  fix incorrectly made larger chunks look unstable. The benchmark now retains
  3000 bytes below 64 MiB and uses 6000 bytes for the quicz-shaped 64 MiB
  aggregate; 12/14/16 KiB datagram experiments were slower or much noisier.
- Multi-stream `--round-robin-chunk-bytes` scans did not find a better stable
  default either: 16 KiB timed out on upload and hit `StreamBufferTooLarge` on
  download; 32 KiB improved download to ~40 MiB/s but still timed out on upload.

Future multi-stream payload-buffer work needs per-send or per-stream lifetime
isolation, not one shared mutable buffer or a change that increases the
multi-stream send/receive critical section.

#### HTTP/1 request-head parse fast paths (2026-11-08)

Four request-head hot spots were removed. `Method.parse` now dispatches on the
method length and first byte before comparing registered method names, instead
of testing up to ten full slices for every start line. The strict request-line
parser locates its two SP delimiters with the SIMD scalar search instead of
walking the target byte by byte. A shared `LineIterator`
replaces `std.mem.splitSequence` for head and trailer lines: it finds the first
CR with the SIMD single-byte search and checks the next byte for LF, preserving
exact split-on-CRLF semantics without the generic two-byte substring search.
The head terminator search uses the same CR-first strategy instead of the
generic four-byte substring search at the request, response and owned-head
entry points.

Eight CPU-0 alternating fixed-binary pairs of `bench-http1-parse` at 50,000
iterations and five samples per arm measured the combined change:

| Scenario | Before ns/op | After ns/op | Speedup |
| --- | ---: | ---: | ---: |
| borrowed | 210.5 | 184.0 | 1.144x |
| owned | 532.5 | 254.0 | 2.096x |
| owned + Host | 555.0 | 279.0 | 1.989x |

Isolated pairs measured method dispatch at 1.022x borrowed, the head-end scan
at a further 1.057x borrowed, and the line iterator at 1.049x borrowed and
2.043x owned. The strict request-line fast path was neutral on the short
origin-form target (1.008x borrowed, 1.000x owned) and improved the longer
absolute-form target by 1.2-2.8%. A byte-at-a-time CR scan was measured and
rejected at 0.938-0.953x. One earlier head-end batch ran under heavy unrelated
host load and was discarded; the reported pairs were repeated on a quieter
host. The HTTP/1 suite passed 577/577, `fuzz-parsers`/`fuzz-stateful` replayed
4/4, `interop-http-external-clients` passed against curl/nghttp2, and the
complete library suite passed 6771/6771. Evidence is in
[the HTTP/1 parse evidence](../evidence/http1/2026-11-08-parse-fast-path.json).

