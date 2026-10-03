# netz vs `~/Work/hyper` HTTP/1, HTTP/2 and HTTP/3 audit

This audit tracks direct same-host evidence for the HTTP/1 and HTTP/2 portion
of the netz improvement goal. Hyper's benchmark definitions are used where
possible instead of comparing unrelated codec microbenchmarks.

## HTTP/1 16-request pipeline

The current netz HTTP/1 parser, pipeline, and streaming-body benchmarks obtain
`std.Io` from zio and identify `zio-std-io` in their output. The two networked
benchmarks use `std.Io.async` for the local server; allocator telemetry does not
include the independently allocated zio runtime. The checked-in
`bench-http1-hyper` gate builds the Cargo.lock-pinned Hyper fixtures once, runs
fixed ReleaseFast binaries in an odd CPU-pinned ABBA-order sample set, and
rejects incomplete workload, timing arithmetic, runtime identity, revision, or
binary/lock hash evidence.

On 2026-09-15, five CPU-0 samples on an NVIDIA Jetson AGX Thor (`aarch64`,
Linux 6.8.12-1021-tegra) measured the zio-backed 16-request netz pipeline at
749-799 ns/request (761 ns median) and the Hyper server with its upstream
sync client at 842-854 ns/request (851 ns median), a 1.118x median advantage.
The same gate measured 1-MiB bidirectional bodies as follows:

```text
fixed:   netz 722.152-747.392 us (740.191 median)
         Hyper 768.572-783.444 us (779.315 median), netz 1.053x
chunked: netz 724.570-754.458 us (748.436 median)
         Hyper 951.686-967.723 us (953.148 median), netz 1.274x
```

These are named same-application-shape loopback workloads rather than a claim
that netz is universally faster. The older x86 measurements below used the
former `std.Io.Threaded` harness and remain historical evidence.

Hyper's `benches/pipeline.rs::hello_world_16` sends sixteen identical
bodyless requests on one TCP connection and enables `pipeline_flush(true)` for
sixteen `"Hello, World!"` responses. Hyper automatically adds a 29-byte Date
value. Netz now generates the same current IMF-fixdate through its ordinary
server path, so the benchmark no longer injects a fixed field and still sends
the same 89 response bytes per request. Netz performs 200 untimed warmup batches before
its 2,000 measured batches, matching the calibration intent of Rust's Bencher.

Equivalent netz command:

```sh
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
```

To remove this host's P-core/E-core scheduler variance, both compiled binaries
were pinned to CPU 0. The reference checkout was Hyper revision
`084473f728f9d07b3be5845475aa2f62ed9ff579`, built with
`rustc 1.98.0-nightly (e7815e522 2026-06-04)` and run with:

```sh
cd ~/Work/hyper
cargo bench --bench pipeline hello_world_16 --features full
HYPER_BENCH=$(
  find target/release/deps -maxdepth 1 -type f \
    -name 'pipeline-*' -executable -print -quit
)
taskset -c 0 "$HYPER_BENCH" --bench hello_world_16
```

2026-08-17 ranges, each from five pinned process runs:

```text
hyper hello_world_16:
  13.38-13.85 us / 16-request batch
  0.836-0.866 us/request

netz bench-http1-pipeline:
  11.38-12.03 us / 16-request batch
  0.711-0.752 us/request
  1.330-1.406 million requests/s
```

In this historical Threaded capture, netz was about 1.11-1.22x faster.

A 2026-09-04 three-run CPU-0 recapture after switching the benchmark to the
runtime-generated Date measured netz at 0.733-0.750 us/request
(11.73-12.00 us/batch) and Hyper at 13.50-13.54 us/batch
(0.844-0.846 us/request). Netz remained about 1.13-1.15x faster.

## Implementation evidence

The result is backed by reusable runtime changes rather than a pre-rendered
benchmark response:

- HTTP/1, HTTP/2 and HTTP/3 server limits enable an automatic `Date` response
  field by default and allow it to be disabled. All three protocols share one allocation-free
  thread-local IMF-fixdate cache that refreshes only when the real-clock second
  changes. Explicit caller fields win case-insensitively; interim 1xx responses
  omit the generated field (HTTP/1 101 remains a final upgrade response); pure
  HTTP/1 and HTTP/3 codec helpers remain deterministic and wall-clock-free;
- ordinary, streaming and batched HTTP/1 responses, plus ordinary, streaming,
  bodyless/body batches, pushed responses and traditional/extended CONNECT in
  HTTP/2, all use the same production defaulting path. Batch preflight includes
  the generated field in header-size validation before reading the clock or
  mutating HPACK state, and one cached value is synchronously consumed for the
  whole batch;
- HTTP/3 development, preconfigured-protection, and authenticated-handshake
  runtimes add the same default to aggregate and streaming final responses,
  including both the parent and pushed response in server push and successful
  Extended CONNECT. Informational heads remain untouched, explicit `date` wins
  case-insensitively, and generated values are QPACK never-indexed so a
  once-per-second field cannot churn the dynamic table. Common header lists use
  stack storage with exact allocation fallback. HTTP/3's paced push aggregate
  commits only the parent/push heads up front, then streams both bodies and
  trailers under one deadline; this permits pushed bodies larger than the
  initial QUIC connection or unidirectional-stream window and stops an active
  push when the client sends `CANCEL_PUSH`;
- HTTP/1 trailer validation rejects connection-control fields (`Connection`,
  `Keep-Alive`, `Proxy-Connection`, and `Upgrade`) in addition to the existing
  framing, routing, authentication, response-control, and representation
  fields. One central policy covers aggregate and streaming encoders and
  decoders, so forbidden fields fail before local emission and cannot affect
  persistent-message reuse when received. The bidirectional Hyper process gate
  deliberately sends a real `Connection: close` trailer over cleartext and
  TLS; netz reports `InvalidTrailer` and closes that connection without a
  response;
- response codecs and both owned/caller-storage parsers share the RFC 9112
  status-line grammar. Even an empty optional reason phrase retains its
  mandatory separating SP, while a peer line that omits that delimiter is
  rejected instead of being normalized differently by separate parser paths;
- 304 responses can preserve an explicit Transfer-Encoding as representation
  metadata, as permitted by RFC 9112, while aggregate and streaming writers
  suppress both content and the otherwise-required terminating chunk;
- Transfer-Encoding parsing validates coding and parameter tokens without
  allocation, honors commas inside quoted parameter values, rejects malformed
  or unterminated parameters, and rejects parameters on `chunked` itself;
- low-level request/response writers apply the same Host, HTTP-version and
  Transfer-Encoding grammar before reserving output; requests additionally
  reject missing or mismatched framing and both directions reject simultaneous
  Content-Length plus Transfer-Encoding instead of emitting ambiguous bytes.
  Non-empty response bodies must match a declared Content-Length, while empty
  HEAD-style metadata remains valid; pre-encoded chunked bodies must contain
  one complete body with valid trailers and no ambiguous suffix bytes, and
  explicit Trailer declarations must use permitted names, select chunked
  framing, and cover every emitted trailer field;
- CONNECT request authority must agree with Host across borrowed, owned and
  runtime validation, and senders reject request content, Content-Length,
  Transfer-Encoding and trailers as required by RFC 9110;
- TRACE request writers reject non-empty content, transfer coding and trailers;
  aggregate and streaming paths preserve a legal zero-length request instead
  of defaulting an unknown-length TRACE to chunked framing;
- request TE values use the transfer-coding grammar, reject the reserved
  `chunked` name, and require the HTTP/1.1 `Connection: TE` hop-by-hop marker;
  runtime writers synthesize a missing marker, while response writers reject
  the request-only field before emitting bytes;
- outbound Connection lists use strict token syntax and cannot nominate Host,
  Content-Length, Transfer-Encoding, Trailer, or Connection itself; Upgrade is
  limited to HTTP/1.1, requires its connection option and valid protocol-list
  syntax, and is mandatory on 101 responses;
- outbound Expect values use their list grammar; `100-continue` must be the
  sole expectation on an HTTP/1.1 request that will send non-empty content,
  and response writers reject the request-only field;
- both owned and caller-storage request parsers enforce Host cardinality,
  syntax, and absolute-/authority-form agreement before body parsing, so a
  direct codec caller cannot accidentally omit the runtime validation step;
- persistent clients/connections retain request/response header descriptors,
  trailer rendering and encoding buffers;
- server `Limits.request_head_timeout` applies one absolute deadline to each
  request head over TCP or TLS, starts while the connection is idle before its
  first byte, does not reset on trickled bytes, resets for each persistent
  request (and each unbuffered member of a pipeline batch), and stops before
  body reads; protocol transports remain behind `std.Io`, so deadline behavior
  is not split across an OS-specific public API;
- connection-owning HTTP/1 `serve*` helpers expose
  `Limits.max_request_headers` and map request-head byte/count overflow to a
  terminal `431 Request Header Fields Too Large` response with
  `Connection: close`, matching Hyper's server parse-error behavior. The
  handler is never called, `serveUntil` still reports the original
  `HeadersTooLarge` or `TooManyHeaders` to its observer, and lower-level
  `readRequest(ParseOptions)` remains caller-controlled. Malformed request
  lines, methods, versions, header syntax, and Host validation similarly map
  to terminal 400 responses. Internal head/body phase tracking keeps malformed
  or oversized chunked trailers, timeouts, EOF, TLS, and body-framing failures
  from being reflected. An independent
  `Limits.max_request_target_bytes` bound maps request-target overflow to
  terminal 414 without conflating it with the aggregate head-byte limit;
- client `Limits.response_head_timeout` applies one absolute deadline from the
  first required response byte through the final response head. Partial bytes
  and informational 1xx heads do not renew it, while body reads remain outside
  the budget. The same policy covers aggregate and streaming responses,
  Expect/100-continue, CONNECT and generic Upgrade over cleartext and TLS;
- non-chunked bodies are borrowed and sent with header+body vectored TCP I/O
  (or one TLS flush) instead of copied into a temporary whole-message buffer;
- `Limits.write_strategy` exposes connection-level `auto`, `vectored`, and
  `flatten` control for complete messages, response pipelines, and streaming
  body chunks, matching Hyper's explicit writev/flatten policy surface. The
  default preserves the existing behavior: ordinary header/body writes remain
  borrowed, response pipelines at or below 16 KiB are coalesced, and larger
  pipelines use wide POSIX writev. Explicit flattening uses independent
  connection-owned reusable storage so prepared heads and streaming
  terminators cannot be invalidated while copied. Allocation and overflow
  failures before the first transport call remain retryable; transport errors
  retain the fail-closed connection rule;
- `Connection.writeResponses` validates and flushes a response pipeline in one
  transport write, matching Hyper's `pipeline_flush` scheduling shape;
- small response pipelines remain coalesced for minimal syscall/iovec overhead,
  while pipelines above 16 KiB validate every response first, retain only
  encoded heads/chunk framing, and borrow fixed bodies into one writev instead
  of copying the entire batch. The batch-only encoded bytes, descriptor list,
  and iovec list are allocated together on first pipeline use, removing three
  empty containers from ordinary client and server connections while retaining
  their warmed capacity. Streaming trailer-name descriptors and backing names
  are likewise allocated only when a writer must retain them through
  `finishTrailers`; generated `Trailer:` values use 256 stack bytes with an
  exact temporary fallback. Complete-message trailers therefore create no
  persistent trailer state. The retained streaming descriptors and copied
  names share one pointer-aligned backing allocation, reducing that state from
  72 to 24 bytes and its first-use allocations from three to two. Multi-chunk
  streaming descriptors and iovecs likewise share one
  pointer-aligned backing allocation in a 24-byte lazy state, reducing first
  use from three allocations to two while retaining warmed capacity. Each
  hexadecimal chunk header reserves the exact platform maximum (18 bytes on
  64-bit targets) instead of 32. Contiguous flattening reuses the response-batch
  allocation because those buffers must coexist, removing its standalone empty
  list from ordinary connections. Request Host/TE normalization, framing
  validation, generated fields, and final encoding likewise share one reusable
  header-descriptor list instead of copying through a second retained list. A
  representative cold request first dropped from three scratch allocations to
  two. Final
  header descriptors now use 16 uninitialized stack slots with an exact
  allocation fallback for larger sets, leaving only the encoded-byte
  allocation on the common cold path; returned heads own their encoded bytes
  after temporary descriptor storage is released. The warmed aggregate and
  streaming paths allocate nothing further. The exact-width Content-Length
  decimal buffer is likewise call-local during head encoding instead of
  remaining resident for the connection lifetime;
- complete requests, single responses, and both coalesced and borrowed response
  batches finish all validation and allocation before transport I/O. Once a
  write begins, any transport error permanently retires the HTTP/1 connection:
  the peer may have received an arbitrary prefix and HTTP/1 has no stream reset
  that can restore framing. The same rule covers CONNECT/Upgrade handshakes and
  automatic `100 Continue`; pooled leases therefore discard failed sockets.
  Deterministic tests expose four-byte socket-visible prefixes before failure,
  while invalid Content-Length preflight remains retryable without any write;
- HTTP/1.1 response trailer fields require the associated request's exact
  `TE: trailers` token. Owned and streaming request values expose
  `acceptsTrailers()`; low-level response options carry that explicit
  capability, while the high-level serve loop derives it automatically and
  cannot be overridden by the handler. Unnegotiated trailer responses fail
  before their head is written. This is stricter than Hyper's silent trailer
  suppression and prevents an application from believing integrity metadata
  reached a client when it was discarded;
- `Connection.readRequestBatchInto` parses request heads and fixed or chunked
  bodies into caller storage, borrows one receive buffer and consumes its
  prefix once per batch. It validates the complete batch before mutation, then
  strips chunk framing in place and compacts the pipelined suffix without a
  body allocation. Trailer syntax/count/forbidden-name rules are enforced,
  while the intentionally trailer-less borrowed result discards trailer
  metadata;
- borrowed head parsing scans CRLF-delimited lines once instead of first
  scanning for CRLFCRLF and then rescanning every header line.
- strict header-line parsing now combines colon discovery with RFC token
  validation and combines value validation with OWS-boundary tracking. Its
  token-byte classification uses a compile-time 256-entry table, following the
  audited picohttpparser approach. An isolated borrowed-parser profile drove
  this change; five CPU-0 runs improved from 333-335 to 280-282 ns/op, while a
  full 0-255 equivalence test preserves the prior token grammar.
- request framing now returns the selected body mode, parsed Content-Length and
  TE+CL must-close decision from one header scan. This removes the prior second
  Content-Length parse and extra field-name scans; the isolated borrowed parser
  improved again from a 282-ns median to 264 ns. Valid final `chunked` retains
  precedence over malformed Content-Length while still forcing close, matching
  the existing anti-smuggling contract and its new explicit regression.
- Host validation now finds structural delimiters, brackets and the optional
  port colon in one pass instead of repeatedly searching the same authority.
  The isolated borrowed parser improved from a 264-ns median to 238 ns; existing
  malformed-authority, IPv6-literal and port-range tests retain the strict
  request-smuggling boundary.
- forcing the compact header-line parser inline reduced the isolated borrowed
  median from 238 to 231 ns and also improved both owned benchmark modes. Two
  seemingly plausible alternatives were rejected by direct A/B: a scalar
  CRLF/header state machine lost the standard library's vectorized delimiter
  scan, while vectorized colon search reintroduced a second name pass.

Connection persistence and Upgrade decisions scan every repeated `Connection`
field as one comma-separated token list while ordinary `header()` lookup still
returns the first field. Thus a later `close` token overrides an earlier
`keep-alive`, and an `upgrade` token on any field enables an otherwise valid
request or 101 response handoff. Aggregate, borrowed-head, streaming, writer,
serve-loop, and pooled-client paths share this rule, including pool eviction
when a later response field carries `close`. This matches Hyper's `get_all`
handling for connection-close reuse decisions rather than inspecting only the
first field.

Request framing also follows Hyper's smuggling hardening when both
`Transfer-Encoding` and `Content-Length` are present: chunked decoding still
wins and `Content-Length` is removed from borrowed, aggregate, and streaming
request metadata, but the request is marked `must_close` so `keepAlive()` is
false regardless of header order or an explicit `Connection: keep-alive`. The
HTTP/1 serve loop therefore completes exactly that response with
`Connection: close` and never interprets a buffered pipeline suffix as another
request. Response-side framing semantics are unchanged.

The parser also mirrors Hyper's explicitly opt-in HTTP/1 compatibility
controls while preserving strict defaults.
Header field names retain their exact input spelling in both borrowed and
owned parse results; lookup remains ASCII case-insensitive. Writers expose a
per-message `HeaderNameCasing` policy: `.preserve` keeps caller spelling, while
`.title_case` renders each dash-separated component in conventional HTTP/1
title case without allocating or mutating the supplied fields. The same policy
applies to generated fields and terminal chunked trailer lines; `Trailer`
header value tokens remain caller-authored metadata.
`allow_multiple_spaces_in_request_line_delimiters` accepts repeated ASCII SP
between method, target and version, and
`allow_spaces_after_header_name_in_responses` accepts SP/HTAB immediately
before a response field colon. Direction-specific
`ignore_invalid_headers_in_requests` and
`ignore_invalid_headers_in_responses` can skip an otherwise malformed header
line, but still reject NUL and bare CR rather than permitting ambiguous line
boundaries. Response whitespace tolerance never affects requests or trailers,
preserving the request-smuggling boundary described by Hyper's public API.
Both owned and caller-buffer head parsers share these rules. The corresponding
local Hyper/httparse tests and netz parity tests pass on the same
malformed/default and accepted/opt-in wire forms:

```sh
cd ~/Work/hyper
cargo test --features full \
  test_parse_allow_request_with_multiple_spaces_in_request_line
cargo test --features full \
  test_parse_allow_response_with_spaces_before_colons
cd ~/.cargo/registry/src/rsproxy.cn-e3de039b2554c837/httparse-1.10.1
cargo test test_ignore_header_line_with_whitespaces_after_header_name_in_request
cargo test test_ignore_header_line_with_whitespaces_after_header_name_in_response

cd ~/project-z/netz
zig test -ODebug \
  --test-filter 'HTTP/1 Hyper-shaped parser compatibility' ...
zig test -ODebug \
  --test-filter 'HTTP/1 invalid-header compatibility' ...
```

Client response parsing also exposes an opt-in
`ParseOptions.allow_http_0_9_responses`, matching Hyper's
`http09_responses` switch while retaining a strict default. The aggregate and
callback-streaming clients classify fragmented `H`, `HT`, `HTT`, and `HTTP`
prefixes before falling back to a headerless response, so a split HTTP/1.x
status line is never mistaken for legacy body data and malformed `HTTP/...`
still fails the normal parser. Accepted HTTP/0.9 data is represented as a 200
close-delimited response, remains subject to the configured body and absolute
deadline limits, rejects empty EOF, and permanently retires the connection.
The response-head timeout covers classification until the first unambiguous
legacy body byte; caller-owned whole-response deadlines continue through the
EOF-delimited body.
Runtime clients accept this legacy response form only for GET requests. The
lower-level `parseResponse` option is intentionally request-context-free, so
callers using that codec directly remain responsible for applying method
semantics.
The representation is receive-only: every request and response writer rejects
`.http_0_9`.

The streaming chunked-body reader now applies the same opt-in obs-fold policy
to trailers instead of silently retaining a stricter second parser. Strict
mode continues to reject folded trailers. Compatibility mode unfolds each
continuation to one SP, owns the resulting values independently of receive
buffer compaction, and works when every trailer byte arrives in a separate
transport read. Focused request and response regressions cover both directions,
matching Hyper's documented response-side obsolete-line-folding behavior.

The aggregate chunked encoder now matches the streaming writer by eliding empty
application slices. Since a zero-sized HTTP/1 chunk is the message terminator,
emitting one for an empty slice would truncate any later chunks and trailers.
Mixed empty/non-empty and all-empty regressions verify one final terminator,
correct trailer placement, and exact-capacity allocation-free output.
The shared trailer validator now checks complete field-name and field-value
syntax before applying the forbidden-name policy. Array-based callers and the
streaming terminator therefore reject empty/invalid names and CR/LF value
injection before any terminator bytes are staged.

The aggregate HTTP/1 readers apply `Limits.max_body_bytes` to decoded chunk
payload only, not chunk-size lines, extensions, CRLF framing, trailers, or
bytes read ahead from the next pipelined message. Exact-limit and empty chunked
bodies therefore remain valid, while an oversized chunk is rejected as soon as
its size line is available. Trailer blocks have their own `max_head_bytes`
budget, and every chunk-size line has a shared
`max_chunk_extension_bytes + 32` wire bound. The limit is enforced whether or
not CRLF is already buffered, so one oversized complete line cannot bypass the
incremental check; the unbuffered adapter retains one-byte reads until it
discovers the exact message boundary. Pure decoding, aggregate framing, and
streaming-reader regressions cover the complete-line case.

The batch read path uses the same chunk wire scanner as aggregate reads, then
decodes only after every requested message and trailer block validates. Mixed
fixed/chunked pipelines, empty chunked bodies, extensions, trailers, TE+CL
terminal-request handling, and pipelined-suffix preservation are covered. Its
returned `consumed` length names the compacted prefix rather than the original
wire length, so the existing one-call `consumeRequestBatch` contract remains
valid. Because this borrowed API has no trailer output storage, valid trailer
fields are checked and discarded; callers that need them use the owned or
streaming request APIs. Aggregate chunk scanning also caps retained wire
framing relative to the decoded body budget, preventing many legal-size chunk
lines from amplifying a small body limit into unbounded buffering.

The pipeline benchmark accepts `--large-body` (16 × 64 KiB responses) to cover
the borrowed-body branch. Three CPU-0-pinned ReleaseFast runs completed at
10.66–10.79 us/request versus 15.43 us/request with the former whole-batch
copy, a 1.43–1.45x local improvement. The default same-shape Hyper 13-byte
benchmark remains coalesced and measured 0.742 us/request after this change.

## HTTP/1 bidirectional 1-MiB streaming bodies

Hyper's existing `end_to_end` benchmark includes fixed-size HTTP/1 bodies, but
does not expose a runnable 1-MiB fixed/chunked pair. The checked-in
`tools/hyper_http1_body` harness therefore imports the audited local Hyper
revision without modifying `~/Work/hyper`; `bench-http1-body` mirrors it.
Its Cargo lockfile pins the support crates and the wrapper builds offline after
the initial dependency cache is populated.
Both use one persistent connection, current-thread event loops, TCP_NODELAY,
20 warmup plus 200 measured round trips, a 1-MiB request and response, and
borrowed streaming receive. Fixed mode sends one exact Content-Length body per
direction. Chunked mode preserves 64 application chunks of 16 KiB per
direction; Hyper's `StreamBody` and netz's `writeChunks` retain those same
boundaries. Both now obtain their Date value from their normal server runtime.

Commands:

```sh
taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=fixed --warmup=20 --iterations=200
taskset -c 0 tools/bench_hyper_http1_body.sh \
  --mode=fixed --warmup=20 --iterations=200

taskset -c 0 zig build bench-http1-body -Doptimize=ReleaseFast -- \
  --mode=chunked --warmup=20 --iterations=200
taskset -c 0 tools/bench_hyper_http1_body.sh \
  --mode=chunked --warmup=20 --iterations=200
```

2026-08-19 ranges, each from five CPU-0-pinned process runs:

```text
fixed Content-Length, 1 MiB each direction:
  netz:  268.72-270.10 us/round-trip, 7,404-7,442 aggregate MiB/s
  hyper: 288.61-293.14 us/round-trip, 6,822-6,929 aggregate MiB/s
  netz is about 1.07-1.09x faster

chunked, 64 x 16 KiB each direction:
  netz:  284.04-286.06 us/round-trip, 6,991-7,041 aggregate MiB/s
  hyper: 414.64-417.45 us/round-trip, 4,790-4,823 aggregate MiB/s
  netz is about 1.45-1.47x faster
```

A three-run 2026-09-04 fixed-mode recapture with netz's generated Date measured
268.93-274.31 us/round-trip for netz and 287.20-288.11 us for Hyper, retaining
an approximately 1.05-1.07x latency advantage.

H1 enables TCP_NODELAY, fixed readers deliver socket bytes directly to
callbacks, chunk descriptors and vectored slice lists retain connection
scratch, and `writeChunks` batches many caller boundaries without concatenating
payloads. On POSIX, large HTTP/1 batches use the platform IOV limit instead of
Zig Threaded's portable eight-iovec cap. Chunked readers now read up to 64 KiB
directly into their retained connection buffer. One transport read may span
multiple size/data/CRLF records or reach the next pipelined message, while the
parser still invokes the callback at each wire-chunk boundary and commits only
the current message. This removes repeated exact-boundary reads without
aggregating a whole body. Both modes demonstrated an advantage in these
historical Threaded loopback workloads; neither establishes current zio
performance or whole-library superiority.

The same gate also covers a finer streaming shape without changing either
implementation: 1 MiB each direction as 1,024 x 1-KiB chunks, 10 warmups and
100 measured round trips. Three CPU-0 runs measured netz at 581.64-590.26 us
(3,388-3,438 aggregate MiB/s) versus Hyper at 2.031-2.653 ms
(753-984 MiB/s), a conservative 3.44-4.56x latency advantage. This stresses
boundary preservation rather than bulk copy: netz renders descriptors into
retained scratch and submits borrowed slices up to the POSIX IOV limit, while
the callback reader still observes every application chunk.

`bench-http1-body --stats` now adds the same thread-safe allocator telemetry as
the H2/WebSocket benchmarks. A short 1-MiB smoke used 37 allocations and
1,063,364 peak live bytes for fixed framing, versus 45 allocations and
1,288,250 peak live bytes for 64 x 16-KiB chunked framing. In both cases the
1-MiB application payload dominates live memory; retained chunk/vector scratch
adds roughly 225 KiB for chunked framing and allocation counts stay constant
across body bytes after warmup. The Hyper harness now accepts the same
`--stats` switch, enabled through an opt-in `allocation-stats` Cargo feature so
ordinary timing runs retain the system allocator directly. Its process-wide
atomic wrapper reports requested allocation/free/reallocation bytes and the
same size buckets without recursively allocating.

A matched CPU-0 run of the documented 1-MiB-per-direction, twenty-warmup,
hundred-iteration matrix measured:

```text
fixed:
  netz   286.850 us/op, 489 allocations, 1,063,300 peak live bytes
  Hyper  307.999 us/op, 4,899 allocations, 2,461,724 peak live bytes

16-KiB chunked:
  netz   304.222 us/op, 495 allocations, 1,269,638 peak live bytes
  Hyper  440.550 us/op, 34,417 allocations, 2,153,292 peak live bytes
```

Netz therefore used 90.0% fewer allocation calls and 56.8% less peak live
memory in fixed mode, and 98.6% fewer calls plus 41.0% less peak live memory in
chunked mode for this exact process-wide workload. Hyper's fixed-body run also
requested 100,692,363 cumulative bytes versus netz's 1,095,970; its chunked
run requested 3,469,637 versus netz's 1,309,426. These are allocator-request
counters rather than RSS measurements and include setup plus warmup on both
sides.

The benchmark evidence is complemented by a strict process-boundary semantic
gate. `zig build interop-http1-hyper -Doptimize=ReleaseFast` builds against the
audited local Hyper checkout and runs the same scenarios over fresh cleartext
and TLS 1.3 connections in both directions. Both netz executables obtain
`std.Io` from `netz.runtime.Backend`, whose implementation is zio; the audited
Hyper fixture uses a Tokio current-thread runtime. Terminal success records and
runner assertions bind the endpoint identities as `zio-std-io` and
`hyper-tokio`, so this gate verifies the execution backend as well as the wire
semantics. The encrypted half uses the checked-in localhost identity and each
client validates that certificate.
Each peer sends a POST with two chunked DATA contributions, explicitly
negotiates `TE: trailers`, and terminates with a request trailer. The receiving
peer verifies method, query-bearing target, custom header, reconstructed body,
and trailer. The response path repeats the two-chunk plus terminal-trailer
shape with status 201 and exact response metadata. Each direction then performs
an `Expect: 100-continue` exchange. The sender withholds its declared request
body until the other implementation emits an HTTP/1.1 100 response, and the
receiver verifies the body plus final response. Hyper observes netz's interim
response through its `on_informational` extension. Netz now exposes the same
shape through `InformationalObserver` on aggregate and streaming client reads;
callbacks receive each ordered borrowed 1xx head, while a configurable count
limit prevents an endless interim-response chain from causing unbounded work.
The Hyper fixture sends 103 Early Hints and 102 Processing with distinct
headers before a final 200, and the netz client validates every status/header
over both cleartext and certificate-verified TLS. Netz also uses
`RequestWriter.waitForContinue`, which consumes preceding non-100 1xx
responses and returns a typed owned final response if the server rejects the
expectation before the body. The external client gate exercises both
branches against raw wire responses in the same Hyper/Tokio fixture: a 103
Early Hints followed by 100 Continue releases the exact ten-byte body, while a
417 response causes netz to send zero body bytes, return the owned rejection,
reject further writes through the stale writer, and mark the connection
unusable. The peer waits for EOF and fails if any declared-body byte arrives,
so this is observable process-boundary evidence rather than an in-process state
assertion. The netz HTTP/1 server uses the same parser, streaming-body state,
vectored writer, persistent connection, and CONNECT tunnel surface over either
raw TCP or its native TLS transport. This is functional HTTP/1.1 and HTTPS
interoperability evidence rather than a benchmark proxy.

The same process gate now exercises that CONNECT surface directly in both
endpoint roles over cleartext and TLS. Each server writes its protocol preface
immediately after the 200 response so the receiving HTTP implementation must
preserve any already-read tunnel suffix during parser handoff. The clients then
send 17/18-byte opaque payloads and validate exact replies in the reverse
direction. Hyper uses `upgrade::on` with `with_upgrades`, while netz uses
`openConnectTunnel` and `acceptConnectTunnel`; the gate awaits tunnel-task
completion instead of inferring success from the HTTP status.
Successful CONNECT handoff now permanently marks the parent netz HTTP/1 client
or server connection unusable for HTTP framing, matching the existing generic
Upgrade ownership rule. A pooled lease therefore closes a handed-off tunnel
socket instead of returning it to the idle set; focused tests also reject any
subsequent HTTP read/write attempt while the tunnel retains the transport.
HTTP/1 CONNECT and generic Upgrade tunnels also expose `closeWrite`. Cleartext
uses the socket send-half shutdown; standard-library and vail TLS first send an
authenticated `close_notify` and then close the socket write direction. Reads
remain available for the peer's final data and EOF. Once shutdown starts, a
failed close, duplicate close, later application write, or TLS KeyUpdate is
rejected without touching the transport. Real CONNECT tests cover cleartext,
standard-library TLS client, vail TLS client and vail TLS server paths, while a
deterministic injected shutdown error covers the fail-closed transition.
The same tunnel exposes `writeParts` and arbitrary `writeSlices`, matching
Hyper `Upgraded`'s vectored-write surface. Cleartext retains caller slices
through wide POSIX iovecs and TLS consumes them under one flush boundary. A
real CONNECT exchange includes an empty middle slice and verifies exact bytes
in both directions. If any write fails after an unknown socket-visible prefix,
the tunnel permanently rejects later writes and TLS key updates while leaving
the read half available. HTTP/2 tunnels additionally expose timeout/deadline
variants for single, two-part, and arbitrary-slice writes. Their
`TunnelWriteProgress` reports application bytes and FIN independently: after a
flow-control deadline, callers resend only the uncommitted suffix, and an
invalid clock leaves both values zero. A real bidirectional CONNECT regression
covers the ordinary `Tunnel` and preflighted `TunnelWriter` paths across slice
boundaries. RFC 8441 Ping and Close build on that cursor: each retains one
encoded masked control frame across a timeout, prevents another WebSocket frame
from interleaving, and resumes only its uncommitted suffix. Ping restores normal
writes after completion; Close commits HTTP/2 END_STREAM exactly once.
HTTP/2's TLS listener now also exposes the same single-connection
`serveConnection` helper as the TCP and Unix listeners. A real TLS regression
serves two sequential requests, verifies the returned count, and checks the
terminal `GOAWAY(last_stream_id=3, NO_ERROR, "serve-complete")`.
HTTP/1's TLS listener likewise exposes plain `acceptStream`, `serveOne`, and
`serveConnection` entry points alongside its bounded accept variants. This
lets external accept loops adopt a connected socket without inventing a dummy
deadline and gives the TLS listener the same one-connection convenience
surface as the cleartext and Unix listeners.

Generic HTTP/1.1 `101 Switching Protocols` now has the same explicit transport
handoff rather than being available only through the WebSocket adapter. The
client validates `Connection: Upgrade`, the selected Upgrade token, empty HTTP
body/trailers, and then exposes any bytes read past the response head. The
server validates the corresponding request before sending 101 and transferring
its buffered request suffix. The Hyper process gate exercises both endpoint
roles over cleartext and TLS with protocol `netz-test`, bidirectional opaque
payloads, and an immediate server preface; the netz-server direction uses
Hyper's generic `upgrade::on`/`with_upgrades` path rather than WebSocket code.
The WebSocket HTTP/1 client additionally exposes a typed `ConnectAttempt`: an
application can inspect a rejected status, headers, decoded trailers, and a
bounded Content-Length/chunked/close-delimited body before mapping it to the
legacy `InvalidResponse` error. Successful attempts retain the normal 101
validation and exact buffered-byte handoff.

## HTTP/2 consecutive and parallel round trips

Hyper's `benches/end_to_end.rs` defines consecutive empty GET, consecutive
10-byte and 100-KiB POST, parallel x10 empty GET, max-window chunked request,
and max-window 1-MiB response scenarios on persistent HTTP/2 connections. The
netz h2c benchmark mirrors them with 1,000 untimed warmup iterations for small
messages (100 for 100 KiB) and 2,000 measured iterations. The 10-stream body
workloads use 5 warmups and 20 measured batches because each batch transfers
about 10 MiB. The current netz executable obtains `std.Io` from zio and
schedules its local server through `std.Io.async`; its output identifies
`zio-std-io`. Historical numbers below predate that migration:

```sh
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast

cd ~/Work/hyper
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
taskset -c 0 "$HYPER_H2_BENCH" \
  --bench http2_parallel_x10_req_10kb_100_chunks_max_window
taskset -c 0 "$HYPER_H2_BENCH" \
  --bench http2_parallel_x10_res_1mb
```

The reference revision/toolchain are the same as the HTTP/1 comparison above.
Both servers now generate Date through their default production response path;
the netz benchmark contains no benchmark-only Date field.
Syscall traces verified equal steady-state wire shapes:

- empty: 19-byte request and 11-byte response for each implementation;
- 10-byte POST: 43 request bytes (24-byte HEADERS + 19-byte DATA) and an
  11-byte response for each implementation;
- 100-KiB POST: the same Content-Length and 16-KiB DATA framing, consumed
  incrementally by both servers rather than retained as one application body.

2026-08-17 ranges, each from five CPU-0-pinned process runs:

```text
http2_consecutive_x1_empty:
  netz:   9.55-9.96 us/op
  hyper: 12.51-12.54 us/op
  netz is about 1.26-1.31x faster

http2_consecutive_x1_req_10b:
  netz:  10.09-10.38 us/op
  hyper: 41.15-41.37 ms/op

http2_consecutive_x1_req_100kb:
  netz:  23.52-23.57 us/op
  hyper: 37.24-38.68 us/op
  netz is about 1.58-1.64x faster

http2_parallel_x10_empty:
  netz:  26.35-26.60 us/10-request batch
         2.63-2.66 us/request
  hyper: 47.50-48.46 us/10-request batch
         4.75-4.85 us/request
  netz is about 1.79-1.84x faster per batch

http2_parallel_x10_req_10kb_100_chunks_max_window:
  netz:  1.64-1.74 ms/10-stream batch
         164-174 us/request
  hyper: 3.36-3.40 ms/10-stream batch
         336-340 us/request
  netz is about 1.93-2.07x faster per batch

http2_parallel_x10_res_1mb (2026-08-19):
  netz:  1.663-1.671 ms/10-stream batch
         166.3-167.1 us/request
  hyper: 2.957-3.035 ms/10-stream batch
         295.7-303.5 us/request
  netz is about 1.77-1.82x faster per batch
```

A 2026-09-04 three-run CPU-0 recapture of the four direct Hyper benchmark
shapes after removing netz's fixed Date produced 9.980-10.288 us,
10.516-10.525 us, 23.173-23.279 us and 27.611-27.808 us/batch respectively.
Corresponding Hyper spot samples were 12.514 us, 41.012 ms, 37.168 us and
47.994 us/batch. The real automatic-Date path therefore preserves the earlier
ordering; the five-run ranges above remain the primary baseline.

For the response case, Hyper supplies one `Full<Bytes>` per stream. The locked
h2 0.4.15 scheduler splits it at the default 16-KiB frame limit and requeues
the stream after each frame. Netz uses the same 16-KiB round-robin contribution,
so the comparison matches not only body and window sizes but also DATA
interleaving.

The 10-byte result is a specific Linux TCP scheduling cliff, not a general
3,500x whole-stack claim. In the audited Hyper run, HEADERS and DATA are two
small `writev` calls and the response follows about 41 ms later. Netz preserves
the same two HTTP/2 frames and 43 wire bytes but submits their four borrowed
slices in one `sendmsg`, avoiding Nagle/delayed-ACK interaction. Larger bodies,
trailers, fragmented header blocks and flow-control-blocked streams use the
normal multi-write fallback.

HTTP/1 now also exposes the Body-style send boundary that was previously only
available for HTTP/2:

- `Client.startRequest` returns a stateful `RequestWriter`; fixed-length bodies
  are checked transactionally across writes, unknown HTTP/1.1 entity bodies use
  chunked transfer coding, and `finishTrailers` emits only fields announced by
  `Trailer`;
- `Connection.startResponse` provides the server counterpart and shares the
  existing HEAD, 1xx/204/304, and successful CONNECT body-suppression rules;
- chunk headers, borrowed application bytes, and CRLF are sent as vectored
  slices without a body-sized concatenation;
- a request writer owns the connection until its response is consumed, while a
  response writer releases it only after a complete fixed body or terminating
  chunk. Abandonment marks the HTTP/1 connection unusable because, unlike
  HTTP/2 RST_STREAM, HTTP/1 has no per-message reset that can restore framing.
- `Connection.readRequestStreaming` and `Client.requestStreaming` provide the
  receive-side counterpart. Fixed-length, chunked, trailer-bearing and
  close-delimited bodies are delivered as borrowed callback slices without a
  body-sized allocation; returned start-line/header/trailer metadata remains
  owned, and bytes already read from the next pipelined message stay buffered.
  `RequestWriter.readResponseStreaming` performs the same one-time response
  handoff after an incremental upload. Callback or framing failure poisons the
  HTTP/1 connection rather than risking reuse at an unknown message boundary.

Reusable implementation changes behind these H2 results:

- a shared Zig 0.16 stream-vector helper correctly reserves `netWrite`'s final
  data element as its splat pattern and handles partial writes;
- HTTP/1, HTTP/2 and WebSocket now use that single reviewed helper instead of
  three subtly incorrect copies;
- HPACK encoders retain their block scratch between HEADERS writes;
- common request/response descriptor lists use stack storage, with exact
  allocation fallback for larger caller header sets;
- a one-frame body with available flow credit is submitted together with its
  HEADERS frame without concatenating or copying application bytes;
- DATA frames are submitted in vectored bursts, TCP_NODELAY avoids delayed-ACK
  stalls at flow-window boundaries, and connection/stream receive windows are
  independently configurable;
- one connection read buffer can retain several coalesced frames, while
  ordinary owning APIs still receive independent frame copies;
- `readRequestStreaming` returns an owned request head/trailers and delivers
  borrowed DATA slices to a callback without body-sized aggregation;
- `requestStreaming` provides the symmetric client path: response DATA is
  delivered as borrowed callback slices while the returned status, initial
  headers and trailers remain owned. It skips valid informational responses,
  strictly accounts Content-Length, returns flow credit while the body is
  arriving, and sends RST_STREAM(CANCEL) when the callback fails, matching
  Hyper's `Incoming` frame-stream lifecycle without requiring an async body
  object;
- `Limits.max_local_error_reset_streams` mirrors h2/Hyper's connection-lifetime
  defense against peer-driven reset churn. It defaults to 1024, counts only
  RST_STREAM generated by the library for a peer-caused stream protocol error,
  and turns the next such reset into
  `GOAWAY(ENHANCE_YOUR_CALM, "too_many_internal_resets")`. `null` disables
  the guard; application cancellation, timeout cleanup, and capacity-driven
  REFUSED_STREAM do not consume it;
- `Connection.peerMaxConcurrentStreams`,
  `availableLocalStreamCapacity`, `activeLocalStreamCount`,
  `activePeerStreamCount`, and `peerExtendedConnectEnabled` expose the live
  peer SETTINGS and stream-accounting state needed by multiplexing schedulers.
  The capacity query uses the same priority-reservation calculation as the
  actual next-stream admission check and must be re-read after each open. A
  raw-peer test changes SETTINGS_MAX_CONCURRENT_STREAMS from 3 to 1 and then 4
  through the ordinary PING frame pump, while a real CONNECT test observes
  capacity exhaustion and restoration only after both halves close;
- Hyper's `max_send_buffer_size` bounds DATA retained by its asynchronous
  per-stream send queue. Netz's blocking writers do not own such a queue: they
  borrow caller slices only until each flow-controlled transport write returns,
  and report partial progress when peer input interrupts duplex writes. Adding
  the same-named limit here would constrain caller chunk size rather than bound
  retained memory, so it is intentionally not exposed;
- `startResponse` returns a stateful `ResponseWriter` for server-side streaming
  bodies. Separate writes preserve flow-control backpressure, cumulative
  Content-Length is validated before each frame is sent, DATA FIN and trailers
  terminate exactly once, and dropping an unfinished writer sends
  RST_STREAM(CANCEL). This mirrors Hyper/h2's `SendStream` lifecycle in the
  blocking runtime rather than requiring callers to reach private frame APIs.
  Both response and request writers expose timeout/deadline variants for DATA
  writes and finishes plus `committedBytes()`: successful DATA bursts advance
  the cursor even if the later flow-control wait times out, while an invalid or
  expired deadline leaves frames, windows, and writer state untouched. Callers
  can therefore retry exactly the remaining suffix without duplicating bytes;
- aggregate and informational response writers require the peer request stream
  to remain active. Once a final response releases it, a second final or 1xx
  write returns `InvalidStreamId` without emitting bytes or reclaiming a stream
  slot, and the same connection can serve the next request;
- `startRequest` provides the client-side counterpart. `RequestWriter` accepts
  bounded or length-unbounded DATA chunks, request trailers and transactional
  length retries, remains responsible for cancellation after request-body FIN,
  and hands off exactly once to either aggregate or callback-streaming response
  receive. This matches Hyper's request `Body` → h2 `SendStream` ownership
  boundary without aggregating the upload first. If response HEADERS or a peer
  reset arrives while upload DATA is blocked on flow control, netz preserves
  the one owned application frame, reports partial write progress through the
  writer state, closes the request half and transfers the response to either
  receive mode instead of discarding it. The pending storage stays bounded to
  one frame because control returns to the caller immediately, paralleling
  Hyper's independently driven response future/body pipe;
- `RequestWriter.beginDuplex` and `Connection.acceptDuplexRequest` transfer a
  stream to a single-owner step driver whose request and response halves close
  independently. Client response and server request events expose owned heads,
  DATA, trailers, FIN, informational heads and resets; DATA writes report the
  exact committed prefix when peer input interrupts flow-control progress. Both
  client request writes and server response writes now expose relative-timeout
  and absolute-deadline forms for single slices, parts, slice lists, and final
  DATA. Their cumulative committed-byte cursors also advance after a deadline
  expires following a successful flow-control burst, allowing exact suffix-only
  continuation without replaying bytes. The
  same owner alternates socket pumping and writes, avoiding a second reader,
  preserving HPACK/CONTINUATION state across bounded timeouts, and preventing
  the classic both-sides-waiting-for-window-credit deadlock. Existing aggregate
  and callback-streaming APIs retain their sequential behavior;
- `requestBatchInto` opens bodyless streams together, accepts response frames in
  any stream order, and returns owned responses in request order.
  `requestBatchWithInformationalInto` adds borrowed, ordered 1xx callbacks
  correlated by request index and stream ID; the body-bearing and streaming
  batch variants expose the same observer contract, and each stream keeps an
  independent bounded informational-response count;
- `requestBodyBatchInto` extends that boundary to DATA. It transactionally
  stages every HPACK block, then sends application-sized DATA contributions
  round-robin without copying payloads. When all unfinished uploads are
  flow-controlled, the sole connection owner processes WINDOW_UPDATE and
  early response frames before resuming the exact unsent suffix. A complete
  early response is retained in its request-indexed result while sibling
  uploads continue, avoiding both response-queue overflow and half-duplex
  deadlock. The server counterpart,
  `readRequestBatchStreamingInto`, routes interleaved DATA by stream ID into
  callbacks, validates each Content-Length and owns each head/trailer set. Its
  timeout/deadline variants preserve one awake-clock budget across control
  traffic, every request HEADERS/CONTINUATION chain, interleaved DATA, trailers,
  and sibling completion. A timeout before any stream admission preserves the
  partial frame for retry; after admission, call-local request state cannot be
  reconstructed, so every admitted member is cancelled and the connection
  fails closed. A callback-originated `error.Timeout` remains an application
  rejection and does not poison the synchronized connection;
- `writeResponseBatch` validates and encodes a bodyless response set before one
  submission; a deep-cloned HPACK encoder is committed only after the wire
  write succeeds, so a failed batch cannot desynchronize compression state;
- `writeResponseBodyBatch` extends the server boundary to complete bodies that
  need not fit current connection and per-stream credit. It stages all HPACK
  state and allocation before wire I/O, borrows payloads, submits each stream's
  application contribution round-robin, and pumps WINDOW_UPDATE while every
  unfinished stream is blocked. The scheduler rotates its starting stream so a
  small connection update cannot repeatedly favor stream zero. The
  corresponding `requestBatchStreamingInto` client path demultiplexes
  interleaved DATA by request index, continuously returns flow credit,
  validates each declared length, and retains only owned response metadata
  rather than a batch-sized body aggregate;
- `serveRequestBatchConcurrent` provides a bounded server-side handler batch.
  The connection owner reads the declared number of complete requests, starts
  each handler as its request becomes available, and writes responses in
  handler-completion order. Workers never access the connection: one owner
  retains frame-reader, HPACK and socket-write ordering, and each owned request
  remains alive until its response is submitted so response slices may borrow
  request storage. A handler failure resets only that stream with
  INTERNAL_ERROR, does not consume the peer-protocol-error reset budget, and is
  returned by input index. A handler's accidental 100-199 final response is
  instead replaced by a bodyless final 500 and reported as `InvalidStatus` in
  that request's result slot; successful siblings and later
  requests remain usable. Calls require an idle server-side request set, and a
  batch larger than the locally advertised SETTINGS_MAX_CONCURRENT_STREAMS
  limit is rejected before allocation or I/O. While handlers run, the owner
  races completions with one connection read, handles PING and other
  connection-control frames immediately, and retains application frames in a
  bounded wire-ordered queue. Cancellation preserves partial HTTP/2 frames and
  partial TLS records, so a trickled frame cannot delay an already-complete
  handler and canceling the read cannot desynchronize the encrypted stream.
  Real same-connection tests block `/slow`, require the later `/fast` response
  first, acknowledge a PING with a later request already on the wire, preserve
  that request for the next serve call, exercise partial-frame cancellation and
  stream-local handler failure, and then complete another request. The checked-in
  Hyper client repeats fast-before-slow over both h2c and TLS with its one-second
  keep-alive enabled. This is bounded aggregate admission, not Hyper's
  continuously accepting per-stream service executor: responses begin only
  after the declared request batch has been read, and CONNECT tunnels remain on
  their dedicated ownership APIs;
- large batch header blocks retain normal HEADERS/CONTINUATION framing.

### HTTP/2 constrained-window parallel responses

The max-window Hyper workload does not exercise response backpressure. A
checked-in companion harness therefore uses the same Hyper revision through a
local path dependency without modifying `~/Work/hyper`. Both peers run ten
bodyless requests, wait until all ten handlers exist, then concurrently stream
1 MiB per response with a 16-KiB maximum DATA frame size, an 8-KiB stream
window and the RFC default 65,535-byte connection window. Both clients drain
all response bodies concurrently. The current netz benchmark uses zio through
`std.Io` and runs its server as a `std.Io.async` task; historical timings below
were captured with `std.Io.Threaded`.

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --warmup=5 --iterations=20
taskset -c 0 tools/bench_hyper_http2_flow.sh \
  --warmup=5 --iterations=20
```

2026-08-19 ranges, each from five CPU-0-pinned process runs:

```text
netz:  7.367-7.447 ms/10-stream batch
       1,342-1,357 body MiB/s
hyper: 10.192-10.379 ms/10-stream batch
       963-981 body MiB/s
netz is about 1.37-1.41x faster per batch
```

With automatic Date generated by the product path, three alternating
CPU-0-pinned runs on 2026-09-04 measured netz at 7.586-7.660 ms/batch
(1,305-1,318 MiB/s) and Hyper at 10.155-10.196 ms/batch
(980-984 MiB/s), a 1.33-1.34x latency advantage. An additional alternating
short-run A/B against the saved pre-change netz binary measured 7.487 ms median
with automatic Date versus 7.482 ms with the former fixed field, a 0.07%
difference inside normal run noise.

This evidence covers normal WINDOW_UPDATE-driven completion and round-robin
progress. End-to-end tests separately verify a member-stream reset is observed
while the server is blocked on response credit. It remains one synchronous
loopback shape, not a claim about all priorities, cancellation races or network
conditions.

The runtime also exposes opt-in `Limits.adaptive_window`, with a configurable
`adaptive_window_max` (16 MiB by default), for the receive side of either role.
It follows Hyper's BDP policy without floating-point or estimator allocation:
DATA starts a reserved-namespace PING sample, a matching ACK grows the target
when the sampled bytes reach two thirds of the previous estimate, and stable
samples progressively back off probe frequency. Connection growth is sent as
WINDOW_UPDATE and stream growth as SETTINGS_INITIAL_WINDOW_SIZE. SETTINGS are
serialized: growth measured before the initial or previous SETTINGS ACK is
max-coalesced, and existing plus future receive-stream windows switch together
only after the combined wire write succeeds. Stale/unrelated PING ACKs cannot
mutate the estimator, and public PING APIs reject the internal namespace.

Both flow harnesses accept `--adaptive` and, like Hyper's public builder,
override fixed-window arguments with 65,535-byte stream and connection starting
windows. Their same-process topology, body, parallelism, warmup, measurement,
checksum, TCP_NODELAY and CPU placement are otherwise matched. The netz
harness uses a measurement-external in-process semaphore after the last response,
so its server cannot race client-side final flow-control writes without adding
PING traffic to the measured wire shape. A 40-process stress run completed
without a premature close. Five alternating CPU-0-pinned ReleaseFast runs on
2026-09-03, each with ten parallel 1-MiB responses, five warmups and twenty
measured batches, produced 2.687-3.056 ms/batch for netz (2.714 ms median) and
5.137-5.325 ms/batch for Hyper (5.261 ms median): netz was 1.94x faster at the
median. Every run verified the same 262,144,000-byte checksum. Three telemetry
runs used 1,623-1,630 netz allocations and 1,288,070 peak live bytes versus
35,999-36,319 Hyper allocations and 1,383,265-1,522,926 peak live bytes. Netz
therefore used about 95.5% fewer allocation calls, 99.4% fewer cumulative
allocated bytes, and 6.9-15.4% less peak live memory; its 1,162,243-byte
pre-teardown live count was 8.4% higher than Hyper's 1,072,615 bytes. These are
matched loopback workload results, not universal throughput or memory claims.

### RFC 9218 priority-aware response scheduling

When `SETTINGS_NO_RFC7540_PRIORITIES=1` is enabled, the same flow-controlled
batch writer now applies the Priority request field and later
`PRIORITY_UPDATE` signals to DATA selection:

- the lowest urgency that currently has both connection and stream credit is
  selected first;
- non-incremental responses at that urgency complete one at a time in ascending
  stream-ID order;
- incremental responses at that urgency share each application-chunk pass and
  rotate their starting stream;
- a high-urgency stream with zero stream credit does not idle usable
  connection credit that a lower-urgency stream can consume;
- priority is re-read each pass, so an update received while the writer pumps
  WINDOW_UPDATE can affect the next DATA burst.

The ordinary benchmark path remains round-robin so the Hyper comparison above
keeps its previous equal scheduling shape. An opt-in internal workload uses one
urgency-0 non-incremental stream, four urgency-2 incremental streams and five
urgency-5 incremental streams:

```sh
taskset -c 0 zig build bench-http2-flow -Doptimize=ReleaseFast -- \
  --priority --parallel=10 --body-bytes=1048576 \
  --stream-window=8192 --connection-window=65535 \
  --warmup=2 --iterations=5
```

Two sets of three CPU-0-pinned 2026-08-19 runs:

```text
7.880-8.015 ms/10-stream batch
1,247-1,268 body MiB/s
```

This is an internal overhead/repeatability baseline, not a cross-stack ratio.
The audited Hyper dependency, h2 0.4.15, queues streams without RFC 9218
urgency/incremental state and therefore cannot run an equal semantic workload.
End-to-end tests prove non-incremental stream-ID order, incremental sharing,
Priority-header ordering, PRIORITY_UPDATE precedence, and use of lower-urgency
connection credit while a more urgent stream has no stream credit.

## Current feature comparison

| Area | netz | hyper |
| --- | --- | --- |
| HTTP/1 client/server | Backend-neutral `std.Io`, native TLS 1.3 client/server, persistent/pipelined serving, bounded concurrent TCP/Unix/TLS listeners, long-running supervisors with cancellation plus accept/connection error policy, configurable DNS/TCP connect, TLS handshake, and caller-owned absolute per-request-head deadlines over TCP/TLS, stateful fixed/chunked writers, client/server Expect/100-continue, observable bounded informational responses, and callback-streaming fixed/chunked/close-delimited readers. A caller-owned request deadline preserves a partial head for an explicit later retry, while configured Slowloris protection retains its fail-closed connection policy. Aggregate request/response transport errors retire the connection after validation but before any possible reuse, including automatic 100, CONNECT/Upgrade, and coalesced or borrowed response batches; deterministic preflight failures remain retryable. Successful CONNECT and generic Upgrade handoffs permanently exit HTTP framing on both endpoint roles, so a pool closes the handed-off socket instead of returning it to idle reuse. A thread-safe bounded HTTP/HTTPS client pool reuses eligible idle connections per scheme/authority, exposes exclusive leases for streaming APIs, caps the combined idle/leased/connecting population, reports that live count, and offers relative/absolute FIFO capacity waits with wakeups on release, failure, eviction and close. It also enforces a monotonic idle timeout, evicts least-recently-used idle entries, discards non-reusable responses, and retries a stale reused connection once only for idempotent methods. Certificate-verified HTTPS interop with Hyper is exercised in both endpoint roles; installed curl 8.5.0 also verifies the production server over cleartext and certificate-verified TLS with exact request/response and persistent reuse checks | Async runtime integration, mature ecosystem and generic Body polling; its server header-read timeout has equivalent absolute per-head semantics |
| HTTP/1 strictness | Case-sensitive RFC token methods, including allocation-free borrowed extension methods and registered QUERY safety/idempotency; Host/authority, TE/CL, CONNECT/HEAD/status body semantics, trailers, 100-continue only after complete request-head/framing validation, ordered 1xx observation and bounded interim chains | Mature RFC behavior and broad production use |
| HTTP/2 | Prior-knowledge TCP/Unix client/server, h2c Upgrade, and native TLS 1.3 client/server with mandatory `h2` ALPN, optional/required client authentication, and separate resolved-address plus TLS-host/authority connection; configurable DNS/TCP connect budgets; symmetric single-connection `serveConnection` helpers plus bounded concurrent and long-running supervised TCP/Unix/TLS serving; an authority-keyed, total/idle-bounded exclusive connection pool for cleartext and verified TLS that reuses HPACK state, offers FIFO timeout/deadline capacity waits, retries a stale reused socket once only for idempotent methods, and discards GOAWAY, active-stream and push-capable connections; HPACK, bounded ordered informational callbacks, push, priorities, fixed or opt-in BDP-adaptive receive flow control, graceful GOAWAY draining, public Last-Stream-ID retry classification, tunnels/RFC 8441, explicit absolute-deadline PING round trips, and single-reader inactivity-aware keep-alive cycles with active/idle policy; certificate-verified TLS interop with Hyper/h2 is exercised in both endpoint roles, including 1xx, push, and push opt-out. Separate curl 8.5.0/nghttp2 1.59.0 and nghttp2 1.68.1 clients verify h2c/TLS requests, response headers/bodies, distinct streams on one connection, certificate trust, and TLS ALPN | Tokio h2 integration and production client/server, including automatic BDP-adaptive receive flow control and background keep-alive interval/timeout/idle policy |
| HTTP/1 direct pipeline sample | 0.711-0.752 us/request pinned | 0.836-0.866 us/request pinned |
| HTTP/1 fixed 1-MiB duplex | 268.72-270.10 us/op pinned | 288.61-293.14 us/op pinned |
| HTTP/1 chunked 1-MiB duplex | 284.04-286.06 us/op pinned | 414.64-417.45 us/op pinned |

With server push disabled, a structurally valid peer PUSH_PROMISE is a
connection-level RFC 9113 protocol error in every aggregate, streaming, and
batch response path. Netz emits `GOAWAY(PROTOCOL_ERROR, "push-disabled")`,
returns the existing `InvalidFrame` API error, and prevents the connection from
being reused. The real h2c regression observes the exact wire error.

HTTP/1 method parsing and writing now follow RFC 9110 section 9.1's complete,
case-sensitive `method = token` grammar instead of rejecting every method
outside a fixed enum. Registered methods retain tagged fast paths, including
QUERY's safe/idempotent classification, while extension methods borrow their
wire or caller storage and remain conservatively unsafe and non-idempotent.
Malformed tokens are rejected before output, and lowercase spellings such as
`head` remain extensions rather than accidentally receiving HEAD response-body
semantics. Unit and real TCP client/server tests cover the full token alphabet,
invalid bytes, exact serialization, and end-to-end PURGE handling, matching
Hyper's `Method::from_bytes` capability without adding parse-time allocation.
The bidirectional Hyper process gate sends PURGE in both directions over
cleartext and certificate-verified TLS, verifies the exact case-sensitive
method and target at the independent peer, sends it on an already reused
netz-client connection, and continues with a later Expect exchange on the
Hyper-client connection.
The HTTP/1, HTTP/2, and HTTP/3 pool paths now derive safe/idempotent method
classification from one shared case-sensitive helper. In particular, QUERY is
eligible for the same single stale-connection retry as GET or PUT on every
HTTP version, while lowercase or unknown extension names remain ineligible.

The Hyper process gate now also establishes a dedicated persistent connection
for two URI-based requests through `http1.client_pool.Pool`, in both cleartext
and certificate-verified TLS modes. Hyper counts exactly two requests on that
single accepted socket, while netz verifies case-insensitive authority reuse
and one idle pooled connection afterward. This is direct cross-process evidence
for the pool rather than inference from the standalone persistent Client tests.
| HTTP/2 consecutive empty | 9.55-9.96 us/op pinned | 12.51-12.54 us/op pinned |
| HTTP/2 consecutive 10-byte POST | 10.09-10.38 us/op pinned, coalesced frame submission | 41.15-41.37 ms/op pinned, delayed-ACK cliff on this host |
| HTTP/2 consecutive 100-KiB POST | 23.52-23.57 us/op pinned, streaming receive | 37.24-38.68 us/op pinned |
| HTTP/2 parallel x10 empty | 26.35-26.60 us/batch pinned | 47.50-48.46 us/batch pinned |
| HTTP/2 parallel x10 × 100 × 10-KiB request chunks | 1.64-1.74 ms/batch pinned | 3.36-3.40 ms/batch pinned |
| HTTP/2 parallel x10 × 1-MiB responses | 1.663-1.671 ms/batch pinned | 2.957-3.035 ms/batch pinned |
| HTTP/2 parallel x10 × 1-MiB responses, 8-KiB stream window | 7.367-7.447 ms/batch pinned | 10.192-10.379 ms/batch pinned |

Both bounded client pools now treat idle sockets as reclaimable rather than as
permanent occupants of the global connection budget. If an acquisition for a
new authority reaches `max_connections` while another authority has idle
capacity, the least-recently-used idle socket is closed and its accounting slot
is transferred directly to the new connection attempt. Checked-out leases are
never evicted, and a genuinely all-leased/all-connecting pool still returns or
waits on `ConnectionLimitReached`. Cross-authority TCP regressions for HTTP/1
and HTTP/2 set total and idle capacity to one, proving the second origin
connects, the first socket observes EOF, and the live count never exceeds one.
Capacity waits now use a shared allocation-free intrusive FIFO admission queue
rather than generation broadcasts. New acquisitions cannot barge ahead of
blocked callers; timeout/cancellation unlinks a stack-owned ticket and wakes its
successor. Real TCP tests hold the sole slot, enqueue two waiters in a known
order, and prove that they acquire in that order.
HTTP/1, HTTP/2, ordinary HTTP/3 and dispatcher-shared HTTP/3 leases also make
`release` and `discard` idempotent on the same handle. Ownership is marked
inactive before returning or destroying the connection, so repeated cleanup
cannot duplicate an idle entry, close an already transferred socket, decrement
capacity twice, or remove a reused dispatcher route. Real pool tests cover both
release-then-discard and discard-then-release while checking idle, leased,
connection and route counts. As with other Zig resource handles, callers must
not explicitly copy an active lease.
HTTP/1 pooled one-shot requests also expose an end-to-end absolute deadline: a
single timestamp spans FIFO capacity waiting, a new DNS/TCP/TLS connection when
needed, stale-idempotent retry, and the complete response. HTTP/2 pooled
one-shot requests expose the same contract through TLS and SETTINGS bootstrap;
both pools provide relative-timeout wrappers that convert once at API entry.

Both protocol `Limits` now also expose a TCP connect timeout used by literal-IP,
hostname, URI, Unix-socket and pooled connection paths. Host resolution and all
address attempts share one awake-clock deadline; a concurrently completed but
unselected socket is closed. HTTP/1 direct-address, hostname, Unix, standard TLS
and vail TLS constructors additionally accept a caller-owned absolute deadline.
HTTP/1 TLS servers expose matching post-accept timeout/deadline forms for the
complete TLS handshake, including already accepted streams; configured TLS
handshake limits remain stricter.
The standard-library TLS client initializer and low-level complete-request /
request-aware-response stream adapters likewise expose relative-timeout and
absolute-deadline pairs, allowing protocol upgrade adapters to choose either
budget form without duplicating timestamp conversion.
HTTP/2 direct-address, hostname, Unix and TLS constructors expose the same
contract through the complete SETTINGS bootstrap. TLS paths preserve the outer
deadline across DNS/TCP and TLS while all paths retain stricter phase limits.
HTTP/2 TLS servers expose matching post-accept timeout/deadline forms spanning
TLS 1.3, ALPN validation, and the HTTP/2 preface/SETTINGS bootstrap.
Cleartext TCP and Unix-domain HTTP/2 servers expose the same post-accept
timeout/deadline contract for their complete preface/SETTINGS bootstrap; TCP
also accepts an already-dispatched stream under either a relative timeout or a
caller timestamp. TLS already-accepted streams expose the same pair across TLS,
ALPN validation, and HTTP/2 bootstrap.
Both protocol constructors also provide relative-timeout wrappers that convert
the end-to-end budget once at entry.
Ordinary timeout-based APIs remain separate from HTTP
response/preface handshake budgets, and failed pool connects continue to return
their reserved capacity slot.

Native HTTP/1 vail TLS client and server connections expose their authenticated
peer chain, negotiated ALPN/cipher suite/hash, RFC 8446 exporter, explicit
KeyUpdate and update counters. They also expose explicit TLS write-half close
and authenticated peer-close state. The record stream maps a valid
`close_notify` to byte-stream EOF, keeps fatal or malformed alerts as errors,
and distinguishes transport EOF before a record from a partially received TLS
record. Receiving `close_notify` does not disable the local write direction, so
servers can finish an HTTP response and send their reciprocal notification.
The client keeps the standard-library HTTPS
path as its compatibility default and offers `connectVailTlsHost` /
`requestUriVailTls` when those advanced features are required. CONNECT/Upgrade
tunnels preserve the vail connection and KeyUpdate access after the HTTP parser
hands off the encrypted byte stream. The Hyper HTTP/1 process gate now runs its
HTTPS client direction through that vail path: rustls sends a real reciprocal
KeyUpdate before the response, netz verifies the server chain and negotiation
metadata, responds exactly once, and completes the remaining HTTP/1 scenarios.

RFC 9218 scheduling now selects urgency and the lowest-ID exclusive
non-incremental stream in one candidate scan rather than two. The priority-aware
10-stream/1-MiB/8-KiB-window benchmark measured 7.79–7.96 ms/batch and
1.26–1.28 GiB/s across three CPU-0 runs; the immediately preceding two-scan
sample was 8.03 ms/batch. HTTP/2 and HTTP/3 both carry replacement-order tests.

HTTP/1 CONNECT and Upgrade tunnels now expose timeout and absolute-deadline
reads across cleartext, standard-library TLS, and vail TLS transports. Bytes
that the HTTP parser read past the switching response/request are returned
before validating or arming the timeout, while later TLS record reads retain
one absolute caller budget. A regression covers buffered upgrade bytes, a
silent-peer timeout, and successful reuse of the same tunnel afterward.
Complete aggregate HTTP/1 client requests and streaming request writers also
expose response timeout/deadline methods. Their deadline spans informational
heads, the final head, fixed/chunked/close-delimited body, and trailers; a
configured response-head timeout is still enforced when it expires earlier.
Both the complete-request and split request-writer forms can retain ordered
informational callbacks under that same timeout/deadline budget. Their
callback-streaming counterparts provide the same combinations while retaining
the borrowed-body and final-head callbacks.
Because HTTP/1 cannot cancel one exchange independently, timeout marks the
connection unusable so pools cannot replay against ambiguous leftover bytes.
One-shot HTTP and HTTPS URI helpers additionally accept an end-to-end absolute
deadline spanning DNS/TCP, standard or vail TLS, request emission, and the same
complete response boundary, while retaining every stricter phase timeout.
Relative-timeout wrappers convert their budget once at the one-shot API entry.
The reusable low-level TCP stream adapters now expose the same timeout/deadline
pair for buffered requests and request-aware responses. One deadline covers
the complete head/body/trailer sequence while bytes already read for the next
pipelined exchange remain in caller-owned storage. Both buffered and
unbuffered request-aware response adapters retain informational-response
callbacks on their bounded variants without granting the final response a new
budget after each 1xx head.
Complete aggregate client requests reserve the same generation-tagged exchange
slot as streaming writers before any transport write and retain it through all
informational heads, the final head, body, and trailers. An informational
callback therefore cannot reenter the same HTTP/1 client and interleave a
second request into the active response; it receives `ConnectionBusy`. Pure
local request-validation failures still roll back to an idle reusable client,
transport or response failures remain terminal, and a complete keep-alive
response releases the slot for the next request. A persistent-connection
regression observes 103, rejects callback reentry before another wire write,
then completes a second request on the same socket.

HTTP/2 aggregate and callback-streaming client requests now expose relative-
timeout and absolute-deadline forms on both complete requests and split
request/response flows. One deadline covers the complete response, including
permitted connection-control traffic and fragmented header blocks, without
renewal. Aggregate and callback-streaming complete-request, split-response, and
streaming-request writer variants can retain ordered informational-response
callbacks under that same budget, so a 1xx response cannot grant extra time to
the final response head or body.
All callbacks that borrow HTTP/2 decoder or DATA-frame storage now execute
under an explicit single-reader guard. They may still open or write independent
streams, preserving normal HTTP/2 multiplexing, but a recursive aggregate,
streaming, batch, tunnel, PING, or control read fails before advancing the
shared frame reader. Stream-reset and abandonment operations that would release
the callback's outer lifecycle are rejected under the same guard.
A two-stream regression sends both requests first, tries to read and reset the
sibling from stream 1's 103 callback, observes `UnexpectedFrame` for both, then
completes both responses in order after the outer callback returns.
Handshake-backed and preconfigured-key HTTP/3 clients apply the equivalent
single-owner rule while aggregate response, whichever-ready, and pushed 1xx
callbacks run. Recursive response, push, control, or CONNECT-DATAGRAM reads
return the local `ConcurrentRead` error before consuming buffered state or UDP;
one-attempt send-only operations remain available. State-destructive request or
push cancellation is rejected in the same callback scope, preventing an outer
aggregate from releasing its own lifecycle or push storage while decoding a
borrowed head. Real handshake, protected two-response, and protected push
regressions verify the outer message and untouched sibling still complete after
rejected reentry.
The bodyless aggregate, callback-streaming bodyless, and flow-control-
preflighted body-bearing batch APIs also expose timeout/deadline pairs,
including their informational-observer forms. Relative budgets are converted
once before request staging, and the same absolute deadline spans all
interleaved control frames, final heads, continuations, DATA, trailers, and
PUSH_PROMISE continuation blocks; completion of one member never renews the
remaining batch. Deadline validation precedes stream-ID, HPACK, flow-control,
and socket mutation. The write side retains the transport's blocking contract,
so the deadline bounds response aggregation or callback delivery rather than
interrupting a socket syscall already in progress. A transport read timeout
after submission sends one best-effort reset batch for only the unfinished
streams, releases all local stream state, and retires the connection from
reuse. A callback that independently returns `error.Timeout` remains an
application rejection and therefore cancels its batch without poisoning the
otherwise synchronized connection. A partial HEADERS or DATA transport write
is fail-closed because its visible wire prefix cannot be rolled back safely.
Body-bearing batches can now select callback-streaming responses as well as
owned aggregation. The new `requestBodyBatchStreaming*` family reuses the same
transactional HPACK staging, request DATA batching, duplex flow-control pump,
1xx correlation, cleanup, and deadline-aware response state machine; it retains
only owned response headers/trailers and a byte count while delivering DATA.
In three alternating CPU-0 paired runs of an internal ten-stream shape with
exactly 1 MiB in each direction, callback streaming took 3.422-3.540 ms/batch
versus 6.744-7.020 ms/batch for aggregation. Its measured peak live memory was
155,557 bytes versus 10,640,263 bytes, and it eliminated all fifty
1-MiB response allocations across five measured batches. This is a
same-runtime API comparison, not an external Hyper ratio.
The bounded callback-streaming APIs also have final-head variants for complete
requests, split response reads, and `RequestWriter`. They invoke the final-head
callback after every observed 1xx head and before the first DATA slice, while
the original absolute deadline continues through body and trailers. A callback
that returns `error.Timeout` is treated as an application rejection: it cancels
only that stream and does not poison an otherwise reusable connection.
A timeout sends RST_STREAM(CANCEL) best-effort and marks the connection
unusable because discarded HPACK/body state cannot safely be reconstructed;
client pools consequently discard that lease. Netz also exposes
one-shot HTTP/HTTPS URI deadline helpers that preserve that same absolute
timestamp across DNS/TCP, TLS, SETTINGS bootstrap, and the complete response;
matching relative-timeout wrappers convert once before any network work.
h2c Upgrade one-shot and existing-stream helpers provide the same timeout and
absolute-deadline forms: one caller budget spans TCP when applicable, the
HTTP/1.1 101 response, HTTP/2 SETTINGS bootstrap, and the complete stream-1
response without renewal, while stricter connect and handshake limits remain
in force. The upgrade request may carry a fixed-length or chunked body plus
trailers; the server returns those complete HTTP/1.1 bytes as the already
half-closed HTTP/2 stream 1 request, matching RFC 7540 section 3.2 semantics.
Server-side `acceptUpgradeWithTimeout` and `acceptUpgradeWithDeadline` apply
one outer budget after TCP accept through the complete Upgrade request and the
HTTP/2 SETTINGS exchange rather than granting a fresh timeout after 101.
HTTP/2 Extended CONNECT now exposes matching request/response timeout and
absolute-deadline forms. The client checks the deadline before request emission,
then preserves it across informational or connection-control frames, fragmented
HPACK, and the final successful response head; timeout cancels the stream and
makes discarded aggregate state ineligible for pooled reuse. The server reader
carries one deadline through the complete request header block and preserves a
partially received frame for retry when no stream has yet been admitted.
Client attempt variants also preserve a final non-2xx status, owned response
headers, bounded DATA body, and final trailers instead of collapsing
authentication, redirect, and retry policy into `InvalidStatus`. Rejected
streams are fully drained and retired so the same HTTP/2 connection remains
available for a later sibling request; body overflow cancels only that stream,
and the compatibility methods still drain the rejection before requiring a 2xx
tunnel. The server's matching rejection helper uses ordinary HTTP/2 response
framing and derives Content-Length from the supplied body.
The RFC 9220 adapter now applies the same rejection-entity contract over
HTTP/3: attempt values retain bounded DATA and trailers, reject oversized
declared Content-Length before body allocation, skip informational heads, and
fully drain compatibility failures. Its server-side `rejectWithBody` uses the
paced aggregate writer so flow-control recovery, generated Content-Length, and
trailers share normal HTTP/3 response semantics. A caller-owned H3 session is
restored after a complete rejection and remains usable for sibling requests; a
limit failure cancels only the offending CONNECT stream. Caller-owned server
sessions are likewise restored after an explicit rejection or an abandoned
pending decision; the latter reports only that CONNECT's cancellation before a
sibling request proceeds.
Aggregate and callback-streaming server request readers now provide the same
relative-timeout and absolute-deadline forms across initial headers, DATA,
trailers, interleaved connection control, and queued complete sibling requests.
The head-callback streaming form has matching bounded variants so applications
can initialize a decoder without granting the body a fresh budget. A timeout
before any request stream is admitted retains partial frame-reader bytes for a
later retry. Once HEADERS admits a stream, both readers send
RST_STREAM(CANCEL), retire its flow-control and priority state, cancel any
admitted sibling requests made unreachable by the failure, and fail the
connection closed because stack-owned HPACK/body progress cannot be safely
reconstructed.
All public HTTP/1 and HTTP/2 request/response and pool deadline entry points
reject timestamps outside the awake-clock domain before parsing, writing, or
reserving pool capacity, matching the constructor deadline contract.
Netz also exposes
`Connection.pingWithTimeout(data, timeout)` and
`Connection.pingWithDeadline(data, deadline)` for a bounded HTTP/2
liveness round trip and `KeepAlive.run(connection)` for repeatable scheduled
keep-alive cycles. Passive PING, GOAWAY, RST_STREAM, WINDOW_UPDATE, and RFC
9218 PRIORITY_UPDATE readers now provide both timeout and absolute-deadline
variants, and HTTP/2 tunnels
provide `readWithTimeout` alongside `readWithDeadline`. A tunnel read holds the
connection's single frame-reader lease only for that call; if it encounters a
sibling response, it preserves the complete frame or fragmented HPACK block in
wire order and returns `ResponseAvailable` so the owning response reader can
consume it without loss. The keep-alive driver
waits until a full interval of peer receive inactivity, supports Hyper-shaped
active-stream versus `while_idle` policy, and
then requires the matching ACK within a separate timeout. Both use awake-clock
absolute deadlines: stale ACKs and interleaved SETTINGS, PING, WINDOW_UPDATE,
PRIORITY, GOAWAY, and extension control traffic cannot renew the ACK budget.
Interleaved application frames are retained in wire order for the next request/
response reader. `Limits.max_pending_ping_frames` bounds that queue; the frame
that reaches the cap remains recoverable even though the probe returns
`MessageTooLarge`. Local cleartext tests cover silent-peer timeout, stale-ACK
and control-frame pressure, receive-activity rescheduling, idle skip/opt-in,
active response preservation, request/response frame preservation, queue-cap
preservation, partial-frame timeout recovery, one-budget control-frame waits,
and tunnel timeout recovery; native TLS tests cover both direct PING and
scheduled idle keep-alive. Unlike Hyper's continuously polled background
connection driver,
the blocking netz driver deliberately runs one cycle at a time and must be the
sole frame reader; applications repeat it from their owning event loop.

Peer-provided RFC 8336 ORIGIN and RFC 7838 ALTSVC metadata are also bounded for
the lifetime of each HTTP/2 connection. `Limits.max_peer_origins` and
`Limits.max_alternative_services` default to 256; duplicate origins consume no
new capacity, and an existing ALTSVC key may still be replaced at capacity.
Additional unique advisory entries are ignored without closing the connection.
Focused state and wire tests verify that retained counts and capacities stop
growing while later PING traffic remains usable. Their list/index pairs are
now allocated independently on first use rather than embedded in every
connection. The speculative HPACK decoder used only while synchronizing a
two-phase graceful shutdown and the second HPACK encoder used only for
transactional batch writes are likewise allocated on first use. Server-push
reservation queues and indexes now use the same lazy ownership model; clients
that advertise `SETTINGS_ENABLE_PUSH=0` and servers that never initiate push do
not allocate it. RFC 9218 update and idle-reservation indexes are also retained
only after the first priority operation; the ordinary stream lifecycle takes a
null-state fast path. On 64-bit targets these changes reduce
`runtime.Connection` from 2,496 to 1,840 bytes: 80 bytes from peer metadata,
112 bytes after alignment from the cold decoder, 160 bytes from batch staging,
160 bytes from push state, 112 bytes after alignment from priority state, and
32 bytes after alignment from tag-free pending frame/header slots. Client and
server duplex streams also drop from 128 to 120 bytes and from 216 to 208 bytes
respectively.
Layout, disabled-limit, ownership-transfer, retry, and exhaustive
allocation-failure tests cover these boundaries; this is fixed-state evidence,
not a throughput claim.

Inbound HPACK decoding now enforces `Limits.max_header_list_size` while walking
the compressed block rather than after materializing every header. Static,
dynamic and Huffman-backed fields are charged using RFC 9113's uncompressed
`name + value + 32` accounting before allocating application-visible output.
The two `usize` limits emitted as `SETTINGS_HEADER_TABLE_SIZE` and
`SETTINGS_MAX_HEADER_LIST_SIZE` must fit the protocol's 32-bit setting value;
connection and listener construction now rejects larger values instead of
silently advertising `2^32-1` while enforcing a different local policy. The
maximum representable value is preserved exactly in the encoded SETTINGS.
HPACK prefix-integer decoding likewise accepts the complete `u64` range. Its
final high-order group uses checked shifting and addition, while unterminated
or wider encodings return `IntegerOverflow` instead of truncating high bits or
relying on a build-mode overflow trap. Boundary tests round-trip `u64::max`
and reject both terminal and continuing over-width inputs.
After the limit is crossed, the decoder still consumes and validates the rest
of the block and applies incremental-indexing updates, keeping the connection's
compression context synchronized for later streams without retaining oversized
output. Failing-allocator tests cover the allocation-free non-indexed rejection
path, while a second block proves indexed state survives an oversized first
block. Incremental literals also interpret all six name-index bits correctly;
the high index bit is no longer confused with the Never Indexed marker from
the separate four-bit representation. HPACK dynamic-table entries and decoded
dynamic indexed fields now each keep name/value bytes in one contiguous
allocation; eviction, clear, clone and allocation-failure tests cover the
single-owner invariant while the public field slices remain unchanged. A
warmed-table regression verifies each additional insertion needs one string
allocation rather than two. Decoder tables additionally omit the encoder-only
name and exact-value hash indexes: inbound wire references are positional, so
maintaining those maps spent two probes and retained capacity without serving
a decode operation. The HPACK benchmark now obtains its monotonic clock from
zio and reports the backend explicitly; its historical numbers below predate
that migration. It reports encoder and decoder churn separately; three pinned
ReleaseFast runs measured 277-282 ns/insert with
reverse indexes and 46-50 ns/insert for the decoder's positional-only table.
Allocation, eviction, clone and failure-path tests verify the no-index
lifecycle while encoder lookup behavior remains unchanged.
HPACK and QPACK now also share one canonical Huffman codec module. HPACK's
encoder writes compressed string bytes directly into its already-reserved
header-block output instead of allocating a temporary encoded slice and then
copying it. A warmed retained-scratch regression uses a failing allocator to
prove compressed never-indexed fields need no transient allocation. Three
pinned ReleaseFast HPACK runs measured 261-265 ns for stateful encode-only,
down from 316-319 ns immediately before this change.
HTTP/3 local SETTINGS validation also rejects every configured numeric value
that cannot be encoded as a 62-bit QUIC varint; the default
`max_field_section_size = u64::max` remains the intentional omitted-setting
sentinel. Handshake session construction applies this before binding or
connecting UDP and now consistently rejects a QPACK blocked-stream limit above
the runtime's concurrent request-stream capacity. Codec boundary tests cover
all six numeric SETTINGS fields and the maximum legal varint, with QPACK table
capacity additionally bounded by the platform's addressable `usize` range.
The runtime owning decode path first replaced per-field Huffman/dynamic output
allocations with a stack-staged byte sequence, a descriptor array and one
shared contiguous string block. Offset-based plans keep slices valid while
scratch grows, and bounded decode still consumes incremental-indexing fields
after an output limit so the connection table stays synchronized. Three pinned
runs measured that two-output-allocation stage at 1,246-1,253 ns for this
seven-field benchmark; the later single-allocation layout is described below.
HTTP/2 receive paths now decode the overwhelmingly common END_HEADERS block
directly from the buffered frame instead of first copying it into a temporary
ArrayList. Fragmented HEADERS and PUSH_PROMISE sequences retain one assembly
buffer per connection because each continuation read invalidates the previous
frame borrow; consecutive fragmented round trips verify stable capacity and
backing storage. A focused single-frame test verifies that this scratch remains
entirely unallocated. The full 2,958-test Netz suite, strict h2spec 147/147 run,
bidirectional Hyper h2c/TLS gate, and h2 Push/1xx gate remain green. Five
CPU-0 runs of the matched h2c matrix measured 9.555-9.920 us for consecutive
empty requests, 10.051-10.498 us for 10-byte requests, 22.744-22.921 us for
100-KiB requests, 25.630-25.815 us per ten-request empty batch, 1.658-1.707 ms
for the ten-stream request-body batch, and 1.685-1.703 ms for the ten-stream
1-MiB response batch. These are current regression ranges; the dated matched
Hyper comparison above remains the cross-stack evidence.
Aggregate request and response reads now also keep the complete common-case
wire frame borrowed through immediate HPACK decode/body copy, matching the
existing streaming response path. A queued application frame remains owned
until the iteration finishes, and fragmented HEADERS copy the first fragment
into connection-owned continuation scratch before advancing the frame reader.
Warmup-scoped h2c allocator telemetry attributes the removed copies exactly:
the empty exchange fell from six to four allocations per request, eliminating
one 19-byte request frame and one 11-byte response frame while retaining the
two owned HPACK allocations at each endpoint at that intermediate stage.
Existing CONTINUATION and interleaved-request tests cover borrowed lifetime and
the pending-frame owning fallback.
HPACK owned decode then coalesces each descriptor array and its contiguous
name/value bytes into one aligned allocation. `freeOwnedFields` detects that
layout while retaining compatibility with existing callers that provide a
separate `block_storage`. The same warmed empty exchange therefore fell again
from four allocations to two per request, one owned header block at each
endpoint, with unchanged cumulative bytes. Allocation-failure coverage and
pointer-layout assertions exercise the combined ownership contract; an
integration regression swaps in allocation-tracking allocators around the
second aggregate request and response read and requires exactly one HPACK
allocation on each side.
Known-length aggregate request bodies now reserve their validated
`Content-Length` exactly and transfer that buffer directly into `OwnedRequest`.
Previously a 10-byte POST grew to a 143-byte `ArrayList` allocation and then
allocated/copied the exact 10-byte result. Warmed h2c telemetry now reports
three allocations per exchange rather than four, and the integration
allocation regression first warms DATA flow-control storage before requiring
only the combined request-header block and exact body allocation on the server.
Known-length aggregate responses now use the same exact reservation and direct
ownership transfer. A dedicated 10-byte response scenario dropped from four to
three allocations per exchange and removed the same transient 143-byte growth
block; its warmed fixed-binary range was 10.006-10.363 us/op versus the captured
16.843-us pre-change sample. Client-side allocation regression permits only the
combined response-header block and exact body allocation after warmup.
Aggregate response batches now likewise consume ordinary frames through the
reusable borrowed reader rather than duplicating every response frame. The
parallel x10 empty workload removed 20,000 exact 11-byte allocations across
2,000 measured batches (80,000 to 60,000 total calls). A focused batch test
warms the connection, reads three responses through the aggregate state
machine, and permits only their three combined HPACK ownership blocks.
Transactional batch encoders now use a second connection-owned HPACK encoder
as reusable staging storage. Copying live state reuses dynamic-entry blocks,
both lookup-index tables and encoded scratch; a successful write swaps live and
staging encoders, while a validation/encoding failure leaves live state intact.
The warmed parallel x10 empty workload consequently fell from 60,000 to 40,000
allocations over 2,000 batches. Its exact-size telemetry contains only one
request and one response HPACK ownership block per exchange; encoder staging is
allocation-free. HPACK fail-first reuse and runtime rollback tests protect both
the allocation and transactional guarantees.
The single-stream streaming request path now borrows its initial HEADERS frame
as well as subsequent DATA. The 100-KiB POST telemetry dropped from 6,020 to
4,020 allocations over 2,000 requests by removing one exact 26-byte frame copy
per request; the two remaining steady-state allocations are the request and
response HPACK ownership blocks. The integration allocation test exercises the
same header-plus-streamed-DATA path after warmup.
The bidirectional Hyper process gate now exercises that boundary directly over
h2c and TLS. A netz client waits through an idle interval, receives Hyper/h2's
PING ACK, and completes another request on the same connection. In the reverse
direction Hyper enables its actual 25 ms background keep-alive with idle probes
using the harness's Tokio-backed implementation of Hyper's timer interface,
waits 100 ms, and then completes another request through the netz server. This
proves netz services external PINGs rather than relying only on local peers.
The same process gate now runs two URI requests through `http2.client_pool.Pool`
over both h2c and certificate-verified TLS, requires distinct response bodies,
and verifies one idle/total connection afterward while the Hyper process
confirms that both requests arrived on its single accepted connection.
Single-stream cancellation and ordinary GOAWAY now use caller-buffer frame
encoders: the fixed 13-byte RST_STREAM always stays on the stack, and common
GOAWAY debug strings use a bounded 256-byte stack path with an exact heap
fallback only for larger diagnostics. The public helpers retain ArrayList
compatibility while wire-parity and short-buffer tests cover the direct form.
Late DATA, HEADERS, and duplicate RST_STREAM frames for locally reset streams
are ignored through a bounded, configurable `Limits.max_reset_stream_history`
FIFO with an O(1) membership index. The default retains up to 64 stream IDs
for at least `Limits.reset_stream_duration` (one second by default), while zero
capacity disables tolerance. Expired entries are reclaimed lazily without a
background timer; when the fixed capacity is full, a newer reset is left
untracked rather than evicting an older stream before its retention deadline.
Capacity is reserved before a RST_STREAM becomes visible, including batch
cancellation, so allocation failure cannot leave wire and local reset state
inconsistent.
When a valid peer request exceeds the advertised local concurrent-stream
limit, every server request reader now consumes and decodes its complete HPACK
field section, sends `RST_STREAM(REFUSED_STREAM)`, and continues serving the
connection instead of surfacing a connection-fatal flow-control error. The
refused stream advances the observed stream-ID cursor without entering active,
window, response, priority, callback, or pending-request state. Fragmented
HEADERS coverage proves that dynamic-table mutations survive refusal and can be
referenced by a later request after capacity is released; late DATA, trailers,
and duplicate resets use the same bounded reset-history policy described above.
Remotely reset requests waiting in the server's pending-accept queue are
tracked separately through `Limits.max_pending_accept_reset_streams`, matching
Rust h2's defense against reset-after-HEADERS churn that no longer counts
toward stream concurrency. Once a peer reset for a queued request is consumed,
netz immediately frees that request's owned headers/body/trailers, leaves a
small tombstone in accept order so later accepts cannot surface the canceled
stream, and decrements the accounting only when the application drains past
that queue position. The default bound is 20. Exceeding it sends
`GOAWAY(ENHANCE_YOUR_CALM, "too_many_resets")`, marks the connection locally
unusable, and drops any remaining queued accepts rather than retaining
unbounded queued-cancel memory. Focused regressions cover queued sibling
cancellation during aggregate, single-request streaming, and batch-streaming
request reads, unrelated queue integrity, tombstone slot reuse without
allocation, and the exact GOAWAY code and debug string on overflow.
The remaining fixed control helpers expose the same allocation-free boundary:
PING encodes its complete 17-byte frame and WINDOW_UPDATE its complete 13-byte
frame into exact caller-owned arrays. Their compatibility writers still grow
the destination only once and encode directly into its final storage, while
wire-parity tests and the zero-window-increment rejection cover the new API.
The runtime already wrote these two frame types as a stack header plus borrowed
payload, so it deliberately keeps that scatter/gather path rather than copying
them into a second contiguous buffer. A pinned full h2c benchmark after this
API addition measured 10.120 us for consecutive empty requests, 22.990 us for
100-KiB requests, and 27.482 us per ten-request empty batch; these are a
regression sample, not a claim that this helper-only addition accelerates the
runtime. h2spec strict remains 147/147, and the bidirectional Hyper h2c/TLS
keep-alive, cancellation and GOAWAY gate remains green.

## Remaining evidence

The shared `fuzz-parsers` target exercises strict borrowed and owned HTTP/1
request/response parsing and chunked decoding; HTTP/2 frame envelopes, known
payload shapes, SETTINGS, HPACK blocks, and Huffman input; and HTTP/3 frames,
control streams, messages, SETTINGS, QPACK instructions, and bounded field
blocks. Inputs are capped at 64 KiB and owned results are leak-checked. Default
tests replay structured seeds and deterministic mutations; Zig's `--fuzz` mode
adds coverage-guided search. The companion `fuzz-stateful` target drives
bounded HTTP/1 incremental and pipelined message sequences, HTTP/2 flow-window
and HPACK dynamic-table transitions, and HTTP/3 split control frames and QPACK
table transitions. It found and now guards an HPACK compaction bug in which
duplicate-name lookup keys could outlive their backing entry. Live socket
scheduling is additionally covered for HTTP/1 by `fuzz-http1-connection`: each
bounded input runs through the production loopback TCP client/server and checks
persistent reuse, complete and streaming fixed/chunked request bodies, chunked
response trailers, HEAD body suppression, and request/response-selected close
boundaries against an independent operation model. The sibling
`fuzz-http1-tls-connection` target carries that state model over authenticated
TLS 1.3, checks `http/1.1` ALPN and cipher metadata, and mutates bidirectional
traffic-key updates across persistent and rotated connections. The dedicated
`fuzz-http2-connection` target covers real h2c connection state: ordinary
and streaming bodies, request trailers, reversed two-stream response batches,
PING, RST_STREAM cancellation, GOAWAY and connection rotation. The sibling
`fuzz-http2-tls-connection` target carries the same state model over
authenticated TLS 1.3, checks mandatory `h2` ALPN and cipher metadata, and
mutates bidirectional traffic-key updates between HTTP/2 operations. The
dedicated `fuzz-http3-connection` target covers authenticated QUIC/TLS HTTP/3
connection state: complete and streaming bodies, request and response trailers,
reversed multiplexed responses, cancellation, HEAD body suppression, and
terminal two-phase GOAWAY.

The persistent server now treats peer EOF at an empty request
boundary as orderly retirement instead of a connection failure. A client may
send one or more complete HTTP/1 requests, shut down its write half, and still
receive every response; `serve` then returns the completed request count and
`serveUntil` reuses its worker without notifying the connection-error observer.
This does not relax request framing: a partial head, short Content-Length body,
or unterminated chunked body still fails with `ConnectionClosed`, and public
`serveOne` retains its existing empty-EOF error contract. Native TLS now has
the same HTTP boundary behavior without weakening record authentication:
authenticated `close_notify` is EOF, bare transport EOF is eligible for the
empty-request-boundary exception only, and a partial TLS record or fatal alert
remains an error. Close-delimited HTTPS response bodies complete only on
`close_notify`; a bare EOF fails with `UnexpectedEof`. Real TLS tests cover a
complete request followed by client close-notify, partial request head/fixed
body/chunked body followed by close-notify, idle raw EOF, and a one-byte TLS
record prefix followed by EOF. Record-level tests additionally cover fatal and
malformed alerts, `user_canceled` followed by `close_notify`, header/payload
truncation, and authenticated application data delivered before later
truncation.
Server limits now also expose Hyper-style `keep_alive = false` for the
connection-owning `serve*` helpers. It overrides an application-supplied
`Connection: keep-alive`, writes `Connection: close`, completes the current
response, and retires without dispatching an already buffered pipeline suffix.
Direct `readRequest`/`writeResponse` users retain explicit lifecycle control,
and the default remains persistent.
Connection-owning HTTP/1 serve helpers also reject a handler's non-final
100/102/103-style informational result. They emit one 500 response with
Connection: close, retire the connection, and return InvalidResponse instead
of reading another request while a conforming client is still waiting for the
final response. This matches Hyper's single-response service boundary; direct
writeResponse remains available for applications that explicitly send
informational heads followed by a final response.
HTTP/2 high-level handler boundaries apply the same final-response invariant
without sacrificing multiplexing: `serveOne`, same-connection concurrent
batches, and listener-level `serveConcurrent` replace any handler-returned
100-199 response with a bodyless final 500, then return or record
`InvalidStatus`. The affected stream terminates normally on the wire, siblings
and later requests remain usable, and direct `writeInformationalResponse`
continues to emit explicit 1xx heads before a separate final response. HTTP/3
development `serveConcurrent` and authenticated `serveOne` use the same
500-plus-`InvalidStatus` rule, while `sendResponseWithInformational` and
`InformationalResponse` retain explicit interim-response behavior.
Connection-owning HTTP/2 server APIs now also reflect request-read protocol
failures on the wire before returning the original local error. Malformed HPACK
emits `GOAWAY(COMPRESSION_ERROR)`, while a broken HEADERS/CONTINUATION sequence
emits `GOAWAY(PROTOCOL_ERROR)`. Direct `readRequest` remains write-free for
callers that own connection policy. The HPACK decoder records whether a shared
`BufferTooShort` came from malformed input or only the configured output-field
limit, preserving the public error contract without misclassifying resource
policy as compression failure. Real h2c tests cover `serveOne` and
`serveConcurrent`, exact GOAWAY codes, original server-side errors, and zero
handler invocation. Once a request stream has been admitted, malformed request
headers, pseudo-header omissions, negotiated Extended CONNECT violations, and
Content-Length mismatches instead receive `RST_STREAM(PROTOCOL_ERROR)`; the
server returns the original local error and can continue serving a sibling
stream on the same connection. Direct request readers retain explicit wire
policy.
HTTP/2 TCP, Unix, TLS, and h2c-upgrade listener `acceptWithTimeout`/
`acceptWithDeadline` calls now apply one absolute budget from the start of
socket acceptance through protocol bootstrap. The accept/timer race explicitly
closes any socket completed after timeout, so periodic idle-listener work and
shutdown checks cannot leak descriptors or wait indefinitely.
HTTP/1 TLS listener bounded accept uses the same shared race helper, extending
its existing TLS-handshake deadline to cover idle socket acceptance as well.
Client aggregate and streaming response readers now apply the symmetric rule:
malformed response fields, status, or Content-Length reset only the affected
stream with `PROTOCOL_ERROR`; configured response-size overflow uses
`ENHANCE_YOUR_CALM`; malformed HPACK or a broken CONTINUATION chain remains a
connection-level GOAWAY. RFC 9412 ORIGIN and the registered WebTransport stream
frame type are rejected when misplaced on request/response message streams by
both aggregate and incremental readers; the runtime emits
`H3_FRAME_UNEXPECTED`, while genuinely unknown extension frames remain
ignorable. Batch readers send the precise reset for the offending
member and `CANCEL` for other unfinished members in one write, while completed
and peer-reset members are left untouched. Too many informational responses
use `ENHANCE_YOUR_CALM`; an unterminated continuation flood is likewise a
connection error because the next frame boundary cannot be recovered. Rejected
DATA restores its already-consumed connection receive credit before stream
cleanup. Real h2c tests cover aggregate, streaming, and batch response paths,
sibling reuse, and connection-error precedence.

1. Add a cancellation-race benchmark that combines reset timing with the
   priority-aware flow scheduler. **Completed:** `bench-http2-flow --priority
   --cancel-after=8` opens ten 1-MiB responses behind 8-KiB stream/65,535-byte
   connection windows, processes eight priority-scheduled DATA callbacks, then
   cancels all unfinished members. The client now writes every RST_STREAM in
   one batch instead of one transport write per stream and drops their retained
   send/receive-window entries. Unlike generic half-close cleanup, this happens
   only at RST_STREAM, where both directions are terminal. Five CPU-0 runs took
   230.4-241.2 us from request submission through server observation of the
   reset batch. One `--stats` run
   used 293 allocations and 1,287,988 peak live bytes. Hyper/h2 has no RFC 9218
   scheduler, so that priority benchmark remains internal timing evidence.
   `zig build bench-http2-cancel-hyper -Doptimize=ReleaseFast` adds a distinct
   cross-client comparison against one fixed, pinned Hyper server. Each of five
   alternating samples uses one persistent h2c connection for twenty warmups
   and 1,000 measured batches. A batch opens a 128-KiB response and a concurrent
   sibling, consumes exactly the 8-KiB stream window, cancels the first body,
   and completes the 16-KiB sibling only after Hyper has dropped its incomplete
   response body upon observing stream cancellation; a final request proves
   connection reuse. The existing reverse-direction interoperability gate
   separately decodes and requires the exact `RST_STREAM(CANCEL)` error code.
   Repeated long five-sample runs measured netz at 132.2-153.6 us/batch by
   median and Hyper at 143.3-200.2 us/batch, a 1.044-1.433x advantage for netz
   in this shape. Short 100-batch exploratory medians ranged from a 0.939x
   regression to a 1.229x advantage and are treated as scheduler noise rather
   than folded into the claim. The netz explicit allocator peak was
   203,352-203,385 bytes
   versus Hyper's process-wide Rust requested-byte peak of 144,750 bytes; those
   allocator scopes differ and are reported without a ratio. Client process
   MaxRSS medians were 11,264-12,288 KiB for netz and 11,264 KiB for Hyper under
   BusyBox `time`, so no RSS advantage is claimed. The strict checker verifies
   every client result, all 1,020 server-observed cancellations and 1,020
   sibling completions per sample, timing arithmetic, reuse, allocation
   arithmetic, RSS source, binary hashes,
   CPU assignment, Cargo lock, and Hyper revision `084473f7`. This is a focused
   same-server cancellation/recovery result, not a general HTTP/2 throughput
   claim.
2. Run the new `bench-http2-flow --stats` allocator telemetry on the full
   netz/Hyper comparison matrix. **Completed for the primary constrained-window
   shape:** both harnesses now report allocation calls, realloc/remap calls,
   cumulative bytes, live bytes, peak live bytes and common size buckets from
   thread-safe process-wide allocator wrappers. The Hyper wrapper delegates to
   `System` and records requested sizes without recursively allocating;
   `tools/bench_hyper_http2_flow.sh` enables it only when passed `--stats`.
   The netz benchmark reports allocation
   calls, cumulative allocated/freed bytes, live bytes, peak live bytes and
   size buckets through a shared thread-safe benchmark allocator; a two-stream
   64-KiB/8-KiB-window smoke observed 293 allocations and 288,461 peak live
   bytes. Equal instrumentation is still needed on the Hyper harness before
   making a memory ratio.
   On the full 10-stream/1-MiB/8-KiB-window shape, call-stack sampling showed
   WINDOW_UPDATE flow pumping allocating one 13-byte OwnedFrame per control
   frame. The server now consumes those frames directly from retained reader
   storage. Three CPU-0 runs used exactly 1,910 allocations versus 12,948 before
   (85.2% fewer), while peak live bytes stayed 1,286,109 because the eliminated
   frames were transient. Stable runs measured 7.20-7.23 ms/batch; one noisy
   10.81-ms sample is retained as variance rather than folded into a speed
   ratio. Exact-size allocation reporting remains available for the next audit.
   Owned decoded header blocks now place every name/value string in one shared
   allocation rather than two allocations per field. The same full flow shape
   used exactly 1,488 allocations versus 1,910 before (22.1% fewer) across
   three runs; stable samples were 7.08-7.10 ms/batch and peak live memory
   remained about 1.29 MB. Push-promise ownership uses the same block-aware
   deinitializer, and tests cover both ordinary and pushed headers.
   Three matched CPU-0 runs of the documented 10-stream/1-MiB/8-KiB-window,
   five-warmup/twenty-iteration shape were repeated on 2026-08-27. Netz took
   7.433-7.458 ms/batch (7.448 ms median) versus Hyper's 10.096-10.126 ms
   (10.122 ms median), a 1.36x median throughput advantage. Both sides verified
   the identical 262,144,000-byte checksum. Netz used exactly 1,606 allocation
   calls, 1,569,363 cumulative allocated bytes and 1,288,070 peak live bytes;
   Hyper used 54,086-54,224 allocation calls, 11,664-11,760 reallocations,
   298,232,879-299,587,537 cumulative allocated bytes and 1,346,882-1,346,885
   peak live bytes. Against the median Hyper run, netz therefore used 97.0%
   fewer allocation calls, 99.5% fewer cumulative requested bytes and 4.4%
   less peak live memory. These process-wide counters include runtime setup and
   warmup in both implementations and are a matched workload result, not a
   universal allocator or RSS claim.
3. Keep the external h2spec gate current. The h2c adapter passes all 147 tests
   in h2spec v2.6.0 strict server mode (`H2SPEC=/tmp/h2spec-download/h2spec zig
   build interop-http2-h2spec -Doptimize=ReleaseFast`, reconfirmed 2026-09-10).
   The gate now supplies `--strict` itself and parses h2spec's summary so an
   empty selection, skipped case, or failed case cannot be mistaken for a
   successful conformance run. The long-lived adapter now obtains `std.Io`
   from zio and schedules accepted connections in a `std.Io.Group`, with no
   detached OS-thread fallback; its readiness line identifies
   `server_io=zio-std-io`. This covers the external h2c wire checks.
   On 2026-09-28,
   `zig build interop-http-external-clients -Doptimize=ReleaseFast` ran
   installed curl 8.5.0 (libcurl/OpenSSL/nghttp2 1.59.0) against netz
   HTTP/1.1 and HTTP/2 servers over cleartext and certificate-verified TLS, and
   nghttp2 1.68.1 against HTTP/2 over both transports. Each arm verifies two
   exact requests and responses on one connection; the HTTP/2 arms require
   distinct odd stream IDs, and nghttp TLS must report ALPN `h2`. This broadens
   real client coverage beyond Hyper without claiming exhaustive client
   behavior. The native
   TLS 1.3 HTTP/2 runtime separately has an end-to-end encrypted request test
   that verifies `h2` ALPN and the transport-derived `https` pseudo-header,
   plus no-common-ALPN rejection and required-client-certificate tests; verified
   peer chains are exposed on accepted server connections, and the vail-backed
   HTTP/2 client retains and exposes the authenticated server chain. Both vail
   TLS endpoint roles expose RFC 8446 exporter keying material for channel
   binding and typed `negotiatedCipherSuite()` /
   `negotiatedAlpn()` / `negotiatedTranscriptHash()` metadata for authentication policy and
   diagnostics. `updateTrafficKeys(request_peer_update)` sends RFC 8446
   KeyUpdate under the current epoch, rotates afterward, transparently handles
   fragmented peer updates, performs requested reciprocal updates, and exposes
   sent/received counters; the encrypted HTTP/2 test exchanges a request after
   both directions rotate. The bidirectional Hyper TLS gate independently uses
   rustls's production `refresh_traffic_keys()` API in each peer direction,
   requires netz to observe/respond exactly once, and continues HTTP/2 traffic
   on the rotated epochs. Passing `--tls` to
   the same h2spec command runs all 147 strict cases through TLS 1.3 and
   negotiated `h2` when h2spec is built with a current Go TLS stack that offers
   an X25519 key share. This was reconfirmed 147/147 on 2026-09-10 by building
   the unchanged upstream v2.6.0 commit `70ac2294` with Go 1.22.2. The old
   release binary reports Go 1.12.7 and fails its first TLS case before the H2
   preface; an OpenSSL control against the same netz listener negotiated TLS
   1.3, `TLS_AES_128_GCM_SHA256`, and ALPN `h2`, isolating that failure to the
   obsolete external ClientHello rather than the HTTP/2 or TLS server path.
   After the zio migration, both h2c and TLS strict suites were rerun against
   the upstream v2.6.0 commit `70ac2294`; each completed 147/147 with zero
   skipped and zero failed cases.
   Bidirectional interoperability now has a separate process boundary rather
   than being inferred from those h2spec server-only results:
   `zig build interop-http2-hyper-client -Doptimize=ReleaseFast` builds a
   one-shot server from the audited `~/Work/hyper` checkout and drives it with
   a netz client. Both netz endpoint roles use zio behind `std.Io`, while the
   Hyper fixture uses its Tokio current-thread executor; the terminal records
   and runner assertions bind them as `zio-std-io` and `hyper-tokio`. Hyper
   verifies the POST method, query-bearing path, request
   header, body, and request trailer; netz verifies Hyper's 201 status, response
   header, two DATA frames joined into `hyper-response`, and terminal response
   trailer. The same gate then reverses the roles: an audited Hyper client sends
   two DATA frames joined into `hyper-request` plus a terminal trailer to a netz
   server, which verifies the complete request and uses its stateful response
   writer to send two DATA contributions plus a terminal trailer. Hyper verifies
   that response. Both cancellation halves now advertise an 8-KiB stream
   receive window and the standard 65,535-byte connection window, open the
   cancel target and a sibling concurrently, and declare a 128-KiB target
   response. The receiver consumes exactly 8 KiB, proving that the response is
   unfinished and has exhausted its stream credit, then sends
   `RST_STREAM(CANCEL)`. The sender does not release a 16-KiB sibling response
   until it observes that exact cancellation; the sibling then completes on
   the same HTTP/2 connection. Hyper's server body-drop signal verifies the
   netz-client direction, while the netz server verifies Hyper's reset code.
   The netz client additionally discards DATA already in flight for its locally
   reset stream, restoring the shared credit so those bytes cannot be mistaken
   for or starve the concurrent sibling; the callback-error path likewise
   restores the triggering DATA's charged connection credit before
   cancellation. A deterministic buffered-frame regression also forces that
   cleanup WINDOW_UPDATE to fail with a terminal peer-close error after the
   late DATA and sibling response have arrived together. The client ignores
   only `SocketUnconnected`/`ConnectionResetByPeer` in this reset-cleanup path,
   restores the rolled-back local connection credit, and still returns the
   complete sibling response with exact final window accounting; ordinary
   capacity-release write failures remain observable. The gate builds the
   locked Rust harness offline after its
   crates are cached and fails on either process or
   any exact value mismatch. The same command now repeats the complete
   bidirectional request/trailer and concurrent cancellation scenarios over
   TLS 1.3: the netz client validates the fixture certificate and both sides
   require ALPN `h2`. This is direct encrypted Hyper interoperability rather
   than an inference from local TLS tests. The matrix also exercises graceful
   shutdown in both directions. Hyper starts its recommended two-phase GOAWAY
   while stream 7 is active; netz answers the synchronization PING, drains that
   stream through the narrowed boundary, and refuses to open stream 9. On a
   fresh reverse connection, netz sends `GOAWAY(last_stream_id=7, NO_ERROR)`,
   completes stream 7, and Hyper refuses a subsequent request. Both cases run
   over h2c and certificate-verified TLS, so this is peer-visible draining
   evidence rather than inference from local GOAWAY tests.
   The connection API also exposes Hyper/h2-style two-phase graceful shutdown:
   `gracefulShutdown`, `gracefulShutdownWithTimeout`, and
   `gracefulShutdownWithDeadline` first send `GOAWAY(2^31-1, NO_ERROR)`, wait
   for the exact fixed shutdown-PING acknowledgement while preserving
   interleaved application frames, and then narrow GOAWAY to the highest
   validated and admitted peer stream. If a lower local GOAWAY already exists,
   it remains the upper bound rather than being widened. A bounded wait keeps
   its original awake-clock deadline and an ACK-read timeout can be retried
   without resending either the first GOAWAY or the PING. One absolute deadline
   now covers both GOAWAY writes, the synchronization PING write, peer PING ACK
   writes encountered while waiting, and the matching ACK read over TCP or TLS.
   A write timeout is terminal because an unknown frame or TLS-record prefix may
   have reached the peer, while an ACK-read timeout remains resumable. A real
   TCP backpressure regression fills the kernel send queue and proves the first
   GOAWAY write times out without committing shutdown state. Callers must give
   shutdown exclusive frame-reader access.
   `zig build interop-http2-h2-push -Doptimize=ReleaseFast` adds direct
   server-push evidence with Hyper's audited low-level h2 dependency, because
   Hyper's high-level client intentionally sends SETTINGS_ENABLE_PUSH=0. In
   the enabled direction, the h2 server promises stream 2 from request stream
   1; netz validates the complete promised GET pseudo-header set, consumes the
   independent 200 response and exact CSS body, and also completes the parent
   response. In the reverse direction, the h2 client disables push and netz
   must reject `promisePush` before returning the normal 204 parent response.
   Both scenarios run over h2c and certificate-verified TLS. The netz endpoint
   is identified as `zio-std-io`; this direct h2 crate peer is identified as
   `rust-h2-tokio`, rather than being mislabeled as the high-level Hyper API.
   The same gate now
   also exchanges ordered 103 Early Hints and 102 Processing heads before a
   200 response in both directions. Netz exposes borrowed informational-head
   callbacks on aggregate and streaming request APIs, caps each chain with
   `Limits.max_informational_responses`, and applies that bound even to legacy
   skip-only and pushed-response paths. Multiplexed aggregate, body-bearing and
   streaming batches additionally report request index and stream ID, with
   interleaved local tests proving correlation and per-stream bounds. The h2
   client explicitly polls its
   informational queue and checks both statuses; netz checks both statuses and
   their distinct headers.
4. **Completed:** combine the bidirectional process-boundary cancellation
   cases with constrained flow-control windows and concurrent streams. The
   gate described above verifies exact CANCEL codes, target-only termination,
   connection-credit recovery, and sibling completion in both directions. This
   remains a focused loopback interoperability case rather than a
   whole-library superiority claim.
5. RFC 8441 server application frames now submit the stack-resident WebSocket
   header and borrowed application payload through a two-slice HTTP/2 tunnel
   write. The tunnel treats both slices as one flow-controlled byte sequence,
   allowing DATA frame and window boundaries to cross the join without a
   payload-sized concatenation. A constrained 8-KiB stream-window test sends
   more than 16 KiB, forcing repeated WINDOW_UPDATE and client masking cycles,
   and confirms that the H2 WebSocket adapter
   retains no frame scratch after sending in either direction; client masking
   uses a bounded 16-KiB stack buffer. `H2Connection.sendBinaryParts` retains
   one RFC 6455 message across both caller slices, and the underlying tunnel's
   slice writer permits HTTP/2 DATA frames to cross either logical join. The
   existing bidirectional Hyper RFC 8441
   process gate remains the external interoperability check. Its netz endpoint
   now obtains `std.Io` from zio, and the runner binds the peer identities as
   `zio-std-io` and `hyper-tokio`. Five CPU-0 4-KiB
   echo samples after adding H2 two-part writes measured 30.987-32.321
   us/roundtrip (31.394 us mean, 31.072 us median, 1.63% relative standard
   deviation); this overlaps the prior range and is not presented as
   a latency improvement. The full
   2,958-test Netz suite, 147-case h2spec strict gate, and bidirectional Hyper h2c/TLS
   request, cancellation, keep-alive and GOAWAY matrix remain green.
   Compressed fragmented RFC 8441 messages now use the same tunnel sequence:
   server fragments remain borrowed, common client batches use fixed stack
   storage, and oversized client fragments stream through bounded masking
   chunks. This removes the H2 adapter's final payload-sized send-frame buffer
   without giving up the common 16-frame coalescing behavior. Five CPU-0 runs
   of that 4-KiB/16-fragment compressed workload measured 37.032-38.500
   us/roundtrip (37.651 us mean, 37.372 us median, 1.55% relative standard
   deviation). A 64-KiB bidirectional regression forces the oversized masking
   fallback and disables the connection allocator after warmup on both peers.
   Uncompressed fragmentation uses the same bounded batching strategy, with a
   40-KiB bidirectional regression crossing the masking boundary.
   RFC 8441's mutually exclusive resumable application message, Ping, and Close
   transactions now share one 296-byte tagged union. Automatic Pong/Close stays
   independent because the receive owner can queue it behind an older
   application write. On 64-bit targets this reduces each `H2Connection` from
   2,000 to 1,600 bytes (20.0%) without narrowing payload, cursor, or control
   state. A layout assertion plus the existing partial-DATA, queued-auto-Pong,
   close-FIN, and fatal-reset regressions guard the new representation. The
   bidirectional Hyper h2c/TLS RFC 8441 gate was reconfirmed after this change
   on 2026-10-02, including fragmented text, Ping/Pong, bounded Close, TLS
   metadata, and traffic-key update coverage.
   HTTP/1 WebSocket application sends now expose the same single-frame
   timeout/deadline surface as RFC 8441. TCP reports an exact RFC 6455 wire
   prefix, while standard and vail TLS retain a partially submitted ciphertext
   record and expose only its fully committed plaintext prefix. Same-slice
   retries preserve the client mask, frame header, and compressed output;
   unrelated reads, sends, and TLS KeyUpdate calls fail with
   `WriteInProgress` until the frame completes.
   HTTP/1 bounded Ping and Close now share that retained-wire discipline. They
   encode once, resume only the uncommitted suffix, reject mismatched Ping or
   Close retries and prevent every other frame/read/KeyUpdate from crossing the
   pending control frame. `close_sent` is published only after full transport
   commit. Deterministic TCP and standard-WSS regressions split both control
   frames across real transport writes, reconstruct the exact masked wire image,
   and verify that the peer parses a single Ping or Close.
   RFC 8441 and RFC 9220 Close retries now enforce the same caller contract:
   while a retained Close is incomplete, a second `closeWith*` call must carry
   the original code/reason. A mismatch returns `WriteInProgress` without
   advancing the H2 flow-control cursor or emitting another H3 packet.
   Their `close_sent` flag is now published only after the complete Close frame
   and stream FIN commit; ordinary sends, receives, and TLS/QUIC key updates
   uniformly return `WriteInProgress` while that retained control frame exists.
   Bounded Ping has the same invariant and accepts a same-payload retry through
   either `pingWith*` or `continuePing*`; mismatched retries do not advance the
   H2/H3 transport cursor.
   Arbitrary multi-slice single-frame sends now have one native H1/H2/H3 A/B
   gate as well. It compares an explicit caller-side join with direct
   `sendBinarySlices` under the same uncompressed 4-KiB/eight-part persistent
   echo shape at both endpoints. The runner pins one CPU, alternates execution
   order, takes five-sample medians, and strictly verifies the protocol,
   transport, workload, logical bytes, checksum, and completion records. The
   The first 2026-09-09 CPU-0 run exposed ratios of 1.506 for H1, 1.017 for
   H2, and 1.382 for H3. Routing H1 through the existing POSIX wide-iovec
   writer and grouping H3 borrowed ranges into packet-sized DATA contributions
   reduced a subsequent final-code five-sample run to 1.008, 1.002, and 1.022
   respectively. H3's cursor commits only after a successful send, preserving
   retry semantics without a payload-sized join. This establishes reproducible
   API-shape and optimization evidence, not an external-library or equal-wire
   claim; no ratio is used as a gate threshold.
