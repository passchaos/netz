# netz architecture and performance doctrine

This document is the top-level design authority for netz. Per-protocol parity
documents describe feature completeness and their own evidence; this document
defines the architecture those modules must preserve and the performance rules a
change must satisfy before it is accepted.

The first requirement is performance beyond the reference implementations. That
does not relax correctness: protocol conformance, bounded memory, and explicit
error semantics are prerequisites for measuring speed at all.

## 1. Mission and non-goals

netz is a Zig 0.16 protocol toolkit for HTTP/1.1, HTTP/2, HTTP/3, WebSocket,
WebTransport, MQTT 3.1/3.1.1/5, gRPC, WireGuard, and mesh/overlay wire
protocols. It provides:

- byte-level codecs that are pure Zig and can be fuzzed or embedded directly;
- state machines that consume only `std.Io` and caller-provided storage;
- application surfaces (clients, servers, brokers, pools) that own their
  workers and expose bounded, deadline-aware operations;
- interop and benchmark gates against independent implementations.

Non-goals:

- no C ABI, no other-language bindings, no generated foreign wrappers;
- no runtime configuration that silently trades bounded memory for speed;
- no hidden global event loop, thread pool, or allocator inside protocol code;
- no feature that cannot be verified against a reference peer or a protocol
  specification.

Reference implementations used for parity and performance comparisons live under
`~/Work`: `rumqtt`, `websocket.zig`, `hyper`, `wtransport`, `quicz`,
`quic-zig`, `s2n-quic`, `tquic`, and the official `grpc` C++ tree. External
pinned peers include quic-go, Mosquitto, nghttpd/nghttp, h2spec, Autobahn,
curl/libcurl, Chromium, and Firefox.

## 2. Layers and dependency direction

```text
L3  application surfaces   clients, servers, brokers, endpoint pools
        ^
L2  state machines         connection/stream/session/channel/router runtimes
        ^
L1  byte codecs            HTTP/1, HTTP/2+HPACK, HTTP/3+QPACK, QUIC,
                           WebSocket, MQTT, gRPC
        ^
L0  transport facade       std.Io streams, TCP/DNS connect, TLS, socket options
```

| Layer | Authoritative paths | Rule |
| --- | --- | --- |
| L0 | `src/runtime.zig`, `src/stream.zig`, `src/internal/stream_io.zig`, `src/internal/tcp_connect.zig`, `src/tls/` | The only layer allowed to import `zio`. Protocol code never sees a zio or OS handle type; it sees `std.Io` and plain slices. |
| L1 | `src/http1/`, `src/http2/`, `src/http3/`, `src/quic/`, `src/websocket/`, `src/mqtt/`, `src/grpc/` | Codecs are `std`-only and allocation-explicit. A parser returns borrowed views; an encoder writes into caller storage. |
| L2 | `*/runtime.zig`, `src/quic/*`, `src/mqtt/broker*`, `src/mqtt/session/`, `src/mqtt/router.zig`, `src/mqtt/retained/`, `src/grpc/channel/`, `src/grpc/xds/` | One owner per transport or protocol object. State transitions are explicit; blocking and deadline behavior is part of the API. |
| L3 | `src/http/`, `src/streaming.zig`, `src/mqtt/` client/reconnect/bridge APIs, `src/grpc/` client/server APIs, `src/webtransport/` endpoint APIs | Owns workers only through explicit managed wrappers; exposes bounded queues and four receive modes (blocking, relative timeout, absolute deadline, nonblocking). |
| cross-cutting | `src/alloc.zig`, `src/internal/`, `src/mqtt/persistence/`, `src/internal/observability*` | Reusable bounded caches, scratch storage, persistence, and metrics. |

`src/vpn/wireguard/` and `src/mesh/` follow the same layering: WireGuard
handshake/message/session codecs and state machines, mesh discovery messages,
and DERP frames/relay state machines are protocol code. Product policy (TUN,
routing, DNS, kill-switch, configuration, credentials, control plane,
MagicDNS, ACL, NAT/path selection) remains in `vpnz` and `meshz`; netz must
never import those product layers.

The dependency rule is enforced by convention and by review: a codec module that
imports `zio`, a socket handle, or an allocator-owning global is an architecture
bug, not a style issue. `std.posix` appears only in runtime layers for
socket-option and ancillary-data syscalls (for example `SO_LINGER` or
`recvmsg`), never in codecs.

Scale at the time of writing: 1,776 Zig files and roughly 820,000 lines, split
into self-contained protocol directories. The size is deliberate: protocol
runtimes are allowed to be large, but each hot path must be locally auditable.

## 3. Performance invariants

Every accepted change preserves P1-P10. A change that violates one needs an
explicit architecture decision recorded here, not a local workaround.

**P1 - Caller-owned output, preflight capacity.** Parsers and encoders write
into caller buffers. APIs that must allocate use `ensureUnusedCapacity` or an
equivalent preflight before committing state, so a failure cannot leave a
half-written packet or a dangling borrowed key.

**P2 - Allocation-free steady state.** Parse, encode, match, route, and frame
paths do not allocate after warmup. This is enforced by tests that install a
failing allocator and then run the operation (for example
`retained matchInto is allocation free and exact capacity`). Scratch buffers
are caller-provided, stack-fixed, or preallocated at construction.

**P3 - Borrowed views and explicit ownership.** Delivery and parse results are
borrowed slices into stable storage. Ownership transfer is named (`owned`,
`Owned...`, `...Alloc`, `deinit`). No hot path copies a payload merely to make
an API easier to use.

**P4 - Single-owner state machines, no hidden concurrency.** A connection,
stream, session, or endpoint has one owner. Managed wrappers that do own a
worker expose explicit start/stop/wait/deinit contracts and never introduce a
second socket reader. Locks do not appear in per-packet hot paths; atomics are
used at ownership boundaries only.

**P5 - Bounded everything.** Every queue, table, scratch buffer, retry loop, and
deadline has an explicit bound. Memory budgets are part of the public options:
`max_messages`, `max_message_bytes`, `max_total_bytes`, and
`max_index_bytes` for the retained store; queue and in-flight limits for
sessions, streams, and channels. An attacker-controlled input must not turn one
bounded object into unbounded index or metadata memory.

**P6 - Deadline and transactional-error discipline.** Absolute deadlines compose
through nested operations. A timeout or cancellation never commits a partial
packet, never leaks a queue slot, and never turns an ambiguous write into a
retry. Relative timeouts are converted once at the public boundary; internal
code compares absolute deadlines.

**P7 - Comptime specialization over runtime dispatch.** Protocol variants
(HTTP/1 vs HTTP/2 vs HTTP/3, MQTT 3.1/3.1.1/5, TLS 1.2/1.3) are selected at
comptime where the alternative is a per-byte branch. Bounded cardinalities use
inline fixed arrays; heap maps are reserved for genuinely unbounded key spaces.

**P8 - SIMD and word-at-a-time only where measured.** Vector scans, table-driven
Huffman decode, and word-wise masking are accepted only with fixed-binary A/B
evidence and a semantic differential test. An optimization that is neutral
within noise is removed rather than kept for appearance.

**P9 - Data layout is part of the algorithm.** Hot structs stay small; parallel
arrays replace repeated scans; index nodes use narrow integer links; match
results are emitted in table order through a preallocated bitmap rather than a
per-call result vector. Cache-line behavior is a review criterion.

**P10 - No unmeasured performance claims.** Every accepted performance change
records a fixed-binary A/B with alternating order and pinned CPU, or an
external reference gate. Rejected experiments are recorded with their numbers so
the same idea is not re-tried without new evidence. Absolute numbers are claimed
only on a quiet host; on a loaded host only interleaved ratios are claimed.

## 4. Hot-path catalog

| Path | Technique | Evidence |
| --- | --- | --- |
| HTTP/1 request line and headers | strict SIMD request-line dispatch, merged validation, single-pass line iteration, shared control-byte value table | `docs/evidence/http1/2026-11-08-parse-fast-path.json`, `docs/evidence/http1/2026-11-09-value-table.json` |
| HPACK decode | 12-bit table-driven Huffman decode, single-pass decode into stack scratch | `docs/evidence/hpack_huffman/2026-11-08.json` |
| HPACK encode | single-pass Huffman encode for short strings, exact output sizing | `docs/evidence/hpack_huffman/2026-11-08.json` |
| HTTP/2 header validation | tag-based pseudo-header classification, one comparison per name, shared byte-table name/value validation with HTTP/3 | `docs/evidence/http2_header_validation/2026-11-09.json`, `docs/evidence/http2_header_validation/2026-11-09-field-tables.json` |
| HTTP/3 capsule write | classify type/value length once, bounds-checked varint writer | `docs/evidence/http3_capsule/2026-11-08-write-fast-path.json` |
| QUIC PADDING | 32-byte vector scan over zero padding | `docs/evidence/quic_padding_scan/2026-11-08.json` |
| CONNECT-UDP capsule headers | cached header classification per session | `docs/evidence/connect_udp/2026-11-08-header-cache.json` |
| MQTT topic-name validation | merged ASCII/wildcard scan, tail-slot churn removal | `docs/evidence/mqtt_session/2026-11-08-topic-name-validation.json` |
| MQTT router | indexed unsubscribe, single-pass trie match, borrowed match/selection state, shared-group map, entry free list | `docs/evidence/mqtt_router/2026-11-08.json`, `docs/evidence/mqtt_router/2026-11-08-borrowed-emission.json` |
| MQTT ACL | precomputed filter level boundaries, one topic split per authorization | `docs/evidence/mqtt_acl/2026-11-08-filter-boundaries.json` |
| MQTT retained | topic trie with child lists and edge map, 40-byte nodes, range-cleared bitmap ordering, allocation-free match, bounded index memory | `docs/evidence/mqtt_retained/2026-11-08-trie.json`, `docs/evidence/mqtt_retained/2026-11-08-index-budget.json`, `docs/evidence/mqtt_retained/2026-11-08-bitmap-range-clear.json` |
| WebSocket masking | vector XOR with rotated mask, bounded stack scratch | `src/websocket/mod.zig` tests |
| gRPC shared requests | borrowed shared request storage, official large-frame comparison | `docs/evidence/grpc_response/2026-11-08.json` |

The catalog is not a permission list: a path not listed here is still expected
to satisfy P1-P10. It records where the current architecture has already been
pushed to a measured limit.

## 5. Memory doctrine

- **Message bytes and index bytes are separate budgets.** The retained store
  charges topic/payload/property bytes to `max_total_bytes` and trie node/edge
  bytes to `max_index_bytes`. A 64 KiB topic with tens of thousands of levels
  must not be able to allocate gigabytes of index nodes.
- **Amplification is bounded by construction.** Any per-entry metadata that is
  not proportional to the entry's own byte budget needs its own cap or a
  documented constant-factor bound.
- **Index nodes stay narrow.** The retained trie node is 40 bytes: six `u32`
  sentinel links plus a borrowed edge slice. Prefer sentinel integers over
  optional `usize` fields and parallel arrays over pointer-rich nodes.
- **Hot read paths borrow returned state.** Match and delivery helpers return
  or read `*const Entry`; the emission loop does not copy the entry header for
  every result. The measured cost is per-result struct copies, not by-value
  `self`: Zig's ABI already passes large `self` receivers by reference on this
  target, so converting only the receiver is not a reliable win.
- **Large message buffers reuse.** `alloc.BlockCache` retains power-of-two
  blocks up to a configurable byte cap for message-sized allocations; protocol
  code does not keep its own unbounded free lists.
- **Scratch resets are proportional to the work done.** The retained match
  bitmap records the word range it touched and clears only that range, so a
  selective lookup on a large table does not pay an O(table) clear. Any scratch
  state shared across calls must have a reset cost tied to what the previous
  call touched, or an O(1) generation tag.
- **Scratch is bounded and owned.** Per-connection scratch is sized at
  construction; per-call scratch is stack-fixed or caller-provided. Deep
  protocol inputs fall back to a slower bounded path instead of growing a heap
  traversal stack.

## 6. Concurrency and ownership model

- A transport has one reader owner. Sibling streams are multiplexed by that
  owner, not by competing tasks reading the same socket.
- Blocking operations take relative timeouts or caller-owned absolute
  deadlines. A timed write that may have committed a prefix retires the
  connection rather than retrying an ambiguous packet.
- Managed clients and brokers optionally run a worker on a dedicated thread or
  as a `std.Io` task. Both forms expose the same stop, wait, timeout, and
  deinit contracts.
- Queues are bounded and support blocking, relative-timeout,
  absolute-deadline, and nonblocking consumption with deep-owned results.
- Cancellation is checked before state preparation and again at the commit
  point; an abandoned command cannot mutate state after its caller left.

## 7. Measurement doctrine

Accepted performance claims use the following protocol:

1. Build both arms as fixed binaries from the same benchmark source.
2. Pin to one CPU (`taskset -c N`) and run alternating AB/BA pairs; use at
   least eight pairs for a claim.
3. Compare medians per pair and report the median ratio and per-pair wins. A
   scenario is neutral when wins are split and the ratio is within noise.
4. Use harnessz sampling (`examples/support/bench_sampling.zig`) with warmup and
   repeated samples; report min/p50/p90/p99/mean/stddev.
5. Record the binary SHA-256 values, command, pair count, order, host-load
   caveat, and source SHA-256 values in `docs/evidence/<area>/<date>.json`.
6. Run `zig build verify-evidence`; invalid JSON blocks the change. Unresolved
   entries are expected only for fixture-relative names; a new unresolved
   repository path must be fixed or mapped to its moved location.

`zig build bench-record` and `zig build bench-gate` maintain harnessz baselines
for the sampler-backed microbenchmarks under `benchmarks/baselines/`. The record
and gate steps are serialized in `build.zig` so concurrent benchmarks cannot
distort each other, but a quiet host is still required: unrelated host work
competes for cores and memory bandwidth. The gate fails on a median regression
beyond the configured ratio; `--warn-only` is for loaded-host diagnostics, not
for accepting a regression. A pinned run must be compared against a baseline
recorded under the same affinity because the environment fingerprint includes
the process CPU count.

Reference gates are the external truth for performance and conformance:
quic-go, nghttpd/nghttp, h2spec, Mosquitto, Autobahn, curl/libcurl, Chromium,
Firefox, and official gRPC C++ scenarios. A microbenchmark win never overrides
a reference-gate regression.

## 8. Verification matrix

| Gate | Command | Scope |
| --- | --- | --- |
| Full library | `zig build test-lib --summary all` | all unit and runtime tests (6,777 at the time of writing) |
| Focused | `zig build test-lib -Dtest-filter=<area>` | fast iteration on one protocol or subsystem |
| Package surface | `zig build test-package --summary all` | public API smoke tests |
| Cross-compile | `zig build test-compile -Dtarget=<triple> --summary all` | portable test compilation |
| Fuzz | `zig build fuzz-*` | parser and state-machine differential/robustness targets |
| Interop | `zig build interop-*` | independent peers and official implementations |
| Browser | `zig build interop-browser*` | real Chromium/Firefox protocol stacks |
| Benchmark gate | `zig build bench-gate` | sampler-backed baselines |
| Evidence audit | `zig build verify-evidence` | evidence JSON validity, source hashes, and the unresolved-path ceiling (`--max-unresolved`) |
| Release archive | `zig build release-source-archive` | deterministic pinned-dependency archive |

## 9. Change acceptance checklist

A performance or architecture change is accepted only when all answers are yes:

1. Does it preserve P1-P10, or does it record an explicit exception here?
2. Is the hot path still allocation-free in steady state, with a failing
   allocator test where applicable?
3. Is every new buffer, queue, retry, and index bounded by an option or a
   compile-time constant?
4. Does the fixed-binary A/B show a win outside noise, with alternating order
   and pinned CPU?
5. Do the focused tests, full library suite, and relevant interop gate pass?
6. Is the evidence file complete (command, pairs, hashes, results, notes) and
   does `verify-evidence` report `invalid=0` with unresolved entries limited to
   fixture-relative names?
7. Are rejected alternatives recorded with their numbers?
8. Are README, this document, and the per-protocol parity/benchmark docs
   updated where behavior or guidance changed?

## 10. Known structural gaps

These are current limits, not permission to ignore them:

- **HTTP/3 pool streaming** is limited to buffered requests on the shared
  dispatcher. Connection-level H3 streaming is available through
  `http.startHttp3Request` on an exclusive `HandshakeClient`, and
  `http.Pool.startRequest` returns `error.H3StreamingUnsupported` when a live
  Alt-Svc route would select H3 (`docs/http_streaming.md`).
- **Firefox STOP_SENDING** remains a separately documented browser gap in the
  WebTransport browser gate.
- **WebTransport over HTTP/2** is implemented for non-browser deployments
  (server-to-server and proxy legs) with a scripted draft-15 Python peer and a
  production endpoint queue. Browsers ship WebTransport over HTTP/3 only, so
  the remaining work is external coverage breadth, not a browser-interop gap
  (`docs/webtransport_parity.md`).
- **Retained trie index cost** is an approximation (`node + edge-map slot`);
  the budget is conservative but not an exact allocator accounting.
- **Deep-filter fallback** in the retained store uses a linear
  `topicMatchesFilter` scan for filters deeper than 64 levels. It is bounded
  and correct but not trie-accelerated.
- **Sampler-backed baseline gates are host-load sensitive.** `bench-gate`
  failures on a loaded host need a quiet-host confirmation before they are
  treated as regressions; the evidence notes must say which condition applied.

## 11. Document map

| Document | Authority |
| --- | --- |
| `docs/architecture.md` (this file) | architecture, performance doctrine, acceptance rules |
| `docs/performance-playbook.md` | how to profile, benchmark, and record evidence |
| `docs/benchmark-baseline.md` | historical and current benchmark results |
| `docs/coverage.md` | feature-level coverage inventory and verification targets |
| `docs/grpc_parity.md` | gRPC feature/interop completeness |
| `docs/hyper_parity.md` | HTTP/1.1 and HTTP/2 behavior versus Hyper |
| `docs/quicz_parity.md` | QUIC behavior versus quicz |
| `docs/rumqtt_parity.md` | MQTT behavior versus rumqtt |
| `docs/websocket_zig_parity.md` | WebSocket behavior versus websocket.zig |
| `docs/webtransport_parity.md` | WebTransport behavior versus wtransport |
| `docs/evidence/` | machine-readable evidence for every accepted claim |
