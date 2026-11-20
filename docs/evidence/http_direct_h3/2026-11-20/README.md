# Unified direct H3 and Reader composition

Base revision: `a35e5940`, Zig 0.16.0, macOS aarch64, 2026-11-20.
`sources.json` records the final changed production/test source hashes.

`Client` previously owned only TCP H1/H2 transports, although native H3 and
the optional H3 Pool dispatcher already existed. The unified connection now
owns a heap-stable native QUIC client when `protocol_policy = .http3_only`.
This makes complete requests, common body sources, manual streaming, response
ownership, metadata and redirect policy available through the same facade.
Default selection remains `prefer_http2`; direct H3 requires HTTPS and rejects
unsupported proxy/ALPN/TLS/early-data combinations during initialization.

Reader source waits compose with one absolute deadline, distinguish natural
source failures from interruption, join borrowed source/buffer storage, and
retain late successful reads. Available source bytes are delivered without
waiting for a full 16-KiB contribution. Manual uploads retain an unaccepted
contribution suffix and enforce its source identity before continuation.
Ordinary requests still require an explicitly replayable source for a fresh
attempt. `ResponseSink.toWriter`, discard, optional callbacks and matching
response timeout forms compose with both direct and pooled handles.

## Reproduced shared-endpoint wake defect

A Reader sent three bytes, then waited until its 30-ms source deadline expired.
On resuming, the shared H3 endpoint accepted exactly 65,536 bytes into its queue,
but the dispatcher did not consume further DATA and exhausted the request
deadline. The diagnosis is retained in `reader-resume-debug.log`:

```text
pooled H3 Reader resume: Timeout, accepted=65536, source=81923
```

The dispatcher waited on the endpoint's `state.activity`, while stream body,
trailer and cancel operations set only the stream's own `activity`. The new
optional `worker_activity` connects shared stream commands to the endpoint
owner wake. Independent endpoints retain their existing stream wake. The live
128-KiB upload regression now pauses, times out, resumes with one source and
receives a complete response on both endpoint backends.

`Pool.StreamHandle.discard()` also previously called normal deinit and could
return a completed TCP lease to idle reuse. It now invokes lease discard.
H1/H2 loopback coverage verifies the idle count drops to zero and the next
request establishes a fresh connection; normal deinit still reuses one.

## Coverage and gates

| Gate | Result | Artifact |
| --- | --- | --- |
| Direct H3 and Reader deadlines before contribution/sink refinements | 103/103; both I/O backends and IP families | `ipv6-reader-debug.log` |
| Initial wider H3/Reader ReleaseFast snapshot | 111/111 | `releasefast.log` |
| Expanded paused Reader upload before owner-wake repair | 116/117; one shared H3 failure | `final-debug.log` |
| Focused diagnosis, including shared H2 Reader progress | 100/101; same H3 timeout | `reader-resume-debug.log` |
| Direct H3, Reader source/upload, duplex and pooled H3 after wake repair | 119/119 | `verified-debug.log` |
| Final pooled TCP Reader continuation and discard | 100/100 | `tcp-reader-discard-debug.log` |
| Final combined ReleaseFast gate | 130/130 | `verified-releasefast.log` |

Direct H3 tests use both Threaded and zio over IPv4 and bracketed IPv6. They
exercise slice override, unknown/known/zero Reader bodies, zero-body trailers,
manual body/trailer streaming, interim callbacks, Never Indexed fields,
negotiation metadata, connection reuse, owned responses after connection close,
cross-origin redirects, Reader replay and client-identity restrictions.
The public Reader tests deliver a prefix before blocking, check exact cumulative
acceptance on timeout, then resume without losing bytes. Shared H2 tests require
the first three bytes to reach the server before the source is released, while
a later sibling and cancellation still preserve connection ownership.

The final broad gate uses this selected bundle (Debug's TCP additions are run
separately as recorded above):

```sh
zig build test-http -Doptimize=ReleaseFast \
  '-Dtest-filter=unified HTTP direct H3' \
  '-Dtest-filter=unified HTTP Reader' \
  '-Dtest-filter=duplex handle' \
  '-Dtest-filter=pooled H3 fields and interim callbacks' \
  '-Dtest-filter=streaming deadlines' \
  '-Dtest-filter=reader-backed' \
  '-Dtest-filter=reader body' \
  '-Dtest-filter=blocked Reader' --summary all

zig build test-http \
  '-Dtest-filter=streaming deadlines return H1 H2' \
  '-Dtest-filter=streaming deadlines discard completed' --summary all
```

Counts include imported support tests and overlap between bundles; they must
not be added together. These are selected loopback and source-boundary checks,
with no new external-peer certification, all-protocol run or performance claim.
Public contracts are in [direct H3](../../../http_direct_h3.md),
[streaming](../../../http_streaming.md) and
[the HTTP review index](../../../http-overview.md).
