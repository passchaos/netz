# Unified HTTP/2 shared request validation

Ordinary `http.Pool.requestUri` calls admit later requests through the same
HTTP/2 connection while an earlier response is pending. One owner drives all
frames, uploads, stream deadlines and cancellation. The existing unified lease
retains connection/origin/TLS/ALPN/ticket and combined TCP/H3 budget accounting.

| Gate | Result | Evidence |
| --- | --- | --- |
| Ordinary/exclusive Debug with zio ownership regression | 176/176 tests | `ownership.Debug.corrected.log` |
| Existing negotiation/admission/close/H3 Debug | 204/204 tests | `pool-regressions.Debug.log` |
| Complete xDS plus affected unified HTTP pool ReleaseSafe | 537/537 tests | `../../grpc_federation_status/2026-11-07/xds-http.ReleaseSafe.log` |
| Independent Hyper/rustls Debug | H1, H2 and H2 shared passed | `hyper.Debug.corrected.log` |
| Independent Hyper/rustls ReleaseSafe | H1, H2 and H2 shared | `hyper.ReleaseSafe.log` |

The ReleaseSafe count is one combined gate, not a separate HTTP test count.
`gates.json` stores commands, exit codes and owning-source manifests. The
independent shared mode uses pinned ECDSA TLS, H2 ALPN and one accepted TCP
connection for seven calls. Hyper barriers ensure B starts after A waits, a
response-body drop confirms actual cancellation, and survivor/later reuse
assertions remain mandatory. H1/H2 legacy modes retain their two-call checks.

The first independent shared run caught a production ownership error missed by
the original Threaded test. Runtime-decoded headers can use packed storage;
freeing their interior name/value slices corrupted the allocator. Cleanup now
uses `http2.runtime.freeHeaderFields` for headers and trailers. Gdb allocation
and pointer evidence is retained with `ownership-diagnosis.md`; the earlier
SIGSEGV stop was zio's handled stack-growth signal. No stack-size workaround
was used. A canonical `Backend.initZio` test receives held response HEADERS,
completes a probe in wire order, then cancels while preserving its sibling and
reuse. Failed gate logs and gdb artifacts are retained.

Traditional CONNECT and explicit push configurations use their existing
exclusive aggregate paths, with separate real-loopback regressions. Their
duplex/shared follow-up owners and required invariants are documented in
`docs/http_client_pool.md`; they do not count as shared-request coverage.

Reproduce with:

```sh
zig build interop-http-unified-hyper -Doptimize=ReleaseSafe --summary all
```

The scenario is a bounded localhost interoperability check, with an explicit
raw-lease/ordinary-request reader ownership boundary. Broader functionality and
fleet-duration operation remain part of the active library goal.
