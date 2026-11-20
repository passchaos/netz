# Concurrent informational response composition

Parent: `739d7a33`, Zig 0.16.0, macOS aarch64. Owning implementation and
regression source hashes are in `sources.json`.

| Gate | Result | Scope |
| --- | --- | --- |
| Debug focused H2/H3 | 106/106, including support tests | New 1xx composition plus existing continuous concurrent serving |
| ReleaseFast focused H2/H3 | 107/107, including support tests | Same scope plus stateless 304 representation-length round trip |

The selected tests verify actual native H2 and certificate-verified QUIC/TLS H3
connections, together with the development H3 transport:

- independent 100/103 before a final head, body contributions and trailers;
- expired informational deadlines produce no interim bytes, and interim writes
  after a final head fail without altering the response;
- H3's compound informational/body helper can leave the body open or finish
  through response trailers, including zero content;
- HEAD, 204 and 304 retain empty wire content while delivering interim heads;
  HEAD/304 can describe a non-zero selected representation;
- an invalid later interim head is rejected before a compound list's first
  valid head is sent;
- 24 application fields plus synthesized Content-Length use exact descriptor
  overflow rather than a fixed-stack ceiling;
- a 9,000-byte response falls back from the one-packet literal path and
  preserves earlier informational stream offsets;
- a failed literal streaming-head preflight preserves the earlier 103 prefix
  before a 5,000-byte field is delivered through the streaming path;
- ordinary concurrent serving and same-connection subsequent requests remain
  compatible.

The literal sender now separates `initial_offset` from `release_received` in
`ResponseLiteralOptions`; the previous positional entry point remains a
compatibility wrapper. Interim offsets are removed only after successful
literal output. Buffered header preparation is shared under
`runtime/concurrent/response.zig`.

Commands:

```sh
zig build test-http2 test-http3 \
  '-Dtest-filter=concurrent informational' \
  '-Dtest-filter=continuous concurrent' --summary all

zig build test-http2 test-http3 -Doptimize=ReleaseFast \
  '-Dtest-filter=concurrent informational' \
  '-Dtest-filter=continuous concurrent' --summary all
```

`Debug.log` and `ReleaseFast.log` retain build summaries with trailing
whitespace normalized. This is local correctness evidence for the captured
sources, not a new whole-library, external-peer or throughput certification.
See [streaming contracts](../../../http_streaming.md) for public usage.
