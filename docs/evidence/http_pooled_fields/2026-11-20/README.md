# Pooled HTTP/3 field and callback parity

Parent: `43cf33d2`, Zig 0.16.0, macOS aarch64. `sources.json` records owning
implementation and regression hashes.

Debug and ReleaseFast each passed **102/102** tests, including imported support
tests. The matching named gates check:

- Both shared-endpoint and exclusive-endpoint H3 pool dispatchers, using real
  certificate-verified TCP/TLS discovery followed by QUIC/TLS uploads.
- Forty request trailers and forty response fields/trailers without a wrapper
  limit below the protocol's field/byte limits.
- QPACK Never Indexed metadata through the public trailer mapper, queued
  request field copies, interim callback, retained final head and final trailers.
- Interim callbacks before final begin, DATA and end; later requests reuse the
  same accepted QUIC connection.
- Repeated completed reads perform no callback replay, with final heads retained
  until handle deinitialization. Existing raw H1/H2/H3 duplex gates check the same
  successful-read behavior.
- Mixing poll and read on the shared stream delivers interim and completion
  events only once. A missing interim callback still drains and frees queued
  metadata in wire order.

Interim heads remain owned by the stream until delivery/deinitialization. The
underlying response reader's configured informational and field limits bound
that retention; the wrapper does not add a separate arbitrary field-count cap.
Body and callback metadata remain borrowed for callback duration.

```sh
zig build test-http \
  '-Dtest-filter=pooled H3 fields and interim' \
  '-Dtest-filter=streams a request through HTTP3' \
  '-Dtest-filter=stream response callbacks preserve interims' \
  '-Dtest-filter=duplex handle streams request and response' --summary all

zig build test-http -Doptimize=ReleaseFast \
  '-Dtest-filter=pooled H3 fields and interim' \
  '-Dtest-filter=streams a request through HTTP3' \
  '-Dtest-filter=stream response callbacks preserve interims' \
  '-Dtest-filter=duplex handle streams request and response' --summary all
```

Logs retain summaries with trailing whitespace normalized. This is local
functionality/ownership evidence rather than a new whole-library, external-peer
or throughput certification. The separately reproduced zio no-deadline H2
cancellation wait remains under investigation.
