# Unified streaming upload deadlines and H3 queue ownership

Validated on 2026-11-20 with Zig 0.16.0 on macOS aarch64, against delivery
base `8e3fd5b0`. This batch connects native deadline forms to unified and pooled
stream handles, and repairs large H3 dispatcher contributions.

Connection/Pool head setup and standalone H3 setup have explicit deadline and
timeout forms. Direct and pooled upload handles share write/finish/trailer
forms and `UploadProgress`: per-call accepted body bytes and message-end
acceptance. Setup does not store a deadline for later calls. H1 retains its
terminal output-failure policy; H2/H3 retain native interruption progress.
An expired H1 body call preserves an unobserved Continue wait.

The original H3 blocking queue admitted only complete contributions up to
64 KiB, so a larger input could never make progress even while a worker drained
it. The regression using `2 * max_pending_write_bytes + 3` bytes reproduced that
failure. The queue now accepts bounded pieces, retains accepted prefixes on
timeout/cancellation, validates known lengths before acceptance, treats empty
non-final writes as no-ops, and admits FIN/trailers once. Caller operations are
serialized separately from the worker queue so capacity waits release the
worker mutex.

Both dispatchers previously submitted an entire queued piece as one QUIC
packet. They now retain native DATA fragment state across packet sizing,
stream/connection credit, pacing and congestion waits; no worker adds a second
UDP reader. Per-call pooled progress means copied queue ownership, not delivery.
The bounded worker and queue remain independent of application contribution
size. Exclusive upload rejection also retains preceding interim heads rather
than discarding their owning events.

| Build | Result including imported support tests | Output |
| --- | --- | --- |
| Debug | 112/112 | [debug.log](debug.log) |
| ReleaseFast | 112/112 | [releasefast.log](releasefast.log) |

The focused HTTP bundle selects `unified HTTP streaming deadlines`,
`duplex handle streams request`, `H3 streaming queue`,
`stream blocking body write`, and `pooled H3 fields and interim callbacks`.
ReleaseFast adds `-Doptimize=ReleaseFast`; both use `--summary all`.

Coverage includes direct H1/H2/H3, pooled H1/H2 lease reuse, both H3 endpoint
backends, expired calls, exact per-call progress, H1 Continue retry, ordered
interim retention, metadata/trailer preservation, oversized 128-KiB-plus-three
uploads with public streaming receive under unchanged buffer limits, queue
suffix retry, cancellation joins and complete body-length preflight. Original
untimed duplex and pooled-field checks remain selected alongside new variants.

Upload helpers and pooled stream ownership have their own modules; queue tests
are separated from the stream owner. `source-hashes.sha256` captures the tested
sources. This batch does not rerun whole-library or peer/performance suites.
Client/Connection explicit H3 selection and Reader-source deadline composition
remain separate subsequent work.
