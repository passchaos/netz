# HTTP body source and replay correctness

Parent revision: `b0d5d8ec`, Zig 0.16.0, macOS aarch64. `sources.json`
records the delivered implementation and regression source hashes.

The Debug source/replay bundle passed **106/106** tests including imported
support tests. Its matching named tests verify:

- BodySource precedence in ordinary pooled H2 requests for slice, known-length
  Reader, unknown-length Reader and empty Reader bodies, including trailers.
- Exact 70-KiB content through a 320-byte peer stream window, followed by a
  later same-connection request.
- Late sibling admission while the source Reader is blocked, and zio source
  cancellation/join while preserving sibling and later connection reuse.
- No stale retry for a consumed single-pass Reader; exact complete replay for
  an explicitly resettable Reader and for a slice.
- Failed rewind without replacement dialing, and source I/O failure without
  misclassifying it as a stale transport error.
- Body-preserving 307 redirects with explicit rewind.
- A real certificate-verified H3 upload rejected after all bytes arrive:
  explicit rewind delivers the exact content through TCP fallback, while a
  single-pass Reader preserves the H3 error without another origin request.
- Existing H3 fallback/backoff and streaming upload behavior.

`sources.Debug.log` contains the final Debug command result. The release
source/replay/trailer/duplex bundle passed **108/108** in
ReleaseFast, recorded in `sources.ReleaseFast.log`. It uses the same source
hashes and adds the H1/H2/H3 duplex and trailer boundary regressions. The separate H1
trailer/Header bundle passed **93/93** in Debug, recorded in
`trailers.Debug.log`; it covers 16/17/40 trailer declarations plus real H2/H3
never-indexed field preservation. Logs retain observations and summaries;
trailing whitespace is normalized.

```sh
zig build test-http \
  '-Dtest-filter=pooled H2' \
  '-Dtest-filter=single-pass Reader' \
  '-Dtest-filter=replayable Reader' \
  '-Dtest-filter=Reader rewind' \
  '-Dtest-filter=Reader failure' \
  '-Dtest-filter=body source slice still' \
  '-Dtest-filter=backs off failed HTTP3' \
  '-Dtest-filter=streams a request through HTTP3' --summary all
```

## Existing ownership wait remains pending

The separate `unified HTTP ordinary H2 zio cancels an owned packed response
head and preserves sibling reuse` regression stalls at the survivor await in
`src/http/client_pool/shared_tcp/tests.zig:175`. The first broader source run
reached this existing test before its new body-source case; it was sampled and
explicitly terminated after diagnosis. An isolated clean worktree at
`b0d5d8ec` reproduced the same wait with only that named filter. Its process was
also sampled and explicitly terminated. These stopped runs are not passes.

`pending-ownership-wip.sample.txt` and
`pending-ownership-baseline.sample.txt` retain the actual native call graphs;
unrelated binary-image listings are omitted. Both show the main task awaiting
the surviving request inside the zio executor's kqueue wait. Debugger inspection
confirmed the server release event was already set. The causal layer remains
under investigation; this is not evidence that the new source producer causes
or resolves that existing issue.

No new whole-library, external-peer or performance certification is claimed.
The successful local gates use production protocol paths with Threaded and
zio fixtures. See [the body API](../../../http_bodies.md) for the explicit
source lifetime and replay contracts.
