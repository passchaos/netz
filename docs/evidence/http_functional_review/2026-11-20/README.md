# HTTP functionality review evidence

Baseline: `a8015e85e6c0bbd1a33e3719219e50229ac9c00c`, Zig 0.16.0,
macOS aarch64, 2026-11-20. Production source hashes are in `sources.json`.
Blank diagnostic lines in the failing log have trailing whitespace removed;
all observations and failure records are retained.
The body-source probe uses the real h2c Pool/client/server path with a
`std.Io.Threaded` loopback fixture. It is a functionality reproduction, not
an external-peer, zio-specific, throughput or long-duration result.

| Check | Result | Artifact |
| --- | --- | --- |
| H1/H2/H3 duplex handles, negotiated H1/H2 pool retention, H2-to-H3 Alt-Svc reuse, combined TCP/H3 budget rebalancing | 99/99 tests passed, including imported support tests | `smoke.Debug.log` |
| H2 HEADERS+END_STREAM concurrent body completion | 33/33 tests passed, including imported support tests | `bodyless.Debug.log` |
| Ordinary pooled H2 body_source precedence | Reproduced defect; both Reader and slice requests sent the fallback body. Public-precedence assertion failed. Combined probe/EOF command: 127/128 passed, one failed | `body-source-probe.Debug.log`, `body-source-probe.patch` |

## Body source reproduction

One H2 pool with `cleartext_protocol = .http2_prior_knowledge` submits two
POST requests to an echo server. Both set `body = "fallback"`; the first
sets a fixed Reader containing `reader-body`, and the second sets
`body_source.slice = "slice-body"`. The server returns its actual received
body before the client asserts the documented source precedence.

The exact observation is:

```text
review probe: reader source received=fallback; slice source received=fallback
expected: reader-body
found: fallback
```

`shared_tcp.Exchange.init` declares `body_length = request.body.len`, and
`Exchange.write` slices only `request.body`. The ordinary shared request owner
passes the original RequestOptions into that exchange without normalizing or
consuming `body_source`. The two requests therefore succeed at the protocol
level while sending the wrong content.

The archived patch adds a temporary test and one import. It was removed after
capture; it is not registered in the normal build. On matching source files,
replay it with:

```sh
git apply --check docs/evidence/http_functional_review/2026-11-20/body-source-probe.patch
git apply docs/evidence/http_functional_review/2026-11-20/body-source-probe.patch
zig build test-http test-http2 \
  '-Dtest-filter=HTTP functional review' \
  '-Dtest-filter=bodyless request observes body EOF' --summary all
git apply --reverse docs/evidence/http_functional_review/2026-11-20/body-source-probe.patch
```

The build is expected to fail the body-source assertion on the captured
baseline; the H2 bodyless target should pass. Guard completion messages in the
log are not the test result: the build reports the assertion failure and its
nonzero exit explicitly.

## Passing checks on restored sources

```sh
zig build test-http \
  '-Dtest-filter=duplex handle streams request and response' \
  '-Dtest-filter=retains negotiated h1 and h2' \
  '-Dtest-filter=learns Alt-Svc' \
  '-Dtest-filter=global budget rebalances' --summary all

zig build test-http2 \
  '-Dtest-filter=bodyless request observes body EOF' --summary all
```

The selected named tests exercise live transports; reported suite counts also
include imported support tests. No new full-library, fuzz campaign,
independent peer matrix or performance claim is made. The trailer-array and
consumed-Reader replay findings in [the overview](../../../http-overview.md)
come from static inspection and were not reproduced by this probe.
