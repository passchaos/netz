# Native HTTP/1 streaming deadlines

Validated on 2026-11-20 with Zig 0.16.0 on macOS aarch64, against delivery
base `844c4ebd`. This batch adds native H1 deadline/timeout operations and
extracts request/response writer owners and response-sequence helpers from the
runtime root. Existing public writer names remain aliases to their owners.

Client request and server response head setup have explicit deadline forms.
Request and response writers have deadline/timeout write, chunk, finish and
trailer operations. Buffered server responses have bounded write forms as well.
The returned writer does not inherit a setup deadline: callers reuse one
absolute timestamp when they need a whole-operation budget.

Tracked timed writes preserve the known application body prefix, excluding
chunk descriptors, CRLF and trailers. Progress remains stable after a completed
writer's connection is reused. H1 transport failures keep their existing
terminal framing policy; an expired call before I/O leaves the writer active.
Continue waits bound an early final response body and preserve ordered 103/100
observations. They retain an earlier enclosing response deadline if one exists.

| Build | Result, including imported support tests | Evidence |
| --- | --- | --- |
| Debug | 44/44 | [debug.log](debug.log) |
| ReleaseFast | 44/44 | [releasefast.log](releasefast.log) |

The same focused bundle selects `HTTP/1 streaming deadlines`,
`HTTP/1 body writer`, `request writer`, `response writer`, `streaming client`
and `client observes informational` through `zig build test-http1`; ReleaseFast
adds `-Doptimize=ReleaseFast`. Both commands use `--summary all`.

New loopback checks cover Threaded and zio TCP, auto/vectored/flatten output,
fixed and chunked partial writes, multi-chunk contributions, trailer negotiation,
Continue pre-expiry retry and early final-response timeout, completed-writer
progress after reuse, buffered response output, and native TLS12/native
TLS13/standard TLS13 streams. Existing writer checks preserve transactional
length validation, forbidden-body status rules and abandoned-exchange cleanup.

`source-hashes.sha256` records the source snapshot. This bundle does not rerun
whole-library or peer/performance suites. Unified/pool write deadlines and
Reader-source deadline composition continue in the next batch.
