# weft → netz integration requests

`weft` is the application layer on top of `netz`. These are the protocol-level
capabilities weft still needs in order to reach its target feature set. They are
filed here because the netz optimization work is active and weft must not
duplicate HTTP framing, TLS, QUIC, or codec logic.

Source consumer: `/home/passchaos/project-z/weft` (currently 162/162 tests green
in Debug and ReleaseFast at `2ef066f`).

## 1. HTTP/3 concurrent request bodies (delivered)

`9e663343` added bounded resident buffering, `body_blocked`/`body_pending`
retries (`73c34dac`), and the handshake adapter fix that treats a consumed
`DATA` frame as "no bytes available" instead of `UnexpectedFrame`. Weft's H3
adapter now pulls request DATA through `.h3_stream`
(`HandshakeServerSession.ConcurrentStream.nextBody`) with a bounded resident
window and works for streaming uploads, request trailers, and buffered routes.

## 2. HTTP/3 concurrent stream serving (delivered)

`HandshakeServerSession.serveConcurrentStreams` is adopted by weft's
`Http3Server`:

- up to `min(max_concurrent_streams, max_concurrent_handlers)` handler tasks;
- owner-serialized response heads, DATA, trailers, and cancellation;
- HEAD / 204 / 304 suppress the body while preserving the representation
  `Content-Length` (`suppress_body` + `response_finished`);
- bounded per-stream request buffers and `max_body_bytes` enforcement;
- shutdown through a per-session event fed by the server's global shutdown.

Weft verifies this with the existing HTTP/3 package test (GET, POST upload,
request/response trailers, batch concurrency, streaming response, HEAD).

## 3. Streaming response trailers

`52705ff1` emits streaming response trailers in the development runtime.
Weft's H3 adapter sends them through `ConcurrentStream.finishWithTrailers`
after the final DATA contribution; the package test covers
`/trailers-stream` end to end.

## 4. Optional follow-ups

- Streaming Brotli/zstd response compression is now implemented in weft using
  vort's incremental encoders; no netz work needed.
- `ConcurrentStream.trailers()` is now synchronized in both HTTP/2 and HTTP/3
  (`39a99d08`). The accessor takes the per-stream body mutex, so `Ctx.trailers()`
  can read it safely before END_STREAM without handler/owner overlap.
- HTTP/2 throughput is now covered by `2adc9c63` (pooled concurrent handlers
  and spurious-wait handling). On the reference host
  (`zig build bench-h2 -Doptimize=ReleaseFast`):
  - HTTP/1 keep-alive: ~16.4 µs/req, 61k req/s
  - HTTP/2 sequential: ~26.0 µs/req, 38.5k req/s
  - HTTP/2 batch=32: ~14.9 µs/req, 67.0k req/s
  Batched H2 now exceeds HTTP/1; the sequential path still pays HTTP/2
  framing. No remaining netz blocker here.
- HTTP/3 synthetic-handshake throughput (`zig build bench-h3`) after
  `462906fc`:
  - sequential: ~71 µs/req, 14.2k req/s
  - batch=8 GET: ~52 µs/req, 19.2k req/s
  - batch=8 upload (2 KiB): ~85 µs/req, 11.8k req/s
  - batch=32 GET: ~134 µs/req, 7.4k req/s
  - batch=32 upload (2 KiB): ~161 µs/req, 6.2k req/s
  The previous fixed ~2 ms sequential stall is gone. The historical 7.4k
  batch-32 number predates the current runtime. A 2026-11-19 run on a
  32-logical-CPU host measured 43.1k req/s at batch 8 and 39.1k req/s at
  batch 32 for GET, and 25.2k/22.8k req/s for the 2-KiB upload. The remaining
  ~9% batch-32 drop is much smaller than the historical capture.
  A matching `max_handler_threads = 8` experiment measured 39.5k batch-32 GET
  req/s, within run noise of the uncapped 39.1k result, so the current drop is
  not thread oversubscription on that host. A `perf` sample of the in-process
  run was dominated by receive/wait/event-loop frames rather than handler
  execution, so the next step is a split client/server profile of the owner
  command and receive path.
- `serveConcurrentStreams` now exposes `max_worker_threads` and reports
  `Summary.workers_spawned` (`74acea01`, `11f971e1`). The default remains one
  worker per possible concurrent handler; weft can cap the pool to test whether
  batch-32 contention comes from thread scheduling. The cap is clamped to
  `1..max_streams`, and the HTTP/2/HTTP/3 gates cover single-worker completion.

## 5. Current build status

- weft: `zig build test --global-cache-dir /tmp/weft-zig-global` → 108/108
  (Debug and ReleaseFast); `zig build examples` passes.
- netz: filtered `HTTP/3 continuous concurrent` runs report
  `268/268 tests passed`; the only failing steps are Python interop scripts
  that need Go 1.24+, which is not installed on this host.

## 6. Error response after a failed request read (delivered)

Status: delivered in `7d8f1650 feat(http1): answer a failed request read with
respondAndClose`. Weft uses `Connection.respondAndClose(response, deadline)`
for all reader-surfaced statuses and verifies 431/414 end to end
(`package: oversized request head and target return 431 and 414`). Weft's
Debug and ReleaseFast suites are 145/145.

Original report: `Connection.drainAndClose(deadline)` alone did not solve the
whole problem.

Reproduction: serve with `max_head_bytes = 512`, send a request head larger
than that. Weft catches `error.HeadersTooLarge`, maps it to `431`, and calls
`connection.writeResponse(...)` followed by `connection.drainAndClose(...)`.
The write fails with `error.ConnectionUnusable` because
`RequestBodyReader`'s producer already ran `writer_state.failRead()`, which
sets `phase = .unusable`; `writeResponse` starts with
`writer_state.ensureAvailable()`. The client therefore sees only EOF.

The same applies to every error surfaced by the reader (`400`, `408`, `413`,
`414`, `431`), since they all arrive after `failRead()`.

Requested API (either shape works for weft):

1. `Connection.respondAndClose(response: ResponseOptions, deadline:
   std.Io.Clock.Timestamp) Error!void` — write the response even when
   `writer_state.phase == .unusable` (the connection will not be reused),
   then half-close, drain bounded input, and close. This is the preferred
   shape because it keeps the "write, then drain, then close" ordering inside
   netz and cannot be misused to reuse a retired connection.
2. Or `Connection.writeResponseAfterReadFailure(ResponseOptions)` plus the
   existing `drainAndClose(deadline)`, with the same bypass semantics.

Why it matters: without this, an oversized or malformed HTTP/1 request gets a
connection reset/EOF instead of the protocol status code, which is observable
by clients and reverse proxies. Weft has the status mapping and bounded drain
wiring ready; only the post-failure write path is missing.

Verification once available: weft's package test sends a head over
`max_head_bytes` and a target over `max_request_target_bytes` and expects
`431` and `414` respectively (the test is currently removed because the write
is refused upstream).

## 7. Stream-level body-limit error on HTTP/2

Status: delivered (option 1). An oversize declared `Content-Length` no longer
fails request admission: the stream is accepted with
`ServerDuplexStream.request_body_over_limit = true`, and
`ConcurrentStream.nextBody` returns `error.PayloadTooLarge` for that stream.
The handler can answer `413`, the connection stays open, and sibling streams
continue. A body that grows past the cap without a declared length is also
reported as `PayloadTooLarge` instead of the raw `MessageTooLarge`.
Covered by `HTTP/2 concurrent oversize declared body stays stream-scoped` in
`src/http2/runtime/concurrent_tests.zig`.

Weft verification: `package: HTTP/2 server body limit returns 413 and keeps
the connection` sends a 2 KiB body against a 1 KiB server budget, asserts
`413`, then reuses the same client connection for a normal GET and asserts
`200`. Weft's Debug and ReleaseFast suites are 162/162.

Original reproduction: an HTTP/2 server with `Limits.max_body_bytes = 1024`
received a POST whose declared `Content-Length` was 2048; the concurrent
engine returned `error.MessageTooLarge`, ending the whole connection.

## 8. HTTP/2 body completion for a request that ends at HEADERS

Status: open, optional for weft.

Weft now buffers HTTP/2 non-streaming request bodies only when the request
declares a non-zero `Content-Length`. A request without a declared length
keeps the streaming reader because the concurrent engine publishes
`body_finished` only while draining a stream. A GET/HEAD-style request whose
HEADERS frame carries END_STREAM never produces a `.stream` pump event, so a
handler that calls `ConcurrentStream.nextBody()` waits indefinitely instead of
observing the empty body.

Requested behavior: when a newly accepted stream is already finished, either
drain it immediately (moving any buffered DATA into the slot and setting
`body_finished`) or expose a public `bodyFinished()`/`bodyAvailable()` state
that accounts for both buffered DATA and END_STREAM. That would let weft buffer
or safely skip every HTTP/2 request body without the declared-length
heuristic.

Reproduction: open an h2c connection, send a GET whose HEADERS frame has
END_STREAM, and call `ConcurrentStream.nextBody()` from the handler. It blocks
even though the request has no body.

