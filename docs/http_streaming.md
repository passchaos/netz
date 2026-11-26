# Streaming request bodies and multiplexed streams

Stable aliases for application adapters live in `netz.streaming`:

```zig
const streaming = netz.streaming;
const h1 = streaming.http1;
const h2 = streaming.http2;
const h3 = streaming.http3;
```

Every body path is bounded by the protocol `Limits.max_body_bytes`; body slices
are borrowed only for the callback or event lifetime.

## HTTP/1

Two stable shapes are available.

### Pull body reader

`Connection.readRequestBody*` returns `netz.streaming.http1.BodyReader`. It
starts an independently admitted producer that drives the existing push parser.
Construction returns `error.ConcurrencyUnavailable` if the backend cannot admit
that producer; the reader allocation is released and parsing has not started.
The reader exposes:

```zig
var reader = try connection.readRequestBody(.{});
defer reader.deinit();
const head = try reader.head();       // method/target/headers/content-length
while (try reader.next()) |chunk| {   // borrowed until the next call
    try consume(chunk);
}
var request = try reader.takeRequest();
defer request.deinit(allocator);      // headers, trailers and body framing
try connection.writeResponse(.{ .body = "ok", .request_method = request.method });
```

Chunks are FIFO and the queue is bounded by `readRequestBodyWithBuffer`'s
`max_buffered_bytes` (default 64 KiB); the producer blocks while the queue is
full. `Head.streamContentDecoder` builds the `Content-Encoding` chain for
`step`/`finish` decoding of the encoded chunks. The total body remains bounded by
`Limits.max_body_bytes`; an oversized
Content-Length is reported by `head`, and an oversized chunked body is reported
by `next`. After the body completes, keep-alive and pipelining remain usable.
`Expect: 100-continue` is handled by the underlying parser, and trailers are in
`takeRequest`. `requestReady` reports whether the producer has finished;
`takeRequest` is non-blocking and returns `error.RequestNotComplete` before then,
so an undrained full queue cannot deadlock the caller.
`deinit` before completion cancels the producer and closes the connection
because an unread body cannot preserve keep-alive. The returned chunk slice
must be consumed before the next `next` call.

### Push contract

`Connection.readRequestStreaming*` parses the head and delivers body chunks to a
caller callback before returning the owned request metadata:

```zig
var request = try connection.readRequestStreamingWithHead(
    &context,
    begin,   // fn (ctx, StreamingRequestHead) !void
    consume, // fn (ctx, []const u8) !void
);
defer request.deinit(allocator);
// consume ran for every chunk in wire order; trailers are now in request.trailers.
try connection.writeResponse(.{ .body = "ok", .request_method = request.method });
```

The callback must consume the slice before returning. The connection remains
usable for keep-alive and pipelining after the request completes; the next
`readRequest*` call may observe a request that was already buffered. Chunk order,
`Expect: 100-continue`, trailers, `Limits.max_body_bytes`, and cancellation at
read boundaries are covered by `src/http1/runtime/body_reader_tests.zig`,
`src/http1/runtime/body_pull_tests.zig`, and the message/chunk tests.

### Native writer deadlines

HTTP/1 `Client.startRequestWithDeadline` and
`Connection.startResponseWithDeadline` bound head setup. Their `WithTimeout`
forms derive one awake-clock deadline for that setup. Subsequent body writes,
finish operations and response reads take their own explicit bounds; reusing
one absolute timestamp composes an overall operation budget:

```zig
var writer = try client.startRequestWithDeadline(.{
    .method = .POST,
    .target = "/upload",
    .host = "example.com",
    .body_length = null, // unknown length; native H1 uses ?usize
}, until);
defer writer.deinit();
try writer.writeWithDeadline(chunk, until);
try writer.finishWithDeadline(until);
var response = try writer.readResponseWithDeadline(until);
defer response.deinit(allocator);
```

Request and response writers expose `writeWithDeadline`,
`writeChunksWithDeadline`, `finishWithDeadline` and
`finishTrailersWithDeadline`, together with corresponding timeout forms.
`committedBytes()` counts application body bytes rather than chunk headers,
CRLF or trailers. It retains the known prefix after partial timed output and
remains stable for a completed writer when the connection starts a new
exchange. An untimed transport failure may have an unknown additional prefix.
HTTP/1 transport output failures retire the connection; the count does not
permit replay on that failed byte stream. A pre-expired call starts no I/O and
leaves an active writer usable.

`waitForContinueWithDeadline` and its informational/timeout forms include the
body of an early final response in the same budget, while still observing
ordered 103/100 heads. `Connection.writeResponseWithDeadline` and
`writeResponseWithTimeout` cover a complete buffered head/body/trailer message.
The advanced `StreamingBodyWriter.init` constructor remains available; timed
operations require the I/O and tracked output hook supplied by
`initWithDeadline`. Native request/response constructors install them.


### Finite HTTP/1 and WebSocket service batches

`Server.serveConcurrent` and the corresponding Unix-domain/TLS server forms
accept a fixed number of connections and admit each handler as an independent
task. The returned `ConcurrentServeResult` owns one error slot per accepted
input; successful completion retains the existing per-connection results.
The WebSocket server forms use the same finite-batch lifetime contract.

If the backend cannot admit a worker, the call returns
`error.ConcurrencyUnavailable` before invoking that handler and closes its
accepted connection. A later accept, admission or caller-cancellation failure
cancels and joins already admitted workers before freeing their result storage.
The caller must keep its handler context alive until the serve call returns.

## HTTP/2

Two stable shapes are available:

- `Connection.readRequestStreaming*` delivers DATA through per-request callbacks
  and returns an owned `StreamingRequest` with headers and trailers.
- `Connection.readRequestBatchStreamingInto` drives several admitted streams in
  peer HEADERS order. Each callback receives the stream ID, so one application
  loop can keep independent parsers/checksums while DATA frames arrive
  round-robin.

A server that closes immediately after `writeResponseBodyBatch` must first
drain pending client control frames (WINDOW_UPDATE/GOAWAY). Closing with unread
bytes in the receive queue turns the final FIN into a RST; an exact-boundary
window makes that path observable because the client must send WINDOW_UPDATEs
while the batch is finishing. The batch regression test drains with a bounded
deadline and uses the exact window. Normal connection-owning serve loops keep
reading frames and do not need a special drain.

For step-driven ownership use `Connection.acceptDuplexRequest*`; it returns a
`netz.streaming.http2.Stream`. The handle exposes `readRequestEvent*` (`data`,
`trailers`, `finished`, `reset`), `pollRequestEvent*`, response writes,
`finishResponse*`, `reset`, and bounded request draining. `nextBody()` is a
pull convenience: it returns the next DATA slice (borrowed until the following
call), retains trailers for `requestTrailers()`, returns null at END_STREAM and
surfaces a peer reset as `error.StreamReset`. `streamContentDecoder` builds the
`Content-Encoding` chain for decoding those DATA slices.

`Connection.serveRequestBatchConcurrent` is the built-in concurrent batch
surface. It reads `request_count` complete requests, runs each handler in its
own task, and serializes responses in completion order. The `Connection` remains
the sole frame-reader, HPACK owner and socket writer; workers receive immutable
owned requests and never touch the connection. Handler failures reset only their
stream with `INTERNAL_ERROR`, and the returned
`netz.streaming.http2.ConcurrentResult` carries one error slot per input. CONNECT
requests are rejected because their open-ended lifetime cannot be represented by
a completed-response batch.

`requestBatchWithPerStreamDeadlinesAndCancellation` races its sole frame read
against the cancellation observer's event. Both tasks require independent
concurrency admission, including when the executor has no asynchronous capacity.
If admission fails, the call joins every admitted task before returning. A frame
completed during that join is delivered once before interruption; a caller
cancellation is rearmed for the next cancellation point. A wake alone joins the
canceled read before returning, preserving partial parser input and allowing the
same connection to serve a later request. Reader timeouts, protocol errors and
EOF remain observable.

Concurrency contract:

- One task owns the connection frame reader at a time. Accept streams from that
  task, then route owned events to per-stream application state.
- Per-stream state and flow control are independent; a slow sibling does not
  block another stream's DATA delivery.
- Response writes on one connection are not a multi-writer API. Serialize them
  through the owning task or an application queue.
- GOAWAY, resets, cancellation and per-stream buffers remain owned by the
  runtime; a reset is an event, not an unqualified connection error.

## HTTP/3

`Server.receiveRequestEvent*` returns a multiplexed `RequestEvent` carrying
`from` and `stream_id`. Its `message.value` is a DATA/trailers/FIN event; `reset`
identifies the cancelled stream. `receiveRequestEventFor*` polls one named
stream, and `readRequestData`/`skipRequestData` pull its DATA into a caller
buffer. Applications poll all streams from one loop and send responses with
`sendResponseBody*`, `finishRequest`, or the full `sendResponse*` forms.
Cumulative request-body bytes are bounded by `Limits.max_body_bytes` (or
`HandshakeSessionOptions.max_body_bytes` for protected sessions); a declared
Content-Length is checked as well, and exceeding the budget surfaces
`error.PayloadTooLarge` at the next read boundary. The same limit applies to
client response and push bodies (`Client`, `HandshakeClient`,
`ProtectedClient`). Per-stream buffering remains bounded by
`max_stream_buffer`.

`Server.serveConcurrent` runs a fixed count of handlers concurrently and
serializes response submission. Its `netz.streaming.http3.ConcurrentResult`
owns the received requests and one error slot per input; handlers must not
deinitialize the borrowed request or retain its slices after the result is
deinitialized. The same single-reader/one-writer rules as HTTP/2 apply.

For concurrent HTTP/3 streams, `writeDataWithProgress*` reports
`DataWriteProgress` on success and error. `committed_bytes` counts bytes from
the input of that call, `fin_committed` records the final stream marker, and
`retryable` indicates whether the same stream can accept a safe suffix. After
an interrupted write, submit `data[progress.committed_bytes..]` only when
`retryable` is true, and request FIN only if it was not committed. Each call
resets the output; progress is not a cumulative stream offset. The deadline
and relative-timeout forms are `writeDataWithProgressAndDeadline` and
`writeDataWithProgressAndTimeout`.

Finite HTTP/3 sends carry one absolute budget through command admission,
pacing, the endpoint send mutex and cooperative socket submission. A timed
operation cancels and joins its submission worker before releasing borrowed
payloads. A complete socket commit remains successful if the timer races it;
an incomplete batch retains its confirmed prefix before returning the error.
Failure to admit the deadline watcher returns `error.ConcurrencyUnavailable`.
Actual network errors retain their error tag. The cleartext development path
has the same socket budget, but its multi-packet head/body ownership remains
conservative: an attempted partial submission requires the owner's terminal
cleanup rather than a retry of the complete input.

For stateful WebTransport STREAM sends, the byte-count output describes the
confirmed application prefix of that call, including an error return. Retry
only the remaining suffix, using the same stream's committed offset and a
chosen remaining budget. Contiguous and sliced writes, their association
prefix, FIN and fair cross-stream batches bound actual socket submission.
DATAGRAM batches report the confirmed payload prefix and consume every sealed
packet number; development and preconfigured-key paths retain the same rule.
A deadline worker always joins before its borrowed buffers are released.
HTTP/3 pacing stays with the connection reader: a later pacing wake must not
hide a peer CLOSE or STOP that is already waiting on the socket.

## Client duplex requests (HTTP/1, HTTP/2, HTTP/3)

`netz.http.RequestHandle` is the connection-level streaming client shape shared
by all three protocols. The caller writes the request body incrementally and
receives the response through callbacks; neither direction is buffered whole.

```zig
const until = std.Io.Clock.Timestamp.fromNow(io, .{
    .clock = .awake,
    .raw = .fromSeconds(10),
});
var handle = try connection.startRequestWithDeadline("/upload", .{
    .method = "POST",
    .headers = &.{.{ .name = "te", .value = "trailers" }},
    .trailers = &.{.{ .name = "x-checksum", .value = "" }},
    .body_length = .unknown, // or .{ .exact = n }; derived when omitted
}, until);
defer handle.deinit();

var progress: netz.http.UploadProgress = .{};
try handle.writeBodyWithDeadline("chunk-1", &progress, until);
try handle.writeBodyWithDeadline("chunk-2", &progress, until);
try handle.finishTrailersWithDeadline(
    &.{.{ .name = "x-checksum", .value = "1" }}, &progress, until,
);

var sink = MySink{};
const head = try handle.readResponseWithDeadline(sink.responseSink(), until);
```

Request headers, declared trailers, `finishTrailers` and response callbacks
all use the same `http.Header` type. `http.DuplexHeader` is a compatibility
alias; callers do not need a separate trailer array. H2/H3 never-indexed
metadata is preserved in both directions. H1 trailer declarations keep the
stack fast path and allocate exact descriptor overflow for larger field sets.
For a manual H1 upload, `RequestOptions.trailers` announces the field names;
`finishTrailers` supplies their final values.

A completed response can be read again to obtain its retained final head;
the second call performs no I/O and does not repeat begin/data/end or interim
callbacks. Final head fields stay valid until handle deinitialization. Body,
interim and trailer views remain callback-scoped. Both H3 pool backends forward
interim heads in wire order; their common-field adapter preserves Never Indexed
metadata and uses exact descriptor overflow instead of a separate trailer-count
ceiling.

`ResponseSink` has four callbacks:

- `begin(head)` once with the final `status` and owned header copies;
- `data(bytes)` for each body chunk, borrowed for the callback only;
- `end(trailers)` once, after the last chunk;
- optional `informational(head)` for every 1xx head, including `100 Continue`
  and `103 Early Hints`, before `begin`.

The begin/data/end callbacks default to ignoring their input, so a custom sink
only needs to supply the callbacks it uses. `ResponseSink.discard()` drains a
response without retaining its body. `ResponseSink.toWriter(&writer)` forwards
body chunks to any `std.Io.Writer`; the caller owns flushing and can customize
the head/trailer/1xx callbacks on the returned sink. Writer failures propagate
through the response read. For example:

```zig
var output: std.Io.Writer.Allocating = .init(allocator);
defer output.deinit();
const head = try handle.readResponseWithTimeout(
    netz.http.ResponseSink.toWriter(&output.writer), .fromSeconds(10),
);
try consume(head.status, output.written());
```

`readResponseWithDeadline` bounds head and body waits with one absolute awake
clock deadline on every protocol. `body_length` declares the manual write
length: `.unknown` selects HTTP/1 chunked framing (HTTP/2 omits Content-Length)
and `.exact = n` selects fixed framing; when omitted, the length is derived
from `body` or `body_source`. `Handle.writeBody` surfaces
`error.ResponseAvailable` when a peer rejects the request early; call
`readResponse` to drain the already-received final response. HTTP/1
`Expect: 100-continue` is handled on the first body write.

`RequestHandle` and `Pool.StreamHandle` have matching `writeBodyWithDeadline`,
`finishBodyWithDeadline` and `finishTrailersWithDeadline` methods, with timeout
forms as well. `UploadProgress` is reset for each call: `accepted_bytes` reports
the body prefix accepted by that call and `end_accepted` reports message-end
acceptance. H1 transport failures keep their terminal connection policy;
H2/H3 interrupted writes can continue with their unaccepted suffix where the
native owner remains usable. An expired call accepts nothing and retains an
unobserved H1 Continue wait. Calls after body completion return
`error.RequestBodyFinished`.

Pooled H3 progress means ownership transferred into its bounded dispatcher
queue; it does not establish delivery or peer acknowledgement. Both endpoint
backends split large contributions while retaining at most 64 KiB of queued
body data plus one worker contribution. The worker uses packet/credit-aware
STREAM fragments, retaining its cursor across backpressure. A timed-out caller
can inspect the accepted prefix and retry only the suffix. FIN/trailers are
accepted once, and known body lengths are checked before accepting a call's
prefix. Empty non-final writes queue no work. Ordinary pooled `writeBody` and
Reader uploads wait for this queue's capacity.

Request setup has explicit deadline/timeout forms on `Connection` and `Pool`,
and standalone H3 has `startHttp3RequestWithDeadline`/`WithTimeout`. Setup bounds
connection admission and head output; subsequent body/read operations use
explicit deadlines. `writeBodyFromReaderWithDeadline` and `WithTimeout` bound
both cooperative source reads and network writes with one operation deadline;
`UploadProgress.accepted_bytes` is cumulative across that call's chunks.
These methods pump bytes without finishing the body. Complete request methods
also apply their deadline to Reader reads and final trailers. Cancellation joins
source I/O before returning; a custom Reader must cooperate with `std.Io`
cancellation. Natural read failures surface as `RequestBodyReadFailed`.

Reader pumping retains one reusable 16-KiB contribution per handle. It returns
available source bytes without waiting to fill the contribution. If output
accepts only a prefix before a timeout or cancellation, the handle retains the
suffix. Call the Reader method again with the same Reader to drain it before
reading more source bytes. While a suffix is pending, a different Reader returns
`RequestBodySourceChanged`; direct body writes or body/trailer completion with
a pending suffix return `RequestBodyPending`. The source cursor can therefore
be ahead of `accepted_bytes`: callers must not rewind or manually resend a
retained contribution. Deinitializing the handle releases it. Continuation
still requires a usable native writer; H1 transport failures retain their
terminal policy.

Timed and ordinary TCP reads use the same socket I/O surface. Canceling a
timed wait joins its read before releasing the receive buffer; bytes or EOF
accepted during that join are retained, and a caller cancellation is rearmed
for its next cancellation point. Wrapped `std.Io` vtables continue to receive
their own `netRead` calls. This preserves the persistent socket registration
when H2 siblings mix deadline and no-deadline requests.

Surfaces:

- `http.Connection.startRequest` for an owned HTTP/1, HTTP/2 or explicit
  HTTP/3 connection. H3 uses `prefer_http3` or `http3_only`;
  see [direct H3 configuration](http_direct_h3.md).
- `http.Pool.startRequest` for a pooled HTTP/1, HTTP/2 or direct HTTP/3 lease, or for the
  HTTP/3 dispatcher when a live Alt-Svc route selects H3. The returned
  `Pool.StreamHandle` returns a completed TCP exchange to the idle pool and
  cancels an abandoned H3 stream. Explicit `discard()` closes a TCP lease;
  on H3 it releases the command and cancels an unfinished stream.
- `http.startHttp3Request(allocator, &handshake_client, request, body_length)`
  for an exclusive HTTP/3 `HandshakeClient`. Abandoning an unfinished H3 handle
  cancels its stream so the QUIC connection stays reusable.
- `Sender.startStream` on either HTTP/3 pool dispatcher
  (`SharedHandshakeClientPoolRequestSender` and
  `HandshakeClientPoolSharedSender`). The returned handle queues body chunks,
  reads response callbacks, and owns the dispatcher command until `deinit`.
- `SharedHandshakeClientPool.StreamTransaction` for a raw HTTP/3 pool lease.
  The caller pumps `receive*`, routes events through `processEvent`, and writes
  body chunks with `writeBody`/`writeTrailers`; backpressure errors mean "pump
  events, then retry".

Limits:

- HTTP/1 forward-proxy connections reject streaming requests with
  `error.StreamingBodyUnsupported`.
- The handle borrows its connection; the connection or pool must outlive it.

## Continuous concurrent serving

Concurrent HTTP/3 stream commands validate absolute awake-clock deadlines
before queue admission and before owner execution, including inline handlers.
Rejection at either admission point leaves response startup, DATA, trailer and
reset state unchanged. Compound informational writes retain the command's
original deadline through their interim heads.

Long-lived HTTP server connections use a per-connection owner loop instead of a
fixed request batch:

```zig
const streaming = netz.streaming;

var shutdown: std.Io.Event = .unset;
var connection = try server.accept();
defer connection.close();
_ = try connection.serveConcurrentStreams(
    HandlerContext, &context, Handler.run,
    .{ .max_streams = 64, .shutdown = &shutdown },
);

// HTTP/3 HandshakeServerSession:
_ = try session.serveConcurrentStreams(
    HandlerContext, &context, Handler.run,
    .{ .max_streams = 64, .shutdown = &shutdown },
);
```

The handler receives `*streaming.http2.ConcurrentStream` or
`*streaming.http3.ConcurrentStream` and runs in its own task. Streams are
accepted continuously in arrival order; at most `max_streams` handlers run at
once and additional accepted heads wait in arrival order. Both protocols expose
the same shape:

```zig
fn run(ctx: *Context, stream: *Stream) !void {
    while (try stream.nextBody(buf, deadline)) |n| try consume(buf[0..n]);
    if (stream.trailers()) |fields| try observe(fields);
    try stream.startResponse(.{ .status = 200 });
    try stream.writeData(chunk_a, false); // may block on flow control
    try stream.writeData(chunk_b, true);
    // or, for a buffered response, one owner round trip instead of two:
    // try stream.startResponseWithBody(.{ .status = 200 }, chunk_a, true);
    // or: try stream.finishWithTrailers(fields);
}
```

Concurrency contract:

- One task owns the connection frame reader, HPACK/QPACK state and socket
  writer. Handlers never touch connection state; body reads and response
  head/DATA/trailers/reset are serialized through the owner.
- Request DATA is delivered incrementally. The owner copies at most
  `max_buffered_body_bytes` resident bytes per stream into a bounded per-stream
  queue. The default is `HandshakeServerSession.maxBodyBuffer`, i.e.
  `HandshakeSessionOptions.max_stream_buffer` for the production HTTP/3
  session; an explicit engine option overrides it. This is a resident-buffer
  cap, not a body-size cap: the total body remains bounded by `max_body_bytes`.
  When the queue fills, the owner stops pulling new DATA and wakes the handler
  so it can drain what is resident; `nextBody` frees space and wakes the owner
  to resume reading. This keeps `nextBody` incremental without first buffering
  a whole upload, and a small cap (for example 256 KiB) still delivers uploads
  larger than the cap. A fully consumed DATA frame reports zero readable bytes,
  not `error.UnexpectedFrame`, so handshake and development sessions share the
  same pull path. `HandshakeSessionOptions.max_stream_buffer` must still admit
  the largest incoming QUIC STREAM frame; lower the peer's
  `max_stream_frame_data` when testing a cap below the default frame size.
- The `ConcurrentStream` handle is valid only while its handler runs. `nextBody`
  copies into the caller buffer; `trailers()` borrows the retained trailer
  fields until the handler returns and takes the per-stream body mutex while
  reading them, so the call is synchronized even before END_STREAM. All
  `ConcurrentStream` methods are safe from the handler task and must not be
  called concurrently from another task. The connection driver must not call
  handler methods; it only runs `serveConcurrentStreams`.
- `startResponseWithBody(response, body_length, data, fin)` (HTTP/3) and
  `startResponseWithBody(options, data, fin)` (HTTP/2) submit the head and the
  first DATA contribution as one owner command. Use it for buffered responses:
  a sequential request otherwise pays two wake/command round trips. Streaming
  responses still use `startResponse` plus `writeData`.
- Response ordering: `startResponse`, then any number of `writeData(data, false)`,
  then either `writeData(final, true)`, `finish()`, or `finishWithTrailers`.
  `finishWithTrailers` sends the trailing HEADERS with FIN; do not call `finish`
  or `writeData` afterwards. For HEAD/204/304 responses, `startResponse` may
  carry the representation `Content-Length` with a non-zero `body_length`; the
  owner marks the response finished and `finish()` is a no-op, so no DATA frame
  is emitted.
- Every response-start, informational, DATA, trailer-finish and reset form has
  an absolute-deadline and a relative-timeout variant (`*WithDeadline`,
  `*WithTimeout`). Expired or foreign-clock deadlines and non-positive
  timeouts are rejected before queue allocation or output, including inline
  handlers. The unbounded forms keep the owner's normal flow-control waiting.
- HTTP/2 and HTTP/3 retain the original timestamp through command admission, execution
  and socket submission. If a handler wait expires or is canceled, it waits
  for the owner to release the borrowed command before returning. A command
  that fully completes during that race returns success; a skipped or partial
  command retains the wait error. Cleanup can therefore finish after the
  timestamp.
- HTTP/2 preserves actual task cancellation when reporting a response that
  committed during cancellation. The next cancellation point still reports
  `Canceled`; reporting the committed response does not acknowledge that
  notification for the handler.
- HTTP/2 commands retain their committed DATA prefix and completed response
  head while the owner services inbound progress or retries backpressure.
  The direct `ServerDuplexStream` also offers
  `startResponseWithBodyWithDeadline`/`WithTimeout` for one complete buffered
  response and `resetWithDeadline`/`WithTimeout` for terminal output. Explicit
  reset preserves the caller's deadline when applying the configured terminal
  cleanup cap; expired admission leaves stream ownership untouched.
- HTTP/3 `writeDataWithProgress`, `writeDataWithProgressAndDeadline` and
  `writeDataWithProgressAndTimeout` accept `*Stream.DataWriteProgress`.
  Both byte and FIN progress are reset before admission and published on every
  return path, including timeout and cancellation. The owner retains progress
  across flow-control, congestion and pacing retries, so it sends each prefix
  once. Continue after an error only when `progress.retryable` is true, using
  the suffix described above. The development runtime reports false after a
  failed submission with an unknown visible prefix and closes that send
  direction. Native QUIC reports its exact prefix, allowing a caller to resume
  the suffix under its chosen remaining budget. Simple `writeData*` forms
  discard this metadata; applications that need recovery should use the
  progress forms.
- A handler that returns without finishing its response has that stream reset
  (`INTERNAL_ERROR`/`cancel`) instead of leaking it. A peer reset/cancel is
  delivered to `nextBody` as `error.StreamReset` and does not poison siblings.
- `shutdown` stops new acceptance, lets active handlers finish, then sends
  GOAWAY. An overall `deadline` or `idle_timeout` returns `error.Timeout` and
  cancels active streams. `idle_timeout` is a normal connection end, not a
  failure: callers should treat `error.Timeout` from an idle-configured
  `serveConcurrentStreams` as clean shutdown and not log it as an error.
  Peer GOAWAY/close stops acceptance and releases active streams.
- Response writes remain a single-writer path; a blocked write on one stream
  can delay sibling writes but never corrupts HPACK/QPACK or stream state.
- Handlers run on a per-connection worker pool that grows lazily up to
  `max_streams`. A sequential connection reuses one worker instead of spawning
  a thread per request; a multiplexed connection adds workers only while every
  existing worker is busy. `max_worker_threads` optionally caps the pool below
  `max_streams` (clamped to at least one), which can reduce thread-scheduling
  contention for CPU-bound handlers; queued handlers wait in arrival order.
  `Summary.workers_spawned` reports how many handler threads the call created.
  `worker_stack_size` (default 1 MiB) bounds the virtual memory reserved by
  each worker. The API is independent of the caller's `std.Io` executor.
- Handler `nextBody`/command waits ignore spurious futex wakeups: an expired
  absolute deadline is checked against the awake clock, so a wake that does not
  set the event cannot surface a false `error.Timeout`.
- The HTTP/3 owner races its QUIC receive against the command wake. A wake
  that wins cancels the receive; a receive that completes late is retained and
  delivered on the next owner iteration, so a fully processed packet is never
  dropped. `command_poll_interval` (default 100 µs) remains the maximum receive
  budget while a handler is active, and `poll_interval` remains the idle
  budget; both are fallbacks now that commands interrupt the receive directly.
  The HTTP/2 owner uses the same wake-race shape for its frame read.

## Expect: 100-continue

Concurrent H2/H3 handler streams can send interim responses independently of
the final response and its body:

```zig
try stream.writeInformationalResponse(103, &.{.{
    .name = "link", .value = "</style.css>; rel=preload",
}});
// Start the final response, write its DATA contributions, then finish/trailer.
```

`writeInformationalResponseWithDeadline` bounds both admission and the interim
head output with the supplied awake-clock deadline. Interim writes after the
final head are rejected without sending bytes. The H3
`startResponseWithBodyAndInformational` convenience method also accepts a
non-final first body part followed by `writeData`/`finishWithTrailers`; a final
part sends any trailers supplied in the response. Compound calls preflight the
entire interim list before sending its first head. HEAD/204/304 responses retain
their status/method-specific body rules and still deliver the interim heads.
For a HEAD or 304 H3 streaming response, `body_length` describes the selected
representation length and may be non-zero while the wire content is empty.
204/205 continue to reject non-zero content lengths. A literal `try*` send that
fails before socket progress retains the prior interim offset for a later
streaming fallback; receive-credit release is a separate named send option.

- HTTP/1 exposes `RequestWriter.waitForContinue*` on the client and sends the
  interim head before an expected body is read on the server.
- HTTP/2 servers send `100 Continue` before consuming request DATA in both
  `readRequest` (aggregate) and `readRequestStreaming` paths. Clients that send
  an `expect` field observe the interim head through the existing
  `InformationalObserver`.
- HTTP/3 servers send `100 Continue` before body reads in the streaming
  `receiveRequestEvent*` paths. The response send layer tracks the byte offset
  consumed by informational heads, so the final response head and body start
  after every 1xx section instead of conflicting at stream offset zero.
- HTTP/3 aggregate `receiveRequest*` decodes a complete request head as soon as
  it arrives and sends `100 Continue` before waiting for the body, matching the
  streaming paths. A head that ends the stream never receives an interim head.

## Build status

The earlier `tls_material` relative-import, missing `grpc/http2/mod.zig` and
`cds/decode.zig` `type_url` shadowing blockers were fixed in
`43809172 feat(grpc): publish CDS upstream TLS clusters`. Targeted
`xds`, `delta` and `test-package` gates pass; weft can rebuild against that
commit or later.
