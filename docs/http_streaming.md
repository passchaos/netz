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
starts a background producer that drives the existing push parser and exposes:

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

## HTTP/2

Two stable shapes are available:

- `Connection.readRequestStreaming*` delivers DATA through per-request callbacks
  and returns an owned `StreamingRequest` with headers and trailers.
- `Connection.readRequestBatchStreamingInto` drives several admitted streams in
  peer HEADERS order. Each callback receives the stream ID, so one application
  loop can keep independent parsers/checksums while DATA frames arrive
  round-robin.

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

## Continuous concurrent serving

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
  fields until the handler returns. All `ConcurrentStream` methods are safe from
  the handler task and must not be called concurrently from another task. The
  connection driver must not call handler methods; it only runs
  `serveConcurrentStreams`.
- Response ordering: `startResponse`, then any number of `writeData(data, false)`,
  then either `writeData(final, true)`, `finish()`, or `finishWithTrailers`.
  `finishWithTrailers` sends the trailing HEADERS with FIN; do not call `finish`
  or `writeData` afterwards. For HEAD/204/304 responses, `startResponse` may
  carry the representation `Content-Length` with a non-zero `body_length`; the
  owner marks the response finished and `finish()` is a no-op, so no DATA frame
  is emitted.
- A handler that returns without finishing its response has that stream reset
  (`INTERNAL_ERROR`/`cancel`) instead of leaking it. A peer reset/cancel is
  delivered to `nextBody` as `error.StreamReset` and does not poison siblings.
- `shutdown` stops new acceptance, lets active handlers finish, then sends
  GOAWAY. An overall `deadline` or `idle_timeout` returns `error.Timeout` and
  cancels active streams. Peer GOAWAY/close stops acceptance and releases
  active streams.
- Response writes remain a single-writer path; a blocked write on one stream
  can delay sibling writes but never corrupts HPACK/QPACK or stream state.
- Handlers run on a per-connection worker pool that grows lazily up to
  `max_streams`. A sequential connection reuses one worker instead of spawning
  a thread per request; a multiplexed connection adds workers only while every
  existing worker is busy. `worker_stack_size` (default 1 MiB) bounds the
  virtual memory reserved by each worker. The API is independent of the
  caller's `std.Io` executor.
- Handler `nextBody`/command waits ignore spurious futex wakeups: an expired
  absolute deadline is checked against the awake clock, so a wake that does not
  set the event cannot surface a false `error.Timeout`.

## Build status

The earlier `tls_material` relative-import, missing `grpc/http2/mod.zig` and
`cds/decode.zig` `type_url` shadowing blockers were fixed in
`43809172 feat(grpc): publish CDS upstream TLS clusters`. Targeted
`xds`, `delta` and `test-package` gates pass; weft can rebuild against that
commit or later.
