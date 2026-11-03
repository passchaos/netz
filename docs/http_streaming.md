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
`error.PayloadTooLarge` at the next read boundary. Per-stream buffering remains
bounded by `max_stream_buffer`.

`Server.serveConcurrent` runs a fixed count of handlers concurrently and
serializes response submission. Its `netz.streaming.http3.ConcurrentResult`
owns the received requests and one error slot per input; handlers must not
deinitialize the borrowed request or retain its slices after the result is
deinitialized. The same single-reader/one-writer rules as HTTP/2 apply.

## Build status

The earlier `tls_material` relative-import, missing `grpc/http2/mod.zig` and
`cds/decode.zig` `type_url` shadowing blockers were fixed in
`43809172 feat(grpc): publish CDS upstream TLS clusters`. Targeted
`xds`, `delta` and `test-package` gates pass; weft can rebuild against that
commit or later.
