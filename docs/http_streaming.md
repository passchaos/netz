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

## HTTP/1 push contract

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
read boundaries are covered by `src/http1/runtime/body_reader_tests.zig` and the
message/chunk tests. The response is written after the consume callback returns,
so a handler can inspect the full body, trailers and request head first.

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
`finishResponse*`, `reset`, and bounded request draining.

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
identifies the cancelled stream. Applications poll all streams from one loop and
send responses with `sendResponseBody*`, `finishRequest`, or the full
`sendResponse*` forms. The same single-reader/one-writer rules as HTTP/2 apply.

## Build status

The earlier `tls_material` relative-import, missing `grpc/http2/mod.zig` and
`cds/decode.zig` `type_url` shadowing blockers were fixed in
`43809172 feat(grpc): publish CDS upstream TLS clusters`. Targeted
`xds`, `delta` and `test-package` gates pass; weft can rebuild against that
commit or later.
