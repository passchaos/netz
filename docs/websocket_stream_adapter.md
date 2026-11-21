# WebSocket over a caller-supplied byte stream

`netz.websocket.stream_connection.Connection` applies RFC 6455 framing to any
bidirectional byte stream. It is the lightweight adapter for HTTP/2 or HTTP/3
extended CONNECT, tests and embedders that already own the transport. The
version-specific `netz.websocket.runtime` connections own their sockets and
add deadline, concurrency and extension machinery.

```zig
var connection = netz.websocket.stream_connection.Connection.init(
    allocator,
    io,
    .{
        .context = transport,
        .read_fn = read,
        .write_fn = write,
        .close_fn = close,
    },
    .{ .role = .server },
);
defer connection.deinit();

var message = try connection.receiveMessage();
defer message.deinit(allocator);
try connection.sendText("reply");
try connection.sendClose(.normal_closure, "done");
```

## Transport contract

`read_fn` returns `0` at EOF and fills at most `buffer.len` bytes. `write_fn`
must write the complete slice or return an error. `close_fn` is optional and
runs once from `deinit`/`close`.

`read_deadline_fn` and `write_deadline_fn` are optional absolute-deadline
callbacks. When supplied, `receiveMessageWithDeadline`,
`sendFrameWithDeadline`, the typed `send*WithDeadline` forms,
`sendCloseWithDeadline`, and `closeWithDeadline` bound lock acquisition and the
transport operation with one awake-clock deadline. Every `WithDeadline` form
has a `WithTimeout` counterpart that converts one relative budget at the
boundary and rejects a non-positive duration before any transport I/O. Without
the matching callback those calls return `error.DeadlineUnsupported`; the
ordinary blocking forms remain available.

```zig
var message = try connection.receiveMessageWithDeadline(until);
try connection.sendCloseWithDeadline(.normal_closure, "done", until);
```

`closeWithDeadline`/`closeWithTimeout` are resumable: a rejected budget or a
failed Close write leaves the connection open so the caller can retry with a
larger budget or fall back to the unbounded `close`.

Client-role connections mask outgoing frames and require unmasked peer frames;
server-role connections do the reverse. `max_frame_bytes` bounds one wire frame
(including the header) and `max_message_bytes` bounds a reassembled fragmented
message. Both are checked before allocating the frame payload.

## Close state

- `sendClose` marks the close as sent only after the write succeeds, so a
  failed write can be retried. A reason longer than 123 bytes returns
  `error.InvalidControlFrame` instead of being silently truncated.
- After either side starts the closing handshake, only a Close frame may be
  written. Data, Ping and Pong calls return `error.ConnectionClosed`.
- Receiving a Close stores its status code and reason, echoes the code when the
  peer supplied one, and makes `receiveMessage` return
  `error.ConnectionClosed`. `peerClose()` exposes the retained code/reason
  until deinit.
- A malformed Close payload or another invalid control frame sends Close 1002,
  marks the adapter terminal and returns the parser error. The same buffered
  bytes are not re-read on the next call.

`receiveMessage` returns an owned `Message`; its payload is freed by
`Message.deinit`. Close metadata is copied into the connection, so it remains
valid after the frame buffer is reused.
