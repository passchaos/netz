# WebSocket over a caller-supplied byte stream

`netz.websocket.stream_connection.Connection` applies RFC 6455 framing to any
bidirectional byte stream. It is the lightweight adapter for HTTP/2 or HTTP/3
extended CONNECT, tests and embedders that already own the transport. The
version-specific `netz.websocket.runtime` connections own their sockets and
add transport recovery and extension negotiation.

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
must write the complete slice or return an error. A write callback error may
follow partial output; because this callback supplies no byte cursor, the
adapter retires the transport and returns the original error. Later valid
sends and receives return `error.ConnectionClosed`, including when no
`close_fn` was supplied.

`close_fn` is optional and runs at most once from `abort`, `deinit`, `close`,
or a terminal write failure. It releases the caller-owned transport without
appending WebSocket frames; it must return promptly so bounded failures keep
their deadline contract. `abort()` invokes this teardown directly.

`write_parts_fn` is an optional two-slice write. When supplied for a
server-role connection, unmasked frames are sent as the encoded header plus
the caller's payload slice without copying the payload into the adapter
buffer; `write_parts_deadline_fn` is the independently selected bounded
counterpart. Both callbacks must write both
ranges completely or return an error; empty payloads are valid. Client-role
frames always take the masked copy path.

`write_slices_fn` is the arbitrary-slice counterpart for unmasked frames:
`(context, header, slices)` must write the header and every slice completely
or return an error. `write_slices_deadline_fn` is its independently selected
bounded form.
`sendTextSlices`, `sendBinarySlices` and `sendFrameSlices` (plus
`WithTimeout`/`WithDeadline`) accept `[]const []const u8`; text validation
spans slice boundaries. Without a slice callback the adapter writes the header
and each non-empty slice under the same write lock, and client-role frames are
masked into the staging buffer.

`read_deadline_fn` and `write_deadline_fn` are optional absolute-deadline
callbacks. When supplied, `receiveMessageWithDeadline`,
`sendFrameWithDeadline`, the typed `send*WithDeadline` forms,
`sendFrameSlicesWithDeadline`, `sendCloseWithDeadline`, and
`closeWithDeadline` bound lock acquisition and the transport operation with one
awake-clock deadline. Every `WithDeadline` form has a `WithTimeout` counterpart
that converts one relative budget at the boundary and rejects a non-positive
duration before any transport I/O. Without the matching callback those calls
return `error.DeadlineUnsupported`; the ordinary blocking forms remain
available.

```zig
var message = try connection.receiveMessageWithDeadline(until);
try connection.sendCloseWithDeadline(.normal_closure, "done", until);
```

`closeWithDeadline`/`closeWithTimeout` remain available for retry after a
budget, capability, or encoding rejection before a write callback is invoked.
An invoked callback error, including `Timeout` or cancellation, retires the
transport because it may have emitted part of a Close frame. A scatter-write
fallback that committed its header also retires the transport if a later
slice's preflight fails. A fresh frame cannot complete that existing prefix.

Client-role connections mask outgoing frames and require unmasked peer frames;
server-role connections do the reverse. `max_frame_bytes` bounds each incoming
and outgoing wire frame, including its length encoding and optional four-byte
mask. `max_message_bytes` bounds application payloads in both directions and
the aggregate incoming fragmented message. Control payloads remain subject to
the RFC 125-byte cap and the wire-frame limit, independently of the application
message budget. A rejected outgoing frame returns `PayloadTooLarge` before
staging, mask generation, UTF-8 scanning or any write callback; the connection
remains usable.

Incoming headers are validated for masking, RSV bits, minimal length encoding,
fragment association and remaining message budget before payload copying or
requesting the remaining body. Oversize input sends Close 1009 when the configured frame budget
and transport permit, then retires the adapter; protocol/header failures use
1002 and invalid text uses 1007. Subsequent receives return `ConnectionClosed`.
Small message limits also bound read-ahead to the application/control window;
default limits retain 16 KiB receive batching. Split headers request their
actual 2/4/6/8/10/14 bytes rather than requiring a following frame.

Input is committed after control handling or assembly succeeds. A read timeout,
frame payload allocation failure, or assembly OOM preserves
the exact frame and accepted fragment prefix for retry. A Pong whose deadline
or capability is rejected before its write likewise leaves its Ping available.
An invoked write callback error still follows the terminal policy above.

## Close state

- `sendClose` commits its sent state under the write lock after the callback
  succeeds. An invoked callback error leaves that flag unset and retires the
  transport. A reason longer than 123 bytes returns
  `error.InvalidControlFrame` before writing.
- After either side starts the closing handshake, only a Close frame may be
  written. Data, Ping and Pong calls return `error.ConnectionClosed`.
- Receiving a Close stores its status code and reason, echoes the code when the
  peer supplied one, and makes `receiveMessage` return
  `error.ConnectionClosed`. `peerClose()` exposes the retained code/reason
  until deinit.
- Malformed Close/control headers use Close 1002; invalid UTF-8 uses 1007.
  The adapter retires the transport and returns the parser error. Terminal
  errors do not fabricate a received peer Close or re-read buffered bytes.

`receiveMessage` returns an owned `Message`; its payload is freed by
`Message.deinit`. Close metadata is copied into the connection, so it remains
valid after the frame buffer is reused.

## Concurrent operations

One receiver may run alongside serialized senders when the transport callbacks
support that usage. A sender rechecks lifecycle state after acquiring the write
mutex, so a writer queued behind Close cannot emit application data and two
queued Close calls emit one frame. Terminal failure wakes queued writers into
`ConnectionClosed`. `isClosed()`, `closeSent()` and `closeReceived()` provide
synchronized snapshots; `peerClose()` reads metadata after the receiver
publishes it. Treat the connection's state fields as internal storage.

`deinit` requires all active operations to finish. The adapter retains input,
output and assembly storage until then, so a writer's failure does not free
memory that the receiver is still using.
