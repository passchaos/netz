# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, and state helpers for:

- HTTP/1.1 requests, responses, chunked transfer decoding, trailer fields,
  keep-alive/upgrade handling, ambiguous body-length rejection, and a blocking
  `std.Io.net` TCP client/server runtime
- HTTP/2 frame headers, SETTINGS, DATA/HEADERS payload parsing, and a bootstrap
  HPACK static/literal encoder-decoder
- HTTP/3 frame, SETTINGS, DATAGRAM, request/response HEADERS+DATA helpers, and
  stateless QPACK literal helpers
- QUIC varints, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames)
- WebSocket handshakes, nonce validation, frame masking, strict frame/control
  validation, close payload checks, message assembly, and a blocking TCP
  client/server runtime over HTTP/1 Upgrade
- MQTT 3.1.1/5 fixed headers, CONNECT/CONNACK, PUBLISH, PUBACK-style
  acknowledgements, SUBSCRIBE/SUBACK, PING, DISCONNECT, properties, and
  remaining length
- WebTransport capsules, unidirectional stream headers, CONNECT metadata, and
  datagram mapping
- WebRTC building blocks: STUN, XOR-MAPPED-ADDRESS helpers, ICE candidates,
  SDP, DTLS record headers, RTP packets/extensions/padding, and SCTP common
  headers

The lower protocol layers remain codec-first so they can be fuzzed and embedded,
but practical runtime APIs are being added in priority order. HTTP/1 and
WebSocket now include blocking TCP client/server runtimes built on Zig 0.16
`std.Io.net`; TLS, event loops, congestion control, and richer high-level
clients/servers can layer on the same byte-level pieces.

## Build

```sh
zig build test
```

The build script pins the package to Zig `0.16.0`.

## Implementation order

Protocol work is prioritized as: HTTP/1 + HTTP/2, WebSocket, QUIC, HTTP/3,
MQTT, then WebRTC.

## Package use

```zig
const netz = @import("netz");

const accept = netz.websocket.acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
_ = accept;
```

HTTP/1 can also run over a real TCP stream:

```zig
var threaded = std.Io.Threaded.init(allocator, .{});
defer threaded.deinit();
const io = threaded.io();

var client = try netz.http1.runtime.Client.connect(
    allocator,
    io,
    try std.Io.net.IpAddress.parse("127.0.0.1", 8080),
    .{},
);
defer client.close();

var response = try client.request(.{
    .method = .GET,
    .target = "/",
    .headers = &.{.{ .name = "Host", .value = "localhost" }},
});
defer response.deinit(allocator);
```

WebSocket can upgrade over the same TCP layer:

```zig
var ws = try netz.websocket.runtime.Client.connect(
    allocator,
    io,
    try std.Io.net.IpAddress.parse("127.0.0.1", 8080),
    .{ .host = "localhost", .target = "/chat" },
);
defer ws.close();

try ws.sendText("hello");
var frame = try ws.receiveFrame();
defer frame.deinit(allocator);
```

## Design notes

- Parsers keep slices pointing into caller-owned buffers unless a protocol needs
  mutation/unmasking (for example WebSocket frame payloads).
- Public structs expose decoded wire values and avoid hidden allocation; objects
  that allocate provide explicit `deinit` methods.
- The HTTP/2 HPACK and HTTP/3 QPACK helpers are bootstrap literal codecs.  They
  intentionally reject dynamic-table/Huffman encodings until a dedicated table
  implementation is added.
- WebRTC support covers signaling/transport wire primitives (STUN, ICE, SDP,
  DTLS/RTP/SCTP headers), forming a foundation for peer-connection state
  machines and SRTP/SCTP data-channel layers.
