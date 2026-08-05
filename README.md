# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, and state helpers for:

- HTTP/1.1 requests, responses, chunked transfer decoding, trailer fields,
  keep-alive/upgrade handling, ambiguous body-length rejection, and a blocking
  `std.Io.net` TCP client/server runtime
- HTTP/2 frame headers, SETTINGS, DATA/HEADERS payload parsing, a bootstrap
  HPACK static/literal encoder-decoder, and a blocking prior-knowledge h2c
  client/server runtime
- HTTP/3 frame, SETTINGS, DATAGRAM, request/response HEADERS+DATA helpers,
  stateless QPACK literal helpers, and a cleartext development runtime over the
  QUIC UDP frame endpoint
- QUIC varints, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames), plus
  CRYPTO stream reassembly, v1 Initial key/header/payload protection, protected
  Initial packet seal/open, Initial CRYPTO byte exchange over UDP, minimal TLS
  ClientHello/ServerHello/EncryptedExtensions/Finished encoding and parsing,
  protected Initial ClientHello ↔ ServerHello exchange, protected Handshake
  packet server/client Finished flights, and handshake/application secret
  derivation for QUIC, plus a blocking UDP endpoint runtime for frame datagrams
- WebSocket handshakes, nonce validation, frame masking, strict frame/control
  validation, close payload checks, message assembly, and a blocking TCP
  client/server runtime over HTTP/1 Upgrade
- MQTT 3.1.1/5 fixed headers, CONNECT/CONNACK, PUBLISH, PUBACK-style
  acknowledgements, SUBSCRIBE/SUBACK, PING, DISCONNECT, properties, and
  remaining length, plus a blocking TCP client/server runtime
- WebTransport capsules, unidirectional stream headers, CONNECT metadata, and
  datagram mapping, plus a cleartext development runtime over the HTTP/3 dev
  transport
- WebRTC building blocks: STUN, XOR-MAPPED-ADDRESS helpers, ICE candidates,
  SDP, DTLS record headers, RTP packets/extensions/padding, and SCTP common
  headers, plus a blocking UDP STUN binding client/server runtime

The lower protocol layers remain codec-first so they can be fuzzed and embedded,
but practical runtime APIs are being added in priority order. HTTP/1,
prior-knowledge HTTP/2 (h2c), and WebSocket now include blocking TCP
client/server runtimes built on Zig 0.16 `std.Io.net`; QUIC has Initial
protection primitives plus a blocking UDP endpoint runtime for datagram/frame
transport; MQTT has a blocking TCP client/server runtime for
CONNECT/PUBLISH/PING/DISCONNECT flows. TLS, event loops, congestion control,
ICE/DTLS/SRTP state machines, and richer high-level clients/servers can layer on
the same byte-level pieces.

The HTTP/3 runtime is intentionally labeled as a cleartext development transport:
it exercises real UDP I/O and HTTP/3 frame/message handling over QUIC STREAM
frames, but it is not a substitute for RFC-compliant QUIC TLS packet protection.
The WebTransport runtime builds on that same development transport for local
CONNECT/datagram flows and is likewise not a substitute for standards-compliant
HTTP/3 over protected QUIC.

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
