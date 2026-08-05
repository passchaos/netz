# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, and state helpers for:

- HTTP/1.1 requests, responses, chunked transfer decoding, trailer fields,
  keep-alive/upgrade handling, pipelined byte buffering for persistent
  connections, ambiguous body-length rejection, and a blocking `std.Io.net`
  TCP client/server runtime with a `std.Io.async` concurrent server helper
- HTTP/2 frame headers, SETTINGS, DATA/HEADERS payload parsing, a bootstrap
  HPACK static/literal encoder-decoder, PING/GOAWAY/WINDOW_UPDATE connection
  management, connection- and stream-level flow-control enforcement including
  SETTINGS_INITIAL_WINDOW_SIZE updates, and a blocking prior-knowledge h2c
  client/server runtime with a `std.Io.async` concurrent server helper
- HTTP/3 frame, SETTINGS, DATAGRAM, request/response HEADERS+DATA helpers,
  typed SETTINGS negotiation state, stateless QPACK literal helpers, a
  cleartext development runtime over the QUIC UDP frame endpoint, a protected
  1-RTT QUIC STREAM runtime with
  STREAM frame splitting/reassembly, and a handshake-backed protected
  client/server runtime, plus a `std.Io.async` request receive helper for the
  development runtime
- QUIC varints, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames), plus
  CRYPTO stream reassembly, v1 Initial key/header/payload protection, protected
  Initial packet seal/open, Initial CRYPTO byte exchange over UDP, minimal TLS
  ClientHello/ServerHello/EncryptedExtensions/Finished encoding and parsing,
  protected Initial ClientHello ↔ ServerHello exchange, protected Handshake
  packet server/client Finished flights, and handshake/application secret
  derivation for QUIC, an integrated minimal client/server handshake that
  establishes 1-RTT connection objects, stateless reset token helpers, packet number space ACK tracking wired
  into 1-RTT ACK/STREAM exchange, stream send/receive state with offset reassembly and FIN,
  flow-control state for MAX_DATA/MAX_STREAM_DATA/BLOCKED frames wired into
  1-RTT DATA_BLOCKED/MAX_DATA and STREAM_DATA_BLOCKED/MAX_STREAM_DATA handling,
  NewReno-style congestion-window and bytes-in-flight send admission wired into
  1-RTT sending and ACK processing,
  a minimal 1-RTT recovery queue for PTO retransmission of unacknowledged
  ack-eliciting frame payloads,
  endpoint-level connection-ID routing primitives for stable multi-connection
  demultiplexing wired into raw UDP receive routing and 1-RTT connection
  delivery, NEW_CONNECTION_ID/RETIRE_CONNECTION_ID lifecycle state wired into
  1-RTT, transport/application CONNECTION_CLOSE state, PATH_CHALLENGE/PATH_RESPONSE validation state wired into 1-RTT,
  plus a blocking UDP endpoint runtime for frame datagrams with a
  `std.Io.async` concurrent receive helper
- WebSocket handshakes, nonce validation, frame masking, strict frame/control
  validation, close payload checks, message assembly, serialized connection
  writes, and a blocking TCP client/server runtime over HTTP/1 Upgrade with a
  `std.Io.async` concurrent server helper
- MQTT 3.1.1/5 fixed headers, CONNECT/CONNACK, PUBLISH,
  PUBACK/PUBREC/PUBREL/PUBCOMP acknowledgements, SUBSCRIBE/SUBACK, PING,
  DISCONNECT, properties, and remaining length, plus a blocking TCP
  client/server runtime with a `std.Io.async` concurrent server helper, QoS
  publish inflight limiting, and QoS 2 exactly-once publish handshakes
- WebTransport capsules, unidirectional stream headers, CONNECT metadata, and
  datagram mapping, session lifecycle/counter state, plus a cleartext
  development runtime over the HTTP/3 dev transport, a protected QUIC 1-RTT
  runtime over protected HTTP/3, and a handshake-backed protected runtime with
  a `std.Io.async` datagram receive helper
- WebRTC building blocks: STUN, XOR-MAPPED-ADDRESS helpers, ICE candidates,
  SDP, DTLS record headers, RTP packets/extensions/padding, and SCTP common
  headers, plus blocking UDP STUN binding, RTP packet, and same-socket
  STUN/DTLS/RTP peer runtimes with a `std.Io.async` concurrent receive helper

The lower protocol layers remain codec-first so they can be fuzzed and embedded,
but practical runtime APIs are being added in priority order. HTTP/1,
prior-knowledge HTTP/2 (h2c), and WebSocket now include blocking TCP
client/server runtimes built on Zig 0.16 `std.Io.net`; QUIC has Initial
protection primitives plus a blocking UDP endpoint runtime for datagram/frame
transport; MQTT has a blocking TCP client/server runtime for
CONNECT/SUBSCRIBE/PUBLISH/PING/DISCONNECT flows, including QoS 1 and QoS 2
publish acknowledgements. TLS, event loops, congestion control,
ICE/DTLS/SRTP state machines, and richer high-level clients/servers can layer on
the same byte-level pieces.

The legacy HTTP/3 development runtime is intentionally labeled as cleartext; the
protected HTTP/3 runtime uses the QUIC 1-RTT short-packet API for request/response
STREAM frames. WebTransport has the cleartext development transport, a protected
runtime that performs CONNECT over protected HTTP/3 and datagrams over protected
QUIC 1-RTT packets, and a handshake-backed protected session API.

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
