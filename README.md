# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, and state helpers for:

- HTTP/1.1 requests, responses, header field syntax validation, chunked transfer decoding with extension limits, close-delimited response bodies, runtime chunked
  transfer writing with validated trailer fields, keep-alive/upgrade handling, pipelined
  byte buffering for persistent connections, method-aware response body
  handling for HEAD and successful CONNECT, interim 1xx response skipping plus
  server-side `Expect: 100-continue` handling, ambiguous body-length rejection,
  and a blocking `std.Io.net` TCP client/server runtime with a `std.Io.async`
  concurrent server helper
- HTTP/2 frame headers, RFC-bounded SETTINGS validation, DATA/HEADERS (including PADDED/PRIORITY self-dependency checks)/PRIORITY/PUSH_PROMISE/CONTINUATION/RST_STREAM payload parsing and active-stream reset propagation, a bootstrap
  HPACK static/literal encoder-decoder, PING/GOAWAY/WINDOW_UPDATE connection
  management including interleaved SETTINGS/PING/WINDOW_UPDATE/PRIORITY handling and GOAWAY propagation during stream reads and post-GOAWAY request suppression, default client server-push opt-out, connection- and stream-level flow-control enforcement including
  SETTINGS_INITIAL_WINDOW_SIZE updates, SETTINGS_MAX_FRAME_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE validation,
  outbound frame splitting, frame-envelope and stream-id direction/monotonicity validation, request/response trailers, pre-HEADERS frame ordering checks, interim 1xx response skipping, content-length
  validation, HTTP/2 pseudo-header/lowercase field-name validation,
  connection-specific header rejection including `TE` rules,
  and CONNECT body rules, and a blocking prior-knowledge h2c client/server runtime with a
  `std.Io.async` concurrent server helper
- HTTP/3 frame, SETTINGS, DATAGRAM, request/response HEADERS+DATA helpers,
  SETTINGS-first control-stream negotiation with GOAWAY and MAX_PUSH_ID monotonicity checks,
  CANCEL_PUSH/PUSH_PROMISE/MAX_PUSH_ID payload codecs,
  request/response message decoding with ordered HEADERS/DATA/trailer handling,
  HTTP/3 pseudo-header/lowercase field-name and connection-specific header validation,
  DATA-frame aggregation, content-length validation, stateless QPACK literal helpers, a cleartext development runtime over the QUIC
  UDP frame endpoint, a protected 1-RTT QUIC STREAM runtime with STREAM frame
  splitting/reassembly and SETTINGS exchange, and a handshake-backed protected
  client/server runtime, plus a `std.Io.async` request receive helper for the
  development runtime
- QUIC varints, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames) with stream-count bounds on MAX_STREAMS/STREAMS_BLOCKED and
  RFC 9000 packet-type legality checks for Initial/Handshake/0-RTT/1-RTT, typed
  RFC-defaulted transport-parameter encoding/validation (duplicate detection,
  endpoint-specific client/server parameter rules, preferred-address parsing,
  max UDP payload/ACK delay/stream-count bounds), Retry packet codec
  with version-specific integrity-tag verification, plus CRYPTO stream reassembly with duplicate-overlap conflict detection,
  v1/v2 Initial key/header/payload protection with version-aware salts, HKDF labels, and long-header type bits, protected Initial packet seal/open, long-header packet boundary peeking for coalesced datagrams, Version Negotiation packet codec and endpoint-level unsupported-version responses,
  Initial CRYPTO byte exchange over UDP with RFC 9000 1200-byte Initial datagram padding/validation, coalesced Initial+Handshake CRYPTO datagram helpers, minimal TLS
  ClientHello/ServerHello/EncryptedExtensions/Finished encoding and parsing,
  protected Initial ClientHello ↔ ServerHello exchange, protected Handshake
  packet server/client Finished flights, and handshake/application secret
  derivation for QUIC, an integrated minimal client/server handshake that emits
  practical transport parameters and applies negotiated flow-control, stream,
  and UDP-payload limits to established 1-RTT connection objects, stateless reset token helpers,
  packet-number space ACK tracking with never-sent ACK range rejection and adaptive truncated packet-number
  encoding wired into 1-RTT ACK/STREAM exchange, stream send/receive state with
  duplicate-overlap conflict detection, offset reassembly, FIN, RESET_STREAM final-size validation, and STOP_SENDING
  to RESET_STREAM response handling,
  flow-control state for MAX_DATA/MAX_STREAM_DATA/BLOCKED frames wired into
  1-RTT DATA_BLOCKED/MAX_DATA and STREAM_DATA_BLOCKED/MAX_STREAM_DATA handling,
  stream-count flow control with MAX_STREAMS and STREAMS_BLOCKED handling,
  protected 0-RTT long-header packet seal/open and frame datagram helpers with
  0-RTT packet-type restrictions,
  short-header spin-bit preservation plus an opt-in single-path spin policy,
  client-side NEW_TOKEN storage plus HANDSHAKE_DONE confirmation with server-only
  role validation for both frames,
  1-RTT key-update derivation and key-phase state with ACK gating and retained
  previous receive/send generations for reordered short-header packets,
  NewReno-style congestion-window and bytes-in-flight send admission wired into
  1-RTT sending and ACK/ACK_ECN processing with sent ECN counter validation, RFC 9002-style RTT/PTO estimation with
  ACK-delay adjustment,
  a 1-RTT recovery queue for PTO and packet-threshold retransmission of
  unacknowledged ack-eliciting frame payloads,
  endpoint-level connection-ID routing primitives for stable multi-connection
  demultiplexing wired into raw UDP receive routing and 1-RTT connection
  delivery, NEW_CONNECTION_ID active-limit/duplicate-CID/reset-token validation and RETIRE_CONNECTION_ID lifecycle state wired into
  1-RTT, transport/application CONNECTION_CLOSE state, PATH_CHALLENGE/PATH_RESPONSE validation state wired into 1-RTT,
  plus a blocking UDP endpoint runtime for frame datagrams with a
  `std.Io.async` concurrent receive helper
- WebSocket handshakes, nonce validation, frame masking, strict frame/control
  validation, close payload checks, fragmented message assembly with aggregate
  message-size limits, automatic PING→PONG and close echo handling,
  subprotocol negotiation, serialized connection writes, and a blocking TCP
  client/server runtime over HTTP/1 Upgrade with a `std.Io.async` concurrent
  server helper
- MQTT 3.1.1/5 fixed headers, CONNECT/CONNACK with Last Will and
  username/password payload support, PUBLISH,
  PUBACK/PUBREC/PUBREL/PUBCOMP acknowledgements, SUBSCRIBE/SUBACK,
  UNSUBSCRIBE/UNSUBACK, PING,
  DISCONNECT, AUTH enhanced-authentication exchanges, properties, remaining length, topic-name/filter validation, and
  wildcard matching, plus a blocking TCP client/server runtime with a
  `std.Io.async` concurrent server helper, QoS publish inflight limiting, and
  QoS 2 exactly-once publish handshakes
- WebTransport capsules, unidirectional stream headers, CONNECT metadata, and
  datagram mapping, session lifecycle/counter state, plus a cleartext
  development runtime over the HTTP/3 dev transport, a protected QUIC 1-RTT
  runtime over protected HTTP/3, and a handshake-backed protected runtime with
  a `std.Io.async` datagram receive helper
- WebRTC building blocks: STUN, ICE connectivity-check helpers with
  USERNAME/PRIORITY/ICE-CONTROLLING/CONTROLLED/USE-CANDIDATE plus
  MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT validation,
  XOR-MAPPED-ADDRESS helpers, ICE candidates, SDP parsing with DTLS fingerprint
  and ICE credential extraction, DTLS record headers, RTP packets/extensions/padding, RTCP
  sender/receiver reports plus PLI/NACK feedback, SCTP DATA packet parsing/writing, CRC32C validation, and DCEP DataChannel OPEN/ACK codecs, plus
  blocking UDP STUN binding, RTP/RTCP packet, and same-socket STUN/DTLS/RTP/RTCP
  peer runtimes with a `std.Io.async` concurrent receive helper

The lower protocol layers remain codec-first so they can be fuzzed and embedded,
but practical runtime APIs are being added in priority order. HTTP/1,
prior-knowledge HTTP/2 (h2c), and WebSocket now include blocking TCP
client/server runtimes built on Zig 0.16 `std.Io.net`; QUIC has Initial
protection primitives plus a blocking UDP endpoint runtime for datagram/frame
transport with endpoint-level Version Negotiation responses for unsupported
long-header versions; MQTT has a blocking TCP client/server runtime for
CONNECT/SUBSCRIBE/PUBLISH/PING/DISCONNECT flows, including QoS 1 and QoS 2
publish acknowledgements. TLS, event loops, congestion control,
ICE/DTLS/SRTP state machines, and richer high-level clients/servers can layer on
the same byte-level pieces.

The legacy HTTP/3 development runtime is intentionally labeled as cleartext; the
protected HTTP/3 runtime uses the QUIC 1-RTT short-packet API for SETTINGS
control streams and request/response STREAM frames. WebTransport has the
cleartext development transport, a protected runtime that performs CONNECT over
protected HTTP/3 and datagrams over protected QUIC 1-RTT packets, and a
handshake-backed protected session API.

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
