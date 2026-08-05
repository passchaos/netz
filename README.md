# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, and state helpers for:

- HTTP/1.1 requests, responses, chunked bodies, keep-alive/upgrade handling
- HTTP/2 frame headers, SETTINGS, DATA/HEADERS payload parsing, and a bootstrap
  HPACK literal decoder
- HTTP/3 frame, SETTINGS, DATAGRAM, and stateless QPACK literal helpers
- QUIC varints, long-header parsing, stream IDs, and transport parameters
- WebSocket handshakes, frame masking, control validation, and message assembly
- MQTT 3.1.1/5 fixed headers, CONNECT, PUBLISH, properties, and remaining length
- WebTransport capsules, unidirectional stream headers, CONNECT metadata, and
  datagram mapping
- WebRTC building blocks: STUN, ICE candidates, SDP, DTLS record headers, RTP,
  and SCTP common headers

The first implementation layer is intentionally codec-first rather than bound to
one runtime.  TLS, UDP/TCP sockets, event loops, congestion control, and high
level clients/servers can be layered on top while the byte-level pieces remain
small enough to fuzz and unit test.

## Build

```sh
zig build test
```

The build script pins the package to Zig `0.16.0`.

## Package use

```zig
const netz = @import("netz");

const accept = netz.websocket.acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
_ = accept;
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
