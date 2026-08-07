# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, and state helpers for:

- HTTP/1.1 requests, responses, header field syntax validation, chunked transfer decoding with strict chunk-size grammar and extension limits, close-delimited and non-chunked-transfer-coded response bodies, runtime chunked
  transfer writing with validated and repeated-value-merged trailer fields, opt-in obsolete folded-field
  unfolding, request-target/status/reason-phrase start-line validation, status-forbidden response-body write rejection, keep-alive/upgrade handling, pipelined
  byte buffering for persistent connections, method-aware response body
  handling for HEAD and successful CONNECT, authority-form CONNECT target validation including bracketed IPv6 and CONNECT tunnel helpers, interim 1xx response skipping plus
  server-side `Expect: 100-continue` handling even when body bytes are pre-read with invalid-head suppression, pure-digit Content-Length enforcement,
  TE-over-CL precedence with parsed `Content-Length` stripping, ambiguous body-length rejection
  across repeated/coalesced `Content-Length`, and unsupported transfer-coding and HTTP/1.0 transfer-coding rejection,
  and a blocking `std.Io.net` TCP client/server runtime with HTTP/1.1 default
  persistence, optional Host/port synthesis, `http://`/`https://` URI helpers
  with host-name DNS and IPv4/bracketed-IPv6 literal connect support, TLS client transport via Zig `std.crypto.tls`
  with host verification plus OS/custom CA bundles, and a `std.Io.async`
  concurrent server helper
- HTTP/2 frame headers, RFC-bounded SETTINGS validation, DATA/HEADERS (including PADDED/PRIORITY self-dependency checks)/PRIORITY/PUSH_PROMISE/CONTINUATION/RST_STREAM payload parsing and active-stream reset propagation, a bootstrap
  HPACK static/literal encoder-decoder with RFC 7541 Huffman strings plus
  dynamic-table indexing/size-update state for long-lived runtimes with local decoder table-size enforcement and automatic
  peer table-size update emission plus h2/hyper-style non-indexing for volatile or oversized fields and automatic
  never-index encoding for sensitive fields, PING/GOAWAY/WINDOW_UPDATE connection
  management including interleaved SETTINGS/PING/WINDOW_UPDATE/PRIORITY handling and GOAWAY propagation during stream reads and post-GOAWAY request suppression/rejection and same-control-stream GOAWAY emission with persistent control-stream offsets, default client server-push opt-out, connection- and stream-level flow-control enforcement including
  SETTINGS_INITIAL_WINDOW_SIZE updates and configurable advertisement, configurable SETTINGS_HEADER_TABLE_SIZE/SETTINGS_MAX_CONCURRENT_STREAMS/SETTINGS_MAX_FRAME_SIZE advertisement, bidirectional SETTINGS_MAX_CONCURRENT_STREAMS enforcement, SETTINGS_MAX_FRAME_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE validation with inbound advertised-frame-size enforcement,
  outbound frame splitting with DATA sends that wait for WINDOW_UPDATE capacity
  and inbound DATA consumers that account for full padded frame payloads and restore connection/stream receive capacity,
  frame-envelope and stream-id direction/monotonicity validation, request/response trailers with forbidden-field rejection, pre-HEADERS frame ordering checks, interim 1xx response skipping and explicit server-side informational response sending, content-length
  validation with pure-digit Content-Length enforcement, HTTP/2 pseudo-header/lowercase field-name/value and control-character validation, `:method` and `:protocol` token validation,
  URI-like `:scheme`/`:path`/`:authority` validation with Host fallback and Host/`:authority` mismatch rejection,
  connection-specific header rejection including `TE` rules,
  status-forbidden response-body write rejection,
  traditional CONNECT header-only tunnel acceptance with DATA tunnel helpers and strict `:authority`-only host:port pseudo-header rules, CONNECT body/Content-Length rules, and opt-in RFC 8441 extended CONNECT / `:protocol` handling with irreversible
  SETTINGS_ENABLE_CONNECT_PROTOCOL downgrade rejection,
  open/accept/reject tunnel helpers and DATA-frame tunnel read/write mapping, RFC 7540 h2c Upgrade client/server helpers that carry `HTTP2-Settings` and receive/respond on stream 1, and a blocking prior-knowledge h2c client/server runtime with default `:authority` host/port synthesis and transport/URI-derived `:scheme`,
  `http://` URI helpers with host-name DNS and IPv4/bracketed-IPv6 literal connect support, and a `std.Io.async` concurrent server helper
- HTTP/3 frame, SETTINGS, DATAGRAM, request/response HEADERS+DATA helpers,
  SETTINGS-first control-stream negotiation with unique peer control-stream tracking, forbidden frame rejection on control/request streams, and QPACK encoder/decoder critical stream registration with explicit non-empty-instruction rejection while dynamic tables are unsupported, GOAWAY and MAX_PUSH_ID monotonicity checks plus post-GOAWAY request suppression/rejection and same-control-stream GOAWAY emission with persistent control-stream offsets,
  CANCEL_PUSH/PUSH_PROMISE/MAX_PUSH_ID/PRIORITY_UPDATE payload codecs,
  RFC 9218 Priority field parsing/serialization,
  request/response message decoding with ordered HEADERS/DATA/trailer handling, interim 1xx response skipping and runtime emission before final responses, and forbidden trailer-field rejection,
  HTTP/3 pseudo-header/lowercase field-name, `:method`/`:protocol` token, URI path/scheme/authority, Host/`:authority`, traditional CONNECT body rules, and connection-specific header validation,
  DATA-frame aggregation, pure-digit content-length and status-forbidden response-body validation, stateless QPACK helpers with RFC 9204 static-table references plus literal fallback, a cleartext development runtime over the QUIC
  UDP frame endpoint, a protected 1-RTT QUIC STREAM runtime with STREAM frame
  splitting/reassembly and SETTINGS exchange, and a handshake-backed protected
  client/server runtime, plus a `std.Io.async` request receive helper for the
  development runtime
- QUIC varints, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames) with stream-count bounds on MAX_STREAMS/STREAMS_BLOCKED and
  RFC 9000 packet-type legality checks for Initial/Handshake/0-RTT/1-RTT, typed
  RFC-defaulted transport-parameter encoding/validation (duplicate detection,
  endpoint-specific client/server parameter rules, preferred-address parsing,
  max UDP payload/idle-timeout/ACK delay/stream-count bounds), Retry packet codec
  with version-specific integrity-tag verification, plus CRYPTO stream reassembly with duplicate-overlap conflict detection,
  v1/v2 Initial key/header/payload protection with version-aware salts, HKDF labels, and long-header type bits, version-specific TLS QUIC packet-protection labels, protected Initial packet seal/open, long-header packet boundary peeking for coalesced datagrams, Version Negotiation packet codec, RFC 9368 `version_information` transport parameters, endpoint-level unsupported-version responses, client-side Version Negotiation selection/restart helpers, and automatic handshake restart on negotiated versions,
  Initial CRYPTO byte exchange over UDP with RFC 9000 1200-byte Initial datagram padding/validation, client-carried Initial address tokens, server-side token validation hooks, and server-issued address-validation NEW_TOKEN frames, coalesced Initial+Handshake CRYPTO datagram helpers, HMAC-based
  address-validation token helpers for Retry/NEW_TOKEN with lifetime, version,
  peer-address binding, Retry ODCID/RSCID binding, secret rotation, replay
  filtering, Retry datagram issue/validate helpers, client-side Retry
  processing that enforces one-Retry/early-Retry rules and prepares retried
  Initial inputs, plus server-side retried Initial token/transport-parameter
  validation hooks, minimal TLS
  ClientHello/ServerHello/EncryptedExtensions/Finished encoding and parsing,
  protected Initial ClientHello ↔ ServerHello exchange, protected Handshake
  packet server/client Finished flights, and handshake/application secret
  derivation for QUIC, an integrated minimal client/server handshake for QUIC v1/v2 that emits
  practical transport parameters and applies negotiated flow-control, stream,
  and UDP-payload limits to established 1-RTT connection objects, stateless reset token helpers,
  packet-number space ACK tracking with bounded duplicate/old packet suppression, ACK range semantic validation, receive-frame semantic preflight before multi-frame side effects, and adaptive truncated packet-number
  encoding wired into 1-RTT ACK/STREAM exchange, stream send/receive state with
  duplicate-overlap conflict detection, offset reassembly, FIN, RESET_STREAM final-size validation, and STOP_SENDING
  to RESET_STREAM response handling,
  RFC 9221 QUIC DATAGRAM negotiation limits with 1-RTT send helpers,
  receive queues, max-payload calculation, queue overflow/drop counters, and
  oversized/disabled DATAGRAM rejection,
  draft ACK_FREQUENCY and IMMEDIATE_ACK frame codecs with `min_ack_delay`
  transport-parameter negotiation and opt-in 1-RTT state updates for requested
  ACK threshold/max-delay/reordering behavior,
  flow-control state for MAX_DATA/MAX_STREAM_DATA/BLOCKED frames wired into
  1-RTT DATA_BLOCKED/MAX_DATA and STREAM_DATA_BLOCKED/MAX_STREAM_DATA handling,
  stream-count flow control with MAX_STREAMS and STREAMS_BLOCKED handling,
  protected 0-RTT long-header packet seal/open and frame datagram helpers with
  0-RTT packet-type restrictions,
  short-header spin-bit preservation plus an opt-in single-path spin policy,
  client-side NEW_TOKEN storage plus HANDSHAKE_DONE confirmation with server-only
  role validation for both frames,
  transport-parameter-derived idle timeout deadline tracking and explicit
  peer-address validation hooks with RFC 9000 3x anti-amplification send
  budget enforcement for unvalidated server paths,
  1-RTT key-update derivation and key-phase state with ACK gating and retained
  previous receive/send generations for reordered short-header packets,
  NewReno-style congestion-window and bytes-in-flight send admission wired into
  1-RTT sending and ACK/ACK_ECN processing with receive-side ECN counter
  reporting, sent ECN counter validation, ACK_ECN CE congestion response,
  reordered-ACK_ECN tolerance, and plain-ACK ECN fallback disablement, RFC 9002-style RTT/PTO estimation with ACK-delay
  adjustment, packet/time-threshold loss detection, earliest loss/PTO timer
  deadlines, exponential PTO backoff, two-probe PTO service, and persistent
  congestion detection that collapses the congestion window and resets the RTT
  measurement epoch after long contiguous lost periods, PMTUD/DPLPMTUD path MTU
  probe sizing state with IPv4/IPv6 ceilings, loss-driven search backoff, and
  1-RTT PING+PADDING probe packets wired to ACK/loss feedback,
  a 1-RTT recovery queue for PTO plus packet-threshold and time-threshold
  retransmission of unacknowledged ack-eliciting frame payloads,
  endpoint-level connection-ID routing primitives for stable multi-connection
  demultiplexing wired into raw UDP receive routing and 1-RTT connection
  delivery, including peer-path binding and active-migration-disabled route
  rejection, NEW_CONNECTION_ID active-limit/duplicate-CID/reset-token validation and RETIRE_CONNECTION_ID lifecycle state wired into
  1-RTT, transport/application CONNECTION_CLOSE state, PATH_CHALLENGE/PATH_RESPONSE validation state with duplicate challenge suppression wired into 1-RTT,
  peer-migration helpers that honor disable_active_migration, apply a server
  preferred_address by selecting its CID/reset token and peer IP/port, reset
  anti-amplification and PMTUD path state, queue PATH_CHALLENGE,
  track path-validation deadlines, retry timed-out challenges, record failed
  validation attempts, and validate the new path on a matching PATH_RESPONSE,
  plus a blocking UDP endpoint runtime for frame datagrams with a
  `std.Io.async` concurrent receive helper
- WebSocket handshakes with Host authority, body-framing rejection, duplicate-subprotocol and nonce validation, frame masking, strict frame/control
  validation including control/continuation RSV rejection, close payload checks, fragmented message assembly with aggregate
  message-size limits, automatic PING→PONG and close echo/completed-close short-circuit handling,
  outbound text/close/control-frame validation plus codec-level invalid-frame write rejection,
  subprotocol token validation, split-header subprotocol and extension-offer negotiation, optional permessage-deflate negotiation with
  no-context-takeover RFC 7692 sync-flush raw-DEFLATE encode/decode plus rejection of
  unsupported extension parameters/window sizes, framed 101 upgrade responses, and compressed fragmented sends, serialized connection writes, a blocking TCP
  client/server runtime over HTTP/1 Upgrade with a `std.Io.async` concurrent
  server helper, `ws://`/`wss://` URI helpers with host-name DNS and IPv4/bracketed-IPv6 literal connect support plus
  Host/port synthesis, TLS client transport shared with HTTP/1, and RFC 8441
  WebSocket-over-HTTP/2 adapters that negotiate `:protocol = websocket`,
  subprotocols, permessage-deflate, and transport-derived `:scheme` over an h2 DATA tunnel
- MQTT 3.1.1/5 fixed headers, CONNECT/CONNACK with Last Will and
  username/password payload support, PUBLISH,
  PUBACK/PUBREC/PUBREL/PUBCOMP acknowledgements, SUBSCRIBE/SUBACK,
  UNSUBSCRIBE/UNSUBACK, PING,
  DISCONNECT, AUTH enhanced-authentication exchanges, properties, exact packet bounds, minimal remaining length, MQTT UTF-8 string validation, response-topic/topic-name/filter validation, payload-format UTF-8 validation, and
  wildcard and shared-subscription matching, plus a blocking TCP client/server runtime with a
  `std.Io.async` concurrent server helper, MQTT v5 Server Keep Alive, Receive Maximum, Maximum Packet Size, Maximum QoS, Retain Available, and Topic Alias negotiation/resolution with outgoing alias registration checks, QoS publish inflight limiting, and
  QoS 2 exactly-once publish handshakes, including MQTT v5 PUBACK/PUBREC/PUBREL/PUBCOMP reason-code/property validation and negative publish acknowledgement propagation
- WebTransport capsules, unidirectional stream headers, CONNECT metadata with client-bidi session-id validation, and
  datagram mapping, session lifecycle/counter state, plus a cleartext
  development runtime over the HTTP/3 dev transport, a protected QUIC 1-RTT
  runtime over protected HTTP/3 with automatic WebTransport/H3 DATAGRAM
  SETTINGS advertisement and negotiation checks, and a handshake-backed
  protected runtime that uses QUIC 1-RTT DATAGRAM send/receive queues with
  WebTransport payload-size accounting and batch receive helpers
- WebRTC building blocks: STUN, ICE connectivity-check helpers with priority encode/decode,
  USERNAME/PRIORITY/ICE-CONTROLLING/CONTROLLED/USE-CANDIDATE plus
  MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT validation,
  XOR-MAPPED-ADDRESS helpers, ICE candidates with RFC/Pion-compatible candidate type/local/TCP/relay priority and pair-priority helpers, SDP parsing with DTLS fingerprint, DTLS setup role parse/generation helpers,
  ICE credential, BUNDLE-aware media selection, RTP `extmap` extraction, and modern/legacy SCTP DataChannel port plus max-message-size metadata, DTLS record headers, RTP packets/extensions/padding, RTCP
  RFC 5285 one-byte/two-byte header extension codecs for MID/RID/TWCC/audio-level/playout-delay/video-orientation/absolute-send-time/absolute-capture-time/video-layer-allocation style metadata encode/decode and timestamp-estimation helpers, sender/receiver reports with profile extensions plus sender/receiver-report statistics and Pion-style packet/compound destination SSRC extraction, SDES/CNAME, BYE, application-defined APP, Extended Reports (Loss/Duplicate RLE, packet receipt times, RRTR/DLRR, statistics summary, VoIP metrics, unknown blocks), and compound RTCP packets, PLI/SLI/FIR/RRR/REMB/NACK/CCFB/TWCC feedback including validated Generic NACK FCI and no-delta packet status, RTP sequence-gap NACK tracking, and Pion-style NACK pair sequence helpers, SRTP/SRTCP NULL_HMAC_SHA1_80 authentication with ROC/SRTCP-index tracking and replay-window checks, SCTP INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK, HEARTBEAT/SHUTDOWN lifecycle, ABORT/ERROR causes, RE-CONFIG stream reset with DataChannel reset request/response packet helpers, FORWARD-TSN/I-FORWARD-TSN partial-reliability, and DATA/I-DATA/SACK packet parsing/writing, receive-side SACK state generation, DATA/I-DATA fragment reassembly with receive-buffer limits, CRC32C validation, and DCEP DataChannel OPEN/ACK codecs with Pion-compatible 4-byte ACK wire format and channel-type reliability and SDP/DTLS-role data-channel ID allocation/registry helpers plus PPID payload classification/normalization on reassembled messages and DataChannel DATA chunk construction, fragmentation, and send-state helpers, plus
  blocking UDP STUN binding, RTP/SRTP/RTCP/SRTCP packet, and same-socket STUN/DTLS/RTP/RTCP
  peer runtimes with SRTP/SRTCP send/receive helpers and a `std.Io.async` concurrent receive helper

The lower protocol layers remain codec-first so they can be fuzzed and embedded,
but practical runtime APIs are being added in priority order. HTTP/1 now has
blocking HTTP and HTTPS client/server-side transport helpers, HTTP/2 covers both
prior-knowledge h2c and RFC h2c Upgrade client/server flows, WebSocket includes a
blocking TCP runtime, and WebSocket clients also support WSS over the shared TLS
client transport; QUIC has Initial
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
handshake-backed protected session API. The protected WebTransport runtimes
enable CONNECT, H3 DATAGRAM, WebTransport max-sessions, and draft-13
per-session stream/data credit SETTINGS by default, then reject DATAGRAM send or
receive calls if the peer did not negotiate the matching capabilities.

## Build

```sh
zig build test
```

Runnable examples are under `examples/` and are wired into the build:

```sh
zig build examples
zig build run-http1-hello
zig build run-http2-h2c
zig build run-websocket-echo
# Linux only: raw std.os.linux.IoUring-backed clients
zig build run-linux-io-uring-http1
zig build run-linux-io-uring-http1-server
zig build run-linux-io-uring-websocket
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

var response = try netz.http1.runtime.Client.requestUri(
    allocator,
    io,
    "http://localhost:8080/",
    .{},
    .{},
);
defer response.deinit(allocator);
```

WebSocket can upgrade over the same TCP layer:

```zig
var ws = try netz.websocket.runtime.Client.connectUri(
    allocator,
    io,
    "ws://localhost:8080/chat",
    .{},
);
defer ws.close();

try ws.sendText("hello");
var frame = try ws.receiveFrame();
defer frame.deinit(allocator);
```

The HTTP and WebSocket URI helpers synthesize Host / `:authority` / `:scheme`
from the URI and can connect to host names, IPv4 literals, and bracketed IPv6
literals such as `http://[::1]:8080/` and `ws://[::1]:8080/chat`.

On Zig 0.16, `std.Io.Uring` exists but its `std.Io.net` networking hooks are
still unavailable. The portable runtimes therefore use the `std.Io` abstraction
through `netz.runtime.Backend.initAuto(.evented_then_threaded)`, which keeps
protocol modules on the `std.Io` abstraction and falls back to `std.Io.Threaded`
when the pinned Zig stdlib cannot compile/use Evented networking. Linux-only
HTTP/1 and cleartext WebSocket helpers (`requestUriLinuxIoUring` /
`connectUriLinuxIoUring`) remain available for raw `std.os.linux.IoUring`
experiments on IP-literal URIs; the Linux examples demonstrate those paths.

Handshake-backed WebTransport sessions expose the negotiated DATAGRAM budget so
callers can avoid sending a payload the underlying QUIC peer will reject:

```zig
var session = try netz.webtransport.runtime.HandshakeClientSession.connect(
    allocator,
    io,
    .{ .ip4 = .loopback(0) },
    server_addr,
    .{
        .authority = "localhost",
        .path = "/wt",
        .h3 = handshake_options,
    },
);
defer session.deinit();

if (session.maxDatagramPayloadSize()) |limit| {
    if ("hello".len <= limit) try session.sendDatagram("hello");
}
```

## Design notes

- Parsers keep slices pointing into caller-owned buffers unless a protocol needs
  mutation/unmasking (for example WebSocket frame payloads).
- Public structs expose decoded wire values and avoid hidden allocation; objects
  that allocate provide explicit `deinit` methods.
- The HTTP/2 HPACK helper maintains per-connection dynamic table state and RFC
  7541 Huffman strings; the stateless literal convenience helpers remain
  intentionally conservative.  HTTP/3 QPACK is still bootstrap/stateless and
  rejects dynamic-table instructions until a full encoder/decoder stream state
  machine is added.
- WebRTC support covers signaling/transport wire primitives (STUN, ICE, SDP,
  DTLS/RTP/SCTP headers), forming a foundation for peer-connection state
  machines and SRTP/SCTP data-channel layers.
