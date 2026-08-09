# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, and state helpers for:

- HTTP/1.1 requests, responses, header field syntax validation, chunked transfer decoding with strict no-leading-OWS chunk-size grammar, extension newline rejection, and extension limits, close-delimited and non-chunked-transfer-coded response bodies, runtime chunked
  transfer writing with validated and repeated-value-merged trailer fields, opt-in obsolete folded-field
  unfolding, strict allocation-free borrowed request/response head parsing into
  caller header storage with exact Content-Length pipeline offsets and
  method/status-aware response boundaries, request-target/status/reason-phrase start-line validation with method-specific asterisk/authority-form and no-fragment rules, status-forbidden response-body write rejection, keep-alive/upgrade handling, pipelined
  byte buffering for persistent connections, method-aware response body
  handling for HEAD and successful CONNECT, Host/authority delimiter validation, strict authority-form CONNECT target delimiter/userinfo rejection, malformed absolute-form authority validation including bracketed IPv6, and CONNECT tunnel helpers, interim 1xx response skipping plus
  server-side `Expect: 100-continue` handling even when body bytes are pre-read with invalid-head suppression, pure-digit Content-Length enforcement,
  TE-over-CL precedence with parsed `Content-Length` stripping, ambiguous body-length rejection
  across repeated/coalesced `Content-Length`, and unsupported transfer-coding and HTTP/1.0 transfer-coding rejection,
  and a blocking `std.Io.net` TCP client/server runtime with HTTP/1.1 default
  persistence, optional Host/default-port, CONNECT authority, and absolute-form authority synthesis, `http://`/`https://` URI helpers
  with userinfo rejection, host-name DNS and IPv4/bracketed-IPv6 literal connect support, TLS client transport via Zig `std.crypto.tls`
  with host verification plus OS/custom CA bundles, and a `std.Io.async`
  concurrent server helper
- HTTP/2 frame headers, RFC-bounded SETTINGS validation, DATA/HEADERS (including PADDED/PRIORITY self-dependency checks)/PRIORITY/PUSH_PROMISE/CONTINUATION/RST_STREAM payload parsing and active-stream reset propagation, a bootstrap
  HPACK static/literal encoder-decoder with RFC 7541 Huffman strings plus
  dynamic-table indexing/size-update state for long-lived runtimes with local decoder table-size enforcement and automatic
  peer table-size update emission plus h2/hyper-style non-indexing for volatile or oversized fields and automatic
  never-index encoding for sensitive fields, PING with opaque ACK matching, GOAWAY/WINDOW_UPDATE connection
  management including interleaved SETTINGS/PING/WINDOW_UPDATE/PRIORITY handling, active-stream RST_STREAM guarding, PUSH_PROMISE parent/promised-stream validation, GOAWAY propagation during stream reads and post-GOAWAY request suppression/rejection and same-control-stream GOAWAY emission with persistent control-stream offsets, default client server-push opt-out, connection- and stream-level flow-control enforcement including
  SETTINGS_INITIAL_WINDOW_SIZE updates and configurable advertisement, configurable SETTINGS_HEADER_TABLE_SIZE/SETTINGS_MAX_CONCURRENT_STREAMS/SETTINGS_MAX_FRAME_SIZE advertisement, bidirectional SETTINGS_MAX_CONCURRENT_STREAMS enforcement, SETTINGS_MAX_FRAME_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE validation with inbound advertised-frame-size enforcement,
  outbound frame splitting plus h2-style CONTINUATION chain flood, stream-id overflow, wrong-direction HEADERS, and idle-stream DATA/WINDOW_UPDATE send limits, with DATA sends that wait for WINDOW_UPDATE capacity
  and inbound DATA consumers that account for full padded frame payloads and restore connection/stream receive capacity,
  frame-envelope validation including fixed-size RST_STREAM and SETTINGS payload-multiple checks, stream-id direction/monotonicity validation, request/response trailers with forbidden-field rejection, pre-HEADERS frame ordering checks, interim 1xx response skipping and explicit server-side informational response sending, content-length
  validation with pure-digit Content-Length enforcement, HTTP/2 pseudo-header/lowercase field-name/value and control-character validation, `:method` token validation with case-sensitive HEAD/CONNECT/OPTIONS semantics and `:protocol` token validation,
  URI-like `:scheme`/origin-form `:path`/`:authority` validation with Host fallback and Host/`:authority` mismatch rejection,
  connection-specific header rejection including `TE` rules,
  status-forbidden response-body write rejection,
  traditional CONNECT header-only tunnel acceptance with DATA tunnel helpers and strict `:authority`-only host:port pseudo-header rules, CONNECT body/Content-Length rules, and opt-in RFC 8441 extended CONNECT / `:protocol` handling with irreversible
  SETTINGS_ENABLE_CONNECT_PROTOCOL downgrade rejection,
  open/accept/reject tunnel helpers and DATA-frame tunnel read/write mapping, RFC 7540 h2c Upgrade client/server helpers that carry `HTTP2-Settings` and receive/respond on stream 1, and a blocking prior-knowledge h2c client/server runtime with default `:authority` host/port synthesis and transport/URI-derived `:scheme`,
  `http://` URI helpers with host-name DNS and IPv4/bracketed-IPv6 literal connect support, and a `std.Io.async` concurrent server helper
- HTTP/3 frame, SETTINGS, DATAGRAM, request/response HEADERS+DATA helpers,
  SETTINGS-first control-stream negotiation with unique peer control-stream tracking, forbidden frame rejection on control/request streams, client-initiated push-stream rejection, and QPACK encoder/decoder critical stream registration with FIN/RESET_STREAM/STOP_SENDING closure rejection, RFC 9204 dynamic-table FIFO/absolute-relative indexing/eviction state, Required Insert Count wrapping, all relative/post-base dynamic field-line forms with blocking/eviction distinction and never-indexed preservation, Huffman-capable encoder and decoder instruction codecs, a connection-scoped decoder with out-of-order/split encoder-stream reassembly plus coalesced feedback, and a non-blocking encoder state with Known Received Count gating, decoder-stream reassembly, outstanding reference accounting, and prohibited-eviction prevention, GOAWAY and MAX_PUSH_ID monotonicity checks plus post-GOAWAY request suppression/rejection and same-control-stream GOAWAY emission with persistent control-stream offsets,
  CANCEL_PUSH/PUSH_PROMISE/MAX_PUSH_ID/PRIORITY_UPDATE payload codecs with malformed-payload rejection and advertised MAX_PUSH_ID enforcement for received PUSH_PROMISE frames,
  RFC 9218 Priority field parsing/serialization,
  request/response message encoding/decoding with ordered HEADERS/DATA/trailer handling, static or dynamic QPACK field-section decoding with per-stream Section Acknowledgment accounting, non-blocking Known-Received dynamic writers for request/response/interim/trailer sections with sensitive-field exclusion and speculative future inserts, inbound and outbound SETTINGS_MAX_FIELD_SECTION_SIZE enforcement, response-side PUSH_PROMISE tolerance, interim 1xx response skipping and runtime emission before final responses, and forbidden trailer-field rejection,
  HEADERS-only dynamic request/response writers for incremental DATA sending
  with Content-Length generation/verification and CONNECT/204/304 body guards,
  HTTP/3 pseudo-header/lowercase field-name, `:method` token validation with case-sensitive CONNECT/OPTIONS semantics, SETTINGS-gated `:protocol` token, URI scheme/origin-form path/authority, Host/`:authority`, traditional CONNECT body rules, and connection-specific header validation,
  DATA-frame aggregation, pure-digit content-length, three-digit `:status`, and status-forbidden response-body validation, stateless QPACK helpers with RFC 9204 static-table references, Huffman string literals, and literal fallback, a cleartext development runtime over the QUIC
  UDP frame endpoint, a protected 1-RTT QUIC STREAM runtime with STREAM frame
  splitting/reassembly, SETTINGS exchange, persistent QPACK encoder/decoder
  instruction streams in both connection directions, peer-capacity
  negotiation, and automatic non-blocking dynamic request/response compression
  after decoder feedback, and a handshake-backed protected client/server
  runtime; both server paths retain bounded per-request-stream reassembly state
  so interleaved streams are not dropped, surface RESET_STREAM request
  cancellation, and expose client/server cancel helpers that send
  RESET_STREAM+STOP_SENDING with conditional QPACK stream cancellation. Servers
  also expose two-phase GOAWAY initiation/completion and drain-completion
  tracking over queued and application-owned requests. Clients can send
  pre-request or live RFC 9218 PRIORITY_UPDATE frames on persistent control
  streams, with received priority field values owned by connection state.
  Protected clients also expose split `sendRequest`/`receiveResponse` APIs with
  bounded per-stream response reassembly, preserving interleaved responses and
  resets instead of discarding non-target streams. `receiveNextResponse`
  provides an event-style response/reset queue with explicit stream IDs, while
  outstanding request tracking rejects unknown or duplicate completion and
  enforces the configured concurrency bound. Protected clients and servers also
  expose `startRequest`/`sendRequestBody` and
  `startResponse`/`sendResponseBody`, preserving per-stream QUIC offsets across
  multiple DATA chunks and enforcing declared Content-Length at FIN. Streaming
  messages can instead finish with dynamic QPACK trailer HEADERS through
  `finishRequestTrailers`/`finishResponseTrailers`, plus a `std.Io.async`
  request receive helper for the development runtime
- QUIC varints, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames) with frame-payload close-error classification, shortest-form frame-type enforcement, empty non-FIN STREAM no-op rejection, stream-count bounds on MAX_STREAMS/STREAMS_BLOCKED and
  RFC 9000 packet-type legality checks for Initial/Handshake/0-RTT/1-RTT, typed
  RFC-defaulted transport-parameter encoding/validation (duplicate detection,
  endpoint-specific client/server parameter rules, preferred-address parsing and specified-address validation,
  max UDP payload 1200..65527/idle-timeout/ACK delay/stream-count bounds), Retry packet codec
  with version-specific integrity-tag verification, plus CRYPTO stream reassembly with empty-frame no-op handling and duplicate-overlap conflict detection,
  v1/v2 Initial key/header/payload protection with version-aware salts, HKDF labels, long-header type bits, fixed-bit, connection-ID length, supported-version, and header-protection sample-bound validation, version-specific TLS QUIC packet-protection labels, protected Initial packet seal/open, long-header packet boundary peeking for coalesced datagrams, Version Negotiation packet codec with randomized response first byte and reserved-version greasing tolerance, RFC 9368 `version_information` transport parameters, endpoint-level unsupported-version responses, client-side Version Negotiation selection/restart helpers, and automatic handshake restart on negotiated versions,
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
  and UDP-payload limits to established 1-RTT connection objects with static-key-derived stateless reset token and packet helpers,
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
  previous receive/send generations for reordered short-header packets, peer-triggered
  send-key synchronization before ACK, and RFC 9001 AES-128-GCM `2^23`
  per-generation confidentiality plus `2^52` lifetime authentication-failure
  integrity limits with proactive key rotation and terminal limit handling,
  configurable RFC 9438 CUBIC (default) and NewReno congestion-window control with
  bytes-in-flight send admission wired into 1-RTT sending and ACK/ACK_ECN processing,
  deterministic timestamp injection plus automatic monotonic runtime timing,
  default configurable RFC 9406 HyStart++ slow-start overshoot prevention with
  packet-number RTT rounds, Conservative Slow Start, jitter recovery, and public
  window/in-flight observability, high-BDP CUBIC performance regression coverage, and receive-side ECN counter
  reporting, sent ECN counter validation, ACK_ECN CE congestion response,
  reordered-ACK_ECN tolerance, and plain-ACK ECN fallback disablement, RFC 9002-style RTT/PTO estimation with negotiated ACK-delay
  encode/decode and adjustment, packet/time-threshold loss detection, earliest loss/PTO timer
  deadlines, capped exponential PTO backoff, two-probe PTO service, and persistent
  congestion detection that collapses the congestion window and resets the RTT
  measurement epoch after long contiguous lost periods, default RFC 9002 token-bucket
  send pacing with configurable burst/disable controls, exact retry deadlines,
  ACK bypass, transactional rejection, and path-reset handling, allocation-free short-packet
  sealing into caller storage and connection-level plaintext/protected send-buffer
  reuse (while retaining stable recovery payload ownership), PMTUD/DPLPMTUD path MTU
  probe sizing state with IPv4/IPv6 ceilings, loss-driven search backoff, and
  1-RTT PING+PADDING probe packets wired to ACK/loss feedback,
  a 1-RTT recovery queue for PTO plus packet-threshold and time-threshold
  retransmission of unacknowledged ack-eliciting frame payloads, exact frame
  wire-length prediction, allocation-free caller-storage multi-packet protection,
  single-allocation batch wrappers, and portable UDP batch submission that maps
  to Linux `sendmmsg` through Zig `std.Io`, including paced two-probe PTO batch
  submission and transactional partial-send recovery that never reuses an
  already-emitted packet number, plus zero-copy Linux `UDP_SEGMENT` offload for
  contiguous equal-sized packet batches with one-shot capability fallback and
  opt-in Linux `UDP_GRO` receive coalescing with shared zero-copy segment
  ownership, in-place current-key 1-RTT decryption, reusable frame scratch,
  and strict wire-order low-peak batch servicing,
  endpoint-level connection-ID routing with unroutable zero-DCID long-header drops and static-key token derivation primitives for stable multi-connection
  demultiplexing wired into raw UDP receive routing and 1-RTT connection
  delivery, including peer-path binding and active-migration-disabled route
  rejection, NEW_CONNECTION_ID receive/send active-limit, duplicate-CID/reset-token validation and RETIRE_CONNECTION_ID lifecycle/preflight state with NEW/RETIRE CID-error close mapping wired into
  1-RTT, transport/application CONNECTION_CLOSE state including frame-payload, ACK, ACK_FREQUENCY negotiation, DATAGRAM negotiation, stream-limit/state/flow-control/final-size/data-conflict, server-only frame, and selected semantic error close emission, PATH_CHALLENGE/PATH_RESPONSE validation state with duplicate challenge suppression and caller-storage batch drains/sends wired into 1-RTT,
  peer-migration helpers that honor disable_active_migration, apply a server
  preferred_address by selecting its CID/reset token and peer IP/port, reset
  anti-amplification and PMTUD path state, queue PATH_CHALLENGE,
  track path-validation deadlines, retry timed-out challenges, record failed
  validation attempts, and validate the new path on a matching PATH_RESPONSE,
  plus a blocking UDP endpoint runtime for frame datagrams with a
  `std.Io.async` concurrent receive helper
- WebSocket handshakes with Host authority, body-framing rejection, duplicate-subprotocol and nonce validation, frame masking, strict frame/control
  validation including control/continuation RSV rejection, typed close-frame parse/write helpers and close payload checks, fragmented message assembly with aggregate
  message-size limits, automatic active-state PING→PONG and close echo/completed-close short-circuit handling plus tungstenite-style data-send/read suppression after receiving Close,
  outbound text/close/control-frame validation plus codec-level invalid-frame write rejection,
  subprotocol token validation with strict client response selection, split-header subprotocol and extension-offer negotiation, optional permessage-deflate negotiation with
  no-context-takeover RFC 7692 sync-flush raw-DEFLATE encode/decode plus quoted window-bit parsing and rejection of
  unsupported extension parameters/window sizes, framed 101 upgrade responses, and compressed fragmented sends, serialized connection writes, a blocking TCP
  client/server runtime over HTTP/1 Upgrade with a `std.Io.async` concurrent
  server helper, `ws://`/`wss://` URI helpers with userinfo rejection, host-name DNS and IPv4/bracketed-IPv6 literal connect support plus
  Host/port synthesis, TLS client transport shared with HTTP/1, and RFC 8441
  WebSocket-over-HTTP/2 adapters that negotiate `:protocol = websocket`,
  subprotocols, permessage-deflate, reject duplicate/legacy critical handshake
  fields, and use transport-derived `:scheme` over an h2 DATA tunnel
- MQTT 3.1.1/5 fixed headers, CONNECT/CONNACK with Last Will,
  version-scoped username/password flag validation and payload support, PUBLISH,
  PUBACK/PUBREC/PUBREL/PUBCOMP acknowledgements, SUBSCRIBE/SUBACK,
  UNSUBSCRIBE/UNSUBACK, PING,
  DISCONNECT with MQTT v5 minimal reason-only encoding, AUTH enhanced-authentication exchanges, properties, exact packet bounds, minimal remaining length, MQTT UTF-8 string validation, response-topic/topic-name/filter validation, clean-session empty-client-id checks, version-specific MQTT 3.1.1/v5 property and SUBSCRIBE option validation, payload-format UTF-8 validation, and
  wildcard and shared-subscription matching with MQTT 5 No Local/shared-subscription combination rejection,
  a broker-grade topic-level subscription trie with hashed literal edges,
  allocation-free caller-buffer matching, exact linear overflow fallback,
  subscription-option replacement, publisher-aware No Local filtering, and
  per-group/filter shared-subscription round robin, plus a blocking TCP client/server runtime with a
  `std.Io.async` concurrent server helper, MQTT v5 Server Keep Alive, Receive Maximum capped by local inflight limits, Maximum Packet Size, negotiated-or-configured Maximum QoS and Retain Available enforcement for incoming/outgoing publishes, and Topic Alias negotiation/resolution capped to local alias storage with outgoing alias registration checks, QoS publish inflight limiting, and
  QoS 2 exactly-once publish handshakes with unsolicited PUBREL rejection and negative-PUBREC receive-slot release, including MQTT v5 PUBACK/PUBREC/PUBREL/PUBCOMP reason-code/property validation with minimal reason-only encoding, dedicated UNSUBACK parsing, and negative publish acknowledgement propagation
- WebTransport capsules, unidirectional stream headers, CONNECT metadata with client-bidi session-id validation, and
  datagram mapping, session lifecycle/counter state, plus a cleartext
  development runtime over the HTTP/3 dev transport, a protected QUIC 1-RTT
  runtime over protected HTTP/3 with automatic WebTransport/H3 DATAGRAM
  SETTINGS advertisement and negotiation checks, and a handshake-backed
  protected runtime that uses QUIC 1-RTT DATAGRAM send/receive queues with
  WebTransport payload-size accounting and batch receive helpers
- WebRTC building blocks: STUN, ICE connectivity-check helpers with priority encode/decode,
  USERNAME ufrag demux, PRIORITY/ICE-CONTROLLING/CONTROLLED/USE-CANDIDATE role-conflict tiebreaker decisions, UNKNOWN-ATTRIBUTES helpers, and authenticated 487 Role Conflict error responses plus
  MESSAGE-INTEGRITY (HMAC-SHA1) and FINGERPRINT validation,
  XOR-MAPPED-ADDRESS helpers, ICE candidates with RFC/Pion-compatible network/transport/component/candidate/TCP/relay-protocol type string parsing plus candidate type/local/TCP/relay priority, pair-priority, IPv6 zone normalization, extension lookup/export/mutation/empty-value round-tripping, and candidate-ufrag generation matching helpers, SDP type helpers with strict and case-insensitive parsing, SDP candidate-line formatting, SDP parsing plus generic/repeated attribute helpers, structured origin/session-name/timing-line, session contact-line, structured repeat/time-zone, ranged media-line, media information-line, structured connection-line, bandwidth-line, encryption-key-line, and RTCP-address formatting/extraction and full-session writing with DTLS fingerprint, ICE-lite and DTLS/ICE transport attribute-line helpers, DTLS setup role parse/generation helpers,
  ICE credential token validation, BUNDLE-aware media selection and media-direction parse/reverse/intersection/negotiation-preference/BUNDLE/MID attribute-line helpers including BUNDLE MID extraction/matching, direct MID media lookup, and application/DataChannel media detection, ICE trickle/renomination option detection and advertisement formatting, RTP `extmap` extraction and attribute-line formatting, RTCP feedback constants plus RTP codec-line and RTPMAP/FMTP/RTCP-feedback attribute-line format/write/dedupe/intersection helpers with Pion-compatible media-kind codec typing, RTX/FlexFEC payload lookup, FlexFEC/ULPFEC MIME mapping, and default codec clock matching, SDP track extraction with SSRC/RID/MID lookup and MSID/structured msid-semantic/RID/simulcast/SSRC attribute-line helpers and Pion-style possible/repeated-MID Plan-B detection helpers, and modern/legacy SCTP DataChannel port formatters plus DataChannel protocol-token validation, Pion-compatible max-message-size metadata defaults and `sctp-init` decoding, empty DataChannel PPID placeholder validation, validated single and multi-record DTLS record headers, RTP packets/extensions/padding, RTCP packet/batch/compound wire-size helpers, RTCP
  RFC 5285 one-byte/two-byte and raw RFC 3550 header extension codecs for MID/RID/RSID/TWCC/audio-level/playout-delay/video-orientation/absolute-send-time/absolute-capture-time/video-layer-allocation style metadata encode/decode, profile-aware mutation/clear including raw ID-0 payloads, and timestamp-estimation helpers with Pion-style VLA payload sizing, RFC 5285 padding termination, and lenient TWCC/audio-level/playout-delay/absolute-send-time/absolute-capture-time/video-layer-allocation parsing plus unknown-RTP MID/RID/RSID demux details, sender/receiver reports with profile extensions and wire-size helpers plus sender/receiver-report statistics including RTP sequence-cycle accounting, signed cumulative-loss helpers/reporting, and timestamp-wrap-safe jitter, LSR/DLSR timing, compact-NTP RTT helpers, and Pion-style packet/compound destination SSRC and compound CNAME extraction, SDES/CNAME, BYE, application-defined APP with base packet wire-size helpers, Extended Reports (Loss/Duplicate RLE chunk helpers/builders, packet receipt times, RRTR/DLRR RTT helpers, statistics summary, VoIP metrics, unknown blocks, wire-size helpers), compound RTCP packets plus reduced-size RTCP packet batches and RawPacket-style unknown RTCP round-tripping, PLI/SLI/FIR/RRR/REMB/NACK/CCFB/TWCC feedback including saturated REMB bitrate parsing and feedback wire-size helpers, RFC 8888 CCFB sequence/arrival-offset/arrival-time and wire-size helpers plus validated 13-bit arrival offsets, and TWCC sequence/arrival lookup plus packet-status chunk, wire-size, 64ms reference-time, and 250us delta quantization helpers with compact status-vector writes, validated Generic NACK FCI and no-delta packet status, RTP sequence-gap NACK tracking, and Pion-style NACK pair range/list sequence helpers, SRTP/SRTCP NULL_HMAC_SHA1_80 authentication with ROC/SRTCP-index tracking and replay-window checks, SCTP INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK, HEARTBEAT/SHUTDOWN lifecycle, ABORT/ERROR causes, RE-CONFIG stream reset with DataChannel reset request/response packet helpers, FORWARD-TSN/I-FORWARD-TSN partial-reliability, and DATA/I-DATA/SACK packet parsing/writing with I-DATA fragment-sequence validation, receive-side SACK state generation, DATA/I-DATA fragment reassembly with receive-buffer limits, CRC32C validation, and DCEP DataChannel OPEN/ACK codecs with Pion-compatible 4-byte ACK wire format and channel-type reliability and SDP/DTLS-role data-channel ID allocation/registry helpers plus PPID payload classification/normalization on reassembled messages and DataChannel DATA chunk construction, fragmentation, and send-state helpers, plus
  blocking UDP STUN binding, RTP/SRTP/RTCP/SRTCP packet or reduced-size packet-batch, and same-socket STUN/DTLS/RTP/RTCP
  peer runtimes with SRTP/SRTCP and multi-record DTLS encode/send/receive/demux helpers and a `std.Io.async` concurrent receive helper

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

Native microbenchmarks are also wired into the build.  Prefer `ReleaseFast`
when collecting performance evidence:

```sh
zig build bench -Doptimize=ReleaseFast
zig build bench-http1-parse -Doptimize=ReleaseFast
zig build bench-http2-hpack -Doptimize=ReleaseFast
zig build bench-http3-dev -Doptimize=ReleaseFast
zig build bench-http3-qpack -Doptimize=ReleaseFast
zig build bench-mqtt-router -Doptimize=ReleaseFast
zig build bench-quic-short-packet -Doptimize=ReleaseFast
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
```

The aggregate `bench` step runs the current protocol microbenchmarks:

- HTTP/1 borrowed request-head parsing versus owned full request parsing,
- HTTP/2 HPACK stateful dynamic-table encode/decode versus stateless helpers,
- HTTP/3 cleartext development request/response round trips,
- HTTP/3 QPACK field-section encoding against a populated dynamic table,
- MQTT subscription-router trie matching versus a linear filter scan,
- QUIC short-packet sealing with caller-provided storage versus the allocating
  convenience wrapper,
- QUIC Linux `UDP_SEGMENT` batching versus `sendmmsg`, plus `UDP_GRO`
  coalesced receive versus plain per-datagram receive,
- QUIC 1-RTT sequential packet protection/send versus allocation-free batched
  protection with reusable scratch and UDP GSO/sendmmsg submission,
- end-to-end QUIC 1-RTT UDP_GRO batch receive versus per-packet receive,
  including decryption, frame parsing, state application, and cleanup.

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
  7541 Huffman strings; the stateless literal convenience helpers accept legal
  leading table-size updates while keeping dynamic state scoped to one block.
  HTTP/3 QPACK now provides RFC 9204 dynamic-table state with single-pass
  exact/name matching, dynamic field
  sections, both instruction stream codecs, and Protected plus handshake-backed
  client/server decode-side live encoder-stream processing with decoder
  feedback. Both protected runtimes persist their encoder/decoder streams and
  automatically use peer-capacity-bounded, reference-safe dynamic compression
  for repeated request and response fields after either preconfigured 1-RTT or
  a full QUIC handshake. The preconfigured 1-RTT runtime also reuses protected
  packet scratch and batches multi-packet STREAM sends through UDP GSO or
  sendmmsg while preserving packet-number progress on partial socket writes.
  Both runtimes keep outbound encoding non-blocking: newly inserted fields stay
  literal until acknowledged. On receive they can advertise
  non-zero `SETTINGS_QPACK_BLOCKED_STREAMS` up to the bounded concurrent-stream
  limit, retain multiple complete dependent request/response messages, continue
  processing split/reordered encoder instructions, and resume each once its
  Required Insert Count is available.
- WebRTC support covers signaling/transport wire primitives (STUN, ICE, SDP,
  DTLS/RTP/SCTP headers), forming a foundation for peer-connection state
  machines and SRTP/SCTP data-channel layers.
