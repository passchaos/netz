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
- HTTP/2 frame headers, RFC-bounded SETTINGS validation, DATA/HEADERS (including PADDED/PRIORITY self-dependency checks)/PRIORITY/PUSH_PROMISE/CONTINUATION/RST_STREAM payload parsing, RFC 8336 single-probe exact-indexed ORIGIN origin-set state, RFC 7838 exact-indexed ALTSVC connection/stream advertisements with per-target replacement, and active-stream reset propagation, a bootstrap
  HPACK static/literal encoder-decoder with RFC 7541 Huffman strings,
  pseudo-header static fast paths, empty-dynamic-table lookup skips, O(1)
  FIFO dynamic-index eviction, and single-pass request/response pseudo-header
  and length extraction, plus
  exact dynamic-table indexing/size-update state for long-lived runtimes with local decoder table-size enforcement and automatic
  peer table-size update emission plus h2/hyper-style non-indexing for volatile or oversized fields and automatic
  never-index encoding for sensitive fields, PING with opaque ACK matching, GOAWAY/WINDOW_UPDATE connection
  management including interleaved SETTINGS/PING/WINDOW_UPDATE/PRIORITY handling and compacting interleaved request FIFO reuse, RFC 9218 SETTINGS_NO_RFC7540_PRIORITIES negotiation and client-only PRIORITY_UPDATE signaling with indexed bounded pre-request buffering, single-probe reservation/replacement, cached idle-request pruning, and promised-push validation, active-stream RST_STREAM guarding, explicit opt-in PUSH_PROMISE promised-request/pushed-response lifecycle with parent/promised-stream validation, single-lookup local push reservations, indexed reserved/pending push lookups, O(1) cursor FIFO promised-request notification delivery, head/tail-cancel fast paths with targeted pending-index repair, and client RST_STREAM(CANCEL) refusal of reserved pushes, GOAWAY propagation during stream reads and post-GOAWAY request suppression/rejection, cached multi-set drain-floor checks, and same-control-stream GOAWAY emission with persistent control-stream offsets, default client server-push opt-out, connection- and stream-level flow-control enforcement including
  transactional single-pass SETTINGS_INITIAL_WINDOW_SIZE updates and configurable advertisement, configurable SETTINGS_HEADER_TABLE_SIZE/SETTINGS_MAX_CONCURRENT_STREAMS/SETTINGS_MAX_FRAME_SIZE advertisement, bidirectional SETTINGS_MAX_CONCURRENT_STREAMS enforcement, SETTINGS_MAX_FRAME_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE validation with inbound advertised-frame-size enforcement,
  outbound frame splitting plus h2-style CONTINUATION chain flood, stream-id overflow, indexed active-stream tracking with single-probe activation, wrong-direction HEADERS, and idle-stream DATA/WINDOW_UPDATE send limits, with DATA sends that wait for WINDOW_UPDATE capacity
  and inbound DATA consumers that account for full padded frame payloads with single-probe indexed stream-window state and restore connection/stream receive capacity,
  frame-envelope validation including fixed-size RST_STREAM and SETTINGS payload-multiple checks, stream-id direction/monotonicity validation, request/response trailers with forbidden-field rejection, pre-HEADERS frame ordering checks, interim 1xx response skipping and explicit server-side informational response sending, content-length
  validation with pure-digit Content-Length enforcement, indexed response-body semantics retention with single-probe updates, HTTP/2 pseudo-header/lowercase field-name/value and control-character validation, `:method` token validation with case-sensitive HEAD/CONNECT/OPTIONS semantics and `:protocol` token validation,
  URI-like `:scheme`/origin-form `:path`/`:authority` validation with Host fallback and Host/`:authority` mismatch rejection,
  connection-specific header rejection including `TE` rules,
  status-forbidden response-body write rejection,
  traditional CONNECT header-only tunnel acceptance with DATA tunnel helpers and strict `:authority`-only host:port pseudo-header rules, CONNECT body/Content-Length rules, and opt-in RFC 8441 extended CONNECT / `:protocol` handling with irreversible
  SETTINGS_ENABLE_CONNECT_PROTOCOL downgrade rejection,
  open/accept/reject tunnel helpers and DATA-frame tunnel read/write mapping, RFC 7540 h2c Upgrade client/server helpers that carry `HTTP2-Settings` and receive/respond on stream 1, and a blocking prior-knowledge h2c client/server runtime with default `:authority` host/port synthesis and transport/URI-derived `:scheme`,
  `http://` URI helpers with host-name DNS and IPv4/bracketed-IPv6 literal connect support, and a `std.Io.async` concurrent server helper
- HTTP/3 frame, SETTINGS, DATAGRAM, request/response HEADERS+DATA helpers,
  RFC 9297 Capsule Protocol TLV parsing/writing with allocation-free
  caller-buffer encoding, `Capsule-Protocol` structured-field validation, and
  an incremental iterator for CONNECT stream data, borrowed and owning
  normalized HTTP/3 origin keys for conservative connection-reuse/coalescing
  policy decisions including direct owned-key construction from parsed origins,
  plus an indexed generic origin-keyed idle pool with chunked case-folded hashing and single-lookup release checks for runtime-specific
  client handles with explicit expiry pruning and targeted index repair,
  SETTINGS-first control-stream negotiation with unique peer control-stream tracking, forbidden frame rejection on control/request streams, client-initiated push-stream rejection, and QPACK encoder/decoder critical stream registration with FIN/RESET_STREAM/STOP_SENDING closure rejection, RFC 9204 dynamic-table FIFO/absolute-relative indexing/eviction state, Required Insert Count wrapping, all relative/post-base dynamic field-line forms with blocking/eviction distinction and never-indexed preservation, Huffman-capable encoder and decoder instruction codecs, a connection-scoped decoder with out-of-order/split encoder-stream reassembly plus coalesced feedback, and a non-blocking encoder state with Known Received Count gating, decoder-stream reassembly, single-pass outstanding reference accounting with adjacent duplicate fast paths, single-probe pending-section indexing, tail-release fast paths, and prohibited-eviction prevention, GOAWAY and MAX_PUSH_ID monotonicity checks plus post-GOAWAY request suppression/rejection, cached multi-set drain-floor checks, and same-control-stream GOAWAY emission with persistent control-stream offsets,
  collision-verified hash indexes for current QPACK exact/name matches with
  zero-reference lookup/encoding short-circuits, restricted-reference scan
  fallback, O(1) FIFO eviction index retirement, and indexed QPACK static-name
  lookups with pseudo-header fast paths,
  CANCEL_PUSH/PUSH_PROMISE/MAX_PUSH_ID/PRIORITY_UPDATE payload codecs with malformed-payload rejection, indexed per-ID control-state lookups with single-probe priority replacement, and advertised MAX_PUSH_ID enforcement for received PUSH_PROMISE frames,
  RFC 9218 Priority field parsing/serialization,
  request/response message encoding/decoding with ordered HEADERS/DATA/trailer handling, static or dynamic QPACK field-section decoding with indexed per-stream Section Acknowledgment/cancellation accounting with targeted index repair and prefix-skipping cancellation compaction, non-blocking Known-Received dynamic writers for request/response/interim/trailer sections with sensitive-field exclusion and speculative future inserts, inbound and outbound SETTINGS_MAX_FIELD_SECTION_SIZE enforcement, response-side PUSH_PROMISE tolerance, interim 1xx response skipping and runtime emission before final responses, and forbidden trailer-field rejection,
  HEADERS-only dynamic request/response writers for incremental DATA sending
  with Content-Length generation/verification, parsed length reuse, and
  CONNECT/204/304 body guards,
  an incremental message reader that emits owned request/response heads,
  reuses parsed pseudo-header/Content-Length lookups, preallocates aggregated
  DATA bodies from declared lengths under buffered-byte caps, exposes
  bounded-window DATA availability, dynamic trailers, and FIN while validating
  informational responses and Content-Length without aggregating body bytes,
  HTTP/3 pseudo-header/lowercase field-name, `:method` token validation with case-sensitive CONNECT/OPTIONS semantics, SETTINGS-gated `:protocol` token, URI scheme/origin-form path/authority, Host/`:authority`, traditional CONNECT body rules, and connection-specific header validation,
  DATA-frame aggregation, pure-digit content-length, three-digit `:status`, and status-forbidden response-body validation, stateless QPACK helpers with RFC 9204 static-table references, Huffman string literals, and literal fallback, a cleartext development runtime over the QUIC
  UDP frame endpoint, a protected 1-RTT QUIC STREAM runtime with STREAM frame
  splitting/reassembly, SETTINGS exchange, persistent QPACK encoder/decoder
  instruction streams in both connection directions, peer-capacity
  negotiation, and automatic non-blocking dynamic request/response compression
  after decoder feedback, and a handshake-backed protected client/server
  runtime with `https://` URI endpoint parsing/DNS/literal target resolution
  plus `HandshakeClient.connectUri` / `requestUri` for public H3 client
  tooling; both server paths retain indexed bounded per-request-stream reassembly state
  so interleaved streams are not dropped, surface RESET_STREAM request
  cancellation, and expose client/server cancel helpers that send
  RESET_STREAM+STOP_SENDING with conditional QPACK stream cancellation. Servers
  also expose two-phase GOAWAY initiation/completion and drain-completion
  tracking over queued and indexed application-owned requests. Clients can send
  pre-request or live RFC 9218 PRIORITY_UPDATE frames on persistent control
  streams, including promised-push priorities. Received priority fields are
  owned and retained per request stream or push ID rather than collapsing
  unrelated elements into one connection-global value.
  Protected clients also expose split `sendRequest`/`receiveResponse` APIs with
  indexed bounded per-stream request/response reassembly with single-probe buffered stream creation,
  indexed buffered-presence checks, short-circuit ready polling, and targeted ready-stream lookup, preserving interleaved responses and
  resets instead of discarding non-target streams. `receiveNextResponse`
  provides an indexed cursor-backed FIFO event-style response/reset queue with
  empty-reset insert fast paths, single-probe reset recording, and explicit stream IDs, while
  outstanding request tracking uses single-probe client opens/server activation and rejects unknown or duplicate completion and
  enforces the configured concurrency bound. Protected clients and servers also
  expose `startRequest`/`sendRequestBody` and
  `startResponse`/`sendResponseBody`, preserving per-stream QUIC offsets across
  multiple DATA chunks with single-lookup chunk accounting plus cached FIN cleanup and enforcing declared Content-Length at FIN. Streaming
  messages can instead finish with dynamic QPACK trailer HEADERS through
  indexed streaming body state for
  `finishRequestTrailers`/`finishResponseTrailers`. Preconfigured-protection
  and handshake-backed servers expose
  `receiveRequestEvent`/`readRequestData`, while their clients expose
  per-stream `receiveResponseEvent`/`readResponseData` plus
  `receiveNextResponseEvent` for one tquic-style poll loop over every indexed
  outstanding response and reset. Both directions provide
  indexed active streaming readers, bounded-window network reads with automatic QPACK head/trailer feedback,
  interleaved-stream and reset identity preservation, Content-Length
  validation, prepared reset-record fast paths, and no full-body aggregation. When UDP_GRO is enabled, protected
  and handshake packet pumps retain the decrypted batch behind a one-packet
  cursor, and reuse compacted pending receive slots, amortizing recvmsg/decryption without bulk-inserting the whole GRO
  payload into a small HTTP/3 stream window. Handshake streaming readers return
  consumed protocol offsets to both QUIC flow-control levels, compact the
  transport overlap-validation window, keep reset and cancelled-push FIFO queues
  on O(1) cursor pops, and emit ACK/MAX_DATA/MAX_STREAM_DATA so bodies can
  continue beyond their initially negotiated stream credit. Both
  protected clients also maintain persistent MAX_PUSH_ID/CANCEL_PUSH control
  state with monotonic advertisement, per-ID cancellation retention, local
  STOP_SENDING of active cancelled pushes, single-probe cancellation recording,
  and advertised-range validation.
  Streaming response readers decode PUSH_PROMISE into owned promised-request
  heads, preserve the push ID, enforce the advertised limit, and account
  dynamic QPACK section feedback instead of discarding promised fields like
  the current reference runtimes. Push promise registration uses single-probe
  indexes, and push stream binding reuses one map probe. Protected and handshake runtimes also bind
  reordered server-initiated push streams to indexed promises, expose indexed targeted
  streaming and owned aggregate pushed-response APIs, and can emit
  PUSH_PROMISE plus the corresponding unidirectional pushed response with
  shared dynamic QPACK state, plus a
  `std.Io.async` request receive helper for the development runtime
- QUIC varints, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames) with frame-payload close-error classification, shortest-form frame-type enforcement, empty non-FIN STREAM no-op rejection, stream-count bounds on MAX_STREAMS/STREAMS_BLOCKED and
  RFC 9000 packet-type legality checks for Initial/Handshake/0-RTT/1-RTT, typed
  RFC-defaulted transport-parameter encoding/validation (duplicate detection,
  endpoint-specific client/server parameter rules, preferred-address parsing and specified-address validation,
  max UDP payload 1200..65527/idle-timeout/ACK delay/stream-count bounds), Retry packet codec
  with version-specific integrity-tag verification, plus CRYPTO stream reassembly with empty-frame no-op handling and duplicate-overlap conflict detection,
  v1/v2 Initial key/header/payload protection with version-aware salts, HKDF labels, long-header type bits, fixed-bit, connection-ID length, supported-version, and header-protection sample-bound validation, version-specific TLS QUIC packet-protection labels, protected Initial packet seal/open, long-header packet boundary peeking for coalesced datagrams, Version Negotiation packet codec with randomized response first byte and reserved-version greasing tolerance, RFC 9368 `version_information` transport parameters, endpoint-level unsupported-version responses, integrated server-side response-and-continue handling, client-side Version Negotiation selection/restart helpers, and automatic handshake restart on negotiated versions,
  Initial CRYPTO byte exchange over UDP with RFC 9000 1200-byte Initial
  datagram padding/validation, MTU-bounded multi-Initial CRYPTO packetization
  and cross-datagram TLS-message reassembly for large post-quantum
  ClientHello/ServerHello flights, client-carried Initial address tokens,
  server-side token validation hooks, and server-issued address-validation
  NEW_TOKEN frames, coalesced Initial+Handshake CRYPTO datagram helpers,
  bounded RFC 9002-style exponential PTO retries for synchronous client
  Initial/0-RTT and server Initial+Handshake flights with fresh packet numbers,
  plus configurable retry exhaustion and total wait bounds and deterministic
  whole-flight loss injection tests, HMAC-based
  address-validation token helpers for Retry/NEW_TOKEN with lifetime, version,
  peer-address binding, Retry ODCID/RSCID binding, secret rotation,
  digest-indexed single-lookup replay filtering with export/restore snapshots, Retry datagram issue/validate helpers, client-side Retry
  processing that enforces one-Retry/early-Retry rules, automatically resends
  the exact ClientHello under Retry-derived Initial keys, ignores invalid Retry
  injection, suppresses 0-RTT replay, plus an integrated server Retry policy
  with secure nonce generation, queued pre-Retry 0-RTT discard, and retried
  Initial token/DCID/transport-parameter validation, minimal TLS
  ClientHello/ServerHello/EncryptedExtensions/Finished encoding and parsing,
  protected Initial ClientHello ↔ ServerHello exchange, protected Handshake
  packet server/client Finished flights, and handshake/application secret
  derivation for QUIC, an integrated minimal client/server handshake for QUIC v1/v2 that emits
  practical transport parameters and applies negotiated flow-control, stream,
  and UDP-payload limits to established 1-RTT connection objects with static-key-derived stateless reset token and packet helpers,
  packet-number space ACK tracking with cached retained-packet counts, tail
  ACK-range append/removal fast paths, and bounded duplicate/old packet suppression,
  ACK range semantic validation plus monotonic sent-packet insertion fast paths and indexed exact sent-packet lookup with
  no-new-ACK short-circuiting, tail-forget fast paths, cached sortedness for
  ACK/loss scans, and single-pass ACK marking,
  receive-frame semantic preflight before multi-frame side effects, and adaptive truncated packet-number
  encoding wired into 1-RTT ACK/STREAM exchange, indexed stream send/receive state with
  duplicate-overlap conflict detection, offset reassembly, FIN, RESET_STREAM final-size validation, and STOP_SENDING
  to RESET_STREAM response handling,
  RFC 9221 QUIC DATAGRAM negotiation limits with 1-RTT send helpers,
  receive queues, max-payload calculation, queue overflow/drop counters, and
  oversized/disabled DATAGRAM rejection,
  RFC 9287 `grease_quic_bit` transport-parameter negotiation with strict
  pre-negotiation fixed-bit validation, negotiated zero-bit receive routing,
  and connection-seeded unpredictable 1-RTT QUIC Bit emission,
  draft ACK_FREQUENCY and IMMEDIATE_ACK frame codecs with `min_ack_delay`
  transport-parameter negotiation and opt-in 1-RTT state updates for requested
  ACK threshold/max-delay/reordering behavior, plus automatic ACK coalescing
  that respects the negotiated threshold, max-delay timer, and IMMEDIATE_ACK
  override,
  flow-control state for MAX_DATA/MAX_STREAM_DATA/BLOCKED frames wired into
  1-RTT DATA_BLOCKED/MAX_DATA and STREAM_DATA_BLOCKED/MAX_STREAM_DATA handling
  with one advisory BLOCKED emission per unchanged limit to avoid retry-loop
  packet storms and opt-in adaptive receive-window growth,
  stream-count flow control with MAX_STREAMS and STREAMS_BLOCKED handling plus
  the same per-limit duplicate suppression for stream-count exhaustion,
  protected 0-RTT long-header packet seal/open and frame datagram helpers with
  0-RTT packet-type restrictions, an indexed owning origin+ALPN session cache with
  cached transactional LRU eviction and stats, expiry, independent TLS session copies, stable
  cache/lease/early-data stats, exclusive single-use early-data leases with
  single-lookup lease indexing, RFC
  9000 §7.4.1 remembered-parameter
  filtering/reduction checks, RFC 9221 DATAGRAM restoration, snapshot-capable
  0-RTT replay filters with digest-indexed single-lookup duplicate checks, cached earliest expiry, explicit expiry
  pruning, and next-expiry observability for worker handoff, and a lease-backed
  sender that consumes a ticket after the first successful 0-RTT packet,
  plus automatic TLS early_data signaling, ClientHello-bound early traffic
  keys, coalesced Initial+0-RTT sending, explicit server acceptance/rejection,
  bounded thread-safe replay gating, remembered-parameter enforcement, and
  application packet-number/flow/recovery state continuity after key install,
  plus integrated TLS 1.3 PSK-DHE resumption with origin/ALPN/age-bound owned
  sessions, mandatory-last pre_shared_key binders, constant-time binder
  verification, selected-identity signaling, unknown-identity full-handshake
  fallback, and matching-identity bad-binder rejection,
  post-handshake NewSessionTicket issue/parse over 1-RTT CRYPTO, transcript-
  bound resumption PSK derivation, indexed bounded owning server ticket storage with cached LRU eviction and single-lookup issue insertion,
  client cache insertion, and origin+ALPN automatic ticket selection on both
  sides of the next connection,
  plus allocation-free AES-256-GCM stateless tickets with origin+ALPN
  associated-data binding, explicit key IDs, current+three-history key
  rotation, tamper/expiry enforcement, and a native seal/open benchmark,
  Vail-backed non-PSK TLS 1.3 server authentication with Certificate and
  Ed25519/ECDSA-P256/ECDSA-P384 CertificateVerify signing and verification,
  RSA-PSS/RSAE and RSA-PSS/PSS SHA-256/SHA-384/SHA-512 X.509
  CertificateVerify verification, pinned raw-key
  verification or an application X.509 trust-policy callback, transcript/signature tamper
  rejection, and optional mutual TLS with CertificateRequest plus client
  possession proof,
  together with Vail's zero-allocation X.509 chain/hostname/time verifier over
  caller or platform CA bundles, its system-CA loader for production clients,
  and CertificateRequest-driven mutual TLS with client possession proof,
  with TLS 1.3 early/handshake/application/resumption HKDF, Finished, PSK
  binder, early-traffic, and traffic-update secrets centralized in Vail while
  netz retains only QUIC-specific packet-protection labels,
  and Vail-owned PSK-DHE/early_data/NewSessionTicket wire codecs while netz
  retains origin+ALPN caches, replay leases, and remembered QUIC parameters,
  with stateless ticket AEAD formats and key rotation also owned by Vail while
  netz keeps only ticket issuance/storage policy and transport integration,
  and Vail-owned X25519/secp256r1/secp384r1 ECDHE plus the registered
  secp256r1MLKEM768, X25519MLKEM768, and secp384r1MLKEM1024 hybrid
  post-quantum exchanges and SHA-256/SHA-384 transcript hashing, with
  X25519MLKEM768 preferred by default, ordered classical fallback, and split
  multi-Initial plus standalone 0-RTT flights under a 1200-byte path budget
  while netz supplies randomness and retains QUIC packet/transport
  orchestration,
  plus Vail domain-separated HMAC and constant-time comparison primitives for
  Retry/NEW_TOKEN authentication and stateless reset derivation while netz
  retains their QUIC wire formats, lifetimes, replay policy, and key rotation,
  and Vail secure-memory/SHA-256 helpers for ticket caches and replay filters
  while netz retains cache eviction and single-use policy,
  with TLS 1.3 AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305 negotiation,
  SHA-256/SHA-384 traffic-key derivation, nonce construction, AEAD, and
  header-protection execution
  delegated to Vail behind source-compatible QUIC packet APIs, including
  suite/hash-bound stateful and stateless tickets, PSK binders, resumption,
  0-RTT, CertificateVerify/Finished, NSS key logging, and suite-specific RFC
  9001 usage limits,
  short-header spin-bit preservation plus an opt-in single-path spin policy,
  client-side NEW_TOKEN storage plus non-blocking TLS-completion state,
  application-order-preserving HANDSHAKE_DONE scheduling, client confirmation
  from either HANDSHAKE_DONE or a validated 1-RTT ACK, ACK delivery tracking,
  and PTO retransmission with server-only role validation for both frames,
  transport-parameter-derived idle timeout deadline tracking with RFC-style
  ack-eliciting send restart semantics,
  handshake-confirmed keep-alive PING scheduling with idle-timeout caps,
  PTO-flooring, one-shot outstanding probes, and peer-activity reset, plus
  a single next-timer selector across loss/PTO/path-validation/keep-alive/idle/close/key-discard
  work with a due-timer service dispatcher for event-loop arming and an
  indexed single-lookup endpoint-level timer scheduler for multi-connection loops, and
  peer-address validation hooks with RFC 9000 3x anti-amplification send
  budget enforcement for unvalidated server paths,
  1-RTT key-update derivation and key-phase state with ACK gating and retained
  previous receive/send generations for reordered short-header packets, peer-triggered
  send-key synchronization before ACK, cached ACK-gate clearing for local
  key updates, and negotiated-suite RFC 9001
  confidentiality/integrity limits with proactive key rotation and terminal
  limit handling,
  configurable RFC 9438 CUBIC (default) and NewReno congestion-window control with
  bytes-in-flight send admission wired into 1-RTT sending and ACK/ACK_ECN processing,
  deterministic timestamp injection plus automatic monotonic runtime timing,
  default configurable RFC 9406 HyStart++ slow-start overshoot prevention with
  packet-number RTT rounds, Conservative Slow Start, jitter recovery, and public
  window/in-flight observability, high-BDP CUBIC performance regression coverage, and receive-side ECN counter
  reporting, cached PTO-base send-time selection, sent ECN counter validation, ACK_ECN CE congestion response,
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
  1-RTT PING+PADDING probe packets wired to ACK/loss feedback with
  ordinary-send and recovery-retransmit size enforcement from the currently
  validated path MTU,
  an indexed 1-RTT recovery queue with single-lookup packet-number insertion, cached newest retransmission packet numbers, and aggregate queue stats for PTO plus packet-threshold and time-threshold
  retransmission of unacknowledged ack-eliciting frame payloads with single-pass
  ACK-range retirement, no-op ACK short-circuiting, O(1) tail ACK/copy removal,
  single-pass sent-packet tracker stats, exact frame wire-length prediction,
  allocation-free caller-storage multi-packet protection,
  single-allocation batch wrappers, and stateful connection batches that
  transactionally commit flow control, congestion, recovery, pacing, stream
  offsets, AEAD key phases, and socket-visible prefixes. Portable UDP batch
  submission maps to Linux `sendmmsg` through Zig `std.Io`, including paced
  two-probe PTO batches and nonce-safe partial-send recovery, plus zero-copy
  Linux `UDP_SEGMENT` offload for
  contiguous equal-sized packet batches with one-shot capability fallback and
  opt-in Linux `UDP_GRO` receive coalescing with shared zero-copy segment
  ownership, in-place current-key 1-RTT decryption, reusable frame scratch,
  and strict wire-order low-peak batch servicing,
  endpoint-level connection-ID routing with single-probe registration,
  length-indexed short-header dispatch and unroutable zero-DCID long-header drops and static-key token derivation primitives for stable multi-connection
  demultiplexing wired into raw UDP receive routing and 1-RTT connection
  delivery, including peer-path binding and active-migration-disabled route
  rejection, NEW_CONNECTION_ID receive/send active-limit, single-pass receive/send duplicate-CID/reset-token validation and RETIRE_CONNECTION_ID lifecycle/preflight state with NEW/RETIRE CID-error close mapping wired into
  1-RTT, draft-ietf-quic-load-balancers-21 QUIC-LB CID generation/routing
  extraction with validated config rotation/lengths, Appendix B single-pass and
  nibble-correct four-pass AES vectors, caller-provided nonce entropy, and
  transactional local-CID/reset-token issuance,
  transport/application CONNECTION_CLOSE state including frame-payload, ACK, ACK_FREQUENCY negotiation, DATAGRAM negotiation, stream-limit/state/flow-control/final-size/data-conflict, server-only frame, and selected semantic error close emission, indexed PATH_CHALLENGE/PATH_RESPONSE validation state with single-lookup duplicate challenge/response suppression and caller-storage batch drains/sends wired into 1-RTT,
  peer-migration helpers and authenticated non-probing packet receive handling
  that honor disable_active_migration, preserve congestion/PMTU state for NAT
  rebinding, apply a server preferred_address by selecting its CID/reset token
  and peer IP/port, reset anti-amplification and PMTUD path state, queue PATH_CHALLENGE, retain cursor-backed PATH_RESPONSE targets,
  cache path-validation deadlines, skip early timeout scans, retry timed-out
  challenges, expose failed validation attempts in connection stats, and
  validate the new path on a matching PATH_RESPONSE,
  streaming qlog 0.4 observability with RFC 7464 JSON-SEQ framing, strict JSON
  escaping, caller-visible sink failures, allocation-free event views, complete
  ACK-range/ECN and packet-frame emission without fixed-size truncation, plus
  optional 1-RTT connection observers that automatically emit successful
  connection-start, transport-parameter, packet send/receive, packet-loss,
  recovery metrics, key-update, key-retirement, and close events with sticky,
  caller-queryable diagnostics that never roll back network state, plus a
  no-allocation 1-RTT `stats`/`getStats` snapshot with lifetime packet/byte,
  loss, stream, DATAGRAM, RTT, congestion, recovery, sent/received-packet
  including retained ACK-history plus ack-eliciting in-flight size and latest send time, ECN,
  authentication, and key-update counters plus indexed per-stream send/receive stat snapshots with
  remaining credit for fast telemetry loops,
  plus NSS SSLKEYLOGFILE-compatible handshake/application traffic-secret
  streaming from both integrated handshake roles with caller-visible sink
  failures,
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
- WebTransport capsules, unidirectional stream headers, CONNECT metadata with client-bidi session-id validation and `Capsule-Protocol` request/response advertisement, and
  datagram mapping, session lifecycle/counter state, plus a cleartext
  development runtime over the HTTP/3 dev transport, a protected QUIC 1-RTT
  runtime over protected HTTP/3 with automatic WebTransport/H3 DATAGRAM
  SETTINGS advertisement and negotiation checks, and a handshake-backed
  protected runtime that uses QUIC 1-RTT DATAGRAM send/receive queues with
  WebTransport payload-size accounting, batch receive helpers, and
  WebTransport-style `stats`/`getStats` access to the underlying QUIC 1-RTT
  counters
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
zig build run-http3-handshake
zig build run-websocket-echo
zig build run-http3-fetch
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify --head
# Optional diagnostic: performs a preliminary HTTPS HEAD Alt-Svc discovery.
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify --discover
# Linux only: raw std.os.linux.IoUring-backed clients
zig build run-linux-io-uring-http1
zig build run-linux-io-uring-http1-server
zig build run-linux-io-uring-websocket
```

`run-http3-handshake` is the self-contained local HTTP/3 counterpart to the
public fetch tool: it binds a QUIC/H3 server on loopback, performs a protected
client handshake, exchanges one request/response, and exits.
The public HTTP/3 URI client resolves all same-family DNS answers and retries
transient UDP path failures such as QUIC handshake timeouts on the next
address, which makes CDN-backed origins more robust when one anycast edge is
temporarily dropping UDP/443.

Native microbenchmarks are also wired into the build.  Prefer `ReleaseFast`
when collecting performance evidence:

```sh
zig build bench -Doptimize=ReleaseFast
zig build bench-http1-parse -Doptimize=ReleaseFast
zig build bench-http2-hpack -Doptimize=ReleaseFast
zig build bench-http3-dev -Doptimize=ReleaseFast
zig build bench-http3-capsule -Doptimize=ReleaseFast
zig build bench-http3-qpack -Doptimize=ReleaseFast
zig build bench-mqtt-router -Doptimize=ReleaseFast
zig build bench-quic-short-packet -Doptimize=ReleaseFast
zig build bench-quic-padding-parse -Doptimize=ReleaseFast
zig build bench-quic-lb -Doptimize=ReleaseFast
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
zig build bench-quic-ack-ranges -Doptimize=ReleaseFast
zig build bench-quic-stream-window -Doptimize=ReleaseFast
```

The aggregate `bench` step runs the current protocol microbenchmarks:

- HTTP/1 borrowed request-head parsing versus owned full request parsing,
- HTTP/2 HPACK stateful dynamic-table encode/decode versus stateless helpers,
- HTTP/3 cleartext development request/response round trips,
- HTTP/3 Alt-Svc `h3` / `h3-29` endpoint discovery parsing and origin-relative connection target resolution for real-site upgrade hints,
- HTTP/3 Capsule Protocol parsing/iteration and caller-buffer encoding for
  CONNECT-stream extension payloads,
- HTTP/3 QPACK field-section encoding against a populated dynamic table,
- MQTT subscription-router trie matching versus a linear filter scan,
- QUIC AES-128-GCM and ChaCha20-Poly1305 short-packet sealing with
  caller-provided storage versus the allocating convenience wrapper,
- QUIC long PADDING run parsing for Initial padding and PMTUD/probe payloads,
- QUIC-LB encrypted server-ID extraction with the draft's three-pass
  load-balancer optimization,
- QUIC Linux `UDP_SEGMENT` batching versus `sendmmsg`, plus `UDP_GRO`
  coalesced receive versus plain per-datagram receive,
- QUIC 1-RTT stateful sequential send versus stateful batched protection with
  reusable scratch, full recovery/flow accounting, and UDP GSO/sendmmsg
  submission,
- end-to-end QUIC 1-RTT UDP_GRO owning-batch cursor receive versus per-packet receive,
  including decryption, frame parsing, state application, and cleanup.
- QUIC ACK range generation with allocating ownership versus caller-provided
  stack storage for the 1-RTT ACK send hot path,
- bounded QUIC receive-stream compaction across long absolute offsets, including
  retained-memory reduction versus the previous absolute-offset buffer model.

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
  7541 Huffman strings with collision-verified exact/name hash indexes for
  current dynamic entries; the stateless literal convenience helpers accept
  legal leading table-size updates while keeping dynamic state scoped to one block.
  HTTP/3 QPACK now provides RFC 9204 dynamic-table state with single-pass
  exact/name matching, dynamic field
  sections, both instruction stream codecs, and Protected plus handshake-backed
  client/server decode-side live encoder-stream processing with decoder
  feedback. Both protected runtimes persist their encoder/decoder streams and
  automatically use peer-capacity-bounded, reference-safe dynamic compression
  for repeated request and response fields after either preconfigured 1-RTT or
  a full QUIC handshake. The preconfigured 1-RTT runtime also reuses protected
  packet scratch. Both preconfigured and handshake-backed runtimes batch
  multi-packet STREAM sends through UDP GSO or sendmmsg while preserving
  flow/recovery state and consuming every protected packet number on partial
  socket writes.
  Both runtimes keep outbound encoding non-blocking: newly inserted fields stay
  literal until acknowledged. On receive they can advertise
  non-zero `SETTINGS_QPACK_BLOCKED_STREAMS` up to the bounded concurrent-stream
  limit, retain multiple complete dependent request/response messages, continue
  processing split/reordered encoder instructions, and resume each once its
  Required Insert Count is available.
- WebRTC support covers signaling/transport wire primitives (STUN, ICE, SDP,
  DTLS/RTP/SCTP headers), forming a foundation for peer-connection state
  machines and SRTP/SCTP data-channel layers.
