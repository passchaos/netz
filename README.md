# netz

`netz` is a Zig 0.16 protocol toolkit for modern application networking.  It
starts with deterministic parsers, serializers, preallocated fixed-width wire-integer helpers, and state helpers for:

- HTTP/1.1 requests, responses, preallocated request/response/header-block writes, header field syntax validation, chunked transfer decoding with strict no-leading-OWS chunk-size grammar, exact-body allocation, empty-terminator encode/decode fast paths, extension newline rejection, and extension limits, close-delimited and non-chunked-transfer-coded response bodies, runtime chunked
  transfer writing with preallocated chunks plus validated and repeated-value-merged trailer fields, opt-in obsolete folded-field
  unfolding, exact-allocation/empty-header owned-parse fast paths, strict allocation-free borrowed request/response head parsing into
  caller header storage with exact Content-Length pipeline offsets and
  method/status-aware response boundaries, request-target/status/reason-phrase start-line validation with method-specific asterisk/authority-form and no-fragment rules, status-forbidden response-body write rejection, keep-alive/upgrade handling, pipelined
  byte buffering with exact-message ownership transfer, allocation-free caller-storage request-pipeline batch parsing and one-prefix consumption, reusable runtime header/trailer/encoding scratch for persistent connections, and aggregate Content-Length/Transfer-Encoding/chunk/trailer boundary decisions grouped under `http1/runtime/message/`, non-chunked header/body vectored writes, transactional batched response validation and one-flush pipeline writes, method-aware response body
  handling for HEAD and successful CONNECT, stateful incremental request/response writers with fixed-length or chunked framing, cross-write Content-Length enforcement, announced/merged trailers, exact response handoff, client-side `Expect: 100-continue` gating with early-final-response handoff, and connection-poisoning abandonment semantics, plus callback-based streaming request and response readers with owned heads/trailers, fixed/chunked/close-delimited framing, pipelined-suffix preservation, and no body-sized aggregation, Host/authority delimiter validation, strict authority-form CONNECT target delimiter/userinfo rejection, malformed absolute-form authority validation including bracketed IPv6, and CONNECT tunnel helpers, interim 1xx response skipping plus
  server-side `Expect: 100-continue` handling even when body bytes are pre-read with invalid-head suppression, pure-digit Content-Length enforcement,
  TE-over-CL precedence with parsed `Content-Length` stripping and mandatory connection retirement on ambiguous requests, ambiguous body-length rejection
  across repeated/coalesced `Content-Length`, unsupported transfer-coding and HTTP/1.0 transfer-coding rejection, strict-by-default opt-in Hyper-shaped repeated request-line SP, response-only whitespace-before-colon compatibility, and direction-specific invalid-header skipping that still rejects ambiguous NUL/CR boundaries,
  Hyper-style default automatic server `Date` generation backed by a shared
  allocation-free per-second cache, with explicit-field preservation, 1xx
  exclusion, deterministic pure codec helpers, and an opt-out limit,
  and a blocking `std.Io.net` TCP client/server runtime with HTTP/1.1 default
  keep-alive plus an opt-out serve policy that closes after one response,
  a configurable serve-side request-header count bound, and automatic terminal
  431 responses for request-head byte/count overflow while preserving the
  original parser error for server supervision, plus terminal 400 responses
  for malformed request-line/header/method/version/Host syntax and a configurable
  request-target bound with terminal 414 responses,
  persistence, independent optional absolute request- and response-head
  deadlines across cleartext and TLS (without extending either deadline on
  partial input, with the response budget spanning interim 1xx heads, and
  without timing message bodies), per-connection graceful shutdown that completes the active
  response with `Connection: close` and suppresses later requests, optional
  Host/default-port, CONNECT authority, and absolute-form authority synthesis, `http://`/`https://` URI helpers
  with userinfo rejection, host-name DNS and IPv4/bracketed-IPv6 literal connect support, TLS client transport via Zig `std.crypto.tls`
  with host verification plus OS/custom CA bundles, an opt-in vail HTTPS client
  for mTLS/ALPN/peer-chain/exporter/KeyUpdate access, and a `std.Io.async`
  concurrent server helper
- Shared vail-backed TLS 1.3 stream client/server wrappers with optional/required
  client authentication, explicit ALPN offer/selection enforcement, owned
  negotiated-protocol metadata, authenticated cipher-suite/transcript-hash
  introspection, RFC 8446 post-handshake KeyUpdate with reciprocal-update
  handling and bounded peer control bursts, and vectored plaintext writes that
  coalesce protocol slices into bounded TLS records without a heap concatenation
- HTTP/2 frame headers with direct parse/preallocated writes and full-frame direct writes, with owned/borrowed transport I/O, envelope validation, fixed-frame encoding, and transactional HEADERS/CONTINUATION batching grouped under `http2/runtime/frame/`; RFC-bounded SETTINGS validation, DATA/HEADERS (including PADDED/PRIORITY self-dependency checks)/PRIORITY/PUSH_PROMISE/CONTINUATION/RST_STREAM payload parsing, RFC 8336 single-probe exact-indexed ORIGIN origin-set state with exact-allocation/empty-payload parse fast paths, allocation-free/preallocated writes, empty-index membership and duplicate-entry skips, RFC 7838 single-probe exact-indexed ALTSVC connection/stream advertisements with allocation-free/preallocated writes, identical replacement skips and per-target replacement, and active-stream reset propagation, a bootstrap
  HPACK static/literal encoder-decoder with RFC 7541 Huffman strings, preallocated prefix-integer writes, exact encode/decode output preallocation, retained runtime encode scratch, preallocated empty/short/raw-preferred string write fast paths, and connection-owning server/client APIs that emit exact COMPRESSION_ERROR/PROTOCOL_ERROR/ENHANCE_YOUR_CALM GOAWAY frames for malformed HPACK, broken CONTINUATION sequences, or unterminated header floods while returning the original local error, plus stream-local PROTOCOL_ERROR/ENHANCE_YOUR_CALM resets for malformed or oversized admitted messages across aggregate, streaming, and batch paths with exact connection-credit restoration and sibling cleanup; a configurable connection-lifetime budget counts only library-generated peer-protocol-error resets and escalates excess churn to GOAWAY(ENHANCE_YOUR_CALM), without charging application cancellation, timeout cleanup, or REFUSED_STREAM admission control,
  pseudo-header and common-header static fast paths, internal empty-dynamic-table lookup skips, single-lookup
  dynamic insert indexing, O(1)
  FIFO dynamic-index eviction, and single-pass request/response pseudo-header
  and length extraction, plus
  header lookup, Content-Length normalization, pseudo-header/URI/authority
  validation, trailer rules, and response-body semantics grouped under
  `http2/runtime/headers/`,
  exact dynamic-table indexing/size-update state for long-lived runtimes with local decoder table-size enforcement and automatic
  peer table-size update emission plus h2/hyper-style non-indexing for volatile or oversized fields and automatic
  never-index encoding for sensitive fields, fixed-control-frame and preallocated control-frame write fast paths, PING with opaque ACK matching plus explicit absolute-deadline round trips and a reusable single-reader inactivity-aware keep-alive driver with active/idle policy, monotonic probe payloads, connection-control processing and a configurable bounded FIFO preserving interleaved application frames, GOAWAY/WINDOW_UPDATE connection
  management including interleaved SETTINGS/PING/WINDOW_UPDATE/PRIORITY handling and compacting interleaved request FIFO reuse, RFC 9218 SETTINGS_NO_RFC7540_PRIORITIES negotiation and client-only PRIORITY_UPDATE signaling with preallocated frame payload writes, indexed bounded pre-request buffering, allocation-free full-capacity rejection, identical-update skips, single-probe reservation/replacement, cached idle-request pruning/activation with empty-index checks, empty-update lookups/removals, and promised-push validation, active-stream RST_STREAM guarding, fixed-capacity plus minimum-duration local-reset history, and a connection-lifetime budget for peer-induced protocol-error resets that escalates excess churn to GOAWAY(ENHANCE_YOUR_CALM), explicit opt-in PUSH_PROMISE promised-request/pushed-response lifecycle with preallocated PUSH_PROMISE frame writes, parent/promised-stream validation, single-lookup local push reservations with empty-index local lookup skips and promised-push queue indexing, indexed reserved/pending push lookups and releases with empty-index skips, O(1) cursor FIFO promised-request notification delivery, head/tail-cancel fast paths with empty-pending skips and targeted pending-index repair, and client RST_STREAM(CANCEL) refusal of reserved pushes, GOAWAY propagation and allocation-free GOAWAY emission during stream reads and post-GOAWAY request suppression/rejection, cached multi-set drain-floor checks, and same-control-stream GOAWAY emission with persistent control-stream offsets, default client server-push opt-out, connection- and stream-level flow-control enforcement with signed bounded window arithmetic and zero-length DATA semantics isolated under `http2/runtime/flow/`, including
  transactional single-pass SETTINGS_INITIAL_WINDOW_SIZE updates, exact-allocation/empty SETTINGS parse fast paths, and allocation-conscious configurable advertisement, configurable SETTINGS_HEADER_TABLE_SIZE/SETTINGS_MAX_CONCURRENT_STREAMS/SETTINGS_MAX_FRAME_SIZE advertisement, bidirectional SETTINGS_MAX_CONCURRENT_STREAMS enforcement, SETTINGS_MAX_FRAME_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE validation with inbound advertised-frame-size enforcement, RFC 9218 response DATA scheduling with dynamic PRIORITY_UPDATE precedence, single-pass urgency/exclusive-stream selection, sequential non-incremental stream-ID order, incremental round-robin sharing, and blocked-stream bypass,
  outbound frame splitting plus h2-style CONTINUATION chain flood, stream-id overflow, indexed active-stream tracking with single-probe activation, duplicate reserve skips, empty-index active checks, and empty-index release skips, wrong-direction HEADERS, and idle-stream DATA/WINDOW_UPDATE send limits, with stack-first request/response header descriptors, TCP_NODELAY, configurable connection/stream receive windows, vectored HEADERS+DATA and multi-DATA bursts, transactional bodyless multi-stream request/response batches with HPACK-state staging and out-of-order response reassembly, connection-level bulk frame read buffering, callback-based streaming request and response bodies with owned heads/trailers, stateful incremental request/response writers with transactional cross-chunk Content-Length enforcement, DATA/trailer finish, response handoff, and abandoned-writer cancellation, bounded early-response preservation while an upload waits on flow control with partial-write accounting and aggregate/streaming response transfer, strict streamed receive Content-Length accounting, callback-error RST_STREAM cancellation, and DATA sends that wait for WINDOW_UPDATE capacity
  and inbound DATA consumers that account for full padded frame payloads with single-probe indexed stream-window state, empty-index membership skips, restore connection/stream receive capacity, and optionally grow both receive targets from an allocation-free BDP estimator with reserved PING correlation and serialized SETTINGS acknowledgement,
  frame-envelope validation including fixed-size RST_STREAM and SETTINGS payload-multiple checks, stream-id direction/monotonicity validation, request/response trailers with forbidden-field rejection, pre-HEADERS frame ordering checks, bounded ordered interim 1xx observation across single and multiplexed client reads with request-index/stream-ID batch correlation and explicit server-side informational response sending, content-length
  validation with pure-digit Content-Length enforcement, indexed response-body semantics retention with single-probe updates, duplicate reserve skips, and empty-index lookup skips, HTTP/2 pseudo-header/lowercase field-name/value and control-character validation, `:method` token validation with case-sensitive HEAD/CONNECT/OPTIONS semantics and `:protocol` token validation,
  URI-like `:scheme`/origin-form `:path`/`:authority` validation with Host fallback and Host/`:authority` mismatch rejection,
  connection-specific header rejection including `TE` rules and stack-first,
  exact-capacity removal of every `Connection`-nominated hop-by-hop field
  without a fixed field-count ceiling,
  status-forbidden response-body write rejection,
  Hyper-style default automatic server `date` generation for ordinary,
  streaming, batched, pushed, and CONNECT final responses, with explicit-field
  preservation, informational-response exclusion, and an opt-out limit,
  traditional CONNECT header-only tunnel acceptance with DATA tunnel helpers and strict `:authority`-only host:port pseudo-header rules, CONNECT body/Content-Length rules, bounded Extended CONNECT rejection bodies/trailers with stream-local cleanup, and opt-in RFC 8441 extended CONNECT / `:protocol` handling with irreversible
  SETTINGS_ENABLE_CONNECT_PROTOCOL downgrade rejection,
  open/accept/reject tunnel helpers and DATA-frame tunnel read/write mapping, RFC 7540 h2c Upgrade client/server helpers that carry `HTTP2-Settings` and receive/respond on stream 1, a blocking prior-knowledge h2c client/server runtime with default `:authority` host/port synthesis and transport/URI-derived `:scheme`, and a native TLS 1.3 client/server runtime that requires negotiated `h2` ALPN and optionally authenticates clients with application-visible verified certificate chains,
  `http://` URI helpers with host-name DNS and IPv4/bracketed-IPv6 literal connect support, allocation-free HTTP/2 runtime SETTINGS/frame sends, and a `std.Io.async` concurrent server helper
- HTTP/3 frame headers with preallocated generic writes and direct QUIC-varint emission, SETTINGS payload length reuse with preallocation/direct-varint writes and exact-allocation parsing, preallocated single-varint control frames, preallocated PUSH_PROMISE/push-stream prefixes/PRIORITY_UPDATE, preallocated DATAGRAM/Capsule, and unidirectional stream prefixes with preallocated small-varint write fast paths, request/response HEADERS+DATA helpers,
  stack-first request/response/informational/Push-Promise header assembly with
  exact allocation fallback instead of a hidden 64-field descriptor ceiling,
  default automatic server `date` generation across development, protected, and
  authenticated runtimes for aggregate, streaming, pushed, and CONNECT final
  responses, with a shared allocation-free per-second cache, stack-first header
  views, case-insensitive explicit-field preservation, 1xx exclusion, opt-out
  controls, and no wall-clock dependency in the pure codec; final-response
  owners can explicitly wait with a timeout/deadline for reliable QUIC recovery
  to drain before destroying a short-lived session, while `serveConnection`
  applies a configurable bounded drain automatically and multi-connection
  endpoint callbacks resynchronize their send-side PTO timer after handlers,
  with URI/DNS/connect-deadline policy and server response shaping split into
  focused `runtime/client` and `runtime/server` submodules rather than growing
  the central runtime file, including non-truncating stack-first multi-address
  DNS collection, a shared runtime error layer for those submodules,
  and request/Push/critical-stream scratch ownership isolated under
  `runtime/send`, including an exact MTU-aware packetizer shared by handshake,
  preconfigured protected, and cleartext runtimes that repacks and splits
  oversized STREAM descriptors before datagram emission; the cleartext
  adapter's bounded retained-DATAGRAM FIFO and
  its ownership tests plus associated-stream receive/send/ID-cursor state are
  isolated under `runtime/development`; QPACK connection state, focused
  state-machine tests, dynamic request/response writer tests, and protected
  QPACK request/response transport coverage are grouped under `runtime/qpack`;
  indexed client/server
  request lifecycle, response decode context, priority state, and graceful
  GOAWAY drain boundaries are grouped under `runtime/stream`, with the runtime
  root adapting only concrete readers; aggregate request/response reassembly,
  reset FIFO state, and shared QPACK dependency inspection are nested under
  `runtime/stream/buffered`; indexed outbound body state, Content-Length
  accounting, lightweight flow limits, and reusable batch scratch are grouped
  in `runtime/stream/outbound_body.zig`; incremental HEADERS/DATA/trailer
  parsing and multiplexed active-reader/reset scheduling, with their focused
  tests, live in `runtime/stream/reader.zig` and `runtime/stream/set.zig`; push
  stream reassembly, promise binding, cancellation queues, and fair polling are
  grouped under `runtime/stream/push`; cleartext aggregate request ownership
  and peer-aware reassembly live in `runtime/development/request_buffer.zig`,
  while per-peer parser/lifecycle/QPACK/response state is coordinated under
  `runtime/development/server_peer`; role-aware control/QPACK stream
  classification, transactional control-state application, GOAWAY/priority ID
  checks, and critical-stream closure validation live under `runtime/control`,
  RFC 9297 Capsule Protocol TLV parsing/writing with preallocated direct-varint ArrayList and allocation-free
  caller-buffer encoding, `Capsule-Protocol` structured-field validation, and
  an incremental iterator for CONNECT stream data, borrowed and owning
  normalized HTTP/3 origin keys for conservative connection-reuse/coalescing
  policy decisions including direct owned-key construction from parsed origins,
  plus an indexed generic origin-keyed idle pool with empty-pool miss fast paths, chunked case-folded hashing, and single-lookup release/new-origin append checks for runtime-specific
  client handles with explicit expiry pruning and targeted index repair,
  SETTINGS-first control-stream negotiation with unique peer control-stream tracking, bidirectional message-stream and non-critical extension-stream role-validation skips before preallocated control-state rollback cloning, forbidden frame rejection on control/request streams, client-initiated push-stream rejection, and prefix-driven peer-unidirectional stream classification that reassembles offset-zero type bytes before routing control/QPACK/push streams or draining unknown reserved types, without assuming fixed critical stream IDs; stateful routing returns consumed control/QPACK/unknown bytes to both QUIC receive windows, retires terminal unknown streams to restore MAX_STREAMS credit, while push streams return their fragmented association prefix exactly once before preserving application DATA backpressure, preserves reordered WebTransport 0x54 prefixes on both roles, and failed MAX_DATA/MAX_STREAM_DATA writes retry from the connection timer with fair MTU-bounded multi-stream credit coalescing; QPACK encoder/decoder critical stream registration with duplicate-stream `H3_STREAM_CREATION_ERROR` plus FIN/RESET_STREAM/STOP_SENDING closure rejection, RFC 9204 dynamic-table FIFO/absolute-relative indexing/eviction state, Required Insert Count wrapping, preallocated/assume-capacity varint and prefix-integer writes, all relative/post-base dynamic field-line forms with blocking/eviction distinction and never-indexed preservation, Huffman-capable encoder with reused length prechecks/exact slice allocation and direct-to-target byte emission plus preallocated decoder with empty-input fast paths, instruction codecs with preallocated instruction and field-section literal-name writes, a connection-scoped decoder with out-of-order/split encoder-stream reassembly plus preallocated coalesced feedback, and a non-blocking encoder state with Known Received Count gating, decoder-stream reassembly, single-pass outstanding reference accounting with adjacent duplicate fast paths, empty-reference eviction checks, single-probe pending-section indexing with empty-index skips, tail-release fast paths, and prohibited-eviction prevention, GOAWAY and MAX_PUSH_ID monotonicity checks plus post-GOAWAY request suppression/rejection, cached multi-set drain-floor checks, and same-control-stream GOAWAY emission with persistent control-stream offsets,
  collision-verified hash indexes with single-lookup dynamic insert tracking for current QPACK exact/name matches with
  zero-reference lookup/encoding short-circuits, static-block zero-prefix and preallocated empty/short-string write fast paths, restricted-reference scan
  fallback, O(1) FIFO eviction index retirement, and indexed QPACK static-name
  lookups with pseudo-header and common-header fast paths,
  CANCEL_PUSH/PUSH_PROMISE/MAX_PUSH_ID/PRIORITY_UPDATE payload codecs with malformed-payload rejection, indexed per-ID control-state lookups with empty-index skips, identical priority-update skips, and single-probe priority replacement, and advertised MAX_PUSH_ID enforcement for received PUSH_PROMISE frames,
  RFC 9218 Priority field parsing/serialization,
  request/response message encoding/decoding with ordered HEADERS/DATA/trailer handling, static or dynamic QPACK field-section decoding with indexed per-stream Section Acknowledgment/cancellation accounting with targeted index repair and prefix-skipping cancellation compaction, non-blocking Known-Received dynamic writers for request/response/interim/trailer sections with sensitive-field exclusion and speculative future inserts, inbound and outbound SETTINGS_MAX_FIELD_SECTION_SIZE enforcement, exact post-assembly and incremental receive signaling (`QPACK_DECOMPRESSION_FAILED` connection closes for malformed QPACK, connection closes for invalid frame sequences, and stream-local `H3_MESSAGE_ERROR` cancellation for malformed HTTP semantics while siblings remain usable), connection-wide enforcement of the locally advertised QPACK blocked-stream budget across buffered aggregate streams, active incremental readers, and push streams (including a zero-budget first dependency), constant-space client completion history using the shared HTTP/WebTransport bidirectional stream-ID allocation frontier rather than one tombstone per completed request, full aggregate, incremental, and detached-head PUSH_PROMISE request-field decoding with dynamic-section feedback, transactional aggregate and incremental request/response/push event admission with retryable local preflight failures, promise registration only after validation, queued QPACK feedback after send failures, and allocation-safe cleartext aggregate request ownership transfer, bounded ordered interim 1xx response observation on aggregate and incremental client paths, request-stream correlation for aggregate multiplexed reads, push-ID/parent-request/push-stream correlation for aggregate pushed responses, per-stream bounds for multiplexed and pushed responses, runtime emission before final and pushed responses, and forbidden trailer-field rejection,
  HEADERS-only dynamic request/response writers for incremental DATA sending
  with Content-Length generation/verification, parsed length reuse, and
  CONNECT/204/304 body guards, including detached Extended CONNECT FIN
  detection that distinguishes a missing final HEADERS section from a
  truncated HTTP/3 frame,
  an incremental message reader that emits owned request/response heads,
  reuses parsed pseudo-header/Content-Length lookups, preallocates aggregated
  DATA bodies from declared lengths under buffered-byte caps, exposes
  bounded-window DATA availability, dynamic trailers, and FIN while validating
  informational responses and Content-Length without aggregating body bytes,
  HTTP/3 pseudo-header/lowercase field-name, `:method` token validation with case-sensitive CONNECT/OPTIONS semantics, SETTINGS-gated `:protocol` token, URI scheme/origin-form path/authority, Host/`:authority`, traditional CONNECT body rules, and connection-specific header validation,
  DATA-frame aggregation, pure-digit content-length, three-digit `:status`,
  status-forbidden response-body validation, and request-aware HEAD/traditional
  CONNECT body suppression and client validation across aggregate and
  incremental APIs, stateless QPACK helpers with RFC 9204 static-table
  references, Huffman string literals, and literal fallback, a cleartext development runtime over the QUIC
  UDP frame endpoint with preallocated frame payload sends, a protected 1-RTT QUIC STREAM runtime with STREAM frame
  splitting/reassembly, SETTINGS exchange, persistent QPACK encoder/decoder
  instruction streams in both connection directions, peer-capacity and
  blocked-stream-limit negotiation, automatic speculative dynamic references
  up to the peer's `SETTINGS_QPACK_BLOCKED_STREAMS` budget, and conservative
  Known Received Count fallback after that budget is exhausted, and a
  handshake-backed protected client/server
  runtime with `https://` URI endpoint parsing/DNS/literal target resolution
  plus `HandshakeClient.connectUri` / `requestUri` for public H3 client
  tooling; both server paths retain indexed bounded per-request-stream reassembly state
  so interleaved streams are not dropped, surface RESET_STREAM request
  cancellation, distinguish an ended request with no initial HEADERS as
  stream-local `H3_REQUEST_INCOMPLETE` while retaining sibling streams, and
  classify an ended response without final HEADERS as stream-local
  `H3_MESSAGE_ERROR` plus bounded 1xx overflow as `H3_EXCESSIVE_LOAD`, and
  expose client/server cancel helpers that send
  RESET_STREAM+STOP_SENDING with conditional QPACK stream cancellation and empty-buffer skips. Servers
  also expose two-phase GOAWAY initiation/completion and drain-completion
  tracking over queued and indexed application-owned requests. Clients can send
  pre-request or live RFC 9218 PRIORITY_UPDATE frames on persistent control
  streams, including promised-push priorities. Received priority fields are
  owned and retained per request stream or push ID rather than collapsing
  unrelated elements into one connection-global value.
  Protected clients also expose split `sendRequest`/`receiveResponse` APIs with
  indexed bounded per-stream request/response reassembly with single-probe buffered stream creation,
  indexed buffered-presence checks with empty-reset, empty-remove, and empty-ready skips, short-circuit ready polling, and targeted ready-stream lookup, preserving interleaved responses and
  resets instead of discarding non-target streams. `receiveNextResponse` and
  `receiveNextResponseWithInformational`
  provide an indexed cursor-backed FIFO event-style response/reset queue with
  empty-reset insert/take fast paths, tail-targeted reset removals, single-probe reset recording, and explicit stream IDs, while
  outstanding request tracking uses single-probe client opens/server activation, empty-index lookup/finish skips on both roles, and rejects unknown or duplicate completion and
  enforces the configured concurrency bound. Protected clients and servers also
  expose `startRequest`/`sendRequestBody` and
  `startResponse`/`sendResponseBody`, preserving per-stream QUIC offsets across
  multiple DATA chunks with empty-open/finish lookup skips, single-lookup chunk accounting plus cached FIN cleanup and enforcing declared Content-Length at FIN.
  Handshake-backed clients and server sessions additionally expose negotiated
  TLS cipher-suite/transcript-hash metadata and QUIC key-update control/counts,
  bounded `serveOne`/`serveConnection` request-response loops with automatic
  paced aggregate responses and two-phase GOAWAY completion, and expose
  `sendRequestBodyBatchPaced`/`sendResponseBodyBatchPaced`: one DATA
  contribution per stream is packet-size checked, protected through the
  stateful QUIC batch path, and committed only for the socket-visible prefix,
  with isolated DATA-prefix storage for recovery-safe borrowed payloads.
  Streaming
  messages can instead finish with dynamic QPACK trailer HEADERS through
  indexed streaming body state for
  `finishRequestTrailers`/`finishResponseTrailers`. Preconfigured-protection
  and handshake-backed servers expose
  `receiveRequestEvent`/`readRequestData`, while their clients expose
  per-stream `receiveResponseEvent`/`readResponseData` plus
  `receiveNextResponseEvent` for one tquic-style poll loop over every indexed
  outstanding response and reset. Both directions provide
  indexed active streaming readers with single-lookup activation, empty-index/reset lookup skips, and empty-index removal skips, bounded-window network reads with automatic QPACK head/trailer feedback,
  interleaved-stream and reset identity preservation, Content-Length
  validation, prepared reset-record fast paths, and no full-body aggregation. When UDP_GRO is enabled, protected
  and handshake packet pumps retain the decrypted batch behind a one-packet
  cursor, and reuse compacted pending receive slots, amortizing recvmsg/decryption without bulk-inserting the whole GRO
  payload into a small HTTP/3 stream window. The handshake cursor uses a timed
  owning-batch receive, so ACK-delay, PTO/loss recovery, flow-control, idle, and
  close timers continue to run even when no peer datagram is currently queued.
  Handshake streaming readers return
  consumed protocol offsets to both QUIC flow-control levels, compact the
  transport overlap-validation window, keep reset and cancelled-push FIFO queues
  on O(1) cursor pops, and emit ACK/MAX_DATA/MAX_STREAM_DATA so bodies can
  continue beyond their initially negotiated stream credit. Stateful servers
  also register peer request-stream retirement when aggregate or incremental
  parsing reaches FIN; after the response FIN/RESET is acknowledged, QUIC
  automatically returns MAX_STREAMS and reclaims the copied transport buffer. Both
  protected clients also maintain persistent MAX_PUSH_ID/CANCEL_PUSH control
  state with monotonic advertisement, per-ID cancellation retention and empty-cancel lookup skips, local
  STOP_SENDING of active cancelled pushes, single-probe cancellation recording,
  and advertised-range validation.
  Streaming response readers decode PUSH_PROMISE into owned promised-request
  heads, preserve the push ID, enforce the advertised limit, and account
  dynamic QPACK section feedback instead of discarding promised fields like
  the current reference runtimes. Push promise registration uses single-probe
  indexes, push stream insertion/binding reuse one map probe, empty-index targeted push lookups/removals, and protected and handshake runtimes also bind
  reordered server-initiated push streams to indexed promises, expose indexed targeted
  streaming and owned aggregate pushed-response APIs, including
  `receivePushWithInformational` callbacks correlated by push, parent request,
  and push-stream IDs, and can emit PUSH_PROMISE plus the corresponding
  unidirectional pushed response (with optional informational heads) with
  shared dynamic QPACK state, plus a
  `std.Io.async` request receive helper for the development runtime. The
  runtime internals are grouped by responsibility under `runtime/control/`,
  `runtime/stream/`, `runtime/qpack/`, `runtime/send/`, and
  `runtime/receive/`; server request-packet routing and RFC 9114/9204
  connection-error classification are isolated there, including idempotent
  duplicate RESET_STREAM handling and exact application close codes. Handshake
  and lightweight protected clients also share one response/control/QPACK/Push
  router, including prompt Insert Count Increment feedback. The
  control/QPACK critical-stream receive and send logic
  and development coordination remain grouped under `runtime/development/`,
  and authenticated message, Push, streaming-head, DATA, and trailer emission
  live with focused tests under those nested modules instead of continuing to
  grow the runtime root. Multi-packet HTTP/3 sends distinguish zero-progress
  failures from socket-visible partial sends: retryable preflight failures keep
  state, progress-aware DATA batches commit only their accepted prefix, and
  ambiguous message/Push/trailer partial sends fail the connection closed
  rather than guessing delivery. The RFC 9218 complete-body scheduler owns its
  stack-first candidate workspace and fixed packet staging under
  `runtime/response_scheduler/core.zig`; staged packets retain their source response
  index, so progress commits do not rescan or hash stream IDs.
  Protected client/server integration coverage is split by responsibility under
  `runtime/client/tests`, `runtime/server/tests`, `runtime/control/tests`, and
  `runtime/stream/push/tests`, keeping the large runtime root focused on API and
  orchestration rather than test fixtures.
- gRPC over HTTP/2 with bounded 5-byte length-prefixed message framing,
  compressed-flag validation, eight-digit `grpc-timeout` parse/format with
  non-shortening deadline rounding, all canonical status codes, HTTP-to-gRPC
  fallback mapping, tolerant percent-encoded `grpc-message` handling,
  content-type/TE/method-path/custom-metadata validation, unpadded binary
  metadata Base64 sending with padded/unpadded/comma-joined receive support,
  strict per-message gzip and RFC 1950 zlib-wrapped `deflate` codecs backed by
  `~/project-z/vort`, bounded decompression, typed
  `grpc-accept-encoding` negotiation, asymmetric request/response algorithms,
  and gRPC Core-compatible fallback when compression does not shrink a message,
  plus unary and sequential request/response message-stream h2c client/server
  helpers with opaque protobuf payloads, initial/trailing metadata,
  final HEADERS-before-DATA callbacks, arbitrary prefix/payload split
  reassembly, several messages per DATA callback, zero-copy complete
  uncompressed messages, exact allocation for split messages, independent
  per-message compression, trailers-only errors, decoded-message ownership,
  truncated-message stream reset with unconditional local stream-credit and
  flow-window retirement even when the best-effort reset write fails, typed
  early `grpc-status` handoff when a
  flow-control-blocked upload receives server trailers, and `grpc-status`
  enforcement, plus `grpc.pbz.ClientTransport` and `ServerTransport` for
  plugging generated pbz service clients and handlers directly into all four
  gRPC RPC shapes; protobuf remains an application-layer choice and pbz is
  only a lazy integration dependency
- QUIC varints with encode length reuse, preallocated direct writes, long-header parsing, stream IDs, transport parameters, and core
  frame codecs (STREAM, CRYPTO, ACK, close, DATAGRAM, flow-control frames) with one-byte control-frame, direct single-/multi-varint, varint-payload, STREAM, DATAGRAM, NEW_CONNECTION_ID, and ACK_FREQUENCY write/length, fixed PATH, STREAM flag-byte, reset/stop, NEW_TOKEN, NEW_CONNECTION_ID, CRYPTO, MAX_DATA, stream flow-control, close, ACK/ACK_ECN, DATAGRAM, and ACK_FREQUENCY frame-type write fast paths, frame-payload close-error classification, shortest-form frame-type enforcement, empty non-FIN STREAM no-op rejection, stream-count bounds on MAX_STREAMS/STREAMS_BLOCKED and
  RFC 9000 packet-type legality checks for Initial/Handshake/0-RTT/1-RTT, typed
  RFC-defaulted transport-parameter encoding/validation with direct integer values and preallocated header/value writes (preallocated duplicate detection, exact-allocation raw parsing,
  endpoint-specific client/server parameter rules, stack-written preferred-address encoding plus parsing and specified-address validation,
  max UDP payload 1200..65527/idle-timeout/ACK delay/stream-count bounds), Retry packet codec with preallocated writes
  and version-specific integrity-tag verification, plus CRYPTO stream reassembly with empty-frame/write/consume no-op handling, pre-reserved assume-capacity/direct-varint CRYPTO frame batches, contiguous duplicate fast paths, and duplicate-overlap conflict detection,
  v1/v2 Initial key/header/payload protection with version-aware salts, HKDF labels, long-header type bits, fixed-bit, connection-ID length, supported-version, and header-protection sample-bound validation, version-specific TLS QUIC packet-protection labels, preallocated protected Initial/Handshake/0-RTT packet seal with direct header/varint/packet-number writes and Initial packet open, long-header packet boundary peeking for coalesced datagrams, Version Negotiation packet codec with preallocated writes and randomized response first byte, reserved-version greasing tolerance, and allocation-free client discard preflight, RFC 9368 stack-written `version_information` transport parameters, endpoint-level unsupported-version responses, integrated server-side response-and-continue handling, client-side Version Negotiation selection/restart helpers, and automatic handshake restart on negotiated versions,
  Initial CRYPTO byte exchange over UDP with RFC 9000 1200-byte Initial
  datagram padding/validation, MTU-bounded multi-Initial CRYPTO packetization
  with allocation-free Initial/Handshake CRYPTO payload extraction and
  cross-datagram TLS-message reassembly for large post-quantum
  ClientHello/ServerHello flights, client-carried Initial address tokens,
  server-side token validation hooks, and server-issued address-validation
  NEW_TOKEN frames, preallocated coalesced Initial+Handshake CRYPTO datagram helpers,
  bounded RFC 9002-style exponential PTO retries for synchronous client
  Initial/0-RTT and server Initial+Handshake flights with fresh packet numbers,
  passive split-flight waits that use the same bounded total PTO budget instead
  of failing on the first PTO, optional wall-clock handshake budgets that keep
  capped PTO probes separate from final timeout, Handshake-space CRYPTO-less
  packet skips, plus configurable retry exhaustion and deterministic
  whole-flight loss injection tests, HMAC-based
  address-validation token helpers with exact Retry peer bindings for Retry/NEW_TOKEN with lifetime, version,
  peer-address binding, Retry ODCID/RSCID binding, secret rotation,
  digest-indexed single-lookup replay filtering with disabled-filter fingerprint skips, empty-index membership skips, and export/restore snapshots, plus an optional bounded, process-owned shared replay gate for server handshakes. The shared gate authenticates and checks every token binding before atomically remembering its fingerprint, so concurrent Retry or NEW_TOKEN reuse is rejected before TLS processing and server-flight emission. It provides local in-process coverage only, not distributed replay coordination or an external durable store. Retry datagram issue/validate helpers, client-side Retry
  processing that enforces one-Retry/early-Retry rules, automatically resends
  the exact ClientHello under Retry-derived Initial keys, ignores invalid Retry
  injection, suppresses 0-RTT replay, plus an integrated server Retry policy
  with secure nonce generation, queued pre-Retry 0-RTT discard, and retried
  Initial token/DCID/transport-parameter validation, minimal TLS
  ClientHello/ServerHello/EncryptedExtensions/Finished encoding with preallocated handshake messages, direct ClientHello/ServerHello/EncryptedExtensions/Finished bodies, cipher-suite vectors, SNI/ALPN/supported-groups/key-share extension payloads, extension wrappers, and fixed-width integer writes plus parsing,
  protected Initial ClientHello ↔ ServerHello exchange with client-side non-target
  datagram filtering, protected Handshake packet server/client Finished flights, and handshake/application secret
  derivation for QUIC, an integrated minimal client/server handshake for QUIC v1/v2 that emits
  practical transport parameters and applies negotiated flow-control, stream,
  and UDP-payload limits to established 1-RTT connection objects with static-key-derived stateless reset token and preallocated packet helpers,
  packet-number space ACK tracking with cached retained-packet counts, allocation-free single-range ACK ownership, first/newest/oldest-range fast paths, tail
  ACK-range append/removal fast paths, and bounded duplicate/old packet suppression,
  ACK range semantic validation plus zero-range decode skips and preallocated
  ACK frame writes, empty-sent-space rejection, pre-oldest ACK prune skips, single-ACK packet transactional precheck reuse, and constant-time acknowledged-ECT versus ACK_ECN watermark checks that survive metadata compaction,
  monotonic sent-packet insertion fast paths, best-effort indexed-or-sorted exact sent-packet lookup with tail fast paths and O(1) index invalidation after metadata compaction, and cached latest ordinary ACK-eliciting PTO anchors with PMTU-probe fallback scans,
  no-new-ACK short-circuiting with sorted-range scan breaks and lower-bound ACK probes, lookup-free tail-forget fast paths, cached sortedness for
  ACK/loss scans, single-pass ACK marking, pointer-based recovery compaction that recycles matches in place and copies only moved survivors, binary-searched clean single-range recovery ACK retirement with conservative retransmission/multi-range/unsorted fallback, plus single-pass outbound frame sizing/recovery/ACK/flight classification,
  receive-frame semantic preflight before multi-frame side effects, preallocated single-byte, single-, double-, triple-varint, fixed PATH, ACK_FREQUENCY, variable-payload, CRYPTO, STREAM, DATAGRAM, NEW_CONNECTION_ID, and close frame writes, and direct adaptive truncated packet-number
  encoding wired into 1-RTT ACK/STREAM exchange, indexed stream send/receive state with pre-reserved assume-capacity STREAM frame batches, preallocated receive-state clones, and empty non-FIN send no-ops, single-lookup flow creation and empty-index lookup skips,
  zero-consume skips, contiguous duplicate-overlap fast paths, conflict detection, offset reassembly, FIN, RESET_STREAM final-size validation, and STOP_SENDING
  to RESET_STREAM response handling,
  RFC 9221 QUIC DATAGRAM negotiation limits with 1-RTT send helpers,
  receive queues, max-payload calculation, queue overflow/drop counters, and
  oversized/disabled DATAGRAM rejection,
  RFC 9287 `grease_quic_bit` transport-parameter negotiation with strict
  pre-negotiation fixed-bit validation, negotiated zero-bit receive routing,
  and connection-seeded unpredictable 1-RTT QUIC Bit emission,
  draft ACK_FREQUENCY and IMMEDIATE_ACK frame codecs with `min_ack_delay`
  transport-parameter negotiation and opt-in 1-RTT state updates for requested
  ACK threshold/max-delay/reordering behavior, directional capability checks,
  transactional rejection of requests below the advertised minimum or at least
  2^14 milliseconds, and zero-valued immediate-ACK/disabled-reordering modes,
  plus automatic ACK coalescing
  that respects the negotiated threshold, max-delay timer, and IMMEDIATE_ACK
  override,
  flow-control state with zero-byte reserve/consume, saturated-consume skips, and duplicate receive-offset no-ops for MAX_DATA/MAX_STREAM_DATA/BLOCKED frames wired into
  1-RTT DATA_BLOCKED/MAX_DATA and STREAM_DATA_BLOCKED/MAX_STREAM_DATA handling
  with one advisory BLOCKED emission per unchanged limit to avoid retry-loop
  packet storms and opt-in adaptive receive-window growth,
  stream-count flow control with MAX_STREAMS and STREAMS_BLOCKED handling plus
  the same per-limit duplicate suppression for stream-count exhaustion; peer
  stream credit is returned only after both directions are terminal, including
  acknowledgement of the local FIN/RESET, with early release requests flushed
  automatically by the ACK receive path. Released peer stream buffers and map
  entries are reclaimed, sequential closed IDs collapse into a constant-space
  watermark, sparse closures use merged ranges, stale recovery frames are
  removed, failed automatic credit sends retain state behind an aggregate
  connection-timer retry, and stable ID-based receive pagination survives swap
  removal. Locally initiated request streams use the same compressed history
  and ACK-gated reclamation after their peer response reaches FIN/RESET, so
  long-lived HTTP/3 clients retain active work rather than historical streams,
  protected 0-RTT long-header packet seal/open and preallocated frame datagram helpers with
  0-RTT packet-type restrictions, an indexed owning origin+ALPN session cache with
  cached transactional LRU eviction and stats, expired-hit eviction, independent TLS session copies, stable
  cache/lease/early-data stats, exclusive single-use early-data leases with
  single-lookup lease indexing and empty-index acquisition/lease checks, RFC
  9000 §7.4.1 remembered-parameter
  filtering/reduction checks, RFC 9221 DATAGRAM restoration, snapshot-capable
  0-RTT replay filters with digest-indexed single-lookup duplicate checks and empty-index snapshot restores, cached earliest expiry scan skips, explicit expiry
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
  bound resumption PSK derivation, indexed bounded owning server ticket storage with cached LRU eviction, earliest-expiry scan skips, empty-store lookup skips, and single-lookup issue insertion,
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
  indexed single-lookup endpoint-level timer scheduler with empty-index/no-op
  service skips and unarmed-connection service short-circuits for
  multi-connection loops, and
  peer-address validation hooks with RFC 9000 3x anti-amplification send
  budget enforcement for unvalidated server paths,
  1-RTT key-update derivation and key-phase state with ACK gating and retained
  previous receive/send generations for reordered short-header packets, peer-triggered
  send-key synchronization before ACK, cached ACK-gate clearing for local
  key updates, and negotiated-suite RFC 9001
  confidentiality/integrity limits with proactive key rotation and terminal
  limit handling,
  configurable RFC 9438 CUBIC (default) and NewReno congestion-window control with zero-byte reserve/ACK/loss/PTO accounting no-ops,
  bytes-in-flight send admission wired into 1-RTT sending and ACK/ACK_ECN processing,
  deterministic timestamp injection plus automatic monotonic runtime timing,
  default configurable RFC 9406 HyStart++ slow-start overshoot prevention with
  packet-number RTT rounds, Conservative Slow Start, jitter recovery, and public
  window/in-flight observability, high-BDP CUBIC performance regression coverage, and receive-side Not-ECT skips plus ECN counter
  reporting, cached PTO-base send-time selection, old-ACK RTT sample skips, sent ECN counter validation, ACK_ECN CE congestion response,
  reordered-ACK_ECN tolerance, and plain-ACK ECN fallback disablement, RFC 9002-style RTT/PTO estimation with negotiated ACK-delay
  encode/decode zero-exponent fast paths and zero-delay adjustment skips, pre-first packet/time-threshold loss skips, packet/time-threshold loss detection, earliest loss/PTO timer
  deadlines, capped exponential PTO backoff, two-probe PTO service, and persistent
  congestion detection with already-reported period skips that collapses the congestion window and resets the RTT
  measurement epoch after long contiguous lost periods, default RFC 9002 token-bucket
  send pacing with configurable burst/disable controls, zero-packet sent no-ops, current-budget deadline skips, full-budget arithmetic skips, exact retry deadlines,
  ACK bypass, transactional rejection, and path-reset handling, allocation-free short-packet
  sealing into caller storage and connection-level plaintext/protected send-buffer
  reuse (while retaining stable recovery payload ownership), PMTUD/DPLPMTUD path MTU
  probe sizing state with IPv4/IPv6 ceilings, duplicate-ACK and stale-loss no-ops, loss-driven search backoff, and
  1-RTT PING+PADDING probe packets wired to ACK/loss feedback with
  ordinary-send and recovery-retransmit size enforcement from the currently
  validated path MTU,
  a compact ordered 1-RTT recovery queue with empty-payload preflight, monotonic packet-number insertion fast paths, cached newest retransmission packet numbers, and aggregate queue stats for PTO plus packet-threshold and time-threshold
  retransmission of unacknowledged ack-eliciting frame payloads with single-pass
  ACK-range retirement, no-op ACK short-circuiting, O(1) tail ACK/copy removal and middle retransmission-copy retirement,
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
  ownership or caller-buffer batch views, preallocated 1-RTT frame payload
  encoding, in-place current-key 1-RTT decryption, reusable receive/frame
  scratch,
  strict wire-order low-peak batch servicing, and bounded power-of-two
  recovery-payload reuse with allocation-free ACK-time recycling, four direct
  per-class slots, payload-intrusive overflow free lists, and a global
  idle-byte cap that lets the active size class absorb a complete ACK burst,
  endpoint-level connection-ID routing with single-probe registration and empty-length unregister skips,
  max-length-cached short-header dispatch with validated-key construction, empty-length long-header skips, unroutable zero-DCID long-header drops and static-key token derivation primitives for stable multi-connection
  demultiplexing wired into raw UDP receive routing and 1-RTT connection
  delivery, including peer-path binding and active-migration-disabled route
  rejection, NEW_CONNECTION_ID receive/send active-limit, single-pass receive/send duplicate-CID/reset-token validation, in-use-count-gated zero-copy stateless-reset token slice matching, and cursor-backed RETIRE_CONNECTION_ID lifecycle/preflight state with NEW/RETIRE CID-error close mapping wired into
  1-RTT, draft-ietf-quic-load-balancers-21 QUIC-LB CID generation/routing
  extraction with validated config rotation/lengths, Appendix B single-pass and
  nibble-correct four-pass AES vectors, caller-provided nonce entropy, and
  transactional local-CID/reset-token issuance,
  transport/application CONNECTION_CLOSE state including frame-payload, ACK, ACK_FREQUENCY negotiation, DATAGRAM negotiation, stream-limit/state/flow-control/final-size/data-conflict, server-only frame, and selected semantic error close emission, indexed PATH_CHALLENGE/PATH_RESPONSE validation state with preallocated clone copies and empty-outstanding challenge/response lookup skips, single-lookup duplicate challenge/response suppression, and caller-storage batch drains/sends wired into 1-RTT,
  peer-migration helpers and authenticated non-probing packet receive handling
  that honor disable_active_migration, preserve RTT while resetting
  tuple-local congestion/PMTU/ECN/PTO state for NAT rebinding, apply a server
  preferred_address by selecting its CID/reset token
  and peer IP/port, apply server-only full-datagram anti-amplification
  accounting, retain fixed-capacity per-candidate tuple budgets across
  probing-to-active transitions, emit 1200-byte path-validation datagrams,
  reset PMTUD path state, queue PATH_CHALLENGE with prepare/send/commit
  transactional indexing, retain cursor-backed PATH_RESPONSE targets,
  cache path-validation deadlines, skip early timeout scans, requeue timed-out
  challenges with single-lookup indexing, atomically preflight timeout retry
  storage, restore the last validated address/CID after validation failure,
  retain exact PATH_RESPONSE source tuples across migration, select a valid
  replacement when Retire Prior To removes the current peer CID, expose failed validation attempts in connection stats, and
  validate the new path on a matching PATH_RESPONSE, retire redundant
  same-path challenges and timers after that success, while sent-packet path
  epochs keep delayed old-path ACK/loss from changing the active path's RTT,
  congestion window, bytes in flight, PTO backoff, ECN, PMTU, or persistent
  congestion state without dropping reliable retransmission ownership,
  batch PATH_CHALLENGE timeout deadline recomputation across burst expirations,
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
  authentication, and key-update counters plus indexed per-stream send/receive stat snapshots with empty-index query skips and
  remaining credit for fast telemetry loops,
  plus NSS SSLKEYLOGFILE-compatible handshake/application traffic-secret
  streaming from both integrated handshake roles with caller-visible sink
  failures,
  plus a blocking UDP endpoint runtime for frame datagrams with a
  `std.Io.async` concurrent receive helper
- WebSocket handshakes with Host authority, body-framing rejection, duplicate-subprotocol and nonce validation, shared HTTP/1/RFC 8441 header policy isolated under `runtime/handshake`, HTTP/1 client attempts that preserve rejected status/headers/trailers/bounded body while legacy connect helpers retain `InvalidResponse`, two-phase TCP/Unix/WSS server admission that exposes path, headers, and authenticated TLS metadata before 101 and can accept with custom fields or return a closing 3xx-5xx response, plus RFC 8441 per-stream pending admission that exposes CONNECT metadata before 200 and can accept with custom fields or reject without closing sibling HTTP/2 streams, frame masking, strict frame/control
  validation including control/continuation RSV rejection, typed close-frame parse/write helpers and close payload checks, fragmented message assembly with aggregate
  message-size limits, automatic active-state PING→PONG and close echo/completed-close short-circuit handling plus tungstenite-style data-send/read suppression after receiving Close, deadline-aware frame reads and bounded graceful-close waits that surface peer close details without discarding in-flight application frames,
  caller-buffer frame/message receive for allocation-free uncompressed
  persistent echo loops plus compressed-message output directly into caller
  storage with reusable per-connection wire/history scratch across HTTP/1 and
  RFC 8441 HTTP/2, plus explicit mutable-buffer in-place client masking for applications
  that accept the same post-send mutation contract as websocket.zig,
  outbound text/close/control-frame validation plus codec-level invalid-frame write rejection,
  subprotocol token validation with strict client response selection, split-header subprotocol and extension-offer negotiation, optional permessage-deflate negotiation with
  no-context-takeover RFC 7692 sync-flush raw-DEFLATE encode/decode, retained
  independent send/receive codec scratch, actual LZ77/Huffman wire compression
  with uncompressed fallback when compression expands the message, plus quoted window-bit parsing and rejection of
  unsupported extension parameters/window sizes, framed 101 upgrade responses,
  compressed fragmented sends that stream discontiguous plaintext directly
  into DEFLATE with constant-space cross-fragment UTF-8 validation, serialized connection writes, a blocking TCP
  client/server runtime over HTTP/1 Upgrade, Unix-domain listener/client
  transports using the same handshake and framing state machine, optional absolute WS/WSS
  opening-handshake deadlines, shared absolute TLS 1.3 handshake budgets for
  WSS listeners and client-identity connections, and a `std.Io.async` concurrent
  server helper, `ws://`/`wss://` URI helpers with userinfo rejection, host-name DNS and IPv4/bracketed-IPv6 literal connect support plus
  Host/port synthesis, shared verified TLS client transport plus opt-in
  Ed25519/ECDSA/SM2 client identities, native TLS 1.3 WSS listeners with
  optional client authentication and concurrent serving, and RFC 8441
  WebSocket-over-HTTP/2 adapters with per-stream two-phase server admission and
  client attempt results that preserve non-2xx status/headers/bounded body/trailers, plus equivalent
  RFC 9220 client attempts (including caller-owned session restoration after a
  fully drained rejected stream), pending admission before the HTTP/3 200
  response that restores caller-owned server sessions after rejection or
  abandonment, and HTTP/3 rejection helpers that send DATA/trailers with
  automatic Content-Length while preserving sibling-stream reuse,
  negotiate `:protocol = websocket`,
  subprotocols, permessage-deflate, reject duplicate/legacy critical handshake
  fields, and use transport-derived `:scheme` over an h2 DATA tunnel
- MQTT 3.1.1/5 fixed headers, CONNECT/CONNACK with Last Will,
  version-scoped username/password flag validation and payload support, PUBLISH,
  PUBACK/PUBREC/PUBREL/PUBCOMP acknowledgements, SUBSCRIBE/SUBACK,
  UNSUBSCRIBE/UNSUBACK, PING,
  DISCONNECT with MQTT v5 minimal reason-only encoding, AUTH
  enhanced-authentication exchanges with CONNECT-before-CONNACK multi-step
  challenges, owned method binding, active re-authentication and ordinary
  traffic gating, broker event-loop policy hooks, Protocol Error on method
  mismatch, properties, exact packet bounds, minimal remaining length, MQTT
  UTF-8 string validation, response-topic/topic-name/filter validation,
  clean-session empty-client-id checks, version-specific MQTT 3.1.1/v5
  property and SUBSCRIBE option validation, payload-format UTF-8 validation, and
  wildcard and shared-subscription matching with MQTT 5 No Local/shared-subscription combination rejection,
  a broker-grade topic-level subscription trie with hashed literal edges,
  allocation-free caller-buffer matching, exact linear overflow fallback,
  subscription-option replacement, publisher-aware No Local filtering, and
  per-group/filter shared-subscription RoundRobin/Random/Sticky selection plus
  stable low-remapping Rendezvous hashing, plus a bounded retained-message
  store with exact O(1) lookup, wildcard matching, MQTT 5 expiry countdown,
  Retain Handling 0/1/2, shared-subscription suppression, QoS downgrade and
  connection-scoped property stripping, plus a bounded persistent Session
  Store with full subscription restoration, Session Expiry, offline QoS 1/2
  queues, Receive Maximum scheduling, DUP/PUBREL reconnect retransmission,
  out-of-order ACKs and incoming QoS 2 deduplication, atomic versioned broker
  snapshots, and an opt-in fsynced append journal with CRC/sequence/footer
  validation, torn-tail recovery, atomic compaction, and protocol-visible
  durability boundaries, plus coherent allocation-free broker statistics for
  connection, Session, subscription, retained, queue, inflight, QoS 2 and Will
  state and retained `$SYS` gauge publication through the normal routing/ACL
  path, integrated into one live
  TCP and Unix-domain broker listeners that auto-detect MQTT 3.1.1/5 per connection, exposes
  opt-in bounded HAProxy PROXY protocol v1/v2 parsing before TCP, TLS, WS, or
  WSS application handshakes, with trusted source, destination, transport and
  v2 TLV metadata,
  heterogeneous TCP/Unix/TLS/WS/Unix-WS/WSS listener sources sharing one broker core, with
  finite deterministic batches plus a graceful-shutdown production supervisor
  that continuously replaces disconnected clients, and
  Mosquitto-compatible mount-point namespaces with inbound PUBLISH/Will and
  ordinary/shared-filter mapping plus fail-closed live/durable outbound topic
  projection,
  pre-registration CONNECT authorization with remote/proxy/certificate
  identity context plus pre-mutation
  PUBLISH/SUBSCRIBE/UNSUBSCRIBE, per-recipient outgoing-delivery, and
  publication-time Will access-control hooks, and
  performs version-correct property/ACK downgrades, including securely
  generated anonymous Client IDs, MQTT 5 Assigned Client Identifier reporting
  and reconnect reuse, generation-safe duplicate-ClientID takeover that
  tolerates stale displaced-connection DISCONNECT completion, plus an indexed Will
  Delay scheduler with Session-end deadlines, reconnect cancellation, Clean
  Start takeover and DISCONNECT 0x00/0x04 handling, plus exact broker-side
  Keep Alive enforcement with 1.5x inbound inactivity deadlines, zero-disable
  semantics, bounded large-packet progress renewal and ungraceful Will/Session
  cleanup, plus a blocking TCP
  client/server runtime with a
  `std.Io.async` concurrent server helper, native MQTT-over-TLS clients with
  system or caller-provided CA roots, hostname verification, and optional
  client identities, plus configurable absolute TLS 1.3 handshake budgets for
  listeners and identity-enabled clients, plus TLS 1.3
  servers with caller-provided certificate chains/signers and concurrent
  serving, including optional/required client-certificate authentication,
  pluggable trust verification, verified peer-chain access on both native TLS
  endpoint roles and identity-enabled WSS clients, RFC 8446 exporter keying
  material plus negotiated cipher-suite/hash metadata on vail-backed HTTP/1
  servers, HTTP/2, WebSocket, and MQTT connections, including ordinary WSS
  clients that opt into vail without presenting a certificate, explicit
  application traffic-key rotation plus update counters, authenticated
  close-notify EOF with explicit write-half shutdown and strict bare-EOF /
  partial-record truncation errors, and opt-in native MQTT TLS ALPN negotiation
  with the selected protocol exposed per
  connection, and
  MQTT-over-WebSocket client/server adapters for MQTT 3.1.1 and MQTT 5, with
  strict `mqtt` subprotocol
  negotiation, `ws://`/`wss://` client and server transports, WSS client
  identities with system/caller CA or pin/custom server verification, MQTT
  byte-stream reassembly across binary-message boundaries, and in-place client
  masking,
  an optional absolute CONNECT/CONNACK packet deadline shared by TCP, TLS, WS,
  and WSS without large-packet progress renewal, MQTT v5 Server Keep Alive,
  conditional Response Information, Request Problem Information filtering for server ACK/AUTH diagnostics, Receive Maximum capped by local inflight limits, Maximum Packet Size, negotiated-or-configured Maximum QoS and Retain Available enforcement for incoming/outgoing publishes, and Topic Alias negotiation/resolution capped to local alias storage with outgoing alias registration checks, QoS publish inflight limiting, and
  MQTT 5 Server Reference validation plus opt-in bounded, loop-detecting
  CONNACK redirects for TCP/TLS/WS/WSS with per-hop authorization and fresh
  TLS authority verification, and
  QoS 2 exactly-once publish handshakes with unsolicited PUBREL rejection and negative-PUBREC receive-slot release, including MQTT v5 PUBACK/PUBREC/PUBREL/PUBCOMP reason-code/property validation with minimal reason-only encoding, dedicated UNSUBACK parsing, and negative publish acknowledgement propagation
- WebTransport capsules, unidirectional stream headers, CONNECT metadata with client-bidi session-id validation and `Capsule-Protocol` request/response advertisement, and
  stack-first CONNECT metadata assembly with exact allocation fallback rather
  than the former 57/62 additional-field ceilings, while
  `SETTINGS_MAX_FIELD_SECTION_SIZE` remains the interoperable byte budget, and
  datagram mapping with shared stack-first endpoint encoding and exact-size
  allocation fallback under `webtransport/runtime/datagram/`, session
  lifecycle/counter state, protected-runtime
  long-lived Extended CONNECT setup with bidirectional caller-buffer Capsule
  DATA, incremental WT_DRAIN_SESSION/WT_CLOSE_SESSION events, detailed and
  clean-FIN close, post-drain same-Session DATAGRAM traffic, and post-close
  operation rejection, plus a cleartext
  development runtime over the HTTP/3 dev transport with STREAM/HEADERS/body/
  cancellation send orchestration and retained DATAGRAM cloning grouped under
  `http3/runtime/development/send.zig`, a protected QUIC 1-RTT
  runtime over protected HTTP/3 with automatic WebTransport/H3 DATAGRAM
  SETTINGS advertisement and negotiation checks, plus packet-order CONNECT
  DATAGRAM routing/terminal/error handling under
  `http3/runtime/datagram/routing.zig`, and a handshake-backed
  protected runtime that uses QUIC 1-RTT DATAGRAM send/receive queues with
  WebTransport payload-size accounting, batch receive helpers, modern
  `0x41 + Session ID` bidirectional and `0x54 + Session ID` unidirectional
  stream association, real-handshake bidi/uni open/send/receive with
  per-session limits, prevalidated transactional cross-stream packet-batch writes that
  commit only the socket-visible prefix, with indexed O(n) duplicate validation
  and stable fixed-capacity priority selection under `runtime/stream/`, shared
  HTTP/3/WT stream-ID allocation, and
  CONNECT attempts across development, lightweight protected, authenticated,
  and stateful protected runtimes that retain bounded non-2xx DATA/trailers,
  paired with complete server rejection entities and stream-local cancellation
  on overflow; authenticated blocking/dispatcher paths additionally provide
  caller-owned client/server session restoration and sibling reuse, and
  WebTransport-style `stats`/`getStats` access to the underlying QUIC 1-RTT
  counters, plus an externally negotiated-key stateful runtime with the same
  recovery, congestion/flow-control, associated-stream, cancellation, and
  session-lifecycle facilities as the integrated TLS-handshake runtime
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
prior-knowledge h2c and RFC h2c Upgrade client/server flows, WebSocket includes
blocking TCP, Unix-domain and native TLS runtimes with pre-101 application
admission, and WebSocket clients also support WSS over the shared TLS client
transport; QUIC has Initial
protection primitives plus a blocking UDP endpoint runtime for datagram/frame
transport with endpoint-level Version Negotiation responses for unsupported
long-header versions; MQTT has blocking TCP and WebSocket client/server
runtimes plus native TLS client/server transport for
CONNECT/SUBSCRIBE/PUBLISH/PING/DISCONNECT flows, including QoS 1 and QoS 2
publish acknowledgements. The TLS and
MQTT TLS and WebSocket clients support `mqtts://`/`ssl://` and `wss://`
respectively through the shared verified TLS client transport. Configuring
either client's `client_identity` selects the vail TLS 1.3 stream and answers
CertificateRequest while preserving system/caller CA and hostname policy or an
explicit server verifier. The TLS server reuses the same MQTT
broker-side state machine as TCP/WebSocket and supports optional or required
TLS 1.3 client certificates with application-visible verified DER chains.
Clients without an identity retain Zig's standard TLS implementation.
`tls_handshake_timeout` applies to netz's vail-backed TLS 1.3 client and server
handshakes as one absolute receive budget across all handshake records; the
Zig 0.16 standard TLS client path does not expose an equivalent handshake
deadline. HTTP/1, HTTP/2, WSS, MQTT TLS, and MQTT WSS listeners forward the
same server option, while HTTP/2 and identity-enabled MQTT/WSS clients expose
the client-side option.
WSS servers reuse the cleartext HTTP Upgrade/frame state machine and may expose
verified TLS client chains. Event loops, congestion control,
ICE/DTLS/SRTP state machines, and richer high-level clients/servers can layer on
the same byte-level pieces.

The legacy HTTP/3 development runtime is intentionally labeled as cleartext; the
protected HTTP/3 runtime uses the QUIC 1-RTT short-packet API for SETTINGS
control streams and request/response STREAM frames. WebTransport has the
cleartext development transport, a protected runtime that performs CONNECT over
protected HTTP/3 and datagrams over protected QUIC 1-RTT packets, and a
handshake-backed protected session API, plus a stateful preconfigured-key API
for deployments that negotiate and authenticate 1-RTT keys externally. The
protected WebTransport runtimes
enable CONNECT, H3 DATAGRAM, WebTransport max-sessions, and draft-13
per-session stream/data credit SETTINGS by default, then reject DATAGRAM send or
receive calls if the peer did not negotiate the matching capabilities.
Handshake-backed sessions additionally expose caller-buffer incremental stream
reads before FIN, flow-credit return after every delivered prefix, mapped
32-bit WebTransport RESET_STREAM/STOP_SENDING APIs, and typed data/reset/stopped
events while retaining the whole-FIN receive helper for compatibility. A
packet-sized partial-write API returns actual progress for fair multi-stream
scheduling, with independent FIN and blocking write-all compatibility. Their
Extended CONNECT streams remain open for bounded incremental Capsule Protocol
control, including advisory drain, detailed/clean close, split DATA/capsule
parsing, UTF-8 reason validation and WT_SESSION_GONE cleanup of associated
streams. Terminal cleanup also discovers peer streams whose complete
association prefix was already buffered by QUIC before the WebTransport
registry observed it; same-session streams receive WT_SESSION_GONE without
consuming their payload, while incomplete, ordinary HTTP/3, and other-session
prefixes remain untouched. Handshake-backed sessions separately expose authenticated peer QUIC
application/transport close details, including code, reason, and transport
frame type, without conflating connection shutdown with a Session close
capsule. The lightweight preconfigured-key protected runtime shares the same
incremental Capsule parser and drain/close semantics, including same-chunk
event retention through the largest valid 1024-byte close reason; associated
streams intentionally remain unavailable because that transport does not own
ACK/loss recovery or flow control. `StatefulProtectedServer` and
`StatefulProtectedClientSession` fill that gap for externally negotiated keys:
they use the complete QUIC connection engine and therefore expose bidi/uni
association, partial/batched writes, incremental and whole-stream reads,
RESET_STREAM/STOP_SENDING, stream/session limits, connection statistics, and
session-close cleanup. Stateful servers also provide two-phase CONNECT
admission: applications can inspect authority, path, Origin, User-Agent, and
custom request fields before accepting with custom response fields or rejecting
with a final 3xx-5xx status. Stateful clients can attach validated custom
CONNECT fields and retain the successful response metadata for the session
lifetime. `HandshakeClientSession.connectUri` additionally accepts one complete
HTTPS URL and derives DNS targets, SNI, authority, and path/query with the same
multi-address fallback as the HTTP/3 client. Stateful sessions also expose the
session ID, current migration-aware peer address, address-validation status,
and smoothed RTT, plus an explicit connection-level application-close API that
does not conflate QUIC shutdown with a WebTransport Session close. Integrated
TLS sessions additionally expose RFC 8446 exporter keying material, with
matching client/server output and no per-call allocation, plus negotiated ALPN
and deeply owned authenticated peer certificate chains. Their connection IDs,
negotiated transport parameters,
ALPN, packet keys, and optional resumption master secret must all come from the
same authenticated external negotiation; the API does not replace TLS or
authenticate those inputs.

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
zig build run-webtransport-handshake-stream
zig build bench-webtransport-stream -Doptimize=ReleaseFast
# Bidirectional wtransport interop for CONNECT admission metadata, DATAGRAM,
# bidi/uni streams, mapped RESET_STREAM/STOP_SENDING codes, post-cancellation
# reuse, Session drain, and connection-level close.
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast
# Requires h2spec 2.6.0 on PATH, or H2SPEC=/absolute/path/to/h2spec. The gate
# always enables strict mode and rejects empty, skipped, or failed test runs.
zig build interop-http2-h2spec -Doptimize=ReleaseFast
# Also run the same strict suite over TLS 1.3 with mandatory h2 ALPN.
zig build interop-http2-h2spec -Doptimize=ReleaseFast -- --tls
# Build the locked local Hyper reference offline, then verify chunked bodies,
# negotiated trailers, and Expect/100-continue handshakes in both directions.
# The netz client also proves 103-before-100 handling and a bodyless 417 early
# final response that makes the incomplete HTTP/1 exchange non-reusable.
zig build interop-http1-hyper -Doptimize=ReleaseFast
# Build the locked local Hyper reference offline, then verify POST headers,
# multi-frame bodies/trailers plus bidirectional cancellation of a 128-KiB
# response at an 8-KiB stream window while a concurrent sibling completes on
# the same connection.
zig build interop-http2-hyper-client -Doptimize=ReleaseFast
# Build the audited quic-go fixture and verify HTTP/3 POST bodies/trailers,
# ordered 103/102 responses, and streamed responses/trailers over
# certificate-checked QUIC v1 and v2 in both directions,
# including H3_REQUEST_CANCELLED followed by same-connection reuse in both
# directions. The reverse case closes a partially-read quic-go response body
# and requires netz to observe the exact cancellation before serving stream 4.
zig build interop-http3-quic-go -Doptimize=ReleaseFast
# Use Hyper's HTTP/2 Extended CONNECT server to validate netz RFC 8441 frame
# masking, text exchange, Ping/Pong, and the WebSocket Close handshake.
zig build interop-websocket-hyper-h2 -Doptimize=ReleaseFast
# Build the quic-go fixtures from the audited local quicz checkout and run
# certificate-verified, ALPN-checked two-stream echoes in both directions,
# including a quic-go server that forces a Retry/address-validation round trip,
# plus two netz-initiated 1-RTT key updates with ACK gating and peer decryption,
# followed by quic-go RESET_STREAM, STOP_SENDING, and rolling flow-control
# and stream-limit renewal probes, client/server unidirectional streams,
# four-datagram Initial/application loss recovery, and exact application-close
# codes/reasons in both directions. A separate path gate issues additional
# Connection IDs, rejects a pre-probe switch, validates PATH_CHALLENGE /
# PATH_RESPONSE, migrates from 127.0.0.1 through 127.0.0.2 to 127.0.0.3
# with distinct source ports, and completes a stream after each switch. A
# loss variant drops the first PATH_RESPONSE on both candidate paths and
# requires timer-driven PATH_CHALLENGE retries before either switch. A separate
# same-IP source-port rebinding drops four datagrams, recovers by PTO,
# and verifies that NAT rebinding does not start active path validation.
zig build interop-quic-quic-go -Doptimize=ReleaseFast
# Requires Docker and the crossbario/autobahn-testsuite image. Optional trailing
# arguments select individual case IDs; with none, all 517 cases run. Pass
# --tls before case IDs to run the same gate over native TLS 1.3 WSS.
zig build interop-websocket-autobahn -Doptimize=ReleaseFast
zig build interop-websocket-autobahn -Doptimize=ReleaseFast -- --tls
# Drive the browser WebSocket API from Chrome against netz. The gate checks
# Origin rejection/acceptance, subprotocol and permessage-deflate negotiation,
# compressed text, binary data, automatic Pong, and a clean Close handshake.
zig build interop-websocket-chrome -Doptimize=ReleaseFast
zig build interop-websocket-chrome -Doptimize=ReleaseFast -- --tls
zig build run-websocket-echo
zig build run-http3-fetch
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify --head
# Optional diagnostic: performs a preliminary HTTPS HEAD Alt-Svc discovery.
zig build run-http3-fetch -- https://robotics.bytedance.com/ --verify --discover
```

`run-http3-handshake` is the self-contained local HTTP/3 counterpart to the
public fetch tool: it binds a QUIC/H3 server on loopback, performs a protected
client handshake, exchanges one request/response, and exits.
The HTTP/2 interop step starts a loopback h2c server and runs the external
h2spec server suite. Additional h2spec selectors can be passed after `--`, for
example `-- generic/3.4`. The public HTTP/3 URI client resolves all same-family
DNS answers and retries
transient UDP path failures such as QUIC handshake timeouts on the next
address, which makes CDN-backed origins more robust when one anycast edge is
temporarily dropping UDP/443.

Native microbenchmarks are also wired into the build.  Prefer `ReleaseFast`
when collecting performance evidence.  The current local baseline and
comparison gaps are recorded in `docs/benchmark-baseline.md`:

```sh
zig build bench -Doptimize=ReleaseFast
zig build bench-http1-parse -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http1-pipeline -Doptimize=ReleaseFast
zig build bench-http2-hpack -Doptimize=ReleaseFast
taskset -c 0 zig build bench-http2-h2c -Doptimize=ReleaseFast
zig build bench-http3-dev -Doptimize=ReleaseFast
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=1
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=upload --streams=4
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=16777216 --mode=download --streams=4
zig build bench-http3-capsule -Doptimize=ReleaseFast
zig build bench-http3-qpack -Doptimize=ReleaseFast
zig build bench-websocket-frame -Doptimize=ReleaseFast
zig build bench-websocket-receive-buffer -Doptimize=ReleaseFast
zig build bench-mqtt-router -Doptimize=ReleaseFast
zig build bench-quic-short-packet -Doptimize=ReleaseFast
zig build bench-quic-padding-parse -Doptimize=ReleaseFast
zig build bench-quic-lb -Doptimize=ReleaseFast
zig build bench-quic-udp-batch -Doptimize=ReleaseFast
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=1 --verbose
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=4 --verbose
taskset -c 0 zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=200 --skip-server-verification
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=lifecycle-churn --iterations=4096 --streams=16 --loss-pct=5
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=lifecycle-churn --iterations=4096 --streams=16 --reorder-every=5
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream --warmup=200 --iterations=5000
zig build bench-quic-ack-ranges -Doptimize=ReleaseFast
zig build bench-quic-stream-window -Doptimize=ReleaseFast
```

The aggregate `bench` step runs the current protocol microbenchmarks:

- HTTP/1 borrowed request-head parsing versus owned full request parsing,
- HTTP/1 persistent 16-request pipeline round trips with caller-storage batch
  parsing, small-response coalescing, and transactional large fixed-body
  vectored batches that borrow payloads, matching Hyper's `hello_world_16`
  benchmark shape,
- HTTP/2 HPACK stateful dynamic-table encode/decode versus stateless helpers,
- HTTP/2 persistent h2c round trips matching Hyper's consecutive empty,
  consecutive 10-byte/100-KiB-request, and parallel x10 empty end-to-end
  shapes,
- HTTP/3 cleartext development request/response round trips,
- HTTP/3 real-handshake paced upload/download throughput with configurable
  body size, direction mode, stream count, round-robin scheduling quantum,
  1-RTT datagram size, paced body chunk size, optional cross-stream body packet
  batching, and iteration count,
- HTTP/3 Alt-Svc `h3` / `h3-29` endpoint discovery parsing and origin-relative connection target resolution for real-site upgrade hints,
- HTTP/3 Capsule Protocol parsing/iteration and caller-buffer encoding for
  CONNECT-stream extension payloads,
- HTTP/3 QPACK field-section encoding against a populated dynamic table,
- HTTP/3 QPACK 512-entry reference-set encoding with large-only hashed
  deduplication and first-reference ordering,
- HTTP/3 QPACK dynamic-table churn with single-allocation name/value ownership,
- WebSocket masked frame encoding with allocating, caller-buffer, and
  header-only streaming paths, plus retained no-context-takeover
  permessage-deflate throughput and wire-size reporting; stream transports
  share nested `runtime/message/` helpers for bounded-slab receive growth,
  compressed-fragment partitioning, Close-state send admission, and owned
  message finalization,
- WebSocket persistent 4 KiB binary echo over one real upgraded connection,
  using caller-buffer receive and explicit in-place client masking, plus a
  negotiated permessage-deflate mode with logical-throughput reporting,
- MQTT subscription-router combined ordinary/shared count+emit trie matching
  versus a linear filter scan, retained connection PUBLISH encoding scratch,
  and linear-time overlapping-subscription broker flush plans,
- QUIC AES-128-GCM and ChaCha20-Poly1305 short-packet sealing with
  caller-provided storage versus the allocating convenience wrapper,
- bounded QUIC DATAGRAM receive queuing in an O(1) ring under
  `quic/one_rtt/datagram_queue.zig`, with exact one-time capacity reservation,
  newest-data retention, packet-number rollback, and explicit payload ownership,
- QUIC long PADDING run parsing for Initial padding and PMTUD/probe payloads,
- QUIC-LB encrypted server-ID extraction with the draft's three-pass
  load-balancer optimization,
- real-handshake raw QUIC STREAM upload throughput with configurable aggregate
  bytes, one or multiple streams, iteration count, and userspace packet batch
  size, including ACK-driven packet-threshold retransmission and
  allocation-free receive consumption,
- QUIC Linux `UDP_SEGMENT` batching versus `sendmmsg`, plus `UDP_GRO`
  coalesced receive versus plain per-datagram receive,
- QUIC 1-RTT stateful sequential send versus stateful batched protection with
  reusable scratch, full recovery/flow accounting, and UDP GSO/sendmmsg
  submission, with shared `one_rtt/frame_traits.zig` classification for
  ACK-eliciting/in-flight/retransmission/ECN/path-validation/HANDSHAKE_DONE/ACK
  watermark and STREAM-byte metadata,
- stateless QUIC 1-RTT single-packet sizing and caller-buffer send with direct
  frame encoding into the final packet's plaintext region followed by in-place
  AEAD, while the ownership wrapper performs one exact packet allocation,
- end-to-end QUIC 1-RTT UDP_GRO owning-batch cursor receive versus per-packet receive,
  including decryption, frame parsing, state application, and cleanup, plus a
  single-datagram in-place service path for state-only event loops.
- QUIC ACK range generation with allocating ownership versus caller-provided
  stack storage, plus allocation-free transactional recovery application
  directly from arbitrary wire-range counts,
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

Servers can inspect and reject the HTTP Upgrade before sending 101:

```zig
var pending = try server.receiveUpgradeRequest(.{});
var pending_open = true;
defer if (pending_open) pending.deinit();

if (!std.mem.eql(u8, pending.target(), "/chat") or
    !std.mem.eql(
        u8,
        pending.header("Authorization") orelse "",
        "Bearer example-token",
    ))
{
    try pending.reject(401, "Unauthorized", &.{
        .{ .name = "WWW-Authenticate", .value = "Bearer" },
    }, "authentication required\n");
    pending_open = false;
    return;
}

var ws = try pending.acceptWithHeaders(&.{
    .{ .name = "X-Admission", .value = "accepted" },
});
pending_open = false;
defer ws.close();
```

The pending value owns the transport until an outcome succeeds. TCP, Unix, and
WSS listeners share this API; WSS additionally exposes verified peer
certificates and negotiated cipher/hash metadata during admission.

The HTTP and WebSocket URI helpers synthesize Host / `:authority` / `:scheme`
from the URI and can connect to host names, IPv4 literals, and bracketed IPv6
literals such as `http://[::1]:8080/` and `ws://[::1]:8080/chat`.

On Zig 0.16, `std.Io.Uring` exists but its `std.Io.net` networking hooks are
still unavailable. All protocol runtimes nevertheless stay on the `std.Io`
abstraction: `netz.runtime.Backend.initAuto(.zio_then_threaded)` uses zio's
complete `std.Io` implementation (io_uring with automatic epoll fallback on
Linux, plus portable backends elsewhere), and falls back to `std.Io.Threaded`
if zio cannot initialize. Neither zio nor OS-specific rings leak into the HTTP,
WebSocket, QUIC, or other protocol APIs.

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
  sections, both instruction stream codecs, and lightweight Protected plus
  stateful client/server decode-side live encoder-stream processing with decoder
  feedback. These HTTP/3 runtimes persist their encoder/decoder streams and
  automatically use peer-capacity-bounded, reference-safe dynamic compression
  for repeated request and response fields after either preconfigured 1-RTT or
  a full QUIC handshake. Large field sections deduplicate dynamic references
  with temporary hash membership while preserving first-use order; ordinary
  sections retain their allocation-free stack and linear fast path. The
  lightweight preconfigured 1-RTT runtime also
  reuses protected packet scratch. Stateful preconfigured-key and
  handshake-backed runtimes batch
  multi-packet STREAM sends through UDP GSO or sendmmsg while preserving
  flow/recovery state and consuming every protected packet number on partial
  socket writes.
  Both runtimes bound speculative outbound references by the peer-advertised
  potentially-blocked stream count; Section Acknowledgment, Insert Count
  Increment, and Stream Cancellation release that budget while referenced
  entries remain protected from eviction. On receive they can advertise
  non-zero `SETTINGS_QPACK_BLOCKED_STREAMS` up to the bounded concurrent-stream
  limit, retain multiple complete dependent request/response messages, continue
  processing split/reordered encoder instructions, and resume each once its
  Required Insert Count is available.
- WebRTC support covers signaling/transport wire primitives (STUN, ICE, SDP,
  DTLS/RTP/SCTP headers), forming a foundation for peer-connection state
  machines and SRTP/SCTP data-channel layers.
