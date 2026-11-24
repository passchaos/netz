# Protocol coverage and verification inventory

This is the detailed feature-level coverage inventory referenced from
[README.md](../README.md). It records the bounded fuzz and live-network
verification targets plus the protocol behaviors covered by the library.
Architecture rules, performance invariants, and the change acceptance checklist
remain in [architecture.md](architecture.md); the documentation map is
[README.md](README.md) in this directory.

The four public protocol families share a bounded parser fuzz target.
`zig build fuzz-parsers` replays valid and hostile HTTP/1, HTTP/2, HTTP/3,
HPACK, QPACK, WebSocket, WebTransport, and MQTT seeds plus deterministic
truncation/bit-flip/random mutations under the leak-checking test allocator.
`zig build fuzz-parsers --fuzz=100000` runs Zig's coverage-guided fuzzer
against the same 64-KiB-bounded cross-protocol target. `zig build
fuzz-stateful` drives bounded operation sequences through HTTP/1 pipelines,
HTTP/2 flow control and HPACK, HTTP/3 control streams and QPACK, WebSocket
fragmented-message assembly, WebTransport session/stream lifecycles, and MQTT
Session/QoS persistence; add `--fuzz=N` for coverage-guided sequence discovery.

Latest guided replays (2026-11-22): `fuzz-parsers` 50,000 iterations,
`fuzz-stateful` 2,000, HTTP/1 300, HTTP/1+TLS 100, HTTP/2 200, HTTP/2+TLS 100,
HTTP/3 100, and WebTransport endpoint 50; all passed. Per-run logs and the
pass-by-pass ledger live under `docs/evidence/protocol_review/2026-11-21/`.
`zig build fuzz-http1-connection` drives bounded request/response sequences
through a production loopback TCP client and server. It covers persistent
reuse, complete and streaming fixed/chunked bodies, trailers, HEAD suppression,
and request- or response-selected connection retirement.
`zig build fuzz-http1-tls-connection` carries the same model over authenticated
TLS 1.3, verifies `http/1.1` ALPN and negotiated cipher metadata, and mutates
bidirectional traffic-key updates across persistent and rotated connections.
`zig build fuzz-http2-connection` exercises a production h2c connection across
ordinary and streaming request/response bodies, request trailers, reversed
two-stream response batches, PING, RST_STREAM cancellation, GOAWAY and fresh
connection rotation.
`zig build fuzz-http2-tls-connection` carries the same model over authenticated
TLS 1.3, verifies mandatory `h2` ALPN and negotiated cipher metadata, and uses
input-selected bidirectional traffic-key updates between HTTP/2 operations.
`zig build fuzz-http3-connection` drives authenticated QUIC/TLS HTTP/3 client
and server sessions through complete and streaming requests, request and
response trailers, reversed multiplexed responses, cancellation, HEAD body
suppression, and terminal two-phase GOAWAY.
`zig build fuzz-webtransport-endpoint` establishes two authenticated
WebTransport sessions through one production UDP endpoint and varies
cross-session DATAGRAM, paired-DATAGRAM, bidirectional-stream, DRAIN and CLOSE
ordering while checking exact handle routing and payload isolation.
`zig build fuzz-mqtt-live-broker` starts the production broker and three real
loopback TCP clients for each bounded input. It checks exact-topic
SUBSCRIBE/UNSUBSCRIBE ordering, live QoS 0 fanout, retained write, replacement,
deletion and Retain Handling 0 replay against an independent delivery model,
using PINGREQ/PINGRESP as deterministic no-sleep barriers.
`zig build fuzz-mqtt-tls-live-broker` runs the same broker model through three
certificate-pinned native TLS 1.3 clients, requires `mqtt` ALPN and
AES-128-GCM/SHA-256, and rotates traffic keys in both directions before the
modeled publishes and subscription changes.
`zig build fuzz-mqtt-reconnect` drives a persistent reconnect client against a
scripted real TCP peer. It verifies QoS 1/2 completion, lost-ACK PUBLISH replay
with stable Packet Identifier and DUP, PUBREL-only recovery, fresh-Session
transaction loss, and ordered accepted-subscription replay.
`zig build fuzz-mqtt-tls-reconnect` applies the same fault schedule through a
certificate-pinned native TLS connector and validates `mqtt` ALPN plus
AES-128-GCM/SHA-256 on every replacement connection.
`zig build fuzz-mqtt-wss-reconnect` carries it through certificate-pinned WSS,
requiring `http/1.1` ALPN before the WebSocket `mqtt` subprotocol and MQTT 5
session recovery.
`zig build fuzz-mqtt-bridge` adds a real upstream TCP peer, the production
inbound bridge, a local production broker and two local clients. It checks
QoS 0/1 mapping and acknowledgement ordering, retained replacement/deletion,
fresh/resumed upstream Sessions, subscription replay, DUP normalization and
connection-scoped property isolation.
`zig build fuzz-mqtt-tls-bridge` runs the same upstream fault and routing model
through a certificate-pinned native TLS connector, requiring `mqtt` ALPN and
AES-128-GCM/SHA-256 on every replacement upstream connection.
`zig build fuzz-mqtt-bridge-qos2` exercises the durable inbound bridge
transaction across PUBREC/PUBREL/PUBCOMP, transport reconnect, complete Bridge
recreation, fresh-Session epoch replacement, local exactly-once fanout and
retained replay through a crash-safe commit log.
`zig build fuzz-mqtt-tls-bridge-qos2` runs that durability oracle through a
certificate-pinned native TLS upstream, requiring `mqtt` ALPN and
AES-128-GCM/SHA-256 after initial connection, reconnect, and Bridge recreation.
`zig build fuzz-mqtt-outbound-bridge` drives the two-client outbound Bridge
between independent real TCP peers. Its model checks topic and property
mapping, source acknowledgement after target delivery, retained propagation,
target resend under preserved/fresh Sessions, source Session transitions and
ordered subscription replay.
`zig build fuzz-mqtt-tls-outbound-bridge` runs both source and target through
independent certificate-pinned native TLS connectors, requiring `mqtt` ALPN
and AES-128-GCM/SHA-256 after every reconnect on both broker legs.
`zig build fuzz-mqtt-outbound-bridge-qos2` composes two production brokers,
the durable coordinator, publisher, subscriber and restartable OutboundBridge.
It verifies end-to-end exactly-once delivery, pre-wire and PUBREL-phase journal
restore, independent source/target reconnects, retained replacement/deletion
and connection-scoped property isolation.
`zig build fuzz-mqtt-tls-outbound-bridge-qos2` runs that same crash-recovery
oracle with every publisher, subscriber, source, and target connection over
certificate-pinned native TLS, checking `mqtt` ALPN and AES-128-GCM/SHA-256
after each bridge reconnect or recreation.
`zig build fuzz-http-content-coding` feeds arbitrary field values and bounded
payloads through the shared gzip, deflate, Brotli, and Zstandard response-body
decoders, including caller-buffer limit and malformed-input paths.
`zig build fuzz-websocket-compression` separately checks hostile bounded
DEFLATE input and exact standard/Vort single-buffer and fragmented-input
round trips across RFC 7692 window sizes; it also accepts `--fuzz=N`.
`zig build fuzz-websocket-context` exercises the public stateful RFC 7692
compressor/decompressor across independent directions, retained and explicitly
reset histories, fragmented/repeated messages, hostile input, and transactional
output-limit failures. The HTTP/1, HTTP/2, and HTTP/3 runtimes additionally
support explicit
`allow_context_takeover` opt-in across ordinary, sliced, fragmented, and
deadline-resumable sends plus allocating, caller-buffer, and raw-frame receive
APIs. With the default opt-out policy, all three transports negotiate both
`*_no_context_takeover` parameters.
`zig build fuzz-websocket-h1-context`, `fuzz-websocket-h2-context`, and
`fuzz-websocket-h3-context` additionally carry the same bounded operation
sequences through real loopback HTTP/1 Upgrade, RFC 8441 Extended CONNECT, and
authenticated QUIC/TLS RFC 9220 sessions with context takeover enabled in both
directions. The companion `fuzz-websocket-h1-tls-context` and
`fuzz-websocket-h2-tls-context` targets authenticate WSS and RFC 8441 TLS
peers, require `http/1.1` or `h2` ALPN, fix AES-128-GCM/SHA-256, and exercise a
bidirectional TLS 1.3 KeyUpdate before the modeled traffic. They mix
text/binary, contiguous/sliced/fragmented/deadline sends, owned/caller-buffer
receives, and interleaved Ping/Pong without allowing input to create an
unbounded peer wait. These
targets are joined by `zig build fuzz-quic-wire`, which covers QUIC long
headers, Version Negotiation, Retry integrity, transport parameters, frame
streams, and carried TLS handshake messages. `zig build fuzz-quic-protection`
separately checks QUIC v1/v2 Initial, Handshake, 0-RTT, and 1-RTT packet and
header protection: Initial uses its RFC-mandated AES-128-GCM, while the other
packet spaces exercise AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, and SM4-GCM.
It also covers truncation and authenticated-tamper rejection.
`zig build fuzz-quic-connection`
adds bounded stateful QUIC v1/v2 sequences over real loopback UDP: bidirectional
STREAM/FIN and PING traffic, ACK/recovery, deliberate loss/reordering, duplicate
and corrupted delivery, PTO retransmission, RESET_STREAM, application reads,
and key updates across all supported traffic ciphers. `zig build fuzz-quic-path`
adds real-UDP path-state sequences across three loopback IPs and multiple source
ports: superseded and invalid PATH_RESPONSE, validation, timeout/retry/fallback,
NAT rebinding, and bidirectional stream traffic after path changes. The QUIC
targets are joined by `zig build fuzz-quic-handshake`, which negotiates QUIC
v1/v2, AES-128/SHA-256 or AES-256/SHA-384, and X25519/P-256/P-384 while
recovering from dropped or authentication-failed client/server flights and
validating Retry, bounded timeout, and post-handshake 1-RTT traffic.
`fuzz-quic-endpoint` runs four authenticated v1/v2 clients against one
socket-owning endpoint with a two-connection limit, verifies limit rejection,
removal and retry admission, exact per-connection STREAM routing, and stale-CID
isolation. `zig build test-quic-endpoint-soak` additionally cycles 64
authenticated v1/v2 and AES-128/AES-256 connections through one server socket.
After all four protocol combinations warm retained capacity, every generation
must return connection, pending-handshake, CID-route, and allocator live-byte
state to the same baseline; final endpoint teardown must return live bytes to
zero. Multi-hour, high-concurrency stability remains outside these bounded
models. The pinned GitHub Actions workflow replays all thirty-seven
corpora and the complete test gate on pushes and pull requests, then runs the
thirty-seven coverage-guided targets
daily and on demand. The live HTTP/1 and HTTP/2 targets default to 256 daily
connections, the TLS HTTP/1, TLS HTTP/2, and HTTP/3 connection targets to 64
authenticated sessions, the WebSocket H1/H2 TLS targets to 64 authenticated
sessions, the WebSocket H3 target to 128 authenticated sessions, ordinary live
MQTT targets to 128 real-network runs, the TLS live-broker target to 32, the
TLS reconnect target to 16, the WSS reconnect target to 8 and the TLS inbound-
bridge target to 16 authenticated runs, inbound/outbound durable
MQTT bridge QoS 2 to 64/32 runs, the TLS durable inbound bridge target to 8,
the TLS outbound-bridge target to 8 authenticated runs, its durable QoS 2
counterpart to 4, the WebTransport
endpoint target to 32
two-session runs, the QUIC path target to 256 runs, the QUIC handshake target
and QUIC endpoint target to 32 runs, and the in-memory targets to 10,000
iterations. A manual `fuzz_runs` value overrides all targets. The source
checkout uses sibling `../vail`, `../vort`, `../pbz`, `../kron`, `../regexz`,
`../webpkiz`, and `../harnessz` paths. CI checks out their public pinned sources
with the read-only `github.token`; `NETZ_DEPENDENCIES_TOKEN` is an optional
override for dependency access. The separate release workflow requires that
custom secret.
Pushes and pull requests also compile the complete library and public-package
test surfaces for baseline AArch64/x86_64 Linux, x86_64 Windows, and
AArch64/x86_64 macOS. A native Windows runner additionally executes the focused
HTTP peer-address, HTTP/3 CONNECT DATAGRAM, QUIC target receive,
WebTransport operation/stream reader/buffer admission and targeted events
and WebSocket byte-stream adapter
tests, covering zio Winsock queries, portable address vectors, datagram owner/
progress preflight, terminal write failures and queued Close/send ordering.
Live CONNECT DATAGRAM regressions use Netz's zio backend on every platform.
Zig 0.16's Windows `std.Io.Threaded` rejects deadline-bound UDP `net_receive`
operations with `ConcurrencyUnavailable`, including CONNECT fixture setup.

Use `zig build test-lib` for the complete in-process library suite without
external interoperability and release-tool checks; `zig build test` remains
the complete repository gate. Both accept `-Doptimize` and repeatable
`-Dtest-filter` options.
The complete gate includes the independent Node.js HTTP/2 A6 hedging runner;
it checks response-head commitment and observes loser CANCEL before the
winner emits its body. The in-process `test-lib` gate remains self-contained.

Current protocol coverage includes:

- Shared HTTP Content-Encoding parsing and bounded whole-representation decode
  for HTTP/1, HTTP/2, and HTTP/3 requests and responses, including
  repeated/stacked coding fields, reverse-order decoding, allocating and
  caller-buffer APIs, gzip,
  RFC 1950 `deflate`, Brotli, and Zstandard through Vort, with an eight-layer
  nesting cap and a decoded-size limit applied independently to every layer;
  streaming decoders for identity, single, and stacked codings that preserve
  exact input/output progress across arbitrary fragmentation and output
  backpressure, bound every intermediate layer through reusable fixed-capacity
  queues, require an explicit EOF finish, and expose constructors on each
  protocol's streaming response-head type. Unified H1/H2/H3
  `http.OwnedResponse` and redirected responses retain the same explicit
  allocating/caller-buffer decode surface without hiding a representation
  transform inside connection pooling,
- Shared RFC 8470 `http.early_data` semantics for HTTP/1, HTTP/2, and HTTP/3:
  any received `Early-Data` instance, including repeated or invalid values, is
  classified as replay risk; origin-facing sends require one canonical value;
  and a gateway receives an explicit preserve/set/none forwarding decision so
  an HTTP/1 `Connection` nomination cannot silently erase the signal during
  HTTP/2 conversion. Responses and request/response trailers reject the field
  in every protocol. HTTP/3 aggregate and endpoint-handler requests expose
  `mightHaveBeenEarly()`, combining accepted current-hop 0-RTT provenance with
  a prior hop's header even when the current connection is ordinary 1-RTT,
- Application-level form helpers: bounded `application/x-www-form-urlencoded`
  encode/decode and a streaming `multipart/form-data` writer/reader/parser.
  `RequestOptions.body_source` streams reader-backed bodies over HTTP/1
  chunked framing, HTTP/2 DATA frames, and bounded HTTP/3 request DATA.
  See `docs/http_forms.md`.
- An explicit, single-owner RFC 6265/RFC6265bis-22 `http.CookieJar` that
  deep-owns state from every repeated H1/H2/H3 `Set-Cookie` field; validates
  the lenient user-agent syntax with CTL and 4,096-byte bounds; applies
  Max-Age-over-Expires precedence, the recommended 400-day lifetime cap,
  host/default paths, Secure/HttpOnly, case-insensitive `__Secure-`/`__Host-`
  rules, plus the current layered-cookies `__Http-`/`__Host-Http-`
  Secure+HttpOnly constraints and unconditional value-only prefix rejection;
  CHIPS `Partitioned` cookies with Secure enforcement, explicit schemeful-site
  plus cross-site-ancestor keys, independent replacement/selection and a
  separate per-domain/per-partition default of 50 cookies and 10 KiB of
  name+value bytes; insecure secure-cookie overlay protection, SameSite
  Strict/Lax/None/Lax-by-default and the bounded unsafe-navigation window;
  preserves host-only and Domain cookies as distinct keys; and emits ordered
  Cookie values into caller or allocator storage. A dedicated redirected-
  response entry point binds new state to `final_uri`, never the initiating
  origin. Domain cookies fail closed
  by default until the caller explicitly selects unchecked matching or
  supplies a current Public Suffix checker; internationalized domains use
  caller-provided IDNA A-labels. A separate outgoing header ceiling prevents
  aggregate state from creating an unbounded request field. Bounded
  per-domain/global eviction
  prefers non-Secure excess state then oldest access, and `endSession` removes
  non-persistent cookies. Its full-fidelity persistent snapshot is versioned
  (v2 retains partition keys and restores unpartitioned v1),
  CRC-checked, capacity/policy validated, transactionally restored, excludes
  expired/session state, and uses file fsync, atomic replacement, plus parent-
  directory fsync with mode 0600. CRC detects corruption, not malicious
  tampering, and neither format encrypts Cookie secrets; applications needing
  confidentiality at rest must supply it below this API. Separate
  `*NetscapeLossy` APIs preserve curl-compatible
  domain/path/Secure/HttpOnly/expiry/name/value fields but require an explicit
  metadata-loss acknowledgement because SameSite and original timestamps
  cannot be represented; partitioned cookies are safely omitted instead of
  being flattened into cross-site state,
- A single-owner `http.CookieSession` composition that owns the unified
  H1/H2/optional-H3 Pool plus CookieJar. It rejects ambiguous caller Cookie
  fields, appends derived Cookie as HPACK/QPACK Never Indexed, commits every
  intermediate redirect response's Set-Cookie before resolving its Location,
  recomputes state for each target URI, binds final state to the actual hop,
  and preserves the pool's stale retry, Alt-Svc fallback, connection budgets,
  cross-origin credential/client-identity isolation, method rewriting and one
  absolute deadline. The actual method of each hop—including a 301/302/303
  rewrite—drives SameSite Lax eligibility. Cross-origin redirects
  conservatively become cross-site unless the application explicitly proves
  otherwise,
- A unified duplex `http.RequestHandle` for HTTP/1, HTTP/2, and HTTP/3 with
  incremental request-body writes (`writeBody`, `writeBodyFromReader`,
  `finishBody`, `finishTrailers`), callback-scoped response chunks and trailers,
  optional 1xx observation, deadline-bounded response reads, early-response
  handoff, abandoned-H3 stream cancellation, pooled HTTP/1/H2 leasing through
  `http.Pool.startRequest`, and pooled HTTP/3 streaming through the shared and
  exclusive pool dispatchers when an Alt-Svc route is active; H3 also opens the
  same handle through `http.startHttp3Request` on an exclusive
  `HandshakeClient`.
- A unified `http.Client`/`http.Connection` surface for HTTP/1.1 and HTTP/2,
  plus an optional HTTP/3-capable `http.Pool`:
  HTTPS performs one certificate-verified vail TLS 1.2/1.3 handshake offering
  `h2,http/1.1`, then transfers that exact authenticated transport into the
  selected runtime without reconnecting; explicit `http1_only`/`http2_only`
  policies and legacy no-ALPN-to-H1 fallback are available. Cleartext uses an
  explicit HTTP/1 or H2 prior-knowledge policy. Common method/header/body/
  trailer request options use stack-first protocol mapping, responses expose
  one owned status/body view plus the selected protocol, zero-allocation
  ordered header/trailer iterators, case-insensitive repeated-value filters,
  first-value lookup, preserved H1 spelling and H2/H3 Never-Indexed metadata,
  and the shared bounded Content-Encoding decoder; relative or
  absolute deadlines cover DNS/TCP, TLS, H2 SETTINGS, and the complete
  response. Bounded redirects may change negotiated protocol between origins
  while retaining method replay, credential/mTLS isolation, downgrade policy,
  final URI metadata, and one whole-chain deadline. The authority-keyed pool
  retains the negotiated protocol without another TLS handshake, caps the
  combined idle/leased/connecting population, uses allocation-free FIFO
  capacity admission, per-origin and global idle bounds, true global LRU and
  monotonic idle retirement, and retries one stale reused connection only for
  idempotent methods. TLS 1.2/1.3 tickets are retained by exact origin and ALPN,
  and pool redirects release each completed hop before acquiring the next
  origin. `client.http_proxy` routes cleartext HTTP through absolute-form
  proxy requests and HTTPS through an HTTP/1.1 CONNECT before origin TLS;
  proxy headers remain proxy-only, the pool reuses one proxy connection per
  origin, SOCKS5 and HTTP proxy routes are mutually exclusive, and an HTTP/3
  pool is rejected while a proxy is configured. When callers explicitly configure QUIC/TLS verification, successful
  H1/H2 responses populate the bounded Alt-Svc cache and later requests use the
  origin-preserving H3 pool. H3 responses share the same owned protocol/status/
  header/body surface. QUIC failures enter exponential backoff; only idempotent
  methods replay over the existing TCP pool by default, while non-idempotent
  requests surface the H3 failure without duplicate application delivery. One
  absolute deadline remains unchanged across the H3 attempt and TCP fallback.
  Cross-origin redirects clear caller-supplied TCP TLS 1.2/1.3 tickets and
  require an H3 redirect-aware connector that removes QUIC resumption,
  address-validation, early-data, deterministic random/key material, and
  disallowed client identity before dialing the next authority.
  Idle H3 connections can additionally serve another HTTPS origin only after
  the peer explicitly adds that origin through RFC 9412 ORIGIN and the
  authenticated leaf certificate independently covers its DNS name or exact IP
  subjectAltName. The pool retains the connection's initial origin key across
  coalesced requests, keeps the current request origin separately owned, and
  applies a 421 response before returning the connection to idle state. A 421
  excludes only that request origin; a later ORIGIN frame may re-authorize it.
  Connections without a retained certificate chain and certificate-mismatched
  advertisements remain ineligible rather than treating ORIGIN or a public-key
  pin as sufficient authority.
  The exclusive H3 pool now maps same-origin URI batches, including Alt-Svc
  routes, onto the connection's independently-deadlined batch core while
  preserving original request indices, SETTINGS observation, and 421 updates.
  `HandshakeClientPoolSharedDispatcher` layers a bounded FIFO and cloneable
  senders over that core: one caller-selected driver remains the sole pool and
  socket owner, compatible direct or Alt-Svc commands coalesce on one QUIC
  connection, and producer timeout/cancellation wakes the driver to cancel only
  that request. Stack-owned commands keep borrowed URI/header/body/trailer
  storage alive until completion or cancellation convergence.
  The exclusive H3 backend retains its own explicit total/idle limits in
  addition to the TCP pool's limits. An optional move-stable shared budget also
  caps the combined TCP/QUIC idle, leased, and connecting population, with
  allocation-free FIFO admission, caller deadlines, exact failure/eviction/
  close accounting, and aggregate connection/waiter counters. When an Alt-Svc
  H3 connection needs a full shared budget, it can retire the oldest idle TCP
  connection and transfer that capacity without exceeding the configured cap;
  a later TCP origin can symmetrically retire the oldest idle H3 connection.
  The H3 backend can additionally opt into RFC 8470 0-RTT without bypassing
  the unified surface. Successful responses record peer SETTINGS in a bounded,
  origin-scoped LRU independent of Alt-Svc and TLS ticket ownership. A safe
  request is prepared only after acquisition proves a new connection is
  required; idle H3 reuse remains ordinary 1-RTT with no early-request
  encoding/allocation. New connections require both remembered SETTINGS and an
  origin+ALPN ticket, retain one absolute admission/handshake/response budget,
  and expose accepted/rejected plus 425-retry metadata on `OwnedResponse`.
  TLS rejection and the first 425 replay once over 1-RTT; a second 425 is final.
  Unsafe/unknown methods stay 1-RTT under the default safe-only policy, and
  `RequestOptions.allow_early_data=false` disables even an eligible request.
  Cross-origin redirects never reuse this early-data path. When the configured
  server emits a post-handshake NewSessionTicket, every H3 response/push/
  detached-stream pump opportunistically feeds authenticated 1-RTT CRYPTO into
  a bounded reassembler and writes each complete ticket to the origin+ALPN
  cache; it never performs an extra socket wait merely to obtain a ticket.
  Fragmented/out-of-order CRYPTO uses the transport reassembler, multiple
  messages advance monotonically, zero-lifetime tickets are discarded, and a
  malformed authenticated ticket fail-closes the connection,
- HTTP/1.1 requests, responses, strict owned/borrowed Host and CONNECT-authority validation, preallocated request/response/header-block writes with version, exact non-empty Content-Length, and complete pre-encoded chunked-body validation, header field syntax validation, CONNECT framing rejection and bodyless TRACE enforcement, chunked transfer encoding that elides empty application slices before its sole terminator, chunked decoding with strict no-leading-OWS chunk-size grammar, exact-body allocation, empty-terminator encode/decode fast paths, extension newline rejection, and complete/incomplete chunk-size-line bounds, close-delimited and non-chunked-transfer-coded response bodies, runtime chunked
  transfer writing with preallocated chunks plus fully syntax-validated,
  declaration-matched and repeated-value-merged trailer fields, server response trailers gated by the
  request's valid HTTP/1.1 `TE: trailers` plus `Connection: TE` capability,
  with runtime request writers synthesizing the required connection option,
  strict Connection option syntax and framing-field nomination rejection,
  version-correct Upgrade coupling, body-aware `Expect: 100-continue`, opt-in obsolete folded-field
  unfolding, exact-allocation/empty-header owned-parse fast paths, strict allocation-free borrowed request/response head parsing into
  caller header storage with single-pass strict CRLF/name/value validation,
  exact Content-Length pipeline offsets and
  method/status-aware response boundaries, request-target/status/reason-phrase start-line validation with method-specific asterisk/authority-form and no-fragment rules, status-forbidden response-body write rejection with RFC-compliant 304 representation metadata, keep-alive/upgrade handling, pipelined
  byte buffering with exact-message ownership transfer, allocation-free caller-storage request-pipeline batch parsing with transactional in-place chunk decoding and one-prefix consumption, reusable runtime header/trailer/encoding scratch for persistent connections, canonical status-line encoding including empty reason phrases, and aggregate Content-Length/Transfer-Encoding/chunk/trailer boundary decisions grouped under `http1/runtime/message/`, non-chunked header/body vectored writes, transactional batched response validation and one-flush pipeline writes, method-aware response body
  handling for HEAD and successful CONNECT, sender-side RFC 9110 enforcement that 205 responses contain no content while receivers still consume their declared framing, stateful incremental request/response writers with fixed-length or chunked framing, cross-write Content-Length enforcement, announced/merged trailers, exact response handoff, client-side `Expect: 100-continue` gating with early-final-response handoff, and connection-poisoning abandonment semantics, plus callback-based streaming request and response readers with owned heads/trailers, fixed/chunked/close-delimited framing, pipelined-suffix preservation, and no body-sized aggregation, Host/authority delimiter validation, strict authority-form CONNECT target delimiter/userinfo rejection, malformed absolute-form authority validation including bracketed IPv6, deadline-bounded CONNECT/generic-Upgrade opening handoffs spanning request write, informational responses and the final entity, and CONNECT tunnel helpers, interim 1xx response skipping plus
  server-side `Expect: 100-continue` handling even when body bytes are pre-read, with full request-head/Host/framing/size validation before any interim response, pure-digit Content-Length enforcement,
  TE-over-CL precedence with parsed `Content-Length` stripping and mandatory connection retirement on ambiguous requests, shared quote-aware Transfer-Encoding parsing across codecs and runtime message boundaries, ambiguous body-length rejection
  across repeated/coalesced `Content-Length`, unsupported transfer-coding rejection, strict-by-default opt-in Hyper-shaped repeated request-line SP, response-only whitespace-before-colon compatibility, and direction-specific invalid-header skipping that still rejects ambiguous NUL/CR boundaries,
  owning request/response head APIs with opt-in line unfolding, metadata-derived
  runtime body boundaries, and retained folded values in streaming results,
  complete folded-field validation even in ignored groups, with one owned
  unfolded value per accepted field and bounded storage under repeated folding,
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
  Host/default-port, CONNECT authority, and absolute-form authority synthesis,
  `http://`/`https://` URI helpers, persistent HTTP forward-proxy requests with
  fragment-free absolute-form targets, and one-shot HTTP/HTTPS proxy helpers
  whose single deadline spans proxy DNS/TCP, CONNECT, origin TLS and the final
  response while keeping proxy-only credentials outside the authenticated
  origin request,
  plus bounded 300/301/302/303/307/308 URI redirect following with RFC 3986
  relative resolution, canonical loop detection, HTTPS downgrade protection,
  configurable POST rewrite semantics, 307/308 body replay, cross-origin
  credential stripping, proxy retention and one deadline across the chain,
  with userinfo rejection, host-name DNS and IPv4/bracketed-IPv6 literal connect support, TLS client transport via Zig `std.crypto.tls`
  with host verification plus OS root bundles, platform-native macOS/Windows verification, custom CA bundles, and compiled-in Mozilla roots, an opt-in vail HTTPS client
  for mTLS/ALPN/peer-chain/exporter/KeyUpdate access, and a `std.Io.async`
  concurrent server helper; aggregate client calls hold the generation-tagged
  HTTP/1 exchange slot from pre-write validation through the complete final
  response, preventing informational callbacks from reentering and interleaving
  another request while preserving retry after purely local validation errors;
  pooled single-request clients are reused only at an empty HTTP/decrypted-TLS
  input boundary, and cleartext leases additionally perform a native
  nonblocking socket peek before returning idle; buffered or kernel-queued
  unsolicited responses and EOF are therefore discarded instead of being
  attributed to the next lease; pooled URI requests expose the same bounded
  redirect policy and whole-chain deadline, releasing every response before
  reacquiring its next authority so same-origin hops can immediately reuse the
  connection while cross-origin hops retain pool capacity, LRU, TLS-ticket,
  credential-isolation, and mTLS-identity rules
- Shared vail-backed TLS 1.2/1.3 stream client/server wrappers with explicit
  TLS-1.3-only, TLS-1.2-only, or highest-version negotiation policy; TLS 1.2
  permits only ECDHE+AEAD suites, requires Extended Master Secret and secure
  renegotiation signaling, supports X25519/P-256/P-384/P-521 in both endpoint
  roles with an X25519-first/P-256-fallback high-level default, and rejects
  renegotiation. Exact TLS-1.2-only mode advertises all four groups, while a
  dual-version ClientHello advertises only its X25519/P-256 TLS 1.3 retry
  material. Both versions provide
  optional/required client authentication, explicit ALPN enforcement, owned
  negotiated-protocol metadata, authenticated cipher-suite/transcript-hash
  introspection, default RFC 6066 OCSP status requests plus optional mandatory
  staple validation across HTTP/1, HTTP/2, WSS, MQTT TLS, and MQTT-over-WSS,
  RFC 5077 TLS 1.2 stateless session tickets with identity/ALPN/lifetime-bound
  client caches, rotating server keyrings, unique per-connection nonces, and
  authenticated invalid-ticket fallback to a full handshake;
  TLS 1.2/1.3 clients select certificates against the requested signature
  algorithms, certificate-chain constraints, and acceptable CA names; TLS 1.2
  additionally checks the requested certificate type and supports P-521. Both
  versions send an empty Certificate when no configured identity is suitable;
  OpenSSL process gates verify matching-certificate and optional unmatched-CA
  handshakes, while TLS 1.2 servers reject CertificateVerify algorithms outside
  the exact set they advertised. TLS 1.3 clients ignore unknown
  CertificateRequest extensions for forward compatibility while still
  rejecting every duplicate extension type across the complete 16-bit namespace
  without an arbitrary count ceiling, as well as malformed known extensions;
  repeated signature-algorithm values remain acceptable in TLS 1.2/1.3 ClientHello
  and TLS 1.3 CertificateRequest vectors, while a present certificate-authorities
  extension must contain at least one non-empty DistinguishedName;
  TLS 1.3 OID filters enforce Key Usage and Extended Key Usage subsets on the
  client leaf, reject malformed or repeated recognized filters and prohibited
  anyExtendedKeyUsage requests, and ignore unrecognized extension OIDs;
  TLS 1.3 CertificateRequest accepts the standard empty status-request signal,
  rejects non-empty forms and recognized extensions prohibited in that message,
  and ignores only genuinely unknown extensions;
  configured client identities can attach leaf or per-chain-entry OCSP staples;
  they are sent only when requested, rejected when unsolicited, and passed to
  the server trust verifier without losing CertificateEntry association;
  servers preflight all CertificateRequest fields and nested lengths before
  emitting ServerHello, so invalid authentication configuration is transactional;
  both peers reject a non-empty CertificateRequest context during the initial
  TLS 1.3 handshake, reserving it for post-handshake authentication;
  HTTP/1 and HTTP/2 pools use a bounded identity-and-port cache to resume new
  connections after idle eviction or non-reusable connection retirement;
  a bidirectional OpenSSL process gate verifies ticket resumption with netz in
  both the TLS client and server roles,
  RFC 8446 TLS 1.3 PSK-DHE resumption with authenticated post-handshake
  NewSessionTicket retention, identity/ALPN/age validation, renewed tickets,
  full-namespace extension duplicate detection, strict extension placement and
  vector bounds with unknown-extension tolerance, invalid-ticket fallback to a
  certificate-authenticated full handshake, generic TLS preservation of finite
  early-data limits, and QUIC-only enforcement of RFC 9001's `0xffffffff`
  sentinel; zero-lifetime tickets are consumed and discarded without failing
  the established connection, and client/server caches consistently expire
  tickets at the exact advertised lifetime boundary. A ticket can resume with
  another cipher suite using the same transcript hash, while 0-RTT still
  requires the ticket's original cipher suite and ALPN context,
  separate bounded HTTP/1 and HTTP/2 pool caches that resume after physical
  connection retirement; MQTT reconnect clients retain separate TLS 1.2 and
  TLS 1.3 tickets, renew them across native TLS or WSS connections, and discard
  them locally when their advertised lifetime expires; configured native MQTT
  TLS and WSS listeners expose both ticket versions with independent keyrings,
  explicit server identity and lifetime bounds, and OpenSSL resumption gates,
  without enabling early data,
  RFC 8446 TLS 1.3 post-handshake KeyUpdate with reciprocal-update
  handling and bounded peer control bursts, and vectored plaintext writes that
  coalesce protocol slices into bounded TLS records without a heap concatenation
- Strict owned TLS server-identity loading from PEM certificate chains and
  unencrypted P-256/P-384 SEC1 or PKCS#8 and RFC 8410 Ed25519 private keys,
  with bounded input, canonical
  DER validation, secret-buffer clearing, and leaf certificate/key matching
- Strict owned PEM CA-file loading for TLS client authentication, with bounded
  certificate counts, validity and clientAuth CA-usage checks, duplicate-name
  rejection, and exact DER authority names for TLS 1.3 CertificateRequest
- Strict owned Ed25519, P-256 ECDSA/SHA-256, P-384 ECDSA/SHA-384, or
  1024-4096-bit RSA PKCS#1 v1.5 SHA-256 PEM CRL loading, including
  issuer/cRLSign, signature, update-window, extension and leaf-serial
  validation before bind, plus RFC 5280 base/delta composition with newest
  compatible-delta selection and `removeFromCRL` handling, and direct or
  multi-hop delegated indirect CRLs with mandatory signer authorization,
  shared-trust-anchor validation, and leaf `cRLIssuer`/distribution-point
  matching
- Caller-supplied bounded caching of successful X.509 bundle verification for
  repeated exact hostname/DER chains; per-connection CertificateVerify remains
  mandatory, and replacing the trust bundle or time snapshot requires replacing
  the cache
- HTTP/2 frame headers with direct parse/preallocated writes and full-frame direct writes, with owned/borrowed transport I/O, envelope validation, fixed-frame encoding, and transactional HEADERS/CONTINUATION batching grouped under `http2/runtime/frame/`; RFC-bounded SETTINGS validation, DATA/HEADERS (including PADDED/PRIORITY self-dependency checks)/PRIORITY/PUSH_PROMISE/CONTINUATION/RST_STREAM payload parsing, RFC 8336 single-probe exact-indexed ORIGIN origin-set state with exact-allocation/empty-payload parse fast paths, allocation-free/preallocated writes, empty-index membership and duplicate-entry skips, RFC 7838 single-probe exact-indexed ALTSVC connection/stream advertisements with allocation-free/preallocated writes, identical replacement skips and per-target replacement, and active-stream reset propagation, a bootstrap
  HPACK static/literal encoder-decoder with RFC 7541 Huffman strings, preallocated prefix-integer writes, complete `u64` prefix-integer decoding with explicit over-width rejection, exact encode/decode output preallocation, retained runtime encode scratch, preallocated empty/short/raw-preferred string write fast paths, and connection-owning server/client APIs that emit exact COMPRESSION_ERROR/PROTOCOL_ERROR/ENHANCE_YOUR_CALM GOAWAY frames for malformed HPACK, broken CONTINUATION sequences, or unterminated header floods while returning the original local error, plus stream-local PROTOCOL_ERROR/ENHANCE_YOUR_CALM resets for malformed or oversized admitted messages across aggregate, streaming, and batch paths with exact connection-credit restoration and sibling cleanup; configurable connection-lifetime budgets bound both library-generated peer-protocol-error resets and retained peer ORIGIN/ALTSVC advertisements, without charging application cancellation, timeout cleanup, or REFUSED_STREAM admission control,
  pseudo-header and common-header static fast paths, internal empty-dynamic-table lookup skips, single-lookup
  dynamic insert indexing, O(1)
  FIFO dynamic-index eviction, and single-pass request/response pseudo-header
  and length extraction, plus
  header lookup, Content-Length normalization, pseudo-header/URI/authority
  validation, trailer rules, and response-body semantics grouped under
  `http2/runtime/headers/`,
  protocol-error GOAWAY output, including pre-Connection bootstrap rejection
  of a bad client preface, malformed handshake frame envelope, or invalid
  peer SETTINGS on direct, TLS, and h2c-upgrade accepts, shares the finite
  `Limits.terminal_cleanup_timeout` budget (10 ms by default, zero skips
  output), is stack-encoded without allocation, preserves the original
  error, and stops after a failed terminal write; the terminal TLS
  close_notify shares that same single remaining budget during bootstrap
  and receives its own equal-sized budget on established-connection
  teardown (replacing the TLS destructor's formerly unbounded alert write),
  and is suppressed after a failed write or with a partial TLS record
  pending, so neither GOAWAY nor alert output can outlive connection
  cleanup; queued request overflow shares this budget across resets
  and GOAWAY,
  one absolute `handshake_timeout` or caller deadline also bounds every
  outbound bootstrap byte: cleartext/TLS client preface, both endpoints'
  initial SETTINGS/WINDOW_UPDATE/ACK frames, and h2c's HTTP/1.1 Upgrade
  request and 101 response; the legacy h2c path uses one budget for the
  HTTP/1.1 phase and a fresh phase budget after switching protocols, while
  explicit deadlines are never renewed,
  exact dynamic-table indexing/size-update state for long-lived runtimes with local decoder table-size enforcement and automatic
  peer table-size update emission plus h2/hyper-style non-indexing for volatile or oversized fields and automatic
  never-index encoding for sensitive fields, fixed-control-frame and preallocated control-frame write fast paths, PING with opaque ACK matching plus explicit absolute-deadline round trips whose budget covers probe/ACK writes as well as reads, and a reusable single-reader inactivity-aware keep-alive driver with active/idle policy, monotonic probe payloads, connection-control processing and a configurable bounded FIFO preserving interleaved application frames, GOAWAY/WINDOW_UPDATE connection
  management including interleaved SETTINGS/PING/WINDOW_UPDATE/PRIORITY handling and compacting interleaved request FIFO reuse, RFC 9218 SETTINGS_NO_RFC7540_PRIORITIES negotiation and client-only PRIORITY_UPDATE signaling with preallocated frame payload writes, indexed bounded pre-request buffering, allocation-free full-capacity rejection, identical-update skips, single-probe reservation/replacement, cached idle-request pruning/activation with empty-index checks, empty-update lookups/removals, and promised-push validation, active-stream RST_STREAM guarding, fixed-capacity plus minimum-duration local-reset history, and a connection-lifetime budget for peer-induced protocol-error resets that escalates excess churn to GOAWAY(ENHANCE_YOUR_CALM), explicit opt-in PUSH_PROMISE promised-request/pushed-response lifecycle with preallocated PUSH_PROMISE frame writes, parent/promised-stream validation, single-lookup local push reservations with empty-index local lookup skips and promised-push queue indexing, indexed reserved/pending push lookups and releases with empty-index skips, O(1) cursor FIFO promised-request notification delivery, head/tail-cancel fast paths with empty-pending skips and targeted pending-index repair, and client RST_STREAM(CANCEL) refusal of reserved pushes, GOAWAY propagation and allocation-free GOAWAY emission during stream reads and post-GOAWAY request suppression/rejection, cached multi-set drain-floor checks, and same-control-stream GOAWAY emission with persistent control-stream offsets, default client server-push opt-out, connection- and stream-level flow-control enforcement with signed bounded window arithmetic and zero-length DATA semantics isolated under `http2/runtime/flow/`, including
  transactional single-pass SETTINGS_INITIAL_WINDOW_SIZE updates, exact-allocation/empty SETTINGS parse fast paths, and allocation-conscious configurable advertisement, configurable SETTINGS_HEADER_TABLE_SIZE/SETTINGS_MAX_CONCURRENT_STREAMS/SETTINGS_MAX_FRAME_SIZE advertisement, bidirectional SETTINGS_MAX_CONCURRENT_STREAMS enforcement, SETTINGS_MAX_FRAME_SIZE and SETTINGS_MAX_HEADER_LIST_SIZE validation with inbound advertised-frame-size enforcement, RFC 9218 response DATA scheduling with dynamic PRIORITY_UPDATE precedence, single-pass urgency/exclusive-stream selection, sequential non-incremental stream-ID order, incremental round-robin sharing, and blocked-stream bypass,
  outbound frame splitting plus h2-style CONTINUATION chain flood, stream-id overflow, indexed active-stream tracking with single-probe activation, duplicate reserve skips, empty-index active checks, and empty-index release skips, wrong-direction HEADERS, and idle-stream DATA/WINDOW_UPDATE send limits, with stack-first request/response header descriptors, TCP_NODELAY, configurable connection/stream receive windows, vectored HEADERS+DATA and multi-DATA bursts, transactional bodyless multi-stream request/response batches with HPACK-state staging, out-of-order response reassembly, single-budget timeout/deadline variants for aggregate or callback-streaming bodyless response batches, and an owned-result observer variant with independent per-stream deadlines that resets only expired members, restores their charged connection credit, decodes late HPACK blocks, continues later siblings, stops expired upload cursors, and commits request trailers only for surviving streams, full-duplex body-bearing batches that round-robin uploads across connection/stream window updates while retaining early sibling responses, and interleaved streaming request batches, connection-level bulk frame read buffering, callback-based streaming request and response bodies with owned heads/trailers, stateful incremental request/response writers with transactional cross-chunk Content-Length enforcement, DATA/trailer finish, response handoff, and abandoned-writer cancellation, bounded early-response preservation while an upload waits on flow control with partial-write accounting and aggregate/streaming response transfer, timeout/deadline-bounded ordinary, full-duplex, and CONNECT tunnel DATA writes with exact committed-byte cursors for suffix-only retry, strict streamed receive Content-Length accounting, callback-error RST_STREAM cancellation, and DATA sends that wait for WINDOW_UPDATE capacity
  and inbound DATA consumers that account for full padded frame payloads with single-probe indexed stream-window state, empty-index membership skips, restore connection/stream receive capacity, and optionally grow both receive targets from an allocation-free BDP estimator with reserved PING correlation and serialized SETTINGS acknowledgement,
  frame-envelope validation including fixed-size RST_STREAM and SETTINGS payload-multiple checks, stream-id direction/monotonicity validation, request/response trailers with forbidden-field rejection, pre-HEADERS frame ordering checks, bounded ordered interim 1xx observation across single and multiplexed client reads with request-index/stream-ID batch correlation and explicit server-side informational response sending, plus terminal 500 fallback and per-request `InvalidStatus` reporting when a high-level handler accidentally returns 1xx as its final response, active-stream guards that prevent final or informational response writers from reopening completed streams, content-length
  validation with pure-digit Content-Length enforcement, indexed response-body semantics retention with single-probe updates, duplicate reserve skips, and empty-index lookup skips, end-to-end TCP/Unix/TLS/h2c listener deadlines spanning accept plus protocol bootstrap with accepted-socket race cleanup, HTTP/2 pseudo-header/lowercase field-name/value and control-character validation, `:method` token validation with case-sensitive HEAD/CONNECT/OPTIONS semantics and `:protocol` token validation,
  URI-like `:scheme`/origin-form `:path`/`:authority` validation with Host fallback and Host/`:authority` mismatch rejection,
  connection-specific header rejection including `TE` rules and stack-first,
  exact-capacity removal of every `Connection`-nominated hop-by-hop field
  without a fixed field-count ceiling,
  status-forbidden response-body write rejection plus sender-side empty-content
  enforcement for 205 without changing DATA/END_STREAM receive framing,
  failed aggregate and callback response reads return all still-held DATA
  connection credit, including padding, without counting low-watermark
  refills or adaptive grants twice; complete peer resets and length errors at
  response trailers preserve connection reuse for later streams,
  failed aggregate, callback, and batched request reads reclaim their held
  DATA connection credit through the shared `http2/runtime/flow` model; a
  reset batch member returns only its own credit while surviving requests
  retain their accounting and can be completed with replacement admission,
  Hyper-style default automatic server `date` generation for ordinary,
  streaming, batched, pushed, and CONNECT final responses, with explicit-field
  preservation, informational-response exclusion, and an opt-out limit,
  traditional CONNECT header-only tunnel acceptance with DATA tunnel helpers and strict `:authority`-only host:port pseudo-header rules, CONNECT body/Content-Length rules, bounded Extended CONNECT rejection bodies/trailers with stream-local cleanup, and opt-in RFC 8441 extended CONNECT / `:protocol` handling with irreversible
  SETTINGS_ENABLE_CONNECT_PROTOCOL downgrade rejection,
  open/accept/reject tunnel helpers and DATA-frame tunnel read/write mapping, RFC 7540 h2c Upgrade client/server helpers that carry `HTTP2-Settings` and receive/respond on stream 1, a blocking prior-knowledge h2c client/server runtime with default `:authority` host/port synthesis and transport/URI-derived `:scheme`, and a native TLS 1.2/1.3 client/server runtime that requires negotiated `h2` ALPN and optionally authenticates clients with application-visible verified certificate chains,
  `http://`/`https://` URI helpers with host-name DNS and IPv4/bracketed-IPv6
  literal connect support plus the same bounded RFC 3986 redirect, method/body
  replay, cross-origin credential/trailer isolation, HTTPS downgrade policy and
  whole-chain deadline contract as HTTP/1, with client certificates blocked
  and resumption tickets cleared on cross-origin hops by default; the
  authority-keyed pool exposes the same redirect API, releasing each completed
  lease before reacquiring so same-origin hops reuse HPACK/TLS state and
  cross-origin hops retain capacity, LRU, ticket, and identity policy. The
  pool also exposes same-origin URI batches: request descriptors and targets
  use bounded stack storage with exact fallbacks, all HEADERS are submitted
  through one lease before response reads, body-bearing batches round-robin
  DATA through connection/stream flow control while retaining early sibling
  responses and then commit terminal request trailers under a separate HPACK
  transaction, out-of-order streams map back to caller order, one absolute
  deadline spans admission and the complete batch, and a stale reused
  connection is retried only when every method is idempotent.
  `SharedDispatcher` adds Hyper-shaped execution ownership: one driver is the
  sole pool/frame reader, cloneable `SharedSender` handles feed a bounded
  queue, and commands with independent deadlines coalesce through the
  per-stream result observer. Senders can choose owned aggregation or
  callback-streaming final heads/DATA with owned terminal headers and trailers;
  compatible response modes coalesce without adding another frame reader. An
  expired or callback-rejected member is reset/completed, its upload cursor
  stops borrowing caller data, and only surviving streams emit request trailers
  while later siblings continue.
  Canceling an in-flight producer task sets a reusable dispatcher event; the
  driver races that event against pool-capacity admission or its sole frame
  read, preserves a concurrently completed frame, and emits target-only CANCEL
  without polling. Queued commands still unlink without wire I/O, queue
  overflow is explicit, and close wakes every queued producer,
  allocation-free HTTP/2 runtime
  SETTINGS/frame sends, and a `std.Io.async` concurrent server helper
- HTTP/3 frame headers with preallocated generic writes and direct QUIC-varint emission, transactional single-reservation SETTINGS frames with payload length reuse and exact-allocation parsing, preallocated single-varint control frames, preallocated PUSH_PROMISE/push-stream prefixes/PRIORITY_UPDATE, preallocated DATAGRAM/Capsule, and unidirectional stream prefixes with preallocated small-varint write fast paths, request/response HEADERS+DATA helpers,
  stack-first request/response/informational/Push-Promise header assembly with
  exact allocation fallback instead of a hidden 64-field descriptor ceiling,
  default automatic server `date` generation across development, protected, and
  authenticated runtimes for aggregate, streaming, pushed, and CONNECT final
  responses, with a shared allocation-free per-second cache, stack-first header
  views, case-insensitive explicit-field preservation, 1xx exclusion, opt-out
  controls, and no wall-clock dependency in the pure codec; final-response
  owners can explicitly wait with a timeout/deadline for application/control
  QUIC recovery to drain before destroying a short-lived session, without
  waiting for ACKs of replaceable receive-credit advertisements, while
  `serveConnection` applies one configurable absolute budget across both
  GOAWAY phases and the recovery drain automatically, and multi-connection
  endpoint callbacks resynchronize their send-side PTO timer after handlers;
  promoted sessions reject blocking socket-owning helpers and expose
  transactional one-attempt complete or head/DATA/trailer response paths, with
  one-attempt two-phase GOAWAY initiation/completion whose pacing failures roll
  back HTTP/3 control state and stream offsets, and a two-connection pacing-HOL
  regression; dispatcher-bound clients likewise expose transactional one-shot
  GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, and request/push PRIORITY_UPDATE control
  writes, while dispatcher-bound servers have a matching one-shot ORIGIN
  advertisement; QUIC peer-CID selection uses move-stable owned backing so
  by-value session promotion cannot corrupt later response routing,
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
  with shared host equality, canonical text, and hashing for unreserved
  percent escapes and IPv6 address aliases; reserved escapes and IPvFuture
  literals retain distinct identity across route keys and ORIGIN authorization,
  plus an indexed generic origin-keyed idle pool with empty-pool miss fast paths,
  exact-origin preference, bounded policy-filtered cross-origin selection,
  stable connection-origin ownership, canonical host hashing, and
  single-lookup release/new-origin append checks for runtime-specific
  client handles with explicit expiry pruning and targeted index repair,
  SETTINGS-first control-stream negotiation with unique peer control-stream tracking, bidirectional message-stream and non-critical extension-stream role-validation skips before preallocated control-state rollback cloning, forbidden frame rejection on control/request streams including misplaced WebTransport stream prefixes, client-initiated push-stream rejection, and prefix-driven peer-unidirectional stream classification that reassembles offset-zero type bytes before routing control/QPACK/push streams or draining unknown reserved types, without assuming fixed critical stream IDs; stateful routing returns consumed control/QPACK/unknown bytes to both QUIC receive windows, retires terminal unknown streams to restore MAX_STREAMS credit, while push streams return their fragmented association prefix exactly once before preserving application DATA backpressure, preserves reordered WebTransport 0x54 prefixes on both roles, and failed MAX_DATA/MAX_STREAM_DATA writes retry from the connection timer with fair MTU-bounded multi-stream credit coalescing; QPACK encoder/decoder critical stream registration with duplicate-stream `H3_STREAM_CREATION_ERROR` plus FIN/RESET_STREAM/STOP_SENDING closure rejection, RFC 9204 dynamic-table FIFO/absolute-relative indexing/eviction state, Required Insert Count wrapping, checked prefix-integer decoding through the maximum `usize` with bounded wider-value rejection, preallocated/assume-capacity varint writes plus transactional single-reservation field-section prefixes and Encoder Stream instructions, all relative/post-base dynamic field-line forms with blocking/eviction distinction and never-indexed preservation, Huffman-capable encoder with reused length prechecks/exact slice allocation and direct-to-target byte emission plus preallocated decoder with empty-input fast paths, instruction codecs with preallocated instruction and field-section literal-name writes, a connection-scoped decoder with out-of-order/split encoder-stream reassembly plus preallocated coalesced feedback, and a non-blocking encoder state with Known Received Count gating, decoder-stream reassembly, single-pass outstanding reference accounting with adjacent duplicate fast paths, empty-reference eviction checks, single-probe pending-section indexing with empty-index skips, tail-release fast paths, and prohibited-eviction prevention, GOAWAY and MAX_PUSH_ID monotonicity checks plus post-GOAWAY request suppression/rejection, cached multi-set drain-floor checks, and same-control-stream GOAWAY emission with persistent control-stream offsets,
  collision-verified hash indexes with single-lookup dynamic insert tracking for current QPACK exact/name matches with
  zero-reference lookup/encoding short-circuits, stack-planned transactional single-reservation static blocks with allocation-free ASCII name normalization and never-indexed preservation across exact-static/name/literal representations, plus preallocated empty/short-string write fast paths, restricted-reference scan
  fallback, O(1) FIFO eviction index retirement, and indexed QPACK static-name
  lookups with pseudo-header and common-header fast paths,
  CANCEL_PUSH/PUSH_PROMISE/MAX_PUSH_ID/PRIORITY_UPDATE payload codecs with malformed-payload rejection, generic-frame rejection of the lengthless WebTransport `0x41 + Session ID` prefix, indexed per-ID control-state lookups with empty-index skips, identical priority-update skips, and single-probe priority replacement, and advertised MAX_PUSH_ID enforcement for received PUSH_PROMISE frames,
  RFC 9218 Priority field parsing/serialization,
  request/response message encoding/decoding with ordered HEADERS/DATA/trailer handling, static or dynamic QPACK field-section decoding with indexed per-stream Section Acknowledgment/cancellation accounting with targeted index repair and prefix-skipping cancellation compaction, transactional dynamic field-section output/reference rollback, non-blocking Known-Received dynamic writers for request/response/interim/trailer sections with sensitive-field exclusion and speculative future inserts, inbound and outbound SETTINGS_MAX_FIELD_SECTION_SIZE enforcement, exact post-assembly and incremental receive signaling (`QPACK_DECOMPRESSION_FAILED` connection closes for malformed QPACK, connection closes for invalid frame sequences including control-only ORIGIN or misplaced WebTransport stream frames, and stream-local `H3_MESSAGE_ERROR` cancellation for malformed HTTP semantics while siblings remain usable), connection-wide enforcement of the locally advertised QPACK blocked-stream budget across buffered aggregate streams, active incremental readers, and push streams (including a zero-budget first dependency), constant-space client completion history using the shared HTTP/WebTransport bidirectional stream-ID allocation frontier rather than one tombstone per completed request, full aggregate, incremental, and detached-head PUSH_PROMISE request-field decoding with dynamic-section feedback, transactional aggregate and incremental request/response/push event admission with retryable local preflight failures, promise registration only after validation, queued QPACK feedback after send failures, and allocation-safe cleartext aggregate request ownership transfer, bounded ordered interim 1xx response observation on aggregate and incremental client paths, request-stream correlation for aggregate multiplexed reads, push-ID/parent-request/push-stream correlation for aggregate pushed responses, per-stream bounds for multiplexed and pushed responses, runtime emission before final and pushed responses, terminal 500 fallback with per-request `InvalidStatus` reporting when a high-level handler returns 1xx as its final response, and forbidden trailer-field rejection,
  incremental handshake-client response polling with retained stream-local
  cancellation across socket failures, backpressure and receive deadlines,
  healthy sibling response progress, and explicit `ResponseEventResult` failure
  ownership transfer through `pollNextResponseEventOnceWithFailure`,
  suspended readers after explicit request/response failure transfer and
  server cancellation credit reclamation across RESET ACK and late upload FIN,
  shared handshake request/response DATA access with retained Content-Length
  cancellation, scoped truncated-frame errors and consumed-byte counts that
  survive receive-credit socket failures,
  incremental pushed-response failure retention with parent-request isolation,
  scoped STOP_SENDING/QPACK retry and explicit `PushEventResult` ownership
  through `pollPushEventOnceWithFailure` and `tryRejectPush`,
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
  rechecks known QUIC final sizes before DATA reads and skips, including FIN
  arriving after partial delivery: final Content-Length mismatches cancel only
  the affected request or push with `H3_MESSAGE_ERROR`, while truncated frames
  close with `H3_FRAME_ERROR`,
  and a connection-scoped receive-owner guard across development, protected,
  and authenticated client informational callbacks: recursive response, push,
  control, raw-development-stream, or CONNECT-DATAGRAM reads fail locally with
  `ConcurrentRead` before advancing buffered or socket state, while explicit
  one-attempt send-only operations remain available; request/push cancellation
  and association teardown are also deferred or rejected during the callback
  so they cannot invalidate the aggregate reader that owns the borrowed head,
  HTTP/3 pseudo-header/lowercase field-name, `:method` token validation with case-sensitive CONNECT/OPTIONS semantics, SETTINGS-gated `:protocol` token, URI scheme/origin-form path/authority, Host/`:authority`, traditional CONNECT body rules, and connection-specific header validation,
  DATA-frame aggregation, pure-digit content-length, three-digit `:status`,
  status-forbidden response-body validation, sender-side empty-content
  enforcement for 205 without changing DATA/FIN receive framing, and request-aware HEAD/traditional
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
  tooling. The shared HTTP layer also exposes a thread-safe, origin-keyed
  `http.AltSvcCache`: it applies RFC 7838's 24-hour default max-age, peer `ma`
  expiry, `ma=0`, `clear`, replacement without HTTP/3, configurable entry and
  max-age bounds, true LRU eviction, and exponential QUIC failure backoff.
  Refreshing the same target preserves its backoff so a TCP response cannot
  make every request retry a broken UDP path. Each retained entry stores its
  origin and target strings in one contiguous allocation, and each concurrent-
  safe lookup clones one independent contiguous snapshot instead of three
  separate strings. The handshake client provides
  bounded authenticated URI redirects with RFC 3986 resolution,
  QPACK credential/representation cleanup, method/DATA/trailer replay policy,
  fresh QUIC CIDs and ephemeral handshake inputs per hop, cross-origin
  client-identity/resumption isolation, final-URI metadata and one deadline
  across the complete chain. The exclusive authenticated client pool exposes
  the same ordinary, detailed, timeout, and absolute-deadline redirect forms;
  every completed hop releases its lease before the next URI is acquired, so
  same-origin redirects immediately reuse QPACK/QUIC/TLS state while
  cross-origin hops retain capacity/LRU policy and clear origin-bound default-
  connector state. The exclusive pool also accepts an explicit Alt-Svc route
  for acquire and complete-request timeout/deadline APIs: it keys reuse by the
  original origin, authenticates SNI/certificates and emits `:authority` for
  that origin, while dialing only the advertised alternative host and port.
  The single-UDP-owner shared pool provides matching
  `beginUriFollowingRedirects*` transactions: they replay multi-packet bodies,
  consume only their current connection/stream events, and leave unrelated
  response, push, and unrouted events caller-owned. The same shared pool now
  accepts explicit Alt-Svc acquisition with relative or absolute deadlines:
  DNS/UDP uses the advertised target while SNI, certificate validation,
  origin+ALPN ticket collection, pool identity, and request authority remain
  bound to the original URI. Idle reuse prefers the exact origin, then permits
  cross-origin selection only with both RFC 9412 authorization and retained
  leaf-certificate DNS/IP coverage. Coalesced leases retain a separate request
  origin, expose a fail-closed 421 observation hook, and keep the authenticated
  connection origin stable across release. `PreparedEarlyRequest` plus
  `HandshakeClient.connectWithEarlyRequest` provide a typed one-request 0-RTT
  path: the owned offer carries a complete literal/static-QPACK request and
  the mandatory SETTINGS/QPACK critical-stream prefixes, reports accepted
  versus rejected without automatic application replay, restores the accepted
  request's response semantics and stream cursors, routes server-side early
  bytes before the first blocking read, and rejects reduced remembered peer
  SETTINGS. RFC 8470 safety is enforced before allocation or ticket use:
  `PreparedEarlyRequest.init` accepts only registered safe methods, while
  `initWithOptions(... allow_unsafe_replay)` makes application acceptance of
  POST/PUT/CONNECT/custom-method replay risk explicit. Accepted server-side
  request provenance remains visible as `was_early_data` on aggregate
  `OwnedHandshakeRequest`, every streaming request message, and the final
  `OwnedEndpointRequest`, so handlers can return 425 or apply application-level
  anti-replay policy. The marker stays true when 1-RTT continues an early
  stream, remains false for independent 1-RTT streams, and rejected 0-RTT never
  enters request state. `HandshakeClient.requestWithEarlyData*` closes the
  RFC 8470 client loop: TLS-rejected requests and accepted requests answered
  with 425 are replayed exactly once after the handshake over 1-RTT, while a
  second 425 is returned without a retry loop. Results distinguish
  transport rejection from 425, and one absolute deadline covers handshake,
  initial response, and replay without renewing the budget. Zero timeout fails
  before allocation, ticket consumption, packet-number use, or socket I/O.
  The lower-level `connectWithEarlyRequest*` family now also provides relative
  and absolute handshake bounds. The endpoint handler supervisor applies an
  optional `allow`/`reject`/`inspect` replay-risk policy at request HEADERS,
  before scheduling application code or copying DATA. A 425 admission drains
  the remaining body and trailers directly through receive-window credit,
  queues the HTTP response only after request FIN, and never invokes the
  business handler; ordinary 1-RTT requests bypass the inspector. Both server
  paths retain
  indexed bounded per-request-stream reassembly state
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
  enforces the configured concurrency bound. Authenticated clients also expose
  an owned-response batch with per-request absolute deadlines and optional
  cross-task cancellation. Terminal results retain caller indices despite
  reversed completion; an expired or actively canceled member sends only its
  own H3_REQUEST_CANCELLED while siblings continue under their original
  budgets. The cancellation event races the sole response read and preserves a
  response that completes on the same handoff. Successful response ownership
  transfers through the observer, while a connection failure is reported to
  every unfinished member. Protected clients and servers also
  expose `startRequest`/`sendRequestBody` and
  `startResponse`/`sendResponseBody`, preserving per-stream QUIC offsets across
  multiple DATA chunks with empty-open/finish lookup skips, single-lookup chunk accounting plus cached FIN cleanup and enforcing declared Content-Length at FIN.
  Handshake-backed clients and server sessions additionally expose
  timeout/deadline-bounded `startRequest` and `startResponse` variants whose
  single budget covers stream admission, SETTINGS/QPACK, HEADERS, pacing, and
  flow-control progress; successful Extended CONNECT server admission uses the
  same budget for receive-credit preparation, response HEAD delivery, and
  WebTransport request-reader detachment before ownership transfer, plus
  negotiated TLS cipher-suite/transcript-hash metadata and QUIC key-update
  control/counts,
  bounded `serveOne`/`serveConnection` request-response loops with automatic
  paced aggregate responses and two-phase GOAWAY completion, and expose
  `sendRequestBodyBatchPaced`/`sendResponseBodyBatchPaced`: one DATA
  contribution per stream is packet-size checked, protected through the
  stateful QUIC batch path, and committed only for the socket-visible prefix,
  with isolated DATA-prefix storage for recovery-safe borrowed payloads. The
  scheduler accounts for HTTP/3 DATA framing exactly against QUIC stream and
  connection flow credit while retaining a separate conservative packet
  margin for congestion and datagram limits, so even three-byte window updates
  can make forward progress without overfilling the transport.
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
  validation, prepared reset-record fast paths, and no full-body aggregation.
  Aggregate server requests decode a complete head as soon as it arrives and
  send `100 Continue` before waiting for an expected body; streaming request
  events apply the same rule. When UDP_GRO is enabled, protected
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
  state with monotonic advertisement, exact prefix-plus-sparse-range cancellation
  history, local STOP_SENDING of active cancelled pushes,
  and advertised-range validation. Servers reject cancellation of an ID they
  never promised with `H3_ID_ERROR` before retaining cancellation state.
  Streaming response readers decode PUSH_PROMISE into owned promised-request
  heads before, between, or after response frames, including after trailing
  HEADERS as RFC 9114 permits; they preserve the push ID, enforce the advertised
  limit, and account dynamic QPACK section feedback instead of discarding
  promised fields like the current reference runtimes. Push promise registration uses single-probe
  indexes, push stream insertion/binding reuse one map probe, empty-index targeted push lookups/removals, and protected and handshake runtimes also bind
  reordered server-initiated push streams to indexed promises, expose indexed targeted
  streaming and owned aggregate pushed-response APIs, including
  `receivePushWithInformational` callbacks correlated by push, parent request,
  and push-stream IDs, and can emit PUSH_PROMISE plus the corresponding
  unidirectional pushed response (with optional informational heads) with
  shared dynamic QPACK state. Authenticated and protected servers additionally
  expose `sendResponseWithPushPaced*`: parent/push heads are committed first,
  then the pushed DATA/trailers and any parent body advance in bounded chunks
  (push first, so a parent body cannot starve its advertised resource) instead of requiring a
  complete pushed body to fit current QUIC credit. The authenticated path
  observes `CANCEL_PUSH`/`STOP_SENDING` between chunks, resets and retires the
  push stream without closing the connection, discards already in-flight
  post-cancellation STREAM data without recreating a bounded push reader, and
  uses one absolute deadline
  across settings, heads, flow-control progress, DATA, and trailers. There is
  also a
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
  shared unary/streaming/duplex fallback mapping with owned diagnostics for
  missing or malformed status, tolerant percent-encoded `grpc-message` handling,
  owned `google.rpc.Status` error details with opaque `Any` iteration,
  status-consistency validation and dedicated unary/streaming/gRPC-Web output,
  request content-type/TE/method-path/custom-metadata validation, unpadded binary
  metadata Base64 sending with padded/unpadded/comma-joined receive support,
  standard ORCA per-RPC backend load reports in
  `endpoint-load-metrics-bin`, with bounded protobuf decoding, exact metadata
  ownership, validated utilization values and named metric maps,
  plus typed ORCA OOB request/client/server streams with protobuf Duration,
  request-cost selection, incremental owned reports, per-read deadlines and
  stream-local cancellation under explicit single-owner multiplexing,
  with optional SharedChannel per-endpoint background ownership, bounded
  latest-value fan-out, explicit unavailable/unimplemented/shutdown states,
  automatic transport reconnect and coexistence with Health, keepalive and
  business RPCs,
  strict allocation-free RFC 6750 Bearer metadata parsing, constant-time token
  comparison, a caller-buffer client field constructor that always requests
  HPACK Never Indexed across unary and streaming calls, and a server helper
  that returns trailers-only
  `UNAUTHENTICATED` while preserving the HTTP/2 channel for later RPCs;
  duplex servers can apply the same check immediately after request HEADERS,
  before reading DATA, and then boundedly drain a rejected upload;
  `authorization` remains automatically HPACK never-indexed,
  strict per-message gzip and RFC 1950 zlib-wrapped `deflate` codecs backed by
  a package-local focused encoder and Vort's bounded decompression, typed
  `grpc-accept-encoding` negotiation, asymmetric request/response algorithms,
  and gRPC Core-compatible fallback when compression does not shrink a message,
  lazy reconnecting channels with explicit/service-config wait-for-ready,
  one deadline spanning connection readiness and the RPC, upstream-compatible
  jittered connection backoff, cancel/reset controls, and no implicit replay
  after an RPC reaches a transport,
  pre-resolved multi-endpoint pick-first and READY-only round-robin selection
  with per-endpoint backoff, bounded warming, optional pick-first shuffling,
  and standard service-config load-balancing selection; hostname Channels use
  an asynchronous system or injected resolver, preserve unchanged ready
  subchannels across address updates, retain healthy addresses across resolver
  failures, expose explicit refresh plus connectivity state, and provide
  generation-stamped concurrent watches that survive Channel shutdown,
  dedicated client Health Watch with automatic reconnect/backoff, bounded
  setup and resumable reads, SERVING waits and UNIMPLEMENTED disablement,
  standard healthCheckConfig parsing with configured/explicit service selection
  and allocation-free disabled Watch construction,
  same-connection client Health Watch and business duplex streams driven by
  one owner, with independent framing/compression and sibling cancellation,
  a shared HTTP/2 frame pump with command wakes and gRPC/Health event polling
  for owners that schedule multiple active streams,
  background shared unary channels with cloneable send handles, per-endpoint
  workers, same-connection Health Watch admission, ready endpoint selection,
  dynamic DNS address membership with connection/health retention and draining
  retirement, including independent hostname sources in resolved targets,
  shared streaming/duplex Writer and Reader capabilities with concurrent
  directions, bounded encoded input, consumption-driven stream credit,
  per-message compression, half-close, and cancellation/retirement joins,
  owned service config and cancellation/join before caller return,
  stream-level encoding with per-message compression opt-out on sequential and
  duplex client/server writers,
  plus unary and sequential request/response message-stream h2c client/server
  helpers with opaque protobuf payloads, listener/HTTP2-bootstrap and request
  timeout/deadline entry points, initial/trailing metadata,
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
  only a lazy integration dependency. The bidirectional h2c/TLS gRPC C++
  process gates run the netz endpoints on zio-backed `std.Io` and identify the
  pinned Linux peer as `grpc-cpp-posix-event-engine`; they cover upstream's
  canonical compressed-unary and compressed-streaming probes plus gzip/identity
  request and response messages in both endpoint directions, plus exact unary
  and bidirectional status/message propagation including Unicode and control
  whitespace, and trailers-only `UNIMPLEMENTED` results for both unknown
  methods and unknown services. They also cover canonical empty and 271828-byte
  request/314159-byte response unary calls, plus cancellation immediately
  after request metadata and after the first response, and half-duplex buffering
  that emits four ordered responses only after request END_STREAM. The canonical
  slow-consumer case drives 2000 responses through HTTP/2 flow control while
  the application reads one every 20 ms; a 100-iteration large-unary RPC soak
  additionally verifies persistent-channel stream retirement. A matching
  100-iteration channel soak recreates TCP/TLS/ALPN/certificate state for every
  large unary RPC. An authenticated EmptyCall additionally carries Bearer
  metadata from grpc-cpp to netz over both h2c and TLS. The canonical
  `orca_per_rpc` case is also bidirectional: netz emits reports consumed by
  grpc-cpp's backend-metrics policy and decodes reports emitted by grpc-cpp,
  over both h2c and verified TLS. The canonical `orca_oob` case additionally
  drives a long-lived report stream beside a business duplex RPC, applies and
  observes two server metric updates, and cancels only the OOB stream in both
  endpoint directions over h2c and verified TLS. A separate official-server
  SharedChannel gate verifies background OOB admission and two independent
  report watchers without weakening the exact keepalive ACK gate. The official reflection
  and generated-pbz gates also use zio, with the pbz server scheduled through
  `std.Io.async`. The server-side `grpc.channelz.v1` registry exposes paginated
  top channels and servers, per-entity call counters, connectivity state, and
  the standard unary admin methods; `channelz.serve` maps protocol errors to
  gRPC status and leaves unrelated paths to the application dispatcher.
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
  ClientHello/ServerHello flights, incremental negotiated-hash transcript
  snapshots across both roles' Certificate/Finished/key-derivation boundaries,
  client-carried Initial address tokens,
  server-side token validation hooks, and server-issued address-validation
  NEW_TOKEN frames, preallocated coalesced Initial+Handshake CRYPTO datagram helpers,
  bounded RFC 9002-style exponential PTO retries for synchronous client
  Initial/0-RTT and server Initial+Handshake flights with fresh packet numbers,
  exact protected-versus-socket-sent flight progress, pre-protection MTU/range
  validation, allocation-free long-header sealing after one batch reservation,
  and nonce-safe PN gaps after zero/partial socket writes, including batched
  1-RTT PTO probes whose unsent sealed suffix is removed from recovery while
  its packet numbers remain retired,
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
  injection, suppresses 0-RTT replay, and preserves an explicit rejected
  early-data disposition across Version Negotiation without carrying old-key
  packet numbers into the replacement version, plus an integrated server Retry policy
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
  receive-frame semantic preflight before multi-frame side effects with
  shape-specific single-STREAM and single-DATAGRAM validation, preallocated
  single-byte, single-, double-, triple-varint, fixed PATH, ACK_FREQUENCY,
  variable-payload, CRYPTO, STREAM, DATAGRAM, NEW_CONNECTION_ID, and close
  frame writes, and direct adaptive truncated packet-number
  encoding wired into 1-RTT ACK/STREAM exchange, indexed stream send/receive state with pre-reserved assume-capacity STREAM frame batches, preallocated receive-state clones, and empty non-FIN send no-ops, single-lookup flow creation and empty-index lookup skips,
  zero-consume skips, contiguous duplicate-overlap fast paths, conflict detection, offset reassembly, FIN, RESET_STREAM final-size validation, and STOP_SENDING
  to RESET_STREAM response handling,
  draft-ietf-quic-reliable-stream-reset-09 negotiation and RESET_STREAM_AT
  codec/state/recovery support, including 0-RTT capability memory, decreasing
  Reliable Size, reliable-prefix retransmission, and WebTransport delivery
  before the terminal reset event; the real-handshake WebTransport churn gate
  exercises both ordinary and reliable reset under deterministic loss and
  packet reordering,
  RFC 9221 QUIC DATAGRAM negotiation limits with 1-RTT send helpers,
  MTU-bounded multi-frame batch packing with exact logical-prefix progress,
  configurable receive queues plus caller-buffer single and up-to-64-item
  blocking/timeout/deadline reads, synchronous borrowed batch visitation for
  zero-copy application inspection, automatic
  pending-ACK coalescing on single DATAGRAM sends, max-payload calculation,
  queue overflow/drop counters, and
  oversized/disabled DATAGRAM rejection,
  RFC 9287 `grease_quic_bit` transport-parameter negotiation with strict
  pre-negotiation fixed-bit validation, negotiated zero-bit receive routing,
  and connection-seeded unpredictable 1-RTT QUIC Bit emission,
  draft ACK_FREQUENCY and IMMEDIATE_ACK frame codecs with `min_ack_delay`
  transport-parameter negotiation and opt-in 1-RTT state updates for requested
  ACK threshold/max-delay/reordering behavior, directional capability checks,
  optional peer-gated automatic requests appended to the first non-empty 1-RTT
  packet (alongside HANDSHAKE_DONE when required), socket-commit-safe pending
  state and ordinary PTO recovery, optional caller-selected Requested Max Ack
  Delay with conservative in-flight/confirmed PTO accounting,
  RFC 9002 initial application-data PTO including initial RTT variance and the
  effective peer ACK delay,
  wire-tolerance-to-local-trigger conversion,
  Quinn-style IMMEDIATE_ACK hints on negotiated PTO probes with exact-MTU
  fallback and non-retransmittable per-probe ownership,
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
  credit polling for shared-endpoint loops reserves bidirectional or
  unidirectional IDs only when credit is already present, without reading the
  UDP socket, waiting, emitting STREAMS_BLOCKED, or advancing a blocked cursor;
  handle-based dispatcher variants keep the aggregate timer index synchronized;
  complete contiguous STREAM writes can use `sendStream`,
  `sendStreamWithTimeout`, or `sendStreamWithDeadline` to consume positive
  connection/stream credit tails, split by exact packet size and congestion
  budget, and report the exact socket-visible prefix through `committed_out`
  on timeout or network error; the matching `sendStreamSlices*` forms packetize
  borrowed scatter/gather payloads across slice and MTU boundaries without a
  join allocation, filling each fair single-packet submission across adjacent
  slices with the same logical-prefix and final-FIN contract;
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
  sender that consumes a ticket after the first protected 0-RTT packet and
  skips its nonce even when the UDP socket reports zero progress,
  plus automatic TLS early_data signaling, ClientHello-bound early traffic
  keys, coalesced Initial+0-RTT sending, explicit server acceptance/rejection,
  a typed complete-request helper that emits the mandatory HTTP/3
  control/QPACK stream prefixes, explicitly reports acceptance versus replay,
  restores response method semantics and stream cursors after acceptance, and
  rejects reduced remembered peer SETTINGS before consuming a response; the
  server preserves accepted early STREAM provenance through aggregate,
  incremental, and endpoint-handler request ownership so replay-sensitive work
  can receive 425 without classifying requests from stream IDs. High-level
  early-data requests automatically replay TLS rejection or the first 425 only
  after 1-RTT is installed, preserve the complete request, and return a second
  425 instead of looping,
  bounded thread-safe replay gating, remembered-parameter enforcement, and
  application packet-number/flow/recovery state continuity after key install,
  including sparse import that advances past every protected 0-RTT nonce while
  tracking only packet numbers actually handed to the socket,
  plus integrated TLS 1.3 PSK-DHE resumption with origin/ALPN/age-bound owned
  sessions, mandatory-last multi-identity `pre_shared_key` offers, constant-time
  index-aligned binder verification, later-identity selection, 0-RTT binding to
  identity zero, unknown-identity full-handshake fallback, and matching-identity
  bad-binder rejection,
  post-handshake NewSessionTicket issue/parse over 1-RTT CRYPTO, transcript-
  bound resumption PSK derivation, indexed bounded owning server ticket storage with cached LRU eviction, earliest-expiry scan skips, empty-store lookup skips, and single-lookup issue insertion,
  client cache insertion, and origin+ALPN automatic ticket selection on both
  sides of the next connection,
  plus allocation-free AES-256-GCM stateless tickets with origin+ALPN
  associated-data binding, explicit key IDs, current+three-history key
  rotation, tamper/expiry enforcement, and a native seal/open benchmark,
  Vail-backed non-PSK TLS 1.3 server authentication with Certificate and
  Ed25519/ECDSA-P256/ECDSA-P384 CertificateVerify signing and verification,
  stream-server compatibility ChangeCipherSpec emission after ServerHello for
  Zig standard TLS clients while OpenSSL/rustls peers ignore it per RFC 8446,
  RSA-PSS/RSAE and RSA-PSS/PSS SHA-256/SHA-384/SHA-512 X.509
  CertificateVerify verification, pinned raw-key
  verification or an application X.509 trust-policy callback, transcript/signature tamper
  rejection, and optional mutual TLS with CertificateRequest plus client
  possession proof,
  together with Vail's zero-allocation X.509 chain/hostname/time verifier over
  caller, system-root, platform-native, or compiled-in Mozilla trust, its system-CA loader for production clients,
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
  short-header spin-bit preservation plus an opt-in RFC 9000 per-path spin
  policy available to direct and handshake-created connections, with
  highest-packet-number filtering, reset on destination-CID changes, and
  independent 1-in-16 handshake suppression,
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
  indexed single-lookup endpoint-level timer scheduler with exact-update and
  monotonic-earliest skips, empty-index and no-op service skips, plus
  terminal-state filtering that prevents stale ACK/recovery timers from
  outranking close lifecycle work, and unarmed-connection service skips for
  multi-connection loops, and a pointer-only handshake completion queue that
  constructs established connections in their final stable allocation instead
  of copying multi-kilobyte state through the shared endpoint, with idle
  completion polling and handshake-deadline wakeups disabled once no workers
  remain, and
  peer-address validation hooks with RFC 9000 3x anti-amplification send
  budget enforcement for unvalidated server paths,
  1-RTT key-update derivation and key-phase state with ACK gating and retained
  previous receive/send generations for reordered short-header packets, peer-triggered
  send-key synchronization before ACK, cached ACK-gate clearing for local
  key updates, and negotiated-suite RFC 9001
  confidentiality/integrity limits with proactive key rotation and terminal
  limit handling,
  configurable RFC 9438 CUBIC (default) and NewReno congestion-window control with zero-byte reserve/ACK/loss/PTO accounting no-ops,
  RFC 9002 protected-packet bytes-in-flight send admission wired into 1-RTT
  sending and ACK/ACK_ECN processing,
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
  send pacing with configurable burst/disable controls and an optional explicit
  bytes-per-second ceiling that can be retuned on an established connection
  without repricing already earned credit, public effective-rate/configured-
  ceiling statistics, qlog pacing-rate emission, zero-packet sent no-ops, current-budget deadline skips, full-budget arithmetic skips, exact retry deadlines,
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
  submission maps same- or heterogeneous-destination messages to Linux
  `sendmmsg` through Zig `std.Io`, with allocation-free address descriptors,
  exact prefix progress, paced two-probe PTO batches, and nonce-safe
  partial-send recovery, plus zero-copy
  Linux `UDP_SEGMENT` offload for
  contiguous equal-sized packet batches with one-shot capability fallback and
  opt-in Linux `UDP_GRO` receive coalescing with shared zero-copy segment
  ownership or caller-buffer batch views, reusable 1-RTT packet-codec scratch,
  direct recovery-payload encoding, direct mixed-frame encoding into final
  protected-packet storage, handshake-scoped reusable datagram receives whose
  allocation transfers into established 1-RTT receive scratch, in-place
  current-key 1-RTT decryption, and bounded non-GRO multi-datagram receive
  cursors that amortize zio socket waits and one monotonic clock sample across
  each kernel receive batch while exposing only one packet at a time to HTTP/3,
  preserving any datagrams already dequeued when a later batch-drain receive
  reports an error,
  strict wire-order low-peak batch servicing, and bounded power-of-two
  recovery-payload reuse with allocation-free ACK-time recycling, four direct
  per-class slots, payload-intrusive overflow free lists, and a global
  idle-byte cap that lets the active size class absorb a complete ACK burst,
  plus implicit dense-prefix STREAM receive tracking that allocates packed
  presence words only after reordering creates a gap,
  endpoint-level connection-ID routing with single-probe registration and empty-length unregister skips,
  max-length-cached short-header dispatch with validated-key construction, empty-length long-header skips, unroutable zero-DCID long-header drops and static-key token derivation primitives for stable multi-connection
  demultiplexing wired into raw UDP receive routing and 1-RTT connection
  delivery, including peer-path binding and active-migration-disabled route
  rejection, NEW_CONNECTION_ID receive/send active-limit, single-pass receive/send duplicate-CID/reset-token validation, in-use-count-gated zero-copy stateless-reset token slice matching, and cursor-backed RETIRE_CONNECTION_ID lifecycle/preflight state with NEW/RETIRE CID-error close mapping wired into
  1-RTT, draft-ietf-quic-load-balancers-21 QUIC-LB CID generation/routing
  extraction with validated config rotation/lengths, Appendix B single-pass and
  nibble-correct four-pass AES vectors, caller-provided nonce entropy, and
  transactional local-CID/reset-token issuance,
  fatal TLS handshake alerts carried by Initial/Handshake CONNECTION_CLOSE
  with ALPN `0x178`, peer transport-parameter close codes, fresh packet numbers,
  server anti-amplification accounting and close-aware CRYPTO receive loops,
  bounded failed-handshake closing/draining CID routes with cached close replay,
  response rate and amplification limits, three-PTO expiry, admission-time
  allocation and deadline-bounded worker-completion polling,
  transport/application CONNECTION_CLOSE state including frame-payload, ACK, ACK_FREQUENCY negotiation, DATAGRAM negotiation, stream-limit/state/flow-control/final-size/data-conflict, server-only frame, and selected semantic error close emission, indexed PATH_CHALLENGE/PATH_RESPONSE validation state with preallocated clone copies and empty-outstanding challenge/response lookup skips, single-lookup duplicate challenge/response suppression, and caller-storage batch drains/sends wired into 1-RTT,
  including one invariant payload-limit calculation per DATAGRAM batch while
  ordinary packet-number ranges skip duplicate packet-plan materialization
  while boundary widths and exhaustion retain exact pre-send validation,
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
  caller-queryable diagnostics that never roll back network state; connection
  observation also preserves monotonic qlog order across explicit nanosecond,
  internal awake-clock, and millisecond close timestamps, plus a
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
- WebSocket handshakes with Host authority, list-aware HTTP/1 Upgrade/Connection validation, bidirectional HTTP/1 101 framing-field rejection, duplicate-subprotocol and nonce validation, single-reservation transactional HTTP/1 server handshake encoding, shared HTTP/1/RFC 8441 header policy isolated under `runtime/handshake`, HTTP/1 client attempts that preserve rejected status/headers/trailers/bounded body while legacy connect helpers retain `InvalidResponse`, two-phase TCP/Unix/WSS server admission that exposes path, headers, and authenticated TLS metadata before 101 and can accept with custom fields or return a closing 3xx-5xx response, plus RFC 8441 per-stream pending admission that exposes CONNECT metadata before 200 and can accept with custom fields or reject without closing sibling HTTP/2 streams, frame masking, strict frame/control
  validation including control/continuation RSV rejection, checked frame-header-plus-payload sizing across allocating, caller-buffer, HTTP/1, HTTP/2, and HTTP/3 receive paths, and transactional RFC-bounded 63-bit payload lengths across contiguous and multi-slice writers, typed close-frame parse/write helpers and close payload checks, fragmented message assembly with aggregate
  message-size limits, automatic active-state PING→PONG and close echo/completed-close short-circuit handling plus tungstenite-style data-send/read suppression after receiving Close, deadline-aware frame reads and bounded graceful-close waits that surface peer close details without discarding in-flight application frames,
  caller-buffer frame/message receive for allocation-free uncompressed
  persistent echo loops plus compressed-message output directly into caller
  storage with reusable per-connection wire/history scratch across HTTP/1 and
  RFC 8441 HTTP/2, plus explicit mutable-buffer in-place client masking for applications
  that accept the same post-send mutation contract as websocket.zig,
  arbitrary-slice text and binary single-frame sends with cross-slice UTF-8
  validation and opcode-matched partial-write resumption,
  outbound text/close/control-frame validation plus codec-level invalid-frame write rejection,
  unique and null-member-tolerant subprotocol-offer validation with RFC-compliant optional server selection and opt-in required-selection policy, split-header subprotocol and extension negotiation with complete request/response RFC 6455 list and token/quoted-token grammar validation even when compression is disabled and RFC 7692-compliant decline-and-continue handling for well-formed unsupported offers, optional permessage-deflate negotiation with
  RFC 7692 client responses checked against the exact HTTP/1, RFC 8441, or RFC 9220 offer, including fail-closed `client_max_window_bits` authorization, its offered-value hint semantics, and the hard `server_max_window_bits` bound,
  default no-context-takeover plus explicit HTTP/1 context-takeover opt-in,
  transactional RFC 7692 sync-flush raw-DEFLATE encode/decode, retained
  independent send/receive codec scratch, actual LZ77/Huffman wire compression
  with SIMD longest-match prefix scans within contiguous input spans, including
  independently advancing discontiguous fragment cursors without joining
  plaintext, and uncompressed fallback when compression expands the message,
  plus quoted/quoted-pair window-bit parsing and rejection of
  unsupported extension parameters/window sizes, framed 101 upgrade responses,
  compressed fragmented sends that stream discontiguous plaintext directly
  into DEFLATE with constant-space cross-fragment UTF-8 validation,
  owned frame allocation retries that preserve buffered wire bytes and the
  prior fragment/UTF-8 cursor across HTTP/1, HTTP/2, and HTTP/3, including a
  partially validated frame retained by an earlier receive timeout, message
  assembly and final decompression retries that retain accepted fragments,
  restore masked frame bytes and commit compression history once, plus
  batched secure-random fills that retain a fresh mask key per frame without a
  CSPRNG backend call per fragment; bounded H1 masked and unmasked fragment
  sequences also share one transport submission instead of one write per
  frame. Connection writes remain serialized, with a blocking TCP
  client/server runtime over HTTP/1 Upgrade, Unix-domain listener/client
  transports using the same handshake and framing state machine, optional absolute WS/WSS
  opening-handshake deadlines, shared absolute TLS 1.3 handshake budgets for
  WSS listeners and client-identity connections, and a `std.Io.async` concurrent
  server helper, `ws://`/`wss://` URI helpers with userinfo rejection, host-name DNS and IPv4/bracketed-IPv6 literal connect support plus
  Host/port synthesis, and cleartext HTTP-proxy CONNECT helpers for both WS and
  WSS whose caller-owned deadline spans proxy DNS/TCP, CONNECT, origin TLS and
  Upgrade while proxy-only headers remain isolated from the origin handshake,
  plus bounded HTTP redirect following with RFC 3986 relative-Location
  resolution, loop detection, one whole-chain deadline, proxy retention,
  authenticated WSS revalidation, default WSS-to-WS downgrade rejection, and
  cross-origin Upgrade-header/client-certificate isolation. Redirect options
  can attach the shared HTTP CookieJar: every WS/WSS hop derives Cookie from
  its actual URI, consumes intermediate/final Set-Cookie before Location,
  rejects an ambiguous caller Cookie field, treats cross-origin as cross-site
  unless explicitly proven otherwise, preserves proxy header isolation, and
  prevents Secure WSS cookies from reaching WS,
  while RFC 8441 and RFC 9220 client attempts accept the same Jar through
  `CookieHandshakeOptions`, emit its Cookie field as HPACK/QPACK Never Indexed,
  and commit Set-Cookie from both accepted and rejected final responses.
  H2 derives Cookie scope from its transport-resolved `:scheme` plus the actual
  `:authority`/`:path`; H3 derives it from its HTTPS authority/path or parsed
  URI. Callers therefore cannot bind a Jar lookup to a different host or Path.
  Invalid authority/path and caller Cookie/Cookie2 conflicts fail before
  request I/O,
  shared verified TLS client transport plus opt-in
  Ed25519/ECDSA/SM2 client identities, native TLS 1.3 WSS listeners with
  optional client authentication and concurrent serving, and RFC 8441
  WebSocket-over-HTTP/2 adapters with per-stream two-phase server admission and
  client attempt results that preserve non-2xx status/headers/bounded body/trailers, plus equivalent
  RFC 9220 client attempts (including caller-owned session restoration after a
  fully drained rejected stream), pending admission before the HTTP/3 200
  response that restores caller-owned server sessions after rejection or
  abandonment, and HTTP/3 rejection helpers that send DATA/trailers with
  automatic Content-Length while preserving sibling-stream reuse, plus an
  explicitly retained rejection value with bounded delivery-recovery drains
  for applications that require ACK-confirmed teardown; RFC 9220
  connections expose bounded recovery-idle drains and flush terminal Close
  acknowledgements before applications stop driving their receive loops,
  negotiate `:protocol = websocket`,
  subprotocols, permessage-deflate, reject duplicate/legacy critical handshake
  fields, and use transport-derived `:scheme` over an h2 DATA tunnel
- MQTT 3.1/3.1.1/5 fixed headers with transactional Remaining Length preflight and
  exact header-only capacity reservation, plus single-reservation transactional
  Remaining Length, UTF-8 string, and Binary Data primitives, CONNECT/CONNACK with Last Will,
  version-scoped Client Identifier rules (including MQTT 3.1's 1-23-character
  bound), legacy PUBREL/SUBSCRIBE/UNSUBSCRIBE retransmission DUP flags,
  strict MQTT 3.1 reserved CONNACK handling with an explicit Mosquitto
  Session Present extension mode, username/password flag validation and payload support, PUBLISH,
  PUBACK/PUBREC/PUBREL/PUBCOMP acknowledgements, SUBSCRIBE/SUBACK,
  UNSUBSCRIBE/UNSUBACK, PING,
  DISCONNECT with MQTT v5 minimal reason-only encoding, AUTH
  enhanced-authentication exchanges with CONNECT-before-CONNACK multi-step
  challenges, owned method binding, active re-authentication and ordinary
  traffic gating, broker event-loop policy hooks, Protocol Error on method
  mismatch, properties, exact packet bounds, minimal remaining length, MQTT
  UTF-8 string validation with mandatory NUL/noncharacter rejection and opt-in
  Mosquitto-compatible strict C0/C1 control rejection across identifiers,
  topics, filters, and all
  MQTT 5 UTF-8 property keys/values, response-topic/topic-name/filter validation
  including the complete 65,535-byte wire limit,
  clean-session empty-client-id checks and bidirectional Clean Start/Session
  Present enforcement, MQTT 5 Assigned Client Identifier, Response
  Information, and Authentication Method request/response binding,
  version-specific MQTT 3.1.1/v5
  property and SUBSCRIBE option validation, payload-format UTF-8 validation, and
  wildcard and shared-subscription matching with MQTT 5 No Local/shared-subscription combination rejection,
  a broker-grade topic-level subscription trie with hashed literal edges,
  allocation-free caller-buffer matching, exact linear overflow fallback,
  subscription-option replacement, publisher-aware No Local filtering, and
  per-group/filter shared-subscription RoundRobin/Random/Sticky selection plus
  stable low-remapping Rendezvous hashing, plus a bounded retained-message
  store with exact O(1) lookup, wildcard matching, MQTT 5 expiry countdown,
  optional broker-driven periodic expiry pruning with persisted removals,
  Retain Handling 0/1/2, shared-subscription suppression, QoS downgrade and
  connection-scoped property stripping, plus lazy connection-lifetime writers
  for transient QoS 2 subscribers so fanout does not serialize unrelated
  socket progress; writer ordering remains per connection, PINGRESP drains
  older delivery work, self-delivery stays synchronous so its PUBLISH precedes
  PUBACK/PUBCOMP, and a 16-message scheduling high watermark restores
  synchronous backpressure before the configured hard queue limit, while QoS
  0/1 and durable Session delivery retain their ordered synchronous path, plus
  a bounded persistent Session
  Store with full subscription restoration, Session Expiry, offline QoS 1/2
  queues, shared immutable Topic Name/payload backing for multi-destination
  offline fanout, adoptable QoS 1 ingress packets, and released QoS 2 pending
  transactions, Receive Maximum scheduling, DUP/PUBREL reconnect retransmission,
  out-of-order ACKs and incoming QoS 2 deduplication, atomic versioned broker
  snapshots whose file contents and, on supported POSIX targets, replacement
  directory entry are synced, matching identity-bound reconnect-client
  snapshot file save/load with bounded transactional restore, direct v7 section
  and property encoding with byte-identical compatibility evidence in
  [MQTT commit-log costs](mqtt_commit_log_costs.md), and an opt-in
  fsynced append journal with
  CRC/sequence/footer validation,
  torn-tail recovery, directory-synced atomic compaction, and protocol-visible
  durability boundaries, plus coherent allocation-free state gauges and
  lock-free cumulative wire/PUBLISH counters for connection, Session,
  subscription, retained, queue, inflight, QoS 2 and Will state, with retained
  `$SYS` gauge publication through the normal routing/ACL
  path plus optional application-reported `$SYS/broker/heap/current` and
  `$SYS/broker/heap/maximum` gauges sourced from a caller heap snapshot,
  integrated into one live
  TCP and Unix-domain broker listeners that auto-detect MQTT 3.1/3.1.1/5 per connection, exposes
  opt-in bounded HAProxy PROXY protocol v1/v2 parsing before TCP, TLS, WS, or
  WSS application handshakes, with trusted source, destination, transport and
  v2 TLV metadata,
  heterogeneous TCP/Unix/TLS/WS/Unix-WS/WSS listener sources sharing one broker core, with
  listener-configured HAProxy PROXY v1/v2 parsing before transport handshakes,
  including required v2 TLS/client-certificate assertions and validated
  proxy-certificate CN username mapping on trusted cleartext listeners,
  finite deterministic batches plus a graceful-shutdown production supervisor
  that continuously replaces disconnected clients, and
  listener-specific MQTT 3.1/3.1.1/5 admission with version-correct refusal,
  independent listener-local and broker-global simultaneous connection caps
  that actively close excess peers and reuse capacity after disconnect,
  Mosquitto-compatible mount-point namespaces with inbound PUBLISH/Will and
  ordinary/shared-filter mapping plus fail-closed live/durable outbound topic
  projection,
  pre-registration CONNECT authorization with remote/proxy/certificate
  identity context plus pre-mutation
  PUBLISH/SUBSCRIBE/UNSUBSCRIBE, per-recipient outgoing-delivery, and
  publication-time Will access-control hooks, a strict Mosquitto-style broker
  configuration subset for shared TCP/Unix/TLS/WebSocket/WSS listeners, including
  separate IPv4/IPv6 wildcard sockets by default plus listener-local
  single-family socket domains and named-interface address binding enforced
  before bind,
  bounded, ordered Mosquitto-compatible `include_dir` expansion and
  LF/CRLF configuration files, with a typed missing-root error that the
  production CLI reports with the exact path and Mosquitto-compatible exit 3
  before opening any listener, plus
  supervised single-Session inbound, outbound, mixed, and `topic ... both ...`
  bridges whose runtime Set deep-owns every nested configuration value for
  safe staged replacement, with strict QoS/prefix mapping and local/remote loop suppression,
  upstream Session/authentication settings, bounded
  reconnect policy, vail-backed TLS 1.2/1.3 with CA/hostname verification,
  explicit testing-only `bridge_insecure` hostname opt-out that retains CA
  path, validity, signature, serverAuth EKU, revocation, and OCSP validation,
  explicit minimum-version policy, separate ordered TLS 1.2/TLS 1.3
  cipher-suite policy, required stapled-OCSP validation, and automatic
  RFC 5077 ticket reuse on same-host TLS 1.2 bridge reconnects without
  leaking tickets across multi-address failover targets,
  and optional encrypted-key mTLS,
  primary-preferred and round-robin multi-address
  failover, retained local/remote connection-state notifications,
  automatic/one-shot lifecycles, independently configurable remote/local
  Client IDs and clean Sessions, per-bridge Receive Maximum, Topic Alias,
  outgoing packet-size and RETAIN policy, stale remote-subscription cleanup,
  Mosquitto private-bridge negotiation with same-endpoint MQTT 3.1/3.1.1 fallback
  for one-way bridges and mandatory private mode for bidirectional bridges,
  explicit local IPv4/IPv6 source-address binding across cleartext and TLS
  reconnects, configurable TCP keepalive plus optional Linux
  `TCP_USER_TIMEOUT` policy preserved across cleartext/TLS fallback and
  reconnect attempts, source-locked per-bridge
  `bridge_reload_type lazy|immediate` SIGHUP replacement with
  prepare-before-commit rollback and no listener/client interruption, and
  crash-safe QoS 2 state,
  listener-local P-256/P-384/P-521/Ed25519/RSA PEM `certfile`/`keyfile`,
  PBES2-encrypted PKCS#8 keys with file-backed passwords, and
  ordered OpenSSL-style `ciphers` and `ciphers_tls1.3` policies on both TLS
  and WSS listeners,
  opt-in TLS 1.2 stateless tickets with per-listener process-lifetime keys,
  explicit server-identity binding, and bounded lifetime,
  optional/required
  mTLS through strictly validated `cafile` and bounded TCP/TLS `capath` trust
  sources with `require_certificate`, plus owned certificate-CN
  or OpenSSL-compatible RFC 2253 full-Subject username mapping before all MQTT
  authorization and Session policy, with established TCP/WSS identity-mapped
  Sessions remaining usable across atomic TLS/security SIGHUP generations, and
  bounded hashed
  password-file authentication compatible with Argon2id, `$7$`
  PBKDF2-SHA512, and legacy `$6$` salted SHA-512 entries, plus fail-closed
  global or `per_listener_settings`-isolated Mosquitto password/ACL files,
  including empty/comment-only zero-user generations for atomic named-user
  revocation, explicit credentialless deny-all listeners, and CONNECT
  authorization before duplicate-Client-ID takeover so rejected peers cannot
  displace a live Session or publish its Will,
  with anonymous/user scopes and Linux SIGHUP atomic password/ACL plus TLS/WSS
  server-identity/key-password/client-CA/CRL, bridge-generation, and
  per-listener anonymous/zero-ID/assigned-prefix, protocol-version,
  Maximum-QoS/Keep-Alive/Topic-Alias admission plus periodic/change-count/disabled
  autosave-policy reload, including source-locked retained-state checkpoint and
  restart recovery after change-count activation,
  selective live credential revocation, cross-subsystem rollback, and
  ref-counted in-flight handshake generations, exact per-listener WebSocket Origin allowlists,
  a bounded configurable HTTP Upgrade head size for WS/WSS listeners, and
  per-listener zero-length Client ID admission,
  separate global caps for simultaneously admitted connections and for active
  plus unexpired offline MQTT Sessions, with connection-local overload closure
  and protocol-correct Session-capacity refusal,
  deny precedence and `%u`/`%c` patterns, global
  full-packet and Application Message payload limits, global retained-message
  availability with MQTT 5 capability advertisement and version-correct
  rejection, a Mosquitto-compatible global per-client QoS 1/2 inflight limit
  enforced in both directions with MQTT 5 Receive Maximum advertisement, an
  independent outgoing inflight payload-byte limit through PUBCOMP, and
  count/payload-byte limits for each durable Session's queued messages,
  listener-scoped inbound and broker-created Topic Alias limits, a global
  administrative expiration cap for abandoned persistent Sessions, periodic
  retained-message expiry pruning with durable journal/autosave updates,
  retained `$SYS` publication with a zero-disable policy, configurable
  TCP_NODELAY across raw, TLS, WebSocket and WSS listeners, and configurable
  global/per-listener assigned Client ID prefixes plus the deprecated
  Mosquitto-compatible global `clientid_prefixes` admission policy, plus
  opt-in Mosquitto-compatible outgoing QoS upgrades across live,
  retained and durable delivery, plus default-on retained-source ACL rechecks
  with persisted Client ID, username and source-listener identity, and
  exposes a broker-internal persistent consumer with collision-proof identity,
  owned PUBLISH/PUBREL events, retained replay, explicit QoS completion, and
  journal-backed restart recovery for in-process subscription sources and
  configured outbound bridges with direct local consumption, including
  queue-threshold-triggered lazy connections and idle disconnects, and
  performs version-correct property/ACK downgrades, including securely
  generated anonymous Client IDs, MQTT 5 Assigned Client Identifier reporting
  and reconnect reuse, generation-safe duplicate-ClientID takeover that
  tolerates stale displaced-connection DISCONNECT completion, plus an indexed Will
  Delay scheduler with Session-end deadlines, reconnect cancellation, Clean
  Start takeover and DISCONNECT 0x00/0x04 handling, plus exact broker-side
  Keep Alive enforcement with 1.5x inbound inactivity deadlines, zero-disable
  semantics, bounded large-packet progress renewal and ungraceful Will/Session
  cleanup, plus a blocking TCP
  client/server runtime with shared, fail-closed TCP keepalive and Linux
  `TCP_USER_TIMEOUT` socket policies across TCP, TLS, WS, and WSS and a
  `std.Io.async` concurrent server helper, native MQTT-over-TLS clients with
  system, caller-provided file, or bounded OpenSSL-style CA-directory roots,
  hostname verification, and optional
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
  MQTT-over-WebSocket client/server adapters for MQTT 3.1, MQTT 3.1.1 and MQTT 5, with
  strict `mqtt` subprotocol
  negotiation, `ws://`/`wss://` client and server transports, WSS client
  identities with system/caller CA or pin/custom server verification,
  cleartext HTTP CONNECT proxy clients with isolated proxy/origin headers and
  one deadline through CONNECT, origin TLS, Upgrade and MQTT CONNACK, plus
  bounded HTTP Upgrade redirects before MQTT CONNECT with WebSocket downgrade,
  cross-origin credential and proxy policy preserved, HTTP-plus-MQTT nested
  redirect chains that retain the actual authenticated broker URI for MQTT
  authorization/loop/default-transport decisions, and reconnect connectors
  that rebuild the HTTP chain while forwarding same-origin TLS tickets,
  proxy-preserving MQTT 5 redirects whose deadline spans the complete chain,
  and reconnect connectors that open a fresh tunnel while retaining WSS
  ticket resumption, MQTT
  byte-stream reassembly across binary-message boundaries, and in-place client
  masking,
  an optional absolute CONNECT/CONNACK packet deadline shared by TCP, TLS, WS,
  and WSS without large-packet progress renewal, MQTT 5 reauthentication
  interleaved with established-session QoS, subscription and PING traffic,
  bounded AUTH waits that preserve packet order across deadlines and local
  allocation failure, terminal DISCONNECT handling that stops network I/O
  while preserving earlier queued packets and peer diagnostics, MQTT v5 Server Keep Alive,
  conditional Response Information, Request Problem Information filtering for server ACK/AUTH diagnostics, Receive Maximum capped by local inflight limits, Maximum Packet Size, negotiated-or-configured Maximum QoS and Retain Available enforcement for incoming/outgoing publishes, and Topic Alias negotiation/resolution capped to local alias storage with outgoing alias registration checks, QoS publish inflight limiting, and
  adaptive connection-local Packet Identifier tracking with independent
  incoming/outgoing sparse maps and bounded dense fallback for unusually large
  inflight windows, a shared outgoing PUBLISH/SUBSCRIBE/UNSUBSCRIBE identifier
  space that retains timed-out control exchanges until their validated ACKs,
  live durable-Session reservations shared with reconnect PUBLISH/PUBREL
  ownership across staged sends, queue drains and Session Present recovery,
  late subscription ACK preservation, and transactional local-failure rollback,
  split `writeSubscribe`/`completeSubscribe` and
  `writeUnsubscribe`/`completeUnsubscribe` APIs with timeout/deadline variants,
  reverse-order completion and retained ACK decoding after allocation failure,
  plus a single-owner reconnect command/event driver whose
  managed network worker can run on a dedicated OS thread or the caller's
  existing `std.Io` executor with the same stop, bounded-wait, terminal-error,
  and deinit contract, plus reconnecting one-attempt publishes whose returned
  Packet Identifier is transactionally bound to the submitted message without
  hidden queue insertion when Receive Maximum is exhausted, and
  MQTT 5 Server Reference validation plus opt-in bounded, loop-detecting
  CONNACK redirects for TCP/TLS/WS/WSS with per-hop authorization and fresh
  TLS authority verification, and
  QoS 2 exactly-once publish handshakes with unsolicited PUBREL rejection and negative-PUBREC receive-slot release, including MQTT v5 PUBACK/PUBREC/PUBREL/PUBCOMP reason-code/property validation with minimal reason-only encoding, dedicated UNSUBACK parsing, and negative publish acknowledgement propagation,
  synchronous QoS completion that correlates Packet Identifiers, retains
  interleaved application packets and sibling ACKs in bounded wire order,
  retries queued ACK decoding after allocation failure, and retransmits
  PUBREL for repeated successful PUBREC while preserving inflight accounting,
  timeout/deadline-bounded complete and split publishes whose single budget
  spans PUBLISH, PUBACK or PUBREC/PUBREL/PUBCOMP and interleaved traffic,
  reports committed PUBLISH identifiers for receive-timeout recovery, and
  resumes QoS 2 at its retained stage without retransmitting the PUBLISH,
- WebTransport capsules with core and incremental UTF-8/1024-byte close-reason
  enforcement, unidirectional and bidirectional stream headers, and HTTP/3
  DATAGRAM payloads with transactional single-reservation encoding,
  CONNECT metadata with client-bidi session-id validation and
  `Capsule-Protocol` request/response advertisement, and
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
  WebTransport payload-size accounting, owning and caller-buffer batch receive
  helpers with exact partial progress and non-consuming short-buffer retry,
  plus an authenticated `EndpointServer` with configurable non-zero
  per-connection Session capacity: connection+Session composite routing keeps
  CONNECT control, DATAGRAM, associated streams and CLOSE metadata isolated,
  while excess CONNECTs receive `H3_REQUEST_REJECTED`; the default and every
  standalone owning adapter remain honest one-Session endpoints. The matching
  authenticated `EndpointClient` owns one H3 reader while stable per-Session
  objects share global QUIC stream IDs, preserve bounded non-2xx admission
  metadata, enforce both peer SETTINGS and a local Session cap, and expose
  targeted DATAGRAM, associated-stream, CLOSE and removal operations, plus
  timeout/deadline-bounded RESET/STOP and reliable application-prefix reset
  while preserving sibling traffic through the owning HTTP/3 reader, resumable
  CLOSE/FIN with timeout/deadline bounds and retained close metadata, plus
  advisory DRAIN with timeout/deadline bounds and resumable DATA framing, plus
  stable-key `pollAny`/`receiveAny*` fairness across ready Sessions even after
  hash-map growth or removal of the prior producer,
  modern
  `0x41 + Session ID` bidirectional and `0x54 + Session ID` unidirectional
  stream association with shared parsing for accepted and early streams,
  clean-FIN truncated Session IDs rejected with `H3_FRAME_ERROR` while
  reordered header bytes and pre-association resets retain their ownership,
  real-handshake bidi/uni open/send/receive with
  per-session limits, prevalidated transactional cross-stream packet-batch writes that
  commit only the socket-visible prefix, with indexed O(n) duplicate validation
  and stable fixed-capacity priority selection under `runtime/stream/`, shared
  HTTP/3/WT stream-ID allocation, and
  CONNECT attempts across development, lightweight protected, authenticated,
  and stateful protected runtimes that retain bounded non-2xx DATA/trailers,
  paired with complete server rejection entities and stream-local cancellation
  on overflow; authenticated blocking/dispatcher paths additionally provide
  caller-owned client/server session restoration and sibling reuse, while
  direct successful CONNECT promotion flushes the response-head delayed ACK
  before ownership transfer so short-lived servers can retire recovery state,
  and
  WebTransport-style `stats`/`getStats` access to the underlying QUIC 1-RTT
  counters. Authenticated endpoint, standalone handshake, and stateful
  protected facades also expose one process-local `StableConnectionId` that is
  shared by Sessions on the same QUIC connection and survives value moves,
  peer-CID rotation, NAT rebinding, and migration; it is an observability key,
  not a wire identifier, persistent identity, or authorization credential.
  An externally negotiated-key stateful runtime has the same
  recovery, congestion/flow-control, associated-stream, cancellation, and
  session-lifecycle facilities as the integrated TLS-handshake runtime.
  Both expose exact initial Session stream-data/bidi/uni quotas through
  `initial_flow_limits`, including negotiated zero credit that waits for
  explicit Capsule grants; shared endpoints retain independent Session budgets.
  Applications can set `require_session_flow_control = true` to reject peers
  whose SETTINGS do not enable those quotas before a Session is established.
  Retained CONNECT refusals advance on endpoint polls without another UDP
  packet, while accepted Sessions and buffered sibling requests keep progressing.
  The `serveUntil` callback observes request, Session, connection and handshake
  failures with their scope and continues serving peers; callback and endpoint
  operation errors return to the caller.
  HTTP/3 message failures transfer typed request-rejection ownership before
  CONNECT admission, preserving their parser cause through send retries.
  Default HTTP/3 request polling also retains failed cancellation, reports
  socket errors, and keeps healthy request readers selectable during retries.
  Session maintenance settles abandoned RESET/STOP receive data even while
  applications only receive DATAGRAMs or write sibling streams, allowing
  WT_MAX_DATA to advance without consuming the pending RESET notification;
  association-only reliable prefixes can settle immediately, while reliable
  application bytes remain readable before their reset event.
- WebRTC signaling, media, security, data-channel codecs, and UDP peer runtime
  have moved to the sibling `horizon` package. Netz remains focused on the
  transport and HTTP/WebSocket/WebTransport stack.

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
either client's `client_identity` or explicit TLS version policy selects the
vail TLS 1.2/1.3 stream; an identity answers
CertificateRequest while preserving system/caller CA and hostname policy or an
explicit server verifier. The TLS server reuses the same MQTT
broker-side state machine as TCP/WebSocket and supports optional or required
TLS 1.2/1.3 client certificates with application-visible verified DER chains.
Clients without an identity retain Zig's standard TLS implementation.
`tls_handshake_timeout` applies to netz's vail-backed TLS 1.2/1.3 client and server
handshakes as one absolute receive budget across all handshake records; the
Zig 0.16 standard TLS client path does not expose an equivalent handshake
deadline. HTTP/1, HTTP/2, WSS, MQTT TLS, and MQTT WSS listeners forward the
same server option, while HTTP/2 and identity-enabled MQTT/WSS clients expose
the client-side option.
WSS servers reuse the cleartext HTTP Upgrade/frame state machine and may expose
verified TLS client chains. The maintained MQTT mTLS, listener-mount, WS/WSS,
PROXY-WS/WSS, and Origin interoperability processes obtain `std.Io` from
`netz.runtime.Backend`; their external OpenSSL and Mosquitto-derived runners
assert `server_io=zio-std-io` instead of accepting an unspecified backend.
Event loops, congestion control,
Richer high-level clients and servers can layer on the same byte-level pieces.

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
32-bit WebTransport RESET_STREAM/STOP_SENDING APIs, application-byte-counted
reliable reset APIs backed by negotiated QUIC RESET_STREAM_AT, and typed
data/reset/stopped events while retaining the whole-FIN receive helper for
compatibility. That
helper converts QUIC's authoritative final size before subtracting the
association prefix, so narrow targets reject unrepresentable complete streams
without overflowing while reconstructing their buffer range. Once a
client application runs an explicit transport pump,
`serviceTransportWithTimeout` and `serviceTransportWithDeadline` provide
timer-aware bounded receive intervals so a worker can observe a stop condition
and exit cooperatively without canceling an in-flight UDP receive. Rejected
handshake sessions expose the same methods, and the stateful protected client
forwards them. After a local STOP_SENDING is committed, buffered and later
in-flight bytes on that
direction are drained without application delivery: only connection-level
MAX_DATA credit is restored, the cancelled stream's MAX_STREAM_DATA limit is
not expanded, and terminal FIN triggers transport stream retirement. The
drain runs before whichever-ready, targeted, and whole-stream polling, so a
caller waiting only on a sibling cannot strand shared connection credit; a
racing RESET_STREAM settles its complete QUIC final-size charge but is still
reported once from session-owned metadata even if the transport stream is
already reclaimed. Peer resets receive the same WebTransport-specific cleanup
without changing QUIC's generic reset-first/partial-delivery behavior. A
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
timeout/deadline-bounded RESET_STREAM and STOP_SENDING, per-stream targeted
reads, delayed-ACK flushing, bounded reliable-delivery drains for short-lived
sessions, stream/session limits, connection statistics, and session-close
cleanup. A deterministic loopback regression consumes the first
client associated-stream datagram after CONNECT, permits the later uni stream
to complete first, and requires the lost bidi prefix/payload/FIN to recover
before the echoed response; this verifies that the preconfigured-key facade is
using the full 1-RTT recovery owner rather than the lightweight packet codec.
Stateful servers also provide two-phase CONNECT
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

## Proxy, VPN, and mesh protocol families

The application-proxy modules under `src/proxy/` cover SOCKS5 (CONNECT, BIND,
UDP ASSOCIATE, RFC 1929 authentication), HTTP/1 CONNECT, Shadowsocks AEAD,
Trojan, VLESS/VMess with TLS/WebSocket/HTTP/2/QUIC/gRPC transports, TUIC v5, and
Hysteria v3, together with shared ACL, destination, connection-limit,
rate-limit, reload, statistics, and bounded TCP/UDP/TLS/QUIC relay primitives.
`zig build fuzz-proxy` replays bounded hostile inputs through the SOCKS5, HTTP
CONNECT, Trojan, VLESS, VMess, TUIC, and Hysteria codecs. The feature matrix
and current verification limits are in [proxy_parity.md](proxy_parity.md).

`src/vpn/wireguard/` owns the Noise IKpsk2 handshake, message codecs, cookie
replies, replay protection, transport sessions, timers, and metrics.
`src/mesh/` owns mesh identity/endpoint types, bounded wire helpers, the disco
message codec, and DERP frame/relay/client state machines with their WebSocket
adapter. Product policy for both families remains in `vpnz` and `meshz`.
`zig build fuzz-wireguard-mesh` covers the WireGuard message parsers, disco
messages, and DERP frames. The feature matrix and current verification limits
are in [vpn_mesh_parity.md](vpn_mesh_parity.md).

