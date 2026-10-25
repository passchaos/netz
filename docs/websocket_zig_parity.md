# netz vs `/nav_env/Work/websocket.zig` parity audit

This audit records direct evidence for the WebSocket portion of the broader
netz improvement goal. It distinguishes feature coverage from measured hot
paths so a codec microbenchmark is not mistaken for complete server
superiority.

## Feature comparison

| Area | netz | `websocket.zig` reference |
| --- | --- | --- |
| HTTP/1 Upgrade client/server | Covered, including host names, IPv4/IPv6, Unix-domain listener/client transports, two-phase application admission before 101 with request metadata, custom acceptance fields, and final 3xx-5xx rejection, client `ConnectAttempt` access to rejected status/headers/trailers/bounded body while legacy `connect*` retains `InvalidResponse`, bounded 300/301/302/303/307/308 following with RFC 3986 relative resolution, canonical loop detection, one chain deadline, WSS downgrade and cross-origin credential policy, strict duplicate critical-header checks, upgrade-body rejection, single-reservation transactional 101 encoding with exact-capacity and fail-first-allocation coverage, optional client DNS/TCP connect budgets, caller-owned relative/absolute connection deadlines spanning DNS/TCP, TLS where applicable, and the complete HTTP Upgrade, cleartext HTTP-proxy CONNECT for WS/WSS with isolated proxy/origin headers and one deadline across proxy connection, CONNECT, origin TLS, and Upgrade, including a fresh tunnel on every redirected authority, optional absolute HTTP-phase deadlines over WS/WSS, including rejection bodies, that are not renewed by trickled bytes, and long-running bounded TCP/Unix/TLS supervisors with graceful cancellation plus accept/connection error policy | Covered with configurable handshake parsing, pre-101 handler callbacks and custom response headers, a Unix listener, client TCP/TLS connect timeouts, a server-side handshake timeout, worker pools and coordinated shutdown |
| WSS client/server | Covered through shared TLS transports with host/CA verification, separate resolved-address plus TLS-host connection, optional client identities, caller-provided server identities, optional/required client certificates, verified peer chains and concurrent serving | Client covered; 0.16 README labels the branch experimental, while the audited server API terminates cleartext WebSocket |
| HTTP/2 and HTTP/3 WebSocket (RFC 8441/RFC 9220) | Covered through extended CONNECT client/server adapters. The authenticated HTTP/3 path negotiates CONNECT over QUIC/TLS, preserves masking direction, subprotocol, Origin and permessage-deflate validation, and exchanges data/control/Close frames across split HTTP/3 DATA framing | Neither transport is present in the audited source |
| permessage-deflate | Negotiated and exercised by HTTP/1, H2, and H3 runtimes with actual LZ77/Huffman compression and expansion fallback. Client response validation is bound to the exact RFC 7692 offer on every transport, including the rule that `client_max_window_bits` must be authorized by the offer, its offered value is only a hint, and offered `server_max_window_bits` is a hard upper bound. Every client can offer both bounds from stack storage, and every server accept API can actively select them while capping the result to peer offers. All three transports additionally support explicit context-takeover opt-in across ordinary, sliced, fragmented, deadline-resumable, allocating, caller-buffer, and raw-frame APIs while retaining no-context as the default policy | Negotiation/decompression exists, but audited 0.16 client/server send compression code is disabled |
| Fragmentation / aggregate limits | Strict assembler and runtime message limits, UTF-8 validation after fragmented text assembly | Fragment assembly and configurable message/buffer limits |
| Receive/send ownership | `parseFrameInto`, `receiveMessageInto`, and its absolute-deadline variant use caller storage, including permessage-deflate output with reusable connection scratch on HTTP/1, RFC 8441, and RFC 9220; all three clients expose `sendBinaryInPlace` for the reference's mutable post-send contract while safe `[]const u8` sends remain available | Reader returns borrowed payloads and allocates/pools compressed output; client send APIs require mutable payloads and leave them masked |
| Close / Ping / Pong | Typed close parsing/writing, close-state guards, automatic Pong and Close replies, deadline-bounded typed peer-Close reads, plus deadline-bounded active Ping/Pong round trips that preserve interleaved application frames for HTTP/1 Upgrade, RFC 8441, and RFC 9220. Partial receive data and partially sent explicit or automatic control replies remain resumable after timeout without changing their mask, replaying a committed prefix, or losing a peer Ping/Close event | Handler callbacks and automatic default control replies |
| Concurrent sends | Serialized by per-connection `std.Io.Mutex`; writers recheck Close state after acquiring it, and HTTP/1, RFC 8441, plus RFC 9220 runtime tests exercise concurrent sends (the H2/H3 cases share one compressed encoder) | Documented thread-safe connection writes |
| TCP/TLS latency policy | TCP_NODELAY defaults on for ordinary accepted and client TCP/WSS sockets; WSS header + first payload bytes fill one TLS record/network write; configurable in runtime limits/connect options | Server enables NODELAY, audited client leaves Nagle enabled unless the embedding application changes the socket |
| I/O abstraction | HTTP/1, HTTP/2, and HTTP/3 adapters consume only `std.Io`; backend selection stays outside the protocol API | Custom epoll/kqueue/Windows server backends |

RFC 8441 now has process-boundary interoperability evidence in addition to the
in-process tests and benchmark:

```sh
zig build interop-websocket-hyper-h2 -Doptimize=ReleaseFast
```

The gate builds the audited `/nav_env/Work/hyper` checkout offline, enables Hyper's
HTTP/2 Extended CONNECT setting, and verifies the `CONNECT` method,
`:protocol = websocket`, path and WebSocket version before accepting its
upgraded byte stream. A netz client then sends masked text split across three
WebSocket fragments, validates Hyper's unmasked response, exchanges Ping/Pong
payloads, and completes a deadline-bounded Close 1000/`done` handshake while
checking Hyper's echoed close details. The Hyper fixture parses and writes RFC
6455 framing independently, so this is external RFC 8441 wire evidence rather
than a second netz endpoint.

RFC 9220 now has an owning authenticated HTTP/3 client/server runtime in
`websocket.runtime.h3`. It enables `SETTINGS_ENABLE_CONNECT_PROTOCOL`, waits
for peer SETTINGS, and requires the server to advertise that capability before
opening Extended CONNECT with `:protocol = websocket`. It validates version,
Origin, and subprotocol fields, then carries masked client and unmasked server
frames through streaming HTTP/3 DATA. A real QUIC/TLS test forces each frame
across five-byte HTTP/3 stream contributions and verifies fragmented text,
automatic Ping/Pong, and bidirectional Close. The same test negotiates
permessage-deflate with no-context-takeover and exercises a compressed
fragmented text message.

`zig build interop-websocket-h3-quic-go -Doptimize=ReleaseFast` adds
bidirectional process-boundary coverage against quic-go v0.59.0 from the
repository-owned, checksum-locked Go module, for both QUIC v1 and v2. In each
direction it
requires peer SETTINGS support, TLS certificate verification on the client,
Origin and subprotocol negotiation, masked fragmented client text, an unmasked
server response, two independently reset no-context-takeover
permessage-deflate messages in both directions,
Ping/Pong, and an echoed Close 1000/`done`. Netz limits each HTTP/3 stream
contribution to five bytes, which drives quic-go beyond its automatic
100-packet first key-update threshold; the QUIC v2 cases explicitly select the
pinned v0.59 compatibility profile while the library default remains RFC 9369.
The Go fixture implements its own bounded RFC 6455 frame reader/writer, so this
is external wire evidence rather than two netz adapters sharing a codec.
The benchmark runner now carries its selected QUIC version through both
implementations, the request metadata, and every config/result/completion
record; the checker rejects a v1/v2 mismatch instead of accepting a successful
v1 run requested as v2.

`zig build interop-websocket-chrome -Doptimize=ReleaseFast` now drives Chrome's
native browser WebSocket API against the HTTP/1 runtime. The first connection
comes from a disallowed origin and must fail before Upgrade; a second origin is
accepted and verifies client-preferred subprotocol selection, actual
permessage-deflate traffic in both directions, text and binary messages,
browser-generated Pong for a server Ping, and a clean 1001 close with the exact
reason. Passing `-- --tls` repeats the same matrix over native TLS 1.3 using a
fresh short-lived certificate and an exact Chrome SPKI pin rather than a global
certificate-error bypass. The captured gate used Chrome 146.0.7680.164. Chrome
does not expose Pong frames or compressed-wire flags to JavaScript, so those
two properties are asserted by the independent netz server endpoint on the
same real browser connection while the browser verifies decoded payloads and
close metadata. Browser coverage for RFC 8441/9220 remains limited by the
standard browser WebSocket API's HTTP version selection and current browser
support.

`websocket.runtime.TlsServer` negotiates TLS 1.2 or TLS 1.3 before the same transport-neutral
HTTP Upgrade parser and frame state machine used by cleartext `Server`.
The vail-backed WSS client and server expose explicit TLS-1.2-only,
TLS-1.3-only, and highest-version policies; a real TLS 1.2 ALPN Upgrade and
binary echo regression covers the legacy-compatible path. QUIC-backed RFC
9220 WebSocket remains TLS 1.3-only as required by QUIC.
TLS 1.2 WSS clients select a configured identity only when its certificate
type, signature algorithm, and issuing CA match CertificateRequest. P-521 is
included in the supported signature set, and an unsuitable identity produces
the required empty Certificate response instead of aborting optional mTLS.
The shared `interop-tls12-client-auth-openssl` gate verifies both matching and
unmatched CA selection against an independent OpenSSL server. Server-side
CertificateVerify validation rejects algorithms outside the advertised set.
`interop-tls13-client-auth-openssl` verifies the same CA-aware identity
selection and empty-certificate fallback for TLS 1.3; unknown request
extensions remain forward-compatible while duplicate types are rejected across
the complete 16-bit namespace without an arbitrary count ceiling. Repeated
signature-algorithm values are accepted in TLS 1.2/1.3 ClientHello and TLS 1.3
CertificateRequest vectors. A present certificate-authorities extension must
contain at least one non-empty DistinguishedName, and the initial handshake
requires an empty CertificateRequest context. TLS 1.3 OID filters additionally
constrain client leaf Key Usage and Extended Key Usage; duplicate or malformed
recognized filters are rejected while unrecognized OIDs remain ignorable. The
standard empty status-request signal is accepted, while non-empty forms and
recognized extensions prohibited in CertificateRequest are rejected. Client
identities can provide leaf or per-entry OCSP staples; requested responses reach
the server verifier, while unsolicited responses are rejected. The
server preflights the complete request before emitting ServerHello, so invalid
authentication configuration cannot leave a partial flight.
WSS callers can also transfer an RFC 5077 TLS 1.2 ticket between connections;
the server policy uses an application-owned rotating keyring and reports
whether the handshake resumed.
The same versioned WSS transport exposes RFC 8446 TLS 1.3 NewSessionTicket
extraction and PSK-DHE resumption without enabling early data. Ticket extension
parsing uses full-namespace duplicate detection, rejects recognized misplaced
extensions and the RFC-forbidden 65,535-byte vector, and ignores genuinely
unknown extensions. Stream TLS preserves exact finite or zero RFC 8446
`max_early_data_size` values instead of applying QUIC's sentinel rule, and
zero-lifetime tickets are discarded without failing the established WSS
connection. Client caches and server keyrings consistently expire tickets at
the exact advertised lifetime boundary.
End-to-end tests cover verified localhost CA/SAN, strict subprotocol selection,
encrypted binary echo, public-client mTLS with server pin verification and
application-visible client certificate chains, and the shared close/ownership
path. Setting `ConnectOptions.tls_identity` on the existing TLS host/URI
helpers selects the same vail stream transport as native MQTT TLS; absent a
pin/custom verifier, it maps caller CA bundles or system roots plus hostname
verification. TLS
client reads are true short reads, so a small Upgrade response no longer waits
for a caller's larger scratch buffer to fill.

HTTP/1 TCP, Unix, and native TLS servers expose the same two-phase admission
surface. `receiveUpgradeRequest*` parses and validates the opening handshake but
does not send 101; its owning `PendingUpgrade` exposes the target, request
headers, and authenticated WSS certificate/cipher/hash metadata. Applications
may then call `acceptWithHeaders` to add validated response fields or `reject`
with a final 3xx-5xx response and body; convenience 403, 404, and 429 helpers
cover common policy outcomes. Rejections always add `Connection: close`, and
both outcomes prevent applications from overriding WebSocket negotiation or
HTTP body-framing fields. TCP, Unix, and WSS timeout/deadline entry points apply
one absolute budget to listener accept and the complete HTTP/TLS Upgrade; a
timeout/accept race closes any late accepted socket. The original deadline also
remains in force across the application decision and every response write.
`runtime/handshake/response.zig` applies that same absolute budget to 101,
rejection headers and body, and automatic 426 version negotiation on TCP/Unix
and native TLS. Unbounded callers keep the existing scatter write. A pending
value owns the transport until an outcome succeeds or it is deinitialized.
Validation failures allow another decision; a response write failure marks the
pending value terminal, shuts down its socket, and blocks another 101 or
rejection from following an ambiguous wire prefix. Request and TLS metadata
remain valid until `deinit` releases ownership.
Server response-head limits now apply before descriptor or byte allocation.
`runtime/handshake/acceptance.zig` preflights mandatory 101 fields together with
negotiated, configured, and per-request fields; the codec's shared
`handshake/server.zig` validates singleton fields across those groups and keeps
transactional exact-reservation writing. The public `writeServerHandshake`
entry point is unchanged. `runtime/handshake/rejection.zig` likewise accounts
for the status/reason, application fields, `Connection: close`, generated
Content-Length, and final CRLF before preparing an ordinary rejection or
an automatic 426. A 304 remains bodyless without a generated length, and HEAD
suppression retains the ordinary representation length. Encoded response heads
reserve their exact checked size. An allocator that refuses every allocation
now sees `HeadersTooLarge` without being called for an oversized head. Real
TCP and pinned-WSS tests exceed the 16-descriptor stack path, then successfully
retry the same pending request, proving no response prefix or terminal state
escaped the size failure. Independent wire expectations cover exact-fit and
one-byte-short limits, decimal length widths, 304/HEAD framing, and invalid
status, reason, or caller framing fields.
The focused server-codec, response-budget, HTTP/1 handshake, Unix/WSS, proxy,
redirect and MQTT-over-WebSocket Debug gate passes 241/241 tests; public-module
checks pass 2/2.
Injected slow and partial TCP/WSS
writes verify timeout propagation, one budget across header/body, retained
metadata, and failed-response retry rejection. The focused handshake, WSS/Unix,
server lifecycle, Close timeout,
and MQTT-over-WebSocket gate passes 210/210 tests in Debug and ReleaseFast,
with public-module package checks passing 2/2. Existing `accept*` entry points remain
compatible wrappers that receive and immediately accept. End-to-end TCP, Unix,
and WSS tests inspect credentials before 101; the TCP tests additionally prove
that no response is sent before admission, custom acceptance fields survive the
wire, a 401 response carries its body and closes, and delayed admission expires
the original deadline. This closes the reference server's pre-upgrade handler
gap without introducing a callback or worker-pool policy into the transport.
Client HTTP/1 Upgrade now establishes its HTTP-phase deadline before nonce,
header preparation, and request serialization. The earlier of that deadline
and the caller's outer deadline bounds tracked request writing and all response
reads; the response phase cannot regain time spent writing. The extracted
`runtime/handshake/request.zig` retains target/Host validation, exact head-size
preflight, field-capacity policy, and bodyless encoding. Its common handshake
writer covers direct WS/WSS, caller-connected streams, URI/host, and proxy
composition without a separate request send path. Injected slow and partial
writes prove that WS and WSS HTTP-phase limits cancel request output, shorter
phase limits survive a wider caller-stream budget, and failure closes a
transferred stream so the peer sees EOF rather than waiting for its own timeout.
The combined request/response handshake, deadline, WSS/Unix, proxy, redirect,
resolver, and MQTT connection gate passes 213/213 tests in Debug and
ReleaseFast; public-module package checks pass 2/2.
The same HTTP-phase deadline now governs rejected response entities as well as
heads. Fixed-length payloads, chunk-size/data/trailer reads, and EOF-delimited
bodies all retain the earlier phase/caller timestamp instead of reverting to
only the outer deadline after a non-101 head. A server that sends a rejection
head and then stalls can no longer bypass `http1_handshake_timeout`, even when
no outer timeout is configured. The HTTP head/entity reader lives in
`runtime/handshake/receive.zig`, alongside its delimiter-limit test. Real TCP,
certificate-pinned native TLS, and Zig-standard TLS regressions exercise 45
combinations of framing, phase-only/earlier-outer budgets, stalled/trickled
entities, and complete bodies with owned metadata/trailers. The stalled case
first reproduced `ConnectionClosed` after the peer's own timeout in the old
implementation; it now produces `Timeout` and the peer observes client teardown.
The standard TLS arm tests record-reader behavior without system-root loading;
certificate pinning is verified by the native TLS arm.
HTTP/1 TCP, Unix, and native TLS admission additionally implement RFC 6455
version negotiation: an otherwise valid request offering a version other than
13 receives a bounded final `426 Upgrade Required` with
`Sec-WebSocket-Version: 13` and `Connection: close` before the transport is
retired. Missing/duplicate version fields, malformed keys, disallowed Origins,
or bytes coalesced after the request head remain ordinary handshake failures
and cannot trigger the capability response. Codec, cleartext real-socket, and
authenticated WSS tests cover the same shared path.
RFC 8441 now exposes the same decision boundary through
`H2Server.receiveUpgradeRequest*` and `PendingH2Upgrade`. Applications can
inspect the CONNECT stream ID, path, scheme, authority, and request fields
before any 200 response, then accept with additional response fields or reject
with a final 3xx-5xx response. `rejectWithBody` can additionally send an
ordinary HTTP/2 DATA body and final trailers; framing fields remain adapter-
owned so the generated Content-Length matches the bytes on the wire. Rejecting
or dropping a pending value terminates only that HTTP/2 stream, leaving sibling
requests and the shared HPACK state usable. Deadline variants retain their
original absolute budget across the application decision. Real h2c tests cover
metadata, custom acceptance fields, Content-Length and END_STREAM-delimited
rejection bodies, trailers, body-limit cancellation, 401 rejection followed by
a successful sibling request, and delayed-decision timeout. Existing
`H2Server.accept*` calls remain immediate compatibility wrappers.
RFC 8441 applies the same version advertisement without resetting or closing
the parent connection. An otherwise valid Extended CONNECT with version 12
receives a header-only 426 containing `sec-websocket-version: 13`; the server
returns typed `UnsupportedVersion`, then a normal sibling request completes on
the same HTTP/2 connection. Malformed version syntax, legacy connection fields,
bad Origin/subprotocol/extension grammar, and invalid server response options
remain ordinary validation errors and cannot trigger the advertisement.
`H2Client.openAttempt*` completes the other side of that policy: final non-2xx
status, response fields, bounded body, and trailers remain owned and
inspectable, while `requireAccepted` and the legacy `open*` wrappers retain
strict WebSocket negotiation after draining the complete rejection. A valid
426 whose repeated or comma-separated `sec-websocket-version` list excludes 13
maps to typed `UnsupportedVersion`; missing/malformed lists and contradictory
lists that still advertise 13 retain `InvalidStatus`. The body bound is the
caller-owned HTTP/2 connection's `Limits.max_body_bytes`; an overflow cancels
only that stream. The underlying HTTP/2 attempt API retires rejected streams
immediately, so the connection can issue a sibling request after authentication
failure.
RFC 9220 exposes the corresponding `Server.receiveUpgradeRequest*` and
`receiveSessionUpgradeRequest*` entry points. Its `PendingUpgrade` owns the
HTTP/3 session while the decision is pending, exposes CONNECT
path/authority/headers, preserves the original handshake deadline through the
application decision, and can either add accepted response fields or emit a
final 3xx-5xx rejection. A pending value created from a caller-owned session
returns that session after rejection or destruction; acceptance still
transfers it into the WebSocket connection.
`rejectWithBody` adds ordinary HTTP/3 DATA and final trailers, with automatic
Content-Length when a body is present and framing fields kept under the
adapter's control. Short-lived rejection drains reliable QUIC recovery before
session teardown on a best-effort bounded budget. Applications that require a
confirmed policy boundary can instead use `rejectRetained` or
`rejectWithBodyRetained`: the returned `RejectedUpgrade` keeps the HTTP/3
recovery state alive, exposes timer-aware transport servicing, and supports
explicit timeout/deadline delivery-only drains before teardown or restoration
of a caller-owned session. A real QUIC/TLS regression drops the first final
rejection datagram and requires PTO retransmission, exact status/header/body/
trailers, and an empty delivery-recovery queue. Existing `accept*` methods
remain immediate wrappers.
Unsupported RFC 9220 versions now use that same recovery ownership for the
automatic 426 advertisement. Caller-owned server sessions receive their H3
state back with the response still represented in ACK/PTO recovery, then
complete the existing rejection/drop sequence and an ordinary sibling request
on that connection. Server-owned admission retains the `RejectedUpgrade`,
performs its bounded delivery-only drain, restores the session to the outer
owner, and only then returns typed `UnsupportedVersion` for teardown. Real
authenticated QUIC tests validate the exact version header in both modes.
`Client.connect*Attempt*` retains the complete non-2xx response body and
trailers under `Limits.max_rejection_body_bytes`, rejects an oversized declared
Content-Length before allocating or reading DATA, and skips bounded 1xx heads
before the final response. Declared-length bodies use one exact retained
allocation even when DATA arrives fragmented; unknown-length rejections keep
the bounded incremental path. Compatibility `connect*` calls return typed
`UnsupportedVersion` for a valid 426 advertisement that excludes 13; missing,
malformed, or contradictory advertisements and all other non-2xx responses
retain `InvalidResponse`. Caller-owned HTTP/3 sessions are restored after a
complete rejection without an unnecessary stream cancellation; limit failures
abandon only the affected CONNECT stream.
Authenticated transport tests cover 103 followed by body/trailers, automatic
Content-Length, split DATA without Content-Length, legacy draining, body-limit
cancellation, explicit server rejection and dropped pending requests, and a
successful sibling request on both reused client and server sessions.
HTTP/3 WebSocket URI connects inherit HTTP/3's optional per-address handshake
timeout. A silent UDP route can therefore fail within its own phase budget and
fall through to the next address while the original WebSocket handshake
deadline, SNI, and `:authority` remain unchanged.
They also inherit the opt-in QUIC Happy Eyeballs policy. A real silent-first
regression gives the first route a two-second phase budget but launches the
second independent QUIC handshake after 20 ms and completes without waiting
for that budget. TLS identity, URI authority, total deadline, cancellation,
and loser endpoint cleanup remain owned by the HTTP/3 connector.

HTTP/1 URI clients now optionally follow bounded 300/301/302/303/307/308
responses rather than forcing applications to reconstruct each Upgrade from a
`ConnectAttempt`. `Location` uses RFC 3986 resolution, dot-segment removal and
fragment stripping; canonical scheme/host/default-port URI records detect
loops before another dial. One caller deadline covers every DNS/TCP, proxy
CONNECT, TLS, rejection drain and Upgrade in the chain. WSS-to-WS downgrade is
rejected by default. On a cross-origin hop, explicit Host is resynthesized,
all caller `extra_headers` are dropped unless policy opts in, TLS resumption
tickets are cleared, and a configured client certificate is refused unless a
separate policy opt-in permits it. Server trust and hostname verification apply
independently to every WSS authority. A configured cleartext proxy is retained,
but each hop gets a new authority-form CONNECT and proxy fields never enter the
origin Upgrade. Missing Location leaves the final 3xx `ConnectAttempt`
inspectable; duplicate or empty Location fails closed.
WS/WSS hostname, URI, redirect, and proxy connections also expose the shared
TCP `AddressConnectPolicy`. Ordered resolver fallback remains the default;
opt-in Happy Eyeballs stable-interleaves address families under a bounded
stagger and in-flight cap. Resolver results change only the socket route, never
Host, SNI, or certificate identity. Literal IPs bypass resolution/racing, one
absolute deadline covers every attempt, and cancellation closes successful
losers before the connection API returns.
The same redirect options can now attach `http.CookieJar`. Before every WS/WSS
hop the client derives one Cookie field from that URI after applying Path,
Domain, Secure, HttpOnly and SameSite; a caller-supplied Cookie/Cookie2 is
rejected rather than ambiguously merged. Every intermediate 3xx, accepted 101,
or final rejection commits its Set-Cookie fields before Location handling, so
a same-origin redirect observes new state immediately. Cross-origin remains a
conservative cross-site boundary unless the application explicitly proves
otherwise, while host-only/domain matching still decides actual Cookie scope.
Real WS tests cover an intermediate Cookie on the next hop, a 101 Cookie in the
jar, and caller-header conflict before network I/O. A two-origin test proves
Authorization and origin-A Cookie isolation while storing origin-B state only
for B. WSS coverage sends `Secure; SameSite=None` across a same-host port
redirect and proves the resulting cookie is unavailable to cleartext WS. The
existing proxy path remains unchanged: proxy credentials stay on CONNECT and
the derived Cookie is an origin Upgrade field under the original chain
deadline.

RFC 8441 and RFC 9220 client attempts now use the same single-owner CookieJar
through `CookieHandshakeOptions`. No caller-supplied scope is accepted: H2
derives it from the transport-resolved `:scheme` and actual
`:authority`/`:path`, while H3 uses its HTTPS authority/path or parsed URI.
Cookie selection therefore cannot diverge from the Extended CONNECT request's
host or Path. The adapters reject Cookie/Cookie2 ownership conflicts and
invalid targets/authorities before request I/O, derive WebSocket state with GET
and HTTP-API semantics, encode Cookie as HPACK/QPACK Never Indexed, and ingest
every Set-Cookie field before returning either an accepted or rejected attempt.
Real H2 and authenticated H3 exchanges inspect the peer-decoded sensitivity
bit; cover query-insensitive Path selection, cleartext Secure exclusion and
cross-authority isolation; and prove accepted plus non-2xx response state
reaches the Jar. The H3 one-shot-server regression also proves invalid
configuration cannot consume a QUIC handshake before the valid request.

The reference has a richer callback-oriented standalone server surface and
pooled-buffer/thread-pool configuration. Netz has broader protocol integration
(shared HTTP/TLS APIs and RFC 8441), but those are different strengths rather
than proof that every server workload is faster.

`websocket.runtime.UnixServer` and `Client.connectUnix` now cover the local
IPC transport exposed by the reference. They reuse the ordinary HTTP/1 Upgrade,
subprotocol, permessage-deflate, frame and close state machines rather than
forking a Unix-only protocol path. The client requires an explicit HTTP Host
authority because a filesystem socket path is not one; the listener deliberately
does not apply the TCP-only NODELAY option. Both HTTP/1 and WebSocket Unix
listeners expose the same bounded `serveConcurrent` shape as TCP. An end-to-end test negotiates a
subprotocol and compression, exchanges text in both directions, and closes over
a real filesystem Unix socket.

Client `ConnectOptions.connect_timeout` now bounds hostname resolution and all
TCP address attempts with one awake-clock deadline for WS, WSS, literal-IP,
hostname, URI and Unix-socket helpers. The connect task is cancellation-aware,
and a connection that wins concurrently with the timer is explicitly closed if
it was not selected. This is separate from the TLS and HTTP Upgrade handshake
budgets, so enabling it cannot silently shorten a configured response-head
deadline. Standard-library and vail-backed WSS clients both honor the public
`ConnectOptions.tls_handshake_timeout`; the nested vail option may override it
when a distinct policy is required. The audited websocket.zig client also exposes connect timeouts; netz
now covers the same liveness boundary without its POSIX-only nonblocking/poll
implementation.

HTTP/1 Upgrade clients now also accept typed `ConnectOptions.extra_headers`,
matching the reference client's custom handshake-header facility without its
raw string injection surface. The option is shared by WS, WSS, and Unix-socket
entry points. Header syntax is validated, and fields owned by the
runtime (Host, Upgrade, Connection, Origin, WebSocket negotiation fields) or
capable of adding an HTTP request body (Content-Length, Transfer-Encoding and
Trailer) are rejected before any request bytes are sent. This supports common
Authorization and Cookie handshakes without permitting duplicate critical
fields or ambiguous body framing. The fully encoded request head is also
checked against `Limits.max_head_bytes` before the first transport write.
HTTP/1 Upgrade parsing now also threads explicit `Limits.max_request_headers`
and `Limits.max_response_headers` into every WS/WSS handshake request/response
parser call, so header-count bounds are independent from the byte budget on
both server and client paths.

## Direct frame hot-path evidence

The current frame benchmark obtains its clock from a zio-backed `std.Io`. The
H1, RFC 8441, and RFC 9220 self-echo benchmarks use that backend for both
endpoints and schedule their local server through `std.Io.async`; H1
multi-connection clients use `std.Io.Group` and an `std.Io.Event` start barrier.
Every structured result identifies both endpoints as `zio-std-io`, and the
caller-join/direct-slices verifier rejects missing or mismatched backend
identities. Unless explicitly marked as a zio-era rerun, older timing ranges in
this section remain historical `std.Io.Threaded` evidence.

Run:

```sh
zig build bench-websocket-frame -Doptimize=ReleaseFast
taskset -c 0 zig build bench-websocket-receive-buffer -Doptimize=ReleaseFast
taskset -c 0 zig build bench-websocket-h3-echo -Doptimize=ReleaseFast
taskset -c 0 zig build bench-websocket-h3-echo -Doptimize=ReleaseFast -- \
  --stats
```

The receive-buffer benchmark exercises 8,192 coalesced eight-byte frames over
20 iterations. Five CPU-0 runs measured 2.14-2.17 ns/frame for the retained
read-window implementation versus 489.24-497.03 ns/frame for eager tail
compaction, a 226-231x synthetic speedup. More importantly, it reduced copied
bytes from 5,368,053,760 to 1,305,600: HTTP/1, RFC 8441, and RFC 9220 receive
paths are now amortized linear rather than quadratic when a transport read
contains many small frames. The benchmark is intentionally adversarial and is
not presented as an end-to-end network throughput ratio.
The dedicated RFC 9220 benchmark uses a real QUIC/TLS connection with a
4096-byte datagram limit and 3500-byte paced DATA chunks. Three CPU-0 runs of
the 4 KiB caller-buffer echo measured 54.730-56.287 us/roundtrip
(138.79-142.74 logical MiB/s). Bounded messages of up to 16 fragments now
encode all RFC 6455 frames into one 16 KiB stack buffer and submit one paced
HTTP/3 DATA sequence; each client fragment still receives an independent random
mask key. Three CPU-0 runs of the same payload split into 16 WebSocket frames
fell from 355.548-355.816 us/roundtrip to 52.230-54.194 us/roundtrip
(144.16-150.39 MiB/s), a roughly 6.6-6.8x latency reduction. Larger fragment
counts or wire payloads retain the bounded streaming fallback.
The external quic-go RFC 9220 client/server and benchmark executables now use
zio behind the `std.Io` protocol boundary. Their runner rejects success, shape,
and memory records unless the netz endpoint is `zio-std-io` and the quic-go
endpoint is `quic-go-netpoll`; older Threaded timing ranges remain historical.
The RFC 9220 adapter also reserves the bounded receive-window tail before an
HTTP/3 DATA read and lets the stream reader fill it directly. This removes the
former 16 KiB stack staging buffer and its `scratch -> inbuf` copy while keeping
the existing 16 KiB read-ahead ceiling; QUIC's receive storage still performs
the one copy required by the current public H3 reader contract. This follows
tquic's separate DATA streaming state and Hyper's direct-fill receive-buffer
pattern without introducing a wrapping ring into the contiguous frame parser.
Caller-buffer RFC 9220 messages go one step further after their frame header is
known: data-frame payload is read from the HTTP/3 stream directly into caller
storage, or into reusable compressed scratch, and masked in place. A resumable
frame cursor pins the output identity and payload offset across deadlines;
interleaved control frames remain in connection-owned storage because their
temporary stack output cannot survive a timeout.
The caller-buffer header path now requests only the missing 2-14 header bytes
instead of reading ahead most of the first H3 DATA chunk into `inbuf`. A timeout
regression sends a header plus a 512-byte payload prefix in one H3 write and
verifies the final-buffer progress survives while `inbuf` remains within its
256-byte header slab. On a 64-KiB echo A/B, five CPU-0 runs measured a
121.213-us median with exact header reads versus 124.133 us with read-ahead, a
2.4% reduction; the ordinary 4-KiB shape remained within timing noise. The H3
benchmark now exposes `--stats`; a warmed 200-roundtrip run reported only nine
one-time growth allocations and no per-message allocation.
The HTTP/1 caller-buffer path now uses the same header-staging/data-direct
split. Its socket or TLS read is bounded to the current frame remainder, so a
1 KiB masked text payload can cross a timeout in caller storage without growing
the WebSocket receive buffer to the frame size; a real TCP regression verifies
the partial offset, same-buffer retry rule, mask phase, and completed payload.
RFC 8441 now retains each owned HTTP/2 DATA frame with a cursor and copies its
WebSocket bytes directly into the final caller/compression destination. This
preserves sibling-frame routing, padding validation, flow-control accounting,
and DATA read-ahead while removing the `H2 DATA -> inbuf -> out` staging copy.
A bidirectional h2c regression splits both unmasked server and masked client
payloads across DATA frames, exercises timeout recovery, and keeps `inbuf`
smaller than the 1 KiB WebSocket message. A second multiplexing regression
inserts a sibling response between two DATA portions and verifies that
`ResponseAvailable` preserves the partial WebSocket cursor until the sibling is
consumed and the same caller buffer resumes.

The 2026-08-17 same-host sample ranges for 200,000 masked 4 KiB binary frames:

```text
netz allocating masked frame:        85-97 ns/op
netz caller-buffer masked frame:      71-82 ns/op
netz header-only stream preparation:  0.54-0.56 ns/op
websocket.zig header + copy/mask:      101-127 ns/op
```

The reference measurement calls `proto.writeFrameHeader`, copies the immutable
payload into scratch, then calls its SIMD `proto.mask`. Copying is required for
an equivalent contract: the reference client API accepts `[]u8` and masks it
in place, while netz accepts `[]const u8` and preserves caller memory.
The same benchmark now includes incremental UTF-8 validation of 4 KiB ASCII
and sparse-Unicode telemetry messages. A vector high-bit scan skips complete
ASCII blocks only while no multibyte sequence is pending, then resumes after
the original byte state machine completes each Unicode code point. One CPU-0
run measured 40.32 ns/message versus 2007.79 ns for the directly invoked
scalar ASCII path (49.80x), and 301.08 versus 2184.19 ns for sparse Unicode
(7.25x). Split multibyte sequences plus valid and invalid high bytes at every
offset across several vector boundaries retain direct regression coverage.
Masked client text uses the same no-copy validator: it XORs and checks ASCII
blocks as vectors, preserves all four mask phases across partial transport
reads, and falls back to the incremental code-point state machine only when
needed. One CPU-0 same-process run measured 58.37 ns per 4 KiB message versus
2097.76 ns for the former scalar XOR/feed loop, a 35.94x speedup.
Caller-buffer receives now fuse copy, unmasking, and the common ASCII UTF-8
check into one vector pass. The non-ASCII fallback reuses the incremental DFA
and remains resumable across transport chunks. A same-process 4 KiB run measured
44.81 ns/message for the fused path versus 72.29 ns for vector mask-copy followed
by a separate vector UTF-8 scan, a 1.61x speedup.
HTTP/1, RFC 8441, and RFC 9220 receive paths also reuse the `FrameHeader` they
already parsed to size their transport read instead of decoding the same
variable-length header again in the complete-frame codec. The frame benchmark's
same-process masked short-frame loop measured 4.30 ns/frame with header reuse
versus 7.85 ns/frame for the former duplicate parse, a 1.83x reduction in that
fixed parser component. Length-boundary and masked/unmasked equivalence tests
cover both allocating and caller-buffer predecoded APIs.
Those predecoded APIs now derive the complete wire length through one checked
`FrameHeader.wireLen` operation. HTTP/1, RFC 8441, and RFC 9220 receive paths
share it, so a payload that fits `usize` but whose header-plus-payload length
does not fit returns `PayloadTooLarge` instead of wrapping on a narrow target
or trapping for a caller-constructed header. A boundary test covers allocating,
caller-buffer, and in-place decode entry points.
The shared length-only frame-header encoder also enforces RFC 6455's 63-bit
payload ceiling before writing any extended length. Boundary tests round-trip
the maximum legal value and reject the first value whose wire high bit would
make the frame invalid without modifying caller header storage, so slice and
fragmented send paths cannot produce a frame that the decoder must reject and
failed preflight remains retry-safe.
Aggregate H1, RFC 8441, and RFC 9220 receives now transfer the transport's
incremental UTF-8 state into `MessageAssembler`: both frame parsing and message
assembly skip their otherwise-repeated payload scans, and finalization trusts
only the assembler's internal proof for uncompressed text. Compressed text and
externally constructed messages retain the final validation pass. Thus ordinary
complete text is validated once while fragmented text still rejects a malformed
sequence at the decisive byte.
Allocating message receives now also retain their accepted fragment prefix
after a local allocation failure. `message/assembler.zig` checkpoints opcode,
compression and UTF-8 state without restoring a stale buffer pointer after
growth; append and final owned-slice failures roll back to the accepted prefix.
The shared `runtime/message/receive.zig` loop keeps the current wire frame until
assembly and final decompression both succeed. An OOM restores an in-place
unmasked frame to its original masked wire bytes, restores the frame validator,
and retains the assembler for the next `receiveMessage` call. Compressed input
whose final inflate could not allocate is adopted back into assembler storage;
RFC 7692 takeover history commits only after complete decode and text validation.
The same transaction covers HTTP/1, RFC 8441 and RFC 9220, both masking roles,
first/middle/final fragments, final owned slices, and continuous compression.
Adjacent failing-allocator tests retry each allocation boundary and verify a
following independent or history-dependent message, plus a real TCP case that
first times out on a masked UTF-8 prefix. Receive-mode changes remain local
errors while a message is retained; malformed input still follows the existing
Close/error path.
Caller-buffer context decoding now also retains complete compressed input
after a final decoder allocation failure. The shared
`runtime/message/complete_into.zig` finalizer owns decoding, text validation
and history commit for HTTP/1, RFC 8441 and RFC 9220. Its completion marker
prevents a retry from reading the following message, and complete compressed
input releases the old output address so the caller may supply new storage.
Partial-message timeouts still require the same destination. Repeated OOM,
undersized output and receive-mode misuse preserve the pending message; a
successful retry commits history once. Tests cover both masking roles,
fragmented messages, every decoder allocation, an established dictionary and
real TCP timeout/OOM recovery. Invalid deflate or decoded UTF-8 still follows
the protocol Close path after memory becomes available.
Validation passes the complete Debug WebSocket matrix, focused ReleaseFast
assembly/Close tests, package reachability, real H1 WS/WSS receive smokes,
Hyper h2c/TLS RFC 8441 interoperability, quic-go RFC 9220 in both directions
over QUIC v1/v2 using Go 1.24.13, and the deterministic H1/H2/H3 compression
context fuzz targets.
Their owning-message loops also decode complete frames in place in the
connection buffer and copy payload bytes only once into `MessageAssembler`. The
public frame API keeps its independent owned payload, while aggregate receives
avoid allocating and freeing an intermediate payload for every fragment. A
failing-allocator regression preallocates only the final assembler storage and
proves a complete buffered message needs no per-frame allocation. A CPU-0
same-process 4 KiB binary parse measured 1.96 ns/frame in place versus 63.51
ns/frame through the former owned allocation/copy path, a 32.43x reduction in
that isolated parser component.
`MessageAssembler` now also gives a complete, unfragmented message one exact
payload allocation. It bypasses geometric `ArrayList` growth followed by a
final shrink/remap; fragmented messages retain amortized growth. An allocator
regression verifies one allocation and no resize/remap for this common case.
Caller-buffer H1/RFC 8441 receives retain their existing transport-read
fail-fast validator but no longer rescan the complete uncompressed message;
the shared resumable state carries the validation proof across continuation
frames and timeout retries. RFC 9220 now validates each newly arrived HTTP/3
DATA slice inside the current WebSocket frame and carries that proof across
continuations and timeout retries. A real QUIC regression limits STREAM payloads
to five bytes, advertises a 1 KiB masked text frame, then withholds all but the
two-byte invalid prefix; caller-buffer, owning-message, and frame receives all
return `InvalidUtf8` and Close 1007 without waiting for the unfinished frame. A
second case carries an incomplete code point from one frame into a separately
received continuation and rejects its decisive byte before that frame finishes.
Compressed caller-buffer text remains validated after inflation.

Netz's actual unmasked TCP server path prepares only the validated stack header
and uses one vectored network write for header + borrowed payload. Masked
clients copy and mask in one SIMD pass through a fixed 16 KiB stack scratch,
so payload size no longer drives heap allocation.

The same command also measures one 4 KiB repeated telemetry-like message
through no-context-takeover compression. Complete and discontiguous messages
now use a package-local focused fixed-DEFLATE sync-flush encoder. Its reusable
4K-entry hash chain avoids clearing Zig flate's roughly 224 KiB compressor
state per message. The chunked encoder keeps plaintext discontiguous while a
bounded 16 KiB rolling dictionary preserves matches across caller slices. A
2026-09-10 CPU-0 run of the persistent 4-KiB compressed echo measured 22.296
us/roundtrip, versus the previous 29.44-31.14 us range.

```text
permessage-deflate: 3.860 us/message, 4096 -> 69 wire bytes
16-slice streaming: 7.587 us/message, 4096 -> 69 wire bytes, no join
```

These are CPU-0-pinned `ReleaseFast` regression samples from 2026-09-10. The
package-local encoder remains in the same small-microsecond class as the
preceding external-backend range of 5.55-6.10 us/message while retaining the
same 69-byte wire output. Adjacent slice coalescing, rolling history and one
shared fixed block also reduce the first chunked path's 463-byte payload to the
same 69 bytes as the complete-message path. This remains an
internal encoder baseline and compression-ratio example, not a cross-library
speed ratio: the audited websocket.zig 0.16 send paths currently hard-code
`compressed = false`, so no equal compressed-send workload exists there.

A 2026-09-30 zio-era fixed-binary A/B isolates the contiguous LZ77 match scan.
The candidate compares two SIMD blocks at a time and locates the first unequal
lane only when a block differs; match selection and fixed-DEFLATE output remain
unchanged. Seven alternating CPU-0 pairs all favored the candidate:

```text
baseline:  5.516-5.549 us/message, median 5.526 us
candidate: 4.195-4.215 us/message, median 4.203 us
paired candidate/baseline median: 0.7605 (-23.9%)
wire payload: 4096 -> 69 bytes; checksum: 8351760000 in every run
16-slice control medians: 10.102 us baseline, 10.100 us candidate
```

At that checkpoint the chunked control remained unchanged because
discontiguous matching still used byte-at-a-time slice cursors. The fixed
binaries and paired log are retained under
`zig-out/websocket-vort-match-ab/`; their SHA-256 identities are
`8224fa43e4b178284c26f7d2d62ad42377b3f934cee3d69c147133ae378f37ab`
and `c12e8a08229218e57c7eafa1cad9d86ede228980697e0e4706fe3afdd4f8db36`.

The follow-up keeps each plaintext slice borrowed, but compares the largest
currently contiguous span from both match cursors with the same SIMD scanner.
The cursors advance independently when either span reaches a slice boundary;
empty slices and a scalar tail remain covered without an aggregate plaintext
buffer. Seven alternating CPU-0 fixed-binary pairs measured:

```text
16-slice baseline:  10.101-10.120 us/message, median 10.112 us
16-slice candidate:  5.814-5.908 us/message, median  5.818 us
paired candidate/baseline median: 0.5758 (-42.4%)
contiguous control medians: 4.200 us baseline, 4.201 us candidate
contiguous paired median ratio: 1.0000
wire payload: 4096 -> 69 bytes; checksum: 8351760000 in every run
```

The fixed binaries and final paired log live under
`zig-out/websocket-vort-chunk-match-ab/`. Their SHA-256 identities are
`c12e8a08229218e57c7eafa1cad9d86ede228980697e0e4706fe3afdd4f8db36`
and `8a7f7bc3bc9a55a335f37c5471d9432aca8e9e1b0b7abf873f08dd48b458d97e`;
the log hash is
`70d549525df781433c18cfdf6abda7c3d67d932db4c419df20165f80549fd47b`.

Inbound no-context and context-takeover messages now use Vort's bounded raw
DEFLATE decoder. The caller-buffer path no longer retains the former 64-KiB
Zig-flate window per connection, while context takeover passes its committed
history as a bounded preset dictionary and preserves explicit preview/commit/
discard semantics. Seven order-alternated CPU-0 fixed-binary pairs decoded the
same 69-byte wire message to 4 KiB: the prior path measured 1070-1081
ns/message (1072 median), and Vort measured 467-471 ns/message (468 median), a
56.3% median reduction with 7/7 candidate wins. Both arms reported checksum
`8353707268`; this is an internal decoder A/B, not a comparison with
websocket.zig.

## Persistent echo evidence

The end-to-end benchmark uses one real HTTP/1 upgraded connection, 20 untimed
warmup exchanges, then 200 measured 4 KiB binary echo round trips. Client
requests are masked, server replies are unmasked, both wire frames use minimal
16-bit extended lengths, and both clients copy the echoed application payload
back into their mutable send buffer before the next round. Handshake time is
excluded. The maintained netz executable obtains that backend-neutral `std.Io`
from zio and no longer exposes a Threaded benchmark fallback.

The same executable accepts `--compression`, negotiating permessage-deflate on
both endpoints and exercising retained send/receive scratch plus direct caller-
buffer inflation over a real upgraded connection. Five 2026-08-20 CPU-0 runs
measured 29.44-31.14 us/roundtrip (250.91-265.34 logical payload MiB/s),
4.6-5.0x lower latency than the previous 144.6-147.5 us range. Three four-
connection CPU 0-7 runs measured 12.09-12.18 us aggregate/roundtrip and
641.52-645.95 logical MiB/s, versus the previous 45.96 us/169.98 MiB/s. These
are internal compressed-runtime baselines because the
audited websocket.zig outbound compressor remains disabled.

Adding `--fragmented` sends the same client payload as sixteen application
slices while the server continues to echo one complete message. Three CPU-14
runs measured 35.80-36.60 us/roundtrip and 213.48-218.24 logical MiB/s after
the runtime began batching small masked and unmasked compressed continuation
frames. The same workload previously took 129.24 us/roundtrip before batching.
The complete-message control measured 30.65-30.91 us/roundtrip, so preserving
sixteen RFC 6455 frame boundaries costs 16.8-19.4% rather than multiplying
socket writes sixteenfold. All runs verified checksum 51,000.

RFC 8441 has a separate `bench-websocket-h2-echo` gate with the same warmup,
iteration, payload and compression shape. Three CPU-14 complete-message runs
measured 37.91-38.44 us/roundtrip and 203.23-206.05 logical MiB/s; sixteen-
slice runs measured 43.66-44.00 us and 177.56-178.94 MiB/s. Before coalescing
the RFC 6455 frame sequence into one flow-controlled tunnel write, the same
fragmented gate took 98.55-137.68 us. The batch therefore reduces latency by
2.2-3.2x while preserving every WebSocket frame boundary; its remaining
15.1-16.0% cost versus one frame is the real framing/masking work. Each run
verified checksum 51,000.
After removing RFC 8441's payload-sized send-frame buffer, five CPU-0 runs of
the same sixteen-slice compressed workload measured 37.032-38.500 us/roundtrip
(37.651 us mean, 37.372 us median, 1.55% relative standard deviation,
202.91-210.96 logical MiB/s). The common sixteen-frame case still uses one
bounded stack batch, so the prior coalescing benefit is retained while the
connection no longer owns a duplicate encoded-message allocation.

A 2026-09-30 zio-era audit found that those batches still called the secure
random backend once for every masked client frame. One H1 trace with five
warmups and twenty measured messages made 403 `getrandom` calls: 400 for the
sixteen masks per message and three for setup. The H1, H2, and H3 batch writers
now fill up to sixteen independent four-byte mask keys with one CSPRNG request;
every frame still carries its own fresh unpredictable key. The same trace now
makes 28 calls, exactly one per message plus the three setup calls.

Seven alternating CPU-0 fixed-binary pairs with fifty warmups measured the
production compressed-fragmented echo path:

| Transport | Baseline median | Batched-mask median | Paired ratio | Reduction |
|---|---:|---:|---:|---:|
| H1 Upgrade, 1,000 rounds | 143.901 us | 70.876 us | 0.4929 | 50.7% |
| RFC 8441, 1,000 rounds | 121.229 us | 31.329 us | 0.2581 | 74.2% |
| RFC 9220, 500 rounds | 145.937 us | 56.293 us | 0.3833 | 61.7% |

All 21 primary pairs completed with the expected checksum and favored the
candidate. Five-pair uncompressed-fragmented controls, which use the same H2
and H3 mask batches without the compressor, measured 107.344 to 16.477 us on
H2 and 191.387 to 105.028 us on H3. Fifteen-pair unfragmented H2/H3 controls
overlapped and had candidate/baseline paired medians of 1.0108 and 1.0121;
those paths do not execute the new batch helper, so no single-frame performance
claim is made. Exact binaries and logs are retained under
`zig-out/websocket-fragmented-echo-ab/`.

HTTP/1 now applies the same bounded batching to uncompressed fragmented
messages instead of issuing one random request and one transport write per
client frame. A masked message whose worst-case headers plus payload fit the
existing 16 KiB stack scratch is encoded once and submitted once; unmasked
servers keep payload slices borrowed and submit up to sixteen header/payload
pairs per vectored write. Larger messages retain the prior streaming fallback.
The H1 echo benchmark now permits `--fragmented` without compression so this
path remains directly measurable. Seven alternating CPU-0 fixed-binary pairs
with fifty warmups and 1,000 measured 4 KiB round trips produced:

```text
baseline:  143.041-146.236 us/roundtrip, median 144.530 us
candidate:  53.681-54.944 us/roundtrip, median  54.664 us
paired candidate/baseline median: 0.3768 (-62.3%)
```

All seven pairs favored the candidate and retained checksum 255,000. The
compressed-fragmented and ordinary uncompressed single-frame controls had
paired medians 1.0021 and 0.9987, respectively. A five-warmup, twenty-message
`strace` control reduced `getrandom` calls from 403 to 28. Exact binaries and
the paired log are retained in `zig-out/websocket-h1-fragment-batch-ab/`; the
baseline, candidate, and log SHA-256 values are
`de75d747ccb06475155edd07fe5dd0d3b389ecbc3c357de251b703898cc29cdb`,
`b25278fc3c47df867d567f00be12a6632ab68f5eed0ea64f5dc46cbed54addfb`,
and `2dcaff447dd51d7a28d516c2cb8b9d7ddf55bee6af4939625d2c22d7b1d77833`.

The HTTP/2 Extended CONNECT, traditional CONNECT, and tunnel-response builders
now stage their pseudo-headers and ordinary headers in 16-entry stack buffers,
matching the ordinary HTTP/2 request/response path. Larger application header
sets retain an exact heap fallback. A fail-first unit test proves the full
common stack capacity does not allocate and that the first overflow reports OOM
cleanly before a successful fallback allocation. The 2,958-test Netz suite and the
external Hyper RFC 8441 fragmented-text/Ping/Pong/bounded-Close gate remain
green, as does the broader bidirectional Hyper h2c/TLS gate. Five CPU-0 4-KiB
RFC 8441 echo runs measured 31.105-31.955 us/roundtrip (31.507 us mean, 0.94%
standard deviation, 244.48-251.16 logical MiB/s). This is a persistent-connection
regression sample; the one-time CONNECT allocation removal is intentionally not
presented as a steady-state echo throughput gain.
RFC 8441 server application frames now keep their RFC 6455 header on the stack
and pass it with the borrowed payload to `Tunnel.writeParts`. HTTP/2 applies
DATA frame sizing and connection/stream flow control across that logical join,
including a DATA frame that contains the end of the WebSocket header and the
start of its payload, without retaining a payload-sized frame buffer. An
8-KiB-window regression sends more than 16 KiB to force multiple WINDOW_UPDATE
and client masking cycles, then verifies the complete message plus zero retained
frame scratch. Client frames still require
masking, but now stream through the same bounded 16-KiB stack scratch used by
HTTP/1 WebSocket instead of retaining the complete masked frame. The
constrained-window regression verifies zero retained frame scratch in both
directions and uses the arbitrary-slice API so HTTP/2 DATA framing crosses both
the WebSocket header/payload and application-slice joins. A separate negotiated
permessage-deflate test verifies multiple borrowed slices are compressed as one
binary message in both directions and still do not grow frame scratch.
Five CPU-0 4-KiB regression samples after adding H2 borrowed-slice writes measured
30.987-32.321 us/roundtrip (31.394 us mean, 31.072 us median, 1.63% relative
standard deviation, 241.71-252.11 logical MiB/s). The range
overlaps the earlier samples, so it is recorded as no demonstrated steady-state
speedup; the proven improvement is eliminating payload-sized retained scratch
on both directions of the ordinary single-frame path. The full 2,958-test Netz suite
and the bidirectional Hyper RFC 8441 gate remain green.

The first compressed frame is copied once from the transport/caller frame
buffer into retained compressed scratch. This is intentional: Zig's raw
inflater may overwrite output before consuming aliased input. A regression test
checks that scratch holds the exact wire payload before caller-buffer inflate.
Uncompressed binary messages accept an arbitrary caller-owned slice list. The
server submits the header and slices without concatenating payload bytes, using
bounded scatter/gather where the transport supports it; the client masks
through bounded stack chunks while carrying one RFC 6455 mask offset across
every slice. Empty slices are accepted, and the receiver still observes one
FIN-terminated binary frame rather than WebSocket continuation frames. This
lets MQTT-over-WebSocket encode packet prefixes and application payloads
without a plaintext join. Runtime and codec tests cover the 125/126 and
65535/65536 frame-length transitions. When permessage-deflate is negotiated,
the same API feeds all borrowed slices directly to the retained encoder.
A fail-after-warmup runtime test verifies that repeated compressed multi-slice
sends do not allocate through the connection allocator. The original
`sendBinaryParts` remains as a two-slice compatibility wrapper across HTTP/1,
RFC 8441, and RFC 9220.

The native `bench-websocket-slices-ab` gate compares that arbitrary-slice API
with an explicit caller-side join over all three transports. Its default
workload uses one persistent connection, 20 warmups, 1,000 measured 4-KiB
round trips, eight application slices, no compression, one WebSocket frame,
one pinned CPU, alternating shape order, and five-sample medians. The strict
verifier requires matching workload fields, logical bytes, checksums, and
completion for every sample. The first 2026-09-09 CPU-0 run exposed
direct-slices/caller-joined median ratios of 1.506 (HTTP/1), 1.017 (RFC 8441),
and 1.382 (RFC 9220). H1 now uses the existing POSIX wide-iovec writer so its
frame header plus eight payload slices fit one submission, while H3 groups
borrowed ranges across application-slice boundaries into packet-sized DATA
contributions. The final-code historical Threaded five-sample run measured
1.008, 1.002, and 1.022. The 2026-09-15 zio rerun, with the same five
alternating CPU-0 samples, measured ratios of 1.030, 1.017, and 1.018. The
caller-joined/direct-slices medians were 16.042/16.530 us for H1,
17.057/17.340 us for RFC 8441, and 138.932/141.480 us for RFC 9220. Every zio
record identified both endpoints as `zio-std-io`, transferred 8,192,000
logical bytes, and produced checksum 255,000. Historical and zio results must
not be combined. The gate
deliberately has no speed threshold, and these self-echo results are neither an
external-library comparison nor equal-wire evidence.

Netz uses `sendBinaryInPlace` and `receiveMessageInto`; the former deliberately
leaves caller storage masked, matching websocket.zig's mutable-input contract,
while the latter assembles fragments and handles control frames without a
message allocation. With permessage-deflate, the decompressed message lands
directly in the caller buffer. TCP and RFC 8441 connections retain bounded
compressed-wire scratch plus a reusable receive DEFLATE history window. Both
complete and fragmented sends use the package-local raw fixed-block sync flush;
the fragmented form feeds per-slice token plans into one block without joining
plaintext and carries up to 16 KiB of prior plaintext as match history. Both
paths remove the RFC 7692 suffix and set RSV1 only when the wire payload is
strictly smaller; incompressible/small input is sent unchanged rather than
paying expansion, and payloads below 32 bytes skip compressor setup entirely.
No-context-takeover resets codec state for every message
while retaining wire buffers. RFC 8441 caller-buffer receive now writes each
uncompressed frame directly into application storage and each compressed
continuation directly into codec scratch; it no longer allocates every frame
or retains a second whole-message buffer. The focused encoder retains its hash
chain per connection; receive-side codec storage is allocation-free
after first-use warmup. The H2 adapter retains tunnel/frame and codec scratch
but avoids separate application-message and decompressed-message allocations.
Buffered regressions prove both an uncompressed fragmented message with an
interleaved control frame and a warmed compressed fragmented message complete
without another caller-allocator allocation. A CPU-0 ReleaseFast regression
run measured 31.566 us/roundtrip for one 4-KiB frame and 37.087 us for sixteen
fragments, with checksum 51,000 in both cases; these overlap the prior ranges
and document that removing the duplicate receive buffer did not trade memory
for a visible throughput regression.
Fragmented compressed sends no longer concatenate plaintext first: each caller
slice feeds the same bit-packed DEFLATE stream directly, UTF-8 is validated
across slice boundaries with four bytes of state, and only compressed wire
scratch remains. A wire-level regression also verifies that requested frame
count/FIN boundaries survive compression and only the first frame carries RSV1.
Tests cover a zlib-generated dynamic-DEFLATE fixture, fragmented compressed
text with interleaved PING, send/receive scratch reuse under failing allocators,
actual wire shrink plus RSV1, expansion fallback without RSV1, output overflow,
and H2 compressed caller storage in both directions.
The authenticated HTTP/3 adapter now uses the same chunked-input encoder
and incremental UTF-8 validation. It retains only compressed output, preserves
the caller's fragment count on the wire, and no longer allocates a joined
plaintext message before sending RFC 9220 DATA.
TCP and RFC 8441 receive APIs now also complete the RFC 6455 failure handshake:
malformed frames send Close 1002, invalid message UTF-8 sends 1007, and frame,
aggregate-message, or decompression limits send 1009 before returning the typed
local error. Nested frame/message readers suppress duplicate Close frames.
Both transports also expose absolute-deadline message reads. RFC 8441 carries
the same deadline through HTTP/2 frame parsing, connection-control frames,
WebSocket fragmentation and Ping/Pong handling, so upper-layer inactivity
budgets cannot be extended by transport control traffic.
One earlier four-connection `--stats` run made 7,151 allocations, allocated
48,068,236 cumulative bytes and peaked at 1,240,114 live bytes while verifying
checksum 111,600. The fixed-sync-flush encoder now writes directly into the
connection-owned output list and resets retained arena-backed token/hash/history
workspace between no-context-takeover messages. A 2026-08-23 one-connection,
220-exchange rerun reduced allocator calls from 1,791 to 33 and cumulative
allocation from 11,885,411 to 231,619 bytes for complete 4 KiB messages. The
sixteen-fragment form likewise used 33 calls and 231,707 cumulative bytes; both
retained about 114 KiB live at report time. A failing-allocator regression
proves that a warmed fragmented encode performs no further caller-allocation.

```sh
taskset -c 0 zig build bench-websocket-echo -Doptimize=ReleaseFast

zig build-exe -OReleaseFast -lc \
  --dep websocket --dep counting_allocator --dep zio \
  -Mroot=benchmarks/reference/websocket_zig_echo.zig \
  --dep build \
  -Mwebsocket=/home/passchaos/Work/websocket.zig/src/websocket.zig \
  -Mcounting_allocator=examples/support/counting_allocator.zig \
  --dep zio_options \
  -Mzio=zig-pkg/zio-0.17.0-xHbVVI_jJQC3YbgU7JydwAV7MuASkOTd73YqBaKlFFUz/src/zio.zig \
  -Mbuild=benchmarks/reference/websocket_zig_build_options.zig \
  -Mzio_options=benchmarks/reference/zio_options.zig \
  -femit-bin=/tmp/bench-websocket-zig-echo
taskset -c 0 /tmp/bench-websocket-zig-echo --tcp-nodelay
```

The reference driver now obtains its client-side `std.Io` and clock from zio.
The audited `websocket.zig` server continues to use its own public blocking
worker API; this is retained as a reference-library behavior rather than
misreported as a zio server. The cross-library numbers below predate the driver
migration and remain historical Threaded evidence.

Twenty alternating CPU-0 samples with TCP_NODELAY enabled on both clients:

```text
netz:
  9.146-10.537 us/roundtrip
  median 9.501 us, trimmed mean 9.539 us

websocket.zig:
  13.231-14.406 us/roundtrip
  median 13.630 us, trimmed mean 13.702 us

netz latency advantage:
  1.435x by median, 1.436x by trimmed mean
```

A CPU-0 `ReleaseFast` regression run on 2026-09-04 after adding two-phase
admission measured 9.513 us/roundtrip, 105,117 roundtrips/s, and 822.44 MiB/s
of uncompressed-equivalent wire throughput. Handshake time is excluded, so the
sample confirms that the new pre-101 control path did not alter the established
frame hot path; it is not presented as a new throughput improvement.

The websocket.zig public client defaults to Nagle enabled and writes its masked
header then payload separately. Five default-socket samples were about
41.09-41.38 ms/roundtrip, while netz's vectored header+payload submission was
10.26-10.71 us in that run. This roughly 3,915x cliff is specifically Linux
Nagle/delayed-ACK interaction, not a broad library ratio. `strace -f -c`
recorded about 442 netz sendmsg calls versus 443 reference sendmsg plus 228
writev calls for 220 total exchanges. The tuned TCP_NODELAY comparison above is
the primary implementation result.

### Four concurrent persistent connections

The same benchmark accepts `--connections=4`. All clients finish 20 warmup
exchanges, wait on one start event, then execute 200 measured round trips each.
Aggregate latency divides wall time to the slowest client by all 800 measured
round trips; handshake, warmup, shutdown, and joins remain outside the timed
interval. Both processes were restricted to CPUs 0-7.

```sh
taskset -c 0-7 zig build bench-websocket-echo \
  -Doptimize=ReleaseFast -- --connections=4
taskset -c 0-7 /tmp/bench-websocket-zig-echo \
  --tcp-nodelay --connections=4
```

Twenty alternating samples:

```text
netz:
  3.788-4.802 us aggregate/roundtrip
  median 4.150 us, trimmed mean 4.173 us
  median 240,993 roundtrips/s, 1,885.51 wire MiB/s

websocket.zig:
  4.912-5.653 us aggregate/roundtrip
  median 5.212 us, trimmed mean 5.221 us
  median 191,883 roundtrips/s, 1,501.28 wire MiB/s

netz aggregate-latency advantage:
  1.256x by median, 1.251x by trimmed mean
```

### Mixed payload and higher-concurrency coverage

Both checked-in echo harnesses now accept `--mixed` and use the identical
deterministic `1, 7, 125, 126, 1024, 4096`-byte schedule. This crosses the
RFC 6455 7-bit/16-bit payload-length boundary while retaining tiny control-like,
medium and 4-KiB application messages. Reports use the exact 200-iteration
schedule rather than multiplying by an average, and both sides verify the same
payload checksum. The websocket.zig fixture's fixed 16-entry benchmark arrays
were replaced with bounded dynamic storage and its connection cap was raised to
256, matching netz. Passing `--latency` now records every measured exchange
and reports p50, p99 and p99.9 separately for each payload size. Sampling is
opt-in so ordinary throughput and allocator runs retain their previous
instrumentation shape.

Three CPU-0..31 runs at 64 concurrent persistent connections produced:

```text
netz:
  0.940-0.988 us aggregate/roundtrip
  1,011,630-1,063,066 roundtrips/s

websocket.zig:
  1.274-1.406 us aggregate/roundtrip
  710,848-784,670 roundtrips/s

netz advantage:
  1.289-1.496x across the observed throughput ranges
```

All runs verified 22,753,024 logical payload bytes and checksum 4,846,784. The
netz harness now gives its blocking handlers an unlimited async resource limit;
the former default could strand connections above the host's CPU count behind
handlers waiting for their next echo. The websocket.zig reference uses its
blocking worker implementation, and its fixed 16-entry benchmark bookkeeping
was replaced with bounded dynamic arrays. Both harnesses now permit 256
connections rather than imposing an artificial 16-connection ceiling.

Five alternating CPU-0..31 runs at 128 connections with `--mixed --latency`
extended the equal-shape evidence beyond the earlier 64-connection point. All
runs verified 45,506,048 logical payload bytes and checksum 9,762,432. Median
aggregate results were 1,283 ns/roundtrip and 779,291 roundtrips/s for netz,
versus 1,639 ns and 610,007 roundtrips/s for websocket.zig, a 1.28x throughput
advantage. Median-of-run per-class latency percentiles were:

```text
payload   netz p50/p99/p99.9 us   websocket.zig p50/p99/p99.9 us
1 B       96.6 / 426 / 1777       154.6 / 487 / 2180
7 B       88.7 / 345 / 783        148.5 / 460 / 1252
125 B     93.0 / 430 / 1264       149.7 / 645 / 2900
126 B     92.2 / 325 / 1570       149.6 / 436 / 2280
1024 B    95.4 / 333 / 813        154.0 / 496 / 2381
4096 B    98.9 / 439 / 970        157.6 / 513 / 1509
```

Netz is lower at every reported class/percentile in this five-run summary.
The sample count per class is also printed (4,224 or 4,352 here), making
schedule or aggregation drift visible rather than silently comparing different
distributions.

The maximum shared 256-connection setting also completed three alternating
CPU-0..31 latency runs. Median aggregate results were 1,062 ns/roundtrip and
941,113 roundtrips/s for netz versus 1,394 ns and 717,186 roundtrips/s for the
reference, a 1.31x advantage. All runs verified 91,012,096 logical payload
bytes, checksum 19,800,064, and matching per-class sample counts of 8,448 or
8,704. Per-run tail values remain scheduler-sensitive at this saturation
level, so the 128-connection table above is the detailed class comparison.

One `strace -f -c` run recorded about 1,768 netz `sendmsg` calls. The
reference recorded about 1,772 `sendmsg` plus 892 `writev` calls: its client
still sends mask/header separately from payload. Tracing perturbs latency, so
these counts explain submission shape but are not timing samples.

Server handshake policy also includes an optional exact Origin allowlist for
both HTTP/1.1 Upgrade and RFC 8441. When configured, a missing, duplicate, or
non-matching Origin is rejected before the successful handshake; leaving the
list empty preserves native-client behavior. The MQTT adapter exposes the same
policy for WS and WSS, and its Mosquitto-derived process gate ports the raw
allowed/denied request shape from `13-websocket-bad-origin.py`.
Any WSS client can opt into the vail transport to retain and expose the
authenticated server certificate chain; a client certificate remains optional.
mTLS servers expose the verified client chain through
the same `peerCertificates()` API. Both vail-backed endpoint roles expose TLS
exporter keying material for channel binding plus typed negotiated cipher-suite
and transcript-hash metadata. Cleartext and Zig standard-library TLS paths
return null rather than claiming unavailable negotiation details.
Vail-backed WSS additionally exposes RFC 8446 application traffic-key updates
and counters. A client/server mTLS test requests a reciprocal update and then
exchanges a complete WebSocket message under the rotated epochs.
An ordinary-client test exercises the same metadata, exporter and reciprocal-
update path without presenting a client certificate.
The same vail WSS option object carries `stapled_ocsp` and `request_ocsp` into
the shared TLS verifier. Status requests default on; mandatory policy rejects
missing or invalid staples before the HTTP Upgrade request is emitted.
RFC 8441 connections forward the complete peer-chain, ALPN, cipher/hash,
exporter, KeyUpdate and counter API to their shared parent HTTP/2 TLS
connection, so an application cannot accidentally inspect or rotate only one
logical WebSocket stream.
`interop-websocket-hyper-h2` now runs both h2c and TLS modes. In TLS mode the
audited Hyper fixture uses rustls to request KeyUpdate before RFC 8441 setup;
netz verifies the server certificate, `h2` ALPN and typed suite/hash, derives an
exporter through the WebSocket object, compares it byte-for-byte with rustls's
independent output, returns exactly one update, and then
completes fragmented text, Ping/Pong and bounded Close on the rotated keys. The
netz client obtains `std.Io` from the zio-backed runtime, and the runner requires
the terminal records to identify `zio-std-io` and `hyper-tokio`.

Active Ping waits on HTTP/1, RFC 8441 and RFC 9220 tolerate unsolicited or stale
Pong payloads as RFC 6455 section 5.5.3 permits. Only a payload matching the
probe completes the wait. Unrelated Pongs are consumed under the original
absolute deadline, including already buffered frames, while application data
and peer Close details retain their owned event delivery. One shared reader
keeps this behavior consistent across transports. Real TCP tests verify timeout
continuation without a second Ping; the external Hyper RFC 8441 fixture sends
an unsolicited Pong and application data before its matching reply over h2c
and certificate-verified TLS, and checks that netz preserves their order.

Both stream WebSocket and RFC 8441 adapters now expose absolute-deadline frame
reads plus `closeWithTimeout`. A close step sends Close at most once, consumes
interleaved Ping/Pong frames under one non-renewing deadline, and returns either
the owned peer Close details or an owned text/binary/continuation frame that was
already in flight. Applications can process returned data and call another
bounded step without duplicating Close. Tests cover silent peers, control-frame
trickling, successful close details, in-flight data, WSS, and HTTP/2 extended
CONNECT. This is stricter shutdown liveness than the audited websocket.zig
close helper, which writes Close and closes the socket without waiting for a
peer response. Both TCP/WSS and RFC 8441 close senders encode the bounded
125-byte control payload in stack storage, avoiding a transient allocation at
the shutdown boundary. RFC 8441 now uses that fixed-buffer path for every Ping,
Pong and Close frame, including automatic Pong and Close replies. A fresh H2
tunnel no longer allocates or retains `send_frame_buffer` capacity merely to
exchange control traffic. Ordinary and compressed-fragment application writes
now use borrowed server payloads or bounded client masking, so the H2 adapter no
longer owns a send-frame growable buffer. A bidirectional compressed-fragment
regression, including a 64-KiB fail-after-warmup case, verifies message bytes,
frame boundaries and no post-warmup caller allocation after removing that field.
The same bounded batch/stream fallback handles uncompressed fragmentation; a
40-KiB bidirectional test crosses the 16-KiB masking boundary. A
real h2c test checks a client Ping, server Pong and
bidirectional Close while both sides retain zero send-frame scratch. A
CPU-0-pinned 4-KiB echo run after this change measured 33.075 us/roundtrip and
236.20 logical MiB/s; this is a regression sample rather than a new
cross-library comparison.

Both HTTP/1 Upgrade/WSS and RFC 8441 connections now expose relative-timeout
counterparts for frame, owned-message, and caller-buffer message receives. One
absolute deadline continues through fragmented messages and interleaved control
frames. Partial wire frames, the owning message assembler, caller-buffer offsets,
compression mode, and incremental UTF-8 validation remain resumable after a
timeout; caller-buffer retries must present the same storage so already written
bytes cannot be silently lost.

Bounded receives on HTTP/1, RFC 8441, and RFC 9220 also carry that same
deadline through automatic Pong and peer-Close echo writes. Each connection
retains a separately encoded automatic control frame, its stable client mask,
and the exact transport-visible cursor. A retry completes only the unsent
suffix before reading again. Frame-oriented APIs additionally retain and return
the already parsed peer Ping or Close exactly once, while message-oriented APIs
resume the hidden reply and continue assembling the application message; this
includes RFC 9220's caller-buffer receive path, whose automatic-control resume
now runs before its unrelated-writer guard. All
other writers return `WriteInProgress` while this transaction is pending.
If a bounded application/Ping/Close writer already owns a partial wire prefix
when the peer control frame is parsed, the automatic reply queues behind that
specific transaction instead of discarding the peer event. Only the original
same-payload or same-descriptor retry may complete the earlier frame; new
writers remain blocked. The next matching receive then emits the queued reply,
preserving one total byte-stream order across concurrent reader/writer tasks.
Applications that intentionally send Pong outside the automatic receive path
also have `sendPongWithTimeout` and `sendPongWithDeadline` on HTTP/1, RFC 8441,
and RFC 9220. They report the same complete-frame `MessageWriteProgress`, keep
one client mask across retries, reject a different payload while partial, and
resume only the unsent transport-visible suffix.
The same transports expose send-only `sendPingWith*`, `sendCloseWith*`, and
nullable `sendCloseFrameWith*` forms for event loops that own peer-response
polling. Unlike `pingWith*` and `closeWith*`, these methods stop once the local
control frame commits. H2/H3 Close completion includes the request-stream FIN;
all variants retain exact control bytes and mask state across timeout.
Bounded fragmented sends are exposed as `sendFragmentedWithTimeout` and
`sendFragmentedWithDeadline` on all three transports. Their O(1) pending state
retains the caller's descriptor-array identity, current fragment index, current
frame header/mask and cumulative wire cursor; it never copies the whole
fragment list. A timeout can therefore occur inside any header or payload and
resume only that suffix. Each later fragment receives its own client mask,
compressed messages retain the connection-owned compressed scratch and RSV1
only on their first frame, and compression expansion falls back to the original
fragment payloads. A different descriptor array returns `WriteInProgress`
without advancing transport state.
The mutable client fast path likewise exposes
`sendBinaryInPlaceWithTimeout` and `sendBinaryInPlaceWithDeadline` on HTTP/1,
RFC 8441, and RFC 9220. Deadline and role/extension validation run before the
caller buffer changes. The first accepted attempt generates one mask, applies
it in place once, and retains the header plus exact transport cursor; retries
with the same mutable slice send the already-masked suffix directly. A
different slice is rejected without re-masking or advancing output. The buffer
remains masked after success, preserving the original in-place API contract.
Ping and Close progress also expose timeout and absolute-deadline continuation
forms on both transports. A caller can handle an interleaved application frame
and resume with either its original total deadline or a new bounded wait
without retransmitting the Ping or Close control frame.
RFC 8441 setup now has matching `openWithDeadline`/`openWithTimeout` and
`acceptWithDeadline`/`acceptWithTimeout` entry points. They delegate to the
HTTP/2 Extended CONNECT deadline primitives, so interleaved control frames and
fragmented HPACK cannot renew the handshake budget; client timeout cancels the
uncompleted stream and prevents reuse of ambiguous aggregate decoder state.
Dropping an established RFC 8441 adapter before completing its WebSocket Close
handshake now abandons only that Extended CONNECT stream with
`RST_STREAM(CANCEL)` and releases its parent HTTP/2 stream/window state. A real
h2c regression holds `MAX_CONCURRENT_STREAMS` at one, observes the first
stream's exact reset, then completes a second WebSocket on the same reusable
connection; an ordinarily completed Close remains an idempotent no-op at
adapter destruction.

Caller-connected WebSocket upgrades now expose matching timeout and absolute-
deadline APIs for cleartext plus standard/vail TLS streams. This lets the
public `proxy.socks5` layer bound proxy DNS/TCP/CONNECT and then carry the same
deadline through origin TLS and the HTTP Upgrade without conflating proxy and
origin authority. The independent Python peer verifies WS and hostname-checked
WSS text, Ping/Pong, and bidirectional Close, then reuses the same adoption
surface for MQTT-over-WS/WSS with strict `mqtt` subprotocol negotiation,
CONNECT/CONNACK, PING, and DISCONNECT. Invalid zero budgets close the
caller-supplied stream before returning.

URI clients and redirect chains now accept a first-class SOCKS5 route in
addition to the existing HTTP CONNECT route; configuring both fails before
network I/O. Each redirect authority opens a fresh remote-DNS SOCKS tunnel
under the original absolute deadline, while existing cross-origin policy strips
end-to-end credentials and clears origin TLS tickets as before. A two-authority
independent gate checks one WS redirect plus two WSS reconnect chains, exact
six-tunnel ordering, Authorization isolation, TLS 1.3 hostname verification,
and retained rejection metadata. That gate found and now guards a duplicate
rejection-transport close in the initial adapter implementation.

RFC 9220 URI clients now expose the same SOCKS5 route through HTTP/3 UDP
ASSOCIATE. The URI host remains proxy-resolved while TLS SNI, certificate
identity, `:authority`, Cookie scope, and the Extended CONNECT path remain
bound to the HTTPS origin. One caller deadline spans proxy authentication,
association creation, QUIC/TLS, peer SETTINGS, and the WebSocket CONNECT
response; the shared HTTP/3 transport gate independently proves the underlying
remote-DNS and connection-lifecycle path before the unchanged RFC 9220 codec is
adopted. `zig build interop-websocket-h3-socks5 -Doptimize=ReleaseFast`
then runs the complete independent quic-go exchange through that route:
fragmented masked text, two no-context-takeover compressed messages,
Ping/Pong, and Close 1000/`done`, with certificate verification and proxy-side
`localhost` DNS asserted by the relay.

## Remaining evidence before a broad completion claim

Fatal stream/TLS receive failures now terminate WebSocket ownership across
frame, allocating-message, caller-buffer, Ping and Close receive APIs. Bare TLS
EOF, truncated record headers/payloads, failed record authentication and the
standard TLS client's corresponding errors preserve their original cause while
releasing buffered frames, fragmented messages, compression scratch and pending
outbound state. Later reads, data writes and Ping fail with ConnectionClosed;
no WebSocket Close is fabricated on a failed TLS channel. An authenticated TLS
close_notify without a WebSocket Close also ends the WebSocket abnormally.
`runtime/receive_failure.zig` shares the terminal classification across HTTP/1,
RFC 8441 and RFC 9220, while timeout, cancellation, local allocation failure and
retained-write conflicts stay retryable. Real TLS 1.2/1.3 client/server tests
cover every receive entry point, standard and vail WSS clients, and HTTP/2
allocating/caller-buffer messages after underlying TLS truncation. Existing
stream reset tests retain the per-session termination boundary for HTTP/3.

Local bounded-read interruptions (`Timeout`, `Canceled`, and
`ConcurrencyUnavailable`) retain the incremental receive cursor across TCP,
WSS, RFC 8441 and RFC 9220. TLS 1.2/1.3 keep partial ciphertext without
advancing the authenticated record sequence; WebSocket keeps partial frames,
completed fragments and split UTF-8 state without retiring reads or writes.
An incomplete caller-buffer message requires the same output pointer and
length on retry. A replacement output returns `BufferTooShort` while preserving
the original operation. The standard TLS client's network reader preserves
executor admission failure through `std.Io.Reader`'s erased `ReadFailed`
boundary instead of turning it into a terminal `Unexpected` error.
Socket-backed TLS prefix tests and real WSS/H2/H3 handshake tests cover native
TLS 1.2/1.3 and standard TLS 1.3 clients, inject cancellation and executor
admission failure, resume the same message, receive the following message,
and prove the connection remains writable. Fatal authentication, truncation
and peer stream failures still follow the terminal policy above.

The shared `fuzz-parsers` target feeds bounded arbitrary bytes through
WebSocket frame headers, owned frames, Close payloads and permessage-deflate
extension negotiation. Default tests replay truncations, byte flips and random
inputs; Zig's `--fuzz` mode adds coverage guidance. The companion
`fuzz-stateful` target drives bounded text/binary fragmentation, continuation,
control-frame interleaving, UTF-8 completion, and aggregate message limits.
HTTP/1 Upgrade validation combines repeated field lines and comma-separated
protocol lists, accepts the case-insensitive `websocket` token wherever it
appears, rejects malformed protocol or Connection members, and requires status
101 on the client response path.
Extension offers are likewise scanned to the end across repeated fields on
HTTP/1, HTTP/2, and HTTP/3 before selecting the first supported
`permessage-deflate` alternative. Unknown extensions remain ignorable only
when their token, parameter, and quoted-token grammar is valid; malformed
members after a usable offer and malformed offers presented while compression
is disabled now fail the handshake instead of escaping validation.
Syntactically valid `permessage-deflate` offers with unknown, duplicate, or
invalid-valued parameters are declined independently as RFC 7692 requires, so
a later valid alternative can still be selected without weakening the fatal
RFC 6455 syntax boundary.
Client response validation also combines repeated extension field lines before
checking the exact offer. A null list member beside one negotiated extension is
tolerated, while an unknown server selection or a repeated
`permessage-deflate` selection remains a fatal handshake error.
Quoted extension parameter values are unescaped without allocation before
their RFC 7692 window-size semantics are applied, so legal quoted-pairs remain
interoperable while decoded non-token, non-decimal, leading-zero, and out-of-
range values stay rejected.
The dedicated `fuzz-websocket-compression` target feeds arbitrary bounded bytes
to the RFC 7692 inflater and verifies exact round trips through the standard and
Vort compressors, including fragmented plaintext and every negotiated 8-15 bit
window. `fuzz-websocket-context` adds independent directional RFC 7692 state
machines, retained and explicitly reset histories, fragmented and repeated
messages, output-limit rollback, hostile compressed sequences, and every
negotiated window. A Python zlib continuous-stream vector independently proves
that the second message consumes prior-message history and fails after reset.
`fuzz-websocket-h1-context`, `fuzz-websocket-h2-context`, and
`fuzz-websocket-h3-context` now drive the same bounded operation sequences
through real loopback HTTP/1 Upgrade, RFC 8441 Extended CONNECT, and
authenticated QUIC/TLS RFC 9220 sessions. The H1/H2 companion TLS targets
add certificate-pinned WSS and RFC 8441 sessions, mandatory `http/1.1`/`h2`
ALPN, fixed AES-128-GCM/SHA-256 negotiation, and bidirectional TLS 1.3
KeyUpdate accounting. Both directions retain context while
the input selects text/binary, contiguous/sliced/fragmented/deadline sends,
owned/caller-buffer receives, and interleaved Ping/Pong. The H2 path
additionally traverses SETTINGS negotiation, DATA framing, and stream/
connection flow control; H3 traverses the TLS handshake, peer SETTINGS, QUIC
packet protection and STREAM transport. Their lockstep model fixes message
cardinality and applies a five-second bound to every read, so fuzz input cannot
manufacture a peer wait. HTTP/1 loopback tests also cover its opt-in
takeover handshake, bidirectional history, compression fallback, API mixing,
and partial-write resume; RFC 8441 and RFC 9220 endpoint tests cover the same
state across their flow-controlled transports. The public compressor now has
an explicit preview/commit/discard boundary: expansion fallback or an abandoned
write can discard the preview without advancing the retained dictionary, while
commit is allocation-free after preview. The shared runtime compression scratch
now owns the same preview transaction, supports stateful decode directly into
caller storage, and can observe fragmented raw-frame messages solely to advance
the receive dictionary. HTTP/1, H2, and H3 invoke those boundaries at their
transport commit points while retaining both `*_no_context_takeover`
parameters as the default negotiation policy.

The shared policy now lives in `compression/policy.zig` and exposes
`context_takeover = .none | .client | .server | .both`, naming the WebSocket
endpoint whose compressor may retain history. HTTP/1, RFC 8441, RFC 9220 and
URI options carry this policy through pending handshakes. An explicit value
overrides `allow_context_takeover`; null retains that shorthand and the default
no-context behavior. The server direction requires the corresponding
no-context flag when restricted; a client may choose stateless sends locally
even when the server omits its client-side flag. A permitted direction can
still agree to a stricter peer offer. Twenty-four loopback combinations select each policy
from either endpoint across all three transports. They inspect negotiated
flags and independently inflate actual messages with Zig's standard decoder:
only the retained-history direction's second message depends on its first.
Exact-offer validation additionally requires the server to acknowledge an
offered `server_no_context_takeover`, as RFC 7692 section 7.1.1.1 specifies.
The client-only offer flag remains a hint as section 7.2.1 specifies, so a
permissive client can use the final agreed parameters. Real TCP regressions
also emulate a peer omitting that hint and verify stateless sends under local
no-context policy. Alternative offers are checked separately so response
parameters cannot be assembled from incompatible alternatives.

All TCP/TLS and RFC 8441 timeout APIs derive awake-clock deadlines once at
entry, while their absolute-deadline counterparts now reject other clock
domains before sending Ping/Close or mutating incremental receive state. The
HTTP/3 adapter applies the same validation before pumping QUIC.
The authenticated HTTP/3 adapter now also applies this contract to RFC 9220
session establishment itself. Client connect APIs preserve one absolute
awake-clock timestamp across QUIC/TLS, peer SETTINGS, Extended CONNECT, and
the response head. Before a successful response transfers receive-loop
ownership to the WebSocket session, the client now flushes that HEAD's pending
delayed ACK under the same absolute deadline. This lets a short-lived server
finish its reliable response drain even though a successful CONNECT stream
remains open; a 1200-byte-MTU regression with 80 request and 80 response fields
failed consistently before the fix and completed in three consecutive focused
runs afterward. Server accept APIs preserve the deadline across the first QUIC
Initial, TLS, peer SETTINGS/request processing, and the complete 200 response
write, including response-head pacing. An exhausted-pacer regression gives the
server only one nanosecond, requires zero sends and zero sleeps on timeout, then
retries the same pending decision successfully after restoring transport
capacity. Existing
HTTP/3 sessions expose matching bounded adapter entry points. A cross-phase
regression completes QUIC/TLS, withholds CONNECT past the original deadline,
and verifies that the server does not start a fresh post-handshake budget.
URI entry points accept a complete HTTPS URL and derive DNS target, SNI,
authority, and the raw path/query while retaining HTTP/3's multi-address
fallback. Their timeout/deadline forms keep that same absolute budget through
resolution, every QUIC/TLS attempt, SETTINGS, and the CONNECT response.
Direct-address and URI clients also expose attempt variants that preserve a
non-2xx Extended CONNECT status, owned response headers, bounded body, and
trailers for application authentication, redirect, or retry policy. The
compatibility connect helpers continue to map those responses to
`InvalidResponse` after draining the entity. Caller-owned HTTP/3 sessions
expose matching attempt variants; abandoning an incomplete attempt resets only
its CONNECT stream, while a fully consumed rejection restores the session
without a redundant cancellation.
HTTP/3 WebSocket connections now expose the same typed Ping and Close progress
events as HTTP/1 and RFC 8441. Timeout/deadline continuations return in-flight
application frames with ownership and resume without retransmitting the control
frame; peer Close code/reason metadata remains owned until event deinit. Strict
passive Close receives likewise expose untimed, timeout, and absolute-deadline
forms, while `sendCloseFrame(null)` supports a valid metadata-free Close.
RFC 9220 active Close now carries that deadline through outbound HTTP/3 DATA
submission as well as the peer wait. If flow control or pacing expires after a
packet-sized prefix, the connection retains the one encoded frame and its
client mask plus the exact committed byte offset; `continueClose*` sends only
the remaining suffix. Other application/control sends are rejected once this
Close starts, and FIN is considered sent only after its packet reaches the
socket. A real-handshake, five-byte STREAM-fragment regression forces a partial
Close timeout and verifies one exact code/reason after continuation.
Calling `closeWith*` again while that frame is pending must supply the same
code/reason; a mismatch returns `WriteInProgress` before another QUIC packet or
HTTP/3 DATA contribution is emitted.
RFC 9220 connections also expose `waitForRecoveryIdleWithTimeout` and
`waitForRecoveryIdleWithDeadline` for short-lived owners. A terminal peer Close
flushes its cumulative ACK before delivery, while the explicit connection-wide
drain drives ACK/loss/PTO processing until reliable HTTP/3 DATA is acknowledged
and then flushes any final ACK under the same absolute budget. A deterministic loopback
test drops the first client Close datagram and requires PTO retransmission, the
exact echoed code/reason, and empty client/server recovery queues before either
connection is destroyed.
RFC 9220 binary scatter/gather sends now expose matching
`sendBinarySlicesWithTimeout` and `sendBinarySlicesWithDeadline` entry points.
They retain one frame header and client mask, track the exact socket-visible
RFC 6455 byte prefix across HTTP/3 DATA chunks, and rebuild only a bounded
16-KiB wire segment from the borrowed application slices on each retry. The
caller keeps the same slice descriptor array and its payload bytes stable until
completion; an equivalent but different descriptor array is rejected with
`WriteInProgress` before another send. A real TLS/QUIC regression crosses empty
and non-empty slice boundaries, resumes after a partial timeout, verifies one
complete masked frame at the server, and also exercises the unmasked server
direction.
HTTP/1 Upgrade/WSS and RFC 8441 expose the same bounded scatter/gather API and
retry contract. They preserve one header, one client mask, and a cumulative
wire cursor while rebuilding only a bounded output chunk from the original
slices. TCP/TLS and HTTP/2 DATA flow-control progress therefore resume without
joining the application payload or duplicating a frame prefix; mismatched
descriptor arrays are rejected before further output. Tests force partial TCP
writes and a five-byte HTTP/2 connection/stream window, then verify exact
masked client frames and unmasked server responses, including compressed
multi-slice messages.
RFC 8441 now applies the same rule at the HTTP/2 DATA boundary. A bounded Close
stores its encoded bytes and one client mask, records only complete DATA bursts,
and lets `continueClose*` finish the exact suffix plus END_STREAM before waiting
for the peer. A real CONNECT regression exhausts both HTTP/2 send windows after
five bytes, rejects application sends during the partial Close, restores credit,
and verifies one exact masked Close code/reason at the server. Re-entering
`closeWith*` with different metadata is rejected without consuming restored
flow-control credit or changing the committed cursor.
Both multiplexed transports now publish `close_sent` only after the complete
Close frame and request-stream FIN are committed. Until then, ordinary frame
and message receives, data/control sends, and connection KeyUpdate return
`WriteInProgress`; this mirrors HTTP/1's transport-safe pending state rather
than reporting a completed close prematurely.
Bounded RFC 8441 Ping uses the same one-mask, exact-offset discipline without
closing the write half. A partially submitted Ping returns `WriteInProgress`
for different retry/continuation payloads and unrelated frame sends; either
the original `pingWith*` entry point or `continuePing*` completes the matching
suffix, then restores ordinary application writes after the Pong arrives.
RFC 9220 Ping now has the same property across paced HTTP/3 DATA submission. A
fixed-clock real-handshake regression times out after a packet-visible prefix,
retains one mask and cursor, rejects a mismatched retry or application
write, and leaves receive state untouched until that Ping is continued; it then
completes the exact suffix and receives the matching Pong.
RFC 9220 also matches the HTTP/1 and RFC 8441 arbitrary-slice binary send API:
server frames retain scatter/gather input through HTTP/3 DATA framing, clients
apply one continuous mask through bounded scratch, and negotiated compression
consumes the slices without allocating a joined plaintext message.
Single-frame HTTP/1 Upgrade/WSS, RFC 8441, and RFC 9220 text and binary sends
additionally expose timeout and absolute-deadline forms.
`MessageWriteProgress` reports the
cumulative RFC 6455 frame-byte prefix; a retry keeps the same caller payload,
mask, header, and compression scratch, so neither the WebSocket prefix nor
application bytes are replayed. Unmasked servers retain borrowed payload
slices, while clients rebuild only the current masked suffix in fixed 16-KiB
scratch. Cleartext HTTP/1 progress is the exact socket-accepted prefix. TLS
progress is deliberately record-aligned: both standard-library and vail TLS
retain partial ciphertext in connection-owned storage and count its plaintext
only after the complete record reaches the socket, preventing nonce reuse or
duplicate WebSocket bytes across a retry. Real H2 flow-control and H3 pacing
regressions parse the resumed wire bytes as one exact masked frame; HTTP/1
chunk-boundary tests independently fix the one-mask suffix reconstruction
contract.
Bounded TCP and WSS sends also retain their exact transaction after local
executor admission failure (`ConcurrencyUnavailable`). Native TLS 1.2/1.3
preserve the already-encrypted record and its nonce, matching the standard
TLS client's retained ciphertext behavior. A timer admission failure racing
an already-completed socket write still reports that accepted prefix.
Socket-backed regressions cover interruption before any write, partial record
headers and ciphertext, and the boundary between two authenticated records.
Real WS/WSS exchanges cover binary slices, in-place masking, compression
context takeover, Ping/Pong, Close and automatic replies across all client TLS
backends. Resuming commits one message/control frame; the next message and
read remain usable, while genuine network write errors still retire native
TLS records.
HTTP/1 bounded Ping and Close use the same retained-frame transport path. A
timeout keeps the encoded header, client mask, payload, and committed cursor;
the matching `continuePing*` or `closeWith*`/`continueClose*` call writes only
the suffix. Different Ping payloads or Close code/reason values, application
sends, receives, and TLS KeyUpdate return `WriteInProgress` while a control
frame is incomplete. `close_sent` becomes visible only after the entire Close
frame is transport-committed. Real TCP and standard-WSS regressions split both
control frames across transport writes and parse exactly one reconstructed
masked frame at the peer.
Its caller-buffer receive APIs likewise assemble uncompressed messages directly
into application storage, reuse connection-owned compressed input/inflater
scratch, and preserve partial-frame plus completed-fragment progress across
timeout, cancellation and executor admission retries while requiring the same
output buffer for resumed messages.
RFC 8441 and H3 clients additionally expose `sendBinaryInPlace`: callers
opting into mutable post-send storage avoid the immutable client's masking
copy, matching the HTTP/1/reference API while keeping safe `[]const u8`
alternatives. The synchronous H2 tunnel send consumes the borrowed masked
payload before ownership returns even when flow control divides it into DATA.
All H3 message, fragmentation, control, Close, and key-update send entry points
serialize complete write sequences. This protects compression scratch and stops
concurrent callers from interleaving one RFC 6455 frame across HTTP/3 DATA.
The authenticated H3 server connection also reads its established Extended
CONNECT stream through a targeted request-event API. A ready sibling HTTP/3
request therefore remains queued for its own consumer instead of being
mistaken for malformed WebSocket traffic; the real handshake exchange test
interleaves such a sibling, completes its 204 response, and continues the
WebSocket data/control/Close sequence on the original stream.
All HTTP/1, RFC 8441, and RFC 9220 application-send entry points now also
apply `Limits.max_frame_bytes` and `Limits.max_message_bytes` before acquiring
the send mutex, allocating compressor scratch, or mutating an in-place client
buffer. This includes text, binary, two-slice binary, and fragmented messages;
fragmented sends bound every caller-selected frame and their logical aggregate.
Ping, Pong, and Close additionally obey the configured frame bound as well as
RFC 6455's 125-byte control-frame limit, matching receive-side enforcement.
Configured-limit failures consistently return `MessageTooLarge`, while only
unrepresentable aggregate wire lengths retain `PayloadTooLarge`. A shared
validation matrix, transport-specific pre-I/O tests, and a real TCP exact-limit
exchange cover these boundaries. The audited Tungstenite configuration applies
its similarly named frame/message limits only to incoming data; netz deliberately
uses one symmetric resource policy for both directions.
Protocol-level receive failures now terminate the receive half consistently on
HTTP/1/WSS, RFC 8441, and RFC 9220. When no older outbound transaction owns the
wire, the adapter emits the mapped Close; retained input, fragmented-message,
caller-buffer cursor, and decompression storage are released in either case,
and later receive calls return `ConnectionClosed` instead of reparsing the same
hostile frame prefix. New application/Ping/Pong writes also fail closed. If an
existing outbound transaction or an error-Close write prevents safe framing,
the TCP transport or only the affected Extended CONNECT stream is aborted and
its pending send storage is released. Timeout and HTTP/2 early-response conditions remain
resumable and retain their existing state. RFC 9220 owned-message completion
uses the same single-owner decompression finalizer as HTTP/1 and RFC 8441, with
an allocator-backed regression for compressed text that inflates to invalid
UTF-8. RFC 8441 retained DATA frames are released through the parent HTTP/2
connection allocator that created them, including zero-length DATA, ordinary
consumption, fatal receive cleanup, and connection teardown; a split-allocator
regression guards this ownership boundary.
Unbounded outbound operations follow the same rule: because they expose no
cursor from which an application can safely resume after an ambiguous partial
write, data, mutable in-place, explicit control, and automatic control failures
retire the HTTP/1 byte stream or only the affected H2/H3 CONNECT stream. The
bounded deadline variants retain their exact prefix cursor and remain resumable.
Deterministic closed-peer/retired-stream regressions verify the terminal state,
pending-storage release, and multiplexed parent-connection reuse.
HTTP/1 WSS additionally rejects TLS KeyUpdate after protocol failure or either
Close direction becomes terminal. RFC 8441 and RFC 9220 keep their connection-
level KeyUpdate APIs available because healthy multiplexed siblings may still
share the parent H2/H3 transport.
HTTP/1, RFC 8441, and HTTP/3 writers also validate connection Close state after
acquiring their send mutex, so a sender queued behind Close cannot append a
data or control frame after the closing handshake has begun. Ping and Close
deadline APIs revalidate their absolute budget after lock contention. Close
flags use acquire/release atomics because a sole receive owner and concurrent
application writers may observe those transitions on different threads.
Owned Close diagnostics now take over the already-allocated frame payload on
HTTP/1, RFC 8441 and RFC 9220. Typed Close reads, Ping waits and close-handshake
waits no longer allocate a second reason buffer after consuming the terminal
frame, so local memory pressure cannot lose an otherwise decoded diagnostic.
The reason remains owned beyond receive-buffer reuse and connection teardown;
`OwnedCloseFrame.deinit` releases the original allocation. Empty Close payloads
still produce no diagnostic, and frame-allocation failure preserves input for
retry. Direct `Frame.takeClose` validates before ownership transfer and leaves
an invalid frame owned by its caller.
Automatic PONG and Close replies retain an already-consumed control frame even
if the client's secure mask-key source fails during reply preparation. The
same receive API retries preparation without losing the original frame or
delivery mode. After encoding succeeds, partial or failed bounded writes keep
the same mask and byte cursor. A local Close suppresses an unsent reply while
still delivering the retained peer frame once. Borrowed message readers keep
the original input bytes until preparation succeeds, so they also resume
without dropping a PING or Close.
Allocating receives on every transport preserve `was_compressed` provenance
after decompression, so callers and concurrency regressions can distinguish an
RSV1 message from an uncompressed fallback without inspecting wire storage.
The HTTP/1 Upgrade regression also drives two writers through the negotiated
permessage-deflate encoder concurrently and accepts either complete-message
order while requiring exact decompressed payloads.
HTTP/3 receive paths now use the same RFC 6455 failure mapping as HTTP/1 and
RFC 8441, sending 1002 for malformed framing, 1007 for invalid text, and 1009
for configured frame/message limits while preserving the original local error.
Cleartext server acceptance likewise exposes timeout and absolute-deadline
forms for the complete HTTP/1.1 Upgrade after TCP accept, while preserving a
stricter configured handshake limit. Already accepted HTTP/1 connections can
be upgraded with either a relative timeout or caller-owned deadline. WSS server
acceptance carries that budget through both TLS 1.3 and HTTP Upgrade, with each
configured phase timeout able to shorten but never renew it; already-accepted
TLS streams expose the same relative and absolute forms. Unix-domain WebSocket
listeners expose the same post-accept Upgrade deadline contract without
applying TCP-only socket options.

1. **Completed at 128 connections:** the equal-shape mixed-payload benchmark
   now reports per-class p50/p99/p99.9 and retains matching checksum/sample
   counts. The maximum 256-connection setting also completes with matching
   accounting and a 1.31x median aggregate advantage; use longer runs when
   investigating scaling beyond these short saturation samples.
2. **Completed for 128 mostly-idle cleartext connections:** compare buffer-pool
   behavior and peak memory while all connections remain established. The
   reference exposes explicit small/large buffer pools. The
   netz echo benchmark now accepts `--stats` and reports thread-safe allocation
   counts, cumulative bytes, peak live bytes and size buckets. Four cleartext
   connections used 54 allocations and 52,784 peak live bytes in the captured
   smoke; one connection used 15 allocations and 13,196 peak live bytes. Four
   compressed connections used 106 allocations and 1,139,720 peak live bytes,
   dominated by sixteen retained 64-KiB codec windows. Add equal telemetry to
   the websocket.zig harness and extend beyond 16 mostly-idle connections before
   making a memory ratio. The fixed 16-connection benchmark bookkeeping has
   since been replaced by bounded dynamic arrays and the cap raised to 256 in
   both harnesses. Equal 64-connection mixed-payload telemetry initially
   recorded 1,095 allocations and 851,974 peak live bytes for netz versus 402
   allocations and 683,242 peak live bytes for websocket.zig. The dominant
   difference was ArrayList's geometric growth retaining roughly 6.5 KiB for
   each 4,104-byte cleartext frame. The TCP receive path now grows retained
   storage to the exact delivered byte count while preserving reuse. A matched
   rerun used 572,420 peak live bytes for netz versus 683,242 for websocket.zig
   (16.2% lower); netz also ended before deferred connection teardown with
   286,592 live bytes versus 363,580 (21.2% lower). Exact growth causes more
   small allocation/remap events across the mixed schedule, so the result is a
   resident-memory advantage rather than an allocation-count claim. Three
   matched 128-connection mixed runs then produced identical telemetry on every
   repetition: netz used 1,145,860 peak live bytes and ended with 575,232 live
   bytes, versus websocket.zig's 1,311,690 peak and 671,932 final live bytes.
   Netz therefore retained 12.6% less at peak and 14.4% less at report time at
   twice the earlier concurrency. It made 2,823 allocation calls versus 595,
   preserving the explicit trade-off: exact growth lowers resident memory but
   intentionally performs more small allocator operations. Receive growth now
   rounds only to a bounded 256-byte slab. This coalesces the common split
   frame-header/payload reads while retaining at most 255 bytes of slack per
   connection, instead of returning to ArrayList's geometric over-allocation.
   A 64-connection mixed smoke kept the same 1,095 allocation count but lowered
   peak live bytes from 652,544 with a 512-byte slab prototype to 619,520; it
   also reduced exact-growth event sizes from the earlier audit. Three matched
   256-connection runs were likewise byte-stable: netz used 2,290,692 peak and
   1,150,464 final live bytes versus websocket.zig's 2,528,794 peak and
   1,286,588 final bytes, reductions of 9.4% and 10.6% at the maximum supported
   benchmark concurrency.
   `zig build bench-websocket-mostly-idle -Doptimize=ReleaseFast` now makes the
   distinct mostly-idle question reproducible. It pins clean websocket.zig
   revision `efa87973`, alternates execution order, hashes both binaries, and
   rejects mismatched topology, activity, workload, checksum, runtime identity,
   allocator scope, or snapshot phase. In each arm all 128 HTTP/1 WebSocket
   connections complete the Upgrade and a one-byte classification echo; only
   eight then perform two warmups and twenty measured 4-KiB round trips. The
   allocator snapshot is taken while every connection remains live and before
   any Close or transport teardown. Two independent three-sample runs were
   byte-stable: netz retained 340,480 bytes at both the live snapshot and peak,
   while websocket.zig retained 1,317,836 bytes (3.871x netz) at both points.
   These counters cover same-process client-plus-server explicit allocations.
   Separate BusyBox `time` MaxRSS medians were 38,912-39,936 KiB for netz
   and 160,256-160,768 KiB for websocket.zig (4.013-4.132x); that whole-process
   result includes runtime and thread-stack cost but still excludes kernel
   socket memory. The reference's blocking server uses one OS thread and a
   4,128-byte receive buffer per connection, while netz uses zio tasks and grows
   retained receive storage on demand. The two memory scopes remain separately
   labeled rather than being combined into one ratio.
   HTTP/1, RFC 8441, and RFC 9220 connection state now store their mutually
   exclusive resumable application message, Ping, and Close transactions in
   one shared tagged-union design. With the obsolete Zig-flate receive window
   removed, `runtime.Connection` falls from 1,968 to 1,536 bytes and
   `runtime.H2Connection` from 2,000 to 1,568 bytes: 432 bytes less fixed state
   for every live H1 connection or RFC 8441 tunnel (22.0% and 21.6%). The H3
   client/server connection types likewise fall from 18,944/18,352 to
   18,512/17,920 bytes, saving 432 bytes per RFC 9220 tunnel (2.3%/2.4%).
   Automatic Pong/Close state remains separate because a receive owner may
   queue it behind an older application write. Layout assertions and the
   existing exact-suffix, queued-auto-Pong, control-frame, and fatal-cleanup
   regressions guard these reductions and that concurrency contract. This is
   inline connection-state evidence; it is not folded into the explicit-
   allocator or throughput ratios above.
   The post-change bidirectional quic-go gate passed the full fragmented-text,
   no-context-takeover compression, Ping/Pong, Close, key-update, and QUIC
   v1/v2 matrix on 2026-10-02.
3. Keep the external Autobahn gate current.
   `zig build interop-websocket-autobahn -Doptimize=ReleaseFast` runs the
   digest-locked Autobahn Testsuite 25.10.1 fuzzing client against the dedicated
   long-lived netz echo endpoint. Passing `--tls` runs the identical cases over
   native TLS 1.3 WSS using the checked-in localhost test identity. On
   current builds the listener obtains `std.Io` from zio and uses the runtime's
   bounded long-running supervisor with 64 reusable accept/connection workers;
   the runner rejects a server that does not identify `server_io=zio-std-io`.
   The extracted report verifier rejects duplicate JSON keys, unexpected or
   additional agents, missing statuses, disallowed status values, and any full
   run that differs from the versioned 25.10.1 manifest's exact 517 case IDs,
   including a count-preserving missing/unknown substitution. The manifest
   records the upstream source revision, image digest, group boundaries, total,
   canonical case-ID digest, and the exact expected non-OK statuses. Unlisted
   cases must report `OK` for both behavior fields, so an arbitrary regression
   to otherwise accepted `NON-STRICT` or `INFORMATIONAL` can no longer pass.
   Explicit case selections remain a non-empty manifest subset and each
   selected case must match the same status baseline. The runner defaults to
   Docker and accepts `AUTOBAHN_CONTAINER_RUNTIME=podman` or an absolute
   compatible runtime path; digest-locked image inspection, host-network
   execution, mounted reports, and strict manifest verification remain
   identical. A container-free local mode accepts absolute `AUTOBAHN_WSTEST`,
   `AUTOBAHN_TESTSUITE_PACKAGE`, and `AUTOBAHN_PYPY_ARCHIVE` paths. It requires
   the official Testsuite 25.10.1 wheel SHA-256
   `b57ee6b22de624a03256878ad453c9897d2ad7ee08a4c38b35ee2847637e1383`,
   official PyPy 2.7 v7.3.20 aarch64 archive SHA-256
   `f22a1be607deeaa4f9be6bc63aae09fe4fb5b990d6a23aa4e7c5960dc5d93c96`,
   extracted interpreter SHA-256
   `49e7090077ad56808642d5a73a44bd8b293780058c0203e6f90a8f9abed1beba`,
   exact Autobahn 0.10.9/Testsuite 25.10.1 version output, a byte-for-byte
   comparison of all 195 installed suite files with the wheel, and the
   checked-in complete dependency freeze. The measured environment's canonical
   freeze SHA-256 was
   `87915f06ebb80622877b2257302bf75988fbe245a05b4e58266a85875b922a6c`.
   This preserves executable-environment identity on the aarch64 host where
   the published digest-locked image is amd64-only and no Docker/Podman runtime
   is installed. The real-socket smoke remains green over cleartext and TLS
   with eight concurrent peers plus protocol-error isolation and worker reuse,
   while the strict report-checker unit suite passes 14/14. The separate
   `interop-websocket-autobahn-smoke` gate uses real cleartext and TLS sockets
   without Docker: eight simultaneous peers verify masked text/binary echo,
   Ping/Pong and Close. A separate connection interleaves Ping/Pong inside a
   fragmented text message, completes it through Continuation, and verifies the
   aggregate echo. Another connection negotiates permessage-deflate with both
   no-context-takeover parameters; an independent Python raw-DEFLATE encoder
   sends a compressed message across Continuation with an interleaved Ping,
   then a fresh inflater validates each of two compressed echoes. An unmasked
   takeover-enabled connection then repeats an incompressible 4-KiB binary
   message through persistent Python compressor/inflater contexts; its second
   compressed echo is rejected by a fresh inflater, proving that the server
   really reused prior-message history rather than merely accepting the
   parameter. An unmasked frame requires Close(1002), invalid UTF-8 requires
   Close(1007), and a fresh successful connection after each failure proves
   the listener and reusable worker remain healthy.
   A proposed raw-zlib `server_max_window_bits=9` extension to this smoke was
   rejected rather than retained: a compliant server may fall back to an
   uncompressed echo when the 512-byte window expands the selected payload,
   while Python's raw-DEFLATE inflater accepts long-distance streams even when
   constructed with `wbits=-9`. It therefore cannot independently prove the
   emitted LZ77 distance bound. Small-window correctness remains covered by
   the direct codec/differential tests and historical Autobahn manifest, not
   overstated by this socket smoke.
   The smoke still checks the independently useful transport boundary: it
   requires exact `client_max_window_bits=9` and `server_max_window_bits=9`
   response parameters, sends through a 9-bit Python compressor, and receives
   a compressed binary echo over both cleartext and WSS. That is negotiation
   and roundtrip evidence only; it is deliberately combined with, rather than
   substituted for, the direct distance-bound tests.
   On 2026-10-16, the locked local runner completed all 517 cases against the
   zio-backed server over WSS with behavior counts `OK=514` and
   `INFORMATIONAL=3`, and close-behavior counts `OK=514` and
   `INFORMATIONAL=3`. The cleartext run likewise completed all 517 cases with
   behavior counts `OK=514` and `INFORMATIONAL=3`;
   close-behavior counts were `OK=514` and `INFORMATIONAL=3`. The 54
   compression cases previously reported as `UNIMPLEMENTED` now complete as
   `OK`: the server echoes `server_max_window_bits=9` when offered and bounds
   every emitted LZ77 distance to that negotiated 512-byte window. The
   four fail-fast UTF-8 cases previously reported as `NON-STRICT` are also now
   `OK`: invalid text is rejected as soon as the decisive byte arrives, even
   before the current frame or a fragmented message has completed. The
   runner accepts only the exact per-case baseline, reports every non-OK case,
   and exits unsuccessfully for regressions, `UNIMPLEMENTED`, failures,
   missing, or unknown statuses. Optional case IDs select a faster focused run
   without weakening those expectations. This is
   external RFC 6455/RFC 7692 conformance evidence for both cleartext HTTP/1.1
   Upgrade and WSS. RFC 8441 now has the separate Hyper process gate described
   above, although it is a focused lifecycle check rather than the 517-case
   Autobahn suite. The remaining three non-OK Autobahn results are
   inherently
   informational in Testsuite source: 7.1.6 explicitly allows implementation-
   defined close ordering, while 7.13.1 and 7.13.2 state that behavior for
   private-use close codes 5000 and 65535 is undefined. They are reported by
   that category rather than inflated into a 517-case pass claim.
4. Add an equal-wire compressed echo comparison if the reference re-enables
   its currently disabled outbound compressor; until then the netz timing is
   only an internal baseline.

The handshake capacity audit now includes real 80-request / 80-response-field
round trips for HTTP/1 Upgrade, RFC 8441, and RFC 9220. HTTP/1 uses its explicit
100-field request/response limits and a 16-KiB head budget; HTTP/2 uses its
256-field and 16-KiB header-list limits. HTTP/3 uses a 1200-byte QUIC datagram
limit with 64-byte never-indexed values, so success requires actual STREAM
fragmentation rather than QPACK repetition. The H3 client completes the normal
attempt-to-connection promotion after inspecting all 80 response fields, while
the server independently verifies all 80 request fields. H1/H2 capacity tests
live under `runtime/handshake/` instead of enlarging the existing handshake
header test file. The shared HTTP/1 and RFC 8441 handshake policy now lives
beside those tests in `runtime/handshake/headers.zig`: singleton lookup,
reserved/framing-field validation, legacy RFC 8441 rejection, extension
selection, and duplicate-aware subprotocol preference are no longer embedded
in the roughly ten-thousand-line runtime root. Private aliases retain existing
call and test shapes; the public API is unchanged and the root is about 270
lines smaller.
HTTP/1 Upgrade, RFC 8441, and RFC 9220 request/success-response descriptor
assembly now shares `runtime/handshake/storage.zig`: up to 16 fields remain on
the stack and larger sets use one exact allocation. HTTP/1 rejection fields and
the Host-completion writer use the same policy. The storage test proves the
common path under an allocator that rejects every allocation and verifies the
first overflow reports OOM; the three 80+80 wire tests cover each fallback.
Subprotocol offer serialization uses a 128-byte stack buffer, while duplicate
token detection uses 16 stack slots before exact fallback; H1, RFC 8441, and
RFC 9220 now share that grammar and preference implementation.
Client-side H1, RFC 8441, and RFC 9220 request construction also rejects an
exact duplicate in the configured preference list before serializing any
header bytes, while preserving case-sensitive protocol identity. Incoming
`1#token` lists ignore RFC 2616 null members but still reject a field set with
no actual subprotocol.
On the response path, all three transports accept RFC 6455's null subprotocol
selection even when the client offered preferences. Applications that require
an application protocol can set `require_subprotocol`; unsolicited or malformed
server selections remain handshake failures.
Final isolated `bench-websocket-echo --stats` smokes reported 18 allocations /
9,916 peak live bytes at one connection and 51 / 39,664 bytes at four
connections, identical
to the immediately preceding descriptor-only run. Latency was 9.224 and 9.733
us/roundtrip respectively. This is no-regression evidence; whole-connection
telemetry is dominated by other retained allocations and does not isolate the
removed temporary handshake buffers.

HTTP/1 clients now expose `ConnectAttempt` through direct-address and WS/WSS URI
helpers, with relative/absolute deadline variants. A non-101 final
response retains owned status, headers, decoded chunked trailers, and a body
bounded by `Limits.max_rejection_body_bytes`; the transport is closed before a
direct address attempt returns. `requireAccepted` maps a valid 426 with a
repeated or comma-separated version advertisement excluding 13 to typed
`UnsupportedVersion`; missing, malformed, or contradictory advertisements and
other non-101 responses keep the established `InvalidResponse` mapping.
Successful attempts preserve bytes coalesced after the 101 head and transfer
them without another copy into the WebSocket receive buffer. Bodyless interim
1xx responses are skipped under the same absolute deadline and
`Limits.max_informational_responses` bound.
Successful 101 responses reject `Content-Length`, `Transfer-Encoding`, and
`Trailer` on both the server writer and client validator; caller-supplied
server fields are checked before the transactional writer changes its output.

HTTP/1 rejected-response retention now checks body boundaries before allocating
the response copy. An excessive declared Content-Length, buffered chunk-size
prefix, or EOF-delimited body returns `BodyTooLarge` without body I/O or a
rejection-buffer allocation. Complete fixed-length and chunked entities retain
only their own wire bytes, including trailers; bodyless responses discard all
coalesced successors. EOF-delimited reads share HTTP/1's bounded collector,
which reads at most the remaining quota plus one overflow-detection byte under
the original absolute deadline. Accepted 101 heads and coalesced WebSocket
frames still transfer their original allocations even with a zero rejection
body limit. The adjacent handshake regressions cover fail-first allocation,
exact and zero limits, entity boundaries, trailers, and ownership transfer.
The focused WS/WSS, Unix, proxy, redirect and MQTT WebSocket handshake matrix
passes 239 tests in both Debug and ReleaseFast; package API reachability passes
its two tests.
