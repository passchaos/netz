# netz WebTransport parity audit

This audit compares netz with the WebTransport implementations available under
`~/Work`: `quicz` and modern Rust `wtransport`. It records wire-version
differences explicitly because draft WebTransport stream association changed
over time.

## Current direct evidence

Run:

```sh
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
zig build bench-webtransport-datagram -Doptimize=ReleaseFast
zig build bench-webtransport-stream -Doptimize=ReleaseFast
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- --send-all
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- --send-all --stream-slices=8
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- --send-all --enable-gro-receive
zig build interop-webtransport-stream-churn -Doptimize=ReleaseFast
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast
zig build interop-webtransport-wtransport-churn -Doptimize=ReleaseFast
zig build interop-webtransport-chrome -Doptimize=ReleaseFast
WEBTRANSPORT_ORIGIN_ONLY=1 zig build interop-webtransport-chrome -Doptimize=ReleaseFast
```

The external interoperability gate builds the audited `~/Work/wtransport`
checkout at `d96cbb8` and exercises both directions over real TLS
1.3/QUIC/HTTP/3 connections. Every netz process in the native interop,
benchmark, loss, and reorder gates now runs on zio behind the `std.Io` protocol
boundary. Machine-readable success records bind netz endpoints to
`zio-std-io` and the independently maintained Tokio/Quinn peer to
`wtransport-quinn-tokio`; strict verifiers reject legacy or mismatched backend
identities. The local incremental stream benchmark also creates its backend
explicitly and schedules the receiving peer with `std.Io.async`, rather than
creating an OS-thread worker. The wtransport-client/netz-server half verifies a
successful Extended CONNECT at `/interop`, bidirectional DATAGRAM exchange, a
client-created bidirectional stream and its reverse direction, client- and
server-created unidirectional streams, mapped application-code 71
RESET_STREAM, code 72 STOP_SENDING, a bidirectional sibling already active
when cancellation occurs, and a `CLOSE_WEBTRANSPORT_SESSION` with code 77/reason
`netz done` in the Chrome gate. Because wtransport 0.7 does not expose peer
session-close metadata, its native client instead validates netz's QUIC
application close code 77/reason `netz done`. The netz-client/wtransport-server
half repeats CONNECT, DATAGRAM,
both stream directions, mapped reset code 73, mapped stop code 74, and
same-session sibling completion, then waits for and validates the server's QUIC
application close code 0/reason `interop complete`. Session
close capsules and connection-level shutdown remain separate typed APIs, so the
gate cannot mistake a clean CONNECT-stream FIN for a peer connection close.
Immediately before its detailed close, netz now sends WT_DRAIN_SESSION on the
same ordered CONNECT stream. The audited wtransport driver has no public drain
event and treats this capsule as unknown, but receiving the following exact
close code/reason proves it skipped DRAIN without losing capsule framing. The
response stream is now opened before each peer sends STOP_SENDING, and the
receiver withholds its reply until it observes that cancellation. In the
netz-client half, the first mapped STOP_SENDING datagram is deliberately
dropped; the peer can release the sibling only after QUIC retransmits it. This
also exposed and fixed a transport-progress bug: a blocking WebTransport
DATAGRAM receive now services loss/PTO timers instead of sleeping indefinitely
while its own recoverable control packet is outstanding. The gate exposed four
cross-stack assumptions now covered in production code: Client Finished can
follow an Initial ACK in the same UDP datagram, modern peers may omit the older
Capsule-Protocol and per-session stream-limit settings, and HTTP/3 critical
stream IDs must not be hidden from WebTransport association based only on
their numeric values.
Both native endpoint roles now expose the negotiated WebTransport application
payload limit as `maxDatagramSize`, subtracting QUIC DATAGRAM framing and the
session-ID prefix. The underlying QUIC query also subtracts the current path
MTU's short-header, adaptive packet-number, and AEAD overhead rather than
reporting only the peer's DATAGRAM frame allowance. The gate compares this
with wtransport's corresponding API
and requires both implementations to reject an allocation-backed payload one
byte above their independently reported limit before continuing normally.
Handshake-backed WebTransport client/server sessions also expose the negotiated
TLS cipher suite and transcript hash together with QUIC key-update initiation,
local/peer generation counts and the outstanding ACK gate. The same APIs are
forwarded by the stateful protected client wrapper; metadata comes from the
shared authenticated QUIC connection rather than per-session guesses.

The Chrome gate drives the browser's real `WebTransport` API through
Puppeteer, not a native QUIC substitute. It generates a fresh P-256 localhost
identity because the browser's `serverCertificateHashes` exception requires a
certificate validity period of at most two weeks. The server receives the
same zio-backed netz server binary and its success records identify the browser
side as `chromium-network-service`, avoiding a false wtransport runtime label.
The server receives the
origin page's dynamically allocated `http://localhost:<port>` serialization as
an exact allowlist and verifies the browser-generated Origin before accepting
CONNECT. Before that allowed run, a second netz listener deliberately trusts a
different Origin, returns 403, and the same browser page must observe
`transport.ready` rejection. The allowed run then verifies CONNECT,
DATAGRAM, bidirectional and unidirectional streams, RESET_STREAM code 71,
STOP_SENDING code 72, sibling reuse, and clean session close. Chrome coalesces
its Handshake Finished and first 1-RTT control-stream packet in one UDP
datagram; netz now retains that short-header suffix through the blocking TLS
transition instead of silently dropping the peer's HTTP/3 SETTINGS. Chrome
also correctly omits the server-facing ENABLE_CONNECT_PROTOCOL setting from
its client SETTINGS, so WebTransport negotiation treats that setting as a
directional server capability while still requiring the client's WebTransport
and H3 DATAGRAM advertisements.
The browser also checks the resolved `transport.closed` value exactly: close
code 77 and reason `netz done`, after a netz DRAIN immediately followed by
CLOSE_WEBTRANSPORT_SESSION and CONNECT FIN. Chromium exposes no drain event,
so this proves ordered capsule consumption rather than application visibility
of the advisory signal. A cleanly resolved promise alone is not counted as
evidence for CLOSE_WEBTRANSPORT_SESSION metadata propagation.
It additionally requires Chrome's real
`WebTransportDatagramDuplexStream.maxDatagramSize` to be a positive negotiated
limit, while the netz peer performs its own one-byte-over-limit rejection.

`run-webtransport-handshake-stream` now covers one real QUIC/TLS handshake,
HTTP/3 SETTINGS and extended CONNECT negotiation, then:

- client-opened bidirectional stream with server reverse-direction echo,
- client-to-server unidirectional stream,
- server-to-client unidirectional stream,
- caller-buffer incremental reads before FIN with immediate flow-credit return,
- mapped 32-bit RESET_STREAM and STOP_SENDING lifecycle events,
- runtime WT_DRAIN_SESSION/WT_CLOSE_SESSION send and receive over the
  long-lived Extended CONNECT stream,
- session/transport stream limits and stream-ID direction validation,
- shared HTTP/3 request/WebTransport bidi and push/WebTransport uni ID
  allocation, preventing sibling protocol stream collisions.

The existing handshake runtime test combines those stream paths with a
WebTransport DATAGRAM round trip and transport statistics.

## Feature comparison

| Area | netz | `~/Work/quicz` | `~/Work/wtransport` |
| --- | --- | --- | --- |
| CONNECT / SETTINGS | Handshake, protected and dev runtimes; every server exposes a two-phase request object with authority/path/origin/header inspection, custom success headers, and typed 403/404/429 or generic 3xx-5xx rejection. Every client can send validated custom CONNECT headers, retain accepted response metadata, and opt into an attempt API that preserves non-2xx status, headers, bounded DATA, and trailers. Every pending server type can emit the complete rejection entity. CONNECT metadata uses a 16-field stack-first view with exact allocation fallback instead of fixed 57/62 additional-field ceilings; SETTINGS_MAX_FIELD_SECTION_SIZE remains the byte limit. Server acceptance enforces one RFC 6454 Origin across every runtime: the secure default permits native clients to omit Origin but requires any explicit value to match the CONNECT scheme/authority with canonical host/default-port handling; exact cross-origin allowlists and an explicit allow-any policy are available. Duplicate, empty, malformed, opaque `null`, and unapproved cross-origin values cannot reach a 2xx response. Handshake and protected CONNECT streams remain open for Capsule Protocol traffic | Codec/session helpers | Production async endpoint/session with request inspection, Origin policy, and accept/reject methods |
| DATAGRAM | Dev, protected, real-handshake, batch receive, payload budget/stats | Codec/session counters | Production send/receive |
| Bidirectional streams | Real-handshake and stateful preconfigured-key open/send, reverse direction, whole-FIN compatibility receive plus caller-buffer incremental and stream-ID-targeted reads, reset/stop, lifecycle/limits and per-send-stream priority; the cleartext development runtime also supports both initiators, reverse-direction data, fragmented modern `0x41` association, coordinated IDs, per-session limits, and timeout/deadline-bounded whole-FIN receive; standalone stateful sessions expose timeout/deadline-bounded opens, sends, packet writes, FIN, RESET_STREAM, and STOP_SENDING backed by QUIC credit/recovery; bounded batch writes select higher-priority streams first with stable equal-priority order; a concurrent sibling survives cancellation loss in external interop | Session registry and old-draft prefix codec | Production async bidi streams with read/reset/stop and Quinn-backed send priority; interoperates with netz while another stream is being cancelled |
| Unidirectional streams | Real-handshake and stateful preconfigured-key operation in both directions, incremental and stream-ID-targeted reads, mapped reset/stop, lifecycle/limits and send priority; the cleartext development runtime supports both initiators, fragmented `0x54` association, coordinated IDs, per-session limits, and timeout/deadline-bounded whole-FIN receive; standalone stateful sessions expose bounded open/send/write/FIN/reset/stop operations; a deterministic preconfigured-key regression drops the first associated-stream datagram and requires cross-stream reorder plus exact recovery, while external interop drops netz's first STOP_SENDING and requires exact-code peer observation | Session registry and header codec | Production async uni streams with read/reset/stop and send priority; exact mapped codes are verified against netz |
| Close/drain capsule codec | Real-handshake and protected runtime send/receive, split frame/capsule parsing, clean-FIN close and UTF-8/1024-byte validation; authenticated and stateful sessions expose bounded reliable-delivery drains so short-lived owners can wait for CLOSE/FIN acknowledgement and PTO recovery; detached successful CONNECT streams accept DATA and unknown extension frames but reject known forbidden and HTTP/2-reserved frame types with connection-level H3_FRAME_UNEXPECTED; real-handshake SESSION_GONE stream cleanup; Chrome consumes netz DRAIN before an exactly validated WebTransport CLOSE, while native wtransport consumes DRAIN before a separately validated QUIC application close | Close codec/state; audited session helper handles close/drain but accepts bare capsule fallback | Session close lifecycle; current driver has no DRAIN API/event, but its unknown-capsule path interoperably skips netz DRAIN before the following terminal event |
| Stream association wire format | Modern `0x41` frame type + Session ID; uni `0x54` + Session ID | Audited code writes only Session ID for bidi streams | Modern `0x41` + Session ID and `0x54` + Session ID |

The cleartext development client/server now keep the Extended CONNECT request
and response directions open after acceptance and expose the same incremental
Capsule control surface used by the lightweight protected runtime. Clients and
servers can send and receive caller-buffer session DATA, DRAIN, detailed CLOSE,
and clean FIN; receive operations have relative-timeout and absolute awake-clock
deadline forms. Development DATAGRAM sends also have matching timeout/deadline
entry points; one caller deadline is validated again after encoding and before
the single UDP write, so expiration cannot emit a datagram. Development
session DATA, DRAIN, CLOSE, and the automatic FIN response to a peer CLOSE now
share bounded send entry points. Their lightweight cleartext transport cannot
recover an exact socket-visible prefix after a multi-packet write: expiration
before the first UDP attempt is retryable and reported by
`DevelopmentBodyWriteProgress`, while any later failure deliberately
fail-closes that send direction instead of risking duplicate Capsule bytes.
Pending peer terminal events remain owned until bounded FIN cleanup either
succeeds or transitions to this explicit terminal failure. Associated
bidirectional/unidirectional sends use the same timeout/deadline contract for
both the first association prefix plus payload and later payload-only writes.
An ambiguous visible-prefix failure retires only that stream in the
WebTransport registry, leaving sibling streams usable; zero-attempt timeout
leaves the prefix flag, byte count, and FIN state unchanged. Partial HTTP/3
frames and partial capsules remain resumable after timeout. Malformed control
capsules cancel the CONNECT stream with H3_MESSAGE_ERROR, while a known
non-DATA frame after successful CONNECT closes the connection with
H3_FRAME_UNEXPECTED. Unknown extension/grease frames are still skipped as
required by HTTP/3. Parser tests cover every known forbidden type and all four
HTTP/2-reserved code points; a stateful QUIC regression also observes the exact
application close code and reason on the peer. Server receive routing includes
the peer address so two
development clients may independently use request stream zero. Associated
bidirectional and unidirectional streams now use the same packet pump, modern
`0x41 + Session ID` / `0x54 + Session ID` prefixes, peer-and-session routing,
shared HTTP/3 stream-ID cursors, bounded FIN-complete reassembly, and
`StreamRegistry` local/peer limits. The development surface intentionally
does not claim the stateful runtime's flow control, recovery, incremental
reads, RESET_STREAM, or STOP_SENDING guarantees. It remains a deterministic
adapter for codec, routing, and lifecycle integration tests.

CONNECT request and success-response assembly is centralized under
`runtime/connect/headers.zig`. Common requests stay on a 16-field stack buffer;
larger valid sets allocate exactly once, with allocation failure occurring
before a 2xx response can become observable. Development, lightweight
protected, and authenticated handshake tests each exchange 80 request and 80
response application fields. Protected and handshake cases use an explicit
1200-byte datagram limit and never-indexed 64-byte values, exercising real
STREAM fragmentation instead of relying on repeated-field compression. A
separate small-budget test rejects the same
shape with `ExcessiveLoad`, confirming that the protocol boundary is the peer's
`SETTINGS_MAX_FIELD_SECTION_SIZE`, not an adapter-specific field count. The
admission and capacity tests live beside that helper under `runtime/connect/`
instead of adding more flat runtime siblings.

development/test transport with no QUIC handshake, authentication, encryption,
or congestion recovery; production users should use the handshake-backed
runtime.
Session teardown releases every fully associated receive stream and local or
reverse send entry for that CONNECT. A prefix that is still incomplete cannot
yet be attributed to one session, so it is retained while any same-peer session
remains active. Definitive peer retirement—no request lifecycle, response body,
or associated send entry—then removes those otherwise-unclassifiable prefixes
and the peer stream-ID cursor. IDs therefore remain monotonic without reuse for
the complete live-peer lifetime, while long-lived servers bound cursor and
partial-prefix storage by active peers rather than historical address churn.
The handshake-backed endpoint applies the same ownership boundary: while a
CONNECT is detached, a client-initiated bidirectional stream with a fragmented
modern `0x41` prefix remains in QUIC storage until WebTransport claims it,
whereas an ordinary HEADERS-prefixed sibling remains routed as HTTP/3. A real
two-connection endpoint regression exchanges DATAGRAMs, bidirectional streams,
and close capsules on both sessions under bounded receive deadlines. Both
endpoint roles also preserve a RESET_STREAM that overtakes its fragmented
association prefix, so the WebTransport layer reports the mapped terminal
event instead of the generic HTTP/3 router consuming it.
The development HTTP/3 pump is also the sole UDP reader for both CONNECT DATA
and QUIC DATAGRAM traffic. It retains each DATAGRAM frame independently—even
when a packet also advances a control stream—in configurable count and raw-byte
budgets with oldest-drop semantics. A disabled queue intentionally drops
unreliable DATAGRAMs, while a packet exceeding a nonzero byte budget is
rejected explicitly; a slow consumer therefore cannot starve control progress
or create an unbounded queue.

Authenticated and lightweight protected client/server sessions also expose
timeout- and absolute-deadline-bounded DATAGRAM and DATAGRAM batch sends; the
authenticated sessions additionally expose bounded batch receive, incremental stream, whole-FIN
stream, DRAIN/CLOSE, and peer connection-close receive calls. Outbound
DATAGRAM batches prevalidate every payload and future packet size before the
first UDP submission, then report the exact socket-visible input prefix through
`committed_count`; packet numbers consumed by protected but unsent suffixes are
never reused. HTTP/3 encodes the Quarter Stream ID prefixes and payloads into
registry-owned reusable backing storage before submission rather than allocating
each datagram independently. Lightweight protected sessions retain equivalent
WebTransport, QUIC-payload, and protected-packet scratch, so equal-or-smaller
batches allocate nothing after warmup. Shared-endpoint sessions expose the same operation as
one socket-batch attempt without reading the shared socket, while standalone
sessions transparently continue across the transport's bounded 64-packet batch
window. Lightweight batches are deliberately one transport batch (at most 64
items) because that runtime has no recovery state: packet numbers advance for
the complete protected batch while `committed_count` reports only the socket-
visible prefix, making suffix retry nonce-safe. Tests cover whole-batch prevalidation, partial `sendmmsg` completion,
nonce-safe packet-number gaps, exact statistics, ordered bidirectional runtime
delivery, and more than one batch window. Their
development and lightweight protected facades expose
`maxDatagramPayloadSize` plus a zero-returning `maxDatagramSize` convenience
form. The result accounts for the QUIC DATAGRAM type/length, WebTransport
Quarter Stream ID, and, for protected packets, short-header CID, fixed
four-byte packet number, and AEAD tag. Real UDP tests send the exact 4092-byte
development and 4067-byte protected limits for 4096-byte endpoints, then prove
that limit-plus-one is rejected before a socket call; protected rejection also
leaves the packet number unchanged.
`sendSessionDataSlicesWithTimeout` / `sendSessionDataSlicesWithDeadline`
methods submit borrowed Capsule Protocol slices directly through HTTP/3 DATA
packetization without first joining them. `BodyWriteProgress.committed_bytes`
is the exact socket-visible prefix over the logical concatenation, including
when a packet crosses slice boundaries, so a timed-out caller can rebuild and
send only the remaining suffix; `fin_committed` separately records the final
stream transition. Invalid budgets reset progress before returning and emit no
packet. A bounded batch uses one
deadline for every requested DATAGRAM, returns any prefix received before the
deadline, and records the terminal timeout in the next batch error slot. One
absolute application deadline spans unrelated QUIC packets while earlier PTO,
delayed-ACK, keep-alive, path-validation, idle and close timers continue to
run; neither transport maintenance nor control traffic renews the caller's
budget.
Authenticated standalone sessions now expose symmetric
`sendDatagramWithTimeout` / `sendDatagramWithDeadline` calls. They wait for
QUIC congestion and pacing capacity while using the existing HTTP/3 packet
visitor, so ACK progress cannot bypass control/QPACK, associated DATAGRAM, or
detached CONNECT routing. Timeout retains no hidden application queue and does
not increment the sent-DATAGRAM count; callers may retry explicitly. The
stateful protected client facade forwards the same API. Shared-endpoint
sessions instead expose `trySendDatagramWithTimeout` /
`trySendDatagramWithDeadline`: these never read the shared UDP socket and
return congestion or pacing backpressure so the sole
`EndpointServer.receive*` owner can route packets or service its pacing timer
before retrying the same absolute deadline. The endpoint's plain
`sendDatagram` is likewise a single attempt rather than a hidden blocking
convenience loop. The underlying
QUIC recovery path also distinguishes ACK-eliciting, in-flight DATAGRAM
packets from retransmittable payload: a lost pure DATAGRAM causes a fresh PING
PTO probe, while a mixed STREAM+DATAGRAM packet retains only the reliable
frames. RFC 9221 application bytes are never replayed.
Standalone `HandshakeClientSession` and `AcceptedHandshakeSession` stream opens
now have matching timeout and absolute-deadline forms. Registry capacity and
the cumulative per-session WebTransport limit are preflighted before either a
QUIC or shared HTTP/3 stream-ID cursor advances; successful commit is then
allocation-free. Client bidirectional IDs remain coordinated with the HTTP/3
request cursor, and server unidirectional IDs with the HTTP/3 push cursor. An
invalid/expired deadline consumes neither registry state nor transport ID; the
focused stateful-preconfigured test also covers successful bounded opens when
initial transport credit is available. QUIC-level tests separately exercise an
actual wait for a cumulative `MAX_STREAMS` update. Standalone sessions expose
matching bounded send, packet-sized write, and FIN APIs. One absolute awake-clock
deadline covers association-prefix transmission plus every congestion, flow-
control, and pacing wait. Complete sends expose the exact socket-visible
application prefix on error, excluding association bytes, so callers resume at
that offset; a payload may be fully committed while its requested FIN times out.
`sendStreamSlices`, `sendStreamSlicesWithTimeout`, and
`sendStreamSlicesWithDeadline` extend this contract to borrowed scatter/gather
payloads. A packet may carry several consecutive STREAM frames that cross
application-slice boundaries, and a multi-packet send uses the QUIC batch path;
partial socket completion reports one exact prefix over the logical
concatenation so retry never duplicates association or application bytes. The
stateful preconfigured client forwards the same API. Shared-endpoint sessions
provide the one-packet `sendStreamSlices` form, preserving their single UDP
reader/nonblocking contract. The parallel `writeStreamSlices` family consumes
at most one packet-sized logical prefix, crosses slice boundaries without a
join, excludes association bytes from its return count, and has timeout and
absolute-deadline forms for standalone sessions; shared-endpoint sessions
expose the same operation as one nonblocking attempt.
Shared-endpoint server sessions also expose transactional `sendSessionData`
and `sendSessionDataSlices` calls. They submit one HTTP/3 DATA contribution
without reading the shared socket, refresh the dispatcher timer after either
success or backpressure, and leave body length, stream offset, and FIN state
unchanged when the packet is not accepted.
Packet-sized writes never hide application progress on timeout, and FIN is
marked only after its packet reaches the socket. RESET_STREAM also has relative-
timeout and absolute-deadline forms: congestion and pacing are serviced under
the same budget, and the registry records the reset only after socket
submission, so a timeout remains safely retryable. STOP_SENDING now has the
same bounded contract from the QUIC connection through both standalone
WebTransport endpoint roles and the stateful protected client facade. Invalid
or expired deadlines consume no packet number and leave both transport and
WebTransport stop state uncommitted; a later retry sends the exact mapped code.
After STOP_SENDING reaches the socket, standalone sessions discard any
contiguous receive bytes already buffered for that direction and return only
connection-level credit with MAX_DATA. They deliberately do not enlarge the
cancelled stream's MAX_STREAM_DATA window, and clear any stale pending stream
credit. Every incremental, targeted, and whole-stream poll first sweeps all
registered stopped receive directions, so an application waiting only on a
sibling cannot leave connection credit trapped behind cancelled in-flight
DATA. If the ACK carried beside STOP_SENDING is lost, an older associated-
stream prefix can be retransmitted after that sweep has advanced QUIC's
receive cursor. HTTP/3 request and response routing now retain that prefix with
the detached WebTransport owner instead of reclassifying it as a fresh QPACK
or unknown unidirectional stream and attempting to commit an older absolute
offset. Deterministic router regressions cover both endpoint roles, while the
real-handshake DATAGRAM waiter drops the first STOP_SENDING packet and
completes only after recovery. A terminal FIN marks the peer half closed and
requests transport stream
retirement, while RESET_STREAM remains observable exactly once before
reclamation. Because QUIC charges RESET_STREAM's complete final size even when
reassembly still has gaps, that case settles the whole abandoned direction's
connection charge while consuming only the actually contiguous buffer; later
overlap/final-size validation therefore remains intact. Peer RESET_STREAM has
the same connection-credit treatment even without a preceding local stop. Its
code and final size move into the session registry before QUIC reclaims a
terminal stream, so a targeted sibling read can make progress without losing
the reset's later one-shot application event. The generic QUIC stream API keeps
its reset-first/optional-partial-delivery contract; this eager discard is used
only where WebTransport has explicitly abandoned the payload. The one-socket-
submission `stopOnce` form defers this drain to the
next poll so its nonblocking contract remains exact. Small-window regressions
verify both that discarding six of eight bytes emits MAX_DATA without changing
the stream receive limit, and that a targeted sibling read still completes
after the cancelled stream receives later DATA.
The stateful protected client facade also forwards targeted `readStreamId*`
polling and explicit delayed-ACK flushing, removing the last associated-stream
surface differences from its owned handshake session.
`writeStreamsWithTimeout` and
`writeStreamsWithDeadline` extend that contract across a fair priority-ordered
packet batch: every association prefix and the final application batch recheck
one deadline, while the caller's per-stream counts commit only the socket-
visible packet prefix. Shared-endpoint sessions intentionally keep
their socket-free one-attempt contract. Standalone sessions expose
`releaseCompletedPeerStream` to request terminal peer stream credit while
retaining cumulative WebTransport registry accounting. Bidirectional credit is
emitted only after the local FIN/RESET and preceding reliable data are
acknowledged; an early request is completed automatically by the QUIC ACK path.
Released transport stream buffers are reclaimed behind compressed closed-ID
ranges, while WebTransport's registry intentionally retains its separate
per-session lifetime accounting. Stream discovery uses stable ID-based
pagination so reclamation cannot skip a swap-moved active stream. A failed
automatic credit update remains pending and retries through the aggregate QUIC
connection timer without requiring another peer packet. Whole-stream and
incremental WebTransport readers now register transport retirement when FIN or
RESET_STREAM is delivered; local FIN/reset paths do the same, so associated
streams are compacted after both applicable halves become terminal while the
registry continues enforcing lifetime session limits.
Bounded receive entry points validate the caller's awake-clock deadline before
polling already-buffered events. An expired or wrong-clock timestamp therefore
cannot register an association, consume QUIC bytes, return flow-control credit,
allocate a whole stream, or modify caller output before returning `Timeout`.
Shared-endpoint stream opens and explicit peer-stream release are single
attempts: paced STREAMS_BLOCKED/MAX_STREAMS frames return backpressure and arm
the dispatcher timer without consuming a stream ID or release state.
The shared-endpoint poll adapter refreshes its dispatcher timer after every
application-state poll, including null and error results, so a failed
automatic MAX_STREAMS send or protocol-error control work cannot leave a
deadline visible only inside the connection while the single UDP owner blocks
indefinitely.
Its routed-packet boundary performs the same post-adapter synchronization for
accepted, pending, rejected, and newly arriving CONNECT sessions, including
protocol parse errors that replace an earlier QUIC timer with close state.
Endpoint-level `closeConnection` also refreshes the dispatcher before returning
a socket error: QUIC deliberately commits closing state even if its first
CONNECTION_CLOSE datagram cannot be sent, so the shared owner can still expire
that connection after the transport's three-PTO closing period.
The endpoint-accepted
variant is deliberately nonblocking: it only inspects buffered state, sends a
credit update when ready, and refreshes the dispatcher timer without reading
UDP. It now forwards the same authenticated metadata that is valid on the
shared promoted connection: peer-path validation, smoothed RTT, TLS exporter
material, retained peer certificates, negotiated ALPN/cipher suite/transcript
hash, and QUIC key-update initiation plus local/peer generation counts and the
outstanding ACK gate. Borrowed ALPN/certificate slices still belong to the
promoted handshake-backed HTTP/3 session and therefore remain valid only until
the endpoint removes that accepted connection.
The multi-connection endpoint preserves HTTP/3 handshake-worker failures as a
finite typed payload rather than widening them to `anyerror`. In particular,
an expired shared-endpoint admission is observable as `error.Timeout` with its
pending handle after completion handling has released its Initial and
registration, so applications can distinguish admission pressure from TLS or
QUIC rejection.
Client-side shared-endpoint setup has matching timeout and absolute-deadline
forms for the QUIC/TLS handshake plus initial Extended CONNECT write. This
also gives dispatcher owners a finite point at which they may stop routing and
tear down a failed handshake instead of relying on an unbounded worker join.
URI clients inherit HTTP/3's total `connect_timeout`: DNS resolution and each
address-specific QUIC/TLS attempt share one absolute deadline across Initial,
Retry, Version Negotiation, and passive Handshake flights. A real silent-UDP
test verifies the WebTransport adapter reaches that deadline instead of
waiting for the lower-level multi-PTO default. `connectUriWithDeadline` also
accepts an existing absolute awake-clock budget from an application workflow
and preserves it through the final Extended CONNECT response rather than
ending the budget after QUIC/TLS establishment. Direct-address handshake
clients expose the same complete-session deadline, and explicit deadline APIs
retain a shorter configured HTTP/3 connect timeout when present. Matching
relative-timeout helpers convert their end-to-end budget once at API entry.
Authenticated servers expose the symmetric contract: `acceptWithDeadline` and
`receiveSessionRequestWithDeadline` preserve one caller-owned awake-clock
timestamp from the first QUIC Initial through TLS 1.3 and the first Extended
CONNECT request. Relative-timeout forms convert once at entry, while the
existing PTO/recovery budget can still impose an earlier handshake bound. A
cross-phase regression completes QUIC/TLS, withholds CONNECT until the original
deadline expires, and verifies that server admission does not restart its
budget after authentication.
Dispatcher-fed Initial and injected per-handshake datagram-source entry points
expose the same absolute and relative forms. Thus adopting a shared-endpoint
architecture no longer requires giving up the caller deadline or restarting it
between routed Initial processing, QUIC/TLS, and CONNECT admission.
The endpoint handshake worker also sends the server HTTP/3 SETTINGS and QPACK
stream prefixes before promotion, keeping critical-stream initialization out of
the single-owner application callback that later accepts or rejects CONNECT.
Successful endpoint CONNECT admission then uses one packet containing a
literal/static QPACK HEADERS section plus any receive-credit update. Rejection
uses the same one-packet literal encoding with FIN. Pacing, congestion,
flow-control, or MTU rejection leaves the request pending and safely retryable;
oversized admission metadata returns `DatagramTooLarge` instead of partially
publishing a response or introducing a dynamic encoder-stream dependency.
Endpoint request polling likewise makes only nonblocking receive-credit and
QPACK-feedback attempts; queued decoder instructions are drained in packet-
sized prefixes and remain retryable across dispatcher pacing turns.
Dispatcher-driven clients apply the same rule while a WebTransport CONNECT is
pending: routed response packets never wait for QPACK decoder feedback, final
heads remain in QUIC reassembly until receive credit can be committed, and a
rejected response body is delivered once even when its credit update is paced.
Every null poll republishes the connection timer without unregistering its CID
route, so a later endpoint turn can finish feedback, promotion, or rejection.
Malformed request cleanup submits RESET_STREAM and STOP_SENDING atomically in
one packet; if pacing rejects that packet, the parser state remains available
for the next endpoint turn instead of blocking or exposing partial cleanup.
Accepted-session polling applies the same rule to CONNECT capsules and
associated stream data: receive-credit backpressure rolls back parser/registry
state and delays the application event until a later dispatcher turn.
At the QUIC layer, a received STOP_SENDING records its mandatory RESET_STREAM
response and attempts it once. Pacing or transient send failure arms a distinct
dispatcher timer, so packet routing never waits and the reset is not forgotten.
Stale STREAMS_BLOCKED frames follow the same pattern: the current MAX_STREAMS
limits are coalesced into one response attempt and retained behind a dedicated
timer when transport backpressure prevents immediate delivery.
PATH_CHALLENGE responses are also surfaced as immediate endpoint timer work;
each turn submits one padded PATH_RESPONSE to the recorded source address, and
keeps both the challenge and route intact across pacing or send failure.
Outbound PATH_CHALLENGE retries with an explicit transport timestamp now make
one send attempt as well; pacing preserves the pending challenge and gives its
path-validation timer priority over an equal generic pacing notification.

## Important interoperability correction

`~/Work/quicz/src/h3/webtransport.zig` encodes a bidirectional stream prefix as
only the Session ID. The audited `wtransport-proto` implementation defines
`WEBTRANSPORT_STREAM = 0x41` and serializes that special frame type followed
directly by Session ID (without the ordinary H3 payload-length field). Netz
implements and tests the latter format:

```text
session stream id 256 -> 40 41 41 00
                         ^^^^ frame type 0x41
                              ^^^^^ session id 256
```

Accepting only the modern explicit prefix avoids confusing a legacy
Session-ID-only prefix with an ordinary HTTP/3 DATA/HEADERS frame.

## Incremental stream and cancellation evidence

`HandshakeClientSession` and `AcceptedHandshakeSession` expose `readStream`,
`writeStream`, `writeStreams`, `finishStream`, `resetStream`, and `stopStream`.
`readStream`
copies only the next contiguous prefix into caller storage, releases it to QUIC
flow control immediately, and returns data/FIN, RESET_STREAM, or STOP_SENDING
events. Whichever-ready reads resume after the last productive associated
stream through a stable stream-ID cursor, skipping unrelated HTTP/3, whole-read,
and idle streams without allowing one continuously readable stream to starve
its siblings. This supplies the fairness that wtransport obtains from separate
per-stream `accept_bi`/`accept_uni` handles while retaining netz's unified event
API. Standalone `writeStream` waits for positive transport credit but submits
at most one packet-sized application prefix and returns its actual length,
allowing callers to round-robin many active streams; `finishStream` submits FIN
independently. Their `WithTimeout`/`WithDeadline` forms preserve one awake-clock
budget through transport progress and remain retryable after timeout; bounded
`writeStreams` provides the same contract for fair multi-stream batches.
Shared-endpoint `writeStream`, `writeStreams`, `sendStream`, and
`finishStream`, `resetStream`, and `stopStream` instead make one socket-free
attempt and return flow-control, congestion, or pacing backpressure to the sole
`EndpointServer.receive*` owner.
The endpoint `drain` method applies the same single-packet rule to its Capsule
and commits the HTTP/3 body offset and local draining state only after the
packet reaches the socket.
Endpoint `close` likewise sends its CLOSE capsule and FIN once, then advances
at most one associated-stream RESET/STOP per later call or endpoint poll. Each
successful control packet is committed independently, so pacing, congestion,
or socket failure cannot duplicate the capsule or abandon the unsent suffix.
An initial `writeStream` may commit only the association prefix and return zero
application bytes; retrying the unchanged payload after dispatcher progress is
therefore unambiguous. Endpoint `sendStream` is atomic and single-packet, while
larger sends use repeated `writeStream` calls followed by `finishStream`.
The blocking handshake-session `sendStream` write-all helper instead submits up
to 64 consecutive packets for the same stream per socket batch. It snapshots
aggregate connection, stream, and congestion credit rather than the single-
datagram `SendCredit.available()` value, and advances the registry only by the
socket-visible prefix when a batch send is partial. `writeStream` remains a
one-packet operation, so this optimization does not weaken caller-controlled
cross-stream fairness.
`writeStreams` stages one fair packet-sized slice per sendable
stream through QUIC's stateful packet batch, orders candidates by signed stream
priority with stable equal-priority ordering, and commits registry/caller offsets
only for the socket-visible prefix. This provides allocation-free concurrent
stream progress without hiding flow control behind per-stream write-all tasks.
Batch duplicate validation and selected membership use generation marks stored
with the registry's existing stream index, so validation is O(streams), adds no
temporary allocation, and still rejects every item before association-prefix
I/O. Prefix setup retains dynamic per-selection credit checks; once all prefixes
are present, the steady path scans credit once and maintains a fixed top-64
stable priority window instead of repeatedly rescanning all writes. Marking a
stream before prefix transmission also prevents a high-priority prefix that
exhausts its stream window from being selected forever in the same batch. The
implementation and focused white-box tests are grouped under
`runtime/stream/batch.zig` and `runtime/stream/tests/batch.zig`.
The runtime maps
WebTransport's 32-bit application error space into HTTP/3 codes while skipping
reserved codepoints and exposes both mapped and raw values on receive.

The real-handshake test sends 96 KiB through an 8 KiB advertised stream window,
reads it with 2-3 KiB caller buffers before FIN, verifies payload and flow
progress, and then exchanges both reset and stop events. Thus a successful test
cannot be explained by retaining a complete body behind the advertised window.

The benchmark uses one 4 MiB real-handshake bidirectional transfer, a 64 KiB
stream window, and 16 KiB caller storage. Three consecutive CPU-0
`ReleaseFast` runs of the default fair `writeStreams` mode measured:

```text
send API calls:                 1146
caller-visible partial writes: 1146
read events:                    1147
checksum:          534773760
median elapsed:    18.14 ms
median throughput: 220 MiB/s
```

The explicit single-stream `--send-all` mode calls `sendStream` once and uses
the same receive/window configuration. Its three runs measured 246, 247, and
254 MiB/s, with a 16.13 ms median and the same 1147 read events. The median is
about 12% faster than the fair partial-write mode while reducing caller-visible
send API calls from 1146 to one. These 2026-09-07 same-host numbers are an
internal API/path comparison; no equal-wire wtransport/quicz ratio is claimed.

`--enable-gro-receive` now exercises WebTransport's timer-aware state-only QUIC
batch pump. One kernel/GRO receive is decrypted and applied in place, its ACK
decision is accumulated across the packet batch, and `readStream` then returns
one fair associated-stream event from the resulting connection state. It does
not wait for future datagrams merely to fill the caller buffer. Three CPU-0
single-stream runs measured 400, 405, and 408 MiB/s (9.86 ms median), with 362
read events instead of 1147; against the same binary's 237, 243, and 246 MiB/s
non-GRO samples this is about 67% higher median throughput. A four-stream 4 MiB
aggregate smoke completed at 217 MiB/s, and focused tests cover cumulative ACK,
FIN, timeout/resume, and preserving the cross-stream rotation cursor when two
streams arrive in the same GRO batch.
The follow-up caller-buffer GRO path removes the remaining per-batch receive
allocation by growing connection-owned storage once and reusing it. Three
fixed-binary CPU-0 runs of the same 4 MiB shape measured 503, 510, and 514
MiB/s (7.83 ms median), another 26% over the preceding 405 MiB/s median. The
underlying 54-packet QUIC STREAM microbenchmark measured a 688 ns/packet
state-only median versus 1155 ns/packet for the owning GRO batch.

The benchmark now also accepts `--streams` and `--transfer-bytes`. A four-stream
1 MiB-per-stream real-handshake run completed at 70 MiB/s aggregate with 3971
socket-visible partial writes, exercising the batch API rather than four
sequential write loops. The local `wtransport` API exposes independent async
stream writes but no one-call cross-stream packet batch or visible-prefix
commit result.

The benchmark also accepts `--stream-window`, `--one-rtt-datagram-size`, and
`--disable-pacing`. Connection receive credit scales with stream count instead
of the former fixed two-window cap. Three real-handshake runs with four 4-MiB
streams, 1-MiB per-stream windows and 8-KiB datagrams measured 188-195 MiB/s
aggregate, versus the obsolete 26 MiB/s result from the 128-KiB connection-
credit/4-KiB-datagram configuration. Batch validation occurs before any
association prefix is sent, so a bad later stream cannot expose a partial batch.
A CPU-0 64-stream smoke transferred and verified 1 MiB with 320 partial writes
and checksum 133,693,440 after the indexed validation/selection change. Repeated
fixed-binary samples varied from 19 to 40 MiB/s under host scheduling noise, so
they are retained only as completion and no-deadlock evidence rather than a new
throughput baseline.

Accepted stateful server sessions and authenticated/stateful client sessions
now expose dispatcher-oriented
`processPacket`, `pollStream`, `pollCompleteStream`, `pollDatagram`, and
`pollSessionEvent` methods, plus `pollPeerConnectionClose` for connection-level
termination metadata. The poll methods never read UDP: one endpoint owner
routes authenticated QUIC packets, after which each WebTransport session drains
only its own associated stream, DATAGRAM, and detached CONNECT/Capsule state.
Whole-stream polling transfers ownership only after FIN and leaves incomplete
streams in QUIC reassembly. Client packet injection also preserves 0x41/0x54
WebTransport extension streams before HTTP/3's response/push classification,
while continuing to process control and QPACK traffic and flush decoder
feedback. A two-client shared-endpoint test interleaves
same-numbered complete associated streams, DATAGRAMs, and a DRAIN capsule and
verifies that payloads and control events remain isolated by QUIC connection.
A client-side routed-packet test covers incremental and complete associated
streams, DATAGRAM delivery, and DRAIN polling without a second socket reader.
That client path now starts from the public `beginEstablishedConnect` API: it
wraps an authenticated QUIC connection on a caller-owned endpoint, exposes the
stable connection pointer for CID registration, accepts routed packets while
the CONNECT response is pending, and promotes through `pollConnect` without
performing a hidden UDP read. After promotion, the dispatcher pointer is
explicitly replaced because moving the owning state changes its connection
address. The atomic `replaceConnection` operation preserves all CID routes and
timer identity while swapping that pointer, avoiding an unregister/register
gap.
The promoted client session now retains its dispatcher binding. Its stream,
DATAGRAM, Capsule, reset/stop, drain/close, and stream-open operations select
single-attempt transport primitives and refresh the dispatcher timer after
success, backpressure, or parse failure. Blocking receive/service helpers fail
with `InvalidDispatcherState` on this object rather than competing for the
shared UDP socket. Incremental and whole-stream reads preserve transport bytes
until receive credit commits, while terminal cleanup advances at most one FIN,
RESET_STREAM, or STOP_SENDING packet per endpoint turn.
Dispatcher-driven CONNECT polling now binds that invariant before parsing the
response. Abandoning a returned attempt performs at most one cancellation send
and never sleeps or reads UDP; if pacing prevents the terminal frames from
being emitted, local HTTP/3 bookkeeping is still released and the connection
is marked non-reusable instead of returning latent stream state to a pool.
`beginConnectFrom` now composes the preceding phase as well: a sole endpoint
owner can feed a CID-bound handshake inbox, receive a pending WebTransport
CONNECT on the caller-owned endpoint, then register and drive it through the
same dispatcher without an intermediate socket owner or endpoint transfer.
The handshake server can additionally begin HTTP/3/WebTransport admission from
the dispatcher's owned Initial event, so the first packet is not reread from the
shared socket. At the QUIC layer, subsequent Initial/Retry/0-RTT/Handshake
datagrams can now be routed by the sole socket owner into a bounded per-handshake
inbox, and a real handshake regression verifies completion and promotion to the
established CID router without competing socket readers. HTTP/3 now exposes
source-aware Initial acceptance. WebTransport additionally exposes a split
`HandshakeAdmission`: the caller completes QUIC/TLS from an inbox, promotes its
connection, injects routed 1-RTT packets, and non-blockingly polls for the
Extended CONNECT request. HTTP/3's bounded handshake supervisor owns worker
creation, completion reporting, per-connection random CIDs, failed-admission
cleanup, expiry, and stable heap-backed promotion while its receive API remains
the sole UDP owner. `webtransport.runtime.EndpointServer` now composes that
transport loop without moving a registered QUIC connection: it owns pending
CONNECT policy state and stable accepted-session objects, supports accept/reject
transitions, dispatches associated streams, DATAGRAMs and Capsules, and removes
protocol state before unregistering the HTTP/3 connection. Ready-session
polling resumes after the last session that produced an event, so a continuously
ready stream, DATAGRAM queue, or Capsule source cannot starve another accepted
connection. The cursor is a stable connection handle rather than a hash-table
bucket and safely falls back to a complete scan after removal or rehash; a
deterministic three-session regression covers rotation, idle-session skipping,
wraparound, and stale-cursor recovery. This matches the fairness property in
the audited quicz endpoint registry while providing it at the WebTransport
application-event boundary rather than only outbound QUIC datagram polling.
A two-client real
TLS/QUIC test accepts both sessions, checks stable pointers, isolated
bidirectional DATAGRAM and stream echoes, exact CLOSE metadata, then verifies
route cleanup. Endpoint timer expiry also propagates as a typed `closed` event
after pending/accepted/rejected protocol state has been removed.

## Session drain and close lifecycle

Handshake sessions now keep their Extended CONNECT request/response stream open
after successful HEADERS instead of using the aggregate HTTP/3 helper that
immediately sent FIN. `drain`, `close`, and `receiveSessionEvent` operate on
that stream:

- WT_DRAIN_SESSION remains advisory; streams and datagrams stay usable.
- WT_CLOSE_SESSION carries a 32-bit code plus at most 1024 bytes of UTF-8,
  sends CONNECT FIN immediately, and makes new stream/datagram operations fail.
- a peer close or clean CONNECT FIN produces a typed terminal event; clean FIN
  maps to code zero and an empty reason.
- session termination sends RESET_STREAM/STOP_SENDING with WT_SESSION_GONE for
  every non-terminal associated stream direction.
- malformed close length/UTF-8 resets the CONNECT stream with H3_MESSAGE_ERROR.

Local session close now treats CONNECT as a bidirectional stream rather than
retiring its association when the local FIN is submitted. Client, standalone
server, and shared-endpoint server sessions retain receive routing until the
peer CLOSE/FIN/reset is consumed, so a caller can send CLOSE and then await the
peer's terminal acknowledgement without `UnexpectedStream`. New streams and
DATAGRAM sends still fail immediately through the closed session state. Shared
endpoint sessions remain addressable until explicit connection removal; after
their terminal event is delivered they stop producing application events but
retain detached HTTP/3 routing for late ACK/terminal packets. Association
storage is finally released by session or endpoint teardown; until then its
stable terminal state rejects receives precisely and drops late datagrams.
Packet routing records FIN, RESET_STREAM, and connection close even when a
packet carries no DATAGRAM, so a DATAGRAM arriving in a later packet is dropped
before queue allocation. The client paced-send progress path also carries the
complete detached-association registry: if a CLOSE/FIN arrives while a request
body or close capsule is blocked on QUIC flow control, it remains owned by the
WebTransport control reader while MAX_STREAM_DATA can unblock the send.
Authenticated client and standalone-server sessions additionally expose
`closeWithTimeout` and `closeWithDeadline`. One absolute awake-clock deadline
now covers the encoded CLOSE capsule, CONNECT FIN, and every associated-stream
`WT_SESSION_GONE` RESET_STREAM/STOP_SENDING submission. The capsule is encoded
once into fixed storage and retains its exact socket-visible offset across a
timeout; FIN commits `local_close_sent`, and later calls resume only unfinished
stream cleanup. Completed terminal frames remain recorded per stream, so they
are not submitted twice. While a partial CLOSE is pending, application sends,
stream creation, drain, reset, and stop calls fail with `InvalidSessionState`
instead of interleaving bytes after the capsule prefix. Dispatcher-bound
client sessions deliberately retain their existing nonblocking one-shot close
path; dispatcher-fed standalone server sessions reject blocking close deadlines
instead of competing for the shared UDP socket. Terminal events are retained
until automatic FIN and stream cleanup succeeds, so transient backpressure
cannot consume the only observable close/reset notification.
If the CONNECT send direction is already permanently cancelled, rejected,
stopped, retired, or the connection is closed, a bounded CLOSE drops its
unreplayable capsule cursor and records a terminal local-close failure. Later
close calls can still finish associated-stream cleanup, while application
sends remain closed; timeout, congestion, flow-control, pacing, and task
cancelation continue to preserve the exact pending capsule for retry.
This terminal distinction is covered with an authenticated session whose
underlying Extended CONNECT bookkeeping is deliberately retired before CLOSE:
the first bounded close reports `UnexpectedStream`, clears its pending capsule,
closes application state, and a later close performs cleanup without replay.
Real QUIC/TLS tests force both client and server capsule timeouts, validate the
exact peer code/reason after continuation, and force a second timeout between
associated-stream terminal frames before completing cleanup.
Authenticated and stateful client/server sessions also expose
`waitForRecoveryIdleWithTimeout` / `waitForRecoveryIdleWithDeadline`. These
drive ACK, loss, and PTO processing until reliable application/control frames
are acknowledged, then flush the final cumulative peer ACK under the same
absolute budget. This allows a short-lived owner to preserve its final
CLOSE/FIN instead of destroying recovery state immediately after socket submission. A
deterministic preconfigured-key regression drops the first CLOSE datagram,
requires PTO retransmission and exact peer code/reason delivery, then drains
the automatic reverse FIN before either endpoint is destroyed. Dispatcher-
bound sessions continue to rely on their endpoint event loop and reject this
blocking operation.
The advisory DRAIN capsule has matching `drainWithTimeout` and
`drainWithDeadline` APIs. It is encoded once into fixed storage, retains its
socket-visible byte offset after timeout, rejects interleaved application or
CLOSE bytes while incomplete, and resumes only the suffix. After the complete
DRAIN commits, the session remains usable for new streams and later CLOSE.
Dispatcher-bound sessions keep their existing one-shot `drain` path and reject
the blocking deadline form. A real TLS/QUIC regression forces a partial DRAIN,
continues it, observes exactly one peer drain event, then opens another stream
before clean session close.

The CONNECT stream uses a fixed-size incremental state machine. HTTP/3 DATA
frame headers and Capsule Protocol varints may split at any byte boundary;
unknown capsule values are skipped without allocation or whole-value buffering.
Focused tests sweep every split point around an unknown capsule followed by
WT_DRAIN_SESSION. Real-handshake tests cover drain, post-drain stream traffic,
detailed close, clean-FIN close and post-close rejection, and reject FIN after
truncated 2-, 4-, or 8-byte Capsule type varints with H3_MESSAGE_ERROR rather
than misreporting a clean session close.

The lightweight preconfigured-key protected runtime also establishes
WebTransport with incremental HTTP/3 request/response HEADERS rather than the
aggregate helpers that set QUIC FIN. Its client exposes relative-timeout and
absolute-deadline connect/attempt variants; one unchanged deadline covers peer
SETTINGS and the final Extended CONNECT head, including response bytes that race
ahead of the control stream. Protected server accept and pending-admission APIs
carry the same bounded contract through fragmented request HEADERS. The full
stateful preconfigured-key wrappers provide the same one-budget client and
server variants, including server calls that begin from a known peer.
`sendSessionData`, `sendSessionDataSlicesWithTimeout` /
`sendSessionDataSlicesWithDeadline`, and `receiveSessionData` expose bounded
caller-buffer DATA on that long-lived Extended CONNECT stream in both
directions. The scatter/gather forms preserve caller slice ownership while the
synchronous call runs and report exact aggregate committed-byte progress for
suffix-only retries. Protected client and server
control writers now also expose relative-timeout and absolute-deadline forms
for raw session DATA, DRAIN, and CLOSE. DRAIN/CLOSE capsules are encoded once
into fixed session storage, retain their exact socket-visible offset on timeout,
and resume only the unsent suffix; invalid deadlines leave the control state
unstarted. Bounded terminal receive keeps a parsed peer CLOSE pending until its
automatic CONNECT FIN can be submitted under the same deadline, so backpressure
cannot consume the only observable code/reason. A simultaneous peer CLOSE does
not truncate an already-partial local CLOSE. Protected DATAGRAM senders expose
matching timeout/deadline forms; the timestamp is validated again immediately
before the single UDP submission, and an expired call does not consume a packet
number. Its typed `drain`, `close`, and
`receiveSessionEvent` APIs now reuse the shared incremental Capsule state
machine after HTTP/3 removes DATA framing. A fixed reader buffer is sized for a
maximum legal CLOSE capsule and retains bytes after the first event, including
DRAIN and a 1024-byte-reason CLOSE in one DATA payload. Clean FIN maps to
close code zero; partial capsules at FIN fail, malformed capsules cancel the
request with H3_MESSAGE_ERROR, and operations after local close fail.
Lightweight protected server session reads are now targeted by CONNECT stream
ID, matching the development and stateful transports. A ready ordinary HTTP/3
sibling remains buffered for its own consumer instead of being mistaken for
invalid WebTransport control data; the protected end-to-end test interleaves
that sibling and completes both exchanges independently.

The lightweight protected end-to-end test fragments HTTP/3 across five-byte QUIC STREAM
payloads, receives DRAIN, exchanges a DATAGRAM after that advisory event,
receives a detailed client CLOSE, and completes the opposite CONNECT direction
with FIN. Thus a pass cannot be explained by a CONNECT stream that ended
immediately after status 200. Associated bidi/uni streams and SESSION_GONE
cleanup remain unavailable on that legacy adapter because it does not own a
stateful recovery connection. Applications with externally negotiated keys use
`StatefulProtectedServer` / `StatefulProtectedClientSession` instead. Those
types expose the complete associated-stream surface over the full 1-RTT owner.
A deterministic real-UDP regression drops the first post-CONNECT client
associated-stream datagram, observes the later uni stream first, then requires
the lost modern bidi association prefix, payload, and FIN to recover exactly.
It also verifies bounded STOP_SENDING first rejects a zero budget without
committing registry state, then delivers application code 92 on retry. The
recovery case passed five consecutive focused runs.

All client attempt types retain the non-2xx body and trailers under
`Limits.max_rejection_body_bytes`; declared-length and unknown-length overflow
cancel the incomplete CONNECT, while a complete entity needs no contradictory
reset. A declared Content-Length reserves the retained body exactly once, so
fragmented rejection DATA does not geometrically grow its allocation;
unknown-length entities retain the bounded incremental path. The development
and lightweight protected pending types expose matching
`rejectWithBody` helpers, including automatic Content-Length and trailers, and
dropping a protected pending decision retires its bounded H3 request state.
Authenticated clients can also open WebTransport through a caller-owned HTTP/3
session with `connectSession*` and `connectSessionAttempt*`. Ownership is moved
only while the attempt is live: success transfers the H3 session into the
WebTransport session, while a complete rejection restores the caller's session
without an extra cancellation. Legacy helpers still return `SessionRejected`,
but only after draining the entity. The authenticated pending server API uses
the HTTP/3 paced writer for the same complete rejection entity. A
dispatcher pending attempt waits for the complete rejection and preserves DATA
already coalesced behind the head. Real QUIC/TLS regressions cover explicit and
legacy rejection, body/trailer ownership, overflow, and a successful sibling
request on the reused connection. Server-side `acceptSession*` and
`receiveSessionRequestFromSession*` provide the symmetric caller-owned entry
points: an accepted session keeps ownership, while explicit rejection returns
the H3 session when its `RejectedHandshakeSession` is destroyed and dropping a
pending decision rejects only that CONNECT before restoring the session. A
real handshake test exercises both outcomes and then serves a sibling request.

## Remaining gaps

The shared `fuzz-parsers` target exercises bounded Capsule, DATAGRAM and
bidirectional/unidirectional association-header parsing with deterministic and
coverage-guided mutation. The companion `fuzz-stateful` target drives session
establish/drain/close transitions, datagram accounting, bounded local/peer
stream registration, FIN/reset/stop/priority transitions, HTTP/3 control-stream
fragmentation, and QPACK table mutation. Authenticated QUIC/TLS HTTP/3
connection scheduling is additionally covered by `fuzz-http3-connection`,
including streaming and multiplexed requests, trailers, cancellation, HEAD
body suppression, and two-phase GOAWAY. The dedicated
`fuzz-webtransport-endpoint` target then establishes two authenticated sessions
through one production UDP endpoint and mutates cross-session DATAGRAM, paired
DATAGRAM, bidirectional-stream, DRAIN and CLOSE ordering while verifying exact
handle routing, both-session progress and payload isolation.

1. The endpoint also exposes a synchronous `serveUntil` callback loop with
   bounded receive polling and external shutdown. Add independent per-session
   handler tasks only if profiling shows that serialized callback dispatch is
   insufficient; QUIC/HTTP/3 state remains intentionally single-owner. HTTP/3
   promotion now marks the session dispatcher-bound, so blocking helpers reject
   before competing for the shared socket. WebTransport endpoint admission uses
   the transactional one-attempt CONNECT response/detach path, while routed
   packet QPACK feedback and request rejection remain one-attempt operations. The
   typed endpoint receive also accepts one caller-owned absolute deadline; it
   retains that timestamp while routing unrelated connections, completing
   handshakes, and servicing transport timers. Its relative-timeout wrapper
   converts once at entry and follows the same path.
   The underlying QUIC connection now owns move-stable selected-peer-CID
   storage. This closes an external wtransport failure where moving the
   handshake-backed session during admission left the active destination CID
   borrowing the old inline pool address; the peer then dropped the CONNECT
   response as an unknown CID. The native bidirectional matrix passes after a
   deterministic move-and-CID-rotation wire regression.
2. Expand browser coverage beyond Chromium. The checked-in Chrome gate now
   covers real browser CONNECT, DATAGRAM, bidirectional/unidirectional streams,
   exact mapped RESET_STREAM and STOP_SENDING codes, sibling reuse, and close.
   The wtransport gate also covers both client/server directions across
   CONNECT, DATAGRAM, and bidirectional/unidirectional streams. Each direction
   now sends and observes
   exact mapped RESET_STREAM and STOP_SENDING codes. The next bidirectional
   stream is opened before cancellation and the response is gated on peer
   observation, so completion proves a concurrent sibling survives. The
   netz-client half additionally discards the first STOP_SENDING datagram and
   completes only after transport recovery delivers the exact code. Its
   wtransport-client half also skips a netz WT_DRAIN_SESSION and checks the
   immediately following detailed session-close capsule, while its
   wtransport-server half
   checks netz's peer QUIC application-close code and reason handling. Firefox
   and Safari browser automation remain separate gaps.
3. Extend the bounded stream-churn gate to larger long-run distributions;
   concurrent packet-batched
   stream throughput and cancellation-under-loss now have real-handshake
   baselines. The
   same benchmark accepts `--reset-every` and `--reset-after-bytes`, raises
   both QUIC and WebTransport negotiated stream limits to the requested shape,
   and validates every reset code/direction alongside FIN/data checksums. A
   64-stream smoke reset 32 streams after 256 bytes while the other 32 delivered
   16 KiB each: 532,480 verified bytes, 350 read events, and complete terminal
   coverage. `--loss-pct=5` enables a fixed-seed endpoint interceptor only
   after the authenticated CONNECT. A cancelable client transport-progress
   future now keeps ACK/loss/PTO processing live after the last local FIN/reset
   until the server validates completion, fixing the prior large-stream
   teardown deadlock. Five 64-stream runs each considered 320 server datagrams,
   dropped the same 21, delivered all 32 RESET_STREAM and 32 FIN terminal
   events, and verified 532,480 bytes/checksum 67,891,200.
   The same endpoint hook now supports real packet reordering rather than only
   loss: `--reorder-every=5` held exactly 112 of 561 datagrams in three 8-stream
   runs, then sent each after its successor while preserving QUIC packet-number
   state. Every run verified 2,097,152 bytes/checksum 267,386,880 at 175-183
   MiB/s. With `--fault-direction=client`, three runs reordered the actual
   STREAM/FIN direction: 121-123 of 605-615 client datagrams were held, all
   bytes/checksum still matched, and throughput was 153-161 MiB/s. Batch-tail
   holds are flushed explicitly so reordering cannot become hidden loss.
   A separate external wtransport gate now runs 32-, 64-, 128-, and 256-stream
   client-upload shapes in both implementation-role directions with
   deterministic loss and pair reordering. Netz's outbound direction uses a
   seeded 5% endpoint interceptor;
   wtransport's outbound direction uses an unprivileged loopback UDP relay that
   stays transparent during handshake and is armed only for the reset and FIN
   phases. Every stream first delivers an indexed 256-byte
   prefix. Only after wtransport acknowledges all prefixes does the sender use
   an explicit 64-bit seed and stable SplitMix64 selection to reset a
   non-periodic subset with application code `0x4000 + index`; indices zero and
   one are fixed to reset and FIN respectively so every valid shape exercises
   both terminal paths. Direction, fault type, stream count, and repetition all
   select distinct seeds in the default matrix. A second reliable
   barrier proves wtransport observed every exact mapped code before the other
   streams continue to 16 KiB and FIN. The receiver reports exact FIN/reset
   counts, a 256-bit reset mask, application-code sum, byte total and checksum;
   an independent Python verifier recomputes all of them from the reported seed.
   Zig and Rust fixed-vector tests independently lock the same selection and
   summary values. The gate also finishes a bidi
   sibling opened before cancellation and verifies control-stream FIN plus peer
   connection close. All sixteen sender-direction/size/fault combinations passed
   twice consecutively. Because each scenario uses a different seed, its exact
   FIN/reset split, byte count, checksum, reset mask, and code sum deliberately
   vary instead of repeating one alternating-bit pattern. The result protocol
   uses a
   network-order 256-bit reset mask, and the Zig, Rust, and independent Python
   verifier all cover its highest bit and reject 257 streams. The verifier
   checks the declared
   `netz-client-outbound` or `wtransport-client-outbound` scope and, for the
   proxy path, requires matching process/proxy counters plus at least one
   actual fault in both the RESET and FIN phases. The proxy now uses a
   deterministic single-shot arm for each phase: every reverse-role case drops
   exactly two datagrams or completes exactly two reorder pairs overall,
   independent of the stream count. The direct netz-sender cases retain
   their seeded continuous 5% loss/every-fifth reordering schedules. This
   remains a bounded loopback lifecycle gate rather than a production-network
   or throughput comparison.
   A bounded repeatability gate runs a mixed FIN/reset shape three times under
   deterministic 5% loss, then runs sustained client-direction FIN traffic
   three times under reordering. It requires exact delivered-byte/reset
   accounting and at least one injected fault per run. This is
   lifecycle/recovery evidence rather than a cross-stack throughput comparison.
   The internal real-handshake harness now accepts up to 256 concurrent streams
   instead of stopping at the former 64-entry terminal table. A larger
   128-stream/64-KiB-per-stream matrix passed three loss and three reorder runs.
   Each loss run delivered 64 exact RESET_STREAM terminals plus 64 FINs,
   4,210,688 bytes, checksum 536,862,720, and deterministically dropped 96 of
   1,540-1,545 considered server datagrams. Each client-direction reorder run
   delivered all 128 FINs and 8,388,608 bytes/checksum 1,069,547,520 while
   holding 522-524 of 2,610-2,620 considered datagrams. The external wtransport
   verifier's earlier 64-stream mask cap is now replaced by the shared
   network-order 256-bit result described above. The internal harness also
   configures both peers'
   `max_session_streams` from the requested shape rather than silently retaining
   the runtime default of 128. At the 256-stream ceiling, a mixed 16-KiB run
   delivered 128 RESET_STREAM terminals plus 128 FINs, 2,129,920 bytes and
   checksum 271,564,800 after 84 injected drops; an all-FIN reorder run
   delivered 4,194,304 bytes/checksum 534,773,760 after holding 335 of 1,679
   datagrams. A 257-stream request remains rejected before network setup. The
   ordinary wtransport comparison also supports 256 parallel streams with
   multiword duplicate/FIN tracking; a two-role 1-KiB-per-stream run completed
   all 256 streams and matched 262,144 bytes/checksum 33,423,360 in each
   direction.

The whole-stream and caller-buffer incremental receive pollers enumerate QUIC
receive streams through a fixed 256-ID stack page, but that page is not a
protocol limit. Dedicated regressions populate 256 unrelated peer streams and
place the matching WebTransport stream in the next physical table slot. Both
the whole-stream poller and the incremental poller find the second-page target;
the latter also starts from a stale round-robin cursor and proves the wrapped
scan still crosses the page boundary.
Syntactically valid WebTransport streams carrying another Session ID are now
rejected and skipped instead of poisoning every later poll. Peer bidi streams
receive one atomic `RESET_STREAM` plus `STOP_SENDING`, peer uni streams receive
`STOP_SENDING`, all with `WT_BUFFERED_STREAM_REJECTED`. Retained and late bytes
are discarded to restore connection flow-control credit, terminal streams are
retired from QUIC without consuming this session's registry limits, and both
blocking and one-attempt pollers continue to a valid sibling.
