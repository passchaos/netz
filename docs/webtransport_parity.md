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
zig build interop-webtransport-stream-churn -Doptimize=ReleaseFast
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast
zig build interop-webtransport-chrome -Doptimize=ReleaseFast
```

The external interoperability gate builds the audited `~/Work/wtransport`
checkout at `d96cbb8` and exercises both directions over real TLS
1.3/QUIC/HTTP/3 connections. The wtransport-client/netz-server half verifies a
successful Extended CONNECT at `/interop`, bidirectional DATAGRAM exchange, a
client-created bidirectional stream and its reverse direction, client- and
server-created unidirectional streams, mapped application-code 71
RESET_STREAM, code 72 STOP_SENDING, a bidirectional sibling already active
when cancellation occurs, and a `CLOSE_WEBTRANSPORT_SESSION` with code 77/reason
`netz done`. The netz-client/wtransport-server half repeats CONNECT, DATAGRAM,
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
certificate validity period of at most two weeks. The gate verifies CONNECT,
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
code 77 and reason `netz done`, after the same netz DRAIN-before-CLOSE
sequence used by native wtransport. Chromium exposes no drain event, so this
proves ordered capsule consumption rather than application visibility of the
advisory signal. A cleanly resolved promise alone is not counted as evidence
for CLOSE_WEBTRANSPORT_SESSION metadata propagation.
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
| CONNECT / SETTINGS | Handshake, protected and dev runtimes; every server exposes a two-phase request object with authority/path/origin/header inspection, custom success headers, and typed 403/404/429 or generic 3xx-5xx rejection. Every client can send validated custom CONNECT headers, retain accepted response metadata, and opt into an attempt API that preserves non-2xx status and headers. Handshake and protected CONNECT streams remain open for Capsule Protocol traffic | Codec/session helpers | Production async endpoint/session with request inspection and accept/reject methods |
| DATAGRAM | Dev, protected, real-handshake, batch receive, payload budget/stats | Codec/session counters | Production send/receive |
| Bidirectional streams | Real-handshake open/send, reverse direction, whole-FIN compatibility receive plus caller-buffer incremental reads, reset/stop, lifecycle/limits and per-send-stream priority; the cleartext development runtime also supports both initiators, reverse-direction data, fragmented modern `0x41` association, coordinated IDs, per-session limits, and timeout/deadline-bounded whole-FIN receive; standalone handshake sessions expose timeout/deadline-bounded opens backed by QUIC stream credit; bounded batch writes select higher-priority streams first with stable equal-priority order; a concurrent sibling survives cancellation loss in external interop | Session registry and old-draft prefix codec | Production async bidi streams with read/reset/stop and Quinn-backed send priority; interoperates with netz while another stream is being cancelled |
| Unidirectional streams | Real-handshake both directions, incremental reads, mapped reset/stop, lifecycle/limits and send priority; the cleartext development runtime supports both initiators, fragmented `0x54` association, coordinated IDs, per-session limits, and timeout/deadline-bounded whole-FIN receive; standalone handshake sessions expose timeout/deadline-bounded opens backed by QUIC stream credit; external interop drops netz's first STOP_SENDING and requires exact-code peer observation after recovery | Session registry and header codec | Production async uni streams with read/reset/stop and send priority; exact mapped codes are verified against netz |
| Close/drain capsule codec | Real-handshake and protected runtime send/receive, split frame/capsule parsing, clean-FIN close and UTF-8/1024-byte validation; real-handshake SESSION_GONE stream cleanup; external wtransport consumes netz DRAIN before an exactly validated CLOSE | Close codec/state; audited session helper handles close/drain but accepts bare capsule fallback | Session close lifecycle; current driver has no DRAIN API/event, but its unknown-capsule path interoperably skips netz DRAIN and reports the immediately following CLOSE |
| Stream association wire format | Modern `0x41` frame type + Session ID; uni `0x54` + Session ID | Audited code writes only Session ID for bidi streams | Modern `0x41` + Session ID and `0x54` + Session ID |

The cleartext development client/server now keep the Extended CONNECT request
and response directions open after acceptance and expose the same incremental
Capsule control surface used by the lightweight protected runtime. Clients and
servers can send and receive caller-buffer session DATA, DRAIN, detailed CLOSE,
and clean FIN; receive operations have relative-timeout and absolute awake-clock
deadline forms. Partial HTTP/3 frames and partial capsules remain resumable
after timeout, malformed control capsules cancel the CONNECT stream with
H3_MESSAGE_ERROR, and server receive routing includes the peer address so two
development clients may independently use request stream zero. Associated
bidirectional and unidirectional streams now use the same packet pump, modern
`0x41 + Session ID` / `0x54 + Session ID` prefixes, peer-and-session routing,
shared HTTP/3 stream-ID cursors, bounded FIN-complete reassembly, and
`StreamRegistry` local/peer limits. The development surface intentionally
does not claim the stateful runtime's flow control, recovery, incremental
reads, RESET_STREAM, or STOP_SENDING guarantees. It remains a deterministic
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
The development HTTP/3 pump is also the sole UDP reader for both CONNECT DATA
and QUIC DATAGRAM traffic. It retains each DATAGRAM frame independently—even
when a packet also advances a control stream—in configurable count and raw-byte
budgets with oldest-drop semantics. A disabled queue intentionally drops
unreliable DATAGRAMs, while a packet exceeding a nonzero byte budget is
rejected explicitly; a slow consumer therefore cannot starve control progress
or create an unbounded queue.

Authenticated client/server sessions also expose timeout- and absolute-deadline
bounded DATAGRAM, DATAGRAM batch, incremental stream, whole-FIN stream,
DRAIN/CLOSE, and peer connection-close receive calls. A bounded batch uses one
deadline for every requested DATAGRAM, returns any prefix received before the
deadline, and records the terminal timeout in the next batch error slot. One
absolute application deadline spans unrelated QUIC packets while earlier PTO,
delayed-ACK, keep-alive, path-validation, idle and close timers continue to
run; neither transport maintenance nor control traffic renews the caller's
budget.
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
`releaseCompletedPeerStream` to return terminal peer stream credit while
retaining cumulative WebTransport registry accounting. The endpoint-accepted
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
API. `writeStream` waits for positive transport credit but submits at most
one packet-sized application prefix and returns its actual length, allowing
callers to round-robin many active streams; `finishStream` submits FIN
independently. `writeStreams` stages one fair packet-sized slice per sendable
stream through QUIC's stateful packet batch, orders candidates by signed stream
priority with stable equal-priority ordering, and commits registry/caller offsets
only for the socket-visible prefix. This provides allocation-free concurrent
stream progress without hiding flow control behind per-stream write-all tasks.
The runtime maps
WebTransport's 32-bit application error space into HTTP/3 codes while skipping
reserved codepoints and exposes both mapped and raw values on receive.

The real-handshake test sends 96 KiB through an 8 KiB advertised stream window,
reads it with 2-3 KiB caller buffers before FIN, verifies payload and flow
progress, and then exchanges both reset and stop events. Thus a successful test
cannot be explained by retaining a complete body behind the advertised window.

The benchmark uses one 4 MiB real-handshake bidirectional transfer, a 64 KiB
stream window, 16 KiB caller storage, partial writes and independent FIN:

```text
partial writes:    4036
read events:       4037
checksum:          534773760
median elapsed:    96.43 ms
median throughput: 41 MiB/s
```

These are the median elapsed time and corresponding integer throughput from
three consecutive 2026-08-18 same-host `ReleaseFast` runs after switching the
benchmark to one-packet partial writes. This deliberately prioritizes
caller-controlled fairness over the write-all helper's throughput; it is an
internal baseline and no equal-wire wtransport/quicz ratio is claimed.

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
server variants, including server calls that begin from a known peer. `sendSessionData` and
`receiveSessionData` expose bounded caller-buffer DATA on that long-lived
Extended CONNECT stream in both directions. Its typed `drain`, `close`, and
`receiveSessionEvent` APIs now reuse the shared incremental Capsule state
machine after HTTP/3 removes DATA framing. A fixed reader buffer is sized for a
maximum legal CLOSE capsule and retains bytes after the first event, including
DRAIN and a 1024-byte-reason CLOSE in one DATA payload. Clean FIN maps to
close code zero; partial capsules at FIN fail, malformed capsules cancel the
request with H3_MESSAGE_ERROR, and operations after local close fail.

The protected end-to-end test fragments HTTP/3 across five-byte QUIC STREAM
payloads, receives DRAIN, exchanges a DATAGRAM after that advisory event,
receives a detailed client CLOSE, and completes the opposite CONNECT direction
with FIN. Thus a pass cannot be explained by a CONNECT stream that ended
immediately after status 200. Associated bidi/uni streams and SESSION_GONE
cleanup remain on the production-oriented handshake runtime because the
lightweight protected transport does not own a stateful recovery connection.

## Remaining gaps

1. The endpoint also exposes a synchronous `serveUntil` callback loop with
   bounded receive polling and external shutdown. Add independent per-session
   handler tasks only if profiling shows that serialized callback dispatch is
   insufficient; QUIC/HTTP/3 state remains intentionally single-owner. The
   typed endpoint receive also accepts one caller-owned absolute deadline; it
   retains that timestamp while routing unrelated connections, completing
   handshakes, and servicing transport timers. Its relative-timeout wrapper
   converts once at entry and follows the same path.
2. Expose associated bidi/uni stream APIs on preconfigured protected and
   development runtimes. Protected CONNECT/Capsule lifecycle is now
   long-lived, but the lightweight protected HTTP/3 runtime deliberately lacks
   a full `one_rtt.Connection`; association streams must not be advertised
   until ACK, recovery, flow control and reset/stop state share one connection
   owner. Its existing session-control path now has timeout and absolute-
   deadline receive variants on both endpoint roles. One unchanged awake-clock
   budget spans every HTTP/3 DATA fragment, and parser state survives a timeout
   between fragments so callers can resume without losing Capsule bytes. The
   lightweight protected DATAGRAM readers expose matching bounded variants and
   preserve one deadline while skipping unrelated protected packets; the
   cleartext development DATAGRAM client/server expose the same timeout and
   absolute-deadline surface.
3. Expand browser coverage beyond Chromium. The checked-in Chrome gate now
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
4. Add larger long-run stream-churn distributions; concurrent packet-batched
   stream throughput and cancellation-under-loss now have real-handshake
   baselines. The
   same benchmark now accepts `--reset-every` and `--reset-after-bytes`, raises
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
   holds are flushed explicitly so reordering cannot become hidden loss. The
   remaining gap is
   external wtransport/browser interop rather than basic cancellation recovery
   at the benchmark's maximum stream count.
   A bounded repeatability gate runs a mixed FIN/reset shape three times under
   deterministic 5% loss, then runs sustained client-direction FIN traffic
   three times under reordering. It requires exact delivered-byte/reset
   accounting and at least one injected fault per run. This is
   lifecycle/recovery evidence rather than a cross-stack throughput comparison.
