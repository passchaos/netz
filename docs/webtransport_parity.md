# netz WebTransport parity audit

This audit compares netz with the WebTransport implementations available under
`/nav_env/Work`: `quicz` and modern Rust `wtransport`. It records wire-version
differences explicitly because draft WebTransport stream association changed
over time.

## GOAWAY and Session drain

Received HTTP/3 GOAWAY becomes an application-visible `draining` event for every
active WebTransport Session on that connection, including shared client and
server endpoints and the protected-runtime control readers. This follows
draft-16 Section 4.7: the signal is advisory, so existing Sessions can still
open streams and exchange DATAGRAMs. Repeated GOAWAY frames and a
WT_DRAIN_SESSION capsule share one notification per Session; subsequent CLOSE
metadata remains ordered and intact, and already-closed Sessions do not emit a
new drain event. Protected readers advance one control packet at a time rather
than waiting indefinitely for CONNECT DATA after a control-only GOAWAY.

A client with a received GOAWAY cannot start another WebTransport CONNECT on
that H3 connection, even when the first GOAWAY carries the maximum stream ID.
Admission returns `GoAwayReceived` before allocation or stream reservation and
requires a new connection. A CONNECT whose prefix was already sent before
GOAWAY remains retryable below the peer's request cutoff. Wire regressions in
`src/webtransport/runtime/goaway_tests.zig` cover both endpoint roles, multiple
Sessions, control-only wakeups, DATAGRAM/stream reuse, duplicate advisory
signals and exact later CLOSE metadata; the pending CONNECT regression checks
that backpressure resumes its committed suffix after GOAWAY.

## CONNECT transport termination

Authenticated Session owners observe CONNECT send-side STOP_SENDING, RESET
and FIN in the shared lifecycle, including before application sends and stream
opens. STOP_SENDING closes the Session even while QUIC's mandatory RESET
response is paced. Polling retains one scoped reset event with the transport
error code, or a normal code-zero close for an otherwise-untracked local FIN.
Associated streams terminate with WT_SESSION_GONE; sibling Sessions keep
their streams and DATAGRAMs on the same QUIC connection.

Buffered DRAIN/CLOSE events retain their order and exact application metadata
when they race with send termination. In-flight peer CONNECT bytes after a
synthesized termination are discarded; bytes beyond an actually decoded
WT_CLOSE_SESSION still require H3_MESSAGE_ERROR. Regression coverage lives in
`src/webtransport/runtime/session_control/connect_termination_tests.zig` and
`connect_sibling_tests.zig`, using real UDP/H3 traffic in both endpoint roles.

Peer CONNECT RESET and fully received FIN also close application state before
stream opens, writes or DATAGRAM operations, including when Session opening
credit is already available or Session flow control is unnegotiated. A FIN
whose control bytes still have gaps waits for those bytes. Capsule events stay
pending, so a buffered CLOSE preserves its code/reason even when reason
allocation first fails. Explicit local CLOSE can still finish the open send
direction before that peer event is decoded. Registered associated streams
receive WT_SESSION_GONE cleanup, and shared client/server siblings keep their
streams and DATAGRAMs. Protected-UDP coverage is in
`session_control/receive_termination_tests.zig` and `receive_sibling_tests.zig`.

DATAGRAM send preflight also processes control bytes already buffered on an
accepted CONNECT before submitting new application packets. A buffered CLOSE
prevents single and batch sends without consuming another UDP packet; its
code/reason stays available as one Session event, and sibling Sessions remain
usable. Buffered DRAIN remains advisory and still permits DATAGRAMs. Invalid
deadlines leave the control input untouched, and a close-reason allocation
failure rolls parsing back for retry. Bounded batches retain one deadline
across this preflight and socket submission. Protected-UDP tests cover owning
client/server sessions, both shared endpoint roles, exact zero batch progress,
event retention, and sibling DATAGRAM/stream continuation.

Bounded DATAGRAM sends also recheck owning Session control after congestion
progress and while waiting for pacing. HTTP/3's shared send loop invokes the
application progress owner before each retry, and WebTransport waits through
its existing CONNECT packet router until pacing or the caller deadline allows
another attempt. A CLOSE that arrives during either wait stops the unsent
suffix and retains its event; DRAIN remains advisory. Real-UDP tests cover both
endpoint roles, shared-client sibling events, pacing wakeups without peer data,
and a batch with exactly one committed datagram before CLOSE interrupts it.

## Current direct evidence

Run:

```sh
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
zig build bench-webtransport-datagram -Doptimize=ReleaseFast
zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- \
  --payload-bytes=1024 --iterations=10000
zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- \
  --burst --batch-size=16 --max-in-flight=64 --receive-into \
  --payload-bytes=1024 --iterations=10000
zig build bench-webtransport-stream -Doptimize=ReleaseFast
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- --send-all
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- --send-all --stream-slices=8
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- --send-all --enable-gro-receive
zig build interop-webtransport-stream-churn -Doptimize=ReleaseFast
zig build interop-webtransport-wtransport -Doptimize=ReleaseFast
zig build interop-webtransport-socks5 -Doptimize=ReleaseFast
zig build interop-webtransport-wtransport-churn -Doptimize=ReleaseFast
zig build interop-webtransport-chrome -Doptimize=ReleaseFast
WEBTRANSPORT_ORIGIN_ONLY=1 zig build interop-webtransport-chrome -Doptimize=ReleaseFast
FIREFOX=/path/to/firefox zig build interop-webtransport-firefox -Doptimize=ReleaseFast
WEBTRANSPORT_FIREFOX_STOP_SENDING=1 FIREFOX=/path/to/firefox \
  zig build interop-webtransport-firefox -Doptimize=ReleaseFast
```

The external interoperability gate builds the audited `/nav_env/Work/wtransport`
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
WebTransport's handshake URI client and multi-session `EndpointClient` now
accept the same SOCKS5 UDP route as HTTP/3. They keep URI DNS inside the proxy,
retain origin SNI/`:authority`, move the association into the sole QUIC socket
owner, and preserve one absolute deadline through proxy, QUIC/TLS, SETTINGS,
and Extended CONNECT. IP preferred-address traffic remains inside the same
association while destination-path ECN and GSO/GRO explicitly fall back rather
than reusing relay-hop metadata. The independent wtransport gate now repeats
the rejected and accepted connections through two authenticated associations,
then verifies DATAGRAM limits and exchange, bidirectional and unidirectional
streams, RESET_STREAM/STOP_SENDING recovery, connection reuse, and peer close.
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
certificate validity period of at most two weeks. The driver requires
Puppeteer's launched-browser version to identify Chrome and records both the
requested launcher and live `/proc/<pid>/exe` SHA-256 values in every client
success record, alongside the page's Chrome User-Agent. The server receives the
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
The sibling Firefox gate runs the same origin-rejection and accepted-session
paths through Firefox 156.0.1's native WebTransport/Necko implementation. It
requires Puppeteer's launched-browser version to begin with `firefox/`, records
that version plus the SHA-256 of the requested launcher and running process
image in both client success records, and verifies the Firefox User-Agent at
both the page and server boundaries. The runner requires the rejected-Origin
and accepted-Session processes to report the same version and process-image
hash. It then covers
certificate-hash authentication, CONNECT, DATAGRAM, bidirectional and
unidirectional streams, an exact mapped RESET_STREAM code 71 from
`WritableStreamDefaultWriter.abort()`, a second bidirectional stream on the
same Session after that reset, DRAIN framing, and exact close code 77/reason
`netz done`. Firefox exposes the WebTransport API only after its
HTTP/3/WebTransport preferences are enabled. Firefox may defer the reset
stream's preceding write until `abort()`, so the gate does not deadlock on a
server acknowledgement before aborting: it aborts first, writes an independent
DATAGRAM as an outbound scheduling barrier, and counts success only after the
netz server observes the remote unidirectional RESET_STREAM with code 71. The
server accepts any valid payload prefix that won the race with reset, but still
rejects a wrong stream direction, initiator, code, FIN, or payload. Firefox
156.0.1's `ReadableStreamDefaultReader.cancel()` still did not produce a
server-visible STOP_SENDING code 72 with either a consumed or unread payload,
including after an outbound DATAGRAM barrier, so that half remains an explicit
browser-specific gap.
A current Firefox source audit confirms `WebTransportReceiveStream::Create`
still installs the generic `InputToReadableStreamAlgorithms` without a
cancellation callback into WebTransport/Neqo, so switching between
`reader.cancel()` and `ReadableStream.cancel()` cannot manufacture the missing
transport frame. The gate no longer hard-codes that reduced matrix from the
browser name: `WEBTRANSPORT_FIREFOX_STOP_SENDING=1` selects the complete
Chrome-equivalent client/server path and requires the exact server-visible
code 72. The default remains the verified reset-only Firefox matrix until an
installed build actually implements that hook.
The 2026-09-29 artifact run used Chrome 153.0.8010.12 with process-image
SHA-256 `839efe5fd8b6a773dd81b2e10afdc15f3c0a17316fb82b5908c0533306c4ed9e`
and Firefox 156.0.1 with process-image SHA-256
`fc2340fc1c149f351b60033c79fd133a94e1b02741e04ff52e012eca970193c9`;
both rejected the denied Origin and completed their supported accepted-Session
matrix. These identify the tested artifacts rather than imposing fixed browser
versions on future gate runs.

The 2026-10-23 verification used Chromium 149.0.7827.196 (CDP product
`Chrome/149.0.7827.196`, process-image SHA-256
`3a7459ac6edc2ed80101d3b5a0492cae71a0097012a4f236b308d0a9b848290f`)
and Firefox 158.0.1 (process-image SHA-256
`e0dd6e00fd23cfc0fafa658526409d675ca20b5663ac19f589a2861dda21a0e8`).
Both rejected the denied Origin and completed their supported accepted-Session
matrix. Chromium completed the full reset/STOP_SENDING matrix. The explicit
full Firefox STOP_SENDING gate was also retried on 158.0.1; its `cancel-done`
DATAGRAM still timed out, so that version's verified default remains the
reset-only matrix.

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

## Draft-16 flow-control model and runtime

`webtransport.Capsule` now parses and serializes WT_MAX_DATA, the uni/bidi
WT_MAX_STREAMS variants, WT_DATA_BLOCKED, and the uni/bidi WT_STREAMS_BLOCKED
variants from `draft-ietf-webtrans-http3-16`. Their payload contains exactly one
QUIC varint; allocating and caller-buffer writers validate complete output
before appending any byte. Fixed wire vectors cover all six assigned types,
and bounded parser fuzzing includes each type alongside hostile mutations.

The public `webtransport.flow_control.State` provides session-level limits and
accounting. Both endpoint SETTINGS must indicate flow-control intent; a zero
initial stream limit requires an explicit grant. Peer MAX_* capsules must
strictly increase the previous limit, stream counts cannot exceed 2^60, and
data accounting uses new highest-offset growth with association headers
excluded. RESET Final Size charges body bytes lost in flight, and receive
violations leave prior state intact. Receiver grants are prepared without
mutation and committed separately after successful Capsule submission. BLOCKED
values remain advisory, and HTTP/2-only stream-data Capsules are rejected.

The authenticated handshake-backed and shared endpoint Session runtimes now
share a stable registry-owned State with their incremental CONNECT control
reader. All six flow Capsules are processed when flow control is negotiated,
including fragmented values; they are ignored
when negotiation is disabled. Peer MAX_* updates dynamically unlock stream
opens, and incoming stream counts are checked against the advertised cumulative
limits. Opening without available credit allocates no QUIC stream ID. Owning
deadline-bound opens can receive additional CONNECT progress under the same
absolute deadline, retaining DRAIN/CLOSE/reset notifications for the caller;
shared dispatcher sessions use nonblocking progress through their sole reader.

Session `grantData` and `grantStreams` APIs atomically submit one Capsule and
commit the advertised receive limit only after successful socket submission.
They are one-attempt operations that callers retry on backpressure. Parser and
shared-state snapshots also roll back peer grants when returning QUIC receive
credit fails. Duplicate, decreasing or excessive peer limits and incoming
stream-limit violations cancel the affected CONNECT with WT_FLOW_CONTROL_ERROR,
without terminating sibling sessions. Runtime tests cover both roles, zero
initial credit, failed submissions, fragmented grants, deadline waits and
shared-session isolation.

Receive-side stream data is now charged by each stream's highest QUIC offset,
including out-of-order gaps, before copying application bytes or retiring
transport state. Association headers are excluded even with zero data credit;
locally initiated bidirectional reverse directions carry no second header.
RESET Final Size reconciles lost bytes exactly once, including resets first
observed while parsing the association. Failed association-prefix credit return
rolls back both registration and its session data charge. Excess data rejects
the affected CONNECT before application delivery, and shared-client tests verify
that sibling sessions remain usable.

Flow maintenance and DATAGRAM receivers also discover complete buffered stream
associations before an application selects a stream reader. Discovery charges
the Session's stream/data limits without consuming the prefix or payload and
leaves the whole-stream/incremental choice open. Owned, caller-buffer, batch and
nonblocking DATAGRAM receivers inspect buffered STREAM state before delivery,
including STREAM and DATAGRAM frames arriving in the same QUIC packet. This
inspection preserves buffered CLOSE notification and completed-DATAGRAM ordering.
RESET/STOP abandonment and later incremental takeover return prefix credit
only once. Tests cover both endpoint roles, fresh and queued DATAGRAMs, retained
reader choice, scoped flow-error rejection and STOP abandonment.

Successful incremental or whole-stream consumption now replenishes WT_MAX_DATA
after half the receive window is consumed. RESET/STOP abandonment releases the
remaining accounted body credit once. Replenishment uses the same transactional
one-attempt sender as explicit grants: backpressure or socket failure leaves
the target pending for the next Session operation or dispatcher poll. It does
not wait for a peer BLOCKED capsule. Explicit data grants can enlarge the policy
window, and zero initial data credit stays zero until explicitly granted.
Shared dispatcher adapters refresh their recovery/pacing timer after deferred
grant or rejection submission, including operations that otherwise send no data.
Owning automatic-grant pacing waits now receive through the existing HTTP/3
owner until either control/input arrives, pacing wakes, or the caller deadline
expires. CLOSE interrupts the wait before a grant is submitted and retains its
code/reason; DRAIN remains advisory. Already buffered application input and input
received during the wait are delivered before another socket wait. The readiness
check follows the active API: a whole-stream reader waits for FIN, and a
targeted reader leaves ready siblings to their owner. Unrelated packets and
partial streams therefore cannot suppress grant pacing timers. Incremental
and whole-stream readers also continue through that HTTP/3 packet cursor, so
its retained UDP/GRO batch suffix cannot be skipped by a separate receive path.
Pending grants remain derivable after an early return and resume at a pacing
wake without fresh peer traffic. Protected-UDP regressions cover both roles,
ordinary/bounded data receives, exact batch prefixes, DRAIN/CLOSE, fresh and
buffered stream input, peer-visible timer-only grant recovery, and single-attempt
or dispatcher-bound maintenance that never takes over the shared socket.

Send-side body quotas now cover contiguous and scatter/gather writes, complete
multi-packet sends, and cross-stream batches. Fair writes truncate to available
session credit; one-attempt complete sends reject an excessive body before
submission. Every packet batch reserves one aggregate session budget in its
priority order and charges only its socket-submitted prefix. Association bytes,
FIN, and CONNECT control DATA remain excluded. Retransmission stays owned by
QUIC and does not charge the session again.

Owning Session operations now bind a temporary CONNECT progress context while
waiting for data credit, retaining DRAIN/CLOSE/reset events and using the same
absolute deadline across Capsule fragments, QUIC credit, congestion and pacing.
Deadline-bound complete sends report the exact committed application prefix on
failure so callers can resume without duplication. Dispatcher-bound operations
retain their one-attempt contract and leave socket receives to the shared owner.

Negotiated flow-control sessions now replenish WT_MAX_STREAMS as peer streams
are retired. Full registry records are reclaimed only after both applicable
halves terminate, application FIN/RESET/STOP notifications are delivered, and
QUIC compacts its ACK/recovery state. Cumulative byte and opening counters remain
intact. Transport closed-ID ranges prevent old associations from being counted
again, and explicit release of an already retired peer stream stays idempotent.
Configured retention limits bound active and pending-terminal records; when an
otherwise completed record awaits ACK, opening can wait for its reclamation.

Owning incremental, targeted, complete-stream and DATAGRAM readers now service
pending credits while waiting for the next application event, so stream reopening
does not depend on a new stream-data packet. HTTP/3's optional maintenance callback
preserves the owned and fresh caller-buffer/batch DATAGRAM paths, queued packet
order, callback errors and one absolute deadline. Explicit transport servicing
also observes registry retirement after ACK progress. Data/bidi/uni updates coalesce into one atomic
CONNECT DATA submission. Failed submissions leave every advertised limit intact;
pacing waits retain the same absolute deadline, and socket errors in an owning
wait are returned for retry. Serial bidi/uni tests reuse one retained slot, and a
lost grant recovers through QUIC while the reader waits for the next stream.
Buffered DRAIN/CLOSE/reset notifications remain available to the application;
unnegotiated MAX_* updates are ignored, prohibited HTTP/2 Capsules remain scoped
session errors, and forbidden CONNECT frames retain connection-level handling.

HTTP/3 SETTINGS now retain the legacy and draft-16 enable codepoints separately.
`Settings.webtransport_versions` can restrict a local advertisement to either
wire family; an omitted set preserves the existing dual advertisement. Received
SETTINGS record only the peer's actual enable flags. `webtransport.negotiatedVersion`
chooses the highest common family, and runtime negotiation rejects disjoint
advertisements. An explicit zero enable value in one family cannot disable or
manufacture support for the other. Newer legacy session-limit identifiers take
precedence over older identifiers regardless of payload order, including a zero
limit. Accepted HTTP/3 0-RTT additionally rejects losing any remembered wire
family before committing the new peer SETTINGS.

Resumable deadline-bound explicit grant APIs still need runtime integration.
These tests therefore do not establish full draft-16 session-flow-control
compliance. Authenticated owning connections and shared endpoints now choose
`webtransport-h3` for draft-16 and `webtransport` for the legacy family before
submitting CONNECT. They wait for peer SETTINGS, validate the directional server
Extended CONNECT setting and both H3 DATAGRAM settings. Both families require
non-zero QUIC DATAGRAM limits in both directions; draft-16 additionally requires
RESET_STREAM_AT in both directions. Missing
modern capabilities reject the session without falling back to an older mutually
advertised family. The legacy family retains its negotiated transport behavior.
The lightweight protected-key test runtime advertises only its implemented legacy
family and rejects a modern-only configuration.

Dispatcher-driven pending CONNECT owns the authority, path, Origin and additional
headers until SETTINGS is ready. It advances the critical-stream preface and
literal/static QPACK HEADERS one packet per poll, preserving partial offsets after
pacing, congestion, flow-control or small frame-budget backpressure. Owning sends
retain the same absolute deadline through SETTINGS and request submission. Server
admission retains request bytes until the client's SETTINGS arrive and validates
the token against the selected family before handing the request to the caller.
Accepted modern client sessions also permit omission of the client's
SETTINGS_ENABLE_CONNECT_PROTOCOL, including bidirectional stream operations.
Malformed CONNECT tokens or capability combinations cancel that CONNECT with
H3_MESSAGE_ERROR. The shared endpoint retains cancellation state across socket
submission failures and transport backpressure, returns the original validation
error after submission, and leaves sibling Sessions usable. Closing connections
do not retry pending request cancellation. The owning cancellation path checks
the same absolute deadline before submission and every retry.

## Application protocol negotiation

The native runtimes implement draft-16's WT-Available-Protocols List and
WT-Protocol String Item using RFC 9651 syntax. Client offers retain their
preference order and escaped string values; repeated List field lines combine
in wire order. A malformed member or non-String value causes the entire field
to be ignored. Parameters have no negotiation semantics, including valid
RFC 9651 Date and Display String parameters. Duplicate selection fields are
invalid Items and are ignored by optional negotiation.

Owning connect options use `limits.application_protocols`; `EndpointClient`
per-Session options expose `application_protocols` directly. Both accept a
`webtransport.application_protocol.Policy` with `values` and `required`:

```zig
.application_protocols = .{
    .values = &.{ "chat.v2", "chat.v1" },
    .required = true,
}
```

Server `Limits.application_protocols.values` is its supported set. Acceptance
chooses the client's first supported value, or validates an explicitly supplied
WT-Protocol field against the offer and local policy. A required policy with no
common value returns `NoCommonApplicationProtocol` before status 200 is sent;
the pending request remains available for application rejection or a different
admission decision. `offeredApplicationProtocols()` exposes a validated request
view. Accepted server and client sessions expose the selected value through
`applicationProtocol()`, whose borrowed String supports decoded comparisons and
caller-buffer decoding. It remains valid until the owning session is released.

Clients retain an owned offer through the response, including dispatcher-driven
CONNECT whose caller option strings have already been released. A successful
response with an unoffered selection, or without a valid selection when required,
resets only that CONNECT with WT_ALPN_ERROR (`0x0817b3dd`). Buffered associated
data streams terminate with WT_SESSION_GONE. Failed socket submission retains
the shared rejection state for retry and never publishes an accepted Session.
Optional missing/malformed selections are accepted without a selected protocol.
Tests cover escaped identifiers over real QUIC/TLS, per-Session selection on a
shared connection, rejection while a sibling remains usable, and cancellation
retry without taking a second UDP receive owner.

## Feature comparison

| Area | netz | `~/Work/quicz` | `~/Work/wtransport` |
| --- | --- | --- | --- |
| CONNECT / SETTINGS | Handshake, protected and dev runtimes; every server exposes a two-phase request object with authority/path/origin/header inspection, custom success headers, and typed 403/404/429 or generic 3xx-5xx rejection. Every client can send validated custom CONNECT headers, retain accepted response metadata, and opt into an attempt API that preserves non-2xx status, headers, bounded DATA, and trailers. Every pending server type can emit the complete rejection entity. The authenticated shared `EndpointServer` additionally advertises and enforces a configurable non-zero Session capacity per HTTP/3 connection, keys accepted state by connection plus CONNECT stream ID, and returns H3_REQUEST_REJECTED beyond capacity. The matching `EndpointClient` owns one H3 reader, retains stable per-Session state, enforces both the server-advertised capacity and an independent local bound, and preserves a complete bounded rejection entity before reusing the same connection; standalone owning adapters retain an exact capacity of one. CONNECT metadata uses a 16-field stack-first view with exact allocation fallback instead of fixed 57/62 additional-field ceilings; SETTINGS_MAX_FIELD_SECTION_SIZE remains the byte limit. Server acceptance enforces one RFC 6454 Origin across every runtime: the secure default permits native clients to omit Origin but requires any explicit value to match the CONNECT scheme/authority with canonical host/default-port handling; exact cross-origin allowlists and an explicit allow-any policy are available. Duplicate, empty, malformed, opaque `null`, and unapproved cross-origin values cannot reach a 2xx response. Handshake and protected CONNECT streams remain open for Capsule Protocol traffic | Codec/session helpers | Production async endpoint/session with request inspection, Origin policy, and accept/reject methods |
| DATAGRAM | Dev, protected, real-handshake, owning/caller-buffer batch receive, payload budget/stats | Codec/session counters | Production send/receive |
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
and close capsules on both sessions under bounded receive deadlines. A second
real QUIC/TLS regression opens CONNECT streams 0 and 4 on one connection,
exchanges independent DATAGRAMs and associated bidirectional streams, and
validates distinct CLOSE codes/reasons. A third CONNECT above the advertised
capacity receives H3_REQUEST_REJECTED without disturbing either accepted
Session. Shared stream classification recognizes another active Session ID and
leaves that stream untouched for its owning registry; unknown Session IDs keep
the existing WT_BUFFERED_STREAM_REJECTED behavior. The authenticated
`EndpointClient` exercises the same connection from the initiating side: a 404
attempt retains status/custom headers/bounded entity state, then two accepted
Sessions exchange independent DATAGRAMs and associated streams, send distinct
CLOSE metadata, and are removed separately without destroying H3. Its third
open is rejected locally from the peer SETTINGS/local-cap minimum before a
request stream is consumed. Draft-16 admission also enforces section 5.1:
without Session flow-control intent from both endpoints, only one simultaneous
Session is allowed even if the advertised and configured capacities are larger.
The client rejects a second CONNECT with `SessionLimitExceeded` before stream-ID
or wire mutation; the server submits H3_REQUEST_REJECTED instead of admitting
that CONNECT, leaving the original Session usable. Closed Session owners keep
their metadata and still count against local object limits, but release the
protocol's simultaneous-session slot. The client's `max_sessions` bounds all
retained owners, while the server's SETTINGS limit applies only to live
Sessions. The server likewise applies `max_sessions_per_connection` to live
Sessions and separately bounds retained owners with
`max_retained_sessions_per_connection`; its default is
`max(16, max_sessions_per_connection)`, and an explicit zero fails before bind
or allocation. Capacity-one regressions keep old close metadata while reusing
the same connection, then fill the independent object quota and verify refusal.
An abandoned CONNECT keeps the simultaneous-session slot
until cancellation is submitted, while remaining associated-stream cleanup
continues to own its memory. The shared policy lives in
`runtime/connect/session_capacity.zig`; protected-UDP regressions cover both
flow-intent directions, exact RESET/STOP codes, cancellation backpressure and
sequential reuse without removing old close metadata. Targeted receive remains
available, while
`pollAny`/`receiveAny*` use a stable Session-ID round-robin cursor so a busy
Session cannot starve another; deterministic readiness tests cover wraparound
and stale-cursor removal, and the real TLS test receives both DATAGRAM and
reverse-stream events through this whichever-ready path. Both
endpoint roles also preserve a RESET_STREAM that overtakes its fragmented
association prefix, so the WebTransport layer reports the mapped terminal
event instead of the generic HTTP/3 router consuming it.
Shared-client Sessions also expose `resetStreamWithTimeout/Deadline`,
`stopStreamWithTimeout/Deadline`, and `resetStreamReliably` with timeout and
deadline counterparts. Reliable Size counts application bytes; even an
unwritten unidirectional stream can deliver its association prefix before
reset with zero Session data credit. Bounded cancellation routes progress
through the one owning HTTP/3 reader, preserving sibling DATAGRAMs while
congestion delays submission. Invalid ownership, unnegotiated reliable reset,
unsent prefixes, and active callback readers fail before cancellation changes
stream state. Timeout and socket submission failure leave RESET/STOP retryable.
If progress receives a QUIC connection close or a connection-scoped HTTP/3
protocol failure, cancellation updates every shared Session and discards all
their DATAGRAM queues before returning. A Session CLOSE remains isolated and
its exact code/reason event stays readable while siblings continue operating.
Shared-client `closeWithTimeout/Deadline` also bounds CLOSE, CONNECT FIN and
associated SESSION_GONE cleanup. CLOSE encoding is retained before the first
write, and a one-byte DATA-frame budget is resumable across timeout or socket
failure without duplicate bytes. Retries must use the same code/reason while
the CLOSE is pending; peer CLOSE cancels a partial DATA frame or receives an
empty FIN when no bytes were submitted. Polling and explicit removal resume
the same pending metadata, while a cleanup failure after FIN never replays
the capsule. Sibling traffic remains routed by the owning HTTP/3 reader.
Shared-client Sessions also expose `drain`, `drainWithTimeout`, and
`drainWithDeadline`. The advisory capsule uses fixed encoded storage and
retains one HTTP/3 DATA contribution across partial writes, allocation failure,
timeout and socket failure. No FIN is sent; stream and DATAGRAM operations
remain available after completion. While a DRAIN contribution is incomplete,
CLOSE and ordinary application sends are rejected rather than interleaved.
Polling resumes it one packet at a time, and removal finishes DRAIN before
its normal CLOSE. Peer CLOSE preserves its exact event and cancels incomplete
DATA framing, while connection termination updates all shared Sessions.
The development HTTP/3 pump is also the sole UDP reader for both CONNECT DATA
and QUIC DATAGRAM traffic. It retains each DATAGRAM frame independently—even
when a packet also advances a control stream—in configurable count and raw-byte
budgets with oldest-drop semantics. A disabled queue intentionally drops
unreliable DATAGRAMs, while a packet exceeding a nonzero byte budget is
rejected explicitly; a slow consumer therefore cannot starve control progress
or create an unbounded queue.

Authenticated and lightweight protected client/server sessions also expose
timeout- and absolute-deadline-bounded DATAGRAM and DATAGRAM batch sends; the
authenticated sessions additionally expose bounded owning batch receive plus
single and batch `receiveDatagramInto` caller-buffer variants. One absolute
deadline spans the complete batch and the output count retains the exact
completed prefix on failure. Fresh matching DATAGRAMs bypass the HTTP/3
association payload allocation, while an undersized destination leaves the
payload queued for a larger retry. Existing owning receive APIs and their
lifetime semantics are unchanged. Authenticated sessions also expose incremental stream, whole-FIN
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
leaves the packet number unchanged. The public WebTransport Capsule,
unidirectional-stream header, bidirectional-stream header, and HTTP/3 DATAGRAM
payload writers precompute their exact wire size and reserve once before
emitting any varint or payload byte. Short caller storage and fail-first
allocation tests verify that these primitive encoders leave their destinations
unchanged, while existing round trips cover all resulting wire forms.
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
The owning HTTP/3 receive pump submits QPACK decoder feedback one packet at a
time and retains its unsent prefix on pacing, congestion, or stream-credit
backpressure. A ready WebTransport DATAGRAM therefore remains deliverable
through both owning and caller-buffer APIs even while feedback is blocked.
Active receives resume pending feedback at its pacing wake under the original
application deadline, including a decoder-stream prefix that needs its own
packet; they do not require an extra peer packet to trigger that retry.
Authenticated standalone sessions now expose symmetric
`sendDatagramWithTimeout` / `sendDatagramWithDeadline` calls. They wait for
QUIC congestion and pacing capacity while using the existing HTTP/3 packet
visitor, so ACK progress cannot bypass control/QPACK, associated DATAGRAM, or
detached CONNECT routing. Timeout retains no hidden application queue and does
not increment the sent-DATAGRAM count; callers may retry explicitly. Ordinary
single sends still return `CongestionLimited` without reading UDP when the
congestion window is full, while ordinary batches wait for congestion relief.
Both ordinary and bounded sends advance buffered CONNECT control before each
retry. Pacing waits use the existing HTTP/3 receive owner until the earlier
pacing wake or application deadline, so a peer CLOSE interrupts a waiting send
with `InvalidSessionState` before another DATAGRAM is submitted. The close event
retains its exact code/reason, a batch reports its exact committed prefix, and
sibling Session events remain available. A pacing wake alone retries an ordinary
send without exposing an application timeout. Real protected-UDP regressions
cover both endpoint roles, zero and nonzero batch prefixes, queued CLOSE during
single-send congestion backpressure, and shared-client sibling delivery. The
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
marked only after its packet reaches the socket. Stream reset also has relative-
timeout and absolute-deadline forms: congestion and pacing are serviced under
the same budget, and the registry records the reset only after socket
submission, so a timeout remains safely retryable. STOP_SENDING now has the
same bounded contract from the QUIC connection through both standalone
WebTransport endpoint roles and the stateful protected client facade. Invalid
or expired deadlines consume no packet number and leave both transport and
WebTransport stop state uncommitted; a later retry sends the exact mapped code.
When the peer advertises QUIC `reset_stream_at`, stream opens now bind their
association bytes to transport reset state before returning an ID. Prefix/state
allocation precedes ID consumption across H3 request/push and QUIC namespaces.
Ordinary application reset, dual-direction cancellation, automatic STOP_SENDING
response and SESSION_GONE cleanup then use RESET_STREAM_AT with at least that
prefix. Resetting an unwritten stream can submit its header and reset in one
packet, even with zero session data credit; header bytes remain excluded from
application accounting. Legacy peers without the extension retain RESET_STREAM
compatibility, as covered by the native wtransport gate.

Explicit `resetStreamReliably*` adds a guaranteed application-data prefix. Its
public `reliable_size` counts application bytes rather than association bytes;
the adapter translates that to the QUIC offset and rejects unsent application
prefixes. A zero-sized application guarantee can reset an unwritten stream.
STOP abandonment keeps a bounded 16-byte protocol prefix view separately from
application-readable storage, so reliable association headers arriving after an
early stop remain identifiable without restoring discarded application DATA.
Receive polling delivers the complete reliable prefix before the one-shot reset
event, waits across reordered gaps, ignores reordered Reliable Size increases,
and never lets automatic abandoned-stream cleanup reclaim the prefix early.
The real TLS/QUIC stream-churn binary exposes `--reliable-reset`; its repository
gate retains the ordinary reset/loss and all-FIN/reorder baselines, then repeats
the mixed FIN/reset shape with RESET_STREAM_AT under both ACK loss and outbound
STREAM/reset reordering. A one-run eight-stream, 4-KiB smoke delivered the exact
17,408 expected bytes and four reset events in both reliable fault modes, with
five client datagrams actually held in the reorder case.
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
The shared abandoned-receive cleanup now also handles a locally stopped
stream whose `RESET_STREAM_AT` Reliable Size has not arrived contiguously.
A preceding STOP_SENDING has already abandoned application reads and returned
QUIC receive credit; waiting for those reads again used to trap WebTransport
Session credit and suppress the reset notification. The cleanup in
`runtime/association/abandoned.zig` now settles the complete final-size Session
charge and retains the peer's exact reset code/final size for one later event.
A targeted sibling can complete first without hiding that event. QUIC still
retains the missing reliable prefix for transport validation and reclamation:
late bytes are discarded, invalid Final Size is rejected, and neither Session
credit nor the application event can be counted twice. A stream without local
STOP_SENDING still delivers its reliable prefix before reset. This follows the
abandoned-read boundary discussed in
[reliable-reset draft-11 section 5.4](https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-5.4)
and Quinn's receive-stop contract without bypassing QUIC's prefix state.
Sixteen deterministic cases combine client/server roles, bidi/uni directions,
RESET-before/after-STOP ordering, and ordinary/one-attempt cleanup. They first
reproduced a 10-byte final-size Session charge with only one byte consumed;
the repaired path consumes all ten before the missing prefix arrives, preserves
sibling delivery, reports one reset, and rejects invalid late final-size data.
The independent wtransport gate also remains green in both endpoint roles,
including exact reset/stop codes, concurrent sibling reuse, and recovery after
one dropped STOP_SENDING packet.
The focused WebTransport and QUIC reliable-reset/stopped-receive/reset-prefix
Debug gate passes 479/479 tests; public-module checks pass 2/2.
The compact-storage assertions in `runtime/layout_tests.zig` retain their
adapter budgets while accounting for the wrapper tail padding induced by an
embedded HTTP/3 transport's alignment. This avoids treating the existing
16-byte transport alignment as added WebTransport state in optimized builds.
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
ranges, while WebTransport retains separate cumulative session accounting.
Negotiated flow sessions additionally reclaim full terminal registry records
after their application events are delivered. Stream discovery uses stable ID-based
pagination so reclamation cannot skip a swap-moved active stream. A failed
automatic credit update remains pending and retries through the aggregate QUIC
connection timer without requiring another peer packet. Whole-stream and
incremental WebTransport readers now register transport retirement when FIN or
RESET_STREAM is delivered; local FIN/reset paths do the same, so associated
streams are compacted after both applicable halves become terminal while the
registry continues enforcing cumulative session limits. Negotiated WT_MAX_STREAMS
updates return opening credit after registry retirement; unnegotiated adapters
retain their existing bounded policy.
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
Retry, Version Negotiation, and passive Handshake flights. WebTransport now
exports the same public `AddressResolver` contract as HTTP, WebSocket, and
MQTT. Resolver results remain transport routes only: URI authority and TLS
identity stay bound to the original hostname, literal IPs bypass the callback,
and endpoint/URI option normalization retains the resolver. Unlike
wtransport's current resolver trait, which returns only the first address,
the contract preserves an allocator-owned ordered address set for fallback.
A real URI handshake regression uses an otherwise unresolvable hostname,
requires the caller deadline in the resolver callback, and completes through
the returned loopback address. An optional HTTP/3 `address_attempt_timeout`
gives each resolved UDP route a fresh QUIC/TLS phase budget without renewing the
total caller/connect deadline; the same regression now places a silent UDP
endpoint first and requires fallback to the authenticated server. A separate
silent-only test verifies the WebTransport adapter reaches its total deadline
instead of waiting for the lower-level multi-PTO default.
Owning WebTransport URI connects also pass through HTTP/3's opt-in QUIC Happy
Eyeballs policy. Their silent-first regression now retains a two-second first
attempt budget but starts the live route after 20 ms, proving the Extended
CONNECT adapter uses a concurrent winner rather than sequential timeout
fallback. Dual-family callers supply `alternate_local_address`; authority,
certificate policy, and the end-to-end WebTransport deadline remain tied to
the original URI.
`connectUriWithDeadline` also
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

Shared `EndpointClient` opening failures retain a bounded cleanup owner until
CONNECT cancellation is submitted. Cleanup uses one-attempt HTTP/3 cancellation
and retries on later client operations or Session removal, so congestion,
pacing, and a failed socket send cannot turn an ordinary opening timeout into
whole-connection termination or extend it with a pacing wait. Cleanup capacity
is reserved before sending CONNECT, and pending attempts count against the
same local/peer admission bound as accepted Sessions. Early DATAGRAMs for the
failed CONNECT are discarded; associated streams remain owned during retries
and are terminated with `WT_SESSION_GONE` without consuming sibling traffic.
Application-protocol failures use the same queue with `WT_ALPN_ERROR`.
Real protected-UDP regressions cover congestion, pacing, socket failure,
allocation failure before and after CONNECT submission, admission recovery,
early stream cleanup, and continued sibling stream/DATAGRAM traffic.

That cleanup ownership also covers the allocation and partial transmission of
the CONNECT HEADERS itself. HTTP/3 `startRequestOwned` and
`startRequestOwnedWithDeadline` report every allocated request stream even on
failure; their streaming-head sender retains the exact submitted prefix across
pacing, flow-control, and congestion progress. A truncated request head is
canceled on that stream instead of rolling back through whole-connection
termination. Outbound body offsets are published only after the complete head
is submitted. Protected-UDP cases verify a one-byte partial head under pacing
and congestion timeout, zero-byte and partial socket failure with exact RESET
final sizes, and a large CONNECT head that resumes ACK progress and is decoded
completely by its peer while the first Session remains active.
An additional dynamic-QPACK case retains the speculative field-section
references across local cancellation until the peer's Section Acknowledgment
or Stream Cancellation arrives. A local RESET/FIN cannot prove that a field
section was decoded, so it does not permit early eviction or discard of its
encoder references. Only unsent sections are rolled back, using immutable
section-sequence checkpoints that survive earlier peer acknowledgments.
The encoder bounds pending descriptors plus reference arrays by its configured
`max_stream_buffer` budget; it uses static/literal representations once that
budget is exhausted and resumes dynamic references after peer feedback.
Decoders with a nonzero maximum dynamic-table capacity generate Stream
Cancellation even when HEADERS has not arrived. One-attempt feedback can submit
the stream-type prefix alone under one-byte STREAM/frame limits while retaining
all instruction bytes for the next turn. Protected-UDP tests verify delayed
acknowledgments, entry pinning until peer cancellation, ordinary completion,
and exact cancellation/prefix bytes alongside the budget and rollback cases.

QPACK decoder insert feedback also survives a partially processed encoder-stream
batch. Instruction decoding or insertion can fail after earlier table updates
and receive offsets were committed; the decoder queues their Insert Count
Increment before returning the error, using capacity reserved before mutation.
Retry emits only the remaining increment, and retransmitted consumed bytes
cannot duplicate table entries or feedback. Allocation-point fault injection,
recovery, and invalid-suffix regressions cover those transitions.

Peer `STOP_SENDING` rejection also completes scoped cleanup after QUIC has
already submitted its matching RESET. QUIC cancellation preserves that
RESET's original error code and final size while using the caller's requested
code for the receive half. Reliable-reset downgrades preserve the same reset
identity, and pacing/congestion failures leave received bytes owned for retry.
A protected-UDP rejection case verifies both cancellation codes on the wire,
continued sibling DATAGRAM delivery in both directions, and renewed CONNECT
admission after the rejected attempt is retired.

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
Whole-stream polling treats QUIC's final size as the authoritative wire bound:
it converts the complete prefix-plus-payload size to `usize` before subtracting
the association prefix, then reuses that checked total for availability,
copying, and flow-credit release. This prevents a representable payload length
from overflowing when its prefix is added back on narrow targets; focused tests
cover valid bounds, prefix underflow, and target-width overflow.

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

The handshake client and rejected-handshake session now expose
`serviceTransportWithTimeout` and `serviceTransportWithDeadline`; the stateful
protected client forwards the same bounded transport-pump API. The GRO stream
benchmark services the client in 10 ms intervals, publishes server completion
only after Session teardown, and stops and awaits the worker cooperatively.
This fixes a teardown race in which canceling a future blocked in an otherwise
idle UDP receive could hang after the peer had already received and validated
the complete payload and FIN. In a fixed-binary CPU-0 A/B of the 4 MiB,
eight-slice `--send-all --enable-gro-receive` shape, the baseline hit the outer
2-second watchdog in all 7 runs; the candidate completed all 7 in
13.944-14.951 ms at 267-286 MiB/s, with 358-359 read events and checksum
534,773,760. The non-GRO control completed in both arms for all 7 pairs, with
22.365 ms baseline and 22.216 ms candidate medians (0.990 paired median ratio).
This is liveness evidence, not a throughput-speedup claim. The retained
baseline, candidate, and paired-log SHA-256 values are respectively
`73e897a03ed825da1538ecb0c0cf0789ab22fbc2fe57e3d853cdd3c793b12b98`,
`a9b58c65373cf4cb0eb50cee3c3ec6dcc6990bf3b265b3946220dc2127a61271`, and
`9e8f51a99d4da29f5349fcc6bfa84c422cd1641e5b2ac078652394deab0a2d3f`.

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
established CID router without competing socket readers. RFC 9001 ticket
validation remains separate from the shared TLS codec: every present QUIC
`max_early_data_size` must be `0xffffffff`, while finite TLS limits remain valid
for stream transports. A zero-lifetime QUIC ticket advances the authenticated
CRYPTO stream but is not inserted into the session cache. QUIC client and
server stores reject tickets exactly at the advertised lifetime boundary and
before their issue time. HTTP/3 now exposes
source-aware Initial acceptance.
WebTransport additionally exposes a split
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

Authenticated endpoint, standalone handshake, and stateful protected
WebTransport facades now expose a process-local `StableConnectionId`, matching
wtransport's stable-connection observability without leaking a mutable QUIC
CID or peer address. The value is allocated once by QUIC 1-RTT construction,
survives connection/session moves, peer-CID rotation and path migration, and is
shared by every WebTransport Session multiplexed on that connection. It is
deliberately not serialized, persisted, or accepted as an authorization
credential. QUIC lifecycle tests prove nonzero uniqueness plus move/migration
stability, and both endpoint roles prove two Sessions share one ID.

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
- DATA after a received WT_CLOSE_SESSION is rejected with an atomic
  RESET_STREAM plus STOP_SENDING carrying H3_MESSAGE_ERROR, including when the
  violating suffix shares the same QUIC STREAM frame as the valid CLOSE. The
  close code/reason remains application-visible, buffered suffix bytes are
  discarded only after the rejection reaches the socket, and endpoint-driven
  sessions keep enforcing this rule after their terminal event was delivered.

The shared `EndpointClient` applies the same rule to every accepted Session.
It inspects terminal CONNECT streams before sending a pending FIN reply,
rejects late bytes after that FIN with STOP_SENDING, and retains failed or
paced cancellation for a later poll. Local or peer CLOSE also suppresses
associated-stream and DATAGRAM delivery and advances WT_SESSION_GONE cleanup
one packet per poll. Explicit Session removal checks for pending protocol
cancellation before its ordinary FIN. Focused real-UDP tests inspect the peer's
exact RESET_STREAM/STOP_SENDING codes, inject a failed socket submission, and
verify a second Session can still receive and open streams on the connection.

Shared client and server endpoints now apply RFC 9297 section 3.3 to malformed
Capsules and truncated CONNECT DATA: they cancel only the affected stream with
H3_MESSAGE_ERROR using an atomic RESET_STREAM/STOP_SENDING submission. Detection
immediately blocks new application sends, while failed or paced submission
retains the original bytes for retry. Successful rejection commits terminal
Session state, suppresses repeated InvalidCapsule events and advances associated
stream cleanup through the existing one-attempt path. Client Session removal
also completes a pending malformed-message rejection. Real-UDP regressions
cover invalid UTF-8, short and oversized CLOSE declarations, nonempty DRAIN,
truncated Capsule varints and DATA frames, socket failure, pacing and a sibling
Session that continues on the same connection. Registered and buffered-stream
WT_SESSION_GONE cleanup now lives in a separate session-control module while
preserving the existing blocking, deadline and one-attempt entry points.
Close-storage layout regressions retain exact 296-byte Control and 456-byte
protected-reader bounds and check WebTransport adapter overhead separately from
embedded HTTP/3/QUIC state, so transport growth does not obscure those bounds.

Independent handshake-backed client/server sessions now share the same Capsule
rejection coordinator. They cancel CONNECT and finish WT_SESSION_GONE stream
cleanup before reporting InvalidCapsule. A timeout or socket error preserves
that pending notification even when CONNECT cancellation already succeeded;
the next receive resumes unfinished cleanup without replaying committed
terminal frames. Absolute deadlines also bound post-CLOSE suffix cancellation
and receive-credit pacing while retaining the peer's exact close code/reason.
Dispatcher-backed clients advance one terminal packet per poll before reporting
the retained error. All standalone application-stream and DATAGRAM receive
surfaces reject terminal or pending-close state, including complete-stream and
batch APIs, while retaining ConnectDatagramAssociationClosed for terminated
DATAGRAM receives; session-control receives continue observing peer CLOSE/FIN.
Batch failures still clear their caller-owned progress count before validation.
Five real-UDP regressions exercise both roles, cancellation timeout, cleanup
timeout, preserved CLOSE metadata, and bounded dispatcher progress through a
production Extended CONNECT exchange with preconfigured packet-protection keys.

Handshake-backed sessions now observe QUIC closing, draining and closed state
at packet, control and application receive boundaries. Connection termination
closes their logical Session state and makes unfulfilled reads fail with
ConnectionClosed; it does not manufacture a normal WebTransport CLOSE event.
Accepted WebTransport DATAGRAM associations opt into connection-close queue
discard. A direct DATAGRAM receive already fulfilled before the close frame in
an ordered packet retains its completed result, then exposes terminal state to
every following operation. Incremental and complete stream readers stop before
copying data from a terminal connection. Previously decoded CLOSE metadata and
pending malformed-Capsule notifications remain observable even when transport
termination makes further FIN/RESET cleanup impossible. Shared clients update
all accepted Sessions and permit explicit removal after close; shared servers
suppress stale application events while continuing their typed connection-close
event path. Regressions cover both endpoint roles, buffered payloads, both
DATAGRAM/close frame orders, whole/incremental stream reads and shared Sessions.

The 1024-byte reason limit now belongs to the core WebTransport capsule codec
and is reused by the incremental runtime, so standalone writers and parsers
cannot create or accept a CLOSE capsule that the session state machine would
later reject. Direct boundary tests accept 1024 bytes, reject 1025 bytes in
both directions, and preserve existing output on an oversized write.

Local session close now treats CONNECT as a bidirectional stream rather than
retiring its association when the local FIN is submitted. Client, standalone
server, and shared-endpoint server sessions retain receive routing until the
peer CLOSE/FIN/reset is consumed, so a caller can send CLOSE and then await the
peer's terminal acknowledgement without `UnexpectedStream`. New streams and
DATAGRAM sends still fail immediately through the closed session state. Shared
endpoint sessions remain addressable until explicit Session or connection removal; after
their terminal event is delivered they stop producing application events but
retain detached HTTP/3 routing for late ACK/terminal packets. Association
storage is finally released by session or endpoint teardown; until then its
stable terminal state rejects receives precisely and drops late datagrams.
Shared-server `removeSession` now completes terminal work before dropping its
Session owner. It observes buffered Capsules, gives malformed/post-CLOSE rejection
priority over an ordinary FIN, and normally closes an active Session with code
zero. Registered streams and complete but unread buffered streams receive
WT_SESSION_GONE cleanup before their metadata is released. An unfinished CONNECT
receive direction is stopped with the optional WT_SESSION_GONE signal. A failed
send or pacing/credit limit keeps the Session addressable, retains completed FIN
and reset/stop submissions, and leaves the advertised Session capacity occupied
until retry succeeds; removal never claims a second socket reader. Already-reset
CONNECT send directions proceed through cleanup instead of trying to replay CLOSE.
Local CLOSE also suppresses queued stream/DATAGRAM delivery while the endpoint
continues processing the peer's terminal acknowledgement and sibling Sessions.
Shared Session destruction now releases heap-backed CLOSE reason storage on
Session removal, connection removal and endpoint teardown. Regressions exercise
those three paths, registered and unread FIN streams, socket failure before
rejection and after CLOSE, a peer STOP_SENDING, and continued sibling delivery
after the peer processes the removed CONNECT's close/reset exchange.
Shared-server CLOSE now retains its encoded code/reason and a DATA-frame cursor
until FIN is committed or protocol/connection termination cancels it. The same
resumable HTTP/3 response writer handles one-frame packets and one-byte STREAM
fragments. Direct close/removal calls advance while immediately writable;
endpoint polling submits at most one pending-close fragment per turn. Backpressure
or socket failure preserves the exact wire offset, and retries with different
close parameters are rejected instead of replacing an unfinished Capsule.
Removal resumes an already-pending detailed CLOSE rather than starting code zero.
Peer termination cancels an incomplete DATA frame or replies with FIN before any
frame bytes have been sent. Malformed/post-CLOSE handling stays ahead of this
ordinary close path, and connection termination releases pending storage without
another send. CLOSE storage is shared with the owning adapters, remains inline
through 128 encoded bytes and allocates only the exact longer payload length.
Tests cover wire-prefix retry, automatic polling, original-code retention during
removal, heap teardown, peer termination and protocol-error precedence.
The shared client's `removeSession` now also normally closes an active CONNECT
before releasing the Session. A retained DATA-frame cursor records its exact
wire offset, including a partially submitted frame header, so retry never inserts
a second header or repeats CLOSE bytes. The writer submits one bounded STREAM
fragment at a time and works with a one-frame packet budget and one-byte stream
frames. Socket/allocator failures keep the owner; ordinary pacing, congestion and
stream-credit waits continue through the existing sole HTTP/3 receiver and retain
sibling packets. While a CLOSE is pending, application data stays hidden for that
Session and siblings remain usable. Buffered protocol rejection still precedes
CLOSE/FIN, and forbidden CONNECT frames retain connection-level error handling.
If the peer terminates while the sender waits for credit, an unwritten CLOSE can
be acknowledged with FIN; an incomplete DATA frame is canceled with
WT_SESSION_GONE and its HTTP/3 request state is released. Successful removal
terminates registered streams and aborts an unfinished CONNECT receive direction
before destroying the metadata. Regressions verify peer CLOSE decoding, failure
before/after the close submission, one-byte-header retry, flow/congestion progress,
peer termination without a further grant, registered-stream cleanup and siblings.
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
once into retained storage and keeps its exact socket-visible offset across a
timeout; encoded values through 128 bytes stay inline, while longer close
reasons allocate only their exact encoded length. FIN commits
`local_close_sent`, and later calls resume only unfinished stream cleanup.
Completed terminal frames remain recorded per stream, so they are not
submitted twice. While a partial CLOSE is pending, application sends, stream
creation, drain, reset, and stop calls fail with `InvalidSessionState` instead
of interleaving bytes after the capsule prefix. Dispatcher-bound client
sessions deliberately retain their existing nonblocking one-shot close path;
dispatcher-fed standalone server sessions reject blocking close deadlines
instead of competing for the shared UDP socket. Terminal events are retained
until automatic FIN and stream cleanup succeeds, so transient backpressure
cannot consume the only observable close/reset notification.
On 64-bit targets the outbound pending-Close state falls from 1,064 to 160
bytes. The inbound Capsule control parser now applies the same policy to its
reason storage: `Control` falls from 1,160 to 296 bytes, and the protected
reader that embeds it initially fell from 2,224 to 1,360 bytes. Its separate
post-event suffix buffer now uses the same 128-byte inline/exact-allocation
policy, reducing the reader again to 456 bytes. Short peer reasons and short
event suffixes remain allocation-free; longer values allocate only after their
bounds are validated. Failed reason allocation, failed suffix allocation, and
failed QUIC receive-credit commit restore the complete parser snapshot and
release any allocation made by that attempt. Completed reasons remain borrowed
and stable until session teardown.

The development and lightweight protected server/client Session layouts, which
embed that reader, now shed 2,672 bytes relative to the original layout:
`AcceptedSession` is 1,064 bytes, `AcceptedProtectedSession` is 872 bytes,
`ClientSession` is 7,352 bytes, and `ProtectedClientSession` is 8,960 bytes.
The authenticated server/client types use `Control` directly and remain at
17,320/17,864 bytes, 1,768 bytes below their originals. Layout tests pin those
values; allocation-failure tests cover both 128-byte inline boundaries, retry
after OOM, invalid long UTF-8 cleanup, retained-suffix rollback, and the
existing maximum-reason timeout paths. Session teardown and every terminal
send branch free owned fallback storage. The bidirectional native wtransport
gate was reconfirmed on 2026-10-02 after this change, covering both endpoint-
role directions through CONNECT, streams, DATAGRAM, cancellation, drain, and
terminal close behavior.
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

Independently owned handshake client/server sessions also expose
`waitForStreamRecoveryIdleWithTimeout` / `waitForStreamRecoveryIdleWithDeadline`
for one associated send direction. The selected stream's DATA, FIN and
RESET_STREAM/RESET_STREAM_AT remain protected by normal QUIC ACK/loss/PTO
processing, while outstanding sibling streams do not prolong that wait.
Inbound associated traffic remains available to ordinary readers. Timeouts
remain retryable under a later deadline; ownership, receive-only direction,
awake-clock, callback-reader and dispatcher checks precede transport progress.
The shared implementation lives in `runtime/stream/recovery.zig`, and HTTP/3
handshake client/server APIs expose the same per-stream waiting through
`http3/runtime/stream/recovery.zig`. The QUIC layer supplies a read-only
stream-scoped delivery query without adding send-path metadata. Wire regressions
exercise both endpoint roles, bidi/uni FIN and RESET, outstanding sibling FIN,
preserved inbound data, timeout/retry, and recovery after a dropped target
packet.

The focused WebTransport and HTTP/3 lifecycle/recovery/QPACK matrix passes 485
tests in Debug and ReleaseFast, and package reachability passes two tests. The
bidirectional wtransport gate now invokes the per-stream wait after bidi and
uni FIN submission in both netz roles, then completes cancellation, concurrent
sibling reuse and session close with the external peer.

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
carry the same bounded contract through fragmented request HEADERS and the
successful response. Authenticated server admission completes receive-credit
and CONNECT-association preparation before making 200 visible, then sends the
response HEAD and detaches the request reader within the same absolute
deadline. A deterministic exhausted-pacer regression proves an expired attempt
sends and sleeps zero times, retains the pending request without outbound-body
state, and succeeds when retried under a fresh budget. The full
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

The legacy adapter also preserves CONNECT RESET_STREAM events in both roles:
targeted client H3 polling retains the raw code before its generic
RequestCancelled/RequestRejected result consumes it, while server polling
forwards its structured reset. The shared Capsule control closes the Session
and releases any partially decoded CLOSE reason without requiring a clean
Capsule boundary. An already-decoded CLOSE retains its borrowed metadata.
Real protected-UDP regressions verify that Session application sends stop
and ordinary HTTP sibling requests continue on the same connection.

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
without an extra cancellation. Direct successful promotion flushes the response
HEAD's delayed QUIC ACK before ownership changes, preserving the caller's
absolute deadline when present. A real reused-connection regression first
drains all earlier recovery traffic, then proves a short-lived server can retire
the accepted response without the client performing another receive. Legacy
helpers still return `SessionRejected`,
but only after draining the entity. The authenticated pending server API uses
the HTTP/3 paced writer for the same complete rejection entity. A
dispatcher pending attempt waits for the complete rejection and preserves DATA
already coalesced behind the head. Real QUIC/TLS regressions cover explicit and
legacy rejection, body/trailer ownership, overflow, and a successful sibling
request on the reused connection. Server-side `acceptSession*` and
`receiveSessionRequestFromSession*` provide the symmetric caller-owned entry
points: an accepted session keeps ownership, while explicit rejection returns
the H3 session when its `RejectedHandshakeSession` is destroyed. The rejected
value exposes bounded delivery-only recovery drains so an owning server can
keep a final 3xx-5xx response recoverable through loss without waiting for
replaceable receive-credit acknowledgements. Dropping a
pending decision rejects only that CONNECT before restoring the session. A
real handshake test exercises both outcomes and then serves a sibling request.

Authenticated and stateful preconfigured QUIC constructors now accept exact
initial Session quotas through `Limits.initial_flow_limits` and
`EndpointClientOptions.initial_flow_limits`. Null retains the existing defaults;
an explicit zero remains zero in SETTINGS rather than being filled by a
constructor. `settingsWithInitialFlowLimits` provides the same normalization
for direct HTTP/3 setup. When Session flow control is negotiated, zero data or
stream credit remains blocked until its WT_MAX_DATA/WT_MAX_STREAMS grant.
These initial values apply to every Session on that transport as draft-16
section 5.5 requires. A single Session can explicitly disable negotiation with
three zero values; a multi-Session server configuration requires at least one
nonzero intent value. Legacy stateless adapters reject explicit quotas because
they lack Session flow accounting. Reusing an established transport requires
matching its already configured settings and cannot rewrite initial quotas.
Adjacent real protected-QUIC tests drive both constructor directions, retain
zero data through an initial timeout, then exchange bytes after explicit data
and stream grants. Shared-client tests prove that granting one Session leaves
its sibling blocked. The settings policy is grouped under
`webtransport/settings/flow.zig`.

```zig
.limits = .{
    .initial_flow_limits = .{ .data = 0, .bidi = 1, .uni = 0 },
    .require_session_flow_control = true,
}
```

`Limits.require_session_flow_control` and
`EndpointClientOptions.require_session_flow_control` default to false. Setting
either to true makes negotiated Session flow control an admission requirement:
the client checks peer SETTINGS before allocating or sending CONNECT, including
queued dispatcher attempts and reuse of an existing authenticated transport.
The shared client retains this transport-wide policy for every Session open.
Servers reject a valid CONNECT that lacks negotiated flow control with scoped
`H3_REQUEST_REJECTED` RESET_STREAM/STOP_SENDING before sending status 200.
Failed cancellation retains the request owner for retry, leaving the connection
and sibling Sessions usable. The `serveUntil` loop continues after this policy
refusal and can accept a later qualifying peer. Owning pending server decisions
enforce the policy on acceptance, retaining their metadata for cancellation
retries. The local result is `SessionFlowControlRequired`,
not a malformed-peer error. Explicit three-zero initial quotas combined with
the requirement fail as `InvalidSessionState` before transport construction;
legacy stateless adapters return `SessionFlowControlRequired` because they
cannot enforce it. Real protected-QUIC and TLS/shared-endpoint regressions
exercise required-policy rejection, retained cancellation, and accepted quota
grants. Legacy wtransport interoperability continues with the default policy.

Shared endpoints schedule retained CONNECT refusals as connection work even
when the peer has no accepted Session. Each buffered poll retries cancellation
before waiting for UDP traffic; pacing or congestion on one connection leaves
other connections and accepted Sessions eligible for progress. Early-stream
termination and CONNECT cancellation refresh the dispatcher timer after both
successful and failed submissions. The original scoped rejection cause is
reported only after its cancellation reaches the socket. Refused connections
also remain eligible for later buffered CONNECT requests, including a valid
request coalesced in the same QUIC packet as a malformed sibling. Cancellation
ownership and admission reservations are grouped in
`webtransport/runtime/connect/endpoint_rejection.zig`. Adjacent protected-QUIC
tests cover no-new-packet retry, pacing isolation, recovery timer replacement,
expired deadlines, and coalesced sibling admission.

`serveUntil` reports peer failures through `ServeEvent.handshake_failed`,
`connect_rejected`, `connection_failed`, and `session_failed`, then continues
serving the endpoint. CONNECT refusals expose the connection handle, Session
ID, finite `ConnectRejectionReason`, and HTTP/3 cancellation code, including
otherwise-silent Session capacity refusals. A Session failure is reported after
its CONNECT reset has been submitted; the notification consumes the terminal
error report while endpoint maintenance continues associated-stream cleanup.
Connection failures require a peer protocol error and a matching local HTTP/3
application close, preserving the dispatcher's close/recovery lifecycle.
Handshake failures retain the supervisor's finite worker error and pending
handshake handle. Application callback errors and endpoint I/O/resource errors
return from `serveUntil` to the caller.

Failure capture lives only for one synchronous endpoint receive and is cleared
before the callback. Ordinary `receive*` APIs retain their existing error
results, including calls made inside a callback. Peer failure notifications
carry copied metadata and require no queue allocation. The service loop and
failure boundary live under `webtransport/runtime/endpoint_server/serve.zig`.
Real QUIC/TLS regressions exercise malformed and excess CONNECT, malformed
Capsule and flow rejection, post-close data, a closed critical stream, failed
ALPN negotiation, continued sibling traffic, and independent socket/callback
error propagation.

HTTP/3 parsing failures before a valid CONNECT head also retain their request
scope. `HandshakeServerSession.pollRequestEventOnceWithFailure` returns a
`RequestEventResult` containing a normal event or an identified `RequestFailure`.
The failure carries its stream ID, finite parser error, and cancellation code;
its caller owns `tryCancelRequest` submission and any needed retry. Local
operation failures and QPACK/connection errors propagate as errors. The shared
WebTransport admission reader transfers these failures into its reserved
CONNECT rejection owner before attempting cancellation, so a failed socket
submission cannot lose the cause or the stream. Completed failures reach
`ServeEvent.connect_rejected` with `ConnectRejectionReason.http3_request_error`
and the optional `ServeConnectRejection.http3_error` payload. Buffered valid
sibling requests remain eligible for admission after rejection. Adjacent real
QUIC tests cover missing or duplicate pseudo-headers, socket-failure retry,
coalesced sibling admission, explicit rejection ownership, allocation errors,
and QPACK connection scope.

Default HTTP/3 request event polling now retains its own failed-message
cancellation state. It reserves failure storage before decoding and suspends
the failed reader until cancellation is submitted, allowing healthy sibling
requests to remain selectable under pacing or congestion. Detection still
reports the parser error immediately when cancellation is only backpressured.
Socket errors propagate with the original failure retained; completed retry
reports the original parser error while retiring its owner. Targeted polls
preserve each request's own failure, and owning receives retain cancellation across their existing
deadline. The explicit `pollRequestEventOnceWithFailure` API can also take
ownership of a failure previously retained by default polling. This state
remains bounded by the existing live request limit.

Fresh request and response failures transferred by explicit polling also
suspend their readers until caller-owned cancellation completes. Further
poll/read calls cannot rediscover the same parser failure, and other streams
remain selectable. Server-side cancellation now registers completed receive
halves for QUIC reclamation: RESET acknowledgment returns MAX_STREAMS credit,
while a late FIN completes an initially unfinished upload's retirement. Failed
application cancellation preserves pending rejection even when malformed
HEADERS prevented the request from entering the application lifecycle. Real
QUIC tests constrain the connection to one concurrent stream and verify a new
request can proceed after ordinary or malformed-request cancellation.

The handshake client's incremental response event polls retain the same
cancellation ownership. A malformed response suspends only its reader, while
healthy response streams can continue under cancellation backpressure. Socket
errors and receive deadlines preserve the failed request and its parser cause;
a completed cancellation retry reports that original cause. The explicit
`HandshakeClient.pollNextResponseEventOnceWithFailure` API returns a
`ResponseEventResult` with either an event or a `ResponseFailure`, and transfers
cancellation ownership for fresh or retained failures. Local allocation errors
leave decoding retryable; malformed QPACK remains a connection error. Shared
pending cancellation storage lives in `http3/runtime/receive/pending_failure.zig`,
with adjacent request and response ownership types and protected-QUIC tests.

Handshake request and response DATA access shares that failed-message owner.
Reads, available-byte queries and skips retain Content-Length cancellation
across socket failures or backpressure, and a later event poll can transfer
the failure to its explicit caller. A suspended message exposes no further
payload while healthy siblings remain eligible for events. Truncated DATA
frames still close the connection with `H3_FRAME_ERROR`; API-state errors leave
the message intact. The shared `http3/runtime/receive/message_data.zig` module
returns successful read/skip counts before advertising their receive credit,
so a later socket failure cannot hide bytes already consumed. The next read
or event poll submits that credit. Real QUIC regressions cover both roles,
late FIN, cancellation retry and transfer, rejection allocation failure,
framing/operation error scope, and receive-credit retry without duplicate DATA.

Handshake-client push polling and DATA reads also retain stream-local failure
ownership. A failed push keeps its Push ID, parent request ID, stream ID,
parser cause and cancellation code until STOP_SENDING is submitted, and skips
that reader while healthy pushes and ordinary responses remain usable.
`pollPushEventOnceWithFailure` returns an event or an identified `PushFailure`;
its caller can retry `tryRejectPush` without cancelling the parent request.
Detection reports its parser cause under cancellation backpressure, socket
errors preserve the rejection for retry, and receive deadlines keep the owner.
Explicit CANCEL_PUSH can take over retained rejection; a peer RESET retires
the failed owner and promise without reopening its stream. QPACK cancellation
is prepared before STOP_SENDING and recorded once; failed decoder feedback
remains queued. Allocation/API errors retain ordinary scope and malformed
QPACK or truncated DATA remains a connection error. These policies live under
`http3/runtime/stream/push/` with adjacent protected-QUIC regressions.

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
   checks netz's peer QUIC application-close code and reason handling. A
   separate Firefox 156.0.1 gate now binds its output to Puppeteer's actual
   launched-browser version, launcher/process-image SHA-256, and page/server
   User-Agent before covering
   Origin policy, CONNECT, DATAGRAM, both stream directions, exact mapped
   RESET_STREAM code 71, same-Session reuse after reset, DRAIN framing and
   exact close metadata. Firefox STOP_SENDING remains open because its current
   reader `cancel()` path did not emit code 72 for either a consumed or unread
   payload, even after a following outbound DATAGRAM. Safari automation
   remains a separate gap.
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
   A 2026-10-18 ceiling extension then ran only the 256-stream shape at 64 KiB
   per stream, three seeds for each sender/fault pairing: twelve additional
   cross-implementation sessions. With netz sending, loss runs delivered
   118-132 FINs and 124-138 resets, verified 7,768,576-8,682,496 bytes and
   dropped 394-453 of 8,214-9,171 considered datagrams; reorder runs delivered
   128-130 FINs and 126-128 resets, verified 8,421,376-8,551,936 bytes and held
   1,571-1,577 datagrams. With wtransport sending through the single-shot
   relay, loss runs delivered 128-138 FINs and 118-128 resets with exactly two
   drops; reorder runs delivered 114-133 FINs and 123-142 resets with exactly
   two held pairs. Every run independently matched its seeded byte count,
   checksum, 256-bit reset mask and application-code sum. This extends the
   maximum-concurrency cross-peer evidence to three repetitions and four times
   the prior per-stream payload without turning loopback fault injection into
   a production-network claim.
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
   A 2026-10-18 native ceiling run then raised every stream to 64 KiB and ran
   ordinary loss, client-direction reordering, reliable-reset loss and
   reliable-reset reordering three times each. The first loss attempt exposed
   the benchmark's ordinary-reset loop using the single-attempt API: after the
   congestion window filled, legal `CongestionLimited` backpressure escaped as
   a fatal error. Ordinary resets now use `resetStreamWithDeadline`, sharing
   the send phase's original absolute deadline while ACK/PTO progress makes the
   next RESET_STREAM sendable, matching the already bounded reliable-reset and
   FIN paths. All twelve reruns passed. Each mixed run verified 128 resets, 128
   FINs and 8,454,144 bytes with its exact checksum; each all-FIN reorder run
   verified 256 FINs and 16,777,216 bytes. This closes the maximum-concurrency
   repeatability shape at three repetitions; multi-minute and heterogeneous
   network distributions remain evidence work rather than a basic progress
   bug.
   The default `interop-webtransport-stream-churn` gate now appends a compact
   ceiling regression on every run: 256 streams, 512 bytes per stream, 128
   ordinary resets after a 256-byte prefix and deterministic 5% loss. It
   verifies 98,304 bytes and forces the reset burst beyond the initial
   congestion window, preserving the former failure boundary without turning
   routine validation into the full 64-KiB long-run matrix.

The whole-stream and caller-buffer incremental receive pollers enumerate QUIC
receive streams through a fixed 256-ID stack page, but that page is not a
protocol limit. Dedicated regressions populate 256 unrelated peer streams and
place the matching WebTransport stream in the next physical table slot. Both
the whole-stream poller and the incremental poller find the second-page target;
the latter also starts from a stale round-robin cursor and proves the wrapped
scan still crosses the page boundary.
Shared server association lookup recognizes accepted and pending Sessions on
the same connection. Polling an active Session leaves early data for a pending
sibling buffered until acceptance; a real QUIC/TLS regression delays the second
Session's acceptance while the first remains active and verifies exact delivery.
Maintenance discovery leaves other Session IDs untouched. Standalone explicit stream
pollers reject unknown Session IDs and continue to a valid sibling instead of
poisoning later polls. Rejected peer bidi streams receive one atomic
`RESET_STREAM` plus `STOP_SENDING`, peer uni streams receive
`STOP_SENDING`, all with `WT_BUFFERED_STREAM_REJECTED`. Retained and late bytes
are discarded to restore connection flow-control credit, terminal streams are
retired from QUIC without consuming this session's registry limits, and both
blocking and one-attempt pollers continue to a valid sibling.
Authenticated and stateful WebTransport servers now retain DATAGRAMs that arrive
before their CONNECT is registered. `Limits.early_connect_datagrams` defaults to
64 payloads and 64 KiB per connection, with a 30-second age limit; packet routing
and acceptance expire stale entries. Count/byte pressure evicts the oldest early
payload, and an individually oversized payload is dropped. Accepted association
queues retain their independent limits. Generic HTTP/3 leaves this behavior
disabled unless `HandshakeSessionOptions.early_connect_datagrams` opts in.
Acceptance reserves metadata and queue storage before sending 200, then transfers
early payloads in order after the response is committed. A failed acceptance
restores its reservation without consuming early data or recording a retired
association. Explicit or protocol-level rejection discards only that CONNECT's
early payloads. Retired association history is bounded and folds QUIC's retired
stream ranges so completed data streams do not impose a lifetime Session limit.
Late payloads cannot recreate a removed association; unknown FIN/reset and QUIC
connection termination discard their early state. Tests cover allocation failure,
FIFO/count/byte limits, age expiry, actual QUIC pre-CONNECT reordering, acceptance
send failure/retry, a 403 rejection and continued sibling delivery.

The shared `EndpointServer` also retains streams whose CONNECT has not yet
arrived, with `Limits.early_connect_streams` defaulting to 64 streams, 256 KiB
of retained offset span and a 30-second lifetime per connection. The byte policy
includes association headers and out-of-order gaps. Metadata remains separate
from QUIC's payload storage; acceptance releases the early claim without choosing
a whole-stream or incremental reader. Existing registered stream records are
never reparsed as association headers, even when their next application bytes
look exactly like a WebTransport prefix.
Unknown and pending Sessions share this budget. Count/byte overflow and expiry
reject the affected stream with WT_BUFFERED_STREAM_REJECTED. Unclaimed streams
for rejected CONNECTs, removed Sessions and already-closed Sessions instead trigger WT_SESSION_GONE;
the exact transport marker survives prefix abandonment and late data. Before
cancellation reaches the socket, send and metadata-allocation failures retain
unconsumed data for retry. After submission, the marker retains the scoped
decision while QUIC releases abandoned receive credit.
The endpoint's socket wait includes the earliest expiry, so cleanup also runs
without later traffic, while preserving the application's absolute deadline.
Each maintenance step submits at most one cancellation packet and refreshes its
dispatcher timer. Registered application streams keep their owning Session's
lifecycle. Invalid Session IDs close the connection with H3_ID_ERROR, as required
by draft-16 section 4; a closed valid Session ID still uses scoped cleanup.
Focused tests cover both stream directions, count/byte limits, fragmented
association headers, cancellation/allocator failure, already-owned data and
invalid IDs. Real QUIC/TLS cases verify a stream arriving before CONNECT on an
active sibling connection, idle expiry wakeup, delayed acceptance, and exact
WT_SESSION_GONE after a 403 rejection with continued sibling DATAGRAM delivery.
The dedicated early-stream policy currently applies to the shared server;
standalone owning and client admission paths retain their QUIC receive bounds.

Ordinary stream association now uses the same connection-error boundary as
early-stream discovery. An invalid Session ID on a peer bidi or uni stream
returns `InvalidSessionId` and installs `H3_ID_ERROR` (0x108) before any registry
insertion or application-byte consumption. Owning whole-stream and incremental
readers, nonblocking stream polls and DATAGRAM-only maintenance all enforce this
rule in both endpoint roles, including when a valid DATAGRAM is already ready.
A fragmented Session ID remains buffered until its varint completes; a failed
close socket write retains the protocol error and local closing state. Focused
preconfigured-key QUIC/UDP regressions exercise these boundaries. Existing
pending/unknown/closed valid Session IDs continue through their scoped handling.
