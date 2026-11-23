# QUIC/HTTP/WebSocket/WebTransport review, 2026-11-21

Base revision: `28dd7d76`, Zig 0.16.0, macOS aarch64. This is a focused
correctness and interface review of connection setup, CRYPTO/stream ownership,
fallback and shutdown paths. It fixes the confirmed QUIC handshake defect and
records remaining design findings without changing their behavior.

## Fixed: Handshake CRYPTO flights were single-datagram

`prepareHandshakeCrypto` sealed the complete Handshake-level CRYPTO flight into
one UDP datagram and rejected it with `DatagramTooLarge` when it exceeded the
endpoint limit. Real certificate flights routinely exceed a safe MTU:

- The H3 endpoint default is 4 KiB (`receive_policy.default_endpoint_max_datagram_size`).
- A normal 3-4 KiB certificate chain plus CertificateVerify and Finished can
  cross that bound.
- At a 1200-byte path MTU almost any real chain fails.
- Client mTLS flights have the same problem, and the server's
  `receiveClientHandshakeCryptoFromDatagram` created a fresh reassembler per
  datagram, so it also required the client flight to arrive in one datagram.

The fix adds MTU-bounded Handshake packetization (`sendHandshakeProgress`,
`handshakeFlightWireLen`, `handshakeFlightPacketCount`,
`largestHandshakeChunk`) and keeps one CRYPTO reassembler across client
datagrams. Each packet carries one contiguous CRYPTO range and consumes a fresh
packet number.

### Packet-number ownership

`HandshakeFlight` previously had no `next_packet_number`. After sending the
client Finished flight, the caller still pointed CONNECTION_CLOSE at the first
packet number of that flight, so an error on the post-send path could reuse an
AEAD nonce. The flight now records the first unused packet number, and
retransmissions stride by the complete flight size instead of one.

### Evidence

| Gate | Result | Artifact |
| --- | --- | --- |
| 1200-byte endpoints, 16-entry certificate chain (4928 bytes), server auth + mTLS, Threaded + zio | 36/36 | `handshake-fragmentation-debug.log` |
| Existing handshake/PTO/certificate/prepared-verifier regressions | 63/63 | `handshake-regression-debug.log` |
| Direct H3 and ordered protocol policy end-to-end | 108/108 | `http-h3-debug.log` |

The end-to-end case previously required 8192-byte datagrams to pass; it now
runs at 1200 bytes. Client and server flights both span multiple packets, and
the server reassembles the client Certificate flight across datagrams.

```sh
zig build test-quic \
  '-Dtest-filter=QUIC Handshake CRYPTO flight packetizes' \
  '-Dtest-filter=QUIC default CRYPTO limit' --summary all

zig build test-quic \
  '-Dtest-filter=QUIC handshake' '-Dtest-filter=certificate' \
  '-Dtest-filter=prepared' '-Dtest-filter=handshake PTO' --summary all

zig build test-http \
  '-Dtest-filter=unified HTTP direct H3' \
  '-Dtest-filter=unified HTTP protocol policy' --summary all
```

## Fixed: minor interface hygiene

`http.ResponseSink.discard()` pointed at a `const` context through
`@constCast`. The storage is now writable even though the stateless callbacks
never access it, removing a latent UB footgun from a public constructor.

## Findings ledger

These are source-level findings from the opening audit. Every entry is now
resolved; the pass that closed each one is recorded in the row and in the
sections below.

| ID | Area | Finding | Suggested direction |
| --- | --- | --- | --- |
| P1 | Resolved in the second pass | After an H3 *connection* failure the body was never read, yet fallback for an idempotent method still called `bodySource().prepareReplay()`, rejecting a single-pass Reader. | The attempt now records whether the request started; setup failures fall back without replay, started requests keep method/replay gating. |
| P2 | Resolved in the twenty-second pass | Server Handshake flights previously required the complete certificate flight to fit the anti-amplification allowance. | The sender now plans the largest prefix of the unacknowledged CRYPTO suffix, advances packet numbers contiguously, and maps client ACKs to delivered ranges. The 40-entry 1200-byte certificate and mTLS regressions pass; see the twenty-second pass below. |
| P3 | Resolved in the sixth pass | The legacy/stateless adapters returned `WebTransportNotNegotiated` for caller configuration they cannot support (`initial_flow_limits`). | They now return `UnsupportedWebTransportOption`; genuine peer capability failures keep `WebTransportNotNegotiated`. |
| P4 | Resolved in the eighth pass | `Client.Options.http3.handshake.handshake.alpn_protocols` nests two `handshake` levels because the facade wraps the native handshake options. | `nativeHandshake()`/`sessionOptions()` return mutable pointers to the native blocks, so call sites no longer spell the nested path; the stored layout is unchanged. |
| P6 | Resolved | `drains GRO response batch one packet at a time` hung on platforms without GRO because its skip path joined a server thread still blocked in `receiveRequest`. | The skip path now closes the connection first; the test skips cleanly and the full H3 suite completes. |
| P5 | Resolved in the seventh pass | `websocket.stream_connection.Connection.close()` had no deadline form and `receiveMessage()` had no absolute-deadline variant. | Optional `read_deadline_fn`/`write_deadline_fn` callbacks now back `receiveMessageWithDeadline`, `sendFrameWithDeadline`, the typed send forms and `sendCloseWithDeadline`; missing callbacks return `DeadlineUnsupported`. |
| P7 | Resolved in the eleventh pass | The 1-RTT application send size is configured through `handshake.handshake.initial_one_rtt_config.max_datagram_size` while `limits.quic.max_datagram_size` is only the socket cap. | `Http3ConnectOptions.applicationDatagramSize()`/`setApplicationDatagramSize()` expose one knob and raise the socket cap to match; the native fields keep their intentional two-layer meaning. |
| P8 | Resolved in the twelfth pass | The WebSocket bounded-send test assumed a 512-KiB frame blocks behind a small socket buffer. | The test detects a host that absorbs the frame and skips; the blocking path keeps its timeout and progress assertions. |

Counts include imported support tests and overlap between bundles. The evidence
is scoped loopback and source-boundary verification; it is not a new
external-peer matrix or performance claim.


## Second pass: H3 stream ownership and fallback wake

The P1 follow-up exposed two deeper defects that are now fixed.

### Stream-start double free

Both H3 dispatchers armed raw `errdefer allocator.destroy(...)` for the stream
and handle *and* called `handle.deinit()` on timeout. DebugAllocator reported a
double free at `startStream` after a pending connection failure. Ownership is
now explicit: raw errdefers are armed only before the command is enqueued; after
enqueue every failure path calls `handle.deinit()`.

### Pending connect failures did not wake stream callers

`complete()` set `command.done` but stream callers wait on the stream's own
`user_ready` event. A failed pending H3 connection therefore stayed invisible
until the outer request deadline: a 150-ms H3 connect budget surfaced as a
5001-ms `Timeout`. `complete()` now fails the attached stream before setting
`command.done`, and the request falls back to TCP at the configured budget.

### Alt-Svc fallback without a started request

`requestHttp3` now reports whether the request head was emitted. A connection
setup failure can use the configured TCP route for any method without a rewind;
once the request starts, the existing method/replay policy still applies.
This preserves the existing test where an H3 upload rejection must not replay a
consumed single-pass Reader.

### WebSocket byte-stream close state

The generic adapter allowed data frames after either side started the closing
handshake, and marked a failed Close write as sent. It now rejects non-Close
frames after the closing handshake starts, refuses further receives after a
peer Close, and marks `close_sent` only after a successful write.

| Gate | Result | Artifact |
| --- | --- | --- |
| H3 fallback, direct H3, pooled H3, streaming deadlines | 119/119 | `h3-fallback-debug.log` |
| WebSocket stream adapter close state | 10/10 | `websocket-close-debug.log` |
| H3 runtime suite | Filtered bundle: 61/61 passed, 1 skipped, 1 pre-existing GRO hang (current and base `28dd7d76`) | `http3-gro-hang.txt` |

The H3 fallback case uses a discovery Alt-Svc entry pointing at a closed UDP
port, a 150-ms H3 connect budget and a single-pass PUT Reader. It now reaches
TCP in about the connect budget instead of consuming the 5-second request
deadline, and the Reader is consumed exactly once.

The complete `test-http3` suite could not finish because
`HTTP/3 handshake client drains GRO response batch one packet at a time`
blocks: the client joins its server thread while the server waits in
`receiveRequest` for a request that never arrives. A clean worktree at
`28dd7d76` reproduces the identical stack, so it is unrelated to this batch and
is recorded as an open finding (P6) rather than hidden as a pass.


## Third pass: H3 close parity and final-flight send failures

Two smaller correctness gaps closed after the second pass.

- `http.Connection.close()` for H3 only deinitialized the QUIC owner, so the
  peer learned about the end through an idle timeout instead of
  CONNECTION_CLOSE. It now sends a best-effort `CONNECTION_CLOSE` with
  `NO_ERROR` before teardown. `closeWithoutCloseNotify` and
  `closeWithDeadline` remain local, deadline-safe teardown.
- The client's final Handshake CRYPTO flight has no PTO retransmission. Its
  sender previously ignored `send_error` and partial socket progress, so a
  failed or truncated Finished flight could look like a successful handshake.
  It now returns the socket error (or `HandshakeSendFailed`) and preserves the
  first unused Handshake packet number so the error-path CONNECTION_CLOSE
  cannot reuse a protected AEAD nonce.

| Gate | Result | Artifact |
| --- | --- | --- |
| Direct H3 including peer-observed CONNECTION_CLOSE, plus protocol policy | 109/109 | `h3-close-debug.log` |
| QUIC handshake, PTO, certificate, prepared verifier, CRYPTO limits | 64/64 | `quic-close-debug.log` |

The close test has the server session wait for the next request after the
response and assert `error.ConnectionClosed`, proving the facade delivered the
close frame rather than dropping the connection locally.


## Fourth pass: handshake datagrams must not rely on IP fragmentation

The H3 endpoint default is a 4096-byte datagram limit, chosen for receive
batching. Handshake flights previously used that same value as their send
packet size, so a certificate flight could leave as a 4-KiB UDP datagram before
PMTUD had confirmed the path. RFC 9000 requires QUIC handshakes to fit the
minimum path MTU; relying on IP fragmentation is not interoperable.

Client Initial, retransmitted Initial, client final Handshake, and server
Initial+Handshake flights are now capped at 1200 bytes via
`quic.initial_exchange.handshakeDatagramSize`. The existing CRYPTO
packetization splits larger flights; the endpoint receive capacity is
unchanged.

| Gate | Result | Artifact |
| --- | --- | --- |
| QUIC handshake, PTO, certificate, prepared verifier, CRYPTO limits | 65/65 | `quic-handshake-mtu-debug.log` |
| Direct H3, protocol policy, Reader replay/fallback, pooled H3 | 115/115 | `http-handshake-mtu-debug.log` |

### Correction: 1-RTT already defaults to 1200

A follow-up inspection of `quic.one_rtt.Config` and `quic.handshake` showed that
1-RTT packets already default to `max_datagram_size = 1200`
(`congestion.default_max_datagram_size`). The H3 endpoint's 4096-byte limit is
a socket/receive capacity, not the 1-RTT send size; only handshake flights were
incorrectly using it. The handshake cap above is therefore the complete
interop fix for the default configuration.

The remaining interface wart is that raising the application send size requires
`handshake.handshake.initial_one_rtt_config.max_datagram_size`, while
`limits.quic.max_datagram_size` is only a socket cap. The two knobs are now
documented; unifying their names is a future API cleanup (P7, revised).


## Fifth pass: WebSocket byte-stream close metadata

The generic `websocket.stream_connection` adapter now parses incoming Close
payloads instead of discarding them:

- `peerClose()` exposes the retained status code and reason.
- The reply echoes the peer's status code, as RFC 6455 5.5.1 recommends.
- An oversized close reason returns `InvalidControlFrame` instead of being
  silently truncated.
- A malformed Close/control frame sends Close 1002, marks the adapter terminal
  and returns the parser error; the next call no longer re-reads the same
  buffered bytes.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebSocket stream adapter close/state cases | 13/13 | `websocket-stream-close.log` |
| Full WebSocket suite | 501/502; one pre-existing host-sensitive failure at HEAD | `websocket-suite.log` |

The full-suite failure is
`HTTP1 context takeover commits only after bounded send completes`: the test
expects a 1-second timeout from a 512-KiB write with `SO_SNDBUF=4096`, but this
host completes the write. It reproduces with the working tree stashed at
`32c48e52`, so it is recorded as P8 rather than attributed to this change.


## Sixth pass: WebTransport option errors

The legacy/stateless WebTransport adapters reject explicit Session flow-limit
configuration because they cannot account for it. They previously returned
`WebTransportNotNegotiated`, which reads as a peer negotiation outcome. The
three construction sites now return `UnsupportedWebTransportOption`, while a
genuinely unavailable peer capability still returns
`WebTransportNotNegotiated`.

| Gate | Result | Artifact |
| --- | --- | --- |
| Explicit flow limits and required-flow-control construction cases | 117/117 | `webtransport-options-debug.log` |
| Full WebTransport suite | 756/758 passed, 2 skipped | `webtransport-suite.log` |


## Seventh pass: WebSocket byte-stream deadlines

`websocket.stream_connection` gained optional absolute-deadline transport
callbacks. When `read_deadline_fn`/`write_deadline_fn` are present,
`receiveMessageWithDeadline`, `sendFrameWithDeadline`, the typed
`send*WithDeadline` forms and `sendCloseWithDeadline` bound both lock
acquisition and the transport operation with one awake-clock deadline.
Without the matching callback they return `error.DeadlineUnsupported`; the
ordinary blocking forms are unchanged. The automatic Pong and Close replies
inside a bounded receive use the same deadline.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebSocket stream adapter deadline and close cases | 15/15 | `websocket-deadline-debug.log` |
| Full WebSocket suite | 503/504; only the pre-existing P8 host-sensitive failure | `websocket-suite-deadlines.log` |


## Rejected experiment: server-only handshake prefixes

A prefix-only change to `InitialHandshakeFlight` was implemented and then
reverted. It computed the largest CRYPTO prefix fitting the current
anti-amplification budget and sent that prefix on every PTO. The 1200-byte
16-certificate regression timed out (`HandshakeTimeout`): after the client
receives the server Initial it enters `receiveServerHandshakeCrypto` and stops
sending, so the server's received-byte budget does not grow and the remaining
certificate prefix is never admitted. The fix must add client-side PTO
retransmission/probing while waiting for the server flight; server prefix
sending alone is not sufficient. The working tree was restored to the audited
revision, and the large-certificate test continues to pass with the complete
reservation.


## Eighth pass: H3 flat accessors and a test-discovery gap

`Http3ConnectOptions` gained `nativeHandshake()` and `sessionOptions()`, which
return mutable pointers to the native QUIC/TLS handshake and HTTP/3 session
option blocks. This removes the need to spell `handshake.handshake` or
`handshake.session` at call sites without changing the stored layout.

While adding the regression, `-Dtest-filter="unified HTTP ALPN policy"` failed
the focused-suite guard: `client/types.zig` was imported by `client.zig` but
its test block was not referenced from a test block, so the ALPN policy and H3
option tests were never part of `test-http`. Adding `_ = types;` to the client
test block includes them.

| Gate | Result | Artifact |
| --- | --- | --- |
| H3 flat accessors plus the previously unregistered ALPN policy test | 85/85 | `h3-flat-accessors.log` |


## Ninth pass: client PTO probing while awaiting a Handshake flight

`receiveServerHandshakeCrypto` previously waited with one passive deadline and
sent nothing after the first Handshake ACK. A server that sends a partial
certificate flight subject to anti-amplification therefore had no way to grow
its received-byte budget. The wait loop now uses per-PTO attempts: on timeout it
invokes an optional `retransmit.Probe`, which the client wires to its sent
Initial (or 0-RTT) flight, then retries until `max_retries` or the hard
deadline. Any received datagram resets the PTO counter.

The deterministic unit test uses a scripted source that times out twice before
returning a complete Handshake packet. With the probe, the source is polled
three times and two probes are emitted; without a probe, the same always-timeout
source returns `HandshakeTimeout`. A 40-entry certificate regression also runs
at 1200-byte datagrams with the default retry count.

| Gate | Result | Artifact |
| --- | --- | --- |
| Probe unit case plus handshake/certificate/PTO/CRYPTO regressions | 66/66 | `quic-probe-regression.log` |
| Direct H3, protocol policy, H3 fallback | 111/111 | `http-after-probe.log` |


## Tenth pass: GRO skip-path deadlock and full H3 suite

The GRO response-batch test is Linux-specific. On a host without GRO it took
its skip branch, which joined a server thread that was already blocked in
`receiveRequest`; the client had not sent any requests because the skip check
runs immediately after the handshake. The skip path now sends
`CONNECTION_CLOSE`, joins the server, and returns `SkipZigTest`.

With that fixed, the complete `test-http3` suite finishes instead of hanging:
927/931 passed and 4 skipped. One load-sensitive assertion in the concurrent
handshake test observed 2 completed requests instead of 1: the producer's
timeout completion can race its abandoned flag under full-suite load. The test
now accepts both orderings, matching the existing pending-handshake test's
race-tolerant assertion; the isolated test still passes.

| Gate | Result | Artifact |
| --- | --- | --- |
| GRO test in isolation | 61/63 passed, 2 skipped | `http3-gro-fixed.log` |
| Full HTTP/3 suite | 927/931 passed, 4 skipped | `http3-full-after-fixes.log` |


## Eleventh pass: application MTU helper and full HTTP gate

`Http3ConnectOptions` gained `applicationDatagramSize()` and
`setApplicationDatagramSize()`. The setter updates the 1-RTT send size and
raises the endpoint socket cap to match, so a valid packet cannot be rejected by
`DatagramTooLarge`. `Client.init` now rejects a 1-RTT send size larger than the
socket cap at configuration time.

Running the complete `test-http` gate exposed a compile regression from adding
`ConnectionValue.http3`: the `pool_returns` test support switched exhaustively
over `.http1`/`.http2` and had no `.http3` arm. It now treats H3 as unreachable
for the TCP TLS helper, and the full suite compiles.

| Gate | Result | Artifact |
| --- | --- | --- |
| H3 application MTU helper and direct H3 | 104/104 | `h3-mtu-validation.log` |
| Full HTTP suite | 303/303 | `http-full-suite.log` |


## Twelfth pass: WebSocket bounded-send host behavior

`HTTP1 context takeover commits only after bounded send completes` expects a
512-KiB compressed frame to block behind a small socket buffer. On this macOS
host the kernel absorbs the complete frame, so the call returns success and the
partial-write assertions cannot run. The test now detects that outcome and
returns `SkipZigTest`; on hosts where the write blocks it keeps the original
`Timeout`, progress, preview-pending and context-takeover assertions.

The full WebSocket suite now reports 503/504 passed with one skip and no
failures.

| Gate | Result | Artifact |
| --- | --- | --- |
| Bounded-send test on this host | 37/38, 1 skipped | `ws-bounded-send-skip.log` |
| Full WebSocket suite | 503/504, 1 skipped | `websocket-suite-final.log` |


## Rejected again: server prefixes with receive-driven PTO

After adding client PTO probes, server prefix sending was retried. The 16- and
40-entry 1200-byte certificate regressions still timed out. Each prefix attempt
delivers a datagram, which resets `receiveServerHandshakeCrypto`'s PTO counter;
the client therefore never reaches the timeout that emits a probe, and the
server budget stays at its initial value. Supporting both requires a probe
timer that advances independently of received datagrams (or ACK-driven budget
accounting). The working tree was restored; the client-probe tests pass 37/37.


## Thirteenth pass: deadline close parity for direct H3

`Connection.closeWithDeadline` validated the deadline and then deinitialized
the QUIC owner without sending CONNECTION_CLOSE, unlike `close()`. It now sends
the same best-effort `NO_ERROR` close after validation. The direct H3 close
test is parameterized over both forms and asserts that the server session
observes `error.ConnectionClosed`.

| Gate | Result | Artifact |
| --- | --- | --- |
| Direct H3 normal and deadline close | 97/97 | `h3-deadline-close.log` |


## Fourteenth pass: timer-driven client probes

The client probe schedule was previously driven by `receiveTimeout` errors:
any received datagram reset the PTO counter, so a server sending partial
certificate prefixes could suppress the probes indefinitely. The wait now uses
an absolute `next_probe_ms` timer:

- the receive wait is capped by the next probe time and the hard deadline;
- the top of the loop probes when the timer expires, regardless of traffic;
- the schedule restarts only when `reassembler.contiguous_end` advances.

The scripted probe test now honors the requested wait so the timer fires
deterministically. Probe, CRYPTO-limit and PTO regressions pass 40/40.

Server prefix sending was re-applied on top of the timer and still failed the
40-entry regression: the server's `InitialHandshakeFlight.send` ran once with
`available=7200`, `initial=2400`, `prefix=4551`, then never ran again even
though the client emitted probes. That is a separate server-loop issue; the
prefix change was reverted and is recorded as remaining P2 work.


### Prefix follow-up: budget exhaustion, not a missing retry

A diagnostic in `InitialHandshakeFlight.send` showed exactly one send
(`available=7200`, `prefix=4551`). The second attempt does not print because
`initial_bytes > available`: the first prefix consumed the complete 7200-byte
budget, and the client's probe datagrams did not increase
`anti_amplification.bytes_received`. The server loop does retry; it simply has
no budget. The next investigation is whether the probes are routed to the
pending handshake inbox or whether `observeReceived` is skipped for them.


## Fifteenth pass: server flight accounting and full QUIC gate

Running the complete `test-quic` suite exposed two test-gate problems and one
server-side accounting defect:

- `retransmit_tests` still passed a raw `SendInitialOptions` to
  `initialThenHandshakeCryptoWireLen`, whose second parameter became
  `SendFlightOptions` when Handshake CRYPTO flights were packetized. The test
  now wraps the options and the full suite compiles.
- `InitialHandshakeFlight` assigned `next_handshake_packet_number` only after a
  successful Handshake send. A partial Initial flight or a protection error
  left it null, so a later CONNECTION_CLOSE was skipped. The number is now
  reserved as `base + planned_packets` before any Initial datagram is visible.
- Migration-path tests bind `127.0.0.2`; hosts without that loopback alias now
  skip on `AddressUnavailable`.

The full suite completes: 1106/1130 passed, 23 skipped, and one rotating
load-sensitive UDP test failure. The dispatcher batch-suffix and receive
cancellation tests each pass in isolation; both are recorded as host-load
flakes rather than product failures.

| Gate | Result | Artifact |
| --- | --- | --- |
| Large certificate, client probe, PTO | 40/40 | `quic-after-accounting-focused.log` |
| Full QUIC suite | 1106/1130, 23 skipped, 1 rotating flake | `quic-full-final2.log` |
| Dispatcher and receive-cancel flakes in isolation | 33/33 and 32/32 | `quic-dispatcher-isolated.log`, `quic-receive-cancel-isolated.log` |


## Sixteenth pass: host-independent blocked-output deadlines

The full `test-http2` suite exposed that the saturation fixtures could not
bound a small control-frame write on this macOS host:

- A blocking descriptor ignores `MSG_DONTWAIT` once the peer window closes, so
  the fill loop itself slept in `sendto` and the suite hung.
- Filling through `O_NONBLOCK` and restoring blocking mode avoids the hang,
  but the kernel still accepts small frames past `EAGAIN`: a 17-byte PING, and
  even a 17-byte send behind a blocked 4 MiB filler, both succeed. The
  "blocked small write" premise is therefore host-dependent.

Changes:

- `internal/testing/tcp_saturation.zig` fills with `O_NONBLOCK`, restores the
  caller's descriptor flags, caps the fill, and reports
  `error.BufferNotSaturated` so a host without backpressure skips instead of
  hanging.
- The PING probe test stalls the transport's `netWrite` and asserts the
  deadline cancels the concurrent write (`Timeout`, terminal lease).
- `BlockedOutput.initStalled` gives the GOAWAY, PING-ACK and WebTransport
  SETTINGS write-timeout tests the same deterministic stalled output while
  keeping real socket reads.
- `closeWithTimeout` was added to `http.Connection`, `http1.Client` and
  `http2.Connection`, matching the existing `WithDeadline`/`WithTimeout`
  convention used by requests, WebSocket and WebTransport close paths. An
  expired budget still retires the transport.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/2 suite | 982/982 | `http2-full-after-stall-fix.log` |
| Refactored stalled-output state tests | 35/35 | `http2-stalled-output-tests.log` |
| HTTP/1 handoff backpressure gate | 36/36 | `http1-handoff-saturation.log` |
| Full HTTP suite after `closeWithTimeout` | 304/304 | `http-full-after-close-timeout.log` |
| Direct H3 close/deadline/timeout CONNECTION_CLOSE | 106/106 | `http-h3-close-timeout.log` |
| Internal saturation and wide-write tests | 224/224 | `lib-saturation.log` |
| Saturation helper unit test | 2/2 | `tcp-saturation-unit.log` |


## Seventeenth pass: generic opcode-driven bounded sends

`sendMessage(opcode, payload)` had no matching `WithTimeout`/`WithDeadline`
forms even though the typed `sendText*`/`sendBinary*` pairs and the
opcode-driven `sendMessageWithDeadlineLocked` already existed. HTTP/1,
RFC 8441 and RFC 9220 connections now expose:

- `sendMessageWithDeadline(opcode, payload, progress, deadline)`;
- `sendMessageWithTimeout(opcode, payload, progress, timeout)`.

Both validate text/binary opcodes before acquiring the send mutex, report the
same complete-frame `MessageWriteProgress`, and keep the existing partial-frame
retry identity. The bounded-mutex admission test now covers the generic form on
all three transports and both roles.

| Gate | Result | Artifact |
| --- | --- | --- |
| Generic bounded send plus mutex admission | 96/96 | `ws-generic-send.log` |
| Full WebSocket suite | 504/505, 1 host-sensitive skip | `ws-full-after-generic.log` |


## Eighteenth pass: adoption timeout parity

`adoptTlsStream` already had `WithTimeout`/`WithDeadline` forms, but
`adoptPriorKnowledgeStream` and `adoptNegotiatedTls` only had the unbounded and
absolute-deadline forms. Both families now expose `WithTimeout`, with the same
pre-transfer rule as `adoptTlsStreamWithTimeout`: a non-positive relative
budget returns `error.Timeout` before stream/TLS ownership moves, so the caller
still closes the resource.

| Gate | Result | Artifact |
| --- | --- | --- |
| Expired-budget adoption rejection | 32/32 | `http2-adopt-timeout.log` |
| Full HTTP/2 suite | 983/983 | `http2-full-after-adopt.log` |


## Nineteenth pass: remaining read, probe and H3 request timeout forms

The last deadline-only public entry points gained their `WithTimeout` pairs:

- HTTP/2 `readOwnedFrameWithTimeout`,
  `readOwnedFrameForDuplexWithTimeout`,
  `readOwnedClientDuplexFrameWithTimeout`,
  `readOwnedServerDuplexFrameWithTimeout` and
  `beginPingProbeWithTimeout`. Each rejects a non-positive budget before any
  socket read or PING write and otherwise converts once to the existing
  absolute-deadline path.
- HTTP/3 `startRequestOwnedWithTimeout`. A non-positive budget clears `owner`
  before returning Timeout, matching the deadline form's unowned preflight.

The invalid-budget test now asserts all four HTTP/2 read forms return Timeout
before transport I/O; the background PING probe test covers both the rejected
and accepted timeout forms; the H3 owned-head test covers the zero-budget
request form.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/2 read/probe timeout forms | 35/35 | `http2-probe-read-timeouts.log` |
| Full HTTP/2 suite | 983/983 | `http2-full-after-read-timeouts.log` |
| HTTP/3 owned request head timeout | 103/103 | `http3-owned-head-timeout.log` |

The remaining deadline-only names are intentional: H3 connect/request
primitives already take a relative `connect_timeout` through options,
WebSocket `ensureBuffered*` are internal prefetch steps behind typed receive
APIs, and WebTransport `pollWithDeadline` never blocks on transport I/O.
The thirty-eighth pass later added explicit `WithTimeout` forms to the H3
connect entry points for parity with the other connect APIs; the
option-based `connect_timeout` remains the default when no explicit budget is
supplied, and an explicit budget is still capped by it.


## Twentieth pass: HTTP/1 close timeout coverage

`http1.Client.closeWithTimeout` was added with the close-budget parity batch
but only the unified H3 timeout close had direct coverage. The cleartext path
now has both cases: an expired budget returns `Timeout`, retires the client and
lets the peer observe EOF; a positive budget closes the lease cleanly. P7 was
also marked resolved because the H3 facade accessors already expose one
application send size and keep the socket cap in sync. P2 is now the only open
review item and records the narrowed prefix-sender requirement.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/1 close timeout retirement | 17/17 | `http1-close-timeout.log` |


## Rejected: budget-aware server prefixes (third attempt)

A prefix sender was implemented and reverted. It planned the largest Handshake
prefix fitting the current anti-amplification allowance, advanced packet
numbers contiguously for the peer's expected-number check, gated client
Handshake acceptance on a complete-flight attempt, and reset the retry budget
when same-path probes grew the allowance. The 16-entry certificate and mTLS
regressions passed, but the 40-entry case timed out.

Instrumentation showed the allowance oscillating while the prefix stayed small:

```text
srv send rt=0 avail=7200 init=2400 pkts=4 crypto=4096/12754
obs bytes=1200 rt-reset
srv send rt=1 avail=652 init=2400 pkts=0 crypto=0/12754
obs bytes=1200 rt-reset
srv send rt=1 avail=7852 init=2400 pkts=5 crypto=5120/12754
obs bytes=1200 rt-reset
srv send rt=2 avail=7283 init=2400 pkts=4 crypto=4096/12754
```

Each attempt resends CRYPTO from offset zero for loss recovery, so duplicate
data consumes the allowance as fast as the client's probes grow it. A viable
prefix sender must know which Handshake CRYPTO was delivered (for example from
the client's ACK largest-acknowledged) and send only the unacknowledged
suffix; otherwise the prefix cannot grow. The working tree was restored to the
audited complete-flight sender, and the 40-entry regression passes again.


## Twenty-first pass: continuous Handshake CRYPTO ACKs

The client previously acknowledged only the first Handshake CRYPTO packet,
which unblocked servers that gate the rest of the flight but gave no delivery
signal for later packets. `receiveServerHandshakeCrypto` now acknowledges every
authenticated Handshake packet that contributes CRYPTO data, using a fresh
client Handshake packet number per ACK. CRYPTO-less ACK/PADDING packets still
do not consume ACK numbers, preserving the bounded behavior and the
"skips many CRYPTO-less Handshake packets" invariant.

This is the client-side prerequisite for ACK-aware server prefix growth: a
server can map acknowledged packet numbers to the CRYPTO ranges it delivered
instead of resending from offset zero.

| Gate | Result | Artifact |
| --- | --- | --- |
| Large-certificate and 40-entry probe flight | 35/35 | `quic-continuous-acks.log` |
| QUIC handshake, CRYPTO, PTO, certificate, prepared bundle | 66/66 | `quic-handshake-after-acks.log` |
| Full QUIC suite | 1106/1130, 23 skipped, 1 host-load UDP ECN flake | `quic-full-after-acks.log` |
| UDP ECN batch test in isolation | 32/32 | `quic-ecn-isolated.log` |

The ECN failure is the same rotating load-sensitive endpoint batching class
recorded for the fifteenth pass; it passes in isolation and does not touch the
handshake path.


## Twenty-second pass: ACK-aware server Handshake prefixes

The rejected third prefix attempt failed because it resent CRYPTO from offset
zero. The client-side continuous ACKs from the twenty-first pass now make an
ACK-aware sender possible:

- `InitialHandshakeFlight` plans the largest prefix of the **unacknowledged**
  CRYPTO suffix that fits the current anti-amplification allowance.
- Server Handshake packet numbers advance contiguously across attempts, so the
  client's expected-number check keeps matching.
- `observeReceived` decrypts client Handshake packets with the client keys,
  records ACK ranges, and maps packet numbers to CRYPTO ranges. The delivered
  prefix only advances when a range starts at the current prefix end, so a lost
  middle packet is retransmitted instead of skipped by a later ACK.
- A CRYPTO-bearing client Certificate/Finished or a validated
  `CONNECTION_CLOSE` is accepted as the handshake response; ACK-only packets no
  longer stop the sender. The close path rewinds the expected packet number so
  the receive loop opens the same datagram.
- Same-path observed bytes reset the retry budget; the hard deadline still
  bounds the handshake. The tracked flight is bounded to 64 packets, matching
  the existing `max_datagrams` limit.

| Gate | Result | Artifact |
| --- | --- | --- |
| 40-entry certificate, mTLS, close reservation, prepared verifier | 40/40 | `quic-ack-aware-prefix.log` |
| Deterministic ACK suffix-resume unit test | 36/36 | `quic-suffix-unit.log` |
| Missing-middle-range retransmission unit test | 1109/1132, 23 skipped | `quic-full-after-gap-test.log` |
| QUIC handshake, CRYPTO, PTO, certificate, prepared bundle | 66/66 | `quic-handshake-after-prefix.log` |
| Full QUIC suite | 1107/1130, 23 skipped, no failures | `quic-full-after-prefix.log` |
| Full HTTP/3 suite | 927/931, 4 skipped | `http3-after-ack-prefix.log` |
| Full WebTransport suite | 756/758, 2 skipped | `webtransport-after-ack-prefix.log` |
| Full HTTP suite | 305/305 | `http-after-ack-prefix.log` |
| Full WebSocket suite | 504/505, 1 host-sensitive skip | `ws-after-ack-prefix.log` |


## Twenty-third pass: parsed-URI pool timeout parity

`http2.client_pool` exposed `acquireUri{,WithTimeout,WithDeadline}` and
`acquireParsedUri{,WithDeadline}` but no relative-timeout form for an
already-parsed URI. `acquireParsedUriWithTimeout` completes the matrix; a
non-positive budget returns `Timeout` before dialing, matching the other pool
timeout forms. The focused test asserts the rejection and that no connection is
created.

| Gate | Result | Artifact |
| --- | --- | --- |
| Parsed-URI pool timeout rejection | 37/37 | `http2-pool-parsed-timeout.log` |


## Twenty-fourth pass: bounded concurrent trailer finish

The concurrent HTTP/2 and HTTP/3 `Stream` API exposed unbounded
`finishWithTrailers` but no deadline or relative-timeout form, so a handler
could not bound the final trailer submission. Both backends now provide
`finishWithTrailersWithDeadline` and `finishWithTrailersWithTimeout`; the
timeout form rejects a non-positive budget before queueing the command, and a
positive budget bounds the handler's wait for owner completion. The concurrent
informational tests cover the zero-budget rejection and a successful bounded
trailer finish on both protocols.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/2 concurrent bounded trailer finish | 34/34 | `http2-concurrent-trailer-timeout.log` |
| HTTP/3 concurrent bounded trailer finish | 65/65 | `http3-concurrent-trailer-timeout.log` |


## Twenty-fifth pass: concurrent reset and combined informational budgets

Two remaining concurrent response operations had no bounded form:

- `reset` on HTTP/2 and HTTP/3 now has `resetWithDeadline` and
  `resetWithTimeout`; a non-positive budget is rejected before queueing the
  cancel command.
- HTTP/3 `startResponseWithBodyAndInformational` now has deadline and timeout
  forms, so the combined informational + head + first-body fast path can be
  bounded like the other response-start variants.

The concurrent informational suites cover the zero-budget rejection for both
operations and a successful bounded combined response start.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/2 concurrent reset timeout | 34/34 | `http2-concurrent-reset-timeout.log` |
| HTTP/3 concurrent reset and informational timeout | 65/65 | `http3-concurrent-reset-timeout.log` |


## Twenty-sixth pass: concurrent timeout matrix completion

The concurrent response-start and DATA writers had absolute-deadline forms but
no relative-timeout counterparts, leaving a partial timeout surface next to the
new trailer/reset forms. HTTP/2 and HTTP/3 now expose:

- `startResponseWithTimeout`
- `startResponseWithBodyWithTimeout`
- `writeInformationalResponseWithTimeout`
- `writeDataWithTimeout`

Each rejects a non-positive budget before queueing the owner command and
otherwise converts once to the existing deadline path. The informational suites
assert the zero-budget rejection for all four on both protocols.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/2 concurrent timeout matrix | 34/34 | `http2-concurrent-timeout-matrix.log` |
| HTTP/3 concurrent timeout matrix | 65/65 | `http3-concurrent-timeout-matrix.log` |
| Full library and public-package compile | 9/9 steps | `test-compile-final.log` |
| Public package surface tests | 26/26 | `test-package-final.log` |
| QUIC prefix/close cleanup regression | 36/36 | `quic-cleanup.log` |

The ACK-aware flight also dropped an unused packet-number field and the
redundant `handshakeComplete()` getter after the accept gate moved to the
CRYPTO/close datagram flags; the focused regression confirms no behavior
change.


## Twenty-seventh pass: bounded push cancellation

`Connection.cancelPush` emitted RST_STREAM(CANCEL) with an unbounded write, so
a client canceling a reserved push during backpressure could block
indefinitely. It now has `cancelPushWithDeadline` and `cancelPushWithTimeout`;
the prepared-reset write helper accepts the deadline directly, preserving the
existing preparation/credit order and the promise ownership on failure. A
non-positive budget is rejected before touching the promise.

| Gate | Result | Artifact |
| --- | --- | --- |
| Bounded push cancellation | 34/34 | `http2-cancel-push-timeout.log` |


## Twenty-eighth pass: bounded complete-request submission

`Connection.sendCompleteRequest` exposed the head/body submission primitive
with no deadline or timeout form, unlike the surrounding request APIs. Add
`sendCompleteRequestWithDeadline` and `sendCompleteRequestWithTimeout`; both
validate the budget before touching the transport, and the timeout form rejects
a non-positive duration before validating request options. The invalid-budget
suite asserts the zero-budget path returns `Timeout` before any transport I/O.

| Gate | Result | Artifact |
| --- | --- | --- |
| Complete-request submission budget | 33/33 | `http2-send-request-timeout.log` |


## Twenty-ninth pass: retransmit test registration

The handshake retransmission tests lived behind `retransmit.zig`'s own
anonymous `test { _ = @import("retransmit_tests.zig"); }` block. Because
`retransmit.zig` is pulled in by production code rather than by a test-block
import, filtered `zig build test-quic -Dtest-filter=...` runs pruned the
file's named tests and tripped the focused-scope guard. The import now lives
in `handshake.zig`'s top-level test block, where the other handshake test
files are registered. The full QUIC count drops from 1132 to 1131 because the
removed anonymous aggregator block was itself one test entry; all 14 named
retransmission tests remain registered.

The full-suite run after the move reported one failure,
`QUIC UDP endpoint batch preserves independent ECN control messages`, a known
load-sensitive UDP batching flake; the isolated run passes 59/60 (1 skipped).

| Gate | Result | Artifact |
| --- | --- | --- |
| Filtered retransmission registration | 33/33 | `quic-retransmit-filtered.log` |
| Isolated ECN batching regression | 59/60 (1 skipped) | `quic-ecn-isolated.log` |


## Thirtieth pass: pool timeout with origin isolation

`Pool.acquireUriWithDeadlineAndOriginIsolation` was the only acquisition
variant without a timeout counterpart: callers that needed the internal
redirect origin-isolation hook had to build an awake-clock deadline
themselves, while every other acquisition form offered both deadline and
timeout. Add `acquireUriWithTimeoutAndOriginIsolation`, matching the existing
non-positive-budget rejection order: the timeout check runs before origin-key
parsing or any pool/transport work. The new focused test asserts both
`acquireUriWithTimeout` and the origin-isolation form return `Timeout` at a
zero budget without registering a waiter or opening a connection, and the
public package surface test pins the new declaration.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite | 305/305 | `http-full-pool-timeout.log` |
| Public package surface tests | 26/26 | `test-package-pool-timeout.log` |


## Thirty-first pass: WebSocket byte-stream timeout forms

`websocket.stream_connection.Connection` is the public RFC 6455 framing
adapter used by HTTP/2 extended CONNECT and HTTP/3 CONNECT byte streams. Its
receive and send operations exposed only absolute-deadline forms, forcing
callers that hold a relative budget to construct an awake-clock timestamp
themselves. Add `WithTimeout` counterparts for `receiveMessage`, `sendText`,
`sendBinary`, `sendPing`, `sendPong`, `sendFrame`, and `sendClose`; each
routes through the shared `deadline_policy.fromTimeout` helper, so a
non-positive duration returns `Timeout` before lock acquisition or transport
I/O, and the existing deadline/`DeadlineUnsupported` contracts are unchanged.
The new focused test asserts zero-budget rejection without touching the
transport, then exercises the bounded receive and send paths.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite | 504/505 (1 skipped) | `websocket-stream-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-stream-timeouts.log` |


## Thirty-second pass: incremental WebTransport timeout forms

`webtransport.runtime.incremental_stream` exposed `read`, `readId`, and
`stop` with absolute-deadline counterparts only, so callers holding a
relative budget had to construct an awake-clock timestamp themselves. Add
`readWithTimeout`, `readIdWithTimeout`, and `stopWithTimeout`; each converts
through `deadline_policy.fromTimeout`, rejecting a non-positive duration with
`Timeout` before any socket wait, registry lookup, or STOP_SENDING write.
The existing GRO incremental-read test now also asserts zero-budget rejection
for the read and stop timeout forms, and the public package surface test pins
all three declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite | 755/757 (2 skipped) | `webtransport-stream-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-webtransport-timeouts.log` |


## Thirty-third pass: handshake WebTransport stream timeout forms

The public `webtransport.runtime.handshake_stream` helpers exposed `send`,
`sendSlices`, `write`, `writeSlices`, `finish`, and `receive` with
absolute-deadline counterparts only. Add the six `WithTimeout` forms; each
converts through `deadline_policy.fromTimeout`, so a non-positive duration
returns `Timeout` before any packet, FIN, or receive work, and the committed
prefix/FIN retry contracts of the deadline forms are preserved. These are
conversion-only wrappers over the already-tested progress paths; the public
package surface test pins all six declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite | 755/757 (2 skipped) | `webtransport-handshake-stream-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-handshake-stream-timeouts.log` |


## Thirty-fourth pass: WebTransport reset timeout forms

The incremental stream surface re-exported `reset` and `resetReliably` with
absolute-deadline counterparts only. Add `resetWithTimeout` and
`resetReliablyWithTimeout` (plus the internal `resetWithCodeAndTimeout`);
each converts through `deadline_policy.fromTimeout`, so a non-positive
duration returns `Timeout` before registry lookup, association-prefix
binding, or any RESET_STREAM/RESET_STREAM_AT write. The GRO incremental-read
test now asserts zero-budget rejection for both reset forms, and the public
package surface test pins the new declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite | 755/757 (2 skipped) | `webtransport-reset-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-reset-timeouts.log` |


## Thirty-fifth pass: WebTransport batch write timeout

`webtransport.runtime.stream_batch.write` had only an absolute-deadline
bounded form, unlike the rest of the stream write surface. Add
`writeWithTimeout`; it mirrors `writeWithDeadline`'s order exactly: reject a
short `counts` buffer, clear the committed counts, then convert the relative
budget through `deadline_policy.fromTimeout`, so a non-positive duration
returns `Timeout` before staging or transport work and never reports stale
committed bytes. The wrong-clock batch test now also asserts the timeout
form clears counts and leaves the stream prefix and offsets untouched.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite | 755/757 (2 skipped) | `webtransport-batch-timeout.log` |
| Public package surface tests | 26/26 | `test-package-batch-timeout.log` |


## Thirty-sixth pass: WebTransport session-control timeout forms

`webtransport.runtime.session_control.Control` exposed `poll`,
`rejectPostTerminalData`, and `rejectInvalidCapsule` with absolute-deadline
counterparts only. Add `pollWithTimeout`, `rejectPostTerminalDataWithTimeout`,
and `rejectInvalidCapsuleWithTimeout`; each converts through
`deadline_policy.fromTimeout`, so a non-positive duration returns `Timeout`
before pending events are consumed, rejection state is recorded, or
RESET_STREAM/STOP_SENDING is written. The buffered-close credit test now
asserts zero-budget poll rejection, and the public package surface test pins
all three declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite | 755/757 (2 skipped) | `webtransport-session-control-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-session-control-timeouts.log` |


## Thirty-seventh pass: concurrent body deadline spelling

The HTTP/2 and HTTP/3 concurrent `Stream` types exposed
`startResponseWithBodyWithTimeout` next to
`startResponseWithBodyAndDeadline`, while every sibling bounded operation
uses the `WithDeadline`/`WithTimeout` pair. Add the canonical
`startResponseWithBodyWithDeadline` on both types and mark the `AndDeadline`
spelling as a compatibility alias that forwards to the same owner-command
submission. The informational-response tests now assert zero-budget
rejection through the new name.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/2 suite | 984/984 | `http2-concurrent-body-deadline.log` |
| Full HTTP/3 suite | 926/930 (4 skipped) | `http3-concurrent-body-deadline.log` |


## Thirty-eighth pass: H3 endpoint and Alt-Svc timeout forms

`HandshakeClient` exposed `connectAdoptingEndpoint`,
`connectOwningEndpoint`, `connectUriAltSvc`, and
`connectUriAltSvcWithEarlyRequest` with absolute-deadline counterparts only,
while every other connect entry point pairs `WithDeadline` with
`WithTimeout`. Add the four timeout forms; each rejects a non-positive
duration before touching the endpoint, resolver, or handshake, and delegates
to the deadline form so the existing `connect_timeout` cap still applies.

The shared-endpoint handshake-progress test also allowed only 3 or 4
completed requests, but both deadline-bound requests (timed and
resolution-timed) independently race their abandonment flags, so 5 is a
legitimate outcome; the range is now 3..5 with the reasoning recorded.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/3 suite | 927/931 (4 skipped) | `http3-connect-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-connect-timeouts.log` |


## Thirty-ninth pass: remaining H3 connect timeout forms

Two public connect entry points still lacked a relative-budget spelling:
`HandshakeClient.connectFromWithEarlyRequest` and
`http3.socks5_runtime.connectHost`. Add
`connectFromWithEarlyRequestWithTimeout` and `connectHostWithTimeout`; both
reject a non-positive duration before touching the endpoint, SOCKS
association, cache, or lease, then delegate to the deadline form so the
option-based `connect_timeout` cap still applies. A new SOCKS5 test asserts
the zero-budget rejection before UDP ASSOCIATE, and the public package
surface test pins both declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/3 suite | 927/931 (4 skipped) | `http3-more-connect-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-more-connect-timeouts.log` |


## Fortieth pass: WebSocket adapter bounded close

`websocket.stream_connection.Connection.close()` was terminal and unbounded:
it swallowed every Close-write failure and closed the transport regardless.
Add `closeWithDeadline`/`closeWithTimeout` with resumable semantics matching
the pool close contract: validate the awake-clock budget first, send the
Close frame under it, and only then mark the connection closed and close the
transport. A zero budget, an expired deadline, a missing deadline-capable
transport, or a failed Close write leaves the connection open so the caller
can retry with a larger budget or fall back to the unbounded `close()`. New
tests cover the rejected budget, the successful bounded Close, and the
`DeadlineUnsupported` transport path followed by an unbounded close.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite | 506/507 (1 skipped) | `websocket-bounded-close.log` |
| Public package surface tests | 26/26 | `test-package-bounded-close.log` |


## Forty-first pass: QUIC server visitor receive timeout

`quic.endpoint_server.Server` exposed `receiveVisitingWithDeadline` without a
relative-budget counterpart, unlike `receive`/`receiveWithTimeout` on the same
type. Add `receiveVisitingWithTimeout`; a non-positive duration returns
`Timeout` before any receive attempt, otherwise it converts once to the
existing absolute-deadline path. The visitor test now asserts the zero-budget
rejection before delivering the packet that the deadline form rejects from
the callback. The API map also records the two receive spellings:
`*WithTimeout` takes `std.Io.Duration`, while `*Timeout` takes
`std.Io.Timeout` (which can express `none` or an absolute deadline).

| Gate | Result | Artifact |
| --- | --- | --- |
| Full QUIC suite | 1108/1131 (23 skipped) | `quic-server-visiting-timeout.log` |
| Public package surface tests | 26/26 | `test-package-visiting-timeout.log` |


## Forty-second pass: QUIC connection timeout forms

Four `quic.one_rtt.Connection` operations exposed only absolute-deadline
forms: `trySendDatagram`, `trySendDatagramOnce`, `waitForPacingAvailability`,
and `flushPendingAck`. Add `trySendDatagramWithTimeout`,
`trySendDatagramOnceWithTimeout`, `waitForPacingAvailabilityWithTimeout`, and
`flushPendingAckWithTimeout`; each converts once through
`deadline_policy.fromTimeout`, so a non-positive duration returns `Timeout`
before DATAGRAM validation, pacing inspection, ACK flush, or socket
submission. The existing datagram, pacing, and delayed-ACK tests now assert
the zero-budget rejection before the successful deadline path.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full QUIC suite | 1108/1131 (23 skipped) | `quic-connection-timeout-forms.log` |
| Public package surface tests | 26/26 | `test-package-connection-timeouts.log` |


## Forty-third pass: HTTP/1 tunnel write timeout and timed-read harness

`http1.runtime.Tunnel` exposed `writeSlicesWithDeadline` without a
relative-budget counterpart. Add `writeSlicesWithTimeout`; it clears the
progress record, rejects a closed write half, then converts once through
`deadline_policy.fromTimeout`, so a non-positive duration returns `Timeout`
before any slice reaches the transport. The tunnel test asserts the
zero-budget rejection leaves `committed_bytes` and the transport untouched.

The full HTTP/1 suite also exposed a pre-existing crash in the aggregate
100-Continue partial-write test. That test replaces `Connection.io.userdata`
with a fake writer while copying the Threaded vtable, so the portable
deadline read's `std.Io.Select` called Threaded group functions with the
wrong userdata and segfaulted during task allocation. The fake vtable now
forwards `netRead`, `sleep`, `groupConcurrent`, `groupAwait`, and
`groupCancel` to the base io with the backend's own userdata; the test passes
and the full suite is green.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/1 suite | 474/474 | `http1-tunnel-timeout.log` |
| Public package surface tests | 26/26 | `test-package-tunnel-timeout.log` |


## Forty-fourth pass: Alt-Svc request timeout forms

`HandshakeClient.requestUriAltSvc` and `requestUriAltSvcHeader` issued a full
Alt-Svc request with no caller deadline, while the plain `requestUri` family
offers both bounded forms. Refactor both through a `Before` helper and add
`requestUriAltSvcWithDeadline`/`WithTimeout` plus the header counterparts. One
absolute budget spans target selection, the Alt-Svc connection, and the
request; the connect phase is still capped by `options.connect_timeout` and
cannot renew the budget. A non-positive timeout returns `Timeout` before
header parsing or routing. The Alt-Svc timeout test asserts zero-budget
rejection for the new request forms alongside the connect form.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/3 suite | 927/931 (4 skipped) | `http3-altsvc-request-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-altsvc-request-timeouts.log` |


## Forty-fifth pass: pool Alt-Svc redirect timeout

`HandshakeClientPool.requestUriAltSvcForRedirect` had a deadline form but no
relative-budget counterpart, unlike the neighbouring `requestUriAltSvc` pair.
Add `requestUriAltSvcForRedirectWithTimeout`; a non-positive duration returns
`Timeout` before acquisition or routing, otherwise it converts once to the
existing deadline path. The redirect-routing test now asserts the zero-budget
rejection without invoking the connector, then keeps the existing
cross-origin redirect assertion.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/3 suite | 927/931 (4 skipped) | `http3-pool-redirect-timeout.log` |
| Public package surface tests | 26/26 | `test-package-pool-redirect-timeout.log` |


## Forty-sixth pass: WebTransport server handshake receive timeouts

Two public WebTransport receive helpers exposed only absolute-deadline
forms: `receiveStatefulSessionRequest` and
`receiveProtectedDatagramFromEndpoint`. Add the relative-timeout
counterparts; both reject a non-positive duration before settings exchange,
request parsing, rejection policy, socket reads, or packet opening, then
delegate to the existing deadline path. A new test asserts the protected
datagram helper rejects a zero budget without advancing the expected packet
number, and the package surface pins both declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite | 756/758 (2 skipped) | `webtransport-handshake-receive-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-handshake-receive-timeouts.log` |


## Forty-seventh pass: WebSocket direct read buffering

`stream_connection.ensureBefore` read every transport chunk into a 16 KiB
stack buffer and then copied it into the frame buffer, costing one extra copy
per read. It now reads directly into the ArrayList's spare capacity after
reserving the chunk. The 16 KiB amortization is retained for small frame
headers, while each reservation is capped at 64 KiB so a peer that advertises
a large frame cannot force a whole-frame allocation before sending its
payload; the frame-size limit is enforced before the read. A new adapter test
round-trips a 40 KiB binary frame through multiple reads and the compaction
path.

The bounded parser fuzz corpus also replayed clean: `zig build fuzz-parsers`
passed 9/9 steps and 2/2 tests, covering the cross-protocol HTTP/1, HTTP/2,
HTTP/3, HPACK, QPACK, WebSocket, WebTransport, and MQTT seeds.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite | 507/508 (1 skipped) | `websocket-direct-read-buffer.log` |
| Parser fuzz corpus replay | 9/9 steps, 2/2 tests | `fuzz-parsers-replay.log` |
| Public package surface tests | 26/26 | `test-package-direct-read-buffer.log` |


## Forty-eighth pass: HTTP/2 owned stream accept timeout

`http2.runtime.acceptOwnedStreamWithDeadline` had no relative-budget
counterpart. Add `acceptOwnedStreamWithTimeout`; a non-positive duration
honors the transfer-on-entry contract by closing the accepted stream and
returning `Timeout` without invoking the handshake, otherwise it converts
once to the deadline path. A new listener-backed test asserts the peer
observes EOF, the handshake callback is never entered, and the public package
surface pins both spellings.

The bounded stateful fuzz corpus also replayed clean: `zig build fuzz-stateful`
passed 9/9 steps and 2/2 tests across HTTP/1 pipelines, HTTP/2 flow control
and HPACK, HTTP/3 control streams and QPACK, WebSocket fragmented assembly,
WebTransport session/stream lifecycles, and MQTT Session/QoS persistence.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/2 suite | 985/985 | `http2-owned-accept-timeout.log` |
| Public package surface tests | 26/26 | `test-package-owned-accept-timeout.log` |
| Stateful fuzz corpus replay | 9/9 steps, 2/2 tests | `fuzz-stateful-replay.log` |


## Forty-ninth pass: HTTP/3 live connection fuzz replay

`zig build fuzz-http3-connection` replayed its bounded corpus against
production authenticated QUIC/TLS HTTP/3 client and server sessions. The run
covers complete and streaming requests, request/response trailers, reversed
multiplexed responses, cancellation, HEAD body suppression, and terminal
two-phase GOAWAY, and finished 9/9 steps with 3/3 tests passing.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/3 live connection fuzz replay | 9/9 steps, 3/3 tests | `fuzz-http3-connection-replay.log` |


## Fiftieth pass: WebTransport endpoint fuzz replay

`zig build fuzz-webtransport-endpoint` replayed its bounded corpus against
two authenticated WebTransport sessions sharing one production UDP endpoint,
varying cross-session DATAGRAM, paired-DATAGRAM, bidirectional-stream, DRAIN
and CLOSE ordering while checking exact handle routing and payload isolation.
The run finished 9/9 steps with 3/3 tests passing.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebTransport endpoint fuzz replay | 9/9 steps, 3/3 tests | `fuzz-webtransport-endpoint-replay.log` |


## Fifty-first pass: HTTP/2 live connection fuzz replay

`zig build fuzz-http2-connection` replayed its bounded corpus through a
production h2c connection covering ordinary and streaming request/response
bodies, request trailers, reversed two-stream response batches, PING,
RST_STREAM cancellation, GOAWAY and fresh connection rotation. The run
finished 9/9 steps with 3/3 tests passing.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/2 live connection fuzz replay | 9/9 steps, 3/3 tests | `fuzz-http2-connection-replay.log` |


## Fifty-second pass: HTTP/1 live connection fuzz replay

`zig build fuzz-http1-connection` replayed its bounded corpus through a
production loopback TCP client and server, covering persistent reuse,
complete and streaming fixed/chunked bodies, trailers, HEAD suppression, and
request- or response-selected connection retirement. The run finished 9/9
steps with 3/3 tests passing.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/1 live connection fuzz replay | 9/9 steps, 3/3 tests | `fuzz-http1-connection-replay.log` |


## Fifty-third pass: HTTP/2 TLS connection fuzz replay

`zig build fuzz-http2-tls-connection` replayed its bounded corpus over
authenticated TLS 1.3 with mandatory `h2` ALPN, negotiated cipher metadata,
and input-selected bidirectional traffic-key updates between HTTP/2
operations. The run finished 9/9 steps with 3/3 tests passing.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/2 TLS connection fuzz replay | 9/9 steps, 3/3 tests | `fuzz-http2-tls-connection-replay.log` |


## Fifty-fourth pass: WebTransport H2 endpoint init timeout

The HTTP/2 WebTransport `EndpointClient` and `EndpointServer` constructors
from an already negotiated connection exposed `initWithDeadline` without a
relative-budget counterpart. Add `initWithTimeout`; a non-positive duration
honors the transfer-on-entry contract by closing the unpublished transport
without TLS shutdown output and returning `Timeout`, otherwise it converts
once through the connection's awake-clock io. Client- and server-side tests
assert the peer observes EOF, and the package surface pins both declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite | 758/760 (2 skipped) | `webtransport-h2-init-timeout.log` |
| Public package surface tests | 26/26 | `test-package-h2-init-timeout.log` |
| Full library and package compile | 9/9 steps | live `zig build test-compile` |


## Fifty-fifth pass: HTTP/1 TLS connection fuzz replay

`zig build fuzz-http1-tls-connection` replayed its bounded corpus over
authenticated TLS 1.3, verified `http/1.1` ALPN and negotiated cipher
metadata, and mutated bidirectional traffic-key updates across persistent and
rotated connections. The run finished 9/9 steps with 3/3 tests passing.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/1 TLS connection fuzz replay | 9/9 steps, 3/3 tests | `fuzz-http1-tls-connection-replay.log` |


## Fifty-sixth pass: CONNECT-UDP adapter timeout forms

The public `http1.runtime.ConnectUdpTunnel` adapter (RFC 9298 over the HTTP/1
Upgrade tunnel) exposed `writeSlicesWithDeadline` and `readWithDeadline`
without relative-budget counterparts. Add `writeSlicesWithTimeout` (delegating
to `Tunnel.writeSlicesWithTimeout`, which clears the committed-byte progress
before validation) and `readWithTimeout` (converting once through the inner
tunnel io). A non-positive duration returns `Timeout` before any transport
read or slice submission. A tunnel test asserts the cleared progress and the
zero-budget rejection, and the package surface pins both declarations.

A bounded coverage-guided parser run, `zig build fuzz-parsers --fuzz=2000`,
also exited successfully (`result=0` in the guard record); only the trailing
build lines were captured, so no per-test summary is claimed.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/1 suite | 475/475 | `http1-connect-udp-timeout.log` |
| Public package surface tests | 26/26 | `test-package-connect-udp-timeout.log` |
| Guided parser fuzz (2000 iterations) | exit 0 | `fuzz-parsers-guided.log` |


## Fifty-seventh pass: zero-copy single-frame message assembly

`MessageAssembler` duplicated every frame payload into its buffer, and the
byte-stream adapter then duplicated the assembled payload once more for
single-frame messages. Add `feedOwned`: when an owned frame completes the
message by itself (including a finishing continuation after an empty first
fragment), the assembler transfers the frame's payload allocation instead of
copying it and clears `frame.payload` so the caller's `Frame.deinit` is a
no-op. `stream_connection.receiveMessageBefore` now uses the owned path;
multi-frame assembly and the borrowed runtime frame path are unchanged.

The assembler's inline tests were also registered from the WebSocket test
root; previously a production import alone left them out of filtered builds
and tripped the focused-suite guard, the same pruning behavior fixed for the
QUIC retransmission tests. New tests cover the single-frame transfer and a
finishing-continuation transfer.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite | 509/510 (1 skipped) | `websocket-owned-message.log` |
| Public package surface tests | 26/26 | `test-package-owned-message.log` |


## Fifty-eighth pass: HTTP/2 timing-test hardening

A full-library run under a heavily loaded host surfaced two timing-sensitive
HTTP/2 tests that passed in isolation but failed in the full suite:
`bounded control reads keep one absolute deadline` relied on 30 ms server
sleeps inside a 70 ms client budget, and
`h2c server caller deadline spans request and bootstrap` used a 50 ms accept
budget with a 25 ms client delay. The control-read test is now deterministic:
the server sends both WINDOW_UPDATEs, signals an event, and waits for the
client to time out before sending GOAWAY, so no server sleep participates in
the assertion. The h2c test keeps the same remainder-carried-into-bootstrap
shape with 2 s accept, 300 ms consumed, and a 10 s phase timeout. Three
consecutive full HTTP/2 runs passed 985/985 under the same host load.

The same full-library run also exposed out-of-scope and environmental
failures, recorded here for a future cleanup: `internal.tcp_connect` and
`internal.socket_options` socket tests, two MQTT config-include tests, and an
`mqtt.broker.runtime_policy` SIGILL. The in-scope WebTransport failure in that
run (`stream send wait observes CLOSE in the retained HTTP3 cursor suffix`)
passed in isolation and in two subsequent full WebTransport runs
(758/760, 2 skipped), confirming a load-sensitive flake.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/2 suite (three consecutive runs) | 985/985 each | live runs |
| Full WebTransport suite (two runs after the flake) | 758/760 (2 skipped) each | live runs |
| Full-library loaded run | 7078 pass, 41 skip, 12 fail, 1 crash | `test-lib-load-run.log` |


## Fifty-ninth pass: host-portable shared socket tests

The loaded full-library run left three shared-infrastructure test failures
that also reproduced in filtered `test-lib` runs. They were test assumptions,
not production defects:

- The two `internal.tcp_connect` IPv4 source-bind tests require a
  `127.0.0.2` loopback alias that macOS does not configure. They now skip on
  `error.AddressUnavailable`, matching the existing QUIC migration-test
  convention.
- The `internal.socket_options` TCP_NODELAY test expected `getsockopt` to
  return exactly 1. A direct C probe on macOS 26.6 shows the kernel normalizes
  the enabled value to 4 (set 0 reads back 0), so the test now asserts only
  that the value is non-zero.

Filtered `test-lib` runs after the fixes: IPv4 source 254/255 (1 skipped),
resolved bound 222/223 (1 skipped), and no-delay 225/225. The remaining
full-library failures are the out-of-scope MQTT config-include tests and the
`mqtt.broker.runtime_policy` SIGILL already recorded in the fifty-eighth
pass.

| Gate | Result | Artifact |
| --- | --- | --- |
| Filtered `test-lib` IPv4 source bind | 254/255 (1 skipped) | live run |
| Filtered `test-lib` resolved bound | 222/223 (1 skipped) | live run |
| Filtered `test-lib` TCP no-delay | 225/225 | live run |


## Sixtieth pass: zero-allocation guarantee for owned assembly

The fifty-seventh pass added `MessageAssembler.feedOwned` to transfer a
complete frame's payload, but only pointer identity was asserted. A new test
runs the transfer against a `std.testing.FailingAllocator` whose first
allocation fails and requires the call to succeed with
`has_induced_failure == false`, proving the single-frame path performs no
allocator traffic at all. The transferred payload still points at the frame's
original allocation and the frame payload is cleared.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite | 510/511 (1 skipped) | `websocket-owned-no-alloc.log` |
| Public package surface tests | 26/26 | `test-package-owned-no-alloc.log` |


## Sixty-first pass: guided stateful fuzz

`zig build fuzz-stateful --fuzz=500` ran 500 coverage-guided mutations of the
stateful operation sequences (HTTP/1 pipelines, HTTP/2 flow control and HPACK,
HTTP/3 control streams and QPACK, WebSocket fragmented assembly, WebTransport
session/stream lifecycles, and MQTT Session/QoS persistence). The run finished
9/9 steps with 2/2 tests passing and no panic or leak report.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided stateful fuzz (500 iterations) | 9/9 steps, 2/2 tests | `fuzz-stateful-guided.log` |


## Sixty-second pass: full-library rerun after socket fixes

The full-library suite was rerun after the host-portable socket-test fixes.
The three fixed tests no longer appear; the run reported 7080 pass, 43 skip,
8 fail and 2 crash out of 7133, compared with 7078/41/12/1 before. The
remaining failures rotate with host load and are not deterministic:

- In-scope/adjacent flakes: QUIC UDP batch receive cancellation and the
  WebTransport retained-cursor CLOSE test both pass in their dedicated suites;
  `internal.tcp_connect` Happy Eyeballs hit a Zig `Threaded` `EISCONN`
  programmer-bug panic under load and passed in an isolated filtered run
  (223/223).
- Out of scope: two gRPC channel tests, one gRPC shared-cancellation test, one
  SOCKS5 UDP association test, two MQTT config-include tests, and the MQTT
  runtime-policy SIGILL.

Dedicated gates remain green: HTTP/2 985/985 three times, WebTransport
758/760 twice. The rotating failure set is host-load evidence, not a
regression in the reviewed protocols.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full-library rerun | 7080 pass, 43 skip, 8 fail, 2 crash | `test-lib-after-socket-fixes.log` |
| Isolated Happy Eyeballs test | 223/223 | live run |


## Sixty-third pass: two-slice writes for unmasked adapter frames

`websocket.stream_connection` always encoded the complete frame into its
write buffer, copying the payload even for unmasked server-role frames. The
public `Transport` now accepts optional `write_parts_fn` and
`write_parts_deadline_fn` callbacks. When the matching callback is present,
server-role frames are written as the encoded header plus the caller's
payload slice with no copy; bounded sends use the deadline callback only when
both parts callbacks exist, otherwise the buffered deadline path is retained.
Client-role frames still take the masked copy path because masking transforms
the payload. Both callbacks must write both ranges completely or return an
error.

Tests cover the unmasked parts path (header parse, payload pointer identity,
concatenated output), zero-budget rejection before the callback, the bounded
success path, and the client masking fallback. The package surface pins both
new fields, and the adapter document records the contract.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite | 512/513 (1 skipped) | `websocket-parts-write.log` |
| Public package surface tests | 26/26 | `test-package-parts-write.log` |


## Sixty-fourth pass: QUIC many-visitor receive timeout

`quic.endpoint_server.Server` exposed `receiveVisitingWithTimeout` but its
multi-datagram counterpart only had the `std.Io.Timeout` union and absolute
deadline forms. Add `receiveManyVisitingWithTimeout` taking a relative
`std.Io.Duration`; a non-positive duration returns `Timeout` before buffer
validation or any receive attempt, matching the deadline form's ordering.
The visitor test asserts the zero-budget rejection alongside the existing
single-visitor checks, and the package surface pins the declaration.

The first full QUIC run hit the known load-sensitive
`receive_cancel_tests` UDP-batch flake; it passed in isolation and the
recorded rerun passed 1108/1131 with 23 skipped.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full QUIC suite (recorded rerun) | 1108/1131 (23 skipped) | `quic-many-visiting-timeout.log` |
| Public package surface tests | 26/26 | `test-package-many-visiting-timeout.log` |


## Sixty-fifth pass: dispatcher relative-timeout receive forms

`quic.endpoint_dispatcher.Dispatcher` exposed the `std.Io.Timeout` union
forms and absolute deadlines but not the canonical relative-budget forms that
`endpoint_server.Server` now offers. Add `receiveWithTimeout`,
`receiveVisitingWithTimeout`, and `receiveManyVisitingWithTimeout` taking
`std.Io.Duration`; each rejects a non-positive budget before buffer
validation or any socket wait, then converts once to the existing deadline
path. The union `*Timeout` spellings remain for supervisor loops that need
`none` or an absolute deadline. The dispatcher test now asserts all three
zero-budget rejections, and the package surface pins the declarations.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full QUIC suite | 1108/1131 (23 skipped) | `quic-dispatcher-timeouts.log` |
| Public package surface tests | 26/26 | `test-package-dispatcher-timeouts.log` |


## Sixty-sixth pass: API-map accuracy after the review

The cross-protocol API map still described the pre-review QUIC
anti-amplification behavior ("the server still reserves the complete
flight"), which the twenty-second pass replaced with the ACK-aware largest
unacknowledged CRYPTO prefix. The row now states the prefix planner and ACK
range advancement, with client PTO probes on an independent timer. The
WebSocket byte-stream row also records the relative-timeout forms and the
two-slice write path added by the recent passes. No code changed; the map
now matches the implementation and the recorded evidence.

| Gate | Result | Artifact |
| --- | --- | --- |
| Documentation consistency | API map matches passes 22, 57, 60, 63 | `docs/protocol_api_map.md` |


## Sixty-seventh pass: CRYPTO buffer limit documentation and accessor pin

The API map described the QUIC CRYPTO reassembly limit as "grown on demand",
which could suggest the 256 KiB default rises automatically. The row now
states that storage grows with received data only up to `max_crypto_buffer`,
and a new paragraph documents `error.CryptoBufferTooLarge` for large
certificate chains plus the `nativeHandshake().max_crypto_buffer` override on
H3 clients. The existing flat-accessor test now also mutates and verifies
`max_crypto_buffer`, pinning the documented path.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite | 305/305 | `http-crypto-buffer-accessor.log` |
| Public package surface tests | 26/26 | `test-package-crypto-buffer-accessor.log` |


## Sixty-eighth pass: full-suite triage guidance

The API map's verification section now lists `test-lib` and records that its
single-binary run includes real-UDP and tight-timing tests that can rotate on
a heavily loaded host; protocol-scoped steps are the first triage choice. This
matches the observed full-library runs in passes 58 and 62, where the failing
set changed between runs while the dedicated suites stayed green.

| Gate | Result | Artifact |
| --- | --- | --- |
| Documentation consistency | triage guidance matches passes 58/62 | `docs/protocol_api_map.md` |


## Sixty-ninth pass: direct fixed-length HTTP/1 body reads

The non-buffered HTTP/1 message helper reserved the final owned body size and
then copied each 4 KiB transport read through a stack scratch before
appending. It now reads directly into the ArrayList's reserved spare capacity
and advances the length by the returned count, removing one copy per read for
fixed-length bodies. The one-byte head/chunk-discovery reads are unchanged
because they must not cross into a pipelined message.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/1 suite | 475/475 | `http1-direct-body-read.log` |
| Public package surface tests | 26/26 | `test-package-direct-body-read.log` |


## Seventieth pass: multipart initial-boundary underflow

A 10,000-iteration guided parser fuzz run found an integer underflow in both
multipart initial-boundary searches. When the delimiter appears at buffer
offset one, the CRLF-prefix check computed `position - 2` before verifying
that the position is at least two, panicking instead of rejecting the body.
Both `http.multipart.parser` and `http.multipart.stream_parser` now require
`position >= 2` before slicing the prefix; an offset-one occurrence is
treated as an invalid prefix and the search continues.

The regression test feeds `"X--<boundary>"` to both the non-streaming and
streaming parsers and requires `error.MissingInitialBoundary`; without the
guard it reproduced the fuzz panic.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite | 306/306 | `http-multipart-underflow.log` |
| Public package surface tests | 26/26 | `test-package-multipart-underflow.log` |
| Guided parser fuzz (crash record) | underflow found, input saved | `fuzz-parsers-underflow-crash.log` |


## Seventy-first pass: parser fuzz after the multipart fix

`zig build fuzz-parsers --fuzz=20000` replayed the corpus plus 20,000
coverage-guided mutations after the initial-boundary guard landed. The run
finished 9/9 steps with 2/2 tests passing and no further panic, confirming
the underflow fix and leaving the cross-protocol parser surface clean at this
iteration count.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided parser fuzz (20,000 iterations) | 9/9 steps, 2/2 tests | `fuzz-parsers-guided-20k.log` |


## Seventy-second pass: guided stateful fuzz after the multipart fix

`zig build fuzz-stateful --fuzz=2000` ran 2,000 coverage-guided mutations of
the stateful operation sequences after the multipart guard landed. The run
finished 9/9 steps with 2/2 tests passing and no panic, covering HTTP/1
pipelines, HTTP/2 flow control and HPACK, HTTP/3 control streams and QPACK,
WebSocket fragmented assembly, WebTransport session/stream lifecycles, and
MQTT Session/QoS persistence.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided stateful fuzz (2,000 iterations) | 9/9 steps, 2/2 tests | `fuzz-stateful-guided-2k.log` |


## Seventy-third pass: guided HTTP/1 connection fuzz

`zig build fuzz-http1-connection --fuzz=300` ran 300 coverage-guided
mutations through a production loopback TCP client and server, covering
persistent reuse, complete and streaming fixed/chunked bodies, trailers, HEAD
suppression, and request/response-selected retirement. The run finished 9/9
steps with 3/3 tests passing and no panic.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided HTTP/1 connection fuzz (300 iterations) | 9/9 steps, 3/3 tests | `fuzz-http1-connection-guided.log` |


## Seventy-fourth pass: guided HTTP/2 connection fuzz

`zig build fuzz-http2-connection --fuzz=200` ran 200 coverage-guided
mutations through a production h2c connection, covering ordinary and
streaming bodies, trailers, reversed response batches, PING, RST_STREAM,
GOAWAY, and connection rotation. The run finished 9/9 steps with 3/3 tests
passing and no panic.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided HTTP/2 connection fuzz (200 iterations) | 9/9 steps, 3/3 tests | `fuzz-http2-connection-guided.log` |


## Seventy-fifth pass: guided HTTP/3 connection fuzz

`zig build fuzz-http3-connection --fuzz=100` ran 100 coverage-guided
mutations through authenticated QUIC/TLS HTTP/3 client and server sessions,
covering complete and streaming requests, trailers, reversed multiplexed
responses, cancellation, HEAD suppression, and two-phase GOAWAY. The run
finished 9/9 steps with 3/3 tests passing and no panic.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided HTTP/3 connection fuzz (100 iterations) | 9/9 steps, 3/3 tests | `fuzz-http3-connection-guided.log` |


## Seventy-sixth pass: guided WebTransport endpoint fuzz

`zig build fuzz-webtransport-endpoint --fuzz=50` ran 50 coverage-guided
mutations across two authenticated WebTransport sessions sharing one
production UDP endpoint, varying cross-session DATAGRAM, paired-DATAGRAM,
bidirectional-stream, DRAIN and CLOSE ordering while checking exact handle
routing and payload isolation. The run finished 9/9 steps with 3/3 tests
passing and no panic.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided WebTransport endpoint fuzz (50 iterations) | 9/9 steps, 3/3 tests | `fuzz-webtransport-endpoint-guided.log` |


## Seventy-seventh pass: guided HTTP/2 TLS connection fuzz

`zig build fuzz-http2-tls-connection --fuzz=100` ran 100 coverage-guided
mutations over authenticated TLS 1.3 with mandatory `h2` ALPN, verified
cipher metadata, and bidirectional traffic-key updates between HTTP/2
operations. The run finished 9/9 steps with 3/3 tests passing and no panic.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided HTTP/2 TLS connection fuzz (100 iterations) | 9/9 steps, 3/3 tests | `fuzz-http2-tls-connection-guided.log` |


## Seventy-eighth pass: guided HTTP/1 TLS connection fuzz

`zig build fuzz-http1-tls-connection --fuzz=100` ran 100 coverage-guided
mutations over authenticated TLS 1.3 with `http/1.1` ALPN, verified cipher
metadata, and bidirectional traffic-key updates across persistent and rotated
connections. The run finished 9/9 steps with 3/3 tests passing and no panic.

With this run the guided fuzz matrix is complete: parser, stateful, HTTP/1,
HTTP/1+TLS, HTTP/2, HTTP/2+TLS, HTTP/3, and the WebTransport shared endpoint
all pass after the multipart initial-boundary fix.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided HTTP/1 TLS connection fuzz (100 iterations) | 9/9 steps, 3/3 tests | `fuzz-http1-tls-connection-guided.log` |


## Seventy-ninth pass: deep parser fuzz

`zig build fuzz-parsers --fuzz=50000` ran 50,000 coverage-guided mutations
after the multipart fix. The run finished 9/9 steps with 2/2 tests passing
and no panic, extending the parser corpus coverage well beyond the 10,000
iterations that found the initial-boundary underflow.

| Gate | Result | Artifact |
| --- | --- | --- |
| Guided parser fuzz (50,000 iterations) | 9/9 steps, 2/2 tests | `fuzz-parsers-guided-50k.log` |


## Eightieth pass: full protocol gate matrix

All protocol-scoped suites and the public package surface were rerun
sequentially after the review, the zero-copy changes, and the multipart fix.
Every step passed:

| Gate | Result |
| --- | --- |
| HTTP | 306/306 |
| HTTP/1 | 475/475 |
| HTTP/2 | 985/985 |
| HTTP/3 | 927/931 (4 skipped) |
| QUIC | 1108/1131 (23 skipped) |
| WebSocket | 512/513 (1 skipped) |
| WebTransport | 758/760 (2 skipped) |
| Public package surface | 26/26 |

Artifact: `gate-matrix-final.log`.


## Eighty-first pass: coverage inventory reflects the fuzz matrix

`docs/coverage.md` now records the latest guided replay counts (parser
50,000, stateful 2,000, HTTP/1 300, HTTP/1+TLS 100, HTTP/2 200, HTTP/2+TLS
100, HTTP/3 100, WebTransport endpoint 50) and points at the evidence ledger,
so readers can see both the target inventory and the current verification
state in one place.

| Gate | Result | Artifact |
| --- | --- | --- |
| Documentation consistency | counts match passes 70-79 | `docs/coverage.md` |


## Eighty-second pass: zero-budget H3 close contract

The unified `Connection.closeWithTimeout` documents that an expired budget
retires the transport without close-notify output, but only positive budgets
were covered. The direct-H3 close test now has a `zero_timeout` mode: the
client asserts `error.Timeout` from `closeWithTimeout(.zero)`, and the peer
must observe no terminal frame (its bounded receive times out) instead of a
CONNECTION_CLOSE. The existing `close`, `closeWithDeadline`, and positive
`closeWithTimeout` modes still require the peer to see `ConnectionClosed`.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite | 307/307 | `http-h3-zero-close.log` |
| Public package surface tests | 26/26 | `test-package-h3-zero-close.log` |


## Eighty-third pass: evidence hash audit observation

`zig build verify-evidence` completed successfully in report-only mode:
290 evidence files, 10,832 recorded source hashes, 6,518 matched, 4,314
stale, 0 unresolved/invalid/unreadable. The stale entries are pre-existing
drift in older evidence sets (the sampled output is entirely
`grpc_ordinary_health_gate/2026-11-02-*`), not protocol-review artifacts:
the logs added by this review record command output rather than source
hashes. Rewriting thousands of historical hashes would discard provenance
and is outside this review's scope; the observation is recorded so a future
strict-mode cleanup can start from a measured baseline.

| Gate | Result | Artifact |
| --- | --- | --- |
| Evidence hash audit (report-only) | 6,518 matched / 4,314 stale / 0 invalid | live `zig build verify-evidence` |


## Eighty-fourth pass: deadline-bounded ACK deferral and the retained-cursor flake

The `WebTransport stream send wait observes CLOSE in the retained HTTP3 cursor
suffix` test failed intermittently in ReleaseSafe before its send wait ran.
Stage instrumentation showed two legitimate receive-batch shapes after the
DATAGRAM was queued: `next_index=1 count=2` when the CLOSE capsule shared the
raw batch, and `next_index=1 count=1` when the deadline-bounded cursor took the
single-datagram timer-blocked read and left the CLOSE in the socket. The old
`next_index < count` assertion treated the second shape as a failure even
though the send wait observed the CLOSE and returned `InvalidSessionState` in
both shapes.

The test now asserts the observable contract in either interleaving and is
named for it. The receive audit also closed a real deadline-bound gap: every
HTTP/3 ACK emission point on a bounded receive (packet visitor, single-packet
visitor, GRO batch, and the pending-ACK retry) now uses the try-send QUIC
counterparts, so pacing, congestion, or flow-control backpressure defers the
ACK instead of blocking the receive past its deadline. Unbounded `visit`
paths keep the blocking ACK behavior.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebTransport (ReleaseSafe) | 758/760 (2 skipped) | `webtransport-pacing-close-flake-rs.log` |
| WebTransport (Debug) | 758/760 (2 skipped) | `webtransport-pacing-close-flake-debug.log` |
| HTTP/3 (ReleaseSafe) | 927/931 (4 skipped) | `http3-ack-defer-rs.log` |
| QUIC (ReleaseSafe) | 1108/1131 (23 skipped) | `quic-ack-defer-rs.log` |
| Targeted send-wait test | 10/10 repeated runs, both batch shapes observed | live runs |


## Eighty-fifth pass: WebSocket text scatter/gather parity

The arbitrary-slice single-frame send API existed only for binary messages
(`sendBinarySlices*`), so text callers holding borrowed slices had to join the
payload or emit WebSocket continuation frames. TCP, RFC 8441 (HTTP/2), and
RFC 9220 (HTTP/3) connections now expose `sendTextSlices`,
`sendTextSlicesWithTimeout`, and `sendTextSlicesWithDeadline` alongside the
opcode-generic `sendMessageSlices*` forms and two-slice `sendTextParts`
wrappers.

`validateOutgoingMessageParts` is now opcode-aware and validates text slices as
one logical UTF-8 message, so a code point may span a slice boundary and
invalid UTF-8 is rejected before any frame byte is written. Partial-write
resumption also matches the pending opcode, so a binary message cannot be
resumed as text with the same descriptor array.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebSocket (Debug) | 513/514 (1 skipped) | `websocket-text-slices-debug.log` |
| WebSocket (ReleaseSafe) | 513/514 (1 skipped) | `websocket-text-slices-rs.log` |
| New text-slices round-trips | TCP, RFC 8441, and RFC 9220 masked/unmasked single frames | live run |


## Eighty-sixth pass: WebTransport control-progress timeout pairing

`receiveControlProgressWithDeadline` and `finishPolledSessionEventWithDeadline`
were the only public WebTransport session operations without a relative-timeout
counterpart on either the client or the accepted server session, breaking the
cross-protocol `WithTimeout`/`WithDeadline` pairing recorded in the API map.
Both sessions now expose `receiveControlProgressWithTimeout` and
`finishPolledSessionEventWithTimeout`. A non-positive budget returns `Timeout`
before any socket read, terminal-data rejection, or close-notify side effect.

The new zero-budget test drives both roles and asserts that the rejected budget
leaves `local_close_sent` and `pending_closed` untouched.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebTransport (Debug) | 759/761 (2 skipped) | `webtransport-control-timeout-debug.log` |
| WebTransport (ReleaseSafe) | 759/761 (2 skipped) | `webtransport-control-timeout-rs.log` |


## Eighty-seventh pass: application usage guide and unified client example

Application-facing documentation previously started from version-specific
runtimes, while the recommended entry point for real use is the unified
`netz.http.Client`/`Pool` facade. `docs/usage.md` now maps common tasks to the
recommended HTTP, WebSocket, WebTransport and QUIC APIs, records the
`WithTimeout`/`WithDeadline`, close and error conventions, and points at a
runnable example for each path.

`examples/http/unified_client.zig` (new `run-http-unified-client` step) runs a
local HTTP/1 server, performs one one-shot request with a relative deadline,
then two pooled requests that reuse the negotiated connection. The README,
documentation map and example index now lead with this entry point, and
`docs/architecture.md` records the stream-adapter slice and HTTP/2
WebTransport staging limits discovered during the audit.

| Gate | Result | Artifact |
| --- | --- | --- |
| Example compile matrix | 76/76 steps | live `zig build examples` |
| Unified client example | one-shot + two pooled HTTP/1 requests, all 200 | live `zig build run-http-unified-client` |


## Eighty-eighth pass: HTTP example catalog toward hyper/reqwest/curl

The HTTP example surface only covered transport smoke tests and low-level
duplex/chunked paths. Five application-shaped examples now cover the common
reference-project recipes, each self-contained against a loopback HTTP/1
server:

- `run-http-client-forms`: `netz.http.form` query encoding, URL-encoded POST,
  and HEAD header inspection.
- `run-http-client-json`: typed JSON request and response bodies.
- `run-http-download`: chunked server response streamed through
  `RequestHandle.readResponse` into a file.
- `run-http-upload-multipart`: slice and reader parts written with
  `multipart.write`, generated Content-Type, and server-side
  `multipart.parse`.
- `run-http-cookie-session`: `CookieSession` stores a `Set-Cookie` and the next
  pooled request carries it automatically.
- `run-http-redirects`: relative 302 resolution, one-deadline chain following,
  and final URI/hop reporting.

The catalog exposed one duplex contract worth documenting: a `RequestHandle`
must finish its request body (`finishBody()`) before `readResponse()`;
otherwise the runtime returns `error.InvalidWriterState`. `docs/usage.md` now
records it.

| Gate | Result | Artifact |
| --- | --- | --- |
| Example compile matrix | 81/81 steps | live `zig build examples` |
| forms | GET 200, POST 200, HEAD 200 with 32-byte Content-Length | live run |
| JSON | `hello netz`, doubled=42 | live run |
| download | 8192 bytes streamed, status 200 | live run |
| multipart | 3 parts parsed with filename and reader body | live run |
| cookie session | `/me` observed `session=abc123` without an explicit header | live run |
| redirects | 1 hop, final URI `/new`, status 200 | live run |


## Eighty-ninth pass: verified HTTPS client example

The HTTP example catalog had no TLS path, leaving the most common production
configuration (server authentication) without a runnable reference. The new
`run-http-https-client` example starts the HTTP/1.1 TLS listener with the test
ECDSA P-256 identity and connects through the unified client with an explicit
`server_verifier` pin, mirroring `curl --cacert` / a pinned-key client. It
documents that removing the verifier falls back to the platform roots, which do
not trust the test certificate.

| Gate | Result | Artifact |
| --- | --- | --- |
| Example compile matrix | `run-http-https-client` builds and runs | live `zig build run-http-https-client` |
| HTTPS round-trip | `HTTPS http1 200: hello over verified TLS` | live run |


## Ninetieth pass: CONNECT proxy example and latent server-init fixes

Adding the `run-http-proxy-client` example (`curl -x` shape: local CONNECT
proxy, local TLS origin, unified client with an HTTP proxy URI and a pinned
origin key) exposed that both proxy server `init` functions had never been
compiled: `const listener` was passed to the mutating `deinit` in `errdefer`,
and `serve`/`Job.run` discarded `fetchAdd`/`fetchSub` results. The HTTP CONNECT
and SOCKS5 servers now compile and run through their public API.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP CONNECT proxy example | `proxied HTTPS http1 200: hello through the CONNECT proxy` | live `zig build run-http-proxy-client` |
| Proxy server init/serve tests | 19/19 | live `zig build test-proxy -Dtest-filter='proxy server init and deinit'` |


## Ninety-first pass: HTTP/2 TLS and prefer_http3 client recipes

The HTTP example catalog now covers the remaining protocol-selection shapes:

- `run-http-h2-tls`: the HTTP/2 TLS listener requires `h2` ALPN; the unified
  client uses `.http2_only` with a pinned server key and reports
  `H2 TLS http2 200: hello over HTTP/2 TLS`.
- `run-http-h3-prefer`: a local QUIC/TLS origin with the test identity; the
  unified client uses `.prefer_http3`, pins the origin key through
  `http3.handshake.handshake.server_auth`, and reports
  `prefer_http3 http3 200: hello from prefer_http3`. No TCP listener exists,
  so a failed H3 probe has no fallback.

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/2 TLS | `H2 TLS http2 200: hello over HTTP/2 TLS` | live `zig build run-http-h2-tls` |
| prefer_http3 | `prefer_http3 http3 200: hello from prefer_http3` | live `zig build run-http-h3-prefer` |


## Ninety-second pass: routed server and streaming upload recipes

Two more application shapes complete the HTTP catalog:

- `run-http-server-routes`: one persistent HTTP/1.1 connection serves `/`,
  `/health`, `/hello?name=`, `POST /echo`, a 404 path, and a `/quit` route
  that finishes its response before closing the server loop.
- `run-http-upload-reader`: the unified client sends a 45,056-byte body from a
  `std.Io.Reader` source with an explicit length (fixed framing), and the
  server reports the exact received size.

| Gate | Result | Artifact |
| --- | --- | --- |
| Routed server | `/` 200 home, `/health` 200 ok, `/hello?name=netz` 200, `/echo` 200, `/missing` 404, `/quit` 200 bye | live `zig build run-http-server-routes` |
| Reader upload | `uploaded 45056 bytes -> 200: received 45056 bytes` | live `zig build run-http-upload-reader` |


## Ninety-third pass: WSS echo with a pinned server key

The WebSocket examples only covered cleartext WS. `run-websocket-wss-echo`
starts `websocket.runtime.TlsServer` with the test ECDSA P-256 identity and
connects through `connectUri` with `vail_tls.server_verifier` pinned to that
public key, mirroring a browser `wss://` client with an explicit trust
override. The exchange sends text, receives the echo, and completes the Close
handshake.

| Gate | Result | Artifact |
| --- | --- | --- |
| WSS echo | `WSS echo: hello over WSS` | live `zig build run-websocket-wss-echo` |


## Ninety-fourth pass: WebTransport DATAGRAM echo

The WebTransport example only covered streams. `run-webtransport-datagram-echo`
now exercises both DATAGRAM receive forms on a real QUIC/TLS session: one
owned `receiveDatagramWithTimeout` and one `receiveDatagramIntoWithTimeout`
into caller storage, with the server echoing each unreliable payload.

| Gate | Result | Artifact |
| --- | --- | --- |
| DATAGRAM owned | `DATAGRAM echo (owned): hello datagram` | live `zig build run-webtransport-datagram-echo` |
| DATAGRAM into | `DATAGRAM echo (into): caller buffer` | live run |


## Ninety-fifth pass: H3 trust parity with the TCP client

The unified `netz.http.Client` verified H1/H2 servers with the platform roots
but silently skipped H3 server authentication when the caller configured no
explicit trust material: `quic.handshake.ClientOptions.server_auth` stayed
null while the TCP TLS side built a platform verifier. `Owner.connect` now
installs a platform-root verifier for the H3 route when no verifier, native
store, environment, non-system root source, or CA bundle is configured; the
temporary store lives only for the synchronous handshake.

The low-level QUIC/WebTransport contract is unchanged and now documented
explicitly: those callers must set `server_auth`, `system_store`, or
`system_environ`. `docs/protocol_api_map.md` gains a TLS server-authentication
table covering all four transports. The H3 and WebTransport examples now use
the test identity plus a pinned key so they exercise real verification.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 307/307 | live `zig build test-http` |
| H3 handshake example | 200 with pinned verification | live run |
| WebTransport stream example | bidi=4, uni=14, server_uni=15 | live run |
| WebTransport DATAGRAM example | owned + caller-buffer echoes | live run |
| prefer_http3 example | `prefer_http3 http3 200` | live run |


## Ninety-sixth pass: WebTransport URI trust parity

`webtransport.runtime.EndpointClient` URI connects inherited the low-level
QUIC default and skipped server authentication when no trust material was
configured, while the HTTP and WebSocket URI clients verify with the platform
roots. The URI connect path now installs a platform-root verifier when
`server_auth`, `system_store`, `system_environ`, and a non-system
`root_source` are all absent; the temporary store lives only for the
synchronous handshake. Lower-level WebTransport session and address helpers
keep the explicit configuration contract documented in the API map.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebTransport (Debug) | 759/761 (2 skipped) | live `zig build test-webtransport` |


## Ninety-seventh pass: managed serve loop example

`Server.serveUntil` is the production accept loop (bounded connections and
requests, error policies, shutdown event), but no example exercised it. The
new `run-http-server-serve-until` example routes `/hello` and `/status`
through the handler callback, serves two pooled requests, then sets the
shutdown event and waits for the loop to finish. The handler returns
`ResponseOptions` with static bodies because the loop writes the response
after the callback returns.

| Gate | Result | Artifact |
| --- | --- | --- |
| Managed serve loop | `/hello` 200, `/status` 200, clean stop after 2 requests | live `zig build run-http-server-serve-until` |


## Ninety-eighth pass: large streamed response and the body cap

`http1_limits.max_body_bytes` bounds the received body for buffered responses
and for `RequestHandle` streaming alike: a 20 MiB streamed response with the
default limits failed with `BodyTooLarge` from `body_reader.addBodyBytes`.
The new `run-http-large-body-stream` example raises the cap to 24 MiB, streams
20 MiB through a SHA-256 sink, and reports the digest without retaining the
complete response. `docs/usage.md` now states that the cap covers both paths
and names the per-protocol override.

| Gate | Result | Artifact |
| --- | --- | --- |
| Large streamed response | `streamed 20971520 bytes (cap raised to 24 MiB) sha256=5141c925...` | live `zig build run-http-large-body-stream` |


## Ninety-ninth pass: pooled H3 and WebSocket-over-H3 trust parity

The direct H3 route verified peers with platform roots, but the pool's Alt-Svc
H3 backend and WebSocket-over-H3 URI connects still used the low-level QUIC
default, which disables certificate verification when no trust material is
set. `quic.client_trust` now maps the unified TCP policy onto QUIC handshakes:
explicit H3 trust wins, otherwise the handshake inherits `client.tls`
(`server_verifier`, client identity, native store, environment, root source),
then loads one platform store. The pool keeps that store for its lifetime;
WebSocket and WebTransport URI connects keep it for the synchronous handshake.
A TCP `tls.ca_bundle` has no QUIC representation, so pooled Alt-Svc H3 rejects
it with `UnsupportedH3TrustConfiguration`, `http3_only` rejects it at init, and
`prefer_http3` keeps the request on TCP.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 307/307 | live `zig build test-http` |
| QUIC trust unit tests | 38/38 matched | live `zig build test-quic -Dtest-filter=trust` |
| WebSocket H3 URI tests | 81/81 matched | live `zig build test-websocket -Dtest-filter='HTTP3 URI'` |
| WebSocket directional H3 URI | 77/77 matched | live `zig build test-websocket -Dtest-filter='directional takeover HTTP3 URI'` |
| WebTransport (Debug, filtered) | 93/93 matched | live `zig build test-webtransport -Dtest-filter='flow negotiation requires intent'` |


## Hundredth pass: URI facade connection IDs and pooled H3 defaults

`Pool.Options.http3 = .{}` now enables the Alt-Svc backend: the handshake
options default to empty IDs, which the pool connector generates per
connection. WebSocket-over-H3 and WebTransport URI connects generate empty
client IDs themselves, so `UriConnectOptions.h3` and
`EndpointClient.Options.h3` can be omitted. Explicit IDs still control
reproducibility and resumption continuity. `Pool.Options.http3` also exposes
the same `nativeHandshake()`/`sessionOptions()` flat accessors as
`Http3ConnectOptions`.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 307/307 | live `zig build test-http` |
| WebSocket H3 URI tests (empty IDs) | 81/81 matched | live `zig build test-websocket -Dtest-filter='HTTP3 URI'` |
| WebTransport (Debug, filtered) | 93/93 matched | live `zig build test-webtransport -Dtest-filter='flow negotiation requires intent'` |


## Hundred-and-first pass: pooled Alt-Svc H3 example

The new `run-http-pool-alt-svc-h3` example starts an H2/TLS origin that
advertises `alt-svc: h3=":port"` and an H3 server on that port. The pool uses
`.http3 = .{}` (default limits, generated connection IDs, trust inherited from
`client.tls`) and upgrades the second request to H3. `run-http-h3-prefer` now
shows the same inheritance directly: it sets only `.tls.server_verifier` and
lets the H3 route reuse that pin.

| Gate | Result | Artifact |
| --- | --- | --- |
| Pool Alt-Svc H3 | `first http2 200: tcp discovery`, `second http3 200: hello over Alt-Svc HTTP/3` | live `zig build run-http-pool-alt-svc-h3` |
| prefer_http3 example | `prefer_http3 http3 200: hello from prefer_http3` | live `zig build run-http-h3-prefer` |


## Hundred-and-second pass: direct HTTP/3 over SOCKS5 UDP ASSOCIATE

The unified `netz.http.Client` skipped H3 whenever `socks5_proxy` was set; only
the pool and the WebSocket/WebTransport facades could route QUIC through a
SOCKS5 proxy. `prefer_http3` and `http3_only` now use `socks5_runtime.connectHost`
with proxy-side domain resolution and TLS identity bound to the URI origin.
A cleartext HTTP/1.1 CONNECT proxy still makes H3 ineligible and is rejected by
`http3_only`. SOCKS5 replies that reject or cannot describe the UDP relay
(`ProxyCommandUnsupported`, `ProxyConnectionNotAllowed`,
`ProxyInvalidRelayAddress`, `ProxyProtocolViolation`, and related address-type
errors) advance protocol selection, so `prefer_http3` falls back to TCP through
the same proxy instead of failing the request.

| Gate | Result | Artifact |
| --- | --- | --- |
| Direct H3 through SOCKS5 | 200 over `http3`, body `socks-h3` | live `zig build test-http -Dtest-filter='SOCKS5 UDP ASSOCIATE'` |
| UDP-denied proxy fallback | 200 over `http2`, body `tcp-fallback` | live `zig build test-http -Dtest-filter='SOCKS5 denies UDP'` |
| Full HTTP suite (Debug) | 309/309 | live `zig build test-http` |


## Hundred-and-third pass: pooled Alt-Svc H3 through SOCKS5

The pool's shared SOCKS5 endpoint (`ensureSocks5SharedEndpoint` with proxy-side
domain routing) had no end-to-end test against a real proxy. A new regression
starts an H2/TLS origin advertising `alt-svc`, an H3 origin, and a SOCKS5
server; the pool uses `client.socks5_proxy` plus `.http3 = .{}`. The first
request is H2 through CONNECT, the second is H3 through UDP ASSOCIATE. Proxy
replies that reject or cannot describe the UDP relay advance protocol
selection, so `prefer_http3` falls back to TCP through the same proxy.

| Gate | Result | Artifact |
| --- | --- | --- |
| Pool Alt-Svc H3 via SOCKS5 | h2 discovery then h3 `h3-through-socks5` | live `zig build test-http -Dtest-filter='Alt-Svc H3 through SOCKS5'` |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http` |


## Hundred-and-fourth pass: WebSocket stream-adapter slice sends

The caller-supplied byte-stream adapter had only single-buffer and optional
two-slice writes, so multi-slice payloads required staging or a contiguous
copy. `Transport` now accepts `write_slices_fn` and
`write_slices_deadline_fn` as `(context, header, slices)` callbacks, and
`Connection` exposes `sendTextSlices`, `sendBinarySlices`, `sendFrameSlices`
plus their timeout/deadline forms. Text validation (`utf8ValidateSlices`)
spans slice boundaries. Server-role frames use the slice callback when present
and otherwise write the header plus each non-empty slice under the same write
lock; client-role frames mask into the staging buffer. Control frames remain on
their contiguous APIs.

| Gate | Result | Artifact |
| --- | --- | --- |
| Stream adapter tests | 26/26 | live `zig build test-websocket -Dtest-filter='stream adapter'` |


## Hundred-and-fifth pass: WebTransport over HTTP/2 slice sends

The HTTP/3 WebTransport session exposed `sendStreamSlices*`, but the HTTP/2
session and its endpoint facades only accepted contiguous stream payloads.
`Session` now has `sendStreamSlicesWithDeadline`/`WithTimeout`, backed by
`State.prepareStreamLength`/`commitStreamLength` and
`Capsule.writeStreamHeaderInto`; `EndpointClient` and `EndpointServer` forward
the same shape through a staged command buffer. The H2 session itself writes
the encoded capsule header and borrowed payload slices directly, so the slice
path no longer copies the payload; `Pending` is a union of contiguous control
writes and zero-copy stream writes with resumable header/payload progress. The
virtual-stream FIN travels in the capsule type, not as HTTP/2 END_STREAM; the
slice path stages with `pending.fin = false` so the session stream stays open
for later capsules and datagrams.

| Gate | Result | Artifact |
| --- | --- | --- |
| H2 WebTransport tests | 205/205 | live `zig build test-webtransport -Dtest-filter='HTTP2'` |
| H2 zero-copy slice staging | 106/106 | live `zig build test-webtransport -Dtest-filter='HTTP2 slice'` |
| H2 slice sends over TLS/h2 duplex | client `hel`+`lo`, server `rep`+`ly`, datagram follows the finished stream | live `zig build test-webtransport -Dtest-filter='HTTP2 TLS runtime exchanges'` |
| H2 endpoint facade slice sends | client `hel`+`lo` and server `rep`+`ly` through `EndpointClient`/`EndpointServer` | live endpoint client/server tests |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport` |


## Hundred-and-sixth pass: slice-send examples and usage notes

`run-websocket-echo` now sends text from multiple slices on both the client
and server, demonstrating the runtime `sendTextSlices` API while keeping the
existing permessage-deflate negotiation. `docs/usage.md` names the HTTP/3
`sendStreamSlices` and HTTP/2 `sendStreamSlicesWith{Timeout,Deadline}` forms
and their staging difference. `run-webtransport-h2-capsule-echo` drives the
draft-15 HTTP/2 capsule path end to end: a virtual stream sent from slices is
echoed by the server, then both sides drain and close the session.
`run-webtransport-handshake-stream` now sends both client and server HTTP/3
streams from slices, covering the handshake session slice API in both
directions. `run-http-custom-resolver` maps `api.example.test` to the local
TLS listener with a custom `AddressResolver`, mirroring `curl --resolve` while
keeping the hostname as the request authority and TLS SNI.

| Gate | Result | Artifact |
| --- | --- | --- |
| WebSocket slice echo | `hello websocket` / `echo from netz websocket` | live `zig build run-websocket-echo` |
| HTTP/2 WebTransport capsule echo | `WebTransport H2 echo: echo: hello h2` | live `zig build run-webtransport-h2-capsule-echo` |
| HTTP/3 WebTransport slice streams | `WebTransport handshake streams ok: bidi=4, uni=14, server_uni=15` | live `zig build run-webtransport-handshake-stream` |
| Custom resolver (`--resolve`) | `custom resolver http1 200: hello from api.example.test` | live `zig build run-http-custom-resolver` |


## Hundred-and-seventh pass: H3 endpoint session slice sends

`webtransport.runtime.EndpointClient` sessions only forwarded contiguous
stream payloads even though the handshake/stateful sessions and the H2 endpoint
already exposed slices. `Session.sendStreamSlices`,
`sendStreamSlicesWithTimeout` and `sendStreamSlicesWithDeadline` now forward
to `flow_write.sendSlices*` with the same owner, connection and control checks.
A two-session authenticated test sends `stream-` + `first` from slices and
verifies the echoed concatenation.

| Gate | Result | Artifact |
| --- | --- | --- |
| H3 endpoint slice send | 107/107 matched | live `zig build test-webtransport -Dtest-filter='endpoint client multiplexes two authenticated'` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport` |


## Hundred-and-eighth pass: H3 server AcceptedSession slice sends

The public `webtransport.runtime.AcceptedSession` only forwarded contiguous
stream payloads, while the client and the stateful/handshake server sessions
already exposed slices. The H3 server now has
`sendDevelopmentStreamSlices*` and `sendDevelopmentStreamPartsSlices*`
primitives that encode each borrowed slice into frames without joining them;
`AcceptedSession` adds `sendStreamSlices`,
`sendStreamSlicesWithTimeout` and `sendStreamSlicesWithDeadline` with the same
prefix, rollback and `recordSent` behavior as the contiguous path. The
development stream test exercises both the association-prefix and non-prefix
slice paths, including a trailing empty slice that still carries FIN. The
stateful endpoint server's `EndpointAcceptedSession.sendStreamSlices` path is
exercised by the concurrent real-session test as well.

| Gate | Result | Artifact |
| --- | --- | --- |
| Development server slice sends | 102/102 matched | live `zig build test-webtransport -Dtest-filter='development streams preserve prefixes'` |
| H3 endpoint server slice sends | 105/105 matched | live `zig build test-webtransport -Dtest-filter='endpoint server owns concurrent real sessions'` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport` |


## Hundred-and-ninth pass: cumulative protocol gate

After the trust-parity, SOCKS5, WebSocket slice and WebTransport slice/capsule
series, the three scoped protocol suites were rerun together:

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http` |
| Full WebSocket suite (Debug) | 519/520 (1 skipped) | live `zig build test-websocket` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport` |
| QUIC trust unit tests | 38/38 | live `zig build test-quic -Dtest-filter='trust'` |
| Public package surface | 26/26 | live `zig build test-package` |


## Hundred-and-tenth pass: reconnecting H2 client slice forwarding

`webtransport.h2.ReconnectingEndpointClient` forwarded contiguous stream
payloads but not the slice forms added to `EndpointClient`. It now exposes
`sendStreamSlicesWithDeadline` and `sendStreamSlicesWithTimeout`, preserving
the generation check, `state.enter/leave`, and failure classification of the
contiguous path. The reconnecting filter compiles and passes 133/133.

| Gate | Result | Artifact |
| --- | --- | --- |
| Reconnecting H2 client tests | 133/133 | live `zig build test-webtransport -Dtest-filter='reconnecting'` |


## Hundred-and-eleventh pass: H2 endpoint listener slice forwarding

`webtransport.h2.EndpointListener` forwarded contiguous stream sends but not
the slice forms. It now exposes `sendStreamSlicesWithDeadline` and
`sendStreamSlicesWithTimeout`, acquiring the connection, releasing it after the
call, and forwarding to `EndpointServer.sendStreamSlicesWithDeadline`. The
listener test now also opens a client stream, receives the seed payload, and
replies from `to-` + `a` slices. The EndpointListener filter passes 137/137.
Together with the reconnecting client forwarding, the full WebTransport suite
remains 761/763 (2 skipped).

| Gate | Result | Artifact |
| --- | --- | --- |
| H2 EndpointListener tests | 137/137 | live `zig build test-webtransport -Dtest-filter='EndpointListener'` |
| H2 listener slice stream round-trip | client `seed-`+`a`, listener `to-`+`a` | live listener test |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport` |


## Hundred-and-twelfth pass: one-port H2/H1 ALPN dispatch

`netz.tls.alpn_server` already reported the negotiated protocol, and HTTP/2 had
`adoptNegotiatedTlsServer`, but HTTP/1 had no way to adopt an
already-negotiated TLS server connection. HTTP/1 now exports
`http1.runtime.adoptNegotiatedTlsServer`: `http/1.1` and legacy no-ALPN peers
are accepted, any other protocol fails closed with `error.InvalidAlpn`, and
ownership of the `tls_stream.ServerConnection` transfers at entry (deinit on
failure).

The audit also found that the HTTP/1 vail client connect path
(`Client.connectVailTlsHost*`) did not validate the server's ALPN selection, so
a server that selected `h2` could be driven with HTTP/1.1 bytes. It now rejects
any negotiated protocol other than `http/1.1`, matching
`Client.adoptNegotiatedTls`; a missing ALPN remains accepted for legacy HTTPS.

`examples/http/alpn_server.zig` serves one TLS port with
`alpn_protocols = {"h2","http/1.1"}`, dispatches on
`accepted.tls.negotiatedAlpn()`, and is exercised by `http2_only` and
`http1_only` unified clients with the pinned test key.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http --summary all` |
| ALPN-filtered HTTP suite | 103/103 | live `zig build test-http -Dtest-filter='ALPN' --summary all` |
| H1 TLS-filtered suite | passed | live `zig build test-http -Dtest-filter='TLS'` |
| One-port ALPN example | `ALPN http2 200: hello over HTTP/2 ALPN` and `ALPN http1 200: hello over HTTP/1.1 ALPN` | live `zig build run-http-alpn-server` |


## Hundred-and-thirteenth pass: mutual TLS example

The HTTP example set covered pinned server trust but not client
authentication. `examples/http/mutual_tls.zig` now mirrors `reqwest`'s
`Identity` and `curl --cert --key`: the HTTP/1.1 TLS listener sets
`.client_auth = .{ .verifier = ... }`, the unified client supplies
`.tls.client_identity`, and the handler reads the authenticated chain from
`Connection.peerCertificates()` before responding. Both sides use the
deterministic test key so the example runs without files; the docs note that
production deployments use distinct identities.

| Gate | Result | Artifact |
| --- | --- | --- |
| Mutual TLS example | `mTLS http1 200: hello from mutual TLS (peer certs=1)` | live `zig build run-http-mutual-tls` |


## Hundred-and-fourteenth pass: ALPN protocol-confusion hardening

The one-port ALPN adoption exposed a general pattern: an HTTP/1.1 or WSS
runtime can only speak its own protocol, but three entry points accepted a
negotiated result they could not serve.

- `http1.runtime.TlsServer.listen` now validates the ALPN offer list through
  `validateHttp1AlpnProtocols` and rejects anything other than `http/1.1` with
  `error.InvalidAlpn` before binding.
- `websocket.runtime.TlsServer.listen` and `initWithListener` apply the same
  rule, since WSS is an HTTP/1.1 Upgrade.
- `websocket.runtime.tls_client_identity` now rejects a negotiated ALPN other
  than `http/1.1` (null remains accepted for legacy origins), matching the H1
  client.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http --summary all` |
| Full WebSocket suite (Debug) | 521/522 (1 skipped) | live `zig build test-websocket --summary all` |
| MQTT WebSocket-filtered suite | 595/596 (1 skipped) | live `zig build test-mqtt -Dtest-filter='websocket'` |
| ALPN-filtered HTTP suite | 104/104 | live `zig build test-http -Dtest-filter='ALPN' --summary all` |


## Hundred-and-fifteenth pass: private-CA recipe and authentication overview

`examples/http/custom_ca.zig` mirrors `curl --cacert`: it builds an empty
`netz.tls.trust.SystemStore`, adds only the deterministic test certificate,
and passes it as `.tls.system_store`, which H1/H2 and the H3 routes share.
`docs/http-overview.md` now has an "Authentication and trust" section covering
server verification choices, mTLS, proxy/cookie/redirect credential rules, ALPN
protocol selection, and server-side identity rotation and peer chains.

| Gate | Result | Artifact |
| --- | --- | --- |
| Custom CA example | `custom CA http1 200: hello from a custom CA` | live `zig build run-http-custom-ca` |


## Hundred-and-sixteenth pass: `curl --compressed` recipe

`examples/http/content_coding.zig` serves a gzip body and decodes it on the
client with `OwnedResponse.decodeContentAlloc`, after advertising the shared
`content_coding.accept_encoding` offer. The server compresses with Zig's flate
gzip container; the client reports the encoded and decoded sizes and verifies
the round trip. `docs/usage.md` now points at the example and the
`decodeContentInto` caller-buffer counterpart.

| Gate | Result | Artifact |
| --- | --- | --- |
| Content coding example | `content coding http1 200: 86 -> 528 bytes, codings=1, match=true` | live `zig build run-http-content-coding` |


## Hundred-and-seventeenth pass: timeout and deadline recipe

`examples/http/timeouts.zig` mirrors reqwest's `.timeout()` and curl's
`--max-time`. One slow origin answers after 200 ms; a 50 ms per-request
timeout returns `error.Timeout`, while a 2 s absolute deadline completes the
same exchange. The docs note that the budget spans DNS/TCP, TLS, upload and the
complete response rather than only the connect.

| Gate | Result | Artifact |
| --- | --- | --- |
| Timeout example | `50 ms timeout: error.Timeout (expected)` and `2 s deadline: http1 200: slow but successful` | live `zig build run-http-timeouts` |


## Hundred-and-eighteenth pass: HTTP/3 server ALPN validation and public QUIC trust helper

`http3.runtime.HandshakeServer.bind` accepted any `alpn_protocol` string even
though the HTTP/3 runtime can only speak `h3`/`h3-NN`; a misconfigured
`hq-interop` server would negotiate a protocol its framing cannot use. `bind`
now rejects non-HTTP/3 identifiers with `error.InvalidAlpn`, symmetric with the
client's post-handshake check, and a test covers both rejection and the
`h3-29` draft form.

The QUIC low-level handshake disables certificate verification when
`server_auth`, `system_store`, `system_environ` and a non-default
`root_source` are all unset. That remains the documented low-level contract,
but the helper that installs platform roots was private to the H3 facades.
`quic.mod` now exports `client_trust`, and the package surface test covers
`hasExplicitTrust` and `applyPlatformRootDefault`; `docs/usage.md` warns raw
QUIC callers and points at the helper.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP/3 suite (Debug) | 928/932 (4 skipped) | live `zig build test-http3 --summary all` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |
| H3 handshake server tests | 53/53 | live `zig build test-http3 -Dtest-filter='rejects a non-HTTP/3 ALPN'` |
| Public package surface (trust helper) | 2/2 | live `zig build test-package -Dtest-filter='QUIC client trust'` |


## Hundred-and-nineteenth pass: verified-by-default HTTP/3 fetch example

`examples/http/http3_fetch.zig` connected without certificate verification
unless `--verify` was passed, so the runnable H3 entry point diverged from the
unified client's secure default. It now verifies with the platform roots by
default; `--no-verify` remains only for controlled self-signed peers and
`--verify` stays accepted as a no-op. `docs/build.md` and `docs/usage.md` now
state that the low-level `HandshakeClient.connectUri*`/`requestUri*` helpers
require explicit trust while the unified/WS/WT facades install roots.

| Gate | Result | Artifact |
| --- | --- | --- |
| Example compiles and parses flags | `HTTP/3 fetch attempt ... failed: InvalidUri` after 5 attempts for an `http://` URI | live `zig build run-http3-fetch -- http://127.0.0.1:1/` |


## Hundred-and-twentieth pass: WebTransport HTTP/2 TLS metadata parity

HTTP/3 WebTransport sessions exposed the authenticated peer chain and
negotiated TLS metadata, but the HTTP/2 capsule `Session`, `EndpointServer` and
pending-request surfaces did not. They now forward `peerCertificates()`,
`negotiatedAlpn()` and `negotiatedCipherSuite()` from the underlying HTTP/2
connection, so mTLS authorization works the same way on both WebTransport
variants. Tests assert the negotiated `h2` ALPN and the server chain on a TLS
session, and that an anonymous client has no peer certificate.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-twenty-first pass: authenticated raw QUIC handshake example

`examples/quic/quic_handshake_echo.zig` ran the raw `quic.handshake` path with
no server identity and no client trust, which is the exact foot-gun documented
for the low-level API. The server now presents the deterministic test identity
and the client pins its key, so the example demonstrates an authenticated
handshake while remaining self-contained. Other QUIC examples use preconfigured
1-RTT keys and are unaffected.

| Gate | Result | Artifact |
| --- | --- | --- |
| Authenticated QUIC handshake example | `QUIC handshake echo ok: hello over a real netz QUIC handshake` | live `zig build run-quic-handshake-echo` |


## Hundred-and-twenty-second pass: WebTransport HTTP/2 endpoint-client metadata

The HTTP/2 WebTransport `EndpointClient` still hid the handshake metadata that
its `Session`, `EndpointServer` and HTTP/3 counterpart expose. It now forwards
`peerCertificates()`, `negotiatedAlpn()` and `negotiatedCipherSuite()` from the
owned HTTP/2 connection; the TLS endpoint test asserts the `h2` ALPN and the
server chain. This completes the same-code mTLS inspection story across
WebTransport variants and endpoint facades.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-twenty-third pass: WebTransport HTTP/2 transcript-hash parity

The HTTP/2 WebTransport surfaces exposed peer certificates, ALPN and cipher
suite but not the negotiated transcript hash that WebSocket and HTTP/3
WebTransport expose for channel binding. `webtransport.h2.Session`,
`EndpointClient`, `EndpointServer` and pending requests now forward
`negotiatedTranscriptHash()` from the underlying HTTP/2 connection. TLS tests
assert it is present on both the client endpoint and a server pending request.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-twenty-fourth pass: HTTP/3 WebTransport endpoint-client metadata

The HTTP/3 WebTransport `EndpointClient` exposed peer certificates and ALPN but
not the negotiated cipher suite or transcript hash that
`HandshakeClientSession` and the endpoint server already provide.
`EndpointClient` now forwards both from the handshake client, and the endpoint
client test asserts AES-128-GCM/SHA-256. This completes the TLS metadata surface
across HTTP/2 and HTTP/3 WebTransport sessions, clients, servers and pending
requests.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-twenty-fifth pass: ALPN positive-path tests and API discoverability

The ALPN hardening tests only covered rejection. Both listeners now also assert
that an explicit `http/1.1`-only offer list is accepted, and
`netz.tls.alpn_server` points callers at
`http1.runtime.adoptNegotiatedTlsServer`/`http2.runtime.adoptNegotiatedTlsServer`
and the runnable example. The protocol API map now records that the low-level
`http3.runtime.HandshakeClient.connectUri*`/`requestUri*` helpers require
explicit trust.

| Gate | Result | Artifact |
| --- | --- | --- |
| ALPN-filtered HTTP suite | 105/105 | live `zig build test-http -Dtest-filter='ALPN' --summary all` |
| ALPN-filtered WebSocket suite | 55/55 | live `zig build test-websocket -Dtest-filter='ALPN' --summary all` |


## Hundred-and-twenty-sixth pass: cumulative protocol gate after the trust/API series

After the ALPN adoption, trust-default, WebTransport metadata and example
series, the scoped protocol suites were rerun together:

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http --summary all` |
| Full WebSocket suite (Debug) | 521/522 (1 skipped) | live `zig build test-websocket --summary all` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |
| Full HTTP/3 suite (Debug) | 928/932 (4 skipped) | live `zig build test-http3 --summary all` |
| QUIC trust unit tests | 38/38 | live `zig build test-quic -Dtest-filter='trust' --summary all` |
| Public package surface | 27/27 | live `zig build test-package --summary all` |


## Hundred-and-twenty-seventh pass: EndpointServer TLS metadata coverage

The new HTTP/2 `EndpointServer` TLS metadata accessors were not referenced by a
test, so Zig's lazy analysis had not proven them. The reconnecting TLS endpoint
test now asserts the `h2` ALPN, a non-null transcript hash and no client
certificate for its anonymous client, exercising
`peerCertificates()`/`negotiatedAlpn()`/`negotiatedTranscriptHash()` on the
server owner. The H2 capsule guide documents the shared metadata surface.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-twenty-eighth pass: HTTP/1 WebSocket Origin allowlist coverage

`AcceptOptions.allowed_origins` was exercised for RFC 8441/H3 and in unit
tests, but not end-to-end on the HTTP/1 Upgrade server. A new test connects
with a denied Origin, asserts the server returns `error.InvalidOrigin` before
any 101 response, then completes a normal exchange with an allowed Origin over
the same listener. `docs/usage.md` now documents the opening-handshake
authentication surface (Origin, subprotocols, extra headers, pre-upgrade
credential checks and redirect stripping).

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 522/523 (1 skipped) | live `zig build test-websocket --summary all` |


## Hundred-and-twenty-ninth pass: RFC 8441 WebSocket-over-HTTP/2 example

The WebSocket example set covered cleartext H1 and WSS but not RFC 8441.
`examples/websocket/websocket_h2_echo.zig` reuses one h2c connection for an
extended CONNECT with `:protocol = websocket`, negotiates the `echo.v1`
subprotocol and echoes one message. The same shape works over TLS by swapping
in `http2.runtime.TlsServer`/`TlsClient`.

| Gate | Result | Artifact |
| --- | --- | --- |
| RFC 8441 example | `RFC 8441 server received: hello over RFC 8441` and the matching client line | live `zig build run-websocket-h2-echo` |


## Hundred-and-thirtieth pass: RFC 8441 pending-upgrade TLS metadata

The HTTP/1 pending upgrade exposed the parsed request plus TLS metadata, but
`PendingH2Upgrade` only exposed request fields. It now forwards
`peerCertificates()`, `negotiatedAlpn()`, `negotiatedCipherSuite()` and
`negotiatedTranscriptHash()` from the parent HTTP/2 connection, so RFC 8441
servers can authorize the peer before sending the 200 response. The TLS
transport-end test asserts the `h2` ALPN, transcript hash and anonymous peer
through the pending surface.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 522/523 (1 skipped) | live `zig build test-websocket --summary all` |


## Hundred-and-thirty-first pass: HTTP/1 server ALPN metadata

The HTTP/1 server `Connection` exposed the peer chain, cipher suite, TLS
version and transcript hash but not the negotiated ALPN token that the client,
pending upgrade and HTTP/2 surfaces expose. `Connection.negotiatedAlpn()` now
returns the selected token (null for cleartext and legacy no-ALPN peers), and
the ALPN adoption test asserts `http/1.1` on a real negotiated connection.

| Gate | Result | Artifact |
| --- | --- | --- |
| ALPN-filtered HTTP suite | 105/105 | live `zig build test-http -Dtest-filter='ALPN' --summary all` |


## Hundred-and-thirty-second pass: WebTransport HTTP/2 session exporter coverage

The H2 `Session.exportKeyingMaterial` already wrapped the raw TLS exporter in
the WebTransport `EXPORTER-WebTransport` context (stream ID + label +
context), but no TLS test exercised it. The listener TLS test now exports a
32-byte secret through the session API, proving the channel-binding path on a
real connection.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-thirty-third pass: HTTP/1 pipeline performance baseline

ReleaseFast builds succeeded after the host swap recovered. Same-application
loopback numbers from `bench-http1-pipeline` (pipeline depth 16, 13-byte body,
50 warmup + 500 iterations):

| Strategy | ns/request | requests/s |
| --- | --- | --- |
| auto | 6,314 | 158,366 |
| auto (repeat) | 6,622 | 151,002 |
| vectored | 6,563 | 152,347 |
| flatten | 6,695 | 149,352 |

64 KiB body, 20 warmup + 200 iterations:

| Strategy | ns/request | requests/s |
| --- | --- | --- |
| auto | 175,148 / 185,856 | 5,709 / 5,380 |
| vectored | 153,467 | 6,516 |

Run-to-run variance is roughly 5-10% on this shared host. `auto` selects
`.vectored` for response batches above the 16-KiB borrow threshold, so the
large-body auto and vectored runs execute the same path; the spread is host
noise. No write-path regression or obvious optimization target was found, so
no code change is warranted from this baseline.


## Hundred-and-thirty-fourth pass: full HTTP/2 h2c benchmark coverage

`bench_http2_h2c` excluded the 1-MiB response and duplex scenarios because they
had deadlocked in the in-process single-executor harness. All three now
complete, so the exclusion filter is removed and the default benchmark step
exercises all ten scenarios. Full h2c baseline (ReleaseFast, zio-std-io;
1000/2000 iterations, large scenarios 2/5):

| Scenario | ns/request | requests/s |
| --- | --- | --- |
| consecutive x1 empty | 116,935 | 8,551 |
| shared consecutive x1 empty | 139,482 | 7,169 |
| consecutive x1 req 10 B | 67,689 | 14,773 |
| consecutive x1 req 100 KiB | 137,112 | 7,293 |
| consecutive x1 res 10 B | 99,597 | 10,040 |
| parallel x10 empty | 12,180 | 82,100 |
| parallel x10 req 10 KiB x100 max window | 827,063 | 1,200 |
| parallel x10 res 1 MiB | 799,257 | 1,250 |
| parallel x10 duplex 1 MiB aggregate | 1,844,688 | 540 |
| parallel x10 duplex 1 MiB streaming | 1,716,526 | 580 |

Run-to-run variance is roughly 5-10% on this shared host. The previously
excluded scenarios completing is evidence that the old single-executor
flow-control deadlock no longer reproduces.


## Hundred-and-thirty-fifth pass: WebTransport performance baseline

ReleaseFast WebTransport over the native QUIC/TLS endpoint (zio-std-io,
loopback, 1 MiB transfer, one stream):

| Configuration | Elapsed | Throughput | Send calls / partial |
| --- | --- | --- | --- |
| default (pacing, 16-KiB caller buffer) | 25.56 ms | 39 MiB/s | 273 / 273 |
| `--disable-pacing` | 18.17 ms | 55 MiB/s | 273 / 273 |
| `--send-all` | 16.87 ms | 59 MiB/s | 1 / 0 |
| `--stream-window=262144` | 20.95 ms | 47 MiB/s | 284 / 284 |

DATAGRAM echo: 20,000 round trips, 42,091 ns/datagram (23,757 datagrams/s).

The incremental path pays per-call pacing/backpressure overhead; `--send-all`
measures the continuous-send ceiling. No regression or single obvious runtime
fix was identified from these numbers, so no code change is warranted.


## Hundred-and-thirty-sixth pass: QUIC handshake performance baseline

ReleaseFast QUIC/TLS 1.3 handshake benchmark with pinned P-256 server
verification (zio-std-io, loopback, 50 iterations):

| Metric | Value |
| --- | --- |
| total elapsed | 27.03 ms |
| connections/s | 1,849.8 |
| p50 | 409,916 ns |
| p99 / p99.9 | 1,228,042 ns |

The pinned-verifier handshake path completes sub-millisecond at p50. This is a
baseline only; no code change is warranted from a single noisy run.


## Hundred-and-thirty-seventh pass: QUIC stream echo baseline

Echo mode uses a fixed 1-KiB payload per round trip (`--transfer-bytes` applies
to the upload/churn modes), 50 iterations, ReleaseFast, loopback:

| Metric | Value |
| --- | --- |
| p50 | 116,500 ns |
| p99 / p99.9 | 248,334 ns |
| payload verified | 51,200 B |

The 1-KiB echo path is ~3.5x lower latency at p50 than a full handshake and
remains well below the 1-ms p99 bound on this host.


## Hundred-and-thirty-eighth pass: cumulative gate after the metadata and benchmark series

All scoped protocol suites were rerun live after the ALPN metadata, RFC 8441
pending-upgrade metadata, WebTransport TLS metadata/exporter and benchmark
coverage series:

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http --summary all` |
| Full WebSocket suite (Debug) | 522/523 (1 skipped) | live `zig build test-websocket --summary all` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |
| Full HTTP/3 suite (Debug) | 928/932 (4 skipped) | live `zig build test-http3 --summary all` |
| QUIC trust unit tests | 38/38 | live `zig build test-quic -Dtest-filter='trust' --summary all` |
| Public package surface | 27/27 | live `zig build test-package --summary all` |


## Hundred-and-thirty-ninth pass: RFC 9220 WebSocket-over-HTTP/3 example

`examples/websocket/websocket_h3_echo.zig` completes the WebSocket transport
matrix: an extended CONNECT on a real QUIC/TLS connection, pinned server key,
`echo.v1` subprotocol and one echoed message. Building it surfaced two
ownership requirements that were not documented: the H3 `Connection` owns the
handshake client/session (`deinit` required) and `closeWithTimeout` returns a
`CloseHandshakeEvent` that owns the peer Close or an in-flight application
frame. The example now releases both, and `docs/usage.md` states the event
ownership rule. Leak-free run:

`RFC 9220 server received: hello over RFC 9220`
`RFC 9220 client received: hello over RFC 9220`

| Gate | Result | Artifact |
| --- | --- | --- |
| RFC 9220 example | leak-free echo over QUIC/TLS | live `zig build run-websocket-h3-echo` |


## Hundred-and-fortieth pass: uniform WebSocket connection release

The H3 WebSocket connection only exposed `deinit()`, while HTTP/1 and HTTP/2
connections use `close()`. H3 now provides `close()` as a documented alias so
one cleanup pattern works across transports; an internal local name was
renamed to avoid shadowing. The RFC 9220 example uses `close()` and remains
leak-free.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 522/523 (1 skipped) | live `zig build test-websocket --summary all` |
| RFC 9220 example | leak-free echo | live `zig build run-websocket-h3-echo` |


## Hundred-and-forty-first pass: WebSocket close asymmetry and RFC 9220 auth metadata

The HTTP/3 WebSocket connection has no send-only `sendClose`; its
`closeWithTimeout` sends once and surfaces in-flight application frames so one
call can drain and close. The API map records this asymmetry and
`docs/usage.md` spells out the pattern. The RFC 9220 example now prints the
negotiated `h3` ALPN and asserts the pinned server chain before echoing,
demonstrating authenticated metadata through the public surface.

| Gate | Result | Artifact |
| --- | --- | --- |
| RFC 9220 example | `ALPN: h3`, `server certificate chain: 1`, echo | live `zig build run-websocket-h3-echo` |


## Hundred-and-forty-second pass: WebSocket frame-reception parity

HTTP/1 and HTTP/2 distinguish `receiveFrame` (returns control frames) from
`receiveFrameAuto*` (services Pong/Close replies), while HTTP/3 already
services them inside its plain receive path. HTTP/3 now exposes
`receiveFrameAuto`/`WithTimeout`/`WithDeadline` as documented aliases so
generic call sites stay source-compatible; the API map and usage guide record
the semantic difference.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 522/523 (1 skipped) | live `zig build test-websocket --summary all` |


## Hundred-and-forty-third pass: WebSocket sendMessage parity

HTTP/1 and HTTP/2 exposed the opcode-driven `sendMessage`, but the HTTP/3
connection only had `sendText`/`sendBinary` plus deadline-bounded message
forms. HTTP/3 now provides the same unbounded `sendMessage`, mirroring the
typed send path and rejecting non-text/binary opcodes. The RFC 9220 example
sends its echo through `sendMessage`.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 522/523 (1 skipped) | live `zig build test-websocket --summary all` |
| RFC 9220 example | echo through `sendMessage` | live `zig build run-websocket-h3-echo` |


## Hundred-and-forty-fourth pass: compile-only library gate and benchmark entry points

`zig build test-compile` compiled both test roots without running them after
the WebSocket API-parity series: 9/9 steps succeeded. The API map now lists
the maintained performance entry points (`bench-http1-pipeline`,
`bench-http1-body`, `bench-http2-h2c`, `bench-quic-handshake-stream`,
`bench-webtransport-stream`, `bench-webtransport-datagram`) and points at the
review ledger for recent numbers.

| Gate | Result | Artifact |
| --- | --- | --- |
| Compile-only library gate | 9/9 steps | live `zig build test-compile --summary all` |


## Hundred-and-forty-fifth pass: fuzz corpus replay gate

Bounded fuzz corpus replays after the WebSocket API-parity series:

| Gate | Result | Artifact |
| --- | --- | --- |
| Parser corpus | 2/2 tests | live `zig build fuzz-parsers --summary all` |
| State-sequence corpus | 2/2 tests | live `zig build fuzz-stateful --summary all` |
| HTTP/1 connection corpus | 3/3 tests | live `zig build fuzz-http1-connection --summary all` |
| HTTP/1 TLS connection corpus | 3/3 tests | live `zig build fuzz-http1-tls-connection --summary all` |
| HTTP/2 connection corpus | 3/3 tests | live `zig build fuzz-http2-connection --summary all` |
| HTTP/3 connection corpus | 3/3 tests | live `zig build fuzz-http3-connection --summary all` |
| WebTransport endpoint corpus | 3/3 tests | live `zig build fuzz-webtransport-endpoint --summary all` |


## Hundred-and-forty-sixth pass: WebTransport session trust documentation correction

The WebTransport quick start used `HandshakeClientSession.connectUriWithTimeout`
and claimed the URI form verifies against the system trust store by default.
That is true for `EndpointClient` URI connects, but the lower-level session
helper keeps the explicit-trust contract: a null `server_auth` with no store,
environment, or non-default root source leaves QUIC verification disabled
(`quic.handshake.connectAttempt` builds no verifier in that case). The usage
guide now states the distinction and marks the trust fields required in the
snippet.

| Gate | Result | Artifact |
| --- | --- | --- |
| Documentation audit | behavior matched to the `root_source`/`server_auth` verifier branches | code inspection of `quic.handshake.connectAttempt` |


## Hundred-and-forty-seventh pass: trust documentation precision

The HTTP overview claimed "every TLS route verifies the peer certificate by
default", which overstates the low-level QUIC/H3 helpers. It now scopes the
claim to the unified client, pool and Alt-Svc routes and points at the API map
for the explicit-configuration helpers. The `verify_host = false` row now
notes that it applies to TCP TLS only; H3 routes keep the configured
verifier's hostname policy (`ClientTlsTrust` has no verify-host field).

| Gate | Result | Artifact |
| --- | --- | --- |
| Documentation audit | claims matched to `ClientTlsTrust` fields and `quic.handshake.connectAttempt` branches | code inspection |


## Hundred-and-forty-eighth pass: WebTransport TLS bullet scoped to the verifying facade

The WebTransport usage bullet still said URI connects install platform roots
without distinguishing `EndpointClient` from `HandshakeClientSession`. It now
names `EndpointClient` as the verifying URI facade and marks the session
helpers as requiring explicit trust, matching the quick-start correction from
pass 146.

| Gate | Result | Artifact |
| --- | --- | --- |
| Documentation audit | bullet matches the `applyPlatformRootDefault` call sites | code inspection of `endpoint_client.zig` and `handshake_client_session.zig` |


## Hundred-and-forty-ninth pass: HTTP/1 streaming-body baseline

`bench-http1-body` (1-MiB body, 16-KiB chunks, 20 warmup + 100 iterations,
ReleaseFast, loopback):

| Mode | ns/round-trip | aggregate MiB/s |
| --- | --- | --- |
| fixed | 1,619,407 | 1,235 |
| chunked | 1,926,780 | 1,038 |

Fixed-length framing is ~19% faster than chunked framing at this size; both
exceed 1 GiB/s aggregate on loopback. Baseline only; no code change is
warranted from a single run.


## Hundred-and-fiftieth pass: WebTransport H2 Session application-protocol accessor

`Session` stored the negotiated WebTransport application protocol but only
exposed it as a field, while the endpoint facades provide
`applicationProtocol()`. `Session.applicationProtocol()` now returns the
selected token, and the runtime tests use it for the required `echo`
negotiation cases. The API map also records the remaining H2 key-update and
reconnecting-facade metadata asymmetries.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-fifty-first pass: WebTransport application-protocol type note

HTTP/2 `applicationProtocol()` returns the decoded selected identifier as a
byte slice, while HTTP/3 returns a validated `application_protocol.String`
whose comparisons decode RFC 9651 escapes. The API map now records the type
difference so callers comparing escaped identifiers use the matching
comparator.

| Gate | Result | Artifact |
| --- | --- | --- |
| Documentation audit | H2 decode path (`decodedLen`/`decodeInto`) matched to H3 `String` | code inspection of `webtransport/h2/runtime.zig` |


## Hundred-and-fifty-second pass: cumulative gate after the WebSocket/WebTransport parity series

All scoped protocol suites were rerun live after the final API-parity,
trust-documentation and benchmark series:

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http --summary all` |
| Full WebSocket suite (Debug) | 522/523 (1 skipped) | live `zig build test-websocket --summary all` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |
| Full HTTP/3 suite (Debug) | 928/932 (4 skipped) | live `zig build test-http3 --summary all` |
| QUIC trust unit tests | 38/38 | live `zig build test-quic -Dtest-filter='trust' --summary all` |
| Public package surface | 27/27 | live `zig build test-package --summary all` |


## Hundred-and-fifty-third pass: per-protocol suite gate

The narrower per-protocol suites were run in addition to the cumulative gate:

| Gate | Result | Artifact |
| --- | --- | --- |
| HTTP/1 scope | 478/478 | live `zig build test-http1 --summary all` |
| HTTP/2 scope | 985/985 | live `zig build test-http2 --summary all` |
| QUIC scope | 1113/1136 (23 skipped) | live `zig build test-quic --summary all` |

The full QUIC suite includes real-UDP timing tests; all executed tests passed
on this run, with 23 environment-gated skips.


## Hundred-and-fifty-fourth pass: WebTransport endpoint metadata lifetime contract

The HTTP/2 endpoint metadata accessors read handshake-fixed TLS fields
directly from the worker-owned connection, so they must not race with endpoint
shutdown (which retires that connection). `EndpointClient`, `EndpointServer`
and the usage guide now state the live-endpoint contract explicitly.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |


## Hundred-and-fifty-fifth pass: WebTransport applicationProtocol discoverability

The H2 capsule guide and the usage TLS bullet now mention
`Session.applicationProtocol()` alongside the TLS metadata accessors, so the
negotiated application protocol is discoverable from the same section.


## Hundred-and-fifty-sixth pass: aggregate example compile gate

`zig build examples -j2 --summary all` compiled every registered example
executable against the current public API after the WebSocket/WebTransport
parity series: 102/102 steps succeeded. This covers the new HTTP/1 ALPN,
mutual-TLS, custom-CA, content-coding, timeout, RFC 8441 and RFC 9220
examples together with the pre-existing set.

| Gate | Result | Artifact |
| --- | --- | --- |
| Aggregate example compile | 102/102 steps | live `zig build examples -j2 --summary all` |


## Hundred-and-fifty-seventh pass: no-ALPN client rejection coverage

An H1 client using the default empty ALPN list cannot complete a handshake
against an ALPN dispatcher configured with `{"h2","http/1.1"}`. A new test
connects with no ALPN offer, asserts both the client and server handshakes
fail, and the usage guide now states that such clients must offer
`http/1.1` explicitly.

| Gate | Result | Artifact |
| --- | --- | --- |
| ALPN-filtered HTTP suite | 106/106 | live `zig build test-http -Dtest-filter='ALPN' --summary all` |
| Full HTTP/1 scope | 479/479 | live `zig build test-http1 --summary all` |

The HTTP/1 scope count grew from 478 to 479, confirming the new test is part
of the full per-protocol gate (the `test-http` scope composes a different
subset).


## Hundred-and-fifty-eighth pass: WebTransport HTTP/2 Origin allowlist coverage

The H2 capsule runtime already enforced `ServerOptions.origin`
(`same_origin_or_absent` by default, `exact` allowlists, `allow_any`), but only
the policy unit tests covered it. The invalid-CONNECT runtime test now sends a
denied Origin, asserts the server returns `error.InvalidOrigin` with a 403
rejection, and then completes the healthy sibling session.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |
| Invalid CONNECT/Init filter | 125/125 | live `zig build test-webtransport -Dtest-filter='invalid CONNECT and Init reject only their streams' --summary all` |


## Hundred-and-fifty-ninth pass: RFC 8441 Origin allowlist coverage

The H2 WebSocket admission path validated `allowed_origins` but had no
end-to-end test. A new TLS test sends a denied Origin through an RFC 8441
extended CONNECT, asserts the server returns `error.InvalidOrigin` before any
acceptance response, and verifies the client sees no accepted connection. The
server aborts only that extended-CONNECT stream.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 523/524 (1 skipped) | live `zig build test-websocket --summary all` |
| Origin filter | 43/43 | live `zig build test-websocket -Dtest-filter='rejects a denied Origin' --summary all` |


## Hundred-and-sixtieth pass: RFC 9220 Origin allowlist coverage

The H3 WebSocket admission path validated `allowed_origins` but only positive
cases were tested. A new QUIC/TLS test sends a denied Origin through an RFC
9220 extended CONNECT, asserts the server returns `error.InvalidOrigin`
before acceptance, and verifies the client receives no connection. Together
with the H1, RFC 8441 and WebTransport H2 cases, all WebSocket transports now
have an end-to-end Origin rejection test.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 524/525 (1 skipped) | live `zig build test-websocket --summary all` |
| Origin filter | 95/95 | live `zig build test-websocket -Dtest-filter='rejects a denied Origin' --summary all` |


## Hundred-and-sixty-first pass: WebTransport origin-policy discoverability

The WebTransport usage section now documents both server knobs:
`Limits.origin_policy` for H3 and `ServerOptions.origin` for HTTP/2 capsules,
including the default same-origin-or-absent behavior and the `.exact` /
`.allow_any` modes. Together with the H1/RFC 8441/RFC 9220/H2/H3 rejection
tests, the Origin matrix is fully covered and documented.

| Gate | Result | Artifact |
| --- | --- | --- |
| Origin rejection matrix | H1, RFC 8441, RFC 9220, WT H2, WT H3 | live test runs recorded in passes 128, 158, 159, 160 and `admission_tests.zig` |


## Hundred-and-sixty-second pass: RFC 9220 required-subprotocol coverage

`AcceptOptions.require_subprotocol` was enforced on H3 but only tested on
H1/H2. A new QUIC/TLS test connects without offering a subprotocol to a server
that requires one, asserts `error.InvalidSubprotocol` before acceptance, and
verifies the client receives no connection.

| Gate | Result | Artifact |
| --- | --- | --- |
| Full WebSocket suite (Debug) | 525/526 (1 skipped) | live `zig build test-websocket --summary all` |
| Subprotocol filter | 70/70 | live `zig build test-websocket -Dtest-filter='requires a selected subprotocol' --summary all` |


## Hundred-and-sixty-third pass: cumulative gate after the Origin/subprotocol coverage

All scoped suites were rerun live after the H1/RFC 8441/RFC 9220 Origin and
required-subprotocol tests plus the WebTransport H2 Origin test:

| Gate | Result | Artifact |
| --- | --- | --- |
| Full HTTP suite (Debug) | 310/310 | live `zig build test-http --summary all` |
| Full HTTP/1 suite (Debug) | 479/479 | live `zig build test-http1 --summary all` |
| Full WebSocket suite (Debug) | 525/526 (1 skipped) | live `zig build test-websocket --summary all` |
| Full WebTransport suite (Debug) | 761/763 (2 skipped) | live `zig build test-webtransport --summary all` |
| Full HTTP/3 suite (Debug) | 928/932 (4 skipped) | live `zig build test-http3 --summary all` |
| QUIC trust unit tests | 38/38 | live `zig build test-quic -Dtest-filter='trust' --summary all` |
| Public package surface | 27/27 | live `zig build test-package --summary all` |


## Hundred-and-sixty-fourth pass: 0-RTT verification record

The user asked whether QUIC 0-RTT is verified. Live scoped runs:

| Gate | Result | Artifact |
| --- | --- | --- |
| QUIC 0-RTT filter | 62/62 | live `zig build test-quic -Dtest-filter='0-RTT' --summary all` |
| H3 early-data filter | 101/101 | live `zig build test-http3 -Dtest-filter='early' --summary all` |

Coverage includes authenticated 0-RTT stream data, ChaCha20 and
AES-256-SHA384 cipher variants, retransmitted and socket-rejected packet
numbers, ticket-age skew rejection with PSK resumption, Version Negotiation
rejection reporting, the replay filter (duplicates, expiry, snapshots),
PSK/ClientHello-bound keys, remembered transport-parameter validation, and H3
typed early requests with `was_early_data` provenance across accepted and
rejected cases.
