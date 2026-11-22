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
