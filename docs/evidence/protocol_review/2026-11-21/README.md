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

## Open findings

These are source-level findings, not reproduced defects, and are intentionally
left out of this batch.

| ID | Area | Finding | Suggested direction |
| --- | --- | --- | --- |
| P1 | Resolved in the second pass | After an H3 *connection* failure the body was never read, yet fallback for an idempotent method still called `bodySource().prepareReplay()`, rejecting a single-pass Reader. | The attempt now records whether the request started; setup failures fall back without replay, started requests keep method/replay gating. |
| P2 | Partially resolved | Client `receiveServerHandshakeCrypto` now emits PTO probes on a timer, independent of received datagrams, and restarts the schedule only when contiguous CRYPTO bytes advance. Server prefix sending still needs separate investigation. | Keep the timer probe; debug why a server prefix attempt only sends once in the 40-entry regression. |
| P3 | Resolved in the sixth pass | The legacy/stateless adapters returned `WebTransportNotNegotiated` for caller configuration they cannot support (`initial_flow_limits`). | They now return `UnsupportedWebTransportOption`; genuine peer capability failures keep `WebTransportNotNegotiated`. |
| P4 | HTTP H3 options | `Client.Options.http3.handshake.handshake.alpn_protocols` nests two `handshake` levels because the facade wraps the native handshake options. | Add flat accessors or a `quic` sub-struct while keeping the existing fields as deprecated aliases. |
| P6 | Resolved | `drains GRO response batch one packet at a time` hung on platforms without GRO because its skip path joined a server thread still blocked in `receiveRequest`. | The skip path now closes the connection first; the test skips cleanly and the full H3 suite completes. |
| P5 | WebSocket byte-stream adapter | `websocket.stream_connection.Connection.close()` has no deadline form and `receiveMessage()` has no absolute-deadline variant; the adapter is documented as caller-driven byte-stream framing. | Add deadline variants if H2/H3 extended-CONNECT embedders need bounded framing reads. |

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
