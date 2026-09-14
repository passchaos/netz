# netz vs `~/Work/quicz` HTTP/QUIC parity audit

This audit tracks the user goal: use the HTTP/QUIC implementations under
`~/Work` as a reference and evolve netz until its feature coverage and
performance are stronger.  It is intentionally evidence-based: each completed
item lists concrete netz code or a runnable command, and each gap remains open
until it has a direct artifact and validation.

## Current validated netz commands

These commands are the lightweight functional smoke set used while improving
parity:

```sh
zig build test
zig build run-quic-echo -Doptimize=ReleaseFast
zig build run-quic-handshake-echo -Doptimize=ReleaseFast
zig build run-quic-datagram-echo -Doptimize=ReleaseFast
zig build run-quic-close -Doptimize=ReleaseFast
zig build interop-quic-quic-go -Doptimize=ReleaseFast
zig build interop-quic-s2n -Doptimize=ReleaseFast
zig build run-http3-fetch -Doptimize=ReleaseFast -- --discover --verify --head https://robotics.bytedance.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- --alt-svc='h3=":443"; ma=2592000' --verify --head https://robotics.bytedance.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- --alt-svc='h3=":443"; ma=86400' --verify --expect-status=200 --min-body-bytes=100000 https://cloudflare-quic.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- --alt-svc='h3=":8443"; ma=86400' --verify --expect-status=200 --min-body-bytes=400 https://quic.tech/
zig build interop-http3-public -Doptimize=ReleaseFast
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=upload --streams=2 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=download --streams=1 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=download --streams=4 --verbose
```

Longer performance gates that have been used successfully include:

```sh
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=67108864 --mode=upload --streams=4 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=1 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=4 --verbose
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream --warmup=200 --iterations=5000
zig build bench-quic-datagram -Doptimize=ReleaseFast
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=100
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=200
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=1 --verbose
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=4 --verbose
```

## Current `~/Work/quicz` comparison context

A direct run of `~/Work/quicz/examples/quic_bench_hs.zig` with Zig 0.16 and
`-OReleaseFast -lc` produced these loopback real-handshake reference numbers:

```text
quicz Stream Upload:       228.77 MB/s mean, 3.3% stddev, 5 x 64 MiB
quicz Multi-Stream (4x):   244.85 MB/s mean, 2.8% stddev, 5 x 64 MiB
quicz Echo Latency:        P50 10.5us, P99 14.3us, P99.9 377.8us
netz Echo Latency:         P50 20.6us, P99 30.5us, P99.9 38.7us
quicz DATAGRAM:            228.01 MB/s, 1200B payload
netz QUIC DATAGRAM:        297.06 MiB/s, 1200B payload, 16 MiB transfer
netz Stream Upload:        311.69 MiB/s mean, 3.1% stddev, 3 x 64 MiB
netz Multi-Stream (4x):    314.68 MiB/s mean, 0.6% stddev, 3 x 64 MiB
quicz Handshake:           P50 563.4us, P99 775.3us, 1131.3 conn/s
netz Handshake verified:   P50 1172.1us, P99 1367.8us, 830.7 conn/s
netz Handshake skip-verify:P50 657.9-833.0us, P99 1327.7-9971.1us, median 881.9 conn/s
quicz Stream Open:         48.1-52.0M streams/s, 100k streams
netz Stream Open:          680.2-778.0M streams/s, 100k streams
quicz Aggregate (4 conn):  503.2-533.1 MB/s, 4 x 64 MiB
netz Aggregate (4 conn):   730.4-900.6 MiB/s, 4 x 64 MiB
quicz Loss (1/5%):         220.8-236.7 / 216.8-223.6 MB/s
netz Loss (1/5%):          255.2-289.3 / 287.0-314.3 MiB/s
quicz Loss +100us RTT:     98.7-105.0 / 95.9-98.4 MB/s
netz Loss +100us RTT:      121.1-131.2 / 116.4-127.6 MiB/s
```

The original handshake values are fresh same-host ReleaseFast runs. Latency uses 200
fresh real TLS 1.3 connections and rate uses 100. The netz mode pins X25519
and TLS_AES_128_GCM_SHA256, reuses one immutable deterministic P-256 long-term
identity, and reports P50/P99/P99.9 plus aggregate connections/s. Every sample
still creates and validates a fresh server CertificateVerify against a pinned
key, whereas the current quicz workload sets `skip_cert_verify = true`. Netz
also uses an executor worker around its blocking public accept/connect API.
Those security and scheduling differences make this a concrete optimization
baseline, not a performance-superiority verdict.
The netz benchmark now also accepts `--skip-server-verification`, which retains
the server's Certificate and fresh P-256 CertificateVerify signature but skips
the client verification exactly like the audited quicz configuration. Five
CPU-0 runs put netz p50 at 657.9-833.0 us and median rate at 881.9 conn/s; three
quicz runs put p50 at 800.3-811.9 us and median rate at 749.3 conn/s. The broad
netz p99/rate ranges show host scheduling noise, so the result closes the
verification-policy mismatch but does not support a universal handshake claim.

The echo rows use the same 1 KiB/5,000-round real-handshake workload. A fresh
CPU-0-pinned three-run comparison measured netz at P50 10.44-10.57 us, P99
15.22-15.53 us, and P99.9 31.89-47.02 us, versus quicz at P50 10.5-10.7 us,
P99 16.0-19.5 us, and P99.9 206.3-211.2 us. Netz is therefore effectively
tied at p50, faster at p99, and substantially stronger at p99.9. The measured
step came from retaining the first unresolved sent-packet index so cumulative
ACK and loss scans no longer grow with connection lifetime. A following
compaction step retires contiguous acknowledged metadata in 256-packet batches
while retaining interval validation for duplicate cumulative ACKs. A 50,000
round CPU-0 run kept 149 allocations/685,276 cumulative bytes and 560,036 peak
live bytes, ended at zero, and measured 10.659/15.583/18.106 us p50/p99/p99.9.

The stream-open rows are a CPU-0-pinned, same-shape reservation microbenchmark
after a real handshake. Netz returns the complete expected ID sequence with no
timed-loop allocation and is 13.1-16.2x faster in the captured runs. It does
not claim stream close/recycling or on-wire churn, neither of which the quicz
reference loop measures.

The aggregate rows include worker creation, four independent I/O contexts,
real handshakes, four 64 MiB uploads, and teardown. Netz verifies every one of
the 268,435,456 aggregate payload bytes before reporting and is 1.37-1.79x
faster even without normalizing MB/s versus MiB/s in its favor.

The loss rows use the same 4 MiB single-stream, seeded client-to-server drop
policy and optional 100 us RTT delay. Netz verifies full receiver completion
and is conservatively 1.08-1.45x faster across all four scenarios without unit
normalization. Its loss mode reports exact injected and transport-observed loss
and can wrap the full run in allocator telemetry.

The server's Version Negotiation hot path also avoids allocator churn from
unauthenticated UDP triggers. The packet codec exposes exact validated sizing
and caller-buffer encoding; the endpoint writes the common response into a
256-byte stack buffer and allocates exactly once only for unusually large
advertised version lists. The owning compatibility API now allocates the exact
result directly instead of growing an ArrayList and converting it to another
allocation. A failing-allocator UDP test proves the common two-version response
is sent and parsed without heap use, while wire-parity and short-buffer tests
cover the public direct encoder.
The full quic-go and s2n-quic transport matrices remain green after this
change, including QUIC v1/v2, forced Retry, flow control, resets, cancellation
retransmission, key update, migration, NAT rebinding, and peer close. Those
gates do not themselves send an unsupported-version trigger, so the dedicated
real-UDP Version Negotiation test remains the direct evidence for this path.
The server Initial receiver now separates the RFC 9000 minimum UDP-datagram
size from the first long-header packet's encoded Length. After validating the
complete 1200-byte datagram, it can pass a shorter Initial packet slice into
CRYPTO reassembly and discard an all-zero trailing invalid-packet suffix;
nonzero trailing bytes remain rejected, and every later standalone Initial
datagram still has to meet the 1200-byte minimum. This closes an observed tquic
wire-shape failure: its 294-byte Initial plus 906-byte zero suffix previously
entered a silent retry loop. Focused one- and two-packet tests cover strict,
validated-slice, reordered continuation, and nonzero-tail cases; the complete
tquic normal/Retry request and GOAWAY matrix now passes in both directions.
The integrated Retry response now follows the same model. Fixed-size address
validation tokens are encoded into caller storage, ODCID/RSCID binding is fed
to HMAC incrementally instead of materializing a concatenated binding, and the
RFC 9001 Retry integrity pseudo-packet is fed to GHASH in segments rather than
allocated. `retry_flow.issueInto` then writes the complete bounded Retry packet
into the handshake's stack buffer. The compatibility APIs retain ownership
semantics with one final exact allocation. RFC v1/v2 vectors, wire-parity and
failing-allocator tests cover the direct codec and validation paths; forced
Retry succeeds against both quic-go v1/v2 and s2n-quic. A CPU-0-aligned
100-connection handshake regression sample without Retry measured 472.770 us
p50 and 2,048.1 connections/s; it checks the shared handshake path but is not
a Retry-specific performance claim.
Server handshakes can additionally borrow a bounded, process-owned
`SharedReplayFilter`. Retry and NEW_TOKEN inputs are authenticated and checked
for lifetime, version, peer address, and applicable ODCID/RSCID bindings before
the filter atomically remembers the validated fingerprint. Consequently, of
concurrent attempts to reuse one valid token, at most one passes the local gate;
the others fail as invalid packets before TLS processing or a server flight.
The filter is caller-sized and supports snapshot export/restore, but it does not
claim distributed coordination, external durable storage, or external-peer
replay/expiry coverage.
The server's first 1-RTT application send also appends HANDSHAKE_DONE through a
16-frame stack-first view instead of allocating a temporary `Frame` array. The
caller frames remain first, preserving HTTP/3 application ordering; oversized
low-level batches retain an exact heap fallback. Direct fail-first tests cover
the common stack case and transactional fallback, while a real first-send test
now shows four required recovery/queue allocations rather than six with the
retired indexes or seven with the additional temporary frame array. Five
CPU-0, 100-connection, quicz-aligned
handshake samples measured 2,035.4-2,072.3 connections/s (2,060.7 mean, 0.65%
relative standard deviation) with p50 466.117-472.825 us. This is a regression
sample, not a new cross-stack ratio.
ACK piggybacking now uses the same 16-frame stack-first staging policy. This
covers HTTP/3's default eight-frame application packet plus its cumulative ACK
without the former ninth-frame heap fallback, and still allocates an exact
array for unusually large low-level batches. Fail-first tests cover both sides
of that threshold and preserve application-frame-before-ACK ordering. Five
CPU-0 5,000-round echo regressions measured p50 12.759-12.985 us, p99
16.989-21.891 us, and p99.9 25.249-34.553 us. These noisier samples are
recorded without replacing the earlier matched quicz comparison.
HTTP/3 packetization now uses that primitive automatically for the first
outbound application packet when a delayed ACK is pending and frame/MTU budgets
allow it. If the combined packet is too large or temporarily blocked, the
application packet follows its original path and the ACK remains scheduled.
When a client returns its final aggregate, streaming, reset, or push event, it
also makes a nonblocking ACK attempt so a short-lived peer can finish recovery
without requiring another application receive call. A 4-stream/1-MiB download
that timed out after the handshake ACK default changed to 2/25 ms completed
5/5 times after this lifecycle fix. The wide throughput range is treated only
as completion evidence. A successful Extended CONNECT response is not a
terminal stream event, so its WebSocket adapter now performs a separate bounded
ACK flush before transferring receive-loop ownership out of HTTP/3. The same
absolute handshake deadline covers any pacing wait. The 1200-byte-MTU
80-request/80-response-field regression failed consistently without this
handoff and completed in three consecutive focused runs after it.
PMTU probe construction now uses the connection's pre-sized plaintext scratch
for the canonical PING-plus-PADDING payload instead of allocating and freeing a
probe-sized temporary list on every search step. Recovery still takes stable
ownership before the socket write. A real UDP regression sends and retires one
probe, then re-arms the same size under an allocator that rejects all new
allocations; the second exact-size probe succeeds with stable scratch pointers.
The full 2,958-test Netz suite and both quic-go and s2n-quic transport matrices
remain green after the change.
QUIC PMTU handling now also detects path MTU black holes from ordinary
non-probe loss bursts instead of only explicit probe loss. The implementation
records the protected datagram size for each sent packet, clears black-hole
evidence only when an ACK validates a current-MTU-sized packet, collapses one
contiguous loss episode into one signal, falls back to the base 1200-byte QUIC
datagram size after the fourth distinct qualifying burst, and rearms probing
only after a 60-second cooldown. Completed searches separately re-arm a safe
reprobe after 600 seconds. When PMTU changes, the 1-RTT connection immediately
retunes congestion and pacing datagram-size assumptions so steady-state burst
and cwnd heuristics remain coherent with the new path size. Dedicated
PING/PADDING probes stay outside generic retransmission ownership; their sent
metadata retains an independent loss timer, so a lost lone probe is retried by
the PMTU search rather than accidentally resurfacing as an ordinary PTO packet.
QUIC 1-RTT automatic ECN marking is now path-scoped rather than a single
tracker-global latch. Ordinary convenience sends mark eligible application
packets `ECT(0)` while the current path is in testing/capable state, reset
back to testing on NAT rebinding or authenticated migration, and fall back to
`Not-ECT` only for the current path after pre-mutation plain-ACK or invalid
ACK_ECN evidence shows validation failure. Explicit `sendWithEcn*` calls keep
their caller-selected codepoint and do not participate in the automatic socket
fallback to `Not-ECT` on `EcnUnavailable`. Batch sends apply `ECT(0)` only
when every packet in the submitted batch is auto-ECN-eligible; if the runtime
must retry the automatic send as `Not-ECT`, the tracked sent-packet ECN
metadata is rewritten to match the on-wire retry. For source compatibility,
`SentPacketTracker.disableEcnValidation`, `SentPacketTracker.ecnDisabled()`,
and `SentPacketStats.ecn_validation_failed` remain as deprecated manual-latch
surfaces only; they no longer drive the new path-local automatic ECN state.
Focused regression coverage for this redesign lives under
`src/quic/one_rtt/tests/basic.zig`, `src/quic/one_rtt/tests/crypto_path.zig`,
and `src/quic/ecn.zig`.
The same sent-packet path epoch now isolates all migration-sensitive recovery
feedback, not only ECN and PMTU. ACK and loss processing still retires every
packet number and recovery payload across path changes, so reliable old-path
data remains eligible for retransmission on the new path. Separate current-path
summaries alone update RTT, congestion-window growth/reduction, bytes in flight,
PTO backoff, loss deadlines, and persistent-congestion detection. A delayed
old-path ACK therefore cannot seed the replacement path's RTT, grow its cwnd,
subtract its in-flight bytes, or clear its PTO backoff; old-path loss cannot
collapse the new cwnd. Full IP migration resets RTT with congestion, pacing,
PMTU, ECN, PTO, and persistent-congestion state, while port-only NAT rebinding
preserves RTT and still starts a fresh tuple-local recovery epoch. Deterministic
mixed-epoch tracker tests and connection tests cover old-only and mixed ACKs,
packet/time-threshold loss, persistent-congestion boundaries, PTO state, and
old reliable payload retransmission.
Stateless Reset generation now has the same caller-buffer boundary. The public
codec validates before modifying output, and the endpoint derives the token,
fills unpredictable bytes, caps responses at 1200 bytes, requires a valid
short-header trigger, and always sends a packet shorter than the trigger from
fixed stack storage. A real UDP failing-allocator test verifies token matching,
the anti-amplification length rule, short-trigger suppression, and rejection of
invalid retired CIDs. This complements the existing receive-side rule that only
tests reset tokens after packet authentication fails. The quic-go and s2n-quic
transport matrices, plus the local application-close executable, remain green;
these are regression gates, while the socket-backed failing-allocator test is
the direct evidence for reset emission.

The old values share a host and aggregate transfer shape but not a controlled
CPU layout. A fresh CPU-0-pinned quicz run produced 15.97/16.12 MB/s because
both same-process endpoints contend for one CPU; a matching netz raw probe was
also scheduling-bound. The previous 1.36x/1.29x raw STREAM ratios are withdrawn
until both stacks use an equivalent endpoint CPU layout.

HTTP/3 is a separate evidence gap: quicz's benchmark calls raw
`sendOnStream`, while `bench-http3-handshake-transfer` includes DATA framing,
request/response/QPACK work, and response completion. No equal-wire quicz H3
benchmark currently exists, so the netz H3 numbers are reported as internal
progress rather than a direct superiority claim.

HTTP/3's post-handshake GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, and canonical
PRIORITY_UPDATE transmit paths now encode into fixed caller-owned arrays and
split them into a fixed stack frame array. This removes both transient
ArrayLists previously created for every such control message while preserving
stream offsets and transactional rollback on validation or send failure. The
public fixed-buffer encoders have wire-parity, maximum-varint, invalid-ID, and
state-rollback tests. A CPU-0-pinned cleartext regression run measured 9.878
us/request over 1,000 persistent requests; this is an internal regression
sample rather than an equal-wire quicz comparison. The bidirectional tquic
GOAWAY/Retry matrix and the quic-go v1/v2 request, cancellation, and 1xx matrix
remain green after the change. The audited quicz H3 layer has no RFC 9218
PRIORITY_UPDATE support.
The RFC 9218 complete-response scheduler now keeps each committed offset beside
its candidate metadata for up to sixteen concurrent responses in stack storage,
while a fixed transport-sized staging batch carries the originating response
index beside every packet chunk. Socket-visible prefix commits therefore need
no stream-ID rescan or hash lookup. Larger response sets allocate only one exact
candidate array and one temporary duplicate-ID set instead of separate offset,
candidate, chunk, and index storage. This removes four setup allocations from
the common 1-16 stream call and halves the large-set allocation sites without
changing scheduling order. Candidate refresh also accumulates the RFC 9218
winner in the same pass, eliminating the former second full candidate scan;
allocation-failure, allocation-count, duplicate-ID,
out-of-order-index, and partial-prefix tests cover both storage paths. A
three-iteration CPU-0, four-stream/16-MiB real-handshake download sample after
the change measured 54.75-55.19 MiB/s, with a 55.03 MiB/s mean and 0.37%
standard deviation. It remains an internal regression result rather than a
cross-stack throughput claim. A 17-stream heap-path run measured 53.97 MiB/s
before scan fusion and 54.04 MiB/s after it; this noise-level result is treated
only as a no-regression check. H3 now also reads connection flow, congestion,
and PMTU once per refresh and uses QUIC's narrow per-stream credit query inside
the loop; the same shape measured 54.23 MiB/s, again within noise. The full
2,958-test Netz suite and quic-go v1/v2 plus tquic normal/Retry/GOAWAY gates remain
green.
Handshake-backed request, response, streaming-head, and trailer sends now keep
one encoded-byte buffer and one borrowing STREAM-frame descriptor list per
session. The buffers are cleared only after QUIC has copied protected recovery
payloads, so subsequent streams reuse their capacity without extending caller
payload lifetimes. Dynamic HEADERS encoding also reserves the maximum frame
prefix inside the final output and closes that gap in place, eliminating the
former temporary QPACK block allocation. A fail-first warmed encoding test and
the three-exchange real-handshake dynamic-QPACK test verify output/frame
storage reuse and unchanged acknowledgement state. The quic-go v1/v2 and tquic
normal/Retry process matrices remain green. A CPU-0 1-MiB single-stream upload
regression ran five iterations at 110.23 MiB/s mean with 2.31% standard
deviation; this small transfer is a
regression sample rather than an equal-wire quicz result.
The lightweight preconfigured-key client and server now apply the same retained
message/frame scratch to complete request/response sequences, streaming heads,
and trailers. Their paced streaming writers also accept borrowed body-part
slices, avoiding caller-side concatenation while preserving one final FIN, and
can batch one DATA contribution per stream through one protected UDP batch while
committing only the socket-visible prefix. Request and response DATA, borrowed
body-part, batch, and trailer writers expose relative-timeout and absolute-deadline
variants. One awake-clock deadline is checked before every protected socket
batch; zero progress remains retryable, while `BodyWriteProgress` and batch
progress report the exact visible byte/chunk prefix so callers can resume only
the unsent suffix. A visible multi-packet prefix followed by failure keeps the
existing fail-closed protected-sender rule. Invalid-clock and already-expired
calls leave packet number, body offset/length/FIN, lifecycle, and pending QPACK
sections unchanged. End-to-end tests expire immediately after the first DATA
packet in both directions, resume the precise suffix, finish with bounded
trailers, and verify the peer receives the complete body and trailers exactly
once; a lower-level test crosses the maximum protected packet-batch boundary.
The lightweight server applies the
same RFC 9218 urgency/incremental selection to complete response bodies, using
the configured peer stream window as its sendability bound. Its multi-response
scheduler also exposes relative-timeout and absolute-deadline forms with one
socket-visible committed-byte counter per input response. The complete input
set is validated before sending; a deadline or socket error after a packet
prefix updates both the public counters and internal scheduling cursor before
returning, so callers can rebuild the next call from each exact suffix. A real
protected-wire priority test covers zero-progress timeout, transactional length
validation, first-packet expiry, suffix resumption, and complete peer-visible
responses in priority order. Protected sends synchronously protect and submit the datagrams
before returning, so these borrowing descriptors have the same bounded lifetime;
Push remains separate because its promise and pushed-response encodings must be
live together. Three dynamic-QPACK exchanges assert stable backing pointers on
both endpoints, while streamed request/response tests reuse the same allocations
from HEADERS through trailers and through a flow-control-blocked trailer retry.
The full 2,958-test Netz suite, quic-zig QPACK gate, quic-go v1/v2 matrix, tquic
normal/Retry and GOAWAY matrix, and native wtransport matrix remain green. A
post-change CPU-0 cleartext regression measured 9.765 us/request over 1,000
persistent requests; a five-run 1-MiB real-handshake upload measured 107.40
MiB/s mean with 3.99% standard deviation. Both remain internal regression
samples rather than equal-wire quicz comparisons.
Protected SETTINGS and QPACK encoder/decoder critical-stream sends now retain
their construction bytes and borrowing STREAM descriptors inside the existing
protected send state. The same state also routes one-datagram sends through the
exact-sized batch-into API, eliminating the frame-payload and protected-packet
allocations that the former single-packet convenience path still performed. A
fail-first test proves SETTINGS state/offset rollback, then switches both the
HTTP/3 sender and UDP endpoint to an allocator that rejects allocation and
successfully sends warmed SETTINGS, encoder instructions, decoder feedback, and
a single packet without moving any scratch allocation. The 2,958-test Netz suite,
quic-zig QPACK gate, quic-go v1/v2 matrix, tquic normal/Retry/GOAWAY matrix, and
native wtransport matrix remain green. Five CPU-0 cleartext samples measured
9.554-9.710 us/request (9.647 us mean, 0.71% standard deviation), again an
internal regression sample rather than an equal-wire comparison.
Protected DATA chunks now use the same split-prefix strategy as the
handshake-backed batch sender: the small HTTP/3 DATA prefix and first fragment
live in session-owned fixed storage, remaining STREAM frames borrow the caller
body only for the synchronous send, and the existing body frame list is reused.
The retained full-payload list remains only as a fallback for empty/oversized
prefix edge cases. Tests exercise both endpoints across multiple chunks, prove
that the common path never allocates the full DATA payload, and retry a
flow-control-blocked final chunk under an allocator that rejects every new
allocation while checking stream offset, byte-count, FIN, packet-number, and
scratch-pointer stability. The full 2,958-test Netz suite plus quic-go v1/v2, tquic
normal/Retry/GOAWAY, and native wtransport gates remain green. Five CPU-0
cleartext samples measured 9.569-9.674 us/request (9.645 us mean, 0.40% standard
deviation). A six-iteration real-handshake 1-MiB upload regression measured
108.65 MiB/s mean with 4.06% standard deviation; these remain internal samples.
Server Push now owns a separate reusable pair of encoded buffers plus one frame
descriptor list in both handshake and protected server sessions. Two buffers
remain necessary because the parent PUSH_PROMISE/response and pushed response
heads must coexist until their borrowing STREAM descriptors have been copied
into transport-owned packet/recovery storage. The `sendResponseWithPushPaced*`
family keeps DATA and trailers out of that head batch and advances the pushed
stream first, followed by any parent body, in bounded contributions. This keeps
a large parent from starving the advertised push and lets a 64 KiB pushed
response complete through 16 KiB
connection and unidirectional-stream windows as the client consumes data and
returns credit. Its authenticated implementation checks `CANCEL_PUSH` and
`STOP_SENDING` between chunks, sends the required RESET_STREAM, releases local
stream/body state, and returns `RequestCancelled` without closing the
connection. The client records cancelled push-stream ordinals compactly and
credits/discards already in-flight bytes instead of recreating a bounded push
reader after STOP_SENDING. One absolute deadline covers setup, heads, receive-side progress,
DATA, and trailers; non-cancellation failure after visible heads is fail-closed
because the aggregate API exposes no suffix cursor. The lightweight protected
variant retains the same bounded framing and marks its send state unusable if a
later aggregate step fails. A two-exchange protected test verifies the
parent, pushed, and frame backing pointers remain stable while stream and push
IDs advance. A fail-first full protected-send test forces the pushed-response
buffer to grow after the parent acquired dynamic QPACK references and verifies
pending sections, reference counts, encoder offset/prefix, and packet number all
roll back. The 2,958-test Netz suite plus quic-go v1/v2, tquic normal/Retry/GOAWAY,
and native wtransport matrices remain green. The unrelated cleartext benchmark
was noisy at 9.764-10.753 us/request across the five stable follow-up samples
(10.205 us mean, 4.17% standard deviation), so it is retained only as a
regression check and not evidence of a Push throughput change.
Handshake-backed SETTINGS and QPACK encoder/decoder sends now have their own
session-level payload and STREAM-descriptor scratch, independent of ordinary
messages and Push encodings that must remain live while encoder instructions
are sent first. SETTINGS encodes all three critical-stream prefixes before
forming any borrowing slice, so ArrayList growth cannot invalidate a previously
built frame. The dynamic-QPACK handshake test records stable critical-scratch
capacity and backing pointers across steady-state instruction/feedback rounds;
a direct connection test forces the initial SETTINGS allocation to fail and
verifies settings state, all critical stream offsets, prefix flags, and packet
number remain unchanged before a successful retry. The full 2,958-test Netz suite,
quic-zig QPACK gate, quic-go v1/v2 matrix, tquic normal/Retry/GOAWAY matrix, and
native wtransport matrix remain green. Five CPU-0 real-handshake 1-MiB upload
runs measured 104.96-109.62 MiB/s (108.17 MiB/s mean); this transfer-dominated
sample is a regression guard rather than a critical-stream speed claim.

The benchmark keeps UDP GSO/GRO disabled and defaults to one submitted packet
per userspace batch because this host clamps `net.core.rmem_max` to 212,992
bytes. Larger same-process loopback bursts overflow that kernel queue and
measure artificial packet-threshold recovery rather than protocol throughput;
`--batch-packets` remains available to test hosts with appropriately tuned
socket buffers. GSO/GRO performance stays covered by the dedicated QUIC batch
benchmarks.

HTTP/3 aggregate and incremental receive paths now preserve RFC 9114/9204
error scope after stream assembly as well as during packet routing. Malformed
QPACK field sections emit connection-level `QPACK_DECOMPRESSION_FAILED`;
the locally configured blocked-stream budget is enforced connection-wide after
each complete packet across buffered aggregate streams, active incremental
readers, and pushed responses. This permits encoder instructions later in the
same packet to unblock a section, while a first unresolved dependency at a
zero advertised budget closes the wire with `QPACK_DECOMPRESSION_FAILED`. The
budget comes directly from runtime configuration even before local SETTINGS
have been emitted.
invalid frame sequences retain their connection-level HTTP/3 close; malformed
request or response semantics terminate only the offending bidirectional
stream with `H3_MESSAGE_ERROR`, including QPACK Stream Cancellation and local
lifecycle cleanup where required. Real TLS-handshake tests assert peer-visible
close/reset codes and sibling reuse. A client request stream that reaches FIN
without an initial HEADERS section instead receives stream-local
`H3_REQUEST_INCOMPLETE`; a truncated HTTP/3 frame remains the distinct
connection-level `H3_FRAME_ERROR`. A response stream that reaches FIN without
a final HEADERS section is instead reset with stream-local `H3_MESSAGE_ERROR`,
and configured 1xx overflow uses stream-local `H3_EXCESSIVE_LOAD`; push streams
use the same scope and release any outstanding QPACK dependency. Aggregate
responses now decode and validate every PUSH_PROMISE request field section,
include its dynamic dependency in Section Acknowledgment accounting, and commit
promise IDs only after the complete final response validates. A later malformed
final response therefore emits one QPACK Stream Cancellation when required,
leaves no orphan promise, and preserves valid sibling responses and promises.
The detached Extended CONNECT head-only path applies the same promise field
decoding, ID validation, registration, and acknowledgment rules before handing
the stream to WebTransport or another protocol adapter. Aggregate request and
response delivery now copies ready reassembly state until fallible QPACK-feedback
preparation completes, then commits without further allocation. A zero-progress
feedback send failure no longer loses an already decoded message: delivery
succeeds, decoder instructions remain queued, and a later control pump retries
them. Incremental request, response, and pushed-response readers reserve their
acknowledgment capacity before advancing a field-section, while terminal request
completion is allocation-free; both use the same queued-feedback rule after
commit. The
cleartext development aggregate server likewise preallocates final message bytes
and retained-datagram ownership before removing a ready reassembly entry.
Client request completion uses the monotonic shared HTTP/WebTransport
bidirectional stream-ID allocation frontier plus the bounded outstanding-request
index, instead of retaining one hash-table tombstone per completed request.
Completion and response-reset dequeue therefore require no lifecycle allocation,
while allocated extension IDs remain distinguishable from future unsolicited
response IDs. Pending push cancellations remain queued until STOP_SENDING is
successfully submitted, so transient local failures do not silently consume
that signal.
Detached Extended CONNECT head polling also consults the QUIC final size: a
complete stream without final response HEADERS fails with stream-local
`H3_MESSAGE_ERROR`, while an actually truncated HTTP/3 frame remains a
connection-level `H3_FRAME_ERROR` instead of polling forever.
HTTP/2 CONNECT tunnels now model local and remote half-close independently.
DATA `END_STREAM`, explicit `closeWrite`, and multi-slice `TunnelWriter` sends
close only the local direction; peer `END_STREAM` closes only the receive
direction; and the parent connection releases stream concurrency and flow
windows exactly once after both halves finish. RST still terminates both sides
immediately. A real h2c regression holds `SETTINGS_MAX_CONCURRENT_STREAMS` at
one, proves a half-closed tunnel continues consuming that slot, then reuses the
same parent connection after the opposite half closes.

## Feature parity table

The persistent shared-socket aggregate now exercises both sender roles through
one server UDP owner. Server-originated transfers reserve unidirectional streams
without reading the socket and resume every prelude, payload, FIN, and control
send after pacing, congestion, or flow-control backpressure. Five verified
16-connection, 16-MiB runs per direction completed at 71.458 MiB/s median for
the client sender and 84.688 MiB/s for the server sender; their ranges overlap,
so this closes the bidirectional coverage gap without claiming a directional
speed advantage. HTTP/3 handshake sessions now also accept authenticated
`ReceivedPacketView` values directly, so a caller-buffer shared dispatcher can
apply request frames without first allocating an owning packet. The owning
compatibility entry point delegates to the same implementation. The built-in
HTTP/3 endpoint now exposes `receiveManyOnce`, which performs bounded UDP batch
receive, applies borrowed packets within the caller-buffer lifetime, retains
additional request events in session state, and returns only stable application
or lifecycle events. Existing single-event receive APIs remain compatible.

The sent-packet optimistic-ACK guard now has a validation-only ordered fast
path: it streams the peer's ranges and proves exact coverage using binary
packet boundaries plus retired-prefix intersections, while unsorted metadata
keeps the conservative full precheck. Nine fixed-binary CPU-0 pairs reduced a
4,096-packet cumulative-ACK check from 3,142 to 25 ns/op median (125.7x), with
allocation-failure, generated-hole, retired-prefix, overflow, and unsorted
fallback tests. The later mutation pass remains authoritative for ECN, path,
RTT, congestion, and newly-ACKed summaries. Fresh 1-MiB real-handshake gates
also verified every byte under 24/120 reordered datagrams and 6/126 seeded
drops. This is an internal validation result, not evidence of general or
equal-wire superiority over quicz.

| Area from `~/Work/quicz` examples | netz status | Evidence | Remaining work |
| --- | --- | --- | --- |
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered with local and cross-process latency evidence plus an equal-CPU-layout quic-go throughput harness | `examples/quic_echo.zig`, `examples/bench_quic_handshake_stream.zig`, `bench-quic-quic-go`, and `bench-quic-persistent-external`; CPU-0-pinned local netz P50/P99/P99.9 echo ranges were 10.44-10.57 / 15.22-15.53 / 31.89-47.02 us versus quicz 10.5-10.7 / 16.0-19.5 / 206.3-211.2 us. The certificate-verified two-process persistent 1-KiB echo keeps one request outstanding: five final-schema runs gave netz-client median P50 24.172 us versus quic-go-client 25.851 us against a fixed quic-go server (1.069x), and 23.729 versus 24.361 us against a fixed netz server (1.027x). The fresh-connection throughput harness pins client/server separately, runs both sender roles, and requires exact FIN/bytes/checksum for 1 and 4 unidirectional streams. Complete-connection userspace socket accounting is also available. All external comparisons remain `same-application-shape`. | Socket-boundary evidence proves the current workloads are not equal-wire. Repeat with kernel/interface capture on a permitted host and equalize GRO, ACK/pacing, packetization, and application scheduling before a general STREAM ratio. |
| QUIC TLS 1.3 handshake latency/rate (`quic_bench_hs`) | Covered with authenticated and quicz-aligned modes | `examples/bench_quic_handshake_stream.zig`, `--mode=handshake`; verified samples sustained 824.1-830.7 conn/s with P50 1172.1 us. `--skip-server-verification` retains Certificate/signing while matching quicz client policy; five CPU-0 runs measured P50 657.9-833.0 us and median 881.9 conn/s versus three quicz runs at P50 800.3-811.9 us and median 749.3 conn/s. Exact Initial sizing cut allocator calls from 167.0 to 92.0 per connection. Direct client/server and caller-supplied datagram-source paths expose relative-timeout and absolute-deadline variants; server variants also cover a pre-received Initial. One awake-clock timestamp covers Initial, fragmented Initial CRYPTO, Retry, Version Negotiation or optional standalone 0-RTT, and all active/passive TLS flights while retaining an earlier configured recovery deadline. Before address validation, server Initial/Handshake flights, PTO retransmissions, and protocol-error closes share an exact full-datagram 3x receive budget; valid Retry/NEW_TOKEN or an authenticated client Handshake packet removes that limit. A silent-client regression starts with one 1200-byte tokenless Initial and proves multiple PTO attempts never emit more than 3600 bytes. Every protected 0-RTT attempt consumes its one-shot ticket and packet number even if the UDP socket reports zero progress. Successfully transmitted PTO copies are imported into the shared application-data packet-number space after acceptance, share one recovery payload group, and can be acknowledged independently; rejected or pre-Retry 0-RTT still advances the first 1-RTT packet number without retaining stream/flow state or becoming ACK-valid. The typed HTTP/3 early-request helper emits SETTINGS plus both QPACK critical-stream prefixes with one complete literal/static-QPACK request, explicitly reports accepted versus rejected so replay remains an application decision, restores request response semantics and stream cursors after acceptance, routes server-side preloaded early streams before blocking reads, and rejects reduced remembered HTTP/3 SETTINGS. Real-handshake loss tests require the first 1-RTT packet to follow the dynamically observed 0-RTT copy count. | Equalize worker scheduling and reduce p99 variance before a whole-surface handshake claim. |
| QUIC stream-open churn (`quic_bench_hs`) | Covered and faster for the reference reservation workload; on-wire peer-stream renewal and mixed FIN/reset churn are verified under clean, bidirectional-loss, and bidirectional-reorder schedules | `examples/bench_quic_handshake_stream.zig`, `--mode=stream-churn`; CPU-0-pinned netz sustained 680.2-778.0M streams/s versus quicz 48.1-52.0M streams/s, a 13.1-16.2x range. IDs, limit enforcement, both endpoint roles, zero timed-loop allocation, final ID and checksum are validated. `openStreamWith{Timeout,Deadline}` and the unidirectional counterparts wait for authenticated cumulative MAX_STREAMS while pumping packets and QUIC timers under one absolute awake-clock deadline; timeout and invalid-clock rejection leave the next ID untouched. The original open APIs remain immediate and return `StreamLimitExceeded`. `Connection.pollOpenStream`/`pollOpenUnidirectionalStream` and the handle-based dispatcher counterparts instead reserve only already-available credit: they never read the UDP socket, wait, emit STREAMS_BLOCKED, or advance a blocked cursor, and dispatcher calls refresh the centralized timer even on close errors. Tests route authenticated bidi and uni MAX_STREAMS through the sole dispatcher receive owner before polling succeeds. `--mode=lifecycle-churn` keeps a bounded concurrent credit set, alternates one-byte FIN/echo and RESET_STREAM with exact codes, and requires cumulative MAX_STREAMS before reusing each batch. Its two-endpoint receive wait uses the earliest timer from either connection and no fixed polling quantum. A 128-stream/16-credit smoke verified clean, seeded 5% loss in both directions (14/276 and 16/284 injected drops), and every-fifth-datagram bidirectional reordering (45/228 and 45/227 holds), including exact terminal counts, final stream ID, checksum, and injection counts. The production batch-release API emits one cumulative MAX_STREAMS packet for up to 64 completed streams instead of one packet each, but only after the local FIN or RESET_STREAM and preceding reliable stream data are acknowledged; an early application release request is retained and flushed by the ACK path. Released peer and local streams are removed from active send/receive maps, each stream-number space collapses sequential IDs into a watermark and sparse closures into merged ranges, late frames cannot recreate upper-protocol state, failed automatic credit sends retry from the aggregate connection timer, and ID-based pagination remains stable across swap removal. The quic-go process gate separately advertises one bidirectional stream and requires completed streams 0, 4, 8, and 12. | Add an equal quicz on-wire lifecycle harness before claiming a cross-stack throughput ratio. |
| QUIC concurrent aggregate (`quic_bench_hs`) | Covered for four independent connections, including an external quic-go process matrix and a shared-socket event loop | `examples/bench_quic_handshake_stream.zig`, `--mode=aggregate --connections=4 --transfer-bytes=67108864`, and `bench-quic-persistent-external --mode=aggregate`; the internal netz run completed at 730.35-900.57 MiB/s versus quicz 503.23-533.10 MB/s. The external five-run 4 x 1-MiB matrix pins client/server processes to separate CPUs, starts every connection through one GO barrier, and validates 40 client results plus 40 server completions. With a fixed quic-go peer, final-schema runs measured netz senders at 152.580 and 149.825 MiB/s medians versus quic-go's 111.179 and 112.307 MiB/s (1.372x/1.334x). The original netz/netz control fell to 73.333/66.736 MiB/s in the other two fixed-endpoint comparisons, exposing same-process single-CPU worker contention rather than supporting a universal claim. A production shared-server topology now routes up to sixteen benchmark connections over one UDP socket. Its caller-buffer visitor avoids owning receive allocations for warmed current-key packets and applies ACK policy inside the server adapter. A Quinn-style bounded ready-message drain (32-message default) additionally amortizes wait/poll and dispatcher scheduling while preserving Initial-admission and callback-error suffixes in an owning FIFO. The strict result schema records the batch size. A same-binary five-sample 4 x 1-MiB comparison improved median throughput from 70.990 to 86.325 MiB/s (21.6%); ranges were 66.467-80.259 and 51.544-97.483 MiB/s, so host scheduling noise is explicitly retained. Batch-32 smokes reached 92.107 MiB/s for eight connections and 78.435 MiB/s for sixteen, with exact bytes/checksum/completion in every run. Local CID pools additionally expose a transactional active-set revision, letting ordinary packets skip the full router reconciliation; a four-CID ReleaseFast ABBA microbenchmark reduced that call from 627-637 to 9 ns (66.01-66.92x). Connections with a handshake-coalesced application datagram now notify a stable dispatcher-owned ready index instead of forcing every receive turn to scan the whole connection table. The callback remains valid across dispatcher and connection moves and is removed before unregister/deinit. Three CPU-0 fixed-binary runs reduced an empty 1,024-connection lookup from 4848.59 ns median to 0.76 ns (about 6,380x); this is an isolated scheduler result, not a whole-transfer throughput claim. Bounded `Connection.sendWith{Timeout,Deadline}` now handles flow/congestion backpressure through the state-only receive path, so reliable credit packets are ACKed and unrelated application data stays buffered. Receive reassembly measures its bound from the application cursor rather than retained consumed storage, and recovery groups with no in-flight copies expose a stable immediate PTO. A pre-fix 16 x 9-MiB shared upload completed only 15/16 connections and left the last at 8,387,712 bytes; three post-fix upload/download runs all completed 150,994,944 bytes with checksum 19,251,855,360. | Compare shared-socket event loops against an independently maintained peer with equivalent socket ownership and capture equal-wire traffic before generalizing the throughput result. |
| QUIC simulated loss (`quic_bench_hs`) | Covered and faster for all four reference scenarios | `examples/bench_quic_handshake_stream.zig`, `--mode=loss`; 1%/5% loopback and 1%/5% with 100 us RTT were conservatively 1.08-1.45x faster than quicz, with deterministic injected-drop counts, full 4 MiB receiver completion, transport loss counters and optional memory telemetry. | Add bidirectional loss, reordering and corruption cases before generalizing beyond the reference one-way loss model. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered and faster than current quicz DATAGRAM sample | `examples/quic_datagram_echo.zig`, `examples/bench_quic_datagram.zig`, `examples/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo`, `zig build bench-quic-datagram -Doptimize=ReleaseFast`. DATAGRAM packets remain ACK-eliciting and congestion-controlled but RFC 9221 payload bytes no longer enter the retransmission cache: pure-DATAGRAM PTO sends a fresh PING, and mixed packets retain only reliable frames. Explicit timeout/deadline send APIs wait for ACK credit without an unbounded queue; HTTP/3/WebTransport adapters preserve their packet routing while waiting. | Keep raw and WebTransport DATAGRAM benchmarks in the comparison matrix. |
| Graceful/application close (`graceful_close`, close lifecycle) | Covered by local tests/examples and exact bidirectional quic-go process checks | `examples/quic_close.zig`, one_rtt lifecycle tests, `zig build run-quic-close`, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; netz validates quic-go's peer application close code 57/reason `quic-go interop complete`, while quic-go validates netz code 58/reason `netz interop complete` | Add long-lived graceful shutdown/draining timing only if application shutdown workloads require it. |
| Packet protection / initial keys / key update | Covered by modules, tests, and quic-go process interop | `src/quic/protection.zig`, `src/quic/zero_rtt`, `src/quic/one_rtt/tests/basic.zig`, `src/quic/one_rtt/tests/crypto_path.zig`, `zig build test`, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; the external gate has netz initiate two ACK-gated 1-RTT key updates, verifies both local and peer update counters reach two and both phases return to zero, while quic-go decrypts and echoes one fresh stream in each generation. A connection-level test now sends and receives a FIN-terminated STREAM, advances Key Phase, and receives another STREAM for AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, ChaCha20-Poly1305/SHA-256, and SM4-GCM/SM3. Netz delegates next-secret derivation to Vail's suite-aware QUIC implementation, closing the former SM3 key-update initialization trap. Authenticated and preconfigured `EstablishedConnection` values retain and expose their negotiated cipher suite/hash and forward key-update control, local/peer counts, and the ACK gate without requiring callers to reach into the packet engine. | Keep vector and external coverage current as TLS suites evolve. |
| Loss recovery / PTO / retransmission | Partially covered and improved, with two-peer process evidence | Recovery tests cover timer-driven losses and bounded payload caching; recovery also validates then streams arbitrary ACK range counts without a decoded-range allocation, unlike the audited quicz allocating ACK decode. Ordered original-only recovery queues merge fragmented ACK ranges in O(packets+ranges), while retransmission and out-of-order cases retain the conservative membership scan; a fixed-binary 128-packet/64-range benchmark improved 2.69x with 7/7 paired wins. ACK_FREQUENCY capabilities are directional: only the endpoint that advertised `min_ack_delay` accepts the peer's requests, and only a peer advertisement enables local sends. New requests are transactionally rejected with PROTOCOL_VIOLATION when Requested Max Ack Delay is below that advertised minimum or at least 2^14 milliseconds; obsolete sequence numbers remain ignored, while zero Ack-Eliciting/Reordering Threshold values retain their specified meanings. Established 1-RTT connections optionally apply independently seeded, bounded PTO jitter (0–50%) using a stable per-arm epoch, so repeated scheduler reads cannot move an armed deadline; zero remains deterministic and consumes no entropy, and the separate pre-establishment handshake retransmission timer is unchanged. Receive preflight uses packet-local path/stream shadows instead of cloning heap-backed path-validation state per packet. A one-STREAM packet now keeps the same transactional `RecvState.Preflight` checks but skips the unrelated multi-stream, connection-ID, and path-validation shadows; seven CPU-0 order-alternated pairs reduced the visitor median from 1328 to 1308 ns/packet (1.5%) and service from 1336 to 1298 ns/packet (2.8%), with every pair faster, while five padding pairs moved only from 1397 to 1395 ns/packet (0.1%, noise-level). `RecvState` also packs received-byte presence into capacity-retaining machine words instead of one bool byte per buffered byte. Against the preflight-fast baseline, five visitor pairs reduced the median from 1324 to 1166 ns/packet (11.9%) and seven service pairs from 1328 to 1172 ns/packet (11.7%), with every pair faster; the STREAM profile's `memset` share fell from about 11.5% to 0.22%. Ordered non-overlapping STREAM frames also skip bytewise duplicate scans, while retransmission overlap retains strict conflict accounting. Recovery payloads keep four direct power-of-two blocks per class and use payload-intrusive O(1) overflow lists under the existing 1 MiB cap, allowing a dominant 4-KiB class to absorb ACK bursts without per-block metadata. The recovery queue no longer maintains two hash indexes on every send and rebuilds them on every ACK; its hot ordered scans stay contiguous, monotonic packet-number insertion is O(1), and rare direct lookups scan the bounded in-flight queue. ACK compaction scans entries by pointer, recycles matches in place, and copies only survivors that move; a clean twenty-pair A/B measured +8.6% mean/+14.4% median. Clean single-range ACKs with no retransmission copies now binary-search the monotonic original-packet queue and recycle one selected slice, while multi-range ACKs use the linear merge; retransmission/unsorted cases preserve the scan fallback. Loss-timer queries reuse the cached latest ACK-eliciting packet when it is ordinary data and scan only when a PMTU probe owns that cache; the next five-pair CPU-0 A/B improved the same H3 workload another 7.5% mean/7.4% median and reduced timer self samples from 13.5% to 2.0%. ACK processing also compares monotonic acknowledged-ECT and validated ACK_ECN watermarks in O(1), preserving the result after packet-metadata compaction; the following captured five-pair A/B improved mean/median another 10.5%/13.7% and removed the prior 2.7% scan from the profile. Single-ACK packets now reuse their shape-bound transactional precheck summary during apply, avoiding a second metadata scan while multi-frame packets preserve independent validation; two clean order-balanced ten-pair sets measured +3.4% for both mean and median and reduced `precheckAckRanges` samples from 5.35% to 1.67%. Sent-packet metadata compaction now clears its best-effort exact index in O(1), rather than removing retired keys and rewriting every survivor; two clean twenty-pair sets measured +7.3% mean/+2.6% median and removed `refreshPacketIndexFrom` from the profile. Single-packet send preparation also folds wire length, recovery length, flight/ACK traits, HANDSHAKE_DONE detection, and largest-ACK observation into one frame pass; a clean twenty-pair A/B measured +10.6% mean and removed standalone `Frame.wireLen` from the top profile. The preceding five-pair steps improved it by 33.8% and 28.5%; 5% packet-loss runs remained throughput-neutral while recovering every byte. Thread-safe telemetry after the first step reduced median allocations 29.6%, exact 4-KiB allocations 49.6%, cumulative allocated bytes 22.0%, and peak live bytes 15.5%. The real-handshake raw STREAM gate reorders every fifth client datagram and verifies all 4 MiB; a corruption mode flips authenticated ciphertext in exactly 25/504 datagrams and recovers all data. The quic-go process gate independently drops four netz server datagrams during Initial flight and four after application STREAM data. Separate s2n-quic connections drop netz's first post-arm RESET_STREAM or STOP_SENDING datagram and require the exact cancellation code after recovery. | Add broader reordering/corruption distributions and long-run recovery benchmarks; aggressive non-default packet/body sizing still needs separate coverage. |
| Flow control / stream reset / STOP_SENDING | Covered by implementation, tests, and two external QUIC peers, including cancellation loss | `src/quic/flow_control.zig`, `src/quic/stream.zig`, one_rtt tests, `zig build interop-quic-quic-go -Doptimize=ReleaseFast`, `zig build interop-quic-s2n -Doptimize=ReleaseFast`, and `zig build interop-http3-quic-go -Doptimize=ReleaseFast`; the raw external clients send RESET_STREAM error 41, separately observe STOP_SENDING error 42 and return RESET_STREAM error 42, and prove a concurrent stream 4 remains usable. Both external matrices transfer/echo 12 KiB through advertised 8 KiB connection and 2 KiB stream windows; the s2n-quic case also requires netz to observe actual flow-control blocking before credit advances. Receive-side connection `MAX_DATA` accounting follows RFC 9000's sum of each stream's highest received offset: sparse STREAM gaps consume credit, lower-offset gap fills and retransmissions do not consume it again, and RESET_STREAM charges only the remaining distance to its final size. Encrypted-packet regressions cover the single-STREAM fast path, mixed STREAM/RESET multi-frame preflight and rollback, and reordered data after reset. This closes a sparse-offset credit bypass still present in the audited quicz implementation, which counts newly stored payload bytes. `one_rtt.Connection.pollStream` exposes allocation-free, socket-free data/FIN/reset events for dispatcher loops, returns receive credit as bytes are copied, reports zero-length FIN plus RESET_STREAM exactly once, and rotates across ready streams so one busy stream cannot starve its siblings. `pollStreamId` provides targeted access without disturbing that fair cursor. An opt-in `enable_reset_partial_delivery` policy now drains the contiguous prefix buffered when RESET_STREAM arrives, including across small caller buffers and targeted polling, before reporting the reset exactly once. Later reordered STREAM data remains transport validation state and is never delivered after that reset boundary. The default remains reset-first and retains unread transport bytes only for reordered/duplicate validation. Handshake-created connections propagate the same policy. Matching blocking, relative-timeout, and absolute-deadline receive methods use the timer-aware packet service loop and retain partial stream state across timeout. Two additional s2n-quic client connections use netz's stable UDP send interceptor to drop exactly the first datagram after RESET_STREAM(41) or STOP_SENDING(42), then require the peer-visible exact code after recovery and sibling completion. The quic-go matrix additionally advances from stream 0 through 12 under an initial one-stream limit. The HTTP/3 gate drops the first H3_REQUEST_CANCELLED STOP_SENDING in each direction and requires retransmission, exact sender observation, and completion of a concurrent sibling under fixed flow-control windows. | Extend cancellation-loss coverage to reordered cancellation and longer mixed FIN/reset churn. |
| Connection IDs / stateless reset / path validation / migration | Covered in modules/tests with external active-migration and NAT-rebinding gates | `src/quic/connection_id.zig`, `src/quic/stateless_reset.zig`, `src/quic/path_validation.zig`, lifecycle tests, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; on accepted peer tuples, every ordinary owning, borrowed/timer-aware, batch, and routed 1-RTT receive path checks active peer reset tokens only after authentication fails, enters draining for three current PTOs, and excludes matching resets from the AEAD integrity counter. RFC 9000's endpoint-role asymmetry is enforced before decryption: clients silently discard unknown server tuples; servers retain authenticated client NAT rebinding/migration unless their own advertised `disable_active_migration` policy chooses RFC 9000's drop behavior for new client IPs. The peer's parameter remains distinct and only constrains local active migration. These drops do not change packet-number, stream, key-update, path, AEAD-failure, or telemetry state. CID routing itself no longer treats unauthenticated source addresses as connection errors, and the dispatcher consumes both established-path policy drops and pending-handshake peer mismatches. The shared server now offers an explicit endpoint reset key; when enabled it derives the handshake transport-parameter token and every local CID token from that same key, rejects conflicting raw/typed configuration and manual mismatched tokens, and consumes unknown fixed-bit short packets after sending an allocation-free reset. Responses are strictly shorter than their trigger, require the endpoint's minimum plausible 1-RTT length, and share Quinn's default 20 ms endpoint-wide minimum interval across source addresses. The default remains disabled. Owning, visitor, and batch receive tests cover the same policy, and a real two-client authenticated handshake verifies peer-visible initial tokens plus derived-token CID rotation. Pending PATH_RESPONSE state is capped per connection (default 8, matching tquic's receive-side challenge cap): excess unique PATH_CHALLENGEs are ignored without rejecting the authenticated packet, FIFO/index/target-address storage stays aligned, and a dropped counter exposes sustained pressure. During preferred-address validation the selected preferred tuple and retained prior validated tuple remain usable, but a third tuple is still discarded. The integrated client handshake registers the server's initial-CID transport-parameter token, while an unnegotiated initial CID no longer treats its zero-filled storage as a token. Netz issues three additional CIDs, and quic-go migrates one connection from `127.0.0.1` through `127.0.0.2` to `127.0.0.3` on distinct source ports. Both candidate paths reject `Path.Switch` before validation, complete PATH_CHALLENGE/PATH_RESPONSE probing, switch, and carry streams 4 and 8. A second run drops the first PATH_RESPONSE on each candidate path, then requires netz's blocking receive timer to retransmit both PATH_CHALLENGEs before the same two migrations and echoes can finish. A separate connection swaps its UDP socket to a new `127.0.0.1` source port without `AddPath`, drops four post-rebinding datagrams, recovers the stream by PTO, and proves netz selected the new tuple while keeping it validated and queuing no path challenge. | Extend the verified two-hop shape to longer path-churn runs before generalizing beyond loopback. |
| Latency spin bit | Covered as an opt-in direct and authenticated-handshake policy | `OneRttConfig.enable_spin_bit` reaches established connections while retaining the disabled default and independently suppressing one in sixteen handshake connections. The value and highest authenticated packet number are tracked separately for the current, retained validated, and bounded candidate paths. Reordered lower packet numbers cannot roll the signal backward; NAT rebinding and migration select the new path's state, failed validation restores the retained path's state, and changing the destination connection ID resets the selected path to zero. Real UDP tests inspect protected short-header bits after a handshake, reordering, manual CID selection, automatic `retire_prior_to` replacement, candidate traffic, NAT rebinding, and failed migration. | Keep passive-observation comparisons scoped to controlled paths; the spin signal is intentionally absent from the randomized disabled sample. |
| Retry/token/address validation | Covered by implementation, local replay tests, and certificate-verified quic-go and s2n-quic process gates | `src/quic/retry_flow.zig`, `src/quic/address_validation_token.zig`, handshake/retry tests, `zig build interop-quic-quic-go -Doptimize=ReleaseFast`, and `zig build interop-quic-s2n -Doptimize=ReleaseFast`; a caller-sized `SharedReplayFilter` provides atomic, bounded process-local duplicate rejection after token authentication and binding checks for integrated Retry and NEW_TOKEN validation. Both independent servers force source-address validation, while netz verifies and follows the valid Retry, authenticates the server, completes two streams, and validates peer application close on the retried connection. The external gates do not exercise replay or expiry. | Add replay/expiry probes against an external peer before generalizing beyond a valid Retry exchange; use coordinated external state when replay protection must span processes or hosts. |
| Congestion control (NewReno/CUBIC/HyStart++) | Covered and defaulted to CUBIC for 1-RTT | `src/quic/congestion.zig`, `src/quic/hystart.zig`, congestion tests; ACK processing samples utilization before removing bytes in flight, suppresses NewReno/CUBIC growth while app-limited, and excludes idle time from the CUBIC epoch. Negotiated idle timeout is clamped to RFC 9000's three-base-PTO minimum using the live RTT estimator and peer ACK delay | Keep comparing long-lived congestion traces under equal loss/RTT schedules. |
| UDP batching / GSO / GRO | Covered through timer-aware QUIC/HTTP/3 paths | Batch/GRO APIs plus `servicePacket` and synchronous `visitPacket` apply current-key datagrams in connection-owned receive storage with retained frame scratch; their timer-servicing forms also accept caller deadlines without allowing earlier PTO/ACK/keep-alive work to extend the application budget. Explicit one-RTT packet, batch, state-only, visitor, and stream receive deadline entry points validate an unexpired awake-clock timestamp before consulting any preloaded datagram or buffered stream bytes, so invalid deadlines are side-effect free; relative-timeout forms still normalize their caller budget once. Raw parsed, owned-byte, caller-buffer, and GRO-batch endpoint receive APIs now accept relative durations or absolute deadlines, with matching helpers on the lightweight QUIC server/client wrappers and type-erased handshake datagram source. Relative convenience forms convert once to an awake-clock deadline. Version-Negotiation filtering and CID-routed receive expose the same bounded forms and preserve one absolute budget across any unsupported-version datagrams they answer and discard. The shared-socket endpoint dispatcher also exposes an explicit awake-clock deadline receive, rejects incompatible clock domains before comparing them with transport timers, and lets an earlier PTO/ACK/idle timer wake the same bounded call without renewing the caller budget. HTTP/3's request and raw-transport endpoint callback loops refresh the selected connection timer after the application or protocol-adapter handler returns, so a response/control send cannot leave a new PTO absent from the shared scheduler. Its routed-packet adapter refreshes again after HTTP/3 parsing on both success and error, because ACK, QPACK, stream-error, or connection-close work occurs after the dispatcher initially processes the QUIC packet. Its buffered request poll adapter likewise refreshes after every session poll, including null and error results, so receive-credit, QPACK feedback, completed-stream retirement, protocol-error control frames, or a failed automatic MAX_STREAMS send cannot leave a new retry deadline visible only inside the connection. Handshake-backed HTTP/3 and WebTransport non-GRO pumps no longer create discarded owned packet diagnostics or per-packet UDP buffers, while GRO keeps a lazy owning suffix for one-packet application routing. The captured 16 MiB/four-stream H3 step reduced allocation calls another 47.8-48.1%. Both ordinary and batched stateful sends now encode ACK-eliciting frames directly into stable recovery storage and let AEAD read from that buffer, eliminating the former second full plaintext copy through packet scratch; ACK-only packets retain their reusable transient/in-place path. Unit coverage checks stable ownership, canonical bytes, emitted-wire decryption, and partial-batch rollback. Stateless batch results distinguish protected from socket-sent packets so callers advance beyond every consumed AEAD nonce while committing application state only for the visible prefix; quic-go and s2n-quic loss/retransmission gates remain green. | Keep H3 GRO opt-in on this small-rmem host and retest on tuned systems. |
| HTTP/3 request/response, Alt-Svc and RFC 9412 ORIGIN | Covered by bidirectional quic-go and tquic process interop plus verified public fetches against ByteDance, Cloudflare, and quiche deployments | `zig build interop-http3-quic-go -Doptimize=ReleaseFast` verifies certificate-checked POST headers, split body writes and trailers in both directions over QUIC v1 and forced RFC 9369 v2. In each direction and version the peers open the cancellation target and a sibling concurrently on one connection, negotiate fixed 8 KiB stream / 24 KiB connection receive windows, read 12 KiB from a declared 128 KiB response, deliberately drop the first H3_REQUEST_CANCELLED STOP_SENDING datagram, and require retransmission plus exact sender observation before releasing the sibling response. The sibling then completes with its body and trailers, and the quic-go client independently asserts one dial and at least two traced STOP_SENDING transmissions. The development client exposes timeout/deadline request and informational-response variants: the awake deadline is validated before stream commitment and rechecked before every UDP send and response receive (an individual UDP send syscall itself is not deadline-aware); because its response assembler is call-local, any post-send receive or parse failure makes that client fail closed rather than risking response/stream misassociation. The development server exposes timeout/deadline-bounded aggregate request receive under one unchanged awake-clock budget, retaining partial STREAM state for a later call, and one-call bounded `serveConcurrent`, with peer-aware request assembly, concurrent handler dispatch, serialized multi-datagram response writes, retained request metadata, and per-worker errors; a real two-client UDP test drives the complete public client/server path. The authenticated handshake server additionally exposes bounded `serveOne`/`serve`/`serveConnection` helpers: they retain full request ownership through the handler, use paced response-body/trailer sending, preserve a persistent connection across the configured request count, and finish with the two-phase GOAWAY sequence. Authenticated clients expose timeout/deadline-bounded per-stream, multiplexed whichever-ready, and server-push aggregate/streaming receive; authenticated servers expose the symmetric bounded aggregate and multiplexed streaming request receives. Authenticated clients can also be constructed on a caller-owned shared endpoint, accept dispatcher-routed packets through `processResponsePacket`, and nonblockingly drain per-stream, whichever-ready, and push events through `pollResponseEvent`, `pollNextResponseEvent`, and `pollPushEvent`. A two-origin one-socket regression routes interleaved responses by CID, verifies stream-zero state remains isolated per connection, then injects GOAWAY after the last response has finished to prove control progress does not require a dummy request or competing socket read. Detached Extended CONNECT progress pumps expose relative-timeout, absolute-deadline, and packet-injection forms in both directions, keeping protocol adapters on the same single-owner QUIC loop. In both directions, one absolute budget spans unrelated traffic, control/QPACK progress, GRO batches, and transport timers, while timeout leaves request/parser/decoder lifecycle state resumable rather than implicitly finishing or resetting the stream. Response writers and aggregate/incremental clients now retain request method context: HEAD advertises representation length without DATA, successful traditional CONNECT rejects HTTP body/trailer bytes and strips `Content-Length: 0`, while extended CONNECT retains DATA semantics. Clients also expose the peer GOAWAY ID and RFC 9114 retry classification: request streams at or above that ID are known unprocessed, while lower IDs remain potentially processed. Aggregate and head-only decoders expose ordered borrowed 1xx callbacks and enforce configurable limits; aggregate multiplexed reads attach the selected request-stream ID, aggregate pushed reads attach the push ID, parent request-stream ID, and push-stream ID, and servers can emit 1xx sequences on pushed responses. Authenticated and lightweight preconfigured-key per-stream, whichever-ready, and push aggregation expose callback-preserving timeout/deadline variants; one unchanged deadline covers all interim heads and the final response. Both clients retain incomplete response reassembly and partially consumed push head/body/trailer ownership so a later bounded aggregate call can resume after timeout, while rejecting mixed aggregate/incremental push consumption. The lightweight client also exposes socket-free per-stream, whichever-ready, and push polling plus timeout/deadline-bounded whichever-ready streaming response events, retaining active readers and partial frames across timeout; the lightweight server exposes matching socket-free request-event polling for externally owned loops and resumable timeout/deadline-bounded aggregate request receive. Lightweight request and response stream readers can also discard DATA without copying while returning receive-window credit. The lightweight client can explicitly await peer SETTINGS under one relative or absolute budget while retaining earlier response/push bytes, matching the authenticated capability-negotiation path. Incremental request and push streams enforce the same bound, and authenticated/lightweight push readers can discard DATA without a caller buffer while returning receive credit. This matches quic-go's bounded `Got1xxResponse` behavior while retaining a caller-configurable per-stream limit. RFC 9412 support adds server ORIGIN emission plus bounded, incrementally accumulated client Origin Sets, strict server-to-client direction checks, canonical scheme/host/default-port matching, empty-frame initialization, invalid-entry skipping, 421 removal hooks, and control frames split at every byte boundary. Authenticated server ORIGIN emission exposes relative-timeout and absolute-deadline variants; invalid-clock or expired calls leave packet number, control-stream offset, and the local advertisement marker unchanged, while one absolute budget covers SETTINGS and ORIGIN delivery. `pollControl` lets event loops consume authority updates without waiting for an application message, and all authenticated/lightweight client/server control pumps expose relative-timeout and absolute-deadline variants that preserve buffered application streams. Connection reuse queries deliberately remain certificate-agnostic and require the caller to perform authority validation. The audited local quicz, quic-go v0.59.0, and tquic H3 sources expose no ORIGIN frame implementation, so this feature currently has independent RFC wire vectors and a real protected-QUIC runtime exchange rather than a false external-peer claim. `zig build interop-http3-tquic -Doptimize=ReleaseFast` builds audited tquic `0169abde20c6`; the verified netz-client direction exercises GET, byte Range (206), and POST-body digest, then separately sends client GOAWAY while stream 0 is active, completes that accepted response, requires tquic's exact GOAWAY(0) acknowledgement, and rejects stream 4. The reverse direction verifies two ordinary requests, then separately requires tquic to observe netz's maximum-ID and final GOAWAY(4), finish accepted stream 0, and reject creation of stream 4. Every tquic scenario runs with and without forced Retry. `examples/http3_fetch.zig`, explicit status/body assertions, and Alt-Svc gates cover three independent public endpoints, including quiche on UDP/8443 | Keep live public-server coverage and add ORIGIN interop when an independently maintained peer exposes RFC 9412. |
| HTTP/3 real-handshake upload benchmark | Covered and reliable at the tested default, with a dual-role quic-go reference | `examples/bench_http3_handshake_transfer.zig`; CPU-0-pinned 4-stream 64 MiB upload completed 5/5 iterations at 141.78 MiB/s mean and 2.76% stddev with ACK threshold 4 and adaptive DATA sizing; exact-size cross-stream body batching is also available but opt-in on this small-rmem host. DATA framing emits the small HTTP/3 prefix separately and borrows the complete application body in the common case, including multi-stream workloads. Short-lived download sessions explicitly drain reliable QUIC recovery before teardown, with one absolute client deadline; a deterministic test drops the final DATA/FIN once and requires PTO recovery, exact bytes, FIN, and empty recovery. Five CPU-0 1 MiB download iterations completed at 105.87-126.36 MiB/s (120.41 MiB/s mean, 6.18% stddev). The latest matched 16 MiB/four-stream A/B combines intrusive bounded recovery reuse with ordered STREAM preflight fast paths and raised mean throughput from 114.11 to 152.69 MiB/s (33.8%), while all 25 iterations per side verified exact bytes/status. Thread-safe telemetry reduced median allocation calls 29.6%, and peak live bytes 15.5%. `zig build bench-http3-quic-go -Doptimize=ReleaseFast` adds certificate-verified, two-CPU, fresh-connection-per-sample upload and download in both netz/quic-go role pairings. Its 4 MiB samples validate status, headers, EOF, exact bytes, and checksum after an untimed ready request; the recorded sender ranges are netz 169.75-175.54 MiB/s upload and 169.03-176.47 MiB/s download, versus quic-go 45.25-124.16 MiB/s and 50.55-73.21 MiB/s. `bench-http3-quic-go-multistream` extends the same process matrix to 4 and 16 concurrent streams over QUIC v1/v2; each upload/download and role pairing verifies every stream plus aggregate bytes/checksum. The Go fixture now serves a CA-signed non-CA server leaf, matching production TLS server-auth policy instead of relying on a CA certificate as an endpoint identity. An opt-in process-memory run measured netz sender RSS at 9,772-9,984 KiB versus quic-go sender RSS at 22,528-23,296 KiB, and netz receiver RSS at 7,936-10,240 KiB versus quic-go receiver RSS at 19,712-19,968 KiB; runtime allocation counters remain separately scoped. This is explicitly same-application-shape because GSO/GRO, ACK policy, cipher reporting, and packetization are not fully equalized. Direct tests cover prefix ownership, offsets/FIN, exact-prefix limits, cache size classes/full budget, fast adjacent frames, overlap conflicts, fallback and allocation rollback. | Add capture-backed equal-wire accounting before making a cross-stack ratio; then reduce the remaining packet-protection and event-loop cost. |
| HTTP/3 real-handshake download and RFC 9218 response scheduling | Covered for current benchmark scale; feature coverage exceeds the local quicz H3 layer | `HandshakeServerSession.sendResponseBodiesPaced` schedules borrowed complete bodies by the request Priority field and live PRIORITY_UPDATE, serializes non-incremental responses by stream ID, round-robins incremental peers, bypasses flow-blocked urgent streams, and replans after socket-visible packet prefixes; real-handshake tests cover all four behaviors and the benchmark sends `Priority: u=3, i`. Retained request/push update state now has a configurable per-connection total bound, replacements remain valid at capacity, terminal request and cancelled-push state is retired, and server runtimes validate every update in a batched control fragment. Stateful server request completion also registers transport retirement, so aggregate and incremental FIN paths return MAX_STREAMS and reclaim copied request buffers after the response FIN/RESET is acknowledged; a one-stream-credit churn test advances through four request IDs without application release calls. Server push streams likewise register local uni retirement after send and peer uni retirement after FIN/reset consumption. Finished/cancelled push promises leave the active map and enter an exact compressed prefix+sparse-range history; RFC 9114 only recommends sequential Push IDs, so out-of-order IDs retain their holes rather than being collapsed unsafely. Request IDs must be client-initiated bidirectional IDs within the active QUIC receive limit; invalid IDs roll back the whole fragment and authenticated connections close with H3_ID_ERROR. `~/Work/quicz/src/h3` has no Priority field, PRIORITY_UPDATE, urgency, or incremental scheduler. The runtime now supports byte- or packet-cadence cooperative yielding; using a chunk-size-independent three-packet cadence raised five 64MiB/four-stream iterations from 11.35 MiB/s to a stable 44.15 MiB/s mean (3.47% stddev) while retaining full completion. After enabling borrowed DATA framing for multi-stream runs, a CPU-0 16 MiB/four-stream regression sample measured 45.72 MiB/s mean with 10.99% stddev. Packet construction now encodes ACK-eliciting frames directly into stable recovery allocations for both batch and ordinary sends, eliminating the previous encode-to-packet-buffer then full-payload copy into recovery; direct tests compare retained recovery bytes with canonical frame encoding and decrypt the emitted packets. The post-batch sample measured 49.37 MiB/s mean with 0.93% stddev, and the subsequent ordinary-path sample measured 49.91 MiB/s with 0.22% stddev. These are internal regression samples, not an equal-wire quicz comparison. | Continue apples-to-apples quicz throughput work before making a whole-stack performance claim; move same-process loopback pacing policy into a reusable event-loop benchmark harness. |
| QPACK / Capsule / HTTP Datagrams / WebTransport | Covered by modules, stateful runtime APIs, benchmarks, real-handshake streams, lifecycle controls, native wtransport interop, and a real Chrome browser gate | QPACK dynamic entries use indexed lookup, FIFO head eviction and one contiguous string allocation versus quicz reverse scans, front insertion and two string allocations. Field-section prefixes use RFC 9204 prefix integers rather than QUIC varints; boundary tests cross encoded Required Insert Count 63 and Delta Base 127, while `interop-http3-qpack-quic-zig` independently decodes a speculative section after 64 inserts. Dynamic sections choose Required Insert Count as their minimal Base, and the dependency prepass excludes dynamic name matches shadowed by the selected static representation, preventing phantom blocking and Section Acknowledgments. The decoder independently derives the highest actual dynamic reference across all four relative/post-Base field forms and rejects both under-reported mandatory dependencies and non-minimal over-reported counts. Request, response and trailer paths decode both literal and dynamic QPACK sections directly into one allocation containing the field descriptors and shared name/value bytes, rather than first allocating per Huffman/dynamic field and copying again. Offset plans remain valid across scratch growth, all four relative/post-Base representation families retain exact dependency validation, and allocation-failure plus exact allocation-count tests cover both owning decoders. Pinned 32-field dynamic decode samples measured 751-762 ns/block across four stable runs with one 835-ns outlier, versus the preceding 835-857 ns range. Settings-aware decoders enforce the uncompressed `name + value + 32` field-section budget before Huffman output allocation or dynamic-entry copying, including static, literal and all dynamic representations. Handshake-backed HTTP/3 clients and servers expose RFC 9297 DATAGRAM send, poll, timeout/deadline receive, exact payload-budget, and explicit close APIs for detached Extended CONNECT streams. A bounded per-association demultiplexer retains interleaved streams independently, drains accepted payloads before stable stream-terminal errors, drops unknown/closed associations, maps malformed Quarter Stream IDs to H3_DATAGRAM_ERROR, and requires both HTTP/3 SETTINGS and directional QUIC DATAGRAM negotiation. WebTransport uses the same demultiplexer so sessions cannot steal one another's DATAGRAMs; server acceptance reserves its association before status 200, while dispatcher-driven clients expose stable-storage promotion helpers instead of publishing moved-from connection pointers. Stateful WebTransport adapters advertise their implemented one-session-per-HTTP/3-connection capacity even if a larger setting is supplied. While that session remains active, additional request streams are rejected in both directions with `H3_REQUEST_REJECTED`; endpoint mode retains a paced rejection for retry, preserves the sole UDP receive owner, and continues routing first-session traffic from the same packet. Terminal cleanup scans peer-initiated QUIC receive state for complete same-session association prefixes before sending WT_SESSION_GONE, so streams buffered before registry admission cannot survive session close; incomplete, ordinary HTTP/3, local, and other-session streams remain untouched. Capsule fallback remains an explicit codec-level choice. WebTransport adds transactional cross-stream batches and modern 0x41 association. Its external wtransport gate drops a mapped STOP_SENDING while a sibling stream is live and requires transport recovery plus sibling completion. The Chrome gate independently covers browser CONNECT, DATAGRAM, bidi/uni streams, mapped reset/stop, sibling reuse, drain, and close. | Expand browser coverage beyond Chromium; native wtransport and Chrome do not cover Firefox or Safari behavior. |

Handshake-backed and lightweight protected HTTP/3 clients guard the
connection-scoped receive owner while aggregate informational callbacks run.
Recursive response, whichever-ready, push, control, and CONNECT-DATAGRAM reads
return the recoverable local `ConcurrentRead` error before consuming buffered
events, UDP, or QPACK state; this error is never mapped to an HTTP/3 connection
close. State-destructive request/push cancellation is rejected under the same
guard, while one-attempt send-only operations remain available. Real handshake,
protected two-response, and protected pushed-response regressions preserve the
outer aggregate and untouched sibling after rejected reentry.

The authenticated single-connection convenience server now applies its
configurable shutdown timeout as one absolute deadline after the final
response. Both GOAWAY phases and the subsequent reliable-send recovery drain
share that budget, so pacing cannot make `serveConnection` shutdown unbounded.
A deterministic pacing test verifies that timeout leaves the packet number,
control-stream offset, GOAWAY value, and shutdown phase unmodified.

Public HTTP/3 coverage now also includes `cloudflare-quic.com`: a
certificate-verified HEAD returned 200, and the executable's new
`--expect-status=200 --min-body-bytes=100000` gate accepted a 125,959-byte GET.
That deployment sends a cross-signed GTS Root R4 while this host trusts the
self-signed form. The shared vail trust verifier now matches that anchor only
by exact Subject and complete SubjectPublicKeyInfo, while retaining hostname,
presented-chain signature, and terminal/anchor validity checks.
An independent request to the quiche-backed `quic.tech:8443` endpoint also
passed certificate verification, status 200, and a 462-byte response-body
check, covering explicit Alt-Svc routing to a non-default UDP port.
The optional `interop-http3-public` gate runs those checks together with a
verified Meta H3 request that requires its current 302 unsupported-browser
redirect. Each case has an outer timeout and any transport, trust, status, or
minimum-body mismatch fails the build step.
The default system/bundle verifier additionally enforces the RFC 5280 usage
subset needed by TLS server authentication: leaf digitalSignature and
serverAuth/anyExtendedKeyUsage when present, CA=true plus optional keyCertSign
on every presented intermediate, pathLen, and rejection of unsupported critical
extensions. Explicit public-key pins and custom trust callbacks remain
application-defined policy.

HTTP/3 high-level service handlers cannot accidentally leave a request stream
with only an informational response. Development `serveConcurrent` and
authenticated `serveOne` replace a handler-returned 100-199 response with a
bodyless final 500, finish the stream, and report `InvalidStatus` in the
corresponding call or result slot without failing healthy siblings. Explicit
`sendResponseWithInformational` sequences and `InformationalResponse` retain
their 1xx-before-final behavior.
Both authenticated and lightweight preconfigured-key HTTP/3 servers expose
timeout/deadline-bounded RFC 9412 ORIGIN emission. One unchanged awake-clock
deadline covers mandatory SETTINGS and the ORIGIN frame; expiry before ORIGIN
submission retains the settings progress but leaves the ORIGIN marker and
control-stream offset retryable. If a multi-batch protected send has already
made a prefix socket-visible, the lightweight sender becomes unusable instead
of allowing packet-number or stream-offset reuse.
Lightweight protected clients and servers likewise expose bounded GOAWAY, and
protected servers expose bounded initial/final graceful-shutdown phases. The
same deadline spans SETTINGS and GOAWAY; timeout cannot advance the local
GOAWAY ID or shutdown state before the matching control bytes are committed.
Authenticated and lightweight clients also expose bounded MAX_PUSH_ID and
CANCEL_PUSH sends. The latter reserves all fallible retirement state before
the control frame is visible; if its remaining STOP_SENDING work exceeds the
same absolute budget, it stays queued and a retry resumes cleanup without
emitting a duplicate CANCEL_PUSH.
On receive, servers accept cancellation only for a Push ID they actually
promised. An unpromised ID is rejected transactionally before it reaches the
retained cancellation set and produces an `H3_ID_ERROR` connection close.
Sent/promised Push IDs and received cancellation IDs use exact contiguous-prefix
plus sparse-range sets rather than duplicate arrays and hash tables. Sequential
IDs require no range allocation, membership is O(1) for the common prefix, and
control-stream rollback clones only the outstanding sparse ranges.
Incomplete control frames and complete unknown extensions avoid deep state
snapshots, while role-specific validation happens per complete frame before
mutation; this preserves SETTINGS-first and whole-chunk rollback semantics
without parsing or cloning the same control input twice.
Both client runtimes also provide timeout/deadline variants for request and
push PRIORITY_UPDATE. Validation precedes mutation, and one absolute deadline
spans critical-stream SETTINGS plus the priority frame without advancing the
packet number or control-stream cursor on zero-progress expiry.
Authenticated and lightweight servers also bound the complete server-push
operation: SETTINGS, any QPACK encoder instructions, the parent-stream
PUSH_PROMISE/final response, and the pushed response share one absolute
deadline. A phase-boundary timeout preserves valid critical-stream progress
but leaves push IDs, the next push-stream ID, request lifecycle, and pending
QPACK sections uncommitted for retry; a socket-visible partial message makes
the underlying connection unusable instead of permitting ambiguous replay.
Their explicit informational-response senders likewise expose timeout/deadline
variants spanning SETTINGS, QPACK instructions, every 1xx HEADERS block, and
the final response. Invalid deadlines leave the request lifecycle and all send
cursors untouched; partial socket-visible sequences retain the same fail-close
rule as other aggregate HTTP/3 messages.
The corresponding complete-response helpers on authenticated and lightweight
servers expose the same bounded contract without requiring callers to use the
informational API with an empty 1xx list.
Lightweight protected clients and servers now match the authenticated streaming
HEAD APIs with timeout/deadline variants. Invalid deadlines are rejected before
request-stream allocation or response-body registration, and a valid deadline
covers SETTINGS, QPACK instructions, and the request/response HEADERS send.
The lightweight aggregate request deadline now covers request transmission as
well as response receipt. If SETTINGS is committed before the budget expires,
the unsent request lifecycle and QPACK section are discarded while its QUIC
stream ID remains consumed, preventing later requests from reusing an
ambiguously exposed stream number.
The stateful HTTP/3 GRO receive cursor also validates an absolute deadline
before sending a deferred ACK or advancing a retained packet batch. Wrong-clock
and expired calls are therefore side-effect free, and a later valid call still
observes the original packet.

The external HTTP/3 throughput harness now runs 1, 4, or 16 concurrent
request streams in either direction and supports forced QUIC v2 through
`NETZ_HTTP3_INTEROP_VERSION=2`. The aggregate multi-stream gate covers both
v1 and v2 by default. Its Go and Zig endpoints select the requested version,
v2 uses the compatibility key-update profile required by the pinned quic-go
v0.59 peer, and every config/result/server-completion/memory record carries
`quic_version`. The strict checker rejects missing or mismatched versions, so
a v2 command cannot silently report a successful v1 measurement.
| TLS backend/process interop examples | Covered in both directions through standalone, certificate-verified quic-go and s2n-quic process gates | QUIC handshake tests, `examples/quic_handshake_echo.zig`, `zig build interop-quic-quic-go -Doptimize=ReleaseFast` (bidirectional/unidirectional streams, RESET_STREAM, STOP_SENDING, rolling limits, and Initial/application PTO recovery), `zig build interop-quic-s2n -Doptimize=ReleaseFast` (independent s2n-tls stack, ALPN, two streams with FIN, exact RESET_STREAM/STOP_SENDING exchanges and cancellation retransmission with a concurrent sibling, application close), HTTP/3 public fetch with `--verify` | Add broader public peers before making a full interoperability claim. |

Authenticated aggregate HTTP/3 deadlines now cover the complete operation
rather than only response receipt or the DATA phase. Client request admission,
SETTINGS/QPACK instructions, request HEADERS/body/trailers, paced server
response HEADERS/body/trailers, and response receive all reuse one absolute
awake-clock timestamp. The stateful packetizer rechecks it before every socket
attempt and bounds pacing waits. A zero-packet timeout leaves the connection
retryable; once a multi-packet logical send has exposed a prefix, a later
timeout retires the connection locally without risking an unbounded close send
or replaying bytes at the same stream offset. A real handshake regression
forces both request-HEADERS and response-HEADERS pacing timeouts, verifies zero
socket calls and unchanged packet numbers, then successfully reuses the
connection after pacing is released. A lower-level regression covers the
partial-visible fail-closed branch. Authenticated incremental
`startRequestWith{Timeout,Deadline}` and
`startResponseWith{Timeout,Deadline}` now bound stream admission, SETTINGS,
QPACK instructions, HEADERS packetization, pacing, and flow-control progress
under one absolute deadline; invalid deadlines leave request IDs, packet
numbers, and lifecycle state untouched. Their zero-copy borrowed
body-parts writers now have matching timeout/deadline forms on authenticated
clients and servers. They validate the complete logical length before sending,
retain slice boundaries without joining, and report exact socket-visible bytes
plus FIN state so callers can resume from the remaining suffix. A real TLS/QUIC
test forces a three-byte cross-slice prefix to commit before timeout in each
direction, resumes the remainder, and verifies one exact request and response.
Authenticated servers likewise expose timeout/deadline variants for waiting
on peer response cancellation. One absolute budget covers routed packets and
transport timers; after STOP_SENDING is observed, stream retirement is
registered for timer-driven retry instead of delaying cancellation delivery on
a paced MAX_STREAMS update.
Authenticated GOAWAY emission and both phases of graceful server shutdown also
have timeout/deadline variants. SETTINGS setup and the GOAWAY control frame
share one absolute budget, and a failed pre-send attempt rolls back the GOAWAY
identifier, control-stream offset, and shutdown phase for an exact retry.
Streaming request and response trailer writers now expose the same timeout and
deadline forms: invalid or pre-send pacing deadlines retain QPACK/body state
and packet numbers for retry, while a visible multi-packet prefix remains
fail-closed because a field section cannot be safely replayed.

The native wtransport interop now also exposes a two-CPU cross-process
`bench-webtransport-wtransport` gate. It runs both implementation-role
directions for deterministic stream uploads and one-outstanding DATAGRAM
ping-pong with CONFIG/GO/DONE boundaries, byte/checksum/FIN validation, warmup,
and stable machine-readable results. It is deliberately reported as
same-application-shape rather than equal-wire: the two peers currently expose
different effective WebTransport DATAGRAM payload limits. Userspace UDP
accounting below proves the stream shapes differ; kernel/interface capture is
still needed before any equivalent-packetization claim.
Its opt-in process-memory matrix covers stream upload and DATAGRAM ping-pong in
both role directions. Three default-shape runs measured stream RSS at 10,240
KiB for the netz client versus 11,264-11,312 KiB for the wtransport client,
and 4,352 KiB for the netz server versus 6,144-6,400 KiB for the wtransport
server. DATAGRAM RSS was 3,840 KiB for both netz roles, 6,144-6,400 KiB for
the wtransport client, and 5,888-6,144 KiB for its server. Netz explicit
allocation records ended at zero live bytes; Rust system-requested counters
remain separately scoped diagnostics. A strict verifier independently derives
the expected bytes/checksum and requires distinct result, server-completion,
and memory records.
A separate `--traffic` pass joins both endpoints' userspace UDP payload bytes
and logical datagram counts for the complete persistent connection. Three
stream runs measured 112.094-112.114 MB / 180,705-180,728 datagrams for
wtransport-client + netz-server, versus 108.990-109.108 MB /
115,105-117,800 datagrams for netz-client + wtransport-server. The 32-byte
DATAGRAM shapes were closer at 920.825-920.836 KB / 18,227 datagrams and
920.357-920.359 KB / 18,229 datagrams. This proves the stream workloads are
not equal-wire and keeps the comparison scoped accordingly; Quinn connection
stats and netz socket counters still do not replace permitted-host kernel or
interface capture.

The RFC 9220 quic-go peer likewise exposes
`bench-websocket-h3-quic-go`. It runs a certificate-verified persistent binary
echo in both implementation-role pairings on separate CPUs, excludes handshake
and warmup from timing, varies and validates all 4 KiB payloads at both peers,
and requires a normal Close. Five 1,000-round samples measured
101.80-103.39 us/roundtrip for netz-client + quic-go-server and
102.25-103.34 us/roundtrip for quic-go-client + netz-server. The overlapping
ranges are reported by role pair, not attributed to one library. This remains
same-application-shape because GSO/GRO, ACK policy, packetization, and syscall
counts have not been proven equal.
An opt-in three-run memory pass over the same workload measured whole-process
peak RSS of 3,840/3,584 KiB for the netz client/server and 13,056/13,056 KiB
for the quic-go server/client role pairings. Both netz explicit-allocation
records ended at zero live bytes. Go runtime-heap and netz allocator counters
remain separately scoped diagnostics; only whole-process RSS is compared
across languages. The strict runner independently recomputes the application
checksum and requires distinct result and server-completion records before it
accepts either memory record.

The RFC 8441 Hyper 1.11 peer now also has a dual-role, two-CPU persistent echo
gate, `bench-websocket-hyper-h2`. It excludes h2c/SETTINGS/CONNECT/READY and
warmup from timing, disables compression and adaptive windows, uses one
outstanding 4 KiB message, and validates every round-dependent payload at both
peers before a normal Close. Five 1,000-round runs measured
20.33-22.29 us/roundtrip for netz-client + Hyper-server and
21.07-23.28 us/roundtrip for Hyper-client + netz-server. These are role-pair
same-application-shape results, not equal-wire or isolated single-library
costs, because HTTP/2 scheduling, HPACK, frame packing, masking, syscalls, and
executor behavior remain implementation-specific.
An opt-in memory run over the same 20-warmup/1,000-measured/4-KiB workload
recorded whole-process peak RSS of 2,304/2,048 KiB for the netz client/server
and 3,328/3,328 KiB for the Hyper server/client role pairings. Netz's explicit
allocator ended at zero live bytes; Rust requested-allocation counters remain a
separately scoped diagnostic rather than a cross-language ratio. The strict
runner now requires unique client-result and server-completion records with the
exact independently recomputed checksum, and Hyper waits for both the upgrade
echo task and connection driver before its memory snapshot.

WebTransport's incremental and whole-stream readers now benefit from a QUIC
receive-stream ID enumeration fast path: increasing physical IDs append
directly, while swap-removal layouts retain the stable sorted fallback. Ten
fixed-binary 64-stream pairs reduced the public enumeration call from a
1,084.55 ns median to 97.64 ns (91.0%, 11.1x), with identical checksums. The
end-to-end 64-stream transfer remains UDP-queue-bimodal, so this is recorded as
a CPU-path improvement rather than a throughput ratio.
Steady 64-stream write-batch staging now carries each selected stream's offset
from its initial registry lookup into frame construction instead of repeating
the hash lookup. Ten alternating fixed-binary CPU-0 pairs reduced median pure
staging cost from 1,217.593 to 1,019.589 ns (16.3%, 1.19x), with identical
descriptor checksums. This socket-free measurement is likewise scoped only to
the staging CPU path, not end-to-end throughput or a cross-library result.

Peer unidirectional streams are classified only after their offset-zero type
varint becomes contiguous. A bounded connection-scoped reassembler retains
out-of-order suffixes, so reserved/unknown streams are ignored and arbitrarily
allocated control, QPACK, and push streams reach the correct state machine
without relying on fixed stream-ID guesses. Client and server routing tests
cover both a reserved type on the conventional QPACK ID and a real QPACK
encoder stream allocated at a later ID.
Once either QPACK critical stream is registered, a different stream declaring
the same type is rejected before generic reassembly with
`H3_STREAM_CREATION_ERROR`, as required by RFC 9204. Direct encoder/decoder
state tests cover both types, and a protected-client wire test verifies the
application close code instead of leaking the internal `WrongStream` error.
Stateful HTTP/3 routing also commits every consumed control, QPACK, and
ignored-extension byte through the underlying QUIC receive cursor. Push streams
commit only their parsed type/Push-ID prefix and preserve message DATA
backpressure, including when that prefix is split across packets, without later
double-crediting it as application consumption. Terminal unknown streams also
return their unidirectional MAX_STREAMS slot, while active WebTransport sessions
preserve 0x54 streams even when the two-byte type is reordered across packets.
Both stream- and connection-level receive windows therefore keep advancing on
connection-long critical streams; if a MAX_STREAM_DATA/MAX_DATA write is paced,
congested, or fails at the socket, the latest absolute credit remains queued on
an independent connection timer instead of replaying already committed HTTP/3
parser state. Pending per-stream updates are selected in stable round-robin
order and coalesced into one packet up to a fixed frame cap and the active MTU,
reducing timer turns and control packets without starving a higher stream ID.
Client/server QPACK, control-stream, fragmented push-prefix,
terminal-extension, reordered WebTransport-prefix, and injected send-failure
tests cover these ownership boundaries.

The 1-RTT anti-amplification budget is server-only and accounts complete
protected UDP datagram lengths rather than plaintext payload lengths. Batch and
PTO partial-send rollback retain exactly the socket-visible prefix. Clients can
therefore probe a migrated or server-preferred address before receiving bytes
on that path, including when the server advertised `disable_active_migration`;
ordinary client-selected migration still honors that transport parameter.
PATH_CHALLENGE state is now transactional as well: capacity and frame bytes are
prepared before send, while pending challenges move to outstanding and consume
a retry only after the packet is accepted by the transport. Each outstanding
challenge records the path epoch on which it was sent, so a delayed response
from path B cannot validate the current path C; the same C response may still
arrive on another tuple as RFC 9000 permits. Deterministic tests cover
wire-byte budget boundaries, a partial batch, preferred-address probing, and
single/batched challenge retries after anti-amplification blocking.
When validation of the selected path exhausts its retries, the connection now
restores the last validated peer address and its still-active CID, or selects
a peer-issued replacement if Retire Prior To removed that CID. Superseded path
epochs are abandoned instead of being retransmitted on the current tuple, and
duplicate migration challenges are rejected before any path mutation. Timeout
retry allocation is preflighted for the whole due set, so allocator failure
cannot half-commit expiration. Queued PATH_RESPONSE work retains the exact
source tuple even if the active path changes before the response is emitted.
Path validation helpers now expand PATH_CHALLENGE and PATH_RESPONSE datagrams
to RFC 9000's 1200-byte minimum. Servers keep a fixed eight-slot, allocation-
free candidate-tuple budget table: only authenticated probing datagrams add
credit, responses debit the matching tuple, referenced slots cannot be
evicted, and the ninth referenced candidate is rejected instead of borrowing
another path's allowance. When non-probing traffic selects a candidate, its
accumulated received/sent bytes transfer into the active path budget. Client
responses on known server paths are padded without the server-only amplification
restriction; challenges from unknown server tuples are discarded. Local tests
cover insufficient candidate credit, exact 1200-byte response/challenge
emission, candidate-to-active transfer and capacity exhaustion. If a timed
challenge retry is still blocked by amplification or congestion, a short
retry deadline remains armed instead of losing all transport wakeups. The
quic-go migration and migration-under-loss process gates remain green. Failed
validation history is retained as a saturating count rather than an
ever-growing challenge list, eliminating long-connection growth and migration
clone cost without reducing the public statistics surface.
Local transport/application close and peer draining now derive a three-current-
PTO expiry from the endpoint's awake clock when callers do not inject explicit
test timing. The deadline rounds both the current time and PTO upward before
millisecond storage, so it cannot expire before RFC 9000's minimum; shared
endpoint schedulers therefore retire ordinary and protocol-error closes without
requiring another peer packet. Explicit `close*At` timestamps remain available
for deterministic embedders and tests.
The shared endpoint also consumes routed datagrams for connections already in
closing or draining state instead of surfacing `ConnectionClosed` as a fatal
multi-connection loop error, while retaining the connection's close-expiry
timer. If the current datagram itself triggers a transport close, the original
validation error remains visible and the newly installed close timer is synced
before it returns.
Ordinary short-header authentication failures addressed to a registered CID
are likewise consumed by the shared endpoint after incrementing the
connection's AEAD integrity counter; reaching the negotiated cipher limit still
surfaces `AeadLimitReached` and closes the connection. A forged packet therefore
cannot stop the sole receive loop merely by knowing a visible CID, while the
mandatory integrity-failure safety limit remains effective.
Pre-authentication short-header format failures, including truncated header-
protection samples and undersized packets, are also consumed without charging
that integrity counter. Reserved bits are checked only after AEAD succeeds, as
required by RFC 9000 section 17.3.1: an authenticated violation installs and
surfaces a `PROTOCOL_VIOLATION` close, whereas random ciphertext cannot forge
one. Likewise, once retained previous-generation keys are discarded, an
apparent old Key Phase that cannot authenticate is treated as ordinary invalid
ciphertext rather than an observable `KEY_UPDATE_ERROR` oracle. Focused codec,
connection, and dispatcher regressions cover all three boundaries plus delivery
of a valid packet after a discarded malformed packet.
Initial, Handshake, and 0-RTT packet protection applies the same deferred-error
rule from RFC 9000 section 17.2 and RFC 9001 section 9.5: long-header reserved
bits are reported only after AEAD succeeds. Tests cover every protected long
packet type with both an authenticated non-zero value and a forged header whose
unchanged tag must instead produce `AuthenticationFailed`.
Handshake-owned receive loops now discard pre-authentication long-header parse
and AEAD failures while preserving one absolute timeout and the peer tuple.
This covers the first/retried server Initial, multi-packet Initial CRYPTO, both
Handshake directions, and accepted 0-RTT; low-level one-packet open APIs retain
their diagnostic errors. Authenticated CRYPTO/frame failures and
`InvalidReservedBits` remain visible, and invalid Initials use RFC 9000 section
10.2.3's explicit discard allowance before any CRYPTO state is committed.
Authenticated Handshake and accepted 0-RTT reserved-bit violations also emit a
best-effort transport `CONNECTION_CLOSE(PROTOCOL_VIOLATION)` at the highest
available encryption level before preserving `InvalidReservedBits` for the
caller. Initial and Handshake flight construction now validates the complete
packet-number/MTU range and reserves all storage before its first in-place AEAD
operation. Batch sends retain both protected and socket-sent counts: zero or
partial socket progress leaves PN gaps and PTO retransmits under a fresh range,
while server anti-amplification accounting keeps only the submitted prefix.
Established 1-RTT PTO probe batches follow the same rule: only the socket-sent
prefix remains in congestion, sent-packet, and recovery state, but every sealed
probe advances the packet-number space so an unsent suffix can never reuse an
AEAD nonce on the next timer firing.
Lightweight WebTransport DATAGRAM sends use that same protection boundary for
both stack-backed and allocating packet storage: a socket rejection after seal
retires the packet number, while pre-seal validation, deadline, or allocation
failure remains side-effect free. Stateless batch progress also reports
post-seal endpoint-interceptor failures as values with the complete protected
count, so HTTP/3 and WebTransport owners cannot lose nonce consumption when no
datagram reached the socket. Held-packet interceptor state is published only
after its owned copy succeeds, keeping allocation failure transactional.
The server also prepares its Handshake packet before emitting Initial bytes and
tracks the next unused Handshake packet number across every protected PTO copy,
so neither allocation failure nor a socket-rejected suffix can reuse a nonce.
The 0-RTT handoff separately records protected packet-number consumption and
the sparse subset actually accepted by the UDP socket. The installed 1-RTT
state advances past every protected nonce, while ACK validation, congestion,
and recovery contain only real socket-sent copies with their exact long-header
datagram size. An accepted server waits through same-path Initial PTO copies
for the following standalone 0-RTT packet under one fixed handshake deadline.
The symmetric rejection path applies the same filtering before discarding the
standalone 0-RTT datagram, so a lost first early packet followed by PTO's
Initial-then-0-RTT sequence still completes PSK resumption instead of treating
the retransmitted Initial as malformed early data.
If Version Negotiation restarts the connection, the original 0-RTT packet is
never replayed under the replacement version and its old-key packet numbers do
not advance the new application space; the client nevertheless retains an
explicit rejected disposition so typed HTTP/3 leaves replay to the caller.
Initial flight packet plans and datagram views now use stack storage for the
default 64-packet bound, retaining a heap fallback for explicitly larger
flights. In back-to-back 50-connection ReleaseFast runs with certificate
verification and allocator telemetry, this removed exactly four allocations
per connection (4501 to 4301 total); the observed P50 moved from 807.5 to
801.9 microseconds, while the single-run throughput change remains too noisy
for a general performance claim.
Closing connections now respond to current-path datagrams through a dedicated
timer rather than parsing application frames or retransmitting immediately.
The first response requires one packet, subsequent thresholds double to 2, 4,
8, and so on, and each response is delayed by one smoothed RTT. A failed socket
send rearms the same bounded retry without losing the three-PTO hard expiry; a
draining connection never schedules or emits a response. This follows the
rate-limited closing model audited in s2n-quic while keeping endpoint routing
and all waits on the `std.Io` abstraction.

## Known blockers before declaring the goal complete

HTTP/3's shared-endpoint handshake admission now uses the exact absolute
deadline recorded when the Initial was registered, rather than relying only on
the supervisor to close its inbox during periodic expiry scans. The worker's
QUIC/TLS accept path therefore cannot outlive that admission budget between
poll iterations.

The generic HTTP/3 origin-keyed idle pool now performs true global LRU
capacity eviction. Its entry array uses `swapRemove` so array position cannot
encode age; each release therefore records an independent monotonic sequence
and capacity replacement scans the configured small idle set by timestamp plus
sequence. Focused tests force a middle acquisition to swap a newer connection
into index zero, then prove the genuinely oldest connection is evicted, and
also cover several releases in the same millisecond.

`HandshakeClientPool` now integrates that policy with real authenticated HTTP/3
clients. Its exclusive leases retain QPACK/control state, normalize URI origins,
discard GOAWAY/closed/non-quiescent clients, retry one stale reused connection
only for idempotent methods, and accept a connector callback so certificate,
resumption, CID generation, and endpoint ownership policy stay explicit. A
total connection limit includes idle, leased, and in-progress handshakes; a new
origin may replace the global least-recently-used idle client without exceeding
that cap, while a pool containing only leases/handshakes rejects new admission
and failed connects release their reservation. Relative-timeout and absolute-
deadline acquisition wait for capacity under one awake-clock budget through
the same allocation-free FIFO admission queue used by HTTP/1 and HTTP/2. New
callers cannot barge ahead of older blocked requests, and timeout/cancellation
unlinks its stack-owned ticket before waking the successor, while
pool close wakes every waiter and causes outstanding leases to be discarded on
return. Deadline-bounded acquisitions also cover arbitrary connector execution,
closing a concurrent late success, and pooled one-shot requests carry that same
timestamp through stale retry and complete response assembly. A relative-timeout
wrapper converts its budget once at API entry. Returning a
successful response uses best-effort idle caching: if pool
metadata allocation fails, the connection is closed and the completed HTTP
result still reaches the caller rather than being replaced by an OOM error. A
default connector securely
generates fresh CIDs while retaining caller TLS/resumption policy. A
real TLS/QUIC regression issues two differently cased URI requests through one
accepted connection and verifies the second lease is reused; a companion case
marks GOAWAY before release and proves the connection is not cached. A
two-server TLS/QUIC regression also constrains the total to one connection,
leaves origin A idle, then requests origin B and proves that the idle A client
is closed and its slot transferred before B is dialed; a second B request
reuses that replacement while the pool remains at exactly one connection. Each
Another real TLS/QUIC regression holds the only slot, queues two waiters in a
known order, and verifies ordered admission as each predecessor is discarded.
URI clients additionally accept one absolute connect budget spanning hostname
resolution and every address-specific QUIC/TLS attempt. That same deadline is
carried through Initial, Retry, Version Negotiation and passive Handshake
flight reads rather than restarting for each stage or fallback address. Direct-
address clients use the same total timeout directly in addition to the lower-
level bounded PTO/retry policy. Explicit `connectWithDeadline` and
`connectUriWithDeadline` entry points let a larger operation share its existing
awake-clock budget instead of converting it back into a relative timeout; both
also expose explicit per-call timeout counterparts. The
one-shot `requestUriWithDeadline` path carries that same timestamp through DNS,
all QUIC/TLS connection attempts, request transmission, and response assembly;
its relative-timeout counterpart converts the budget once before any work.
`SharedHandshakeClientPool` now owns one `std.Io` UDP endpoint and one QUIC
dispatcher across all pooled origins. Its CID-routed handshake inboxes keep
TLS workers off the socket, successful clients move into stable heap storage
before atomic dispatcher promotion, and idle reuse/global LRU eviction retain
the configured connection cap. Only the pool's `receive*` methods own UDP
receive; leases send through single-attempt helpers, expose stable connection
handles for response correlation, and reject client methods that would start a
competing receive loop. `receiveManyOnce` adds a bounded caller-buffer receive
turn for established pool connections: its dispatcher applies borrowed packet
views synchronously, while returned response/push events own all header state
needed after the receive storage is reused. The existing owning
`processResponsePacket` entry point remains source-compatible.
The batch suppresses repeated unconsumed DATA-ready notifications for one
connection/stream without dropping later application state. A real two-origin
TLS regression waits until both servers have submitted their responses,
observes a multi-event receive, overwrites the caller buffer, and still
validates both status lines and bodies. Leases provide one-attempt complete
requests and streaming uploads (`tryStartRequest`, `trySendRequestBody`, and
`trySendRequestBodyParts`, and `tryFinishRequestTrailers`), with literal/static
QPACK request sections so a retry never commits encoder dependencies separately
from the request packet. Their underlying QUIC one-shot sends also keep
automatically generated `STREAMS_BLOCKED`, `DATA_BLOCKED`, and
`STREAM_DATA_BLOCKED` notifications on the caller-supplied timestamped path:
pacing returns immediately without sleeping, and a failed HTTP/3 request start
does not advance its stream ID, request lifecycle, QPACK dependencies, or body
state. The vectored body helper borrows multiple caller
slices behind one DATA prefix and performs one socket submission; pacing or
validation failure leaves the body length, STREAM offset, and FIN state intact
for an identical retry. Leases also expose nonblocking multi-stream body
batches: the result reports the exact socket-visible committed prefix together
with any partial send error, so callers retry only the untouched suffix.
The authenticated client primitives supporting that
integration are explicitly nonblocking: `pollResponseEventOnce`,
`pollNextResponseEventOnce`, and `pollPushEventOnce` never receive or sleep,
and their matching response/push DATA helpers preserve unread bytes while
receive credit, QPACK feedback, or STOP_SENDING is paced. Terminal response
and push events remain reconstructible and are delivered exactly once after
the endpoint owner advances the connection timer. Dispatcher-bound Extended
CONNECT attempts also use one-shot cancellation during adapter cleanup; a
pacing failure cannot block deinitialization and instead makes the connection
ineligible for reuse after local request state is retired.

The endpoint foundation now includes a concrete single-receive-owner
`quic.endpoint_dispatcher.Dispatcher`. It owns established-connection CID
routes and the aggregate endpoint timer index, dispatches one UDP datagram to
the matching `one_rtt.Connection`, refreshes that connection's deadline after
each packet, and admits only structurally valid, minimum-sized v1/v2 Initials
to the future handshake layer. Unknown short packets, malformed/undersized
Initials, and non-Initial long headers are typed separately for drop or
stateless-reset policy without letting connection tasks race on the socket. A
shared-server policy now consumes eligible unknown short packets itself when a
static reset key is configured. Its single endpoint timestamp applies a default
20 ms minimum response interval across all source addresses, and the same key
derives the TLS transport-parameter token, Initial CID pool token, and later
dispatcher-routed CID tokens. The server can atomically advertise a replacement
with a monotonic `retire_prior_to`; the new route is published immediately, the
old route remains usable until the peer confirms `RETIRE_CONNECTION_ID`, and a
failed send rolls back both the CID pool and route map. When the reset key is
enabled, the shared server also fills each established local CID pool to the
peer's advertised active limit (bounded by netz's eight-slot pool) and replaces
retired IDs through nonblocking sends on later packet/timer turns. Each refill
coalesces all missing NEW_CONNECTION_ID frames into one protected datagram, so
the default four-CID target adds three routes with one UDP send. A
real two-connection handshake switches away from seq=0, sends both retirement
confirmations, observes derived-token seq=4 replacements, and finishes with four
live routes per connection. A separate real UDP state-loss regression completes
an authenticated handshake, removes the server connection and every CID route,
then sends through the client's still-active old CID. The shared server answers
with the handshake-advertised derived token, and the client enters three-PTO
draining without charging its AEAD integrity-failure counter; three consecutive
runs completed. Disabled configuration preserves the typed
`unrouted` event. Raw/pre-filled token conflicts and preferred-address config
whose route cannot yet be owned by this shared server are rejected at init. A
two-client test sends to one server UDP socket, verifies exact per-connection
delivery, services a selected PTO through the shared timer index, preserves an
valid unknown Initial for admission, sends Version Negotiation before admitting
the following packet, wakes a socket wait for connection PTO, and removes every
route/timer before connection storage can be destroyed. Route-level migration
blocking now permits same-IP port rebinding and rejects only address changes
before authenticated connection processing, matching the transport's existing
NAT-rebinding behavior.
The dispatcher now also mirrors each connection's authoritative fixed-capacity
local CID pool. Initial IDs are installed at registration, dispatcher-mediated
NEW_CONNECTION_ID sends preflight endpoint-wide collisions before changing
transport state, and authenticated RETIRE_CONNECTION_ID packets remove obsolete
routes before the next event is exposed. The per-connection route list and
router reserve the negotiated pool maximum up front, keeping receive-time CID
reconciliation allocation-free after state mutation.
HTTP/3's stateful server session now exposes `processRequestPacket` plus
`pollRequestEvent`: an endpoint owner can inject one already-authenticated QUIC
packet and drain ready HTTP/3 events without any session attempting another UDP
read. A two-client preconfigured-key test routes interleaved SETTINGS and
request packets through one dispatcher/socket into two independent HTTP/3
sessions, validating each path and each QPACK/control state independently.
All authenticated HTTP/3 request, response, push, streaming-event and detached
progress deadline entry points validate the awake-clock domain before pumping
QUIC state. A wrong-clock timestamp therefore fails without consuming a packet
or mutating a resumable request/response lifecycle.
The integrated QUIC server handshake can now consume the first client Initial
already owned by that dispatcher, and HTTP/3/WebTransport expose corresponding
`acceptFromInitial` entry points. This removes a second socket read at admission
and preserves explicit datagram ownership. The QUIC layer now also provides a
bounded thread-safe pending-handshake inbox and a type-erased datagram source.
One dispatcher/socket owner routes later Initial, Retry, 0-RTT, and Handshake
datagrams by the admitted original/server CID and peer tuple while handshake
workers consume only their inbox. A real three-party regression (client, sole
socket owner, handshake worker) completes TLS without a second socket reader,
then atomically promotes the pending route to established 1-RTT routing.
The client handshake now accepts the same `DatagramSource` abstraction through
`connectFrom`; a reciprocal three-party regression keeps a client endpoint's
socket in one owner while its handshake worker consumes only a CID/source-bound
inbox. The ordinary `connect` API remains the endpoint-backed convenience path.
HTTP/3 exposes the same source-driven construction on `HandshakeClient`,
retaining caller ownership of the endpoint so the established client can be
registered directly with the endpoint dispatcher after TLS completes. Its
timeout and absolute-deadline forms preserve one budget across the complete
source-driven QUIC/TLS handshake, matching the direct-endpoint client surface.
Path validation now converges immediately after any matching response validates
the selected path: redundant same-path challenges and their retry deadline are
discarded after the complete response packet is applied, so they cannot later
inflate failed-validation statistics. Deferring that cleanup until packet end
still permits several valid PATH_RESPONSE frames in one packet.

This is deliberately not yet described as a complete HTTP/3 multi-connection
server. The low-level ownership and routing primitive is now present, but the
HTTP/3 now exposes an owning admission lifecycle plus a bounded handshake
supervisor. It generates unique per-connection server CIDs, assigns inboxes,
starts cancelable workers, reports completions without blocking the socket
owner, unregisters failures, and returns stable heap-backed sessions whose
successful promotion cannot invalidate dispatcher pointers. Admission has
separate pending-handshake and aggregate pending-plus-established connection
caps, releasing total capacity when a live connection is removed. The supervisor's
single-owner receive API interleaves completion polling, endpoint timers, and
UDP routing. Shared endpoint sends are serialized across handshake/connection
workers, including ECN socket state, GSO fallback state, and deterministic
fault-injection queues. WebTransport exposes a split handshake/admission object that can
be promoted before CONNECT polling. Its endpoint server now retains stable
pending and accepted sessions around HTTP/3's sole-receiver transport loop,
dispatches CONNECT, stream, DATAGRAM and Capsule events, and shares HTTP/3's
handshake expiry policy. The remaining convenience work is a callback/task
supervisor above this typed event loop. HTTP/3 now
has an endpoint server that stores stable promoted sessions, routes packets and
timers, polls requests without per-connection socket reads, and explicitly
removes connection routes before destroying session state. Request polling now
resumes after the last productive connection via a stable-handle cursor, so a
busy connection cannot starve another ready request even if the session map
rehashes. This brings the HTTP/3 application-event boundary up to the fair
cross-record polling behavior in the audited quicz endpoint registry. Within
each connection, multiplexed incremental request and response polling likewise
resumes after the last productive stream via a stable stream-ID cursor; busy
DATA streams therefore cannot starve ready sibling streams, and swap-removing
a completed stream cannot invalidate the cursor. Untargeted server-push polling
uses the same policy while targeted push reads leave the shared cursor intact;
unpromised push streams may remain buffered without starving promised siblings.
The audited local quicz H3 layer has no corresponding server-push event API.
Its bounded
`receiveTransportOnce` and cancellable `serveTransportUntil` APIs let protocol
adapters retain that single receive owner without busy waiting. The handshake
supervisor and owning endpoint also expose absolute-deadline receive variants,
including the transport-only boundary used by WebTransport, so unrelated
packets and timer servicing cannot renew an outer operation's budget. Matching
one-shot relative-timeout wrappers convert to that deadline once at API entry.
Expired idle
or draining connections now emit a typed `closed` event only after their CID
routes and stable session storage have been reclaimed. A two-client
Callers may also service a bounded snapshot of all currently due timers in one
turn. Every connection appears at most once even if PTO processing rearms an
already-due deadline, preventing one lossy connection from monopolizing the
shared endpoint before UDP receive or sibling timer work. A two-client
real TLS/QUIC test exercises the full admission and promotion path on one UDP
socket. The owning HTTP/3 endpoint also exposes a bounded `receiveOnce` and a
cancellable `serveUntil` callback loop for connected, closed, and request
events; callbacks borrow the stable session and request only for their
synchronous invocation, preserving the single-owner transport invariant. A
promoted session is now explicitly dispatcher-bound: blocking request receive,
paced response, flow-control read, cancellation, and recovery-drain helpers
reject before reading the shared UDP socket. Endpoint handlers instead have
transactional one-attempt static-QPACK APIs for a complete one-packet response
or for response head, DATA, and trailers separately, plus one-attempt request
DATA read/skip helpers. A two-client regression first forces connection A's
response to fail with `PacingLimited`, only then sends B's request, completes B,
and finally resumes A's head/body/trailers. This proves transport backpressure
on one connection no longer creates callback-level HOL or steals B's datagram;
long-running application computation remains the caller's responsibility in
this intentionally synchronous callback API. Dispatcher-owned servers also
expose one-attempt `trySendGoAway`, `tryInitiateShutdown`, and
`tryCompleteShutdown`: pacing failure rolls back the control-stream offset,
local GOAWAY ID, packet number, and shutdown phase, while a retry emits the
maximum-ID and final-ID GOAWAY sequence monotonically. A real protected-wire
test parses both frames at the peer. Dispatcher-owned clients have the matching
one-attempt control surface for GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, and request
or push PRIORITY_UPDATE. Each complete control frame must fit one packet;
pacing, congestion, flow-control, frame-count, and MTU failures roll back the
control-stream offset and mutable control/push state. A protected-wire test
forces and retries every path before parsing the exact peer-visible frame.
  Dispatcher-owned servers can likewise advertise a complete RFC 9412 ORIGIN
  frame with `trySendOrigins`; the frame must fit one packet and failure rolls
  back both the advertisement marker and control-stream offset.

QUIC now keeps the selected peer connection ID in address-stable owned storage
instead of borrowing an inline CID-pool entry. HTTP/3 and WebTransport sessions
are intentionally moved by value during admission; without stable storage a
later response could use bytes overwritten at the old address and be silently
dropped by an external endpoint router. A move-after-CID-rotation regression
verifies the exact destination CID on wire, and the bidirectional native
wtransport gate validates CONNECT, DATAGRAM, streams, cancellation, reuse,
drain, and close after the fix.

1. **Large HTTP/3 download reliability**: local real-handshake download now
   covers 4MiB/16MiB/64MiB benchmark-scale responses in both single-stream and
   four-stream runs, in addition to the 1MiB smoke tests and protected
   small-window coverage. The remaining work is long-run repeatability rather
   than a basic benchmark-scale functional gap.
2. **Aggressive receive batching**: the prior timer starvation is fixed.
   Timer-aware GRO completed five 64 MiB/four-stream uploads and three
   downloads, including a transport test where PTO fires after a deliberately
   dropped packet. It remains opt-in because throughput is worse on this host,
   not because of a known reliability stall.
3. **Aggressive transfer settings**: the benchmark uses 3000-byte multi-stream
   chunks below 64 MiB and 6000 bytes for quicz-shaped 64 MiB runs. Larger
   12/14/16 KiB datagrams were slower or noisier, while cross-stream GSO
   batching remains opt-in because this host's small receive queue favors
   sequential packet submission.
4. **Complete external interop matrix**: public H3 fetch is proven against
   `robotics.bytedance.com`, including `--discover`, manual `--alt-svc`, and
   `--verify`, and independently against `cloudflare-quic.com` with verified
   HEAD plus a 125,959-byte GET response. The Cloudflare chain terminates in a
   cross-signed GTS Root R4 while the system bundle contains its self-signed
   form. Netz now recognizes that trust anchor only when Subject, public-key
   algorithm, and public-key bytes all match; it still checks the presented
   chain links, hostname, and both terminal/anchor validity periods. A focused
   regression accepts the equivalent cross-signed identity but rejects the
   same Subject with another key. A separate local process gate builds quic-go v0.59.0 from the
   audited `~/Work/quicz` fixture and checks HTTP/3 in both directions with
   verified TLS identities: each side validates POST method, query-bearing
   path, authority, custom headers, request body/trailer, status 201, response
   body/trailer, and multiple DATA writes. Both directions now exercise the
   cancellation target and stream 4 sibling concurrently under fixed 8 KiB
   per-stream and 24 KiB connection receive windows. Each target declares a
   128 KiB response, crosses the initial stream window by reading 12 KiB, then
   cancels. In both directions the gate deliberately discards the first
   datagram carrying STOP_SENDING, forcing QUIC loss recovery to retransmit
   the control frame. The sender must then observe exact code 0x10c
   (`H3_REQUEST_CANCELLED`) before the already-present sibling is allowed to
   respond, and that sibling must still complete with its expected body and
   trailers. The quic-go side traces at least two matching STOP_SENDING
   transmissions and counts exactly one QUIC dial, so the reverse result
   cannot be explained by either a non-cancellation packet loss or a
   replacement connection. Fresh connections in both QUIC v1 and v2 also
   exchange 103 Early Hints and 102 Processing before a final 200 in both
   endpoint roles. Netz validates ordered status and distinct header values;
   quic-go validates netz through its standard `Got1xxResponse` trace.
   A second process gate builds tquic `0169abde20c6` from the audited
   `~/Work/tquic` checkout and performs reused-connection HTTP/3 exchanges in
   both endpoint directions, both normally and with the server forcing QUIC
   Retry. The netz-client direction checks a complete GET, a byte Range with
   exact 206/body, and a POST whose tquic-computed MD5 is verified, plus
   `server: tquic`, the server certificate/hostname, and its own observed Retry
   state. The tquic-client direction checks two request-success counters and
   dumped response files, while the netz server independently validates both
   paths and whether Retry completed. Only the tquic-client direction lacks
   trust validation
   because that CLI exposes no CA option; the netz-client direction is
   certificate verified.
   Google and Facebook public peers remain unverified and are not counted as
   coverage; this host's Google DNS path currently resolves through a private
   proxy address whose UDP/443 handshake times out.
   The synchronous handshake now preserves a first 1-RTT packet coalesced
   behind the peer's Handshake flight in both endpoint roles. The server-side
   path was required by Chrome's Handshake Finished plus HTTP/3 control stream;
   the client path now retains the symmetric server Handshake plus application
   suffix as well, including its ECN marking, instead of silently discarding
   an early HANDSHAKE_DONE, SETTINGS, or application packet. Deterministic
   tests cover both wire shapes before the external matrix below.

   Raw QUIC now has a separate process-boundary client gate:
   `zig build interop-quic-quic-go -Doptimize=ReleaseFast` builds quic-go
   v0.59.0 from the audited `~/Work/quicz` fixture, loads its generated
   localhost CA into netz's verifier, requires TLS 1.3 `hq-interop` ALPN, and
   verifies two independent bidirectional STREAM echoes plus FIN. The same gate
   forces RFC 9369 QUIC v2 in both directions on separate connections: netz
   selects v2 against a v2-only quic-go server, and a v2-only quic-go client
   completes the same two-stream exchange against a v2-only netz server. Both
   external peers inspect and report the negotiated version rather than
   inferring it from successful TLS or application data. The gate therefore
   covers v2 long-header type mapping, Initial salts/labels, transport-parameter
   version information, 1-RTT streams, FIN, and application close handling.
   Version identity is also retained in established connection state so RFC
   9369's `quicv2 ku` key-update secret and subsequent `quicv2 key`/`iv`
   derivations remain the default after the handshake; a two-endpoint v2
   regression decrypts the first updated-key stream and checks the peer
   transition. The audited quic-go v0.59.0 updater still derives `quic ku`
   unconditionally. Netz now offers an explicit full-connection compatibility
   profile for that pinned peer: the process gate forces QUIC v2 through two
   ACK-gated updates in each direction while leaving standards-compliant RFC
   9369 derivation as the public default.
   The same gate
   repeats that exchange against a quic-go `Transport` whose
   `VerifySourceAddress` callback always requires Retry. Netz exposes and
   asserts the authenticated Retry transition, then still completes both
   streams and validates application close code 57 on that connection. This is
   direct external coverage for Retry integrity, authenticated token carriage in the second
   Initial, ODCID/RSCID transport-parameter binding and post-Retry 1-RTT state.
   A second forced-Retry connection repeats those assertions with both peers
   constrained to QUIC v2, additionally covering the RFC 9369 Retry integrity
   key/nonce and v2 long-header mapping across the complete retry handshake.
   A separate connection proves live 1-RTT key updates instead of relying only
   on local crypto vectors: netz sends a baseline stream, initiates key phase
   one, waits for an ACK of that generation before initiating phase two, and
   sends another stream after each transition. Quic-go decrypts and echoes all
   three streams; netz observes both peer response-key transitions, both ACK
   gates clearing, the final phase returning to zero, and the normal peer close.
   The same gate
   also runs the fixture's certificate-verifying quic-go client against a
   one-shot netz server and checks the same two stream IDs, payloads, FINs, and
   `hq-interop` ALPN. Two additional fresh connections verify application
   cancellation: quic-go sends RESET_STREAM with error 41 and then completes a
   stream 4 echo; separately, netz sends STOP_SENDING with error 42, observes
   quic-go's required RESET_STREAM response with the same error, and completes
   another stream 4 echo. A fourth client connection transfers and echoes
   12,288 bytes through deliberately advertised 8,192-byte connection and
   2,048-byte stream windows, so completion requires multiple on-wire
   MAX_DATA/MAX_STREAM_DATA credit updates rather than merely parsing the
   transport parameters. A fifth connection advertises one bidirectional
   stream and completes client streams 0, 4, 8, and 12 in sequence; netz only
   returns each MAX_STREAMS slot after the peer receive side is consumed and
   the local send side reaches FIN or RESET, and duplicate release attempts are
   idempotent. A sixth connection sends a client-initiated unidirectional
   stream 2 and requires a netz-initiated unidirectional stream 3 response,
   with exact payloads and FIN validated in both directions. Two final
   connections make quic-go discard four netz datagrams: once immediately
   after the first application STREAM write and once from the server's Initial
   flight. Both recover and complete the same two-stream echo. The Initial-loss
   case additionally verifies that established netz receive pumps silently
   discard late long-header retransmissions from obsolete packet-number spaces
   instead of decoding them as malformed short-header packets. Supporting that
   standard quic-go client required netz's
   1-RTT connection state to distinguish a legal zero-length Initial Source
   Connection ID from the non-empty IDs required in NEW_CONNECTION_ID frames.
   This is direct two-way QUIC transport evidence, not a local loopback proxy
   for HTTP/3. The initial netz-client/quic-go-server connection also waits for
   and verifies quic-go's application close code 57 and reason, rather than
   treating completed STREAM echoes as connection-close evidence. A ninth
   connection reverses that assertion: netz closes with code 58/reason
   `netz interop complete`, and quic-go reads the remote `ApplicationError`
   from its connection context and verifies both fields. A tenth reverse
   connection verifies multi-hop active migration rather than treating
   same-IP port changes as path validation: netz sends three additional
   `NEW_CONNECTION_ID` frames, and quic-go creates UDP transports bound to
   `127.0.0.2` and then `127.0.0.3`, each with a source port distinct from all
   earlier paths. Each candidate requires `Path.Switch()` to return
   `ErrPathNotValidated` before `Path.Probe()` succeeds. Streams 4 and 8 carry
   `migrated` and `migrated-again` after the respective switches. Netz observes
   each new IP and source port while the path is still unvalidated, sends its
   own PATH_CHALLENGE, waits for the authenticated PATH_RESPONSE, and only then
   returns that path's exact stream echo. Repeated
   retransmission of an already processed `RETIRE_CONNECTION_ID` is handled
   idempotently, as required when quic-go rotates its active and probing CIDs.
   An eleventh reverse connection repeats both candidate paths while a
   datagram wrapper drops the first PATH_RESPONSE from each path. Netz's
   blocking receive scheduler immediately sends each requeued PATH_CHALLENGE
   at its validation timeout and arms the next PTO; quic-go reports exactly two
   dropped probe datagrams and both `Path.Probe()` calls succeed only after
   those retries. Streams 4 and 8 still complete after the respective
   validated switches. A twelfth reverse connection covers the distinct
   NAT-rebinding branch:
   quic-go swaps the socket behind one `Transport` from one `127.0.0.1` port to
   another without calling `AddPath`, deliberately drops the first four
   outgoing datagrams, and still completes stream 4 through PTO recovery. Netz
   verifies the source port changed while the IP did not, keeps the path
   validated, and exposes zero queued/outstanding path-validation challenges.
   An independent bidirectional process gate now runs against s2n-quic 1.85.0
   at audited commit `254767581b3b47f53ceb88206b09aa6066e0f7f5`:
   `zig build interop-quic-s2n -Doptimize=ReleaseFast`. A netz client
   authenticates a freshly CA-signed localhost leaf served by s2n-tls, and an
   s2n-quic client with an otherwise empty trust store authenticates netz's
   fixture identity. The s2n server also asserts the `localhost` SNI. Both
   directions require `hq-interop`, exact stream IDs 0 and 4, two
   FIN-terminated echoes totaling ten bytes, and the expected peer
   application-close code. Separate connections in both directions verify
   RESET_STREAM error 41 and STOP_SENDING error 42 with the corresponding
   RESET_STREAM response, while a concurrently opened stream 4 still
   completes its echo. Two more s2n-client connections arm netz's stable UDP
   send interceptor immediately before RESET_STREAM(41) or STOP_SENDING(42)
   and discard exactly the first resulting datagram. The reset client withholds
   stream 4's FIN until it observes the retransmitted exact error 41; the stop
   exchange requires s2n-quic to observe error 42 and answer with
   RESET_STREAM(42). Both sibling echoes then finish before application close,
   demonstrating cancellation recovery without connection-wide disruption. A
   fourth netz-client connection sends and receives
   12,288 bytes through s2n-quic's advertised 8,192-byte connection and
   2,048-byte stream windows, explicitly asserting that transmission blocked
   before MAX_DATA/MAX_STREAM_DATA reopened credit. The netz-client half
   also completes a separate forced-Retry connection against s2n-quic's
   endpoint limiter and asserts `retry_processed`, authenticated TLS, both
   stream echoes, and peer application close on that retried connection. It
   explicitly selects X25519
   because s2n-quic 1.85.0 rejects the fragmented post-quantum ClientHello
   before all CRYPTO ranges arrive; this limitation is not hidden as broader
   post-quantum interoperability.
5. **Broader performance comparison against `~/Work/quicz`**: raw QUIC
   STREAM now has equivalent two-CPU, dual-role quic-go process harnesses for
   fresh transfer, persistent echo, and four-connection aggregate transfer,
   but still needs capture-backed equal-wire accounting. HTTP/3 likewise lacks
   an equal-wire reference. DATAGRAM, loss simulation, and stream reservation
   have direct faster artifacts. Raw QUIC now exposes a protocol-neutral
   shared-endpoint server owner and a verified four-connection benchmark over
   one server UDP socket. Its initial same-binary result is 0.717x the four-
   socket topology, exposing an owning-receive/scheduling deficit rather than
   supporting a whole-stack superiority claim. The external aggregate matrix
   also exposes a netz/netz worker-scheduling deficit. Mixed FIN/reset
   lifecycle churn now has a bounded-credit on-wire
   netz baseline, but no equal quicz harness yet. Echo latency now has a
   controlled artifact that is tied/faster across percentiles. Handshake
   latency/rate now has a verification-policy-aligned artifact, but the two
   workloads still need equal worker scheduling and lower tail variance before
   the whole quicz benchmark surface can be considered surpassed.

## Development HTTP/3 streaming

The cleartext development runtime now supports persistent incremental request
and response streams. Clients can start a request, send DATA chunks, and
consume response head/DATA/trailer/finish events; servers expose the symmetric
peer-aware event, body-read, response-head, and response-body APIs. Nullable
body lengths keep Extended CONNECT streams open, timeout and deadline calls
retain parser state, per-stream buffers and the global server stream count
remain bounded, and server stream identity includes the UDP peer so different
clients may both use stream zero safely. This is a deterministic development
facility, not a replacement for authenticated handshake-backed HTTP/3.

## Next recommended work

1. Extend the two-CPU raw QUIC process comparison with kernel/interface packet
   capture, WebSocket/WebTransport allocation telemetry, lossy/reordered on-wire lifecycle churn,
   and broader connection-count scaling. Persistent echo, four independent
   connections, and a four-connection shared-server-socket event loop are now
   covered. Optimize the shared dispatcher's owning receive path; its initial
   same-binary result is 0.717x the independent-server topology.
   Complete-connection userspace UDP counters
   expose materially different wire shapes, but this host denies unprivileged
   capture. Equalize GRO, ACK/pacing, packetization, and application stream
   scheduling before promoting it from same-application-shape to equal-wire.
2. Re-run HTTP/3 GRO on a host with larger kernel UDP receive buffers; the
   timer/recovery path is now safe, but this host's throughput regresses.
3. Reduce remaining HTTP/3 packet-protection and recovery bookkeeping cost.
   The current-key in-place receive path now computes header protection once
   and reuses that preview for decryption instead of peeking Key Phase and then
   recomputing the mask. Five CPU-0 samples reduced median allocating, service,
   and visitor cost by 2.6%, 3.8%, and 4.5%. Single-STREAM transactional
   preflight now avoids unrelated general-packet shadows; seven paired runs
   reduced visitor/service median cost another 1.5%/2.8%. Packed receive-byte
   tracking then reduced those STREAM medians another 11.9%/11.7% and removed
   the prior per-byte bitmap memset hotspot. Gap closure now finds the next
   absent receive bit by scanning packed machine words and using `ctz`, rather
   than testing every byte position. A dedicated `stream_gap` benchmark swaps
   adjacent packets without changing bytes, packet numbers, or stream offsets;
   seven CPU-0 pairs reduced visitor/service medians by 13.4%/13.2%, with 7/7
   wins in both modes, while the ordered STREAM shape remained noise-level. A
   subsequent bitmap-range precheck skips the preflight and commit byte loops
   when an allocated-buffer intersection contains no received bytes, while
   preserving byte-exact conflict checks for real retransmission overlap. Five
   more CPU-0 pairs reduced the current gap-fill visitor/service medians from
   2734/2751 to 1970/1983 ns per packet (27.9% each, 5/5 wins); ordered controls
   remained within 0.5%. A
   seven-pair real TLS/H3 four-stream upload check also improved in every pair,
   from 82.492 to 72.817 ms median per 16-MiB iteration. Cross-suite connection tests cover AES-128, AES-256,
   ChaCha20, and SM4 through STREAM receive and key update, in addition to
   non-mutating fallback on a phase mismatch. A separate
   experiment caching single-stream batch accounting was rejected after its
   median regressed 1.3%; `bench-quic-one-rtt-send --stream-fragments=4` remains
   as an H3-shaped guard against retrying that unprofitable shape blindly.
   Recovery encoding instead now reuses validation's packet-level knowledge to
   skip a second per-frame retransmittability classification when every payload
   byte is reliable; mixed DATAGRAM packets retain exact filtering. Frame
   classification itself now uses one tag switch instead of three. In the
   final long profile, the former standalone `frame_traits.classify` hotspot
   (9.26% before) disappeared from the reported hot list, while aggregate
   `Traits.observe` accounted for 2.09%. A label-parsed, CPU-0-pinned rerun of
   five order-alternated 50,000-iteration fixed-binary pairs improved the
   sequential median from 114.635 to 111.895 us/batch (2.4%, 5/5 pairs) and
   the batch median from 101.473 to 98.525 us/batch (2.9%, 4/5 pairs). One
   baseline batch sample reached 116.687 us and one final pair regressed 0.36%,
   so this is a median fast-path result rather than an all-pairs claim.
   STREAM/DATA framing now borrows all body bytes in the common case, and both
   ordinary and batch sends encode directly into stable recovery storage
   instead of copying a second plaintext payload. Exact-size batching still
   needs a larger-rmem host to show a throughput benefit.
4. Continue broadening public HTTP/3 interop beyond the independently verified
   ByteDance, Cloudflare, and quiche deployments.
