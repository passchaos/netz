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
zig build fuzz-quic-wire
zig build fuzz-quic-protection
zig build fuzz-quic-connection
zig build run-quic-echo -Doptimize=ReleaseFast
zig build run-quic-handshake-echo -Doptimize=ReleaseFast
zig build run-quic-datagram-echo -Doptimize=ReleaseFast
zig build run-quic-close -Doptimize=ReleaseFast
zig build interop-quic-quic-go -Doptimize=ReleaseFast
zig build interop-quic-s2n -Doptimize=ReleaseFast
zig build interop-quic-quinn -Doptimize=ReleaseFast
zig build run-http3-fetch -Doptimize=ReleaseFast -- --discover --verify --head https://robotics.bytedance.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- --alt-svc='h3=":443"; ma=2592000' --verify --head https://robotics.bytedance.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- --alt-svc='h3=":443"; ma=86400' --verify --expect-status=200 --min-body-bytes=100000 https://cloudflare-quic.com/
zig build run-http3-fetch -Doptimize=ReleaseFast -- --alt-svc='h3=":8443"; ma=86400' --verify --expect-status=200 --min-body-bytes=400 https://quic.tech/
zig build interop-http3-public -Doptimize=ReleaseFast
zig build interop-http3-quic-go -Doptimize=ReleaseFast
zig build interop-http3-tquic -Doptimize=ReleaseFast
zig build interop-connect-udp-h3 -Doptimize=ReleaseFast
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=upload --streams=2 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=download --streams=1 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=2 --body-bytes=1048576 --mode=download --streams=4 --verbose
```

A fresh 2026-11-01 `interop-http3-tquic` run passed GET, byte Range, POST,
ORIGIN, connection reuse, and both-direction two-phase GOAWAY(4) drain with
Retry disabled and forced; see
`docs/evidence/http3_tquic/2026-11-01.json`.

A fresh 2026-11-01 `interop-quic-quinn` run passed both roles with certificate
verification, `hq-interop` ALPN, DATAGRAM, deterministic loss and reorder on
netz outbound, a surviving stream sibling, and exact peer close; see
`docs/evidence/quic_quinn/2026-11-01.json`.

A fresh 2026-11-01 `interop-quic-s2n` run passed both roles with 32-stream
mixed churn, 16 FIN and 16 reset terminals, exact bytes/checksum/reset mask,
and deterministic loss/reorder on netz outbound; see
`docs/evidence/quic_s2n/2026-11-01.json`.

Fresh 2026-11-01 live fuzz gates passed `fuzz-http3-connection`,
`fuzz-webtransport-endpoint` and `fuzz-quic-connection` at 3/3 tests each; see
`docs/evidence/live_fuzz/2026-11-01.json`.

A fresh 2026-11-01 `interop-http3-public` run passed ByteDance, Cloudflare,
quic.tech:8443 and Meta. The quic.tech case exposed two client handshake
issues: the server sends an ACK-only Initial packet 0 followed by a
CRYPTO-offset-0 packet 1, and it gates the rest of the Handshake flight on an
ACK for the first CRYPTO packet. The filter now records the accepted packet
number so `openInitialCryptoFlightFrom` starts at packet 1, and the handshake
client acknowledges the first Handshake CRYPTO packet with client Handshake
keys before reserving the next packet number for its Finished flight. quic.tech
now completes the handshake and returns HTTP/3 200 with a 462-byte body. See
`docs/evidence/http3_public/2026-11-01.json`.

After both handshake fixes, the external client-role gates were re-run on
2026-11-01: `interop-quic-quinn`, `interop-quic-s2n`, `interop-quic-quic-go`,
`interop-http3-quic-go`, `interop-websocket-h3-quic-go`, `interop-http3-tquic`
and `interop-webtransport-wtransport` all exited 0 with their full both-role
matrices. The quic-go gates used the pinned Go 1.24.13 toolchain through
`GO_BIN`. Logs and per-gate results are in
`docs/evidence/quic_handshake_ack/2026-11-01.json`.

`fuzz-quic-wire` provides a dedicated 64 KiB-bounded corpus for QUIC long
headers, Version Negotiation, Retry parsing and integrity verification, typed
and untyped transport parameters, owned and caller-storage frame parsing,
packet-type frame legality, and the TLS ClientHello, ServerHello,
EncryptedExtensions, and Finished messages carried by QUIC CRYPTO frames. The
default test gate replays structured seeds plus deterministic truncation,
bit-flip, and random mutations; `zig build fuzz-quic-wire --fuzz=N` enables
coverage-guided runs, and scheduled CI preserves its corpus. This target does
not claim stateful live-connection or network-I/O fuzz coverage.
`fuzz-quic-protection` supplies the complementary encrypted-packet gate. Its
bounded generated path round-trips QUIC v1/v2 Initial, Handshake, 0-RTT, and
1-RTT packets, caller-storage and prepared-key APIs, Initial's mandated
AES-128-GCM plus all four negotiated traffic ciphers, zero-fixed-bit policy,
and next-generation key phases. Its hostile path covers arbitrary/truncated
input, packet-number reconstruction, long-header peeking, header protection,
owning opens, and authenticated tag mutation. It does not model loss,
reordering, connection state, sockets, or TLS key schedule transitions.
`fuzz-quic-connection` covers that adjacent stateful layer with two production
`Connection` values and real loopback UDP sends. A bounded scheduler captures
protected datagrams and drives delivery, loss, newest-first reordering,
duplication, corruption, explicit ACKs, PTO retransmission, bidirectional
STREAM/FIN/PING traffic, RESET_STREAM terminal delivery, application reads, and
key updates for QUIC v1/v2 and all supported traffic ciphers. Prefix-exact
application data, packet-number bounds, stream-count bounds, and directional
key-generation bounds are checked after every operation. The companion
`fuzz-quic-path` target drives authenticated packets across real UDP sockets on
three loopback IPs and multiple source ports. It covers superseded and invalid
PATH_RESPONSE, validation, timeout/retry/fallback, NAT rebinding, and
bidirectional stream traffic after path changes. `fuzz-quic-handshake` covers
the integrated QUIC/TLS layer across v1/v2, AES-128/SHA-256 and
AES-256/SHA-384, X25519/P-256/P-384, first-flight loss and corruption on either
side, Retry, bounded timeout, and post-handshake 1-RTT traffic. Long-running
connection limits remain outside these bounded fuzz models. The companion
`fuzz-quic-endpoint` target adds four authenticated v1/v2 clients and
AES-128/SHA-256 or AES-256/SHA-384 across one server-owned UDP socket. Its
two-connection admission cap is hit and surfaced before each removal; the same
waiting client is then admitted, exchanges an isolated STREAM/FIN echo, and the
old CID is observed only as unrouted traffic. The target also found and fixed
shared-endpoint workers defaulting every admitted v2 Initial back to v1 instead
of preserving the dispatcher's authenticated version choice. The CI-backed
`test-quic-endpoint-soak` gate then establishes 64 sequential authenticated
connections on one endpoint, alternating both versions and both AES suites.
After warming the four combinations, every removal must restore zero live
connections, workers, pending routes, and established CID routes plus the same
tracked allocator live-byte baseline; full teardown must reach zero live bytes.
Multi-hour and high-concurrency resource soaks remain separate future evidence.
The first extended run exposed an RFC 9001 Section 6.2 state conflation: netz
rejected a valid peer update after it had sent the required new-phase ACK merely
because that ACK packet had not itself been acknowledged. Receive-update
confirmation is now tracked independently from the local-update initiation gate
and clears only after a socket-committed ACK range covers the triggering packet.
A direct regression also proves that a true second peer update before that ACK
is rejected transactionally, without committing its STREAM or packet number.

Longer performance gates that have been used successfully include:

```sh
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=5 --body-bytes=67108864 --mode=upload --streams=4 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=1 --verbose
zig build bench-http3-handshake-transfer -Doptimize=ReleaseFast -- --iterations=1 --body-bytes=67108864 --mode=download --streams=4 --verbose
zig build bench-quic-one-rtt-send -Doptimize=ReleaseFast
zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=visitor --frame=stream --warmup=200 --iterations=5000
taskset -c 0 zig build bench-quic-one-rtt-receive -Doptimize=ReleaseFast -- --mode=service --frame=datagram --warmup=500 --iterations=10000
zig build bench-quic-datagram -Doptimize=ReleaseFast
zig build bench-quic-datagram-quinn -Doptimize=ReleaseFast -- --samples=5 --warmup=200 --iterations=5000
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=100
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --mode=handshake --iterations=200
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=1 --verbose
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- --iterations=3 --transfer-bytes=67108864 --streams=4 --verbose
```

The maintained ACK-range, connection-router, PADDING parser, short-packet
protection, receive sliding-window, session-ticket keyring, endpoint CID
synchronization, pending-ready-index, timer scheduler, and receive-stream-ID
microbenchmarks obtain any required UDP endpoint and their monotonic clock from
`netz.runtime.Backend` and report
`zio-std-io`. Numeric comparisons captured before 2026-09-15 remain historical
Threaded evidence unless a result is explicitly labeled as a zio-era rerun.
The raw DATAGRAM, 1-RTT send/receive, and UDP GSO/GRO benchmarks also obtain all
endpoint I/O and timing from zio-backed `std.Io`; the local DATAGRAM receiver
runs through `std.Io.async`. Earlier results remain historical Threaded
evidence until rerun under the documented fixed-binary protocol.

Single-DATAGRAM receive preflight now validates the negotiated wire-size limit
without constructing unrelated STREAM, connection-ID, or path-validation
shadows. Nine CPU-0 fixed-binary, order-alternated service-path pairs reduced
the median from 2,849 to 2,812 ns/packet (1.30%, 9/9 wins). Earlier
1024-byte/window-16 Quinn matrices left a directional cross-stack gap; the
connection-level GRO result below supersedes those non-GRO measurements for
the current windowed benchmark configuration.

Vail `6f22077` later grouped four independent PMULL products inside the compact
runtime-width GHASH loop. Nine clean CPU-0 fixed-binary pairs reduced the same
1,149-byte netz receive path from 2,689 to 2,646 ns/packet (1.60%, 9/9 wins)
while adding 776 bytes of ELF `.text`. A fresh five-sample Quinn matrix with
published Vail `1219d45` measured netz-client p50 at 163.460/189.514 us against
fixed Quinn/netz servers and Quinn-client p50 at 139.089/166.441 us. Those
same-application-shape ratios are 0.851x/0.878x, so the remaining large-payload
packet-protection/event-loop gap is still open.

Vail `bd821ba` subsequently kept the byte-reversed blocks, cached powers, and
four-way products in NEON registers throughout PMULL accumulation. Nine clean
CPU-0 fixed-binary pairs reduced the 1,149-byte state-service path from 2,641
to 2,565 ns/packet (2.88%, 9/9 wins), and seven caller-buffer delivery pairs
moved from 2,681 to 2,618 ns/packet (2.35%, 7/7 wins). The benchmark ELF
`.text` grew by 252 bytes. Vail's 1,200-byte AES-128-GCM microbenchmark
independently reduced seal/open-plus-seal by 10.34%/10.12%, with all seven
pairs faster.

The following five-sample Quinn matrix with published Vail `cfe6e33` measured
netz-client p50 at 162.155/186.674 us against fixed Quinn/netz servers and
Quinn-client p50 at 136.932/164.674 us. Its 0.844x/0.882x ratios moved in
opposite directions from the preceding capture, so no cross-process latency
gain is claimed from this separately packetized comparison.

Saturated equal-size receive queues now overwrite the oldest allocation in
place rather than temporarily retaining a `capacity + 1` payload block through
the recycle pool. A fail-first allocator test verifies the no-allocation
overwrite and FIFO order. Nine CPU-0 fixed-binary service-path pairs reduced
the 1,149-byte DATAGRAM median from 2,811 to 2,774 ns/packet (1.32%, 9/9 wins).
The queue now also enforces an independent cumulative payload-byte budget,
matching current Quinn's defense against many nonempty DATAGRAMs while retaining
the existing item cap for zero-length and metadata pressure. The default is 64
KiB; oldest entries are evicted until both limits admit a payload, while a
single payload larger than the budget is dropped without disturbing older
entries. Allocation failure before replacement leaves the FIFO unchanged, an
equal-sized eviction remains allocation-free, and direct caller-buffer or
borrowed-visitor delivery bypasses the queue. Public configuration and stats
expose the byte cap and current queued payload bytes alongside item counts and
drop accounting.

A synchronous borrowed DATAGRAM batch visitor now applies and cumulatively
acknowledges caller-buffer packets while delivering payload views without a
queue or application-buffer copy. It retains callback-bounded lifetimes and
rejects recursive receives. Nine alternating copy/borrowed modes in one frozen
binary moved the 1,149-byte median from 2,694 to 2,626 ns/packet (2.52%, 9/9).

Vail now provides a self-contained prepared AES-GCM context that caches the
expanded AES key and GHASH table, replacing its optional external backend.
Nine ARM64 fixed-binary pairs moved the same receive shape from 2,771 to 2,754
ns/packet (0.61%, 8/9 wins); x86_64 additionally uses Vail's
VAES/VPCLMULQDQ path. Vail's follow-up ARM64 16-block PMULL reduction then
moved the median from 2,752 to 2,606 ns/packet (5.31%, 9/9 wins); seven
short-packet pairs improved prepared AES-128 seal/open by 34.5%/23.3% and
AES-256 by 24.5%/19.2%, with every pair faster. The netz build no longer
exposes obsolete AWS-LC flags.

The real-handshake STREAM benchmark now uses zio-backed `std.Io` for every
mode. Aggregate connection workers share that backend through `std.Io.Group`;
the public benchmark no longer creates OS-thread or Threaded-I/O fallbacks.

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
`SharedReplayFilter`. The shared endpoint server now installs a lazily allocated
16,384-entry filter by default whenever Retry or NEW_TOKEN authentication is
configured without an explicit filter; an explicit caller-owned filter wins,
and a zero endpoint capacity deliberately retains the low-level stateless
policy. Retry and NEW_TOKEN inputs are authenticated and checked
for lifetime, version, peer address, and applicable ODCID/RSCID bindings before
the filter atomically remembers the validated fingerprint. Consequently, of
concurrent attempts to reuse one valid token, at most one passes the local gate;
the others fail as invalid packets before TLS processing or a server flight.
The filter remains caller-sized when explicitly supplied and supports snapshot
export/restore, but it does not claim distributed coordination, external durable
storage, or external-peer replay/expiry coverage.
Endpoint UDP receive paths now also treat operation-level `MessageOversize`
as an unauthenticated asynchronous ICMP Packet-Too-Big/Fragmentation-Needed
hint and retry the socket, matching Quinn's DPLPMTUD policy. Owned,
caller-buffer, GRO-batch, and receive-many paths share that rule; timed retries
retain one absolute deadline, while an actually truncated data/control message
still fails with `DatagramTooLarge` through `MSG_TRUNC`/`MSG_CTRUNC`.
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
PMTU probe construction now writes the canonical PING-plus-PADDING payload
directly into the connection's protected-packet buffer instead of allocating
and freeing a probe-sized temporary list on every search step. Recovery still
excludes probe payload while sent-packet metadata records its identity before
the socket write. A real UDP regression sends and retires one probe, then
re-arms the same size under an allocator that rejects all new allocations; the
second exact-size probe succeeds with stable packet-scratch pointers.
The full 2,958-test Netz suite and both quic-go and s2n-quic transport matrices
remain green after the change.
Ready PMTU probes now also participate in the connection and endpoint timer
schedule instead of depending on unrelated application traffic to call the
low-level probe API. This starts the initial search automatically, continues
multi-step searches after ACK or loss feedback, and transmits a new probe when
the 600-second raise timer reopens a completed search. Congestion, pacing, and
anti-amplification limits retain probe readiness behind bounded retry deadlines
so a blocked path neither loses the search nor creates a zero-deadline event
loop. A synchronous local `EMSGSIZE`/configured datagram rejection belongs to
the exact unsent probe, so it lowers the search ceiling and retries a smaller
size instead of terminating the endpoint loop or repeating the impossible
datagram forever. Focused real-UDP regressions cover the initial interest,
blocked retry, exact send-size rejection, and dispatcher-owned raise-timer
path.
QUIC PMTU handling now also detects path MTU black holes from ordinary
non-probe loss bursts instead of only explicit probe loss. The implementation
records the protected datagram size for each sent packet, clears black-hole
evidence selectively when a later ACK disproves it, and evaluates each complete
contiguous non-probe loss burst by its smallest datagram. A burst containing a
base-sized packet is therefore ordinary congestion rather than MTU evidence
regardless of whether the large or small loss is reported first; PMTU probes do
not bridge two ordinary bursts. Suspicious bursts retain their individual
minimum sizes in bounded state, so a successful non-probe datagram removes
every burst no larger than itself even when that ACK is below the current PMTU;
larger bursts remain evidence. After the fourth distinct all-large burst, the
path falls back to the base 1200-byte QUIC datagram size and rearms probing only
after a 60-second cooldown. Completed searches
separately re-arm a safe reprobe after 600 seconds. When PMTU changes, the
1-RTT connection immediately
retunes congestion and pacing datagram-size assumptions so steady-state burst
and cwnd heuristics remain coherent with the new path size. Dedicated
PING/PADDING probes stay outside generic retransmission ownership; their sent
metadata retains an independent loss timer, so a lost lone probe is retried by
the PMTU search rather than accidentally resurfacing as an ordinary PTO packet.
Disabling active discovery now disables only those probes and timers: a path
configured above 1200 bytes still uses the same bounded ACK/loss detector and
falls back passively after four qualifying bursts, while a later path reset
restores the configured initial size.
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
built frame. The standalone SETTINGS frame encoder likewise computes and
reserves its complete header-plus-payload length before appending either part;
a fail-first exact-capacity regression proves allocation failure cannot expose
a partial frame, while a preallocated exact-size frame requires no growth.
Standalone QPACK Encoder Stream instructions and the two-integer field-section
prefix now apply the same rule: Huffman/raw string sizes are planned first and
the complete logical item is reserved once. Fail-first partial-capacity tests
prove that an allocation error exposes neither a truncated instruction nor a
half prefix, and exact-capacity paths perform no allocation. The dynamic-QPACK
handshake test records stable critical-scratch
capacity and backing pointers across steady-state instruction/feedback rounds;
a direct connection test forces the initial SETTINGS allocation to fail and
verifies settings state, all critical stream offsets, prefix flags, and packet
number remain unchanged before a successful retry. The full 2,958-test Netz suite,
quic-zig QPACK gate, quic-go v1/v2 matrix, tquic normal/Retry/GOAWAY matrix, and
native wtransport matrix remain green. Five CPU-0 real-handshake 1-MiB upload
runs measured 104.96-109.62 MiB/s (108.17 MiB/s mean); this transfer-dominated
sample is a regression guard rather than a critical-stream speed claim.

The stateless literal field-section codec preserves an application's explicit
Never Indexed choice across exact static matches, static-name references, and
literal-name representations. Exact static matches are deliberately encoded
as literals with a static name reference because an Indexed Field Line has no
N bit; both allocating and single-allocation decoders retain the flag, and a
round-trip regression also covers lowercase normalization of literal names.
Its common path now plans up to 64 field representations on the stack, computes
the complete encoded length, and reserves output once before writing. Mixed-
case names use an allocation-free folded static-table lookup and are lowercased
directly into literal-name output; partial-capacity and exact-capacity tests
prove OOM rollback and zero-allocation encoding for representative blocks.
Dynamic field-section encoding now gives its output bytes and caller-visible
absolute-reference list one shared rollback boundary. A small-block regression
lets the prefix and a new reference commit internally, then fails the indexed
field write and verifies both caller-owned lists return to their original
contents; the existing large-block preflight tests cover its separate scratch
and reference-reservation failures.

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

The shared raw-QUIC server now supports endpoint-owned `preferred_address` on
either its primary UDP endpoint or a caller-owned secondary endpoint. Each
admission generates distinct sequence-0 and preferred sequence-1 CIDs, derives
both reset tokens from the endpoint key, and installs both pending routes before
the handshake worker can expose application traffic. The multi-endpoint owner
races both sockets while keeping one dispatcher, CID map, connection state, and
timer schedule; received datagrams retain their local endpoint provenance so
PATH_RESPONSE is sent from the address that received PATH_CHALLENGE, and
authenticated non-probing traffic commits later sends to that local endpoint.
Established servers register sequence 1 without emitting `NEW_CONNECTION_ID`;
clients copy and register the advertised CID during connection construction,
then select it for preferred-path validation. Real shared-server handshakes
cover both same-address CID rotation and migration to distinct IPv4 and IPv6
UDP endpoints: the client observes PATH_RESPONSE and a subsequent PING from the
advertised address,
while the server routes the client's sequence-1 traffic. The two-connection
gate proves preferred CIDs and reset tokens are not reused. Typed and raw
caller-supplied preferred parameters are rejected because their fixed CID cannot
be shared safely; secondary endpoints must share the server's I/O context and
remain caller-owned for its lifetime. Multi-endpoint visitor receives race both
sockets into separate reusable buffers, apply established packets in place, and
drain immediately ready datagrams up to the caller's batch bound; only the rare
second socket completion is copied into one preallocated retained slot so
canceling the receive race cannot lose it. Tests check callback payload
pointers, two-packet batch delivery, simultaneous-socket preservation,
callback-error state commitment, and source-correct stateless-reset responses.
The server can also encode IPv4 and IPv6 candidates together under the RFC's
single preferred CID/token when one family uses the primary endpoint and the
other uses the secondary endpoint, matching Quinn's separate v4/v6
configuration surface. Typed wire round-trip tests require both candidates,
and real handshakes verify each family both as a single-family advertisement
and as the selected candidate of a dual-stack advertisement. Low-level clients
can start preferred-address validation from a caller-owned local endpoint,
enabling IPv4-to-IPv6 and IPv6-to-IPv4 migration while one dispatcher serially
injects both sockets. Tests verify sequence-1 routing, delayed packets on the
retained old path, PATH_RESPONSE, subsequent traffic, wrong-family rollback,
and timeout restoration of peer address, CID, and local endpoint. New-path
packets that combine PATH_CHALLENGE with non-probing traffic now apply against
the prepared path state transactionally on both owning and visitor receives,
so committing the migration cannot discard the queued PATH_RESPONSE. A real
SOCKS5 gate carries an IPv6 preferred target through one IPv4 UDP relay,
accepts the client's first sequence-1 packet during the bounded
handshake-promotion window, completes PATH_CHALLENGE/PATH_RESPONSE, switches
the server's local endpoint, and exchanges a post-migration PING. Ordinary
pending sequence-0 CIDs retain strict original-peer isolation; only the
already-advertised alternate CID admits a new tuple before promotion, and the
established connection still authenticates it before changing path state. A
fresh 2026-11-01 `interop-http3-socks5-pool` run passed three origins, HTTP/1
discovery, four H3 requests, three TCP tunnels and one UDP association, with
two active/four total QUIC connections, domain-route limit 2, route churn,
remote DNS, a shared endpoint, TLS 1.3 and a complete close deadline; see
`docs/evidence/http3_socks5_pool/2026-11-01.json`. The
shared HTTP/3 client pool now owns an optional opposite-family endpoint and exposes
preferred migration through its lease. Its single receive owner races both
sockets with `std.Io.Select`, folds the dispatcher timer into the same absolute
deadline, preserves a simultaneous second datagram, and keeps its bounded
caller-buffer receive path from allocating owning UDP datagrams for established
packets. Real
IPv4-to-IPv6 and IPv6-to-IPv4 TLS/H3 coverage runs on zio through the `std.Io`
abstraction, validates the advertised sequence-1 path, sends a request/response
on the preferred family, then releases and re-acquires the same origin and
reuses the same connection. A
second zio test leaves the preferred address silent, observes all validation
retries and timeout rollback, and completes an H3 request on the original IPv4
path. Direct blocking `Connection.receive*` remains a per-connection API;
shared clients should use the pool's single receive owner.

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

The external certificate-verified handshake matrix now runs every netz endpoint
on zio behind `std.Io` and binds each sample, result, and server completion to
both endpoint runtimes, its endpoint role, and the configured timeout. A
2026-09-15 5 x 100 rerun measured client P50 at 1.365 ms for netz versus 1.044
ms for quic-go against a fixed quic-go server, and 0.981 versus 0.870 ms against
a fixed netz server. The zio client handshake path therefore remains a concrete
optimization target; historical Threaded ratios are not treated as zio results.
The HTTP/3 quic-go benchmark likewise now runs both netz endpoint roles on zio
behind `std.Io`. Its strict schema binds config, client-owned results, server
completion, and memory telemetry to both endpoint runtimes and rejects mixed
legacy data. QUIC v1 single-stream and QUIC v2 four-stream upload/download
matrices passed in both mixed role pairs; a zio-only v2 four-stream/RSS gate
also completed with exact bytes/checksum and zero retained netz allocator bytes.
The older throughput ranges remain pre-zio historical evidence until a full
fixed-binary comparison is recaptured.
The bidirectional tquic HTTP/3 process gate now follows the same runtime
boundary: both netz executables use zio and pass only `std.Io` into the
protocol stack. Its exact success records bind the netz endpoint to
`zio-std-io` and the audited tquic tools at `0169abde20c6` to their
`mio::Poll`/`mio::net::UdpSocket` loop (`tquic-mio`) for every ordinary, Retry,
and GOAWAY/drain scenario.
The fresh-handshake matrix now also has a self-contained Quinn/rustls peer at
the pinned audited revision. It verifies 2,200 full, non-resumed QUIC v1
handshakes across four role pairs with X25519, AES-128-GCM-SHA256, certificate
verification, a round-indexed echo, and peer close. Its explicit prepared-P256
mode now proves that QUIC honors the same caller-owned CertificateVerify hook as
ordinary TLS. Two mirrored 3x30 blocks reduced fixed-Quinn-server netz-client
P50 by 21.7% and 20.3%; prepared netz was 5.3% and 12.1% below the same-block
Quinn client. The default fresh-verifier results and both modes remain
same-security-policy rather than equal-wire claims.

Published Vail `73e2a4c` now routes Linux ARM64 ReleaseFast/ReleaseSafe P-256
Montgomery multiply and square through fixed `s2n-bignum` kernels while keeping
the portable implementation for Debug and ReleaseSmall. Eight fixed-binary
prepared-verifier pairs all improved, from a 35,642 to 29,458 ns midpoint
median (17.4%); the prepared benchmark added 5,080 bytes of `.text`. In the
fixed-Quinn-server netz-client handshake, instructions and the post-trust
interval improved in all eight mirrored pairs by median paired ratios of
0.913918 and 0.875768. Complete P50 improved in only five pairs (0.977508
median ratio), so the end-to-end result remains bounded support rather than a
general cross-stack claim; the handshake benchmark added 8,168 bytes of
`.text`. A zero-loss 1,000-sample follow-up profile removed portable field
multiplication from the hotspot list: P-256 time now concentrates in public
double-scalar comb/add/double work (14.72%), the new multiply kernel (4.13%),
and public-scalar inversion (2.52%), while X25519 variable/fixed loops retain
14.52%/3.71%. These are the next measured crypto targets; worker scheduling,
packetization, and the load-sensitive tail still need separate equal-wire
evidence before any whole-handshake superiority claim.

Published Vail `040193a` now also embeds the matching ARM64
Montgomery-Jacobian doubling and mixed-add schedules. ReleaseFast/ReleaseSafe
identity, equal, inverse, and deterministic double-scalar comparisons match
Zig std; Debug/ReleaseSmall remain portable, and the complete Vail plus x86_64
compile gates pass. Eight fixed-binary prepared-verifier pairs all improved
from a 29,531 to 17,808.5 ns midpoint median (39.70%); preparation improved
7.38%, and the GNU `size` text total fell 91,664 bytes because the calls replace
repeatedly inlined formulas. Against one fixed Quinn server and certificate,
netz client instructions improved in all eight mirrored pairs by 10.02% at the
median. Complete P50 improved in six pairs by an 8.23% median ratio, but timed
sums won only five, so latency remains bounded support rather than a universal
claim. The netz benchmark's GNU `size` text total fell 126,548 bytes.

The 1,000-connection follow-up profile removed the former 14.72%
`doubleScalarMulComb` entry. X25519 variable/fixed loops now account for
18.67%/3.68%, the complete prepared P-256 verifier body 8.76%, ARM64 mixed-add
4.08%, and point doubling only 0.42%. P-256 doubling is therefore closed as an
independent hotspot; the next crypto work must isolate public scalar inversion
or move to the now-larger X25519/non-crypto costs while the equal-wire and tail
scheduling gaps remain open.

Typed transport-parameter parsing now tracks the complete known ID set in one
word and keeps eight unknown/greasing IDs on the stack before allocating an
overflow list. This removes the former count pass and common per-extension seen
allocation without weakening duplicate detection, unknown-parameter handling,
directionality, or integer/value validation. Fail-first known, inline-unknown,
overflow-OOM, and duplicate-after-spill tests pass in Debug and ReleaseFast;
the broader filtered gate completed 158/158 steps and 153/153 tests. A
100-connection local handshake reduced allocations from 5,701 to 5,501,
exactly two per connection, and requested bytes by 57,468 with identical zero
live bytes and 56,031-byte peak. Eight fixed-Quinn-server pairs reduced client
instructions by a 0.998210 median ratio (6/8 wins), but complete P50 won only
3/8, so no latency gain is claimed. A 1,000-connection profile no longer
reported the former 2.63% typed-parser entry above 0.2%. A tested exact encoder
pre-reserve was discarded after a 4.69% paired P50 regression; only the
allocation-free common parser is retained.

Published Vail `209f58b` further adds BoringSSL/AWS-LC's ISC ARM64
variable-time BEEU schedule for the public P-256 signature scalar inverse;
secret signing keeps its constant-schedule implementation. ReleaseFast and
ReleaseSafe boundary plus deterministic differentials match the fixed-time
inverse, Debug/ReleaseSmall retain the portable path, and complete Vail plus
x86_64 compile gates pass. The component moved from 2,797 to 971 ns/op. Eight
fixed-binary prepared-verifier pairs all improved from 17,789.5 to 15,520.5 ns
(12.75%, 0.872092 paired ratio), while preparation stayed neutral. Against one
fixed Quinn server, client instructions improved in all eight pairs by 3.52%;
complete P50 split 4/8 at a 1.005035 ratio, so no whole-handshake latency gain
is claimed. A 1,000-connection profile now places X25519 variable/fixed loops
at 19.44%/4.26%, ahead of public scalar inversion at 2.98%; the latter is no
longer an independent implementation gap.

The generic RFC 9297 HTTP Datagram association now also has a typed RFC 9298
CONNECT-UDP layer across HTTP/1.1, HTTP/2, and HTTP/3. It implements the default
MASQUE URI Template with strict target validation and IPv6 percent encoding,
version-correct Upgrade or Extended CONNECT negotiation, Capsule-Protocol
validation, generic Context ID framing, Context ID 0 UDP payloads, and the
65,527-byte UDP ceiling. HTTP/3 preserves absolute deadlines across skipped
unknown contexts and aborts malformed input with H3_MESSAGE_ERROR. HTTP/2 and
HTTP/1.1 use a shared incremental DATAGRAM Capsule stream with bounded partial
input, unknown capsule/context skipping, and exact timed-write progress; errors
reset the H2 stream or abort the H1 connection. Real regressions cover H1
absolute-URI GET/101 negotiation and fragmented reads across a timeout, H2 DATA
fragmentation plus flow-control timeout/resume, and authenticated H3 SETTINGS
ordering and bidirectional routing. Configured Level-3 URI Templates support the
RFC 9298-legal simple, form-query and continuation operators plus extra scalar
variables; forbidden Level-2/3 operators and all Level-4 modifiers fail during
compilation. A second H3 Session in the same real exchange uses a query template
and application-selected server target, rather than treating custom templates
as the default path.
The adjacent `http3.connect_ip` module now implements the RFC 9484 protocol
core: strict wildcard/DNS/IP-prefix and `ipproto` scopes, default or configured
Level-3 URI Templates, Extended CONNECT metadata, Context ID 0 IP packet
framing, and caller-buffer ADDRESS_ASSIGN, ADDRESS_REQUEST, and ordered
ROUTE_ADVERTISEMENT Capsule codecs. Malformed address families, non-network
prefixes, zero or per-Capsule duplicate emitted Request IDs,
reversed/overlapping routes, and short output are rejected transactionally.
An allocation-free packet view validates IPv4 header/total lengths and IPv6
payload lengths, extracts source/destination addresses, follows the RFC 8200
Hop-by-Hop, Routing, Fragment, Authentication, and Destination Options chain,
and recognizes encrypted ESP as opaque. A non-initial fragment or ESP packet
with no statelessly visible final protocol remains unresolved and is
eligible only for a protocol-zero route; forwarding helpers also decrement
IPv4 TTL with a recomputed header checksum or IPv6 Hop Limit.
Encrypted HTTP/1.1 and HTTP/2 typed Sessions now multiplex configuration and IP
packet Capsules without implicit event loss. The authenticated HTTP/3 Session
retains its streaming CONNECT reader for ADDRESS/ROUTE Capsules while routing
Context ID 0 through QUIC DATAGRAM, including either-plane-first delivery and
bidirectional FIN. Its EndpointServer surface has matching one-attempt accept,
send, poll, and close APIs; the dispatcher remains the sole UDP reader and
hands the typed Session explicit FIN observation. A new offline-locked process
gate, `zig build interop-connect-ip-h3 -Doptimize=ReleaseFast`, uses the audited
`~/Work/h3` `Protocol::CONNECT_IP` token plus an independent Rust
ADDRESS_REQUEST/ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT, and Context-ID codec. Netz
and h3/Quinn each run as client and server, exchange an advertised route and
empty-snapshot withdrawal plus policy-matching 20-byte IPv4 packets in both
directions with delivery ack, and independently observe request and response
FIN before connection shutdown.
An optional per-tunnel `ConfigurationState` adds the cross-Capsule rules that a
stateless codec cannot enforce: lifetime Request ID uniqueness, bounded
assignment/route snapshots in both directions, empty-list withdrawal, and
two-phase local ID and snapshot commit across timed writes. Outgoing nonzero
assignment IDs must correlate to peer requests; peer updates are transactional;
and symmetric source/route queries include RFC 9484's ICMP exception. H1/H2
`localPacketAllowed` and `peerPacketAllowed` queries consume the parsed packet
view directly, including IPv6 extension traversal and unresolved-protocol
fail-closed behavior. H1/H2 payload-only reads cannot bypass configuration
validation or state application,
and a local allocation failure leaves the Capsule retryable without a false
protocol reset. Kernel interface and forwarding policy remain
application-owned.
Parsed request scopes additionally classify packets as allowed, denied,
requiring caller-owned DNS resolution, or requiring fragment reassembly.
Literal IPv4/IPv6 prefixes and extension-aware `ipproto` values are enforced
directly with the RFC 9484 ICMP exception; reg-name scopes can consume an
authoritative resolved-address set without embedding resolver policy in the
protocol core. The h3/Quinn matrix now uses a restricted
`203.0.113.0%2F24`/TCP request instead of a wildcard and checks the actual
client packet against it in both Netz endpoint roles.
H1/H2 Capsule Sessions additionally expose caller-buffer receive with
non-consuming BufferTooShort retries. An offline-locked Hyper process matrix
independently validates both endpoint roles over cleartext and TLS for both
versions, including H2 Extended CONNECT settings, H1 Upgrade, multi-byte
Capsule lengths, fragmentation, and unknown extension skipping.
An offline-locked `~/Work/h3`/Quinn matrix independently verifies both H3
endpoint roles, SETTINGS, unknown and Context ID 0 datagrams, real UDP proxying,
application delivery acknowledgment, and request/response FIN ordering.
The Capsule CONNECT-UDP layer also exposes a caller-owned UDP relay:
target resolution and authorization remain application policy, while the relay
preserves datagram boundaries, filters unexpected sources, handles empty and
truncated packets, reports directional/drop counters, and terminates on typed
peer-close, cancellation, deadline, or forwarding-limit reasons. One
cancel-safe select serializes Session ownership so H2 flow-control writes do not
race an independent reader. H3 typed Sessions match the caller-buffer receive
surface and retain complete payloads across short-output retries, but blocking
H3 receive owns endpoint progress; generic blocking relay explicitly returns
`DispatcherRequired`, and H3 proxy loops remain under their dispatcher/session
owner.
`http3.runtime.ConnectUdpDispatcherRelay` supplies that production H3 loop for
shared endpoints without transferring QUIC receive ownership away from
`EndpointServer`. It binds stable relay state to connection handle plus CONNECT
stream ID, races the single dispatcher read with bounded per-target UDP reads,
rotates the starting relay, and limits work per relay per turn. Target replies
blocked by pacing or congestion enter a bounded FIFO; overflow, truncation, and
unexpected-source drops are counted separately. Applications still resolve and
authorize every target before registering its socket. A real regression uses
one H3 connection, two simultaneous CONNECT-UDP streams, and two UDP echo
targets, and verifies queued interleaving, unknown Context handling, exact
directional counters, request reset, response FIN, and deterministic teardown.

| Area from `~/Work/quicz` examples | netz status | Evidence | Remaining work |
| --- | --- | --- | --- |
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered with local and cross-process latency evidence plus an equal-CPU-layout quic-go throughput harness | `examples/quic/quic_echo.zig`, `examples/benchmarks/bench_quic_handshake_stream.zig`, `bench-quic-quic-go`, and `bench-quic-persistent-external`; CPU-0-pinned local netz P50/P99/P99.9 echo ranges were 10.44-10.57 / 15.22-15.53 / 31.89-47.02 us versus quicz 10.5-10.7 / 16.0-19.5 / 206.3-211.2 us. The certificate-verified two-process persistent 1-KiB echo keeps one request outstanding: five historical pre-zio runs gave netz-client median P50 24.172 us versus quic-go-client 25.851 us against a fixed quic-go server (1.069x), and 23.729 versus 24.361 us against a fixed netz server (1.027x). The fresh-connection throughput harness pins client/server separately, runs both sender roles, and requires exact FIN/bytes/checksum for 1 and 4 unidirectional streams. Its netz endpoints and persistent netz endpoints now run on zio behind `std.Io`; strict result, completion, socket, and memory validation rejects legacy or mismatched backend identities. Complete-connection userspace socket accounting is also available. All external comparisons remain `same-application-shape`, and historical Threaded ratios are not zio results. | Re-run the cross-library matrices on zio, then add kernel/interface capture on a permitted host and equalize GRO, ACK/pacing, packetization, and application scheduling before a general STREAM ratio. |
| QUIC TLS 1.3 handshake latency/rate (`quic_bench_hs`) | Covered with authenticated and quicz-aligned modes | `examples/benchmarks/bench_quic_handshake_stream.zig`, `--mode=handshake`; verified samples sustained 824.1-830.7 conn/s with P50 1172.1 us. `--skip-server-verification` retains Certificate/signing while matching quicz client policy; five CPU-0 runs measured P50 657.9-833.0 us and median 881.9 conn/s versus three quicz runs at P50 800.3-811.9 us and median 749.3 conn/s. Exact Initial sizing cut allocator calls from 167.0 to 92.0 per connection. Direct client/server and caller-supplied datagram-source paths expose relative-timeout and absolute-deadline variants; server variants also cover a pre-received Initial. One awake-clock timestamp covers Initial, fragmented Initial CRYPTO, Retry, Version Negotiation or optional standalone 0-RTT, and all active/passive TLS flights while retaining an earlier configured recovery deadline. Before address validation, server Initial/Handshake flights, PTO retransmissions, and protocol-error closes share an exact full-datagram 3x receive budget; valid Retry/NEW_TOKEN or an authenticated client Handshake packet removes that limit. A silent-client regression starts with one 1200-byte tokenless Initial and proves multiple PTO attempts never emit more than 3600 bytes. Every protected 0-RTT attempt consumes its one-shot ticket and packet number even if the UDP socket reports zero progress. Successfully transmitted PTO copies are imported into the shared application-data packet-number space after acceptance, share one recovery payload group, and can be acknowledged independently; rejected or pre-Retry 0-RTT still advances the first 1-RTT packet number without retaining stream/flow state or becoming ACK-valid. The typed HTTP/3 early-request helper emits SETTINGS plus both QPACK critical-stream prefixes with one complete literal/static-QPACK request, explicitly reports accepted versus rejected so replay remains an application decision, restores request response semantics and stream cursors after acceptance, routes server-side preloaded early streams before blocking reads, and rejects reduced remembered HTTP/3 SETTINGS. RFC 8470 construction is safe-method-only unless the application explicitly opts into unsafe replay; accepted STREAM provenance reaches aggregate, incremental, and endpoint-handler requests as `was_early_data`, remains true across 1-RTT continuation, and stays absent from rejected or ordinary 1-RTT requests. Real-handshake loss tests require the first 1-RTT packet to follow the dynamically observed 0-RTT copy count. | Equalize worker scheduling and reduce p99 variance before a whole-surface handshake claim. |
| QUIC stream-open churn (`quic_bench_hs`) | Covered and faster for the reference reservation workload; on-wire peer-stream renewal and mixed FIN/reset churn are verified under clean, bidirectional-loss, and bidirectional-reorder schedules | `examples/benchmarks/bench_quic_handshake_stream.zig`, `--mode=stream-churn`; CPU-0-pinned netz sustained 680.2-778.0M streams/s versus quicz 48.1-52.0M streams/s, a 13.1-16.2x range. IDs, limit enforcement, both endpoint roles, zero timed-loop allocation, final ID and checksum are validated. `openStreamWith{Timeout,Deadline}` and the unidirectional counterparts wait for authenticated cumulative MAX_STREAMS while pumping packets and QUIC timers under one absolute awake-clock deadline; timeout and invalid-clock rejection leave the next ID untouched. The original open APIs remain immediate and return `StreamLimitExceeded`. `Connection.pollOpenStream`/`pollOpenUnidirectionalStream` and the handle-based dispatcher counterparts instead reserve only already-available credit: they never read the UDP socket, wait, emit STREAMS_BLOCKED, or advance a blocked cursor, and dispatcher calls refresh the centralized timer even on close errors. Tests route authenticated bidi and uni MAX_STREAMS through the sole dispatcher receive owner before polling succeeds. `--mode=lifecycle-churn` keeps a bounded concurrent credit set, alternates one-byte FIN/echo and RESET_STREAM with exact codes, and requires cumulative MAX_STREAMS before reusing each batch. Its two-endpoint receive wait uses the earliest timer from either connection and no fixed polling quantum. A 128-stream/16-credit smoke verified clean, seeded 5% loss in both directions (14/276 and 16/284 injected drops), and every-fifth-datagram bidirectional reordering (45/228 and 45/227 holds), including exact terminal counts, final stream ID, checksum, and injection counts. The production batch-release API emits one cumulative MAX_STREAMS packet for up to 64 completed streams instead of one packet each, but only after the local FIN or RESET_STREAM and preceding reliable stream data are acknowledged; an early application release request is retained and flushed by the ACK path. Released peer and local streams are removed from active send/receive maps, each stream-number space collapses sequential IDs into a watermark and sparse closures into merged ranges, late frames cannot recreate upper-protocol state, failed automatic credit sends retry from the aggregate connection timer, and ID-based pagination remains stable across swap removal. The quic-go process gate separately advertises one bidirectional stream and requires completed streams 0, 4, 8, and 12. | Add an equal quicz on-wire lifecycle harness before claiming a cross-stack throughput ratio. |
| QUIC concurrent aggregate (`quic_bench_hs`) | Covered for four independent connections, including an external quic-go process matrix and a shared-socket event loop | `examples/benchmarks/bench_quic_handshake_stream.zig`, `--mode=aggregate --connections=4 --transfer-bytes=67108864`, and `bench-quic-persistent-external --mode=aggregate`; the internal netz run completed at 730.35-900.57 MiB/s versus quicz 503.23-533.10 MB/s. The external five-run 4 x 1-MiB matrix pins client/server processes to separate CPUs, starts every connection through one GO barrier, and validates 40 client results plus 40 server completions. With a fixed quic-go peer, final-schema runs measured netz senders at 152.580 and 149.825 MiB/s medians versus quic-go's 111.179 and 112.307 MiB/s (1.372x/1.334x). The original netz/netz control fell to 73.333/66.736 MiB/s in the other two fixed-endpoint comparisons, exposing same-process single-CPU worker contention rather than supporting a universal claim. A production shared-server topology now routes up to sixteen benchmark connections over one UDP socket. Its caller-buffer visitor avoids owning receive allocations for warmed current-key packets and applies ACK policy inside the server adapter. A Quinn-style bounded ready-message drain (32-message default) additionally amortizes wait/poll and dispatcher scheduling while preserving Initial-admission and callback-error suffixes in an owning FIFO. The strict result schema records the batch size. A same-binary five-sample 4 x 1-MiB comparison improved median throughput from 70.990 to 86.325 MiB/s (21.6%); ranges were 66.467-80.259 and 51.544-97.483 MiB/s, so host scheduling noise is explicitly retained. Batch-32 smokes reached 92.107 MiB/s for eight connections and 78.435 MiB/s for sixteen, with exact bytes/checksum/completion in every run. Negotiated client-only ACK_FREQUENCY then moved a five-pair 16-connection upload median from 57.579 to 76.974 MiB/s (33.7%, 4/5 wins) and reduced the server UDP-send median 59.4%; overlapping ranges and a mixed reverse-direction control limit this to workload-specific evidence. Local CID pools additionally expose a transactional active-set revision, letting ordinary packets skip the full router reconciliation; a four-CID ReleaseFast ABBA microbenchmark reduced that call from 627-637 to 9 ns (66.01-66.92x). Connections with a handshake-coalesced application datagram now notify a stable dispatcher-owned ready index instead of forcing every receive turn to scan the whole connection table. The callback remains valid across dispatcher and connection moves and is removed before unregister/deinit. Three CPU-0 fixed-binary runs reduced an empty 1,024-connection lookup from 4848.59 ns median to 0.76 ns (about 6,380x); this is an isolated scheduler result, not a whole-transfer throughput claim. Bounded `Connection.sendWith{Timeout,Deadline}` now handles flow/congestion backpressure through the state-only receive path, so reliable credit packets are ACKed and unrelated application data stays buffered. Receive reassembly measures its bound from the application cursor rather than retained consumed storage, and recovery groups with no in-flight copies expose a stable immediate PTO. A pre-fix 16 x 9-MiB shared upload completed only 15/16 connections and left the last at 8,387,712 bytes; three post-fix upload/download runs all completed 150,994,944 bytes with checksum 19,251,855,360. | Compare shared-socket event loops against an independently maintained peer with equivalent socket ownership and capture equal-wire traffic before generalizing the throughput result. |

The raw QUIC throughput, persistent, mixed FIN/reset churn, fresh-handshake,
handshake-fault, and complete lifecycle quic-go executables now share the repository-owned
`tools/interop/quic_go_module`, pinned to quic-go v0.59.0 by `go.mod` and
`go.sum`. Their runners use `GOTOOLCHAIN=local` and `-mod=readonly`, removing
the old dependency on a mutable `~/Work/quicz` module checkout. The lifecycle
client and server retain all 19 existing echo, Retry, key-update, stream
cancellation/flow/limit, PTO, close, migration, migration-loss, and NAT
rebinding scenarios. The handshake-fault gate's repository-owned peers cover
all 16 v1/v2, loss/corruption, client/server-outbound, and endpoint-role
combinations with exact fault and application-close verification.
| QUIC simulated loss (`quic_bench_hs`) | Covered and faster for all four reference scenarios | `examples/benchmarks/bench_quic_handshake_stream.zig`, `--mode=loss`; 1%/5% loopback and 1%/5% with 100 us RTT were conservatively 1.08-1.45x faster than quicz, with deterministic injected-drop counts, full 4 MiB receiver completion, transport loss counters and optional memory telemetry. | Add bidirectional loss, reordering and corruption cases before generalizing beyond the reference one-way loss model. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered with native s2n-quic and Quinn process interop plus fixed-peer Quinn latency evidence; faster than the historical current-quicz DATAGRAM sample | `examples/quic/quic_datagram_echo.zig`, `examples/benchmarks/bench_quic_datagram.zig`, `examples/benchmarks/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo`, `zig build bench-quic-datagram -Doptimize=ReleaseFast`, `zig build interop-quic-s2n -Doptimize=ReleaseFast`, `zig build interop-quic-quinn -Doptimize=ReleaseFast`, and `zig build bench-quic-datagram-quinn -Doptimize=ReleaseFast -- --samples=5 --warmup=200 --iterations=5000`. DATAGRAM packets remain ACK-eliciting and congestion-controlled but RFC 9221 payload bytes no longer enter the retransmission cache: pure-DATAGRAM PTO sends a fresh PING, and mixed packets retain only reliable frames. Both native-peer gates cover both endpoint-role pairings, unordered payload sets, exact boundaries, local oversized rejection, reliable stream 4, and application close. The Quinn gate additionally makes netz the outbound sender in both roles under deterministic first-DATAGRAM loss and real pair reordering. Batch sends pack multiple DATAGRAM frames up to the MTU/frame cap while preserving exact logical-prefix progress after partial socket sends; their pure-DATAGRAM specialization skips generic STREAM/recovery bookkeeping without bypassing congestion, pacing, ECN, anti-amplification, key update, or nonce accounting. Batch validation computes the invariant negotiated/path payload limit once, then skips duplicate packet-plan materialization only when the worst-case packet-number range is legal and keeps one encoded width; boundary widths, exhaustion, and pending control frames retain exact preflight. Caller-buffer batch receive drains up to 64 UDP messages or GRO segments under one deadline and one cumulative ACK decision. Connection-level single-packet APIs now adapt GRO through the owning endpoint path, copy only the current segment into connection scratch, and preserve the remaining shared-buffer segments for later STREAM, control, or DATAGRAM processing; low-level endpoint caller-buffer APIs retain their explicit ownership error. A mixed STREAM/DATAGRAM GSO regression covers timed and untimed connection receive paths. The windowed Quinn benchmark enables netz GRO only when `window > 1`. A 2026-10-13 post-rebase three-sample 1,024-byte/window-16 matrix measured netz/Quinn p50 at 125.436/137.010 us with a fixed Quinn server (netz 1.092x), and 122.973/122.390 us with a fixed netz server (netz 0.995x). This closes the previously recorded p50 gap for that bounded shape without turning three samples into a universal claim. The original one-outstanding and earlier non-GRO results remain separately scoped. | Add longer/lossy windows and independent-peer outbound fault injection when an audited peer exposes a deterministic hook. |
| Graceful/application close (`graceful_close`, close lifecycle) | Covered by local tests/examples and exact bidirectional quic-go process checks | `examples/quic/quic_close.zig`, one_rtt lifecycle tests, `zig build run-quic-close`, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; netz validates quic-go's peer application close code 57/reason `quic-go interop complete`, while quic-go validates netz code 58/reason `netz interop complete` | Add long-lived graceful shutdown/draining timing only if application shutdown workloads require it. |
| Packet protection / initial keys / key update | Covered by modules, tests, and quic-go process interop | `src/quic/protection.zig`, `src/quic/zero_rtt`, `src/quic/one_rtt/tests/basic.zig`, `src/quic/one_rtt/tests/crypto_path.zig`, `zig build test`, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; the external gate has netz initiate two ACK-gated 1-RTT key updates, verifies both local and peer update counters reach two and both phases return to zero, while quic-go decrypts and echoes one fresh stream in each generation. A connection-level test now sends and receives a FIN-terminated STREAM, advances Key Phase, and receives another STREAM for AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, ChaCha20-Poly1305/SHA-256, and SM4-GCM/SM3. Netz delegates next-secret derivation to Vail's suite-aware QUIC implementation, closing the former SM3 key-update initialization trap. Authenticated and preconfigured `EstablishedConnection` values retain and expose their negotiated cipher suite/hash and forward key-update control, local/peer counts, and the ACK gate without requiring callers to reach into the packet engine. | Keep vector and external coverage current as TLS suites evolve. |
| Loss recovery / PTO / retransmission | Partially covered and improved, with two-peer process evidence | Recovery tests cover timer-driven losses and bounded payload caching; recovery also validates then streams arbitrary ACK range counts without a decoded-range allocation, unlike the audited quicz allocating ACK decode. Ordered original-only recovery queues merge fragmented ACK ranges in O(packets+ranges), while retransmission and out-of-order cases retain the conservative membership scan; a fixed-binary 128-packet/64-range benchmark improved 2.69x with 7/7 paired wins. ACK_FREQUENCY capabilities are directional: only the endpoint that advertised `min_ack_delay` accepts the peer's requests, and only a peer advertisement enables local sends. An opt-in request is appended to the first non-empty 1-RTT packet, remains pending across socket failure, and enters ordinary PTO recovery only after a successful send; wire tolerance three becomes a local fourth-packet ACK trigger. New requests are transactionally rejected with PROTOCOL_VIOLATION when Requested Max Ack Delay is below that advertised minimum or at least 2^14 milliseconds; obsolete sequence numbers remain ignored, while zero Ack-Eliciting/Reordering Threshold values retain their specified meanings. Established 1-RTT connections optionally apply independently seeded, bounded PTO jitter (0–50%) using a stable per-arm epoch, so repeated scheduler reads cannot move an armed deadline; zero remains deterministic and consumes no entropy, and the separate pre-establishment handshake retransmission timer is unchanged. Receive preflight uses packet-local path/stream shadows instead of cloning heap-backed path-validation state per packet. A one-STREAM packet now keeps the same transactional `RecvState.Preflight` checks but skips the unrelated multi-stream, connection-ID, and path-validation shadows; seven CPU-0 order-alternated pairs reduced the visitor median from 1328 to 1308 ns/packet (1.5%) and service from 1336 to 1298 ns/packet (2.8%), with every pair faster, while five padding pairs moved only from 1397 to 1395 ns/packet (0.1%, noise-level). `RecvState` also packs received-byte presence into capacity-retaining machine words instead of one bool byte per buffered byte. Against the preflight-fast baseline, five visitor pairs reduced the median from 1324 to 1166 ns/packet (11.9%) and seven service pairs from 1328 to 1172 ns/packet (11.7%), with every pair faster; the STREAM profile's `memset` share fell from about 11.5% to 0.22%. Ordered non-overlapping STREAM frames also skip bytewise duplicate scans, while retransmission overlap retains strict conflict accounting. Recovery payloads keep four direct power-of-two blocks per class and use payload-intrusive O(1) overflow lists under the existing 1 MiB cap, allowing a dominant 4-KiB class to absorb ACK bursts without per-block metadata. The recovery queue no longer maintains two hash indexes on every send and rebuilds them on every ACK; its hot ordered scans stay contiguous, monotonic packet-number insertion is O(1), and rare direct lookups scan the bounded in-flight queue. ACK compaction scans entries by pointer, recycles matches in place, and copies only survivors that move; a clean twenty-pair A/B measured +8.6% mean/+14.4% median. Clean single-range ACKs with no retransmission copies now binary-search the monotonic original-packet queue and recycle one selected slice, while multi-range ACKs use the linear merge; retransmission/unsorted cases preserve the scan fallback. Loss-timer queries reuse the cached latest ACK-eliciting packet when it is ordinary data and scan only when a PMTU probe owns that cache; the next five-pair CPU-0 A/B improved the same H3 workload another 7.5% mean/7.4% median and reduced timer self samples from 13.5% to 2.0%. The next RFC 9002 time-threshold loss deadline is now also retained when ACK/loss, RTT, PMTU, or path state changes, matching Quinn, quiche, and tquic instead of rescanning every retained sent-packet record on each endpoint timer refresh. Seven fixed-binary CPU-0 pairs reduced a 256-record/255-ACKed-record, one-gap full connection timer query from 125.12-126.58 ns to 3.08-3.11 ns (40.8x at the median, 7/7 wins); five shared-server transfer pairs moved the client-sender median from 62.744 to 60.822 MiB/s with 2/5 wins and the server-sender median from 80.275 to 82.260 MiB/s with 4/5 wins. Both ranges overlap, so the raw transfer result is supporting evidence rather than a general throughput claim. Five fixed-binary H3 pairs moved four-stream upload median from 130.87 to 134.64 MiB/s with 5/5 wins, while the equal-wire cross-stack gap remains open. ACK processing also compares monotonic acknowledged-ECT and validated ACK_ECN watermarks in O(1), preserving the result after packet-metadata compaction; the following captured five-pair A/B improved mean/median another 10.5%/13.7% and removed the prior 2.7% scan from the profile. Single-ACK packets now reuse their shape-bound transactional precheck summary during apply, avoiding a second metadata scan while multi-frame packets preserve independent validation; two clean order-balanced ten-pair sets measured +3.4% for both mean and median and reduced `precheckAckRanges` samples from 5.35% to 1.67%. Sent-packet metadata compaction now clears its best-effort exact index in O(1), rather than removing retired keys and rewriting every survivor; two clean twenty-pair sets measured +7.3% mean/+2.6% median and removed `refreshPacketIndexFrom` from the profile. Single-packet send preparation also folds wire length, recovery length, flight/ACK traits, HANDSHAKE_DONE detection, and largest-ACK observation into one frame pass; a clean twenty-pair A/B measured +10.6% mean and removed standalone `Frame.wireLen` from the top profile. The preceding five-pair steps improved it by 33.8% and 28.5%; 5% packet-loss runs remained throughput-neutral while recovering every byte. Thread-safe telemetry after the first step reduced median allocations 29.6%, exact 4-KiB allocations 49.6%, cumulative allocated bytes 22.0%, and peak live bytes 15.5%. The real-handshake raw STREAM gate reorders every fifth client datagram and verifies all 4 MiB; a corruption mode flips authenticated ciphertext in exactly 25/504 datagrams and recovers all data. The quic-go process gate independently drops four netz server datagrams during Initial flight and four after application STREAM data. Separate s2n-quic connections drop netz's first post-arm RESET_STREAM or STOP_SENDING datagram and require the exact cancellation code after recovery. | Add broader reordering/corruption distributions and long-run recovery benchmarks; aggressive non-default packet/body sizing still needs separate coverage. |
| Flow control / stream reset / STOP_SENDING | Covered by implementation, tests, and two external QUIC peers, including cancellation loss, reordering, and bounded mixed churn | `src/quic/flow_control.zig`, `src/quic/stream.zig`, one_rtt tests, `zig build interop-quic-quic-go -Doptimize=ReleaseFast`, `zig build interop-quic-s2n -Doptimize=ReleaseFast`, and `zig build interop-http3-quic-go -Doptimize=ReleaseFast`; the raw external clients send RESET_STREAM error 41, separately observe STOP_SENDING error 42 and return RESET_STREAM error 42, and prove a concurrent stream 4 remains usable. Both external matrices transfer/echo 12 KiB through advertised 8 KiB connection and 2 KiB stream windows; the s2n-quic case also requires netz to observe actual flow-control blocking before credit advances. Receive-side connection `MAX_DATA` accounting follows RFC 9000's sum of each stream's highest received offset: sparse STREAM gaps consume credit, lower-offset gap fills and retransmissions do not consume it again, and RESET_STREAM charges only the remaining distance to its final size. Encrypted-packet regressions cover the single-STREAM fast path, mixed STREAM/RESET multi-frame preflight and rollback, and reordered data after reset. This closes a sparse-offset credit bypass still present in the audited quicz implementation, which counts newly stored payload bytes. `one_rtt.Connection.pollStream` exposes allocation-free, socket-free data/FIN/reset events for dispatcher loops, returns receive credit as bytes are copied, reports zero-length FIN plus RESET_STREAM exactly once, and rotates across ready streams so one busy stream cannot starve its siblings. `pollStreamId` provides targeted access without disturbing that fair cursor. An opt-in `enable_reset_partial_delivery` policy now drains the contiguous prefix buffered when RESET_STREAM arrives, including across small caller buffers and targeted polling, before reporting the reset exactly once. Later reordered STREAM data remains transport validation state and is never delivered after that reset boundary. The default remains reset-first and retains unread transport bytes only for reordered/duplicate validation. Handshake-created connections propagate the same policy. Matching blocking, relative-timeout, and absolute-deadline receive methods use the timer-aware packet service loop and retain partial stream state across timeout. Separate s2n-quic connections drop or reorder netz's first post-arm RESET_STREAM(41) and STOP_SENDING(42). The reorder cases use the production send interceptor to hold the exact cancellation datagram, send the sibling STREAM first, then flush the held packet; both endpoint-role directions require `held_cancel_datagrams=1`, exact peer-visible codes, sibling-before-cancel completion, and final application close. A separate s2n case in each endpoint-role direction verifies 32 concurrent streams after a common prefix, with 16 full 16-KiB FIN completions and 16 index-coded resets; both peers independently match total bytes, checksum, reset mask/code sum, and final close. The clean pair covers both sender directions; loss and real pair-reorder variants make netz the outbound sender in both endpoint roles. The fault variants use explicit reset/FIN phase markers and require one netz outbound fault per phase, while retaining exact terminal verification after recovery; they do not inject s2n-quic outbound faults. The quic-go matrix additionally advances from stream 0 through 12 under an initial one-stream limit. The HTTP/3 gate drops the first H3_REQUEST_CANCELLED STOP_SENDING in each direction and requires retransmission, exact sender observation, and completion of a concurrent sibling under fixed flow-control windows. | Extend mixed-churn duration/distributions and add independent-peer outbound fault injection when the peer exposes a deterministic hook. |
| Connection IDs / stateless reset / path validation / migration | Covered in modules/tests with external active-migration and NAT-rebinding gates | `src/quic/connection_id.zig`, `src/quic/stateless_reset.zig`, `src/quic/path_validation.zig`, lifecycle tests, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; on accepted peer tuples, every ordinary owning, borrowed/timer-aware, batch, and routed 1-RTT receive path checks active peer reset tokens only after authentication fails, enters draining for three current PTOs, and excludes matching resets from the AEAD integrity counter. RFC 9000's endpoint-role asymmetry is enforced before decryption: clients silently discard unknown server tuples; servers retain authenticated client NAT rebinding/migration unless their own advertised `disable_active_migration` policy chooses RFC 9000's drop behavior for new client IPs. The peer's parameter remains distinct and only constrains local active migration. These drops do not change packet-number, stream, key-update, path, AEAD-failure, or telemetry state. CID routing itself no longer treats unauthenticated source addresses as connection errors, and the dispatcher consumes both established-path policy drops and pending-handshake peer mismatches. The shared server now offers an explicit endpoint reset key; when enabled it derives the handshake transport-parameter token and every local CID token from that same key, rejects conflicting raw/typed configuration and manual mismatched tokens, and consumes unknown fixed-bit short packets after sending an allocation-free reset. Responses are strictly shorter than their trigger, require the endpoint's minimum plausible 1-RTT length, and share Quinn's default 20 ms endpoint-wide minimum interval across source addresses. The default remains disabled. Owning, visitor, and batch receive tests cover the same policy, and a real two-client authenticated handshake verifies peer-visible initial tokens plus derived-token CID rotation. Pending PATH_RESPONSE state is capped per connection (default 8, matching tquic's receive-side challenge cap): excess unique PATH_CHALLENGEs are ignored without rejecting the authenticated packet, FIFO/index/target-address storage stays aligned, and a dropped counter exposes sustained pressure. During preferred-address validation the selected preferred tuple and retained prior validated tuple remain usable, but a third tuple is still discarded. The integrated client handshake registers the server's initial-CID transport-parameter token, while an unnegotiated initial CID no longer treats its zero-filled storage as a token. Netz issues three additional CIDs, and quic-go migrates one connection from `127.0.0.1` through `127.0.0.2` to `127.0.0.3` on distinct source ports. Both candidate paths reject `Path.Switch` before validation, complete PATH_CHALLENGE/PATH_RESPONSE probing, switch, and carry streams 4 and 8. A second run drops the first PATH_RESPONSE on each candidate path, then requires netz's blocking receive timer to retransmit both PATH_CHALLENGEs before the same two migrations and echoes can finish. A separate connection swaps its UDP socket to a new `127.0.0.1` source port without `AddPath`, drops four post-rebinding datagrams, recovers the stream by PTO, and proves netz selected the new tuple while keeping it validated and queuing no path challenge. | Extend the verified two-hop shape to longer path-churn runs before generalizing beyond loopback. |
| Latency spin bit | Covered as an opt-in direct and authenticated-handshake policy | `OneRttConfig.enable_spin_bit` reaches established connections while retaining the disabled default and independently suppressing one in sixteen handshake connections. The value and highest authenticated packet number are tracked separately for the current, retained validated, and bounded candidate paths. Reordered lower packet numbers cannot roll the signal backward; NAT rebinding and migration select the new path's state, failed validation restores the retained path's state, and changing the destination connection ID resets the selected path to zero. Real UDP tests inspect protected short-header bits after a handshake, reordering, manual CID selection, automatic `retire_prior_to` replacement, candidate traffic, NAT rebinding, and failed migration. | Keep passive-observation comparisons scoped to controlled paths; the spin signal is intentionally absent from the randomized disabled sample. |
| Retry/token/address validation | Covered by implementation, local replay tests, and certificate-verified quic-go and s2n-quic process gates | `src/quic/retry_flow.zig`, `src/quic/address_validation_token.zig`, handshake/retry tests, `zig build interop-quic-quic-go -Doptimize=ReleaseFast`, and `zig build interop-quic-s2n -Doptimize=ReleaseFast`; `SharedReplayFilter` provides atomic, bounded process-local duplicate rejection after token authentication and binding checks for integrated Retry and NEW_TOKEN validation. The shared endpoint server automatically owns a 16,384-entry filter when address-token authentication is configured without one; explicit caller ownership and a zero-capacity opt-out remain available. Both independent servers force source-address validation, while netz verifies and follows the valid Retry, authenticates the server, completes two streams, and validates peer application close on the retried connection. The external gates do not exercise replay or expiry. | Add replay/expiry probes against an external peer before generalizing beyond a valid Retry exchange; use coordinated external state when replay protection must span processes or hosts. |
| Congestion control (NewReno/CUBIC/HyStart++) | Covered and defaulted to CUBIC for 1-RTT | `src/quic/congestion.zig`, `src/quic/hystart.zig`, congestion tests; ACK processing samples utilization before removing bytes in flight, suppresses NewReno/CUBIC growth while app-limited, and excludes idle time from the CUBIC epoch. Negotiated idle timeout is clamped to RFC 9000's three-base-PTO minimum using the live RTT estimator and peer ACK delay | Keep comparing long-lived congestion traces under equal loss/RTT schedules. |
| UDP batching / GSO / GRO | Covered through timer-aware QUIC/HTTP/3 paths | Batch/GRO APIs plus `servicePacket` and synchronous `visitPacket` apply current-key datagrams in connection-owned receive storage with retained frame scratch; their timer-servicing forms also accept caller deadlines without allowing earlier PTO/ACK/keep-alive work to extend the application budget. Explicit one-RTT packet, batch, state-only, visitor, and stream receive deadline entry points validate an unexpired awake-clock timestamp before consulting any preloaded datagram or buffered stream bytes, so invalid deadlines are side-effect free; relative-timeout forms still normalize their caller budget once. Raw parsed, owned-byte, caller-buffer, and GRO-batch endpoint receive APIs now accept relative durations or absolute deadlines, with matching helpers on the lightweight QUIC server/client wrappers and type-erased handshake datagram source. Relative convenience forms convert once to an awake-clock deadline. Version-Negotiation filtering and CID-routed receive expose the same bounded forms and preserve one absolute budget across any unsupported-version datagrams they answer and discard. The shared-socket endpoint dispatcher also exposes an explicit awake-clock deadline receive, rejects incompatible clock domains before comparing them with transport timers, and lets an earlier PTO/ACK/idle timer wake the same bounded call without renewing the caller budget. HTTP/3's request and raw-transport endpoint callback loops refresh the selected connection timer after the application or protocol-adapter handler returns, so a response/control send cannot leave a new PTO absent from the shared scheduler. Its routed-packet adapter refreshes again after HTTP/3 parsing on both success and error, because ACK, QPACK, stream-error, or connection-close work occurs after the dispatcher initially processes the QUIC packet. Its buffered request poll adapter likewise refreshes after every session poll, including null and error results, so receive-credit, QPACK feedback, completed-stream retirement, protocol-error control frames, or a failed automatic MAX_STREAMS send cannot leave a new retry deadline visible only inside the connection. Handshake-backed HTTP/3 and WebTransport non-GRO pumps no longer create discarded owned packet diagnostics or per-packet UDP buffers, while GRO keeps a lazy owning suffix for one-packet application routing. Non-GRO HTTP/3 connections with packet-sized endpoint limits now drain up to sixteen independent UDP datagrams into at most 64 KiB through zio/`std.Io`, sample one monotonic processing timestamp for that kernel batch, then authenticate and apply one packet per upper-layer turn; compact bounded indexes preserve the prior connection layouts. Callback errors preserve the untouched suffix, invalid deadlines do not advance it, large default datagram limits retain the prior single-packet path, and preferred-address migration remains on its dual-socket receive path. A fixed-binary four-stream download comparison improved the median 13.7% with 5/5 paired wins while upload remained within 1.6% with overlapping ranges. The captured 16 MiB/four-stream H3 step reduced allocation calls another 47.8-48.1%. Both ordinary and batched stateful sends now encode ACK-eliciting frames directly into stable recovery storage and let AEAD read from that buffer, eliminating the former second full plaintext copy through packet scratch; ACK-only packets retain their reusable transient/in-place path. Connection qlog observation clamps mixed explicit nanosecond, internally sampled, and millisecond-derived timestamps to the last emitted event while the standalone encoder still rejects genuinely regressed input. Unit coverage checks stable ownership, canonical bytes, emitted-wire decryption, and partial-batch rollback. Stateless batch results distinguish protected from socket-sent packets so callers advance beyond every consumed AEAD nonce while committing application state only for the visible prefix; quic-go and s2n-quic loss/retransmission gates remain green. | Keep H3 GRO opt-in on this small-rmem host and retest on tuned systems. |
| HTTP/3 request/response, Alt-Svc and RFC 9412 ORIGIN | Covered by bidirectional quic-go and tquic process interop plus verified public fetches against ByteDance, Cloudflare, and quiche deployments | `zig build interop-http3-quic-go -Doptimize=ReleaseFast` verifies certificate-checked POST headers, split body writes and trailers in both directions over QUIC v1 and forced RFC 9369 v2. In each direction and version the peers open the cancellation target and a sibling concurrently on one connection, negotiate fixed 8 KiB stream / 24 KiB connection receive windows, read 12 KiB from a declared 128 KiB response, deliberately drop the first H3_REQUEST_CANCELLED STOP_SENDING datagram, and require retransmission plus exact sender observation before releasing the sibling response. The sibling then completes with its body and trailers, and the quic-go client independently asserts one dial and at least two traced STOP_SENDING transmissions. The development client exposes timeout/deadline request and informational-response variants: the awake deadline is validated before stream commitment and rechecked before every UDP send and response receive (an individual UDP send syscall itself is not deadline-aware); because its response assembler is call-local, any post-send receive or parse failure makes that client fail closed rather than risking response/stream misassociation. The development server exposes timeout/deadline-bounded aggregate request receive under one unchanged awake-clock budget, retaining partial STREAM state for a later call, and one-call bounded `serveConcurrent`, with peer-aware request assembly, concurrent handler dispatch, serialized multi-datagram response writes, retained request metadata, and per-worker errors; a real two-client UDP test drives the complete public client/server path. The authenticated handshake server additionally exposes bounded `serveOne`/`serve`/`serveConnection` helpers: they retain full request ownership through the handler, use paced response-body/trailer sending, preserve a persistent connection across the configured request count, and finish with the two-phase GOAWAY sequence. Authenticated clients expose timeout/deadline-bounded per-stream, multiplexed whichever-ready, and server-push aggregate/streaming receive; authenticated servers expose the symmetric bounded aggregate and multiplexed streaming request receives. Authenticated clients can also be constructed on a caller-owned shared endpoint, accept dispatcher-routed packets through `processResponsePacket`, and nonblockingly drain per-stream, whichever-ready, and push events through `pollResponseEvent`, `pollNextResponseEvent`, and `pollPushEvent`. A two-origin one-socket regression routes interleaved responses by CID, verifies stream-zero state remains isolated per connection, then injects GOAWAY after the last response has finished to prove control progress does not require a dummy request or competing socket read. Detached Extended CONNECT progress pumps expose relative-timeout, absolute-deadline, and packet-injection forms in both directions, keeping protocol adapters on the same single-owner QUIC loop. In both directions, one absolute budget spans unrelated traffic, control/QPACK progress, GRO batches, and transport timers, while timeout leaves request/parser/decoder lifecycle state resumable rather than implicitly finishing or resetting the stream. Response writers and aggregate/incremental clients now retain request method context: HEAD advertises representation length without DATA, successful traditional CONNECT rejects HTTP body/trailer bytes and strips `Content-Length: 0`, while extended CONNECT retains DATA semantics. Clients also expose the peer GOAWAY ID and RFC 9114 retry classification: request streams at or above that ID are known unprocessed, while lower IDs remain potentially processed. Aggregate and head-only decoders expose ordered borrowed 1xx callbacks and enforce configurable limits; aggregate multiplexed reads attach the selected request-stream ID, aggregate pushed reads attach the push ID, parent request-stream ID, and push-stream ID, and servers can emit 1xx sequences on pushed responses. Authenticated and lightweight preconfigured-key per-stream, whichever-ready, and push aggregation expose callback-preserving timeout/deadline variants; one unchanged deadline covers all interim heads and the final response. Both clients retain incomplete response reassembly and partially consumed push head/body/trailer ownership so a later bounded aggregate call can resume after timeout, while rejecting mixed aggregate/incremental push consumption. The lightweight client also exposes socket-free per-stream, whichever-ready, and push polling plus timeout/deadline-bounded whichever-ready streaming response events, retaining active readers and partial frames across timeout; the lightweight server exposes matching socket-free request-event polling for externally owned loops and resumable timeout/deadline-bounded aggregate request receive. Lightweight request and response stream readers can also discard DATA without copying while returning receive-window credit. The lightweight client can explicitly await peer SETTINGS under one relative or absolute budget while retaining earlier response/push bytes, matching the authenticated capability-negotiation path. Incremental request and push streams enforce the same bound, and authenticated/lightweight push readers can discard DATA without a caller buffer while returning receive credit. This matches quic-go's bounded `Got1xxResponse` behavior while retaining a caller-configurable per-stream limit. RFC 9412 support adds server ORIGIN emission plus bounded, incrementally accumulated client Origin Sets, strict server-to-client direction checks, canonical scheme/host/default-port matching, empty-frame initialization, invalid-entry skipping, 421 removal hooks, and control frames split at every byte boundary. Authenticated server ORIGIN emission exposes relative-timeout and absolute-deadline variants; invalid-clock or expired calls leave packet number, control-stream offset, and the local advertisement marker unchanged, while one absolute budget covers SETTINGS and ORIGIN delivery. `pollControl` lets event loops consume authority updates without waiting for an application message, and all authenticated/lightweight client/server control pumps expose relative-timeout and absolute-deadline variants that preserve buffered application streams. Connection reuse queries deliberately remain certificate-agnostic and require the caller to perform authority validation. The repository-pinned quic-go v0.59.0 module and audited tquic H3 sources expose no ORIGIN frame implementation, so this feature currently has independent RFC wire vectors and a real protected-QUIC runtime exchange rather than a false external-peer claim. `zig build interop-http3-tquic -Doptimize=ReleaseFast` builds audited tquic `0169abde20c6`; the verified netz-client direction exercises GET, byte Range (206), and POST-body digest, then separately sends client GOAWAY while stream 0 is active, completes that accepted response, requires tquic's exact GOAWAY(0) acknowledgement, and rejects stream 4. The reverse direction verifies two ordinary requests, then separately requires tquic to observe netz's maximum-ID and final GOAWAY(4), finish accepted stream 0, and reject creation of stream 4. Every tquic scenario runs with and without forced Retry. `examples/http/http3_fetch.zig`, explicit status/body assertions, and Alt-Svc gates cover three independent public endpoints, including quiche on UDP/8443 | Keep live public-server coverage and add ORIGIN interop when an independently maintained peer exposes RFC 9412. |
| HTTP/3 real-handshake upload benchmark | Covered and reliable at the tested default, with a dual-role quic-go reference | `examples/benchmarks/bench_http3_handshake_transfer.zig`; CPU-0-pinned 4-stream 64 MiB upload completed 5/5 iterations at 141.78 MiB/s mean and 2.76% stddev with ACK threshold 4 and adaptive DATA sizing; exact-size cross-stream body batching is also available but opt-in on this small-rmem host. DATA framing emits the small HTTP/3 prefix separately and borrows the complete application body in the common case, including multi-stream workloads. Short-lived download sessions explicitly drain reliable QUIC recovery before teardown, with one absolute client deadline; a deterministic test drops the final DATA/FIN once and requires PTO recovery, exact bytes, FIN, and empty recovery. Five CPU-0 1 MiB download iterations completed at 105.87-126.36 MiB/s (120.41 MiB/s mean, 6.18% stddev). The latest matched 16 MiB/four-stream A/B combines intrusive bounded recovery reuse with ordered STREAM preflight fast paths and raised mean throughput from 114.11 to 152.69 MiB/s (33.8%), while all 25 iterations per side verified exact bytes/status. Thread-safe telemetry reduced median allocation calls 29.6%, and peak live bytes 15.5%. `zig build bench-http3-quic-go -Doptimize=ReleaseFast` adds certificate-verified, two-CPU, fresh-connection-per-sample upload and download in both netz/quic-go role pairings. Its 4 MiB samples validate status, headers, EOF, exact bytes, and checksum after an untimed ready request. A 2026-10-15 zio-era five-sample four-stream QUIC v1 refresh measured netz sender ranges of 139.266-166.578 MiB/s upload and 152.796-167.907 MiB/s download, versus quic-go sender ranges of 148.030-149.207 MiB/s and 55.852-73.717 MiB/s. Sender attribution matters: the lower download row is the quic-go server send path, not a netz client receive result. `bench-http3-quic-go-multistream` extends the same process matrix to 4 and 16 concurrent streams over QUIC v1/v2; each upload/download and role pairing verifies every stream plus aggregate bytes/checksum. The Go fixture now serves a CA-signed non-CA server leaf, matching production TLS server-auth policy instead of relying on a CA certificate as an endpoint identity. An opt-in process-memory run measured netz sender RSS at 9,772-9,984 KiB versus quic-go sender RSS at 22,528-23,296 KiB, and netz receiver RSS at 7,936-10,240 KiB versus quic-go receiver RSS at 19,712-19,968 KiB; runtime allocation counters remain separately scoped. Linux `AF_PACKET/SOCK_DGRAM` capture now succeeds on this host with a dedicated `CAP_NET_RAW` Python and a 32-MiB effective packet receive buffer. Four v1/v2 upload/download gates each completed both mixed implementation roles with zero packet-socket drops, retained bounded DLT_RAW PCAP prefixes, independently reparsed directional UDP/IP totals and packet-size sequences, and workload/binary hashes. The captures prove the shapes are not equal-wire: netz sender datagram counts were 1.025x/1.126x quic-go for v1 upload/download and 1.066x/1.170x for v2, while UDP-byte ratios were 1.020x/1.007x and 1.064x/1.031x. Sender mean payloads were 1182/1060 B for netz versus 1187/1186 B for quic-go in v1, and 1185/1046 B versus 1187/1186 B in v2. The timing results therefore remain explicitly same-application-shape; the direction-aware packet-fill default is now implemented, while ACK cadence remains an evidence-backed optimization target. Direct tests cover prefix ownership, offsets/FIN, exact-prefix limits, cache size classes/full budget, fast adjacent frames, overlap conflicts, fallback and allocation rollback. | Re-run capture after the packet-fill change and analyze ACK/frame/cipher differences before making a cross-stack equal-wire throughput claim; then reduce the remaining packet-protection and event-loop cost. |

The close lifecycle now has an explicit saturated-congestion regression matching
the failure shape fixed in current Quinn. It sends reliable STREAM data without
acknowledging it, clamps the congestion window to zero remaining credit, proves
an ordinary PING is rejected with `CongestionLimited`, and then requires an
application `CONNECTION_CLOSE` to reach the peer immediately with its exact
code and reason. The close packet does not enter bytes-in-flight or recovery,
so cancellation cannot leave the peer waiting for idle timeout merely because
the sender stopped processing ACKs with a full congestion window.

The shared HTTP layer now also owns a bounded, thread-safe Alt-Svc cache keyed
by authenticated origin. It applies RFC 7838's 24-hour default age, peer `ma`,
an optional deployment cap, `ma=0`, `clear`, and removal when a replacement
field omits HTTP/3. True LRU eviction bounds origin churn, while exponential
failure backoff survives refreshes of the same alternative so a broken QUIC
path is not retried after every successful TCP response. Allocation-failure
coverage verifies that replacement never publishes a partial entry. Entry
replacement and each thread-safe hit now use exactly one contiguous owned
string block; an allocation-count regression rejects a return to per-field
ALPN/host allocations. The
exclusive authenticated H3 pool now consumes these routes without confusing
transport and authority identity: its cache key, TLS SNI/certificate policy,
and QPACK `:authority` remain the original origin while DNS/UDP uses the
alternative host and port. A real handshake test sends two case-equivalent
origin URIs through one advertised loopback service and requires one QUIC
connection plus exact origin authority on both requests.
The same exclusive and unified pools now turn RFC 9412 into a complete safe
coalescing decision instead of exposing only a certificate-agnostic query.
Cross-origin idle reuse requires an explicit peer Origin Set member and a
retained authenticated leaf covering the requested DNS name or exact IP
subjectAltName; public-key pins do not bypass that name check, and resumed
connections without a retained chain are ineligible. Leases keep the initial
connection origin distinct from the current request origin. A 421 response
removes the request origin before release without poisoning the original
origin, and a later ORIGIN frame can re-authorize it. Real handshakes prove one
accepted cross-origin connection, certificate-mismatch isolation, 421
exclusion, and ordinary 1-RTT behavior even through the early-capable
acquisition path. A unified two-origin H2 Alt-Svc discovery test independently
requires one H3/QUIC accept for both authorities.
Host identity now uses the same shared authority module for owned origin keys,
idle-pool hash lookup, active route matching, and authorization snapshots.
Unreserved percent escapes and IPv6 textual aliases select the same origin;
reserved escapes remain encoded, and bracketed IPvFuture literals cannot
collide with DNS names. ORIGIN deduplication, 421 exclusion, and later
re-authorization use that same identity. A real authenticated shared-route
regression advertises `https://%6cocalhost:4444`, coalesces the normalized
`localhost` origin, applies 421 revocation, and isolates unauthorized origins.
The unified HTTP pool now closes the next product boundary: after an
authenticated H2 response advertises H3, two later URI requests select H3 and
reuse one QUIC connection while returning the common owned response type. A
silent alternative-service endpoint independently proves exponential
suppression and same-deadline H1 fallback. The replay boundary is method-aware:
GET falls back, but POST returns the H3 failure and never reaches the TCP
server. HTTP/3 is opt-in and requires an explicit QUIC certificate policy.
Cross-origin Alt-Svc redirects now require a distinct connector hook. The
default hook preserves the new origin's URI/SNI policy while clearing QUIC
resumption, address-validation, early-data, deterministic random/key inputs,
and client identity unless forwarding was explicitly authorized; a custom
connector without this boundary fails closed instead of falling back to its
ordinary alternative-service dial.
The unified pool now also offers origin-scoped HTTP/3 0-RTT. Peer SETTINGS are
remembered in a separate bounded LRU, and the default connector scopes its
resumption cache key to the normalized URI authority rather than a process-
global server ID. Only a newly reserved connection can consume a ticket and
prepare a request; an idle H3 hit stays 1-RTT without unused early-request
allocation. Real handshakes cover accepted early data followed by a
425/stream-4 retry, TLS-layer rejection followed by a stream-0 replay, ordinary
idle reuse despite an available ticket, safe-only suppression for POST, and a
per-request opt-out. Unified responses expose disposition/retry metadata while
one absolute deadline still covers admission, DNS, handshake, initial response,
and replay. The H3 response pump also captures post-handshake tickets without
an additional receive wait: authenticated CRYPTO passes through a bounded
fragmented/out-of-order reassembler, complete messages populate the origin+
ALPN cache, zero-lifetime tickets are discarded, and malformed tickets
fail-close the connection. The real unified test obtains its resumption
tickets from server-emitted NewSessionTicket messages rather than preloading
the client cache.

The four verified capture artifacts are
`zig-out/http3-captures/run.0fFQq2` (v1 upload),
`zig-out/http3-captures/run.ELJ1qP` (v1 download),
`zig-out/http3-captures/run.3F95f3` (v2 upload), and
`zig-out/http3-captures/run.dnM6wq` (v2 download). Their comparison-record
SHA-256 values are respectively
`9aaf734c9d9e0c583d29e5e87e6046fb1a09dc3da77e3783023feebf773b9ede`,
`12d1d3a28d864b9f83405bff55fafdd9769cf5369bfb5834e71da4c4418d9c0d`,
`65c90c7804a70f38e8b1a4d70ad068fa476390c6d35f432827a6c76e858ffc56`,
and `3d3bb1ffaf3e6d62afcc8093b5f48948b1b494dd638c440e5504f99b959f6f12`.
The packet socket reports one cooked `PACKET_HOST` IPv4 copy on Linux
loopback; the runner records that boundary explicitly rather than calling it
physical egress. `net.core.rmem_max` and `net.core.rmem_default` were raised
temporarily to 33,554,432 for zero-drop capture and restored to 212,992 after
the runs.
| HTTP/3 real-handshake download and RFC 9218 response scheduling | Covered for current benchmark scale; feature coverage exceeds the local quicz H3 layer | `HandshakeServerSession.sendResponseBodiesPaced` schedules borrowed complete bodies by the request Priority field and live PRIORITY_UPDATE, serializes non-incremental responses by stream ID, round-robins incremental peers, bypasses flow-blocked urgent streams, and replans after socket-visible packet prefixes; real-handshake tests cover all four behaviors and the benchmark sends `Priority: u=3, i`. Candidate sizing accounts for the variable-length HTTP/3 DATA prefix exactly against QUIC connection/stream flow credit, while congestion and datagram limits retain a separate conservative packet margin. This allows a three-byte stream-window increment to carry its two-byte DATA prefix plus one body byte instead of being misclassified as blocked, with real protected-session timeout/resume coverage. Retained request/push update state now has a configurable per-connection total bound, replacements remain valid at capacity, terminal request and cancelled-push state is retired, and server runtimes validate every update in a batched control fragment. Stateful server request completion also registers transport retirement, so aggregate and incremental FIN paths return MAX_STREAMS and reclaim copied request buffers after the response FIN/RESET is acknowledged; a one-stream-credit churn test advances through four request IDs without application release calls. Server push streams likewise register local uni retirement after send and peer uni retirement after FIN/reset consumption. Finished/cancelled push promises leave the active map and enter an exact compressed prefix+sparse-range history; RFC 9114 only recommends sequential Push IDs, so out-of-order IDs retain their holes rather than being collapsed unsafely. Request IDs must be client-initiated bidirectional IDs within the active QUIC receive limit; invalid IDs roll back the whole fragment and authenticated connections close with H3_ID_ERROR. `~/Work/quicz/src/h3` has no Priority field, PRIORITY_UPDATE, urgency, or incremental scheduler. The runtime now supports byte- or packet-cadence cooperative yielding; using a chunk-size-independent three-packet cadence raised five 64MiB/four-stream iterations from 11.35 MiB/s to a stable 44.15 MiB/s mean (3.47% stddev) while retaining full completion. After enabling borrowed DATA framing for multi-stream runs, a CPU-0 16 MiB/four-stream regression sample measured 45.72 MiB/s mean with 10.99% stddev. Packet construction now encodes ACK-eliciting frames directly into stable recovery allocations for both batch and ordinary sends, eliminating the previous encode-to-packet-buffer then full-payload copy into recovery; direct tests compare retained recovery bytes with canonical frame encoding and decrypt the emitted packets. The post-batch sample measured 49.37 MiB/s mean with 0.93% stddev, and the subsequent ordinary-path sample measured 49.91 MiB/s with 0.22% stddev. These are internal regression samples, not an equal-wire quicz comparison. | Continue apples-to-apples quicz throughput work before making a whole-stack performance claim; move same-process loopback pacing policy into a reusable event-loop benchmark harness. |
| QPACK / Capsule / HTTP Datagrams / WebTransport | Covered by modules, stateful runtime APIs, benchmarks, real-handshake streams, lifecycle controls, native wtransport interop, and real Chrome and Firefox browser gates | QPACK dynamic entries use indexed lookup, FIFO head eviction and one contiguous string allocation versus quicz reverse scans, front insertion and two string allocations. Field-section prefixes use RFC 9204 prefix integers rather than QUIC varints; their decoder accepts the complete platform `usize` range and rejects wider encodings without wrapped shifts or addition. Boundary tests cross encoded Required Insert Count 63 and Delta Base 127, while `interop-http3-qpack-quic-zig` independently decodes a speculative section after 64 inserts. Dynamic sections choose Required Insert Count as their minimal Base, and the dependency prepass excludes dynamic name matches shadowed by the selected static representation, preventing phantom blocking and Section Acknowledgments. The decoder independently derives the highest actual dynamic reference across all four relative/post-Base field forms and rejects both under-reported mandatory dependencies and non-minimal over-reported counts. Request, response and trailer paths decode both literal and dynamic QPACK sections directly into one allocation containing the field descriptors and shared name/value bytes, rather than first allocating per Huffman/dynamic field and copying again. Offset plans remain valid across scratch growth, all four relative/post-Base representation families retain exact dependency validation, and allocation-failure plus exact allocation-count tests cover both owning decoders. On 64-bit targets, compact owned-field plans reduce per-plan state from 72 to 56 bytes and the 32-field stack budget by 512 bytes. Nine CPU-0 fixed-binary comparisons measured 571-582 ns/block (574 median), versus 682-710 ns/block (693 median) at parent `e128fb55`; the candidate won every pair and reduced median time by 17.2%. Settings-aware decoders enforce the uncompressed `name + value + 32` field-section budget before Huffman output allocation or dynamic-entry copying, including static, literal and all dynamic representations. Handshake-backed HTTP/3 clients and servers expose RFC 9297 DATAGRAM send, poll, timeout/deadline receive, exact payload-budget, and explicit close APIs for detached Extended CONNECT streams. A bounded per-association demultiplexer retains interleaved streams independently, drains accepted payloads before stable stream-terminal errors, drops unknown/closed associations, maps malformed Quarter Stream IDs to H3_DATAGRAM_ERROR, and requires both HTTP/3 SETTINGS and directional QUIC DATAGRAM negotiation. WebTransport uses the same demultiplexer so sessions cannot steal one another's DATAGRAMs; server acceptance reserves its association before status 200, while dispatcher-driven clients expose stable-storage promotion helpers instead of publishing moved-from connection pointers. The authenticated shared endpoint advertises and enforces a configurable non-zero Session capacity per HTTP/3 connection while standalone owning adapters remain one-Session surfaces. Accepted server state is keyed by connection plus CONNECT stream ID; the matching authenticated client owns one H3 reader and stable per-Session response/stream/control state. Both sides leave streams for another active Session untouched. The client preserves bounded rejection metadata before connection reuse, enforces the minimum of peer SETTINGS plus its local cap, and offers targeted or stable-key round-robin whichever-ready Session receive; excess server-side CONNECTs receive H3_REQUEST_REJECTED without interrupting accepted DATAGRAM, associated-stream, or CLOSE traffic. Real QUIC/TLS regressions prove both endpoint roles with two accepted Sessions on one connection, including a refused/rejected attempt, independent data planes, fair interleaved receive, distinct CLOSE metadata, and per-Session teardown. Terminal cleanup scans peer-initiated QUIC receive state for complete same-session association prefixes before sending WT_SESSION_GONE, so streams buffered before registry admission cannot survive session close; incomplete, ordinary HTTP/3, local, and other-session streams remain untouched. Capsule fallback remains an explicit codec-level choice. WebTransport adds transactional cross-stream batches and modern 0x41 association. Its external wtransport gate drops a mapped STOP_SENDING while a sibling stream is live and requires transport recovery plus sibling completion. The Chrome gate independently covers browser CONNECT, DATAGRAM, bidi/uni streams, mapped reset/stop, sibling reuse, drain, and close. The Firefox 156.0.1 gate binds its result to the launched-browser version, launcher/process-image SHA-256, and page/server User-Agent across both browser phases and covers Origin rejection/acceptance, CONNECT, DATAGRAM, bidi/uni streams, exact mapped reset code 71, same-Session reuse after reset, drain, and exact close metadata. | Add Safari automation and keep Firefox STOP_SENDING explicit until its reader-cancel path emits code 72; native wtransport and Chrome already verify both mapped codes. |

The current integrated HTTP/3 and WebTransport receive policy defaults endpoint
capacity to 4,096 bytes while leaving generic QUIC at 65,535. Generated
`max_udp_payload_size` transport parameters are capped to physical receive
capacity and oversized raw overrides are rejected. The bounded policy lives in
`src/http3/runtime/receive/policy.zig`, and the transport-parameter rule lives
in `src/quic/handshake/transport_limits.zig`, keeping both out of the large
runtime and handshake facades. The generic RFC 9000 codec still accepts the
complete wire ranges: `max_idle_timeout` can use the full QUIC varint range and
an explicit `max_udp_payload_size` is invalid only below 1200, while actual
sends remain bounded by the endpoint and path limits. RFC 9368 validation also
keeps its role asymmetry: a client list must contain its chosen version, a
server list may omit it, and an explicitly empty server list is rejected after
Version Negotiation. Preferred-address validation rejects the RFC 9000-invalid
combination with a zero-length server connection ID. A CPU-0, seven-pair,
order-alternated, same-binary
16 MiB/four-stream download A/B measured batch 16 at 86.02 MiB/s median versus
67.20 MiB/s for batch 1 (1.280x, 6/7 wins), with exact payload/status checks and
`zio-std-io` on every arm. Bidirectional tquic interop passed with and without
Retry. The quic-go v1/v2 gate now uses a repository-owned module pinned with
`go.mod`/`go.sum`, removing the former external-checkout failure mode while
retaining an independent quic-go process in both endpoint roles.

Established 1-RTT connections now group packet-codec scratch in a dedicated
module and eliminate the separate plaintext buffer. Reliable frames encode
directly into recovery ownership; mixed frames, PMTU probes, and augmented PTO
retransmissions encode into final packet storage before in-place AEAD. This
matches the reusable-buffer principle visible in Quinn and tquic plus quiche's
caller-output send interface. A 100-iteration
local two-endpoint handshake run reduced allocation calls from 8,001 to 7,801,
cumulative bytes from 14,469,287 to 11,773,513, and peak live bytes from 88,289
to 61,333. Seven fixed-binary, CPU-0 pairs found only small timing movement:
quicz-aligned P50 improved 0.6% with 4/7 wins and verified P50 improved 0.7%
with 7/7 wins. A seven-pair first-echo control improved 13.3% with 7/7 wins,
while one long-lived echo control improved 4.7%; the latter is only supporting
evidence, so no broad steady-state throughput claim is made.
Direct zio-backed handshakes now receive into one handshake-scoped allocation
and transfer that exact storage into established 1-RTT receive scratch. A
scoped release hook preserves datagram lifetime; nested fragmented-flight reads
fall back to owned storage, and dispatcher inbox sources retain their owning
FIFO contract. This mirrors Quinn's endpoint `recv_buf` and tquic's loop-level
receive buffer without exposing a Threaded production fallback. Against the
preceding fixed binary, 100 two-endpoint handshakes reduced skip-verification
allocation calls 10.3%, cumulative bytes 40.4%, and peak live bytes 15.1%; the
verified reductions were 9.6%, 40.3%, and 15.0%. Seven CPU-0 alternating pairs
showed only noise-level handshake movement (skip P50 +0.5%, verified P50 +0.1%)
and a 5,000-round echo control was unchanged at 15.574 versus 15.575 us.
HTTP/3 client request lifecycle state now uses one stream-ID-keyed map instead
of parallel ID, index, and semantics arrays plus a map. Standard HTTP methods
are inline tags, while extension methods retain exact owned bytes for safe send
retry; HEAD, traditional CONNECT, Extended CONNECT, GOAWAY retry disposition,
and finished-stream behavior are unchanged. The client implementation and its
allocation/failure tests moved to
`src/http3/runtime/stream/lifecycle/client.zig`. Seven fixed-binary CPU-0 H3
upload pairs moved the 16-MiB/four-stream median from 144.52 to 145.63 MiB/s
(0.8%, 6/7 wins) and reduced the allocator-call median from 658 to 652. This is
a small internal lifecycle result, not a general cross-stack throughput claim.
Server lifecycle state is likewise one stream-ID-to-priority map instead of an
active array plus index map; it caches the lowest active ID directly for
GOAWAY drain and scans only when that exact request finishes. The server logic
and tests moved to `runtime/stream/lifecycle/server.zig`. Seven matched H3
upload pairs were neutral at 148.86 versus 148.76 MiB/s median, while allocator
calls fell deterministically from 652 to 651; this is recorded as structural
and allocation evidence rather than a speed claim.

Handshake-backed and lightweight protected HTTP/3 clients guard the
connection-scoped receive owner while aggregate informational callbacks run.
Completed aggregate responses now use a two-phase ownership transfer: all
fallible HTTP/3/QPACK validation runs against the retained response, then the
reassembly allocation is moved into the owned result without a second whole
message copy when the allocator supports in-place shrink. The fallback remains
transactional for other allocators. Three fixed-binary 16 MiB quic-go download
memory pairs reduced median netz explicit peak bytes by 21.1%, cumulative
allocation by 19.3%, and whole-process peak RSS by 16.0%. Five throughput pairs
overlapped and the candidate won only 1/5, so this is an allocation/peak-memory
improvement rather than a throughput claim.
The symmetric aggregate request path also commits each copied contiguous prefix
to QUIC before FIN and moves the completed reassembly allocation only after
decode, QPACK, lifecycle, and transport-release preparation succeeds. A
dedicated 16 MiB aggregate-upload benchmark measured 37.1% lower median
explicit peak bytes and 39.5% lower cumulative allocation across three
fixed-binary pairs. Five throughput pairs improved the tested median from
59.00 to 67.15 MiB/s with 4/5 wins, but their ranges overlap slightly, so the
result is not generalized beyond this bounded aggregate shape.
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
Its shared QUIC visitor and batch pumps now also treat an authenticated
duplicate packet number as discard-only input and continue under the original
deadline until fresh application progress arrives. A duplicate segment cannot
erase fresh packets already accepted from the same GRO batch. The low-level
owning `receivePacket` API retains its explicit `DuplicatePacket` result for
transport diagnostics; focused tests cover both contracts. This matches
quiche's receive path, which records duplicate packet numbers as ignored rather
than surfacing them as a connection failure.

The external HTTP/3 throughput harness now runs 1, 4, or 16 concurrent
request streams in either direction and supports forced QUIC v2 through
`NETZ_HTTP3_INTEROP_VERSION=2`. The aggregate multi-stream gate covers both
v1 and v2 by default. Its Go and Zig endpoints select the requested version,
v2 uses the compatibility key-update profile required by the pinned quic-go
v0.59 peer, and every config/result/server-completion/memory record carries
`quic_version`. The strict checker rejects missing or mismatched versions, so
a v2 command cannot silently report a successful v1 measurement.
| TLS backend/process interop examples | Covered in both directions through standalone, certificate-verified quic-go, s2n-quic, and Quinn process gates | QUIC handshake tests, `examples/quic/quic_handshake_echo.zig`, `zig build interop-quic-quic-go -Doptimize=ReleaseFast` (bidirectional/unidirectional streams, RESET_STREAM, STOP_SENDING, rolling limits, and Initial/application PTO recovery), `zig build interop-quic-s2n -Doptimize=ReleaseFast` (independent s2n-tls stack, ALPN, native RFC 9221 DATAGRAM negotiation/boundaries in both directions, exact RESET_STREAM/STOP_SENDING exchanges and cancellation recovery), `zig build interop-quic-quinn -Doptimize=ReleaseFast` (independent rustls/Quinn RFC 9221 boundaries, stream sibling, and close), HTTP/3 public fetch with `--verify` | Add broader public peers before making a full interoperability claim. |

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
and stable machine-readable results. Every netz role now runs on zio behind
`std.Io`; config, result, completion, traffic, memory, and churn records bind
both endpoints to `zio-std-io` or `wtransport-quinn-tokio`, and strict
verifiers reject mismatches. A zio migration smoke passed two 64-KiB streams
for three measured rounds and three 32-byte DATAGRAM round trips in both role
pairs, with exact checksums and zero retained netz allocator bytes. A separate
32-stream matrix passed loss and reorder in both sender directions. These are
functional gates, not performance comparisons. The harness is deliberately
reported as same-application-shape rather than equal-wire: the two peers expose
different effective WebTransport DATAGRAM payload limits. Userspace UDP
accounting below proves the stream shapes differ; kernel/interface capture is
still needed before any equivalent-packetization claim.
Its opt-in process-memory matrix covers stream upload and DATAGRAM ping-pong in
both role directions. Historical pre-zio default-shape runs measured stream
RSS at 10,240 KiB for the netz client versus 11,264-11,312 KiB for the
wtransport client,
and 4,352 KiB for the netz server versus 6,144-6,400 KiB for the wtransport
server. DATAGRAM RSS was 3,840 KiB for both netz roles, 6,144-6,400 KiB for
the wtransport client, and 5,888-6,144 KiB for its server. Netz explicit
allocation records ended at zero live bytes; Rust system-requested counters
remain separately scoped diagnostics. A strict verifier independently derives
the expected bytes/checksum and requires distinct result, server-completion,
and memory records. These RSS values are not current zio measurements.
A separate historical pre-zio `--traffic` pass joined both endpoints' userspace
UDP payload bytes and logical datagram counts for the complete persistent
connection. Three
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
and requires a normal Close. Both netz roles now run on zio behind `std.Io`;
the strict schema binds every config, result, completion, and memory record to
`zio-std-io` or `quic-go-netpoll`, validates the timeout and complete shape,
and recomputes the reported timing metrics. Historical pre-zio five-run
1,000-round samples measured
101.80-103.39 us/roundtrip for netz-client + quic-go-server and
102.25-103.34 us/roundtrip for quic-go-client + netz-server. The overlapping
ranges are reported by role pair, not attributed to one library. They are not
current zio performance evidence. A zio migration smoke subsequently verified
three 1-KiB echoes in both role pairs, exact checksum 391,680, and zero retained
netz allocator bytes. It remains a functional gate rather than a performance
comparison, and the whole harness remains same-application-shape because
GSO/GRO, ACK policy, packetization, and syscall counts have not been proven
equal.
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
peers before a normal Close. The current netz client and server obtain
`std.Io` from zio, and the strict checker binds every config, result, completion
and memory record to `zio-std-io` or `hyper-tokio`. The five 1,000-round runs
below predate that migration and remain historical Threaded evidence:
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
protected UDP datagram lengths rather than plaintext payload lengths. RFC 9002
congestion accounting likewise includes the QUIC header and AEAD tag for every
ordinary send, PTO retransmission, PMTU probe, and imported 0-RTT copy. Batch
and PTO partial-send rollback retain exactly the socket-visible prefix. Clients
can therefore probe a migrated or server-preferred address before receiving bytes
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
Close packet construction also budgets the complete short-header/CID/packet-
number/AEAD overhead and the actual QUIC-varint widths of transport or
application error codes. Oversized reasons are truncated to the largest
prefix that fits the current path MTU, preserving a code-point boundary for
valid UTF-8, while the local `CloseInfo` retains the full diagnostic.
`resendClose` recomputes that prefix against the current PMTU and packet-number
width, so a path-size change cannot strand a closing connection behind
`DatagramTooLarge`.
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
Peer TLS validation failures now emit transport `CONNECTION_CLOSE` with the
RFC 9001 `0x100 + AlertDescription` code at the available Initial or Handshake
encryption level. Both roles use `0x178` for failed ALPN; cipher/key-share
selection, malformed TLS messages, certificate validation and Finished checks
retain their local error while submitting the corresponding fatal alert.
Peer transport-parameter errors use `TRANSPORT_PARAMETER_ERROR`. Close
construction uses bounded stack storage, consumes its packet number once,
pads client Initial datagrams to 1200 bytes and honors server anti-amplification
accounting. Local resource failures do not become peer alerts, and failed close
socket writes cannot replace the original validation error. Initial response
filtering accepts authenticated close-only packets, and Initial/Handshake
CRYPTO extraction terminates on a validated close instead of waiting for TLS
bytes or accepting CRYPTO from the same packet. Protected QUIC v1/v2 regressions
check both roles, exact wire codes, fresh packet numbers, local and socket
failure boundaries, and forged-close discard followed by valid-close receipt.
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
Ticket-age skew beyond the configured tolerance likewise rejects and discards
0-RTT without rejecting an otherwise live, binder-authenticated PSK: the
connection continues as a resumed 1-RTT handshake, and the rejected early
request never reaches replay marking or application stream state.
The server also validates complete multi-identity PSK and binder vectors,
selects a configured stateful or stateless ticket at its original wire index,
and reports that index in ServerHello. Selecting any identity after index zero
continues PSK resumption but rejects 0-RTT, whose parameters belong only to the
first offered identity.
PSK resumption may select another cipher suite with the same transcript hash;
the stricter original-suite check remains at the 0-RTT acceptance boundary.
If Version Negotiation restarts the connection, the original 0-RTT packet is
never replayed under the replacement version and its old-key packet numbers do
not advance the new application space; the client nevertheless retains an
explicit rejected disposition so typed HTTP/3 leaves replay to the caller.
Typed request construction now also enforces RFC 8470 before any allocation,
lease mutation, packet-number consumption, or socket I/O. The ordinary
`PreparedEarlyRequest.init` accepts only case-sensitive registered safe methods
(GET, HEAD, OPTIONS, TRACE, and QUERY); POST, PUT, CONNECT, lowercase or unknown
methods fail with `UnsafeEarlyDataMethod`. Applications with request-specific
replay protections can use `initWithOptions` and the deliberately named
`allow_unsafe_replay` policy. This opt-in changes only construction policy:
accepted/rejected transport disposition and application-owned retry remain
unchanged. On the receive side, each active QUIC stream records whether
accepted 0-RTT supplied bytes or FIN. That provenance survives later 1-RTT
continuation and is carried by aggregate requests, every streaming event, and
endpoint-handler-owned requests as `was_early_data`; an independent 1-RTT
stream remains false and rejected early data creates no request state. Servers
can therefore return 425 or apply application-specific anti-replay policy
without guessing from stream IDs. The one-shot client API completes the other
half of RFC 8470: it automatically retries a TLS-rejected request or the first
425 response exactly once after the handshake using 1-RTT, preserves method,
target, headers, body, and trailers, and returns a second 425 without looping.
The result distinguishes transport rejection from application 425. Timeout
and absolute-deadline variants use one unchanged budget across the handshake,
initial response, and retry; a zero budget fails before allocation, ticket
consumption, packet-number use, or socket I/O. The lower-level early-request
connect API exposes matching relative and absolute handshake bounds. Shared
RFC 8470 header semantics additionally combine current-hop QUIC provenance
with a prior gateway's `Early-Data` signal. Any received instance, including
invalid or repeated values, remains replay-sensitive; origin-facing sends are
canonicalized by an explicit gateway action, and responses or trailers reject
the field. Aggregate and endpoint-handler requests expose this combined result
through `mightHaveBeenEarly()`, including ordinary 1-RTT current hops.
The endpoint handler supervisor can enforce `allow`, blanket `reject`, or a
resource-specific `inspect` decision at HEADERS time. A 425 decision occurs
before application scheduling and before DATA aggregation; subsequent DATA
and trailers are discarded without body copying while returning receive
credit, then the response is queued after request FIN. Ordinary 1-RTT requests
bypass the inspector, and applications remain responsible for RFC 8470's
cross-instance consistency requirement when using a callback.
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
Local-stream peer-frame validation now follows RFC 9000's implicit-open rule
audited in current `/nav_env/Work/quiche`: opening a higher-numbered local
bidirectional or unidirectional stream opens every lower stream of that type,
even when its transport state remains lazily unallocated. Authenticated
client/server role coverage sends `STREAM`, `RESET_STREAM`, `MAX_STREAM_DATA`,
and `STOP_SENDING` on those lower IDs, verifies lazy half-stream creation and
the automatic RESET response, and proves the next unopened IDs still fail
transactionally with `STREAM_STATE_ERROR`.
Receive-stream terminal delivery also distinguishes an unread FIN from an EOF
already returned to the application. A later same-final-size `RESET_STREAM`
still replaces unread or partially consumed data and reports its application
error, but it no longer makes the stream readable again after FIN was delivered.
The reset metadata remains available for diagnostics, duplicate consistency,
and final-size validation, matching the current `/nav_env/Work/quiche`
first-terminal behavior without discarding transport evidence.
`NEW_TOKEN` validation now keeps wire decoding separate from endpoint
semantics, matching current `/nav_env/Work/s2n-quic`. A client receiving an
empty token emits `FRAME_ENCODING_ERROR`, while a server receiving any
`NEW_TOKEN` emits `PROTOCOL_VIOLATION`; both closes identify frame type `0x07`.
The role-neutral decoder therefore retains an empty token long enough to make
that decision, while frame encoders and every public send path continue to
reject constructing one. Real protected 1-RTT tests cover valid client receipt
and empty/non-empty violations in both endpoint roles.
Locally sending `STOP_SENDING` now transfers every outstanding receive byte
back to connection flow control immediately, matching current
`/nav_env/Work/s2n-quic`; the abandoned stream never receives new
`MAX_STREAM_DATA` credit. STREAM bytes that were already in flight and a later
RESET final size are still charged under RFC 9000 section 4.5, then consumed
without becoming application-readable so sibling streams cannot be starved.
Blocking cancellation sends an eligible `MAX_DATA` update immediately, while
one-attempt APIs retain their single-submission boundary and schedule that
credit through the connection timer. Tests cover buffered and late data, reset
gaps, idempotent compatibility discard, and a failed credit send followed by
timer-driven retry.
Receive key updates now classify authenticated packets as current, next, or
retained-previous generation, track the current phase's lowest packet number,
and reuse the connection's monotonic `expected_packet_number` for its maximum,
following RFC 9001 sections 6.4-6.5 and current
`/nav_env/Work/s2n-quic`. A next-generation packet at or below an old-phase
maximum, or a retained-old packet above the new-phase minimum, terminates the
connection with `KEY_UPDATE_ERROR`; reordered old packets below that boundary
remain accepted until previous-key discard. The minimum is lowered by reordered
current-phase packets rather than frozen at the first update packet. A second
peer update before acknowledgement now also sends the required connection close
instead of returning a recoverable error. Focused tests cover both invalid
directions, reordered new-phase arrival, legal delayed old packets, duplicate
gating, and exact close state. The ordering state folds its ACK gate into two
sentinel `u64`s, preserving the prior `Connection` layouts.
Server migration filtering now treats RFC 6335 user and dynamic ports as one
non-system NAT-rebinding class while rejecting transitions into or out of the
0-1023 system-port range, matching current `/nav_env/Work/s2n-quic`. The check
runs before header protection, packet-number reconstruction, stateless-reset
comparison, or frame parsing, so a denied tuple cannot mutate authentication or
path state. Protected routed-packet coverage migrates 1024 -> 49152 -> 1025
with `disable_active_migration` enabled, then proves a 1025 -> 443 packet is
dropped without advancing the peer tuple, expected packet number, or receive
statistics.
STREAM send preflight now also checks the complete protected packet against
available congestion credit before materializing lazy stream state. This keeps
the existing exact `Frame.wireLen`/CID/packet-number/AEAD sizing while closing
the same near-capacity ownership boundary audited in current
`/nav_env/Work/quiche`: when cwnd can hold a four-byte stream ID and eight-byte
offset header but not one payload byte, the send returns `CongestionLimited`
without consuming a stream slot, flow credit, packet number, or recovery state.
A real UDP regression restores the window and sends that exact retained byte;
batch sends already performed their full-packet congestion preflight before
stream materialization.
Zero-length FIN acknowledgement is independently owned as well. Netz recovery
retains complete encoded STREAM frames, so ACKing an earlier data-only packet
cannot satisfy a later empty FIN, matching the lifecycle correction audited in
current `/nav_env/Work/quiche`. A focused regression ACKs the data packet,
sends FIN in its own packet, requests local stream retirement after the peer
receive half closes, and proves duplicate data ACKs leave the FIN recovery
payload and stream state intact; only ACKing the FIN packet releases recovery
and completes the retained retirement request.

## Known blockers before declaring the goal complete

Fatal handshake rejection now retains its original and server CID routes
after the worker releases its inbox and TLS state. The raw QUIC and HTTP/3
endpoint owners replay the final protected close through their shared receive
path, including borrowed and batched receives. Closing responses use a growing
interval and a cumulative three-times-received-byte limit; other peers and QUIC
versions receive no reply. A peer close retains silent draining routes. All
aliases expire after three times the current handshake PTO, including its
backoff, without extending the caller's receive deadline. The configurable
`closing_handshake_capacity` (default 1024) includes reserved live handshakes
and unexpired closing entries. Admission reserves storage before any worker
runs, so closing promotion allocates nothing and capacity exhaustion refuses
new work without evicting an existing closing route. Initial close socket
failure retains the exact ciphertext for a later permitted response. Endpoint
tests verify rejection is reported once, retransmission cannot create a second
admission, aliases and capacity are recovered on expiry, peer binding,
amplification, rate limiting, allocation failure and socket retry.

HTTP/3 supervisor receives with absolute deadlines also poll worker completion
at `handshake_poll_interval` (default 5 ms), capped by the original deadline.
A silent handshake failure can therefore reach the caller promptly without
requiring another UDP datagram to wake the receive loop.

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
reuses that replacement while the pool remains at exactly one connection.
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
The owning URI client now applies that same deadline across bounded
300/301/302/303/307/308 chains. Each hop performs a fresh QUIC/TLS handshake
with new original/local Connection IDs and fresh ephemeral inputs; explicit
Retry tokens, early data and resumption state are not replayed blindly.
Cross-origin client identities are denied by default and explicit resumption
state is cleared. QPACK Authorization/Cookie/Host/trailer fields receive the
same isolation as H1/H2; 303 rewrites non-HEAD requests to GET and removes DATA
plus representation fields, while 307/308 retain safe borrowed bodies. The
detailed result owns its final URI and hop count. Authenticated in-process tests
cover two independent servers, and the repository-pinned quic-go gate verifies
the two-connection 303 flow for QUIC v1 and v2 while its cancellation,
informational and reverse-role scenarios remain green.
The exclusive `HandshakeClientPool` exposes the same ordinary, detailed,
timeout and absolute-deadline redirect family. Each fully consumed response is
released before the next URI acquisition, preserving one whole-chain deadline,
stale-idempotent retry and pool capacity/LRU rules. Same-origin 303 hops reuse
the exact authenticated connection and its QPACK state; cross-origin 307 keeps
the method/body and ordinary fields while stripping credentials and trailers.
The default connector receives an explicit redirect security context, clears
manual/automatic resumption, early data, address-validation tokens, configured
server identity and deterministic ephemeral inputs on an origin boundary, and
the connector contract declares whether mTLS identity is configured so the
pool can reject that boundary before second-hop I/O. Local TLS/QUIC tests cover
same- and cross-origin paths. The repository-pinned quic-go v1/v2 gate requires
the exclusive pool's two redirect requests to use one connection.
`SharedHandshakeClientPool` owns one primary and an optional opposite-family
`std.Io` UDP endpoint plus one QUIC dispatcher across all pooled origins. Its
CID-routed handshake inboxes keep TLS workers off both sockets, successful
clients move into stable heap storage before atomic dispatcher promotion, and
idle reuse/global LRU eviction retain the configured connection cap. An opt-in
RFC 8305 policy stable-interleaves resolver results and staggers concurrent
handshakes from the matching endpoint; both synchronous acquisition and the
cloneable request driver promote a winner on either socket. Resumption and
0-RTT remain first-attempt-only, while a later winner reports rejection for one
safe 1-RTT replay. Loser cleanup unregisters and closes its inbox before
joining the worker, avoiding a wait for its phase deadline. Only the pool's
`receive*` methods own UDP receive; leases expose stable connection handles for
response correlation and reject client methods that would start a competing
receive loop. `receiveManyOnce` adds a bounded caller-buffer receive
turn for established pool connections: its dispatcher applies borrowed packet
views synchronously, while returned response/push events own all header state
needed after the receive storage is reused. The existing owning
`processResponsePacket` entry point remains source-compatible.
Explicit Alt-Svc acquisition now preserves the same single-reader topology:
the dispatcher resolves and dials only the alternative host/port while the URI
origin continues to own SNI, certificate policy, origin+ALPN resumption/ticket
state, pool identity, and `:authority`. Idle selection prefers exact matches
and permits a different origin only after both RFC 9412 authorization and
retained leaf-certificate DNS/IP validation. Coalesced leases keep their
request origin separate from the stable connection origin and expose a
fail-closed 421 removal hook. A real protected-QUIC test verifies correct ticket
scope, same-handle coalescing, certificate-mismatch isolation, original-origin
reuse after 421, and a fresh connection for the excluded origin.
The underlying authenticated client now exposes an owned-response batch with
per-stream absolute deadlines and an optional producer cancellation event.
Requests remain correlated by input index under reversed response order;
deadline or active cancellation sends H3_REQUEST_CANCELLED only for the target
stream, preserves each sibling's original budget, and keeps the connection
reusable. The cancellation event races the sole response receive and gives a
simultaneously completed response precedence, matching the driver/sender split
used by mature H3 stacks without adding another socket reader. Real protected
QUIC coverage includes POST body/trailers, reversed completion, both cancel
sources, exact peer-visible codes, sibling progress, and reuse.
The exclusive H3 pool now maps same-origin direct/Alt-Svc URI batches onto that
runtime primitive, including pre-admission expiry/cancellation filtering,
original-index translation, SETTINGS observation, 421 handling and lease
cleanup. A bounded cloneable-sender dispatcher adds stack-owned FIFO commands
without creating another socket reader. Compatible producers coalesce on one
QUIC connection; timeout or task cancellation wakes the sole driver and waits
for target-stream cancellation convergence before releasing borrowed command
storage. Real coverage verifies four producers, reversed responses, one
connection, later Alt-Svc reuse, then a short canceled command beside a
successful long-deadline sibling.
`beginUriFollowingRedirects*` adds the matching event-driven redirect boundary
without introducing a competing UDP reader. Its transaction replays borrowed
bodies through bounded one-packet DATA attempts, consumes only events matching
its current connection handle and request stream, drains each intermediate
response, releases that lease, and then acquires the next origin under the same
absolute deadline. Unrelated response, push and unrouted events remain
caller-owned. Same-origin 303 tests force a multi-packet POST and prove the
second GET reuses the same route; cross-origin 307 tests preserve method/body
and ordinary fields while stripping credentials and trailers before a fresh
route is promoted. The quic-go v1/v2 process gate now runs one-shot, exclusive-
pool, and shared-pool redirects: six requests and three redirects must use
exactly four connections, with one connection for each pool's two requests.
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
live routes per connection. Explicit peer-CID rotation now reserves the bounded
retirement queue before changing state, removes the prior CID only after that
reservation succeeds, and surfaces queue exhaustion without changing the
selected CID or use counts. A separate real UDP state-loss regression completes
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
The caller-buffer batch receive path returns a bounded snapshot of timers due
across different connections, with each connection serviced at most once before
UDP receive gets another turn. A pacing-limited PTO keeps its exact future pacing
wake-up without aborting the rest of the snapshot. At 16 connections this reduced
the timer-heavy server-sender receive-call median from 3,266 to 1,088 against the
immediate parent, while throughput ranges overlapped; this is scheduling
amortization evidence rather than a throughput claim.
The same scheduler now rejects an all-future timer snapshot from its cached
earliest deadline instead of scanning every connection on each receive turn.
Five CPU-0 fixed-binary ABBA rounds reduced that query from 7.31-9.03 to 0.38
ns/op at 16 connections and from 407.25-424.34 to 0.38-0.42 ns/op at 1,024;
the one-due controls retained their linear snapshot cost. Five shared-server
transfer pairs had overlapping ranges and 3/5 candidate wins in both sender
directions, so they establish no regression rather than a throughput gain.
When the caller and transport deadlines share the awake clock, receive-timeout
composition now orders their absolute timestamps directly instead of reading
that clock twice to compare remaining durations. Tests prove the same-clock
branch makes no clock call and the generic cross-clock branch still makes both
reads. Five shared-server pairs favored the candidate 4/5 times in both sender
directions, but their throughput ranges overlapped, so this remains a fixed-work
reduction rather than a throughput claim.
Independent-message batch receive also leaves ancillary buffers uninitialized
until the OS fills them, matching Quinn's Linux `MaybeUninit` receive storage and
removing a fixed 2,304-byte stack write at the default 32-message width on this
Linux AArch64 ABI. A real ECT(0)/ECT(1)/CE/Not-ECT batch verifies exact
per-message metadata. Five paired long transfers had overlapping ranges and
mixed direction results, so this is a fixed-work reduction rather than a
throughput claim. A new `--netz-only` runner mode makes same-binary
independent-topology measurements reproducible without a Go fixture. Current
three-sample shared/independent medians were 96.750/94.295 MiB/s for
client-sender and 75.982/87.691 MiB/s for server-sender; wide overlaps mean the
historical shared gap has narrowed in this observation but is not yet proven
closed.
The endpoint router now probes its stored fixed-size CID keys with borrowed
datagram slices, avoiding a zero-fill and copy on every lookup. A dedicated
64-route benchmark reduced 16-byte CID hit latency from 51.98 to 28.62 ns and
same-length miss latency from 39.56 to 12.03 ns, with 5/5 wins in both cases.
A five-pair 16-connection shared-server check also improved server-sender median
throughput from 85.021 to 90.453 MiB/s with 5/5 pair wins, but the ranges
overlap, so this remains supporting end-to-end evidence. An experiment that
coalesced all packet/timer notifications per connection was removed after both
sender-direction medians regressed despite reducing ready notifications.
The shared server also exposes socket-free STREAM send credit so application
loops can submit a positive flow-control tail without weakening transactional
`trySend` semantics. A real 1,024-byte-window regression timed out at payload
offset zero before the change and completed 65,536 bytes plus checksum and
completion exchange after it. A 16-connection server-sender pressure run then
completed 1 GiB total exactly. Standard-window throughput pairs were mixed with
overlapping ranges, so this closes a progress gap rather than claiming speed.
The shared blocking payload helper now applies the same credit-aware prefix
rule, covering client-sender and independent-server paths. With a 1,024-byte
stream window, parent `4fe04ace` timed out at client payload offset zero while
the candidate completed both sender directions in shared and independent
topologies. Standard 1-MiB-window throughput remained noisy and overlapping.
The raw connection also exposes `cancelStreamWithTimeout` and
`cancelStreamWithDeadline`. They preserve the existing atomic RESET_STREAM plus
STOP_SENDING submission while waiting for ACK/loss/PTO or pacing under one
absolute awake-clock budget. Expiry, pacing/congestion timeout and socket
failure leave both halves retryable and retain unread bytes; success preserves
an already committed FIN and suppresses duplicate cancellation packets. Seven
real-UDP regressions verify both frames in one protected packet, exact code and
Final Size, queued ACK progress, timeout rollback, socket failure and the
STOP_SENDING-only path after local FIN.

The underlying raw connection now exposes deadline-bounded complete STREAM
writes with exact committed-prefix reporting. Tests cover positive flow-credit
tails, multi-packet MTU splitting, FIN, timeout continuation, and socket-visible
partial failure followed by suffix retry, without weakening the existing
single-packet transactional send APIs.
Borrowed scatter/gather variants now extend that contract across slice
boundaries without first joining application buffers. Their logical committed
prefix remains exact after a socket-visible packet error; flow-credit timeout,
MTU packetization, empty slices, overflow preflight, suffix retry, and final
FIN placement have direct raw-connection coverage. Stateful STREAM sends now
also charge flow control by new highest-offset increments, so sparse gaps are
counted and overlap is not double-charged. Batch and 0-RTT preflight use a
per-stream final-size shadow, and partial socket prefixes roll back only their
unsent offset increments.
The shared benchmark now exercises ACK policy through negotiated draft-07
ACK_FREQUENCY rather than changing only the server's local configuration. Both
peers advertise `min_ack_delay`, but only the client requests that the server
ACK on the fourth ack-eliciting packet; the server does not make the reverse
request. Five fixed-binary, order-interleaved 16-connection upload pairs moved
the median from 57.579 to 76.974 MiB/s (33.7%, 4/5 wins) and reduced the server
UDP-send median from 10,950 to 4,445 datagrams (59.4%). The throughput ranges
overlap. The reverse-direction control moved from 80.281 to 85.733 MiB/s with
3/5 wins and overlapping ranges, supporting only the absence of the systematic
regression produced by bidirectional requests. Every arm verified 16 MiB, the
exact checksum, 16 completions, and DONE/DONE_ACK. The frame's wire tolerance
of three is converted to an internal fourth-packet trigger; negotiated automatic
requests share the first non-empty 1-RTT packet with HANDSHAKE_DONE when needed,
remain pending across socket failure, and enter ordinary PTO recovery only after
successful transmission. Once negotiated, every application-data PTO probe also
carries a fresh, non-retransmittable IMMEDIATE_ACK hint, matching Quinn; a
full-MTU reliable payload omits the optional byte instead of losing data. A
real 4-MiB 5%-loss run dropped 25/504 datagrams and verified all bytes. Five
fixed-binary 1-MiB/100-us pairs had 3/5 candidate wins but overlapping ranges
and a slightly slower independently sorted median, so this is a recovery
correctness result rather than a speed claim. Callers can additionally select
an explicit Requested Max Ack Delay. The sender includes any socket-visible but
unconfirmed increase in PTO immediately, retains the maximum across successive
requests, and commits a decrease only when an ACK covers the newest request's
recovery group or any retransmission copy. RTT adjustment, PTO jitter, idle and
keep-alive bounds, persistent congestion, path reset, and close/drain timing use
the same effective delay. The no-sample application-data PTO now includes the
full RFC 9002 initial RTT + 4*rttvar + max_ack_delay (325 ms at defaults) rather
than the previous 200-ms underestimate. Socket failure leaves the prior PTO
unchanged, and the shared benchmark's null delay override preserves its ACK/4
policy. A final-source five-pair 5%-loss/100-us check won 2/5; medians moved
from 9.552 to 9.390 ms but the ranges overlap, so no performance gain is
claimed.
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

HTTP/3 now exposes an owning multi-connection admission lifecycle plus a
bounded handshake supervisor. It generates unique per-connection server CIDs,
assigns inboxes,
starts cancelable workers, reports completions without blocking the socket
owner, unregisters failures, and returns stable heap-backed sessions whose
successful promotion cannot invalidate dispatcher pointers. Admission has
separate pending-handshake and aggregate pending-plus-established connection
caps, releasing total capacity when a live connection is removed. The supervisor's
single-owner receive API interleaves completion polling, endpoint timers, and
UDP routing. Shared endpoint sends are serialized across handshake/connection
workers, including ECN socket state, GSO fallback state, and deterministic
fault-injection queues. `EndpointServer.serveHandlersUntil` adds the aggregate
application convenience layer above that single-owner loop. It assembles HEAD,
DATA, trailers, and FIN into bounded owned requests; runs at most
`max_handler_tasks` callbacks concurrently; copies every returned response
through a caller-selectable thread-safe allocator immediately after the
callback returns; and returns response head, packet-sized DATA, and trailers to the
endpoint owner for transactional nonblocking sends. `max_pending_requests`,
`max_request_body_bytes`, and optional `stop_after_responses` bound retained
work and one-shot server lifetime.
Callbacks receive a borrowed `OwnedEndpointRequest` pointer with exact
connection/stream identity and owned decoded fields/body/trailers; returned
slices may borrow that request or longer-lived context, but not callback stack
locals.
Handler failures either report and reject only that stream with
`H3_REQUEST_REJECTED` or stop according to policy; a persistent-connection
regression proves a later request succeeds after such a rejection. `zig build
interop-http3-quic-go-handlers -Doptimize=ReleaseFast` pins quic-go v0.59.0
and opens two independent QUIC connections for each of v1 and v2. Both
handlers must enter a barrier before either returns, and quic-go verifies both
echoed bodies and response trailers. This is application-handler concurrency
evidence rather than handshake admission alone. Streaming requests, Extended
CONNECT, and protocol adapters continue to use `serveUntil` or
`serveTransportUntil`, so mutable session state never crosses worker threads.
WebTransport exposes a split handshake/admission object that can
be promoted before CONNECT polling. Its endpoint server now retains stable
pending and accepted sessions around HTTP/3's sole-receiver transport loop,
dispatches CONNECT, stream, DATAGRAM and Capsule events, and shares HTTP/3's
handshake expiry policy. HTTP/3's endpoint server stores stable promoted
sessions, routes packets and timers, polls requests without per-connection
socket reads, and explicitly
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
   same Subject with another key. A separate local process gate builds quic-go
   v0.59.0 from the repository-owned checksum-locked module and checks HTTP/3 in both directions with
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
   v0.59.0 from the repository-owned checksum-locked module, loads its generated
   localhost CA into netz's verifier, requires TLS 1.3 `hq-interop` ALPN, and
   verifies two independent bidirectional STREAM echoes plus FIN. The shared
   netz client/server executables obtain `std.Io` from the zio-backed
   `netz.runtime.Backend`; the runner and handshake-fault verifier require
   `zio-std-io` and `quic-go-netpoll` identities for the appropriate endpoint
   roles. The same gate
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
   fixture identity. The same zio-backed netz peer executables are used here;
   the fixture's `#[tokio::main]` runtime and both shell directions explicitly
   assert `zio-std-io` versus `s2n-quic-tokio`. The s2n server also asserts the
   `localhost` SNI. Both
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
   demonstrating cancellation recovery without connection-wide disruption.
   Two further connections run a bounded mixed lifecycle with each stack as
   sender: all 32 streams first deliver a verified 256-byte prefix, then 16
   streams reach a 16-KiB FIN while 16 terminate with exact index-specific
   reset codes. Both peers independently require the same 266,240-byte total,
   checksum, reset mask/code sum, control-stream completion, and application
   close. Four more connections make netz the sender in both endpoint roles
   under one RESET-phase plus one FIN-phase datagram loss or real pair
   reordering. Explicit phase acknowledgements prove recovery before rearming,
   and the netz endpoint requires exactly two injected faults per connection.
   The fault scope is netz outbound; s2n-quic's outbound path is not modified.
   Two dedicated connections additionally enable s2n-quic's native unstable
   RFC 9221 provider and exercise both endpoint-role pairings. Each endpoint
   sends two distinct small DATAGRAMs plus one boundary DATAGRAM, while the
   receiver compares an unordered set. With netz advertising a 64-byte frame
   limit, s2n sends exactly 62 payload bytes and rejects 65 locally; netz's
   1200-byte path yields an exact 1163-byte payload boundary and rejects 1164
   locally. Both directions then complete a reliable stream 4 `world` echo and
   application close, separating unreliable-message success from stream and
   connection lifecycle success. The netz endpoints use zio-backed `std.Io`;
   the independent provider runs on s2n-quic's Tokio runtime.
   A separate Quinn 0.12 process gate at audited commit
   `d9c8c4c695fc64292d9b117844ea6924ca0d0815` runs the same two role
   pairings with rustls and Quinn's native DATAGRAM API. Quinn deliberately
   reports a conservative 55-byte payload boundary for netz's 64-byte frame
   limit and rejects 56 bytes; Quinn's eight-byte CID lets netz send exactly
   1171 bytes on the fixed 1200-byte path and reject 1172. It independently
   verifies the unordered payload set, stream 4, close 57/58, ALPN/SNI, and
   `zio-std-io` versus `quinn-tokio-rustls`. Four further connections arm a
   one-shot netz outbound fault immediately before its three DATAGRAM sends in
   each endpoint role. Under loss, Quinn receives exactly the latter two,
   completes reliable stream 4, then observes no retransmission for another
   100 ms. Under hold/send/flush reordering, Quinn receives all three and
   requires the second small payload before the first. Every case records one
   injected fault and the expected application close; Quinn outbound traffic
   is not fault-injected.
   A separate netz-client connection sends and receives
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
   but still needs capture-backed equal-wire accounting. HTTP/3 now has four
   zero-drop v1/v2 upload/download AF_PACKET artifacts for both mixed role
   pairs; they prove materially different packetization rather than equal-wire
   traffic. DATAGRAM,
   loss simulation, and stream reservation
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

## HTTP/3 direction-aware paced body batching

The production handshake runtime now resolves a zero
`paced_body_chunk_bytes` by endpoint role: 5,000 logical DATA bytes for client
request bodies and 8,000 for server response and push bodies. Explicit
non-zero overrides retain their former behavior. The larger response batch is
not a larger packet: current congestion, connection/stream flow control,
STREAM frame sizing, and datagram limits still determine each protected
packet. A standard 1,200-byte datagram therefore exposes only 1,136 bytes of
body capacity, while the benchmark's 8,192-byte datagram can use the complete
8,000-byte response batch.

CPU-0-pinned, warmed, fixed-binary AB/BA comparisons against clean commit
`162dc380cd796025b22bb872db9c6c130ab9ffcb` improved four-stream downloads from
140.23 to 221.88 MiB/s for 16 MiB (+58.30% paired mean) and from 146.98 to
203.05 MiB/s for 64 MiB (+38.15%). The direction split was required: using
8,000 in both directions regressed upload by 11.55%, whereas the final
5,000-byte request default left the seven-pair 16-MiB upload control at
208.74 versus 208.64 MiB/s (-0.02%, noise-level). Every run verified exact
bytes and four status-200 responses. Baseline and candidate SHA-256 values are
`f59cdfdda5a161ee8ddf747b1e4855e22a4b3a3afaf8d212b6c4ecb850a35579` and
`86e70110399ace34a9380bdf522605aa51d8356a6e7b2745225869449658fb11`.
This closes the identified internal server-download packet-fill default gap;
cross-stack results remain same-application-shape until a new capture proves
wire-shape equivalence.

The response scheduler now also refuses to turn only the transient tail of a
congestion window into a short DATA packet. A diagnostic 1,280-byte-MTU run had
shown 833-, 48-, and 208-byte body contributions whenever congestion credit
fell below the otherwise usable 1,152-byte contribution. Flow-control-limited
chunks and final tails still progress immediately. Fixed ReleaseFast AB/BA
runs improved four-stream download throughput by 63.25% at a standard
1,200-byte datagram, 64.15% at the cross-stack-shaped 1,280-byte datagram,
31.66% for the default 8-KiB/16-MiB shape, and 40.63% for the default
8-KiB/64-MiB shape. The single-stream download and multi-stream upload controls
were noise-level at +0.45% and +0.41%. A certificate-verifying quic-go v0.59.0
gate then completed five samples in both download role pairings with exact
bytes, checksums, stream counts, and statuses. A new privileged capture is
still required to replace the pre-change 1,125-byte packet-size distribution;
the current process cannot open AF_PACKET and has no passwordless sudo.

The new `bench-http3-quic-go --socket-traffic` mode supplies a strict
no-privilege userspace boundary while that PCAP rerun is unavailable. It wraps
both stacks' UDP endpoints, disables GSO, validates sender/receiver accounting,
and marks timings unusable. On the full v1 2-warmup + 5-measured, four-stream,
4-MiB-per-stream shape, a fresh 2026-11-01 run measures netz averaging
1,190.000/1,189.105 UDP payload bytes for download/upload versus quic-go's
1,186.089/1,187.161. The former packet-fill deficit is therefore absent at this
boundary. Netz still sends 3.33%/4.26% more datagrams and 3.67%/4.43% more
bytes, narrowing the remaining investigation to retransmission and control/ACK
behavior without claiming encrypted-frame or kernel-wire equivalence.
Structured transport/qlog attribution then matched 3,306 netz download losses
to 3,315 quic-go `dos_prevention` drops and 4,081 netz upload losses to 4,102
corresponding drops. All quic-go duplicate, payload-decrypt, and other drop
categories and all netz authentication failures were zero. The residual
retransmission cost therefore comes from the peer's bounded unprocessed-packet
queue under this zero-latency workload, not malformed netz packets; future
pacing work must preserve normal-network throughput rather than hiding the
receiver limit with a benchmark-only delay. The fresh comparison is recorded in
`docs/evidence/http3_socket_traffic/2026-11-01.json`.
Netz now exposes an optional production `max_pacing_rate_bytes_per_second` on
both direct and handshake-created 1-RTT connections. The token bucket uses the
lower of that ceiling and `1.25 * cwnd / RTT`, while the default remains
unlimited. Established connections can change or remove the ceiling without a
reconnect: the pacer first accounts elapsed time under the old rate, preserves
already earned burst credit, advances from a non-regressing timestamp, and
invalidates any cached pacing wake-up before future sends use the new policy.
The shared-socket dispatcher exposes matching handle-based setters that update
the registered connection and its endpoint timer index as one owner operation.
Connection statistics expose both the configured ceiling and the effective
rate after the congestion-derived value is capped; qlog
`recovery:metrics_updated` now populates its existing `pacing_rate` field from
the same calculation instead of silently omitting it.
`bench-http3-quic-go` accepts the corresponding
`--netz-max-pacing-rate-bytes-per-second` experiment parameter and records it
in config and loss-attribution records. A 1-MiB/s, four-stream, 64-KiB-per-
stream upload smoke held the netz sender at 1.010 MiB/s with zero transport
loss and zero quic-go drops; the reverse pairing left quic-go uncapped. This
validates the control path without promoting that artificial loopback rate to
a production default.
A fixed-binary A/B/B/A follow-up on clean commit `b618417d` used four 4-MiB
streams and one warmup plus two measured connections per arm. The same
netz-client, netz-server, and quic-go executable hashes appeared in every
record. Unlimited netz upload arms lost 1,918/2,133 packets and the matching
quic-go receiver reported 1,928/2,144 `dos_prevention` drops; unlimited
download arms lost 1,413/2,592 with 1,416/2,598 peer drops. Both 128-MiB/s
candidate arms in both directions had zero transport loss and zero peer drops.
A single coarse scan retained losses at 192 and 256 MiB/s but not at 128 or
96 MiB/s. This isolates a host-specific receiver-capacity knee; it supports the
new opt-in control while explicitly leaving the production default unlimited.

## Next recommended work

The Quinn full-handshake matrix now removes its certificate-wire confounder:
both server implementations receive the same generated CA-signed P-256 leaf
and scalar, and the strict result includes the identity hash plus per-connect
UDP counts/bytes. Phase timing showed repeat leaf-to-CA trust verification as
the largest netz-client component. The new bounded, caller-owned TLS bundle
verification cache keys successful decisions by exact host and DER chain while
retaining mandatory per-connection CertificateVerify. A five-pair fixed-binary
ABBA run reduced fixed-Quinn-server P50 from 2.283 to 1.709 ms and raised the
rate from 376.0 to 508.2 connects/s. The remaining roughly 0.6-1.0 ms around
each side of the trust callback is the next profiling target; packet counters
show one 1,200-byte receive for both clients, so it should be split into QUIC
protection/key-schedule/CertificateVerify and endpoint scheduling rather than
attributed to extra receives.
The subsequent shared-identity 5x100 cross-stack matrix measured 1.679 ms for
netz versus 1.311 ms for Quinn at fixed-Quinn-server P50 (netz 0.781x), and
2.055 ms for netz versus 2.272 ms for Quinn at fixed-netz-server P50 (netz
1.105x). These remain complete role-pair observations, not isolated library or
equal-wire rankings.
The QUIC client now also owns one incremental negotiated transcript state,
matching the stateful transcript approach used by mature TLS stacks instead of
rehashing ClientHello and ServerHello at five successive derivation/signature
boundaries. SHA-256/SHA-384/SM3 snapshot equivalence plus authenticated, PSK,
mTLS, and 0-RTT handshake tests cover the ordering. A fixed-Quinn-server 5x100
same-binary ABBA moved P50 from 1.586 to 1.275 ms and timed-sum rate from 615.7
to 730.2 connects/s; that run isolated CertificateVerify and pre-trust
packet/key-schedule work as the next targets. The prepared-verifier pass below
addresses repeated fixed-identity CertificateVerify cost without weakening
fresh-key or multi-identity behavior.
The final shared-identity 5x100 matrix measured netz/Quinn at 1.136/1.051 ms
P50 with the fixed Quinn server (netz 0.925x), versus the preceding
1.679/1.311 ms matrix. UDP counts and bytes were unchanged. The fixed netz
server produced 1.617/1.270 ms, so further work must continue to separate
client cryptography from server scheduling rather than treating either
complete-pair result as a universal implementation ranking.
The same incremental transcript owner now covers the server. This also fixes
the mTLS application-secret derivation boundary to server Finished; the P-384
mTLS test now proves the correction by exchanging protected STREAM data after
authentication. A fixed-Quinn-client 5x100 A/B moved server-path P50 2.234 to
2.140 ms but moved timed-sum rate 395.4 to 390.8/s, so no end-to-end server
speedup is claimed.
The final both-role incremental 5x100 matrix measured fixed-Quinn-server
netz/Quinn at 1.618/1.357 ms P50 (netz 0.839x) and fixed-netz-server at
1.972/2.201 ms (netz 1.116x). Its absolute shift from the immediately preceding
matrix is treated as host-load noise; the same-binary A/B remains the causal
evidence.

The client CertificateVerify path now honors `ClientVerifier`'s prepared
Ed25519, P-256, and RSA hooks. Integrated matching/mismatched P-256 handshakes
prove success and exact-key rejection. The fixed-identity Quinn runner builds
the P-256 table outside the timed loop and labels every sample; a
fresh/prepared/prepared/fresh block ABBA reduced fixed-Quinn-server P50 by
21.7% and 20.3%, with the post-trust phase down 49.3% and 51.4%. Trust-path
verification remains enabled on every connection through the separate bounded
cache, and the prepared table is never installed automatically in that
multi-identity cache. Remaining handshake work is therefore pre-trust
packet/key-schedule/event-loop cost and tail scheduling, not another removal of
certificate authentication. A prepared-mode fixed-Quinn-server profile then
attributed 21.9% of isolated netz-client cycles to X25519 shared-secret
multiplication and roughly another 14--15% to fixed-base public-key recovery.
Published Vail `2317957` splits a portable five-group/four-column X25519 table
from the unchanged Ed25519 prepared-verifier table. Fixed-binary CPU-0 evidence
reduced X25519 public recovery 26.1% and a pure in-memory TLS client handshake
6.65%, with every candidate arm faster. The cross-process Quinn block result
was host-noisy and is not promoted as a complete-handshake gain. Vail
`ad3f8e7` additionally makes the QUIC TLS server reject a non-empty initial
client-auth request context before emitting either output flight, matching RFC
8446 and the ordinary TLS server path. Published Vail `89d6292` subsequently
adds a constant-time s2n-bignum-derived ARM64 variable-base ladder with explicit
secret-stack and caller-register clearing. Fixed-binary CPU-0 evidence reduced
the shared-secret primitive 42.5% and a pure in-memory TLS client handshake
20.6%, with every candidate arm faster; ReleaseFast/ReleaseSafe differential
tests cover 4,096 deterministic arbitrary points. Cross-process Quinn blocks
remained host-noisy and are not cited as end-to-end gains. Published Vail
`8571f55` then adds the companion constant-time ARM64 fixed-base kernel with a
48,576-byte affine table and explicit 448-byte stack/register clearing.
Fixed-binary evidence reduced public recovery 59.4% and a pure in-memory TLS
client handshake another 14.3%, with every candidate arm faster and 4,096
deterministic public-key differential cases. Two mirrored fixed-Quinn-server
blocks improved netz-client P50 by 0.4% and 4.9% despite slower Quinn controls;
this remains bounded workload evidence. Packet/key-schedule work and tail
scheduling remained the next handshake targets. The following Netz pass moved
coalesced 1-RTT preload and accepted/rejected 0-RTT import into one typed
client/server promotion boundary before the first established return.
ReleaseFast disassembly removed three explicit 9,328-byte copies from each of
`connectAttempt` and `acceptInternal`, reduced their fixed stack reservations
by 18,464 and 18,528 bytes, and reduced the benchmark ELF `.text` by 2,704
bytes. Focused Debug/ReleaseFast lifecycle gates and the strict four-role Quinn
smoke pass. Short same-certificate fixed-binary blocks gave four of four P50
wins and a 0.12% aggregate instruction reduction, but longer blocks moved with
host load in both directions; copy, stack, code-size, and instruction evidence
is causal, while complete-handshake latency remains a bounded observation.
The follow-up caller-storage one-RTT initializer then reduced 9,016-byte copies
inside `establishedConnection` from three to one and its fixed stack reservation
from 35,696 to 17,968 bytes, with exhaustive allocation-failure rollback
coverage. Four of four short-block instruction pairs improved by 0.08% at the
midpoint median, while complete-handshake P50 won only three of four and had a
slightly worse four-block midpoint. This retains the exact copy/stack benefit
without promoting noisy end-to-end latency. The remaining handshake targets
were packet/key-schedule work and tail scheduling outside these removed
returns. Long-header open now additionally retains one mutable packet copy and
decrypts Initial, Handshake, and 0-RTT payloads in place, so DCID, SCID, token,
and plaintext share one allocation instead of separately owned slices. A real
100-connection run reduced allocations from 7,901 to 6,401 (15 per connection,
19.0%) and cumulative bytes 5.2%, with zero live bytes and neutral peak storage.
Ten fixed-binary mirrored pairs all improved P50 and rate; midpoint medians
moved by 0.27% and 0.24%, while P99 remained neutral. Fail-first OOM and
single-allocation tests cover all three packet types. Remaining handshake work
was online crypto/key-schedule cost and tail scheduling rather than long-packet
ownership churn. Finished now also encodes into caller storage: the server
appends directly to its existing flight, the ordinary client sends its stack
message, and mTLS retains one exact owned fallback. A 100-connection run fell
from 6,401 to 6,101 allocations (three per connection), reduced cumulative
bytes 0.77%, and retained zero live bytes. Ten fixed-binary mirrored pairs gave
nine P50 wins and a 0.18% midpoint reduction; rate and P99 were mixed, so they
are not promoted. SHA-384, short-buffer, ordinary, and mutual-TLS tests cover
the caller-storage and fallback branches. The CRYPTO reassembler's two small
data/presence allocations were the next distinct ownership target. It now
shares STREAM's lazy packed bitmap: continuous CRYPTO bytes keep an implicit
dense prefix, and only the first gap materializes presence words. Transactional
OOM, matching overlap, sparse fill, and conflicting-data tests retain exact
semantics. A real 100-connection run fell from 6,101 to 5,701 allocations
(four per connection, 6.6%) and cumulative bytes 2.2%, with zero live bytes and
an unchanged peak. Twenty fixed-binary mirrored pairs were timing-neutral at
10/20 P50 and 9/20 rate wins, so only the deterministic allocation/state
reduction is claimed. Remaining handshake work is online crypto/key-schedule
cost and tail scheduling.

1. Extend the two-CPU raw QUIC process comparison with kernel/interface packet
   capture, WebSocket/WebTransport allocation telemetry, and lossy/reordered
   on-wire lifecycle churn. Persistent echo, four independent connections,
   and one-socket shared-server scaling at 1/4/16/64 connections are now
   covered. The pinned zio backend now fulfills multi-slot `std.Io` UDP receive
   with native batching. A five-sample mirrored-order topology run measured
   shared/independent medians of 1.031x for client-sender and 1.052x for
   server-sender, replacing the pre-fix 0.661x/0.649x baseline. The ranges
   overlap, so this removes the observed median deficit without establishing
   that shared topology is generally faster.
   `bench-quic-persistent-external --mode=aggregate --netz-only
   --server-topology=compare` now provides that missing fixed-binary, odd-sample
   mirrored-order topology gate. It fixes both sides to ACK-every=2 and 25 ms,
   then reports per-sender shared/independent median ratios after strict
   completion validation.
   Its `--connection-counts=1,4,16,64 --server-topology=shared` companion runs
   both sender roles at each size and reports aggregate retention without
   assuming linear throughput on two fixed CPUs. A three-sample 1-MiB-per-
   connection run retained 82.0%/87.0% of one-connection aggregate throughput
   at 64 client/server-sender connections while verifying exact 64-MiB delivery
   and all 64 completions in every arm. Its periodic exact payload verifier no
   longer makes scalar generation/verification the top benchmark hotspot;
   fixed-binary 64-connection medians improved 32.7%/12.1% without changing
   application bytes, checksum, FIN, or completion exchange.
   Complete-connection userspace UDP counters and the new loopback packet
   captures expose materially different wire shapes. Equalize GRO, ACK/pacing,
   packetization, and application stream
   scheduling before promoting it from same-application-shape to equal-wire.
2. Re-run HTTP/3 GRO on a host with larger kernel UDP receive buffers; the
   timer/recovery path is now safe, but this host's throughput regresses.
3. Reduce remaining HTTP/3 packet-protection and recovery bookkeeping cost.
   The current-key in-place receive path now computes header protection once
   and reuses that preview for decryption instead of peeking Key Phase and then
   recomputing the mask. Five CPU-0 samples reduced median allocating, service,
   and visitor cost by 2.6%, 3.8%, and 4.5%. Single-STREAM transactional
   Prepared AES state now keeps only the negotiated suite's header-protection
   schedule in a tagged union, matching quiche/tquic's suite-specific key
   ownership. Each prepared object shrank from 1,792 to 1,600 bytes and each
   AES connection therefore retains 384 fewer bytes across send/receive state.
   Seven fixed-binary short-packet and real H3 A/B pairs were throughput-neutral
   (H3 median 162.15 to 162.32 MiB/s, 4/7 wins), so this is recorded only as a
   deterministic memory reduction. Connection ownership now groups send and
   receive prepared keys into one stable allocation while retaining
   single-direction and non-AES variants for low-level mixed-suite
   configurations. A linked-backend 100-handshake run reduced allocations from
   7,901 to 7,701 with unchanged peak memory; seven fixed-binary paired runs
   left median rate/P50 within 0.3%. Vail `b6dd7b6` then reduced each inner
   prepared AEAD state from 1,344 to 752 bytes by keeping only the negotiated
   AES context. The combined netz object is 1,008 bytes; a repeated 100-handshake
   run retained 7,701 allocations but reduced total requested bytes to
   7,456,115 and peak live bytes to 56,211. Direct directional pointers keep
   the ownership tag off the per-packet access path; a same-Vail seven-pair H3
   control improved the four-stream upload median 1.7% with 6/7 wins, retained
   only as workload-specific supporting evidence. Single-STREAM transactional
   preflight now avoids unrelated general-packet shadows; seven paired runs
   reduced visitor/service median cost another 1.5%/2.8%. Packed receive-byte
   tracking then reduced those STREAM medians another 11.9%/11.7% and removed
   the prior per-byte bitmap memset hotspot. Ordered streams now keep this
   presence state as an implicit dense prefix and allocate packed words only
   after the first gap; the bitmap implementation and model tests moved to
   `src/quic/stream/received_bitmap.zig`. Seven current fixed-binary visitor
   pairs reduced ordered STREAM median 2.0% with 7/7 wins and left the reordered
   gap control within 0.6%. A real H3 four-stream upload remained noise-level
   (-0.4%, 3/7 wins), while seven allocator pairs used a 5.7% lower median
   call count. Gap closure
   finds the next
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
   Send validation no longer merges each classified frame into an all-zero
   temporary Traits before merging that temporary into the packet aggregate.
   The final implementation preserves the existing out-pointer call shape and
   overwrites the per-frame scratch directly, including exact STREAM byte
   accounting. Two return-value variants were rejected first: the uninlined
   form reduced instructions 0.31% but regressed cycles 1.38% in the one-frame
   shape; forcing it inline reduced H3-shaped instructions 1.83% but still
   regressed 50k four-fragment cycles 0.37%. The out-pointer form passed the
   same long H3 guard with instructions/cycles/sequential/batch improved by
   paired medians of 1.80%/0.58%/0.80%/1.11%. Single-STREAM controls improved
   0.64%/0.31% instructions/cycles, and DATAGRAM controls improved 1.09%/0.67%;
   its packed DATAGRAM batch path intentionally bypasses the changed validator
   and remained neutral. A real TLS/H3 four-stream 16-MiB upload completed 3/3
   at 232.25 MiB/s mean, while quic-go v1/v2 and tquic normal/Retry/GOAWAY
   matrices remained green. Full fixed-binary rows are recorded in
   `docs/evidence/quic_frame_traits_direct/2026-10-30.json`.
   Profiling that accepted binary then showed the remaining per-frame scratch
   copy below `validateOutboundFrames`: one frame was classified into a
   temporary Traits and then merged into the packet aggregate. Validation now
   accumulates directly into the packet Traits and returns only the current
   frame's retransmittable bit for recovery-length accounting. Relative to the
   preceding accepted binary, five 50k four-fragment pairs improved H3-shaped
   instructions/cycles/batch medians by 0.48%/0.13%/0.56%; one-fragment
   controls improved instructions/cycles/sequential/batch by
   0.40%/0.67%/0.49%/0.94%. A 50k DATAGRAM control improved instructions and
   cycles 0.57%/0.29%; sequential wall time moved 0.41% slower with 2/5 wins,
   while the specialized packed path stayed neutral, so no DATAGRAM timing
   claim is made. A follow-up that borrowed the complete packet Traits by
   pointer into preparation was rejected: H3 sequential instructions/cycles/
   wall time regressed 4.0%/2.6%/3.0%, each 0/5. The value boundary therefore
   remains despite its diagnostic memcpy attribution. Real H3, quic-go v1/v2,
   tquic normal/Retry/GOAWAY, Debug/ReleaseFast and package gates remain green.
   Evidence is in
   `docs/evidence/quic_traits_aggregate_direct/2026-10-30.json`.
   The next accepted send-path pass removes the best-effort exact-index hash
   write from strictly increasing sent packet numbers. Ordered history keeps
   tail and binary-search exact lookup; only unordered synthetic history
   maintains the sparse hash plus linear fallback, including duplicate checks
   for candidates above an unordered tail. Cumulative ACK validation
   additionally proves full retained-history bounds from its endpoints, and
   ordered recovery with no retransmission copies updates aggregate counters
   once per ACK. The first server 1-RTT send consequently allocates three
   times instead of four. Five CPU-0 fixed-binary 50k four-fragment pairs
   improved instructions/cycles/sequential/batch by paired medians of
   1.05%/4.73%/2.43%/1.93%; PMU won 5/5 and both wall-time paths won 4/5.
   The ordinary 5k recovery timer was too
   noisy at a roughly one-percent boundary, so the decision gate increased
   both fixed binaries to 100k identical recovery cycles. A correctness fix
   for unordered history then exposed an instruction-placement regression in
   byte-identical recovery code; the hot `applyAck` entry is now explicitly
   32-byte aligned. Final arm medians were 5218/5058 ns for
   baseline/candidate, with a 2.49% paired improvement and 3/5 wins. It is
   retained as a no-regression gate rather than a broad recovery speed claim.
   Three final-source real
   four-stream 16-MiB TLS/H3 uploads completed at 168.53-170.38 MiB/s, and
   quic-go v1/v2, 32/64-stream loss/reorder churn, tquic Retry/GOAWAY,
   Debug/ReleaseFast, and package gates remained green. This is
   same-application-shape evidence, not an equal-wire claim. Full rows and the
   rejected intermediate ACK/recovery measurements are in
   `docs/evidence/quic_sent_packet_ordered_fast_path/2026-10-30.json`.
   A post-change DWARF profile then attributed 2.06% self time to
   `Frame.wireLen`, split almost evenly between ordinary preparation and the
   stateful batch preflight. STREAM range validation already checked the end
   offset and computed the stream-ID/offset varint lengths. It now returns
   that metadata so batch wire sizing adds only the data-length varint and
   payload bytes; non-STREAM and ordinary paths are unchanged. Five CPU-0
   50k four-fragment pairs improved instructions/cycles by paired medians of
   0.72%/0.79% (5/5 and 4/5) and batch wall time by 0.38%. A one-fragment
   control improved instructions/cycles 0.18%/1.04%, both 5/5; a 50k DATAGRAM
   control was instruction/wall neutral and improved cycles 0.42%. The next
   profile reduced `Frame.wireLen` to 0.82% and retained it only below the
   unchanged ordinary prepare path. Five fixed-binary real-H3 pairs, with
   three exact 16-MiB/four-stream samples per arm, were neutral at a 0.22%
   paired improvement and 3/5 wins. Compacting the complete validated Traits
   result was rejected after instructions/cycles/sequential regressed
   0.10%/0.22%/0.78%; the existing value boundary remains. A separate
   quic-go-style one-millisecond pacing floor barely changed peer queue drops
   and reduced netz upload to 13.7-15.3 MiB/s, so it was also removed rather
   than turning a host-specific loopback limit into a production default.
   Full evidence is in
   `docs/evidence/quic_stream_range_wirelen/2026-10-30.json`.
   STREAM/DATA framing now borrows all body bytes in the common case, and both
   ordinary and batch sends encode directly into stable recovery storage
   instead of copying a second plaintext payload. Exact-size batching still
   needs a larger-rmem host to show a throughput benefit.
4. Continue broadening public HTTP/3 interop beyond the independently verified
   ByteDance, Cloudflare, and quiche deployments.

## RFC 8879 certificate compression on stream TLS clients

The blocking TLS 1.3 client used by HTTP/1, HTTP/2, gRPC, WebSocket, and MQTT
over TLS now advertises the `compress_certificate` extension by default with
brotli, zstd, and zlib in preference order (`src/tls/stream/versioned_client_connection.zig`).
The vail stack enforces the advertised-algorithm check and a 64 KiB
uncompressed-size bound before allocation; both are overridable per connection
through `certificate_compression_algorithms` (empty list disables the
extension) and `max_decompressed_certificate_len`. A raw-socket ClientHello
capture test proves the default algorithm list, the empty-list omission, a
custom order, and duplicate-algorithm rejection. TLS 1.3 stream servers
compress their Certificate on demand with the same preference list through
vail's RFC 8879 policy (brotli, zstd, zlib in the client's advertised order,
emitted only when it saves bytes), and an authenticated loopback test with a
repeated DER chain proves the client receives and verifies a compressed
Certificate end to end.

The netz QUIC client (`src/quic/tls_client_hello.zig`) also advertises RFC
8879 by default with the same brotli/zstd/zlib preference and accepts type-0x19
compressed Certificate messages: the client handshake decompresses with vail
(enforcing the advertised-algorithm and a 64 KiB bound before allocation) for
chain verification while the transcript retains the compressed message as
required by the spec. Servers with compression disabled accept the offer and
send the ordinary Certificate message. Tests cover
the extension encoding (default/custom/omitted), the 0x19 server-flight split
with transcript boundaries, decompression round trip, and unoffered-algorithm
rejection. QUIC servers now also emit compressed Certificates: the server
parses the client offer, compresses on demand with the first mutually
supported algorithm in client preference order (brotli/zstd/zlib by default),
and keeps the transcript over the compressed message so CertificateVerify
stays valid; an authenticated handshake with a six-copy DER chain proves the
client decompresses and verifies it, while a server with compression disabled
still completes the same handshake with an uncompressed Certificate. The
negotiated algorithm is exposed on the established connection.

The client now retains decompressed Certificate storage until the established
connection owns its DER copies. Parsed chain entries borrow that storage;
freeing it immediately after authentication left later identity checks reading
released memory during HTTP/3 connection coalescing. A real handshake
regression forces zlib, brotli, and zstd separately, asserts the selected
algorithm and exact retained DER, and verifies both accepted and mismatched
server identities after `connectWithTimeout` returns.
