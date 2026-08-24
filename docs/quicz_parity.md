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

The benchmark keeps UDP GSO/GRO disabled and defaults to one submitted packet
per userspace batch because this host clamps `net.core.rmem_max` to 212,992
bytes. Larger same-process loopback bursts overflow that kernel queue and
measure artificial packet-threshold recovery rather than protocol throughput;
`--batch-packets` remains available to test hosts with appropriately tuned
socket buffers. GSO/GRO performance stays covered by the dedicated QUIC batch
benchmarks.

## Feature parity table

| Area from `~/Work/quicz` examples | netz status | Evidence | Remaining work |
| --- | --- | --- | --- |
| QUIC 1-RTT STREAM echo (`quic_echo_*`, `udp_one_rtt_loopback`) | Covered and faster at p99/p99.9 while tied at p50 | `examples/quic_echo.zig`, `examples/quic_handshake_echo.zig`, `examples/bench_quic_handshake_stream.zig`, `--mode=echo`; CPU-0-pinned netz P50/P99/P99.9 ranges were 10.44-10.57 / 15.22-15.53 / 31.89-47.02 us versus quicz 10.5-10.7 / 16.0-19.5 / 206.3-211.2 us. The benchmark verifies 5,120,000 bytes and needs only 159 allocations across 5,000 rounds. The quic-go process gate also verifies client stream 2 and server stream 3 unidirectional payloads plus FIN. `zig build interop-quic-s2n -Doptimize=ReleaseFast` independently verifies two FIN-terminated bidirectional streams, ALPN, certificate/hostname authentication and peer application-close codes in both endpoint directions against s2n-quic 1.85.0. | Raw 64 MiB throughput still needs equivalent endpoint CPU placement before a general STREAM verdict. |
| QUIC TLS 1.3 handshake latency/rate (`quic_bench_hs`) | Covered with authenticated and quicz-aligned modes | `examples/bench_quic_handshake_stream.zig`, `--mode=handshake`; verified samples sustained 824.1-830.7 conn/s with P50 1172.1 us. `--skip-server-verification` retains Certificate/signing while matching quicz client policy; five CPU-0 runs measured P50 657.9-833.0 us and median 881.9 conn/s versus three quicz runs at P50 800.3-811.9 us and median 749.3 conn/s. Exact Initial sizing cut allocator calls from 167.0 to 92.0 per connection. | Equalize worker scheduling and reduce p99 variance before a whole-surface handshake claim. |
| QUIC stream-open churn (`quic_bench_hs`) | Covered and faster for the reference reservation workload; on-wire peer-stream renewal and mixed FIN/reset churn are verified | `examples/bench_quic_handshake_stream.zig`, `--mode=stream-churn`; CPU-0-pinned netz sustained 680.2-778.0M streams/s versus quicz 48.1-52.0M streams/s, a 13.1-16.2x range. IDs, limit enforcement, both endpoint roles, zero timed-loop allocation, final ID and checksum are validated. `--mode=lifecycle-churn` keeps only eight concurrent credits, repeatedly opens 4,096 real TLS/QUIC streams, alternates one-byte FIN/echo and RESET_STREAM with exact codes, and requires cumulative MAX_STREAMS before reusing each batch. Three CPU-0 runs completed at 105.9-106.7K terminal streams/s. The new production batch-release API emits one cumulative MAX_STREAMS packet for up to 64 completed streams instead of one packet each. The quic-go process gate separately advertises one bidirectional stream and requires completed streams 0, 4, 8, and 12. | Add lossy/reordered lifecycle churn and an equal quicz on-wire harness before claiming a cross-stack lifecycle throughput ratio. |
| QUIC concurrent aggregate (`quic_bench_hs`) | Covered and faster for four independent connections | `examples/bench_quic_handshake_stream.zig`, `--mode=aggregate --connections=4 --transfer-bytes=67108864`; netz completed at 730.35-900.57 MiB/s versus quicz 503.23-533.10 MB/s, a conservative 1.37-1.79x range, while verifying 4 x 64 MiB at receiver completion. | Add connection-count scaling curves and shared-event-loop comparison before generalizing beyond the four-worker shape. |
| QUIC simulated loss (`quic_bench_hs`) | Covered and faster for all four reference scenarios | `examples/bench_quic_handshake_stream.zig`, `--mode=loss`; 1%/5% loopback and 1%/5% with 100 us RTT were conservatively 1.08-1.45x faster than quicz, with deterministic injected-drop counts, full 4 MiB receiver completion, transport loss counters and optional memory telemetry. | Add bidirectional loss, reordering and corruption cases before generalizing beyond the reference one-way loss model. |
| QUIC DATAGRAM (`datagram_echo`, `quic_bench_datagram`) | Covered and faster than current quicz DATAGRAM sample | `examples/quic_datagram_echo.zig`, `examples/bench_quic_datagram.zig`, `examples/bench_webtransport_datagram.zig`, `zig build run-quic-datagram-echo`, `zig build bench-quic-datagram -Doptimize=ReleaseFast` | Keep raw and WebTransport DATAGRAM benchmarks in the comparison matrix. |
| Graceful/application close (`graceful_close`, close lifecycle) | Covered by local tests/examples and exact bidirectional quic-go process checks | `examples/quic_close.zig`, one_rtt lifecycle tests, `zig build run-quic-close`, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; netz validates quic-go's peer application close code 57/reason `quic-go interop complete`, while quic-go validates netz code 58/reason `netz interop complete` | Add long-lived graceful shutdown/draining timing only if application shutdown workloads require it. |
| Packet protection / initial keys / key update | Covered by modules, tests, and quic-go process interop | `src/quic/protection.zig`, `src/quic/zero_rtt`, `src/quic/one_rtt/tests/crypto_path.zig`, `zig build test`, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; the external gate has netz initiate two ACK-gated 1-RTT key updates, verifies both local and peer update counters reach two and both phases return to zero, while quic-go decrypts and echoes one fresh stream in each generation | Keep vector and external coverage current as TLS suites evolve. |
| Loss recovery / PTO / retransmission | Partially covered and improved, with two-peer process evidence | Recovery tests cover timer-driven losses and bounded payload caching; recovery also validates then streams arbitrary ACK range counts without a decoded-range allocation, unlike the audited quicz allocating ACK decode. Receive preflight now uses packet-local path/stream shadows instead of cloning heap-backed path-validation state per packet, cutting 16 MiB/four-stream H3 allocation calls by 16.2-16.5% in the captured A/B. The real-handshake raw STREAM gate reorders every fifth client datagram and verifies all 4 MiB; a corruption mode flips authenticated ciphertext in exactly 25/504 datagrams and recovers all data. The quic-go process gate independently drops four netz server datagrams during Initial flight and four after application STREAM data, then verifies both two-stream echoes. Separate s2n-quic connections drop netz's first post-arm RESET_STREAM or STOP_SENDING datagram and require the exact cancellation code after recovery. | Add broader reordering/corruption distributions and long-run recovery benchmarks; aggressive non-default packet/body sizing still needs separate coverage. |
| Flow control / stream reset / STOP_SENDING | Covered by implementation, tests, and two external QUIC peers, including cancellation loss | `src/quic/flow_control.zig`, `src/quic/stream.zig`, one_rtt tests, `zig build interop-quic-quic-go -Doptimize=ReleaseFast`, `zig build interop-quic-s2n -Doptimize=ReleaseFast`, and `zig build interop-http3-quic-go -Doptimize=ReleaseFast`; the raw external clients send RESET_STREAM error 41, separately observe STOP_SENDING error 42 and return RESET_STREAM error 42, and prove a concurrent stream 4 remains usable. Both external matrices transfer/echo 12 KiB through advertised 8 KiB connection and 2 KiB stream windows; the s2n-quic case also requires netz to observe actual flow-control blocking before credit advances. Two additional s2n-quic client connections use netz's stable UDP send interceptor to drop exactly the first datagram after RESET_STREAM(41) or STOP_SENDING(42), then require the peer-visible exact code and stream 4 completion after retransmission. The quic-go matrix additionally advances from stream 0 through 12 under an initial one-stream limit. The HTTP/3 gate drops the first H3_REQUEST_CANCELLED STOP_SENDING in each direction and requires retransmission, exact peer observation, and completion of a concurrent sibling under fixed flow-control windows. | Extend cancellation-loss coverage to reordered cancellation and longer mixed FIN/reset churn. |
| Connection IDs / stateless reset / path validation / migration | Covered in modules/tests with external active-migration and NAT-rebinding gates | `src/quic/connection_id.zig`, `src/quic/stateless_reset.zig`, `src/quic/path_validation.zig`, lifecycle tests, and `zig build interop-quic-quic-go -Doptimize=ReleaseFast`; every ordinary owning, borrowed/timer-aware, batch, and routed 1-RTT receive path checks active peer reset tokens only after authentication fails, enters draining for three current PTOs, and excludes matching resets from the AEAD integrity counter. The integrated client handshake registers the server's initial-CID transport-parameter token, while an unnegotiated initial CID no longer treats its zero-filled storage as a token. Netz issues three additional CIDs, and quic-go migrates one connection from `127.0.0.1` through `127.0.0.2` to `127.0.0.3` on distinct source ports. Both candidate paths reject `Path.Switch` before validation, complete PATH_CHALLENGE/PATH_RESPONSE probing, switch, and carry streams 4 and 8. A second run drops the first PATH_RESPONSE on each candidate path, then requires netz's blocking receive timer to retransmit both PATH_CHALLENGEs before the same two migrations and echoes can finish. A separate connection swaps its UDP socket to a new `127.0.0.1` source port without `AddPath`, drops four post-rebinding datagrams, recovers the stream by PTO, and proves netz selected the new tuple while keeping it validated and queuing no path challenge. | Extend the verified two-hop shape to longer path-churn runs before generalizing beyond loopback. |
| Retry/token/address validation | Covered by implementation, tests and certificate-verified quic-go and s2n-quic process gates | `src/quic/retry_flow.zig`, `src/quic/address_validation_token.zig`, handshake/retry tests, `zig build interop-quic-quic-go -Doptimize=ReleaseFast`, and `zig build interop-quic-s2n -Doptimize=ReleaseFast`; both independent servers force source-address validation, netz verifies and follows the Retry, authenticates the server, completes two streams, and validates peer application close on the retried connection | Add replay/expiry probes against an external peer before generalizing beyond a valid Retry exchange. |
| Congestion control (NewReno/CUBIC/HyStart++) | Covered and defaulted to CUBIC for 1-RTT | `src/quic/congestion.zig`, `src/quic/hystart.zig`, congestion tests; ACK processing samples utilization before removing bytes in flight, suppresses NewReno/CUBIC growth while app-limited, and excludes idle time from the CUBIC epoch. Negotiated idle timeout is clamped to RFC 9000's three-base-PTO minimum using the live RTT estimator and peer ACK delay | Keep comparing long-lived congestion traces under equal loss/RTT schedules. |
| UDP batching / GSO / GRO | Covered through timer-aware QUIC/HTTP/3 paths | Batch/GRO APIs plus `servicePacket` and synchronous `visitPacket` apply current-key datagrams in connection-owned receive storage with retained frame scratch; handshake-backed HTTP/3 and WebTransport non-GRO pumps no longer create discarded owned packet diagnostics or per-packet UDP buffers, while GRO keeps a lazy owning suffix for one-packet application routing. The captured 16 MiB/four-stream H3 step reduced allocation calls another 47.8-48.1%. | Keep H3 GRO opt-in on this small-rmem host and retest on tuned systems. |
| HTTP/3 request/response and Alt-Svc | Covered by bidirectional quic-go and tquic process interop plus public fetch against robotics.bytedance.com with discovery/manual Alt-Svc | `zig build interop-http3-quic-go -Doptimize=ReleaseFast` verifies certificate-checked POST headers, split body writes and trailers in both directions over QUIC v1 and forced RFC 9369 v2. In each direction and version the peers open the cancellation target and a sibling concurrently on one connection, negotiate fixed 8 KiB stream / 24 KiB connection receive windows, read 12 KiB from a declared 128 KiB response, deliberately drop the first H3_REQUEST_CANCELLED STOP_SENDING datagram, and require retransmission plus exact sender observation before releasing the sibling response. The sibling then completes with its body and trailers, and the quic-go client independently asserts one dial and at least two traced STOP_SENDING transmissions. Aggregate and head-only decoders expose ordered borrowed 1xx callbacks and enforce configurable limits; aggregate multiplexed reads attach the selected request-stream ID, aggregate pushed reads attach the push ID, parent request-stream ID, and push-stream ID, and servers can emit 1xx sequences on pushed responses. Incremental request and push streams enforce the same bound. This matches quic-go's bounded `Got1xxResponse` behavior while retaining a caller-configurable per-stream limit. `zig build interop-http3-tquic -Doptimize=ReleaseFast` builds audited tquic `0169abde20c6`; the verified netz-client direction exercises GET, byte Range (206), and POST-body digest, then separately sends client GOAWAY while stream 0 is active, completes that accepted response, requires tquic's exact GOAWAY(0) acknowledgement, and rejects stream 4. The reverse direction verifies two ordinary requests, then separately requires tquic to observe netz's maximum-ID and final GOAWAY(4), finish accepted stream 0, and reject creation of stream 4. Every tquic scenario runs with and without forced Retry. `examples/http3_fetch.zig`, `run-http3-fetch --discover --verify --head`, `run-http3-fetch --alt-svc='h3=":443"; ma=2592000' --verify --head` cover a public endpoint | Keep live public-server coverage and broaden feature cases against the second implementation. |
| HTTP/3 real-handshake upload benchmark | Covered and reliable at the tested default | `examples/bench_http3_handshake_transfer.zig`; CPU-0-pinned 4-stream 64 MiB upload completed 5/5 iterations at 141.78 MiB/s mean and 2.76% stddev with ACK threshold 4 and adaptive DATA sizing; exact-size cross-stream body batching is also available but opt-in on this small-rmem host | Build an equal-wire quicz H3 reference before making a cross-stack ratio; then reduce netz per-packet recovery/framing cost. |
| HTTP/3 real-handshake download and RFC 9218 response scheduling | Covered for current benchmark scale; feature coverage exceeds the local quicz H3 layer | `HandshakeServerSession.sendResponseBodiesPaced` schedules borrowed complete bodies by the request Priority field and live PRIORITY_UPDATE, serializes non-incremental peers, round-robins incremental peers, bypasses flow-blocked urgent streams, and replans after socket-visible packet prefixes; real-handshake tests cover all four behaviors and the benchmark sends `Priority: u=3, i`. `~/Work/quicz/src/h3` has no Priority field, PRIORITY_UPDATE, urgency, or incremental scheduler. The runtime now supports byte- or packet-cadence cooperative yielding; using a chunk-size-independent three-packet cadence raised five 64MiB/four-stream iterations from 11.35 MiB/s to a stable 44.15 MiB/s mean (3.47% stddev) while retaining full completion. | Continue apples-to-apples quicz throughput work before making a whole-stack performance claim; move same-process loopback pacing policy into a reusable event-loop benchmark harness. |
| QPACK / Capsule / WebTransport | Covered by modules, benchmarks, real-handshake streams, lifecycle controls, and native wtransport interop | QPACK dynamic entries use indexed lookup, FIFO head eviction and one contiguous string allocation versus quicz reverse scans, front insertion and two string allocations. Field-section prefixes use RFC 9204 prefix integers rather than QUIC varints; boundary tests cross encoded Required Insert Count 63 and Delta Base 127, while `interop-http3-qpack-quic-zig` independently decodes a speculative section after 64 inserts. Dynamic sections choose Required Insert Count as their minimal Base, and the dependency prepass excludes dynamic name matches shadowed by the selected static representation, preventing phantom blocking and Section Acknowledgments. The decoder independently derives the highest actual dynamic reference across all four relative/post-Base field forms and rejects both under-reported mandatory dependencies and non-minimal over-reported counts. Request, response and trailer paths decode both literal and dynamic QPACK sections directly into one shared field-section string block, rather than first allocating per Huffman/dynamic field and copying again. Offset plans remain valid across scratch growth, all four relative/post-Base representation families retain exact dependency validation, and allocation-failure tests cover both owning decoders. Pinned 32-field dynamic decode samples measured 816-905 ns/block. Settings-aware decoders enforce the uncompressed `name + value + 32` field-section budget before Huffman output allocation or dynamic-entry copying, including static, literal and all dynamic representations. WebTransport adds transactional cross-stream batches and modern 0x41 association. Its external wtransport gate now drops a mapped STOP_SENDING while a sibling stream is live and requires transport recovery plus sibling completion. | Add browser interop; native wtransport does not stand in for browser behavior. |
| TLS backend/process interop examples | Covered in both directions through standalone, certificate-verified quic-go and s2n-quic process gates | QUIC handshake tests, `examples/quic_handshake_echo.zig`, `zig build interop-quic-quic-go -Doptimize=ReleaseFast` (bidirectional/unidirectional streams, RESET_STREAM, STOP_SENDING, rolling limits, and Initial/application PTO recovery), `zig build interop-quic-s2n -Doptimize=ReleaseFast` (independent s2n-tls stack, ALPN, two streams with FIN, exact RESET_STREAM/STOP_SENDING exchanges and cancellation retransmission with a concurrent sibling, application close), HTTP/3 public fetch with `--verify` | Add broader public peers before making a full interoperability claim. |

## Known blockers before declaring the goal complete

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
   `--verify`. A separate local process gate builds quic-go v0.59.0 from the
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
   Broader public peer coverage is still not audited; recent
   Cloudflare/Google/Facebook probes failed or timed out and are intentionally
   not counted as coverage.
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
   derivations are used after the handshake; a two-endpoint v2 regression
   decrypts the first updated-key stream and checks the peer transition. The
   audited quic-go v0.59.0 updater still derives `quic ku` unconditionally, so
   that version-specific update is not misrepresented as external interop.
   The same gate
   repeats that exchange against a quic-go `Transport` whose
   `VerifySourceAddress` callback always requires Retry. Netz exposes and
   asserts the authenticated Retry transition, then still completes both
   streams and validates application close code 57 on that connection. This is
   direct external coverage for Retry integrity, token replay into the second
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
   STREAM comparisons need equivalent endpoint CPU placement, and HTTP/3 still
   lacks an equal-wire quicz reference. DATAGRAM, loss simulation, four-
   connection aggregate throughput, and stream reservation have direct faster
   artifacts. Mixed FIN/reset lifecycle churn now has a bounded-credit on-wire
   netz baseline, but no equal quicz harness yet. Echo latency now has a
   controlled artifact that is tied/faster across percentiles. Handshake
   latency/rate now has a verification-policy-aligned artifact, but the two
   workloads still need equal worker scheduling and lower tail variance before
   the whole quicz benchmark surface can be considered surpassed.

## Next recommended work

1. Rebuild the raw QUIC comparison with equivalent endpoint CPU placement,
   then add lossy/reordered on-wire lifecycle churn and connection-count
   scaling cases. The handshake artifact includes allocation telemetry;
   equalize certificate verification and endpoint scheduling before comparing
   its rate. The old unpinned ratio is no longer accepted as proof.
2. Re-run HTTP/3 GRO on a host with larger kernel UDP receive buffers; the
   timer/recovery path is now safe, but this host's throughput regresses.
3. Reduce HTTP/3 per-packet recovery ownership and STREAM/DATA framing cost;
   exact-size multi-stream batching now exists but needs a larger-rmem host to
   show a throughput benefit.
4. Broaden public HTTP/3 interop beyond `robotics.bytedance.com`.
