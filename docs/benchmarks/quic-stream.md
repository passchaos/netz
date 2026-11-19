# QUIC real-handshake STREAM comparison

[Back to the benchmark index](../benchmark-baseline.md).

## Raw QUIC real-handshake STREAM comparison

Captured on 2026-08-17 with a fresh TLS 1.3/QUIC handshake per iteration:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --iterations=3 --transfer-bytes=67108864 --streams=1 --verbose
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --iterations=3 --transfer-bytes=67108864 --streams=4 --verbose
```

```text
netz single stream:
  samples: 298.21, 318.45, 318.43 MiB/s
  mean: 311.69 MiB/s, stddev: 3.06%
  payload bytes received: 201326592

netz four streams:
  samples: 317.32, 313.78, 312.95 MiB/s
  mean: 314.68 MiB/s, stddev: 0.60%
  payload bytes received: 201326592
```

The historical same-host quicz run recorded above produced 228.77 MB/s
single-stream and 244.85 MB/s four-stream means. Those values were not
CPU-pinned. A new `taskset -c 0 /tmp/quicz-bench-hs` run produced 15.97 MB/s
and 16.12 MB/s because both same-process endpoints contend for one CPU; a
matching pinned netz probe was similarly scheduling-bound. The prior 1.36x and
1.29x ratios are therefore withdrawn. Future raw QUIC claims require an
equivalent endpoint CPU layout, not merely a shared host and transfer size.

The new `bench-quic-quic-go` process harness supplies that equivalent two-CPU
layout against quic-go v0.59.0 from the repository-owned, checksum-locked Go
module. It runs both client/server sender roles with a
fresh certificate-verified QUIC v1 connection per sample. An untimed fixed
control stream exchanges CONFIG/READY before 1 or 4 unidirectional data streams
transfer deterministic payloads; t1 occurs only after the receiver verifies
every byte and FIN and returns DONE with the exact aggregate checksum. The
sender returns DONE_ACK before the receiver closes the connection. Both
processes disable GSO and do not enable UDP_GRO; both use fixed 1 MiB stream and 8 MiB
connection windows, and the measured 1-RTT MTU is 1280 bytes.

```sh
zig build bench-quic-quic-go -Doptimize=ReleaseFast -- \
  --warmup=2 --iterations=5 --bytes-per-stream=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --timeout-ms=30000
```

The current harness runs every netz endpoint on zio and exposes only `std.Io`
to the QUIC implementation. Config, sender result, receiver completion, socket
traffic, and optional memory records carry `client_io` and `server_io`; the
strict checkers reject missing or role-inconsistent backend identities and
independently recompute each measured-round checksum. `--netz-only` provides a
two-process zio control without invoking quic-go. A
2026-09-15 ReleaseFast smoke with one fresh connection per direction and a
256-KiB payload verified checksum 33,423,360, exact bidirectional socket
accounting, and completion exchange at 56.446 MiB/s client-send and 65.788
MiB/s server-send. These are single-sample runtime checks, not comparative
performance evidence.
The final schema was also exercised against quic-go v0.59.0 for both role pairs
and both sender directions, with and without memory telemetry; every 64-KiB
sample verified checksum 8,355,840, completion exchange, paired socket traffic,
and runtime identity. A reduced 32-stream matrix additionally passed loss and
reordering in both directions and role pairs after the shared churn commands
moved to zio. These are migration gates rather than performance samples.

The cross-library measurements below were captured before this zio migration
and remain historical `std.Io.Threaded` baselines. They must not be cited as
zio performance; a new fixed-binary, CPU-pinned, order-interleaved quic-go run
is required for a current ratio.

CPU-0/client and CPU-1/server samples on 2026-09-08 measured:

| Streams | Sender | Role pair | Throughput |
|---:|---|---|---:|
| 1 | netz | netz client + quic-go server | 227.48-228.77 MiB/s |
| 1 | netz | quic-go client + netz server | 172.74-185.68 MiB/s |
| 1 | quic-go | quic-go client + netz server | 43.78-72.31 MiB/s |
| 1 | quic-go | netz client + quic-go server | 59.01-126.12 MiB/s |
| 4 | netz | netz client + quic-go server | 210.53-216.66 MiB/s |
| 4 | netz | quic-go client + netz server | 145.62-147.99 MiB/s |
| 4 | quic-go | quic-go client + netz server | 116.83-121.03 MiB/s |
| 4 | quic-go | netz client + quic-go server | 115.01-122.68 MiB/s |

Each 1-stream sample verified 4,194,304 bytes and checksum 534,773,760; each
4-stream sample verified 16,777,216 bytes and checksum 2,139,095,040. The wide
single-stream quic-go ranges and netz's role sensitivity are retained instead
of compressed into a ratio. This is `same-application-shape`, not equal-wire:
both processes disable GSO and do not enable UDP_GRO, but quic-go advertises a
different maximum UDP payload, uses per-stream goroutines while netz
round-robins one event loop, and retains implementation-specific
ACK/pacing/packetization. Capture-level UDP byte and
datagram accounting at the kernel/interface boundary is still required before
a general raw STREAM superiority claim.

The harness now also records complete-connection UDP payload bytes and logical
datagram counts at both processes' userspace socket boundaries. The counters
start before handshake and end after the benchmark close exchange, so they
include Initial, Handshake, 1-RTT data, ACK/control, and teardown traffic. GSO
is disabled for both stacks; netz disables GRO, while the audited quic-go
v0.59 receive path uses `recvmmsg` batching and does not enable Linux UDP_GRO.
Every counted logical segment is therefore one socket-visible UDP payload. The
runner joins client and server records by role pair/sample, rejects
missing/duplicate records and impossible negative
send-versus-peer-receive deltas, and preserves positive deltas when one endpoint
stops receiving after connection close. Telemetry is printed out-of-band rather
than sent over the measured QUIC connection.

Three CPU-0/client + CPU-1/server samples used `--warmup=1 --iterations=3`
with the same 4 MiB-per-stream shape and measured these complete-connection
ranges:

| Streams | Sender implementation | Total UDP datagrams | Total UDP payload bytes | Payload overhead |
|---:|---|---:|---:|---:|
| 1 | netz | 3,950-4,195 | 4,323,315-4,334,573 | 3.08-3.34% |
| 1 | quic-go | 7,318-7,328 | 4,448,566-4,454,107 | 6.06-6.19% |
| 4 | netz | 15,687-20,057 | 17,275,226-17,497,963 | 2.97-4.30% |
| 4 | quic-go | 29,661-30,103 | 18,357,564-18,895,334 | 9.42-12.62% |

The ranges combine both client/server role pairings for each sender
implementation rather than attributing peer ACK cost to only one process. All
24 measured connections retained exact application bytes, checksum, FIN, and
two endpoint telemetry records. Most one-stream directions had exact
send/peer-receive equality. Positive teardown/read-stop deltas remained visible
(one 29-byte quic-go close response in the stable one-stream case and larger
ACK tails in some four-stream cases) instead of being silently subtracted.

These socket-boundary numbers demonstrate that the workloads are **not
equal-wire**: quic-go's sender shapes use materially more ACK/control traffic
and roughly twice as many UDP datagrams in these samples. They strengthen the
fairness audit but do not replace a kernel packet capture, since this host
denies unprivileged `tcpdump`, passwordless elevation, and user/network
namespaces. Future promotion still requires capture-backed IP/UDP accounting
plus equalized GRO, ACK/pacing, packetization, and application scheduling.

### Raw QUIC persistent echo and multi-connection aggregate versus quic-go

`bench-quic-persistent-external` fills the persistent echo and process-level
multi-connection gaps in the raw QUIC matrix. It uses the repository-owned,
checksum-locked quic-go v0.59.0 module and pins client/server processes to
separate CPUs, disables GSO on both peers, does not enable GRO, and performs a
certificate-verified QUIC v1 handshake before timing. The runner exercises all
four netz/quic-go client/server combinations in alternating order. Each result
is accepted only after the peer has consumed and validated exact payload bytes,
FIN, and checksum and the DONE/DONE_ACK exchange completes; a separate server
record must independently agree.

The netz side of the current harness uses zio as its execution backend and
passes only `std.Io` into QUIC. Every result and server-completion record names
both endpoint runtimes (`zio-std-io` or `quic-go-netpoll`), and the strict
checker and summary reject missing or mismatched runtime identities. The
historical measurements below predate that migration and were collected with
the former `std.Io.Threaded` harness; they remain historical baselines, not zio
performance evidence. New zio performance claims require a fresh fixed-binary,
CPU-pinned, order-interleaved run.

A 2026-09-15 ReleaseFast migration smoke used four connections, one 256-KiB
stream per connection, and both sender roles. The shared-server topology
verified 1,048,576 bytes and checksum 133,693,440 at 63.686 MiB/s upload and
78.468 MiB/s download; the independent topology verified the same payload at
81.419 and 77.144 MiB/s. A separate 2-warmup/20-measurement persistent echo
run verified all 22,528 bytes and checksum 2,872,320. Every record identified
both endpoints as `zio-std-io`. These single-sample results establish runtime
and verifier coverage only; they are not comparative performance evidence.

A 2026-11-19 zio-era single-sample smoke at the current head used the shared
server topology, four connections, and one 1-MiB stream per connection. It
measured 162.732 MiB/s for the netz client sender and 62.131 MiB/s for the
netz server sender. Both result and server-completion records identified
`zio-std-io`, verified 4,194,304 bytes with checksum 534,773,760, and reported
four completed connections. The server-sender record shows the shared endpoint
receiving 3,692 datagrams through 2,034 receive calls while sending 948
datagrams. This refreshes the zio runtime-path evidence; the fixed-binary
quic-go server-role matrix is recorded below.

```sh
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --mode=echo --samples=5 --warmup=200 --iterations=5000 \
  --payload-bytes=1024 --timeout-ms=30000
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --mode=aggregate --samples=5 --connections=4 --streams=1 \
  --bytes-per-stream=1048576 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=60000
```

The 2026-09-10 echo run produced these medians of each run's P50, with 5,000
measured 1-KiB round trips after 200 warmups:

| Fixed server | netz client | quic-go client | netz latency advantage |
|---|---:|---:|---:|
| quic-go | 24.172 us | 25.851 us | 1.069x |
| netz | 23.729 us | 24.361 us | 1.027x |

Against the fixed quic-go server, median P99/P99.9 values were 29.346/37.456
us for netz and 33.599/41.540 us for quic-go. Against the fixed netz server,
they were 27.273/36.060 us for netz and 30.586/43.463 us for quic-go. Every run verified
5,324,800 echoed bytes including warmup and checksum 678,912,000.

The aggregate run used four simultaneous independent endpoint/connection
workers in each process and one 1-MiB unidirectional stream per connection. A
GO record was sent only after all four TLS/QUIC handshakes and control streams
were ready. The timed interval includes per-connection payload/buffer
construction, stream prelude/setup, all payload and FIN transmission,
byte/checksum validation, and DONE/DONE_ACK completion. It is therefore a
complete application-transfer cost rather than an isolated steady-state send
loop. Five runs produced:

| Fixed endpoint | Sender implementation | Median MiB/s | Range MiB/s | Netz / quic-go |
|---|---|---:|---:|---:|
| quic-go server | client: netz / quic-go | 152.580 / 111.179 | 140.160-162.861 / 110.880-111.999 | 1.372x |
| netz server | client: netz / quic-go | 73.333 / 101.045 | 55.856-123.198 / 100.273-101.974 | 0.726x |
| netz client | server: netz / quic-go | 66.736 / 100.897 | 51.345-109.791 / 98.920-101.474 | 0.661x |
| quic-go client | server: netz / quic-go | 149.825 / 112.307 | 136.079-160.929 / 110.288-112.968 | 1.334x |

All 40 aggregate result records and 40 independent server completion records
verified 4,194,304 bytes and checksum 534,773,760. The mixed-role results show
that a netz sender is faster in both mixed-role comparisons, while the netz/netz control
is materially slower and more variable when eight endpoint workers share the
two pinned process CPUs. This is useful evidence of both the sender fast path
and a remaining same-process scheduling bottleneck, not a universal superiority
claim. This original topology uses one UDP socket per connection; the following
shared-server extension isolates the alternative production ownership model.

A 2026-11-19 zio-era fixed-binary matrix reran the same 4 x 1-MiB aggregate
shape against the pinned quic-go v0.59.0 fixture with Go 1.24.7, three samples
per role pairing, CPU-pinned client/server processes, GSO/GRO disabled, and
exact byte/checksum validation. Medians:

| Fixed endpoint | Sender implementation | Median MiB/s (netz / quic-go) | Netz / quic-go |
| --- | --- | ---: | ---: |
| quic-go server | client | 166.242 / 110.262 | 1.508x |
| netz server | client | 134.644 / 106.832 | 1.260x |
| netz client | server | 136.381 / 107.384 | 1.270x |
| quic-go client | server | 170.343 / 109.769 | 1.552x |

Every record identified the netz side as `zio-std-io` and the quic-go side as
`quic-go-netpoll`, verified 4,194,304 bytes and checksum 534,773,760, and
reported four completed connections. The historical server-sender deficits
(0.726x with a fixed netz client and 0.661x with a fixed quic-go client) are
reversed to 1.270x and 1.552x in this zio-era configuration. This is still a
same-application-shape comparison, not an equal-wire or universal claim. Rows
and the command are in
`docs/evidence/quic_persistent_external/2026-11-19-zio-server-role.json`.

Raw QUIC now also exposes `quic.endpoint_server.Server`, a protocol-neutral
single-owner loop for bounded concurrent TLS handshakes, CID routing, aggregate
timers, socket-free stream polling/sending, and explicit post-application ACK
policy. It follows the same bounded endpoint-work design as the audited Quinn
driver, which caps receive/event work before yielding. The dispatcher now also
drains ACK-driven packet-threshold retransmissions before returning a routed
packet, matching netz's blocking and visitor receive paths instead of delaying
repair until PTO. A direct two-client real-handshake test verifies distinct
handles and echo payloads over one UDP socket; a focused dispatcher regression
drops packet numbers 0-3, delivers an ACK for packet 4, and observes immediate
retransmissions 5 and 6.

The persistent aggregate harness accepts this production topology with:

```sh
zig build bench-quic-persistent-external -Doptimize=ReleaseFast -- \
  --mode=aggregate --samples=3 --connections=4 --streams=1 \
  --bytes-per-stream=1048576 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=60000 \
  --server-topology=shared
```

The runner labels it `endpoint_topology=shared-server-udp`, rejects incompatible
mode/role combinations, and keeps its result set separate from independent-UDP
summaries. Five verified 4 x 1-MiB client-upload samples measured
56.554-64.812 MiB/s (59.627 median), with exact 4,194,304-byte and
534,773,760 checksum agreement on both sides. Seven manual order-alternated
same-binary pairs measured 57.026-69.958 MiB/s (62.757 median) for the shared
server versus 80.979-93.000 MiB/s (87.565 median) for four server sockets, or
0.717x. This closes the missing executable shared-socket shape but deliberately
records its remaining allocation/scheduling deficit rather than presenting it
as a speedup. The audited quic-go fixture and Go toolchain were unavailable for
this capture, so no new cross-library ratio is claimed. Separate verified
smokes covered four connections with four 256-KiB streams each (4 MiB total)
and eight connections with one 256-KiB stream each (2 MiB total), including
exact FIN, byte, checksum, and DONE/DONE_ACK validation.

The shared endpoint now also exposes caller-buffer `receiveVisiting*` APIs. For
an established non-GRO connection on the current key phase, the dispatcher
routes and decrypts in place, applies transport frames through retained frame
scratch, and exposes borrowed packet/frame views only for the duration of the
callback. Unknown-CID and handshake traffic keeps the owning path, and key
updates keep the safe allocating fallback because an in-place failed-key trial
cannot preserve ciphertext for another generation. The endpoint server adapter
applies negotiated ACK policy after a successful callback. A failing-allocator
real-UDP test covers warmed established packets, including a rotated one-byte
CID; separate tests cover callback error propagation and the key-update
fallback.

`HandshakeServerSession.processRequestPacketView` exposes the matching HTTP/3
boundary: custom shared loops can apply an authenticated borrowed packet during
the dispatcher callback without constructing an owning `ReceivedPacket`. The
existing owning method delegates to this path, and a regression releases the
source packet immediately after the call before polling the retained request.
The built-in HTTP/3 `EndpointServer.receiveManyOnce` now connects that path to
the bounded caller-buffer dispatcher. Borrowed packets are fully applied inside
the call; only stable request, connection, close, failure, and owned-unrouted
events escape. One real UDP regression routes two complete requests in one
batch, overwrites the caller buffer, and then validates both retained request
heads; another admits and promotes two concurrent real TLS handshakes through
the same API. The existing single-event receive APIs remain unchanged for
compatibility.
The shared authenticated client pool now exposes the symmetric bounded
`receiveManyOnce` path. `HandshakeClient.processResponsePacketView` lets its
dispatcher apply established response packets before caller receive storage is
reused, while response and push stream state retains the data needed by later
poll/read calls. The owning packet API remains source-compatible. A real
two-origin TLS regression queues both responses, observes more than one event
in a batch, overwrites the receive
buffer, and then validates both response statuses and bodies. Empty and
oversized event slices, non-positive poll intervals, and idle timeout are
covered separately. This is a functionality and ownership result; no
throughput ratio is claimed.

A same-host, same-command three-sample A/B against commit `17109fda` measured
the caller-buffer shared server at 64.455-79.452 MiB/s (69.691 median) versus
the owning baseline at 51.322-64.565 MiB/s (64.454 median), an 8.1% median
increase. Every arm independently verified 4,194,304 bytes, checksum
534,773,760, four completed connections, and the completion exchange. The
ranges overlap and only three samples were collected, so this is a regression
sample supporting the allocation-path change, not a general throughput claim.

The persistent shared topology now covers both sender roles. Server-originated
transfers use the same single socket owner and explicitly resumable state
machine as uploads: unidirectional stream reservation and every prelude, data,
FIN, and completion-control send are nonblocking, while routed packet and
timer events resume connections held by pacing, congestion, or flow control.
The endpoint server exposes the dispatcher's socket-free unidirectional stream
poll so applications do not introduce a competing UDP receiver. Five verified
16-connection, 16-MiB runs transferred 80 MiB in each direction. Client-sender
samples measured 62.790-79.786 MiB/s (71.458 median), while server-sender
samples measured 80.013-96.256 MiB/s (84.688 median). The server-sender runs
handled 2,783-3,402 timer events and sent 14,755-14,842 datagrams, providing
direct coverage of backpressure recovery across all connections. The ranges
overlap, so these measurements establish bidirectional completion and scaling
coverage rather than a directional throughput advantage. A separate four-
connection/four-stream smoke verified 4 MiB, every FIN, checksum, and the
DONE/DONE_ACK exchange in both directions.

The fixed runner now accepts a strictly increasing
`--connection-counts=1,4,...` matrix in netz-only aggregate mode. It executes
both sender directions at every count, filters mixed result logs back to one
shape before computing medians, and emits aggregate-throughput retention,
work-normalized elapsed ratio, and per-connection throughput relative to the
first count. It deliberately does not call linear aggregate throughput an
ideal on a fixed two-CPU layout.

A final CPU-10/11 three-sample shared-server run used 1, 4, 16, and 64
connections, one 1-MiB stream per connection, one server UDP socket, receive
batch 32, and ACK-every 4 with a 25-ms maximum delay. All 24 arms passed
certificate, FIN, byte, checksum, socket/datagram/event-counter, and
DONE/DONE_ACK validation. At 64 connections each direction transferred exactly
67,108,864 bytes with checksum 8,556,380,160. Client-sender median aggregate
throughput was 172.367, 180.558, 161.761, and 141.339 MiB/s, retaining 1.000x,
1.048x, 0.938x, and 0.820x of the one-connection result. Server-sender medians
were 167.458, 158.532, 154.646, and 145.678 MiB/s, retaining 1.000x, 0.947x,
0.923x, and 0.870x. The matrix closes the missing shared-socket
connection-count evidence through 64 concurrent connections; it remains a
same-application-shape two-process result rather than an equal-wire or
multi-core scaling claim.

Those final results use an exact periodic payload verifier rather than charging
the transport for scalar benchmark bookkeeping. The affine payload repeats
every 256 bytes; a compile-time table supplies exact block comparison, sender
fill, and checksum prefix sums. Tests compare its output against bytewise
generation at cycle edges, arbitrary offsets and all configured stream/round
biases, verify a 1-MiB payload in Debug/ReleaseFast, and flip an interior byte
to prove corruption still fails. An initial exponential fill exposed Zig
0.16's range-narrowing of `@min(len, 256)` to `u9`; explicit `usize` progress
and read-only 256-byte copies replaced it before the candidate benchmark.

Ten CPU-10/11 fixed-binary, order-alternated 64 x 1-MiB pairs compared baseline
`ead8e956819208cb7eaa8069b9199e775fa010fa1771ff60fbe97bdb76cc2bed`
with candidate
`0e4ed798c8896590d664bcdbbd4dccb4a4d52f87d99ff6ea5614d0bb973e19d9`.
Client-sender throughput rose from a 107.810 to 142.045 MiB/s median (1.327x,
10/10 wins); server-sender rose from 133.941 to 149.130 MiB/s (1.121x, 10/10).
One-GiB server profiles removed the former 19.80% scalar `verifyPayload`
hotspot to 0.70% and removed the former 17.60% `PayloadSet.init` hotspot.
Approximate upload/server-sender cycle event counts fell from 8,357,470,339 to
7,026,378,417 (-15.93%) and 11,453,765,401 to 9,527,935,031 (-16.82%). The
application bytes, wire protocol, checksum and completion contract are
unchanged; this is a benchmark-fidelity improvement that exposes the actual
crypto, clock, recovery and routing costs more clearly.

The same runner can launch a selected netz endpoint under `perf record` with
`--profile-role=client|server --profile-dir=PATH`; filenames include topology,
connection count, sender and run so a matrix cannot silently overwrite another
profile. The strict aggregate checksum remains independently recomputed, but
the checker now uses the payload generator's exact arithmetic: multiplier 131
is odd, so every 256-offset cycle visits all byte values once. Complete cycles
therefore contribute 32,640 and only the at-most-255-byte tail is iterated. A
bytewise oracle covers 0/1/255/256/257 and 1,023/1,024/1,025 boundaries across
one/four streams and connection biases through 255. A real 64-connection,
64-MiB-per-connection run then verified both 4-GiB directions and checksum
547,608,330,240 without the former minutes-long Python pass.

That profile support was used to evaluate sharing one monotonic receive
timestamp across every datagram returned by one dispatcher batch. Baseline and
candidate binaries were
`ead8e956819208cb7eaa8069b9199e775fa010fa1771ff60fbe97bdb76cc2bed` and
`82fd7ca2154890b303f301741af91848678188dd7c12ac0dcc7bdf5ef9eeef4d`.
On a 64-connection 1-GiB upload profile, `clock_gettime` fell from 13.47% to
11.30% and approximate cycles from 8,357,470,339 to 8,259,002,794 (-1.18%),
but throughput moved from 89.655 to 89.217 MiB/s. Ten fixed-binary,
order-alternated 64 x 1-MiB pairs likewise gave a 0.996272 upload median ratio
with only 4/10 candidate wins; the reverse direction measured 1.008218 with
8/10. The transport candidate was fully removed because it did not improve its
target upload shape. The profiler and constant-time verifier remain as durable
evidence infrastructure.

After the periodic exact payload helper removed the former 19.80% verifier
tax, the same dispatcher timestamp idea was rebuilt and evaluated again rather
than assuming the old result still applied. Current baseline
`0e4ed798c8896590d664bcdbbd4dccb4a4d52f87d99ff6ea5614d0bb973e19d9`
and candidate
`ef38e20353b4789865dc4a0b139764fa7c78bb98954e7c997445e009b72b6ba5`
ran twenty CPU-10/11, order-alternated 64 x 1-MiB pairs. The target
client-sender median ratio was 0.998541 with only 8/20 candidate wins;
server-sender was 1.009257 with 12/20. A three-datagram clock-count regression
proved the intended five-to-three read reduction, but the cleaner end-to-end
upload evidence remained neutral. The production candidate and its private
timestamp plumbing were therefore removed again; this rules out retrying that
isolated optimization without a materially different clock/timer design.

A materially different send-side clock candidate was also rejected for
correctness rather than timing. `endpoint_server.Server.trySend` temporarily
used zio's already refreshed event-loop awake snapshot, with the existing
exact-clock fallback for foreign runtimes and calls outside the matching task.
This resembles Quinn's caller-supplied `poll_transmit(now)` boundary and left
ordinary Connection send/receive, RTT, PTO, and deadline APIs unchanged. The
64-connection client-sender arm completed 67,108,864 bytes with checksum
8,556,380,160 at 140.244 MiB/s, but the first server-sender arm failed its
30-second deadline before producing a result. A continuously runnable shared
server can revisit pacing without yielding through a backend poll, so its scan
snapshot need not advance soon enough to release the pacing block. Baseline and
candidate SHA-256 values were
`0e4ed798c8896590d664bcdbbd4dccb4a4d52f87d99ff6ea5614d0bb973e19d9`
and
`16412e977e0a0e6bc1d78beb8fedc3c697b6049a94c0f011059bb74f2a9c5df0`.
The candidate was fully removed after that first terminal failure. QUIC send
timestamps and pacing retain fresh awake-clock reads; a future shared-time
design must define and test explicit refresh/yield ownership rather than reuse
an event-loop snapshot implicitly.

The exposed server-sender profile then motivated a staged ACK-summary
experiment. A single-ACK packet already validates every range and ECN count
before mutation, but the ordinary path subsequently rescanned the same sent
metadata for plain-ACK ECN policy and RTT eligibility. A new
`bench-quic-ack-ranges` arm models the exact four-packet cumulative cycle:
prevalidate, plain-ACK preflight, RTT sample, and validated apply. With
identical benchmark source, seven CPU-0 fixed-binary, order-alternated pairs
reduced that cycle from a 363 to 247 ns median (0.680x, 7/7 wins). Baseline and
candidate SHA-256 values were
`2e84f1471a352e40dbe48e6ae8576b861ecee02a08fba6bc769882426423a336`
and
`a47aa97d0795357c06487209972e11828837d97a7fa768fdd4648743130021c0`.

That isolated result was not sufficient to retain the transport change. The
first token expansion copied the validation summary through the receive path;
a matched server-sender profile put 2.69% of samples in `memcpy` below
`applyReceivedFramesForDestination`, versus 0.30% in the baseline. Seven
64-connection, 64 x 1-MiB fixed-binary pairs then produced a 0.981
candidate/baseline server-sender median with only 1/7 wins, so that form was
rejected. A materially narrower retry kept one stack token, passed it by
pointer, and removed the low-value cached mark window. Its persistent baseline
and candidate SHA-256 values were
`0e4ed798c8896590d664bcdbbd4dccb4a4d52f87d99ff6ea5614d0bb973e19d9`
and
`98273d96d1c2a659c63d4ce1cb251dd9a043fe052db27924d40afe8774e4a759`.
Across seven CPU-0/1 AB/BA pairs, client-sender throughput had a 1.009 paired
median with 5/7 wins, but the target server-sender shape was neutral at 1.001
with 4/7 wins. Every arm still verified 67,108,864 bytes, checksum
8,556,380,160, all 64 connections, and the completion exchange. The complete
production candidate was removed: eliminating duplicate metadata scans is not
retained when its target end-to-end workload remains neutral. The
microbenchmark arm remains to make a future smaller representation or fused
recovery design measurable without weakening validation, RTT, loss, ECN, or
mutation ordering.

A same-connection transmit-batch candidate was also evaluated and removed. It
staged up to four resumable STREAM packets per socket submission using the
existing exact protected/socket-visible prefix result. Five order-alternated
16-connection, 16-MiB server-sender pairs measured 86.307, 105.154, 95.560,
95.648, and 88.004 MiB/s for the retained one-packet path (95.560 median),
versus 81.025, 69.699, 99.228, 93.564, and 70.437 MiB/s for batches of four
(81.025 median). Only one of five pairs favored batching, and its median was
15.2% lower; a batch size of 32 also produced an intermittent tail timeout at
16 connections. The current Threaded backend already uses `sendmmsg`, while
QUIC pacing limits useful per-connection bursts, so the additional protection
and staging work is not retained.

A narrower dispatcher candidate reused the already-resolved connection-table
entry when checking whether authenticated packet processing changed local CID
routes, instead of looking the same handle up again. Five fixed-binary,
order-interleaved 16-connection, 16-MiB-total pairs against parent 857f6329
did not support retaining it. Client-sender throughput was 54.146-60.556 MiB/s
(57.195 median) before and 53.267-67.029 MiB/s (54.890 median) after, with 2/5
candidate wins. Server-sender throughput was 84.686-112.349 MiB/s (93.718
median) before and 69.022-113.377 MiB/s (85.711 median) after, with 1/5
candidate wins. The ranges overlap, but both medians moved lower and the pair
outcomes were unfavorable. Every arm verified 16,777,216 bytes, checksum
2,139,095,040, all sixteen connections, and the completion exchange. The
candidate was fully removed; this evidence rules out another locally cheaper
hash lookup as an end-to-end shared-owner improvement on its own.

A follow-up attempted to remove the shared upload application copy by visiting
the contiguous bytes already retained in each QUIC receive stream. The first
callback-scoped version committed flow-control credit through the existing
nonblocking retry path. Five fixed-binary, order-interleaved 16-connection,
16-MiB-total upload pairs measured 53.732-62.595 MiB/s (59.810 median) for
the retained copying path and 46.512-62.856 MiB/s (51.846 median) for the
borrowed path. The candidate won 2/5 pairs and its median was 13.3% lower.
Every arm verified 16,777,216 bytes, checksum 2,139,095,040, all sixteen
connections, and the completion exchange. One exploratory candidate smoke
also received 27,166 datagrams versus the previously recorded 14,758 for this
shape, but later packet counts varied; that observation is retained only as a
warning that receive-credit timing can change wire work, not as a causal ratio.

A narrower correction used exactly the old transactional
releaseReceivedCapacity path after the borrowed callback, preserving the
ordinary MAX_DATA/MAX_STREAM_DATA send timing. Four-connection smoke then
matched the retained path at 1,112 received upload datagrams. Two fixed-binary
16-connection ABBA pairs nevertheless favored the retained upload path both
times: parent measured 46.340/66.429 MiB/s and candidate measured
42.949/54.673 MiB/s. The untouched server-sender control split 1/2, confirming
substantial host variance but providing no evidence for an upload gain. Both
borrowed APIs, their tests, and the benchmark integration were fully removed;
the transport retains its existing explicit availableReceivedStream plus
releaseReceivedCapacity primitives for callers whose ownership model already
makes that tradeoff worthwhile.

The next shared-loop step follows Quinn's bounded receive-cycle design: one
bounded receive operation drains already-ready UDP messages nonblocking, or
waits for one when the socket starts empty, into a reusable caller buffer. The
portable Zig Threaded backend still invokes
`recvmsg` once per datagram (this is not a false `recvmmsg` claim), but the
batch amortizes deadline setup, polling, dispatcher entry, and application-loop
scheduling. Netz exposes the limit through
`Endpoint.receiveManyBytesInto*`, `Dispatcher.receiveManyVisitingWithDeadline`,
and `Server.receiveManyVisitingWithDeadline`; the benchmark defaults to the
same 32-message Unix batch width used by the audited Quinn checkout. Existing
GRO APIs remain separate because their segments share one source/control
record. New Initials stop the batch and retain the already-read suffix until
admission publishes its CID route; callback or protocol errors likewise retain
the unprocessed suffix, preventing batch-only packet loss. Tests cover warmed
zero-allocation established batches, callback-error recovery, Initial admission
ordering, deadline validation, and the real two-client handshake server path.

The benchmark now records and strictly verifies `server_receive_batch`, and
rejects summaries that mix batch sizes. A same-binary five-sample comparison
of the verified four-connection, 4 x 1-MiB upload measured batch 1 at
66.467-80.259 MiB/s (70.990 median) and batch 32 at 51.544-97.483 MiB/s
(86.325 median), a 21.6% median gain. The low batch-32 outlier is retained
rather than discarded. Separate batch-16/32 exploration reached 94.287 and
99.341 MiB/s medians in quieter samples, supporting 32 as the bounded default
without treating those non-paired runs as the headline ratio. Batch-32 scaling
smokes verified 8 MiB over eight connections at 92.107 MiB/s median and 16 MiB
over sixteen connections at 78.435 MiB/s median, with exact byte, checksum,
connection-completion, and DONE/DONE_ACK validation in every run.

Profiling the 16-connection shared server exposed another scaling cost in its
handshake-completion channel. The queue previously stored the roughly 9-KiB
EstablishedConnection inline, reserving about 1.1 MiB for the default 128
pending handshakes and copying the value through worker, queue, poll, and final
stable allocation. GDB samples during steady-state receive repeatedly stopped
in a 9,064-byte completion temporary clear, and ReleaseFast disassembly showed
about a 41.6-KiB stack frame for the batch receive wrapper. The endpoint owner
now preallocates the final stable connection, the worker constructs directly
into it, and the completion queue transfers only a success/failure tag through
a record statically capped at four machine words. The receive wrapper stack
fell to about 24.5 KiB, while the default completion queue's element storage
is capped at 4 KiB. The final connection allocation count is unchanged.

Five order-interleaved 16-connection, 16-MiB total uploads measured
71.515-85.421 MiB/s (79.110 median) with the pointer queue and
70.240-85.514 MiB/s (77.489 median) with the inline queue. The 2.1% higher
candidate median and overlapping ranges do not establish a throughput gain;
the change is retained for the approximately 280x bounded queue-memory
reduction and smaller hot receive stack, not presented as a throughput win.
Every run verified 16,777,216 bytes, checksum 2,139,095,040, all 16
connections, and the completion exchange.

Once all handshake workers have been consumed, the server now uses the atomic
active-worker count to bypass the empty completion queue, empty admission-map
expiry scan, and 5-ms handshake-poll deadline cap. A newly admitted Initial
increments the count before its worker can run, and a completed worker remains
counted until its queue record is consumed, so zero cannot hide pending
handshake work. Five order-interleaved comparisons against the pointer-queue
baseline, again using 16 connections and 16 MiB total, measured
62.892-83.443 MiB/s (68.005 median) with the idle-handshake fast path and
61.822-80.120 MiB/s (62.878 median) without it, an 8.2% median increase. The
ranges overlap, so this is supporting regression evidence rather than a broad
throughput claim; focused tests separately cover both zero and nonzero worker
states and real concurrent handshakes.

The batch dispatcher now also accepts an already-composed std.Io.Timeout. The
server validates the public caller deadline once, applies any active handshake
cap, and passes that absolute timestamp through without a second awake-clock
validation/read in the dispatcher. Public deadline entry points still reject
expired or cross-clock timestamps, and the timeout entry point also supports
the unbounded form used by lower-level event loops. Five order-interleaved
16-connection, 16-MiB comparisons against commit 8035e52b measured
63.805-87.090 MiB/s (74.840 median) after this change and
64.986-78.193 MiB/s (70.608 median) before it, a 6.0% median increase. The
ranges overlap, so the result supports removing duplicate per-batch work but
is not treated as an independent throughput claim.

The bench-quic-endpoint-pending executable measures the dispatcher's
pre-socket check for application packets retained by a completed handshake.
Its original full connection-table scan measured 71.60-76.33 ns at 16
connections, 570.78-617.82 ns at 128, and 4822.24-5121.12 ns at 1,024, while a
direct known-handle empty check stayed at 6.19-8.16 ns. Connections now notify
a dispatcher-owned ready index when `preloadReceivedDatagram` changes their
single pending slot from empty to occupied. Registration reserves the index
capacity before binding the no-allocation callback; replacement transfers the
binding, and unregister/deinit remove it before connection storage can move or
expire. This preserves direct post-registration preload users as well as the
usual handshake-promotion path without an O(connection count) fallback scan.
Three CPU-0 ReleaseFast runs with the same anti-elision barrier measured empty
index lookup at 0.88-0.96 ns for 1 connection, 0.76-0.79 ns for 16, 0.76 ns
for 128, and 0.76-0.77 ns for 1,024. Matching parent-commit runs measured
6.77-7.46, 70.29-76.24, 568.62-603.95, and 4794.96-5124.73 ns. The
1,024-connection medians therefore fell from 4848.59 to 0.76 ns (about 6,380x).
This is an isolated idle-dispatch cost result, not an end-to-end throughput
claim. A post-change shared-server smoke transferred 16,777,216 bytes in each
direction across sixteen connections with the exact 2,139,095,040 checksum and
completion exchange. Its single upload/download samples were 81.016 and
114.163 MiB/s, respectively, so they are retained as reliability evidence, not
as an independent throughput result.

Raw QUIC now also exposes `Connection.sendWithTimeout` and
`Connection.sendWithDeadline` for bounded STREAM/control sends that may need
peer flow-control or congestion progress. The helper keeps one absolute
awake-clock budget, services connection timers, applies ACK policy to packets
consumed only for progress, and leaves unrelated application data buffered.
The persistent benchmark previously freed those progress packets without ACKing
them. In multi-connection uploads, reliable MAX_DATA/MAX_STREAM_DATA packets
could consequently remain in flight until the receiver's control-packet
congestion window filled: pre-fix 2 x 16-MiB runs repeatedly left one transfer
at 8,387,712 bytes, and a 16 x 9-MiB run completed only 15/16 connections with
the last at the same offset. With the bounded send helper, the same 16 x 9-MiB
shape completed upload and download with exact 150,994,944 bytes, checksum
19,251,855,360, all sixteen connections, and the completion exchange. The
single post-fix samples were 41.516 MiB/s upload and 75.123 MiB/s download, so
this is reliability evidence across the initial 8-MiB connection window, not a
comparative throughput claim. Interop utilities that intentionally consume
packets only to advance transport state now use the state-only ACK-applying
receive path for the same reason. Receive reassembly also now measures its
bounded live window from the application read cursor, forcing compaction when
a retained consumed prefix would otherwise make a valid in-window frame look
oversized. Finally, an orphaned reliable recovery group whose sent copies are
all marked lost exposes a stable immediate PTO instead of recomputing "now"
on every scheduler query. With all three corrections, three consecutive
16 x 9-MiB bidirectional runs completed exactly; upload measured
51.206-51.988 MiB/s (51.973 median) and download 81.235-90.804 MiB/s
(83.065 median). A further 16 x 16-MiB run completed 268,435,456 bytes per
direction with checksum 34,225,520,640. These results remain
same-application-shape reliability data rather than a cross-stack throughput
claim.

The shared persistent benchmark now emits strictly checked receive-loop and
socket counters so future work can distinguish configured batch width from
actual batching. One verified 16-connection, 16-MiB upload with a configured
batch of 32 used 12,665 receive calls for 14,758 UDP datagrams, only 1.17
datagrams per call on average, while still reaching a maximum of 23. It
returned 14,743 events: 14,710 packets, 16 connections, and 17 timers. The
endpoint sent 14,785 datagrams / 605,774 UDP payload bytes and received
17,446,671 bytes. The checker requires event-class totals to match, one or more
events per successful call, connected events to match the requested connection
count, returned-event maxima to fit the configured bound, and accumulated
received datagrams to equal the endpoint socket counter. A high-level call can
read more than one socket batch when an entire batch is discarded or handed to
pending handshake workers, so its datagram maximum is reported but not bounded
by the per-socket batch size. This shows that batching
captures bursts but the typical call is close to a singleton, so reducing
per-call dispatcher work is higher leverage than increasing the batch width.

The same shared harness can now isolate the server's local ACK cadence with
the server-ack-every and server-ack-delay-us options; both values are recorded
in the client result, server completion, and summary, and mixed-policy result
sets are rejected. TLS-handshake-established connections and this benchmark
now default to an ACK after every second ack-eliciting application packet or
25 ms, whichever comes first. This matches the RFC 9000 recommendation and the
default cadence used by the audited Quinn and tquic implementations. The
low-level one-RTT ConnectionConfig deliberately retains its historical 1/0
default for callers that do not drive transport timers. ACK-policy overrides
remain limited to the shared netz/netz topology so cross-peer comparisons
cannot silently change shape.

Five verified 16-connection, 16-MiB samples measured 68.146-84.832 MiB/s
(77.088 median) with the historical 1/0 policy and 70.167-88.472 MiB/s
(77.220 median) with 2 packets / 25 ms. The throughput ranges overlap, so this
does not establish a throughput improvement. The 2/25-ms policy did reduce
server UDP sends from 14,780-14,787 to 7,456-7,460, approximately 49.6%, while
all samples retained exact bytes, checksum, connection completion, and the
DONE/DONE_ACK exchange. Default-path smoke runs without explicit ACK options
also completed at 1, 4, and 16 connections and recorded the expected 2/25-ms
policy; the 16-connection run sent 7,454 server datagrams at 76.832 MiB/s.

Short-delay concurrency exposed a separate issue: 2 packets / 1 ms succeeds
for one connection but originally timed out for four and sixteen connections.
The endpoint timer selector allowed a stale ACK-delay deadline to outrank the
close lifecycle after an application close; servicing it attempted a normal
ACK in closing state and surfaced ConnectionClosed from the shared loop. The
selector now exposes only close-response and close-expiry work while closing,
only close expiry while draining, and no timers once closed or idle-timed-out.
The previously failing four- and sixteen-connection 2/1-ms runs now complete;
the timer-aware handshake default uses 2/25 ms, while the low-level one-RTT
configuration remains 1/0 for timer-unaware callers.

Delayed ACKs also exposed a short-lived HTTP/3 completion edge. A client could
return the final response or push event with one ACK-eliciting STREAM/FIN still
behind its 25-ms timer, then stop driving receive while the server waited for
reliable-response recovery to drain. HTTP/3 packetization now opportunistically
appends that cumulative ACK to the first response packet when its frame and MTU
budgets permit; failure leaves the ACK pending and sends the application packet
unchanged. Client aggregate, multiplexed, and push completion additionally make
a nonblocking final ACK attempt before returning their terminal event. The
previously timing-out 4-stream/1-MiB download completed 5/5 runs after the fix;
throughput ranged from 45.84 to 48.33 MiB/s under visible host scheduling noise,
so this is reliability evidence rather than a throughput claim. Focused tests
cover STREAM-before-ACK wire ordering, frame-budget fallback, oversize rollback,
and clearing the delayed-ACK deadline at response and push completion.

The zio multi-message receive update exposed the complementary loss case in
the single-process transfer benchmark: its final ACK could be sent and lost,
after which the client stopped driving the connection while the server waited
for reliable response recovery. The benchmark now continues bounded HTTP/3
control polling until the server reports an empty recovery queue. A real zio
handshake regression deliberately drops that terminal ACK, requires the server
to send a PTO retransmission, and then verifies that client polling produces a
fresh ACK and lets the server finish. Five consecutive 16-MiB/four-stream runs
completed in all four upload/download and ordinary/body-batch shapes; the
download means were 65.80 and 72.32 MiB/s, respectively. These timings are
recorded only as post-fix stability evidence.

The server and dispatcher now both expose batch visitor entry points taking an
already-composed std.Io.Timeout. Public WithDeadline forms retain strict
awake-clock and expiry validation, while the shared benchmark can compose its
absolute budget once and pass it through every receive turn. Five
order-interleaved 16-connection, 16-MiB comparisons against commit b0544f2c
measured 68.192-78.576 MiB/s (69.963 median) with the server-level timeout path
and 57.507-69.848 MiB/s (67.376 median) before it, a 3.8% median increase. The
ranges overlap, so this supports removing a redundant per-call clock read but
is not treated as an independent throughput claim.

Endpoint CID mirroring now carries a monotonic revision on the fixed-size local
CID pool. Initial registration, successful NEW_CONNECTION_ID issuance, and an
actual RETIRE_CONNECTION_ID advance it; repeated retirement and failed
transactional sends do not. The dispatcher caches that revision plus the route
metadata which can change on migration. Ordinary STREAM/ACK packets therefore
skip active-CID enumeration, collision probes, router replacement, and stale
route scans with one revision/metadata comparison, while CID or path changes
still complete a full synchronization before returning the packet.
`bench-quic-endpoint-cid-sync` measures this isolated CPU cost with four active
CIDs. Three CPU-0 ReleaseFast ABBA runs over two million calls measured forced
synchronization at 627-637 ns/op and the unchanged-revision fast path at
9 ns/op, or 66.01-66.92x relative call throughput. Direct tests also assert
that a normal authenticated PING does not increment the full-sync counter,
whereas issuance and retirement each increment it exactly once. This is a
hot-path microbenchmark, not a whole-connection throughput ratio.

The bench-quic-endpoint-timers executable isolates how the endpoint timer
scheduler scales before changing its data structure. It covers ordinary
non-earliest updates, an unchanged write to the cached earliest entry, moving
that entry later, removing and rearming the earliest connection,
earliestDeadline reads, and a bounded due scan whose only due entry is at the
array tail. At one connection, operations labelled non-earliest necessarily
collapse to the sole (and therefore earliest) entry. The remove measurements
include both operations so every timed iteration starts with the same number
of armed connections.

Three CPU-0 ReleaseFast runs on the 2026-09-13 Linux AArch64 host with two
million fast-path iterations and at least 64 million examined entries per
scan-sensitive case measured:

| Connections | Non-earliest update | Unchanged earliest | Postpone earliest | Remove + rearm earliest | earliestDeadline | Bounded due scan |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 10.35-11.20 ns | 10.11-10.24 ns | 10.21-10.35 ns | 24.92-25.35 ns | 1.15-2.66 ns | 1.15-1.53 ns |
| 16 | 11.93-11.95 ns | 55.80-62.65 ns | 41.11-42.29 ns | 64.06-65.47 ns | 1.15-2.34 ns | 7.32-7.70 ns |
| 128 | 12.20-12.34 ns | 401.58-413.53 ns | 348.28-352.75 ns | 412.69-414.28 ns | 1.15-2.37 ns | 50.82-74.03 ns |
| 1024 | 11.92-11.96 ns | 3165.51-3179.04 ns | 3106.69-3110.58 ns | 3175.62-3176.15 ns | 1.15-2.60 ns | 408.43-470.82 ns |

The cached read and non-earliest update remain constant, while all three
cached-earliest mutations expose the current full-array recomputation. Most
notably, an identical timer write costs about 3.17 us at 1,024 connections even
though it cannot change ordering. This evidence makes an exact no-op update
fast path the next low-risk experiment. A heap is not yet justified: it would
also add ordering work to the measured 12 ns ordinary-update path. The bounded
due scan is intentionally linear because it provides a stable per-event-loop
snapshot, but the benchmark keeps its independent scaling cost visible.

The benchmark was then extended to distinguish three more scheduler changes.
Three CPU-0 runs after the exact-update fast path measured:

| Connections | Advance current earliest | Non-earliest becomes earliest | Remove + rearm non-earliest |
|---:|---:|---:|---:|
| 1 | 9.30-9.44 ns | 9.35-9.50 ns | 23.73-23.90 ns |
| 16 | 32.56-32.71 ns | 9.37-9.48 ns | 24.37-24.47 ns |
| 128 | 338.50-360.39 ns | 10.02-10.34 ns | 36.54-36.79 ns |
| 1024 | 3108.29-3109.39 ns | 10.00-10.08 ns | 24.52-24.85 ns |

This exposes a second unnecessary scan: moving the already-earliest timer
earlier cannot invalidate its position. In contrast, a non-earliest timer can
become earliest and a non-earliest timer can be removed in constant time. The
audited Quinn driver similarly avoids resetting an unchanged runtime timer;
tquic uses a double-ended priority queue for its multi-connection endpoint.
The local measurements do not justify adopting that queue wholesale because
it would impose logarithmic maintenance on the two fast cases above. They do
justify separately eliminating the current-earliest advance scan.

That monotonic fast path now keeps the cached index when the current earliest
timer's new deadline is equal or earlier, while still updating an observable
timer-kind change. Three adjacent CPU-0 runs reduced the 1,024-connection
advance-earliest case from 3108.29-3109.39 ns to 8.48-8.69 ns per update, a
358-367x latency reduction. At the same size, a true postponement still
measured 3106.64-3107.64 ns, a non-earliest timer becoming earliest measured
10.00-10.16 ns, and non-earliest remove-plus-rearm measured 24.49-24.52 ns.
The remaining scans therefore stay visible and the array/index design retains
its constant-time ordinary-update behavior.

An indexed binary min-heap candidate was also implemented and tested, using
the existing handle-to-slot map as its reverse index, then fully removed. At
1,024 connections it reduced a true earliest postponement from about 3.11 us
to 190.83 ns and earliest remove-plus-rearm from about 3.17 us to 224.35 ns.
However, a non-earliest timer becoming earliest increased from about 10 ns to
166.44 ns; at 16 connections the heap was slower for every measured
order-changing update/removal. Two order-reversed real 16-connection shared
server pairs were also inconclusive: heap versus array measured 85.467 versus
88.502 MiB/s, then 103.706 versus 88.340 MiB/s. With no stable end-to-end gain
and a clear cost in the ordinary small endpoint sizes, the tquic-style heap is
not retained. These rejected results delimit when a future adaptive structure
might become worthwhile instead of treating lower asymptotic complexity as a
performance claim.

An adaptive follow-up retained the unordered array below 128 armed connections
and heapified the same entry storage above that point, with a 64-entry exit
threshold. It reused the handle-to-slot map as the reverse index and pruned
future subtrees during bounded due snapshots. Five CPU-0 microbenchmark runs
at 1,024 connections reduced median earliest postponement from 3,109.39 to
195.03 ns, earliest remove-plus-rearm from 3,172.40 to 226.85 ns, and one due
entry among 1,024 from 409.23 to 4.64 ns. A non-earliest entry becoming the new
minimum rose from 10.10 to 167.36 ns, while the 16-connection array path stayed
within 2%. Deterministic model tests covered 5,000 mixed updates, removals,
threshold transitions, heap/index invariants, and exact due snapshots.

The candidate was nevertheless removed after the real shared-endpoint control.
Five order-alternated 128-connection, one-socket, 64-KiB-per-connection pairs
showed extreme host/scheduling variance and worse candidate medians: upload
18.678 versus 54.551 MiB/s and download 10.375 versus 29.150 MiB/s. Ranges
overlapped, so these values do not isolate timer cost, but they provide no
end-to-end basis for retaining the extra ordering work. The existing array and
cached-minimum implementation remains the production choice.

The evidence harness itself now permits up to 256 connections only for a
netz/netz shared-server endpoint; independent-socket and cross-stack shapes
retain the existing 16-connection cap. Its readiness reader validates the
complete comma-separated port count and terminating newline before starting
clients. Before that fix one of ten 128-connection A/B arms consumed a partial
server readiness line and failed locally with `InvalidArgument`; afterward all
ten arms completed both directions with exact 8,388,608-byte, 128/128 and
checksum 1,069,547,520 validation. This expands functional scaling evidence
and fixes a measurement race, but the wide throughput spread remains an
explicit scheduler/benchmark-stability gap.

The selected follow-up keeps the array/index design and returns immediately
when an existing connection's timer kind and deadline are both unchanged.
Three adjacent CPU-0 runs reduced the 1,024-connection unchanged-earliest case
from 3165.51-3179.04 ns to 6.78-6.90 ns per update, a 459-469x latency
reduction. The 1,024-connection ordinary non-earliest update measured
8.78-8.99 ns; a genuinely postponed earliest timer remained
3105.56-3114.79 ns and remove-plus-rearm remained 3170.05-3172.24 ns. Thus the
optimization removes only the provable no-op scan without hiding the remaining
linear operations or imposing heap maintenance on ordinary updates.

The bounded due query now checks the cached earliest deadline before scanning
the stable timer array. This preserves the bounded snapshot when any timer is
due, while making the common all-future receive turn independent of connection
count. Five CPU-0 ReleaseFast ABBA rounds against parent `1f3a5a97`, with two
adjacent samples per arm, used two million iterations at 16 connections and
62,500 at 1,024 connections. They reduced the 16-connection all-future query
from 7.31-9.03 ns/op to 0.38 ns/op. At 1,024 connections it fell from
407.25-424.34 ns/op to 0.38-0.42 ns/op. The
one-due-at-array-tail control remained 7.69-9.24 versus 7.70-9.21 ns/op at 16
connections and 408.67-410.45 versus 408.31-409.79 ns/op at 1,024, confirming
that due snapshot work stays visible. This matches Quinn and tquic's endpoint
designs, which consult the next deadline before processing timeout work.

Five fixed-binary, order-interleaved 16-connection, 16-MiB-total shared-server
pairs completed exactly in both sender directions. Client-sender throughput was
69.545-81.820 MiB/s (71.618 median) before and 51.981-87.514 MiB/s (72.599
median) after, with 3/5 pair wins. Server-sender throughput was 80.111-97.652
MiB/s (82.052 median) before and 72.933-94.584 MiB/s (84.589 median) after,
also with 3/5 wins. The wide overlapping ranges make this end-to-end no-
regression evidence, not a throughput improvement claim. Every arm verified
16,777,216 bytes, checksum 2,139,095,040, all 16 connections, and the
completion exchange.

Shared dispatcher receive timeout composition now compares absolute raw values
when the transport timer and caller deadline use the same clock. The normal
shared-server path uses the awake clock for both, so it no longer performs two
`durationFromNow` clock reads on every socket-wait turn. A focused test passes
an unusable `std.Io` and still selects both possible same-clock minima, proving
that branch is clock-read-free. A separate fixed-clock test retains the generic
cross-clock behavior, observes exactly two reads, and orders deadlines by
remaining duration rather than incomparable epochs.

Five fixed-binary, order-interleaved 16-connection, 16-MiB-total pairs against
parent `f232a0b3` completed exactly in both sender directions. Client-sender
throughput was 68.990-81.605 MiB/s (73.906 median) before and
72.643-80.460 MiB/s (76.276 median) after, with 4/5 candidate wins.
Server-sender throughput was 74.444-92.247 MiB/s (80.120 median) before and
80.281-92.579 MiB/s (83.786 median) after, also with 4/5 candidate wins. The
raw ranges overlap, so these results support removing fixed receive-turn work
but do not establish a throughput gain. Every arm verified 16,777,216 bytes,
checksum 2,139,095,040, all 16 connections, and the completion exchange.

The shared dispatcher's caller-buffer batch now also returns a bounded snapshot
of due timers instead of at most one timer per receive call. Each connection is
visited once per snapshot, so an immediately rearmed connection cannot starve
its peers or UDP receive. If PTO transmission is temporarily pacing-limited,
the endpoint replaces the already-due loss entry with the connection's exact
future pacing wake-up and continues through the snapshot; a 16-connection
pressure run caught the prior error propagation after 10/16 downloads, while
the corrected run completed all 16. Direct public-API tests cover a two-event
capacity bound, a third timer left for the next call, UDP data remaining queued
until due timers are serviced, and progress past a paced connection.

Three fixed-binary, order-interleaved comparisons against parent `d605cd55`
used the shared-server aggregate shape with 16 connections, one 1-MiB stream
per connection, and receive batch 32. In the timer-heavy server-sender direction,
the baseline used 2,800-3,368 receive calls (3,266 median) for 2,586-3,124 timer
events, while the timer-batch candidate used 1,008-1,135 calls (1,088 median)
for 2,797-3,372 timer events: a 66.7% median call-count reduction. Throughput
was 77.996-85.504 MiB/s (80.651 median) before and 75.629-87.950 MiB/s
(84.438 median) after. Client-sender throughput was 69.609-93.420 MiB/s
(79.518 median) before and 63.189-79.369 MiB/s (73.885 median) after. Both
throughput ranges overlap, and the upload median moved lower, so this is retained
as bounded scheduling/call-amortization evidence, not a throughput improvement.
Every arm verified 16,777,216 bytes, checksum 2,139,095,040, all 16
connections, and the completion exchange.

The caller-buffer independent-message receive path no longer zeroes every
ancillary-data slot before calling the I/O backend. The kernel/backend writes
the received control-message prefix and returns its exact length; unused suffixes
and unused batch slots are never parsed. This follows Quinn's Linux receive path,
which uses `MaybeUninit` ancillary storage, while preserving initialized message
descriptors. At the default batch width this removes an unconditional 2,304-byte
stack write per receive call on this Linux AArch64 ABI (4,608 bytes at the public
maximum of 64). A real four-datagram UDP regression receives ECT(0), ECT(1),
CE, and then Not-ECT in one batch, proving that control metadata neither crosses
slots nor leaks into a later unmarked datagram.

Five fixed-binary, order-interleaved 4 x 16-MiB comparisons against parent
`bcb678e7` were directionally mixed. Client-sender throughput was
32.023-42.752 MiB/s (36.655 median) before and 34.380-39.088 MiB/s
(35.953 median) after; the candidate won 2/5 pairs. Server-sender throughput was
39.733-48.835 MiB/s (46.162 median) before and 41.839-55.302 MiB/s
(48.243 median) after; the candidate won 4/5 pairs. Both ranges overlap, so no
throughput improvement is claimed; the change is retained for the definite
elimination of unused initialization and its direct ECN correctness coverage.
Every run verified 67,108,864 bytes, checksum 8,556,380,160, four completed
connections, and the completion exchange.

The persistent benchmark runner now accepts `--netz-only`, which runs the
netz/netz pair in independent topology without requiring Go or an external
fixture; its strict summary still requires both sender roles and every requested
sample. On the same final binary, three 4 x 1-MiB shared samples measured
85.365-102.847 MiB/s (96.750 median) for the client sender and
67.411-85.390 MiB/s (75.982 median) for the server sender. Three independent
samples measured 88.226-102.534 MiB/s (94.295 median) and
52.909-92.712 MiB/s (87.691 median), respectively. The resulting median ratios
are 1.026x and 0.867x, but both pairs have heavily overlapping ranges and the
topologies were not order-interleaved, so this supersedes the stale 0.717x
observation only as a current noisy baseline, not as evidence that the shared
topology has conclusively reached parity.

The topology runner now has a strict `--server-topology=compare --netz-only`
mode. It reuses one ReleaseFast executable, pins client/server to CPUs 0/1,
uses an odd sample count, mirrors independent/shared order on alternating
rounds, fixes both topologies to ACK-every=2 and 25 ms, and validates every
payload, checksum, completion exchange, backend identity, and topology before
summarizing. A 2026-09-15 five-sample zio-era run with four connections and
one 1-MiB stream per connection measured:

```text
sender          independent median  shared median  shared/independent
client             66.070 MiB/s      43.653 MiB/s       0.661x
server             63.710 MiB/s      41.337 MiB/s       0.649x
```

The independent ranges were 55.443-67.770 and 56.237-74.028 MiB/s; shared
ranges were 41.649-44.977 and 36.148-58.804 MiB/s. This is a same-stack
topology baseline that quantifies the shared endpoint scheduling gap; it is not
a cross-library speed claim.

That gap was traced below the QUIC dispatcher: zio v0.17.0 implemented the
multi-slot `std.Io` network receive operation with one `recvmsg`, so the
caller's 32-message buffer normally returned one datagram. Netz now pins zio
commit `54cb18f05d3feaec431353de85d5d10dac93d37b`, which implements the same
`std.Io.net.Socket.receiveManyTimeout` contract with native multi-slot UDP
receive (`recvmmsg` when no ancillary buffers are needed and a portable drain
fallback otherwise). Direct Linux zio/`std.Io` and QUIC-endpoint regressions
queue multiple datagrams and require one call to return all of them in order;
the latter covers the ancillary-control path used for ECN. No zio or
OS-specific API enters the QUIC layer.

A fixed-binary, CPU-0/1, five-pair shared-only A/B against the v0.17.0 binary
measured 65.915 versus 42.417 MiB/s client-sender medians (1.554x, 4/5 paired
wins) and 65.633 versus 48.363 MiB/s server-sender medians (1.357x, 3/5 paired
wins). The candidate ranges remained wide, so these are workload-specific
medians rather than a general speed claim. More directly, completed shared
runs returned as many as 32 events from one receive call, whereas the old
backend returned at most one packet event in the upload path and three total
events in the timer-heavy download path. Ten subsequent shared runs completed
both sender directions with exact 4,194,304-byte payloads, checksum
534,773,760, four completions, and DONE/DONE_ACK.

The strict topology gate was then rerun on the final candidate with the same
four connections, 1 MiB per connection, ACK/2, 25-ms delay, and mirrored
ordering:

```text
sender          independent median  shared median  shared/independent
client             70.158 MiB/s      72.318 MiB/s       1.031x
server             64.338 MiB/s      67.712 MiB/s       1.052x
```

Independent ranges were 65.909-77.678 and 61.757-69.883 MiB/s; shared ranges
were 70.069-77.274 and 44.199-69.233 MiB/s. The overlapping ranges do not show
that shared is faster, but this controlled run no longer reproduces the prior
0.661x/0.649x median deficit. The remaining work is wider connection-count and
host coverage plus capture-backed equal-wire comparison.

The endpoint CID router, CID synchronization, pending-ready-index, timer
scheduler, and receive-stream-ID benchmarks now obtain their UDP endpoint,
where needed, and monotonic clock from zio-backed `std.Io`; each prints the
runtime identity. Their historical A/B numbers below predate that runtime
migration. The endpoint CID router uses
`HashMap.getAdapted` with the borrowed CID
slice from the datagram instead of zero-filling and copying it into a 20-byte
fixed key for every lookup. Stored keys remain fixed-size and owned, and all
registration, collision, mixed-length longest-prefix, removal, long-header, and
greased fixed-bit semantics are unchanged. This follows the same parsed-CID-to-
route separation used by the audited Quinn and tquic endpoint implementations.
The new `bench-quic-connection-router` measures 64 registered 16-byte CIDs with
ten million rotating hits and same-length misses. Five CPU-0 ReleaseFast ABBA
runs reduced hit latency from 51.80-52.23 ns (51.98 median) to 28.38-29.02 ns
(28.62 median), a 44.9% reduction with 5/5 wins. Miss latency fell from
38.90-39.72 ns (39.56 median) to 11.86-13.14 ns (12.03 median), a 69.6%
reduction with 5/5 wins.

Five fixed-binary order-interleaved 16-connection, 16-MiB-total shared-server
pairs against parent `d567941f` also completed exactly. Server-sender throughput
was 73.684-87.131 MiB/s (85.021 median) before and 83.277-104.812 MiB/s
(90.453 median) after; the candidate won all five pairs and the median paired
ratio was 1.053x. Client-sender throughput was 62.231-82.841 MiB/s
(73.173 median) before and 59.452-116.552 MiB/s (86.686 median) after, with
3/5 wins. Both raw ranges overlap, so the isolated lookup result is the strong
claim and the transfer result is supporting evidence, not a whole-topology
throughput verdict. Every arm verified 16,777,216 bytes, checksum
2,139,095,040, all 16 connections, and the completion exchange.

Two adjacent scheduling experiments were rejected. Coalescing all packet/timer
events for one connection into one end-of-batch application wake-up reduced the
timer-heavy server-sender notification median by 45.8%, but reduced throughput
from 82.749 to 79.553 MiB/s and won only 1/5 pairs; immediate ACK-driven send
opportunities were more valuable than fewer callback invocations. Moving the
server send plus timer refresh behind a dispatcher wrapper also failed to show
a stable benefit and was removed. The existing per-packet application wake-up
and direct server send path are therefore retained.

The shared endpoint server now also exposes a socket-free `streamSendCredit`
snapshot for nonblocking application loops. The persistent server-sender used
to retry its full 1,152-byte payload chunk even when a stream window had a
smaller positive tail. Because `trySend` is deliberately transactional, a
1,024-byte advertised stream window left 1,008 bytes after the 16-byte prelude
and the full chunk could never commit. The sender now submits the positive
prefix allowed by connection, stream, congestion, and datagram credit; zero
credit still performs the original attempt so QUIC can emit DATA_BLOCKED or
STREAM_DATA_BLOCKED. Timeout diagnostics retain per-connection credit, cwnd,
in-flight, recovery, pacing, and next-timer state for future failures.

A fixed-binary real TLS/QUIC regression against parent `3ccbb9d3` used one
shared-server connection, a 1,024-byte stream window, and a 65,536-byte
server-originated payload. The parent timed out in `stage=payload` with offset
zero; the candidate transferred all 65,536 bytes, verified checksum 8,355,840,
and completed the DONE/DONE_ACK exchange. A 16-connection pressure run then
transferred 64 MiB per connection (1,073,741,824 bytes total), checksum
136,902,082,560, and all completion exchanges in about 195 seconds. Three
order-interleaved 16-connection, 16-MiB-total pairs were noisy: server-sender
candidate throughput was 82.035-105.988 MiB/s versus parent
78.725-102.589 MiB/s with 2/3 wins, while client-sender was
63.328-83.471 versus 70.786-100.162 MiB/s with 1/3 wins. All ranges overlap,
so the retained claim is progress/reliability, not throughput improvement.
The shared `transfer.sendPayloads` helper had the same fixed-chunk assumption
on the blocking client and independent server paths. It now consumes any
positive `SendCredit.available()` prefix before blocking for more transport
progress, while a zero-credit one-byte probe retains DATA_BLOCKED and
STREAM_DATA_BLOCKED signaling. Against parent `4fe04ace`, the same one-
connection, 1,024-byte-window, 65,536-byte shared run timed out during the
client-sender payload at offset zero; the candidate completed both sender
directions with exact bytes, checksum, and DONE/DONE_ACK. The candidate also
completed both directions in the independent topology. Three fixed-binary,
order-interleaved standard-window shared pairs were noisy: client-sender
throughput was 70.175-82.803 MiB/s (75.876 median) before and
64.423-86.394 MiB/s (77.895 median) after; server-sender was
69.777-87.339 MiB/s (79.613 median) before and 75.609-91.790 MiB/s
(82.877 median) after. The candidate won 2/3 pairs in both directions and all
ranges overlap, so this remains a correctness/progress result.
Raw `one_rtt.Connection` now exposes the reusable `sendStream`,
`sendStreamWithTimeout`, and `sendStreamWithDeadline` forms behind that fix.
They send one contiguous logical payload across exact MTU, connection, stream,
congestion, and pacing boundaries; `committed_out` reports the socket-visible
data prefix on every return, and FIN is emitted only with the last prefix.
Direct tests force a five-byte window into 4/5/3-byte chunks, resume from a
five-byte timeout prefix, validate empty FIN, and inject `NetworkDown` after a
visible first packet before retrying the exact suffix of a 2,000-byte payload.
The persistent benchmark invokes this helper only for short credit tails, so
its ordinary full-chunk fast path is unchanged. Three paired standard-window
reruns of the final benchmark path against parent `efcdd342` showed wide host
scheduling noise even though both ReleaseFast executables had identical hot-
function addresses and the benchmark source was identical. Client-sender
throughput was 65.690-79.945 MiB/s before and 67.040-72.981 MiB/s after; the
candidate won 1/3 pairs. Server-sender throughput was 69.517-86.863 MiB/s
before and 78.616-92.544 MiB/s after; the candidate won 2/3 pairs. Both ranges
overlap, so this is not treated as an API performance result; the direct
progress and retry tests are the claim.
The same raw connection surface now has `sendStreamSlices`,
`sendStreamSlicesWithTimeout`, and `sendStreamSlicesWithDeadline`. They stage
adjacent borrowed slices as consecutive STREAM frames and fill each packet
across slice boundaries without changing the connection's one-packet fairness
policy; committed bytes are reported across the logical concatenation. Direct
tests cover empty slices, a five-byte flow-credit prefix crossing a slice
boundary, offset-overflow
preflight with no packet or stream-state mutation, a socket-visible packet
prefix followed by exact suffix retry, and FIN only on the final packet.
This is a functionality/copy-avoidance result; no throughput claim is made.
The shared stateful send preflight now also charges connection and stream flow
control by each stream's new highest-offset increment rather than summing
STREAM payload lengths. Sparse offsets therefore include their gap, while
overlap and retransmission-shaped frames consume no duplicate credit. The same
transactional accounting covers single sends, partial socket batch prefixes,
and accepted 0-RTT imports; a per-batch shadow rejects conflicting FIN/final
sizes before the first packet is sent. Direct tests cover sparse and overlapping
frames, partial rollback, FIN-only stream materialization, same-packet and
cross-packet final-size conflicts, 0-RTT multi-stream reserve failure, and
0-RTT sparse/overlap accounting.

Five CPU-0 fixed-binary order-interleaved pairs against parent `aa15da55` used
the existing 32-packet raw send benchmark with 50,000 iterations per arm. For
one STREAM descriptor per packet, parent batch cost was 3,219-3,574 ns/packet
(3,499 median) and the corrected path was 3,407-3,574 ns/packet (3,530 median).
With four descriptors per packet, parent was 3,611-3,688 ns/packet (3,655
median) and the corrected path was 3,649-3,750 ns/packet (3,692 median). The
candidate won 1/5 pairs in both shapes and both ranges overlap. This records an
approximately 1% median validation cost for closing protocol correctness gaps;
it is not treated as a performance improvement.

The shared-server benchmark now negotiates draft-07 ACK_FREQUENCY instead of
silently installing a benchmark-only receive policy. Both endpoints advertise
`min_ack_delay=1000`; the client appends one ACK_FREQUENCY request to its first
non-empty 1-RTT packet, while the server deliberately does not make the reverse
request. The wire Ack-Eliciting Threshold is a tolerance, not the local trigger
count: wire value 3 requests an ACK on the fourth ack-eliciting packet. The
receive path now performs that `+1` conversion with saturation. The requested
maximum ACK delay remains the peer's transport-parameter value, so the policy
does not lengthen PTO. Low-level keyed connections retain their 1/0 defaults,
and handshake users must opt in to sending the request after peer capability is
known.

Five fixed-binary, order-interleaved 16-connection, 16-MiB-total pairs compared
parent `017a3473` with server ACK/2 against the negotiated client request for
server ACK/4. The parent and candidate executable SHA-256 values were
`a17c6f4596040cd9a230e24dee0c5b1c81fdbb9d966ff2e7cc8f922e6484c593`
and `7a0d8fc6897283145071a3c117d2cf6db59098e8fcab36a97c9bd0eac282b672`.
Client-sender samples were 65.267, 56.383, 57.579, 66.328, and 57.252
MiB/s for the parent versus 90.483, 76.974, 68.014, 81.159, and 55.224
MiB/s for the candidate. Their medians were 57.579 and 76.974 MiB/s, a
33.7% increase with 4/5 paired wins. The ranges, 56.383-66.328 and
55.224-90.483 MiB/s, overlap, so this does not establish a universal or
per-run win. Server UDP sends fell from 10,579-12,304 datagrams (10,950
median) to 4,377-4,472 (4,445 median), a 59.4% median reduction.

The server-sender control retained the client's ordinary ACK behavior. Parent
samples were 78.970, 95.858, 80.281, 78.660, and 85.087 MiB/s; candidate
samples were 80.489, 87.458, 76.407, 90.833, and 85.733 MiB/s. Medians were
80.281 and 85.733 MiB/s with 3/5 candidate wins, but the ranges overlap. This
is evidence against the systematic download regression seen with bidirectional
requests, not a download speedup claim. Every arm verified 16,777,216 bytes,
checksum 2,139,095,040, all 16 connections, and DONE/DONE_ACK completion.
Direct tests additionally prove first-packet HANDSHAKE_DONE/ACK_FREQUENCY
coalescing, socket-failure retry without consuming the sequence or pending
request, PTO retransmission after a successful send, explicit-request override,
and rejection when the peer did not advertise support. A post-freeze rebuild
reproduced the candidate hash, and a two-connection shared smoke reported
ACK/4 while completing exact upload and download verification.

The follow-up recovery path now mirrors audited Quinn
`d9c8c4c695fc64292d9b117844ea6924ca0d0815`: when the peer advertised
ACK_FREQUENCY support, every application-data PTO probe also carries
IMMEDIATE_ACK so the sparse ACK policy cannot delay recovery feedback. The
hint is ack-eliciting and congestion-accounted but not retained in the recovery
payload; every later PTO creates a fresh request. A full-MTU reliable payload
keeps all data and omits the optional byte. Direct tests cover a pure-DATAGRAM
flight, single and two-probe reliable recovery, exact-MTU fallback, socket zero
progress, partial batch progress, and the original unnegotiated PING path.

A ReleaseFast real TLS/QUIC 4-MiB loss run dropped exactly 25/504 datagrams,
reported 25 transport losses, and verified all bytes. Five fixed-binary,
order-interleaved 1-MiB pairs at 5% seeded loss and 100 us configured RTT used
parent `c3f85d99` (`770015f1a18753f64449e3dd49424e1c7bfe2b155936c54e090d419c7680f546`)
and candidate
`ff0b8337cfa57c821675feb517ad732aff0232109b094ce3b842f13ce1c91a9c`.
Parent elapsed times were 10.161, 9.314, 10.213, 9.131, and 9.272 ms;
candidate times were 9.543, 9.294, 9.821, 9.946, and 9.373 ms. The candidate
won 3/5 pairs, while independently sorted medians were 9.314 and 9.543 ms and
the ranges overlap. This is protocol/recovery evidence with no throughput or
latency improvement claim. Every arm deterministically dropped 6/126
datagrams, reported six transport losses, and verified 1,048,576 bytes.

ACK_FREQUENCY requests can now also select an explicit Requested Max Ack Delay
instead of inheriting the peer transport parameter. This follows Quinn's PTO
safety rule: a larger request widens application-data PTO only after the packet
is socket-visible; while several requests are unconfirmed, PTO retains their
maximum possible delay; an ACK covering any copy of the newest recovery group
commits that value and may then lower the bound. RTT ACK-delay capping, idle
minimums, keep-alive floors, stateless-reset draining, persistent-congestion
thresholds, PTO jitter, and path resets use the same effective value. The
no-sample application-data PTO now also follows RFC 9002/Quinn's initial RTT +
4*rttvar + max_ack_delay formula: with the 100-ms initial RTT and 25-ms peer
delay it is 325 ms, rather than the former under-estimated 200 ms. Direct tests
cover 25-to-80-ms widening, an unconfirmed 10-ms downshift that remains at
80 ms, confirmation down to 10 ms, ACK of a retransmission copy, explicit
packet-number acknowledgement, invalid values below `min_ack_delay` or at the
2^14-ms limit, and socket failure leaving the original 25-ms PTO unchanged.
The shared benchmark leaves the request override null, so its established ACK/4
policy is unchanged; a post-change two-connection upload/download smoke verified
exact bytes, checksum, connection completion, and ACK/4. A new 4-MiB 5%-loss run
again dropped 25/504 datagrams, reported 25 transport losses, and verified all
bytes.

Five final-source, fixed-binary, order-interleaved 1-MiB pairs at 5% seeded
loss and 100 us configured RTT compared parent `6cd4611c`
(`aa13d564246e92a7a0c75d7fa25e35843be842e039c4d561ce47add5f058e12b`)
with candidate
`e1a73a652292414199c6b1277fbea2526785fbdfbc7b79f66f4a0f067cf8fb2a`.
Parent elapsed times were 9.409, 9.552, 9.760, 10.740, and 9.332 ms; candidate
times were 10.490, 9.699, 9.256, 9.276, and 9.390 ms. The candidate won 2/5
pairs; independently sorted medians were 9.552 and 9.390 ms and ranges overlap.
Every arm deterministically dropped 6/126 datagrams, reported six transport
losses, and verified 1,048,576 bytes. This step is retained for protocol and
recovery correctness, with no throughput or latency improvement claim.

One follow-up packet-protection shortcut was tested and rejected. The ordinary
single-packet path already computes protected length in `prepareFramesForSend`;
the candidate reused that value for sent metadata and the final sealing helper
instead of recomputing it twice. Five fixed-binary CPU-0 pairs of the
32-packet/1-KiB send microbenchmark moved sequential median only from 138,952
to 138,631 ns/batch (0.23%, 3/5 wins), while the batch control was likewise
noise-level. The parent/candidate send-benchmark SHA-256 values were
`2034af763f6044020917dfd7bb7ef41ccaec61ecf72e76a2d1ab14e86d68cac3` and
`5691f247827163eb8263da81526bf7ce56590952484217ae93e20872bbb8f284`.
Five order-interleaved 16-MiB/four-stream real TLS/HTTP/3 upload
pairs measured parent 136.50-145.20 MiB/s (142.68 median) and candidate
138.72-147.46 MiB/s (142.33 median), with 2/5 candidate wins. Every run
verified 16,777,216 bytes and status total 800; those binaries hashed to
`987d2e01b5cffee31268c01d6b8eb2dcb9cfc2b5ca825af27f3471e86ac0f3e1` and
`894c3503e775abf5cd87aa0102b98d8204404d924a5d919976cbe1701646b674`.
The implementation was removed;
these overlapping results do not justify adding another internal API parameter.

A later profile attributed roughly 2.8% of the one-packet send microbenchmark
to compiler-generated `memcpy` below `prepareFramesForSend`. Three narrower
forms were tested rather than assuming that symbol attribution identified the
copied object. Borrowing the complete `Frame` union reduced one encoding-side
copy but left the prepare-side share at roughly 3.5%; ten CPU-0 fixed-binary
pairs put its sequential candidate/baseline median near 0.995, with the batch
control neutral. Replacing the private `PreparedFrames` return with caller
storage likewise left about 3.1% under prepare and produced a 1.000 sequential
paired median with 5/10 wins. Both forms were removed. Their baseline and
candidate send-benchmark SHA-256 values were respectively
`9389c03126434984cd3cc4c7eed7c5dc6087fc702331d7ee0803779253cc0758` /
`43bae52464b17b5661435682e1d566ce8fc5a6ea81f80c04507581cc2df53adc`
and
`9389c03126434984cd3cc4c7eed7c5dc6087fc702331d7ee0803779253cc0758` /
`ddf823af5d30a5ac2382ad508e1db9eb0fed848b9a1149ab803e859852cee469`.

The final form specialized only the common STREAM length calculation. AArch64
disassembly proved that it avoided the former 80-byte `Frame` load/store before
`wireLen`, while every other frame kept the general validation path. Ten fixed
send-microbenchmark pairs measured a 0.992 sequential paired median with 7/10
wins; the batch control remained neutral. The baseline/candidate hashes were
`9389c03126434984cd3cc4c7eed7c5dc6087fc702331d7ee0803779253cc0758` and
`4c1b863dd2fc79ec179ce43bd86656d76235eb044650a03c7ada36617b611e55`.
That structural improvement still did not survive the complete workload:
seventeen CPU-0/1, order-alternated 64 x 1-MiB pairs produced a 1.001
server-sender paired median with 11/17 wins and a 1.003 client-sender median
with 9/17. Persistent baseline/candidate hashes were
`0e4ed798c8896590d664bcdbbd4dccb4a4d52f87d99ff6ea5614d0bb973e19d9` and
`5bb677fc334adb43f35bcded445e951bf252165f891c129ba27a45a2a2d55abc`.
Every arm verified 67,108,864 bytes, checksum 8,556,380,160, all 64
connections, and the completion exchange. The candidate was fully removed:
avoiding one compiler-generated metadata copy is not retained when both
end-to-end sender directions remain neutral.

### Raw QUIC mixed FIN/reset recovery versus quic-go

The separate process gate below exercises terminal stream churn instead of
timing it:

```sh
zig build interop-quic-quic-go-churn -Doptimize=ReleaseFast
```

It runs 32- and 64-stream cases for both connection-role pairings, both
client/server sender roles, and deterministic loss/reordering, with two runs
per combination by default. Every unidirectional stream carries a 12-byte
index prelude and an acknowledged 256-byte payload prefix. Every second stream
then resets with code `0x4000 + index`; only after the receiver observes all
exact codes do the remaining streams continue to 16 KiB and FIN. A
bidirectional sibling opened before churn completes afterward, followed by
control-stream FIN in both directions and an exact application close.

All four actual sender endpoints use the same unprivileged UDP relay. The
client tells it to fault the client-to-server or server-to-client path as
appropriate, and each RESET and FIN phase deterministically incurs exactly one
drop or one completed pair reorder. The independent verifier recomputes the
payload checksum, FIN/reset counts, reset mask and error-code sum, requires both
phase counters, and cross-checks the client's cumulative counters against the
proxy. Netz additionally checks RESET final size when it is the receiver;
quic-go v0.59 exposes the exact remote stream ID and error code but not the
peer's final size through its public `StreamError`.
The raw benchmark/churn peer and its protocol tests are built from the same
repository-owned, checksum-locked Go module as the HTTP/3 fixtures; the
loss/reorder relay remains a separate process.

The captured default 32-case two-run matrix completed every case. The 32-stream
shape verified 16 FIN, 16 RESET, 266,240 application bytes, checksum
33,945,600, mask `0x00000000aaaaaaaa`, and code sum 262,400. The 64-stream
shape verified 32 FIN, 32 RESET, 532,480 bytes, checksum 67,891,200, mask
`0xaaaaaaaaaaaaaaaa`, and code sum 525,312. Each case reported two drops or
two completed reorder pairs—one in each terminal phase. This closes the former
external raw-transfer loss/reorder and mixed-churn gap. It remains bounded
loopback recovery evidence, not a throughput or equal-wire result.

### Raw QUIC handshake fault recovery versus quic-go

```sh
zig build interop-quic-handshake-fault -Doptimize=ReleaseFast
```

The gate runs 16 authenticated cases: QUIC v1/v2, both netz/client and
netz/server role pairings, both client- and server-outbound handshake
directions, and either one forced first-datagram loss or one last-ciphertext-bit
corruption. The unprivileged relay disarms after exactly one fault. Its strict
verifier cross-checks direction, implementation scope, version, and counters,
then requires both peer logs to prove certificate validation, `hq-interop`, two
exact streams, 10 echoed bytes, and application close.
The quic-go sides are the repository-owned `raw_echo_server` and
`raw_echo_client` commands in `tools/interop/quic_go_module`, pinned to quic-go
v0.59.0 by `go.mod` and `go.sum`. The runner selects a local Go toolchain and
builds them with `GOTOOLCHAIN=local` and `-mod=readonly`, so this gate no longer
borrows peer source or module metadata from a mutable `~/Work` checkout.

The first real client-loss run exposed a gap hidden by same-library injection:
netz split its post-quantum ClientHello across two 1200-byte Initial datagrams.
After offset zero was lost, quic-go ACKed the surviving suffix; netz accepted
that ACK-only Initial as handshake progress and stopped retransmitting the
ClientHello. The response filter now authenticates candidate Initials and
requires non-empty CRYPTO offset zero before leaving the PTO loop. Direct wire
tests reject ACK-only and suffix-only Initials and accept the offset-zero form.
All 16 external cases and the pre-existing complete quic-go lifecycle
matrix pass after the fix. This is deterministic recovery evidence, not a
performance or equal-wire result.

The complete `interop-quic-quic-go` lifecycle matrix is now self-contained as
well. Its repository-owned `lifecycle_client` and extended `raw_echo_server`
cover 19 process scenarios: v1/v2 echo, Retry and two key updates, reset/stop,
flow-control and stream-credit renewal, unidirectional streams, Initial and
application PTO recovery, exact application close, two-hop active migration
with and without a dropped probe response, and same-IP NAT rebinding. During
the migration-loss conversion, a delayed duplicate PATH_RESPONSE exposed an
over-strict netz receive path. Netz now ignores responses that do not match an
outstanding challenge, as Quinn, quiche, and tquic do, while retaining same-
packet STREAM processing; encrypted regression coverage locks that behavior.

The same harness accepts `--stats` for process and allocator memory evidence:

```sh
zig build bench-quic-quic-go -Doptimize=ReleaseFast -- \
  --warmup=1 --iterations=3 --bytes-per-stream=4194304 \
  --chunk-bytes=16384 --stream-window=1048576 --stats
```

GNU time measures whole-process maximum resident set size for every client and
server process. This is the directly comparable cross-language metric. Netz
also wraps its explicit allocator and requires zero live bytes after teardown;
quic-go reports `runtime.MemStats` heap counters. Allocation counts, cumulative
allocated bytes, netz peak-live bytes, and Go `HeapSys` are implementation- and
runtime-specific diagnostics and are therefore not divided into cross-language
ratios. The three-measured-connection run above produced:

| Streams | Implementation workload | Process peak RSS (KiB) | Runtime allocation count | Runtime allocated bytes | Runtime peak/reserved bytes |
|---:|---|---:|---:|---:|---:|
| 1 | netz sender | 9,248-9,336 | 9,190-12,053 | 29,914,732-32,383,622 | peak live 6,301,599-6,304,088 |
| 1 | netz receiver | 3,328-3,584 | 318-341 | 1,579,928-1,603,277 | peak live 319,319-321,809 |
| 1 | quic-go sender | 26,368-26,624 | 103,129-103,674 | 29,403,816-30,041,488 | ending HeapSys 20,676,608-20,709,376 |
| 1 | quic-go receiver | 10,752-11,008 | 56,668-60,240 | 2,274,320-2,515,000 | ending HeapSys 3,932,160 |
| 4 | netz sender | 27,440-27,608 | 41,224-67,016 | 129,347,669-160,471,876 | peak live 24,982,425-25,000,639 |
| 4 | netz receiver | 6,908-7,212 | 362-393 | 12,100,091-12,331,038 | peak live 3,128,072-3,171,815 |
| 4 | quic-go sender | 51,332-51,456 | 402,043-406,112 | 106,536,616-107,394,072 | ending HeapSys 54,165,504-54,198,272 |
| 4 | quic-go receiver | 13,312-19,968 | 265,700-301,569 | 11,257,960-19,460,168 | ending HeapSys 8,060,928-12,255,232 |

Each range combines the two endpoint-role placements for that sender/receiver
workload. The verifier required all 16 process records, positive RSS and
runtime counters, the expected allocator scope, and `live_bytes=0` for every
netz process. `--stats` is opt-in: default throughput runs do not instantiate
the counting allocator, call Go `ReadMemStats`, or launch through GNU time.

This comparison intentionally disables GSO/GRO. The host clamps
`net.core.rmem_max` to 212,992 bytes, so a same-process multi-packet burst can
overflow the effective UDP receive queue and create artificial loss. The
benchmark defaults to one submitted packet per userspace batch while retaining
`--batch-packets` for tuned hosts. Dedicated GSO/GRO benchmarks remain the
evidence for coalesced I/O performance.

The transport changes supporting this run are not benchmark-only shortcuts:
STREAM packet validation now borrows existing receive state instead of cloning
the retained body, applications can borrow and incrementally consume
contiguous STREAM data without allocation, and ACK-driven packet-threshold
losses can be retransmitted in a bounded drain before waiting for PTO.

WebTransport incremental and whole-stream pollers enumerate active QUIC receive
stream IDs through `receivedStreamIdsAfterInto`. The stable pagination contract
must survive swap-removal, but the common transport layout appends increasing
stream IDs. An ordered-tail fast path now appends those IDs directly and falls
back to the existing bounded insertion sort only after reclamation has made the
physical table unordered. The dedicated public-API microbenchmark uses 64
active receive streams and validates every sorted ID on every iteration:

```sh
taskset -c 0 zig build bench-quic-stream-ids -Doptimize=ReleaseFast -- \
  --iterations=2000000
```

Ten alternating fixed-binary pairs measured 1,083.82-1,085.17 ns/enumeration
before and 97.56-97.76 ns/enumeration after, with checksum 16,384,000,000 in
every run. Median cost fell from 1,084.55 to 97.64 ns (91.0%, 11.1x). The
ordinary one-stream WebTransport throughput guard moved only +0.17% in median,
while the 64-stream end-to-end benchmark remained dominated by a host UDP
queue bimodality and moved about -1.0% in median. Therefore this is recorded as
a verified stream-enumeration CPU reduction, not an end-to-end throughput
claim. Existing pagination tests continue to remove a stream between pages and
require the remaining IDs in order, covering the unordered fallback.

### Raw QUIC TLS 1.3 handshake latency, rate, and memory

A 2026-11-19 in-process `--mode=handshake --iterations=100 --stats` run at the
current head recorded 8,101 allocations and 38,357,402 bytes for 100 handshakes
(81.01 allocations and 383,574 bytes per connection), with 2,892.9 conn/s and
p50 318.5 us. The two largest per-connection allocations are one >64-KiB
allocation (~230,096 bytes) and one <=64-KiB allocation (65,536 bytes). The
historical ~57-allocations/connection figure came from a different harness and
is not reproduced by the current `--stats` measurement; this is a baseline for
future pre-trust allocation work, not a regression claim. Rows are in
`docs/evidence/quic_handshake_allocations/2026-11-19.json`.

A follow-up attribution pass recorded caller return addresses for allocations
of at least 64 KiB (`--capture-large=65536`) and resolved them with
`addr2line`. Both the 65,536-byte and 230,096-byte per-connection allocations
came from `acceptInternal` preparing a zlib certificate compressor
(`Prepared.initZlib`) for a 65-byte test certificate whose compressed form
cannot pay for RFC 8879's 12-byte framing. `ServerOptions` now accepts
caller-prepared `PreparedView`s, and the benchmark prepares one zlib view once
per process. A prepared entry that matches the configured Certificate message
is authoritative for its algorithm, so the handshake skips both the
per-connection deflate window and the compressor state when compression cannot
save bytes. In the same fixed binary, prepared reuse measured 7,701
allocations and 8,770,970 bytes (77.01 allocations / 87,710 bytes per
connection) with p50 218.6 us and 3,662.1 conn/s, versus 8,101 allocations and
38,357,340 bytes (81.01 / 383,573) with p50 309.8 us and 2,730.3 conn/s under
`--no-prepared-compression`. Rows are in
`docs/evidence/quic_handshake_allocations/2026-11-19-prepared-certificate-compression.json`.

The established-connection scratch regions are fixed packet and ACK buffers,
so the next pass replaced their geometric `ArrayList` growth with precise
capacities. Allocation count stayed at 7,701, while three runs measured
7,723,400-7,723,522 bytes (77,234 bytes per connection, 11.9% below the
prepared-reuse rows) with p50 222.1 us and 4,028.3 conn/s; the timing move is
noise-level, so only the allocation reduction is claimed. Rows are in
`docs/evidence/quic_handshake_allocations/2026-11-19-scratch-capacity.json`.

The default client offers brotli before zlib, so a zlib-only prepared view
still let every handshake run on-demand brotli and zstd preparation. The
benchmark now prepares all three default server algorithms once per process.
Three runs measured 5,801 allocations (58.01 per connection), 6,676,706 bytes
(66,767 per connection), p50 191.6 us, and 4,643.6 conn/s. Against the
original on-demand baseline that is -82.6% allocated bytes and -38.2% p50;
against the scratch-only rows it removes 19 allocations and 10,467 bytes per
connection. Rows are in
`docs/evidence/quic_handshake_allocations/2026-11-19-prepared-all-algorithms.json`.

The cross-process counterpart uses a long-running server and a fresh client
UDP endpoint plus full handshake for every sample:

```sh
zig build bench-quic-handshake-external -Doptimize=ReleaseFast
zig build bench-quic-handshake-external -Doptimize=ReleaseFast -- --netz-only
```

Both processes are pinned to distinct CPUs. Each run performs 10 untimed warmup
connections followed by 100 measured connections, repeated five times with
reversed role-pair order on alternating runs. TLS is fixed to QUIC v1, X25519,
TLS_AES_128_GCM_SHA256, and verified localhost certificates. Only the client
`connect`/`Dial` call is timed; endpoint creation, a round-indexed 16-byte
echo, application close, and teardown remain outside. Accordingly the reported
rate is explicitly `connects_per_second_from_timed_sum`, not whole-process
connection throughput. The quic-go client/server executable and its tests live
in the same repository-owned v0.59.0 module as the HTTP/3 and raw-stream peers.
The strict verifier reconstructs every total and
percentile from 100 sample records and requires a matching server completion
record for all 110 connections, 3,520 echoed bytes, checksum 5,995, and peer
close.
This benchmark's quic-go executable and unit tests are also built from
`tools/interop/quic_go_module` with `GOTOOLCHAIN=local` and
`-mod=readonly`. The full lifecycle and handshake-fault gates now use the
repository-owned raw peer commands described above as well.

The pinned Quinn revision
`d9c8c4c695fc64292d9b117844ea6924ca0d0815` now provides the same executable
four-role matrix when the audited quic-go fixture is unavailable:

```sh
zig build bench-quic-handshake-quinn -Doptimize=ReleaseFast -- \
  --samples=5 --warmup=10 --iterations=100
zig build bench-quic-handshake-quinn -Doptimize=ReleaseFast -- \
  --samples=5 --warmup=10 --iterations=100 \
  --netz-prepared-p256=enabled
```

Both stacks are restricted to QUIC v1, TLS 1.3, X25519,
TLS_AES_128_GCM_SHA256, certificate verification, and disabled TLS resumption.
The runner hashes the fixed ReleaseFast netz/Quinn binaries and Quinn lockfile,
pins clients and servers to separate CPUs (the first two available by default),
and uses odd ABBA-ordered samples. A
strict matrix verifier checks that order plus every raw handshake sample,
aggregate, server completion, runtime identity, echo byte/checksum, and close.
The client keeps its fresh endpoint alive for 20 ms after the untimed echo and
100 ms after the final connection so the long-running peer observes the
already-submitted CONNECTION_CLOSE; neither grace interval enters the
connect-only timing.

The Quinn matrix now generates one CA-signed P-256 leaf and supplies the exact
same leaf and private scalar to both server implementations. The environment
record includes its DER length and SHA-256, and every client sample records UDP
datagrams/bytes at connect completion. This removes the earlier comparison's
self-signed 308-byte netz identity versus CA-signed roughly 468-byte Quinn
identity confounder. With the shared identity, both clients receive one
1,200-byte server datagram against Quinn; netz returns after two client
datagrams/1,283 bytes, while Quinn returns after three/2,538 bytes. These are
userspace UDP counters, not kernel packet capture, but they exclude extra netz
receive scheduling as the source of the fixed-Quinn-server gap.

Client-side phase timing around the production trust callback measured a
representative nine-connection median split of 0.94 ms before trust, 1.31 ms
inside X.509 path verification, and 0.94 ms after trust. The dominant repeated
operation was therefore the unchanged leaf-to-CA signature verification.
`tls.trust_cache.BundleVerifierCache` is now an opt-in, caller-owned, bounded
cache for clients that intentionally retain one trust bundle and verification
time snapshot across connections. Its SHA-256 key covers the exact server name,
chain count, and length-delimited DER bytes; only successful path checks are
cached, and TLS CertificateVerify still runs for every handshake. The Quinn
benchmark uses 64 caller-provided entries and requires one cold miss followed
by hits for every remaining connection.

A same-binary, CPU-7/client and CPU-13/server, five-pair ABBA run against a
fixed Quinn server measured the uncached path at 2.283 ms P50, 9.280 ms P99,
and 376.0 connects/s from the median timed sum. The cached path measured 1.709
ms, 6.757 ms, and 508.2 connects/s: 25.1% lower P50 and 35.2% higher derived
rate. The P99 improvement is retained as local evidence only because this host
has unrelated scheduler load.

The final shared-identity 5 x 100 matrix used netz SHA-256
`58c4fc0e50db7e57ee4e6f86d98136c2c03d2bb77fadea4508790d454c3f0666`
and Quinn SHA-256
`cd14eca7908d20123d4c822c71e1d5ca09037dfc5109688361f80dbe347ef4cd`:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + Quinn server | 1.679 ms | 8.312 ms | 550.3 |
| Quinn client + Quinn server | 1.311 ms | 3.175 ms | 738.8 |
| Quinn client + netz server | 2.272 ms | 8.013 ms | 406.6 |
| netz client + netz server | 2.055 ms | 4.462 ms | 455.8 |

Against the fixed Quinn server, the remaining netz-client P50 gap is 28.0%
(0.781x); against the fixed netz server, netz is 9.5% lower at P50 (1.105x).
The direction still depends on the server. This matrix is now equal in server
certificate bytes but remains same-security-policy rather than equal-wire: the
client packetization differs materially, as the UDP counters above show.

The next client CPU pass replaced five overlapping whole-transcript hashes with
one negotiated incremental transcript state plus cheap boundary snapshots. It
retains the exact TLS ordering for authenticated, PSK, client-certificate,
SHA-384, and SM3 paths; focused tests compare every snapshot against the former
one-shot construction. A fixed-Quinn-server 5x100 ABBA run compared the already
published cache baseline binary
`36f290466c5d7fc37c4baf05137dd584ab28a8c4f7b08ed4855f3cf663e8d5dd`
with the incremental binary
`07ed8888345aaf0b9fcb2b996d5470529855fc558d3b96b85a6964c66b759853`.
Median P50 fell from 1.586 to 1.275 ms (19.6%, four of five paired wins),
median timed-sum rate rose from 615.7 to 730.2 connects/s (18.6%), and median
P99 moved from 4.360 to 3.110 ms. The tail result remains local evidence on
this loaded host.

The final post-change shared-identity 5x100 matrix on the same CPUs used netz
SHA-256
`07ed8888345aaf0b9fcb2b996d5470529855fc558d3b96b85a6964c66b759853`
and Quinn SHA-256
`cd14eca7908d20123d4c822c71e1d5ca09037dfc5109688361f80dbe347ef4cd`:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + Quinn server | 1.136 ms | 3.797 ms | 765.8 |
| Quinn client + Quinn server | 1.051 ms | 4.628 ms | 834.1 |
| Quinn client + netz server | 1.270 ms | 6.357 ms | 675.2 |
| netz client + netz server | 1.617 ms | 3.781 ms | 593.1 |

Against the fixed Quinn server, netz is now 8.1% higher at P50 (0.925x), down
from the prior matrix's 28.0% gap. The fixed-netz-server direction measured
netz at 0.785x in this run, reinforcing that whole-pair scheduling and server
behavior still prevent an isolated client ranking. All four pairs retained the
same median connect-time UDP datagram and byte counts as before the transcript
change.

The server now uses the same incremental transcript owner. In addition to
removing its overlapping hashes, this corrected the authenticated-client
application-secret boundary to the server Finished, as required by TLS 1.3; a
P-384 mTLS test now exchanges protected STREAM data after both identities are
verified, where it previously checked only metadata. A fixed-Quinn-client
5x100 ABBA compared client-only incremental binary
`07ed8888345aaf0b9fcb2b996d5470529855fc558d3b96b85a6964c66b759853`
with both-role incremental binary
`58ad398e697d727bf32ec4a0e01df7b2a20e9eab25bcd134ccc6ada0d37d3868`.
Median P50 moved from 2.234 to 2.140 ms (4.2%, three of five paired wins),
while median timed-sum rate moved from 395.4 to 390.8 connects/s. These
conflicting small changes are treated as performance-neutral; the retained
benefit is less duplicate work and the corrected mTLS traffic-secret boundary.
The final both-role incremental 5x100 matrix used netz SHA-256
`58ad398e697d727bf32ec4a0e01df7b2a20e9eab25bcd134ccc6ada0d37d3868`: fixed
Quinn server measured netz/Quinn at 1.618/1.357 ms P50 (netz 0.839x), while
fixed netz server measured 1.972/2.201 ms (netz 1.116x). The higher absolute
latencies than the immediately preceding run demonstrate host-load sensitivity;
the same-binary A/B above remains the attribution evidence.

The QUIC client now routes server CertificateVerify through the configured
`ClientVerifier`, so its existing caller-owned prepared Ed25519, P-256, and RSA
hooks are effective for QUIC as well as ordinary TLS. The Quinn runner exposes
this explicitly as `--netz-prepared-p256=enabled`: it builds one P-256 public
table from the fixed leaf before the timed loop, records the mode in every
sample and aggregate, and still performs ordinary X.509 path verification plus
a per-handshake exact public-key match before using the table. A mismatched
prepared table fails the integrated handshake with `InvalidCertificate`.

A 2026-10-15 CPU-0/client, CPU-1/server block ABBA used one ReleaseFast netz
binary (`575e14df1baf81abffb69805edea6bcde746499659afb4945c4f6f1efe8a9f8c`)
and pinned Quinn
`d9c8c4c695fc64292d9b117844ea6924ca0d0815`. Each
fresh/prepared/prepared/fresh block contained three odd-order samples, ten
warmups, and thirty measured fresh connections per role pair. Against the
fixed Quinn server, the first adjacent pair moved netz P50 from 765.724 to
599.507 us (21.7% lower), and the reverse-order pair moved from 589.814 us
fresh to 470.333 us prepared (20.3% lower). The corresponding post-trust
medians, which include CertificateVerify, fell 229.689 to 116.553 us and
198.246 to 96.276 us (49.3% and 51.4%). Against the fixed netz server, the two
prepared reductions were 27.2% and 15.8%. In both prepared blocks the complete
netz-client/Quinn-server P50 was lower than the same-block Quinn client by
5.3% and 12.1%. The different blocks generated different but equivalent
CA-signed P-256 leaves, so the two mirrored directions are the causal evidence;
the absolute cross-block values remain host-load-sensitive, same-security-policy
results rather than an equal-wire or universal client ranking.

The prepared-P256 profile then isolated the next client CPU costs instead of
guessing from complete-process latency. A 500-connection fixed-Quinn-server run
measured 412.062 us P50 with 325.628 us before trust, 0.630 us in the cached
trust callback, and 83.851 us after trust. `perf record -F 1999 -e cycles:u`
captured 6,496 samples with zero loss; filtering the unique netz-client PID
left 368 call-chain samples. X25519 arbitrary-point multiplication accounted
for 21.9%, while fixed-base public-key recovery's inversion, additions, and
constant-time table selections accounted for roughly another 14--15%.
Packet protection, transport-parameter parsing, and the remaining key-schedule
entries were individually below 3%.

Published Vail `2317957` therefore gives portable X25519 public-key recovery a
dedicated five-group/four-column/13-window table, while its prepared Ed25519
verifier retains the original four-group/five-column table. This avoids the
13% prepared-Ed25519 regression found when the table was initially shared.
Eight CPU-0 fixed-binary microbenchmark arms reduced X25519 public-key recovery
from a 26,096 ns midpoint median to 19,287.5 ns (26.1%, every arm faster). An
independent 5,000-iteration in-memory TLS client handshake ABBA reduced the
midpoint median from 109,244.5 to 101,980 ns (6.65%, every arm faster) with
identical ClientHello/server-flight/Finished sizes and checksums. The
representative benchmark ELF `.text` also fell from 2,999,624 to 2,961,696
bytes. A corresponding cross-process Quinn block run moved in opposite
directions under host load, so it is retained only as a passing interop/control
gate and not used to claim an end-to-end latency gain. Same-host AWS-LC
microbenchmarks still leave concrete ARM64 targets: about 9,915 versus 19,290
ns for public-key recovery and 41,210 versus 49,460 ns for the shared secret.

Published Vail `89d6292` closes the measured variable-base gap with an embedded
Linux ARM64 ReleaseFast/ReleaseSafe ladder derived from the formally verified
s2n-bignum schedule. It masks the peer's high bit, clamps the scalar, uses a
fixed 251-step ladder plus three final doublings and constant-schedule
inversion, then clears its complete 320-byte secret stack and caller-saved GPRs.
Debug and ReleaseSmall retain the portable implementation. ReleaseFast and
ReleaseSafe RFC 7748, 1,000-step iterated, boundary, and 4,096 deterministic
arbitrary-point differential cases all matched Zig std, including all-zero
rejection. Disassembly separately confirmed all twenty 16-byte zero stores and
x0--x17 clearing before the callee-saved register restore.

Eight CPU-0 fixed-binary ABBA arms reduced the shared-secret midpoint median
from 97,889 to 56,310 ns under the same throttled window (42.5%, every candidate
arm faster); unthrottled samples moved 48,818 to about 28,100 ns with the same
ratio. The latter is about 31.8% below the same-host AWS-LC 41,210 ns reference.
A separate 5,000-iteration in-memory TLS client handshake ABBA reduced the
midpoint median from 102,013 to 80,991.5 ns (20.6%, every candidate arm faster)
with identical wire lengths and checksum. A zero-loss 997-Hz profile attributed
94.4% of 2,828 samples to the fixed ladder loop, 5.4% to inversion, and only
0.2% to the wrapper, all-zero check, and explicit clearing. Primitive/TLS
benchmark ELF `.text` increased by 4,152/9,428 bytes. The matching
portable/ARM64 netz benchmark hashes were
`afd5ddca976d88236c62076fb394e341b0a862461fb045c00f74197f7ac69924`
and `aa036f0c66426b7463f509c0f2101380fff83c4cc1cc3fe8c5f796fb0dd53c3e`.
Their cross-process Quinn blocks again moved with host load rather than in a
stable old/new direction, so the strict four-role matrices remain passing
interop controls and do not support an end-to-end latency claim.

Published Vail `8571f55` adds the companion s2n-bignum-derived ARM64 fixed-base
kernel and its 48,576-byte affine table. It consumes 63 signed four-bit windows
with constant-time selection, performs constant-schedule projection/inversion,
then clears the complete 448-byte secret stack and x0--x17. Debug and
ReleaseSmall retain the 11.25 KiB portable table. ReleaseFast/ReleaseSafe RFC
7748, iterated, boundary, and 4,096 deterministic public-key differential cases
matched Zig std; disassembly confirmed all twenty-eight 16-byte zero stores and
register clearing before return.

Eight CPU-0 fixed-binary ABBA arms reduced public-key recovery from a 19,289.5
ns midpoint median to 7,829 ns (59.4%, every candidate arm faster), about 21.0%
below the same-host AWS-LC 9,915 ns reference. A 5,000-iteration in-memory TLS
client handshake ABBA reduced 81,138 to 69,570.5 ns (14.3%, every candidate arm
faster) with identical wire lengths and checksum. A zero-loss 997-Hz profile
attributed 81.9% of 800 samples to the fixed-window loop and 18.1% to inversion;
the wrapper and clearing were below the reporting threshold. Primitive/TLS
benchmark ELF `.text` increased by 17,816/55,900 bytes. The matching netz
baseline/candidate hashes were
`aa036f0c66426b7463f509c0f2101380fff83c4cc1cc3fe8c5f796fb0dd53c3e`
and `b13d01c01518c277395b38ebbed3d8addd4d667faa2a8b8455352529dd8281da`.
Two mirrored fixed-Quinn-server blocks reduced complete netz-client P50 by 0.4%
and 4.9% even though Quinn's controls were slower in both candidate blocks.
This is bounded supporting evidence for the tested workload, not a universal
cross-stack latency claim.

The next handshake pass removed a value-movement artifact rather than changing
cryptography or the timed boundary. `EstablishedConnection` is 9,328 bytes on
this 64-bit build, of which the embedded one-RTT `Connection` is 9,016 bytes.
The client and server previously constructed that value, performed their
coalesced 1-RTT and accepted/rejected 0-RTT transitions, and returned it again.
Those transitions now share the typed
`src/quic/handshake/established_promotion.zig` ownership boundary and execute
before the first return. ReleaseFast disassembly of fixed binary
`b13d01c01518c277395b38ebbed3d8addd4d667faa2a8b8455352529dd8281da`
versus candidate
`9055a6b20d5aec722ef4935b94d0c8233c6a82c3221214e6ce73847de2373648`
removed all three explicit 9,328-byte `memcpy` calls from both
`connectAttempt` and `acceptInternal`. Their fixed stack reservations fell
82,288 to 63,824 bytes and 94,512 to 75,984 bytes respectively (excluding the
unchanged prologue and server scalable-vector slot), while benchmark ELF
`.text` fell 3,776,943 to 3,774,239 bytes.

Debug and ReleaseFast focused library gates cover ordinary authenticated
handshakes, preconfigured state, coalesced packets, and the complete accepted,
rejected, retransmitted, socket-rejected, Retry, Version Negotiation, and replay
0-RTT matrix. The strict four-role Quinn smoke verified the expected checksums
and median UDP packet/byte shapes. Eight same-certificate fixed-Quinn-server
short blocks used old/new/new/old/new/old/old/new order on CPU 0/1, with ten
warmups and 100 measured connections. The candidate won all four adjacent
mirrored P50 pairs by 22.4%, 16.4%, 5.9%, and 3.6%; aggregate client
instructions had a 112.183M
baseline versus 112.044M candidate midpoint median (0.12% lower, three of four
paired wins). Longer blocks and earlier cross-process blocks moved with host
frequency/load, including one same-certificate long run in the opposite
direction. The retained causal claim is therefore the eliminated copies,
smaller stack/code, and modest instruction reduction; the full-handshake P50
movement remains supporting rather than universal evidence.

A follow-up keeps the ordinary value-returning one-RTT initializer but adds a
caller-storage form for the integrated handshake. Its allocation, prepared-key,
receive-scratch, connection-ID, random-generator, and preferred-address
ownership all roll back through the completed output object after ownership is
transferred; an exhaustive allocation-failure test covers that boundary.
ReleaseFast disassembly of baseline
`9055a6b20d5aec722ef4935b94d0c8233c6a82c3221214e6ce73847de2373648`
and candidate
`a1af6ddfd3afb982f88dc8c52754000f48e900c0b80521f9999e99e4adf6334e`
reduced the 9,016-byte copies inside `establishedConnection` from three to one
and its fixed stack reservation from 35,696 to 17,968 bytes (49.7%). The one
remaining copy installs the finished `Connection` in the public value-returned
`EstablishedConnection`; benchmark ELF `.text` increased by only 164 bytes.

Eight same-certificate short blocks used the same mirrored order and counts as
the preceding pass. Aggregate instructions fell in all four candidate pairs;
the midpoint median moved 111.872M to 111.781M (0.08%). Complete-handshake P50
won three pairs but lost the fourth, and the four-block midpoint moved 381.536
to 386.555 us, so no full-handshake latency gain is claimed. Independent
500-connection profiles passed exact wire/checksum validation and no longer
attributed a sampled large-copy path directly to `establishedConnection`, but
their absolute 388.634/370.013 us P50 movement remains host-load-sensitive.
The retained result is the exact copy-count, stack, ownership, and instruction
improvement.

The next allocation pass follows Quinn and tquic's inline connection-ID
ownership and quiche's borrowed-header approach without changing Netz's public
slice fields. Initial, Handshake, and 0-RTT open now retain their one mutable
protected-packet copy, remove header protection and AEAD in place, and expose
DCID, SCID, token, and plaintext slices into that single owned allocation.
The former payload allocation plus independent CID/token duplicates are gone.
Focused tests require exactly one allocation for every long-packet open, verify
that every returned slice lies inside the retained storage, cover all three
packet types, and force fail-first OOM on each API.

A CPU-0 100-connection authenticated two-endpoint allocation pair used
baseline binary
`d2bf2c5c1bbe5f237c5ef2bd265260a4f5571ffb22cd96718efbf45bbd526193`
and candidate
`1bc8ad59b6e817c6b3ab3ff0ce8cdaf237f83bca2fbb7f07f3437dc6f7ae0837`.
Allocation calls fell from 7,901 to 6,401, exactly 15 fewer per connection
(19.0%); cumulative requested bytes fell 7,472,185 to 7,083,159 (5.2%). Both
runs ended at zero live bytes, peak live storage remained neutral at
56,155/56,213 bytes, and benchmark ELF `.text` fell by 1,496 bytes. The
largest stable 8,900-byte allocations remain the client/server handshake
receive buffers that transfer directly into established one-RTT scratch.

Twenty fixed-binary 1,000-connection blocks formed ten adjacent mirrored
pairs. Candidate P50 and derived rate improved in all ten pairs. Their midpoint
medians moved 577.088 to 575.524 us (0.27% lower) and 1,633.1 to 1,637.0
connections/s (0.24% higher); P99 was effectively neutral at 687.571 versus
688.497 us. This supports a small bounded handshake gain alongside the exact
allocation reduction, not a general cross-stack latency claim.

Five remaining 182-byte allocation sites were then resolved by conditional
breakpoints: server Finished, client Finished, the assembled client flight, and
the CRYPTO reassembler's data/presence arrays. Finished now has a 52-byte
caller-buffer encoder covering SHA-256, SHA-384, and SM3. The server writes its
Finished directly into the existing flight; an unauthenticated client sends
the stack-encoded Finished directly, while mTLS retains one exact-capacity
owned fallback for Certificate plus CertificateVerify plus Finished. SHA-384
caller-buffer equivalence, short-buffer rejection, ordinary handshakes, and
mutual TLS protected-data exchange cover both branches. The two reassembler
allocations remain for a separate lifecycle change.

A CPU-0 100-connection allocation pair reduced calls from 6,401 to 6,101,
exactly three per connection (4.7%), cumulative bytes from 7,083,159 to
7,028,594 (0.77%), and peak live bytes from 56,213 to 56,031; both runs ended
at zero live bytes. Fixed binaries were
`1bc8ad59b6e817c6b3ab3ff0ce8cdaf237f83bca2fbb7f07f3437dc6f7ae0837`
and
`ea16bad1d60ebcebe117e4d5756ca4dbeeb4cff614c62ed17a8c95e6f37e26bd`;
benchmark ELF `.text` fell by 1,812 bytes. Twenty 1,000-connection blocks
formed ten mirrored pairs: candidate P50 improved in nine, with a 576.338 to
575.273 us midpoint median (0.18%). Rate won six pairs and P99 moved in both
directions, so only the exact allocation/code reduction and bounded P50 support
are retained.

CRYPTO reassembly now reuses the STREAM receive bitmap's proven representation:
an ordered prefix is implicit and consumes no presence allocation, while the
first gap materializes packed machine words. Contiguous appends and matching
overlap extensions stay implicit; retransmitted bytes are still compared before
overwrite, sparse fills retain exact conflict detection, and buffer/bitmap
capacity is reserved transactionally before either logical length changes.
Focused regressions run the ordered path under a fail-first allocator, force
gap-materialization OOM and retry, fill that gap, and retain the existing
out-of-order/conflicting-data model coverage.

An exact clean-`f06ca41e` baseline binary
`23af254c95614aa8fb21393d1fd3a43c64657db87595694ee53926ec10315c42`
and candidate
`8316ef6ac7466204decff6bb69e8f545b167ce877623c5a0bda9005780220a4b`
reduced a 100-connection run from 6,101 to 5,701 allocations, exactly four per
connection (6.6%), and cumulative bytes from 7,028,594 to 6,873,454 (2.2%).
Both ended at zero live bytes with the same 56,031-byte peak, and benchmark ELF
`.text` changed by only -20 bytes. Forty fixed-binary 1,000-connection blocks
formed twenty mirrored pairs: P50 won 10/20 and rate 9/20; pair midpoint ratios
were 1.0002 and 0.9995. Complete-handshake timing is therefore neutral, while
the allocation and sparse-state reductions are deterministic.

Published Vail `73e2a4c` then replaces the remaining portable ARM64 P-256
Montgomery field multiply/square operations in ReleaseFast and ReleaseSafe
with fixed `s2n-bignum` kernels pinned to upstream commit
`4d1356a7470663c752660a59375dc3a9ef548428`. Debug and ReleaseSmall retain the
portable Zig path. Both optimized modes passed the P-256 differential and
verifier gates, the complete Vail suite passed, and the x86_64 ReleaseFast
compile gate confirmed that the ARM64 assembly did not leak into other targets.
Eight CPU-0 fixed-binary prepared-verifier pairs all favored the candidate:
the midpoint median fell from 35,642 to 29,458 ns/verify (17.4%), with a
0.82597 median paired ratio. Prepared-table construction, which stays outside
the online handshake timer and is reused by the caller, fell from 923,607.5 to
728,520.5 ns (21.1%). The candidate's 29,533 ns smoke result was 40.0% below
the same-host AWS-LC parsed-verifier result of 49,135 ns. The representative
prepared-verifier ELF `.text` grew from 640,784 to 645,864 bytes (+5,080).

The corresponding fixed-Quinn-server netz-client comparison used baseline
SHA-256
`17d408bc8e524ff38655533a79a997f94a4d433ea856913c2a928c1774ed4526`
and candidate
`0e4a9fcb160ccf0c8500a63652381458b95eed7f5350a09b847a611b3fb7fb94`.
Across eight mirrored pairs, client instructions fell in every pair with a
0.913918 median paired ratio (8.6%), and the post-trust interval likewise fell
in every pair with a 0.875768 ratio (12.4%). Complete-handshake P50 won only
five pairs, with a 0.977508 ratio (2.25%), so that movement is bounded support
rather than a general latency claim. The handshake benchmark ELF `.text` grew
from 3,770,543 to 3,778,711 bytes (+8,168). A fixed Quinn-client/netz-server
control left server instructions near 383.12M and effectively unchanged; the
prepared verifier is therefore not presented as a signer optimization.

A post-candidate 1,000-connection netz-client profile recorded 1,000 samples
with none lost. Host load inflated its 7.532 ms P99, so the 399.446 us P50 is
not used as an absolute A/B claim. The profile is still useful for call-path
ordering: the former portable field-multiply hotspot disappeared, while
`doubleScalarMulComb` accounted for 14.72%, the ARM64 Montgomery multiply
kernel 4.13%, public-scalar inversion 2.52%, and the X25519 variable/fixed
loops 14.52%/3.71%. Compared with the preceding profile's approximately 27.8%
prepared P-256 total and 17.1%/4.2% X25519 loops, field multiplication is no
longer the dominant P-256 target. The next cryptographic work should therefore
measure the public comb/add/double and inversion paths alongside X25519 rather
than further tuning handshake allocation or key-schedule sites already down
near 1--2%.

Published Vail `040193a` then moves the public prepared verifier's complete
Montgomery-Jacobian doubling and mixed-add formulas onto the matching ARM64
`s2n-bignum` schedules from the same pinned upstream revision. The mixed-add
wrapper preserves identity inputs and distinguishes its exceptional equal-point
identity result from the correct inverse-point identity before dispatching to
the dedicated doubling kernel. ReleaseFast/ReleaseSafe focused tests cover
identity, equal, inverse, and 64 deterministic double-scalar comparisons against
Zig std; Debug/ReleaseSmall retain the portable formulas. The complete Debug
and ReleaseFast Vail suites and the x86_64 Linux ReleaseFast compile gate pass.

Eight CPU-0 fixed-binary prepared-verifier pairs used published field-only
baseline SHA-256
`9530cf582fdf8884709a0addb6451bd0db88116faee4d6d2d8ade25c0e348b07`
and point-kernel candidate
`259cccb3e8e5f9986b6caccadc7e284eaa04654bdcc338942d2ccd56cba2cb94`.
Every pair favored the candidate: the midpoint median fell from 29,531 to
17,808.5 ns/verify (39.70%), with a 0.603439 median paired ratio. Preparation,
which remains outside the online timer and reusable by the caller, fell from
728,880.5 to 675,097 ns (7.38%, 8/8 wins). The candidate is 63.75% below the
same-host 49,135 ns AWS-LC parsed-verifier reference, or about 2.76x its
throughput. Replacing repeatedly inlined formulas also reduced the prepared
benchmark's GNU `size` text total from 645,864 to 554,200 bytes (-91,664).

The corresponding same-certificate fixed-Quinn-server client comparison used
netz baseline SHA-256
`0e4a9fcb160ccf0c8500a63652381458b95eed7f5350a09b847a611b3fb7fb94`
and candidate
`e555bd546538f2c5fca8e09d764b6f306cf6c6c42004327da67df97e32d74986`.
Across eight mirrored 100-connection pairs, client instructions fell in every
pair with a 0.899752 median paired ratio (10.02%). Complete P50 won six pairs
with a 0.917684 ratio (8.23%), while timed sums won only five pairs despite a
0.896965 median ratio. Host-load excursions reached both sides of the matrix,
so only the instruction reduction is treated as causal and the complete timing
as bounded support. All arms verified 110 connections including warmup, exact
echo checksum 5,995, certificate validation, and peer close. The candidate also
passed the complete four-role Quinn smoke. Its GNU `size` text total fell from
3,778,711 to 3,652,163 bytes (-126,548), rather than paying a whole-binary code
size increase for the dedicated schedules.

A zero-loss 1,000-connection candidate profile recorded 296 samples and a
407.051 us P50; its 3.101 ms P99 remains load-sensitive. The former 14.72%
`doubleScalarMulComb` hotspot is gone. The new ordering is the X25519 variable
and fixed loops at 18.67%/3.68%, the complete P-256 prepared-verifier body at
8.76%, ARM64 P-256 mixed-add at 4.08%, and point doubling at 0.42%. The next
crypto pass should therefore re-audit public scalar inversion and the residual
prepared-verifier body, but X25519 and non-crypto handshake work now outrank
P-256 doubling; further point-kernel work needs a newly isolated hotspot.

The next handshake allocation pass targets typed QUIC transport-parameter
duplicate detection. The former parser first scanned the complete extension to
count parameters, allocated one `u64` entry per parameter, then scanned that
array linearly for every decoded ID. Known parameters now occupy a 32-bit seen
set, while up to eight unknown/greasing IDs stay in caller-stack storage; only
the ninth distinct unknown ID allocates an overflow list. Duplicate detection
still spans the known set, inline unknown IDs, and overflow. Fail-first tests
prove a complete practical known-parameter block and eight unknown IDs parse
without allocation, the ninth unknown reports OOM transactionally, and a
duplicate after spill is still rejected. Debug and ReleaseFast focused library
gates pass; the broader filtered build completed 158/158 steps and 153/153
tests, and the four-role Quinn certificate/echo/close smoke remains green.

A CPU-0 fixed-binary 100-connection local-handshake pair used baseline SHA-256
`2c7e5987cbf2c253422fd147837097a6d01af14d7d3369178073d0961d708068`
and candidate
`5e96d191fe30aaeb81896d087829c2ea5dc79d5d38e894dba9a2d087220b4868`.
Allocation calls fell from 5,701 to 5,501, exactly two per connection (3.5%),
and cumulative requested bytes from 6,873,388 to 6,815,920 (-57,468, 0.84%).
Both runs freed every byte and retained the same 56,031-byte peak. GNU `size`
text increased only 216 bytes while total static size fell eight bytes after
the corresponding BSS reduction.

The fixed-Quinn-server client matrix used baseline SHA-256
`e555bd546538f2c5fca8e09d764b6f306cf6c6c42004327da67df97e32d74986`
and candidate
`d23674a7d4ad1d5cb8a50cdc8287675c64cf118f9f955a789268d1fd3cddcc73`.
Eight mirrored 100-connection pairs produced a 0.998210 median instruction
ratio (0.179% lower, 6/8 wins) and 0.969649 post-trust ratio (3.04% lower, 6/8
wins). Complete P50 won only 3/8 with a 1.017151 ratio, so no handshake-latency
gain is claimed. A zero-loss 1,000-connection follow-up recorded 235 samples;
the former 2.63% typed-parser entry disappeared below the 0.2% reporting
threshold. An exact upfront encoder-length/reserve experiment was rejected:
despite a 0.09% instruction reduction, it won only 1/8 P50 pairs and regressed
the paired median 4.69%. The retained change is therefore the exact allocation,
memory, duplicate-detection, and small instruction result without the extra
encoding prepass.

Published Vail `209f58b` then replaces the portable public-scalar binary-GCD
inside ARM64 P-256 verification with BoringSSL/AWS-LC's ISC-licensed,
four-limb variable-time BEEU schedule pinned to `7eab8046`. Inputs and output
remain canonical little-endian integers modulo the subgroup order before Vail
converts the inverse back to its Montgomery scalar representation. The route is
strictly limited to public signature-verification input; secret signing
inversion retains the constant-schedule implementation. The one, `n - 1`, and
256 deterministic nonzero cases match the fixed-time inverse in ReleaseFast
and ReleaseSafe, while Debug and ReleaseSmall retain the portable binary-GCD
oracle. Complete Debug/ReleaseFast Vail suites, both optimized P-256 suites,
and the x86_64 ReleaseFast compile gate pass.

The component benchmark moved Vail public inversion from 2,797 to 971 ns/op
(65.28%). Eight CPU-0 fixed-binary prepared-verifier pairs used baseline
SHA-256
`259cccb3e8e5f9986b6caccadc7e284eaa04654bdcc338942d2ccd56cba2cb94`
and candidate
`bccdaaba164bf3368b537ca1c1feb84417a72bfea1119e3967bc57784247e148`.
Every candidate arm won: the midpoint median fell from 17,789.5 to 15,520.5
ns/verify (12.75%), with a 0.872092 median paired ratio. Preparation remained
neutral at 0.999954 with four wins per side. The candidate is 68.41% below the
same-host 49,135 ns AWS-LC parsed-key reference, or about 3.17x its throughput;
GNU `size` text also fell from 554,200 to 552,472 bytes (-1,728).

The fixed-Quinn-server matrix used netz baseline SHA-256
`d23674a7d4ad1d5cb8a50cdc8287675c64cf118f9f955a789268d1fd3cddcc73`
and candidate
`04292422d29463f89658be67abd97c9f392a46212a9539d6567dc76ee3253975`.
Client instructions improved in all eight mirrored 100-connection pairs with a
0.964808 median ratio (3.52%). Complete P50 split 4/8 at a neutral 1.005035
ratio, and both pre/post-trust timings followed host-load excursions rather
than the primitive direction, so no complete-handshake latency gain is claimed.
The candidate passed the four-role Quinn certificate/echo/close smoke and its
GNU `size` text fell 1,632 bytes. A zero-loss 1,000-connection profile recorded
219 samples at 352.603 us P50 and 685.160 us P99. X25519 variable/fixed loops
now account for 19.44%/4.26%, while the P-256 verifier body, mixed-add, public
inverse, and doubling account for 7.37%/5.40%/2.98%/1.47%. The next crypto pass
therefore returns to X25519 or must isolate a new point/verifier sub-hotspot;
public scalar inversion is no longer an independent implementation gap.

The historical 2026-09-16 5 x 100 full-handshake capture used netz binary SHA-256
`fbb112f461774e4edb8fa8f05f46b78af138f3ce348ffade25d3d57929d307b6`
and Quinn binary SHA-256
`931a0f03e7821268eb93cc0388d8302162304821c1987877e2f2800f683c63f1`:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + Quinn server | 2.565 ms | 6.649 ms | 375.3 |
| Quinn client + Quinn server | 1.312 ms | 2.700 ms | 741.4 |
| Quinn client + netz server | 2.208 ms | 6.551 ms | 436.2 |
| netz client + netz server | 1.517 ms | 3.340 ms | 546.5 |

Against the fixed Quinn server, netz's p50 was 1.95x higher (0.512x). Against
the fixed netz server, netz's p50 was 28.2% lower (1.393x). The direction
reverses with the server, so this establishes a concrete netz-client/Quinn
server optimization target but not a general client or server ranking. The
historical benchmark remains `same-security-policy`: executor design,
packetization, socket plumbing, and certificate representation were not
equalized. The shared-identity matrix above supersedes it for current
fixed-server comparisons.

The current netz client and server run on zio behind `std.Io`. Handshake
samples, aggregate results, and server completions carry `client_io`,
`server_io`, `endpoint_role`, and `timeout_ms`; the strict verifier rejects
missing, mismatched, legacy-backend, or wrong-owner records. A 2026-09-15
ReleaseFast 5 x 100 order-interleaved rerun produced these zio-era medians:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + quic-go server | 1.365 ms | 1.863 ms | 718.1 |
| quic-go client + quic-go server | 1.044 ms | 2.150 ms | 925.0 |
| quic-go client + netz server | 0.870 ms | 1.735 ms | 1,120.0 |
| netz client + netz server | 0.981 ms | 1.369 ms | 963.7 |

All 2,200 connections completed the authenticated echo/close exchange and all
20 result plus 20 server-completion records verified checksum 5,995. Against
a fixed quic-go server the netz-client P50 is 1.31x higher and its derived rate
is 0.78x; against a fixed netz server its P50 is 1.13x higher and rate 0.86x.
The current zio client handshake path therefore remains a concrete performance
gap. The netz/netz tail is lower in this run, but the workloads are not
equal-wire and the per-run P99 ranges overlap, so this is not a broad tail
superiority claim.

The historical 2026-09-09 CPU-0/client and CPU-1/server medians after the exact
trust-anchor and P-256 verification optimizations were:

| Complete role pair | P50 connect | P99 connect | Derived connects/s |
|---|---:|---:|---:|
| netz client + quic-go server | 0.609 ms | 1.009 ms | 1,608.2 |
| quic-go client + quic-go server | 0.506 ms | 1.047 ms | 1,864.7 |
| quic-go client + netz server | 0.656 ms | 1.090 ms | 1,478.7 |
| netz client + netz server | 0.749 ms | 0.787 ms | 1,332.1 |

These are complete role-pair results, not separable client/server costs. The
2026-09-09 table predates the zio migration and is retained as a
`std.Io.Threaded` baseline, not current zio performance. The
same-server comparisons leave netz's client handshake path as a concrete
remaining latency target: 1.20x the quic-go client P50 against the quic-go
server and 1.14x against the netz server in this capture. The harness does not
equalize executor implementation, syscall batching, certificate
representation, or kernel wire shape, so it is a same-security-policy
optimization baseline rather than an equal-wire or broad superiority claim.

The benchmark's one-certificate chain configures that same certificate as its
trust anchor. The former verifier still checked the anchor's self-signature
after hostname validation, adding a second P-256 verification on top of TLS
1.3 CertificateVerify. Trust-anchor signatures are not part of path
validation: possession comes from the separately verified CertificateVerify,
while configuring the anchor is the trust decision. The shared vail verifier
recognizes an exact anchor and the cross-signed form of the same Subject and
SubjectPublicKeyInfo, checks both validity intervals, and skips only the trust
anchor's issuer signature. It continues to verify every leaf and intermediate
signature; dedicated tests also reject a same-subject/different-key certificate
and expired or not-yet-valid equivalent anchors.

A same-build 3x500 A/B against the quic-go server measured the old path at
1.171 ms P50 and 845.9 derived connects/s, versus 0.741 ms and 1,331.4/s after
the change: 36.7% lower P50 and 57.4% higher rate from the timed sums. In the
canonical 5x100 capture above, the old 1.191 ms baseline fell 36.2% to 0.759
ms. A follow-up 2,000-connection `perf` sample measured 0.752 ms P50; the old
`Certificate.Bundle.verify` P-256 path had accounted for about 33% of sampled
cycles, while the optimized trust callback accounted for 0.51% and the
mandatory TLS CertificateVerify became the dominant user-space path. This
gain applies to exact-anchor deployments such as this benchmark, not to a
normal leaf-to-CA chain where the leaf signature remains mandatory.

The remaining TLS CertificateVerify profile then exposed a second independent
cost: Zig's generic ECDSA verifier computed `u1*G` and `u2*Q` separately before
adding the points even though P-256 provides a variable-time public
double-scalar primitive for exactly that verification equation. Vail's P-256
TLS verifier now uses `P256.mulDoubleBasePublic`; DER parsing, canonical/nonzero
`r`/`s` checks, the TLS 1.3 role-specific context, transcript hashing, public
key validation, and error mapping remain unchanged. Thirty-two deterministic
key/signature cases are checked against the stdlib verifier, with wrong
transcripts, zero and non-canonical scalar negatives, and a direct client-role
context test. The P-384, Ed25519, RSA-PSS, and SM2 paths are untouched.

A five-pair CPU-0 microbenchmark measured the stdlib P-256 verifier at
433.560-438.650 us and the double-scalar path at 284.567-286.806 us per
verification, a stable 34-35% reduction. The same-build external 3x500 result
then moved from the exact-anchor path's 0.741 ms P50 and 1,331.4 derived
connects/s to 0.598 ms and 1,644.6/s, another 19.2% lower P50 and 23.5% higher
rate. The canonical 5x100 result in the table measured 0.609 ms and 1,608.2/s.
Relative to the original 1.191 ms/833.7 baseline, the two changes together
lowered P50 by 48.9% and raised the timed-sum rate by 92.9%. A final
2,000-connection `perf` sample measured 0.608 ms P50 and showed
`mulDoubleBasePublic` under the mandatory CertificateVerify path, with the
eliminated trust-anchor self-verification still absent.

Captured on 2026-08-19 using authenticated P-256 CertificateVerify, X25519,
TLS_AES_128_GCM_SHA256, and fresh loopback QUIC endpoints for every sample:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=handshake --iterations=200
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=handshake --iterations=100 --stats
```

Three consecutive samples after the optimization were:

```text
connections/s: 824.1, 830.7, 817.6
p50:           1179.1, 1172.1, 1185.2 us
p99:           1409.9, 1367.8, 1712.8 us
```

The first two values came from 200-iteration runs; the final value came from
the 100-iteration allocator run. A later validation pair under varying host
load sustained 797.2 and 806.2 conn/s, so the faster pair is evidence of the
captured improvement rather than a guaranteed floor. The allocator run ended
with zero live bytes, 9,201 allocations (92.0 per connection), 15,001,739
cumulative bytes and an 88,276-byte peak. Before exact Initial packet sizing it
used 16,701 allocations
(167.0 per connection), 1,700 remaps and 22,185,904 cumulative bytes. The new
wire-length calculation removes speculative encrypt/allocate/free probes and
reserves exact long-header packet storage, reducing allocation calls by 44.9%,
remaps by 88.2%, and cumulative allocated bytes by 32.4%.

The benchmark also stopped creating one OS thread per connection and now uses
the existing `std.Io` executor, while the immutable long-term P-256 key is
materialized once and each handshake still creates a fresh CertificateVerify
signature and validates it against the pinned public key. Relative to the
original captured 638.0 conn/s sample, the current 824.1-830.7 conn/s pair is
29.2-30.2% higher. The current quicz sample remains faster and skips server
CertificateVerify validation, so this is an internal improvement rather than
a cross-stack superiority claim.

`--skip-server-verification` now exposes that policy difference explicitly
without removing the server Certificate or its fresh P-256 CertificateVerify
signature. Five CPU-0-pinned 200-connection runs measured p50
657.9-833.0 us, p99 1.328-9.971 ms, and 449.6-1426.7 conn/s; the middle samples
were 668.8 us and 881.9 conn/s. Three matching runs of the audited quicz
handshake-only artifact measured p50 800.3-811.9 us, p99 3.005-5.813 ms and
538.4-788.6 conn/s. Netz is therefore faster at p50 in four of five captured
runs and has the higher median rate, but host scheduling still produces enough
tail/rate variance that this is evidence of a closed verification-cost gap, not
a universal handshake-superiority claim. A 100-connection `--stats` run ended
with zero live bytes and used 9,001 allocations, 14,985,675 cumulative bytes
and an 88,276-byte peak.

Established connections now keep reusable protected-packet, receive-datagram,
frame, and ACK-range storage together in one lifecycle module. Reliable frames
encode directly into stable recovery ownership; mixed/non-retransmittable
frames, PMTU probes, and PTO IMMEDIATE_ACK augmentation encode directly into
the final packet payload before in-place AEAD. This removes the redundant
path-sized plaintext scratch allocation entirely. It follows the reusable-
buffer principle visible in Quinn's endpoint `RecvState` and tquic's endpoint
receive loop, plus quiche's caller-output send interface, while retaining
netz's connection-local ownership and zio/`std.Io` boundary. Direct tests
decrypt the mixed-frame wire result and cover scratch-init allocation rollback.
The implementation and dedicated tests live in `src/quic/one_rtt/scratch.zig`
and `src/quic/one_rtt/tests/scratch.zig`.

In a 100-iteration local client+server handshake run with server verification
skipped, the fixed baseline used 8,001 allocations, 14,469,287 cumulative
bytes, and an 88,289-byte peak. The direct-encoding build used 7,801 allocations,
11,773,513 cumulative bytes, and a 61,333-byte peak: 2.5% fewer allocations,
18.6% fewer allocated bytes, and a 30.5% lower peak. With P-256
CertificateVerify enabled, the corresponding counts were 8,501 to 8,301,
14,507,829 to 11,812,274 bytes, and 88,370 to 61,414 peak bytes.

Seven CPU-0, order-alternated, 200-handshake comparisons used baseline SHA-256
`5cbf897b6c89defa292b082265802c1a47f92a3463622e72ea7deef4ece426e1`
and candidate SHA-256
`11427ea0239aaba6c4d88d7734908e36fae2b6f3a2b7a771d74a35b66f167452`.
In quicz-aligned mode, median P50 moved from 600.753 to 596.874 us (0.6%,
4/7 wins), and median rate from 1,503.5 to 1,511.5 connections/s (0.5%,
4/7 wins). With CertificateVerify, median P50 moved from 919.422 to 912.597 us
(0.7%, 7/7 wins), while median rate moved from 1,013.7 to 1,021.3/s (0.7%,
6/7 wins). These timing differences are noise-level; the supported claim is
reduced allocation and memory without a measured handshake-latency regression.
A seven-pair first-echo control moved the one-round median from 146.945 to
127.427 us with 7/7 paired wins. One 5,000-round steady-state control moved
from 16.287 to 15.519 us; it is only supporting evidence, not a broad
steady-state speed claim.

The s2n-quic process matrix now also covers cancellation reordering in both
endpoint-role directions. A reusable one-shot interop state arms immediately
before netz emits RESET_STREAM(41) or STOP_SENDING(42), holds exactly that
protected datagram, sends stream 4's complete `world` packet first, and then
flushes the held cancellation. Both the netz-client/s2n-server and
s2n-client/netz-server cases require one held datagram, peer-visible exact
error codes, sibling completion before cancellation observation, and the final
application close. The fault state and its deterministic contract test live in
`tools/interop/support/one_shot_reorder.zig`; the existing loss-retransmission
cases remain separate.

The same s2n-quic gate now includes a clean-network, bounded mixed lifecycle
in both endpoint-role directions. It opens one persistent control stream and
32 concurrent data streams, verifies a deterministic 256-byte prefix on every
stream, then alternates 16 full 16-KiB FIN completions with 16 RESET_STREAM
terminations. Reset codes are `0x4000 + stream_index`; both independent peers
must report 266,240 accepted bytes, checksum 33,945,600, reset mask
`0x00000000aaaaaaaa`, reset-code sum 262,400, and the expected application
close. The protocol implementations are isolated in
`tools/interop/support/s2n_churn*.zig` and
`tools/interop/quic_s2n/src/churn.rs`, keeping the peer entry points focused on
transport setup and scenario routing. The churn protocol now separates RESET
and FIN terminal work with authenticated control markers. Four additional
connections make netz the outbound sender as client and server, under loss and
real pair reordering. A reusable phased interceptor arms immediately before
each terminal phase and requires exactly one dropped datagram or completed
hold/flush pair in each phase. The receiver acknowledges all exact resets
before the second arm, then verifies every FIN payload before returning the
same aggregate result. This proves recovery without depending on encrypted
packet parsing; it covers netz outbound faults only and does not claim injected
s2n-quic outbound loss. This remains reliability coverage rather than a
throughput comparison.

The s2n-quic process matrix also enables its native unstable RFC 9221
DATAGRAM provider and runs a separate bidirectional DATAGRAM connection for
each endpoint-role pairing. Each peer sends two distinct small payloads and
one boundary payload, and each receiver validates the three-member set without
assuming DATAGRAM ordering. Netz advertises a 64-byte maximum DATAGRAM frame,
so s2n-quic successfully sends the exact 62-byte length-present payload and
rejects a 65-byte application payload locally as exceeding peer transport
limits. Netz uses a 1200-byte path datagram size, reports and successfully
sends its exact 1163-byte application boundary, and rejects 1164 bytes locally.
After both unreliable directions finish, client-initiated stream 4 completes a
FIN-terminated `world` echo and the peer application close is verified as 57
or 58. Both strict process cases report `zio-std-io` for the netz endpoint and
`s2n-quic-tokio` for the independent fixture. This is functional negotiation,
boundary, isolation, and lifecycle evidence; it is not a throughput result.

An independent Quinn process matrix reuses the same wire-control protocol and
runs the same two endpoint-role pairings at audited Quinn commit
`d9c8c4c695fc64292d9b117844ea6924ca0d0815`. Quinn's public
`max_datagram_size()` intentionally subtracts its conservative nine-byte
DATAGRAM frame bound from netz's advertised 64-byte limit, so the exact Quinn
payload boundary is 55 bytes and 56 bytes returns `TooLarge`. In the opposite
direction, Quinn's eight-byte short-header CID gives netz an exact 1171-byte
payload boundary for the fixed 1200-byte path, and netz rejects 1172 bytes.
Both sides again validate two distinct small payloads plus the boundary as an
unordered set, reliable stream 4, application close 57/58, certificate trust,
ALPN/SNI, and `zio-std-io` versus `quinn-tokio-rustls`. The Zig protocol is
shared in `tools/interop/support/native_datagram.zig`; the independent Quinn
adapter remains isolated under `tools/interop/quic_quinn/`. Four additional
connections make netz the outbound DATAGRAM sender as client and server under
one deterministic loss or real hold/send/flush reordering fault. Quinn requires
the loss case to omit exactly the first payload, completes the reliable stream
4 exchange, then waits another 100 ms to prove it was not retransmitted. The
reorder case requires the second small payload before the first and still
receives all three payloads. Both peers require exactly one injected fault and
the expected application close. This is functional reliability evidence, not
a performance claim, and does not inject faults into Quinn's outbound path.

The next zio receive-path step gives direct endpoint-backed handshake sources
one reusable datagram allocation. Each returned datagram keeps a scoped release
hook, so a nested flight receive falls back to the source's owning path while
the preceding bytes remain live. Routed dispatcher inboxes expose no
caller-buffer capability and retain their existing owning FIFO semantics. At
successful establishment the reader allocation transfers into the connection's
1-RTT receive scratch instead of overlapping a second path-sized allocation.
This follows Quinn's allocate-once endpoint `recv_buf` and tquic's receive buffer
outside its endpoint loop, while keeping netz's zio/`std.Io` boundary and
explicit source ownership. The reusable reader is isolated in
`src/quic/handshake/datagram_reader.zig`; tests cover reuse, nested lifetime,
owning-source fallback, transfer identity, validation failure, and allocation-
failure rollback.

The fixed baseline for this step is the preceding direct-packet-scratch binary
SHA-256
`11427ea0239aaba6c4d88d7734908e36fae2b6f3a2b7a771d74a35b66f167452`;
the final receive-reuse candidate is
`a3d4f0f7068cff7a6b5281a35e9d0a62b5f1f7233fd23335c169764394646cf8`.
In 100 fresh local client+server handshakes with verification skipped,
allocation calls fell from 7,801 to 7,001 (10.3%), cumulative allocated bytes
from 11,773,609 to 7,014,691 (40.4%), and peak live bytes from 61,333 to 52,098
(15.1%). With CertificateVerify enabled, the corresponding values were 8,301
to 7,501 calls (9.6%), 11,812,079 to 7,053,071 bytes (40.3%), and 61,414 to
52,179 peak bytes (15.0%). Both modes ended at zero live bytes. Exact 8,900-byte
allocations fell from four to two per handshake: one receive allocation per
endpoint remains and becomes that connection's established receive scratch.

Seven CPU-0-pinned, order-alternated, 200-handshake pairs showed no stable
latency change. In quicz-aligned mode, median P50 moved from 578.520 to 581.150
us (candidate 2/7 wins) while median rate moved from 1,568.2 to 1,574.3/s
(3/7 wins). With CertificateVerify, median P50 moved from 895.262 to 896.132 us
(3/7 wins), and median rate from 1,053.6 to 1,052.3/s (3/7 wins). A seven-pair
first-echo control moved from 104.528 to 106.186 us with 4/7 wins, and one
5,000-round steady control was effectively unchanged at 15.574 versus 15.575
us. These timings are noise-level controls; the supported result is lower
allocation volume and peak memory without a measured application-data
regression.

### Raw QUIC real-handshake 1 KiB echo latency

Captured on 2026-08-20 with one real authenticated handshake followed by 5,000
ordered 1 KiB STREAM round trips on stream 0. Both endpoints run sequentially
on CPU 0, ACKs are piggybacked on the next request/response, and every returned
payload byte is checked before its latency sample is accepted:

```sh
taskset -c 0 zig build bench-quic-handshake-stream \
  -Doptimize=ReleaseFast -- --mode=echo
taskset -c 0 /tmp/quicz-echo-only
```

Three consecutive pinned runs:

```text
netz:
  p50:   10.44-10.57 us
  p99:   15.22-15.53 us
  p99.9: 31.89-47.02 us
  rate:  92,252-93,030 round trips/s

quicz:
  p50:   10.5-10.7 us
  p99:   16.0-19.5 us
  p99.9: 206.3-211.2 us
```

Netz is 0.99-1.02x quicz at p50, 1.03-1.28x faster at p99, and 4.4-6.6x lower
at p99.9 in these controlled runs. The new `sendWithPendingAck` transport API
combines an application response with its cumulative ACK, and receiving an
ACK-of-ACK prunes old received packet-number ranges. A subsequent perf profile
showed sent-packet ACK/loss processing repeatedly scanning the full resolved
metadata prefix: cost grew with connection lifetime despite one new packet per
round. `SentPacketTracker` now retains a first-unacknowledged cursor, uses
binary range boundaries for cumulative ACK validation, and starts recovery
scans at the unresolved suffix. A 5,000-round `--stats` run made 159 total
allocations, ended with zero live bytes, and verified all 5,120,000 echoed
payload bytes.

Sent-packet metadata now also compacts acknowledged contiguous prefixes in
256-packet batches. The tracker retains the retired packet-number interval for
duplicate cumulative ACK validation, while unresolved/lost packets keep full
RTT, ECN, PMTU and recovery fields. A CPU-0 50,000-round `--stats` run sustained
92,374.6 round trips/s at p50/p99/p99.9 10.659/15.583/18.106 us, made 149
allocations, allocated 685,276 cumulative bytes, peaked at 560,036 live bytes,
and ended at zero. Metadata is therefore bounded by unresolved work rather than
connection lifetime without regressing the ACK-cursor latency result.

### Raw QUIC stream-open rate

Captured on 2026-08-20 after one real handshake. Like quicz's stream-churn
case, the timed region reserves 100,000 locally initiated bidirectional stream
IDs without transmitting STREAM frames:

```sh
taskset -c 0 zig build bench-quic-handshake-stream \
  -Doptimize=ReleaseFast -- --mode=stream-churn
taskset -c 0 /tmp/quicz-stream-churn-only
```

```text
netz:   680.2M, 778.0M, 777.7M streams/s
quicz:   48.1M,  52.0M,  51.7M streams/s
```

This controlled artifact puts netz at 13.1-16.2x the quicz stream-open rate.
The new transport API enforces negotiated bidi/uni stream limits, returns the
RFC stream-ID sequences for both endpoint roles, and creates stream flow state
lazily on first use. A 100,000-stream `--stats` run made no allocations in the
timed loop: the whole real-handshake process made 92 allocations, ended with
zero live bytes, and returned the expected final ID 399,996 and checksum
19,999,800,000. This is a stream-reservation microbenchmark, not evidence for
wire-level open/close throughput.

The on-wire `--mode=lifecycle-churn` path now optionally injects loss or
reordering in both directions after handshake completion. Its lifecycle pump
waits on both UDP endpoints in one readiness operation, bounded by the earliest
transport timer on either connection and one absolute awake-clock benchmark
deadline. This avoids both a fixed 1 ms polling quantum in the clean path and
starving reverse ACKs until PTO. Every run verifies the exact FIN/reset split,
last stream ID, checksum, cumulative MAX_STREAMS renewal, and deterministic
per-direction fault counts. A 128-stream/16-credit smoke completed clean, 5%
loss, and every-fifth-datagram reordering runs in 6.01, 8.17, and 4.11 ms of
timed lifecycle work. The loss run considered/dropped 276/14 client datagrams
and 284/16 server datagrams; the reorder run held exactly 45 of 228 and 45 of
227 respectively. These short unpinned runs are correctness and scheduler
regression evidence, not throughput comparisons. Reproduce them with:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=lifecycle-churn --iterations=128 --streams=16
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=lifecycle-churn --iterations=128 --streams=16 --loss-pct=5
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=lifecycle-churn --iterations=128 --streams=16 --reorder-every=5
```

After adding path-epoch recovery isolation, CPU-pinned 256-stream reruns
completed with the same exact 128 FIN / 128 reset split, final stream ID 1020,
and checksum 26,496. The 5% bidirectional-loss run considered/dropped 556/27
client and 562/28 server datagrams, reported 11/18 transport losses, and
completed at 18,924-23,812 streams/s. The every-fifth-datagram reorder run held
91/455 client and 90/454 server datagrams and completed at 26,016-35,446
streams/s.
These remain deterministic fault/recovery checks rather than cross-stack speed
claims. A 4,096-stream loss run exceeded the benchmark's fixed 30-second
deadline and is not used as performance evidence.

### Raw QUIC four-connection aggregate throughput

Captured on 2026-08-20 with the same shape as quicz's thread-per-connection
scaling case: four worker threads, one independent `std.Io` per worker, one
real handshake and one 64 MiB upload per connection. The aggregate timer
includes worker creation, handshakes, transfers and teardown:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=aggregate --connections=4 --transfer-bytes=67108864
timeout 180 /tmp/quicz-aggregate-only
```

```text
netz:  730.35, 790.22, 900.57 MiB/s
quicz: 503.23, 513.22, 533.10 MB/s
```

The conservative cross-unit ratio (netz MiB/s divided by quicz MB/s without
giving netz the 1.048576 unit conversion advantage) is 1.37-1.79x. Every netz
worker must report exactly 64 MiB received before the result is accepted. A
separate four-connection × 16 MiB `--stats` run verified 64 MiB aggregate,
made 160,993 allocation calls, allocated 700,944,509 cumulative bytes and had
8,473,284 summed worker peak bytes, with zero live bytes at worker teardown.
This is connection-level parallel scaling evidence, not a single-connection or
HTTP/3 claim.

### Raw QUIC deterministic loss recovery

Captured on 2026-08-20 using the quicz loss shape: one real handshake, a 4 MiB
single-stream upload, seeded xorshift client-to-server packet loss, and optional
50 us one-way busy-wait delay for a configured 100 us RTT. The interceptor is
enabled only after handshake completion, so TLS setup is not faulted:

```sh
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=1
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=5
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=1 --rtt-us=100
zig build bench-quic-handshake-stream -Doptimize=ReleaseFast -- \
  --mode=loss --loss-pct=5 --rtt-us=100
```

Three-run ranges against a freshly compiled quicz loss-only binary:

| Scenario | netz MiB/s | quicz MB/s | Conservative ratio |
| --- | ---: | ---: | ---: |
| 1% loopback | 255.19-289.29 | 220.84-236.72 | 1.08-1.31x |
| 5% loopback | 286.99-314.31 | 216.79-223.64 | 1.28-1.45x |
| 1% / 100 us RTT | 121.13-131.24 | 98.73-105.03 | 1.15-1.33x |
| 5% / 100 us RTT | 116.43-127.62 | 95.88-98.42 | 1.18-1.33x |

The ratio again does not normalize MB/s versus MiB/s in netz's favor. Each
run verifies all 4,194,304 receive bytes and reports considered/dropped
datagrams plus transport-declared loss. The seeded 5% cases consistently
dropped 25 of 504 client datagrams. A 5%/100 us `--stats` run made 31,254
allocations, allocated 231,757,047 cumulative bytes, peaked at 832,363 live
bytes and ended with zero live bytes. The endpoint interceptor consumes dropped
datagrams from QUIC's send perspective, including batch submissions, so normal
packet-number/recovery semantics remain active.

The same real-handshake gate now accepts
`--mode=reorder --reorder-every=5`. The client endpoint holds every fifth
outgoing datagram,
sends its successor first, then releases the held packet; handshake traffic is
excluded by enabling the hook only for the 4 MiB STREAM upload. Three CPU 0-7
runs verified all 4,194,304 bytes, considered 504-610 datagrams, held 100-122,
and reported 33-160 packets declared lost while completing at 310.38-379.01
MiB/s. A no-drop control through the same fault-mode path measured 313.00-
466.71 MiB/s. The wide first-run spread is reported rather than converted into
a speed claim; the durable result is successful byte-exact recovery under real
client STREAM packet reordering.

`--mode=corrupt --corrupt-every=20` covers authenticated corruption rather than
ordinary loss. The endpoint copies every selected client datagram, flips one
ciphertext bit and leaves caller storage/recovery metadata untouched; the peer
discards `AuthenticationFailed` packets and normal PTO/ACK recovery restores
their STREAM ranges. Three CPU 0-7 runs corrupted exactly 25 of 504 datagrams,
reported exactly 25 transport losses, verified all 4,194,304 bytes, and
completed at 276.51-464.70 MiB/s. As with reordering, the wide scheduling range
precludes a speed verdict; this is deterministic AEAD-rejection/recovery
evidence.

