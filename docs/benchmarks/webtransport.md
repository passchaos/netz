# WebTransport results

[Back to the benchmark index](../benchmark-baseline.md).

## WebTransport runtime smoke and DATAGRAM baseline

Validated on 2026-08-17:

```sh
zig build run-webtransport-handshake-stream -Doptimize=ReleaseFast
zig build bench-webtransport-datagram -Doptimize=ReleaseFast
zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- \
  --payload-bytes=1024 --iterations=10000
zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- \
  --burst --batch-size=16 --max-in-flight=64 --receive-into \
  --payload-bytes=1024 --iterations=10000
```

```text
WebTransport handshake streams ok: bidi=4, uni=14, server_uni=15

WebTransport datagram runtime benchmark
  iterations: 10000
  datagrams: 20000
  payload bytes: 27
  ns/roundtrip: 13242
  ns/datagram: 6621
  datagrams/s: 151031
```

WebTransport's resumable outbound CLOSE storage now keeps encoded capsules
through 128 bytes inline and allocates longer reasons at their exact encoded
size. The inbound Capsule parser uses the same threshold for peer close
reasons, retaining longer values in one exact allocation. This reduces
`PendingSessionClose` from 1,064 to 160 bytes, `session_control.Control` from
1,160 to 296 bytes, and initially reduced
`protected_session_control.Reader` from 2,224 to 1,360 bytes. The reader's own
post-event suffix storage now also uses 128 inline bytes plus exact fallback,
reducing it again to 456 bytes. The resulting Session sizes are 1,064 B for
`AcceptedSession`, 872 B for `AcceptedProtectedSession`, 17,320 B for
`AcceptedHandshakeSession`, 7,352 B for `ClientSession`, 17,864 B for
`HandshakeClientSession`, and 8,960 B for `ProtectedClientSession`. Relative
to the original layout, the four reader-backed Session types save 2,672 bytes
each and the two direct-Control types save 1,768 bytes each.
The ordinary short-close paths remain allocation-free; tests force both first
over-inline allocations to fail, retry the same input after rollback, reject
invalid long UTF-8 without leaking, and retain the existing maximum-reason
timeout coverage. These are deterministic layout and allocation-path results
rather than throughput measurements.

The stream smoke uses real QUIC/TLS and HTTP/3 CONNECT rather than the
cleartext development transport. It validates modern bidirectional association
(`0x41 + Session ID`), both unidirectional directions, reverse-direction bidi
data, >1-packet stream fragmentation, per-session stream credit and shared
HTTP/3/WebTransport stream-ID allocation. The DATAGRAM number remains a netz
baseline; no equivalent same-command quicz/wtransport result was captured.
The cross-stream writer now keeps batch membership generations in the existing
stream registry index. Duplicate validation is linear and allocation-free,
selected checks are O(1), and the all-prefix-sent steady path scans candidates
once while maintaining a fixed stable-priority top-64 window. The prefix path
continues to re-evaluate credit after each association write and now marks before
that write, preventing a newly blocked high-priority stream from starving its
siblings. A CPU-0 64-stream/16-KiB smoke verified all 1,048,576 bytes across 320
partial writes with checksum 133,693,440; repeated fixed-binary throughput varied
19-40 MiB/s, so only correctness/no-deadlock is claimed.
Development and lightweight protected endpoint sends now share one stack-first
WebTransport DATAGRAM codec under `runtime/datagram/`: payloads whose Quarter
Stream ID plus body fit 4 KiB need no WebTransport-layer allocation, while
larger payloads allocate their exact wire size once. Previously only the
development endpoint had the stack path; protected sends always grew an
ArrayList before QUIC protection. Tests cover wire parity, invalid-session
preflight before allocation, allocation-free common encoding, and exact
fallback OOM. Owned QUIC/protected/handshake DATAGRAM lifetimes are colocated
in the same nested module without moving mutable QUIC connection state.
Three fixed-binary CPU-0 cleartext DATAGRAM runs after the extraction measured
7.940-8.103 us/roundtrip (246,820-251,883 datagrams/s) with the exact existing
checksum. This is an internal regression range; it does not isolate the new
protected-only allocation removal and is not an external throughput ratio.

The same executable accepts `--burst` to exercise the authenticated HTTP/3
WebTransport runtime and its deadline-bounded congestion backpressure:

```sh
zig build bench-webtransport-datagram -Doptimize=ReleaseFast -- \
  --burst --iterations=1000 --send-timeout-ms=1000
```

A final post-change smoke attempted, sent, and received all 1,000 DATAGRAMs
with zero timeouts. The 35-byte workload measured 5.808 us p50 / 15.416 us
p99 send latency, 5.11 logical MiB/s, and the exact checksum 3,549,000. This is an
internal backpressure regression baseline, not a cross-stack throughput claim.
The original cleartext ping-pong mode and output remain the default.
Both ping-pong and authenticated burst modes accept
`--payload-bytes=1..1024`. Omitting it preserves their historical 27-byte and
35-byte payloads respectively, so existing baseline checksums remain stable.
Authenticated burst mode also accepts `--max-in-flight=N`. The sender waits
for enough complete-batch capacity whenever `N` successfully submitted
DATAGRAMs remain unconsumed, so long 1024-byte loopback runs exercise sustained
QUIC/HTTP3 processing instead of overflowing the local UDP queue. The option
is burst-only and opt-in; omitted runs retain the historical unbounded sender
and report `max_in_flight=0`.
`--receive-into` switches the authenticated receiver to the new caller-buffer
API. Fresh matching payloads are copied directly from authenticated packet
storage; a short caller buffer retains the DATAGRAM in the ordinary bounded
association queue, so retry does not silently consume it. The owning APIs and
the benchmark default remain unchanged. The caller-buffer batch forms fill an
arrival-ordered output prefix under one absolute deadline and report the exact
completed count on failure. In `--receive-into` mode the benchmark receives
groups matching `--batch-size`, capped by `--max-in-flight`, and reports the
effective `receive_batch_size`.

For 1,000 1024-byte DATAGRAMs, allocation telemetry fell from 2,221 to 1,220
allocations and removed all 1,000 per-DATAGRAM 1024-byte association payload
allocations (1,024,144 fewer allocated bytes overall in that run). Nine
alternating CPU-0 ReleaseFast pairs at 100,000 DATAGRAMs, batch 16, and window
64 compared owning and caller-buffer modes from fixed binaries. Median logical
throughput rose from 99.19 to 100.69 MiB/s (1.5%), caller-buffer won 7/9 pairs,
and median send p50 fell from 4,397 to 4,352 ns. A separate cross-build run was
directionally consistent (98.24 to 100.10 MiB/s, 9/9 wins). The 35-byte shape
did not show a stable throughput gain, so caller-buffer receive is opt-in and
the owning path remains the default.
Replacing the benchmark's repeated single caller-buffer calls with the batch
API added only two fixed scratch allocations (16,640 bytes for batch 16), not
per-DATAGRAM allocation. Nine additional alternating fixed-binary CPU-0 pairs
at 100,000×1024B moved median throughput from 92.42 to 94.45 MiB/s (2.2%, 8/9
wins) and median send p50 from 4,796 to 4,564 ns (4.8% lower). This is a
same-workload caller-buffer single-versus-batch comparison; the remaining
1,025-byte allocation per DATAGRAM belongs to the QUIC receive queue.
After the protected stack-send integration, the same 1,000-DATAGRAM bounded
burst again attempted/sent/received all 1,000 with zero timeout and checksum
3,549,000. The loaded-host sample was 10.483 us p50 / 17.998 us p99 and
3.32 logical MiB/s, so it is recorded as lifecycle evidence rather than a new
performance baseline.

The authenticated burst mode now accepts `--batch-size=N` (maximum 64) and
uses the exact-prefix DATAGRAM batch sender. HTTP/3 pre-encodes all Quarter
Stream ID prefixes into reusable registry-owned storage, while QUIC reports
the socket-visible input prefix independently from packet numbers consumed by
protection. Five alternating CPU-0 ReleaseFast pairs with 1,000 35-byte
DATAGRAMs measured 2.81-3.37 MiB/s for batch size 1 and 3.49-4.10 MiB/s for
batch size 16; median throughput rose from 2.91 to 3.76 MiB/s (1.29x), and API
calls fell from 1,000 to 63. Every run received all 1,000 DATAGRAMs with
checksum 3,549,000. The benchmark raises only its own bounded receive queue to
the requested iteration count so this sender comparison does not conflate
intentional production queue eviction with kernel/socket throughput.

The multi-stream benchmark now scales connection credit with stream count and
exposes stream-window/datagram/pacing controls. Four 4-MiB streams with 1-MiB
stream windows and 8-KiB datagrams completed at 188-195 MiB/s aggregate across
three ReleaseFast runs. This replaces the earlier 26 MiB/s result whose fixed
128-KiB connection window unintentionally serialized four streams.
Read-only QUIC stream queries now borrow `Connection` instead of copying its
roughly 7.5-KiB state for every credit, stats, and active-ID pagination probe.
Five fixed-binary CPU-0 A/B pairs with the default 64-KiB stream window and a
4-MiB single stream measured 270-272 MiB/s versus 236-240 MiB/s (1.13-1.15x
throughput). Four equivalent runs with four 4-MiB streams measured 276-278
MiB/s versus 211-213 MiB/s (1.30-1.32x). The 64-MiB single-stream profile
reduced aggregate `memcpy` samples from 10.93% to 3.42%; the former copies
under incremental polling and stream-credit queries disappeared. Compile-time
receiver assertions guard the four hot query APIs. These are internal A/B
results and do not replace the differently configured 8-KiB/1-MiB-window
baseline above.

The benchmark also accepts `--loss-pct=N`. Handshake and CONNECT setup remain
reliable; a fixed-seed endpoint interceptor starts immediately before the
associated-stream phase, so STREAM/RESET_STREAM/ACK loss decisions are exactly
repeatable without conflating certificate setup. Five consecutive runs of:

```sh
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- \
  --streams=16 --transfer-bytes=16384 --stream-window=65536 \
  --reset-every=2 --reset-after-bytes=256 --loss-pct=5 \
  --send-timeout-ms=30000
```

The benchmark now keeps a bounded client transport pump alive after its last
FIN/reset so ACK, loss and PTO state continue progressing until the server has
validated every terminal event and torn down its Session. The worker calls
`serviceTransportWithTimeout` in 10 ms intervals, checks an atomic stop flag,
and is awaited cooperatively instead of canceling an in-flight UDP receive.
Handshake clients and rejected-handshake sessions also expose
`serviceTransportWithDeadline`, and the stateful protected client forwards both
bounded service APIs. This removes the prior large-stream teardown deadlock.
The send-all, fair `writeStreams`, and FIN paths share one absolute awake-clock
deadline created immediately before the associated-stream workload; the
default is 30 seconds and `--send-timeout-ms` overrides it. In single-stream
`--send-all` mode, `--stream-slices=N` selects the zero-join scatter/gather
sender. Slice descriptors are built before timing and the output includes the
selected count, so `N=1` and `N=8` provide an equivalent-byte/checksum A/B
shape. Five alternating CPU-0 ReleaseFast pairs with a 1-MiB payload and pacing
disabled measured 288-305 MiB/s for one slice and 295-307 MiB/s for eight
slices; medians were 304 and 299 MiB/s respectively (0.98x). Every run
delivered 1,048,576 bytes with checksum 133,693,440 in 287 receive events. This
small loopback sample demonstrates parity and no material vectored-path
regression; it is not a cross-library throughput claim. Five 64-stream
runs considered 320 server datagrams and dropped the
same 21 every time. All 32 reset streams reported application code 42 after
their 256-byte prefix, all 32 non-reset streams reached FIN, and every run
verified 532,480 bytes and checksum 67,891,200. Elapsed time ranged
10.656-14.923 ms (34-47 MiB/s); read-event fragmentation varied independently
from the exact terminal/byte result. This is deterministic
cancellation/recovery evidence, not an equal-wire wtransport throughput
comparison.

A fixed-binary CPU-0 liveness A/B used a 4 MiB transfer, eight input slices,
`--send-all --enable-gro-receive`, and an outer 2-second watchdog. The baseline
timed out in all 7 runs after the application transfer had completed; the
bounded-service candidate completed all 7 in 13.944-14.951 ms at 267-286 MiB/s,
with 358-359 read events and checksum 534,773,760. All 7 non-GRO control pairs
completed in both arms: the baseline median was 22.365 ms, the candidate median
was 22.216 ms, and the paired candidate/baseline median was 0.990. The result
establishes teardown liveness without claiming a throughput speedup. The fixed
baseline binary, candidate binary, and paired log have SHA-256 values
`73e897a03ed825da1538ecb0c0cf0789ab22fbc2fe57e3d853cdd3c793b12b98`,
`a9b58c65373cf4cb0eb50cee3c3ec6dcc6990bf3b265b3946220dc2127a61271`, and
`9e8f51a99d4da29f5349fcc6bfa84c422cd1641e5b2ac078652394deab0a2d3f`,
respectively.

The internal harness terminal table was subsequently raised from 64 to a
bounded 256 entries. Three 128-stream/64-KiB mixed FIN/reset runs under seeded
5% server-direction loss each delivered 64 RESET_STREAM terminals, 64 FINs,
4,210,688 bytes, checksum 536,862,720, and dropped exactly 96 of 1,540-1,545
considered datagrams. Three matching all-FIN client-direction reorder runs
delivered 8,388,608 bytes and checksum 1,069,547,520 while holding 522-524 of
2,610-2,620 datagrams. The measured loopback rates ranged 98-134 MiB/s for the
mixed loss shape and 25-28 MiB/s for reorder, but these remain scheduler- and
fault-shape-sensitive correctness observations rather than comparative
throughput claims. The external wtransport harness retains its 64-stream cap
because its independently verified wire result carries a `u64` reset mask.
Both benchmark peers now set `max_session_streams` from the requested shape;
previously the newly enlarged terminal table could accept a value above 128
while the runtime correctly rejected it at its independent default limit. At
the bounded ceiling of 256 streams, one 16-KiB mixed loss run delivered 128
RESET_STREAM terminals plus 128 FINs, 2,129,920 bytes/checksum 271,564,800, and
dropped 84 of 1,280 considered datagrams. One all-FIN client-reorder run
delivered 4,194,304 bytes/checksum 534,773,760 while holding 335 of 1,679
datagrams. The parser still rejects 257 streams before network setup.

`--reorder-every=N` now exercises the complementary non-loss case. The endpoint
owns every selected datagram, sends the next packet first, then releases the
held packet; QUIC packet numbers and recovery metadata are therefore committed
normally rather than rewritten by the harness. Three CPU 0-7 runs of:

```sh
zig build bench-webtransport-stream -Doptimize=ReleaseFast -- \
  --streams=8 --transfer-bytes=262144 --stream-window=65536 \
  --one-rtt-datagram-size=4096 --reorder-every=5
```

held exactly 112 of 561 considered server datagrams per run, verified all
2,097,152 bytes and checksum 267,386,880, and completed in 10.92-11.40 ms
(175-183 MiB/s). The benchmark reports held/considered counts separately from
loss, and rejects combining both injectors so the network shape remains
unambiguous.

The benchmark also accepts `--fault-direction=client`, placing the same hook on
the sender of WebTransport STREAM/FIN packets rather than on server ACKs. Three
runs of the command above plus `--fault-direction=client` considered 605-615
client datagrams, held 121-123, verified the same 2,097,152 bytes/checksum
267,386,880, and completed in 12.37-13.07 ms (153-161 MiB/s). A held packet at
the end of a batch is now explicitly flushed, preventing the emulator from
turning an intended reorder into accidental loss.

The external lifecycle gate extends that evidence across both roles with the
independent audited `wtransport` implementation:

```sh
zig build interop-webtransport-wtransport-churn -Doptimize=ReleaseFast
```

It runs 32- and 64-stream cases twice in each sender direction under
deterministic loss and pair reordering. Netz's outbound direction uses its
seeded 5% endpoint interceptor; wtransport's outbound direction crosses an unprivileged
loopback UDP relay that remains transparent for the handshake and is armed
only around the RESET and FIN phases. Half the streams
deliver an acknowledged 256-byte prefix and then RESET_STREAM with application
code `0x4000 + index`; the other half continue to 16 KiB and FIN only after
wtransport has reported every reset. A bidi sibling opened before cancellation
then completes after that barrier. The independent verifier derives expected
bytes, checksum, FIN/reset counts, reset bit mask, and application-code sum from
the requested shape and also requires a real drop/hold count and peer close.
For the proxy direction it checks that both RESET and FIN phases actually hit
the selected fault and that the sender and proxy report identical counters.
The proxy now uses one deterministic single-shot arm in each terminal phase,
so every captured wtransport-sender case drops exactly two datagrams or
completes exactly two reorder pairs overall, independent of the 32/64-stream
size. Netz sends retain the seeded continuous endpoint schedule: the latest
two-run matrix dropped 11/31 datagrams or held 49/100-101 for the 32/64-stream
shapes.
The 32-stream shape verifies 266,240 bytes/checksum 33,945,600, mask
`0x00000000aaaaaaaa`, and code sum 262,400; the 64-stream shape verifies
532,480/67,891,200, mask `0xaaaaaaaaaaaaaaaa`, and code sum 525,312. This is
external recovery/lifecycle evidence for both client-outbound fault scopes,
not a production-network or throughput comparison.

### WebTransport steady stream-batch staging

`bench-webtransport-stream-batch` isolates the production steady-state batch
selection and STREAM-frame staging path from UDP queues, packet protection, and
commit bookkeeping. It registers 64 streams with varied priorities and nonzero
offsets, stages one 1-KiB slice per stream, validates the complete descriptor
checksum, and deliberately performs no socket I/O or registry mutation:

```sh
taskset -c 0 zig build bench-webtransport-stream-batch \
  -Doptimize=ReleaseFast -- --warmup=20000 --iterations=300000
```

Steady staging previously looked up every selected stream in the registry a
second time solely to recover `send_offset`. `OrderedWrite` now carries that
offset from the first lookup; staging contains no I/O, commit, or registry
mutation between the snapshot and frame construction. A direct test uses a
nonzero offset and verifies that staging neither advances it nor records sent
bytes.

Ten alternating fixed-binary CPU-0 pairs measured 1,213.699-1,245.951
ns/staging before and 1,010.843-1,135.826 ns/staging after. Median cost fell
from 1,217.593 to 1,019.589 ns (16.3%, 1.19x), with checksum 52,761,600,000 in
every 300,000-iteration run. Baseline SHA-256 was
`cf3c9d71c20908aab6c33e4f7b9ce457a9a7ffb08e204344c2def43ed271c1a0`;
candidate SHA-256 was
`60ac76743f1574180f8a4653302a2c101be1cc445fe129cbf042e58534aead2c`.
This is an internal staging CPU result, not an end-to-end throughput or
cross-library claim; the existing UDP-backed 64-stream benchmark remains the
appropriate system-level guard and remains susceptible to this host's receive
queue bimodality.

## WebTransport versus wtransport, same application shape

The external wtransport gate now has a separate benchmark mode that leaves its
existing correctness conversation unchanged. Run both implementation-role
directions on separate CPUs with:

```sh
zig build bench-webtransport-wtransport -Doptimize=ReleaseFast -- \
  --mode=stream --warmup=20 --iterations=5 --streams=1 \
  --bytes-per-stream=4194304 --chunk-bytes=16384 \
  --stream-window=1048576 --timeout-ms=30000

zig build bench-webtransport-wtransport -Doptimize=ReleaseFast -- \
  --mode=datagram-pingpong --warmup=200 --iterations=5000 \
  --payload-bytes=32 --timeout-ms=30000
```

The runner selects two CPUs from its current affinity mask and pins the client
and server separately. Each pair performs a real QUIC v1/TLS/HTTP/3 CONNECT,
with every netz endpoint running on zio behind `std.Io` and the Rust peer using
its Tokio multi-thread runtime over wtransport/Quinn. Config, result,
server-completion, traffic, and memory records carry `client_io` and
`server_io`; the strict verifier rejects legacy or mismatched identities,
requires one config from each endpoint, validates the complete configured
shape, and recomputes stream throughput. Each pair then
opens one dedicated bidirectional WebTransport control stream, and validates
the fixed big-endian `CONFIG`/`CONFIG_ACK` exchange before timing. Stream
rounds open and associate every data stream before `ROUND_READY`/`GO`; the
sender writes deterministic bytes in the configured application chunks and
stops its timer only after the receiver has checked every byte and FIN and
returned checksum-bound `ROUND_DONE`. The sender then returns `ROUND_ACK`, the
receiver emits an empty reverse FIN on every data stream, and the sender
verifies those FINs before starting the next round. Reverse-half work therefore
cannot be coalesced into the timed `ROUND_DONE` packet, and bidirectional stream
lifecycle/credit is not leaked across warmups. The harness sets both QUIC
MAX_STREAMS and netz's
legacy WebTransport stream SETTINGS from the total configured workload rather
than relying on the default 16-stream cap. DATAGRAM
latency keeps exactly one request outstanding and stops each sample only after
receiving and byte-checking its matching echo. Warmups follow the same path but
are excluded from reported samples. Stream mode closes the workload with
`BENCHMARK_DONE`/`BENCHMARK_ACK`; DATAGRAM mode binds those messages to the
aggregate byte count and checksum. The client then sends
`CLOSE_READY`, receives `CLOSE_ACK`, finishes its control-stream send
direction, and requires the server FIN; the server symmetrically requires the
client FIN before finishing its direction. Netz flushes the pending transport
ACK after observing the peer FIN. Thus success and traffic snapshots no longer
depend on the former 100 ms sleep. No QUIC close frame is part of the
measurement or its success condition, preventing a transport close from
overtaking the result boundary. `--timeout-ms` bounds handshake, control, and
receive operations. Each stream round also creates one absolute awake-clock
send deadline after `GO`; every netz payload chunk and FIN reuses that timestamp.
The Rust sender uses the equivalent Tokio instant for every `write_all` in the
round. The runner's independent 180-second process deadline remains an outer
watchdog rather than the stream sender's only bound.

Output uses stable `key=value` lines and always records role pair, requested and
effective stream windows, payload/chunk shape, certificate policy, GSO/GRO,
pacing, checksum, and `complete=true`. The harness deliberately reports
`benchmark_scope=same-application-shape`, not equal-wire: both sides use a
1200-byte path MTU, QUIC v1, disabled GSO, matching advertised flow windows,
the same application chunks, and separate CPU placement. Netz explicitly
disables GRO; Quinn opportunistically enables it without a public wtransport
switch, so the Rust output records `gro=implementation-default`. The current
APIs also produce different maximum WebTransport DATAGRAM payloads (1170 for
netz and 1161 for wtransport in the smoke run) and do not expose every ACK or
packet coalescing knob. Userspace UDP accounting below quantifies the resulting
shape, while kernel/interface capture is still required before upgrading this
evidence to a strict equal-wire comparison.

ReleaseFast smoke coverage has passed in both role directions for one and four
streams at 64 KiB per stream and for ten measured 32-byte ping-pongs. The
four-stream rounds verified 262,144 logical bytes, four FINs, and checksum
33,423,360 on both receivers; ping-pong verified checksum 32,178. These short
runs establish harness correctness only and are not retained as performance
claims.

A 2026-09-15 zio migration smoke used two 64-KiB streams, one warmup, and three
measured rounds in both role pairs, followed by three measured 32-byte
DATAGRAM round trips. Each stream pair verified 393,216 aggregate bytes and
checksum 50,135,040; each DATAGRAM pair verified 128 bytes including warmup
and checksum 10,166. Both netz endpoint roles ended with `live_bytes=0`, and
the available whole-process RSS source was labeled `busybox-time-maxrss`. A
separate 32-stream churn gate passed loss and pair reordering in both sender
directions with 16 FINs, 16 resets, 266,240 bytes, checksum 33,945,600, reset
mask `0x00000000aaaaaaaa`, and code sum 262,400. These are functional and
evidence-pipeline gates, not performance comparisons.

The historical pre-zio CPU-0/client, CPU-1/server run used 20 warmups plus five
measured iterations and explicitly gave the netz endpoint the RFC 9000-style
local ACK policy of one ACK per two ack-eliciting packets or 25 ms, while
preserving an immediate ACK for reordering gaps of three packets. Five runs
(25 samples per role pair) measured 141.489-145.081 MiB/s with the wtransport
client sender and 207.671-210.863 MiB/s with the netz client sender. Four 4-MiB
streams measured 80.14-83.35 MiB/s and 194.44-195.46 MiB/s respectively; every
sample verified 16,777,216 bytes, four FINs, and checksum 2,139,095,040. The
five 200-warmup/5,000-sample 32-byte DATAGRAM ping-pong runs measured
wtransport-client p50/p90/p99/p99.9 ranges of 28.815-29.549 /
32.002-33.843 / 34.706-36.471 / 38.404-42.725 us and netz-client ranges of
29.632-29.804 / 33.207-33.807 / 34.536-35.829 / 37.897-39.480 us, with
checksum 15,084,056 in both directions. These are same-application-shape
cross-process samples, not equal-wire ratios or whole-library superiority
claims. They were captured with the former `std.Io.Threaded` netz harness and
must not be cited as current zio performance.

Five historical order-alternated A/B pairs isolated the ACK-policy change.
Both arms used the same benchmark code, workload, CPU assignment, and
`--traffic` instrumentation; A passed `--netz-ack-every=1` and
`--netz-max-ack-delay-us=0`, while B passed `--netz-ack-every=2` and
`--netz-max-ack-delay-us=25000`. Pair order alternated A/B then B/A to reduce
time-order bias. For wtransport-client + netz-server, median stream throughput
rose from 113.135 to 142.935 MiB/s (26.3%) and complete-connection datagrams
fell from 180,658-180,752 to 135,855-136,226 (about 24.8%). The opposite role
pair's median remained effectively flat, 209.520 versus 209.068 MiB/s, as
expected because wtransport remains its receiver. This is a benchmark-local
policy selection through the public handshake configuration; the library
default remains the conservative one-packet/zero-delay behavior.

Both modes also accept `--stats`. Only this opt-in path enables the netz
counting allocator, builds the Rust peer with its system-allocation wrapper,
and wraps all four processes with GNU time. The strict verifier requires the
exact number of stream sample records (or one DATAGRAM percentile record), one
separate server-completion record, and two memory records per role pair. It
independently reconstructs stream and DATAGRAM checksums, so memory output
cannot substitute for application completion. Three historical pre-zio
default-shape runs recorded the following whole-process peak RSS:

| Mode | Implementation | Endpoint role | Process peak RSS (KiB) |
|---|---|---|---:|
| 1 x 4 MiB stream upload | netz | client/sender | 10,240 |
| 1 x 4 MiB stream upload | wtransport | client/sender | 11,520-11,776 |
| 1 x 4 MiB stream upload | netz | server/receiver | 4,352 |
| 1 x 4 MiB stream upload | wtransport | server/receiver | 6,144-6,400 |
| 32-byte DATAGRAM ping-pong | netz | client | 3,840 |
| 32-byte DATAGRAM ping-pong | wtransport | client | 6,144-6,400 |
| 32-byte DATAGRAM ping-pong | netz | server | 3,840 |
| 32-byte DATAGRAM ping-pong | wtransport | server | 6,144 |

For the stream shape, netz client/server peak explicit live bytes were
6,522,634-6,523,146 and 570,488-871,368; the wtransport client/server peak
requested live bytes were 8,456,194-8,518,298 and 3,252,091-3,253,272. For
DATAGRAM ping-pong, the corresponding netz peaks were 95,067-95,092 and
55,651-55,721, while wtransport reported 3,166,100-3,166,168 and
3,154,072-3,154,140. All four netz runs in every repetition ended at zero
explicit live bytes after complete WebTransport/HTTP/3/QUIC/runtime teardown.
Rust retains about 2.2 KiB of process-global requested allocations after the
Tokio runtime is dropped; this is not treated as a leak. Whole-process maximum
RSS is the cross-language metric, and the differently scoped allocator
counters are not used as a cross-language ratio. These memory observations
retain the same `same-application-shape` boundary as the timing results.

The historical `--traffic` pass was a separate opt-in because netz's
thread-safe endpoint counters add atomic work. It joined one complete-connection
record from each endpoint after handshake, all warmup and measured work, the
benchmark
acknowledgment, `CLOSE_ACK`, and the bidirectional control-stream FIN exchange.
Netz reports successful socket I/O;
wtransport reports Quinn `ConnectionStats.udp_tx/udp_rx`. Both count UDP
payload bytes without IP/UDP headers and logical datagrams under GSO/GRO, but
this is userspace evidence rather than kernel/interface capture. Three default
runs recorded:

| Mode / role pair | Total UDP payload bytes | Total logical UDP datagrams |
|---|---:|---:|
| stream, wtransport client + netz server | 110,476,141-110,567,252 | 135,893-135,972 |
| stream, netz client + wtransport server | 108,986,418-109,001,281 | 114,967-115,318 |
| DATAGRAM, wtransport client + netz server | 827,115-827,122 | 15,623 |
| DATAGRAM, netz client + wtransport server | 826,649-826,651 | 15,625 |

The stream connection transports 25 total 4-MiB application rounds (20
warmups plus five measured). Its 1.47-1.58 MB total-payload and roughly
20.6-21.0 thousand datagram differences show that ACK/control traffic and packet
scheduling are materially different even though the application shape matches.
The DATAGRAM shapes are much closer but still not byte-identical. Endpoint
observation deltas were non-negative; Quinn-client/netz-server stream runs had
664-739 client tail datagrams (794,934-885,638 bytes) not yet observed when the
server snapshot was taken, while the reverse role pair differed by one final
1200-byte client datagram and zero to three server datagrams (0-101 bytes).
These timing-boundary deltas are printed rather than hidden. `--traffic` and `--stats` must run
separately, and neither changes the ordinary benchmark path.

### zio timed-I/O waiter fast path

On 2026-10-10, fixed `ReleaseFast` binaries isolated the zio timed-I/O change
while keeping the netz source at `0bf9d383`. The baseline used zio
`3c23d1c36024fb9a1bc22d27a388f097b99a3a5f`; the candidate used the pushed
`passchaos/zio` commit `4f12748e34c86f39560c03414c062b0705d99acd`.
The candidate lets a runtime task wait directly on its I/O completion's
`Waiter` timer instead of constructing the generic two-member `Group(.race)`.
The no-task and non-suspending fallbacks are unchanged, and timeout or external
cancellation still cancels the I/O completion and waits for that cancellation
to converge before returning.

The MQTT QoS 2 matrix pinned the driver to CPU 5, the broker to CPU 7, and the
2-ms RSS sampler to CPU 13. Each shape used five paired samples with AB/BA order,
1,000 warmup publishes, 10,000 measured publishes, persistent 3,600-second
Sessions, and exact delivery/checksum verification. A pair was accepted only
when its complete lifetime had no competing Zig compiler; balanced 32x32 and
4-KiB results were reacquired pair by pair after unrelated host compilation
invalidated the original tails. Ratios below are candidate/baseline, so higher
throughput and lower latency are better:

| Shape | Throughput paired median (range) | p50 ratio | p99 ratio | Result |
|---|---:|---:|---:|---|
| serial, 1 publisher / 1 subscriber | 1.0584x (1.0373-1.0957x) | 0.9210x | 0.9677x | positive |
| publishers-32 | 0.9973x (0.9880-1.0026x) | 1.0040x | 1.0020x | neutral |
| fanout-32 | 1.0110x (1.0029-1.0348x) | 0.9551x | 0.9358x | positive |
| balanced-32x32 | 1.0010x (0.9785-1.0062x) | 0.9892x | 0.9929x | neutral |
| 4-KiB payload, 4x4 | 1.0176x (1.0041-1.0345x) | 0.9476x | 0.9430x | positive; 5/5 pairs |

The broker baseline/candidate and shared driver SHA-256 values are
`9a0ae6df6a55ebc8f671c657860c7f36e9c6dfcc2c0a59dff94e24b70d601f57`,
`676f8742a2f2da042e4709faa0b92c446cb9a324ab2ad56f184d0cfe9372d691`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
The paired records are retained under `zig-out/mqtt-timed-wait-ab`,
`zig-out/mqtt-timed-wait-balanced-pairwise`, and
`zig-out/mqtt-timed-wait-large-pairwise`. Sampled RSS moved in both directions,
so this experiment supports no memory claim.

Seven additional order-alternated, CPU-0 pairs covered encrypted and framed
MQTT transports with their existing complete-message checks. MQTT-over-
WebSocket measured a 1.0053x paired throughput median over a 0.9914-1.0134x
range and won 6/7 pairs. Native MQTT-over-TLS measured 0.9998x over
0.9931-1.0082x and won 3/7, which is explicitly neutral. The WebSocket
baseline/candidate binary hashes are
`1967543d017dcfc69af50b653a2304f039a770ad130daea03e44267fd5cdd046` and
`cd1b297483d6932bc56a0aa793ebf8b09b0a576c42e14f0d8d585ffd594dcb0c`;
the TLS hashes are
`85f11b504518e86f2b1716c73acf1dd78cbbb9909209d47208cefc16ce6ce639`
and `11851ec7bcf2733495009403ce0c55c2f63a43713b8d8b13672b1b6300398817`.

Matched broker `perf` captures explain the targeted change. The table reports
self-sample percentages, not absolute CPU time; percentages can rise when the
candidate completes sooner, so only the disappearance or movement of the
specific call path is used as structural evidence:

| Symbol | Baseline self | Candidate self |
|---|---:|---:|
| `common.timedWaitForIoClock` | 3.11% | 0.48% |
| `ev.completion.Group.groupCallback` | 0.33% | absent |
| `ev.loop.Loop.cancelLocal` | 1.26% | absent |
| `common.Waiter.timedWaitClock` | absent | 2.64% |
| `runtime.loopClearTimer` | absent | 2.43% |
| `ev.loop.Loop.addInternal` | 3.65% | 2.74% |
| `__kernel_clock_gettime` | 12.62% | 16.35% |

The clean 100,000-publish candidate profile completed 100,000 deliveries with
checksum 25,725,000 at 20,601 publishes/s, 38,463-ns p50, and 49,565-ns p99.
The old `Group.groupCallback`/`Loop.cancelLocal` target overhead is gone; the
remaining timer insertion, waiter, clear, and clock costs identify the next
runtime-level optimization boundary.

A follow-up zio change at
`aa1a91f768f4ff9ae92c9937c6b8ef5d0d0e8851` removed the remaining redundant
clock read when `Loop.setTimer` receives an already absolute deadline. Relative
durations still refresh their origin, while every poll refreshes the snapshot
before comparing either kind of timer. A 10,000,000-iteration CPU-thread-time
microbenchmark of absolute `setTimer` plus `clearTimer`, pinned to CPU 0 and
alternated for seven pairs, moved from a 133-ns/op baseline median to 61 ns/op;
the paired candidate/baseline median was 0.4656x over a 0.4511-0.4812x range,
with 7/7 wins. This measures the timer arm/disarm primitive, not end-to-end I/O.

The same fixed MQTT broker/driver binaries were run for five AB/BA pairs with
the broker and driver isolated on CPUs 10 and 11, outside the concurrent build's
`0-9,12,13` affinity. Candidate/baseline throughput paired medians were 1.0042x,
1.0122x, 1.0037x, 1.0046x, and 1.0074x for serial, publishers-32, fanout-32,
balanced-32x32, and 4-KiB payloads respectively. The result is positive to
neutral across complete application shapes; it is not presented as a 0.4-1.2%
general throughput promise. The baseline and candidate broker hashes were
`676f8742a2f2da042e4709faa0b92c446cb9a324ab2ad56f184d0cfe9372d691`
and `74cff6622c25318b1d0f6c6fb45a4056af6fcdcb282d049b8fc0a5a2e5959d53`.
A matched 100,000-publish candidate profile completed at 21,117 publishes/s,
37,723-ns p50, and 45,668-ns p99. `__kernel_clock_gettime` self samples fell
from 16.35% to 11.54%, and its former 6.17% child path below
`Waiter.timedWaitClock` disappeared completely; remaining samples come from
the event-loop poll snapshot. As above, percentages from different-duration
profiles are explanatory call-path evidence rather than absolute CPU ratios.

The zio dependency is subsequently pinned to
`1b258ef7bd2042b1eb04c34c2ebbc522f118635d`. Its new `Runtime.stackMetrics()`
snapshot separates the configured 8-MiB per-coroutine virtual ceiling from the
256-KiB initial committed extent, and reports active/retained stacks, peak
concurrency, the largest observed per-stack commit, and total virtual address
space reserved by the pool. Netz exposes the same values through
`runtime.Backend.stackMetrics()` without leaking a zio-specific type into its
runtime facade. POSIX stack growth updates the high-water counter only when a
guard fault expands committed pages; ordinary coroutine yields do not acquire
a lock or update a counter. This provides workload evidence for future stack
limit tuning instead of treating virtual reservation as RSS.

An attempted follow-up that bypassed the timer mutex whenever the resuming
task happened to run on the timer's loop was rejected before commit. Its
isolated five-million-iteration arm/clear primitive fell from 60.43 to 27.84
ns/op, but zio's existing `multi-executor: timeout cancel racing a cross-loop
readiness edge` test reproduced pairing-heap corruption. Other executor threads
may still mutate a loop's timer heap while servicing cross-loop socket state,
so pointer equality is not an ownership proof. A future linked-timer design
must route removal back to the timer owner and acknowledge it before releasing
stack storage; the mutex remains in production.

MQTT packet framing now carries the already validated `FixedHeader` beside the
complete packet length. TCP read-ahead, uninterrupted owned TCP reads,
TLS-backed stream reads, and WebSocket aggregation reuse that result instead of
decoding Remaining Length again when constructing `OwnedPacket`. A TCP body
resumed by a later call deliberately reparses its retained header rather than
growing per-connection state for an uncommon path. Five fixed-binary,
CPU-10/11, order-alternated QoS 2 pairs measured candidate/baseline throughput
medians of 1.0046x, 1.0022x, 1.0041x, 0.9989x, and 1.0008x for serial,
publishers-32, fanout-32, balanced-32x32, and 4-KiB payloads. The ranges
overlapped, so this is a deterministic duplicate-work removal with no broad
throughput claim. In matched 100,000-publish profiles, the former 1.33%
`FixedHeader.parse` child path below `readTcpPacketWithPolicy` disappeared;
the remaining `FixedHeader.parse` samples come from outgoing validation and
packet-specific parsing. Baseline broker, candidate broker, and fixed driver
SHA-256 values are respectively
`74cff6622c25318b1d0f6c6fb45a4056af6fcdcb282d049b8fc0a5a2e5959d53`,
`7555c1775b84778f985c69e411f7e52a1761151a3be72493a6df395182b41975`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
The complete A/B and profile artifacts are retained under
`zig-out/mqtt-fixed-header-ab` and `zig-out/mqtt-fixed-header-profile`.

A follow-up lets the public PUBLISH and publish-acknowledgement decoders accept
an already bounded payload plus the framing metadata. Their ordinary whole-
packet `parse` entry points retain complete independent wire validation, while
the broker uses the preframed form only after `OwnedPacket` construction and
connection-level flag/direction checks. Against the framing-only baseline,
five fixed-binary CPU-10/11 pairs produced throughput medians of 1.0088x,
1.0135x, 1.0025x, 1.0003x, and 1.0002x in the same five-shape order. Ranges
still overlap, so this is again recorded as deterministic work removal rather
than a general throughput claim. In the matched 100,000-publish profile,
`FixedHeader.parse` fell from 1.64% to 0.66% self samples and its remaining
samples came only from outbound packet validation; receive-side PUBLISH and
PUBACK/PUBREC/PUBREL/PUBCOMP decoding no longer reparses the header. The
framing-only baseline broker, final candidate broker, and fixed driver hashes
are respectively
`7555c1775b84778f985c69e411f7e52a1761151a3be72493a6df395182b41975`,
`51866c4694a3fc96d28491d5d5204f103b97ecb88ccf7acff32ed45ecccf3253`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Artifacts are retained under `zig-out/mqtt-payload-parse-ab` and
`zig-out/mqtt-payload-parse-profile`.

The next stage separates codec-produced output from arbitrary or restored raw
packet bytes. Internal CONNECT, CONNACK, publish acknowledgement, subscription,
PING, DISCONNECT, and AUTH writers now pass their compile-time-known packet type
to a private transport helper, retaining direction, authentication-state,
peer-size, deadline, and transport-failure checks without reparsing bytes they
just encoded. Public Session packet injection and restored wire bytes continue
through the fully validating `writePacket` path. Against the preframed-parser
baseline, five fixed-binary CPU-10/11 QoS 2 pairs produced throughput medians
of 1.0101x, 1.0006x, 0.9989x, 1.0238x, and 1.0053x in serial,
publishers-32, fanout-32, balanced-32x32, and 4-KiB order. The ranges overlap,
so this is retained as a validated removal of duplicate work rather than a
general throughput claim. A matched 100,000-publish profile no longer contains
`FixedHeader.parse`; the preceding profile attributed its remaining 0.66% self
samples solely to outbound `Connection.writePacket`. Baseline broker, candidate
broker, and fixed driver SHA-256 values are respectively
`51866c4694a3fc96d28491d5d5204f103b97ecb88ccf7acff32ed45ecccf3253`,
`dccf66204cdb25779951c4ae42a2fd37085710d8e45e69b98b972addceeb2836`,
and `30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Artifacts are retained under `zig-out/mqtt-generated-write-ab` and
`zig-out/mqtt-generated-write-profile`.

Durable MQTT Sessions now maintain the number of PUBLISH packets that have
been selected on the current Network Connection and still consume the peer's
Receive Maximum. Selection, write rollback, acknowledgements, expiry, policy
drops, QoS capping, reconnect and snapshot restoration update that bounded
`u16` state directly; `drainInto` no longer performs a separate full inflight
scan just to reconstruct the window. The value is also exposed as
`outgoing_publish_window_used` in per-Session and aggregate statistics. A
state-machine regression covers staged and immediate PUBLISH, repeated
rollback, PUBACK, positive and negative PUBREC, PUBREL/PUBCOMP, expiry,
discard/drop, QoS-0 completion, reconnect and snapshot restore.

The matching `bench-mqtt-session` workload fills one Session with 16,384 sent
QoS 1 PUBLISH packets, then measures an empty drain while the peer window is
full. Seven CPU-11 order-alternated fixed-binary pairs were used; each binary
reports the median of seven 2,000-iteration samples. The baseline ranged from
62,516 to 67,720 ns/drain with a 62,906-ns median, while the candidate ranged
from 37,825 to 38,896 ns/drain with a 38,136-ns median. The paired
candidate/baseline median was 0.6058x (0.5615-0.6161x), with 7/7 candidate
wins. Baseline and candidate SHA-256 values are respectively
`c75fb096d91278f9d3e28f65591afddd640fc2231a552a9a1898a0d03898947c`
and
`9b07284286954637503a3f2bdd0e1fb941525647985c4acf572a5dddd4fc76e2`;
the identical benchmark source hashed to
`c0d0c5d21a710b8233f12acb28ced62895da915e0bf919dab89cab71a52b196b`.
This proves removal of one redundant O(n) accounting scan, not that the whole
drain is O(1): the remaining pass still searches for pending retransmissions.
Artifacts are retained under `zig-out/mqtt-session-count-ab`; the result-table
SHA-256 is
`fc73ae84ba56f2055cf89e06f8fb75fc8e7dd778f862030a377c9a8d7d02b73e`.

A fixed-binary end-to-end control then ran five AB/BA pairs of all five durable
QoS 2 broker shapes with the server, client and sampler pinned to CPUs 10, 11
and 13. All 50 arms completed their exact delivery counts and checksums.
Candidate/baseline throughput paired medians were 0.9993x, 1.0080x, 0.9886x,
1.0043x and 1.0034x for serial, publishers-32, fanout-32, balanced-32x32 and
4-KiB payloads. These ordinary windows of 1, 4, 4, 4 and 16 are neutral, as
expected for an optimization aimed at large retained inflight sets. Baseline
broker, candidate broker and fixed driver hashes are respectively
`dccf66204cdb25779951c4ae42a2fd37085710d8e45e69b98b972addceeb2836`,
`01aaa15bbe71548cf964ae1e42938cf523f1b9303a02d3309bfc3bc9f1879982`
and
`30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
The complete 63,817,477-byte artifact is retained under
`zig-out/mqtt-session-count-broker-ab`; its result-table SHA-256 is
`b70a9ba65252ed7b20e0f043927e7399a637a2580ed7fa177e0942d27af13a76`.

A follow-up removes the remaining unconditional inflight pass. Each Session
keeps an exact pending-send count and a conservative lowest candidate slot;
selection advances the cursor in slot order, while retry, PUBREC, reconnect
and snapshot restore lower it. A stale low cursor after deletion costs at most
one repair scan and cannot skip work. The same change derives reusable holes
as `inflight.items.len - inflight_count`, replacing the other full-array scan,
and lets immediate publish reject pending older work from the exact count.
Blocked PUBREL and a reconnect with an output buffer smaller than the pending
set have dedicated regressions, and debug statistics validate the count/cursor
relationship against the underlying records.

With the benchmark loop raised to 20,000 iterations and both the Store and
result length passed through `doNotOptimizeAway`, seven CPU-11 alternating
fixed-binary pairs compared the count-only baseline with the cursor candidate.
The baseline measured 40,871-42,504 ns/full-window empty drain with a
42,261-ns median; the candidate measured 9-10 ns with a 10-ns median. The
paired candidate/baseline median was 0.0002366x (7/7 wins). This is structural
evidence that the no-pending path no longer depends on the 16,384-entry
inflight array; the absolute nanosecond value is not extrapolated to socket or
broker throughput. Baseline, candidate, identical source and result-table
SHA-256 values are respectively
`7a1568dffda5e0d7aca38fa2bee30e00c3ae921458572c892c9b8df8d1f024bd`,
`a060a7efd309611eec08911618ef423b9a055f66ae1efe1bd29d4068a40c58be`,
`28f34cda67400c01854506f6dc468743f773877e47fc7c0f282dd4d315faa564`
and
`28e45e17bc7a4cbbb67b4287a367682eb7417f3009a8c685bd125c5f4e3ddcb1`.
Artifacts are retained under `zig-out/mqtt-session-cursor-ab`.

The final fixed-binary durable QoS 2 control again completed all 50 ordinary-
window broker arms with exact delivery counts and checksums. Throughput paired
medians were 1.0035x, 0.9999x, 1.0142x, 0.9982x and 1.0158x in the five-shape
order, with overlapping ranges; the result is neutral/no-regression evidence.
Baseline broker, candidate broker and fixed driver SHA-256 values are
`01aaa15bbe71548cf964ae1e42938cf523f1b9303a02d3309bfc3bc9f1879982`,
`2ce2eddba2b2a8c8911525a94848683926c189a1d11371ace0f56e0b83ed6de7`
and
`30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
The complete 63,819,797-byte artifact is retained under
`zig-out/mqtt-session-cursor-broker-ab`; its result-table SHA-256 is
`8e7178f83b685236db9c8706940f5a8d7e1e7449028bb64e16ed11a9e170963e`.

An ordering audit then found that reusable inflight array holes could put a
newer PUBLISH before older unacknowledged PUBLISH packets during reconnect.
That violates MQTT-4.6.0-1's requirement to resend PUBLISH packets in their
original send order. A deterministic regression first reproduced
`four,two,three` after sending `one,two,three`, acknowledging `one`, and
reusing its slot for `four`; both direct reconnect and snapshot restoration
now produce `two,three,four`. Each inflight record participates in an
allocation-free circular order list. Packet Identifier lookup remains O(1),
and slot reuse keeps its existing allocation-free behavior. The pending-send
cursor walks this stable logical order instead of physical slots. The two
`u16` links fit existing alignment padding:
DWARF reports `Inflight` unchanged at 128 bytes and `Session` unchanged at 400
bytes on the measured aarch64 build.

Seven CPU-11 order-alternated `bench-mqtt-session` pairs against the cursor-only
baseline found neutral common-path cost: resume was 1.000x by paired median,
reconnect drain was 0.9969x, and the full-window empty path remained 9 ns by
candidate median. Allocation counts and live bytes in both fanout modes were
unchanged. Baseline, candidate, identical benchmark source and result-table
SHA-256 values are respectively
`a060a7efd309611eec08911618ef423b9a055f66ae1efe1bd29d4068a40c58be`,
`30ca20381959c8838e234d2c9a7bbdd1b70a8ea19a41c2685a4eceb2bb574992`,
`28f34cda67400c01854506f6dc468743f773877e47fc7c0f282dd4d315faa564`
and
`345fed1b6c6a0707b8efba933c2866ac6400ce4fc34c165f2b9d557ae09900fe`.
Artifacts are retained under `zig-out/mqtt-session-order-ab`.

The final five-pair durable QoS 2 broker control completed all 50 arms with
exact delivery counts and checksums. Throughput paired medians were 0.9994x,
1.0070x, 0.9938x, 0.9854x and 1.0058x in serial, publishers-32, fanout-32,
balanced-32x32 and 4-KiB order. The mixed, overlapping results are recorded as
no broad performance claim; preserving the mandatory retransmission order is
the result. Baseline broker, candidate broker and fixed driver hashes are
`2ce2eddba2b2a8c8911525a94848683926c189a1d11371ace0f56e0b83ed6de7`,
`6577b422bd02b70e89d3ee1f4d57ff9120f10ba3a122d72c759ef6290b7d5bcb`
and
`30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
The complete 63,824,845-byte artifact is retained under
`zig-out/mqtt-session-order-final-broker-ab`; its result-table SHA-256 is
`9492a06a010fff8a9e37641660dd97c11f46f936277fc5abd1b629c59a5807f4`.

Stable logical order made the remaining physical-slot cost independently
visible: `appendOrReuseAssumeCapacity` still searched the complete inflight
array for a tombstone. Inflight storage now uses Packet Identifier zero as its
private free-slot marker and threads free indices through two `u16` fields in
the record's existing tail padding. The active order head owns the free-list
head, so there is no second allocation or larger Session object; removing the
last active record clears the logical array while retaining its capacity. Debug
statistics traverse both circular active order and the free chain, checking
that together they cover every slot exactly once. This also removes the tagged
optional around every entry: fixed-binary DWARF reports each slot falling from
144 to 128 bytes (11.1%, or 256 KiB at 16,384 slots), while `Inflight` remains
128 bytes and `Session` remains 400 bytes.

A new benchmark fills 16,384 inflight records, repeatedly acknowledges the
tail and immediately inserts its replacement, and therefore isolates the old
worst-case tombstone search. Seven CPU-11 order-alternated fixed-binary pairs,
each with seven internal 20,000-operation samples, reduced the median from
15,935 to 147 ns/op. The paired candidate/baseline median was 0.00921x, with
7/7 wins. Resume remained 1.000x, reconnect drain improved to 0.9897x by
paired median, and the full-window empty path remained at 11 ns. Baseline,
candidate, identical benchmark source and result-table SHA-256 values are
respectively
`c31b35218d43bdfdd361cbd17fc5fd3e899a870e8fc0a8443252676e5830d8b6`,
`632cb513fb2ee91603f4b786c96502826ef2c81ece48875e113ccb3faaf44717`,
`8828de18a82e6fcedd5cb94ab6546eaa8152b90852950d4a81a53748bb34d079`
and
`d7db2830160b9503074cc9b4e7c682e8f340d5e8f2a863064d4e3932cca51231`.
Artifacts are retained under `zig-out/mqtt-session-free-slot-ab`.

A CPU-0-pinned 2026-11-19 zio-era smoke of `bench-mqtt-session` recorded resume
102 ns/op, offline queue 395 ns/message, reconnect drain 1,223 ns/session,
independent fanout 308 ns/target versus shared 62 ns/target (16,896 vs 768
allocations; 11,345,920 vs 3,052,544 live bytes), full-window empty drain
8 ns/op, and tail-slot churn 273 ns/op. This refreshes the backend identity and
scenario shape only.

The corresponding five-pair durable QoS 2 broker control completed all 50
arms with exact delivery counts and checksums. Throughput paired medians were
0.9981x, 1.0011x, 0.9941x, 1.0017x and 1.0068x in the five-shape order, with
overlapping ranges and no broad throughput claim. Baseline broker, candidate
broker and fixed driver hashes are
`6577b422bd02b70e89d3ee1f4d57ff9120f10ba3a122d72c759ef6290b7d5bcb`,
`167d13799ab1e98be993fe6a6dcae72d0f506b77b77d64760b22de091c81edd8`
and
`30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
The complete 63,827,365-byte artifact is retained under
`zig-out/mqtt-session-free-slot-broker-ab`; its result-table SHA-256 is
`f2dfc98bba49507efb4861a6db6041784532d6cd08a256d80dd169d65a37e98e`.

The MQTT router now maintains exact active and shared-subscription counts as
part of successful subscribe, replacement, unsubscribe, and bulk subscriber
removal transactions. `Broker.matchRoutesForPublisherLocked` therefore obtains
its safe output upper bound in O(1) instead of scanning the complete
tombstone-preserving subscription array before every PUBLISH. A dedicated
ReleaseFast benchmark used 4,098 live subscriptions and one million count
queries in each of seven CPU-4-pinned, order-alternated fixed-binary pairs. The
baseline median was 2,359,466,335 ns total (2,359 ns/query); the candidate
median was 769,100 ns total (769 ps/query), a 0.0003260x ratio, or about 3,068x
lower latency. Every run produced the identical 4,098,000,000 count checksum.
The baseline, candidate, and result-table SHA-256 values are respectively
`e697e7d8779bd30380bc0a80594af37c93eef2f5e45cb41d83c7b9ae764ffe60`,
`828f22b4e6b18d165ecc49c03e53bdd3b5a29ed52df86e359bb83a1c7aa3863d`,
and `4f51bef06230163d173090cb7aa7215c17fb9373933749ca28c5865624c0eaaa`.
Artifacts are retained under `zig-out/mqtt-router-count-ab`.

A separate seven-pair, fixed-binary fanout-32 durable QoS 2 control pinned the
driver and broker to CPUs 4 and 5, used 1,000 warmups plus 10,000 measured
publishes, and completed 320,000 exact deliveries per arm. Candidate/baseline
paired medians were 1.0007x for throughput, 0.9997x for p50, and 0.9820x for
p99, with overlapping samples. The application-scale result is therefore
neutral; this change is retained for its deterministic removal of an O(n)
operation whose cost otherwise grows with subscription-table history.

The broker receive loop now passes a caller-owned `BrokerEvent` output slot to
the packet reader instead of returning the large tagged union by value. The
original return-value API remains as a compatibility wrapper. Generated
ReleaseFast assembly reduces `ClientTask.runLoop`'s stack frame from `0xa70`
to `0xa00` bytes and removes the intervening groups of 128-bit event copies.
Ownership tests cover a prefixed heap-backed successful event and verify both
one-time release and that a malformed packet rolls back its allocation while
leaving the caller's output value untouched.

Five fixed-binary AB/BA pairs then exercised serial, 32-publisher, 32-subscriber
fanout, balanced 32x32, and 4-KiB durable QoS 2 workloads with the broker,
driver, and RSS sampler pinned to CPUs 10, 11, and 13. All 50 arms completed
their exact delivery and checksum checks. Candidate/baseline throughput paired
medians were 1.0011x, 1.0153x, 0.9989x, 1.0048x, and 1.0028x respectively.
The 32-publisher candidate won all five pairs (1.0093-1.0255x), with p50 and
p99 paired medians of 0.9841x and 0.9842x; the other shapes are treated as
neutral because their ranges overlap, including two noisy balanced samples.
RSS was neutral. Baseline broker, candidate broker, and fixed driver SHA-256
values are
`167d13799ab1e98be993fe6a6dcae72d0f506b77b77d64760b22de091c81edd8`,
`69eb0d455d8df0ea00599399773488e0843576771479b798395c327b28466833`,
and
`30cd02ba439014bb32cf00828a929d2502811573acae629cbc6bc772bb0246ab`.
Artifacts are retained under `zig-out/mqtt-event-out-ab`; the 50-row result
table hashes to
`29f79ec8b05ee30ddcb6f9effb2ae1adc193431063a26ad344003ea8a0872ce5`.

Synchronous durable Session flushing now carries one O(1) snapshot of whether
the locked selection left another unsent transmission. After the selected
packet is committed to the socket, a false snapshot skips the former second
state-mutex acquisition and empty `drainInto` probe. Every producer still
schedules or performs its own flush, so an enqueue racing the socket write
cannot be stranded. The shared durable and transient writer tasks deliberately
retain drain-until-empty behavior; an initial prototype that yielded after each
snapshot regressed fanout throughput and was rejected. The final
`DetachedSessionPacket` remains 112 bytes (120 bytes as an optional return) and
`ClientTask.runLoop` retains its `0xa00` ReleaseFast stack frame.

Seven fixed-binary AB/BA pairs then exercised serial, publishers-32,
fanout-32, balanced-32x32, and 4-KiB durable QoS 2 with the broker/driver on
CPUs 10/11. Candidate/baseline throughput paired medians were 0.9954x,
1.0049x, 0.9982x, 0.9972x, and 1.0025x; every range crossed 1.0 and RSS was
neutral. This is therefore retained as deterministic removal of a redundant
lock/drain operation, not as an end-to-end speed claim. Matched 100,000-message
serial profiles had comparable 5.05/5.10-second durations and zero lost
samples; `Broker.flushSlotLocked` fell from 211 samples (4.35%) to 156 (3.22%).
The baseline broker, final candidate broker, fixed driver, and 70-row result
table SHA-256 values are respectively
`a0c016fd604350fffa6159f54424e54f8e85b40ea1d73fae5e5d75b54747ad01`,
`1361e5914bc49042c228d4b9eaa89af8ab749c378a5d6d1432b0ccfb88539c49`,
`cf09a9b947ceadb34fd8ef12ff90c9c768134c4935095fe8f313b4670b50f618`,
and `3109bfce4a11204a007767aef287a58d40e47c51f39de68a21969250359a1843`.
Artifacts are retained under `zig-out/mqtt-session-tail-probe-sync-final`,
`zig-out/mqtt-current-head-serial-profile`, and
`zig-out/mqtt-session-tail-probe-sync-profile`.

The acknowledgement side now retains the per-connection writer mutex while a
successful PUBACK, terminal PUBREC, or PUBCOMP immediately flushes newly
available durable Session credit. The old path released that mutex after
committing acknowledgement state, then called `flushSlot`, which reacquired the
same mutex before selecting the next packet. The new shared helper releases on
every success/error return but calls `flushSlotLocked` directly when work is
required. Persistence finalize and exactly-once ordering remain unchanged:
durable state is still committed before bytes reach the peer, and the writer
ownership interval now has no interleaving gap. Mosquitto's corresponding
single event-loop handlers likewise update outgoing state and release the next
message without an intervening connection-writer handoff.

Eight CPU-0/client, CPU-1/broker fixed-binary pairs used 1,000 warmups plus
10,000 measured durable QoS 2 serial publishes, window one, 256-byte payloads,
and 3,600-second Sessions. Baseline broker SHA-256 was
`6eb6322b1f97c74cc8ff4fc4f27d2b204507e0c7df2008bf1002ed93ff9eeab3`,
candidate
`c997fe419acaedaab671b786a4fbd8e8cd971f47e2c2ee2786f509768be08974`,
and fixed driver
`94274aac3e3b17cb4a2a34dc851d6808ad6b5ea7f721edf75dc493b0a80cb396`.
All arms completed 10,000 exact deliveries with checksum 2,695,000. Broker
instructions had a 0.998182 paired median (0.182% lower, 7/8 wins), p99 a
0.963928 ratio (3.61% lower, 6/8 wins), while throughput and p50 remained
neutral at 0.998355 and 1.001291 with four and three wins. GNU `size` text fell
256 bytes with unchanged total static size.

Matched 100,000-message profiles had zero lost samples. Their absolute
durations moved 6.984 to 7.088 seconds under host load, so they do not support
a latency claim; explanatory sample shares moved `ClientTask.runLoop` from
10.56% to 10.07% and `Broker.flushSlotLocked` from 2.82% to 2.53%. Debug and
ReleaseFast focused broker gates each passed 47 tests, and the source-locked
Mosquitto packet-sequence gate passed all 1,825 scenarios. The retained result
is the eliminated writer-lock handoff, instruction/p99 support, and exact
protocol/lifecycle coverage rather than closure of the broader durable QoS 2
serial gap.

The broker already reserves `Router.subscriptionCount()` route slots before a
PUBLISH match, but the router still traversed its trie once to count and again
to emit. When no shared subscription exists and caller capacity covers every
live subscription, there is no round-robin cursor or post-count capacity error
to protect. That common normal-subscription path now emits in one traversal;
shared groups, undersized output, No Local filtering, `$SYS`, wildcard edges,
and a trie frontier wider than the 128-node stack keep the original
count-before-commit or exact linear fallback. A direct regression compares the
new full-capacity result with a deliberately bounded count-path result,
including exact and `+` subscriptions, an unmatched entry, and No Local.

Eight fixed-binary durable QoS 2 serial pairs reused the preceding CPU 0/1,
1,000-warmup, 10,000-publish, window-one shape. Baseline broker SHA-256 was
`c997fe419acaedaab671b786a4fbd8e8cd971f47e2c2ee2786f509768be08974`,
candidate
`6e227cf7230b201eb97089f001907c82eb71ad498324e1e4bdde5ff57bb4d0bd`,
and the fixed driver remained
`94274aac3e3b17cb4a2a34dc851d6808ad6b5ea7f721edf75dc493b0a80cb396`.
All 16 arms completed 10,000 deliveries with checksum 2,695,000. Broker
instructions fell by a 0.958415 paired median (4.16%, 8/8 wins), throughput
rose by 1.003569 (0.36%, 5/8), p50 fell by 0.961156 (3.88%, 5/8), and p99 by
0.950137 (4.99%, 6/8). The two broker ELFs have identical GNU `size` totals.

Zero-loss 100,000-message profiles moved `Router.matchTrie` from 2.59% to
1.41% and `ClientTask.runLoop` from 10.07% to 9.69%. Their absolute durations
moved 7.088 to 4.617 seconds under different host load, so only the fixed-pair
results and explanatory call-path shares are retained. Debug/ReleaseFast
router gates passed 62 tests, and focused live routing, No Local, shared-group,
and inbound QoS 2 gates passed 47 tests. The result closes the redundant
normal-route count traversal without changing shared-subscription cursor
semantics.

The zio runtime's task-local timed-I/O path previously submitted the socket
operation and, once it had to park, used a second waiter timer whose completion
had to be cleared after ordinary I/O won. The revised path preserves
already-ready I/O without arming a timer, then directly links a blocking
operation to its deadline. Natural completion removes that timer and wakes the
task; timeout and external cancellation still wait for the underlying I/O to
settle before stack-owned state can be released. A same-deadline regression
also proves that a natural I/O result wins the contested handoff.

Sixteen CPU-0/client, CPU-1/broker fixed-binary pairs used 1,000 warmups plus
10,000 measured durable QoS 2 serial publishes, window one, 256-byte payloads,
and 3,600-second Sessions. Baseline broker SHA-256 was
`6e227cf7230b201eb97089f001907c82eb71ad498324e1e4bdde5ff57bb4d0bd`,
candidate
`abdd898a564795ee1f433d8cc7bd10e9ecbcf250c31b15640f46ddc1d3861eaa`,
and the fixed driver remained
`94274aac3e3b17cb4a2a34dc851d6808ad6b5ea7f721edf75dc493b0a80cb396`.
All 32 arms completed 10,000 exact deliveries with checksum 2,695,000.
Broker instructions fell by a 0.993655 paired median (0.634%, 16/16 wins),
throughput rose by 1.023601 (2.36%, 15/16), p50 fell by 0.983143 (1.69%,
13/16), and p99 by 0.991456 (0.85%, 12/16).

Matched zero-loss 100,000-message profiles completed in 4.791 and 4.591
seconds under the same host session. The baseline's standalone
`Waiter.timedWaitClock` and `runtime.loopClearTimer` symbols accounted for
4.18% and 2.39% of sampled cycles; neither remained a standalone top symbol
in the candidate. Symbol shares are explanatory rather than additive cost
claims, while the fixed-pair instruction result is the retained performance
evidence. zio's complete default suite passed 767 tests with 8 platform skips;
the 17 focused timed-I/O tests passed in Debug, ReleaseFast, single-executor,
pinned, poll, and epoll configurations. Netz Keep Alive tests passed 54/54
across TCP, TLS, and WebSocket, and the source-locked Mosquitto gate passed all
1,825 packet sequences. MQTT's 1.5x Keep Alive limit, zero-disable behavior,
large-packet progress renewal, and resumable fragmented reads are unchanged.

MQTT traffic accounting now separates its concurrency domains as well. Each
Connection has one protocol reader and one externally serialized writer, so
its private received/sent counters use atomic load/store for snapshot safety
instead of four multi-writer read-modify-write operations per Control Packet.
The public immediate aggregate sink retains `fetchAdd` semantics. The broker
uses a deferred sink: `stats()` adds active Connection snapshots to the
already-retired lifetime total under the state mutex, and unregister or an
unadmitted Connection close flushes its final delta exactly once. This keeps
live, rejected, and closed-connection totals while removing the shared broker
counter updates from steady-state packet processing.

A baseline 100,000-publish profile exposed all four local-plus-sink atomic
updates in `recordPacketReceived`; the final profile no longer contains those
per-packet RMW sequences. The retained clean-tree comparison used twelve
CPU-0/client, CPU-1/broker order-alternated fixed-binary pairs, 2,000 warmups,
40,000 measured durable QoS 2 serial publishes, window one, 256-byte payloads,
and 3,600-second Sessions. Baseline broker, candidate broker, and fixed driver
SHA-256 values were respectively
`db90fff072e4d64b42657da515c470f15edcefb780a284a3fa060c1740950638`,
`b952fd18010b0379f44516c98714ff209d1ae83dc86bcd4f419d18e9561e8407`,
and
`9b4753e76193e5a3c41b21a7f2171cc55f1185b17ffe5045c85e0227112795b9`.
All 24 arms completed 40,000 exact deliveries and checksum 10,780,000. Broker
cycles improved by a 1.032222 baseline/candidate paired median (12/12 wins),
instructions by 1.000876 (12/12), throughput by 1.006236 (10/12), and p50 by
1.010936 (11/12). P99 was effectively neutral at 1.001168 with 7/12 wins.

A separate four-pair standard-shape control kept throughput neutral for
fanout-32, balanced-32x32, and 4-KiB traffic, while publishers-32 improved by
a 1.021864 median; cycles improved in all serial, publishers-32, and 4-KiB
pairs. The shorter serial timing samples were noisy despite 4/4 cycle and
instruction wins, so the longer twelve-pair result above is the supported
serial conclusion and no general all-shape throughput claim is made. Debug and
ReleaseFast focused MQTT gates, exact live/offline broker statistics, and all
1,825 source-locked Mosquitto packet sequences pass. Artifacts are retained
under `zig-out/mqtt-traffic-counter-ab`.

The broker receive boundary now also uses the transport's `OwnedPacket`
directly instead of converting it into an identical runtime struct, returning
another validated temporary, and then materializing a `BrokerEvent`. The
caller-output path validates that packet in place and writes the selected event
variant only after all parsing and semantic checks succeed. Compatibility APIs
still return an owned event by value, and failures leave caller output
untouched. `ClientTask.runLoop` therefore reserves one fewer 48-byte packet:
its ReleaseFast stack frame fell from `0xbb0` to `0xb80`, the function body
shrunk 424 bytes, and the broker ELF `.text` fell 1,676 bytes.

Twelve clean CPU-0/client, CPU-1/broker fixed-binary pairs reused the 2,000-
warmup, 40,000-publish durable QoS 2 serial shape above. Baseline broker,
candidate broker, and fixed driver SHA-256 values were respectively
`b952fd18010b0379f44516c98714ff209d1ae83dc86bcd4f419d18e9561e8407`,
`29c945aafe7556c5c92069a066b634f2b621d2cb40bc4f2aa38d98106e5fbefc`,
and
`9b4753e76193e5a3c41b21a7f2171cc55f1185b17ffe5045c85e0227112795b9`.
All 24 arms completed 40,000 exact deliveries and checksum 10,780,000.
Instructions improved by a 1.006130 baseline/candidate paired median with
12/12 wins, throughput by 1.010833 with 9/12, p50 by 1.015487 with 11/12,
and p99 by 1.013144 with 12/12. Cycles were near-neutral at 1.002869 with
7/12 wins and are not claimed as an improvement.

In the four-pair five-shape control, instructions improved in every pair for
every shape: paired medians were 1.005747, 1.004677, 1.007291, 1.008551, and
1.005011 for serial, publishers-32, fanout-32, balanced-32x32, and 4-KiB
traffic. Throughput was neutral to positive outside the deliberately short,
noisy serial control; the longer serial result above is the supported timing
conclusion. The matched candidate profile no longer contains the targeted
validated-packet reconstruction hotspot. Debug and ReleaseFast focused MQTT
gates passed 136 tests, and all 1,825 source-locked Mosquitto packet sequences
pass. Artifacts are retained under `zig-out/mqtt-broker-event-ab`.

PUBLISH prefix generation now carries one validated wire plan from length
preflight into direct encoding. The plan retains the encoded Properties length
beside the public prefix/total lengths, so `writePublishPrefixAssumeCapacity`
does not rescan and revalidate the same list before writing it. Public
`writePublish` and `writePublishPrefix` still perform the complete topic,
payload-format, QoS, Packet Identifier, property-context, duplicate-property,
Remaining Length, and integer-overflow checks before the destination changes.

Sixteen clean CPU-0/client, CPU-1/broker fixed-binary pairs reused the 2,000-
warmup, 40,000-publish durable QoS 2 serial shape. Baseline broker, candidate
broker, and fixed driver SHA-256 values were respectively
`29c945aafe7556c5c92069a066b634f2b621d2cb40bc4f2aa38d98106e5fbefc`,
`22d16d8906d2b6a91c60e0359f359f7dbda1d4525c5911873b406b93e6dc6e4e`,
and
`9b4753e76193e5a3c41b21a7f2171cc55f1185b17ffe5045c85e0227112795b9`.
All 32 arms completed 40,000 exact deliveries and checksum 10,780,000.
Instructions improved by a 1.004498 baseline/candidate paired median with
16/16 wins, cycles by 1.010746 with 11/16, throughput by 1.007156 with 12/16,
and p50 by 1.014379 with 13/16. P99 was effectively neutral at 1.001253 with
10/16 wins.

The matched profile reduced `writePropertiesAssumeCapacity` from roughly 0.62%
to 0.25% of sampled broker cycles and no longer contains a second Properties
length call below prefix emission; percentages from separately timed profiles
are explanatory rather than an absolute CPU ratio. Four-pair standard-shape
controls reduced instructions in every serial, publishers-32, balanced-32x32,
and 4-KiB arm and three of four fanout arms. Their short-run throughput was
mixed and neutral, so only the longer serial timing result is retained. Focused
Debug/ReleaseFast MQTT gates passed 138 tests and all 1,825 source-locked
Mosquitto packet sequences pass. Artifacts are retained under
`zig-out/mqtt-publish-plan-ab`.

Inbound QoS 2 release now carries one awake-clock snapshot from Message Expiry
evaluation into the same publication's route enqueue. The PUBREL path formerly
called `cachedAwakeNow` once while rebuilding the pending PUBLISH and again
inside `routeReleasedPublishMode`; both values belonged to one indivisible
release transaction. Sharing the first timestamp removes the second executor
lookup and also makes expiry and queued remaining lifetime use one exact
instant. Persistence locking, pending-record removal, durable fanout commit,
network dispatch and PUBCOMP ordering are unchanged.

Eight CPU-0/client, CPU-1/broker fixed-binary pairs used alternating AB/BA
order, 2,000 warmups, 40,000 measured durable QoS 2 serial publishes, window
one, 256-byte payloads and 3,600-second Sessions. Baseline broker, candidate
broker and fixed driver SHA-256 values were respectively
`2b547dad2cfc4f2d2300fccb2723ef5fa1a1573a8285f51333c530594f1ba870`,
`4476f64a7266e843166480e059bde502b34afb69051e367a64b4f5ba4bab9bd6`,
and
`df965444715c19f38772a6c5b204f60ee5951605a08e0e84d14c2805350988d6`.
All 16 arms completed 40,000 deliveries with checksum 10,780,000. Broker
instructions improved by a 1.002510 baseline/candidate paired median with 8/8
wins and cycles by 1.007600 with 8/8 wins. Throughput, p50 and p99 were mixed,
with median improvement ratios of 0.995647, 0.994381 and 0.992960; no timing
improvement is claimed.

Two-pair controls for publishers-32, fanout-32, balanced-32x32 and 4-KiB
payloads reduced instructions by paired medians of 1.0039x, 1.0057x, 1.0036x
and 1.0054x. Cycles and timing were mixed, including a deliberately noisy 4-KiB
p99, so the retained result is only the deterministic removal of one clock
lookup from each released QoS 2 Application Message. Result-table SHA-256
values are `d644ad525235eb760b351e2d62927584c6922a0d8703efc5ff7b0b03dc804839`
for serial and `3b4d56cb9ba61226ec1625176ec9d644a211546e22e8dc555f25570e19ba7b22`
for controls. The zero-loss current profile report hashes to
`58e97db685f41e1dcc1921f9fe4a185fe75141e0d5208b62dc2aedf9beed3083`;
artifacts are retained under `zig-out/mqtt-qos2-release-clock-ab`.

MQTT Control Packet types occupy every non-zero value of their four-bit wire
field. `packetTypeFromFirstByte` now rejects zero first and converts 1 through
15 directly, instead of calling the generic `std.enums.fromInt` lookup whose
failure path was unreachable for a `u4`. Exhaustive tests bind every enum field
to its high nibble and preserve reserved-type-zero error precedence before
Remaining Length validation. No accepted or rejected wire value changes.

Eight CPU-0/client, CPU-1/broker fixed-binary pairs reused the 2,000-warmup,
40,000-publish serial durable QoS 2 shape and the fixed driver above. Baseline
broker, candidate broker and driver SHA-256 values were respectively
`4476f64a7266e843166480e059bde502b34afb69051e367a64b4f5ba4bab9bd6`,
`5c981574d1a0720f164fb47c8a2b770c5ce95c4f8100ec21a29170088f8facdf`,
and
`df965444715c19f38772a6c5b204f60ee5951605a08e0e84d14c2805350988d6`.
All arms completed 40,000 exact deliveries with checksum 10,780,000. Broker
instructions improved by a 1.009357 baseline/candidate paired median with 8/8
wins and a narrow 1.008045-1.010145 range. One candidate arm encountered
severe host noise, so cycles, throughput and latency receive no improvement
claim despite their otherwise positive medians.

Two-pair publishers-32, fanout-32, balanced-32x32 and 4-KiB controls improved
instructions in every arm, with paired medians of 1.0075x, 1.0221x, 1.0124x
and 1.0092x. Timing and cycles were mixed under host load. A zero-loss
100,000-message candidate profile no longer contains the targeted generic enum
lookup above `packetTypeFromFirstByte`; its report SHA-256 is
`51b88a9f963cad1aa44a503f2aae96f42c28dcac07948d9acdc4b7640ca0bac2`.
Serial and control result tables hash to
`3ee4c77d93230c5400455d4df8c28086c37f2e3d8c9a536c07afb50ec93a6395`
and `a6ccde70321e832e8f4260b4a194849975e76d8f7792d497f34a59d194571480`;
artifacts are retained under `zig-out/mqtt-packet-type-direct-ab`.

The acknowledgement decoder now handles a complete two-byte payload directly.
After packet-type and flag validation, an MQTT 3.1/3.1.1/5 PUBACK, PUBREC,
PUBREL, or PUBCOMP containing only its non-zero Packet Identifier has an
implicit Success reason and no properties, so it need not construct the
general reason/property cursor path. Explicit reasons, an encoded Property
Length, properties, trailing bytes, and short payloads retain the original
decoder. MQTT 3.1 PUBREL also retains its retransmission bit. This follows
Mosquitto's corresponding `remaining_length > 2` reason and `> 3` property
split. `AckPacket.parsePayload` shrank from 788 to 760 ReleaseFast bytes; the
whole broker ELF size was unchanged.

Eight fixed-binary AB/BA pairs pinned the client and broker to otherwise-idle
CPUs 10 and 11. Each arm used 5,000 warmups plus 100,000 measured durable QoS
2 serial publishes, window one, a 256-byte payload, and a 3,600-second Session.
Baseline broker SHA-256 was
`5c981574d1a0720f164fb47c8a2b770c5ce95c4f8100ec21a29170088f8facdf`,
candidate
`be4de343460c12b7f0e46edb27a273da1c491715435850239d3f9be4b34677a6`,
and the fixed driver
`df965444715c19f38772a6c5b204f60ee5951605a08e0e84d14c2805350988d6`.
All 16 arms completed exactly 100,000 deliveries with checksum 25,725,000.
Broker instructions improved by a 1.002076 baseline/candidate paired median
with 8/8 wins and a 1.000685-1.002602 range. Throughput, p50, p99, and cycles
had respective improvement medians of 1.000965, 1.008389, 1.004639, and
1.002379, but every range crossed 1.0, so no timing or cycle improvement is
claimed.

Two-pair publishers-32, balanced-32x32, and 4-KiB controls were neutral to
positive in absolute timing and cycles. A longer four-pair fanout-32 control
used 2,000 warmups, 20,000 publishes, and 640,000 exact deliveries per arm;
its throughput, cycles, and instructions medians were 1.001766, 0.998633, and
1.005615 with 2/4 wins and ranges crossing 1.0. It is therefore retained only
as a no-stable-regression control, not a fanout performance claim. Debug and
ReleaseFast exhaustive ACK gates cover all four packet types and 256 reason
values plus the minimal form across all three protocol versions. The selected
Mosquitto wire-vector gate passed 287 scenarios, and the source-locked packet
sequence gate passed all 1,825 scenarios. Raw serial and control artifacts are
under `zig-out/mqtt-ack-minimal-parse-ab`; their manifest hashes to
`e49295cf0e95664c7fe2a16676fcaae7f82e28c3a19a9281fbcc14e6ed9c8987`.

The durable acknowledgement path now hands its already-held broker state lock
directly to selection of the next Session transmission when no live commit log
or persistent-change autosave backend is enabled. The writer lock was already
retained across this boundary; the old in-memory path nevertheless unlocked
the state mutex after PUBACK, terminal PUBREC, or PUBCOMP, ran a persistence
finalizer that had no configured work, and immediately reacquired the same
mutex in `flushSlotLocked`. Manual snapshots use that mutex and therefore see
either side of the combined ACK/selection mutation. Enabling a commit log or
autosave keeps the original intermediate durability barrier, so the ACK state
is still persisted before selection and every selected Packet Identifier is
persisted before its bytes can reach the peer.

Eight fixed-binary AB/BA pairs pinned the client and broker to CPUs 10 and 11
and used 5,000 warmups plus 100,000 measured durable QoS 2 serial publishes,
window one, a 256-byte payload, and a 3,600-second Session. Baseline broker
SHA-256 was
`be4de343460c12b7f0e46edb27a273da1c491715435850239d3f9be4b34677a6`,
candidate
`9b7ddbd812b8215084006991ce9f580da2ce364f42bffa121ed832e9230bcaf3`,
and the fixed driver remained
`df965444715c19f38772a6c5b204f60ee5951605a08e0e84d14c2805350988d6`.
All 16 arms completed 100,000 exact deliveries with checksum 25,725,000.
Broker instructions improved by a 1.005394 paired median with 8/8 wins and a
1.004642-1.006132 range. Throughput, p50, p99, and cycles had improvement
medians of 1.005828, 1.010336, 1.003315, and 1.001590, but their ranges crossed
1.0, so no serial timing or cycle improvement is claimed.

Two-pair publishers-32, fanout-32, balanced-32x32, and 4-KiB controls showed
no stable absolute regression. A longer four-pair fanout-32 control used 2,000
warmups plus 20,000 publishes and 640,000 deliveries per arm. Its throughput,
cycles, and instructions improved by medians of 1.012888, 1.046069, and
1.010738, each with 4/4 wins and ranges above 1.0; p50 remained mixed and is
not claimed. Matched zero-loss 100,000-message profiles moved the flush
function's self share from 3.57% to 2.50%. Those independently sampled shares
are explanatory rather than additive A/B evidence. ReleaseFast generation
reduced the flush implementation from 9,080 to 8,696 bytes and broker `.text`
by 704 bytes; `.bss` rose 768 bytes, leaving total static size 64 bytes larger.

Debug and ReleaseFast gates cover the coalesced window-one Session path,
PUBREC/PUBREL replay, transient PUBCOMP accounting, the commit-log ACK barrier,
and an explicit default/autosave/commit-log branch-selection test. The complete
broker-focused test filter, 287 selected Mosquitto wire vectors, and all 1,825
source-locked packet sequences pass. Fixed serial/control artifacts and both
profiles are retained under `zig-out/mqtt-ack-flush-lock-handoff-ab` and
`zig-out/mqtt-ack-flush-lock-handoff-profile`; the combined manifest hashes to
`b2412a946cfc03433990344caee10d52294169c09c52ee52a39d4b93fb3ccb46`.

The production MQTT broker now moves Keep Alive inactivity scheduling out of
each packet read and into its existing lifecycle deadline driver. Standalone
`mqtt.runtime` server APIs retain their per-call timed-read behavior. Finite
and supervised Broker listeners instead install one exact awake-clock deadline
after CONNACK, renew it with one atomic update after every complete Control
Packet, and use an allocation-free progress observer while more than 1,000
bytes remain in a partial large packet. The driver scans stable connection
slots only when a lifecycle deadline wakes it. Its compare-and-exchange claim
cannot override concurrent progress; a stale pre-renewal wake therefore
reschedules instead of closing the connection. Initial installation is
serialized with the driver's slot scan and generation snapshot. TCP, TLS,
WebSocket and WSS all retain the existing 1.5x timeout, zero-disable, large-
packet renewal, control-frame exclusion and ungraceful Will semantics.

This follows Mosquitto `5cd25465`'s `src/keepalive.c` separation of packet
activity from the event-loop timeout check. Netz uses its already allocated
slot table rather than Mosquitto's maximum-Keep-Alive-sized ring. An active
`runtime.Connection` gains one eight-byte atomic deadline and grows from 824 to
832 bytes; the 96-byte preallocated `ClientSlot` is unchanged. The scan is
O(configured slots) per actual/stale lifecycle wake, while packet activity is
O(1), allocation-free, and takes no broker mutex after first installation.

The missing kernel tool was installed as Ubuntu/NVIDIA package
`linux-tools-6.8.0-1021-nvidia-tegra` 6.8.0-1021.21; its binary reports perf
6.8.12 and successfully reads this kernel's user cycles/instructions PMU.
Before implementation, a 4,435-sample zero-loss profile attributed 3.00% self
to `common.timedWaitForIoClock`, 2.52% to `runtime.Executor.loopSetTimer`, and
the timed-read child 2.11% of `ev.loop.Loop.addInternal`. A same-binary
Keep-Alive-zero control reduced broker instructions by roughly 7.5%, selecting
the centralized design. The final 4,351-sample profile contains none of
`timedWaitForIoClock`, `loopSetTimer`, or managed deadline scanning above the
0.5% report threshold; `__kernel_clock_gettime` moved from 16.50% to 12.59%.
Profile percentages are explanatory, not additive A/B evidence.

The retained fixed-binary control used eight AB/BA pairs, CPU 0 for one shared
driver and CPU 1 for the broker, 1,000 warmups, 10,000 measured durable QoS 2
serial publishes, window one, a 256-byte payload, and a 3,600-second Session.
Baseline broker, candidate broker and fixed driver SHA-256 values were
`9559493e4eab6da55d2f99f9ebb383bdb674da6a5bf3ac78409c31e6170cf9c4`,
`34b50eeb85b9602898cd96d89653fde35e310f59aa2bfacf4c14d27c3ab34f6d`,
and `e87cfaf79149cadbf1ef8f5cc4b9b7a6aadde705a60131d975df06702caeeee1`.
Every arm completed exactly 10,000 deliveries with checksum 2,695,000.
Baseline/candidate broker instructions improved by a 1.058698 paired median
(5.54% fewer, 8/8 wins) and cycles by 1.117220 (10.49% fewer, 8/8 wins).
Throughput and latency remained load-sensitive and receive no improvement
claim. The final same-client Mosquitto gate completed 10,000 exact deliveries;
netz remained behind at 22,091 versus 31,651 publishes/s, so this removes one
runtime CPU deficit without closing the broader serial QoS 2 gap. Full data is
in `docs/evidence/mqtt_managed_keep_alive/2026-10-29.json`.

For WebTransport, independently built baseline and candidate binaries each
completed a real QUIC/TLS/HTTP/3 burst of 10,000 1-KiB DATAGRAMs with batch
size 16, maximum 64 in flight, caller-buffer receive, zero timeouts, 10,000
receives, and checksum 921,600,000. Their hashes are
`5da9d9135efab810447d31fa31ff88c5119e104ba085f4421884e2ce45da0b11` and
`36f8a3090d69c6e1731bcddc35547a83668ef23ed13736246742088b1b856eb9`.
External Zig compilation prevented a clean timed pair, so this is deliberately
recorded only as cross-protocol correctness evidence, not an A/B performance
result.

zio's focused runtime-task tests cover natural I/O completion, timeout-driven
cancellation, and external cancellation under the default, epoll, poll,
single-executor, and pinned schedules. Its final complete suite passed 767
tests with 8 platform skips. With the remote dependency selected, Netz's
focused Keep Alive gate passed 54 tests and the Mosquitto packet-sequence gate
passed all 1,825 source-locked scenarios.

