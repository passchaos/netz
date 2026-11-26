# Project-wide optimization review, 2026-11-19

Audited baseline: `425a9e1c99052ff393fa6a920452f8f9f54a8d9d`, branch
`optimize/audit-batch-1`, Zig 0.16.0, Linux x86_64. This is an implementation
and evidence review, with isolated boundary reproductions. It does not claim
an exhaustive line-by-line review or a new full-library/performance result.
The opening findings describe that audit baseline. Implementation progress is
recorded below, with separate acceptance evidence for each completed batch.

The most valuable next work is proxy relay correctness, followed by endpoint
fairness and reusable relay storage. Several codec paths have already received
measured optimizations; their rejected experiments should remain part of the
decision record. Structural work should make the existing owners easier to
audit without introducing another reader or changing public import paths.

## Priority queue

P0 means a confirmed correctness defect; P1 means a
common-path integration defect or a resource/fairness concern; P2 means an
engineering or validation improvement; P3 means a less common optimization.
An observed mechanism is distinguished from an unmeasured performance benefit.

| ID | Priority | Work | Evidence strength |
| --- | --- | --- | --- |
| R1 | P0 | Preserve the complete relay FIFO suffix across QUIC backpressure | Actual Hysteria drain reproduced; identical TUIC code inspected |
| R2 | P0 | Make negotiated rate arithmetic safe and retain fractional credit | Actual ByteBucket assertion failure and Debug overflow reproduced |
| R3 | P1 | Packetize TCP relay chunks before raw QUIC sends | Actual raw QUIC boundary verified; both proxy callers inspected |
| R4 | P1 | Give the shared proxy pump a bounded, fair service turn | Blocking timeouts and unbounded drain loops inspected; latency unmeasured |
| R5 | P1 | Reuse bounded relay payload storage | One allocation/copy per TCP read inspected; throughput unmeasured |
| R6 | P2 | Split large owner responsibilities and public-surface/build tests | File/function counts and build graph inspected |
| R7 | P2 | Unify dependency pins and distinguish current from historical evidence | Local/CI revisions and evidence audit measured |
| R8 | P2 | Complete independent interop and performance coverage | Current parity documents and latest recorded runs inspected |
| R9 | P3 | Offer reusable scratch for deep retained filters | Allocation fallback inspected; workload importance unmeasured |

### Implementation progress

| Item | Current state |
| --- | --- |
| R1 | Shared FIFO owner implemented; first/middle/last/FIN refusal, fatal send and teardown regressions pass. Batch gates complete; acceptance evidence recorded below. |
| R2 | Wide/fractional rate accounting, independent burst limits and committed-prefix charging implemented; shared and single-connection TCP/UDP maximum-rate regressions pass. Batch gates complete; acceptance evidence recorded below. |
| R3 | Exact packet-sized cursor and bounded pre-connect input implemented; both proxy large-body regressions and real socket-prefix/packet-number-width tests pass. Batch gates complete; acceptance evidence recorded below. |
| R4 | In progress: persistent target-writer owner prepared. Integration, fair ready scheduling and mixed hot/idle measurements remain pending. |
| R5 | Pending: reusable relay blocks and allocation/peak-memory/throughput measurements. |
| R6 | Focused protocol roots and a no-matching-test guard implemented. Owner, package-test and build-registration extraction remains pending. |
| R7 | Historical reproducer now replays the audited Git revision. Shared dependency pins and current-evidence index remain pending. |
| R8 | Independent TUIC 128-KiB body and native/quic UDP modes verified. Remaining peer gates, workload matrices and profiles are pending. |
| R9 | Pending: caller-owned/reusable deep-filter scratch and comparative telemetry. |

R1-R3 implementation acceptance is in
[the relay evidence](../evidence/proxy_relay/2026-11-19/evidence.json): 225/225
ReleaseSafe component/proxy tests, six final-source scenarios (55/55 runner
tests including aggregators), and an exact 128-KiB response plus UDP in both
independent sing-box modes. The complete repository gate remains part of the
final R1-R9 audit.

The original R1-R9 scope and acceptance requirements below remain active.

## R1: relay batches lose ownership under backpressure

Locations: [TUIC drain](../../src/proxy/tuic/shared/server.zig),
[Hysteria drain](../../src/proxy/hysteria/shared/server.zig), and
[shared relay queue](../../src/proxy/internal/relay_queue.zig).

`flushRelayOutbound` removes up to eight `Outbound` items from the queue. If
`sendRelayItem` returns false for item k, it stores only that item in
`pending_out` and returns. Items k+1 through the end of the local batch have
already left the queue and have no owner. DATA chunks can be lost and their
allocations leaked; a queued FIN can be lost too. Relay teardown frees only
`pending_out` and items still in the queue.

The isolated probe calls the actual Hysteria method with three queued chunks
and a rate cap that prevents the first send. It observes `input=3 retained=1
orphaned=2`. TUIC has the same drain loop, with congestion, pacing, flow-control
and anti-amplification refusals as its false-return cases. The probe uses
stack-backed chunks to observe ownership without intentionally leaking heap
memory; heap-leak consequences follow from the production reader's `dupe`
and teardown paths.

Use either one-item dequeue with one pending item, or relay-owned batch
storage with a retained cursor. Preserve FIFO order and account for every
item during fatal send errors and teardown. Add production regressions for
first/middle/last refusal, repeated refusal followed by recovery, DATA plus
FIN, exact byte order, and zero live bytes after shutdown. Exercise both
protocols and the actual QUIC refusal modes.

## R2: rate arithmetic, liveness, and commit accounting

Locations: [ByteBucket](../../src/proxy/internal/byte_bucket.zig),
[Hysteria shared server](../../src/proxy/hysteria/shared/server.zig),
[legacy single-connection server](../../src/proxy/hysteria/v3_server.zig), and
[hello codec](../../src/proxy/hysteria/v3_protocol.zig).

Two failures are reproduced directly against ByteBucket:

- `refill` calculates `elapsed * rate` in u64. An accepted wire rate of
  `maxInt(u64)` and elapsed time of two nanoseconds produces an integer-overflow
  panic in Debug. The hello codec accepts u64 rates; with the default unlimited
  server setting, `negotiateRate` selects the client's finite rate. The primitive
  crash is reproduced; a complete authenticated malicious-peer exchange was
  not run. ReleaseFast behavior is not validated by this Debug reproduction.
- `refill` rounds to whole bytes and always advances `last_refill_ns`, losing
  fractional credit. After consuming a one-byte initial burst at one byte/s,
  1,000 polls spaced one millisecond apart yield zero bytes instead of one.

Related integration concerns are visible in the same path. Capacity equals
one second of the rate, while a TCP chunk can be larger than that capacity;
whole-chunk `tryConsume` can never succeed in that case, and the legacy
`wait` cannot accumulate enough tokens. The shared sender consumes tokens
before `trySend` and does not refund a retryable refusal. The receive path
ignores a `tryConsume` result when queuing TCP data, then charges the pending
buffer again when flushing. These accounting/liveness consequences are source
findings, rather than separate end-to-end reproductions.

Use wider intermediate arithmetic or checked/saturating arithmetic with a
defined supported range, preserve fractional byte-nanosecond credit, and
define a burst budget independently of the average rate. TCP output needs a
byte cursor so a low rate can make partial progress. Charge each committed
byte once, preserving credit on failed/retried output. Validate zero/unlimited,
very low and maximum rates, frequent polls, long idle intervals, partial writes,
QUIC backpressure, cancellation, and both Debug and ReleaseSafe arithmetic.

## R3: default relay reads exceed a raw QUIC packet

Both proxy configs default to a 16-KiB TCP read buffer. Their shared
`sendRelayItem` passes the complete read as one STREAM frame to
`endpoint_server.Server.trySend`. That API forwards to one-RTT `trySend`,
which attempts one protected packet and rejects oversized output; it does not
split an application buffer.

The isolated boundary probe uses an actual one-RTT connection with a 4,096-byte
datagram limit and verifies that a 16,384-byte STREAM chunk returns
`DatagramTooLarge`. Both proxy sender branches treat this as a fatal error,
free the chunk and close the relay. The exact maximum can be smaller after
transport negotiation and includes packet/frame overhead. Existing small-echo
tests do not establish correctness for a full default-sized TCP read.

Add a packet-size-aware cursor that queries the connection's current payload
budget, advances offsets only after committed sends, retains the unsent suffix,
and emits FIN only after all DATA. Cover reads of 4/16/64 KiB, changing packet
number widths, low peer datagram limits, flow/congestion refusal halfway through,
and exact TCP round trips against an independent peer. Batch already-valid
packets through the existing endpoint batch API only after ownership is sound.

## R4: shared endpoint fairness

The receive owner is now correct: TUIC and Hysteria share the QUIC endpoint
pump. However, service still walks every connection, association and relay.
Each idle UDP association attempts a receive with a one-millisecond timeout;
each blocked TCP write can occupy up to ten milliseconds. These waits happen
on the pump. Read-ready UDP associations and outbound TCP queues are drained
until empty, with no per-turn item/byte budget. A continuously ready source
can therefore monopolize a turn; N blocked TCP targets can add approximately
N times the write quantum before another connection is serviced. This is a
mechanism finding, not a measured p99 bound.

Move target-socket reads and writes to explicit per-association/relay owners
that publish through bounded queues, or use readiness-aware nonblocking
operations. Keep one QUIC receive owner. Give the pump packet/byte/time budgets
and a round-robin cursor; schedule only ready owners while handling expiry.
Profile mixed hot/idle connections, permanently blocked targets and continuous
UDP producers. Require bounded sibling delay, clean shutdown, and stable
p50/p99, throughput, CPU and allocation metrics against fixed binaries.

## R5: allocation-free relay steady state

`Relay.readerTask` allocates its read buffer once, then duplicates every TCP
read into a new allocation. Both UDP association paths also allocate encoded
packets and free them after each send. A block-cache backend may recycle
backing blocks, but these paths still make allocator calls and copy payloads.
The eight-item queue bounds item count; it does not establish allocation-free
steady state. Inbound storage also compacts consumed bytes with `copyForwards`.

After R1/R3, use a bounded block pool or fixed slots sized from the packet/read
budgets. Ownership must stay with a slot until QUIC has accepted or copied its
data; then return the slot to the reader. Preserve queue and total-byte bounds.
Measure allocation calls per MiB, peak live bytes and throughput for small and
large packets plus backpressure. Use a fail-after-warmup allocator only on
operations whose ownership contract makes zero allocations achievable.

## R6: owner structure and verification costs

The source inventory contains 1,988 Zig files and 862,412 lines including
tests. Already-extracted tests do not explain the largest owner files:

| File | Lines | Indented function declarations | Named test bodies |
| --- | ---: | ---: | ---: |
| `src/http2/runtime/connection.zig` | 15,986 | 588 | 0 |
| `src/quic/one_rtt/connection.zig` | 15,390 | 661 | 0 |
| `src/http3/runtime/handshake_client.zig` | 8,347 | 339 | 0 |
| `src/mqtt/broker/core.zig` | 6,329 | 152 | 0 |

Split coherent operations and their private state into flow/credit, header
assembly, request/response batches, recovery/send, and shutdown/lifecycle
modules. Existing HTTP/2 `Receiver`/`Lifecycle` helpers provide a pattern.
Keep owner-local invariants, explicit context and public re-exports; avoid
exposing every private method merely to enable extraction. Measure compile
time and code size before claiming a build or runtime benefit.

`test/package_test.zig` has 11,611 lines in only 24 named tests, often with
many scenarios inside one test. Split by protocol and public behavior so a
filter can select the smallest reproducible surface. `build.zig` still has
1,065 lines despite its eleven helper modules. Move executable/checker
registrations into existing protocol/build responsibilities. `tools/interop`
has 275 directly tracked files: group stable fixture families and update
evidence path mappings as part of any move.

The current `test-lib` filter compiles a shared package root, and imported
dependency tests can still run. Focused module roots and minimum matched-test
checks would improve iteration and prevent a green filtered command from
being mistaken for coverage of an uninstantiated surface. Keep a final package
and complete-library gate for changes that cross protocol boundaries.

## R7: reproducibility and evidence freshness

The existing evidence gate passes: 288 source-hash-bearing JSON files, 10,797
entries, 6,634 matched, 4,163 stale, zero unresolved, invalid or unreadable.
Historical source hashes are valid historical records, so drift does not prove
a regression and rewriting them to current hashes would destroy provenance.

Add a small current-evidence index per protocol/runtime/host profile that pins
the accepted source revision, dependency revisions, binary hashes and raw
results. Apply strict checks to that index while retaining historical records.
The current auditor also skips missing/wrongly typed source-hash fields; a
schema for acceptance records can prevent incomplete claims from looking valid.

CI repeats seven dependency pins across four job configurations, and the source
archive tool maintains its own constants. Local path dependencies currently
differ from CI for pbz (94 commits beyond the pin), regexz (22), harnessz (2)
and vail (1), all with clean local trees. This proves different inputs, not API
incompatibility. Use one pin manifest plus a local check/bootstrap command;
verify a clean pinned cohort before updating pins. The README's zio commit
description also predates the pin in `build.zig.zon`.

Eight sampler-backed baseline gates are already serialized. Keep timing off
shared compile/test workloads; a dedicated controlled performance job or runner
is more useful than a noisy threshold on generic CI. Record fixed-peer role,
CPU layout, window/chunk policy and full source/dependency hashes.

## R8: protocol coverage and next measurements

| Area | Current evidence / conclusion | Next useful work |
| --- | --- | --- |
| HTTP/1 and unified HTTP | Borrowed parse/SIMD paths and pooled deadline/retirement behavior already covered | Large-body streaming/aggregation and idle-pool churn profiles; preserve ownership/deadlines |
| HTTP/2 and gRPC data plane | HPACK, borrowed frames and batch encoder reuse already optimized; ordinary owned empty exchanges still have two header allocations | Profile retained header ownership, slow-stream fairness and many concurrent RPCs; an owned response allocation alone is not a defect |
| QUIC and HTTP/3 | Precise scratch, prepared certificate compression and recovery work already landed | Current packet/recovery/receive-buffer allocation profiles, connection-count scaling and tail scheduling |
| HTTP/3 comparison | Nov 19 kernel captures complete with zero drops; sender datagram ratios 1.016 upload and 1.005 download, packet-size sequences differ | Treat as the same application shape; isolate fixed-peer A/B and explain ACK/padding/control differences before an equal-wire claim |
| WebSocket | Masking and H1/H2/H3 sliced writes already have evidence | Persistent/mostly-idle and compressed-message reference profiles before more codec micro-tuning |
| WebTransport | Nov 19 native wtransport and churn reruns pass; Chrome rerun passes | Current controlled throughput/memory comparison and broader independent H2 capsule coverage; Firefox snap launch failure is environmental, STOP_SENDING remains separately open |
| MQTT | Latest pinned serial durable QoS2 sample is 1.059x Mosquitto throughput and 0.612x peak RSS; old RSS penalty is not reproduced in that shape | Order-balanced multi-publisher/fanout/QoS/durable/restart matrix; a short serial sample does not establish broad superiority |
| gRPC/xDS | Managed TLS refresh now self-drives; ADS/SDS/delta/LRS and shared ownership have extensive in-repo gates | Repeated rotation/failover with live RPCs, official peers, memory/queue bounds and many-cluster profiles |
| TLS, runtime and internal helpers | Explicit backend, trust policy, prepared/cache and deadline facilities exist | Many-connection stack/crypto/trust cache budgets; keep cryptographic optimization in vail and execution optimization in zio |
| Proxy | sing-box gates exist for Shadowsocks/Trojan/VLESS/VMess/TUIC; Hysteria v3 has no independent current-toolchain peer | R1-R5 first, then payload/backpressure/churn and fixed-binary proxy throughput/RSS comparisons |
| WireGuard / mesh DERP | Bounded codecs/state machines, unit tests and fuzz; no independent peer gate | wireguard-go handshake/transport and DERP peer/churn checks, then codec/crypto/forwarding benchmarks; product policy stays in vpnz/meshz |

Latest evidence pointers:
[HTTP/3 captures](../evidence/http3_equal_wire_capture/2026-11-19/evidence.json),
[MQTT current serial comparison](../evidence/mqtt_qos2_serial_profile/2026-11-19.json),
[Chrome/Firefox rerun](../evidence/webtransport_chrome/2026-11-19-rerun.json), and
[wtransport rerun](../evidence/webtransport_wtransport/2026-11-19-rerun.json).
Protocol authorities remain in [the documentation index](../README.md).

## R9: deeper retained-filter scratch

The retained trie already bounds index bytes, reuses match bitmaps and handles
normal filters without allocation. For filters deeper than 64 levels,
`matchBitsInto` allocates level-end and traversal arrays, with a linear scan
fallback on allocation failure. Offer caller-owned or bounded reusable scratch
if deep-filter workloads matter. Compare shallow and deep selective/wildcard
cases with allocation telemetry; keep exact ordering and the OOM fallback.
This is lower priority than common relay, HTTP and QUIC paths.

## Review validation and execution order

The recorded [review evidence](../evidence/optimization_audit/2026-11-19/evidence.json)
includes reproducible isolated probes and logs. Existing
`zig build test-lib -Dtest-filter='shared endpoint serves' --summary all`
passed 216/216 tests. The targeted ownership and fractional-refill probes fail
their two assertions, and the separate overflow probe aborts in Debug.
The packet-size boundary probe passes by requiring `DatagramTooLarge` from
the actual raw QUIC API. Those are observations of the audited baseline,
not newly introduced failures in the production tree.

The 79 active Markdown documents checked before this addition have no missing
local link targets. No full test, new external interop run or timed benchmark
was performed for this documentation review.

Implement R1-R3 with production regressions first; then combine R4/R5 with
small owner extractions and fixed-binary measurements. R6/R7 can proceed in
separate commits that retain protocol behavior. Refresh the affected independent
gates before broadening performance claims in R8. Keep R9 workload-driven.

## HTTP-family follow-up, 2026-11-26

This follow-up reviews production revision `31febe5a`. Its native Linux and
Windows combined protocol and HTTP/3 socket deadline steps passed. The complete
CI [run 45740784651](https://github.com/passchaos/netz/actions/runs/45740784651)
failed separately in a WebTransport send-flow test and the client CA reload
interop sequence. Scoped results do not close complete acceptance.

| Priority | Remaining work | Current evidence and acceptance boundary |
| --- | --- | --- |
| P0 | Qualify the native deadline fixture repairs on pinned platforms | Clock and partial-send fixtures now preserve Threaded userdata and joined lifetimes. Local full HTTP/3 passed 1,005 cases with four existing GRO skips; selected Windows compilation passed. Pinned native/complete CI remains required. |
| P0 | Diagnose client CA reload retained-connection failure | The complete run reports BrokenPipe while reading old MQTT PINGRESP before SIGHUP; the same head's isolated native CA reload step passed. Rejected-certificate and anonymous-client transitions need examination with the unchanged pinned dependencies. |
| P1 | Join finite HTTP/1 and WebSocket service workers on failure | Independent worker admission and joined failure cleanup implemented. Eight real-socket cases cover initial/partial admission, later accept failure and caller cancellation; current native H1/WS and Windows compilation passed. Pinned native verification remains required. |
| P1 | Guarantee HTTP/2 batch receive/wake admission | Independent task admission and joined completion retention implemented in `frame/wake.zig`. Actual entered-read cancellation with zero async capacity and same-socket reuse pass locally; reader timeout, protocol error, EOF and caller cancellation rearm are covered. Native pinned verification remains required. |
| P1 | Copy WebTransport H2 slices once into owned job storage | Both endpoint roles now stage directly into the job arena after deadline/cancellation admission. Real public command submission measures two caller allocations for both contiguous and sliced input; expired/wrong-clock calls make zero allocation attempts. Selected native tests and Windows compilation pass; pinned native and complete qualification remain open. |
| P2 | Extract coherent HTTP/2 and WebSocket owner responsibilities | The current H2 connection has 16,145 lines and WebSocket runtime has 3,705. Extract batch/frame and finite-service responsibilities while retaining existing public imports, connection state and sole-reader ownership. |
| P2 | Complete grouped fuzz replay acceptance | All 37 entry points and 107 named tests preserved in eight groups. Native Linux unfiltered grouped replay passed in run45750666840 preflight, including the unchanged real IP-migration root. Complete acceptance remains separate. |

The grouped replay [validation record](../evidence/fuzz_replay_groups/2026-11-26/validation.json)
separates the single paired compilation sample, all-member macOS replay and
Windows cross-compilation from pending native Linux and complete CI acceptance.
The existing budgets, dependency pins and real IP-migration tests remain part of
the acceptance contract.

The native fixture [qualification](../evidence/protocol_native_test_context/2026-11-26/validation.json)
records the repaired callbacks, actual send-prefix and pacing checks, full
HTTP/3 result, Windows compilation and the remaining pinned CI boundary.

The H2 batch wake [qualification](../evidence/http2_batch_wake/2026-11-26/validation.json)
records current-source native cancellation and completion-retention checks and
the matching Windows cross-compilation. It does not establish native Windows,
Linux or complete acceptance. In revision `997de2c7`,
[run 45761345203](https://github.com/passchaos/netz/actions/runs/45761345203)
still reports the Linux client CA reload failure before SIGHUP. The bounded
observer reports only three expected `CertificateUntrusted` accept events;
there is no connection-stage cause in that output. Windows' original native
protocol step passed, while the send-deadline step reports unsupported Threaded
datagram deadline calls in further H3 and WebTransport fixtures. Those failures
remain open with unchanged dependency pins, commands and budgets.
The complete job subsequently ended with two failed nodes: the `src/root.zig`
test process terminated with `ABRT`, and CA reload failed with BrokenPipe at
206 ms before SIGHUP. The public failure summary does not identify the crashing
test, so neither its cause nor complete acceptance is closed by scoped passes.

The WebTransport H2 sliced storage [qualification](../evidence/webtransport_h2_slice_storage/2026-11-26/validation.json)
records mutation/abandonment ownership, every staging allocation failure, actual
caller allocation counters and both endpoint TLS round trips. The original
native combined protocol command remains unchanged; an independent H2 wake and
sliced-storage command shares its existing five-minute budget on Linux/Windows.
The final combined native scopes pass 39 H2 and 147 WebTransport cases; the
matching Windows scopes compile. These counts include imported support tests
and do not establish a throughput result or complete acceptance.

### Native fixture follow-up on e421d17a

[Run 45766158848](https://github.com/passchaos/netz/actions/runs/45766158848)
passed the Linux native task, including the original protocol command, added
H2 owned-input command, send-deadline scopes and isolated CA reload. Complete
MQTT configuration interop also passed. That does not identify a causal repair
for the earlier retained TLS connection loss; its history remains relevant.

The complete run now identifies its GP at test 2300/7469, `WebTransport protected
runtime CONNECT and datagrams over QUIC 1-RTT`. That fixture and two same-family
DATA-slice fixtures still replaced Threaded userdata with clock observers.
They now use stable native context, complete typed callback forwarding and
atomic send-advanced clocks. Synthetic awake deadlines become remaining native
durations at backend submission. All changed UDP fixture bodies retain POSIX
Threaded plus application-backend coverage and use application IOCP on Windows;
selected peer threads are canceled/joined Futures.

The [forwarding qualification](../evidence/protocol_native_test_context/2026-11-26/forwarding.json)
records 68 core checks, final H3 84 and WebTransport 143 scoped native cases,
matching Windows compilation and 13 failure-annotation checks. Real UDP tests
observe an entered read before cancellation, reuse its socket, and capture the
exact synthetic deadline duration reaching the actual backend. GP, illegal
instruction and stack-overflow prefaces retain their original test name before
long stacks, with the existing twelve-annotation cap.

Windows' new owned-input command failed in two existing H2 TLS endpoint tests:
EndpointClient received `AuthenticationFailed` at `closed_a`, and EndpointServer
received `Unexpected` at `/overflow`, both following native `CONNECTION_RESET`.
Their first peer-side cause remains open. This prevents native Windows/complete
acceptance despite current local fixture passes. Original commands, dependency
pins, budgets and real IP-migration assertions are preserved.

### WebSocket H3 context follow-up on fd016266

[Run 45773335592](https://github.com/passchaos/netz/actions/runs/45773335592)
passed Linux's original/added protocol and send-deadline steps. Its complete
test process progressed to 4205/7472 and aborted in `WebSocket HTTP3 bounds paced
admission with 80 headers at 1200 MTU`: the clock wrapper supplied observer
userdata to inherited Threaded Group.concurrent and allocator callbacks.

That fixture and seven same-family frame/control/message fixtures now use the
actual-backend Native observer. Their peer tasks support cancellation/join, and
admission observation ends before Pending transfers its H3 ownership. All
original header/MTU, zero-send/pacing-sleep, mask-once, committed-prefix, FIN,
exact suffix and mismatch-refusal assertions remain. Deadline fixtures and small
shared header checks are extracted behind the original formal test import.
The [qualification](../evidence/websocket_h3_native_context/2026-11-26/validation.json)
records 87 native scoped cases and same-range Windows compilation; delivered
revision native and complete acceptance remains pending.

Windows still reports an H2 EndpointServer connection reset while opening `/b`.
Both H2 TLS peers now print their first error stage; their original backend,
traffic, KeyUpdate, capacity, close and reuse assertions remain. The local
135-case scope and Windows 8/8-step compilation pass, while the actual first
Windows peer cause remains unproven. Linux isolated/full CA reload also still
fails before SIGHUP at about 160-162 ms, with only expected rejected-certificate
accept events. Neither prior isolated passes nor current scoped repairs close
these remaining correctness requirements or the broader optimization goal.

### Windows TCP completion investigation on 26de4f06

[Run 45785436516](https://github.com/passchaos/netz/actions/runs/45785436516)
has finished. The Windows owned-input scope's first peer failure is now
`stage=CLOSE input err=RecordTooLarge`, followed by `CONNECTION_RESET` and
`Unexpected` in the EndpointServer Session close sequence. This establishes
the peer's TLS record-parser failure stage, but not its root cause.
The native x86_64 Linux resolver, original/added protocol, HTTP/3 send-deadline
and isolated CA reload steps passed. An isolated CA reload pass does not
explain the retained-connection failures in earlier runs.
The complete step ended after its existing 28-minute command budget with exit
137; its public summary also contains a failed MQTT broker configuration
interop node. Neither that exit nor the truncated summary identifies a new
HTTP-family crash or closes complete acceptance.

The current Threaded Windows ordinary receive calls `deviceIoControl`, whose
cancellation path cancels/joins the native request and returns `Canceled`
without returning a successful completion's byte count. Losing a consumed
prefix could desynchronize the incremental TLS reader; that mechanism still
needs native evidence. `std.Io.Batch.cancel()` explicitly preserves operations
that complete successfully despite cancellation. Its Windows AFD receive
path uses the same flags and can expose the retained completion without
changing socket nonblocking mode or replacing the Threaded backend.
Its current Windows cancel implementation also begins with an infinite
alertable wait before issuing kernel cancellation. The experiment arms one
native self-alert for a pending Batch to let an idle receive reach cancel/join;
that liveness boundary is qualified separately from completion retention.

A [minimal native experiment](../evidence/windows_tcp_completion/2026-11-26/README.md)
now records the raw cancellation result and buffer contents, checks retention
after controlled cancellation of an actually completed Batch receive, and
checks an entered pending receive's cancellation/join and same-socket reuse.
The original native resolver and combined protocol commands are unchanged;
the standalone Windows probe runs serially in the existing resolver step.
Production transport code and H2 traffic/KeyUpdate/capacity/close assertions
remain unchanged while the primitive is being qualified. A passing candidate
completion test alone will not establish the cause of the H2 TLS failure.

### HTTP/2 inbound field-section owner extraction

The connection's inbound field-section assembly and decode logic now lives in
`src/http2/runtime/headers/inbound.zig`. Its stateless `Reader` groups ordinary
and raw CONTINUATION collection, queued/deferred duplex-header completion,
complete-limit rejection and HPACK error classification. `Connection` still
owns its scratch, decoder, pending header slots, reader mode and error state;
private transport operations are passed through explicit existing-function
callbacks. Existing public methods and read ownership remain intact.

The root shrinks from 16,093 to 15,982 lines; the extracted module has 154 lines.
This improves the responsibility boundary and makes complete/incomplete header
failure policy reviewable in one place. It does not establish a runtime or
compile-time speedup. The [qualification](../evidence/http2_inbound_headers/2026-11-26/validation.json)
records 62 selected native cases, including 27 named HTTP/2 behaviors, and
matching Windows compilation. Malformed/unterminated CONTINUATION, complete
field/byte limits, HPACK reuse, parent/sibling isolation, deferred duplex heads
and aggregate/streaming deadlines are covered by existing real-socket tests.
Pinned native and complete acceptance remains separate. The broader H2 owner
extraction work and Windows TCP/TLS completion investigation remain active.

### TCP probe real-cancellation correction on 4a25e2fb

The native Windows [run 45793518173](https://github.com/passchaos/netz/actions/runs/45793518173)
aborted the first TCP probe in `Threaded.recancelInner`: the harness tried to
initiate cancellation with `recancel` before observing any real `Canceled`.
The target raw receive had not begun, so this result does not establish byte
loss or the pending Batch cancellation behavior. Production transport code
remains unchanged while these mechanisms are qualified.

The corrected harness uses actual parent Future cancellation and an event
handshake at both raw-read and completed-Batch boundaries. It rearms only a
real cancellation already observed by the worker. A portable contract case
checks that initial and rearmed cancellation are both delivered. The probe
streams through the existing progress wrapper after the original combined and
owned-input H2 commands, keeping their exact text, five-minute step budget and
failure aggregation. [The follow-up qualification](../evidence/windows_tcp_completion/2026-11-26/real-cancellation.json)
separates that portable contract and Windows code generation from pending
native Windows results and the still-unproven H2 TLS root cause.

### Windows Threaded read completion retention

The corrected native probe in [run 45799170389](https://github.com/passchaos/netz/actions/runs/45799170389)
returned `Canceled` and zero count from an ordinary Threaded read after five
payload bytes reached its buffer. The actual Batch completion retained all
five bytes and rearmed real parent cancellation; entered idle cancellation
and exact same-socket reuse also passed after one self-alert. This establishes
the primitive's count-loss mechanism. Its original H2 TLS endpoint tests
still fail with `RecordTooLarge`; native causal repair remains to be qualified.

HTTP/1, HTTP/2, native TLS record readers, the standard TLS vector reader,
WebSocket and raw H2 frame readers now share an internal socket-read boundary.
Matching Threaded AFD requests retain completion storage through cancel/join,
return accepted bytes or EOF, and rearm actual cancellation. They preserve
the same asynchronous socket and receive flags. Timed fallback tasks use that
same primitive and reject already canceled callers before task admission.
Custom netRead operations and application-backend registrations retain their
own callbacks. An independent QUIC prefix command qualifies the repaired
full-forwarding observer within the original five-minute protocol budget.

[The focused qualification](../evidence/windows_stream_read/2026-11-26/validation.json)
records 352 native scoped passes, 15 Windows-only skips on macOS and matching
Windows compile groups of 14/14, 14/14 and 8/8 steps. Five real Windows read
fixtures cover bytes/EOF, early/entered cancellation, vector destinations,
socket reuse and 64 active races; their native run remains pending. Original
H2 backends, KeyUpdate/capacity/close/reuse assertions, dependency pins,
commands, budgets and migration inputs remain intact. Complete acceptance and
fixed-workload performance qualification are still open.

### Full CI abort context ownership

The library ABRT's first test remains unknown in the latest public failure
summaries. A replay of the actual verbose log structure reproduces a separate
diagnostic defect: a delayed `failed command` signal summary was associated
with a later fuzz artifact, while allocator abort prefaces could be ignored or
hidden behind the twelve-annotation cap. Empty failed-command logs also raised
an exception instead of preserving missing-output information.

The extractor now indexes last-visible tests by cache executable and invocation,
resolves signal summaries through their failed command, and starts fresh context
for repeated executions. Unknown artifacts remain unassigned. Native crash and
allocator prefaces receive priority within the existing cap, and signal blocks
end at the failed command. [The qualification](../evidence/ci_crash_artifact_context/2026-11-26/validation.json)
records 22 focused checks, including actual child SIGABRT and Windows quoted
paths. This improves the next owning-path diagnosis; it does not close the
library crash or native/complete acceptance. Commands, budgets, pins and
failure status remain unchanged.

### Native Windows stream-read qualification on a265f9b7

[Run 45805867462](https://github.com/passchaos/netz/actions/runs/45805867462)
passed Windows' unchanged H1/H2 resolver/read command and original/added H2
protocol command step. The existing `stream timed` filter includes all five
new Windows read contracts through their formal import; the platform guard
executes them on this runner. The original Threaded H2 TLS endpoint Session,
KeyUpdate, capacity, close and reuse assertions passed too. The raw std.Io
baseline still reproduces zero reported count after five consumed bytes,
while the retained Batch count and pending-read socket reuse checks pass.

This closes the delivered stream-read adaptation's selected native Windows
contract and H2 TLS qualification. It does not close all native or complete
acceptance. The later HTTP/3 fixture command failed in two sends with expected
`Timeout` but actual `Unexpected`, returning from protected send packetization.
The bounded old annotation lacks the triggering test after the long trace.
The extractor's new active-artifact fallback retains that last visible test
even beyond forty trace lines. The first H3 send cause and complete-library
ABRT still need direct owning-path evidence; commands, budgets and pins remain.

### Located complete-run removal deadline GP

The complete run's full annotations identify its GP at test4591/7478,
`WebTransport endpoint client removal deadline spans CLOSE RESET and STOP
without renewal`. The stack enters allocator creation through Threaded
Group.concurrent. The fixture's ExpiringSend userdata was supplied to
inherited backend callbacks. That is an owning-path ABI mismatch, separate
from the now-qualified Windows TCP byte-count repair.

The fixture uses the shared Native observer and typed callback forwarding,
atomic selected-send clock advancement and actual-backend deadline wakeups.
Endpoint I/O restoration precedes observer destruction and fixture cleanup.
All seven same-family tests retain their original traffic and CLOSE/RESET/STOP,
four-send, pending-DRAIN, protocol-rejection, retry and sibling assertions on
supported real backends. The local scope passes118 cases and Windows8/8-step
compilation; an independent native scope remains inside the original
five-minute protocol budget. Complete/native crash qualification is still open.

### H3 response deadline observer delegate ownership

The protected response deadline fixture saves an endpoint created by the
actual-backend runner, then installs a Native clock observer without assigning
its delegate. That selects a new embedded Threaded backend for a socket that
may belong to application IOCP. The observer now delegates to the saved socket
owner and restores endpoint I/O before destruction; existing timing, SETTINGS,
stream/lifecycle/QPACK, aggregate/streaming retry and exact-body assertions
remain unchanged. [The focused qualification](../evidence/h3_response_native_delegate/2026-11-26/validation.json)
records66 native scoped passes and matching Windows8/8 compilation.

Native H3 command output lacks verbose executable markers. Its immediate
failure fallback now retains the last visible command-output test after a long
trace, while known artifacts and delayed signal summaries retain their own
invocation context. Twenty-four diagnostic cases pass. Attribution of the
current two expected-Timeout/actual-Unexpected send failures is still pending
delivered native evidence; the source ownership repair alone does not close
that causal gate or the broader optimization scope.

### Located complete-run session-control deadline crash

[Run 45813013101](https://github.com/passchaos/netz/actions/runs/45813013101),
attempt 1, advanced beyond the repaired endpoint-removal fixture, then aborted
at test 4692/7478, `WebTransport authenticated close deadline resumes capsule
and stream cleanup`. Its stack reaches Threaded Group.concurrent allocator
creation with FixedSendIo userdata supplied to inherited backend callbacks.
Five related session-control deadline fixtures had the same callback-owner
mismatch. Their former sleep override also fabricated `Canceled` instead of
letting real deadline-task cancellation release a backend wait.

These fixtures now share the existing Native observer's typed forwarding,
borrow their actual socket/execution backend and restore endpoint I/O before
observer destruction. Selected successful sends advance an atomic synthetic
awake clock and wake an actual event. Peer tasks use the same real I/O backend
and are joined or canceled before owner destruction. The tests are split into
close/drain and cleanup modules, with all five original names formally imported.
Exact capsule suffixes, conflicting retry metadata, completed stream prefixes,
terminal event retention and no pacing-duration sleep remain asserted; the
deadline watcher itself uses a cancellable absolute wait.

[The focused qualification](../evidence/session_control_native_delegate/2026-11-26/validation.json)
records 119 native scoped passes, including all five fixtures on POSIX Threaded
and the application backend, plus Windows 8/8 compilation. A separate native
session-control command runs the five existing names inside the unchanged
five-minute protocol step. The original combined command, failure propagation,
dependency pins and complete-gate budgets remain unchanged. Delivered Linux
and Windows native runs and complete-crash qualification remain pending.

The same complete run's first named test failure is test 4486/7478,
`HTTP/2 concurrent informational responses compose with bodies and trailers`,
with `StreamReset`; an earlier MalformedHeader stack entry is not root-cause
evidence. This requires an independent reproducer and remains open, as do the
Windows H3 expected-Timeout/actual-Unexpected failures. The peer QUIC close
loss fixture's remaining DropFirstCloseIo inherited-callback ownership also
needs a separate audit; its forwarding scope is not qualified by these five
deadline tests. The continuous optimization goal remains active.
