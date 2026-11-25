# QUIC/HTTP3 socket deadlines and DATA progress

Finite H3 response commands now carry their original awake-clock deadline
through owner admission, pacing, packet protection, endpoint send locking and
cooperative socket submission. The deadline watcher is admitted before work
starts. Cancellation joins the worker and collects late results before releasing
borrowed commands or packet storage. A complete commit wins a racing wait
failure; an incomplete operation retains its confirmed progress and error.

Concurrent H3 DATA exposes per-call `committed_bytes`, `fin_committed` and
`retryable`. Owner retries retain this progress and send only the uncommitted
suffix. Stateful QUIC commits recovery and flow-control state for the visible
packet prefix while consuming packet numbers for every protected packet.
Development sends use one watcher per bounded packet window; unknown partial
submission still requires terminal owner cleanup. Response mutation was moved
into a cohesive development response module.

[validation.json](validation.json) records checks on the current main sources
based on `90ea57309ddceff227bbf6be1acfe17d04eb243d`: 115 HTTP3 and 44 QUIC
tests passed on macOS, the same scope compiled for x86_64 Windows, and the
ReleaseFast benchmark's finite-deadline option completed a smoke run with 128
packets per path. Cases cover actual UDP prefix/timeout/network errors, joined socket-lock
cancellation, nonce-safe suffix reuse, complete send races, borrowed command
release, DATA prefix retry and same-connection reuse. Test wrappers preserve
native backend userdata and use atomic clocks tied to actual sends.

The native CI workflow adds the portable socket-deadline and command-admission
scope on Linux and Windows. [ci_control_flow.json](ci_control_flow.json) records
shell syntax and simulated success/failure exits; child exit 7 remains step
exit 7 with an annotation. The previous combined protocol command, dependency
pins and existing timeout values are preserved. These control-flow checks and
Windows compilation do not establish native runtime success.

[sender_deadline_pairs.json](sender_deadline_pairs.json) preserves five
alternating-order pairs from one fixed candidate ReleaseFast executable before
main integration. Each sample sent 32,000 packets per path on macOS/zio. The
sequential finite/unbounded ratio had median 1.0544 (range 1.0217–1.1380).
Batch ratios ranged 0.9327–1.0289, crossing parity. No stable batch speedup is
claimed. The benchmark isolates the sender, does not drain the receiver or
process ACKs, and does not establish end-to-end throughput. Its new
`--send-timeout-ms` option reproduces the finite stream-send mode.

Local Vail is `d93847a7e091c835406ee10c0a86fd064f1475dd`; CI retains
`3b772b0cccb64d84fbc760df6428bc51e0fe0761`. Broader native and complete
acceptance remains pending. The previous pinned run
[45716045826](https://github.com/passchaos/netz/actions/runs/45716045826)
passed the original Windows protocol combination but failed Linux client CA
reload before SIGHUP and the complete gate. MQTT diagnostic errors now identify
PINGREQ send versus PINGRESP read and the original exception class, with one
non-consuming peer observation after failure. Its 16 support tests passed;
Linux-only reload behavior cannot be verified on this macOS host.
