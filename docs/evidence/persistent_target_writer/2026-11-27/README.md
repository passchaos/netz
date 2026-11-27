# Persistent shared-proxy target writers

The shared TUIC/Hysteria service loop previously attempted each target TCP
write under a ten-millisecond deadline. Controlled native stalls measured a
linear turn cost. Relays now have explicit concurrent read/write owners;
the QUIC receive and connection-state owner submits immutable input loans and
collects their exact completion.

The pending buffer remains independent of the borrowed loan. Its growth and
allocation failure cannot relocate the writer's bytes. Partial progress keeps
the FIFO suffix. The logical input limit remains 256 KiB by default, while two
retained backing buffers can occupy at most twice that storage. Hysteria charges
a reservation before publication and refunds uncommitted bytes, including the
final completion collected on relay retirement. TCP FIN waits for drained input
and is sent once. Synchronous flush entry points remain available.

The actual native scope passes 77 tests, including original TCP/UDP, 4/16/64-KiB
bodies, maximum negotiated rates, loan growth/OOM, actual deadline retry, joined
stop and visible partial completion. A healthy TCP sibling delivers its exact
bytes while another target remains blocked. The post-batching TUIC scope passes
57 tests. Windows same-scope compilation and the final changed TUIC scope are
recorded separately from native Windows execution.

Both unchanged sing-box 1.14.4 gates pass: exact 131,072-byte TCP responses and
17-byte UDP replies, in native and QUIC UDP relay modes. The native host asset
matches the official release digest and revision
`c005f35300ce76427dc285481ec5695f5b179cd2`.

## Fixed-binary qualification

The resource probe runs against identical measurement source and an immutable
`a9b85557` production baseline. It uses distinct TCP sockets, controlled
`netWrite` stalls and actual ten-millisecond deadlines. All five samples per
shape enter every expected callback and retain the queued bytes. Completion
collection occurs outside the measured submission turn; this measures service
cost, not target completion latency or kernel backpressure.

| Application backend, 32 targets | Baseline | Candidate |
| --- | ---: | ---: |
| Small-input service median | 369.650 ms | 0.011834 ms |
| Burst service median | 367.742 ms | 0.010083 ms |
| Burst Relay live allocation | 4,475,904 B | 3,172,352 B |
| Small-input process peak RSS | 9,142,272 B | 10,715,136 B |
| Burst process peak RSS | 14,336,000 B | 13,467,648 B |

Relay allocation excludes backend/task memory; process RSS includes it. The
extra owners increase small-input RSS, especially on Threaded: 32 targets use
13,795,328 B versus 10,403,840 B. Burst Threaded RSS is 16,465,920 B versus
15,777,792 B. All 24 rows return zero Relay live bytes after joined cleanup.
The resource data does not establish allocation-free steady state or broad
connection-count superiority.

The first eager per-fragment input-submission sample increased upload/echo
medians by 11–19%. TUIC now starts the collected input batch at the end of a
service turn. The rejected sample remains in
[eager-transfers.json](eager-transfers.json).

The final independent-peer comparison uses AB then BA ordering, nine samples
per run and exact 128-KiB payload checks. Combined 18-sample medians are:

| Transfer | Baseline | Candidate |
| --- | ---: | ---: |
| Download | 10.832 ms | 10.1505 ms |
| Upload and echo | 12.586 ms | 12.793 ms |

The two upload rounds differ by about -0.6% and +5.3%, so the first sample's
consistent large slowdown is absent. This small warmed workload does not prove
large-scale throughput or p99 fairness. Source hashes, commands, binary hashes,
raw sample logs and assertions are recorded in validation and the adjacent
resource/transfer records.

The original two-millisecond QUIC receive budget and ten-millisecond target
write budget remain. At most eight signaled-relay service turns precede the
normal QUIC receive/timer path. Existing relay outbound sends already have an
eight-packet turn bound. UDP association owners, finite stream/datagram drains,
fair ready scheduling, larger workload matrices and complete/native acceptance
remain part of the active R4-R9 and HTTP-family goal.
