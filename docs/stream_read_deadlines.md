# Absolute stream read deadlines

The shared timed reader keeps one submitted `std.Io.Batch` under the caller's
original awake-clock deadline. An early scheduling `Timeout` continues waiting
on that batch. A completed read is consumed once, so a retry cannot submit a
second read against the same socket or lose bytes already received.

The installed Zig 0.16 Threaded backend converts a remaining poll deadline to
whole milliseconds and explicitly permits spurious timeout notifications. The
previous `std.Io.operateTimeout` call propagated those notifications as a final
read failure. A deterministic backend returning Timeout with 500 ns remaining
fails against that implementation and succeeds with the retained reader.

Actual expiry, cancellation and executor failure cancel and join the batch
before borrowed buffer descriptors leave scope. If cancellation races a natural
completion, the reader returns the consumed bytes and rearms cancellation for
the caller's next cancellation point. Nested operation errors remain errors;
EOF remains a zero-byte read. Empty reads perform no socket operation, and
expired or foreign-clock deadlines reject a nonempty read before submission.

The POSIX streaming-file operation and Windows network operation keep their
existing platform-specific result decoding. This helper underlies TCP packet
reads and TLS record reads used by HTTP, WebSocket, MQTT and gRPC.

Focused regressions cover repeated early notifications without resubmission,
completion accompanying Timeout, true expiry without deadline renewal, joined
cancellation with and without progress, nested errors and EOF. A real Threaded
socket test verifies absolute expiry, rejection of a stale deadline without
consuming queued bytes, later socket reuse, and orderly EOF. Debug and
ReleaseSafe run these tests; Windows compilation checks its receive branch.

Evidence is recorded under `docs/evidence/stream_read_deadline/2026-11-07/`.
The original and fresh TCP/TLS MQTT QoS 2 replay seeds also pass with the new
reader. This establishes the deadline correction; it does not establish that
the earlier intermittent retained-probe timeout had this cause. The QoS 2
harness now reports local broker listener errors as well as its operation
phase and remote peer error.

A separate configured-broker post-EOF timeout reproduced with an ext4 journal
commit wait. Its snapshot-producing fixtures now distinguish bounded durable
shutdown completion from connection teardown; the evidence includes the
captured thread wait channels and repeated process/restart checks.
