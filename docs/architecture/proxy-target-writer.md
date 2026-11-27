# Shared proxy target-write ownership

TUIC and Hysteria keep one owner for QUIC receive, connection state and sends.
Each TCP relay has a concurrent reader and a persistent target writer. Reader
creation uses `concurrent`, so an I/O implementation with no async capacity
cannot execute a blocking reader inline on the endpoint service loop.

`relay_queue/inbound.zig` owns two input buffers. Incoming bytes append to the
mutable pending buffer. Submission exchanges buffer ownership and lends an
immutable range to the writer. Pending growth cannot move or overwrite that
range. A partial completion advances only the committed prefix; the remaining
loan precedes all newer pending bytes. Submission does not copy payload bytes.

The default logical input limit remains 256 KiB, counting the uncommitted loan
and pending bytes together. Each backing buffer is bounded by that limit;
the two reusable buffers can retain up to twice that storage. Allocation is
lazy. The additional retained-buffer and concurrent-owner costs must be
included in workload memory qualification.

Hysteria's receive bucket reserves credit before publication to the writer.
A rejected submission immediately returns unused credit. Completion keeps
only committed bytes charged and refunds the rest. Relay retirement joins the
writer and collects its final completion before the connection loses that
reservation. A timed-out loan retains its exact cursor and can retry under a
new ten-millisecond write budget.

TCP send shutdown requires both input buffers to be drained and no active
loan. It happens once. Full relay cleanup closes the outbound queue, joins the
writer, shuts down TCP to wake the reader, joins the reader, then releases the
socket and buffers. The synchronous `flushInbound`/`flushInboundUpTo` surface
remains available to standalone callers; shared pumps use explicit submission
and completion collection.

Reader output and writer completion publish relay readiness. The pump handles
only signaled relays during completion turns, with at most eight such turns
before returning to its existing QUIC receive/timer path. Regular receive
turns also handle credit replenishment and expiry.

This work removes target DATA writes from the service loop.
Relay outbound drain already allows at most eight single-packet send attempts
per turn. UDP associations use independent bounded receive/send owners as
described in [UDP ownership](proxy-udp-ownership.md). The remaining R4 scope
requires finite stream/datagram drains, fair ready scheduling and mixed hot/idle/blocked
workload measurements. Those requirements remain active in
[the optimization backlog](optimization-backlog.md).

Qualification must retain the existing FIFO/backpressure, packet-sized relay,
maximum-rate, exact body and independent-peer cases. Additional native stream
cases cover growth and allocation failure during a loan, actual timeout and
retry, joined cancellation, uncollected partial completion, shared credit
refund on retirement, and FIN after input completion. Cross-compilation is
recorded separately from native execution.
