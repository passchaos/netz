# Shared proxy UDP association ownership

TUIC and Hysteria retain one owner for QUIC receive, protocol encoding,
connection state and rate buckets. Each UDP association borrows its target
socket into a concurrent receiver and a concurrent resolver/sender in
[`udp_session.zig`](../../src/proxy/internal/udp_session.zig). The shared pump
only publishes outgoing datagrams and collects received packets and send
completions. Association creation fails if either concurrent owner cannot be
admitted; it never falls back to running target I/O inline.

The sender has 32 slots. Publication copies the payload and any borrowed host
into reusable slot buffers before enqueuing its index. Slots stay immutable
until their completion is collected. Queue saturation rejects the new packet
without taking ownership or waiting. Domain destinations use the existing
resolution timeout and current reloadable policy inside the sender. Literal
IP behavior follows the existing proxy path. TUIC's initial domain association
still resolves and binds on its existing worker, then queues its first payload
through the same sender as later packets.

The receiver has eight slots. Each packet loans its address, bytes and
truncation flag to the pump; the pump encodes it before calling `release`.
The receiver cannot reuse a loaned slot. A full queue waits for a returned
slot, allowing the operating system's normal UDP buffering/drop behavior.
Empty datagrams remain messages. A positive native receive count retains the
message even if the operation also reports an error. Truncated messages are
visible to the owner and discarded by both protocol encoders.

An atomic pending-message count also preserves packets already published
before a subsequent fatal receive. The pump drains and flushes those packets
within the same eight-message turn budget before closing the association.
Hysteria encodes a numeric host without an endpoint port; its wire port field
is independent. Shared and standalone paths use the same IPv4/IPv6 formatter.

Each association service turn collects at most 32 send completions and eight
received messages. Each encoded-reply drain attempts at most eight sends;
there is one drain before and one after receiving packets. A separate
eight-slot [`Replies`](../../src/proxy/internal/udp_session/replies.zig) FIFO
retains encoded packets through congestion, pacing, flow-control and
anti-amplification refusal. New replies follow the blocked front even when
earlier slots have been freed. A full reply FIFO drops the new reply and frees
its encoding.

TUIC QUIC-mode replies use one unidirectional stream per encoded Packet and
send FIN with that complete Packet. The shared path attempts one packet-sized
STREAM frame per call, using the same flow, congestion and packet-size budget
as TCP relay output. A cursor and immutable payload identity retain the exact
unsent suffix with the FIFO front through refusal. Statistics charge each
committed prefix once. A committed FIN clears the stream even when the native
operation accompanies its positive count with an error. This follows the
pinned independent peer's one-Packet reader; sharing a response stream causes
later replies to be discarded.

Standalone TUIC uses the same per-Packet state with its existing 100-ms timed
send quantum and 100-attempt limit. Each timed attempt advances by the actual
committed prefix and verifies the final stream size before clearing ownership.
The pinned independent peer passes the original TCP/UDP gates and small/large
Packet matrices on both shared and standalone owners. Native execution and
platform compilation are recorded separately in the
[PacketStream evidence](../evidence/tuic_packet_stream/2026-11-27/README.md).

Cancellation releases the payload borrow while retaining its stream ID.
Association retirement transfers that ID into a connection-owned queue with
64 slots, retrying at most eight resets per turn. A failed reset keeps its
slot. Queue saturation closes the connection so retirement cannot orphan a
stream. Connection destruction remains the final owner of outstanding IDs.

Both incoming uni-command parser pools have eight slots. Each slot reuses
bounded storage, including the configured UDP payload limit plus the maximum
269-byte Packet header. FIN returns the slot without freeing retained storage;
incomplete bytes at FIN remain a protocol error. A maximum valid 253-byte
domain needs 257 encoded address bytes, so CONNECT and Packet share a 259-byte
scratch bound covering the wire length field's full range.

Owner publication signals the existing pump readiness flag. Completion turns
visit signaled associations and relays. At most eight completion turns precede
the ordinary two-millisecond QUIC receive/timer path. That ordinary path also
retries encoded replies, replenishes credit and expires idle associations.
QUIC stream/datagram input drains and broader ready scheduling still require
their original R4 work.

Hysteria reserves the entire outgoing payload from its shared receive bucket
before publication. Rejection or allocation failure immediately refunds the
reservation. A send completion reports reserved and actually committed byte
counts; the pump refunds their difference and charges statistics for the
committed bytes. A positive send count with a complete payload remains a
successful datagram even if an error accompanies it. A shorter accepted
payload reports its committed prefix and `MessageOversize`; it is never
replayed as another datagram. TUIC also records committed input bytes only
after completion.

Retirement closes the queues, cancels and joins both owners, then collects
every still-active send reservation exactly once. Completed native sends
retain their committed counts even if cancellation prevents publishing the
completion index. Commands that never reached the socket are canceled with
zero committed bytes. Received leases remain valid across `stop` and must be
returned before `deinit`. Buffers are freed before the association closes its
borrowed socket. This ordering also applies to setup failure and connection
teardown.

For datagram limit D, receiver payload storage is at most 8D and sender payload
plus host storage is at most 64D. Allocation is lazy and retained capacity is
reused. With the default D=4096, that conservative raw-buffer ceiling is
288 KiB per association, excluding metadata, encoded replies, resolver
allocations, task stacks and backend/kernel buffering. There are two concurrent
owners per association; both protocols enforce their configured association
limit before creation. These bounds do not establish RSS, allocation-free
protocol encoding or an overall throughput/p99 improvement.

Native qualification covers immutable payload/host publication, FIFO and
slot reuse, saturation, allocation rejection, zero/truncated/positive-count
receives, committed prefixes, cancellation, joined lease lifetime and exact
Hysteria reservation/refund across full queues and healthy siblings. A separate
32-association case observes target-read callbacks and verifies that calling
the actual service method submits no target reads. Native execution, Windows
compilation and independent-peer results are recorded separately in the
[UDP ownership evidence](../evidence/udp_association_owners/2026-11-27/README.md).
