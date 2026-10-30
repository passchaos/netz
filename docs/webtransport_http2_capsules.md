# HTTP/2 WebTransport Capsule protocol foundation

`webtransport.h2` provides the Capsule wire layer from
[draft-ietf-webtrans-http2-15](https://www.ietf.org/archive/id/draft-ietf-webtrans-http2-15.html).
It adds HTTP/2 virtual-stream STREAM/FIN, RESET_STREAM, STOP_SENDING,
MAX_STREAM_DATA and STREAM_DATA_BLOCKED to the existing DATAGRAM, session
CLOSE/DRAIN and session flow-control capsules. These are separate from native
HTTP/3 WebTransport stream association headers.

```zig
var storage: [128]u8 = undefined;
const capsule = netz.webtransport.h2.Capsule{ .stream = .{
    .id = 4,
    .data = "hello",
    .fin = true,
} };
const wire = try capsule.writeInto(&storage);
const decoded = try netz.webtransport.h2.Capsule.parse(wire);
```

STREAM type `0x190b4d3c` carries data without FIN and `0x190b4d3b` carries FIN.
RESET_STREAM includes a 32-bit application error encoded as a QUIC varint and
the Reliable Size; its relationship to delivered data belongs to the future
virtual-stream state machine. Known payloads enforce field cardinality and
trailing-byte rules. Whole-capsule parsing distinguishes an incomplete envelope
from a malformed complete payload. Writers preflight the complete output and
retain caller storage or an existing list prefix on validation failure and OOM.
PADDING writers emit only zero bytes; readers permit non-zero received padding
as allowed by the draft. Application stream identifiers retain all 62 bits,
and application error codes cannot exceed 32 bits.

`h2.Reader` consumes capsules across arbitrary HTTP/2 DATA fragmentation. Its
caller retains a slice which advances only for successfully consumed bytes:

```zig
var reader = netz.webtransport.h2.Reader.init(allocator, max_payload_bytes);
defer reader.deinit();
var remaining: []const u8 = data_fragment;
while (try reader.next(&remaining)) |capsule| {
    // Payload aliases the Reader until the next call or deinit.
    try process(capsule);
}
```

Unknown capsules and padding are skipped without payload allocation, including
64-bit declared lengths split over multiple DATA fragments. Known capsules
reserve at most the caller's payload quota. An oversized declaration fails
before body allocation; allocation failure preserves the decoded envelope and
leaves the slice at the first unconsumed body byte for retry. A malformed
payload remains a terminal parser failure, while clean CONNECT FIN is accepted
only between complete capsules. CLOSE reason validation retains the existing
UTF-8 and 1024-byte rules.

Validation uses independent fixed wire vectors, every stream-ID/varint
boundary, every byte split in an encoded stream capsule, exact output and OOM
boundaries, unknown/padding skips and terminal parser failure. The existing
cross-protocol parser fuzz target now includes the HTTP/2 wire parser and
fragmented Reader alongside five new structured seeds and deterministic
mutations. Run:

```sh
zig build test-lib -Dtest-filter='WebTransport HTTP2' --summary all
zig build fuzz-parsers --summary all
```

The virtual-stream `h2.State` now enforces direction/initiator ownership,
cumulative implicit opening, session and per-stream data credit, duplicate
FIN/reset/STOP rejection and exact RESET Reliable Size. Output preparation is
separate from commit so a failed Capsule submission cannot advance stream
offsets or grants. Equal MAX values are permitted for this HTTP/2 wire family;
decreasing values fail. Retirement requires terminal directions and consumed
receive data, then folds IDs into compact per-type closed prefixes. A 1024-
stream sequential churn regression leaves no live entries or sparse ranges.

HTTP/2 supports the seven draft-15 SETTINGS codepoints. `Limits.webtransport`
advertises capability and initial credit; capability requires Extended CONNECT
opt-in. `Connection.peerWebTransportSettings()` returns only values whose ACK
was completely sent. `localWebTransportSettings()` returns only locally sent
values acknowledged by the peer. Callers capture those value snapshots at
CONNECT request/acceptance; later updates cannot mutate the copies. Dynamic
updates preserve the old acknowledged value until ACK and reject overlapping
unacknowledged SETTINGS transactions. A blocked submission retires connection
reuse while keeping the old local sent/acknowledged snapshots.

`webtransport.h2.runtime` now establishes an HTTP/2 WebTransport Session over
TLS with negotiated `h2`. The client waits for acknowledged
SETTINGS_ENABLE_CONNECT_PROTOCOL and SETTINGS_WT_ENABLED state before opening
Extended CONNECT. The server validates HTTPS CONNECT metadata and the existing
Origin policy, negotiates WT-Available-Protocols/WT-Protocol, and returns
stream-scoped 400, 403, or 405 rejection where admission fails. Invalid
requests do not retire healthy sibling streams.

`connectAttemptWith{Timeout,Deadline}` preserves a complete non-2xx response
for application policy: status, response headers, bounded DATA and trailers
remain owned until `deinit`. `requireAccepted` transfers an accepted Session
and otherwise returns `SessionRejected` without destroying the inspection
surface. Accepted Sessions retain their response headers after that transfer.
On the server, `PendingSession.rejectWith{Timeout,Deadline}` sends status,
headers, body and trailers under the caller's single original budget.

WebTransport-Init is parsed as an RFC 8941 Dictionary across all field lines.
Known `u`, `bl`, and `br` members require non-negative Integers, unknown valid
members and parameters are ignored, duplicate keys use the final member, and
the result takes the greater of the per-Session field and the correct
acknowledged SETTINGS snapshot. RFC 9651-only Date and Display String values
remain invalid for this RFC 8941 field. `initial_receive_stream_data` provides
a typed client/server option for emitting the header without caller-managed
wire text.

The owning `h2.Session` carries virtual streams, reliable datagrams, DRAIN and
CLOSE, reset/stop signals, credit updates, and per-Session TLS exporter
contexts over the CONNECT DATA stream. Payload events remain valid until the
next public receive call. Flow-control waits retain unrelated events in bounded
queues, while interrupted writes own their encoded capsule and resume only the
uncommitted suffix before virtual-stream accounting advances. Deadline and
relative-timeout forms cover admission, receive, sends, control updates,
drain, close, and retained-write resumption.

The protocol foundation's Debug and ReleaseFast filters pass 141/141, package
checks pass 22/22, and the seeded plus deterministic parser fuzz checks pass.

The subsequent virtual-stream/SETTINGS filters pass 155/155 in Debug and
ReleaseFast. Real TCP tests exchange and update all seven SETTINGS in both
directions and retain pre-update snapshots across PING/ACK barriers; a
saturated-socket regression verifies failed-output ownership. Package checks
pass 22/22 and the HTTP/2 connection state-model target passes all three tests.

The complete Session driver filter passes 157/157 in Debug and ReleaseFast;
package checks pass 24/24 and the parser fuzz gate passes 2/2. Its authenticated
TLS loopback tests exchange both stream directions, datagrams, flow-control
updates, reset, stop, drain, close, application protocols, accepted response
metadata, and explicit WebTransport-Init credit. A second regression preserves
a complete 429 response entity, proves 400 rejections for invalid CONNECT
metadata and Init syntax, and then accepts a succeeding sibling Session.
Independent draft-15 implementation or browser/proxy interop remains external
evidence work; the local gate does not claim that evidence.

The multiplexing transport and Session adapter pass 168/168 focused Debug tests
and 134/134 targeted ReleaseFast tests. The production h2c connection fuzz gate
passes 3/3, and the independent bidirectional Hyper matrix passes all 9 build
steps across h2c and TLS while exercising multiplexing, cancellation, flow
control, GOAWAY, pooling, trailers, redirects, and TLS KeyUpdate. Hyper does not
implement draft-15 WebTransport, so this proves the shared HTTP/2 router stayed
interoperable; it is not presented as independent WebTransport evidence.

`webtransport.h2.runtime.connectDuplexWith{Timeout,Deadline}` and the matching
attempt forms now promote those routed HTTP/2 handles into the same owning
`h2.Session` state machine used by blocking tunnels. Accepted response metadata,
WebTransport-Init, application protocols, resumable Capsule writes, virtual
stream flow control, DATAGRAM, CLOSE and exporter contexts remain shared rather
than duplicated. Non-2xx duplex attempts retain the complete bounded response
entity. Multiple Sessions on one connection may be driven serially; each read
routes sibling frames through the connection owner and later delivers them to
the correct Session without a second socket reader.
