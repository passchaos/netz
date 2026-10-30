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

This layer does not yet establish an HTTP/2 WebTransport session. The remaining
implementation must supply virtual-stream state/flow control, acknowledged
SETTINGS snapshots, WebTransport-Init parsing, Extended CONNECT admission and
client/server transport drivers. Stream reset Reliable Size equality,
duplicate/reset ordering and flow-control updates must be enforced there.
These requirements remain part of the active library goal.

The protocol foundation's Debug and ReleaseFast filters pass 141/141, package
checks pass 22/22, and the seeded plus deterministic parser fuzz checks pass.
