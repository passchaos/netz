# HTTP/3 CONNECT DATAGRAM ownership and progress

Authenticated `http3.runtime.HandshakeClient` and `HandshakeServerSession`
associate HTTP DATAGRAM payloads with an Extended CONNECT request stream.
`sendConnectDatagram(s)*`, `pollConnectDatagram*` and
`receiveConnectDatagram(s)*` provide owned and caller-buffer forms. WebTransport
reuses this association and supplies Session control/flow maintenance through
the progress forms.

Every receive operation validates its owner, awake-clock deadline, request
stream ID, association and negotiated HTTP/QUIC DATAGRAM capability before
calling protocol progress or touching the delivery queue. Blocking receive
requires an owning session; dispatcher-bound owners return
`InvalidDispatcherState`. Client callback-reader reentry returns
`ConcurrentRead` before an external progress callback runs, preserving the
current callback's borrowed response data.

Batch progress is per call. `committed_count` and `received_count` are reset to
zero before preflight errors, including callback/dispatcher rejection. After
work starts, counts retain the exact completed logical prefix on error. A
caller can advance past that prefix without interpreting an older call's
count as new progress. Caller-buffer receive trims only completed output slices;
the uncompleted suffix keeps its original destinations.

`receiveConnectDatagramWithProgress`, `receiveConnectDatagramIntoWithProgress`
and `receiveConnectDatagramsIntoWithProgress` share the implementation in
`http3/runtime/datagram/receive.zig`. A progress object declares `ErrorSet` and
supplies `maintain(?Timestamp)`. Optional `inspect(?Timestamp)` checks already
buffered protocol state without socket reads, sleeps or waiting for output
credit. Best-effort nonblocking protocol notifications can remain pending.
The receive helper passes `null` to buffered inspection: the operation's budget
was checked before admission, and payload delivery must survive a deadline
that expires while the fulfilled packet is being parsed. Actual Session or
protocol rejection from inspection still propagates.

Maintenance and socket waits retain the original absolute deadline. If an
output is already filled or a matching DATAGRAM is already queued after a
receive turn, delivery does not require another timed wait. Before the next
batch destination begins, the same budget is checked again, so a completed
prefix remains observable when its remaining suffix times out.

Caller-buffer `BufferTooShort` is non-consuming at the HTTP association queue.
The application can retry with larger storage; direct packet delivery follows
the same policy by retaining an oversized payload in that queue. Stream FIN,
RESET and QUIC connection close retain their ordering relative to queued
DATAGRAMs. WebTransport applies its Session-level termination policy while
inspecting buffered control before exposing application data.
