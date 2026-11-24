# WebTransport operation ownership

An owning HTTP/3 WebTransport Session shares its CONNECT control stream and
associated-stream registry with the underlying H3 reader. Operations that
advance this state must be admitted before parsing buffered control or
performing lifecycle maintenance.

While a client H3 callback borrows response input, Session operations that
advance this state return `ConcurrentRead`. Rejection leaves buffered CLOSE
input, pending Session events, local DRAIN/CLOSE retry state and application
buffers available to their original owner. Deferred lifecycle observation also
waits until the callback releases its borrow; the next admitted operation can
then settle flow-control violations or termination normally.

Blocking DATAGRAM receive requires an independently owned Session. A bound
endpoint dispatcher returns `InvalidDispatcherState` before Session cleanup,
flow grants or queue access. Client and accepted-server Sessions apply the same
rule to owned, caller-buffer and batch receive, including relative-timeout and
absolute-deadline forms. Shared endpoint consumers use their existing pollers.
Blocking Session-event waits and deadline-bound event cleanup have the same
owner requirement. Ordinary Session-event polling remains nonblocking for a
shared endpoint, while still rejecting callback reentry.

Incremental `readStream*`, targeted `readStreamId*` and whole-stream
`receiveStream*` have the same blocking-owner requirement. Admission precedes
stream association, reader-mode claims, buffered payload copies and receive
credit updates, even when a complete payload and FIN are already buffered.
Rejection preserves receive cursors, registry records and caller storage.
`pollStream` and `pollCompleteStream` retain buffered delivery for shared owners.
The composable H3 readers in `runtime/flow/read.zig` enforce this admission before
their progress callbacks as well.

Caller-buffer batch progress is per call: `received_count` clears before owner
admission and retains the completed prefix after work begins. Rejected calls
preserve output bytes, destination pointers and lengths. Batch send similarly
clears `committed_count` before application preflight.

Relative DATAGRAM and stream receive timeouts become an awake-clock deadline at
the public entry point and delegate to the matching deadline form. Owned,
caller-buffer, targeted and batch forms therefore keep one budget through
Session admission, negotiation, control maintenance and socket waits.

The common admission rules live in `webtransport/runtime/owner.zig`.
`connection_lifecycle.zig` uses them before mutable buffered inspection and
deferred cleanup; Session facades admit blocking readers before registering
that cleanup. The [H3 DATAGRAM contract](http3_datagrams.md) supplies the
underlying association queue and completed-prefix delivery semantics.
