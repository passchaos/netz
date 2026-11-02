# EDS request drop admission

Decoded `ClusterLoadAssignment.policy.drop_overloads` now participates in
application RPC admission. `eds.Snapshot.publishWithDeadline` and the ADS/EDS
publication helper replace the channel's owned drop categories in the same
transaction as target/config publication. Invalid categories or allocation
failure leave the prior topology and policy intact.

Categories are evaluated in received order with an independent uniform sample
in `[0, 1000000)` for each category. The first sample below its normalized
`requests_per_million` selects the drop reason. Zero never drops; one million
always drops. Category probabilities compose on surviving traffic, rather than
being added into one total. Fractions decoded from HUNDRED/TEN_THOUSAND/MILLION
retain their existing normalization and saturation to one million.

Unary policy rejection returns `UNAVAILABLE`, an owned message
`EDS-configured drop: <category>`, `transport = null`, and `was_dropped = true`.
The retry driver returns this result immediately before charging retry throttle
or attempting another RPC. Hedging treats it as a fatal winner, stops pending
hedges and cancels active losers. Streaming/duplex opening reports the local
`CallDropped` error before application HEADERS. Neither result invents an HTTP/2
response from the server.

Ordinary Channel accepts `Options.drop_categories` and owns its category names.
SharedChannel accepts the same initial option through `Options.channel` and
exposes dynamic replacements:

```zig
_ = try channel.updateWithTimeout(.{
    .drop_categories = .{ .replace = &.{.{
        .category = "overload",
        .requests_per_million = 250000,
    }} },
}, .fromSeconds(5));
// An empty replacement disables admission drops.
_ = try channel.updateWithTimeout(.{
    .drop_categories = .{ .replace = &.{} },
}, .fromSeconds(5));
```

A physical call is sampled when admitted to the pending queue. An updated
policy reevaluates still-queued calls once under its new policy revision;
unchanged policy contents and ordinary endpoint-owner wakeups do not resample a
waiting call. Already admitted active RPCs continue under their original
transport ownership. A policy containing a full-drop category reports READY
and rejects calls even with no endpoints. This mirrors grpc-core's drop-all
picker behavior and keeps a wait-for-ready caller from waiting forever for a
backend that the control plane intends to reject.

`Channel.dropStats()` and `SharedChannel.dropStats()` expose monotonic evaluated
and dropped counts. Evaluated counts include checks with nonempty categories,
including streaming checks; disabled policy incurs no sampling or category
allocation. A changed policy may evaluate a queued attempt again, so telemetry
counts policy evaluations rather than only logical RPCs. Category storage is
bounded to 256 entries, 4096 bytes per name, valid UTF-8 and normalized fractions.
Metadata/message limits and expired admission budgets retain local validation
before sampling. Shared application drop policy is not copied into transport
owners' internal health/control channels.

`zig build interop-grpc-eds-drop --summary all` compares the actual official
grpc-js-xds cluster-impl picker with deterministic samples, including category
ordering, first-match and accepted boundaries. Independent grpc-js servers then
count ordinary/shared application calls. Native calls validate approximately
half drop with a 500-RPC phase, full-drop retry/hedging/streaming suppression,
dynamic disable followed by resumed delivery, and full rejection on an empty EDS
assignment. Server call counts must equal accepted native calls; rejected calls
produce no application RPC. One backend HTTP/2 session must survive the live
policy changes. Native adjacent tests also verify queued-call reevaluation,
active-call completion, invalid input/cancellation boundaries, allocator rollback,
and no retry-throttle debit. Evidence is recorded in
`docs/evidence/grpc_eds_drop/2026-11-03.json`.

This implements request drop categories. Cluster circuit breaking, LRS drop and
per-locality load reporting, route/resource validation and other remaining xDS
control-plane integration are separate work.

The required full gRPC regression also checks outlier isolation. Its socket
fixture now schedules sample collection, ejection and expiry as distinct phases,
so scheduler delay cannot rotate away the request-volume samples before the
isolation assertion. Actual endpoint selection and timer-driven recovery remain
verified. A canceled queued call is rejected before policy reevaluation and
consumes no additional drop sample.
