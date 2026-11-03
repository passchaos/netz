# Load Reporting Service

`grpc.xds.lrs` implements the v3
`LoadReportingService/StreamLoadStats` wire protocol over the same
background-owned SharedChannel duplex model as ADS. The application supplies
aggregated per-cluster counters; the module owns envelopes, stream state and
report output.

```zig
var client = try netz.grpc.xds.lrs.Client.init(allocator, sender, .{
    .node = .{
        .id = "netz-lrs",
        .client_features = &.{"envoy.lrs.supports_send_all_clusters"},
    },
});
defer client.deinit();
try client.connectWithDeadline(deadline);
var event = try client.nextWithDeadline(deadline);
defer event.deinit();
if (event == .response) {
    // event.response.value.clusters / interval_ns / flags
}
try client.reportWithDeadline(&cluster_stats, deadline);
```

## Envelopes

`codec` owns `LoadStatsRequest`, `LoadStatsResponse`, `ClusterStats`,
`UpstreamLocalityStats`, `Locality` and `DroppedRequests`.

| Message | Fields |
| --- | --- |
| `LoadStatsRequest` | `node`=1, `cluster_stats`=2 |
| `LoadStatsResponse` | `clusters`=1, `load_reporting_interval`=2, `report_endpoint_granularity`=3, `send_all_clusters`=4 |
| `ClusterStats` | `cluster_name`=1, `upstream_locality_stats`=2, `total_dropped_requests`=3, `load_report_interval`=4, `dropped_requests`=5, `cluster_service_name`=6 |
| `UpstreamLocalityStats` | `locality`=1, `total_successful_requests`=2, `total_requests_in_progress`=3, `total_error_requests`=4, `total_issued_requests`=8 |
| `DroppedRequests` | `category`=1, `dropped_count`=2 |

The codec validates UTF-8, non-empty cluster/category names, duplicate cluster
names, positive durations, malformed protobuf and bounded message/cluster/
locality/dropped/text sizes. Requests can be decoded by an independent peer
through `decodeRequest`, and responses through `decodeResponse`.

## Stream behavior

The first request on every stream carries the serialized ADS Node, including
`client_features`. Later report requests omit the node. The server response
selects cluster names, the minimum reporting interval and whether endpoint
granularity is requested; `send_all_clusters` is honored only when the node
advertises `envoy.lrs.supports_send_all_clusters`.

`reportWithDeadline` writes the caller's `ClusterStats` list. A terminal or
ambiguous write failure disconnects the stream; the next `connectWithDeadline`
starts a fresh stream and sends the node again. The caller drives reporting
from the response interval. There is no ACK/NACK protocol in LRS.

## Channel counters

`SharedChannel.Options.enable_lrs_stats = true` opts into per-cluster counters.
Each unary attempt increments issued and in-progress when the worker opens the
stream, then success/error and decrements in-progress at completion. Streaming
calls increment issued and in-progress when the stream opens and success/error
plus the in-progress decrement when the terminal arrives. Queue, drop and
circuit rejections never increment issued or in-progress. Channel drops and circuit
rejections increment total dropped requests and per-category counts for the
RPC-local cluster; circuit rejections use the `circuit_breaking` category.
Per-endpoint counters are retained for resolved IPv4/IPv6 endpoints; host
endpoints without a resolved socket address omit endpoint granularity.
Counters use a dedicated mutex; disabled channels skip the lock entirely, so
ordinary channels keep their existing hot path.

`SharedChannel.lrsStatsSnapshot(allocator)` returns owned entries;
`lrs.integration.build` converts them into `ClusterStats` with the caller's
locality and reporting interval. Cluster names in the report borrow the
snapshot storage, so keep the snapshot alive until the report is encoded.
## Caller-driven reporter

`lrs.Reporter` wraps a connected `Client` and a source SharedChannel. Its
`onResponse` applies the server interval, cluster set and endpoint-granularity
flag: `send_all_clusters` clears the filter, an explicit list reports exactly
those clusters, and an empty list reports none. `nextDeadline` returns the next interval boundary and
`reportIfDueWithDeadline` writes only when that boundary has passed.
`reportWithDeadline` builds a filtered snapshot report immediately. The caller
remains responsible for driving the loop.

`Client.rebind` moves the LRS client to a new channel while retaining the
encoded node. `ControlPlane.moveToNextServer` switches the shared control
channel without connecting its owned delta client, then
`ControlPlane.rebindLrs` moves the LRS client and the reporter keeps using the
same client pointer. The next connect sends the node again on the new stream.
A real two-server test covers this composition.

## Scheduler

`lrs.Scheduler` owns a `Reporter` and drives the report loop:

```zig
var scheduler = lrs.Scheduler.init(allocator, &client, channel, .{});
defer scheduler.deinit();
scheduler.runWithTimeout(timeout) catch |err| switch (err) {
    error.LrsTerminal => {}, // server closed the stream
    error.Timeout => {}, // application deadline expired
    else => return err,
};
```

`run` waits for the next response or the current report deadline, whichever
comes first. A response updates the interval, cluster filter and endpoint
granularity; when the deadline arrives the scheduler writes a due report and
returns to waiting. A terminal stream surfaces `error.LrsTerminal`; the overall
deadline surfaces `error.Timeout`. Run the scheduler in a background task and
cancel it when discovery stops. A real loopback test drives a unary call,
receives an interval response, observes one report with exact
issued/successful counters, and then a terminal.

`runWithControlPlane` makes the loop failover-aware. On a terminal it calls
`ControlPlane.failoverLrsWithDeadline`, which advances to the next usable
bootstrap server, rebinds the LRS client and reconnects with the retained node;
reporting resumes one interval after the new stream starts. A server that
refuses the reconnect is skipped until every usable server has been tried or
the overall deadline expires. Use `run` when the application owns reconnection
and `runWithControlPlane` when the scheduler should survive control-plane
restarts. A real two-server test terminates the first stream, observes the
failover to the second server and verifies the second report's counters.

## Verification

Native tests cover request/response round trips, locality counters, dropped
categories, intervals, malformed/duplicate/over-limit input, UTF-8 rejection,
per-cluster unary and streaming counter aggregation, in-progress tracking,
channel drop and per-category attribution, integration conversion, reporter
interval/filter/rebind behavior, endpoint granularity, the scheduler report
loop, scheduler failover across two servers, ControlPlane failover
composition, and a real
loopback duplex session that observes the node, a response, a report with exact
counters, a second `send_all_clusters` response, a terminal, and node replay on
a replacement stream. See
`docs/evidence/grpc_lrs/native-2026-11-03.json`.

`zig build interop-grpc-lrs` runs the client against an independent Node peer
that loads the pinned official Envoy `lrs.proto` and `load_report.proto`. It
checks exact node/features, response interval and flags, report counters,
cluster/service names, dropped requests, endpoint address/port and counters,
then a second `send_all_clusters` response. Results and source/proto hashes are in
`docs/evidence/grpc_lrs/2026-11-03.json`.

## Remaining integration

Unary and streaming channel counters, endpoint granularity, envelopes, the
caller-driven reporter, the foreground scheduler, ControlPlane
failover/reload composition and rebinding are complete. Applications still own
the task that runs `Scheduler.run` and the decision to reconnect after
`error.LrsTerminal` or `error.Timeout`.
