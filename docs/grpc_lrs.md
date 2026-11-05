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
Entries also retain the xDS cluster implementation `edsServiceName` and report
it as `ClusterStats.cluster_service_name`, so management servers can aggregate
clusters that share an EDS service. Unary and streaming responses carrying an
`endpoint-load-metrics-bin` ORCA report accumulate CPU, memory and application
utilization per cluster; `LocalityStats` emits fields 12/13/14 when present,
and named ORCA metrics are emitted as `load_metric_stats` field 5 with per-name
sum and sample counts.

ORCA propagation is opt-in per cluster, matching Envoy's
`lrs_report_endpoint_metrics` contract. The xDS runtime reads CDS field 57
(`lrs_report_endpoint_metrics`, repeated string) and applies it to the
destination channel on publish:

| CDS selector | Propagated metric |
| --- | --- |
| `cpu_utilization` | `LocalityStats` field 12 |
| `mem_utilization` | `LocalityStats` field 13 |
| `application_utilization` | `LocalityStats` field 14 |
| `named_metrics.*` | all named metrics |
| `named_metrics.<name>` | named metric `<name>` |

Unknown selectors are ignored. A cluster with no selectors propagates nothing,
so ORCA reports are decoded but not accumulated. Direct embedders can configure
the same selection with `SharedChannel.setLrsPropagation(cluster, propagation)`.
Counters use a dedicated mutex; disabled channels skip the lock entirely, so
ordinary channels keep their existing hot path.

`SharedChannel.lrsStatsSnapshot(allocator)` returns cumulative counters since
channel creation. `lrsStatsDeltaSnapshot(allocator)` returns the counters since
the previous delta snapshot, which is the LRS reporting-interval contract; the
reporter uses it automatically. In both forms `in_progress` is a current gauge,
while issued, successful, error and dropped counts are interval deltas in the
delta form. `lrs.integration.build` converts either snapshot into
`ClusterStats` with the caller's locality and reporting interval. The reporter
sets `load_report_interval` to the actual elapsed time between reports rather
than the configured interval, matching the proto contract for delayed reports.
Cluster names in the report borrow the snapshot storage, so keep the snapshot
alive until the report is encoded.
## Caller-driven reporter

`lrs.Reporter` wraps a connected `Client` and a source SharedChannel. Its
`onResponse` applies the server interval, cluster set and endpoint-granularity
flag: `send_all_clusters` clears the filter only when the node advertised
`envoy.lrs.supports_send_all_clusters`; otherwise the explicit cluster list is
used. An explicit list reports exactly
those clusters, and an empty list reports none. `nextDeadline` returns the next interval boundary and
`reportIfDueWithDeadline` writes only when that boundary has passed.
`reportWithDeadline` builds a filtered snapshot report immediately. After an
all-zero report, the next consecutive all-zero interval is skipped, matching
grpc-core's `LoadReportCountersAreZero` behavior; the first zero report is
still sent. The caller remains responsible for driving the loop.

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

`run` waits for the next response, the current report deadline, or the overall
deadline, whichever comes first. The overall deadline bounds the socket wait
even when the server's report interval is longer, so a timeout returns promptly
instead of waiting for the next report. A response updates the interval,
cluster filter and endpoint granularity; when the deadline arrives the scheduler
writes a due report and returns to waiting. A terminal stream surfaces
`error.LrsTerminal`; the overall deadline surfaces `error.Timeout`. Run the
scheduler in a background task and cancel it when discovery stops. A real
loopback test drives a unary call, receives an interval response, observes one
report with exact issued/successful counters, and then a terminal. A focused
test also gives the scheduler a 100 ms budget while the server advertises a
10-second report interval and asserts the call returns within one second.

`runWithControlPlane` makes the loop recovery-aware. On a terminal it first
calls `ControlPlane.reconnectLrsWithDeadline`, which reconnects the current
server without moving the shared channel. If that fails, it calls
`failoverLrsWithDeadline`, which advances to the next usable bootstrap server,
rebinds the LRS client and reconnects with the retained node. Failed reconnects
are retried with exponential backoff (`retry_initial_ns`, default 100 ms,
doubling to `retry_max_ns`, default 10 s) until the overall deadline; permanent
configuration and allocation errors are returned immediately. Reporting
resumes one interval after a successful reconnect. Use `run` when the
application owns reconnection and `runWithControlPlane` when the scheduler
should survive control-plane restarts. Real tests cover a same-server
reconnect and a failover to a second server, each verifying the next report's
counters.

## Verification

Native tests cover request/response round trips, locality counters, dropped
categories, intervals, malformed/duplicate/over-limit input, UTF-8 rejection,
per-cluster unary and streaming counter aggregation, in-progress tracking,
channel drop and per-category attribution, integration conversion, reporter
interval/filter/rebind behavior, send_all_clusters feature gating, endpoint granularity, EDS service-name propagation, ORCA utilization and named-metric accumulation, interval-delta reporting with actual elapsed intervals and zero-report skipping,
the scheduler report loop, same-server reconnect, scheduler failover across two servers, ControlPlane failover
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
