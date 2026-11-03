# Delta xDS transport

`grpc.xds.ads.delta` implements the v3
`AggregatedDiscoveryService/DeltaAggregatedResources` method over the same
background-owned HTTP/2 SharedChannel stream model as state-of-the-world ADS.
A delta response is a diff: every `Resource` carries its own version, and
removed names are explicit. The transport is schema-agnostic; typed decoding
and publication remain the application's responsibility.

```zig
const delta = netz.grpc.xds.ads.delta;
var client = try delta.Client.init(allocator, sender, .{
    .node = .{ .id = "netz-delta" },
});
defer client.deinit();
try client.setSubscription(cluster_type, &.{ "a", "b" });
try client.connectWithDeadline(deadline);
var event = try client.nextWithDeadline(deadline);
defer event.deinit();
if (event == .update) {
    _ = try typed_apply(event.update); // validate and publish
    try client.acceptAppliedUpdate(event.update);
    _ = try client.flushWithDeadline(deadline); // send the ACK
}
```

## Wire mapping

The codec follows the pinned Envoy v3 `discovery.proto` field numbers.

| Message | Fields |
| --- | --- |
| `DeltaDiscoveryRequest` | `node`=1, `type_url`=2, `resource_names_subscribe`=3, `resource_names_unsubscribe`=4, `initial_resource_versions`=5, `response_nonce`=6, `error_detail`=7 |
| `DeltaDiscoveryResponse` | `system_version_info`=1, `resources`=2, `type_url`=4, `nonce`=5, `removed_resources`=6 |
| `Resource` | `version`=1, `resource`=2, `name`=3, `aliases`=4, `ttl`=6 |

`Resource.resource` may be absent. That is a TTL/heartbeat refresh: the version
and TTL are updated without repeating the payload. A present `google.protobuf.Any`
must have a non-empty type URL, and the client exposes `resourcesMatchType()`
so an application can reject a wrong-type payload before publication. The
decoder also accepts TTLs and aliases; negative or overflowing durations fail
with `InvalidResourceTtl`.

## Subscription and version state

Each type keeps three independent sets:

- the desired resource names (sorted, unique),
- the accepted `name -> version` map for names still desired,
- the pending subscribe/unsubscribe diff for the next request.

Changing the desired set produces only the added and removed names. A name
removed before its first request cancels the pending subscribe; a previously
accepted name removed from the desired set emits an unsubscribe and drops its
version. Names accepted from an unsolicited server update are applied by the
caller but are not retained as reconnect state for a name that is no longer
desired.

A response stores its nonce and a client/epoch/sequence token. `acceptAppliedUpdate`
records the response's per-resource versions and removals after the application
has actually published them; `acknowledgeWithDeadline` does the same and writes
the ACK immediately. `rejectWithDeadline` keeps every accepted version, stores
the non-OK `google.rpc.Status`, and writes a NACK carrying the response nonce.
The nonce is cleared only after the ACK/NACK request is written, so a failed
write leaves the response retryable on a new stream.

`resetStream()` (called by `disconnect` and every terminal) drops nonces,
pending decisions and pending diffs while retaining accepted versions. The first
request of the new stream resubscribes the complete desired set and includes
the accepted versions as `initial_resource_versions`. Resubscribing all names is
intentional: a stream that died before a newly added resource was delivered
would otherwise lose that subscription.

Requests are coalesced per type. A type awaiting an application decision defers
only its own output; unrelated types continue to flush. Subscription changes
that arrive while a decision is pending are retained in the staged state and
sent together with the later ACK/NACK. Allocation failures during staging,
version application, nonce replacement or ACK construction leave the previous
desired set, accepted versions and pending decision intact.

## Bounds and rejected variants

Message, resource-count, resource-payload and name/version sizes are bounded by
`delta.codec.Limits`; subscription counts and type counts are bounded by
`delta.subscriptions.Options`. Duplicate resource names, duplicate removed
names, and a name that is both updated and removed reject the response. The
following variants are rejected rather than silently ignored because applying
them with a plain name would be wrong:

- `Resource.resource_name` (dynamic-parameter variants),
- `DeltaDiscoveryResponse.removed_resource_names` (field 8),
- `DeltaDiscoveryResponse.resource_errors` (field 9, including per-resource
  `NOT_FOUND`).

Delta subscriptions are explicit. An empty desired set sends no subscribe
entries; unlike state-of-the-world ADS it is not a wildcard subscription.

## Verification

`zig build test-lib -Dtest-filter=delta` covers:

- request/response/Resource round trips, TTL heartbeat resources, aliases,
  removed names and initial versions,
- duplicate/overlap rejection, unsupported variants, malformed protobuf,
  message/resource/payload/name bounds and negative TTLs,
- per-resource version updates, removals, heartbeats, unsolicited resources,
  NACK version retention, stale tokens and cross-client tokens,
- reconnect version replay and stale pending decisions,
- constructor and state allocation-failure sweeps,
- a real TLS-free loopback duplex session that observes subscribe diffs,
  unsubscribe diffs, ACK nonces, a wrong-type NACK, terminal reconnect with
  `initial_resource_versions`, and a TTL heartbeat.

`zig build interop-grpc-delta-ads --summary all` runs the transport against an
independent Node peer that loads the pinned official Envoy v3 `ads.proto` and
`discovery.proto` through grpc-js-xds. The peer implements
`DeltaAggregatedResources` itself and asserts the exact request transcript:
initial node/subscriptions, ACK nonce, subscribe/unsubscribe diff, NACK
`error_detail`, reconnect `initial_resource_versions`, and a payload-free TTL
heartbeat ACK. It requires two streams and seven requests. Results and
source/proto hashes are in
`docs/evidence/grpc_delta_ads/2026-11-03.json`.

## Typed automatic runtime

`grpc.xds.runtime.Controller` now has delta entry points alongside the SotW
methods:

```zig
_ = try controller.startDeltaWithDeadline(&client, destination, deadline);
try client.connectWithDeadline(deadline);
var event = try client.nextWithDeadline(deadline);
defer event.deinit();
if (event == .update) {
    _ = try controller.applyDeltaWithDeadline(
        &client, event.update, destination, deadline,
    );
}
```

Start prepares the LDS listener subscription and publishes a rejecting
selector. A listener delta selects inline or dynamic RDS and prepares the exact
RDS name. RDS deltas create or replace the route projection. CDS deltas update
only the clusters referenced by the current route plan; an explicit removal
resolves the cluster as not found and clears its endpoint image. EDS deltas
replace only the assignment named by the present resource, so sibling
assignments and their connections are untouched; an explicit removal publishes
an empty assignment. Payload-free heartbeats reuse the accepted listener,
route, cluster or endpoint image and only advance the per-resource version.
`initial_resource_versions` plus full desired-set replay after reconnect let
the controller resume without resending every accepted payload.

Every publication still goes through the existing transactional plan: typed
resources are validated before publication, the target, target lifetime,
service config and call selector change atomically, and the delta version is
accepted only after the application actually published the update. A failed
publication leaves the previous topology, caches and accepted version intact.
The old projection can remain referenced by an in-flight selector, so its
clusters and endpoints stay usable until the channel retires that generation.

Native tests cover inline and dynamic listeners, partial EDS replacement,
payload-free CDS/EDS/RDS heartbeats, explicit EDS/CDS/RDS/LDS removal, dynamic
RDS restoration and the exact accepted-version map. See
`src/grpc/xds/runtime/delta_tests.zig` and
`docs/evidence/grpc_delta_runtime/2026-11-03.json`.

`zig build interop-grpc-delta-runtime --summary all` drives the same typed
chain against an independent Node peer that implements
`DeltaAggregatedResources` with official Envoy Listener, RouteConfiguration,
Cluster and ClusterLoadAssignment schemas. A real grpc-js backend must receive
exactly two RPCs on one connection: one after the EDS assignment, one after an
explicit EDS removal followed by a resource restore. The client also observes
UNAVAILABLE after the removal and after explicit listener deletion. Results and
source/proto hashes are in
`docs/evidence/grpc_delta_runtime/interop-2026-11-03.json`.

## TTL expiry

Every typed delta resource records its `Resource.ttl` as an awake-clock
deadline. A resource without a TTL clears the timer; a heartbeat with a TTL
refreshes it without republishing the payload. `Controller.nextDeltaExpiry`
returns the earliest outstanding deadline, and
`Controller.expireDeltaWithDeadline` removes every due resource:

- an expired listener publishes the rejecting empty projection and clears its
  RDS name;
- an expired route configuration publishes an empty route image while the
  listener stays accepted;
- an expired CDS cluster clears its endpoint image and resolves as not found;
- an expired EDS assignment publishes an empty assignment, leaving sibling
  assignments untouched.

An expired CDS cluster releases its EDS image with the cluster; restoring the
cluster therefore requires a fresh EDS answer before admission resumes. The
EDS subscription name remains registered, so a reconnect or a later full
assignment can restore the endpoints.

Expired resources are also removed from the accepted `name -> version` map, so
a reconnect does not advertise a payload the application no longer has. The
desired subscription name remains registered; a later full resource (or a
reconnect) can restore it. A payload-free heartbeat for an expired resource is
rejected rather than accepted with a missing image. Heartbeat-only refreshes do
not publish a new target revision.

Native tests use short TTLs to cover EDS/CDS/RDS/LDS expiry, EDS restore,
heartbeat refresh and timer clearing, version forgetting, and the absence of a
new revision for a heartbeat-only refresh. See
`src/grpc/xds/runtime/delta_ttl_tests.zig` and
`docs/evidence/grpc_delta_ttl/2026-11-03.json`.

## Remaining integration

This slice supplies the transport, envelope codec, subscription/version state,
stream client, typed automatic LDS/RDS/CDS/EDS publication and TTL expiry.
Bootstrap parsing and automatic control-plane failover remain follow-up work.
Typed SotW publication is unchanged.
