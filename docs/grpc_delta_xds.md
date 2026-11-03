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

## Remaining integration

This slice supplies the transport, envelope codec, subscription/version state
and stream client. Typed delta publication into the automatic LDS/RDS/CDS/EDS
controller and TTL expiry enforcement remain follow-up work. Typed SotW
publication is unchanged.
