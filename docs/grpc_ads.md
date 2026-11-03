# xDS v3 ADS sessions

`grpc.xds.ads.Client` owns a state-of-the-world ADS session over a
`SharedChannelSender`. It sends `DiscoveryRequest`, returns owned
`DiscoveryResponse` envelopes, and keeps desired subscriptions and accepted
versions per resource type. Resource `Any.value` images remain opaque for an
application or resource decoder to validate and apply.

```zig
const ads = netz.grpc.xds.ads;
var sender = channel.sender();
defer sender.deinit();
var discovery = try ads.Client.init(allocator, sender, .{
    .node = .{ .id = "worker-1", .cluster = "application" },
});
defer discovery.deinit();
try discovery.setSubscription(
    "type.googleapis.com/envoy.config.cluster.v3.Cluster",
    &.{"backend"},
);
try discovery.connectWithTimeout(.fromSeconds(5));
var event = try discovery.nextWithTimeout(.fromSeconds(30));
defer event.deinit();
switch (event) {
    .update => |update| {
        // Validate and apply resource payloads before accepting their version.
        if (update.resourcesMatchType()) {
            try discovery.acknowledgeWithTimeout(update, .fromSeconds(5));
        } else {
            try discovery.rejectWithTimeout(update, .{
                .message = "resource type mismatch",
            }, .fromSeconds(5));
        }
    },
    .terminal => |terminal| {
        // Apply the application's retry/backoff policy before reconnecting.
        _ = terminal;
    },
}
```

The example's type check illustrates the ACK/NACK API; applications must also
validate each resource schema and commit its configuration before ACK. An
empty resource-name list explicitly subscribes to that type's wildcard. Names
are copied, sorted and checked for duplicates. `setSubscription` coalesces the
latest names without writing; `flushWith{Timeout,Deadline}` sends dirty types,
except a type whose response still awaits an application decision. An ACK/NACK
combines its decision with the latest desired names. Decisions carry a stable client identity, stream epoch
and response sequence so an earlier same-type response or previous stream
cannot overwrite current state.

A successful application acceptance advances the retained version before ACK
output. If ACK encoding allocation fails, the applied version remains dirty
and a later flush can retry it. A transport write failure abandons that stream
because output may have committed a prefix. The next connect replays desired
names and applied versions with empty nonces and no old NACK. A server terminal
similarly closes the session; connection replacement is supplied by the
SharedChannel. `connectWith{Timeout,Deadline}` starts a fresh stream when needed
and uses one budget for opening and subscription replay. Its admission deadline
is separate from `Options.request.timeout`, which controls the entire RPC
lifetime. The default has no whole-RPC deadline. A local receive timeout,
cancellation or executor admission failure preserves the active stream unless
its whole-RPC deadline has expired.

Each stream's first outgoing request includes Node; later requests omit it.
Node owns encoded id, cluster, locality, user-agent and client-feature fields.
Optional `Node.metadata` accepts a serialized `google.protobuf.Struct`. Message,
resource count/size, resource-type count and resource-name bounds are explicit
options. Malformed envelopes, unexpected unregistered resource types and fatal
transport errors terminate the current stream while preserving desired/applied
state. Type mismatches inside a valid response remain available for NACK.
Client operations require one serialized application caller; SharedChannel
continues to own HTTP/2 reads and writes in the background.

`zig build interop-grpc-ads --summary all` uses the official Envoy discovery
protobufs and grpc-js. The independent server verifies Node and metadata,
interleaved CDS/EDS ACKs, a wrong-type NACK retaining the old version, rejection
of a superseded response token, replay on a second stream, empty reconnect
nonces, and continued delivery after a local timeout and a short admission
budget. It requires two ADS streams on exactly one HTTP/2 session. Adjacent
native tests also cover constructor and codec allocation failures, bounded
messages/resources, malformed protobuf, selector ownership and ACK allocation
retry.

This module provides ADS transport and subscription/version state. Typed EDS decoding and publication are provided by
[the EDS adapter](grpc_eds.md), and [the CDS controller](grpc_cds.md) connects
EDS-backed CDS policies and limits to transactional CDS/EDS publication.
[Typed RDS and immutable RPC selectors](grpc_rds.md) publish routing over
existing cluster-manager children. [Client LDS/HCM](grpc_lds.md) now selects
inline/dynamic RDS, inherits HCM duration and drives route subscription updates.
[Automatic multi-cluster discovery](grpc_xds_runtime.md) connects all four
typed resources and prepares CDS/EDS subscriptions with topology publication.
The [delta ADS transport](grpc_delta_xds.md) now provides per-resource versions,
subscribe/unsubscribe diffs, explicit removals, TTL/heartbeat resources,
`initial_resource_versions` replay and the same ACK/NACK ownership model.
Typed delta publication and resource-expiry enforcement are implemented.
[The bootstrap parser and insecure control-plane failover](grpc_bootstrap.md)
select and retry `http://` xDS servers while preserving accepted versions.
TLS bootstrap credentials, authority-specific control planes and LRS remain
required follow-up work for full xDS integration.
