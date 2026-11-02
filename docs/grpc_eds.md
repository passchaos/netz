# EDS resources and channel publication

`grpc.xds.eds.decode` owns an Envoy v3 `ClusterLoadAssignment` and validates
its locality/endpoint data. `Snapshot.create` projects that resource into a
reference-owned target and service config for a `SharedChannel`.
`publishUpdateWithDeadline` connects ADS response validation to publication:
all resources in that response must decode and have unique cluster names,
the selected assignment is published, its ADS version advances, and its ACK is
flushed under the caller's original deadline.

```zig
var event = try discovery.nextWithTimeout(.fromSeconds(30));
defer event.deinit();
if (event == .update) {
    _ = try netz.grpc.xds.eds.publishUpdateWithDeadline(
        &discovery,
        event.update,
        "backend",
        application_channel,
        .{ .authority = "backend.example" },
        .{},
        deadline,
    );
}
```

The application handles validation errors with the ADS NACK API. A decoding,
projection or channel-update failure leaves the old topology and ADS version
intact. Once publication succeeds, its version is authoritative even if the
remaining ACK budget expires or output fails; a later flush or reconnect sends
the accepted version. Old or cross-client ADS tokens are checked before
publication. A requested assignment omitted from a valid SotW response publishes
an empty target and ACKs its version, removing new RPC admission.

Localities retain region/zone/sub-zone identity, priority and weight. Locality
weights omitted or zero assign no load. Per-endpoint omitted weight defaults
to one, while explicit zero fails validation. UNKNOWN, HEALTHY and DRAINING
resource entries are retained; unsupported/unhealthy statuses are filtered as
in grpc-core. Serving projection selects UNKNOWN/HEALTHY, retaining DRAINING
only in the typed resource for future override-host handling. Dense priority
indices, per-priority uint32 locality-weight sums, duplicate locality identities
and duplicate endpoint addresses are checked. Byte/count/text/address bounds
prevent unbounded resource construction.

Projection generates `priority_experimental` with one
`xds_wrr_locality_experimental` child per priority, preserving the selected
endpoint child policy (`round_robin` by default). Length-prefixed locality path
names avoid collisions between arbitrary locality component strings. Endpoint
weights remain separate from locality weights and are available to endpoint
ring-hash child policies. Numeric TCP IPv4/IPv6 addresses are supported.
Additional addresses stay together as one logical endpoint, using the existing
bounded full-HTTP/2 connection race under one deadline; successful unselected
connections are closed. TLS projection keeps origin identity and authority
separate from the numeric EDS socket address.

A snapshot owns every generated path, key, authority and connector context.
`SharedChannel.Update.target_lifetime` is an explicit retain/release descriptor:
canonical inventory, active sources/workers and retained children keep the
storage alive. A caller can release its Snapshot reference after publication.
Equal path/host/key string content across distinct snapshots preserves ordinary
endpoint connection identity. Config-only updates retain the target owner too.
TLS verification bundles, callbacks and custom contexts within supplied TLS
options retain their existing caller-owned lifetime contracts.

Drop categories are decoded, normalized to requests per million and applied
before endpoint selection. See [request drop admission](grpc_eds_drop.md) for
ordered sampling, unary/streaming errors and dynamic updates. UDP, named
ports/custom resolvers, non-socket addresses and LEDS alternate locality config
forms are rejected. Endpoint metadata, auto-host-rewrite, active health-check
configuration and policy stale-time/overprovisioning integration need further
work. The decoder and projection do not claim those deployment behaviors.

`zig build interop-grpc-eds --summary all` runs an independent ADS control plane
using the official Envoy EDS schema to encode resources and four official
grpc-js application backends. It checks initial locality weighting, a bad
resource NACK preserving version/topology, priority failover when primary
endpoints become unhealthy, restored weighting and SotW deletion. Each backend
must observe one HTTP/2 session across changes. Native adjacent tests cover
allocator rollback, resource limits, path identity, caller snapshot release,
config-only target retention, equal-snapshot connection reuse and alternate
address connection competition. Evidence is in
`docs/evidence/grpc_eds/2026-11-03.json`.

The EDS matrix exposed a nested priority/weighted pick handoff problem. Pending
requests now retain one provisional selected worker and wake it when another
owner makes the choice. Cached choices are checked against the current highest
ready priority, so a lower-priority connection cannot keep new admission after
a higher priority recovers. A deterministic priority selection test covers
that recovery boundary.
