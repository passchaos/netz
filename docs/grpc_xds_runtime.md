# Automatic typed xDS discovery

`grpc.xds.runtime.Controller` drives client LDS/HCM, RDS, EDS-backed CDS and EDS
into one SharedChannel. It derives referenced cluster/service subscriptions and
builds cluster-manager topology with per-cluster admission; applications no
longer assemble endpoint addresses or child policy JSON for discovered clusters.

```zig
const controller = try netz.grpc.xds.runtime.Controller.create(allocator, .{
    .listener_name = "frontend",
    .target = .{ .authority = "payments.example" },
});
defer controller.deinit();
_ = try controller.startWithDeadline(&discovery, application, deadline);
try discovery.connectWithDeadline(deadline);
var event = try discovery.nextWithDeadline(deadline);
defer event.deinit();
if (event == .update) {
    _ = try controller.applyWithDeadline(
        &discovery, event.update, application, deadline,
    );
}
```

Start installs a rejecting selector and empty manager before committing the
listener subscription. A valid listener selects inline/dynamic RDS; a route
snapshot derives exact raw CDS names from its cluster keys. CDS supplies EDS
service names, endpoint LB policy and circuit request limits. EDS produces
priority/locality/endpoints and drop categories. The assembled target retains
each projected EDS snapshot and owns prefixed hierarchy paths. Its manager
children wrap their endpoint policy in xds_cluster_impl admission, so circuit
or category policy belongs to the selected cluster.

Referenced children without CDS/EDS answers report CONNECTING and queue
fail-fast RPCs under their original deadline. SotW omission removes LDS/CDS
resources; omitted RDS/EDS resources retain their cache and unanswered EDS
children remain pending. Present empty routes/assignments remove new admission. CDS EDS-name
changes immediately clear previous endpoints and create a pending child until
matching service data arrives. Same-name CDS policy updates reproject cached
EDS bytes; identical configuration and unchanged EDS responses retain their
projected snapshot. RDS/HCM route changes reuse the LDS projection semantics,
including inline/dynamic selection and timeout defaults.

Every CDS/EDS response resource is typed and validates before publication,
with sorted duplicate names. A staging plan clones immutable identity/CDS and
snapshot references, changes only its provisional cache, and prepares desired
CDS/EDS type/name sets together. The ADS batch reserves capacity for all new
types and owns sorted names before the SharedChannel transaction. Actual
publication replaces target, target lifetime, manager service config and route
selector atomically. Only then are names and accepted caches swapped without
allocation, followed by ADS version acceptance and ACK output. Malformed or
duplicate resources, quota/bounds, stale tokens, expired budgets, subscription
allocation or topology failure preserve prior caches/names/revision/version.
An ACK output failure retains the already applied version as with typed
LDS/RDS/CDS adapters.

Old projection epochs retain their cluster dependencies while config/call
references remain. `synchronizeWithDeadline` and later updates prune unused
projection/cache entries when only the controller reference remains. This
keeps an in-flight RPC and its retry decision usable after new routes select
another cluster. Endpoint/circuit transport references outlive cache removal.
The last named subscription remains registered when its desired set is empty
to avoid a wildcard request; extra late resources validate but do not recreate
unreferenced children. The caller invokes synchronization while driving the
serialized discovery loop.

Controller settings bound clusters/projections and decoded route/CDS/EDS/target
storage. The budget counts unique shared route snapshots rather than charging
each HCM projection for the same data. Cluster identity and EDS snapshots use
owning references during staging; a transaction's discarded plan releases only
its provisional references. The target and published selector keep storage
alive after controller destruction. Caller-provided TLS bundles/callback
contexts retain their existing lifetime requirements.

`local_service_config_json` supplies local method/health/retry configuration;
otherwise start captures the destination's initial JSON. Discovery replaces
its LB field while preserving the local remainder. Channel-level explicit
drop/circuit policies compose with cluster policies. Target authority, HTTP/2
limits, TLS addressing and multi-address connection-race settings come from
Options.target, with actual child LB/circuit identities supplied by CDS.

`zig build interop-grpc-xds-runtime --summary all` starts with an empty
application data plane and receives official LDS → RDS → CDS → EDS resources
from an independent grpc-js ADS server. Two grpc-js backends verify pending
discovery delivery, empty RDS/EDS response retention, partial EDS sibling
retention, quota/category isolation, EDS service-name replacement,
CDS duplicate NACK rollback, route changes, old RPC completion and listener
deletion. The peer counts ten actual RPCs and requires one HTTP/2 session for
each application backend. Native tests cover full chain/cache transitions,
constructor/start allocation rollback, batched subscription commit, local
configuration preservation and resource/entry budget priority. Evidence is in
`docs/evidence/grpc_xds_runtime/2026-11-03.json`; corrected SotW semantics
are recorded in `docs/evidence/grpc_xds_sotw/2026-11-03/runtime.Debug.json`.

The controller requires one serialized application caller and an ADS transport
provided by the application. The [delta ADS transport](grpc_delta_xds.md) now
provides per-resource versions, subscribe/unsubscribe diffs, explicit removals
and `initial_resource_versions` replay, and this controller has matching
`startDeltaWithDeadline`, `synchronizeDeltaWithDeadline` and
`applyDeltaWithDeadline` entry points for typed incremental LDS/RDS/CDS/EDS
publication. `nextDeltaExpiry` and `expireDeltaWithDeadline` enforce
`Resource.ttl` for all four types, refresh timers from payload-free heartbeats
and forget expired accepted versions. The
[bootstrap parser and control-plane failover](grpc_bootstrap.md)
select `http://` servers, retry refused servers and rebind the same delta client
with `initial_resource_versions` replay. Certificate providers and certificate rotation,
authority-specific control planes, aggregate/DNS CDS and full security, streaming LRS call-stat aggregation, periodic reporting,
non-router filters and capture/rewriting remain open. Unsupported resource
features continue to fail typed validation rather than claim deployment
support.
