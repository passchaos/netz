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

`Options.lrs` optionally makes the controller own an `lrs.Runner`. The runner
starts once after the first successful SotW or delta start/synchronization and
is joined by `Controller.deinit`. Its LRS control plane must be dedicated to
the runner, and the destination channel must enable LRS statistics; see
[LRS](grpc_lrs.md#controller-owned-runner).

CDS clusters may reference SDS certificate and validation secrets. The
controller subscribes to those names, caches the decoded `Secret` resources,
and keeps a referencing cluster pending until every secret is available. A
resolved cluster publishes its endpoints with the secret material; secret
rotation reprojects it, and removal makes it pending again instead of falling
back to cleartext. See [SDS](grpc_sds.md).

`Options.ignore_resource_deletion` implements the gRPC xDS server feature of
the same name. When set, a SotW omission or a delta `removed_resources` entry
retains the accepted listener, route, cluster or endpoint assignment instead
of deleting it. The default remains deletion for LDS/CDS and state retention
for RDS/EDS as before.

`Options.fail_on_data_errors` implements the gRPC xDS server feature of the
same name. When a SotW or delta resource fails typed validation, its cached
listener/cluster/assignment/secret is dropped and the change is published, then
the response is still NACKed so the control plane can correct it. Without the
option the previous cached resource is retained, matching the default
fail-safe behavior. The invalid resource's name is recovered leniently from
field 1 when the payload is truncated after it.

`Options.trusted_xds_server` implements the gRPC xDS server feature of the same
name. It is required before an RDS `auto_host_rewrite` may replace the request
`:authority` with the selected endpoint's authority; without it the field is
ignored, matching grpc-core's refusal to let an untrusted control plane
redirect requests. Bootstrap already exposes the parsed flag on each server.

`Options.resource_timer_is_transient_error` implements the gRPC xDS server
feature of the same name together with the initial resource-fetch timer.
`Controller.nextResourceTimerExpiry` and `pollResourceTimers` arm a timer for
every subscribed but undelivered LDS/RDS/CDS/EDS/SDS resource (15 s by
default, or 30 s with the feature), and `resourceStatus` reports `requested`,
`acked`, `does_not_exist` or `timeout`. Without the feature an expired timer
reports `does_not_exist`; with it the same resource reports a transient
`timeout`, matching grpc-core. A delivered resource clears its timer and
reports `acked`. `Controller.expireResourceTimersWithDeadline` additionally
publishes the does-not-exist effect: a timed-out EDS resource becomes an empty
assignment, while LDS/RDS/CDS/SDS were never cached and therefore already
match the absent configuration. The transient-error mode publishes nothing.
`Options.resource_timer_timeout` may shorten the budget, for example in
deterministic tests.

`Options.authority` and `Options.additional_authorities` enable `xdstp://`
resource names for one or more authorities served by the controller's control
plane. The listener, route, cluster, endpoint-assignment and secret names are
parsed and must match one of the configured authorities and their expected
resource type. Old-style names remain valid. Authorities routed to different
xDS servers still need separate controllers; routing several authorities from
one controller over distinct ADS streams remains open.

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
`Resource.ttl` for LDS/RDS/CDS/EDS, refresh timers from payload-free heartbeats
and forget expired accepted versions. Delta SDS resources use the same TTL
driver, including payload-free heartbeat refreshes. The
[bootstrap parser and control-plane failover](grpc_bootstrap.md)
select `http://` servers, retry refused servers and rebind the same delta client
with `initial_resource_versions` replay. Bootstrap `refresh_interval` exposes a
TLS reload schedule checked by `reloadIfDue`; certificate providers and
authority-specific control planes, other custom CDS extensions (STATIC, DNS and
`envoy.clusters.aggregate` clusters are supported), full security (inline
upstream TLS and SDS-provided certificate/validation material are supported),
non-router filters and capture/rewriting remain open.
Aggregate clusters subscribe to their ordered leaf clusters and publish an
ordered `priority_experimental` child policy over the live leaf policies. The
aggregate name remains a manager selection key rather than an endpoint path
element, so leaf cluster paths match directly. A loopback regression serves the
first leaf, retires it, and verifies the same channel falls back to the second
leaf in order.
## Client status discovery

`grpc.xds.csds.encodeResponse` encodes one
`envoy.service.status.v3.ClientStatusResponse` for a client-side CSDS
`FetchClientStatus` handler. `Controller.encodeClientStatus(client, allocator,
options)` gathers the accepted LDS/RDS/CDS/EDS/SDS resources with their type
URL, name, raw wire bytes and ACKED status; SotW reports the type's accepted
version and delta reports the per-resource accepted version. Subscribed but
undelivered resources are included without wire bytes as REQUESTED or
DOES_NOT_EXIST, so a dump taken immediately after start shows what the client is
waiting for. Pass the encoded `ads.codec.encodeNode` bytes as `Options.node`. The application serves the admin
service from its own gRPC server and returns these response bytes; netz does not
own an admin listener, and the request's node matchers are ignored because the
response describes this client.

`Controller.fetchClientStatus(client, allocator, request_bytes, options)` serves
one `FetchClientStatus` request body directly: it validates and decodes the
request, ignores node matchers, and honors `exclude_resource_contents` by
omitting resource wire bytes while keeping type, name, version and status.

```zig
const node = try netz.grpc.xds.ads.codec.encodeNode(allocator, configuration.adsNode());
defer allocator.free(node);
const response = try controller.fetchClientStatus(
    discovery, allocator, request_bytes, .{ .node = node },
);
```

`zig build interop-grpc-csds` emits one response and decodes it with the
official Envoy `csds.proto` schema shipped by the pinned grpc-js-xds
dependency, checking the node, scope, every resource type/name/version/status
and the accepted `google.protobuf.Any` bytes.

Unsupported resource features continue to fail typed validation rather than
claim deployment support.
