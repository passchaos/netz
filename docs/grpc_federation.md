# Managed federated xDS discovery

`grpc.xds.runtime.managed.Managed(.sotw)` and `Managed(.delta)` own discovery
sessions for bootstrap authorities while feeding one transactional Controller
and data channel. They derive initial listener names through
[bootstrap client targets](grpc_client_target.md), then route RDS/CDS/EDS/SDS
dependency watches by each resource name's authority. Old-style names use the
top-level bootstrap servers; an authority with no server inventory inherits
that inventory.

```zig
const Managed = grpc.xds.runtime.managed.Managed(.sotw);
const discovery = try Managed.createForTarget(
    allocator, io, configuration, channel, "xds://tenant/frontend", .{},
);
defer discovery.deinit();
_ = try discovery.startWithDeadline(deadline);
var event = try discovery.nextWithDeadline(deadline);
defer event.deinit();
_ = try discovery.applyWithDeadline(&event, deadline);
```

Callers serialize facade operations. Returned events own their supplying
Session reference and response/error until `Event.deinit`. A transport outcome
can be reconnected on its authority with `reconnectWithDeadline`; its failover
argument selects whether to advance that authority's bootstrap inventory.
`synchronizeWithDeadline` reconciles watches, and delta mode exposes the next
expiry and transactional expiry application.

Before target publication, the facade prepares every affected discovery
subscription batch. New Session membership is reserved provisionally, so
validation, allocation and publication failure release unused membership and
do not consume the Session limit. Accepted inner preparations remain owned
through nested LDS/RDS/CDS dependency changes. Network reads are joined before
competing outcomes enter pending storage. Retired authorities discard their
cached outcomes even when a failed transport no longer has a stream.

Shared streaming readers retain their default RPC-cancellation behavior.
ADS readers opt into local read interruption, allowing the managed receiver to
cancel a competing wait while preserving that ADS stream and its buffered
decoder state. Explicit RPC cancellation and RPC deadline expiry remain
terminal. A later read can consume the buffered response from the same stream.

SotW omission and delta removals/heartbeats affect only the supplying authority.
Server features such as trusted xDS, data-error handling and deletion policy
are applied to that authority's resource operation and restored afterward.
SDS replacement/removal and TTL/version changes stage before publication;
allocation or publication failure preserves accepted caches and versions.

A replacement route waiting for dependencies retains the previous valid RPC
selector and its required watches. Target entries use current accepted state:
withdrawn TLS material, endpoints and clusters are not restored by selector
retention. Already admitted calls retain their own selector/transport lifetime.
Accepted CDS still carries its discovery Source for automatic LRS, so reporting
continues on the correct supplying server across route and discovery changes.

Bootstrap server targets accept ordinary DNS/IP `host:port` and `dns:///`
spelling alongside HTTP/HTTPS aliases. The first supported channel credential
selects plaintext or TLS; a failed TLS connection does not select a later
insecure credential. Only selected TLS material is loaded. Raw Controller and
ADS client entry points remain available for applications that own dispatch.

The independent `interop-grpc-federation` fixture uses two official-schema ADS
servers and real backends. It checks A LDS to B RDS/CDS/EDS, scoped cache
decisions, a pending B-to-A handoff, old B-call completion and source-specific
automatic LRS. Both SotW and delta modes use the same public managed facade.
Native tests additionally cover quota/prepare rollback, source feature scope,
pending-handoff SDS withdrawal, expiry rollback and event lifetime.
Cluster quotas count unique dependencies across retained route projections.
Storage limits include candidate and retained serving-inventory backing
allocations before publication, with cache/version/revision rollback on rejection.
CSDS reports inline route contents as part of LDS; they do not acquire an
independent RDS version or acceptance status.

`Managed.encodeClientStatus(allocator, options)` and
`fetchClientStatus(allocator, request_bytes, options)` expose one CSDS client
configuration for the complete desired authority graph. Each accepted resource
owns its wire bytes, version and acceptance time independently of a SotW
response's type version. Retained old RDS watches therefore keep their own
version while a replacement route waits for dependencies. Retired watches leave
the dump after synchronization. The bootstrap node is included by default;
`Options.node` can supply a different encoded node.

NACK entries preserve the previously accepted image unless data-error policy
withdraws it. `error_state` records the rejected version, details and attempt
time separately. Content exclusion keeps all of that metadata. A partial
data-error publication records valid siblings when their cache transaction
commits; sending the NACK does not change their acceptance time. A later
rejection of identical wire/version is still a distinct failed attempt.

`diagnostics.max_resources` defaults to 65,536 and
`diagnostics.max_storage_bytes` to 64 MiB. The storage budget counts candidate
and retained history together, including owned resource buffers and inventory
capacity. Preparation failure preserves cache publication and diagnostic
history. Already returned response bytes own their snapshot independently of
later discovery changes or facade teardown.

`nextResourceTimerExpiry`, `pollResourceTimers` and `resourceStatus` use each
supplying session's server features. Refreshing one authority preserves other
authorities' timers. CSDS reports current Envoy `TIMEOUT` for transient initial
fetch failures and `DOES_NOT_EXIST` for the ordinary expiry policy.
`grpc.xds.csds_service.respondManagedFetch` serves these queries through an
application-owned gRPC admin connection. Serialize queries with discovery
operations, as with the other facade APIs.
