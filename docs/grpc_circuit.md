# Cluster circuit breaking

`grpc.circuit_breaker` provides a shared in-flight request counter keyed by
`(cluster, eds_service_name)`. Ordinary and shared channels can select that
identity and an admission limit through `Channel.Options.circuit_breaker`:

```zig
var channel = try netz.grpc.SharedChannel.init(allocator, io, target, .{
    .channel = .{ .circuit_breaker = .{
        .cluster = "payments",
        .eds_service_name = "payments-endpoints",
        .max_concurrent_requests = 1024,
    } },
});
```

The same identity across channels shares the count, including ordinary and
background channels. Different EDS service identities remain separate. The
process registry owns copied identity strings independently of the first
channel's allocator or I/O backend. Active request permits retain the counter
until completion even if a channel's policy handle is removed. Registry entries
are removed when the last policy/permit reference leaves.

A queued request does not reserve a permit. Once an endpoint can admit it, an
atomic compare/exchange checks and increments its shared active count. The
limit therefore holds across competing channel/endpoint owners. grpc-core also
checks the shared count before selection, though its separate check/increment
can overshoot under concurrent picks. This implementation makes reservation
atomic. EDS category drops precede the circuit check. Saturated circuit admission
returns a marked local unary `UNAVAILABLE` response with message
`circuit breaker drop`, which retry and hedging treat as terminal policy
rejection. Streaming opening returns `CallDropped` before request HEADERS.
Wait-for-ready does not bypass the circuit cap.

Permits are released when the transport attempt completes, fails, is reset, or
is retired after cancellation. Unary caller interruption alone does not release
capacity while its owner still has an active attempt. Shared stream opening
transfers the permit from its pending job to the active stream; response
metadata or an intermediate message does not finish it. Ordinary stream writers
and duplex calls release through the existing one-shot completion observer.
Shutdown settles transport ownership before counter cleanup. Internal
health/control channels do not inherit application circuit options.

SharedChannel updates can replace the limit or identity atomically:

```zig
_ = try channel.updateWithTimeout(.{
    .circuit_breaker = .{ .replace = .{
        .cluster = "payments",
        .eds_service_name = "payments-endpoints",
        .max_concurrent_requests = 64,
    } },
}, .fromSeconds(5));
// Explicitly remove this channel's policy, while active permits stay valid.
_ = try channel.updateWithTimeout(.{
    .circuit_breaker = .{ .replace = null },
}, .fromSeconds(5));
```

Lowering a limit preserves existing RPCs and rejects new requests until the
count falls below that picker/channel's limit. Raising a limit allows additional
admission. Zero rejects every new attempt. Another channel with the same
identity can retain a different configured limit while observing the same count,
as grpc-core picker instances do. Changes in identity route new permits to the
new counter; already active calls keep their old permits. Invalid identity or
transaction allocation failure preserves the prior policy/revision.

EDS snapshots install a default limit of 1024, using resource name for the EDS
service and, by default, logical cluster. `TargetOptions.cluster` and
`max_concurrent_requests` allow CDS-derived identity/limit to be supplied;
publication includes them in the target/drop/config transaction.
`circuitStats()` exposes shared active count and monotonic admitted/rejected
counts for the currently installed identity. Removing the policy returns an
empty local probe; other policy handles continue to observe its still-active
counter. Admission is bounded per configured cluster identity, while
`max_active_calls_per_endpoint` retains its independent transport queue bound.

`zig build interop-grpc-circuit --summary all` exercises the actual official
grpc-js-xds circuit picker and an independent grpc-js server. Native ordinary and
shared channels verify shared identity, independent EDS identity, changed limits,
non-retryable rejection, stream cancellation and policy removal while a stream
is active. The server requires exactly five permitted RPCs, three channel-owned
HTTP/2 sessions and peer observation of stream cancellation. Native tests also
cover atomic owner races, constructors/registry allocation rollback, lowering
and raising limits with concurrent real RPCs, terminal-only ordinary duplex and client-streaming
release, peer failure/shutdown cleanup and EDS limit installation. Evidence is
in `docs/evidence/grpc_circuit/2026-11-03.json`.

Typed CDS now extracts the first DEFAULT request threshold through
[the CDS controller](grpc_cds.md), publishing its limit and identity with EDS
targets. [Per-child cluster-impl](grpc_cluster_impl.md) now applies selected
cluster budgets independently and composes channel/cluster permits.
[Automatic child orchestration](grpc_xds_runtime.md) and
[source-pinned LRS reporting](grpc_lrs_automatic.md) connect these identities
to accepted CDS. The standalone APIs above explicitly attach one circuit
identity to each channel or EDS projection.
