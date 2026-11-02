# Per-cluster admission policies

`xds_cluster_impl_experimental` wraps one cluster's endpoint policy with EDS
drop categories and a shared circuit request counter. Cluster-manager callers
use their existing RPC-local cluster key; admission resolves the matching
child before transport selection, so one dropped/saturated cluster does not
block a healthy sibling.

```json
{"loadBalancingConfig":[{"xds_cluster_manager_experimental":{"children":{
  "cluster:payments":{"childPolicy":[{"xds_cluster_impl_experimental":{
    "clusterName":"payments","edsServiceName":"payments-eds",
    "maxConcurrentRequests":64,
    "dropCategories":[{"category":"overload","requestsPerMillion":10000}],
    "childPolicy":[{"round_robin":{}}]
  }}]}
}}}]}
```

The child can keep priority, locality, ring-hash, WRR and outlier behavior.
Admission metadata is retained on that child's runtime root without creating
another endpoint picker. A root policy or direct cluster-manager child may
own admission, optionally through a transparent outlier wrapper. Nested impl
policies/managers and ambiguous placement below unrelated weighted/priority
branches fail validation. Configured cluster/EDS identity text, unsigned
concurrency, drop count/fractions and child-policy depth remain bounded.

Ordinary Channel and SharedChannel apply channel-level drops, then cluster
categories, before circuit checks and endpoint admission. Both scopes retain
their request limits. Identical channel/cluster circuit identities acquire one
permit under the stricter cap; independent identities are reserved together
and released through one owning permit. A second reservation failure releases
the first. Permits retain their process-owned counters across policy removal
and release on actual unary/stream completion or cancellation cleanup.

Drops return marked local unary UNAVAILABLE or pre-wire `CallDropped` for
stream opening, retaining retry/hedging suppression. A drop-all child reports
READY even with no usable endpoints. `discoveryPending` marks unresolved
automatic-discovery children as CONNECTING, so fail-fast readiness does not
turn a pending CDS/EDS lookup into endpoint failure. An active quota rejects
new picks while preserving already active RPCs.

Shared updates transfer category counters and preserve a queued RPC's sample
when category contents are unchanged. A circuit-only change does not create
another drop trial. Changed categories re-evaluate queued calls once. Cluster
dispatch checks each candidate job's policy independently, allowing a healthy
sibling to progress around a failed, pending or saturated child. Ordinary
and shared `clusterDropStats`/`clusterCircuitStats` expose the selected child's
counters; existing channel stats continue to describe channel-level policies.

`zig build interop-grpc-cluster-impl --summary all` uses actual grpc-js-xds
pickers for independent budgets and category drops, plus two grpc-js backends
for ordinary/shared stream and unary traffic. Circuit/category rejections do
not appear on wire, raising an A limit permits another request while A's stream
is active, B remains independent and terminal stream completion restores A
capacity. Native tests cover config/allocator rollback, composite permit
reservation, missing-endpoint drop-all, cross-channel stream counters and
queued discovery/category updates. Evidence is in
`docs/evidence/grpc_cluster_impl/2026-11-03.json`.

The full gRPC gate also exposed a size-based allocation test injection that
locked the same mutex twice after StreamCall/Job layout changes. The injection
now enters once, preserving its cleanup-lock assertion independently of other
allocation sizes.

[Automatic typed discovery](grpc_xds_runtime.md) now generates these cluster
children from LDS/RDS/CDS/EDS. LRS and full control-plane bootstrap/failover/
expiry integration remain subsequent work.
