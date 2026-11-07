# Automatic LRS discovery-source binding

Bootstrap-managed ADS clients now retain immutable discovery provenance.
`ControlPlane.newSotwClient`, `newDeltaClient` and its managed delta client
carry the selected server, copied node/request inputs and retained bootstrap
credential/provider configuration. Each received update freezes that source;
accepted CDS owns it until replacement CDS is accepted.

For managed CDS `lrs_server: self`, the runtime Controller stages an independent
LRS owner pinned to the server that delivered that resource. It reserves runner
storage and background task admission before target publication, then activates
network connection afterward. An unavailable reporting server does not turn a
valid CDS resource into a NACK or delay publication until a connection succeeds.

Discovery failover and reporting migration are distinct events. Cached CDS
continues reporting to its original source after ADS rebind. Accepting new CDS,
including identical bytes from a different source, publishes a new reporting
binding for new calls. Calls already admitted retain their source and metric
selection through completion. Old owners remain while calls or final deltas
need them; publication pins coordinate idle retirement with rapid disable and
re-enable updates.

Shared counters distinguish `(discovery source, cluster, EDS service)`.
Source-specific delta snapshots advance only that source's interval baselines,
so a new runner cannot consume another runner's unsent completion or metrics.
The LRS wire report still uses Envoy's cluster/service identities on the proper
server connection. Source inventory is bounded by `Limits.max_lrs_sources`,
and source/allocation/task preparation failure preserves prior target state.

The immutable source key is a 32-byte SHA-256 fingerprint of bounded canonical
server/node/request and provider configuration. Strings and node metadata are
owned; bootstrap lifetime is retained. Automatic transports retry their pinned
accepted server independently of ADS mutable failover state. Authority-specific
control-plane loops use the selected authority's server inventory.

`disable_automatic_lrs` opts out. Existing `Options.lrs` takes precedence as an
explicit transport/failover override. Manually constructed ADS clients without
source provenance retain their explicit-LRS behavior; applications can use
the managed factories or supply a retained discovery source. Callers requesting
local channel statistics can still inspect those separately from automatic
transport. `automatic_lrs` configures polling, connection and reporting options.

Native tests cover SotW and delta automatic activation, initial and late CDS
enablement, default-disabled channel statistics, deletion, A-to-B provenance,
old in-flight calls, NACK/OOM/source-limit rollback, unavailable LRS opening,
explicit override and opt-out, node/TLS/provider lifetime, and authority retry
inventory. See [CDS registrations](grpc_lrs_registration.md) for admission and
metric handling, and the validation artifacts for the measured scope.

The independent `interop-grpc-lrs-automatic` fixture uses official Envoy and
ORCA schemas with seven real application RPCs and no explicit LRS options.
It checks cached A CDS after ADS rebind to B, a rejected replacement,
byte-identical accepted B CDS, and completion of a held A call. A reports
three issued and three successful calls; B reports one issued and one failed
call, with exact utilization and `named_metrics.load` sums. The unselected
cluster stays routable and absent from LRS. Closing C's listening socket while
retaining its ADS connection forces a new LRS connection refusal; valid CDS
must still publish within 250 ms and route a successful RPC.

This wire fixture covers SotW. Delta activation, receipt provenance and actual
generated unary/streaming routes are covered by native tests. Service lookup
uses the full generated manager route key (for example `cluster:eligible`);
only the cluster name placed in LRS is stripped to `eligible`. The reporting
transport's terminal error is published atomically for live `failureReason()`
queries. Commands, source/executable/schema hashes, strict counters and
diagnosed failure artifacts are in `docs/evidence/grpc_lrs_automatic/2026-11-07/`.
