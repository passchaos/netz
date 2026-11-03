# Typed delta xDS runtime gate

Run `zig build interop-grpc-delta-runtime --summary all`, adding
`-- --output <report.json>` to save hashes and results.

The independent peer loads the pinned official Envoy v3 schemas and implements
`DeltaAggregatedResources` with real Listener, RouteConfiguration, Cluster and
ClusterLoadAssignment payloads. The native client uses
`runtime.Controller.startDeltaWithDeadline` and `applyDeltaWithDeadline` against
a destination channel connected to an official grpc-js backend.

The peer checks the exact subscription/ACK sequence: LDS listener, RDS route
config, CDS cluster, EDS assignment, an explicit EDS removal, an EDS restore,
and an explicit LDS removal. The client must observe one backend endpoint and a
successful RPC after the EDS resource, zero endpoints and UNAVAILABLE after the
explicit removal, a restored endpoint and successful RPC after the EDS resource,
and UNAVAILABLE after listener deletion. The backend must see exactly two
application calls on one connection. Typed payloads are decoded by netz; this
gate does not reuse a SotW response path.
