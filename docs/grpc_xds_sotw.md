# Resource omission in SotW xDS

RDS and EDS DiscoveryResponse messages can contain a subset of subscribed
resources. A resource missing from one such response keeps its last accepted
configuration. LDS and CDS are complete SotW types: omission of a previously
accepted listener or cluster represents deletion. This follows grpc-core's
`XdsResourceType.AllResourcesRequiredInSotW` contract and the same resource-type
methods in the pinned official grpc-js-xds package.

| Type | Missing from response | Present with empty routing/endpoints |
| --- | --- | --- |
| LDS | Delete the accepted listener and reject new route admission | Apply typed Listener/HCM validation |
| CDS | Delete the accepted cluster and its endpoint/admission cache | Apply typed Cluster validation |
| RDS | Keep the accepted selector and HCM projection | Publish a selector with no matching route |
| EDS | Keep the accepted target, drop policy and discovery state | Publish an assignment with no endpoints; its drop policy still applies |

The independent RDS/EDS publication helpers, LDS's dynamic route controller,
CDS's endpoint controller and automatic LDS/RDS/CDS/EDS controller all enforce
this distinction. Every response resource still decodes and checks duplicate
names before acceptance, including resources unrelated to the selected name.
Malformed resources, duplicate names, stale tokens and expired deadlines keep
the accepted version and application configuration intact. Unchanged responses
read the channel revision under the original deadline and reject a closed
channel; they never use an unbounded control-plane mutex wait.

An omitted RDS/EDS resource advances the accepted ADS version and ACKs without
replacing its target or selector epoch. ACK output failure retains that accepted
version for flush/reconnect. For every type, omission of a newly requested
resource is unanswered, since the response may precede its subscription.
Initial omission does not establish an empty assignment: the automatic controller leaves a newly subscribed EDS child
pending, so queued calls retain their original deadline. Explicit empty
assignment delivery completes discovery and changes new admission to the
ordinary unavailable/drop policy. Changing the CDS EDS service name clears the
old image and resumes discovery; a late old-name response cannot resolve it.

Partial EDS updates replace only present children. Siblings keep their exact
snapshot and backend connections. Unchanged assignments and responses with no
selected resources leave the application revision unchanged. Retired resources
are still pruned through the controller's synchronization lifecycle.

Focused native tests cover all five publication paths, omitted and unrelated
resources, initial and service-name discovery, explicit empty routing/targets,
duplicate/malformed responses, ACK failure, stale tokens, expired budgets,
contended channel admission and channel closure.
The corrected `interop-grpc-eds`, `interop-grpc-rds` and
`interop-grpc-xds-runtime` gates send these updates from independent ADS peers
using official Envoy protobuf schemas. Backends count actual permitted calls
and require reused HTTP/2 sessions. The peers also assert the official SDK's
SotW resource-type classification. Results, source hashes and local grpc-core
reference hashes are recorded in
`docs/evidence/grpc_xds_sotw/2026-11-03.json`.

This change covers SotW omission, including existing LDS/CDS deletion behavior.
The separate [delta xDS transport](grpc_delta_xds.md) now covers explicit
removals and Resource envelopes at the transport/state layer. Typed delta
application, TTL expiry, bootstrap parsing and insecure control-plane failover
are implemented; TLS bootstrap credentials, authority-specific control planes
and broader security/filter deployment remain open work.
