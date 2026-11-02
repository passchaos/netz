# RPC-local cluster manager interoperability

Run `zig build interop-grpc-cluster-manager --summary all`. Add
`-- --output /tmp/grpc-cluster-manager.json` to retain the result. Node.js and
npm are required. The runner reuses the package-lock-pinned official grpc-js-xds
1.14.2 dependencies under `../grpc_locality`, installing them with `npm ci` if
missing.

The official xDS manager is instantiated with deterministic child pickers. Its
actual picker must select `a` and `b` from `extraPickInfo.cluster`, return
INTERNAL for unknown/missing clusters, and stop admitting a removed child while
its sibling still works. Native configuration uses grpc-core's
`xds_cluster_manager_experimental` and `childPolicy` names; grpc-js-xds uses
`xds_cluster_manager` and `child_policy`.

Three independent grpc-js servers validate ordinary/shared unary and duplex
RPCs, complete call counts and selector-header absence. Native shared calls
include a refused fourth child: its queued wait-for-ready call must expire while
a later healthy-child call succeeds, and a fail-fast call must return
ConnectionUnavailable despite a ready sibling. A config update removes `a`,
checks UnknownCluster and continued `b` delivery, then restores `a`. Each live
backend must see exactly one HTTP/2 session, including across removal/restoration.
The adjacent native tests additionally prove an admitted call survives child
removal and an ordinary call never dials an unrelated refused child.

All child processes have bounded waits. Reports bind the native binary,
production/test sources and official cluster-manager source with SHA-256. This
is per-RPC policy/transport evidence, while ADS and route-config selection need
separate implementation and validation.
