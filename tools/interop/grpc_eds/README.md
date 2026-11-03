# ADS to EDS application routing interoperability

Run `zig build interop-grpc-eds --summary all`, optionally with
`-- --output /tmp/grpc-eds.json`. It reuses the package-lock-pinned dependencies
under `../grpc_locality`; npm installs them with `npm ci` when absent.

The independent Node control plane encodes official Envoy v3
ClusterLoadAssignment resources. A native ADS client validates and publishes
them into a distinct SharedChannel. Four grpc-js backends independently count
all completed calls and HTTP/2 sessions.

The sequence requires 400 primary-priority calls using locality weights 1:3
and exact round-robin inside a two-endpoint locality; a duplicate-locality
NACK retaining the old version and configuration; 20 calls to the second
priority after primary endpoints become unhealthy; 400 primary calls after
restoration with reversed 3:1 weights; 40 calls after empty and unrelated SotW
responses retain the accepted assignment; and a present empty assignment
removing new backend admission. Exactly thirteen ADS requests and one application HTTP/2
session per backend are required. Payloads and native/server counts must match.

Every subprocess has a bounded wait. Reports bind the native executable,
production/test source files and official EDS/address protobuf schemas with
SHA-256. Separate native tests cover multi-address connection races and target
storage ownership/rollback. This runner establishes the demonstrated EDS
serving behavior; nonzero drop execution, bootstrap/route discovery and other
control-plane policies remain explicit implementation work.
