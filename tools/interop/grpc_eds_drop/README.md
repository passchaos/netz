# EDS drop admission interoperability

Run `zig build interop-grpc-eds-drop --summary all`, optionally with
`-- --output /tmp/grpc-eds-drop.json`. The runner uses package-lock-pinned
`../grpc_locality` dependencies and installs them with `npm ci` if absent.

The actual official grpc-js-xds cluster-impl picker receives deterministic
samples for three ordered drop categories. The gate requires first-category,
second-category and accepted results at strict threshold boundaries. Separate
native unit vectors exercise the same semantics.

The independent grpc-js service counts every accepted ordinary/shared RPC.
A native ordinary client issues 500 calls at 50% drop. The shared client receives
50%, 100%, disabled and empty-assignment/100% policies through an official Envoy
EDS protobuf ADS service. Full-drop unary calls with UNAVAILABLE retry configured,
a hedged call, and streaming opening must cause no application RPC; disabling
drops resumes delivery. The shared client requires one hedging attempt and exact
policy evaluation/drop counts. Backend wire counts must equal native accepted
counts and remain on one HTTP/2 session across updates. ADS must observe eight
requests with matching accepted versions/nonces.

Subprocess waits are bounded. Reports bind native binary, source files and the
actual official cluster-impl implementation SHA-256. Adjacent native tests cover
policy update rollback, queued-call reevaluation and active-call preservation.
