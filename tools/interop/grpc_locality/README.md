# xDS locality policy interoperability

Run `zig build interop-grpc-locality --summary all`. Add
`-- --output /tmp/grpc-locality.json` to retain the report. Node.js and npm are
required; the runner installs the package-lock-pinned official grpc-js-xds
1.14.2 dependencies with `npm ci` when absent.

The official xDS locality implementation generates weighted-target configs for
1:3 and 3:1 locality weights. The runner captures its actual delegated config
and compares it with the native installed runtime's target weights. grpc-js-xds
uses its own `xds_wrr_locality` / `child_policy` JSON spelling; netz uses the
grpc-core `xds_wrr_locality_experimental` / `childPolicy` spelling.

Three official grpc-js servers then verify ordinary (400 RPCs) and shared
(400 + 400 + 20 + 100 RPCs) client routing. The locality with two endpoints must
balance them evenly, while locality weight controls the aggregate ratio.
Shared target updates reverse weights, remove the first locality by setting
its weights to zero, and restore it. Payloads, complete server call counts and
exactly one HTTP/2 session per backend must all match. Every subprocess has a
bounded wait; a failed assertion or native call fails the gate. Reports bind
native binary, source files and official xDS implementation SHA-256 values.

The positive-weight config generation is checked against the independent
JavaScript implementation. Native adjacent tests additionally check grpc-core's
first-positive rule for conflicting weights, missing/zero locality handling,
nested parent paths, allocation failure, in-flight RPC retention and unchanged
priority clocks. This gate does not stand in for full xDS discovery testing.
