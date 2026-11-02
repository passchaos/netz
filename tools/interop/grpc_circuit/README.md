# Cluster circuit interoperability

Run `zig build interop-grpc-circuit --summary all`, optionally with
`-- --output /tmp/grpc-circuit.json`. Node.js/npm are required; package-lock-pinned
`../grpc_locality` dependencies install with `npm ci` if absent.

The actual official grpc-js-xds cluster-impl picker is instantiated twice with
the same cluster/EDS identity and once with a distinct EDS identity. Its request
start/end callbacks must make the same-identity picker drop, leave the separate
EDS picker available and restore admission after completion.

The independent grpc-js service verifies native ordinary/shared channels. A
held unary request blocks the ordinary channel under cap one. A separate EDS
identity can complete another call. Raising cap to two admits a request that
releases the held call. A shared stream then holds capacity after a message,
causes a hedged unary to drop with one attempt, and remains counted when this
channel removes its policy. Peer-confirmed stream cancellation releases that
identity for an ordinary unary. Zero limit rejects stream and unary admission.

The server requires exactly five application RPCs, no rejected payload, three
HTTP/2 sessions and one canceled stream. Native counters require four admitted
and four rejected attempts for the shared identity and zero remaining active
requests. Retry-throttle balance must remain unchanged on circuit rejection.
Every subprocess has a bounded wait; reports bind executable, source and actual
official cluster-impl hashes. Adjacent tests broaden lifecycle and atomic cap
coverage, and the EDS/drop gates validate their existing dynamic policies with
circuit admission enabled.
