# Listener-driven client routing gate

Run `zig build interop-grpc-lds --summary all`; add
`-- --output <report.json>` to store the report and source hashes.

The official Envoy LDS/HCM/RDS schemas deliver inline and dynamic routing
through ADS. Actual grpc-js-xds validation checks the common fixture contracts;
native tests additionally cover grpc-core's effective terminal ordering when
an ignored optional filter follows the router.

Two grpc-js backends count 38 RPCs, including duplex, slow calls, and four
allowed RBAC route overrides. Eight canonical RBAC probes check proto3's
omitted ALLOW action, the HTTP rules wrapper, explicit DENY, disabling through
absent `rbac` or `rules`, and deny-all through present empty `rules`.
Denied probes require no backend call. The pinned grpc-js-xds validator rejects
the two canonical disabling overrides; the peer asserts that exact limitation
and validates a copy omitting those two routes, while the official-schema wire
exchange includes all five overrides. The gate
checks inherited and explicit-zero route deadlines, cached RDS projection after
HCM changes, old in-flight deadlines, name/mode replacement, late RDS, NACK
rollback and deletion. Each backend must retain one HTTP/2 session. The client
uses an explicitly configured cluster manager; automatic CDS/EDS child
orchestration remains the next control-plane integration step.
