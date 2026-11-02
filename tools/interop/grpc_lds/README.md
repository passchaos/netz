# Listener-driven client routing gate

Run `zig build interop-grpc-lds --summary all`; add
`-- --output <report.json>` to store the report and source hashes.

The official Envoy LDS/HCM/RDS schemas deliver inline and dynamic routing
through ADS. Actual grpc-js-xds validation checks the common fixture contracts;
native tests additionally cover grpc-core's effective terminal ordering when
an ignored optional filter follows the router.

Two grpc-js backends count 31 RPCs, including duplex and slow calls. The gate
checks inherited and explicit-zero route deadlines, cached RDS projection after
HCM changes, old in-flight deadlines, name/mode replacement, late RDS, NACK
rollback and deletion. Each backend must retain one HTTP/2 session. The client
uses an explicitly configured cluster manager; automatic CDS/EDS child
orchestration remains the next control-plane integration step.
