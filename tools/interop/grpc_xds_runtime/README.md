# Full typed ADS discovery gate

Run `zig build interop-grpc-xds-runtime --summary all`, adding
`-- --output <report.json>` to save hashes and results.

The independent ADS peer uses official Envoy schemas and delivers
LDS/RDS/CDS/EDS into a native application channel with no static child map or
backend endpoints. Two grpc-js backends count ten permitted requests. The gate
checks pending fail-fast discovery through an initial omitted CDS response, cluster admission/drop isolation, EDS name
replacement, empty RDS/EDS response retention, partial EDS sibling retention,
duplicate NACK rollback, old in-flight route completion and
listener removal, with one reused HTTP/2 session per backend. Subscription
updates may coalesce a retained per-type NACK with new resource names.
