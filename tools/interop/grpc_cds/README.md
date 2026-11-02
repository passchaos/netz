# CDS to EDS integration gate

Run `zig build interop-grpc-cds --summary all`; add
`-- --output <report.json>` to save the report and source hashes.

The peer uses the pinned official Envoy protobufs, grpc-js-xds CDS parser and
two grpc-js backends. It validates legacy RR/ring policy conversion, ordered
typed fallback to WrrLocality, circuit limits including zero, same-EDS cached
publication, EDS name replacement, CDS/EDS validation NACKs, deletion and late
EDS handling. Wire counts exclude the circuit-rejected call; backend sessions
must be reused across configuration updates. Modern typed ring/least-request
and first-DEFAULT circuit parsing are covered by adjacent native tests and the
local grpc-core reference; this grpc-js-xds version has different typed policy
coverage and uses the last DEFAULT threshold.
