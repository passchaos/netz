# v3 ADS interoperability

Run `zig build interop-grpc-ads --summary all`, optionally with
`-- --output /tmp/grpc-ads.json`. Node.js/npm are required. This runner reuses
`../grpc_locality`'s package-lock-pinned grpc-js-xds dependencies, which include
the official Envoy v3 ADS, discovery and Node schemas. It loads those schemas
with the official proto-loader and serves through grpc-js.

The peer requires exact Node id/cluster/locality/client-feature/Struct metadata,
initial subscriptions, CDS and EDS version/nonce isolation, names merged into
ACK, a NACK for a wrong-type resource with retained previous version and
INVALID_ARGUMENT detail, rejection of an older same-type response, and a second
stream replaying accepted versions with empty nonce/error. The second stream
outlives a 50-ms opening budget and resumes after a local 10-ms receive timeout.
Exactly nine requests, two ADS streams and one HTTP/2 session must be observed.

All subprocesses have bounded waits. The result binds native binary, source
files and official protobuf schemas with SHA-256. Native adjacent tests extend
coverage to allocation failure, request/response codec bounds, held-mutex stream
admission rollback and retrying a failed ACK encoding without losing the applied
version. This gate establishes state-of-the-world ADS transport behavior, while
typed resource decoders, config publication and control-plane failover remain
separate implementation requirements.
