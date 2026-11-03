# Delta ADS wire compatibility gate

Run `zig build interop-grpc-delta-ads --summary all`, adding
`-- --output <report.json>` to save hashes and results.

The independent peer loads the pinned official Envoy v3 `ads.proto` and
`discovery.proto` through grpc-js-xds's protobuf definitions. It implements
`DeltaAggregatedResources` directly and asserts the netz request transcript:

- initial `node` and `resource_names_subscribe` with no nonce or versions,
- ACK with the response nonce and no pending diff,
- subscribe/unsubscribe diff after the desired set changes,
- NACK carrying the invalid response nonce and `error_detail`,
- reconnect with `initial_resource_versions` and the complete desired set,
- ACK of a TTL-only heartbeat Resource with no payload.

The response resources use official `Resource` messages with per-resource
versions, `removed_resources`, and a `google.protobuf.Any` payload. This gate
validates wire field numbers and envelope ownership against the official
schema; typed LDS/RDS/CDS/EDS publication remains a separate follow-up.
