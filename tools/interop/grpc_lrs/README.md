# Load Reporting Service wire compatibility gate

Run `zig build interop-grpc-lrs --summary all`, adding
`-- --output <report.json>` to save hashes and results.

The independent peer loads the pinned official Envoy v3 `lrs.proto` and
`load_report.proto` through grpc-js-xds. It implements `StreamLoadStats` and
checks the netz request transcript:

- initial request with the node id and `envoy.lrs.supports_send_all_clusters`
  client feature, and no cluster stats,
- a response carrying cluster names, a 100-ms reporting interval and endpoint
  granularity,
- one report with cluster/service name, locality, successful/error/issued
  counters, total dropped requests, a dropped category and the report interval,
- a second response with `send_all_clusters`.

The client must decode both responses and observe a clean terminal. This gate
validates the LRS wire field numbers against the official schema; call-stat
aggregation inside the application remains separate.
