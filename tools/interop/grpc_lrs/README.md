# Load Reporting Service wire compatibility gate

Run `zig build interop-grpc-lrs --summary all`, adding
`-- --output <report.json>` to save hashes and results.

The independent peer loads the pinned official Envoy v3 `lrs.proto` and
`load_report.proto` through grpc-js-xds. Node's official `StreamLoadStats`
request serializer first builds a `LoadStatsRequest` with two cluster reports
named `a` and distinct EDS service names, `eds-a` and `eds-other`. It passes
those serialized bytes as a base64 argument to the native client. The client
uses production `lrs.codec.decodeRequest` and checks both identities, every
metric count and sum, locality, endpoint, counter, dropped category and interval.

The native client separately constructs matching reports and sends them
through the production LRS client and encoder. The official Node request
deserializer must retain the exact official field names and values in that
live request. Both directions check these locality metrics:

| Official field | Field number | `eds-a` count / sum | `eds-other` count / sum |
| --- | --- | --- | --- |
| `cpu_utilization` | 12 | 1 / 0.5 | 5 / 1.25 |
| `mem_utilization` | 13 | 2 / 0.25 | 6 / 1.5 |
| `application_utilization` | 14 | 3 / 1.0 | 7 / 3.5 |
| `load_metric_stats`, metric `load` | 5 | 4 / 2.0 | 8 / 4.5 |
| `load_metric_stats`, metric `other` | 5 | 1 / 3.0 | 9 / 5.5 |

The official metric member names are `num_requests_finished_with_metric` and
`total_metric_value`, plus `metric_name` for named metrics. Different values
for the two EDS identities make accidental aggregation or swapped metrics
observable. The first report preserves the original `127.0.0.1:1001`
endpoint, counters, `throttle` drop and 100-ms interval. The second uses
`127.0.0.2:1002`, distinct counters, a `circuit` drop and a 200-ms interval.

The existing `StreamLoadStats` transcript still requires:

- initial request with the node id and `envoy.lrs.supports_send_all_clusters`
  client feature, and no cluster stats,
- a response carrying cluster names, a 100-ms reporting interval and endpoint
  granularity,
- one request with both cluster/service identities, localities, endpoints,
  successful/error/issued/in-progress counters, drops, metrics and intervals,
- a second response with `send_all_clusters`.

The client must decode both responses and observe a clean OK terminal. Reports
include explicit encoder/decoder, utilization, named-metric and distinct-service
contracts; the decoded official fixture and received native report; the fixture
byte count and SHA-256; source, executable and pinned schema hashes. The runner
rejects source or executable changes during execution. Native operations have
five-second deadlines, the native subprocess has a 30-second timeout and the
outer runner has a 45-second timeout.

The peer's schema serialization can be checked without a native build:

```sh
node tools/interop/grpc_lrs/peer.js --schema-check
```

This gate verifies the production wire encoder and request decoder against
the official schema. Application call-stat aggregation is covered separately.
