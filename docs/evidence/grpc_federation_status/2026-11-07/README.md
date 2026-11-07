# Federated CSDS and partial delta acceptance

Managed discovery exposes one CSDS configuration for its complete desired
authority graph. Each resource retains its own accepted wire/version/time and
failed-attempt context. Partial delta cache changes commit their corresponding
accepted-version map before the response-level NACK, so reconnect describes the
payloads actually retained by that authority.

| Gate | Result | Evidence |
| --- | --- | --- |
| CSDS and delta transaction Debug | 209/209 tests | `transactions.Debug.final.log` |
| Complete xDS module plus affected unified HTTP pool ReleaseSafe | 537/537 tests | `xds-http.ReleaseSafe.log` |
| Independent federated ADS/LRS/CSDS ReleaseSafe | SotW and delta | `federation.ReleaseSafe/report.json` |

Counts are Zig's reported focused/module test counts, including imported
dependencies. The ReleaseSafe count is one combined xDS/HTTP gate. `gates.json`
retains exact commands, results, elapsed time and source manifests. Wire reports
also record executable, dependency and imported official schema hashes.

The native suite covers independent authority versions, NACK metadata with
accepted-image retention or withdrawal, content exclusion, owned response
snapshots, pending old/new RDS versions, retired-watch pruning, source-specific
initial-fetch timers, TTL expiry rollback, history budgets and allocation
failure. Publisher errors cannot accept identical wire at a newer version.
Partial data-error publication preserves valid sibling acceptance time when the
NACK is sent; rejecting the same wire/version in another attempt remains a new
failure.

CDS/EDS/SDS delta regressions seed three valid gRPC route dependencies, commit a
valid replacement and withdraw a failed sibling, then inspect the original
nonce/NACK and actual reconnect `initial_resource_versions`. Version-map OOM
must reject before publication. An injected clock verifies payload acceptance
time follows successful publication while a heartbeat refreshes TTL without
changing that time. SotW failed typed validation overrides deletion retention;
genuine omissions continue to honor the source feature.

The independent two-authority peer retains real ADS, LRS and application
traffic checks. It decodes full/excluded CSDS snapshots after A's NACK and a
final snapshot after handoff/pruning. Assertions compare accepted Any hashes
with the actual resources each server sent, preserve B's cached deletion state
and original accepted version, check A's rejected version/details, and require
old B resources to leave the final inventory.

Current Envoy status schema provenance is under
`src/grpc/xds/csds_schema/provenance.json`: the active gRPC reference pins
data-plane-api commit `6ef568cf4a67362849911d1d2a546fd9f35db2ff`, including
`RECEIVED_ERROR = 5` and `TIMEOUT = 6`. Codec tests use exact current-schema wire
vectors and hostile requests; the existing pinned Node decoder consumes the
compatible ACK/NACK/deletion fields used by the federation scenario.

Earlier failed gates remain available. Initial source parsing errors and
fixture errors were corrected without changing cache/version/nonce/OOM
predicates: exact routes need `/service/method`, and an xdstp EDS cluster needs
an explicit EDS service name before unsupported policy validation is reached.

Reproduce the wire scenario with a fresh output path:

```sh
zig build interop-grpc-federation -Doptimize=ReleaseSafe --summary all -- \
  --output /tmp/netz-csds-federation-fresh/report.json
```

Facade queries and discovery operations require serialized caller access.
This evidence covers the bounded resource graph and two-authority localhost
scenario; the overall protocol-library goal remains active.
