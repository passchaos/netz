# Managed federated xDS validation

The public `runtime.managed.Managed(.sotw/.delta)` facade owns distinct
bootstrap-authority Sessions while feeding one transactional Controller and
data channel. Client targets expand bootstrap listener templates, with
credential order selecting plaintext or TLS for DNS/IP control-plane targets.

| Gate | Result | Evidence |
| --- | --- | --- |
| Focused federation/target/reader Debug | 350/350 tests | `native.Debug.complete.log` |
| CSDS, routed LDS/RDS, registry and managed Debug | 185/185 tests | `publication.Debug.complete.log` |
| Complete xDS module and resumable readers ReleaseSafe | 461/461 tests | `xds.ReleaseSafe.complete.log` |
| Independent final ReleaseSafe wire | SotW and delta | `wire.ReleaseSafe.complete/report.json` |
| C-Core target/template wire oracle | 37/37 vectors | `../../grpc_client_target/2026-11-07/full.Debug.final/report.json` |

The test counts are Zig's reported `test-lib` counts, including imported
dependency tests. `gates.json` records each exact command, terminal exit code,
summary, elapsed time and source manifest. Each wire report separately records
native and Node executable hashes, source hashes, pinned package metadata and
the imported official Envoy protobuf schema closure.

The independent peer uses real ADS, LRS and backend connections. A LDS points
to B RDS/CDS/EDS, while canary traffic uses A CDS/EDS. Source-specific deletion
features must preserve B's exact cached resources and delete only A's resources.
A malformed A CDS response must NACK without changing B or the published
revision. A replacement route waits for A CDS/EDS while calls continue to B;
a held B call then completes after new main traffic reaches A. Delta emits
dependency unsubscriptions; SotW retains its last named request to avoid an
empty wildcard subscription. Automatic self-LRS reports B's seven main
completions and A's two canary plus one new-main completion in both modes.

Native regressions cover membership quota rollback, nested preparation,
inactive-session event cleanup, accepted CDS provenance, source-scoped
SotW/delta updates, heartbeat/expiry rollback and pending-handoff SDS
withdrawal. Retaining a selector cannot restore withdrawn certificates,
clusters or endpoints. Cancellation of a competing ADS read preserves its
receive queue, while explicit RPC cancellation and RPC expiry remain terminal.

Final review also found and corrected three boundaries:

- Candidate and retained serving-inventory backing allocations now count
  against `max_storage_bytes` before publication.
- Shared cluster references across retained projections count once toward
  `max_clusters`; a third unique cluster still rejects without cache, version
  or revision changes.
- CSDS keeps inline route contents in LDS instead of assigning them an
  independent RDS version/status. Existing CSDS cardinality assertions remain.

The expanded ReleaseSafe run also exposed a test borrowing an old LRS
selection across publication. The test now retains that owner explicitly;
source-key, OOM, revision and exact-count assertions are preserved. Earlier
failed runs and their source manifests remain in this directory. Expected
transport-close/cancel diagnostics can appear in successful LRS runs; the
terminal test summary and exit code identify the gate outcome.

The complete xDS ReleaseSafe command is:

```sh
zig build test-lib -Doptimize=ReleaseSafe \
  -Dtest-filter=grpc.xds \
  '-Dtest-filter=stream interruption returns' \
  '-Dtest-filter=resumable read cancellation' --summary all
```

Reproduce the final wire gate with a fresh output directory:

```sh
zig build interop-grpc-federation -Doptimize=ReleaseSafe --summary all -- \
  --output /tmp/netz-federation-fresh/report.json
```

The facade requires serialized caller operations and caller-driven
reconnection/expiry. The wire evidence is a bounded two-authority localhost
scenario. Broader protocol feature work and long-duration fleet operation
remain tracked by the library's parity and interoperability documents.
