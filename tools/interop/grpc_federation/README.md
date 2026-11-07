# Production Managed federation wire gate

This fixture runs `runtime.managed.Managed(mode)` against two distinct localhost
ADS and LRS peers using official Envoy protobuf schemas. It reuses the existing,
pinned `grpc_locality/node_modules` dependencies. JavaScript serves independent
protobuf resources and captures real raw HTTP/2 application deliveries. Native
resource names drive production subscriptions; the application supplies no
discovery router, manual watch changes, resolver switching, or synthetic stats.

Build `client.zig` centrally using the repository's `netz` module. The fixture
does not install dependencies or build executables. Run a prebuilt client:

```sh
python3 tools/interop/grpc_federation/run.py \
  --native /path/to/prebuilt/grpc-federation \
  --output /tmp/netz-federation-fresh/report.json
```

The default runs both SotW and delta through the same Managed facade; use
`--mode sotw` or `--mode delta` for focused checks. Each mode uses fresh peers,
a fresh native process and a bootstrap with ordinary bare `host:port` targets.
Every run requires a fresh sibling case directory to preserve evidence.

The scenario starts with A LDS referencing B RDS. The remote route sends main
traffic to B CDS/EDS and canary traffic to A CDS/EDS. B's source advertises
`ignore_resource_deletion`; A's source does not. An omission/removal of B CDS
must retain B's exact cluster and endpoint snapshot. An A omission/removal must
delete A's cached cluster while preserving B. A restoration and malformed A
CDS response then prove successful recovery and a source-specific NACK that
preserves the other authority and publication revision.

B RDS next moves main traffic to a pending A cluster. Real RPCs must continue
reaching B until A CDS and EDS are complete. A B RPC remains held through the
replacement, then finishes at B after a new RPC reaches A. Production
synchronization prunes the global desired B dependency watches after that held
call completes. Delta explicitly unsubscribes on the wire. SotW retains the
last per-type request instead of emitting an empty wildcard subscription.
Automatic self-LRS records actual requests at their owning source: B reports
seven main completions, A reports two canary completions and one new main
completion. No application invokes `Stats.record` or supplies an LRS transport.

The strict peer validates authority-specific watches, emitted response
ACK/NACKs, accepted versions, data-plane source/order/`:authority`, pending
replacement behavior, held-call completion ordering, final dependency pruning,
and automatic LRS identities/counts. Native assertions additionally inspect
cache identity and source features. Dedicated barrier RPCs only coordinate
server response timing; they do not control discovery subscriptions.

Native execution has a 45-second watchdog, each barrier has a 4.5-second peer
deadline and a 5-second native deadline, and the outer peer deadline is 55
seconds. Reports retain bootstrap JSON, full ADS/LRS/application transcripts,
native stdout/stderr, pending barrier diagnostics and failures. Source,
executable, dependency metadata and imported schema closure hashes identify
the implementation and independent wire evidence. Run after native source
integration stabilizes; changing source files invalidates the evidence.
