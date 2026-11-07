# CDS-controlled LRS registrations

The xDS runtime Controller automatically binds managed CDS `lrs_server: self`
to the source that delivered that resource. `Options.lrs` remains an explicit
transport override. Accepted CDS controls which cluster and EDS service
identities collect counters in that channel; the LRS server's requested cluster
filter selects the wire report. See [automatic source binding](grpc_lrs_automatic.md).

The target stages an immutable selection of reporting identities and ORCA
metric propagation fields. It copies all strings before channel publication
and publishes the selection with the target in the same transaction. The
selection's arena contributes to the Controller resource budget. NACKs and
allocation failures preserve the previous published registration set.

| CDS change | New calls | Previously captured calls |
| --- | --- | --- |
| `lrs_server: self` enabled | Capture that cluster and EDS identity | Keep their captured identity and metrics |
| Reporting disabled or CDS removed | Collect no new counters | Finish under their original registration |
| EDS service or metric selection changed | Use the new identity and fields | Keep the old identity and fields |
| NACK or failed publication | Use the previous accepted selection | Keep their captured registration |

Unary and streaming calls pin their registration before sending HEADERS. They
increment issued and in-progress counters only after successful opening. An
opening failure releases its unstarted pin, so an interval snapshot cannot
publish a phantom issued request or hide a later successful request. Completion
uses the captured counter and metric propagation rather than re-reading CDS.

Counter storage is keyed by discovery source and the `(cluster name, EDS
service name)` pair and remains stable while a call holds a registration. Retired identities stay
reportable through their final delta and are reclaimed after their pins and
unreported counters drain. LRS request decoding accepts the same cluster name
with different EDS service names and rejects duplicate pairs. This matches
grpc-core's LRS load-report map, which also keys statistics by that pair.
The request decoder retains CPU, memory, application and named metrics,
enforces the metric count bound and releases partially parsed children on
truncated input or allocation failure.

CDS metric selectors use the grpc-core LRS naming convention: ORCA's raw
`load` named metric reports as `named_metrics.load`, for both an individual
selector and `named_metrics.*`. Calls retain that naming mode with their
admitted metric selection. Manual propagation and direct codec reports keep
the names supplied by the caller.

Delta CDS equality includes both `lrs_self` and metric propagation, so a change
that affects only reporting still publishes. The encoded reports continue to
intersect collected counters with the LRS server's requested cluster names,
including `send_all_clusters`. Standalone channels with no CDS selection keep
their existing manual collection behavior.

Warm counter and endpoint lookups allocate only on a miss. Borrowed tuple
hashing matches the stored length-prefixed key without concatenating strings
on each call. The immutable registration index uses binary search. Regression
tests exercise warmed identities, endpoints, categories and metrics while the
counter allocator rejects all further allocations.

Tests cover SotW and delta report contents, requested/all-cluster selection,
enable/disable/deletion, EDS replacement, propagation-only changes, retained
unary and streaming completion, copied inputs and publication rollback.
The local grpc-core references are
`src/core/xds/grpc/xds_cluster_parser.cc`,
`src/core/load_balancing/xds/xds_cluster_impl.cc`, and
`src/core/xds/xds_client/lrs_client.{h,cc}` under `/home/passchaos/Work/grpc`.
