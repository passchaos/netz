# Automatic source-pinned LRS interoperability

Run `zig build interop-grpc-lrs-automatic --summary all`, optionally adding
`-- --output /tmp/grpc-lrs-automatic.json`. The runner uses the existing pinned
grpc-js, proto-loader, protobufjs and official Envoy schemas in `../grpc_locality`.
It installs those lockfile dependencies with `npm ci` only if absent.

The native executable accepts three ports: control planes A and B and a TCP
relay for C. Node starts those independent services and invokes the executable.
For an existing executable, use:

```sh
python3 tools/interop/grpc_lrs_automatic/run.py /absolute/path/to/native-client --output /tmp/grpc-lrs-automatic.json
```

The client uses `runtime.Backend`, `runtime.Controller`, and managed
`ControlPlane.newSotwClient`/`rebindSotw` discovery. The destination starts with
default disabled LRS stats and the controller has no explicit `Options.lrs`.
An official inline LDS route configuration discovers two CDS/EDS clusters.
Only `eligible` opts into `lrs_server: self`; `ignored` remains routable but must
never appear in load reports, even when the LRS server requests both clusters.
Actual application RPCs carry identifying metadata and official ORCA reports
in trailing metadata. No fixture calls `Stats.record` or manually enables stats.

The provenance case performs these event-gated transitions:

1. Accept LDS, self-CDS and EDS from A, then complete `first` and `ignored-a`
   application calls. Start and hold a second eligible RPC at the Node peer.
2. Rebind the managed discovery client to B and accept B's EDS while retaining
   cached A CDS. Complete `cached`; a barrier waits for A's exact report totals
   of three issued, two successful and one in progress. B must have no LRS stream.
3. NACK unsupported CDS from B. The accepted CDS version, destination revision
   and selected reporting source remain A.
4. Accept byte-identical valid replacement CDS from B. New `new` and `ignored-b`
   application calls execute, with `new` returning UNAVAILABLE. B's first LRS
   request must carry B's captured source metadata. A's held RPC is released
   only after B reports its failure, and A must report that old RPC's completion.

| Report source | Issued | Successful | Failed | CPU count / sum | Memory count / sum | Application count / sum | Named count / sum |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A | 3 | 3 | 0 | 3 / 1.5 | 3 / 0.75 | 3 / 3 | 3 / 6 |
| B | 1 | 0 | 1 | 1 / 0.75 | 1 / 0.5 | 1 / 1.5 | 1 / 4.5 |

Both sources must send exactly one initial LRS node request. Report request
counts may vary with the reporting interval; the summed counter and metric
totals are exact. Official field names, cluster/EDS identities, endpoint
addresses and counters, positive report intervals, zero drops and final
in-progress gauges are checked on every report. The selected named metric
must preserve the official CDS key `named_metrics.load`; the unselected metric
is excluded. Source metadata `x-source: A/B` and distinct native source hashes
prove which captured discovery request/server owns each reporting stream.

The refused-network case keeps C's established ADS TCP stream open, then closes
the relay's listener before delivering valid self-CDS. New automatic LRS TCP
connections to that pinned source receive ConnectionRefused. CDS must still
publish and ACK under a 250-ms deadline, EDS must route an actual successful
application call, and automatically enabled stats must retain that call's
source identity and issued/successful counters. The relay must have accepted
exactly one connection and C must receive no LRS request.

The fixture covers SotW managed discovery. Delta source pinning and failure
cases are covered by the adjacent native automatic-LRS tests. The report
contains ordinary ADS ACK/NACK transcripts, all seven application calls and
metadata/deadlines, ordered barrier/report events, exact source totals, source
identity hashes, byte-identical CDS hashes, executable/source/official-proto
hashes, and explicit result contracts. It rejects source or executable changes
during execution. Barriers wait on events rather than sleep polling. Operations
use absolute deadlines, the held RPC retains its original 15-second deadline,
the native subprocess is bounded at 35 seconds and the outer runner at 45.

Failures retain a machine-readable `AUTOMATIC_LRS_FAILURE` record with each
pending barrier's expected and actual values, current source gauges and summed
counters, initial/report request counts, complete received ADS/LRS messages,
application calls, ordered events and native output. When `--output` is supplied,
the runner writes that failure report with source/executable hashes before
returning a failed exit status. The same strict predicates and deadlines apply.

Check schema construction without a native build:

```sh
node tools/interop/grpc_lrs_automatic/peer.js --schema-check
```
