# CDS policy and CDS/EDS publication

`grpc.xds.cds.decode` owns an Envoy v3 EDS-backed `Cluster`: logical cluster
name, EDS service name, DEFAULT circuit request limit and endpoint LB policy.
The EDS name defaults to the cluster name; an `xdstp:` cluster must specify its
service name. EDS ConfigSource must select ADS or self. The first DEFAULT
circuit threshold supplies `max_requests`, defaulting to 1024 when omitted;
HIGH thresholds do not supply the application limit. Zero rejects new RPCs.

Legacy ROUND_ROBIN generates locality weighting with a round-robin endpoint
child. Legacy RING_HASH generates a direct policy across localities within each
priority. Ordered typed policies support round-robin, ring-hash, pick-first,
least-request and WrrLocality. Unknown extension types allow ordered fallback;
a recognized invalid configuration fails the resource. WrrLocality wraps its
endpoint child, with a recursion bound of 16; repeated locality wrapping is
currently unsupported. Modern ring hash accepts DEFAULT_HASH or XX_HASH;
legacy ring hash accepts XX_HASH. Both validate `1 <= min <= max <= 8388608`.
Generated policies pass the ordinary ServiceConfig parser before acceptance.
The current ring runtime still caps allocation at 4096 entries.

The serialized application controller connects CDS and EDS updates to one
SharedChannel:

```zig
var controller = try netz.grpc.xds.cds.Controller.init(allocator, .{
    .cluster_name = "payments",
    .target = .{ .authority = "payments.example" },
});
defer controller.deinit();
try controller.subscribe(&discovery);
try discovery.connectWithTimeout(.fromSeconds(5));
var event = try discovery.nextWithDeadline(deadline);
defer event.deinit();
if (event == .update) {
    _ = controller.applyWithDeadline(
        &discovery, event.update, application_channel, deadline,
    ) catch |err| {
        // Check acceptedVersion before NACK: publication may have succeeded
        // while ACK encoding or output failed. Resume flush/reconnect then.
        return err;
    };
}
```

The application owns receive/reconnect scheduling and NACKs rejected resources
through ADS. Controller operations and ADS decisions require one serialized
caller. Every CDS/EDS resource in a response is decoded and names must be
unique before publication. Invalid input, stale tokens, expired admission and
allocation/publication failure retain the previous topology, subscription,
cached resource and accepted version.

A successful CDS update subscribes to its EDS name and atomically publishes
the policy, circuit identity/limit, endpoints and drops. Subscription storage
is prepared first and committed without allocation after channel publication.
The controller owns the accepted CDS configuration and matching EDS image.
Changing policy or limit with the same EDS name reprojects that image without
waiting for another EDS response. Changing EDS name immediately clears old
endpoints and drops, changes the circuit identity and subscribes to the new
name. A matching EDS response then supplies its endpoints. An omitted matching
assignment publishes an empty target. An omitted selected CDS cluster removes
the target, drops and circuit policy, discards the cache and keeps the last
named EDS subscription to avoid accidentally requesting a wildcard. Late EDS
responses are validated and ACKed but cannot recreate the deleted cluster.

Each priority retains priority failover. Locality wrappers retain distinct
priority/locality paths and separate endpoint weights. Direct policies retain
the same stable priority/locality endpoint identity while their leaf matches
all locality suffixes under a priority. They use locality weight times raw
endpoint weight for ring selection, matching grpc-core's unnormalized weight conversion. A product
that exceeds uint32 fails projection. Caller-supplied target authority and TLS
connection options retain the EDS adapter's existing lifetime contracts; CDS
provides policy and circuit fields. Snapshot references own generated strings
and connectors, so the controller can be destroyed after publication while
the channel and active transports keep their own retained storage.

After channel publication the controller accepts the ADS version before ACK
encoding/output. A failed ACK leaves the applied state authoritative; flush or
reconnect replays the accepted version and desired names. Callers must avoid
NACKing a version that has already committed. Pre-publication validation and
publication errors leave the response undecided and available for NACK.

CDS transport_socket, transport_socket_matches, outlier_detection, lrs_server
and upstream_config are explicitly rejected. LOGICAL_DNS and aggregate/custom
cluster discovery are also unsupported. This slice handles an explicitly
selected EDS-backed cluster; LDS/RDS routing, bootstrap, control-plane failover,
resource expiry, Delta xDS, LRS and full security integration remain open.

`zig build interop-grpc-cds --summary all` compares valid fixture policies and
limits with the actual grpc-js-xds CDS parser and uses official Envoy schemas
over ADS. Two independent grpc-js backends count locality and stable ring
routing, same-EDS policy/circuit changes, zero-limit pre-wire rejection, changed
EDS name, invalid CDS/EDS NACKs and CDS deletion with late EDS delivery. The
backends must retain one HTTP/2 session each across updates. Evidence is stored
in `docs/evidence/grpc_cds/2026-11-03.json`.
