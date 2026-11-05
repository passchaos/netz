# CDS policy and CDS/EDS publication

`grpc.xds.cds.decode` owns an Envoy v3 `Cluster`: logical cluster name,
discovery type, EDS service name for EDS clusters, DEFAULT circuit request limit
and endpoint LB policy. EDS clusters use an ADS/self `ConfigSource` and the
service name defaults to the cluster name; an `xdstp:` EDS cluster must specify
its service name. STATIC clusters carry an inline `load_assignment` whose
`cluster_name` must match the cluster; they publish endpoints through the same
priority/locality runtime without an EDS subscription. STRICT_DNS and
LOGICAL_DNS clusters likewise use an inline assignment, publishing host
endpoints that retain priority and locality identity; LOGICAL_DNS retains one
endpoint per locality while STRICT_DNS retains every declared endpoint. An
`envoy.clusters.aggregate` custom cluster (CDS field 38) carries an ordered list
of leaf cluster names; the runtime subscribes to every leaf and publishes an
ordered `priority_experimental` child policy over the live leaf policies. The
aggregate entry itself has no endpoints, EDS subscription or TLS transport.
Other custom cluster extensions remain unsupported. The
first DEFAULT
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

A successful CDS update subscribes to its EDS name when the cluster is EDS and
atomically publishes the policy, circuit identity/limit, endpoints and drops.
STATIC and DNS clusters publish their inline assignment immediately and request
no EDS subscription; switching a selected cluster between EDS and non-EDS
updates the subscription set in the same transaction.
Subscription storage
is prepared first and committed without allocation after channel publication.
The controller owns the accepted CDS configuration and matching EDS image.
Changing policy or limit with the same EDS name reprojects that image without
waiting for another EDS response. Changing EDS name immediately clears old
endpoints and drops, changes the circuit identity and subscribes to the new
name. A matching EDS response then supplies its endpoints. Omitted EDS
assignments preserve the cached image and target; a present empty assignment
clears endpoints. An omitted selected CDS cluster removes
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

`transport_socket` accepts one inline
`envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext`: an optional SNI
name, inline `trusted_ca`, one inline certificate chain/private-key pair, and
`tls_params` minimum/maximum protocol versions using Envoy's `TlsProtocol`
values (`AUTO` defaults to TLS 1.2/1.3; TLS 1.0/1.1 are rejected) and a TLS 1.2
cipher-suite allowlist using the OpenSSL names for the supported ECDHE
GCM/ChaCha suites, and `match_subject_alt_names` exact/prefix/suffix/contains
matchers (case-sensitive or insensitive). SAN matching requires a trust
source and replaces SNI hostname verification with the configured matcher set.
`system_root_certs` selects the platform trust store; without any inline CA,
identity or hash verification also uses the platform store. Hex SHA-256 `verify_certificate_hash` pins and base64 SHA-256
`verify_certificate_spki` pins are checked against the peer chain after normal
chain verification. EDS, STATIC and
DNS endpoints become TLS targets; without
`trusted_ca` the platform roots are used. SDS certificate and validation
references are exposed as `Cluster.tls_sds` when `Limits.allow_sds` is set and
are resolved by the runtime controller; direct CDS consumers that leave the
option unset keep rejecting them. Certificate providers, ECDH curve lists,
regex/custom SAN matchers, file/environment data sources and other transport
sockets are explicitly rejected. See [SDS](grpc_sds.md).
`transport_socket_matches` and `lrs_server` are also rejected. Cluster
`upstream_config` accepts `HttpProtocolOptions.http2_protocol_options` and maps
`hpack_table_size`, `max_concurrent_streams`, `initial_stream_window_size` and
`initial_connection_window_size` onto the cluster's HTTP/2 connection limits;
unspecified fields retain the application's target limits. HTTP/1, HTTP/3 and
automatic/downstream protocol selection are rejected. Cluster
`outlier_detection` is projected into the SharedChannel's
`outlier_detection_experimental` wrapper: interval, base/max ejection time, max
ejection percent, success-rate enforcement/stdev/minimum-hosts/request-volume,
and failure-percentage threshold/enforcement/minimum-hosts/request-volume.
Consecutive-5xx, gateway-failure and local-origin controls, ejection jitter,
active-health-check unejection and monitors have no gRPC counterpart and are
rejected when enabled. The generated policy passes the ordinary ServiceConfig
parser before publication. Aggregate/custom cluster discovery is unsupported.
This slice handles EDS-backed, STATIC, STRICT_DNS and LOGICAL_DNS clusters.
Typed delta CDS/EDS publication is available through the automatic runtime;
delta CDS/EDS TTL expiry is covered. Bootstrap parsing and control-plane
failover are available. LDS/RDS routing, certificate providers and automatic
refresh scheduling, authority-specific control planes and full security
integration remain open.

`zig build interop-grpc-cds --summary all` compares valid fixture policies and
limits with the actual grpc-js-xds CDS parser and uses official Envoy schemas
over ADS. Two independent grpc-js backends count locality and stable ring
routing, same-EDS policy/circuit changes, zero-limit pre-wire rejection, changed
EDS name, invalid CDS/EDS NACKs and CDS deletion with late EDS delivery. The
backends must retain one HTTP/2 session each across updates. Native tests also
cover STATIC and DNS inline-assignment decoding, cluster-name matching, SotW
and delta publication, endpoint reprojection, the absence of an EDS
subscription, inline upstream TLS decoding and a real certificate-verified
STATIC cluster RPC. Evidence is stored in
`docs/evidence/grpc_cds/tls-2026-11-03.json`.
