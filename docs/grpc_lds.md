# Client LDS/HCM and listener-driven RDS

`grpc.xds.lds` owns Envoy v3 client API Listener resources and their
HttpConnectionManager configuration. The serialized controller subscribes to
one listener, publishes inline routes or selects the named dynamic RDS
resource, and installs the resulting immutable RPC selector on SharedChannel.

```zig
var controller = try netz.grpc.xds.lds.Controller.init(allocator, .{
    .listener_name = "frontend",
    .authority = "payments.example",
});
defer controller.deinit();
try controller.subscribe(&discovery);
try discovery.connectWithTimeout(.fromSeconds(5));
var event = try discovery.nextWithDeadline(deadline);
defer event.deinit();
if (event == .update) {
    _ = try controller.applyWithDeadline(
        &discovery, event.update, application_channel, deadline,
    );
}
```

The application channel supplies its cluster-manager children and endpoints,
using the RDS cluster keys described in [RDS integration](grpc_rds.md). LDS
control changes and ADS application decisions require one serialized caller.
SharedChannel still owns concurrent application HTTP/2 traffic in the
background. Applications provide reconnect scheduling and NACK handling for
rejected updates. They check acceptedVersion before NACKing output failures,
because successful selector publication commits the resource version before
ACK encoding or output.

The decoder requires Listener.api_listener with a v3 HCM Any. Address presence
alongside API Listener follows grpc-core's client interpretation; address-only
server listeners are currently unsupported. It validates filter names and
typed configs, allows unsupported optional filters, rejects unsupported
mandatory filters and requires exactly one effective router terminal. Router
disable and repeated terminals are invalid. Optional unsupported entries are
removed before terminal validation, so an ignored optional entry after the
router does not change effective order. Router payload framing, BoolValue and
string fields are checked. Filter-specific deployment options beyond client
routing are not claimed as implemented.

HCM selects inline route_config or RDS through ADS/SELF ConfigSource. AUTO API
version follows the ADS session's v3 type URL; explicit V2 and unsupported
versions fail validation. The same source decoder is used for EDS-backed CDS.
Nonzero xff_num_trusted_hops and original_ip_detection_extensions are rejected
as in grpc-core's client HCM validation. Scoped routes and extension config
discovery remain unsupported. Listener/resource text, filter count, decoded
storage and nested RDS limits bound construction.

Inline RDS is decoded once during LDS validation. Its owned parsed resource is
transferred into the route snapshot at publication. Dynamic RDS snapshots are
cached as immutable parsed data. HCM common_http_protocol_options.
max_stream_duration supplies the route default; route-specific max duration
and grpc_timeout_header_max retain RDS precedence, including a zero route cap
disabling the HCM default while preserving the caller's deadline.

With the same dynamic RDS name, an LDS update reuses the cached parsed route
snapshot and publishes a new immutable HCM timeout projection. A projection
retains its source directly, so repeated updates do not form parent chains.
It copies only immutable views for resolution, leaving the source reference
counter untouched. Existing RPCs keep their selected cluster/hash/deadline;
new RPCs use the new default duration. Shared service-config storage and
backend transports remain reused.

Changing inline/dynamic mode or the dynamic RDS name immediately removes old
route admission. A new dynamic name gets a rejecting snapshot until matching
RDS arrives, with subscription allocation prepared before publication and
desired names committed without allocation afterwards. SotW omission of the
listener removes its cache and installs a rejecting selector. Omission of the
requested RDS assignment preserves its cached routes, while a present empty
route resource publishes empty routes. Late RDS data in
inline or deleted-listener mode is validated and ACKed without publishing or
restoring earlier routing. The last named RDS subscription remains registered
to avoid an empty-name wildcard subscription.

All LDS/RDS response resources validate and have unique names before selector
publication. Invalid resources, required cluster topology, stale response
tokens, expired deadlines, subscription preparation or transaction allocation
failure preserve the prior listener, cached route data, names, channel revision
and accepted version. Once publication succeeds, the cache/version is retained
even if ACK output fails. Controller destruction releases its own references;
published projections keep route storage alive independently.

`zig build interop-grpc-lds --summary all` uses the official Listener/HCM/RDS
and ADS schemas plus grpc-js-xds Listener validation, with two grpc-js
application backends. It checks inline and dynamic routing, stream dispatch,
HCM timeout inheritance, explicit route zero override, same-name cached
projection, new-name admission clearing, late RDS handling, invalid filter/
inline NACKs and listener deletion. A held old 300 ms RPC completes after a new
20 ms HCM default starts rejecting slow new calls. The peer counts all 31 RPCs
and requires one HTTP/2 session per application backend. Native tests cover
codec/resource bounds, inline owned-resource transfer/allocation failure,
effective terminal handling, subscription/cache/version rollback and stale or
expired decisions. Evidence is in
`docs/evidence/grpc_lds/2026-11-03.json`.

[Automatic typed discovery](grpc_xds_runtime.md) now derives cluster/service
subscriptions and publishes CDS/EDS children from these listener/RDS snapshots.
Bootstrap,
control-plane failover/retry, resource expiry, Delta xDS, LRS, non-router HTTP
filters, server listener/filter-chain interpretation and full security/rewriting
configuration remain open.
