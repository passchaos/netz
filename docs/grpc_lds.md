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

`envoy.filters.http.rbac.v3.RBAC` is decoded and enforced. The decoder consumes
the filter config, unwraps its nested `rules` policy, and uses Envoy's v3 field
numbers and enum values (`ALLOW = 0`, `DENY = 1`; principal `header = 6`,
`not_id = 8`, `url_path = 9`; permission `header = 4`, `not_rule = 8`,
`url_path = 10`; header `safe_regex_match = 11`, `contains_match = 12`,
`string_match = 13`; regex `regex = 2`). `shadow_rules` are audit-only and are
consumed without enforcement. The supported grpc-core request-side subset
covers `any`, header, URL-path and `and`/`or`/`not` principals and permissions
with ALLOW and DENY policies; one RBAC filter per HCM is accepted. Authenticated,
source/direct/remote IP, metadata and requested-server-name principals or
permissions, destination IP/port and metadata permissions, the `LOG` action and
the action-based matcher filter forms, and CEL `condition`/`checked_condition`
fields are rejected at decode so an unsupported policy never silently allows
traffic. Evaluation runs before route selection: a denied unary call returns
PERMISSION_DENIED without touching a backend, and a denied streaming open
returns `error.PermissionDenied`. Route/vhost `typed_per_filter_config`
overrides remain unsupported with the existing RDS rejection.

The interop gate now carries RBAC through the official Envoy schema and
grpc-js-xds's own Listener validation and policy parser. The inline listener
DENIES requests carrying `x-deny`: a unary call returns trailers-only
PERMISSION_DENIED and a duplex open fails with `error.PermissionDenied`, while
the backend RPC counters stay unchanged, proving rejection happens before any
connection or request reaches a cluster. The same `x-deny` header is routed
normally after a later inline listener without RBAC replaces the listener,
so the probe also proves the policy is scoped to its listener rather than to
the channel. grpc-js-xds registers only a server-side RBAC constructor, so the
fixture marks the filter `is_optional` to pass its client-side Listener
validator; netz enforces supported optional filters instead of skipping them.

`envoy.filters.http.fault.v3.HTTPFault` is decoded and enforced on the client
path. The supported subset covers fixed `grpc_status` and `http_status` aborts,
`header_abort`, fixed `fixed_delay` and `header_delay` delays,
`FractionalPercent`, and `max_active_faults`. A percentage is required for both
abort and delay, matching grpc-js-xds's config validation, and a numerator above
its denominator is capped at 100%. HTTP abort statuses use the same fallback
mapping as response trailers; HTTP 200 and gRPC OK never abort. Header-driven
aborts read `x-envoy-fault-abort-grpc-request`,
`x-envoy-fault-abort-request`, and
`x-envoy-fault-abort-request-percentage`; header delays read
`x-envoy-fault-delay-request` (milliseconds) and
`x-envoy-fault-delay-request-percentage`. A fixed delay above the 24-hour
decode bound is rejected, and header delays are clamped to that bound. Abort
returns the configured status with message `Fault injected`; a delay sleeps
only up to the attempt or open deadline and then returns `error.Timeout`
instead of extending past it. Fault injection runs per unary attempt (including
retries and hedging) and once before a streaming open; an aborted stream opens
with an immediately readable terminal event and no backend connection. Listener
RBAC is evaluated before fault injection, and a fault filter placed before RBAC
is rejected rather than silently reordering the chain. `upstream_cluster`
restricts injection to requests routed to that xDS cluster; a request routed to
another cluster, or one without a selected xDS cluster, is not faulted. Every
configured fault `headers` matcher must match before injection; the shared
HeaderMatcher grammar covers presence, exact/prefix/suffix/contains, range,
inverted, regex, and string matchers. `downstream_nodes` and
`response_rate_limit` change which requests or bytes are affected and remain
rejected as unsupported.

Route and virtual-host `typed_per_filter_config` overrides are decoded for both
supported filters. An entry whose key matches the HCM filter instance name
replaces that filter for the selected route, with route scope taking precedence
over virtual-host scope. A direct `RBACPerRoute` (or bare `RBAC`) value replaces
the listener policy; an `RBACPerRoute` without a policy, or a `FilterConfig`
marked `disabled`, disables RBAC for that route so the request is admitted.
Fault overrides work the same way: a direct `HTTPFault` replaces the listener
policy and a disabled entry removes it. Entries for other filter names are
ignored, matching Envoy's per-filter keying. A malformed supported override
fails listener publication instead of silently falling back to the listener
policy.

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
inline NACKs, RBAC denial/scope, fault abort/delay/percentage scope, a route
fault override that replaces the listener policy, and listener deletion. A held
old 300 ms RPC completes after a new 20 ms HCM default starts rejecting slow new
calls. The peer counts all 31 RPCs plus one allowed RBAC-scope probe, two allowed
fault probes and no backend call for the overridden route, excludes denied and
aborted probes from backend counters, and requires one HTTP/2 session per
application backend. Native tests cover codec/resource bounds, inline
owned-resource transfer/allocation failure, effective terminal handling,
subscription/cache/version rollback, stale or expired decisions, per-filter
override decoding and scope, and unary/streaming fault aborts before any
connection. Evidence is in
`docs/evidence/grpc_lds/2026-11-03.json`, the RBAC interop report
`docs/evidence/grpc_lds/2026-11-06-rbac-interop.json`, and the fault interop
report `docs/evidence/grpc_lds/2026-11-06-fault-interop.json`.

[Automatic typed discovery](grpc_xds_runtime.md) now derives cluster/service
subscriptions and publishes CDS/EDS children from these listener/RDS snapshots.
Typed delta listener/RDS publication and TTL expiry are available through the
same runtime. Bootstrap parsing and control-plane failover are
available; certificate providers and automatic refresh scheduling, authority-specific control planes, controller-owned LRS scheduling,
non-router HTTP filters, server listener/filter-chain interpretation and full
security/rewriting configuration remain open.
