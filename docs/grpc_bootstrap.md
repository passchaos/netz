# xDS bootstrap and control-plane failover

`grpc.xds.bootstrap` parses the gRPC xDS bootstrap JSON into bounded, owned
configuration. `grpc.xds.control_plane.ControlPlane` turns a DNS/IP bootstrap
target and its selected channel credentials into a SharedChannel and delta ADS
client, and can move the same logical discovery session to the next server.

```zig
const configuration = try netz.grpc.xds.bootstrap.parse(allocator, json, .{});
defer configuration.deinit();
const plane = try netz.grpc.xds.control_plane.ControlPlane.init(
    allocator, io, configuration, .{},
);
defer plane.deinit();
try plane.connectWithDeadline(deadline);
const discovery = plane.discovery(); // *delta.Client

_ = try controller.startDeltaWithDeadline(discovery, destination, deadline);
// ... drive next/apply events ...
// On a terminal event:
try plane.failoverWithDeadline(deadline);
```

## Parsed configuration

`Bootstrap.parse` accepts:

| Field | Behavior |
| --- | --- |
| `xds_servers` | Required, non-empty array of server objects |
| `server_uri` | Required DNS/IP `host:port`, `dns:///host:port`, or HTTP/HTTPS alias; DNS defaults to port 443, HTTP/HTTPS aliases to 80/443; IPv6 brackets accepted |
| `channel_creds` | Required array of `{type, config}`; at least one known type (`insecure`, `tls`, `google_default`, `xds`) |
| `tls` config | `ca_certificate_file`, `certificate_file`, `private_key_file`, `refresh_interval`, `root_certificate_provider`, `identity_certificate_provider`; certificate/key must be paired; direct files and provider references are mutually exclusive |
| `certificate_providers` | Optional map of provider name to `{plugin_name, config}`; `file_watcher` supports `certificate_file`, `private_key_file`, `ca_certificate_file`, `refresh_interval`; `static_file` supports the same files but loads once and rejects `refresh_interval` |
| `server_features` | Optional string array; the four grpc-core feature names set booleans, unknown entries are retained but inert |
| `node` | Optional `{id, cluster, locality, metadata}`; `id` is required when present |
| `authorities` | Optional map of authority name to `{xds_servers, client_listener_resource_name_template, fallback_on_reachability_only}` |
| `client_default_listener_resource_name_template` | Optional string |
| `server_listener_resource_name_template` | Optional string |

Authority templates must begin with `xdstp://<authority>/`. Duplicate JSON
fields, malformed JSON, empty server lists, non-object nodes, invalid URIs,
unknown provider references and unknown-only channel credentials fail parsing.
`file_watcher` and `static_file` are the supported certificate-provider
plugins; non-empty `allowed_grpc_services` remains rejected as unsupported
rather than silently ignored.

`node.metadata` is encoded into a bounded `google.protobuf.Struct` image
(`Struct` map entries, `Value` oneofs, nested structs/lists, booleans, numbers,
strings and null). The parser bounds metadata bytes, entries and recursion
depth. `Bootstrap.adsNode()` returns an `ads.codec.Node` whose metadata bytes
can be passed directly to `delta.Client`.

## Control plane

`ControlPlane` selects the first supported `insecure` or `tls` credential in
the server's ordered list. The URI controls target spelling and default port;
credentials control plaintext or TLS. A connection failure does not select a
later credential or downgrade TLS. Only the selected credential's TLS material
is loaded.
TLS uses `ca_certificate_file` as the server trust bundle when present and the
platform roots otherwise. `certificate_file` plus `private_key_file` supply an
optional client identity for mTLS. The files are loaded once at control-plane
creation or failover. `refresh_interval` accepts the gRPC duration form
(`"10s"`, `"1.25s"`, default ten minutes); zero disables scheduled refresh.
`refreshInterval` returns the current server's period and `nextRefreshDeadline`
returns its next boundary. `reloadIfDueWithDeadline` reloads and reconnects only
when that boundary has passed, so discovery can call it between stream
operations. `root_certificate_provider` and `identity_certificate_provider`
reference file-backed providers; their file paths and the shorter of the
referenced refresh intervals are used for the control-plane TLS material.
`static_file` providers contribute a zero interval, so they are loaded once.
Provider rotation still reloads through the same caller-driven reconnect
schedule rather than updating live transports in place.
`runtime.Options.applyServerFeatures(plane.server())` copies the selected
server's `ignore_resource_deletion`, `fail_on_data_errors`,
`trusted_xds_server` and `resource_timer_is_transient_error` booleans before
`Controller.create`. `Controller.applyServerFeatures(plane.server())` also
updates a live controller's options and listener policy, so call it again after
`failoverWithDeadline` selects a server with a different feature set. RDS
snapshots created before the change keep the trust policy they were built with;
later publications use the new one.

`Options.authority` selects an authority's `xds_servers` (falling back to the
top-level list when the authority has none); an unknown authority fails with
`InvalidControlPlaneOptions`. The bootstrap node is used unless `Options.node`
overrides it; a missing node id fails with `InvalidBootstrapNode`.

[Managed federation](grpc_federation.md) owns these authority sessions and
routes dependency watches while retaining one Controller/data-plane publisher.
Its target factory uses the bootstrap's listener templates and a parsed
`xds:` URI through [client target resolution](grpc_client_target.md).

`connectWithDeadline` tries the current server and then the remaining usable
servers. Each attempt gets `Options.server_open_timeout` (default 250 ms) or
the remaining overall deadline, whichever is earlier. A refused or
unresponsive control plane is therefore skipped without consuming the whole
discovery budget.

`failoverWithDeadline` advances to the next usable server, creates a new
SharedChannel, and rebinds the same `delta.Client`. Rebind transfers ownership
of the new sender, disconnects the old stream and retains desired names plus
accepted per-resource versions. The next connect therefore sends
`initial_resource_versions` and the complete desired set to the replacement
server. `reconnectWithDeadline` reconnects the current server after a terminal.
`reloadServerWithDeadline` re-reads the current server's TLS files, creates a
new channel and material, rebinds the client and reconnects. A failed load,
including a CA file that yields no certificates, leaves the old channel and
material untouched. Callers can drive reload from their own refresh schedule.
The runtime controller can keep using the same `*delta.Client` pointer across
failover and reload.

`sender()` creates another sender on the current channel. `moveToNextServer`
switches the channel without connecting the owned delta client, and
`rebindDelta`/`rebindLrs` move external delta or LRS clients to that new
channel. This lets multiple clients share one control-plane channel and follow
the same failover or TLS reload; the LRS reporter keeps using the same client
pointer after rebind. `reconnectLrsWithDeadline` retries the current server with
the per-server opening budget, while `failoverLrsWithDeadline` combines the
switch, rebind and reconnect for an LRS client and skips servers that refuse the new stream, so an
LRS scheduler can survive a terminal without the application driving each
server step.

## Bounds and verification

Limits cover bootstrap bytes, servers, authorities, channel credentials,
server features, text, and metadata bytes/entries/depth. Native tests cover the
complete parsed shape, URI defaults and IPv6, metadata Struct encoding through
`ads.codec.encodeNode`, invalid/unsupported shapes, duplicate fields, bounds,
allocation failure sweeps, refused-server failover, two-server failover with
`initial_resource_versions` replay, a real TLS handshake using a bootstrap CA
file, TLS material reload with version replay and failed-load rollback, the
`refresh_interval` schedule including due/not-due transitions, and unusable
server or node-less configurations. See
`docs/evidence/grpc_bootstrap/2026-11-03.json`.

## Remaining integration

Certificate-provider plugins other than `file_watcher`/`static_file`, a self-driving refresh
task, a background retry schedule and further gRPC resolver target families
remain follow-up work. DNS/IP target spelling is supported. `reloadIfDue`
exposes the bootstrap-derived schedule, while the discovery-owning task calls
it at the reconnect boundary. Managed federation dispatches authority watches
and applies each server's features to its own resource operations.
