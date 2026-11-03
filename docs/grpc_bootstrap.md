# xDS bootstrap and control-plane failover

`grpc.xds.bootstrap` parses the gRPC xDS bootstrap JSON into bounded, owned
configuration. `grpc.xds.control_plane.ControlPlane` turns an insecure
`http://` bootstrap server into a SharedChannel and delta ADS client, and can
move the same logical discovery session to the next server.

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
| `server_uri` | Required `http://` or `https://` authority; default ports 80/443; IPv6 brackets accepted |
| `channel_creds` | Required array of `{type, config}`; at least one known type (`insecure`, `tls`, `google_default`, `xds`) |
| `server_features` | Optional string array; the four grpc-core feature names set booleans, unknown entries are retained but inert |
| `node` | Optional `{id, cluster, locality, metadata}`; `id` is required when present |
| `authorities` | Optional map of authority name to `{xds_servers, client_listener_resource_name_template, fallback_on_reachability_only}` |
| `client_default_listener_resource_name_template` | Optional string |
| `server_listener_resource_name_template` | Optional string |

Authority templates must begin with `xdstp://<authority>/`. Duplicate JSON
fields, malformed JSON, empty server lists, non-object nodes, invalid URIs and
unknown-only channel credentials fail parsing. Non-empty
`certificate_providers` or `allowed_grpc_services` are rejected as unsupported
features rather than silently ignored.

`node.metadata` is encoded into a bounded `google.protobuf.Struct` image
(`Struct` map entries, `Value` oneofs, nested structs/lists, booleans, numbers,
strings and null). The parser bounds metadata bytes, entries and recursion
depth. `Bootstrap.adsNode()` returns an `ads.codec.Node` whose metadata bytes
can be passed directly to `delta.Client`.

## Control plane

`ControlPlane` currently supports insecure `http://` servers. `https://` or
`tls`-only configurations parse but `ControlPlane.init` returns
`NoUsableXdsServer`; certificate-provider and TLS credential support remain
future work. `Options.authority` selects an authority's `xds_servers` (falling
back to the top-level list when the authority has none); an unknown authority
fails with `InvalidControlPlaneOptions`. The bootstrap node is used unless
`Options.node` overrides it; a missing node id fails with
`InvalidBootstrapNode`.

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
The runtime controller can keep using the same `*delta.Client` pointer across
failover.

## Bounds and verification

Limits cover bootstrap bytes, servers, authorities, channel credentials,
server features, text, and metadata bytes/entries/depth. Native tests cover the
complete parsed shape, URI defaults and IPv6, metadata Struct encoding through
`ads.codec.encodeNode`, invalid/unsupported shapes, duplicate fields, bounds,
allocation failure sweeps, refused-server failover, two-server failover with
`initial_resource_versions` replay, and unusable TLS-only or node-less
configurations. See `docs/evidence/grpc_bootstrap/2026-11-03.json`.

## Remaining integration

TLS bootstrap channel credentials, certificate providers, a background retry
schedule and DNS/aggregate control-plane targets remain follow-up work. The
parser retains authority server lists and per-server feature flags, and
`Options.authority` already selects those servers.
