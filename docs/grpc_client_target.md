# Bootstrap-derived xDS client targets

`grpc.xds.client_target.resolve` constructs a listener resource name and data
authority from an `xds:` target and a parsed bootstrap. The result owns its
strings independently of the caller's URI and bootstrap; release it with
`Resolved.deinit`. `resolveWithOptions` additionally accepts a raw default
authority override. Limits bound input and expanded listener names to 4096
bytes by default.

An unqualified target uses `client_default_listener_resource_name_template`,
falling back to `%s` when absent or empty. A qualified target first looks up
the bootstrap authority, then uses its listener template or the default
`xdstp://<authority>/envoy.config.listener.v3.Listener/%s`.
Every `%s` is substituted; constant templates are supported.

URI authority and path percent escapes decode once. The service name is the
decoded path with one leading slash removed. An empty path or trailing slash
fails resolution. Valid query/fragment components do not enter the listener
name or data authority. An xdstp template escapes its substituted path using
RFC 3986 path characters, preserving `/`, `:` and `@`. Non-xdstp templates
receive the decoded service name directly.

The data authority comes from the entire service name, escaped as a URI
authority. It is separate from the discovery server/authority. The result also
exposes the decoded authority of a generated xdstp listener, so a custom
top-level template can route its initial watch to the correct authority.
HTTP request writers separately validate authority syntax. An opaque service
identifier that would produce userinfo in this default authority can use a
valid `default_authority` override while retaining its listener resource name.

| Target and bootstrap | Listener name | Data authority |
| --- | --- | --- |
| `xds:///book/catalog`, defaults | `book/catalog` | `book%2Fcatalog` |
| `xds://tenant/api:443`, authority `{}` | `xdstp://tenant/envoy.config.listener.v3.Listener/api:443` | `api:443` |
| `xds:///api%20name?x=y#f`, top-level xdstp template for tenant | `xdstp://tenant/envoy.config.listener.v3.Listener/api%20name` | `api%20name` |

These rules follow grpc-core's URI resolver. The installed grpc-js resolver
keeps raw path escapes and query/fragment text, and escapes `:`/`@` differently
for xdstp templates. The independent fixture therefore uses a pinned C-Core
client's real LDS subscriptions and backend `:authority` headers.

The source references are `src/core/resolver/xds/xds_resolver.cc`,
`src/core/resolver/resolver_factory.h`, and `src/core/util/uri.cc` under the
local grpc checkout. Native vectors cover defaults, repeated/constant/empty
templates, escaped names, authority lookup, path rejection, bounded expansion
and ownership under allocation failure. The process fixture lives under
`tools/interop/grpc_client_target/`.
