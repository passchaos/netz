# RDS resources and per-RPC configuration

`grpc.xds.rds` owns and decodes Envoy v3 `RouteConfiguration`, projects the
selected authority's virtual host into an immutable selector and publishes it
through `SharedChannel.Update.call_selector`. A SharedChannel can also retain
an initial selector through `SharedChannelOptions.call_selector`.

```zig
const routes = try netz.grpc.xds.rds.Snapshot.create(
    allocator, route_config_proto, .{},
    .{ .authority = "payments.example" },
);
defer routes.release();
var application = try netz.grpc.SharedChannel.init(allocator, io, target, .{
    .service_config_json = cluster_manager_config,
    .call_selector = routes.descriptor(),
});
defer application.deinit();
var sender = application.sender();
defer sender.deinit();
var reply = try sender.unary(.{
    .path = "/payments.Service/Get", .message = request,
    .timeout = .{ .value = 3, .unit = .second },
});
defer reply.deinit();
```

RDS-selected cluster manager keys use `cluster:` followed by the protobuf
cluster name. The manager's child names and endpoint hierarchy must contain
these keys. A selector's required clusters are checked against the same
prepared LB topology before publication, so a missing/misconfigured child
cannot cause traffic to enter an unrelated endpoint policy. Applications can
replace target, service config and selector in one update. The ADS adapter
publishes against the application's existing cluster-manager topology; full
CDS child orchestration remains separate work.

Virtual-host selection uses case-insensitive exact, suffix, prefix and universe
domain precedence. Routes are evaluated in received order using full safe
regex, literal exact/prefix or path-separated-prefix matching, all header
predicates and optional runtime fraction. `path_separated_prefix` compares the
path with query and fragment removed, matching either the prefix itself or the
prefix followed by `/`; `/demo.Service` therefore matches
`/demo.Service/Get` but not `/demo.ServiceX/Get`. Binary metadata is absent from
the routing view and repeated ASCII header values are joined with commas.
Missing value predicates fail before inversion by default. Envoy's explicit
`treat_missing_header_as_empty` instead evaluates absence as a present empty
value for string, range and presence conditions before applying inversion;
RBAC and fault filters share that matcher. Regex execution budgets and header
count/text limits apply to both forms. Non-gRPC
exact/prefix/path-separated-prefix paths and query/CONNECT routes are skipped.
Unsupported path-match policies and metadata/TLS matchers are rejected.
Matching inappropriate/non-forwarding actions return a local unary
UNAVAILABLE without transport or a streaming `InvalidRouteAction` error;
missing routes similarly return local UNAVAILABLE or `NoMatchingRoute`.
These are configuration errors and are separate from EDS/circuit drops.

Forwarding supports one cluster or relative weighted clusters. Zero weights
are omitted, positive weights are summed with checked uint32 bounds and the
deprecated total_weight field does not replace that sum. Cluster choice is
made once per RPC and stays stable across retries. Header hashes use XXH64 of
the joined visible value; `io.grpc.channel_id` supplies a stable channel hash.
Multiple successful hash rules rotate the old hash left by one and XOR the new
hash, with terminal rules stopping after a hash exists. Without a successful
rule a random request hash is generated. Unsupported cookie/connection/query
hash sources are ignored as in grpc-core. A header hash policy's optional
`regex_rewrite` applies the same capture-aware replacement to the joined header
value before XXH64; a non-matching rewrite keeps the original value. Route path
`regex_rewrite` is implemented with the same substitution engine. Cluster/hash
attributes remain internal request options and never become application wire
metadata.

`regex_rewrite` (RouteAction field 32) decodes a `RegexMatchAndSubstitute`
pattern and substitution, compiles the pattern with the bounded xDS safe-regex
parser, and applies leftmost-first global replacement with RE2 `\0`..`\9`
capture references and `\\` escaping. Greedy and lazy quantifiers retain their
priority semantics. Replacement runs on an explicit backtracking stack with
hard step, choice and capture-trail budgets; a pathological rewrite fails the
request locally instead of running unboundedly. The selector precomputes the
exact rewritten length so the existing request-input copy still uses one
allocation and preserves the header-byte limit.

`prefix_rewrite`, literal `path_rewrite`, and
`host_rewrite_literal`/`host_rewrite_header`/literal `host_rewrite` are applied
when the selected request inputs are copied. A prefix rewrite replaces the
matched route prefix; for a non-prefix path match it replaces the complete
path. A header host rewrite uses the first visible value, including the
`:authority`, `:path`, `:method` and `:scheme` pseudo-headers. `host_rewrite_path_regex`
evaluates the request path with query and fragment removed and uses the
capture-aware replacement result as `:authority`. `auto_host_rewrite`
is resolved after endpoint selection: the worker replaces `:authority` with the
selected endpoint's configured authority (host authority for host endpoints,
explicit endpoint authority for IP endpoints). Like grpc-core, automatic host
rewriting is honored only when the control plane is configured with
`trusted_xds_server`; an untrusted server's `auto_host_rewrite` is ignored
rather than allowed to redirect the request authority. Rewritten paths and authorities
are bounded by the selector's `max_header_bytes` before any copy. The rewrite
descriptor is internal: it is consumed by unary, streaming and retry input
ownership and never becomes application metadata. `path_rewrite`/`host_rewrite`
values containing format specifiers and unsupported rewrite variants fail
validation instead of being ignored.

`path_match_policy` and `path_rewrite_policy` (`TypedExtensionConfig`) support
the Envoy URI-template extensions. The match policy compiles a bounded template
(`*`, `**`, `{name}`, `{name=*}`, `{name=**}`, `{name=videos/*}` and embedded
segment variables such as `{file}.vtt`), matches the path with query and
fragment removed, and captures named values. The rewrite policy substitutes
those values into the rewritten path; only names declared by the match template
may appear in the rewrite. Unsupported extension type URLs fail validation.

Route-level `request_headers_to_add` and `request_headers_to_remove` are
applied to non-binary application metadata when request inputs are copied.
Additions support append, add-if-absent, overwrite and overwrite-if-exists;
removals run first and match header names case-insensitively. Literal values
only: `%` format specifiers, reserved gRPC/HTTP pseudo-headers, `content-type`,
`te`, `grpc-*` and `-bin` names fail validation. Header mutations are internal
request state and never survive as xDS attributes on the wire.

Route-level `response_headers_to_add` and `response_headers_to_remove` follow
the same literal-value and action rules. They are copied into owned RPC state
so they remain valid after the selector generation is released, then applied
to received response metadata before gRPC status parsing. Unary responses
rewrite the owned HTTP/2 head; streaming and duplex responses rewrite the head
in `ClientDuplex.beginResponse`. The original header block is freed only after
the replacement block is fully allocated, so allocation failure leaves the
original response intact for normal cleanup.

Route timeout prefers grpc_timeout_header_max to max_stream_duration; zero
disables the route/HCM cap, preserving the caller's deadline. An absent route
cap can use Options.default_max_stream_duration. The selected cap and service
config/caller timeout are applied to the original RPC entry timestamp, so
selection time is included. The matching engine checks the original admission
deadline and cancellation during evaluation, including long regex execution.
Expired/canceled/closed admission retains its existing priority over local
no-route status and allocation. Request path/header bytes and resource text,
host/domain/route/cluster/hash counts, cumulative regex instructions and arena
storage are bounded. Sorted name/key validation avoids quadratic duplicate
searches in large resource sets.

Route retry policy overrides virtual-host policy when present, including an
explicit empty retry_on disabling inherited retry. Supported retry_on codes
are cancelled, deadline-exceeded, internal, resource-exhausted and unavailable;
unknown codes do not enable retries. Default num_retries is one, with the
ordinary maximum clamped to five total attempts. Backoff defaults to 25 ms/
250 ms with multiplier two; an explicit base interval requires positive time
and max defaults to ten times base. The retained service-config retry throttle
is attached to the selected policy and survives selector-only updates.
Explicit unary retry/hedging APIs retain their caller override behavior.

Selectors are retained in immutable config generations. Selector-only updates
share parsed service-config storage directly, rather than retaining prior
generation chains. A reader retains one epoch through unary completion or
stream admission; queued/active transport inputs own copied cluster strings.
Existing RPCs retain their route decision when a new selector is published.
LB/health/ORCA state can recognize unchanged service-config storage, preserving
backend transports and policy state across route updates. Generic custom
selectors must be immutable/thread-safe and supply no-allocation retain/release
callbacks; callback context and service-config views are borrowed for the call.

For ADS updates use `rds.publishUpdateWithDeadline`: it validates every resource
and checks unique names before publishing the requested selector. RDS SotW
omission preserves the accepted selector and ACKs without changing its epoch.
A present resource with no routes installs a rejecting selector. Invalid resources, topology,
old/cross-client tokens, expired budgets or transaction allocation failure
leave the old selector/configuration and ADS version intact. Publication then
advances the accepted ADS version before ACK output. As with CDS/EDS, callers
must inspect acceptedVersion before NACKing an ACK output failure and use
flush/reconnect to replay the committed version.

`zig build interop-grpc-rds --summary all` uses official RDS/ADS schemas and
the actual grpc-js-xds RDS validator with two independent grpc-js backends.
It checks exact-host precedence, header/safe-regex and weighted dispatch,
streaming, actual retry attempts and throttle accounting, the route deadline,
NACK rollback, omitted/unrelated-resource retention, explicit empty routes and
an old in-flight RPC completing after a new route becomes active. All 448
permitted RPCs are counted and each backend must
reuse one HTTP/2 session. Native tests cover allocation/topology rollback,
constructor ownership, bounded selector epochs, decoder limits, skipped
non-GRPC paths, inherited retry disable and admission priority. Existing ADS,
CDS and official RE2 gates provide regression evidence in
`docs/evidence/grpc_rds/2026-11-03.json`; the corrected SotW gate is in
`docs/evidence/grpc_xds_sotw/2026-11-03/rds.Debug.json`.

This integrates client RDS selection with existing cluster managers.
[Client LDS/HCM orchestration](grpc_lds.md) now selects inline/dynamic RDS and
reprojects cached routes under HCM defaults. Typed delta route publication is
available through the automatic runtime. Bootstrap parsing and insecure
control-plane failover are available; automatic multi-cluster CDS/EDS
orchestration, authority-specific control planes and automatic LRS reporting
are implemented through the automatic runtime. Certificate providers other
than `file_watcher`/`static_file`, automatic bootstrap refresh scheduling, HTTP filter
overrides beyond RBAC/fault and non-URI-template `path_rewrite_policy` formats
remain open.
Delta route TTL expiry is covered. Literal prefix/whole-path and authority
rewrites, automatic endpoint authority rewriting, and literal request/response
header additions/removals are covered by native selection, owned-input and
on-wire tests. Unsupported recognized filter, rewrite, timeout-offset and
plugin features fail validation; this module does not silently claim their
deployment behavior. Evidence is recorded in
`docs/evidence/grpc_rds/2026-11-04-rewrites.json`,
`docs/evidence/grpc_rds/2026-11-04-literal-path-host.json`,
`docs/evidence/grpc_rds/2026-11-04-request-headers.json`,
`docs/evidence/grpc_rds/2026-11-05-regex-path-rewrite.json`,
`docs/evidence/grpc_rds/2026-11-05-auto-host-rewrite.json` and
`docs/evidence/grpc_rds/2026-11-05-response-headers.json`.
