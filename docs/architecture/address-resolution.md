# Address resolution and scheduling

URI identity and transport addresses have separate ownership. DNS chooses the
addresses to attempt; the original URI continues to own TLS authentication,
SNI, HTTP authority and pool identity. Literal IP routes bypass application
resolution in the URI facades. Native socket interface constraints do not
configure DNS traffic; see [local network binding](../local_network_binding.md).

The unified HTTP `Options.address_resolver`, native HTTP/1 and HTTP/2
`Limits.address_resolver`,
WebSocket `ConnectOptions.address_resolver`, HTTP/3
`HandshakeClientOptions.address_resolver` and SOCKS5
`Options.address_resolver` use the same callback contract. A resolver value
contains a borrowed context pointer and a function accepting the caller's
allocator, `std.Io`, hostname, port and optional absolute deadline. Independent
routes may call it concurrently. The context must outlive the clients/pools
storing it and their pending calls. The implementation must honor I/O cancellation
and the deadline, and return an allocator-owned address slice. Callers free that
slice after address scheduling completes. Authentication identity remains
independent of those returned addresses.

Native H1/H2 named TCP/TLS constructors and URI request helpers use the resolver
and address policy in their `Limits`. `address_connect_policy = null` selects
ordered fallback; setting `.happy_eyeballs` enables bounded staggered attempts.
These choices compose with `local_address`, `network_interface` and the original
connection deadline. Literal IP routes bypass the application resolver.

```zig
var connection = try netz.http2.runtime.Client.connectTlsHost(
    allocator, io, "api.example.com", 443,
    .{
        .address_resolver = resolver,
        .address_connect_policy = .{ .happy_eyeballs = .{
            .attempt_delay = .fromMilliseconds(250),
            .max_in_flight = 2,
        } },
    },
    .{},
);
defer connection.close();
```

Native proxy transports inherit configured resolver/policy from the owning
limits. Proxy-specific `ProxyOptions` fields override those inherited values;
origin hostnames in CONNECT remain proxy-resolved. `http2.runtime.limitsToHttp1`
preserves all shared transport fields when adapting limits. See [native option
evidence](../evidence/native_resolver_policy/2026-11-25/README.md).

System full-address resolution is shared by TCP address racing, SOCKS5 relay
resolution, proxy ACL destination resolution and HTTP/3 URI/Alt-Svc resolution.
The DNS producer owns a separate concurrent task, while one consumer drains a
16-entry queue and deduplicates addresses in first-seen order. The collector
keeps its first 16 unique addresses on the stack and spills only for larger
answers; the returned slice is owned by the caller. HTTP/3's first-address
resolver uses the same producer ownership and cancels/drains remaining results
after taking the first address.

Ordered TCP hostname connects consume that same reader incrementally. An
available address starts a connection immediately, and the next attempt begins
only after a retryable failure. Ordinary, source-address-bound and
interface-bound paths share this ordering, source-family filter and DNS
teardown. Their connection deadline covers lookup and all attempts, including
the compatibility `hostBound` entry points. Native socket connect APIs report
concurrent task admission failure as `SystemResources`.

An `.ordered` policy keeps one TCP attempt active, so a pending first candidate
holds back later candidates. Applications choosing overlapping attempts can
set the unified HTTP or WebSocket `address_connect_policy` to
`.{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(250), .max_in_flight = 2 } }`.
URI authentication, authority and binding policy stay attached to the owning
connection options. [Ordered hostname evidence](../evidence/ordered_hostname_connections/2026-11-25/README.md)
covers exact ordering, early DNS results and source-family bindings.

A bounded system lookup validates its awake-clock deadline before task
admission and races collection against that original timestamp. Explicit
concurrency prevents the lookup or timeout task from executing inline when an
executor's async quota is exhausted. Zero async quota therefore still works
when concurrent task admission is available. An executor unable to admit the
required tasks returns `ConcurrencyUnavailable`. The common resolver error
contract and application callback `ResolveError` both include it, so a callback
can delegate to system resolution or compose concurrent I/O directly.

Timeout, cancellation, allocation failure and partial task admission join all
admitted tasks before queue storage disappears. Unselected owned address
results are freed while draining the completion selector. Common TCP/proxy
lookup timeouts return `Timeout`; native HTTP/3 maps DNS expiry to
`HandshakeTimeout`. An earlier overall shared request deadline retains
`Timeout`, as described in [the H3 budget evidence](../evidence/http3_acquisition_deadline/2026-11-25/README.md).

The deterministic [system resolver regressions](../../src/http3/runtime/client/system_resolver_tests.zig)
exercise the common, proxy and H3 entry points with zero async quota: a delayed
lookup under an 80-ms deadline, 41 emitted results containing 40 unique
addresses, unavailable concurrency before DNS entry, and rejection of a foreign
clock. H3 literal routing retains its bypass on an executor without concurrency.
Existing native hostname and collector/OOM checks cover transport integration
and ownership. Results are recorded in [the resolver evidence](../evidence/system_address_resolution/2026-11-25/README.md).
