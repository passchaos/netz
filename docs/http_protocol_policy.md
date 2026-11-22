# Ordered HTTP protocol selection

`http.ProtocolPolicy` controls the connection's eligible protocol order.
The default remains `prefer_http2`.

| Policy | HTTPS selection |
| --- | --- |
| `prefer_http3` | Try H3 over QUIC first, then offer H2/H1 over TCP TLS. |
| `prefer_http2` | Offer H2 before H1 in one TCP TLS ALPN handshake. |
| `http3_only` | Require H3 over QUIC/TLS 1.3. |
| `http2_only` | Require H2 ALPN over TCP TLS. |
| `http1_only` | Require H1 over TCP TLS. |

H2/H1 feasibility uses the authenticated peer's ALPN choice; it does not open
two TLS connections. H3 is never negotiated by TCP ALPN: the TCP handshake
offers `h2` and `http/1.1`, while H3 requires a QUIC connection whose own TLS
handshake offers `h3`. `prefer_http3` therefore probes QUIC before starting the
TCP ALPN handshake. Cleartext has no TLS ALPN: H3 is ineligible, and the
existing `cleartext_protocol` selects H1 or explicit H2 prior knowledge.
`http3_only` rejects cleartext URIs.

```zig
var client = try netz.http.Client.init(allocator, io, .{
    .protocol_policy = .prefer_http3,
});
defer client.deinit();
var response = try client.requestUriWithTimeout(
    "https://example.com/resource", .{}, .fromSeconds(10),
);
defer response.deinit();

// The pool uses the same policy for its primary connection leases.
var pool = try netz.http.Pool.init(allocator, io, .{
    .client = .{ .protocol_policy = .prefer_http3 },
});
defer pool.deinit();
```

`prefer_http3` probes the URI's origin host and port without requiring a prior
Alt-Svc advertisement. `http3.preference_timeout` defaults to 250 ms and bounds
only H3 connection selection. A caller connection deadline further limits the
probe to half its remaining budget, leaving time for TCP selection. Both phases
keep the original deadline; a TCP fallback does not renew it. Explicit H3
handshake/address budgets can be stricter. `http3_only` uses ordinary connection
and handshake budgets without a preference probe or TCP fallback.
During a preference probe, Happy Eyeballs' address-attempt delay is further
capped at one quarter of the probe budget. This lets an alternate address
family participate before a short feasibility window ends.

Connection/protocol unavailability advances selection: for example a UDP
timeout, refusal, unreachable path or unsupported QUIC version. Certificate
verification, invalid configuration, allocation and caller-cancellation errors
remain errors. Direct H3 is ineligible when a cleartext HTTP/1.1 CONNECT proxy
is configured or TLS 1.3 is disabled, so a preference policy uses the
configured TCP route. SOCKS5 stays eligible: TCP uses CONNECT and H3 uses UDP
ASSOCIATE with proxy-side domain resolution. The strict H3 policy rejects an
HTTP CONNECT proxy and TLS 1.2-only policy. A TCP
`tls.ca_bundle` has no QUIC representation: `prefer_http3` stays on TCP unless
explicit H3 trust (`server_auth`, a native store, an environment, or a
non-default root source) is configured, and `http3_only` rejects the
configuration at `Client.init` with `error.UnsupportedH3TrustConfiguration`.

Selection ends before sending an application request. This allows POST and
single-pass Reader requests to select TCP safely after an H3 connection failure.
Once a request starts, response/upload failures do not restart protocol
selection. Existing stale retry, redirect and Alt-Svc request replay rules
still apply independently.
An established connection keeps its selected protocol. Pool idle reuse does
not repeat the H3 probe for every request; optional Alt-Svc routing can select
a learned H3 alternative on subsequent requests.

`Pool.Options.client` governs its primary `Client` connections and supports
both H3 policies. `acquireUri`, ordinary requests and `startRequest` can return
or use exclusive H3 connections, with the same idle/admission/combined budgets.
The H2 frame owner hands other negotiated protocols to the exclusive request
path. Optional `Pool.Options.http3` remains the Alt-Svc dispatcher backend for
shared H3 multiplexing, discovery, managed 0-RTT and SOCKS5 UDP routing.

`connectionCount`/`idleCount` describe the primary backend, including its direct
H3 connections. `http3ConnectionCount`/`http3IdleCount` describe the optional
Alt-Svc backend; `totalConnectionCount` spans both. TCP session-ticket caches
remain keyed by origin/ALPN and direct H3 uses its native resumption settings.
Cross-origin isolation clears explicit TCP and QUIC resumption inputs.

See [direct H3 configuration](http_direct_h3.md),
[pool ownership](http_client_pool.md), and
[selection evidence](evidence/http_protocol_policy/2026-11-20/README.md).
