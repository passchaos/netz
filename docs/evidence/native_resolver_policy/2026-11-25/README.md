# Native H1/H2 resolver and address policy — 2026-11-25

Native H1/H2 `Limits` exposed source-address, interface and connection timeout
configuration, while their named/URI TCP paths did not expose the shared
application resolver or address-connect policy. Callers needing custom DNS or
bounded Happy Eyeballs therefore had to use a different facade or open/adopt a
stream. Four capability-gated regressions fail on the baseline with
`MissingNativeResolverOptions`: 22/26 selected tests pass.

Both native limits now carry the common `address_resolver` and an optional
`address_connect_policy`; null retains ordered fallback. The shared named
connection boundary validates the policy before authority allocation, retains
the original absolute budget, and passes resolver, policy and binding together
to the endpoint connector. Endpoint admission rejects expired/foreign deadlines
before entering the callback. Logical TLS identity and authority remain derived
from the original name. Native URI and h2c Upgrade request helpers also use the
configured policy, including policy preflight before URI storage allocation.

Native proxy resolution inherits the owning resolver/policy when configured,
with explicit proxy options taking precedence. H2-to-H1 limit conversion now
retains source address, interface, resolver, policy and connect timeout. An
actual H1 connection opened through converted H2 limits verifies policy rejection
before callback entry and the requested native source/interface constraint.

Live H1/H2 requests use the logical `native.endpoint.test:8443` authority while
the resolver chooses different loopback ports. Each protocol covers unbounded,
deadline and timeout named constructors, ordinary URI requests, ordered and
Happy Eyeballs policy, refused-first fallback, and literal bypass. The resolver
checks the exact caller-owned deadline. Native zio fixtures combine resolution
and Happy Eyeballs with source/interface constraints. Admission cases verify
invalid policy, OOM and foreign clocks before callback entry, TLS constructor
propagation, and proxy inheritance/override using distinct DNS errors. Native
Linux/Windows CI runs these cases through the H1/H2 scoped suites.

Native Windows diagnostics at `3fa4e581` confirm that the refused-first
explicit-deadline fixture exhausts its two-second budget in the native TCP
attempt: H1 reports `Timeout` with zero/negative remaining milliseconds, and H2
reports the same failure with `-10ms` remaining. Resolver deadline checks pass.
Successful fallback needs room for Windows to publish the closed-port refusal,
so only this fixture's Windows connect budget is five seconds and its accept
budget is six seconds. Other hosts retain the original two/three-second
budgets. Production timeout policy and request/literal/admission budgets retain
their existing behavior.

```sh
zig build test-http1 test-http2 '-Dtest-filter=HTTP1 native resolver policy' '-Dtest-filter=HTTP2 native resolver policy' -j1 --summary all
```

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline native configuration capability | 22/26 passed; all 4 new expectations fail | [before.log](before.log) |
| Initial live routing, identity, admission and binding coverage | 64/64 passed | [initial.log](initial.log) |
| Final native routing, proxy precedence and H2→H1 projection | 65/65 passed | [final.log](final.log) |
| Named/TLS identity, proxies, h2c Upgrade, unified HTTP and WS overlap | 284/284 passed | [Debug.log](Debug.log) |
| Native Windows refused-first fixture before budget correction | `Timeout` at the original deadline | [native-windows-before.json](native-windows-before.json) |
| Platform-specific refusal budget correction on the local host | 65/65 passed | [windows-budget.Debug.log](windows-budget.Debug.log) |
| Corrected native resolver fixtures for Windows | Compiled | [windows-budget.compile.log](windows-budget.compile.log) |
