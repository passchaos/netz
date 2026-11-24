# Socket interface policy during adoption — 2026-11-24

QUIC previously applied a requested interface while taking ownership of an
existing SOCKS5 UDP association. That changes a socket after it has already
bound, and Winsock ADD_IFLIST can retain earlier receive-list entries. Shared
H3 pool adoption did not verify its requested interface against the endpoint.

Both paths now assert the existing native socket policy before allocation or
ownership transfer. Unconstrained/differently constrained sockets return
`InterfaceBindingMismatch`; rejected adoption retains caller resources and
settings. Matching name/index selections transfer ownership normally. Create
the endpoint or association with the desired interface before binding it.

The shared checker reads SO_BINDTODEVICE on Linux, IP_BOUND_IF/IPV6_BOUND_IF on
Darwin, and UNICAST_IF plus an enabled, single-entry receive list on Windows.
A foreign IO backend is rejected before a Winsock/native handle is accessed.
The query performs no setters and adds no work to packet send/receive paths.

| Verification | Result | Evidence |
| --- | --- | --- |
| New rejection regressions before the fix | 88/91 passed, 3 expected failures | [before.log](before.log) |
| Adoption behavior, Debug | 96 passed, 4 Windows-only skips, 0 failures | [adoption.Debug.log](adoption.Debug.log) |
| Adoption behavior, ReleaseSafe | 96 passed, 4 Windows-only skips, 0 failures | [adoption.ReleaseSafe.log](adoption.ReleaseSafe.log) |
| Existing SOCKS5 routing and adoption overlap | 131 passed, 4 Windows-only skips, 0 failures | [socks5-overlap.Debug.log](socks5-overlap.Debug.log) |
| Windows adoption compilation | 8/8 build steps passed | [windows-compile.log](windows-compile.log) |

Native tests exercise matching IPv4/IPv6 sockets, name/index equivalence,
caller-owned TCP/UDP traffic after rejection, unchanged kernel binding after
rejection, and foreign-backend rejection before handle access. Windows-only
cases disable receive filtering while preserving the outgoing interface, or
add a second receive-list entry; both must be rejected without rewriting the
policy. The second-entry test skips if the host accepts no other interface.
Native execution is recorded separately from cross-compilation when CI finishes.

## Creation and adoption error boundaries

The first native Linux job failed its complete library/public-package compile
gate, while the first native Windows transport job succeeded. The shared
interface error set had included the adoption-only mismatch error in socket
creation signatures. Configuration/creation errors are now distinct from
read-only adoption errors, preserving the existing source-bound TCP APIs.
The complete Linux compile gate passed after this separation (8/8 steps), and
the owning library's source-bound TCP tests passed (225 passed, 1 platform skip).
The combined creation/adoption checks passed (98 passed, 5 platform skips).

| Additional verification | Result | Evidence |
| --- | --- | --- |
| Full Linux library/public-package compilation | 8/8 build steps passed | [linux-full-compile.log](linux-full-compile.log) |
| Source-bound TCP owning library tests | 225 passed, 1 skip | [legacy-tcp.Debug.log](legacy-tcp.Debug.log) |
| Creation/adoption error boundary | 98 passed, 5 skips | [errors.Debug.log](errors.Debug.log) |
| Final Windows error boundary compilation | 8/8 build steps passed | [errors.windows-compile.log](errors.windows-compile.log) |

See [the interface contract](../../../local_network_binding.md).

```sh
zig build test-quic test-http3 '-Dtest-filter=network interface adoption' -j1 --summary all
zig build test-quic test-http3 '-Dtest-filter=network interface adoption' -Doptimize=ReleaseSafe -j1 --summary all
zig build test-quic test-http3 '-Dtest-filter=SOCKS5' '-Dtest-filter=network interface adoption' -j1 --summary all
zig build test-compile '-Dtest-filter=network interface adoption' -Dtarget=x86_64-windows-gnu -j1 --summary all
```
