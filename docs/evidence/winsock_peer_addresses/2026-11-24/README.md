# Backend-aware Windows peer queries, 2026-11-24

Base revision: `944ac037`, Zig 0.16.0, macOS aarch64.

The shared TCP peer helper now receives the connection's `std.Io`. Windows
zio owns Winsock sockets and can use the documented `getpeername` API; a
foreign backend is rejected before accessing its handle. Zig Threaded's native
AFD client handles continue to report unavailable IP metadata. HTTP/1,
HTTP/2 and WebSocket callers forward their existing IO object, so public
address APIs and connection layouts do not change.

The isolated Winsock adapter retains a 128-byte SOCKADDR_STORAGE on the stack,
rejects failed and invalid-length results, and decodes IPv4/IPv6 IP metadata.
Fixed Windows vectors verify the port's network byte order, native flow/scope
fields, IP octets, ABI sizes/offsets, every truncated prefix, and non-IP
families. An explicit test import keeps these vectors active on POSIX, where
the native Windows query branch is eliminated.

zio's generic IP connect records the selected destination in its std socket;
Threaded records a local sockname. Adopted and explicitly bound streams can
carry different cached addresses. Tests preserve those fields while comparing
the actual peer at both ends of Threaded and zio IPv4/IPv6 connections. The
[public contract](../../../peer_addresses.md) documents the backend distinction.

| Gate | Result | Artifact |
| --- | --- | --- |
| Scoped peer-address tests on macOS | 100/100 | [peer-address.Debug.log](peer-address.Debug.log) |
| Scoped WebSocket connection test on macOS | 48/48 | [websocket.Debug.log](websocket.Debug.log) |
| Windows library/public-package test compile and link | 8/8 steps | [windows-compile.log](windows-compile.log) |
| CI YAML and matrix/token invariants | Passed with Ruby YAML parser | `.github/workflows/ci.yml` |

Counts include imported support tests. The local Windows gate compiles and
links x86_64 Windows test binaries; it does not establish native execution.

```sh
zig build test-http '-Dtest-filter=peer address' --summary all
zig build test-websocket \
  '-Dtest-filter=runtime client and server exchange over TCP' --summary all
zig build test-compile '-Dtest-filter=peer address' \
  -Dtarget=x86_64-windows --summary all
```

## Native Windows CI admission

The portable CI matrix retains its three Linux-hosted cross-compile targets
and adds a Windows runner that executes the focused peer-address tests.
Its explicit target is `x86_64-windows-gnu`; Bash and the Windows Zig download
cache path are configured for that runner.

The preceding CI run for `944ac037`
([45321067496](https://github.com/passchaos/netz/actions/runs/45321067496))
failed every build job at `Require sibling dependency credentials`, before
compilation. Anonymous reads of `build.zig.zon` succeeded at every configured
pin: vail `3b772b0c`, vort `a48e1151`, pbz `6513ef1f`, kron `77b9572a`,
webpkiz `35c9f4bf`, regexz `f1507670`, and harnessz `e626f26b`.
CI now uses its read-only `github.token` for public dependency checkouts and
retains `NETZ_DEPENDENCIES_TOKEN` as an optional override. Native Windows
execution is tracked by the new job after publication.

Reference: [Microsoft getpeername contract](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getpeername).
