# Shared HTTP/3 endpoint IO provenance — 2026-11-24

`SharedHandshakeClientPool.initWithOwnedEndpoint` previously accepted any
`std.Io`, stored it for scheduling and deadlines, but retained an endpoint and
QUIC dispatcher operating on the endpoint's original IO context. This could
mix different backends or different instances of one backend in one pool.

Adoption now rejects mismatched userdata/vtable with `InvalidPoolOptions`
before pool allocation or ownership transfer. The caller retains a usable
endpoint on rejection. Copies of the exact IO context remain valid. Pass
`endpoint.io` to the constructor; allocate the endpoint pointer with the pool
allocator so its eventual destruction uses the right allocation owner.

| Verification | Result | Evidence |
| --- | --- | --- |
| Corrected regressions before the fix | 57/60 passed, 3 expected failures | [before.log](before.log) |
| IO adoption, Debug | 60/60 passed | [Debug.log](Debug.log) |
| IO adoption, ReleaseSafe | 60/60 passed | [ReleaseSafe.log](ReleaseSafe.log) |
| Shared SOCKS5 and interface adoption overlap | 69 passed, 2 Windows-only skips | [overlap.Debug.log](overlap.Debug.log) |
| Windows compile | 8/8 build steps passed | [windows-compile.log](windows-compile.log) |

Tests use two Threaded instances sharing one vtable but distinct userdata,
and zio versus Threaded. Rejected endpoints still exchange real UDP packets
through their original IO context. A failing pool allocator proves the IO
check happens before allocation. A positive test adopts an exact IO copy.
The native Linux and Windows CI filters also select these regressions; native
results are recorded separately from cross-compilation once CI completes.

```sh
zig build test-http3 '-Dtest-filter=HTTP3 endpoint adoption' -j1 --summary all
zig build test-http3 '-Dtest-filter=HTTP3 endpoint adoption' -Doptimize=ReleaseSafe -j1 --summary all
zig build test-http3 '-Dtest-filter=HTTP3 endpoint adoption' '-Dtest-filter=shared HTTP3 SOCKS5' '-Dtest-filter=network interface adoption' -j1 --summary all
zig build test-compile '-Dtest-filter=HTTP3 endpoint adoption' -Dtarget=x86_64-windows-gnu -j1 --summary all
```
