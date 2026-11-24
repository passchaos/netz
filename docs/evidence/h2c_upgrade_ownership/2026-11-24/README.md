# h2c Upgrade stream ownership — 2026-11-24

`Client.connectStreamUpgrade*` takes stream ownership at entry, but its common
deadline path validated the clock before constructing the connection and its
close guard. Expired or foreign-clock deadlines returned `Timeout` without
closing the adopted socket. The same gap affected TCP-opening
`connectUpgradeWithDeadline` and `connectUpgradeWithTimeout` when the deadline
expired after TCP completion. A non-positive timeout on an adopted stream also
returned before installing any cleanup owner.

Deadline validation now runs after the connection close guard and before
local-limit validation, socket options or either handshake. Non-positive
adopted timeouts close the supplied stream immediately. This aligns the
absolute and relative h2c Upgrade APIs with their documented ownership
contract. Successfully returned `H2cUpgradeResult` values still own the
connection and 101 metadata and use `deinit(allocator)` for cleanup.

The shared fixture now lives in `internal/testing/connection_transition.zig`
and handles owned clients and Upgrade responses. For a TCP-opening constructor,
an event requires the connect timer to enter its blocking wait before the
socket can complete and the virtual clock expires. This forces the connected
result to reach the protocol owner; the timer cannot win and mask a missing
protocol close through the connect race's own cleanup. Direct stream adoption
uses the same close/write/EOF checks without a connect timer.

Six public API scenarios cover:

- TCP-opening absolute and relative budgets that expire after connect.
- Adopted streams with an expired awake deadline or a foreign-clock deadline.
- Adopted streams with zero or negative relative timeouts.

Every scenario requires `Timeout`, exactly one native socket close, zero
protocol writes and EOF from the real IPv4 loopback peer. A failed baseline
assertion rescues its leaked socket. The first baseline captured three failing
tests before production changes; the final overlap uses the strengthened
timer-start synchronization. That overlap also covers H1 standard/vail and
WSS standard/vail transitions, H2 TLS transitions, the 101/SETTINGS deadline
boundary and SETTINGS coalesced with the 101 response. Native Linux and
Windows CI select all three new h2c ownership tests.

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline before the fix | 33/36 passed, 3 expected failures with zero closes | [before.log](before.log) |
| Synchronized fixture and affected connection/Upgrade paths | 112/112 passed | [Debug.log](Debug.log) |

At commit `a821d3d6`, the [native Linux connection/Upgrade step](https://github.com/passchaos/netz/actions/runs/45417181440/job/138526713207)
and [native Windows transport step](https://github.com/passchaos/netz/actions/runs/45417181440/job/138526713809)
both completed successfully. The exact conclusions and timestamps are recorded
in [native-platforms.json](native-platforms.json), independently of cross-compilation
and the overall CI workflow result.

```sh
zig build test-http2 '-Dtest-filter=HTTP/2 h2c stream ownership' -j1 --summary failures
zig build test-http1 test-http2 test-websocket '-Dtest-filter=HTTP/2 h2c stream ownership' '-Dtest-filter=deadline expires after TCP connect' '-Dtest-filter=HTTP/2 h2c deadline preserves SETTINGS coalesced with 101' '-Dtest-filter=HTTP/2 h2c caller deadline spans 101 and binary bootstrap' '-Dtest-filter=HTTP/2 h2c client bounds' -j1 --summary all
```
