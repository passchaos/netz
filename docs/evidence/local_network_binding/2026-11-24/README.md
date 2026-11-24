# Local network binding verification — 2026-11-24

This change adds actual named/indexed socket interface constraints independently
from source IP/port selection. HTTP/1, HTTP/2, WebSocket, unified HTTP and SOCKS5
TCP owners share the binding connector; QUIC endpoint limits carry the same
interface into H3/WebTransport, shared pools and migration endpoints. Native TCP/UDP sockets install the
interface policy before bind; TCP listeners apply it before bind/listen.

See [the API and native support contract](../../../local_network_binding.md).
Linux uses SO_BINDTODEVICE, Darwin uses IP_BOUND_IF/IPV6_BOUND_IF, and Windows
UDP combines UNICAST_IF with receive-interface lists. Windows TCP requests fail
explicitly because Winsock has no corresponding received-TCP constraint.

| Verification | Result | Evidence |
| --- | --- | --- |
| Binding plus ordinary/direct/preferred H3, Debug | 171/171 passed | [binding-and-h3.Debug.log](binding-and-h3.Debug.log) |
| Binding, ReleaseSafe | 156/156 passed | [binding.ReleaseSafe.log](binding.ReleaseSafe.log) |
| TCP timeout/hostname/address racing and HTTP/WS/SOCKS overlap | 372 passed, 5 platform skips, 0 failures | [connection-overlap.Debug.log](connection-overlap.Debug.log) |
| Windows binding-path compilation | 8/8 build steps passed | [windows-compile.log](windows-compile.log) |
| UDP policy before bind, Debug | 158/158 passed | [before-bind.Debug.log](before-bind.Debug.log) |
| UDP policy before bind, ReleaseSafe | 158/158 passed | [before-bind.ReleaseSafe.log](before-bind.ReleaseSafe.log) |
| UDP policy before bind, Windows compilation | 8/8 build steps passed | [before-bind.windows-compile.log](before-bind.windows-compile.log) |

## Scope of the native checks

Live tests read back socket options and exchange IPv4/IPv6 TCP bytes and QUIC
UDP datagrams on loopback. They verify name/index selection, combined source
and interface constraints, ordered/Happy Eyeballs retries, listener inheritance,
HTTP forward/CONNECT and WebSocket option propagation, explicit backend and
configuration rejection, and expired deadlines. Authenticated H3 tests set
conflicting native H3 bind options to ensure common HTTP options override them;
the pool test inspects its actual shared UDP socket.

Cross-compilation is recorded separately from execution. The portable workflow
runs the binding suite natively on x86_64 Linux and includes it in the native
Windows transport suite. Native CI snapshots will identify the exact tested
commit and jobs once those runs finish.

## First native Windows result

The first native Linux job at `d920f47b` succeeded; its exact steps are recorded
in [native-linux.json](native-linux.json). The first native Windows job failed
while adding the receive interface with ADD_IFLIST (option 29), after the
outgoing-interface option succeeded. Its error annotations are preserved in
[windows-first-annotations.json](windows-first-annotations.json).

The follow-up configures receive filtering before adding the index and moves
all interface policy before UDP bind. This prevents another interface's packet
from entering an initially unconstrained receive queue. Explicit UDP device
binding uses zio's native socket creation, while ordinary std.Io source binds
retain their existing path. The native Windows probe compares enable/add and
bind ordering plus both interface-index byte orders; its outcomes and the next
native regression result will be recorded separately.

## Windows receive list and family checks

The bounded native probe at `6d6cd8ec` confirmed that receive filtering must be
enabled before ADD_IFLIST, and that interface-list indices use host byte order
for both IPv4 and IPv6. The successful probe rows and subsequent protocol
failure stacks are recorded in [windows-probe-messages.json](windows-probe-messages.json).
IPv4 progressed through the real send/receive regression; the remaining failure
was the V6ONLY query performed before bind.

The next correction configures V6ONLY before bind and validates its actual value
after bind, before returning the socket. Boolean query buffers are initialized
and accept byte or DWORD results; interface indices still require DWORD. The
native probe additionally records raw V6ONLY and IFLIST bytes. Linux native
execution of the UDP setup before bind succeeded at `6d6cd8ec`, recorded in
[native-linux-before-bind.json](native-linux-before-bind.json).

## Fixture corrections found by overlap checks

The initial overlap run exposed two fixture problems, recorded in
[initial-overlap.Debug.log](initial-overlap.Debug.log). The UDP forged-source
fixture sent to a wildcard bind address; an isolated archive of baseline
`e98e653262ee24336d89cbb0b00326b7ef2c7671` reproduced this failure (123/124 passed), recorded in
[baseline-fixtures.log](baseline-fixtures.log). It now sends to loopback at the
association's real bound port while retaining the wrong sender tuple.

The successful-loser race fixture invoked a new real Threaded connect after
its worker was canceled. On Darwin, Zig 0.16's EINTR retry can then report
ISCONN as a programmer assertion. Its unchanged baseline path passed the
isolated run, so this was intermittent. The fixture now prepares the connected
socket before starting the cancelable race and delays only its returned result.
It still checks staggering, cancellation draining, exact loser closure and EOF
at the accepted peer. The production connection-race implementation is unchanged.

## Reproduction

```sh
zig build test-http test-quic '-Dtest-filter=network interface' '-Dtest-filter=unified HTTP direct H3' '-Dtest-filter=unified HTTP protocol policy' -j1 --summary all
zig build test-http test-quic '-Dtest-filter=network interface' -Doptimize=ReleaseSafe -j1 --summary all
zig build test-http test-http1 test-http2 test-websocket test-proxy '-Dtest-filter=connect timeout' '-Dtest-filter=SOCKS5' '-Dtest-filter=Happy Eyeballs' '-Dtest-filter=client connects by host name' '-Dtest-filter=TCP bound' -j1 --summary all
zig build test-compile '-Dtest-filter=network interface' -Dtarget=x86_64-windows-gnu -j1 --summary all
```
