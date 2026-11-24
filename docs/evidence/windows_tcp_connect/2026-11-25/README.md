# Windows TCP connect boundaries — 2026-11-25

Native Windows CI for ordered hostname acquisition failed at two transport
boundaries. The repository-pinned zio IOCP connector attempted a wildcard bind
on a socket already bound to its source tuple, reporting `EINVAL`. The standard
Threaded AFD connector sent `CONNECTION_REFUSED` to `unexpectedStatus`, exiting
instead of allowing IPv6/IPv4 fallback. Diagnostic commit `275dc8fa` exposed
the exact failed test and stack through public CI annotations.

Netz now retains the prebound Winsock socket and issues ConnectEx directly.
Its OVERLAPPED event suppresses delivery to zio's IOCP and uses a native wait
callback to publish completion to the owning `std.Io.Event`. Timeout and
cancellation request `CancelIoEx`, then wait for kernel completion and callback
retirement before releasing address/OVERLAPPED storage. Successful setup installs
`SO_UPDATE_CONNECT_CONTEXT`. This uses no per-connection blocking waiter.

For the native Threaded connector, a bound AFD socket is created through its
existing `std.Io` backend, and its public device-control operation issues the
connect. Native status mapping preserves refusal, reset, unreachable, timeout,
resource and cancellation errors. Custom `netConnectIp` interceptors and foreign
backends retain their own implementations. Socket creation/binding and teardown
remain with the same owner and backend. Pinned dependency sources are unchanged.

Fixed IPv4/IPv6 sockaddr vectors and AFD status tests run on the local host.
Native regressions cover refusal for both families through ordinary Threaded
and prebound zio TCP paths. Ordered hostname/source tests and new native H1/H2
resolver policy tests compile for the actual Windows target and are selected
by native CI. The scoped `<protocol>-compile` build targets compile selected
tests without attempting to execute a foreign binary.

| Verification | Result | Evidence |
| --- | --- | --- |
| Windows failure stacks | IOCP EINVAL rebind and fatal AFD refusal | [before.txt](before.txt) |
| Final prebound callback and AFD implementation, Windows target | Compiled | [compile.log](compile.log) |
| Local ABI/status/refusal, native resolver, binding, identity and WS overlap | 196/196 passed | [Debug.log](Debug.log) |
| Refusal test budget follow-up on the local host | 23/23 passed | [refusal-budget.log](refusal-budget.log) |

The first repair CI executes the original ordered-hostname and source-binding
cases successfully. Its two additional closed-port refusal tests reach their
one-second test deadline before Windows reports refusal. Their regression-only
budget is increased to five seconds; production timeout values are unchanged.
The next native CI run must confirm the final refusal status for both families.
