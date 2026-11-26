# Complete forwarding for remaining send observers

After the session-control repairs, a source audit found 41 further wrappers
that copied a delegate VTable, replaced only `netSend` and installed an
ObservedBatchSend pointer as userdata. Inherited clock, task, cancellation and
socket callbacks could interpret that pointer as their backend context.
The wrappers now use the observer's complete typed forwarding interface.
One later reinstallation in the allocating DATAGRAM path also uses the same
interface. All original test names, packet bytes, errors, nonces, counters,
retry/credit/association assertions and endpoint restoration remain intact.

The next complete gate on 4b8a5a84,
[run 45828900564 attempt 1](https://github.com/passchaos/netz/actions/runs/45828900564),
identifies another inherited-callback crash at 4786/7488, `WebTransport
caller-owned H3 bounds acceptance and flushes response ACK`. Its acceptance
deadline observer also returned fabricated cancellation from sleep.
That fixture now borrows the actual backend through Native's full forwarding,
uses an atomic awake clock and actual cancellable deadline wait, and restores
endpoint I/O in a scope that ends before acceptance transfers ownership.
Its original zero-send/no-packet-number advance, rejected origin, retained
request state, promoted session and response ACK/recovery assertions remain.
The peer runs as an actual Future on supported backends.

The same run's first named failure is an independent shared Happy Eyeballs
every-route timeout at 1741/7488. Its original 100 ms total deadline and both
Initial-packet assertions remain open for owning-path qualification.
Windows stops earlier at the progress helper's new short-child test, where
Python print uses CRLF. That child now writes explicit LF bytes; exact raw-log
and separate CRLF-preservation checks remain. Eleven local helper checks pass.

[validation.json](validation.json) records the exact original test scopes,
current source hashes and native-versus-compile boundaries. Pins, existing
commands, test budgets and failure annotation limits remain unchanged.
The continuous goal stays active; these repairs do not establish full native,
complete, interop or performance acceptance.
