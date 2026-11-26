# WebTransport rejection callback ownership

[Run 45820773252 attempt 1](https://github.com/passchaos/netz/actions/runs/45820773252)
on f126f64c aborts at test 4712/7479, `WebTransport standalone retains malformed
Capsule error through cleanup timeout`. The visible stack enters Threaded
Group.concurrent allocator creation through inherited callbacks with a send
observer's userdata. Six session-control rejection, CONNECT termination and
flow fixtures have this callback-owner mismatch.

The shared ObservedBatchSend now provides a complete typed forwarding table.
Its send override keeps the original error/accepted-prefix accounting; every
other callback reaches the actual delegate with its own userdata and tokens.
The selected-send pacing observer uses the same forwarding contract. All six
fixtures restore endpoint I/O before their observer and protocol owners leave
scope and exercise supported actual datagram backends.

Original assertions remain: malformed Capsule errors survive cleanup timeout;
the first committed CONNECT rejection is retained; associated RESET/STOP work
continues once; socket failure can retry cancellation; grant and receive-credit
state commit only at their original boundaries; metadata and deferred errors
are not replaced. [validation.json](validation.json) records the focused
native and Windows compile results. Delivered Linux/Windows native and
complete-crash qualification remain pending.

The same run's Windows protocol step times out at its unchanged five-minute
limit after public annotations report the TCP completion/reuse probe passing.
Those annotations expose the step name while hiding custom notice titles,
so they cannot identify the later active invocation. Progress messages now
carry the invocation title and emit a startup notice before the first periodic
update. Actual-child tests retain exact raw logs, UTF-8, exit status, owned
child cleanup and interruption reporting. Pins, existing commands, budgets
and the failure annotation cap remain unchanged. Independent command scopes
retain failure propagation; their next native run must locate any remaining
stall. The continuous optimization goal stays active.
