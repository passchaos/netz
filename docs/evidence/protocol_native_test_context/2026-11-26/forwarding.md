# Actual backend delegation for deterministic protocol fixtures

The previous pinned complete run identifies a GP at `WebTransport protected
runtime CONNECT and datagrams over QUIC 1-RTT`. That fixture and two DATA-slice
fixtures replaced Threaded userdata with send-clock observers while retaining
unrelated native callbacks. They now use stable Native observer context, atomic
clocks/counters and cancellation/join peer futures. Every original committed
prefix, exact suffix, FIN, flow-credit and socket-call assertion remains.

The new `forwarded_io` helper derives every function signature from std.Io's
VTable and forwards every callback with the delegate's actual userdata. Future,
Group, futex, socket and Batch tokens therefore remain with the actual backend.
The Native observer retains its embedded Threaded userdata as its stable local
context; explicit forwarding handles delegation, while default Threaded mode
retains its prior callback contract. Synthetic awake deadlines become remaining
native durations before backend waits; other clocks and relative durations retain
their existing values. Fake-clock deadline watchers wake through the actual
backend's events instead of blocking a native coroutine with a foreign wait.

Two real UDP regressions cancel an entered batch read and reuse its socket, and
record the exact synthetic remaining duration seen by the actual backend.
Changed UDP fixture roots run both supported POSIX backends and application IOCP
on native Windows. All send-flow grant waits, visible-prefix writes and peer
shutdowns keep real transport execution.

[forwarding.json](forwarding.json) records source hashes and scoped native/Windows
compilation. Native Windows and complete acceptance require the delivered
revision's CI. The previous revision's Linux native and complete MQTT config
interop passed, but that is not a causal fix for the earlier CA reload failure.
Its new Windows H2 owned-input command exposed two TLS peer disconnections;
those retained failure stages and their first peer cause remain open. Pins,
original native commands, CI budgets and real IP-migration assertions are unchanged.

Failure annotations now recognize GP, illegal-instruction and stack-overflow
prefaces before long stacks. The annotation cap remains twelve and test names or
warning diagnostics containing those phrases are not treated as crash prefaces.
