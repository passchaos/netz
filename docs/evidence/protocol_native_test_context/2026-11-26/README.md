# Native protocol deadline test contexts

The repaired fixtures complete the native macOS HTTP/3 protocol check:
1,005 tests passed, four existing GRO cases skipped, and none failed. The
selected HTTP/3 scope passed 78 tests, WebTransport send-flow passed 120 tests,
and the selected HTTP/3/WebTransport tests compiled for Windows. These results
are recorded in [validation](validation.json); pinned native and complete CI at
the delivered revision remain required.

Several fixtures copied Threaded callbacks while replacing their userdata with
a clock or send observer. Native concurrent callbacks then interpreted the
observer as a Threaded backend. Complete HTTP/3 diagnostics exposed this in
paced push, protected DATA streaming, request DATA batching and aggregate
head/body deadlines. Linux complete CI identified the same pattern in the
WebTransport multi-packet socket-error fixture.

These fixtures now reuse the existing Native sender backend. Every inherited
callback receives the backend's own userdata. Custom send callbacks have an
explicit context, and mutable awake clocks and counters use atomic storage.
Send-advanced clocks move after a confirmed socket send. Paced-push clocks move
only after the peer receives the promise, then wake the native deadline watcher.

Fixed pacing probes retain the native cancelable deadline watcher and count
pacing-duration waits separately. An insufficient budget must leave socket
send count, packet number and body offsets unchanged. Batch and aggregate peers
use cancelable Futures, joined before borrowed state teardown. Fixtures restore
endpoint I/O before destroying their sender backend. Stream retirement,
parent/sibling survival, exact committed credit, suffix payload and FIN checks
remain covered.

The native CI deadline step keeps its original combined command and runs these
fixture filters separately within the same five-minute budget. All dependency
pins, existing budgets and real IP migration cases remain intact. The preceding
[run 45740784651](https://github.com/passchaos/netz/actions/runs/45740784651)
passed both native combined protocol steps but failed complete acceptance in
the WebTransport observer and, separately, client CA reload before SIGHUP.
The latter remains unresolved. Local Vail differs from the fixed CI pin, so
local tests do not substitute for pinned platform results.
