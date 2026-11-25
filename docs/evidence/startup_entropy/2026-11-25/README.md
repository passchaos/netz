# H3 URI preparation under the connection budget — 2026-11-25

At `10103a75`, owning unified HTTP, H3 WebSocket and WebTransport endpoint URI
clients generate QUIC connection IDs and load default roots before the native
H3 connector starts its configured `connect_timeout`. Preparation therefore
does not consume that timeout, and connection-ID entropy also bypasses an
existing caller deadline's timer admission.

Three deterministic regressions expose the latter defect: a backend that
rejects scheduler admission and fails every entropy call reports
`EntropyUnavailable`, rather than rejecting timer admission before entropy.
The baseline records 272/275 passes and three failing URI cases in
[before.Debug.log](before.Debug.log).

The URI owners now combine their H3 timeout with the original caller timestamp
before preparation. They clear the relative timeout before passing the same
timestamp through entropy, roots, DNS, SOCKS5 and the native H3 handshake.
WebSocket's Extended CONNECT exchange retains its separate caller-owned
opening deadline. Zero H3 connection budgets report `HandshakeTimeout` before
entropy or root access.

The shared entropy helper admits its timer first and joins both tasks on every
exit. Source successes and failures are accepted only while the budget and
cancellation state permit them. Protected native entropy may finish after a
timeout; its borrowed buffer remains alive until the writer is joined.
A deterministic timer-winner regression holds that writer behind a gate,
triggers expiry, observes cleanup begin with the caller still waiting, then
releases the write and verifies the timeout and completed buffer.

Stable connection-ID storage generates only missing IDs and publishes their
slices after successful entropy. Two missing IDs share one entropy request;
configured IDs are preserved, and failed generation leaves the option value
unchanged. The real WebTransport endpoint URI fixture uses one zio runtime,
generated IDs and a P-256 certificate pin, and joins or cancels its server peer
on every exit. Existing authenticated HTTP and WebSocket URI checks cover
the owning constructors and protocol-selection overlap.

[Local validation metadata](local-validation.json) records source hashes and
results. [The guard log](guard.log) records serialized Zig supervision; all
builds use `-j1`. Windows compilation is distinct from native execution.
The native Linux/Windows trust-startup gate includes `startup entropy`.

| Verification | Result | Evidence |
| --- | --- | --- |
| URI preparation baseline | 272/275 passed; three failures | [before.Debug.log](before.Debug.log) |
| Debug | 297/297 passed | [Debug.log](Debug.log) |
| ReleaseSafe | 348/348 passed | [ReleaseSafe.log](ReleaseSafe.log) |
| windows-compile | Compiled successfully | [windows-compile.log](windows-compile.log) |
