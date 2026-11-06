# A6 hedging commitment evidence

The aggregate report is `2026-11-06.json`. The independent HTTP/2 transcripts
are `2026-11-06.Debug.json` and `2026-11-06.ReleaseSafe.json`; both record six
cases, the native executable hash and hashes of the 18 runner/runtime sources.
`2026-11-06/gates.json` records commands, exit codes and validation summaries.

The gRPC library gates exercise 837 tests in Debug and ReleaseSafe. The Node
HTTP/2 peers verify ordinary HEADERS commitment, suppression of later hedges,
committed UNAVAILABLE failure accounting, trailers-only acceleration,
informational HEADERS and a single call-wide transparent replay budget. The
held-body cases require the ordered transcript `B HEADERS < A CANCEL < B body`.
Native lifecycle tests cover retained physical Job ownership, queued loser
removal, interrupted fault delay and the original deadline after commitment.

Reproduce the focused checks with:

```sh
zig build test-lib -Dtest-filter=gRPC --summary all
zig build test-lib -Doptimize=ReleaseSafe -Dtest-filter=gRPC --summary all
zig build interop-grpc-hedging-commit --summary all
zig build interop-grpc-hedging-commit -Doptimize=ReleaseSafe --summary all
zig build interop-mqtt-socks5 --summary all
zig build test -j1 --summary all
```

Earlier repository logs remain available to explain the validation path:

- `repository.Debug.initial-offline-race.log`: the security reload fixture
  published before the persistent subscriber's DISCONNECT had retired its
  live delivery. The fixture now waits for orderly socket EOF before testing
  fresh offline QoS 1 delivery, retaining its exact `0x32` packet check.
- `repository.Debug.parallel-uncertain.log`: two QoS 2 fuzz cases failed and a
  session-expiry child exceeded the five-second process teardown guard during
  the parallel gate. The isolated QoS 2 gate, the same failed seed and all six
  expiry/restart scenarios subsequently passed. Final repository verification
  uses the serial command from CI.
- `repository.Debug.serial-socks-race.log`: all 6790 native tests passed; the
  SOCKS timeout peer rejected EOF before a complete greeting. Its whole-connect
  deadline can expire at that point. Only the delayed timeout peer now accepts
  incomplete EOF; complete malformed greetings and normal handshake checks
  remain strict. The focused socket-pair check exercised three incomplete EOF
  boundaries, three invalid greetings and a delayed valid method selection.
- `repository.Debug.serial-bridge-qos2-uncertain.log`: 6789/6790 native tests
  passed, with only the structured inbound bridge QoS 2 case failing without
  output. Its fixed recovery and epoch sequences passed isolated replay with
  the same runner seed (`0x4a337f0d`). The shared TCP/TLS harness now prints the
  input, operation index, phase, original error and peer error before error
  cleanup. Packet deadlines and PINGRESP delivery fences remain unchanged.
  An initial TLS diagnostic run also recorded a retained-probe Timeout;
  `mqtt-tls-bridge-qos2.Debug.diagnostics.initial-timeout.log` preserves it.
  After extending diagnostics to startup and individual probe operations,
  five fresh TCP runs and three fresh TLS runs passed all three tests each.
  Their distinct runner seeds prevent a cache hit from being counted as a
  repeated execution. The final repository run reuses successful test caches
  with the earlier `0x4a337f0d` runner seed. The intermittent QoS 2 timeout
  remains a follow-up investigation; these replays do not establish its cause.

These MQTT corrections change interoperability fixture synchronization and
timeout expectations. The broad five-protocol goal remains active.
