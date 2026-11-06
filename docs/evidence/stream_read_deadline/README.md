# Stream deadline and CDS/LRS validation

`2026-11-07.json` is the aggregate report. Per-command results and logs are in
`2026-11-07/gates.json`. The original reader counterexample intentionally
returns `FAIL (Timeout)` with a future absolute deadline; the retained-batch
reader passes the same scenario.

The temporary standalone unit root used during parallel implementation was
removed after the regular library gate passed. Its exact contents are recorded
in the aggregate report. The permanent focused checks are:

```sh
zig build test-lib -Dtest-filter=LRS -Dtest-filter='stream timed reader' --summary all
zig build test-lib -Doptimize=ReleaseSafe -Dtest-filter=LRS -Dtest-filter='stream timed reader' --summary all
zig build test-lib -Dtest-filter='read interruption' -Dtest-filter='stream timed' --summary all
zig build interop-grpc-lrs --summary all
zig build interop-grpc-lrs -Doptimize=ReleaseSafe --summary all
zig build interop-grpc-hedging-commit --summary all
zig build interop-grpc-hedging-commit -Doptimize=ReleaseSafe --summary all
zig build test -j1 --seed 0x4a337f0d --summary all
```

The official Envoy LRS transcripts live under
`docs/evidence/grpc_lrs_registration/`. They validate native request decoding
from official-schema serialized bytes and native encoding through the official
peer, including utilization metrics, named metrics and distinct EDS identities.
The current A6 transcripts live under `docs/evidence/grpc_hedging_commit/`.

Early LRS integration logs preserve the naming, tuple validation, delta change
detection and metric decoding failures that the focused gate exposed. The final
gate records describe the corrected implementation. Original/fresh MQTT QoS 2
replays pass; the early-timeout correction is proven independently of the
unconfirmed cause of the earlier intermittent retained-probe Timeout.

`repository.Debug.initial-shared-properties-shutdown.log` records a complete
6802/6802 native pass with only the configured broker process-exit fixture
failing its five-second wait. The isolated reproduction in
`mqtt-shared-properties.Debug.ext4-fsync-timeout.log` captured the main thread
waiting in `io_cqring_wait` and its I/O worker in `jbd2_log_wait_commit` after
the wire exchanges completed. Final snapshot file/directory fsync can exceed
that connection-teardown guard. Snapshot-producing fixtures now use a separate
bounded 30-second persistence completion allowance, while ordinary configured
broker teardown retains its five-second default. Child output is continuously
drained and a timeout includes the case/generation, elapsed time and available
thread wait channels. Twenty actual QoS1/QoS2 three-generation replays pass.
