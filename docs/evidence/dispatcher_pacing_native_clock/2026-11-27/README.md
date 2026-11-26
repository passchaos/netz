# Dispatcher pacing with a native frozen clock

Complete run 45863309674 aborts at 4830/7490,
`WebTransport endpoint control and datagram sends do not wait for pacing`.
An immutable worktree at `19a8694f` reproduces the same ownership failure on
macOS: case 47/111 aborts with a Bus error in Threaded task allocation.
`trySendDatagramWithDeadline` enters `progress_deadline.before`, which admits
an absolute-deadline watcher before the operation. The fixture passes a clock
observer's userdata to inherited Threaded callbacks.

All 11 fixtures sharing that observer now use the complete native clock probe.
Backend callbacks receive their actual delegate and owner tokens; awake time
is atomic, and manual clock changes wake an entered deadline wait. Every
case runs on POSIX Threaded with zero async capacity and the application
backend with one executor. Windows datagram cases use the supported
application backend.

The zero-wait contract concerns pacing duration sleeps. The bounded send API
also owns a real absolute-deadline watcher, whose wait must be cancellable and
joined. The old sleep override fabricated `Canceled`, conflating these two
operations. The fixtures now check zero pacing duration sleeps while allowing
the real watcher to retain the original caller budget. No socket budget or
protocol assertion is disabled to obtain a pass.

All 24 original dispatcher test names remain, and the 410 protocol assertion
statements compare identically after normalizing atomic counter reads and the
explicit pacing-sleep counter. They include unchanged PacingLimited results,
no packet-number or state commit on refusal, timer kinds and resumption,
DATAGRAM committed prefixes, body offsets, stream credit, CLOSE and cleanup
idempotence. The large control/DATAGRAM fixture is extracted behind the
original formal test import.

[validation.json](validation.json) records the failing baseline, current
source hashes, 126 scoped native passes and Windows 8/8 compilation.
Delivered Linux/Windows execution and complete acceptance remain separate.
The continuous HTTP-family goal still includes CA reload, the Windows native
protocol budget, remaining I/O observers, fairness and workload performance.
