# H3 response deadline observer socket ownership

Base revision: `f5dcf94e42d7fd1a2f42fabd42c9265f478ce78b`.
This change keeps the protected response deadline fixture on the execution
and socket backend that created its client endpoint.

## Source-level ownership defect

`protectedResponseDeadlines` already runs through the actual-backend fixture
runner. It saves the endpoint's original I/O before installing a Native clock
observer, but the observer omitted `delegate_io`. That default selects its
new embedded Threaded backend for callbacks and sends. The socket may belong
to the application backend, including IOCP on Windows.

[The fixture](../../../../src/http3/runtime/client/tests/deadline.zig) now passes
the saved endpoint I/O as its delegate. The shared Native observer forwards
all callback userdata and tokens to that owner, keeps the synthetic awake
clock, translates remaining deadline budgets and restores the original I/O
before observer destruction.

Other inspected Native observers create their sockets through their own
embedded Threaded backend; their absent delegate has a different ownership
contract. Those configurations were not changed.

## Contract verification and causal boundary

The original selected response fixture passes 66 native scoped tests and
matching Windows compilation in eight steps. Its POSIX Threaded and application
backend cases retain the one-send timeout, SETTINGS progress, zero request
stream/lifecycle/QPACK mutation, aggregate and receive-next retry, exact body
contents, streaming completion and peer cancellation/join assertions.

The current Windows protocol fixture command still reports expected `Timeout`
but actual `Unexpected`. Its old bounded context does not name the triggering
test after the long transport trace. The saved-socket ownership defect is
directly inspected and repaired; native attribution of those two failures
remains pending the delivered revision's evidence.

The native fixture command does not use `--verbose`, so its log lacks cache
executable markers. Immediate failure context now keeps the last visible test
in command output when no active artifact is known. Known artifacts retain
their own invocation's context, while delayed signal summaries continue to
resolve their failed executable rather than using a later test. The diagnostic
scope passes 24 cases, including non-verbose long traces and a known artifact
that fails before printing a new test name.

[validation.json](validation.json) records source hashes, exact commands and
logs. Current native/complete CI acceptance and fixed-workload performance
remain separate; budgets, pins and protocol assertions are preserved.
