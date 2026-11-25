# Retire terminal transport reads before Session cleanup output

The real TLS reconnect regression observed one write after the old stream had
returned EOF/reset. The parent call chain was Session transport receive ->
Session.fail -> duplex reset -> HTTP2 reset frame -> timed TLS write. Deferring
abortive cleanup until the worker finally block left this earlier reset intact.

Known connection-terminal read failures now retire output before Session.fail
can send a cancellation reset. Capsule/message failures retain stream-local
reset behavior. Terminal worker errors also retire transport before Session
and TLS destructor output. No dependency pin or logging suppression is used.

The lightweight observer records actual native stream EOF/reset and rejects
later writes while the old generation retires, then stops tracking before
socket handle reuse. Graceful and abortive first-generation closure, future
Session reconnect, ordinary duplex/tunnel exchange, encoded deadline writes
and malformed capsule handling are covered by the integrated scope. Main-tree
Debug passed 135 tests and scoped Windows compilation passed. Windows native
execution remains for CI; compile-only evidence is not runtime acceptance.

Stack tracing used during diagnosis perturbed scheduling and is removed from
the regression. The passing evidence uses only atomic counters and preserves
the original failure/error behavior rather than relying on trace-time expiry.
