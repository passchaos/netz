# H2 actual cancellation fixture teardown

Native Windows run [45849067907](https://github.com/passchaos/netz/actions/runs/45849067907/job/140010311279)
on `4b1924f4` reports all 44 selected H2 cases as passed, then exits 1 with
logged `ESHUTDOWN`/`PIPE_DISCONNECTED` errors. In the actual cancellation
fixture, an unfinished stream's deferred `deinit` sends RST_STREAM after the
test has deliberately closed the TCP send half. Catching that reset error
does not remove the backend's error log or make the test process successful.

Skipped and expired commands now retire their protocol stream before the TCP
half-close, with a one-second reset timeout. The peer checks one cleanup
RST_STREAM for those outcomes and zero for a fully completed response. The
existing exact body, HEADERS/FIN, caller cancellation, command release and
response-finished assertions remain. Production code is unchanged.

[validation.json](validation.json) records the local 36-case native pass,
Windows cross-compilation and source/log hashes. Windows native execution of
the correction remains pending. The previous run's five-minute Windows
protocol-step timeout is a separate open finding; neither that budget nor
any existing CI command or dependency pin changes here.

The complete run's new required-flow fixture GP and the Linux/client-CA reload
failure are also separate follow-ups. Historical evidence remains unchanged,
and this selected test result does not close the continuous HTTP-family goal.
