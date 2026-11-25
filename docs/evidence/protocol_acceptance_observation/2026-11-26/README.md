# Preserve protocol acceptance and observe CA precondition failure

Run 45698097878 failed native Windows reconnect verification because the
otherwise successful test logged `[zio] (err): WSASend failed: .ECONNABORTED`.
The complete gate also observed old MQTT Broken pipe before SIGHUP at age
224 ms with the broker still alive and no queued output, then ended with exit
137 at its existing 28-minute limit. Neither root cause is closed by this patch.

The native protocol step again executes the original combined command.
Isolated cases diagnose only its failure and cannot replace the original
nonzero status. Three control-flow checks cover success, original failure with
successful diagnostics, and differing failures in both paths. The exact main
shell block passes syntax validation. HTTP1 pull-reader coverage runs in the
existing native resolver step before the reconnect case.

CA precondition diagnostics now record old-socket status after each prior TLS
probe. Nonblocking TCP peek does not send extra PING, consume pending bytes,
change the socket mode or close the owned descriptor. The bounded observations
are emitted only when the pre-SIGHUP MQTT ping fails. Sixteen broker helper
checks and nine annotation checks passed. These are diagnostics and local
verification, not proof of native Linux/Windows or complete acceptance.

Dependency pins and the existing CI budgets remain unchanged.
