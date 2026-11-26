# Finite HTTP/1 and WebSocket worker lifetime

Finite service batches now admit handlers with `Group.concurrent`. Exhausted
concurrent capacity returns `ConcurrencyUnavailable` before that handler runs,
and the just-accepted connection remains owned by the caller's error cleanup.
Already admitted workers are cancelled and joined on a later accept, admission
or caller-cancellation failure before their borrowed result array is freed.
Normal completion still returns the per-connection errors to the caller.

The shared probe keeps native callback userdata intact and observes real TCP
reads and per-socket closes. Eight scenarios cover HTTP/1 and WebSocket with
zero async capacity, no concurrent capacity, partial worker admission and caller
cancellation while both readers are blocked. Initial refusal starts no read;
every started reader finishes and each accepted socket closes exactly once.
Tests register through each runtime's formal test entrypoint.

[Validation](validation.json) records 26 HTTP/1 and 54 WebSocket native tests,
including ordinary TCP/TLS service, and Windows compilation of the same scopes.
Pinned native CI at the delivered revision remains required.
