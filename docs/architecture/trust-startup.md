# Trust loading during connection startup

System-root loading is part of connection startup. TCP TLS 1.2/1.3, QUIC,
the unified HTTP H3 client, H3 WebSocket and WebTransport URI constructors use
the connection's existing awake-clock deadline while loading native roots.
The TLS `handshake_timeout` starts before verified-client root loading and is
capped by an earlier caller deadline. The next handshake phase receives the
same timestamp.

`src/tls/trust_loading.zig` owns bounded system-root loading. It validates the
deadline and cancellation at admission, admits the timeout watcher before the
load, and joins both tasks on every exit. Concurrency admission failure returns
`ConcurrencyUnavailable` before loading begins. The result queue has two
entries and retains every successful store until the caller accepts it or
cleanup destroys it.

The worker checks the original deadline before loading and after either a
success or a failure. The receiving owner checks again before transferring the
store. An operation that finishes late cannot turn a timeout into a newly
loaded store or an unrelated loading error. Cancellation of the caller joins
the loader before caller-owned arguments can go out of scope.

TCP TLS retains native trust-loading errors. The QUIC adapter under
`src/quic/client_trust/` preserves `Canceled`, `OutOfMemory` and
`ConcurrencyUnavailable`, and maps other source failures to
`NativeTrustStoreUnavailable`. Its policy application commits inherited options
and the output store only after successful loading. QUIC's low-level handshake
reports an expired handshake budget as `HandshakeTimeout`.

`src/quic/handshake/client_authentication.zig` owns the low-level handshake's
optional system store, bundle verifier and platform verifier. It is initialized at its final
address, because verifier contexts borrow those fields, and destroyed after the
synchronous handshake. The bundle verifier itself has a borrowed callback
context and must remain in the owner's stable storage. Explicit verifiers and caller-owned stores retain their
existing precedence; the low-level QUIC `.system` default still requires an
explicit store or environment to enable certificate verification.

The deadline race surrounds system-root loading, including native file reads.
Bundled-root construction and platform-verifier initialization check the budget
before and after setup. Their synchronous CPU/native work must finish before
its owned state can be destroyed. A caller-owned TCP CA bundle retains its
existing shared-lock lifetime through certificate verification.

See [the startup evidence](../evidence/trust_startup/2026-11-25/README.md) for
the original cancellation failures, deadline admission checks, late-result
reclamation, and authenticated trust-policy validation.
