# GOAWAY recovery and response commitment

Ordinary unary retry and SharedChannel hedging share one transparent transport
replay budget. A peer GOAWAY whose last accepted stream ID is below the
request's stream permits replay before any response head. REFUSED_STREAM uses
the same budget. A replay preserves the request body, metadata and logical
attempt index, consumes no configured attempt or throttle token, and advertises
the original absolute deadline's remaining `grpc-timeout`.

The shared hedging driver handles GOAWAY inside the attempt task, before its
result reaches the scheduler. A replay of hedge index 1 therefore still sends
`grpc-previous-rpc-attempts: 1`. A subsequent REFUSED_STREAM can consume a
configured non-fatal hedge, which debits throttling and advances that index.
A second GOAWAY or explicit transparent-retry opt-out remains visible to the
caller. Streams at or below the peer's accepted boundary continue normally.

`ConnectionGoAway` can also arise when the local HTTP/2 endpoint sends a
GOAWAY for flow-control or DATA/reset-budget violations. This supplies no proof
about whether the peer processed the request. Aggregate and shared attempt
owners require an actual peer unprocessed-stream boundary before exposing a
replayable error; local protocol failures return `InvalidFrame`. A locally
unusable connection cannot authorize replay even after a prior peer GOAWAY.

A final or informational response head proves that the stream was processed.
A later GOAWAY below that stream contradicts that evidence and returns
`InvalidFrame`, preventing transparent or configured hedging replay.
The shared worker checks its retained head evidence before destroying the
failed duplex response. HTTP/2 complete-request submission and aggregate
response reception check GOAWAY during both ordinary input and flow-blocked
uploads, including the initial send before a pending response owner exists.
Aggregate retirement releases per-stream flow windows on both successful and
failed completion, including accepted and unprocessed GOAWAY streams.
Discarded body-credit return and peer GOAWAY state remain owned by the transport.

The live TCP regressions in
`src/grpc/channel/shared/hedging/recovery_tests.zig` cover original and later
hedge replay, exact body/metadata/previous-attempt headers, decreasing timeout,
token accounting, repeated and mixed GOAWAY/refusal, opt-out, timeout cleanup,
accepted streams, local connection/reset-limit failures and contradictory
final/informational heads. They also run
ordinary SharedChannel unary recovery without hedging. Aggregate HTTP/2
regressions independently cover ordinary gRPC Channel calls and flow-blocked
uploads. The tests use real production HTTP/2 client and server transports.

Verification is recorded in
`docs/evidence/grpc_goaway_recovery/2026-11-06.json`.
The Debug HTTP/2 and gRPC policy/recovery suite passes 1,142/1,142, focused
ReleaseSafe checks pass 332/332, and the complete repository gate passes all
187 steps and 6,782/6,782 tests without skips. The independent LDS gate counts
38 backend RPCs while checking canonical RBAC route policy forms. The shared
SOCKS interop Go detector additionally discovers supported cached GOPATH SDKs;
seven discovery regressions and both default HTTP/3 SOCKS gates pass.
