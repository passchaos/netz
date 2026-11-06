# A6 hedging commitment

SharedChannel commits a hedged unary RPC when an attempt receives valid ordinary
initial response metadata. The selected attempt continues under the original
deadline, queued losing jobs are removed, active losing streams receive CANCEL,
and pending hedge timers stop. Its eventual status remains the RPC result even
when that status is configured nonfatal. A6/grpc-core failure accounting still
debits a configured nonfatal error; commitment prevents another attempt.

Informational HTTP/2 heads do not select a hedge winner. They remain conservative
processing evidence for transparent-replay safety. Trailers-only nonfatal errors
also remain eligible to accelerate another hedge. Fatal statuses and local policy
drops select a winner without waiting for another attempt.

One reference-counted control object owns the winning index, copied nonfatal
membership, commitment event and call-wide transparent replay budget. Each
physical Job retains it until retirement, so cancellation or an interrupted
caller cannot leave a queued/active Job pointing into a destroyed scheduler
stack. Transparent REFUSED_STREAM and peer-unprocessed GOAWAY share the one
budget across every logical hedge. Replays keep their logical attempt index and
the original deadline, and still repick a resolver endpoint.

The [A6 commitment and buffering requirements](https://github.com/grpc/proposal/blob/master/A6-client-retries.md#when-retries-are-valid)
are implemented at the response metadata event, rather than at completed unary
response delivery. The local grpc-core reference records configured failure
throttling before its commitment check. Java's hedging implementation commits at
initial metadata too, but has different throttle accounting after commitment;
netz follows the A6/grpc-core failure debit.

`zig build interop-grpc-hedging-commit --summary all` uses independent Node
HTTP/2 peers and the production zio-backed SharedChannel. Six scenarios verify:

- A peer withholds the winner's DATA/trailers until the loser observes exact
  RST_STREAM(CANCEL), proving cancellation precedes winner completion.
- A held ordinary response head suppresses later requests.
- A committed UNAVAILABLE remains the result and consumes one failure token.
- Trailers-only UNAVAILABLE still accelerates the next hedge.
- Informational 103 does not prevent another attempt from committing.
- A refused attempt consumes the single call-wide transparent budget; a refusal
  on the next logical hedge cannot silently create a fourth physical request.

The complete repository gate includes this runner. Its transcript checks exact
backend counts, request metadata, attempt indices, reset codes and ordered
header/CANCEL/body events. Native lifecycle tests additionally check queued
ownership, pending fault delay cancellation and the post-commit deadline.

Current evidence is recorded in
`docs/evidence/grpc_hedging_commit/2026-11-06.json`.
