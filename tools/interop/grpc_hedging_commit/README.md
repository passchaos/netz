# A6 hedging commitment interoperability

Run `zig build interop-grpc-hedging-commit --summary all`, optionally with
`-- --output /tmp/grpc-hedging-commit.json`. The runner requires Node.js and
Python 3 and uses only their standard libraries. It installs no dependencies.
To run an existing native executable directly:

```sh
python3 tools/interop/grpc_hedging_commit/run.py /absolute/path/to/netz-grpc-hedging-commit-client --output /tmp/grpc-hedging-commit.json
```

The native client uses `netz.runtime.Backend` and the production
`netz.grpc.SharedChannel`. Each case creates a fresh round-robin channel with
the independent HTTP/2 peers A and B, waits for both endpoint owners to become
READY, and starts one hedged unary RPC with a five-second deadline. Requests
carry preserved application metadata, a framed message naming the case,
`grpc-timeout`, and the logical attempt index.

| Case | A/B requests | Result | Body | Final milli-tokens |
| --- | --- | --- | --- | --- |
| `head_cancels_loser` | 1/1 | OK | `b-committed` | 4000 |
| `head_suppresses_later` | 1/0 | OK | `a-held` | 4000 |
| `head_unavailable_wins` | 1/0 | UNAVAILABLE | absent | 3000 |
| `trailers_only_accelerates` | 1/1 | OK | `b-accelerated` | 4000 |
| `informational_does_not_commit` | 1/1 | OK | `b-informational` | 4000 |
| `call_wide_transparent_budget` | 2/1 | UNAVAILABLE, REFUSED_STREAM | absent | 2000 |

In the first case, A holds its response and B sends ordinary initial HEADERS.
B sends no DATA or trailers until A's independent Node HTTP/2 stream reports
the exact client `RST_STREAM(CANCEL)` code 8. The transcript must order B's head
before A's cancellation and A's cancellation before B's body and trailers.
The informational case repeats that gate after A sends status 103, proving
that an informational head permits B to start and commit.

For the two immediate-head cases, A sends ordinary initial HEADERS and waits
350 ms before completing, beyond the native 75 ms hedge delay. B must receive
zero requests. An eventual UNAVAILABLE status remains A's committed result
even though the policy lists UNAVAILABLE as nonfatal. A6/grpc-core failure
accounting still consumes one token without launching another attempt.
A trailers-only UNAVAILABLE instead accelerates B; its configured
three-second hedge delay and exact native launch counters distinguish that
acceleration from an ordinary delayed hedge.

The transparent-budget case follows round-robin selection across physical
requests: A is refused at logical index 0, its transparent replay selects B
and returns trailers-only UNAVAILABLE with the same omitted attempt index,
then logical hedge 1 selects A and is refused. There must be no fourth request
on B. The peer would answer that unexpected replay with OK, exposing a budget
incorrectly reset for each hedge. The exact metadata sequence is A/null,
B/null, A/`1`; both physical refusals use reset code 7. This case preserves
normal resolver selection without imposing endpoint affinity on a replay.

Reports include observed backend counts, all request metadata, exact stream
reset codes, response statuses and bodies, ordered events, and native hedging
and throttle counters. A native `reset_code` of -1 means the result contains
no peer reset; completed Node streams have reset code 0. Source and executable
SHA-256 values bind the report to the checked files, and the runner rejects
changes to those files during execution. Cancellation waits are event driven
and bounded at three seconds; the complete native subprocess is bounded at
35 seconds and the outer runner at 45 seconds. The fixture timers implement
intentional response delays and deadlines without sleep polling.
