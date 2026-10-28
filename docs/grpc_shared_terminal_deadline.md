# Shared gRPC final DATA and terminal deadline

The shared endpoint owner now commits a terminal response in the same turn as
the final encoded DATA enters the per-call ring. A subsequent RPC deadline
cannot replace that already parsed result with Timeout while the application
has paused response consumption.

A response ending in HTTP/2 DATA can leave both a DATA event and an owned
terminal in `ClientDuplex.pending_terminal`. The former owner copied DATA and
returned to its loop. Its next turn first checked the RPC deadline, so a
deadline crossing that scheduling boundary retired the call with Timeout and
lost the committed status. A real TCP regression drives the production owner
one turn at a time to hold exactly that boundary; the original implementation
fails with `expected null, found error.Timeout`.

After copying the final bytes, the owner drains only the already staged
terminal, using the existing raw receive API. This step performs no network
read and needs no credit write on the completed stream. One completion helper
releases transport ownership and publishes terminal state plus retirement
under the call lock. Readers still observe initial metadata and all queued
messages before the terminal.

Consumer decoding remains strict. The matching truncated-payload test retains
BufferTooShort after the RPC deadline; an already parsed transport terminal
does not make an incomplete gRPC envelope valid. Both regressions then complete
a second RPC on the same HTTP/2 connection with a one-stream peer limit,
proving that the completed call released its stream slot. Pending operations
keep their original deadline and cancellation behavior.

Run the targeted checks with:

```sh
zig build test-lib -Dtest-filter='gRPC shared' -Dtest-filter='gRPC response fallback' -Dtest-filter='gRPC bounded message' --summary all
zig build interop-grpc-response -Doptimize=ReleaseFast --summary all
```

The independent HTTP/2 response-policy gate now additionally opens one shared
native connection. It checks a DATA FIN response without grpc-status and then
a normal trailers-terminated response on that same connection. Each call has
a 500-ms RPC deadline and waits 550 ms after request output before consuming
the buffered message/status. The native client verifies that its deadline has
actually passed. The raw Node peer requires exact per-case request counts,
one stream at a time, and three persistent connections overall: the official
grpc-js client, the direct native client, and the shared native client.

Missing grpc-status keeps the existing native UNKNOWN fallback. The pinned
grpc-js client's INTERNAL outcome for that malformed response remains a
separate recorded oracle result; this change does not merge those expectations.
The existing transparent refusal, HTTP fallback, Host/authority, early-upload,
and NO_ERROR-after-END_STREAM checks remain in the gate. Verification passes
160 focused checks, 129 checks in the single-stream-slot regression filter,
and the ReleaseFast independent matrix with 26 scenarios and 74 native RPCs,
including two shared RPCs consumed after their deadline.

[The before/after and independent-peer evidence](evidence/grpc_shared/2026-10-28-terminal-deadline.json)
retains the original Timeout failure, exact verification scopes, pinned SDK
outcomes and source/executable fingerprints.
