# Complete HTTP/3 requests under flow control

`HandshakeClient.sendRequest`, `request` and their timeout/deadline variants
send complete borrowed requests through the same transport credit and DATA
pacing machinery as streaming uploads. The caller's deadline covers SETTINGS,
stream admission, the initial HEADERS, DATA, trailing HEADERS and response
reception. Receiving an ACK or an increased flow limit never renews it.

The complete request is validated before SETTINGS or stream reservation. This
includes method/authority semantics, Content-Length, trailer legality and both
peer field-section limits. `Request.writeCompleteHeadDynamic` shares those
checks with the complete dynamic writer while encoding only the initial
HEADERS. The native runtime borrows application DATA and retains one encoded
field section at a time.

`runtime/client/complete_request.zig` owns the complete send, and
`runtime/send/field_section.zig` shares its exact-prefix HEADERS submission
with explicitly owned streaming request heads. Each fragment is bounded by
current stream and connection credit and exact protected-packet sizing. The
cursor advances after socket submission. Trailers use the body's final stream
offset and attach FIN only to their last fragment.

A failure before request bytes become visible retains a retryable reserved
stream. A failure after a partial head, body or trailer retires the request's
local ownership and attempts one scoped H3_REQUEST_CANCELLED reset. This
convenience API cannot hand a partially sent upload back to the caller. Cleanup
does not wait beyond the expired application budget; a refused cancellation
makes the connection ineligible for pool reuse. Existing sibling owners remain
independent, and the original send error remains visible.

## Reference and regression

The local Rust h3 reference at `1f3d5295833ad454343f25d55633fb6bee1027b2`
separately awaits initial HEADERS, `send_data`, trailing HEADERS and FIN in
`h3/src/client/connection.rs` and `h3/src/client/stream.rs`. QUIC provides the
flow-control wait for these operations.

The old native composite sender submitted all encoded request frames as one
packet batch. A 9,216-byte complete POST against pinned quic-go v0.59.0's
2,048-byte stream window fails with `FlowControlBlocked` in
`sendPreparedConnectionMessageUntil`. The same independent RFC 9530 gate now
checks that exact upload size in both roles and QUIC versions, verifies digest
headers and trailers, and requires one reused connection per transcript.
The original Appendix D digest vector remains a separate fixed input.

Nearby regression tests additionally transfer 5,000-byte initial and trailing
field values plus a 28,672-byte body through fixed 2-KiB stream and 8-KiB
connection windows. Both bounded and unbounded complete calls must decode the
exact request and response, retire outbound storage and admit a later request.
Separate no-reader cases exhaust credit in the head, body and trailer phases;
each must return Timeout, reset only its own stream and complete a sibling
response on the same connection. Invalid complete bodies and trailers must
consume neither packets nor stream IDs, and empty-body trailers must carry FIN.

## Verification

```sh
zig build test-lib -Dtest-filter='HTTP/3' -Dtest-filter='HTTP3' --summary all
zig build test-lib -Dtest-filter='HTTP/3' -Dtest-filter='HTTP3' -Doptimize=ReleaseFast --summary all
zig build test-package --summary all
zig build interop-http-digest-quic-go --summary all
zig build interop-http-digest-quic-go -Doptimize=ReleaseFast --summary all
```

The HTTP/3 regression suite passes 991/991 in both Debug and ReleaseFast;
public-package checks pass 26/26. Each independent interop mode completes all
36 requests across the four role/version transcripts.

The before/after transcripts, source hashes and command results are stored in
`docs/evidence/http3_complete_requests/2026-11-01.json`. These establish the
complete-request flow-control and ownership behavior; cross-stack throughput
remains a separate measurement.
