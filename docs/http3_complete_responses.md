# Complete native HTTP/3 responses

`HandshakeServerSession.sendResponse`, its timeout/deadline forms, the paced
variants and complete responses with informational HEADERS now share one send
owner. It validates the complete final response and all informational sections
before sending SETTINGS or response bytes. Content-Length, status/method body
rules, trailer legality and the peer's field-section limits use the same checks
as the complete dynamic serializer.

Initial informational and final HEADERS advance through the transport's current
stream and connection credit and exact protected-packet size. DATA stays borrowed
and uses the existing paced writer. Complete response trailers share the same
field-section cursor with complete client requests; FIN is committed only after
the last trailing HEADERS fragment. The original awake-clock deadline covers
the whole operation and is never renewed by ACK or credit progress.

Field-section fragments also retain the packetizer's opportunistic cumulative
ACK policy. When the packet/frame budget permits, the ACK commits with the
application fragment; otherwise it remains owned by the delayed-ACK timer.
This preserves prompt request-FIN acknowledgement and completed-stream
reclamation, including HEADERS-only final responses.

Before any response prefix reaches the socket, failure rolls back its QPACK
preparation and leaves the request available for retry. Once a prefix is visible,
the complete API retires that request's HTTP ownership and attempts a scoped
H3_INTERNAL_ERROR cancellation. It preserves the original send error and the
other request owners on the connection.

Cancellation does not wait past the application budget. A refused cancellation
uses storage reserved before response submission, then retries at a later
authenticated packet or complete-response send. Outstanding cancellations block
final shutdown and drain completion. The session owns and releases this storage
at teardown; it does not create a background worker or a second socket reader.

`src/http3/runtime/server/complete_response.zig` owns the complete response path,
and `src/http3/runtime/send/complete_trailers.zig` shares trailer submission
between native client and server owners. Explicit streaming and dispatcher
one-packet APIs retain their separate contracts.

## Aggregate server push timeout scoping

The deadline-bounded aggregate push APIs preflight both the parent and pushed
responses and reserve parent cancellation storage before either head becomes
visible. A timeout after the heads are visible now resets only the push stream
or the parent request that failed, preserves the connection and any completed
sibling response, and returns the original error. A peer push cancellation
still completes the parent response before returning `RequestCancelled`.
`tryResetStream` retires the server-initiated push send side without requiring
a receive half that HTTP/3 never opens. The non-paced one-packet push API and
the protected server retain their separate contracts.

A regression blocks the push body on flow control, advances the server's awake
clock past the original deadline, and requires both the push and parent
streams to reset while the connection stays open and a later request on the
same connection completes. The same regression also covers a bodyless parent:
its HEAD/FIN is already complete, so only the push resets and the parent
response survives. Evidence is recorded in
`docs/evidence/http3_push_timeout/2026-11-01.json`.

## Evidence

The local Rust h3 server reference at
`1f3d5295833ad454343f25d55633fb6bee1027b2` separately awaits response HEADERS,
DATA and trailers in `h3/src/server/stream.rs` and provides stream-scoped stop
operations. The native af48cccb response path instead closed the connection
after an aggregate body timeout. A production QUIC regression records that
failure before this change.

Native regressions check ordinary, unbounded paced and bounded informational
responses with 5,000-byte field values and a 28,672-byte body across fixed 2-KiB
stream and 8-KiB connection windows. They check the exact 103 section, final
HEADERS, body, trailers, FIN and later request admission. Independent timeout
cases block initial HEADERS, DATA and trailing HEADERS; each must cancel only
its own stream and complete a sibling response on the same connection. A
socket-write refusal additionally leaves a bounded pending cancellation which
must retire after packet progress or before a sibling response. Invalid complete
messages consume no response bytes and retain the owner for a valid retry.

The pinned quic-go v0.59.0 digest gate additionally carries 5,000-byte 103,
final-header and trailer values through the `/trailer` exchange. Both native
and Go clients check every value, complete digest validation and later
same-connection requests, in both endpoint roles and QUIC v1/v2. The existing
9-KiB complete upload, sliced bodies, corruption and representation-digest
checks remain in the transcript.

Detailed command results, source hashes, counterexample and independent peer
transcripts are stored in `docs/evidence/http3_complete_responses/2026-11-01.json`.
