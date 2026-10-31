# HTTP integrity fields

`http.digest` implements RFC 9530 Content-Digest, Repr-Digest,
Want-Content-Digest and Want-Repr-Digest. SHA-256 and SHA-512 are the two
currently Active algorithms in IANA's HTTP digest registry. Unsupported and
Deprecated algorithms retain valid Dictionary syntax but cannot satisfy an
enabled integrity check.

All parsing, hashing, comparison and generation use fixed storage. Parsing
bounds matching field bytes across headers/trailers to 16 KiB by default and counts at
most 64 members, including duplicates and unsupported algorithms. Callers can
lower either bound through ParseOptions. No digest operation takes an allocator.
Known digest bytes are copied into fixed arrays, so parsed results outlive the
input field strings. Both padded and unpadded valid Byte Sequences are accepted.

RFC 8941 syntax is checked over the complete field collection. Repeated field
lines and trailers form one Dictionary; the last occurrence of a key replaces
its previous value. RFC 9530 Byte Sequence or integer/weight constraints are
applied to that final Dictionary, so a replaced semantic value cannot change
the result. Malformed Structured Field syntax anywhere still fails. Unknown
parameters are validated and ignored; RFC 9651-only parameter types are
rejected for these RFC 8941 fields.

HTTP/1.1, HTTP/2 and HTTP/3 responses and the unified owning/redirected response
expose explicit verification:

```zig
const result = try response.verifyContentDigest(.{});
```

Default Policy requires an Active supported digest and verifies every supplied,
enabled algorithm. A good SHA-512 value cannot hide a mismatching SHA-256 value.
`required = false` reports `absent` or `unsupported` without claiming a match;
an invalid field or enabled mismatching digest remains an error. Algorithm
flags allow applications to require their own SHA-256/SHA-512 policy. Digest
comparisons use the standard library's constant-time implementation.

Content-Digest hashes the actual message content: after HTTP/1 transfer coding
or HTTP/2/3 frame removal, while gzip/br/zstd Content-Encoding stays intact.
Call `verifyContentDigest` on the original response before decoding its content.
For HEAD, Content-Digest covers the empty message content; Repr-Digest can
describe an entire selected representation. For 206, Content-Digest covers the
range or multipart content, while Repr-Digest describes the entire selected
representation. `digest.verify(.representation, complete_data, headers,
trailers, policy)` therefore requires explicit complete representation bytes.

Generation uses the same fixed-storage value model:

```zig
const values = try http.digest.compute(content, .{});
var field_storage: [http.digest.max_value_bytes]u8 = undefined;
const field_value = try values.writeInto(&field_storage);
// Send field_value as Content-Digest or Repr-Digest for its computed data.
```

Caller-buffer writers validate capacity before changing any output byte. Two
digests occupy at most 154 bytes. Preferences use integer weights 0 through 10;
zero and unlisted algorithms are not selected by `Preferences.select`, and equal
positive weights prefer SHA-512. Preferences are advisory under RFC 9530.

Streaming receivers can hash body callbacks before trailers arrive:

```zig
var hasher = try http.DigestHasher.init(.{ .max_content_bytes = body_limit });
// For every content callback:
try hasher.update(content_chunk);
// After the complete content and trailer section:
const computed = try hasher.finish();
const field = try http.digest.parseMessage(.content,
    streamed.headers, streamed.trailers, .{});
const result = try http.digest.verifyComputed(field, computed, .{});
```

The byte quota rejects an update before changing either hash or byte count.
Finish is one-shot; a later update/finish fails with InvalidDigestState.
Authentication and metadata protection remain responsibilities of TLS or
message-signature policy.

Validation uses RFC 9530 Appendix D fixed vectors, exact quota/capacity edges,
duplicate/schema ordering, malformed and unsupported members, hash lifetime,
HEAD/representation distinction, HTTP/1 chunked trailers and HTTP/3 QPACK/DATA
images. `interop-http-digest-python` uses independent hashlib hashing and pinned
http-sfv 0.9.9 parsing through real TLS 1.3 HTTP/1.1 and HTTP/2 connections.
Each connection sends eight requests covering compressed content, trailers,
four typed failures, streaming hashing and independently checked generated
digests/preferences. Successful later requests prove connection reuse after
verification failures. Evidence is recorded in
`docs/evidence/http_digest/2026-10-31.json`.

The focused HTTP digest tests pass 150/150 in Debug and ReleaseFast. Both
independent HTTPS peer runs verify all 16 requests.


## Independent HTTP/3 network verification

`zig build interop-http-digest-quic-go` builds a repository-pinned quic-go
0.59.0 peer offline from go.mod/go.sum and runs both endpoint roles with QUIC
v1 and v2. Every pairing uses a freshly generated CA-signed P-256 identity,
certificate/hostname verification, TLS 1.3 and h3 ALPN. One connection carries
eight requests: gzip content, digest trailers, a conflicting digest, HEAD,
206, streaming content, a digest-bearing POST with request trailers, and a
final checked response. Go's SHA/gzip implementations independently validate
Netz's generated bytes; Netz validates the reverse direction. Both streaming
receivers hash bounded chunks before the digest trailers arrive.

The 2-KiB stream and 8-KiB connection windows remain fixed while 10-KiB bodies
advance. This gate reproduced an old paced-response failure: a logical DATA
chunk crossed several QUIC packets, then exhausted stream credit after a
visible prefix and triggered the atomic packetizer's failure cleanup. Blocking
request/response and pushed body helpers now submit DATA contributions sized
against current flow, congestion and path budgets. Each successful contribution
is a complete HTTP/3 DATA frame, preserving an exact application prefix when
a later deadline expires. Request/response routing and push cancellation keep
driving their owning receive loop.

The complete matrix checks 32 requests and same-connection reuse after the
conflicting digest. A regression additionally limits flow credit to 128 bytes,
expires the deadline after one socket send and requires exactly 125 content
bytes plus the three-byte DATA header to remain committed without closing the
connection. Existing request, response, push and deadline regressions cover
the shared sender. Evidence is recorded in
`docs/evidence/http_digest_h3/2026-10-31.json`. The `interop-http-digest` aggregate
step runs the HTTP1/HTTP2 Python gate and the HTTP3 quic-go gate together.
Individual gates accept `--report`; use distinct files when retaining results.

The focused paced-body regression bundle passes 147/147 in Debug and
ReleaseFast. Each independent quic-go matrix verifies all 32 requests.


## Flow-aware sliced HTTP/3 bodies

The HTTP3 digest gate now includes a ninth `/sliced` request. Each endpoint
role uploads and downloads the 10-KiB payload through multiple borrowed slices,
including empty descriptors and boundaries inside a DATA contribution. QUIC
v1 exercises unbounded PartsPaced APIs; QUIC v2 exercises their absolute
deadline forms and requires an exact complete application-byte prefix. Digest
request trailers and response trailers independently verify every byte. The
expanded matrix verifies 36 requests, with a later checked response on each
same connection.

Request and response PartsPaced entry points now share `paced_body.writeParts`.
It computes current stream, connection, congestion and packet capacity before
staging descriptors, then commits the descriptor cursor only after the packet
reaches the socket. Backpressure receives peer progress before recomputing
capacity; it does not retry an oversized fixed contribution. One-frame
configuration fallbacks preserve the single-buffer sender's progress contract.
The existing deadline regression now covers contiguous and sliced inputs,
requiring the same exact 125-byte prefix under 128 bytes of flow credit.

The pinned quic-go 0.59 peer applies the v1 update label to QUIC v2 traffic
secrets. This longer matrix crosses its initial 100-packet update threshold,
so the fixture explicitly selects the existing quic_go_v0_59 update profile
for that peer/version pairing. The RFC9369 profile stays the library default.
The Go fixture also supplies a logger for its trailer-failure path. Scope and
verified results are in `docs/evidence/http3_paced_parts/2026-10-31.json`.

The sliced-body regression bundle passes 147/147 in Debug and ReleaseFast.
Each independent HTTP3 matrix verifies all 36 requests.
