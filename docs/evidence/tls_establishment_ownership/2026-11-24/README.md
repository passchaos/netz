# TLS1.3 established-result ownership — 2026-11-24

`versioned_client_connection.fromEstablished` removed the selected ALPN and
peer certificate chain from the handshake result before allocating the
retained ticket context's server identity. If that allocation failed, the
caller's `Established.deinit()` could no longer release those buffers. TLS1.2
already allocated its retained ticket before detaching metadata.

TLS1.3 now finishes the fallible ticket-context allocation before detaching
handshake-owned buffers or secrets. Connection allocation or ticket-context
OOM leaves the input result intact for caller cleanup. A successful conversion
still transfers ALPN, certificates, traffic keys/secrets, current sequence
numbers, exporter state and the configured ticket context to the connection.
The raw stream remains caller-owned on conversion failure.

The deterministic fixture in `stream/testing/established_ownership.zig` uses
valid AES128-GCM traffic keys/secrets and an allocated localhost certificate
and ALPN. It injects failure at connection allocation and the following ticket
identity allocation, then checks original buffer pointers, traffic secrets,
ownership flags and absence of a stream close. The baseline rescue restores
prematurely detached pointers so the assertion can fail without leaking its
own fixture. Successful ticket-retained and ticket-disabled conversions check
the same pointers, keys, sequence numbers 7/11 and the retained server identity
and master secret, followed by connection cleanup. The synthetic stream never
performs record I/O; a fake close callback counts lifetime completion.

The overlap runs real TLS1.2, TLS1.3 and highest-version negotiation plus a
full TLS1.3 ticket acquisition/resumption. Native Linux and Windows CI select
the two new establishment regressions.

| Verification | Result | Evidence |
| --- | --- | --- |
| Baseline before the fix | 9/10 passed; expected missing-ALPN ownership failure | [before.log](before.log) |
| OOM/transfer and real version/ticket overlap | 15/15 passed | [Debug.log](Debug.log) |

```sh
zig build test-tls '-Dtest-filter=versioned TLS establishment' -j1 --summary failures
zig build test-tls '-Dtest-filter=versioned TLS establishment' '-Dtest-filter=TLS 1.3 RFC 8446 ticket resumes the authenticated session' '-Dtest-filter=versioned TLS stream negotiates TLS 1.3 only' '-Dtest-filter=versioned TLS stream negotiates highest version' '-Dtest-filter=versioned TLS stream negotiates TLS 1.2 only' -j1 --summary all
```
