# QUIC handshake CRYPTO defaults

Base revision: `ef1660f0`, Zig 0.16.0, macOS aarch64, 2026-11-21.
Final production/test source hashes are recorded in `sources.json`.

`~/Work/agent-learn` reproduced `CryptoBufferTooLarge` during the H3 connection
attempt with the zio backend. A temporary diagnostic in the CRYPTO reassembler
captured the actual range, without payload or credential output:

```text
QUIC CRYPTO diagnostic: offset=3845 bytes=264 end=4109 limit=4096
error: CryptoBufferTooLarge
```

The received range crossed the native client's 4-KiB default. This is a byte
span rejection, rather than a data-race, allocator leak or packet-count limit.
The diagnostic was removed after capture; `reproduction.txt` retains its output.

Native QUIC client and server options now share a 256-KiB per-encryption-level
default, matching the unified TCP/TLS handshake size budget. Reassembly storage
still grows on demand and does not reserve that capacity at construction.
The explicit `max_crypto_buffer` setting and its transactional rejection remain
unchanged. The server counterpart admits large authenticated client flights.

The focused loopback test uses sixteen DER certificate entries (4928 bytes
before TLS framing), leaf-key pinning and a real CertificateVerify signature.
CRYPTO frames split at the native 1024-byte contribution limit. An 8-KiB local
datagram capacity admits the existing native sender's complete certificate
packet; the test certifies CRYPTO-frame reassembly rather than multi-datagram
server flight packetization. Client and mTLS server paths run with both
Threaded and zio. Explicit 4-KiB and default final-span overflow probes confirm
that a failure leaves the prior buffer state intact.

| Gate | Result | Artifact |
| --- | --- | --- |
| Large certificate/mTLS and explicit/default boundaries, Debug | 35/35 | `verified-debug.log` |
| Matching ReleaseFast gate | 35/35 | `releasefast.log` |
| Original application with zio and both HTTP requests | Exit 0; H3/200 and H2/200; no leak reports | `application-summary.txt` |

The earlier `debug.log` and `diagnostic-debug.log` capture the first fixture's
HandshakeTimeout with a 4-KiB datagram capacity, before that local transport
capacity was adjusted to admit its 5-KiB certificate packet.

```sh
zig build test-quic '-Dtest-filter=QUIC default CRYPTO limit' --summary all
zig build test-quic -Doptimize=ReleaseFast \
  '-Dtest-filter=QUIC default CRYPTO limit' --summary all
```

Counts include imported support tests. These are scoped handshake and boundary
checks, with one application smoke run; they are not a new protocol-wide peer
certification or benchmark result.
