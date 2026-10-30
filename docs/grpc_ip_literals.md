# Numeric gRPC and HTTP/2 endpoints

`grpc.Channel`, `grpc.SharedChannel` and the HTTP/2 host connection APIs accept
canonical IPv4 addresses and IPv6 addresses in either bare or bracketed form.
The port remains a separate argument. For example:

```zig
var channel = try netz.grpc.SharedChannel.init(allocator, io, .{
    .tls_host = .{
        .host = "[::1]",
        .port = 8443,
        .tls = .{ .ca_bundle = trusted_bundle },
    },
}, .{});
defer channel.deinit();
```

`internal/endpoint_host.zig` separates the borrowed DNS/TLS identity from the
socket address and HTTP authority. IPv6 authorities use brackets and the
standard address formatter, so `::1`, `[::1]` and `0:0:0:0:0:0:0:1` all send
`[::1]:8443`. The TLS identity excludes brackets. Default numeric resolution
returns the parsed address without a DNS lookup. A configured gRPC address
resolver still owns route selection and receives the unbracketed identity;
its selected address does not replace the logical authority or TLS identity.
Both direct host targets and host members in an endpoint list follow this
contract. Scoped sockets remain expressible through typed IP endpoints.

The default CA verifier matches an IP identity against an exact `iPAddress`
subjectAltName. A certificate containing only `DNS:localhost` cannot authorize
`127.0.0.1` or `::1`. Vail's ClientHello writer omits SNI for numeric identities
as required by [RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066#section-3),
while retaining the original identity in certificate verification and session
ticket context. DNS SNI and caller-supplied verifier policy retain their
existing behavior. TLS 1.2, TLS 1.3 and mandatory `h2` ALPN use the same policy.

The shared `http2/runtime/client/host_connect.zig` module validates the route
and captures the connect deadline before authority allocation and network
admission. Relative and absolute entry points share this ownership boundary.
Allocation cannot renew the connection budget. Expiry after TCP connection
releases both the socket and authority before TLS admission.

## Verification

The adjacent unit and real socket regressions cover IPv4/IPv6, bracket and
expanded forms, both gRPC owners, endpoint lists, resolver overrides, invalid
input, allocation rejection, the original connect deadline and socket cleanup
after TCP success. Run the focused contract with:

```sh
zig build test-lib -Dtest-filter='gRPC IP host' \
  -Dtest-filter='endpoint host' -Dtest-filter='HTTP/2 host connection' \
  -Dtest-filter='authority allocation cannot renew' \
  -Dtest-filter='TLS host closes ownership' --summary all
zig build interop-grpc-ip-literals -Doptimize=ReleaseFast --summary all -- \
  --output docs/evidence/grpc_ip_literals/2026-10-30.json
```

The process gate uses pinned official grpc-js 1.14.0, the standard Node TLS
client and an independent Node HTTP/2 peer. OpenSSL creates one CA and separately signs an IP-SAN leaf and a
DNS-only leaf with the same key. Every accepted connection exchanges two
exact unary messages on one HTTP/2 connection; both address families run over
h2c, TLS 1.2 and TLS 1.3. Native coverage exercises ordinary, relative-timeout
and absolute-deadline HTTP/2 host/address APIs, ordinary Channel, SharedChannel
and both endpoint-list variants. The peer checks exact authority, scheme,
ALPN, negotiated TLS version and absence of numeric native SNI. Negative TLS
cases require certificate rejection before any HTTP/2 request.

The gate records grpc-js SNI independently. Its pinned SDK sets numeric SNI,
which current Node rejects before handshake. That exact upstream failure is
retained as evidence. When the SDK cannot establish numeric TLS, the standard
Node TLS/HTTP2 client supplies the independent TLS, RPC, authority and reuse
checks. Its empty `servername` disables SNI while leaving default CA and IP
identity verification enabled; DNS-only leaves must fail with
`ERR_TLS_CERT_ALTNAME_INVALID`. The official SDK continues to verify both
address families over h2c and runs the TLS checks on runtimes that permit its
numeric SNI.

The recorded [2026-10-30 matrix](evidence/grpc_ip_literals/2026-10-30.json)
contains 108 accepted native connections and 216 exact RPCs, plus 80 rejected
native TLS attempts. Every accepted connection is reused twice. Source hashes
bind the record to the native implementation, driver, peer and pinned SDK.
Node v26.10.0 rejects the SDK's numeric SNI in all TLS scenarios. The independent
Node TLS control rejects the same DNS-only leaves with the exact identity
error; its TLS 1.2 peer session allocation is recorded separately before native
attempts, which create no additional HTTP/2 sessions or requests.
