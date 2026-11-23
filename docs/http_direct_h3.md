# Direct HTTP/3 through the unified client

`netz.http.Client` and `netz.http.Connection` support HTTP/3 using
`prefer_http3` (H3 then H2/H1) or `http3_only` (required H3). H3 opens a
QUIC/TLS 1.3 connection to an HTTPS URI. The default remains `prefer_http2`;
see [ordered selection](http_protocol_policy.md) for feasibility and deadlines.

```zig
var client = try netz.http.Client.init(allocator, io, .{
    .protocol_policy = .http3_only,
});
defer client.deinit();

var response = try client.requestUriWithTimeout(
    "https://example.com/resource", .{}, .fromSeconds(10),
);
defer response.deinit();
std.debug.assert(response.protocol() == .http3);

// Reuse one connection explicitly, including manual streaming requests.
var connection = try client.connectUriWithTimeout(
    "https://example.com", .fromSeconds(10),
);
defer connection.close();
var handle = try connection.startRequest("/upload", .{
    .method = "POST", .body_length = .unknown,
});
defer handle.deinit();
try handle.writeBody("first part");
try handle.finishBody();
_ = try handle.readResponse(sink);
```

Complete requests accept the same `body`, overriding `body_source.slice` or
`body_source.reader`, headers and trailers as H1/H2. Responses own their body
and decoded fields, so they outlive a one-shot client's QUIC connection.
Manual handles use the common `ResponseSink`, body/trailer operations,
`UploadProgress` and deadline forms described in [streaming](http_streaming.md).
The connection must outlive its handles, and one task drives it at a time.
An abandoned unfinished handle cancels its request stream.

`Client.Options.http3` configures the native QUIC limits and handshake. Empty
connection IDs are securely generated per connection. The two nested owners
also have flat accessors:

```zig
var h3: netz.http.Http3ConnectOptions = .{};
h3.nativeHandshake().server_name = "example.com"; // handshake.handshake
h3.sessionOptions().max_body_bytes = 64 * 1024 * 1024; // handshake.session
```
 A null local bind selects
an ephemeral wildcard bind for each resolved address family; H3 defaults to
bounded Happy Eyeballs and also supports an explicit local address. The URI
hostname remains the TLS SNI/verification identity and HTTP authority.
Common `Options.tls` verifier, client identity and trust settings are inherited
when their native H3 counterparts are unset. System certificate verification
is enabled by default.
QUIC client/server handshakes retain up to 256 KiB of CRYPTO data per encryption
level by default, matching the TCP/TLS handshake budget. Storage grows on demand;
explicit `handshake.handshake.max_crypto_buffer` values retain their configured
bound. The old 4-KiB default could reject ordinary server certificate flights.
Handshake-level CRYPTO flights are also split into datagrams capped at the
1200-byte QUIC minimum path MTU, so certificate and mTLS flights never depend
on IP fragmentation. The peer reassembles client CRYPTO across datagrams.
Application data uses the 1-RTT `max_datagram_size`, which defaults to the
1200-byte QUIC minimum; the endpoint's larger limit is a socket/receive cap, not
the send packet size. Use `setApplicationDatagramSize` to raise both together;
`Client.init` rejects a send size above the socket cap. PMTUD remains opt-in.

```zig
var h3: netz.http.Http3ConnectOptions = .{};
h3.setApplicationDatagramSize(1400);
```

`Connection.close()` sends a best-effort QUIC CONNECTION_CLOSE with
`NO_ERROR`, matching the H1/H2 close-notify contract. `closeWithDeadline` and
`closeWithTimeout` validate the budget first and then send the same best-effort
close; an expired budget still retires the owner. `closeWithoutCloseNotify`
retires the local QUIC owner without a close frame.

`connectUri*`, `request*`, Reader reads, body output and response reads preserve
one absolute operation deadline. A custom Reader must cooperate with `std.Io`
cancellation: the library joins the read task before releasing its borrowed
source or buffer. Natural source failures become `RequestBodyReadFailed`;
an operation deadline becomes `Timeout`.

Explicit redirect helpers use the common method, downgrade and credential
policies. Preserving redirects need a replayable Reader. Crossing an origin
clears QUIC resumption inputs, and client identities remain restricted by
default. Negotiation metadata reports `h3`, TLS 1.3, the native resume flag and
the QUIC 0-RTT status (`earlyDataStatus()`). TCP session-ticket getters return
null on an H3 connection; QUIC resumption uses the native H3 handshake inputs.

The strict H3 policy requires HTTPS and an H3 ALPN list. TLS-1.2-only policy,
HTTP/SOCKS proxy options, invalid connection budgets and raw early-data offers
are rejected during initialization. `http3_only` does not perform TCP fallback;
`prefer_http3` advances to H2/H1 when H3 connection selection is unavailable.
For discovery, shared concurrent requests, SOCKS5 UDP routing
and managed 0-RTT replay, use the existing
[`Pool.Options.http3`](http_client_pool.md) configuration. `Pool.Options.client`
configures primary H1/H2/H3 leases and accepts both H3 policies.

Focused loopback evidence is in
[the direct H3 delivery record](evidence/http_direct_h3/2026-11-20/README.md).
