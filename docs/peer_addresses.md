# Transport peer addresses

`peerAddress()` and `remoteAddress()` identify the remote transport endpoint.
They can be used independently of TLS certificate and negotiation metadata:
cleartext IP connections also have a peer address.

| Surface | Address API |
| --- | --- |
| Unified HTTP client connection | `http.Connection.peerAddress()` |
| HTTP/1 client or accepted server connection | `http1.runtime.Client.peerAddress()`, `http1.runtime.Connection.peerAddress()` |
| gRPC accepted server connection | `grpc.runtime.ServerConnection.peerAddress()` |
| HTTP/2 client or accepted server connection | `http2.runtime.Connection.peerAddress()` |
| HTTP/1 and HTTP/2 buffered, batch, streaming and pull-body requests | `from` on the request or its head |
| HTTP/3 handshake requests | `OwnedHandshakeRequest.from` |
| WebSocket admission and established connections | `peerAddress()` |
| HTTP/2 WebTransport sessions and endpoint owners | `remoteAddress()` |
| HTTP/2 WebTransport pending requests | `peerAddress()` |
| HTTP/3 WebTransport sessions and endpoint owners | `remoteAddress()`; multiplexed client sessions borrow their owner as `remoteAddress(client)` |

TCP address accessors return `?std.Io.net.IpAddress`. An IP peer is available
on accepted connections and through native client socket queries on POSIX.
Unix-domain streams return `null`, including their HTTP request `from` fields.
A failed or unsupported native client query also returns `null`. Zig 0.16's
Windows `std.Io` sockets use AFD handles and do not provide a remote-address
query, so TCP client accessors currently return `null` there. Accepted Windows
IP connections still have the address recorded by accept.

QUIC-backed address accessors read the current peer path from their connection
owner. They return a concrete IP address and reflect path migration. The
unified HTTP connection wraps this value in the same optional return type as
its TCP branches.

```zig
if (connection.peerAddress()) |peer| {
    // The same code works for a unified HTTP client and H1/H2 connections.
    std.debug.print("transport peer: {f}\n", .{peer});
}
```

Client accessors previously returned the local ephemeral address on HTTP/2
and HTTP/1 WebSocket connections. Callers should handle the optional return
value; the reported IP endpoint is now the remote peer. The socket's existing
`stream.socket.address` is preserved: std.Io records the local endpoint for
client connects and the remote endpoint for accepted streams. An HTTP/1 server
`Connection` owns an accepted stream; client-created streams belong to `Client`.

TCP client introspection performs one native socket query per call. Accepted
connections use their cached address without a syscall. These operations do
not allocate, read protocol bytes, advance flow control or add per-connection
storage. As with other metadata accessors, callers must keep the connection
alive while inspecting it.

A TCP CONNECT or SOCKS tunnel reports the connected proxy's transport address.
The HTTP authority and TLS identity describe the origin separately. HTTP
forwarding headers do not change the transport peer; applications that use
them for client identity must apply their own trusted-proxy policy.
