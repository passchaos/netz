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
A failed or unsupported native client query also returns `null`. On Windows,
Netz's zio backend owns Winsock sockets and queries their peer through
`getpeername`. The helper checks the `std.Io` backend before calling Winsock.
Zig 0.16's Threaded backend owns native AFD handles and has no supported peer
query here, so its TCP client accessors return `null`. Accepted Windows IP
connections retain the address recorded by accept for either backend.
The portable CI matrix includes a native Windows runner that executes the
focused HTTP peer-address tests, including zio socket queries and the Windows
address vectors.

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
`stream.socket.address` is preserved. Threaded records the local endpoint for
client connects, while zio's generic IP connect records the selected destination.
Accepted IP streams record the remote endpoint. Adopted or explicitly bound
streams can have their own recorded address, so backend identity alone cannot
replace a native peer query. An HTTP/1 server `Connection` owns an accepted
stream; client-created streams belong to `Client`.

TCP client introspection performs one native socket query per call. Accepted
connections use their cached address without a syscall. These operations do
not allocate, read protocol bytes, advance flow control or add per-connection
storage. As with other metadata accessors, callers must keep the connection
alive while inspecting it.

A TCP CONNECT or SOCKS tunnel reports the connected proxy's transport address.
The HTTP authority and TLS identity describe the origin separately. HTTP
forwarding headers do not change the transport peer; applications that use
them for client identity must apply their own trusted-proxy policy.
