# Remote transport peer metadata, 2026-11-24

Base revision: `301ea6a3`, Zig 0.16.0, macOS aarch64.

HTTP/2 and HTTP/1 WebSocket client `peerAddress()` previously returned the
local ephemeral endpoint stored by Zig 0.16 in `stream.socket.address`.
HTTP/2 WebTransport inherited the same value through `remoteAddress()`.
Existing non-zero-port checks could not distinguish it from a remote peer.

The shared `internal/socket_address.zig` boundary now queries the connected
native socket on POSIX and reads cached accept metadata on servers. H1/H2,
WebSocket, HTTP/2 WebTransport and gRPC TCP accessors return optional IP
metadata. Unix requests also preserve null `from` fields. The unified HTTP
connection forwards H1/H2 through this boundary and H3 through its current
QUIC peer path. The socket's stored address and connection layouts are
unchanged. See [the public contract](../../../peer_addresses.md) for API
migration, proxies, query cost and current Windows limitations.

Tests compare the exact listening endpoint with the client's reported peer,
distinguish both ends of a live TCP connection, exercise IPv4/IPv6 on Threaded
and zio, and assert no IP peer on Unix or unconnected sockets. WS and WSS
CONNECT proxy tests check the proxy address; real TLS WebTransport tests check
the Session and EndpointClient server port.

| Gate | Result | Artifact |
| --- | --- | --- |
| Scoped Debug protocol and package tests | 382/382 | [focused-debug.log](focused-debug.log) |
| HTTP/1 client/server size guards | 13/13 | [h1-layout.log](h1-layout.log) |
| Complete library/package test compilation, without running the suites | 9/9 steps | [test-compile.log](test-compile.log) |
| Linux address module compilation | passed | [linux-compile.log](linux-compile.log) |
| Windows address module compilation | passed | [windows-compile.log](windows-compile.log) |

Counts include imported support tests and overlap between protocol roots.
This evidence establishes metadata semantics and existing layout bounds; it
does not claim a throughput improvement or external-peer interoperability.

```sh
zig build test-http test-http1 test-http2 test-websocket test-webtransport test-package \
  '-Dtest-filter=peer address' \
  '-Dtest-filter=keeps optional state compact' \
  '-Dtest-filter=keeps resumable writes compact' \
  '-Dtest-filter=connects by host name' \
  '-Dtest-filter=exchange over a Unix socket' \
  '-Dtest-filter=runtime client and server exchange over TCP' \
  '-Dtest-filter=extended CONNECT exchanges messages' \
  '-Dtest-filter=EndpointClient owns multiplexed' \
  '-Dtest-filter=EndpointListener isolates a slow TLS handshake' \
  '-Dtest-filter=EndpointServer owns admission' \
  '-Dtest-filter=connection exposes H1 TLS metadata' \
  '-Dtest-filter=direct H3 Client Connection' \
  '-Dtest-filter=URI connects through HTTP CONNECT proxy' \
  '-Dtest-filter=WSS URI authenticates origin through HTTP CONNECT proxy' \
  '-Dtest-filter=public ALPN adoption and metadata' --summary all
```


The complete compile gate is justified by the public TCP return-type change:
it checks repository consumers without running all protocol suites. Linux and
Windows checks only compile the address module; no runtime or network behavior
on those hosts is inferred from them.

```sh
zig build test-compile -j1 --summary all
zig test src/internal/socket_address.zig -target x86_64-linux -fno-emit-bin
zig test src/internal/socket_address.zig -target x86_64-windows -fno-emit-bin
```

```sh
zig build test-http1 \
  '-Dtest-filter=connections keep optional write scratch compact' --summary all
```

The layout guards retain HTTP/1 Client/Connection at 448/384 bytes, HTTP/2
Connection at 2080 bytes in Debug, and HTTP/1 WebSocket Connection at 1616
bytes on this 64-bit target.
