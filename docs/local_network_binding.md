# Local network binding

`local_address` selects a source IP and port. `network_interface` constrains
the actual socket's sending and receiving interface. They are independent:
selecting a source address does not pin the socket to a device, and selecting
a device lets the OS choose an address on it.

The common interface selector is `netz.runtime.NetworkInterface`. Use a device
name in application configuration:

```zig
const interface: netz.runtime.NetworkInterface = .{ .name = "en0" };
```

Names are borrowed for the client/pool lifetime. POSIX names are the native
names (`en0`, `eth0`, `lo`). Windows accepts an adapter alias (`Ethernet`) or
its canonical interface name. The socket setup resolves the name automatically.

## HTTP and WebSocket

One unified HTTP option applies to H1, H2 and H3, including protocol fallback,
redirects, address retries and newly created pool connections:

```zig
var client = try netz.http.Client.init(allocator, io, .{
    .network_interface = .{ .name = "en0" },
    // Optional, independent source IP and ephemeral source port:
    .local_address = try std.Io.net.IpAddress.parse("192.168.1.20", 0),
});
defer client.deinit();

var pool = try netz.http.Pool.init(allocator, io, .{
    .client = .{ .network_interface = .{ .name = "en0" } },
    .http3 = .{},
});
defer pool.deinit();

var ws = try netz.websocket.runtime.Client.connectUri(
    allocator, io, "wss://example.com/socket",
    .{ .network_interface = .{ .name = "en0" } },
);
defer ws.close();
```

The version-specific HTTP/1 and HTTP/2 clients expose both fields in their
existing `runtime.Limits`; WebSocket exposes them in `ConnectOptions`.
HTTP/1 and HTTP/2 TCP/TLS listeners also use `Limits.network_interface`;
their listening address remains the positional bind address. Lower-level
listeners use `netz.runtime.listenTcp(..., .{ .network_interface = ... })`.
The native interface option is installed before bind/listen.
WebTransport over H2 and WebSocket over H2 use the binding configured on the
owning HTTP/2 connection. Stream adoption and protocol upgrades retain the
application's existing transport; binding fields govern newly opened sockets.
Unix-domain connects reject either IP/device binding option.

For HTTP CONNECT, forward proxies and SOCKS5, binding governs the local socket
to the proxy. The proxy chooses its own origin-side route. SOCKS5 `Options`
exposes both TCP binding fields; `UdpAssociateOptions.network_interface`
controls the UDP side and inherits the TCP interface when omitted. Owning
HTTP/WS connection options override corresponding proxy binding fields when
set. H3's QUIC interface policy reaches both the SOCKS5 control connection and
its UDP association.

When adopting a `UdpAssociation` with `Endpoint.fromSocks5Association*`, or an
endpoint with `SharedHandshakeClientPool.initWithOwnedEndpoint`, a requested
`network_interface` asserts the policy already installed on that socket.
An unconstrained or differently constrained socket returns
`InterfaceBindingMismatch`; failed adoption retains the caller's resources and
socket settings. Configure the interface while creating the association or
endpoint, before bind. Windows adoption checks both outgoing UNICAST_IF and an
enabled receive list containing exactly the requested interface. Shared H3
endpoint adoption also requires `io` to match `endpoint.io` exactly; a different
I/O context returns `InvalidPoolOptions` before allocation or ownership transfer.

## QUIC, HTTP/3 and WebTransport

QUIC already accepts a positional local IP/port. Its `runtime.Limits` now adds
`network_interface`, which applies to every endpoint created with those limits:

```zig
var connection = try netz.quic.runtime.Client.connect(
    allocator, io,
    .{ .ip4 = .unspecified(0) },
    peer_address,
    .{ .network_interface = .{ .name = "en0" } },
);
defer connection.deinit();
```

Native H3, H3 WebSocket and H3 WebTransport constructors retain their local
address argument and carry the interface in their H3 limits:

```zig
const limits: netz.http3.runtime.Limits = .{
    .quic = .{ .network_interface = .{ .name = "en0" } },
};
```

This includes alternate-family endpoints, shared pools, and newly created
migration endpoints. Interface constraints remain in force during QUIC peer
address migration. A unified HTTP `local_address` overrides the legacy
H3-specific local address and disables alternate-family binds; every candidate
must use that source family. With no source address, each candidate uses its
own family's wildcard bind on the selected interface.

## Advanced: native interface indices

`NetworkInterface.index` accepts a nonzero native OS interface index. This is
useful when an application already has an index from interface enumeration or
a route query, or needs to reuse a resolved `std.Io.net.Interface`. Ordinary
named-interface configuration does not require this extra step.

`interface.resolve(io)` returns the native `std.Io.net.Interface`:

```zig
const native = try interface.resolve(io);
const selected: netz.runtime.NetworkInterface = .{ .index = native.index };
```

Keep indices as runtime data. They are local to the operating system and can
change after device removal or system reconfiguration; a hardcoded number is
not a stable device identity for stored application configuration.

## Native behavior and errors

| Platform / transport | Socket mechanism | Behavior |
| --- | --- | --- |
| Linux TCP / UDP | `SO_BINDTODEVICE` | Restricts sending and reception to the selected device. |
| macOS TCP / UDP | `IP_BOUND_IF` / `IPV6_BOUND_IF` | Constrains the socket to the interface for its address family. |
| Windows UDP | `IP[V6]_UNICAST_IF` plus `IP[V6]_ADD_IFLIST` and `IP[V6]_IFLIST` | Pins outgoing unicast and restricts received datagrams to that interface. |
| Windows TCP | No equivalent receive-interface constraint | Returns `OptionUnsupported` when interface binding is requested. Source-address binding remains available. |
| Other platforms | No implemented device constraint | Returns `OptionUnsupported` when requested. |

TCP source/device binding requires Netz's zio backend: Zig 0.16's generic
`std.Io` cannot connect an already bound socket. Unconstrained connects retain
the existing generic backend path. UDP interface constraints likewise require
zio to install the policy before bind; unconstrained UDP source-address binding retains generic std.Io support.
Foreign Windows backends can expose AFD handles and are rejected.

Empty names, embedded NULs and index zero return `InvalidNetworkInterface`.
Missing devices return `InterfaceNotFound`; overlong names return `NameTooLong`.
Adoption policy mismatches return `InterfaceBindingMismatch`.
Kernel permission failures return `AccessDenied`. Unsupported socket options
return `OptionUnsupported`; other option failures return `SocketOptionFailed`.
Constrained Windows IPv6 UDP sockets are IPv6-only so mapped IPv4 packets
cannot bypass the IPv6 receive list; adopting a dual-stack Windows UDP socket
with a requested interface returns `OptionUnsupported`.
Failed setup closes the socket. Configuration, permission and unsupported
binding errors terminate the attempt instead of retrying through an unbound
socket or a different interface.

Interface constraints are installed before native TCP/UDP bind, TCP connect,
and the first UDP send, preventing unfiltered incoming packets from entering a
new socket during setup. DNS resolution remains the resolver's responsibility;
system DNS and custom resolver callbacks do not inherit socket binding.
An explicit source IP must belong to the desired interface and match the peer
address family. Use source port zero for pools or address racing; a fixed
nonzero TCP source port can make simultaneous attempts collide, so use ordered
fallback when reserving one exact source tuple.

Tests read back the live native socket options and exchange TCP bytes and QUIC
datagrams on IPv4/IPv6 loopback. They also cover ordered/Happy Eyeballs fallback,
name/index selection, source-address composition, protocol/proxy propagation,
invalid configuration, backend rejection and expired deadlines. Multi-device
route behavior still depends on the host's interface addresses and routing
configuration; see [the multi-NIC recipe](http3_multipath.md).
