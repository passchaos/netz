//! IP peer metadata at the native stream boundary.
//!
//! Zig 0.16 Threaded records a local sockname for client connects; zio
//! records the selected destination. Accepted streams record a remote address.
//! Keep that distinction out of protocol facades without
//! changing the std socket's address or adding state to every connection.

const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const winsock = @import("socket_address/winsock.zig");
const net = std.Io.net;

/// The address returned by accept is already the remote peer. Unix streams
/// use std.Io's port-zero placeholder and have no IP peer.
pub fn accepted(stream: net.Stream) ?net.IpAddress {
    const address = stream.socket.address;
    return if (address.getPort() != 0) address else null;
}

/// Query the connected socket's actual IP peer without allocating or touching
/// protocol input. Returns null for non-IP streams or an unavailable query.
/// On Windows, only zio's Winsock sockets can use getpeername. A foreign IO
/// backend may own native AFD handles, which must not be treated as SOCKETs.
pub fn connected(io: std.Io, stream: net.Stream) ?net.IpAddress {
    if (comptime builtin.os.tag == .windows) {
        _ = zio.Runtime.fromIo(io) orelse return null;
        return winsock.query(stream);
    }
    if (comptime !@hasDecl(std.posix.system, "getpeername")) return null;

    const Address = extern union {
        any: std.posix.sockaddr,
        ip4: std.posix.sockaddr.in,
        ip6: std.posix.sockaddr.in6,
    };
    var address: Address = undefined;
    var length: std.posix.socklen_t = @sizeOf(Address);
    const result = std.posix.system.getpeername(
        stream.socket.handle,
        &address.any,
        &length,
    );
    if (std.posix.errno(result) != .SUCCESS or
        length < @sizeOf(std.posix.sa_family_t)) return null;
    return switch (address.any.family) {
        std.posix.AF.INET => if (length >= @sizeOf(std.posix.sockaddr.in)) .{
            .ip4 = .{
                .bytes = @bitCast(address.ip4.addr),
                .port = std.mem.bigToNative(u16, address.ip4.port),
            },
        } else null,
        std.posix.AF.INET6 => if (length >= @sizeOf(std.posix.sockaddr.in6)) .{
            .ip6 = .{
                .bytes = address.ip6.addr,
                .port = std.mem.bigToNative(u16, address.ip6.port),
                .flow = address.ip6.flowinfo,
                .interface = .{ .index = address.ip6.scope_id },
            },
        } else null,
        else => null,
    };
}

test {
    // The Windows branch is eliminated on POSIX, so import its portable ABI
    // vectors explicitly instead of relying on a live query to reach them.
    _ = winsock;
    _ = @import("socket_address/tests.zig");
}
