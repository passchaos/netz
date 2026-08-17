const std = @import("std");
const builtin = @import("builtin");

const net = std.Io.net;

/// Disable Nagle on a TCP stream.
///
/// `std.Io` 0.16 does not yet expose a portable socket-option operation, so
/// Windows keeps the platform default. Centralizing the POSIX path avoids
/// subtle protocol-specific copies and keeps latency policy at call sites.
pub fn setTcpNoDelay(
    stream: net.Stream,
) std.posix.SetSockOptError!void {
    if (comptime builtin.os.tag == .windows) return;
    const enabled: c_int = 1;
    try std.posix.setsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&enabled),
    );
}
