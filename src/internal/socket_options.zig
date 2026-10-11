const std = @import("std");
const builtin = @import("builtin");

const net = std.Io.net;

pub const Error = error{SocketOptionFailed};
pub const TcpUserTimeoutError = Error || error{SocketOptionUnsupported};

pub const TcpOptions = struct {
    no_delay: bool = false,
    user_timeout_ms: ?u32 = null,
};

/// Apply the requested TCP policy to one connected or accepted stream.
pub fn applyTcp(stream: net.Stream, options: TcpOptions) TcpUserTimeoutError!void {
    if (options.no_delay) try setTcpNoDelay(stream);
    if (options.user_timeout_ms) |milliseconds| {
        try setTcpUserTimeout(stream, milliseconds);
    }
}

/// Disable Nagle on a TCP stream.
///
/// `std.Io` 0.16 does not yet expose a portable socket-option operation, so
/// Windows keeps the platform default. Centralizing the POSIX path avoids
/// subtle protocol-specific copies and keeps latency policy at call sites.
pub fn setTcpNoDelay(
    stream: net.Stream,
) Error!void {
    if (comptime builtin.os.tag == .windows) return;
    const enabled: c_int = 1;
    std.posix.setsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&enabled),
    ) catch return error.SocketOptionFailed;
}

/// Bound how long transmitted data may remain unacknowledged before Linux
/// closes the TCP connection. A zero value explicitly restores the kernel
/// default; callers use an optional value to distinguish that from leaving
/// the socket untouched.
///
/// TCP_USER_TIMEOUT is a Linux-specific UAPI. Fail an explicit request on
/// other platforms instead of silently accepting a policy that cannot be
/// enforced. Zig 0.16 does not expose the constant, whose stable UAPI value is
/// 18 (`include/uapi/linux/tcp.h`).
pub fn setTcpUserTimeout(
    stream: net.Stream,
    milliseconds: u32,
) TcpUserTimeoutError!void {
    if (comptime builtin.os.tag != .linux) {
        return error.SocketOptionUnsupported;
    }
    const tcp_user_timeout: u32 = 18;
    std.posix.setsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        tcp_user_timeout,
        std.mem.asBytes(&milliseconds),
    ) catch return error.SocketOptionFailed;
}

test "TCP no-delay is enabled on a live stream" {
    if (comptime builtin.os.tag == .windows) return;

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);

    try setTcpNoDelay(server);
    var enabled: c_int = 0;
    var enabled_len: std.posix.socklen_t = @sizeOf(c_int);
    const result = std.posix.system.getsockopt(
        server.socket.handle,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        @ptrCast(&enabled),
        &enabled_len,
    );
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(result));
    try std.testing.expectEqual(@as(std.posix.socklen_t, @sizeOf(c_int)), enabled_len);
    try std.testing.expectEqual(@as(c_int, 1), enabled);
}

test "TCP user timeout preserves explicit zero and milliseconds" {
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expectError(
            error.SocketOptionUnsupported,
            setTcpUserTimeout(undefined, 1),
        );
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);

    try setTcpUserTimeout(server, 0);
    try expectTcpUserTimeout(server, 0);
    try setTcpUserTimeout(server, 12_345);
    try expectTcpUserTimeout(server, 12_345);
}

fn expectTcpUserTimeout(stream: net.Stream, expected: u32) !void {
    var actual: u32 = undefined;
    var actual_len: std.posix.socklen_t = @sizeOf(u32);
    const result = std.posix.system.getsockopt(
        stream.socket.handle,
        std.posix.IPPROTO.TCP,
        18,
        @ptrCast(&actual),
        &actual_len,
    );
    try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(result));
    try std.testing.expectEqual(
        @as(std.posix.socklen_t, @sizeOf(u32)),
        actual_len,
    );
    try std.testing.expectEqual(expected, actual);
}
