const std = @import("std");
const builtin = @import("builtin");

const net = std.Io.net;

pub const Error = error{SocketOptionFailed};
pub const TcpPolicyError = Error || error{
    InvalidSocketOption,
    SocketOptionUnsupported,
};

pub const TcpKeepAlive = struct {
    idle_seconds: u32,
    interval_seconds: u32,
    probe_count: u32,
};

pub const TcpOptions = struct {
    no_delay: bool = false,
    keep_alive: ?TcpKeepAlive = null,
    user_timeout_ms: ?u32 = null,
};

/// Apply the requested TCP policy to one connected or accepted stream.
pub fn applyTcp(stream: net.Stream, options: TcpOptions) TcpPolicyError!void {
    if (options.no_delay) try setTcpNoDelay(stream);
    if (options.keep_alive) |keep_alive| {
        try setTcpKeepAlive(stream, keep_alive);
    }
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
) TcpPolicyError!void {
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

/// Enable TCP keepalive and set all three detection parameters atomically from
/// the caller's perspective. A failure aborts connection setup; a partially
/// configured socket is never returned to the application.
pub fn setTcpKeepAlive(
    stream: net.Stream,
    options: TcpKeepAlive,
) TcpPolicyError!void {
    if (options.idle_seconds == 0 or
        options.interval_seconds == 0 or
        options.probe_count == 0)
    {
        return error.InvalidSocketOption;
    }
    if (comptime builtin.os.tag == .windows) {
        return error.SocketOptionUnsupported;
    }
    if (comptime !@hasDecl(std.posix.SO, "KEEPALIVE") or
        !(@hasDecl(std.posix.TCP, "KEEPIDLE") or
            @hasDecl(std.posix.TCP, "KEEPALIVE")) or
        !@hasDecl(std.posix.TCP, "KEEPINTVL") or
        !@hasDecl(std.posix.TCP, "KEEPCNT"))
    {
        return error.SocketOptionUnsupported;
    }

    const enabled: c_int = 1;
    try setSocketOption(
        stream,
        std.posix.SOL.SOCKET,
        std.posix.SO.KEEPALIVE,
        enabled,
    );
    const idle_option = if (@hasDecl(std.posix.TCP, "KEEPIDLE"))
        std.posix.TCP.KEEPIDLE
    else
        std.posix.TCP.KEEPALIVE;
    try setSocketOption(
        stream,
        std.posix.IPPROTO.TCP,
        idle_option,
        options.idle_seconds,
    );
    try setSocketOption(
        stream,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.KEEPINTVL,
        options.interval_seconds,
    );
    try setSocketOption(
        stream,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.KEEPCNT,
        options.probe_count,
    );
}

fn setSocketOption(
    stream: net.Stream,
    level: i32,
    option: u32,
    value: anytype,
) Error!void {
    std.posix.setsockopt(
        stream.socket.handle,
        level,
        option,
        std.mem.asBytes(&value),
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
    // Some Darwin kernels normalize the enabled value (observed 4 on macOS
    // 26); only zero means Nagle remains active.
    try std.testing.expect(enabled != 0);
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

test "TCP keepalive configures idle interval and probe count" {
    if (comptime builtin.os.tag != .linux) return;

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

    try setTcpKeepAlive(server, .{
        .idle_seconds = 31,
        .interval_seconds = 11,
        .probe_count = 7,
    });
    try expectSocketOption(
        server,
        std.posix.SOL.SOCKET,
        std.posix.SO.KEEPALIVE,
        1,
    );
    try expectSocketOption(
        server,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.KEEPIDLE,
        31,
    );
    try expectSocketOption(
        server,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.KEEPINTVL,
        11,
    );
    try expectSocketOption(
        server,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.KEEPCNT,
        7,
    );
}

test "TCP keepalive rejects zero parameters before touching a socket" {
    inline for (.{
        TcpKeepAlive{ .idle_seconds = 0, .interval_seconds = 1, .probe_count = 1 },
        TcpKeepAlive{ .idle_seconds = 1, .interval_seconds = 0, .probe_count = 1 },
        TcpKeepAlive{ .idle_seconds = 1, .interval_seconds = 1, .probe_count = 0 },
    }) |options| {
        try std.testing.expectError(
            error.InvalidSocketOption,
            setTcpKeepAlive(undefined, options),
        );
    }
}

fn expectTcpUserTimeout(stream: net.Stream, expected: u32) !void {
    try expectSocketOption(
        stream,
        std.posix.IPPROTO.TCP,
        18,
        expected,
    );
}

fn expectSocketOption(
    stream: net.Stream,
    level: i32,
    option: u32,
    expected: u32,
) !void {
    var actual: u32 = undefined;
    var actual_len: std.posix.socklen_t = @sizeOf(u32);
    const result = std.posix.system.getsockopt(
        stream.socket.handle,
        level,
        option,
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
