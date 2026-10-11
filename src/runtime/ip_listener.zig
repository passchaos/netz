//! Backend-aware TCP listener construction for socket options that Zig's
//! `std.Io.net.IpAddress.ListenOptions` does not expose yet.

const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");

const net = std.Io.net;

pub const Options = struct {
    kernel_backlog: u31 = std.Io.net.default_kernel_backlog,
    reuse_address: bool = false,
    /// Null leaves the platform default unchanged. False explicitly permits
    /// IPv4-mapped connections and true rejects them. Either explicit policy
    /// must be applied before bind, so unsupported backends fail closed.
    ip6_only: ?bool = null,
};

/// Create a TCP listener while retaining Netz's `std.Io.net.Server` protocol
/// boundary. The current Netz runtime is zio-backed; foreign I/O backends are
/// rejected when they cannot promise the requested pre-bind socket policy.
pub fn listen(
    io: std.Io,
    address: net.IpAddress,
    options: Options,
) net.IpAddress.ListenError!net.Server {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    if (options.ip6_only != null and address != .ip6) {
        return error.OptionUnsupported;
    }

    const domain: zio.os.net.Domain = switch (address) {
        .ip4 => .ipv4,
        .ip6 => .ipv6,
    };
    var socket = zio.net.Socket.open(.stream, domain, .tcp) catch |err|
        return mapOpenError(err);
    errdefer socket.close();

    if (options.reuse_address) {
        socket.setReuseAddress(true) catch return error.OptionUnsupported;
        // Match std.Io's reuse_address behavior where SO_REUSEPORT exists.
        socket.setReusePort(true) catch {};
    }
    if (options.ip6_only) |enabled| try setIpv6Only(socket, enabled);

    socket.bind(.{ .ip = zioIpAddress(address) }) catch |err|
        return mapBindError(err);
    socket.listen(options.kernel_backlog) catch |err|
        return mapListenError(err);

    return .{
        .socket = .{
            .handle = stdIoSocketHandle(socket.handle),
            .address = stdIpAddress(socket.address.ip),
        },
        .options = if (net.Server.AcceptOptions != void) .{
            .mode = .stream,
            .protocol = .tcp,
        },
    };
}

fn setIpv6Only(
    socket: zio.net.Socket,
    enabled: bool,
) net.IpAddress.ListenError!void {
    const option: u32 = switch (builtin.os.tag) {
        .linux => 26,
        .windows, .macos, .ios, .freebsd, .netbsd, .openbsd, .dragonfly => 27,
        else => return error.OptionUnsupported,
    };
    const value: c_int = @intFromBool(enabled);
    zio.os.net.setsockopt(
        socket.handle,
        zio.os.net.IPPROTO.IPV6,
        option,
        std.mem.asBytes(&value),
    ) catch return error.OptionUnsupported;
}

fn zioIpAddress(address: net.IpAddress) zio.net.IpAddress {
    return switch (address) {
        .ip4 => |ip4| .initIp4(ip4.bytes, ip4.port),
        .ip6 => |ip6| .initIp6(
            ip6.bytes,
            ip6.port,
            ip6.flow,
            ip6.interface.index,
        ),
    };
}

fn stdIpAddress(address: zio.net.IpAddress) net.IpAddress {
    return switch (address.getFamily()) {
        .ipv4 => .{ .ip4 = .{
            .bytes = @bitCast(address.in.addr),
            .port = std.mem.bigToNative(u16, address.in.port),
        } },
        .ipv6 => .{ .ip6 = .{
            .bytes = address.in6.addr,
            .port = std.mem.bigToNative(u16, address.in6.port),
            .flow = address.in6.flowinfo,
            .interface = .{ .index = address.in6.scope_id },
        } },
    };
}

fn stdIoSocketHandle(
    handle: @FieldType(zio.net.Socket, "handle"),
) net.Socket.Handle {
    return if (@typeInfo(net.Socket.Handle) == .pointer)
        @ptrCast(handle)
    else
        @intCast(handle);
}

fn mapOpenError(err: anyerror) net.IpAddress.ListenError {
    return switch (err) {
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.ProtocolNotSupported => error.ProtocolUnsupportedBySystem,
        error.ProcessFdQuotaExceeded => error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded => error.SystemFdQuotaExceeded,
        error.SystemResources => error.SystemResources,
        error.Canceled => error.Canceled,
        else => error.Unexpected,
    };
}

fn mapBindError(err: anyerror) net.IpAddress.ListenError {
    return switch (err) {
        error.AddressInUse => error.AddressInUse,
        error.AddressUnavailable => error.AddressUnavailable,
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.NetworkDown => error.NetworkDown,
        error.SystemResources => error.SystemResources,
        error.Canceled => error.Canceled,
        else => error.Unexpected,
    };
}

fn mapListenError(err: anyerror) net.IpAddress.ListenError {
    return switch (err) {
        error.AddressInUse => error.AddressInUse,
        error.NetworkDown => error.NetworkDown,
        error.SystemResources => error.SystemResources,
        error.OperationNotSupported => error.SocketModeUnsupported,
        error.Canceled => error.Canceled,
        else => error.Unexpected,
    };
}

test "TCP listener rejects unsupported std.Io backends" {
    try std.testing.expectError(
        error.OptionUnsupported,
        listen(
            std.testing.io,
            .{ .ip6 = .loopback(0) },
            .{ .ip6_only = true },
        ),
    );
}

test "TCP listener sets IPv6-only before bind" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const runtime = try zio.Runtime.init(std.testing.allocator, .{});
    defer runtime.deinit();
    const io = runtime.io();
    var server = try listen(
        io,
        .{ .ip6 = .loopback(0) },
        .{ .reuse_address = true, .ip6_only = true },
    );
    defer server.deinit(io);

    var enabled: c_int = 0;
    try zio.os.net.getsockopt(
        server.socket.handle,
        zio.os.net.IPPROTO.IPV6,
        26,
        std.mem.asBytes(&enabled),
    );
    try std.testing.expectEqual(@as(c_int, 1), enabled);
}
