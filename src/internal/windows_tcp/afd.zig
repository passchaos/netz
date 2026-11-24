//! Threaded AFD connect with recoverable native connection statuses.
const std = @import("std");
const builtin = @import("builtin");
const encoded_address = @import("../socket_address/winsock.zig").Encoded;
const net = std.Io.net;
const windows = std.os.windows;
pub const Result = net.IpAddress.ConnectError!net.Stream;

pub fn nativeThreaded(io: std.Io, address: net.IpAddress) ?Result {
    if (comptime builtin.os.tag != .windows) return null;
    // Preserve foreign backends and application interceptors. The native
    // Threaded function's AFD status mapping is the boundary being replaced.
    var reference: std.Io.Threaded = .init_single_threaded;
    if (io.vtable.netConnectIp != reference.io().vtable.netConnectIp) return null;
    return connect(io, address);
}

fn connect(io: std.Io, address: net.IpAddress) Result {
    const local: net.IpAddress = switch (address) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const socket = local.bind(io, .{ .mode = .stream, .protocol = .tcp }) catch |err| switch (err) {
        error.AddressInUse => return error.Unexpected,
        else => return @errorCast(err),
    };
    errdefer socket.close(io);
    const Storage = extern struct { reserved: [3]usize = @splat(0), address: [28]u8 };
    const encoded = encoded_address.init(address);
    const storage: Storage = .{ .address = encoded.bytes };
    const result = try std.Io.operate(io, .{ .device_io_control = .{
        .file = .{ .handle = socket.handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.CONNECT,
        .in = std.mem.asBytes(&storage)[0 .. @offsetOf(Storage, "address") + encoded.len],
    } });
    try status(result.device_io_control.u.Status);
    return .{ .socket = socket };
}

pub fn status(value: windows.NTSTATUS) net.IpAddress.ConnectError!void {
    return switch (value) {
        .SUCCESS => {},
        .CONNECTION_REFUSED => error.ConnectionRefused,
        .CONNECTION_RESET => error.ConnectionResetByPeer,
        .NETWORK_UNREACHABLE => error.NetworkUnreachable,
        .HOST_UNREACHABLE => error.HostUnreachable,
        .IO_TIMEOUT => error.Timeout,
        .INSUFFICIENT_RESOURCES => error.SystemResources,
        .ACCESS_DENIED => error.AccessDenied,
        .INVALID_ADDRESS, .ADDRESS_NOT_ASSOCIATED => error.AddressUnavailable,
        .CANCELLED => error.Canceled,
        else => error.Unexpected,
    };
}

test "Windows TCP AFD statuses preserve retry and cancellation errors" {
    try status(.SUCCESS);
    try std.testing.expectError(error.ConnectionRefused, status(.CONNECTION_REFUSED));
    try std.testing.expectError(error.NetworkUnreachable, status(.NETWORK_UNREACHABLE));
    try std.testing.expectError(error.HostUnreachable, status(.HOST_UNREACHABLE));
    try std.testing.expectError(error.Timeout, status(.IO_TIMEOUT));
    try std.testing.expectError(error.Canceled, status(.CANCELLED));
    try std.testing.expectError(error.AccessDenied, status(.ACCESS_DENIED));
}
