//! Native socket creation with independent address and interface constraints.
const std = @import("std");
const zio = @import("zio");
const interfaces = @import("network_interface.zig");
const net = std.Io.net;

pub const NetworkInterface = interfaces.NetworkInterface;
pub const Error = interfaces.Error;
pub const applyInterface = interfaces.apply;
pub const validateDatagramFamily = interfaces.validateDatagramFamily;
pub const ConnectError = net.IpAddress.ConnectError || Error || error{AddressInUse};

pub const Binding = struct {
    local_address: ?net.IpAddress = null,
    network_interface: ?NetworkInterface = null,

    pub fn fromOptions(options: anytype) Binding {
        return .{ .local_address = options.local_address, .network_interface = options.network_interface };
    }

    pub fn isRequested(self: Binding) bool {
        return self.local_address != null or self.network_interface != null;
    }
};

pub fn connect(io: std.Io, address: net.IpAddress, binding: Binding, timeout: zio.Timeout) ConnectError!net.Stream {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    const local_address = binding.local_address orelse switch (address) {
        .ip4 => net.IpAddress{ .ip4 = .unspecified(0) },
        .ip6 => net.IpAddress{ .ip6 = .unspecified(0) },
    };
    if (std.meta.activeTag(address) != std.meta.activeTag(local_address)) return error.AddressFamilyUnsupported;
    const family = std.meta.activeTag(address);
    var socket = zio.net.Socket.open(.stream, if (family == .ip4) .ipv4 else .ipv6, .tcp) catch |err| return mapConnectError(err);
    errdefer socket.close();
    if (binding.network_interface) |interface| try interfaces.apply(io, stdHandle(socket.handle), family, .stream, interface);
    socket.bind(.{ .ip = zioAddress(local_address) }) catch |err| return mapConnectError(err);
    const bound_address = stdAddress(socket.address.ip);
    socket.connect(.{ .ip = zioAddress(address) }, .{ .timeout = timeout }) catch |err| return mapConnectError(err);
    return .{ .socket = .{ .handle = stdHandle(socket.handle), .address = bound_address } };
}

/// Install a requested interface before bind, so the socket never queues
/// datagrams from another device. Unconstrained source binds retain std.Io.
pub fn bindDatagram(io: std.Io, address: net.IpAddress, interface: ?NetworkInterface) (net.IpAddress.BindError || Error)!net.Socket {
    const selected = interface orelse return address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    const family = std.meta.activeTag(address);
    var socket = zio.net.Socket.open(.dgram, if (family == .ip4) .ipv4 else .ipv6, .udp) catch |err| return mapDatagramBindError(err);
    errdefer socket.close();
    try interfaces.prepareDatagram(stdHandle(socket.handle), family);
    try interfaces.apply(io, stdHandle(socket.handle), family, .dgram, selected);
    socket.bind(.{ .ip = zioAddress(address) }) catch |err| return mapDatagramBindError(err);
    try interfaces.validateDatagramFamily(stdHandle(socket.handle), family);
    return .{ .handle = stdHandle(socket.handle), .address = stdAddress(socket.address.ip) };
}

fn mapDatagramBindError(err: anyerror) (net.IpAddress.BindError || Error) {
    return switch (err) {
        error.AddressInUse => error.AddressInUse,
        error.AddressUnavailable => error.AddressUnavailable,
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.SystemResources => error.SystemResources,
        error.NetworkDown => error.NetworkDown,
        error.ProtocolUnsupportedBySystem, error.ProtocolNotSupported => error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily => error.ProtocolUnsupportedByAddressFamily,
        error.ProcessFdQuotaExceeded => error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded => error.SystemFdQuotaExceeded,
        error.SocketModeUnsupported => error.SocketModeUnsupported,
        error.OptionUnsupported => error.OptionUnsupported,
        error.AccessDenied => error.AccessDenied,
        error.Canceled => error.Canceled,
        else => error.Unexpected,
    };
}

/// A requested device policy is installed before bind/listen, so queued
/// incoming TCP handshakes cannot predate the constraint.
pub fn listenTcp(io: std.Io, address: net.IpAddress, options: net.IpAddress.ListenOptions, interface: ?NetworkInterface) (net.IpAddress.ListenError || Error)!net.Server {
    if (interface) |selected| {
        if (options.mode != .stream or options.protocol != .tcp) return error.OptionUnsupported;
        return @import("../runtime/ip_listener.zig").listen(io, address, .{
            .kernel_backlog = options.kernel_backlog,
            .reuse_address = options.reuse_address,
            .network_interface = selected,
        });
    }
    return address.listen(io, options);
}

fn zioAddress(address: net.IpAddress) zio.net.IpAddress {
    return switch (address) {
        .ip4 => |ip4| .initIp4(ip4.bytes, ip4.port),
        .ip6 => |ip6| .initIp6(ip6.bytes, ip6.port, ip6.flow, ip6.interface.index),
    };
}

fn stdAddress(address: zio.net.IpAddress) net.IpAddress {
    return switch (address.getFamily()) {
        .ipv4 => .{ .ip4 = .{ .bytes = @bitCast(address.in.addr), .port = std.mem.bigToNative(u16, address.in.port) } },
        .ipv6 => .{ .ip6 = .{ .bytes = address.in6.addr, .port = std.mem.bigToNative(u16, address.in6.port), .flow = address.in6.flowinfo, .interface = .{ .index = address.in6.scope_id } } },
    };
}

fn stdHandle(handle: @FieldType(zio.net.Socket, "handle")) net.Socket.Handle {
    return if (@typeInfo(net.Socket.Handle) == .pointer) @ptrCast(handle) else @intCast(handle);
}

fn mapConnectError(err: anyerror) ConnectError {
    return switch (err) {
        error.AccessDenied => error.AccessDenied,
        error.AddressInUse => error.AddressInUse,
        error.AddressUnavailable => error.AddressUnavailable,
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.Canceled => error.Canceled,
        error.ConnectionPending => error.ConnectionPending,
        error.ConnectionRefused => error.ConnectionRefused,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.HostUnreachable => error.HostUnreachable,
        error.NetworkDown => error.NetworkDown,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.ProcessFdQuotaExceeded => error.ProcessFdQuotaExceeded,
        error.ProtocolUnsupportedByAddressFamily => error.ProtocolUnsupportedByAddressFamily,
        error.ProtocolUnsupportedBySystem => error.ProtocolUnsupportedBySystem,
        error.SocketModeUnsupported => error.SocketModeUnsupported,
        error.SystemFdQuotaExceeded => error.SystemFdQuotaExceeded,
        error.SystemResources => error.SystemResources,
        error.Timeout => error.Timeout,
        error.WouldBlock => error.WouldBlock,
        else => error.Unexpected,
    };
}
