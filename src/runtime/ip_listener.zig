//! Backend-aware TCP listener construction for socket options that Zig's
//! `std.Io.net.IpAddress.ListenOptions` does not expose yet.

const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const interfaces = @import("../internal/network_interface.zig");

const net = std.Io.net;

const supports_interface_addresses = switch (builtin.os.tag) {
    .linux, .macos, .ios, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

const IfAddrs = extern struct {
    next: ?*IfAddrs,
    name: [*:0]const u8,
    flags: c_uint,
    address: ?*const zio.os.net.sockaddr,
    netmask: ?*const zio.os.net.sockaddr,
    ifu: ?*const zio.os.net.sockaddr,
    data: ?*anyopaque,
};

const libc = if (supports_interface_addresses) struct {
    extern "c" fn getifaddrs(result: *?*IfAddrs) c_int;
    extern "c" fn freeifaddrs(addresses: *IfAddrs) void;
} else struct {};

pub const InterfaceAddresses = struct {
    ip4: ?net.IpAddress = null,
    ip6: ?net.IpAddress = null,

    pub fn count(self: InterfaceAddresses) usize {
        return @as(usize, @intFromBool(self.ip4 != null)) +
            @as(usize, @intFromBool(self.ip6 != null));
    }
};

pub const InterfaceAddressError = error{
    InvalidInterfaceName,
    InterfaceNotFound,
    AddressFamilyUnsupported,
    SystemResources,
    OptionUnsupported,
    Unexpected,
};

pub const Options = struct {
    /// Native send/receive device constraint, applied before bind/listen.
    network_interface: ?interfaces.NetworkInterface = null,
    kernel_backlog: u31 = std.Io.net.default_kernel_backlog,
    reuse_address: bool = false,
    /// Null leaves the platform default unchanged. False explicitly permits
    /// IPv4-mapped connections and true rejects them. Either explicit policy
    /// must be applied before bind, so unsupported backends fail closed.
    ip6_only: ?bool = null,
};

/// Return the first IPv4 and IPv6 addresses assigned to a named interface,
/// matching Mosquitto's listener selection. The result borrows no libc state.
pub fn resolveInterfaceAddresses(
    name: []const u8,
    port: u16,
) InterfaceAddressError!InterfaceAddresses {
    if (comptime !supports_interface_addresses) {
        return error.OptionUnsupported;
    }
    if (name.len == 0 or std.mem.indexOfScalar(u8, name, 0) != null) {
        return error.InvalidInterfaceName;
    }

    var head: ?*IfAddrs = null;
    const rc = libc.getifaddrs(&head);
    if (rc != 0) {
        return switch (std.posix.errno(rc)) {
            .NOMEM => error.SystemResources,
            else => error.Unexpected,
        };
    }
    defer if (head) |addresses| libc.freeifaddrs(addresses);

    var found_interface = false;
    var result: InterfaceAddresses = .{};
    var current = head;
    while (current) |entry| : (current = entry.next) {
        if (!std.ascii.eqlIgnoreCase(name, std.mem.span(entry.name))) continue;
        found_interface = true;
        const address = entry.address orelse continue;
        const address_len: zio.os.net.socklen_t = switch (address.family) {
            zio.os.net.AF.INET => @sizeOf(zio.os.net.sockaddr.in),
            zio.os.net.AF.INET6 => @sizeOf(zio.os.net.sockaddr.in6),
            else => continue,
        };
        var resolved = stdIpAddress(
            zio.net.Address.fromPosix(address, address_len).ip,
        );
        resolved.setPort(port);
        switch (resolved) {
            .ip4 => {
                if (result.ip4 == null) result.ip4 = resolved;
            },
            .ip6 => {
                if (result.ip6 == null) result.ip6 = resolved;
            },
        }
        if (result.count() == 2) break;
    }
    if (!found_interface) return error.InterfaceNotFound;
    if (result.count() == 0) return error.AddressFamilyUnsupported;
    return result;
}

/// Create a TCP listener while retaining Netz's `std.Io.net.Server` protocol
/// boundary. The current Netz runtime is zio-backed; foreign I/O backends are
/// rejected when they cannot promise the requested pre-bind socket policy.
pub fn listen(
    io: std.Io,
    address: net.IpAddress,
    options: Options,
) (net.IpAddress.ListenError || interfaces.Error)!net.Server {
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
    if (options.network_interface) |interface| try interfaces.apply(io, stdIoSocketHandle(socket.handle), std.meta.activeTag(address), .stream, interface);

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

test "interface address resolution selects loopback addresses" {
    if (comptime !supports_interface_addresses) return error.SkipZigTest;

    const interface_name = if (builtin.os.tag.isDarwin()) "lo0" else "lo";
    const addresses = try resolveInterfaceAddresses(interface_name, 1883);
    const ip4 = addresses.ip4 orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual([_]u8{ 127, 0, 0, 1 }, ip4.ip4.bytes);
    try std.testing.expectEqual(@as(u16, 1883), ip4.getPort());
    try std.testing.expectError(
        error.InterfaceNotFound,
        resolveInterfaceAddresses("netz-interface-that-does-not-exist", 1883),
    );
}
