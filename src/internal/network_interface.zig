//! Native interface constraints, independent of source address selection.
const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const net = std.Io.net;
const windows_native = struct {
    extern "ws2_32" fn setsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]const u8, length: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn getsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]u8, length: *c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
};

pub const Error = net.Interface.Name.ResolveError || net.Interface.NameError || error{
    InvalidNetworkInterface,
    OptionUnsupported,
    SocketOptionFailed,
};

/// A socket routing constraint. Names are borrowed for the owning client's
/// lifetime. Windows accepts an adapter alias (for example `Ethernet`) or its
/// canonical interface name; POSIX uses `en0`, `eth0`, etc.
pub const NetworkInterface = union(enum) {
    name: []const u8,
    index: u32,

    pub fn resolve(self: NetworkInterface, io: std.Io) Error!net.Interface {
        switch (self) {
            .index => |index| {
                if (index == 0) return error.InvalidNetworkInterface;
                return .{ .index = index };
            },
            .name => |name| {
                if (name.len == 0 or std.mem.indexOfScalar(u8, name, 0) != null) {
                    return error.InvalidNetworkInterface;
                }
                if (comptime builtin.os.tag == .windows) return resolveWindows(name);
                const native = try net.Interface.Name.fromSlice(name);
                const result = try native.resolve(io);
                if (result.index == 0) return error.InterfaceNotFound;
                return result;
            },
        }
    }
};

/// Prepare a native UDP socket before interface policy and bind.
pub fn prepareDatagram(handle: net.Socket.Handle, family: net.IpAddress.Family) Error!void {
    if (comptime builtin.os.tag == .windows) {
        if (family == .ip6) {
            const enabled: u32 = 1;
            try setOption(handle, 41, 27, std.mem.asBytes(&enabled));
        }
    }
}

/// Validate the actual family policy once a native UDP socket is bound.
/// This also checks caller-owned sockets when an association is adopted.
pub fn validateDatagramFamily(handle: net.Socket.Handle, family: net.IpAddress.Family) Error!void {
    if (comptime builtin.os.tag == .windows) {
        if (family == .ip6) {
            var ipv6_only: u32 = 0;
            var length: c_int = @sizeOf(u32);
            if (windows_native.getsockopt(@ptrCast(handle), 41, 27, std.mem.asBytes(&ipv6_only).ptr, &length) != 0) return error.SocketOptionFailed;
            // Winsock providers may report BOOLEAN (one byte) or DWORD for
            // boolean options. Zero-initialize the remaining bytes before
            // decoding the value; interface indices still require DWORD.
            if ((length != 1 and length != @sizeOf(u32)) or ipv6_only == 0) {
                if (comptime @import("builtin").is_test) std.debug.print("Winsock V6ONLY length={d} value={d}\n", .{ length, ipv6_only });
                return error.OptionUnsupported;
            }
        }
    }
}

/// Apply before TCP connect or the first UDP send. Windows foreign backends
/// can expose AFD handles rather than Winsock sockets and are rejected.
pub fn apply(io: std.Io, handle: net.Socket.Handle, family: net.IpAddress.Family, mode: net.Socket.Mode, interface: NetworkInterface) Error!void {
    if (comptime builtin.os.tag == .windows) {
        _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
        // Winsock has no device constraint for received TCP packets.
        if (mode != .dgram) return error.OptionUnsupported;
    }
    const resolved = try interface.resolve(io);
    switch (comptime builtin.os.tag) {
        .linux => {
            const name = try resolved.name(io);
            try setOption(handle, std.posix.SOL.SOCKET, std.posix.SO.BINDTODEVICE, name.bytes[0 .. name.toSlice().len + 1]);
        },
        .macos, .ios, .tvos, .watchos, .visionos => {
            // Darwin <netinet/in.h>, <netinet6/in6.h> stable socket ABI.
            const level: i32 = if (family == .ip4) 0 else 41;
            const option: u32 = if (family == .ip4) 25 else 125;
            try setOption(handle, level, option, std.mem.asBytes(&resolved.index));
        },
        .windows => {
            // Constrain both outgoing unicast and incoming datagrams.
            // UNICAST_IF alone would leave reception unconstrained.
            if (family == .ip4 and resolved.index > 0x00ffffff) return error.InvalidNetworkInterface;
            const level: i32 = if (family == .ip4) 0 else 41;
            const value = windowsIndex(family, resolved.index);
            try setOption(handle, level, 31, std.mem.asBytes(&value));
            const enabled: u32 = 1;
            try setOption(handle, level, 28, std.mem.asBytes(&enabled));
            try setOption(handle, level, 29, std.mem.asBytes(&resolved.index));
        },
        else => return error.OptionUnsupported,
    }
}

fn windowsIndex(family: net.IpAddress.Family, index: u32) u32 {
    return if (family == .ip4) std.mem.nativeToBig(u32, index) else index;
}

fn setOption(handle: net.Socket.Handle, level: i32, option: u32, bytes: []const u8) Error!void {
    if (comptime builtin.os.tag == .windows) {
        if (windows_native.setsockopt(@ptrCast(handle), level, @intCast(option), bytes.ptr, @intCast(bytes.len)) != 0) {
            return switch (windows_native.WSAGetLastError()) {
                10013 => error.AccessDenied,
                10042, 10045 => error.OptionUnsupported,
                10022 => error.InvalidNetworkInterface,
                10049 => error.InterfaceNotFound,
                else => error.SocketOptionFailed,
            };
        }
    } else {
        const result = std.posix.system.setsockopt(handle, level, option, bytes.ptr, @intCast(bytes.len));
        return switch (std.posix.errno(result)) {
            .SUCCESS => {},
            .ACCES, .PERM => error.AccessDenied,
            .NOPROTOOPT, .OPNOTSUPP => error.OptionUnsupported,
            .NODEV, .NXIO => error.InterfaceNotFound,
            .INVAL => error.InvalidNetworkInterface,
            .NOMEM, .NOBUFS => error.SystemResources,
            else => error.SocketOptionFailed,
        };
    }
}

fn resolveWindows(name: []const u8) Error!net.Interface {
    // std.Io Interface.Name has zero capacity on Windows in Zig 0.16.
    // Use IP Helper's UTF-16 API without exposing OS types to callers.
    if (name.len > 768) return error.NameTooLong;
    var wide: [769:0]u16 = undefined;
    const length = std.unicode.utf8ToUtf16Le(&wide, name) catch return error.InvalidNetworkInterface;
    if (length > 256) return error.NameTooLong;
    wide[length] = 0;
    const windows = std.os.windows;
    var library: *anyopaque = undefined;
    switch (windows.ntdll.LdrLoadDll(null, null, &.init(std.unicode.utf8ToUtf16LeStringLiteral("iphlpapi.dll")), &library)) {
        .SUCCESS => {},
        else => return error.OptionUnsupported,
    }
    defer _ = windows.ntdll.LdrUnloadDll(library);
    const NameToLuid = *const fn ([*:0]const u16, *u64) callconv(.winapi) u32;
    const LuidToIndex = *const fn (*const u64, *u32) callconv(.winapi) u32;
    const alias_fn = try lookupWindows(NameToLuid, library, "ConvertInterfaceAliasToLuid");
    const name_fn = try lookupWindows(NameToLuid, library, "ConvertInterfaceNameToLuidW");
    const index_fn = try lookupWindows(LuidToIndex, library, "ConvertInterfaceLuidToIndex");
    var luid: u64 = undefined;
    if (alias_fn(@ptrCast(&wide), &luid) != 0 and name_fn(@ptrCast(&wide), &luid) != 0) return error.InterfaceNotFound;
    var index: u32 = undefined;
    if (index_fn(&luid, &index) != 0 or index == 0) return error.InterfaceNotFound;
    return .{ .index = index };
}

fn lookupWindows(comptime Function: type, library: *anyopaque, symbol: []const u8) Error!Function {
    var result: std.os.windows.PVOID = undefined;
    switch (std.os.windows.ntdll.LdrGetProcedureAddress(library, &.init(symbol), 0, &result)) {
        .SUCCESS => return @ptrCast(result),
        else => return error.OptionUnsupported,
    }
}

test "network interface validates names and indices without a socket" {
    inline for (.{ NetworkInterface{ .index = 0 }, NetworkInterface{ .name = "" }, NetworkInterface{ .name = "en0\x00other" } }) |interface| {
        try std.testing.expectError(error.InvalidNetworkInterface, interface.resolve(undefined));
    }
    try std.testing.expectEqual(@as(u32, 7), (try (NetworkInterface{ .index = 7 }).resolve(undefined)).index);
}

test "network interface Windows IPv4 and IPv6 option byte order" {
    const ip4 = windowsIndex(.ip4, 0x01020304);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, std.mem.asBytes(&ip4));
    try std.testing.expectEqual(@as(u32, 0x01020304), windowsIndex(.ip6, 0x01020304));
}

test "network interface rejects missing devices and overlong names" {
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    try std.testing.expectError(error.InterfaceNotFound, (NetworkInterface{ .name = "netz_missing" }).resolve(backend.io()));
    const long_name: [1024]u8 = @splat('x');
    try std.testing.expectError(error.NameTooLong, (NetworkInterface{ .name = &long_name }).resolve(backend.io()));
}
