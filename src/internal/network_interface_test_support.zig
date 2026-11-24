//! Live native assertions reused by transport binding regressions.
const std = @import("std");
const builtin = @import("builtin");
const interfaces = @import("network_interface.zig");
const net = std.Io.net;

pub fn loopback() interfaces.NetworkInterface {
    return .{ .name = switch (builtin.os.tag) {
        .linux => "lo",
        .windows => "Loopback Pseudo-Interface 1",
        else => "lo0",
    } };
}

pub fn supportedTcp() bool {
    return builtin.os.tag == .linux or builtin.os.tag == .macos;
}

pub fn expectBound(io: std.Io, socket: net.Socket) !void {
    const interface = try loopback().resolve(io);
    const family = std.meta.activeTag(socket.address);
    if (comptime builtin.os.tag == .linux) {
        var name: [net.Interface.Name.max_len + 1]u8 = undefined;
        const size = try getOption(socket.handle, std.posix.SOL.SOCKET, std.posix.SO.BINDTODEVICE, &name);
        try std.testing.expect(size > 0);
        try std.testing.expectEqualStrings("lo", std.mem.sliceTo(name[0..size], 0));
    } else if (comptime builtin.os.tag == .windows) {
        const level: i32 = if (family == .ip4) 0 else 41;
        try expectInteger(socket.handle, level, 31, interface.index);
        var enabled: u32 = 0;
        const enabled_len = try getOption(socket.handle, level, 28, std.mem.asBytes(&enabled));
        try std.testing.expect(enabled_len == 1 or enabled_len == @sizeOf(u32));
        try std.testing.expect(enabled != 0);
        try expectInteger(socket.handle, level, 33, interface.index);
    } else {
        try expectInteger(socket.handle, if (family == .ip4) 0 else 41, if (family == .ip4) 25 else 125, interface.index);
    }
}

fn expectInteger(handle: net.Socket.Handle, level: i32, option: u32, expected: u32) !void {
    var actual: u32 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try getOption(handle, level, option, std.mem.asBytes(&actual)));
    try std.testing.expectEqual(expected, actual);
}

fn getOption(handle: net.Socket.Handle, level: i32, option: u32, bytes: []u8) !usize {
    if (comptime builtin.os.tag == .windows) {
        const native = struct {
            extern "ws2_32" fn getsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]u8, length: *c_int) callconv(.winapi) c_int;
        };
        var length: c_int = @intCast(bytes.len);
        try std.testing.expectEqual(@as(c_int, 0), native.getsockopt(@ptrCast(handle), level, @intCast(option), bytes.ptr, &length));
        return @intCast(length);
    } else {
        var length: std.posix.socklen_t = @intCast(bytes.len);
        const result = std.posix.system.getsockopt(handle, level, option, bytes.ptr, &length);
        try std.testing.expectEqual(std.posix.E.SUCCESS, std.posix.errno(result));
        return @intCast(length);
    }
}
