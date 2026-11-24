//! Read-only interface policy checks for caller-owned native sockets.
const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const interfaces = @import("../network_interface.zig");
const net = std.Io.net;
const Error = interfaces.Error;

/// Adoption asserts an existing constraint instead of installing one after
/// bind. Rejection leaves the caller's socket and receive policy unchanged.
pub fn require(io: std.Io, socket: net.Socket, requested: interfaces.NetworkInterface) Error!void {
    _ = zio.Runtime.fromIo(io) orelse return error.OptionUnsupported;
    const expected = try requested.resolve(io);
    const family = std.meta.activeTag(socket.address);
    switch (comptime builtin.os.tag) {
        .linux => {
            var name: [net.Interface.Name.max_len + 1]u8 = @splat(0);
            const length = get(socket.handle, std.posix.SOL.SOCKET, std.posix.SO.BINDTODEVICE, &name) catch |err| return scalarError(err);
            if (length > name.len) return error.SocketOptionFailed;
            const actual = std.mem.sliceTo(name[0..length], 0);
            const expected_name = try expected.name(io);
            if (!std.mem.eql(u8, actual, expected_name.toSlice())) return error.InterfaceBindingMismatch;
        },
        .macos, .ios, .tvos, .watchos, .visionos => {
            const actual = try integer(socket.handle, if (family == .ip4) 0 else 41, if (family == .ip4) 25 else 125);
            if (actual != expected.index) return error.InterfaceBindingMismatch;
        },
        .windows => {
            try interfaces.validateDatagramFamily(socket.handle, family);
            const level: i32 = if (family == .ip4) 0 else 41;
            // Winsock returns UNICAST_IF indices in host byte order.
            if (try integer(socket.handle, level, 31) != expected.index) return error.InterfaceBindingMismatch;
            var enabled: u32 = 0;
            const boolean_size = get(socket.handle, level, 28, std.mem.asBytes(&enabled)) catch |err| return scalarError(err);
            if (boolean_size != 1 and boolean_size != @sizeOf(u32)) return error.SocketOptionFailed;
            if (enabled == 0) return error.InterfaceBindingMismatch;
            // A second entry, or a list too large for this buffer, proves the
            // socket also admits another interface. Do not broaden/rewrite it.
            var received: [2]u32 = @splat(0);
            const length = get(socket.handle, level, 33, std.mem.asBytes(&received)) catch |err| switch (err) {
                error.BufferTooSmall => return error.InterfaceBindingMismatch,
                else => |other| return other,
            };
            if (length != @sizeOf(u32) or received[0] != expected.index) return error.InterfaceBindingMismatch;
        },
        else => return error.OptionUnsupported,
    }
}

fn integer(handle: net.Socket.Handle, level: i32, option: u32) Error!u32 {
    var value: u32 = 0;
    if ((get(handle, level, option, std.mem.asBytes(&value)) catch |err| return scalarError(err)) != @sizeOf(u32)) return error.SocketOptionFailed;
    return value;
}

fn scalarError(err: anyerror) Error {
    return switch (err) {
        error.BufferTooSmall => error.SocketOptionFailed,
        else => @errorCast(err),
    };
}

fn get(handle: net.Socket.Handle, level: i32, option: u32, bytes: []u8) (Error || error{BufferTooSmall})!usize {
    if (comptime builtin.os.tag == .windows) {
        const native = struct {
            extern "ws2_32" fn getsockopt(socket: *opaque {}, level: c_int, option: c_int, value: [*]u8, length: *c_int) callconv(.winapi) c_int;
            extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
        };
        var length: c_int = @intCast(bytes.len);
        if (native.getsockopt(@ptrCast(handle), level, @intCast(option), bytes.ptr, &length) != 0) return switch (native.WSAGetLastError()) {
            10014 => error.BufferTooSmall,
            10055 => error.SystemResources,
            10042, 10045 => error.OptionUnsupported,
            10013 => error.AccessDenied,
            else => error.SocketOptionFailed,
        };
        if (length < 0 or @as(usize, @intCast(length)) > bytes.len) return error.SocketOptionFailed;
        return @intCast(length);
    } else {
        var length: std.posix.socklen_t = @intCast(bytes.len);
        const result = std.posix.system.getsockopt(handle, level, option, bytes.ptr, &length);
        return switch (std.posix.errno(result)) {
            .SUCCESS => @intCast(length),
            .NOPROTOOPT, .OPNOTSUPP => error.OptionUnsupported,
            .ACCES, .PERM => error.AccessDenied,
            .NOBUFS, .NOMEM => error.SystemResources,
            else => error.SocketOptionFailed,
        };
    }
}
