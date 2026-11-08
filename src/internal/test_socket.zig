//! Cross-target fake socket values for tests that never perform I/O on them.
//! POSIX uses an integer descriptor while Windows uses an opaque pointer, so
//! literal zero/one values do not compile on both targets.

const std = @import("std");

pub fn handle() std.Io.net.Socket.Handle {
    if (comptime @typeInfo(std.Io.net.Socket.Handle) == .pointer) {
        return @ptrFromInt(1);
    } else {
        return 1;
    }
}

pub fn socket() std.Io.net.Socket {
    return .{
        .handle = handle(),
        .address = .{ .ip4 = .loopback(0) },
    };
}

pub fn stream() std.Io.net.Stream {
    return .{ .socket = socket() };
}
