//! Windows Winsock peer queries and portable SOCKADDR decoding.

const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const ws = std.os.windows.ws2_32;

const native = struct {
    extern "ws2_32" fn getpeername(
        socket: *opaque {},
        address: *ws.sockaddr,
        length: *c_int,
    ) callconv(.winapi) c_int;
};

/// The caller must establish that this is a Winsock socket, not a foreign
/// std.Io backend's native file/AFD handle. The query never drives network IO.
pub fn query(stream: net.Stream) ?net.IpAddress {
    if (comptime builtin.os.tag != .windows) return null;
    var address: ws.sockaddr.storage = .{ .family = 0 };
    var length: c_int = @sizeOf(@TypeOf(address));
    if (native.getpeername(
        @ptrCast(stream.socket.handle),
        @ptrCast(&address),
        &length,
    ) != 0) return null;
    if (length < 0 or length > @sizeOf(@TypeOf(address))) return null;
    return decode(std.mem.asBytes(&address)[0..@intCast(length)]);
}

/// Windows SOCKADDR_IN/SOCKADDR_IN6 use little-endian family, flow and scope
/// fields, a network-order port, and unchanged IP octets. Keep this boundary
/// independent of the host's sockaddr layout so fixed Windows vectors can be
/// verified on every platform.
pub fn decode(bytes: []const u8) ?net.IpAddress {
    if (bytes.len < 2) return null;
    return switch (std.mem.readInt(u16, bytes[0..2], .little)) {
        ws.AF.INET => if (bytes.len >= 16) .{ .ip4 = .{
            .port = std.mem.readInt(u16, bytes[2..4], .big),
            .bytes = bytes[4..8].*,
        } } else null,
        ws.AF.INET6 => if (bytes.len >= 28) .{ .ip6 = .{
            .port = std.mem.readInt(u16, bytes[2..4], .big),
            .flow = std.mem.readInt(u32, bytes[4..8], .little),
            .bytes = bytes[8..24].*,
            .interface = .{ .index = std.mem.readInt(u32, bytes[24..28], .little) },
        } } else null,
        else => null,
    };
}

pub const Encoded = struct {
    bytes: [28]u8 align(4) = @splat(0),
    len: usize,

    pub fn init(address: net.IpAddress) Encoded {
        var result: Encoded = .{ .len = if (address == .ip4) 16 else 28 };
        switch (address) {
            .ip4 => |ip4| {
                std.mem.writeInt(u16, result.bytes[0..2], ws.AF.INET, .little);
                std.mem.writeInt(u16, result.bytes[2..4], ip4.port, .big);
                result.bytes[4..8].* = ip4.bytes;
            },
            .ip6 => |ip6| {
                std.mem.writeInt(u16, result.bytes[0..2], ws.AF.INET6, .little);
                std.mem.writeInt(u16, result.bytes[2..4], ip6.port, .big);
                std.mem.writeInt(u32, result.bytes[4..8], ip6.flow, .little);
                result.bytes[8..24].* = ip6.bytes;
                std.mem.writeInt(u32, result.bytes[24..28], ip6.interface.index, .little);
            },
        }
        return result;
    }
};

test {
    _ = @import("winsock_tests.zig");
}
