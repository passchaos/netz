const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");

pub const Pair = struct {
    client: runtime.Connection,
    peer: runtime.Connection,

    pub fn init(io: std.Io, protocol: mqtt.ProtocolVersion) !Pair {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const client_stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer client_stream.close(io);
        const peer_stream = try listener.accept(io);
        return .{
            .client = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, client_stream), .protocol = protocol, .endpoint_role = .client },
            .peer = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, peer_stream), .protocol = protocol, .endpoint_role = .server },
        };
    }

    pub fn deinit(self: *Pair) void {
        self.client.close();
        self.peer.close();
    }
};
