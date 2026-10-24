const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Pair = struct {
    client: runtime.Connection,
    peer: runtime.Connection,
    fn init(io: std.Io) !Pair {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{
            .client = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, stream) },
            .peer = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, peer) },
        };
    }
    fn deinit(self: *Pair) void {
        self.client.close();
        self.peer.close();
    }
    fn reauth(self: *Pair) !void {
        try self.client.authentication.beginConnect(std.testing.allocator, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
        try self.client.authentication.finishServerInitial();
        try self.client.authentication.beginReauthentication(&.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
    }
    fn success(self: *Pair) !void {
        try self.peer.writeAuth(0, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
    }
};

test "MQTT reauthentication deadline retains ordinary packets and the active exchange" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    try pair.reauth();
    _ = try pair.peer.writePublish("first", "one", .{});
    try std.testing.expectError(error.Timeout, pair.client.receiveReauthenticationWithTimeout(.fromMilliseconds(5)));
    try std.testing.expectEqual(@import("auth.zig").Phase.reauthenticating, pair.client.authentication.phase);
    _ = try pair.peer.writePublish("second", "two", .{});
    try pair.success();
    var result = try pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1));
    defer result.auth.deinit(std.testing.allocator);
    try std.testing.expect(result.complete);
    inline for (.{ "first", "second" }) |topic| {
        var packet = try pair.client.readPublish();
        defer packet.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(topic, packet.publish.topic);
    }
}

test "MQTT reauthentication queue overflow retains all packet bytes for retry" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    try pair.reauth();
    pair.client.limits.max_pending_ping_packets = 1;
    _ = try pair.peer.writePublish("first", "one", .{});
    _ = try pair.peer.writePublish("second", "two", .{});
    try pair.success();
    try std.testing.expectError(error.TooManyPendingPackets, pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1)));
    inline for (.{ "first", "second" }) |topic| {
        var packet = try pair.client.readPublish();
        defer packet.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(topic, packet.publish.topic);
    }
    var result = try pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1));
    defer result.auth.deinit(std.testing.allocator);
    try std.testing.expect(result.complete);
}

test "MQTT reauthentication queued AUTH decoding allocation failure preserves ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    try pair.reauth();
    _ = try pair.peer.writePublish("first", "one", .{});
    try pair.success();
    try pair.peer.writePingResp();
    // A correlated PING wait first retains PUBLISH and AUTH in its queue.
    try pair.client.pingWithTimeout(.fromSeconds(1));
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    {
        pair.client.allocator = failing.allocator();
        defer pair.client.allocator = std.testing.allocator;
        try std.testing.expectError(error.OutOfMemory, pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1)));
    }
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@import("auth.zig").Phase.reauthenticating, pair.client.authentication.phase);
    var result = try pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1));
    defer result.auth.deinit(std.testing.allocator);
    try std.testing.expect(result.complete);
    var packet = try pair.client.readPublish();
    defer packet.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("first", packet.publish.topic);
}

test "MQTT reauthentication DISCONNECT stops the wait and preserves diagnostics" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    try pair.reauth();
    _ = try pair.peer.writePublish("first", "one", .{});
    try pair.peer.writeDisconnectWithProperties(0x87, &.{.{ .utf8 = .{ .id = .reason_string, .value = "expired" } }});
    try std.testing.expectError(error.ConnectionClosed, pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1)));
    try std.testing.expectError(error.ConnectionClosed, pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1)));
    try std.testing.expect(!pair.client.isUsable());
    try std.testing.expectError(error.ConnectionClosed, pair.client.writePingReq());
    var first = try pair.client.readPublish();
    defer first.deinit(std.testing.allocator);
    var refused = try pair.client.readDisconnect();
    defer refused.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0x87), refused.disconnect.reason_code);
    try std.testing.expectEqualStrings("expired", refused.disconnect.properties[0].utf8.value);
    try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
}
