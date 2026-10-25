const std = @import("std");
const mqtt = @import("../../mod.zig");
const Pair = @import("../acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;
const properties = [_]mqtt.Property{
    .{ .four_byte = .{ .id = .session_expiry_interval, .value = 5 } },
    .{ .utf8 = .{ .id = .reason_string, .value = "finished" } },
};

test "MQTT DISCONNECT budgets validate before output and commit Session expiry after success" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        var pair = try Pair.init(io, protocol);
        defer pair.deinit();
        pair.client.connect_session_expiry = 60;
        pair.peer.connect_session_expiry = 60;
        pair.client.session_expiry_interval = 60;
        const fields: []const mqtt.Property = if (protocol == .v5) &properties else &.{};
        const foreign = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .real });
        try std.testing.expectError(error.Timeout, pair.client.writeDisconnectWithDeadline(0, fields, foreign));
        try std.testing.expectError(error.Timeout, pair.client.writeDisconnectWithDeadline(0, fields, std.Io.Timestamp.zero.withClock(.awake)));
        try std.testing.expectError(error.Timeout, pair.client.writeDisconnectWithTimeout(0, fields, .zero));
        try std.testing.expect(pair.client.isUsable());
        try std.testing.expectEqual(@as(u32, 60), pair.client.session_expiry_interval);
        if (protocol == .v5) {
            try std.testing.expectError(error.InvalidProperty, pair.peer.writeDisconnectWithDeadline(0, &properties, .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake })));
            try std.testing.expect(pair.peer.isUsable());
        }
        try std.testing.expectError(error.Timeout, pair.peer.readBrokerEventWithTimeout(.fromMilliseconds(5)));
        try pair.client.writeDisconnectWithTimeout(0, fields, .fromSeconds(1));
        var disconnect = try pair.peer.readDisconnect();
        defer disconnect.deinit(allocator);
        try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
        try std.testing.expectEqual(@as(u32, if (protocol == .v5) 5 else 60), pair.client.session_expiry_interval);
        try std.testing.expect(!pair.client.isUsable());
        if (protocol == .v5) try std.testing.expectEqual(@as(u32, 5), mqtt.sessionExpiryInterval(disconnect.disconnect.properties).?);
    }
}

test "MQTT DISCONNECT expiry is unchanged after a canceled write" {
    for ([_]bool{ false, true }) |absolute| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var blocked = BlockedWrite{ .delegate = io, .packet_type = .disconnect };
        BlockedWrite.active = &blocked;
        defer BlockedWrite.active = null;
        var vtable = io.vtable.*;
        vtable.netWrite = BlockedWrite.netWrite;
        const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
        var pair = try Pair.init(observed_io, .v5);
        defer pair.deinit();
        pair.client.connect_session_expiry = 60;
        pair.client.session_expiry_interval = 60;
        blocked.armed.store(true, .release);
        const timeout = std.Io.Duration.fromMilliseconds(50);
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = timeout, .clock = .awake });
        try std.testing.expectError(error.Timeout, if (absolute) pair.client.writeDisconnectWithDeadline(0, &properties, deadline) else pair.client.writeDisconnectWithTimeout(0, &properties, timeout));
        try std.testing.expect(blocked.canceled.load(.acquire));
        try std.testing.expectEqual(@as(u32, 60), pair.client.session_expiry_interval);
        try std.testing.expect(!pair.client.isUsable());
    }
}
