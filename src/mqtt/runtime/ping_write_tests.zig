const std = @import("std");
const mqtt = @import("../mod.zig");
const Pair = @import("acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT split PING writes validate budgets and packet direction before output" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        var pair = try Pair.init(io, protocol);
        defer pair.deinit();
        const invalid = std.Io.Clock.Timestamp{ .clock = .real, .raw = std.Io.Clock.real.now(io).addDuration(.fromSeconds(1)) };
        try std.testing.expectError(error.Timeout, pair.client.writePingReqWithTimeout(.zero));
        try std.testing.expectError(error.Timeout, pair.peer.writePingRespWithTimeout(.zero));
        try std.testing.expectError(error.Timeout, pair.client.writePingReqWithDeadline(invalid));
        try std.testing.expectError(error.Timeout, pair.peer.writePingRespWithDeadline(invalid));
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake });
        try std.testing.expectError(error.InvalidPacketDirection, pair.peer.writePingReqWithDeadline(deadline));
        try std.testing.expectError(error.InvalidPacketDirection, pair.client.writePingRespWithDeadline(deadline));
        try std.testing.expect(pair.client.isUsable() and pair.peer.isUsable());
        // Reading the first valid exchange also proves invalid calls wrote no
        // MQTT prefix before reporting their local error.
        try pair.client.writePingReqWithTimeout(.fromSeconds(1));
        try pair.peer.readPingReq();
        try pair.peer.writePingRespWithDeadline(deadline);
        var event = try pair.client.readClientPacketEventWithDeadline(deadline);
        defer event.deinit(allocator);
        try std.testing.expect(event == .pingresp);
    }
}

test "MQTT split PING writes cancel blocked client and server output" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]bool{ false, true }) |response| {
            for ([_]bool{ false, true }) |absolute| {
                var blocked = BlockedWrite{ .delegate = io, .packet_type = if (response) .pingresp else .pingreq };
                BlockedWrite.active = &blocked;
                defer BlockedWrite.active = null;
                var vtable = io.vtable.*;
                vtable.netWrite = BlockedWrite.netWrite;
                const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
                var pair = try Pair.init(observed_io, protocol);
                defer pair.deinit();
                const connection = if (response) &pair.peer else &pair.client;
                blocked.armed.store(true, .release);
                const deadline = std.Io.Clock.Timestamp.fromNow(observed_io, .{ .raw = .fromMilliseconds(30), .clock = .awake });
                const result = if (response)
                    (if (absolute) connection.writePingRespWithDeadline(deadline) else connection.writePingRespWithTimeout(.fromMilliseconds(30)))
                else
                    (if (absolute) connection.writePingReqWithDeadline(deadline) else connection.writePingReqWithTimeout(.fromMilliseconds(30)));
                try std.testing.expectError(error.Timeout, result);
                try std.testing.expect(blocked.entered.load(.acquire));
                try std.testing.expect(blocked.canceled.load(.acquire));
                try std.testing.expect(!connection.isUsable());
            }
        }
    }
}
