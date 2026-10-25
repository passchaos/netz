const std = @import("std");
const mqtt = @import("../../mod.zig");
const Pair = @import("../acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT bounded receive diagnostics preserve authentication errors and retire transport" {
    const Mode = enum { client, broker, typed };
    for (std.enums.values(Mode)) |mode| {
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
        try pair.client.authentication.beginConnect(allocator, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
        _ = try pair.peer.writePublish("too/early", "before authentication", .{});
        blocked.armed.store(true, .release);
        const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromMilliseconds(50), .clock = .awake });
        switch (mode) {
            .client => try std.testing.expectError(error.AuthenticationInProgress, pair.client.readClientPacketEventWithDeadline(deadline)),
            .broker => try std.testing.expectError(error.AuthenticationInProgress, pair.client.readBrokerEventWithDeadline(deadline)),
            .typed => try std.testing.expectError(error.AuthenticationInProgress, pair.client.readAuthWithDeadline(deadline)),
        }
        try std.testing.expect(blocked.entered.load(.acquire));
        try std.testing.expect(blocked.canceled.load(.acquire));
        try std.testing.expect(!pair.client.isUsable());
    }
}
