const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const Pair = @import("../runtime/acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT reconnect protocol diagnostics share poll deadlines and preserve the original error" {
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
        var shutdown: std.Io.Event = .unset;
        var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{
            .protocol = .v5,
            .client_id = "diagnostic-budget",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
        }, .{}, &shutdown);
        defer client.deinit();
        const pair = try Pair.init(observed_io, .v5);
        client.connection_state = pair.client;
        client.connection().?.session_expiry_interval = 60;
        var peer = pair.peer;
        defer peer.close();
        _ = try client.publishOneAttempt("kept/after-diagnostic", "owned", .{ .qos = .at_least_once });
        var publish = try peer.readPublish();
        publish.deinit(allocator);
        try peer.writePubAck(99, 0);
        blocked.armed.store(true, .release);
        const outcome = if (absolute)
            client.pollWithDeadline(std.Io.Clock.awake.now(io).addDuration(.fromMilliseconds(50)), .{ .reconnect_after_transport_error = false })
        else
            client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false });
        try std.testing.expectError(error.InvalidAcknowledgement, outcome);
        try std.testing.expect(blocked.entered.load(.acquire));
        try std.testing.expect(blocked.canceled.load(.acquire));
        try std.testing.expect(client.connection() == null);
        const stats = try client.outgoing.stats(client.outgoing_handle);
        try std.testing.expectEqual(@as(usize, 1), stats.queued_count + stats.inflight_count);
    }
}

test "MQTT reconnect AUTH diagnostics share the poll deadline" {
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
        var shutdown: std.Io.Event = .unset;
        var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{ .protocol = .v5, .client_id = "poll-auth-diagnostic" }, .{}, &shutdown);
        defer client.deinit();
        const pair = try Pair.init(observed_io, .v5);
        client.connection_state = pair.client;
        var peer = pair.peer;
        defer peer.close();
        try client.connection().?.authentication.beginConnect(allocator, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
        client.connection().?.authentication.phase = .reauthenticating;
        try peer.writeAuth(0x18, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "other" } }});
        blocked.armed.store(true, .release);
        const result = if (absolute)
            client.pollWithDeadline(std.Io.Clock.awake.now(io).addDuration(.fromMilliseconds(50)), .{ .reconnect_after_transport_error = false })
        else
            client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false });
        try std.testing.expectError(error.AuthenticationMethodMismatch, result);
        try std.testing.expect(blocked.canceled.load(.acquire));
        try std.testing.expect(client.connection() == null);
    }
}
