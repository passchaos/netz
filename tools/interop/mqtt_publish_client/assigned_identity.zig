//! Mosquitto assigns the identity, then resumes it after Client reconstruction.
const std = @import("std");
const mqtt = @import("netz").mqtt;

pub fn exercise(allocator: std.mem.Allocator, io: std.Io, port: u16) !void {
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const options = mqtt.runtime.ConnectOptions{
        .protocol = .v5,
        .client_id = "",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    };
    for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| {
        var observer = try mqtt.runtime.Client.connectWithTimeout(allocator, io, address, .{ .protocol = .v5, .client_id = "netz-assigned-identity-observer" }, .fromSeconds(3));
        defer observer.close();
        var suback = try observer.subscribeWithTimeout(&.{.{ .topic_filter = "completion/assigned", .qos = .at_most_once }}, .{}, .fromSeconds(3));
        defer suback.deinit(allocator);
        var shutdown: std.Io.Event = .unset;
        var source = try mqtt.reconnect.Client.init(allocator, io, address, options, .{}, &shutdown);
        var source_owned = true;
        defer if (source_owned) source.deinit();
        try source.seedSubscription(.{ .topic_filter = "completion/assigned", .qos = .at_most_once, .no_local = true }, &.{.{ .varint = .{ .id = .subscription_identifier, .value = 11 } }});
        try std.testing.expect(!(try source.connectWithTimeout(.fromSeconds(3))).session_present);
        try std.testing.expect(source.clientId().len > 0);
        try std.testing.expectEqualStrings(source.connection().?.assignedClientId().?, source.clientId());
        const assigned_id = try allocator.dupe(u8, source.clientId());
        defer allocator.free(assigned_id);
        const packet_id = try source.stagePublish("completion/assigned", "reconstructed", .{ .qos = qos });
        var image: std.ArrayList(u8) = .empty;
        defer image.deinit(allocator);
        try source.writeSessionSnapshot(&image);
        source.deinit();
        source_owned = false;
        var restored = try mqtt.reconnect.Client.init(allocator, io, address, options, .{}, &shutdown);
        defer restored.deinit();
        try restored.restoreSessionSnapshot(image.items);
        @memset(image.items, 0);
        try std.testing.expectEqualStrings(assigned_id, restored.clientId());
        try std.testing.expect(restored.hasSubscription("completion/assigned"));
        try std.testing.expect((try restored.connectWithTimeout(.fromSeconds(3))).session_present);
        try std.testing.expectEqualStrings(assigned_id, restored.clientId());
        while ((try restored.outgoingQoSState(packet_id)) != null) {
            try std.testing.expectEqual(packet_id, try restored.completeNextPublish());
        }
        var delivery = try observer.readClientPacketEventWithTimeout(.fromSeconds(3));
        defer delivery.deinit(allocator);
        try std.testing.expect(delivery == .publish);
        try std.testing.expectEqualStrings("completion/assigned", delivery.publish.publish.topic);
        try std.testing.expectEqualStrings("reconstructed", delivery.publish.publish.payload);
        // No Local must survive the image; a self-delivery would precede the
        // PINGRESP and make this ordered event check fail.
        try restored.connection().?.writePingReq();
        var next = try restored.connection().?.readClientPacketEventWithTimeout(.fromSeconds(3));
        defer next.deinit(allocator);
        try std.testing.expect(next == .pingresp);
        try restored.disconnectWithProperties(0, &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 0 } }});
        try observer.disconnect(0);
    }
    std.debug.print("netz assigned identity interop passed: protocol=mqtt5 qos=1,2 session-resume=true reconstructed=true no-local=true\n", .{});
}
