//! Mosquitto's DISCONNECT expiry bounds the client's persisted Session image.
const std = @import("std");
const mqtt = @import("netz").mqtt;

pub fn exercise(allocator: std.mem.Allocator, io: std.Io, port: u16) !void {
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(port) };
    const options = mqtt.runtime.ConnectOptions{
        .protocol = .v5,
        .client_id = "netz-retention-interop",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    };
    var shutdown: std.Io.Event = .unset;
    var source = try mqtt.reconnect.Client.init(allocator, io, address, options, .{}, &shutdown);
    var source_owned = true;
    defer if (source_owned) source.deinit();
    try source.seedSubscription(.{ .topic_filter = "retention/#" }, &.{});
    _ = try source.connectWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(@as(u32, 60), source.sessionExpiryInterval());
    const id = try source.stagePublish("retention/stale", "obsolete", .{ .qos = .exactly_once });
    try source.disconnectWithProperties(0, &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 1 } }});
    try std.testing.expectEqual(@as(u32, 1), source.sessionExpiryInterval());
    var image: std.ArrayList(u8) = .empty;
    defer image.deinit(allocator);
    try source.writeSessionSnapshot(&image);
    source.deinit();
    source_owned = false;
    try std.Io.sleep(io, .fromSeconds(2), .awake);
    var restored = try mqtt.reconnect.Client.init(allocator, io, address, options, .{}, &shutdown);
    defer restored.deinit();
    try restored.restoreSessionSnapshot(image.items);
    @memset(image.items, 0);
    try std.testing.expectEqual(@as(u32, 1), restored.sessionExpiryInterval());
    try std.testing.expectEqual(@as(usize, 0), (try restored.outgoingStats()).inflight_count);
    try std.testing.expect((try restored.outgoingQoSState(id)) == null);
    try std.testing.expect(restored.hasSubscription("retention/#"));
    try std.testing.expect(!(try restored.connectWithTimeout(.fromSeconds(3))).session_present);
    // Fresh replay restored the subscription. An ordinary synchronous publish
    // retains its self-delivery while completing the independent wire ACK.
    var progress: mqtt.runtime.PublishProgress = .{};
    try restored.connection().?.publishWithTimeout("retention/fresh", "live", .{ .qos = .at_least_once }, &progress, .fromSeconds(3));
    var event = try restored.connection().?.readClientPacketEventWithTimeout(.fromSeconds(3));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings("retention/fresh", event.publish.publish.topic);
    try std.testing.expectEqualStrings("live", event.publish.publish.payload);
    try restored.disconnectWithProperties(0, &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 0 } }});
    std.debug.print("netz Session retention interop passed: protocol=mqtt5 disconnect-expiry=1 expired-qos-discarded=true subscriptions-replayed=true\n", .{});
}
