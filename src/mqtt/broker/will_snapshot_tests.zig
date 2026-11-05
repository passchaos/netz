const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;

test "broker restart restores default Will from snapshot and journal" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        try restoreDefaultWill(protocol, false);
        try restoreDefaultWill(protocol, true);
    }
}

fn restoreDefaultWill(protocol: mqtt.ProtocolVersion, journal: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var source = try context.testBrokerFn(allocator, io, 1, 64);
    defer source.deinit();
    try source.createCommitLog(tmp.dir, "source.log", .{});
    var serving_source = context.ServeStateType{ .broker = &source, .connection_count = 1 };
    const source_thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serving_source});
    var source_joined = false;
    defer if (!source_joined) source_thread.join();
    var client = try runtime.Client.connectWithTimeout(allocator, io, source.address(), .{
        .protocol = protocol,
        .client_id = "default-will-source",
        .clean_start = false,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }} else &.{},
        .will = .{ .topic = "persist/default-will", .payload = "offline", .qos = .at_least_once, .retain = true },
    }, .fromSeconds(5));
    defer client.close();
    try client.pingWithTimeout(.fromSeconds(5));
    try source.saveLiveSnapshot(tmp.dir, "crash.db");
    {
        source.persistence_mutex.lockUncancelable(io);
        defer source.persistence_mutex.unlock(io);
        const bytes = try tmp.dir.readFileAlloc(io, "source.log", allocator, .limited(1024 * 1024));
        defer allocator.free(bytes);
        try tmp.dir.writeFile(io, .{ .sub_path = "crash.log", .data = bytes });
    }
    // Graceful cleanup cancels the source's Will. The independent files model
    // a crash at its earlier live checkpoint, when that Will still existed.
    try client.disconnect(0);
    try context.joinServerFn(source_thread, &source_joined, &serving_source);
    try std.testing.expectEqual(@as(usize, 0), source.wills.count());
    try std.testing.expectEqual(@as(usize, 0), source.retained.count());

    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    if (journal) {
        try restored.restoreCommitLog(tmp.dir, "crash.log", .{});
    } else {
        try restored.restoreSnapshot(tmp.dir, "crash.db");
    }
    const handle = restored.wills.handleForClient("default-will-source").?;
    const view = try restored.wills.view(handle);
    try std.testing.expect(mqtt.willDelayInterval(view.properties) == null);
    try std.testing.expect(view.message_expiry_interval == null);
    try std.testing.expect(restored.wills.nextDeadline().?.nanoseconds <= std.Io.Clock.awake.now(io).nanoseconds);

    var serving_restored = context.ServeStateType{ .broker = &restored, .connection_count = 1 };
    const restored_thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serving_restored});
    var restored_joined = false;
    defer if (!restored_joined) restored_thread.join();
    var subscriber = try runtime.Client.connectWithTimeout(allocator, io, restored.address(), .{
        .protocol = .v5,
        .client_id = "default-will-reader",
    }, .fromSeconds(5));
    defer subscriber.close();
    var suback = try subscriber.subscribe(&.{.{ .topic_filter = "persist/default-will", .qos = .at_least_once }}, .{});
    defer suback.deinit(allocator);
    var event = try subscriber.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings("persist/default-will", event.publish.publish.topic);
    try std.testing.expectEqualStrings("offline", event.publish.publish.payload);
    try subscriber.writePubAck(event.publish.publish.packet_id.?, 0);
    const extra = subscriber.readClientPacketEventWithTimeout(.fromMilliseconds(30));
    if (extra) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.Timeout, err);
    }
    try subscriber.pingWithTimeout(.fromSeconds(5));
    try subscriber.disconnect(0);
    try context.joinServerFn(restored_thread, &restored_joined, &serving_restored);
    try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
    try std.testing.expectEqual(@as(usize, 0), restored.will_publishers.count());
    var matches: [1]mqtt.retained.Match = undefined;
    const retained = try restored.retained.matchInto("persist/default-will", std.Io.Clock.awake.now(io), &matches);
    try std.testing.expectEqual(@as(usize, 1), retained.len);
    try std.testing.expectEqualStrings("offline", retained[0].payload);
}
