const std = @import("std");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");
const source_mod = @import("local_source.zig");

fn sourceFor(broker: *broker_mod.Broker, io: std.Io, shutdown: *std.Io.Event) !source_mod.Client {
    var source = try source_mod.Client.init(std.testing.allocator, io, broker, [_]u8{0x93} ** 16, .{
        .protocol = .v5,
        .client_id = "local-source-retry",
        .clean_start = false,
    }, shutdown, false);
    errdefer source.deinit();
    try source.seedSubscription(.{ .topic_filter = "retry/#", .qos = .exactly_once }, &.{});
    _ = try source.connect();
    return source;
}

fn selectRelease(source: *source_mod.Client, broker: *broker_mod.Broker) !u16 {
    try broker.publishLocal(.{ .dup = false, .qos = .exactly_once, .retain = false, .topic = "retry/value", .packet_id = null, .properties = &.{}, .payload = "once" });
    var publish = (try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) orelse return error.TestUnexpectedResult;
    defer publish.deinit(std.testing.allocator);
    try std.testing.expect(publish == .publish);
    const packet_id = publish.publish.publish.packet_id.?;
    try source.stageIncomingQoS2(packet_id);
    try source.flushStagedIncomingQoS2(packet_id, .{});
    var release = (try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) orelse return error.TestUnexpectedResult;
    defer release.deinit(std.testing.allocator);
    try std.testing.expect(release == .pubrel);
    try std.testing.expectEqual(packet_id, release.pubrel.ack.packet_id);
    return packet_id;
}

test "local source QoS2 retries PUBREL after completion commit rollback" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var broker = try broker_mod.Broker.init(std.testing.allocator, threaded.io(), .{});
    defer broker.deinit();
    var shutdown: std.Io.Event = .unset;
    var source = try sourceFor(&broker, threaded.io(), &shutdown);
    defer source.deinit();
    const packet_id = try selectRelease(&source, &broker);
    // A mismatched release or an uncleared receipt must never remove the
    // broker's inflight delivery ahead of the coordinator's durable boundary.
    try std.testing.expectError(error.InvalidAcknowledgement, source.writeStagedIncomingQoS2Completion(packet_id ^ 0x8000, .{}));
    try std.testing.expectError(error.InvalidAcknowledgement, source.writeStagedIncomingQoS2Completion(packet_id, .{}));
    try std.testing.expectEqual(@as(usize, 1), try source.pendingCount());
    try source.stageIncomingQoS2Completion(packet_id, .{});
    // Coordinator commit failed: its caller restores the previous receipt.
    try source.discardStagedIncomingQoS2Completion(packet_id);
    var retry = (try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) orelse return error.TestUnexpectedResult;
    defer retry.deinit(std.testing.allocator);
    try std.testing.expect(retry == .pubrel);
    try std.testing.expectEqual(packet_id, retry.pubrel.ack.packet_id);
    try source.stageIncomingQoS2Completion(packet_id, .{});
    try source.writeStagedIncomingQoS2Completion(packet_id, .{});
    try std.testing.expect((try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) == null);
    try std.testing.expectEqual(@as(usize, 0), try source.pendingCount());
}

test "local source QoS2 retries PUBCOMP durability before selecting another delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var broker = try broker_mod.Broker.init(failing.allocator(), io, .{});
    defer broker.deinit();
    try broker.createCommitLog(tmp.dir, "retry.log", .{});
    var shutdown: std.Io.Event = .unset;
    var source = try sourceFor(&broker, io, &shutdown);
    defer source.deinit();
    const packet_id = try selectRelease(&source, &broker);
    try source.stageIncomingQoS2Completion(packet_id, .{});
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, source.writeStagedIncomingQoS2Completion(packet_id, .{}));
    try std.testing.expect(failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    // The broker already removed its inflight entry in memory. Polling must
    // retry its durability barrier even though there is no delivery to drain.
    try std.testing.expect((try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) == null);
    {
        var restored = try broker_mod.Broker.init(allocator, io, .{});
        defer restored.deinit();
        try restored.restoreCommitLog(tmp.dir, "retry.log", .{});
        try std.testing.expectEqual(@as(usize, 0), restored.stats().session_inflight_messages);
    }
    try broker.publishLocal(.{ .dup = false, .qos = .at_most_once, .retain = false, .topic = "retry/next", .packet_id = null, .properties = &.{}, .payload = "next" });
    var next = (try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) orelse return error.TestUnexpectedResult;
    defer next.deinit(allocator);
    try std.testing.expect(next == .publish);
    try std.testing.expectEqualStrings("next", next.publish.publish.payload);
    try source.completeQoS0();
}

test "local source QoS0 retries completion journal failure before next delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var broker = try broker_mod.Broker.init(failing.allocator(), io, .{ .queue_qos0_messages = true });
    defer broker.deinit();
    try broker.createCommitLog(tmp.dir, "zero.log", .{});
    var shutdown: std.Io.Event = .unset;
    var source = try sourceFor(&broker, io, &shutdown);
    defer source.deinit();
    for ([_][]const u8{ "sent", "next" }) |payload| {
        try broker.publishLocal(.{ .dup = false, .qos = .at_most_once, .retain = false, .topic = "retry/zero", .packet_id = null, .properties = &.{}, .payload = payload });
    }
    var sent = (try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })).?;
    defer sent.deinit(allocator);
    try std.testing.expectEqualStrings("sent", sent.publish.publish.payload);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, source.completeQoS0());
    try std.testing.expect(failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(@as(usize, 1), try source.pendingCount());
    // An empty adapter poll must finish the removed delivery's journal write,
    // without selecting or resending either message in the same call.
    try std.testing.expect((try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) == null);
    {
        var restored = try broker_mod.Broker.init(allocator, io, .{ .queue_qos0_messages = true });
        defer restored.deinit();
        try restored.restoreCommitLog(tmp.dir, "zero.log", .{});
        try std.testing.expectEqual(@as(usize, 1), restored.stats().session_queued_messages);
    }
    var next = (try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })).?;
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("next", next.publish.publish.payload);
    try source.completeQoS0();
    try std.testing.expect((try source.pollWithOptions(.{ .timeout = .fromMilliseconds(1) })) == null);
}
