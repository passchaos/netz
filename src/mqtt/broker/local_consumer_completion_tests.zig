//! Persistence retries after a selected QoS 0 delivery was sent successfully.
const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const Broker = @import("../broker.zig").Broker;

test "broker local consumer retries QoS0 completion without consuming the next delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for ([_]bool{ false, true }) |explicit_retry| {
        var tmp = test_tmp.tmpDir(.{});
        defer tmp.cleanup();
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var broker = try Broker.init(failing.allocator(), io, .{ .queue_qos0_messages = true });
        defer broker.deinit();
        try broker.createCommitLog(tmp.dir, "completion.log", .{});
        var consumer = try broker.openLocalConsumer(.{
            .id = [_]u8{0x95} ** 16,
            .subscriptions = &.{.{ .topic_filter = "completion" }},
        });
        defer broker.closeLocalConsumer(&consumer);
        try std.testing.expectError(error.InvalidAcknowledgement, broker.completeLocalConsumerQoS0(&consumer));
        for ([_][]const u8{ "sent", "next" }) |payload| {
            try broker.publishLocal(.{ .dup = false, .qos = .at_most_once, .retain = false, .topic = "completion", .packet_id = null, .properties = &.{}, .payload = payload });
        }
        var sent = (try broker.pollLocalConsumer(&consumer)).?;
        defer sent.deinit();
        try std.testing.expectEqualStrings("sent", sent.publish.value.payload);
        var retry_handle = consumer;
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, broker.completeLocalConsumerQoS0(&consumer));
        try std.testing.expect(failing.has_induced_failure);
        // The barrier must keep failing instead of selecting the next message.
        failing.fail_index = failing.alloc_index;
        try std.testing.expectError(error.OutOfMemory, broker.pollLocalConsumer(&consumer));
        failing.fail_index = std.math.maxInt(usize);
        if (explicit_retry) {
            try broker.completeLocalConsumerQoS0(&consumer);
        } else {
            var recovery = try broker.pollLocalConsumer(&retry_handle);
            defer if (recovery) |*event| event.deinit();
            try std.testing.expect(recovery == null);
        }
        {
            var restored = try Broker.init(allocator, io, .{ .queue_qos0_messages = true });
            defer restored.deinit();
            try restored.restoreCommitLog(tmp.dir, "completion.log", .{});
            try std.testing.expectEqual(@as(usize, 1), restored.stats().session_queued_messages);
        }
        // A completed barrier cannot silently acknowledge a fresh selection.
        try std.testing.expectError(error.InvalidAcknowledgement, broker.completeLocalConsumerQoS0(&consumer));
        var next = (try broker.pollLocalConsumer(&consumer)).?;
        defer next.deinit();
        try std.testing.expectEqualStrings("next", next.publish.value.payload);
        try broker.completeLocalConsumerQoS0(&consumer);
        try std.testing.expect((try broker.pollLocalConsumer(&consumer)) == null);
    }
}
