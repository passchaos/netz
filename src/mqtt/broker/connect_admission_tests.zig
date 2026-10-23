const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;

const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;

test "broker rejected Will count admission preserves live Session ownership" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]bool{ false, true }) |clean_start| {
            try rejectedWillAdmission(protocol, clean_start, .{ .max_wills = 0 }, false, null);
        }
    }
}

test "broker rejected Will byte admission preserves prior Will and Session" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]bool{ false, true }) |clean_start| {
            try rejectedWillAdmission(protocol, clean_start, .{ .max_will_bytes = 512 }, true, null);
            try rejectedWillAdmission(protocol, clean_start, .{ .max_total_bytes = 512 }, true, null);
        }
    }
}

test "broker failed Will allocation preserves live Session ownership" {
    // The first three allocations copy ClientID, topic and payload; the next
    // reserves the scheduler's ClientID index. Both failure boundaries must
    // precede Session mutation, including Clean Start replacement.
    for ([_]usize{ 0, 3 }) |failure_offset| {
        for ([_]bool{ false, true }) |clean_start| {
            try rejectedWillAdmission(.v5, clean_start, .{}, false, .{ .will = failure_offset });
        }
    }
}

test "broker failed Session admission discards prepared Will before takeover" {
    try rejectedWillAdmission(.v5, true, .{}, true, .session);
}

const AllocationFailure = union(enum) {
    will: usize,
    session,
};

fn rejectedWillAdmission(
    protocol: mqtt.ProtocolVersion,
    clean_start: bool,
    options: mqtt.will_scheduler.Options,
    old_has_will: bool,
    allocation_failure: ?AllocationFailure,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.testBrokerFn(allocator, io, 2, 64);
    defer broker.deinit();
    broker.wills.options = options;
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const fail_session = if (allocation_failure) |failure| std.meta.activeTag(failure) == .session else false;
    if (fail_session) {
        broker.sessions.allocator = failing.allocator();
    } else {
        broker.wills.allocator = failing.allocator();
    }

    var serve = context.ServeStateType{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var old = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{
        .protocol = protocol,
        .client_id = "rejected-will-takeover",
        .clean_start = false,
        .will = if (old_has_will) .{
            .topic = "admission/prior-will",
            .payload = "prior",
            .retain = true,
        } else null,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{
            .id = .session_expiry_interval,
            .value = 120,
        } }} else &.{},
    }, .fromSeconds(5));
    defer old.close();
    var suback = try old.subscribe(&.{.{
        .topic_filter = "admission/value",
        .qos = .at_least_once,
    }}, .{});
    defer suback.deinit(allocator);

    const previous = blk: {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        const handle = broker.sessions.find("rejected-will-takeover", std.Io.Clock.awake.now(io)).?;
        const route_id = try broker.sessions.routeId(handle);
        if (allocation_failure) |failure| {
            const offset: usize = switch (failure) {
                .will => |value| value,
                .session => 0,
            };
            failing.fail_index = failing.alloc_index + offset;
        }
        break :blk .{
            .handle = handle,
            .route_id = route_id,
            .owner = broker.session_owners.get(route_id).?,
            .will = broker.wills.handleForClient("rejected-will-takeover"),
            .will_bytes = broker.wills.totalBytes(),
            .will_publisher_count = broker.will_publishers.count(),
        };
    };

    defer {
        broker.state_mutex.lockUncancelable(io);
        failing.fail_index = std.math.maxInt(usize);
        broker.state_mutex.unlock(io);
    }
    const new_payload = [_]u8{'x'} ** 1024;
    const attempt_result = runtime.Client.connectAttemptWithTimeout(allocator, io, broker.address(), .{
        .protocol = protocol,
        .client_id = "rejected-will-takeover",
        .clean_start = clean_start,
        .will = .{ .topic = "admission/will", .payload = &new_payload },
    }, .fromSeconds(5));
    if (allocation_failure != null) {
        if (attempt_result) |result| {
            var unexpected = result;
            unexpected.deinit(allocator);
            return error.TestUnexpectedResult;
        } else |err| {
            try std.testing.expectEqual(error.ConnectionClosed, err);
        }
    } else {
        var refused = try attempt_result;
        defer refused.deinit(allocator);
        try std.testing.expect(!refused.accepted());
        try std.testing.expectEqual(@as(u8, if (protocol == .v5) 0x97 else 0x03), refused.connack.connack.reason_code);
        try std.testing.expect(!refused.connack.connack.session_present);
    }

    {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        try std.testing.expectEqual(@as(?@TypeOf(previous.handle), previous.handle), broker.sessions.find("rejected-will-takeover", std.Io.Clock.awake.now(io)));
        try std.testing.expectEqual(@as(?@TypeOf(previous.owner), previous.owner), broker.session_owners.get(previous.route_id));
        try std.testing.expectEqual(@as(usize, 1), (try broker.sessions.stats(previous.handle)).subscription_count);
        try std.testing.expectEqual(@as(usize, 1), broker.router.subscriptionCount());
        try std.testing.expectEqual(previous.will, broker.wills.handleForClient("rejected-will-takeover"));
        try std.testing.expectEqual(previous.will_bytes, broker.wills.totalBytes());
        try std.testing.expectEqual(previous.will_publisher_count, broker.will_publishers.count());
        try std.testing.expect(broker.wills.nextDeadline() == null);
        try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
        if (previous.will) |handle| {
            try std.testing.expectEqualStrings("prior", (try broker.wills.view(handle)).payload);
        }
        failing.fail_index = std.math.maxInt(usize);
    }
    try broker.publishLocal(.{
        .topic = "admission/value",
        .payload = "still-live",
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .packet_id = null,
    });
    var event = try old.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings("still-live", event.publish.publish.payload);
    try old.disconnect(0);
    if (allocation_failure != null) {
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectError(error.OutOfMemory, context.joinServerFn(thread, &joined, &serve));
    } else {
        try context.joinServerFn(thread, &joined, &serve);
    }
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
}
