const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;

test "broker unrepresentable CONNACK preserves existing Session" {
    for ([_]bool{ false, true }) |clean_start| try rejectedReply(.packet_limit, clean_start);
}

test "broker expired CONNECT preserves existing Session before CONNACK" {
    for ([_]bool{ false, true }) |clean_start| try rejectedReply(.deadline, clean_start);
}

test "broker CONNACK allocation failure preserves existing Session" {
    for ([_]bool{ false, true }) |clean_start| try rejectedReply(.allocation, clean_start);
}

const Failure = enum { packet_limit, deadline, allocation };

fn rejectedReply(failure: Failure, clean_start: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Policy = struct {
        io: std.Io,
        failure: Failure,
        failing: *std.testing.FailingAllocator,

        fn authorize(context_ptr: *anyopaque, connect: mqtt.Connect) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (connect.username != null and std.mem.eql(u8, connect.username.?, "replacement")) {
                if (self.failure == .deadline) std.Io.sleep(self.io, .fromMilliseconds(75), .awake) catch return false;
                if (self.failure == .allocation) self.failing.fail_index = self.failing.alloc_index;
            }
            return true;
        }
    };
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var policy = Policy{ .io = io, .failure = failure, .failing = &failing };
    var broker = try context.testBrokerFn(allocator, io, 2, 64);
    defer broker.deinit();
    broker.options.connect_authorization = .{ .context = &policy, .authorize = Policy.authorize };
    if (failure == .deadline) broker.options.accept.connect_timeout = .fromMilliseconds(50);
    if (failure == .allocation) broker.server.?.allocator = failing.allocator();
    var serve = context.ServeStateType{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();
    var old = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "reply-admission",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
        .will = .{ .topic = "reply/prior-will", .payload = "prior", .retain = true },
    }, .fromSeconds(5));
    defer old.close();
    defer failing.fail_index = std.math.maxInt(usize);
    var suback = try old.subscribe(&.{.{ .topic_filter = "reply/value", .qos = .at_least_once }}, .{});
    defer suback.deinit(allocator);
    try broker.publishLocal(.{ .topic = "reply/value", .payload = "pending", .qos = .at_least_once, .dup = false, .retain = false, .packet_id = null });
    var pending = try old.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer pending.deinit(allocator);
    try std.testing.expect(pending == .publish);
    try old.pingWithTimeout(.fromSeconds(5));
    const previous = blk: {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        const handle = broker.sessions.find("reply-admission", std.Io.Clock.awake.now(io)).?;
        const route_id = try broker.sessions.routeId(handle);
        break :blk .{ .handle = handle, .route_id = route_id, .owner = broker.session_owners.get(route_id).?, .will = broker.wills.handleForClient("reply-admission"), .stats = try broker.sessions.stats(handle) };
    };
    var properties = [_]mqtt.Property{
        .{ .four_byte = .{ .id = .session_expiry_interval, .value = 0 } },
        .{ .four_byte = .{ .id = .maximum_packet_size, .value = 8 } },
    };
    const attempted = runtime.Client.connectAttemptWithTimeout(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "reply-admission",
        .clean_start = clean_start,
        .username = "replacement",
        .properties = properties[0..if (failure == .packet_limit) 2 else 1],
    }, .fromSeconds(5));
    if (attempted) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.ConnectionClosed, err);
    }
    if (failure == .allocation) try std.testing.expect(failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        try std.testing.expectEqual(@as(?@TypeOf(previous.handle), previous.handle), broker.sessions.find("reply-admission", std.Io.Clock.awake.now(io)));
        try std.testing.expectEqual(@as(?@TypeOf(previous.owner), previous.owner), broker.session_owners.get(previous.route_id));
        try std.testing.expectEqualDeep(previous.stats, try broker.sessions.stats(previous.handle));
        try std.testing.expectEqual(previous.will, broker.wills.handleForClient("reply-admission"));
        try std.testing.expect(broker.wills.nextDeadline() == null);
        try std.testing.expectEqual(@as(usize, 1), broker.router.subscriptionCount());
    }
    try old.writePubAck(pending.publish.publish.packet_id.?, 0);
    try old.pingWithTimeout(.fromSeconds(5));
    try broker.publishLocal(.{ .topic = "reply/value", .payload = "still-live", .qos = .at_most_once, .dup = false, .retain = false, .packet_id = null });
    var event = try old.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings("still-live", event.publish.publish.payload);
    try old.disconnect(0);
    switch (failure) {
        .deadline => try std.testing.expectError(error.Timeout, context.joinServerFn(thread, &joined, &serve)),
        .allocation => try std.testing.expectError(error.OutOfMemory, context.joinServerFn(thread, &joined, &serve)),
        .packet_limit => try std.testing.expectError(error.OutgoingPacketTooLarge, context.joinServerFn(thread, &joined, &serve)),
    }
}
