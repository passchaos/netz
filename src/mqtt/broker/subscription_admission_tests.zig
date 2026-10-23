const std = @import("std");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;

test "broker failed subscription restoration preserves live Session capability" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]usize{ 3, 4 }) |failure_offset| {
            try failedAdmission(protocol, failure_offset, false);
        }
    }
}

test "broker failed connection storage allocation preserves prior Session" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        try failedAdmission(protocol, 0, false);
        try failedAdmission(protocol, 0, true);
    }
}

test "broker connection storage handles policy and Session quota refusal" {
    const allocator = std.testing.allocator;
    for ([_]bool{ false, true }) |policy_refusal| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var failing = std.testing.FailingAllocator.init(allocator, .{});
        var broker = try context.testBrokerFn(allocator, io, 1, 64);
        defer broker.deinit();
        broker.allocator = failing.allocator();
        if (!policy_refusal) broker.sessions.options.max_sessions = 0;
        const Policy = struct {
            allocator: *std.testing.FailingAllocator,
            refuse: bool,
            called: std.atomic.Value(bool) = .init(false),

            fn authorize(context_ptr: *anyopaque, _: mqtt.Connect) bool {
                const self: *@This() = @ptrCast(@alignCast(context_ptr));
                if (self.refuse) self.allocator.fail_index = self.allocator.alloc_index;
                self.called.store(true, .release);
                return !self.refuse;
            }
        };
        var policy = Policy{ .allocator = &failing, .refuse = policy_refusal };
        broker.options.connect_authorization = .{ .context = &policy, .authorize = Policy.authorize };
        var serve = context.ServeStateType{ .broker = &broker, .connection_count = 1 };
        const thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serve});
        var joined = false;
        defer if (!joined) thread.join();
        defer failing.fail_index = std.math.maxInt(usize);
        var result = try runtime.Client.connectAttemptWithTimeout(allocator, io, broker.address(), .{
            .protocol = .v5,
            .client_id = "storage-refusal",
        }, .fromSeconds(5));
        defer result.deinit(allocator);
        try std.testing.expect(!result.accepted());
        try std.testing.expectEqual(@as(u8, if (policy_refusal) 0x87 else 0x89), result.connack.connack.reason_code);
        try context.joinServerFn(thread, &joined, &serve);
        try std.testing.expect(policy.called.load(.acquire));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 0), broker.sessions.count());
        try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
        try std.testing.expect(!broker.slots[0].state.active);
        try std.testing.expect(broker.slots[0].connection == null);
    }
}

fn failedAdmission(protocol: mqtt.ProtocolVersion, failure_offset: usize, clean_start: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var broker = try context.testBrokerFn(allocator, io, 2, 64);
    defer broker.deinit();
    broker.allocator = failing.allocator();
    broker.router.allocator = failing.allocator();
    const Admission = struct {
        allocator: *std.testing.FailingAllocator,
        offset: usize,
        armed: std.atomic.Value(bool) = .init(false),

        fn authorize(context_ptr: *anyopaque, connect: mqtt.Connect) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (connect.username) |username| {
                if (std.mem.eql(u8, username, "replacement")) {
                    // Stable connection storage comes first, then a resumed
                    // subscriber's delivery descriptor/queue and restoration
                    // copy/journal. Arm the requested preparation boundary.
                    self.allocator.fail_index = self.allocator.alloc_index + self.offset;
                    self.armed.store(true, .release);
                }
            }
            return true;
        }
    };
    var admission = Admission{ .allocator = &failing, .offset = failure_offset };
    broker.options.connect_authorization = .{ .context = &admission, .authorize = Admission.authorize };
    var serve = context.ServeStateType{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();
    var old = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{
        .protocol = protocol,
        .client_id = "restore-admission",
        .clean_start = false,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }} else &.{},
        .will = .{ .topic = "restore/prior-will", .payload = "prior", .retain = true },
    }, .fromSeconds(5));
    defer old.close();
    defer failing.fail_index = std.math.maxInt(usize);
    var suback = try old.subscribe(&.{.{ .topic_filter = "restore/value", .qos = .at_least_once }}, .{});
    defer suback.deinit(allocator);
    try broker.publishLocal(.{ .topic = "restore/value", .payload = "pending", .qos = .at_least_once, .dup = false, .retain = false, .packet_id = null });
    var pending = try old.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer pending.deinit(allocator);
    try std.testing.expect(pending == .publish);
    try old.pingWithTimeout(.fromSeconds(5));
    const previous = blk: {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        const handle = broker.sessions.find("restore-admission", std.Io.Clock.awake.now(io)).?;
        const route_id = try broker.sessions.routeId(handle);
        break :blk .{
            .handle = handle,
            .route_id = route_id,
            .owner = broker.session_owners.get(route_id).?,
            .stats = try broker.sessions.stats(handle),
            .will = broker.wills.handleForClient("restore-admission"),
        };
    };
    const attempted = runtime.Client.connectAttemptWithTimeout(allocator, io, broker.address(), .{
        .protocol = protocol,
        .client_id = "restore-admission",
        .clean_start = clean_start,
        .username = "replacement",
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 0 } }} else &.{},
    }, .fromSeconds(5));
    if (attempted) |result| {
        var unexpected = result;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.ConnectionClosed, err);
    }
    try std.testing.expect(admission.armed.load(.acquire));
    try std.testing.expect(failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        try std.testing.expectEqual(@as(?@TypeOf(previous.handle), previous.handle), broker.sessions.find("restore-admission", std.Io.Clock.awake.now(io)));
        try std.testing.expectEqual(@as(?@TypeOf(previous.owner), previous.owner), broker.session_owners.get(previous.route_id));
        try std.testing.expectEqual(previous.stats, try broker.sessions.stats(previous.handle));
        try std.testing.expectEqual(previous.will, broker.wills.handleForClient("restore-admission"));
        try std.testing.expect(broker.wills.nextDeadline() == null);
        try std.testing.expectEqual(@as(usize, 1), broker.router.subscriptionCount());
    }
    // The old handle must still accept its in-flight acknowledgement after a
    // rejected peer, then deliver fresh traffic over the existing subscription.
    try old.writePubAck(pending.publish.publish.packet_id.?, 0);
    try old.pingWithTimeout(.fromSeconds(5));
    try broker.publishLocal(.{ .topic = "restore/value", .payload = "still-live", .qos = .at_most_once, .dup = false, .retain = false, .packet_id = null });
    var event = try old.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings("still-live", event.publish.publish.payload);
    try old.disconnect(0);
    try std.testing.expectError(error.OutOfMemory, context.joinServerFn(thread, &joined, &serve));
}

test "broker resumed Session prepares missing ordinary and shared routes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try context.testBrokerFn(allocator, io, 1, 64);
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);
    const old = try broker.sessions.open("rebuild-routes", false, 120, now);
    _ = try broker.sessions.setSubscription(old.handle, .{
        .topic_filter = "rebuild/value",
        .qos = .at_least_once,
        .no_local = true,
        .retain_as_published = true,
    }, 3);
    _ = try broker.sessions.setSubscription(old.handle, .{
        .topic_filter = "$share/workers/rebuild/jobs/+",
        .qos = .at_least_once,
    }, 9);
    try broker.sessions.disconnect(old.handle, null, now);
    // State supplied without its router index still needs complete restoration
    // on reconnect. Reusing existing routes must not remove this capability.
    try std.testing.expectEqual(@as(usize, 0), broker.router.subscriptionCount());
    var serve = context.ServeStateType{ .broker = &broker, .connection_count = 1 };
    const thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();
    var result = try runtime.Client.connectWithConnAckWithTimeout(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "rebuild-routes",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
    }, .fromSeconds(5));
    defer result.deinit(allocator);
    try std.testing.expect(result.connack.connack.session_present);
    try broker.publishLocal(.{ .topic = "rebuild/value", .payload = "ordinary", .qos = .at_least_once, .dup = false, .retain = true, .packet_id = null });
    try receive(&result.connection, "ordinary", 3, true);
    try broker.publishLocal(.{ .topic = "rebuild/jobs/one", .payload = "shared", .qos = .at_least_once, .dup = false, .retain = false, .packet_id = null });
    try receive(&result.connection, "shared", 9, false);
    try result.connection.publish("rebuild/value", "local", .{ .qos = .at_least_once });
    try result.connection.pingWithTimeout(.fromSeconds(5));
    const unexpected = result.connection.readClientPacketEventWithTimeout(.fromMilliseconds(30));
    if (unexpected) |value| {
        var event = value;
        event.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.Timeout, err);
    }
    try result.connection.disconnect(0);
    try context.joinServerFn(thread, &joined, &serve);
    try std.testing.expectEqual(@as(usize, 2), broker.router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), broker.router.sharedSubscriptionCount());
}

fn receive(connection: *runtime.Connection, payload: []const u8, identifier: usize, retain: bool) !void {
    var event = try connection.readClientPacketEventWithTimeout(.fromSeconds(5));
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings(payload, event.publish.publish.payload);
    try std.testing.expectEqual(retain, event.publish.publish.retain);
    var identifier_count: usize = 0;
    for (event.publish.publish.properties) |property| {
        if (property == .varint and property.varint.id == .subscription_identifier) {
            try std.testing.expectEqual(identifier, property.varint.value);
            identifier_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), identifier_count);
    try connection.writePubAck(event.publish.publish.packet_id.?, 0);
}
