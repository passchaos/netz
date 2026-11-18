//! Tests moved out of the module runtime root.

const std = @import("std");
const mqtt = @import("../mod.zig");
const net = std.Io.net;
const broker_root = @import("../broker.zig");
const runtime = @import("../runtime.zig");
const AccessControlHandler = broker_root.AccessControlHandler;
const Broker = broker_root.Broker;
const ClientBuffers = broker_root.ClientBuffers;
const ClientSlot = broker_root.ClientSlot;
const Delivery = broker_root.Delivery;
const DeliveryAuthorization = broker_root.DeliveryAuthorization;
const DeliveryAuthorizationChain = broker_root.DeliveryAuthorizationChain;
const ListenerAccessControlHandler = broker_root.ListenerAccessControlHandler;
const NetworkDeliveryMode = broker_root.NetworkDeliveryMode;
const Publication = broker_root.Publication;
const RegistrationProgress = broker_root.RegistrationProgress;
const Stats = broker_root.Stats;
const SystemMetric = broker_root.SystemMetric;
const builtin = broker_root.builtin;
const createRoutePublication = broker_root.createRoutePublication;
const disconnectReasonForReadViolation = broker_root.disconnectReasonForReadViolation;
const formatSystemMetric = broker_root.formatSystemMetric;
const load_metrics = broker_root.load_metrics;
const networkDeliveryMode = broker_root.networkDeliveryMode;
const nextConnectionGeneration = broker_root.nextConnectionGeneration;
const prepareRetainedDeliveryProperties = broker_root.prepareRetainedDeliveryProperties;
const retained_mod = broker_root.retained_mod;
const router_mod = broker_root.router_mod;
const sessionSubscriberId = broker_root.sessionSubscriberId;
const session_mod = broker_root.session_mod;
const session_property_scratch_retain_capacity = broker_root.session_property_scratch_retain_capacity;
const session_write_scratch_retain_limit = broker_root.session_write_scratch_retain_limit;
const session_writer = broker_root.session_writer;
const shouldScheduleSessionDelivery = broker_root.shouldScheduleSessionDelivery;
const shouldScheduleTransientDelivery = broker_root.shouldScheduleTransientDelivery;
const subscriberId = broker_root.subscriberId;
const subscription_change = broker_root.subscription_change;
const test_tmp = broker_root.test_tmp;
const transient_delivery_async_high_watermark = broker_root.transient_delivery_async_high_watermark;
const will_mod = broker_root.will_mod;

test {
    _ = subscription_change;
    _ = @import("prometheus.zig");
}

test "MQTT broker capacity slots keep connection state out of line" {
    try std.testing.expect(
        @sizeOf(ClientSlot) <= @sizeOf(runtime.Connection) / 2,
    );
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 96), @sizeOf(ClientSlot));
        const buffers_size: usize = switch (builtin.mode) {
            .Debug, .ReleaseSafe => 152,
            .ReleaseFast, .ReleaseSmall => 144,
        };
        try std.testing.expectEqual(buffers_size, @sizeOf(ClientBuffers));
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(ClientSlot, "state")),
        );
        try std.testing.expectEqual(
            @sizeOf(?[*]u8),
            @sizeOf(@FieldType(ClientSlot, "assigned_client_id_ptr")),
        );
        try std.testing.expectEqual(
            @sizeOf(?[*]const u8),
            @sizeOf(@FieldType(ClientSlot, "username_ptr")),
        );
        try std.testing.expectEqual(
            @as(usize, 64),
            @bitSizeOf(@FieldType(ClientSlot, "state")),
        );
    }
    try std.testing.expectEqual(
        @sizeOf(?*ListenerAccessControlHandler),
        @sizeOf(@FieldType(ClientSlot, "listener_access_control")),
    );
}

test "MQTT broker allocates client buffers on demand" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.buffers == null);

    var descriptor_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        slot.ensureDeliveryCapacity(descriptor_failure.allocator(), 4),
    );
    try std.testing.expect(slot.buffers == null);

    var queue_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        slot.ensureDeliveryCapacity(queue_failure.allocator(), 4),
    );
    try std.testing.expect(slot.buffers == null);

    try slot.ensureDeliveryCapacity(std.testing.allocator, 4);
    try std.testing.expect(slot.buffers.?.queue.capacity >= 4);
    slot.clearBuffers(std.testing.allocator);
    try std.testing.expect(slot.buffers == null);
}

test "MQTT broker starts transient delivery writers on demand" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
    });
    defer broker.deinit();

    const slot = &broker.slots[0];
    slot.state.active = true;
    _ = try slot.ensureBuffers(allocator);
    try std.testing.expect(slot.buffers.?.delivery_writer == null);

    broker.state_mutex.lockUncancelable(io);
    try std.testing.expect(broker.ensureDeliveryWriterLocked(0, slot));
    const writer = slot.buffers.?.delivery_writer.?;
    try std.testing.expect(broker.ensureDeliveryWriterLocked(0, slot));
    try std.testing.expect(slot.buffers.?.delivery_writer.? == writer);
    broker.state_mutex.unlock(io);

    try std.testing.expect(broker.stopDeliveryWriter(slot) == null);
    try std.testing.expect(slot.buffers.?.delivery_writer == null);
    slot.state.active = false;
}

test "MQTT broker allocates assigned client identifiers on demand" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
    });
    defer broker.deinit();

    const slot_index = try broker.claimSlot();
    const slot = &broker.slots[slot_index];
    try std.testing.expect(slot.assignedClientId() == null);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    broker.allocator = failing.allocator();
    broker.state_mutex.lockUncancelable(io);
    const failed_assignment = broker.assignClientIdLocked(slot, "test-");
    broker.state_mutex.unlock(io);
    broker.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, failed_assignment);
    try std.testing.expect(slot.assignedClientId() == null);
    try std.testing.expectEqual(@as(u7, 0), slot.state.assigned_client_id_len);

    broker.state_mutex.lockUncancelable(io);
    const assigned = broker.assignClientIdLocked(
        slot,
        "test-",
    ) catch |err| {
        broker.state_mutex.unlock(io);
        return err;
    };
    try std.testing.expectEqualStrings(assigned, slot.assignedClientId().?);
    try std.testing.expect(std.mem.startsWith(u8, assigned, "test-"));
    broker.state_mutex.unlock(io);

    broker.abortRegistration(slot_index, 0, false);
    try std.testing.expect(slot.assignedClientId() == null);
    broker.releaseClaimedSlot(slot_index);
}

test "MQTT broker stores borrowed username with wire length" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.username() == null);

    var bytes = [_]u8{ 'u', 's', 'e', 'r' };
    slot.setUsername(&bytes);
    try std.testing.expectEqualStrings("user", slot.username().?);
    bytes[0] = 'U';
    try std.testing.expectEqualStrings("User", slot.username().?);

    slot.setUsername("");
    try std.testing.expectEqualStrings("", slot.username().?);
    slot.setUsername(null);
    try std.testing.expect(slot.username() == null);
    try std.testing.expectEqual(@as(u16, 0), slot.state.username_len);
}

test "MQTT broker stores optional Session and Will handles without tags" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.sessionHandle() == null);
    try std.testing.expect(slot.willHandle() == null);

    const session_handle = session_mod.Handle{
        .index = 7,
        .generation = 11,
    };
    const will_handle = will_mod.Handle{
        .index = 13,
        .generation = 17,
    };
    slot.setSessionHandle(session_handle);
    slot.setWillHandle(will_handle);
    try std.testing.expectEqualDeep(session_handle, slot.sessionHandle().?);
    try std.testing.expectEqualDeep(will_handle, slot.willHandle().?);

    slot.setSessionHandle(null);
    slot.setWillHandle(null);
    try std.testing.expect(slot.sessionHandle() == null);
    try std.testing.expect(slot.willHandle() == null);
}

test "MQTT broker lazily reserves Will publisher index" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(
        std.testing.allocator,
        threaded.io(),
        .{ .limits = .{ .max_connections = 2 } },
    );
    defer broker.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        broker.will_publishers.capacity(),
    );
}

test "MQTT ACK flush lock handoff excludes live persistence backends" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(
        allocator,
        io,
        .{ .limits = .{ .max_connections = 1 } },
    );
    defer broker.deinit();

    {
        broker.state_mutex.lockUncancelable(io);
        defer broker.state_mutex.unlock(io);
        try std.testing.expect(
            broker.canCoalesceAcknowledgedSessionFlushLocked(),
        );
        broker.persistent_change_autosave_enabled.store(true, .release);
        try std.testing.expect(
            !broker.canCoalesceAcknowledgedSessionFlushLocked(),
        );
        broker.persistent_change_autosave_enabled.store(false, .release);
    }

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "ack-handoff.log", .{});

    broker.state_mutex.lockUncancelable(io);
    defer broker.state_mutex.unlock(io);
    try std.testing.expect(
        !broker.canCoalesceAcknowledgedSessionFlushLocked(),
    );
}

test "MQTT broker Will index allocation failure precedes Session mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var broker = try Broker.init(failing.allocator(), io, .{
        .limits = .{ .max_connections = 1 },
        .session = .{ .max_sessions = 1 },
    });
    defer broker.deinit();

    const slot_index = try broker.claimSlot();
    defer broker.releaseClaimedSlot(slot_index);
    var progress: RegistrationProgress = .{};
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        broker.register(
            slot_index,
            .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 30,
                .client_id = "will-allocation-failure",
                .will = .{
                    .topic = "will/allocation-failure",
                    .payload = "offline",
                    .qos = .at_least_once,
                    .retain = false,
                    .properties = &.{},
                },
            },
            null,
            null,
            broker.options.auto_client_id_prefix,
            &progress,
        ),
    );
    failing.fail_index = std.math.maxInt(usize);

    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        broker.will_publishers.capacity(),
    );
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try std.testing.expect(broker.sessions.find(
        "will-allocation-failure",
        std.Io.Clock.awake.now(io),
    ) == null);
    try std.testing.expect(broker.slots[slot_index].sessionHandle() == null);
    try std.testing.expect(broker.slots[slot_index].willHandle() == null);
}

test "MQTT broker stores optional retained source identity without tag" {
    var slot: ClientSlot = .{};
    try std.testing.expect(slot.retainedSourceId() == null);

    slot.setRetainedSourceId(0);
    try std.testing.expectEqual(@as(?u64, 0), slot.retainedSourceId());
    slot.setRetainedSourceId(std.math.maxInt(u64));
    try std.testing.expectEqual(
        @as(?u64, std.math.maxInt(u64)),
        slot.retainedSourceId(),
    );

    slot.setRetainedSourceId(null);
    try std.testing.expect(slot.retainedSourceId() == null);
}

test "MQTT broker allocates listener ACL metadata on demand" {
    var slot: ClientSlot = .{};
    var marker: u8 = 0;
    const access_control = ListenerAccessControlHandler{
        .context = &marker,
    };

    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try slot.setListenerAccessControl(failing.allocator(), null);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(slot.accessControl() == null);
    try std.testing.expectError(
        error.OutOfMemory,
        slot.setListenerAccessControl(
            failing.allocator(),
            access_control,
        ),
    );
    try std.testing.expect(slot.accessControl() == null);

    try slot.setListenerAccessControl(
        std.testing.allocator,
        access_control,
    );
    try std.testing.expectEqual(
        access_control.context,
        slot.accessControl().?.context,
    );
    slot.clearListenerAccessControl(std.testing.allocator);
    try std.testing.expect(slot.accessControl() == null);
}

test "MQTT broker detects configured delivery authorization callbacks" {
    const Callbacks = struct {
        fn publish(
            context: *anyopaque,
            connect: mqtt.Connect,
            message: mqtt.Publish,
        ) bool {
            _ = context;
            _ = connect;
            _ = message;
            return true;
        }

        fn subscribe(
            context: *anyopaque,
            connect: mqtt.Connect,
            subscription: mqtt.Subscription,
        ) bool {
            _ = context;
            _ = connect;
            _ = subscription;
            return true;
        }

        fn delivery(
            context: *anyopaque,
            authorization: DeliveryAuthorization,
        ) bool {
            _ = context;
            _ = authorization;
            return true;
        }
    };
    var context: u8 = 0;
    const global_without_delivery = AccessControlHandler{
        .context = &context,
        .authorize_publish = Callbacks.publish,
        .authorize_subscribe = Callbacks.subscribe,
    };
    const global_with_delivery = AccessControlHandler{
        .context = &context,
        .authorize_publish = Callbacks.publish,
        .authorize_subscribe = Callbacks.subscribe,
        .authorize_delivery = Callbacks.delivery,
    };
    const listener_without_delivery = ListenerAccessControlHandler{
        .context = &context,
    };
    const listener_with_delivery = ListenerAccessControlHandler{
        .context = &context,
        .authorize_delivery = Callbacks.delivery,
    };

    try std.testing.expect(!(DeliveryAuthorizationChain{}).configured());
    try std.testing.expect(!(DeliveryAuthorizationChain{
        .broker = &global_without_delivery,
        .listener = &listener_without_delivery,
    }).configured());
    try std.testing.expect((DeliveryAuthorizationChain{
        .broker = &global_with_delivery,
    }).configured());
    try std.testing.expect((DeliveryAuthorizationChain{
        .listener = &listener_with_delivery,
    }).configured());
}

test "MQTT retained replay reuses property scratch" {
    const allocator = std.testing.allocator;
    const source = [_]mqtt.Property{
        .{ .four_byte = .{
            .id = .message_expiry_interval,
            .value = 60,
        } },
        .{ .utf8 = .{
            .id = .content_type,
            .value = "application/octet-stream",
        } },
    };
    var scratch: std.ArrayList(mqtt.Property) = .empty;
    defer scratch.deinit(allocator);

    try prepareRetainedDeliveryProperties(
        &scratch,
        allocator,
        &source,
        59,
    );
    const allocation = scratch.allocatedSlice().ptr;
    try std.testing.expectEqual(@as(?u32, 59), mqtt.messageExpiryInterval(scratch.items));

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try prepareRetainedDeliveryProperties(
        &scratch,
        failing.allocator(),
        &source,
        58,
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(allocation, scratch.allocatedSlice().ptr);
    try std.testing.expectEqual(@as(?u32, 58), mqtt.messageExpiryInterval(scratch.items));

    try prepareRetainedDeliveryProperties(
        &scratch,
        failing.allocator(),
        &source,
        null,
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), scratch.items.len);
    try std.testing.expect(scratch.items[0] == .utf8);
}

test "MQTT transient delivery scheduling respects persistence and watermark" {
    const limit = transient_delivery_async_high_watermark;
    try std.testing.expect(shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        limit - 1,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        limit,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .at_most_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(shouldScheduleTransientDelivery(
        false,
        .at_least_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        true,
        .exactly_once,
        2,
        0,
        limit,
        false,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .exactly_once,
        2,
        0,
        limit,
        true,
    ));
    try std.testing.expect(!shouldScheduleTransientDelivery(
        false,
        .at_least_once,
        1,
        0,
        limit,
        false,
    ));
    try std.testing.expect(shouldScheduleSessionDelivery(
        2,
        1,
        limit,
        false,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        2,
        limit,
        limit,
        false,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        1,
        0,
        limit,
        false,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        2,
        0,
        limit,
        true,
        true,
    ));
    try std.testing.expect(!shouldScheduleSessionDelivery(
        2,
        0,
        limit,
        false,
        false,
    ));

    try std.testing.expectEqual(
        NetworkDeliveryMode.synchronous,
        networkDeliveryMode(false, .at_most_once),
    );
    try std.testing.expectEqual(
        NetworkDeliveryMode.asynchronous,
        networkDeliveryMode(false, .at_least_once),
    );
    try std.testing.expectEqual(
        NetworkDeliveryMode.asynchronous,
        networkDeliveryMode(false, .exactly_once),
    );
    try std.testing.expectEqual(
        NetworkDeliveryMode.asynchronous,
        networkDeliveryMode(true, .at_most_once),
    );
}

test "MQTT live overlap merge uses the current queue tail" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    const buffers = try slot.ensureBuffers(allocator);
    defer {
        // This test compares pointer identity only; its stack Publications do
        // not own reference-counted allocations and must not be released.
        buffers.queue.clearRetainingCapacity();
        buffers.queue_head = 0;
        slot.clearBuffers(allocator);
    }
    try buffers.queue.ensureTotalCapacityPrecise(allocator, 4);

    var prior_publication: Publication = undefined;
    var current_publication: Publication = undefined;
    var later_publication: Publication = undefined;
    slot.appendDeliveryAssumeCapacity(.{
        .publication = &prior_publication,
        .qos = .at_most_once,
        .retain = false,
    });
    try std.testing.expect(
        slot.tailDeliveryForPublication(&current_publication) == null,
    );

    slot.appendDeliveryAssumeCapacity(.{
        .publication = &current_publication,
        .qos = .at_least_once,
        .retain = false,
    });
    _ = slot.popDelivery();
    const current = slot.tailDeliveryForPublication(
        &current_publication,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(mqtt.QoS.at_least_once, current.qos);

    slot.appendDeliveryAssumeCapacity(.{
        .publication = &later_publication,
        .qos = .at_most_once,
        .retain = false,
    });
    try std.testing.expect(
        slot.tailDeliveryForPublication(&current_publication) == null,
    );
}

test "durable Session write scratch retains only bounded packets" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(allocator);
    const buffers = try slot.ensureBuffers(allocator);

    try buffers.session_write_scratch.ensureTotalCapacityPrecise(
        allocator,
        1024,
    );
    const retained = buffers.session_write_scratch.allocatedSlice().ptr;
    slot.releaseOversizedSessionScratch(allocator);
    try std.testing.expectEqual(
        retained,
        buffers.session_write_scratch.allocatedSlice().ptr,
    );

    try buffers.session_write_scratch.ensureTotalCapacityPrecise(
        allocator,
        session_write_scratch_retain_limit + 1,
    );
    slot.releaseOversizedSessionScratch(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.session_write_scratch.capacity,
    );

    try buffers.session_property_scratch.ensureTotalCapacityPrecise(
        allocator,
        session_property_scratch_retain_capacity + 1,
    );
    slot.releaseOversizedSessionScratch(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.session_property_scratch.capacity,
    );
}

test "legacy private bridge subscriptions prevent loops and preserve retain" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1 }) |protocol| {
        const bridge_connect = mqtt.Connect{
            .protocol = protocol,
            .bridge_mode = true,
            .clean_start = false,
            .keep_alive_seconds = 60,
            .client_id = "bridge",
        };
        var subscription = mqtt.Subscription{
            .topic_filter = "sensors/#",
            .qos = .at_least_once,
        };
        Broker.applyPrivateBridgeSubscriptionPolicy(
            bridge_connect,
            &subscription,
        );
        try std.testing.expect(subscription.no_local);
        try std.testing.expect(subscription.retain_as_published);

        var ordinary = mqtt.Subscription{
            .topic_filter = "sensors/#",
            .qos = .at_least_once,
        };
        var ordinary_connect = bridge_connect;
        ordinary_connect.bridge_mode = false;
        Broker.applyPrivateBridgeSubscriptionPolicy(ordinary_connect, &ordinary);
        try std.testing.expect(!ordinary.no_local);
        try std.testing.expect(!ordinary.retain_as_published);
    }
}

test "MQTT broker transfers prefixed packet ownership to Publication" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );
    const packet_len = 80;
    const allocation = try failing.allocator().alignedAlloc(
        u8,
        .@"16",
        @sizeOf(Publication) + packet_len,
    );
    const wire = allocation[@sizeOf(Publication)..];
    @memset(wire, 0xaa);
    @memcpy(wire[9..22], "adopted/topic");
    @memcpy(wire[43..50], "payload");
    var packet = runtime.OwnedPacket{
        .bytes = wire,
        .fixed = undefined,
        .prefix_len = @sizeOf(Publication),
    };
    defer packet.deinit(failing.allocator());

    const publication = try createRoutePublication(
        failing.allocator(),
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = wire[9..22],
            .packet_id = 17,
            .properties = &.{},
            .payload = wire[43..50],
        },
        2,
        std.Io.Timestamp.fromNanoseconds(0),
        &packet,
    );
    defer publication.release();
    defer publication.release();

    try std.testing.expectEqual(@as(u16, 0), packet.prefix_len);
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqual(@as(usize, 1), failing.allocations);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqualStrings("adopted/topic", publication.topic());
    try std.testing.expectEqualStrings("payload", publication.payload());
}

test "MQTT Will route failure consumes a partially committed publication" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
        },
        .retained = .{ .max_messages = 1 },
    });
    defer broker.deinit();
    const now = std.Io.Clock.awake.now(io);

    const handle = try broker.wills.set(
        "partial-will",
        .{
            .topic = "will/partial",
            .payload = "committed-once",
            .qos = .at_least_once,
            .retain = true,
        },
        60,
    );
    try broker.will_publishers.put(allocator, handle, null);
    _ = broker.wills.close(handle, .session_ended, now) catch unreachable;

    // Fail the route-plan allocation only. The retained store and router own
    // their original allocator, while match allocation uses Broker.allocator.
    try broker.router.subscribe(1, .{ .topic_filter = "will/#" });
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    broker.allocator = failing.allocator();
    var published_any = false;
    var persistent_changed = false;
    const result = broker.publishDueWillsLocked(
        now,
        &published_any,
        &persistent_changed,
    );
    broker.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(published_any);
    try std.testing.expect(persistent_changed);
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    var retained_storage: [1]retained_mod.Match = undefined;
    const retained = try broker.retained.matchInto(
        "will/partial",
        now,
        &retained_storage,
    );
    try std.testing.expectEqual(@as(usize, 1), retained.len);
    try std.testing.expectEqualStrings(
        "committed-once",
        retained[0].payload,
    );
    try std.testing.expect(broker.wills.pollOneDue(now) == null);
}

test "MQTT delivery queues use bounded eager staging and lazy growth" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(Delivery));
    }
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const queue_capacity = 1_024;
    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = queue_capacity,
        },
        .session = .{ .max_sessions = 2 },
    });
    defer broker.deinit();

    const publisher_slot = try broker.claimSlot();
    var publisher_progress: RegistrationProgress = .{};
    _ = try broker.register(
        publisher_slot,
        .{
            .protocol = .v5,
            .clean_start = true,
            .keep_alive_seconds = 30,
            .client_id = "publisher-only",
        },
        null,
        null,
        broker.options.auto_client_id_prefix,
        &publisher_progress,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        if (broker.slots[publisher_slot].buffers) |buffers|
            buffers.queue.capacity
        else
            0,
    );
    broker.abortRegistration(
        publisher_slot,
        0,
        publisher_progress.rollback_changed,
    );
    broker.releaseClaimedSlot(publisher_slot);

    const now = std.Io.Clock.awake.now(io);
    const stored = try broker.sessions.open(
        "returning-subscriber",
        false,
        60,
        now,
    );
    _ = try broker.sessions.setSubscription(
        stored.handle,
        .{ .topic_filter = "queue/#", .qos = .at_least_once },
        null,
    );
    try broker.sessions.disconnect(stored.handle, null, now);

    const subscriber_slot = try broker.claimSlot();
    var subscriber_progress: RegistrationProgress = .{};
    var resume_properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    const subscriber_registration = try broker.register(
        subscriber_slot,
        .{
            .protocol = .v5,
            .clean_start = false,
            .keep_alive_seconds = 30,
            .client_id = "returning-subscriber",
            .properties = &resume_properties,
        },
        null,
        null,
        broker.options.auto_client_id_prefix,
        &subscriber_progress,
    );
    try std.testing.expectEqual(
        @as(usize, transient_delivery_async_high_watermark),
        broker.slots[subscriber_slot].buffers.?.queue.capacity,
    );
    try std.testing.expect(
        broker.slots[subscriber_slot].buffers.?.queue.capacity <
            queue_capacity,
    );
    broker.abortRegistration(
        subscriber_slot,
        subscriber_registration.subscriber_id,
        subscriber_progress.rollback_changed,
    );
    try std.testing.expect(broker.slots[subscriber_slot].buffers == null);
    broker.releaseClaimedSlot(subscriber_slot);
}

test "MQTT delivery queue growth is transactional and bounded" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(allocator);

    try slot.ensureDeliveryCapacity(allocator, 2);
    const buffers = slot.buffers.?;
    buffers.route_reservations = 2;

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        slot.ensureDeliveryReservationCapacity(
            failing.allocator(),
            1,
            64,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), buffers.queue.capacity);
    try std.testing.expectEqual(@as(usize, 2), buffers.route_reservations);

    buffers.route_reservations = 0;
    try slot.ensureDeliveryReservationCapacity(allocator, 3, 64);
    try std.testing.expect(buffers.queue.capacity >= 3);
    try std.testing.expect(buffers.queue.capacity <= 64);

    var no_allocation = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try slot.ensureDeliveryReservationCapacity(
        no_allocation.allocator(),
        1,
        64,
    );
    try std.testing.expect(!no_allocation.has_induced_failure);
}

test "MQTT delivery queue reservations reclaim a consumed prefix" {
    const allocator = std.testing.allocator;
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(allocator);
    try slot.ensureDeliveryCapacity(allocator, 4);

    const publication = try Publication.createFromPublish(
        allocator,
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = "queue/compact",
            .packet_id = 1,
            .properties = &.{},
            .payload = "payload",
        },
        2,
        std.Io.Timestamp.fromNanoseconds(0),
    );
    const buffers = slot.buffers.?;
    buffers.queue.items.len = 4;
    buffers.queue.items[2] = .{
        .publication = publication,
        .qos = .at_least_once,
        .retain = false,
    };
    buffers.queue.items[3] = .{
        .publication = publication,
        .qos = .at_least_once,
        .retain = false,
    };
    buffers.queue_head = 2;

    var no_allocation = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try slot.ensureDeliveryReservationCapacity(
        no_allocation.allocator(),
        2,
        64,
    );
    try std.testing.expect(!no_allocation.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), buffers.queue_head);
    try std.testing.expectEqual(@as(usize, 2), buffers.queue.items.len);
    try std.testing.expectEqual(@as(usize, 4), buffers.queue.capacity);
    try std.testing.expectEqual(publication, buffers.queue.items[0].publication);
    try std.testing.expectEqual(publication, buffers.queue.items[1].publication);
}

test "MQTT offline durable fanout adopts and shares prefixed publication bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
        .session = .{
            .max_sessions = 2,
            .max_queued_per_session = 2,
        },
    });
    defer broker.deinit();

    var handles: [2]session_mod.Handle = undefined;
    for (&handles, 0..) |*handle, index| {
        var client_id: [32]u8 = undefined;
        const opened = try broker.sessions.open(
            try std.fmt.bufPrint(&client_id, "offline-{d}", .{index}),
            false,
            60,
            .zero,
        );
        handle.* = opened.handle;
        _ = try broker.sessions.setSubscription(
            opened.handle,
            .{ .topic_filter = "shared/#", .qos = .at_least_once },
            null,
        );
        _ = try broker.router.subscribeWithIdentifierStatus(
            sessionSubscriberId(opened.route_id),
            .{ .topic_filter = "shared/#", .qos = .at_least_once },
            null,
        );
        try broker.sessions.disconnect(opened.handle, null, .zero);
    }

    var persistent_changed = false;
    var publication_committed = false;
    const packet_len = 64;
    const allocation = try allocator.alignedAlloc(
        u8,
        .@"16",
        @sizeOf(Publication) + packet_len,
    );
    const wire = allocation[@sizeOf(Publication)..];
    @memset(wire, 0xaa);
    @memcpy(wire[5..17], "shared/topic");
    @memcpy(wire[17..25], "text/bin");
    @memcpy(wire[31..45], "shared-payload");
    var packet = runtime.OwnedPacket{
        .bytes = wire,
        .fixed = undefined,
        .prefix_len = @sizeOf(Publication),
    };
    defer packet.deinit(allocator);
    var property_fields = [_]mqtt.Property{
        .{ .utf8 = .{ .id = .content_type, .value = wire[17..25] } },
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    };
    var plan = try broker.enqueuePublishLocked(
        false,
        null,
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = wire[5..17],
            .packet_id = 1,
            .properties = &property_fields,
            .payload = wire[31..45],
        },
        null,
        null,
        null,
        false,
        .zero,
        &persistent_changed,
        &publication_committed,
        &packet,
        null,
    );
    defer plan.deinit(allocator);
    try std.testing.expect(!packet.owns_bytes);
    try std.testing.expectEqual(@as(u16, 0), packet.prefix_len);
    try std.testing.expect(persistent_changed);
    try std.testing.expect(publication_committed);
    try std.testing.expectEqual(@as(usize, 0), plan.deliveries.len);
    try std.testing.expectEqual(@as(usize, 0), plan.session_deliveries.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        plan.synchronous_session_targets.len,
    );

    var first_output: [1]session_mod.Transmission = undefined;
    var second_output: [1]session_mod.Transmission = undefined;
    const first = try broker.sessions.drainInto(
        handles[0],
        .zero,
        1,
        &first_output,
    );
    const second = try broker.sessions.drainInto(
        handles[1],
        .zero,
        1,
        &second_output,
    );
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqual(
        first[0].publish.topic.ptr,
        second[0].publish.topic.ptr,
    );
    try std.testing.expectEqual(
        first[0].publish.payload.ptr,
        second[0].publish.payload.ptr,
    );
    try std.testing.expectEqual(wire.ptr, first[0].publish.topic.ptr);
    try std.testing.expectEqual(@as(usize, 1), first[0].publish.properties.len);
    try std.testing.expectEqual(@as(usize, 1), second[0].publish.properties.len);
    try std.testing.expectEqualStrings("text/bin", first[0].publish.properties[0].utf8.value);
    try std.testing.expectEqualStrings("text/bin", second[0].publish.properties[0].utf8.value);
    try std.testing.expectEqualStrings("shared/topic", first[0].publish.topic);
    try std.testing.expectEqualStrings(
        "shared-payload",
        first[0].publish.payload,
    );
}

test "MQTT released QoS 2 fanout adopts pending publication bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
        .session = .{
            .max_sessions = 2,
            .max_queued_per_session = 2,
        },
    });
    defer broker.deinit();

    var handles: [2]session_mod.Handle = undefined;
    for (&handles, 0..) |*handle, index| {
        var client_id: [32]u8 = undefined;
        const opened = try broker.sessions.open(
            try std.fmt.bufPrint(&client_id, "qos2-offline-{d}", .{index}),
            false,
            60,
            .zero,
        );
        handle.* = opened.handle;
        _ = try broker.sessions.setSubscription(
            opened.handle,
            .{ .topic_filter = "qos2/shared/#", .qos = .exactly_once },
            null,
        );
        _ = try broker.router.subscribeWithIdentifierStatus(
            sessionSubscriberId(opened.route_id),
            .{ .topic_filter = "qos2/shared/#", .qos = .exactly_once },
            null,
        );
        try broker.sessions.disconnect(opened.handle, null, .zero);
    }

    try std.testing.expect(try broker.pending_qos2.recordWithSourceAndPublicationPrefix(
        77,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "qos2/shared/topic",
            .packet_id = 9,
            .payload = "pending-payload",
        },
        "publisher",
        null,
        null,
        .zero,
        true,
    ));
    var pending = broker.pending_qos2.take(77, 9).?;
    var pending_live = true;
    defer if (pending_live) broker.pending_qos2.recycle(&pending);
    const message_pointer = pending.bytes.ptr;
    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    const publish = (try pending.asPublish(9, .zero, &properties)).?;
    var plan = try broker.enqueuePublishLocked(
        false,
        null,
        publish,
        null,
        null,
        null,
        false,
        .zero,
        null,
        null,
        null,
        &pending,
    );
    defer plan.deinit(allocator);
    try std.testing.expect(!pending.canAdoptPublication());
    broker.pending_qos2.recycle(&pending);
    pending_live = false;

    var first_output: [1]session_mod.Transmission = undefined;
    var second_output: [1]session_mod.Transmission = undefined;
    const first = try broker.sessions.drainInto(
        handles[0],
        .zero,
        1,
        &first_output,
    );
    const second = try broker.sessions.drainInto(
        handles[1],
        .zero,
        1,
        &second_output,
    );
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqual(message_pointer, first[0].publish.topic.ptr);
    try std.testing.expectEqual(
        first[0].publish.topic.ptr,
        second[0].publish.topic.ptr,
    );
    try std.testing.expectEqual(
        first[0].publish.payload.ptr,
        second[0].publish.payload.ptr,
    );
}

test "MQTT publisher route plans reuse bounded slot storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
    });
    defer broker.deinit();

    const slot_index = try broker.claimSlot();
    const slot = &broker.slots[slot_index];
    slot.state.generation = @intCast(nextConnectionGeneration(
        slot.state.generation,
    ));
    const publisher_id = subscriberId(slot_index, slot.state.generation);
    try broker.router.subscribe(20, .{ .topic_filter = "tasks/#" });
    try broker.router.subscribe(10, .{ .topic_filter = "$share/g/tasks/+" });
    try broker.router.subscribe(11, .{ .topic_filter = "$share/g/tasks/+" });

    var first = try broker.matchRoutesForPublisherLocked(
        publisher_id,
        publisher_id,
        "tasks/a",
    );
    try std.testing.expect(first.scratch_owner != null);
    try std.testing.expectEqual(@as(usize, 2), first.items.len);
    try std.testing.expectEqual(@as(router_mod.SubscriberId, 10), first.items[1].subscriber_id);
    const scratch_ptr = first.items.ptr;
    first.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 0),
        slot.buffers.?.route_matches.items.len,
    );

    {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        broker.allocator = failing.allocator();
        defer broker.allocator = allocator;
        var second = try broker.matchRoutesForPublisherLocked(
            publisher_id,
            publisher_id,
            "tasks/b",
        );
        defer second.deinit(broker.allocator);
        try std.testing.expect(second.scratch_owner != null);
        try std.testing.expectEqual(scratch_ptr, second.items.ptr);
        try std.testing.expectEqual(@as(router_mod.SubscriberId, 11), second.items[1].subscriber_id);
        try std.testing.expect(!failing.has_induced_failure);
    }

    // Keep retained per-publisher memory bounded. Larger subscription sets
    // fall back before matching, so an allocation failure cannot advance the
    // shared group's round-robin cursor.
    for (30..60) |id| {
        try broker.router.subscribe(
            @intCast(id),
            .{ .topic_filter = "tasks/#" },
        );
    }
    {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        broker.allocator = failing.allocator();
        defer broker.allocator = allocator;
        try std.testing.expectError(
            error.OutOfMemory,
            broker.matchRoutesForPublisherLocked(
                publisher_id,
                publisher_id,
                "tasks/c",
            ),
        );
    }
    var fallback = try broker.matchRoutesForPublisherLocked(
        null,
        publisher_id,
        "tasks/c",
    );
    defer fallback.deinit(allocator);
    try std.testing.expect(fallback.scratch_owner == null);
    try std.testing.expectEqual(@as(usize, 32), fallback.items.len);
    try std.testing.expectEqual(
        @as(router_mod.SubscriberId, 10),
        fallback.items[fallback.items.len - 1].subscriber_id,
    );

    slot.clearBuffers(allocator);
    broker.releaseClaimedSlot(slot_index);
}

test "MQTT Clean Start journals only committed Session replacement" {
    const backing = std.testing.allocator;
    var threaded = std.Io.Threaded.init(backing, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(backing, .{});
    var broker = try Broker.init(failing.allocator(), io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
        },
        .session = .{ .max_sessions = 2 },
    });
    defer broker.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    const now = std.Io.Clock.awake.now(io);
    const old = try broker.sessions.open(
        "failed-clean-start",
        false,
        60,
        now,
    );
    _ = try broker.sessions.setSubscription(
        old.handle,
        .{ .topic_filter = "failed/clean/#", .qos = .at_least_once },
        null,
    );
    _ = try broker.router.subscribeWithIdentifierStatus(
        sessionSubscriberId(old.route_id),
        .{ .topic_filter = "failed/clean/#", .qos = .at_least_once },
        null,
    );
    _ = try broker.pending_qos2.record(
        sessionSubscriberId(old.route_id),
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "failed/clean/inbound",
            .packet_id = 91,
            .properties = &.{},
            .payload = "must-not-return",
        },
        now,
    );
    try broker.sessions.disconnect(old.handle, null, now);
    try broker.createCommitLog(tmp.dir, "failed-clean.log", .{});

    // Failure while preparing the replacement must preserve the durable
    // Session and must not journal a deletion that never committed.
    const slot_index = try broker.claimSlot();
    var slot_claimed = true;
    defer if (slot_claimed) broker.releaseClaimedSlot(slot_index);
    var progress: RegistrationProgress = .{};
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        broker.register(
            slot_index,
            .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 30,
                .client_id = "failed-clean-start",
            },
            null,
            null,
            broker.options.auto_client_id_prefix,
            &progress,
        ),
    );
    try std.testing.expect(!progress.rollback_changed);
    try std.testing.expectEqual(@as(?session_mod.Handle, old.handle), broker.sessions.find(
        "failed-clean-start",
        std.Io.Clock.awake.now(io),
    ));
    try std.testing.expectEqual(@as(usize, 1), broker.router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), broker.pending_qos2.count());
    failing.fail_index = std.math.maxInt(usize);
    broker.finishPartialPersistentChange(progress.rollback_changed);

    {
        var rejected_image = try Broker.init(backing, io, .{
            .limits = .{ .max_connections = 1 },
        });
        defer rejected_image.deinit();
        try rejected_image.restoreCommitLog(tmp.dir, "failed-clean.log", .{});
        try std.testing.expect(rejected_image.sessions.find(
            "failed-clean-start",
            std.Io.Clock.awake.now(io),
        ) != null);
        try std.testing.expectEqual(@as(usize, 1), rejected_image.router.subscriptionCount());
        try std.testing.expectEqual(@as(usize, 1), rejected_image.pending_qos2.count());
    }

    // Once replacement commits, aborting the provisional connection at the
    // CONNACK boundary must persist its deletion of the prior durable state.
    progress = .{};
    const registration = try broker.register(slot_index, .{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 30,
        .client_id = "failed-clean-start",
    }, null, null, broker.options.auto_client_id_prefix, &progress);
    try std.testing.expect(progress.rollback_changed);
    broker.abortRegistration(slot_index, registration.subscriber_id, progress.rollback_changed);
    broker.releaseClaimedSlot(slot_index);
    slot_claimed = false;
    broker.finishPartialPersistentChange(progress.rollback_changed);

    var restored = try Broker.init(backing, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
        },
    });
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "failed-clean.log", .{});
    try std.testing.expect(restored.sessions.find(
        "failed-clean-start",
        std.Io.Clock.awake.now(io),
    ) == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        restored.router.subscriptionCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        restored.pending_qos2.count(),
    );
}

test "broker maps negotiated capability violations to DISCONNECT reasons" {
    try std.testing.expectEqual(
        @as(?u8, 0x9b),
        disconnectReasonForReadViolation(error.QoSNotSupported),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x9a),
        disconnectReasonForReadViolation(error.RetainNotSupported),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x93),
        disconnectReasonForReadViolation(error.ReceiveMaximumExceeded),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x94),
        disconnectReasonForReadViolation(error.TopicAliasInvalid),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x9e),
        disconnectReasonForReadViolation(
            error.SharedSubscriptionsNotSupported,
        ),
    );
    try std.testing.expectEqual(
        @as(?u8, 0xa1),
        disconnectReasonForReadViolation(
            error.SubscriptionIdentifiersNotSupported,
        ),
    );
    try std.testing.expectEqual(
        @as(?u8, 0xa2),
        disconnectReasonForReadViolation(
            error.WildcardSubscriptionsNotSupported,
        ),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x82),
        disconnectReasonForReadViolation(error.InvalidProperty),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x82),
        disconnectReasonForReadViolation(error.InvalidPacketDirection),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x82),
        disconnectReasonForReadViolation(error.ReservedPacketType),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidFlags),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidQoS),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidPacketType),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidPropertyIdentifier),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.MalformedPropertyContext),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.MalformedSubscriptionOptions),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReasonForReadViolation(error.InvalidUtf8),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x95),
        disconnectReasonForReadViolation(error.PacketTooLarge),
    );
}

test "broker rejects invalid listener Client Identifier prefixes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.InvalidProperty,
        Broker.init(allocator, io, .{
            .limits = .{ .max_connections = 1 },
            .client_id_prefix = "bad\x00prefix",
        }),
    );
    var required_prefix = [_]u8{ 's', 'e', 'c', 'u', 'r', 'e', '-' };
    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_connections = 1 },
        .client_id_prefix = &required_prefix,
    });
    defer broker.deinit();
    @memset(&required_prefix, 'x');
    try std.testing.expectEqualStrings(
        "secure-",
        broker.options.client_id_prefix,
    );

    try std.testing.expectError(
        error.InvalidProperty,
        broker.serveListeners(&.{.{
            .source = undefined,
            .auto_client_id_prefix = "x" ** 51,
            .connection_count = 0,
        }}),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        broker.serveListeners(&.{.{
            .source = undefined,
            .auto_client_id_prefix = "bad\x00prefix",
            .connection_count = 0,
        }}),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        broker.serveListeners(&.{.{
            .source = undefined,
            .max_connections = 0,
            .connection_count = 0,
        }}),
    );
    var shutdown: std.Io.Event = .unset;
    try std.testing.expectError(
        error.InvalidProperty,
        broker.serveListenersUntil(&.{.{
            .source = undefined,
            .max_connections = 0,
        }}, .{ .shutdown = &shutdown }),
    );
}

test "transient inflight payload accounting is lazy and clears safely" {
    var slot: ClientSlot = .{};
    defer slot.clearBuffers(std.testing.allocator);

    try std.testing.expect(slot.buffers == null);
    try std.testing.expectEqual(
        @as(u32, 0),
        if (slot.buffers) |buffers|
            buffers.transient_inflight_payloads.capacity()
        else
            0,
    );
    try std.testing.expect(!slot.transientInflightPayloadLimitReached(10));
    const buffers = try slot.ensureBuffers(std.testing.allocator);
    try buffers.transient_inflight_payloads.ensureUnusedCapacity(
        std.testing.allocator,
        2,
    );
    slot.recordTransientInflight(1, 6);
    slot.recordTransientInflight(2, 6);
    try std.testing.expect(slot.transientInflightPayloadLimitReached(10));
    try std.testing.expect(!slot.releaseTransientInflight(99));
    try std.testing.expect(slot.releaseTransientInflight(1));
    try std.testing.expectEqual(
        @as(usize, 6),
        buffers.transient_inflight_payload_bytes,
    );
    slot.clearTransientInflight();
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.transient_inflight_payload_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        buffers.transient_inflight_payloads.count(),
    );
}

test {
    _ = load_metrics;
    _ = @import("source_view_tests.zig");
    _ = @import("../broker_tests.zig");
    _ = @import("persistence_tests.zig");
    _ = @import("local_consumer_tests.zig");
    _ = @import("router_churn_tests.zig");
    _ = @import("fanout/transport_tests.zig");
    _ = @import("fanout/flush_tests.zig");
}

test "MQTT broker teardown collects late shared writer errors before slot reuse" {
    try @import("session_writer/retirement_tests.zig").lateErrorBeforeReuse(struct {
        pub const BrokerType = Broker;
        pub const claim = Broker.claimSlot;
        pub const release = Broker.releaseClaimedSlot;
        pub const unregister = Broker.unregister;
        pub const id = subscriberId;
    });
}

test "broker retained expiry scan persists physical removal" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var source = try Broker.init(allocator, io, .{
        .retained_expiry_interval = .fromMilliseconds(10),
        .persistent_change_autosave = .{
            .dir = tmp.dir,
            .sub_path = "expiry.db",
            .max_changes = 1,
        },
    });
    var source_owned = true;
    defer if (source_owned) source.deinit();
    const stored_at = std.Io.Clock.awake.now(io);
    const expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 1,
    } }};
    _ = try source.retained.applyPublish(
        "expiry/persisted",
        "value",
        .{
            .retain = true,
            .properties = &expiry,
            .now = stored_at,
        },
    );
    try source.createCommitLog(tmp.dir, "expiry.log", .{});

    // The first lifecycle pass establishes the periodic scan deadline. The
    // second crosses both that deadline and the retained message's lifetime.
    try source.processDueLifecycle(stored_at);
    try source.processDueLifecycle(
        stored_at.addDuration(.fromSeconds(2)),
    );
    try std.testing.expectEqual(@as(usize, 0), source.stats().retained_messages);
    try std.testing.expectEqual(@as(?anyerror, null), source.persistentChangeAutosaveError());
    _ = try tmp.dir.statFile(io, "expiry.db", .{});
    // Initial state is record 1 and periodic removal is record 2.
    try std.testing.expectEqual(@as(u64, 3), try source.appendCommit());
    source.deinit();
    source_owned = false;

    var journal_restored = try Broker.init(allocator, io, .{});
    defer journal_restored.deinit();
    try journal_restored.restoreCommitLog(tmp.dir, "expiry.log", .{});
    try std.testing.expectEqual(
        @as(usize, 0),
        journal_restored.stats().retained_messages,
    );

    var snapshot_restored = try Broker.init(allocator, io, .{});
    defer snapshot_restored.deinit();
    try snapshot_restored.restoreSnapshot(tmp.dir, "expiry.db");
    try std.testing.expectEqual(
        @as(usize, 0),
        snapshot_restored.stats().retained_messages,
    );
}

test "MQTT broker $SYS version and client aliases match Mosquitto" {
    try std.testing.expectEqualStrings("$SYS/broker/version", SystemMetric.version.topic());
    try std.testing.expectEqualStrings("$SYS/broker/clients/active", SystemMetric.clients_active.topic());
    try std.testing.expectEqualStrings("$SYS/broker/clients/inactive", SystemMetric.clients_inactive.topic());
    try std.testing.expectEqualStrings("$SYS/broker/messages/stored", SystemMetric.messages_stored.topic());
    try std.testing.expectEqualStrings("$SYS/broker/store/messages/count", SystemMetric.store_messages_count.topic());
    try std.testing.expectEqualStrings("$SYS/broker/store/messages/bytes", SystemMetric.store_messages_bytes.topic());
    try std.testing.expectEqualStrings("$SYS/broker/packet/out/count", SystemMetric.packet_out_count.topic());
    try std.testing.expectEqualStrings("$SYS/broker/packet/out/bytes", SystemMetric.packet_out_bytes.topic());
    try std.testing.expectEqualStrings("$SYS/broker/connections/socket/count", SystemMetric.connections_socket_count.topic());
    try std.testing.expectEqualStrings("$SYS/broker/load/sockets/1min", SystemMetric.load_sockets_1min.topic());
    try std.testing.expectEqualStrings("$SYS/broker/load/sockets/5min", SystemMetric.load_sockets_5min.topic());
    try std.testing.expectEqualStrings("$SYS/broker/load/sockets/15min", SystemMetric.load_sockets_15min.topic());
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "netz version 0.1.0",
        formatSystemMetric(&buffer, undefined, .version).?,
    );
    // Heap gauges are omitted when no heap source is configured.
    var heap_stats: Stats = std.mem.zeroes(Stats);
    try std.testing.expect(formatSystemMetric(&buffer, heap_stats, .heap_current) == null);
    try std.testing.expect(formatSystemMetric(&buffer, heap_stats, .heap_maximum) == null);
    heap_stats.heap_current_bytes = 1_536;
    heap_stats.heap_maximum_bytes = 4_096;
    try std.testing.expectEqualStrings("1536", formatSystemMetric(&buffer, heap_stats, .heap_current).?);
    try std.testing.expectEqualStrings("4096", formatSystemMetric(&buffer, heap_stats, .heap_maximum).?);
    try std.testing.expectEqualStrings("$SYS/broker/heap/current", SystemMetric.heap_current.topic());
    try std.testing.expectEqualStrings("$SYS/broker/heap/maximum", SystemMetric.heap_maximum.topic());
}
