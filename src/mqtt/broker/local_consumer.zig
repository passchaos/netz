//! Owned delivery values for broker-internal persistent consumers.
//!
//! The Broker owns routing and Session state. These values cross the broker
//! mutex boundary without borrowing Session storage, allowing a caller to
//! perform remote I/O before acknowledging or retrying the local delivery.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const session_route = @import("session_route.zig");
const session = @import("../session/mod.zig");

pub const Options = struct {
    /// Stable identity for this subscription set. Reopening with a changed
    /// set is rejected; use another identity when reconfiguring the source.
    id: [16]u8,
    subscriptions: []const mqtt.Subscription,
    /// Maximum concurrently selected QoS 1/2 PUBLISH packets. A selected
    /// QoS 0 event must be completed or retried before the next poll.
    receive_maximum: u16 = 16,
};

pub const Handle = struct {
    session: session.Handle,
    route_id: u64,
    receive_maximum: u16,
    session_present: bool,
    active: bool = true,
};

pub const AckAction = session.AckAction;

pub const OwnedPublish = struct {
    allocator: std.mem.Allocator,
    value: mqtt.Publish,
    topic: []u8,
    payload: []u8,
    properties: []mqtt.Property,

    pub fn init(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
    ) !OwnedPublish {
        const topic = try allocator.dupe(u8, publish.topic);
        errdefer allocator.free(topic);
        const payload = try allocator.dupe(u8, publish.payload);
        errdefer allocator.free(payload);
        const properties = try owned_properties.clone(
            allocator,
            publish.properties,
            owned_properties.keepAll,
        );
        return .{
            .allocator = allocator,
            .value = .{
                .dup = publish.dup,
                .qos = publish.qos,
                .retain = publish.retain,
                .topic = topic,
                .packet_id = publish.packet_id,
                .properties = properties.properties,
                .payload = payload,
            },
            .topic = topic,
            .payload = payload,
            .properties = properties.properties,
        };
    }

    pub fn deinit(self: *OwnedPublish) void {
        owned_properties.deinit(self.allocator, self.properties);
        self.allocator.free(self.payload);
        self.allocator.free(self.topic);
        self.* = undefined;
    }
};

pub const Event = union(enum) {
    publish: OwnedPublish,
    pubrel: u16,

    pub fn deinit(self: *Event) void {
        switch (self.*) {
            .publish => |*publish| publish.deinit(),
            .pubrel => {},
        }
        self.* = undefined;
    }
};

const internal_client_id_prefix = "\x00netz-local-consumer-v1:";
pub const internal_client_id_len = internal_client_id_prefix.len + 32;

pub fn isInternalClientId(client_id: []const u8) bool {
    return client_id.len == internal_client_id_len and
        std.mem.startsWith(u8, client_id, internal_client_id_prefix);
}

pub fn internalClientId(
    id: [16]u8,
    storage: *[internal_client_id_len]u8,
) []const u8 {
    const prefix = internal_client_id_prefix;
    @memcpy(storage[0..prefix.len], prefix);
    const hex = std.fmt.bytesToHex(id, .lower);
    @memcpy(storage[prefix.len..], &hex);
    return storage;
}

/// Broker-facing implementation; the context keeps state and persistence
/// coordination private to the Broker while this module owns consumer policy.
pub fn Operations(comptime Context: type) type {
    return struct {
        const Broker = Context.BrokerType;
        const Error = Context.ErrorType;
        const LocalConsumer = Handle;
        const LocalConsumerOptions = Options;
        const LocalConsumerEvent = Event;
        const LocalConsumerAckAction = AckAction;
        const session_mod = session;

        /// Open one durable, broker-internal subscription source. Its identifier
        /// is encoded outside valid MQTT UTF-8, so a network client cannot take
        /// over this Session. This trusted producer API does not apply network
        /// subscriber ACLs. Callers must serialize operations on each handle
        /// and close it before `Broker.deinit`; separate consumers can run
        /// concurrently. Commit failures can leave a recoverable Session;
        /// reopening the same identity retries its durability boundary.
        pub fn openLocalConsumer(
            self: *Broker,
            options: LocalConsumerOptions,
        ) Error!LocalConsumer {
            if (options.subscriptions.len == 0 or options.receive_maximum == 0) {
                return error.InvalidProperty;
            }
            if (options.subscriptions.len > self.options.session.max_subscriptions_per_session) {
                return error.SubscriptionLimitExceeded;
            }
            for (options.subscriptions, 0..) |subscription, index| {
                try mqtt.validateTopicFilter(subscription.topic_filter);
                if (subscription.retain_handling > 2 or
                    (subscription.no_local and std.mem.startsWith(
                        u8,
                        subscription.topic_filter,
                        "$share/",
                    )))
                {
                    return error.InvalidSubscription;
                }
                for (options.subscriptions[0..index]) |previous| {
                    if (std.mem.eql(
                        u8,
                        previous.topic_filter,
                        subscription.topic_filter,
                    )) return error.InvalidSubscription;
                }
            }

            var client_id_storage: [internal_client_id_len]u8 =
                undefined;
            const client_id = internalClientId(
                options.id,
                &client_id_storage,
            );
            const now = std.Io.Clock.awake.now(self.io);
            self.state_mutex.lockUncancelable(self.io);
            var state_locked = true;
            var persistent_changed = Context.pruneExpiredSessionRoutesLocked(self, now) != 0;
            errdefer if (state_locked) {
                Context.recordPersistentChangeLocked(self, persistent_changed);
                self.state_mutex.unlock(self.io);
                Context.finishPartialPersistentChange(self, persistent_changed);
            };
            try self.local_consumer_routes.ensureUnusedCapacity(self.allocator, 1);
            const previous = self.sessions.find(client_id, now);
            if (previous) |handle| {
                const route_id = try self.sessions.routeId(handle);
                if (self.local_consumer_routes.contains(route_id)) {
                    return error.LocalConsumerAlreadyOpen;
                }
                if (!try localConsumerSubscriptionsEqualLocked(
                    self,
                    handle,
                    options.subscriptions,
                )) return error.LocalConsumerIdentityMismatch;
            }
            const opened = try self.sessions.open(
                client_id,
                false,
                std.math.maxInt(u32),
                now,
            );
            var registration_complete = false;
            errdefer if (!registration_complete and !opened.session_present) {
                _ = self.router.removeSubscriber(
                    session_route.sessionSubscriberId(opened.route_id),
                ) catch {};
                self.sessions.discardHandle(opened.handle) catch {};
            };
            if (!opened.session_present) {
                persistent_changed = true;
                for (options.subscriptions) |subscription| {
                    const session_existed = try self.sessions.setSubscription(
                        opened.handle,
                        subscription,
                        null,
                    );
                    const route_existed = try self.router.subscribeWithStatus(
                        session_route.sessionSubscriberId(opened.route_id),
                        subscription,
                    );
                    std.debug.assert(!session_existed and !route_existed);
                    const deliveries = try self.retained.deliveriesAlloc(
                        self.allocator,
                        subscription,
                        .{
                            .subscriber_id = session_route.sessionSubscriberId(opened.route_id),
                            .subscriber_client_id = client_id,
                            .upgrade_outgoing_qos = self.options.upgrade_outgoing_qos,
                        },
                        now,
                    );
                    defer self.allocator.free(deliveries);
                    var properties: std.ArrayList(mqtt.Property) = .empty;
                    defer properties.deinit(self.allocator);
                    for (deliveries) |delivery| {
                        if (!Context.retainedSourceAuthorized(self, delivery)) continue;
                        try Context.prepareRetainedDeliveryProperties(
                            &properties,
                            self.allocator,
                            delivery.properties,
                            delivery.message_expiry_interval,
                        );
                        try Context.enqueueSessionDeliveryLocked(
                            self,
                            opened.handle,
                            null,
                            true,
                            delivery.qos,
                            .{
                                .dup = false,
                                .qos = delivery.qos,
                                .retain = true,
                                .topic = delivery.topic,
                                .packet_id = null,
                                .properties = properties.items,
                                .payload = delivery.payload,
                            },
                            now,
                            &persistent_changed,
                        );
                        properties.clearRetainingCapacity();
                    }
                }
            }
            try self.sessions.disconnect(opened.handle, null, now);
            self.local_consumer_routes.putAssumeCapacityNoClobber(
                opened.route_id,
                opened.handle,
            );
            registration_complete = true;
            Context.recordPersistentChangeLocked(self, persistent_changed);
            self.state_mutex.unlock(self.io);
            state_locked = false;
            Context.finalizePersistentChange(
                self,
                true,
                persistent_changed,
            ) catch |err| {
                self.state_mutex.lockUncancelable(self.io);
                _ = self.local_consumer_routes.remove(opened.route_id);
                // Keep the durable Session on commit failure: a caller can reopen
                // the same identity and retry the durability boundary without
                // losing messages that were already routed into this Session.
                self.state_mutex.unlock(self.io);
                return err;
            };
            return .{
                .session = opened.handle,
                .route_id = opened.route_id,
                .receive_maximum = options.receive_maximum,
                .session_present = opened.session_present,
            };
        }

        pub fn closeLocalConsumer(
            self: *Broker,
            consumer: *LocalConsumer,
        ) void {
            if (!consumer.active) return;
            self.state_mutex.lockUncancelable(self.io);
            if (ownsConsumerLocked(self, consumer)) {
                // Return a selected QoS 0 message before open() changes the Session
                // generation. QoS 1/2 become retransmittable on the next open.
                self.sessions.disconnect(
                    consumer.session,
                    null,
                    std.Io.Clock.awake.now(self.io),
                ) catch unreachable;
                _ = self.local_consumer_routes.remove(consumer.route_id);
            }
            self.state_mutex.unlock(self.io);
            consumer.active = false;
        }

        /// Return one owned Session transmission, or null when no work is ready.
        /// Selection is journaled before the event is returned. The returned value
        /// owns its bytes and can be used after the Broker lock is released.
        pub fn pollLocalConsumer(
            self: *Broker,
            consumer: *LocalConsumer,
        ) Error!?LocalConsumerEvent {
            if (!consumer.active) return error.LocalConsumerClosed;
            self.state_mutex.lockUncancelable(self.io);
            var state_locked = true;
            var persistent_changed = false;
            errdefer if (state_locked) {
                Context.recordPersistentChangeLocked(self, persistent_changed);
                self.state_mutex.unlock(self.io);
                Context.finishPartialPersistentChange(self, persistent_changed);
            };
            if (!ownsConsumerLocked(self, consumer)) {
                return error.LocalConsumerClosed;
            }
            var storage: [1]session_mod.Transmission = undefined;
            const transmissions = try self.sessions.drainIntoTrackingSnapshotChange(
                consumer.session,
                std.Io.Clock.awake.now(self.io),
                consumer.receive_maximum,
                &storage,
                &persistent_changed,
            );
            if (transmissions.len == 0) {
                Context.recordPersistentChangeLocked(self, persistent_changed);
                self.state_mutex.unlock(self.io);
                state_locked = false;
                try Context.finalizePersistentChange(
                    self,
                    persistent_changed,
                    persistent_changed,
                );
                return null;
            }
            const event = cloneLocalConsumerEvent(
                self,
                transmissions[0],
            ) catch |err| {
                retryLocalConsumerTransmissionLocked(
                    self,
                    consumer.session,
                    transmissions[0],
                ) catch {};
                Context.recordPersistentChangeLocked(self, persistent_changed);
                self.state_mutex.unlock(self.io);
                state_locked = false;
                Context.finishPartialPersistentChange(self, persistent_changed);
                return err;
            };
            Context.recordPersistentChangeLocked(self, persistent_changed);
            self.state_mutex.unlock(self.io);
            state_locked = false;
            Context.finalizePersistentChange(
                self,
                true,
                persistent_changed,
            ) catch |err| {
                self.retryLocalConsumerEvent(consumer, event) catch {};
                var owned = event;
                owned.deinit();
                return err;
            };
            return event;
        }

        pub fn acknowledgeLocalConsumer(
            self: *Broker,
            consumer: *LocalConsumer,
            packet_type: mqtt.PacketType,
            packet_id: u16,
            reason_code: u8,
        ) Error!LocalConsumerAckAction {
            if (!consumer.active) return error.LocalConsumerClosed;
            if (packet_type != .puback and packet_type != .pubrec and
                packet_type != .pubcomp)
            {
                return error.InvalidPacketType;
            }
            self.state_mutex.lockUncancelable(self.io);
            var state_locked = true;
            defer if (state_locked) self.state_mutex.unlock(self.io);
            if (!ownsConsumerLocked(self, consumer)) {
                return error.LocalConsumerClosed;
            }
            const action = try self.sessions.handleAck(
                consumer.session,
                packet_type,
                packet_id,
                reason_code,
            );
            Context.recordPersistentChangeLocked(self, true);
            self.state_mutex.unlock(self.io);
            state_locked = false;
            try Context.finalizePersistentChange(self, true, true);
            return action;
        }

        /// Complete ownership of a QoS 0 delivery after the downstream operation
        /// succeeds. Until this call, `retryLocalConsumerEvent` can restore it to
        /// the front of the durable queue.
        pub fn completeLocalConsumerQoS0(
            self: *Broker,
            consumer: *LocalConsumer,
        ) Error!void {
            if (!consumer.active) return error.LocalConsumerClosed;
            self.state_mutex.lockUncancelable(self.io);
            var state_locked = true;
            defer if (state_locked) self.state_mutex.unlock(self.io);
            if (!ownsConsumerLocked(self, consumer)) {
                return error.LocalConsumerClosed;
            }
            try self.sessions.completeQoS0Transmission(
                consumer.session,
                consumer.route_id,
                0,
            );
            Context.recordPersistentChangeLocked(self, true);
            self.state_mutex.unlock(self.io);
            state_locked = false;
            try Context.finalizePersistentChange(self, true, true);
        }

        /// Return a previously selected event to the Session transmission cursor.
        /// The event remains caller-owned and must still be deinitialized.
        pub fn retryLocalConsumerEvent(
            self: *Broker,
            consumer: *LocalConsumer,
            event: LocalConsumerEvent,
        ) Error!void {
            if (!consumer.active) return error.LocalConsumerClosed;
            self.state_mutex.lockUncancelable(self.io);
            defer self.state_mutex.unlock(self.io);
            if (!ownsConsumerLocked(self, consumer)) {
                return error.LocalConsumerClosed;
            }
            try retryLocalConsumerTransmissionLocked(
                self,
                consumer.session,
                switch (event) {
                    .publish => |publish| .{ .publish = .{
                        .topic = publish.value.topic,
                        .payload = publish.value.payload,
                        .qos = publish.value.qos,
                        .retain = publish.value.retain,
                        .dup = publish.value.dup,
                        .packet_id = publish.value.packet_id orelse 0,
                        .properties = publish.value.properties,
                        .message_expiry_interval = mqtt.messageExpiryInterval(
                            publish.value.properties,
                        ),
                    } },
                    .pubrel => |packet_id| .{ .pubrel = .{
                        .packet_id = packet_id,
                    } },
                },
            );
        }

        fn ownsConsumerLocked(self: *Broker, consumer: *const LocalConsumer) bool {
            const current = self.local_consumer_routes.get(consumer.route_id) orelse
                return false;
            return current.index == consumer.session.index and
                current.generation == consumer.session.generation;
        }

        fn cloneLocalConsumerEvent(
            self: *Broker,
            transmission: session_mod.Transmission,
        ) Error!LocalConsumerEvent {
            return switch (transmission) {
                .pubrel => |pubrel| .{ .pubrel = pubrel.packet_id },
                .publish => |publish| blk: {
                    var properties: std.ArrayList(mqtt.Property) = .empty;
                    defer properties.deinit(self.allocator);
                    try Context.prepareRetainedDeliveryProperties(
                        &properties,
                        self.allocator,
                        publish.properties,
                        publish.message_expiry_interval,
                    );
                    break :blk .{ .publish = try OwnedPublish.init(
                        self.allocator,
                        .{
                            .dup = publish.dup,
                            .qos = publish.qos,
                            .retain = publish.retain,
                            .topic = publish.topic,
                            .packet_id = if (publish.qos == .at_most_once)
                                null
                            else
                                publish.packet_id,
                            .properties = properties.items,
                            .payload = publish.payload,
                        },
                    ) };
                },
            };
        }

        fn retryLocalConsumerTransmissionLocked(
            self: *Broker,
            handle: session_mod.Handle,
            transmission: session_mod.Transmission,
        ) Error!void {
            switch (transmission) {
                .publish => |publish| try self.sessions.retryUnsentPublish(
                    handle,
                    publish.packet_id,
                ),
                .pubrel => |pubrel| try self.sessions.retryUnsentPubRel(
                    handle,
                    pubrel.packet_id,
                ),
            }
        }

        fn localConsumerSubscriptionsEqualLocked(
            self: *Broker,
            handle: session_mod.Handle,
            expected: []const mqtt.Subscription,
        ) Error!bool {
            const stats_value = try self.sessions.stats(handle);
            if (stats_value.subscription_count != expected.len) return false;
            const storage = try self.allocator.alloc(
                session_mod.Subscription,
                expected.len,
            );
            defer self.allocator.free(storage);
            const actual = try self.sessions.subscriptionsInto(handle, storage);
            for (expected) |wanted| {
                var found = false;
                for (actual) |existing| {
                    if (!std.mem.eql(
                        u8,
                        wanted.topic_filter,
                        existing.topic_filter,
                    )) continue;
                    found = existing.qos == wanted.qos and
                        existing.no_local == wanted.no_local and
                        existing.retain_as_published ==
                            wanted.retain_as_published and
                        existing.retain_handling == wanted.retain_handling and
                        existing.subscription_identifier == null;
                    break;
                }
                if (!found) return false;
            }
            return true;
        }
    };
}

test "internal local-consumer identifiers cannot collide with MQTT UTF-8" {
    var storage: [internal_client_id_len]u8 = undefined;
    const client_id = internalClientId([_]u8{0xab} ** 16, &storage);
    try std.testing.expectEqual(@as(usize, internal_client_id_len), client_id.len);
    try std.testing.expectError(
        error.InvalidUtf8,
        mqtt.validateUtf8String(client_id),
    );
}

test "owned local-consumer publish survives source mutation" {
    const allocator = std.testing.allocator;
    var topic = "source/topic".*;
    var payload = "payload".*;
    var property_value = "value".*;
    var properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .content_type,
        .value = &property_value,
    } }};
    var publish = try OwnedPublish.init(allocator, .{
        .dup = true,
        .qos = .at_least_once,
        .retain = true,
        .topic = &topic,
        .packet_id = 7,
        .properties = &properties,
        .payload = &payload,
    });
    defer publish.deinit();
    @memset(&topic, 'x');
    @memset(&payload, 'x');
    @memset(&property_value, 'x');
    try std.testing.expectEqualStrings("source/topic", publish.value.topic);
    try std.testing.expectEqualStrings("payload", publish.value.payload);
    try std.testing.expectEqualStrings(
        "value",
        publish.value.properties[0].utf8.value,
    );
}

test "owned local-consumer publish allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testOwnedPublishAllocationFailures,
        .{},
    );
}

fn testOwnedPublishAllocationFailures(allocator: std.mem.Allocator) !void {
    var properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = "key",
        .value = "value",
    } }};
    var publish = try OwnedPublish.init(allocator, .{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "source/topic",
        .packet_id = 1,
        .properties = &properties,
        .payload = "payload",
    });
    defer publish.deinit();
}
