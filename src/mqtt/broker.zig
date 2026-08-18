//! Bounded in-memory MQTT broker core.
//!
//! This module composes the transport-independent connection runtime with the
//! topic router. It intentionally focuses on the live broker hot path:
//! SUBSCRIBE/UNSUBSCRIBE, QoS 0/1 PUBLISH routing, No Local/shared selection,
//! downstream acknowledgements, and connection cleanup. Durable sessions,
//! retained state, QoS 2, and Will scheduling remain explicit higher-level
//! components rather than being silently approximated here.

const std = @import("std");
const mqtt = @import("mod.zig");
const router_mod = @import("router.zig");
const runtime = @import("runtime.zig");

const net = std.Io.net;

pub const Error = runtime.Error || router_mod.Error || error{
    BrokerFull,
    ClientNotRegistered,
    ClientOffline,
    UnsupportedBrokerPacket,
};

pub const Limits = struct {
    max_connections: usize = 1024,
    max_queued_deliveries_per_connection: usize = 256,
    runtime: runtime.Limits = .{},
};

pub const Options = struct {
    limits: Limits = .{},
    router: router_mod.Options = .{},
    accept: runtime.AcceptOptions = .{
        .protocol = .v5,
        .max_outgoing_inflight = 64,
    },
};

const Publication = struct {
    allocator: std.mem.Allocator,
    references: std.atomic.Value(usize),
    bytes: []u8,
    topic_len: usize,

    fn create(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        reference_count: usize,
    ) std.mem.Allocator.Error!*Publication {
        std.debug.assert(reference_count != 0);
        const bytes_len = std.math.add(
            usize,
            publish.topic.len,
            publish.payload.len,
        ) catch return error.OutOfMemory;
        const bytes = try allocator.alloc(u8, bytes_len);
        errdefer allocator.free(bytes);
        @memcpy(bytes[0..publish.topic.len], publish.topic);
        @memcpy(bytes[publish.topic.len..], publish.payload);
        const publication = try allocator.create(Publication);
        publication.* = .{
            .allocator = allocator,
            .references = .init(reference_count),
            .bytes = bytes,
            .topic_len = publish.topic.len,
        };
        return publication;
    }

    fn topic(self: Publication) []const u8 {
        return self.bytes[0..self.topic_len];
    }

    fn payload(self: Publication) []const u8 {
        return self.bytes[self.topic_len..];
    }

    fn release(self: *Publication) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        if (previous != 1) return;
        const allocator = self.allocator;
        allocator.free(self.bytes);
        self.* = undefined;
        allocator.destroy(self);
    }
};

const Delivery = struct {
    publication: *Publication,
    qos: mqtt.QoS,
    retain: bool,

    fn deinit(self: *Delivery) void {
        self.publication.release();
        self.* = undefined;
    }
};

const ClientSlot = struct {
    generation: u32 = 0,
    active: bool = false,
    connection: ?runtime.Connection = null,
    writer_mutex: std.Io.Mutex = .init,
    queue: std.ArrayList(Delivery) = .empty,
    queue_head: usize = 0,
    // Used only while `state_mutex` is held. A route can select the same
    // client through overlapping subscriptions, so capacity must account for
    // every delivery in the plan before any queue is mutated.
    route_reservations: usize = 0,

    fn clearQueue(self: *ClientSlot) void {
        for (self.queue.items[self.queue_head..]) |*delivery| {
            delivery.deinit();
        }
        self.queue.clearRetainingCapacity();
        self.queue_head = 0;
    }

    fn queuedCount(self: ClientSlot) usize {
        return self.queue.items.len - self.queue_head;
    }

    fn popDelivery(self: *ClientSlot) ?Delivery {
        if (self.queue_head == self.queue.items.len) return null;
        const delivery = self.queue.items[self.queue_head];
        self.queue_head += 1;
        if (self.queue_head >= 64 and
            self.queue_head * 2 >= self.queue.items.len)
        {
            const remaining = self.queue.items.len - self.queue_head;
            if (remaining != 0) {
                std.mem.copyForwards(
                    Delivery,
                    self.queue.items[0..remaining],
                    self.queue.items[self.queue_head..],
                );
            }
            self.queue.items.len = remaining;
            self.queue_head = 0;
        }
        return delivery;
    }

    fn pushFront(self: *ClientSlot, delivery: Delivery) void {
        if (self.queue_head != 0) {
            self.queue_head -= 1;
            self.queue.items[self.queue_head] = delivery;
            return;
        }

        // `popDelivery` can compact consumed storage before the network write
        // reports InflightFull. Compaction leaves at least one unused element
        // of capacity, allowing the delivery to be restored without an
        // allocation or a fallible backpressure path.
        std.debug.assert(self.queue.items.len < self.queue.capacity);
        const old_len = self.queue.items.len;
        self.queue.appendAssumeCapacity(delivery);
        std.mem.copyBackwards(
            Delivery,
            self.queue.items[1 .. old_len + 1],
            self.queue.items[0..old_len],
        );
        self.queue.items[0] = delivery;
    }

    fn appendDeliveryAssumeCapacity(
        self: *ClientSlot,
        delivery: Delivery,
    ) void {
        // Consumed prefix storage is part of the bounded queue allocation. Use
        // it before growing logical length; this keeps the hot route path
        // allocation-free even if compaction has not reached its threshold.
        if (self.queue.items.len == self.queue.capacity and
            self.queue_head != 0)
        {
            const remaining = self.queuedCount();
            std.mem.copyForwards(
                Delivery,
                self.queue.items[0..remaining],
                self.queue.items[self.queue_head..],
            );
            self.queue.items.len = remaining;
            self.queue_head = 0;
        }
        std.debug.assert(self.queue.items.len < self.queue.capacity);
        self.queue.appendAssumeCapacity(delivery);
    }
};

/// A broker listener that accepts a configured, bounded number of live TCP
/// clients and routes between them until each disconnects.
pub const Broker = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: runtime.Server,
    options: Options,
    router: router_mod.Router,
    slots: []ClientSlot,
    state_mutex: std.Io.Mutex = .init,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: Options,
    ) Error!Broker {
        if (options.limits.max_connections == 0 or
            options.limits.max_queued_deliveries_per_connection == 0 or
            options.accept.protocol != .v5)
        {
            return error.InvalidProperty;
        }
        const slots = try allocator.alloc(
            ClientSlot,
            options.limits.max_connections,
        );
        @memset(slots, .{});
        errdefer allocator.free(slots);
        var router = try router_mod.Router.initWithOptions(
            allocator,
            options.router,
        );
        errdefer router.deinit();
        return .{
            .allocator = allocator,
            .io = io,
            .server = try runtime.Server.listen(
                allocator,
                io,
                bind_address,
                options.limits.runtime,
            ),
            .options = options,
            .router = router,
            .slots = slots,
        };
    }

    pub fn deinit(self: *Broker) void {
        for (self.slots) |*slot| {
            slot.clearQueue();
            slot.queue.deinit(self.allocator);
            if (slot.connection) |*connection| connection.close();
        }
        self.allocator.free(self.slots);
        self.router.deinit();
        self.server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Broker) net.IpAddress {
        return self.server.address();
    }

    /// Accept exactly `connection_count` clients and serve them concurrently.
    ///
    /// This finite form makes lifecycle and benchmark teardown deterministic.
    /// A process-level accept loop can call it repeatedly in batches.
    pub fn serve(
        self: *Broker,
        connection_count: usize,
    ) anyerror!void {
        if (connection_count > self.slots.len) return error.BrokerFull;
        var group: std.Io.Group = .init;
        errdefer group.cancel(self.io);
        const errors = try self.allocator.alloc(
            ?anyerror,
            connection_count,
        );
        defer self.allocator.free(errors);
        @memset(errors, null);

        for (errors, 0..) |*result, index| {
            var accepted = try self.server.accept(self.options.accept);
            errdefer accepted.deinit(self.allocator);
            const subscriber_id = try self.register(
                index,
                &accepted.connection,
            );
            const task = ClientTask{
                .broker = self,
                .slot_index = index,
                .subscriber_id = subscriber_id,
                .accepted = accepted,
                .result = result,
            };
            group.async(self.io, ClientTask.run, .{task});
        }
        group.await(self.io) catch {};
        for (errors) |maybe_error| {
            if (maybe_error) |err| return err;
        }
    }

    fn register(
        self: *Broker,
        slot_index: usize,
        connection: *runtime.Connection,
    ) Error!router_mod.SubscriberId {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        if (slot.active) return error.BrokerFull;
        slot.generation +%= 1;
        if (slot.generation == 0) slot.generation = 1;
        slot.active = true;
        slot.connection = connection.*;
        connection.* = undefined;
        // The configured queue count is also the memory bound. Reserve it once
        // during setup so routing performs no destination queue allocation
        // while holding the global router lock.
        slot.queue.ensureTotalCapacity(
            self.allocator,
            self.options.limits
                .max_queued_deliveries_per_connection,
        ) catch |err| {
            connection.* = slot.connection.?;
            slot.connection = null;
            slot.active = false;
            return err;
        };
        return subscriberId(slot_index, slot.generation);
    }

    fn unregister(
        self: *Broker,
        slot_index: usize,
        id: router_mod.SubscriberId,
    ) void {
        const slot = &self.slots[slot_index];
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        _ = self.router.removeSubscriber(id) catch {};
        slot.active = false;
        slot.clearQueue();
        self.state_mutex.unlock(self.io);
        if (slot.connection) |*value| value.close();
        slot.connection = null;
    }

    fn handleSubscribe(
        self: *Broker,
        id: router_mod.SubscriberId,
        connection: *runtime.Connection,
        subscribe: mqtt.Subscribe,
    ) Error!void {
        const reasons = try self.allocator.alloc(
            u8,
            subscribe.subscriptions.len,
        );
        defer self.allocator.free(reasons);
        self.state_mutex.lockUncancelable(self.io);
        for (subscribe.subscriptions, 0..) |subscription, index| {
            self.router.subscribe(id, subscription) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            reasons[index] = @intFromEnum(subscription.qos);
        }
        self.state_mutex.unlock(self.io);
        const slot = try self.slotForSubscriber(id);
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        try connection.writeSubAck(
            subscribe.packet_id,
            reasons,
            &.{},
        );
    }

    fn handleUnsubscribe(
        self: *Broker,
        id: router_mod.SubscriberId,
        connection: *runtime.Connection,
        unsubscribe: mqtt.Unsubscribe,
    ) Error!void {
        const reasons = try self.allocator.alloc(
            u8,
            unsubscribe.topic_filters.len,
        );
        defer self.allocator.free(reasons);
        self.state_mutex.lockUncancelable(self.io);
        for (unsubscribe.topic_filters, 0..) |filter, index| {
            self.router.unsubscribe(id, filter) catch |err| switch (err) {
                error.SubscriptionNotFound => {
                    reasons[index] = 0x11;
                    continue;
                },
                else => {
                    self.state_mutex.unlock(self.io);
                    return err;
                },
            };
            reasons[index] = 0;
        }
        self.state_mutex.unlock(self.io);
        const slot = try self.slotForSubscriber(id);
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        try connection.writeUnsubAck(
            unsubscribe.packet_id,
            reasons,
            &.{},
        );
    }

    fn routePublish(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
    ) Error!void {
        if (publish.qos == .exactly_once) {
            return error.UnsupportedBrokerPacket;
        }
        self.state_mutex.lockUncancelable(self.io);
        const matches = self.router.matchAllocForPublisher(
            self.allocator,
            publish.topic,
            publisher_id,
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            return err;
        };
        defer self.allocator.free(matches);

        // Compact the router result in place into a stable enqueue plan. This
        // is important for shared subscriptions: running the match a second
        // time would advance their round-robin cursor twice. It also makes the
        // publication's reference count exactly equal to transferred queue
        // ownership.
        var plan_count: usize = 0;
        var has_live_match = false;
        for (matches) |match| {
            const destination_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ) orelse continue;
            const destination = &self.slots[destination_index];
            if (!destination.active or
                subscriberId(
                    destination_index,
                    destination.generation,
                ) != match.subscriber_id)
            {
                continue;
            }
            has_live_match = true;
            if (destination.queuedCount() +
                destination.route_reservations >=
                self.options.limits
                    .max_queued_deliveries_per_connection)
            {
                // Match Mosquitto's bounded outgoing queues: a saturated
                // subscriber drops this delivery, but it was still a matching
                // subscription and therefore does not turn the publisher's
                // PUBACK into "No matching subscribers".
                continue;
            }
            destination.route_reservations += 1;
            matches[plan_count] = match;
            plan_count += 1;
        }
        const plan = matches[0..plan_count];

        const publication = if (plan.len == 0)
            null
        else
            Publication.create(
                self.allocator,
                publish,
                plan.len,
            ) catch |err| {
                self.releaseRouteReservations(plan);
                self.state_mutex.unlock(self.io);
                return err;
            };
        for (plan) |match| {
            const destination_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ).?;
            const destination = &self.slots[destination_index];
            const delivery_qos = minQos(
                publish.qos,
                match.subscription.qos,
            );
            const delivery = Delivery{
                .publication = publication.?,
                .qos = delivery_qos,
                .retain = if (match.subscription.retain_as_published)
                    publish.retain
                else
                    false,
            };
            destination.appendDeliveryAssumeCapacity(delivery);
        }
        self.releaseRouteReservations(plan);
        self.state_mutex.unlock(self.io);

        if (publish.packet_id) |packet_id| {
            const publisher_slot = try self.slotForSubscriber(
                publisher_id,
            );
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            publisher.writePubAck(
                packet_id,
                if (has_live_match) 0 else 0x10,
            ) catch |err| {
                publisher_slot.writer_mutex.unlock(self.io);
                return err;
            };
            publisher_slot.writer_mutex.unlock(self.io);
        }
        try self.flushPlan(plan);
    }

    fn releaseRouteReservations(
        self: *Broker,
        plan: []const router_mod.Match,
    ) void {
        for (plan) |match| {
            const destination_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ).?;
            const destination = &self.slots[destination_index];
            std.debug.assert(destination.route_reservations != 0);
            destination.route_reservations -= 1;
        }
    }

    fn slotForSubscriber(
        self: *Broker,
        id: router_mod.SubscriberId,
    ) Error!*ClientSlot {
        const index = subscriberIndex(id, self.slots.len) orelse
            return error.ClientNotRegistered;
        const slot = &self.slots[index];
        if (!slot.active or
            subscriberId(index, slot.generation) != id or
            slot.connection == null)
        {
            return error.ClientOffline;
        }
        return slot;
    }

    fn flushPlan(
        self: *Broker,
        plan: []const router_mod.Match,
    ) Error!void {
        for (plan, 0..) |match, plan_index| {
            // Overlapping subscriptions can enqueue multiple copies for one
            // client. Flush that slot once; the slot loop drains every copy.
            var already_flushed = false;
            for (plan[0..plan_index]) |previous| {
                if (previous.subscriber_id == match.subscriber_id) {
                    already_flushed = true;
                    break;
                }
            }
            if (already_flushed) continue;
            const slot_index = subscriberIndex(
                match.subscriber_id,
                self.slots.len,
            ) orelse continue;
            try self.flushSlot(slot_index, &self.slots[slot_index]);
        }
    }

    fn flushSlot(
        self: *Broker,
        slot_index: usize,
        slot: *ClientSlot,
    ) Error!void {
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        while (true) {
            self.state_mutex.lockUncancelable(self.io);
            if (!slot.active or slot.connection == null or
                slot.queuedCount() == 0)
            {
                self.state_mutex.unlock(self.io);
                return;
            }
            var delivery = slot.popDelivery().?;
            self.state_mutex.unlock(self.io);

            const connection = &slot.connection.?;
            const packet_id = connection.writePublish(
                delivery.publication.topic(),
                delivery.publication.payload(),
                .{
                    .qos = delivery.qos,
                    .retain = delivery.retain,
                },
            ) catch |err| switch (err) {
                error.InflightFull => {
                    // Mirror Mosquitto's queued/inflight split: retain the
                    // delivery at the front until a downstream PUBACK frees
                    // credit. Never turn ordinary backpressure into message
                    // loss or a connection error.
                    self.state_mutex.lockUncancelable(self.io);
                    slot.pushFront(delivery);
                    self.state_mutex.unlock(self.io);
                    return;
                },
                else => {
                    delivery.deinit();
                    return err;
                },
            };
            delivery.deinit();
            // QoS 1 completion arrives later through this connection's reader;
            // only one writer mutates its outgoing inflight table at a time.
            _ = packet_id;
            _ = slot_index;
        }
    }
};

const ClientTask = struct {
    broker: *Broker,
    slot_index: usize,
    subscriber_id: router_mod.SubscriberId,
    accepted: runtime.AcceptedClient,
    result: *?anyerror,

    fn run(task: ClientTask) std.Io.Cancelable!void {
        var accepted = task.accepted;
        // `register` moved the connection into the stable broker slot.
        accepted.connect.deinit(task.broker.allocator);
        accepted.connection = undefined;
        const slot = &task.broker.slots[task.slot_index];
        const connection = &slot.connection.?;

        task.runLoop(slot, connection) catch |err| {
            task.result.* = err;
        };
        task.broker.unregister(
            task.slot_index,
            task.subscriber_id,
        );
    }

    fn runLoop(
        task: ClientTask,
        slot: *ClientSlot,
        connection: *runtime.Connection,
    ) !void {
        while (true) {
            var event = connection.readBrokerEvent() catch |err| {
                return err;
            };
            defer event.deinit(task.broker.allocator);
            switch (event) {
                .subscribe => |*owned| {
                    try task.broker.handleSubscribe(
                        task.subscriber_id,
                        connection,
                        owned.subscribe,
                    );
                },
                .unsubscribe => |*owned| {
                    try task.broker.handleUnsubscribe(
                        task.subscriber_id,
                        connection,
                        owned.unsubscribe,
                    );
                },
                .publish => |*owned| {
                    try task.broker.routePublish(
                        task.subscriber_id,
                        connection,
                        owned.publish,
                    );
                },
                .puback => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    connection.applyPubAck(owned.ack) catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                    try task.broker.flushSlot(
                        task.slot_index,
                        slot,
                    );
                },
                .pingreq => {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    connection.writePingResp() catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                },
                .disconnect => {
                    return;
                },
            }
        }
    }
};

fn subscriberId(index: usize, generation: u32) router_mod.SubscriberId {
    return (@as(u64, generation) << 32) | @as(u32, @intCast(index));
}

fn subscriberIndex(id: router_mod.SubscriberId, count: usize) ?usize {
    const index: usize = @intCast(@as(u32, @truncate(id)));
    return if (index < count) index else null;
}

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

test {
    _ = @import("broker_tests.zig");
}
