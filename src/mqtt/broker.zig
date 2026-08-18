//! Bounded in-memory MQTT broker core.
//!
//! This module composes the transport-independent connection runtime with the
//! topic router. It intentionally focuses on the live broker hot path:
//! SUBSCRIBE/UNSUBSCRIBE, QoS 0/1/2 PUBLISH routing, No Local/shared selection,
//! downstream acknowledgements, and connection cleanup. Durable sessions,
//! retained state, and Will scheduling remain explicit higher-level components
//! rather than being silently approximated here.

const std = @import("std");
const mqtt = @import("mod.zig");
const router_mod = @import("router.zig");
const runtime = @import("runtime.zig");
const qos2_mod = @import("broker/qos2.zig");
const publication_mod = @import("broker/publication.zig");
const will_driver_mod = @import("broker/will_driver.zig");
const retained_mod = @import("retained/mod.zig");
const session_mod = @import("session/mod.zig");
const will_mod = @import("will/mod.zig");

const net = std.Io.net;

pub const Error = runtime.Error || router_mod.Error ||
    retained_mod.Error || publication_mod.Error || qos2_mod.Error ||
    session_mod.Error || will_mod.Error || error{
    BrokerFull,
    ClientNotRegistered,
    ClientOffline,
};

pub const Limits = struct {
    max_connections: usize = 1024,
    max_queued_deliveries_per_connection: usize = 256,
    /// Aggregate cap for inbound QoS 2 Application Messages awaiting PUBREL.
    ///
    /// Per-connection Receive Maximum remains enforced by `runtime.Connection`;
    /// this independent broker-wide bound prevents many clients from turning
    /// valid-but-stalled handshakes into unbounded owned payload memory.
    max_pending_incoming_qos2: usize = 4096,
    runtime: runtime.Limits = .{},
};

pub const Options = struct {
    limits: Limits = .{},
    router: router_mod.Options = .{},
    retained: retained_mod.Options = .{},
    session: session_mod.Options = .{},
    will: will_mod.Options = .{},
    accept: runtime.AcceptOptions = .{
        .protocol = .v5,
        .max_outgoing_inflight = 64,
    },
};

const Publication = publication_mod.Publication;

const Delivery = struct {
    publication: *Publication,
    qos: mqtt.QoS,
    retain: bool,
    subscription_identifier: ?usize = null,

    fn deinit(self: *Delivery) void {
        self.publication.release();
        self.* = undefined;
    }
};

const RoutePlan = struct {
    matches: []router_mod.Match,
    has_live_match: bool,
};

const ClientSlot = struct {
    generation: u32 = 0,
    active: bool = false,
    connection: ?runtime.Connection = null,
    will_handle: ?will_mod.Handle = null,
    session_handle: ?session_mod.Handle = null,
    session_present: bool = false,
    graceful_disconnect: bool = false,
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
    pending_qos2: qos2_mod.Store,
    retained: retained_mod.Store,
    sessions: session_mod.Store,
    wills: will_mod.Scheduler,
    will_driver: will_driver_mod.Driver = .{},
    session_owners: std.AutoHashMapUnmanaged(
        session_mod.Handle,
        router_mod.SubscriberId,
    ) = .empty,
    will_publishers: std.AutoHashMapUnmanaged(
        will_mod.Handle,
        ?router_mod.SubscriberId,
    ) = .empty,
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
            options.limits.max_pending_incoming_qos2 == 0 or
            options.limits.max_pending_incoming_qos2 >
                std.math.maxInt(u32) or
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
        var pending_qos2 = try qos2_mod.Store.init(
            allocator,
            options.limits.max_pending_incoming_qos2,
        );
        errdefer pending_qos2.deinit();
        var retained = retained_mod.Store.init(
            allocator,
            options.retained,
        );
        errdefer retained.deinit();
        var sessions = session_mod.Store.init(
            allocator,
            options.session,
        );
        errdefer sessions.deinit();
        var wills = will_mod.Scheduler.init(
            allocator,
            options.will,
        );
        errdefer wills.deinit();
        var session_owners: std.AutoHashMapUnmanaged(
            session_mod.Handle,
            router_mod.SubscriberId,
        ) = .empty;
        errdefer session_owners.deinit(allocator);
        try session_owners.ensureTotalCapacity(
            allocator,
            @intCast(options.limits.max_connections),
        );
        var will_publishers: std.AutoHashMapUnmanaged(
            will_mod.Handle,
            ?router_mod.SubscriberId,
        ) = .empty;
        errdefer will_publishers.deinit(allocator);
        try will_publishers.ensureTotalCapacity(
            allocator,
            @intCast(options.will.max_wills),
        );
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
            .pending_qos2 = pending_qos2,
            .retained = retained,
            .sessions = sessions,
            .wills = wills,
            .session_owners = session_owners,
            .will_publishers = will_publishers,
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
        self.session_owners.deinit(self.allocator);
        self.will_publishers.deinit(self.allocator);
        self.wills.deinit();
        self.sessions.deinit();
        self.retained.deinit();
        self.pending_qos2.deinit();
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
        self.will_driver.start();
        // Unlike `Io.async`, `concurrent` guarantees the deadline driver is
        // assigned execution before we block in the client group. A merely
        // lazy future could otherwise leave an immediate Will queued until all
        // clients had already disconnected.
        var will_future = try std.Io.concurrent(
            self.io,
            Broker.runWillDriver,
            .{self},
        );
        var clients_started: usize = 0;
        var clients_joined = false;
        defer if (!clients_joined) {
            // An accept/setup failure must not strand already-started readers
            // behind this finite serve call.
            for (self.slots[0..clients_started]) |*slot| {
                if (slot.connection) |*connection| {
                    connection.shutdown() catch {};
                }
            }
            group.cancel(self.io);
        };
        var stop_driver = true;
        defer if (stop_driver) {
            self.will_driver.stop(self.io);
            _ = will_future.cancel(self.io);
        };
        const errors = try self.allocator.alloc(
            ?anyerror,
            connection_count,
        );
        defer self.allocator.free(errors);
        @memset(errors, null);

        for (errors, 0..) |*result, index| {
            var pending = try self.server.acceptPending(
                self.options.accept,
            );
            errdefer pending.deinit(self.allocator);
            const subscriber_id = try self.register(
                index,
                pending.connect.connect,
            );
            var accept_options = self.options.accept;
            accept_options.session_present =
                self.slots[index].session_present;
            var accepted = pending.finish(accept_options) catch |err| {
                self.abortRegistration(index, subscriber_id);
                return err;
            };
            errdefer accepted.deinit(self.allocator);
            self.attachConnection(
                index,
                subscriber_id,
                &accepted.connection,
            );
            try self.flushSlot(index, &self.slots[index]);
            const task = ClientTask{
                .broker = self,
                .slot_index = index,
                .subscriber_id = subscriber_id,
                .accepted = accepted,
                .result = result,
            };
            group.async(self.io, ClientTask.run, .{task});
            clients_started += 1;
        }
        group.await(self.io) catch {};
        clients_joined = true;
        self.will_driver.stop(self.io);
        const will_result = will_future.await(self.io);
        stop_driver = false;
        if (will_result) |err| return err;
        for (errors) |maybe_error| {
            if (maybe_error) |err| return err;
        }
    }

    fn register(
        self: *Broker,
        slot_index: usize,
        connect: mqtt.Connect,
    ) Error!router_mod.SubscriberId {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        if (slot.active) return error.BrokerFull;
        slot.generation +%= 1;
        if (slot.generation == 0) slot.generation = 1;
        slot.active = true;
        slot.connection = null;
        slot.will_handle = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.graceful_disconnect = false;
        // The configured queue count is also the memory bound. Reserve it once
        // during setup so routing performs no destination queue allocation
        // while holding the global router lock.
        slot.queue.ensureTotalCapacity(
            self.allocator,
            self.options.limits
                .max_queued_deliveries_per_connection,
        ) catch |err| {
            slot.active = false;
            return err;
        };
        const id = subscriberId(slot_index, slot.generation);
        const now = std.Io.Clock.awake.now(self.io);
        const previous_session_handle = self.sessions.find(
            connect.client_id,
            now,
        );
        const previous_session_owner = if (previous_session_handle) |handle|
            self.session_owners.get(handle)
        else
            null;
        const opened_session = self.sessions.openConnect(
            connect,
            now,
        ) catch |err| {
            slot.active = false;
            return err;
        };
        if (previous_session_handle) |handle| {
            _ = self.session_owners.remove(handle);
        }
        if (opened_session.replaced_connection) {
            if (previous_session_owner) |owner_id| {
                self.detachReplacedSessionOwner(owner_id);
            }
        }
        slot.session_handle = opened_session.handle;
        slot.session_present = opened_session.session_present;
        self.session_owners.putAssumeCapacityNoClobber(
            opened_session.handle,
            id,
        );
        self.restoreSessionSubscriptions(
            id,
            opened_session.handle,
        ) catch |err| {
            // `openConnect` gave this connection a fresh generation. Roll it
            // offline on setup failure rather than leaving a phantom connected
            // owner in the Store.
            self.sessions.disconnect(
                opened_session.handle,
                null,
                now,
            ) catch {};
            _ = self.session_owners.remove(opened_session.handle);
            slot.active = false;
            return err;
        };
        const previous_handle = self.wills.handleForClient(
            connect.client_id,
        );
        const accepted_will = self.wills.acceptConnect(
            connect,
            now,
        ) catch |err| {
            self.sessions.disconnect(
                opened_session.handle,
                null,
                now,
            ) catch {};
            _ = self.session_owners.remove(opened_session.handle);
            _ = self.router.removeSubscriber(id) catch {};
            slot.active = false;
            return err;
        };
        if (accepted_will.previous == .canceled) {
            if (previous_handle) |handle| {
                _ = self.will_publishers.remove(handle);
            }
        }
        if (accepted_will.previous == .due_now and
            accepted_will.previous_due != null)
        {
            // A due prior Will keeps its existing publisher mapping. It is
            // detached from the ClientID index by the scheduler and the timer
            // will release both records after publication.
            std.debug.assert(previous_handle != null);
        }
        slot.will_handle = accepted_will.current;
        if (accepted_will.current) |handle| {
            self.will_publishers.putAssumeCapacityNoClobber(
                handle,
                id,
            );
        }
        self.will_driver.notify(self.io);
        return id;
    }

    fn detachReplacedSessionOwner(
        self: *Broker,
        owner_id: router_mod.SubscriberId,
    ) void {
        const owner_index = subscriberIndex(
            owner_id,
            self.slots.len,
        ) orelse return;
        const owner = &self.slots[owner_index];
        if (!owner.active or
            subscriberId(owner_index, owner.generation) != owner_id)
        {
            return;
        }
        _ = self.router.removeSubscriber(owner_id) catch {};
        owner.session_handle = null;
        // Wake its reader without closing the descriptor under it. The task
        // remains the owning closer and sees its invalidated Session handle.
        if (owner.connection) |*connection| {
            connection.shutdown() catch {};
        }
    }

    fn attachConnection(
        self: *Broker,
        slot_index: usize,
        id: router_mod.SubscriberId,
        connection: *runtime.Connection,
    ) void {
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);
        const slot = &self.slots[slot_index];
        std.debug.assert(slot.active);
        std.debug.assert(slot.connection == null);
        std.debug.assert(
            subscriberId(slot_index, slot.generation) == id,
        );
        slot.connection = connection.*;
        connection.* = undefined;
    }

    fn abortRegistration(
        self: *Broker,
        slot_index: usize,
        id: router_mod.SubscriberId,
    ) void {
        self.state_mutex.lockUncancelable(self.io);
        const slot = &self.slots[slot_index];
        // Session Store, router, and Will scheduler are committed before the
        // CONNACK write. A transport failure at that final step must roll back
        // every provisional owner, not leave a resumable ghost Session.
        if (slot.session_handle) |handle| {
            _ = self.session_owners.remove(handle);
            self.sessions.discardHandle(handle) catch {};
        }
        if (slot.will_handle) |handle| {
            _ = self.will_publishers.remove(handle);
            _ = self.wills.close(handle, .normal_disconnect, .zero) catch {};
        }
        _ = self.router.removeSubscriber(id) catch {};
        slot.active = false;
        slot.connection = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.will_handle = null;
        self.state_mutex.unlock(self.io);
        self.will_driver.notify(self.io);
    }

    fn restoreSessionSubscriptions(
        self: *Broker,
        subscriber_id: router_mod.SubscriberId,
        handle: session_mod.Handle,
    ) Error!void {
        const stats = try self.sessions.stats(handle);
        const subscriptions = try self.allocator.alloc(
            session_mod.Subscription,
            stats.subscription_count,
        );
        defer self.allocator.free(subscriptions);
        const restored = try self.sessions.subscriptionsInto(
            handle,
            subscriptions,
        );
        for (restored) |subscription| {
            _ = try self.router.subscribeWithIdentifierStatus(
                subscriber_id,
                .{
                    .topic_filter = subscription.topic_filter,
                    .qos = subscription.qos,
                    .no_local = subscription.no_local,
                    .retain_as_published = subscription.retain_as_published,
                    .retain_handling = subscription.retain_handling,
                },
                subscription.subscription_identifier,
            );
        }
    }

    fn unregister(
        self: *Broker,
        slot_index: usize,
        id: router_mod.SubscriberId,
    ) Error!void {
        const slot = &self.slots[slot_index];
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        if (!slot.graceful_disconnect) {
            if (slot.will_handle) |handle| {
                _ = self.wills.close(
                    handle,
                    .ungraceful,
                    std.Io.Clock.awake.now(self.io),
                ) catch |err| {
                    if (err == error.WillNotFound) {
                        // A newer connection with the same ClientID already
                        // canceled or committed this generation during
                        // takeover. The stale transport close has no remaining
                        // Will lifecycle work.
                        slot.will_handle = null;
                    } else {
                        self.state_mutex.unlock(self.io);
                        return err;
                    }
                };
            }
        }
        if (slot.session_handle) |handle| {
            _ = self.session_owners.remove(handle);
            self.sessions.disconnect(
                handle,
                null,
                std.Io.Clock.awake.now(self.io),
            ) catch |err| {
                if (err != error.SessionNotFound) {
                    self.state_mutex.unlock(self.io);
                    return err;
                }
            };
        }
        _ = self.router.removeSubscriber(id) catch {};
        _ = self.pending_qos2.removePublisher(id);
        slot.active = false;
        slot.clearQueue();
        self.state_mutex.unlock(self.io);
        self.will_driver.notify(self.io);
        if (slot.connection) |*value| value.close();
        slot.connection = null;
        slot.will_handle = null;
        slot.session_handle = null;
        slot.session_present = false;
    }

    fn handleDisconnect(
        self: *Broker,
        slot: *ClientSlot,
        disconnect: mqtt.Disconnect,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        if (slot.will_handle) |handle| {
            const result = self.wills.closeDisconnect(
                handle,
                disconnect,
                std.Io.Clock.awake.now(self.io),
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            if (result == .canceled) {
                _ = self.will_publishers.remove(handle);
                slot.will_handle = null;
            }
        }
        if (slot.session_handle) |handle| {
            _ = self.session_owners.remove(handle);
            self.sessions.disconnectPacket(
                handle,
                slot.connection.?.protocol,
                disconnect,
                std.Io.Clock.awake.now(self.io),
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            slot.session_handle = null;
        }
        slot.graceful_disconnect = true;
        self.state_mutex.unlock(self.io);
        self.will_driver.notify(self.io);
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
        const subscription_identifier = mqtt.subscriptionIdentifier(
            subscribe.properties,
        );
        const now = std.Io.Clock.awake.now(self.io);
        const slot = try self.slotForSubscriber(id);
        // Serialize the subscription transition with every writer. Once the
        // router makes a new subscription visible, concurrent publishers may
        // enqueue for this slot; holding the writer lock guarantees SUBACK is
        // emitted before either retained replay or those live deliveries.
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        for (subscribe.subscriptions, 0..) |subscription, index| {
            const session_handle = slot.session_handle orelse {
                self.state_mutex.unlock(self.io);
                return error.SessionNotFound;
            };
            const session_existed = self.sessions.setSubscription(
                session_handle,
                subscription,
                subscription_identifier,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const existed = self.router.subscribeWithIdentifierStatus(
                id,
                subscription,
                subscription_identifier,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            std.debug.assert(existed == session_existed);
            reasons[index] = @intFromEnum(subscription.qos);
            const deliveries = self.retained.deliveriesAlloc(
                self.allocator,
                subscription,
                .{
                    .subscription_existed = existed,
                    .subscriber_id = id,
                    .subscription_identifier = subscription_identifier,
                },
                now,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            defer self.allocator.free(deliveries);
            self.enqueueRetainedDeliveries(
                slot,
                deliveries,
                now,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
        }
        self.state_mutex.unlock(self.io);
        try connection.writeSubAck(
            subscribe.packet_id,
            reasons,
            &.{},
        );
        // Retained replay is deliberately queued before SUBACK but flushed
        // only afterwards. This preserves protocol ordering while using the
        // same Receive Maximum/backpressure path as live fanout.
        try self.flushSlotLocked(slot);
    }

    /// Queue retained replay while `state_mutex` is held.
    ///
    /// Each Store delivery is a borrowed view. Clone it into one
    /// reference-counted Publication per retained Application Message before
    /// releasing the Store lock, then transfer that sole reference into the
    /// subscriber queue.
    fn enqueueRetainedDeliveries(
        self: *Broker,
        slot: *ClientSlot,
        deliveries: []const retained_mod.Delivery,
        now: std.Io.Timestamp,
    ) Error!void {
        for (deliveries) |delivery| {
            if (slot.queuedCount() >= self.options.limits
                .max_queued_deliveries_per_connection)
            {
                // Retained replay follows the same bounded outgoing queue
                // policy as live fanout. A successful SUBSCRIBE is not turned
                // into a connection failure merely because this client is
                // already saturated.
                continue;
            }
            const publication = try Publication.createFromRetained(
                self.allocator,
                delivery,
                1,
                now,
            );
            slot.appendDeliveryAssumeCapacity(.{
                .publication = publication,
                .qos = delivery.qos,
                .retain = true,
                .subscription_identifier = delivery.subscription_identifier,
            });
        }
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
        const slot = try self.slotForSubscriber(id);
        self.state_mutex.lockUncancelable(self.io);
        for (unsubscribe.topic_filters, 0..) |filter, index| {
            const session_handle = slot.session_handle orelse {
                self.state_mutex.unlock(self.io);
                return error.SessionNotFound;
            };
            const session_removed = self.sessions.removeSubscription(
                session_handle,
                filter,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            self.router.unsubscribe(id, filter) catch |err| switch (err) {
                error.SubscriptionNotFound => {
                    std.debug.assert(!session_removed);
                    reasons[index] = 0x11;
                    continue;
                },
                else => {
                    self.state_mutex.unlock(self.io);
                    return err;
                },
            };
            std.debug.assert(session_removed);
            reasons[index] = 0;
        }
        self.state_mutex.unlock(self.io);
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
        // Subscription Identifier is generated by a Server while forwarding;
        // it is never legal on a Client-to-Server PUBLISH.
        if (mqtt.subscriptionIdentifier(publish.properties) != null) {
            return error.InvalidProperty;
        }
        if (publish.qos == .exactly_once) {
            return self.recordQoS2Publish(
                publisher_id,
                publisher,
                publish,
            );
        }
        return self.routeReleasedPublish(
            publisher_id,
            publisher,
            publish,
            true,
        );
    }

    fn recordQoS2Publish(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        _ = self.pending_qos2.record(
            publisher_id,
            publish,
            std.Io.Clock.awake.now(self.io),
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            if (err != error.ReceiveMaximumExceeded) return err;

            // A broker-wide pending-transaction cap is an MQTT quota failure,
            // not malformed client behavior. Reject this transaction with the
            // standard QoS 2 response and release the runtime receive slot so
            // the connection can continue.
            const publisher_slot = try self.slotForSubscriber(publisher_id);
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            defer publisher_slot.writer_mutex.unlock(self.io);
            try publisher.writePubRec(publish.packet_id.?, 0x97);
            return;
        };
        self.state_mutex.unlock(self.io);

        // Mosquitto stores the inbound QoS 2 base message before PUBREC and
        // routes only when PUBREL arrives. A retransmitted PUBLISH receives the
        // same PUBREC without replacing or duplicating the stored message.
        const publisher_slot = try self.slotForSubscriber(publisher_id);
        publisher_slot.writer_mutex.lockUncancelable(self.io);
        defer publisher_slot.writer_mutex.unlock(self.io);
        try publisher.writePubRec(publish.packet_id.?, 0);
    }

    fn handlePubRel(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        ack: mqtt.AckPacket,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        var pending = self.pending_qos2.take(
            publisher_id,
            ack.packet_id,
        ) orelse {
            self.state_mutex.unlock(self.io);
            // Mosquitto deliberately acknowledges an unknown/repeated PUBREL:
            // the original PUBCOMP may have been lost after the message was
            // already released. MQTT 5 allows 0x92, but Success is maximally
            // interoperable and keeps this path idempotent.
            const publisher_slot = try self.slotForSubscriber(publisher_id);
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            defer publisher_slot.writer_mutex.unlock(self.io);
            try publisher.writePubComp(ack.packet_id, 0);
            return;
        };
        self.state_mutex.unlock(self.io);
        defer pending.deinit();

        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        if (try pending.asPublish(
            ack.packet_id,
            std.Io.Clock.awake.now(self.io),
            &properties,
        )) |publish| {
            try self.routeReleasedPublish(
                publisher_id,
                publisher,
                publish,
                false,
            );
        }

        const publisher_slot = try self.slotForSubscriber(publisher_id);
        publisher_slot.writer_mutex.lockUncancelable(self.io);
        defer publisher_slot.writer_mutex.unlock(self.io);
        try publisher.writePubComp(ack.packet_id, 0);
    }

    fn routeReleasedPublish(
        self: *Broker,
        publisher_id: router_mod.SubscriberId,
        publisher: *runtime.Connection,
        publish: mqtt.Publish,
        acknowledge_qos1: bool,
    ) Error!void {
        self.state_mutex.lockUncancelable(self.io);
        const plan = self.enqueuePublishLocked(
            publisher_id,
            publish,
            std.Io.Clock.awake.now(self.io),
        ) catch |err| {
            self.state_mutex.unlock(self.io);
            return err;
        };
        defer self.allocator.free(plan.matches);
        self.state_mutex.unlock(self.io);

        if (acknowledge_qos1) if (publish.packet_id) |packet_id| {
            const publisher_slot = try self.slotForSubscriber(
                publisher_id,
            );
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            publisher.writePubAck(
                packet_id,
                if (plan.has_live_match) 0 else 0x10,
            ) catch |err| {
                publisher_slot.writer_mutex.unlock(self.io);
                return err;
            };
            publisher_slot.writer_mutex.unlock(self.io);
        };
        try self.flushPlan(plan.matches);
    }

    /// Apply retained state and enqueue live fanout while `state_mutex` is held.
    ///
    /// Will publication reuses this exact route without a publisher
    /// Connection, while client PUBLISH adds its acknowledgement after the
    /// lock is released.
    fn enqueuePublishLocked(
        self: *Broker,
        publisher_id: ?router_mod.SubscriberId,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!RoutePlan {
        _ = self.retained.applyParsedPublish(
            publish,
            publisher_id,
            now,
        ) catch |err| return err;
        const matches = self.router.matchAllocForPublisher(
            self.allocator,
            publish.topic,
            publisher_id,
        ) catch |err| return err;
        errdefer self.allocator.free(matches);

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
            Publication.createFromPublish(
                self.allocator,
                publish,
                plan.len,
                now,
            ) catch |err| {
                self.releaseRouteReservations(plan);
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
                .subscription_identifier = match.subscription_identifier,
            };
            destination.appendDeliveryAssumeCapacity(delivery);
        }
        self.releaseRouteReservations(plan);
        if (plan.len == matches.len) return .{
            .matches = matches,
            .has_live_match = has_live_match,
        };
        if (plan.len == 0) {
            self.allocator.free(matches);
            return .{
                .matches = try self.allocator.alloc(
                    router_mod.Match,
                    0,
                ),
                .has_live_match = has_live_match,
            };
        }
        if (self.allocator.resize(matches, plan.len)) {
            return .{
                .matches = matches[0..plan.len],
                .has_live_match = has_live_match,
            };
        }
        const exact = try self.allocator.dupe(router_mod.Match, plan);
        self.allocator.free(matches);
        return .{
            .matches = exact,
            .has_live_match = has_live_match,
        };
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
        _ = slot_index;
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        return self.flushSlotLocked(slot);
    }

    fn flushSlotLocked(
        self: *Broker,
        slot: *ClientSlot,
    ) Error!void {
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
            var properties: std.ArrayList(mqtt.Property) = .empty;
            defer properties.deinit(self.allocator);
            if (!try delivery.publication.appendDeliveryProperties(
                &properties,
                self.allocator,
                delivery.subscription_identifier,
                std.Io.Clock.awake.now(self.io),
            )) {
                delivery.deinit();
                continue;
            }
            const packet_id = connection.writePublish(
                delivery.publication.topic(),
                delivery.publication.payload(),
                .{
                    .qos = delivery.qos,
                    .retain = delivery.retain,
                    .properties = properties.items,
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
        }
    }

    fn runWillDriver(
        self: *Broker,
    ) ?anyerror {
        while (!self.will_driver.stopped()) {
            self.state_mutex.lockUncancelable(self.io);
            const published_any = self.publishDueWillsLocked(
                std.Io.Clock.awake.now(self.io),
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const deadline = self.wills.nextDeadline();
            const generation =
                self.will_driver.currentGeneration();
            self.state_mutex.unlock(self.io);

            if (published_any) {
                self.flushAllSlots() catch |err| return err;
            }
            self.will_driver.wait(
                self.io,
                generation,
                deadline,
            ) catch |err| switch (err) {
                error.Canceled => return err,
            };
        }
        return null;
    }

    /// Claim and route every Will whose deadline has passed.
    ///
    /// `state_mutex` stays held from scheduler claim through queue ownership
    /// transfer and scheduler release. This makes reconnect cancellation race
    /// against one atomic publication decision: a reconnect either removes the
    /// scheduled Will first, or observes it already committed.
    fn publishDueWillsLocked(
        self: *Broker,
        now: std.Io.Timestamp,
    ) Error!bool {
        var published_any = false;
        while (self.wills.pollOneDue(now)) |handle| {
            try self.publishWillLocked(handle, now);
            published_any = true;
        }
        return published_any;
    }

    fn flushAllSlots(self: *Broker) Error!void {
        for (self.slots, 0..) |*slot, index| {
            try self.flushSlot(index, slot);
        }
    }

    fn publishWillLocked(
        self: *Broker,
        handle: will_mod.Handle,
        now: std.Io.Timestamp,
    ) Error!void {
        const will = try self.wills.view(handle);
        const publisher_id = self.will_publishers.get(handle) orelse null;
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        try properties.ensureTotalCapacity(
            self.allocator,
            will.properties.len,
        );
        for (will.properties) |property| {
            // Will Delay controls scheduling and is forbidden on a normal
            // PUBLISH. Message Expiry and all other Will Application Message
            // properties begin when the Will is actually published.
            if (property == .four_byte and
                property.four_byte.id == .will_delay_interval)
            {
                continue;
            }
            properties.appendAssumeCapacity(property);
        }
        const publish = mqtt.Publish{
            .dup = false,
            .qos = will.qos,
            .retain = will.retain,
            .topic = will.topic,
            .packet_id = null,
            .properties = properties.items,
            .payload = will.payload,
        };
        const plan = try self.enqueuePublishLocked(
            publisher_id,
            publish,
            now,
        );
        defer self.allocator.free(plan.matches);
        try self.wills.releaseDue(handle);
        _ = self.will_publishers.remove(handle);

        // The state lock cannot be held across socket writes. Queue ownership
        // is committed at this point; the timer loop releases the lock before
        // flushing all active slots below.
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
            if (!ungracefulTransportClose(err)) {
                task.result.* = err;
            }
        };
        task.broker.unregister(
            task.slot_index,
            task.subscriber_id,
        ) catch |err| {
            task.result.* = err;
        };
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
                .pubrec => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    connection.applyPubRec(owned.ack) catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                },
                .pubrel => |*owned| {
                    try task.broker.handlePubRel(
                        task.subscriber_id,
                        connection,
                        owned.ack,
                    );
                },
                .pubcomp => |*owned| {
                    slot.writer_mutex.lockUncancelable(task.broker.io);
                    connection.applyPubComp(owned.ack) catch |err| {
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
                .disconnect => |*owned| {
                    try task.broker.handleDisconnect(
                        slot,
                        owned.disconnect,
                    );
                    return;
                },
            }
        }
    }
};

fn ungracefulTransportClose(err: anyerror) bool {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.ConnectionAborted,
        error.SocketUnconnected,
        => true,
        else => false,
    };
}

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
