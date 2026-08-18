//! Bounded in-memory MQTT broker core.
//!
//! This module composes the transport-independent connection runtime with the
//! topic router and bounded retained, Session, QoS 2, and Will state. It
//! focuses on the live broker hot path: SUBSCRIBE/UNSUBSCRIBE, QoS 0/1/2
//! routing, offline Session queueing, reconnect retransmission, No Local/shared
//! selection, downstream acknowledgements, and connection cleanup.

const std = @import("std");
const mqtt = @import("mod.zig");
const router_mod = @import("router.zig");
const runtime = @import("runtime.zig");
const client_id_mod = @import("broker/client_id.zig");
const qos2_mod = @import("broker/qos2.zig");
const publication_mod = @import("broker/publication.zig");
const session_route = @import("broker/session_route.zig");
const will_driver_mod = @import("broker/will_driver.zig");
const retained_mod = @import("retained/mod.zig");
const session_mod = @import("session/mod.zig");
const will_mod = @import("will/mod.zig");

const net = std.Io.net;

pub const Error = runtime.Error || router_mod.Error ||
    retained_mod.Error || publication_mod.Error || qos2_mod.Error ||
    session_mod.Error || will_mod.Error || std.Io.RandomSecureError || error{
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
    /// Prefix for broker-assigned Client Identifiers. Copied by `listen`.
    ///
    /// Mosquitto limits `auto_id_prefix` to 50 bytes; matching that cap keeps
    /// the generated identifier below MQTT's u16 UTF-8 string bound.
    auto_client_id_prefix: []const u8 = "netz-",
    router: router_mod.Options = .{},
    retained: retained_mod.Options = .{},
    session: session_mod.Options = .{},
    will: will_mod.Options = .{},
    accept: runtime.AcceptOptions = .{
        .protocol = .v5,
        .max_outgoing_inflight = 64,
    },
    /// Optional policy for MQTT 5 re-authentication AUTH packets received by
    /// the live broker event loop.
    authentication: ?AuthenticationHandler = null,
};

pub const AuthenticationHandler = struct {
    context: *anyopaque,
    /// Complete any CONNECT-before-CONNACK exchange and call
    /// `pending.authorizeAuthentication()` only after policy success.
    start: *const fn (
        context: *anyopaque,
        pending: *runtime.PendingAcceptedClient,
    ) Error!void,
    handle: *const fn (
        context: *anyopaque,
        connection: *runtime.Connection,
        auth: mqtt.Auth,
        complete: bool,
    ) Error!void,
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
    storage: []router_mod.Match,
    deliveries: []const router_mod.Match,
    session_targets: []const router_mod.Match,
    has_matching_subscriber: bool,
};

const EncodedSessionPacket = session_route.EncodedPacket;
const subscriberId = session_route.connectionSubscriberId;
const nextConnectionGeneration = session_route.nextConnectionGeneration;
const sessionSubscriberId = session_route.sessionSubscriberId;
const sessionRouteId = session_route.sessionRouteId;
const subscriberIndex = session_route.connectionIndex;

const ClientSlot = struct {
    generation: u32 = 0,
    active: bool = false,
    connection: ?runtime.Connection = null,
    will_handle: ?will_mod.Handle = null,
    session_handle: ?session_mod.Handle = null,
    session_present: bool = false,
    assigned_client_id_len: u8 = 0,
    assigned_client_id: [client_id_mod.max_len]u8 = undefined,
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
        u64,
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
            std.math.cast(
                u32,
                options.limits.max_connections,
            ) == null or
            options.limits.max_queued_deliveries_per_connection == 0 or
            options.limits.max_pending_incoming_qos2 == 0 or
            options.limits.max_pending_incoming_qos2 >
                std.math.maxInt(u32) or
            options.auto_client_id_prefix.len >
                client_id_mod.max_prefix_len)
        {
            return error.InvalidProperty;
        }
        try mqtt.validateUtf8String(options.auto_client_id_prefix);
        const auto_client_id_prefix = try allocator.dupe(
            u8,
            options.auto_client_id_prefix,
        );
        errdefer allocator.free(auto_client_id_prefix);
        var owned_options = options;
        owned_options.auto_client_id_prefix = auto_client_id_prefix;
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
            u64,
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
            .options = owned_options,
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
        self.allocator.free(self.options.auto_client_id_prefix);
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
            if (pending.connection.authentication.phase ==
                .authenticating)
            {
                const handler = self.options.authentication orelse
                    return error.AuthenticationNotConfigured;
                try handler.start(
                    handler.context,
                    &pending,
                );
                if (!pending.authentication_authorized) {
                    return error.AuthenticationInProgress;
                }
            }
            const subscriber_id = try self.register(
                index,
                pending.connect.connect,
            );
            var accept_options = self.options.accept;
            accept_options.session_present =
                self.slots[index].session_present;
            if (self.slots[index].assigned_client_id_len != 0) {
                accept_options.assigned_client_identifier =
                    self.slots[index].assigned_client_id[0..self.slots[index].assigned_client_id_len];
            }
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
        slot.generation = nextConnectionGeneration(slot.generation);
        slot.active = true;
        slot.connection = null;
        slot.will_handle = null;
        slot.session_handle = null;
        slot.session_present = false;
        slot.assigned_client_id_len = 0;
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
        // `find` removes an expired Session without exposing its route ID.
        // Prune first so the router and Session Store always retire stable
        // identities atomically from the broker's point of view.
        self.pruneExpiredSessionRoutesLocked(now) catch |err| {
            slot.active = false;
            return err;
        };
        var effective_connect = connect;
        if (connect.client_id.len == 0) {
            effective_connect.client_id = self.assignClientIdLocked(
                slot,
            ) catch |err| {
                slot.active = false;
                return err;
            };
        }
        const previous_session_handle = self.sessions.find(
            effective_connect.client_id,
            now,
        );
        const previous_route_id = if (previous_session_handle) |handle|
            self.sessions.routeId(handle) catch null
        else
            null;
        const previous_session_owner = if (previous_session_handle) |handle|
            if (self.sessions.routeId(handle) catch null) |route_id|
                self.session_owners.get(route_id)
            else
                null
        else
            null;
        const opened_session = self.sessions.openConnect(
            effective_connect,
            now,
        ) catch |err| {
            slot.active = false;
            return err;
        };
        if (previous_route_id) |route_id| {
            _ = self.session_owners.remove(route_id);
        }
        if (opened_session.replaced_connection) {
            if (previous_session_owner) |owner_id| {
                self.detachReplacedSessionOwner(owner_id);
            }
        }
        if (previous_route_id) |route_id| {
            if (route_id != opened_session.route_id) {
                // Clean Start destroys the previous Session and allocates a
                // new stable identity. The old subscriptions must disappear
                // immediately rather than surviving as an unresolvable route.
                _ = self.router.removeSubscriber(
                    sessionSubscriberId(route_id),
                ) catch {};
            }
        }
        slot.session_handle = opened_session.handle;
        slot.session_present = opened_session.session_present;
        self.session_owners.putAssumeCapacityNoClobber(
            opened_session.route_id,
            id,
        );
        self.restoreSessionSubscriptions(
            opened_session.handle,
            opened_session.route_id,
        ) catch |err| {
            self.rollbackOpenedSessionLocked(
                opened_session.handle,
                opened_session.route_id,
                opened_session.session_present,
                now,
            );
            slot.active = false;
            return err;
        };
        const previous_handle = self.wills.handleForClient(
            effective_connect.client_id,
        );
        const accepted_will = self.wills.acceptConnect(
            effective_connect,
            now,
        ) catch |err| {
            self.rollbackOpenedSessionLocked(
                opened_session.handle,
                opened_session.route_id,
                opened_session.session_present,
                now,
            );
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
                sessionSubscriberId(opened_session.route_id),
            );
        }
        self.will_driver.notify(self.io);
        return id;
    }

    fn assignClientIdLocked(
        self: *Broker,
        slot: *ClientSlot,
    ) Error![]const u8 {
        while (true) {
            var random: [client_id_mod.random_len]u8 = undefined;
            try std.Io.randomSecure(self.io, &random);
            const id = client_id_mod.format(
                &slot.assigned_client_id,
                self.options.auto_client_id_prefix,
                random,
            );
            if (self.sessions.containsClientId(id)) continue;
            slot.assigned_client_id_len = @intCast(id.len);
            return id;
        }
    }

    /// Roll back a Session generation opened before CONNACK commits.
    ///
    /// Existing Session State remains resumable after a failed transport;
    /// brand-new provisional state is discarded so a failed accept cannot
    /// manufacture Session Present or consume the Session quota.
    fn rollbackOpenedSessionLocked(
        self: *Broker,
        handle: session_mod.Handle,
        route_id: u64,
        session_present: bool,
        now: std.Io.Timestamp,
    ) void {
        _ = self.session_owners.remove(route_id);
        if (session_present) {
            self.sessions.disconnect(handle, null, now) catch {};
        } else {
            self.sessions.discardHandle(handle) catch {};
        }
        if (self.sessions.handleForRouteId(route_id) == null) {
            _ = self.router.removeSubscriber(
                sessionSubscriberId(route_id),
            ) catch {};
        }
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
        _: router_mod.SubscriberId,
    ) void {
        self.state_mutex.lockUncancelable(self.io);
        const slot = &self.slots[slot_index];
        // Session Store, router, and Will scheduler are committed before the
        // CONNACK write. A transport failure at that final step must roll back
        // every provisional owner. A resumed Session is returned offline
        // rather than discarded: its pre-existing subscriptions and inflight
        // QoS state remain valid even though this transport never completed.
        if (slot.session_handle) |handle| {
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                self.rollbackOpenedSessionLocked(
                    handle,
                    value,
                    slot.session_present,
                    std.Io.Clock.awake.now(self.io),
                );
            }
        }
        if (slot.will_handle) |handle| {
            _ = self.will_publishers.remove(handle);
            _ = self.wills.close(handle, .normal_disconnect, .zero) catch {};
        }
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
        handle: session_mod.Handle,
        route_id: u64,
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
                sessionSubscriberId(route_id),
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
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                _ = self.session_owners.remove(value);
            }
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
            const stats = self.sessions.stats(handle) catch null;
            if (stats == null or stats.?.expiry_interval == 0) {
                if (route_id) |value| {
                    _ = self.router.removeSubscriber(
                        sessionSubscriberId(value),
                    ) catch {};
                }
            }
        }
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
            const route_id = self.sessions.routeId(handle) catch null;
            if (route_id) |value| {
                _ = self.session_owners.remove(value);
            }
            self.sessions.disconnectPacket(
                handle,
                slot.connection.?.protocol,
                disconnect,
                std.Io.Clock.awake.now(self.io),
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const session_removed = self.sessions.stats(handle) catch |err|
                err == error.SessionNotFound;
            if (session_removed == true) {
                if (route_id) |value| {
                    _ = self.router.removeSubscriber(
                        sessionSubscriberId(value),
                    ) catch {};
                }
            }
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
        const session_handle = slot.session_handle orelse
            return error.SessionNotFound;
        const session_route_id = try self.sessions.routeId(
            session_handle,
        );
        // Serialize the subscription transition with every writer. Once the
        // router makes a new subscription visible, concurrent publishers may
        // enqueue for this slot; holding the writer lock guarantees SUBACK is
        // emitted before either retained replay or those live deliveries.
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        self.state_mutex.lockUncancelable(self.io);
        for (subscribe.subscriptions, 0..) |subscription, index| {
            const session_existed = self.sessions.setSubscription(
                session_handle,
                subscription,
                subscription_identifier,
            ) catch |err| {
                self.state_mutex.unlock(self.io);
                return err;
            };
            const route_id = try self.sessions.routeId(session_handle);
            const existed = self.router.subscribeWithIdentifierStatus(
                sessionSubscriberId(route_id),
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
                    .subscriber_id = sessionSubscriberId(session_route_id),
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
            if (delivery.qos != .at_most_once) {
                // Persistent Session State is the sole Packet Identifier
                // owner for every QoS 1/2 delivery to this client, including
                // retained replay. Mixing this path with Connection.writePublish
                // would let two independent allocators reuse the same ID.
                const handle = slot.session_handle orelse
                    return error.SessionNotFound;
                var properties: std.ArrayList(mqtt.Property) = .empty;
                defer properties.deinit(self.allocator);
                try properties.ensureTotalCapacity(
                    self.allocator,
                    delivery.properties.len,
                );
                for (delivery.properties) |property| {
                    if (property == .four_byte and
                        property.four_byte.id ==
                            .message_expiry_interval)
                    {
                        const remaining =
                            delivery.message_expiry_interval orelse
                            continue;
                        properties.appendAssumeCapacity(.{ .four_byte = .{
                            .id = .message_expiry_interval,
                            .value = remaining,
                        } });
                    } else {
                        properties.appendAssumeCapacity(property);
                    }
                }
                const publish = mqtt.Publish{
                    .dup = false,
                    .qos = delivery.qos,
                    .retain = delivery.retain,
                    .topic = delivery.topic,
                    .packet_id = null,
                    .properties = properties.items,
                    .payload = delivery.payload,
                };
                try self.enqueueSessionDeliveryLocked(
                    handle,
                    delivery.subscription_identifier,
                    delivery.retain,
                    delivery.qos,
                    publish,
                    now,
                );
                continue;
            }
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
            const route_id = try self.sessions.routeId(session_handle);
            self.router.unsubscribe(
                sessionSubscriberId(route_id),
                filter,
            ) catch |err| switch (err) {
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
            if (connection.protocol == .v5) reasons else &.{},
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
            // MQTT 3.1.1 has no PUBREC reason field. Mosquitto emits the same
            // control packet but its wire helper omits the negative reason,
            // completing the QoS handshake without routing the rejected
            // Application Message.
            try publisher.writePubRec(
                publish.packet_id.?,
                protocolReason(publisher.protocol, 0x97),
            );
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
        defer self.allocator.free(plan.storage);
        self.state_mutex.unlock(self.io);

        if (acknowledge_qos1) if (publish.packet_id) |packet_id| {
            const publisher_slot = try self.slotForSubscriber(
                publisher_id,
            );
            publisher_slot.writer_mutex.lockUncancelable(self.io);
            publisher.writePubAck(
                packet_id,
                protocolReason(
                    publisher.protocol,
                    if (plan.has_matching_subscriber) 0 else 0x10,
                ),
            ) catch |err| {
                publisher_slot.writer_mutex.unlock(self.io);
                return err;
            };
            publisher_slot.writer_mutex.unlock(self.io);
        };
        try self.flushPlan(plan);
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
        try self.pruneExpiredSessionRoutesLocked(now);
        const route_publisher_id = if (publisher_id) |id|
            self.canonicalPublisherId(id)
        else
            null;
        _ = self.retained.applyParsedPublish(
            publish,
            route_publisher_id,
            now,
        ) catch |err| return err;
        const matches = self.router.matchAllocForPublisher(
            self.allocator,
            publish.topic,
            route_publisher_id,
        ) catch |err| return err;
        errdefer self.allocator.free(matches);
        // Compact the router result in place into a stable enqueue plan. This
        // is important for shared subscriptions: running the match a second
        // time would advance their round-robin cursor twice. It also makes the
        // publication's reference count exactly equal to transferred queue
        // ownership.
        var has_matching_subscriber = false;
        for (matches) |*match| {
            if (sessionRouteId(match.subscriber_id)) |route_id| {
                const handle = self.sessions.handleForRouteId(
                    route_id,
                ) orelse {
                    // A stable route without Session State can only be a
                    // rollback residue. Do not report it as a matching
                    // subscriber, and make it ineligible for both partitions
                    // below.
                    match.subscriber_id = 0;
                    continue;
                };
                has_matching_subscriber = true;
                const delivery_qos = minQos(
                    publish.qos,
                    match.subscription.qos,
                );
                if (delivery_qos == .at_most_once) {
                    // Mosquitto delivers QoS 0 directly to an online
                    // persistent client, but drops it while that client is
                    // offline unless its non-default queue_qos0 option is
                    // enabled. Resolve the stable Session route to the current
                    // slot only for this lightweight, connection-local path.
                    const owner_id = self.session_owners.get(
                        route_id,
                    ) orelse {
                        match.subscriber_id = 0;
                        continue;
                    };
                    const destination_index = subscriberIndex(
                        owner_id,
                        self.slots.len,
                    ) orelse {
                        match.subscriber_id = 0;
                        continue;
                    };
                    const destination = &self.slots[destination_index];
                    if (!self.slotOwnsSessionRoute(
                        destination_index,
                        destination,
                        owner_id,
                        route_id,
                    )) {
                        match.subscriber_id = 0;
                        continue;
                    }
                    match.subscriber_id = owner_id;
                    continue;
                }
                try self.enqueueSessionDeliveryLocked(
                    handle,
                    match.subscription_identifier,
                    if (match.subscription.retain_as_published)
                        publish.retain
                    else
                        false,
                    delivery_qos,
                    publish,
                    now,
                );
                const owner_id = self.session_owners.get(
                    route_id,
                ) orelse {
                    match.subscriber_id = 0;
                    continue;
                };
                const destination_index = subscriberIndex(
                    owner_id,
                    self.slots.len,
                ) orelse {
                    match.subscriber_id = 0;
                    continue;
                };
                if (!self.slotOwnsSessionRoute(
                    destination_index,
                    &self.slots[destination_index],
                    owner_id,
                    route_id,
                )) {
                    match.subscriber_id = 0;
                }
                continue;
            }
        }

        // Partition Session-backed QoS 1/2 flush targets into the tail. A swap
        // is safe while walking backwards: every element in the target tail
        // has already been classified. The front remains available for
        // lightweight QoS 0 delivery compaction without another allocation.
        var session_target_start = matches.len;
        var match_index = matches.len;
        while (match_index != 0) {
            match_index -= 1;
            const route_id = sessionRouteId(
                matches[match_index].subscriber_id,
            ) orelse continue;
            session_target_start -= 1;
            if (match_index != session_target_start) {
                std.mem.swap(
                    router_mod.Match,
                    &matches[match_index],
                    &matches[session_target_start],
                );
            }
            matches[session_target_start].subscriber_id =
                self.session_owners.get(route_id).?;
        }

        var plan_count: usize = 0;
        for (matches[0..session_target_start]) |match| {
            if (match.subscriber_id == 0) continue;
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
            has_matching_subscriber = true;
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
        return .{
            .storage = matches,
            .deliveries = matches[0..plan_count],
            .session_targets = matches[session_target_start..],
            .has_matching_subscriber = has_matching_subscriber,
        };
    }

    fn pruneExpiredSessionRoutesLocked(
        self: *Broker,
        now: std.Io.Timestamp,
    ) Error!void {
        const due_count = self.sessions.dueExpiryCount(now);
        if (due_count == 0) return;
        const route_ids = try self.allocator.alloc(
            u64,
            due_count,
        );
        defer self.allocator.free(route_ids);
        const removed = try self.sessions.pruneExpiredInto(
            now,
            route_ids,
        );
        for (removed) |route_id| {
            _ = self.router.removeSubscriber(
                sessionSubscriberId(route_id),
            ) catch {};
        }
    }

    fn enqueueSessionDeliveryLocked(
        self: *Broker,
        handle: session_mod.Handle,
        subscription_identifier: ?usize,
        retain: bool,
        qos: mqtt.QoS,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!void {
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(self.allocator);
        try properties.ensureTotalCapacity(
            self.allocator,
            publish.properties.len +
                @intFromBool(subscription_identifier != null),
        );
        for (publish.properties) |property| {
            if ((property == .two_byte and
                property.two_byte.id == .topic_alias) or
                (property == .varint and
                    property.varint.id == .subscription_identifier))
            {
                continue;
            }
            properties.appendAssumeCapacity(property);
        }
        if (subscription_identifier) |identifier| {
            properties.appendAssumeCapacity(.{ .varint = .{
                .id = .subscription_identifier,
                .value = identifier,
            } });
        }
        _ = self.sessions.enqueuePublish(
            handle,
            publish.topic,
            publish.payload,
            .{
                .qos = qos,
                .retain = retain,
                .properties = properties.items,
                .now = now,
            },
        ) catch |err| switch (err) {
            error.QueueFull => return,
            else => return err,
        };
    }

    fn handleSessionAckLocked(
        self: *Broker,
        slot: *ClientSlot,
        ack: mqtt.AckPacket,
    ) Error!bool {
        const handle = slot.session_handle orelse return false;
        if (!self.sessions.ownsPacketId(handle, ack.packet_id)) {
            return false;
        }
        _ = try self.sessions.handleAck(
            handle,
            ack.packet_type,
            ack.packet_id,
            ack.reason_code,
        );
        return true;
    }

    fn canonicalPublisherId(
        self: *Broker,
        id: router_mod.SubscriberId,
    ) router_mod.SubscriberId {
        if (sessionRouteId(id) != null) return id;
        const index = subscriberIndex(id, self.slots.len) orelse return id;
        const slot = &self.slots[index];
        const handle = slot.session_handle orelse return id;
        const route_id = self.sessions.routeId(handle) catch return id;
        return sessionSubscriberId(route_id);
    }

    fn slotOwnsSessionRoute(
        self: *Broker,
        index: usize,
        slot: *ClientSlot,
        owner_id: router_mod.SubscriberId,
        route_id: u64,
    ) bool {
        if (!slot.active or slot.connection == null or
            subscriberId(index, slot.generation) != owner_id)
        {
            return false;
        }
        const handle = slot.session_handle orelse return false;
        return (self.sessions.routeId(handle) catch return false) == route_id;
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
        plan: RoutePlan,
    ) Error!void {
        for (plan.deliveries, 0..) |match, plan_index| {
            // Overlapping subscriptions can enqueue multiple copies for one
            // client. Flush that slot once; the slot loop drains every copy.
            var already_flushed = false;
            for (plan.deliveries[0..plan_index]) |previous| {
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
        for (plan.session_targets, 0..) |match, target_index| {
            var already_flushed = false;
            for (plan.deliveries) |previous| {
                if (previous.subscriber_id == match.subscriber_id) {
                    already_flushed = true;
                    break;
                }
            }
            if (!already_flushed) {
                for (plan.session_targets[0..target_index]) |previous| {
                    if (previous.subscriber_id == match.subscriber_id) {
                        already_flushed = true;
                        break;
                    }
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
            if (try self.takeSessionPacketLocked(slot)) |packet_value| {
                var packet = packet_value;
                defer packet.deinit();
                slot.connection.?.writeEncodedSessionPacket(
                    packet.bytes,
                ) catch |err| switch (err) {
                    error.OutgoingPacketTooLarge => {
                        if (packet.kind == .pubrel) return err;
                        // Match Mosquitto's oversized outgoing handling: once
                        // the peer's Maximum Packet Size rejects a PUBLISH,
                        // remove that transaction and continue draining rather
                        // than permanently consuming Session inflight credit.
                        self.state_mutex.lockUncancelable(self.io);
                        if (slot.session_handle) |handle| {
                            _ = self.sessions.dropOversizedPublish(
                                handle,
                                packet.packet_id,
                            ) catch {};
                        }
                        self.state_mutex.unlock(self.io);
                        continue;
                    },
                    else => return err,
                };
                continue;
            }
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
                connection.protocol,
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

    /// Reserve and encode one Session transmission under the state lock.
    ///
    /// `drainInto` mutates queued/inflight ownership. Encoding before unlocking
    /// guarantees its borrowed views cannot be invalidated by an ACK or
    /// takeover, while the detached byte slice keeps network I/O outside the
    /// global lock.
    fn takeSessionPacketLocked(
        self: *Broker,
        slot: *ClientSlot,
    ) Error!?EncodedSessionPacket {
        const handle = slot.session_handle orelse return null;
        const connection = &(slot.connection orelse return null);
        self.state_mutex.lockUncancelable(self.io);
        defer self.state_mutex.unlock(self.io);

        var storage: [1]session_mod.Transmission = undefined;
        const transmissions = self.sessions.drainInto(
            handle,
            std.Io.Clock.awake.now(self.io),
            connection.max_outgoing_inflight,
            &storage,
        ) catch |err| switch (err) {
            error.SessionNotFound => return null,
            else => return err,
        };
        if (transmissions.len == 0) return null;
        return try session_route.encodeTransmission(
            self.allocator,
            connection.protocol,
            transmissions[0],
        );
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
        defer self.allocator.free(plan.storage);
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
                .auth => |*owned| {
                    const handler = task.broker.options.authentication orelse
                        return error.AuthenticationNotConfigured;
                    const complete =
                        try connection.applyAuthenticationEvent(
                            owned.auth,
                        );
                    try handler.handle(
                        handler.context,
                        connection,
                        owned.auth,
                        complete,
                    );
                },
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
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_owned =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (!session_owned) connection.applyPubAck(
                        owned.ack,
                    ) catch |err| {
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
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_owned =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (!session_owned) connection.applyPubRec(
                        owned.ack,
                    ) catch |err| {
                        slot.writer_mutex.unlock(task.broker.io);
                        return err;
                    };
                    slot.writer_mutex.unlock(task.broker.io);
                    if (session_owned) {
                        try task.broker.flushSlot(
                            task.slot_index,
                            slot,
                        );
                    }
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
                    task.broker.state_mutex.lockUncancelable(
                        task.broker.io,
                    );
                    const session_owned =
                        task.broker.handleSessionAckLocked(
                            slot,
                            owned.ack,
                        ) catch |err| {
                            task.broker.state_mutex.unlock(
                                task.broker.io,
                            );
                            slot.writer_mutex.unlock(task.broker.io);
                            return err;
                        };
                    task.broker.state_mutex.unlock(task.broker.io);
                    if (!session_owned) connection.applyPubComp(
                        owned.ack,
                    ) catch |err| {
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

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

fn protocolReason(
    protocol: mqtt.ProtocolVersion,
    reason_code: u8,
) u8 {
    // MQTT 3.1.1 ACK packets have no reason-code field. Success is the only
    // representable response; MQTT 5 keeps the broker's richer result.
    return if (protocol == .v5) reason_code else 0;
}

test {
    _ = @import("broker_tests.zig");
}
