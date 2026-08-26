//! Stateful cleartext MQTT client reconnection.
//!
//! The packet runtime intentionally represents one Network Connection. This
//! layer owns the state that must outlive that transport: copied CONNECT
//! parameters, queued/inflight publications, Packet Identifiers, and retry
//! scheduling. It reuses the broker Session store because MQTT applies the
//! same QoS 1/2 retransmission rules in both directions.

const std = @import("std");
const mqtt = @import("mod.zig");
const owned_properties = @import("owned_properties.zig");
const runtime = @import("runtime.zig");
const session = @import("session/mod.zig");

const net = std.Io.net;

pub const Error = runtime.Error || session.Error || error{
    InvalidReconnectPolicy,
    ConnectionUnavailable,
    SessionLost,
    SubscriptionLimitExceeded,
    SubscriptionRefused,
    OwnedPropertyLimitExceeded,
};

const OptionsError = mqtt.Error || std.mem.Allocator.Error ||
    error{OwnedPropertyLimitExceeded};

pub const Backoff = enum {
    fixed,
    linear,
    exponential,
};

/// Retry delays are bounded and saturating. `max_delay` may equal
/// `initial_delay`, yielding a fixed delay independently of `backoff`.
pub const ReconnectPolicy = struct {
    initial_delay: std.Io.Duration = .fromSeconds(1),
    max_delay: std.Io.Duration = .fromSeconds(30),
    backoff: Backoff = .exponential,
    /// Zero means retry until cancellation, matching long-lived client loops.
    max_attempts: usize = 0,

    pub fn validate(self: ReconnectPolicy) Error!void {
        if (self.initial_delay.nanoseconds <= 0 or
            self.max_delay.nanoseconds < self.initial_delay.nanoseconds)
        {
            return error.InvalidReconnectPolicy;
        }
    }

    pub fn delay(self: ReconnectPolicy, failed_attempts: usize) std.Io.Duration {
        if (failed_attempts == 0) return .zero;
        const initial = self.initial_delay.nanoseconds;
        const maximum = self.max_delay.nanoseconds;
        if (initial >= maximum) return self.max_delay;
        const scaled = switch (self.backoff) {
            .fixed => initial,
            .linear => blk: {
                const attempts: i96 = std.math.cast(
                    i96,
                    failed_attempts,
                ) orelse break :blk maximum;
                break :blk std.math.mul(i96, initial, attempts) catch maximum;
            },
            .exponential => blk: {
                const shift = @min(failed_attempts - 1, 95);
                const factor = @as(i96, 1) << @intCast(shift);
                break :blk std.math.mul(i96, initial, factor) catch maximum;
            },
        };
        return .fromNanoseconds(@min(scaled, self.max_delay.nanoseconds));
    }
};

const OwnedWill = struct {
    topic: []u8,
    payload: []u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []mqtt.Property,

    fn clone(
        allocator: std.mem.Allocator,
        value: mqtt.LastWill,
    ) !OwnedWill {
        const topic = try allocator.dupe(u8, value.topic);
        errdefer allocator.free(topic);
        const payload = try allocator.dupe(u8, value.payload);
        errdefer allocator.free(payload);
        const properties = try owned_properties.clone(
            allocator,
            value.properties,
            owned_properties.keepAll,
        );
        return .{
            .topic = topic,
            .payload = payload,
            .qos = value.qos,
            .retain = value.retain,
            .properties = properties.properties,
        };
    }

    fn view(self: OwnedWill) mqtt.LastWill {
        return .{
            .topic = self.topic,
            .payload = self.payload,
            .qos = self.qos,
            .retain = self.retain,
            .properties = self.properties,
        };
    }

    fn deinit(self: *OwnedWill, allocator: std.mem.Allocator) void {
        allocator.free(self.topic);
        allocator.free(self.payload);
        owned_properties.deinit(allocator, self.properties);
        self.* = undefined;
    }
};

const OwnedConnectOptions = struct {
    value: runtime.ConnectOptions,
    client_id: []u8,
    properties: []mqtt.Property,
    username: ?[]u8,
    password: ?[]u8,
    will: ?OwnedWill,

    fn init(
        allocator: std.mem.Allocator,
        options: runtime.ConnectOptions,
    ) OptionsError!OwnedConnectOptions {
        const client_id = try allocator.dupe(u8, options.client_id);
        errdefer allocator.free(client_id);
        const properties = try owned_properties.clone(
            allocator,
            options.properties,
            owned_properties.keepAll,
        );
        errdefer owned_properties.deinit(allocator, properties.properties);
        const username = if (options.username) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (username) |value| allocator.free(value);
        const password = if (options.password) |value|
            try allocator.dupe(u8, value)
        else
            null;
        errdefer if (password) |value| allocator.free(value);
        const will = if (options.will) |value|
            try OwnedWill.clone(allocator, value)
        else
            null;
        errdefer if (will) |*value| {
            var owned = value.*;
            owned.deinit(allocator);
        };

        var value = options;
        value.client_id = client_id;
        value.properties = properties.properties;
        value.username = username;
        value.password = password;
        value.will = if (will) |owned| owned.view() else null;
        return .{
            .value = value,
            .client_id = client_id,
            .properties = properties.properties,
            .username = username,
            .password = password,
            .will = will,
        };
    }

    fn deinit(self: *OwnedConnectOptions, allocator: std.mem.Allocator) void {
        if (self.will) |*will| will.deinit(allocator);
        if (self.password) |value| allocator.free(value);
        if (self.username) |value| allocator.free(value);
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.client_id);
        self.* = undefined;
    }
};

pub const ConnectEvent = struct {
    session_present: bool,
    failed_attempts: usize,
};

pub const SubscriptionOptions = struct {
    /// Maximum number of filters retained for fresh-session replay.
    max_subscriptions: usize = 1024,
};

const OwnedSubscription = struct {
    filter: []u8,
    qos: mqtt.QoS,
    no_local: bool,
    retain_as_published: bool,
    retain_handling: u2,
    properties: []mqtt.Property,

    fn deinit(self: *OwnedSubscription, allocator: std.mem.Allocator) void {
        allocator.free(self.filter);
        owned_properties.deinit(allocator, self.properties);
        self.* = undefined;
    }

    fn value(self: OwnedSubscription) mqtt.Subscription {
        return .{
            .topic_filter = self.filter,
            .qos = self.qos,
            .no_local = self.no_local,
            .retain_as_published = self.retain_as_published,
            .retain_handling = self.retain_handling,
        };
    }
};

/// A synchronous, cancellation-aware reconnecting MQTT client for TCP.
///
/// Methods are single-owner: an application must serialize `connect`,
/// `publish`, acknowledgement reads and `deinit`. Cancellation may be signaled
/// concurrently and interrupts retry backoff; call `connection().shutdown()`
/// as well when an application needs to interrupt an already-established
/// blocking read.
pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    address: net.IpAddress,
    options: OwnedConnectOptions,
    policy: ReconnectPolicy,
    shutdown: *std.Io.Event,
    connection_state: ?runtime.Connection = null,
    outgoing: session.Store,
    outgoing_handle: session.Handle,
    outgoing_open: bool = true,
    subscription_options: SubscriptionOptions,
    subscriptions: std.ArrayList(OwnedSubscription) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
    ) Error!Client {
        return initWithOptions(
            allocator,
            io,
            address,
            options,
            policy,
            shutdown,
            .{},
        );
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
        subscription_options: SubscriptionOptions,
    ) Error!Client {
        try policy.validate();
        if (options.client_id.len == 0) return error.InvalidClientId;
        var owned_options = try OwnedConnectOptions.init(allocator, options);
        errdefer owned_options.deinit(allocator);
        var outgoing = session.Store.init(allocator, .{
            .max_sessions = 1,
            .max_queued_per_session = std.math.maxInt(u16),
            .max_inflight_per_session = std.math.maxInt(u16),
        });
        errdefer outgoing.deinit();
        const opened = try outgoing.open(
            owned_options.value.client_id,
            false,
            std.math.maxInt(u32),
            .zero,
        );
        return .{
            .allocator = allocator,
            .io = io,
            .address = address,
            .options = owned_options,
            .policy = policy,
            .shutdown = shutdown,
            .subscription_options = subscription_options,
            .outgoing = outgoing,
            .outgoing_handle = opened.handle,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.connection_state) |*active| active.close();
        for (self.subscriptions.items) |*subscription| {
            subscription.deinit(self.allocator);
        }
        self.subscriptions.deinit(self.allocator);
        self.outgoing.deinit();
        self.options.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn connection(self: *Client) ?*runtime.Connection {
        return if (self.connection_state) |*active| active else null;
    }

    /// Connect immediately, then retry failures after the configured delay.
    /// The initial failure count is one, so `delay(1)` is the first sleep.
    /// Protocol-level CONNACK refusal is terminal; retrying credentials or an
    /// administratively rejected Client Identifier would only hide the cause.
    pub fn connect(self: *Client) (Error || std.Io.Cancelable)!ConnectEvent {
        if (self.connection_state != null) return error.InvalidProperty;
        var failed_attempts: usize = 0;
        while (true) {
            if (self.shutdown.isSet()) return error.Canceled;
            if (failed_attempts != 0) {
                if (self.policy.max_attempts != 0 and
                    failed_attempts >= self.policy.max_attempts)
                {
                    return error.ConnectionUnavailable;
                }
                try self.waitBackoff(self.policy.delay(failed_attempts));
            }

            var attempt = runtime.Client.connectAttempt(
                self.allocator,
                self.io,
                self.address,
                self.options.value,
            ) catch |err| {
                if (!retryableConnectError(err)) return err;
                failed_attempts += 1;
                continue;
            };
            if (!attempt.accepted()) {
                attempt.deinit(self.allocator);
                return error.ConnectRefused;
            }
            var result = try attempt.requireAccepted();
            const session_present = result.connack.connack.session_present;
            result.connack.deinit(self.allocator);
            self.connection_state = result.connection;

            // A fresh broker Session cannot recognize Packet Identifiers from
            // the old session. Dropping that state matches rumqttc's behavior
            // and prevents stale QoS traffic from being replayed into it.
            if (!session_present) {
                self.resetOutgoingState() catch |err| {
                    if (self.connection_state) |*active| active.close();
                    self.connection_state = null;
                    return err;
                };
            } else if (!self.outgoing_open) {
                const reopened = self.outgoing.open(
                    self.options.value.client_id,
                    false,
                    std.math.maxInt(u32),
                    std.Io.Clock.awake.now(self.io),
                ) catch |err| {
                    if (self.connection_state) |*active| active.close();
                    self.connection_state = null;
                    return err;
                };
                self.outgoing_handle = reopened.handle;
                self.outgoing_open = true;
            }
            self.replayPending() catch |err| {
                // The CONNECT succeeded but replay did not. Preserve every
                // durable packet and report the transport failure rather than
                // claiming a usable connection.
                self.disconnectTransport();
                return err;
            };
            if (!session_present) {
                self.replaySubscriptions() catch |err| {
                    self.disconnectTransport();
                    return err;
                };
            }
            return .{
                .session_present = session_present,
                .failed_attempts = failed_attempts,
            };
        }
    }

    /// Close only the current transport. Durable outgoing QoS state remains
    /// owned by this client and is marked for retransmission on the next
    /// successful connection.
    pub fn disconnectTransport(self: *Client) void {
        if (self.connection_state) |*active| active.close();
        self.connection_state = null;
        if (self.outgoing_open) {
            self.outgoing.disconnect(
                self.outgoing_handle,
                null,
                std.Io.Clock.awake.now(self.io),
            ) catch {};
            self.outgoing_open = false;
        }
    }

    /// Send a graceful MQTT DISCONNECT and retire only the Network
    /// Connection. Outgoing QoS state remains available until acknowledgements
    /// complete or a future CONNACK reports that the Session no longer exists.
    pub fn disconnect(self: *Client, reason_code: u8) Error!void {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        try active.disconnect(reason_code);
        self.disconnectTransport();
    }

    /// Mark a failed established connection for retry and reconnect it.
    /// Applications call this after any read/write error that makes the
    /// current transport unusable.
    pub fn reconnect(
        self: *Client,
    ) (Error || std.Io.Cancelable)!ConnectEvent {
        self.disconnectTransport();
        return self.connect();
    }

    pub fn outgoingStats(self: *Client) Error!session.Stats {
        return self.outgoing.stats(self.outgoing_handle);
    }

    pub fn subscriptionCount(self: *const Client) usize {
        return self.subscriptions.items.len;
    }

    /// Subscribe and remember only filters accepted by the broker. A future
    /// reconnect replays them when CONNACK reports that no Session survived.
    /// Existing entries are updated transactionally after SUBACK.
    pub fn subscribe(
        self: *Client,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
    ) Error!runtime.OwnedSubAck {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        var additions: usize = 0;
        for (subscriptions, 0..) |subscription, index| {
            try mqtt.validateTopicFilter(subscription.topic_filter);
            if (self.subscriptionIndex(subscription.topic_filter) == null and
                firstSubscriptionIndex(subscriptions, index) == null)
            {
                additions += 1;
            }
        }
        if (additions > self.subscription_options.max_subscriptions -|
            self.subscriptions.items.len)
        {
            return error.SubscriptionLimitExceeded;
        }
        var staged = try self.allocator.alloc(
            ?OwnedSubscription,
            subscriptions.len,
        );
        defer self.allocator.free(staged);
        @memset(staged, null);
        defer for (staged) |*maybe_subscription| {
            if (maybe_subscription.*) |*subscription| {
                subscription.deinit(self.allocator);
            }
        };
        for (subscriptions, 0..) |subscription, index| {
            staged[index] = try cloneSubscription(
                self.allocator,
                subscription,
                options.properties,
            );
        }
        try self.subscriptions.ensureUnusedCapacity(self.allocator, additions);
        var suback = try active.subscribe(subscriptions, options);
        errdefer suback.deinit(self.allocator);
        if (suback.suback.reason_codes.len != subscriptions.len) {
            return error.UnexpectedPacket;
        }
        for (staged, suback.suback.reason_codes) |*maybe_subscription, reason| {
            if (reason >= 0x80) continue;
            const owned = maybe_subscription.*.?;
            maybe_subscription.* = null;
            if (self.subscriptionIndex(owned.filter)) |index| {
                self.subscriptions.items[index].deinit(self.allocator);
                self.subscriptions.items[index] = owned;
            } else {
                self.subscriptions.appendAssumeCapacity(owned);
            }
        }
        return suback;
    }

    /// Unsubscribe and remove only filters accepted by the broker.
    pub fn unsubscribe(
        self: *Client,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
    ) Error!runtime.OwnedUnsubAck {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        var unsuback = try active.unsubscribe(filters, options);
        errdefer unsuback.deinit(self.allocator);
        if (active.protocol == .v3_1_1) {
            for (filters) |filter| self.removeSubscription(filter);
        } else {
            for (filters, unsuback.unsuback.reason_codes) |filter, reason| {
                if (reason < 0x80) self.removeSubscription(filter);
            }
        }
        return unsuback;
    }

    pub fn publish(
        self: *Client,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
    ) Error!?u16 {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        if (@intFromEnum(options.qos) >
            @intFromEnum(active.peerMaximumQoS()))
        {
            return error.InvalidQoS;
        }
        if (options.retain and !active.peerRetainAvailable()) {
            return error.InvalidProperty;
        }
        if (options.qos == .at_most_once) {
            try active.publish(topic, payload, options);
            return null;
        }
        _ = try self.outgoing.enqueuePublish(
            self.outgoing_handle,
            topic,
            payload,
            .{
                .qos = options.qos,
                .retain = options.retain,
                .properties = options.properties,
                .now = std.Io.Clock.awake.now(self.io),
            },
        );
        var transmission: [1]session.Transmission = undefined;
        const selected = try self.outgoing.drainInto(
            self.outgoing_handle,
            std.Io.Clock.awake.now(self.io),
            active.max_outgoing_inflight,
            &transmission,
        );
        if (selected.len == 0 or selected[0] != .publish) {
            return error.InflightFull;
        }
        const publish_value = selected[0].publish;
        active.writeClientSessionTransmission(selected[0]) catch |err| {
            if (!retryableConnectError(err)) {
                try self.outgoing.retryUnsentPublish(
                    self.outgoing_handle,
                    publish_value.packet_id,
                );
                return err;
            }
            // The store already owns this packet. Reconnect marks the selected
            // inflight entry sendable and replays it with DUP, so no separate
            // rollback is required here.
            const connected = try self.reconnect();
            if (!connected.session_present) return error.SessionLost;
        };
        return publish_value.packet_id;
    }

    /// Retry queued QoS publications after a connection becomes available.
    /// This is useful when `publish` returned `ConnectionUnavailable` after
    /// durably queueing the request.
    pub fn flushPending(self: *Client) Error!void {
        return self.replayPending();
    }

    /// Read and apply one QoS acknowledgement. For PUBREC, PUBREL is emitted
    /// before returning so the durable state transition is wire-visible.
    pub fn completeNextPublish(self: *Client) Error!u16 {
        while (true) {
            const active = self.connection() orelse
                return error.ConnectionUnavailable;
            var event = active.readBrokerEvent() catch |err| {
                if (!retryableConnectError(err)) return err;
                const connected = try self.reconnect();
                if (!connected.session_present) return error.SessionLost;
                continue;
            };
            defer event.deinit(self.allocator);
            const ack = switch (event) {
                .puback => |value| value.ack,
                .pubrec => |value| value.ack,
                .pubcomp => |value| value.ack,
                else => return error.UnexpectedPacket,
            };
            const action = try self.outgoing.handleAck(
                self.outgoing_handle,
                ack.packet_type,
                ack.packet_id,
                ack.reason_code,
            );
            if (action == .send_pubrel) try self.replayPending();
            if (!ack.accepted()) return error.PublishRefused;
            return ack.packet_id;
        }
    }

    fn waitBackoff(
        self: *Client,
        delay: std.Io.Duration,
    ) std.Io.Cancelable!void {
        if (delay.nanoseconds <= 0) {
            if (self.shutdown.isSet()) return error.Canceled;
            return;
        }
        self.shutdown.waitTimeout(self.io, .{
            .duration = .{ .raw = delay, .clock = .awake },
        }) catch |err| switch (err) {
            error.Timeout => return,
            error.Canceled => return error.Canceled,
        };
        return error.Canceled;
    }

    fn resetOutgoingState(self: *Client) Error!void {
        self.outgoing.deinit();
        self.outgoing = session.Store.init(self.allocator, .{
            .max_sessions = 1,
            .max_queued_per_session = std.math.maxInt(u16),
            .max_inflight_per_session = std.math.maxInt(u16),
        });
        const opened = try self.outgoing.open(
            self.options.value.client_id,
            false,
            std.math.maxInt(u32),
            std.Io.Clock.awake.now(self.io),
        );
        self.outgoing_handle = opened.handle;
        self.outgoing_open = true;
    }

    fn replayPending(self: *Client) Error!void {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        // Select one packet at a time. If its socket write fails, the Session
        // store can conservatively mark exactly that packet as a retransmit;
        // later queued packets retain first-delivery DUP semantics.
        var batch: [1]session.Transmission = undefined;
        while (true) {
            const transmissions = try self.outgoing.drainInto(
                self.outgoing_handle,
                std.Io.Clock.awake.now(self.io),
                active.max_outgoing_inflight,
                &batch,
            );
            if (transmissions.len == 0) return;
            for (transmissions) |transmission| {
                active.writeClientSessionTransmission(transmission) catch |err| {
                    if (!retryableConnectError(err) and
                        transmission == .publish)
                    {
                        try self.outgoing.retryUnsentPublish(
                            self.outgoing_handle,
                            transmission.publish.packet_id,
                        );
                    }
                    self.disconnectTransport();
                    return err;
                };
            }
        }
    }

    fn replaySubscriptions(self: *Client) Error!void {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        // MQTT 5 Subscription Identifier/User Properties are scoped to the
        // SUBSCRIBE packet. Re-emit each accepted filter with the exact owned
        // properties from the operation that established it.
        for (self.subscriptions.items) |stored| {
            const one = [_]mqtt.Subscription{stored.value()};
            var suback = try active.subscribe(&one, .{
                .properties = stored.properties,
            });
            defer suback.deinit(self.allocator);
            if (suback.suback.reason_codes[0] >= 0x80) {
                return error.SubscriptionRefused;
            }
        }
    }

    fn subscriptionIndex(self: *const Client, filter: []const u8) ?usize {
        for (self.subscriptions.items, 0..) |subscription, index| {
            if (std.mem.eql(u8, subscription.filter, filter)) return index;
        }
        return null;
    }

    fn removeSubscription(self: *Client, filter: []const u8) void {
        const index = self.subscriptionIndex(filter) orelse return;
        var removed = self.subscriptions.orderedRemove(index);
        removed.deinit(self.allocator);
    }
};

fn firstSubscriptionIndex(
    subscriptions: []const mqtt.Subscription,
    end: usize,
) ?usize {
    for (subscriptions[0..end], 0..) |subscription, index| {
        if (std.mem.eql(
            u8,
            subscription.topic_filter,
            subscriptions[end].topic_filter,
        )) return index;
    }
    return null;
}

fn cloneSubscription(
    allocator: std.mem.Allocator,
    subscription: mqtt.Subscription,
    properties: []const mqtt.Property,
) OptionsError!OwnedSubscription {
    const filter = try allocator.dupe(u8, subscription.topic_filter);
    errdefer allocator.free(filter);
    const copied_properties = try owned_properties.clone(
        allocator,
        properties,
        owned_properties.keepAll,
    );
    return .{
        .filter = filter,
        .qos = subscription.qos,
        .no_local = subscription.no_local,
        .retain_as_published = subscription.retain_as_published,
        .retain_handling = subscription.retain_handling,
        .properties = copied_properties.properties,
    };
}

fn retryableConnectError(err: anyerror) bool {
    return switch (err) {
        error.AddressUnavailable,
        error.ConnectionAborted,
        error.ConnectionClosed,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.InputOutput,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.PipeBusy,
        error.SocketUnconnected,
        error.Timeout,
        error.Unexpected,
        error.WouldBlock,
        => true,
        else => false,
    };
}

test "MQTT reconnect policy bounds fixed linear and exponential delays" {
    const initial = std.Io.Duration.fromMilliseconds(100);
    const maximum = std.Io.Duration.fromMilliseconds(450);
    const fixed = ReconnectPolicy{
        .initial_delay = initial,
        .max_delay = maximum,
        .backoff = .fixed,
    };
    try std.testing.expectEqual(@as(i96, 100_000_000), fixed.delay(3).nanoseconds);
    const linear = ReconnectPolicy{
        .initial_delay = initial,
        .max_delay = maximum,
        .backoff = .linear,
    };
    try std.testing.expectEqual(@as(i96, 300_000_000), linear.delay(3).nanoseconds);
    const exponential = ReconnectPolicy{
        .initial_delay = initial,
        .max_delay = maximum,
    };
    try std.testing.expectEqual(@as(i96, 400_000_000), exponential.delay(3).nanoseconds);
    try std.testing.expectEqual(@as(i96, 450_000_000), exponential.delay(99).nanoseconds);
    try std.testing.expectError(error.InvalidReconnectPolicy, (ReconnectPolicy{
        .initial_delay = .fromMilliseconds(2),
        .max_delay = .fromMilliseconds(1),
    }).validate());
}
