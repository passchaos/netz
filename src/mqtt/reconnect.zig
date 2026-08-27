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
const command_queue = @import("reconnect/command_queue.zig");
const owned_subscription = @import("reconnect/subscription.zig");

const net = std.Io.net;

pub const CommandQueue = command_queue.CommandQueue;
pub const CommandQueueError = command_queue.Error;
pub const CommandCompletion = command_queue.Completion;
pub const CommandCompletionHandler = command_queue.CompletionHandler;
pub const OwnedCommandCompletion = command_queue.OwnedCompletion;
pub const CompletionQueue = command_queue.CompletionQueue;
pub const CompletionQueueError = command_queue.CompletionQueueError;

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

pub const Jitter = enum {
    none,
    /// Uniformly choose a delay in [0, backoff]. This is the AWS-style full
    /// jitter strategy and minimizes synchronized reconnect storms.
    full,
    /// Uniformly choose a delay in [backoff/2, backoff]. Equal jitter retains
    /// a minimum cooldown while still spreading reconnect attempts.
    equal,
};

/// Retry delays are bounded and saturating. `max_delay` may equal
/// `initial_delay`, yielding a fixed delay independently of `backoff`.
pub const ReconnectPolicy = struct {
    initial_delay: std.Io.Duration = .fromSeconds(1),
    max_delay: std.Io.Duration = .fromSeconds(30),
    backoff: Backoff = .exponential,
    jitter: Jitter = .none,
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

    /// Apply the configured jitter using an explicit sample. Keeping this
    /// calculation pure makes bounds and edge values deterministic in tests.
    pub fn jitteredDelay(
        self: ReconnectPolicy,
        failed_attempts: usize,
        random_sample: u64,
    ) std.Io.Duration {
        const base = self.delay(failed_attempts).nanoseconds;
        if (base <= 0 or self.jitter == .none) {
            return .fromNanoseconds(base);
        }
        const base_unsigned: u128 = @intCast(base);
        const minimum: u128 = switch (self.jitter) {
            .none => unreachable,
            .full => 0,
            .equal => base_unsigned / 2,
        };
        const width = base_unsigned - minimum;
        // Multiplication-high maps every u64 sample into an inclusive bounded
        // interval without modulo bias. `width + 1` is safe because durations
        // are positive i96 values.
        const offset: u128 = if (random_sample == std.math.maxInt(u64))
            width
        else
            @intCast(
                (@as(u192, random_sample) * @as(u192, width + 1)) >> 64,
            );
        return .fromNanoseconds(@intCast(minimum + offset));
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

pub const PollOptions = struct {
    /// Maximum time this call may spend waiting for the next packet or
    /// keep-alive transition.
    timeout: std.Io.Duration,
    /// Maximum interval between PINGREQ and PINGRESP. Null uses the
    /// broker-negotiated Keep Alive interval.
    ping_response_timeout: ?std.Io.Duration = null,
    /// Upper bound on how long a silent socket read delays observing the
    /// shared shutdown event. Short bounded reads preserve single ownership
    /// while making cancellation independent of the MQTT Keep Alive value.
    cancellation_check_interval: std.Io.Duration = .fromMilliseconds(100),
};

pub const QueuedServeOptions = struct {
    poll: PollOptions,
    /// Maximum socket wait before newly queued commands are observed.
    command_poll_interval: std.Io.Duration = .fromMilliseconds(10),
    /// Bound command work between socket reads so sustained producers cannot
    /// starve inbound acknowledgements or Keep Alive traffic.
    max_commands_per_tick: usize = 64,
};

pub const RunQueuedOptions = struct {
    queue_capacity: usize = 16,
    serve: QueuedServeOptions,
};

pub const QueuedRun = struct {
    io: std.Io,
    shutdown: *std.Io.Event,
    queue: *CommandQueue,
    worker: std.Thread,
    result: *?anyerror,

    pub fn publish(
        self: *QueuedRun,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
    ) CommandQueueError!?u16 {
        return self.queue.publish(topic, payload, options);
    }

    pub fn publishAsync(
        self: *QueuedRun,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        completion: command_queue.CompletionHandler,
    ) CommandQueueError!u64 {
        return self.queue.publishAsync(
            topic,
            payload,
            options,
            completion,
        );
    }

    /// Enqueue an owned PUBLISH and route its result into `completions`.
    pub fn publishQueued(
        self: *QueuedRun,
        completions: *CompletionQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
    ) CommandQueueError!u64 {
        return self.publishAsync(
            topic,
            payload,
            options,
            completions.handler(),
        );
    }

    pub fn subscribeAsync(
        self: *QueuedRun,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        completion: command_queue.CompletionHandler,
    ) CommandQueueError!u64 {
        return self.queue.subscribeAsync(
            subscriptions,
            options,
            completion,
        );
    }

    /// Enqueue an owned SUBSCRIBE with an awaitable, owned completion.
    pub fn subscribeQueued(
        self: *QueuedRun,
        completions: *CompletionQueue,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
    ) CommandQueueError!u64 {
        return self.subscribeAsync(
            subscriptions,
            options,
            completions.handler(),
        );
    }

    pub fn unsubscribeAsync(
        self: *QueuedRun,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        completion: command_queue.CompletionHandler,
    ) CommandQueueError!u64 {
        return self.queue.unsubscribeAsync(
            filters,
            options,
            completion,
        );
    }

    /// Enqueue an owned UNSUBSCRIBE with an awaitable, owned completion.
    pub fn unsubscribeQueued(
        self: *QueuedRun,
        completions: *CompletionQueue,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
    ) CommandQueueError!u64 {
        return self.unsubscribeAsync(
            filters,
            options,
            completions.handler(),
        );
    }

    pub fn flushPending(self: *QueuedRun) CommandQueueError!void {
        return self.queue.flushPending();
    }

    pub fn beginReauthentication(
        self: *QueuedRun,
        properties: []const mqtt.Property,
    ) CommandQueueError!void {
        return self.queue.beginReauthentication(properties);
    }

    pub fn stop(self: *QueuedRun) void {
        self.shutdown.set(self.io);
    }

    /// Join the managed worker and release its command-channel resources. The
    /// reconnect Client and shutdown Event must still be alive at this point.
    /// Deinitialization requests shutdown, so joining an idle worker is safe.
    pub fn deinit(self: *QueuedRun) ?anyerror {
        self.stop();
        self.worker.join();
        const result = self.result.*;
        const allocator = self.queue.allocator;
        allocator.destroy(self.result);
        self.queue.deinit();
        allocator.destroy(self.queue);
        self.* = undefined;
        return result;
    }
};

/// One observable transition from the reconnecting client's ordered event
/// loop. Packet-bearing variants own their bytes until `deinit` is called.
pub const ClientEvent = union(enum) {
    connected: ConnectEvent,
    publish: runtime.OwnedPublish,
    puback: runtime.OwnedAck,
    pubrec: runtime.OwnedAck,
    pubrel: runtime.OwnedAck,
    pubcomp: runtime.OwnedAck,
    pingreq: void,
    pingresp: void,
    disconnect: runtime.OwnedDisconnect,
    auth: runtime.OwnedAuth,

    pub fn deinit(self: *ClientEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .publish => |*value| value.deinit(allocator),
            .puback => |*value| value.deinit(allocator),
            .pubrec => |*value| value.deinit(allocator),
            .pubrel => |*value| value.deinit(allocator),
            .pubcomp => |*value| value.deinit(allocator),
            .disconnect => |*value| value.deinit(allocator),
            .auth => |*value| value.deinit(allocator),
            .connected, .pingreq, .pingresp => {},
        }
        self.* = undefined;
    }
};

pub const SubscriptionOptions = struct {
    /// Maximum number of filters retained for fresh-session replay.
    max_subscriptions: usize = 1024,
};

const OwnedSubscription = owned_subscription.Owned;

/// A synchronous, cancellation-aware reconnecting MQTT client for TCP.
///
/// Methods are single-owner: an application must serialize `connect`,
/// `publish`, acknowledgement reads and `deinit`. Cancellation may be signaled
/// concurrently and interrupts retry backoff; call `connection().shutdown()`
/// as well when an application needs to interrupt an already-established
/// blocking read.
pub const Client = struct {
    const Target = union(enum) {
        tcp: net.IpAddress,
        connector: runtime.ClientConnector,
    };

    allocator: std.mem.Allocator,
    io: std.Io,
    target: Target,
    options: OwnedConnectOptions,
    policy: ReconnectPolicy,
    shutdown: *std.Io.Event,
    connection_state: ?runtime.Connection = null,
    outgoing: session.Store,
    outgoing_handle: session.Handle,
    outgoing_open: bool = true,
    subscription_options: SubscriptionOptions,
    subscriptions: std.ArrayList(OwnedSubscription) = .empty,
    keep_alive_deadline: ?std.Io.Timestamp = null,
    ping_response_deadline: ?std.Io.Timestamp = null,

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
        return initTarget(
            allocator,
            io,
            .{ .tcp = address },
            options,
            policy,
            shutdown,
            subscription_options,
        );
    }

    /// Initialize with a transport-specific connector. Connector context and
    /// transport configuration are borrowed for the Client lifetime; MQTT
    /// CONNECT fields continue to be deeply owned exactly as in `init`.
    pub fn initConnector(
        allocator: std.mem.Allocator,
        io: std.Io,
        connector: runtime.ClientConnector,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
    ) Error!Client {
        return initConnectorWithOptions(
            allocator,
            io,
            connector,
            options,
            policy,
            shutdown,
            .{},
        );
    }

    pub fn initConnectorWithOptions(
        allocator: std.mem.Allocator,
        io: std.Io,
        connector: runtime.ClientConnector,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
        subscription_options: SubscriptionOptions,
    ) Error!Client {
        return initTarget(
            allocator,
            io,
            .{ .connector = connector },
            options,
            policy,
            shutdown,
            subscription_options,
        );
    }

    fn initTarget(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
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
            .target = target,
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
                const retry_delay = if (self.policy.jitter == .none)
                    self.policy.delay(failed_attempts)
                else blk: {
                    var random_bytes: [8]u8 = undefined;
                    self.io.random(&random_bytes);
                    break :blk self.policy.jitteredDelay(
                        failed_attempts,
                        std.mem.readInt(u64, &random_bytes, .little),
                    );
                };
                try self.waitBackoff(retry_delay);
            }

            var attempt = self.connectAttempt() catch |err| {
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
            self.connection_state.?.resetPacketIdentifiers();

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
            self.noteControlSent();
            self.ping_response_deadline = null;
            return .{
                .session_present = session_present,
                .failed_attempts = failed_attempts,
            };
        }
    }

    fn connectAttempt(self: *Client) runtime.Error!runtime.ConnectAttempt {
        return switch (self.target) {
            .tcp => |address| runtime.Client.connectAttempt(
                self.allocator,
                self.io,
                address,
                self.options.value,
            ),
            .connector => |connector| connector.connectAttempt(
                self.allocator,
                self.io,
                self.options.value,
            ),
        };
    }

    /// Close only the current transport. Durable outgoing QoS state remains
    /// owned by this client and is marked for retransmission on the next
    /// successful connection.
    pub fn disconnectTransport(self: *Client) void {
        if (self.connection_state) |*active| active.close();
        self.connection_state = null;
        self.keep_alive_deadline = null;
        self.ping_response_deadline = null;
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
        self.noteControlSent();
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
        self.noteControlSent();
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
        self.noteControlSent();
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
            self.noteControlSent();
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
        self.noteControlSent();
        return publish_value.packet_id;
    }

    /// Drive exactly one ordered client event, returning null when the caller's
    /// bound expires first. The method is the sole reader and performs all QoS
    /// acknowledgements, keep-alive probes, and retryable reconnects itself.
    /// Applications must not mix it concurrently with typed reads or
    /// `completeNextPublish`.
    pub fn pollWithOptions(
        self: *Client,
        options: PollOptions,
    ) (Error || std.Io.Cancelable)!?ClientEvent {
        if (options.timeout.nanoseconds <= 0) return error.Timeout;
        if (options.ping_response_timeout) |timeout| {
            if (timeout.nanoseconds <= 0) return error.Timeout;
        }
        if (options.cancellation_check_interval.nanoseconds <= 0) {
            return error.Timeout;
        }
        const call_deadline = std.Io.Clock.awake.now(self.io).addDuration(
            options.timeout,
        );

        while (true) {
            if (self.shutdown.isSet()) return error.Canceled;
            if (self.connection_state == null) {
                return .{ .connected = try self.connect() };
            }

            const now = std.Io.Clock.awake.now(self.io);
            if (self.ping_response_deadline) |deadline| {
                if (now.nanoseconds >= deadline.nanoseconds) {
                    return .{ .connected = try self.reconnect() };
                }
            } else if (self.keepAliveDeadline()) |deadline| {
                if (now.nanoseconds >= deadline.nanoseconds) {
                    const active = self.connection().?;
                    active.writePingReq() catch |err| {
                        if (!retryableConnectError(err)) return err;
                        return .{ .connected = try self.reconnect() };
                    };
                    const sent_at = std.Io.Clock.awake.now(self.io);
                    self.keep_alive_deadline = sent_at.addDuration(
                        .fromSeconds(active.keep_alive_seconds),
                    );
                    self.ping_response_deadline = sent_at.addDuration(
                        self.pingResponseTimeout(options),
                    );
                    return .{ .pingreq = {} };
                }
            }
            if (now.nanoseconds >= call_deadline.nanoseconds) {
                return null;
            }

            const read_deadline = self.nextPollDeadline(
                call_deadline,
                now,
                options.cancellation_check_interval,
            );
            const wait = now.durationTo(read_deadline);
            var packet_event = self.connection().?.readClientPacketEventWithTimeout(
                wait,
            ) catch |err| {
                if (err == error.Timeout) continue;
                if (!retryableConnectError(err)) return err;
                return .{ .connected = try self.reconnect() };
            };
            var packet_owned = true;
            defer if (packet_owned) packet_event.deinit(self.allocator);
            const client_event = try self.applyPacketEvent(&packet_event);
            if (client_event) |event| {
                packet_owned = false;
                return event;
            }
        }
    }

    pub fn pollWithTimeout(
        self: *Client,
        timeout: std.Io.Duration,
    ) (Error || std.Io.Cancelable)!?ClientEvent {
        return self.pollWithOptions(.{ .timeout = timeout });
    }

    /// Run the single-owner reconnect/keep-alive loop until `shutdown` is set.
    /// Events are borrowed only for the synchronous callback and are released
    /// immediately afterward, including when the handler returns an error.
    pub fn serveUntil(
        self: *Client,
        comptime Context: type,
        context: *Context,
        comptime handler: *const fn (
            *Context,
            *Client,
            *ClientEvent,
        ) anyerror!void,
        options: PollOptions,
    ) anyerror!void {
        while (!self.shutdown.isSet()) {
            var event = self.pollWithOptions(options) catch |err| {
                if (err == error.Canceled and self.shutdown.isSet()) return;
                return err;
            } orelse continue;
            defer event.deinit(self.allocator);
            try handler(context, self, &event);
        }
    }

    /// Drive a bounded multi-producer command channel and inbound MQTT events
    /// from one transport owner. Command execution errors are returned to the
    /// submitting producer; only poll or event-handler failures stop the loop.
    pub fn serveQueuedUntil(
        self: *Client,
        queue: *CommandQueue,
        comptime Context: type,
        context: *Context,
        comptime handler: *const fn (
            *Context,
            *Client,
            *ClientEvent,
        ) anyerror!void,
        options: QueuedServeOptions,
    ) anyerror!void {
        if (options.command_poll_interval.nanoseconds <= 0 or
            options.max_commands_per_tick == 0)
        {
            return error.InvalidProperty;
        }
        defer queue.stop(error.CommandQueueClosed);
        while (!self.shutdown.isSet()) {
            // Establish transport ownership before accepting commands. This
            // lets producers enqueue immediately after startup without racing
            // a transient ConnectionUnavailable result.
            if (self.connection_state == null) {
                var event = self.pollWithOptions(options.poll) catch |err| {
                    if (err == error.Canceled and self.shutdown.isSet()) return;
                    return err;
                } orelse continue;
                defer event.deinit(self.allocator);
                try handler(context, self, &event);
                continue;
            }
            var handled: usize = 0;
            while (handled < options.max_commands_per_tick) : (handled += 1) {
                const command = queue.take() catch |err| switch (err) {
                    error.CommandQueueClosed => return,
                    else => return err,
                } orelse break;
                self.executeQueuedCommand(command);
            }
            var poll = options.poll;
            poll.timeout = .fromNanoseconds(@min(
                poll.timeout.nanoseconds,
                options.command_poll_interval.nanoseconds,
            ));
            var event = self.pollWithOptions(poll) catch |err| {
                if (err == error.Canceled and self.shutdown.isSet()) return;
                return err;
            } orelse continue;
            defer event.deinit(self.allocator);
            try handler(context, self, &event);
        }
    }

    /// Spawn a managed OS thread that owns all MQTT transport access. The
    /// returned handle may be shared by producers; signal the Client's
    /// shutdown Event before `QueuedRun.deinit` when the handler does not stop
    /// the loop itself.
    pub fn runQueued(
        self: *Client,
        comptime Context: type,
        context: *Context,
        comptime handler: *const fn (
            *Context,
            *Client,
            *ClientEvent,
        ) anyerror!void,
        options: RunQueuedOptions,
    ) (std.mem.Allocator.Error || std.Thread.SpawnError)!QueuedRun {
        const result = try self.allocator.create(?anyerror);
        errdefer self.allocator.destroy(result);
        result.* = null;
        const queue = try self.allocator.create(CommandQueue);
        errdefer self.allocator.destroy(queue);
        queue.* = try CommandQueue.init(
            self.allocator,
            self.io,
            options.queue_capacity,
        );
        errdefer queue.deinit();
        const worker = try std.Thread.spawn(.{}, struct {
            fn run(
                client: *Client,
                command_channel: *CommandQueue,
                handler_context: *Context,
                result_ptr: *?anyerror,
                serve_options: QueuedServeOptions,
            ) void {
                client.serveQueuedUntil(
                    command_channel,
                    Context,
                    handler_context,
                    handler,
                    serve_options,
                ) catch |err| {
                    result_ptr.* = err;
                };
            }
        }.run, .{ self, queue, context, result, options.serve });
        return .{
            .io = self.io,
            .shutdown = self.shutdown,
            .queue = queue,
            .worker = worker,
            .result = result,
        };
    }

    /// Initiate MQTT 5 re-authentication. Subsequent AUTH challenges and the
    /// final success packet are processed by the same single-owner poll path.
    /// The supplied properties are borrowed only for this synchronous write.
    pub fn beginReauthentication(
        self: *Client,
        properties: []const mqtt.Property,
    ) Error!void {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        try active.beginReauthenticationWithProperties(properties);
        self.noteControlSent();
    }

    /// Retry queued QoS publications after a connection becomes available.
    /// This is useful when `publish` returned `ConnectionUnavailable` after
    /// durably queueing the request.
    pub fn flushPending(self: *Client) Error!void {
        try self.replayPending();
        self.noteControlSent();
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

    fn applyPacketEvent(
        self: *Client,
        packet_event: *runtime.ClientPacketEvent,
    ) Error!?ClientEvent {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        return switch (packet_event.*) {
            .publish => |owned| blk: {
                if (owned.publish.packet_id) |packet_id| {
                    switch (owned.publish.qos) {
                        .at_most_once => unreachable,
                        .at_least_once => try active.writePubAck(packet_id, 0),
                        .exactly_once => {
                            const duplicate =
                                try self.outgoing.recordIncomingQoS2(
                                    self.outgoing_handle,
                                    packet_id,
                                );
                            try active.writePubRec(packet_id, 0);
                            self.noteControlSent();
                            if (duplicate) {
                                return null;
                            }
                        },
                    }
                    self.noteControlSent();
                }
                break :blk .{ .publish = owned };
            },
            .puback => |owned| blk: {
                _ = try self.applyOutgoingAck(owned.ack);
                break :blk .{ .puback = owned };
            },
            .pubrec => |owned| blk: {
                const action = try self.applyOutgoingAck(owned.ack);
                if (action == .send_pubrel) {
                    try self.replayPending();
                    self.noteControlSent();
                }
                break :blk .{ .pubrec = owned };
            },
            .pubrel => |owned| blk: {
                const packet_id = owned.ack.packet_id;
                const pending = try self.outgoing.containsIncomingQoS2(
                    self.outgoing_handle,
                    packet_id,
                );
                if (pending) {
                    // Session Present can resume a transaction whose receive
                    // bit lived on the old socket. Recreate only that local
                    // accounting before the normal PUBCOMP writer clears it.
                    try active.resumeIncomingQoS2(packet_id);
                    try self.outgoing.completeIncomingQoS2(
                        self.outgoing_handle,
                        packet_id,
                    );
                }
                // Unknown/repeated PUBREL is idempotently acknowledged: the
                // prior PUBCOMP may have been lost after durable completion.
                try active.writePubComp(packet_id, 0);
                self.noteControlSent();
                break :blk .{ .pubrel = owned };
            },
            .pubcomp => |owned| blk: {
                _ = try self.applyOutgoingAck(owned.ack);
                break :blk .{ .pubcomp = owned };
            },
            .pingresp => |*packet| blk: {
                if (self.ping_response_deadline == null) {
                    return error.UnexpectedPacket;
                }
                self.ping_response_deadline = null;
                packet.deinit(self.allocator);
                break :blk .{ .pingresp = {} };
            },
            .disconnect => |owned| blk: {
                self.disconnectTransport();
                break :blk .{ .disconnect = owned };
            },
            .auth => |owned| blk: {
                const complete = try active.applyAuthenticationEvent(
                    owned.auth,
                );
                if (!complete) {
                    const handler = self.options.value.authentication orelse
                        return error.AuthenticationNotConfigured;
                    const response = try handler.respond(
                        handler.context,
                        owned.auth,
                    );
                    try active.continueReauthenticationWithProperties(
                        0x18,
                        response,
                    );
                    self.noteControlSent();
                }
                break :blk .{ .auth = owned };
            },
        };
    }

    fn executeQueuedCommand(
        self: *Client,
        command: *command_queue.Command,
    ) void {
        switch (command.operation) {
            .publish => |publish_command| {
                const packet_id = self.publish(
                    publish_command.topic,
                    publish_command.payload,
                    publish_command.options,
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return;
                };
                command.finishSuccess(self.io, packet_id);
                return;
            },
            .publish_owned => |publish_command| {
                const packet_id = self.publish(
                    publish_command.topic,
                    publish_command.payload,
                    .{
                        .qos = publish_command.qos,
                        .retain = publish_command.retain,
                        .dup = publish_command.dup,
                        .properties = publish_command.properties,
                    },
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return;
                };
                command.finishSuccess(self.io, packet_id);
                return;
            },
            .subscribe_owned => |subscribe_command| {
                var subscriptions = std.ArrayList(mqtt.Subscription).empty;
                defer subscriptions.deinit(self.allocator);
                subscriptions.ensureTotalCapacity(
                    self.allocator,
                    subscribe_command.subscriptions.len,
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return;
                };
                for (subscribe_command.subscriptions) |stored| {
                    subscriptions.appendAssumeCapacity(stored.value());
                }
                var suback = self.subscribe(
                    subscriptions.items,
                    .{ .properties = subscribe_command.properties },
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return;
                };
                command.finishSubAck(self.io, &suback);
                return;
            },
            .unsubscribe_owned => |unsubscribe_command| {
                var unsuback = self.unsubscribe(
                    unsubscribe_command.filters,
                    .{ .properties = unsubscribe_command.properties },
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return;
                };
                command.finishUnsubAck(self.io, &unsuback);
                return;
            },
            .flush_pending => {
                self.flushPending() catch |err| {
                    command.finishFailure(self.io, err);
                    return;
                };
            },
            .begin_reauthentication => |properties| {
                self.beginReauthentication(properties) catch |err| {
                    command.finishFailure(self.io, err);
                    return;
                };
            },
        }
        command.finishSuccess(self.io, null);
    }

    fn applyOutgoingAck(
        self: *Client,
        ack: mqtt.AckPacket,
    ) Error!session.AckAction {
        return self.outgoing.handleAck(
            self.outgoing_handle,
            ack.packet_type,
            ack.packet_id,
            ack.reason_code,
        );
    }

    fn noteControlSent(self: *Client) void {
        const active = if (self.connection_state) |*current|
            current
        else
            return;
        if (active.keep_alive_seconds == 0) {
            self.keep_alive_deadline = null;
            return;
        }
        self.keep_alive_deadline = std.Io.Clock.awake.now(self.io).addDuration(
            .fromSeconds(active.keep_alive_seconds),
        );
    }

    fn keepAliveDeadline(self: *const Client) ?std.Io.Timestamp {
        return self.keep_alive_deadline;
    }

    fn pingResponseTimeout(
        self: *const Client,
        options: PollOptions,
    ) std.Io.Duration {
        return options.ping_response_timeout orelse
            .fromSeconds(self.connection_state.?.keep_alive_seconds);
    }

    fn nextPollDeadline(
        self: *const Client,
        call_deadline: std.Io.Timestamp,
        now: std.Io.Timestamp,
        cancellation_check_interval: std.Io.Duration,
    ) std.Io.Timestamp {
        var result = call_deadline;
        if (self.ping_response_deadline orelse self.keepAliveDeadline()) |internal| {
            if (internal.nanoseconds < result.nanoseconds) result = internal;
        }
        const cancellation_deadline = now.addDuration(
            cancellation_check_interval,
        );
        if (cancellation_deadline.nanoseconds < result.nanoseconds) {
            result = cancellation_deadline;
        }
        return result;
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
    return OwnedSubscription.clone(allocator, subscription, properties);
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

test "MQTT reconnect jitter remains inside policy bounds" {
    const base = ReconnectPolicy{
        .initial_delay = .fromMilliseconds(100),
        .max_delay = .fromMilliseconds(800),
        .jitter = .full,
    };
    try std.testing.expectEqual(
        @as(i96, 0),
        base.jitteredDelay(3, 0).nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 400_000_000),
        base.jitteredDelay(3, std.math.maxInt(u64)).nanoseconds,
    );

    var equal = base;
    equal.jitter = .equal;
    try std.testing.expectEqual(
        @as(i96, 200_000_000),
        equal.jitteredDelay(3, 0).nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 400_000_000),
        equal.jitteredDelay(3, std.math.maxInt(u64)).nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 0),
        equal.jitteredDelay(0, std.math.maxInt(u64)).nanoseconds,
    );

    var none = base;
    none.jitter = .none;
    try std.testing.expectEqual(
        @as(i96, 400_000_000),
        none.jitteredDelay(3, 0).nanoseconds,
    );

    const huge_ns = std.math.maxInt(i96) - 1;
    const huge = ReconnectPolicy{
        .initial_delay = .fromNanoseconds(huge_ns),
        .max_delay = .fromNanoseconds(huge_ns),
        .backoff = .fixed,
        .jitter = .full,
    };
    try std.testing.expectEqual(
        huge_ns,
        huge.jitteredDelay(1, std.math.maxInt(u64)).nanoseconds,
    );
}
