//! Stateful transport-agnostic MQTT client reconnection.
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
const event_queue = @import("reconnect/event_queue.zig");
const delivery_queue = @import("reconnect/delivery_queue.zig");
const owned_subscription = @import("reconnect/subscription.zig");
const subscription_replay = @import("reconnect/subscription_replay.zig");
const session_snapshot = @import("reconnect/snapshot.zig");
const session_identity = @import("reconnect/session_identity.zig");
const session_retention = @import("reconnect/retention.zig");
const reconnect_target = @import("reconnect/target.zig");
const backoff = @import("reconnect/backoff.zig");
const tls_stream = @import("../tls/mod.zig").stream;
const deadline_policy = @import("../internal/deadline.zig");

const net = std.Io.net;

test {
    _ = @import("reconnect/keep_alive_write_tests.zig");
    _ = @import("reconnect/event_write_tests.zig");
    _ = @import("reconnect/qos_write_tests.zig");
    _ = @import("reconnect/auth_write_tests.zig");
    _ = @import("reconnect/diagnostic_deadline_tests.zig");
    _ = @import("reconnect/recovery/serve_tests.zig");
    _ = @import("reconnect/recovery/event_tests.zig");
    _ = @import("reconnect/recovery/protocol_tests.zig");
    _ = @import("reconnect/recovery/duplicate_tests.zig");
}

pub const CommandQueue = command_queue.CommandQueue;
pub const CommandQueueError = command_queue.Error;
pub const CommandEnqueueTimeoutError = command_queue.EnqueueTimeoutError;
pub const CommandCompletion = command_queue.Completion;
pub const CommandCompletionHandler = command_queue.CompletionHandler;
pub const OwnedCommandCompletion = command_queue.OwnedCompletion;
pub const CompletionQueue = command_queue.CompletionQueue;
pub const CompletionQueueError = command_queue.CompletionQueueError;
pub const CompletionQueueReceiveTimeoutError =
    command_queue.CompletionQueueReceiveTimeoutError;

pub const Error = runtime.Error || session.Error || error{
    InvalidReconnectPolicy,
    ConnectionUnavailable,
    SessionLost,
    SubscriptionLimitExceeded,
    SubscriptionRefused,
    OwnedPropertyLimitExceeded,
    ManualAcknowledgementsDisabled,
};

pub const SessionSnapshotError = session_snapshot.Error || error{
    SnapshotBusy,
    SessionPersistenceDisabled,
    SessionStateNotEmpty,
    SessionLost,
};
pub const SessionSnapshotFileError = SessionSnapshotError ||
    session_snapshot.FileError;

const OptionsError = mqtt.Error || std.mem.Allocator.Error ||
    error{OwnedPropertyLimitExceeded};

pub const Backoff = backoff.Backoff;
pub const Jitter = backoff.Jitter;
pub const ReconnectPolicy = backoff.Policy;

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
        errdefer if (password) |value| {
            std.crypto.secureZero(u8, value);
            allocator.free(value);
        };
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
        if (self.password) |value| {
            std.crypto.secureZero(u8, value);
            allocator.free(value);
        }
        if (self.username) |value| allocator.free(value);
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.client_id);
        self.* = undefined;
    }
};

pub const ConnectEvent = struct {
    /// Session Present reported by the broker's CONNACK.
    session_present: bool,
    /// Both endpoints retained the previous Session. False when local expiry
    /// or an earlier failed Session reset discarded its QoS state, even if
    /// the broker still reports Session Present.
    session_resumed: bool = false,
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
    /// Whether a retryable error on an established transport may reconnect
    /// within this call. Fair schedulers can disable this for short read
    /// slices, then give the now-disconnected client a full connection budget
    /// on their next turn. Initial connection attempts are unaffected.
    reconnect_after_transport_error: bool = true,
};

/// Internal scheduling options for an already-absolute poll budget. Timestamps
/// in reconnect state are raw awake-clock values, so this avoids pretending
/// they can be compared with an arbitrary `std.Io.Clock.Timestamp`.
pub const DeadlinePollOptions = struct {
    ping_response_timeout: ?std.Io.Duration = null,
    cancellation_check_interval: std.Io.Duration = .fromMilliseconds(100),
    reconnect_after_transport_error: bool = true,
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

const QueuedRunState = struct {
    finished: std.Io.Event = .unset,
    result: ?anyerror = null,
    io_task: std.Io.Future(void) = undefined,
};

const QueuedRunWorker = union(enum) {
    thread: std.Thread,
    io_task,
};

fn QueuedRunWorkerFn(
    comptime Context: type,
    comptime handler: *const fn (
        *Context,
        *Client,
        *ClientEvent,
    ) anyerror!void,
) type {
    return struct {
        fn run(
            client: *Client,
            command_channel: *CommandQueue,
            handler_context: *Context,
            run_state: *QueuedRunState,
            serve_options: QueuedServeOptions,
        ) void {
            defer run_state.finished.set(client.io);
            client.serveQueuedUntil(
                command_channel,
                Context,
                handler_context,
                handler,
                serve_options,
            ) catch |err| {
                run_state.result = err;
            };
        }
    };
}

pub const QueuedRunWaitError = std.Io.Cancelable;
pub const QueuedRunWaitTimeoutError = std.Io.Event.WaitTimeoutError;

pub const QueuedRun = struct {
    io: std.Io,
    shutdown: *std.Io.Event,
    queue: *CommandQueue,
    worker: QueuedRunWorker,
    state: *QueuedRunState,

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

    /// Wait for bounded queue capacity without waiting for MQTT delivery.
    pub fn publishAsyncTimeout(
        self: *QueuedRun,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        completion: command_queue.CompletionHandler,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.publishAsyncTimeout(
            topic,
            payload,
            options,
            completion,
            timeout,
        );
    }

    /// Preserve a caller-owned absolute budget while waiting for queue space.
    pub fn publishAsyncWithDeadline(
        self: *QueuedRun,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        completion: command_queue.CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.publishAsyncWithDeadline(
            topic,
            payload,
            options,
            completion,
            deadline,
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

    pub fn publishQueuedTimeout(
        self: *QueuedRun,
        completions: *CompletionQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.publishAsyncTimeout(
            topic,
            payload,
            options,
            completions.handler(),
            timeout,
        );
    }

    pub fn publishQueuedWithDeadline(
        self: *QueuedRun,
        completions: *CompletionQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.publishAsyncWithDeadline(
            topic,
            payload,
            options,
            completions.handler(),
            deadline,
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

    pub fn subscribeAsyncTimeout(
        self: *QueuedRun,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        completion: command_queue.CompletionHandler,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.subscribeAsyncTimeout(
            subscriptions,
            options,
            completion,
            timeout,
        );
    }

    pub fn subscribeAsyncWithDeadline(
        self: *QueuedRun,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        completion: command_queue.CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.subscribeAsyncWithDeadline(
            subscriptions,
            options,
            completion,
            deadline,
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

    pub fn subscribeQueuedTimeout(
        self: *QueuedRun,
        completions: *CompletionQueue,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.subscribeAsyncTimeout(
            subscriptions,
            options,
            completions.handler(),
            timeout,
        );
    }

    pub fn subscribeQueuedWithDeadline(
        self: *QueuedRun,
        completions: *CompletionQueue,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.subscribeAsyncWithDeadline(
            subscriptions,
            options,
            completions.handler(),
            deadline,
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

    pub fn unsubscribeAsyncTimeout(
        self: *QueuedRun,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        completion: command_queue.CompletionHandler,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.unsubscribeAsyncTimeout(
            filters,
            options,
            completion,
            timeout,
        );
    }

    pub fn unsubscribeAsyncWithDeadline(
        self: *QueuedRun,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        completion: command_queue.CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.unsubscribeAsyncWithDeadline(
            filters,
            options,
            completion,
            deadline,
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

    pub fn unsubscribeQueuedTimeout(
        self: *QueuedRun,
        completions: *CompletionQueue,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.unsubscribeAsyncTimeout(
            filters,
            options,
            completions.handler(),
            timeout,
        );
    }

    pub fn unsubscribeQueuedWithDeadline(
        self: *QueuedRun,
        completions: *CompletionQueue,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.unsubscribeAsyncWithDeadline(
            filters,
            options,
            completions.handler(),
            deadline,
        );
    }

    pub fn disconnect(
        self: *QueuedRun,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) CommandQueueError!void {
        return self.queue.disconnect(reason_code, properties);
    }

    pub fn disconnectAsync(
        self: *QueuedRun,
        reason_code: u8,
        properties: []const mqtt.Property,
        completion: command_queue.CompletionHandler,
    ) CommandQueueError!u64 {
        return self.queue.disconnectAsync(
            reason_code,
            properties,
            completion,
        );
    }

    pub fn disconnectAsyncTimeout(
        self: *QueuedRun,
        reason_code: u8,
        properties: []const mqtt.Property,
        completion: command_queue.CompletionHandler,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.disconnectAsyncTimeout(
            reason_code,
            properties,
            completion,
            timeout,
        );
    }

    pub fn disconnectAsyncWithDeadline(
        self: *QueuedRun,
        reason_code: u8,
        properties: []const mqtt.Property,
        completion: command_queue.CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.disconnectAsyncWithDeadline(
            reason_code,
            properties,
            completion,
            deadline,
        );
    }

    /// Enqueue a graceful disconnect with an awaitable completion.
    pub fn disconnectQueued(
        self: *QueuedRun,
        completions: *CompletionQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) CommandQueueError!u64 {
        return self.disconnectAsync(
            reason_code,
            properties,
            completions.handler(),
        );
    }

    pub fn disconnectQueuedTimeout(
        self: *QueuedRun,
        completions: *CompletionQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.disconnectAsyncTimeout(
            reason_code,
            properties,
            completions.handler(),
            timeout,
        );
    }

    pub fn disconnectQueuedWithDeadline(
        self: *QueuedRun,
        completions: *CompletionQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.disconnectAsyncWithDeadline(
            reason_code,
            properties,
            completions.handler(),
            deadline,
        );
    }

    pub fn acknowledge(
        self: *QueuedRun,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
    ) CommandQueueError!void {
        return self.queue.acknowledge(packet_id, qos, options);
    }

    pub fn acknowledgeAsync(
        self: *QueuedRun,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        completion: command_queue.CompletionHandler,
    ) CommandQueueError!u64 {
        return self.queue.acknowledgeAsync(
            packet_id,
            qos,
            options,
            completion,
        );
    }

    pub fn acknowledgeAsyncTimeout(
        self: *QueuedRun,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        completion: command_queue.CompletionHandler,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.acknowledgeAsyncTimeout(
            packet_id,
            qos,
            options,
            completion,
            timeout,
        );
    }

    pub fn acknowledgeAsyncWithDeadline(
        self: *QueuedRun,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        completion: command_queue.CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.acknowledgeAsyncWithDeadline(
            packet_id,
            qos,
            options,
            completion,
            deadline,
        );
    }

    /// Enqueue an inbound PUBLISH acknowledgement with an awaitable result.
    pub fn acknowledgeQueued(
        self: *QueuedRun,
        completions: *CompletionQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
    ) CommandQueueError!u64 {
        return self.acknowledgeAsync(
            packet_id,
            qos,
            options,
            completions.handler(),
        );
    }

    pub fn acknowledgeQueuedTimeout(
        self: *QueuedRun,
        completions: *CompletionQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.acknowledgeAsyncTimeout(
            packet_id,
            qos,
            options,
            completions.handler(),
            timeout,
        );
    }

    pub fn acknowledgeQueuedWithDeadline(
        self: *QueuedRun,
        completions: *CompletionQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.acknowledgeAsyncWithDeadline(
            packet_id,
            qos,
            options,
            completions.handler(),
            deadline,
        );
    }

    pub fn flushPending(self: *QueuedRun) CommandQueueError!void {
        return self.queue.flushPending();
    }

    pub fn flushPendingAsync(
        self: *QueuedRun,
        completion: command_queue.CompletionHandler,
    ) CommandQueueError!u64 {
        return self.queue.flushPendingAsync(completion);
    }

    pub fn flushPendingAsyncTimeout(
        self: *QueuedRun,
        completion: command_queue.CompletionHandler,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.flushPendingAsyncTimeout(completion, timeout);
    }

    pub fn flushPendingAsyncWithDeadline(
        self: *QueuedRun,
        completion: command_queue.CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.flushPendingAsyncWithDeadline(
            completion,
            deadline,
        );
    }

    pub fn flushPendingQueued(
        self: *QueuedRun,
        completions: *CompletionQueue,
    ) CommandQueueError!u64 {
        return self.flushPendingAsync(completions.handler());
    }

    pub fn flushPendingQueuedTimeout(
        self: *QueuedRun,
        completions: *CompletionQueue,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.flushPendingAsyncTimeout(
            completions.handler(),
            timeout,
        );
    }

    pub fn flushPendingQueuedWithDeadline(
        self: *QueuedRun,
        completions: *CompletionQueue,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.flushPendingAsyncWithDeadline(
            completions.handler(),
            deadline,
        );
    }

    pub fn beginReauthentication(
        self: *QueuedRun,
        properties: []const mqtt.Property,
    ) CommandQueueError!void {
        return self.queue.beginReauthentication(properties);
    }

    pub fn beginReauthenticationAsync(
        self: *QueuedRun,
        properties: []const mqtt.Property,
        completion: command_queue.CompletionHandler,
    ) CommandQueueError!u64 {
        return self.queue.beginReauthenticationAsync(
            properties,
            completion,
        );
    }

    pub fn beginReauthenticationAsyncTimeout(
        self: *QueuedRun,
        properties: []const mqtt.Property,
        completion: command_queue.CompletionHandler,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.beginReauthenticationAsyncTimeout(
            properties,
            completion,
            timeout,
        );
    }

    pub fn beginReauthenticationAsyncWithDeadline(
        self: *QueuedRun,
        properties: []const mqtt.Property,
        completion: command_queue.CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.queue.beginReauthenticationAsyncWithDeadline(
            properties,
            completion,
            deadline,
        );
    }

    pub fn beginReauthenticationQueued(
        self: *QueuedRun,
        completions: *CompletionQueue,
        properties: []const mqtt.Property,
    ) CommandQueueError!u64 {
        return self.beginReauthenticationAsync(
            properties,
            completions.handler(),
        );
    }

    pub fn beginReauthenticationQueuedTimeout(
        self: *QueuedRun,
        completions: *CompletionQueue,
        properties: []const mqtt.Property,
        timeout: std.Io.Duration,
    ) CommandEnqueueTimeoutError!u64 {
        return self.beginReauthenticationAsyncTimeout(
            properties,
            completions.handler(),
            timeout,
        );
    }

    pub fn beginReauthenticationQueuedWithDeadline(
        self: *QueuedRun,
        completions: *CompletionQueue,
        properties: []const mqtt.Property,
        deadline: std.Io.Clock.Timestamp,
    ) CommandEnqueueTimeoutError!u64 {
        return self.beginReauthenticationAsyncWithDeadline(
            properties,
            completions.handler(),
            deadline,
        );
    }

    pub fn stop(self: *QueuedRun) void {
        self.shutdown.set(self.io);
    }

    /// Return whether the managed reconnect worker has exited. A true result
    /// acquire-synchronizes with its final error write, so `wait` and the
    /// bounded wait variants may safely return that result afterward.
    pub fn isFinished(self: *const QueuedRun) bool {
        return self.state.finished.isSet();
    }

    /// Wait until the managed reconnect worker exits, without joining it or
    /// releasing any resources. A null result is a clean shutdown; a non-null
    /// result is the terminal poll or event-handler error. The QueuedRun must
    /// remain alive until every concurrent waiter has returned.
    pub fn wait(self: *QueuedRun) QueuedRunWaitError!?anyerror {
        try self.state.finished.wait(self.io);
        return self.state.result;
    }

    /// Wait for worker termination under one relative awake-clock budget.
    /// Timeout does not stop or join the worker and a later wait may resume.
    pub fn waitTimeout(
        self: *QueuedRun,
        timeout: std.Io.Duration,
    ) QueuedRunWaitTimeoutError!?anyerror {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitWithDeadline(.fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    /// Wait for worker termination without renewing an existing absolute
    /// awake-clock deadline. An expired or incompatible deadline is rejected
    /// before observing or changing worker state.
    pub fn waitWithDeadline(
        self: *QueuedRun,
        deadline: std.Io.Clock.Timestamp,
    ) QueuedRunWaitTimeoutError!?anyerror {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        while (!self.isFinished()) {
            self.state.finished.waitTimeout(
                self.io,
                .{ .deadline = deadline },
            ) catch |err| switch (err) {
                // std.Io.Event permits spurious timeout wakeups. Recheck the
                // absolute budget so one cannot shorten the caller's wait.
                error.Timeout => {
                    if (self.isFinished()) break;
                    if (deadline.durationFromNow(self.io).raw.nanoseconds <= 0) {
                        return error.Timeout;
                    }
                    continue;
                },
                error.Canceled => return error.Canceled,
            };
        }
        return self.state.result;
    }

    /// Join the managed worker and release its command-channel resources. The
    /// reconnect Client and shutdown Event must still be alive at this point.
    /// Deinitialization requests shutdown, so joining an idle worker is safe.
    pub fn deinit(self: *QueuedRun) ?anyerror {
        self.stop();
        switch (self.worker) {
            .thread => |worker| worker.join(),
            .io_task => self.state.io_task.await(self.io),
        }
        const result = self.state.result;
        const allocator = self.queue.allocator;
        allocator.destroy(self.state);
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

pub const ClientEventQueue = event_queue.Queue(ClientEvent);
pub const OwnedClientEvent = ClientEventQueue.OwnedEvent;
pub const ClientEventQueueError = ClientEventQueue.Error;
pub const ClientEventQueueReceiveTimeoutError =
    ClientEventQueue.ReceiveTimeoutError;

const QueuedEventAdapter = struct {
    fn handle(
        queue: *ClientEventQueue,
        client: *Client,
        event: *ClientEvent,
    ) !void {
        queue.send(event.*, client.allocator) catch |err| switch (err) {
            error.EventQueueClosed => if (client.shutdown.isSet())
                return
            else
                return err,
            error.Canceled => return error.Canceled,
        };
        // `serveQueuedUntil` releases its local event after callback return.
        // Replace it with a non-owning variant after transfer.
        event.* = .{ .pingresp = {} };
    }
};

/// Managed reconnect worker paired with its event sink. Closing the sink
/// before joining ensures bounded-queue backpressure cannot deadlock shutdown.
pub const QueuedEventRun = struct {
    commands: QueuedRun,
    events: *ClientEventQueue,

    pub fn stop(self: *QueuedEventRun) void {
        self.commands.stop();
        self.events.close();
    }

    pub fn isFinished(self: *const QueuedEventRun) bool {
        return self.commands.isFinished();
    }

    pub fn wait(self: *QueuedEventRun) QueuedRunWaitError!?anyerror {
        return self.commands.wait();
    }

    pub fn waitTimeout(
        self: *QueuedEventRun,
        timeout: std.Io.Duration,
    ) QueuedRunWaitTimeoutError!?anyerror {
        return self.commands.waitTimeout(timeout);
    }

    pub fn waitWithDeadline(
        self: *QueuedEventRun,
        deadline: std.Io.Clock.Timestamp,
    ) QueuedRunWaitTimeoutError!?anyerror {
        return self.commands.waitWithDeadline(deadline);
    }

    pub fn deinit(self: *QueuedEventRun) ?anyerror {
        self.stop();
        const result = self.commands.deinit();
        self.* = undefined;
        return result;
    }
};

pub const InboundQoS2ReleasePolicy = enum {
    /// Complete incoming QoS 2 immediately when PUBREL arrives.
    automatic,
    /// Surface PUBREL and wait for `Client.completeIncomingQoS2`. PUBREL can
    /// be surfaced again while completion remains pending, so the application
    /// release operation must be idempotent. This lets it establish a durable
    /// boundary before making PUBCOMP visible to the peer.
    deferred,
};

pub const OutboundQoS2ReleasePolicy = enum {
    /// Advance an accepted PUBREC and emit PUBREL in the same poll call.
    automatic,
    /// Advance to `await_pubcomp`, surface PUBREC, and hold PUBREL until
    /// `flushPending`. This lets a single-owner coordinator persist the new
    /// Session state before the control packet becomes visible to the peer.
    deferred,
};

pub const OutboundReplayCapabilityPolicy = enum {
    /// Preserve the accepted Application Message exactly. A peer capability
    /// that shrinks across reconnect makes replay fail closed.
    strict,
    /// Let QoS 1 replay follow the current peer capabilities. Maximum QoS 0
    /// lowers the wire PUBLISH to QoS 0 and completes the stored transaction
    /// after the socket write; Retain Available=false clears RETAIN. QoS 2
    /// remains strict because weakening it would violate its durable boundary.
    adapt_qos1,
};

pub const IncomingQoS2ResumeState = enum {
    await_pubrel,
    release_pending,
};

pub const ClientOptions = struct {
    /// Maximum number of filters retained for fresh-session replay.
    max_subscriptions: usize = 1024,
    /// Leave inbound QoS 1/2 PUBLISH acknowledgements to the application. The
    /// application must acknowledge them through this Client or its queued
    /// handle so the single socket-owner invariant is preserved.
    manual_acknowledgements: bool = false,
    inbound_qos2_release_policy: InboundQoS2ReleasePolicy = .automatic,
    outbound_qos2_release_policy: OutboundQoS2ReleasePolicy = .automatic,
    outbound_replay_capability_policy: OutboundReplayCapabilityPolicy =
        .strict,
    /// Deliver a retransmitted inbound QoS 2 PUBLISH to a manual-acknowledging
    /// application instead of consuming it after re-emitting PUBREC. Durable
    /// bridges use this to compare the complete message against their own
    /// persisted transaction before acknowledging the retry.
    surface_incoming_qos2_retransmissions: bool = false,
    /// Optional notification emitted when an outbound PUBLISH reaches its
    /// protocol delivery boundary: socket completion for QoS 0, PUBACK for
    /// QoS 1, and PUBCOMP (or a negative PUBREC) for QoS 2. An opt-in QoS 1
    /// replay lowered to QoS 0 completes at its replacement socket write but
    /// still reports the caller's original QoS and Packet Identifier. This
    /// observes all sends, including retransmissions restored from durable
    /// Session state.
    publish_delivery: ?PublishDeliveryHandler = null,
};

pub const SubscriptionOptions = ClientOptions;

pub const PublishDelivery = struct {
    packet_id: ?u16,
    qos: mqtt.QoS,
    /// Peer acknowledgement reason, or local Quota Exceeded (0x97) when a
    /// resumed PUBLISH cannot fit the newly negotiated Maximum Packet Size.
    reason_code: u8,
    /// Borrowed from the incoming acknowledgement for this callback only.
    properties: []const mqtt.Property,
};

pub const PublishDeliveryHandler = struct {
    context: *anyopaque,
    /// Runs synchronously on the connection owner. The callback must not wait
    /// for another operation that requires that same owner to make progress.
    complete: *const fn (context: *anyopaque, delivery: PublishDelivery) void,
};

pub const PublishAttempt = struct {
    packet_id: ?u16,
    /// True when a QoS 1/2 write lost its transport after the reconnect
    /// Session had taken ownership. Drive `pollWith*` to reconnect and replay
    /// instead of submitting the Application Message a second time.
    transport_interrupted: bool = false,
};

pub const PublishDeliveryQueue = delivery_queue.Queue(
    PublishDelivery,
    PublishDeliveryHandler,
);
pub const OwnedPublishDelivery = PublishDeliveryQueue.OwnedDelivery;
pub const PublishDeliveryQueueError = PublishDeliveryQueue.Error;
pub const PublishDeliveryQueueReceiveTimeoutError =
    PublishDeliveryQueue.ReceiveTimeoutError;

const OwnedSubscription = owned_subscription.Owned;

/// A synchronous, cancellation-aware reconnecting MQTT client for TCP.
///
/// Methods are single-owner: an application must serialize `connect`,
/// `publish`, acknowledgement reads and `deinit`. Cancellation may be signaled
/// concurrently and interrupts retry backoff; call `connection().shutdown()`
/// as well when an application needs immediate interruption of an already-
/// established blocking read. `requestReconnect` provides a data-race-free
/// bounded-latency alternative when its poll loop is active.
pub const Client = struct {
    const Target = reconnect_target.Target;

    allocator: std.mem.Allocator,
    io: std.Io,
    target: Target,
    options: OwnedConnectOptions,
    policy: ReconnectPolicy,
    retry_schedule: backoff.Schedule,
    shutdown: *std.Io.Event,
    connection_state: ?runtime.Connection = null,
    session_resumed: bool = false,
    outgoing: session.Store,
    outgoing_handle: session.Handle,
    outgoing_open: bool = true,
    // A lost broker Session stays lost if preparing its replacement fails.
    // Retain the old Store for inspection, but never replay or snapshot it.
    outgoing_session_lost: bool = false,
    retention: session_retention.State = .{ .interval = std.math.maxInt(u32) },
    client_options: ClientOptions,
    subscriptions: std.ArrayList(OwnedSubscription) = .empty,
    // A fresh broker Session needs all desired filters restored. Preserve the
    // unconfirmed suffix across transport loss or refusal during recovery.
    subscription_replay_index: ?usize = null,
    keep_alive_deadline: ?std.Io.Timestamp = null,
    ping_response_deadline: ?std.Io.Timestamp = null,
    // At most one applied incoming event whose automatic response/replay
    // failed. Its owned packet must precede reconnect and later wire events.
    pending_event: ?ClientEvent = null,
    tls12_session_ticket: ?tls_stream.Tls12SessionTicket = null,
    tls13_session_ticket: ?tls_stream.Tls13SessionTicket = null,
    last_connect_refusal: ?runtime.OwnedConnAck = null,
    reconnect_requested: std.atomic.Value(bool) = .init(false),

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
        client_options: ClientOptions,
    ) Error!Client {
        return initTarget(
            allocator,
            io,
            .{ .tcp = address },
            options,
            policy,
            shutdown,
            client_options,
        );
    }

    /// Initialize a reconnecting raw MQTT client from a DNS hostname. The
    /// hostname is copied so retry policy never depends on caller storage.
    pub fn initHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
    ) Error!Client {
        return initHostWithOptions(
            allocator,
            io,
            host,
            port,
            options,
            policy,
            shutdown,
            .{},
        );
    }

    pub fn initHostWithOptions(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
        client_options: ClientOptions,
    ) Error!Client {
        const target = try Target.initHost(allocator, host, port);
        return initTarget(
            allocator,
            io,
            target,
            options,
            policy,
            shutdown,
            client_options,
        );
    }

    /// Initialize from a validated cleartext MQTT URI. The canonical URI is
    /// copied into the client and reparsed for every attempt, so retries can
    /// re-resolve DNS while remaining independent of caller-owned storage.
    pub fn initUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
    ) Error!Client {
        return initUriWithOptions(
            allocator,
            io,
            uri_text,
            options,
            policy,
            shutdown,
            .{},
        );
    }

    pub fn initUriWithOptions(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
        client_options: ClientOptions,
    ) Error!Client {
        const target = try Target.initUri(allocator, uri_text);
        return initTarget(
            allocator,
            io,
            target,
            options,
            policy,
            shutdown,
            client_options,
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
        client_options: ClientOptions,
    ) Error!Client {
        return initTarget(
            allocator,
            io,
            .{ .connector = connector },
            options,
            policy,
            shutdown,
            client_options,
        );
    }

    fn initTarget(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: runtime.ConnectOptions,
        policy: ReconnectPolicy,
        shutdown: *std.Io.Event,
        client_options: ClientOptions,
    ) Error!Client {
        var owned_target = target;
        errdefer owned_target.deinit(allocator);
        try policy.validate();
        if (client_options.inbound_qos2_release_policy == .deferred and
            !client_options.manual_acknowledgements)
        {
            return error.ManualAcknowledgementsDisabled;
        }
        if (client_options.surface_incoming_qos2_retransmissions and
            (!client_options.manual_acknowledgements or
                client_options.inbound_qos2_release_policy != .deferred))
        {
            return error.ManualAcknowledgementsDisabled;
        }
        if (options.client_id.len == 0 and options.protocol != .v5) return error.InvalidClientId;
        var owned_options = try OwnedConnectOptions.init(allocator, options);
        errdefer owned_options.deinit(allocator);
        var outgoing = try session_identity.FreshSession.init(allocator, owned_options.value.client_id, .zero);
        errdefer outgoing.deinit();
        return .{
            .allocator = allocator,
            .io = io,
            .target = owned_target,
            .options = owned_options,
            .policy = policy,
            .retry_schedule = .init(policy),
            .shutdown = shutdown,
            .client_options = client_options,
            .outgoing = outgoing.store,
            .outgoing_handle = outgoing.handle,
            .retention = session_retention.State.configured(options.protocol, options.clean_start, options.properties),
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.connection_state) |*active| active.close();
        if (self.pending_event) |*value| value.deinit(self.allocator);
        self.clearLastConnectRefusal();
        if (self.tls12_session_ticket) |*ticket| ticket.deinit();
        if (self.tls13_session_ticket) |*ticket| ticket.deinit();
        for (self.subscriptions.items) |*subscription| {
            subscription.deinit(self.allocator);
        }
        self.subscriptions.deinit(self.allocator);
        self.outgoing.deinit();
        self.options.deinit(self.allocator);
        self.target.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn connection(self: *Client) ?*runtime.Connection {
        return if (self.connection_state) |*active| active else null;
    }

    /// Effective identity retained across transports. An empty MQTT 5 identity
    /// becomes the server-assigned Client ID after the first accepted CONNACK
    /// or after restoring a snapshot into an unassigned client. The returned
    /// slice is borrowed until identity assignment, restore, or deinit.
    pub fn clientId(self: *const Client) []const u8 {
        return self.options.value.client_id;
    }

    /// Effective Session lifetime from the latest successful CONNECT/CONNACK
    /// or DISCONNECT. Requested CONNECT options remain unchanged for retries.
    pub fn sessionExpiryInterval(self: *const Client) u32 {
        return self.retention.interval;
    }

    /// True only while the active connection resumed the previous Session at
    /// both endpoints. Durable stores may import peer QoS 2 markers then.
    pub fn sessionResumed(self: *const Client) bool {
        return self.connection_state != null and self.session_resumed;
    }

    /// Borrow the most recent failed CONNACK. The view remains valid until
    /// the next connect attempt, explicit adaptation/take, or deinitialization.
    pub fn lastConnectRefusal(self: *const Client) ?mqtt.ConnAck {
        const owned = self.last_connect_refusal orelse return null;
        return owned.connack;
    }

    /// Transfer ownership of the most recent failed CONNACK to the caller,
    /// which must deinitialize it with the allocator used to create this Client.
    pub fn takeLastConnectRefusal(self: *Client) ?runtime.OwnedConnAck {
        const owned = self.last_connect_refusal orelse return null;
        self.last_connect_refusal = null;
        return owned;
    }

    /// Explicitly lower the owned CONNECT Will to capabilities advertised by
    /// a QoS/Retain refusal. Returns true only when one field changed; callers
    /// may then retry without risking an unbounded refusal loop.
    pub fn adaptWillToLastConnectRefusal(self: *Client) bool {
        const refusal = self.last_connect_refusal orelse return false;
        const will = if (self.options.will) |*value| value else return false;
        const changed = switch (refusal.connack.reason_code) {
            0x9b => blk: {
                const maximum = mqtt.maximumQoS(
                    refusal.connack.properties,
                ) orelse break :blk false;
                if (@intFromEnum(will.qos) <= @intFromEnum(maximum)) {
                    break :blk false;
                }
                will.qos = maximum;
                break :blk true;
            },
            0x9a => blk: {
                const available = mqtt.retainAvailable(
                    refusal.connack.properties,
                ) orelse break :blk false;
                if (available or !will.retain) break :blk false;
                will.retain = false;
                break :blk true;
            },
            else => false,
        };
        if (!changed) return false;
        self.options.value.will = will.view();
        self.clearLastConnectRefusal();
        return true;
    }

    /// Explicitly downgrade an owned MQTT 5 CONNECT after an Unsupported
    /// Protocol Version refusal. MQTT 5 CONNECT and Will properties cannot be
    /// represented by legacy protocols: CONNECT properties are discarded,
    /// while a non-empty Will property list or an unassigned identity fails
    /// closed. Returns false for
    /// unrelated refusals or when this Client is no longer configured for v5.
    pub fn adaptProtocolToLastConnectRefusal(
        self: *Client,
        fallback: mqtt.ProtocolVersion,
        bridge_mode: bool,
    ) Error!bool {
        if (fallback == .v5) return error.InvalidProperty;
        const refusal = self.last_connect_refusal orelse return false;
        if (self.options.value.protocol != .v5 or
            refusal.connack.reason_code != 0x84)
        {
            return false;
        }
        if (self.options.will) |will| {
            if (will.properties.len != 0) return error.InvalidProperty;
        }
        if (self.options.value.client_id.len == 0) return error.InvalidClientId;
        self.options.value.protocol = fallback;
        self.options.value.bridge_mode = bridge_mode;
        self.options.value.v3_1_connack_mode = if (fallback == .v3_1 and bridge_mode)
            .mosquitto
        else
            .strict;
        self.options.value.properties = &.{};
        self.retention = session_retention.State.configured(fallback, self.options.value.clean_start, &.{});
        self.clearLastConnectRefusal();
        return true;
    }

    /// Ask the single-owner poll loop to retire its current transport and
    /// reconnect. This method is thread-safe; the request is observed within
    /// `PollOptions.cancellation_check_interval` while a read is blocked.
    pub fn requestReconnect(self: *Client) void {
        self.reconnect_requested.store(true, .release);
    }

    /// Connect immediately unless policy retained a post-disconnect delay,
    /// then retry failures after the configured delay. The initial failure
    /// count is one, so `delay(1)` is the first failed-attempt sleep.
    /// Protocol-level CONNACK refusal is terminal; retrying credentials or an
    /// administratively rejected Client Identifier would only hide the cause.
    pub fn connect(self: *Client) (Error || std.Io.Cancelable)!ConnectEvent {
        return self.connectUntil(null);
    }

    pub fn connectWithDeadline(
        self: *Client,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || std.Io.Cancelable)!ConnectEvent {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        return self.connectUntil(deadline);
    }

    pub fn connectWithTimeout(
        self: *Client,
        timeout: std.Io.Duration,
    ) (Error || std.Io.Cancelable)!ConnectEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn connectUntil(
        self: *Client,
        deadline: ?std.Io.Clock.Timestamp,
    ) (Error || std.Io.Cancelable)!ConnectEvent {
        if (self.connection_state != null) return error.InvalidProperty;
        self.clearLastConnectRefusal();
        var failed_attempts: usize = 0;
        while (true) {
            if (self.shutdown.isSet()) return error.Canceled;
            if (deadline) |absolute| {
                if (absolute.durationFromNow(self.io).raw.nanoseconds <= 0) {
                    return error.Timeout;
                }
            }
            try self.waitForScheduledAttempt(deadline);

            const tls_tickets = self.usableTlsSessionTickets();
            const expired_before_attempt = self.retention.expired(std.Io.Clock.awake.now(self.io));
            var attempt = self.connectAttemptBefore(
                deadline,
                tls_tickets,
            ) catch |err| {
                if (err == error.Timeout) return err;
                if (!retryableConnectError(err)) return err;
                failed_attempts += 1;
                if (self.policy.max_attempts != 0 and
                    failed_attempts >= self.policy.max_attempts)
                {
                    self.retry_schedule.clearScheduled();
                    return error.ConnectionUnavailable;
                }
                _ = self.retry_schedule.scheduleFailure(
                    self.policy,
                    failed_attempts,
                    std.Io.Clock.awake.now(self.io),
                    self.retrySample(),
                );
                continue;
            };
            if (!attempt.accepted()) {
                self.rememberTls12SessionTicket(&attempt);
                self.rememberTls13SessionTicket(
                    &attempt,
                    tls_tickets.tls13 != null,
                ) catch |err| {
                    attempt.deinit(self.allocator);
                    return err;
                };
                std.debug.assert(attempt.connection == null);
                self.last_connect_refusal = attempt.connack;
                attempt.connack = undefined;
                return error.ConnectRefused;
            }
            var result = try attempt.requireAccepted();
            const identity_assigned = self.options.value.client_id.len == 0;
            const session_present = result.connack.connack.session_present;
            // Record known Session loss before ticket, identity or Store
            // allocation can fail. A later preserved Session cannot revive
            // the Packet Identifiers belonging to the lost one.
            if ((!session_present or expired_before_attempt) and !identity_assigned) {
                self.subscription_replay_index = 0;
                self.outgoing_session_lost = true;
            }
            if (identity_assigned) {
                session_identity.adopt(self, result.connection.assignedClientId() orelse {
                    result.deinit(self.allocator);
                    return error.InvalidProperty;
                }) catch |err| {
                    result.deinit(self.allocator);
                    return err;
                };
            }
            self.retention.connected(result.connection.sessionExpiryInterval());
            errdefer if (self.connection_state == null and self.retention.expires_at == null) {
                self.retention.disconnected(std.Io.Clock.awake.now(self.io));
            };
            self.rememberTls12SessionTicketFromConnection(&result.connection);
            self.rememberTls13SessionTicketFromConnection(
                &result.connection,
                tls_tickets.tls13 != null,
            ) catch |err| {
                result.deinit(self.allocator);
                return err;
            };
            result.connack.deinit(self.allocator);
            self.connection_state = result.connection;
            self.connection_state.?.resetPacketIdentifiers();
            self.session_resumed = session_present and !identity_assigned and !self.outgoing_session_lost;

            if (self.outgoing_session_lost) {
                self.resetOutgoingState() catch |err| {
                    if (self.connection_state) |*active| active.close();
                    self.connection_state = null;
                    self.session_resumed = false;
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
                    self.session_resumed = false;
                    return err;
                };
                self.outgoing_handle = reopened.handle;
                self.outgoing_open = true;
            }
            const ownership = self.outgoing.packetIdentifierOwnership(self.outgoing_handle) catch |err| {
                self.disconnectTransport();
                return err;
            };
            self.connection_state.?.setOutgoingPacketIdentifierOwner(ownership) catch |err| {
                self.disconnectTransport();
                return err;
            };
            self.replayPendingUntil(deadline) catch |err| {
                // The CONNECT succeeded but replay did not. Preserve every
                // durable packet and report the transport failure rather than
                // claiming a usable connection.
                self.disconnectTransport();
                return err;
            };
            if (self.subscription_replay_index != null) {
                self.replaySubscriptions(deadline) catch |err| {
                    self.disconnectTransport();
                    return err;
                };
            }
            self.noteControlSent();
            self.ping_response_deadline = null;
            self.retry_schedule.noteConnected(
                std.Io.Clock.awake.now(self.io),
            );
            return .{
                .session_present = session_present,
                .session_resumed = self.session_resumed,
                .failed_attempts = failed_attempts,
            };
        }
    }

    fn clearLastConnectRefusal(self: *Client) void {
        if (self.last_connect_refusal) |*refusal| {
            refusal.deinit(self.allocator);
            self.last_connect_refusal = null;
        }
    }

    fn connectAttemptBefore(
        self: *Client,
        deadline: ?std.Io.Clock.Timestamp,
        tickets: runtime.ClientTlsSessionTickets,
    ) runtime.Error!runtime.ConnectAttempt {
        return if (deadline) |absolute|
            self.target.connectAttemptWithDeadline(
                self.allocator,
                self.io,
                self.options.value,
                tickets,
                absolute,
            )
        else
            self.target.connectAttempt(
                self.allocator,
                self.io,
                self.options.value,
                tickets,
            );
    }

    fn usableTlsSessionTickets(
        self: *Client,
    ) runtime.ClientTlsSessionTickets {
        return .{
            .tls12 = self.usableTls12SessionTicket(),
            .tls13 = self.usableTls13SessionTicket(),
        };
    }

    fn usableTls12SessionTicket(
        self: *Client,
    ) ?*const tls_stream.Tls12SessionTicket {
        const ticket = if (self.tls12_session_ticket) |*cached|
            cached
        else
            return null;
        const now_seconds: u64 = @intCast(@max(
            0,
            std.Io.Timestamp.now(self.io, .real).toSeconds(),
        ));
        if (now_seconds < ticket.session.created_at_seconds or
            now_seconds - ticket.session.created_at_seconds >=
                ticket.session.lifetime_seconds)
        {
            ticket.deinit();
            self.tls12_session_ticket = null;
            return null;
        }
        return ticket;
    }

    fn usableTls13SessionTicket(
        self: *Client,
    ) ?*const tls_stream.Tls13SessionTicket {
        const ticket = if (self.tls13_session_ticket) |*cached|
            cached
        else
            return null;
        const now_ms: u64 = @intCast(@max(
            0,
            std.Io.Timestamp.now(self.io, .real).toMilliseconds(),
        ));
        _ = ticket.obfuscatedTicketAge(now_ms) catch {
            ticket.deinit();
            self.tls13_session_ticket = null;
            return null;
        };
        return ticket;
    }

    fn rememberTls12SessionTicket(
        self: *Client,
        attempt: *runtime.ConnectAttempt,
    ) void {
        const active_connection = if (attempt.connection) |*active|
            active
        else
            return;
        self.rememberTls12SessionTicketFromConnection(active_connection);
    }

    fn rememberTls12SessionTicketFromConnection(
        self: *Client,
        active_connection: *runtime.Connection,
    ) void {
        if (active_connection.takeTls12SessionTicket()) |ticket| {
            if (self.tls12_session_ticket) |*cached| cached.deinit();
            self.tls12_session_ticket = ticket;
            return;
        }
        if (active_connection.negotiatedTlsProtocol() == .tls12 and
            !(active_connection.wasTlsSessionResumed() orelse false))
        {
            if (self.tls12_session_ticket) |*cached| cached.deinit();
            self.tls12_session_ticket = null;
        }
    }

    fn rememberTls13SessionTicket(
        self: *Client,
        attempt: *runtime.ConnectAttempt,
        offered_ticket: bool,
    ) runtime.Error!void {
        const active_connection = if (attempt.connection) |*active|
            active
        else
            return;
        try self.rememberTls13SessionTicketFromConnection(
            active_connection,
            offered_ticket,
        );
    }

    fn rememberTls13SessionTicketFromConnection(
        self: *Client,
        active_connection: *runtime.Connection,
        offered_ticket: bool,
    ) runtime.Error!void {
        if (try active_connection.takeTls13SessionTicket()) |ticket| {
            if (self.tls13_session_ticket) |*cached| cached.deinit();
            self.tls13_session_ticket = ticket;
            return;
        }
        if (offered_ticket and
            active_connection.negotiatedTlsProtocol() == .tls13 and
            !(active_connection.wasTlsSessionResumed() orelse false))
        {
            if (self.tls13_session_ticket) |*cached| cached.deinit();
            self.tls13_session_ticket = null;
        }
    }

    /// Close only the current transport. Durable outgoing QoS state remains
    /// owned by this client and is marked for retransmission on the next
    /// successful connection.
    pub fn disconnectTransport(self: *Client) void {
        if (self.connection_state) |*active| {
            self.retention.interval = active.sessionExpiryInterval();
            self.retention.disconnected(std.Io.Clock.awake.now(self.io));
            self.rememberTls13SessionTicketFromConnection(
                active,
                false,
            ) catch {
                if (self.tls13_session_ticket) |*ticket| ticket.deinit();
                self.tls13_session_ticket = null;
            };
            self.retry_schedule.noteDisconnected(
                self.policy,
                std.Io.Clock.awake.now(self.io),
                self.retrySample(),
            );
            active.close();
        }
        self.connection_state = null;
        self.session_resumed = false;
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

    /// Clear any delay scheduled for the next connection attempt while
    /// retaining the decorrelated-jitter history. Lifecycle policies such as
    /// a lazy bridge use this after an intentional idle disconnect.
    pub fn clearScheduledReconnectDelay(self: *Client) void {
        self.retry_schedule.clearScheduled();
    }

    /// Send a graceful MQTT DISCONNECT and retire only the Network
    /// Connection. Outgoing QoS state remains available until acknowledgements
    /// complete or a future CONNACK reports that the Session no longer exists.
    pub fn disconnect(self: *Client, reason_code: u8) Error!void {
        return self.disconnectWithProperties(reason_code, &.{});
    }

    /// Send a graceful MQTT 5 DISCONNECT with packet properties. MQTT 3.1.1
    /// accepts only reason code zero and an empty property slice.
    pub fn disconnectWithProperties(
        self: *Client,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) Error!void {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        active.writeDisconnectWithProperties(reason_code, properties) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
        self.noteControlSent();
        if (mqtt.sessionExpiryInterval(properties)) |interval| self.retention.interval = interval;
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

    /// Discard outgoing PUBLISH entries whose Message Expiry Interval has
    /// elapsed, including one currently awaiting an acknowledgement.
    /// Returns true when at least one transmission was released.
    pub fn pruneExpiredOutgoing(
        self: *Client,
        now: std.Io.Timestamp,
    ) Error!bool {
        return self.outgoing.pruneExpiredOutgoing(
            self.outgoing_handle,
            now,
        );
    }

    pub fn outgoingQoSState(
        self: *Client,
        packet_id: u16,
    ) Error!?session.OutgoingQoSState {
        return self.outgoing.outgoingQoSState(
            self.outgoing_handle,
            packet_id,
        );
    }

    pub fn incomingQoS2State(
        self: *Client,
        packet_id: u16,
    ) Error!?session.IncomingQoS2State {
        return self.outgoing.incomingQoS2State(
            self.outgoing_handle,
            packet_id,
        );
    }

    /// Append an identity-bound snapshot of this client's durable MQTT Session
    /// state, desired subscriptions and partial subscription recovery progress.
    /// The client is single-owner, so an online caller can stage state,
    /// append it to a larger durable record, and only then select network work.
    /// This in-memory form keeps atomic composition with higher-level
    /// coordinator state under caller control; `saveSessionSnapshotFile` owns
    /// crash-safe standalone replacement. Restoration stays offline-only.
    pub fn writeSessionSnapshot(
        self: *Client,
        out: *std.ArrayList(u8),
    ) SessionSnapshotError!void {
        return self.writeSessionSnapshotAt(
            out,
            std.Io.Clock.awake.now(self.io),
            std.Io.Clock.real.now(self.io),
        );
    }

    pub fn writeSessionSnapshotAt(
        self: *Client,
        out: *std.ArrayList(u8),
        monotonic_now: std.Io.Timestamp,
        realtime_now: std.Io.Timestamp,
    ) SessionSnapshotError!void {
        if (self.pending_event != null) return error.SnapshotBusy;
        if (self.options.value.clean_start or
            (!configuredPersistentSession(self.options.value) and self.retention.interval == 0))
        {
            return error.SessionPersistenceDisabled;
        }
        if (self.options.value.client_id.len == 0) return error.InvalidClientId;
        if (self.outgoing_session_lost) return error.SessionLost;
        var fresh: ?session_identity.FreshSession = null;
        defer if (fresh) |*value| value.deinit();
        const lifetime = self.retention.view(monotonic_now);
        if (lifetime.remaining_ns == 0) fresh = try session_identity.FreshSession.init(self.allocator, self.clientId(), monotonic_now);
        return session_snapshot.encodeWithRetention(
            if (fresh) |*value| &value.store else &self.outgoing,
            if (fresh) |value| value.handle else self.outgoing_handle,
            self.options.value.protocol,
            self.options.value.client_id,
            out,
            self.allocator,
            monotonic_now,
            realtime_now,
            .{ .values = self.subscriptions.items, .replay_index = self.subscription_replay_index },
            lifetime,
        );
    }

    /// Atomically persist one identity-bound reconnect Session snapshot. The
    /// file and containing directory are synced before success is returned.
    pub fn saveSessionSnapshotFile(
        self: *Client,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) SessionSnapshotFileError!void {
        return self.saveSessionSnapshotFileAt(
            dir,
            sub_path,
            std.Io.Clock.awake.now(self.io),
            std.Io.Clock.real.now(self.io),
        );
    }

    pub fn saveSessionSnapshotFileAt(
        self: *Client,
        dir: std.Io.Dir,
        sub_path: []const u8,
        monotonic_now: std.Io.Timestamp,
        realtime_now: std.Io.Timestamp,
    ) SessionSnapshotFileError!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try self.writeSessionSnapshotAt(
            &encoded,
            monotonic_now,
            realtime_now,
        );
        try session_snapshot.saveAtomic(
            self.io,
            dir,
            sub_path,
            encoded.items,
        );
    }

    /// Transactionally replace an empty offline reconnect Session from a
    /// snapshot written by `writeSessionSnapshot`. Protocol and Client ID are
    /// validated by the envelope before the temporary Store is swapped in.
    /// Saved subscriptions merge with compatible caller-seeded filters within
    /// the configured limit; conflicting options or properties reject restore.
    /// Version-one snapshots preserve the caller's desired subscriptions.
    /// Version three deducts offline Session expiry before restoring either
    /// QoS direction; desired subscriptions remain available after expiry.
    /// An unassigned MQTT 5 client also adopts the validated saved identity;
    /// a client with an explicit identity requires an exact match.
    /// The next successful CONNACK must report Session Present before any
    /// restored Packet Identifier can be replayed; a fresh Session discards it
    /// through the existing reconnect path.
    pub fn restoreSessionSnapshot(
        self: *Client,
        bytes: []const u8,
    ) SessionSnapshotError!void {
        return self.restoreSessionSnapshotAt(
            bytes,
            std.Io.Clock.awake.now(self.io),
            std.Io.Clock.real.now(self.io),
        );
    }

    pub fn restoreSessionSnapshotAt(
        self: *Client,
        bytes: []const u8,
        monotonic_now: std.Io.Timestamp,
        realtime_now: std.Io.Timestamp,
    ) SessionSnapshotError!void {
        try self.validateSessionSnapshotRestore();
        var restored = if (self.options.value.client_id.len == 0)
            try session_snapshot.decodeAssignedClient(
                self.allocator,
                bytes,
                session_identity.options(),
                monotonic_now,
                realtime_now,
                self.client_options.max_subscriptions,
            )
        else
            try session_snapshot.decodeWithSubscriptionLimit(
                self.allocator,
                bytes,
                session_identity.options(),
                self.options.value.protocol,
                self.options.value.client_id,
                monotonic_now,
                realtime_now,
                self.client_options.max_subscriptions,
            );
        defer restored.deinit();
        if (!configuredPersistentSession(self.options.value) and restored.retention_state == null) return error.SessionPersistenceDisabled;
        if (restored.has_subscription_state) {
            try restored.subscription_state.merge(self.allocator, self.subscriptions.items, self.options.value.protocol, self.client_options.max_subscriptions);
        }
        const assigned_id = if (self.options.value.client_id.len == 0)
            try session_identity.clone(self.allocator, try restored.store.clientId(restored.handle))
        else
            null;
        self.outgoing.swap(&restored.store);
        self.outgoing_handle = restored.handle;
        self.outgoing_open = false;
        self.outgoing_session_lost = false;
        if (restored.retention_state) |value| self.retention = value;
        if (assigned_id) |value| session_identity.install(self, value);
        if (restored.has_subscription_state) {
            std.mem.swap(std.ArrayList(OwnedSubscription), &self.subscriptions, &restored.subscription_state.values);
            self.subscription_replay_index = restored.subscription_state.replay_index;
        }
    }

    fn validateSessionSnapshotRestore(
        self: *Client,
    ) SessionSnapshotError!void {
        if (self.connection_state != null or self.pending_event != null) return error.SnapshotBusy;
        if (self.options.value.clean_start) {
            return error.SessionPersistenceDisabled;
        }
        const current = try self.outgoing.stats(self.outgoing_handle);
        if (current.subscription_count != 0 or current.queued_count != 0 or
            current.inflight_count != 0 or current.incoming_qos2_count != 0)
        {
            return error.SessionStateNotEmpty;
        }
    }

    /// Bounded, transactionally decoded counterpart to
    /// `saveSessionSnapshotFile`. The existing Session is unchanged on any
    /// read, checksum, identity, protocol, limit, or decode failure.
    pub fn restoreSessionSnapshotFile(
        self: *Client,
        dir: std.Io.Dir,
        sub_path: []const u8,
    ) SessionSnapshotFileError!void {
        return self.restoreSessionSnapshotFileAt(
            dir,
            sub_path,
            std.Io.Clock.awake.now(self.io),
            std.Io.Clock.real.now(self.io),
        );
    }

    pub fn restoreSessionSnapshotFileAt(
        self: *Client,
        dir: std.Io.Dir,
        sub_path: []const u8,
        monotonic_now: std.Io.Timestamp,
        realtime_now: std.Io.Timestamp,
    ) SessionSnapshotFileError!void {
        try self.validateSessionSnapshotRestore();
        const encoded = try session_snapshot.loadAlloc(
            self.allocator,
            self.io,
            dir,
            sub_path,
        );
        defer self.allocator.free(encoded);
        try self.restoreSessionSnapshotAt(
            encoded,
            monotonic_now,
            realtime_now,
        );
    }

    pub fn subscriptionCount(self: *const Client) usize {
        return self.subscriptions.items.len;
    }

    /// Return whether an accepted subscription is retained for reconnect
    /// replay. The filter is borrowed only for this lookup.
    pub fn hasSubscription(
        self: *const Client,
        filter: []const u8,
    ) bool {
        return self.subscriptionIndex(filter) != null;
    }

    /// Seed application-owned desired subscription state before CONNECT. A
    /// fresh broker Session receives the subscription through normal reconnect
    /// replay; Session Present=1 leaves the retained remote subscription
    /// untouched and emits no redundant SUBSCRIBE after recovery completed.
    /// If recovery is pending, newly added filters join its unconfirmed suffix.
    pub fn seedSubscription(
        self: *Client,
        subscription: mqtt.Subscription,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.connection_state != null) return error.ConnectionBusy;
        var validation_buffer: std.ArrayList(u8) = .empty;
        defer validation_buffer.deinit(self.allocator);
        try mqtt.Subscribe.write(
            &validation_buffer,
            self.allocator,
            self.options.value.protocol,
            1,
            properties,
            &.{subscription},
        );
        if (self.subscriptionIndex(subscription.topic_filter) != null) return;
        if (self.subscriptions.items.len >=
            self.client_options.max_subscriptions)
        {
            return error.SubscriptionLimitExceeded;
        }
        var owned = try cloneSubscription(
            self.allocator,
            subscription,
            properties,
        );
        errdefer owned.deinit(self.allocator);
        try self.subscriptions.append(self.allocator, owned);
    }

    /// Stage the receive-side marker for one QoS 2 PUBLISH without emitting
    /// PUBREC. A coordinator can now snapshot this source Session together
    /// with a staged target PUBLISH before calling `acknowledge`.
    pub fn stageIncomingQoS2(self: *Client, packet_id: u16) Error!void {
        if (!self.client_options.manual_acknowledgements or
            self.client_options.inbound_qos2_release_policy != .deferred)
        {
            return error.ManualAcknowledgementsDisabled;
        }
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        if (!active.hasPendingIncomingPublish(packet_id, .exactly_once)) {
            return error.UnexpectedPacket;
        }
        if (try self.outgoing.stageIncomingQoS2(
            self.outgoing_handle,
            packet_id,
        )) {
            return error.InvalidAcknowledgement;
        }
    }

    /// Roll back a staged receive marker while no PUBREC write has begun.
    pub fn discardStagedIncomingQoS2(
        self: *Client,
        packet_id: u16,
    ) Error!void {
        if (!self.client_options.manual_acknowledgements or
            self.client_options.inbound_qos2_release_policy != .deferred)
        {
            return error.ManualAcknowledgementsDisabled;
        }
        return self.outgoing.discardStagedIncomingQoS2(
            self.outgoing_handle,
            packet_id,
        );
    }

    /// Emit PUBREC for an already-staged durable inbound QoS 2 transaction.
    /// This also supports restoration before the broker retransmits PUBLISH:
    /// the persisted marker proves the peer transaction. Negative PUBREC
    /// removes the marker after the write succeeds.
    pub fn flushStagedIncomingQoS2(
        self: *Client,
        packet_id: u16,
        options: runtime.AcknowledgeOptions,
    ) Error!void {
        if (!self.client_options.manual_acknowledgements or
            self.client_options.inbound_qos2_release_policy != .deferred)
        {
            return error.ManualAcknowledgementsDisabled;
        }
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        const state = try self.outgoing.incomingQoS2State(
            self.outgoing_handle,
            packet_id,
        ) orelse return error.UnexpectedPacket;
        if (state != .await_pubrel) return error.UnexpectedPacket;
        var validated_ack: std.ArrayList(u8) = .empty;
        defer validated_ack.deinit(self.allocator);
        try mqtt.AckPacket.write(
            &validated_ack,
            self.allocator,
            active.protocol,
            .pubrec,
            packet_id,
            options.reason_code,
            options.properties,
        );
        if (validated_ack.items.len > active.peerMaximumPacketSize()) {
            return error.OutgoingPacketTooLarge;
        }
        try self.outgoing.markIncomingQoS2PubRecStarted(
            self.outgoing_handle,
            packet_id,
        );
        try active.resumeIncomingQoS2(packet_id);
        active.writePubRecWithProperties(
            packet_id,
            options.reason_code,
            options.properties,
        ) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
        if (options.reason_code >= 0x80) {
            try self.outgoing.completeIncomingQoS2(
                self.outgoing_handle,
                packet_id,
            );
        }
        self.noteControlSent();
    }

    /// Acknowledge one inbound PUBLISH when manual acknowledgements are
    /// enabled. QoS 0 requires no wire response. QoS 1 emits PUBACK and QoS 2
    /// durably records the transaction before emitting PUBREC.
    pub fn acknowledge(
        self: *Client,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
    ) Error!void {
        if (qos == .at_most_once) return;
        if (!self.client_options.manual_acknowledgements) {
            return error.ManualAcknowledgementsDisabled;
        }
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        switch (qos) {
            .at_most_once => unreachable,
            .at_least_once => {
                if (!active.hasPendingIncomingPublish(packet_id, qos)) {
                    return error.UnexpectedPacket;
                }
                active.writePubAckWithProperties(
                    packet_id,
                    options.reason_code,
                    options.properties,
                ) catch |err| {
                    self.retireConnectionAfterOperationError(err);
                    return err;
                };
            },
            .exactly_once => {
                if (!active.hasPendingIncomingPublish(packet_id, qos)) {
                    return error.UnexpectedPacket;
                }
                const staged_pubrec_visibility = try self.outgoing
                    .incomingQoS2PubRecMayBeVisible(
                    self.outgoing_handle,
                    packet_id,
                );
                // Validate and size the complete ACK before making the Session
                // marker visible. Errors here are provably pre-wire, so a
                // corrected acknowledgement can retry on this transport. The
                // runtime writer still has its own scratch allocation; failure
                // there is conservatively treated like ambiguous output below.
                var validated_ack: std.ArrayList(u8) = .empty;
                defer validated_ack.deinit(self.allocator);
                try mqtt.AckPacket.write(
                    &validated_ack,
                    self.allocator,
                    active.protocol,
                    .pubrec,
                    packet_id,
                    options.reason_code,
                    options.properties,
                );
                if (validated_ack.items.len > active.peerMaximumPacketSize()) {
                    return error.OutgoingPacketTooLarge;
                }
                var recorded = false;
                if (options.reason_code < 0x80) {
                    const duplicate = try self.outgoing.recordIncomingQoS2(
                        self.outgoing_handle,
                        packet_id,
                    );
                    if (duplicate and
                        staged_pubrec_visibility.? and
                        !self.client_options
                            .surface_incoming_qos2_retransmissions)
                    {
                        return error.UnexpectedPacket;
                    }
                    recorded = true;
                    try self.outgoing.markIncomingQoS2PubRecStarted(
                        self.outgoing_handle,
                        packet_id,
                    );
                }
                active.writePubRecWithProperties(
                    packet_id,
                    options.reason_code,
                    options.properties,
                ) catch |err| {
                    // Automatic release historically rolls this marker back.
                    // Deferred release must retain it because a partial PUBREC
                    // write can make PUBREL the peer's next legal packet; its
                    // application-owned release boundary needs the stored
                    // transaction to survive that ambiguous wire outcome.
                    if (recorded and
                        self.client_options.inbound_qos2_release_policy ==
                            .automatic)
                    {
                        self.outgoing.completeIncomingQoS2(
                            self.outgoing_handle,
                            packet_id,
                        ) catch unreachable;
                    }
                    self.retireConnectionAfterOperationError(err);
                    return err;
                };
                if (options.reason_code >= 0x80 and
                    staged_pubrec_visibility != null)
                {
                    try self.outgoing.completeIncomingQoS2(
                        self.outgoing_handle,
                        packet_id,
                    );
                }
            },
        }
        self.noteControlSent();
    }

    /// Recreate the protocol marker for an inbound QoS 2 transaction restored
    /// by an application-owned durable store. Call this only while
    /// `sessionResumed()` is true; local expiry or a fresh Session returns
    /// SessionLost even if the peer reports Session Present. Repeating the
    /// call is idempotent.
    pub fn restoreIncomingQoS2(
        self: *Client,
        packet_id: u16,
        state: IncomingQoS2ResumeState,
    ) Error!void {
        if (!self.client_options.manual_acknowledgements or
            self.client_options.inbound_qos2_release_policy != .deferred)
        {
            return error.ManualAcknowledgementsDisabled;
        }
        if (self.connection_state == null) {
            return error.ConnectionUnavailable;
        }
        if (!self.sessionResumed()) return error.SessionLost;
        _ = try self.outgoing.recordIncomingQoS2(
            self.outgoing_handle,
            packet_id,
        );
        if (state == .release_pending) {
            try self.outgoing.markIncomingQoS2ReleasePending(
                self.outgoing_handle,
                packet_id,
            );
        }
    }

    /// Complete a deferred inbound QoS 2 release and emit PUBCOMP.
    ///
    /// The Session marker is retained until the complete PUBCOMP write
    /// succeeds. A transport failure therefore leaves the transaction
    /// recoverable after Session-Present reconnect and immediately retires the
    /// unusable current transport before returning the write error.
    pub fn completeIncomingQoS2(
        self: *Client,
        packet_id: u16,
        options: runtime.AcknowledgeOptions,
    ) Error!void {
        if (!self.client_options.manual_acknowledgements) {
            return error.ManualAcknowledgementsDisabled;
        }
        if (self.client_options.inbound_qos2_release_policy != .deferred) {
            return error.UnexpectedPacket;
        }
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        // Keep protocol/property/packet-size failures before receive-state
        // mutation. The runtime writer still allocates its retained scratch;
        // any later failure keeps the Session marker because output may be
        // ambiguous and a Session-Present reconnect can safely retry.
        var validated_ack: std.ArrayList(u8) = .empty;
        defer validated_ack.deinit(self.allocator);
        try mqtt.AckPacket.write(
            &validated_ack,
            self.allocator,
            active.protocol,
            .pubcomp,
            packet_id,
            options.reason_code,
            options.properties,
        );
        if (validated_ack.items.len > active.peerMaximumPacketSize()) {
            return error.OutgoingPacketTooLarge;
        }
        const state = try self.outgoing.incomingQoS2State(
            self.outgoing_handle,
            packet_id,
        ) orelse return error.UnexpectedPacket;
        if (state != .release_pending) return error.UnexpectedPacket;
        try active.resumeIncomingQoS2(packet_id);
        active.writePubCompWithProperties(
            packet_id,
            options.reason_code,
            options.properties,
        ) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
        self.outgoing.completeIncomingQoS2(
            self.outgoing_handle,
            packet_id,
        ) catch unreachable;
        self.noteControlSent();
    }

    /// Remove a release-pending marker before an enclosing durable commit.
    /// No transport state or bytes change; `writeStagedIncomingQoS2Completion`
    /// performs the post-commit PUBCOMP and the discard method rolls back a
    /// failed commit.
    pub fn stageIncomingQoS2Completion(
        self: *Client,
        packet_id: u16,
        options: runtime.AcknowledgeOptions,
    ) Error!void {
        if (!self.client_options.manual_acknowledgements or
            self.client_options.inbound_qos2_release_policy != .deferred)
        {
            return error.ManualAcknowledgementsDisabled;
        }
        if (packet_id == 0) return error.InvalidPacketIdentifier;
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        var validated_ack: std.ArrayList(u8) = .empty;
        defer validated_ack.deinit(self.allocator);
        try mqtt.AckPacket.write(
            &validated_ack,
            self.allocator,
            active.protocol,
            .pubcomp,
            packet_id,
            options.reason_code,
            options.properties,
        );
        if (validated_ack.items.len > active.peerMaximumPacketSize()) {
            return error.OutgoingPacketTooLarge;
        }
        const state = try self.outgoing.incomingQoS2State(
            self.outgoing_handle,
            packet_id,
        ) orelse return error.UnexpectedPacket;
        if (state != .release_pending) return error.UnexpectedPacket;
        try self.outgoing.completeIncomingQoS2(
            self.outgoing_handle,
            packet_id,
        );
    }

    pub fn discardStagedIncomingQoS2Completion(
        self: *Client,
        packet_id: u16,
    ) Error!void {
        return self.outgoing.restoreIncomingQoS2ReleasePending(
            self.outgoing_handle,
            packet_id,
        );
    }

    pub fn writeStagedIncomingQoS2Completion(
        self: *Client,
        packet_id: u16,
        options: runtime.AcknowledgeOptions,
    ) Error!void {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        if (try self.outgoing.containsIncomingQoS2(
            self.outgoing_handle,
            packet_id,
        )) {
            return error.UnexpectedPacket;
        }
        try active.resumeIncomingQoS2(packet_id);
        active.writePubCompWithProperties(
            packet_id,
            options.reason_code,
            options.properties,
        ) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
        self.noteControlSent();
    }

    /// Subscribe and remember only filters accepted by the broker. A future
    /// reconnect replays them when CONNACK reports that no Session survived.
    /// Failed replay resumes its unconfirmed suffix even if the next connection
    /// preserves that partially restored Session. Existing entries are updated
    /// transactionally after SUBACK.
    pub fn subscribe(
        self: *Client,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
    ) Error!runtime.OwnedSubAck {
        return self.subscribeUntil(subscriptions, options, null);
    }

    pub fn subscribeWithTimeout(self: *Client, subscriptions: []const mqtt.Subscription, options: runtime.SubscribeOptions, timeout: std.Io.Duration) Error!runtime.OwnedSubAck {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.subscribeWithDeadline(subscriptions, options, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn subscribeWithDeadline(self: *Client, subscriptions: []const mqtt.Subscription, options: runtime.SubscribeOptions, deadline: std.Io.Clock.Timestamp) Error!runtime.OwnedSubAck {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.subscribeUntil(subscriptions, options, deadline);
    }

    fn subscribeUntil(self: *Client, subscriptions: []const mqtt.Subscription, options: runtime.SubscribeOptions, deadline: ?std.Io.Clock.Timestamp) Error!runtime.OwnedSubAck {
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
        if (additions > self.client_options.max_subscriptions -|
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
        var suback = (if (deadline) |absolute|
            active.subscribeWithDeadline(subscriptions, options, absolute)
        else
            active.subscribe(subscriptions, options)) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
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
        return self.unsubscribeUntil(filters, options, null);
    }

    pub fn unsubscribeWithTimeout(self: *Client, filters: []const []const u8, options: runtime.UnsubscribeOptions, timeout: std.Io.Duration) Error!runtime.OwnedUnsubAck {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.unsubscribeWithDeadline(filters, options, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn unsubscribeWithDeadline(self: *Client, filters: []const []const u8, options: runtime.UnsubscribeOptions, deadline: std.Io.Clock.Timestamp) Error!runtime.OwnedUnsubAck {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.unsubscribeUntil(filters, options, deadline);
    }

    fn unsubscribeUntil(self: *Client, filters: []const []const u8, options: runtime.UnsubscribeOptions, deadline: ?std.Io.Clock.Timestamp) Error!runtime.OwnedUnsubAck {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        var unsuback = (if (deadline) |absolute|
            active.unsubscribeWithDeadline(filters, options, absolute)
        else
            active.unsubscribe(filters, options)) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
        self.noteControlSent();
        errdefer unsuback.deinit(self.allocator);
        if (active.protocol.isLegacy()) {
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
        const attempt = try self.publishOneAttempt(topic, payload, options);
        if (!attempt.transport_interrupted) return attempt.packet_id;
        const connected = try self.connect();
        if (!connected.session_resumed) return error.SessionLost;
        return attempt.packet_id;
    }

    /// Own a QoS 1/2 PUBLISH and reserve its stable Packet Identifier without
    /// emitting network bytes or mutating connection-local Packet Identifier
    /// and Topic Alias state. The caller can append `writeSessionSnapshot` to a
    /// larger atomic coordinator record before `flushPending` performs the
    /// first send. On the same process that first send uses DUP=0; after
    /// snapshot restoration it conservatively uses DUP=1.
    pub fn stagePublish(
        self: *Client,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
    ) Error!u16 {
        const active = self.connection() orelse
            return error.ConnectionUnavailable;
        try active.validateClientSessionPublish(topic, payload, options);
        return self.outgoing.stageImmediatePublishAvoiding(
            self.outgoing_handle,
            topic,
            payload,
            .{
                .qos = options.qos,
                .retain = options.retain,
                .properties = options.properties,
                .now = std.Io.Clock.awake.now(self.io),
            },
            active.max_outgoing_inflight,
            active.packet_identifiers.ownership(),
        );
    }

    /// Roll back a locally staged PUBLISH before `flushPending` selects it.
    /// Coordinators use this when their durable commit fails.
    pub fn discardStagedPublish(
        self: *Client,
        packet_id: u16,
    ) Error!void {
        return self.outgoing.discardStagedPublish(
            self.outgoing_handle,
            packet_id,
        );
    }

    /// Queue and attempt one outbound PUBLISH without reconnecting inside this
    /// call. On a retryable QoS 1/2 transport failure, Session state retains
    /// the message, the transport is retired, and the Packet Identifier is
    /// returned with `transport_interrupted=true`. This lets a coordinator
    /// keep other connections alive while `pollWith*` reconnects and replays.
    /// QoS 0 has no recoverable state and therefore returns its write error.
    pub fn publishOneAttempt(
        self: *Client,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
    ) Error!PublishAttempt {
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
            active.publish(topic, payload, options) catch |err| {
                self.retireConnectionAfterOperationError(err);
                return err;
            };
            self.noteControlSent();
            self.finishPublishDelivery(.{
                .packet_id = null,
                .qos = .at_most_once,
                .reason_code = 0,
                .properties = &.{},
            });
            return .{ .packet_id = null };
        }
        try session.validatePublishForSession(
            topic,
            payload,
            options.properties,
        );
        // This either reserves the exact submitted message or leaves it
        // unowned. Existing replay/queue work must be driven explicitly, so a
        // one-attempt call can never send an older packet and return its ID.
        const transmission = try self.outgoing.beginImmediatePublishAvoiding(
            self.outgoing_handle,
            topic,
            payload,
            .{
                .qos = options.qos,
                .retain = options.retain,
                .properties = options.properties,
                .now = std.Io.Clock.awake.now(self.io),
            },
            active.max_outgoing_inflight,
            active.packet_identifiers.ownership(),
        );
        const publish_value = transmission;
        active.writeClientSessionTransmission(.{ .publish = transmission }) catch |err| {
            if (!retryableConnectError(err) and active.isUsable()) {
                const dropped = try self.outgoing.dropOutgoingPublish(
                    self.outgoing_handle,
                    publish_value.packet_id,
                );
                std.debug.assert(dropped == .dropped);
                return err;
            }
            // The store already owns this packet. Disconnect marks the
            // selected inflight entry sendable so a later poll/connect can
            // replay it with DUP without a second enqueue.
            self.disconnectTransport();
            return .{
                .packet_id = publish_value.packet_id,
                .transport_interrupted = true,
            };
        };
        self.noteControlSent();
        return .{ .packet_id = publish_value.packet_id };
    }

    /// Drive exactly one ordered client event, returning null when the caller's
    /// bound expires first or when an established transport is retired and
    /// `reconnect_after_transport_error` is false. The method is the sole
    /// reader and performs all QoS acknowledgements, keep-alive probes, and
    /// enabled retryable reconnects itself.
    /// An interrupted automatic reply retains its applied incoming event.
    /// Retryable socket failures may return that event before reconnecting;
    /// expired calls leave it for the next poll. QoS 2 PUBLISH retries continue
    /// the handshake without a second application delivery.
    /// Applications must not mix it concurrently with typed reads or
    /// `completeNextPublish`.
    pub fn pollWithOptions(
        self: *Client,
        options: PollOptions,
    ) (Error || std.Io.Cancelable)!?ClientEvent {
        if (options.timeout.nanoseconds <= 0) return error.Timeout;
        return self.pollUntil(
            std.Io.Clock.awake.now(self.io).addDuration(options.timeout),
            options.ping_response_timeout,
            options.cancellation_check_interval,
            options.reconnect_after_transport_error,
        );
    }

    /// Drive one ordered event until an absolute awake-clock deadline. Keep
    /// Alive and shutdown polling may shorten socket waits but never renew the
    /// caller's total budget.
    pub fn pollWithDeadline(
        self: *Client,
        deadline: std.Io.Timestamp,
        options: DeadlinePollOptions,
    ) (Error || std.Io.Cancelable)!?ClientEvent {
        if (std.Io.Clock.awake.now(self.io).nanoseconds >=
            deadline.nanoseconds) return error.Timeout;
        return self.pollUntil(
            deadline,
            options.ping_response_timeout,
            options.cancellation_check_interval,
            options.reconnect_after_transport_error,
        );
    }

    const PollController = @import("reconnect/poll.zig").Controller(struct {
        pub const ClientType = Client;
        pub const EventType = ClientEvent;
        pub const ErrorType = Error || std.Io.Cancelable;
        pub const connectBefore = Client.connectEventBefore;
        pub const keepAlive = Client.keepAliveDeadline;
        pub const retryable = retryableConnectError;
        pub const retireAfterError = Client.retireConnectionAfterOperationError;
        pub const nextDeadline = Client.nextPollDeadline;
        pub const pruneExpired = Client.pruneExpiredOutgoing;
        pub const diagnose = Client.disconnectForPeerProtocolViolation;
        pub const apply = Client.applyPacketEvent;
    });

    const pollUntil = PollController.run;

    fn connectEventBefore(
        self: *Client,
        deadline: std.Io.Timestamp,
    ) (Error || std.Io.Cancelable)!?ClientEvent {
        const connected = self.connectWithDeadline(
            deadline.withClock(.awake),
        ) catch |err| switch (err) {
            error.Timeout => return null,
            else => |other| return other,
        };
        return .{ .connected = connected };
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
                if (self.executeQueuedCommand(command)) return;
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
        const state = try self.allocator.create(QueuedRunState);
        errdefer self.allocator.destroy(state);
        state.* = .{};
        const queue = try self.allocator.create(CommandQueue);
        errdefer self.allocator.destroy(queue);
        queue.* = try CommandQueue.init(
            self.allocator,
            self.io,
            options.queue_capacity,
        );
        errdefer queue.deinit();
        const worker = try std.Thread.spawn(
            .{},
            QueuedRunWorkerFn(Context, handler).run,
            .{ self, queue, context, state, options.serve },
        );
        return .{
            .io = self.io,
            .shutdown = self.shutdown,
            .queue = queue,
            .worker = .{ .thread = worker },
            .state = state,
        };
    }

    /// Schedule the managed reconnect worker on this Client's existing
    /// `std.Io` executor instead of creating an OS thread. The returned handle
    /// has the same producer, stop, wait, and deinit contract as `runQueued`;
    /// deinit awaits the task after requesting graceful shutdown.
    pub fn runQueuedAsync(
        self: *Client,
        comptime Context: type,
        context: *Context,
        comptime handler: *const fn (
            *Context,
            *Client,
            *ClientEvent,
        ) anyerror!void,
        options: RunQueuedOptions,
    ) std.mem.Allocator.Error!QueuedRun {
        const state = try self.allocator.create(QueuedRunState);
        errdefer self.allocator.destroy(state);
        state.* = .{};
        const queue = try self.allocator.create(CommandQueue);
        errdefer self.allocator.destroy(queue);
        queue.* = try CommandQueue.init(
            self.allocator,
            self.io,
            options.queue_capacity,
        );
        errdefer queue.deinit();
        state.io_task = self.io.async(
            QueuedRunWorkerFn(Context, handler).run,
            .{ self, queue, context, state, options.serve },
        );
        return .{
            .io = self.io,
            .shutdown = self.shutdown,
            .queue = queue,
            .worker = .io_task,
            .state = state,
        };
    }

    /// Spawn the managed reconnect worker and transfer every event into a
    /// bounded owned queue. This gives applications a rumqtt-style event
    /// stream without introducing a second socket reader. Close `events` to
    /// unblock a full queue before joining the worker during early shutdown.
    pub fn runQueuedEvents(
        self: *Client,
        events: *ClientEventQueue,
        options: RunQueuedOptions,
    ) (std.mem.Allocator.Error || std.Thread.SpawnError)!QueuedEventRun {
        return .{
            .commands = try self.runQueued(
                ClientEventQueue,
                events,
                QueuedEventAdapter.handle,
                options,
            ),
            .events = events,
        };
    }

    /// `runQueuedEvents` using the Client's existing `std.Io` executor rather
    /// than a dedicated OS thread.
    pub fn runQueuedEventsAsync(
        self: *Client,
        events: *ClientEventQueue,
        options: RunQueuedOptions,
    ) std.mem.Allocator.Error!QueuedEventRun {
        return .{
            .commands = try self.runQueuedAsync(
                ClientEventQueue,
                events,
                QueuedEventAdapter.handle,
                options,
            ),
            .events = events,
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
        active.beginReauthenticationWithProperties(properties) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
        self.noteControlSent();
    }

    /// Retry queued QoS publications after a connection becomes available.
    /// This is useful when `publish` returned `ConnectionUnavailable` after
    /// durably queueing the request.
    pub fn flushPending(self: *Client) Error!void {
        return self.flushPendingUntil(null);
    }

    pub fn flushPendingWithTimeout(self: *Client, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.flushPendingWithDeadline(.fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn flushPendingWithDeadline(self: *Client, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.flushPendingUntil(deadline);
    }

    fn flushPendingUntil(self: *Client, deadline: ?std.Io.Clock.Timestamp) Error!void {
        try self.outgoing.releasePendingPubRels(self.outgoing_handle);
        self.replayPendingUntil(deadline) catch |err| {
            self.retireConnectionAfterOperationError(err);
            return err;
        };
        self.noteControlSent();
    }

    /// Read and apply one QoS acknowledgement. With automatic outbound QoS 2
    /// release, PUBREL is emitted before returning. Deferred release instead
    /// leaves it behind the `flushPending` durability boundary.
    pub fn completeNextPublish(self: *Client) Error!u16 {
        while (true) {
            const active = self.connection() orelse
                return error.ConnectionUnavailable;
            var event = active.readBrokerEvent() catch |err| {
                self.retireUnusableConnection();
                if (!retryableConnectError(err)) return err;
                const connected = try self.reconnect();
                if (!connected.session_resumed) return error.SessionLost;
                continue;
            };
            defer event.deinit(self.allocator);
            const ack = switch (event) {
                .puback => |value| value.ack,
                .pubrec => |value| value.ack,
                .pubcomp => |value| value.ack,
                else => return error.UnexpectedPacket,
            };
            const action = try self.applyOutgoingAck(ack);
            if (action == .send_pubrel and
                self.client_options.outbound_qos2_release_policy ==
                    .automatic)
            {
                try self.replayPending();
            }
            if (action == .completed) {
                self.finishPublishDelivery(.{
                    .packet_id = ack.packet_id,
                    .qos = if (ack.packet_type == .puback)
                        .at_least_once
                    else
                        .exactly_once,
                    .reason_code = ack.reason_code,
                    .properties = ack.properties,
                });
            }
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

    fn waitBackoffUntil(
        self: *Client,
        delay: std.Io.Duration,
        deadline: ?std.Io.Clock.Timestamp,
    ) (std.Io.Cancelable || error{Timeout})!void {
        const bounded = if (deadline) |absolute| blk: {
            const remaining = absolute.durationFromNow(self.io).raw;
            if (remaining.nanoseconds <= 0) return error.Timeout;
            break :blk std.Io.Duration.fromNanoseconds(@min(
                delay.nanoseconds,
                remaining.nanoseconds,
            ));
        } else delay;
        try self.waitBackoff(bounded);
        if (deadline) |absolute| {
            if (absolute.durationFromNow(self.io).raw.nanoseconds <= 0) {
                return error.Timeout;
            }
        }
    }

    fn waitForScheduledAttempt(
        self: *Client,
        deadline: ?std.Io.Clock.Timestamp,
    ) (std.Io.Cancelable || error{Timeout})!void {
        const remaining = self.retry_schedule.remaining(
            std.Io.Clock.awake.now(self.io),
        ) orelse return;
        if (remaining.nanoseconds > 0) {
            try self.waitBackoffUntil(remaining, deadline);
        }
        self.retry_schedule.clearScheduled();
    }

    fn retrySample(self: *Client) u64 {
        if (self.policy.jitter == .none) return 0;
        var random_bytes: [8]u8 = undefined;
        self.io.random(&random_bytes);
        return std.mem.readInt(u64, &random_bytes, .little);
    }

    fn resetOutgoingState(self: *Client) Error!void {
        var fresh = try session_identity.FreshSession.init(self.allocator, self.options.value.client_id, std.Io.Clock.awake.now(self.io));
        defer fresh.deinit();
        fresh.install(self);
    }

    const ReplayContext = struct {
        pub const ClientType = Client;
        pub const ErrorType = Error;
        pub const retryable = retryableConnectError;
        pub const finishDelivery = Client.finishPublishDelivery;
    };

    fn replayPending(self: *Client) Error!void {
        return self.replayPendingUntil(null);
    }

    fn replayPendingUntil(self: *Client, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return @import("reconnect/replay.zig").drain(ReplayContext, self, deadline);
    }

    fn replaySubscriptions(self: *Client, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return subscription_replay.run(Error, self, deadline);
    }

    const PacketEvents = @import("reconnect/packet_events.zig").Controller(struct {
        pub const ClientType = Client;
        pub const ErrorType = Error;
        pub const EventType = ClientEvent;
        pub const applyOutgoingAck = Client.applyOutgoingAck;
        pub const finishDelivery = Client.finishPublishDelivery;
        pub const noteControlSent = Client.noteControlSent;
        pub const replayPending = Client.replayPendingUntil;
        pub const retireUnusableConnection = Client.retireUnusableConnection;
    });

    const applyPacketEvent = PacketEvents.apply;

    fn finishPublishDelivery(
        self: *Client,
        delivery: PublishDelivery,
    ) void {
        if (self.client_options.publish_delivery) |handler| {
            handler.complete(handler.context, delivery);
        }
    }

    /// Returns true after a successful graceful disconnect, instructing the
    /// queue owner to stop instead of immediately reconnecting.
    fn executeQueuedCommand(
        self: *Client,
        command: *command_queue.Command,
    ) bool {
        switch (command.operation) {
            .publish => |publish_command| {
                const packet_id = self.publish(
                    publish_command.topic,
                    publish_command.payload,
                    publish_command.options,
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishSuccess(self.io, packet_id);
                return false;
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
                    return false;
                };
                command.finishSuccess(self.io, packet_id);
                return false;
            },
            .subscribe_owned => |subscribe_command| {
                var subscriptions = std.ArrayList(mqtt.Subscription).empty;
                defer subscriptions.deinit(self.allocator);
                subscriptions.ensureTotalCapacity(
                    self.allocator,
                    subscribe_command.subscriptions.len,
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                for (subscribe_command.subscriptions) |stored| {
                    subscriptions.appendAssumeCapacity(stored.value());
                }
                var suback = self.subscribe(
                    subscriptions.items,
                    .{ .properties = subscribe_command.properties },
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishSubAck(self.io, &suback);
                return false;
            },
            .unsubscribe_owned => |unsubscribe_command| {
                var unsuback = self.unsubscribe(
                    unsubscribe_command.filters,
                    .{ .properties = unsubscribe_command.properties },
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishUnsubAck(self.io, &unsuback);
                return false;
            },
            .disconnect => |disconnect_command| {
                return self.executeDisconnectCommand(
                    command,
                    disconnect_command.reason_code,
                    disconnect_command.properties,
                );
            },
            .disconnect_owned => |disconnect_command| {
                return self.executeDisconnectCommand(
                    command,
                    disconnect_command.reason_code,
                    disconnect_command.properties,
                );
            },
            .acknowledge => |acknowledge_command| {
                self.acknowledge(
                    acknowledge_command.packet_id,
                    acknowledge_command.qos,
                    acknowledge_command.options,
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishAcknowledge(self.io);
                return false;
            },
            .acknowledge_owned => |acknowledge_command| {
                self.acknowledge(
                    acknowledge_command.packet_id,
                    acknowledge_command.qos,
                    .{
                        .reason_code = acknowledge_command.reason_code,
                        .properties = acknowledge_command.properties,
                    },
                ) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishAcknowledge(self.io);
                return false;
            },
            .flush_pending => {
                self.flushPending() catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishFlushPending(self.io);
                return false;
            },
            .begin_reauthentication => |properties| {
                self.beginReauthentication(properties) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishReauthentication(self.io);
                return false;
            },
            .begin_reauthentication_owned => |properties| {
                self.beginReauthentication(properties) catch |err| {
                    command.finishFailure(self.io, err);
                    return false;
                };
                command.finishReauthentication(self.io);
                return false;
            },
        }
    }

    fn executeDisconnectCommand(
        self: *Client,
        command: *command_queue.Command,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) bool {
        if (self.connection() == null) {
            command.finishFailure(self.io, error.ConnectionUnavailable);
            return false;
        }
        // Validate and encode before signaling shutdown. A protocol error must
        // leave the active connection and reconnect loop usable.
        self.disconnectWithProperties(reason_code, properties) catch |err| {
            command.finishFailure(self.io, err);
            return false;
        };
        // Set shutdown before publishing success. A synchronous caller may
        // return and immediately call `deinit`, which must not race the worker
        // into a fresh reconnect iteration.
        self.shutdown.set(self.io);
        command.finishDisconnect(self.io);
        return true;
    }

    fn applyOutgoingAck(
        self: *Client,
        ack: mqtt.AckPacket,
    ) Error!session.AckAction {
        const action = try self.outgoing.handleAck(
            self.outgoing_handle,
            ack.packet_type,
            ack.packet_id,
            ack.reason_code,
        );
        if (action == .send_pubrel and
            self.client_options.outbound_qos2_release_policy == .deferred)
        {
            try self.outgoing.blockPendingPubRel(
                self.outgoing_handle,
                ack.packet_id,
            );
        }
        return action;
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

    /// Preserve an established connection after purely local validation or
    /// application callback failure, but never retain a transport whose read
    /// or write progress is ambiguous.
    fn retireUnusableConnection(self: *Client) void {
        const unusable = if (self.connection_state) |*active|
            !active.isUsable()
        else
            false;
        if (unusable) self.disconnectTransport();
    }

    /// Synchronous public operations own both their socket write and matching
    /// response read, so a known transport failure retires the connection even
    /// when no write marker was set (for example EOF while awaiting SUBACK).
    fn retireConnectionAfterOperationError(
        self: *Client,
        err: anyerror,
    ) void {
        if (retryableConnectError(err)) {
            self.disconnectTransport();
        } else {
            self.retireUnusableConnection();
        }
    }

    /// Report a peer-originated MQTT violation when this is an established
    /// MQTT 5 connection, then retire the connection for every protocol
    /// version. The original parse/state error remains the caller-visible
    /// result; inability to write the diagnostic is deliberately secondary.
    fn disconnectForPeerProtocolViolation(
        self: *Client,
        err: anyerror,
        deadline: std.Io.Clock.Timestamp,
    ) bool {
        const reason_code =
            runtime.disconnectReasonForProtocolViolation(err, .client) orelse
            return false;
        const active = self.connection() orelse return true;
        if (active.protocol == .v5) {
            active.writeDisconnectWithDeadline(reason_code, &.{}, deadline) catch {};
        }
        self.disconnectTransport();
        return true;
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

fn configuredPersistentSession(options: runtime.ConnectOptions) bool {
    if (options.clean_start) return false;
    return switch (options.protocol) {
        .v3_1, .v3_1_1 => true,
        .v5 => (mqtt.sessionExpiryInterval(options.properties) orelse 0) != 0,
    };
}

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

test {
    _ = @import("reconnect/session_resume_tests.zig");
    _ = @import("reconnect/retention_tests.zig");
    _ = @import("reconnect/retention_codec_tests.zig");
    _ = @import("reconnect/retention_snapshot_tests.zig");
    _ = @import("reconnect/snapshot_checkpoint_tests.zig");
    _ = @import("reconnect/retention_lifecycle_tests.zig");
    _ = @import("reconnect/retention_attempt_tests.zig");
    _ = @import("reconnect/assigned_identity_tests.zig");
    _ = @import("reconnect/assigned_identity_snapshot_tests.zig");
    _ = @import("reconnect/session_identity_tests.zig");
    _ = @import("reconnect/session_reset_tests.zig");
    _ = @import("reconnect/subscription_replay_tests.zig");
    _ = @import("reconnect/subscription_snapshot_tests.zig");
    _ = @import("reconnect/snapshot_subscriptions_tests.zig");
}
