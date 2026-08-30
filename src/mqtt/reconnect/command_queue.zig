//! Bounded multi-producer command channel for the reconnect event loop.
//!
//! Synchronous requests borrow their payload until completion. Asynchronous
//! PUBLISH, SUBSCRIBE, UNSUBSCRIBE, DISCONNECT, manual acknowledgement, and
//! re-authentication requests instead deep-copy all variable data, so
//! producers may return immediately while one loop retains exclusive
//! transport ownership.

const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const session = @import("../session/mod.zig");
const owned_properties = @import("../owned_properties.zig");
const owned_subscription = @import("subscription.zig");

pub const Error = runtime.Error || session.Error || std.Io.Cancelable || error{
    CommandQueueClosed,
    CommandQueueFull,
    CommandIdentifierExhausted,
    InvalidReconnectPolicy,
    ConnectionUnavailable,
    SessionLost,
    SubscriptionLimitExceeded,
    OwnedPropertyLimitExceeded,
    ManualAcknowledgementsDisabled,
};
pub const EnqueueTimeoutError = Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

const EnqueueWait = union(enum) {
    duration: std.Io.Duration,
    deadline: std.Io.Clock.Timestamp,
};

/// Queue capacity waits use the awake clock so a caller's absolute budget is
/// comparable to the timestamp consumed by `Timestamp.wait`. Validate before
/// cloning variable command data as well as at the final enqueue boundary: the
/// first check avoids needless ownership work, while the second covers budgets
/// that expire during allocation.
fn validateEnqueueDeadline(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Timeout.Error!void {
    if (deadline.clock != .awake or
        deadline.durationFromNow(io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
}

pub const CommandQueue = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    storage: []*Command,
    queue: std.Io.Queue(*Command),
    allocator_mutex: std.Io.Mutex = .init,
    next_command_id: std.atomic.Value(u64) = .init(1),
    async_commands: std.atomic.Value(usize) = .init(0),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        capacity: usize,
    ) std.mem.Allocator.Error!CommandQueue {
        const storage = try allocator.alloc(*Command, capacity);
        return .{
            .allocator = allocator,
            .io = io,
            .storage = storage,
            .queue = .init(storage),
        };
    }

    /// Close the channel and fail commands that had entered the bounded
    /// buffer. Call only after the loop owner has stopped accessing the queue.
    pub fn deinit(self: *CommandQueue) void {
        self.stop(error.CommandQueueClosed);
        std.debug.assert(self.async_commands.load(.acquire) == 0);
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn publish(
        self: *CommandQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
    ) Error!?u16 {
        var command = Command{ .operation = .{ .publish = .{
            .topic = topic,
            .payload = payload,
            .options = options,
        } } };
        try self.submit(&command);
        return command.packet_id;
    }

    /// Deep-copy and enqueue a publication without waiting for socket I/O.
    /// Completion is delivered exactly once by the loop or by queue shutdown.
    /// A full bounded queue fails without taking ownership from the caller.
    /// `complete` runs synchronously on the loop thread and must not submit a
    /// blocking command to this same queue. The queue allocator must support
    /// concurrent use if it is also used elsewhere while producers enqueue.
    pub fn publishAsync(
        self: *CommandQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        completion: CompletionHandler,
    ) Error!u64 {
        return self.publishAsyncInternal(
            topic,
            payload,
            options,
            completion,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Deep-copy a publication and wait up to `timeout` for bounded queue
    /// capacity. Success transfers ownership to the reconnect loop but does
    /// not wait for socket delivery; `completion` still reports that result.
    pub fn publishAsyncTimeout(
        self: *CommandQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        completion: CompletionHandler,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.publishAsyncInternal(
            topic,
            payload,
            options,
            completion,
            .{ .duration = timeout },
        );
    }

    /// Enqueue an owned publication without renewing a caller's existing
    /// absolute budget while waiting for bounded queue capacity.
    pub fn publishAsyncWithDeadline(
        self: *CommandQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        completion: CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!u64 {
        try validateEnqueueDeadline(self.io, deadline);
        return self.publishAsyncInternal(
            topic,
            payload,
            options,
            completion,
            .{ .deadline = deadline },
        );
    }

    fn publishAsyncInternal(
        self: *CommandQueue,
        topic: []const u8,
        payload: []const u8,
        options: runtime.PublishOptions,
        completion: CompletionHandler,
        enqueue_wait: ?EnqueueWait,
    ) EnqueueTimeoutError!u64 {
        self.allocator_mutex.lockUncancelable(self.io);
        defer self.allocator_mutex.unlock(self.io);
        const command = try self.allocator.create(Command);
        errdefer self.allocator.destroy(command);
        const owned_topic = try self.allocator.dupe(u8, topic);
        errdefer self.allocator.free(owned_topic);
        const owned_payload = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(owned_payload);
        const properties = try owned_properties.clone(
            self.allocator,
            options.properties,
            owned_properties.keepAll,
        );
        errdefer owned_properties.deinit(
            self.allocator,
            properties.properties,
        );
        const command_id = try self.nextCommandId();
        command.* = .{
            .operation = .{ .publish_owned = .{
                .topic = owned_topic,
                .payload = owned_payload,
                .qos = options.qos,
                .retain = options.retain,
                .dup = options.dup,
                .properties = properties.properties,
            } },
            .async_completion = .{
                .command_id = command_id,
                .handler = completion,
            },
            .owner = self,
        };
        try self.enqueueOwnedMaybeWait(command, enqueue_wait);
        return command_id;
    }

    /// Deep-copy subscriptions and MQTT 5 properties before enqueueing.
    /// Successful SUBACK data is borrowed by the completion callback for that
    /// invocation.
    pub fn subscribeAsync(
        self: *CommandQueue,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        completion: CompletionHandler,
    ) Error!u64 {
        return self.subscribeAsyncInternal(
            subscriptions,
            options,
            completion,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn subscribeAsyncTimeout(
        self: *CommandQueue,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        completion: CompletionHandler,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.subscribeAsyncInternal(
            subscriptions,
            options,
            completion,
            .{ .duration = timeout },
        );
    }

    pub fn subscribeAsyncWithDeadline(
        self: *CommandQueue,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        completion: CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!u64 {
        try validateEnqueueDeadline(self.io, deadline);
        return self.subscribeAsyncInternal(
            subscriptions,
            options,
            completion,
            .{ .deadline = deadline },
        );
    }

    fn subscribeAsyncInternal(
        self: *CommandQueue,
        subscriptions: []const mqtt.Subscription,
        options: runtime.SubscribeOptions,
        completion: CompletionHandler,
        enqueue_wait: ?EnqueueWait,
    ) EnqueueTimeoutError!u64 {
        self.allocator_mutex.lockUncancelable(self.io);
        defer self.allocator_mutex.unlock(self.io);
        const command = try self.allocator.create(Command);
        errdefer self.allocator.destroy(command);
        const owned_subscriptions = try cloneSubscriptions(
            self.allocator,
            subscriptions,
        );
        errdefer deinitSubscriptions(self.allocator, owned_subscriptions);
        const properties = try owned_properties.clone(
            self.allocator,
            options.properties,
            owned_properties.keepAll,
        );
        errdefer owned_properties.deinit(
            self.allocator,
            properties.properties,
        );
        const command_id = try self.nextCommandId();
        command.* = .{
            .operation = .{ .subscribe_owned = .{
                .subscriptions = owned_subscriptions,
                .properties = properties.properties,
            } },
            .async_completion = .{
                .command_id = command_id,
                .handler = completion,
            },
            .owner = self,
        };
        try self.enqueueOwnedMaybeWait(command, enqueue_wait);
        return command_id;
    }

    /// Deep-copy filters and MQTT 5 properties before enqueueing. Successful
    /// UNSUBACK data is borrowed by the completion callback for that invocation.
    pub fn unsubscribeAsync(
        self: *CommandQueue,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        completion: CompletionHandler,
    ) Error!u64 {
        return self.unsubscribeAsyncInternal(
            filters,
            options,
            completion,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn unsubscribeAsyncTimeout(
        self: *CommandQueue,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        completion: CompletionHandler,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.unsubscribeAsyncInternal(
            filters,
            options,
            completion,
            .{ .duration = timeout },
        );
    }

    pub fn unsubscribeAsyncWithDeadline(
        self: *CommandQueue,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        completion: CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!u64 {
        try validateEnqueueDeadline(self.io, deadline);
        return self.unsubscribeAsyncInternal(
            filters,
            options,
            completion,
            .{ .deadline = deadline },
        );
    }

    fn unsubscribeAsyncInternal(
        self: *CommandQueue,
        filters: []const []const u8,
        options: runtime.UnsubscribeOptions,
        completion: CompletionHandler,
        enqueue_wait: ?EnqueueWait,
    ) EnqueueTimeoutError!u64 {
        self.allocator_mutex.lockUncancelable(self.io);
        defer self.allocator_mutex.unlock(self.io);
        const command = try self.allocator.create(Command);
        errdefer self.allocator.destroy(command);
        const owned_filters = try cloneStrings(self.allocator, filters);
        errdefer deinitStrings(self.allocator, owned_filters);
        const properties = try owned_properties.clone(
            self.allocator,
            options.properties,
            owned_properties.keepAll,
        );
        errdefer owned_properties.deinit(
            self.allocator,
            properties.properties,
        );
        const command_id = try self.nextCommandId();
        command.* = .{
            .operation = .{ .unsubscribe_owned = .{
                .filters = owned_filters,
                .properties = properties.properties,
            } },
            .async_completion = .{
                .command_id = command_id,
                .handler = completion,
            },
            .owner = self,
        };
        try self.enqueueOwnedMaybeWait(command, enqueue_wait);
        return command_id;
    }

    /// Gracefully disconnect through the loop that owns the transport. The
    /// property slice is borrowed until this synchronous call returns.
    pub fn disconnect(
        self: *CommandQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
    ) Error!void {
        var command = Command{ .operation = .{ .disconnect = .{
            .reason_code = reason_code,
            .properties = properties,
        } } };
        try self.submit(&command);
    }

    /// Deep-copy MQTT 5 properties and enqueue a graceful disconnect. A
    /// successful command stops the owning reconnect loop after its completion
    /// callback returns; queued commands behind it fail during queue shutdown.
    pub fn disconnectAsync(
        self: *CommandQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
    ) Error!u64 {
        return self.disconnectAsyncInternal(
            reason_code,
            properties,
            completion,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn disconnectAsyncTimeout(
        self: *CommandQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.disconnectAsyncInternal(
            reason_code,
            properties,
            completion,
            .{ .duration = timeout },
        );
    }

    pub fn disconnectAsyncWithDeadline(
        self: *CommandQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!u64 {
        try validateEnqueueDeadline(self.io, deadline);
        return self.disconnectAsyncInternal(
            reason_code,
            properties,
            completion,
            .{ .deadline = deadline },
        );
    }

    fn disconnectAsyncInternal(
        self: *CommandQueue,
        reason_code: u8,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
        enqueue_wait: ?EnqueueWait,
    ) EnqueueTimeoutError!u64 {
        self.allocator_mutex.lockUncancelable(self.io);
        defer self.allocator_mutex.unlock(self.io);
        const command = try self.allocator.create(Command);
        errdefer self.allocator.destroy(command);
        const copied_properties = try owned_properties.clone(
            self.allocator,
            properties,
            owned_properties.keepAll,
        );
        errdefer owned_properties.deinit(
            self.allocator,
            copied_properties.properties,
        );
        const command_id = try self.nextCommandId();
        command.* = .{
            .operation = .{ .disconnect_owned = .{
                .reason_code = reason_code,
                .properties = copied_properties.properties,
            } },
            .async_completion = .{
                .command_id = command_id,
                .handler = completion,
            },
            .owner = self,
        };
        try self.enqueueOwnedMaybeWait(command, enqueue_wait);
        return command_id;
    }

    /// Acknowledge an inbound PUBLISH through the event-loop socket owner.
    /// MQTT 5 properties are borrowed until this synchronous call completes.
    pub fn acknowledge(
        self: *CommandQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
    ) Error!void {
        var command = Command{ .operation = .{ .acknowledge = .{
            .packet_id = packet_id,
            .qos = qos,
            .options = options,
        } } };
        try self.submit(&command);
    }

    /// Deep-copy MQTT 5 acknowledgement properties and enqueue without
    /// waiting for the socket write.
    pub fn acknowledgeAsync(
        self: *CommandQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        completion: CompletionHandler,
    ) Error!u64 {
        return self.acknowledgeAsyncInternal(
            packet_id,
            qos,
            options,
            completion,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn acknowledgeAsyncTimeout(
        self: *CommandQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        completion: CompletionHandler,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acknowledgeAsyncInternal(
            packet_id,
            qos,
            options,
            completion,
            .{ .duration = timeout },
        );
    }

    pub fn acknowledgeAsyncWithDeadline(
        self: *CommandQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        completion: CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!u64 {
        try validateEnqueueDeadline(self.io, deadline);
        return self.acknowledgeAsyncInternal(
            packet_id,
            qos,
            options,
            completion,
            .{ .deadline = deadline },
        );
    }

    fn acknowledgeAsyncInternal(
        self: *CommandQueue,
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
        completion: CompletionHandler,
        enqueue_wait: ?EnqueueWait,
    ) EnqueueTimeoutError!u64 {
        self.allocator_mutex.lockUncancelable(self.io);
        defer self.allocator_mutex.unlock(self.io);
        const command = try self.allocator.create(Command);
        errdefer self.allocator.destroy(command);
        const copied_properties = try owned_properties.clone(
            self.allocator,
            options.properties,
            owned_properties.keepAll,
        );
        errdefer owned_properties.deinit(
            self.allocator,
            copied_properties.properties,
        );
        const command_id = try self.nextCommandId();
        command.* = .{
            .operation = .{ .acknowledge_owned = .{
                .packet_id = packet_id,
                .qos = qos,
                .reason_code = options.reason_code,
                .properties = copied_properties.properties,
            } },
            .async_completion = .{
                .command_id = command_id,
                .handler = completion,
            },
            .owner = self,
        };
        try self.enqueueOwnedMaybeWait(command, enqueue_wait);
        return command_id;
    }

    pub fn flushPending(self: *CommandQueue) Error!void {
        var command = Command{ .operation = .flush_pending };
        try self.submit(&command);
    }

    /// Enqueue durable-PUBLISH replay without waiting for socket writes.
    pub fn flushPendingAsync(
        self: *CommandQueue,
        completion: CompletionHandler,
    ) Error!u64 {
        return self.flushPendingAsyncInternal(completion, null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn flushPendingAsyncTimeout(
        self: *CommandQueue,
        completion: CompletionHandler,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.flushPendingAsyncInternal(
            completion,
            .{ .duration = timeout },
        );
    }

    pub fn flushPendingAsyncWithDeadline(
        self: *CommandQueue,
        completion: CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!u64 {
        try validateEnqueueDeadline(self.io, deadline);
        return self.flushPendingAsyncInternal(
            completion,
            .{ .deadline = deadline },
        );
    }

    fn flushPendingAsyncInternal(
        self: *CommandQueue,
        completion: CompletionHandler,
        enqueue_wait: ?EnqueueWait,
    ) EnqueueTimeoutError!u64 {
        self.allocator_mutex.lockUncancelable(self.io);
        defer self.allocator_mutex.unlock(self.io);
        const command = try self.allocator.create(Command);
        errdefer self.allocator.destroy(command);
        const command_id = try self.nextCommandId();
        command.* = .{
            .operation = .flush_pending,
            .async_completion = .{
                .command_id = command_id,
                .handler = completion,
            },
            .owner = self,
        };
        try self.enqueueOwnedMaybeWait(command, enqueue_wait);
        return command_id;
    }

    pub fn beginReauthentication(
        self: *CommandQueue,
        properties: []const mqtt.Property,
    ) Error!void {
        var command = Command{
            .operation = .{ .begin_reauthentication = properties },
        };
        try self.submit(&command);
    }

    /// Deep-copy the MQTT 5 AUTH properties and enqueue the first
    /// re-authentication packet without waiting for its socket write. This
    /// completion covers the initiating write; subsequent AUTH exchanges are
    /// surfaced by the reconnect event loop.
    pub fn beginReauthenticationAsync(
        self: *CommandQueue,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
    ) Error!u64 {
        return self.beginReauthenticationAsyncInternal(
            properties,
            completion,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn beginReauthenticationAsyncTimeout(
        self: *CommandQueue,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.beginReauthenticationAsyncInternal(
            properties,
            completion,
            .{ .duration = timeout },
        );
    }

    pub fn beginReauthenticationAsyncWithDeadline(
        self: *CommandQueue,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!u64 {
        try validateEnqueueDeadline(self.io, deadline);
        return self.beginReauthenticationAsyncInternal(
            properties,
            completion,
            .{ .deadline = deadline },
        );
    }

    fn beginReauthenticationAsyncInternal(
        self: *CommandQueue,
        properties: []const mqtt.Property,
        completion: CompletionHandler,
        enqueue_wait: ?EnqueueWait,
    ) EnqueueTimeoutError!u64 {
        self.allocator_mutex.lockUncancelable(self.io);
        defer self.allocator_mutex.unlock(self.io);
        const command = try self.allocator.create(Command);
        errdefer self.allocator.destroy(command);
        const copied_properties = try owned_properties.clone(
            self.allocator,
            properties,
            owned_properties.keepAll,
        );
        errdefer owned_properties.deinit(
            self.allocator,
            copied_properties.properties,
        );
        const command_id = try self.nextCommandId();
        command.* = .{
            .operation = .{
                .begin_reauthentication_owned = copied_properties.properties,
            },
            .async_completion = .{
                .command_id = command_id,
                .handler = completion,
            },
            .owner = self,
        };
        try self.enqueueOwnedMaybeWait(command, enqueue_wait);
        return command_id;
    }

    fn enqueueOwnedMaybeWait(
        self: *CommandQueue,
        command: *Command,
        wait: ?EnqueueWait,
    ) EnqueueTimeoutError!void {
        if (wait) |bounded| {
            return switch (bounded) {
                .duration => |duration| self.enqueueOwnedTimeout(
                    command,
                    duration,
                ),
                .deadline => |deadline| self.enqueueOwnedWithDeadline(
                    command,
                    deadline,
                ),
            };
        }
        return self.enqueueOwned(command);
    }

    fn submit(self: *CommandQueue, command: *Command) Error!void {
        self.queue.putOne(self.io, command) catch |err| switch (err) {
            error.Closed => return error.CommandQueueClosed,
            error.Canceled => return error.Canceled,
        };
        // Once the pointer is visible to the consumer the stack request must
        // stay alive. Cancellation is therefore deferred until completion.
        command.completed.waitUncancelable(self.io);
        if (command.err) |err| return err;
    }

    fn nextCommandId(self: *CommandQueue) Error!u64 {
        // Zero is a permanent exhausted sentinel. A wrapping fetchAdd would
        // otherwise make identifiers repeat after reporting exhaustion once.
        var current = self.next_command_id.load(.monotonic);
        while (current != 0) {
            const next = if (current == std.math.maxInt(u64)) 0 else current + 1;
            if (self.next_command_id.cmpxchgWeak(
                current,
                next,
                .monotonic,
                .monotonic,
            )) |observed| {
                current = observed;
            } else {
                return current;
            }
        }
        return error.CommandIdentifierExhausted;
    }

    fn enqueueOwned(self: *CommandQueue, command: *Command) Error!void {
        _ = self.async_commands.fetchAdd(1, .monotonic);
        errdefer _ = self.async_commands.fetchSub(1, .monotonic);
        const count = self.queue.put(self.io, &.{command}, 0) catch |err|
            switch (err) {
                error.Closed => return error.CommandQueueClosed,
                error.Canceled => return error.Canceled,
            };
        if (count == 0) return error.CommandQueueFull;
    }

    fn enqueueOwnedTimeout(
        self: *CommandQueue,
        command: *Command,
        timeout: std.Io.Duration,
    ) EnqueueTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.enqueueOwnedWithDeadline(command, .fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    fn enqueueOwnedWithDeadline(
        self: *CommandQueue,
        command: *Command,
        deadline: std.Io.Clock.Timestamp,
    ) EnqueueTimeoutError!void {
        try validateEnqueueDeadline(self.io, deadline);
        _ = self.async_commands.fetchAdd(1, .monotonic);
        var transferred = false;
        errdefer if (!transferred) {
            _ = self.async_commands.fetchSub(1, .monotonic);
        };

        const PutResult = (std.Io.QueueClosedError ||
            std.Io.Cancelable)!void;
        const Wake = union(enum) {
            put: PutResult,
            timeout: std.Io.Cancelable!void,
        };
        var wake_buffer: [2]Wake = undefined;
        var select: std.Io.Select(Wake) = .init(self.io, &wake_buffer);
        try select.concurrent(.put, putOwned, .{ self, command });
        select.concurrent(
            .timeout,
            waitForEnqueueDeadline,
            .{ self.io, deadline },
        ) catch |err| {
            while (select.cancel()) |wake| switch (wake) {
                .put => |result| {
                    result catch continue;
                    transferred = true;
                },
                .timeout => {},
            };
            if (transferred) return;
            return err;
        };

        const first = select.await() catch |err| {
            while (select.cancel()) |wake| switch (wake) {
                .put => |result| {
                    result catch continue;
                    transferred = true;
                },
                .timeout => {},
            };
            if (transferred) return;
            return err;
        };
        switch (first) {
            .put => |result| {
                defer select.cancelDiscard();
                result catch |err| switch (err) {
                    error.Closed => return error.CommandQueueClosed,
                    error.Canceled => return error.Canceled,
                };
                transferred = true;
            },
            .timeout => |result| {
                try result;
                while (select.cancel()) |wake| switch (wake) {
                    .put => |put_result| {
                        put_result catch continue;
                        transferred = true;
                    },
                    .timeout => {},
                };
                // If queue capacity became available exactly as the timeout
                // fired, accepting the command wins: returning Timeout after
                // ownership transferred would hide a live completion ID.
                if (!transferred) return error.Timeout;
            },
        }
    }

    fn putOwned(
        self: *CommandQueue,
        command: *Command,
    ) (std.Io.QueueClosedError || std.Io.Cancelable)!void {
        return self.queue.putOne(self.io, command);
    }

    fn waitForEnqueueDeadline(
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) std.Io.Cancelable!void {
        try deadline.wait(io);
    }

    pub fn take(self: *CommandQueue) Error!?*Command {
        var commands: [1]*Command = undefined;
        const count = self.queue.get(self.io, &commands, 0) catch |err|
            switch (err) {
                error.Closed => return error.CommandQueueClosed,
                error.Canceled => return error.Canceled,
            };
        return if (count == 0) null else commands[0];
    }

    /// Close the channel, wake blocked producers, and fail buffered requests.
    pub fn stop(self: *CommandQueue, reason: Error) void {
        self.queue.close(self.io);
        while (true) {
            var commands: [1]*Command = undefined;
            const count = self.queue.getUncancelable(
                self.io,
                &commands,
                0,
            ) catch break;
            if (count == 0) break;
            commands[0].finishFailure(self.io, reason);
        }
    }
};

pub const Command = struct {
    pub const Disconnect = struct {
        reason_code: u8,
        properties: []const mqtt.Property,
    };

    pub const OwnedDisconnect = struct {
        reason_code: u8,
        properties: []mqtt.Property,
    };

    pub const Acknowledge = struct {
        packet_id: u16,
        qos: mqtt.QoS,
        options: runtime.AcknowledgeOptions,
    };

    pub const OwnedAcknowledge = struct {
        packet_id: u16,
        qos: mqtt.QoS,
        reason_code: u8,
        properties: []mqtt.Property,
    };

    pub const Operation = union(enum) {
        publish: struct {
            topic: []const u8,
            payload: []const u8,
            options: runtime.PublishOptions,
        },
        publish_owned: struct {
            topic: []u8,
            payload: []u8,
            qos: mqtt.QoS,
            retain: bool,
            dup: bool,
            properties: []mqtt.Property,
        },
        subscribe_owned: struct {
            subscriptions: []OwnedSubscription,
            properties: []mqtt.Property,
        },
        unsubscribe_owned: struct {
            filters: [][]const u8,
            properties: []mqtt.Property,
        },
        disconnect: Disconnect,
        disconnect_owned: OwnedDisconnect,
        acknowledge: Acknowledge,
        acknowledge_owned: OwnedAcknowledge,
        flush_pending,
        begin_reauthentication: []const mqtt.Property,
        begin_reauthentication_owned: []mqtt.Property,
    };

    operation: Operation,
    completed: std.Io.Event = .unset,
    err: ?Error = null,
    packet_id: ?u16 = null,
    async_completion: ?struct {
        command_id: u64,
        handler: CompletionHandler,
    } = null,
    owner: ?*CommandQueue = null,

    pub fn finishSuccess(
        self: *Command,
        io: std.Io,
        packet_id: ?u16,
    ) void {
        self.packet_id = packet_id;
        if (self.async_completion) |completion| {
            completion.handler.complete(completion.handler.context, .{
                .command_id = completion.command_id,
                .result = .{ .publish = packet_id },
            });
            self.deinitOwnedFromIo(io);
            return;
        }
        self.completed.set(io);
    }

    pub fn finishFailure(
        self: *Command,
        io: std.Io,
        err: Error,
    ) void {
        self.err = err;
        if (self.async_completion) |completion| {
            completion.handler.complete(completion.handler.context, .{
                .command_id = completion.command_id,
                .result = err,
            });
            self.deinitOwnedFromIo(io);
            return;
        }
        self.completed.set(io);
    }

    pub fn finishSubAck(
        self: *Command,
        io: std.Io,
        suback: *runtime.OwnedSubAck,
    ) void {
        const completion = self.async_completion.?;
        completion.handler.complete(completion.handler.context, .{
            .command_id = completion.command_id,
            .result = .{ .subscribe = .{
                .packet_id = suback.suback.packet_id,
                .reason_codes = suback.suback.reason_codes,
                .properties = suback.suback.properties,
            } },
        });
        suback.deinit(self.owner.?.allocator);
        self.deinitOwnedFromIo(io);
    }

    pub fn finishUnsubAck(
        self: *Command,
        io: std.Io,
        unsuback: *runtime.OwnedUnsubAck,
    ) void {
        const completion = self.async_completion.?;
        completion.handler.complete(completion.handler.context, .{
            .command_id = completion.command_id,
            .result = .{ .unsubscribe = .{
                .packet_id = unsuback.unsuback.packet_id,
                .reason_codes = unsuback.unsuback.reason_codes,
                .properties = unsuback.unsuback.properties,
            } },
        });
        unsuback.deinit(self.owner.?.allocator);
        self.deinitOwnedFromIo(io);
    }

    pub fn finishDisconnect(self: *Command, io: std.Io) void {
        if (self.async_completion) |completion| {
            completion.handler.complete(completion.handler.context, .{
                .command_id = completion.command_id,
                .result = .{ .disconnect = {} },
            });
            self.deinitOwnedFromIo(io);
            return;
        }
        self.completed.set(io);
    }

    pub fn finishAcknowledge(self: *Command, io: std.Io) void {
        if (self.async_completion) |completion| {
            completion.handler.complete(completion.handler.context, .{
                .command_id = completion.command_id,
                .result = .{ .acknowledge = {} },
            });
            self.deinitOwnedFromIo(io);
            return;
        }
        self.completed.set(io);
    }

    pub fn finishFlushPending(self: *Command, io: std.Io) void {
        self.finishVoid(io, .{ .flush_pending = {} });
    }

    pub fn finishReauthentication(self: *Command, io: std.Io) void {
        self.finishVoid(io, .{ .begin_reauthentication = {} });
    }

    fn finishVoid(self: *Command, io: std.Io, result: Completion.Result) void {
        if (self.async_completion) |completion| {
            completion.handler.complete(completion.handler.context, .{
                .command_id = completion.command_id,
                .result = result,
            });
            self.deinitOwnedFromIo(io);
            return;
        }
        self.completed.set(io);
    }

    fn deinitOwnedFromIo(self: *Command, _: std.Io) void {
        const owner = self.owner.?;
        self.deinitOwned(owner);
    }

    fn deinitOwned(self: *Command, owner: *CommandQueue) void {
        owner.allocator_mutex.lockUncancelable(owner.io);
        defer owner.allocator_mutex.unlock(owner.io);
        switch (self.operation) {
            .publish_owned => |publish| {
                owned_properties.deinit(
                    owner.allocator,
                    publish.properties,
                );
                owner.allocator.free(publish.payload);
                owner.allocator.free(publish.topic);
            },
            .subscribe_owned => |subscribe| {
                owned_properties.deinit(
                    owner.allocator,
                    subscribe.properties,
                );
                deinitSubscriptions(
                    owner.allocator,
                    subscribe.subscriptions,
                );
            },
            .unsubscribe_owned => |unsubscribe| {
                owned_properties.deinit(
                    owner.allocator,
                    unsubscribe.properties,
                );
                deinitStrings(owner.allocator, unsubscribe.filters);
            },
            .disconnect_owned => |disconnect_command| {
                owned_properties.deinit(
                    owner.allocator,
                    disconnect_command.properties,
                );
            },
            .acknowledge_owned => |acknowledge_command| {
                owned_properties.deinit(
                    owner.allocator,
                    acknowledge_command.properties,
                );
            },
            .begin_reauthentication_owned => |properties| {
                owned_properties.deinit(owner.allocator, properties);
            },
            else => {},
        }
        const previous = owner.async_commands.fetchSub(1, .release);
        std.debug.assert(previous != 0);
        owner.allocator.destroy(self);
    }
};

pub const Completion = struct {
    command_id: u64,
    result: Error!Result,

    pub const Result = union(enum) {
        publish: ?u16,
        subscribe: Ack,
        unsubscribe: Ack,
        disconnect: void,
        acknowledge: void,
        flush_pending: void,
        begin_reauthentication: void,
    };

    pub const Ack = struct {
        packet_id: u16,
        /// Both slices are borrowed until the completion callback returns.
        reason_codes: []const u8,
        properties: []const mqtt.Property,
    };
};

/// An owned command result removed from a `CompletionQueue`. Unlike the
/// callback-only `Completion`, acknowledgement slices remain valid until
/// `deinit` is called. The originating queue must outlive this value because
/// it serializes allocator access for producers and consumers.
pub const OwnedCompletion = struct {
    command_id: u64,
    result: Error!Result,
    owner: *CompletionQueue,

    pub const Result = union(enum) {
        publish: ?u16,
        subscribe: Ack,
        unsubscribe: Ack,
        disconnect: void,
        acknowledge: void,
        flush_pending: void,
        begin_reauthentication: void,
    };

    pub const Ack = struct {
        packet_id: u16,
        reason_codes: []u8,
        properties: []mqtt.Property,
    };

    fn capture(
        owner: *CompletionQueue,
        completion: Completion,
    ) OwnedCompletion {
        const borrowed = completion.result catch |err| {
            return .{
                .command_id = completion.command_id,
                .result = err,
                .owner = owner,
            };
        };
        const result = cloneResult(owner.allocator, borrowed) catch |err| {
            return .{
                .command_id = completion.command_id,
                .result = err,
                .owner = owner,
            };
        };
        return .{
            .command_id = completion.command_id,
            .result = result,
            .owner = owner,
        };
    }

    fn cloneResult(
        allocator: std.mem.Allocator,
        result: Completion.Result,
    ) Error!Result {
        return switch (result) {
            .publish => |packet_id| .{ .publish = packet_id },
            .subscribe => |ack| .{ .subscribe = try cloneAck(allocator, ack) },
            .unsubscribe => |ack| .{
                .unsubscribe = try cloneAck(allocator, ack),
            },
            .disconnect => .{ .disconnect = {} },
            .acknowledge => .{ .acknowledge = {} },
            .flush_pending => .{ .flush_pending = {} },
            .begin_reauthentication => .{ .begin_reauthentication = {} },
        };
    }

    fn cloneAck(
        allocator: std.mem.Allocator,
        ack: Completion.Ack,
    ) Error!Ack {
        const reason_codes = try allocator.dupe(u8, ack.reason_codes);
        errdefer allocator.free(reason_codes);
        const properties = try owned_properties.clone(
            allocator,
            ack.properties,
            owned_properties.keepAll,
        );
        return .{
            .packet_id = ack.packet_id,
            .reason_codes = reason_codes,
            .properties = properties.properties,
        };
    }

    pub fn deinit(self: *OwnedCompletion) void {
        const owner = self.owner;
        owner.allocator_mutex.lockUncancelable(owner.io);
        defer owner.allocator_mutex.unlock(owner.io);
        if (self.result) |result| switch (result) {
            .publish => {},
            .subscribe => |ack| deinitAck(owner.allocator, ack),
            .unsubscribe => |ack| deinitAck(owner.allocator, ack),
            .disconnect => {},
            .acknowledge => {},
            .flush_pending => {},
            .begin_reauthentication => {},
        } else |_| {}
        const previous = owner.outstanding.fetchSub(1, .release);
        std.debug.assert(previous != 0);
        self.* = undefined;
    }

    fn deinitAck(allocator: std.mem.Allocator, ack: Ack) void {
        owned_properties.deinit(allocator, ack.properties);
        allocator.free(ack.reason_codes);
    }
};

pub const CompletionQueueError = std.mem.Allocator.Error ||
    std.Io.Cancelable || error{CompletionQueueClosed};
pub const CompletionQueueReceiveTimeoutError = CompletionQueueError ||
    std.Io.Timeout.Error || std.Io.ConcurrentError;

/// Bounded, thread-safe sink for asynchronous command completions. It adapts
/// the callback API while deep-owning SUBACK/UNSUBACK data, allowing another
/// thread to await and inspect results after the loop callback has returned.
/// Capacity is intentional backpressure: the MQTT loop waits when this queue
/// is full, so consumers must drain it while commands are in flight. Its
/// allocator must support concurrent use when shared with command producers.
pub const CompletionQueue = struct {
    pub const ReceiveTimeoutError = CompletionQueueReceiveTimeoutError;

    allocator: std.mem.Allocator,
    io: std.Io,
    storage: []OwnedCompletion,
    queue: std.Io.Queue(OwnedCompletion),
    allocator_mutex: std.Io.Mutex = .init,
    outstanding: std.atomic.Value(usize) = .init(0),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        capacity: usize,
    ) std.mem.Allocator.Error!CompletionQueue {
        const storage = try allocator.alloc(OwnedCompletion, capacity);
        return .{
            .allocator = allocator,
            .io = io,
            .storage = storage,
            .queue = .init(storage),
        };
    }

    /// Call only after all command producers have stopped and after releasing
    /// every completion previously returned by `receive` or `tryReceive`.
    pub fn deinit(self: *CompletionQueue) void {
        self.close();
        while (true) {
            var values: [1]OwnedCompletion = undefined;
            const count = self.queue.getUncancelable(
                self.io,
                &values,
                0,
            ) catch break;
            if (count == 0) break;
            values[0].deinit();
        }
        std.debug.assert(self.outstanding.load(.acquire) == 0);
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn handler(self: *CompletionQueue) CompletionHandler {
        return .{ .context = self, .complete = captureCompletion };
    }

    pub fn receive(self: *CompletionQueue) CompletionQueueError!OwnedCompletion {
        return self.queue.getOne(self.io) catch |err| switch (err) {
            error.Closed => error.CompletionQueueClosed,
            error.Canceled => error.Canceled,
        };
    }

    pub fn tryReceive(
        self: *CompletionQueue,
    ) CompletionQueueError!?OwnedCompletion {
        var values: [1]OwnedCompletion = undefined;
        const count = self.queue.get(self.io, &values, 0) catch |err|
            switch (err) {
                error.Closed => return error.CompletionQueueClosed,
                error.Canceled => return error.Canceled,
            };
        return if (count == 0) null else values[0];
    }

    /// Wait for one completion up to the supplied duration. The completion
    /// branch owns its value as soon as the queue removes it, so cancellation
    /// cleanup must release a concurrently completed but unselected value.
    pub fn receiveTimeout(
        self: *CompletionQueue,
        timeout: std.Io.Duration,
    ) CompletionQueueReceiveTimeoutError!OwnedCompletion {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(.fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    /// Wait for one completion until the caller's absolute awake-clock
    /// deadline. A completion removed concurrently with timeout remains owned
    /// by the select cleanup path and is never leaked.
    pub fn receiveWithDeadline(
        self: *CompletionQueue,
        deadline: std.Io.Clock.Timestamp,
    ) CompletionQueueReceiveTimeoutError!OwnedCompletion {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        const Wake = union(enum) {
            completion: (std.Io.QueueClosedError ||
                std.Io.Cancelable)!OwnedCompletion,
            timeout: std.Io.Cancelable!void,
        };
        var buffer: [2]Wake = undefined;
        var select: std.Io.Select(Wake) = .init(self.io, &buffer);
        defer while (select.cancel()) |wake| switch (wake) {
            .completion => |result| if (result) |owned_value| {
                var owned = owned_value;
                owned.deinit();
            } else |_| {},
            .timeout => {},
        };
        try select.concurrent(.completion, receiveRaw, .{self});
        try select.concurrent(
            .timeout,
            waitForDeadline,
            .{ self.io, deadline },
        );
        return switch (try select.await()) {
            .completion => |result| result catch |err| switch (err) {
                error.Closed => error.CompletionQueueClosed,
                error.Canceled => error.Canceled,
            },
            .timeout => |result| {
                try result;
                return error.Timeout;
            },
        };
    }

    pub fn close(self: *CompletionQueue) void {
        self.queue.close(self.io);
    }

    fn receiveRaw(
        self: *CompletionQueue,
    ) (std.Io.QueueClosedError || std.Io.Cancelable)!OwnedCompletion {
        return self.queue.getOne(self.io);
    }

    fn waitForDeadline(
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) std.Io.Cancelable!void {
        try deadline.wait(io);
    }

    fn captureCompletion(
        context: *anyopaque,
        completion: Completion,
    ) void {
        const self: *CompletionQueue = @ptrCast(@alignCast(context));
        self.allocator_mutex.lockUncancelable(self.io);
        var owned = OwnedCompletion.capture(self, completion);
        _ = self.outstanding.fetchAdd(1, .monotonic);
        self.allocator_mutex.unlock(self.io);

        self.queue.putOneUncancelable(self.io, owned) catch {
            // Closing the sink explicitly discards future completions, but any
            // owned ACK data still has to be released on the producer thread.
            owned.deinit();
        };
    }
};

pub const OwnedSubscription = owned_subscription.Owned;

fn cloneSubscriptions(
    allocator: std.mem.Allocator,
    subscriptions: []const mqtt.Subscription,
) Error![]OwnedSubscription {
    const owned = try allocator.alloc(OwnedSubscription, subscriptions.len);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |*subscription| {
            subscription.deinit(allocator);
        }
        allocator.free(owned);
    }
    for (subscriptions, owned) |source, *target| {
        target.* = try OwnedSubscription.clone(allocator, source, &.{});
        initialized += 1;
    }
    return owned;
}

fn deinitSubscriptions(
    allocator: std.mem.Allocator,
    subscriptions: []OwnedSubscription,
) void {
    for (subscriptions) |*value| {
        value.deinit(allocator);
    }
    allocator.free(subscriptions);
}

fn cloneStrings(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) std.mem.Allocator.Error![][]const u8 {
    const owned = try allocator.alloc([]const u8, values.len);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |value| allocator.free(value);
        allocator.free(owned);
    }
    for (values, owned) |source, *target| {
        target.* = try allocator.dupe(u8, source);
        initialized += 1;
    }
    return owned;
}

fn deinitStrings(allocator: std.mem.Allocator, values: [][]const u8) void {
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

pub const CompletionHandler = struct {
    context: *anyopaque,
    /// Invoked exactly once for an accepted command: normally on the MQTT loop
    /// thread, or on the thread that drains buffered commands during `stop`.
    /// The callback must return promptly and must not synchronously wait on a
    /// command submitted to this same queue.
    complete: *const fn (context: *anyopaque, completion: Completion) void,
};

const TestCompletion = struct {
    calls: usize = 0,
    ids: [6]u64 = .{ 0, 0, 0, 0, 0, 0 },
    errors: [6]?anyerror = .{ null, null, null, null, null, null },

    fn complete(context: *anyopaque, completion: Completion) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const index = self.calls;
        self.calls += 1;
        self.ids[index] = completion.command_id;
        _ = completion.result catch |err| {
            self.errors[index] = err;
            return;
        };
    }

    fn handler(self: *@This()) CompletionHandler {
        return .{ .context = self, .complete = complete };
    }
};

test "MQTT command queue supports zero-capacity rendezvous storage" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    try std.testing.expectEqual(@as(usize, 0), queue.queue.capacity());
}

test "MQTT asynchronous command identifiers stay exhausted after overflow" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    queue.next_command_id.store(std.math.maxInt(u64), .monotonic);

    try std.testing.expectEqual(
        std.math.maxInt(u64),
        try queue.nextCommandId(),
    );
    try std.testing.expectError(
        error.CommandIdentifierExhausted,
        queue.nextCommandId(),
    );
    try std.testing.expectError(
        error.CommandIdentifierExhausted,
        queue.nextCommandId(),
    );
}

test "MQTT completion queue owns acknowledgement data" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CompletionQueue.init(std.testing.allocator, io, 2);
    defer queue.deinit();
    try std.testing.expect((try queue.tryReceive()) == null);

    var reason_codes: [2]u8 = .{ 0x00, 0x01 };
    var reason: [8]u8 = "accepted".*;
    var properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .reason_string,
        .value = &reason,
    } }};
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .command_id = 41,
        .result = .{ .subscribe = .{
            .packet_id = 7,
            .reason_codes = &reason_codes,
            .properties = &properties,
        } },
    });
    @memset(&reason_codes, 0xff);
    @memcpy(&reason, "modified");
    properties[0] = .{ .byte = .{
        .id = .maximum_qos,
        .value = 0,
    } };

    var completion = try queue.receive();
    defer completion.deinit();
    try std.testing.expectEqual(@as(u64, 41), completion.command_id);
    const result = try completion.result;
    switch (result) {
        .subscribe => |ack| {
            try std.testing.expectEqual(@as(u16, 7), ack.packet_id);
            try std.testing.expectEqualSlices(
                u8,
                &.{ 0x00, 0x01 },
                ack.reason_codes,
            );
            try std.testing.expectEqualStrings(
                "accepted",
                ack.properties[0].utf8.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MQTT completion queue receive timeout returns data and timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CompletionQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();

    try std.testing.expectError(
        error.Timeout,
        queue.receiveTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        queue.receiveWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );

    const handler = queue.handler();
    handler.complete(handler.context, .{
        .command_id = 45,
        .result = .{ .publish = 23 },
    });
    var completion = try queue.receiveWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer completion.deinit();
    try std.testing.expectEqual(@as(u64, 45), completion.command_id);
    const result = try completion.result;
    switch (result) {
        .publish => |packet_id| try std.testing.expectEqual(
            @as(?u16, 23),
            packet_id,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "MQTT completion queue close wakes a timed receiver" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CompletionQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();

    const Consumer = struct {
        io: std.Io,
        queue: *CompletionQueue,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            var completion = self.queue.receiveTimeout(
                .fromSeconds(30),
            ) catch |err| {
                self.err = err;
                return;
            };
            completion.deinit();
            self.err = error.TestUnexpectedResult;
        }
    };
    var consumer = Consumer{ .io = io, .queue = &queue };
    const thread = try std.Thread.spawn(.{}, Consumer.run, .{&consumer});
    consumer.started.waitUncancelable(io);
    queue.queue.close(io);
    thread.join();
    try std.testing.expectEqual(
        error.CompletionQueueClosed,
        consumer.err.?,
    );
}

test "MQTT completion queue preserves failures and close semantics" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CompletionQueue.init(
        std.testing.allocator,
        threaded.io(),
        1,
    );
    defer queue.deinit();
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .command_id = 42,
        .result = error.ConnectionUnavailable,
    });

    var completion = try queue.receive();
    defer completion.deinit();
    try std.testing.expectEqual(@as(u64, 42), completion.command_id);
    try std.testing.expectError(
        error.ConnectionUnavailable,
        completion.result,
    );
    queue.close();
    handler.complete(handler.context, .{
        .command_id = 44,
        .result = .{ .subscribe = .{
            .packet_id = 10,
            .reason_codes = &.{0x00},
            .properties = &.{.{ .utf8 = .{
                .id = .reason_string,
                .value = "discarded",
            } }},
        } },
    });
    try std.testing.expectError(
        error.CompletionQueueClosed,
        queue.tryReceive(),
    );
}

test "MQTT completion queue allocation failures are owned results" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCompletionQueueAllocationFailure,
        .{},
    );
}

fn checkCompletionQueueAllocationFailure(allocator: std.mem.Allocator) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CompletionQueue.init(allocator, threaded.io(), 1);
    defer queue.deinit();
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .command_id = 43,
        .result = .{ .unsubscribe = .{
            .packet_id = 9,
            .reason_codes = &.{0x00},
            .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "allocation",
                .value = "failure",
            } }},
        } },
    });
    var completion = try queue.receive();
    defer completion.deinit();
    _ = completion.result catch |err| return err;
}

test "MQTT command queue stop wakes a pending producer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 0);
    defer queue.deinit();

    const Producer = struct {
        io: std.Io,
        queue: *CommandQueue,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            self.queue.flushPending() catch |err| {
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var producer = Producer{ .io = io, .queue = &queue };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    producer.started.waitUncancelable(io);
    queue.stop(error.CommandQueueClosed);
    thread.join();
    try std.testing.expectEqual(
        error.CommandQueueClosed,
        producer.err.?,
    );
}

test "MQTT async publish rejects a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 0);
    defer queue.deinit();
    const CompletionContext = struct {
        fn complete(_: *anyopaque, _: Completion) void {}
    };
    var context: u8 = 0;
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.publishAsync(
            "full/topic",
            "payload",
            .{ .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "key",
                .value = "value",
            } }} },
            .{
                .context = &context,
                .complete = CompletionContext.complete,
            },
        ),
    );
}

test "MQTT async publish deadline releases an unqueued command" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const first_id = try queue.publishAsync(
        "queued/first",
        "first",
        .{},
        completion.handler(),
    );

    try std.testing.expectError(
        error.Timeout,
        queue.publishAsyncWithDeadline(
            "queued/timeout",
            "not accepted",
            .{ .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "owned",
                .value = "until timeout",
            } }} },
            completion.handler(),
            .fromNow(io, .{
                .raw = .fromMilliseconds(1),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), queue.async_commands.load(
        .acquire,
    ));
    try std.testing.expectEqual(@as(usize, 0), completion.calls);

    const first = (try queue.take()).?;
    first.finishFailure(io, error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 1), completion.calls);
    try std.testing.expectEqual(first_id, completion.ids[0]);
}

test "MQTT asynchronous command timeout variants reject expired waits" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        1,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const handler = completion.handler();

    try std.testing.expectError(error.Timeout, queue.subscribeAsyncTimeout(
        &.{.{ .topic_filter = "timed/+" }},
        .{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.unsubscribeAsyncTimeout(
        &.{"timed/+"},
        .{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.disconnectAsyncTimeout(
        0,
        &.{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.acknowledgeAsyncTimeout(
        1,
        .at_least_once,
        .{},
        handler,
        .zero,
    ));
    try std.testing.expectError(error.Timeout, queue.flushPendingAsyncTimeout(
        handler,
        .zero,
    ));
    try std.testing.expectError(
        error.Timeout,
        queue.beginReauthenticationAsyncTimeout(
            &.{},
            handler,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
    try std.testing.expectEqual(@as(usize, 0), queue.async_commands.load(
        .acquire,
    ));
}

test "MQTT asynchronous command deadlines reject invalid budgets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const handler = completion.handler();
    const wrong_clock: std.Io.Clock.Timestamp = .{
        .raw = .zero,
        .clock = .real,
    };
    const expired = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .zero,
        .clock = .awake,
    });

    try std.testing.expectError(error.Timeout, queue.publishAsyncWithDeadline(
        "timed/publish",
        "payload",
        .{},
        handler,
        wrong_clock,
    ));
    try std.testing.expectError(error.Timeout, queue.subscribeAsyncWithDeadline(
        &.{.{ .topic_filter = "timed/+" }},
        .{},
        handler,
        expired,
    ));
    try std.testing.expectError(error.Timeout, queue.unsubscribeAsyncWithDeadline(
        &.{"timed/+"},
        .{},
        handler,
        wrong_clock,
    ));
    try std.testing.expectError(error.Timeout, queue.disconnectAsyncWithDeadline(
        0,
        &.{},
        handler,
        expired,
    ));
    try std.testing.expectError(error.Timeout, queue.acknowledgeAsyncWithDeadline(
        1,
        .at_least_once,
        .{},
        handler,
        wrong_clock,
    ));
    try std.testing.expectError(
        error.Timeout,
        queue.flushPendingAsyncWithDeadline(handler, expired),
    );
    try std.testing.expectError(
        error.Timeout,
        queue.beginReauthenticationAsyncWithDeadline(
            &.{},
            handler,
            wrong_clock,
        ),
    );
    // Deadline validation precedes both identifier allocation and deep-copy
    // ownership, so rejected calls cannot create hidden completion IDs.
    try std.testing.expectEqual(
        @as(u64, 1),
        queue.next_command_id.load(.monotonic),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
    try std.testing.expectEqual(@as(usize, 0), queue.async_commands.load(
        .acquire,
    ));
}

test "MQTT async publish deadline waits for bounded queue capacity" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    _ = try queue.publishAsync(
        "queued/first",
        "first",
        .{},
        completion.handler(),
    );

    const Producer = struct {
        io: std.Io,
        queue: *CommandQueue,
        completion: *TestCompletion,
        deadline: std.Io.Clock.Timestamp,
        started: std.Io.Event = .unset,
        result: ?EnqueueTimeoutError!u64 = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            self.result = self.queue.publishAsyncWithDeadline(
                "queued/second",
                "second",
                .{},
                self.completion.handler(),
                self.deadline,
            );
        }
    };
    var producer = Producer{
        .io = io,
        .queue = &queue,
        .completion = &completion,
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        }),
    };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    producer.started.waitUncancelable(io);
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);

    const first = (try queue.take()).?;
    thread.join();
    const second_id = try producer.result.?;
    const second = (try queue.take()).?;
    switch (second.operation) {
        .publish_owned => |publish| {
            try std.testing.expectEqualStrings(
                "queued/second",
                publish.topic,
            );
            try std.testing.expectEqualStrings("second", publish.payload);
        },
        else => return error.TestUnexpectedResult,
    }
    first.finishFailure(io, error.CommandQueueClosed);
    second.finishFailure(io, error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 2), completion.calls);
    try std.testing.expectEqual(second_id, completion.ids[1]);
}

test "MQTT async publish deadline observes queue close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    _ = try queue.publishAsync(
        "queued/first",
        "first",
        .{},
        completion.handler(),
    );

    const Producer = struct {
        io: std.Io,
        queue: *CommandQueue,
        completion: *TestCompletion,
        deadline: std.Io.Clock.Timestamp,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            _ = self.queue.publishAsyncWithDeadline(
                "queued/closed",
                "not accepted",
                .{},
                self.completion.handler(),
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var producer = Producer{
        .io = io,
        .queue = &queue,
        .completion = &completion,
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(30),
            .clock = .awake,
        }),
    };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    producer.started.waitUncancelable(io);
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    queue.queue.close(io);
    thread.join();
    try std.testing.expectEqual(error.CommandQueueClosed, producer.err.?);
    try std.testing.expectEqual(@as(usize, 1), queue.async_commands.load(
        .acquire,
    ));
    queue.stop(error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 1), completion.calls);
}

test "MQTT async subscription commands reject a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = "key",
        .value = "value",
    } }};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.subscribeAsync(
            &.{.{ .topic_filter = "full/+", .qos = .at_least_once }},
            .{ .properties = &properties },
            completion.handler(),
        ),
    );
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.unsubscribeAsync(
            &.{"full/+"},
            .{ .properties = &properties },
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async disconnect rejects a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.disconnectAsync(
            0x00,
            &.{.{ .utf8 = .{
                .id = .reason_string,
                .value = "queue full",
            } }},
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async acknowledgement rejects a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.acknowledgeAsync(
            7,
            .at_least_once,
            .{ .properties = &.{.{ .utf8 = .{
                .id = .reason_string,
                .value = "queue full",
            } }} },
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async control commands reject a full queue without leaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(
        std.testing.allocator,
        threaded.io(),
        0,
    );
    defer queue.deinit();
    var completion: TestCompletion = .{};
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.flushPendingAsync(completion.handler()),
    );
    try std.testing.expectError(
        error.CommandQueueFull,
        queue.beginReauthenticationAsync(
            &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = "mirror",
            } }},
            completion.handler(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), completion.calls);
}

test "MQTT async acknowledgement owns properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var reason: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .reason_string,
        .value = &reason,
    } }};
    _ = try queue.acknowledgeAsync(
        7,
        .at_least_once,
        .{ .reason_code = 0x10, .properties = &properties },
        completion.handler(),
    );
    @memcpy(&reason, "modified");

    const command = (try queue.take()).?;
    switch (command.operation) {
        .acknowledge_owned => |operation| {
            try std.testing.expectEqual(@as(u16, 7), operation.packet_id);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, operation.qos);
            try std.testing.expectEqual(@as(u8, 0x10), operation.reason_code);
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    command.finishFailure(io, error.CommandQueueClosed);
}

test "MQTT async reauthentication owns properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var authentication_data: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } },
        .{ .binary = .{
            .id = .authentication_data,
            .value = &authentication_data,
        } },
    };
    _ = try queue.beginReauthenticationAsync(
        &properties,
        completion.handler(),
    );
    @memcpy(&authentication_data, "modified");

    const command = (try queue.take()).?;
    switch (command.operation) {
        .begin_reauthentication_owned => |owned| {
            try std.testing.expectEqualStrings(
                "original",
                mqtt.authenticationData(owned).?,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    command.finishFailure(io, error.CommandQueueClosed);
}

test "MQTT async disconnect owns properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var reason: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{.{ .utf8 = .{
        .id = .reason_string,
        .value = &reason,
    } }};
    _ = try queue.disconnectAsync(
        0x00,
        &properties,
        completion.handler(),
    );
    @memcpy(&reason, "modified");

    const command = (try queue.take()).?;
    switch (command.operation) {
        .disconnect_owned => |operation| {
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    command.finishFailure(io, error.CommandQueueClosed);
}

test "MQTT async subscription commands own filters and properties" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    var filter: [11]u8 = "owned/topic".*;
    var key: [6]u8 = "source".*;
    var value: [8]u8 = "original".*;
    const properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = &key,
        .value = &value,
    } }};

    _ = try queue.subscribeAsync(
        &.{.{ .topic_filter = &filter, .qos = .exactly_once }},
        .{ .properties = &properties },
        completion.handler(),
    );
    @memcpy(&filter, "other/topic");
    @memcpy(&key, "target");
    @memcpy(&value, "modified");
    const subscribe = (try queue.take()).?;
    switch (subscribe.operation) {
        .subscribe_owned => |operation| {
            try std.testing.expectEqualStrings(
                "owned/topic",
                operation.subscriptions[0].filter,
            );
            try std.testing.expectEqual(mqtt.QoS.exactly_once, operation.subscriptions[0].qos);
            try std.testing.expectEqualStrings(
                "source",
                operation.properties[0].utf8_pair.key,
            );
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8_pair.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    subscribe.finishFailure(io, error.CommandQueueClosed);

    @memcpy(&filter, "owned/topic");
    @memcpy(&key, "source");
    @memcpy(&value, "original");
    _ = try queue.unsubscribeAsync(
        &.{&filter},
        .{ .properties = &properties },
        completion.handler(),
    );
    @memcpy(&filter, "other/topic");
    @memcpy(&key, "target");
    @memcpy(&value, "modified");
    const unsubscribe = (try queue.take()).?;
    switch (unsubscribe.operation) {
        .unsubscribe_owned => |operation| {
            try std.testing.expectEqualStrings(
                "owned/topic",
                operation.filters[0],
            );
            try std.testing.expectEqualStrings(
                "source",
                operation.properties[0].utf8_pair.key,
            );
            try std.testing.expectEqualStrings(
                "original",
                operation.properties[0].utf8_pair.value,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    unsubscribe.finishFailure(io, error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 2), completion.calls);
}

test "MQTT command queue completes buffered async publish on stop" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    const CompletionContext = struct {
        called: usize = 0,
        command_id: u64 = 0,
        err: ?anyerror = null,
        fn complete(
            context: *anyopaque,
            completion: Completion,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.called += 1;
            self.command_id = completion.command_id;
            _ = completion.result catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var completion: CompletionContext = .{};
    const command_id = try queue.publishAsync(
        "stopped/topic",
        "payload",
        .{},
        .{
            .context = &completion,
            .complete = CompletionContext.complete,
        },
    );
    queue.stop(error.CommandQueueClosed);
    try std.testing.expectEqual(@as(usize, 1), completion.called);
    try std.testing.expectEqual(command_id, completion.command_id);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.err.?);
}

test "MQTT command queue fails buffered async commands on stop" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 6);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const subscribe_id = try queue.subscribeAsync(
        &.{.{ .topic_filter = "stopped/+" }},
        .{},
        completion.handler(),
    );
    const unsubscribe_id = try queue.unsubscribeAsync(
        &.{"stopped/+"},
        .{},
        completion.handler(),
    );
    const disconnect_id = try queue.disconnectAsync(
        0x00,
        &.{.{ .utf8 = .{
            .id = .reason_string,
            .value = "stopped",
        } }},
        completion.handler(),
    );
    const acknowledge_id = try queue.acknowledgeAsync(
        7,
        .at_least_once,
        .{},
        completion.handler(),
    );
    const flush_id = try queue.flushPendingAsync(completion.handler());
    const reauthentication_id = try queue.beginReauthenticationAsync(
        &.{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } }},
        completion.handler(),
    );

    queue.stop(error.CommandQueueClosed);

    try std.testing.expectEqual(@as(usize, 6), completion.calls);
    try std.testing.expectEqual(subscribe_id, completion.ids[0]);
    try std.testing.expectEqual(unsubscribe_id, completion.ids[1]);
    try std.testing.expectEqual(disconnect_id, completion.ids[2]);
    try std.testing.expectEqual(acknowledge_id, completion.ids[3]);
    try std.testing.expectEqual(flush_id, completion.ids[4]);
    try std.testing.expectEqual(reauthentication_id, completion.ids[5]);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[0].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[1].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[2].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[3].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[4].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[5].?);
}

test "MQTT async command allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkAsyncCommandAllocationFailure,
        .{},
    );
}

fn checkAsyncCommandAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    var queue = try CommandQueue.init(allocator, threaded.io(), 2);
    defer queue.deinit();
    var completion: TestCompletion = .{};
    const properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = "allocation",
        .value = "failure",
    } }};
    _ = try queue.subscribeAsync(
        &.{
            .{ .topic_filter = "allocated/one" },
            .{ .topic_filter = "allocated/two", .qos = .exactly_once },
        },
        .{ .properties = &properties },
        completion.handler(),
    );
    _ = try queue.unsubscribeAsync(
        &.{ "allocated/one", "allocated/two" },
        .{ .properties = &properties },
        completion.handler(),
    );
    // Finish the two buffered commands so the third operation can exercise
    // every allocation point without depending on queue backpressure.
    (try queue.take()).?.finishFailure(
        threaded.io(),
        error.CommandQueueClosed,
    );
    (try queue.take()).?.finishFailure(
        threaded.io(),
        error.CommandQueueClosed,
    );
    _ = try queue.disconnectAsync(
        0x00,
        &properties,
        completion.handler(),
    );
    (try queue.take()).?.finishFailure(
        threaded.io(),
        error.CommandQueueClosed,
    );
    _ = try queue.acknowledgeAsync(
        7,
        .at_least_once,
        .{ .properties = &properties },
        completion.handler(),
    );
    (try queue.take()).?.finishFailure(
        threaded.io(),
        error.CommandQueueClosed,
    );
    _ = try queue.flushPendingAsync(completion.handler());
    (try queue.take()).?.finishFailure(
        threaded.io(),
        error.CommandQueueClosed,
    );
    _ = try queue.beginReauthenticationAsync(
        &properties,
        completion.handler(),
    );
}
