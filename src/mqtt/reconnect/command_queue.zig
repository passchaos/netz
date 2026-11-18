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
    pub fn nextCommandId(self: *CommandQueue) Error!u64 {
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

pub const TestCompletion = struct {
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
    pub fn handler(self: *@This()) CompletionHandler {
        return .{ .context = self, .complete = complete };
    }
};

pub fn checkCompletionQueueAllocationFailure(allocator: std.mem.Allocator) !void {
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

pub fn checkAsyncCommandAllocationFailure(
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

test {
    _ = @import("command_queue/tests.zig");
}
