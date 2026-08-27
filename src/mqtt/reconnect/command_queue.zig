//! Bounded multi-producer command channel for the reconnect event loop.
//!
//! Synchronous requests borrow their payload until completion. Asynchronous
//! PUBLISH, SUBSCRIBE, and UNSUBSCRIBE requests instead deep-copy all variable
//! data, so producers may return immediately while one loop retains exclusive
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
};

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
        try self.enqueueOwned(command);
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
        try self.enqueueOwned(command);
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
        try self.enqueueOwned(command);
        return command_id;
    }

    pub fn flushPending(self: *CommandQueue) Error!void {
        var command = Command{ .operation = .flush_pending };
        try self.submit(&command);
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
        flush_pending,
        begin_reauthentication: []const mqtt.Property,
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
    };

    pub const Ack = struct {
        packet_id: u16,
        /// Both slices are borrowed until the completion callback returns.
        reason_codes: []const u8,
        properties: []const mqtt.Property,
    };
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
    ids: [2]u64 = .{ 0, 0 },
    errors: [2]?anyerror = .{ null, null },

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

test "MQTT command queue fails buffered async subscription commands on stop" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try CommandQueue.init(std.testing.allocator, io, 2);
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

    queue.stop(error.CommandQueueClosed);

    try std.testing.expectEqual(@as(usize, 2), completion.calls);
    try std.testing.expectEqual(subscribe_id, completion.ids[0]);
    try std.testing.expectEqual(unsubscribe_id, completion.ids[1]);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[0].?);
    try std.testing.expectEqual(error.CommandQueueClosed, completion.errors[1].?);
}

test "MQTT async subscription allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkAsyncSubscriptionAllocationFailure,
        .{},
    );
}

fn checkAsyncSubscriptionAllocationFailure(
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
}
