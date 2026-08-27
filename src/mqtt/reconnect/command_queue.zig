//! Bounded multi-producer command channel for the reconnect event loop.
//!
//! Synchronous requests borrow their payload until completion. Asynchronous
//! PUBLISH requests instead deep-copy all variable data, so producers may
//! return immediately while one loop retains exclusive transport ownership.

const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const session = @import("../session/mod.zig");
const owned_properties = @import("../owned_properties.zig");

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
        const command_id = self.next_command_id.fetchAdd(1, .monotonic);
        if (command_id == 0) return error.CommandIdentifierExhausted;
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
        _ = self.async_commands.fetchAdd(1, .monotonic);
        errdefer _ = self.async_commands.fetchSub(1, .monotonic);
        const count = self.queue.put(
            self.io,
            &.{command},
            0,
        ) catch |err| switch (err) {
            error.Closed => return error.CommandQueueClosed,
            error.Canceled => return error.Canceled,
        };
        // Queue ownership begins only after insertion. Before that point the
        // errdefers above retain responsibility for all allocations.
        if (count == 0) {
            return error.CommandQueueFull;
        }
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
                .result = packet_id,
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
            else => {},
        }
        const previous = owner.async_commands.fetchSub(1, .release);
        std.debug.assert(previous != 0);
        owner.allocator.destroy(self);
    }
};

pub const Completion = struct {
    command_id: u64,
    result: Error!?u16,
};

pub const CompletionHandler = struct {
    context: *anyopaque,
    /// Invoked on the MQTT loop thread exactly once for an accepted command.
    /// The callback must return promptly and must not synchronously wait on
    /// another command submitted to this same queue.
    complete: *const fn (context: *anyopaque, completion: Completion) void,
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
