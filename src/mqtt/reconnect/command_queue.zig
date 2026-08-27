//! Bounded multi-producer command channel for the reconnect event loop.
//!
//! Requests borrow their payload until completion, so producer-side methods
//! synchronously wait after enqueueing. This avoids a second deep copy while
//! ensuring the MQTT connection and its allocator remain owned by one loop.

const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const session = @import("../session/mod.zig");

pub const Error = runtime.Error || session.Error || std.Io.Cancelable || error{
    CommandQueueClosed,
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
        flush_pending,
        begin_reauthentication: []const mqtt.Property,
    };

    operation: Operation,
    completed: std.Io.Event = .unset,
    err: ?Error = null,
    packet_id: ?u16 = null,

    pub fn finishSuccess(
        self: *Command,
        io: std.Io,
        packet_id: ?u16,
    ) void {
        self.packet_id = packet_id;
        self.completed.set(io);
    }

    pub fn finishFailure(
        self: *Command,
        io: std.Io,
        err: Error,
    ) void {
        self.err = err;
        self.completed.set(io);
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
