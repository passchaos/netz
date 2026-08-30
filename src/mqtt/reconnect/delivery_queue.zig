//! Owned queue adapter for terminal outbound PUBLISH delivery notifications.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");

pub fn Queue(comptime Delivery: type, comptime Handler: type) type {
    return struct {
        const Self = @This();

        pub const Error = std.Io.Cancelable || error{DeliveryQueueClosed};
        pub const ReceiveTimeoutError = Error || std.Io.Timeout.Error ||
            std.Io.ConcurrentError;

        pub const OwnedDelivery = struct {
            packet_id: ?u16,
            qos: mqtt.QoS,
            reason_code: u8,
            properties: []mqtt.Property,
            owner: *Self,

            pub fn deinit(self: *OwnedDelivery) void {
                const owner = self.owner;
                owner.allocator_mutex.lockUncancelable(owner.io);
                defer owner.allocator_mutex.unlock(owner.io);
                owned_properties.deinit(owner.allocator, self.properties);
                const previous = owner.outstanding.fetchSub(1, .release);
                std.debug.assert(previous != 0);
                self.* = undefined;
            }
        };

        allocator: std.mem.Allocator,
        io: std.Io,
        storage: []OwnedDelivery,
        queue: std.Io.Queue(OwnedDelivery),
        allocator_mutex: std.Io.Mutex = .init,
        outstanding: std.atomic.Value(usize) = .init(0),

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            capacity: usize,
        ) std.mem.Allocator.Error!Self {
            const storage = try allocator.alloc(OwnedDelivery, capacity);
            return .{
                .allocator = allocator,
                .io = io,
                .storage = storage,
                .queue = .init(storage),
            };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            while (true) {
                var values: [1]OwnedDelivery = undefined;
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

        pub fn handler(self: *Self) Handler {
            return .{ .context = self, .complete = capture };
        }

        pub fn receive(self: *Self) Error!OwnedDelivery {
            return self.queue.getOne(self.io) catch |err| switch (err) {
                error.Closed => error.DeliveryQueueClosed,
                error.Canceled => error.Canceled,
            };
        }

        pub fn tryReceive(self: *Self) Error!?OwnedDelivery {
            var values: [1]OwnedDelivery = undefined;
            const count = self.queue.get(self.io, &values, 0) catch |err|
                switch (err) {
                    error.Closed => return error.DeliveryQueueClosed,
                    error.Canceled => return error.Canceled,
                };
            return if (count == 0) null else values[0];
        }

        /// Wait for a delivery notification up to the supplied duration.
        pub fn receiveTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) ReceiveTimeoutError!OwnedDelivery {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveWithDeadline(.fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        /// Wait under one caller-owned absolute awake-clock budget. If queue
        /// delivery and the timer complete concurrently, cancellation cleanup
        /// releases any removed but unselected owned notification.
        pub fn receiveWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) ReceiveTimeoutError!OwnedDelivery {
            if (deadline.clock != .awake or
                deadline.durationFromNow(self.io).raw.nanoseconds <= 0)
            {
                return error.Timeout;
            }
            const Wake = union(enum) {
                delivery: (std.Io.QueueClosedError ||
                    std.Io.Cancelable)!OwnedDelivery,
                timeout: std.Io.Cancelable!void,
            };
            var buffer: [2]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(self.io, &buffer);
            defer while (select.cancel()) |wake| switch (wake) {
                .delivery => |result| if (result) |owned_value| {
                    var owned = owned_value;
                    owned.deinit();
                } else |_| {},
                .timeout => {},
            };
            try select.concurrent(.delivery, receiveRaw, .{self});
            try select.concurrent(
                .timeout,
                waitForDeadline,
                .{ self.io, deadline },
            );
            return switch (try select.await()) {
                .delivery => |result| result catch |err| switch (err) {
                    error.Closed => error.DeliveryQueueClosed,
                    error.Canceled => error.Canceled,
                },
                .timeout => |result| {
                    try result;
                    return error.Timeout;
                },
            };
        }

        pub fn close(self: *Self) void {
            self.queue.close(self.io);
        }

        fn capture(context: *anyopaque, delivery: Delivery) void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.allocator_mutex.lockUncancelable(self.io);
            const copied = owned_properties.clone(
                self.allocator,
                delivery.properties,
                owned_properties.keepAll,
            ) catch {
                self.allocator_mutex.unlock(self.io);
                return;
            };
            _ = self.outstanding.fetchAdd(1, .monotonic);
            self.allocator_mutex.unlock(self.io);
            var owned = OwnedDelivery{
                .packet_id = delivery.packet_id,
                .qos = delivery.qos,
                .reason_code = delivery.reason_code,
                .properties = copied.properties,
                .owner = self,
            };
            self.queue.putOneUncancelable(self.io, owned) catch {
                owned.deinit();
            };
        }

        fn receiveRaw(
            self: *Self,
        ) (std.Io.QueueClosedError || std.Io.Cancelable)!OwnedDelivery {
            return self.queue.getOne(self.io);
        }

        fn waitForDeadline(
            io: std.Io,
            deadline: std.Io.Clock.Timestamp,
        ) std.Io.Cancelable!void {
            try deadline.wait(io);
        }
    };
}

const TestDelivery = struct {
    packet_id: ?u16,
    qos: mqtt.QoS,
    reason_code: u8,
    properties: []const mqtt.Property,
};

const TestHandler = struct {
    context: *anyopaque,
    complete: *const fn (*anyopaque, TestDelivery) void,
};

const TestQueue = Queue(TestDelivery, TestHandler);

test "MQTT delivery queue owns properties and supports polling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try TestQueue.init(std.testing.allocator, io, 2);
    defer queue.deinit();
    try std.testing.expect((try queue.tryReceive()) == null);

    var reason: [8]u8 = "accepted".*;
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .packet_id = 17,
        .qos = .at_least_once,
        .reason_code = 0x10,
        .properties = &.{.{ .utf8 = .{
            .id = .reason_string,
            .value = &reason,
        } }},
    });
    @memcpy(&reason, "modified");

    var delivery = try queue.receive();
    defer delivery.deinit();
    try std.testing.expectEqual(@as(?u16, 17), delivery.packet_id);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, delivery.qos);
    try std.testing.expectEqual(@as(u8, 0x10), delivery.reason_code);
    try std.testing.expectEqualStrings(
        "accepted",
        delivery.properties[0].utf8.value,
    );
}

test "MQTT delivery queue receive timeout returns data and timeout" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try TestQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();
    try std.testing.expectError(
        error.Timeout,
        queue.receiveTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        queue.receiveWithDeadline(.{ .raw = .zero, .clock = .real }),
    );
    try std.testing.expectError(
        error.Timeout,
        queue.receiveWithDeadline(.fromNow(io, .{
            .raw = .zero,
            .clock = .awake,
        })),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        queue.outstanding.load(.acquire),
    );
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .packet_id = null,
        .qos = .at_most_once,
        .reason_code = 0,
        .properties = &.{},
    });
    try std.testing.expectError(
        error.Timeout,
        queue.receiveWithDeadline(.fromNow(io, .{
            .raw = .zero,
            .clock = .awake,
        })),
    );
    // An expired caller budget never consumes already-owned queue data.
    try std.testing.expectEqual(
        @as(usize, 1),
        queue.outstanding.load(.acquire),
    );
    var delivery = try queue.receiveWithDeadline(.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    }));
    defer delivery.deinit();
    try std.testing.expect(delivery.packet_id == null);
}

test "MQTT delivery queue deadline reports closure distinctly" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var queue = try TestQueue.init(std.testing.allocator, io, 1);
    defer queue.deinit();

    const Consumer = struct {
        io: std.Io,
        queue: *TestQueue,
        deadline: std.Io.Clock.Timestamp,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.io);
            var delivery = self.queue.receiveWithDeadline(
                self.deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
            delivery.deinit();
            self.err = error.TestUnexpectedResult;
        }
    };
    var consumer = Consumer{
        .io = io,
        .queue = &queue,
        .deadline = .fromNow(io, .{
            .raw = .fromSeconds(30),
            .clock = .awake,
        }),
    };
    const thread = try std.Thread.spawn(.{}, Consumer.run, .{&consumer});
    consumer.started.waitUncancelable(io);
    queue.close();
    thread.join();
    try std.testing.expectEqual(error.DeliveryQueueClosed, consumer.err.?);
}

test "MQTT delivery queue drops notifications after close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var queue = try TestQueue.init(
        std.testing.allocator,
        threaded.io(),
        1,
    );
    defer queue.deinit();
    queue.close();
    const handler = queue.handler();
    handler.complete(handler.context, .{
        .packet_id = 18,
        .qos = .exactly_once,
        .reason_code = 0,
        .properties = &.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "closed",
            .value = "discarded",
        } }},
    });
    try std.testing.expectError(
        error.DeliveryQueueClosed,
        queue.tryReceive(),
    );
}
