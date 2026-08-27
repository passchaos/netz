//! Owned queue adapter for terminal outbound PUBLISH delivery notifications.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");

pub fn Queue(comptime Delivery: type, comptime Handler: type) type {
    return struct {
        const Self = @This();

        pub const Error = std.Io.Cancelable || error{DeliveryQueueClosed};

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
