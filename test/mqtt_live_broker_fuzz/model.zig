const std = @import("std");

pub const max_operations = 12;
pub const max_sequence_bytes = max_operations;
pub const event_timeout = std.Io.Duration.fromSeconds(2);
pub const topics = [2][]const u8{
    "fuzz/live/zero",
    "fuzz/live/one",
};

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

pub const lifecycle_seed = smithSliceSeed(&.{
    0x03, 0x00, 0x08, 0x02, 0x07, 0x01,
    0x04, 0x05, 0x13, 0x10, 0x09, 0x02,
});
pub const replacement_seed = smithSliceSeed(&.{
    0x1b, 0x17, 0x1d, 0x18, 0x1d, 0x19,
    0x19, 0x0c, 0x08, 0x12, 0x0a, 0x02,
});
pub const corpus = &.{ &lifecycle_seed, &replacement_seed };

pub const Payload = struct {
    bytes: [3]u8,

    pub fn init(operation: u8, index: usize, topic_index: usize) Payload {
        return .{ .bytes = .{
            operation,
            @intCast(index),
            @intCast(0xa0 | topic_index),
        } };
    }
};

pub const ExpectedDelivery = struct {
    topic_index: usize,
    payload: [3]u8 = undefined,
    payload_len: usize,
    retain: bool,

    pub fn message(
        topic_index: usize,
        payload: Payload,
        retain: bool,
    ) ExpectedDelivery {
        return .{
            .topic_index = topic_index,
            .payload = payload.bytes,
            .payload_len = payload.bytes.len,
            .retain = retain,
        };
    }

    pub fn empty(topic_index: usize) ExpectedDelivery {
        return .{
            .topic_index = topic_index,
            .payload_len = 0,
            .retain = false,
        };
    }
};

pub const ExpectedQueue = struct {
    items: [max_operations]ExpectedDelivery = undefined,
    len: usize = 0,

    pub fn append(
        self: *ExpectedQueue,
        delivery: ExpectedDelivery,
    ) !void {
        if (self.len == self.items.len) return error.ExpectedQueueFull;
        self.items[self.len] = delivery;
        self.len += 1;
    }

    pub fn clear(self: *ExpectedQueue) void {
        self.len = 0;
    }
};

pub const State = struct {
    subscribed: [2][2]bool = .{ .{ false, false }, .{ false, false } },
    retained: [2]?Payload = .{ null, null },
    expected: [2]ExpectedQueue = .{ .{}, .{} },

    pub fn enqueueLive(
        self: *State,
        topic_index: usize,
        delivery: ExpectedDelivery,
    ) !void {
        for (0..self.subscribed.len) |subscriber_index| {
            if (self.subscribed[subscriber_index][topic_index]) {
                try self.expected[subscriber_index].append(delivery);
            }
        }
    }
};

pub const Summary = struct {
    subscribes: usize = 0,
    unsubscribes: usize = 0,
    normal_publishes: usize = 0,
    retained_writes: usize = 0,
    retained_replacements: usize = 0,
    retained_deletes: usize = 0,
    retained_replays: usize = 0,
    subscription_replacements: usize = 0,
    deliveries: usize = 0,
    key_updates: usize = 0,
};

pub fn requireLifecycle(summary: Summary) !void {
    try std.testing.expect(summary.subscribes >= 4);
    try std.testing.expect(summary.unsubscribes >= 2);
    try std.testing.expect(summary.normal_publishes >= 2);
    try std.testing.expect(summary.retained_writes >= 3);
    try std.testing.expect(summary.retained_replacements >= 1);
    try std.testing.expect(summary.retained_deletes >= 1);
    try std.testing.expect(summary.retained_replays >= 3);
    try std.testing.expect(summary.deliveries >= 8);
}
