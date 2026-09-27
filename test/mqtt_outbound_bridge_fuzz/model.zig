const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub const max_operations = 8;
pub const packet_timeout = std.Io.Duration.fromSeconds(2);
pub const coordination_timeout = std.Io.Duration.fromSeconds(5);
pub const source_topics = [2][]const u8{
    "local/device/zero",
    "local/device/one",
};
pub const bridge_filters = [2][]const u8{
    "device/zero",
    "device/one",
};
pub const target_topics = [2][]const u8{
    "remote/device/zero",
    "remote/device/one",
};

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

pub const routing_seed = smithSliceSeed(&.{
    0x00, 0x09, 0x11, 0x0f, 0x01,
});
pub const reconnect_seed = smithSliceSeed(&.{
    0x02, 0x0b, 0x14, 0x0d, 0x1a, 0x17,
});
pub const corpus = &.{ &routing_seed, &reconnect_seed };

pub const Payload = struct {
    bytes: [3]u8,

    pub fn init(operation: u8, index: usize) Payload {
        return .{ .bytes = .{ operation, @intCast(index), 0xc3 } };
    }
};

pub fn qos(operation: u8) mqtt.QoS {
    return if (operation & 0x07 == 0) .at_most_once else .at_least_once;
}

pub fn topicIndex(operation: u8) usize {
    return (operation >> 3) & 0x01;
}

pub fn retain(operation: u8) bool {
    return operation & 0x10 != 0;
}

pub fn sourceDup(operation: u8) bool {
    return operation & 0x07 == 7;
}

pub const Signals = struct {
    source_completed: std.atomic.Value(usize) = .init(0),
    target_completed: std.atomic.Value(usize) = .init(0),
    aborted: std.atomic.Value(bool) = .init(false),
    source_reconnected: [max_operations]std.Io.Event =
        .{.unset} ** max_operations,
    target_done: [max_operations]std.Io.Event = .{.unset} ** max_operations,

    pub fn abort(self: *Signals, io: std.Io) void {
        self.aborted.store(true, .release);
        for (&self.source_reconnected) |*event| event.set(io);
        for (&self.target_done) |*event| event.set(io);
    }
};

pub const Summary = struct {
    forwarded: usize = 0,
    qos0: usize = 0,
    qos1: usize = 0,
    retained: usize = 0,
    source_dup_normalized: usize = 0,
    target_resumed: usize = 0,
    target_fresh: usize = 0,
    source_resumed: usize = 0,
    source_fresh: usize = 0,
    target_replays: usize = 0,
    source_subscription_replays: usize = 0,
};

pub fn requireRouting(summary: Summary) !void {
    try std.testing.expect(summary.forwarded >= 5);
    try std.testing.expect(summary.qos0 >= 1);
    try std.testing.expect(summary.qos1 >= 4);
    try std.testing.expect(summary.retained >= 1);
    try std.testing.expect(summary.source_dup_normalized >= 1);
}

pub fn requireRecovery(summary: Summary) !void {
    try std.testing.expect(summary.target_resumed >= 2);
    try std.testing.expect(summary.target_fresh >= 1);
    try std.testing.expect(summary.target_replays >= 3);
    try std.testing.expect(summary.source_resumed >= 1);
    try std.testing.expect(summary.source_fresh >= 1);
    try std.testing.expect(summary.source_subscription_replays >= 2);
}
