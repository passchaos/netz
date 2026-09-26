const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub const max_operations = 8;
pub const packet_timeout = std.Io.Duration.fromSeconds(2);
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
    source_reconnected: [max_operations]std.Io.Event =
        .{.unset} ** max_operations,
    target_done: [max_operations]std.Io.Event = .{.unset} ** max_operations,
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
