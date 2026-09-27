const netz = @import("netz");

const mqtt = netz.mqtt;

pub const max_operations = 8;
pub const packet_timeout = @import("std").Io.Duration.fromSeconds(2);
pub const topics = [2][]const u8{
    "fuzz/reconnect/zero",
    "fuzz/reconnect/one",
};

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    @import("std").mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

pub const qos_recovery_seed = smithSliceSeed(&.{
    0x00, 0x09, 0x03, 0x0b, 0x02, 0x0c, 0x04,
});
pub const subscription_seed = smithSliceSeed(&.{
    0x05, 0x55, 0x0f, 0x07, 0x06, 0x07, 0x16, 0x0f,
});
pub const mixed_seed = smithSliceSeed(&.{
    0x45, 0x29, 0x47, 0x7b, 0x36, 0x7c,
});
pub const corpus = &.{
    &qos_recovery_seed,
    &subscription_seed,
    &mixed_seed,
};

pub const Payload = struct {
    bytes: [3]u8,

    pub fn init(operation: u8, index: usize) Payload {
        return .{ .bytes = .{ operation, @intCast(index), 0xa5 } };
    }
};

pub const SubscriptionModel = struct {
    order: [topics.len]usize = undefined,
    qos: [topics.len]mqtt.QoS = .{ .at_most_once, .at_most_once },
    len: usize = 0,

    pub fn set(
        self: *SubscriptionModel,
        topic_index: usize,
        qos: mqtt.QoS,
    ) void {
        if (self.indexOf(topic_index) == null) {
            self.order[self.len] = topic_index;
            self.len += 1;
        }
        self.qos[topic_index] = qos;
    }

    pub fn remove(self: *SubscriptionModel, topic_index: usize) bool {
        const index = self.indexOf(topic_index) orelse return false;
        @import("std").mem.copyForwards(
            usize,
            self.order[index .. self.len - 1],
            self.order[index + 1 .. self.len],
        );
        self.len -= 1;
        return true;
    }

    fn indexOf(self: SubscriptionModel, topic_index: usize) ?usize {
        for (self.order[0..self.len], 0..) |candidate, index| {
            if (candidate == topic_index) return index;
        }
        return null;
    }
};

pub const Summary = struct {
    reconnects: usize = 0,
    fresh_sessions: usize = 0,
    resumed_sessions: usize = 0,
    publish_replays: usize = 0,
    pubrel_replays: usize = 0,
    subscription_replays: usize = 0,
    session_losses: usize = 0,
    empty_reconnect_barriers: usize = 0,
};

pub fn requireQosRecovery(summary: Summary) !void {
    const testing = @import("std").testing;
    try testing.expect(summary.reconnects >= 5);
    try testing.expect(summary.fresh_sessions >= 2);
    try testing.expect(summary.resumed_sessions >= 3);
    try testing.expect(summary.publish_replays >= 2);
    try testing.expect(summary.pubrel_replays >= 1);
    try testing.expect(summary.session_losses >= 2);
}
