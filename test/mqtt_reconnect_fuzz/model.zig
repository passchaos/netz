const netz = @import("netz");

const mqtt = netz.mqtt;

pub const max_operations = 8;
pub const packet_timeout = @import("std").Io.Duration.fromSeconds(2);
pub const topics = [2][]const u8{
    "fuzz/reconnect/zero",
    "fuzz/reconnect/one",
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
