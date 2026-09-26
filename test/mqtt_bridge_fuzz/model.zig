const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub const max_operations = 10;
pub const packet_timeout = std.Io.Duration.fromSeconds(2);
pub const remote_topics = [2][]const u8{
    "source/zero",
    "source/one",
};
pub const local_topics = [2][]const u8{
    "mirror/source/zero",
    "mirror/source/one",
};

pub const Payload = struct {
    bytes: [3]u8,

    pub fn init(operation: u8, index: usize) Payload {
        return .{ .bytes = .{ operation, @intCast(index), 0xb7 } };
    }
};

pub const Delivery = struct {
    topic_index: usize,
    payload: [3]u8 = undefined,
    payload_len: usize,
    qos: mqtt.QoS,
    retain: bool,

    pub fn message(
        topic_index: usize,
        payload: Payload,
        qos: mqtt.QoS,
        retain: bool,
    ) Delivery {
        return .{
            .topic_index = topic_index,
            .payload = payload.bytes,
            .payload_len = payload.bytes.len,
            .qos = qos,
            .retain = retain,
        };
    }

    pub fn deletion(topic_index: usize) Delivery {
        return .{
            .topic_index = topic_index,
            .payload_len = 0,
            .qos = .at_least_once,
            .retain = true,
        };
    }
};

pub const State = struct {
    retained: [remote_topics.len]?Delivery = .{ null, null },

    pub fn apply(self: *State, operation: u8, index: usize) ?Delivery {
        const topic_index: usize = (operation >> 3) & 0x01;
        const payload = Payload.init(operation, index);
        const delivery = switch (operation & 0x07) {
            0 => Delivery.message(
                topic_index,
                payload,
                .at_most_once,
                false,
            ),
            1 => Delivery.message(
                topic_index,
                payload,
                .at_least_once,
                false,
            ),
            2 => Delivery.message(
                topic_index,
                payload,
                .at_most_once,
                true,
            ),
            3 => Delivery.message(
                topic_index,
                payload,
                .at_least_once,
                true,
            ),
            4 => Delivery.deletion(topic_index),
            7 => Delivery.message(
                topic_index,
                payload,
                .at_least_once,
                false,
            ),
            5, 6 => return null,
            else => unreachable,
        };
        switch (operation & 0x07) {
            2, 3 => self.retained[topic_index] = delivery,
            4 => self.retained[topic_index] = null,
            else => {},
        }
        return delivery;
    }
};

pub const Summary = struct {
    deliveries: usize = 0,
    qos1_acknowledgements: usize = 0,
    retained_writes: usize = 0,
    retained_deletes: usize = 0,
    duplicate_inputs: usize = 0,
    fresh_reconnects: usize = 0,
    resumed_reconnects: usize = 0,
    subscription_replays: usize = 0,
    retained_probe_deliveries: usize = 0,
};
