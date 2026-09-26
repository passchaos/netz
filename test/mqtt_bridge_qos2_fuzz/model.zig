const std = @import("std");

pub const max_operations = 6;
pub const packet_timeout = std.Io.Duration.fromSeconds(2);
pub const bridge_id = [_]u8{0xd2} ** 16;
pub const remote_topics = [2][]const u8{
    "qos2/zero",
    "qos2/one",
};
pub const local_topics = [2][]const u8{
    "mirror/qos2/zero",
    "mirror/qos2/one",
};

pub const Payload = struct {
    bytes: [3]u8,

    pub fn init(operation: u8, index: usize) Payload {
        return .{ .bytes = .{ operation, @intCast(index), 0xd2 } };
    }
};

pub const Retained = struct {
    payload: Payload,
};

pub const State = struct {
    retained: [remote_topics.len]?Retained = .{ null, null },

    pub fn release(
        self: *State,
        operation: u8,
        index: usize,
    ) void {
        if (operation & 0x08 == 0) return;
        const topic_index: usize = (operation >> 2) & 0x01;
        self.retained[topic_index] = .{
            .payload = Payload.init(operation, index),
        };
    }
};

pub const Summary = struct {
    released: usize = 0,
    ordinary: usize = 0,
    transport_resumes: usize = 0,
    process_resumes: usize = 0,
    fresh_session_discards: usize = 0,
    duplicate_inputs: usize = 0,
    retained_writes: usize = 0,
    subscription_replays: usize = 0,
    retained_probe_deliveries: usize = 0,
};
