const std = @import("std");

pub const max_operations = 6;
pub const packet_timeout = std.Io.Duration.fromSeconds(2);
pub const coordination_timeout = std.Io.Duration.fromSeconds(5);
pub const bridge_id = [_]u8{0xd2} ** 16;
pub const remote_topics = [2][]const u8{
    "qos2/zero",
    "qos2/one",
};
pub const local_topics = [2][]const u8{
    "mirror/qos2/zero",
    "mirror/qos2/one",
};

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

pub const recovery_seed = smithSliceSeed(&.{
    0x00, // Complete normally.
    0x05, // Reconnect transport and resume the PUBREL leg.
    0x0a, // Recreate Bridge and restore a retained transaction.
    0x17, // Fresh Session discards a DUP transaction before PUBREL.
    0x1d, // Retained DUP transaction resumes across transport loss.
    0x12, // DUP transaction resumes across Bridge recreation.
});

pub const epoch_seed = smithSliceSeed(&.{
    0x0b, // Fresh Session discards a retained transaction.
    0x04, // Topic one completes normally in the new epoch.
    0x13, // Another fresh Session discards topic zero.
    0x1a, // Recreate Bridge and restore topic zero with DUP input.
    0x09, // Retained topic zero resumes across transport loss.
});

pub const corpus = &.{ &recovery_seed, &epoch_seed };

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

pub fn requireRecovery(summary: Summary) !void {
    try std.testing.expect(summary.released >= 5);
    try std.testing.expect(summary.transport_resumes >= 2);
    try std.testing.expect(summary.process_resumes >= 2);
    try std.testing.expect(summary.fresh_session_discards >= 1);
    try std.testing.expect(summary.duplicate_inputs >= 2);
    try std.testing.expect(summary.retained_probe_deliveries >= 1);
}

pub fn requireEpochRecovery(summary: Summary) !void {
    try std.testing.expect(summary.released >= 3);
    try std.testing.expect(summary.ordinary >= 1);
    try std.testing.expect(summary.transport_resumes >= 1);
    try std.testing.expect(summary.process_resumes >= 1);
    try std.testing.expect(summary.fresh_session_discards >= 2);
    try std.testing.expect(summary.duplicate_inputs >= 1);
    try std.testing.expect(summary.retained_writes >= 2);
    try std.testing.expect(summary.subscription_replays >= 4);
    try std.testing.expect(summary.retained_probe_deliveries >= 1);
}
