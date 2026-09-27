const std = @import("std");

pub const max_operations = 6;
pub const packet_timeout = std.Io.Duration.fromSeconds(2);
pub const coordination_timeout = std.Io.Duration.fromSeconds(5);
pub const local_subscription_id = 113;
pub const bridge_id = [_]u8{0xe2} ** 16;
pub const source_topics = [2][]const u8{
    "local/qos2/zero",
    "local/qos2/one",
};
pub const bridge_filters = [2][]const u8{
    "qos2/zero",
    "qos2/one",
};
pub const target_topics = [2][]const u8{
    "remote/qos2/zero",
    "remote/qos2/one",
};

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

pub const recovery_seed = smithSliceSeed(&.{
    0x00, // Normal transaction.
    0x11, // Recreate before target wire after source Session resume.
    0x02, // Recreate at target PUBREL boundary.
    0x03, // Resume target Session after losing PUBREC.
    0x0a, // Retained transaction restored at PUBREL boundary.
    0x28, // Retained deletion completes normally.
});

pub const retained_seed = smithSliceSeed(&.{
    0x08, // Retain topic zero.
    0x0d, // Replace retained topic one across pre-wire restart.
    0x18, // Replace retained topic zero after source reconnect.
    0x2b, // Delete retained topic zero across target reconnect.
    0x0e, // Retain topic one across PUBREL restart.
});

pub const corpus = &.{ &recovery_seed, &retained_seed };

pub const Payload = struct {
    bytes: [3]u8,

    pub fn init(operation: u8, index: usize) Payload {
        return .{ .bytes = .{ operation, @intCast(index), 0xe2 } };
    }
};

pub const Retained = struct {
    payload: [3]u8,
    payload_len: usize,
};

pub const State = struct {
    retained: [source_topics.len]?Retained = .{ null, null },

    pub fn apply(self: *State, operation: u8, index: usize) void {
        if (!retain(operation)) return;
        const topic = topicIndex(operation);
        if (deletesRetained(operation)) {
            self.retained[topic] = null;
        } else {
            self.retained[topic] = .{
                .payload = Payload.init(operation, index).bytes,
                .payload_len = 3,
            };
        }
    }
};

pub fn mode(operation: u8) u2 {
    return @truncate(operation);
}

pub fn topicIndex(operation: u8) usize {
    return (operation >> 2) & 0x01;
}

pub fn retain(operation: u8) bool {
    return operation & 0x08 != 0;
}

pub fn reconnectSource(operation: u8) bool {
    return operation & 0x10 != 0;
}

pub fn deletesRetained(operation: u8) bool {
    return retain(operation) and operation & 0x20 != 0;
}

pub const Summary = struct {
    delivered: usize = 0,
    ordinary: usize = 0,
    pre_wire_restores: usize = 0,
    pubrel_restores: usize = 0,
    target_resumes: usize = 0,
    source_resumes: usize = 0,
    retained_writes: usize = 0,
    retained_deletes: usize = 0,
    retained_probe_deliveries: usize = 0,
};

pub fn requireRecovery(summary: Summary) !void {
    try std.testing.expect(summary.delivered >= 6);
    try std.testing.expect(summary.ordinary >= 2);
    try std.testing.expect(summary.pre_wire_restores >= 1);
    try std.testing.expect(summary.pubrel_restores >= 2);
    try std.testing.expect(summary.target_resumes >= 1);
    try std.testing.expect(summary.source_resumes >= 1);
    try std.testing.expect(summary.retained_deletes >= 1);
}

pub fn requireRetained(summary: Summary) !void {
    try std.testing.expect(summary.delivered >= 5);
    try std.testing.expect(summary.retained_writes >= 3);
    try std.testing.expect(summary.retained_deletes >= 1);
    try std.testing.expect(summary.retained_probe_deliveries >= 1);
}
