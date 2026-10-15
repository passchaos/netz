//! Runtime-configurable broker delivery and durable-Session policy.
//!
//! The Broker serializes writers under its state mutex. Readers that begin
//! work outside that mutex use the generation snapshot below, avoiding another
//! global-lock round trip on the PUBLISH hot path.

const std = @import("std");

pub const Delivery = struct {
    /// Maximum Application Message payload bytes; zero is unlimited.
    max_payload_size: usize = 0,
    /// Retain QoS 0 messages for an offline persistent Session.
    queue_qos0_messages: bool = false,
    /// Permit subscription QoS to raise the outgoing source QoS.
    upgrade_outgoing_qos: bool = false,
    /// Re-check the retained publisher's current write authorization on replay.
    check_retain_source: bool = true,
    /// Administrative upper bound for a persistent Session lifetime.
    persistent_session_expiry_seconds: ?u32 = null,

    pub fn validate(self: Delivery) error{InvalidProperty}!void {
        if (self.persistent_session_expiry_seconds == 0) {
            return error.InvalidProperty;
        }
    }
};

pub const Snapshot = struct {
    generation: std.atomic.Value(u64) = .init(0),
    max_payload_size: std.atomic.Value(usize),
    flags: std.atomic.Value(u8),
    persistent_session_expiry_seconds: std.atomic.Value(u32),

    const queue_qos0_bit: u8 = 1 << 0;
    const upgrade_outgoing_qos_bit: u8 = 1 << 1;
    const check_retain_source_bit: u8 = 1 << 2;

    pub fn init(policy: Delivery) Snapshot {
        return .{
            .max_payload_size = .init(policy.max_payload_size),
            .flags = .init(encodeFlags(policy)),
            .persistent_session_expiry_seconds = .init(
                policy.persistent_session_expiry_seconds orelse 0,
            ),
        };
    }

    /// Store one generation. The Broker state mutex provides single-writer
    /// serialization; the odd generation prevents readers from accepting a
    /// partially updated group.
    pub fn store(self: *Snapshot, policy: Delivery) void {
        _ = self.generation.fetchAdd(1, .acq_rel);
        self.max_payload_size.store(policy.max_payload_size, .monotonic);
        self.flags.store(encodeFlags(policy), .monotonic);
        self.persistent_session_expiry_seconds.store(
            policy.persistent_session_expiry_seconds orelse 0,
            .monotonic,
        );
        _ = self.generation.fetchAdd(1, .release);
    }

    pub fn load(self: *const Snapshot) Delivery {
        while (true) {
            const before = self.generation.load(.acquire);
            if (before & 1 != 0) continue;
            const max_payload_size = self.max_payload_size.load(.monotonic);
            const flags = self.flags.load(.monotonic);
            const expiry = self.persistent_session_expiry_seconds.load(
                .monotonic,
            );
            const after = self.generation.load(.acquire);
            if (before != after) continue;
            return .{
                .max_payload_size = max_payload_size,
                .queue_qos0_messages = flags & queue_qos0_bit != 0,
                .upgrade_outgoing_qos = flags & upgrade_outgoing_qos_bit != 0,
                .check_retain_source = flags & check_retain_source_bit != 0,
                .persistent_session_expiry_seconds = if (expiry == 0) null else expiry,
            };
        }
    }

    fn encodeFlags(policy: Delivery) u8 {
        return @as(u8, @intFromBool(policy.queue_qos0_messages)) *
            queue_qos0_bit |
            @as(u8, @intFromBool(policy.upgrade_outgoing_qos)) *
                upgrade_outgoing_qos_bit |
            @as(u8, @intFromBool(policy.check_retain_source)) *
                check_retain_source_bit;
    }
};

test "delivery policy snapshot never exposes a mixed generation" {
    const first = Delivery{
        .max_payload_size = 1,
        .persistent_session_expiry_seconds = 1,
    };
    const second = Delivery{
        .max_payload_size = 2,
        .queue_qos0_messages = true,
        .upgrade_outgoing_qos = true,
        .check_retain_source = false,
        .persistent_session_expiry_seconds = 2,
    };
    var snapshot = Snapshot.init(first);
    var done: std.atomic.Value(bool) = .init(false);
    const Writer = struct {
        fn run(
            target: *Snapshot,
            a: Delivery,
            b: Delivery,
            completed: *std.atomic.Value(bool),
        ) void {
            for (0..100_000) |index| {
                target.store(if (index & 1 == 0) b else a);
            }
            completed.store(true, .release);
        }
    };
    const writer = try std.Thread.spawn(
        .{},
        Writer.run,
        .{ &snapshot, first, second, &done },
    );
    while (!done.load(.acquire)) {
        const value = snapshot.load();
        try std.testing.expect(
            std.meta.eql(value, first) or std.meta.eql(value, second),
        );
    }
    writer.join();
    const final = snapshot.load();
    try std.testing.expect(
        std.meta.eql(final, first) or std.meta.eql(final, second),
    );
}
