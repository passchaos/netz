//! Reusable scratch for established QUIC packet processing.
//!
//! Plaintext is encoded directly into stable recovery ownership or the final
//! protected-packet payload region. Keeping only packet, receive, and ACK
//! scratch avoids a redundant path-sized allocation per connection.

const std = @import("std");
const quic = @import("../mod.zig");

pub const Buffers = struct {
    send_packet: std.ArrayList(u8) = .empty,
    receive_packet: std.ArrayList(u8) = .empty,
    receive_ack_ranges: std.ArrayList(quic.AckRange) = .empty,
    receive_frames: std.ArrayList(quic.Frame) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        send_packet_capacity: usize,
        receive_packet_capacity: usize,
        receive_ack_range_capacity: usize,
    ) std.mem.Allocator.Error!Buffers {
        var buffers: Buffers = .{};
        errdefer buffers.deinit(allocator);
        try buffers.send_packet.ensureTotalCapacity(
            allocator,
            send_packet_capacity,
        );
        try buffers.receive_packet.ensureTotalCapacity(
            allocator,
            receive_packet_capacity,
        );
        try buffers.receive_ack_ranges.ensureTotalCapacity(
            allocator,
            receive_ack_range_capacity,
        );
        return buffers;
    }

    pub fn deinit(self: *Buffers, allocator: std.mem.Allocator) void {
        self.send_packet.deinit(allocator);
        self.receive_packet.deinit(allocator);
        self.receive_ack_ranges.deinit(allocator);
        self.receive_frames.deinit(allocator);
        self.* = undefined;
    }
};

test "QUIC one-RTT scratch reserves reusable packet state" {
    var buffers = try Buffers.init(std.testing.allocator, 1400, 4096, 32);
    defer buffers.deinit(std.testing.allocator);

    try std.testing.expect(buffers.send_packet.capacity >= 1400);
    try std.testing.expect(buffers.receive_packet.capacity >= 4096);
    try std.testing.expectEqual(@as(usize, 0), buffers.receive_frames.capacity);
    try std.testing.expect(buffers.receive_ack_ranges.capacity >= 32);
}

test "QUIC one-RTT scratch initialization rolls back every allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initForTest,
        .{},
    );
}

fn initForTest(allocator: std.mem.Allocator) !void {
    var buffers = try Buffers.init(allocator, 1400, 4096, 32);
    defer buffers.deinit(allocator);
}
