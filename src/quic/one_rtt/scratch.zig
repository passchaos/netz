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
        return initWithReceivePacketStorage(
            allocator,
            send_packet_capacity,
            receive_packet_capacity,
            receive_ack_range_capacity,
            null,
        );
    }

    /// Consume an existing receive allocation on every return path. Handshake
    /// readers use this to hand their reusable datagram buffer to established
    /// 1-RTT state without overlapping two path-sized allocations.
    pub fn initWithReceivePacketStorage(
        allocator: std.mem.Allocator,
        send_packet_capacity: usize,
        receive_packet_capacity: usize,
        receive_ack_range_capacity: usize,
        owned_receive_packet: ?[]u8,
    ) std.mem.Allocator.Error!Buffers {
        var buffers: Buffers = .{
            .receive_packet = if (owned_receive_packet) |storage| blk: {
                var list = std.ArrayList(u8).fromOwnedSlice(storage);
                list.items.len = 0;
                break :blk list;
            } else .empty,
        };
        errdefer buffers.deinit(allocator);
        // These are fixed-capacity packet/ACK scratch regions, not growing
        // collections. Precise capacities avoid the 50% geometric overhang on
        // every connection while leaving normal append paths intact.
        try buffers.send_packet.ensureTotalCapacityPrecise(
            allocator,
            send_packet_capacity,
        );
        try buffers.receive_packet.ensureTotalCapacityPrecise(
            allocator,
            receive_packet_capacity,
        );
        try buffers.receive_ack_ranges.ensureTotalCapacityPrecise(
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

    try std.testing.expectEqual(@as(usize, 1400), buffers.send_packet.capacity);
    try std.testing.expectEqual(@as(usize, 4096), buffers.receive_packet.capacity);
    try std.testing.expectEqual(@as(usize, 0), buffers.receive_frames.capacity);
    try std.testing.expectEqual(@as(usize, 32), buffers.receive_ack_ranges.capacity);
}

test "QUIC one-RTT scratch initialization rolls back every allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initForTest,
        .{},
    );
}

test "QUIC one-RTT scratch adopts existing receive storage" {
    const allocator = std.testing.allocator;
    const storage = try allocator.alloc(u8, 4096);
    const storage_ptr = storage.ptr;
    var buffers = try Buffers.initWithReceivePacketStorage(
        allocator,
        1400,
        4096,
        32,
        storage,
    );
    defer buffers.deinit(allocator);

    try std.testing.expectEqual(
        storage_ptr,
        buffers.receive_packet.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(@as(usize, 4096), buffers.receive_packet.capacity);
}

test "QUIC one-RTT adopted scratch rolls back every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initWithOwnedReceiveForTest,
        .{},
    );
}

fn initForTest(allocator: std.mem.Allocator) !void {
    var buffers = try Buffers.init(allocator, 1400, 4096, 32);
    defer buffers.deinit(allocator);
}

fn initWithOwnedReceiveForTest(allocator: std.mem.Allocator) !void {
    const storage = try allocator.alloc(u8, 16);
    var buffers = try Buffers.initWithReceivePacketStorage(
        allocator,
        1400,
        4096,
        32,
        storage,
    );
    defer buffers.deinit(allocator);
}
