//! Owned interleaved MQTT packets bounded by count and complete wire bytes.

const std = @import("std");
const Packet = @import("../packet_transport.zig").OwnedPacket;

pub const default_max_bytes: usize = 32 * 1024 * 1024;
pub const Error = std.mem.Allocator.Error || error{TooManyPendingPackets};

pub const State = struct {
    packets: std.ArrayList(Packet) = .empty,
    head: usize = 0,
    queued_bytes: usize = 0,
    /// The packet already left the transport before an append failed. Retain
    /// it after the ordinary prefix; max_packet_size bounds this extra packet.
    overflow: ?Packet = null,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.packets.items[self.head..]) |*packet| packet.deinit(allocator);
        self.packets.deinit(allocator);
        if (self.overflow) |*packet| packet.deinit(allocator);
        self.* = .{};
    }

    pub fn count(self: State) usize {
        return self.packets.items.len - self.head + @intFromBool(self.overflow != null);
    }

    pub fn ensureAvailable(self: State, max_packets: usize, max_bytes: usize) error{TooManyPendingPackets}!void {
        if (self.overflow != null or self.count() >= max_packets or self.queued_bytes >= max_bytes) {
            return error.TooManyPendingPackets;
        }
    }

    /// Ownership transfers only after append succeeds. Refuse either quota
    /// before allocation or compaction, and charge bytes only after commit.
    pub fn append(self: *State, allocator: std.mem.Allocator, packet: Packet, max_packets: usize, max_bytes: usize) Error!void {
        if (self.overflow != null or self.count() >= max_packets or
            self.queued_bytes > max_bytes or packet.bytes.len > max_bytes - self.queued_bytes)
        {
            return error.TooManyPendingPackets;
        }
        if (self.head != 0 and self.packets.items.len == self.packets.capacity) self.compact();
        try self.packets.append(allocator, packet);
        self.queued_bytes += packet.bytes.len;
    }

    pub fn retainOverflow(self: *State, packet: Packet) void {
        std.debug.assert(self.overflow == null);
        self.overflow = packet;
    }

    /// Move an already-owned event retry before the queue's later packets.
    /// Ownership and byte accounting transfer only after storage is ready.
    pub fn prependRetained(self: *State, allocator: std.mem.Allocator, packet: Packet) std.mem.Allocator.Error!void {
        if (self.head != 0) {
            self.head -= 1;
            self.packets.items[self.head] = packet;
        } else {
            try self.packets.ensureUnusedCapacity(allocator, 1);
            const len = self.packets.items.len;
            self.packets.items.len += 1;
            @memmove(self.packets.items[1..], self.packets.items[0..len]);
            self.packets.items[0] = packet;
        }
        self.queued_bytes += packet.bytes.len;
    }

    /// Popped packets belong to the caller. Their wire bytes stop consuming
    /// queue quota immediately, while the emergency packet always comes last.
    pub fn pop(self: *State) ?Packet {
        if (self.head < self.packets.items.len) {
            const packet = self.packets.items[self.head];
            self.head += 1;
            self.queued_bytes -= packet.bytes.len;
            return packet;
        }
        std.debug.assert(self.queued_bytes == 0);
        self.packets.clearRetainingCapacity();
        self.head = 0;
        if (self.overflow) |packet| {
            self.overflow = null;
            return packet;
        }
        return null;
    }

    pub const Match = struct { index: usize, packet: Packet };

    /// Borrow a correlated response before detaching it, so a decoder's local
    /// allocation failure leaves the packet at its exact queued position.
    pub fn findFirstMatching(self: *State, context: anytype, comptime matches: fn (@TypeOf(context), Packet) bool) ?Match {
        for (self.packets.items[self.head..], self.head..) |packet, index| {
            if (!matches(context, packet)) continue;
            return .{ .index = index, .packet = packet };
        }
        if (self.overflow) |packet| {
            if (matches(context, packet)) {
                return .{ .index = self.packets.items.len, .packet = packet };
            }
        }
        return null;
    }

    /// Detach an index returned by findFirstMatching, with no intervening
    /// queue mutation. Stable removal retains the other packets' wire order.
    pub fn takeMatch(self: *State, index: usize) Packet {
        if (index == self.packets.items.len) {
            const packet = self.overflow.?;
            self.overflow = null;
            return packet;
        }
        std.debug.assert(index >= self.head and index < self.packets.items.len);
        const packet = self.packets.items[index];
        @memmove(self.packets.items[index .. self.packets.items.len - 1], self.packets.items[index + 1 ..]);
        self.packets.items.len -= 1;
        self.queued_bytes -= packet.bytes.len;
        return packet;
    }

    /// A validated DISCONNECT is a wire-order boundary. Discard any packets
    /// after it that another correlated wait had already dequeued.
    pub fn keepThrough(self: *State, allocator: std.mem.Allocator, index: usize) void {
        if (index == self.packets.items.len) return; // The overflow is last.
        std.debug.assert(index >= self.head and index < self.packets.items.len);
        for (self.packets.items[index + 1 ..]) |*packet| {
            self.queued_bytes -= packet.bytes.len;
            packet.deinit(allocator);
        }
        self.packets.shrinkRetainingCapacity(index + 1);
        if (self.overflow) |*packet| packet.deinit(allocator);
        self.overflow = null;
    }

    fn compact(self: *State) void {
        const remaining = self.packets.items.len - self.head;
        @memmove(self.packets.items[0..remaining], self.packets.items[self.head..]);
        self.packets.items.len = remaining;
        self.head = 0;
    }
};

test {
    _ = @import("pending_tests.zig");
}
