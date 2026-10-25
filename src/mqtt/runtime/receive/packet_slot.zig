//! Compact ownership of one complete packet retained during event decoding.
const std = @import("std");
const mqtt = @import("../../mod.zig");
const Packet = @import("../packet_transport.zig").OwnedPacket;

pub const State = struct {
    bytes: ?[]u8 = null,
    prefix_len: u16 = 0,

    pub fn retain(self: *State, value: Packet) void {
        std.debug.assert(self.bytes == null);
        std.debug.assert(value.owns_bytes);
        self.bytes = value.bytes;
        self.prefix_len = value.prefix_len;
    }

    pub fn packet(self: State) ?Packet {
        const bytes = self.bytes orelse return null;
        return .{
            .bytes = bytes,
            // Framing and direction were validated before ownership transfer.
            .fixed = mqtt.FixedHeader.parse(bytes) catch unreachable,
            .prefix_len = self.prefix_len,
            .traffic_recorded = true,
        };
    }

    pub fn take(self: *State) Packet {
        const value = self.packet().?;
        self.* = .{};
        return value;
    }

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        if (self.bytes != null) {
            var value = self.take();
            value.deinit(allocator);
        }
    }
};
