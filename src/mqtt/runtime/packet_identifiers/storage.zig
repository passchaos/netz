//! Sparse Packet Identifier stages with bounded, transactionally promoted
//! packed storage. Incoming traffic uses two bits, outgoing traffic four.

const std = @import("std");

pub fn Storage(comptime Code: type) type {
    return struct {
        const packet_identifier_slots =
            @as(usize, std.math.maxInt(u16)) + 1;
        const bits_per_identifier = if (@bitSizeOf(Code) <= 2) 2 else 4;
        const identifiers_per_byte = 8 / bits_per_identifier;
        const Dense = [packet_identifier_slots / identifiers_per_byte]u8;
        pub const sparse_limit = 1024;
        const Map = std.AutoHashMapUnmanaged(u16, Code);

        sparse: Map = .empty,
        dense: ?*Dense = null,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.sparse.deinit(allocator);
            if (self.dense) |dense| allocator.destroy(dense);
            self.* = .{};
        }

        pub fn value(self: *const @This(), packet_id: u16) Code {
            return if (self.dense) |dense|
                denseValue(dense, packet_id)
            else
                self.sparse.get(packet_id) orelse 0;
        }

        pub fn contains(
            self: *const @This(),
            packet_id: u16,
            expected: Code,
        ) bool {
            return self.value(packet_id) == expected;
        }

        pub fn add(
            self: *@This(),
            allocator: std.mem.Allocator,
            packet_id: u16,
            new_value: Code,
        ) std.mem.Allocator.Error!bool {
            std.debug.assert(new_value != 0);
            const current = self.value(packet_id);
            if (current != 0) {
                std.debug.assert(current == new_value);
                return false;
            }
            if (self.dense) |dense| {
                setDenseValue(dense, packet_id, new_value);
                return true;
            }
            if (self.sparse.count() >= sparse_limit) {
                try self.promoteToDense(allocator);
                setDenseValue(self.dense.?, packet_id, new_value);
                return true;
            }
            try self.sparse.putNoClobber(allocator, packet_id, new_value);
            return true;
        }

        pub fn remove(
            self: *@This(),
            packet_id: u16,
            expected: Code,
        ) bool {
            if (!self.contains(packet_id, expected)) return false;
            if (self.dense) |dense| {
                setDenseValue(dense, packet_id, 0);
            } else {
                const removed = self.sparse.remove(packet_id);
                std.debug.assert(removed);
            }
            return true;
        }

        pub fn transition(
            self: *@This(),
            packet_id: u16,
            from: Code,
            to: Code,
        ) bool {
            if (!self.contains(packet_id, from)) return false;
            if (self.dense) |dense| {
                setDenseValue(dense, packet_id, to);
            } else {
                self.sparse.getPtr(packet_id).?.* = to;
            }
            return true;
        }

        pub fn clearRetainingCapacity(self: *@This()) void {
            if (self.dense) |dense| {
                @memset(dense, 0);
            } else {
                self.sparse.clearRetainingCapacity();
            }
        }

        pub fn count(self: *const @This(), expected: Code) usize {
            var result: usize = 0;
            if (self.dense) |dense| {
                for (1..packet_identifier_slots) |packet_id| {
                    result += @intFromBool(denseValue(
                        dense,
                        @intCast(packet_id),
                    ) == expected);
                }
                return result;
            }
            var values = self.sparse.valueIterator();
            while (values.next()) |entry| {
                result += @intFromBool(entry.* == expected);
            }
            return result;
        }

        fn promoteToDense(
            self: *@This(),
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!void {
            const dense = try allocator.create(Dense);
            @memset(dense, 0);
            var entries = self.sparse.iterator();
            while (entries.next()) |entry| {
                setDenseValue(dense, entry.key_ptr.*, entry.value_ptr.*);
            }
            self.sparse.deinit(allocator);
            self.sparse = .empty;
            self.dense = dense;
        }

        fn denseValue(dense: *const Dense, packet_id: u16) Code {
            const index = @as(usize, packet_id) / identifiers_per_byte;
            const shift: u3 = @intCast(
                (@as(usize, packet_id) % identifiers_per_byte) * bits_per_identifier,
            );
            return @truncate(dense[index] >> shift);
        }

        fn setDenseValue(dense: *Dense, packet_id: u16, new_value: Code) void {
            const index = @as(usize, packet_id) / identifiers_per_byte;
            const shift: u3 = @intCast(
                (@as(usize, packet_id) % identifiers_per_byte) * bits_per_identifier,
            );
            const clear_mask = ~(@as(u8, std.math.maxInt(Code)) << shift);
            dense[index] = (dense[index] & clear_mask) |
                (@as(u8, new_value) << shift);
        }
    };
}
