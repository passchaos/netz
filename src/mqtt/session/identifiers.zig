//! Stable borrowed sender ownership and transactional identifier selection.
const std = @import("std");
pub const Ownership = @import("../identifier/ownership.zig").Ownership;

/// Ordinary broker Sessions keep their map inline. A reconnect client can
/// promote only the descriptor to stable storage before lending ownership;
/// existing hash storage transfers without rebuilding or duplicating entries.
pub const Index = struct {
    const Map = std.AutoHashMapUnmanaged(u16, usize);
    inline_map: Map = .empty,
    stable: ?*Map = null,

    fn mutable(self: *Index) *Map {
        return self.stable orelse &self.inline_map;
    }

    fn map(self: *const Index) *const Map {
        return self.stable orelse &self.inline_map;
    }

    pub fn deinit(self: *Index, allocator: std.mem.Allocator) void {
        self.mutable().deinit(allocator);
        if (self.stable) |stable| allocator.destroy(stable);
        self.* = .{};
    }

    pub fn contains(self: *const Index, id: u16) bool {
        return self.map().contains(id);
    }

    pub fn get(self: *const Index, id: u16) ?usize {
        return self.map().get(id);
    }

    pub fn ensureUnusedCapacity(self: *Index, allocator: std.mem.Allocator, count: u32) std.mem.Allocator.Error!void {
        return self.mutable().ensureUnusedCapacity(allocator, count);
    }

    pub fn putAssumeCapacityNoClobber(self: *Index, id: u16, value: usize) void {
        self.mutable().putAssumeCapacityNoClobber(id, value);
    }

    pub fn fetchRemove(self: *Index, id: u16) ?Map.KV {
        return self.mutable().fetchRemove(id);
    }

    pub fn borrow(self: *Index, allocator: std.mem.Allocator) std.mem.Allocator.Error!Ownership {
        if (self.stable == null) {
            const stable = try allocator.create(Map);
            stable.* = self.inline_map;
            self.inline_map = .empty;
            self.stable = stable;
        }
        return ownership(@as(*const Map, self.stable.?));
    }
};

pub fn ownership(index: anytype) Ownership {
    return .{ .context = index, .containsFn = struct {
        fn contains(context: *const anyopaque, packet_id: u16) bool {
            const source: @TypeOf(index) = @ptrCast(@alignCast(context));
            return source.contains(packet_id);
        }
    }.contains };
}

pub fn reserve(session: anytype, reserved: ?Ownership) error{InflightFull}!u16 {
    const initial = session.next_packet_id;
    errdefer session.next_packet_id = initial;
    for (0..std.math.maxInt(u16)) |_| {
        const id = session.next_packet_id;
        session.next_packet_id +%= 1;
        if (session.next_packet_id == 0) session.next_packet_id = 1;
        if (session.packet_index.contains(id)) continue;
        if (reserved) |owner| if (owner.contains(id)) continue;
        return id;
    }
    return error.InflightFull;
}

test "MQTT session identifier selection rolls back exhaustion and reuses released reservations" {
    const RawMap = std.AutoHashMapUnmanaged(u16, usize);
    var index: RawMap = .empty;
    defer index.deinit(std.testing.allocator);
    var sender = struct { next_packet_id: u16, packet_index: RawMap }{ .next_packet_id = 65_535, .packet_index = .empty };
    defer sender.packet_index.deinit(std.testing.allocator);
    for (1..@as(usize, std.math.maxInt(u16)) + 1) |id| try index.put(std.testing.allocator, @intCast(id), id);
    const borrowed = ownership(@as(*const RawMap, &index));
    try std.testing.expectError(error.InflightFull, reserve(&sender, borrowed));
    try std.testing.expectEqual(@as(u16, 65_535), sender.next_packet_id);
    try std.testing.expect(index.remove(1));
    try std.testing.expectEqual(@as(u16, 1), try reserve(&sender, borrowed));
    try std.testing.expectEqual(@as(u16, 2), sender.next_packet_id);
    try sender.packet_index.put(std.testing.allocator, 1, 0);
    try std.testing.expectError(error.InflightFull, reserve(&sender, borrowed));
    try std.testing.expectEqual(@as(u16, 2), sender.next_packet_id);
}

test "MQTT session identifier view promotion is transactional and move stable" {
    const allocator = std.testing.allocator;
    var source: Index = .{};
    try source.ensureUnusedCapacity(allocator, 1);
    source.putAssumeCapacityNoClobber(42, 7);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, source.borrow(failing.allocator()));
    try std.testing.expect(source.stable == null);
    try std.testing.expectEqual(@as(?usize, 7), source.get(42));
    const owner = try source.borrow(allocator);
    var moved = source;
    source = .{};
    defer moved.deinit(allocator);
    for (1..1024) |id| {
        try moved.ensureUnusedCapacity(allocator, 1);
        if (!moved.contains(@intCast(id))) moved.putAssumeCapacityNoClobber(@intCast(id), id);
    }
    try std.testing.expect(owner.contains(42));
    try std.testing.expect(owner.contains(1023));
    try std.testing.expect(moved.fetchRemove(42) != null);
    try std.testing.expect(!owner.contains(42));
    _ = try moved.borrow(failing.allocator());
}
