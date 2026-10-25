//! Validated, deep-owned subscription metadata for reconnect snapshots.
const std = @import("std");
const mqtt = @import("../mod.zig");
const persistence = @import("../persistence/codec.zig");
const Owned = @import("subscription.zig").Owned;

pub const Error = persistence.Error || error{ OwnedPropertyLimitExceeded, SnapshotSubscriptionMismatch };
pub const View = struct { values: []const Owned, replay_index: ?usize };

pub const State = struct {
    values: std.ArrayList(Owned) = .empty,
    replay_index: ?usize = null,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        for (self.values.items) |*value| value.deinit(allocator);
        self.values.deinit(allocator);
        self.* = .{};
    }

    /// Caller-seeded configuration composes with the saved state only when
    /// overlapping filters agree. Prepare every allocation before swapping.
    pub fn merge(self: *State, allocator: std.mem.Allocator, configured: []const Owned, protocol: mqtt.ProtocolVersion, maximum: usize) Error!void {
        var saved: std.ArrayList(u8) = .empty;
        defer saved.deinit(allocator);
        var desired: std.ArrayList(u8) = .empty;
        defer desired.deinit(allocator);
        for (configured) |value| {
            for (self.values.items) |existing| {
                if (!std.mem.eql(u8, existing.filter, value.filter)) continue;
                saved.clearRetainingCapacity();
                desired.clearRetainingCapacity();
                try mqtt.Subscribe.write(&saved, allocator, protocol, 1, existing.properties, &.{existing.value()});
                try mqtt.Subscribe.write(&desired, allocator, protocol, 1, value.properties, &.{value.value()});
                if (!std.mem.eql(u8, saved.items, desired.items)) return error.SnapshotSubscriptionMismatch;
                break;
            } else {
                if (self.values.items.len >= maximum) return error.SnapshotLimitExceeded;
                var copied = try Owned.clone(allocator, value.value(), value.properties);
                errdefer copied.deinit(allocator);
                try self.values.append(allocator, copied);
            }
        }
    }
};

pub fn encode(out: *std.ArrayList(u8), allocator: std.mem.Allocator, protocol: mqtt.ProtocolVersion, state: View) Error!void {
    if (state.values.len > std.math.maxInt(u32)) return error.SnapshotLimitExceeded;
    if (state.replay_index) |index| if (index > state.values.len) return error.CorruptSnapshot;
    try persistence.appendInt(out, allocator, u32, @intCast(state.values.len));
    try persistence.appendOptionalInt(out, allocator, u32, if (state.replay_index) |index| @intCast(index) else null);
    var packet: std.ArrayList(u8) = .empty;
    defer packet.deinit(allocator);
    var filters: std.StringHashMapUnmanaged(void) = .empty;
    defer filters.deinit(allocator);
    for (state.values) |value| {
        const entry = try filters.getOrPut(allocator, value.filter);
        if (entry.found_existing) return error.CorruptSnapshot;
        packet.clearRetainingCapacity();
        try mqtt.Subscribe.write(&packet, allocator, protocol, 1, value.properties, &.{value.value()});
        try persistence.appendBlob(out, allocator, packet.items);
    }
}

pub fn decode(cursor: *persistence.Cursor, allocator: std.mem.Allocator, protocol: mqtt.ProtocolVersion, maximum: usize) Error!State {
    const count = try cursor.readInt(u32);
    if (count > maximum) return error.SnapshotLimitExceeded;
    const replay = try cursor.readOptionalInt(u32);
    var state = State{ .replay_index = if (replay) |index| @intCast(index) else null };
    errdefer state.deinit(allocator);
    if (state.replay_index) |index| if (index > count) return error.CorruptSnapshot;
    var filters: std.StringHashMapUnmanaged(void) = .empty;
    defer filters.deinit(allocator);
    for (0..count) |_| {
        const bytes = try cursor.readBlob();
        var packet = mqtt.Subscribe.parse(allocator, protocol, bytes) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return error.CorruptSnapshot,
        };
        defer packet.deinit(allocator);
        if (packet.packet_id != 1 or packet.dup or packet.subscriptions.len != 1) return error.CorruptSnapshot;
        const entry = try filters.getOrPut(allocator, packet.subscriptions[0].topic_filter);
        if (entry.found_existing) return error.CorruptSnapshot;
        var copied = try Owned.clone(allocator, packet.subscriptions[0], packet.properties);
        errdefer copied.deinit(allocator);
        try state.values.append(allocator, copied);
    }
    if (state.replay_index == count) state.replay_index = null;
    return state;
}
