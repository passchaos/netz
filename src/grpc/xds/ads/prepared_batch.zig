//! Allocate every desired type/name before one application publication.
const std = @import("std");
const subscriptions = @import("subscriptions.zig");
pub const Subscription = struct { type_url: []const u8, names: []const []const u8 };
pub const Batch = struct {
    allocator: std.mem.Allocator,
    items: []subscriptions.Prepared,
    pub fn deinit(self: *Batch) void {
        for (self.items) |*item| item.deinit();
        self.allocator.free(self.items);
        self.* = undefined;
    }
    pub fn commit(self: *Batch) void {
        for (self.items) |*item| item.commit();
    }
};
pub fn prepare(state: *subscriptions.State, requested: []const Subscription) subscriptions.Error!Batch {
    if (requested.len > state.options.max_types) return error.DiscoveryTypeLimit;
    var missing: usize = 0;
    for (requested, 0..) |item, index| {
        for (requested[0..index]) |previous| if (std.mem.eql(u8, previous.type_url, item.type_url)) return error.InvalidDiscoveryMessage;
        if (state.find(item.type_url) == null) missing += 1;
    }
    if (missing > state.options.max_types -| state.entries.items.len) return error.DiscoveryTypeLimit;
    try state.entries.ensureUnusedCapacity(state.allocator, missing);
    const items = try state.allocator.alloc(subscriptions.Prepared, requested.len);
    var count: usize = 0;
    errdefer {
        for (items[0..count]) |*item| item.deinit();
        state.allocator.free(items);
    }
    for (requested, items) |item, *prepared| {
        prepared.* = try state.prepare(item.type_url, item.names);
        count += 1;
    }
    return .{ .allocator = state.allocator, .items = items };
}
