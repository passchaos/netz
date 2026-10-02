const std = @import("std");

pub const Origins = struct {
    values: std.ArrayList([]u8) = .empty,
    index: std.StringHashMapUnmanaged(usize) = .empty,

    pub fn deinit(self: *Origins, allocator: std.mem.Allocator) void {
        for (self.values.items) |origin| allocator.free(origin);
        self.values.deinit(allocator);
        self.index.deinit(allocator);
        self.* = undefined;
    }

    pub fn items(self: *const Origins) []const []u8 {
        return self.values.items;
    }

    pub fn capacity(self: *const Origins) usize {
        return self.values.capacity;
    }

    pub fn contains(self: *const Origins, origin: []const u8) bool {
        return self.index.contains(origin);
    }

    pub fn getIndex(self: *const Origins, origin: []const u8) ?usize {
        return self.index.get(origin);
    }

    pub fn store(
        self: *Origins,
        allocator: std.mem.Allocator,
        origin: []const u8,
        limit: usize,
    ) std.mem.Allocator.Error!void {
        if (self.index.contains(origin)) return;
        if (self.values.items.len >= limit) return;

        const slot = try self.index.getOrPut(allocator, origin);
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.index.remove(origin);
        const owned = try allocator.dupe(u8, origin);
        errdefer allocator.free(owned);
        const index = self.values.items.len;
        try self.values.append(allocator, owned);
        self.index.getKeyPtr(origin).?.* = owned;
        slot.value_ptr.* = index;
    }
};

const AlternativeServiceKey = struct {
    stream_id: u31,
    origin: []const u8,
};

const AlternativeServiceKeyContext = struct {
    pub fn hash(_: @This(), key: AlternativeServiceKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, key.stream_id);
        std.hash.autoHash(&hasher, key.origin.len);
        hasher.update(key.origin);
        return hasher.final();
    }

    pub fn eql(
        _: @This(),
        lhs: AlternativeServiceKey,
        rhs: AlternativeServiceKey,
    ) bool {
        return lhs.stream_id == rhs.stream_id and
            std.mem.eql(u8, lhs.origin, rhs.origin);
    }
};

const AlternativeServiceIndex = std.HashMapUnmanaged(
    AlternativeServiceKey,
    usize,
    AlternativeServiceKeyContext,
    std.hash_map.default_max_load_percentage,
);

pub const AlternativeService = struct {
    stream_id: u31,
    origin: []u8,
    field_value: []u8,

    fn deinit(self: *AlternativeService, allocator: std.mem.Allocator) void {
        allocator.free(self.origin);
        allocator.free(self.field_value);
        self.* = undefined;
    }
};

pub const AlternativeServices = struct {
    values: std.ArrayList(AlternativeService) = .empty,
    index: AlternativeServiceIndex = .empty,

    pub fn deinit(
        self: *AlternativeServices,
        allocator: std.mem.Allocator,
    ) void {
        for (self.values.items) |*service| service.deinit(allocator);
        self.values.deinit(allocator);
        self.index.deinit(allocator);
        self.* = undefined;
    }

    pub fn items(self: *const AlternativeServices) []const AlternativeService {
        return self.values.items;
    }

    pub fn capacity(self: *const AlternativeServices) usize {
        return self.values.capacity;
    }

    pub fn getIndex(
        self: *const AlternativeServices,
        stream_id: u31,
        origin: []const u8,
    ) ?usize {
        return self.index.get(.{ .stream_id = stream_id, .origin = origin });
    }

    pub fn store(
        self: *AlternativeServices,
        allocator: std.mem.Allocator,
        stream_id: u31,
        origin_value: []const u8,
        field_value: []const u8,
        limit: usize,
    ) std.mem.Allocator.Error!void {
        const key = AlternativeServiceKey{
            .stream_id = stream_id,
            .origin = origin_value,
        };
        if (self.index.get(key)) |index| {
            const service = &self.values.items[index];
            if (std.mem.eql(u8, service.field_value, field_value)) return;

            const origin = try allocator.dupe(u8, origin_value);
            errdefer allocator.free(origin);
            const value = try allocator.dupe(u8, field_value);
            errdefer allocator.free(value);
            const key_ptr = self.index.getKeyPtr(key) orelse unreachable;
            key_ptr.* = .{ .stream_id = stream_id, .origin = origin };
            allocator.free(service.origin);
            allocator.free(service.field_value);
            service.origin = origin;
            service.field_value = value;
            return;
        }
        if (self.values.items.len >= limit) return;

        const slot = try self.index.getOrPut(allocator, key);
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.index.remove(key);
        const origin = try allocator.dupe(u8, origin_value);
        errdefer allocator.free(origin);
        const value = try allocator.dupe(u8, field_value);
        errdefer allocator.free(value);
        const index = self.values.items.len;
        try self.values.append(allocator, .{
            .stream_id = stream_id,
            .origin = origin,
            .field_value = value,
        });
        slot.key_ptr.* = .{ .stream_id = stream_id, .origin = origin };
        slot.value_ptr.* = index;
    }
};

test "peer metadata containers remain pointer-sized in connections" {
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(Origins));
        try std.testing.expectEqual(
            @as(usize, 48),
            @sizeOf(AlternativeServices),
        );
    }
}

fn exerciseOriginsAllocationFailures(allocator: std.mem.Allocator) !void {
    var origins = Origins{};
    defer origins.deinit(allocator);
    try origins.store(allocator, "https://one.example", 2);
    try origins.store(allocator, "https://one.example", 2);
    try origins.store(allocator, "https://two.example", 2);
    try origins.store(allocator, "https://ignored.example", 2);
    try std.testing.expectEqual(@as(usize, 2), origins.items().len);
    try std.testing.expect(origins.contains("https://one.example"));
    try std.testing.expect(origins.contains("https://two.example"));
}

test "origin metadata is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseOriginsAllocationFailures,
        .{},
    );
}

fn exerciseAlternativeServiceAllocationFailures(
    allocator: std.mem.Allocator,
) !void {
    var services = AlternativeServices{};
    defer services.deinit(allocator);
    try services.store(
        allocator,
        0,
        "https://example.com",
        "h3=\":443\"",
        2,
    );
    try services.store(
        allocator,
        0,
        "https://example.com",
        "h3=\":8443\"",
        2,
    );
    try services.store(
        allocator,
        1,
        "",
        "h2=\"alt.example.com:443\"",
        2,
    );
    try services.store(
        allocator,
        3,
        "",
        "h2=\"ignored.example.com:443\"",
        2,
    );
    try std.testing.expectEqual(@as(usize, 2), services.items().len);
    try std.testing.expectEqualStrings(
        "h3=\":8443\"",
        services.items()[0].field_value,
    );
}

test "alternative-service metadata is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseAlternativeServiceAllocationFailures,
        .{},
    );
}
