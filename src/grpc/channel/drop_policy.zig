//! EDS-style ordered drop categories evaluated before endpoint selection.
const std = @import("std");
pub const Category = struct { category: []const u8, requests_per_million: u32 };
pub const Error = std.mem.Allocator.Error || error{InvalidDropPolicy};
pub const Stats = struct { evaluated: u64, dropped: u64 };
pub const Counters = struct {
    evaluated: std.atomic.Value(u64) = .init(0),
    dropped: std.atomic.Value(u64) = .init(0),
    pub fn snapshot(self: *const Counters) Stats {
        return .{ .evaluated = self.evaluated.load(.acquire), .dropped = self.dropped.load(.acquire) };
    }
};
pub const Policy = struct {
    allocator: ?std.mem.Allocator = null,
    categories: []const Category = &.{},
    pub fn init(gpa: std.mem.Allocator, categories: []const Category) Error!Policy {
        if (categories.len == 0) return .{};
        if (categories.len > 256) return error.InvalidDropPolicy;
        for (categories) |value| if (value.category.len == 0 or value.category.len > 4096 or !std.unicode.utf8ValidateSlice(value.category) or value.requests_per_million > 1000000) return error.InvalidDropPolicy;
        const owned = try gpa.alloc(Category, categories.len);
        var count: usize = 0;
        errdefer {
            for (owned[0..count]) |value| gpa.free(value.category);
            gpa.free(owned);
        }
        for (owned, categories) |*value, source| {
            value.* = .{ .category = try gpa.dupe(u8, source.category), .requests_per_million = source.requests_per_million };
            count += 1;
        }
        return .{ .allocator = gpa, .categories = owned };
    }
    pub fn clone(self: Policy, gpa: std.mem.Allocator) Error!Policy {
        return init(gpa, self.categories);
    }
    pub fn deinit(self: *Policy) void {
        if (self.allocator) |gpa| {
            for (self.categories) |value| gpa.free(value.category);
            gpa.free(self.categories);
        }
        self.* = .{};
    }
    pub fn dropsAll(self: Policy) bool {
        for (self.categories) |value| if (value.requests_per_million == 1000000) return true;
        return false;
    }
    pub fn equivalent(self: Policy, other: Policy) bool {
        if (self.categories.len != other.categories.len) return false;
        for (self.categories, other.categories) |a, b| if (a.requests_per_million != b.requests_per_million or !std.mem.eql(u8, a.category, b.category)) return false;
        return true;
    }
    pub fn choose(self: Policy, io: std.Io, counters: *Counters) ?[]const u8 {
        if (self.categories.len == 0) return null;
        var seed: u64 = undefined;
        io.random(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);
        const Sampling = struct {
            fn next(random: std.Random) u32 {
                return random.uintLessThan(u32, 1000000);
            }
        };
        return self.chooseWith(counters, prng.random(), Sampling.next);
    }
    pub fn chooseWith(self: Policy, counters: *Counters, context: anytype, comptime sample: anytype) ?[]const u8 {
        if (self.categories.len == 0) return null;
        _ = counters.evaluated.fetchAdd(1, .monotonic);
        for (self.categories) |value| {
            if (sample(context) < value.requests_per_million) {
                _ = counters.dropped.fetchAdd(1, .monotonic);
                return value.category;
            }
        }
        return null;
    }
};

test "gRPC drop policy applies independent ordered fractions with first-match category" {
    const gpa = std.testing.allocator;
    var policy = try Policy.init(gpa, &.{ .{ .category = "zero", .requests_per_million = 0 }, .{ .category = "first", .requests_per_million = 200000 }, .{ .category = "second", .requests_per_million = 500000 } });
    defer policy.deinit();
    const Sample = struct {
        values: []const u32,
        index: usize = 0,
        fn next(self: *@This()) u32 {
            const value = self.values[self.index];
            self.index += 1;
            return value;
        }
    };
    var counters: Counters = .{};
    var first = Sample{ .values = &.{ 0, 199999, 0 } };
    try std.testing.expectEqualStrings("first", policy.chooseWith(&counters, &first, Sample.next).?);
    try std.testing.expectEqual(@as(usize, 2), first.index);
    var second = Sample{ .values = &.{ 0, 200000, 499999 } };
    try std.testing.expectEqualStrings("second", policy.chooseWith(&counters, &second, Sample.next).?);
    var accepted = Sample{ .values = &.{ 0, 200000, 500000 } };
    try std.testing.expect(policy.chooseWith(&counters, &accepted, Sample.next) == null);
    try std.testing.expectEqual(Stats{ .evaluated = 3, .dropped = 2 }, counters.snapshot());
}

test "gRPC drop policy validates and owns category strings with allocator rollback" {
    const gpa = std.testing.allocator;
    const Harness = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var policy = try Policy.init(allocator, &.{ .{ .category = "throttle", .requests_per_million = 1000000 }, .{ .category = "second", .requests_per_million = 0 } });
            defer policy.deinit();
            var clone = try policy.clone(allocator);
            defer clone.deinit();
            try std.testing.expect(clone.dropsAll());
        }
    };
    try std.testing.checkAllAllocationFailures(gpa, Harness.run, .{});
    try std.testing.expectError(error.InvalidDropPolicy, Policy.init(gpa, &.{.{ .category = "", .requests_per_million = 1 }}));
    try std.testing.expectError(error.InvalidDropPolicy, Policy.init(gpa, &.{.{ .category = "bad", .requests_per_million = 1000001 }}));
}
