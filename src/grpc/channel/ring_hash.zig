//! grpc-core-compatible `ring_hash_experimental` ketama ring.

const std = @import("std");

pub const max_configured_ring_size: usize = 8_388_608;
pub const default_ring_size_cap: usize = 4096;

pub const Config = struct {
    min_ring_size: usize = 1024,
    max_ring_size: usize = 4096,
    request_hash_header: ?[]const u8 = null,
};

pub fn endpointWeight(endpoint: anytype) u32 {
    return switch (endpoint) {
        .cleartext_ip => |target| target.ring_hash_weight,
        .cleartext_host => |target| target.ring_hash_weight,
        .tls_host => |target| target.ring_hash_weight,
        .tls_address => |target| target.ring_hash_weight,
        .custom => |target| target.ring_hash_weight,
    };
}

pub fn endpointKey(
    endpoint: anytype,
    out: []u8,
) error{ InvalidChannelOptions, BufferTooSmall }![]const u8 {
    const configured = switch (endpoint) {
        .cleartext_ip => |target| target.ring_hash_key,
        .cleartext_host => |target| target.ring_hash_key,
        .tls_host => |target| target.ring_hash_key,
        .tls_address => |target| target.ring_hash_key,
        .custom => |target| target.ring_hash_key,
    };
    if (configured) |key| {
        if (key.len == 0) return error.InvalidChannelOptions;
        return key;
    }
    return switch (endpoint) {
        .cleartext_ip => |target| std.fmt.bufPrint(
            out,
            "{f}",
            .{target.address},
        ) catch error.BufferTooSmall,
        .tls_address => |target| std.fmt.bufPrint(
            out,
            "{f}",
            .{target.address},
        ) catch error.BufferTooSmall,
        .cleartext_host => |target| std.fmt.bufPrint(
            out,
            "{s}:{d}",
            .{ target.host, target.port },
        ) catch error.BufferTooSmall,
        .tls_host => |target| std.fmt.bufPrint(
            out,
            "{s}:{d}",
            .{ target.host, target.port },
        ) catch error.BufferTooSmall,
        .custom => error.InvalidChannelOptions,
    };
}

pub fn sameEndpointIdentity(left: anytype, right: @TypeOf(left)) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        inline else => |left_value, tag| blk: {
            var normalized_left = left_value;
            var normalized_right = @field(right, @tagName(tag));
            normalized_left.ring_hash_weight = 1;
            normalized_right.ring_hash_weight = 1;
            normalized_left.locality_weight = 0;
            normalized_right.locality_weight = 0;
            break :blk std.meta.eql(normalized_left, normalized_right);
        },
    };
}

pub fn uniqueEndpointCount(endpoints: anytype) usize {
    var count: usize = 0;
    for (endpoints, 0..) |endpoint, index| {
        for (endpoints[0..index]) |prior| {
            if (sameEndpointIdentity(prior, endpoint)) break;
        } else {
            count += 1;
        }
    }
    return count;
}

pub const Entry = struct {
    hash: u64,
    endpoint_index: usize,
};

pub const Ring = struct {
    entries: []Entry = &.{},

    pub fn deinit(self: *Ring, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        self.* = .{};
    }

    pub fn rebuild(
        self: *Ring,
        allocator: std.mem.Allocator,
        context: anytype,
        endpoint_count: usize,
        config: Config,
        ring_size_cap: usize,
        comptime keyFor: anytype,
        comptime weightFor: anytype,
    ) !void {
        if (endpoint_count == 0) {
            const previous = self.entries;
            self.entries = &.{};
            allocator.free(previous);
            return;
        }
        var weight_sum: u64 = 0;
        var minimum_weight: u32 = std.math.maxInt(u32);
        for (0..endpoint_count) |index| {
            const weight: u32 = @max(weightFor(context, index), 1);
            weight_sum = std.math.add(u64, weight_sum, weight) catch
                return error.InvalidRingWeight;
            minimum_weight = @min(minimum_weight, weight);
        }
        const min_normalized = @as(f64, @floatFromInt(minimum_weight)) /
            @as(f64, @floatFromInt(weight_sum));
        const minimum = @min(config.min_ring_size, ring_size_cap);
        const maximum = @min(config.max_ring_size, ring_size_cap);
        const scale = @min(
            @ceil(min_normalized * @as(f64, @floatFromInt(minimum))) /
                min_normalized,
            @as(f64, @floatFromInt(maximum)),
        );
        const ring_size: usize = @intFromFloat(@ceil(scale));
        const replacement = try allocator.alloc(Entry, ring_size);
        errdefer allocator.free(replacement);

        var current_hashes: f64 = 0;
        var target_hashes: f64 = 0;
        var entry_index: usize = 0;
        var key_buffer: [256]u8 = undefined;
        var count_buffer: [32]u8 = undefined;
        for (0..endpoint_count) |endpoint_index| {
            const weight: u32 = @max(weightFor(context, endpoint_index), 1);
            const normalized = @as(f64, @floatFromInt(weight)) /
                @as(f64, @floatFromInt(weight_sum));
            target_hashes += scale * normalized;
            const key = try keyFor(context, endpoint_index, &key_buffer);
            var count: usize = 0;
            while (current_hashes < target_hashes) {
                const count_text = std.fmt.bufPrint(
                    &count_buffer,
                    "{d}",
                    .{count},
                ) catch unreachable;
                var hasher = std.hash.XxHash64.init(0);
                hasher.update(key);
                hasher.update("_");
                hasher.update(count_text);
                replacement[entry_index] = .{
                    .hash = hasher.final(),
                    .endpoint_index = endpoint_index,
                };
                entry_index += 1;
                count += 1;
                current_hashes += 1;
            }
        }
        std.debug.assert(entry_index == replacement.len);
        std.mem.sort(Entry, replacement, {}, lessThan);
        const previous = self.entries;
        self.entries = replacement;
        allocator.free(previous);
    }

    pub fn start(self: *const Ring, request_hash: u64) ?usize {
        if (self.entries.len == 0) return null;
        var low: usize = 0;
        var high: usize = self.entries.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.entries[middle].hash < request_hash) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        return if (low == self.entries.len) 0 else low;
    }

    pub fn endpointAt(
        self: *const Ring,
        start_index: usize,
        offset: usize,
    ) usize {
        return self.entries[(start_index + offset) % self.entries.len]
            .endpoint_index;
    }

    pub fn uniqueEndpointAt(
        self: *const Ring,
        start_index: usize,
        ordinal: usize,
    ) ?usize {
        var unique: usize = 0;
        for (0..self.entries.len) |offset| {
            const endpoint = self.endpointAt(start_index, offset);
            for (0..offset) |prior_offset| {
                if (self.endpointAt(start_index, prior_offset) == endpoint) {
                    break;
                }
            } else {
                if (unique == ordinal) return endpoint;
                unique += 1;
            }
        }
        return null;
    }
};

pub fn hash(bytes: []const u8) u64 {
    return std.hash.XxHash64.hash(0, bytes);
}

pub const RequestHash = struct {
    value: u64,
    random: bool = false,
};

pub fn requestHash(
    io: std.Io,
    config: Config,
    options: anytype,
) error{MissingRequestHash}!RequestHash {
    if (config.request_hash_header) |name| {
        var selected: ?[]const u8 = null;
        for (options.metadata) |field| {
            if (std.mem.eql(u8, field.name, name)) selected = field.value;
        }
        if (selected) |value| return .{ .value = hash(value) };
        var random: u64 = undefined;
        io.random(std.mem.asBytes(&random));
        return .{ .value = random, .random = true };
    }
    return .{ .value = options.request_hash orelse
        return error.MissingRequestHash };
}

pub fn virtualNodeHash(key: []const u8, index: usize) u64 {
    var count_buffer: [32]u8 = undefined;
    const count = std.fmt.bufPrint(&count_buffer, "{d}", .{index}) catch
        unreachable;
    var hasher = std.hash.XxHash64.init(0);
    hasher.update(key);
    hasher.update("_");
    hasher.update(count);
    return hasher.final();
}

fn lessThan(_: void, left: Entry, right: Entry) bool {
    if (left.hash != right.hash) return left.hash < right.hash;
    return left.endpoint_index < right.endpoint_index;
}

test "gRPC ring hash builds grpc-core equal and weighted ketama rings" {
    const Endpoint = struct {
        key: []const u8,
        weight: u32,
    };
    const Access = struct {
        fn keyFor(
            endpoints: []const Endpoint,
            index: usize,
            _: *[256]u8,
        ) ![]const u8 {
            return endpoints[index].key;
        }
        fn weightFor(endpoints: []const Endpoint, index: usize) u32 {
            return endpoints[index].weight;
        }
    };
    const allocator = std.testing.allocator;
    var ring: Ring = .{};
    defer ring.deinit(allocator);
    const equal = [_]Endpoint{
        .{ .key = "a", .weight = 1 },
        .{ .key = "b", .weight = 1 },
        .{ .key = "c", .weight = 1 },
    };
    try ring.rebuild(
        allocator,
        &equal,
        equal.len,
        .{ .min_ring_size = 12, .max_ring_size = 12 },
        default_ring_size_cap,
        Access.keyFor,
        Access.weightFor,
    );
    try std.testing.expectEqual(@as(usize, 12), ring.entries.len);
    var counts = [_]usize{ 0, 0, 0 };
    for (ring.entries) |entry| counts[entry.endpoint_index] += 1;
    try std.testing.expectEqualSlices(usize, &.{ 4, 4, 4 }, &counts);
    const b_start = ring.start(virtualNodeHash("b", 0)).?;
    try std.testing.expectEqual(
        @as(usize, 1),
        ring.entries[b_start].endpoint_index,
    );

    const weighted = [_]Endpoint{
        .{ .key = "a", .weight = 1 },
        .{ .key = "b", .weight = 3 },
    };
    try ring.rebuild(
        allocator,
        &weighted,
        weighted.len,
        .{ .min_ring_size = 12, .max_ring_size = 12 },
        default_ring_size_cap,
        Access.keyFor,
        Access.weightFor,
    );
    counts = .{ 0, 0, 0 };
    for (ring.entries) |entry| counts[entry.endpoint_index] += 1;
    try std.testing.expectEqualSlices(usize, &.{ 3, 9 }, counts[0..2]);
}

test "gRPC ring hash wraps request hashes above the final entry" {
    const Endpoint = struct { key: []const u8 };
    const Access = struct {
        fn keyFor(
            endpoints: []const Endpoint,
            index: usize,
            _: *[256]u8,
        ) ![]const u8 {
            return endpoints[index].key;
        }
        fn weightFor(_: []const Endpoint, _: usize) u32 {
            return 1;
        }
    };
    const allocator = std.testing.allocator;
    var ring: Ring = .{};
    defer ring.deinit(allocator);
    const endpoints = [_]Endpoint{.{ .key = "only" }};
    try ring.rebuild(
        allocator,
        &endpoints,
        endpoints.len,
        .{ .min_ring_size = 4, .max_ring_size = 4 },
        default_ring_size_cap,
        Access.keyFor,
        Access.weightFor,
    );
    try std.testing.expectEqual(@as(?usize, 0), ring.start(std.math.maxInt(u64)));
    try std.testing.expectEqual(
        @as(u64, 0x26c7827d889f6da3),
        hash("hello"),
    );
}

test "gRPC ring hash resolves explicit and metadata request hashes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Header = struct { name: []const u8, value: []const u8 };
    const Options = struct {
        request_hash: ?u64 = null,
        metadata: []const Header = &.{},
    };
    const explicit = try requestHash(io, .{}, Options{ .request_hash = 42 });
    try std.testing.expectEqual(@as(u64, 42), explicit.value);
    try std.testing.expect(!explicit.random);
    try std.testing.expectError(
        error.MissingRequestHash,
        requestHash(io, .{}, Options{}),
    );
    const metadata = [_]Header{
        .{ .name = "x-shard", .value = "first" },
        .{ .name = "x-shard", .value = "final" },
    };
    const from_header = try requestHash(
        io,
        .{ .request_hash_header = "x-shard" },
        Options{ .request_hash = 42, .metadata = &metadata },
    );
    try std.testing.expectEqual(hash("final"), from_header.value);
    try std.testing.expect(!from_header.random);
    const random = try requestHash(
        io,
        .{ .request_hash_header = "x-shard" },
        Options{},
    );
    try std.testing.expect(random.random);
}
