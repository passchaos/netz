//! Child-local ketama construction and static-slot fallback for ordinary
//! weighted_target Channels.
const std = @import("std");
const ring_hash = @import("../ring_hash.zig");

pub fn rebuild(
    allocator: std.mem.Allocator,
    _: anytype,
    node: anytype,
    leaf: anytype,
    slots: anytype,
) !void {
    const ContextType = Context(@TypeOf(node), @TypeOf(slots));
    var context = ContextType{ .node = node, .slots = slots };
    try leaf.ring.rebuild(
        allocator,
        &context,
        uniqueSlotCount(node, slots),
        leaf.ring_hash_config,
        ring_hash.default_ring_size_cap,
        ContextType.key,
        ContextType.weight,
    );
}

pub fn pick(
    _: anytype,
    node: anytype,
    leaf: anytype,
    slots: anytype,
    io: std.Io,
    input: anytype,
) error{MissingRequestHash}!?usize {
    const request_hash = try input.resolveHash(io, leaf.ring_hash_config);
    const start = leaf.ring.start(request_hash.value) orelse return null;
    const count = uniqueSlotCount(node, slots);
    for (0..count) |ordinal| {
        const local_index = leaf.ring.uniqueEndpointAt(
            start,
            ordinal,
        ) orelse return null;
        const representative = uniqueSlotAt(
            node,
            slots,
            local_index,
        ).?;
        switch (pickLogical(node, slots, representative, io)) {
            .ready => |index| return index,
            .pending => if (!request_hash.random) return null,
            .failed => {},
        }
    }
    return null;
}

fn Context(comptime NodePointer: type, comptime Slots: type) type {
    return struct {
        node: NodePointer,
        slots: Slots,

        fn key(
            self: *@This(),
            index: usize,
            buffer: *[256]u8,
        ) ![]const u8 {
            const slot_index = uniqueSlotAt(
                self.node,
                self.slots,
                index,
            ).?;
            return ring_hash.endpointKey(
                self.slots[slot_index].endpoint,
                buffer,
            );
        }

        fn weight(self: *@This(), index: usize) u32 {
            const slot_index = uniqueSlotAt(
                self.node,
                self.slots,
                index,
            ).?;
            const endpoint = self.slots[slot_index].endpoint;
            var result: u32 = 0;
            for (self.slots) |slot| {
                if (!pathMatches(
                    slot.endpoint.hierarchicalPath(),
                    self.node.path,
                )) continue;
                if (ring_hash.sameEndpointIdentity(
                    slot.endpoint,
                    endpoint,
                )) {
                    result +|= ring_hash.endpointWeight(slot.endpoint);
                }
            }
            return result;
        }
    };
}

fn uniqueSlotCount(node: anytype, slots: anytype) usize {
    var count: usize = 0;
    for (slots, 0..) |slot, index| {
        if (!pathMatches(
            slot.endpoint.hierarchicalPath(),
            node.path,
        ) or slotDuplicate(node, slots, index)) continue;
        count += 1;
    }
    return count;
}

fn uniqueSlotAt(
    node: anytype,
    slots: anytype,
    target: usize,
) ?usize {
    var ordinal: usize = 0;
    for (slots, 0..) |slot, index| {
        if (!pathMatches(
            slot.endpoint.hierarchicalPath(),
            node.path,
        ) or slotDuplicate(node, slots, index)) continue;
        if (ordinal == target) return index;
        ordinal += 1;
    }
    return null;
}

fn slotDuplicate(node: anytype, slots: anytype, index: usize) bool {
    const endpoint = slots[index].endpoint;
    for (slots[0..index]) |prior| {
        if (!pathMatches(
            prior.endpoint.hierarchicalPath(),
            node.path,
        )) continue;
        if (ring_hash.sameEndpointIdentity(
            prior.endpoint,
            endpoint,
        )) return true;
    }
    return false;
}

const LogicalPick = union(enum) {
    ready: usize,
    pending,
    failed,
};

fn pickLogical(
    node: anytype,
    slots: anytype,
    representative: usize,
    io: std.Io,
) LogicalPick {
    const endpoint = slots[representative].endpoint;
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    var pending = false;
    for (slots, 0..) |*slot, index| {
        if (!pathMatches(
            slot.endpoint.hierarchicalPath(),
            node.path,
        ) or !ring_hash.sameEndpointIdentity(
            slot.endpoint,
            endpoint,
        )) continue;
        if (slot.disabled or slot.weighted_target_ejected) continue;
        if (slot.connection) |*connection| {
            if (connection.isReusable()) return .{ .ready = index };
        }
        if (slot.next_attempt_at_ns) |retry_at| {
            if (retry_at > now) continue;
        }
        pending = true;
    }
    return if (pending) .pending else .failed;
}

fn pathMatches(
    endpoint_path: []const []const u8,
    node_path: []const []const u8,
) bool {
    if (endpoint_path.len < node_path.len) return false;
    for (node_path, endpoint_path[0..node_path.len]) |expected, actual| {
        if (!std.mem.eql(u8, expected, actual)) return false;
    }
    return true;
}

test "ordinary weighted target ring hash collapses child endpoints" {
    const Target = struct {
        address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1) },
        host: []const u8 = "localhost",
        port: u16 = 1,
        ring_hash_key: ?[]const u8,
        ring_hash_weight: u32,
        hierarchical_path: []const []const u8,
    };
    const Endpoint = union(enum) {
        cleartext_ip: Target,
        cleartext_host: Target,
        tls_host: Target,
        tls_address: Target,
        custom: Target,

        fn hierarchicalPath(self: *const @This()) []const []const u8 {
            return switch (self.*) {
                inline else => |target| target.hierarchical_path,
            };
        }
    };
    const Connection = struct {
        ready: bool,

        fn isReusable(self: *@This()) bool {
            return self.ready;
        }
    };
    const Slot = struct {
        endpoint: Endpoint,
        connection: ?Connection,
        disabled: bool = false,
        weighted_target_ejected: bool = false,
        next_attempt_at_ns: ?i96 = null,
    };
    const Node = struct { path: []const []const u8 };
    const Leaf = struct {
        ring_hash_config: ring_hash.Config,
        ring: ring_hash.Ring = .{},
    };
    const Input = struct {
        value: u64,

        pub fn resolveHash(
            self: @This(),
            _: std.Io,
            _: ring_hash.Config,
        ) error{MissingRequestHash}!ring_hash.RequestHash {
            return .{ .value = self.value };
        }
    };
    const ring_path = [_][]const u8{"ring"};
    const sibling_path = [_][]const u8{"sibling"};
    const node = Node{ .path = &ring_path };
    var leaf = Leaf{ .ring_hash_config = .{
        .min_ring_size = 12,
        .max_ring_size = 12,
    } };
    defer leaf.ring.deinit(std.testing.allocator);
    const retry_at = std.math.maxInt(i96);
    var slots = [_]Slot{
        .{
            .endpoint = .{ .custom = .{
                .ring_hash_key = "a",
                .ring_hash_weight = 1,
                .hierarchical_path = &ring_path,
            } },
            .connection = null,
            .next_attempt_at_ns = retry_at,
        },
        .{
            .endpoint = .{ .custom = .{
                .ring_hash_key = "a",
                .ring_hash_weight = 2,
                .hierarchical_path = &ring_path,
            } },
            .connection = .{ .ready = true },
        },
        .{
            .endpoint = .{ .custom = .{
                .ring_hash_key = "b",
                .ring_hash_weight = 1,
                .hierarchical_path = &ring_path,
            } },
            .connection = .{ .ready = true },
        },
        .{
            .endpoint = .{ .custom = .{
                .ring_hash_key = "a",
                .ring_hash_weight = 100,
                .hierarchical_path = &sibling_path,
            } },
            .connection = .{ .ready = true },
        },
    };
    try rebuild(
        std.testing.allocator,
        {},
        &node,
        &leaf,
        &slots,
    );
    try std.testing.expectEqual(@as(usize, 12), leaf.ring.entries.len);
    var counts = [_]usize{ 0, 0 };
    for (leaf.ring.entries) |entry| counts[entry.endpoint_index] += 1;
    try std.testing.expectEqualSlices(usize, &.{ 9, 3 }, &counts);

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectEqual(
        @as(?usize, 1),
        try pick(
            {},
            &node,
            &leaf,
            &slots,
            threaded.io(),
            Input{ .value = ring_hash.virtualNodeHash("a", 0) },
        ),
    );
    try std.testing.expectEqual(
        @as(?usize, 2),
        try pick(
            {},
            &node,
            &leaf,
            &slots,
            threaded.io(),
            Input{ .value = ring_hash.virtualNodeHash("b", 0) },
        ),
    );
}
