const std = @import("std");
const Storage = @import("packet_identifiers/storage.zig").Storage;
const Incoming = Storage(u2);
pub const Ownership = @import("../identifier/ownership.zig").Ownership;
const Outgoing = struct {
    stages: Storage(u3) = .{},
    filter_counts: std.AutoHashMapUnmanaged(u16, usize) = .empty,
    external: ?Ownership = null,

    fn deinit(self: *Outgoing, allocator: std.mem.Allocator) void {
        self.stages.deinit(allocator);
        self.filter_counts.deinit(allocator);
    }
};

/// Sparse connection-local MQTT Packet Identifier ownership.
///
/// Incoming and outgoing Packet Identifier spaces are independent, so one
/// numeric identifier may carry one flag from each direction. QoS 2 stage
/// changes mutate an existing entry and therefore cannot allocate after a
/// protocol packet has already been written.
pub const State = struct {
    pub const Stage = enum(u3) {
        incoming_qos1,
        incoming_qos2,
        outgoing_qos1,
        outgoing_qos2,
        outgoing_qos2_pubrel,
        outgoing_subscribe,
        outgoing_unsubscribe,
    };

    // Keep the two MQTT Packet Identifier spaces physically separate and
    // allocate each only when its direction first needs a Packet Identifier. A
    // connection may have one receive owner and one serialized writer active
    // concurrently; neither direction initializes or mutates the other's map.
    incoming: ?*Incoming = null,
    outgoing: ?*Outgoing = null,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        if (self.incoming) |entries| {
            entries.deinit(allocator);
            allocator.destroy(entries);
        }
        if (self.outgoing) |entries| {
            entries.deinit(allocator);
            allocator.destroy(entries);
        }
        self.* = .{};
    }

    pub fn contains(self: *const State, packet_id: u16, stage: Stage) bool {
        return switch (direction(stage)) {
            .incoming => if (self.incoming) |entries| entries.contains(packet_id, @intCast(code(stage))) else false,
            .outgoing => if (self.outgoing) |entries| entries.stages.contains(packet_id, code(stage)) else false,
        };
    }

    pub fn containsOutgoing(self: *const State, packet_id: u16) bool {
        const outgoing = self.outgoing orelse return false;
        return outgoing.stages.value(packet_id) != 0 or
            if (outgoing.external) |owner| owner.contains(packet_id) else false;
    }

    /// The owner must remain live until detached/reset/deinit. Its lookup is
    /// borrowed and follows Session mutations without duplicating all IDs.
    pub fn setExternalOutgoing(self: *State, allocator: std.mem.Allocator, owner: ?Ownership) std.mem.Allocator.Error!void {
        if (self.outgoing == null) {
            if (owner == null) return;
            const outgoing = try allocator.create(Outgoing);
            outgoing.* = .{};
            self.outgoing = outgoing;
        }
        self.outgoing.?.external = owner;
    }

    /// Short-lived reservation view, usable while this State remains at its
    /// current address. Session allocation passes it only for the active call.
    pub fn ownership(self: *const State) Ownership {
        return .{ .context = self, .containsFn = containsBorrowed };
    }

    fn containsBorrowed(context: *const anyopaque, packet_id: u16) bool {
        const self: *const State = @ptrCast(@alignCast(context));
        return self.containsOutgoing(packet_id);
    }

    pub fn containsOutgoingPublish(self: *const State, packet_id: u16) bool {
        const outgoing = self.outgoing orelse return false;
        const stage_code = outgoing.stages.value(packet_id);
        return stage_code >= 1 and stage_code <= 3;
    }

    /// Add one stage, returning false when it was already present.
    pub fn add(
        self: *State,
        allocator: std.mem.Allocator,
        packet_id: u16,
        stage: Stage,
    ) std.mem.Allocator.Error!bool {
        std.debug.assert(packet_id != 0);
        switch (direction(stage)) {
            .incoming => {
                if (self.incoming) |entries| return entries.add(allocator, packet_id, @intCast(code(stage)));
                const entries = try allocator.create(Incoming);
                entries.* = .{};
                errdefer allocator.destroy(entries);
                errdefer entries.deinit(allocator);
                const added = try entries.add(allocator, packet_id, @intCast(code(stage)));
                self.incoming = entries;
                return added;
            },
            .outgoing => {
                if (self.outgoing) |entries| return entries.stages.add(allocator, packet_id, code(stage));
                const entries = try allocator.create(Outgoing);
                entries.* = .{};
                errdefer allocator.destroy(entries);
                errdefer entries.deinit(allocator);
                const added = try entries.stages.add(allocator, packet_id, code(stage));
                self.outgoing = entries;
                return added;
            },
        }
    }

    /// Reserve a control exchange's stage and expected response count before
    /// writing. Either both pieces commit or the identifier remains unused.
    pub fn addControl(self: *State, allocator: std.mem.Allocator, packet_id: u16, stage: Stage, filter_count: usize) std.mem.Allocator.Error!void {
        std.debug.assert(stage == .outgoing_subscribe or stage == .outgoing_unsubscribe);
        std.debug.assert(!self.containsOutgoing(packet_id));
        _ = try self.add(allocator, packet_id, stage);
        errdefer _ = self.remove(packet_id, stage);
        try self.outgoing.?.filter_counts.putNoClobber(allocator, packet_id, filter_count);
    }

    pub fn controlFilterCount(self: *const State, packet_id: u16, stage: Stage) ?usize {
        if (!self.contains(packet_id, stage)) return null;
        return self.outgoing.?.filter_counts.get(packet_id);
    }

    /// Remove the matching stage in its own direction, including control data.
    pub fn remove(self: *State, packet_id: u16, stage: Stage) bool {
        const removed = switch (direction(stage)) {
            .incoming => if (self.incoming) |entries| entries.remove(packet_id, @intCast(code(stage))) else false,
            .outgoing => if (self.outgoing) |entries| entries.stages.remove(packet_id, code(stage)) else false,
        };
        if (removed and (stage == .outgoing_subscribe or stage == .outgoing_unsubscribe)) {
            _ = self.outgoing.?.filter_counts.remove(packet_id);
        }
        return removed;
    }

    /// Move an existing identifier between QoS stages without allocation.
    pub fn transition(
        self: *State,
        packet_id: u16,
        from: Stage,
        to: Stage,
    ) bool {
        std.debug.assert(direction(from) == direction(to));
        return switch (direction(from)) {
            .incoming => if (self.incoming) |entries| entries.transition(packet_id, @intCast(code(from)), @intCast(code(to))) else false,
            .outgoing => if (self.outgoing) |entries| entries.stages.transition(packet_id, code(from), code(to)) else false,
        };
    }

    pub fn clearRetainingCapacity(self: *State) void {
        if (self.incoming) |entries| entries.clearRetainingCapacity();
        if (self.outgoing) |entries| {
            entries.stages.clearRetainingCapacity();
            entries.filter_counts.clearRetainingCapacity();
            entries.external = null;
        }
    }

    pub fn count(self: *const State, stage: Stage) usize {
        return switch (direction(stage)) {
            .incoming => if (self.incoming) |entries| entries.count(@intCast(code(stage))) else 0,
            .outgoing => if (self.outgoing) |entries| entries.stages.count(code(stage)) else 0,
        };
    }

    const Direction = enum { incoming, outgoing };

    fn direction(stage: Stage) Direction {
        return switch (stage) {
            .incoming_qos1, .incoming_qos2 => .incoming,
            .outgoing_qos1,
            .outgoing_qos2,
            .outgoing_qos2_pubrel,
            .outgoing_subscribe,
            .outgoing_unsubscribe,
            => .outgoing,
        };
    }

    fn code(stage: Stage) u3 {
        return switch (stage) {
            .incoming_qos1, .outgoing_qos1 => 1,
            .incoming_qos2, .outgoing_qos2 => 2,
            .outgoing_qos2_pubrel => 3,
            .outgoing_subscribe => 4,
            .outgoing_unsubscribe => 5,
        };
    }
};

test "MQTT packet identifier state is sparse and direction independent" {
    const legacy_bytes = 5 *
        @sizeOf(std.StaticBitSet(@as(usize, std.math.maxInt(u16)) + 1));
    try std.testing.expect(@sizeOf(State) * 100 < legacy_bytes);

    var state: State = .{};
    defer state.deinit(std.testing.allocator);
    try std.testing.expect(state.incoming == null);
    try std.testing.expect(state.outgoing == null);
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 16), @sizeOf(State));
    }
    try std.testing.expect(!state.contains(65_535, .incoming_qos2));
    try std.testing.expect(try state.add(
        std.testing.allocator,
        65_535,
        .incoming_qos2,
    ));
    try std.testing.expect(try state.add(
        std.testing.allocator,
        65_535,
        .outgoing_qos1,
    ));
    try std.testing.expect(!try state.add(
        std.testing.allocator,
        65_535,
        .outgoing_qos1,
    ));
    try std.testing.expect(state.contains(65_535, .incoming_qos2));
    try std.testing.expect(state.containsOutgoing(65_535));
    try std.testing.expectEqual(
        @as(usize, 1),
        state.count(.outgoing_qos1),
    );

    try std.testing.expect(state.remove(65_535, .outgoing_qos1));
    try std.testing.expect(!state.containsOutgoing(65_535));
    try std.testing.expect(state.contains(65_535, .incoming_qos2));
    try std.testing.expect(state.remove(65_535, .incoming_qos2));
    try std.testing.expectEqual(@as(usize, 0), state.incoming.?.sparse.count());
    try std.testing.expectEqual(@as(usize, 0), state.outgoing.?.stages.sparse.count());
}

test "MQTT packet identifier QoS 2 transition retains allocation" {
    var counting = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var state: State = .{};
    defer state.deinit(counting.allocator());

    try std.testing.expect(try state.add(
        counting.allocator(),
        42,
        .outgoing_qos2,
    ));
    const allocations = counting.allocations;
    counting.fail_index = counting.alloc_index;
    try std.testing.expect(!try state.add(
        counting.allocator(),
        42,
        .outgoing_qos2,
    ));
    try std.testing.expect(state.transition(
        42,
        .outgoing_qos2,
        .outgoing_qos2_pubrel,
    ));
    try std.testing.expectEqual(allocations, counting.allocations);
    try std.testing.expect(!state.contains(42, .outgoing_qos2));
    try std.testing.expect(state.contains(42, .outgoing_qos2_pubrel));
    state.clearRetainingCapacity();
    try std.testing.expect(state.incoming == null);
    try std.testing.expectEqual(@as(usize, 0), state.outgoing.?.stages.sparse.count());
}

test "MQTT packet identifier allocation failure changes no state" {
    var descriptor_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var state: State = .{};
    defer state.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.OutOfMemory,
        state.add(descriptor_failure.allocator(), 7, .incoming_qos1),
    );
    try std.testing.expect(state.incoming == null);
    try std.testing.expect(state.outgoing == null);

    var map_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        state.add(map_failure.allocator(), 7, .incoming_qos1),
    );
    try std.testing.expect(state.incoming == null);
    try std.testing.expect(state.outgoing == null);
}

test "MQTT packet identifier state promotes to bounded dense storage" {
    var state: State = .{};
    defer state.deinit(std.testing.allocator);

    for (1..Incoming.sparse_limit + 2) |packet_id| {
        try std.testing.expect(try state.add(
            std.testing.allocator,
            @intCast(packet_id),
            .incoming_qos1,
        ));
    }
    try std.testing.expect(state.incoming.?.dense != null);
    try std.testing.expectEqual(
        @as(usize, Incoming.sparse_limit + 1),
        state.count(.incoming_qos1),
    );
    try std.testing.expect(state.remove(1, .incoming_qos1));
    try std.testing.expect(!state.contains(1, .incoming_qos1));
    try std.testing.expect(state.contains(
        @intCast(Incoming.sparse_limit + 1),
        .incoming_qos1,
    ));
    try std.testing.expect(try state.add(
        std.testing.allocator,
        65_535,
        .incoming_qos2,
    ));
    try std.testing.expect(state.contains(65_535, .incoming_qos2));
    state.clearRetainingCapacity();
    try std.testing.expect(!state.contains(65_535, .incoming_qos2));
}

test "MQTT packet identifier dense promotion failure preserves sparse state" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var state: State = .{};
    defer state.deinit(failing.allocator());

    for (1..Incoming.sparse_limit + 1) |packet_id| {
        try std.testing.expect(try state.add(
            failing.allocator(),
            @intCast(packet_id),
            .outgoing_qos1,
        ));
    }
    try std.testing.expect(state.outgoing.?.stages.dense == null);
    const allocations = failing.allocations;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        state.add(
            failing.allocator(),
            @intCast(Incoming.sparse_limit + 1),
            .outgoing_qos1,
        ),
    );
    try std.testing.expectEqual(allocations, failing.allocations);
    try std.testing.expect(state.outgoing.?.stages.dense == null);
    try std.testing.expectEqual(
        @as(usize, Incoming.sparse_limit),
        state.count(.outgoing_qos1),
    );
    try std.testing.expect(!state.contains(
        @intCast(Incoming.sparse_limit + 1),
        .outgoing_qos1,
    ));
}

test "MQTT packet identifier control metadata rolls back on allocation failure" {
    var succeeded = false;
    for (0..16) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var state: State = .{};
        defer state.deinit(failing.allocator());
        state.addControl(failing.allocator(), 42, .outgoing_subscribe, 3) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(!state.containsOutgoing(42));
            try std.testing.expectEqual(@as(?usize, null), state.controlFilterCount(42, .outgoing_subscribe));
            continue;
        };
        succeeded = true;
        failing.fail_index = failing.alloc_index;
        try std.testing.expectEqual(@as(?usize, 3), state.controlFilterCount(42, .outgoing_subscribe));
        try std.testing.expect(!state.remove(42, .outgoing_unsubscribe));
        try std.testing.expectEqual(@as(?usize, 3), state.controlFilterCount(42, .outgoing_subscribe));
        try std.testing.expect(state.remove(42, .outgoing_subscribe));
        try std.testing.expectEqual(@as(?usize, null), state.controlFilterCount(42, .outgoing_subscribe));
        try state.addControl(failing.allocator(), 42, .outgoing_unsubscribe, 2);
        state.clearRetainingCapacity();
        try std.testing.expectEqual(@as(?usize, null), state.controlFilterCount(42, .outgoing_unsubscribe));
        try std.testing.expect(!state.containsOutgoing(42));
        break;
    }
    try std.testing.expect(succeeded);
}

test "MQTT packet identifier external sender ownership follows live mutations without copying" {
    var external: State = .{};
    defer external.deinit(std.testing.allocator);
    var state: State = .{};
    defer state.deinit(std.testing.allocator);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, state.setExternalOutgoing(failing.allocator(), external.ownership()));
    try std.testing.expect(state.outgoing == null);
    try state.setExternalOutgoing(std.testing.allocator, external.ownership());
    _ = try external.add(std.testing.allocator, 65_535, .outgoing_qos2);
    try std.testing.expect(state.containsOutgoing(65_535));
    try std.testing.expect(!state.containsOutgoingPublish(65_535));
    try std.testing.expectEqual(@as(usize, 0), state.count(.outgoing_qos2));
    _ = try state.add(std.testing.allocator, 65_535, .incoming_qos2);
    try std.testing.expect(external.remove(65_535, .outgoing_qos2));
    try std.testing.expect(!state.containsOutgoing(65_535));
    try std.testing.expect(state.contains(65_535, .incoming_qos2));
    try state.addControl(std.testing.allocator, 42, .outgoing_subscribe, 1);
    _ = try external.add(std.testing.allocator, 43, .outgoing_qos1);
    state.clearRetainingCapacity();
    try std.testing.expect(!state.containsOutgoing(42));
    try std.testing.expect(!state.containsOutgoing(43));
    try std.testing.expect(external.containsOutgoing(43));
}
