const std = @import("std");

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
    };

    // Keep the two MQTT Packet Identifier spaces physically separate. A
    // connection may have one receive owner and one serialized writer active
    // concurrently; neither direction is allowed to mutate the other's map.
    incoming: DirectionState = .{},
    outgoing: DirectionState = .{},

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.incoming.deinit(allocator);
        self.outgoing.deinit(allocator);
        self.* = .{};
    }

    pub fn contains(self: *const State, packet_id: u16, stage: Stage) bool {
        return self.entriesForConst(stage).contains(
            packet_id,
            code(stage),
        );
    }

    pub fn containsOutgoing(self: *const State, packet_id: u16) bool {
        return self.outgoing.value(packet_id) != 0;
    }

    /// Add one stage, returning false when it was already present.
    pub fn add(
        self: *State,
        allocator: std.mem.Allocator,
        packet_id: u16,
        stage: Stage,
    ) std.mem.Allocator.Error!bool {
        std.debug.assert(packet_id != 0);
        return self.entriesFor(stage).add(
            allocator,
            packet_id,
            code(stage),
        );
    }

    /// Remove one stage and retire an entry once neither direction owns it.
    pub fn remove(self: *State, packet_id: u16, stage: Stage) bool {
        return self.entriesFor(stage).remove(packet_id, code(stage));
    }

    /// Move an existing identifier between QoS stages without allocation.
    pub fn transition(
        self: *State,
        packet_id: u16,
        from: Stage,
        to: Stage,
    ) bool {
        std.debug.assert(direction(from) == direction(to));
        return self.entriesFor(from).transition(
            packet_id,
            code(from),
            code(to),
        );
    }

    pub fn clearRetainingCapacity(self: *State) void {
        self.incoming.clearRetainingCapacity();
        self.outgoing.clearRetainingCapacity();
    }

    pub fn count(self: *const State, stage: Stage) usize {
        return self.entriesForConst(stage).count(code(stage));
    }

    fn entriesFor(self: *State, stage: Stage) *DirectionState {
        return switch (direction(stage)) {
            .incoming => &self.incoming,
            .outgoing => &self.outgoing,
        };
    }

    fn entriesForConst(self: *const State, stage: Stage) *const DirectionState {
        return switch (direction(stage)) {
            .incoming => &self.incoming,
            .outgoing => &self.outgoing,
        };
    }

    const Direction = enum { incoming, outgoing };

    fn direction(stage: Stage) Direction {
        return switch (stage) {
            .incoming_qos1, .incoming_qos2 => .incoming,
            .outgoing_qos1,
            .outgoing_qos2,
            .outgoing_qos2_pubrel,
            => .outgoing,
        };
    }

    fn code(stage: Stage) u2 {
        return switch (stage) {
            .incoming_qos1, .outgoing_qos1 => 1,
            .incoming_qos2, .outgoing_qos2 => 2,
            .outgoing_qos2_pubrel => 3,
        };
    }
};

const DirectionState = struct {
    const packet_identifier_slots =
        @as(usize, std.math.maxInt(u16)) + 1;
    const identifiers_per_byte = 4;
    const Dense = [packet_identifier_slots / identifiers_per_byte]u8;
    const sparse_limit = 1024;
    const Map = std.AutoHashMapUnmanaged(u16, u2);

    sparse: Map = .empty,
    dense: ?*Dense = null,

    fn deinit(self: *DirectionState, allocator: std.mem.Allocator) void {
        self.sparse.deinit(allocator);
        if (self.dense) |dense| allocator.destroy(dense);
        self.* = .{};
    }

    fn value(self: *const DirectionState, packet_id: u16) u2 {
        return if (self.dense) |dense|
            denseValue(dense, packet_id)
        else
            self.sparse.get(packet_id) orelse 0;
    }

    fn contains(
        self: *const DirectionState,
        packet_id: u16,
        expected: u2,
    ) bool {
        return self.value(packet_id) == expected;
    }

    fn add(
        self: *DirectionState,
        allocator: std.mem.Allocator,
        packet_id: u16,
        new_value: u2,
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

    fn remove(
        self: *DirectionState,
        packet_id: u16,
        expected: u2,
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

    fn transition(
        self: *DirectionState,
        packet_id: u16,
        from: u2,
        to: u2,
    ) bool {
        if (!self.contains(packet_id, from)) return false;
        if (self.dense) |dense| {
            setDenseValue(dense, packet_id, to);
        } else {
            self.sparse.getPtr(packet_id).?.* = to;
        }
        return true;
    }

    fn clearRetainingCapacity(self: *DirectionState) void {
        if (self.dense) |dense| {
            @memset(dense, 0);
        } else {
            self.sparse.clearRetainingCapacity();
        }
    }

    fn count(self: *const DirectionState, expected: u2) usize {
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
        self: *DirectionState,
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

    fn denseValue(dense: *const Dense, packet_id: u16) u2 {
        const index = @as(usize, packet_id) / identifiers_per_byte;
        const shift: u3 = @intCast(
            (@as(usize, packet_id) % identifiers_per_byte) * 2,
        );
        return @truncate(dense[index] >> shift);
    }

    fn setDenseValue(dense: *Dense, packet_id: u16, new_value: u2) void {
        const index = @as(usize, packet_id) / identifiers_per_byte;
        const shift: u3 = @intCast(
            (@as(usize, packet_id) % identifiers_per_byte) * 2,
        );
        const clear_mask = ~(@as(u8, 0b11) << shift);
        dense[index] = (dense[index] & clear_mask) |
            (@as(u8, new_value) << shift);
    }
};

test "MQTT packet identifier state is sparse and direction independent" {
    const legacy_bytes = 5 *
        @sizeOf(std.StaticBitSet(@as(usize, std.math.maxInt(u16)) + 1));
    try std.testing.expect(@sizeOf(State) * 100 < legacy_bytes);

    var state: State = .{};
    defer state.deinit(std.testing.allocator);
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
    try std.testing.expectEqual(@as(usize, 0), state.incoming.sparse.count());
    try std.testing.expectEqual(@as(usize, 0), state.outgoing.sparse.count());
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
    try std.testing.expectEqual(@as(usize, 0), state.incoming.sparse.count());
    try std.testing.expectEqual(@as(usize, 0), state.outgoing.sparse.count());
}

test "MQTT packet identifier allocation failure changes no state" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var state: State = .{};
    defer state.deinit(failing.allocator());
    try std.testing.expectError(
        error.OutOfMemory,
        state.add(failing.allocator(), 7, .incoming_qos1),
    );
    try std.testing.expectEqual(@as(usize, 0), state.incoming.sparse.count());
    try std.testing.expectEqual(@as(usize, 0), state.outgoing.sparse.count());
}

test "MQTT packet identifier state promotes to bounded dense storage" {
    var state: State = .{};
    defer state.deinit(std.testing.allocator);

    for (1..DirectionState.sparse_limit + 2) |packet_id| {
        try std.testing.expect(try state.add(
            std.testing.allocator,
            @intCast(packet_id),
            .incoming_qos1,
        ));
    }
    try std.testing.expect(state.incoming.dense != null);
    try std.testing.expectEqual(
        @as(usize, DirectionState.sparse_limit + 1),
        state.count(.incoming_qos1),
    );
    try std.testing.expect(state.remove(1, .incoming_qos1));
    try std.testing.expect(!state.contains(1, .incoming_qos1));
    try std.testing.expect(state.contains(
        @intCast(DirectionState.sparse_limit + 1),
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

    for (1..DirectionState.sparse_limit + 1) |packet_id| {
        try std.testing.expect(try state.add(
            failing.allocator(),
            @intCast(packet_id),
            .outgoing_qos1,
        ));
    }
    try std.testing.expect(state.outgoing.dense == null);
    const allocations = failing.allocations;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        state.add(
            failing.allocator(),
            @intCast(DirectionState.sparse_limit + 1),
            .outgoing_qos1,
        ),
    );
    try std.testing.expectEqual(allocations, failing.allocations);
    try std.testing.expect(state.outgoing.dense == null);
    try std.testing.expectEqual(
        @as(usize, DirectionState.sparse_limit),
        state.count(.outgoing_qos1),
    );
    try std.testing.expect(!state.contains(
        @intCast(DirectionState.sparse_limit + 1),
        .outgoing_qos1,
    ));
}
