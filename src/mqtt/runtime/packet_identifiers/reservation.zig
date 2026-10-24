//! One sender identifier space for QoS PUBLISH and subscription commands.
const std = @import("std");
const State = @import("../packet_identifiers.zig").State;

pub fn Controller(comptime Context: type) type {
    return struct {
        pub fn reserve(connection: *Context.ConnectionType, stage: State.Stage, filter_count: ?usize) Context.ErrorType!u16 {
            const initial = connection.next_packet_id;
            errdefer connection.next_packet_id = initial;
            for (0..std.math.maxInt(u16)) |_| {
                const id = connection.next_packet_id;
                connection.next_packet_id +%= 1;
                if (connection.next_packet_id == 0) connection.next_packet_id = 1;
                if (connection.packet_identifiers.containsOutgoing(id)) continue;
                if (filter_count) |count| {
                    try connection.packet_identifiers.addControl(connection.allocator, id, stage, count);
                } else {
                    _ = try connection.packet_identifiers.add(connection.allocator, id, stage);
                }
                return id;
            }
            return error.InflightFull;
        }
    };
}

test "MQTT packet identifier reservation exhausts the shared sender space transactionally" {
    const Connection = struct {
        allocator: std.mem.Allocator = std.testing.allocator,
        next_packet_id: u16 = 65_535,
        packet_identifiers: State = .{},
    };
    const Reservations = Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = error{ OutOfMemory, InflightFull };
    });
    var connection: Connection = .{};
    defer connection.packet_identifiers.deinit(connection.allocator);
    const stages = [_]State.Stage{ .outgoing_qos1, .outgoing_qos2, .outgoing_qos2_pubrel, .outgoing_subscribe, .outgoing_unsubscribe };
    for (1..@as(usize, std.math.maxInt(u16)) + 1) |id| {
        _ = try connection.packet_identifiers.add(connection.allocator, @intCast(id), stages[id % stages.len]);
    }
    for (1..@as(usize, std.math.maxInt(u16)) + 1) |id| {
        try std.testing.expect(connection.packet_identifiers.contains(@intCast(id), stages[id % stages.len]));
    }
    try std.testing.expectError(error.InflightFull, Reservations.reserve(&connection, .outgoing_subscribe, 2));
    try std.testing.expectEqual(@as(u16, 65_535), connection.next_packet_id);
    try std.testing.expect(connection.packet_identifiers.remove(connection.allocator, 65_534, stages[65_534 % stages.len]));
    _ = try connection.packet_identifiers.add(connection.allocator, 65_534, .incoming_qos2);
    try std.testing.expectEqual(@as(u16, 65_534), try Reservations.reserve(&connection, .outgoing_subscribe, 2));
    try std.testing.expectEqual(@as(?usize, 2), connection.packet_identifiers.controlFilterCount(65_534, .outgoing_subscribe));
    try std.testing.expect(connection.packet_identifiers.contains(65_534, .incoming_qos2));
}
