const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Pair = @import("../acknowledgement/test_connection.zig").Pair;
const allocator = std.testing.allocator;
const Mode = enum { typed, client, broker, caller };
const alias_properties = [_]mqtt.Property{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }};

fn read(connection: *runtime.Connection, mode: Mode, storage: []u8) !runtime.OwnedPublish {
    if (mode == .typed) return connection.readPublish();
    if (mode == .client) {
        var event = try connection.readClientPacketEventWithTimeout(.fromSeconds(1));
        if (event == .publish) return event.publish;
        event.deinit(allocator);
        return error.ExpectedPublish;
    }
    var event = if (mode == .caller) try connection.readBrokerEventInto(storage) else try connection.readBrokerEventWithTimeout(.fromSeconds(1));
    if (event == .publish) return event.publish;
    event.deinit(allocator);
    return error.ExpectedPublish;
}

fn send(connection: *runtime.Connection, topic: []const u8, payload: []const u8, qos: mqtt.QoS) !void {
    _ = try connection.writePublish(topic, payload, .{ .qos = qos, .properties = &alias_properties });
}

test "MQTT owned alias-only publications survive alias replacement and connection close" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Mode)) |mode| {
        var pair = try Pair.init(io, .v5);
        var open = true;
        defer if (open) pair.client.close();
        defer pair.peer.close();
        pair.peer.peer_topic_alias_maximum = 16;
        if (mode == .broker or mode == .caller) pair.client.endpoint_role = .server;
        var seed_storage: [448]u8 = undefined;
        try send(&pair.peer, "first/topic", "seed", .at_most_once);
        var seed = try read(&pair.client, mode, &seed_storage);
        seed.deinit(allocator);
        var old_storage: [448]u8 = undefined;
        try send(&pair.peer, "", "retained", .at_most_once);
        var old = try read(&pair.client, mode, &old_storage);
        defer old.deinit(allocator);
        if (old.publish.topic.ptr == pair.client.incoming_topic_aliases.?.get(1).?.ptr) {
            std.debug.print("{s} OwnedPublish borrows connection Topic Alias storage\n", .{@tagName(mode)});
            return error.OwnedTopicAliasesConnection;
        }
        var replacement_storage: [448]u8 = undefined;
        try send(&pair.peer, "other/topic", "replacement", .at_most_once);
        var replacement = try read(&pair.client, mode, &replacement_storage);
        defer replacement.deinit(allocator);
        try std.testing.expectEqualStrings("first/topic", old.publish.topic);
        try std.testing.expectEqualStrings("retained", old.publish.payload);
        pair.client.close();
        open = false;
        try std.testing.expectEqualStrings("first/topic", old.publish.topic);
        try std.testing.expectEqualStrings("other/topic", replacement.publish.topic);
    }
}

test "MQTT alias-only receive OOM keeps packet order alias table and QoS credit" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Mode)) |mode| {
        for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| {
            var finished = false;
            var failures: usize = 0;
            for (0..16) |fail_index| {
                var pair = try Pair.init(io, .v5);
                defer pair.deinit();
                pair.peer.peer_topic_alias_maximum = 16;
                if (mode == .broker or mode == .caller) pair.client.endpoint_role = .server;
                var storage: [448]u8 = undefined;
                try send(&pair.peer, "first/topic", "seed", .at_most_once);
                var seed = try read(&pair.client, mode, &storage);
                seed.deinit(allocator);
                try send(&pair.peer, "", "first", qos);
                _ = try pair.peer.writePublish("later/topic", "second", .{});
                var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
                pair.client.allocator = failing.allocator();
                const result = read(&pair.client, mode, &storage);
                pair.client.allocator = allocator;
                if (result) |value| {
                    var first = value;
                    defer first.deinit(allocator);
                    try std.testing.expect(!failing.has_induced_failure);
                    try std.testing.expectEqualStrings("first", first.publish.payload);
                    finished = true;
                } else |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    try std.testing.expect(failing.has_induced_failure);
                    failures += 1;
                    try std.testing.expect(pair.client.isUsable());
                    try std.testing.expectEqual(@as(u16, 0), pair.client.incoming_inflight);
                    try std.testing.expectEqualStrings("first/topic", pair.client.incoming_topic_aliases.?.get(1).?);
                    // Caller-owned storage can be reused immediately after OOM.
                    @memset(&storage, 0xaa);
                    var first = try read(&pair.client, mode, &storage);
                    defer first.deinit(allocator);
                    try std.testing.expectEqualStrings("first/topic", first.publish.topic);
                    try std.testing.expectEqualStrings("first", first.publish.payload);
                    try std.testing.expect(first.publish.packet_id != null);
                }
                try std.testing.expectEqual(@as(u16, 1), pair.client.incoming_inflight);
                var later_storage: [448]u8 = undefined;
                var later = try read(&pair.client, mode, &later_storage);
                defer later.deinit(allocator);
                try std.testing.expectEqualStrings("second", later.publish.payload);
                if (finished) break;
            }
            try std.testing.expect(finished and failures != 0);
        }
    }
}
