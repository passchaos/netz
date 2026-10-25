const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const Pair = @import("../runtime/acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT reconnect automatic PUBLISH replies share the poll deadline and retain delivery" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| {
            for ([_]bool{ false, true }) |absolute| {
                for ([_]bool{ false, true }) |visible| try publicationReply(protocol, qos, absolute, visible);
            }
        }
    }
}

fn publicationReply(protocol: mqtt.ProtocolVersion, qos: mqtt.QoS, absolute: bool, visible: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var blocked = BlockedWrite{ .delegate = io, .packet_type = if (qos == .at_least_once) .puback else .pubrec, .write_before_delay = visible };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{
        .protocol = protocol,
        .client_id = "automatic-reply-budget",
        .clean_start = false,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} else &.{},
    }, .{}, &shutdown);
    defer client.deinit();
    const pair = try Pair.init(observed_io, protocol);
    client.connection_state = pair.client;
    client.connection().?.session_expiry_interval = if (protocol == .v5) 60 else std.math.maxInt(u32);
    var peer = pair.peer;
    defer peer.close();
    const id = (try peer.writePublish("automatic/reply", "kept after timeout", .{ .qos = qos })).?;
    blocked.armed.store(true, .release);
    const result = if (absolute)
        try client.pollWithDeadline(std.Io.Clock.awake.now(io).addDuration(.fromMilliseconds(50)), .{ .reconnect_after_transport_error = false })
    else
        try client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false });
    if (result) |value| {
        var event = value;
        event.deinit(allocator);
        return error.AutomaticReplyEscapedDeadline;
    }
    try std.testing.expect(blocked.entered.load(.acquire));
    try std.testing.expect(blocked.canceled.load(.acquire));
    try std.testing.expect(client.connection() == null);
    var snapshot: std.ArrayList(u8) = .empty;
    defer snapshot.deinit(allocator);
    try snapshot.appendSlice(allocator, "prefix");
    try std.testing.expectError(error.SnapshotBusy, client.writeSessionSnapshot(&snapshot));
    try std.testing.expectError(error.SnapshotBusy, client.restoreSessionSnapshot("unread snapshot"));
    try std.testing.expectEqualStrings("prefix", snapshot.items);
    try std.testing.expectError(error.Timeout, client.pollWithTimeout(.zero));
    var delivered = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer delivered.deinit(allocator);
    try std.testing.expect(delivered == .publish);
    try std.testing.expectEqualStrings("automatic/reply", delivered.publish.publish.topic);
    try std.testing.expectEqualStrings("kept after timeout", delivered.publish.publish.payload);
    try std.testing.expectEqual(id, delivered.publish.publish.packet_id.?);
    try std.testing.expectEqual(qos == .exactly_once, try client.outgoing.containsIncomingQoS2(client.outgoing_handle, id));
    try client.writeSessionSnapshot(&snapshot);
}

test "MQTT reconnect interrupted PUBREC preserves alias-only delivery before resumed protocol work" {
    for ([_]bool{ false, true }) |visible| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var blocked = BlockedWrite{ .delegate = io, .packet_type = .pubrec, .write_before_delay = visible, .failure = error.ConnectionResetByPeer };
        BlockedWrite.active = &blocked;
        defer BlockedWrite.active = null;
        var vtable = io.vtable.*;
        vtable.netWrite = BlockedWrite.netWrite;
        const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
        var shutdown: std.Io.Event = .unset;
        var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{
            .protocol = .v5,
            .client_id = "ambiguous-pubrec",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
        }, .{}, &shutdown);
        defer client.deinit();
        const pair = try Pair.init(observed_io, .v5);
        client.connection_state = pair.client;
        client.connection().?.session_expiry_interval = 60;
        var peer = pair.peer;
        defer peer.close();
        peer.peer_topic_alias_maximum = 16;
        const alias_properties = [_]mqtt.Property{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }};
        _ = try peer.writePublish("kept/alias", "seed", .{ .properties = &alias_properties });
        var seed = (try client.pollWithTimeout(.fromSeconds(1))).?;
        seed.deinit(allocator);
        const id = (try peer.writePublish("", "original message", .{ .qos = .exactly_once, .properties = &alias_properties })).?;
        blocked.armed.store(true, .release);
        try std.testing.expectError(error.ConnectionResetByPeer, client.pollWithTimeout(.fromSeconds(1)));
        try std.testing.expect(client.connection() == null);
        if (visible) {
            var ack = try peer.readPubRec();
            defer ack.deinit(allocator);
            try std.testing.expectEqual(id, ack.ack.packet_id);
        }
        blocked.armed.store(false, .release);
        const replacement = try Pair.init(io, .v5);
        client.connection_state = replacement.client;
        client.connection().?.session_expiry_interval = 60;
        var resumed_peer = replacement.peer;
        defer resumed_peer.close();
        if (visible) {
            try resumed_peer.writePubRel(id, 0);
        } else {
            resumed_peer.next_packet_id = id;
            _ = try resumed_peer.writePublish("kept/alias", "original message", .{ .qos = .exactly_once, .dup = true });
            _ = try resumed_peer.writePublish("following", "ordered", .{});
        }
        var original = (try client.pollWithTimeout(.fromSeconds(1))).?;
        defer original.deinit(allocator);
        try std.testing.expect(original == .publish);
        try std.testing.expectEqualStrings("kept/alias", original.publish.publish.topic);
        try std.testing.expectEqualStrings("original message", original.publish.publish.payload);
        try std.testing.expectEqual(@as(u16, 1), mqtt.topicAlias(original.publish.publish.properties).?);
        var next = (try client.pollWithTimeout(.fromSeconds(1))).?;
        defer next.deinit(allocator);
        if (!visible) {
            try std.testing.expect(next == .publish);
            try std.testing.expectEqualStrings("following", next.publish.publish.topic);
            var ack = try resumed_peer.readPubRec();
            defer ack.deinit(allocator);
            try std.testing.expectEqual(id, ack.ack.packet_id);
            try resumed_peer.writePubRel(id, 0);
            var release = (try client.pollWithTimeout(.fromSeconds(1))).?;
            defer release.deinit(allocator);
            try std.testing.expect(release == .pubrel);
        } else {
            try std.testing.expect(next == .pubrel);
        }
        var complete = try resumed_peer.readPubComp();
        defer complete.deinit(allocator);
        try std.testing.expectEqual(id, complete.ack.packet_id);
        try std.testing.expect(!try client.outgoing.containsIncomingQoS2(client.outgoing_handle, id));
    }
}
