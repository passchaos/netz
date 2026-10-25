const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const Pair = @import("../runtime/acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT reconnect automatic PUBREL and PUBCOMP share poll deadlines and preserve QoS2 phases" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]mqtt.PacketType{ .pubrel, .pubcomp }) |packet_type| {
            for ([_]bool{ false, true }) |absolute| try controlReply(protocol, packet_type, absolute);
        }
    }
}

fn controlReply(protocol: mqtt.ProtocolVersion, packet_type: mqtt.PacketType, absolute: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var blocked = BlockedWrite{ .delegate = io, .packet_type = packet_type };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    const options = @import("../runtime.zig").ConnectOptions{
        .protocol = protocol,
        .client_id = "automatic-control-budget",
        .clean_start = false,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} else &.{},
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, options, .{}, &shutdown);
    defer client.deinit();
    const pair = try Pair.init(observed_io, protocol);
    client.connection_state = pair.client;
    client.connection().?.session_expiry_interval = if (protocol == .v5) 60 else std.math.maxInt(u32);
    var peer = pair.peer;
    defer peer.close();
    const id = if (packet_type == .pubrel) blk: {
        const attempt = try client.publishOneAttempt("control/outgoing", "owned", .{ .qos = .exactly_once });
        var publish = try peer.readPublish();
        publish.deinit(allocator);
        try peer.writePubRec(attempt.packet_id.?, 0);
        break :blk attempt.packet_id.?;
    } else blk: {
        const id = (try peer.writePublish("control/incoming", "owned", .{ .qos = .exactly_once })).?;
        var delivered = (try client.pollWithTimeout(.fromSeconds(1))).?;
        delivered.deinit(allocator);
        var ack = try peer.readPubRec();
        ack.deinit(allocator);
        try peer.writePubRel(id, 0);
        break :blk id;
    };
    blocked.armed.store(true, .release);
    const result = if (absolute)
        try client.pollWithDeadline(std.Io.Clock.awake.now(io).addDuration(.fromMilliseconds(50)), .{ .reconnect_after_transport_error = false })
    else
        try client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false });
    if (result) |value| {
        var event = value;
        event.deinit(allocator);
        return error.AutomaticControlEscapedDeadline;
    }
    try std.testing.expect(blocked.entered.load(.acquire));
    try std.testing.expect(blocked.canceled.load(.acquire));
    try std.testing.expect(client.connection() == null);
    var snapshot: std.ArrayList(u8) = .empty;
    defer snapshot.deinit(allocator);
    try client.writeSessionSnapshot(&snapshot);
    var restored = try reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(1) }, options, .{}, &shutdown);
    defer restored.deinit();
    try restored.restoreSessionSnapshot(snapshot.items);
    if (packet_type == .pubrel) {
        try std.testing.expectEqual(.await_pubcomp, (try client.outgoing.outgoingQoSState(client.outgoing_handle, id)).?);
        try std.testing.expectEqual(.await_pubcomp, (try restored.outgoing.outgoingQoSState(restored.outgoing_handle, id)).?);
    } else {
        try std.testing.expect(!try client.outgoing.containsIncomingQoS2(client.outgoing_handle, id));
        try std.testing.expect(!try restored.outgoing.containsIncomingQoS2(restored.outgoing_handle, id));
        const replacement = try Pair.init(io, protocol);
        client.connection_state = replacement.client;
        var resumed_peer = replacement.peer;
        defer resumed_peer.close();
        try resumed_peer.writePubRel(id, 0);
        var release = (try client.pollWithTimeout(.fromSeconds(1))).?;
        defer release.deinit(allocator);
        try std.testing.expect(release == .pubrel);
        var complete = try resumed_peer.readPubComp();
        defer complete.deinit(allocator);
        try std.testing.expectEqual(id, complete.ack.packet_id);
        try std.testing.expect(!try client.outgoing.containsIncomingQoS2(client.outgoing_handle, id));
    }
}

test "MQTT reconnect completed PUBREL permits new identifier reuse after an ambiguous PUBCOMP" {
    for ([_]mqtt.QoS{ .at_least_once, .exactly_once }) |qos| {
        for ([_]bool{ false, true }) |dup| try identifierReuse(qos, dup);
    }
}

fn identifierReuse(qos: mqtt.QoS, dup: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var blocked = BlockedWrite{ .delegate = io, .packet_type = .pubcomp, .write_before_delay = true, .failure = error.ConnectionResetByPeer };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{
        .protocol = .v5,
        .client_id = "ambiguous-pubcomp-id",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, &shutdown);
    defer client.deinit();
    const pair = try Pair.init(observed_io, .v5);
    client.connection_state = pair.client;
    client.connection().?.session_expiry_interval = 60;
    var peer = pair.peer;
    defer peer.close();
    const id = (try peer.writePublish("previous", "old exchange", .{ .qos = .exactly_once })).?;
    var original = (try client.pollWithTimeout(.fromSeconds(1))).?;
    original.deinit(allocator);
    var received = try peer.readPubRec();
    received.deinit(allocator);
    try peer.writePubRel(id, 0);
    blocked.armed.store(true, .release);
    try std.testing.expectError(error.ConnectionResetByPeer, client.pollWithTimeout(.fromSeconds(1)));
    try std.testing.expect(!try client.outgoing.containsIncomingQoS2(client.outgoing_handle, id));
    var complete = try peer.readPubComp();
    complete.deinit(allocator);
    blocked.armed.store(false, .release);
    const replacement = try Pair.init(io, .v5);
    client.connection_state = replacement.client;
    var resumed_peer = replacement.peer;
    defer resumed_peer.close();
    resumed_peer.next_packet_id = id;
    _ = try resumed_peer.writePublish("reused/id", "new exchange", .{ .qos = qos, .dup = dup });
    var next = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer next.deinit(allocator);
    try std.testing.expect(next == .publish);
    try std.testing.expectEqual(id, next.publish.publish.packet_id.?);
    try std.testing.expectEqualStrings("new exchange", next.publish.publish.payload);
    try std.testing.expectEqual(qos == .exactly_once, try client.outgoing.containsIncomingQoS2(client.outgoing_handle, id));
}

test "MQTT reconnect automatic duplicate PUBREC is bounded without another application delivery" {
    for ([_]bool{ false, true }) |manual| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var blocked = BlockedWrite{ .delegate = io, .packet_type = .pubrec };
        BlockedWrite.active = &blocked;
        defer BlockedWrite.active = null;
        var vtable = io.vtable.*;
        vtable.netWrite = BlockedWrite.netWrite;
        const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
        var shutdown: std.Io.Event = .unset;
        var client = try reconnect.Client.initWithOptions(allocator, observed_io, .{ .ip4 = .loopback(1) }, .{
            .protocol = .v5,
            .client_id = "duplicate-reply-budget",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
        }, .{}, &shutdown, .{ .manual_acknowledgements = manual });
        defer client.deinit();
        // This marker represents an Application Message already delivered and
        // acknowledged on the old Network Connection.
        _ = try client.outgoing.recordIncomingQoS2(client.outgoing_handle, 17);
        const pair = try Pair.init(observed_io, .v5);
        client.connection_state = pair.client;
        client.connection().?.session_expiry_interval = 60;
        var peer = pair.peer;
        defer peer.close();
        peer.next_packet_id = 17;
        _ = try peer.writePublish("duplicate", "already delivered", .{ .qos = .exactly_once, .dup = true });
        blocked.armed.store(true, .release);
        try std.testing.expect((try client.pollWithTimeout(.fromMilliseconds(50))) == null);
        try std.testing.expect(blocked.canceled.load(.acquire));
        try std.testing.expect(client.pending_publish == null);
        try std.testing.expect(try client.outgoing.containsIncomingQoS2(client.outgoing_handle, 17));
    }
}
