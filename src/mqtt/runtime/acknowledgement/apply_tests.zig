const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;
const Connection = runtime.Connection;
const net = std.Io.net;
const PacketTransport = @import("../packet_transport.zig").Transport;
const Stage = @import("../packet_identifiers.zig").State.Stage;

fn apply(connection: *Connection, ack: mqtt.AckPacket) runtime.Error!void {
    return switch (ack.packet_type) {
        .puback => connection.applyPubAck(ack),
        .pubrec => connection.applyPubRec(ack),
        .pubcomp => connection.applyPubComp(ack),
        else => error.UnexpectedPacket,
    };
}

const Phase = struct { packet_type: mqtt.PacketType, stage: Stage };
const phases = [_]Phase{
    .{ .packet_type = .puback, .stage = .outgoing_qos1 },
    .{ .packet_type = .pubrec, .stage = .outgoing_qos2 },
    .{ .packet_type = .pubrec, .stage = .outgoing_qos2_pubrel },
    .{ .packet_type = .pubcomp, .stage = .outgoing_qos2_pubrel },
};

fn finishAfterInvalid(pair: *@import("test_connection.zig").Pair, phase: Phase, protocol: mqtt.ProtocolVersion) !void {
    const connection = &pair.client;
    try apply(connection, .{ .packet_type = phase.packet_type, .packet_id = 41 });
    if (phase.packet_type == .pubrec) {
        var packet = try pair.peer.transport.readPacketWithDeadline(allocator, 16, pair.peer.transport.deadlineFromNow(.fromSeconds(1)));
        defer packet.deinit(allocator);
        var pubrel = try mqtt.AckPacket.parse(allocator, protocol, packet.bytes);
        defer pubrel.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 41), pubrel.packet_id);
        try std.testing.expectEqual(protocol == .v3_1 and phase.stage == .outgoing_qos2_pubrel, pubrel.dup);
        try connection.applyPubComp(.{ .packet_type = .pubcomp, .packet_id = 41 });
    }
    try std.testing.expectEqual(@as(u16, 1), connection.outgoing_inflight);
    try std.testing.expect(!connection.hasOutgoingPacketIdentifier(41));
    try std.testing.expect(connection.packet_identifiers.contains(42, .outgoing_qos1));
}

test "MQTT acknowledgement apply exhaustively preserves invalid reason state across versions" {
    const Pair = @import("test_connection.zig").Pair;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (phases) |phase| {
            var pair = try Pair.init(threaded.io(), protocol);
            defer pair.deinit();
            const connection = &pair.client;
            connection.outgoing_inflight = 2;
            _ = try connection.packet_identifiers.add(allocator, 41, phase.stage);
            _ = try connection.packet_identifiers.add(allocator, 42, .outgoing_qos1);
            _ = try connection.packet_identifiers.add(allocator, 41, .incoming_qos2);
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
            connection.allocator = failing.allocator();
            for (0..256) |value| {
                const reason: u8 = @intCast(value);
                const allowed = if (protocol.isLegacy()) reason == 0 else if (phase.packet_type == .pubcomp)
                    reason == 0 or reason == 0x92
                else
                    std.mem.indexOfScalar(u8, &.{ 0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99 }, reason) != null;
                if (allowed) continue;
                try std.testing.expectError(error.InvalidReasonCode, apply(connection, .{ .packet_type = phase.packet_type, .packet_id = 41, .reason_code = reason }));
                try std.testing.expectEqual(@as(u16, 2), connection.outgoing_inflight);
                try std.testing.expect(connection.packet_identifiers.contains(41, phase.stage));
                try std.testing.expect(connection.packet_identifiers.contains(42, .outgoing_qos1));
                try std.testing.expect(connection.packet_identifiers.contains(41, .incoming_qos2));
            }
            connection.allocator = allocator;
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expect(connection.isUsable());
            try std.testing.expectEqual(@as(u64, 0), connection.traffic.stats().messages_sent);
            try std.testing.expectError(error.Timeout, pair.peer.transport.readPacketWithDeadline(allocator, 16, pair.peer.transport.deadlineFromNow(.fromMilliseconds(1))));
            try finishAfterInvalid(&pair, phase, protocol);
            try std.testing.expect(connection.packet_identifiers.contains(41, .incoming_qos2));
        }
    }
}

test "MQTT acknowledgement apply rejects properties and DUP before state or wire progress" {
    const Pair = @import("test_connection.zig").Pair;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (phases) |phase| {
            var pair = try Pair.init(threaded.io(), protocol);
            defer pair.deinit();
            const connection = &pair.client;
            connection.outgoing_inflight = 2;
            _ = try connection.packet_identifiers.add(allocator, 41, phase.stage);
            _ = try connection.packet_identifiers.add(allocator, 42, .outgoing_qos1);
            var properties = [_]mqtt.Property{.{ .two_byte = .{ .id = .receive_maximum, .value = 12 } }};
            try std.testing.expectError(error.InvalidProperty, apply(connection, .{ .packet_type = phase.packet_type, .packet_id = 41, .properties = &properties }));
            try std.testing.expectError(error.InvalidFlags, apply(connection, .{ .packet_type = phase.packet_type, .packet_id = 41, .dup = true }));
            try std.testing.expectEqual(@as(u16, 2), connection.outgoing_inflight);
            try std.testing.expect(connection.packet_identifiers.contains(41, phase.stage));
            try std.testing.expect(connection.packet_identifiers.contains(42, .outgoing_qos1));
            try std.testing.expectEqual(@as(u16, 12), properties[0].two_byte.value);
            try std.testing.expectEqual(@as(u64, 0), connection.traffic.stats().messages_sent);
            try std.testing.expectError(error.Timeout, pair.peer.transport.readPacketWithDeadline(allocator, 16, pair.peer.transport.deadlineFromNow(.fromMilliseconds(1))));
            try finishAfterInvalid(&pair, phase, protocol);
        }
    }
}

test "MQTT acknowledgement apply legal reasons preserve QoS outcomes and exact PUBREL" {
    const Pair = @import("test_connection.zig").Pair;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (phases) |phase| {
            const reasons: []const u8 = if (protocol.isLegacy()) &.{0} else if (phase.packet_type == .pubcomp) &.{ 0, 0x92 } else &.{ 0x00, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99 };
            for (reasons) |reason| {
                var pair = try Pair.init(threaded.io(), protocol);
                defer pair.deinit();
                const connection = &pair.client;
                connection.outgoing_inflight = 2;
                _ = try connection.packet_identifiers.add(allocator, 41, phase.stage);
                _ = try connection.packet_identifiers.add(allocator, 42, .outgoing_qos1);
                var properties = [_]mqtt.Property{.{ .utf8 = .{ .id = .reason_string, .value = "reason" } }};
                const ack = mqtt.AckPacket{ .packet_type = phase.packet_type, .packet_id = 41, .reason_code = reason, .properties = if (protocol == .v5) &properties else &.{} };
                const repeated = phase.packet_type == .pubrec and phase.stage == .outgoing_qos2_pubrel;
                if (phase.packet_type == .pubrec and reason < 0x80) {
                    try apply(connection, ack);
                    try std.testing.expectEqual(@as(u16, 2), connection.outgoing_inflight);
                    try std.testing.expect(connection.packet_identifiers.contains(41, .outgoing_qos2_pubrel));
                    var packet = try pair.peer.transport.readPacketWithDeadline(allocator, 16, pair.peer.transport.deadlineFromNow(.fromSeconds(1)));
                    defer packet.deinit(allocator);
                    var pubrel = try mqtt.AckPacket.parse(allocator, protocol, packet.bytes);
                    defer pubrel.deinit(allocator);
                    try std.testing.expectEqual(mqtt.PacketType.pubrel, pubrel.packet_type);
                    try std.testing.expectEqual(@as(u16, 41), pubrel.packet_id);
                    try std.testing.expectEqual(protocol == .v3_1 and repeated, pubrel.dup);
                } else if (repeated) {
                    try std.testing.expectError(error.UnexpectedPacket, apply(connection, ack));
                    try std.testing.expectEqual(@as(u16, 2), connection.outgoing_inflight);
                    try std.testing.expect(connection.packet_identifiers.contains(41, .outgoing_qos2_pubrel));
                } else {
                    if (reason < 0x80) try apply(connection, ack) else try std.testing.expectError(error.PublishRefused, apply(connection, ack));
                    try std.testing.expectEqual(@as(u16, 1), connection.outgoing_inflight);
                    try std.testing.expect(!connection.hasOutgoingPacketIdentifier(41));
                }
                try std.testing.expect(connection.packet_identifiers.contains(42, .outgoing_qos1));
                try std.testing.expectEqualStrings("reason", properties[0].utf8.value);
            }
        }
    }
}

test "MQTT acknowledgement apply validates reason before releasing outgoing state" {
    for ([_]mqtt.PacketType{ .puback, .pubrec, .pubcomp }) |packet_type| {
        var connection = runtime.Connection{ .allocator = allocator, .transport = undefined, .protocol = .v5, .outgoing_inflight = 2 };
        defer connection.packet_identifiers.deinit(allocator);
        const stage: @import("../packet_identifiers.zig").State.Stage = if (packet_type == .puback) .outgoing_qos1 else if (packet_type == .pubrec) .outgoing_qos2 else .outgoing_qos2_pubrel;
        _ = try connection.packet_identifiers.add(allocator, 41, stage);
        _ = try connection.packet_identifiers.add(allocator, 42, .outgoing_qos1);
        const ack = mqtt.AckPacket{ .packet_type = packet_type, .packet_id = 41, .reason_code = 0x95 };
        const result = switch (packet_type) {
            .puback => connection.applyPubAck(ack),
            .pubrec => connection.applyPubRec(ack),
            .pubcomp => connection.applyPubComp(ack),
            else => unreachable,
        };
        try std.testing.expectError(error.InvalidReasonCode, result);
        try std.testing.expectEqual(@as(u16, 2), connection.outgoing_inflight);
        try std.testing.expect(connection.packet_identifiers.contains(41, stage));
        try std.testing.expect(connection.packet_identifiers.contains(42, .outgoing_qos1));
    }
}

test "MQTT acknowledgement apply invalid successful PUBREC cannot emit PUBREL" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .allocator = allocator, .transport = .initTcp(io, sender), .protocol = .v5, .outgoing_inflight = 1 };
    defer connection.packet_identifiers.deinit(allocator);
    _ = try connection.packet_identifiers.add(allocator, 41, .outgoing_qos2);
    try std.testing.expectError(error.InvalidReasonCode, connection.applyPubRec(.{ .packet_type = .pubrec, .packet_id = 41, .reason_code = 0x11 }));
    try std.testing.expect(connection.packet_identifiers.contains(41, .outgoing_qos2));
    try std.testing.expect(!connection.packet_identifiers.contains(41, .outgoing_qos2_pubrel));
    var transport = @import("../packet_transport.zig").Transport.initTcp(io, peer);
    try std.testing.expectError(error.Timeout, transport.readPacketWithDeadline(allocator, 16, transport.deadlineFromNow(.fromMilliseconds(5))));
}

test "MQTT acknowledgement apply preserves wrong-stage inflight state" {
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .outgoing_inflight = 2,
    };
    defer connection.packet_identifiers.deinit(allocator);
    try std.testing.expect(try connection.packet_identifiers.add(
        allocator,
        41,
        .outgoing_qos1,
    ));
    try std.testing.expect(try connection.packet_identifiers.add(
        allocator,
        42,
        .outgoing_qos2,
    ));

    try std.testing.expectError(
        error.UnexpectedPacket,
        connection.applyPubAck(.{
            .packet_type = .puback,
            .packet_id = 42,
        }),
    );
    try std.testing.expectError(
        error.UnexpectedPacket,
        connection.applyPubRec(.{
            .packet_type = .pubrec,
            .packet_id = 41,
        }),
    );
    try std.testing.expectError(
        error.UnexpectedPacket,
        connection.applyPubComp(.{
            .packet_type = .pubcomp,
            .packet_id = 42,
        }),
    );
    try std.testing.expectEqual(@as(u16, 2), connection.outgoing_inflight);
    try std.testing.expect(connection.packet_identifiers.contains(
        41,
        .outgoing_qos1,
    ));
    try std.testing.expect(connection.packet_identifiers.contains(
        42,
        .outgoing_qos2,
    ));
}

test "MQTT duplicate successful PUBREC retransmits PUBREL" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .outgoing_inflight = 1,
    };
    defer connection.packet_identifiers.deinit(allocator);
    try std.testing.expect(try connection.packet_identifiers.add(
        allocator,
        42,
        .outgoing_qos2_pubrel,
    ));

    try connection.applyPubRec(.{
        .packet_type = .pubrec,
        .packet_id = 42,
    });
    var peer = PacketTransport.initTcp(io, server_stream);
    var repeated = try peer.readPacket(allocator, 16);
    defer repeated.deinit(allocator);
    var pubrel = try mqtt.AckPacket.parse(allocator, .v5, repeated.bytes);
    defer pubrel.deinit(allocator);
    try std.testing.expectEqual(mqtt.PacketType.pubrel, pubrel.packet_type);
    try std.testing.expectEqual(@as(u16, 42), pubrel.packet_id);
    try std.testing.expectEqual(@as(u16, 1), connection.outgoing_inflight);
    try std.testing.expect(connection.packet_identifiers.contains(
        42,
        .outgoing_qos2_pubrel,
    ));
}
