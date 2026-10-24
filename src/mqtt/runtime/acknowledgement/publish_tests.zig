const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");

const allocator = std.testing.allocator;
const Pending = @import("pending.zig").State;

fn borrowed(bytes: []const u8) runtime.OwnedPacket {
    return .{ .bytes = @constCast(bytes), .fixed = mqtt.FixedHeader.parse(bytes) catch unreachable, .owns_bytes = false };
}

test "MQTT publish completion keeps queued ACK on decode allocation failure" {
    var client = runtime.Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .outgoing_inflight = 1,
        .limits = .{ .max_pending_ping_packets = 2 },
    };
    defer client.packet_identifiers.deinit(allocator);
    try std.testing.expect(try client.packet_identifiers.add(allocator, 42, .outgoing_qos1));
    const pending = try allocator.create(Pending);
    defer allocator.destroy(pending);
    pending.* = .{};
    defer pending.deinit(allocator);
    client.pending_packets = pending;
    const first = "\x30\x05\x00\x01x\x001";
    const second = "\x30\x05\x00\x01x\x002";
    // Independently encoded PUBACK 42 with a Reason String property, whose
    // decoder must allocate even though its packet is already in the queue.
    const ack = "\x40\x0a\x00\x2a\x00\x06\x1f\x00\x03yes";
    try pending.append(allocator, borrowed(first), 3, 100);
    try pending.append(allocator, borrowed(ack), 3, 100);
    pending.retainOverflow(borrowed(second));
    const before_bytes = pending.queued_bytes;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    client.allocator = failing.allocator();
    defer client.allocator = allocator;
    try std.testing.expectError(error.OutOfMemory, client.completePublishPubAck(42));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 3), pending.count());
    try std.testing.expectEqual(before_bytes, pending.queued_bytes);
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try std.testing.expect(client.hasOutgoingPacketIdentifier(42));

    client.allocator = allocator;
    // Even a full ordinary queue plus emergency slot must allow a matching
    // ACK to complete without further transport reads or queue allocations.
    try client.completePublishPubAck(42);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try std.testing.expectEqualStrings(first, pending.pop().?.bytes);
    try std.testing.expectEqualStrings(second, pending.pop().?.bytes);
    try std.testing.expect(pending.pop() == null);
}

test "MQTT publish completion preserves queued wrong stage acknowledgement state" {
    var client = runtime.Connection{ .allocator = allocator, .transport = undefined, .outgoing_inflight = 1 };
    defer client.packet_identifiers.deinit(allocator);
    try std.testing.expect(try client.packet_identifiers.add(allocator, 42, .outgoing_qos2));
    var pending: Pending = .{};
    defer pending.deinit(allocator);
    client.pending_packets = &pending;
    try pending.append(allocator, borrowed("\x40\x02\x00\x2a"), 2, 100);
    try std.testing.expectError(error.UnexpectedPacket, client.completePublishPubRec(42));
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try std.testing.expect(client.packet_identifiers.contains(42, .outgoing_qos2));
}

test "MQTT publish completion negative acknowledgements release only their exchange" {
    inline for (.{ mqtt.PacketType.puback, mqtt.PacketType.pubrec, mqtt.PacketType.pubcomp }) |packet_type| {
        var client = runtime.Connection{ .allocator = allocator, .transport = undefined, .outgoing_inflight = 2 };
        defer client.packet_identifiers.deinit(allocator);
        const stage = if (packet_type == .puback) .outgoing_qos1 else if (packet_type == .pubrec) .outgoing_qos2 else .outgoing_qos2_pubrel;
        try std.testing.expect(try client.packet_identifiers.add(allocator, 42, stage));
        try std.testing.expect(try client.packet_identifiers.add(allocator, 43, .outgoing_qos1));
        var pending: Pending = .{};
        defer pending.deinit(allocator);
        client.pending_packets = &pending;
        var bytes: [mqtt.AckPacket.no_properties_max_len]u8 = undefined;
        const encoded = try mqtt.AckPacket.writeNoPropertiesInto(&bytes, .v5, packet_type, 42, if (packet_type == .pubcomp) 0x92 else 0x80);
        try pending.append(allocator, borrowed(encoded), 2, 100);
        const result = switch (packet_type) {
            .puback => client.completePublishPubAck(42),
            .pubrec => client.completePublishPubRec(42),
            .pubcomp => client.completePublishPubComp(42),
            else => unreachable,
        };
        try std.testing.expectError(error.PublishRefused, result);
        try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
        try std.testing.expect(!client.hasOutgoingPacketIdentifier(42));
        try std.testing.expect(client.hasOutgoingPacketIdentifier(43));
    }
}

test "MQTT publish completion closed connection leaves queued acknowledgement untouched" {
    var client = runtime.Connection{ .allocator = allocator, .transport = undefined, .outgoing_inflight = 1 };
    defer client.packet_identifiers.deinit(allocator);
    try std.testing.expect(try client.packet_identifiers.add(allocator, 42, .outgoing_qos1));
    var pending: Pending = .{};
    defer pending.deinit(allocator);
    client.pending_packets = &pending;
    try pending.append(allocator, borrowed("\x40\x02\x00\x2a"), 2, 100);
    client.transport_unusable.store(true, .release);
    try std.testing.expectError(error.ConnectionClosed, client.completePublishPubAck(42));
    try std.testing.expectEqual(@as(usize, 1), pending.count());
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
}

test "MQTT publish completion preserves interleaved PUBLISH and out of order acknowledgements" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        try interleaved(protocol, .at_least_once);
        try interleaved(protocol, .exactly_once);
    }
}

test "MQTT publish completion services sibling PUBREC retry while waiting for PUBACK" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const receiver = try listener.accept(io);
    defer receiver.close(io);
    var client = runtime.Connection{ .allocator = allocator, .transport = .initTcp(io, sender), .outgoing_inflight = 2 };
    defer client.packet_identifiers.deinit(allocator);
    try std.testing.expect(try client.packet_identifiers.add(allocator, 42, .outgoing_qos1));
    try std.testing.expect(try client.packet_identifiers.add(allocator, 43, .outgoing_qos2_pubrel));
    var pending: Pending = .{};
    defer pending.deinit(allocator);
    client.pending_packets = &pending;
    try pending.append(allocator, borrowed("\x50\x02\x00\x2b"), 2, 100);
    try pending.append(allocator, borrowed("\x40\x02\x00\x2a"), 2, 100);
    try client.completePublishPubAck(42);
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try std.testing.expect(client.packet_identifiers.contains(43, .outgoing_qos2_pubrel));
    var transport = @import("../packet_transport.zig").Transport.initTcp(io, receiver);
    var retransmission = try transport.readPacketWithDeadline(allocator, 16, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    defer retransmission.deinit(allocator);
    try std.testing.expectEqualSlices(u8, "\x62\x02\x00\x2b", retransmission.bytes);
}

test "MQTT publish completion queue quotas preserve inflight state and retry wire order" {
    for ([_]bool{ false, true }) |byte_quota| try queueQuota(byte_quota);
}

fn queueQuota(byte_quota: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(allocator);
            try accepted.connection.publish("x", "1", .{});
            try accepted.connection.publish("x", "2", .{});
            try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{
        .client_id = "completion-quota",
        .limits = .{
            .max_pending_ping_packets = if (byte_quota) 256 else 1,
            // Fixed Header 2 + Topic 3 + Property Length 1 + Payload 1.
            .max_pending_packet_bytes = if (byte_quota) 7 else 1024,
        },
    });
    defer client.close();
    const id = (try client.writePublish("out", "payload", .{ .qos = .at_least_once })).?;
    try std.testing.expectError(error.TooManyPendingPackets, client.completePublishPubAck(id));
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try std.testing.expect(client.hasOutgoingPacketIdentifier(id));
    try std.testing.expectEqual(@as(usize, 2), client.pending_packets.?.count());
    for ([_][]const u8{ "1", "2" }) |payload| {
        var incoming = try client.readPublish();
        defer incoming.deinit(allocator);
        try std.testing.expectEqualStrings(payload, incoming.publish.payload);
    }
    try client.completePublishPubAck(id);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn interleaved(protocol: mqtt.ProtocolVersion, qos: mqtt.QoS) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        qos: mqtt.QoS,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = self.protocol });
            defer accepted.deinit(allocator);
            const connection = &accepted.connection;
            var first = try connection.readPublish();
            defer first.deinit(allocator);
            var second = try connection.readPublish();
            defer second.deinit(allocator);
            const first_id = first.publish.packet_id.?;
            const second_id = second.publish.packet_id.?;
            try connection.publish("incoming/one", "one", .{});
            if (self.qos == .at_least_once) {
                try connection.writePubAck(second_id, 0);
                try connection.publish("incoming/two", "two", .{});
                try connection.writePubAck(first_id, 0);
                return;
            }
            try connection.writePubRec(second_id, 0);
            try connection.publish("incoming/two", "two", .{});
            try connection.writePubRec(first_id, 0);
            try self.expectPubRel(connection, first_id, false);
            try self.expectPubRel(connection, second_id, false);
            // Repeated PUBREC is legal after the sender has advanced. It must
            // resend PUBREL and retain the same Packet Identifier and quota.
            try connection.writePubRec(first_id, 0);
            try self.expectPubRel(connection, first_id, self.protocol == .v3_1);
            try connection.writePubComp(second_id, 0);
            try connection.writePubComp(first_id, 0);
        }

        fn expectPubRel(self: *@This(), connection: *runtime.Connection, id: u16, dup: bool) !void {
            var event = try connection.readBrokerEventWithTimeout(.fromSeconds(1));
            defer event.deinit(allocator);
            try std.testing.expect(event == .pubrel);
            try std.testing.expectEqual(id, event.pubrel.ack.packet_id);
            try std.testing.expectEqual(dup, event.pubrel.ack.dup);
            _ = self;
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .qos = qos };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{
        .protocol = protocol,
        .client_id = "completion-order",
        .max_outgoing_inflight = 2,
    });
    defer client.close();
    const first_id = (try client.writePublish("outgoing/one", "first", .{ .qos = qos })).?;
    const second_id = (try client.writePublish("outgoing/two", "second", .{ .qos = qos })).?;
    if (qos == .at_least_once) {
        try client.completePublishPubAck(first_id);
        try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
        try client.completePublishPubAck(second_id);
    } else {
        try std.testing.expectEqual(first_id, try client.completePublishPubRec(first_id));
        try std.testing.expectEqual(second_id, try client.completePublishPubRec(second_id));
        try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);
        try client.completePublishPubComp(first_id);
        try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
        try client.completePublishPubComp(second_id);
    }
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    for ([_][]const u8{ "one", "two" }) |payload| {
        var incoming = try client.readPublish();
        defer incoming.deinit(allocator);
        try std.testing.expectEqualStrings(payload, incoming.publish.payload);
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
