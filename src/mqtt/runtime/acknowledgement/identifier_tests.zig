const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");

const Operation = enum { subscribe, unsubscribe };

const Pair = struct {
    client: runtime.Connection,
    peer: runtime.Connection,

    fn init(io: std.Io, protocol: mqtt.ProtocolVersion) !Pair {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const client_stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer client_stream.close(io);
        const peer_stream = try listener.accept(io);
        return .{
            .client = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, client_stream), .protocol = protocol, .endpoint_role = .client },
            .peer = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, peer_stream), .protocol = protocol, .endpoint_role = .server },
        };
    }

    fn deinit(self: *Pair) void {
        self.client.close();
        self.peer.close();
    }
};

fn exchange(connection: *runtime.Connection, operation: Operation, timeout: std.Io.Duration) !u16 {
    switch (operation) {
        .subscribe => {
            var ack = try connection.subscribeWithTimeout(&.{.{ .topic_filter = "identifiers/#" }}, .{}, timeout);
            defer ack.deinit(connection.allocator);
            return ack.suback.packet_id;
        },
        .unsubscribe => {
            var ack = try connection.unsubscribeWithTimeout(&.{"identifiers/#"}, .{}, timeout);
            defer ack.deinit(connection.allocator);
            return ack.unsuback.packet_id;
        },
    }
}

fn writeAck(connection: *runtime.Connection, operation: Operation, id: u16, reasons: []const u8) !void {
    switch (operation) {
        .subscribe => try connection.writeSubAck(id, reasons, &.{}),
        .unsubscribe => try connection.writeUnsubAck(id, if (connection.protocol == .v5) reasons else &.{}, &.{}),
    }
}

fn readAck(connection: *runtime.Connection, operation: Operation) !u16 {
    switch (operation) {
        .subscribe => {
            var ack = try connection.readSubAck();
            defer ack.deinit(connection.allocator);
            return ack.suback.packet_id;
        },
        .unsubscribe => {
            var ack = try connection.readUnsubAck();
            defer ack.deinit(connection.allocator);
            return ack.unsuback.packet_id;
        },
    }
}

test "MQTT subscription identifiers skip unfinished PUBLISH across wraparound" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Operation)) |operation| {
            var pair = try Pair.init(threaded.io(), protocol);
            defer pair.deinit();
            const client = &pair.client;
            client.max_outgoing_inflight = 1;
            client.next_packet_id = 65_535;
            try std.testing.expectEqual(@as(?u16, 65_535), try client.writePublish("identifiers/publish", "incomplete", .{ .qos = .at_least_once }));
            client.next_packet_id = 65_535;
            try writeAck(&pair.peer, operation, 1, &.{0});
            try std.testing.expectEqual(@as(u16, 1), try exchange(client, operation, .fromSeconds(1)));
            try std.testing.expect(client.hasOutgoingPacketIdentifier(65_535));
            try std.testing.expect(!client.hasOutgoingPacketIdentifier(1));
            try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
        }
    }
}

test "MQTT subscription identifiers retain timed out exchanges and defer late acknowledgements" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Operation)) |first| {
            for (std.enums.values(Operation)) |second| {
                var pair = try Pair.init(threaded.io(), protocol);
                defer pair.deinit();
                const client = &pair.client;
                client.next_packet_id = 65_535;
                try std.testing.expectError(error.Timeout, exchange(client, first, .fromMilliseconds(5)));
                try std.testing.expect(client.hasOutgoingPacketIdentifier(65_535));
                try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
                client.next_packet_id = 65_535;
                // Both complete responses are on the wire before the second
                // request. Only its own identifier can complete that call.
                try writeAck(&pair.peer, first, 65_535, &.{0});
                try writeAck(&pair.peer, second, 1, &.{0});
                try std.testing.expectEqual(@as(u16, 1), try exchange(client, second, .fromSeconds(1)));
                try std.testing.expect(client.hasOutgoingPacketIdentifier(65_535));
                try std.testing.expect(!client.hasOutgoingPacketIdentifier(1));
                try std.testing.expectEqual(@as(u16, 65_535), try readAck(client, first));
                try std.testing.expect(!client.hasOutgoingPacketIdentifier(65_535));
                client.next_packet_id = 65_535;
                try std.testing.expectEqual(@as(?u16, 65_535), try client.writePublish("identifiers/reused", "confirmed", .{ .qos = .exactly_once }));
            }
        }
    }
}

test "MQTT subscription identifiers survive wrong-stage and wrong-count acknowledgements" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Operation)) |operation| {
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const client = &pair.client;
        try std.testing.expectError(error.Timeout, exchange(client, operation, .fromMilliseconds(5)));
        var malformed = [_]u8{ if (operation == .subscribe) 0x90 else 0xb0, 4, 0, 1, 0, 0x7f };
        try pair.peer.transport.writePacket(&malformed);
        try std.testing.expectError(error.InvalidReasonCode, readAck(client, operation));
        try std.testing.expect(client.hasOutgoingPacketIdentifier(1));
        try writeAck(&pair.peer, operation, 1, &.{ 0, 0 });
        try std.testing.expectError(error.UnexpectedPacket, readAck(client, operation));
        try std.testing.expect(client.hasOutgoingPacketIdentifier(1));
        const opposite: Operation = if (operation == .subscribe) .unsubscribe else .subscribe;
        try writeAck(&pair.peer, opposite, 1, &.{0});
        try std.testing.expectError(error.UnexpectedPacket, readAck(client, opposite));
        try std.testing.expect(client.hasOutgoingPacketIdentifier(1));
        try writeAck(&pair.peer, operation, 1, &.{0x80});
        try std.testing.expectEqual(@as(u16, 1), try readAck(client, operation));
        try std.testing.expect(!client.hasOutgoingPacketIdentifier(1));
    }
}

test "MQTT subscription identifiers roll back allocation and packet-size preflight failures" {
    for (std.enums.values(Operation)) |operation| {
        var reached_preflight = false;
        for (0..16) |fail_index| {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
            var client = runtime.Connection{
                .allocator = failing.allocator(),
                .transport = undefined,
                .endpoint_role = .client,
                .protocol = .v5,
                .next_packet_id = 65_535,
                .peer_max_packet_size = 1,
            };
            // No transport operation is reached: every successful allocation
            // path must reject the request against the peer's packet limit.
            const result = switch (operation) {
                .subscribe => blk: {
                    var ack = client.subscribe(&.{.{ .topic_filter = "identifiers/#" }}, .{}) catch |err| break :blk err;
                    ack.deinit(client.allocator);
                    break :blk error.TestUnexpectedResult;
                },
                .unsubscribe => blk: {
                    var ack = client.unsubscribe(&.{"identifiers/#"}, .{}) catch |err| break :blk err;
                    ack.deinit(client.allocator);
                    break :blk error.TestUnexpectedResult;
                },
            };
            defer {
                client.packet_identifiers.deinit(client.allocator);
                client.write_scratch.deinit(client.allocator);
                if (client.pending_packets) |pending| {
                    pending.deinit(client.allocator);
                    client.allocator.destroy(pending);
                }
            }
            if (result == error.OutgoingPacketTooLarge) reached_preflight = true else try std.testing.expectEqual(error.OutOfMemory, result);
            try std.testing.expectEqual(@as(u16, 65_535), client.next_packet_id);
            try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
            try std.testing.expect(!client.hasOutgoingPacketIdentifier(65_535));
            if (reached_preflight) break;
        }
        try std.testing.expect(reached_preflight);
    }
}

test "MQTT subscription identifiers reject PUBLISH acknowledgements for control exchanges" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Operation)) |operation| {
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const client = &pair.client;
        try std.testing.expectError(error.Timeout, exchange(client, operation, .fromMilliseconds(5)));
        client.next_packet_id = 1;
        const id = (try client.writePublish("identifiers/publish", "pending", .{ .qos = .at_least_once })).?;
        try std.testing.expectEqual(@as(u16, 2), id);
        try pair.peer.writePubAck(1, 0);
        try std.testing.expectError(error.UnexpectedPacket, client.completePublishPubAckWithTimeout(id, .fromSeconds(1)));
        try std.testing.expect(client.hasOutgoingPacketIdentifier(1));
        try std.testing.expect(client.hasOutgoingPacketIdentifier(id));
        try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    }
}

test "MQTT subscription identifiers settle multi-filter late responses in legacy and v5 protocols" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Operation)) |operation| {
            var pair = try Pair.init(threaded.io(), protocol);
            defer pair.deinit();
            const client = &pair.client;
            switch (operation) {
                .subscribe => try std.testing.expectError(error.Timeout, client.subscribeWithTimeout(&.{ .{ .topic_filter = "first/#" }, .{ .topic_filter = "second/#" } }, .{}, .fromMilliseconds(5))),
                .unsubscribe => try std.testing.expectError(error.Timeout, client.unsubscribeWithTimeout(&.{ "first/#", "second/#" }, .{}, .fromMilliseconds(5))),
            }
            try std.testing.expect(client.hasOutgoingPacketIdentifier(1));
            try writeAck(&pair.peer, operation, 1, &.{ 0, 0x80 });
            try std.testing.expectEqual(@as(u16, 1), try readAck(client, operation));
            try std.testing.expect(!client.hasOutgoingPacketIdentifier(1));
        }
    }
}
