const std = @import("std");
const mqtt = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const Pair = @import("../test_connection.zig").Pair;
const Operation = enum { subscribe, unsubscribe };
const Budget = enum { ordinary, timeout, deadline };

fn write(connection: *runtime.Connection, operation: Operation, budget: Budget) !u16 {
    const deadline = connection.transport.deadlineFromNow(.fromSeconds(1));
    return switch (operation) {
        .subscribe => switch (budget) {
            .ordinary => connection.writeSubscribe(&.{.{ .topic_filter = "split/#" }}, .{}),
            .timeout => connection.writeSubscribeWithTimeout(&.{.{ .topic_filter = "split/#" }}, .{}, .fromSeconds(1)),
            .deadline => connection.writeSubscribeWithDeadline(&.{.{ .topic_filter = "split/#" }}, .{}, deadline),
        },
        .unsubscribe => switch (budget) {
            .ordinary => connection.writeUnsubscribe(&.{"split/#"}, .{}),
            .timeout => connection.writeUnsubscribeWithTimeout(&.{"split/#"}, .{}, .fromSeconds(1)),
            .deadline => connection.writeUnsubscribeWithDeadline(&.{"split/#"}, .{}, deadline),
        },
    };
}

fn complete(connection: *runtime.Connection, operation: Operation, id: u16, budget: Budget) !u16 {
    const deadline = connection.transport.deadlineFromNow(.fromSeconds(1));
    switch (operation) {
        .subscribe => {
            var ack = switch (budget) {
                .ordinary => try connection.completeSubscribe(id),
                .timeout => try connection.completeSubscribeWithTimeout(id, .fromSeconds(1)),
                .deadline => try connection.completeSubscribeWithDeadline(id, deadline),
            };
            defer ack.deinit(connection.allocator);
            return ack.suback.packet_id;
        },
        .unsubscribe => {
            var ack = switch (budget) {
                .ordinary => try connection.completeUnsubscribe(id),
                .timeout => try connection.completeUnsubscribeWithTimeout(id, .fromSeconds(1)),
                .deadline => try connection.completeUnsubscribeWithDeadline(id, deadline),
            };
            defer ack.deinit(connection.allocator);
            return ack.unsuback.packet_id;
        },
    }
}

fn readRequest(connection: *runtime.Connection, operation: Operation) !u16 {
    switch (operation) {
        .subscribe => {
            var request = try connection.readSubscribe();
            defer request.deinit(connection.allocator);
            return request.subscribe.packet_id;
        },
        .unsubscribe => {
            var request = try connection.readUnsubscribe();
            defer request.deinit(connection.allocator);
            return request.unsubscribe.packet_id;
        },
    }
}

fn writeAck(connection: *runtime.Connection, operation: Operation, id: u16) !void {
    const properties: []const mqtt.Property = if (connection.protocol == .v5) &.{.{ .utf8 = .{ .id = .reason_string, .value = "confirmed" } }} else &.{};
    switch (operation) {
        .subscribe => try connection.writeSubAck(id, &.{0}, properties),
        .unsubscribe => try connection.writeUnsubAck(id, if (connection.protocol == .v5) &.{0} else &.{}, properties),
    }
}

test "MQTT subscription completion supports split requests and reverse-order correlated ACKs" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Operation)) |first| {
            for (std.enums.values(Operation)) |second| {
                for (std.enums.values(Budget)) |budget| {
                    var pair = try Pair.init(threaded.io(), protocol);
                    defer pair.deinit();
                    const client = &pair.client;
                    client.max_outgoing_inflight = 0;
                    const first_id = try write(client, first, budget);
                    const second_id = try write(client, second, budget);
                    try std.testing.expectEqual(@as(u16, 1), first_id);
                    try std.testing.expectEqual(@as(u16, 2), second_id);
                    try std.testing.expectEqual(first_id, try readRequest(&pair.peer, first));
                    try std.testing.expectEqual(second_id, try readRequest(&pair.peer, second));
                    try pair.peer.publish("split/first", "before", .{});
                    try writeAck(&pair.peer, second, second_id);
                    try pair.peer.publish("split/second", "between", .{});
                    try writeAck(&pair.peer, first, first_id);
                    try std.testing.expectEqual(first_id, try complete(client, first, first_id, budget));
                    try std.testing.expect(client.hasOutgoingPacketIdentifier(second_id));
                    // The sibling ACK is recoverable even with an emergency
                    // packet and both configured queue quotas at zero.
                    client.limits.max_pending_ping_packets = 0;
                    client.limits.max_pending_packet_bytes = 0;
                    try std.testing.expectEqual(second_id, try complete(client, second, second_id, budget));
                    try std.testing.expectEqual(@as(u16, 3), client.next_packet_id);
                    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
                    try std.testing.expect(!client.hasOutgoingPacketIdentifier(first_id));
                    try std.testing.expect(!client.hasOutgoingPacketIdentifier(second_id));
                    for ([_][]const u8{ "before", "between" }) |expected| {
                        var message = try client.readPublish();
                        defer message.deinit(client.allocator);
                        try std.testing.expectEqualStrings(expected, message.publish.payload);
                    }
                }
            }
        }
    }
}

test "MQTT subscription completion retries a transport ACK after decode allocation failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Operation)) |operation| {
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const client = &pair.client;
        const id = try write(client, operation, .timeout);
        try std.testing.expectEqual(id, try readRequest(&pair.peer, operation));
        try writeAck(&pair.peer, operation, id);
        // Packet storage succeeds; the first property-decoder allocation fails
        // after the complete ACK has left the socket and entered overflow.
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        client.allocator = failing.allocator();
        const attempt = complete(client, operation, id, .timeout);
        client.allocator = std.testing.allocator;
        try std.testing.expectError(error.OutOfMemory, attempt);
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expect(client.pending_packets.?.overflow != null);
        try std.testing.expect(client.hasOutgoingPacketIdentifier(id));
        const before_packets = client.traffic.stats().messages_received;
        try std.testing.expectEqual(id, try complete(client, operation, id, .timeout));
        try std.testing.expectEqual(before_packets, client.traffic.stats().messages_received);
        try std.testing.expect(client.pending_packets.?.overflow == null);
        try std.testing.expect(!client.hasOutgoingPacketIdentifier(id));
    }
}

test "MQTT subscription completion resumes a timed out split request without retransmission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Operation)) |operation| {
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const client = &pair.client;
        const id = try write(client, operation, .deadline);
        try std.testing.expectEqual(id, try readRequest(&pair.peer, operation));
        switch (operation) {
            .subscribe => try std.testing.expectError(error.Timeout, client.completeSubscribeWithTimeout(id, .fromMilliseconds(5))),
            .unsubscribe => try std.testing.expectError(error.Timeout, client.completeUnsubscribeWithTimeout(id, .fromMilliseconds(5))),
        }
        try std.testing.expect(client.hasOutgoingPacketIdentifier(id));
        const before_packets = client.traffic.stats().messages_sent;
        try writeAck(&pair.peer, operation, id);
        try std.testing.expectEqual(id, try complete(client, operation, id, .deadline));
        try std.testing.expectEqual(before_packets, client.traffic.stats().messages_sent);
        try std.testing.expectEqual(@as(u16, 2), client.next_packet_id);
    }
}

test "MQTT subscription completion rejects unknown and wrong-stage identifiers before I/O" {
    var client = runtime.Connection{ .allocator = std.testing.allocator, .transport = undefined };
    defer client.packet_identifiers.deinit(client.allocator);
    try client.packet_identifiers.addControl(client.allocator, 42, .outgoing_subscribe, 1);
    try std.testing.expectError(error.UnexpectedPacket, client.completeSubscribe(0));
    try std.testing.expectError(error.UnexpectedPacket, client.completeSubscribe(1));
    try std.testing.expectError(error.UnexpectedPacket, client.completeUnsubscribe(42));
    try std.testing.expect(client.pending_packets == null);
    try std.testing.expect(client.hasOutgoingPacketIdentifier(42));
}

test "MQTT subscription completion preserves queued ACKs across closed and expired budgets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Operation)) |operation| {
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const client = &pair.client;
        const id = try write(client, operation, .ordinary);
        const bytes = if (operation == .subscribe) "\x90\x04\x00\x01\x00\x00" else "\xb0\x04\x00\x01\x00\x00";
        try client.pending_packets.?.append(client.allocator, .{ .bytes = @constCast(bytes), .fixed = try mqtt.FixedHeader.parse(bytes), .owns_bytes = false }, 1, 100);
        const before_bytes = client.pending_packets.?.queued_bytes;
        client.transport_unusable.store(true, .release);
        try std.testing.expectError(error.ConnectionClosed, complete(client, operation, id, .ordinary));
        client.transport_unusable.store(false, .release);
        for ([_]std.Io.Clock{ .awake, .real }) |clock| {
            const expired: std.Io.Clock.Timestamp = .{ .raw = .zero, .clock = clock };
            switch (operation) {
                .subscribe => {
                    try std.testing.expectError(error.Timeout, client.completeSubscribeWithDeadline(id, expired));
                    try std.testing.expectError(error.Timeout, client.writeSubscribeWithDeadline(&.{.{ .topic_filter = "expired/#" }}, .{}, expired));
                },
                .unsubscribe => {
                    try std.testing.expectError(error.Timeout, client.completeUnsubscribeWithDeadline(id, expired));
                    try std.testing.expectError(error.Timeout, client.writeUnsubscribeWithDeadline(&.{"expired/#"}, .{}, expired));
                },
            }
            try std.testing.expectEqual(before_bytes, client.pending_packets.?.queued_bytes);
            try std.testing.expect(client.hasOutgoingPacketIdentifier(id));
            try std.testing.expectEqual(@as(u16, 2), client.next_packet_id);
        }
        try std.testing.expectEqual(id, try complete(client, operation, id, .ordinary));
    }
}

test "MQTT subscription completion recovers convenience exchange ACKs after local OOM" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Operation)) |operation| {
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const client = &pair.client;
        const stage: @import("../../packet_identifiers.zig").State.Stage = if (operation == .subscribe) .outgoing_subscribe else .outgoing_unsubscribe;
        // Warm every pre-write allocation so the injected failure belongs to
        // response decoding after the convenience API submits its request.
        try client.packet_identifiers.addControl(client.allocator, 42, stage, 1);
        try std.testing.expect(client.packet_identifiers.remove(42, stage));
        const Pending = @import("../pending.zig").State;
        client.pending_packets = try client.allocator.create(Pending);
        client.pending_packets.?.* = .{};
        try client.write_scratch.ensureTotalCapacity(client.allocator, 1024);
        try writeAck(&pair.peer, operation, 1);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        client.allocator = failing.allocator();
        switch (operation) {
            .subscribe => try std.testing.expectError(error.OutOfMemory, client.subscribeWithTimeout(&.{.{ .topic_filter = "split/#" }}, .{}, .fromSeconds(1))),
            .unsubscribe => try std.testing.expectError(error.OutOfMemory, client.unsubscribeWithTimeout(&.{"split/#"}, .{}, .fromSeconds(1))),
        }
        client.allocator = std.testing.allocator;
        try std.testing.expectEqual(@as(u16, 1), try readRequest(&pair.peer, operation));
        try std.testing.expect(client.pending_packets.?.overflow != null);
        try std.testing.expect(client.hasOutgoingPacketIdentifier(1));
        const before = client.traffic.stats();
        try std.testing.expectEqual(@as(u16, 1), try complete(client, operation, 1, .ordinary));
        try std.testing.expectEqual(before, client.traffic.stats());
    }
}
