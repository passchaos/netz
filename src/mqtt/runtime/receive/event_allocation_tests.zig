//! Event decode failure retains packet order and uncommitted protocol state.
const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Pair = @import("../acknowledgement/test_connection.zig").Pair;
const Pending = @import("../acknowledgement/pending.zig").State;
const allocator = std.testing.allocator;
const Kind = enum { publish, auth, puback, pubrec, pubrel, pubcomp, subscribe, unsubscribe };
const Policy = enum { client, broker, caller, output };
const Source = enum { wire, queued, overflow };
const diagnostic: []const mqtt.Property = &.{.{ .utf8 = .{ .id = .reason_string, .value = "retained diagnostic" } }};

test "MQTT event PUBLISH allocation failure preserves packet and QoS credit" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io(), .v5);
    defer pair.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try mqtt.writePublish(&wire, allocator, .v5, "allocation/topic", "exact payload", .{ .qos = .at_least_once, .packet_id = 42, .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }} });
    try pair.peer.transport.writePacket(wire.items);
    try pair.peer.writePingResp();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    {
        pair.client.allocator = failing.allocator();
        defer pair.client.allocator = allocator;
        try std.testing.expectError(error.OutOfMemory, pair.client.readClientPacketEventWithTimeout(.fromSeconds(1)));
    }
    try std.testing.expectEqual(@as(u16, 0), pair.client.incoming_inflight);
    try std.testing.expect(!pair.client.hasPendingIncomingPublish(42, .at_least_once));
    var event = try pair.client.readClientPacketEventWithTimeout(.fromSeconds(1));
    defer event.deinit(allocator);
    try std.testing.expect(event == .publish);
    try std.testing.expectEqualStrings("exact payload", event.publish.publish.payload);
    try std.testing.expectEqual(@as(u64, 1), pair.client.trafficStats().messages_received);
    var next = try pair.client.readClientPacketEventWithTimeout(.fromSeconds(1));
    defer next.deinit(allocator);
    try std.testing.expect(next == .pingresp);
}

test "MQTT event decode allocation failures retain every packet source and caller-buffer policy" {
    for (std.enums.values(Kind)) |kind| {
        for (std.enums.values(Policy)) |policy| {
            if (policy == .client and (kind == .subscribe or kind == .unsubscribe)) continue;
            for (std.enums.values(Source)) |source| {
                var succeeded = false;
                for (0..16) |fail_index| {
                    if (try allocationCase(kind, policy, source, fail_index)) {
                        succeeded = true;
                        break;
                    }
                }
                try std.testing.expect(succeeded);
            }
        }
    }
}

fn writeKind(wire: *std.ArrayList(u8), kind: Kind) !void {
    switch (kind) {
        .publish => try mqtt.writePublish(wire, allocator, .v5, "allocation/topic", "exact payload", .{ .qos = .exactly_once, .packet_id = 42, .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }} }),
        .auth => try mqtt.Auth.write(wire, allocator, .v5, 0, &.{ .{ .utf8 = .{ .id = .authentication_method, .value = "method" } }, .{ .binary = .{ .id = .authentication_data, .value = "proof" } } }),
        .puback, .pubrec, .pubrel, .pubcomp => try mqtt.AckPacket.write(wire, allocator, .v5, switch (kind) {
            .puback => .puback,
            .pubrec => .pubrec,
            .pubrel => .pubrel,
            .pubcomp => .pubcomp,
            else => unreachable,
        }, 42, 0, diagnostic),
        .subscribe => try mqtt.Subscribe.write(wire, allocator, .v5, 42, &.{.{ .utf8_pair = .{ .id = .user_property, .key = "key", .value = "value" } }}, &.{ .{ .topic_filter = "one/#" }, .{ .topic_filter = "two/+" } }),
        .unsubscribe => try mqtt.Unsubscribe.write(wire, allocator, .v5, 42, &.{.{ .utf8_pair = .{ .id = .user_property, .key = "key", .value = "value" } }}, &.{ "one/#", "two/+" }),
    }
}

fn receive(connection: *runtime.Connection, policy: Policy, kind: Kind, storage: []u8) !void {
    if (policy == .client) {
        var event = try connection.readClientPacketEventWithTimeout(.fromSeconds(1));
        defer event.deinit(connection.allocator);
        switch (kind) {
            .publish => {
                try std.testing.expect(event == .publish);
                try std.testing.expectEqualStrings("exact payload", event.publish.publish.payload);
            },
            .auth => {
                try std.testing.expect(event == .auth);
                try std.testing.expectEqualStrings("proof", event.auth.auth.properties[1].binary.value);
            },
            .puback => try std.testing.expect(event == .puback),
            .pubrec => try std.testing.expect(event == .pubrec),
            .pubrel => try std.testing.expect(event == .pubrel),
            .pubcomp => try std.testing.expect(event == .pubcomp),
            else => unreachable,
        }
        return;
    }
    var event: runtime.BrokerEvent = .{ .pingreq = .{ .bytes = @constCast("\xc0\x00"), .fixed = try mqtt.FixedHeader.parse("\xc0\x00"), .owns_bytes = false } };
    switch (policy) {
        .broker => event = try connection.readBrokerEventWithTimeout(.fromSeconds(1)),
        .caller => event = try connection.readBrokerEventInto(storage),
        .output => connection.readBrokerEventWithKeepAliveIntoPrefixedOut(storage, 32, &event) catch |err| {
            try std.testing.expect(event == .pingreq);
            return err;
        },
        .client => unreachable,
    }
    defer event.deinit(connection.allocator);
    switch (kind) {
        .publish => {
            try std.testing.expect(event == .publish);
            try std.testing.expectEqualStrings("exact payload", event.publish.publish.payload);
        },
        .auth => {
            try std.testing.expect(event == .auth);
            try std.testing.expectEqualStrings("proof", event.auth.auth.properties[1].binary.value);
        },
        .puback => try std.testing.expect(event == .puback),
        .pubrec => try std.testing.expect(event == .pubrec),
        .pubrel => try std.testing.expect(event == .pubrel),
        .pubcomp => try std.testing.expect(event == .pubcomp),
        .subscribe => {
            try std.testing.expect(event == .subscribe);
            try std.testing.expectEqualStrings("two/+", event.subscribe.subscribe.subscriptions[1].topic_filter);
        },
        .unsubscribe => {
            try std.testing.expect(event == .unsubscribe);
            try std.testing.expectEqualStrings("two/+", event.unsubscribe.unsubscribe.topic_filters[1]);
        },
    }
}

fn allocationCase(kind: Kind, policy: Policy, source: Source, fail_index: usize) !bool {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io(), .v5);
    defer pair.deinit();
    pair.client.endpoint_role = .unestablished;
    pair.peer.endpoint_role = .unestablished;
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try writeKind(&wire, kind);
    try pair.peer.transport.writePacket(wire.items);
    if (source != .wire) {
        const pending = try allocator.create(Pending);
        pending.* = .{};
        pair.client.pending_packets = pending;
        const packet = try pair.client.transport.readPacket(allocator, 4096);
        if (source == .queued) try pending.append(allocator, packet, 8, 4096) else pending.retainOverflow(packet);
    }
    try pair.peer.writePingReq();
    var storage: [4096]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
    const result = blk: {
        pair.client.allocator = failing.allocator();
        defer pair.client.allocator = allocator;
        break :blk receive(&pair.client, policy, kind, &storage);
    };
    if (failing.has_induced_failure) {
        try std.testing.expectError(error.OutOfMemory, result);
        try std.testing.expectEqual(@as(u16, 0), pair.client.incoming_inflight);
        try std.testing.expectEqual(@as(usize, 0), pair.client.incomingTopicAliasCount());
        const count = pair.client.trafficStats().messages_received;
        @memset(&storage, 0xaa);
        var repeated = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        {
            pair.client.allocator = repeated.allocator();
            defer pair.client.allocator = allocator;
            try std.testing.expectError(error.OutOfMemory, receive(&pair.client, policy, kind, &storage));
        }
        @memset(&storage, 0xbb);
        try std.testing.expectEqual(@as(u16, 0), pair.client.incoming_inflight);
        try std.testing.expectEqual(@as(usize, 0), pair.client.incomingTopicAliasCount());
        try receive(&pair.client, policy, kind, &storage);
        try std.testing.expectEqual(@as(u64, if (source == .wire) 1 else 0), pair.client.trafficStats().messages_received);
        if (count != 0) try std.testing.expectEqual(count, pair.client.trafficStats().messages_received);
    } else try result;
    if (kind == .publish) {
        try std.testing.expect(pair.client.hasPendingIncomingPublish(42, .exactly_once));
        try std.testing.expectEqual(@as(u16, 1), pair.client.incoming_inflight);
        try pair.client.writePubComp(42, 0);
    }
    var next = try pair.client.readBrokerEventWithTimeout(.fromSeconds(1));
    defer next.deinit(allocator);
    try std.testing.expect(next == .pingreq);
    return !failing.has_induced_failure;
}

test "MQTT retained event packets hand off to typed and correlated readers in order" {
    for ([_]Kind{ .publish, .auth, .puback }) |kind| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(allocator);
        try writeKind(&wire, kind);
        try pair.peer.transport.writePacket(wire.items);
        if (kind == .puback) {
            try std.testing.expect(try pair.client.packet_identifiers.add(allocator, 42, .outgoing_qos1));
            pair.client.outgoing_inflight = 1;
        }
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
        {
            pair.client.allocator = failing.allocator();
            defer pair.client.allocator = allocator;
            try std.testing.expectError(error.OutOfMemory, pair.client.readClientPacketEventWithTimeout(.fromSeconds(1)));
        }
        const packet_ptr = pair.client.retained_receive.bytes.?.ptr;
        try pair.peer.writePingResp();
        const pending = try allocator.create(Pending);
        pending.* = .{};
        pair.client.pending_packets = pending;
        // Keep a later already-owned packet in the emergency slot so moving
        // the earlier event cannot overwrite it or invert their wire order.
        pending.retainOverflow(try pair.client.transport.readPacket(allocator, 4096));
        pair.client.limits.max_pending_ping_packets = 0;
        pair.client.limits.max_pending_packet_bytes = 0;
        var failed_handoff = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        {
            pair.client.allocator = failed_handoff.allocator();
            defer pair.client.allocator = allocator;
            if (kind == .puback) {
                try std.testing.expectError(error.OutOfMemory, pair.client.completePublishPubAckWithTimeout(42, .fromSeconds(1)));
            } else if (kind == .publish) {
                try std.testing.expectError(error.OutOfMemory, pair.client.readPublish());
            } else {
                try std.testing.expectError(error.OutOfMemory, pair.client.readAuthWithTimeout(.fromSeconds(1)));
            }
        }
        try std.testing.expectEqual(packet_ptr, pair.client.retained_receive.bytes.?.ptr);
        try std.testing.expect(pending.overflow != null);
        switch (kind) {
            .publish => {
                var event = try pair.client.readPublish();
                defer event.deinit(allocator);
                try std.testing.expectEqual(packet_ptr, event.packet.bytes.ptr);
                try std.testing.expectEqualStrings("exact payload", event.publish.payload);
                try pair.client.writePubComp(42, 0);
            },
            .auth => {
                var event = try pair.client.readAuthWithTimeout(.fromSeconds(1));
                defer event.deinit(allocator);
                try std.testing.expectEqual(packet_ptr, event.packet.bytes.ptr);
                try std.testing.expectEqualStrings("proof", event.auth.properties[1].binary.value);
            },
            .puback => {
                try pair.client.completePublishPubAckWithTimeout(42, .fromSeconds(1));
                try std.testing.expectEqual(@as(u16, 0), pair.client.outgoing_inflight);
            },
            else => unreachable,
        }
        try std.testing.expect(pair.client.retained_receive.bytes == null);
        var next = try pair.client.readClientPacketEventWithTimeout(.fromSeconds(1));
        defer next.deinit(allocator);
        try std.testing.expect(next == .pingresp);
        try std.testing.expectEqual(@as(u64, 1), pair.client.trafficStats().messages_received);
    }
}

test "MQTT event decode OOM cleanup releases owned and restored caller packets" {
    for ([_]Policy{ .client, .caller }) |policy| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(allocator);
        try writeKind(&wire, .publish);
        try pair.peer.transport.writePacket(wire.items);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = if (policy == .client) 1 else 0 });
        var storage: [4096]u8 = undefined;
        pair.client.allocator = failing.allocator();
        defer pair.client.allocator = allocator;
        try std.testing.expectError(error.OutOfMemory, receive(&pair.client, policy, .publish, &storage));
        @memset(&storage, 0xaa);
        // Pair cleanup exercises both the inline owned slot and connection
        // read-ahead, with no application retry or packet ownership transfer.
    }
}

test "MQTT event semantic failures discard their packet without becoming allocation retries" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io(), .v5);
    defer pair.deinit();
    try pair.peer.transport.writePacketParts("\x40\x02\x00\x00", "");
    try pair.peer.writePingResp();
    try std.testing.expectError(error.InvalidPacketIdentifier, pair.client.readClientPacketEventWithTimeout(.fromSeconds(1)));
    try std.testing.expect(pair.client.retained_receive.bytes == null);
    var next = try pair.client.readClientPacketEventWithTimeout(.fromSeconds(1));
    defer next.deinit(allocator);
    try std.testing.expect(next == .pingresp);
}
