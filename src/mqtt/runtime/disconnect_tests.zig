const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const Pending = @import("acknowledgement/pending.zig").State;

const Pair = struct {
    client: runtime.Connection,
    peer: runtime.Connection,
    fn init(io: std.Io, protocol: mqtt.ProtocolVersion) !Pair {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{
            .client = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, stream), .protocol = protocol },
            .peer = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, peer), .protocol = protocol },
        };
    }
    fn deinit(self: *Pair) void {
        self.client.close();
        self.peer.close();
    }

    // Stage a pre-existing queue from real wire packets, including a suffix
    // from a noncompliant peer. Public readers now stop before that suffix.
    fn buffer(self: *Pair, count: usize) !void {
        const pending = self.client.pending_packets orelse blk: {
            const created = try std.testing.allocator.create(Pending);
            created.* = .{};
            self.client.pending_packets = created;
            break :blk created;
        };
        for (0..count) |_| {
            var packet = try self.client.transport.readPacket(std.testing.allocator, 4096);
            errdefer packet.deinit(std.testing.allocator);
            try pending.append(std.testing.allocator, packet, 16, 4096);
        }
        pending.retainOverflow(try self.client.transport.readPacket(std.testing.allocator, 4096));
    }
};

test "MQTT received DISCONNECT retires typed and event readers after diagnostics" {
    inline for (.{ mqtt.ProtocolVersion.v3_1, mqtt.ProtocolVersion.v3_1_1, mqtt.ProtocolVersion.v5 }) |protocol| {
        inline for (.{ .typed, .client, .client_deadline, .broker, .borrowed_broker }) |operation| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var pair = try Pair.init(threaded.io(), protocol);
            defer pair.deinit();
            // A noncompliant peer keeps its socket open and sends another
            // packet after DISCONNECT. Bypass the public terminating writer.
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(std.testing.allocator);
            try mqtt.Disconnect.write(&bytes, std.testing.allocator, protocol, 0, &.{});
            try bytes.appendSlice(std.testing.allocator, &.{ 0xd0, 0x00 });
            try pair.peer.transport.writePacket(bytes.items);
            switch (operation) {
                .typed => {
                    var packet = try pair.client.readDisconnect();
                    defer packet.deinit(std.testing.allocator);
                    try std.testing.expectEqual(@as(u8, 0), packet.disconnect.reason_code);
                },
                .client => {
                    var packet = try pair.client.readClientPacketEvent();
                    defer packet.deinit(std.testing.allocator);
                    try std.testing.expect(packet == .disconnect);
                },
                .client_deadline => {
                    var packet = try pair.client.readClientPacketEventWithTimeout(.fromSeconds(1));
                    defer packet.deinit(std.testing.allocator);
                    try std.testing.expect(packet == .disconnect);
                },
                .broker => {
                    var packet = try pair.client.readBrokerEvent();
                    defer packet.deinit(std.testing.allocator);
                    try std.testing.expect(packet == .disconnect);
                },
                .borrowed_broker => {
                    var storage: [4096]u8 = undefined;
                    var packet = try pair.client.readBrokerEventInto(&storage);
                    defer packet.deinit(std.testing.allocator);
                    try std.testing.expect(packet == .disconnect);
                },
                else => unreachable,
            }
            try std.testing.expect(!pair.client.isUsable());
            try std.testing.expectError(error.ConnectionClosed, pair.client.writePingReq());
            try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
        }
    }
}

test "MQTT sent DISCONNECT is the final packet and shuts down network I/O" {
    inline for (.{ mqtt.ProtocolVersion.v3_1, mqtt.ProtocolVersion.v3_1_1, mqtt.ProtocolVersion.v5 }) |protocol| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io(), protocol);
        defer pair.deinit();
        try pair.client.disconnect(0);
        try std.testing.expect(!pair.client.isUsable());
        try std.testing.expectError(error.ConnectionClosed, pair.client.writePingReq());
        var packet = try pair.peer.readDisconnect();
        defer packet.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 0), packet.disconnect.reason_code);
        try std.testing.expectError(error.ConnectionClosed, pair.peer.transport.readPacketWithDeadline(std.testing.allocator, 4096, .fromNow(threaded.io(), .{ .raw = .fromMilliseconds(50), .clock = .awake })));
    }
}

test "MQTT synchronous reauthentication method mismatch diagnoses and retires the connection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io(), .v5);
    defer pair.deinit();
    try pair.client.authentication.beginConnect(std.testing.allocator, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
    try pair.client.authentication.finishServerInitial();
    try pair.client.beginReauthentication("start");
    var request = try pair.peer.readAuth();
    defer request.deinit(std.testing.allocator);
    try pair.peer.writeAuth(0x18, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "changed" } }});
    try std.testing.expectError(error.AuthenticationMethodMismatch, pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1)));
    try std.testing.expect(!pair.client.isUsable());
    var refusal = try pair.peer.readDisconnect();
    defer refusal.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0x82), refusal.disconnect.reason_code);
}

test "MQTT correlated waits retain DISCONNECT and stop without a reply or peer EOF" {
    inline for (.{ .ping, .publish, .publish_qos2, .publish_pubcomp, .subscribe, .unsubscribe }) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try mqtt.Disconnect.write(&bytes, std.testing.allocator, .v5, 0x87, &.{.{ .utf8 = .{ .id = .reason_string, .value = "refused" } }});
        try pair.peer.transport.writePacket(bytes.items);
        switch (operation) {
            .ping => try std.testing.expectError(error.ConnectionClosed, pair.client.pingWithTimeout(.fromMilliseconds(50))),
            .publish => {
                const id = (try pair.client.writePublish("pending", "payload", .{ .qos = .at_least_once })).?;
                try std.testing.expectError(error.ConnectionClosed, pair.client.completePublishWithTimeout(id, .at_least_once, .fromMilliseconds(50)));
                try std.testing.expectEqual(@as(u16, 1), pair.client.outgoing_inflight);
            },
            .publish_qos2, .publish_pubcomp => {
                const id = (try pair.client.writePublish("pending", "payload", .{ .qos = .exactly_once })).?;
                if (operation == .publish_pubcomp) try pair.client.applyPubRec(.{ .packet_type = .pubrec, .packet_id = id });
                try std.testing.expectError(error.ConnectionClosed, pair.client.completePublishWithTimeout(id, .exactly_once, .fromMilliseconds(50)));
                try std.testing.expectEqual(@as(u16, 1), pair.client.outgoing_inflight);
            },
            .subscribe => {
                const id = try pair.client.writeSubscribe(&.{.{ .topic_filter = "pending", .qos = .at_least_once }}, .{});
                try std.testing.expectError(error.ConnectionClosed, pair.client.completeSubscribeWithTimeout(id, .fromMilliseconds(50)));
            },
            .unsubscribe => {
                const id = try pair.client.writeUnsubscribe(&.{"pending"}, .{});
                try std.testing.expectError(error.ConnectionClosed, pair.client.completeUnsubscribeWithTimeout(id, .fromMilliseconds(50)));
            },
            else => unreachable,
        }
        try std.testing.expect(!pair.client.isUsable());
        var disconnect = try pair.client.readDisconnect();
        defer disconnect.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 0x87), disconnect.disconnect.reason_code);
        try std.testing.expectEqualStrings("refused", disconnect.disconnect.properties[0].utf8.value);
        try std.testing.expectError(error.ConnectionClosed, pair.client.writePingReq());
    }
}

test "MQTT retained DISCONNECT discards its wire suffix while preserving earlier acknowledgements" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io(), .v5);
    defer pair.deinit();
    const id = try pair.client.writeSubscribe(&.{.{ .topic_filter = "pending", .qos = .at_least_once }}, .{});
    try pair.peer.writeSubAck(id, &.{1}, &.{});
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try mqtt.Disconnect.write(&bytes, std.testing.allocator, .v5, 0x87, &.{});
    try mqtt.writePing(&bytes, std.testing.allocator, true);
    try pair.peer.transport.writePacket(bytes.items);
    try std.testing.expectError(error.ConnectionClosed, pair.client.pingWithTimeout(.fromMilliseconds(50)));
    var accepted = try pair.client.completeSubscribeWithTimeout(id, .fromMilliseconds(50));
    defer accepted.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{1}, accepted.suback.reason_codes);
    var terminal = try pair.client.readDisconnect();
    defer terminal.deinit(std.testing.allocator);
    try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
}

test "MQTT malformed DISCONNECT retains a protocol error instead of graceful termination" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io(), .v5);
    defer pair.deinit();
    var bytes = [_]u8{ 0xe0, 0x01, 0xff };
    try pair.peer.transport.writePacket(&bytes);
    try std.testing.expectError(error.InvalidReasonCode, pair.client.readDisconnect());
    try std.testing.expect(pair.client.isUsable());
    try pair.client.disconnect(0x82);
    var diagnostic = try pair.peer.readDisconnect();
    defer diagnostic.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0x82), diagnostic.disconnect.reason_code);
}

test "MQTT received DISCONNECT consumes a queued terminal boundary and releases its suffix" {
    inline for (.{ .typed, .client, .broker }) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        _ = try pair.peer.writePublish("before", "kept", .{});
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try mqtt.Disconnect.write(&bytes, std.testing.allocator, .v5, 0x87, &.{});
        // Both an ordinary queue entry and the emergency overflow follow it.
        try bytes.appendSlice(std.testing.allocator, &.{ 0xd0, 0, 0xd0, 0 });
        try pair.peer.transport.writePacket(bytes.items);
        try pair.buffer(3);
        var prefix = try pair.client.readPublish();
        defer prefix.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("before", prefix.publish.topic);
        switch (operation) {
            .typed => {
                var terminal = try pair.client.readDisconnect();
                defer terminal.deinit(std.testing.allocator);
            },
            .client => {
                var terminal = try pair.client.readClientPacketEvent();
                defer terminal.deinit(std.testing.allocator);
                try std.testing.expect(terminal == .disconnect);
            },
            .broker => {
                var terminal = try pair.client.readBrokerEvent();
                defer terminal.deinit(std.testing.allocator);
                try std.testing.expect(terminal == .disconnect);
            },
            else => unreachable,
        }
        try std.testing.expect(pair.client.pending_packets == null);
        try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
    }
}

test "MQTT retained DISCONNECT observation preserves the queued prefix and diagnostics" {
    inline for (.{ .auth, .subscribe }) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        const id = try pair.client.writeSubscribe(&.{.{ .topic_filter = "pending", .qos = .at_least_once }}, .{});
        try pair.peer.writeSubAck(id, &.{1}, &.{});
        _ = try pair.peer.writePublish("before", "kept", .{});
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try mqtt.Disconnect.write(&bytes, std.testing.allocator, .v5, 0x87, &.{.{ .utf8 = .{ .id = .reason_string, .value = "expired" } }});
        try bytes.appendSlice(std.testing.allocator, &.{ 0xd0, 0, 0xd0, 0 });
        try pair.peer.transport.writePacket(bytes.items);
        try pair.buffer(4);
        if (operation == .auth) {
            try pair.client.authentication.beginConnect(std.testing.allocator, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
            try pair.client.authentication.finishServerInitial();
            try pair.client.authentication.beginReauthentication(&.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
            try std.testing.expectError(error.ConnectionClosed, pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1)));
        }
        var accepted = try pair.client.completeSubscribeWithTimeout(id, .fromSeconds(1));
        defer accepted.deinit(std.testing.allocator);
        try std.testing.expectEqualSlices(u8, &.{1}, accepted.suback.reason_codes);
        try std.testing.expect(!pair.client.isUsable());
        var prefix = try pair.client.readPublish();
        defer prefix.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("before", prefix.publish.topic);
        var terminal = try pair.client.readDisconnect();
        defer terminal.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("expired", terminal.disconnect.properties[0].utf8.value);
        try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
    }
}

test "MQTT reauthentication DISCONNECT survives exhausted pending packet quotas" {
    inline for (.{ .count, .bytes }) |quota| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io(), .v5);
        defer pair.deinit();
        try pair.client.authentication.beginConnect(std.testing.allocator, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
        try pair.client.authentication.finishServerInitial();
        try pair.client.authentication.beginReauthentication(&.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
        if (quota == .count) pair.client.limits.max_pending_ping_packets = 1 else pair.client.limits.max_pending_packet_bytes = 8;
        // MQTT 5 QoS 0 PUBLISH is exactly eight bytes: fixed header, one-byte
        // topic, empty property list, and a two-byte payload.
        _ = try pair.peer.writePublish("x", "ab", .{});
        try pair.peer.writeDisconnectWithProperties(0x87, &.{.{ .utf8 = .{ .id = .reason_string, .value = "expired" } }});
        try std.testing.expectError(error.ConnectionClosed, pair.client.receiveReauthenticationWithTimeout(.fromSeconds(1)));
        try std.testing.expect(!pair.client.isUsable());
        var prefix = try pair.client.readPublish();
        defer prefix.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("ab", prefix.publish.payload);
        var terminal = try pair.client.readDisconnect();
        defer terminal.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("expired", terminal.disconnect.properties[0].utf8.value);
        try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
    }
}
