const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Pending = @import("../acknowledgement/pending.zig").State;

const Operation = enum { client, client_timeout, client_deadline, broker, broker_timeout, broker_deadline, keep_alive, borrowed, keep_alive_borrowed, prefixed, output };

const Pair = struct {
    receiver: runtime.Connection,
    peer: runtime.Connection,
    fn init(io: std.Io) !Pair {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{
            .receiver = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, stream), .keep_alive_seconds = 1 },
            .peer = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, peer) },
        };
    }
    fn deinit(self: *Pair) void {
        self.receiver.close();
        self.peer.close();
    }
    fn send(self: *Pair) !void {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try mqtt.Disconnect.write(&bytes, std.testing.allocator, .v5, 0x87, &.{.{ .utf8 = .{ .id = .reason_string, .value = "expired" } }});
        try mqtt.writePublish(&bytes, std.testing.allocator, .v5, "after", "discarded", .{});
        try self.peer.transport.writePacket(bytes.items);
    }
};

fn receive(connection: *runtime.Connection, operation: Operation, storage: []u8) !void {
    if (operation == .client or operation == .client_timeout or operation == .client_deadline) {
        var event = switch (operation) {
            .client => try connection.readClientPacketEvent(),
            .client_timeout => try connection.readClientPacketEventWithTimeout(.fromSeconds(1)),
            .client_deadline => try connection.readClientPacketEventWithDeadline(connection.transport.deadlineFromNow(.fromSeconds(1))),
            else => unreachable,
        };
        defer event.deinit(connection.allocator);
        try std.testing.expect(event == .disconnect);
        try std.testing.expect(event.disconnect.packet.owns_bytes);
        try std.testing.expectEqualStrings("expired", event.disconnect.disconnect.properties[0].utf8.value);
        return;
    }
    var event: runtime.BrokerEvent = switch (operation) {
        .broker => try connection.readBrokerEvent(),
        .broker_timeout => try connection.readBrokerEventWithTimeout(.fromSeconds(1)),
        .broker_deadline => try connection.readBrokerEventWithDeadline(connection.transport.deadlineFromNow(.fromSeconds(1))),
        .keep_alive => try connection.readBrokerEventWithKeepAlive(),
        .borrowed => try connection.readBrokerEventInto(storage),
        .keep_alive_borrowed => try connection.readBrokerEventWithKeepAliveInto(storage),
        .prefixed => try connection.readBrokerEventWithKeepAliveIntoPrefixed(storage, 32),
        .output => blk: {
            var out: runtime.BrokerEvent = .{ .pingreq = .{ .bytes = @constCast("\xc0\x00"), .fixed = .{ .packet_type = .pingreq, .flags = 0, .remaining_len = 0, .header_len = 2 }, .owns_bytes = false } };
            connection.readBrokerEventWithKeepAliveIntoPrefixedOut(storage, 32, &out) catch |err| {
                try std.testing.expect(out == .pingreq);
                return err;
            };
            break :blk out;
        },
        else => unreachable,
    };
    defer event.deinit(connection.allocator);
    try std.testing.expect(event == .disconnect);
    try std.testing.expect(event.disconnect.packet.owns_bytes);
    try std.testing.expectEqualStrings("expired", event.disconnect.disconnect.properties[0].utf8.value);
}

test "MQTT event DISCONNECT decoding failures retain diagnostics across every reader" {
    for (std.enums.values(Operation)) |operation| {
        var succeeded = false;
        for (0..8) |fail_index| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var pair = try Pair.init(threaded.io());
            defer pair.deinit();
            try pair.send();
            const pending = try std.testing.allocator.create(Pending);
            pending.* = .{};
            pair.receiver.pending_packets = pending;
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
            var storage: [4096]u8 = undefined;
            const result = blk: {
                pair.receiver.allocator = failing.allocator();
                defer pair.receiver.allocator = std.testing.allocator;
                break :blk receive(&pair.receiver, operation, &storage);
            };
            if (failing.has_induced_failure) {
                try std.testing.expectError(error.OutOfMemory, result);
                // Failure must not keep a pointer into the caller's storage.
                @memset(&storage, 0xaa);
                try receive(&pair.receiver, operation, &storage);
            } else {
                try result;
                succeeded = true;
            }
            try std.testing.expect(!pair.receiver.isUsable());
            try std.testing.expectError(error.ConnectionClosed, receive(&pair.receiver, operation, &storage));
            if (succeeded) break;
        }
        try std.testing.expect(succeeded);
    }
}

test "MQTT prefixed event readers preserve pending prefix and enforce terminal I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    try pair.send();
    var storage: [4096]u8 = undefined;
    // The client event reader observes termination first. The broker hot path
    // must not bypass that state and deliver the noncompliant peer's suffix.
    try receive(&pair.receiver, .client, &storage);
    try std.testing.expectError(error.ConnectionClosed, pair.receiver.readBrokerEventWithKeepAliveIntoPrefixed(&storage, 32));
}

test "MQTT prefixed event readers consume queued packets before transport read ahead" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    _ = try pair.peer.writePublish("before", "kept", .{});
    try pair.send();
    const pending = try std.testing.allocator.create(Pending);
    pending.* = .{};
    pair.receiver.pending_packets = pending;
    // Stage the original prefix, terminal and noncompliant suffix. Another
    // transport-buffered packet must not leap ahead of these queue entries.
    for (0..3) |_| {
        var packet = try pair.receiver.transport.readPacket(std.testing.allocator, 4096);
        errdefer packet.deinit(std.testing.allocator);
        try pending.append(std.testing.allocator, packet, 4, 4096);
    }
    try pair.peer.writePingReq();
    pending.retainOverflow(try pair.receiver.transport.readPacket(std.testing.allocator, 4096));
    try pair.peer.writePingReq();
    var storage: [4096]u8 = undefined;
    var prefix = try pair.receiver.readBrokerEventWithKeepAliveIntoPrefixed(&storage, 32);
    defer prefix.deinit(std.testing.allocator);
    try std.testing.expect(prefix == .publish);
    try std.testing.expectEqualStrings("before", prefix.publish.publish.topic);
    try receive(&pair.receiver, .prefixed, &storage);
    try std.testing.expect(pair.receiver.pending_packets == null);
    try std.testing.expectError(error.ConnectionClosed, pair.receiver.readBrokerEventWithKeepAliveIntoPrefixed(&storage, 32));
}

test "MQTT event receive preflight preserves transport bytes and caller output on allocation failure" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        try pair.send();
        var storage: [4096]u8 = undefined;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        {
            pair.receiver.allocator = failing.allocator();
            defer pair.receiver.allocator = std.testing.allocator;
            try std.testing.expectError(error.OutOfMemory, receive(&pair.receiver, operation, &storage));
        }
        try std.testing.expect(pair.receiver.pending_packets == null);
        try std.testing.expectEqual(@as(u64, 0), pair.receiver.trafficStats().messages_received);
        try receive(&pair.receiver, operation, &storage);
        try std.testing.expectEqual(@as(u64, 1), pair.receiver.trafficStats().messages_received);
    }
}

test "MQTT event receive rejects every policy after local DISCONNECT" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        try pair.receiver.disconnect(0);
        var storage: [4096]u8 = undefined;
        try std.testing.expectError(error.ConnectionClosed, receive(&pair.receiver, operation, &storage));
        try std.testing.expect(pair.receiver.pending_packets == null);
        try std.testing.expectEqual(@as(u64, 0), pair.receiver.trafficStats().messages_received);
    }
}

test "MQTT event terminal protocol errors permit an outgoing diagnostic" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        var bytes = [_]u8{ 0xe0, 1, 0xff };
        try pair.peer.transport.writePacket(&bytes);
        var storage: [4096]u8 = undefined;
        try std.testing.expectError(error.InvalidReasonCode, receive(&pair.receiver, operation, &storage));
        try std.testing.expect(pair.receiver.isUsable());
        try pair.receiver.disconnect(0x82);
        var diagnostic = try pair.peer.readDisconnect();
        defer diagnostic.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u8, 0x82), diagnostic.disconnect.reason_code);
    }
}

test "MQTT prefixed terminal events own aligned packet bytes for short and fallback reads" {
    for ([_]usize{ 1, 4096 }) |storage_len| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        try pair.send();
        var storage: [4096]u8 = undefined;
        var event = try pair.receiver.readBrokerEventWithKeepAliveIntoPrefixed(storage[0..storage_len], 32);
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .disconnect);
        const packet = event.disconnect.packet;
        try std.testing.expect(packet.owns_bytes);
        try std.testing.expectEqual(@as(u16, 32), packet.prefix_len);
        try std.testing.expect(packet.prefixedAllocation() != null);
        @memset(&storage, 0xaa);
        try std.testing.expectEqualStrings("expired", event.disconnect.disconnect.properties[0].utf8.value);
    }
}

test "MQTT event DISCONNECT allocation failure preserves typed and AUTH diagnostic handoff" {
    inline for (.{ .typed, .auth }) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        if (operation == .auth) {
            try pair.receiver.authentication.beginConnect(std.testing.allocator, &.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
            try pair.receiver.authentication.finishServerInitial();
            try pair.receiver.authentication.beginReauthentication(&.{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }});
        }
        try pair.send();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
        {
            pair.receiver.allocator = failing.allocator();
            defer pair.receiver.allocator = std.testing.allocator;
            try std.testing.expectError(error.OutOfMemory, pair.receiver.readClientPacketEvent());
        }
        try std.testing.expect(pair.receiver.retained_receive.bytes != null);
        const bytes = pair.receiver.retained_receive.bytes.?;
        if (operation == .auth) try std.testing.expectError(error.ConnectionClosed, pair.receiver.receiveReauthenticationWithTimeout(.fromSeconds(1))) else try std.testing.expectError(error.ConnectionClosed, pair.receiver.readPublish());
        try std.testing.expect(!pair.receiver.isUsable());
        var diagnostic = try pair.receiver.readDisconnect();
        defer diagnostic.deinit(std.testing.allocator);
        try std.testing.expectEqual(bytes.ptr, diagnostic.packet.bytes.ptr);
        try std.testing.expectEqualStrings("expired", diagnostic.disconnect.properties[0].utf8.value);
        try std.testing.expect(pair.receiver.retained_receive.bytes == null);
        try std.testing.expectError(error.ConnectionClosed, pair.receiver.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
    }
}
