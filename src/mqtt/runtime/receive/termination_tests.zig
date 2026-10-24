const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Pending = @import("../acknowledgement/pending.zig").State;

const Pair = struct {
    client: runtime.Connection,
    peer: runtime.Connection,

    fn init(io: std.Io) !Pair {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{
            .client = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, stream) },
            .peer = .{ .allocator = std.testing.allocator, .transport = .initTcp(io, peer) },
        };
    }

    fn deinit(self: *Pair) void {
        self.client.close();
        self.peer.close();
    }

    fn terminal(self: *Pair) !void {
        const reason: u8 = if (self.client.endpoint_role == .server) 0 else 0x87;
        try self.peer.writeDisconnectWithProperties(reason, &.{.{ .utf8 = .{ .id = .reason_string, .value = "expired" } }});
    }
};

const Operation = enum { connect, connect_deadline, connack, publish, puback, pubrec, pubrel, pubcomp, subscribe, suback, unsubscribe, unsuback, pingreq, auth, auth_deadline };

fn read(connection: *runtime.Connection, operation: Operation) !void {
    switch (operation) {
        .connect, .connect_deadline => {
            var value = if (operation == .connect) try connection.readConnect() else try connection.readConnectWithTimeout(.fromSeconds(1));
            defer value.deinit(connection.allocator);
        },
        .connack => {
            var value = try connection.readConnAck();
            defer value.deinit(connection.allocator);
        },
        .publish => {
            var value = try connection.readPublish();
            defer value.deinit(connection.allocator);
        },
        .puback, .pubrec, .pubrel, .pubcomp => {
            var value = switch (operation) {
                .puback => try connection.readPubAck(),
                .pubrec => try connection.readPubRec(),
                .pubrel => try connection.readSessionPubRel(),
                .pubcomp => try connection.readPubComp(),
                else => unreachable,
            };
            defer value.deinit(connection.allocator);
        },
        .subscribe => {
            var value = try connection.readSubscribe();
            defer value.deinit(connection.allocator);
        },
        .suback => {
            var value = try connection.readSubAck();
            defer value.deinit(connection.allocator);
        },
        .unsubscribe => {
            var value = try connection.readUnsubscribe();
            defer value.deinit(connection.allocator);
        },
        .unsuback => {
            var value = try connection.readUnsubAck();
            defer value.deinit(connection.allocator);
        },
        .pingreq => try connection.readPingReq(),
        .auth, .auth_deadline => {
            var value = if (operation == .auth) try connection.readAuth() else try connection.readAuthWithTimeout(.fromSeconds(1));
            defer value.deinit(connection.allocator);
        },
    }
}

test "MQTT typed readers retain terminal diagnostics instead of discarding a mismatched packet" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var pair = try Pair.init(threaded.io());
        defer pair.deinit();
        pair.client.endpoint_role = switch (operation) {
            .connect, .connect_deadline => .unestablished,
            .subscribe, .unsubscribe, .pingreq, .pubrel => .server,
            else => .client,
        };
        // Typed reads need only the bounded emergency slot, including when
        // application interleaving queues have been disabled entirely.
        pair.client.limits.max_pending_ping_packets = 0;
        pair.client.limits.max_pending_packet_bytes = 0;
        try pair.terminal();
        try std.testing.expectError(error.ConnectionClosed, read(&pair.client, operation));
        try std.testing.expect(!pair.client.isUsable());
        if (pair.client.endpoint_role == .server) try std.testing.expectError(error.ConnectionClosed, pair.client.writePingResp()) else try std.testing.expectError(error.ConnectionClosed, pair.client.writePingReq());
        try std.testing.expectError(error.ConnectionClosed, read(&pair.client, operation));
        if (@intFromEnum(operation) % 2 == 0) {
            var terminal = try pair.client.readDisconnect();
            defer terminal.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("expired", terminal.disconnect.properties[0].utf8.value);
        } else {
            var terminal = try pair.client.readClientPacketEvent();
            defer terminal.deinit(std.testing.allocator);
            try std.testing.expect(terminal == .disconnect);
            try std.testing.expectEqualStrings("expired", terminal.disconnect.disconnect.properties[0].utf8.value);
        }
        try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
    }
}

test "MQTT typed receive allocation preflight fails before consuming terminal bytes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    try pair.terminal();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    {
        pair.client.allocator = failing.allocator();
        defer pair.client.allocator = std.testing.allocator;
        try std.testing.expectError(error.OutOfMemory, pair.client.readPublish());
    }
    try std.testing.expect(pair.client.isUsable());
    try std.testing.expectEqual(@as(u64, 0), pair.client.trafficStats().messages_received);
    try std.testing.expectError(error.ConnectionClosed, pair.client.readPublish());
    try std.testing.expectEqual(@as(u64, 1), pair.client.trafficStats().messages_received);
    var terminal = try pair.client.readDisconnect();
    defer terminal.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("expired", terminal.disconnect.properties[0].utf8.value);
    try std.testing.expectEqual(@as(u64, 1), pair.client.trafficStats().messages_received);
}

test "MQTT typed DISCONNECT decoding failure retains its exact owned packet for retry" {
    inline for (.{ .disconnect, .publish }) |operation| {
        var succeeded = false;
        for (0..8) |fail_index| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var pair = try Pair.init(threaded.io());
            defer pair.deinit();
            try pair.terminal();
            const pending = try std.testing.allocator.create(Pending);
            pending.* = .{};
            pair.client.pending_packets = pending;
            pending.retainOverflow(try pair.client.transport.readPacket(std.testing.allocator, 4096));
            const original_bytes = pending.overflow.?.bytes;
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
            const result = blk: {
                pair.client.allocator = failing.allocator();
                defer pair.client.allocator = std.testing.allocator;
                if (operation == .publish) break :blk read(&pair.client, .publish);
                var terminal = pair.client.readDisconnect() catch |err| break :blk @as(anyerror!void, err);
                terminal.deinit(pair.client.allocator);
                break :blk @as(anyerror!void, {});
            };
            if (failing.has_induced_failure) {
                try std.testing.expectError(error.OutOfMemory, result);
                try std.testing.expect(pair.client.isUsable());
                try std.testing.expectEqual(@as(usize, 1), pending.count());
                try std.testing.expectEqual(original_bytes.ptr, pending.overflow.?.bytes.ptr);
            } else {
                if (operation == .publish) try std.testing.expectError(error.ConnectionClosed, result) else try result;
                succeeded = true;
            }
            if (!succeeded or operation == .publish) {
                var terminal = try pair.client.readDisconnect();
                defer terminal.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("expired", terminal.disconnect.properties[0].utf8.value);
            }
            try std.testing.expect(!pair.client.isUsable());
            if (succeeded) break;
        }
        try std.testing.expect(succeeded);
    }
}

test "MQTT typed terminal handling preserves its prefix and discards a queued wire suffix" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    _ = try pair.peer.writePublish("before", "kept", .{});
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try mqtt.Disconnect.write(&bytes, std.testing.allocator, .v5, 0x87, &.{});
    try bytes.appendSlice(std.testing.allocator, &.{ 0xd0, 0, 0xd0, 0 });
    try pair.peer.transport.writePacket(bytes.items);
    const pending = try std.testing.allocator.create(Pending);
    pending.* = .{};
    pair.client.pending_packets = pending;
    for (0..3) |_| try pending.append(std.testing.allocator, try pair.client.transport.readPacket(std.testing.allocator, 4096), 4, 4096);
    pending.retainOverflow(try pair.client.transport.readPacket(std.testing.allocator, 4096));
    var prefix = try pair.client.readPublish();
    defer prefix.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("before", prefix.publish.topic);
    try std.testing.expectError(error.ConnectionClosed, pair.client.readSubAck());
    try std.testing.expectEqual(@as(usize, 1), pending.count());
    var terminal = try pair.client.readDisconnect();
    defer terminal.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0x87), terminal.disconnect.reason_code);
    try std.testing.expectError(error.ConnectionClosed, pair.client.readClientPacketEventWithTimeout(.fromMilliseconds(5)));
}

test "MQTT typed terminal validation retains protocol error classification" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair = try Pair.init(threaded.io());
    defer pair.deinit();
    var bytes = [_]u8{ 0xe0, 1, 0xff };
    try pair.peer.transport.writePacket(&bytes);
    try std.testing.expectError(error.InvalidReasonCode, pair.client.readPublish());
    try std.testing.expect(pair.client.isUsable());
    try pair.client.disconnect(0x82);
    var response = try pair.peer.readDisconnect();
    defer response.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 0x82), response.disconnect.reason_code);
}
