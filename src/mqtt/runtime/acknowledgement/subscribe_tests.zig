const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const Mode = enum { normal, earlier_ping, overflow, wrong_id, wrong_count };

test "MQTT client SUBSCRIBE preserves PUBLISH before SUBACK" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| try receive(protocol, .normal);
}

test "MQTT client SUBSCRIBE preserves packets queued by an earlier PING" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| try receive(protocol, .earlier_ping);
}

test "MQTT client SUBSCRIBE retains the overflowing packet and pending SUBACK" {
    try receive(.v5, .overflow);
}

test "MQTT client SUBSCRIBE rejects uncorrelated SUBACK after interleaved PUBLISH" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        try receive(protocol, .wrong_id);
        try receive(protocol, .wrong_count);
    }
}

test "MQTT client SUBSCRIBE pending queue failures precede I/O and Packet Identifier mutation" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var client = runtime.Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
        .endpoint_role = .client,
        .limits = .{ .max_pending_ping_packets = 0 },
    };
    try std.testing.expectError(error.TooManyPendingPackets, client.subscribe(&.{.{ .topic_filter = "valid/#" }}, .{}));
    try std.testing.expect(!failing.has_induced_failure);
    client.limits.max_pending_ping_packets = 1;
    try std.testing.expectError(error.OutOfMemory, client.subscribe(&.{.{ .topic_filter = "valid/#" }}, .{}));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(client.pending_packets == null);
    try std.testing.expectEqual(@as(u16, 1), client.next_packet_id);
    try std.testing.expectEqual(@as(usize, 0), client.write_scratch.items.len);
}

fn receive(protocol: mqtt.ProtocolVersion, mode: Mode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        mode: Mode,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = self.protocol });
            defer accepted.deinit(self.server.allocator);
            const connection = &accepted.connection;
            if (self.mode == .earlier_ping) {
                try connection.readPingReq();
                try connection.publish("subscribe/older", "older", .{});
                try connection.writePingResp();
            }
            var request = try connection.readSubscribe();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("subscribe/#", request.subscribe.subscriptions[0].topic_filter);
            try connection.publish("subscribe/first", "one", .{ .retain = true });
            try connection.publish("subscribe/second", "two", .{});
            try connection.writeSubAck(
                request.subscribe.packet_id + @intFromBool(self.mode == .wrong_id),
                if (self.mode == .wrong_count) &.{ 0, 0 } else &.{0},
                &.{},
            );
            try connection.publish("subscribe/after", "after", .{});
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.Client.connect(allocator, io, server.address(), .{
        .client_id = "subscribe-wire-order",
        .protocol = protocol,
        .limits = .{ .max_pending_ping_packets = if (mode == .overflow) 1 else 256 },
    });
    defer client.close();
    if (mode == .earlier_ping) try client.pingWithTimeout(.fromSeconds(2));
    var suback: ?runtime.OwnedSubAck = null;
    defer if (suback) |*owned| owned.deinit(allocator);
    const attempt = client.subscribe(&.{.{ .topic_filter = "subscribe/#" }}, .{});
    switch (mode) {
        .normal, .earlier_ping => suback = try attempt,
        .overflow => {
            try std.testing.expectError(error.TooManyPendingPackets, attempt);
            // A second operation cannot write while emergency storage is full.
            try std.testing.expectError(error.TooManyPendingPackets, client.subscribe(&.{.{ .topic_filter = "subscribe/#" }}, .{}));
        },
        .wrong_id, .wrong_count => try std.testing.expectError(error.UnexpectedPacket, attempt),
    }
    if (mode == .earlier_ping) {
        var older = try client.readPublish();
        defer older.deinit(allocator);
        try std.testing.expectEqualStrings("subscribe/older", older.publish.topic);
        try std.testing.expectEqualStrings("older", older.publish.payload);
    }
    for ([_][]const u8{ "subscribe/first", "subscribe/second" }, [_][]const u8{ "one", "two" }, 0..) |topic, payload, index| {
        var publish = try client.readPublish();
        defer publish.deinit(allocator);
        try std.testing.expectEqualStrings(topic, publish.publish.topic);
        try std.testing.expectEqualStrings(payload, publish.publish.payload);
        try std.testing.expectEqual(index == 0, publish.publish.retain);
    }
    if (mode == .overflow) suback = try client.readSubAck();
    if (suback) |owned| {
        try std.testing.expectEqual(@as(u16, 1), owned.suback.packet_id);
        try std.testing.expectEqualSlices(u8, &.{0}, owned.suback.reason_codes);
    }
    var after = try client.readPublish();
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("subscribe/after", after.publish.topic);
    try std.testing.expectEqualStrings("after", after.publish.payload);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
