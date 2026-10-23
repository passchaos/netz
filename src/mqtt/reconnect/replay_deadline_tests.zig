const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const reconnect = @import("../reconnect.zig");
const BlockedWrite = @import("../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const Phase = enum { qos1, qos2_publish, pubrel };

fn readPublish(connection: *runtime.Connection) !runtime.OwnedPublish {
    var event = try connection.readBrokerEventWithDeadline(connection.transport.deadlineFromNow(.fromSeconds(2)));
    if (event != .publish) {
        event.deinit(connection.allocator);
        return error.TestUnexpectedResult;
    }
    return event.publish;
}

fn readRelease(connection: *runtime.Connection) !runtime.OwnedAck {
    var event = try connection.readBrokerEventWithDeadline(connection.transport.deadlineFromNow(.fromSeconds(2)));
    if (event != .pubrel) {
        event.deinit(connection.allocator);
        return error.TestUnexpectedResult;
    }
    return event.pubrel;
}

test "MQTT reconnect deadline cancels QoS recovery writes after CONNACK" {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        for (std.enums.values(Phase)) |phase| {
            for ([_]bool{ false, true }) |absolute| try exercise(protocol, phase, absolute);
        }
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, phase: Phase, absolute: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = BlockedWrite{ .delegate = io, .packet_type = if (phase == .pubrel) .pubrel else .publish };
    BlockedWrite.active = &observer;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        phase: Phase,
        protocol: mqtt.ProtocolVersion,
        expected_id: std.atomic.Value(u16) = .init(0),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            {
                var initial = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(3));
                defer initial.deinit(self.server.allocator);
                if (self.phase == .pubrel) {
                    var publish = try initial.connection.readPublish();
                    defer publish.deinit(self.server.allocator);
                    try initial.connection.writePubRec(publish.publish.packet_id.?, 0);
                    var release = try initial.connection.readPubRel();
                    defer release.deinit(self.server.allocator);
                    try std.testing.expectEqual(publish.publish.packet_id.?, release.ack.packet_id);
                }
                initial.connection.readPingReq() catch |err| switch (err) {
                    error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                    else => return err,
                };
            }
            {
                var resumed = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, .fromSeconds(3));
                defer resumed.deinit(self.server.allocator);
                if (self.phase == .pubrel) {
                    if (resumed.connection.readSessionPubRel()) |value| {
                        var unexpected = value;
                        unexpected.deinit(self.server.allocator);
                        return error.TestUnexpectedResult;
                    } else |err| switch (err) {
                        error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                        else => return err,
                    }
                } else {
                    if (resumed.connection.readPublish()) |value| {
                        var unexpected = value;
                        unexpected.deinit(self.server.allocator);
                        return error.TestUnexpectedResult;
                    } else |err| switch (err) {
                        error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                        else => return err,
                    }
                }
            }
            var recovered = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, .fromSeconds(3));
            defer recovered.deinit(self.server.allocator);
            const expected = self.expected_id.load(.acquire);
            if (self.phase == .pubrel) {
                var release = try readRelease(&recovered.connection);
                defer release.deinit(self.server.allocator);
                try std.testing.expectEqual(expected, release.ack.packet_id);
                try recovered.connection.writePubComp(expected, 0);
            } else {
                var publish = try readPublish(&recovered.connection);
                defer publish.deinit(self.server.allocator);
                try std.testing.expectEqual(expected, publish.publish.packet_id.?);
                try std.testing.expect(publish.publish.dup);
                try std.testing.expectEqualStrings("deadline/qos", publish.publish.topic);
                try std.testing.expectEqualStrings("payload", publish.publish.payload);
                if (self.phase == .qos1) {
                    try recovered.connection.writePubAck(expected, 0);
                } else {
                    try recovered.connection.writePubRec(expected, 0);
                    // The later PUBLISH is already queued on the transport,
                    // so consume it before waiting for the recovered PUBREL.
                }
            }
            var later = try readPublish(&recovered.connection);
            defer later.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(?u16, expected + 1), later.publish.packet_id);
            try std.testing.expect(!later.publish.dup);
            try std.testing.expectEqualStrings("deadline/later", later.publish.topic);
            try std.testing.expectEqualStrings("later", later.publish.payload);
            if (self.phase == .qos2_publish) {
                var release = try readRelease(&recovered.connection);
                defer release.deinit(self.server.allocator);
                try std.testing.expectEqual(expected, release.ack.packet_id);
                try recovered.connection.writePubComp(expected, 0);
            }
            try recovered.connection.writePubAck(later.publish.packet_id.?, 0);
        }
    };
    var peer = Peer{ .server = &server, .phase = phase, .protocol = protocol };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};
    var client = try reconnect.Client.init(allocator, observed_io, server.address(), .{
        .protocol = protocol,
        .client_id = "bounded-qos-replay",
        .clean_start = false,
        .properties = if (protocol == .v5) &properties else &.{},
        .connect_timeout = .fromSeconds(2),
    }, .{}, &shutdown);
    defer client.deinit();
    _ = try client.connect();
    const packet_id = if (phase == .pubrel) blk: {
        const packet_id = (try client.publish("deadline/qos", "payload", .{ .qos = .exactly_once })).?;
        try std.testing.expectEqual(packet_id, try client.completeNextPublish());
        break :blk packet_id;
    } else try client.stagePublish("deadline/qos", "payload", .{ .qos = if (phase == .qos1) .at_least_once else .exactly_once });
    peer.expected_id.store(packet_id, .release);
    // The staging API reserves one immediate transmission. Put subsequent
    // traffic in the durable FIFO so its ID and DUP flag remain unselected.
    _ = try client.outgoing.enqueuePublish(client.outgoing_handle, "deadline/later", "later", .{ .qos = .at_least_once, .now = std.Io.Clock.awake.now(io) });
    const later_id = packet_id + 1;
    client.disconnectTransport();
    observer.armed.store(true, .release);
    const result = if (absolute)
        client.connectWithDeadline(.fromNow(observed_io, .{ .raw = .fromMilliseconds(50), .clock = .awake }))
    else
        client.connectWithTimeout(.fromMilliseconds(50));
    try std.testing.expectError(error.Timeout, result);
    try std.testing.expect(observer.entered.load(.acquire));
    try std.testing.expect(observer.canceled.load(.acquire));
    try std.testing.expect(client.connection() == null);
    const stats = try client.outgoing.stats(client.outgoing_handle);
    try std.testing.expectEqual(@as(usize, 2), stats.queued_count + stats.inflight_count);
    observer.armed.store(false, .release);
    const restored = try client.connectWithTimeout(.fromSeconds(2));
    try std.testing.expect(restored.session_present);
    try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    if (phase == .qos2_publish) try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    try std.testing.expectEqual(later_id, try client.completeNextPublish());
    const completed = try client.outgoing.stats(client.outgoing_handle);
    try std.testing.expectEqual(@as(usize, 0), completed.queued_count + completed.inflight_count);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
