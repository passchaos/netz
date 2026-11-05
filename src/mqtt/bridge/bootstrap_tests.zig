//! A new coordinator can attach to broker Sessions that already exist.
const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const outbound = @import("outbound.zig");

const timeout: std.Io.Duration = .fromSeconds(2);
const packet_id: u16 = 1;
const properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};

fn disconnect(connection: *runtime.Connection) !void {
    var event = try connection.readBrokerEventWithTimeout(timeout);
    defer event.deinit(connection.allocator);
    try std.testing.expect(event == .disconnect);
}

fn acknowledgement(connection: *runtime.Connection, kind: mqtt.PacketType, id: u16) !void {
    var event = try connection.readBrokerEventWithTimeout(timeout);
    defer event.deinit(connection.allocator);
    const ack = switch (event) {
        .pubrec, .pubrel, .pubcomp => |value| value.ack,
        else => return error.UnexpectedPacket,
    };
    try std.testing.expectEqual(kind, ack.packet_type);
    try std.testing.expectEqual(id, ack.packet_id);
}

const SourcePeer = struct {
    server: *runtime.Server,
    protocol: mqtt.ProtocolVersion,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn publish(connection: *runtime.Connection, duplicate: bool) !void {
        try std.testing.expectEqual(packet_id, (try connection.writePublish("source/value", "bootstrap", .{
            .qos = .exactly_once,
            .dup = duplicate,
        })).?);
    }

    fn serve(self: *@This()) !void {
        {
            var first = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, timeout);
            defer first.deinit(self.server.allocator);
            // The Session already owns this subscription; no SUBSCRIBE is
            // needed before consuming its next Application Message.
            try publish(&first.connection, false);
            // The coordinator must commit before emitting source PUBREC.
            try disconnect(&first.connection);
        }
        var restored = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, timeout);
        defer restored.deinit(self.server.allocator);
        try publish(&restored.connection, true);
        try acknowledgement(&restored.connection, .pubrec, packet_id);
        try restored.connection.writePubRel(packet_id, 0);
        try acknowledgement(&restored.connection, .pubcomp, packet_id);
        try disconnect(&restored.connection);
    }
};

const TargetPeer = struct {
    server: *runtime.Server,
    protocol: mqtt.ProtocolVersion,
    session_present: bool,
    transaction_staged: bool,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        {
            var first = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = self.session_present }, timeout);
            defer first.deinit(self.server.allocator);
            // The first process stops at the pre-wire durable boundary.
            try disconnect(&first.connection);
        }
        var restored = try self.server.acceptWithTimeout(.{ .protocol = self.protocol, .session_present = true }, timeout);
        defer restored.deinit(self.server.allocator);
        var event = try restored.connection.readBrokerEventWithTimeout(timeout);
        defer event.deinit(self.server.allocator);
        try std.testing.expect(event == .publish);
        try std.testing.expectEqual(self.transaction_staged, event.publish.publish.dup);
        try std.testing.expectEqualStrings("target/value", event.publish.publish.topic);
        try std.testing.expectEqualStrings("bootstrap", event.publish.publish.payload);
        const id = event.publish.publish.packet_id.?;
        try restored.connection.writePubRec(id, 0);
        try acknowledgement(&restored.connection, .pubrel, id);
        try restored.connection.writePubComp(id, 0);
        // No second PUBLISH after the completed QoS 2 handshake.
        try disconnect(&restored.connection);
    }
};

test "outbound bridge bootstraps preserved network source Session and restores first QoS2 transaction" {
    try matrix(true);
}

test "outbound bridge persists first preserved network source epoch before staging any transaction" {
    try matrix(false);
}

fn matrix(transaction_staged: bool) !void {
    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |source_protocol| {
        for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |target_protocol| {
            for ([_]bool{ false, true }) |target_present| try exercise(source_protocol, target_protocol, target_present, transaction_staged);
        }
    }
}

fn exercise(source_protocol: mqtt.ProtocolVersion, target_protocol: mqtt.ProtocolVersion, target_present: bool, transaction_staged: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var source_server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer source_server.deinit();
    var target_server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer target_server.deinit();
    var source_peer = SourcePeer{ .server = &source_server, .protocol = source_protocol };
    const source_thread = try std.Thread.spawn(.{}, SourcePeer.run, .{&source_peer});
    var source_joined = false;
    defer if (!source_joined) source_thread.join();
    var target_peer = TargetPeer{ .server = &target_server, .protocol = target_protocol, .session_present = target_present, .transaction_staged = transaction_staged };
    const target_thread = try std.Thread.spawn(.{}, TargetPeer.run, .{&target_peer});
    var target_joined = false;
    defer if (!target_joined) target_thread.join();
    var shutdown: std.Io.Event = .unset;
    const options = outbound.Options{
        .source_connect = .{
            .protocol = source_protocol,
            .client_id = "bootstrap-source",
            .clean_start = false,
            .properties = if (source_protocol == .v5) &properties else &.{},
            .connect_timeout = timeout,
            .network_connect_timeout = timeout,
        },
        .target_connect = .{
            .protocol = target_protocol,
            .client_id = "bootstrap-target",
            .clean_start = false,
            .properties = if (target_protocol == .v5) &properties else &.{},
            .connect_timeout = timeout,
            .network_connect_timeout = timeout,
        },
        .rule = .{ .filter = "value", .local_prefix = "source/", .remote_prefix = "target/", .qos = .exactly_once },
        .coordinator = .{ .bridge_id = [_]u8{0xb0} ** 16, .dir = tmp.dir, .sub_path = "bootstrap.log", .mode = .create },
    };
    {
        var first = try outbound.Bridge.init(allocator, io, source_server.address(), target_server.address(), options, &shutdown);
        defer first.deinit();
        const connected = try first.connect();
        try std.testing.expect(connected.source_session_present);
        try std.testing.expectEqual(target_present, connected.target_session_present);
        try std.testing.expectEqual(@as(u64, 1), first.coordinator.?.source_session_epoch);
        try std.testing.expectEqual(@as(u64, 1), first.coordinator.?.target_session_epoch);
        if (transaction_staged) {
            try outbound.testing.stageNextDurableQoS2(&first, .{ .timeout = timeout });
            const transaction = first.coordinator.?.currentTransaction().?;
            try std.testing.expectEqual(@as(u64, 1), transaction.source_session_epoch);
            try std.testing.expectEqual(@as(u64, 1), transaction.target_session_epoch);
        }
        try first.disconnect(0);
    }
    var restore_options = options;
    restore_options.coordinator.?.mode = .restore;
    var restored = try outbound.Bridge.init(allocator, io, source_server.address(), target_server.address(), restore_options, &shutdown);
    defer restored.deinit();
    try std.testing.expectEqual(@as(u64, 1), restored.source_session_epoch);
    try std.testing.expectEqual(@as(u64, 1), restored.target_session_epoch);
    try std.testing.expectEqual(transaction_staged, restored.hasPendingDurableQoS2());
    const connected = try restored.connect();
    try std.testing.expect(connected.source_session_present and connected.target_session_present);
    try std.testing.expect(try restored.step(.{ .timeout = timeout, .cancellation_check_interval = .fromMilliseconds(5) }));
    try std.testing.expect(!restored.hasPendingDurableQoS2());
    try std.testing.expectEqual(@as(u64, 1), restored.source_session_epoch);
    try std.testing.expectEqual(@as(u64, 1), restored.target_session_epoch);
    try restored.disconnect(0);
    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}
