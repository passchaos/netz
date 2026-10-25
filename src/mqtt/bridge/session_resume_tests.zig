//! Bridge journals must follow local Session retention as well as CONNACK.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");
const outbound = @import("outbound.zig");
const inbound = @import("inbound_flow.zig");
const broker_mod = @import("../broker.zig");

const timeout: std.Io.Duration = .fromSeconds(2);
const session_expiry = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }};

fn connectOptions(id: []const u8) runtime.ConnectOptions {
    return .{
        .client_id = id,
        .clean_start = false,
        .properties = &session_expiry,
        .connect_timeout = timeout,
        .network_connect_timeout = timeout,
    };
}

/// The next packet must be SUBSCRIBE (when expected), then DISCONNECT. A
/// stale target PUBLISH or imported source acknowledgement fails the test.
const PreservedPeer = struct {
    server: *runtime.Server,
    subscription: ?[]const u8 = null,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        var accepted = try self.server.acceptWithTimeout(.{ .session_present = true }, timeout);
        defer accepted.deinit(self.server.allocator);
        if (self.subscription) |filter| {
            var event = try accepted.connection.readBrokerEventWithTimeout(timeout);
            defer event.deinit(self.server.allocator);
            try std.testing.expect(event == .subscribe);
            try std.testing.expectEqualStrings(filter, event.subscribe.subscribe.subscriptions[0].topic_filter);
            try accepted.connection.writeSubAck(event.subscribe.subscribe.packet_id, &.{2}, &.{});
        }
        var event = try accepted.connection.readBrokerEventWithTimeout(timeout);
        defer event.deinit(self.server.allocator);
        try std.testing.expect(event == .disconnect);
    }
};

fn stageTransaction(bridge: *outbound.Bridge) !void {
    bridge.source_session_epoch = 1;
    bridge.target_session_epoch = 1;
    _ = try bridge.source.outgoing.recordIncomingQoS2(bridge.source.outgoing_handle, 77);
    const target = try bridge.target.outgoing.beginImmediatePublish(
        bridge.target.outgoing_handle,
        "mirror/value",
        "old",
        .{ .qos = .exactly_once, .now = std.Io.Clock.awake.now(bridge.target.io) },
        8,
    );
    _ = try bridge.coordinator.?.commit(&bridge.source, &bridge.target, 1, 1, .{
        .phase = .target_await_pubrec,
        .source_session_epoch = 1,
        .target_session_epoch = 1,
        .source_packet_id = 77,
        .target_packet_id = target.packet_id,
        .source_retain = false,
        .source_topic = "source/value",
        .source_payload = "old",
        .source_properties = &.{},
        .source_expiry_interval = null,
    });
}

fn bridgeOptions(dir: std.Io.Dir) outbound.Options {
    return .{
        .source_connect = connectOptions("resume-source"),
        .target_connect = connectOptions("resume-target"),
        .rule = .{ .filter = "source/#", .qos = .exactly_once },
        .coordinator = .{
            .bridge_id = [_]u8{0x5e} ** 16,
            .dir = dir,
            .sub_path = "resume.log",
            .mode = .create,
        },
    };
}

test "outbound bridge local target expiry advances epoch despite Session Present" {
    for ([_]bool{ false, true }) |pending| try targetExpiry(pending);
}

fn targetExpiry(pending: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var peer = PreservedPeer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, PreservedPeer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(allocator, io, .{ .ip4 = .loopback(1) }, server.address(), bridgeOptions(tmp.dir), &shutdown);
    defer bridge.deinit();
    if (pending) try stageTransaction(&bridge) else bridge.target_session_epoch = 1;
    bridge.target.retention.expires_at = .zero;
    const connected = try bridge.target.connectWithTimeout(timeout);
    try std.testing.expect(connected.session_present and !connected.session_resumed);
    if (pending) {
        try std.testing.expectError(error.TargetSessionLost, bridge.noteTargetConnected(connected));
        try std.testing.expect(bridge.coordinator.?.currentTransaction() != null);
    } else try bridge.noteTargetConnected(connected);
    try std.testing.expect(bridge.target_session_present);
    try std.testing.expectEqual(@as(u64, 2), bridge.target_session_epoch);
    try std.testing.expectEqual(@as(usize, 0), (try bridge.target.outgoingStats()).inflight_count);
    try bridge.target.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "outbound bridge local source expiry fails before target replay despite Session Present" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer source.deinit();
    var target = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer target.deinit();
    var peer = PreservedPeer{ .server = &source, .subscription = "source/#" };
    const thread = try std.Thread.spawn(.{}, PreservedPeer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var bridge = try outbound.Bridge.init(allocator, io, source.address(), target.address(), bridgeOptions(tmp.dir), &shutdown);
    defer bridge.deinit();
    try stageTransaction(&bridge);
    bridge.source.retention.expires_at = .zero;
    try std.testing.expectError(error.SourceSessionLost, bridge.connect());
    try std.testing.expect(bridge.source_session_present and !bridge.source.sessionResumed());
    try std.testing.expectEqual(@as(u64, 2), bridge.source_session_epoch);
    try std.testing.expectEqual(@as(usize, 0), (try bridge.source.outgoingStats()).incoming_qos2_count);
    try std.testing.expect(bridge.target.connection() == null);
    try std.testing.expectEqual(@as(usize, 1), (try bridge.target.outgoingStats()).inflight_count);
    // Prove no target connection was even attempted before source validation.
    try std.testing.expectError(error.Timeout, target.acceptPendingWithTimeout(.{}, .fromMilliseconds(20)));
    try bridge.source.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "MQTT inbound bridge local expiry durably retires old epoch despite Session Present" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const id = [_]u8{0x5f} ** 16;
    const key = broker_mod.BridgeQoS2Key{ .bridge_id = id, .session_epoch = 1, .packet_id = 77 };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var peer = PreservedPeer{ .server = &server, .subscription = "remote/#" };
    const thread = try std.Thread.spawn(.{}, PreservedPeer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initWithOptions(allocator, io, server.address(), connectOptions("resume-inbound"), .{}, &shutdown, .{
        .manual_acknowledgements = true,
        .inbound_qos2_release_policy = .deferred,
    });
    defer client.deinit();
    try client.seedSubscription(.{ .topic_filter = "remote/#", .qos = .exactly_once }, &.{});
    client.retention.expires_at = .zero;
    {
        var local = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
        defer local.deinit();
        try local.createCommitLog(tmp.dir, "inbound.log", .{});
        var epoch = try local.beginBridgeQoS2Session(id);
        try std.testing.expectEqual(@as(u64, 1), epoch);
        _ = try local.stageBridgeQoS2(key, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/value",
            .packet_id = null,
            .payload = "old",
        }, .{});
        const connected = try client.connectWithTimeout(timeout);
        try std.testing.expect(connected.session_present and !connected.session_resumed);
        try inbound.noteConnected(allocator, &local, &client, &.{.{ .filter = "remote/#", .qos = .exactly_once }}, id, &epoch, true, connected);
        try std.testing.expectEqual(@as(u64, 2), epoch);
        try std.testing.expect(!local.containsBridgeQoS2(key));
        try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).incoming_qos2_count);
    }
    var restored = try broker_mod.Broker.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "inbound.log", .{});
    try std.testing.expectEqual(@as(?u64, 2), restored.latestBridgeQoS2SessionEpoch(id));
    try std.testing.expect(!restored.containsBridgeQoS2(key));
    try client.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
