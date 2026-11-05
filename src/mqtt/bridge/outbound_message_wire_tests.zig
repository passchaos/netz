//! Expired target messages complete upstream without another target PUBLISH.
const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const runtime = @import("../runtime.zig");
const outbound = @import("outbound.zig");
const fixture = @import("outbound_retention_support.zig");

const timeout: std.Io.Duration = .fromSeconds(3);
const Scenario = enum { restore_publish, restore_release, live_publish };

const Peer = struct {
    server: *runtime.Server,
    source: bool,
    release: bool,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        var accepted = try self.server.acceptWithTimeout(.{ .session_present = true }, timeout);
        defer accepted.deinit(self.server.allocator);
        if (self.source) {
            // Mosquitto can retry an expired outgoing QoS 2 PUBLISH without
            // the Message Expiry property. The accepted or completed target
            // transaction still owns this source handshake and cannot resend it.
            try accepted.connection.writeSessionTransmission(.{ .publish = .{
                .topic = "source/topic",
                .payload = "old",
                .qos = .exactly_once,
                .retain = false,
                .dup = true,
                .packet_id = 77,
                .properties = &.{},
                .message_expiry_interval = null,
            } }, .exactly_once);
            var pubrec = try accepted.connection.readBrokerEventWithTimeout(timeout);
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expect(pubrec == .pubrec);
            try std.testing.expectEqual(@as(u16, 77), pubrec.pubrec.ack.packet_id);
            try std.testing.expectEqual(@as(u8, 0), pubrec.pubrec.ack.reason_code);
            try accepted.connection.writePubRel(77, 0);
            var pubcomp = try accepted.connection.readBrokerEventWithTimeout(timeout);
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expect(pubcomp == .pubcomp);
            try std.testing.expectEqual(@as(u16, 77), pubcomp.pubcomp.ack.packet_id);
        } else if (self.release) {
            var pubrel = try accepted.connection.readBrokerEventWithTimeout(timeout);
            defer pubrel.deinit(self.server.allocator);
            try std.testing.expect(pubrel == .pubrel);
            try std.testing.expectEqual(@as(u16, 1), pubrel.pubrel.ack.packet_id);
            try accepted.connection.writePubComp(1, 0);
        }
        var event = try accepted.connection.readBrokerEventWithTimeout(timeout);
        defer event.deinit(self.server.allocator);
        // Every scenario fails if the target sees an expired PUBLISH.
        try std.testing.expect(event == .disconnect);
    }
};

test "outbound bridge Message Expiry preserves source completion and only accepted target PUBREL" {
    for ([_]Scenario{ .restore_publish, .restore_release, .live_publish }) |scenario| try exercise(scenario);
}

fn exercise(scenario: Scenario) !void {
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
    var shutdown: std.Io.Event = .unset;
    const options = outbound.Options{
        .source_connect = .{
            .client_id = "message-source",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
            .connect_timeout = timeout,
        },
        .target_connect = .{
            .client_id = "message-target",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
            .connect_timeout = timeout,
        },
        .rule = .{ .filter = "source/#", .qos = .exactly_once },
        .coordinator = .{ .bridge_id = [_]u8{0x73} ** 16, .dir = tmp.dir, .sub_path = "message.log", .mode = .create },
    };
    if (scenario != .live_publish) {
        var first = try outbound.Bridge.init(allocator, io, source_server.address(), target_server.address(), options, &shutdown);
        defer first.deinit();
        first.source_session_epoch = 1;
        first.target_session_epoch = 1;
        try fixture.stageWithExpiry(&first.source, &first.target, &first.coordinator.?, if (scenario == .restore_release) .target_await_pubcomp else .target_await_pubrec, 1);
        try std.Io.sleep(io, .fromMilliseconds(1100), .awake);
    }
    var source_peer = Peer{ .server = &source_server, .source = true, .release = scenario == .restore_release };
    const source_thread = try std.Thread.spawn(.{}, Peer.run, .{&source_peer});
    var source_joined = false;
    defer if (!source_joined) source_thread.join();
    var target_peer = Peer{ .server = &target_server, .source = false, .release = scenario == .restore_release };
    const target_thread = try std.Thread.spawn(.{}, Peer.run, .{&target_peer});
    var target_joined = false;
    defer if (!target_joined) target_thread.join();
    var current_options = options;
    if (scenario != .live_publish) current_options.coordinator.?.mode = .restore;
    var bridge = try outbound.Bridge.init(allocator, io, source_server.address(), target_server.address(), current_options, &shutdown);
    defer bridge.deinit();
    _ = try bridge.connect();
    if (scenario == .live_publish) {
        // The first target write is deferred past Message Expiry while both
        // MQTT Sessions remain online and owned by the same bridge.
        try fixture.stageWithExpiry(&bridge.source, &bridge.target, &bridge.coordinator.?, .target_await_pubrec, 1);
        try std.Io.sleep(io, .fromMilliseconds(1100), .awake);
    }
    try std.testing.expect(try bridge.step(.{ .timeout = timeout, .cancellation_check_interval = .fromMilliseconds(5) }));
    try std.testing.expect(!bridge.hasPendingDurableQoS2());
    try std.testing.expectEqual(@as(usize, 0), (try bridge.target.outgoingStats()).inflight_count);
    try std.testing.expectEqual(@as(usize, 0), (try bridge.source.outgoingStats()).incoming_qos2_count);
    try bridge.disconnect(0);
    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}
