//! Durable target outcomes survive loss of the target MQTT Session.
const std = @import("std");
const runtime = @import("../runtime.zig");
const outbound = @import("outbound.zig");
const coordinator = @import("outbound_coordinator.zig");
const fixture = @import("outbound_retention_support.zig");

const SourcePeer = struct {
    server: *runtime.Server,
    rejected: bool,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        var accepted = try self.server.acceptWithTimeout(.{ .session_present = true }, .fromSeconds(2));
        defer accepted.deinit(self.server.allocator);
        var pubrec = try accepted.connection.readBrokerEventWithTimeout(.fromSeconds(2));
        defer pubrec.deinit(self.server.allocator);
        try std.testing.expect(pubrec == .pubrec);
        try std.testing.expectEqual(@as(u16, 77), pubrec.pubrec.ack.packet_id);
        try std.testing.expectEqual(@as(u8, if (self.rejected) 0x87 else 0), pubrec.pubrec.ack.reason_code);
        if (!self.rejected) {
            try accepted.connection.writePubRel(77, 0);
            var pubcomp = try accepted.connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expect(pubcomp == .pubcomp);
            try std.testing.expectEqual(@as(u16, 77), pubcomp.pubcomp.ack.packet_id);
        }
        var disconnect = try accepted.connection.readBrokerEventWithTimeout(.fromSeconds(2));
        defer disconnect.deinit(self.server.allocator);
        try std.testing.expect(disconnect == .disconnect);
    }
};

const TargetPeer = struct {
    server: *runtime.Server,
    session_present: bool,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        var accepted = try self.server.acceptWithTimeout(.{ .session_present = self.session_present }, .fromSeconds(2));
        defer accepted.deinit(self.server.allocator);
        // The durable result completes upstream without another target
        // PUBLISH or PUBREL, regardless of the peer's raw Session bit.
        var event = try accepted.connection.readBrokerEventWithTimeout(.fromSeconds(2));
        defer event.deinit(self.server.allocator);
        try std.testing.expect(event == .disconnect);
    }
};

test "outbound bridge terminal QoS2 outcomes complete source after expired target Session restore" {
    for ([_]coordinator.Phase{ .target_complete, .target_rejected }) |phase| {
        for ([_]bool{ false, true }) |session_present| try exercise(phase, session_present);
    }
}

fn exercise(phase: coordinator.Phase, target_present: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var source_server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer source_server.deinit();
    var target_server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer target_server.deinit();
    var shutdown: std.Io.Event = .unset;
    const options = outbound.Options{
        .source_connect = .{
            .client_id = "terminal-source",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
            .connect_timeout = .fromSeconds(2),
        },
        .target_connect = .{
            .client_id = "terminal-target",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 1 } }},
            .connect_timeout = .fromSeconds(2),
        },
        .rule = .{ .filter = "source/#", .qos = .exactly_once },
        .coordinator = .{ .bridge_id = [_]u8{0x72} ** 16, .dir = tmp.dir, .sub_path = "terminal.log", .mode = .create },
    };
    {
        var first = try outbound.Bridge.init(allocator, io, source_server.address(), target_server.address(), options, &shutdown);
        defer first.deinit();
        first.source_session_epoch = 1;
        first.target_session_epoch = 1;
        try fixture.stage(&first.source, &first.target, &first.coordinator.?, phase);
    }
    try std.Io.sleep(io, .fromMilliseconds(1100), .awake);
    var source_peer = SourcePeer{ .server = &source_server, .rejected = phase == .target_rejected };
    const source_thread = try std.Thread.spawn(.{}, SourcePeer.run, .{&source_peer});
    var source_joined = false;
    defer if (!source_joined) source_thread.join();
    var target_peer = TargetPeer{ .server = &target_server, .session_present = target_present };
    const target_thread = try std.Thread.spawn(.{}, TargetPeer.run, .{&target_peer});
    var target_joined = false;
    defer if (!target_joined) target_thread.join();
    var restore_options = options;
    restore_options.coordinator.?.mode = .restore;
    var bridge = try outbound.Bridge.init(allocator, io, source_server.address(), target_server.address(), restore_options, &shutdown);
    defer bridge.deinit();
    const connected = try bridge.connect();
    try std.testing.expect(connected.source_session_present);
    try std.testing.expectEqual(target_present, connected.target_session_present);
    try std.testing.expect(!bridge.target.sessionResumed());
    try std.testing.expectEqual(@as(u64, 2), bridge.target_session_epoch);
    if (phase == .target_complete) try std.testing.expect(try bridge.step(.{ .timeout = .fromSeconds(2) }));
    try std.testing.expect(!bridge.hasPendingDurableQoS2());
    try std.testing.expectEqual(@as(usize, 0), (try bridge.source.outgoingStats()).incoming_qos2_count);
    try std.testing.expectEqual(@as(usize, 0), (try bridge.target.outgoingStats()).inflight_count);
    try bridge.disconnect(0);
    source_thread.join();
    source_joined = true;
    target_thread.join();
    target_joined = true;
    if (source_peer.err) |err| return err;
    if (target_peer.err) |err| return err;
}
