const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");
const BlockedWrite = @import("../runtime/acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;

test "MQTT reconnect poll deadline cancels automatic Keep Alive output and preserves QoS ownership" {
    for ([_]mqtt.ProtocolVersion{ .v3_1, .v3_1_1, .v5 }) |protocol| {
        for ([_]bool{ false, true }) |absolute| try exercise(protocol, absolute);
    }
}

fn exercise(protocol: mqtt.ProtocolVersion, absolute: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var blocked = BlockedWrite{ .delegate = io, .packet_type = .pingreq, .delay = .fromMilliseconds(400) };
    BlockedWrite.active = &blocked;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        protocol: mqtt.ProtocolVersion,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var accepted = try self.server.acceptWithTimeout(.{ .protocol = self.protocol }, .fromSeconds(2));
            defer accepted.deinit(allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(allocator);
            try std.testing.expectEqualStrings("keepalive/pending", publish.publish.topic);
            accepted.connection.readPingReq() catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {},
                else => return err,
            };
        }
    };
    var peer = Peer{ .server = &server, .protocol = protocol };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, observed_io, server.address(), .{
        .protocol = protocol,
        .client_id = "keepalive-budget",
        .clean_start = false,
        .keep_alive_seconds = 1,
        .properties = if (protocol == .v5) &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }} else &.{},
    }, .{}, &shutdown);
    defer client.deinit();
    _ = try client.connectWithTimeout(.fromSeconds(2));
    const pending = try client.publishOneAttempt("keepalive/pending", "owned", .{ .qos = .at_least_once });
    try std.testing.expect(pending.packet_id != null);
    // Drive the existing automatic probe immediately, without a sleep or a
    // clock adjustment that could bypass deadline-aware transport behavior.
    client.keep_alive_deadline = .zero;
    blocked.armed.store(true, .release);
    const started = std.Io.Clock.awake.now(io);
    const result = if (absolute)
        try client.pollWithDeadline(started.addDuration(.fromMilliseconds(50)), .{ .reconnect_after_transport_error = false })
    else
        try client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false });
    if (result) |value| {
        var event = value;
        event.deinit(allocator);
        return error.PollReportedProbeAfterDeadline;
    }
    try std.testing.expect(blocked.entered.load(.acquire));
    try std.testing.expect(blocked.canceled.load(.acquire));
    try std.testing.expect(client.connection() == null);
    const stats = try client.outgoing.stats(client.outgoing_handle);
    try std.testing.expectEqual(@as(usize, 1), stats.queued_count + stats.inflight_count);
    try std.testing.expect(client.ping_response_deadline == null);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "MQTT reconnect poll expiry precedes automatic Keep Alive without retiring transport" {
    const Clock = struct {
        var current: ?*@This() = null;
        base: std.Io.Timestamp,
        calls: usize = 0,
        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            const self = current.?;
            self.calls += 1;
            return if (self.calls == 1) self.base else self.base.addDuration(.fromSeconds(2));
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Pair = @import("../runtime/acknowledgement/test_connection.zig").Pair;
    const pair = try Pair.init(io, .v5);
    var peer = pair.peer;
    defer peer.close();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(allocator, io, .{ .ip4 = .loopback(1) }, .{ .protocol = .v5, .client_id = "expired-poll", .keep_alive_seconds = 1 }, .{}, &shutdown);
    defer client.deinit();
    client.connection_state = pair.client;
    client.connection_state.?.keep_alive_seconds = 1;
    client.keep_alive_deadline = .zero;
    var clock = Clock{ .base = std.Io.Clock.awake.now(io) };
    Clock.current = &clock;
    defer Clock.current = null;
    var vtable = io.vtable.*;
    vtable.now = Clock.now;
    client.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer client.io = io;
    const result = try client.pollWithOptions(.{ .timeout = .fromMilliseconds(50), .reconnect_after_transport_error = false });
    client.io = io;
    if (result) |value| {
        var event = value;
        event.deinit(allocator);
        return error.ProbeAfterExpiredPoll;
    }
    try std.testing.expect(client.connection() != null);
    try std.testing.expect(client.connection().?.isUsable());
    try std.testing.expect(client.ping_response_deadline == null);
    try std.testing.expectError(error.Timeout, peer.readBrokerEventWithTimeout(.fromMilliseconds(5)));
}
