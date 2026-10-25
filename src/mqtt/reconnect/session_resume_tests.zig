//! Durable receive markers can be imported only into a resumed MQTT Session.
const std = @import("std");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

test "MQTT reconnect fresh Session rejects restored inbound QoS2 markers" {
    try importMarkers(false);
}

test "MQTT reconnect first attachment to preserved Session accepts durable QoS2 markers" {
    try importMarkers(true);
}

fn importMarkers(session_present: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
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
            var event = try accepted.connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer event.deinit(self.server.allocator);
            try std.testing.expect(event == .disconnect);
        }
    };
    var peer = Peer{ .server = &server, .session_present = session_present };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initWithOptions(allocator, io, server.address(), .{
        .client_id = "fresh-resume",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 60 } }},
    }, .{}, &shutdown, .{ .manual_acknowledgements = true, .inbound_qos2_release_policy = .deferred });
    defer client.deinit();
    const connected = try client.connectWithTimeout(.fromSeconds(2));
    try std.testing.expectEqual(session_present, connected.session_present);
    try std.testing.expectEqual(session_present, connected.session_resumed);
    try std.testing.expectEqual(session_present, client.sessionResumed());
    if (session_present) {
        try client.restoreIncomingQoS2(7, .await_pubrel);
        try client.restoreIncomingQoS2(8, .release_pending);
        try client.restoreIncomingQoS2(8, .release_pending);
        try std.testing.expectEqual(@as(usize, 2), (try client.outgoingStats()).incoming_qos2_count);
        try std.testing.expectEqual(.await_pubrel, (try client.incomingQoS2State(7)).?);
        try std.testing.expectEqual(.release_pending, (try client.incomingQoS2State(8)).?);
    } else {
        try std.testing.expectError(error.SessionLost, client.restoreIncomingQoS2(7, .await_pubrel));
        try std.testing.expectError(error.SessionLost, client.restoreIncomingQoS2(8, .release_pending));
        try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).incoming_qos2_count);
    }
    try client.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "MQTT reconnect completion reports locally expired Session instead of awaiting old ACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            {
                var first = try self.server.acceptWithTimeout(.{}, .fromSeconds(2));
                defer first.deinit(self.server.allocator);
                var event = try first.connection.readBrokerEventWithTimeout(.fromSeconds(2));
                defer event.deinit(self.server.allocator);
                try std.testing.expect(event == .publish);
                try first.connection.shutdown();
            }
            var preserved = try self.server.acceptWithTimeout(.{ .session_present = true }, .fromSeconds(2));
            defer preserved.deinit(self.server.allocator);
            var event = try preserved.connection.readBrokerEventWithTimeout(.fromSeconds(2));
            defer event.deinit(self.server.allocator);
            // No replay or wait for a PUBACK belonging to the expired Session.
            try std.testing.expect(event == .disconnect);
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    // Default MQTT 5 Session Expiry is zero, so transport loss expires it.
    var client = try reconnect.Client.init(allocator, io, server.address(), .{
        .client_id = "expired-completion",
        .clean_start = false,
        .connect_timeout = .fromSeconds(2),
        .network_connect_timeout = .fromSeconds(2),
    }, .{ .max_attempts = 1 }, &shutdown);
    defer client.deinit();
    _ = try client.connectWithTimeout(.fromSeconds(2));
    _ = try client.publishOneAttempt("pending", "old", .{ .qos = .at_least_once });
    try std.testing.expectError(error.SessionLost, client.completeNextPublish());
    try std.testing.expect(client.connection() != null);
    try std.testing.expect(!client.sessionResumed());
    try std.testing.expectEqual(@as(usize, 0), (try client.outgoingStats()).inflight_count);
    try client.disconnect(0);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}
